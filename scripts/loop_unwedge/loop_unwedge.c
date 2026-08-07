// SPDX-License-Identifier: GPL-2.0
/*
 * loop_unwedge — inspect and, on demand, force-complete blk-mq requests that
 * were leaked because the driver thread owning them died mid-submission.
 *
 * Diagnosed in mxfs sess137 (ccmemory
 * ccloop-c7ee71c6-sess137-SCST-fileio-async-bvec-UAF-root-caused):
 * a general protection fault in dma_direct_map_sg() killed the
 * loop_rootcg_workfn worker inside __iomap_dio_rw(), stranding that worker's
 * requests in MQ_RQ_IN_FLIGHT forever.  blk-mq cannot recover them: loop's
 * blk_mq_ops has no ->timeout, so blk_mq_rq_timed_out() falls through to
 * BLK_EH_RESET_TIMER and rearms the timer for eternity.  Everything layered
 * above (dm-delay, the ext4 mounted on it, the SCST vdisk_fileio LUN backed by
 * a file on that ext4, the SCSI commands, the iSCSI connection teardown
 * threads) blocks behind those four requests.
 *
 * Force-completing them with BLK_STS_IOERR unwinds the whole tower through the
 * stock endio paths.
 *
 * WHY THIS DOES NOT USE blk_mq_end_request() ON THE BIOS.
 * blk_mq_end_request() calls blk_update_request() -> req_bio_endio() ->
 * bio_advance() -> bvec_iter_advance(), which walks bio->bi_io_vec:
 *
 *	while (bytes && bytes >= bv[idx].bv_len) { bytes -= bv[idx].bv_len; idx++; }
 *
 * For a dm clone bio_alloc_clone() *shares* bi_io_vec with the parent, and for
 * an ITER_BVEC direct-I/O the parent's bi_io_vec IS the submitter's bvec array
 * (bio_iov_bvec_set() references it, it does not copy).  The very bug that
 * caused this wedge frees that array while the I/O is in flight, so the array
 * is recycled slab.  A garbage bv_len of 0 makes that loop spin forever; a
 * large one runs idx off the end.  Walking it is not survivable.
 *
 * So the completion path here never reads a bvec.  For each bio it sets
 * bi_status, zeroes bi_iter.bi_size by hand (the exact post-state
 * bvec_iter_advance() would have produced for a full advance) and calls
 * bio_endio() directly, then ends the now-bio-less request.  Verified safe on
 * the layers above: dm's clone_endio()/dm_io_complete(), iomap's
 * iomap_dio_bio_end_io() (bio_release_pages() no-ops without BIO_PAGE_PINNED,
 * which bio_iov_bvec_set() never sets; bio_free() skips bvec_free() because
 * bi_max_vecs is 0) and SCST's fileio_async_complete() (which for ret < 0
 * takes the scst_sense_hardw_error branch and never touches the bvec) all
 * complete without dereferencing bi_io_vec.
 *
 * Usage:
 *   sudo insmod loop_unwedge.ko devpath=/dev/loop0            # inspect
 *   sudo rmmod loop_unwedge
 *   sudo insmod loop_unwedge.ko devpath=/dev/loop0 act=1 expect=4
 *   sudo rmmod loop_unwedge
 *
 * expect= is a safety interlock: when >= 0, the module refuses to complete
 * anything unless exactly that many in-flight requests were found.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/mm.h>

static char *devpath;
module_param(devpath, charp, 0444);
MODULE_PARM_DESC(devpath, "block device whose leaked in-flight requests to inspect/complete");

static int act;
module_param(act, int, 0444);
MODULE_PARM_DESC(act, "0 = inspect only (default), 1 = force-complete every in-flight request with BLK_STS_IOERR");

static int expect = -1;
module_param(expect, int, 0444);
MODULE_PARM_DESC(expect, "if >= 0, refuse to act unless exactly this many in-flight requests are found");

/* Walk bounds — a corrupt chain must not become an unbounded loop. */
#define LU_BVEC_SCAN_MAX	512
#define LU_BIO_CHAIN_MAX	256

struct lu_ctx {
	int pass;		/* 1 = survey, 2 = complete */
	int nr_inflight;
	int nr_suspect;
	int nr_completed;
	int nr_bios;
};

/*
 * Survey one bio's bvec chain exactly the way bvec_iter_advance() would
 * consume it: start at bi_idx, accumulate bv_len until bi_bvec_done + bi_size
 * bytes are covered.  bi_vcnt is NOT a bound here — dm clones share the
 * parent's bi_io_vec but are allocated with nr_vecs = 0, so bi_vcnt reads 0.
 * Reading a kfree'd slab object is safe (SLUB leaves it mapped); it is the
 * VALUES that may be garbage, which is what this reports.
 */
static int lu_survey_bio(struct bio *bio, int rqidx, int bidx)
{
	struct bio_vec *bvl = bio->bi_io_vec;
	unsigned int idx = bio->bi_iter.bi_idx;
	unsigned int done = bio->bi_iter.bi_bvec_done;
	unsigned int size = bio->bi_iter.bi_size;
	unsigned long long want = (unsigned long long)size + done;
	unsigned long long sum = 0;
	unsigned int i;
	int bad = 0;

	pr_info("loop_unwedge:   rq[%d].bio[%d]=%p bdev=%s vcnt=%u idx=%u bvec_done=%u size=%u io_vec=%p cloned=%d end_io=%ps\n",
		rqidx, bidx, bio,
		bio->bi_bdev && bio->bi_bdev->bd_disk ?
			bio->bi_bdev->bd_disk->disk_name : "?",
		bio->bi_vcnt, idx, done, size, bvl,
		bio_flagged(bio, BIO_CLONED), bio->bi_end_io);

	if (!bvl || !virt_addr_valid(bvl)) {
		pr_warn("loop_unwedge:     BAD: bi_io_vec %p is NULL or outside the direct map\n",
			bvl);
		return -EINVAL;
	}

	for (i = idx; sum < want && i < idx + LU_BVEC_SCAN_MAX; i++) {
		struct bio_vec *bv = &bvl[i];
		struct page *pg = bv->bv_page;
		/*
		 * NOT virt_addr_valid(): a struct page lives in vmemmap, not
		 * the direct map, so virt_addr_valid() is false for every
		 * legitimate page pointer.  page_to_pfn() is plain pointer
		 * arithmetic against vmemmap and is safe to evaluate on any
		 * value; pfn_valid() is the real test.
		 */
		unsigned long pfn = pg ? page_to_pfn(pg) : 0;
		int pgok = pg && pfn_valid(pfn);
		int lenok = bv->bv_len > 0 &&
			    bv->bv_len <= (BIO_MAX_VECS << PAGE_SHIFT) &&
			    (bv->bv_len & 511) == 0;

		pr_info("loop_unwedge:     bv[%u] page=%p pfn=%#lx%s len=%u%s off=%u\n",
			i, pg, pfn, pgok ? "" : " <<BAD PFN>>",
			bv->bv_len, lenok ? "" : " <<BAD LEN>>",
			bv->bv_offset);

		if (!pgok)
			bad++;
		if (!lenok) {
			bad++;
			break;		/* bv_len 0 would spin the real walk */
		}
		sum += bv->bv_len;
	}

	if (sum != want) {
		pr_warn("loop_unwedge:     BAD: covered %llu bytes, bi_size+bvec_done=%llu — bvec chain does not describe this bio\n",
			sum, want);
		bad++;
	}

	if (bad)
		pr_warn("loop_unwedge:     bio %p FAILED validation (%d problems) — its bvec array has been freed and reused\n",
			bio, bad);
	return bad ? -EINVAL : 0;
}

/*
 * Terminate one bio without reading its bvec array.  This reproduces the
 * post-state of a full bio_advance() (bi_size 0, iterator consumed) and then
 * runs the stock bio_endio() so every layer above unwinds normally.
 */
static void lu_kill_bio(struct bio *bio)
{
	bio->bi_next = NULL;
	bio->bi_status = BLK_STS_IOERR;
	bio->bi_iter.bi_bvec_done = 0;
	bio->bi_iter.bi_size = 0;
	bio_clear_flag(bio, BIO_TRACE_COMPLETION);
	bio_endio(bio);
}

static bool lu_iter(struct request *rq, void *priv)
{
	struct lu_ctx *c = priv;
	struct bio *bio, *next;
	int idx, bidx = 0, bad = 0;

	if (blk_mq_rq_state(rq) != MQ_RQ_IN_FLIGHT)
		return true;

	idx = c->nr_inflight++;

	pr_info("loop_unwedge: rq[%d]=%p tag=%d op=%u bytes=%u segs=%u sector=%llu\n",
		idx, rq, rq->tag, (unsigned)req_op(rq),
		blk_rq_bytes(rq), rq->nr_phys_segments,
		(unsigned long long)blk_rq_pos(rq));

	if (c->pass == 1) {
		for (bio = rq->bio; bio; bio = bio->bi_next) {
			if (lu_survey_bio(bio, idx, bidx++))
				bad++;
			if (bidx >= LU_BIO_CHAIN_MAX) {
				pr_warn("loop_unwedge: rq[%d] bio chain exceeds %d, stopping walk\n",
					idx, LU_BIO_CHAIN_MAX);
				bad++;
				break;
			}
		}
		c->nr_bios += bidx;
		if (bad)
			c->nr_suspect++;
		return true;
	}

	/*
	 * Pass 2.  Detach the bio chain and end the request FIRST — with
	 * rq->bio NULL, blk_update_request() returns immediately and never
	 * reaches bvec_iter_advance().  Then terminate the bios by hand, which
	 * is what propagates the error up through dm, iomap and SCST.
	 */
	bio = rq->bio;
	rq->bio = NULL;
	rq->biotail = NULL;
	rq->__data_len = 0;

	blk_mq_end_request(rq, BLK_STS_IOERR);
	c->nr_completed++;

	while (bio) {
		next = bio->bi_next;
		pr_info("loop_unwedge: rq[%d] bio[%d]=%p -> bio_endio(BLK_STS_IOERR)\n",
			idx, bidx++, bio);
		lu_kill_bio(bio);
		c->nr_bios++;
		bio = next;
		if (bidx >= LU_BIO_CHAIN_MAX) {
			pr_warn("loop_unwedge: rq[%d] bio chain exceeds %d, abandoning the rest\n",
				idx, LU_BIO_CHAIN_MAX);
			break;
		}
	}
	return true;
}

static struct bdev_handle *lu_handle;

static int __init loop_unwedge_init(void)
{
	struct request_queue *q;
	struct blk_mq_tag_set *ts;
	struct lu_ctx c = { .pass = 1 };
	int rc = 0;

	if (!devpath || !*devpath) {
		pr_err("loop_unwedge: devpath= is required\n");
		return -EINVAL;
	}

	lu_handle = bdev_open_by_path(devpath, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(lu_handle)) {
		rc = PTR_ERR(lu_handle);
		lu_handle = NULL;
		pr_err("loop_unwedge: cannot open %s: %d\n", devpath, rc);
		return rc;
	}

	q = lu_handle->bdev->bd_disk->queue;
	ts = q->tag_set;
	if (!ts) {
		pr_err("loop_unwedge: %s has no blk-mq tag set (bio-based device?)\n",
		       devpath);
		rc = -ENOTTY;
		goto out;
	}

	pr_info("loop_unwedge: %s disk=%s queue=%p tag_set=%p nr_hw_queues=%u queue_depth=%u act=%d expect=%d\n",
		devpath, lu_handle->bdev->bd_disk->disk_name, q, ts,
		ts->nr_hw_queues, ts->queue_depth, act, expect);

	/*
	 * Pass 1: survey.  Always runs, even when act=1 — the dump is the
	 * evidence record of what state the leaked requests were left in.
	 */
	blk_mq_tagset_busy_iter(ts, lu_iter, &c);
	pr_info("loop_unwedge: survey: %d in-flight request(s), %d bio(s), %d request(s) with a freed/reused bvec chain\n",
		c.nr_inflight, c.nr_bios, c.nr_suspect);

	if (!act) {
		pr_info("loop_unwedge: act=0 — inspection only, nothing was completed\n");
		goto out;
	}

	if (expect >= 0 && c.nr_inflight != expect) {
		pr_err("loop_unwedge: REFUSING to act: found %d in-flight, expect=%d\n",
		       c.nr_inflight, expect);
		rc = -EBUSY;
		goto out;
	}
	if (c.nr_inflight == 0) {
		pr_info("loop_unwedge: nothing in flight, nothing to do\n");
		goto out;
	}

	/*
	 * Pass 2: complete.  Quiesce first so no new dispatch races with the
	 * tag iteration — the same ordering nvme_dev_disable() uses around
	 * nvme_cancel_request().  A corrupt bvec chain is NOT a blocker here:
	 * the completion path below never reads one.
	 */
	c.pass = 2;
	c.nr_inflight = 0;
	c.nr_suspect = 0;
	c.nr_bios = 0;

	blk_mq_quiesce_queue(q);
	blk_mq_tagset_busy_iter(ts, lu_iter, &c);
	blk_mq_unquiesce_queue(q);

	pr_info("loop_unwedge: completed %d of %d in-flight request(s), %d bio(s) ended\n",
		c.nr_completed, c.nr_inflight, c.nr_bios);

out:
	/*
	 * Release the bdev reference here rather than in the exit hook: the
	 * module is loaded to do one thing and is immediately rmmod'ed, and
	 * holding an open handle on the device would block teardown of the
	 * stack we are trying to dismantle.
	 */
	if (lu_handle) {
		bdev_release(lu_handle);
		lu_handle = NULL;
	}
	/* Returning 0 keeps the module resident so the operator sees it in
	 * lsmod; returning an error unloads it immediately.  Either way all
	 * state is already released.
	 */
	return rc;
}

static void __exit loop_unwedge_exit(void)
{
}

module_init(loop_unwedge_init);
module_exit(loop_unwedge_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("inspect / force-complete blk-mq requests leaked by a dead driver thread");
