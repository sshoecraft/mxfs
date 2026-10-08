// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS TCP durable-authority ledger — shadow-page store (see tauth_store.h).
 */
#include "tauth_store.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static uint32_t tauth_crc(uint32_t seed, const void *data, size_t len)
{
	return mxfs_pal_crc32c(seed, data, len);
}

static int tauth_read_block(struct mxfs_tauth_store *s, uint64_t off, void *buf)
{
	s->reads++;
	return mxfs_pal_bdev_read_prio(s->dev, s->base + off, buf,
				       MXFS_TAUTH_PAGE_BYTES);
}

int mxfs_tauth_store_open(struct mxfs_tauth_store *s, mxfs_bdev_t *dev,
			  uint64_t base, uint64_t size,
			  const uint8_t fs_uuid[16],
			  uint32_t local_node, uint64_t local_inc)
{
	struct mxfs_tauth_region_hdr *rh;
	int rc = -EUCLEAN, c;
	int io_fail = 0;

	if (!s || !dev || !fs_uuid)
		return -EINVAL;
	memset(s, 0, sizeof(*s));
	if (!base || !size)
		return -ENODEV;
	if (size < MXFS_TAUTH_REGION_BYTES)
		return -EINVAL;
	s->dev = dev;
	s->base = base;
	s->size = size;
	s->npages = 0;      /* (D-0348 step 2): read from the region header */
	memcpy(s->fs_uuid, fs_uuid, 16);
	s->fs_gen = mxfs_tauth_fs_gen(fs_uuid);
	s->local_node = local_node;
	s->local_inc = local_inc;
	mxfs_pal_get_random_bytes(&s->nonce_state, sizeof(s->nonce_state));
	if (s->nonce_state == 0)
		s->nonce_state = 0x9E3779B97F4A7C15ULL ^ local_inc ^ local_node;

	rh = mxfs_pal_alloc(sizeof(*rh));
	if (!rh)
		return -ENOMEM;
	for (c = 0; c < (int)MXFS_TAUTH_HDR_COPIES; c++) {
		int r = tauth_read_block(s, mxfs_tauth_hdr_off(c), rh);

		if (r) {
			io_fail = 1;
			continue;
		}
		if (mxfs_tauth_region_valid(rh, s->fs_gen, tauth_crc) &&
		    memcmp(rh->fs_uuid, fs_uuid, 16) == 0) {
			/* the geometry the region was formatted with; the envelope
			 * super's tauth_size must cover it (never trust the header
			 * alone to address past the region) */
			if (MXFS_TAUTH_REGION_BYTES_FOR(rh->npages) > size) {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "tauth: P-TAUTH-OPEN-FAIL base=%llu size=%llu "
					     "npages=%u needs %llu -- region header geometry "
					     "exceeds the envelope region",
					     (unsigned long long)base, (unsigned long long)size,
					     rh->npages,
					     (unsigned long long)MXFS_TAUTH_REGION_BYTES_FOR(rh->npages));
				rc = -EINVAL;
				break;
			}
			s->npages = rh->npages;
			s->hash_seed = rh->hash_seed;
			rc = 0;
			break;
		}
	}
	mxfs_pal_free(rh);
	if (rc == -EUCLEAN && io_fail)
		rc = -EIO;
	if (rc == -EUCLEAN || rc == -EIO)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-OPEN-FAIL base=%llu size=%llu rc=%d -- "
			     "no valid region header for this filesystem (v%u, "
			     "seeded geometry)",
			     (unsigned long long)base, (unsigned long long)size, rc,
			     MXFS_TAUTH_VERSION);
	return rc;
}

/*
 * Read both copies; return the winner in *pg.  seq_a / seq_b (optional)
 * carry each copy's valid seq (0 = not valid) so the writer can pick the
 * copy to overwrite without a second read.
 */
static int tauth_page_read_both(struct mxfs_tauth_store *s, uint32_t page_id,
				struct mxfs_tauth_page *pg,
				struct mxfs_tauth_page *scratch,
				uint64_t *seq_a, uint64_t *seq_b, int *copy_out)
{
	uint64_t sa = 0, sb = 0;
	int ra, rb;

	ra = tauth_read_block(s, mxfs_tauth_page_off(s->npages, page_id, 0), pg);
	if (ra == 0 && mxfs_tauth_page_valid(pg, page_id, s->fs_gen, tauth_crc))
		sa = pg->hdr.seq;
	rb = tauth_read_block(s, mxfs_tauth_page_off(s->npages, page_id, 1), scratch);
	if (rb == 0 && mxfs_tauth_page_valid(scratch, page_id, s->fs_gen, tauth_crc))
		sb = scratch->hdr.seq;

	if (seq_a)
		*seq_a = sa;
	if (seq_b)
		*seq_b = sb;
	if (!sa && !sb) {
		if (ra || rb)
			return -EIO;
		s->unknown++;
		return -EUCLEAN;
	}
	if ((sa || sb) && !(sa && sb))
		s->torn_seen++;     /* one copy is not a committed image */
	if (sa && sa == sb && memcmp(pg, scratch, sizeof(*pg)) != 0) {
		/* (step 4): two VALID images with the same seq and
		 * different content = two writers raced this page.  Neither is
		 * the truth; picking one would silently choose a grant.  The
		 * page is conflicted: UNKNOWN until an authority reconciles it
		 * (fail closed). */
		s->conflicts++;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-CONFLICT page=%u seq=%llu writers=%u/%llu vs %u/%llu "
			     "-- two valid divergent images (concurrent writers); page UNKNOWN",
			     page_id, (unsigned long long)sa, pg->hdr.writer_node,
			     (unsigned long long)pg->hdr.writer_inc, scratch->hdr.writer_node,
			     (unsigned long long)scratch->hdr.writer_inc);
		return -EUCLEAN;
	}
	if (sb > sa) {
		memcpy(pg, scratch, sizeof(*pg));
		if (copy_out)
			*copy_out = 1;
	} else if (copy_out) {
		*copy_out = 0;
	}
	return 0;
}

int mxfs_tauth_page_read(struct mxfs_tauth_store *s, uint32_t page_id,
			 struct mxfs_tauth_page *pg, int *copy_out)
{
	struct mxfs_tauth_page *scratch;
	int rc;

	if (!s || !s->dev || !pg || page_id >= s->npages)
		return -EINVAL;
	scratch = mxfs_pal_alloc(sizeof(*scratch));
	if (!scratch)
		return -ENOMEM;
	rc = tauth_page_read_both(s, page_id, pg, scratch, NULL, NULL, copy_out);
	mxfs_pal_free(scratch);
	if (rc == -EUCLEAN)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-PAGE-UNKNOWN page=%u -- no valid copy; "
			     "every resource on it is UNKNOWN (fail closed)", page_id);
	return rc;
}

static inline void ph_add(uint64_t *tot, uint64_t *mx, uint64_t t0)
{
	uint64_t dt = mxfs_pal_time_ms() - t0;

	*tot += dt;
	if (dt > *mx)
		*mx = dt;
}

static void tauth_next_nonce(struct mxfs_tauth_store *s, uint32_t *out)
{
	/* xorshift64 seeded from the PAL RNG at open: unique per write without
	 * a /dev/urandom round trip per commit */
	s->nonce_state ^= s->nonce_state << 13;
	s->nonce_state ^= s->nonce_state >> 7;
	s->nonce_state ^= s->nonce_state << 17;
	*out = (uint32_t)(s->nonce_state ^ (s->nonce_state >> 32));
	if (*out == 0)
		*out = 1;
}

/*
 * (D-0347): the conditional commit.
 *
 *   1. read both copies raw; the unique highest VALID image is the truth
 *      and must match the caller's base token (pg->hdr.seq, write_nonce)
 *      exactly, else -ESTALE — a writer whose image is stale never lands.
 *   2. the spare copy's sector 0, exactly as read, is the CAW compare
 *      value; a live ticket there (another writer mid-commit) is -EBUSY
 *      unless that writer's incarnation is fenced (fenced_cb) or it is our
 *      own abandoned ticket (resume).
 *   3. CAW(spare sector 0 -> ticket): one winner per spare; miscompare =
 *      -ESTALE.  The ticket makes the copy an invalid image, so readers
 *      keep the committed copy.  Flushed before any body byte.
 *   4. body sectors 1..7 with FUA.
 *   5. CAW(ticket -> final sector 0) publishes atomically; a miscompare
 *      here means our ticket was taken over without fencing: -EIO (the
 *      caller poisons and reconciles; P-TAUTH-TICKET-STOLEN).
 *   6. flush; readback.  A later valid seq (or a ticket citing ours as
 *      base) on our copy is a SUPERSEDED commit, not a failure: the CAW
 *      publish was the durable event.
 */
/* One commit in flight — what steps 1-2 decide and the ticket built for it —
 * is a struct mxfs_tauth_wslot (tauth_store.h). */

/*
 * Steps 1-2: read both copies raw (into ca/cb), find the truth, require the
 * caller's base token, pick the spare, refuse a live ticket on it, and build
 * this commit's ticket in *ws.  0, or the commit's result.
 */
static int tauth_write_prepare(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
			       struct mxfs_tauth_page *ca, struct mxfs_tauth_page *cb,
			       struct mxfs_tauth_wslot *ws)
{
	const struct mxfs_tauth_page *spare;
	struct mxfs_tauth_ticket *tk = &ws->tk;
	uint64_t sa = 0, sb = 0, cur_seq, next, t0;
	uint32_t cur_nonce = 0, page_id = pg->hdr.page_id;
	unsigned target;
	int ra, rb;

	/* 1. raw copies + the truth */
	t0 = mxfs_pal_time_ms();
	ra = tauth_read_block(s, mxfs_tauth_page_off(s->npages, page_id, 0), ca);
	if (ra == 0 && mxfs_tauth_page_valid(ca, page_id, s->fs_gen, tauth_crc))
		sa = ca->hdr.seq;
	rb = tauth_read_block(s, mxfs_tauth_page_off(s->npages, page_id, 1), cb);
	if (rb == 0 && mxfs_tauth_page_valid(cb, page_id, s->fs_gen, tauth_crc))
		sb = cb->hdr.seq;
	ph_add(&s->ph_read_ms, &s->ph_read_max, t0);
	if ((ra && !sb) || (rb && !sa))
		return -EIO;    /* an unreadable copy that might hold the truth: no safe base */
	if (!sa && !sb) {
		/* no valid copy: the repair path — the CALLER decided the content
		 * (e.g. every entry UNKNOWN); the store never invents FREE.  Only
		 * an image derived from "nothing" (base 0/0) may repair. */
		s->repairs++;
		cur_seq = 0;
	} else if (sa && sb && sa == sb && memcmp(ca, cb, sizeof(*ca)) != 0) {
		/* pre-ticket era conflict: two writers raced the same seq.  The
		 * page is UNKNOWN; only a repair image (base 0/0) may overwrite. */
		s->conflicts++;
		cur_seq = 0;
	} else {
		cur_seq = sa > sb ? sa : sb;
		cur_nonce = (sa > sb ? ca : cb)->hdr.write_nonce;
	}
	if (pg->hdr.seq != cur_seq || (cur_seq && pg->hdr.write_nonce != cur_nonce)) {
		s->stale_bases++;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "tauth: P-TAUTH-STALE-BASE page=%u base=%llu/%#x platter=%llu/%#x "
			     "-- the image was derived from a superseded commit; refused",
			     page_id, (unsigned long long)pg->hdr.seq, pg->hdr.write_nonce,
			     (unsigned long long)cur_seq, cur_nonce);
		return -ESTALE;
	}
	next = cur_seq + 1;
	if (next == 0 || next == ~0ULL)
		return -EOVERFLOW;
	/* write the copy that does NOT hold the truth */
	target = (sa > sb) ? 1 : 0;
	if (sa == sb && sa != 0)
		target = 1;     /* identical committed images: B is the spare */
	spare = target ? cb : ca;
	ws->target = target;
	ws->next = next;
	ws->off = s->base + mxfs_tauth_page_off(s->npages, page_id, target);

	/* 2. a live ticket on the spare? */
	{
		const struct mxfs_tauth_ticket *lt = (const struct mxfs_tauth_ticket *)spare;

		if (mxfs_tauth_ticket_valid(lt, page_id, s->fs_gen, tauth_crc)) {
			if (lt->writer_node == s->local_node && lt->writer_inc == s->local_inc) {
				s->ticket_resumes++;
			} else if (s->fenced_cb &&
				   s->fenced_cb(s->fenced_data, lt->writer_node, lt->writer_inc)) {
				s->ticket_takeovers++;
				mxfs_pal_log(MXFS_LOG_WARN,
					     "tauth: P-TAUTH-TICKET-TAKEOVER page=%u copy=%u writer=%u/%llu "
					     "seq=%llu -- abandoned by a fenced incarnation",
					     page_id, target, lt->writer_node,
					     (unsigned long long)lt->writer_inc,
					     (unsigned long long)lt->proposed_seq);
			} else {
				s->ticket_busy++;
				return -EBUSY;
			}
		}
	}
	memcpy(ws->spare0, spare, MXFS_TAUTH_TICKET_BYTES);

	/* the ticket that acquires the spare (3.) */
	memset(tk, 0, sizeof(*tk));
	tk->magic = MXFS_TAUTH_TICKET_MAGIC;
	tk->version = MXFS_TAUTH_VERSION;
	tk->page_id = page_id;
	tk->fs_gen = s->fs_gen;
	tk->proposed_seq = next;
	tk->base_seq = cur_seq;
	tk->base_nonce = cur_nonce;
	tauth_next_nonce(s, &tk->ticket_nonce);
	tk->writer_node = s->local_node;
	tk->writer_inc = s->local_inc;
	tk->stamp_ms = mxfs_pal_time_ms();
	tk->crc32c = mxfs_tauth_ticket_crc(tk, tauth_crc);
	return 0;
}

/* 3. the ticket swap, through the store's test knob (ticket_fail_once_rc) */
static int tauth_ticket_swap(struct mxfs_tauth_store *s, const struct mxfs_tauth_wslot *ws)
{
	int knob = s->ticket_fail_once_rc;
	int rc = 0;

	if (!knob || s->ticket_fail_landed)
		rc = mxfs_pal_bdev_compare_and_write(s->dev, ws->off, ws->spare0, &ws->tk);
	if (knob) {
		s->ticket_fail_once_rc = 0;
		rc = knob;
	}
	return rc;
}

/* 3. what the ticket swap's outcome means for the commit */
static int tauth_ticket_result(struct mxfs_tauth_store *s, uint32_t page_id,
			       const struct mxfs_tauth_wslot *ws, int rc)
{
	if (rc == -EAGAIN) {
		s->stale_bases++;
		return -ESTALE;     /* another writer took the spare first */
	}
	if (rc) {
		if (rc == -EBADE)
			s->target_refused++;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-TICKET-FAIL page=%u copy=%u seq=%llu rc=%d",
			     page_id, ws->target, (unsigned long long)ws->next, rc);
	}
	return rc;
}

/* 4. the image under the ticket: its header, stamped for this commit */
static void tauth_write_stamp(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
			      uint64_t next, uint64_t authority_epoch,
			      uint64_t config_epoch)
{
	pg->hdr.magic       = MXFS_TAUTH_PAGE_MAGIC;
	pg->hdr.version     = MXFS_TAUTH_VERSION;
	pg->hdr.nentries    = MXFS_TAUTH_ENTRIES_PER_PAGE;
	pg->hdr.fs_gen      = s->fs_gen;
	pg->hdr.seq         = next;
	pg->hdr.authority_epoch = authority_epoch;
	pg->hdr.config_epoch = config_epoch;
	pg->hdr.writer_node = s->local_node;
	pg->hdr.writer_inc  = s->local_inc;
	pg->hdr.stamp_ms    = mxfs_pal_time_ms();
	tauth_next_nonce(s, &pg->hdr.write_nonce);
	memcpy(pg->hdr.fs_uuid, s->fs_uuid, 16);
	pg->hdr.crc32c      = mxfs_tauth_page_crc(pg, tauth_crc);
}

static int tauth_body_result(struct mxfs_tauth_store *s, uint32_t page_id,
			     const struct mxfs_tauth_wslot *ws, int rc)
{
	if (rc == -EBADE)
		s->target_refused++;
	mxfs_pal_log(MXFS_LOG_ERR,
		     "tauth: P-TAUTH-WRITE-FAIL page=%u copy=%u seq=%llu rc=%d",
		     page_id, ws->target, (unsigned long long)ws->next, rc);
	return rc;
}

/* 5. what the publish swap's outcome means for the commit */
static int tauth_publish_result(struct mxfs_tauth_store *s, uint32_t page_id,
				const struct mxfs_tauth_wslot *ws, int rc)
{
	if (rc == -EAGAIN) {
		s->stolen++;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-TICKET-STOLEN page=%u copy=%u seq=%llu -- our commit "
			     "ticket was taken over while we were live (fencing fault); NOT durable",
			     page_id, ws->target, (unsigned long long)ws->next);
		return -EIO;
	}
	if (rc) {
		if (rc == -EBADE)
			s->target_refused++;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "tauth: P-TAUTH-PUBLISH-FAIL page=%u copy=%u seq=%llu rc=%d -- uncertain",
			     page_id, ws->target, (unsigned long long)ws->next, rc);
		return -EIO;
	}
	return 0;
}

/* 6. read back the copy we published (into scratch): durable means
 * "validates from the platter", not "the write returned" */
static int tauth_write_verify(struct mxfs_tauth_store *s, const struct mxfs_tauth_page *pg,
			      const struct mxfs_tauth_wslot *ws, struct mxfs_tauth_page *scratch)
{
	uint32_t page_id = pg->hdr.page_id;
	int rc;

	rc = tauth_read_block(s, mxfs_tauth_page_off(s->npages, page_id, ws->target), scratch);
	if (rc == 0 && mxfs_tauth_page_valid(scratch, page_id, s->fs_gen, tauth_crc) &&
	    scratch->hdr.seq == ws->next && memcmp(scratch, pg, sizeof(*pg)) == 0)
		return 0;
	if (rc == 0) {
		const struct mxfs_tauth_ticket *lt = (const struct mxfs_tauth_ticket *)scratch;

		if ((mxfs_tauth_page_valid(scratch, page_id, s->fs_gen, tauth_crc) &&
		     scratch->hdr.seq > ws->next) ||
			(mxfs_tauth_ticket_valid(lt, page_id, s->fs_gen, tauth_crc) &&
			 lt->base_seq >= ws->next)) {
			/* a later commit already reused our copy: ours was published */
			s->superseded++;
			return 0;
		}
		rc = -EIO;
	}
	mxfs_pal_log(MXFS_LOG_ERR,
		     "tauth: P-TAUTH-VERIFY-FAIL page=%u copy=%u seq=%llu rc=%d "
		     "-- the published copy does not validate; transition NOT durable",
		     page_id, ws->target, (unsigned long long)ws->next, rc);
	return rc;
}

int mxfs_tauth_page_write(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
			  uint64_t authority_epoch, uint64_t config_epoch,
			  uint32_t torn_after_bytes)
{
	struct mxfs_tauth_page *ca, *cb;
	struct mxfs_tauth_wslot *ws;
	uint32_t page_id;
	uint64_t t0;
	int rc;

	if (!s || !s->dev || !pg)
		return -EINVAL;
	page_id = pg->hdr.page_id;
	if (page_id >= s->npages)
		return -EINVAL;
	ca = mxfs_pal_alloc(sizeof(*ca));
	cb = mxfs_pal_alloc(sizeof(*cb));
	ws = mxfs_pal_alloc(sizeof(*ws));
	if (!ca || !cb || !ws) {
		rc = -ENOMEM;
		goto out;
	}
	/* 1-2. */
	rc = tauth_write_prepare(s, pg, ca, cb, ws);
	if (rc)
		goto out;
	/* 3-5 as one swap where one swap can write the page (span_commit); a
	 * torn-write test commit keeps the ticket protocol it models */
	if (s->span_commit && !torn_after_bytes) {
		s->writes++;
		tauth_write_stamp(s, pg, ws->next, authority_epoch, config_epoch);
		t0 = mxfs_pal_time_ms();
		rc = mxfs_pal_bdev_compare_and_write_span(s->dev, ws->off, ws->spare0, pg,
							   MXFS_TAUTH_PAGE_BYTES);
		ph_add(&s->ph_publish_ms, &s->ph_publish_max, t0);
		if (rc == -EOPNOTSUPP) {
			/* nothing issued: this device's swaps cover one sector */
			s->span_commit = false;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "tauth: P-TAUTH-SPAN-UNSUPPORTED page=%u -- the device "
				     "cannot write a page in one swap; ticket commits from here",
				     page_id);
		} else {
			if (rc == -EAGAIN) {
				/* nothing written: another writer changed the spare first */
				s->stale_bases++;
				rc = -ESTALE;
				goto out;
			}
			/* any other failure: the copy is the new image, torn, or the
			 * old one, as after a failed publish */
			rc = tauth_publish_result(s, page_id, ws, rc);
			if (rc)
				goto out;
			if (!s->fua_durable) {
				t0 = mxfs_pal_time_ms();
				rc = mxfs_pal_bdev_flush(s->dev);
				ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
				if (rc) {
					rc = -EIO;
					goto out;
				}
			}
			s->ph_commits++;
			s->span_commits++;
			rc = tauth_write_verify(s, pg, ws, ca);
			goto out;
		}
	}
	/* 3. acquire the spare */
	s->writes++;
	t0 = mxfs_pal_time_ms();
	rc = tauth_ticket_swap(s, ws);
	ph_add(&s->ph_ticket_ms, &s->ph_ticket_max, t0);
	rc = tauth_ticket_result(s, page_id, ws, rc);
	if (rc)
		goto out;
	if (!s->fua_durable) {
		t0 = mxfs_pal_time_ms();
		rc = mxfs_pal_bdev_flush(s->dev);
		ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
		if (rc)
			goto out;
	}

	/* 4. the image + its body */
	tauth_write_stamp(s, pg, ws->next, authority_epoch, config_epoch);
	if (torn_after_bytes) {
		/* TEST: a partial body, no publish, no verify — the ticket stays
		 * (a crashed writer).  Sector-aligned so the PAL never sees a
		 * sub-sector bio (the trap). */
		uint32_t n = torn_after_bytes & ~511u;

		if (n > MXFS_TAUTH_PAGE_BYTES - MXFS_TAUTH_TICKET_BYTES)
			n = MXFS_TAUTH_PAGE_BYTES - MXFS_TAUTH_TICKET_BYTES;
		if (n)
			(void)mxfs_pal_bdev_write(s->dev, ws->off + MXFS_TAUTH_TICKET_BYTES,
						  (const uint8_t *)pg + MXFS_TAUTH_TICKET_BYTES, n);
		rc = -EIO;
		goto out;
	}
	t0 = mxfs_pal_time_ms();
	rc = mxfs_pal_bdev_write_fua(s->dev, ws->off + MXFS_TAUTH_TICKET_BYTES,
				     (const uint8_t *)pg + MXFS_TAUTH_TICKET_BYTES,
				     MXFS_TAUTH_PAGE_BYTES - MXFS_TAUTH_TICKET_BYTES);
	ph_add(&s->ph_body_ms, &s->ph_body_max, t0);
	if (rc == 0 && !s->fua_durable) {
		t0 = mxfs_pal_time_ms();
		rc = mxfs_pal_bdev_flush(s->dev);
		ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
	}
	if (rc) {
		rc = tauth_body_result(s, page_id, ws, rc);
		goto out;
	}
	/* 5. publish */
	t0 = mxfs_pal_time_ms();
	rc = mxfs_pal_bdev_compare_and_write(s->dev, ws->off, &ws->tk, pg);
	ph_add(&s->ph_publish_ms, &s->ph_publish_max, t0);
	rc = tauth_publish_result(s, page_id, ws, rc);
	if (rc)
		goto out;
	if (!s->fua_durable) {
		t0 = mxfs_pal_time_ms();
		rc = mxfs_pal_bdev_flush(s->dev);
		ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
	}
	s->ph_commits++;
	if (rc) {
		rc = -EIO;
		goto out;
	}
	/* 6. */
	rc = tauth_write_verify(s, pg, ws, ca);
out:
	mxfs_pal_free(ca);
	mxfs_pal_free(cb);
	mxfs_pal_free(ws);
	return rc;
}

/* The PAL vectors for one phase of a batched commit, one entry per page. */
struct tauth_wvec {
	uint64_t     off[MXFS_TAUTH_WRITE_BATCH];
	const void  *cmp[MXFS_TAUTH_WRITE_BATCH];
	const void  *wr[MXFS_TAUTH_WRITE_BATCH];
	void        *buf[MXFS_TAUTH_WRITE_BATCH];
	uint32_t     len[MXFS_TAUTH_WRITE_BATCH];
	int          rc[MXFS_TAUTH_WRITE_BATCH];
	int          idx[MXFS_TAUTH_WRITE_BATCH];
};

/* Steps 1-2 for one page of a batch: see tauth_store.h. */
int mxfs_tauth_page_write_base(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
			       struct mxfs_tauth_wslot *ws)
{
	struct mxfs_tauth_page *ca, *cb;
	int rc;

	if (!s || !s->dev || !pg || !ws || pg->hdr.page_id >= s->npages)
		return -EINVAL;
	ca = mxfs_pal_alloc(sizeof(*ca));
	cb = mxfs_pal_alloc(sizeof(*cb));
	if (!ca || !cb)
		rc = -ENOMEM;
	else
		rc = tauth_write_prepare(s, pg, ca, cb, ws);
	mxfs_pal_free(ca);
	mxfs_pal_free(cb);
	return rc;
}

/* Step 6 for one page of a batch whose barriers left its rc 0. */
int mxfs_tauth_page_write_readback(struct mxfs_tauth_store *s,
				   const struct mxfs_tauth_page *pg,
				   const struct mxfs_tauth_wslot *ws)
{
	struct mxfs_tauth_page *scratch;
	int rc;

	if (!s || !s->dev || !pg || !ws)
		return -EINVAL;
	scratch = mxfs_pal_alloc(sizeof(*scratch));
	if (!scratch)
		return -EIO;    /* published, and not proven: the uncertain outcome */
	rc = tauth_write_verify(s, pg, ws, scratch);
	mxfs_pal_free(scratch);
	return rc;
}

/* Steps 3-5 for every page of a batch whose w[i].rc is 0: see tauth_store.h. */
void mxfs_tauth_page_write_barriers(struct mxfs_tauth_store *s, struct mxfs_tauth_wreq *w,
				    struct mxfs_tauth_wslot *const *ws, int n,
				    uint64_t config_epoch, bool fua_body)
{
	struct tauth_wvec *v;
	uint64_t t0;
	int i, k, m, knob;

	if (!s || !s->dev || !w || !ws || n <= 0 || n > (int)MXFS_TAUTH_WRITE_BATCH)
		return;
	v = mxfs_pal_alloc(sizeof(*v));
	if (!v) {
		/* nothing issued: no ticket, so nothing written */
		for (i = 0; i < n; i++)
			if (!w[i].rc)
				w[i].rc = -ENOMEM;
		return;
	}

	/* 3. every spare acquired: the ticket swaps queued together.  The test
	 * knob takes the first page's swap, by tauth_ticket_swap's rule. */
	knob = s->ticket_fail_once_rc;
	s->ticket_fail_once_rc = 0;
	for (m = 0, i = 0; i < n; i++) {
		if (w[i].rc)
			continue;
		if (knob && !s->ticket_fail_landed) {
			w[i].rc = tauth_ticket_result(s, w[i].pg->hdr.page_id, ws[i], knob);
			knob = 0;
			continue;
		}
		v->off[m] = ws[i]->off;
		v->cmp[m] = ws[i]->spare0;
		v->wr[m] = &ws[i]->tk;
		v->idx[m++] = i;
	}
	if (!m)
		goto out;
	s->writes += (uint64_t)m;
	t0 = mxfs_pal_time_ms();
	k = mxfs_pal_bdev_compare_and_write_many(s->dev, m, v->off, v->cmp, v->wr, v->rc);
	ph_add(&s->ph_ticket_ms, &s->ph_ticket_max, t0);
	if (knob)
		v->rc[0] = knob;        /* issued, and its answer lost */
	for (i = 0; i < m; i++)
		w[v->idx[i]].rc = tauth_ticket_result(s, w[v->idx[i]].pg->hdr.page_id,
						      ws[v->idx[i]], k ? k : v->rc[i]);
	/* ... and ONE flush orders every ticket before any body byte (none when
	 * the swaps' writes are durable as they complete: fua_durable) */
	for (m = 0, i = 0; i < n; i++)
		if (!w[i].rc)
			v->idx[m++] = i;
	if (!m)
		goto out;
	t0 = mxfs_pal_time_ms();
	k = s->fua_durable ? 0 : mxfs_pal_bdev_flush(s->dev);
	ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
	if (k) {
		for (i = 0; i < m; i++)
			w[v->idx[i]].rc = k;
		goto out;
	}

	/* 4. every image stamped and its body written, then ONE flush */
	for (i = 0; i < m; i++) {
		int p = v->idx[i];

		tauth_write_stamp(s, w[p].pg, ws[p]->next, w[p].authority_epoch, config_epoch);
		v->off[i] = ws[p]->off + MXFS_TAUTH_TICKET_BYTES;
		v->buf[i] = (uint8_t *)w[p].pg + MXFS_TAUTH_TICKET_BYTES;
		v->len[i] = MXFS_TAUTH_PAGE_BYTES - MXFS_TAUTH_TICKET_BYTES;
	}
	t0 = mxfs_pal_time_ms();
	if (fua_body)
		k = mxfs_pal_bdev_write_scatter_fua(s->dev, v->off, v->buf, v->len, m);
	else
		k = mxfs_pal_bdev_write_scatter_prio(s->dev, v->off, v->buf, v->len, m);
	ph_add(&s->ph_body_ms, &s->ph_body_max, t0);
	t0 = mxfs_pal_time_ms();
	/* a FUA body on a fua_durable device is durable already; a body written
	 * without FUA is made durable by this flush alone */
	if (k == 0 && !(fua_body && s->fua_durable))
		k = mxfs_pal_bdev_flush(s->dev);
	ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
	if (k) {
		/* the scatter reports one result for all of them: every body
		 * is in doubt, and no publish follows */
		for (i = 0; i < m; i++)
			w[v->idx[i]].rc = tauth_body_result(s, w[v->idx[i]].pg->hdr.page_id,
							    ws[v->idx[i]], k);
		goto out;
	}

	/* 5. every publish queued together, then ONE flush */
	for (i = 0; i < m; i++) {
		int p = v->idx[i];

		v->off[i] = ws[p]->off;
		v->cmp[i] = &ws[p]->tk;
		v->wr[i] = w[p].pg;
	}
	t0 = mxfs_pal_time_ms();
	k = mxfs_pal_bdev_compare_and_write_many(s->dev, m, v->off, v->cmp, v->wr, v->rc);
	ph_add(&s->ph_publish_ms, &s->ph_publish_max, t0);
	for (i = 0; i < m; i++)
		w[v->idx[i]].rc = tauth_publish_result(s, w[v->idx[i]].pg->hdr.page_id,
						       ws[v->idx[i]], k ? k : v->rc[i]);
	for (m = 0, i = 0; i < n; i++)
		if (!w[i].rc)
			v->idx[m++] = i;
	if (!m)
		goto out;
	t0 = mxfs_pal_time_ms();
	k = s->fua_durable ? 0 : mxfs_pal_bdev_flush(s->dev);
	ph_add(&s->ph_flush_ms, &s->ph_flush_max, t0);
	s->ph_commits += (uint64_t)m;
	if (k)
		for (i = 0; i < m; i++)
			w[v->idx[i]].rc = -EIO;
out:
	mxfs_pal_free(v);
}

int mxfs_tauth_page_write_many(struct mxfs_tauth_store *s, struct mxfs_tauth_wreq *w,
			       int n, uint64_t config_epoch)
{
	struct mxfs_tauth_wslot *ws, *wsp[MXFS_TAUTH_WRITE_BATCH];
	int i;

	if (!s || !s->dev || !w || n <= 0 || n > (int)MXFS_TAUTH_WRITE_BATCH)
		return -EINVAL;
	ws = mxfs_pal_alloc(sizeof(*ws) * (size_t)n);
	if (!ws) {
		for (i = 0; i < n; i++)
			w[i].rc = -ENOMEM;
		return -ENOMEM;
	}

	/* 1-2. each page's base, its spare and its ticket */
	for (i = 0; i < n; i++) {
		wsp[i] = &ws[i];
		w[i].rc = mxfs_tauth_page_write_base(s, w[i].pg, &ws[i]);
	}
	/* 3-5.  On a fua_durable device the bodies are written FUA: there the
	 * flush after a plain write completes on the local disk alone, which
	 * would leave the peer's copy of each body in its volatile cache when
	 * the publish lands */
	mxfs_tauth_page_write_barriers(s, w, wsp, n, config_epoch, s->fua_durable);
	/* 6. every published copy read back */
	for (i = 0; i < n; i++)
		if (!w[i].rc)
			w[i].rc = mxfs_tauth_page_write_readback(s, w[i].pg, &ws[i]);
	mxfs_pal_free(ws);
	return 0;
}

int mxfs_tauth_store_verify(struct mxfs_tauth_store *s, uint32_t *two,
			    uint32_t *one, uint32_t *none)
{
	struct mxfs_tauth_page *a, *b;
	uint32_t n2 = 0, n1 = 0, n0 = 0, p;
	int rc = 0;

	if (!s || !s->dev)
		return -EINVAL;
	a = mxfs_pal_alloc(sizeof(*a));
	b = mxfs_pal_alloc(sizeof(*b));
	if (!a || !b) {
		rc = -ENOMEM;
		goto out;
	}
	for (p = 0; p < s->npages; p++) {
		uint64_t sa = 0, sb = 0;
		int r;

		r = tauth_page_read_both(s, p, a, b, &sa, &sb, NULL);
		if (r == -EIO) {
			rc = -EIO;
			break;
		}
		if (sa && sb)
			n2++;
		else if (sa || sb)
			n1++;
		else
			n0++;
	}
	if (two)
		*two = n2;
	if (one)
		*one = n1;
	if (none)
		*none = n0;
	if (rc == 0 && n0)
		rc = -EUCLEAN;
out:
	mxfs_pal_free(a);
	mxfs_pal_free(b);
	return rc;
}

/*
 * Bulk read of `n` consecutive pages of one copy into buf.  A failed run is
 * re-read one page at a time so a single bad sector does not hide the other
 * pages of the run; rcs[i] is each page's read outcome.
 */
static void tauth_read_run(struct mxfs_tauth_store *s, uint32_t first,
			   uint32_t n, unsigned copy,
			   struct mxfs_tauth_page *buf, int *rcs)
{
	uint32_t i;
	int rc;

	rc = mxfs_pal_bdev_read_prio(s->dev,
				     s->base + mxfs_tauth_page_off(s->npages, first, copy),
				     buf, n * MXFS_TAUTH_PAGE_BYTES);
	s->reads++;
	if (rc == 0) {
		for (i = 0; i < n; i++)
			rcs[i] = 0;
		return;
	}
	for (i = 0; i < n; i++)
		rcs[i] = tauth_read_block(s, mxfs_tauth_page_off(s->npages, first + i, copy),
					  &buf[i]);
}

/*
 * 0.75.65 (D-0925): 512 KiB per copy per run — the largest single transfer
 * the rig's iSCSI LUN accepts (max_sectors_kb 512; a larger READ(16) is
 * refused and would drop the run to single-page reads).  Measured before
 * this with 64 KiB runs on the 2-node TCP rig (QNAP LUN, 26426 pages): a
 * whole-region scan took 3975..4371 ms (about 50 MiB/s) for every takeover.
 * Contiguous memory that large can be short, so the run size steps down
 * 128 -> 32 -> 16 pages before the one-page fallback.
 */
#define TAUTH_SCAN_RUN_PAGES    128u

int mxfs_tauth_store_scan(struct mxfs_tauth_store *s, uint32_t first,
			  uint32_t count, mxfs_tauth_page_cb cb, void *data)
{
	struct mxfs_tauth_page *ba = NULL, *bb = NULL;
	int *rca, *rcb;
	uint32_t run, p, end;
	bool io_buf = true;

	if (!s || !s->dev || !cb || first > s->npages || count > s->npages - first)
		return -EINVAL;
	for (run = TAUTH_SCAN_RUN_PAGES; run >= 16; run /= 4) {
		ba = mxfs_pal_alloc_io((size_t)run * MXFS_TAUTH_PAGE_BYTES);
		bb = mxfs_pal_alloc_io((size_t)run * MXFS_TAUTH_PAGE_BYTES);
		if (ba && bb)
			break;
		mxfs_pal_free_io(ba);
		mxfs_pal_free_io(bb);
		ba = bb = NULL;
	}
	if (!ba) {
		/* contiguous memory is short: one page per transfer */
		io_buf = false;
		run = 1;
		ba = mxfs_pal_alloc(sizeof(*ba));
		bb = mxfs_pal_alloc(sizeof(*bb));
		if (!ba || !bb) {
			mxfs_pal_free(ba);
			mxfs_pal_free(bb);
			return -ENOMEM;
		}
	}
	rca = mxfs_pal_alloc((size_t)run * sizeof(*rca));
	rcb = mxfs_pal_alloc((size_t)run * sizeof(*rcb));
	if (!rca || !rcb) {
		mxfs_pal_free(rca);
		mxfs_pal_free(rcb);
		if (io_buf) {
			mxfs_pal_free_io(ba);
			mxfs_pal_free_io(bb);
		} else {
			mxfs_pal_free(ba);
			mxfs_pal_free(bb);
		}
		return -ENOMEM;
	}
	end = first + count;
	for (p = first; p < end; p += run) {
		uint32_t n = end - p < run ? end - p : run;
		uint32_t i;

		tauth_read_run(s, p, n, 0, ba, rca);
		tauth_read_run(s, p, n, 1, bb, rcb);
		for (i = 0; i < n; i++) {
			const struct mxfs_tauth_page *a = &ba[i], *b = &bb[i];
			uint32_t page_id = p + i;
			uint64_t sa = 0, sb = 0;

			if (rca[i] == 0 && mxfs_tauth_page_valid(a, page_id, s->fs_gen, tauth_crc))
				sa = a->hdr.seq;
			if (rcb[i] == 0 && mxfs_tauth_page_valid(b, page_id, s->fs_gen, tauth_crc))
				sb = b->hdr.seq;
			if (!sa && !sb) {
				if (rca[i] || rcb[i]) {
					cb(data, page_id, NULL, -EIO);
				} else {
					s->unknown++;
					cb(data, page_id, NULL, -EUCLEAN);
				}
				continue;
			}
			if (!(sa && sb))
				s->torn_seen++;
			if (sa && sa == sb && memcmp(a, b, sizeof(*a)) != 0) {
				s->conflicts++;
				mxfs_pal_log(MXFS_LOG_ERR,
					     "tauth: P-TAUTH-CONFLICT page=%u seq=%llu writers=%u/%llu vs %u/%llu "
					     "-- two valid divergent images (concurrent writers); page UNKNOWN",
					     page_id, (unsigned long long)sa, a->hdr.writer_node,
					     (unsigned long long)a->hdr.writer_inc, b->hdr.writer_node,
					     (unsigned long long)b->hdr.writer_inc);
				cb(data, page_id, NULL, -EUCLEAN);
				continue;
			}
			cb(data, page_id, sb > sa ? b : a, 0);
		}
		mxfs_pal_cond_resched();
	}
	mxfs_pal_free(rca);
	mxfs_pal_free(rcb);
	if (io_buf) {
		mxfs_pal_free_io(ba);
		mxfs_pal_free_io(bb);
	} else {
		mxfs_pal_free(ba);
		mxfs_pal_free(bb);
	}
	return 0;
}
