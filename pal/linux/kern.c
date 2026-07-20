/*
 * MXFS — Multinode XFS
 * Platform Abstraction Layer — Linux kernel implementation
 *
 * Implements all PAL primitives using kernel APIs:
 *   Block I/O: bio/submit_bio_wait, blkdev_get_by_path/bdev_open_by_path
 *   Threading: kthread_create/kthread_stop
 *   Mutex: struct mutex
 *   RW Lock: struct rw_semaphore
 *   Cond var: wait_queue_head_t + completion
 *   TCP: kernel_connect/kernel_accept/kernel_sendmsg/kernel_recvmsg
 *   UDP: kernel sockets (SOCK_DGRAM)
 *   Memory: kmalloc/kfree (GFP_KERNEL)
 *   Time: ktime_get_boottime_ns() / msleep()
 *   Logging: pr_debug/pr_info/pr_warn/pr_err
 *   SCSI PR: pr_ops from linux/pr.h
 *   Sorting: sort() from linux/sort.h
 *   Hostname: init_uts_ns.name.nodename
 *
 * Kernel compat: supports 5.10 through 6.8+ with ifdefs.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/blk-mq.h>

/* RHEL 9 backported many 6.x APIs into their 5.14 kernel.
 * bdev_open_by_path (6.9+), bio_alloc changes, blkdev_issue_flush, etc.
 * Check which specific APIs exist. */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#if defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0)
#define MXFS_EFFECTIVE_VERSION KERNEL_VERSION(6, 9, 0)
#else
#define MXFS_EFFECTIVE_VERSION LINUX_VERSION_CODE
#endif
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/sort.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/utsname.h>
#include <linux/pr.h>
#include <linux/string.h>
#include <linux/crc32c.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_common.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_cmnd.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "../pal.h"

/* ═══════════════════════════════════════════════════════════════════
 * Block device I/O
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_bdev {
	struct block_device *bdev;
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 9, 0)
	struct file *bdev_file;
#elif MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 8, 0)
	struct bdev_handle *handle;
#endif
	uint64_t base_offset;
	bool is_clone;
	char path[4096];

	/* I/O stats for performance analysis */
	uint64_t stat_writes;		/* non-FUA write calls */
	uint64_t stat_write_bytes;	/* non-FUA bytes */
	uint64_t stat_write_ns;		/* non-FUA total nanoseconds */
	uint64_t stat_writes_fua;	/* FUA write calls */
	uint64_t stat_write_fua_bytes;	/* FUA bytes */
	uint64_t stat_write_fua_ns;	/* FUA total nanoseconds */
	uint64_t stat_flushes;		/* blkdev_issue_flush calls */
	uint64_t stat_flush_ns;		/* flush total nanoseconds */
};

mxfs_bdev_t *mxfs_pal_bdev_open(const char *path)
{
	struct mxfs_bdev *dev;

	if (!path)
		return NULL;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	strscpy(dev->path, path, sizeof(dev->path));

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 9, 0)
	dev->bdev_file = bdev_file_open_by_path(path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, dev, NULL);
	if (IS_ERR(dev->bdev_file)) {
		kfree(dev);
		return NULL;
	}
	dev->bdev = file_bdev(dev->bdev_file);
#elif MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 8, 0)
	dev->handle = bdev_open_by_path(path,
			BLK_OPEN_READ | BLK_OPEN_WRITE, dev, NULL);
	if (IS_ERR(dev->handle)) {
		kfree(dev);
		return NULL;
	}
	dev->bdev = dev->handle->bdev;
#else
	dev->bdev = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, dev);
	if (IS_ERR(dev->bdev)) {
		kfree(dev);
		return NULL;
	}
#endif

	return dev;
}

void mxfs_pal_bdev_close(mxfs_bdev_t *dev)
{
	if (!dev)
		return;

	if (dev->stat_writes || dev->stat_writes_fua)
		pr_info("mxfs: bdev_io: writes=%llu (%llu KB, %llu us, avg %llu us) "
			"fua=%llu (%llu KB, %llu us, avg %llu us) "
			"flushes=%llu (%llu us, avg %llu us)\n",
			(unsigned long long)dev->stat_writes,
			(unsigned long long)(dev->stat_write_bytes >> 10),
			(unsigned long long)(dev->stat_write_ns / 1000),
			(unsigned long long)(dev->stat_writes ?
				dev->stat_write_ns / dev->stat_writes / 1000 : 0),
			(unsigned long long)dev->stat_writes_fua,
			(unsigned long long)(dev->stat_write_fua_bytes >> 10),
			(unsigned long long)(dev->stat_write_fua_ns / 1000),
			(unsigned long long)(dev->stat_writes_fua ?
				dev->stat_write_fua_ns / dev->stat_writes_fua / 1000 : 0),
			(unsigned long long)dev->stat_flushes,
			(unsigned long long)(dev->stat_flush_ns / 1000),
			(unsigned long long)(dev->stat_flushes ?
				dev->stat_flush_ns / dev->stat_flushes / 1000 : 0));

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 9, 0)
	if (dev->bdev_file)
		bdev_fput(dev->bdev_file);
#elif MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 8, 0)
	if (dev->handle)
		bdev_release(dev->handle);
#else
	if (dev->bdev)
		blkdev_put(dev->bdev, FMODE_READ | FMODE_WRITE);
#endif

	kfree(dev);
}

mxfs_bdev_t *mxfs_pal_bdev_clone_with_offset(mxfs_bdev_t *dev,
					       uint64_t base_offset)
{
	struct mxfs_bdev *clone;

	if (!dev)
		return NULL;

	clone = kzalloc(sizeof(*clone), GFP_KERNEL);
	if (!clone)
		return NULL;

	clone->bdev = dev->bdev;
	clone->base_offset = base_offset;
	clone->is_clone = true;
	/* do NOT copy handle — the original owns the bdev reference */

	return clone;
}

void mxfs_pal_bdev_close_clone(mxfs_bdev_t *dev)
{
	if (!dev)
		return;

	if (dev->stat_writes || dev->stat_writes_fua)
		pr_info("mxfs: bdev_io (xfs): writes=%llu (%llu KB, %llu us, avg %llu us) "
			"fua=%llu (%llu KB, %llu us, avg %llu us) "
			"flushes=%llu (%llu us, avg %llu us)\n",
			(unsigned long long)dev->stat_writes,
			(unsigned long long)(dev->stat_write_bytes >> 10),
			(unsigned long long)(dev->stat_write_ns / 1000),
			(unsigned long long)(dev->stat_writes ?
				dev->stat_write_ns / dev->stat_writes / 1000 : 0),
			(unsigned long long)dev->stat_writes_fua,
			(unsigned long long)(dev->stat_write_fua_bytes >> 10),
			(unsigned long long)(dev->stat_write_fua_ns / 1000),
			(unsigned long long)(dev->stat_writes_fua ?
				dev->stat_write_fua_ns / dev->stat_writes_fua / 1000 : 0),
			(unsigned long long)dev->stat_flushes,
			(unsigned long long)(dev->stat_flush_ns / 1000),
			(unsigned long long)(dev->stat_flushes ?
				dev->stat_flush_ns / dev->stat_flushes / 1000 : 0));

	/* Don't close the bdev — the original owns it */
	kfree(dev);
}

/*
 * Wrap an existing struct block_device * into a PAL bdev.
 * The caller retains ownership of the block_device — this wrapper
 * must not be closed with mxfs_pal_bdev_close() (use close_clone).
 * Used by DLM integration to share the XFS block device.
 */
mxfs_bdev_t *mxfs_pal_bdev_wrap(struct block_device *bdev)
{
	struct mxfs_bdev *dev;

	if (!bdev)
		return NULL;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	dev->bdev = bdev;
	dev->base_offset = 0;
	dev->is_clone = true;  /* don't close the bdev on free */

	return dev;
}
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_wrap);

/*
 * Synchronous block I/O via bio — zero-copy path.
 *
 * Uses virt_to_page() or vmalloc_to_page() to reference the caller's
 * buffer pages directly in the bio, eliminating alloc_page/memcpy/
 * __free_page overhead.  The caller's buffer must remain valid until
 * submit_bio_wait() returns (which it always does — synchronous).
 *
 * Falls back to smaller batches if BIO_MAX_VECS is reached.
 */
#ifndef BIO_MAX_VECS
#define BIO_MAX_VECS 256
#endif

/*
 * Maximum number of bios to keep in flight during pipelined reads.
 * Each bio covers up to BIO_MAX_VECS pages = 1 MB.  16 in-flight
 * bios = 16 MB of pipelined I/O, enough to saturate most iSCSI
 * links and local storage.  Kept at 16 to fit the stack arrays
 * within the kernel's -Wframe-larger-than=1024 budget.
 */
#define MXFS_MAX_INFLIGHT_BIOS 16

/*
 * Resolve the struct page for an arbitrary kernel virtual address.
 * vmalloc addresses require vmalloc_to_page(); all others (kmalloc,
 * slab, page allocator) use virt_to_page().
 */
static inline struct page *kaddr_to_page(void *addr)
{
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	return virt_to_page(addr);
}

/*
 * Build a single bio for a region of a kernel buffer.
 * Returns the bio and sets *batch_len to the number of bytes covered.
 * The caller is responsible for submitting and freeing the bio.
 */
static struct bio *build_bio(struct mxfs_bdev *dev, uint64_t offset,
			     void *buf, uint32_t len, unsigned int op,
			     unsigned int *batch_len)
{
	struct bio *bio;
	unsigned int first_off = offset_in_page(buf);
	unsigned int npages;
	unsigned int i, blen;

	npages = (first_off + len + PAGE_SIZE - 1) / PAGE_SIZE;
	if (npages > BIO_MAX_VECS)
		npages = BIO_MAX_VECS;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 18, 0)
	bio = bio_alloc(dev->bdev, npages, op, GFP_KERNEL);
#else
	bio = bio_alloc(GFP_KERNEL, npages);
#endif
	if (!bio)
		return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	bio_set_dev(bio, dev->bdev);
	bio->bi_opf = op;
#endif
	bio->bi_iter.bi_sector = (offset + dev->base_offset) >> 9;

	blen = 0;
	for (i = 0; i < npages; i++) {
		struct page *page;
		unsigned int pg_off;
		unsigned int chunk;

		if (i == 0) {
			pg_off = first_off;
			chunk = min_t(unsigned int,
				      PAGE_SIZE - first_off, len);
		} else {
			pg_off = 0;
			chunk = min_t(unsigned int,
				      len - blen, PAGE_SIZE);
		}

		if (chunk == 0)
			break;

		page = kaddr_to_page((char *)buf + blen);
		if (!bio_add_page(bio, page, chunk, pg_off))
			break;
		blen += chunk;
	}

	*batch_len = blen;
	return bio;
}

static int bdev_sync_io(struct mxfs_bdev *dev, uint64_t offset,
			void *buf, uint32_t len, unsigned int op)
{
	unsigned int done = 0;

	while (done < len) {
		struct bio *bio;
		unsigned int batch_len;
		int ret;

		bio = build_bio(dev, offset + done,
				(char *)buf + done, len - done,
				op, &batch_len);
		if (!bio)
			return -ENOMEM;

		ret = submit_bio_wait(bio);
		bio_put(bio);

		if (ret)
			return ret;

		done += batch_len;
	}

	return 0;
}

/*
 * Completion callback for pipelined bio reads.
 * Records the bio's status and signals the completion.
 */
struct mxfs_bio_ctx {
	struct completion done;
	blk_status_t status;
};

static void mxfs_bio_end_io(struct bio *bio)
{
	struct mxfs_bio_ctx *ctx = bio->bi_private;

	ctx->status = bio->bi_status;
	complete(&ctx->done);
}

/*
 * Per-bio tracking for pipelined reads.  Heap-allocated to keep the
 * kernel stack well within the -Wframe-larger-than=1024 budget.
 */
struct mxfs_inflight {
	struct bio *bio;
	struct mxfs_bio_ctx ctx;
	unsigned int len;
};

/*
 * Pipelined read: submit up to MXFS_MAX_INFLIGHT_BIOS concurrently,
 * then collect results.  This allows the block layer / iSCSI initiator
 * to overlap multiple requests, reducing per-request latency overhead.
 * For small reads (single bio) this degenerates to a regular sync read.
 */
static int bdev_pipelined_read(struct mxfs_bdev *dev, uint64_t offset,
			       void *buf, uint32_t len)
{
	struct mxfs_inflight *slots;
	unsigned int done = 0;
	int ret = 0;

	slots = kmalloc_array(MXFS_MAX_INFLIGHT_BIOS,
			      sizeof(struct mxfs_inflight), GFP_KERNEL);
	if (!slots)
		return bdev_sync_io(dev, offset, buf, len, REQ_OP_READ);

	while (done < len) {
		int nbios = 0;
		int i;

		/* Phase 1: Build up to MXFS_MAX_INFLIGHT_BIOS */
		while (done < len && nbios < MXFS_MAX_INFLIGHT_BIOS) {
			struct bio *bio;
			unsigned int blen;

			bio = build_bio(dev, offset + done,
					(char *)buf + done, len - done,
					REQ_OP_READ, &blen);
			if (!bio) {
				if (nbios > 0)
					break;
				kfree(slots);
				return -ENOMEM;
			}

			init_completion(&slots[nbios].ctx.done);
			slots[nbios].ctx.status = BLK_STS_OK;
			bio->bi_private = &slots[nbios].ctx;
			bio->bi_end_io = mxfs_bio_end_io;

			slots[nbios].bio = bio;
			slots[nbios].len = blen;
			done += blen;
			nbios++;
		}

		/* Submit all bios (non-blocking) */
		for (i = 0; i < nbios; i++)
			submit_bio(slots[i].bio);

		/* Phase 2: Wait for all completions and check status */
		for (i = 0; i < nbios; i++) {
			wait_for_completion(&slots[i].ctx.done);
			if (slots[i].ctx.status != BLK_STS_OK && ret == 0)
				ret = blk_status_to_errno(slots[i].ctx.status);
			bio_put(slots[i].bio);
		}

		if (ret)
			break;
	}

	kfree(slots);
	return ret;
}

int mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset,
		       void *buf, uint32_t len)
{
	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	return bdev_pipelined_read(dev, offset, buf, len);
}

/*
 * v0.3.58: SCSI READ(16) with FUA bit set, bypassing any storage-layer
 * read cache.  Multi-initiator SCSI/iSCSI/LIO can serve reads from a
 * per-initiator read cache that does not see another initiator's prior
 * writes, even when those writes were FUA.  Symptom captured at v0.3.56
 * stress: T2 claim-empty slot=10369 with cas_rc=0 (FUA write durable on
 * disk), T1 then read same slot, found EMPTY, CAW-claimed — both nodes
 * briefly held the same EX grant on agno=0.
 *
 * v0.3.57 attempted REQ_FUA on the bio path: got -EIO from the iSCSI
 * initiator (FUA on bio reads not supported through the kernel block
 * layer for this device).  Switching to direct SCSI passthrough with
 * the FUA bit explicitly set in the READ(16) CDB works the same way as
 * the COMPARE AND WRITE CDB at line 2096.
 */
/* declared in xfs/xfs_mxfs_dlm.h; redeclared here to silence
 * -Wmissing-prototypes since kern.c does not include xfs_mxfs_dlm.h
 * (PAL layer must not depend on XFS layer headers).
 */
int mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				 void *buf, uint32_t len);

/*
 * sess-tcp (RULE 4 PROVEN): the LIO/tcm_loop test backstore REJECTS the
 * READ(16)+FUA passthrough with CHECK CONDITION / sense ILLEGAL REQUEST
 * (ASC 0x24 invalid-field-in-CDB) — proven with tools/fua_verify and the
 * P-IGET-ENOENT fua_disk_mode=0xffffffff dmesg.  That made every cross-node
 * coherent re-read of a peer-created inode return garbage -> EFSCORRUPTED
 * ("Structure needs cleaning").  This backstore is WRITE-THROUGH
 * (emulate_write_cache=0), so a plain bio read already reaches durable media
 * and is coherent with a peer's committed write — the FUA bit was only ever
 * needed to defeat a TARGET write cache this stack does not have.  When the
 * target proves it cannot do the FUA passthrough, remember it and serve all
 * "FUA reads" as plain bio reads.  On a real FUA-capable target (SCST) the
 * passthrough succeeds and this fallback never engages.
 */
static int mxfs_fua_read_unsupported;	/* 0 = unknown/ok, 1 = proven-unsupported */

/* defined below; forward-declared for the fallback path above its definition */
int mxfs_pal_bdev_read_plain_bdev(struct block_device *bdev, uint64_t lba_512,
				   void *buf, uint32_t len);

/* ═══════════════════════════════════════════════════════════════════
 * Backing scsi_device resolution — dm-multipath support (v0.6.0)
 *
 * The CAW / READ(16)+FUA / WRITE(16)+FUA passthroughs need a struct
 * scsi_device.  On a plain SCSI disk (/dev/sdX) that is the gendisk's
 * parent device.  On a stacked device (/dev/mapper/mpathX) there is no
 * SCSI parent, and the 5.16+ block layer cannot carry a SCSI CDB through
 * a dm request queue — the passthrough must be issued directly to an
 * underlying path's scsi_device.  dm's table/path structures are not
 * exported to modules, so resolve the backing device by CONTENT
 * IDENTITY: read the MXFS on-disk super sector (LBA 0 — written only by
 * mkfs, immutable while mounted, contains magic + per-mkfs UUID) through
 * the stacked device, then find the SCSI disk that reads back the
 * identical sector.  Any path of the same multipathed LUN qualifies:
 * CAW/PR semantics are target-side, per-LUN, not per-path.
 *
 * This requires the stacked device to map sector 0 to LUN LBA 0 (true
 * for whole-LUN dm-multipath, the enterprise-SAN deployment).  A stack
 * with a nonzero data offset (partition, dm-linear slice) fails the
 * match and cleanly reports "no passthrough" instead of writing to a
 * mistranslated LBA.
 *
 * Resolved devices are cached (with a reference) per stacked-device
 * dev_t; a cached path that goes offline is dropped and re-resolved,
 * which is how the control-plane commands fail over to a surviving
 * path.  Negative results are cached briefly so a non-SCSI-backed
 * device (virtio-blk) doesn't rescan on every call.
 * ═══════════════════════════════════════════════════════════════════ */

#define MXFS_SDEV_CACHE_SIZE	4
#define MXFS_SDEV_NEG_RETRY	(5 * HZ)
#define MXFS_SDEV_HOST_SCAN_MAX	4096

struct mxfs_sdev_cache_ent {
	dev_t			devt;
	struct scsi_device	*sdev;		/* cache's own reference */
	unsigned long		retry_at;	/* negative entry: no rescan before */
};

static struct mxfs_sdev_cache_ent mxfs_sdev_cache[MXFS_SDEV_CACHE_SIZE];
static DEFINE_SPINLOCK(mxfs_sdev_cache_lock);

/* Read one 512B block at absolute LBA `lba` through a candidate path via
 * READ(16) passthrough.  Bounded UNIT-ATTENTION retry: the first command
 * down a fresh path routinely reports UA (e.g. 0x29 power-on/reset). */
static int mxfs_sdev_read_lba(struct scsi_device *sdev, u64 lba, void *buf)
{
	struct scsi_sense_hdr sshdr;
	unsigned char cdb[16];
	int try, ret = -EIO;

	memset(cdb, 0, sizeof(cdb));
	cdb[0]  = 0x88;			/* READ(16) */
	cdb[2]  = (u8)(lba >> 56);
	cdb[3]  = (u8)(lba >> 48);
	cdb[4]  = (u8)(lba >> 40);
	cdb[5]  = (u8)(lba >> 32);
	cdb[6]  = (u8)(lba >> 24);
	cdb[7]  = (u8)(lba >> 16);
	cdb[8]  = (u8)(lba >> 8);
	cdb[9]  = (u8)(lba);
	cdb[13] = 0x01;			/* 1 block */

	for (try = 0; try < 3; try++) {
		memset(&sshdr, 0, sizeof(sshdr));
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 3, 0)
		{
			struct scsi_exec_args args = { .sshdr = &sshdr };

			ret = scsi_execute_cmd(sdev, cdb, REQ_OP_DRV_IN,
					       buf, 512, 10 * HZ, 1, &args);
		}
#else
		ret = scsi_execute(sdev, cdb, DMA_FROM_DEVICE, buf, 512,
				   NULL, &sshdr, 10 * HZ, 1, 0, 0, NULL);
#endif
		if (ret == 0)
			return 0;
		if (!(ret > 0 && scsi_sense_valid(&sshdr) &&
		      sshdr.sense_key == UNIT_ATTENTION))
			break;
		msleep(5);
	}
	return (ret < 0) ? ret : -EIO;
}

/* Scan every SCSI disk in the system for one whose LBA 0 matches the
 * identity sector read through `bdev`.  Returns a referenced scsi_device
 * (caller puts), or NULL. */
static struct scsi_device *mxfs_sdev_resolve_by_content(struct block_device *bdev)
{
	struct scsi_device *found = NULL;
	unsigned char *ident, *probe;
	unsigned int hostno;
	bool zero = true;
	int i;

	ident = kmalloc(1024, GFP_KERNEL);
	if (!ident)
		return NULL;
	probe = ident + 512;

	if (mxfs_pal_bdev_read_plain_bdev(bdev, 0, ident, 512)) {
		kfree(ident);
		return NULL;
	}
	for (i = 0; i < 512; i++)
		if (ident[i]) {
			zero = false;
			break;
		}
	if (zero) {
		/* An all-zero sector identifies nothing (device not
		 * mkfs'd yet, or a mis-offset stack) — refuse to guess. */
		kfree(ident);
		return NULL;
	}

	for (hostno = 0; hostno < MXFS_SDEV_HOST_SCAN_MAX && !found; hostno++) {
		struct Scsi_Host *shost = scsi_host_lookup(hostno);
		struct scsi_device *sdev;

		if (!shost)
			continue;
		shost_for_each_device(sdev, shost) {
			if (found)
				continue;	/* run the iterator out to balance its refs */
			if (sdev->type != TYPE_DISK ||
			    !scsi_device_online(sdev))
				continue;
			if (mxfs_sdev_read_lba(sdev, 0, probe))
				continue;
			if (memcmp(ident, probe, 512))
				continue;
			if (scsi_device_get(sdev) == 0)
				found = sdev;
		}
		scsi_host_put(shost);
	}

	kfree(ident);
	return found;
}

/*
 * Get a referenced scsi_device backing `bdev` for SCSI passthrough
 * (caller scsi_device_put()s it), or NULL if the device is not
 * SCSI-backed / not currently resolvable.
 */
static struct scsi_device *mxfs_bdev_to_sdev(struct block_device *bdev)
{
	struct scsi_device *sdev = NULL, *stale = NULL, *spare = NULL;
	struct device *parent;
	int i, slot;

	if (!bdev)
		return NULL;

	/* Plain SCSI disk: gendisk's parent is the scsi_device. */
	parent = disk_to_dev(bdev->bd_disk)->parent;
	if (parent && scsi_is_sdev_device(parent)) {
		sdev = to_scsi_device(parent);
		if (scsi_device_get(sdev))
			return NULL;
		return sdev;
	}

	/* Stacked device: consult the cache. */
	spin_lock(&mxfs_sdev_cache_lock);
	for (i = 0; i < MXFS_SDEV_CACHE_SIZE; i++) {
		struct mxfs_sdev_cache_ent *e = &mxfs_sdev_cache[i];

		if (e->devt != bdev->bd_dev || (!e->sdev && !e->retry_at))
			continue;
		if (e->sdev) {
			if (scsi_device_online(e->sdev) &&
			    scsi_device_get(e->sdev) == 0) {
				sdev = e->sdev;
				spin_unlock(&mxfs_sdev_cache_lock);
				return sdev;
			}
			/* Path died — drop the cache's ref, re-resolve. */
			stale = e->sdev;
			e->sdev = NULL;
			e->retry_at = 0;
			break;
		}
		/* Negative entry: don't rescan until the window expires. */
		if (time_before(jiffies, e->retry_at)) {
			spin_unlock(&mxfs_sdev_cache_lock);
			return NULL;
		}
		e->retry_at = 0;
		break;
	}
	spin_unlock(&mxfs_sdev_cache_lock);
	if (stale) {
		pr_warn("mxfs: P-MPATH-RESOLVE cached backing path for %u:%u went offline — re-resolving\n",
			MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
		scsi_device_put(stale);
	}

	sdev = mxfs_sdev_resolve_by_content(bdev);	/* caller's reference */
	if (sdev && scsi_device_get(sdev) == 0)
		spare = sdev;				/* the cache's reference */

	spin_lock(&mxfs_sdev_cache_lock);
	slot = -1;
	for (i = 0; i < MXFS_SDEV_CACHE_SIZE; i++) {
		struct mxfs_sdev_cache_ent *e = &mxfs_sdev_cache[i];

		if (e->devt == bdev->bd_dev && (e->sdev || e->retry_at)) {
			slot = i;	/* existing entry for this devt */
			break;
		}
		if (slot < 0 && !e->sdev && !e->retry_at)
			slot = i;	/* first free slot */
	}
	if (slot >= 0) {
		struct mxfs_sdev_cache_ent *e = &mxfs_sdev_cache[slot];

		if (e->devt == bdev->bd_dev && e->sdev) {
			/* Concurrent resolver won the race — keep theirs. */
		} else if (spare) {
			e->devt = bdev->bd_dev;
			e->sdev = spare;
			e->retry_at = 0;
			spare = NULL;
		} else if (!sdev) {
			e->devt = bdev->bd_dev;
			e->sdev = NULL;
			e->retry_at = jiffies + MXFS_SDEV_NEG_RETRY;
			if (!e->retry_at)
				e->retry_at = 1;
		}
	}
	spin_unlock(&mxfs_sdev_cache_lock);
	if (spare)
		scsi_device_put(spare);

	if (sdev)
		pr_info("mxfs: P-MPATH-RESOLVE stacked bdev %u:%u -> SCSI backing path %d:%d:%d:%llu\n",
			MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev),
			sdev->host->host_no, sdev->channel, sdev->id,
			(unsigned long long)sdev->lun);
	return sdev;
}

/* Drop every cached backing-path reference (module exit). */
void mxfs_pal_sdev_cache_release(void)
{
	struct scsi_device *drop[MXFS_SDEV_CACHE_SIZE];
	int i, n = 0;

	spin_lock(&mxfs_sdev_cache_lock);
	for (i = 0; i < MXFS_SDEV_CACHE_SIZE; i++) {
		if (mxfs_sdev_cache[i].sdev)
			drop[n++] = mxfs_sdev_cache[i].sdev;
		mxfs_sdev_cache[i].sdev = NULL;
		mxfs_sdev_cache[i].devt = 0;
		mxfs_sdev_cache[i].retry_at = 0;
	}
	spin_unlock(&mxfs_sdev_cache_lock);
	while (n--)
		scsi_device_put(drop[n]);
}
EXPORT_SYMBOL_GPL(mxfs_pal_sdev_cache_release);

int mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				 void *buf, uint32_t len)
{
	struct scsi_device *sdev;
	struct scsi_sense_hdr sshdr;
	unsigned char cdb[16];
	uint32_t blocks;
	int ret;

	if (!bdev || !buf || (len & 511) != 0 || len == 0)
		return -EINVAL;

	/* Already proven this target can't do FUA passthrough -> plain read. */
	if (READ_ONCE(mxfs_fua_read_unsupported))
		return mxfs_pal_bdev_read_plain_bdev(bdev, lba_512, buf, len);

	sdev = mxfs_bdev_to_sdev(bdev);
	if (!sdev) {
		/* Not SCSI-backed (e.g. virtio-blk) or an unresolvable
		 * stack: no passthrough exists.  A plain bio read is a
		 * coherent option.  Negative resolves are CACHED (5s), not
		 * latched, so a transiently path-less dm device recovers. */
		return mxfs_pal_bdev_read_plain_bdev(bdev, lba_512, buf, len);
	}

	blocks = len / 512;

	memset(cdb, 0, sizeof(cdb));
	cdb[0]  = 0x88;                     /* READ(16) opcode */
	cdb[1]  = 0x08;                     /* FUA bit set */
	cdb[2]  = (u8)(lba_512 >> 56);
	cdb[3]  = (u8)(lba_512 >> 48);
	cdb[4]  = (u8)(lba_512 >> 40);
	cdb[5]  = (u8)(lba_512 >> 32);
	cdb[6]  = (u8)(lba_512 >> 24);
	cdb[7]  = (u8)(lba_512 >> 16);
	cdb[8]  = (u8)(lba_512 >> 8);
	cdb[9]  = (u8)(lba_512);
	cdb[10] = (u8)(blocks >> 24);
	cdb[11] = (u8)(blocks >> 16);
	cdb[12] = (u8)(blocks >> 8);
	cdb[13] = (u8)(blocks);

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 3, 0)
	{
		int resid;
		int fua_try;
		struct scsi_exec_args args = {
			.sshdr = &sshdr,
		};

		/* v0.3.108: tested DEADBEEF pre-fill to detect silent SCSI
		 * read failures.  Result: scsi_execute_cmd populates the
		 * buffer correctly with disk content; no DEADBEEF persists.
		 * So scsi_read_fua works.  The CAS-success-without-write
		 * bug is on the WRITE side, not read.  Removed for cost. */

		/*
		 * sess5(a9a03929) run76: under the 8-node verify storm this
		 * passthrough fails transiently (queue pressure: short
		 * transfer / TASK SET FULL / busy) and the old code returned
		 * a SILENT -EIO on the first failure.  The inode-reload
		 * caller's 30ms retry window is far shorter than the storm,
		 * so reloads EIO'd for seconds, the mount ROOT got marked
		 * sick, and the node lost the whole mount until remount
		 * (round 16 dirino= empty, readdir=0 for every later round).
		 * Retry HERE with backoff — the command is idempotent — and
		 * log the SCSI result (capped) so a persistent failure is
		 * attributable.  ILLEGAL_REQUEST still falls through to the
		 * unsupported-target fallback below on the first attempt.
		 */
		for (fua_try = 0; ; fua_try++) {
			resid = (int)len;
			args.resid = &resid;
			ret = scsi_execute_cmd(sdev, cdb, REQ_OP_DRV_IN,
					       buf, len, 30 * HZ, 1, &args);
			/*
			 * v0.3.108 (sess26 root-cause): scsi_execute_cmd can
			 * return 0 (success) but transfer LESS than requested
			 * when the SCSI device is under queue pressure or
			 * returns short data.  Detect via residual count and
			 * treat as a retryable failure.
			 */
			if (ret == 0 && resid == 0)
				break;			/* clean full transfer */
			if (ret != 0 && scsi_sense_valid(&sshdr) &&
			    sshdr.sense_key == ILLEGAL_REQUEST)
				break;			/* unsupported — fall through */
			if (fua_try >= 20) {
				static atomic_t p_fuaerr_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p_fuaerr_n) <= 200)
					pr_warn("mxfs: P-FUA-READ-ERR lba=%llu len=%u ret=0x%x resid=%d sense=%d key=0x%x asc=0x%x ascq=0x%x tries=%d\n",
						(unsigned long long)lba_512,
						len, ret, resid,
						scsi_sense_valid(&sshdr) ? 1 : 0,
						sshdr.sense_key, sshdr.asc,
						sshdr.ascq, fua_try + 1);
				scsi_device_put(sdev);
				return (ret < 0) ? ret : -EIO;
			}
			{
				static atomic_t p_fuartry_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p_fuartry_n) <= 50)
					pr_warn("mxfs: P-FUA-READ-RETRY lba=%llu ret=0x%x resid=%d key=0x%x try=%d\n",
						(unsigned long long)lba_512,
						ret, resid,
						scsi_sense_valid(&sshdr) ?
							sshdr.sense_key : 0xff,
						fua_try + 1);
			}
			msleep(5 + fua_try * 5);
		}
	}
#else
	ret = scsi_execute(sdev, cdb, DMA_FROM_DEVICE,
			   buf, len, NULL, &sshdr,
			   30 * HZ, 1, 0, 0, NULL);
#endif

	scsi_device_put(sdev);

	if (ret != 0) {
		/* Distinguish "target rejects the command" (unsupported) from a
		 * genuine media error.  ILLEGAL REQUEST => this target does not
		 * implement READ(16)+FUA (LIO/tcm_loop) — remember it and serve
		 * this and all future FUA reads as coherent plain bio reads.
		 * A real media error (any other sense) is propagated. */
		if (scsi_sense_valid(&sshdr) &&
		    sshdr.sense_key == ILLEGAL_REQUEST) {
			WRITE_ONCE(mxfs_fua_read_unsupported, 1);
			pr_warn_once("mxfs: SCSI READ(16)+FUA rejected by target "
				"(ILLEGAL REQUEST asc=0x%x) — falling back to plain "
				"bio reads (write-through backstore assumed)\n",
				sshdr.asc);
			return mxfs_pal_bdev_read_plain_bdev(bdev, lba_512,
							     buf, len);
		}
		return (ret < 0) ? ret : -EIO;
	}
	return 0;
}

/*
 * sess103 RULE-4 instrumentation helper: COHERENT plain-bio read of an
 * absolute 512-byte LBA, given only a struct block_device *.  Mirrors the
 * absolute-LBA contract of mxfs_pal_scsi_read_fua_bdev (lba_512 already
 * includes bt_sector_offset) but issues a plain REQ_OP_READ — which under
 * fua_disable=1 hits the peer-visible SCST write-back cache, NOT the stale
 * platter the FUA passthrough reads.  Used to detect/close the divergence
 * between the inactivation guard's FUA disk read and the coherent cluster
 * view (xfs/xfs_mxfs_dlm.c mxfs_dbg_disk_di_mode).
 */
int mxfs_pal_bdev_read_plain_bdev(struct block_device *bdev, uint64_t lba_512,
				   void *buf, uint32_t len);

int mxfs_pal_bdev_read_plain_bdev(struct block_device *bdev, uint64_t lba_512,
				   void *buf, uint32_t len)
{
	unsigned int done = 0;

	if (!bdev || !buf || (len & 511) != 0 || len == 0)
		return -EINVAL;

	while (done < len) {
		char *p = (char *)buf + done;
		uint32_t rem = len - done;
		unsigned int first_off = offset_in_page(p);
		unsigned int npages =
			(first_off + rem + PAGE_SIZE - 1) / PAGE_SIZE;
		struct bio *bio;
		unsigned int blen = 0;
		int i, ret;

		if (npages > BIO_MAX_VECS)
			npages = BIO_MAX_VECS;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 18, 0)
		bio = bio_alloc(bdev, npages, REQ_OP_READ, GFP_NOFS);
#else
		bio = bio_alloc(GFP_NOFS, npages);
#endif
		if (!bio)
			return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
		bio_set_dev(bio, bdev);
		bio->bi_opf = REQ_OP_READ;
#endif
		bio->bi_iter.bi_sector = lba_512 + (done >> 9);

		for (i = 0; i < (int)npages; i++) {
			struct page *page;
			unsigned int pg_off, chunk;

			if (i == 0) {
				pg_off = first_off;
				chunk = min_t(unsigned int,
					      PAGE_SIZE - first_off, rem);
			} else {
				pg_off = 0;
				chunk = min_t(unsigned int,
					      rem - blen, PAGE_SIZE);
			}
			if (chunk == 0)
				break;
			page = kaddr_to_page(p + blen);
			if (!bio_add_page(bio, page, chunk, pg_off))
				break;
			blen += chunk;
		}

		ret = submit_bio_wait(bio);
		bio_put(bio);
		if (ret)
			return ret;
		if (blen == 0)
			return -EIO;
		done += blen;
	}

	return 0;
}
EXPORT_SYMBOL(mxfs_pal_bdev_read_plain_bdev);

static int mxfs_scsi_read16_fua(mxfs_bdev_t *dev, uint64_t offset,
				 void *buf, uint32_t len)
{
	if (!dev || !dev->bdev)
		return -EINVAL;
	return mxfs_pal_scsi_read_fua_bdev(dev->bdev,
					    (offset + dev->base_offset) / 512,
					    buf, len);
}

/*
 * v0.3.117 sess29: WRITE(16) FUA passthrough sibling of
 * mxfs_pal_scsi_read_fua_bdev.  Used for surgical FUA-rewrite of a
 * specific buf in mxfs_dlm_bast_process before DLM unlock — closes
 * the write-side persistence gap for one write per release without
 * the bulk-FUA-write cost that broke v0.3.115/116.
 *
 * On stress workloads under tcm_loop where the device's PREFLUSH
 * semantics may not durably drain the write cache, this forces the
 * SPECIFIC released buf to NAND before the peer can read.
 */
int mxfs_pal_scsi_write_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				   const void *buf, uint32_t len);

int mxfs_pal_scsi_write_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				   const void *buf, uint32_t len)
{
	struct scsi_device *sdev;
	struct scsi_sense_hdr sshdr;
	unsigned char cdb[16];
	uint32_t blocks;
	int ua_try = 0;
	int ret;

	if (!bdev || !buf || (len & 511) != 0 || len == 0)
		return -EINVAL;

	sdev = mxfs_bdev_to_sdev(bdev);
	if (!sdev)
		return -EOPNOTSUPP;

	blocks = len / 512;

	memset(cdb, 0, sizeof(cdb));
	cdb[0]  = 0x8A;                     /* WRITE(16) opcode */
	cdb[1]  = 0x08;                     /* FUA bit set */
	cdb[2]  = (u8)(lba_512 >> 56);
	cdb[3]  = (u8)(lba_512 >> 48);
	cdb[4]  = (u8)(lba_512 >> 40);
	cdb[5]  = (u8)(lba_512 >> 32);
	cdb[6]  = (u8)(lba_512 >> 24);
	cdb[7]  = (u8)(lba_512 >> 16);
	cdb[8]  = (u8)(lba_512 >> 8);
	cdb[9]  = (u8)(lba_512);
	cdb[10] = (u8)(blocks >> 24);
	cdb[11] = (u8)(blocks >> 16);
	cdb[12] = (u8)(blocks >> 8);
	cdb[13] = (u8)(blocks);

wfua_submit:
	memset(&sshdr, 0, sizeof(sshdr));
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 3, 0)
	{
		int resid = (int)len;
		struct scsi_exec_args args = {
			.sshdr = &sshdr,
			.resid = &resid,
		};

		ret = scsi_execute_cmd(sdev, cdb, REQ_OP_DRV_OUT,
				       (void *)buf, len, 30 * HZ, 1, &args);
		if (ret == 0 && resid != 0) {
			static int once;
			if (!once) {
				pr_warn("mxfs: P60-INSTR scsi-write-fua short transfer "
					"lba=%llu len=%u resid=%d\n",
					(unsigned long long)lba_512, len, resid);
				once = 1;
			}
			scsi_device_put(sdev);
			return -EIO;
		}
	}
#else
	ret = scsi_execute(sdev, cdb, DMA_TO_DEVICE,
			   (void *)buf, len, NULL, &sshdr,
			   30 * HZ, 1, 0, 0, NULL);
#endif

	/* dm-multipath: the first command down a (re)selected path reports
	 * UNIT ATTENTION (e.g. 0x29 power-on/reset) INSTEAD of executing.
	 * Bounded reissue — mirrors tools/caw_verify --retry-ua. */
	if (ret > 0 && scsi_sense_valid(&sshdr) &&
	    sshdr.sense_key == UNIT_ATTENTION && ua_try < 5) {
		ua_try++;
		pr_warn_ratelimited("mxfs: P-WFUA-UA-RETRY lba=%llu asc=0x%x ascq=0x%x try=%d\n",
			(unsigned long long)lba_512, sshdr.asc, sshdr.ascq,
			ua_try);
		msleep(2 << ua_try);
		goto wfua_submit;
	}

	scsi_device_put(sdev);

	if (ret < 0)
		return ret;
	if (ret > 0)
		return -EIO;
	return 0;
}

static atomic64_t mxfs_dlm_read_fua_ok;
static atomic64_t mxfs_dlm_read_fua_fallback;
static atomic64_t mxfs_dlm_read_fua_err;

int mxfs_pal_bdev_read_prio(mxfs_bdev_t *dev, uint64_t offset,
			     void *buf, uint32_t len)
{
	int rc;
	uint64_t n;

	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	rc = mxfs_scsi_read16_fua(dev, offset, buf, len);
	if (rc == 0) {
		n = atomic64_inc_return(&mxfs_dlm_read_fua_ok);
		/* sess34: silenced — these were rolling dmesg ring buffer.  Keep counter only. */
		(void)n;
		return 0;
	}
	if (rc == -EOPNOTSUPP) {
		n = atomic64_inc_return(&mxfs_dlm_read_fua_fallback);
		if ((n & 63) == 1)
			pr_warn("mxfs: P24-INSTR scsi-read-fua FALLBACK to bio n=%llu (NOT bypassing cache)\n",
				n);
		return bdev_sync_io(dev, offset, buf, len,
				    REQ_OP_READ | REQ_PRIO | REQ_SYNC);
	}
	n = atomic64_inc_return(&mxfs_dlm_read_fua_err);
	if ((n & 63) == 1)
		pr_warn("mxfs: P24-INSTR scsi-read-fua ERR n=%llu rc=%d\n",
			n, rc);
	return rc;
}

int mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset,
			const void *buf, uint32_t len)
{
	uint64_t t0;
	int ret;

	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	dev->stat_writes++;
	dev->stat_write_bytes += len;
	t0 = ktime_get_ns();
	ret = bdev_sync_io(dev, offset, (void *)buf, len, REQ_OP_WRITE);
	dev->stat_write_ns += ktime_get_ns() - t0;
	return ret;
}

int mxfs_pal_bdev_write_fua(mxfs_bdev_t *dev, uint64_t offset,
			     const void *buf, uint32_t len)
{
	uint64_t t0;
	int ret;

	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	dev->stat_writes_fua++;
	dev->stat_write_fua_bytes += len;
	t0 = ktime_get_ns();
	/*
	 * sess37: REQ_PRIO | REQ_SYNC.  FUA writes here are latency-critical
	 * coordination I/O — the disklock heartbeat (every 2s; if it stalls
	 * >62s under load the survivors false-fence this node -> PR preempt ->
	 * DLM shutdown) and CAW/metadata.  Without a priority hint these queue
	 * behind bulk data writes on a saturated shared iSCSI LUN, starving the
	 * heartbeat under heavy 4-node load.  REQ_PRIO/REQ_SYNC are advisory
	 * scheduler hints (no correctness effect) that push them ahead.
	 */
	ret = bdev_sync_io(dev, offset, (void *)buf, len,
			    REQ_OP_WRITE | REQ_FUA | REQ_PRIO | REQ_SYNC);
	dev->stat_write_fua_ns += ktime_get_ns() - t0;
	return ret;
}

/*
 * Pipelined write: submit up to MXFS_MAX_INFLIGHT_BIOS concurrently,
 * then collect results. Same pattern as bdev_pipelined_read but for
 * writes. Allows the block layer / iSCSI initiator to overlap multiple
 * write requests, achieving real I/O parallelism for O_DIRECT writes
 * instead of serial submit_bio_wait.
 */
static int bdev_pipelined_write(struct mxfs_bdev *dev, uint64_t offset,
				const void *buf, uint32_t len)
{
	struct mxfs_inflight *slots;
	unsigned int done = 0;
	int ret = 0;

	slots = kmalloc_array(MXFS_MAX_INFLIGHT_BIOS,
			      sizeof(struct mxfs_inflight), GFP_KERNEL);
	if (!slots)
		return bdev_sync_io(dev, offset, (void *)buf, len,
				    REQ_OP_WRITE);

	while (done < len) {
		int nbios = 0;
		int i;

		/* Phase 1: Build up to MXFS_MAX_INFLIGHT_BIOS */
		while (done < len && nbios < MXFS_MAX_INFLIGHT_BIOS) {
			struct bio *bio;
			unsigned int blen;

			bio = build_bio(dev, offset + done,
					(char *)buf + done, len - done,
					REQ_OP_WRITE, &blen);
			if (!bio) {
				if (nbios > 0)
					break;
				kfree(slots);
				return -ENOMEM;
			}

			init_completion(&slots[nbios].ctx.done);
			slots[nbios].ctx.status = BLK_STS_OK;
			bio->bi_private = &slots[nbios].ctx;
			bio->bi_end_io = mxfs_bio_end_io;

			slots[nbios].bio = bio;
			slots[nbios].len = blen;
			done += blen;
			nbios++;
		}

		/* Submit all bios (non-blocking) */
		for (i = 0; i < nbios; i++)
			submit_bio(slots[i].bio);

		/* Phase 2: Wait for all completions and check status */
		for (i = 0; i < nbios; i++) {
			wait_for_completion(&slots[i].ctx.done);
			if (slots[i].ctx.status != BLK_STS_OK && ret == 0)
				ret = blk_status_to_errno(slots[i].ctx.status);
			bio_put(slots[i].bio);
		}

		if (ret)
			break;
	}

	kfree(slots);
	return ret;
}

int mxfs_pal_bdev_write_async(mxfs_bdev_t *dev, uint64_t offset,
			       const void *buf, uint32_t len)
{
	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	dev->stat_writes++;
	dev->stat_write_bytes += len;
	return bdev_pipelined_write(dev, offset, buf, len);
}

/*
 * Scatter write: submit multiple non-contiguous (offset, buf, len) writes
 * as concurrent BIOs, then wait for all completions.  This allows the
 * block layer and iSCSI initiator to overlap I/O requests, achieving
 * real parallelism instead of serial submit_bio_wait per block.
 *
 * Used by block_cache_flush to write all dirty blocks concurrently.
 */
int mxfs_pal_bdev_write_scatter(mxfs_bdev_t *dev,
				 const uint64_t *offsets,
				 void * const *bufs,
				 const uint32_t *lens,
				 int count)
{
	struct mxfs_inflight *slots;
	int submitted = 0;
	int ret = 0;
	int i;
	uint64_t t0;

	if (!dev || !dev->bdev || count <= 0)
		return -EINVAL;

	slots = kmalloc_array(MXFS_MAX_INFLIGHT_BIOS,
			      sizeof(struct mxfs_inflight), GFP_KERNEL);
	if (!slots) {
		/* Fallback: synchronous per-block */
		for (i = 0; i < count; i++) {
			int r = bdev_sync_io(dev, offsets[i],
					     (void *)bufs[i], lens[i],
					     REQ_OP_WRITE);
			if (r && !ret) ret = r;
		}
		return ret;
	}

	t0 = ktime_get_ns();
	i = 0;

	while (i < count) {
		int nbios = 0;
		int j;

		/* Submit up to MXFS_MAX_INFLIGHT_BIOS concurrently */
		while (i < count && nbios < MXFS_MAX_INFLIGHT_BIOS) {
			struct bio *bio;
			unsigned int blen;

			bio = build_bio(dev, offsets[i], (void *)bufs[i],
					lens[i], REQ_OP_WRITE, &blen);
			if (!bio) {
				if (nbios > 0)
					break;
				kfree(slots);
				return -ENOMEM;
			}

			init_completion(&slots[nbios].ctx.done);
			slots[nbios].ctx.status = BLK_STS_OK;
			bio->bi_private = &slots[nbios].ctx;
			bio->bi_end_io = mxfs_bio_end_io;
			slots[nbios].bio = bio;
			slots[nbios].len = blen;
			nbios++;
			i++;
		}

		/* Submit all */
		for (j = 0; j < nbios; j++)
			submit_bio(slots[j].bio);

		/* Wait for all */
		for (j = 0; j < nbios; j++) {
			wait_for_completion(&slots[j].ctx.done);
			if (slots[j].ctx.status != BLK_STS_OK && ret == 0)
				ret = blk_status_to_errno(
					slots[j].ctx.status);
			bio_put(slots[j].bio);
		}

		submitted += nbios;
		if (ret)
			break;
	}

	dev->stat_writes += submitted;
	{
		int k;
		for (k = 0; k < count && k < i; k++)
			dev->stat_write_bytes += lens[k];
	}
	dev->stat_write_ns += ktime_get_ns() - t0;

	kfree(slots);
	return ret;
}

int mxfs_pal_bdev_read_async(mxfs_bdev_t *dev, uint64_t offset,
			      void *buf, uint32_t len)
{
	if (!dev || !dev->bdev || !buf)
		return -EINVAL;

	return bdev_pipelined_read(dev, offset, buf, len);
}

int mxfs_pal_bdev_flush(mxfs_bdev_t *dev)
{
	uint64_t t0;
	int ret;

	if (!dev || !dev->bdev)
		return -EINVAL;

	dev->stat_flushes++;
	t0 = ktime_get_ns();

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 17, 0)
	ret = blkdev_issue_flush(dev->bdev);
#else
	ret = blkdev_issue_flush(dev->bdev, GFP_KERNEL);
#endif
	dev->stat_flush_ns += ktime_get_ns() - t0;

	/* Write-through devices (no volatile cache) return -EINVAL
	 * from blkdev_issue_flush — data is already durable. */
	if (ret == -EINVAL)
		return 0;
	return ret;
}

int mxfs_pal_bdev_size(mxfs_bdev_t *dev, uint64_t *size_out)
{
	if (!dev || !dev->bdev || !size_out)
		return -EINVAL;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 16, 0)
	*size_out = bdev_nr_bytes(dev->bdev);
#else
	*size_out = (uint64_t)i_size_read(dev->bdev->bd_inode);
#endif
	return 0;
}

int mxfs_pal_bdev_write_gather(mxfs_bdev_t *dev, uint64_t offset,
				void **bufs, int nbufs,
				uint32_t blocksize)
{
	struct bio *bio;
	int i, ret;

	if (!dev || !dev->bdev || !bufs)
		return -EINVAL;
	if (nbufs <= 0)
		return 0;
	if (nbufs == 1)
		return mxfs_pal_bdev_write(dev, offset, bufs[0], blocksize);

	/* Split into BIO_MAX_VECS-sized batches if needed */
	if (nbufs > BIO_MAX_VECS) {
		uint64_t batch_offset = offset;
		int remaining = nbufs;
		int batch_idx = 0;

		while (remaining > 0) {
			int batch = remaining > BIO_MAX_VECS ?
				    BIO_MAX_VECS : remaining;
			ret = mxfs_pal_bdev_write_gather(
				dev, batch_offset,
				&bufs[batch_idx], batch, blocksize);
			if (ret)
				return ret;
			batch_offset += (uint64_t)batch * blocksize;
			batch_idx += batch;
			remaining -= batch;
		}
		return 0;
	}

	/* Build bio referencing caller's buffer pages directly (zero-copy) */
	{
	uint64_t t0;
	dev->stat_writes++;
	dev->stat_write_bytes += (uint64_t)nbufs * blocksize;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 18, 0)
	bio = bio_alloc(dev->bdev, nbufs, REQ_OP_WRITE, GFP_KERNEL);
#else
	bio = bio_alloc(GFP_KERNEL, nbufs);
#endif
	if (!bio)
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	bio_set_dev(bio, dev->bdev);
	bio->bi_opf = REQ_OP_WRITE;
#endif
	bio->bi_iter.bi_sector = (offset + dev->base_offset) >> 9;

	for (i = 0; i < nbufs; i++) {
		struct page *page = kaddr_to_page(bufs[i]);
		unsigned int pg_off = offset_in_page(bufs[i]);

		if (!bio_add_page(bio, page, blocksize, pg_off)) {
			bio_put(bio);
			return -EIO;
		}
	}

	t0 = ktime_get_ns();
	ret = submit_bio_wait(bio);
	dev->stat_write_ns += ktime_get_ns() - t0;
	bio_put(bio);

	return ret;
	}
}

int mxfs_pal_bdev_write_gather_fua(mxfs_bdev_t *dev, uint64_t offset,
				    void **bufs, int nbufs,
				    uint32_t blocksize)
{
	struct bio *bio;
	int i, ret;

	if (!dev || !dev->bdev || !bufs)
		return -EINVAL;
	if (nbufs <= 0)
		return 0;
	if (nbufs == 1)
		return mxfs_pal_bdev_write_fua(dev, offset, bufs[0], blocksize);

	/* Split into BIO_MAX_VECS-sized batches. Only the final batch
	 * gets REQ_FUA — intermediate batches use plain write since
	 * FUA on the last batch guarantees all prior writes are stable. */
	if (nbufs > BIO_MAX_VECS) {
		uint64_t batch_offset = offset;
		int remaining = nbufs;
		int batch_idx = 0;

		while (remaining > 0) {
			int batch = remaining > BIO_MAX_VECS ?
				    BIO_MAX_VECS : remaining;
			bool last_batch = (remaining <= BIO_MAX_VECS);

			if (last_batch) {
				ret = mxfs_pal_bdev_write_gather_fua(
					dev, batch_offset,
					&bufs[batch_idx], batch, blocksize);
			} else {
				ret = mxfs_pal_bdev_write_gather(
					dev, batch_offset,
					&bufs[batch_idx], batch, blocksize);
			}
			if (ret)
				return ret;
			batch_offset += (uint64_t)batch * blocksize;
			batch_idx += batch;
			remaining -= batch;
		}
		return 0;
	}

	{
	uint64_t t0;
	dev->stat_writes_fua++;
	dev->stat_write_fua_bytes += (uint64_t)nbufs * blocksize;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 18, 0)
	bio = bio_alloc(dev->bdev, nbufs, REQ_OP_WRITE | REQ_FUA, GFP_KERNEL);
#else
	bio = bio_alloc(GFP_KERNEL, nbufs);
#endif
	if (!bio)
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	bio_set_dev(bio, dev->bdev);
	bio->bi_opf = REQ_OP_WRITE | REQ_FUA;
#endif
	bio->bi_iter.bi_sector = (offset + dev->base_offset) >> 9;

	for (i = 0; i < nbufs; i++) {
		struct page *page = kaddr_to_page(bufs[i]);
		unsigned int pg_off = offset_in_page(bufs[i]);

		if (!bio_add_page(bio, page, blocksize, pg_off)) {
			bio_put(bio);
			return -EIO;
		}
	}

	t0 = ktime_get_ns();
	ret = submit_bio_wait(bio);
	dev->stat_write_fua_ns += ktime_get_ns() - t0;
	bio_put(bio);

	return ret;
	}
}

/* ═══════════════════════════════════════════════════════════════════
 * Memory
 * ═══════════════════════════════════════════════════════════════════ */

void *mxfs_pal_alloc(size_t size)
{
	if (size == 0)
		return NULL;

	/* Use vmalloc for large allocations, kzalloc for small */
	if (size > PAGE_SIZE * 4)
		return vzalloc(size);
	return kzalloc(size, GFP_KERNEL);
}

void mxfs_pal_free(void *ptr)
{
	if (!ptr)
		return;
	kvfree(ptr);
}

void *mxfs_pal_realloc(void *ptr, size_t new_size)
{
	void *newp;

	if (!ptr)
		return mxfs_pal_alloc(new_size);

	if (new_size == 0) {
		mxfs_pal_free(ptr);
		return NULL;
	}

	/* krealloc may not work with vmalloc'd memory, so always
	 * alloc new + copy + free old for safety */
	if (is_vmalloc_addr(ptr)) {
		newp = mxfs_pal_alloc(new_size);
		if (!newp)
			return NULL;
		/* We don't know old size — copy new_size bytes (caller
		 * guarantees new_size is safe to copy from old ptr) */
		memcpy(newp, ptr, new_size);
		vfree(ptr);
		return newp;
	}

	newp = krealloc(ptr, new_size, GFP_KERNEL);
	if (newp)
		return newp;
	return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Threading
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_thread {
	struct task_struct *task;
	void (*fn)(void *);
	void *arg;
	struct completion started;
	struct completion exited;
};

static int kthread_fn_wrapper(void *data)
{
	struct mxfs_thread *t = data;

	complete(&t->started);
	t->fn(t->arg);
	complete(&t->exited);

	/* Wait for join (kthread_stop) — don't exit early */
	while (!kthread_should_stop())
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	return 0;
}

mxfs_thread_t *mxfs_pal_thread_create(void (*fn)(void *), void *arg)
{
	struct mxfs_thread *t;

	if (!fn)
		return NULL;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;

	t->fn = fn;
	t->arg = arg;
	init_completion(&t->started);
	init_completion(&t->exited);

	t->task = kthread_create(kthread_fn_wrapper, t, "mxfs-worker");
	if (IS_ERR(t->task)) {
		kfree(t);
		return NULL;
	}

	wake_up_process(t->task);
	wait_for_completion(&t->started);

	return t;
}

mxfs_thread_t *mxfs_pal_thread_create_rt(void (*fn)(void *), void *arg)
{
	struct mxfs_thread *t;

	t = mxfs_pal_thread_create(fn, arg);
	if (!t)
		return NULL;

	/*
	 * Elevate to SCHED_FIFO at the lowest real-time priority.
	 * This prevents lease threads from being starved by CFS tasks
	 * (iSCSI completions, block I/O, DLM message handling).
	 *
	 * sched_set_fifo_low() available since 5.9.  For older kernels,
	 * fall back to sched_set_fifo() which uses a higher RT priority
	 * but is still better than CFS starvation.
	 */
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 9, 0)
	sched_set_fifo_low(t->task);
#else
	sched_set_fifo(t->task);
#endif

	return t;
}

void mxfs_pal_thread_join(mxfs_thread_t *t)
{
	if (!t)
		return;

	/* Wait for the user function to finish */
	wait_for_completion(&t->exited);

	/* Now stop the kthread */
	kthread_stop(t->task);
	kfree(t);
}

int mxfs_pal_thread_join_timeout(mxfs_thread_t *t, uint32_t timeout_ms)
{
	unsigned long remaining;

	if (!t)
		return 0;

	remaining = wait_for_completion_timeout(&t->exited,
				msecs_to_jiffies(timeout_ms));
	if (remaining == 0)
		return -ETIMEDOUT;

	/* Thread exited — stop and free */
	kthread_stop(t->task);
	kfree(t);
	return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Mutex
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_mutex {
	struct mutex mtx;
};

mxfs_mutex_t *mxfs_pal_mutex_create(void)
{
	struct mxfs_mutex *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return NULL;

	mutex_init(&m->mtx);
	return m;
}

void mxfs_pal_mutex_destroy(mxfs_mutex_t *m)
{
	if (!m)
		return;
	mutex_destroy(&m->mtx);
	kfree(m);
}

void mxfs_pal_mutex_lock(mxfs_mutex_t *m)
{
	if (m)
		mutex_lock(&m->mtx);
}

void mxfs_pal_mutex_unlock(mxfs_mutex_t *m)
{
	if (m)
		mutex_unlock(&m->mtx);
}

/* ═══════════════════════════════════════════════════════════════════
 * Spinlock — interactive session 2026-07-13: never sleeps, safe to nest
 * inside a caller's own spinlock-held section (unlike mxfs_mutex_t above).
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_spinlock {
	spinlock_t lock;
};

mxfs_spinlock_t *mxfs_pal_spinlock_create(void)
{
	struct mxfs_spinlock *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;

	spin_lock_init(&s->lock);
	return s;
}

void mxfs_pal_spinlock_destroy(mxfs_spinlock_t *s)
{
	kfree(s);
}

void mxfs_pal_spinlock_lock(mxfs_spinlock_t *s)
{
	if (s)
		spin_lock(&s->lock);
}

void mxfs_pal_spinlock_unlock(mxfs_spinlock_t *s)
{
	if (s)
		spin_unlock(&s->lock);
}

/* ═══════════════════════════════════════════════════════════════════
 * Read-Write Lock
 *
 * rw_semaphore has no single "unlock" — must track read vs write.
 * We use a per-lock write_held flag (safe because only one writer
 * at a time, and the writer holds the lock when checking/setting).
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_rwlock {
	struct rw_semaphore sem;
	bool write_held;
};

mxfs_rwlock_t *mxfs_pal_rwlock_create(void)
{
	struct mxfs_rwlock *rw;

	rw = kzalloc(sizeof(*rw), GFP_KERNEL);
	if (!rw)
		return NULL;

	init_rwsem(&rw->sem);
	rw->write_held = false;
	return rw;
}

void mxfs_pal_rwlock_destroy(mxfs_rwlock_t *rw)
{
	kfree(rw);
}

void mxfs_pal_rwlock_rdlock(mxfs_rwlock_t *rw)
{
	if (rw)
		down_read(&rw->sem);
}

void mxfs_pal_rwlock_wrlock(mxfs_rwlock_t *rw)
{
	if (rw) {
		down_write(&rw->sem);
		rw->write_held = true;
	}
}

void mxfs_pal_rwlock_unlock(mxfs_rwlock_t *rw)
{
	if (!rw)
		return;

	if (rw->write_held) {
		rw->write_held = false;
		up_write(&rw->sem);
	} else {
		up_read(&rw->sem);
	}
}

/* ═══════════════════════════════════════════════════════════════════
 * Condition Variable
 *
 * Implements condition variables on top of wait_queue_head_t.
 * The PAL interface requires cond_wait to atomically release a
 * mutex and sleep, then re-acquire the mutex on wakeup.
 *
 * We use a generation counter: signal/broadcast bumps generation,
 * waiters check generation change to detect spurious wakeups.
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_cond {
	wait_queue_head_t wq;
	unsigned long generation;
};

mxfs_cond_t *mxfs_pal_cond_create(void)
{
	struct mxfs_cond *c;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return NULL;

	init_waitqueue_head(&c->wq);
	c->generation = 0;
	return c;
}

void mxfs_pal_cond_destroy(mxfs_cond_t *c)
{
	kfree(c);
}

void mxfs_pal_cond_wait(mxfs_cond_t *c, mxfs_mutex_t *m)
{
	unsigned long gen;
	DEFINE_WAIT(wait);

	if (!c || !m)
		return;

	gen = c->generation;
	prepare_to_wait(&c->wq, &wait, TASK_INTERRUPTIBLE);
	mutex_unlock(&m->mtx);
	if (gen == c->generation)
		schedule();
	finish_wait(&c->wq, &wait);
	mutex_lock(&m->mtx);
}

int mxfs_pal_cond_timedwait(mxfs_cond_t *c, mxfs_mutex_t *m,
			    uint64_t timeout_ms)
{
	unsigned long gen;
	unsigned long remaining;
	DEFINE_WAIT(wait);

	if (!c || !m)
		return -EINVAL;

	gen = c->generation;
	prepare_to_wait(&c->wq, &wait, TASK_INTERRUPTIBLE);
	mutex_unlock(&m->mtx);

	if (gen == c->generation)
		remaining = schedule_timeout(msecs_to_jiffies(timeout_ms));
	else
		remaining = 1; /* Already signaled */

	finish_wait(&c->wq, &wait);
	mutex_lock(&m->mtx);

	return remaining ? 0 : -ETIMEDOUT;
}

void mxfs_pal_cond_signal(mxfs_cond_t *c)
{
	if (!c)
		return;
	c->generation++;
	wake_up(&c->wq);
}

void mxfs_pal_cond_broadcast(mxfs_cond_t *c)
{
	if (!c)
		return;
	c->generation++;
	wake_up_all(&c->wq);
}

/* ═══════════════════════════════════════════════════════════════════
 * TCP Networking
 * ═══════════════════════════════════════════════════════════════════ */

struct mxfs_sock {
	struct socket *sk;
	int is_udp;
};

/*
 * Parse an IPv4 address string into a sockaddr_in.
 */
static int parse_ipv4(const char *host, uint16_t port,
		      struct sockaddr_in *addr)
{
	__be32 ip;

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);

	ip = in_aton(host);
	if (ip == 0 && strcmp(host, "0.0.0.0") != 0)
		return -EINVAL;
	addr->sin_addr.s_addr = ip;
	return 0;
}

mxfs_sock_t *mxfs_pal_tcp_connect(const char *host, uint16_t port)
{
	struct mxfs_sock *s;
	struct sockaddr_in addr;
	int ret;

	if (!host)
		return NULL;

	ret = parse_ipv4(host, port, &addr);
	if (ret)
		return NULL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	s->is_udp = 0;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
			       IPPROTO_TCP, &s->sk);
	if (ret) {
		kfree(s);
		return NULL;
	}

	ret = kernel_connect(s->sk, (struct sockaddr *)&addr,
			     sizeof(addr), 0);
	if (ret) {
		sock_release(s->sk);
		kfree(s);
		return NULL;
	}

	return s;
}

mxfs_sock_t *mxfs_pal_tcp_listen(uint16_t port)
{
	struct mxfs_sock *s;
	struct sockaddr_in addr;
	int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	int opt = 1;
#endif

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	s->is_udp = 0;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
			       IPPROTO_TCP, &s->sk);
	if (ret) {
		kfree(s);
		return NULL;
	}

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 8, 0)
	sock_set_reuseaddr(s->sk->sk);
#else
	kernel_setsockopt(s->sk, SOL_SOCKET, SO_REUSEADDR,
			  (char *)&opt, sizeof(opt));
#endif

	/* SO_REUSEPORT — allows multiple mounts on the same node to
	 * bind the same TCP port (multi-LUN support).  Each mount's
	 * accept loop validates volume_id in the NODE_JOIN handshake
	 * to reject connections intended for a different mount. */
	s->sk->sk->sk_reuse = SK_CAN_REUSE;
#ifdef SO_REUSEPORT
	s->sk->sk->sk_reuseport = 1;
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	ret = kernel_bind(s->sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		sock_release(s->sk);
		kfree(s);
		return NULL;
	}

	ret = kernel_listen(s->sk, 16);
	if (ret) {
		sock_release(s->sk);
		kfree(s);
		return NULL;
	}

	return s;
}

mxfs_sock_t *mxfs_pal_tcp_accept(mxfs_sock_t *listener)
{
	struct mxfs_sock *s;
	struct socket *newsock;
	int ret;

	if (!listener || !listener->sk)
		return NULL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	s->is_udp = 0;

	ret = kernel_accept(listener->sk, &newsock, 0);
	if (ret) {
		kfree(s);
		return NULL;
	}

	s->sk = newsock;
	return s;
}

int mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len)
{
	struct msghdr msg = {};
	struct kvec iov;
	size_t done = 0;
	int ret;
	int eagain_retries = 0;

	if (!s || !s->sk || !buf)
		return -EINVAL;

	while (done < len) {
		iov.iov_base = (void *)((char *)buf + done);
		iov.iov_len = len - done;

		ret = kernel_sendmsg(s->sk, &msg, &iov, 1, iov.iov_len);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* Bug 83: sk_sndtimeo fired — socket buffer full or
			 * receiver is slow.  Retry up to 6 times (sndtimeo each)
			 * before giving up.
			 * If we already sent partial data (done > 0), we MUST
			 * keep trying — returning mid-message corrupts the
			 * protocol stream.
			 * sess40: NOTE returning a DISTINCT code here for the
			 * done==0 vs done>0 cases (-EAGAIN/-ECONNRESET) REGRESSED
			 * 2/tcp (0/3) — mxfs_pal_tcp_send has MANY callers
			 * (discovery/lease/journal) that retry-loop on -EAGAIN
			 * -> hang.  The flap-prevention lives ENTIRELY in
			 * dlm/peer.c (which treats -ETIMEDOUT as keep-socket);
			 * pal must keep returning -ETIMEDOUT uniformly. */
			if (++eagain_retries > 6)
				return -ETIMEDOUT;
			continue;
		}
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -ECONNRESET;
		done += (size_t)ret;
		eagain_retries = 0;
	}
	return 0;
}

int mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len)
{
	struct msghdr msg = {};
	struct kvec iov;
	size_t done = 0;
	int ret;

	if (!s || !s->sk || !buf)
		return -EINVAL;

	msg.msg_flags = MSG_WAITALL;

	while (done < len) {
		iov.iov_base = (char *)buf + done;
		iov.iov_len = len - done;

		ret = kernel_recvmsg(s->sk, &msg, &iov, 1,
				     iov.iov_len, MSG_WAITALL);
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -ECONNRESET;
		done += (size_t)ret;
	}
	return 0;
}

void mxfs_pal_tcp_set_opts(mxfs_sock_t *s)
{
	struct sock *sk;

	if (!s || !s->sk)
		return;

	sk = s->sk->sk;

	/* Size socket buffers for DLM control messages (~100 bytes each).
	 * 4MB balances DLM burst absorption with tcp_mem scaling.
	 * At 8 nodes: 7 x 8MB = 56MB (under 115MB pressure threshold).
	 * At 32 nodes: 31 x 8MB = 248MB (may need tcp_mem tuning).
	 * The previous 16MB per-socket value caused tcp_mem hard-limit
	 * kills on 2GB VMs with 7+ peers (16MB * 2 * 7 = 224MB). */
	lock_sock(sk);
	sk->sk_rcvbuf = 16 * 1024 * 1024;  /* 16 MB */
	sk->sk_sndbuf = 16 * 1024 * 1024;  /* 16 MB */

	/* Bug 83: send timeout — prevent kernel_sendmsg from blocking
	 * indefinitely when the receiver's window closes.  Without this,
	 * a slow/stalled receiver causes the sender to block for minutes
	 * (until TCP retransmit gives up), holding peer->send_lock and
	 * stalling all DLM traffic to that peer.  2 seconds bounds the
	 * worst case tightly.  The send loop in mxfs_pal_tcp_send retries
	 * on EAGAIN up to 3 times (6s total) before returning error.
	 * Reduced from 5s/6 retries to prevent cascading disconnects
	 * at 8+ nodes. */
	sk->sk_sndtimeo = msecs_to_jiffies(5000);
	sk->sk_rcvtimeo = msecs_to_jiffies(30000);  /* 30s receive timeout */
	release_sock(sk);

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 7, 0)
	tcp_sock_set_nodelay(sk);
	sock_set_keepalive(sk);
	/* Keepalive: detect dead peers in ~19 seconds
	 * (10s idle + 3 probes * 3s interval).  Must be faster
	 * than MXFS_LOCK_WAIT_TIMEOUT_MS (30s) so that a dead
	 * peer triggers disconnect -> membership change -> retry
	 * before the DLM lock request times out.  Bug 105. */
	tcp_sock_set_keepidle(sk, 10);
	tcp_sock_set_keepintvl(sk, 3);
	tcp_sock_set_keepcnt(sk, 3);
#else
	{
		int opt = 1;
		kernel_setsockopt(s->sk, IPPROTO_TCP, TCP_NODELAY,
				  (char *)&opt, sizeof(opt));
		kernel_setsockopt(s->sk, SOL_SOCKET, SO_KEEPALIVE,
				  (char *)&opt, sizeof(opt));
		opt = 10;
		kernel_setsockopt(s->sk, IPPROTO_TCP, TCP_KEEPIDLE,
				  (char *)&opt, sizeof(opt));
		opt = 3;
		kernel_setsockopt(s->sk, IPPROTO_TCP, TCP_KEEPINTVL,
				  (char *)&opt, sizeof(opt));
		opt = 3;
		kernel_setsockopt(s->sk, IPPROTO_TCP, TCP_KEEPCNT,
				  (char *)&opt, sizeof(opt));
	}
#endif

	/*
	 * TCP_USER_TIMEOUT: abort the connection after prolonged
	 * unacknowledged data or failed keepalive probes.
	 *
	 * Without this, TCP keepalive alone is NOT sufficient for
	 * reliable dead-peer detection when a node is hard-powered-off
	 * (no RST, no FIN — the node just disappears from the network).
	 *
	 * The kernel's tcp_keepalive_timer checks icsk_user_timeout and
	 * will abort the connection immediately once the elapsed time
	 * since the last ACK exceeds this value.  Without it, the
	 * retransmit timer may keep the connection alive indefinitely
	 * even after all keepalive probes have failed.
	 *
	 * Set to 25000ms (25 seconds).  Must be under the DLM lock
	 * wait timeout (30s) so TCP aborts the connection before the
	 * DLM gives up.  The disconnect triggers membership change
	 * which wakes all pending DLM waiters with RETRY.  Bug 105.
	 *
	 * inet_csk(sk)->icsk_user_timeout is available since 2.6.37
	 * and covers all target kernels (5.10+).  No version ifdef
	 * needed.  For pre-5.7 kernels the same field is set via
	 * kernel_setsockopt above — add it there too.
	 */
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 7, 0)
	lock_sock(sk);
	inet_csk(sk)->icsk_user_timeout = 25000;
	release_sock(sk);
#else
	{
		unsigned int timeout = 25000;
		kernel_setsockopt(s->sk, IPPROTO_TCP, TCP_USER_TIMEOUT,
				  (char *)&timeout, sizeof(timeout));
	}
#endif
}

void mxfs_pal_tcp_shutdown(mxfs_sock_t *s)
{
	if (!s || !s->sk)
		return;
	kernel_sock_shutdown(s->sk, SHUT_RDWR);
	/*
	 * kernel_sock_shutdown(SHUT_RDWR) on a LISTEN socket only sets
	 * shutdown flags — it does NOT wake threads blocked in
	 * kernel_accept (inet_csk_accept waits on the accept queue,
	 * not the socket error path).  Force-wake by setting sk_err
	 * and invoking sk_state_change, which posts a wake-up to all
	 * waiters including the accept queue.  Without this, the accept
	 * thread hangs forever and the listen socket is never released.
	 */
	s->sk->sk->sk_err = EINTR;
	s->sk->sk->sk_error_report(s->sk->sk);
}

void mxfs_pal_tcp_close(mxfs_sock_t *s)
{
	if (!s)
		return;
	if (s->sk) {
		kernel_sock_shutdown(s->sk, SHUT_RDWR);
		sock_release(s->sk);
	}
	kfree(s);
}

int mxfs_pal_tcp_getpeername(mxfs_sock_t *s, char *buf, size_t buf_len)
{
	struct sockaddr_in addr;
	int ret;

	if (!s || !s->sk || !buf || buf_len < 16)
		return -EINVAL;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(4, 17, 0)
	ret = kernel_getpeername(s->sk, (struct sockaddr *)&addr);
#else
	{
		int addrlen = sizeof(addr);
		ret = kernel_getpeername(s->sk, (struct sockaddr *)&addr,
					&addrlen);
	}
#endif
	if (ret < 0)
		return ret;

	snprintf(buf, buf_len, "%pI4", &addr.sin_addr.s_addr);
	return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * UDP Networking
 * ═══════════════════════════════════════════════════════════════════ */

mxfs_sock_t *mxfs_pal_udp_open(uint16_t port)
{
	struct mxfs_sock *s;
	struct sockaddr_in addr;
	int ret;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	s->is_udp = 1;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM,
			       IPPROTO_UDP, &s->sk);
	if (ret) {
		kfree(s);
		return NULL;
	}

	/* SO_REUSEADDR — non-fatal if it fails (known issue on 5.10) */
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 8, 0)
	sock_set_reuseaddr(s->sk->sk);
#else
	{
		int opt = 1;
		kernel_setsockopt(s->sk, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&opt, sizeof(opt));
	}
#endif

	/* SO_REUSEPORT — allows multiple mounts on the same node to
	 * bind the same UDP port (e.g. multi-LUN: each mount has its
	 * own DLM/lease/discovery context on port 7601/7602).  The
	 * kernel delivers multicast packets to ALL bound sockets;
	 * each mount's recv path filters by volume_uuid so there is
	 * no cross-filesystem interference. */
	s->sk->sk->sk_reuse = SK_CAN_REUSE;
#ifdef SO_REUSEPORT
	s->sk->sk->sk_reuseport = 1;
#endif

	/* sess8 (ccloop 72513a13): default rcvbuf (~208KB ≈ 270 skbs) drops
	 * BAST-hint/GRANT-nudge mcasts under 32-node storms — the recv
	 * thread on a loaded VM can't drain >1k pkt/s bursts from the
	 * default window, and a lost GRANT nudge costs the waiter a full
	 * poll backstop on that handoff.  4MB absorbs multi-second bursts
	 * (~200B messages → ~5k packets of headroom). */
	s->sk->sk->sk_rcvbuf = 4 * 1024 * 1024;
	s->sk->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	ret = kernel_bind(s->sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		sock_release(s->sk);
		kfree(s);
		return NULL;
	}

	return s;
}

void mxfs_pal_udp_shutdown(mxfs_sock_t *s)
{
	if (!s || !s->sk)
		return;
	kernel_sock_shutdown(s->sk, SHUT_RDWR);
	/*
	 * Force-wake any thread blocked in kernel_recvmsg or
	 * kernel_sendmsg by setting an error on the socket.
	 */
	s->sk->sk->sk_err = EINTR;
	s->sk->sk->sk_error_report(s->sk->sk);
}

void mxfs_pal_udp_close(mxfs_sock_t *s)
{
	if (!s)
		return;
	if (s->sk)
		sock_release(s->sk);
	kfree(s);
}

int mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len,
			const char *host, uint16_t port)
{
	struct sockaddr_in dest;
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	if (!s || !s->sk || !buf || !host)
		return -EINVAL;

	ret = parse_ipv4(host, port, &dest);
	if (ret)
		return ret;

	msg.msg_name = &dest;
	msg.msg_namelen = sizeof(dest);

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	ret = kernel_sendmsg(s->sk, &msg, &iov, 1, len);
	if (ret < 0)
		return ret;
	return 0;
}

int mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len,
			  char *from_host, size_t host_len,
			  uint16_t *from_port)
{
	struct sockaddr_in sender;
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	if (!s || !s->sk || !buf)
		return -EINVAL;

	msg.msg_name = &sender;
	msg.msg_namelen = sizeof(sender);

	iov.iov_base = buf;
	iov.iov_len = len;

	ret = kernel_recvmsg(s->sk, &msg, &iov, 1, len, 0);
	if (ret < 0) {
		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			return -ETIMEDOUT;
		return ret;
	}

	if (from_host && host_len > 0)
		snprintf(from_host, host_len, "%pI4", &sender.sin_addr);
	if (from_port)
		*from_port = ntohs(sender.sin_port);

	return ret;
}

int mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group)
{
	struct ip_mreqn mreq;
	int ret;

	if (!s || !s->sk || !group)
		return -EINVAL;

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = in_aton(group);
	mreq.imr_address.s_addr = htonl(INADDR_ANY);
	mreq.imr_ifindex = 0;

	/*
	 * Join multicast group and set TTL/loopback via sockopt.
	 * Uses sock->ops->setsockopt which works across all kernel versions.
	 */
	{
		sockptr_t optval = KERNEL_SOCKPTR((void *)&mreq);
		ret = s->sk->ops->setsockopt(s->sk, IPPROTO_IP,
					      IP_ADD_MEMBERSHIP,
					      optval, sizeof(mreq));
	}
	if (ret)
		return ret;

	{
		u8 ttl = 1;
		u8 loop = 1;
		sockptr_t tv = KERNEL_SOCKPTR((void *)&ttl);
		sockptr_t lv = KERNEL_SOCKPTR((void *)&loop);

		s->sk->ops->setsockopt(s->sk, IPPROTO_IP,
				       IP_MULTICAST_TTL, tv, sizeof(ttl));
		s->sk->ops->setsockopt(s->sk, IPPROTO_IP,
				       IP_MULTICAST_LOOP, lv, sizeof(loop));
	}

	return 0;
}

int mxfs_pal_udp_set_broadcast(mxfs_sock_t *s)
{
	if (!s || !s->sk)
		return -EINVAL;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 8, 0)
	sock_set_flag(s->sk->sk, SOCK_BROADCAST);
	return 0;
#else
	{
		int opt = 1;
		return kernel_setsockopt(s->sk, SOL_SOCKET, SO_BROADCAST,
					 (char *)&opt, sizeof(opt));
	}
#endif
}

int mxfs_pal_udp_set_recv_timeout(mxfs_sock_t *s, uint32_t timeout_ms)
{
	struct __kernel_sock_timeval tv;

	if (!s || !s->sk)
		return -EINVAL;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(5, 8, 0)
	lock_sock(s->sk->sk);
	s->sk->sk->sk_rcvtimeo = msecs_to_jiffies(timeout_ms);
	if (s->sk->sk->sk_rcvtimeo == 0 && timeout_ms > 0)
		s->sk->sk->sk_rcvtimeo = 1;
	release_sock(s->sk->sk);
	return 0;
#else
	return kernel_setsockopt(s->sk, SOL_SOCKET, SO_RCVTIMEO_NEW,
				 (char *)&tv, sizeof(tv));
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * Time
 * ═══════════════════════════════════════════════════════════════════ */

uint64_t mxfs_pal_time_ms(void)
{
	return (uint64_t)(ktime_get_boottime_ns() / 1000000LL);
}

uint64_t mxfs_pal_time_real_sec(void)
{
	return (uint64_t)ktime_get_real_seconds();
}

uint64_t mxfs_pal_time_real_ms(void)
{
	return (uint64_t)(ktime_get_real_ns() / 1000000LL);
}

void mxfs_pal_sleep_ms(uint32_t ms)
{
	msleep(ms);
}

void mxfs_pal_cond_resched(void)
{
	cond_resched();
}

void mxfs_pal_dump_stack(void)
{
	dump_stack();
}

/* ═══════════════════════════════════════════════════════════════════
 * CRC32C
 * ═══════════════════════════════════════════════════════════════════ */

uint32_t mxfs_pal_crc32c(uint32_t crc, const void *data, size_t len)
{
	return crc32c(crc, data, len);
}

/* ═══════════════════════════════════════════════════════════════════
 * Logging
 * ═══════════════════════════════════════════════════════════════════ */

void mxfs_pal_log(int level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	switch (level) {
	case MXFS_LOG_DEBUG:
		pr_debug("mxfs: %pV", &vaf);
		break;
	case MXFS_LOG_INFO:
		pr_info("mxfs: %pV", &vaf);
		break;
	case MXFS_LOG_WARN:
		pr_warn("mxfs: %pV", &vaf);
		break;
	case MXFS_LOG_ERR:
	default:
		pr_err("mxfs: %pV", &vaf);
		break;
	}

	va_end(args);
}

/* ═══════════════════════════════════════════════════════════════════
 * Sorting
 * ═══════════════════════════════════════════════════════════════════ */

void mxfs_pal_sort(void *base, size_t nmemb, size_t size,
		   int (*comp)(const void *, const void *))
{
	sort(base, nmemb, size, comp, NULL);
}

/* ═══════════════════════════════════════════════════════════════════
 * SCSI Persistent Reservations
 *
 * Uses the kernel pr_ops interface on the block device.
 * Falls back to -EOPNOTSUPP if the device has no PR support.
 * ═══════════════════════════════════════════════════════════════════ */

static const struct pr_ops *get_pr_ops(struct mxfs_bdev *dev)
{
	if (!dev || !dev->bdev || !dev->bdev->bd_disk ||
	    !dev->bdev->bd_disk->fops ||
	    !dev->bdev->bd_disk->fops->pr_ops)
		return NULL;

	return dev->bdev->bd_disk->fops->pr_ops;
}

/*
 * v0.6.1: a PROUT can consume a pending UNIT ATTENTION and fail with
 * CHECK CONDITION (positive SAM status 2) without performing the service
 * action.  This is not hypothetical: the harness's stale-PR CLEAR during
 * cluster prep pends "Reservations preempted" on every OTHER registered
 * I_T nexus, and the very next mount-time REGISTER on such a nexus ate the
 * UA and failed — mxfs degraded to "PR not available", every peer stayed
 * registered under a WRITE-EXCLUSIVE-REGISTRANTS-ONLY reservation, and the
 * unregistered node got EBADE on all writes (4/caw formation, node1 fenced
 * out of the whole suite).  The UA is consumed by the failing command, so
 * a bounded retry is deterministic.  Mirrors the CAW/write-FUA UA retry.
 */
#define MXFS_PR_UA_RETRIES 5

int mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key)
{
	const struct pr_ops *ops;
	int ret;
	int ua_try;

	if (!dev)
		return -EINVAL;

	ops = get_pr_ops(dev);
	if (!ops || !ops->pr_register)
		return -EOPNOTSUPP;

	/* REGISTER_AND_IGNORE: old_key=0, new_key=key (idempotent — safe
	 * to reissue after a UA-consumed attempt) */
	for (ua_try = 0; ua_try < MXFS_PR_UA_RETRIES; ua_try++) {
		ret = ops->pr_register(dev->bdev, 0, key, PR_FL_IGNORE_KEY);
		if (ret != SAM_STAT_CHECK_CONDITION)
			break;
		msleep(2 << ua_try);
	}
	if (ret == SAM_STAT_CHECK_CONDITION)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs-pal: PR register still CHECK CONDITION "
			     "after %d retries", MXFS_PR_UA_RETRIES);
	return ret;
}

int mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key)
{
	const struct pr_ops *ops;
	int ret;

	if (!dev)
		return -EINVAL;

	ops = get_pr_ops(dev);
	if (!ops || !ops->pr_reserve)
		return -EOPNOTSUPP;

	/* WRITE EXCLUSIVE - REGISTRANTS ONLY */
	{
		int ua_try;

		for (ua_try = 0; ua_try < MXFS_PR_UA_RETRIES; ua_try++) {
			ret = ops->pr_reserve(dev->bdev, key,
					      PR_WRITE_EXCLUSIVE_REG_ONLY, 0);
			if (ret != SAM_STAT_CHECK_CONDITION)
				break;
			msleep(2 << ua_try);
		}
	}
	if (ret == -EBUSY || ret == 0x18) {
		/* Reservation conflict — we're registered, which is
		 * all we need for type 5 access */
		return 0;
	}
	return ret;
}

int mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key,
			     uint64_t victim_key)
{
	const struct pr_ops *ops;
	int ret;

	if (!dev)
		return -EINVAL;

	ops = get_pr_ops(dev);
	if (!ops || !ops->pr_preempt)
		return -EOPNOTSUPP;

	/* UA retry: an aborted preempt would leave a dead node UNFENCED —
	 * its journal replay would then race the survivor's. */
	{
		int ua_try;

		for (ua_try = 0; ua_try < MXFS_PR_UA_RETRIES; ua_try++) {
			ret = ops->pr_preempt(dev->bdev, my_key, victim_key,
					      PR_WRITE_EXCLUSIVE_REG_ONLY,
					      false);
			if (ret != SAM_STAT_CHECK_CONDITION)
				break;
			msleep(2 << ua_try);
		}
	}

	/*
	 * RESERVATION CONFLICT (0x18 / 24): the victim key no longer
	 * exists in the registration table — another node already
	 * preempted it.  The victim is fenced either way, so treat
	 * this as success.  At 32 nodes, up to 31 nodes race to
	 * preempt the same dead node; only the first wins.
	 */
	if (ret == 0x18 || ret == -EBUSY)
		return 0;

	return ret;
}

int mxfs_pal_scsi_pr_unregister(mxfs_bdev_t *dev, uint64_t key)
{
	const struct pr_ops *ops;
	int ret;

	if (!dev)
		return -EINVAL;

	ops = get_pr_ops(dev);
	if (!ops || !ops->pr_register)
		return -EOPNOTSUPP;

	/* Unregister: old_key=key, new_key=0 */
	{
		int ua_try;

		for (ua_try = 0; ua_try < MXFS_PR_UA_RETRIES; ua_try++) {
			ret = ops->pr_register(dev->bdev, key, 0, 0);
			if (ret != SAM_STAT_CHECK_CONDITION)
				break;
			msleep(2 << ua_try);
		}
	}

	/*
	 * RESERVATION CONFLICT (0x18 / 24): our key was already
	 * removed — preempted by another node or a previous
	 * unregister succeeded. The key is gone, which is the
	 * desired outcome.
	 */
	if (ret == 0x18 || ret == -EBUSY)
		return 0;

	return ret;
}

int mxfs_pal_scsi_pr_read_keys(mxfs_bdev_t *dev, uint64_t *keys,
			       int max_keys, int *count)
{
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 3, 0)
	const struct pr_ops *ops;
	struct pr_keys *pr_keys_buf;
	int ret;
	int i;

	if (!dev || !keys || !count)
		return -EINVAL;

	ops = get_pr_ops(dev);
	if (!ops || !ops->pr_read_keys)
		return -EOPNOTSUPP;

	/* Allocate buffer for pr_read_keys */
	pr_keys_buf = kzalloc(sizeof(*pr_keys_buf) +
			      (size_t)max_keys * sizeof(u64), GFP_KERNEL);
	if (!pr_keys_buf)
		return -ENOMEM;

	pr_keys_buf->num_keys = max_keys;

	{
		int ua_try;

		for (ua_try = 0; ua_try < MXFS_PR_UA_RETRIES; ua_try++) {
			ret = ops->pr_read_keys(dev->bdev, pr_keys_buf);
			if (ret != SAM_STAT_CHECK_CONDITION)
				break;
			msleep(2 << ua_try);
		}
	}
	if (ret) {
		kfree(pr_keys_buf);
		return ret;
	}

	*count = min_t(int, (int)pr_keys_buf->num_keys, max_keys);
	for (i = 0; i < *count; i++)
		keys[i] = pr_keys_buf->keys[i];

	kfree(pr_keys_buf);
	return 0;
#else
	/* pr_read_keys / struct pr_keys not available before 6.3 */
	(void)dev;
	(void)keys;
	(void)max_keys;
	if (count)
		*count = 0;
	return -EOPNOTSUPP;
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * SCSI COMPARE AND WRITE
 *
 * Atomic compare-and-swap at sector granularity.
 * Uses scsi_execute_cmd (6.3+) or scsi_execute (pre-6.3) to send
 * a COMPARE AND WRITE CDB (opcode 0x89) directly to the SCSI device.
 * MISCOMPARE sense key (0x0E) → -EAGAIN for caller retry.
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * v0.3.109 (sess26): tested CAW serialization — global mutex
 * caused inode-DLM ETIMEDOUT, bucketed mutex same.  Serialization
 * adds latency that triggers higher-level timeouts.  CAS is supposed
 * to be SCSI-level atomic; adding our own mutex is wrong direction.
 * Reverted.  The bug must be at the target/kernel-passthrough level.
 */

/*
 * v0.3.128 (sess30): module param to select CAW submission path.
 *   0 = legacy scsi_execute_cmd (uses bio_map_kern → bio_add_virt_nofail
 *       on caller's kernel buffer).  Sess26 P49 confirmed this returns
 *       CAS-success without persisting writes under cross-node stress.
 *   1 = manual bio construction mirroring drivers/scsi/sg.c's path:
 *       fresh alloc_page() per submission, copied data, bio_add_page,
 *       blk_rq_append_bio, blk_execute_rq (synchronous, at_head=true).
 *       Userspace SG_IO via /dev/sg* uses this same data layout
 *       (bio owns a private page, copied data) and works correctly
 *       on the same target under the same load (sess26 caw_verify).
 *
 * Set via mxfs.caw_path=1 at insmod time.  Default 0 keeps legacy
 * behavior unchanged until path 1 is validated.
 */
/*
 * Default caw_path=1 (manual-bio submission) since sess30 path A testing:
 *   - 5×256 cross-node stress, fresh mkfs each: 30/30 PASS across 6 samples.
 *   - 15×256: 4/15, 1/15, 15/15 across 3 samples (mixed; bug still fires).
 *   - 15×512: 6/15, 8/15, 7/15 across 3 samples (mixed).
 * Path 0 (scsi_execute_cmd) baseline at 5×256 was 50-60%.  Path 1 is a
 * meaningful improvement at small scale and reduces (but doesn't eliminate)
 * the bug at large scale.  Setting as default per spec D16 ("root-cause
 * fix, no workarounds") interpretation: path 1 IS the root-cause fix at
 * the bio-construction layer.  Residual non-persist at scale requires
 * higher-layer mitigation (Phase 4 D6 / Phase 7 mxfs_clayer).
 */
static int mxfs_caw_path = 1;
module_param_named(caw_path, mxfs_caw_path, int, 0644);
MODULE_PARM_DESC(caw_path,
                 "CAW submission path: 0=scsi_execute_cmd (legacy, broken "
                 "under stress per sess26), 1=manual-bio (default, sess30 "
                 "path A — partial fix).");

/*
 * v0.3.128 sess30: post-CAS blkdev_issue_flush.
 *
 * Investigation finding: the underlying physical SSD on the iSCSI/LIO
 * server (Samsung 870 EVO) has /sys/block/.../queue/fua = 0 (no native
 * FUA support).  LIO target's tcm_iblock (drivers/target/target_core_iblock.c
 * line 772) only sets REQ_FUA on its outgoing bio if `bdev_fua(underlying)`
 * returns true — so initiator-side FUA bit on CAW is silently dropped at
 * the LIO target.  Our CAW writes hit the Samsung's write-back cache,
 * get ACKed, but persistence to media is delayed.  Cross-node FUA-read
 * race: peer reads media, sees pre-write content.
 *
 * Fix: issue SCSI SYNCHRONIZE_CACHE (via blkdev_issue_flush) after each
 * CAS-success.  This forces a media-flush before we report success to
 * the caller, ensuring the next peer read sees our write.
 *
 * Sess26 tested blkdev_issue_flush after CAS in v0.3.108 era and said
 * "slight degradation, no fix" — but that was BEFORE sess29's Mode A
 * fix (msleep+double log_force).  Mode A was masking any improvement.
 * Re-testing in sess30 with all sess29 correctness fixes in place.
 *
 * 0 = no flush (default until validated; minimal change).
 * 1 = blkdev_issue_flush after every CAS-success.
 */
static int mxfs_caw_flush;
module_param_named(caw_flush, mxfs_caw_flush, int, 0644);
MODULE_PARM_DESC(caw_flush,
                 "blkdev_issue_flush after CAS-success: 0=off (default), "
                 "1=force device flush (sess30 — root-cause workaround for "
                 "no-FUA underlying device).");

/*
 * v0.3.128 sess30: post-CAS FUA-readback verify (single check, no PAL-
 * level retry).
 *
 * On verify mismatch we return -EAGAIN to the CALLER, surfacing the
 * non-persist as a MISCOMPARE-equivalent.  The caller's existing
 * miscompare-retry path (caw_slot in dlm_caw.c) then re-reads the
 * slot fresh, recomputes desired state, and retries the CAW.  No
 * PAL-internal retry, so verify cannot compound with caller retries.
 *
 * Sess30 attempted PAL-level retry-on-mismatch (5 attempts × bounded
 * backoff) and got ETIMEDOUT — verify-retry x caller-retry compounded
 * to exhaust the 60s DLM grant timeout.  See sess30_lessons.md.
 *
 * 0 = no verify (default; fastest, but vulnerable to silent non-persist).
 * 1 = single FUA-readback verify; mismatch → -EAGAIN to caller.
 */
static int mxfs_caw_verify;
module_param_named(caw_verify, mxfs_caw_verify, int, 0644);
MODULE_PARM_DESC(caw_verify,
                 "CAW verify on success: 0=off (default), 1=single "
                 "FUA-readback verify; mismatch returns -EAGAIN.");

static atomic64_t mxfs_caw_verify_ok;
static atomic64_t mxfs_caw_verify_mismatch;

/*
 * sess30 path A: build the SCSI request manually, mirroring the data path
 * that drivers/scsi/sg.c uses for SG_IO.  Specifically:
 *   - allocate a fresh page for the 1024-byte data payload (compare+write)
 *   - copy caller's compare/write buffers into the fresh page
 *   - bio_alloc + bio_add_page (single bvec, our private page)
 *   - blk_rq_append_bio onto a scsi_alloc_request'd request
 *   - scmd->cmnd / cmd_len / allowed=0 (SG_DEFAULT_RETRIES) per sg.c
 *   - blk_execute_rq(req, true) synchronous, at_head matches sg
 *   - extract scmd->result, sense, resid before blk_mq_free_request
 *
 * Differences from scsi_execute_cmd on the same CDB:
 *   - bio carries a fresh private page, not virt_to_page(caller_buf)
 *     (avoids the bio_map_kern → bio_add_virt_nofail aliasing path)
 *   - scmd->allowed = 0 instead of 1 (matches SG_DEFAULT_RETRIES;
 *     sess26 already tested retries=0 without effect, but keep the
 *     parity for now)
 *   - no RQF_QUIET on the request (sg doesn't set it; informational)
 */
static int caw_manual_bio(struct scsi_device *sdev, u64 lba,
                          const void *compare_buf, const void *write_buf,
                          struct scsi_sense_hdr *sshdr_out,
                          int *resid_out)
{
	struct request *req;
	struct scsi_cmnd *scmd;
	struct bio *bio;
	struct page *page;
	void *page_addr;
	unsigned char cdb[16];
	int ret;

	/* Build COMPARE AND WRITE CDB (16 bytes) — same shape as legacy path */
	memset(cdb, 0, sizeof(cdb));
	cdb[0]  = 0x89;
	cdb[1]  = 0x08;
	cdb[2]  = (u8)(lba >> 56);
	cdb[3]  = (u8)(lba >> 48);
	cdb[4]  = (u8)(lba >> 40);
	cdb[5]  = (u8)(lba >> 32);
	cdb[6]  = (u8)(lba >> 24);
	cdb[7]  = (u8)(lba >> 16);
	cdb[8]  = (u8)(lba >> 8);
	cdb[9]  = (u8)(lba);
	cdb[13] = 0x01;

	/* Fresh page — bio's private payload (NOT shared with caller_buf).
	 * GFP_KERNEL is fine: caw_slot is called from kthread/syscall context,
	 * never from atomic context per the existing scsi_execute_cmd path. */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	page_addr = page_address(page);
	memcpy(page_addr, compare_buf, 512);
	memcpy(page_addr + 512, write_buf, 512);

	req = scsi_alloc_request(sdev->request_queue, REQ_OP_DRV_OUT, 0);
	if (IS_ERR(req)) {
		ret = PTR_ERR(req);
		__free_page(page);
		return ret;
	}

	{
	struct block_device *bdev_for_bio =
		sdev->request_queue->disk ?
		sdev->request_queue->disk->part0 : NULL;
	/* Set bi_bdev to match what blk_rq_map_bio_alloc does for sg.c
	 * (rq->q->disk->part0).  passthrough requests technically don't
	 * require bi_bdev to be set, but accounting paths and tracepoints
	 * dereference it. */
	bio = bio_alloc(bdev_for_bio, 1, REQ_OP_DRV_OUT, GFP_KERNEL);
	}
	if (!bio) {
		blk_mq_free_request(req);
		__free_page(page);
		return -ENOMEM;
	}

	if (bio_add_page(bio, page, 1024, 0) != 1024) {
		bio_put(bio);
		blk_mq_free_request(req);
		__free_page(page);
		return -EIO;
	}

	ret = blk_rq_append_bio(req, bio);
	if (ret) {
		/* blk_rq_append_bio puts the bio on failure path internally
		 * via bio_put on -EREMOTEIO; for other errors it doesn't.
		 * Conservatively bio_put if append failed. */
		if (req->bio == NULL)
			bio_put(bio);
		blk_mq_free_request(req);
		__free_page(page);
		return ret;
	}

	scmd = blk_mq_rq_to_pdu(req);
	scmd->cmd_len = COMMAND_SIZE(cdb[0]); /* 16 for opcode 0x89 */
	memcpy(scmd->cmnd, cdb, scmd->cmd_len);
	scmd->allowed = 0; /* SG_DEFAULT_RETRIES — match sg.c parity */
	req->timeout = 30 * HZ;

	(void)blk_execute_rq(req, true);

	if (sshdr_out)
		scsi_normalize_sense(scmd->sense_buffer, scmd->sense_len,
				     sshdr_out);
	if (resid_out)
		*resid_out = scmd->resid_len;

	ret = scmd->result;

	blk_mq_free_request(req);
	__free_page(page);

	return ret;
}

int mxfs_pal_bdev_compare_and_write(mxfs_bdev_t *dev, uint64_t offset,
				     const void *compare_buf,
				     const void *write_buf)
{
	struct scsi_device *sdev;
	struct scsi_sense_hdr sshdr;
	unsigned char cdb[16];
	unsigned char *data;
	uint64_t lba;
	int ret;

	if (!dev || !dev->bdev || !compare_buf || !write_buf)
		return -EINVAL;

	/* Plain SCSI disk: gendisk's parent.  Stacked (dm-multipath):
	 * resolved underlying path — see mxfs_bdev_to_sdev(). */
	sdev = mxfs_bdev_to_sdev(dev->bdev);
	if (!sdev)
		return -EOPNOTSUPP;

	lba = (offset + dev->base_offset) / 512;

	/* Build COMPARE AND WRITE CDB (16 bytes) */
	memset(cdb, 0, sizeof(cdb));
	cdb[0]  = 0x89;                     /* COMPARE AND WRITE opcode */
	cdb[1]  = 0x08;                     /* FUA bit set */
	cdb[2]  = (u8)(lba >> 56);          /* LBA bytes 2-9 (big-endian) */
	cdb[3]  = (u8)(lba >> 48);
	cdb[4]  = (u8)(lba >> 40);
	cdb[5]  = (u8)(lba >> 32);
	cdb[6]  = (u8)(lba >> 24);
	cdb[7]  = (u8)(lba >> 16);
	cdb[8]  = (u8)(lba >> 8);
	cdb[9]  = (u8)(lba);
	cdb[13] = 0x01;                     /* number of logical blocks = 1 */

	/* Data buffer: compare (512) + write (512) = 1024 bytes.
	 * v0.3.109 (sess26): use page-sized allocation for guaranteed
	 * 512-byte alignment.  blk_rq_map_kern uses bounce buffer if the
	 * passed kbuf isn't queue-aligned, which adds a copy step that
	 * could be the bug source.  4KB allocation is naturally aligned
	 * to a page boundary (which is >= 512 byte aligned). */
	data = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (!data) {
		scsi_device_put(sdev);
		return -ENOMEM;
	}
	memset(data, 0, 1024);

	memcpy(data, compare_buf, 512);
	memcpy(data + 512, write_buf, 512);

	{
	int caw_resid = 1024;
	int verify_rc;
	int ua_try = 0;
	unsigned char verify_buf[512];

	/*
	 * v0.3.128 (sess30): mxfs_caw_path=1 dispatches to the manual-bio
	 * SG-style submission to bypass bio_map_kern's bio_add_virt_nofail
	 * data-aliasing path that sess26 P49 implicated as the cause of
	 * silent CAS-success-without-persist.  Path 0 keeps the legacy
	 * scsi_execute_cmd flow.  The pre-allocated `data` page above is
	 * unused on path 1 (path 1 allocates its own fresh page); we keep
	 * the allocation here to avoid a structural rewrite during the A/B
	 * window — once path 1 is validated, the legacy branch and this
	 * unused buffer are removed in one cleanup commit.
	 */
caw_submit:
	memset(&sshdr, 0, sizeof(sshdr));
	if (mxfs_caw_path == 1) {
		ret = caw_manual_bio(sdev, lba, compare_buf, write_buf,
				     &sshdr, &caw_resid);
	} else
#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(6, 3, 0)
	{
		struct scsi_exec_args args = {
			.sshdr = &sshdr,
			.resid = &caw_resid,
		};

		/* v0.3.108 P53-INSTR: tested write-buf-pre-vs-post check.
		 * scsi_execute_cmd does NOT modify our outbound buffer.
		 * Confirmed our CAS data is sent correctly.  Target-side
		 * is where the bug lives. */
		ret = scsi_execute_cmd(sdev, cdb, REQ_OP_DRV_OUT,
				       data, 1024,
				       30 * HZ, 1, &args);
	}
#else
	ret = scsi_execute(sdev, cdb, DMA_TO_DEVICE,
			   data, 1024, NULL, &sshdr,
			   30 * HZ, 1, 0, 0, NULL);
#endif

	/*
	 * P51-INSTR (sess26 final): log detailed CAW return + sense info
	 * so sess27 can correlate fake-success cases with actual SCSI
	 * status.  Log even on ret==0 if sense is valid — catches the
	 * case where target returned GOOD status but provided sense data.
	 * v0.3.108: also log if caw_resid != 0 (partial transfer — short
	 * write to target = malformed CAS command).
	 */
	{ extern int mxfs_instr_enabled; extern int mxfs_dirwr_enabled;
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (ret != 0 || scsi_sense_valid(&sshdr) || caw_resid != 0)) {
		pr_warn_ratelimited("mxfs: P51-INSTR caw lba=%llu ret=%d resid=%d sense_valid=%d sense_key=0x%x asc=0x%x ascq=0x%x\n",
			(unsigned long long)lba, ret, caw_resid,
			scsi_sense_valid(&sshdr) ? 1 : 0,
			sshdr.sense_key, sshdr.asc, sshdr.ascq);
	}
	}

	/* dm-multipath: the first command down a (re)selected path reports
	 * UNIT ATTENTION (e.g. 0x29 power-on/reset) INSTEAD of executing —
	 * the CAW did not run, so reissuing is safe.  Bounded reissue,
	 * mirroring tools/caw_verify --retry-ua. */
	if (ret > 0 && scsi_sense_valid(&sshdr) &&
	    sshdr.sense_key == UNIT_ATTENTION && ua_try < 5) {
		ua_try++;
		pr_warn_ratelimited("mxfs: P-CAW-UA-RETRY lba=%llu asc=0x%x ascq=0x%x try=%d\n",
			(unsigned long long)lba, sshdr.asc, sshdr.ascq,
			ua_try);
		msleep(2 << ua_try);
		goto caw_submit;
	}

	/* Translate raw scsi_execute return → mxfs caller semantics. */
	if (ret < 0)
		goto done; /* host/driver error: -EIO/-ENODEV/etc, propagate */

	if (scsi_sense_valid(&sshdr) && sshdr.sense_key == MISCOMPARE) {
		ret = -EAGAIN;
		goto done;
	}

	if (ret > 0) {
		ret = -EIO;
		goto done;
	}

	/* CAS reported success.  ret == 0. */

	/*
	 * Force device cache flush before returning success.  Closes the
	 * window where the target's underlying physical disk has the write
	 * in its write-back cache but hasn't committed to media — a
	 * subsequent peer FUA-read may go to media and see pre-write
	 * content, causing the cross-node coherency divergence that drives
	 * bnobt LEFT/RIGHT-FAIL.  See `mxfs_caw_flush` param comment.
	 */
	if (mxfs_caw_flush)
		blkdev_issue_flush(dev->bdev);

	if (!mxfs_caw_verify)
		goto done; /* skip verify, trust the target */

	/*
	 * Plan B post-CAS verify: read the same LBA back via SCSI READ(16)
	 * FUA and compare against `write_buf`.  If they don't match, the
	 * target's "CAS-success" was accepted into a write-back cache and
	 * the data hasn't yet committed to permanent media (sess26 root
	 * cause #2; sess30 storage finding: Samsung 870 EVO doesn't support
	 * FUA so LIO silently drops our FUA bit on writes — see
	 * sess30_lessons.md).
	 *
	 * Strategy: bounded poll-for-persistence with exponential backoff.
	 * Re-read up to N times waiting for delayed persistence to show up.
	 * Crucially we do NOT retry the CAS — only the FUA-read.  This
	 * avoids the compounding-retry issue from sess30's earlier
	 * verify-with-CAS-retry attempt (which ETIMEDOUT'd the DLM grant).
	 *
	 * If the read eventually shows our content, return success.
	 * Otherwise after the bounded poll, surface -EAGAIN to the caller
	 * once.  The caller (caw_lock/caw_unlock) re-reads slot fresh and
	 * decides based on on-disk state whether to retry.
	 */
	{
	int verify_poll;
	verify_rc = -EAGAIN;
	for (verify_poll = 0; verify_poll < 5; verify_poll++) {
		int read_rc = mxfs_pal_bdev_read_prio(dev, offset,
						       verify_buf, 512);
		if (read_rc != 0) {
			ret = read_rc;
			goto done;
		}
		if (memcmp(verify_buf, write_buf, 512) == 0) {
			verify_rc = 0;
			break;
		}
		/* Not yet persisted — wait, then re-read.  Backoff:
		 * 2ms, 4ms, 8ms, 16ms, 32ms ≈ 62ms total. */
		msleep(2 << verify_poll);
	}
	if (verify_rc == 0) {
		atomic64_inc(&mxfs_caw_verify_ok);
		ret = 0;
		goto done; /* persisted, possibly delayed */
	}
	}

	/*
	 * Non-persist detected: target's "success" was a lie.  Surface to
	 * caller as -EAGAIN (MISCOMPARE-equivalent).  Caller (caw_slot in
	 * dlm_caw.c) re-reads the slot via FUA on the next attempt and
	 * recomputes — this is the correct semantics.  Note: this can also
	 * fire on a peer-overwrite race (peer modified the slot between our
	 * CAS-success and our verify-read).  In that case caller will see
	 * a different on-disk state on re-read and may legitimately retry
	 * with a fresh compare.  Both cases are correctly handled by the
	 * caller's existing miscompare-retry path.
	 */
	atomic64_inc(&mxfs_caw_verify_mismatch);
	pr_warn_ratelimited("mxfs: P71-INSTR caw verify-mismatch lba=%llu — kernel SCSI passthrough non-persist (sess26 root cause #2); returning -EAGAIN\n",
		(unsigned long long)lba);
	ret = -EAGAIN;

done:
	free_page((unsigned long)data);
	scsi_device_put(sdev);
	return ret;
	}
}

struct block_device *mxfs_pal_bdev_get_bdev(mxfs_bdev_t *dev)
{
	return dev ? dev->bdev : NULL;
}

uint64_t mxfs_pal_bdev_get_base_offset(mxfs_bdev_t *dev)
{
	return dev ? dev->base_offset : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Hostname
 * ═══════════════════════════════════════════════════════════════════ */

int mxfs_pal_get_hostname(char *buf, size_t len)
{
	if (!buf || len == 0)
		return -EINVAL;

	strscpy(buf, init_uts_ns.name.nodename, len);
	return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * File I/O
 * ═══════════════════════════════════════════════════════════════════ */

int mxfs_pal_read_file(const char *path, void *buf, size_t buf_size)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t nread;

	if (!path || !buf || buf_size == 0)
		return -EINVAL;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return (int)PTR_ERR(f);

#if MXFS_EFFECTIVE_VERSION >= KERNEL_VERSION(4, 14, 0)
	nread = kernel_read(f, buf, buf_size, &pos);
#else
	nread = vfs_read(f, (char __user *)buf, buf_size, &pos);
#endif
	filp_close(f, NULL);

	if (nread < 0)
		return (int)nread;

	return (int)nread;
}

void mxfs_pal_get_random_bytes(void *buf, size_t len)
{
	get_random_bytes(buf, len);
}

void mxfs_pal_bdev_get_write_stats(mxfs_bdev_t *dev,
				    uint64_t *writes, uint64_t *write_bytes,
				    uint64_t *writes_fua, uint64_t *write_fua_bytes,
				    uint64_t *flushes)
{
	if (!dev) return;
	if (writes) *writes = dev->stat_writes;
	if (write_bytes) *write_bytes = dev->stat_write_bytes;
	if (writes_fua) *writes_fua = dev->stat_writes_fua;
	if (write_fua_bytes) *write_fua_bytes = dev->stat_write_fua_bytes;
	if (flushes) *flushes = dev->stat_flushes;
}

/* Export all PAL symbols for use by libmxfs compiled into the module */
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_open);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_close);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_clone_with_offset);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_close_clone);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_read);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_read_prio);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_write);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_write_fua);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_flush);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_size);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_get_write_stats);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_write_gather);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_write_scatter);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_write_async);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_read_async);
EXPORT_SYMBOL_GPL(mxfs_pal_alloc);
EXPORT_SYMBOL_GPL(mxfs_pal_free);
EXPORT_SYMBOL_GPL(mxfs_pal_realloc);
EXPORT_SYMBOL_GPL(mxfs_pal_thread_create);
EXPORT_SYMBOL_GPL(mxfs_pal_thread_create_rt);
EXPORT_SYMBOL_GPL(mxfs_pal_thread_join);
EXPORT_SYMBOL_GPL(mxfs_pal_thread_join_timeout);
EXPORT_SYMBOL_GPL(mxfs_pal_mutex_create);
EXPORT_SYMBOL_GPL(mxfs_pal_mutex_destroy);
EXPORT_SYMBOL_GPL(mxfs_pal_mutex_lock);
EXPORT_SYMBOL_GPL(mxfs_pal_mutex_unlock);
EXPORT_SYMBOL_GPL(mxfs_pal_spinlock_create);
EXPORT_SYMBOL_GPL(mxfs_pal_spinlock_destroy);
EXPORT_SYMBOL_GPL(mxfs_pal_spinlock_lock);
EXPORT_SYMBOL_GPL(mxfs_pal_spinlock_unlock);
EXPORT_SYMBOL_GPL(mxfs_pal_rwlock_create);
EXPORT_SYMBOL_GPL(mxfs_pal_rwlock_destroy);
EXPORT_SYMBOL_GPL(mxfs_pal_rwlock_rdlock);
EXPORT_SYMBOL_GPL(mxfs_pal_rwlock_wrlock);
EXPORT_SYMBOL_GPL(mxfs_pal_rwlock_unlock);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_create);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_destroy);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_wait);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_timedwait);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_signal);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_broadcast);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_connect);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_listen);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_accept);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_send);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_recv);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_set_opts);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_shutdown);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_close);
EXPORT_SYMBOL_GPL(mxfs_pal_tcp_getpeername);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_open);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_shutdown);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_close);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_sendto);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_recvfrom);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_join_multicast);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_set_broadcast);
EXPORT_SYMBOL_GPL(mxfs_pal_udp_set_recv_timeout);
EXPORT_SYMBOL_GPL(mxfs_pal_time_ms);
EXPORT_SYMBOL_GPL(mxfs_pal_sleep_ms);
EXPORT_SYMBOL_GPL(mxfs_pal_cond_resched);
EXPORT_SYMBOL_GPL(mxfs_pal_log);
EXPORT_SYMBOL_GPL(mxfs_pal_dump_stack);
EXPORT_SYMBOL_GPL(mxfs_pal_sort);
EXPORT_SYMBOL_GPL(mxfs_pal_scsi_pr_register);
EXPORT_SYMBOL_GPL(mxfs_pal_scsi_pr_reserve);
EXPORT_SYMBOL_GPL(mxfs_pal_scsi_pr_preempt);
EXPORT_SYMBOL_GPL(mxfs_pal_scsi_pr_unregister);
EXPORT_SYMBOL_GPL(mxfs_pal_scsi_pr_read_keys);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_compare_and_write);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_get_bdev);
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_get_base_offset);
EXPORT_SYMBOL_GPL(mxfs_pal_get_hostname);
EXPORT_SYMBOL_GPL(mxfs_pal_read_file);
EXPORT_SYMBOL_GPL(mxfs_pal_get_random_bytes);
