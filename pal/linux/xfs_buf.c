// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include <linux/backing-dev.h>
#include <linux/dax.h>

#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_log_recover.h"
#include "xfs_log_priv.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_ag.h"
#include "xfs_buf_mem.h"
#include "xfs_notify_failure.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_inode_item.h"
#include "xfs_bmap_btree.h"
#include "../../dlm/v5_mount.h"

struct kmem_cache *xfs_buf_cache;

/*
 * Locking orders
 *
 * xfs_buf_stale:
 *	b_sema (caller holds)
 *	  b_lock
 *	    lru_lock
 *
 * xfs_buf_rele:
 *	b_lock
 *	  lru_lock
 *
 * xfs_buftarg_drain_rele
 *	lru_lock
 *	  b_lock (trylock due to inversion)
 *
 * xfs_buftarg_isolate
 *	lru_lock
 *	  b_lock (trylock due to inversion)
 */

static void xfs_buf_submit_ex(struct xfs_buf *bp, bool fresh);
static void xfs_buf_submit(struct xfs_buf *bp);
static int xfs_buf_iowait(struct xfs_buf *bp);

/*
 * sess9 (ccloop a864) DIAG — residual wedge#2 (dir_reuse@32/caw rm hang in
 * xfs_buf_iowait): the b_mxfs_force_sync latch (sess8) did NOT stop the
 * lost wakeup — the stuck buffer still reads sync_wait=0 ioend_seen=2
 * relse_seen=2 with ZERO I/O-error alerts and ZERO P-SYNCWAIT-OVERRIDE
 * fires, so counters alone cannot name which submit reset the snapshot or
 * which completion relse'd the sync waiter's buffer.  Record the last 8
 * lifecycle events per buffer; P-IOWAIT-STUCK dumps the ring, giving the
 * exact ordered history for the wedged buffer.  Lock-free single stores —
 * a raced slot is acceptable for a diagnostic.
 *
 * Packing (u64): [63:60] event type (MXFS_BEV_*), [59:44] b_flags & 0xffff,
 * [43] b_mxfs_sync_waiters != 0, [42] b_mxfs_force_sync, [41:30] current->pid & 0xfff,
 * [29:0] ktime_get_real_ns() >> 20 (~1.05ms units, wraps ~13 days).
 */
enum {
	MXFS_BEV_SUBMIT = 1,	/* xfs_buf_submit snapshot point (force_sync bit = pre-consume latch) */
	MXFS_BEV_BIOEND = 2,	/* xfs_buf_bio_end_io entry (real bio completed) */
	MXFS_BEV_IOEND  = 3,	/* xfs_buf_ioend entry (full completion incl. emulated) */
	MXFS_BEV_WORKER = 4,	/* xfs_buf_ioend_work entry (deferred async completion) */
	MXFS_BEV_EHERR  = 5,	/* xfs_buf_ioend_handle_error entry (b_error set) */
	MXFS_BEV_RESUB  = 6,	/* handle_error resubmit branch taken */
	MXFS_BEV_BIO    = 7,	/* real bio issued to the block layer */
	MXFS_BEV_IOFAIL = 8,	/* xfs_buf_ioend_fail (stale + EIO completion) */
	MXFS_BEV_IOWAIT = 9,	/* xfs_buf_iowait received a completion token */
	MXFS_BEV_STALE  = 10,	/* xfs_buf_stale (buffer invalidated / incarnation end) */
};

static inline bool mxfs_agmeta_ops(const struct xfs_buf_ops *ops);
extern const struct xfs_buf_ops xfs_bnobt_buf_ops;
extern const struct xfs_buf_ops xfs_cntbt_buf_ops;
extern const struct xfs_buf_ops xfs_inobt_buf_ops;
extern const struct xfs_buf_ops xfs_finobt_buf_ops;

/* P144 coverage (ccloop-4dd7 extended it to the inode btrees for the inobt
 * double-free record corruption): all four short-form AG btrees. */
static inline bool
mxfs_p144_ops(const struct xfs_buf_ops *ops)
{
	return ops == &xfs_bnobt_buf_ops || ops == &xfs_cntbt_buf_ops ||
	       ops == &xfs_inobt_buf_ops || ops == &xfs_finobt_buf_ops;
}

/*
 * sess6 (ccloop 8ba7ae5c) P144 — free-space btree content fingerprint.
 * crc32c of everything past the 56-byte v5 short-btree header (magic/level/
 * numrecs/siblings/blkno/LSN/uuid/owner/crc): identical RECORD content
 * fingerprints equal across relogs/nodes.  P144-WR at write submission and
 * P144-RD at cold-read completion, joined offline per (agno,daddr), decide
 * whether a reader's first image matches the writer's last write — the
 * discriminator for the AG free-space regression (double-alloc) braid.
 */
static inline void
mxfs_p144_print(struct xfs_buf *bp, const char *tag)
{
	static atomic_t p144_n = ATOMIC_INIT(0);
	struct xfs_btree_block *bb = bp->b_addr;

	if (!bb || BBTOB(bp->b_length) <= 56)
		return;
	if (atomic_inc_return(&p144_n) > 12000)
		return;
	pr_warn("mxfs: P144-%s %s agno=%u daddr=%lld crc=%08x nr=%u lvl=%u lsn=%llx comm=%s realns=%llu\n",
		tag,
		bp->b_ops == &xfs_bnobt_buf_ops ? "bnobt" :
		bp->b_ops == &xfs_cntbt_buf_ops ? "cntbt" :
		bp->b_ops == &xfs_inobt_buf_ops ? "inobt" :
		bp->b_ops == &xfs_finobt_buf_ops ? "finobt" : "agbt?",
		xfs_daddr_to_agno(bp->b_mount, bp->b_maps[0].bm_bn),
		(long long)bp->b_maps[0].bm_bn,
		crc32c(0, (char *)bp->b_addr + 56, BBTOB(bp->b_length) - 56),
		be16_to_cpu(bb->bb_numrecs),
		be16_to_cpu(bb->bb_level),
		(unsigned long long)be64_to_cpu(bb->bb_u.s.bb_lsn),
		current->comm,
		(unsigned long long)ktime_get_real_ns());
}

static void
mxfs_buf_ev(struct xfs_buf *bp, unsigned int type)
{
	u64 v = ((u64)(type & 0xf) << 60) |
		((u64)(bp->b_flags & 0xffff) << 44) |
		((u64)(atomic_read(&bp->b_mxfs_sync_waiters) ? 1 : 0) << 43) |
		((u64)(bp->b_mxfs_force_sync ? 1 : 0) << 42) |
		((u64)(current->pid & 0xfff) << 30) |
		((u64)(ktime_get_real_ns() >> 20) & 0x3fffffff);

	bp->b_mxfs_evring[bp->b_mxfs_evi++ & 7] = v;
}

/*
 * sess-pve (AGI umount-wedge, RULE-4): record one b_hold mutation into the
 * per-buffer hold/rele ring.  MUST be called with bp->b_lock held (all b_hold
 * mutations already are, except the single-threaded alloc init) and AFTER the
 * mutation, so bp->b_hold reads the post-mutation value.  The P-HOLDRING drain
 * dump replays this ring to name whichever acquisition has no matching release.
 * Compiles to nothing when MXFS_HOLD_TRACE == 0.
 */
#if MXFS_HOLD_TRACE
static inline void
mxfs_hold_ev(struct xfs_buf *bp, u8 site, s8 delta, unsigned long caller)
{
	struct mxfs_hold_evt *e =
		&bp->b_mxfs_hold_ring[bp->b_mxfs_hri++ % MXFS_HOLD_RING];

	e->caller = caller;
	e->flags = bp->b_flags;
	e->hold_after = (u16)bp->b_hold;
	e->site = site;
	e->delta = delta;
}
#else
static inline void
mxfs_hold_ev(struct xfs_buf *bp, u8 site, s8 delta, unsigned long caller) {}
#endif

/*
 * ccloop3e02 sess2 ROOT FIX for dir_reuse@32/caw wedge#2a residual: route a
 * single completion event for this buffer to AT MOST one pending
 * synchronous waiter, using an additive credit (b_mxfs_sync_waiters,
 * incremented once per genuinely-synchronous xfs_buf_submit) instead of the
 * single overwritable b_mxfs_sync_wait bool the sess6/8/9 fixes used.  An
 * unrelated concurrent submitter (xfsaild's async delwri racing this
 * buffer's synchronous durable flush) can no longer steal or duplicate
 * another submission's wakeup: each sync submission's credit is consumed
 * by exactly one completion, regardless of which bio's completion runs
 * first.  Returns true if a sync waiter was woken (caller must NOT relse —
 * the woken thread owns that, per the sync-submit protocol); false if the
 * caller should fall back to the existing flags-based (XBF_ASYNC) decision.
 */
static bool
mxfs_buf_completion_wake_sync(struct xfs_buf *bp)
{
	if (!atomic_add_unless(&bp->b_mxfs_sync_waiters, -1, 0))
		return false;
	complete(&bp->b_iowait);
	return true;
}

static inline bool xfs_buf_is_uncached(struct xfs_buf *bp)
{
	return bp->b_rhash_key == XFS_BUF_DADDR_NULL;
}

/*
 * When we mark a buffer stale, we remove the buffer from the LRU and clear the
 * b_lru_ref count so that the buffer is freed immediately when the buffer
 * reference count falls to zero. If the buffer is already on the LRU, we need
 * to remove the reference that LRU holds on the buffer.
 *
 * This prevents build-up of stale buffers on the LRU.
 */
void
xfs_buf_stale(
	struct xfs_buf	*bp)
{
	ASSERT(xfs_buf_islocked(bp));

	mxfs_buf_ev(bp, MXFS_BEV_STALE);

	/*
	 * sess5(ccloop 12e0d157) stale-attribution probe (RULE 4): the 32-node
	 * dlm_scaling AG0 storm = inode-cluster buffers STALED (removed from
	 * cache) then cold-FUA-re-read.  igstale/evict-ring/drain all ruled out,
	 * so the staler is elsewhere.  Count + stack-sample stales of INODE
	 * buffers to find who evicts a buffer this node holds under a lock.
	 * Gated on read_attr_probe; hard ratelimited.
	 */
	{
	extern int mxfs_read_attr_probe;
	extern atomic64_t mxfs_stale_ino;
	if (unlikely(mxfs_read_attr_probe) &&
	    (bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ra_ops)) {
		long long sn = atomic64_inc_return(&mxfs_stale_ino);

		if ((sn & 255) == 0)
			pr_warn("mxfs: STALE-INO n=%lld daddr=%lld flags=0x%x has_bli=%d comm=%s\n",
				sn, (long long)bp->b_maps[0].bm_bn,
				bp->b_flags, bp->b_log_item ? 1 : 0,
				current->comm);
		{
			static DEFINE_RATELIMIT_STATE(mxfs_st_rs, HZ, 1);

			if (__ratelimit(&mxfs_st_rs))
				dump_stack();
		}
	}
	}

	bp->b_flags |= XBF_STALE;

	/*
	 * Clear the delwri status so that a delwri queue walker will not
	 * flush this buffer to disk now that it is stale. The delwri queue has
	 * a reference to the buffer, so this is safe to do.
	 *
	 * Also clear _XBF_FUA_FRESH (MXFS v6a phase 1, v0.3.129):
	 * any stale event re-arms the FUA-read gate so the next read
	 * pierces the storage stack's per-initiator cache.  Same insertion
	 * point as _XBF_DELWRI_Q clear because both are MXFS-internal flags
	 * whose lifetime ends when the buf becomes stale.
	 */
	/* P-DIRSTALE (RULE-4): a multinode dir3 data/block buffer that is
	 * committed-in-AIL and UNDESTAGED is being STALED (evicted).  Its content
	 * is not on disk (dir blocks destage only at DLM release), so evicting it
	 * loses committed data -> a later read cold-fetches 0xFF -> shutdown.
	 * Log the caller so we find who wrongly stales it.
	 * sess6(ccloop): UNGATED — post-FIX-11 no path may stale an undestaged
	 * dir buffer, so this should never fire; when it does (run86 r12: the
	 * f36-f50 block's struct was staled+replaced between the last add and
	 * the release walk, silently), the stack IS the root cause. */
	if (bp->b_addr && bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm)) {
		__be32 m = *(__be32 *)bp->b_addr;
		struct xfs_buf_log_item *sbip = bp->b_log_item;
		bool in_ail = sbip && test_bit(XFS_LI_IN_AIL,
					&sbip->bli_item.li_flags);
		if ((m == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) ||
		     m == cpu_to_be32(XFS_DIR3_DATA_MAGIC))) {
			static atomic_t pds = ATOMIC_INIT(0);
			bool undest = (bp->b_flags & XBF_DONE) ?
				mxfs_dir_buf_is_undestaged(bp) : false;
			/* Focus on the dangerous case: staling an UNDESTAGED (or
			 * in-AIL) dir block whose content is not on disk. */
			if ((undest || in_ail) && atomic_inc_return(&pds) <= 200) {
				pr_warn("mxfs: P-DIRSTALE daddr=%lld magic=0x%x in_ail=%d undest=%d DONE=%d has_bli=%d pin=%d flags=0x%x — staling dir block\n",
					(long long)xfs_buf_daddr(bp), be32_to_cpu(m),
					in_ail, undest,
					(bp->b_flags & XBF_DONE) ? 1 : 0,
					sbip ? 1 : 0,
					atomic_read(&bp->b_pin_count), bp->b_flags);
				/* sess8: stack only under instr — an in-AIL dir
				 * block binval is NORMAL in block->sf shrink
				 * (xfs_dir2_shrink_inode), and the "Call Trace"
				 * keyword fails soak's dmesg-clean criterion. */
				if (unlikely(mxfs_instr_enabled))
					dump_stack();
			}
		}
	}

	bp->b_flags &= ~(_XBF_DELWRI_Q | _XBF_FUA_FRESH | _XBF_MXFS_ALLOC_QUEUED);

	/*
	 * sess27: a stale event ends this buffer incarnation — drop the persistent
	 * inode-cluster dirty-sector mask so an ABA-reused buffer (same daddr, new
	 * inode chunk) does not inherit the prior incarnation's owned-sector set.
	 */
	bp->b_mxfs_idirty_mask = 0;
	bp->b_mxfs_dir_wrcnt_max = 0;	/* sess40: reset dir-write high-water on reuse */
	bp->b_mxfs_relepoch = 0;	/* sess50: reset release-epoch stamp on reuse */
	bp->b_mxfs_stale_pending = false;	/* sess5: clear deferred-stale on reuse */
	/* sess7 (ccloop 8ba7ae5c): stale ends the incarnation — a P150 read-
	 * preserve snapshot from it must never restore into a reused buffer. */
	if (unlikely(bp->b_mxfs_rd_preserve)) {
		kfree(bp->b_mxfs_rd_preserve);
		bp->b_mxfs_rd_preserve = NULL;
	}
	bp->b_mxfs_rd_preserve_mask = 0;

	spin_lock(&bp->b_lock);
	atomic_set(&bp->b_lru_ref, 0);
	if (!(bp->b_state & XFS_BSTATE_DISPOSE) &&
	    (list_lru_del_obj(&bp->b_target->bt_lru, &bp->b_lru))) {
		bp->b_hold--;
		mxfs_hold_ev(bp, MXFS_HS_STALE_LRU, -1, _RET_IP_);
	}

	ASSERT(bp->b_hold >= 1);
	spin_unlock(&bp->b_lock);
}

static void
xfs_buf_free_callback(
	struct callback_head	*cb)
{
	struct xfs_buf		*bp = container_of(cb, struct xfs_buf, b_rcu);

	if (bp->b_maps != &bp->__b_map)
		kfree(bp->b_maps);
	kmem_cache_free(xfs_buf_cache, bp);
}

static void
xfs_buf_free(
	struct xfs_buf		*bp)
{
	unsigned int		size = BBTOB(bp->b_length);

	might_sleep();
	trace_xfs_buf_free(bp, _RET_IP_);

	/*
	 * ccloop 72513a13 tripwire: a SECOND free of the same buffer must not
	 * queue b_rcu twice — that both double-frees the object (test25
	 * panic: BUG mm/slub.c:553 in xfs_buf_free_callback) and corrupts the
	 * RCU callback list (stale callback later fired into unloaded module
	 * text).  Catch the second caller red-handed and make it a no-op:
	 * the first free owns the object from here on.
	 */
	if (test_and_set_bit(0, &bp->b_mxfs_freeflag)) {
		pr_alert("mxfs: P-BUF-DOUBLEFREE daddr=%lld len=%d flags=0x%x hold=%d state=0x%x comm=%s — second xfs_buf_free suppressed\n",
			 (long long)(bp->b_rhash_key),
			 bp->b_length, bp->b_flags, bp->b_hold,
			 bp->b_state, current->comm);
		dump_stack();
		return;
	}

	/*
	 * ccloop 72513a13 sess2 tripwire: freeing a buffer that still has log
	 * items attached (b_li_list non-empty) strands every attached inode
	 * item — dirty in the AIL, li_buf pointing at a soon-recycled
	 * allocation whose fresh b_li_list is empty, so iflush_cluster flushes
	 * nothing and returns -EAGAIN forever (the dir_reuse@32 P113-DRAIN-
	 * WEDGE that starved 31 peers into -ETIMEDOUT shutdowns).  The items
	 * hold buffer references, so reaching here with attachments means the
	 * hold count was corrupted (the P-RAFIX hold-steal family).  Scream
	 * with the culprit's stack; do NOT suppress the free (the count says
	 * zero — suppressing would leak and hide the recycle evidence the
	 * gen stamp now captures).
	 */
	if (unlikely(!list_empty(&bp->b_li_list))) {
		static atomic_t pbla = ATOMIC_INIT(0);
		if (atomic_inc_return(&pbla) <= 6) {
			pr_alert("mxfs: P-BUF-FREE-WITH-ITEMS daddr=%lld len=%d flags=0x%x hold=%d gen=%llu comm=%s — freeing buffer with attached log items\n",
				 (long long)(bp->b_rhash_key),
				 bp->b_length, bp->b_flags, bp->b_hold,
				 (unsigned long long)bp->b_mxfs_alloc_gen,
				 current->comm);
			dump_stack();
		}
	}

	/* sess7 (ccloop 8ba7ae5c): P150 read-preserve leak guard — a read that
	 * errored terminally (no successful completion consumed the snapshot). */
	if (unlikely(bp->b_mxfs_rd_preserve)) {
		kfree(bp->b_mxfs_rd_preserve);
		bp->b_mxfs_rd_preserve = NULL;
		bp->b_mxfs_rd_preserve_mask = 0;
	}

	/* P-DIRFREE (RULE-4): catch the FREE of a multinode dir3 data/block
	 * buffer (its in-core content is about to be destroyed).  If this fires
	 * for the block0 daddr that later cold-reads 0xFF, this is the eviction
	 * that loses the committed-undestaged content.  dump_stack -> the caller. */
	if (unlikely(mxfs_instr_enabled) &&
	    bp->b_addr && bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm)) {
		__be32 m = *(__be32 *)bp->b_addr;
		if (m == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) ||
		    m == cpu_to_be32(XFS_DIR3_DATA_MAGIC)) {
			static atomic_t pdf = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdf) <= 300) {
				pr_warn("mxfs: P-DIRFREE daddr=%lld magic=0x%x has_bli=%d flags=0x%x hold=%d — freeing dir3 buffer (content destroyed)\n",
					(long long)xfs_buf_daddr(bp), be32_to_cpu(m),
					bp->b_log_item ? 1 : 0, bp->b_flags,
					bp->b_hold);
				dump_stack();
			}
		}
	}

	ASSERT(list_empty(&bp->b_lru));

	if (!xfs_buftarg_is_mem(bp->b_target) && size >= PAGE_SIZE)
		mm_account_reclaimed_pages(howmany(size, PAGE_SHIFT));

	if (is_vmalloc_addr(bp->b_addr))
		vfree(bp->b_addr);
	else if (bp->b_flags & _XBF_KMEM)
		kfree(bp->b_addr);
	else
		folio_put(virt_to_folio(bp->b_addr));

	call_rcu(&bp->b_rcu, xfs_buf_free_callback);
}

static int
xfs_buf_alloc_kmem(
	struct xfs_buf		*bp,
	size_t			size,
	gfp_t			gfp_mask)
{
	ASSERT(is_power_of_2(size));
	ASSERT(size < PAGE_SIZE);

	bp->b_addr = kmalloc(size, gfp_mask | __GFP_NOFAIL);
	if (!bp->b_addr)
		return -ENOMEM;

	/*
	 * Slab guarantees that we get back naturally aligned allocations for
	 * power of two sizes.  Keep this check as the canary in the coal mine
	 * if anything changes in slab.
	 */
	if (WARN_ON_ONCE(!IS_ALIGNED((unsigned long)bp->b_addr, size))) {
		kfree(bp->b_addr);
		bp->b_addr = NULL;
		return -ENOMEM;
	}
	bp->b_flags |= _XBF_KMEM;
	trace_xfs_buf_backing_kmem(bp, _RET_IP_);
	return 0;
}

/*
 * Allocate backing memory for a buffer.
 *
 * For tmpfs-backed buffers used by in-memory btrees this directly maps the
 * tmpfs page cache folios.
 *
 * For real file system buffers there are three different kinds backing memory:
 *
 * The first type backs the buffer by a kmalloc allocation.  This is done for
 * less than PAGE_SIZE allocations to avoid wasting memory.
 *
 * The second type is a single folio buffer - this may be a high order folio or
 * just a single page sized folio, but either way they get treated the same way
 * by the rest of the code - the buffer memory spans a single contiguous memory
 * region that we don't have to map and unmap to access the data directly.
 *
 * The third type of buffer is the vmalloc()d buffer. This provides the buffer
 * with the required contiguous memory region but backed by discontiguous
 * physical pages.
 */
static int
xfs_buf_alloc_backing_mem(
	struct xfs_buf	*bp,
	xfs_buf_flags_t	flags)
{
	size_t		size = BBTOB(bp->b_length);
	gfp_t		gfp_mask = GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOWARN;
	struct folio	*folio;

	if (xfs_buftarg_is_mem(bp->b_target))
		return xmbuf_map_backing_mem(bp);

	/* Assure zeroed buffer for non-read cases. */
	if (!(flags & XBF_READ))
		gfp_mask |= __GFP_ZERO;

	if (flags & XBF_READ_AHEAD)
		gfp_mask |= __GFP_NORETRY;

	/*
	 * For buffers smaller than PAGE_SIZE use a kmalloc allocation if that
	 * is properly aligned.  The slab allocator now guarantees an aligned
	 * allocation for all power of two sizes, which matches most of the
	 * smaller than PAGE_SIZE buffers used by XFS.
	 */
	if (size < PAGE_SIZE && is_power_of_2(size))
		return xfs_buf_alloc_kmem(bp, size, gfp_mask);

	/*
	 * Don't bother with the retry loop for single PAGE allocations: vmalloc
	 * won't do any better.
	 */
	if (size <= PAGE_SIZE)
		gfp_mask |= __GFP_NOFAIL;

	/*
	 * Optimistically attempt a single high order folio allocation for
	 * larger than PAGE_SIZE buffers.
	 *
	 * Allocating a high order folio makes the assumption that buffers are a
	 * power-of-2 size, matching the power-of-2 folios sizes available.
	 *
	 * The exception here are user xattr data buffers, which can be arbitrarily
	 * sized up to 64kB plus structure metadata, skip straight to the vmalloc
	 * path for them instead of wasting memory here.
	 */
	if (size > PAGE_SIZE) {
		if (!is_power_of_2(size))
			goto fallback;
		gfp_mask &= ~__GFP_DIRECT_RECLAIM;
		gfp_mask |= __GFP_NORETRY;
	}
	folio = folio_alloc(gfp_mask, get_order(size));
	if (!folio) {
		if (size <= PAGE_SIZE)
			return -ENOMEM;
		trace_xfs_buf_backing_fallback(bp, _RET_IP_);
		goto fallback;
	}
	bp->b_addr = folio_address(folio);
	trace_xfs_buf_backing_folio(bp, _RET_IP_);
	return 0;

fallback:
	for (;;) {
		bp->b_addr = __vmalloc(size, gfp_mask);
		if (bp->b_addr)
			break;
		if (flags & XBF_READ_AHEAD)
			return -ENOMEM;
		XFS_STATS_INC(bp->b_mount, xb_page_retries);
		memalloc_retry_wait(gfp_mask);
	}

	trace_xfs_buf_backing_vmalloc(bp, _RET_IP_);
	return 0;
}

static int
xfs_buf_alloc(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp)
{
	struct xfs_buf		*bp;
	int			error;
	int			i;

	*bpp = NULL;
	bp = kmem_cache_zalloc(xfs_buf_cache,
			GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);

	/*
	 * We don't want certain flags to appear in b_flags unless they are
	 * specifically set by later operations on the buffer.
	 */
	flags &= ~(XBF_TRYLOCK | XBF_ASYNC | XBF_READ_AHEAD);

	/*
	 * A new buffer is held and locked by the owner.  This ensures that the
	 * buffer is owned by the caller and racing RCU lookups right after
	 * inserting into the hash table are safe (and will have to wait for
	 * the unlock to do anything non-trivial).
	 */
	bp->b_hold = 1;
	mxfs_hold_ev(bp, MXFS_HS_ALLOC, 1, _RET_IP_);
	sema_init(&bp->b_sema, 0); /* held, no waiters */

	spin_lock_init(&bp->b_lock);
	atomic_set(&bp->b_lru_ref, 1);
	init_completion(&bp->b_iowait);
	INIT_LIST_HEAD(&bp->b_lru);
	INIT_LIST_HEAD(&bp->b_list);
	INIT_LIST_HEAD(&bp->b_li_list);
	/* ccloop 72513a13 sess2: recycle discriminator for the P113 AIL wedge —
	 * see b_mxfs_alloc_gen in xfs_buf.h. */
	{
		static atomic64_t mxfs_buf_alloc_gen = ATOMIC64_INIT(0);
		bp->b_mxfs_alloc_gen = atomic64_inc_return(&mxfs_buf_alloc_gen);
	}
	bp->b_target = target;
	bp->b_mount = target->bt_mount;
	bp->b_flags = flags;
	bp->b_rhash_key = map[0].bm_bn;
	bp->b_length = 0;
	bp->b_map_count = nmaps;
	if (nmaps == 1)
		bp->b_maps = &bp->__b_map;
	else
		bp->b_maps = kcalloc(nmaps, sizeof(struct xfs_buf_map),
				GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
	for (i = 0; i < nmaps; i++) {
		bp->b_maps[i].bm_bn = map[i].bm_bn;
		bp->b_maps[i].bm_len = map[i].bm_len;
		bp->b_length += map[i].bm_len;
	}

	atomic_set(&bp->b_pin_count, 0);
	init_waitqueue_head(&bp->b_waiters);

	XFS_STATS_INC(bp->b_mount, xb_create);
	trace_xfs_buf_init(bp, _RET_IP_);

	error = xfs_buf_alloc_backing_mem(bp, flags);
	if (error) {
		xfs_buf_free(bp);
		return error;
	}

	*bpp = bp;
	return 0;
}

/*
 *	Finding and Reading Buffers
 */
static int
_xfs_buf_obj_cmp(
	struct rhashtable_compare_arg	*arg,
	const void			*obj)
{
	const struct xfs_buf_map	*map = arg->key;
	const struct xfs_buf		*bp = obj;

	/*
	 * The key hashing in the lookup path depends on the key being the
	 * first element of the compare_arg, make sure to assert this.
	 */
	BUILD_BUG_ON(offsetof(struct xfs_buf_map, bm_bn) != 0);

	if (bp->b_rhash_key != map->bm_bn)
		return 1;

	if (unlikely(bp->b_length != map->bm_len)) {
		/*
		 * found a block number match. If the range doesn't
		 * match, the only way this is allowed is if the buffer
		 * in the cache is stale and the transaction that made
		 * it stale has not yet committed. i.e. we are
		 * reallocating a busy extent. Skip this buffer and
		 * continue searching for an exact match.
		 *
		 * Note: If we're scanning for incore buffers to stale, don't
		 * complain if we find non-stale buffers.
		 */
		if (!(map->bm_flags & XBM_LIVESCAN))
			ASSERT(bp->b_flags & XBF_STALE);
		return 1;
	}
	return 0;
}

static const struct rhashtable_params xfs_buf_hash_params = {
	.min_size		= 32,	/* empty AGs have minimal footprint */
	.nelem_hint		= 16,
	.key_len		= sizeof(xfs_daddr_t),
	.key_offset		= offsetof(struct xfs_buf, b_rhash_key),
	.head_offset		= offsetof(struct xfs_buf, b_rhash_head),
	.automatic_shrinking	= true,
	.obj_cmpfn		= _xfs_buf_obj_cmp,
};

int
xfs_buf_cache_init(
	struct xfs_buf_cache	*bch)
{
	return rhashtable_init(&bch->bc_hash, &xfs_buf_hash_params);
}

void
xfs_buf_cache_destroy(
	struct xfs_buf_cache	*bch)
{
	rhashtable_destroy(&bch->bc_hash);
}

static int
xfs_buf_map_verify(
	struct xfs_buftarg	*btp,
	struct xfs_buf_map	*map)
{
	/* Check for IOs smaller than the sector size / not sector aligned */
	ASSERT(!(BBTOB(map->bm_len) < btp->bt_meta_sectorsize));
	ASSERT(!(BBTOB(map->bm_bn) & (xfs_off_t)btp->bt_meta_sectormask));

	/*
	 * Corrupted block numbers can get through to here, unfortunately, so we
	 * have to check that the buffer falls within the filesystem bounds.
	 */
	if (map->bm_bn < 0 || map->bm_bn >= btp->bt_nr_sectors) {
		xfs_alert(btp->bt_mount,
			  "%s: daddr 0x%llx out of range, EOFS 0x%llx",
			  __func__, map->bm_bn, btp->bt_nr_sectors);
		WARN_ON(1);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int
xfs_buf_find_lock(
	struct xfs_buf          *bp,
	xfs_buf_flags_t		flags)
{
	if (flags & XBF_TRYLOCK) {
		if (!xfs_buf_trylock(bp)) {
			XFS_STATS_INC(bp->b_mount, xb_busy_locked);
			return -EAGAIN;
		}
	} else {
		xfs_buf_lock(bp);
		XFS_STATS_INC(bp->b_mount, xb_get_locked_waited);
	}

	/*
	 * if the buffer is stale, clear all the external state associated with
	 * it. We need to keep flags such as how we allocated the buffer memory
	 * intact here.
	 */
	if (bp->b_flags & XBF_STALE) {
		if (flags & XBF_LIVESCAN) {
			xfs_buf_unlock(bp);
			return -ENOENT;
		}
		ASSERT((bp->b_flags & _XBF_DELWRI_Q) == 0);
		bp->b_flags &= _XBF_KMEM;
		bp->b_ops = NULL;
	}
	return 0;
}

static bool
xfs_buf_try_hold(
	struct xfs_buf		*bp)
{
	spin_lock(&bp->b_lock);
	if (bp->b_hold == 0) {
		spin_unlock(&bp->b_lock);
		return false;
	}
	bp->b_hold++;
	mxfs_hold_ev(bp, MXFS_HS_TRYHOLD, 1, _RET_IP_);
	spin_unlock(&bp->b_lock);
	return true;
}

static inline int
xfs_buf_lookup(
	struct xfs_buf_cache	*bch,
	struct xfs_buf_map	*map,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp)
{
	struct xfs_buf          *bp;
	int			error;

	rcu_read_lock();
	bp = rhashtable_lookup(&bch->bc_hash, map, xfs_buf_hash_params);
	if (!bp || !xfs_buf_try_hold(bp)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	error = xfs_buf_find_lock(bp, flags);
	if (error) {
		xfs_buf_rele(bp);
		return error;
	}

	trace_xfs_buf_find(bp, flags, _RET_IP_);
	*bpp = bp;
	return 0;
}

/*
 * Insert the new_bp into the hash table. This consumes the perag reference
 * taken for the lookup regardless of the result of the insert.
 */
static int
xfs_buf_find_insert(
	struct xfs_buftarg	*btp,
	struct xfs_buf_cache	*bch,
	struct xfs_perag	*pag,
	struct xfs_buf_map	*cmap,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp)
{
	struct xfs_buf		*new_bp;
	struct xfs_buf		*bp;
	int			error;

	error = xfs_buf_alloc(btp, map, nmaps, flags, &new_bp);
	if (error)
		goto out_drop_pag;

	/* The new buffer keeps the perag reference until it is freed. */
	new_bp->b_pag = pag;

	rcu_read_lock();
	bp = rhashtable_lookup_get_insert_fast(&bch->bc_hash,
			&new_bp->b_rhash_head, xfs_buf_hash_params);
	if (IS_ERR(bp)) {
		rcu_read_unlock();
		error = PTR_ERR(bp);
		goto out_free_buf;
	}
	if (bp && xfs_buf_try_hold(bp)) {
		/* found an existing buffer */
		rcu_read_unlock();
		error = xfs_buf_find_lock(bp, flags);
		if (error)
			xfs_buf_rele(bp);
		else
			*bpp = bp;
		goto out_free_buf;
	}
	rcu_read_unlock();

	*bpp = new_bp;
	return 0;

out_free_buf:
	xfs_buf_free(new_bp);
out_drop_pag:
	if (pag)
		xfs_perag_put(pag);
	return error;
}

static inline struct xfs_perag *
xfs_buftarg_get_pag(
	struct xfs_buftarg		*btp,
	const struct xfs_buf_map	*map)
{
	struct xfs_mount		*mp = btp->bt_mount;

	if (xfs_buftarg_is_mem(btp))
		return NULL;
	return xfs_perag_get(mp, xfs_daddr_to_agno(mp, map->bm_bn));
}

static inline struct xfs_buf_cache *
xfs_buftarg_buf_cache(
	struct xfs_buftarg		*btp,
	struct xfs_perag		*pag)
{
	if (pag)
		return &pag->pag_bcache;
	return btp->bt_cache;
}

/*
 * sess33 P-WGHOST helper: return the CANONICAL (rhashtable-resident) xfs_buf
 * pointer for a daddr WITHOUT locking or holding it — pointer comparison only.
 * Used at the dir-DATA write chokepoint to decide whether the buffer being
 * destaged is the canonical instance or a stale ghost that was removed from
 * the rhashtable (mechanism B).  RCU-only; never dereferenced after unlock.
 */
struct xfs_buf *
mxfs_dir_canonical_buf_ptr(
	struct xfs_buftarg	*btp,
	xfs_daddr_t		blkno,
	int			numblks)
{
	struct xfs_buf_map	cmap = { .bm_bn = blkno, .bm_len = numblks };
	struct xfs_buf_cache	*bch;
	struct xfs_perag	*pag;
	struct xfs_buf		*bp;

	pag = xfs_buftarg_get_pag(btp, &cmap);
	bch = xfs_buftarg_buf_cache(btp, pag);
	rcu_read_lock();
	bp = rhashtable_lookup(&bch->bc_hash, &cmap, xfs_buf_hash_params);
	rcu_read_unlock();
	if (pag)
		xfs_perag_put(pag);
	return bp;
}

/*
 * Assembles a buffer covering the specified range. The code is optimised for
 * cache hits, as metadata intensive workloads will see 3 orders of magnitude
 * more hits than misses.
 */
int
xfs_buf_get_map(
	struct xfs_buftarg	*btp,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp)
{
	struct xfs_buf_cache	*bch;
	struct xfs_perag	*pag;
	struct xfs_buf		*bp = NULL;
	struct xfs_buf_map	cmap = { .bm_bn = map[0].bm_bn };
	int			error;
	int			i;

	if (flags & XBF_LIVESCAN)
		cmap.bm_flags |= XBM_LIVESCAN;
	for (i = 0; i < nmaps; i++)
		cmap.bm_len += map[i].bm_len;

	error = xfs_buf_map_verify(btp, &cmap);
	if (error)
		return error;

	pag = xfs_buftarg_get_pag(btp, &cmap);
	bch = xfs_buftarg_buf_cache(btp, pag);

	error = xfs_buf_lookup(bch, &cmap, flags, &bp);
	if (error && error != -ENOENT)
		goto out_put_perag;

	/* cache hits always outnumber misses by at least 10:1 */
	if (unlikely(!bp)) {
		XFS_STATS_INC(btp->bt_mount, xb_miss_locked);

		if (flags & XBF_INCORE)
			goto out_put_perag;

		/* xfs_buf_find_insert() consumes the perag reference. */
		error = xfs_buf_find_insert(btp, bch, pag, &cmap, map, nmaps,
				flags, &bp);
		if (error)
			return error;
	} else {
		XFS_STATS_INC(btp->bt_mount, xb_get_locked);
		if (pag)
			xfs_perag_put(pag);
	}

	/*
	 * Clear b_error if this is a lookup from a caller that doesn't expect
	 * valid data to be found in the buffer.
	 */
	if (!(flags & XBF_READ))
		xfs_buf_ioerror(bp, 0);

	XFS_STATS_INC(btp->bt_mount, xb_get);
	trace_xfs_buf_get(bp, flags, _RET_IP_);
	*bpp = bp;
	return 0;

out_put_perag:
	if (pag)
		xfs_perag_put(pag);
	return error;
}

/*
 * sess8 (ccloop a864) — transient torn-read coherency retry for multi-node dir
 * metadata.  A shared directory bmbt-leaf (extent-map) block or dir3
 * data/leaf/node block that the prior EX holder rewrote in rapid succession
 * right before a fast BAST handoff can be cold-read here in a TRANSIENTLY torn
 * state (bad CRC): the coherent SCST/multipath cache image has not yet settled
 * to the writer's latest complete write when the new holder reads it
 * microseconds after acquiring EX.  PROVEN (dir_reuse_coherency@32/caw): rank25
 * wrote dir ino131's bmbt leaf daddr=46051048 numrecs=19 at wall T, began its
 * bast_process drain+unlock at T+1.6ms, and rank1 cold-read the SAME leaf at
 * T+30ms getting EFSBADCRC -> xfs_btree_read_buf_block -> xfs_create ->
 * xfs_trans_cancel -> FS shutdown -> whole 32-node barrier stall (0/32).  A
 * later raw dump of the same block was a fully valid bmbt leaf, so the torn
 * state had SETTLED -> a coherency-timing artifact, not durable corruption.
 * Upstream treats a read-verify (CRC) error as permanent; for a multi-node dir
 * metadata buffer it is transient, so re-read the coherent medium a bounded
 * number of times (short backoff to let the writer's image settle) before
 * surfacing the error.  The reader holds the dir EX here (it just adopted the
 * inode), so no other node mutates the block during the retry: once the prior
 * holder's final write lands, the block is stable and valid.  A genuinely
 * corrupt block still fails after the retries and shuts down exactly as before,
 * so this cannot mask real corruption (P-DIRCRC-RETRY-FAIL names that case).
 */
int mxfs_dir_read_crc_retries = 8;
module_param_named(dir_read_crc_retries, mxfs_dir_read_crc_retries, int, 0644);
MODULE_PARM_DESC(dir_read_crc_retries,
	"bounded coherent re-read retries for a multi-node dir metadata buffer that fails read-verify CRC (transient torn-read after a fast EX handoff); 0 disables");

int mxfs_dir_read_crc_retry_us = 4000;
module_param_named(dir_read_crc_retry_us, mxfs_dir_read_crc_retry_us, int, 0644);
MODULE_PARM_DESC(dir_read_crc_retry_us,
	"microsecond backoff between multi-node dir metadata coherent re-read retries");

static bool
mxfs_buf_is_multinode_dir_meta(struct xfs_buf *bp)
{
	const struct xfs_buf_ops *ops;

	if (!bp || !bp->b_mount || !bp->b_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm))
		return false;
	if (bp->b_map_count != 1)
		return false;
	ops = bp->b_ops;
	/*
	 * 2026-07-16 (fence_during_write@4/caw): xfs_inode_buf_ops added.
	 * Inode CLUSTER buffers hit the exact same transient torn cold-read
	 * (a shared hot dir means every node allocates its churn files from
	 * the SAME inode chunk, so cluster sectors are rewritten by peers
	 * continuously).  Proven: test4 read dinodes 0x484531/0x484532 with
	 * bad CRC mid-storm (xfs_dinode_verify), xfs_ifree consumed the
	 * EUCLEAN -> SHUTDOWN_META_IO_ERROR -> spurious "fence"; a raw
	 * O_DIRECT dump of all the flagged sectors minutes later showed
	 * every one CRC-VALID on the platter — transient, never durable.
	 * One caveat vs dir blocks: the retry comment above assumes the
	 * reader's EX excludes writers during the retry; for an inode
	 * cluster, OTHER dinodes in the buffer may legitimately still be
	 * rewritten by their owners mid-retry.  Each retry is a fresh whole
	 * snapshot and a tear only exists in the instant of a concurrent
	 * sector write, so the bounded backoff loop still converges; a
	 * pathological continuous tear surfaces as P-DIRCRC-RETRY-FAIL.
	 */
	return ops == &xfs_bmbt_buf_ops ||
	       ops == &xfs_dir3_data_buf_ops ||
	       ops == &xfs_dir3_block_buf_ops ||
	       ops == &xfs_dir3_leaf1_buf_ops ||
	       ops == &xfs_dir3_leafn_buf_ops ||
	       ops == &xfs_dir3_free_buf_ops ||
	       ops == &xfs_da3_node_buf_ops ||
	       ops == &xfs_inode_buf_ops;
}

/*
 * Coherently re-read a single-map buffer's block straight from the shared
 * medium (the same coherence point the dir read path uses: plain bio when
 * mxfs_fua_disable, SCSI FUA otherwise) into bp->b_addr, bypassing the mxfs
 * freshness cache, then re-run the buffer's read verifier.  Returns bp->b_error
 * (0 on a now-valid image).  Process context only (sleeps in the bio wait).
 */
static int
mxfs_buf_coherent_reread_verify(struct xfs_buf *bp)
{
	extern int mxfs_fua_disable;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);
	uint32_t	len = BBTOB(bp->b_length);
	uint64_t	lba;
	void		*mb;
	int		rc;

	if (!bp->b_target || !bp->b_target->bt_bdev || !bp->b_addr ||
	    !bp->b_ops || !len || len > (64u << 10))
		return bp->b_error;
	/*
	 * Bounce through a physically-contiguous buffer (the proven P15I idiom):
	 * bp->b_addr may be vmalloc-backed for multi-page buffers, which the
	 * plain/FUA bdev read helpers do not map, so read into kmalloc memory and
	 * memcpy into b_addr (kernel-virtual contiguous for any backing).
	 */
	mb = kmalloc(len, GFP_NOFS);
	if (!mb)
		return bp->b_error;
	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	rc = mxfs_fua_disable ?
		mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev, lba,
					      mb, len) :
		mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev, lba,
					    mb, len);
	if (rc) {
		kfree(mb);
		return bp->b_error;		/* keep the original error */
	}
	/*
	 * sess7 (ccloop 8ba7ae5c) P150 sibling: this coherent re-read is the
	 * same whole-buffer clobber vector as the cold DMA read — for an
	 * inode cluster with attached inode log items, merge the locally-
	 * attached slots from the CURRENT b_addr (last iflush image) into the
	 * fresh platter snapshot before installing it, so a CRC retry cannot
	 * regress a slot this node's iflush owns.
	 */
	if (bp->b_ops == &xfs_inode_buf_ops && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    !list_empty(&bp->b_li_list)) {
		unsigned int	ilog = bp->b_mount->m_sb.sb_inodelog;
		unsigned int	isz = 1u << ilog;
		unsigned int	ni = ilog ? (len >> ilog) : 0;
		struct xfs_log_item *lip;

		if (ni >= 1 && ni <= 64) {
			list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
				struct xfs_inode_log_item *iip;
				int slot;

				if (lip->li_type != XFS_LI_INODE)
					continue;
				iip = (struct xfs_inode_log_item *)lip;
				if (!iip->ili_inode)
					continue;
				/* EX-held only — same ghost exclusion as the
				 * P150 capture site. */
				if (iip->ili_inode->i_dlm_mode != MXFS_LOCK_EX)
					continue;
				slot = iip->ili_inode->i_imap.im_boffset >> ilog;
				if (slot < 0 || (slot + 1u) * isz > len)
					continue;
				memcpy(mb + slot * isz,
				       bp->b_addr + slot * isz, isz);
				pr_warn_ratelimited(
					"mxfs: P150-REREAD-MERGE daddr=%lld slot=%d ino=%llu\n",
					(long long)bp->b_maps[0].bm_bn, slot,
					(unsigned long long)iip->ili_inode->i_ino);
			}
		}
	}
	memcpy(bp->b_addr, mb, len);
	kfree(mb);
	bp->b_error = 0;
	bp->b_ops->verify_read(bp);
	return bp->b_error;
}

int
_xfs_buf_read(
	struct xfs_buf		*bp)
{
	int			error;

	ASSERT(bp->b_maps[0].bm_bn != XFS_BUF_DADDR_NULL);

	/*
	 * sess75 (ccloop 14d31183) PROVEN ROOT FIX for the unmount wedge: a
	 * buffer that still carries XBF_READ_AHEAD here was counted as an
	 * outstanding readahead in xfs_buf_readahead_map (bt_readahead_count++),
	 * but is now being converted to a synchronous read.  We are about to
	 * clear XBF_READ_AHEAD, so this buffer's eventual __xfs_buf_ioend will see
	 * the flag cleared and SKIP the matching bt_readahead_count-- — leaking
	 * the count by 1.  At unmount xfs_buftarg_wait then spins forever waiting
	 * for the readahead count to reach 0 (D-state umount, no sysrq exit).
	 * Settle the readahead accounting here so inc/dec stay balanced.
	 *
	 * Proven live (RULE 4) on the 16-node dpn=100 zero_silent_loss storm:
	 * P-RA-CLEAR-AT-BUFREAD daddr=<bmbt> comm=touch with the buffer still in
	 * the readahead-tracking table, stack
	 * xfs_iread_extents -> xfs_btree_visit_blocks -> xfs_btree_read_buf_block
	 * -> _xfs_buf_read — a dir extent-map reload's bmbt readahead stolen by
	 * the same lookup's synchronous bmbt read.  The decrement here pairs
	 * exactly with the inc; the re-submitted read below completes with
	 * XBF_READ_AHEAD clear and correctly does not double-decrement.
	 */
	if (unlikely(bp->b_flags & XBF_READ_AHEAD)) {
		bool stole_hold = false;

		percpu_counter_dec(&bp->b_target->bt_readahead_count);
		/*
		 * sess76 (ccloop 14d31183): also release the orphaned readahead
		 * HOLD.  xfs_buf_readahead_map took a hold reference in addition to
		 * incrementing bt_readahead_count; both are released by the async
		 * readahead completion (xfs_buf_ioend -> __xfs_buf_ioend dec +
		 * xfs_buf_relse).  This buffer reached _xfs_buf_read with
		 * XBF_READ_AHEAD still set while WE hold its lock — a pending async
		 * ioend would still own the buffer lock, so that completion never
		 * ran and its hold is still outstanding.  We are converting to a
		 * synchronous read whose completion does NOT relse, so drop the
		 * orphaned hold here.  Guard b_hold>1 so we never free the buffer
		 * we are about to read (xfs_buf_read_map's own reference must
		 * survive).  Without the count dec, xfs_buftarg_wait spins at
		 * unmount; without this hold drop, xfs_buftarg_drain spins forever
		 * on the never-released LRU buffer (the sess76 P-DRAINSTUCK wedge).
		 */
		spin_lock(&bp->b_lock);
		if (bp->b_hold > 1) {
			bp->b_hold--;
			stole_hold = true;
			mxfs_hold_ev(bp, MXFS_HS_RA_ORPHAN, -1, _RET_IP_);
		}
		spin_unlock(&bp->b_lock);
		pr_warn_ratelimited("mxfs: P-RAFIX-BUFREAD settled stolen readahead daddr=%lld ops=%s hold_after=%d droppedhold=%d async=%d comm=%s\n",
			(long long)bp->b_maps[0].bm_bn,
			(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
			bp->b_hold, stole_hold, !!(bp->b_flags & XBF_ASYNC),
			current->comm);
	}

	bp->b_flags &= ~(XBF_WRITE | XBF_ASYNC | XBF_READ_AHEAD | XBF_DONE);
	bp->b_flags |= XBF_READ;
	bp->b_mxfs_force_sync = true;	/* sess8: sync read — latch intent vs the XBF_ASYNC race (see xfs_bwrite) */
	xfs_buf_submit(bp);
	error = xfs_buf_iowait(bp);

	/*
	 * sess8 (ccloop a864): transient torn-read coherency retry for a
	 * multi-node dir metadata buffer (see the comment above
	 * mxfs_buf_is_multinode_dir_meta).  Only on a read-verify CRC failure,
	 * in process context (xfs_buf_iowait blocked here), fs not shut down.
	 */
	if (unlikely((error == -EFSBADCRC || error == -EFSCORRUPTED) &&
		     mxfs_dir_read_crc_retries > 0 &&
		     mxfs_buf_is_multinode_dir_meta(bp) &&
		     bp->b_mount && !xfs_is_shutdown(bp->b_mount))) {
		int	tries;

		for (tries = 1;
		     tries <= mxfs_dir_read_crc_retries &&
			(error == -EFSBADCRC || error == -EFSCORRUPTED);
		     tries++) {
			if (mxfs_dir_read_crc_retry_us > 0)
				usleep_range(mxfs_dir_read_crc_retry_us,
					     mxfs_dir_read_crc_retry_us * 2);
			error = mxfs_buf_coherent_reread_verify(bp);
			pr_warn_ratelimited("mxfs: P-DIRCRC-RETRY daddr=%lld ops=%s try=%d err=%d comm=%s\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ?
					bp->b_ops->name : "?",
				tries, error, current->comm);
		}
		if (!error) {
			bp->b_flags |= XBF_DONE;
			pr_warn_ratelimited("mxfs: P-DIRCRC-RETRY-OK daddr=%lld ops=%s — transient torn read settled\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ?
					bp->b_ops->name : "?");
		} else {
			pr_warn("mxfs: P-DIRCRC-RETRY-FAIL daddr=%lld ops=%s err=%d — durable, not transient\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ?
					bp->b_ops->name : "?",
				error);
		}
	}
	return error;
}

/*
 * Reverify a buffer found in cache without an attached ->b_ops.
 *
 * If the caller passed an ops structure and the buffer doesn't have ops
 * assigned, set the ops and use it to verify the contents. If verification
 * fails, clear XBF_DONE. We assume the buffer has no recorded errors and is
 * already in XBF_DONE state on entry.
 *
 * Under normal operations, every in-core buffer is verified on read I/O
 * completion. There are two scenarios that can lead to in-core buffers without
 * an assigned ->b_ops. The first is during log recovery of buffers on a V4
 * filesystem, though these buffers are purged at the end of recovery. The
 * other is online repair, which intentionally reads with a NULL buffer ops to
 * run several verifiers across an in-core buffer in order to establish buffer
 * type.  If repair can't establish that, the buffer will be left in memory
 * with NULL buffer ops.
 */
int
xfs_buf_reverify(
	struct xfs_buf		*bp,
	const struct xfs_buf_ops *ops)
{
	ASSERT(bp->b_flags & XBF_DONE);
	ASSERT(bp->b_error == 0);

	if (!ops || bp->b_ops)
		return 0;

	bp->b_ops = ops;
	bp->b_ops->verify_read(bp);
	if (bp->b_error)
		bp->b_flags &= ~XBF_DONE;
	return bp->b_error;
}

int
xfs_buf_read_map(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp,
	const struct xfs_buf_ops *ops,
	xfs_failaddr_t		fa)
{
	struct xfs_buf		*bp;
	int			error;

	ASSERT(!(flags & (XBF_WRITE | XBF_ASYNC | XBF_READ_AHEAD)));

	flags |= XBF_READ;
	*bpp = NULL;

	error = xfs_buf_get_map(target, map, nmaps, flags, &bp);
	if (error)
		return error;

	trace_xfs_buf_read(bp, flags, _RET_IP_);

	if (!(bp->b_flags & XBF_DONE)) {
		/*
		 * sess2 (ccloop a16ec5f2) RULE-4 DETECTOR — P-PINNED-REREAD.
		 * Upstream NEVER re-reads a buffer carrying committed-but-not-
		 * checkpointed modifications (DONE implies valid); only mxfs's
		 * coherence-evict DONE-clears can create that state.  A read
		 * here on a PINNED or CIL-DIRTY buffer REPLACES b_addr with
		 * the older disk image: the committed delta (e.g. a peer-
		 * visible dirent add) silently vanishes from materialized
		 * state while the log moves on — the run10 r10 cluster-wide
		 * 4-dirent loss signature (creators lose their own entries,
		 * no P-COUNTREGRESS at any submit).  Log + stack so the
		 * guilty evict site can be identified and gated.
		 */
		if (unlikely(bp->b_log_item &&
			     (test_bit(XFS_LI_DIRTY,
				       &bp->b_log_item->bli_item.li_flags) ||
			      xfs_buf_ispinned(bp)))) {
			pr_warn("mxfs: P-PINNED-REREAD daddr=%lld ops=%s dirty=%d pin=%d in_ail=%d comm=%s — re-reading a buffer with committed-unCheckpointed content (delta will be LOST)\n",
				(long long)bp->b_maps[0].bm_bn,
				ops && ops->name ? ops->name : "?",
				test_bit(XFS_LI_DIRTY,
					 &bp->b_log_item->bli_item.li_flags) ? 1 : 0,
				xfs_buf_ispinned(bp) ? 1 : 0,
				test_bit(XFS_LI_IN_AIL,
					 &bp->b_log_item->bli_item.li_flags) ? 1 : 0,
				current->comm);
			dump_stack();
		}
		/*
		 * sess6 (ccloop 8ba7ae5c) AG-META TIME-TRAVEL FENCE (GPT
		 * RULE-5 design, "flush-before-hazardous-cold-read").  A COLD
		 * read of AG allocation metadata whose AG saw a local write
		 * completion in the CURRENT flush epoch may return the PRE-
		 * write media image (completion == target write cache, not
		 * platter; the FUA read bypasses that cache): the free-space
		 * state regresses and already-owned blocks get re-allocated
		 * (iter_10 proven double-alloc, agno7/295 uv-dir vs pm).
		 * Fence: one coalesced device flush BEFORE the read; the
		 * epoch advance then marks every AG's stamp stale.  No cost
		 * unless an evicted AG-meta buffer is re-read inside an
		 * unflushed window (rare — storm + memory pressure).
		 */
		if (ops && target->bt_mount && target->bt_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(target->bt_mount->m_mxfs_dlm) &&
		    mxfs_agmeta_ops(ops)) {
			struct xfs_mount *fmp = target->bt_mount;
			struct xfs_perag *hpag = xfs_perag_get(fmp,
				xfs_daddr_to_agno(fmp, bp->b_maps[0].bm_bn));

			if (hpag) {
				if (atomic64_read(&hpag->pag_mxfs_meta_wr_epoch) >=
				    atomic64_read(&fmp->m_mxfs_flush_epoch)) {
					extern void mxfs_release_coalesced_flush(
							struct xfs_mount *);
					static atomic_t p143_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p143_n) <= 60)
						pr_warn("mxfs: P143-AGMETA-FLUSHREAD agno=%u daddr=%lld ops=%s wr_epoch=%lld flush_epoch=%lld comm=%s — cold AG-meta read inside unflushed write window; fencing with device flush\n",
							xfs_daddr_to_agno(fmp, bp->b_maps[0].bm_bn),
							(long long)bp->b_maps[0].bm_bn,
							ops->name ? ops->name : "?",
							(long long)atomic64_read(&hpag->pag_mxfs_meta_wr_epoch),
							(long long)atomic64_read(&fmp->m_mxfs_flush_epoch),
							current->comm);
					mxfs_release_coalesced_flush(fmp);
				}
				xfs_perag_put(hpag);
			}
		}

		/* Initiate the buffer read and wait. */
		XFS_STATS_INC(target->bt_mount, xb_get_read);
		bp->b_ops = ops;
		error = _xfs_buf_read(bp);
		/* sess6 (8ba7ae5c): P144-RD — cold-read fingerprint sibling
		 * of the P144-WR submission print (multi-node bnobt/cntbt). */
		if (!error && bp->b_addr && target->bt_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(target->bt_mount->m_mxfs_dlm) &&
		    mxfs_p144_ops(ops))
			mxfs_p144_print(bp, "RD");
	} else {
		/* Buffer already read; all we need to do is check it. */
		error = xfs_buf_reverify(bp, ops);

		/* We do not want read in the flags */
		bp->b_flags &= ~XBF_READ;
		ASSERT(bp->b_ops != NULL || ops == NULL);
	}

	/*
	 * If we've had a read error, then the contents of the buffer are
	 * invalid and should not be used. To ensure that a followup read tries
	 * to pull the buffer from disk again, we clear the XBF_DONE flag and
	 * mark the buffer stale. This ensures that anyone who has a current
	 * reference to the buffer will interpret it's contents correctly and
	 * future cache lookups will also treat it as an empty, uninitialised
	 * buffer.
	 */
	if (error) {
		/*
		 * Check against log shutdown for error reporting because
		 * metadata writeback may require a read first and we need to
		 * report errors in metadata writeback until the log is shut
		 * down. High level transaction read functions already check
		 * against mount shutdown, anyway, so we only need to be
		 * concerned about low level IO interactions here.
		 */
		if (!xlog_is_shutdown(target->bt_mount->m_log))
			xfs_buf_ioerror_alert(bp, fa);

		bp->b_flags &= ~XBF_DONE;
		xfs_buf_stale(bp);
		xfs_buf_relse(bp);

		/* bad CRC means corrupted metadata */
		if (error == -EFSBADCRC)
			error = -EFSCORRUPTED;
		return error;
	}

	*bpp = bp;
	return 0;
}

/*
 *	If we are not low on memory then do the readahead in a deadlock
 *	safe manner.
 */
void
xfs_buf_readahead_map(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	const struct xfs_buf_ops *ops)
{
	const xfs_buf_flags_t	flags = XBF_READ | XBF_ASYNC | XBF_READ_AHEAD;
	struct xfs_buf		*bp;

	/*
	 * Currently we don't have a good means or justification for performing
	 * xmbuf_map_page asynchronously, so we don't do readahead.
	 */
	if (xfs_buftarg_is_mem(target))
		return;

	/*
	 * sess6 (ccloop 8ba7ae5c): skip readahead of AG allocation metadata
	 * inside an unflushed local-write window — an async RA read here
	 * would populate the buffer DONE with a possibly PRE-write media
	 * image, and the later sync read would accept it without ever
	 * passing the xfs_buf_read_map time-travel fence.  Skipping costs
	 * one RA; the sync read that follows takes the fenced path.
	 */
	if (ops && target->bt_mount && target->bt_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(target->bt_mount->m_mxfs_dlm) &&
	    mxfs_agmeta_ops(ops)) {
		struct xfs_perag *hpag = xfs_perag_get(target->bt_mount,
			xfs_daddr_to_agno(target->bt_mount, map[0].bm_bn));

		if (hpag) {
			bool hazard =
				atomic64_read(&hpag->pag_mxfs_meta_wr_epoch) >=
				atomic64_read(&target->bt_mount->m_mxfs_flush_epoch);
			xfs_perag_put(hpag);
			if (hazard)
				return;
		}
	}

	if (xfs_buf_get_map(target, map, nmaps, flags | XBF_TRYLOCK, &bp))
		return;
	trace_xfs_buf_readahead(bp, 0, _RET_IP_);

	if (bp->b_flags & XBF_DONE) {
		xfs_buf_reverify(bp, ops);
		xfs_buf_relse(bp);
		return;
	}
	XFS_STATS_INC(target->bt_mount, xb_get_read);
	bp->b_ops = ops;
	bp->b_flags &= ~(XBF_WRITE | XBF_DONE);
	bp->b_flags |= flags;
	percpu_counter_inc(&target->bt_readahead_count);
	xfs_buf_submit(bp);
}

/*
 * Read an uncached buffer from disk. Allocates and returns a locked
 * buffer containing the disk contents or nothing. Uncached buffers always have
 * a cache index of XFS_BUF_DADDR_NULL so we can easily determine if the buffer
 * is cached or uncached during fault diagnosis.
 */
int
xfs_buf_read_uncached(
	struct xfs_buftarg	*target,
	xfs_daddr_t		daddr,
	size_t			numblks,
	struct xfs_buf		**bpp,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf		*bp;
	int			error;

	*bpp = NULL;

	error = xfs_buf_get_uncached(target, numblks, &bp);
	if (error)
		return error;

	/* set up the buffer for a read IO */
	ASSERT(bp->b_map_count == 1);
	bp->b_rhash_key = XFS_BUF_DADDR_NULL;
	bp->b_maps[0].bm_bn = daddr;
	bp->b_flags |= XBF_READ;
	bp->b_ops = ops;

	xfs_buf_submit(bp);
	error = xfs_buf_iowait(bp);
	if (error) {
		xfs_buf_relse(bp);
		return error;
	}

	*bpp = bp;
	return 0;
}

int
xfs_buf_get_uncached(
	struct xfs_buftarg	*target,
	size_t			numblks,
	struct xfs_buf		**bpp)
{
	int			error;
	DEFINE_SINGLE_BUF_MAP(map, XFS_BUF_DADDR_NULL, numblks);

	error = xfs_buf_alloc(target, &map, 1, 0, bpp);
	if (!error)
		trace_xfs_buf_get_uncached(*bpp, _RET_IP_);
	return error;
}

/*
 *	Increment reference count on buffer, to hold the buffer concurrently
 *	with another thread which may release (free) the buffer asynchronously.
 *	Must hold the buffer already to call this function.
 */
void
xfs_buf_hold(
	struct xfs_buf		*bp)
{
	trace_xfs_buf_hold(bp, _RET_IP_);

	spin_lock(&bp->b_lock);
	bp->b_hold++;
	mxfs_hold_ev(bp, MXFS_HS_HOLD, 1, _RET_IP_);
	spin_unlock(&bp->b_lock);
}

static void
xfs_buf_rele_uncached(
	struct xfs_buf		*bp,
	unsigned long		caller)
{
	ASSERT(list_empty(&bp->b_lru));

	spin_lock(&bp->b_lock);
	/* ccloop 72513a13 poison guard: a rele on b_hold==0 is a
	 * double-release (zombie within the RCU grace window) — the
	 * decrement would wrap and resurrect the buffer into a second
	 * xfs_buf_free (test25 slub double-free family).  Catch it. */
	if (WARN(bp->b_hold == 0,
		 "mxfs: P-BUF-RELE-ZERO uncached daddr=%lld comm=%s — double release suppressed\n",
		 (long long)bp->b_rhash_key, current->comm)) {
		spin_unlock(&bp->b_lock);
		return;
	}
	--bp->b_hold;
	mxfs_hold_ev(bp, MXFS_HS_RELE_UNCACHED, -1, caller);
	if (bp->b_hold) {
		spin_unlock(&bp->b_lock);
		return;
	}
	spin_unlock(&bp->b_lock);
	xfs_buf_free(bp);
}

static void
xfs_buf_rele_cached(
	struct xfs_buf		*bp,
	unsigned long		caller)
{
	struct xfs_buftarg	*btp = bp->b_target;
	struct xfs_perag	*pag = bp->b_pag;
	struct xfs_buf_cache	*bch = xfs_buftarg_buf_cache(btp, pag);
	bool			freebuf = false;

	trace_xfs_buf_rele(bp, _RET_IP_);

	spin_lock(&bp->b_lock);
	ASSERT(bp->b_hold >= 1);
	/* ccloop 72513a13 poison guard (see rele_uncached): rele on a
	 * b_hold==0 zombie must not wrap/hash-remove/perag-put/free a
	 * second time.  WARN gives the extra releaser's stack. */
	if (WARN(bp->b_hold == 0,
		 "mxfs: P-BUF-RELE-ZERO cached daddr=%lld comm=%s — double release suppressed\n",
		 (long long)bp->b_rhash_key, current->comm)) {
		spin_unlock(&bp->b_lock);
		return;
	}
	if (bp->b_hold > 1) {
		bp->b_hold--;
		mxfs_hold_ev(bp, MXFS_HS_RELE_CACHED, -1, caller);
		goto out_unlock;
	}

	/* we are asked to drop the last reference */
	if (atomic_read(&bp->b_lru_ref)) {
		/*
		 * If the buffer is added to the LRU, keep the reference to the
		 * buffer for the LRU and clear the (now stale) dispose list
		 * state flag, else drop the reference.
		 */
		if (list_lru_add_obj(&btp->bt_lru, &bp->b_lru))
			bp->b_state &= ~XFS_BSTATE_DISPOSE;
		else {
			bp->b_hold--;
			mxfs_hold_ev(bp, MXFS_HS_RELE_CACHED, -1, caller);
		}
	} else {
		bp->b_hold--;
		mxfs_hold_ev(bp, MXFS_HS_RELE_CACHED, -1, caller);
		/*
		 * most of the time buffers will already be removed from the
		 * LRU, so optimise that case by checking for the
		 * XFS_BSTATE_DISPOSE flag indicating the last list the buffer
		 * was on was the disposal list
		 */
		if (!(bp->b_state & XFS_BSTATE_DISPOSE)) {
			list_lru_del_obj(&btp->bt_lru, &bp->b_lru);
		} else {
			ASSERT(list_empty(&bp->b_lru));
		}

		ASSERT(!(bp->b_flags & _XBF_DELWRI_Q));
		rhashtable_remove_fast(&bch->bc_hash, &bp->b_rhash_head,
				xfs_buf_hash_params);
		if (pag)
			xfs_perag_put(pag);
		freebuf = true;
	}

out_unlock:
	spin_unlock(&bp->b_lock);

	if (freebuf)
		xfs_buf_free(bp);
}

/*
 * Release a hold on the specified buffer.
 */
void
xfs_buf_rele(
	struct xfs_buf		*bp)
{
	unsigned long		caller = _RET_IP_;

	trace_xfs_buf_rele(bp, _RET_IP_);
	if (xfs_buf_is_uncached(bp))
		xfs_buf_rele_uncached(bp, caller);
	else
		xfs_buf_rele_cached(bp, caller);
}

/*
 *	Lock a buffer object, if it is not already locked.
 *
 *	If we come across a stale, pinned, locked buffer, we know that we are
 *	being asked to lock a buffer that has been reallocated. Because it is
 *	pinned, we know that the log has not been pushed to disk and hence it
 *	will still be locked.  Rather than continuing to have trylock attempts
 *	fail until someone else pushes the log, push it ourselves before
 *	returning.  This means that the xfsaild will not get stuck trying
 *	to push on stale inode buffers.
 */
/*
 * sess1(e8e920f7) RULE-4 probe — b_sema poisoning detector, acquire side.
 * b_sema is a binary lock: immediately after a successful down/down_trylock
 * its count MUST be 0.  count>0 here means the semaphore carries an EXTRA
 * credit from a historical unpaired up (double relse/unlock) — this buffer
 * is now multi-ownable, and every path that "locks" it can run concurrently
 * with another owner (PROVEN live: validate2 run 015913Z, 54× P-WRCNT-RESUBMIT
 * on 3 dir bufs = xfsaild's delwri trylock succeeding while rm held the
 * buffer mid-flush; terminal: double xfs_buf_item_done → ail_delete-not-in-AIL
 * spurious SHUTDOWN 0x8 + xfsaild NULL-relse oops, test1 r17).  The unlock-
 * side probe (P-SEMA-OVERUP) catches the poisoning MOMENT; this one catches
 * every subsequent dual-own so the victim set is visible.
 */
static void
mxfs_buf_sema_dualock_check(
	struct xfs_buf	*bp,
	const char	*path)
{
	unsigned int	semac = READ_ONCE(bp->b_sema.count);

	if (likely(semac == 0))
		return;
	{
		static atomic_t pdl_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&pdl_n);

		if (n <= 400) {
			unsigned int evi = bp->b_mxfs_evi;

			pr_warn("mxfs: P-SEMA-DUALLOCK path=%s daddr=%lld ops=%s flags=0x%x count=%u prev_owner_ip=%pS comm=%s evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx]\n",
			    path,
			    (long long)bp->b_maps[0].bm_bn,
			    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
			    (unsigned int)bp->b_flags, semac,
			    bp->b_lock_ip, current->comm, evi,
			    bp->b_mxfs_evring[(evi + 0) & 7],
			    bp->b_mxfs_evring[(evi + 1) & 7],
			    bp->b_mxfs_evring[(evi + 2) & 7],
			    bp->b_mxfs_evring[(evi + 3) & 7],
			    bp->b_mxfs_evring[(evi + 4) & 7],
			    bp->b_mxfs_evring[(evi + 5) & 7],
			    bp->b_mxfs_evring[(evi + 6) & 7],
			    bp->b_mxfs_evring[(evi + 7) & 7]);
			if (n <= 8)
				dump_stack();
		}
	}
}

int
xfs_buf_trylock(
	struct xfs_buf		*bp)
{
	int			locked;

	locked = down_trylock(&bp->b_sema) == 0;
	if (locked) {
		mxfs_buf_sema_dualock_check(bp, "trylock");
		bp->b_lock_ip = __builtin_return_address(0);
		trace_xfs_buf_trylock(bp, _RET_IP_);
	} else
		trace_xfs_buf_trylock_fail(bp, _RET_IP_);
	return locked;
}

/*
 *	Lock a buffer object.
 *
 *	If we come across a stale, pinned, locked buffer, we know that we
 *	are being asked to lock a buffer that has been reallocated. Because
 *	it is pinned, we know that the log has not been pushed to disk and
 *	hence it will still be locked. Rather than sleeping until someone
 *	else pushes the log, push it ourselves before trying to get the lock.
 */
void
xfs_buf_lock(
	struct xfs_buf		*bp)
{
	trace_xfs_buf_lock(bp, _RET_IP_);

	if (atomic_read(&bp->b_pin_count) && (bp->b_flags & XBF_STALE))
		xfs_log_force(bp->b_mount, 0);
	/*
	 * ccloop-4dd7 sess3 (b54r1 test1 node-wide convoy, RULE-4 probe):
	 * the inode-cluster buffer at daddr 128 was left LOCKED with no live
	 * holder thread anywhere on the node (exhaustive /proc/pid/stack
	 * sweep) and flags XBF_WRITE|ASYNC|DONE — a submitted write whose
	 * completion never ran, or a locker that returned without unlock.
	 * rmdir blocked here inside do_rmdir's dput (which this kernel runs
	 * BEFORE inode_unlock(parent)), so the parent dir i_rwsem convoyed
	 * every worker; the peer starved on the dir DLM 184s -> -110 ->
	 * dirty-cancel shutdown.  Self-name the wedge: after 30s blocked,
	 * report the buffer identity, the last locker (b_lock_ip), and the
	 * completion forensics (evring, ioend/relse counters, sync credit)
	 * every 30s, then keep waiting — no behavior change.
	 */
	while (down_timeout(&bp->b_sema, 30 * HZ) != 0) {
		static atomic_t pbls_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&pbls_n) <= 400) {
			unsigned int evi = bp->b_mxfs_evi;

			pr_warn("mxfs: P-BUFLOCK-STUCK daddr=%lld len=%d ops=%s flags=0x%x hold=%u pin=%d err=%d lock_ip=%pS ioend_seen=%u relse_seen=%u syncw=%d evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx] waiter=%pS comm=%s\n",
				(long long)bp->b_maps[0].bm_bn, bp->b_length,
				bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
				(unsigned int)bp->b_flags, bp->b_hold,
				atomic_read(&bp->b_pin_count), bp->b_error,
				bp->b_lock_ip,
				bp->b_mxfs_ioend_seen, bp->b_mxfs_relse_seen,
				atomic_read(&bp->b_mxfs_sync_waiters), evi,
				bp->b_mxfs_evring[(evi + 0) & 7],
				bp->b_mxfs_evring[(evi + 1) & 7],
				bp->b_mxfs_evring[(evi + 2) & 7],
				bp->b_mxfs_evring[(evi + 3) & 7],
				bp->b_mxfs_evring[(evi + 4) & 7],
				bp->b_mxfs_evring[(evi + 5) & 7],
				bp->b_mxfs_evring[(evi + 6) & 7],
				bp->b_mxfs_evring[(evi + 7) & 7],
				__builtin_return_address(0), current->comm);
		}
	}
	mxfs_buf_sema_dualock_check(bp, "lock");
	bp->b_lock_ip = __builtin_return_address(0);

	trace_xfs_buf_lock_done(bp, _RET_IP_);
}

void
xfs_buf_unlock(
	struct xfs_buf		*bp)
{
	ASSERT(xfs_buf_islocked(bp));

	bp->b_lock_ip = NULL;
	up(&bp->b_sema);
	/*
	 * sess1(e8e920f7) RULE-4 probe — b_sema over-release detector.  For a
	 * binary lock the count after OUR up() can only be 0 (a waiter was
	 * woken / someone immediately re-acquired) or 1 (now free).  count>1
	 * means this up() stacked on top of a still-free semaphore: one of the
	 * two most recent unlockers released a lock it did not own (unpaired
	 * relse/unlock — the poisoning event behind the dual-owner double
	 * submits and the r17 double-item_done crash).  The CURRENT stack is
	 * one of the two suspects; the event ring names the other's path.
	 */
	{
		unsigned int	semac = READ_ONCE(bp->b_sema.count);

		if (unlikely(semac > 1)) {
			static atomic_t pou_n = ATOMIC_INIT(0);
			int n = atomic_inc_return(&pou_n);

			if (n <= 400) {
				unsigned int evi = bp->b_mxfs_evi;

				pr_warn("mxfs: P-SEMA-OVERUP daddr=%lld ops=%s flags=0x%x count=%u comm=%s evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx]\n",
				    (long long)bp->b_maps[0].bm_bn,
				    bp->b_ops && bp->b_ops->name ?
					bp->b_ops->name : "?",
				    (unsigned int)bp->b_flags, semac,
				    current->comm, evi,
				    bp->b_mxfs_evring[(evi + 0) & 7],
				    bp->b_mxfs_evring[(evi + 1) & 7],
				    bp->b_mxfs_evring[(evi + 2) & 7],
				    bp->b_mxfs_evring[(evi + 3) & 7],
				    bp->b_mxfs_evring[(evi + 4) & 7],
				    bp->b_mxfs_evring[(evi + 5) & 7],
				    bp->b_mxfs_evring[(evi + 6) & 7],
				    bp->b_mxfs_evring[(evi + 7) & 7]);
				if (n <= 8)
					dump_stack();
			}
		}
	}
	trace_xfs_buf_unlock(bp, _RET_IP_);
}

STATIC void
xfs_buf_wait_unpin(
	struct xfs_buf		*bp)
{
	DECLARE_WAITQUEUE	(wait, current);

	if (atomic_read(&bp->b_pin_count) == 0)
		return;

	add_wait_queue(&bp->b_waiters, &wait);
	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (atomic_read(&bp->b_pin_count) == 0)
			break;
		io_schedule();
	}
	remove_wait_queue(&bp->b_waiters, &wait);
	set_current_state(TASK_RUNNING);
}

static void
xfs_buf_ioerror_alert_ratelimited(
	struct xfs_buf		*bp)
{
	static unsigned long	lasttime;
	static struct xfs_buftarg *lasttarg;

	if (bp->b_target != lasttarg ||
	    time_after(jiffies, (lasttime + 5*HZ))) {
		lasttime = jiffies;
		xfs_buf_ioerror_alert(bp, __this_address);
	}
	lasttarg = bp->b_target;
}

/*
 * Account for this latest trip around the retry handler, and decide if
 * we've failed enough times to constitute a permanent failure.
 */
static bool
xfs_buf_ioerror_permanent(
	struct xfs_buf		*bp,
	struct xfs_error_cfg	*cfg)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (cfg->max_retries != XFS_ERR_RETRY_FOREVER &&
	    ++bp->b_retries > cfg->max_retries)
		return true;
	if (cfg->retry_timeout != XFS_ERR_RETRY_FOREVER &&
	    time_after(jiffies, cfg->retry_timeout + bp->b_first_retry_time))
		return true;

	/* At unmount we may treat errors differently */
	if (xfs_is_unmounting(mp) && mp->m_fail_unmount)
		return true;

	return false;
}

/*
 * On a sync write or shutdown we just want to stale the buffer and let the
 * caller handle the error in bp->b_error appropriately.
 *
 * If the write was asynchronous then no one will be looking for the error.  If
 * this is the first failure of this type, clear the error state and write the
 * buffer out again. This means we always retry an async write failure at least
 * once, but we also need to set the buffer up to behave correctly now for
 * repeated failures.
 *
 * If we get repeated async write failures, then we take action according to the
 * error configuration we have been set up to use.
 *
 * Returns true if this function took care of error handling and the caller must
 * not touch the buffer again.  Return false if the caller should proceed with
 * normal I/O completion handling.
 */
static bool
xfs_buf_ioend_handle_error(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_error_cfg	*cfg;
	struct xfs_log_item	*lip;

	mxfs_buf_ev(bp, MXFS_BEV_EHERR);

	/*
	 * If we've already shutdown the journal because of I/O errors, there's
	 * no point in giving this a retry.
	 */
	if (xlog_is_shutdown(mp->m_log))
		goto out_stale;

	xfs_buf_ioerror_alert_ratelimited(bp);

	/*
	 * We're not going to bother about retrying this during recovery.
	 * One strike!
	 */
	if (bp->b_flags & _XBF_LOGRECOVERY) {
		xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		return false;
	}

	/*
	 * Synchronous writes will have callers process the error.
	 */
	if (!(bp->b_flags & XBF_ASYNC))
		goto out_stale;

	trace_xfs_buf_iodone_async(bp, _RET_IP_);

	cfg = xfs_error_get_cfg(mp, XFS_ERR_METADATA, bp->b_error);
	if (bp->b_last_error != bp->b_error ||
	    !(bp->b_flags & (XBF_STALE | XBF_WRITE_FAIL))) {
		bp->b_last_error = bp->b_error;
		if (cfg->retry_timeout != XFS_ERR_RETRY_FOREVER &&
		    !bp->b_first_retry_time)
			bp->b_first_retry_time = jiffies;
		goto resubmit;
	}

	/*
	 * Permanent error - we need to trigger a shutdown if we haven't already
	 * to indicate that inconsistency will result from this action.
	 */
	if (xfs_buf_ioerror_permanent(bp, cfg)) {
		xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		goto out_stale;
	}

	/* Still considered a transient error. Caller will schedule retries. */
	list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
		set_bit(XFS_LI_FAILED, &lip->li_flags);
		clear_bit(XFS_LI_FLUSHING, &lip->li_flags);
	}

	xfs_buf_ioerror(bp, 0);
	/*
	 * ccloop3e02 sess2: a blind xfs_buf_relse() here dropped the lock out
	 * from under a still-pending SYNCHRONOUS submitter (xfs_buf_iowait's
	 * caller owns its own relse, after it wakes) — the same class of
	 * b_sema leak as the completion-routing bug this session fixed.  Wake
	 * the registered waiter instead when one is pending; only relse when
	 * this error belongs to a fire-and-forget async submission.
	 */
	if (!mxfs_buf_completion_wake_sync(bp))
		xfs_buf_relse(bp);
	return true;

resubmit:
	xfs_buf_ioerror(bp, 0);
	bp->b_flags |= (XBF_DONE | XBF_WRITE_FAIL);
	mxfs_buf_ev(bp, MXFS_BEV_RESUB);
	/*
	 * sess9 (ccloop a864) / ccloop3e02 sess2: carry the CURRENT sync
	 * waiter credit into the resubmit's reinit so the retry's completion
	 * still knows to wake it.  Do NOT let the resubmit itself register a
	 * SECOND credit (xfs_buf_submit_ex(..., false)) — the original
	 * submission's credit is still outstanding (never consumed, since the
	 * error path bypasses the normal completion routing entirely); a
	 * second increment here would leak an extra credit that no real
	 * caller will ever match, corrupting the count for this buffer's
	 * NEXT incarnation.
	 */
	bp->b_mxfs_force_sync = atomic_read(&bp->b_mxfs_sync_waiters) > 0;
	reinit_completion(&bp->b_iowait);
	xfs_buf_submit_ex(bp, false);
	return true;
out_stale:
	xfs_buf_stale(bp);
	bp->b_flags |= XBF_DONE;
	bp->b_flags &= ~XBF_WRITE;
	trace_xfs_buf_error_relse(bp, _RET_IP_);
	return false;
}

/*
 * mxfs_dir_wr_inflight_dec — retire one counted dir-metadata write from
 * m_mxfs_dir_wr_inflight (real I/O completion in __xfs_buf_ioend, or an
 * emulated one from the bmbt chokepoint-skip path).  GPT-consult follow-up
 * (2026-07-11, see ccmemory gpt-consult-dir_reuse32-architectural-review
 * item #1): the old silent clamp-to-0 on underflow can mask a genuine
 * double-retirement — e.g. a completion that was leaked (never fired) on
 * one submission of a reused buffer, later "recovered" when a SECOND,
 * distinct submission's completion fires and decrements on the leaked
 * submission's behalf (see the P-WRCNT-RESUBMIT keep-single-count logic
 * below), followed by the original leaked completion eventually firing
 * too.  Two decrements against one increment silently clamped to 0 would
 * let the release fence see "0 in-flight" one write EARLIER than true
 * if a third, distinct write was genuinely still in flight at that same
 * moment — exactly the failure mode a boolean-gated counter cannot rule
 * out on its own (see the consult's critique: a bool can't distinguish a
 * retry of the same op from a new op on a reused buffer).  Make the
 * underflow itself loud and diagnosable instead of silently absorbed, so
 * a future stress run either proves this isn't currently firing or hands
 * over the exact daddr/ops/event-ring evidence needed to fix it for real.
 */
static void
mxfs_dir_wr_inflight_dec(
	struct xfs_buf	*bp,
	const char	*ctx)
{
	int now;

	if (!bp->b_mount)
		return;
	now = atomic_dec_return(&bp->b_mount->m_mxfs_dir_wr_inflight);
	if (unlikely(now < 0)) {
		unsigned int wrevi = bp->b_mxfs_evi;

		atomic_set(&bp->b_mount->m_mxfs_dir_wr_inflight, 0);
		pr_warn_ratelimited(
		    "mxfs: P-WRCNT-UNDERFLOW ctx=%s daddr=%lld ops=%s flags=0x%x evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx] — inflight went negative (more retirements than counted increments); clamped to 0 — possible double-retirement of a leaked+recovered completion pair on a reused buffer\n",
		    ctx,
		    (long long)bp->b_maps[0].bm_bn,
		    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
		    (unsigned int)bp->b_flags,
		    wrevi,
		    bp->b_mxfs_evring[(wrevi + 0) & 7],
		    bp->b_mxfs_evring[(wrevi + 1) & 7],
		    bp->b_mxfs_evring[(wrevi + 2) & 7],
		    bp->b_mxfs_evring[(wrevi + 3) & 7],
		    bp->b_mxfs_evring[(wrevi + 4) & 7],
		    bp->b_mxfs_evring[(wrevi + 5) & 7],
		    bp->b_mxfs_evring[(wrevi + 6) & 7],
		    bp->b_mxfs_evring[(wrevi + 7) & 7]);
	}
}

/*
 * sess6 (ccloop 8ba7ae5c): AG allocation-metadata classifier for the
 * time-travel fence (see pag_mxfs_meta_wr_epoch in xfs_ag.h).  These are the
 * buffer types whose regression to a pre-write media image hands already-
 * owned blocks/inodes back to the allocator.  Includes the AGF/AGI root-
 * pointer containers, not just the btree blocks (a stale root redirects the
 * whole traversal).
 */
static inline bool
mxfs_agmeta_ops(const struct xfs_buf_ops *ops)
{
	extern const struct xfs_buf_ops xfs_agf_buf_ops;
	extern const struct xfs_buf_ops xfs_agi_buf_ops;
	extern const struct xfs_buf_ops xfs_agfl_buf_ops;
	extern const struct xfs_buf_ops xfs_bnobt_buf_ops;
	extern const struct xfs_buf_ops xfs_cntbt_buf_ops;
	extern const struct xfs_buf_ops xfs_inobt_buf_ops;
	extern const struct xfs_buf_ops xfs_finobt_buf_ops;

	return ops == &xfs_agf_buf_ops || ops == &xfs_agi_buf_ops ||
	       ops == &xfs_agfl_buf_ops || ops == &xfs_bnobt_buf_ops ||
	       ops == &xfs_cntbt_buf_ops || ops == &xfs_inobt_buf_ops ||
	       ops == &xfs_finobt_buf_ops;
}

/* returns false if the caller needs to resubmit the I/O, else true */
static bool
__xfs_buf_ioend(
	struct xfs_buf	*bp)
{
	trace_xfs_buf_iodone(bp, _RET_IP_);

	/*
	 * sess6 (ccloop 46efd8b6): record the mount flush epoch at every
	 * successful write completion.  "Completed" on this target stack
	 * means the LIO/SCST write cache, not the platter (FUA dropped) —
	 * until a device flush intervenes, a platter/FUA read of this daddr
	 * can return the PRE-write image, and any "refresh from disk"
	 * heuristic keyed on that read would time-travel this buffer behind
	 * its own completed write (the bunmapi i!=1 iext-regress family).
	 * b_mxfs_wr_flush_epoch == current epoch is the "platter may be
	 * behind this buffer" predicate consumed by xfs_iread_bmbt_block.
	 */
	if ((bp->b_flags & XBF_WRITE) && !bp->b_error && bp->b_mount)
		bp->b_mxfs_wr_flush_epoch =
			atomic64_read(&bp->b_mount->m_mxfs_flush_epoch);

	/*
	 * sess6 (ccloop 8ba7ae5c): per-AG sibling of the per-buffer stamp
	 * above, for AG allocation metadata.  The per-buffer epoch dies with
	 * buffer eviction, so a COLD re-read of an evicted AG-meta buffer has
	 * no memory that its last write may still be ahead of the platter —
	 * the read-side fence in xfs_buf_read_map consults this per-AG stamp
	 * instead.  See pag_mxfs_meta_wr_epoch in xfs_ag.h for the full
	 * mechanism (proven double-allocation via bnobt time travel).
	 */
	if ((bp->b_flags & XBF_WRITE) && !bp->b_error && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm && mxfs_agmeta_ops(bp->b_ops)) {
		struct xfs_perag *hpag = xfs_perag_get(bp->b_mount,
			xfs_daddr_to_agno(bp->b_mount,
					  bp->b_maps[0].bm_bn));
		if (hpag) {
			atomic64_set(&hpag->pag_mxfs_meta_wr_epoch,
				atomic64_read(&bp->b_mount->m_mxfs_flush_epoch));
			xfs_perag_put(hpag);
		}
	}

	/*
	 * sess40 (ccloop, GPT-5.5 WRITEBACK-COMPLETION-BARRIER): a counted dir
	 * metadata write bio has now PHYSICALLY completed — drop the per-mount
	 * in-flight count so the dir EX release fence (which polls it) can hand
	 * off the lock knowing no prior-tenure dir-block write can still land.
	 * Only writes are ever counted; this fires once per counted buffer.
	 */
	if (bp->b_mxfs_dir_wr_counted) {
		extern int mxfs_dir_wseq_at_completion;
		/*
		 * sess42(ccloop) RULE-4 ROOT FIX (paired with xfs_buf_submit): a real
		 * shared dir-metadata write bio has now PHYSICALLY completed.  Advance
		 * b_mxfs_written_seq to the logged_seq snapshot HERE (at completion),
		 * not at submit — so mxfs_dir_buf_is_undestaged() reports the block
		 * durable only once it has truly landed on the LUN.  On error, leave
		 * written_seq behind so the block stays undestaged and the release
		 * fence re-drives the flush.  This closes the insert-loss window where
		 * the dir EX lock was handed off with an in-flight (or skip-emulated)
		 * dirent write still capable of landing after the peer cold-read.
		 */
		if (mxfs_dir_wseq_at_completion && !bp->b_error)
			bp->b_mxfs_written_seq = bp->b_mxfs_logged_seq;
		bp->b_mxfs_dir_wr_counted = false;
		mxfs_dir_wr_inflight_dec(bp, "ioend");
	}

	/*
	 * sess41: dir-block writeback LANDING-ORDER trace (P-DLAND).  Fires at the
	 * instant a dir3 data/leaf/block write physically completes, so merging all
	 * nodes' lines by daddr+realns shows which content VERSION of a (reused)
	 * daddr landed last — the smoking gun for the post-submit ordering loss.
	 * Gated by mxfs.dirland (default 0); content fingerprint is an FNV-1a hash
	 * over the post-header bytes (header carries CRC/LSN that differ per write).
	 */
	{
		extern int mxfs_dirland_enabled;
		extern void mxfs_dland_record(u64, u64, u32, u32, int, const char *);

		if (unlikely(mxfs_dirland_enabled) && (bp->b_flags & XBF_WRITE) &&
		    !bp->b_error && bp->b_addr && bp->b_mount &&
		    bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
		    (bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_block_buf_ops ||
		     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
		     bp->b_ops == &xfs_dir3_leafn_buf_ops)) {
			const struct xfs_dir3_blk_hdr *h = bp->b_addr;
			const unsigned char *q = bp->b_addr;
			uint32_t blen = BBTOB(bp->b_length), k, fnv = 2166136261u;
			int dcnt = -1;

			for (k = 64; k < blen; k++)
				fnv = (fnv ^ q[k]) * 16777619u;
			/* sess41: count active dirents for DATA/block buffers so the
			 * ring shows when a block's count drops (the loss moment). */
			if (bp->b_ops == &xfs_dir3_data_buf_ops ||
			    bp->b_ops == &xfs_dir3_block_buf_ops) {
				const char *p = (const char *)bp->b_addr +
					sizeof(struct xfs_dir3_data_hdr);
				const char *endp = (const char *)bp->b_addr + blen;

				dcnt = 0;
				while (p + sizeof(struct xfs_dir2_data_unused) <=
				       endp) {
					const struct xfs_dir2_data_unused *dup =
						(const void *)p;
					const struct xfs_dir2_data_entry *dep;

					if (be16_to_cpu(dup->freetag) ==
					    XFS_DIR2_DATA_FREE_TAG) {
						uint16_t l =
						    be16_to_cpu(dup->length);
						if (l < sizeof(*dup))
							break;
						p += l;
						continue;
					}
					dep = (const void *)p;
					if (dep->namelen == 0 ||
					    dep->namelen > MAXNAMELEN)
						break;
					dcnt++;
					p += xfs_dir2_data_entsize(bp->b_mount,
							dep->namelen);
				}
			}
			mxfs_dland_record((u64)bp->b_maps[0].bm_bn,
				be64_to_cpu(h->owner),
				bp->b_mxfs_dir_incarn, fnv, dcnt,
				bp->b_ops->name ? bp->b_ops->name : "?");
		}
	}

	if (bp->b_flags & XBF_READ) {
		bool inplace_read = bp->b_mxfs_inplace_read;

		bp->b_mxfs_inplace_read = false;
		if (!bp->b_error && is_vmalloc_addr(bp->b_addr))
			invalidate_kernel_vmap_range(bp->b_addr,
				roundup(BBTOB(bp->b_length), PAGE_SIZE));
		/*
		 * sess7 (ccloop 8ba7ae5c) P150 READ-PRESERVE restore — see the
		 * capture site in xfs_buf_submit_ex.  The DMA imported peer-
		 * fresh platter content; put the locally-attached inode slots
		 * back from the pre-read snapshot so the read cannot regress a
		 * slot this node's iflush already owns.  Runs BEFORE
		 * verify_read: each restored slot is a complete iflush product
		 * with a valid embedded CRC, so the merged image verifies.  On
		 * a read ERROR the snapshot is kept for the resubmit (the
		 * capture site skips re-capture while it is set); buffer
		 * teardown frees it if the read never succeeds.
		 */
		if (bp->b_mxfs_rd_preserve && !bp->b_error && bp->b_addr &&
		    bp->b_mount) {
			unsigned int p150_ilog = bp->b_mount->m_sb.sb_inodelog;
			unsigned int p150_isz = 1u << p150_ilog;
			unsigned int p150_len = BBTOB(bp->b_length);
			u64 p150_mask = bp->b_mxfs_rd_preserve_mask;
			int p150_s;
			static atomic_t p150r_n = ATOMIC_INIT(0);

			for (p150_s = 0; p150_s < 64; p150_s++) {
				unsigned int p150_off = p150_s * p150_isz;

				if (!(p150_mask & (1ULL << p150_s)))
					continue;
				if (p150_off + p150_isz > p150_len)
					break;
				memcpy(bp->b_addr + p150_off,
				       bp->b_mxfs_rd_preserve + p150_off,
				       p150_isz);
				if (atomic_inc_return(&p150r_n) <= 20000) {
					struct xfs_dinode *p150_d =
						bp->b_addr + p150_off;

					pr_warn("mxfs: P150-RDRESTORE daddr=%lld slot=%d ino=%llu mode=0%o nx=%u chg=%llu realns=%llu\n",
						(long long)bp->b_maps[0].bm_bn,
						p150_s,
						(unsigned long long)be64_to_cpu(p150_d->di_ino),
						(unsigned int)be16_to_cpu(p150_d->di_mode),
						be32_to_cpu(p150_d->di_nextents),
						(unsigned long long)be64_to_cpu(p150_d->di_changecount),
						(unsigned long long)ktime_get_real_ns());
				}
			}
			kfree(bp->b_mxfs_rd_preserve);
			bp->b_mxfs_rd_preserve = NULL;
			bp->b_mxfs_rd_preserve_mask = 0;
		}
		/*
		 * v0.10.32 (sess7 46efd8b6): an IN-PLACE completion (P91 guard
		 * — no DMA happened) must not run verify_read: the in-core
		 * image is authoritative but its embedded CRC is only stamped
		 * at write submit, so verifying a modified-since-last-write
		 * image manufactures EFSBADCRC ("Metadata CRC error" walls on
		 * a fully-valid LUN, run 154203Z test1 / sess15 P15I inobt).
		 */
		if (!bp->b_error && bp->b_ops && !inplace_read)
			bp->b_ops->verify_read(bp);
		/*
		 * sess15(a9a03929) P15I: 2/tcp r3 corpse — inobt 0x7fc2b8 read
		 * failed CRC (error 74) an instant after P126 staled the same
		 * dirty in-AIL buffer, yet the on-disk block was later fully
		 * valid (recomputed CRC matches; first 128B identical to the
		 * failing image).  Discriminate the two candidate mechanisms
		 * for the NEXT occurrence — torn in-core page mix from the
		 * concurrent staling vs durable garbage later repaired by the
		 * peer's flush — by fingerprinting each 512B sector of the
		 * failed image; offline compare against the platter names the
		 * diverging sectors.  No extra I/O, capped.
		 */
		if (unlikely(bp->b_error == -EFSBADCRC ||
			     bp->b_error == -EFSCORRUPTED) &&
		    bp->b_addr && bp->b_mount && bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm)) {
			static atomic_t p15i_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p15i_n) <= 16) {
				uint32_t p15i_l = BBTOB(bp->b_length), p15i_o;
				char p15i_sc[8 * 9 + 1];
				int p15i_w = 0;

				for (p15i_o = 0;
				     p15i_o + 512 <= p15i_l &&
				     p15i_w < (int)sizeof(p15i_sc) - 10;
				     p15i_o += 512)
					p15i_w += scnprintf(p15i_sc + p15i_w,
						sizeof(p15i_sc) - p15i_w,
						"%08x ",
						crc32c(0, (char *)bp->b_addr +
						       p15i_o, 512));
				pr_warn("mxfs: P15I-CRCFAIL daddr=%lld len=%u err=%d ops=%s flags=0x%x hold=%d secrc=[%s] comm=%s realns=%llu\n",
					(long long)bp->b_maps[0].bm_bn, p15i_l,
					bp->b_error,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					bp->b_flags,
					bp->b_hold, p15i_sc,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
				/* <ccloop a864 sess7> DECISIVE R-a/R-b at the CRC
				 * fail: coherent-read the SAME daddr off the medium
				 * NOW and check its magic.  medium == a VALID bmbt
				 * block (magic BMA3) that DIFFERS from our in-core =>
				 * in-core torn/stale, medium fine (R-b, reader-side).
				 * medium NON-BMA3 (e.g. XDD3 dir-data / garbage) =>
				 * the coherent medium is durably inconsistent
				 * (R-a, writer-side dinode/block-alloc skew).  The
				 * plain-bio read blocks, so process context only. */
				if (!in_interrupt() && !irqs_disabled() &&
				    bp->b_target && bp->b_target->bt_bdev) {
					extern int mxfs_fua_disable;
					extern int mxfs_pal_bdev_read_plain_bdev(
						struct block_device *, uint64_t,
						void *, uint32_t);
					extern int mxfs_pal_scsi_read_fua_bdev(
						struct block_device *, uint64_t,
						void *, uint32_t);
					void	*mb = kmalloc(p15i_l, GFP_NOFS);
					uint64_t mlba = (uint64_t)bp->b_maps[0].bm_bn +
						bp->b_target->bt_sector_offset;
					int	mrc = -1;

					if (mb)
						mrc = mxfs_fua_disable ?
							mxfs_pal_bdev_read_plain_bdev(
								bp->b_target->bt_bdev,
								mlba, mb, p15i_l) :
							mxfs_pal_scsi_read_fua_bdev(
								bp->b_target->bt_bdev,
								mlba, mb, p15i_l);
					if (mrc == 0) {
						uint32_t im = be32_to_cpu(
							*(__be32 *)bp->b_addr);
						uint32_t mm = be32_to_cpu(
							*(__be32 *)mb);
						uint8_t *mbb = mb;
						int same = memcmp(bp->b_addr, mb,
							p15i_l) == 0;

						pr_warn("mxfs: P15I-MEDIUM daddr=%lld incore_magic=0x%08x medium_magic=0x%08x incore_eq_medium=%d medium_bytes=[%02x %02x %02x %02x %02x %02x %02x %02x] verdict=%s\n",
							(long long)bp->b_maps[0].bm_bn,
							im, mm, same,
							mbb[0], mbb[1], mbb[2], mbb[3],
							mbb[4], mbb[5], mbb[6], mbb[7],
							mm == XFS_BMAP_CRC_MAGIC ?
							"MEDIUM-VALID-BMBT(in-core-torn=R-b)" :
							"MEDIUM-NOT-BMBT(coherent-medium-inconsistent=R-a)");
					} else if (mb) {
						pr_warn("mxfs: P15I-MEDIUM daddr=%lld medium_read_rc=%d\n",
							(long long)bp->b_maps[0].bm_bn,
							mrc);
					}
					kfree(mb);
				}
			}
		}
		if (!bp->b_error)
			bp->b_flags |= XBF_DONE;
		if (bp->b_flags & XBF_READ_AHEAD)
			percpu_counter_dec(&bp->b_target->bt_readahead_count);
		/*
		 * sess30 run14d P-DIRRD: read-completion sibling of the
		 * P-DIRWR write-submission trace below.  Logs every dir
		 * metadata block READ from disk on a multi-node mount with
		 * the same past-the-header content crc, so the merged
		 * cross-node timeline shows which on-disk lineage each
		 * node's next dir RMW is based on.  A node whose last
		 * P-DIRRD crc for a daddr predates a peer's P-DIRWR to the
		 * same daddr is RMW'ing from a stale base — the dir-block
		 * lost-update producer, mechanism-independent.
		 */
		if (unlikely(mxfs_dirwr_enabled >= 2 || mxfs_instr_enabled) &&
		    !bp->b_error && bp->b_addr && bp->b_mount &&
		    bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
		    (bp->b_ops == &xfs_dir3_block_buf_ops ||
		     bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
		     bp->b_ops == &xfs_dir3_leafn_buf_ops)) {
			static atomic_t drn = ATOMIC_INIT(0);

			if (atomic_inc_return(&drn) <= 8000) {
				struct xfs_dir3_blk_hdr *rbh = bp->b_addr;

				pr_warn("mxfs: P-DIRRD fmt=%s owner=%lld daddr=%lld crc=%08x fua=%d comm=%s realns=%llu\n",
					(bp->b_ops == &xfs_dir3_block_buf_ops) ? "block" :
					(bp->b_ops == &xfs_dir3_data_buf_ops) ? "data" :
					(bp->b_ops == &xfs_dir3_leaf1_buf_ops) ? "leaf1" : "leafn",
					(long long)be64_to_cpu(rbh->owner),
					(long long)bp->b_maps[0].bm_bn,
					crc32c(0, (char *)bp->b_addr + 48,
					       BBTOB(bp->b_length) - 48),
					(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
			}
		}
	} else {
		if (!bp->b_error) {
			bp->b_flags &= ~XBF_WRITE_FAIL;
			bp->b_flags |= XBF_DONE;
		}

		/*
		 * sess33 (ccloop 14d31183) P136 — dir-dinode write COMPLETION
		 * trace.  P133 logs at SUBMISSION; the revert TOCTOU (a write
		 * coherent when submitted but stale by the time it lands)
		 * is only visible in completion order.  Merged cross-node by
		 * realns, the P136 timeline shows exactly which completion
		 * put the older dinode image back over a peer's newer one.
		 * No extra I/O — logs the payload the device just acked.
		 */
		if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled) &&
		    !bp->b_error && bp->b_addr && bp->b_mount &&
		    bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
		    bp->b_map_count == 1 &&
		    (bp->b_ops == &xfs_inode_buf_ops ||
		     bp->b_ops == &xfs_inode_buf_ra_ops)) {
			uint32_t p136_isz = bp->b_mount->m_sb.sb_inodesize;
			uint32_t p136_len = BBTOB(bp->b_length);
			uint32_t p136_off;
			static atomic_t p136_n = ATOMIC_INIT(0);

			for (p136_off = 0;
			     p136_isz >= 256 && (p136_len & 511) == 0 &&
			     p136_off + p136_isz <= p136_len;
			     p136_off += p136_isz) {
				struct xfs_dinode *p136_d =
					bp->b_addr + p136_off;

				if (be16_to_cpu(p136_d->di_magic) !=
					XFS_DINODE_MAGIC)
					continue;
				/* sess5(186320ae): LOCAL (shortform) dirs were
				 * silently SKIPPED here, hiding exactly the
				 * block->sf conversion destages the uv
				 * dangling-dirent forensics needed.  Log ALL
				 * dir dinode images, with fmt + gen. */
				if (!S_ISDIR(be16_to_cpu(p136_d->di_mode)))
					continue;
				/* sess5(186320ae): 1200 was exhausted 40s before
				 * the dlm_fairness clobber window on 3/4 nodes,
				 * blinding the cross-node write timeline.  The
				 * probe is diagnosis-critical; give it storm
				 * headroom. */
				if (atomic_inc_return(&p136_n) <= 60000)
					pr_warn("mxfs: P136-DIRINO-WRDONE ino=%llu fmt=%u gen=%u size=%lld nx=%u daddr=%lld realns=%llu\n",
						(unsigned long long)be64_to_cpu(p136_d->di_ino),
						(unsigned)p136_d->di_format,
						be32_to_cpu(p136_d->di_gen),
						(long long)be64_to_cpu(p136_d->di_size),
						be32_to_cpu(p136_d->di_nextents),
						(long long)bp->b_maps[0].bm_bn,
						(unsigned long long)ktime_get_real_ns());
			}
		}

		if (unlikely(bp->b_error) && xfs_buf_ioend_handle_error(bp))
			return false;

		/* clear the retry state */
		bp->b_last_error = 0;
		bp->b_retries = 0;
		bp->b_first_retry_time = 0;

		/*
		 * Note that for things like remote attribute buffers, there may
		 * not be a buffer log item here, so processing the buffer log
		 * item must remain optional.
		 */
		if (bp->b_log_item)
			xfs_buf_item_done(bp);

		if (bp->b_iodone)
			bp->b_iodone(bp);
	}

	bp->b_flags &= ~(XBF_READ | XBF_WRITE | XBF_READ_AHEAD |
			 _XBF_LOGRECOVERY);
	return true;
}

static void
xfs_buf_ioend(
	struct xfs_buf	*bp)
{
	mxfs_buf_ev(bp, MXFS_BEV_IOEND);
	if (!__xfs_buf_ioend(bp))
		return;
	if (bp->b_mxfs_ioend_seen < 255)
		bp->b_mxfs_ioend_seen++;
	/*
	 * ccloop3e02 sess2 ROOT FIX wedge#2a residual: consume a pending sync
	 * waiter's credit if one is registered — see mxfs_buf_completion_wake_sync().
	 * Correct even if an unrelated concurrent submitter (xfsaild) raced in
	 * on this same buffer; only logs when that race actually happened
	 * (live XBF_ASYNC set), since the credit path is now the NORMAL route
	 * for every sync completion, not an exceptional override.
	 */
	if (mxfs_buf_completion_wake_sync(bp)) {
		if (bp->b_flags & XBF_ASYNC) {
			static atomic_t psw_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&psw_n) <= 4000)
				pr_warn_ratelimited(
				    "mxfs: P-SYNCWAIT-OVERRIDE daddr=%lld ops=%s flags=0x%x path=ioend — concurrent async submit raced this sync waiter; woke it via the per-submission credit\n",
				    (long long)bp->b_maps[0].bm_bn,
				    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
				    (unsigned int)bp->b_flags);
		}
		return;
	}
	if (bp->b_flags & XBF_ASYNC) {
		if (bp->b_mxfs_relse_seen < 255)
			bp->b_mxfs_relse_seen++;
		xfs_buf_relse(bp);
	} else
		complete(&bp->b_iowait);
}

static void
xfs_buf_ioend_work(
	struct work_struct	*work)
{
	struct xfs_buf		*bp =
		container_of(work, struct xfs_buf, b_ioend_work);

	mxfs_buf_ev(bp, MXFS_BEV_WORKER);
	if (!__xfs_buf_ioend(bp))
		return;
	/*
	 * sess1(e8e920f7): the THIRD completion router.  ccloop3e02 sess2's
	 * wedge#2a fix added the per-submission sync-credit protocol to
	 * xfs_buf_ioend() and xfs_buf_bio_end_io() but left this worker as an
	 * unconditional relse.  A sync-credited submission whose completion
	 * lands here (XBF_ASYNC set concurrently on the shared b_flags by a
	 * lock-free flag writer between bio_end_io's credit check and the
	 * worker run, or an emulated completion re-routed through the work
	 * item) then relse's a lock the sync waiter still owns — the b_sema
	 * over-up that poisons the buffer into multi-ownability (P-SEMA-OVERUP
	 * family).  Route through the same credit-consume protocol as the
	 * other two routers: exactly one ownership-consuming action per
	 * completion.
	 */
	if (mxfs_buf_completion_wake_sync(bp)) {
		if (bp->b_flags & XBF_ASYNC) {
			static atomic_t psww_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&psww_n) <= 4000)
				pr_warn_ratelimited(
				    "mxfs: P-SYNCWAIT-OVERRIDE daddr=%lld flags=0x%x path=worker — async-flagged worker completion woke the pending sync waiter via its credit (no relse)\n",
				    (long long)bp->b_maps[0].bm_bn,
				    (unsigned int)bp->b_flags);
		}
		return;
	}
	if (bp->b_flags & XBF_ASYNC) {
		if (bp->b_mxfs_relse_seen < 255)
			bp->b_mxfs_relse_seen++;
		xfs_buf_relse(bp);
	} else {
		complete(&bp->b_iowait);
	}
}

void
__xfs_buf_ioerror(
	struct xfs_buf		*bp,
	int			error,
	xfs_failaddr_t		failaddr)
{
	ASSERT(error <= 0 && error >= -1000);
	bp->b_error = error;
	trace_xfs_buf_ioerror(bp, error, failaddr);
}

void
xfs_buf_ioerror_alert(
	struct xfs_buf		*bp,
	xfs_failaddr_t		func)
{
	xfs_buf_alert_ratelimited(bp, "XFS: metadata IO error",
		"metadata I/O error in \"%pS\" at daddr 0x%llx len %d error %d",
				  func, (uint64_t)xfs_buf_daddr(bp),
				  bp->b_length, -bp->b_error);
}

/*
 * To simulate an I/O failure, the buffer must be locked and held with at least
 * three references. The LRU reference is dropped by the stale call. The buf
 * item reference is dropped via ioend processing. The third reference is owned
 * by the caller and is dropped on I/O completion if the buffer is XBF_ASYNC.
 */
void
xfs_buf_ioend_fail(
	struct xfs_buf	*bp)
{
	mxfs_buf_ev(bp, MXFS_BEV_IOFAIL);
	bp->b_flags &= ~XBF_DONE;
	xfs_buf_stale(bp);
	xfs_buf_ioerror(bp, -EIO);
	xfs_buf_ioend(bp);
}

int
xfs_bwrite(
	struct xfs_buf		*bp)
{
	int			error;

	ASSERT(xfs_buf_islocked(bp));

	bp->b_flags |= XBF_WRITE;
	bp->b_flags &= ~(XBF_ASYNC | XBF_READ | _XBF_DELWRI_Q |
			 XBF_DONE);

	/*
	 * sess8 (ccloop a864): this is a SYNC write — we xfs_buf_iowait below.
	 * Latch the sync intent under b_sema so a lock-free XBF_ASYNC set (a
	 * racing buf-item unpin on another CPU) landing before xfs_buf_submit's
	 * snapshot cannot misroute the completion to the async/relse branch and
	 * strand this waiter (the residual wedge#2 rm hang).
	 */
	bp->b_mxfs_force_sync = true;
	xfs_buf_submit(bp);
	error = xfs_buf_iowait(bp);
	if (error)
		xfs_force_shutdown(bp->b_mount, SHUTDOWN_META_IO_ERROR);
	return error;
}

static void
xfs_buf_bio_end_io(
	struct bio		*bio)
{
	struct xfs_buf		*bp = bio->bi_private;

	/*
	 * sess35 P-H27-COMPLETE: pair with P-H27-SUBMIT-DIR3 — log write
	 * completion for dir3 bufs. If submit fired but complete doesn't,
	 * that's a stuck bio. If complete fires with status=0, kernel
	 * thinks the write succeeded.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr) {
		const unsigned char *p = bp->b_addr;
		if (p[0] == 0x58 && p[1] == 0x44 && p[2] == 0x42 && p[3] == 0x33) {
			mxfs_idbg("mxfs: P-H27-COMPLETE-DIR3 daddr=%lld bi_status=%d bp=%p realns=%llu\n",
				(long long)bp->b_maps[0].bm_bn,
				bio->bi_status, bp,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * sess3 (ccloop a16ec5f2) watch: completion marker for a WRITE that
	 * covers the watched daddr — pairs with the PW-DADDR/PW-SLOT submit
	 * lines by bp pointer.  A completion long after submit (or landing in
	 * a later DLM tenure) is the late-landing prior-tenure write face.
	 */
	{
		extern unsigned long long mxfs_watch_daddr;

		if (unlikely(mxfs_watch_daddr) && (bp->b_flags & XBF_WRITE)) {
			int wm;

			for (wm = 0; wm < bp->b_map_count; wm++) {
				if ((xfs_daddr_t)mxfs_watch_daddr >=
					bp->b_maps[wm].bm_bn &&
				    (xfs_daddr_t)mxfs_watch_daddr <
					bp->b_maps[wm].bm_bn +
					bp->b_maps[wm].bm_len) {
					pr_warn("mxfs: PW-WDONE daddr=%lld bn=%lld status=%d bp=%px realns=%llu\n",
						(long long)mxfs_watch_daddr,
						(long long)bp->b_maps[wm].bm_bn,
						bio->bi_status, bp,
						(unsigned long long)ktime_get_real_ns());
					break;
				}
			}
		}
	}

	if (bio->bi_status)
		xfs_buf_ioerror(bp, blk_status_to_errno(bio->bi_status));
	else if ((bp->b_flags & XBF_WRITE) && (bp->b_flags & XBF_ASYNC) &&
		 XFS_TEST_ERROR(bp->b_mount, XFS_ERRTAG_BUF_IOERROR))
		xfs_buf_ioerror(bp, -EIO);

	/*
	 * ccloop3e02 sess2 ROOT FIX wedge#2a residual: a real write/read bio
	 * has completed.  Consume a pending sync waiter's credit if one is
	 * registered (mxfs_buf_completion_wake_sync()) — correct even if
	 * XBF_ASYNC got set on this shared buffer object by an unrelated
	 * concurrent submitter (xfsaild racing mxfs_dir_data_owner_scan's
	 * synchronous durable flush on the same buffer), since the credit is
	 * additive per-submission rather than a single overwritable bool.
	 */
	mxfs_buf_ev(bp, MXFS_BEV_BIOEND);
	if (bp->b_mxfs_ioend_seen < 255)
		bp->b_mxfs_ioend_seen++;
	if (mxfs_buf_completion_wake_sync(bp)) {
		if (bp->b_flags & XBF_ASYNC) {
			static atomic_t pswb_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&pswb_n) <= 4000)
				pr_warn_ratelimited(
				    "mxfs: P-SYNCWAIT-OVERRIDE daddr=%lld flags=0x%x path=bio_end — concurrent async submit raced this sync waiter; woke it via the per-submission credit\n",
				    (long long)bp->b_maps[0].bm_bn,
				    (unsigned int)bp->b_flags);
		}
		bio_put(bio);
		return;
	}

	if (bp->b_flags & XBF_ASYNC) {
		if (bp->b_mxfs_relse_seen < 255)
			bp->b_mxfs_relse_seen++;
		INIT_WORK(&bp->b_ioend_work, xfs_buf_ioend_work);
		queue_work(bp->b_mount->m_buf_workqueue, &bp->b_ioend_work);
	} else {
		complete(&bp->b_iowait);
	}

	bio_put(bio);
}

static inline blk_opf_t
xfs_buf_bio_op(
	struct xfs_buf		*bp)
{
	blk_opf_t		op;

	if (bp->b_flags & XBF_WRITE) {
		op = REQ_OP_WRITE;
		/*
		 * v0.3.115/116 sess29 tried REQ_FUA-write (twice — first
		 * gated on mxfs_buf_needs_fua_read, second the same).
		 * The 1st pass made overall pass rate WORSE (mean iters
		 * dropped from 9.5 to 4.75).  The 2nd pass made dd
		 * unusably slow — 256MB dd took 30+ minutes of CPU before
		 * being killed.
		 *
		 * Hypothesis (write-side persistence) remains plausible
		 * per the P55-INSTR iter-3 trace, but blanket FUA-write
		 * isn't the right fix.  Sess30 to investigate more
		 * surgical approaches (e.g., explicit FUA-rewrite of the
		 * SPECIFIC released buf in bast_process before DLM unlock,
		 * or write-barrier-via-tiny-FUA-bio after blkdev_issue_flush).
		 */
	} else {
		op = REQ_OP_READ;
		if (bp->b_flags & XBF_READ_AHEAD)
			op |= REQ_RAHEAD;
	}

	return op | REQ_META;
}

/*
 * sess115 (Gemini RULE-5 Candidate A) — PARTIAL inode-cluster WRITE.
 *
 * Fixes the DLM(per-inode) vs buffer-cache(per-CLUSTER) false-sharing REVERT
 * that loses concurrently-added dirents (cache_coherency cross_visibility: 3 of
 * 4 concurrent dirent adds to a shared shortform dir were durably LOST).
 *
 * PROVEN root: a node holding NL on a dir inode keeps a STALE copy of that
 * inode in a shared 64-inode cluster buffer.  When xfsaild flushes the cluster
 * for a CO-RESIDENT dirty inode, stock XFS writes the WHOLE cluster in one bio,
 * carrying our stale dir slot back to the LUN and CLOBBERING peer-committed
 * dirents (dmesg: node2 writes the dir slot count=1 own=0 AFTER peers committed
 * count=2,3,4 — the dir reverts to count=1, losing node1/node3/node4.txt).
 * The sess61/62 RMW merge (FUA-read + overlay foreign slots) wedges on SCST
 * (sess113) and is disabled under fua_disable, so the revert is unprotected.
 *
 * FIX (sess28 unified, BUG1+BUG2): for an inode-cluster WRITE, submit bios for
 * EVERY inode sector EXCEPT sectors of an in-core inode this node RELEASED
 * (i_dlm_mode==NL) and did not log this round.  An NL-not-logged inode is a
 * peer's now; our cached image of it is STALE prior-tenure.  Skipping it stops
 * us reverting the peer's durable image — both BUG1 (a stale FREE copy of a
 * reused FILE inode reverting a peer's fresh allocation -> dirent->freed inode,
 * P26-IGET-FAIL) and BUG2 (a stale DIR di_size/extent map reverting a peer's
 * grow).  Writing everything else (held EX/PR, or logged this round) means a
 * node never drops an inode it owns or just modified.  v5 dinodes carry a
 * per-inode CRC + LSN with no whole-cluster header CRC, so writing isolated
 * inode-sized runs is fully CRC-valid and leaves the skipped (peer-owned)
 * neighbour's durable on-LUN image untouched.
 *
 * Conservative fallbacks to the stock whole-buffer write (return false):
 *  - single-node mount (no cross-node coherency concern);
 *  - not an inode-cluster buffer, or discontiguous (b_map_count != 1);
 *  - a DIRTY xfs_buf_log_item (di_next_unlinked logged under the AGI): those
 *    buf-logged chunks MUST be persisted and the whole-buffer write already
 *    does so correctly — no worse than today;
 *  - inodes smaller than a sector (can't isolate), or > 64 sectors/cluster;
 *  - the owned-slot set is empty or covers every slot (nothing to skip).
 */

/* sess3 (ccloop 46efd8b6): platter-history probe for DIRECTORY dinode slots.
 * Prints every dir dinode image about to reach the LUN inside a WHOLE-buffer
 * inode-cluster write (reason names the partial-writer bail that allowed it).
 * di_changecount is monotonic per inode, so a cluster-wide merge of these
 * lines totally orders what the platter held; the P62-DUALREAD reader side
 * then shows whether a reload's "disk" view matches the last write (coherent)
 * or predates it (stale read / clobber).  PROVEN need: run 042532Z test31
 * read disk_nx 22 -> 18 regression with no identified writer. */
static void
mxfs_iwr_dir_probe(struct xfs_buf *bp, const char *reason)
{
	struct xfs_mount	*mp = bp->b_mount;
	unsigned int		isize, o;
	static atomic_t		p3dw = ATOMIC_INIT(0);

	if (!mp || !mp->m_sb.sb_inodesize || !bp->b_addr)
		return;
	isize = mp->m_sb.sb_inodesize;
	for (o = 0; o + isize <= BBTOB(bp->b_length); o += isize) {
		struct xfs_dinode *d = bp->b_addr + o;

		if (be16_to_cpu(d->di_magic) != XFS_DINODE_MAGIC)
			continue;
		if ((be16_to_cpu(d->di_mode) & S_IFMT) != S_IFDIR)
			continue;
		if (atomic_inc_return(&p3dw) > 6000)
			return;
		pr_warn("mxfs: P-DIRDW daddr=%lld+%u reason=%s ino=%llu fmt=%u nx=%u size=%lld chg=%llu comm=%s\n",
			(long long)bp->b_maps[0].bm_bn, o >> BBSHIFT, reason,
			(unsigned long long)be64_to_cpu(d->di_ino),
			d->di_format, be32_to_cpu(d->di_nextents),
			(long long)be64_to_cpu(d->di_size),
			(unsigned long long)be64_to_cpu(d->di_changecount),
			current->comm);
	}
}

static bool
mxfs_submit_partial_inode_write(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_perag	*pag;
	struct xfs_log_item	*lip;
	unsigned int		inodelog, sectsize, inodesize, len, ni;
	unsigned int		total_sects, spi, nslots = 0, nskip = 0;
	u64			logged = 0, bli_dirty = 0, skip = 0, dirty = 0, all;
	uint64_t		base_512;
	xfs_fsblock_t		fsb;
	xfs_agblock_t		agbno;
	xfs_agino_t		base_agino;
	bool			vmalloc;
	struct blk_plug		plug;
	struct bio		*tail;
	int			s, run_start, run_end, last_start = -1, runs = 0;

	{ extern int mxfs_partial_iwrite;
	  if (!mxfs_partial_iwrite)
		return false;	/* sess27 diagnostic: force whole-buffer write */
	}
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	if (!(bp->b_flags & XBF_WRITE) || bp->b_ops != &xfs_inode_buf_ops)
		return false;
	if (bp->b_map_count != 1 || !bp->b_addr) {
		mxfs_iwr_dir_probe(bp, "WHOLE-maps");
		return false;
	}
	/*
	 * sess45 (ccloop 8ddb16a2) FIX — a freshly-INITIALIZED inode chunk
	 * (xfs_ialloc_inode_init) stamps EVERY inode in the cluster magic-IN via
	 * an ORDERED buffer (v3: logged logically via xfs_icreate_log, NOT
	 * physically) — so the brand-new FREE inodes (di_mode==0) have no inode
	 * log item this round and are not in-core, and the skip logic below
	 * classifies them as "free-not-logged" and OMITS them from the write.  The
	 * omitted sectors keep the reused block's PRIOR content (leftover file
	 * data / zeros from the just-freed extent) -> a later xfs_iget read-verify
	 * of any inode in the cluster trips on the stale slot (magic 0 / data) ->
	 * EFSCORRUPTED -> shutdown (the 2/tcp crash_consistency wedge; PROVEN
	 * sess45: payload "node2-d4-f24-pay" found IN a free inode slot at
	 * daddr 2095208).  A freshly-allocated chunk has NO peer-owned slots (this
	 * node just allocated the whole chunk under the AG lock; a peer cannot
	 * concurrently own any slot), so the false-sharing protection does not
	 * apply: write the WHOLE buffer so every initialized inode reaches disk.
	 * XFS_BLI_INODE_ALLOC_BUF is set by xfs_trans_inode_alloc_buf for exactly
	 * this initial allocation and is gone for later co-resident flushes, so
	 * those still get the partial-write false-sharing protection.
	 */
	if (bp->b_log_item &&
	    (bp->b_log_item->bli_flags & XFS_BLI_INODE_ALLOC_BUF)) {
		mxfs_iwr_dir_probe(bp, "WHOLE-allocbuf");
		return false;
	}
	/*
	 * sess28: do NOT bail on a DIRTY buffer-log-item.  The reverting write
	 * is exactly an rm-rf unlinked-list (di_next_unlinked) whole-buffer write
	 * that carries a STALE co-resident free slot.  We instead force-write the
	 * BLI dirty ranges (below) and omit only the unlogged/unowned stale slots,
	 * so the BLI's logged bytes are still all persisted (buffer completion is
	 * sound) while the stale slot is not reverted.
	 */
	pag = bp->b_pag;
	if (!pag) {
		extern int mxfs_iwr_enabled;
		if (unlikely(mxfs_iwr_enabled))
			pr_warn_ratelimited(
				"mxfs: P28-IWR-BAIL daddr=%lld reason=NO_PAG -> WHOLE\n",
				(long long)bp->b_maps[0].bm_bn);
		mxfs_iwr_dir_probe(bp, "WHOLE-nopag");
		return false;		/* need the AG ici radix to find NL inodes */
	}

	inodelog  = mp->m_sb.sb_inodelog;
	inodesize = mp->m_sb.sb_inodesize;
	sectsize  = mp->m_sb.sb_sectsize;
	len = BBTOB(bp->b_length);
	ni  = len >> inodelog;
	if (ni == 0 || ni > 64 || sectsize == 0 || (inodesize % sectsize) != 0) {
		mxfs_iwr_dir_probe(bp, "WHOLE-geom");
		return false;
	}
	spi = inodesize / sectsize;		/* sectors per inode */
	total_sects = len / sectsize;
	if (total_sects == 0 || total_sects > 64) {
		mxfs_iwr_dir_probe(bp, "WHOLE-geom");
		return false;
	}

	/* logged[] = slots with a live inode log item this round (we own them). */
	list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
		struct xfs_inode_log_item *iip;
		struct xfs_inode	*ip;
		int			slot, k;

		if (lip->li_type != XFS_LI_INODE)
			continue;
		iip = (struct xfs_inode_log_item *)lip;
		ip = iip->ili_inode;
		if (!ip)
			continue;
		slot = ip->i_imap.im_boffset >> inodelog;
		if (slot < 0 || slot >= (int)ni)
			continue;
		for (k = 0; k < (int)spi; k++)
			logged |= 1ULL << (slot * spi + k);
		nslots++;
	}

	/*
	 * skip[] = in-core inodes this node RELEASED (i_dlm_mode==NL) that are NOT
	 * logged this round.  Such an inode is a peer's now (we released our grant);
	 * our cached cluster image of it is STALE prior-tenure (e.g. a reused inode
	 * we last saw FREE, or a dir whose di_size/extent map predates a peer's
	 * grow).  Whole-writing the cluster would clobber the peer's durable image:
	 *   - BUG1 (file): node1's stale FREE (mode=0) copy of a reused inode reverts
	 *     node2's fresh allocation -> dirent points at a "freed" inode (P26-IGET).
	 *   - BUG2 (dir):  node1's stale di_size reverts node2's dir grow.
	 * The "not logged this round" guard writes anything we actually modified now
	 * (so a freshly-created inode that transiently reads MXFS_LOCK_NL==0 is still
	 * written, sess17), and held EX/PR inodes (mode!=NL) are always written, so a
	 * node never skips an inode it owns.  Enumerate by NUMBER: NL inodes are NOT
	 * on b_li_list.  agbno = fsb % agblocks (fsb encodes agno*agblocks + agbno);
	 * radix key is the AG-relative agino.
	 */
	fsb = (xfs_fsblock_t)(bp->b_maps[0].bm_bn >> mp->m_blkbb_log);
	agbno = (xfs_agblock_t)(fsb % mp->m_sb.sb_agblocks);
	base_agino = (xfs_agino_t)agbno << mp->m_sb.sb_inopblog;

	/*
	 * bli_dirty[] = sectors covered by a DIRTY buffer-log-item range (e.g.
	 * di_next_unlinked logged during unlink).  These bytes MUST reach disk —
	 * never omit a slot that carries them (else the buffer completes with the
	 * BLI marked durable while its logged bytes were skipped).  Map each dirty
	 * 128-byte chunk to its inode slot.
	 */
	if (bp->b_log_item && (bp->b_log_item->bli_flags & XFS_BLI_DIRTY)) {
		struct xfs_buf_log_format *blfp = &bp->b_log_item->__bli_format;
		unsigned int		nbword = NBBY * sizeof(unsigned int);
		unsigned int		c, nbits = blfp->blf_map_size * nbword;

		for (c = 0; c < nbits; c++) {
			unsigned int slot, k;

			if (!(blfp->blf_data_map[c / nbword] &
			      (1U << (c % nbword))))
				continue;
			slot = (c * XFS_BLF_CHUNK) / inodesize;
			if (slot >= ni)
				continue;
			for (k = 0; k < spi; k++)
				bli_dirty |= 1ULL << (slot * spi + k);
		}
	}

	{ unsigned int n_incore = 0, n_nl = 0, n_held = 0, n_nl_logged = 0;
	mxfs_ici_lock(pag);
	for (s = 0; s < (int)ni; s++) {
		struct xfs_inode	*ip;
		struct xfs_dinode	*d = bp->b_addr + (s << inodelog);
		u64			slotbits = 0;
		bool			is_free, is_nl;
		int			k;

		/* FREE (di_mode==0) on the buffer = a prior-tenure freed inode;
		 * writing it back reverts a peer's reallocation (BUG1). */
		is_free = (be16_to_cpu(d->di_magic) == XFS_DINODE_MAGIC &&
			   d->di_mode == 0);
		ip = radix_tree_lookup(&pag->pag_ici_root, base_agino + s);
		if (ip) {
			n_incore++;
			if (ip->i_dlm_mode == MXFS_LOCK_NL)
				n_nl++;
			else
				n_held++;
		}
		/* NL in-core = we released it (BUG2 dir di_size revert). */
		is_nl = (ip && ip->i_dlm_mode == MXFS_LOCK_NL);
		for (k = 0; k < (int)spi; k++)
			slotbits |= 1ULL << (s * spi + k);
		/* Logged / buf-logged THIS round = our genuine committed change;
		 * always write it. */
		if ((logged | bli_dirty) & slotbits) {
			if (is_free || is_nl)
				n_nl_logged++;
			/*
			 * ccloop c7ee71c6 sess14 D3 ROOT FIX (PROVEN, byte-exact,
			 * cv 18:39:39): "logged this round" out-ranked the NL
			 * guard, so a DIRECTORY slot copied into this buffer
			 * under a PRIOR tenure got written after the grant was
			 * released — reverting the platter to our stale entry
			 * set.  Merged 32-node ledger: test27 wrote 7 names at
			 * mode=5, 57ms later test5 wrote its own 3-name image at
			 * **mode=0 (NL)**, erasing node16/23/27/32 permanently
			 * (exactly the 4 files cache_coherency reported missing;
			 * every later write built on the reverted base).
			 *
			 * A dir slot we no longer hold must never be published
			 * from our cached image: if our committed change landed,
			 * our release drain wrote it (rewriting can only revert
			 * peers); if it did not land, that is a drain defect to
			 * fix at the drain — never by racing the platter from
			 * NL.  (GPT RULE-5 invariant: never write an inode core
			 * at NL; land-before-release or recovery-owned.)
			 * Non-dir slots keep the legacy behaviour.
			 */
			/*
			 * sess14 REFINEMENT (RULE 4 — the unrefined skip caused
			 * a REGRESSION, caught same session): skipping EVERY
			 * NL logged dir slot also suppressed the landing of a
			 * freshly created dir whose creator had already
			 * released the grant.  Proven: ino 33554569 (test7's
			 * fdw node7 dir, daddr=33491712 slot=9, img fmt=1
			 * size=6) was skipped repeatedly, never reached the
			 * platter (disk slot read mode=0/FREE), test1 could not
			 * see the dir at all, and test7 finally poisoned its
			 * own in-core copy (P34H-INCARN-POISON) → permanent
			 * ESTALE on its own directory.
			 *
			 * The write is only harmful when a PEER has superseded
			 * the platter since our image was valid — the same
			 * supersession proof P32E uses: master dir_epoch >
			 * our i_dlm_dir_valid_epoch.  With no peer tenure since
			 * our copy (fresh create, private dir), our logged
			 * image is the ONLY source of that dinode and must be
			 * written.  (GPT: retire/skip only on proven
			 * supersession, else land it.)
			 */
			/*
			 * Discriminator (sess14, THIRD iteration — GPT RULE-5
			 * design, and the one that is actually an invariant).
			 * Refuted first: "skip every NL dir slot" stranded a
			 * freshly created dir (its landing IS a post-demote
			 * write) — platter slot stayed FREE, dir invisible
			 * cluster-wide, local ESTALE poison.  Refuted second:
			 * gating on the dir epoch — after release the local
			 * DLM resource view is gone and the epoch lookup
			 * returns 0, so the gate silently disabled the skip
			 * and the cv revert returned (5 files lost at .127).
			 *
			 * The correct question is not "are we NL?" but "do we
			 * still hold publication AUTHORITY for this image?" —
			 * i.e. can a successor writer exist right now?  MXFS
			 * already has exactly that token: MXFS_IF_DLM_RELFLUSH
			 * is set only across the sanctioned release drain, and
			 * per its own invariant (xfs_inode.h:585,
			 * xfs_mxfs_dlm.c:23160) **the on-disk DLM grant is
			 * still HELD for that whole window** — no peer can
			 * have taken EX, so no successor image can exist and
			 * publishing ours is safe (this is the land-before-
			 * release path itself).  Without the token we are a
			 * background flusher (xfsaild/kworker) racing whoever
			 * owns the dir now: our prior-tenure image can only
			 * revert them — the proven cv clobber (test5 mode=0
			 * wrote 3 names over test27's 7, erasing 4 files).
			 */
			{ extern int mxfs_dir_nl_logged_skip;
			  bool authorized = ip &&
				xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH);
			if (is_nl && !is_free && !authorized &&
			    (be16_to_cpu(d->di_mode) & S_IFMT) == S_IFDIR &&
			    mxfs_dir_nl_logged_skip) {
				skip |= slotbits;
				nskip++;
				pr_warn_ratelimited(
					"mxfs: P56-NL-LOGGED-DIR-SKIP daddr=%lld slot=%d ino=%llu img_fmt=%u img_size=%llu valid_epoch=%u self_created=%d comm=%s — logged dir slot at NL without publication authority (no RELFLUSH token); refusing to publish prior-tenure image over the current owner\n",
					(long long)bp->b_maps[0].bm_bn, s,
					(unsigned long long)be64_to_cpu(d->di_ino),
					d->di_format,
					(unsigned long long)be64_to_cpu(d->di_size),
					ip->i_dlm_dir_valid_epoch,
					ip->i_mxfs_self_created ? 1 : 0,
					current->comm);
				continue;
			}
			}
			/* sess56 write-side probe: dump the shortform names of a
			 * LOGGED dir slot being written, so the resurrecting write
			 * (one persisting a stale prior-tenure entry set) is caught
			 * against the reload timeline. */
			if ((be16_to_cpu(d->di_mode) & S_IFMT) == S_IFDIR &&
			    d->di_format == XFS_DINODE_FMT_LOCAL) {
				extern void mxfs_sf_disk_names(struct xfs_mount *,
					struct xfs_dinode *, char *, size_t);
				char wn[128];

				mxfs_sf_disk_names(mp, d, wn, sizeof(wn));
				pr_warn_ratelimited(
					"mxfs: P56-DIRWRITE ino=%llu daddr=%lld incore=%d mode=%d logged=%d relflush=%d dgen=%u lgen=%u vep=%u sfc=%d comm=%s write=[%s]\n",
					(unsigned long long)(ip ? ip->i_ino : 0),
					(long long)bp->b_maps[0].bm_bn,
					ip ? 1 : 0, ip ? ip->i_dlm_mode : -1,
					(int)!!(logged & slotbits),
					/* sess14: does this write carry the
					 * release-drain publication token (grant
					 * still held) or is it a background
					 * flusher racing the current owner? */
					(ip && xfs_iflags_test(ip,
						MXFS_IF_DLM_RELFLUSH)) ? 1 : 0,
					ip ? ip->i_dlm_dir_gen : 0,
					ip ? ip->i_dlm_dir_loaded_gen : 0,
					ip ? ip->i_dlm_dir_valid_epoch : 0,
					(ip && ip->i_mxfs_self_created) ? 1 : 0,
					current->comm, wn);
			} else if ((be16_to_cpu(d->di_mode) & S_IFMT) == S_IFDIR) {
				/* sess3 (ccloop 46efd8b6): grown-dir dinode image
				 * entering the platter via a logged partial write —
				 * the write-side half of the P62-DUALREAD ordering
				 * (chg is monotonic per inode). */
				static atomic_t p3di = ATOMIC_INIT(0);

				if (atomic_inc_return(&p3di) <= 6000)
					pr_warn("mxfs: P-DIRDW daddr=%lld+%u reason=INCLUDED-%s ino=%llu fmt=%u nx=%u size=%lld chg=%llu dlm_mode=%d comm=%s\n",
						(long long)bp->b_maps[0].bm_bn,
						(unsigned int)((s << inodelog) >> BBSHIFT),
						(logged & slotbits) ? "logged" : "blidirty",
						(unsigned long long)be64_to_cpu(d->di_ino),
						d->di_format,
						be32_to_cpu(d->di_nextents),
						(long long)be64_to_cpu(d->di_size),
						(unsigned long long)be64_to_cpu(d->di_changecount),
						ip ? ip->i_dlm_mode : -1,
						current->comm);
			}
			continue;
		}
		/*
		 * sess56 (ccloop 8ddb16a2) — RULE 4 PROVEN (tcp_dlm_scaling
		 * shared-dir leftover n2_r57/r58: a peer-removed dirent durably
		 * RESURRECTED on disk).  A co-resident flush — a churned child
		 * FILE inode sharing the shared dir's 4 KiB inode cluster —
		 * rewrites the WHOLE cluster, including the dir's dinode slot.
		 * The old code wrote any HELD (PR/EX) slot unconditionally; for
		 * a CLEAN dir not logged this round that means writing our
		 * CACHED buffer copy of the dir dinode, which can be STALE
		 * prior-tenure content (the shortform still carries entries a
		 * peer has since removed) -> durable resurrection.  The dir's
		 * on-disk image is already authoritative (our last committed
		 * dirent change was persisted when it was logged), so SKIP a
		 * held clean DIR slot exactly like a released NL one.  Per-inode
		 * v5 CRCs make writing only the modified inode-sized runs valid.
		 * Non-dir held slots keep the original "never drop an inode we
		 * own" behaviour (so an all-skip -> whole-write degenerate case
		 * cannot strand a buffer with no logged inode items).
		 */
		/*
		 * A DIR dinode slot not logged this round is NEVER written from
		 * our cluster buffer, regardless of in-core state.  The flushing
		 * node often holds the 4 KiB cluster buffer cached for a churned
		 * child FILE inode while the shared dir's own inode is NOT
		 * in-core here (ip == NULL) — so the buffer's dir slot is a STALE
		 * prior-tenure image, and writing it back resurrects a
		 * peer-removed dirent (PROVEN sess56: tds n2_r57 leftover persists
		 * even with the in-core-gated skip because the resurrecting write
		 * came from a node that did NOT have the dir in-core).  The dir's
		 * authoritative image is written ONLY by its EX holder's logged
		 * flush (the logged branch above); every other cluster flush
		 * leaves the dir slot untouched on disk.
		 */
		if ((be16_to_cpu(d->di_mode) & S_IFMT) == S_IFDIR) {
			/* sess7 (ccloop 8ba7ae5c): identity + realns added for
			 * the iter_13/14 lost-final-shrink forensics.  MUST
			 * stay ratelimited: the un-ratelimited capped variant
			 * printed ~75/s/node during the dlm_scaling
			 * create/unlink storm (17,964 lines/4min on test17)
			 * and its printk cost alone dragged per-node op rate
			 * below the test's 50 ops/s floor (32/caw 27/32). */
			skip |= slotbits;
			nskip++;
			pr_warn_ratelimited(
				"mxfs: P56-CORESIDENT-DIR-SKIP daddr=%lld slot=%d incore=%d mode=%d img_ino=%llu img_nx=%u img_chg=%llu comm=%s realns=%llu — dir slot not logged this round; skip\n",
				(long long)bp->b_maps[0].bm_bn, s,
				ip ? 1 : 0, ip ? ip->i_dlm_mode : -1,
				(unsigned long long)be64_to_cpu(d->di_ino),
				be32_to_cpu(d->di_nextents),
				(unsigned long long)be64_to_cpu(d->di_changecount),
				current->comm,
				(unsigned long long)ktime_get_real_ns());
			continue;
		}
		if (!is_free && !is_nl)
			continue;		/* held non-dir inode -> write it */
		/* FREE / NL (peer-owned), not logged -> skip (BUG1/BUG2). */
		skip |= slotbits;
		nskip++;
	}
	spin_unlock(&pag->pag_ici_lock);

	{ extern int mxfs_iwr_enabled;
	  if (unlikely(mxfs_iwr_enabled)) {
		pr_warn_ratelimited(
			"mxfs: P28-IWR daddr=%lld ni=%u base_agino=%u logged=%u incore=%u nl=%u held=%u nl_logged=%u nskip=%u -> %s\n",
			(long long)bp->b_maps[0].bm_bn, ni, base_agino, nslots,
			n_incore, n_nl, n_held, n_nl_logged, nskip,
			nskip ? "PARTIAL" : "WHOLE");
		/* When whole-writing, flag any FREE (di_mode==0) dinode in the
		 * buffer — that is the prior-tenure image that reverts a peer's
		 * realloc.  Report di_ino/gen + this slot's in-core dlm_mode. */
		if (nskip == 0) {
			unsigned int o;
			for (o = 0; o + inodesize <= len; o += inodesize) {
				struct xfs_dinode *d = bp->b_addr + o;
				int slot = o >> inodelog;
				struct xfs_inode *ip2;

				if (be16_to_cpu(d->di_magic) != XFS_DINODE_MAGIC)
					continue;
				if (d->di_mode != 0)
					continue;
				mxfs_ici_lock(pag);
				ip2 = radix_tree_lookup(&pag->pag_ici_root,
							base_agino + slot);
				pr_warn_ratelimited(
					"mxfs: P28-IWR-FREEWR daddr=%lld slot=%d di_ino=%llu di_gen=%u logged=%d incore=%d dlm_mode=%d\n",
					(long long)bp->b_maps[0].bm_bn, slot,
					(unsigned long long)be64_to_cpu(d->di_ino),
					be32_to_cpu(d->di_gen),
					!!(logged & (1ULL << (slot * spi))),
					!!ip2, ip2 ? ip2->i_dlm_mode : -1);
				spin_unlock(&pag->pag_ici_lock);
			}
		}
	  }
	}
	}

	all = (total_sects >= 64) ? ~0ULL : ((1ULL << total_sects) - 1);
	dirty = all & ~skip;

	/*
	 * sess3 (ccloop a16ec5f2) watch: record the partial-writer's DECISION
	 * for the watched sector — whether the ino131-class dinode sector is
	 * actually part of the submitted write (included=1), skipped, or the
	 * whole buffer goes out via the fallback paths below.  Pairs with the
	 * PW-DADDR/PW-SLOT submit-chokepoint decode by bp pointer.
	 */
	{
		extern unsigned long long mxfs_watch_daddr;

		if (unlikely(mxfs_watch_daddr) &&
		    (xfs_daddr_t)mxfs_watch_daddr >= bp->b_maps[0].bm_bn &&
		    (xfs_daddr_t)mxfs_watch_daddr < bp->b_maps[0].bm_bn +
						    bp->b_maps[0].bm_len) {
			int wsect = (int)((xfs_daddr_t)mxfs_watch_daddr -
					  bp->b_maps[0].bm_bn);

			pr_warn("mxfs: PW-IWR daddr=%lld wsect=%d included=%d whole=%d logged=0x%llx bli_dirty=0x%llx skip=0x%llx dirty=0x%llx bp=%px comm=%s\n",
				(long long)bp->b_maps[0].bm_bn, wsect,
				(nskip == 0 || dirty == 0) ? 1 :
					!!(dirty & (1ULL << wsect)),
				(nskip == 0 || dirty == 0),
				logged, bli_dirty, skip, dirty, bp,
				current->comm);
		}
	}

	if (nskip == 0)
		return false;		/* nothing to skip -> whole-buffer write */
	if (dirty == 0)
		return false;		/* would write nothing -> whole write */

	base_512 = bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	vmalloc = is_vmalloc_addr(bp->b_addr);

	/* Find the LAST contiguous owned-sector run; it becomes the parent bio. */
	s = 0;
	while (s < (int)total_sects) {
		if (!(dirty & (1ULL << s))) { s++; continue; }
		run_start = s;
		while (s < (int)total_sects && (dirty & (1ULL << s)))
			s++;
		last_start = run_start;
		runs++;
	}
	if (runs == 0)
		return false;

	{
		unsigned int off = last_start * sectsize;
		unsigned int rlen;
		int e = last_start;
		while (e < (int)total_sects && (dirty & (1ULL << e)))
			e++;
		rlen = (e - last_start) * sectsize;
		tail = bio_alloc(bp->b_target->bt_bdev,
				 bio_add_max_vecs((char *)bp->b_addr + off, rlen),
				 xfs_buf_bio_op(bp), GFP_NOIO);
		if (vmalloc)
			bio_add_vmalloc(tail, (char *)bp->b_addr + off, rlen);
		else
			bio_add_virt_nofail(tail, (char *)bp->b_addr + off, rlen);
		tail->bi_iter.bi_sector = base_512 + (off >> 9);
		tail->bi_private = bp;
		tail->bi_end_io = xfs_buf_bio_end_io;
	}

	blk_start_plug(&plug);
	s = 0;
	while (s < (int)total_sects) {
		unsigned int off, rlen;

		if (!(dirty & (1ULL << s))) { s++; continue; }
		run_start = s;
		while (s < (int)total_sects && (dirty & (1ULL << s)))
			s++;
		run_end = s;
		if (run_start == last_start)
			continue;		/* parent run, submitted last */
		off  = run_start * sectsize;
		rlen = (run_end - run_start) * sectsize;
		{
			struct bio *child = bio_alloc(bp->b_target->bt_bdev,
				bio_add_max_vecs((char *)bp->b_addr + off, rlen),
				xfs_buf_bio_op(bp), GFP_NOIO);
			if (vmalloc)
				bio_add_vmalloc(child, (char *)bp->b_addr + off, rlen);
			else
				bio_add_virt_nofail(child, (char *)bp->b_addr + off, rlen);
			child->bi_iter.bi_sector = base_512 + (off >> 9);
			bio_chain(child, tail);
			submit_bio(child);
		}
	}
	mxfs_buf_ev(bp, MXFS_BEV_BIO);
	submit_bio(tail);
	blk_finish_plug(&plug);

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		pr_warn_ratelimited(
			"mxfs: P27-SKIPNL-IWRITE daddr=%lld ni=%u logged=%u skipped=%u runs=%d logged_m=0x%llx dirty_m=0x%llx skip_m=0x%llx realns=%llu\n",
			(long long)bp->b_maps[0].bm_bn, ni, nslots, nskip, runs,
			(unsigned long long)logged,
			(unsigned long long)dirty,
			(unsigned long long)skip,
			(unsigned long long)ktime_get_real_ns());
	return true;
}

/*
 * sess29 (ccloop 8ddb16a2) — count live dirents + fingerprint their inode
 * numbers in a v5 dir3 DATA or BLOCK buffer image.  Used by the write-side
 * stale-RMW detector P29-DATAWRITE: a dir DATA block we are about to submit
 * that has FEWER live dirents than (or a different inumber-set from) the
 * COHERENT on-disk copy is a stale-base read-modify-write that will durably
 * DROP a peer's just-committed dirents — the dir_reuse_coherency
 * "node1_f1..f12 missing from readdir" durable loss.  fp_sum/fp_xor over the
 * lower 32 bits of each inumber catch an equal-count content divergence.
 * block_form: true for xfs_dir3_block_buf_ops (entries end where the trailing
 * leaf-entry array begins), false for xfs_dir3_data_buf_ops (entries run to
 * end of block).
 */
uint32_t
mxfs_dir3_data_fingerprint(struct xfs_mount *mp, const void *blk,
			   uint32_t blklen, bool block_form,
			   uint32_t *fp_sum, uint32_t *fp_xor)
{
	const struct xfs_dir3_data_hdr	*h3 = blk;
	const char			*p, *endp;
	uint32_t			cnt = 0, sum = 0, xr = 0;
	__be32				magic;

	*fp_sum = 0;
	*fp_xor = 0;
	if (!blk || blklen < sizeof(*h3))
		return 0;
	magic = h3->hdr.magic;
	if (magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return 0;
	p = (const char *)blk + sizeof(struct xfs_dir3_data_hdr);
	if (block_form) {
		const struct xfs_dir2_block_tail *btp =
			(const struct xfs_dir2_block_tail *)
				((const char *)blk + blklen) - 1;
		uint32_t lcount = be32_to_cpu(btp->count);

		endp = (const char *)btp -
			(size_t)lcount * sizeof(struct xfs_dir2_leaf_entry);
		if (endp < p || endp > (const char *)blk + blklen)
			endp = (const char *)blk + blklen;
	} else {
		endp = (const char *)blk + blklen;
	}
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;

		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);

			if (l < sizeof(*dup))
				break;		/* malformed -> stop */
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			uint8_t nl = dep->namelen;
			uint32_t inolo;

			if (nl == 0 || nl > MAXNAMELEN)
				break;		/* malformed -> stop */
			inolo = (uint32_t)be64_to_cpu(dep->inumber);
			sum += inolo;
			xr ^= inolo;
			cnt++;
			p += xfs_dir2_data_entsize(mp, nl);
		}
	}
	*fp_sum = sum;
	*fp_xor = xr;
	return cnt;
}
EXPORT_SYMBOL(mxfs_dir3_data_fingerprint);

/*
 * ccloop c7ee71c6 sess14: P172-WRTR — NON-PERTURBING write-provenance ring
 * for the D3 co-resident stale clobber (32/caw cache_coherency durable data
 * loss).  sess13 proved the race is µs-wide and printk-serialization at the
 * write path SUPPRESSES it (4/4 catastrophic hits with dirwr=0 vs 0/3 with
 * dirwr>=1, Fisher p≈0.03), and the capped always-on traces (P170-CLWR cap
 * 800, P3W cap 6000) exhaust during prep/storm long before the clobber.  So:
 * a memory-only circular ring recording EVERY dir-metadata and inode-cluster
 * buffer write submission on a multi-node mount — no printk, no lock, ~µs —
 * dumped only AFTER detection (mxfs.dirring_dump=1 poke from the harness, or
 * auto-throttled on P26-IGET-FAIL).  Merged across nodes by daddr+realns,
 * the write that regressed a slot/dirent-set names the clobberer + path.
 */
#define MXFS_WRTR_N	8192
struct mxfs_wrtr_ent {
	u64	ns;		/* ktime_get_real_ns at submit */
	u64	daddr;
	u64	owner;		/* dir owner ino / first dinode ino in cluster */
	u64	mask;		/* cluster: dirmask<<32|allocmask; dir: sum<<32|xor */
	u32	crc;		/* lineage crc32c past 48B hdr (cluster: whole buf) */
	s32	cnt;		/* active dirents / allocated slots; -1 n/a */
	u32	pid;
	u16	flags;		/* bit0 delwri bit1 fua_fresh bit2 in_ail bit3 dirty
				 * bit4 pin bit5 done bit6 stale bit7 xbf_async */
	u8	type;		/* 0=inocluster 1=block 2=data 3=leaf1 4=leafn 5=danode */
	u8	gmode;		/* DLM granted mode of owner dir (255 = n/a) */
	char	comm[12];
};
static struct mxfs_wrtr_ent mxfs_wrtr[MXFS_WRTR_N];
static atomic_t mxfs_wrtr_idx = ATOMIC_INIT(0);

static void
mxfs_wrtr_record(struct xfs_buf *bp)
{
	struct mxfs_wrtr_ent *e;
	struct xfs_buf_log_item *bip = bp->b_log_item;
	u64 owner = 0, mask = 0;
	s32 cnt = -1;
	u8 type, gmode = 255;

	if (bp->b_ops == &xfs_inode_buf_ops) {
		int isz = bp->b_mount->m_sb.sb_inodesize;
		int nsl = isz ? (int)(BBTOB(bp->b_length) / isz) : 0;
		u32 am = 0, dm = 0;
		int i;

		type = 0;
		if (nsl > 32)
			nsl = 32;
		cnt = 0;
		for (i = 0; i < nsl; i++) {
			struct xfs_dinode *d = (struct xfs_dinode *)
				((char *)bp->b_addr + i * isz);
			u16 mode;

			if (be16_to_cpu(d->di_magic) != XFS_DINODE_MAGIC)
				continue;
			if (!owner)
				owner = be64_to_cpu(d->di_ino);
			mode = be16_to_cpu(d->di_mode);
			if (mode) {
				am |= 1U << i;
				cnt++;
				if (S_ISDIR(mode))
					dm |= 1U << i;
			}
		}
		mask = ((u64)dm << 32) | am;
	} else if (bp->b_ops == &xfs_dir3_block_buf_ops ||
		   bp->b_ops == &xfs_dir3_data_buf_ops) {
		u32 s = 0, x = 0;

		type = (bp->b_ops == &xfs_dir3_block_buf_ops) ? 1 : 2;
		cnt = (s32)mxfs_dir3_data_fingerprint(bp->b_mount, bp->b_addr,
				BBTOB(bp->b_length), type == 1, &s, &x);
		mask = ((u64)s << 32) | x;
		owner = be64_to_cpu(
			((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner);
	} else if (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
		   bp->b_ops == &xfs_dir3_leafn_buf_ops) {
		struct xfs_dir3_leaf_hdr *lh = bp->b_addr;

		type = (bp->b_ops == &xfs_dir3_leaf1_buf_ops) ? 3 : 4;
		owner = be64_to_cpu(lh->info.owner);
		cnt = (s32)be16_to_cpu(lh->count) - (s32)be16_to_cpu(lh->stale);
	} else if (bp->b_ops == &xfs_da3_node_buf_ops) {
		struct xfs_da3_node_hdr *nh = bp->b_addr;

		type = 5;
		owner = be64_to_cpu(nh->info.owner);
		cnt = (s32)be16_to_cpu(nh->__count);
	} else {
		return;
	}

	if (type && owner && bp->b_mount->m_mxfs_dlm)
		gmode = mxfs_v5_dlm_inode_granted_mode(bp->b_mount->m_mxfs_dlm,
						       owner);

	e = &mxfs_wrtr[(u32)atomic_inc_return(&mxfs_wrtr_idx) % MXFS_WRTR_N];
	e->ns = ktime_get_real_ns();
	e->daddr = (u64)xfs_buf_daddr(bp);
	e->owner = owner;
	e->mask = mask;
	e->crc = type ? crc32c(0, (char *)bp->b_addr + 48,
			       BBTOB(bp->b_length) - 48)
		      : crc32c(0, bp->b_addr, BBTOB(bp->b_length));
	e->cnt = cnt;
	e->pid = current->pid;
	e->flags = ((bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0) |
		   ((bp->b_flags & _XBF_FUA_FRESH) ? 2 : 0) |
		   ((bip && test_bit(XFS_LI_IN_AIL,
				     &bip->bli_item.li_flags)) ? 4 : 0) |
		   ((bip && test_bit(XFS_LI_DIRTY,
				     &bip->bli_item.li_flags)) ? 8 : 0) |
		   (xfs_buf_ispinned(bp) ? 16 : 0) |
		   ((bp->b_flags & XBF_DONE) ? 32 : 0) |
		   ((bp->b_flags & XBF_STALE) ? 64 : 0) |
		   ((bp->b_flags & XBF_ASYNC) ? 128 : 0);
	e->type = type;
	e->gmode = gmode;
	strscpy(e->comm, current->comm, sizeof(e->comm));
}

void mxfs_wrtr_dump(void);
void mxfs_wrtr_dump_auto(void);

void
mxfs_wrtr_dump(void)
{
	u32 idx = (u32)atomic_read(&mxfs_wrtr_idx);
	int i;

	pr_warn("mxfs: P172-WRTR-DUMP total=%u ring=%u\n", idx,
		idx > MXFS_WRTR_N ? MXFS_WRTR_N : idx);
	for (i = 0; i < MXFS_WRTR_N; i++) {
		struct mxfs_wrtr_ent *e =
			&mxfs_wrtr[(idx + 1 + i) % MXFS_WRTR_N];

		if (!e->ns)
			continue;
		pr_warn("mxfs: P172-WRTR t=%u daddr=%llu owner=%llu cnt=%d mask=%016llx crc=%08x gm=%u fl=%02x comm=%s pid=%u ns=%llu\n",
			e->type, (unsigned long long)e->daddr,
			(unsigned long long)e->owner, e->cnt,
			(unsigned long long)e->mask, e->crc, e->gmode,
			e->flags, e->comm, e->pid,
			(unsigned long long)e->ns);
	}
}
EXPORT_SYMBOL(mxfs_wrtr_dump);

/*
 * Auto-dump on detection (P26-IGET-FAIL in xfs_inode.c): throttled hard —
 * a dump is ~8K printk lines (~1MB dmesg), and the 16M dmesg ring is the
 * only evidence store under journald rotation.  Max 4 per boot, 120s apart.
 */
void
mxfs_wrtr_dump_auto(void)
{
	static atomic_t auto_n = ATOMIC_INIT(0);
	static unsigned long last_jif;
	int n;

	if (last_jif && time_before(jiffies, last_jif + 120 * HZ))
		return;
	n = atomic_inc_return(&auto_n);
	if (n > 4)
		return;
	last_jif = jiffies;
	pr_warn("mxfs: P172-WRTR-AUTO n=%d (detection-triggered dump)\n", n);
	mxfs_wrtr_dump();
}
EXPORT_SYMBOL(mxfs_wrtr_dump_auto);

/*
 * sess26(ccloop) SUBSET CHECK (sess25's identified path): does the DISK dir
 * DATA block contain a dirent (by inumber) that the IN-CORE block we are about
 * to write LACKS?  If so, writing the in-core image would DROP that dirent =
 * the durable lost-update (a peer added it under EX after we cached our base).
 * The fingerprint (count+sum+xor) detects DIVERGENCE but not direction; this is
 * the real subset test sess25 said is required.  Returns the count of disk
 * inumbers absent from in-core (0 = in-core is a superset = safe to write).
 * Bounded O(n*m) over one block's dirents (rare suppression path).
 */
int
mxfs_dir3_disk_has_extra_inum(struct xfs_mount *mp, const void *incore,
			      const void *disk, uint32_t blklen,
			      bool incore_block_form, bool disk_block_form)
{
	uint64_t	ino_in[256];
	int		nin = 0, extra = 0;
	const char	*p, *endp;
	const struct xfs_dir3_data_hdr *hi = incore, *hd = disk;

	if (!incore || !disk || blklen < sizeof(*hi))
		return 0;
	if (hi->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    hi->hdr.magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return 0;
	if (hd->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    hd->hdr.magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return 0;

	/* collect in-core inumbers */
	p = (const char *)incore + sizeof(struct xfs_dir3_data_hdr);
	if (incore_block_form) {
		const struct xfs_dir2_block_tail *btp =
			(const struct xfs_dir2_block_tail *)
				((const char *)incore + blklen) - 1;
		uint32_t lc = be32_to_cpu(btp->count);
		endp = (const char *)btp - (size_t)lc *
			sizeof(struct xfs_dir2_leaf_entry);
		if (endp < p || endp > (const char *)incore + blklen)
			endp = (const char *)incore + blklen;
	} else {
		endp = (const char *)incore + blklen;
	}
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
			if (nin < 256)
				ino_in[nin++] = be64_to_cpu(dep->inumber);
			p += xfs_dir2_data_entsize(mp, dep->namelen);
		}
	}

	/* scan disk dirents; count those whose inumber is absent in-core */
	p = (const char *)disk + sizeof(struct xfs_dir3_data_hdr);
	if (disk_block_form) {
		const struct xfs_dir2_block_tail *btp =
			(const struct xfs_dir2_block_tail *)
				((const char *)disk + blklen) - 1;
		uint32_t lc = be32_to_cpu(btp->count);
		endp = (const char *)btp - (size_t)lc *
			sizeof(struct xfs_dir2_leaf_entry);
		if (endp < p || endp > (const char *)disk + blklen)
			endp = (const char *)disk + blklen;
	} else {
		endp = (const char *)disk + blklen;
	}
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			uint64_t di;
			int i;
			bool found = false;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
			di = be64_to_cpu(dep->inumber);
			for (i = 0; i < nin; i++)
				if (ino_in[i] == di) { found = true; break; }
			if (!found && nin < 256)	/* nin==256 => can't prove absence */
				extra++;
			p += xfs_dir2_data_entsize(mp, dep->namelen);
		}
	}
	return (nin < 256) ? extra : 0;	/* overflow => inconclusive => don't skip */
}

/*
 * sess2(ccloop 26c41354) — the REINTRODUCE-direction discriminator for the
 * 16-node durable dangling-dirent.
 *
 * The existing write-chokepoint guards (P26/P39/P12) only defend the disk-
 * SUPERSET direction: a buffer that would DROP a peer's dirent (an inum present
 * on disk but absent in-core).  The 16-node dangling-dirent is the OPPOSITE
 * (core-superset): a stale prior-tenure in-core image carries an EXTRA dirent
 * (an inum ABSENT on the current disk) whose on-disk inode is now FREE
 * (di_mode==0).  Writing that image durably REINTRODUCES a removed dirent
 * pointing at a freed inode -> readdir finds the name, iget ENOENTs
 * (P26-IGET-FAIL).  A legit un-landed ADD also shows an in-core-extra inum, but
 * its inode is LIVE on disk; the FREE/LIVE split is the safe discriminator (a
 * dirent to a free inode is NEVER a legitimate add).
 *
 * Walk the in-core dirents; for each whose inum is ABSENT from `disk`, map the
 * inum to its cluster and FUA-read the dinode.  Count FREE ones (magic ok,
 * di_mode==0) as reintroduces; count LIVE / unreadable ones into *live_extra
 * (never suppress those).  Returns the free-reintroduce count and fills
 * first_ino/first_name with the first free reintroduce for logging.  One FUA
 * read per in-core-extra dirent, so the caller MUST gate this on a cheap in-core
 * predicate (dc_stale) to keep the common path free of disk I/O (RULE 0).
 *
 * ccloop cc87fed3 sess9 (RULE 4): @do_trim extends this from detect-only to
 * SURGICAL CORRECTION.  P-REINTRO's own gate (dir_reintro_skip, dropping the
 * whole write) is proven inert here -- these blocks are never in-AIL between
 * operations (P68-EVDECIDE traced: evicted+refetched every modify call), so
 * the divergence is a genuine sub-millisecond TOCTOU between our own fresh
 * read and our own destage of the SAME block, during which a peer's own
 * durable remove of an unrelated (to us) entry lands -- the mirror of the
 * ADD-direction TOCTOU mxfs_dir3_data_writemerge already fixes by grafting,
 * not dropping.  When @do_trim is set, each PROVEN free-target entry (same
 * discriminator: a dirent can never legitimately point to a freed inode) is
 * converted to a free/unused descriptor IN PLACE -- mirrors
 * mxfs_dir3_data_graft_one's low-level unused-descriptor construction, just
 * removing instead of adding.  Every other byte of the write, including this
 * operation's own genuine edit, is untouched; the caller must
 * xfs_dir2_data_freescan() afterward (same as the graft path) before the CRC
 * verifier runs.  live_extra entries are NEVER touched either way (could be
 * a legit un-landed add -- same exclusion dir_reintro_skip already used).
 */
static int
mxfs_dir3_reintro_free_count(struct xfs_mount *mp, void *incore,
			     const void *disk, uint32_t blklen,
			     bool incore_block_form, bool disk_block_form,
			     int *live_extra, uint64_t *first_ino,
			     char *first_name, int *first_namelen,
			     bool do_trim)
{
	extern int xfs_imap(struct xfs_perag *, struct xfs_trans *,
			    xfs_ino_t, struct xfs_imap *, uint);
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
	uint64_t	ino_disk[256];
	int		ndisk = 0, freecnt = 0, livecnt = 0;
	const char	*p, *endp;
	const struct xfs_dir3_data_hdr *hi = incore, *hd = disk;

	if (live_extra)
		*live_extra = 0;
	if (!incore || !disk || blklen < sizeof(*hi))
		return 0;
	if (hi->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    hi->hdr.magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return 0;
	if (hd->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    hd->hdr.magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return 0;

	/* collect disk inumbers */
	p = (const char *)disk + sizeof(struct xfs_dir3_data_hdr);
	if (disk_block_form) {
		const struct xfs_dir2_block_tail *btp =
			(const struct xfs_dir2_block_tail *)
				((const char *)disk + blklen) - 1;
		uint32_t lc = be32_to_cpu(btp->count);
		endp = (const char *)btp - (size_t)lc *
			sizeof(struct xfs_dir2_leaf_entry);
		if (endp < p || endp > (const char *)disk + blklen)
			endp = (const char *)disk + blklen;
	} else {
		endp = (const char *)disk + blklen;
	}
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup))
				break;
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN)
				break;
			if (ndisk < 256)
				ino_disk[ndisk++] = be64_to_cpu(dep->inumber);
			p += xfs_dir2_data_entsize(mp, dep->namelen);
		}
	}
	if (ndisk >= 256)	/* can't prove absence => inconclusive */
		return 0;

	/* walk in-core dirents; for each inum absent on disk, check free-ness.
	 * Non-const (ip2/iendp, not the shared disk-only p/endp) so a proven
	 * free-target entry can be trimmed in place when do_trim is set. */
	{
	char	*ip2, *iendp;

	ip2 = (char *)incore + sizeof(struct xfs_dir3_data_hdr);
	if (incore_block_form) {
		struct xfs_dir2_block_tail *btp =
			(struct xfs_dir2_block_tail *)
				((char *)incore + blklen) - 1;
		uint32_t lc = be32_to_cpu(btp->count);
		iendp = (char *)btp - (size_t)lc *
			sizeof(struct xfs_dir2_leaf_entry);
		if (iendp < ip2 || iendp > (char *)incore + blklen)
			iendp = (char *)incore + blklen;
	} else {
		iendp = (char *)incore + blklen;
	}
	while (ip2 + sizeof(struct xfs_dir2_data_unused) <= iendp) {
		struct xfs_dir2_data_unused *dup = (void *)ip2;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup))
				break;
			ip2 += l;
			continue;
		}
		{
			struct xfs_dir2_data_entry *dep = (void *)ip2;
			uint64_t di;
			int i;
			bool found = false;
			uint32_t esz;

			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN)
				break;
			esz = xfs_dir2_data_entsize(mp, dep->namelen);
			di = be64_to_cpu(dep->inumber);
			for (i = 0; i < ndisk; i++)
				if (ino_disk[i] == di) {
					found = true;
					break;
				}
			if (!found) {
				/* in-core-extra dirent: is its on-disk inode free? */
				struct xfs_perag *pag;
				struct xfs_imap imap;
				int isfree = -1;	/* -1 = unknown/unreadable */

				pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, di));
				if (pag) {
					memset(&imap, 0, sizeof(imap));
					if (xfs_imap(pag, NULL, di, &imap, 0) == 0 &&
					    imap.im_len &&
					    imap.im_boffset + mp->m_sb.sb_inodesize
						<= BBTOB(imap.im_len)) {
						uint32_t clen = BBTOB(imap.im_len);
						void *ctmp = (clen && !(clen & 511)) ?
							kmalloc(clen, GFP_NOFS) : NULL;

						if (ctmp) {
							uint64_t lba =
							  (uint64_t)imap.im_blkno +
							  mp->m_ddev_targp->bt_sector_offset;

							/*
							 * ccloop cc87fed3 sess9 (RULE 4,
							 * PROVEN by a live dir_reuse_coherency
							 * regression: readdir count(exp=800
							 * got=100) EVERY round -- do_trim
							 * wrongly stripped 7/8 nodes' brand-new
							 * concurrent creates): a raw SCSI-FUA
							 * read on this SCST target pierces PAST
							 * the shared write-back cache to the
							 * un-destaged PLATTER (documented
							 * cluster architecture fact, see the
							 * fua_disable=1 default's own rationale
							 * -- normal reads deliberately avoid FUA
							 * for exactly this reason). A peer's
							 * brand-new inode allocation is visible
							 * cluster-wide via the shared cache
							 * immediately but can take longer to
							 * reach the physical platter -- a raw
							 * FUA read of that inode during the gap
							 * still shows di_mode==0 (STALE "free"),
							 * so a legitimately live, just-created
							 * peer dirent was misclassified isfree=1
							 * and (once do_trim landed) surgically
							 * removed. Use the SAME coherent plain
							 * read already used for the dir-block
							 * compare at this exact chokepoint (rdsk
							 * above) instead of a raw FUA read --
							 * matches every other disk-truth read in
							 * this write-side machinery.
							 */
							if (mxfs_pal_bdev_read_plain_bdev(
							    mp->m_ddev_targp->bt_bdev,
							    lba, ctmp, clen) == 0) {
								struct xfs_dinode *dd =
								  (struct xfs_dinode *)
								  ((char *)ctmp +
								   imap.im_boffset);

								if (be16_to_cpu(dd->di_magic)
								    == XFS_DINODE_MAGIC)
									isfree = (dd->di_mode == 0);
							}
							kfree(ctmp);
						}
					}
					xfs_perag_put(pag);
				}
				if (isfree == 1) {
					if (freecnt == 0 && first_ino)
						*first_ino = di;
					if (freecnt == 0 && first_name &&
					    first_namelen) {
						int nl = dep->namelen;

						if (nl > 0 && nl <= MAXNAMELEN) {
							memcpy(first_name, dep->name, nl);
							*first_namelen = nl;
						}
					}
					freecnt++;
					/*
					 * ccloop cc87fed3 sess9: SURGICAL TRIM.
					 * Convert this proven-free-target entry's
					 * own bytes to a valid unused descriptor,
					 * in place -- mirrors
					 * mxfs_dir3_data_graft_one's construction
					 * of a trailing free remainder (freetag,
					 * length, then the tag computed from
					 * length).  esz is XFS_DIR2_DATA_ALIGN(8)-
					 * rounded (xfs_dir2_data_entsize, same as
					 * every real entry) so it always meets the
					 * unused descriptor's minimum size.  Every
					 * OTHER byte of this write, including this
					 * operation's own edit elsewhere in the
					 * block, is untouched; the caller
					 * freescans afterward to rebuild bestfree.
					 */
					if (do_trim) {
						dup->freetag =
						    cpu_to_be16(
							XFS_DIR2_DATA_FREE_TAG);
						dup->length =
						    cpu_to_be16((uint16_t)esz);
						*xfs_dir2_data_unused_tag_p(dup) =
						    cpu_to_be16((uint16_t)
							(ip2 - (char *)incore));
					}
				} else {
					/* LIVE (isfree==0) or unreadable (-1):
					 * never a suppress candidate. */
					livecnt++;
				}
			}
			ip2 += esz;
		}
	}
	}
	if (live_extra)
		*live_extra = livecnt;
	return freecnt;
}

/*
 * sess29(ccloop) graft a single dirent (src, from a peer's on-disk image) into
 * the FIRST free slot of dir DATA block `blk` that can hold it.  Non-logged byte
 * surgery on the final write image: the caller calls xfs_dir2_data_freescan to
 * rebuild bestfree afterwards and verify_write stamps the CRC, so no transaction
 * is involved.  Free lengths and entsize are both XFS_DIR2_DATA_ALIGN(8)-rounded,
 * so the residual free chunk is either 0 (exact) or >= 8 (a valid unused entry).
 * Returns 1 if grafted, 0 if no slot was large enough.
 */
static int
mxfs_dir3_data_graft_one(struct xfs_mount *mp, void *blk, uint32_t blen,
			 const struct xfs_dir2_data_entry *src, uint32_t need)
{
	char	*p = (char *)blk + sizeof(struct xfs_dir3_data_hdr);
	char	*endp = (char *)blk + blen;

	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		struct xfs_dir2_data_unused	*dup = (void *)p;

		if (be16_to_cpu(dup->freetag) != XFS_DIR2_DATA_FREE_TAG) {
			struct xfs_dir2_data_entry *dep = (void *)p;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN)
				return 0;
			p += xfs_dir2_data_entsize(mp, dep->namelen);
			continue;
		}
		{
			uint16_t	flen = be16_to_cpu(dup->length);
			uint16_t	off = (uint16_t)(p - (char *)blk);

			if (flen < sizeof(*dup))
				return 0;
			if (flen >= need &&
			    (flen == need ||
			     flen - need >= sizeof(struct xfs_dir2_data_unused))) {
				struct xfs_dir2_data_entry *dep = (void *)p;
				uint16_t rem = flen - need;

				dep->inumber = src->inumber;
				dep->namelen = src->namelen;
				memcpy(dep->name, src->name, src->namelen);
				xfs_dir2_data_put_ftype(mp, dep,
					xfs_dir2_data_get_ftype(mp,
					    (struct xfs_dir2_data_entry *)src));
				*xfs_dir2_data_entry_tag_p(mp, dep) =
					cpu_to_be16(off);
				if (rem) {
					struct xfs_dir2_data_unused *ndup =
						(void *)(p + need);
					ndup->freetag =
					    cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
					ndup->length = cpu_to_be16(rem);
					*xfs_dir2_data_unused_tag_p(ndup) =
					    cpu_to_be16((uint16_t)(off + need));
				}
				return 1;
			}
			p += flen;
		}
	}
	return 0;
}

/*
 * sess29(ccloop) WRITE-SIDE 3-WAY MERGE — the decisive fix for the dir_reuse
 * durable dirent loss (criteria: 8/tcp 100%).  PROVEN root (sess28 smoking gun):
 * the dir EX holder destages a dir DATA block whose on-disk image moved forward
 * (a peer added a dirent durably) AFTER the block was last refreshed but BEFORE
 * this async xfsaild destage -> the write reverts the peer's add.  This is a
 * write-side TOCTOU the read-side refresh cannot close (a peer can always add
 * after our last read).  Fix it at the bio chokepoint — the last line of defence
 * with disk ground truth: FUA-read the current on-disk image (authoritative; it
 * passed the peer's write verifier) and, ONLY when the two images diverge in
 * BOTH directions (we hold an add the disk lacks AND the disk holds an add we
 * lack = MERGE-NEEDED), graft the disk's unique dirents into OUR in-core block.
 *
 * The MERGE-NEEDED gate is what makes this loss-safe: a legit REMOVE looks like
 * pure-stale (incore_extra==0, disk_extra>0) and is NEVER touched, so a removed
 * entry is never resurrected.  In the dir_reuse create wave there are no
 * concurrent removes, so bidirectional divergence is always two concurrent adds.
 * Grafting peer adds INTO our block (not adopting the disk image wholesale) keeps
 * OUR entries at their logged offsets, so log redo stays consistent.
 *
 * Called from xfs_buf_submit BEFORE xfs_buf_verify_write, so freescan's rebuilt
 * bestfree and the grafted dirents are covered by the CRC the verifier stamps.
 * Returns 1 if b_addr was modified, 0 otherwise.
 */
static int
mxfs_dir3_data_writemerge(struct xfs_buf *bp)
{
	extern int mxfs_dir_write_merge;
	extern int mxfs_dir_choke_merge;
	extern bool mxfs_dir_choke_merge_remset(struct xfs_buf *, uint64_t *,
						uint32_t, uint32_t *);
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
	struct xfs_mount		*mp = bp->b_mount;
	struct xfs_dir3_data_hdr	*hi, *hd;
	const char			*nm_in[512];
	uint8_t				nl_in[512];
	int				nin = 0;
	uint32_t			blen, need;
	void				*dsk;
	const char			*p, *endp;
	uint64_t			lba;
	int				i, loghead = 0, grafted = 0, ourx = 0;
	int				dko = 0;	/* sess41: disk-only-by-name count */
	int				ret = 0;
	/* sess41: disambiguated chokepoint-merge removed-set snapshot. */
	uint64_t			remsnap[256];
	uint32_t			remn = 0;
	bool				disamb = false;

	if (!mxfs_dir_write_merge && !mxfs_dir_choke_merge)
		return 0;
	if (bp->b_ops != &xfs_dir3_data_buf_ops)	/* node/leaf data blocks */
		return 0;
	if (!(bp->b_flags & XBF_WRITE) || !bp->b_addr || bp->b_map_count != 1)
		return 0;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	if (!bp->b_target || !bp->b_target->bt_bdev)
		return 0;
	blen = BBTOB(bp->b_length);
	if (!blen || (blen & 511))
		return 0;
	hi = bp->b_addr;
	if (hi->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC))
		return 0;

	dsk = kmalloc(blen, GFP_NOFS);
	if (!dsk)
		return 0;
	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	/* PLAIN read (NOT FUA): the peer published its add to the target write-back
	 * cache before notifying us; a FUA read hits the lagging platter and tears
	 * (grafts a phantom -> +1 over-count).  The plain read sees the coherent
	 * target-cache image. */
	if (mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev, lba, dsk, blen) != 0)
		goto out;
	hd = dsk;
	/* same block, current incarnation, structurally a data block? */
	if (hd->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	    hd->hdr.owner != hi->hdr.owner)
		goto out;
	if (memcmp(dsk, bp->b_addr, blen) == 0)
		goto out;		/* identical: nothing to merge */

	/* collect in-core NAMES (dedup by name, NOT inumber: the dir's rm+recreate
	 * churn reuses names with fresh inodes, so an inumber-keyed dedup would
	 * graft a stale prior-incarnation entry as a DUPLICATE NAME). */
	p = (const char *)bp->b_addr + sizeof(struct xfs_dir3_data_hdr);
	endp = (const char *)bp->b_addr + blen;
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
			if (nin < 512) {
				nm_in[nin] = (const char *)dep->name;
				nl_in[nin] = dep->namelen;
				nin++;
			}
			p += xfs_dir2_data_entsize(mp, dep->namelen);
		}
	}
	if (nin >= 512)
		goto out;		/* too many to be sure */

	/*
	 * sess41: try to sanction the DISAMBIGUATED merge — owner dir EX-held by
	 * us, valid current-tenure removed-set snapshotted.  When sanctioned, a
	 * disk-only dirent is safe to graft unless its inumber is in the
	 * removed-set (= our own remove); we no longer need the conservative
	 * ourx>0 "both diverge" gate (which missed the pure-stale-base clobber:
	 * our block a subset of disk, ourx==0).
	 */
	disamb = mxfs_dir_choke_merge_remset(bp, remsnap, 256, &remn);
	/* sess41 REACH probe (always-on, capped): the function got past the disk
	 * read + magic/owner + memcmp-differs gates for a dir DATA write, so disk
	 * DIFFERS from in-core here.  disamb tells whether the graft is sanctioned. */
	{
		static atomic_t wmr = ATOMIC_INIT(0);
		if (atomic_inc_return(&wmr) <= 400)
			pr_warn("mxfs: P-WMR-REACH owner=%llu daddr=%lld disamb=%d remn=%u comm=%s\n",
				(unsigned long long)be64_to_cpu(hi->hdr.owner),
				(long long)bp->b_maps[0].bm_bn,
				disamb, remn, current->comm);
	}

	/* incore_extra: do WE hold a NAME the disk lacks?  Gate: MERGE-NEEDED only
	 * (both directions diverge) -> never touch a pure-stale write (a legit
	 * remove looks pure-stale; grafting would resurrect it). */
	p = (const char *)bp->b_addr + sizeof(struct xfs_dir3_data_hdr);
	endp = (const char *)bp->b_addr + blen;
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp && !ourx) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		const struct xfs_dir2_data_entry *dep;
		const char *q, *qe;
		int found = 0;

		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		dep = (const void *)p;
		if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
		/* present on disk by name? */
		q = (const char *)dsk + sizeof(struct xfs_dir3_data_hdr);
		qe = (const char *)dsk + blen;
		while (q + sizeof(struct xfs_dir2_data_unused) <= qe) {
			const struct xfs_dir2_data_unused *qd = (const void *)q;
			const struct xfs_dir2_data_entry *qep;
			if (be16_to_cpu(qd->freetag) == XFS_DIR2_DATA_FREE_TAG) {
				uint16_t l = be16_to_cpu(qd->length);
				if (l < sizeof(*qd)) break;
				q += l;
				continue;
			}
			qep = (const void *)q;
			if (qep->namelen == 0 || qep->namelen > MAXNAMELEN) break;
			if (qep->namelen == dep->namelen &&
			    memcmp(qep->name, dep->name, dep->namelen) == 0) {
				found = 1;
				break;
			}
			q += xfs_dir2_data_entsize(mp, qep->namelen);
		}
		if (!found)
			ourx++;
		p += xfs_dir2_data_entsize(mp, dep->namelen);
	}
	/*
	 * sess41: the disambiguated path (removed-set in hand) is safe even when
	 * ourx==0 (a pure stale-base subset write that would clobber a peer add).
	 * Only the OLD over-grafting path needs the ourx>0 "could be a remove"
	 * heuristic — and it must be explicitly enabled.
	 */
	if (!disamb) {
		if (!mxfs_dir_write_merge)
			goto out;	/* choke-merge not sanctioned; old path off */
		if (ourx == 0)
			goto out;	/* pure-stale: ambiguous (could be a remove) */
	}

	/* graft each disk-only dirent (a peer add we lack, by NAME) into our block */
	p = (const char *)dsk + sizeof(struct xfs_dir3_data_hdr);
	endp = (const char *)dsk + blen;
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		const struct xfs_dir2_data_entry *dep;
		int found = 0;

		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		dep = (const void *)p;
		if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
		for (i = 0; i < nin; i++)
			if (nl_in[i] == dep->namelen &&
			    memcmp(nm_in[i], dep->name, dep->namelen) == 0) {
				found = 1;
				break;
			}
		if (!found) {
			dko++;	/* sess41: a name on disk we lack (peer add or our remove) */
			/*
			 * sess41: in the disambiguated path, NEVER graft a
			 * disk-only dirent whose inumber is in our current-tenure
			 * removed-set — that is OUR remove, not a peer add;
			 * grafting would resurrect it (the dir_write_merge
			 * over-graft-to-803).  A peer add (not removed) is grafted.
			 */
			if (disamb) {
				uint64_t gin = be64_to_cpu(dep->inumber);
				uint32_t k;
				bool removed = false;

				for (k = 0; k < remn; k++)
					if (remsnap[k] == gin) {
						removed = true;
						break;
					}
				if (removed) {
					p += xfs_dir2_data_entsize(mp,
							dep->namelen);
					continue;
				}
			}
			need = xfs_dir2_data_entsize(mp, dep->namelen);
			if (mxfs_dir3_data_graft_one(mp, bp->b_addr, blen, dep,
						     need))
				grafted++;
		}
		p += xfs_dir2_data_entsize(mp, dep->namelen);
	}

	if (grafted) {
		xfs_dir2_data_freescan(mp,
			(struct xfs_dir2_data_hdr *)bp->b_addr, &loghead);
		ret = 1;
		{
			static atomic_t wm = ATOMIC_INIT(0);
			if (atomic_inc_return(&wm) <= 4000)
				pr_warn_ratelimited("mxfs: P-WMERGE2 owner=%llu daddr=%lld grafted=%d dko=%d ourx=%d disamb=%d remn=%u comm=%s — merged peer adds into dir block before destage\n",
					(unsigned long long)be64_to_cpu(hi->hdr.owner),
					(long long)bp->b_maps[0].bm_bn,
					grafted, dko, ourx, disamb, remn,
					current->comm);
		}
	} else if (dko > 0) {
		/* sess41: disk had names we lack but we grafted NONE — either disamb
		 * was not sanctioned, or all disk-only names were in our removed-set.
		 * This is the would-be clobber the merge could NOT prevent. */
		static atomic_t wmn = ATOMIC_INIT(0);
		if (atomic_inc_return(&wmn) <= 4000)
			pr_warn("mxfs: P-WMERGE-NOGRAFT owner=%llu daddr=%lld dko=%d disamb=%d remn=%u comm=%s\n",
				(unsigned long long)be64_to_cpu(hi->hdr.owner),
				(long long)bp->b_maps[0].bm_bn,
				dko, disamb, remn, current->comm);
	}
out:
	kfree(dsk);
	return ret;
}

/*
 * sess34(ccloop) RELEASE-DRAIN DISAMBIGUATED MERGE — the fix for the PROVEN
 * dir_reuse readdir=799 loss.  Called from mxfs_dir_flush_one_daddr with the
 * dir inode `dp` held EX, the buffer `bp` LOCKED, immediately BEFORE the
 * synchronous xfs_bwrite (the proven loss-write).  Reads the coherent on-disk
 * image; a disk-only-by-name dirent is grafted into our in-core block ONLY when
 * its inumber is NOT in this tenure's removed-set (mxfs_dir_was_removed) — i.e.
 * it is a PEER ADD we never refreshed, not our own pending remove.  This is the
 * unambiguous form of the old dir_write_merge (which over-grafted to 803 because
 * it resurrected our removes).  Returns 1 if b_addr was modified (caller's
 * xfs_bwrite then verify_write rebuilds the CRC over the freescan'd image).
 */
int
mxfs_dir3_data_drain_merge(struct xfs_inode *dp, struct xfs_buf *bp)
{
	extern int mxfs_dir_drain_merge;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
	struct xfs_mount		*mp = bp->b_mount;
	struct xfs_dir3_data_hdr	*hi, *hd;
	const char			*nm_in[512];
	uint8_t				nl_in[512];
	int				nin = 0;
	uint32_t			blen, need;
	void				*dsk;
	const char			*p, *endp;
	uint64_t			lba;
	int				i, loghead = 0, grafted = 0;
	int				ret = 0;

	if (!mxfs_dir_drain_merge)
		return 0;
	if (bp->b_ops != &xfs_dir3_data_buf_ops)	/* DATA blocks only */
		return 0;
	if (!bp->b_addr || bp->b_map_count != 1)
		return 0;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	if (!bp->b_target || !bp->b_target->bt_bdev)
		return 0;
	/* removed-set must be complete for this tenure (else merging could
	 * resurrect a remove we failed to record). */
	if (!mxfs_dir_remset_valid(dp))
		return 0;
	blen = BBTOB(bp->b_length);
	if (!blen || (blen & 511))
		return 0;
	hi = bp->b_addr;
	if (hi->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC))
		return 0;

	dsk = kmalloc(blen, GFP_NOFS);
	if (!dsk)
		return 0;
	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	/* PLAIN read (matches writemerge): the peer published its add to the
	 * target's coherent cache; a FUA read can hit a lagging platter. */
	if (mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev, lba, dsk, blen) != 0)
		goto out;
	hd = dsk;
	if (hd->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	    hd->hdr.owner != hi->hdr.owner)
		goto out;
	if (memcmp(dsk, bp->b_addr, blen) == 0)
		goto out;		/* identical: nothing to merge */

	/* collect in-core NAMES (dedup by name: rm+recreate reuses names with
	 * fresh inodes, so an inumber-keyed dedup would graft a duplicate name). */
	p = (const char *)bp->b_addr + sizeof(struct xfs_dir3_data_hdr);
	endp = (const char *)bp->b_addr + blen;
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		{
			const struct xfs_dir2_data_entry *dep = (const void *)p;
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
			if (nin < 512) {
				nm_in[nin] = (const char *)dep->name;
				nl_in[nin] = dep->namelen;
				nin++;
			}
			p += xfs_dir2_data_entsize(mp, dep->namelen);
		}
	}
	if (nin >= 512)
		goto out;		/* too many to be sure */

	/* graft each disk-only-by-name dirent whose inumber is NOT in this
	 * tenure's removed-set (= a peer add we never refreshed, not our remove). */
	p = (const char *)dsk + sizeof(struct xfs_dir3_data_hdr);
	endp = (const char *)dsk + blen;
	while (p + sizeof(struct xfs_dir2_data_unused) <= endp) {
		const struct xfs_dir2_data_unused *dup = (const void *)p;
		const struct xfs_dir2_data_entry *dep;
		int found = 0;

		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint16_t l = be16_to_cpu(dup->length);
			if (l < sizeof(*dup)) break;
			p += l;
			continue;
		}
		dep = (const void *)p;
		if (dep->namelen == 0 || dep->namelen > MAXNAMELEN) break;
		for (i = 0; i < nin; i++)
			if (nl_in[i] == dep->namelen &&
			    memcmp(nm_in[i], dep->name, dep->namelen) == 0) {
				found = 1;
				break;
			}
		if (!found &&
		    !mxfs_dir_was_removed(dp, be64_to_cpu(dep->inumber)) &&
		    !mxfs_dir_name_incore_global(dp, (const char *)dep->name,
						 dep->namelen,
						 bp->b_maps[0].bm_bn)) {
			/* disk-only by name in THIS block, NOT our remove, and
			 * absent from EVERY other in-core dir block (no cross-
			 * block dup) => a genuine peer add we lost: graft it. */
			need = xfs_dir2_data_entsize(mp, dep->namelen);
			if (mxfs_dir3_data_graft_one(mp, bp->b_addr, blen, dep,
						     need))
				grafted++;
		}
		p += xfs_dir2_data_entsize(mp, dep->namelen);
	}

	if (grafted) {
		xfs_dir2_data_freescan(mp,
			(struct xfs_dir2_data_hdr *)bp->b_addr, &loghead);
		ret = 1;
		{
			static atomic_t dm = ATOMIC_INIT(0);
			if (atomic_inc_return(&dm) <= 400)
				pr_warn("mxfs: P34-DRAINMERGE owner=%llu daddr=%lld grafted=%d — grafted peer adds (not our removes) into dir block before release bwrite\n",
					(unsigned long long)be64_to_cpu(hi->hdr.owner),
					(long long)bp->b_maps[0].bm_bn, grafted);
		}
	}
out:
	kfree(dsk);
	return ret;
}

/*
 * sess6 (ccloop 46efd8b6) TRIPWIRE (print-only — the v0.10.24 undestage-mark
 * variant was REFUTED by run 110411Z: every differs-fire had pre-mark lseq==
 * wseq==0, i.e. a struct-recycled CLEAN REPUBLISH image that holds no local
 * truth; marking those undestaged made the next tenure's fence re-publish a
 * STALE leaf under a LATER EX — a manufacture site, not a fix).  A skipped
 * image that differs from the LUN while genuinely undestaged (lseq>wseq)
 * would mean a committed-unwritten bmbt update escaped its own tenure's
 * fence — with the bmbt completion barrier (v0.10.25) that must never
 * happen; this print is the proof either way.
 */
static void
mxfs_bmbt_skip_preserve_truth(
	struct xfs_buf		*bp,
	const char		*site)
{
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	uint32_t		len = BBTOB(bp->b_length);
	void			*raw = NULL;
	int			rc = -1, same = -1;

	if ((len & 511) == 0 && len && bp->b_target && bp->b_target->bt_bdev)
		raw = kmalloc(len, GFP_NOFS);
	if (raw) {
		rc = mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
			(uint64_t)bp->b_maps[0].bm_bn +
			bp->b_target->bt_sector_offset, raw, len);
		if (rc == 0)
			same = !memcmp(raw, bp->b_addr, len);
		kfree(raw);
	}
	/*
	 * v0.10.32 (sess7 46efd8b6) RECONCILE — the sess66 gate comment always
	 * promised "stale it so the peer's leaf stands" but the skip arms only
	 * suppressed the bio, leaving a superseded buffer cached forever: the
	 * iflush-hook resubmitted it at ~40Hz (P61/P77 walls flooding dmesg),
	 * the fence saw it undestaged for the rest of the run, and P91 turned
	 * every read of it into a manufactured CRC error (run 154203Z test1,
	 * 12-era leaf vs LUN 16-era, 40+ minutes of ENOENT).  The skip only
	 * fires when the owner dir is NL or the image is prior-tenure — i.e.
	 * the LUN era is the cluster truth and this image can never legally
	 * land.  Resolve it NOW:
	 *   same==1  -> content already on the LUN: certify destaged.
	 *   same==0  -> superseded divergent image: if it carried undestaged
	 *               committed content, that delta is unreconcilable — the
	 *               loss already happened at the missed fence — account it
	 *               loudly (P81) and certify; then STALE the buffer so the
	 *               next access cold-reads the peers' era instead of
	 *               resubmitting/CRC-failing forever.
	 *   same==-1 -> LUN unreadable: leave state untouched (print only).
	 */
	if (same == 1) {
		if (bp->b_mxfs_logged_seq != bp->b_mxfs_written_seq) {
			pr_warn_ratelimited(
				"mxfs: P82-SKIP-ALREADY-ON-LUN site=%s daddr=%lld lseq=%u wseq=%u — undestaged image is byte-identical to LUN; certifying destaged\n",
				site, (long long)bp->b_maps[0].bm_bn,
				bp->b_mxfs_logged_seq, bp->b_mxfs_written_seq);
			bp->b_mxfs_written_seq = bp->b_mxfs_logged_seq;
		}
		return;
	}
	pr_warn("mxfs: P77-SKIP-DIFFERS site=%s owner=%llu daddr=%lld numrecs=%u same=%d lseq=%u wseq=%u undest=%d — skipped bmbt image differs from LUN (undest=1 would mean a committed update escaped the fence)\n",
		site,
		(unsigned long long)be64_to_cpu(((struct xfs_btree_block *)
			bp->b_addr)->bb_u.l.bb_owner),
		(long long)bp->b_maps[0].bm_bn,
		be16_to_cpu(((struct xfs_btree_block *)
			bp->b_addr)->bb_numrecs),
		same, bp->b_mxfs_logged_seq, bp->b_mxfs_written_seq,
		bp->b_mxfs_logged_seq != bp->b_mxfs_written_seq ? 1 : 0);
	if (same == 0) {
		if (bp->b_mxfs_logged_seq != bp->b_mxfs_written_seq) {
			pr_warn("mxfs: P81-BMBT-SUPERSEDED-DROP site=%s owner=%llu daddr=%lld numrecs=%u lseq=%u wseq=%u — committed bmbt delta missed its release fence and a peer era now owns the LUN; dropping local image (delta LOST — fence bug if this fires)\n",
				site,
				(unsigned long long)be64_to_cpu(
					((struct xfs_btree_block *)
					 bp->b_addr)->bb_u.l.bb_owner),
				(long long)bp->b_maps[0].bm_bn,
				be16_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_numrecs),
				bp->b_mxfs_logged_seq, bp->b_mxfs_written_seq);
			bp->b_mxfs_written_seq = bp->b_mxfs_logged_seq;
		}
		xfs_buf_stale(bp);
	}
}

static void
xfs_buf_submit_bio(
	struct xfs_buf		*bp)
{
	unsigned int		len = BBTOB(bp->b_length);
	unsigned int		nr_vecs = bio_add_max_vecs(bp->b_addr, len);
	unsigned int		map = 0;
	struct blk_plug		plug;
	struct bio		*bio;

	/*
	 * sess2 (ccloop a16ec5f2) RULE-4 block watch: mxfs.watch_daddr=<daddr>
	 * logs EVERY xfs_buf bio touching that (envelope-relative) daddr at this
	 * single submit chokepoint — direction, first 8 content bytes (magic),
	 * ops, comm; full stack for WRITES.  Hunting the writer that leaves the
	 * dir LEAF daddr (deterministically 6279744 in the drc_reliability
	 * layout) ALL-ZERO on the platter while release-drain bwrites of real
	 * leaf content at the same daddr return success.  Default 0 = off.
	 */
	{
	extern unsigned long long mxfs_watch_daddr;
	if (unlikely(mxfs_watch_daddr)) {
		int wm;

		for (wm = 0; wm < bp->b_map_count; wm++) {
			if ((xfs_daddr_t)mxfs_watch_daddr >= bp->b_maps[wm].bm_bn &&
			    (xfs_daddr_t)mxfs_watch_daddr < bp->b_maps[wm].bm_bn +
					       bp->b_maps[wm].bm_len) {
				u64 w0 = bp->b_addr ?
					be64_to_cpu(*(__be64 *)bp->b_addr) : 0;

				pr_warn("mxfs: PW-DADDR %s daddr=%lld map%d/%d bn=%lld len=%d first8=0x%016llx ops=%s flags=0x%x bli=0x%x pag=%d bp=%px realns=%llu comm=%s\n",
					(bp->b_flags & XBF_WRITE) ? "WRITE" : "READ",
					(long long)mxfs_watch_daddr, wm,
					bp->b_map_count,
					(long long)bp->b_maps[wm].bm_bn,
					bp->b_maps[wm].bm_len, w0,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					bp->b_flags,
					bp->b_log_item ?
						bp->b_log_item->bli_flags : 0,
					!!bp->b_pag, bp,
					(unsigned long long)ktime_get_real_ns(),
					current->comm);
				/*
				 * sess3 (ccloop a16ec5f2): when the watched
				 * sector sits in an inode-cluster buffer,
				 * decode it as a dinode (the run12 dir dinode
				 * nx=9->1 durable regression hunter).  Track
				 * max nx per di_gen; a WRITE carrying nx below
				 * the max for the same incarnation is the
				 * regression -> stack (ratelimited: legit rm
				 * shrink also lowers nx).
				 */
				if (bp->b_ops == &xfs_inode_buf_ops &&
				    bp->b_addr) {
					unsigned int woff = BBTOB((unsigned int)
						((xfs_daddr_t)mxfs_watch_daddr -
						 bp->b_maps[wm].bm_bn));

					if (woff + sizeof(struct xfs_dinode) <=
					    BBTOB(bp->b_length)) {
						struct xfs_dinode *wd =
							bp->b_addr + woff;
						u32 nx = be32_to_cpu(wd->di_nextents);
						u32 gen = be32_to_cpu(wd->di_gen);
						bool wr = !!(bp->b_flags & XBF_WRITE);
						static u32 pw_gen, pw_maxnx;
						static DEFINE_RATELIMIT_STATE(pw_rs,
							5 * HZ, 4);
						bool regress;

						if (gen != pw_gen) {
							pw_gen = gen;
							pw_maxnx = nx;
						}
						regress = wr && nx < pw_maxnx;
						if (nx > pw_maxnx)
							pw_maxnx = nx;
						pr_warn("mxfs: PW-SLOT %s%s ino=%llu magic=0x%x mode=0%o fmt=%d nlink=%u nx=%u anx=%u size=%lld nblocks=%llu gen=%u nunl=0x%x lsn=0x%llx maxnx=%u bp=%px comm=%s\n",
							wr ? "WRITE" : "READ",
							regress ? " REGRESS" : "",
							(unsigned long long)be64_to_cpu(wd->di_ino),
							be16_to_cpu(wd->di_magic),
							be16_to_cpu(wd->di_mode),
							wd->di_format,
							be32_to_cpu(wd->di_nlink),
							nx,
							be16_to_cpu(wd->di_anextents),
							(long long)be64_to_cpu(wd->di_size),
							(unsigned long long)be64_to_cpu(wd->di_nblocks),
							gen,
							be32_to_cpu(wd->di_next_unlinked),
							(unsigned long long)be64_to_cpu(wd->di_lsn),
							pw_maxnx, bp,
							current->comm);
						if (regress && __ratelimit(&pw_rs))
							dump_stack();
					}
				} else if (bp->b_flags & XBF_WRITE) {
					dump_stack();
				}
				break;
			}
		}
	}
	}

	/*
	 * sess5(ccloop 12e0d157) read-attribution probe (RULE 4).  This is the
	 * single chokepoint where a COLD (cache-missed) buffer read issues a real
	 * bio.  Classify each read so the 32-node dlm_scaling AG0 inode-cluster
	 * storm can be attributed by class + caller without any per-read stack
	 * unwind (which starved the workload under load).  Gated; default off.
	 */
	{
	extern int mxfs_read_attr_probe;
	extern atomic64_t mxfs_rd_ino_real, mxfs_rd_ino_ra, mxfs_rd_dir;
	extern atomic64_t mxfs_rd_agmeta, mxfs_rd_other;

	if (unlikely(mxfs_read_attr_probe) && !(bp->b_flags & XBF_WRITE)) {
		const struct xfs_buf_ops *o = bp->b_ops;
		bool ra = (bp->b_flags & XBF_READ_AHEAD) ||
			  o == &xfs_inode_buf_ra_ops;
		bool ino = (o == &xfs_inode_buf_ops ||
			    o == &xfs_inode_buf_ra_ops);
		long long tot;

		if (ino && ra)
			atomic64_inc(&mxfs_rd_ino_ra);
		else if (ino)
			atomic64_inc(&mxfs_rd_ino_real);
		else if (o == &xfs_dir3_data_buf_ops ||
			 o == &xfs_dir3_block_buf_ops ||
			 o == &xfs_dir3_leaf1_buf_ops ||
			 o == &xfs_dir3_leafn_buf_ops ||
			 o == &xfs_dir3_free_buf_ops)
			atomic64_inc(&mxfs_rd_dir);
		else if (o == &xfs_agf_buf_ops || o == &xfs_agi_buf_ops ||
			 o == &xfs_agfl_buf_ops || o == &xfs_bnobt_buf_ops ||
			 o == &xfs_cntbt_buf_ops || o == &xfs_inobt_buf_ops ||
			 o == &xfs_finobt_buf_ops)
			atomic64_inc(&mxfs_rd_agmeta);
		else
			atomic64_inc(&mxfs_rd_other);

		/* Periodic dump of ALL classes (every 512 cold reads of any kind),
		 * so the dominant class is visible regardless of which it is. */
		tot = atomic64_read(&mxfs_rd_ino_real) +
		      atomic64_read(&mxfs_rd_ino_ra) +
		      atomic64_read(&mxfs_rd_dir) +
		      atomic64_read(&mxfs_rd_agmeta) +
		      atomic64_read(&mxfs_rd_other);
		if ((tot & 511) == 0)
			pr_warn("mxfs: RD-ATTR tot=%lld ino_real=%lld ino_ra=%lld dir=%lld agm=%lld other=%lld comm=%s daddr=%lld ops=%s\n",
				tot,
				(long long)atomic64_read(&mxfs_rd_ino_real),
				(long long)atomic64_read(&mxfs_rd_ino_ra),
				(long long)atomic64_read(&mxfs_rd_dir),
				(long long)atomic64_read(&mxfs_rd_agmeta),
				(long long)atomic64_read(&mxfs_rd_other),
				current->comm, (long long)bp->b_maps[0].bm_bn,
				(o && o->name) ? o->name : "?");
		/* Stack-sample the INODE reads (real+ra) — the AG0 storm — to get
		 * the caller chain; hard ratelimited so it can't starve the load. */
		if (ino) {
			static DEFINE_RATELIMIT_STATE(mxfs_rd_rs, HZ, 1);

			if (__ratelimit(&mxfs_rd_rs))
				dump_stack();
		}
	}
	}

	/*
	 * sess115: write only owned inode sectors of a shared inode cluster so a
	 * stale foreign slot can't revert peer-committed data (false-sharing).
	 */

	/*
	 * sess4(a16ec5f2) INODE-CLUSTER slot-transition ledger (RULE 4).
	 * run22 dangler autopsy: dirent durable + dinode FREE on disk with no
	 * removal ever submitted for the dirent — the missing link is WHICH
	 * cluster write zeroed the slot (and which one allocated it), when,
	 * from whom.  For every inode-cluster write under dirwr, read the
	 * current disk image and log each slot whose di_mode transitions
	 * 0->!0 (IALLOC-WR) or !0->0 (IFREE-WR) along with the slot's di_ino.
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_map_count == 1 &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_ops == &xfs_inode_buf_ops) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
		uint32_t p4c_len = BBTOB(bp->b_length);
		uint64_t p4c_lba = (uint64_t)bp->b_maps[0].bm_bn +
			bp->b_target->bt_sector_offset;
		uint32_t p4c_isz = bp->b_mount->m_sb.sb_inodesize;
		void *p4c_tmp = (p4c_len && (p4c_len & 511) == 0 &&
				 p4c_isz >= 256) ?
			kmalloc(p4c_len, GFP_NOFS) : NULL;

		if (p4c_tmp && mxfs_pal_bdev_read_plain_bdev(
			    bp->b_target->bt_bdev, p4c_lba, p4c_tmp,
			    p4c_len) == 0) {
			uint32_t off;
			static atomic_t p4c_n = ATOMIC_INIT(0);

			for (off = 0; off + p4c_isz <= p4c_len;
			     off += p4c_isz) {
				struct xfs_dinode *db = p4c_tmp + off;
				struct xfs_dinode *bb = bp->b_addr + off;
				uint16_t dmode, bmode;

				if (be16_to_cpu(db->di_magic) !=
					XFS_DINODE_MAGIC ||
				    be16_to_cpu(bb->di_magic) !=
					XFS_DINODE_MAGIC)
					continue;
				dmode = be16_to_cpu(db->di_mode);
				bmode = be16_to_cpu(bb->di_mode);
				if ((dmode == 0) == (bmode == 0))
					continue;
				if (atomic_inc_return(&p4c_n) > 200000)
					break;
				pr_warn("mxfs: %s daddr=%lld slot=%u ino=%llu dmode=0%o bmode=0%o dgen=%u bgen=%u comm=%s realns=%llu\n",
					bmode ? "P4C-IALLOC-WR" :
						"P4C-IFREE-WR",
					(long long)bp->b_maps[0].bm_bn,
					off / p4c_isz,
					(unsigned long long)be64_to_cpu(
						bb->di_ino),
					dmode, bmode,
					be32_to_cpu(db->di_gen),
					be32_to_cpu(bb->di_gen),
					current->comm,
					(unsigned long long)ktime_get_real_ns());
			}
		}
		if (p4c_tmp)
			kfree(p4c_tmp);
	}

	if (mxfs_submit_partial_inode_write(bp))
		return;

	/*
	 * sess40 (ccloop, GPT-5.5 WRITEBACK-COMPLETION-BARRIER) — count this
	 * directory-metadata write bio as in-flight so the dir EX release fence
	 * (xfs_mxfs_dlm.c) can wait for it to PHYSICALLY COMPLETE before handing
	 * the dir DLM lock to a peer.  ROOT (PROVEN, RULE 4 + GPT-5.5): a dir
	 * DATA/leaf write bio submitted in a PRIOR EX tenure can land AFTER the
	 * next holder cold-read + RMW'd + re-wrote that block, durably reverting a
	 * just-committed dirent (dir_reuse readdir=799 single-entry loss, then a
	 * cascade to DABUF_MAP_HOLE).  The submit-time disk-superset detector is
	 * structurally BLIND to it (at the stale write's submit disk lacked the
	 * entry; it only clobbers at COMPLETION).  The release fence's
	 * "disk==incore at sample instant" probe is likewise blind to an
	 * already-submitted bio that completes late.  The fix is the canonical
	 * clustered-FS invariant (GFS2 glock / OCFS2 / CXFS token): the EX tenure
	 * owns the writeback LIFETIME — no prior-tenure metadata write may still
	 * be capable of landing once the lock is handed off.  Counted once per
	 * buffer; __xfs_buf_ioend decrements when the I/O completes.
	 */
	/*
	 * sess9 (ccloop a864) LEAK NEUTRALIZER (RULE 4, run 160833Z r10+):
	 * if b_mxfs_dir_wr_counted is STILL true here, this buffer is being
	 * re-submitted while its previous counted write never decremented
	 * (a mis-routed completion — the wedge#2 double-submit family).  The
	 * old unconditional reset ERASED that pending count's marker and the
	 * inc below then double-counted → m_mxfs_dir_wr_inflight leaked +1
	 * PERMANENTLY → every subsequent dir EX release paid the full 2×10s
	 * wr-barrier bound (P51-REL drain_ms=20013/20022/20007, three in a
	 * row on rank1) → the 32-node dir convoy froze 30s+ → waiters blew
	 * their 120s acquire budget → rc=-110 shutdowns (r13 collapse,
	 * 27 nodes run 150528Z; 1 node run 160833Z).  Keep the EXISTING
	 * count: this submit's completion will decrement it exactly once.
	 */
	if (unlikely(bp->b_mxfs_dir_wr_counted)) {
		unsigned int wrevi = bp->b_mxfs_evi;

		pr_warn_ratelimited(
		    "mxfs: P-WRCNT-RESUBMIT daddr=%lld ops=%s flags=0x%x inflight=%d evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx] — counted write resubmitted before its completion decremented; keeping single count (leak neutralized)\n",
		    (long long)bp->b_maps[0].bm_bn,
		    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
		    (unsigned int)bp->b_flags,
		    bp->b_mount ?
			atomic_read(&bp->b_mount->m_mxfs_dir_wr_inflight) : -1,
		    wrevi,
		    bp->b_mxfs_evring[(wrevi + 0) & 7],
		    bp->b_mxfs_evring[(wrevi + 1) & 7],
		    bp->b_mxfs_evring[(wrevi + 2) & 7],
		    bp->b_mxfs_evring[(wrevi + 3) & 7],
		    bp->b_mxfs_evring[(wrevi + 4) & 7],
		    bp->b_mxfs_evring[(wrevi + 5) & 7],
		    bp->b_mxfs_evring[(wrevi + 6) & 7],
		    bp->b_mxfs_evring[(wrevi + 7) & 7]);
	} else if ((bp->b_flags & XBF_WRITE) && bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     bp->b_ops == &xfs_dir3_free_buf_ops ||
	     bp->b_ops == &xfs_da3_node_buf_ops ||
	     /* sess6 (46efd8b6) RULE-4 PROVEN (run 110411Z): bmbt writes are
	      * xfsaild-ASYNC on multipath (SCSI FUA passthrough EOPNOTSUPP →
	      * plain bio), so a committed bmbt-leaf bio can still be in
	      * flight at the dir EX handoff and land AFTER the peer's iread
	      * cold-read — the peer's iext then time-travels vs the leaf
	      * everyone later reads (xfs_bmap_del_extent_real i!=1).  Count
	      * bmbt writes into the same completion barrier the dir data/
	      * leaf blocks use; the release fence waits for zero in-flight
	      * before the DLM unlock. */
	     bp->b_ops == &xfs_bmbt_buf_ops)) {
		atomic_inc(&bp->b_mount->m_mxfs_dir_wr_inflight);
		bp->b_mxfs_dir_wr_counted = true;
	}

	/*
	 * sess40 (ccloop) COUNT-REGRESSION detector (always-on, ratelimited) — the
	 * sharp probe for the silent dir_reuse readdir=799 lost-update.  dataclobber
	 * compares a dir-DATA write to the DISK image at submit and is SILENT for
	 * this loss (the clobbering write happens when disk ALSO lacks the entry).
	 * This instead compares to `b_mxfs_dir_wrcnt_max` = the highest active-dirent
	 * count THIS buffer has ever written.  A write whose count is BELOW that
	 * high-water mark means this node is destaging a block image that LOST
	 * entries it previously held — i.e. it RMW'd a STALE base (the lost-update),
	 * regardless of what disk currently shows.  Logs comm + real EX-held + txn
	 * context so we can tell an active modify (legit remove) from a background
	 * xfsaild reflush (the clobber).  In-core only, no I/O.  (A legitimate
	 * multi-dirent remove also regresses count — but the dir_reuse workload only
	 * ADDS within a round, so any regression there is the bug; comm/in_txn
	 * disambiguate.)
	 */
	{
		bool cr_data = (bp->b_ops == &xfs_dir3_data_buf_ops ||
				bp->b_ops == &xfs_dir3_block_buf_ops);
		if (cr_data && (bp->b_flags & XBF_WRITE) && bp->b_addr &&
		    bp->b_map_count == 1 && bp->b_mount && bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm)) {
			bool cr_blk = (bp->b_ops == &xfs_dir3_block_buf_ops);
			uint32_t cr_s = 0, cr_x = 0;
			uint32_t cr_cnt = mxfs_dir3_data_fingerprint(
				bp->b_mount, bp->b_addr, BBTOB(bp->b_length),
				cr_blk, &cr_s, &cr_x);
			if (cr_cnt < bp->b_mxfs_dir_wrcnt_max) {
				uint64_t cr_owner = be64_to_cpu(
					((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner);
				int cr_held = mxfs_v5_dlm_inode_held_rawmode(
					bp->b_mount->m_mxfs_dlm, cr_owner);
				pr_warn_ratelimited(
					"mxfs: P-COUNTREGRESS owner=%llu daddr=%lld cnt=%u prev_max=%u real_mode=%d in_txn=%d in_ail=%d comm=%s — dir-data write LOST entries vs this buffer's own high-water (stale-base RMW = the silent readdir=799 lost-update)\n",
					(unsigned long long)cr_owner,
					(long long)bp->b_maps[0].bm_bn,
					cr_cnt, bp->b_mxfs_dir_wrcnt_max, cr_held,
					current->journal_info ? 1 : 0,
					(bp->b_log_item && test_bit(XFS_LI_IN_AIL,
						&bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
					current->comm);
			} else if (cr_cnt > bp->b_mxfs_dir_wrcnt_max) {
				bp->b_mxfs_dir_wrcnt_max = cr_cnt;
			}
		}
	}

	/* sess60 RULE-4: log every bmbt-leaf WRITE (numrecs + owner hold state)
	 * to catch the node writing a stale leaf over a peer's durable one. */
	mxfs_bmbt_write_probe(bp);

	/* sess28 DIAGNOSTIC: classify dir-DATA writes as MERGE-needed vs pure-stale
	 * to decide the write-side fix (merge vs suppress).  Gated dir_writeprobe. */
	{
		extern int mxfs_dir_writeprobe;
		bool wp_data = bp->b_ops == &xfs_dir3_data_buf_ops ||
			       bp->b_ops == &xfs_dir3_block_buf_ops;
		if (mxfs_dir_writeprobe && wp_data && (bp->b_flags & XBF_WRITE) &&
		    bp->b_addr && bp->b_map_count == 1 && bp->b_mount &&
		    bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
		    bp->b_target && bp->b_target->bt_bdev) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *, uint32_t);
			uint32_t wlen = BBTOB(bp->b_length);
			void *dsk = (wlen && !(wlen & 511)) ?
				kmalloc(wlen, GFP_NOFS) : NULL;
			if (dsk) {
				uint64_t wlba = (uint64_t)bp->b_maps[0].bm_bn +
					bp->b_target->bt_sector_offset;
				if (mxfs_pal_bdev_read_plain_bdev(
					    bp->b_target->bt_bdev, wlba,
					    dsk, wlen) == 0) {
					bool icbf = bp->b_ops ==
						&xfs_dir3_block_buf_ops;
					bool dkbf = ((struct xfs_dir3_blk_hdr *)
						dsk)->magic == cpu_to_be32(
						XFS_DIR3_BLOCK_MAGIC);
					int disk_extra = mxfs_dir3_disk_has_extra_inum(
						bp->b_mount, bp->b_addr, dsk,
						wlen, icbf, dkbf);
					int incore_extra = mxfs_dir3_disk_has_extra_inum(
						bp->b_mount, dsk, bp->b_addr,
						wlen, dkbf, icbf);
					if (disk_extra > 0) {
						static atomic_t wp = ATOMIC_INIT(0);
						uint64_t wowner = be64_to_cpu(
							((struct xfs_dir3_blk_hdr *)
							bp->b_addr)->owner);
						int wmode = mxfs_v5_dlm_inode_held_rawmode(
							bp->b_mount->m_mxfs_dlm, wowner);
						struct xfs_buf_log_item *wbli = bp->b_log_item;
						int wail = wbli && test_bit(XFS_LI_IN_AIL,
							&wbli->bli_item.li_flags);
						int wdirty = wbli && test_bit(XFS_LI_DIRTY,
							&wbli->bli_item.li_flags);
						/* sess33 P-WGHOST: is bp the canonical
						 * rhashtable buffer for this daddr, or a
						 * stale ghost (mechanism B)? */
						struct xfs_buf *wcanon =
							mxfs_dir_canonical_buf_ptr(
								bp->b_target,
								bp->b_maps[0].bm_bn,
								bp->b_length);
						if (incore_extra > 0 && wcanon != bp) {
							static atomic_t wg = ATOMIC_INIT(0);
							if (atomic_inc_return(&wg) <= 200)
								pr_warn("mxfs: P-WGHOST daddr=%lld destage_bp=%px canon_bp=%px GHOST(destaging non-canonical stale buffer over peer add) disk_extra=%d incore_extra=%d held_mode=%d\n",
									(long long)bp->b_maps[0].bm_bn,
									bp, wcanon,
									disk_extra, incore_extra,
									wmode);
						}
						/* sess33: capture the call stack of the
						 * loss-write to identify the exact write
						 * path (delwri_submit vs release-drain vs
						 * direct bwrite).  Capped to 4. */
						if (incore_extra > 0) {
							static atomic_t wst = ATOMIC_INIT(0);
							if (atomic_inc_return(&wst) <= 4) {
								pr_warn("mxfs: P-WMERGE-STACK daddr=%lld comm=%s — stack of the loss-write:\n",
									(long long)bp->b_maps[0].bm_bn,
									current->comm);
								dump_stack();
							}
						}
						if (atomic_inc_return(&wp) <= 300)
							pr_warn("mxfs: P-WMERGE owner=%llu daddr=%lld disk_extra=%d incore_extra=%d held_mode=%d in_ail=%d dirty=%d bgen=%u DONE=%d fua_fresh=%d delwri=%d bp=%px lseq=%u wseq=%u pin=%d comm=%s kind=%s — %s\n",
								(unsigned long long)wowner,
								(long long)bp->b_maps[0].bm_bn,
								disk_extra, incore_extra,
								wmode, wail, wdirty,
								bp->b_mxfs_dir_gen,
								!!(bp->b_flags & XBF_DONE),
								!!(bp->b_flags & _XBF_FUA_FRESH),
								!!(bp->b_flags & _XBF_DELWRI_Q),
								bp,
								bp->b_mxfs_logged_seq,
								bp->b_mxfs_written_seq,
								atomic_read(&bp->b_pin_count),
								current->comm,
								icbf ? "block" : "data",
								incore_extra > 0 ?
								"MERGE-NEEDED" :
								"pure-stale");
					}
				}
				kfree(dsk);
			}
		}
	}

	/*
	 * sess2(ccloop 26c41354) P-REINTRO — the reintroduce-direction guard for
	 * the 16-node durable dangling-dirent (CASE B, PROVEN: release drain is
	 * correct, a post-release async write reintroduces the removed dirent).
	 *
	 * A stale prior-tenure dir DATA/BLOCK image (dc_stale: b_mxfs_dir_gen < the
	 * dir's current i_dlm_dir_gen) carries an EXTRA dirent whose inum is absent
	 * on the current disk AND whose on-disk inode is FREE -> writing it
	 * reintroduces a removed dirent -> P26-IGET-FAIL.  The existing P26/P39/P12
	 * arms only defend the opposite (disk-superset) direction and explicitly
	 * treat any in-core-extra as legit "MERGE-NEEDED" (sess28) — which is wrong
	 * when the extra dirent points at a FREED inode.  Gate the disk read on
	 * dc_stale so the common path (current-tenure writes: bgen==dir_gen) pays
	 * nothing; the per-extra-inum FUA read runs only on the rare stale path
	 * (RULE 0 unaffected).
	 *   mxfs_dir_reintro_probe=1 : LOG candidates (measure, RULE 4 step 2).
	 *   mxfs_dir_reintro_skip=1  : DROP the write + mark for re-read when the
	 *                              image is a clean superseded zombie (in-AIL,
	 *                              !dirty, !pinned, !undestaged, same-incarn)
	 *                              and ALL its in-core-extra dirents are free
	 *                              reintroduces (live_extra==0 => no legit add
	 *                              is ever dropped).
	 */
	{
		extern int mxfs_dir_reintro_probe, mxfs_dir_reintro_skip;
		extern int mxfs_dir_reintro_trim;
		bool ri_data = bp->b_ops == &xfs_dir3_data_buf_ops ||
			       bp->b_ops == &xfs_dir3_block_buf_ops;

		if ((mxfs_dir_reintro_probe || mxfs_dir_reintro_skip ||
		     mxfs_dir_reintro_trim) &&
		    ri_data && (bp->b_flags & XBF_WRITE) && bp->b_addr &&
		    bp->b_map_count == 1 && bp->b_mount &&
		    bp->b_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
		    bp->b_target && bp->b_target->bt_bdev) {
			struct mxfs_dir_skip_info rdsi;
			bool ri_stale, ri_same_incarn;

			memset(&rdsi, 0, sizeof(rdsi));
			(void)mxfs_buf_xfsaild_skip_dir_write(bp, &rdsi);
			/* dc_stale: prior-tenure image (the only kind that can carry
			 * a reintroduce); a current-tenure modify re-read fresh so
			 * bgen==dir_gen and is never considered; bgen==0 excluded. */
			ri_stale = rdsi.in_core && rdsi.dir_gen != 0 &&
				   bp->b_mxfs_dir_gen < rdsi.dir_gen;
			ri_same_incarn = rdsi.buf_incarn != 0 &&
					 rdsi.buf_incarn == rdsi.cur_incarn;

			if (ri_stale) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t rlen = BBTOB(bp->b_length);
				void *rdsk = (rlen && !(rlen & 511)) ?
					kmalloc(rlen, GFP_NOFS) : NULL;

				if (rdsk) {
					uint64_t rlba = (uint64_t)bp->b_maps[0].bm_bn +
						bp->b_target->bt_sector_offset;

					if (mxfs_pal_bdev_read_plain_bdev(
						bp->b_target->bt_bdev, rlba,
						rdsk, rlen) == 0) {
						bool icbf = bp->b_ops ==
							&xfs_dir3_block_buf_ops;
						bool dkbf = ((struct xfs_dir3_blk_hdr *)
							rdsk)->magic == cpu_to_be32(
							XFS_DIR3_BLOCK_MAGIC);
						uint64_t downer = be64_to_cpu(
							((struct xfs_dir3_blk_hdr *)
							rdsk)->owner);
						uint64_t bowner = be64_to_cpu(
							((struct xfs_dir3_blk_hdr *)
							bp->b_addr)->owner);
						int live_extra = 0;
						uint64_t fino = 0;
						char fname[MAXNAMELEN + 1] = {0};
						int fnl = 0;
						int free_reintro = 0;

						/* only a valid same-owner disk dir block is
						 * a safe comparison base */
						if (downer == bowner)
							free_reintro =
							  mxfs_dir3_reintro_free_count(
							    bp->b_mount, bp->b_addr,
							    rdsk, rlen, icbf, dkbf,
							    &live_extra, &fino,
							    fname, &fnl,
							    /*
							     * ccloop cc87fed3 sess9 (RULE 4,
							     * PROVEN by a live durable CRC
							     * corruption -- P-DIRCRC-RETRY-FAIL
							     * daddr=539288 "err=-74 durable, not
							     * transient" traced directly to a
							     * P-REINTRO-TRIM on that exact
							     * daddr): BLOCK format
							     * (xfs_dir3_block_buf_ops) has a
							     * TRAILING LEAF-ENTRY array (hash->
							     * offset) that must stay in sync with
							     * the data entries; trimming only the
							     * data entry leaves a dangling leaf
							     * entry pointing at a now-free slot --
							     * structural corruption.
							     * mxfs_dir3_data_writemerge (the
							     * proven ADD-direction sibling doing
							     * the exact same class of byte-level
							     * entry surgery) EXPLICITLY excludes
							     * block format for this reason (gates
							     * on bp->b_ops ==
							     * xfs_dir3_data_buf_ops only). Match
							     * that precedent: trim ONLY the
							     * separate-leaf DATA format (icbf
							     * false), never block format.
							     */
							    mxfs_dir_reintro_trim != 0 &&
							    !icbf);

						/*
						 * ccloop cc87fed3 sess9: the trimmed entries
						 * are gone from b_addr but bestfree/CRC are
						 * not yet consistent -- freescan rebuilds
						 * bestfree (same as the graft path); the
						 * verifier (called by the caller AFTER this
						 * chokepoint, xfs_buf_verify_write) stamps
						 * the CRC over the corrected image.
						 * live_extra entries were never touched
						 * (mxfs_dir3_reintro_free_count only trims
						 * the proven-free set), so this is safe
						 * regardless of live_extra.
						 */
						if (mxfs_dir_reintro_trim && free_reintro > 0) {
							int trim_loghead = 0;

							xfs_dir2_data_freescan(
							    bp->b_mount,
							    (struct xfs_dir2_data_hdr *)
							    bp->b_addr,
							    &trim_loghead);
							pr_warn_ratelimited(
				"mxfs: P-REINTRO-TRIM owner=%llu daddr=%lld trimmed=%d first_ino=%llu first_name=%s — surgically removed proven-freed-inode dirent(s) in place, write proceeds\n",
								(unsigned long long)bowner,
								(long long)bp->b_maps[0].bm_bn,
								free_reintro,
								(unsigned long long)fino,
								fname[0] ? fname : "?");
						}

						if (free_reintro > 0 ||
						    (mxfs_dir_reintro_probe &&
						     live_extra > 0)) {
							struct xfs_buf_log_item *rbli =
								bp->b_log_item;
							int rail = rbli && test_bit(
								XFS_LI_IN_AIL,
								&rbli->bli_item.li_flags);
							int rdirty = rbli && test_bit(
								XFS_LI_DIRTY,
								&rbli->bli_item.li_flags);
							int rundest =
							  mxfs_dir_buf_is_undestaged(bp);

							pr_warn_ratelimited(
				"mxfs: P-REINTRO owner=%llu daddr=%lld free_reintro=%d live_extra=%d first_free_ino=%llu first_name=%s bgen=%u dirgen=%u same_incarn=%d mode=%d in_ail=%d dirty=%d pin=%d undest=%d done=%d fua_fresh=%d comm=%s — %s\n",
								(unsigned long long)bowner,
								(long long)bp->b_maps[0].bm_bn,
								free_reintro, live_extra,
								(unsigned long long)fino,
								fname[0] ? fname : "?",
								bp->b_mxfs_dir_gen,
								rdsi.dir_gen,
								ri_same_incarn, rdsi.mode,
								rail, rdirty,
								atomic_read(&bp->b_pin_count),
								rundest,
								!!(bp->b_flags & XBF_DONE),
								!!(bp->b_flags & _XBF_FUA_FRESH),
								current->comm,
								(free_reintro > 0 && live_extra == 0) ?
								"PURE-REINTRO" :
								(free_reintro > 0) ? "MIXED" :
								"live-only");

							/* ENFORCE: only a clean superseded
							 * zombie whose in-core-extra is PURELY
							 * free reintroduces (no live add) is
							 * dropped.  Mark for re-read so the next
							 * access cold-fetches the peer's durable
							 * (removed) image (P26/P39 completion). */
							if (mxfs_dir_reintro_skip &&
							    free_reintro > 0 &&
							    live_extra == 0 &&
							    ri_same_incarn &&
							    rail && !rdirty &&
							    atomic_read(&bp->b_pin_count) == 0 &&
							    !rundest) {
								pr_warn_ratelimited(
				"mxfs: P-REINTRO-SKIP owner=%llu daddr=%lld free_reintro=%d ino=%llu name=%s — dropped stale zombie reintroducing a removed dirent to a freed inode; marked for re-read\n",
									(unsigned long long)bowner,
									(long long)bp->b_maps[0].bm_bn,
									free_reintro,
									(unsigned long long)fino,
									fname[0] ? fname : "?");
								bp->b_mxfs_dir_gen = 0;
								bp->b_flags &= ~_XBF_FUA_FRESH;
								bp->b_flags |= XBF_DONE;
								kfree(rdsk);
								bp->b_error = 0;
								xfs_buf_ioend(bp);
								return;
							}
						}
					}
					kfree(rdsk);
				}
			}
		}
	}

	/*
	 * sess61 RULE-4 FIX (PROVEN by P60-BMBTWRITE: a node wrote the shared
	 * dir's bmbt leaf with i_dlm_mode==0/NL — owner=131 numrecs=20 mode=0).
	 * The iop_push guard (mxfs_buf_xfsaild_skip_bmbt_write at
	 * xfs_buf_item.c) samples i_dlm_mode at delwri-QUEUE time, but the
	 * buffer is actually submitted later from xfsaild's buffer_list: if the
	 * dir's per-inode grant was released (EX->NL) in that window the stale
	 * prior-tenure leaf still reaches disk and reverts a peer's newer leaf
	 * records -> the reloader trips `ir.loaded != if_nextents` -> shutdown
	 * -> the zsl silent-loss cascade.  Re-check the SAME predicate HERE, at
	 * the single bio chokepoint (i_dlm_mode sampled at submit time), so an
	 * NL-released bmbt leaf write is never issued.  The release drain
	 * (Invariant #1, while EX) already made every legitimate this-node leaf
	 * change durable, so this write is a superseded redundant image; emulate
	 * a clean completion (no bio) so xfsaild advances and the peer's leaf
	 * stands.  EX/PR-held dirs, regular files, and single-node mounts all
	 * fall through to the normal submit (predicate false).
	 */
	if (mxfs_buf_xfsaild_skip_bmbt_write(bp)) {
		/* sess6 (46efd8b6) tripwire — see mxfs_bmbt_skip_preserve_truth. */
		mxfs_bmbt_skip_preserve_truth(bp, "chokepoint");
		/* sess6 (46efd8b6): this write was counted into the completion
		 * barrier above, but no bio will be issued — uncount HERE so
		 * the emulated xfs_buf_ioend below neither double-decrements
		 * nor (counted-gated) stamps written_seq: a skip-emulated
		 * completion must never certify a genuinely-logged image
		 * "destaged" (the LUN never saw it); it stays undestaged and
		 * the release fence (mxfs_dir_bmbt_scan undestaged arm) lands
		 * it under the lock.  A clean republish (lseq==wseq) is
		 * unaffected. */
		if (bp->b_mxfs_dir_wr_counted) {
			bp->b_mxfs_dir_wr_counted = false;
			mxfs_dir_wr_inflight_dec(bp, "chokepoint-skip");
		}
		pr_warn_ratelimited(
			"mxfs: P61-CHOKEPOINT-SKIP-BMBT owner=%llu daddr=%lld numrecs=%u — NL-released dir, skipping stale leaf write at bio submit\n",
			(unsigned long long)be64_to_cpu(((struct xfs_btree_block *)
				bp->b_addr)->bb_u.l.bb_owner),
			(long long)bp->b_maps[0].bm_bn,
			be16_to_cpu(((struct xfs_btree_block *)
				bp->b_addr)->bb_numrecs));
		bp->b_error = 0;
		/* sess6 (46efd8b6) RULE-4 PROVEN (run 122308Z test7
		 * ir.loaded=23 vs nx=32): do NOT set XBF_DONE here.  A write
		 * buffer normally already has it, but if the reload's bmbt
		 * evict just INVALIDATED this buffer (cleared XBF_DONE so the
		 * next read cold-fetches the peer's leaf), re-marking it DONE
		 * resurrects the stale prior-tenure image with NO read — the
		 * acquire-side iread then cache-hits 23 stale records against
		 * an adopted nx=32 dinode -> EFSCORRUPTED op failures.
		 * Emulate the completion without touching content validity. */
		xfs_buf_ioend(bp);
		return;
	}

	/*
	 * sess17 (ccloop) FIX for 2/tcp crash_consistency.  Dirent analogue of
	 * the P61 bmbt chokepoint skip above.  PROVEN vector (sess16
	 * P35E-DIRWR): after this node releases a dir's EX grant, a stale
	 * lingering dir DATA/leaf BLI (li_empty=1,in_ail=1) is re-flushed by
	 * xfsaild over the (often reused) daddr a peer already made durable ->
	 * the peer's dirents are durably lost.  Suppress an xfsaild write of a
	 * dir DATA/leaf/block/free/node buffer whose owner dir is NL-released
	 * (release drain already made our changes durable) or whose modify-time
	 * tenure stamp is from a prior EX epoch (superseded).  Detector
	 * (P16-DIRBLK-SUBMIT) logs the predicate state for EVERY dir-block write
	 * (gated by dirwr/instr) so the suppression is provable (RULE 4);
	 * enforce gated by mxfs.dirskip (default on).  EX/PR-held this-tenure
	 * dirs, regular files, owners not in cache, and single-node mounts all
	 * fall through to the normal submit.
	 */
	{
		extern int mxfs_dirskip_enabled;
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		struct mxfs_dir_skip_info dsi;
		bool dir_skip = mxfs_buf_xfsaild_skip_dir_write(bp, &dsi);

		/*
		 * sess3(a9a03929) RULE-4 lineage probe (always-on, capped):
		 * EVERY write submit of a low-ino (shared test dir) dir buffer.
		 * run62's cluster kill was a dir data block (daddr 0x3fe1c70)
		 * with CRC-garbage platter content and NO visible write lineage
		 * — this decides never-submitted vs written-then-clobbered for
		 * the next occurrence.  Pairs with P3B-UNLOCK-UNDESTAGED.
		 */
		if (dsi.is_dir_buf && dsi.owner <= 256 &&
		    (bp->b_flags & XBF_WRITE)) {
			static atomic_t p3w_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p3w_n) <= 6000)
				pr_warn("mxfs: P3W-DIRWR owner=%llu daddr=%lld ops=%s lseq=%llu wseq=%llu pin=%d in_ail=%d dirty=%d skip=%d comm=%s realns=%llu\n",
					(unsigned long long)dsi.owner,
					(long long)bp->b_maps[0].bm_bn,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					(unsigned long long)bp->b_mxfs_logged_seq,
					(unsigned long long)bp->b_mxfs_written_seq,
					xfs_buf_ispinned(bp) ? 1 : 0,
					(bp->b_log_item && test_bit(XFS_LI_IN_AIL,
						&bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
					(bp->b_log_item && test_bit(XFS_LI_DIRTY,
						&bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
					dir_skip ? 1 : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}

		if (dsi.is_dir_buf &&
		    unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			pr_warn_ratelimited(
				"mxfs: P16-DIRBLK-SUBMIT owner=%llu daddr=%lld ops=%s in_core=%d mode=%d tenure=%llu epoch=%llu nl=%d tmism=%d aba=%d bincarn=%u cincarn=%u dgen=%u lgen=%u bgen=%u pmp=%d would_skip=%d enforce=%d comm=%s\n",
				(unsigned long long)dsi.owner,
				(long long)bp->b_maps[0].bm_bn,
				bp->b_ops && bp->b_ops->name ?
					bp->b_ops->name : "?",
				dsi.in_core, dsi.mode,
				(unsigned long long)dsi.tenure_id,
				(unsigned long long)dsi.cur_epoch,
				dsi.nl_released, dsi.tenure_mismatch,
				dsi.incarn_aba, dsi.buf_incarn, dsi.cur_incarn,
				dsi.dir_gen, dsi.loaded_gen, bp->b_mxfs_dir_gen,
				(int)(dsi.dir_gen > dsi.loaded_gen),
				dir_skip, mxfs_dirskip_enabled,
				current->comm);

		/*
		 * sess48 decisive write-ordering trace (uncapped-but-bounded,
		 * gated by dirwr): every dir-block write submit with its ACTIVE
		 * dirent count + wall-clock realns + skip decision.  Merge both
		 * nodes' P-WRACT by realns to see who durably writes the stale
		 * base (peer's already-deleted dirents still present) and when.
		 */
		if (dsi.is_dir_buf && dsi.active_count >= 0 &&
		    unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			static atomic_t pwract = ATOMIC_INIT(0);
			if (atomic_inc_return(&pwract) <= 2000000)
				pr_warn("mxfs: P-WRACT owner=%llu daddr=%lld act=%d mode=%d nl=%d would_skip=%d realns=%llu comm=%s\n",
					(unsigned long long)dsi.owner,
					(long long)bp->b_maps[0].bm_bn,
					dsi.active_count, dsi.mode,
					dsi.nl_released, dir_skip,
					(unsigned long long)dsi.realns,
					current->comm);
		}

		/*
		 * sess50(ccloop) RULE-4 content-history trace (WRITE side): count of the
		 * dir DATA/BLOCK image being SUBMITTED to disk, with FUA-fresh + wall-clock.
		 * Merge by realns with P50-RD (read-completion) to reconstruct daddr-120's
		 * count timeline and find the BACKWARD step.  Covers DATA format (P-WRACT
		 * only computes count for BLOCK format, but daddr 120 of a multi-block dir
		 * is DATA format).  dirwr-gated.
		 */
		if (dsi.is_dir_buf && bp->b_addr && bp->b_map_count == 1 &&
		    (bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_block_buf_ops) &&
		    unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			extern uint32_t mxfs_dir3_data_fingerprint(struct xfs_mount *,
				const void *, uint32_t, bool, uint32_t *, uint32_t *);
			bool isblk = (bp->b_ops == &xfs_dir3_block_buf_ops);
			uint32_t s = 0, x = 0;
			uint32_t cnt = mxfs_dir3_data_fingerprint(bp->b_mount,
					bp->b_addr, BBTOB(bp->b_length), isblk, &s, &x);
			pr_warn("mxfs: P50-WR owner=%llu daddr=%lld cnt=%u sum=%u incarn=%u fua_fresh=%d bdirty=%d in_ail=%d realns=%llu comm=%s\n",
				(unsigned long long)dsi.owner,
				(long long)bp->b_maps[0].bm_bn, cnt, s,
				bp->b_mxfs_dir_incarn,
				(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
				(bp->b_log_item && test_bit(XFS_LI_DIRTY,
					&bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
				(bp->b_log_item && test_bit(XFS_LI_IN_AIL,
					&bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
				(unsigned long long)ktime_get_real_ns(),
				current->comm);
		}

		/*
		 * sess40: always-on (ratelimited) record when the ABA dead-
		 * incarnation skip actually suppresses a write — so the fix is
		 * provable in a production (dirwr=0) run, like the P-CLMERGE marker.
		 */
		if (dsi.incarn_aba && dir_skip && mxfs_dirskip_enabled)
			pr_warn_ratelimited(
				"mxfs: P40-INCARN-ABA-DIRSKIP owner=%llu daddr=%lld ops=%s bincarn=%u cincarn=%u mode=%d comm=%s — suppressed xfsaild flush of DEAD prior-incarnation dir block\n",
				(unsigned long long)dsi.owner,
				(long long)bp->b_maps[0].bm_bn,
				bp->b_ops && bp->b_ops->name ?
					bp->b_ops->name : "?",
				dsi.buf_incarn, dsi.cur_incarn, dsi.mode,
				current->comm);

		/*
		 * sess33: always-on (ratelimited) record when the EX-held
		 * already-destaged clean-dir-buffer reflush skip suppresses a
		 * write — provable in a production (dirwr=0) run.
		 */
		/*
		 * sess33: the reflush-skip arm enforces under its OWN param
		 * (dir_reflush_skip), independent of the refuted mxfs_dirskip
		 * gate (the other arms — NL-released, incarn-aba — stay gated by
		 * dirskip).  The arm is keyed on !XBF_DONE (coherency-invalidated
		 * zombie BLI) so it never drops a legit DONE=1 write.
		 */
		{
			extern int mxfs_dir_reflush_skip;
			extern int mxfs_dir_tenure_reflush_skip;
			bool reflush_enf = dsi.reflush_skip && dir_skip &&
					   mxfs_dir_reflush_skip;
			/*
			 * sess37: the tenure-gen zombie-reflush skip (synthesis of
			 * sess33 mechanism + sess41 bgen<dir_gen discriminator).
			 * Enforces under its OWN param, independent of the refuted
			 * mxfs_dirskip gate.  Always-on (ratelimited) marker so the
			 * fix is provable in a production run.
			 */
			bool tenure_enf = dsi.tenure_reflush && dir_skip &&
					  mxfs_dir_tenure_reflush_skip;
			/*
			 * sess50: the PROVEN cross-node release-epoch gate.  Enforces
			 * under its OWN param (default ON).  Always-on marker so the fix
			 * is provable in a production (dirwr=0) run.  Mark the buffer for
			 * re-read (gen=0 + drop FUA-fresh) so the next access cold-fetches
			 * the peer's durable image instead of serving this stale one.
			 */
			extern int mxfs_dir_relepoch_skip;
			bool relepoch_enf = dsi.relepoch_skip && dir_skip &&
					    mxfs_dir_relepoch_skip;

			if (relepoch_enf)
				pr_warn_ratelimited(
					"mxfs: P50-RELEPOCH-SKIP owner=%llu daddr=%lld ops=%s mode=%d comm=%s — skipped reflush of CLEAN pre-release stale dir buffer (relepoch<i_dlm_epoch; peer superseded on LUN)\n",
					(unsigned long long)dsi.owner,
					(long long)bp->b_maps[0].bm_bn,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					dsi.mode, current->comm);

			if (reflush_enf)
				pr_warn_ratelimited(
					"mxfs: P33-REFLUSH-SKIP owner=%llu daddr=%lld ops=%s mode=%d dgen=%u comm=%s — retired zombie BLI (DONE=0 clean destaged in_ail) instead of reflushing stale dir buffer (EX-held)\n",
					(unsigned long long)dsi.owner,
					(long long)bp->b_maps[0].bm_bn,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					dsi.mode, dsi.dir_gen, current->comm);

			if (tenure_enf)
				pr_warn_ratelimited(
					"mxfs: P37-TENURE-REFLUSH-SKIP owner=%llu daddr=%lld ops=%s mode=%d bgen=%u dgen=%u comm=%s — retired prior-tenure zombie BLI (clean destaged in_ail bgen<dgen) instead of reflushing superseded dir buffer (EX-held)\n",
					(unsigned long long)dsi.owner,
					(long long)bp->b_maps[0].bm_bn,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					dsi.mode, bp->b_mxfs_dir_gen,
					dsi.dir_gen, current->comm);

			if (dir_skip &&
			    (mxfs_dirskip_enabled || reflush_enf || tenure_enf ||
			     relepoch_enf)) {
				bp->b_error = 0;
				bp->b_flags |= XBF_DONE;
				/* sess50: for the release-epoch skip, mark the stale image
				 * for re-read so the next access cold-fetches the peer's
				 * durable block (zero the dir gen + drop FUA-fresh, matching
				 * the P26/P39 re-read completion).  Harmless for the other
				 * arms (they already retire a superseded image). */
				if (relepoch_enf) {
					bp->b_mxfs_dir_gen = 0;
					bp->b_flags &= ~_XBF_FUA_FRESH;
				}
				xfs_buf_ioend(bp);
				return;
			}
		}

		/*
		 * sess41 (ccloop 8ddb16a2) FIX for 2/tcp dir_reuse_coherency
		 * Bug A — the stale-tenure block-0 clobber.  The dirskip arms
		 * above are detect-only in production (mxfs_dirskip_enabled
		 * default 0) and their incarnation (ABA) arm was REFUTED
		 * (sess40: fired 0×).  The PROVEN discriminator is TENURE: a
		 * dir DATA/BLOCK buffer whose read-time stamp b_mxfs_dir_gen is
		 * OLDER than the owner dir's current i_dlm_dir_gen was last read
		 * in a PRIOR EX tenure.  The read-time invalidation
		 * (xfs_da_btree.c) that would re-fetch the peer's newer image is
		 * SKIPPED for a dirty/pinned/in-AIL buffer (XBF_TRYLOCK + dirty
		 * guards), so xfsaild can flush this superseded image over the
		 * peer's durable block and durably DROP dirents (the
		 * "node1_f1..f14 missing from readdir, lookup_fail=0" loss).
		 * This is the WRITE-side analogue of that read-time tenure guard.
		 *
		 * SAFE because we never skip on the tenure mismatch alone: we
		 * plain-read the CURRENT on-disk block (coherent under
		 * fua_disable=1) and skip ONLY when the disk image is a VALID
		 * same-owner, same-format dir block carrying strictly MORE live
		 * dirents than the buffer we are about to write (disk_cnt >
		 * buf_cnt) — i.e. the buffer would provably erase peer-committed
		 * dirents.  A current-tenure modification (incl. a legitimate
		 * dirent removal) has b_mxfs_dir_gen == i_dlm_dir_gen (re-stamped
		 * at read), so it takes the fast path and is never considered; a
		 * fresh/unstamped block (b_mxfs_dir_gen == 0) is excluded (the
		 * sess16 fresh-block hazard).  The disk read fires only on the
		 * rare prior-tenure write, so RULE-0 timing is unaffected.
		 */
		{
			extern int mxfs_dataclobber;
			extern int mxfs_dir_ex_write_guard;
			extern int mxfs_dir_stale_incarn_skip;
			extern int mxfs_dir_refresh_inplace;
			bool dc_data = (bp->b_ops == &xfs_dir3_data_buf_ops ||
					bp->b_ops == &xfs_dir3_block_buf_ops);
			bool dc_leaf = (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
					bp->b_ops == &xfs_dir3_leafn_buf_ops);
			/*
			 * sess12 (ccloop) — the SOUND ABA-writeback discriminator:
			 * a dir DATA/LEAF block may only be destaged by the node
			 * that currently holds the dir DLM EX.  A write submitted
			 * while we do NOT hold EX (NL-released, PR cacher, or the
			 * dir inode reclaimed so in_core=0) is a superseded prior-
			 * tenure image.  Legit removes/conversions/fresh-leaf writes
			 * ALL run under EX, so they are never flagged here (this
			 * avoids the refuted mxfs_dataclobber>=2 ghost false-skip).
			 */
			bool dir_not_held_ex = dsi.is_dir_buf &&
				(!dsi.in_core || dsi.mode != MXFS_LOCK_EX);
			bool ex_guard = mxfs_dir_ex_write_guard && dir_not_held_ex;
			extern int mxfs_dir_subset_guard;
			/* sess26: arm the disk-read + real dirent subset test for a
			 * dc_data block (the EX-held stale=0 clobber the dc_stale gates
			 * miss).  The actual skip below requires a clean in-AIL push +
			 * disk-has-extra-inum, so a legit write is never suppressed. */
			bool mxfs_dir_subset_guard_on = mxfs_dir_subset_guard && dc_data;
			/*
			 * dc_stale = the PROVEN safety gate: this buffer was last
			 * read in a PRIOR EX tenure (bgen < current dir_gen).  A
			 * current-tenure modify (incl. a LEGIT dirent/leaf
			 * removal) re-reads the block first, re-stamping
			 * bgen==dir_gen, so it is NEVER stale → never skipped.
			 * bgen==0 (acquire-evict / fresh-init image that was never
			 * re-stamped) counts as stale (0 < dir_gen) — that is the
			 * image xfsaild flushes to clobber the peer.
			 */
			bool dc_stale = dsi.in_core && dsi.dir_gen != 0 &&
					bp->b_mxfs_dir_gen < dsi.dir_gen;
			/*
			 * sess22 (ccloop, GPT design): the dir_reuse readdir=799
			 * residual is a stale-KEPT dir DATA block destaged by the
			 * node that STILL HOLDS EX (so ex_guard's dir_not_held_ex
			 * gate skips it) — a prior-tenure base (dc_stale) that was
			 * kept (in-AIL-undestaged) at the modify-evict, RMW'd, and
			 * flushed, durably erasing a peer's dirent (content-divergent,
			 * ~count-preserving — PROVEN: P22-FREESLOT-STALE 0× = not an
			 * addname double-alloc; the entry is added then VANISHES).
			 * The refuted mxfs_dataclobber>=2 dc_stale skip false-skipped
			 * a prior-INCARNATION ghost at a reused daddr (rm-rf recycles
			 * the dir inode# + block daddrs).  Gate on SAME incarnation
			 * (b_mxfs_dir_incarn == i_generation) so a ghost is excluded
			 * while a genuine this-incarnation stale base is caught.  The
			 * disk-proven content fingerprint below is still required, so a
			 * legit current-tenure write (bgen==dir_gen -> dc_stale=0) is
			 * never considered.
			 */
			bool same_incarn = dsi.buf_incarn != 0 &&
					dsi.buf_incarn == dsi.cur_incarn;

			/* RULE-4 instrumentation (2026-07-14): local lock-belief
			 * snapshot at every multi-node dir data/leaf write candidate
			 * — this node's cached mode/in_core for the dir, plus the
			 * gen comparison that feeds ex_guard/dc_stale.  Lets a
			 * failing run be compared node-by-node against a healthy
			 * one without guessing at the in-core state. */
			if ((dc_data || dc_leaf) && dsi.is_dir_buf)
				pr_warn_ratelimited(
					"mxfs: P-EXGUARD-SNAPSHOT owner=%llu mode=%d in_core=%d dir_gen=%u bgen=%u dc_stale=%d ex_guard=%d kind=%s\n",
					(unsigned long long)dsi.owner, dsi.mode,
					dsi.in_core, dsi.dir_gen, bp->b_mxfs_dir_gen,
					dc_stale, ex_guard, dc_leaf ? "leaf" : "data");

			/*
			 * detect mode (mxfs_dataclobber==1) inspects EVERY
			 * multi-node dir-block write so the real clobber predicate
			 * (bgen vs dir_gen, in_core) is visible at PRODUCTION
			 * config; enforce mode (>=2) inspects only the cheap
			 * tenure-stale gate.  The SKIP itself always requires
			 * dc_stale + a disk-proven clobber, so a legit write is
			 * never suppressed.
			 */
			if ((dc_data || dc_leaf) &&
			    (bp->b_flags & XBF_WRITE) && bp->b_addr &&
			    bp->b_map_count == 1 &&
			    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
			    dsi.is_dir_buf &&
			    ((mxfs_dataclobber &&
			      (mxfs_dataclobber == 1 || dc_stale)) ||
			     ex_guard ||
			     mxfs_dir_subset_guard_on ||
			     (mxfs_dir_refresh_inplace && dc_data) ||
			     (mxfs_dir_stale_incarn_skip && dc_stale &&
			      same_incarn))) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t dco_len = BBTOB(bp->b_length);
				uint64_t dco_lba = (uint64_t)bp->b_maps[0].bm_bn +
					bp->b_target->bt_sector_offset;
				void *dco_tmp = (dco_len &&
						 (dco_len & 511) == 0) ?
					kmalloc(dco_len, GFP_NOFS) : NULL;
				bool clobber = false;
				uint32_t bcnt = 0, dcnt = 0;
				const char *kind = dc_leaf ? "leaf" : "data";

				if (dco_tmp &&
				    mxfs_pal_bdev_read_plain_bdev(
					bp->b_target->bt_bdev, dco_lba,
					dco_tmp, dco_len) == 0) {
					if (dc_data) {
						bool bblk = (bp->b_ops ==
						    &xfs_dir3_block_buf_ops);
						__be32 dmag =
						    ((struct xfs_dir3_blk_hdr *)
						     dco_tmp)->magic;
						bool dblk = (dmag == cpu_to_be32(
						    XFS_DIR3_BLOCK_MAGIC));
						bool ddata = (dmag == cpu_to_be32(
						    XFS_DIR3_DATA_MAGIC));
						uint64_t downer = be64_to_cpu(
						    ((struct xfs_dir3_blk_hdr *)
						     dco_tmp)->owner);
						uint32_t bs=0, bx=0, ds=0, dx=0;

						if ((dblk || ddata) &&
						    (bblk == dblk) &&
						    downer == dsi.owner) {
							bcnt = mxfs_dir3_data_fingerprint(
							    bp->b_mount, bp->b_addr,
							    dco_len, bblk, &bs, &bx);
							dcnt = mxfs_dir3_data_fingerprint(
							    bp->b_mount, dco_tmp,
							    dco_len, dblk, &ds, &dx);
							/*
							 * ccloop cc87fed3 sess8: tried
							 * bidirectional (dcnt != bcnt) to also
							 * catch Case-B reintroduce (bcnt >
							 * dcnt) -- REVERTED, RULE-4 proven
							 * unsafe: posix_multi@8/caw regressed
							 * (renamed content empty, hardlink
							 * name gone, nodes_pass 3/8). Root:
							 * `bcnt > dcnt` is AMBIGUOUS in this
							 * not-held-EX/dc_stale gate between (a)
							 * Case B -- a stale buffer wrongly about
							 * to reintroduce a peer-removed entry --
							 * and (b) a legitimate async post-
							 * release destage of OUR OWN correctly-
							 * dirtied buffer (commit+dirty under EX,
							 * drop EX, destage lands slightly later
							 * with more entries than not-yet-caught-
							 * up disk).  dc_stale's gen-stamping
							 * does not disambiguate these -- both can
							 * present as "stale-tagged, buffer has
							 * more than disk".  The erasure direction
							 * (dcnt > bcnt, kept below) has no such
							 * ambiguity: an async destage of our own
							 * dirty work can never legitimately have
							 * FEWER entries than what peers already
							 * made durable.  Do NOT re-attempt
							 * bidirectional without a way to tell
							 * "our own pending work" from "a peer's
							 * removed-but-still-cached entry" (e.g.
							 * per-entry provenance, not just a count/
							 * checksum diff).
							 */
							clobber = (dcnt > bcnt) ||
							    (dcnt == bcnt && dcnt &&
							     (ds != bs || dx != bx));
						}
					} else {	/* dc_leaf */
						struct xfs_dir3_leaf_hdr *bh =
						    bp->b_addr;
						struct xfs_dir3_leaf_hdr *dh =
						    dco_tmp;
						uint16_t bmag = be16_to_cpu(
						    bh->info.hdr.magic);
						uint16_t dmag = be16_to_cpu(
						    dh->info.hdr.magic);
						uint64_t downer = be64_to_cpu(
						    dh->info.owner);

						if ((bmag == XFS_DIR3_LEAF1_MAGIC ||
						     bmag == XFS_DIR3_LEAFN_MAGIC) &&
						    (dmag == XFS_DIR3_LEAF1_MAGIC ||
						     dmag == XFS_DIR3_LEAFN_MAGIC) &&
						    downer == dsi.owner) {
							const __be32 *be = (const __be32 *)
							    ((char *)bh + sizeof(*bh));
							const __be32 *de = (const __be32 *)
							    ((char *)dh + sizeof(*dh));
							uint32_t maxe =
							    (dco_len - sizeof(*bh)) / 8;
							uint16_t bc = be16_to_cpu(bh->count);
							uint16_t dc = be16_to_cpu(dh->count);
							uint32_t bs=0, bx=0, ds=0, dx=0;
							uint16_t i;

							if (bc > maxe) bc = maxe;
							if (dc > maxe) dc = maxe;
							for (i=0; i<bc; i++) {
								uint32_t h = be32_to_cpu(be[i*2]);
								bs += h; bx ^= h;
							}
							for (i=0; i<dc; i++) {
								uint32_t h = be32_to_cpu(de[i*2]);
								ds += h; dx ^= h;
							}
							bcnt = bc; dcnt = dc;
							/* sess8: REVERTED bidirectional attempt,
							 * see the dc_data clobber comment above
							 * (posix_multi@8/caw regression). */
							clobber = (dc > bc) ||
							    (dc == bc && dc &&
							     (ds != bs || dx != bx));
						}
					}

					if (clobber) {
						/* sess69: the REAL DLM grant (not cached i_dlm_mode)
						 * + txn context — decisive for the "buffer behind disk
						 * under same-tenure EX" puzzle.  real_held=0 = phantom
						 * (clobber while NOT really holding EX); in_txn=0 =
						 * pure background xfsaild reflush (vs an active modify). */
						int p69_rh = mxfs_v5_dlm_inode_held_rawmode(
							bp->b_mount->m_mxfs_dlm, dsi.owner);
						/* sess37: is THIS node the master for the dir
						 * resource?  Settles double-grant (clobber on
						 * master) vs stale-local-DLM (clobber on non-
						 * master, real_mode=5 is stale local state). */
						extern int mxfs_v5_dlm_inode_master_self(
							struct mxfs_v5_dlm *, uint64_t);
						int p37_master = mxfs_v5_dlm_inode_master_self(
							bp->b_mount->m_mxfs_dlm, dsi.owner);
						/* sess38: the AUTHORITATIVE master dir epoch (the
						 * dir_tenure_evict signal).  buf_epoch < master_ep =>
						 * the read-invalidation SHOULD have caught this stale
						 * base but was SKIPPED (trylock/keep-guard); buf_epoch
						 * == master_ep => the MASTER EPOCH itself did not
						 * advance on the handoff (the under-fire root). */
						extern uint32_t mxfs_v5_dlm_inode_dir_epoch(
							struct mxfs_v5_dlm *, uint64_t);
						uint32_t p38_master_ep =
							mxfs_v5_dlm_inode_dir_epoch(
							bp->b_mount->m_mxfs_dlm, dsi.owner);
						struct xfs_buf_log_item *p69_bli = bp->b_log_item;
						int p69_inail = p69_bli && test_bit(XFS_LI_IN_AIL,
							&p69_bli->bli_item.li_flags);
						int p69_dirty = p69_bli && test_bit(XFS_LI_DIRTY,
							&p69_bli->bli_item.li_flags);
						pr_warn_ratelimited(
			"mxfs: P-DATACLOBBER-SKIP kind=%s owner=%llu daddr=%lld buf_cnt=%u disk_cnt=%u bufgen=%u dirgen=%u buf_grantgen=%u cur_grantgen=%u gg_mismatch=%d buf_epoch=%u master_ep=%u mode=%d real_mode=%d master_self=%d in_txn=%d in_ail=%d bdirty=%d pin=%d bflags=0x%x incarn=%u bincarn=%u tenure=%llu in_core=%d stale=%d enforce=%d comm=%s\n",
							kind,
							(unsigned long long)dsi.owner,
							(long long)bp->b_maps[0].bm_bn,
							bcnt, dcnt,
							bp->b_mxfs_dir_gen,
							dsi.dir_gen,
							bp->b_mxfs_grant_gen,
							dsi.cached_grant_gen,
							(int)(bp->b_mxfs_grant_gen != 0 &&
							      bp->b_mxfs_grant_gen !=
							      dsi.cached_grant_gen),
							bp->b_mxfs_dir_epoch,
							p38_master_ep,
							dsi.mode,
							p69_rh, p37_master,
							current->journal_info ? 1 : 0,
							p69_inail, p69_dirty,
							atomic_read(&bp->b_pin_count),
							bp->b_flags,
							dsi.cur_incarn, dsi.buf_incarn,
							(unsigned long long)dsi.tenure_id,
							dsi.in_core,
							dc_stale, mxfs_dataclobber,
							current->comm);
						/* sess50(ccloop) Case-B test (GPT-5.5): was this
						 * buffer last dirtied in a PRIOR EX tenure?
						 * tenure_id(buf) < cur_epoch(i_mxfs_ex_grant_seq)
						 * = a zombie reflush from before our current tenure
						 * (the stale clean-AIL push GPT Fix 4/5 targets);
						 * == = dirtied this tenure (not a cross-tenure zombie). */
						pr_warn_ratelimited(
				"mxfs: P50B-TENURE owner=%llu daddr=%lld buf_tenure=%llu cur_epoch=%llu prior_tenure=%d wrcnt_max=%u buf_cnt=%u disk_cnt=%u xnode=%d in_ail=%d bdirty=%d comm=%s\n",
							(unsigned long long)dsi.owner,
							(long long)bp->b_maps[0].bm_bn,
							(unsigned long long)dsi.tenure_id,
							(unsigned long long)dsi.cur_epoch,
							(int)(dsi.tenure_id != 0 &&
							      dsi.tenure_id < dsi.cur_epoch),
							bp->b_mxfs_dir_wrcnt_max, bcnt, dcnt,
							/* xnode=1: this buffer never wrote as many
							 * entries as disk holds -> a PEER wrote the
							 * higher disk image -> cross-node stale reflush.
							 * xnode=0: this buffer once wrote >= disk_cnt
							 * (it had the entry then reverted) = same-node. */
							(int)(bp->b_mxfs_dir_wrcnt_max < dcnt),
							p69_inail, p69_dirty,
							current->comm);
						/* sess38(ccloop) RULE-4: capture the call stack of
						 * the clobbering write for DATA blocks (the durable
						 * dirent loss).  Distinguishes xfsaild background
						 * reflush of a zombie/invalidated in_ail buffer from
						 * an active in-txn release-drain write.  Gated to a
						 * few dumps so it never floods. */
						if (dc_data) {
							static atomic_t p38st = ATOMIC_INIT(0);
							if (atomic_inc_return(&p38st) <= 6)
								dump_stack();
						}
						/*
						 * sess39 EX-GATED SUBSET-DROP (v2): the residual zombie
						 * reflush.  The prior refuted drop-suppressions
						 * (dir_subset_guard / P26) read disk at the bio chokepoint
						 * WITHOUT gating on holding the dir EX -> the read raced a
						 * peer's concurrent write -> torn image -> false-drop of a
						 * LEGIT write -> readdir=0 cascade (sess26/28 "write-side
						 * disk-compare is racy").  The v1 memcpy refresh corrupted
						 * the verifier (xfs_dir3_block_verify, sess39).  THIS v2
						 * fixes both: gate on `dsi.mode == EX` so NO peer can be
						 * writing this block concurrently -> the dco_tmp plain read
						 * is STABLE, not torn.  Then if disk is a strict SUPERSET
						 * of our clean in-AIL buffer (disk has dirents we lack AND
						 * we have NONE disk lacks = pure stale-subset, no un-landed
						 * work), DROP the stale write via the proven P12/P26
						 * completion (set XBF_DONE + zero b_mxfs_dir_gen + clear
						 * _XBF_FUA_FRESH + xfs_buf_ioend, NO bio, NO memcpy).  The
						 * stale image stays in-core but gen=0 forces the next
						 * read (xfs_da_read_buf) to invalidate + FUA-re-read the
						 * durable superset.  Pure-subset => nothing of ours is
						 * lost.  DATA blocks, clean in-AIL, EX-held, same-incarn.
						 */
						if (mxfs_dir_refresh_inplace && dc_data &&
						    dco_tmp && dsi.in_core &&
						    dsi.mode == MXFS_LOCK_EX &&
						    same_incarn && !p69_dirty && p69_inail &&
						    atomic_read(&bp->b_pin_count) == 0) {
							bool ri_icbf = (bp->b_ops ==
							    &xfs_dir3_block_buf_ops);
							bool ri_dkbf =
							    (((struct xfs_dir3_blk_hdr *)
							      dco_tmp)->magic == cpu_to_be32(
							      XFS_DIR3_BLOCK_MAGIC));
							int ri_disk_extra =
							    mxfs_dir3_disk_has_extra_inum(
							    bp->b_mount, bp->b_addr, dco_tmp,
							    dco_len, ri_icbf, ri_dkbf);
							int ri_core_extra =
							    mxfs_dir3_disk_has_extra_inum(
							    bp->b_mount, dco_tmp, bp->b_addr,
							    dco_len, ri_dkbf, ri_icbf);
							if (ri_disk_extra > 0 &&
							    ri_core_extra == 0) {
								pr_warn_ratelimited(
					"mxfs: P39-EXSUBSET-DROP owner=%llu daddr=%lld buf_cnt=%u disk_cnt=%u disk_extra=%d — EX-held pure-stale-subset; dropped stale write, marked for re-read (no peer-add revert)\n",
									(unsigned long long)dsi.owner,
									(long long)bp->b_maps[0].bm_bn,
									bcnt, dcnt, ri_disk_extra);
								bp->b_mxfs_dir_gen = 0;
								bp->b_flags &= ~_XBF_FUA_FRESH;
								bp->b_flags |= XBF_DONE;
								kfree(dco_tmp);
								bp->b_error = 0;
								xfs_buf_ioend(bp);
								return;
							}
						}
						{
						extern int mxfs_dir_subset_guard;
						int sg_extra = 0, sg_incore_extra = 0;
						if (mxfs_dir_subset_guard && dc_data &&
						    same_incarn && !p69_dirty && p69_inail &&
						    atomic_read(&bp->b_pin_count) == 0) {
							bool icbf = (bp->b_ops ==
							    &xfs_dir3_block_buf_ops);
							bool dkbf = (((struct xfs_dir3_blk_hdr *)
							    dco_tmp)->magic == cpu_to_be32(
							    XFS_DIR3_BLOCK_MAGIC));
							sg_extra = mxfs_dir3_disk_has_extra_inum(
							    bp->b_mount, bp->b_addr, dco_tmp,
							    dco_len, icbf, dkbf);
							/* sess28: in-core inumbers ABSENT from disk =
							 * THIS write's OWN new adds.  Only suppress a
							 * PURE-STALE subset rewrite (adds nothing);
							 * a write that also adds our entries is
							 * MERGE-NEEDED and must NOT be dropped
							 * (P-WMERGE proved subset_guard's readdir=316
							 * was from dropping these legit writes). */
							sg_incore_extra = mxfs_dir3_disk_has_extra_inum(
							    bp->b_mount, dco_tmp, bp->b_addr,
							    dco_len, dkbf, icbf);
						}
						if (sg_extra > 0 && sg_incore_extra == 0) {
							pr_warn_ratelimited(
				"mxfs: P26-SUBSET-SKIP owner=%llu daddr=%lld buf_cnt=%u disk_cnt=%u disk_extra=%d in_ail=%d bdirty=%d comm=%s — suppressed EX-held stale dir write dropping a peer dirent\n",
								(unsigned long long)dsi.owner,
								(long long)bp->b_maps[0].bm_bn,
								bcnt, dcnt, sg_extra,
								p69_inail, p69_dirty,
								current->comm);
							/* match the proven P12 skip: complete the
							 * write-AIL item CLEANLY (XBF_DONE set) so the
							 * AIL advances and no barrier stalls; zero the
							 * dir gen + drop FUA-fresh so the read-path gen
							 * hook (xfs_da_read_buf) refreshes the stale
							 * in-core image from the peer's durable disk on
							 * the next access.  Do NOT clear XBF_DONE here
							 * (xfs_buf_ioend on a write needs it set). */
							bp->b_flags |= XBF_DONE;
							bp->b_flags &= ~_XBF_FUA_FRESH;
							bp->b_mxfs_dir_gen = 0;
							kfree(dco_tmp);
							bp->b_error = 0;
							xfs_buf_ioend(bp);
							return;
						}
						}
						/*
						 * sess5(a9a03929) run75 ROOT: this arm fired on
						 * ex_guard (mode already NL mid-release) against a
						 * freshly-committed grow block whose FIRST write had
						 * not landed — the emulated-clean ioend below retired
						 * the BLI, the release evict destroyed the content,
						 * and the platter kept a prior-mkfs image at the
						 * reused daddr (uuid-mismatch EFSCORRUPTED loop).
						 * An UNDESTAGED buffer (pinned or lseq>wseq under
						 * completion-time wseq) carries the ONLY copy of
						 * committed local work: never suppress it, whatever
						 * the tenure/mode says.  The release fence's own
						 * flush is exactly what must land it.
						 */
						if (((mxfs_dataclobber >= 2 && dc_stale) ||
						    ex_guard ||
						    (mxfs_dir_stale_incarn_skip &&
						     dc_stale && same_incarn)) &&
						    !mxfs_dir_buf_is_undestaged(bp)) {
							/* sess12: disk-proven clobber AND we
							 * don't hold the dir EX -> this is a
							 * superseded prior-tenure background
							 * flush; drop it (the durable peer image
							 * is authoritative) and emulate a clean
							 * ioend so the AIL item is released. */
							pr_warn_ratelimited(
				"mxfs: P12-DIR-EXGUARD-SKIP kind=%s owner=%llu daddr=%lld buf_cnt=%u disk_cnt=%u bufgen=%u dirgen=%u in_core=%d mode=%d dc_stale=%d comm=%s — suppressed non-EX clobbering dir write\n",
								kind,
								(unsigned long long)dsi.owner,
								(long long)bp->b_maps[0].bm_bn,
								bcnt, dcnt,
								bp->b_mxfs_dir_gen,
								dsi.dir_gen, dsi.in_core,
								dsi.mode, dc_stale,
								current->comm);
							kfree(dco_tmp);
							bp->b_error = 0;
							bp->b_flags |= XBF_DONE;
							xfs_buf_ioend(bp);
							return;
						}
					}
				}
				if (dco_tmp)
					kfree(dco_tmp);
			}
		}
	}

	/*
	 * sess56 (ccloop 14d31183) P56-DIRWR-OVER-DISKINODE — decisive M3
	 * (writeback-time clobber) detector.  sess53-55 ruled out M1
	 * (allocator never hands a DATA req a block holding a live inode) and
	 * M2 (the dir-buffer GET path never maps a dir block onto an
	 * inode-cluster daddr).  Yet dir dirent bytes physically overwrite an
	 * inode cluster (ino 135).  So the clobber must be at WRITE SUBMIT: a
	 * STALE cached dir buffer whose target daddr was — between get and now
	 * — freed and reallocated as an inode chunk (by this node or a peer),
	 * then flushed by xfsaild over the new inode cluster.  This probe
	 * plain-reads the CURRENT on-disk content at the target daddr (SCST
	 * cache is coherent under fua_disable=1) and, if it carries live inode
	 * magic at any inode-size boundary, fires: this dir write is about to
	 * clobber a live inode cluster.  Heavy (one read per dir write) — gated
	 * behind mxfs.instr / mxfs.dirwr; functional runs leave it off.
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_map_count == 1 &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops)) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
		uint32_t p56_len = BBTOB(bp->b_length);
		uint64_t p56_lba = (uint64_t)bp->b_maps[0].bm_bn +
			bp->b_target->bt_sector_offset;
		uint32_t p56_isz = bp->b_mount->m_sb.sb_inodesize;
		void *p56_tmp = (p56_len && (p56_len & 511) == 0) ?
			kmalloc(p56_len, GFP_NOFS) : NULL;

		if (p56_tmp && p56_isz >= 256 &&
		    mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
			p56_lba, p56_tmp, p56_len) == 0) {
			uint32_t p56_off;

			for (p56_off = 0; p56_off + p56_isz <= p56_len;
			     p56_off += p56_isz) {
				struct xfs_dinode *p56_d = p56_tmp + p56_off;

				if (be16_to_cpu(p56_d->di_magic) ==
				    XFS_DINODE_MAGIC) {
					static atomic_t p56_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p56_n) <= 200)
						pr_warn("mxfs: P56-DIRWR-OVER-DISKINODE daddr=%lld off=%u disk_ino=%llu disk_mode=0%o disk_gen=%u dirbuf_owner=%lld comm=%s realns=%llu\n",
							(long long)bp->b_maps[0].bm_bn,
							p56_off,
							(unsigned long long)be64_to_cpu(p56_d->di_ino),
							be16_to_cpu(p56_d->di_mode),
							be32_to_cpu(p56_d->di_gen),
							(long long)be64_to_cpu(((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner),
							current->comm,
							(unsigned long long)ktime_get_real_ns());
					break;
				}
			}

			/*
			 * sess19 LEAF-HASH write-clobber detector (RULE 4).
			 * PROVEN this session: the 2/tcp cc_blockdir_probe "loss"
			 * is a dir LEAF hash-index vs DATA block inconsistency —
			 * readdir lists the name (durable in the data block) but
			 * lookup ENOENTs because the LEAF block we are about to
			 * write is MISSING the peer's committed hash entries (a
			 * stale-base RMW under the read keep-guard, DIR-STALE-SKIP
			 * pin=1 undest=1).  p56_tmp already holds the COHERENT
			 * on-disk leaf at this daddr (read above).  Compare the
			 * xfs_dir3_leaf_hdr.count of the buffer WE ARE WRITING vs
			 * the current disk: fewer entries than disk = we are about
			 * to durably DROP the peer's hash entries (the clobber,
			 * caught in the act).  Gated; fires only on buf<disk.
			 */
			if (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
			    bp->b_ops == &xfs_dir3_leafn_buf_ops) {
				struct xfs_dir3_leaf_hdr *p56_bh = bp->b_addr;
				struct xfs_dir3_leaf_hdr *p56_dh = p56_tmp;
				uint16_t p56_dmag =
					be16_to_cpu(p56_dh->info.hdr.magic);
				uint16_t p56_bmag =
					be16_to_cpu(p56_bh->info.hdr.magic);
				uint16_t p56_bc = be16_to_cpu(p56_bh->count);
				uint16_t p56_dc = be16_to_cpu(p56_dh->count);

				/*
				 * sess20: the reuse leaf-hash loss is CONTENT-
				 * divergent at EQUAL count (the count-only clobber
				 * test missed it).  Fingerprint the leaf entries'
				 * hashvals (sum+xor over `count` ents) for both the
				 * buffer being written and the coherent on-disk
				 * leaf; fire when buf DROPS a hashval the disk has
				 * (count-short OR fingerprint mismatch).  ents start
				 * right after the dir3 leaf hdr; each ent is
				 * {__be32 hashval; __be32 address} = 8 bytes. */
				if ((p56_dmag == XFS_DIR3_LEAF1_MAGIC ||
				     p56_dmag == XFS_DIR3_LEAFN_MAGIC) &&
				    (p56_bmag == XFS_DIR3_LEAF1_MAGIC ||
				     p56_bmag == XFS_DIR3_LEAFN_MAGIC)) {
					const __be32 *bent = (const __be32 *)
						((char *)p56_bh + sizeof(*p56_bh));
					const __be32 *dent = (const __be32 *)
						((char *)p56_dh + sizeof(*p56_dh));
					uint32_t maxe = (p56_len - sizeof(*p56_bh)) / 8;
					uint32_t bsum = 0, bxor = 0, dsum = 0, dxor = 0;
					uint16_t bc = (p56_bc <= maxe) ? p56_bc : maxe;
					uint16_t dc = (p56_dc <= maxe) ? p56_dc : maxe;
					uint16_t i;

					for (i = 0; i < bc; i++) {
						uint32_t h = be32_to_cpu(bent[i * 2]);
						bsum += h; bxor ^= h;
					}
					for (i = 0; i < dc; i++) {
						uint32_t h = be32_to_cpu(dent[i * 2]);
						dsum += h; dxor ^= h;
					}

					/*
					 * sess6 (ccloop 186320ae) P-LEAFDROP — SET-based
					 * forward-write drop detector.  The count/fingerprint
					 * tag below cannot discriminate: every legitimate add
					 * diverges (buf = disk + one new hash), and the proven
					 * 8/caw hole (node7_f4: hash durable at count 129,
					 * gone by the 505-entry leaf split, every observed
					 * write count-forward) rode INSIDE forward content.
					 * Adds only APPEND hashvals and removes only mark the
					 * ent STALE (hashval preserved until compaction), so
					 * on any forward write (bc >= dc) the disk's hashvals
					 * must be a MULTISET SUBSET of the buffer's — sorted
					 * arrays, two-pointer walk.  Compaction shrinks
					 * (bc < dc) and is excluded by the gate; a birth
					 * write over a recycled daddr only passes when
					 * bc >= dc (and dir_reuse's per-round name set is
					 * identical, so a dead prior-round leaf subsets too).
					 * A violation names the criminal write IN THE ACT:
					 * comm + stack + the first dropped hashval.
					 */
					if (p56_bc >= p56_dc && dc > 0) {
						uint32_t j = 0, miss = 0;
						uint32_t first_miss = 0;
						uint16_t di;

						for (di = 0; di < dc; di++) {
							uint32_t dh = be32_to_cpu(dent[di * 2]);

							while (j < bc &&
							       be32_to_cpu(bent[j * 2]) < dh)
								j++;
							if (j < bc &&
							    be32_to_cpu(bent[j * 2]) == dh) {
								j++;
								continue;
							}
							if (!miss)
								first_miss = dh;
							miss++;
						}
						if (miss) {
							static atomic_t p6ld_n = ATOMIC_INIT(0);

							if (atomic_inc_return(&p6ld_n) <= 40) {
								pr_err("mxfs: P-LEAFDROP owner=%llu daddr=%lld buf_cnt=%u disk_cnt=%u dropped=%u first_hash=0x%x bufgen=%u bp=%px hold=%d lseq=%u wseq=%u bli=%d inail=%d comm=%s realns=%llu — forward leaf write DROPS durable hashval(s); stack:\n",
									(unsigned long long)be64_to_cpu(p56_bh->info.owner),
									(long long)bp->b_maps[0].bm_bn,
									p56_bc, p56_dc, miss,
									first_miss,
									bp->b_mxfs_dir_gen,
									bp, bp->b_hold,
									bp->b_mxfs_logged_seq,
									bp->b_mxfs_written_seq,
									bp->b_log_item ? 1 : 0,
									(bp->b_log_item && test_bit(XFS_LI_IN_AIL, &bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
									current->comm,
									(unsigned long long)ktime_get_real_ns());
								dump_stack();
							}
						}
					}
					{
						static atomic_t p56l_n = ATOMIC_INIT(0);
						int diverge = (p56_bc < p56_dc ||
							bsum != dsum || bxor != dxor);

						/* sess20: log EVERY leaf write (not just
						 * divergent) so the full count/fingerprint
						 * sequence is visible — to test whether
						 * node2's hashvals EVER reach the durable
						 * leaf.  tag=CLOBBER if buf drops what disk
						 * has, else WRITE. */
						if (atomic_inc_return(&p56l_n) <= 50000)
							pr_warn("mxfs: P-LEAFWRITE tag=%s owner=%lld daddr=%lld buf_cnt=%u disk_cnt=%u bufgen=%u bsum=0x%x dsum=0x%x bxor=0x%x dxor=0x%x comm=%s realns=%llu\n",
								diverge ? "CLOBBER" : "WRITE",
								(long long)be64_to_cpu(((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner),
								(long long)bp->b_maps[0].bm_bn,
								p56_bc, p56_dc, bp->b_mxfs_dir_gen,
								bsum, dsum, bxor, dxor,
								current->comm,
								(unsigned long long)ktime_get_real_ns());
					}
				}
			}

			/*
			 * sess29 (ccloop 8ddb16a2): write-side dir DATA-block
			 * stale-RMW / dirent-loss detector (P29-DATAWRITE).  The
			 * leaf detector above catches only leaf hash-index loss;
			 * this catches the actual dirent CONTENT loss
			 * (dir_reuse_coherency drops node1_f1..f12 from readdir =
			 * a DATA block written with fewer/different dirents than
			 * the coherent on-disk image).  p56_tmp already holds the
			 * COHERENT on-disk block (plain-read above).  Compare the
			 * live-dirent count + inode-number fingerprint of the
			 * buffer we are about to submit vs disk; fire CLOBBER when
			 * the buffer DROPS what disk has (count-short OR
			 * fingerprint mismatch).  Logs every data-block write so
			 * the full per-daddr sequence is visible.
			 */
			if (bp->b_ops == &xfs_dir3_data_buf_ops ||
			    bp->b_ops == &xfs_dir3_block_buf_ops) {
				bool bblk = (bp->b_ops == &xfs_dir3_block_buf_ops);
				__be32 dmag = ((struct xfs_dir3_blk_hdr *)
						p56_tmp)->magic;
				bool dblk = (dmag ==
					cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));
				uint32_t bsum = 0, bxor = 0, dsum = 0, dxor = 0;
				uint32_t bcnt = mxfs_dir3_data_fingerprint(
					bp->b_mount, bp->b_addr, p56_len, bblk,
					&bsum, &bxor);
				uint32_t dcnt = mxfs_dir3_data_fingerprint(
					bp->b_mount, p56_tmp, p56_len, dblk,
					&dsum, &dxor);
				static atomic_t p29_n = ATOMIC_INIT(0);
				int diverge = (bcnt < dcnt ||
					bsum != dsum || bxor != dxor);

				/* sess4(a16ec5f2): 4000 capped out mid-run (test1
				 * burned it on rm-phase removals) leaving the
				 * failing round unrecorded; the ledger replay
				 * needs EVERY dir-data submit. */
				if (atomic_inc_return(&p29_n) <= 100000)
					pr_warn("mxfs: P29-DATAWRITE tag=%s owner=%lld daddr=%lld bblk=%d dblk=%d buf_cnt=%u disk_cnt=%u bufgen=%u bufincarn=%u bsum=0x%x dsum=0x%x bxor=0x%x dxor=0x%x comm=%s realns=%llu\n",
						diverge ? "CLOBBER" : "WRITE",
						(long long)be64_to_cpu(((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner),
						(long long)bp->b_maps[0].bm_bn,
						bblk, dblk, bcnt, dcnt,
						bp->b_mxfs_dir_gen,
						bp->b_mxfs_dir_incarn,
						bsum, dsum, bxor, dxor,
						current->comm,
						(unsigned long long)ktime_get_real_ns());
			}
		}
		if (p56_tmp)
			kfree(p56_tmp);
	}


	bio = bio_alloc(bp->b_target->bt_bdev, nr_vecs, xfs_buf_bio_op(bp),
			GFP_NOIO);
	if (is_vmalloc_addr(bp->b_addr))
		bio_add_vmalloc(bio, bp->b_addr, len);
	else
		bio_add_virt_nofail(bio, bp->b_addr, len);
	bio->bi_private = bp;
	bio->bi_end_io = xfs_buf_bio_end_io;

	/*
	 * If there is more than one map segment, split out a new bio for each
	 * map except of the last one.  The last map is handled by the
	 * remainder of the original bio outside the loop.
	 */
	blk_start_plug(&plug);
	for (map = 0; map < bp->b_map_count - 1; map++) {
		struct bio	*split;

		split = bio_split(bio, bp->b_maps[map].bm_len, GFP_NOFS,
				&fs_bio_set);
		split->bi_iter.bi_sector = bp->b_maps[map].bm_bn +
					   bp->b_target->bt_sector_offset;
		bio_chain(split, bio);
		submit_bio(split);
	}
	bio->bi_iter.bi_sector = bp->b_maps[map].bm_bn +
				 bp->b_target->bt_sector_offset;
	pr_debug("mxfs: buf_io %s daddr=%lld phys=%lld len=%u off=%lld\n",
		 (bp->b_flags & XBF_WRITE) ? "W" : "R",
		 (long long)bp->b_maps[map].bm_bn,
		 (long long)bio->bi_iter.bi_sector,
		 len, (long long)bp->b_target->bt_sector_offset);
	/*
	 * sess35 P-H27: log WRITE submissions of dir3 blocks (magic XDB3
	 * = 0x58 0x44 0x42 0x33 in bp->b_addr[0..3]). Filter aggressively
	 * to keep noise down. Goal: confirm whether test2 actually
	 * submits a write bio for the dir3 buf at LBA 8388408.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr) {
		const unsigned char *p = bp->b_addr;
		long long lba = bp->b_maps[map].bm_bn;
		if (p[0] == 0x58 && p[1] == 0x44 && p[2] == 0x42 && p[3] == 0x33) {
			mxfs_idbg("mxfs: P-H27-SUBMIT-DIR3 daddr=%lld len=%u "
				"first8=%02x%02x%02x%02x%02x%02x%02x%02x bp=%p realns=%llu\n",
				lba, len,
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], bp,
				(unsigned long long)ktime_get_real_ns());
		}
		/* sess35 P-H28: log ALL writes (regardless of magic) to a small
		 * LBA range near the test's dir block, to catch zero-overwrites
		 * that the XDB3-only P-H27 filter would miss.
		 */
		if (lba >= 2097100 && lba <= 16777300) {
			mxfs_idbg("mxfs: P-H28-ANY-WRITE daddr=%lld len=%u "
				"first8=%02x%02x%02x%02x%02x%02x%02x%02x bp=%p realns=%llu\n",
				lba, len,
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], bp,
				(unsigned long long)ktime_get_real_ns());
		}
	}
	mxfs_buf_ev(bp, MXFS_BEV_BIO);
	submit_bio(bio);
	blk_finish_plug(&plug);
}

/*
 * Wait for I/O completion of a sync buffer and return the I/O error code.
 */
static int
xfs_buf_iowait(
	struct xfs_buf	*bp)
{
	ASSERT(!(bp->b_flags & XBF_ASYNC));

	do {
		trace_xfs_buf_iowait(bp, _RET_IP_);
		/*
		 * sess5 (ccloop a864) P-IOWAIT-STUCK — dir_reuse@32/caw wedge#2:
		 * the durable-signal bmbt/owner-scan SYNC bwrite hangs here
		 * forever with device inflight=0 (a lost wakeup / a skip-emulated
		 * write that reinit'd b_iowait but never completed it).  Poll the
		 * completion in bounded slices and dump the buffer state so the
		 * exact broken path is identified next run.  Functionally
		 * identical to wait_for_completion (still blocks until done).
		 */
		while (!wait_for_completion_timeout(&bp->b_iowait,
						    msecs_to_jiffies(4000))) {
			unsigned int evi = bp->b_mxfs_evi;

			pr_warn_ratelimited(
			    "mxfs: P-IOWAIT-STUCK daddr=%lld ops=%s flags=0x%x err=%d wr_counted=%d sync_waiters=%d ioend_seen=%u relse_seen=%u lseq=%u wseq=%u done=%d dir_inflight=%d rd=%d wr=%d comm=%s evi=%u ev=[%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx]\n",
			    (long long)bp->b_maps[0].bm_bn,
			    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
			    (unsigned int)bp->b_flags, bp->b_error,
			    bp->b_mxfs_dir_wr_counted ? 1 : 0,
			    atomic_read(&bp->b_mxfs_sync_waiters),
			    bp->b_mxfs_ioend_seen, bp->b_mxfs_relse_seen,
			    bp->b_mxfs_logged_seq, bp->b_mxfs_written_seq,
			    completion_done(&bp->b_iowait) ? 1 : 0,
			    bp->b_mount ? atomic_read(
				&bp->b_mount->m_mxfs_dir_wr_inflight) : -1,
			    (bp->b_flags & XBF_READ) ? 1 : 0,
			    (bp->b_flags & XBF_WRITE) ? 1 : 0,
			    current->comm, evi,
			    /* oldest -> newest (evi = next overwrite slot) */
			    bp->b_mxfs_evring[(evi + 0) & 7],
			    bp->b_mxfs_evring[(evi + 1) & 7],
			    bp->b_mxfs_evring[(evi + 2) & 7],
			    bp->b_mxfs_evring[(evi + 3) & 7],
			    bp->b_mxfs_evring[(evi + 4) & 7],
			    bp->b_mxfs_evring[(evi + 5) & 7],
			    bp->b_mxfs_evring[(evi + 6) & 7],
			    bp->b_mxfs_evring[(evi + 7) & 7]);
		}
		mxfs_buf_ev(bp, MXFS_BEV_IOWAIT);
		trace_xfs_buf_iowait_done(bp, _RET_IP_);
	} while (!__xfs_buf_ioend(bp));

	return bp->b_error;
}

/*
 * sess30 (ccloop): re-derive a metadata buffer's write verifier from its
 * on-disk magic.  An mxfs reload/FUA path can leave a cached metadata buffer
 * with b_ops==NULL (PROVEN: soak "no buf ops" on an inode cluster, daddr
 * 0x7fc6e0, flushed by xfsaild via delwri).  Writing such a buffer SKIPS the
 * write verifier, so the CRC is NOT recomputed for the modified content —
 * harmless for inodes (di_crc stamped at iflush) but CATASTROPHIC for
 * buffer-CRC metadata (AGI/AGF/AGFL/btrees): the on-disk block lands with a
 * stale CRC → a peer's FUA read fails xfs_*_read_verify (EFSBADCRC err74) →
 * shutdown (the dir_reuse 8/tcp rm-rf mass-inode-free AGI-CRC cascade).
 * Map the magic back to the correct ops so verify_write stamps a valid CRC.
 * All ops referenced here are already linked into this TU.
 */
static const struct xfs_buf_ops *
mxfs_buf_ops_from_magic(struct xfs_buf *bp)
{
	__be32	m32;
	__be16	m16;

	if (!bp->b_addr)
		return NULL;
	m32 = *(__be32 *)bp->b_addr;
	m16 = *(__be16 *)bp->b_addr;

	if (m16 == cpu_to_be16(XFS_DINODE_MAGIC))
		return &xfs_inode_buf_ops;
	if (m32 == cpu_to_be32(XFS_AGI_MAGIC))
		return &xfs_agi_buf_ops;
	if (m32 == cpu_to_be32(XFS_AGF_MAGIC))
		return &xfs_agf_buf_ops;
	if (m32 == cpu_to_be32(XFS_AGFL_MAGIC))
		return &xfs_agfl_buf_ops;
	if (m32 == cpu_to_be32(XFS_ABTB_CRC_MAGIC))
		return &xfs_bnobt_buf_ops;
	if (m32 == cpu_to_be32(XFS_ABTC_CRC_MAGIC))
		return &xfs_cntbt_buf_ops;
	if (m32 == cpu_to_be32(XFS_IBT_CRC_MAGIC))
		return &xfs_inobt_buf_ops;
	if (m32 == cpu_to_be32(XFS_FIBT_CRC_MAGIC))
		return &xfs_finobt_buf_ops;
	if (m32 == cpu_to_be32(XFS_BMAP_CRC_MAGIC))
		return &xfs_bmbt_buf_ops;
	if (m32 == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return &xfs_dir3_block_buf_ops;
	if (m32 == cpu_to_be32(XFS_DIR3_DATA_MAGIC))
		return &xfs_dir3_data_buf_ops;
	if (m32 == cpu_to_be32(XFS_DIR3_FREE_MAGIC))
		return &xfs_dir3_free_buf_ops;
	return NULL;
}

/*
 * Run the write verifier callback function if it exists. If this fails, mark
 * the buffer with an error and do not dispatch the I/O.
 */
static bool
xfs_buf_verify_write(
	struct xfs_buf		*bp)
{
	if (bp->b_ops) {
		bp->b_ops->verify_write(bp);
		if (bp->b_error)
			return false;
	} else if (bp->b_rhash_key != XFS_BUF_DADDR_NULL) {
		/*
		 * Non-crc filesystems don't attach verifiers during log
		 * recovery, so don't warn for such filesystems.
		 */
		if (xfs_has_crc(bp->b_mount)) {
			/*
			 * sess30: a cached metadata buffer reached the write
			 * path with no verifier (mxfs reload/FUA dropped ops).
			 * Re-derive ops from the on-disk magic and run the
			 * verifier so the CRC is recomputed — never write an
			 * un-CRC'd metadata block (the AGI-CRC shutdown root).
			 */
			const struct xfs_buf_ops *ops =
				mxfs_buf_ops_from_magic(bp);

			if (ops) {
				static atomic_t opsrec = ATOMIC_INIT(0);
				if (atomic_inc_return(&opsrec) <= 400)
					pr_warn("mxfs: P30-OPS-RECOVER daddr=0x%llx len=%d ops=%s — re-derived verifier, stamping CRC (write would have been un-CRC'd)\n",
						(unsigned long long)xfs_buf_daddr(bp),
						bp->b_length, ops->name);
				bp->b_ops = ops;
				bp->b_ops->verify_write(bp);
				if (bp->b_error)
					return false;
				return true;
			}
			xfs_warn(bp->b_mount,
				"%s: no buf ops on daddr 0x%llx len %d",
				__func__, xfs_buf_daddr(bp),
				bp->b_length);
			xfs_hex_dump(bp->b_addr, XFS_CORRUPTION_DUMP_LEN);
			dump_stack();
		}
	}

	return true;
}

/*
 * v0.3.62: SCSI READ(16) FUA passthrough for AG-metadata reads in
 * multi-node mode.  Mirrors the v0.3.58 disklock fix: the bio path on
 * iSCSI/LIO returns -EIO when REQ_FUA is set on a read, so we go around
 * it via direct SCSI passthrough with the FUA bit set in the CDB.
 *
 * Returns 0 on successful FUA read (buffer state already finalized via
 * xfs_buf_ioend), -EOPNOTSUPP if the device is not a SCSI sdev (caller
 * falls back to bio), other negative errno on SCSI error.  AG-metadata
 * buffers are virtually always single-segment; multi-segment maps fall
 * back to bio.
 */
static atomic64_t mxfs_buf_fua_ok;
static atomic64_t mxfs_buf_fua_fallback;
static atomic64_t mxfs_buf_fua_err;

static int
mxfs_buf_read_fua(
	struct xfs_buf		*bp)
{
	uint64_t		lba_512;
	uint32_t		len;
	uint64_t		n;
	int			rc;

	if (bp->b_map_count != 1)
		return -EOPNOTSUPP;

	len = BBTOB(bp->b_length);
	lba_512 = bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;

	/*
	 * sess90 DECISIVE PROBE (Gemini RULE-5): a FUA read DMA-overwrites
	 * bp->b_addr with the on-disk image.  XFS NEVER legitimately reads
	 * over a buffer that is PINNED or carries LOG ITEMS — that buffer
	 * holds a logged-but-not-yet-checkpointed modification (a btree
	 * delete/insert committed to the CIL).  If we FUA-read it here we
	 * silently obliterate that modification with stale disk content =
	 * the bnobt lost-removal -> double-free shutdown.  This is the
	 * proposed root mechanism: the read-time XBF_DONE-clear hook lets a
	 * post-trans_roll re-read clobber an uncheckpointed bnobt change.
	 * comm + ops + pin/li state pinpoint it.
	 */
	/*
	 * sess26(ccloop) ROOT FIX (RULE 4): the P91 skip below keeps an in-core
	 * buffer with ANY attached BLI as "authoritative" to protect logged-but-
	 * un-checkpointed work.  But for a multi-node dir DATA/LEAF block that is
	 * DESTAGED (not pinned AND b_mxfs_logged_seq == b_mxfs_written_seq = the
	 * last local mods already left for disk), the BLI merely LINGERS in the AIL
	 * — there is NO un-checkpointed work to protect.  Keeping it (a) serves the
	 * stale prior-tenure RMW base a peer superseded (modify-evict cleared
	 * XBF_DONE but P91 then refused to refetch because the BLI is attached) and
	 * (b) lets xfsaild later destage that stale b_addr over the peer's dirent
	 * (the EX-held in_ail=1 background clobber, dir_reuse_coherency readdir=799).
	 * FUA-piercing a destaged buffer is SAFE: its content is already on the LUN,
	 * so the DMA overwrite yields the same-or-newer (peer-superset) image — and
	 * it simultaneously refreshes b_addr so any later xfsaild push writes fresh,
	 * not stale.  Gated dir_fua_refresh_destaged; pin/undestaged still hard-skip.
	 */
	{
		extern int mxfs_dir_fua_refresh_destaged;
		/*
		 * sess26: DATA/BLOCK ops ONLY — never LEAF.  FUA-refreshing a
		 * fresh LEAF block exposes data-block offsets the stale in-core
		 * data-fork extent map cannot resolve -> xfs_dabuf_map HOLE ->
		 * XFS_DABUF_MAP_HOLE_OK shutdown (sess20 family, 140× in the
		 * leaf-included build).  The durable lost-update is a DATA-block
		 * clobber (readdir=799, lookup_fail=0), so refreshing DATA blocks
		 * is sufficient and adds no new offset mappings.
		 */
		bool is_dir_blk = bp->b_ops == &xfs_dir3_data_buf_ops ||
				  bp->b_ops == &xfs_dir3_block_buf_ops;
		bool destaged = atomic_read(&bp->b_pin_count) == 0 &&
				bp->b_mxfs_logged_seq == bp->b_mxfs_written_seq;
		if (mxfs_dir_fua_refresh_destaged && is_dir_blk && destaged) {
			static atomic_t p26fr = ATOMIC_INIT(0);
			if (atomic_inc_return(&p26fr) <= 8000)
				pr_warn("mxfs: P26-FUAREFRESH daddr=%lld ops=%s has_bli=%d li_empty=%d comm=%s — FUA-piercing destaged lingering-BLI dir base\n",
					(long long)bp->b_maps[0].bm_bn,
					(bp->b_ops == &xfs_dir3_block_buf_ops) ? "block" : "data",
					bp->b_log_item ? 1 : 0,
					list_empty(&bp->b_li_list) ? 1 : 0,
					current->comm);
			goto do_fua_read;	/* refresh the lingering-BLI stale dir base */
		}
	}

	if (atomic_read(&bp->b_pin_count) > 0 || !list_empty(&bp->b_li_list) ||
	    bp->b_log_item) {
		const char *opsname = "?";
		if (bp->b_ops)
			opsname = bp->b_ops->name ? bp->b_ops->name : "noname";
		/*
		 * sess91 ROOT FIX (BACKSTOP): a FUA read DMA-overwrites
		 * bp->b_addr with the on-disk image.  This buffer is PINNED or
		 * carries LOG ITEMS = it holds a logged-but-not-yet-checkpointed
		 * modification that lives ONLY in core.  Reading disk over it
		 * silently obliterates that change with stale content = the
		 * confirmed lost-update family (sess90 P90 FIRED 7× here on the
		 * shutdown node).  The in-core image is authoritative — a logged
		 * buffer was necessarily read before it was modified, so its
		 * content is valid.  DO NOT read: complete the read in-place from
		 * the in-core data and return success.  The XBF_DONE-clear paths
		 * that armed this (xfs_icache.c cluster invalidation, the AG-meta
		 * hook) are now guarded; this is defense-in-depth for any path we
		 * missed.  Deliberately do NOT set _XBF_FUA_FRESH (we did not
		 * pierce the storage cache), so a later clean read still FUA-
		 * refreshes once the modification is checkpointed.
		 */
		pr_warn_ratelimited(
		    "mxfs: P91-FUA-SKIP-LOGGED daddr=%lld ops=%s pin=%d li_empty=%d has_bli=%d bflags=0x%x comm=%s — kept in-core authoritative buffer (clobber averted)\n",
		    (long long)bp->b_maps[0].bm_bn, opsname,
		    atomic_read(&bp->b_pin_count),
		    list_empty(&bp->b_li_list) ? 1 : 0,
		    bp->b_log_item ? 1 : 0, bp->b_flags, current->comm);
		atomic64_inc(&mxfs_fua_p91_skip);
		bp->b_error = 0;
		bp->b_mxfs_inplace_read = true;	/* v0.10.32: no DMA — ioend must not CRC-verify the dirty in-core image */
		xfs_buf_ioend(bp);
		return 0;
	}

do_fua_read:
	rc = mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev, lba_512,
					  bp->b_addr, len);
	if (rc == 0) {
		atomic64_inc(&mxfs_fua_scsi_actual);
		/*
		 * v6a phase 1 (v0.3.129, sess31): mark the buf as freshness-
		 * confirmed.  The FUA SCSI READ pierced the storage stack's
		 * per-initiator read cache, so its content matches disk as of
		 * this moment.  Cleared by xfs_buf_stale on next invalidation.
		 * While the flag is set, mxfs_buf_needs_fua_read's gate
		 * (in xfs_buf_submit) is bypassed and subsequent reads use
		 * plain bio (page cache amortized).  Per
		 * docs/v6-cache-architecture-proposal.md §11.9.
		 */
		bp->b_flags |= _XBF_FUA_FRESH;
		/*
		 * sess63: timeline probe — log every bmbt LEAF that a FUA read
		 * just DMA'd in, so the merged P63-LEAFWR/P63-LEAFRD timeline
		 * shows whether a read lands numrecs=N-1 (the in-core leaf
		 * revert that feeds the torn flush) after the insert wrote N.
		 */
		if (bp->b_ops == &xfs_bmbt_buf_ops && bp->b_addr) {
			struct xfs_btree_block *rb = bp->b_addr;
			static atomic_t p63rd = ATOMIC_INIT(0);
			if (be16_to_cpu(rb->bb_level) == 0 &&
			    atomic_inc_return(&p63rd) <= 4000)
				pr_warn("mxfs: P63-LEAFRD owner=%llu daddr=%lld numrecs=%u comm=%s realns=%llu\n",
					(unsigned long long)be64_to_cpu(
						rb->bb_u.l.bb_owner),
					(long long)bp->b_maps[0].bm_bn,
					be16_to_cpu(rb->bb_numrecs),
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		/*
		 * sess43 ROOT FIX (gen-stamp-on-fresh-read): this FUA read just
		 * loaded the CURRENT on-disk content for this AG-meta buffer.
		 * Stamp b_mxfs_ag_gen to the AG's current generation so the
		 * read-time invalidation hook (mxfs_ag_meta_invalidate_stale)
		 * recognises it as fresh.  WITHOUT this, the buffer stayed
		 * gen-lagging (gen=0) after a walk-stale+reread (the walk clears
		 * DONE but never stamps gen; only the hook's discard branch did),
		 * so once THIS node modified it (in-core ahead of disk) the hook
		 * could not tell this-node-authoritative (gen=0) from peer-stale
		 * (gen=0) and DISCARDED+reverted our committed update → the
		 * disk_differs=1 lost-update family (free-space P70, AGI iunlink,
		 * dir-miss).  Safe: we hold the AG EX, so current disk content +
		 * any subsequent local modify is authoritative until release; the
		 * next fresh acquire bumps pag_dlm_meta_gen and re-stales it.
		 */
		if (bp->b_pag && mxfs_buf_is_ag_metadata(bp))
			bp->b_mxfs_ag_gen = bp->b_pag->pag_dlm_meta_gen;
		/*
		 * sess44 P92 (storage FUA-determinism probe) TESTED + REVERTED:
		 * two back-to-back FUA reads of the same bnobt block ALWAYS
		 * AGREED (P92 fired 0× at 2 nodes) → SCSI READ(16) FUA is
		 * deterministic/reliable; the storage is NOT returning stale on
		 * the FUA read.  So the stale V0 the allocator uses is a CACHED
		 * buffer (fua_fresh set, no FUA at modify time), not a bad read.
		 */
		n = atomic64_inc_return(&mxfs_buf_fua_ok);
		if ((n & 63) == 1)
			mxfs_idbg("mxfs: P26-INSTR buf-read-fua n=%llu (success path)\n",
				(unsigned long long)n);
		xfs_buf_ioend(bp);
		return 0;
	}
	if (rc == -EOPNOTSUPP) {
		n = atomic64_inc_return(&mxfs_buf_fua_fallback);
		if ((n & 63) == 1)
			mxfs_idbg("mxfs: P26-INSTR buf-read-fua FALLBACK to bio n=%llu\n",
				(unsigned long long)n);
		return -EOPNOTSUPP;
	}
	n = atomic64_inc_return(&mxfs_buf_fua_err);
	if ((n & 63) == 1)
		mxfs_idbg("mxfs: P26-INSTR buf-read-fua ERR n=%llu rc=%d daddr=0x%llx\n",
			(unsigned long long)n, rc,
			(unsigned long long)bp->b_maps[0].bm_bn);
	return rc;
}

/*
 * sess39: surgically force a buffer's CURRENT in-memory content to the
 * backing store with a FUA WRITE.  Metadata writes are not FUA, so an
 * iflushed dinode only reaches the SCST write cache; a peer's FUA READ of
 * the backing store misses it (cross-node empty-content).  Used by the
 * file-inode BAST-release to make di_size durable on the platter before the
 * DLM unlock — far cheaper than a device-wide blkdev_issue_flush per file.
 * Single-map buffers only (inode clusters qualify).  Returns 0 on success.
 */
int
mxfs_buf_write_fua(
	struct xfs_buf		*bp)
{
	uint64_t		lba_512;
	uint32_t		len;

	if (!bp || bp->b_map_count != 1 || !bp->b_addr)
		return -EOPNOTSUPP;

	len = BBTOB(bp->b_length);
	lba_512 = bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;

	return mxfs_pal_scsi_write_fua_bdev(bp->b_target->bt_bdev, lba_512,
					    bp->b_addr, len);
}

/*
 * Buffer I/O submission path, read or write. Asynchronous submission transfers
 * the buffer lock ownership and the current reference to the IO. It is not
 * safe to reference the buffer after a call to this function unless the caller
 * holds an additional reference itself.
 */
static void
xfs_buf_submit(
	struct xfs_buf	*bp)
{
	xfs_buf_submit_ex(bp, true);
}

/*
 * ccloop3e02 sess2: fresh=false is for the xfs_buf_ioend_handle_error
 * resubmit path ONLY — it re-dispatches an ALREADY-credited submission (the
 * original xfs_buf_submit's sync/async credit was never consumed, since the
 * error path bypasses the normal completion routing) and must not register
 * a second, unmatched credit.  Every other caller goes through the
 * xfs_buf_submit() wrapper above (fresh=true).
 */
static void
xfs_buf_submit_ex(
	struct xfs_buf	*bp,
	bool		fresh)
{
	/*
	 * sess121 (ccloop 4eef1f39) — write-side stale-AG-meta interlock.
	 * Set when the P93 detector below proves this is a prior-tenure stale
	 * bnobt/cntbt replay about to REVERT a peer's durable free-space split
	 * (the proven cross-node bnobt lost-update -> ltbno+ltlen>bno
	 * double-free shutdown).  Acted on just before bio submission: refresh
	 * the in-core image from the coherent device cache and complete the
	 * writeback WITHOUT issuing the stale physical write (GPT RULE-5
	 * design).  This is the ONLY chokepoint that catches xfsaild's
	 * independent AIL push, which the acquire/release-time invalidation
	 * hooks miss (P117/P121 never fire for an EX-held in-tenure push).
	 */
	bool mxfs_suppress_stale_agwrite = false;

	trace_xfs_buf_submit(bp, _RET_IP_);

	ASSERT(!(bp->b_flags & _XBF_DELWRI_Q));

	/*
	 * On log shutdown we stale and complete the buffer immediately. We can
	 * be called to read the superblock before the log has been set up, so
	 * be careful checking the log state.
	 *
	 * Checking the mount shutdown state here can result in the log tail
	 * moving inappropriately on disk as the log may not yet be shut down.
	 * i.e. failing this buffer on mount shutdown can remove it from the AIL
	 * and move the tail of the log forwards without having written this
	 * buffer to disk. This corrupts the log tail state in memory, and
	 * because the log may not be shut down yet, it can then be propagated
	 * to disk before the log is shutdown. Hence we check log shutdown
	 * state here rather than mount state to avoid corrupting the log tail
	 * on shutdown.
	 */
	if (bp->b_mount->m_log && xlog_is_shutdown(bp->b_mount->m_log)) {
		xfs_buf_ioend_fail(bp);
		return;
	}

	if (bp->b_flags & XBF_WRITE)
		xfs_buf_wait_unpin(bp);

	/*
	 * Make sure we capture only current IO errors rather than stale errors
	 * left over from previous use of the buffer (e.g. failed readahead).
	 */
	bp->b_error = 0;

	/*
	 * v0.10.33 (sess7 46efd8b6): drain any STALE completion token before a
	 * SYNC submit.  I/O owns the buffer lock until its ioend, and we hold
	 * the lock here, so no bio of ours can be in flight — any b_iowait
	 * token present now is a leftover from an unpaired emulated completion
	 * (mxfs skip arms call the full xfs_buf_ioend, and readahead-steal
	 * conversions changed XBF_ASYNC between deposit and consumption).
	 * With a stale token, xfs_buf_iowait returns BEFORE this submit's DMA
	 * lands and __xfs_buf_ioend CRC-verifies the PRE-DMA content — the
	 * perpetual EFSBADCRC read loop on a fully-valid LUN (run 164056Z
	 * test1: b_iowait.done=1 at rest, kcore-verified; every ls of the dir
	 * failed for 6 rounds while both raw paths served current bytes).
	 */
	/*
	 * sess6 (ccloop a864) ROOT FIX (dir_reuse@32/caw wedge#2a): snapshot the
	 * SYNC-vs-ASYNC submit intent NOW, under b_sema, into a field the racy
	 * completion path can trust.  XBF_ASYNC is a non-atomic b_flags bit that
	 * readahead / xfsaild-delwri / buf-item-unpin / inode-flush-fail set on
	 * this same buffer object; if one leaves it set at completion of a
	 * synchronous durable bwrite (mxfs_dir_data_owner_scan / bmbt_scan), the
	 * completion routers below take the async branch (queue_work / relse) and
	 * NEVER complete(&b_iowait) — the sync waiter (rm's per-unlink durable
	 * signal) hangs forever and the whole dir_reuse round wedges.  Routing on
	 * this stable snapshot instead of the live flag guarantees the waiter is
	 * woken (and the buffer is not double-relse'd).
	 */
	/*
	 * sess8 (ccloop a864): honor the sync submitter's b_mxfs_force_sync latch
	 * (set under b_sema by xfs_bwrite / _xfs_buf_read).  The bare
	 * !(XBF_ASYNC) test alone RACES a lock-free XBF_ASYNC set (buf-item unpin
	 * on another CPU) that can land between the submitter clearing XBF_ASYNC
	 * and this snapshot, latching sync intent false and stranding the waiter
	 * (residual wedge#2).  The latch is immune to that race.
	 *
	 * ccloop3e02 sess2: register this submission's wakeup obligation as an
	 * ADDITIVE credit (b_mxfs_sync_waiters) rather than overwriting a single
	 * per-buffer bool — see mxfs_buf_completion_wake_sync().  Only a FRESH
	 * submission registers a credit; the handle_error resubmit path
	 * (fresh=false) reuses the original, still-outstanding credit instead
	 * of registering a second one (see xfs_buf_submit_ex callers).
	 */
	{
		bool this_is_sync = bp->b_mxfs_force_sync ||
				     !(bp->b_flags & XBF_ASYNC);

		if (fresh && this_is_sync)
			atomic_inc(&bp->b_mxfs_sync_waiters);
		mxfs_buf_ev(bp, MXFS_BEV_SUBMIT);	/* sess9 DIAG: force_sync bit still = pre-consume latch */
		bp->b_mxfs_force_sync = false;			/* consumed this submit */
		bp->b_mxfs_ioend_seen = 0;	/* sess6 DIAG: count completions for THIS submit */
		bp->b_mxfs_relse_seen = 0;

		if (this_is_sync)
			reinit_completion(&bp->b_iowait);
	}

	/*
	 * sess29(ccloop) WRITE-SIDE 3-WAY MERGE: before the verifier stamps the
	 * CRC, graft a peer's disk-only dirents into a MERGE-NEEDED dir DATA block
	 * so this async destage cannot revert a peer's durable add (the proven
	 * dir_reuse write-side TOCTOU).  Gated on dir_write_merge; no-op otherwise.
	 */
	if (bp->b_flags & XBF_WRITE)
		mxfs_dir3_data_writemerge(bp);

	if ((bp->b_flags & XBF_WRITE) && !xfs_buf_verify_write(bp)) {
		/*
		 * sess56 (ccloop 14d31183) P56-INCORE-DIFF — the write verifier
		 * rejected this in-core buffer (SHUTDOWN_CORRUPT_INCORE).  For a
		 * dir3 block/data buffer, P54 already proves the ON-DISK copy is
		 * valid, so the in-core image was corrupted by a local modify.
		 * Plain-read the coherent on-disk copy and log the FIRST byte
		 * divergence + the inode-log-item set on the buffer — the diff IS
		 * the corrupting modification, and b_li_list names which inode's
		 * RMW produced it.  Fires only on the failing path (rare).
		 */
		if ((bp->b_ops == &xfs_dir3_block_buf_ops ||
		     bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
		     bp->b_ops == &xfs_dir3_leafn_buf_ops) &&
		    bp->b_addr && bp->b_map_count == 1) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t dlen = BBTOB(bp->b_length);
			uint64_t dlba = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;
			void *dtmp = (dlen && (dlen & 511) == 0) ?
				kmalloc(dlen, GFP_NOFS) : NULL;
			struct xfs_log_item *lip;
			int nli = 0;

			list_for_each_entry(lip, &bp->b_li_list, li_bio_list)
				nli++;

			if (dtmp && mxfs_pal_bdev_read_plain_bdev(
				bp->b_target->bt_bdev, dlba, dtmp, dlen) == 0) {
				uint32_t i, first = dlen, ndiff = 0, b = 0;
				const unsigned char *ic = bp->b_addr;
				const unsigned char *dk = dtmp;

				for (i = 0; i < dlen; i++) {
					if (ic[i] != dk[i]) {
						if (first == dlen)
							first = i;
						ndiff++;
					}
				}
				b = (first < dlen && dlen >= 8) ?
					min(first & ~7U, dlen - 8U) : 0;
				pr_warn("mxfs: P56-INCORE-DIFF daddr=%lld len=%u li_count=%d first_diff=0x%x ndiff=%u base=0x%x incore=%02x%02x%02x%02x%02x%02x%02x%02x disk=%02x%02x%02x%02x%02x%02x%02x%02x comm=%s realns=%llu\n",
					(long long)bp->b_maps[0].bm_bn, dlen, nli,
					first, ndiff, b,
					ic[b], ic[b+1], ic[b+2], ic[b+3],
					ic[b+4], ic[b+5], ic[b+6], ic[b+7],
					dk[b], dk[b+1], dk[b+2], dk[b+3],
					dk[b+4], dk[b+5], dk[b+6], dk[b+7],
					current->comm,
					(unsigned long long)ktime_get_real_ns());
			}
			if (dtmp)
				kfree(dtmp);

			/* Also identify each inode whose log item rides this buf. */
			list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
				if (lip->li_type == XFS_LI_BUF)
					pr_warn("mxfs: P56-INCORE-DIFF-LI type=BUF\n");
			}
		}
		xfs_force_shutdown(bp->b_mount, SHUTDOWN_CORRUPT_INCORE);
		xfs_buf_ioend(bp);
		return;
	}

	/*
	 * sess35 run14d: the content snapshot leaving for disk includes every
	 * modification logged so far — record that.  Mirrors the moment the
	 * write verifier stamps li_lsn into the payload, but as a node-local
	 * counter (see b_mxfs_written_seq in xfs_buf.h).
	 *
	 * sess42(ccloop) RULE-4 PROVEN ROOT FIX: for a SHARED DIR-METADATA write
	 * the stamp must happen at I/O COMPLETION, not here at SUBMIT.  Stamping
	 * here marks the buffer "destaged" (logged_seq == written_seq) the instant
	 * the write is submitted — before the bio has physically landed on the
	 * shared LUN.  mxfs_dir_buf_is_undestaged() then reports the block durable,
	 * so the EX-release durability fence (mxfs_dir_data_durable) hands the dir
	 * lock to a peer while the just-added dirent's data block is still in
	 * flight (or was skip-emulated with no bio at all).  The peer cold-reads
	 * the stale LUN, RMWs, and the entry is durably dropped — the dir_reuse
	 * readdir=799 insert-loss (PROVEN this session: sum of on-disk per-daddr
	 * dirent counts = 801, the victim never reaches disk).  Deferring the
	 * stamp to __xfs_buf_ioend (gated on b_mxfs_dir_wr_counted, which is set
	 * ONLY when a real bio is issued in xfs_buf_submit_bio) keeps the block
	 * provably undestaged until its bio truly completes, so the fence waits.
	 * Non-dir buffers (and skip-emulated writes) keep the submit-time stamp.
	 */
	if (bp->b_flags & XBF_WRITE) {
		extern int mxfs_dir_wseq_at_completion;
		bool defer = mxfs_dir_wseq_at_completion && bp->b_mount &&
			bp->b_mount->m_mxfs_dlm &&
			!mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
			(bp->b_ops == &xfs_dir3_data_buf_ops ||
			 bp->b_ops == &xfs_dir3_block_buf_ops ||
			 bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
			 bp->b_ops == &xfs_dir3_leafn_buf_ops ||
			 bp->b_ops == &xfs_dir3_free_buf_ops ||
			 bp->b_ops == &xfs_da3_node_buf_ops ||
			 /* sess6 (46efd8b6): bmbt rides the same completion-
			  * stamp discipline — see the counted list in
			  * xfs_buf_submit_bio.  A submit-time stamp marked an
			  * in-flight (or skip-emulated) bmbt write "destaged"
			  * so mxfs_dir_bmbt_scan's fence passed while the
			  * committed leaf image had not landed. */
			 bp->b_ops == &xfs_bmbt_buf_ops);

		if (!defer)
			bp->b_mxfs_written_seq = bp->b_mxfs_logged_seq;
	}

	/*
	 * P35E (RULE 4, sess35 run14d): dir-block write lineage.  The CRC
	 * (payload bytes 4-7, already stamped by xfs_buf_verify_write above)
	 * uniquely identifies the image version; logging every dir3
	 * block/data write submit cluster-wide lets a lost-dirent run be
	 * reconstructed as "who wrote which version when" and catches a
	 * superseded image being re-written over a peer's newer block.
	 * Scoped to XDB3/XDD3 magics (the hot shared dir's blocks).
	 * sess38 run14d: gated behind mxfs.dirwr/mxfs.instr for ship —
	 * fires per dir3 block write submit, diagnostic only.
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr) {
		const unsigned char *p35 = bp->b_addr;

		if (p35[0] == 0x58 && p35[1] == 0x44 &&
		    (p35[2] == 0x42 || p35[2] == 0x44) && p35[3] == 0x33) {
			/* sess16: dump dirent names in the block being written so a
			 * concurrent-RMW clobber is visible (one node writes blk=0
			 * WITHOUT the peer's just-added entry). */
			char			names[224];
			struct xfs_da_geometry	*geo =
				bp->b_mount ? bp->b_mount->m_dir_geo : NULL;
			int			pos = 0, guard = 0, nent = 0;
			unsigned int		off, end;

			names[0] = '\0';
			if (geo) {
				if (p35[2] == 0x42) {	/* XDB3 block-format */
					struct xfs_dir2_data_hdr *hdr =
						(void *)bp->b_addr;
					struct xfs_dir2_block_tail *btp =
						xfs_dir2_block_tail_p(geo, hdr);
					end = (unsigned int)((char *)btp -
							     (char *)bp->b_addr);
				} else {
					end = geo->blksize;
				}
				if (end > geo->blksize)
					end = geo->blksize;
				off = geo->data_entry_offset;
				while (off < end && pos < (int)sizeof(names) - 14 &&
				       guard++ < 4096) {
					struct xfs_dir2_data_unused *dup =
						(void *)((char *)bp->b_addr + off);
					struct xfs_dir2_data_entry *dep;
					int nl;

					if (be16_to_cpu(dup->freetag) ==
					    XFS_DIR2_DATA_FREE_TAG) {
						unsigned int len =
							be16_to_cpu(dup->length);
						if (len == 0)
							break;
						off += len;
						continue;
					}
					dep = (void *)((char *)bp->b_addr + off);
					if (dep->namelen == 0)
						break;
					nl = min_t(int, dep->namelen, 13);
					pos += scnprintf(names + pos,
						sizeof(names) - pos, "%.*s ",
						nl, dep->name);
					nent++;
					off += xfs_dir2_data_entsize(
						bp->b_mount, dep->namelen);
				}
			}
			pr_warn("mxfs: P35E-DIRWR daddr=%lld magic=%c%c%c%c crc=%02x%02x%02x%02x lseq=%u wseq=%u in_ail=%d comm=%s nent=%d names=[%s]\n",
				(long long)bp->b_maps[0].bm_bn,
				p35[0], p35[1], p35[2], p35[3],
				p35[4], p35[5], p35[6], p35[7],
				bp->b_mxfs_logged_seq, bp->b_mxfs_written_seq,
				!!(bp->b_log_item &&
				   test_bit(XFS_LI_IN_AIL,
					    &bp->b_log_item->bli_item.li_flags)),
				current->comm, nent, names);

			/*
			 * sess17 (ccloop) DECISIVE clobber detector.  During the
			 * crash_consistency create-only phase a dir DATA block's
			 * dirent count is MONOTONIC NON-DECREASING (only adds, no
			 * removes).  So any write whose nent is LOWER than the
			 * highest nent previously written to the SAME daddr (same
			 * owner incarnation) is a stale-base clobber that drops
			 * committed dirents.  Direct-mapped per-daddr table; the
			 * owner ino (dir3 block header) disambiguates daddr reuse.
			 * comm identifies the vector (xfsaild vs release-drain
			 * kworker vs dd RMW).  Gated by dirwr/instr; diagnostic.
			 */
			{
				static DEFINE_SPINLOCK(p_clob_lock);
				static struct {
					long long daddr;
					uint64_t  owner;
					int       max_nent;
				} p_clob[512];
				uint64_t owner = be64_to_cpu(
					((struct xfs_dir3_blk_hdr *)
					 bp->b_addr)->owner);
				long long daddr = (long long)bp->b_maps[0].bm_bn;
				unsigned idx = ((unsigned)(daddr >> 3)) & 511;
				int prev = -1;

				spin_lock(&p_clob_lock);
				if (p_clob[idx].daddr != daddr ||
				    p_clob[idx].owner != owner) {
					p_clob[idx].daddr = daddr;
					p_clob[idx].owner = owner;
					p_clob[idx].max_nent = nent;
				} else {
					prev = p_clob[idx].max_nent;
					if (nent > prev)
						p_clob[idx].max_nent = nent;
				}
				spin_unlock(&p_clob_lock);

				if (prev >= 0 && nent < prev)
					pr_warn("mxfs: P17-CLOBBER-DROP daddr=%lld owner=%llu nent=%d < prev_max=%d lseq=%u wseq=%u in_ail=%d comm=%s names=[%s]\n",
						daddr,
						(unsigned long long)owner,
						nent, prev,
						bp->b_mxfs_logged_seq,
						bp->b_mxfs_written_seq,
						!!(bp->b_log_item &&
						   test_bit(XFS_LI_IN_AIL,
						    &bp->b_log_item->bli_item.li_flags)),
						current->comm, names);
			}
		}
	}

	/*
	 * sess89 PROBE-A (Gemini RULE-5): SMOKING-GUN for the cross-node bnobt
	 * lost-update / double-alloc.  If this node WRITES an AG free-space or
	 * header buffer (agf/agfl/agi/bnobt/cntbt/inobt/finobt) while it does
	 * NOT hold the AG's DLM grant (not cached, no local holder, not mid
	 * demote-drain, no deferred release), the write reverts the on-disk
	 * image of an AG a PEER now owns -> erases the peer's just-committed
	 * allocation -> block double-allocated -> double-free shutdown.  The
	 * suspected source (Gemini): a buffer enters this node's AIL AFTER
	 * bast_work_fn released the grant (CIL->AIL insertion raced the drain's
	 * log_force), and xfsaild later flushes the STALE in-core image to disk.
	 * current->comm == "xfsaild/*" at this trap == 100% confirmation.
	 * Cheap (in-core field reads, racy-but-diagnostic), always-on, fires
	 * only on the illegal write.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_pag &&
	    (bp->b_ops == &xfs_agf_buf_ops || bp->b_ops == &xfs_agfl_buf_ops ||
	     bp->b_ops == &xfs_agi_buf_ops || bp->b_ops == &xfs_bnobt_buf_ops ||
	     bp->b_ops == &xfs_cntbt_buf_ops || bp->b_ops == &xfs_inobt_buf_ops ||
	     bp->b_ops == &xfs_finobt_buf_ops)) {
		struct xfs_perag *pa = bp->b_pag;
		bool held = pa->pag_dlm_cached || pa->pag_dlm_holders > 0 ||
			    pa->pag_dlm_demoting || pa->pag_dlm_release_pending;
		if (!held) {
			static atomic_t pa_dumped = ATOMIC_INIT(0);
			pr_warn_ratelimited("mxfs: PROBE-A AG-META-WRITE-NOT-HELD agno=%u daddr=%lld ops=%s comm=%s pid=%d cached=%d holders=%d demoting=%d relpend=%d bflags=0x%x\n",
				pag_agno(pa), (long long)bp->b_maps[0].bm_bn,
				(bp->b_ops == &xfs_bnobt_buf_ops ? "bno" :
				 bp->b_ops == &xfs_cntbt_buf_ops ? "cnt" :
				 bp->b_ops == &xfs_agf_buf_ops ? "agf" :
				 bp->b_ops == &xfs_agi_buf_ops ? "agi" :
				 bp->b_ops == &xfs_agfl_buf_ops ? "agfl" :
				 bp->b_ops == &xfs_inobt_buf_ops ? "ino" : "fino"),
				current->comm, current->pid,
				pa->pag_dlm_cached, pa->pag_dlm_holders,
				pa->pag_dlm_demoting, pa->pag_dlm_release_pending,
				bp->b_flags);
			if (atomic_cmpxchg(&pa_dumped, 0, 1) == 0)
				dump_stack();
		}
		/*
		 * sess22 (ccloop 4eef1f39) P125-AG-DIVERGE — NEWARCH §4 / Phase-1
		 * permanent exclusion-divergence assertion, applied to AG locks
		 * (the inode chokepoint analog the design deferred).
		 *
		 * sess90 proved PROBE-A (in-core held) NEVER fires: XFS only writes
		 * AG metadata when in-core believes it holds the AG.  But the
		 * recurring bnobt double-free is an IN-TENURE clobber with no
		 * release/drain — which means in-core thinks we hold the AG EX while
		 * the ON-DISK CAW holder bit for this node is already 0 (a peer can
		 * then own the AG, modify the free-space tree durably, and our
		 * diverged in-core image — pushed by xfsaild or a fast-path RMW —
		 * reverts it).  No notification/fence can fix that: the exclusion
		 * bitmap itself is wrong.  This is exactly NEWARCH §4's "kill P106"
		 * prerequisite, for AGs.
		 *
		 * mxfs_v5_dlm_ag_held() reads the on-disk CAW slot (1 = this node
		 * holds it on disk, 0 = not).  When in-core says held but on-disk
		 * says NOT held, that is the divergence.  Scoped to the free-space-
		 * relevant buffers (bnobt/cntbt/agf/agi) to bound the per-write slot
		 * read; capped stacks; log-only (RULE-4: prove the AG-exclusion
		 * divergence is the bnobt root before the chokepoint refactor that
		 * couples the on-disk bit to in-core mode).
		 */
		/* ccloop 72513a13 sess3: off-by-default — this on-disk slot
		 * read (a probe-chain of FUA SCSI reads) ran on EVERY
		 * AG-metadata write and cost xfsaild 5.3 FUA reads per create
		 * (kprobe-counted).  mxfs.p125_ag_diverge=1 re-arms it. */
		if (mxfs_p125_ag_diverge && held &&
		    (bp->b_ops == &xfs_bnobt_buf_ops ||
		     bp->b_ops == &xfs_cntbt_buf_ops ||
		     bp->b_ops == &xfs_agf_buf_ops ||
		     bp->b_ops == &xfs_agi_buf_ops)) {
			int p125_od = mxfs_v5_dlm_ag_held(
				bp->b_mount->m_mxfs_dlm, pag_agno(pa));
			if (p125_od == 0) {
				static atomic_t p125_n = ATOMIC_INIT(0);
				int p125_seq = atomic_inc_return(&p125_n);
				int p125_exn = -1;
				int p125_exp = mxfs_v5_dlm_ag_ex_count(
					bp->b_mount->m_mxfs_dlm,
					pag_agno(pa), &p125_exn);

				pr_warn_ratelimited("mxfs: P125-AG-DIVERGE#%d agno=%u daddr=%lld %s in-core HELD (cached=%d holders=%d demoting=%d relpend=%d) but ON-DISK holder bit=0 — exclusion divergence; peer can own this AG while we write our diverged image. ondisk_ex_pop=%d ex_nslots=%d comm=%s pid=%d\n",
					p125_seq, pag_agno(pa),
					(long long)bp->b_maps[0].bm_bn,
					(bp->b_ops == &xfs_bnobt_buf_ops ? "bno" :
					 bp->b_ops == &xfs_cntbt_buf_ops ? "cnt" :
					 bp->b_ops == &xfs_agf_buf_ops ? "agf" :
					 "agi"),
					pa->pag_dlm_cached, pa->pag_dlm_holders,
					pa->pag_dlm_demoting,
					pa->pag_dlm_release_pending,
					p125_exp, p125_exn,
					current->comm, current->pid);
				if (p125_seq <= 16)
					dump_stack();
			}
		}
	}

	/*
	 * sess44 P88: catch the bnobt clobbering write.  The bnobt lost-update
	 * (xfs_alloc.c:2231 overlap) reverts the on-disk bnobt to the EXACT
	 * mkfs-pristine whole-AG-free record (numrecs==1).  P70=0 proved the
	 * alloc RMW is self-consistent, so a CORRECT V1 (allocations removed,
	 * higher numrecs) is later OVERWRITTEN on disk by a pristine V0.  Log
	 * every multi-node bnobt/cntbt WRITE with low numrecs (<=2) plus the
	 * first record — a numrecs==1 giant-free write is the clobber.  Trace
	 * the stack to find which buffer/path produced it.  Ratelimited.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_bnobt_buf_ops || bp->b_ops == &xfs_cntbt_buf_ops)) {
		struct xfs_btree_block *p88 = bp->b_addr;
		__u16 nr = be16_to_cpu(p88->bb_numrecs);

		if (nr <= 2 && be16_to_cpu(p88->bb_level) == 0) {
			__be32 *r0 = (__be32 *)
				((char *)p88 + XFS_BTREE_SBLOCK_CRC_LEN);
			/*
			 * sess44 P95 (perag/gen mis-association check) REVERTED:
			 * fired 0× — the buffer's b_pag correctly matches its
			 * daddr's AG, so the gen IS compared against the right AG.
			 * NOT a perag mis-association.
			 */
			/*
			 * sess44 P88b: decisive fork — FUA-read the CURRENT
			 * on-disk content of this block and compare to what we
			 * are about to write (pristine V0).  disk_differs=1 =>
			 * on-disk has DIFFERENT (presumably V1 allocated)
			 * content and we are about to OVERWRITE it with pristine
			 * => writeback/read-staleness (an old V0 buffer clobbers
			 * a durable V1; the durability-at-release path did make
			 * V1 durable, the bug is our stale buffer being written).
			 * disk_differs=0 => on-disk is also pristine => the
			 * release durability path failed to make V1 durable.
			 */
			int p88_dd = mxfs_ag_buf_disk_differs(bp);
			/* sess44 P88c: if disk_differs=1 (we clobber durable V1
			 * with stale V0), log the buffer's gen-coherency state.
			 * buf_gen==pag_gen + FUA_FRESH set => the stale buffer was
			 * treated as "fresh at current gen" so the read-hook never
			 * invalidated it and the FUA gate never re-pierced it =
			 * MASKED-STALE (the gen-stamp-on-fresh-read locked in a
			 * V0 read that raced a peer's release-destage). */
			unsigned long long p88_bg = bp->b_mxfs_ag_gen;
			unsigned long long p88_pg = bp->b_pag ?
				bp->b_pag->pag_dlm_meta_gen : 0;
			/*
			 * sess47 DECISIVE TEST: at the bnobt WRITE, do we
			 * actually HOLD this AG's DLM grant on disk?  In the
			 * cached-AG model we should hold it (cached EX bit) for
			 * any write we originate.  ag_held==0 at a bnobt write
			 * => we are writing AG free-space metadata WITHOUT the
			 * lock (released/BAST'd before our dirty buffer drained,
			 * or a false-cache ABA) — Architectural-Invariant-1
			 * violation and the direct clobber path.  One-shot
			 * dump_stack when a true-pristine (numrecs==1) write
			 * lands while NOT held AND disk has a different (real)
			 * version — that is the producer of the lost update.
			 */
			int p88_held = -1;
			uint32_t p88_agno = bp->b_pag ?
				pag_agno(bp->b_pag) : (uint32_t)-1;
			/* sess52 RULE-4 concurrent-EX measurement: when the
			 * bnobt write clobbers a durable peer version
			 * (disk_differs=1) while gen says fresh, read the AG's
			 * CAW probe chain RAW and report popcount(holders_ex).
			 * ex_pop>1 PROVES two nodes hold EX on this AG at once
			 * (the unproven root); ex_n>1 == sess47 claim-race
			 * (two slots, same AG).  Only on disk_differs to keep
			 * the steady-state cost off the hot write path. */
			int p88_ex_pop = -1, p88_ex_n = -1;
			if (bp->b_pag) {
				p88_held = mxfs_v5_dlm_ag_held(
					bp->b_mount->m_mxfs_dlm, p88_agno);
				if (p88_dd == 1)
					p88_ex_pop = mxfs_v5_dlm_ag_ex_count(
						bp->b_mount->m_mxfs_dlm,
						p88_agno, &p88_ex_n);
			}
			/*
			 * sess53 RULE-4: WHY is this bnobt buffer gen-fresh
			 * (buf_gen==pag_gen) yet content-stale (disk_differs=1)?
			 * Mirror P70's buffer-state fields.  If dirty/in_ail/pin/
			 * delwri are set at the clobbering write, the gen-
			 * invalidation hook (mxfs_ag_meta_invalidate_stale)
			 * COULD NOT have re-read it (same un-refreshable-buffer
			 * limitation as the dir-block hook) => the stale read was
			 * locked in.  All clear => the buffer is genuinely idle
			 * but was gen-STAMPED fresh without a re-read. */
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			struct xfs_buf_log_item *p88_bip = bp->b_log_item;
			int p88_dirty = (p88_bip && test_bit(XFS_LI_DIRTY,
					&p88_bip->bli_item.li_flags)) ? 1 : 0;
			int p88_inail = (p88_bip && test_bit(XFS_LI_IN_AIL,
					&p88_bip->bli_item.li_flags)) ? 1 : 0;
			int p88_pin = xfs_buf_ispinned(bp) ? 1 : 0;
			int p88_delwri = (bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0;
			/* sess79 RULE-4 DIRECTION PROBE: dump the on-disk
			 * numrecs+rec0 (only when disk_differs, to keep cost off
			 * the steady-state path).  disk_nr > our nr => our
			 * in-core buffer is BEHIND the medium (peer wrote newer)
			 * => we are about to CLOBBER a durable peer version with
			 * a stale cached/in-AIL buffer.  disk_nr < our nr => we
			 * are ahead (legit drain pending). */
			uint16_t p88_dnr = 0; uint32_t p88_ds0 = 0, p88_dl0 = 0;
			int p88_dprc = -77;
			if (p88_dd == 1) {
				extern int mxfs_ag_buf_disk_bnobt(struct xfs_buf *,
					uint16_t *, uint32_t *, uint32_t *);
				p88_dprc = mxfs_ag_buf_disk_bnobt(bp, &p88_dnr,
					&p88_ds0, &p88_dl0);
			}
			pr_warn_ratelimited("mxfs: P88-INSTR bnobt-WRITE-low-numrecs daddr=%lld %s agno=%u numrecs=%u level=%u rec0=[start=%u len=%u] disk_nr=%u disk_rec0=[start=%u len=%u] dprc=%d bflags=0x%x disk_differs=%d ag_held=%d buf_gen=%llu pag_gen=%llu fua_fresh=%d ex_pop=%d ex_nslots=%d dirty=%d in_ail=%d pin=%d delwri=%d bp=%p hold=%d lsn=%llu\n",
				(long long)bp->b_maps[0].bm_bn,
				bp->b_ops == &xfs_bnobt_buf_ops ? "bno" : "cnt",
				(unsigned)p88_agno,
				(unsigned)nr, (unsigned)be16_to_cpu(p88->bb_level),
				(unsigned)be32_to_cpu(r0[0]),
				(unsigned)be32_to_cpu(r0[1]),
				(unsigned)p88_dnr, (unsigned)p88_ds0,
				(unsigned)p88_dl0, p88_dprc,
				bp->b_flags, p88_dd, p88_held, p88_bg, p88_pg,
				(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
				p88_ex_pop, p88_ex_n,
				p88_dirty, p88_inail, p88_pin, p88_delwri,
				bp, bp->b_hold,
				(unsigned long long)(p88_bip ?
					p88_bip->bli_item.li_lsn : 0));
			}
			if (nr == 1 && p88_dd == 1 && p88_held == 0) {
				static bool p88_dumped;
				if (!p88_dumped) {
					p88_dumped = true;
					pr_warn("mxfs: P88-CLOBBER-PRODUCER agno=%u writing pristine bnobt while NOT holding AG DLM (disk has real V1) — stack:\n",
						(unsigned)p88_agno);
					dump_stack();
				}
			}
			/*
			 * sess93 DECISIVE PROBE (RULE 4): the REVERT-clobber.
			 * sess90 refuted the xfsaild-not-held theory (PROBE-A 0x)
			 * and the F/TOCTOU theory is refuted by code-reading
			 * (the FUA read is locked+synchronous — no concurrent
			 * txn can modify the buffer mid-read).  So the durable
			 * split is reverted by a pristine bnobt write that occurs
			 * while the AG IS HELD.  Fire on the PRECISE revert
			 * condition: on-disk numrecs is GREATER than what we are
			 * about to write (disk has the split/allocations; we are
			 * overwriting it with a lower-numrecs pristine view) =
			 * a lost-update clobber regardless of held state.  Bounded
			 * to 8 stacks (NOT ratelimited / NOT held-gated, unlike
			 * P88-CLOBBER-PRODUCER above which only caught not-held).
			 * The stack + comm + held + gen + bp identify the producer:
			 * xfsaild delwri flush vs release drain vs a fresh alloc
			 * txn vs cache writeback, and same-bp (in-core revert) vs
			 * different-bp (aliasing).
			 */
			if (p88_dd == 1) {
				extern int mxfs_ag_buf_disk_bnobt(struct xfs_buf *,
					uint16_t *, uint32_t *, uint32_t *);
				uint16_t p93_dnr = 0;
				uint32_t p93_s0 = 0, p93_l0 = 0;

				if (mxfs_ag_buf_disk_bnobt(bp, &p93_dnr,
						&p93_s0, &p93_l0) == 0 &&
				    p93_dnr > nr) {
					extern bool mxfs_buf_is_undestaged(
						struct xfs_buf *);
					struct xfs_buf_log_item *p93_bip =
						bp->b_log_item;
					static atomic_t p93_n = ATOMIC_INIT(0);
					int p93_seq = atomic_inc_return(&p93_n);
					bool p93_inail = p93_bip &&
						test_bit(XFS_LI_IN_AIL,
							&p93_bip->bli_item.li_flags);
					bool p93_dirty = p93_bip &&
						test_bit(XFS_LI_DIRTY,
							&p93_bip->bli_item.li_flags);

					/*
					 * sess121: SUPPRESS this write iff it is a
					 * proven stale prior-tenure replay — disk has
					 * MORE records than we are about to write
					 * (p93_dnr > nr = a peer's durable split we
					 * would revert), AND the buffer carries NO
					 * this-node-ahead content: it is in-AIL but
					 * clean (committed, already destaged at our
					 * last release), not dirty/pinned/delwri, and
					 * mxfs_buf_is_undestaged()==false (its logged
					 * content is already on disk; li_lsn <=
					 * payload_lsn).  An UN-destaged / dirty / pinned
					 * buffer is genuinely this-node-ahead (a legit
					 * local free-everything -> nr=1) and MUST be
					 * written, so it is excluded.  Acted on at the
					 * submission point below. */
					/*
					 * sess23 (ccloop 4eef1f39) — DISABLED.
					 * RULE-4 + Gemini re-diagnosis: the
					 * "disk_nr > in-core nr => stale revert"
					 * discriminator is FUNDAMENTALLY BROKEN.
					 * numrecs LEGITIMATELY DECREASES on a
					 * coalescing free (one freed block bridges
					 * two free extents -> 3 records merge to 1)
					 * and on an exact-match allocation (a whole
					 * free extent record is removed).  When THIS
					 * node holds the AG, cold-reads the peer's
					 * nr=3 image, then its own rename/unlink
					 * frees blocks and the bnobt coalesces to
					 * nr=2, the in-core nr=2 is CORRECT and
					 * AHEAD of disk (our free not yet written).
					 * Suppressing that write (skip + refresh
					 * from coherent disk) DISCARDS our committed
					 * free, leaving the on-disk bnobt at nr=3
					 * while cntbt+AGF freeblks DID land -> the
					 * AG-meta set is torn in half ->
					 * xfs_agf_verify "freeblks != sum(bnobt)"
					 * corruption AND a later free of a block the
					 * skipped bnobt still lists FREE ->
					 * ltbno+ltlen>bno in-core double-free.  The
					 * acquire-invalidation + release-drain fences
					 * are proven tight this run (P79=0, P14
					 * trylock-fail=0, P126=0), so NO stale prior-
					 * tenure buffer can reach here; the write is
					 * always this-tenure-authoritative and MUST
					 * proceed.  Detector below stays LOG-ONLY.
					 */
					(void)p93_inail; (void)p93_dirty;

					if (unlikely(mxfs_dirwr_enabled ||
						     mxfs_instr_enabled) &&
					    p93_seq <= 8) {
						pr_warn("mxfs: P93-REVERT-CLOBBER#%d agno=%u daddr=%lld writing nr=%u over disk_nr=%u held=%d bp=%p comm=%s pid=%d buf_gen=%llu pag_gen=%llu fua_fresh=%d dirty=%d in_ail=%d pin=%d delwri=%d hold=%d — reverting durable bnobt split; stack:\n",
							p93_seq, (unsigned)p88_agno,
							(long long)bp->b_maps[0].bm_bn,
							(unsigned)nr, (unsigned)p93_dnr,
							p88_held, bp, current->comm,
							current->pid, p88_bg, p88_pg,
							(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
							(p93_bip && test_bit(XFS_LI_DIRTY,
								&p93_bip->bli_item.li_flags)) ? 1 : 0,
							(p93_bip && test_bit(XFS_LI_IN_AIL,
								&p93_bip->bli_item.li_flags)) ? 1 : 0,
							xfs_buf_ispinned(bp) ? 1 : 0,
							(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
							bp->b_hold);
						dump_stack();
					}
				}
			}
		}
	}

	/*
	 * sess22 (ccloop 4eef1f39) P124 — ALLOCATION-REVERT detector (RULE 4).
	 * P93/P122 catch ONLY the split-revert direction (disk_nr > nr) and are
	 * gated on nr<=2.  The remaining durable bnobt-lost-update
	 * (P47 DISK-LIVE-same-gen / P81 disk_claims_freed=1 = on-disk inode owns a
	 * block the bnobt lists FREE) is the OPPOSITE direction: a prior-tenure
	 * stale bnobt/cntbt buffer pushed by xfsaild RE-ADDS free space that a
	 * peer's durable ALLOCATION removed (disk_nr < nr, or an equal-numrecs
	 * record shrink/grow that re-frees an allocated block).  P93 misses it
	 * because of the nr<=2 gate and the disk_nr>nr-only condition.
	 *
	 * Fire for ANY numrecs/level when the buffer carries NO this-node-ahead
	 * content (in_ail && !dirty && !pin && !delwri && !undestaged — the same
	 * prior-tenure-stale signature P122 uses) AND the COHERENT on-disk image
	 * (PLAIN read = peer-visible SCST write-back cache under fua_disable=1;
	 * FUA would read the stale platter and miss it) differs from what we are
	 * about to write.
	 *
	 * sess22 RULE-4 2b: PROVEN this run — P124 fired on all 4 nodes with
	 * dir=ALLOC-REVERT(disk<mine) and dir=EQNR-CONTENT-DIFF from comm=xfsaild,
	 * the exact directions P93/P122 miss.  So this is now a PREVENTER, not
	 * just a probe: it GENERALIZES the P122 split-revert interlock to ALL
	 * revert directions using the COHERENT plain read (vs P93/P122's FUA read
	 * that only sees durable-on-platter state).  A buffer matching the
	 * prior-tenure-stale signature carries NO this-node-ahead content, so any
	 * difference from the coherent on-disk image means our write can ONLY
	 * revert a peer's durable change — refresh from coherent cache + skip
	 * (the shared action at the mxfs_suppress_stale_agwrite block below) is
	 * always correct, exactly as for P122.  The pr_warn+stack stays capped at
	 * 16; the suppression itself is uncapped.
	 *
	 * sess6 (ccloop 186320ae): instr-only.  The signature's "carries NO
	 * this-node-ahead content" premise does not hold for a sole-EX-holder
	 * under sustained load (2/caw soak): with no release/BAST there is no
	 * destage, so committed-ahead bnobt content legitimately sits in the AIL
	 * and every xfsaild push differs from disk (EQNR-CONTENT-DIFF, in-core
	 * one allocation AHEAD — P88 companion showed disk catching up each
	 * step, 33->34->35->36, nothing reverted).  The revert family this
	 * probe chased is fixed at the AG acquire path (probe is log-only by
	 * design, see above); its dump_stack under dirwr=1 fails soak's
	 * clean-dmesg criterion on healthy traffic.
	 */
	if (unlikely(mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_map_count == 1 && bp->b_target && bp->b_target->bt_bdev &&
	    (bp->b_ops == &xfs_bnobt_buf_ops || bp->b_ops == &xfs_cntbt_buf_ops)) {
		struct xfs_buf_log_item *p124_bip = bp->b_log_item;
		bool p124_inail = p124_bip && test_bit(XFS_LI_IN_AIL,
				&p124_bip->bli_item.li_flags);
		bool p124_dirty = p124_bip && test_bit(XFS_LI_DIRTY,
				&p124_bip->bli_item.li_flags);
		extern bool mxfs_buf_is_undestaged(struct xfs_buf *);

		if (p124_inail && !p124_dirty && !xfs_buf_ispinned(bp) &&
		    !(bp->b_flags & _XBF_DELWRI_Q) &&
		    !mxfs_buf_is_undestaged(bp)) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t p124_len = BBTOB(bp->b_length);
			uint64_t p124_lba = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;
			void *p124_tmp = ((p124_len & 511) == 0 && p124_len) ?
				kmalloc(p124_len, GFP_NOFS) : NULL;

			if (p124_tmp &&
			    mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
				p124_lba, p124_tmp, p124_len) == 0 &&
			    memcmp(p124_tmp, bp->b_addr, p124_len) != 0) {
				struct xfs_btree_block *p124_mine = bp->b_addr;
				struct xfs_btree_block *p124_disk = p124_tmp;
				uint16_t p124_mnr =
					be16_to_cpu(p124_mine->bb_numrecs);
				uint16_t p124_dnr =
					be16_to_cpu(p124_disk->bb_numrecs);
				static atomic_t p124_n = ATOMIC_INIT(0);
				int p124_seq = atomic_inc_return(&p124_n);

				/*
				 * sess22: suppression REVERTED — generalizing the
				 * P122 refresh+skip to the alloc-revert/eqnr direction
				 * regressed cache_coherency to 0/4 with a new "Corruption
				 * of in-memory data" shutdown (xfs_buf.c:1887): refreshing
				 * ONE bnobt buffer from coherent disk desyncs it from the
				 * sibling cntbt/AGF in-core image (sess118 lesson).  The
				 * write side is the wrong layer.  P124 stays LOG-ONLY: it
				 * proves the producer = xfsaild pushing a STALE cached
				 * prior-tenure bnobt image while we legitimately hold the
				 * AG (P125=0) — an acquire-invalidation-fence (Inv-2)
				 * failure, fixed at the AG acquire path, not here.
				 */
				if (p124_seq <= 16) {
					pr_warn("mxfs: P124-ALLOC-REVERT#%d %s daddr=%lld agno=%u level=%u writing nr=%u over COHERENT disk_nr=%u dir=%s comm=%s pid=%d — prior-tenure-stale write reverts peer's durable bnobt change; stack:\n",
						p124_seq,
						bp->b_ops == &xfs_bnobt_buf_ops ?
							"bnobt" : "cntbt",
						(long long)bp->b_maps[0].bm_bn,
						bp->b_pag ?
							pag_agno(bp->b_pag) :
							(uint32_t)-1,
						(unsigned)be16_to_cpu(
							p124_mine->bb_level),
						(unsigned)p124_mnr,
						(unsigned)p124_dnr,
						p124_dnr < p124_mnr ?
						  "ALLOC-REVERT(disk<mine)" :
						p124_dnr > p124_mnr ?
						  "SPLIT-REVERT(disk>mine)" :
						  "EQNR-CONTENT-DIFF",
						current->comm, current->pid);
					dump_stack();
				}
			}
			kfree(p124_tmp);
		}
	}

	/*
	 * sess133 P133 — dir-DINODE write-submission trace + revert detector
	 * (RULE 4).  The dpn=100 storm dies cluster-wide on a dabuf-map HOLE
	 * at dir block 2 of the shared dir: the on-disk LEAF references data
	 * block 2 while the dinode used for lookup says size=8192/nextents=3
	 * (one growth behind).  P124 watches only bnobt/cntbt, so the dinode
	 * side of "prior-tenure-stale xfsaild push" is invisible.  This logs
	 * EVERY multi-node inode-cluster write's non-shortform DIR dinodes
	 * (only the hot shared dir qualifies — storm children are shortform),
	 * giving a per-write size/nextents timeline mergeable across nodes by
	 * realns, and flags a write whose dir dinode would move the COHERENT
	 * on-disk image BACKWARD (size or nextents shrink = peer's durable
	 * growth reverted).
	 *
	 * v0.5.5 (sess25 ccloop 14d31183): gated behind mxfs.instr — the
	 * probe issues a SYNCHRONOUS plain read per inode-cluster write
	 * containing a dir dinode, in the write-submission path.  Under
	 * the scaling_curve rsync that is one blocking read per xfsaild
	 * cluster push (~0.5-1 ms each), a systemic writeback drag.  The
	 * bug it detected (stale dinode write reverting peer dir growth)
	 * was fixed by the sess21 reload-invalidate guard.
	 */
	/* sess31 (ccloop 14d31183): also enabled by mxfs.dirwr — the zsl
	 * dpn=100 storm tore ino 131's dinode (disk nextents=22) against its
	 * own durable bmbt leaf (23 recs) within 4ms of the grower's release;
	 * this probe was blind to it under instr=0. */
	{ extern int mxfs_iwr_enabled;
	if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled || mxfs_iwr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_map_count == 1 && bp->b_target && bp->b_target->bt_bdev &&
	    (bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ra_ops)) {
		struct xfs_mount *p133_mp = bp->b_mount;
		uint32_t p133_isz = p133_mp->m_sb.sb_inodesize;
		uint32_t p133_len = BBTOB(bp->b_length);
		uint32_t p133_off;
		void *p133_tmp = NULL;
		bool p133_disk_ok = false;

		for (p133_off = 0;
		     p133_isz >= 256 && (p133_len & 511) == 0 &&
		     p133_off + p133_isz <= p133_len;
		     p133_off += p133_isz) {
			struct xfs_dinode *p133_d = bp->b_addr + p133_off;
			struct xfs_buf_log_item *p133_bip = bp->b_log_item;
			static atomic_t p133_wn = ATOMIC_INIT(0);
			static atomic_t p133_rn = ATOMIC_INIT(0);

			if (be16_to_cpu(p133_d->di_magic) != XFS_DINODE_MAGIC)
				continue;

			/*
			 * sess36 (RULE 4): UNCAPPED dinode-write lineage for
			 * the storm dir (low dir inos ≤ 256).  The capped
			 * P133-DIRINO-WR went blind mid-iter (600 budget /
			 * ~28 dir slots per cluster write); the s36 iter3
			 * platter dinode ended nlink=502 with the nx=4 fork
			 * — link count flowed to disk while the fork froze.
			 * This trace shows which writes carried which
			 * (nlink, nx) pairs.
			 */
			if ((mxfs_instr_enabled || mxfs_dirwr_enabled) &&
			    be64_to_cpu(p133_d->di_ino) <= 256 &&
			    S_ISDIR(be16_to_cpu(p133_d->di_mode)))
				pr_warn("mxfs: P36-DINO-WR ino=%llu size=%lld nx=%u nlink=%u nblocks=%llu fmt=%u daddr=%lld comm=%s realns=%llu\n",
					(unsigned long long)be64_to_cpu(p133_d->di_ino),
					(long long)be64_to_cpu(p133_d->di_size),
					be32_to_cpu(p133_d->di_nextents),
					be32_to_cpu(p133_d->di_nlink),
					(unsigned long long)be64_to_cpu(p133_d->di_nblocks),
					p133_d->di_format,
					(long long)bp->b_maps[0].bm_bn,
					current->comm,
					(unsigned long long)ktime_get_real_ns());

			if (!S_ISDIR(be16_to_cpu(p133_d->di_mode)) ||
			    (p133_d->di_format != XFS_DINODE_FMT_EXTENTS &&
			     p133_d->di_format != XFS_DINODE_FMT_BTREE))
				continue;

			if (atomic_inc_return(&p133_wn) <= 600)
				pr_warn("mxfs: P133-DIRINO-WR ino=%llu size=%lld nx=%u nblocks=%llu gen=%u daddr=%lld in_ail=%d dirty=%d pin=%d delwri=%d comm=%s pid=%d realns=%llu\n",
					(unsigned long long)be64_to_cpu(p133_d->di_ino),
					(long long)be64_to_cpu(p133_d->di_size),
					be32_to_cpu(p133_d->di_nextents),
					(unsigned long long)be64_to_cpu(p133_d->di_nblocks),
					be32_to_cpu(p133_d->di_gen),
					(long long)bp->b_maps[0].bm_bn,
					(p133_bip && test_bit(XFS_LI_IN_AIL,
						&p133_bip->bli_item.li_flags)) ? 1 : 0,
					(p133_bip && test_bit(XFS_LI_DIRTY,
						&p133_bip->bli_item.li_flags)) ? 1 : 0,
					xfs_buf_ispinned(bp) ? 1 : 0,
					(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
					current->comm, current->pid,
					(unsigned long long)ktime_get_real_ns());

			/*
			 * sess51 (run14d) — TORN-DIR producer catch at the
			 * authoritative "about to hit disk" point.  A dir dinode
			 * written in EXTENTS format whose FIRST data-fork extent
			 * record does not decode to a valid fs block is a torn
			 * LOCAL->EXTENTS image (di_format=EXTENTS in core but the
			 * fork literal still holds stale shortform bytes, e.g.
			 * "data_node...").  It passes the structural write
			 * verifier (decodes nextents vs forkoff only) but FAILS
			 * every reader's xfs_iformat_extents -> EUCLEAN -> FS
			 * shutdown (PROVEN sess50: ino=444 cross_write_read,
			 * 16-node).  This fires regardless of which path built the
			 * buffer (iflush copy-in / cluster merge overlay / direct)
			 * — the iflush probe in xfs_inode.c only sees the copy-in
			 * path.  Catch it here with the producing stack. */
			if (p133_d->di_format == XFS_DINODE_FMT_EXTENTS &&
			    be32_to_cpu(p133_d->di_nextents) >= 1) {
				struct xfs_bmbt_rec *p133_frp =
					(struct xfs_bmbt_rec *)XFS_DFORK_PTR(
						p133_d, XFS_DATA_FORK);
				struct xfs_bmbt_irec p133_ir;
				unsigned char *p133_fb =
					(unsigned char *)p133_frp;

				xfs_bmbt_disk_get_all(p133_frp, &p133_ir);
				if (!xfs_verify_fsbext(p133_mp,
						p133_ir.br_startblock,
						p133_ir.br_blockcount)) {
					pr_warn("mxfs: P-WRBUF-DIRTORN ino=%llu nx=%u forkoff=%u startblk=0x%llx cnt=0x%llx first16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x daddr=%lld comm=%s pid=%d realns=%llu — torn LOCAL->EXTENTS dir dinode about to be written; stack:\n",
						(unsigned long long)be64_to_cpu(p133_d->di_ino),
						be32_to_cpu(p133_d->di_nextents),
						p133_d->di_forkoff,
						(unsigned long long)p133_ir.br_startblock,
						(unsigned long long)p133_ir.br_blockcount,
						p133_fb[0], p133_fb[1], p133_fb[2], p133_fb[3],
						p133_fb[4], p133_fb[5], p133_fb[6], p133_fb[7],
						p133_fb[8], p133_fb[9], p133_fb[10], p133_fb[11],
						p133_fb[12], p133_fb[13], p133_fb[14], p133_fb[15],
						(long long)bp->b_maps[0].bm_bn,
						current->comm, current->pid,
						(unsigned long long)ktime_get_real_ns());
					dump_stack();
				}
			}

			if (!p133_tmp) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				p133_tmp = kmalloc(p133_len, GFP_NOFS);
				if (p133_tmp &&
				    mxfs_pal_bdev_read_plain_bdev(
					bp->b_target->bt_bdev,
					(uint64_t)bp->b_maps[0].bm_bn +
						bp->b_target->bt_sector_offset,
					p133_tmp, p133_len) == 0)
					p133_disk_ok = true;
			}
			if (p133_disk_ok) {
				struct xfs_dinode *p133_dd =
					p133_tmp + p133_off;

				if (be16_to_cpu(p133_dd->di_magic) ==
					XFS_DINODE_MAGIC &&
				    p133_dd->di_ino == p133_d->di_ino &&
				    (be64_to_cpu(p133_d->di_size) <
					be64_to_cpu(p133_dd->di_size) ||
				     be32_to_cpu(p133_d->di_nextents) <
					be32_to_cpu(p133_dd->di_nextents)) &&
				    atomic_inc_return(&p133_rn) <= 16) {
					pr_warn("mxfs: P133-DIRINO-REVERT ino=%llu writing size=%lld nx=%u over COHERENT disk size=%lld nx=%u daddr=%lld comm=%s pid=%d realns=%llu — stale dinode write reverts peer's durable dir growth; stack:\n",
						(unsigned long long)be64_to_cpu(p133_d->di_ino),
						(long long)be64_to_cpu(p133_d->di_size),
						be32_to_cpu(p133_d->di_nextents),
						(long long)be64_to_cpu(p133_dd->di_size),
						be32_to_cpu(p133_dd->di_nextents),
						(long long)bp->b_maps[0].bm_bn,
						current->comm, current->pid,
						(unsigned long long)ktime_get_real_ns());
					dump_stack();
				}
			}
		}
		kfree(p133_tmp);
	}
	}

	/*
	 * sess32 (ccloop 14d31183) P134 — bmbt write-submission trace +
	 * revert detector (RULE 4).  The zsl dpn=100 storm dies cluster-wide
	 * on "corrupt dinode 131 (btree extents)": dinode nextents vs bmbt
	 * leaf record count torn ON DISK.  Read side already caught the
	 * precursor (P133-BMBT-STALE-SKIP: a bmbt buffer stale vs the
	 * reloaded dinode's i_dlm_dir_gen yet still IN_AIL + _XBF_DELWRI_Q
	 * AFTER the tenure ended) — that queued stale image, when pushed,
	 * rewrites the peer's newer leaf in place.  This logs every
	 * multi-node bmbt write (per-daddr timeline, mergeable across nodes
	 * by realns) and flags a write whose payload differs from the
	 * COHERENT on-disk image (plain read = peer-visible SCST cache)
	 * while carrying the prior-tenure-stale signature.  LOG-ONLY: the
	 * P124 lesson is that write-side refresh/suppression desyncs the
	 * in-core siblings; the fix belongs at the release/acquire fence.
	 * Gated like P133: mxfs.instr or mxfs.dirwr.
	 */
	if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_map_count == 1 && bp->b_target && bp->b_target->bt_bdev &&
	    bp->b_ops == &xfs_bmbt_buf_ops) {
		struct xfs_btree_block *p134_b = bp->b_addr;
		struct xfs_buf_log_item *p134_bip = bp->b_log_item;
		bool p134_inail = p134_bip && test_bit(XFS_LI_IN_AIL,
				&p134_bip->bli_item.li_flags);
		bool p134_dirty = p134_bip && test_bit(XFS_LI_DIRTY,
				&p134_bip->bli_item.li_flags);
		static atomic_t p134_wn = ATOMIC_INIT(0);
		static atomic_t p134_rn = ATOMIC_INIT(0);
		extern bool mxfs_buf_is_undestaged(struct xfs_buf *);

		if (atomic_inc_return(&p134_wn) <= 800)
			pr_warn("mxfs: P134-BMBT-WR owner=%llu daddr=%lld level=%u nr=%u lsn=%llx bgen=%u in_ail=%d dirty=%d pin=%d comm=%s pid=%d realns=%llu\n",
				(unsigned long long)be64_to_cpu(
					p134_b->bb_u.l.bb_owner),
				(long long)bp->b_maps[0].bm_bn,
				(unsigned)be16_to_cpu(p134_b->bb_level),
				(unsigned)be16_to_cpu(p134_b->bb_numrecs),
				(unsigned long long)be64_to_cpu(
					p134_b->bb_u.l.bb_lsn),
				bp->b_mxfs_dir_gen,
				p134_inail ? 1 : 0, p134_dirty ? 1 : 0,
				xfs_buf_ispinned(bp) ? 1 : 0,
				current->comm, current->pid,
				(unsigned long long)ktime_get_real_ns());

		if (p134_inail && !p134_dirty && !xfs_buf_ispinned(bp) &&
		    !mxfs_buf_is_undestaged(bp)) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t p134_len = BBTOB(bp->b_length);
			uint64_t p134_lba = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;
			void *p134_tmp = ((p134_len & 511) == 0 && p134_len) ?
				kmalloc(p134_len, GFP_NOFS) : NULL;

			if (p134_tmp &&
			    mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
				p134_lba, p134_tmp, p134_len) == 0 &&
			    memcmp(p134_tmp, bp->b_addr, p134_len) != 0) {
				struct xfs_btree_block *p134_disk = p134_tmp;
				int p134_seq = atomic_inc_return(&p134_rn);

				if (p134_seq <= 16) {
					pr_warn("mxfs: P134-BMBT-REVERT#%d owner=%llu daddr=%lld writing level=%u nr=%u lsn=%llx over COHERENT disk level=%u nr=%u lsn=%llx disk_owner=%llu comm=%s pid=%d realns=%llu — prior-tenure-stale bmbt write reverts peer's durable dir growth; stack:\n",
						p134_seq,
						(unsigned long long)be64_to_cpu(
							p134_b->bb_u.l.bb_owner),
						(long long)bp->b_maps[0].bm_bn,
						(unsigned)be16_to_cpu(
							p134_b->bb_level),
						(unsigned)be16_to_cpu(
							p134_b->bb_numrecs),
						(unsigned long long)be64_to_cpu(
							p134_b->bb_u.l.bb_lsn),
						(unsigned)be16_to_cpu(
							p134_disk->bb_level),
						(unsigned)be16_to_cpu(
							p134_disk->bb_numrecs),
						(unsigned long long)be64_to_cpu(
							p134_disk->bb_u.l.bb_lsn),
						(unsigned long long)be64_to_cpu(
							p134_disk->bb_u.l.bb_owner),
						current->comm, current->pid,
						(unsigned long long)ktime_get_real_ns());
					dump_stack();
				}
			}
			kfree(p134_tmp);
		}
	}

	/*
	 * sess98 P-DIRWR: mechanism-agnostic dir-block WRITE-submission trace
	 * (RULE 4 — the decisive instrument GPT/sess68 wanted, finally built).
	 * Logs EVERY dir metadata block write on a multi-node mount with its
	 * active-entry count, owner inode, daddr, buffer state, and wall-clock
	 * ns.  Per-node dmesg gives node identity; realns lets the 4 nodes'
	 * writes be MERGED+SORTED into one timeline per daddr.  The clobber =
	 * a write whose active-count is HIGHER than the most-recent prior
	 * write to the same daddr (an already-deleted dirent resurrected) —
	 * that node + moment + EX-held pinpoints the lost-update producer
	 * directly, independent of WHICH stale-base mechanism fed it.  NOT
	 * gated on disk_differs (that FUA-compare is a false positive under
	 * fua_disable=1: it reads the stale platter, not the peer-visible
	 * SCST write-back cache).  Counter-capped (not ratelimited) so the
	 * whole short test is captured without dropping the clobber line.
	 *
	 * v0.5.5 (sess25 ccloop 14d31183): gated behind mxfs.instr — the
	 * 8000-line cap wraps the dmesg ring buffer on every scaling run
	 * (2278-line buffer on the test VMs), hiding every other probe;
	 * it already caused one wrong "0 in dmesg" conclusion in sess23
	 * and nearly another this session.  The dir lost-update family it
	 * traced was fixed in sess83-91.
	 */
	/* sess6 (8ba7ae5c): P144-WR — always-on for multi-node bnobt/cntbt
	 * write submissions (low volume; the double-alloc discriminator). */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    mxfs_p144_ops(bp->b_ops))
		mxfs_p144_print(bp, "WR");

	/* ccloop c7ee71c6 sess13: P170-CLWR — inode-CLUSTER write provenance
	 * for the D3 co-resident stale-slot clobber (32/caw cache_coherency:
	 * platter slot 170 regressed to a prior dir incarnation while
	 * neighbor slots advanced to mode=0 — some node's cluster write
	 * carried a stale slot).  One line per cluster-buf write submission
	 * with EVERY slot's ino:mode:gen-tail; per-node dmesg + realns merge
	 * across nodes names the writer that regressed a slot, independent
	 * of which stale-base mechanism fed it.  Cap 800 always-on (covers a
	 * fresh-prep repro window); uncapped under mxfs.instr. */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_ops == &xfs_inode_buf_ops) {
		static atomic_t clwr_n = ATOMIC_INIT(0);
		int clwr_c = atomic_inc_return(&clwr_n);

		if (clwr_c <= 800 || unlikely(mxfs_instr_enabled)) {
			char clwr_s[420];
			int clwr_sp = 0, clwr_i;
			int clwr_isz = bp->b_mount->m_sb.sb_inodesize;
			int clwr_ns = clwr_isz ?
				(int)(BBTOB(bp->b_length) / clwr_isz) : 0;

			if (clwr_ns > 32)
				clwr_ns = 32;
			for (clwr_i = 0; clwr_i < clwr_ns &&
			     clwr_sp < (int)sizeof(clwr_s) - 32; clwr_i++) {
				struct xfs_dinode *clwr_d =
					(struct xfs_dinode *)((char *)bp->b_addr +
						clwr_i * clwr_isz);

				if (be16_to_cpu(clwr_d->di_magic) !=
				    XFS_DINODE_MAGIC) {
					clwr_sp += scnprintf(clwr_s + clwr_sp,
						sizeof(clwr_s) - clwr_sp, "x,");
					continue;
				}
				clwr_sp += scnprintf(clwr_s + clwr_sp,
					sizeof(clwr_s) - clwr_sp, "%llu:%o:%u,",
					(unsigned long long)be64_to_cpu(clwr_d->di_ino),
					be16_to_cpu(clwr_d->di_mode),
					be32_to_cpu(clwr_d->di_gen) % 10000);
			}
			pr_warn("mxfs: P170-CLWR daddr=%lld len=%u comm=%s flags=0x%x delwri=%d [%s] realns=%llu\n",
				(long long)xfs_buf_daddr(bp),
				(unsigned)BBTOB(bp->b_length),
				current->comm, (unsigned)bp->b_flags,
				(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
				clwr_s,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/* ccloop c7ee71c6 sess14: P172-WRTR always-on memory ring (see
	 * mxfs_wrtr_record above) — every dir-metadata + inode-cluster write
	 * submission on a multi-node mount, no printk (printk suppresses the
	 * D3 race).  Dump via mxfs.dirring_dump=1 or auto on P26-IGET-FAIL. */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm))
		mxfs_wrtr_record(bp);

	if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled >= 2 ||
		     READ_ONCE(mxfs_watch_ino) > 1) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     /* ccloop c7ee71c6 sess6: da3 NODE blocks were the ONE dir
	      * metadata type this trace missed — and the torn-CRC block
	      * that shut down 5/8 nodes (crash_consistency 181124Z,
	      * daddr 11002400) was exactly a da3_node.  Same owner field
	      * (xfs_da3_blkinfo), same lineage-crc semantics. */
	     bp->b_ops == &xfs_da3_node_buf_ops)) {
		static atomic_t dwn = ATOMIC_INIT(0);
		struct xfs_buf_log_item *dwbip = bp->b_log_item;
		const char *dwfmt;
		long long dwowner = -1;
		int dwcount = -1, dwstale = -1, dwactive = -1;
		uint8_t dwgmode = 255;
		bool dwwatch;

		if (bp->b_ops == &xfs_dir3_block_buf_ops) {
			struct xfs_dir3_blk_hdr *bh = bp->b_addr;
			struct xfs_dir2_block_tail *btp =
				((struct xfs_dir2_block_tail *)
				 ((char *)bp->b_addr +
				  bp->b_mount->m_dir_geo->blksize)) - 1;
			dwfmt = "block";
			dwowner = be64_to_cpu(bh->owner);
			dwcount = be32_to_cpu(btp->count);
			dwstale = be32_to_cpu(btp->stale);
			dwactive = dwcount - dwstale;
		} else if (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
			   bp->b_ops == &xfs_dir3_leafn_buf_ops) {
			struct xfs_dir3_leaf_hdr *lh = bp->b_addr;
			dwfmt = (bp->b_ops == &xfs_dir3_leaf1_buf_ops) ?
				"leaf1" : "leafn";
			dwowner = be64_to_cpu(lh->info.owner);
			dwcount = be16_to_cpu(lh->count);
			dwstale = be16_to_cpu(lh->stale);
			dwactive = dwcount - dwstale;
		} else if (bp->b_ops == &xfs_da3_node_buf_ops) {
			struct xfs_da3_node_hdr *nh = bp->b_addr;
			dwfmt = "danode";
			dwowner = be64_to_cpu(nh->info.owner);
			dwcount = be16_to_cpu(nh->__count);
			dwstale = 0;
			dwactive = dwcount;
		} else {
			struct xfs_dir3_blk_hdr *bh = bp->b_addr;
			dwfmt = "data";
			dwowner = be64_to_cpu(bh->owner);
		}

		/* sess10(a9a03929): fire UNCAPPED for the watched storm dir
		 * (the 8000 cap is long exhausted by the time dir_reuse runs
		 * in-suite); legacy instr/dirwr callers keep the cap. */
		dwwatch = READ_ONCE(mxfs_watch_ino) > 1 && dwowner > 0 &&
			  mxfs_ino_watched((uint64_t)dwowner);

		if (dwwatch ||
		    ((mxfs_instr_enabled || mxfs_dirwr_enabled >= 2) &&
		     atomic_inc_return(&dwn) <= 8000)) {

			/* ccloop c7ee71c6 sess6: granted mode of the OWNER
			 * dir's inode lock at submit — the torn-write
			 * discriminator: a dir-block write submitted while
			 * the local mirror is NOT EX-granted names the
			 * exclusivity break directly. */
			if (dwowner > 0 && bp->b_mount->m_mxfs_dlm)
				dwgmode = mxfs_v5_dlm_inode_granted_mode(
					bp->b_mount->m_mxfs_dlm,
					(uint64_t)dwowner);
			/* crc of everything past the 48-byte xfs_dir3_blk_hdr
			 * (magic/crc/blkno/LSN/uuid/owner): the LSN+CRC change
			 * on every relog even when the dirent content is
			 * identical, so hashing past them makes equal entry
			 * content hash equal across nodes/commits — the
			 * lineage key for the merged P-DIRWR/P-DIRRD timeline. */
			pr_warn("mxfs: P-DIRWR fmt=%s owner=%lld daddr=%lld crc=%08x count=%d stale=%d active=%d gmode=%u dirty=%d in_ail=%d pin=%d delwri=%d done=%d comm=%s pid=%d realns=%llu\n",
				dwfmt, dwowner, (long long)bp->b_maps[0].bm_bn,
				crc32c(0, (char *)bp->b_addr + 48,
				       BBTOB(bp->b_length) - 48),
				dwcount, dwstale, dwactive, dwgmode,
				(dwbip && test_bit(XFS_LI_DIRTY,
					&dwbip->bli_item.li_flags)) ? 1 : 0,
				(dwbip && test_bit(XFS_LI_IN_AIL,
					&dwbip->bli_item.li_flags)) ? 1 : 0,
				xfs_buf_ispinned(bp) ? 1 : 0,
				(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
				(bp->b_flags & XBF_DONE) ? 1 : 0,
				current->comm, current->pid,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * sess64 (RULE 4): ALWAYS-ON node1_f1 clobber tracer.  node1_f1 is
	 * DETERMINISTICALLY lost (rank1's first file, durably absent on disk).
	 * Scan every dir DATA/BLOCK buffer WRITE for the exact dirent byte
	 * pattern "\x08node1_f1" (namelen=8 followed by the name) — this is
	 * UNIQUE: it cannot match node1_f10..f19 (namelen 0x09) nor node1_f1.md5
	 * (namelen 0x0c), so prefix collisions are excluded.  Log owner+daddr+
	 * PRESENT/ABSENT+comm on each block0-ish write.  A peer (comm!=rank1's
	 * dd/bash) WRITING the dir block with present=0 after rank1 wrote it
	 * present=1 IS the clobber.  Capped (not the firehose); survives the
	 * dmesg ring unlike dirwr=2.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_data_buf_ops)) {
		static atomic_t n1f1n = ATOMIC_INIT(0);
		static const char pat[9] = { 0x08, 'n','o','d','e','1','_','f','1' };
		/* sess13: also trace a VICTIM name — the recurring drc loss is the
		 * REMOTE nodes' f1 (node1_f1 survives).  present2 tracks node2_f1
		 * so the cross-node write sequence shows whether the victim was
		 * EVER destaged (never-present = lost pre-destage; 1->0 flip =
		 * durable clobber by the flipping writer). */
		static const char pat2[9] = { 0x08, 'n','o','d','e','2','_','f','1' };
		const char *base = bp->b_addr;
		int len = BBTOB(bp->b_length);
		bool present = false, present2 = false;
		int k;

		for (k = 0; k + 9 <= len; k++) {
			if (base[k] == pat[0]) {
				if (!present && memcmp(base + k, pat, 9) == 0)
					present = true;
				if (!present2 && memcmp(base + k, pat2, 9) == 0)
					present2 = true;
				if (present && present2)
					break;
			}
		}
		if (atomic_inc_return(&n1f1n) <= 6000) {
			struct xfs_dir3_blk_hdr *bh = bp->b_addr;
			pr_warn("mxfs: P64-N1F1 owner=%lld daddr=%lld present=%d present2=%d comm=%s pid=%d realns=%llu\n",
				(long long)be64_to_cpu(bh->owner),
				(long long)bp->b_maps[0].bm_bn,
				present ? 1 : 0, present2 ? 1 : 0,
				current->comm, current->pid,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * sess44 P97: inode-cluster lost-update detector (the di_size=0
	 * empty-content root — the ACTUAL cross_write_read assertion fail).
	 * When this node WRITES an inode cluster, FUA-read the on-disk
	 * cluster and check each inode: if the on-disk inode has di_size!=0
	 * but our in-core copy has di_size==0, we are CLOBBERING a peer's
	 * inode (our cluster buffer is stale — a peer wrote that inode's
	 * di_size while we held a different inode's DLM in the same cluster,
	 * and we never refreshed the shared cluster).  di_magic 'IN'=0x494e
	 * at off 0, di_size (__be64) at off 0x38.  Ratelimited; fires only on
	 * the anomaly.
	 */
	{ extern int mxfs_instr_enabled;
	if (unlikely(mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm && bp->b_map_count == 1 &&
	    bp->b_target && bp->b_target->bt_bdev &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ra_ops)) {
		struct xfs_mount *mp = bp->b_mount;
		uint32_t isize = mp->m_sb.sb_inodesize;
		uint32_t len = BBTOB(bp->b_length);

		if (isize >= 256 && len >= isize && !(len & 511)) {
			void *tmp = kmalloc(len, GFP_NOFS);
			uint64_t lba = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;

			if (tmp && mxfs_pal_scsi_read_fua_bdev(
					bp->b_target->bt_bdev, lba, tmp, len) == 0) {
				uint32_t o;

				for (o = 0; o + isize <= len; o += isize) {
					const __u8 *dk = (const __u8 *)tmp + o;
					const __u8 *ic = (const __u8 *)bp->b_addr + o;
					__u16 dmagic = be16_to_cpup((const __be16 *)dk);
					__u64 dsz, icsz;

					if (dmagic != 0x494e)
						continue;
					dsz = be64_to_cpup((const __be64 *)(dk + 0x38));
					icsz = be64_to_cpup((const __be64 *)(ic + 0x38));
					if (dsz != 0 && icsz == 0) {
						/*
						 * sess45: is the inode we're about to
						 * clobber OWNED by this write (attached
						 * to b_li_list at this cluster offset o)?
						 * owned=0 => we are clobbering a PEER's
						 * inode region we don't own => surgical
						 * per-inode write (skip non-owned) fixes it.
						 * owned=1 => our own log item carries
						 * di_size=0 over disk!=0 => a different bug.
						 */
						struct xfs_log_item *lip;
						int owned = 0;
						unsigned long long oino = 0;
						long long ocsz = -1;
						unsigned omode = 99, ostale = 9;
						unsigned ofields = 0;

						list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
							struct xfs_inode_log_item *iip;
							struct xfs_inode *oip;

							if (lip->li_type != XFS_LI_INODE)
								continue;
							iip = container_of(lip,
								struct xfs_inode_log_item, ili_item);
							oip = iip->ili_inode;
							if (oip &&
							    oip->i_imap.im_boffset == o) {
								owned = 1;
								oino = oip->i_ino;
								ocsz = (long long)oip->i_disk_size;
								omode = oip->i_dlm_mode;
								ostale = oip->i_dlm_stale;
								ofields = iip->ili_fields |
									  iip->ili_last_fields;
								break;
							}
						}
						pr_warn_ratelimited("mxfs: P97-INSTR INODE-CLUSTER-CLOBBER daddr=%lld off=%u disk_di_size=%llu buf_incore_size=0 owned=%d ino=%llu ino_ag=%llu node_slot=%u affine_ag=%u incore_disk_size=%lld dlm_mode=%u stale=%u ili_fields=0x%x\n",
							(long long)bp->b_maps[0].bm_bn,
							(unsigned)o,
							(unsigned long long)dsz, owned,
							oino,
							oino ? (unsigned long long)XFS_INO_TO_AGNO(mp, oino) : 0ULL,
							mp->m_mxfs_node_slot,
							mp->m_maxagi ? (mp->m_mxfs_node_slot % mp->m_maxagi) : 0,
							ocsz, omode, ostale, ofields);
						break;
					}
				}
			}
			kfree(tmp);
		}
	} }

	/*
	 * sess10(a9a03929) P10-CLREGRESS — inode-cluster DIR-slot regression
	 * detector (RULE 4, the dlm_scaling/fence SF-loss discriminator).
	 * PROVEN so far: P-SFDIR-REVERT fires with lastrel_flag=1 (the releasing
	 * node's cluster flush RAN, age 5-256ms, at the full size) yet the FUA
	 * platter holds the OLDER dinode moments later — and the raw transport
	 * is clean (6000 cross-node FUA reads over write+sync cycles: 0
	 * anomalies).  Remaining suspect: ANOTHER node's inode-cluster WRITE
	 * (its own co-resident child/subdir dirty) carries STALE bytes for the
	 * shared parent-dir slot and last-writer-wins regresses the platter.
	 * At every multinode inode-cluster write submit (relverify-gated —
	 * adds one FUA read per cluster write): FUA-read the on-disk cluster;
	 * for each DIR dinode slot whose DISK size/SF-count is AHEAD of the
	 * bytes we are about to write, log the imminent regression with
	 * owned/unowned classification.  owned=0 = clobbering a peer's slot.
	 */
	{ extern int mxfs_dir_relverify;
	if (unlikely(mxfs_dir_relverify) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm && bp->b_map_count == 1 &&
	    bp->b_target && bp->b_target->bt_bdev &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ra_ops)) {
		struct xfs_mount *mp = bp->b_mount;
		uint32_t isize = mp->m_sb.sb_inodesize;
		uint32_t len = BBTOB(bp->b_length);

		if (isize >= 256 && len >= isize && !(len & 511)) {
			void *tmp = kmalloc(len, GFP_NOFS);
			uint64_t lba = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;

			if (tmp && mxfs_pal_scsi_read_fua_bdev(
					bp->b_target->bt_bdev, lba, tmp,
					len) == 0) {
				uint32_t o;

				for (o = 0; o + isize <= len; o += isize) {
					const __u8 *dk = (const __u8 *)tmp + o;
					const __u8 *ic = (const __u8 *)bp->b_addr + o;
					__u64 dsz, icsz;
					__u16 dmode;
					__u8 dcnt = 0, iccnt = 0;
					bool regress;

					if (be16_to_cpup((const __be16 *)dk) != 0x494e ||
					    be16_to_cpup((const __be16 *)ic) != 0x494e)
						continue;
					dmode = be16_to_cpup((const __be16 *)(dk + 0x2));
					if (!S_ISDIR(dmode))
						continue;
					/* same incarnation only (di_gen at 0x5C) */
					if (memcmp(dk + 0x5c, ic + 0x5c, 4) != 0)
						continue;
					dsz = be64_to_cpup((const __be64 *)(dk + 0x38));
					icsz = be64_to_cpup((const __be64 *)(ic + 0x38));
					/* SF count byte: dinode v3 core is 176 bytes;
					 * di_version at 0x4, di_format at 0x5 */
					if (dk[0x4] == 3 && ic[0x4] == 3 &&
					    dk[0x5] == XFS_DINODE_FMT_LOCAL &&
					    ic[0x5] == XFS_DINODE_FMT_LOCAL) {
						dcnt = dk[176];
						iccnt = ic[176];
					}
					regress = (dsz > icsz) ||
						  (dsz == icsz && dcnt > iccnt);
					if (!regress)
						continue;
					{
					struct xfs_log_item *lip;
					int owned = 0;
					unsigned ofields = 0;

					list_for_each_entry(lip, &bp->b_li_list,
							    li_bio_list) {
						struct xfs_inode_log_item *iip;

						if (lip->li_type != XFS_LI_INODE)
							continue;
						iip = container_of(lip,
							struct xfs_inode_log_item,
							ili_item);
						if (iip->ili_inode &&
						    iip->ili_inode->i_imap.im_boffset == o) {
							owned = 1;
							ofields = iip->ili_fields |
								  iip->ili_last_fields;
							break;
						}
					}
					pr_warn("mxfs: P10-CLREGRESS daddr=%lld off=%u disk_size=%llu buf_size=%llu disk_sfcnt=%u buf_sfcnt=%u owned=%d ofields=0x%x comm=%s realns=%llu — cluster write would REGRESS a dir dinode slot\n",
						(long long)bp->b_maps[0].bm_bn,
						(unsigned)o,
						(unsigned long long)dsz,
						(unsigned long long)icsz,
						dcnt, iccnt, owned, ofields,
						current->comm,
						(unsigned long long)ktime_get_real_ns());
					}
				}
			}
			kfree(tmp);
		}
	} }

	/*
	 * sess76 P-DIR-LEAF-CLOBBER: the decisive dir2-leaf lost-update detector
	 * (the write-side proof sess73-75 flagged as the missing piece).  sess75
	 * localized the stale-unrefreshable Face-B block to the dir2 LEAF /
	 * hash-index block (blk=0x800000): a node's cached leaf goes stale (a
	 * peer added name-hashes after our last DLM refresh) yet is PINNED by our
	 * own async CIL-unpin tail so neither the acquire drain-evict, the
	 * release evict, nor the lazy read hook can refresh it; we then RMW our
	 * own creates onto the stale leaf and write it back, dropping the peer's
	 * hashes = the on-disk lost update (the faceb divergence n2=9/40 etc).
	 *
	 * At a dir3 leaf1/leafn WRITE in multi-node mode, FUA-read the on-disk
	 * leaf and compare ACTIVE entry counts (count - stale).  in_core_active <
	 * disk_active => this write is dropping name-hashes the disk currently
	 * holds = the clobber, with the buffer-state fields to tell own-CIL-pin
	 * from a genuinely idle stale buffer.  Rate-limited, fires
	 * only on the anomaly.  Leaf writes are infrequent vs data writes, so the
	 * per-write FUA read is cheap relative to the dir mutation rate.
	 *
	 * v0.5.5 (sess25 ccloop 14d31183): gated behind mxfs.instr — "leaf
	 * writes are infrequent" does not hold for the deep-tree rsync
	 * benchmarks (hundreds of leaf writebacks per run, each paying a
	 * synchronous FUA read in the submission path).  The Face-B leaf
	 * lost-update it detected was fixed in sess83-91.
	 */
	if (unlikely(mxfs_instr_enabled) &&
	    (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm && bp->b_map_count == 1 &&
	    bp->b_target && bp->b_target->bt_bdev &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops)) {
		uint32_t len = BBTOB(bp->b_length);
		void *tmp = kmalloc(len, GFP_NOFS);
		uint64_t lba = (uint64_t)bp->b_maps[0].bm_bn +
			bp->b_target->bt_sector_offset;

		if (tmp && len >= sizeof(struct xfs_dir3_leaf) && !(len & 511) &&
		    mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev,
					       lba, tmp, len) == 0) {
			struct xfs_dir3_leaf *ic = bp->b_addr;
			struct xfs_dir3_leaf *dk = tmp;
			__u16 dk_magic = be16_to_cpu(dk->hdr.info.hdr.magic);
			int ic_act = (int)be16_to_cpu(ic->hdr.count) -
				     (int)be16_to_cpu(ic->hdr.stale);
			int dk_act = (int)be16_to_cpu(dk->hdr.count) -
				     (int)be16_to_cpu(dk->hdr.stale);

			/* Only a populated on-disk dir3 leaf can be a victim; a
			 * freshly-zeroed / newly-allocated block is not. */
			if ((dk_magic == XFS_DIR3_LEAF1_MAGIC ||
			     dk_magic == XFS_DIR3_LEAFN_MAGIC) &&
			    ic_act < dk_act) {
				struct xfs_buf_log_item *bip = bp->b_log_item;
				pr_warn_ratelimited("mxfs: P-DIR-LEAF-CLOBBER daddr=%lld incore_active=%d disk_active=%d incore_count=%u incore_stale=%u disk_count=%u disk_stale=%u node_slot=%u dirty=%d in_ail=%d pin=%d delwri=%d done=%d fua_fresh=%d\n",
					(long long)bp->b_maps[0].bm_bn,
					ic_act, dk_act,
					(unsigned)be16_to_cpu(ic->hdr.count),
					(unsigned)be16_to_cpu(ic->hdr.stale),
					(unsigned)be16_to_cpu(dk->hdr.count),
					(unsigned)be16_to_cpu(dk->hdr.stale),
					bp->b_mount->m_mxfs_node_slot,
					(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) ? 1 : 0,
					(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) ? 1 : 0,
					xfs_buf_ispinned(bp) ? 1 : 0,
					(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
					(bp->b_flags & XBF_DONE) ? 1 : 0,
					(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0);
			}
		}
		kfree(tmp);
	}

	/*
	 * sess121 (ccloop 4eef1f39) — act on the write-side stale-AG-meta
	 * interlock set by the P93 detector above.  This buffer is a proven
	 * prior-tenure stale bnobt/cntbt replay (xfsaild AIL push) that would
	 * DMA our reverted free-space image over a peer's durable split ->
	 * ltbno+ltlen>bno double-free shutdown.  Per GPT RULE-5 design:
	 *  1. Refresh bp->b_addr from the COHERENT device cache (plain bio,
	 *     NOT FUA — under fua_disable=1 a plain read hits the peer-visible
	 *     SCST write-back cache; FUA would read the stale platter).  This
	 *     leaves a VALID, non-reverted image in our cache so a later cache
	 *     hit cannot serve the stale free-space tree to the allocator.
	 *  2. Complete the writeback as SUCCESS (xfs_buf_ioerror(bp,0) +
	 *     xfs_buf_ioend) WITHOUT issuing the physical write — the BLI
	 *     iodone (xfs_buf_item_done) removes the item from the AIL so the
	 *     log tail advances; no stale DMA reaches disk; no xfs_buf_stale
	 *     surprise to the BLI state machine; the refreshed block's on-disk
	 *     CRC is already valid (we copy the peer's whole valid block) and
	 *     we never re-stamp/regress the LSN since we skip the write.
	 * If the coherent refresh read FAILS we must NOT let the stale write
	 * proceed and must NOT serve stale content: force shutdown (fail-safe).
	 */
	if (unlikely(mxfs_suppress_stale_agwrite) && bp->b_addr &&
	    bp->b_map_count == 1 && bp->b_target && bp->b_target->bt_bdev) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
		uint32_t len = BBTOB(bp->b_length);
		uint64_t lba = (uint64_t)bp->b_maps[0].bm_bn +
			bp->b_target->bt_sector_offset;
		int rrc = -EIO;
		void *tmp = ((len & 511) == 0 && len) ?
			kmalloc(len, GFP_NOFS) : NULL;

		if (tmp) {
			rrc = mxfs_pal_bdev_read_plain_bdev(
				bp->b_target->bt_bdev, lba, tmp, len);
			if (rrc == 0)
				memcpy(bp->b_addr, tmp, len);
			kfree(tmp);
		}
		if (rrc == 0) {
			pr_warn_ratelimited("mxfs: P122-STALE-AGWRITE-SUPPRESSED daddr=%lld %s len=%u comm=%s — refreshed from coherent cache, write skipped (revert-clobber prevented)\n",
				(long long)bp->b_maps[0].bm_bn,
				bp->b_ops == &xfs_bnobt_buf_ops ? "bnobt" :
				bp->b_ops == &xfs_cntbt_buf_ops ? "cntbt" : "ag",
				len, current->comm);
			xfs_buf_ioerror(bp, 0);
			xfs_buf_ioend(bp);
			return;
		}
		pr_err("mxfs: P122-STALE-AGWRITE-REFRESH-FAILED daddr=%lld rrc=%d — forcing shutdown rather than writing stale free-space\n",
			(long long)bp->b_maps[0].bm_bn, rrc);
		xfs_force_shutdown(bp->b_mount, SHUTDOWN_CORRUPT_INCORE);
		xfs_buf_ioerror(bp, -EFSCORRUPTED);
		xfs_buf_ioend(bp);
		return;
	}

	/*
	 * ccloop c7ee71c6 sess7 — FENCE-V1 (P123): tenure-authorized dir-block
	 * write fence (GPT RULE-5 blueprint; root proof in sess6-C).  A dir
	 * metadata write submitted while the owner dir's DLM granted mode is
	 * below EX is a stale cached image about to interleave with the real
	 * holder's writes on the shared LUN — the captured producer of the
	 * torn da3 CRC block (19 PR + 1 NL writes vs the holder's leaf1->node
	 * split; 5/8-node EUCLEAN shutdown cascade).  Legal writers never
	 * trip this: in-tenure AIL pushes and the release drain both run with
	 * the physical grant still EX (gmode=EX), log recovery is excluded by
	 * flag, and an EX-outgoing drain's mode-transition tail is sanctioned
	 * by the task registry.  Disposition (GPT verdict 2):
	 *  - NO log obligation (no bli, or bli clean+off-AIL, and unpinned):
	 *    the content is a duplicate of durable data or a superseded stale
	 *    image — suppress: complete as SUCCESS without I/O (wseq stamps at
	 *    ioend so the release fence's data_durable converges; skipping
	 *    never worsens the platter).  A bli-free buffer is also STALED so
	 *    the next access cold-reads the peer's current image; a bli
	 *    carrier keeps its state machine untouched (P122 precedent).
	 *  - Log obligation (in-AIL / dirty bli / pinned): committed content
	 *    whose durable supersession we cannot prove — ALLOW (suppressing
	 *    could lose the only copy) and print the P-FENCE-AILLEAK census;
	 *    this is the residual v2 target (certificates + quarantine).
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    !(bp->b_flags & _XBF_LOGRECOVERY) &&
	    (bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     bp->b_ops == &xfs_dir3_free_buf_ops ||
	     bp->b_ops == &xfs_da3_node_buf_ops)) {
		extern bool mxfs_task_in_dir_drain(void);
		long long fowner = -1;
		const char *ffmt;

		/* Owner ino from the block's own header (all six types embed
		 * it: dir3_blk_hdr.owner / dir3_leaf_hdr.info.owner /
		 * da3_node_hdr.info.owner / dir3_free_hdr.hdr.owner). */
		if (bp->b_ops == &xfs_dir3_block_buf_ops ||
		    bp->b_ops == &xfs_dir3_data_buf_ops ||
		    bp->b_ops == &xfs_dir3_free_buf_ops) {
			struct xfs_dir3_blk_hdr *fh = bp->b_addr;

			fowner = be64_to_cpu(fh->owner);
			ffmt = bp->b_ops == &xfs_dir3_block_buf_ops ? "block" :
			       bp->b_ops == &xfs_dir3_data_buf_ops ? "data" :
			       "free";
		} else if (bp->b_ops == &xfs_da3_node_buf_ops) {
			struct xfs_da3_node_hdr *fh = bp->b_addr;

			fowner = be64_to_cpu(fh->info.owner);
			ffmt = "danode";
		} else {
			struct xfs_dir3_leaf_hdr *fh = bp->b_addr;

			fowner = be64_to_cpu(fh->info.owner);
			ffmt = bp->b_ops == &xfs_dir3_leaf1_buf_ops ?
			       "leaf1" : "leafn";
		}

		/* This submission has not (yet) been suppressed — reset the
		 * one-shot verdict consumed by flush_one_daddr's FUA arm. */
		bp->b_mxfs_fence_skipped = false;

		/* Unresolvable owner => cannot prove sub-EX; fail open. */
		if (fowner > 0 &&
		    mxfs_v5_dlm_inode_granted_mode(bp->b_mount->m_mxfs_dlm,
				(uint64_t)fowner) < MXFS_LOCK_EX) {
			struct xfs_buf_log_item *fbip = bp->b_log_item;
			bool f_ail = fbip && test_bit(XFS_LI_IN_AIL,
						&fbip->bli_item.li_flags);
			bool f_dirty = fbip && test_bit(XFS_LI_DIRTY,
						&fbip->bli_item.li_flags);
			bool f_pin = xfs_buf_ispinned(bp);
			/* v1.1 (run 185647Z refutation): the drain sanction is
			 * ATTRIBUTION ONLY, never an allow.  The P97 relfence
			 * loop orders full publication BEFORE the wire unlock,
			 * so a sanctioned drain write observed at sub-EX is by
			 * construction a post-unlock retry tail republishing
			 * already-durable content — and run 185647Z caught one
			 * regressing the new holder's leaf (count=290@PR vs
			 * tip 320) plus paired danode republishes, all allowed
			 * only via the sanction.  Suppress them like any other
			 * unobligated sub-EX write. */
			bool f_drain = mxfs_task_in_dir_drain();

			if (!f_ail && !f_dirty && !f_pin) {
				static atomic_t f_dumps = ATOMIC_INIT(0);

				pr_warn_ratelimited("mxfs: P123-DIRFENCE-SKIP fmt=%s owner=%lld daddr=%lld gmode=%u has_bli=%d in_drain=%d lseq=%llu wseq=%llu done=%d comm=%s — sub-EX stale dir-block write suppressed\n",
					ffmt, fowner,
					(long long)bp->b_maps[0].bm_bn,
					mxfs_v5_dlm_inode_granted_mode(
						bp->b_mount->m_mxfs_dlm,
						(uint64_t)fowner),
					fbip ? 1 : 0, f_drain ? 1 : 0,
					(unsigned long long)bp->b_mxfs_logged_seq,
					(unsigned long long)bp->b_mxfs_written_seq,
					(bp->b_flags & XBF_DONE) ? 1 : 0,
					current->comm);
				/* Producer attribution: first few suppressions
				 * get a stack (which flush arm / evict path
				 * feeds the fence). */
				if (atomic_inc_return(&f_dumps) <= 5)
					dump_stack();
				bp->b_mxfs_fence_skipped = true;
				if (!fbip) {
					xfs_buf_stale(bp);
					bp->b_flags &= ~XBF_DONE;
				}
				xfs_buf_ioerror(bp, 0);
				xfs_buf_ioend(bp);
				return;
			}
			pr_warn_ratelimited("mxfs: P-FENCE-AILLEAK fmt=%s owner=%lld daddr=%lld gmode=%u in_ail=%d dirty=%d pin=%d in_drain=%d lseq=%llu wseq=%llu comm=%s — log-obligated sub-EX dir write ALLOWED (v2 target)\n",
				ffmt, fowner,
				(long long)bp->b_maps[0].bm_bn,
				mxfs_v5_dlm_inode_granted_mode(
					bp->b_mount->m_mxfs_dlm,
					(uint64_t)fowner),
				f_ail ? 1 : 0, f_dirty ? 1 : 0, f_pin ? 1 : 0,
				f_drain ? 1 : 0,
				(unsigned long long)bp->b_mxfs_logged_seq,
				(unsigned long long)bp->b_mxfs_written_seq,
				current->comm);
		}
	}

	/* In-memory targets are directly mapped, no I/O required. */
	if (xfs_buftarg_is_mem(bp->b_target)) {
		xfs_buf_ioend(bp);
		return;
	}

	/*
	 * v0.3.100 (sess25): targeted read-skip for bnobt/cntbt only.
	 * Sess29 extension: also covers xfs_inode_buf_ops since the FUA-read
	 * gate below now routes inode cluster reads through FUA passthrough,
	 * and an FUA read of a buf with attached dirty BLI would overwrite
	 * our in-memory inode modifications.
	 *
	 * If a buf has dirty bli (XFS_LI_DIRTY — modified in current trans
	 * not yet committed), reading from disk would overwrite our
	 * in-memory mods.  Trans then logs pre-mod content.  Disk
	 * eventually reflects pre-mod.  Peer reads pre-mod → bnobt
	 * LEFT/RIGHT-FAIL or Mode A.
	 *
	 * Buf types covered: bnobt/cntbt (per-AG free-space), xfs_inode_buf
	 * (per-inode cluster).  agf/agi/agfl have different update patterns
	 * (always written via committed trans, no in-memory-only mods that
	 * would be lost).  Dir bufs not yet covered — separate Phase 4 work.
	 */
	if ((bp->b_flags & (XBF_READ | XBF_WRITE | XBF_READ_AHEAD)) == XBF_READ &&
	    (bp->b_ops == &xfs_bnobt_buf_ops ||
	     bp->b_ops == &xfs_cntbt_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     bp->b_ops == &xfs_dir3_free_buf_ops)) {
		struct xfs_buf_log_item *bip = bp->b_log_item;
		if (bip && test_bit(XFS_LI_DIRTY,
				    &bip->bli_item.li_flags)) {
			static atomic64_t p45_count;
			uint64_t n = atomic64_inc_return(&p45_count);
			if ((n & 63) == 1)
				mxfs_idbg("mxfs: P45-INSTR READ-skip-dirty n=%llu blkno=%llu\n",
					(unsigned long long)n,
					(unsigned long long)bp->b_maps[0].bm_bn);
			bp->b_flags |= XBF_DONE;
			bp->b_flags &= ~(XBF_READ | XBF_READ_AHEAD);
			xfs_buf_ioend(bp);
			return;
		}
	}

	/*
	 * v0.3.62: AG-metadata reads in multi-node mode go through SCSI
	 * READ(16) FUA passthrough, bypassing any per-initiator iSCSI/LIO
	 * read cache that may not see another node's prior FUA writes.
	 * Read-ahead is excluded (best-effort prefetch — not worth FUA cost,
	 * and the cached value will be re-read via FUA when actually used).
	 *
	 * v0.3.67: also covers inode cluster bufs.  Mode A "dir-removename
	 * ENOENT" failures (sess20 v0.3.44 P21-INSTR confirmed disk content
	 * is correct → peer's stale CACHE) imply peer needs FUA reads for
	 * dinode bufs after a fresh inode-DLM acquire.
	 *
	 * v0.3.68: skip FUA when buf has attached BLI.  A staled-reuse buf
	 * (XBF_STALE was set, b_flags cleared by xfs_buf_find_lock) may
	 * still have b_log_item attached, and that BLI's trans may have
	 * unflushed in-memory modifications.  FUA-reading from disk would
	 * give pre-modification content, and the trans's later commit
	 * would log that pre-modification content — wiping our updates.
	 * Sess22 evidence: T2 alloc'd agbno=22456 len=65520 then 3s later
	 * read pre-alloc state on its own AG-DLM exclusive hold (v0.3.62
	 * run 1 fail).  Bio path doesn't have this issue because the
	 * buffer's current in-memory content is preserved.
	 */
	/*
	 * Sess29 v0.3.114b: FUA-read also covers READ_AHEAD for FUA-relevant
	 * buf types (inode, dir, AG-meta).  Without this, an inode/dir RA
	 * populates the local buf cache via plain bio (per-initiator iSCSI
	 * cache) with pre-modification content; subsequent xfs_buf_get
	 * returns the cached buf and never re-reads, so FUA never fires.
	 * Cost: more SCSI roundtrips for RA hits, but correctness needs it.
	 * Original v0.3.62 comment "RA excluded — cached value re-read via
	 * FUA when actually used" is empirically wrong: the cached value is
	 * NOT re-read; it's hit from cache.
	 */
	/*
	 * v6a phase 1 (v0.3.129, sess31): the !_XBF_FUA_FRESH gate.  If
	 * the buf has been re-read with FUA since its last stale event,
	 * its content already matches disk and the storage stack's
	 * per-initiator cache is not in play — fall through to plain bio,
	 * which amortizes via page cache for subsequent reads of the same
	 * block while still holding the DLM lock.  On the first read
	 * after stale, the flag is unset, so we go FUA to pierce the
	 * lower-layer cache; mxfs_buf_read_fua sets the flag on success.
	 *
	 * Per docs/v6-cache-architecture-proposal.md §11.9 hypothesis H1:
	 * this single gate change converts O(metadata_reads) SCSI round
	 * trips into O(invalidations) SCSI round trips, which is the
	 * lever that should drop the 2-node rsync bench from 9+ min to
	 * under 60 s.
	 */
	{
	extern int mxfs_fua_always;	/* sess39 diagnostic/fix lever */
	extern int mxfs_fua_disable;	/* sess45 lever: SCST shared cache */
	if ((bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
	    !mxfs_fua_disable &&
	    (mxfs_fua_always || !(bp->b_flags & _XBF_FUA_FRESH)) &&
	    bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    mxfs_buf_needs_fua_read(bp)) {
		/*
		 * sess79: the broad "skip FUA when AG owned" lever wedged the
		 * FS under concurrent load (serving a cached inode buffer that
		 * a transaction then spun on → ILOCK hung-task).  Removed; the
		 * safe form is scoped to brand-new inode initialisation.  We
		 * keep the per-class FUA counters to size the composition.
		 */
		mxfs_fua_count(bp);
		/*
		 * sess15(ccloop) PERF probe (RULE 4): the 8-node dir_reuse verify
		 * is FUA-read-bound — dir blocks re-FUA-read ~1×/lookup even cold
		 * with NO gen-invalidation (INVAL=0).  Log, per dir-class FUA read,
		 * the daddr + ops + post-read _XBF_FUA_FRESH so we can count repeats
		 * by daddr and tell whether the read SET the fresh flag (cached next
		 * time) or took the P91-logged short-circuit (flag stays clear ->
		 * re-reads forever).  Dir buffers only, capped.
		 */
		{
			extern int mxfs_dir_perf_probe;
			bool is_dir = bp->b_ops == &xfs_dir3_data_buf_ops ||
				      bp->b_ops == &xfs_dir3_block_buf_ops ||
				      bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
				      bp->b_ops == &xfs_dir3_leafn_buf_ops ||
				      bp->b_ops == &xfs_dir3_free_buf_ops;
			int rc = mxfs_buf_read_fua(bp);
			if (mxfs_dir_perf_probe && is_dir) {
				static atomic_t p15p = ATOMIC_INIT(0);
				unsigned long long owner = 0;
				if (bp->b_addr) {
					__be32 magic = *(__be32 *)bp->b_addr;
					/* dir3 data/block: owner in xfs_dir3_blk_hdr @ +24.
					 * dir3 leaf/free: owner in xfs_da3_blkinfo @ +24 too. */
					if (magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
					    magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
						owner = be64_to_cpu(((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner);
					else if (magic == cpu_to_be32(XFS_DIR3_LEAF1_MAGIC) ||
						 magic == cpu_to_be32(XFS_DIR3_LEAFN_MAGIC) ||
						 magic == cpu_to_be32(XFS_DIR3_FREE_MAGIC))
						owner = be64_to_cpu(((struct xfs_da3_blkinfo *)bp->b_addr)->owner);
				}
				if (atomic_inc_return(&p15p) <= 8000)
					pr_warn("mxfs: P15-DIRFUA daddr=%lld owner=%llu ops=%s rc=%d fresh_after=%d in_ail=%d comm=%s\n",
						(long long)bp->b_maps[0].bm_bn, owner,
						bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
						rc,
						(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
						(bp->b_log_item && test_bit(XFS_LI_IN_AIL, &bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
						current->comm);
			}
			if (rc == 0)
				return;
		}
		/* fall through to bio path on -EOPNOTSUPP / errors */
	}
	}

	/*
	 * sess110 (RULE 4): bnobt in-core-revert probe+guard for the PLAIN-BIO
	 * READ path.  sess92 PROVED the bnobt double-free (ltbno+ltlen>bno,
	 * xfs_alloc.c:2244 shutdown) is a NON-TRANSACTIONAL in-core revert of an
	 * AG-meta buffer (split -> pristine) before the release drain.  The FUA
	 * read path already refuses to DMA disk over a buffer carrying logged-
	 * but-uncheckpointed mods (P91 backstop, mxfs_buf_read_fua L1536).  The
	 * plain-bio read below (xfs_buf_submit_bio) has NO such guard: if any
	 * invalidation/stale path cleared XBF_DONE on an AG-meta (bnobt/cntbt/
	 * agf/agi/inobt) buffer that still holds this node's uncommitted free-
	 * space change (in-AIL/pinned/dirty/delwri/has-BLI), reading here DMAs
	 * the stale pre-split on-disk image over b_addr = the exact revert.  The
	 * in-core image is authoritative (a logged buffer was necessarily read
	 * before it was modified), so refusing the read can never serve stale
	 * data — it only prevents clobbering our own committed work.  Complete
	 * the read in place from the in-core data.  Logs so the timeline proves
	 * the bio path is the revert vector (vs aliasing, which stays silent).
	 */
	if ((bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    mxfs_buf_is_ag_metadata(bp) &&
	    mxfs_buf_has_uncheckpointed_mods(bp)) {
		const char *opsname = (bp->b_ops && bp->b_ops->name) ?
				      bp->b_ops->name : "?";

		/*
		 * sess122 (ccloop) — RULE 4, proven harmful: this read-side
		 * interlock REFUSED a plain-bio READ and kept the in-core image
		 * on the SAME flawed premise sess23 disproved for the write-side
		 * suppression ([[sess23-ccloop-suppression-was-corruptor-3of4]]):
		 * "in-core is always authoritative" is FALSE for a legit AGI
		 * update during ifree (and for coalescing-free numrecs changes).
		 * Direct evidence: `P110-BIO-OVER-LOGGED ... ops=xfs_agi comm=rm`
		 * → `Metadata I/O Error (0x1) at xfs_inactive_ifree`
		 * (xfs/xfs_inode.c:2093) → force-shutdown in test_unlink_visibility
		 * (regressed cache_coherency 3/4 → 2/4).  Under fua_disable=1 the
		 * plain-bio read below hits the COHERENT SCST write-back cache (not
		 * a stale platter), and sess23 PROVED the acquire-invalidation +
		 * release-drain fences are tight (P79/P14/P47/P126 = 0), so letting
		 * the read proceed cannot serve stale data.  Make this LOG-ONLY:
		 * keep the timeline probe, but DO NOT short-circuit the read.
		 *
		 * ccloop-4dd7 sess4 (b60r2, RULE 4): the blanket disable was
		 * ITSELF proven harmful — `P110-BIO-OVER-LOGGED daddr=16
		 * ops=xfs_cntbt pin=1 comm=bash` was followed within 500µs by
		 * `i != 1` at xfs_alloc_fixup_trees + xfs_free_ag_extent in
		 * the SAME task → defer_finish dirty-cancel shutdown: the
		 * read DMA'd the platter cntbt over PINNED (in-CIL, this
		 * tenure's) records while the bnobt kept the newer in-core
		 * state → bnobt/cntbt divergence.  A PINNED (or
		 * committed-unwritten by payload-LSN) AG-meta buffer can
		 * never legitimately adopt the disk image: we hold the AG EX
		 * for the in-flight change, so no peer image can be newer.
		 * The sess122-legit adopt case (AGI during ifree) was a
		 * DESTAGED lingering-BLI buffer — mxfs_buf_is_undestaged()
		 * distinguishes exactly that (pinned || li_lsn newer than the
		 * payload write-stamp).  Refuse the DMA only for undestaged;
		 * destaged-lingering stays LOG-ONLY and the read proceeds.
		 */
		{
		extern bool mxfs_buf_is_undestaged(struct xfs_buf *);
		bool undest = mxfs_buf_is_undestaged(bp);

		pr_warn_ratelimited(
		    "mxfs: P110-BIO-OVER-LOGGED daddr=%lld ops=%s pin=%d li_empty=%d has_bli=%d delwri=%d flags=0x%x undest=%d comm=%s — %s\n",
		    (long long)bp->b_maps[0].bm_bn, opsname,
		    atomic_read(&bp->b_pin_count),
		    list_empty(&bp->b_li_list) ? 1 : 0,
		    bp->b_log_item ? 1 : 0,
		    !!(bp->b_flags & _XBF_DELWRI_Q),
		    bp->b_flags, undest ? 1 : 0, current->comm,
		    undest ? "UNDESTAGED — refusing DMA, completing read from in-core (sess4 b60r2 cntbt revert)" :
			     "LOG-ONLY (destaged-lingering; read proceeds per sess122)");
		if (undest) {
			bp->b_error = 0;
			/*
			 * sess9 (ccloop c7ee71c6) D1b: this in-place completion
			 * MUST skip verify_read, exactly like the P91 FUA-path
			 * twin (v0.10.32 b_mxfs_inplace_read): the in-core image
			 * is authoritative but its embedded CRC is only stamped
			 * at write submit, so verifying logically-dirty content
			 * manufactures EFSBADCRC on a healthy buffer.  PROVEN:
			 * t1 bnobt daddr 2093232 (drc@16 r13, run 203759Z) —
			 * P126 staled the dirty buf, this path served it,
			 * verify_read CRC-failed (P15I-CRCFAIL err=-74, platter
			 * magic VALID per P15I-MEDIUM) → force shutdown → the
			 * withdraw tear poisoned the whole cluster.
			 */
			bp->b_mxfs_inplace_read = true;
			bp->b_flags |= XBF_DONE;
			xfs_buf_ioend(bp);
			return;
		}
		}
	}

	/*
	 * sess61 (RULE 4, PROVEN root of zero_silent_loss): the bmbt analogue of
	 * the sess110 AG-meta read-interlock — but UNLIKE that one (disabled in
	 * sess122 because an AGI read during ifree legitimately adopts a peer's
	 * disk image), this is SAFE to keep ACTIVE because a bmbt extent-map leaf
	 * can only carry THIS node's uncheckpointed mods while THIS node holds the
	 * owning inode/dir EXCLUSIVELY (ILOCK_EXCL + dir DLM EX) — no peer can be
	 * modifying that extent map concurrently, so our in-core image is strictly
	 * authoritative and the on-disk/SCST image can only be OLDER.
	 *
	 * Proven vector (P61-BMBTSCAN/P60-RELAUDIT, build B973EC61): the EX holder
	 * grew the shared storm dir to N extents (in-core iext tree = N, bmbt leaf
	 * buffer = N after xfs_btree_insert), then an invalidation/stale path
	 * cleared XBF_DONE on that still-dirty leaf, and a subsequent plain-bio
	 * READ DMA'd the OLDER on-disk leaf (N-1 records) over b_addr — reverting
	 * the leaf to N-1 while the iext tree stayed N.  The next inode flush then
	 * wrote di_nextents=N paired with the reverted leaf=N-1, so a reloading
	 * peer trips `ir.loaded(N-1) != if_nextents(N)` in xfs_iread_extents ->
	 * EFSCORRUPTED -> FS shutdown -> the whole 16-node storm's silent loss.
	 * No bmbt leaf write of N ever reached disk (P60-BMBTWRITE max=N-1) and the
	 * leaf daddr was stable (no aliasing) — the divergence is purely this
	 * read-over-logged revert.
	 *
	 * Fix: refuse the disk read for a bmbt leaf carrying uncheckpointed mods;
	 * complete it in place from the authoritative in-core image (set XBF_DONE,
	 * no DMA).  Always-on log (rate-limited, fires only on the caught revert —
	 * very low volume) doubles as the RULE-4 proof.
	 */
	if ((bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_ops == &xfs_bmbt_buf_ops && bp->b_addr &&
	    mxfs_buf_has_uncheckpointed_mods(bp)) {
		pr_warn_ratelimited(
		    "mxfs: P61-BIO-OVER-LOGGED-BMBT owner=%llu daddr=%lld incore_numrecs=%u pin=%d has_bli=%d delwri=%d flags=0x%x comm=%s — refusing disk read, keeping authoritative in-core leaf\n",
		    (unsigned long long)be64_to_cpu(((struct xfs_btree_block *)
			bp->b_addr)->bb_u.l.bb_owner),
		    (long long)bp->b_maps[0].bm_bn,
		    be16_to_cpu(((struct xfs_btree_block *)
			bp->b_addr)->bb_numrecs),
		    atomic_read(&bp->b_pin_count),
		    bp->b_log_item ? 1 : 0,
		    !!(bp->b_flags & _XBF_DELWRI_Q),
		    bp->b_flags, current->comm);
		bp->b_error = 0;
		bp->b_flags |= XBF_DONE;
		xfs_buf_ioend(bp);
		return;
	}

	/*
	 * P20-BIO-READ-LOGGED (RULE 4, catch-all probe): a plain-bio READ is
	 * about to DMA platter content over a buffer that has log items
	 * attached (committed work whose only redo is the log).  Under
	 * publish-only dirsig the platter may predate that work — on a
	 * re-mkfs'd LUN it holds the PRIOR incarnation's bytes — so this read
	 * clobbers the in-core image (the iflush bad-magic family:
	 * P20-IFLUSH-FORENSIC disk_differs=0 li_empty=0 with NO
	 * P20-CLUSTER-INVAL = the invalidate came through an unlogged path).
	 * Log identity + a few stacks so the vector names itself.  LOG-ONLY.
	 */
	if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled) &&
	    (bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (!list_empty(&bp->b_li_list) || bp->b_log_item)) {
		static atomic_t p20br = ATOMIC_INIT(0);
		int n = atomic_inc_return(&p20br);

		if (n <= 64)
			pr_warn("mxfs: P20-BIO-READ-LOGGED daddr=%lld ops=%s pin=%d delwri=%d li_empty=%d has_bli=%d bli_flags=0x%x flags=0x%x comm=%s n=%d\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ?
					bp->b_ops->name : "?",
				atomic_read(&bp->b_pin_count),
				!!(bp->b_flags & _XBF_DELWRI_Q),
				list_empty(&bp->b_li_list) ? 1 : 0,
				bp->b_log_item ? 1 : 0,
				bp->b_log_item ?
					(unsigned int)bp->b_log_item->bli_flags : 0u,
				bp->b_flags, current->comm, n);
		if (n <= 8)
			dump_stack();
	}

	/*
	 * sess7 (ccloop 8ba7ae5c) P150 READ-PRESERVE — ROOT FIX of the AG-x/295
	 * dangling-extent double-alloc (PROVEN iter_14, ino 56623258): the rm
	 * storm's dir block->shortform conversion committed (nx 3->0, chg 1922)
	 * and xfsaild's iflush copied the new image into the cluster buffer
	 * (P32/P33 prints) — then a concurrent cold READ of the same cluster
	 * (mxfs_inode_cluster_durable via xfs_remove; buffer previously staled
	 * by the DLM reload invalidation) DMA'd the PRE-shrink platter image
	 * over b_addr (P20-BIO-READ-LOGGED li_empty=0), and the queued delwri
	 * write pushed those stale bytes back to disk (P133/P136 nx=3).  The
	 * flush completion then cleaned the inode item, so the nx=0 state was
	 * never written anywhere: peers adopted the platter's nx=3 map whose
	 * freed block a later allocation legally reused -> cross-inode extent
	 * overlap (EFSCORRUPTED dir).
	 *
	 * Fix — the READ-side mirror of mxfs_submit_partial_inode_write's
	 * false-sharing protection: before the DMA, snapshot the slots whose
	 * inode log items are attached to this buffer (committed local state;
	 * for any inode this node may log it holds/held EX, so the platter is
	 * never NEWER than this buffer's last iflush image of that slot).  At
	 * read completion the snapshot is restored over the DMA'd image, so
	 * the read imports peer-fresh content for every OTHER slot while our
	 * attached slots keep the authoritative local image.  Late-attaching
	 * items (racing trans_log_inode) need no preservation: their copy-in
	 * happens at a FUTURE iflush, which writes into the merged image.
	 */
	if ((bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
	    bp->b_mount && bp->b_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    (bp->b_ops == &xfs_inode_buf_ops ||
	     bp->b_ops == &xfs_inode_buf_ra_ops) &&
	    bp->b_map_count == 1 && bp->b_addr &&
	    !list_empty(&bp->b_li_list) &&
	    !bp->b_mxfs_rd_preserve) {
		unsigned int	p150_ilog = bp->b_mount->m_sb.sb_inodelog;
		unsigned int	p150_len = BBTOB(bp->b_length);
		unsigned int	p150_ni = p150_ilog ? (p150_len >> p150_ilog) : 0;
		struct xfs_log_item *p150_lip;
		u64		p150_mask = 0;

		if (p150_ni >= 1 && p150_ni <= 64) {
			list_for_each_entry(p150_lip, &bp->b_li_list,
					    li_bio_list) {
				struct xfs_inode_log_item *p150_iip;
				int p150_slot;

				if (p150_lip->li_type != XFS_LI_INODE)
					continue;
				p150_iip = (struct xfs_inode_log_item *)p150_lip;
				if (!p150_iip->ili_inode)
					continue;
				/* EX-held only: an attached NL item can be a
				 * stale ghost (P119 family) — restoring its
				 * slot would resurrect prior-tenure bytes over
				 * a peer's fresh image in the local cache.  An
				 * EX-held inode's platter image is never newer
				 * than this buffer's (we are the sole writer);
				 * NL/RELFLUSH release-window inodes need no
				 * preserve (the release loop's iflush_cluster
				 * re-copies from in-core AFTER its read). */
				if (p150_iip->ili_inode->i_dlm_mode !=
						MXFS_LOCK_EX)
					continue;
				p150_slot = p150_iip->ili_inode->i_imap.im_boffset
						>> p150_ilog;
				if (p150_slot < 0 || p150_slot >= (int)p150_ni)
					continue;
				p150_mask |= 1ULL << p150_slot;
			}
			if (p150_mask) {
				void *p150_shadow = kmemdup(bp->b_addr,
						p150_len, GFP_NOFS);

				if (p150_shadow) {
					static atomic_t p150_n = ATOMIC_INIT(0);

					bp->b_mxfs_rd_preserve = p150_shadow;
					bp->b_mxfs_rd_preserve_mask = p150_mask;
					if (atomic_inc_return(&p150_n) <= 20000)
						pr_warn("mxfs: P150-RDPRESERVE daddr=%lld mask=0x%llx comm=%s realns=%llu\n",
							(long long)bp->b_maps[0].bm_bn,
							(unsigned long long)p150_mask,
							current->comm,
							(unsigned long long)ktime_get_real_ns());
				} else {
					pr_warn_ratelimited(
						"mxfs: P150-RDPRESERVE-ENOMEM daddr=%lld mask=0x%llx — read proceeds UNPRESERVED\n",
						(long long)bp->b_maps[0].bm_bn,
						(unsigned long long)p150_mask);
				}
			}
		}
	}

	/*
	 * sess44 FIX ATTEMPT (build D14B0E48) REVERTED: inode-cluster
	 * FUA-read-merge here (FUA-read the disk cluster + restore peer inode
	 * regions not in bp->b_li_list before the write) was CORRECT in
	 * principle but cross_write_read TIMED OUT (rc=124, 180s vs normal
	 * ~5-10s) — likely a HANG: a blocking SCSI FUA-read inside
	 * xfs_buf_submit (the write/writeback path) can deadlock when called
	 * with locks held (AIL push / iflush context).  Per-write FUA is also
	 * a perf killer regardless.  The CORRECT fix for the confirmed
	 * inode-cluster lost-update (P97) must NOT do blocking I/O in
	 * xfs_buf_submit.  Options: (a) surgical per-inode FUA-WRITE of only
	 * the dirty inode sectors from a SAFE context (isize=512 here = 1
	 * sector/inode, so per-inode writes are sector-aligned) — but still
	 * per-inode FUA cost; (b) CLUSTER-GRANULARITY coherency: invalidate a
	 * node's cached inode-cluster buffer when a PEER modifies any inode in
	 * it (inode-DLM BAST broadcasts cluster-wide), so the next flush reads
	 * the peer's current inodes — this avoids per-write FUA (bounded by
	 * contention) and is the performant fix.  See state.md.
	 */

	/*
	 * sess44 FIX ATTEMPT 3 (surgical per-inode FUA-write here) REVERTED:
	 * it did NOT hang (10s — confirms NO-kmalloc/NO-read FUA-WRITE is safe
	 * in xfs_buf_submit, unlike attempt-1's blocking read) BUT did NOT fix
	 * di_size=0.  DECISIVE: writing only this node's inode sectors (never
	 * touching peers) STILL leaves node2 reading node1's file as size 0 →
	 * **the di_size=0 is primarily a READ-SIDE staleness** (node2 reads its
	 * own cached, gen-current-but-stale inode-cluster buffer for node1's
	 * inode; node1's inode IS correct on disk).  This is the SAME read-side
	 * coherency problem as the bnobt (cached buffer treated as fresh,
	 * never FUA-refreshed).  The write-clobber P97 catches is real but
	 * SECONDARY.  ⇒ NEXT: fix the READ side — when node2 stats/igets
	 * node1's inode, force a FUA-refresh of the inode-cluster buffer (the
	 * inode-DLM acquire must invalidate the cached cluster buffer so the
	 * read re-pierces to the medium).  The bnobt + di_size share this ONE
	 * read-side root: a node uses a gen-current-but-stale cached buffer.
	 */

	/*
	 * sess45: SURGICAL per-inode inode-cluster write (gated, default OFF).
	 * The 4-node cross_write_read corruption is the inode-cluster write-
	 * clobber: this node writes the WHOLE cluster buffer carrying a stale
	 * copy of a PEER's inode → xfs_inode_buf_verify fails on read → shutdown
	 * (P97 family).  When mxfs.surgical_inode_write=1, write ONLY this node's
	 * dirty inode sectors (from b_li_list) via FUA — never the whole cluster
	 * — so peer inode regions on disk are untouched.  NO kmalloc / NO read
	 * (proven safe in submit, sess44).  Each dinode carries its own CRC, and
	 * xfs_inode_buf_verify validates per-dinode, so untouched peer sectors
	 * stay valid.  Default OFF keeps the stable build unchanged.
	 */
	{ extern int mxfs_surgical_inode_write;
	  extern int mxfs_pal_scsi_write_fua_bdev(struct block_device *,
			uint64_t, const void *, uint32_t);
	  if (unlikely(mxfs_surgical_inode_write) &&
	      (bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	      bp->b_mount->m_mxfs_dlm && bp->b_map_count == 1 &&
	      bp->b_target && bp->b_target->bt_bdev &&
	      !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	      (bp->b_ops == &xfs_inode_buf_ops ||
	       bp->b_ops == &xfs_inode_buf_ra_ops)) {
		uint32_t isize = bp->b_mount->m_sb.sb_inodesize;

		if (isize >= 512 && (isize & 511) == 0) {
			struct xfs_log_item *lip;
			uint64_t base = (uint64_t)bp->b_maps[0].bm_bn +
				bp->b_target->bt_sector_offset;
			int wrote = 0, werr = 0;

			list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
				struct xfs_inode_log_item *iip;
				uint32_t off;

				if (lip->li_type != XFS_LI_INODE)
					continue;
				iip = container_of(lip,
					struct xfs_inode_log_item, ili_item);
				if (!iip->ili_inode)
					continue;
				off = iip->ili_inode->i_imap.im_boffset;
				if ((uint32_t)off + isize > BBTOB(bp->b_length))
					continue;
				/* sess3 (ccloop 46efd8b6): this surgical FUA
				 * path was the ONE dir-dinode writer P-DIRDW
				 * missed (run 052155Z: LUN held chg=649 while
				 * the instrumented stream's max was 610).
				 * Same print so the platter history is total. */
				{
					struct xfs_dinode *sd =
						(struct xfs_dinode *)
						((char *)bp->b_addr + off);
					if (be16_to_cpu(sd->di_magic) ==
						XFS_DINODE_MAGIC &&
					    (be16_to_cpu(sd->di_mode) & S_IFMT)
						== S_IFDIR) {
						static atomic_t p3ds =
							ATOMIC_INIT(0);
						if (atomic_inc_return(&p3ds) <=
						    6000)
							pr_warn("mxfs: P-DIRDW daddr=%lld+%u reason=SURGICAL-fua ino=%llu fmt=%u nx=%u size=%lld chg=%llu comm=%s\n",
								(long long)bp->b_maps[0].bm_bn,
								off >> BBSHIFT,
								(unsigned long long)be64_to_cpu(sd->di_ino),
								sd->di_format,
								be32_to_cpu(sd->di_nextents),
								(long long)be64_to_cpu(sd->di_size),
								(unsigned long long)be64_to_cpu(sd->di_changecount),
								current->comm);
					}
				}
				if (mxfs_pal_scsi_write_fua_bdev(
					bp->b_target->bt_bdev,
					base + (off >> 9),
					(char *)bp->b_addr + off, isize) == 0)
					wrote++;
				else
					werr++;
			}
			/*
			 * Only skip the whole-cluster bio if we surgically wrote
			 * at least one inode and hit no errors; otherwise fall
			 * through to the normal submit (correctness over the
			 * optimization).
			 */
			if (wrote > 0 && werr == 0) {
				bp->b_error = 0;
				bp->b_flags |= XBF_DONE;
				xfs_buf_ioend(bp);
				return;
			}
		}
	} }

	/*
	 * sess63 (zero_silent_loss WRITER-SIDE ROOT FIX, RULE 4 — proven by direct
	 * platter read di_nextents=N / bmbt-leaf numrecs=N-1 + P133-BMBT-RELFLUSH-ERR
	 * rc=-5 on the SAME leaf daddr, and P60-BMBTWRITE max=N-1 cluster-wide so the
	 * Nth-record leaf write NEVER lands).  The BTREE-dir extent-map bmbt leaf is
	 * the off-by-one producer: under the 16-node shared-dir storm the plain
	 * REQ_OP_WRITE|REQ_META bio for the bmbt leaf intermittently fails -EIO on
	 * the iSCSI/SCST stack — the SAME bio-path failure the FUA *reads* already
	 * route around via SCSI passthrough (mxfs_buf_read_fua).  When the leaf write
	 * fails, di_nextents=N is still published from the inode cluster, so a
	 * reloading peer trips ir.loaded(N-1) != if_nextents(N) at xfs_iread_extents
	 * -> EFSCORRUPTED shutdown = the silent dirent loss.  Route the bmbt-leaf
	 * write through the SCSI FUA passthrough (durable, pierces the SCST write
	 * cache, bypasses the failing bio path) and complete the buffer exactly as
	 * the surgical-inode-write block above does.  This covers EVERY bmbt write
	 * path (xfs_bwrite from the iflush hook / release-flush, and xfsaild delwri)
	 * because they all funnel through xfs_buf_submit.  Scoped to xfs_bmbt_buf_ops
	 * (a dir has a handful of bmbt blocks) so sess29's "blanket FUA-write is a
	 * perf killer" does NOT apply.  On passthrough failure fall through to the
	 * normal bio so a write is never silently dropped.
	 */
	if ((bp->b_flags & XBF_WRITE) && bp->b_addr && bp->b_mount &&
	    bp->b_mount->m_mxfs_dlm && bp->b_map_count == 1 &&
	    bp->b_target && bp->b_target->bt_bdev &&
	    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
	    bp->b_ops == &xfs_bmbt_buf_ops) {
		int bmbt_fuawr;

		/*
		 * sess3 (ccloop 46efd8b6) ROOT FIX for the cache_coherency@32
		 * victim-shutdown family (RULE 4, PROVEN run 045621Z).  The
		 * sess66 tenure-authority gate (mxfs_buf_xfsaild_skip_bmbt_write)
		 * was placed in xfs_buf_submit_bio — but THIS sess63 FUA
		 * passthrough returns before submit_bio, so every bmbt write has
		 * BYPASSED the gate ever since: the iflush-hook's unconditional
		 * "destage even-clean cached leaf" and lingering prior-tenure
		 * images were FUA-written over a peer's newer leaf (P66-LEAFWRITE
		 * tenure=0 lsn=0, divergent numrecs 17->16->17 from many nodes in
		 * the same second; 96 landed vs 145 gate-skips that only fired on
		 * the rare passthrough-failure fallback path).  A reloading peer
		 * then ireads the regressed record set — internally consistent,
		 * so P59 never fires — and dies at P14-DABUF-HOLE (leaf/free
		 * reference a regrown block the stale map lacks) or bunmapi
		 * i!=1 -> dirty xfs_trans_cancel -> silent-looking FS shutdown ->
		 * mount-wide EIO (the "victim node" family).  Run the SAME gate
		 * here: a leaf image NOT produced under the dir's CURRENT EX
		 * tenure (or whose dir is NL-released) is superseded — complete
		 * the buffer without issuing the stale write so the peer's leaf
		 * stands.
		 */
		if (mxfs_buf_xfsaild_skip_bmbt_write(bp)) {
			/* sess6 (46efd8b6) tripwire — see
			 * mxfs_bmbt_skip_preserve_truth.  (bmbt is defer-
			 * stamped and this pre-counting site issues no bio,
			 * so the emulated ioend below cannot stamp wseq —
			 * a genuinely-logged image stays undestaged for the
			 * fence natively.) */
			mxfs_bmbt_skip_preserve_truth(bp, "fua");
			pr_warn_ratelimited(
				"mxfs: P61-FUA-SKIP-BMBT owner=%llu daddr=%lld numrecs=%u tenure=%llu — prior-tenure/NL leaf image, skipping FUA re-publish\n",
				(unsigned long long)be64_to_cpu(
					((struct xfs_btree_block *)
					 bp->b_addr)->bb_u.l.bb_owner),
				(long long)bp->b_maps[0].bm_bn,
				be16_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_numrecs),
				(unsigned long long)bp->b_tenure_id);
			bp->b_error = 0;
			/* sess6 (46efd8b6): no XBF_DONE resurrect — see the
			 * chokepoint skip arm. */
			xfs_buf_ioend(bp);
			return;
		}

		bmbt_fuawr = mxfs_buf_write_fua(bp);

		{
			struct xfs_btree_block *wb = bp->b_addr;
			static atomic_t p63wr = ATOMIC_INIT(0);
			if (be16_to_cpu(wb->bb_level) == 0 &&
			    atomic_inc_return(&p63wr) <= 4000) {
				/*
				 * sess4 (46efd8b6) STRAGGLER DISCRIMINATOR: the
				 * run-072239Z movie shows backward-content bmbt
				 * child images landing between a successor's
				 * grows (test30/test4 21-era at :46 after 24/25
				 * landed).  Capture, AT COMPLETION TIME, the
				 * owner dir's tenure state (mode/holders/seq vs
				 * the buffer's stamp) — a write completing at
				 * mode==NL or stamp!=seq is a cross-boundary
				 * straggler, caught in the act.
				 */
				uint64_t p63_seq = 0;
				int p63_mode = -1, p63_ex = -1;
				struct xfs_perag *p63_pag;
				struct xfs_inode *p63_ip;
				uint64_t p63_owner = be64_to_cpu(
					wb->bb_u.l.bb_owner);
				xfs_agnumber_t p63_agno =
					XFS_INO_TO_AGNO(bp->b_mount, p63_owner);

				if (p63_agno < bp->b_mount->m_sb.sb_agcount &&
				    (p63_pag = xfs_perag_get(bp->b_mount,
							     p63_agno))) {
					mxfs_ici_lock(p63_pag);
					p63_ip = radix_tree_lookup(
						&p63_pag->pag_ici_root,
						XFS_INO_TO_AGINO(bp->b_mount,
								 p63_owner));
					if (p63_ip && p63_ip->i_ino == p63_owner) {
						p63_seq = p63_ip->i_mxfs_ex_grant_seq;
						p63_mode = p63_ip->i_dlm_mode;
						p63_ex = p63_ip->i_dlm_ex_holders;
					}
					spin_unlock(&p63_pag->pag_ici_lock);
					xfs_perag_put(p63_pag);
				}
				pr_warn("mxfs: P63-LEAFWR owner=%llu daddr=%lld numrecs=%u rc=%d buf_tenure=%llu cur_seq=%llu mode=%d ex=%d comm=%s realns=%llu%s\n",
					(unsigned long long)p63_owner,
					(long long)bp->b_maps[0].bm_bn,
					be16_to_cpu(wb->bb_numrecs), bmbt_fuawr,
					(unsigned long long)bp->b_tenure_id,
					(unsigned long long)p63_seq,
					p63_mode, p63_ex,
					current->comm,
					(unsigned long long)ktime_get_real_ns(),
					(p63_mode == 0 ||
					 (p63_seq && bp->b_tenure_id != p63_seq)) ?
						" <<STRAGGLER" : "");
			}
		}
		if (bmbt_fuawr == 0) {
			bp->b_error = 0;
			bp->b_flags |= XBF_DONE;
			/* sess6 (46efd8b6): bmbt is defer-stamped (wseq at
			 * completion) but this synchronous SCSI FUA path never
			 * runs the submit_bio counting, so __xfs_buf_ioend
			 * won't stamp — the write has PHYSICALLY landed here,
			 * stamp honestly or the buffer reads undestaged
			 * forever and the release fence re-writes it every
			 * tenure. */
			bp->b_mxfs_written_seq = bp->b_mxfs_logged_seq;
			xfs_buf_ioend(bp);
			return;
		}
		pr_warn_ratelimited(
			"mxfs: P63-BMBT-FUAWR-FALLBACK daddr=%lld rc=%d — SCSI FUA passthrough write failed, falling back to bio\n",
			(long long)bp->b_maps[0].bm_bn, bmbt_fuawr);
	}

	xfs_buf_submit_bio(bp);
}

/*
 * Log a message about and stale a buffer that a caller has decided is corrupt.
 *
 * This function should be called for the kinds of metadata corruption that
 * cannot be detect from a verifier, such as incorrect inter-block relationship
 * data.  Do /not/ call this function from a verifier function.
 *
 * The buffer must be XBF_DONE prior to the call.  Afterwards, the buffer will
 * be marked stale, but b_error will not be set.  The caller is responsible for
 * releasing the buffer or fixing it.
 */
void
__xfs_buf_mark_corrupt(
	struct xfs_buf		*bp,
	xfs_failaddr_t		fa)
{
	ASSERT(bp->b_flags & XBF_DONE);

	xfs_buf_corruption_error(bp, fa);
	xfs_buf_stale(bp);
}

/*
 *	Handling of buffer targets (buftargs).
 */

/*
 * Wait for any bufs with callbacks that have been submitted but have not yet
 * returned. These buffers will have an elevated hold count, so wait on those
 * while freeing all the buffers only held by the LRU.
 */
static enum lru_status
xfs_buftarg_drain_rele(
	struct list_head	*item,
	struct list_lru_one	*lru,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
	spinlock_t		*lru_lock,
#endif
	void			*arg)

{
	struct xfs_buf		*bp = container_of(item, struct xfs_buf, b_lru);
	struct list_head	*dispose = arg;

	if (!spin_trylock(&bp->b_lock))
		return LRU_SKIP;
	if (bp->b_hold > 1) {
		/*
		 * sess76 (ccloop 14d31183) DIAGNOSTIC P-DRAINSTUCK: the unmount
		 * wedge moved here (xfs_buftarg_drain LRU loop) after the sess75
		 * bt_readahead_count fix.  A buffer pinned at b_hold>1 forever loops
		 * the drain.  Dump its identity so we can prove which path leaked the
		 * reference (suspected: the same stolen-readahead whose async ioend
		 * never ran to drop its hold).  Rate-limited.
		 */
		pr_warn_ratelimited(
			"mxfs: P-DRAINSTUCK daddr=%lld ops=%s hold=%d flags=0x%x state=0x%x pin=%d li_empty=%d has_bli=%d delwri=%d agmeta_hold=%d\n",
			(long long)bp->b_maps[0].bm_bn,
			(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
			bp->b_hold, bp->b_flags, bp->b_state,
			atomic_read(&bp->b_pin_count),
			list_empty(&bp->b_li_list) ? 1 : 0,
			bp->b_log_item ? 1 : 0,
			!!(bp->b_flags & _XBF_DELWRI_Q),
			atomic_read(&bp->b_mxfs_agmeta_hold));
#if MXFS_HOLD_TRACE
		/*
		 * sess-pve: replay this buffer's hold/rele ring so the leaked
		 * reference's acquisition site + caller is named directly.
		 * Once per buffer (b_mxfs_hr_dumped), and capped globally so
		 * multiple stuck buffers or the drain's repeated LRU re-walk
		 * cannot flood the log.
		 */
		if (!bp->b_mxfs_hr_dumped) {
			static atomic_t hrdump_n = ATOMIC_INIT(0);

			bp->b_mxfs_hr_dumped = 1;
			if (atomic_inc_return(&hrdump_n) <= 8) {
				static const char * const sn[] = {
					"ALLOC", "TRYHOLD", "HOLD", "STALE_LRU",
					"RA_ORPHAN", "RELE_UNCACH", "RELE_CACHED" };
				unsigned int h = bp->b_mxfs_hri;
				unsigned int n = (h < MXFS_HOLD_RING) ? h : MXFS_HOLD_RING;
				unsigned int i;

				pr_warn("mxfs: P-HOLDRING daddr=%lld ops=%s hold=%d flags=0x%x — %u events (oldest first):\n",
					(long long)bp->b_maps[0].bm_bn,
					(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
					bp->b_hold, bp->b_flags, n);
				for (i = 0; i < n; i++) {
					unsigned int idx = (h - n + i) % MXFS_HOLD_RING;
					struct mxfs_hold_evt *e = &bp->b_mxfs_hold_ring[idx];

					pr_warn("mxfs:   [%02u] %-11s delta=%+d hold=%u flags=0x%x caller=%pS\n",
						i,
						(e->site < ARRAY_SIZE(sn)) ? sn[e->site] : "?",
						e->delta, e->hold_after, e->flags,
						(void *)e->caller);
				}
			}
		}
#endif
		/* need to wait, so skip it this pass */
		spin_unlock(&bp->b_lock);
		trace_xfs_buf_drain_buftarg(bp, _RET_IP_);
		return LRU_SKIP;
	}

	/*
	 * clear the LRU reference count so the buffer doesn't get
	 * ignored in xfs_buf_rele().
	 */
	atomic_set(&bp->b_lru_ref, 0);
	bp->b_state |= XFS_BSTATE_DISPOSE;
	list_lru_isolate_move(lru, item, dispose);
	spin_unlock(&bp->b_lock);
	return LRU_REMOVED;
}

/*
 * Wait for outstanding I/O on the buftarg to complete.
 */
void
xfs_buftarg_wait(
	struct xfs_buftarg	*btp)
{
	/*
	 * First wait for all in-flight readahead buffers to be released.  This is
	 * critical as new buffers do not make the LRU until they are released.
	 *
	 * Next, flush the buffer workqueue to ensure all completion processing
	 * has finished. Just waiting on buffer locks is not sufficient for
	 * async IO as the reference count held over IO is not released until
	 * after the buffer lock is dropped. Hence we need to ensure here that
	 * all reference counts have been dropped before we start walking the
	 * LRU list.
	 */
	while (percpu_counter_sum(&btp->bt_readahead_count))
		delay(100);
	flush_workqueue(btp->bt_mount->m_buf_workqueue);
}

void
xfs_buftarg_drain(
	struct xfs_buftarg	*btp)
{
	LIST_HEAD(dispose);
	int			loop = 0;
	bool			write_fail = false;

	xfs_buftarg_wait(btp);

	/* loop until there is nothing left on the lru list. */
	while (list_lru_count(&btp->bt_lru)) {
		list_lru_walk(&btp->bt_lru, xfs_buftarg_drain_rele,
			      &dispose, LONG_MAX);

		while (!list_empty(&dispose)) {
			struct xfs_buf *bp;
			bp = list_first_entry(&dispose, struct xfs_buf, b_lru);
			list_del_init(&bp->b_lru);
			if (bp->b_flags & XBF_WRITE_FAIL) {
				write_fail = true;
				xfs_buf_alert_ratelimited(bp,
					"XFS: Corruption Alert",
"Corruption Alert: Buffer at daddr 0x%llx had permanent write failures!",
					(long long)xfs_buf_daddr(bp));
			}
			xfs_buf_rele(bp);
		}
		if (loop++ != 0)
			delay(100);
	}

	/*
	 * If one or more failed buffers were freed, that means dirty metadata
	 * was thrown away. This should only ever happen after I/O completion
	 * handling has elevated I/O error(s) to permanent failures and shuts
	 * down the journal.
	 */
	if (write_fail) {
		ASSERT(xlog_is_shutdown(btp->bt_mount->m_log));
		xfs_alert(btp->bt_mount,
	      "Please run xfs_repair to determine the extent of the problem.");
	}
}

static enum lru_status
xfs_buftarg_isolate(
	struct list_head	*item,
	struct list_lru_one	*lru,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
	spinlock_t		*lru_lock,
#endif
	void			*arg)
{
	struct xfs_buf		*bp = container_of(item, struct xfs_buf, b_lru);
	struct list_head	*dispose = arg;

	/*
	 * we are inverting the lru lock/bp->b_lock here, so use a trylock.
	 * If we fail to get the lock, just skip it.
	 */
	if (!spin_trylock(&bp->b_lock))
		return LRU_SKIP;
	/*
	 * sess7(a9a03929) FIX-19 (RULE-4 PROVEN, run92 r1): an UNDESTAGED
	 * mxfs dir buffer (lseq!=wseq or pinned — committed content whose
	 * only landed copy is the journal, which nothing replays without a
	 * crash) looks CLEAN here (no BLI hold, dirty=0), so drop_caches /
	 * memory pressure reclaimed it and the committed dirents evaporated
	 * cluster-wide: node7's md5-tail bp (daddr=4188352 lseq=15 wseq=0)
	 * was freed by the verify-phase drop_caches while node7 still held
	 * EX with no release in between; every node then FUA-read the
	 * pre-add platter (795/800, LOOKUP_ENOENT + REREAD_MISS).  Dir-class
	 * buffers carrying undestaged local commits must survive reclaim
	 * until the release-drain lands them (their BLI-less seq tracking is
	 * mxfs's own; upstream buffers are protected by the BLI/AIL hold).
	 */
	if (bp->b_ops &&
	    (bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_free_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     bp->b_ops == &xfs_da3_node_buf_ops) &&
	    mxfs_dir_buf_is_undestaged(bp)) {
		static atomic_t p19_n = ATOMIC_INIT(0);

		if ((unsigned)atomic_inc_return(&p19_n) <= 2000)
			pr_warn("mxfs: P-SHRINK-UNDEST-ROTATE daddr=%lld ops=%s lseq=%llu wseq=%llu pin=%d — refusing reclaim of committed-undestaged dir buffer\n",
				(long long)bp->b_maps[0].bm_bn,
				bp->b_ops->name ? bp->b_ops->name : "?",
				(unsigned long long)bp->b_mxfs_logged_seq,
				(unsigned long long)bp->b_mxfs_written_seq,
				atomic_read(&bp->b_pin_count));
		spin_unlock(&bp->b_lock);
		return LRU_ROTATE;
	}
	/*
	 * Decrement the b_lru_ref count unless the value is already
	 * zero. If the value is already zero, we need to reclaim the
	 * buffer, otherwise it gets another trip through the LRU.
	 */
	if (atomic_add_unless(&bp->b_lru_ref, -1, 0)) {
		spin_unlock(&bp->b_lock);
		return LRU_ROTATE;
	}

	bp->b_state |= XFS_BSTATE_DISPOSE;
	list_lru_isolate_move(lru, item, dispose);
	spin_unlock(&bp->b_lock);
	return LRU_REMOVED;
}

static unsigned long
xfs_buftarg_shrink_scan(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct xfs_buftarg	*btp = shrink->private_data;
	LIST_HEAD(dispose);
	unsigned long		freed;

	freed = list_lru_shrink_walk(&btp->bt_lru, sc,
				     xfs_buftarg_isolate, &dispose);

	while (!list_empty(&dispose)) {
		struct xfs_buf *bp;
		bp = list_first_entry(&dispose, struct xfs_buf, b_lru);
		list_del_init(&bp->b_lru);
		xfs_buf_rele(bp);
	}

	return freed;
}

static unsigned long
xfs_buftarg_shrink_count(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct xfs_buftarg	*btp = shrink->private_data;
	return list_lru_shrink_count(&btp->bt_lru, sc);
}

void
xfs_destroy_buftarg(
	struct xfs_buftarg	*btp)
{
	shrinker_free(btp->bt_shrinker);
	ASSERT(percpu_counter_sum(&btp->bt_readahead_count) == 0);
	percpu_counter_destroy(&btp->bt_readahead_count);
	list_lru_destroy(&btp->bt_lru);
}

void
xfs_free_buftarg(
	struct xfs_buftarg	*btp)
{
	xfs_destroy_buftarg(btp);
	fs_put_dax(btp->bt_daxdev, btp->bt_mount);
	/* the main block device is closed by kill_block_super */
	if (btp->bt_bdev != btp->bt_mount->m_super->s_bdev)
		bdev_fput(btp->bt_file);
	kfree(btp);
}

/*
 * Configure this buffer target for hardware-assisted atomic writes if the
 * underlying block device supports is congruent with the filesystem geometry.
 */
static inline void
xfs_configure_buftarg_atomic_writes(
	struct xfs_buftarg	*btp)
{
	struct xfs_mount	*mp = btp->bt_mount;
	unsigned int		min_bytes, max_bytes;

	min_bytes = bdev_atomic_write_unit_min_bytes(btp->bt_bdev);
	max_bytes = bdev_atomic_write_unit_max_bytes(btp->bt_bdev);

	/*
	 * Ignore atomic write geometry that is nonsense or doesn't even cover
	 * a single fsblock.
	 */
	if (min_bytes > max_bytes ||
	    min_bytes > mp->m_sb.sb_blocksize ||
	    max_bytes < mp->m_sb.sb_blocksize) {
		min_bytes = 0;
		max_bytes = 0;
	}

	btp->bt_awu_min = min_bytes;
	btp->bt_awu_max = max_bytes;
}

/* Configure a buffer target that abstracts a block device. */
int
xfs_configure_buftarg(
	struct xfs_buftarg	*btp,
	unsigned int		sectorsize,
	xfs_rfsblock_t		nr_blocks)
{
	struct xfs_mount	*mp = btp->bt_mount;

	if (btp->bt_bdev) {
		int		error;

		error = bdev_validate_blocksize(btp->bt_bdev, sectorsize);
		if (error) {
			xfs_warn(mp,
				"Cannot use blocksize %u on device %pg, err %d",
				sectorsize, btp->bt_bdev, error);
			return -EINVAL;
		}

		if (bdev_can_atomic_write(btp->bt_bdev))
			xfs_configure_buftarg_atomic_writes(btp);
	}

	btp->bt_meta_sectorsize = sectorsize;
	btp->bt_meta_sectormask = sectorsize - 1;
	/* m_blkbb_log is not set up yet */
	btp->bt_nr_sectors = nr_blocks << (mp->m_sb.sb_blocklog - BBSHIFT);
	return 0;
}

int
xfs_init_buftarg(
	struct xfs_buftarg		*btp,
	size_t				logical_sectorsize,
	const char			*descr)
{
	/* The maximum size of the buftarg is only known once the sb is read. */
	btp->bt_nr_sectors = XFS_BUF_DADDR_MAX;

	/* Set up device logical sector size mask */
	btp->bt_logical_sectorsize = logical_sectorsize;
	btp->bt_logical_sectormask = logical_sectorsize - 1;

	/*
	 * Buffer IO error rate limiting. Limit it to no more than 10 messages
	 * per 30 seconds so as to not spam logs too much on repeated errors.
	 */
	ratelimit_state_init(&btp->bt_ioerror_rl, 30 * HZ,
			     DEFAULT_RATELIMIT_BURST);

	if (list_lru_init(&btp->bt_lru))
		return -ENOMEM;
	if (percpu_counter_init(&btp->bt_readahead_count, 0, GFP_KERNEL))
		goto out_destroy_lru;

	btp->bt_shrinker =
		shrinker_alloc(SHRINKER_NUMA_AWARE, "xfs-buf:%s", descr);
	if (!btp->bt_shrinker)
		goto out_destroy_io_count;
	btp->bt_shrinker->count_objects = xfs_buftarg_shrink_count;
	btp->bt_shrinker->scan_objects = xfs_buftarg_shrink_scan;
	btp->bt_shrinker->private_data = btp;
	shrinker_register(btp->bt_shrinker);
	return 0;

out_destroy_io_count:
	percpu_counter_destroy(&btp->bt_readahead_count);
out_destroy_lru:
	list_lru_destroy(&btp->bt_lru);
	return -ENOMEM;
}

struct xfs_buftarg *
xfs_alloc_buftarg(
	struct xfs_mount	*mp,
	struct file		*bdev_file)
{
	struct xfs_buftarg	*btp;
	const struct dax_holder_operations *ops = NULL;
	int			error;


#if defined(CONFIG_FS_DAX) && defined(CONFIG_MEMORY_FAILURE)
	ops = &xfs_dax_holder_operations;
#endif
	btp = kzalloc(sizeof(*btp), GFP_KERNEL | __GFP_NOFAIL);

	btp->bt_mount = mp;
	btp->bt_file = bdev_file;
	btp->bt_bdev = file_bdev(bdev_file);
	btp->bt_dev = btp->bt_bdev->bd_dev;
	btp->bt_daxdev = fs_dax_get_by_bdev(btp->bt_bdev, &btp->bt_dax_part_off,
					    mp, ops);

	/*
	 * Flush and invalidate all devices' pagecaches before reading any
	 * metadata because XFS doesn't use the bdev pagecache.
	 */
	error = sync_blockdev(btp->bt_bdev);
	if (error)
		goto error_free;

	/*
	 * When allocating the buftargs we have not yet read the super block and
	 * thus don't know the file system sector size yet.
	 */
	btp->bt_meta_sectorsize = bdev_logical_block_size(btp->bt_bdev);
	btp->bt_meta_sectormask = btp->bt_meta_sectorsize - 1;

	error = xfs_init_buftarg(btp, btp->bt_meta_sectorsize,
				mp->m_super->s_id);
	if (error)
		goto error_free;

	return btp;

error_free:
	kfree(btp);
	return ERR_PTR(error);
}

static inline void
xfs_buf_list_del(
	struct xfs_buf		*bp)
{
	list_del_init(&bp->b_list);
	wake_up_var(&bp->b_list);
}

/*
 * Cancel a delayed write list.
 *
 * Remove each buffer from the list, clear the delwri queue flag and drop the
 * associated buffer reference.
 */
void
xfs_buf_delwri_cancel(
	struct list_head	*list)
{
	struct xfs_buf		*bp;

	while (!list_empty(list)) {
		bp = list_first_entry(list, struct xfs_buf, b_list);

		xfs_buf_lock(bp);
		bp->b_flags &= ~(_XBF_DELWRI_Q | _XBF_MXFS_ALLOC_QUEUED);
		xfs_buf_list_del(bp);
		xfs_buf_relse(bp);
	}
}

/*
 * Add a buffer to the delayed write list.
 *
 * This queues a buffer for writeout if it hasn't already been.  Note that
 * neither this routine nor the buffer list submission functions perform
 * any internal synchronization.  It is expected that the lists are thread-local
 * to the callers.
 *
 * Returns true if we queued up the buffer, or false if it already had
 * been on the buffer list.
 */
bool
xfs_buf_delwri_queue(
	struct xfs_buf		*bp,
	struct list_head	*list)
{
	ASSERT(xfs_buf_islocked(bp));
	ASSERT(!(bp->b_flags & XBF_READ));

	/*
	 * If the buffer is already marked delwri it already is queued up
	 * by someone else for imediate writeout.  Just ignore it in that
	 * case.
	 */
	if (bp->b_flags & _XBF_DELWRI_Q) {
		trace_xfs_buf_delwri_queued(bp, _RET_IP_);
		return false;
	}

	trace_xfs_buf_delwri_queue(bp, _RET_IP_);

	/*
	 * If a buffer gets written out synchronously or marked stale while it
	 * is on a delwri list we lazily remove it. To do this, the other party
	 * clears the  _XBF_DELWRI_Q flag but otherwise leaves the buffer alone.
	 * It remains referenced and on the list.  In a rare corner case it
	 * might get readded to a delwri list after the synchronous writeout, in
	 * which case we need just need to re-add the flag here.
	 */
	bp->b_flags |= _XBF_DELWRI_Q;
	if (list_empty(&bp->b_list)) {
		xfs_buf_hold(bp);
		list_add_tail(&bp->b_list, list);
	}

	return true;
}

/*
 * Queue a buffer to this delwri list as part of a data integrity operation.
 * If the buffer is on any other delwri list, we'll wait for that to clear
 * so that the caller can submit the buffer for IO and wait for the result.
 * Callers must ensure the buffer is not already on the list.
 */
void
xfs_buf_delwri_queue_here(
	struct xfs_buf		*bp,
	struct list_head	*buffer_list)
{
	/*
	 * We need this buffer to end up on the /caller's/ delwri list, not any
	 * old list.  This can happen if the buffer is marked stale (which
	 * clears DELWRI_Q) after the AIL queues the buffer to its list but
	 * before the AIL has a chance to submit the list.
	 */
	while (!list_empty(&bp->b_list)) {
		xfs_buf_unlock(bp);
		wait_var_event(&bp->b_list, list_empty(&bp->b_list));
		xfs_buf_lock(bp);
	}

	ASSERT(!(bp->b_flags & _XBF_DELWRI_Q));

	xfs_buf_delwri_queue(bp, buffer_list);
}

/*
 * Compare function is more complex than it needs to be because
 * the return value is only 32 bits and we are doing comparisons
 * on 64 bit values
 */
static int
xfs_buf_cmp(
	void			*priv,
	const struct list_head	*a,
	const struct list_head	*b)
{
	struct xfs_buf	*ap = container_of(a, struct xfs_buf, b_list);
	struct xfs_buf	*bp = container_of(b, struct xfs_buf, b_list);
	xfs_daddr_t		diff;

	diff = ap->b_maps[0].bm_bn - bp->b_maps[0].bm_bn;
	if (diff < 0)
		return -1;
	if (diff > 0)
		return 1;
	return 0;
}

static bool
xfs_buf_delwri_submit_prep(
	struct xfs_buf		*bp)
{
	/*
	 * Someone else might have written the buffer synchronously or marked it
	 * stale in the meantime.  In that case only the _XBF_DELWRI_Q flag got
	 * cleared, and we have to drop the reference and remove it from the
	 * list here.
	 */
	if (!(bp->b_flags & _XBF_DELWRI_Q)) {
		xfs_buf_list_del(bp);
		xfs_buf_relse(bp);
		return false;
	}

	trace_xfs_buf_delwri_split(bp, _RET_IP_);
	bp->b_flags &= ~(_XBF_DELWRI_Q | _XBF_MXFS_ALLOC_QUEUED);
	bp->b_flags |= XBF_WRITE;
	return true;
}

/*
 * Write out a buffer list asynchronously.
 *
 * This will take the @buffer_list, write all non-locked and non-pinned buffers
 * out and not wait for I/O completion on any of the buffers.  This interface
 * is only safely useable for callers that can track I/O completion by higher
 * level means, e.g. AIL pushing as the @buffer_list is consumed in this
 * function.
 *
 * Note: this function will skip buffers it would block on, and in doing so
 * leaves them on @buffer_list so they can be retried on a later pass. As such,
 * it is up to the caller to ensure that the buffer list is fully submitted or
 * cancelled appropriately when they are finished with the list. Failure to
 * cancel or resubmit the list until it is empty will result in leaked buffers
 * at unmount time.
 */
int
xfs_buf_delwri_submit_nowait(
	struct list_head	*buffer_list)
{
	struct xfs_buf		*bp, *n;
	int			pinned = 0;
	struct blk_plug		plug;

	list_sort(NULL, buffer_list, xfs_buf_cmp);

	blk_start_plug(&plug);
	list_for_each_entry_safe(bp, n, buffer_list, b_list) {
		if (!xfs_buf_trylock(bp))
			continue;
		if (xfs_buf_ispinned(bp)) {
			xfs_buf_unlock(bp);
			pinned++;
			continue;
		}
		if (!xfs_buf_delwri_submit_prep(bp))
			continue;
		bp->b_flags |= XBF_ASYNC;
		xfs_buf_list_del(bp);
		xfs_buf_submit(bp);
	}
	blk_finish_plug(&plug);

	return pinned;
}

/*
 * Write out a buffer list synchronously.
 *
 * This will take the @buffer_list, write all buffers out and wait for I/O
 * completion on all of the buffers. @buffer_list is consumed by the function,
 * so callers must have some other way of tracking buffers if they require such
 * functionality.
 */
int
xfs_buf_delwri_submit(
	struct list_head	*buffer_list)
{
	LIST_HEAD		(wait_list);
	int			error = 0, error2;
	struct xfs_buf		*bp, *n;
	struct blk_plug		plug;

	list_sort(NULL, buffer_list, xfs_buf_cmp);

	blk_start_plug(&plug);
	list_for_each_entry_safe(bp, n, buffer_list, b_list) {
		xfs_buf_lock(bp);
		if (!xfs_buf_delwri_submit_prep(bp))
			continue;
		bp->b_flags &= ~XBF_ASYNC;
		list_move_tail(&bp->b_list, &wait_list);
		xfs_buf_submit(bp);
	}
	blk_finish_plug(&plug);

	/* Wait for IO to complete. */
	while (!list_empty(&wait_list)) {
		bp = list_first_entry(&wait_list, struct xfs_buf, b_list);

		xfs_buf_list_del(bp);

		/*
		 * Wait on the locked buffer, check for errors and unlock and
		 * release the delwri queue reference.
		 */
		error2 = xfs_buf_iowait(bp);
		xfs_buf_relse(bp);
		if (!error)
			error = error2;
	}

	return error;
}

/*
 * v0.5.5 (sess25 ccloop 14d31183): write out a buffer list synchronously
 * WITHOUT ever sleeping on a pinned buffer while holding its lock.
 *
 * xfs_buf_delwri_submit() calls xfs_buf_submit() with the buffer locked;
 * for a pinned buffer that sleeps in xfs_buf_wait_unpin() until the
 * pinning CIL sequence commits.  MXFS's per-AG eager drain runs this on
 * hot AGI/inode-cluster buffers that concurrent creates RE-log right
 * after the caller's log force, so the buffer is pinned by a NEWER CIL
 * sequence that nothing pushes until the 30 s log worker tick — and
 * every other task on the node then convoys on the held buffer lock.
 * Stack-sample proof (scaling_curve, 4-node): 15.8 s in
 * xfs_buf_wait_unpin under mxfs_dlm_ag_drain_alloc_buflist plus 15.8 s
 * of peer tasks in xfs_buf_lock on the same buffer = the intermittent
 * 20-30 s one-node stall.
 *
 * Strategy: each round, submit every currently-unpinned buffer
 * (collecting them on a wait list), SKIP pinned ones without holding
 * their locks, wait for the submitted I/O, then if pinned buffers
 * remain force the log synchronously (commits the pinning sequence,
 * unpins them) and repeat.  After 10 rounds fall back to the blocking
 * path (forward-progress guard; a fresh log force right before makes
 * the re-pin window microseconds wide).
 */
int
xfs_buf_delwri_submit_nopinwait(
	struct xfs_mount	*mp,
	struct list_head	*buffer_list)
{
	LIST_HEAD		(wait_list);
	int			error = 0, error2;
	struct xfs_buf		*bp, *n;
	struct blk_plug		plug;
	int			round = 0;

	while (!list_empty(buffer_list)) {
		unsigned int	pinned = 0;

		if (round == 10)
			xfs_log_force(mp, XFS_LOG_SYNC);

		list_sort(NULL, buffer_list, xfs_buf_cmp);

		blk_start_plug(&plug);
		list_for_each_entry_safe(bp, n, buffer_list, b_list) {
			xfs_buf_lock(bp);
			if (round < 10 && xfs_buf_ispinned(bp)) {
				xfs_buf_unlock(bp);
				pinned++;
				continue;
			}
			if (!xfs_buf_delwri_submit_prep(bp))
				continue;
			bp->b_flags &= ~XBF_ASYNC;
			list_move_tail(&bp->b_list, &wait_list);
			xfs_buf_submit(bp);
		}
		blk_finish_plug(&plug);

		/* Wait for IO to complete. */
		while (!list_empty(&wait_list)) {
			bp = list_first_entry(&wait_list, struct xfs_buf,
					      b_list);

			xfs_buf_list_del(bp);

			error2 = xfs_buf_iowait(bp);
			xfs_buf_relse(bp);
			if (!error)
				error = error2;
		}

		if (pinned)
			xfs_log_force(mp, XFS_LOG_SYNC);
		round++;
	}

	return error;
}

void xfs_buf_set_ref(struct xfs_buf *bp, int lru_ref)
{
	/*
	 * Set the lru reference count to 0 based on the error injection tag.
	 * This allows userspace to disrupt buffer caching for debug/testing
	 * purposes.
	 */
	if (XFS_TEST_ERROR(bp->b_mount, XFS_ERRTAG_BUF_LRU_REF))
		lru_ref = 0;

	atomic_set(&bp->b_lru_ref, lru_ref);
}

/*
 * Verify an on-disk magic value against the magic value specified in the
 * verifier structure. The verifier magic is in disk byte order so the caller is
 * expected to pass the value directly from disk.
 */
bool
xfs_verify_magic(
	struct xfs_buf		*bp,
	__be32			dmagic)
{
	struct xfs_mount	*mp = bp->b_mount;
	int			idx;

	idx = xfs_has_crc(mp);
	if (WARN_ON(!bp->b_ops || !bp->b_ops->magic[idx]))
		return false;
	return dmagic == bp->b_ops->magic[idx];
}
/*
 * Verify an on-disk magic value against the magic value specified in the
 * verifier structure. The verifier magic is in disk byte order so the caller is
 * expected to pass the value directly from disk.
 */
bool
xfs_verify_magic16(
	struct xfs_buf		*bp,
	__be16			dmagic)
{
	struct xfs_mount	*mp = bp->b_mount;
	int			idx;

	idx = xfs_has_crc(mp);
	if (WARN_ON(!bp->b_ops || !bp->b_ops->magic16[idx]))
		return false;
	return dmagic == bp->b_ops->magic16[idx];
}
