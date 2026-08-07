// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_iomap.h"
#include "xfs_trace.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_reflink.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_mxfs_dlm.h"
#include <mxfs/mxfs_dlm.h>	/* FIX-26/P26PRE: MXFS_LOCK_* modes */
#include <linux/hashtable.h>	/* FIX-26 writepages task registry */

/* sess45: declared locally (as in xfs_da_btree.c) — not exported via a header. */
extern bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx);

struct xfs_writepage_ctx {
	struct iomap_writepage_ctx ctx;
	unsigned int		data_seq;
	unsigned int		cow_seq;
};

static inline struct xfs_writepage_ctx *
XFS_WPC(struct iomap_writepage_ctx *ctx)
{
	return container_of(ctx, struct xfs_writepage_ctx, ctx);
}

/*
 * Fast and loose check if this write could update the on-disk inode size.
 */
static inline bool xfs_ioend_is_append(struct iomap_ioend *ioend)
{
	return ioend->io_offset + ioend->io_size >
		XFS_I(ioend->io_inode)->i_disk_size;
}

/*
 * Update on-disk file size now that data has been written to disk.
 */
int
xfs_setfilesize(
	struct xfs_inode	*ip,
	xfs_off_t		offset,
	size_t			size)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	xfs_fsize_t		isize;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_fsyncts, 0, 0, 0, &tp);
	if (error)
		return error;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	isize = xfs_new_eof(ip, offset + size);
	/* P-SFS (sess10 ccloop 72513a13, RULE-4 for the drc size=0 loss):
	 * xfs_new_eof clamps to VFS i_size — if a reload/evict reset the
	 * in-core size to 0 while this ioend was pending, the append
	 * setfilesize silently no-ops and di_size=0 becomes durable.
	 * Print BOTH arms so the severing (isize=0 with end>di_size) is
	 * directly visible. */
	{
		static atomic_t p_sfs_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_sfs_n) <= 1500)
			pr_warn("mxfs: P-SFS ino=%llu end=%llu isize=%llu vfs=%llu disk=%llu dlm_state=%u comm=%s\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)(offset + size),
				(unsigned long long)isize,
				(unsigned long long)i_size_read(VFS_I(ip)),
				(unsigned long long)ip->i_disk_size,
				ip->i_dlm_state, current->comm);
	}
	if (!isize) {
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		xfs_trans_cancel(tp);
		return 0;
	}

	trace_xfs_setfilesize(ip, offset, size);

	ip->i_disk_size = isize;
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);

	return xfs_trans_commit(tp);
}

/*
 * IO write completion.
 *
 * io_bio was a pointer and io_type (IOMAP_UNWRITTEN) / IOMAP_F_SHARED were
 * the classifiers pre-v6.17; v6.17 embeds io_bio and replaces io_type with
 * per-ioend IOMAP_IOEND_UNWRITTEN/IOMAP_IOEND_SHARED flags (GPT-assisted
 * port, cross-checked against 6.17.2-1-pve's actual linux/iomap.h before
 * applying -- see pal.md Known Pitfalls). mxfs_ioend_unwritten/shared below
 * hide the difference so xfs_end_ioend's own logic doesn't fork.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#define mxfs_ioend_bi_status(ioend)	((ioend)->io_bio->bi_status)
#define mxfs_ioend_shared(ioend)	((ioend)->io_flags & IOMAP_F_SHARED)
#define mxfs_ioend_unwritten(ioend)	((ioend)->io_type == IOMAP_UNWRITTEN)
#define mxfs_ioend_set_bi_end_io(ioend, fn)	((ioend)->io_bio->bi_end_io = (fn))
#else
#define mxfs_ioend_bi_status(ioend)	((ioend)->io_bio.bi_status)
#define mxfs_ioend_shared(ioend)	((ioend)->io_flags & IOMAP_IOEND_SHARED)
#define mxfs_ioend_unwritten(ioend)	((ioend)->io_flags & IOMAP_IOEND_UNWRITTEN)
#define mxfs_ioend_set_bi_end_io(ioend, fn)	((ioend)->io_bio.bi_end_io = (fn))
#endif

STATIC void
xfs_end_ioend(
	struct iomap_ioend	*ioend)
{
	struct xfs_inode	*ip = XFS_I(ioend->io_inode);
	struct xfs_mount	*mp = ip->i_mount;
	xfs_off_t		offset = ioend->io_offset;
	size_t			size = ioend->io_size;
	unsigned int		nofs_flag;
	int			error;

	/*
	 * We can allocate memory here while doing writeback on behalf of
	 * memory reclaim.  To avoid memory allocation deadlocks set the
	 * task-wide nofs context for the following operations.
	 */
	nofs_flag = memalloc_nofs_save();

	/*
	 * Just clean up the in-memory structures if the fs has been shut down.
	 */
	if (xfs_is_shutdown(mp)) {
		error = -EIO;
		goto done;
	}

	/*
	 * Clean up all COW blocks and underlying data fork delalloc blocks on
	 * I/O error. The delalloc punch is required because this ioend was
	 * mapped to blocks in the COW fork and the associated pages are no
	 * longer dirty. If we don't remove delalloc blocks here, they become
	 * stale and can corrupt free space accounting on unmount.
	 */
	error = blk_status_to_errno(mxfs_ioend_bi_status(ioend));
	if (unlikely(error)) {
		if (mxfs_ioend_shared(ioend)) {
			xfs_reflink_cancel_cow_range(ip, offset, size, true);
			mxfs_bmap_punch_delalloc_range(ip, offset,
					offset + size);
		}
		goto done;
	}

	/*
	 * Success: commit the COW or unwritten blocks if needed.
	 */
	if (mxfs_ioend_shared(ioend))
		error = xfs_reflink_end_cow(ip, offset, size);
	else if (mxfs_ioend_unwritten(ioend))
		error = xfs_iomap_write_unwritten(ip, offset, size, false);

	if (!error && xfs_ioend_is_append(ioend))
		error = xfs_setfilesize(ip, ioend->io_offset, ioend->io_size);
done:
	/* P-IOEND-ERR (sess10): an errored ioend ends page writeback WITHOUT
	 * setfilesize — sync(2) swallows it and the durable size stays short.
	 * Make every such swallow loud. */
	if (unlikely(error)) {
		static atomic_t p_ioerr_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_ioerr_n) <= 300)
			pr_warn("mxfs: P-IOEND-ERR ino=%llu off=%llu sz=%zu unwritten=%d shared=%d err=%d vfs=%llu disk=%llu\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)offset, size,
				!!mxfs_ioend_unwritten(ioend),
				!!mxfs_ioend_shared(ioend), error,
				(unsigned long long)i_size_read(VFS_I(ip)),
				(unsigned long long)ip->i_disk_size);
	}
	iomap_finish_ioends(ioend, error);
	memalloc_nofs_restore(nofs_flag);
}

/*
 * Finish all pending IO completions that require transactional modifications.
 *
 * We try to merge physical and logically contiguous ioends before completion to
 * minimise the number of transactions we need to perform during IO completion.
 * Both unwritten extent conversion and COW remapping need to iterate and modify
 * one physical extent at a time, so we gain nothing by merging physically
 * discontiguous extents here.
 *
 * The ioend chain length that we can be processing here is largely unbound in
 * length and we may have to perform significant amounts of work on each ioend
 * to complete it. Hence we have to be careful about holding the CPU for too
 * long in this loop.
 */
void
xfs_end_io(
	struct work_struct	*work)
{
	struct xfs_inode	*ip =
		container_of(work, struct xfs_inode, i_ioend_work);
	struct iomap_ioend	*ioend;
	struct list_head	tmp;
	unsigned long		flags;

	spin_lock_irqsave(&ip->i_ioend_lock, flags);
	list_replace_init(&ip->i_ioend_list, &tmp);
	spin_unlock_irqrestore(&ip->i_ioend_lock, flags);

	iomap_sort_ioends(&tmp);
	while ((ioend = list_first_entry_or_null(&tmp, struct iomap_ioend,
			io_list))) {
		list_del_init(&ioend->io_list);
		iomap_ioend_try_merge(ioend, &tmp);
		xfs_end_ioend(ioend);
		cond_resched();
	}
}

/*
 * FIX-25 (sess8 a9a03929): is the current task the xfs-conv ioend completion
 * worker?  mxfs_dlm_ilock_begin admits this context to a nested EX during a
 * BAST/DEMOTING drain while the DLM mirror still holds EX — the drain's
 * filemap_write_and_wait cannot complete without it (folio-writeback →
 * xfs_end_ioend → xfs_ilock(EX) → demote-wait cycle; run109 test6 wedged
 * 150s+ with live stacks on all three legs).
 */
bool
xfs_task_in_ioend(void)
{
	struct work_struct *w = current_work();

	return w && w->func == xfs_end_io;
}

/*
 * FIX-26 (ccloop c7ee71c6 sess6): registry of tasks currently inside
 * xfs_vm_writepages.  Writeback SUBMISSION (bdi flusher, sync, fsync) holds
 * the folio lock across ->map_blocks, whose delalloc conversion takes
 * xfs_ilock(EX) -> mxfs_dlm_ilock_begin.  If the inode is mid-BAST, the
 * demote-wait would park the submitter while the drain's
 * filemap_write_and_wait spins on the submitter's folio lock — a permanent
 * two-worker deadlock (captured live on test8, 2026-07-25: flusher D-state
 * in mxfs_dlm_ilock_begin under iomap_writepage_map, mxfs-ino-bast worker
 * D-state in __folio_lock under mxfs_dlm_bast_process).  There is no work-fn
 * signature usable here (wb_workfn is static to fs core and sync/fsync enter
 * from syscall context), so the writepages wrapper brackets the call with a
 * stack-resident registry entry keyed by task pointer.
 */
#define XFS_WPTASK_HASH_BITS	6
static DEFINE_SPINLOCK(xfs_wptask_lock);
static DEFINE_HASHTABLE(xfs_wptask_hash, XFS_WPTASK_HASH_BITS);

/* FIX-26 verification injection — see xfs_map_blocks.  Debug-only, 0 = off. */
int mxfs_fix26_delay_ms;
module_param_named(fix26_delay_ms, mxfs_fix26_delay_ms, int, 0644);
MODULE_PARM_DESC(fix26_delay_ms,
	"DEBUG: widen the writeback folio-locked->ilock window by N ms so a peer BAST can be deterministically collided with the FIX-26 admit (0=off)");

/*
 * FIX-27 verification injection (ccloop c7ee71c6 sess24) — see xfs_map_blocks.
 *
 * fix26_delay_ms is placed in xfs_convert_blocks, i.e. the DELALLOC CONVERSION
 * path, which asks for xfs_ilock(EX).  That exercises the EX admit.  It cannot
 * exercise FIX-27, whose whole point is that the submitter's FIRST lock in this
 * path is SHARED: xfs_map_blocks() takes xfs_ilock(ip, XFS_ILOCK_SHARED) before
 * any conversion is considered, and a folio needing no conversion never reaches
 * xfs_convert_blocks at all.
 *
 * So this injection sits at the xfs_map_blocks SHARED acquire, folio already
 * locked.  Note the FIX-26 comment records that a v1 injection at map_blocks
 * entry bought no window "because only the first folio of a walk converts" —
 * true for the EX path, and exactly why it is the RIGHT place for the SHARED
 * path: every folio's map_blocks takes the shared lock, so every one is a
 * genuine collision candidate.  Debug-only, 0 = off.
 */
int mxfs_fix27_delay_ms;
module_param_named(fix27_delay_ms, mxfs_fix27_delay_ms, int, 0644);
MODULE_PARM_DESC(fix27_delay_ms,
	"DEBUG: widen the writeback folio-locked->ILOCK_SHARED window in xfs_map_blocks by N ms so a peer BAST is deterministically collided with the FIX-27 shared-class admit (0=off)");

/*
 * sess25 D-UNMOUNT-BUSY-INODES A/B gate.  mxfs_dlm_evict cancels the two BAST
 * arms, each of which was armed holding an igrab; a cancel that actually
 * cancels QUEUED work means the work function never ran, so that reference is
 * released by nobody.  0 = reproduce the leak (historical behaviour),
 * 1 = release the reference the cancelled arm was holding.  Ships OFF until
 * the paired measurement proves the mechanism, per RULE 4.
 */
/*
 * sess25 A/B gate for D-BAST-IRELE-INACTIVE-SELF-WEDGE and its suspected
 * downstream D-UNMOUNT-BUSY-INODES.  1 restores the pre-fix i_dlm_demoter
 * behaviour (an unconditional store that overwrites a live foreign claim and
 * an unconditional clear), so the wedge can be re-armed on ONE build and the
 * fix measured against its own negative control.  NEVER ship on.
 */
int mxfs_demoter_legacy_clobber;
module_param_named(demoter_legacy_clobber, mxfs_demoter_legacy_clobber, int, 0644);
MODULE_PARM_DESC(demoter_legacy_clobber,
	"A/B ONLY: restore the pre-sess25 unqualified i_dlm_demoter claim (reproduces D-BAST-IRELE-INACTIVE-SELF-WEDGE); 0=fixed (default), 1=broken");

/*
 * sess26 TEST-ONLY wedge injector.  Makes mxfs_dlm_bast_work_fn drop its own
 * demoter claim immediately before its trailing xfs_irele — the exact state a
 * stolen claim leaves it in.  The theft and the wedge have different rates (a
 * legacy-clobber arm measured 30 live-claim steals with wedge_precond=0,
 * because the wedge also needs that irele to be the LAST reference so it
 * cascades into inactivation), so this forces the missing condition and makes
 * D-BAST-IRELE-INACTIVE-SELF-WEDGE demonstrable on demand instead of only
 * observable by luck.  NEVER ship on.
 */
/*
 * sess26 A/B lever for D-SILENT-MKDIR-LOSS.  1 = current behaviour (a dir
 * dirtied under the current EX tenure skips its reload); 0 = always reload.
 * Nominated by a token-frequency differential: the node that lost 8 dirents
 * emitted P6-MIDTENURE-RELOAD-SKIP 661 times against a peer median of 37
 * (range 25-215) in the same scoped window.  See the guard in
 * mxfs_dlm_reload_inode.
 */
/*
 * sess26 FIX for D-SILENT-MKDIR-LOSS — bitmask of i_dlm_stale_src values that
 * the P6 mid-tenure reload skip must NOT swallow.  Bit N set => staleness from
 * source N forces a real reload.
 *
 * Default 0x1A4 = sources 2, 5, 7 and 8. Every one is peer-driven:
 *   src=2  MXFS_IF_DIR_RELOAD set, or dir_gen > dir_loaded_gen — "reader
 *          consuming a peer's DIR_MODIFY: get the peer's full image".
 *   src=5  set while RELEASING the lock — "in-memory fork data may be outdated
 *          when we re-acquire this lock ... will reload from disk on the next
 *          cache miss". A peer may have held EX for the whole interval.
 *   src=7  the else-branch of dir_slow_skip, whose skip condition is literally
 *          "no peer handoff, cached dir kept" — so src=7 means a peer handoff
 *          DID happen.
 *   src=8  MXFS_IF_DIR_RELOAD consumed on the EX-acquire fast path — "a
 *          different node held EX since our last grant".
 *
 * src=1 (readdir refresh) is deliberately EXCLUDED: it is the largest bucket
 * (208-376 per node per 3 runs) yet produced zero repeat streaks once 2/8 were
 * honoured, so it is not swallowing notifications and excluding it keeps the
 * pace cost at zero. Sources 5 and 7 were missed on the first pass because a
 * single run did not exercise them — they only showed up in a 3-run
 * accumulation. Widen this mask, do not disable the skip.
 *
 * Why this is the fix: at src=8 the flag is CLEARED before the reload is
 * attempted, so when P6 then skips, the notification is destroyed outright —
 * flag consumed, i_dlm_stale cleared, nothing re-read. The node never observes
 * the peer's entry and its own later publish omits it, which is exactly
 * silent mkdir loss. Measured: P6 skips are dominated by src 1/2/8 only, and
 * inodes are skip-cleared up to 19 times consecutively with no real reload
 * (i_dlm_p6skip_n), so the notification loss is repeated, not incidental.
 *
 * 0 restores the pre-fix behaviour for A/B. Do NOT "fix" this by setting
 * p6_midtenure_skip=0: measured, that costs dirent_durability 120s -> 240s
 * timeout (RULE 0). This mask reloads only on peer notifications, which is a
 * small fraction of the skips.
 */
unsigned int mxfs_p6_honor_src_mask = 0x1A4u;
module_param_named(p6_honor_src_mask, mxfs_p6_honor_src_mask, uint, 0644);
MODULE_PARM_DESC(p6_honor_src_mask,
	"bitmask of i_dlm_stale_src values the P6 mid-tenure skip must not swallow; default 0x1A4 (peer-driven srcs 2,5,7,8); 0=pre-fix");

int mxfs_p6_midtenure_skip = 1;
module_param_named(p6_midtenure_skip, mxfs_p6_midtenure_skip, int, 0644);
MODULE_PARM_DESC(p6_midtenure_skip,
	"skip the reload when a dir was dirtied under the current EX tenure; 1=on (default), 0=always reload (A/B for D-SILENT-MKDIR-LOSS)");

int mxfs_bast_irele_unclaim_inject;
module_param_named(bast_irele_unclaim_inject, mxfs_bast_irele_unclaim_inject, int, 0644);
MODULE_PARM_DESC(bast_irele_unclaim_inject,
	"TEST-ONLY: drop bast_work_fn's own demoter claim before its trailing irele, forcing the self-wedge; 0=off (default), 1=inject");

int mxfs_teardown_arm_gate = 1;
module_param_named(teardown_arm_gate, mxfs_teardown_arm_gate, int, 0644);
MODULE_PARM_DESC(teardown_arm_gate,
	"skip stranded-release dwork arms during unmount/shutdown/DLM-teardown (D-DWORK-TEARDOWN-LASTREF-LEAK fix); 1=on (default), 0=legacy arm (A/B)");

int mxfs_bast_qfalse_inject;
module_param_named(bast_qfalse_inject, mxfs_bast_qfalse_inject, int, 0644);
MODULE_PARM_DESC(bast_qfalse_inject,
	"TEST-ONLY: bast_work_fn self-requeues at entry (own donated ref) so queue_work collisions hit the false branch deterministically — exercises the P226 extra-ref drop (sess36 D-UNMOUNT-BUSY-INODES verification); 0=off (default), 1=inject");

int mxfs_rel_stale_inject;
module_param_named(rel_stale_inject, mxfs_rel_stale_inject, int, 0644);
MODULE_PARM_DESC(rel_stale_inject,
	"TEST-ONLY: force the stranded (-ESTALE) verdict on inode DLM releases while shutdown/unmounting is set — drives the P6G teardown-era dwork-arm decision deterministically (D-DWORK-TEARDOWN-LASTREF-LEAK A/B); 0=off (default), 1=inject");

/* sess38 A/B (32/caw dir_reuse, same build 0.11.319): knob-on = 6 rounds,
 * knob-off = 7 — CREATEINT moves refresh+evict+FUA-reread INSIDE the
 * serialized dir-EX critical section (~19ms/create cluster-wide vs ~15ms),
 * while the EDEADLK self-demote it avoids is already drain-free
 * (dir_pr_release_fast=1) and burst batching is provided by
 * dir_ex_tenure_floor + dir_ex_batch_grace_ms either way.  Net loss at
 * high contention -> default OFF.  Mechanism kept correct (sess38 leak
 * A/B/C fixes) for low-contention/future use. */
int mxfs_create_intent_ex = 0;
module_param_named(create_intent_ex, mxfs_create_intent_ex, int, 0644);
MODULE_PARM_DESC(create_intent_ex,
	"create-intent dir lookups take the cluster lock at EX from the lookup on; 0=off (default; measured net pace loss at 32-node contention), 1=on");

int mxfs_evict_retain_pr = 1;
module_param_named(evict_retain_pr, mxfs_evict_retain_pr, int, 0644);
MODULE_PARM_DESC(evict_retain_pr,
	"retain a clean PR DLM grant across inode eviction (demand-released via the no-inode BAST path) instead of CAS-clearing it at evict — kills the 32-way drop_caches unlock convoy on hot shared slots; 0=legacy eager unlock, 1=on (default)");

int mxfs_cancel_ref_release;
module_param_named(cancel_ref_release, mxfs_cancel_ref_release, int, 0644);
MODULE_PARM_DESC(cancel_ref_release,
	"release the igrab reference held by a BAST work/dwork arm that mxfs_dlm_evict cancels before it could run; 0=off (reproduces D-UNMOUNT-BUSY-INODES), 1=on");

/* FIX-28 verification injection — see xfs_map_blocks.  Debug-only, 0 = off. */
int mxfs_fix28_drain_stall_ms;
module_param_named(fix28_drain_stall_ms, mxfs_fix28_drain_stall_ms, int, 0644);
MODULE_PARM_DESC(fix28_drain_stall_ms,
	"DEBUG: stall the release drain once, mid-batch, inside its drain-site-2 page flush so a writeback submitter can park in the demote-wait holding a folio of that same batch — closes the ABBA cycle deterministically (0=off)");

/* FIX-27 A/B gate: 0 reproduces the pre-sess24 deadlock (shared-class writeback
 * submitters are NOT admitted through a BAST/DEMOTING demote-wait), 1 = fixed.
 * Exists so the fix can be verified against its own negative control on ONE
 * build, rather than across two builds with a re-prep in between. */
/*
 * DEFAULT 1 = ON as of v0.11.206 (ccloop c7ee71c6 sess25).
 *
 * sess24 shipped this OFF on the grounds that it was "measured never to
 * engage": a P47-FILEBLOCK census under a healthy 32-node workload recorded
 * 4380 demote-wait blocks, 99.7% of them SHARED requests, and turning the
 * admit on produced ZERO admits across 3613 of them.  That measurement was
 * correct and is not retracted -- but it was answering the wrong question.
 * Those blocks are ordinary syscalls (stat/cat/md5sum), which must keep
 * waiting; the admit is scoped to writeback-submission context precisely so it
 * does NOT touch them.  "Does not fire under a healthy workload" is what a
 * deadlock breaker for a rare cycle is SUPPOSED to look like.
 *
 * The reason it can now ship on is that the cycle is no longer rare-and-
 * unreproducible.  tests/abba_wedge_ab.sh builds it deterministically and
 * A/B's it on ONE build (see that file for why sess24's exerciser could not:
 * it collided with drain site 1, where the nest-admit fast path grants the
 * request outright, instead of site 2 where mode==NL is what parks it):
 *
 *   arm 0 (this=0): WEDGED.  Both legs captured from /proc/<pid>/stack,
 *     byte-identical to the test27 live capture --
 *       kworker mxfs-ino-bast  folio_wait_bit_common <- __folio_lock
 *         <- write_cache_pages <- ... <- mxfs_dlm_bast_process+0x5d8
 *       kworker flush-252:1    mxfs_dlm_ilock_begin <- xfs_ilock
 *         <- xfs_map_blocks <- iomap_writepage_map <- write_cache_pages
 *     plus `sync` and `dd` piled up in D state; sync never returned; 2x
 *     P73-WAITSTALL; 0 admits.
 *   RECOVERY of that wedged node by writing 1 here at runtime produced
 *     EXACTLY ONE probe line and the node came back:
 *       P25-IOEND-ADMIT ino=132 state=3 g2=5 req=3 src=writepages
 *     state=3 DEMOTING, g2=5 mirror still EX, req=3 SHARED -- i.e. precisely
 *     the case FIX-26's EX-only gate cannot cover and this one can.
 *   arm 1 (this=1): no wedge, sync completes, 0 P73-WAITSTALL, and 1
 *     P25-IOEND-ADMIT src=writepages on the same constructed collision
 *     (both arms recorded P28-DRAINSITE2 dirty=1 + P28-DRAINHOLD=1 + a
 *     P47-FILEBLOCK in_wb=1 on the same inode, so the hazard was genuinely
 *     built in both -- the fix-on arm did not merely fail to reach it).
 *
 * Safety of admitting a SHARED request is argued in mxfs_ilock_admit_ioend and
 * is backed by a structural guard: the admit sets i_dlm_mode=EX when the mirror
 * is EX, and the pre-unlock check in the release pipeline treats
 * i_dlm_mode != MXFS_LOCK_NL as `stranded` and SKIPS the wire unlock, so an
 * admitted submitter cannot have the grant released out from under it.  The
 * anchored release path is protected by its own gen-anchored unlock (-ESTALE).
 *
 * 0 remains available as the negative control the A/B harness needs.
 */
int mxfs_fix27_shared_admit = 1;
module_param_named(fix27_shared_admit, mxfs_fix27_shared_admit, int, 0644);
MODULE_PARM_DESC(fix27_shared_admit,
	"admit shared-class (PR/CR) writeback-submission ilock requests through a BAST/DEMOTING demote-wait; 0=off (reproduces the deadlock), 1=on (default)");

struct xfs_wptask {
	struct hlist_node	node;
	struct task_struct	*task;
};

static void
xfs_wptask_enter(struct xfs_wptask *e)
{
	e->task = current;
	spin_lock(&xfs_wptask_lock);
	hash_add(xfs_wptask_hash, &e->node, (unsigned long)current);
	spin_unlock(&xfs_wptask_lock);
}

static void
xfs_wptask_exit(struct xfs_wptask *e)
{
	spin_lock(&xfs_wptask_lock);
	hash_del(&e->node);
	spin_unlock(&xfs_wptask_lock);
}

bool
xfs_task_in_writepages(void)
{
	struct xfs_wptask	*e;
	bool			found = false;

	spin_lock(&xfs_wptask_lock);
	hash_for_each_possible(xfs_wptask_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock(&xfs_wptask_lock);
	return found;
}

void
xfs_end_bio(
	struct bio		*bio)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
	struct iomap_ioend	*ioend = bio->bi_private;
#else
	struct iomap_ioend	*ioend = iomap_ioend_from_bio(bio);
#endif
	struct xfs_inode	*ip = XFS_I(ioend->io_inode);
	unsigned long		flags;

	spin_lock_irqsave(&ip->i_ioend_lock, flags);
	if (list_empty(&ip->i_ioend_list))
		WARN_ON_ONCE(!queue_work(ip->i_mount->m_unwritten_workqueue,
					 &ip->i_ioend_work));
	list_add_tail(&ioend->io_list, &ip->i_ioend_list);
	spin_unlock_irqrestore(&ip->i_ioend_lock, flags);
}

/*
 * Fast revalidation of the cached writeback mapping. Return true if the current
 * mapping is valid, false otherwise.
 */
static bool
xfs_imap_valid(
	struct iomap_writepage_ctx	*wpc,
	struct xfs_inode		*ip,
	loff_t				offset)
{
	if (offset < wpc->iomap.offset ||
	    offset >= wpc->iomap.offset + wpc->iomap.length)
		return false;
	/*
	 * If this is a COW mapping, it is sufficient to check that the mapping
	 * covers the offset. Be careful to check this first because the caller
	 * can revalidate a COW mapping without updating the data seqno.
	 */
	if (wpc->iomap.flags & IOMAP_F_SHARED)
		return true;

	/*
	 * This is not a COW mapping. Check the sequence number of the data fork
	 * because concurrent changes could have invalidated the extent. Check
	 * the COW fork because concurrent changes since the last time we
	 * checked (and found nothing at this offset) could have added
	 * overlapping blocks.
	 */
	if (XFS_WPC(wpc)->data_seq != READ_ONCE(ip->i_df.if_seq)) {
		trace_xfs_wb_data_iomap_invalid(ip, &wpc->iomap,
				XFS_WPC(wpc)->data_seq, XFS_DATA_FORK);
		return false;
	}
	if (xfs_inode_has_cow_data(ip) &&
	    XFS_WPC(wpc)->cow_seq != READ_ONCE(ip->i_cowfp->if_seq)) {
		trace_xfs_wb_cow_iomap_invalid(ip, &wpc->iomap,
				XFS_WPC(wpc)->cow_seq, XFS_COW_FORK);
		return false;
	}
	return true;
}

/*
 * Pass in a dellalloc extent and convert it to real extents, return the real
 * extent that maps offset_fsb in wpc->iomap.
 *
 * The current page is held locked so nothing could have removed the block
 * backing offset_fsb, although it could have moved from the COW to the data
 * fork by another thread.
 */
static int
xfs_convert_blocks(
	struct iomap_writepage_ctx *wpc,
	struct xfs_inode	*ip,
	int			whichfork,
	loff_t			offset)
{
	int			error;
	unsigned		*seq;

	/* FIX-26 verification injection (ccloop c7ee71c6 sess6): hold the
	 * conversion — folio locked, xfs_ilock(EX) imminent — for up to N ms
	 * OR until a peer BAST lands on this inode, whichever first.  This
	 * turns every armed conversion into a near-certain BAST collision so
	 * the demote-wait admit (P25 src=writepages) is provably exercised.
	 * (v1 slept at xfs_map_blocks entry: every folio slept but only the
	 * first folio of a walk converts, so ~all sleep time bought no admit
	 * window — 0 collisions in 45s.)  Demoter-exempt; default 0 = off;
	 * unlocked racy read of i_dlm_state is fine for debug pacing. */
	if (unlikely(mxfs_fix26_delay_ms > 0) && (ip->i_dlm_demoter != current && ip->i_dlm_demoter2 != current)) {
		int fix26_left = mxfs_fix26_delay_ms;
		uint8_t fix26_st0 = ip->i_dlm_state;
		uint8_t fix26_md0 = ip->i_dlm_mode;
		static atomic_t p26dbg = ATOMIC_INIT(0);

		while (fix26_left-- > 0 &&
		       ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED)
			msleep(1);
		if (atomic_inc_return(&p26dbg) <= 40)
			pr_warn("mxfs: P26DBG-INJ ino=%llu st0=%u md0=%u st1=%u md1=%u waited_ms=%d wp=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				fix26_st0, fix26_md0,
				ip->i_dlm_state, ip->i_dlm_mode,
				mxfs_fix26_delay_ms - fix26_left - 1,
				xfs_task_in_writepages() ? 1 : 0,
				current->comm);
	}

	/* P26PRE-DELALLOC-SUBEX (ccloop c7ee71c6 sess6) — PRECURSOR PROBE for
	 * the test8 live wedge.  Writeback found delalloc to convert while
	 * i_dlm_mode < EX.  Under the drain invariant (bast_process flushes +
	 * invalidates ALL dirty data BEFORE any downconvert) this state should
	 * be impossible: every dirty delalloc page was created under a
	 * fast-path EX hold and must be flushed by the tenure's release.  The
	 * live wedge proves it happens (flusher converting ino=10485894 under
	 * mode=PR, 30s dirty-expiry after its last EX write).  Print the full
	 * lock state at the moment of the violation so the leak path — drain
	 * skip, invalidate -EBUSY leftovers, admitted-write TOCTOU, recycle
	 * carrying stale dlm state — is identified from a live run instead of
	 * post-hoc log archaeology.  FIX-26's admit keeps the run alive
	 * through the collision, so this probe can actually be harvested. */
	if (unlikely(ip->i_dlm_mode < MXFS_LOCK_EX) &&
	    ip->i_mount->m_mxfs_dlm) {
		static atomic_t p26pre = ATOMIC_INIT(0);

		/* dem_cur=1 = the printing task IS the drain (normal: the
		 * drain flushing its own tenure's data after the mode
		 * pre-clear — 22/22 of the first harvest).  dem_cur=0 = a
		 * FOREIGN task (flusher/sync) converting under a sub-EX mode
		 * — the FIX-26 wedge population; each such event should be
		 * followed by a P25 src=writepages admit, never a P73. */
		if (atomic_inc_return(&p26pre) <= 200)
			pr_warn("mxfs: P26PRE-DELALLOC-SUBEX ino=%llu mode=%u state=%u relflush=%d stale=%d demoter=%d dem_cur=%d exh=%u prh=%u pin=%u wp=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode, ip->i_dlm_state,
				xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
				ip->i_dlm_stale ? 1 : 0,
				ip->i_dlm_demoter ? 1 : 0,
				(ip->i_dlm_demoter == current || ip->i_dlm_demoter2 == current) ? 1 : 0,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count,
				xfs_task_in_writepages() ? 1 : 0,
				current->comm);
	}

	if (whichfork == XFS_COW_FORK)
		seq = &XFS_WPC(wpc)->cow_seq;
	else
		seq = &XFS_WPC(wpc)->data_seq;

	/*
	 * Attempt to allocate whatever delalloc extent currently backs offset
	 * and put the result into wpc->iomap.  Allocate in a loop because it
	 * may take several attempts to allocate real blocks for a contiguous
	 * delalloc extent if free space is sufficiently fragmented.
	 */
	do {
		error = xfs_bmapi_convert_delalloc(ip, whichfork, offset,
				&wpc->iomap, seq);
		if (error)
			return error;
	} while (wpc->iomap.offset + wpc->iomap.length <= offset);

	return 0;
}

static int
xfs_map_blocks(
	struct iomap_writepage_ctx *wpc,
	struct inode		*inode,
	loff_t			offset)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	ssize_t			count = i_blocksize(inode);
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = XFS_B_TO_FSB(mp, offset + count);
	xfs_fileoff_t		cow_fsb;
	int			whichfork;
	struct xfs_bmbt_irec	imap;
	struct xfs_iext_cursor	icur;
	int			retries = 0;
	int			error = 0;

	if (xfs_is_shutdown(mp))
		return -EIO;

	XFS_ERRORTAG_DELAY(mp, XFS_ERRTAG_WB_DELAY_MS);

	/*
	 * FIX-28 verification injection (ccloop c7ee71c6 sess25) — the DRAIN
	 * half of D-BAST-WRITEBACK-ABBA-DEADLOCK.
	 *
	 * sess24's exerciser drove 200/200 submitter-side collisions and still
	 * produced ZERO demote-wait entries.  The reason is now proven from the
	 * code rather than guessed: mxfs_dlm_bast_process flushes TWICE, and the
	 * submitter-side injection broke out of its window as soon as the state
	 * became BAST/DEMOTING — which is drain site 1, where i_dlm_mode is
	 * STILL the granted mode, so mxfs_dlm_ilock_begin's nest-admit fast path
	 * grants the shared request outright and nothing ever parks.  Only site
	 * 2 (after `ip->i_dlm_mode = MXFS_LOCK_NL`, before the on-disk unlock)
	 * can park a submitter, and that is where the live capture was.
	 *
	 * Closing the cycle deterministically needs BOTH halves synchronised,
	 * which is what sess24's handoff named as the missing piece.  This is
	 * the drain half: stall the drain ONCE, mid-batch, after it has fetched
	 * a dirty-tagged folio batch and locked its first folio.  A submitter
	 * arriving during the stall locks a LATER folio of that same batch,
	 * parks in the demote-wait holding it, and when the stall ends the drain
	 * walks into folio_lock() on exactly that folio.  writeback_get_folio()
	 * locks unconditionally and works off the already-fetched batch, so the
	 * submitter having cleared the dirty bit does not save us.
	 *
	 * Demoter-ONLY (the mirror image of fix26/fix27_delay_ms, which are
	 * demoter-exempt) and site-2-only.  Debug-only, 0 = off.
	 */
	if (unlikely(mxfs_fix28_drain_stall_ms > 0) &&
	    (ip->i_dlm_demoter == current || ip->i_dlm_demoter2 == current) &&
	    ip->i_dlm_drain_site == 2 &&
	    !ip->i_dlm_drain_stalled) {
		ip->i_dlm_drain_stalled = 1;
		pr_warn("mxfs: P28-DRAINHOLD ino=%llu off=%lld stall_ms=%d — drain holding a folio mid-batch at site 2 so a writeback submitter can park on a later folio of the same batch\n",
			(unsigned long long)ip->i_ino, (long long)offset,
			mxfs_fix28_drain_stall_ms);
		msleep(mxfs_fix28_drain_stall_ms);
	}

	/*
	 * COW fork blocks can overlap data fork blocks even if the blocks
	 * aren't shared.  COW I/O always takes precedent, so we must always
	 * check for overlap on reflink inodes unless the mapping is already a
	 * COW one, or the COW fork hasn't changed from the last time we looked
	 * at it.
	 *
	 * It's safe to check the COW fork if_seq here without the ILOCK because
	 * we've indirectly protected against concurrent updates: writeback has
	 * the page locked, which prevents concurrent invalidations by reflink
	 * and directio and prevents concurrent buffered writes to the same
	 * page.  Changes to if_seq always happen under i_lock, which protects
	 * against concurrent updates and provides a memory barrier on the way
	 * out that ensures that we always see the current value.
	 */
	if (xfs_imap_valid(wpc, ip, offset))
		return 0;

	/*
	 * If we don't have a valid map, now it's time to get a new one for this
	 * offset.  This will convert delayed allocations (including COW ones)
	 * into real extents.  If we return without a valid map, it means we
	 * landed in a hole and we skip the block.
	 */
retry:
	cow_fsb = NULLFILEOFF;
	whichfork = XFS_DATA_FORK;
	/* FIX-27 verification injection: hold here — folio locked,
	 * ILOCK_SHARED imminent — until a peer BAST lands on this inode or N ms
	 * elapse, so the demote-wait shared-class admit (P25 src=writepages
	 * req=3) is provably exercised.  Demoter-exempt; unlocked racy read of
	 * i_dlm_state is fine for debug pacing. */
	if (unlikely(mxfs_fix27_delay_ms > 0) && (ip->i_dlm_demoter != current && ip->i_dlm_demoter2 != current)) {
		int f27_left = mxfs_fix27_delay_ms;
		uint8_t f27_st0 = ip->i_dlm_state;

		/* Break ONLY into a window that actually parks the submitter.
		 *
		 * v1 broke on ANY state change, which includes BAST->CACHED --
		 * i.e. it released the window exactly when the drain had already
		 * finished, so 68 armed windows produced 6 "collisions" and ZERO
		 * demote-wait entries (P47/P73 both 0 in both A/B arms).
		 *
		 * v2 broke on state==BAST||DEMOTING, and STILL produced 0 P47
		 * over 200/200 "collisions".  Root (sess25, read off the code):
		 * the state goes BAST/DEMOTING at the TOP of the drain, i.e. at
		 * drain site 1, where `ip->i_dlm_mode` is still the granted mode.
		 * mxfs_dlm_ilock_begin then satisfies a shared request from the
		 * nest-admit fast path (i_dlm_mode >= request) and the submitter
		 * sails through without ever reaching the demote-wait.  The state
		 * alone is NOT the parking precondition -- mode==NL is.
		 *
		 * v3 therefore waits for the real precondition: mid-drain AND
		 * i_dlm_mode already dropped to NL, which is exactly drain site 2
		 * (the S_ISREG durability flush) and exactly where test27's live
		 * deadlock was captured. */
		while (f27_left > 0) {
			if ((ip->i_dlm_state == MXFS_DLM_ISTATE_BAST ||
			     ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING) &&
			    ip->i_dlm_mode == 0 /* MXFS_LOCK_NL */)
				break;		/* mid-drain, post-mode-clear */
			msleep(1);
			f27_left--;
		}
		{
			static atomic_t p27dbg = ATOMIC_INIT(0);

			if (atomic_inc_return(&p27dbg) <= 200)
				pr_warn("mxfs: P27-INJECT ino=%llu st0=%u st1=%u mode=%u dsite=%u waited_ms=%d collided=%d\n",
					(unsigned long long)ip->i_ino, f27_st0,
					ip->i_dlm_state, ip->i_dlm_mode,
					ip->i_dlm_drain_site,
					mxfs_fix27_delay_ms - f27_left,
					((ip->i_dlm_state == MXFS_DLM_ISTATE_BAST ||
					  ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING) &&
					 ip->i_dlm_mode == 0));
		}
	}
	xfs_ilock(ip, XFS_ILOCK_SHARED);
	ASSERT(!xfs_need_iread_extents(&ip->i_df));

	/*
	 * Check if this is offset is covered by a COW extents, and if yes use
	 * it directly instead of looking up anything in the data fork.
	 */
	if (xfs_inode_has_cow_data(ip) &&
	    xfs_iext_lookup_extent(ip, ip->i_cowfp, offset_fsb, &icur, &imap))
		cow_fsb = imap.br_startoff;
	if (cow_fsb != NULLFILEOFF && cow_fsb <= offset_fsb) {
		XFS_WPC(wpc)->cow_seq = READ_ONCE(ip->i_cowfp->if_seq);
		xfs_iunlock(ip, XFS_ILOCK_SHARED);

		whichfork = XFS_COW_FORK;
		goto allocate_blocks;
	}

	/*
	 * No COW extent overlap. Revalidate now that we may have updated
	 * ->cow_seq. If the data mapping is still valid, we're done.
	 */
	if (xfs_imap_valid(wpc, ip, offset)) {
		xfs_iunlock(ip, XFS_ILOCK_SHARED);
		return 0;
	}

	/*
	 * If we don't have a valid map, now it's time to get a new one for this
	 * offset.  This will convert delayed allocations (including COW ones)
	 * into real extents.
	 */
	if (!xfs_iext_lookup_extent(ip, &ip->i_df, offset_fsb, &icur, &imap))
		imap.br_startoff = end_fsb;	/* fake a hole past EOF */
	XFS_WPC(wpc)->data_seq = READ_ONCE(ip->i_df.if_seq);
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	/* landed in a hole or beyond EOF? */
	if (imap.br_startoff > offset_fsb) {
		imap.br_blockcount = imap.br_startoff - offset_fsb;
		imap.br_startoff = offset_fsb;
		imap.br_startblock = HOLESTARTBLOCK;
		imap.br_state = XFS_EXT_NORM;
	}

	/*
	 * Truncate to the next COW extent if there is one.  This is the only
	 * opportunity to do this because we can skip COW fork lookups for the
	 * subsequent blocks in the mapping; however, the requirement to treat
	 * the COW range separately remains.
	 */
	if (cow_fsb != NULLFILEOFF &&
	    cow_fsb < imap.br_startoff + imap.br_blockcount)
		imap.br_blockcount = cow_fsb - imap.br_startoff;

	/* got a delalloc extent? */
	if (imap.br_startblock != HOLESTARTBLOCK &&
	    isnullstartblock(imap.br_startblock))
		goto allocate_blocks;

	xfs_bmbt_to_iomap(ip, &wpc->iomap, &imap, 0, 0, XFS_WPC(wpc)->data_seq);
	trace_xfs_map_blocks_found(ip, offset, count, whichfork, &imap);
	return 0;
allocate_blocks:
	error = xfs_convert_blocks(wpc, ip, whichfork, offset);
	if (error) {
		/*
		 * If we failed to find the extent in the COW fork we might have
		 * raced with a COW to data fork conversion or truncate.
		 * Restart the lookup to catch the extent in the data fork for
		 * the former case, but prevent additional retries to avoid
		 * looping forever for the latter case.
		 */
		if (error == -EAGAIN && whichfork == XFS_COW_FORK && !retries++)
			goto retry;
		ASSERT(error != -EAGAIN);
		return error;
	}

	/*
	 * Due to merging the return real extent might be larger than the
	 * original delalloc one.  Trim the return extent to the next COW
	 * boundary again to force a re-lookup.
	 */
	if (whichfork != XFS_COW_FORK && cow_fsb != NULLFILEOFF) {
		loff_t		cow_offset = XFS_FSB_TO_B(mp, cow_fsb);

		if (cow_offset < wpc->iomap.offset + wpc->iomap.length)
			wpc->iomap.length = cow_offset - wpc->iomap.offset;
	}

	ASSERT(wpc->iomap.offset <= offset);
	ASSERT(wpc->iomap.offset + wpc->iomap.length > offset);
	trace_xfs_map_blocks_alloc(ip, offset, count, whichfork, &imap);
	return 0;
}

static void xfs_discard_folio(struct folio *folio, loff_t pos);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
static int
xfs_prepare_ioend(
	struct iomap_ioend	*ioend,
	int			status)
{
	unsigned int		nofs_flag;

	/*
	 * We can allocate memory here while doing writeback on behalf of
	 * memory reclaim.  To avoid memory allocation deadlocks set the
	 * task-wide nofs context for the following operations.
	 */
	nofs_flag = memalloc_nofs_save();

	/* Convert CoW extents to regular */
	if (!status && mxfs_ioend_shared(ioend)) {
		status = xfs_reflink_convert_cow(XFS_I(ioend->io_inode),
				ioend->io_offset, ioend->io_size);
	}

	memalloc_nofs_restore(nofs_flag);

	/* send ioends that might require a transaction to the completion wq */
	if (xfs_ioend_is_append(ioend) || mxfs_ioend_unwritten(ioend) ||
	    mxfs_ioend_shared(ioend))
		mxfs_ioend_set_bi_end_io(ioend, xfs_end_bio);
	return status;
}
#else
/*
 * v6.17+: -> map_blocks moved inside -> writeback_range (this is where
 * xfs_map_blocks's existing per-offset delalloc-to-real-extent logic now
 * gets called from); -> discard_folio is no longer a generic hook, XFS
 * calls xfs_discard_folio() itself on failure; -> prepare_ioend's job
 * (CoW conversion + deciding whether the ioend needs the deferred
 * completion workqueue) moves into -> writeback_submit, driven off
 * wpc->wb_ctx instead of a passed-in ioend.
 */
static ssize_t
xfs_writeback_range(
	struct iomap_writepage_ctx	*wpc,
	struct folio			*folio,
	u64				pos,
	unsigned int			len,
	u64				end_pos)
{
	ssize_t				ret;

	ret = xfs_map_blocks(wpc, folio->mapping->host, pos);
	if (!ret)
		ret = iomap_add_to_ioend(wpc, folio, pos, end_pos, len);
	if (ret < 0)
		xfs_discard_folio(folio, pos);
	return ret;
}

static int
xfs_writeback_submit(
	struct iomap_writepage_ctx	*wpc,
	int				error)
{
	struct iomap_ioend		*ioend = wpc->wb_ctx;
	unsigned int			nofs_flag;

	if (!ioend)
		return iomap_ioend_writeback_submit(wpc, error);

	nofs_flag = memalloc_nofs_save();

	/* Convert CoW extents to regular */
	if (!error && mxfs_ioend_shared(ioend)) {
		error = xfs_reflink_convert_cow(XFS_I(ioend->io_inode),
				ioend->io_offset, ioend->io_size);
	}

	memalloc_nofs_restore(nofs_flag);

	/* send ioends that might require a transaction to the completion wq */
	if (xfs_ioend_is_append(ioend) || mxfs_ioend_unwritten(ioend) ||
	    mxfs_ioend_shared(ioend))
		mxfs_ioend_set_bi_end_io(ioend, xfs_end_bio);

	return iomap_ioend_writeback_submit(wpc, error);
}
#endif

/*
 * If the folio has delalloc blocks on it, the caller is asking us to punch them
 * out. If we don't, we can leave a stale delalloc mapping covered by a clean
 * page that needs to be dirtied again before the delalloc mapping can be
 * converted. This stale delalloc mapping can trip up a later direct I/O read
 * operation on the same region.
 *
 * We prevent this by truncating away the delalloc regions on the folio. Because
 * they are delalloc, we can do this without needing a transaction. Indeed - if
 * we get ENOSPC errors, we have to be able to do this truncation without a
 * transaction as there is no space left for block reservation (typically why
 * we see a ENOSPC in writeback).
 */
static void
xfs_discard_folio(
	struct folio		*folio,
	loff_t			pos)
{
	struct xfs_inode	*ip = XFS_I(folio->mapping->host);
	struct xfs_mount	*mp = ip->i_mount;
	int			error;

	if (xfs_is_shutdown(mp))
		return;

	xfs_alert_ratelimited(mp,
		"page discard on page "PTR_FMT", inode 0x%llx, pos %llu.",
			folio, ip->i_ino, pos);

	/*
	 * The end of the punch range is always the offset of the first
	 * byte of the next folio. Hence the end offset is only dependent on the
	 * folio itself and not the start offset that is passed in.
	 */
	mxfs_bmap_punch_delalloc_range(ip, pos,
				folio_pos(folio) + folio_size(folio));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
static const struct iomap_writeback_ops xfs_writeback_ops = {
	.map_blocks		= xfs_map_blocks,
	.prepare_ioend		= xfs_prepare_ioend,
	.discard_folio		= xfs_discard_folio,
};
#else
static const struct iomap_writeback_ops xfs_writeback_ops = {
	.writeback_range	= xfs_writeback_range,
	.writeback_submit	= xfs_writeback_submit,
};
#endif

STATIC int
xfs_vm_writepages(
	struct address_space	*mapping,
	struct writeback_control *wbc)
{
	struct xfs_writepage_ctx wpc = { };
	struct xfs_wptask	wpt;
	int			ret;

	/*
	 * Writing back data in a transaction context can result in recursive
	 * transactions. This is bad, so issue a warning and get out of here.
	 */
	if (WARN_ON_ONCE(current->journal_info))
		return 0;

	xfs_iflags_clear(XFS_I(mapping->host), XFS_ITRUNCATED);
	/* FIX-26: mark this task as writeback submission for the duration —
	 * mxfs_dlm_ilock_begin admits it through a BAST/DEMOTING demote-wait
	 * (it holds folio locks the drain needs; see xfs_task_in_writepages). */
	xfs_wptask_enter(&wpt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
	ret = iomap_writepages(mapping, wbc, &wpc.ctx, &xfs_writeback_ops);
#else
	wpc.ctx.inode = mapping->host;
	wpc.ctx.wbc = wbc;
	wpc.ctx.ops = &xfs_writeback_ops;
	ret = iomap_writepages(&wpc.ctx);
#endif
	xfs_wptask_exit(&wpt);
	return ret;
}

STATIC int
xfs_dax_writepages(
	struct address_space	*mapping,
	struct writeback_control *wbc)
{
	struct xfs_inode	*ip = XFS_I(mapping->host);

	xfs_iflags_clear(ip, XFS_ITRUNCATED);
	return dax_writeback_mapping_range(mapping,
			xfs_inode_buftarg(ip)->bt_daxdev, wbc);
}

STATIC sector_t
xfs_vm_bmap(
	struct address_space	*mapping,
	sector_t		block)
{
	struct xfs_inode	*ip = XFS_I(mapping->host);

	trace_xfs_vm_bmap(ip);

	/*
	 * The swap code (ab-)uses ->bmap to get a block mapping and then
	 * bypasses the file system for actual I/O.  We really can't allow
	 * that on reflinks inodes, so we have to skip out here.  And yes,
	 * 0 is the magic code for a bmap error.
	 *
	 * Since we don't pass back blockdev info, we can't return bmap
	 * information for rt files either.
	 */
	if (xfs_is_cow_inode(ip) || XFS_IS_REALTIME_INODE(ip))
		return 0;
	return iomap_bmap(mapping, block, &xfs_read_iomap_ops);
}

STATIC int
xfs_vm_read_folio(
	struct file		*unused,
	struct folio		*folio)
{
	return iomap_read_folio(folio, &xfs_read_iomap_ops);
}

STATIC void
xfs_vm_readahead(
	struct readahead_control	*rac)
{
	iomap_readahead(rac, &xfs_read_iomap_ops);
}

static int
xfs_iomap_swapfile_activate(
	struct swap_info_struct		*sis,
	struct file			*swap_file,
	sector_t			*span)
{
	sis->bdev = xfs_inode_buftarg(XFS_I(file_inode(swap_file)))->bt_bdev;
	return iomap_swapfile_activate(sis, swap_file, span,
			&xfs_read_iomap_ops);
}

const struct address_space_operations xfs_address_space_operations = {
	.read_folio		= xfs_vm_read_folio,
	.readahead		= xfs_vm_readahead,
	.writepages		= xfs_vm_writepages,
	.dirty_folio		= iomap_dirty_folio,
	.release_folio		= iomap_release_folio,
	.invalidate_folio	= iomap_invalidate_folio,
	.bmap			= xfs_vm_bmap,
	.migrate_folio		= filemap_migrate_folio,
	.is_partially_uptodate  = iomap_is_partially_uptodate,
	.error_remove_folio	= generic_error_remove_folio,
	.swap_activate		= xfs_iomap_swapfile_activate,
};

const struct address_space_operations xfs_dax_aops = {
	.writepages		= xfs_dax_writepages,
	.dirty_folio		= noop_dirty_folio,
	.swap_activate		= xfs_iomap_swapfile_activate,
};
