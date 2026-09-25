// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- AG unlock, transaction AG handoff and AG BAST work
 */
#define MXFS_TU_ID 30	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
int mxfs_ag_prepass_push_iters = 20;
module_param_named(ag_prepass_push_iters, mxfs_ag_prepass_push_iters, int, 0644);
MODULE_PARM_DESC(ag_prepass_push_iters,
	"no-progress bound (10 ms iterations) of the worker's pre-COMMIT AIL push; non-fatal, the post-COMMIT drains carry Invariant 1 (0 = skip the push)");

/*
 * v0.3.130/0.3.131/0.3.132 v6a phase 2 module params.
 * Declared here so they're visible in mxfs_ag_dlm_lock (which uses
 * mxfs_ag_yield_quantum) below as well as mxfs_ag_dlm_unlock further
 * down (which uses both).  See full MODULE_PARM_DESC near
 * mxfs_ag_dlm_unlock for documentation.
 */
/* v0.5.4: default flipped 0 -> 1.  Instrumented
 * ftrace proof on the scaling_curve 2-node parallel rsync: eager mode
 * ran ~190 sync drains + ~400 xfs_log_force(SYNC) per node (~0.7-0.9 s
 * of a ~5 s wall) with ZERO peer contention (0 ACQ-FRESH — the AG
 * grants never moved).  The lazy path bounds dirty debt via the
 * adaptive yield quantum + per-unlock async delwri submit, and a
 * pending peer BAST still forces the immediate sync drain (Invariant
 * #1 is enforced by the BAST work fn on every release). */
static int mxfs_lazy_ag_drain = 1;
int mxfs_ag_yield_adaptive = 1;	/* v0.3.147 */
int mxfs_p87_refuse_unlock;	/* default OFF until the repair rate is measured */

module_param_named(lazy_ag_drain, mxfs_lazy_ag_drain, int, 0644);
MODULE_PARM_DESC(lazy_ag_drain,
                 "Defer AG-DLM alloc-buflist drain from per-trans unlock "
                 "to bast_work_fn release boundary: 0=eager (default, "
                 "original v0.3.128 behavior), 1=lazy (v0.3.130 v6a "
                 "phase 2 experiment — amortizes FUA writes across "
                 "transactions held under cached AG-DLM).");

/*
 * v0.3.147 adaptive yield quantum (prescription E of the
 * 0.3.x yield-fairness study).  Per-AG effective quantum starts at
 * mxfs_ag_yield_quantum, halves on every peer BAST (fairness signal),
 * doubles after MXFS_AG_YIELD_DOUBLE_THRESH consecutive non-contended
 * eager drains.  SOLO converges to mxfs_ag_yield_quantum (fast); contended
 * multi-node converges to a small quantum (fair).  Bridges the
 * observed SOLO-vs-multi-node tradeoff (q=1 best SOLO, starves T2;
 * q=32 best for SOLO speed too but starves T1 under multi-node) without
 * requiring a workload-aware static knob.
 */
module_param_named(ag_yield_adaptive, mxfs_ag_yield_adaptive, int, 0644);
MODULE_PARM_DESC(ag_yield_adaptive,
                 "Enable adaptive AG-DLM yield quantum.  Default 1.  "
                 "Set 0 to use static ag_yield_quantum without "
                 "halve-on-BAST / double-on-quiet adaptation.");

/*
 *  — TEST-ONLY fault injection for the stranded-AG
 * repair above.  Set to (agno + 1) to make the NEXT release of that AG skip
 * its wire unlock exactly once, leaving our holder bit on the platter with no
 * in-core tenure: the precise state mxfs_ag_strand_repair exists to recover
 * from, and which has not occurred naturally since the fix landed.  Clears
 * itself as it fires.  0 = off (default); never arm outside a validation run.
 */
int mxfs_ag_strand_inject;
EXPORT_SYMBOL(mxfs_ag_strand_inject);
module_param_named(ag_strand_inject, mxfs_ag_strand_inject, int, 0644);
MODULE_PARM_DESC(ag_strand_inject,
	"TEST ONLY: strand an AG once by skipping its wire unlock, to exercise ag_strand_repair; -1=next AG released, N=AG N-1, 0=off");

/*
 * One-shot test hook: returns true if THIS release should be turned into a
 * strand (skip the wire unlock).  Clears the arm as it fires so exactly one AG
 * is stranded once.  Called from every real AG release path — the first two
 * attempts armed only mxfs_dlm_ag_release_work_fn and then
 * mxfs_dlm_ag_bast_work_fn, and BOTH produced 0 strands across a 400-mkdir
 * single-node workload AND a full 32-node mkdir storm, because neither path
 * ran.  Cover them all rather than guess again.
 */
bool
mxfs_ag_strand_inject_hit(xfs_agnumber_t agno, const char *src)
{
	if (likely(!mxfs_ag_strand_inject))
		return false;
	if (mxfs_ag_strand_inject != -1 &&
	    mxfs_ag_strand_inject != (int)agno + 1)
		return false;
	mxfs_ag_strand_inject = 0;
	pr_warn("mxfs: P200-STRAND-INJECT ag=%u src=%s — SKIPPING the wire unlock to strand this AG on purpose; expect P5N-AG-ORPHAN-NAK disk_held=1 repair=1 on the next peer BAST\n",
		agno, src);
	return true;
}

/*
 *  — when xfs_lookup's type-flip resolver (P95B) gives up
 * after its full 200 rounds, FAIL the lookup with -ESTALE instead of handing
 * the VFS an inode whose type contradicts the dirent.  Publishing the mismatch
 * is what makes D-DIRENT-INODE-TYPE-MISMATCH durable and cluster-wide (proven:
 * node5.txt became a directory on all 32 nodes).  0 restores the earlier
 * fall-through for A/B.
 */
/*
 *  — TEST ONLY.  Make xfs_lookup's type-flip resolver
 * (P95B) give up immediately instead of retrying, so the unresolved branch and
 * its -ESTALE handling can be exercised on demand.  Type flips occur often
 * (165 waits in one 32-node run) but the UNRESOLVED outcome is rare, and a fix
 * whose path has never run is not a verified fix.  0 = off (default); never arm
 * outside a validation run.
 */
int mxfs_typeflip_force_unresolved;
EXPORT_SYMBOL(mxfs_typeflip_force_unresolved);
module_param_named(typeflip_force_unresolved, mxfs_typeflip_force_unresolved, int, 0644);
MODULE_PARM_DESC(typeflip_force_unresolved,
	"TEST ONLY: make the type-flip resolver give up immediately, to exercise the unresolved/-ESTALE path; 0=off");

int mxfs_typeflip_fail_unresolved = 1;
EXPORT_SYMBOL(mxfs_typeflip_fail_unresolved);
module_param_named(typeflip_fail_unresolved, mxfs_typeflip_fail_unresolved, int, 0644);
MODULE_PARM_DESC(typeflip_fail_unresolved,
	"fail a lookup with -ESTALE when a dirent/inode type flip cannot be resolved, instead of publishing the mismatch; 1=on (default)");

/*
 *  (D-DIRENT-INODE-TYPE-MISMATCH).  The dirent ftype
 * written by rename/link is snapshotted from the in-core i_mode BEFORE the
 * ILOCK is taken (xfs_vn_rename / xfs_vn_link), and in MXFS the acquire can
 * reload the inode and change its type.  1 = rewrite the ftype from the
 * post-lock, post-reload mode at the last correctable point;
 * 0 = probe only (P206-*-FTYPE-STALE), for the same-build A/B.
 */
int mxfs_rename_ftype_revalidate;
EXPORT_SYMBOL(mxfs_rename_ftype_revalidate);
module_param_named(rename_ftype_revalidate, mxfs_rename_ftype_revalidate, int, 0644);
MODULE_PARM_DESC(rename_ftype_revalidate,
	"Rewrite a rename/link dirent's ftype from the inode's post-ILOCK, "
	"post-reload mode instead of the pre-lock snapshot taken by "
	"xfs_vn_rename/xfs_vn_link.  0=probe only (P206), 1=correct it.");

int mxfs_ag_strand_repair = 1;
EXPORT_SYMBOL(mxfs_ag_strand_repair);
module_param_named(ag_strand_repair, mxfs_ag_strand_repair, int, 0644);
MODULE_PARM_DESC(ag_strand_repair,
                 "Re-adopt and release an AG whose CAW holder bit is set "
                 "on disk while this node has no in-core tenure "
                 "(holders=0, !cached, !demoting, !release_pending) — the "
                 "state in which no peer BAST can ever schedule a release. "
                 "1=repair (default), 0=detect and report only.");

/*
 * Release per-AG DLM lock.  In the cached-AG model this is a holder-count
 * decrement only — the DLM grant is kept on disk past last-holder release.
 * If a peer-side BAST has fired in the meantime, schedule the BAST work
 * which drains pending writes and calls mxfs_v5_dlm_ag_unlock for real.
 */
void
mxfs_ag_dlm_unlock(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	bool			drain_alloc = false;
	bool			schedule_bast = false;
	bool			lazy_skip = false;
	bool			do_latch = false;	/* */

	if (!dlm)
		return;

	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	WARN_ON(pag->pag_dlm_holders <= 0);
	pag->pag_dlm_holders--;
	if (pag->pag_dlm_holders == 0) {
		/*
		 * Cached-AG: keep the DLM grant on disk.  pag_dlm_cached
		 * is a hint to fast-path acquire; it stays true until either
		 * the BAST work fn clears it (committed to release) or
		 * a fresh-acquire fast-path clears it (re-adopted by another
		 * holder on this node).
		 */
		/* invariant: holders cannot reach 0 while a demote
		 * is in flight (the COMMIT requires holders==0 and admission
		 * is closed until completion) — a cached hint installed here
		 * under demoting would be the post-latch adoption hazard. */
		if (unlikely(pag->pag_dlm_demoting))
			WARN_ONCE(1, "mxfs: P12-UNLOCK-WHILE-DEMOTING ag=%u comm=%s latched=%d\n",
				  pag_agno(pag), current->comm,
				  pag->pag_dlm_latched ? 1 : 0);
		else
			pag->pag_dlm_cached = true;
		drain_alloc = pag->pag_mxfs_alloc_dirty;

		if (pag->pag_dlm_bast_pending && !pag->pag_dlm_demoting &&
		    !pag->pag_dlm_release_pending &&
		    !pag->pag_dlm_readopt_pending &&
		    mxfs_ag_handoff_closing(pag)) {
			/*
			 * the LAST-HOLDER UNLOCK takes the release
			 * COMMIT itself (performed at the end of this critical
			 * section so the drain/yield logic below still sees the
			 * pending BAST) and queues the worker for the drains —
			 * no 0->1 re-adoption can win the race any more.
			 */
			do_latch = true;
			schedule_bast = true;
		} else if (pag->pag_dlm_bast_pending &&
		    !pag->pag_dlm_bast_scheduled) {
			pag->pag_dlm_bast_scheduled = true;
			schedule_bast = true;
		}
		/* the schedule edge the starvation analysis
		 * hinges on.  Ratelimited; only fires while a peer waits. */
		if (unlikely(pag->pag_dlm_bast_pending))
			mxfs_probe_ratelimited(
				"mxfs: P12-ULBP ag=%u sched_now=%d was_sched=%d readopt=%u page_ms=%u\n",
				pag_agno(pag), schedule_bast ? 1 : 0,
				(!schedule_bast &&
				 pag->pag_dlm_bast_scheduled) ? 1 : 0,
				pag->pag_dlm_readopt_n,
				jiffies_to_msecs(jiffies -
					pag->pag_dlm_bast_pending_since));
		/*
		 * v0.3.131: bounded yield quantum (D10 proper).  When
		 * mxfs_lazy_ag_drain=1 AND no BAST is pending AND the per-AG
		 * yield counter has remaining budget, skip the drain and
		 * decrement the counter.  When the counter hits 0, fall
		 * through to eager drain and reset the counter to
		 * MXFS_BAST_YIELD_QUANTUM for the next round.
		 *
		 * This caps the amount of dirty AG metadata that can
		 * accumulate before peer's BAST forces drain —
		 * v0.3.130 experiment showed binary skip-or-drain caused
		 * peer starvation (T2 stuck 600s while T1 held cached
		 * grants indefinitely).  Bounded yield quantum amortizes
		 * the per-trans drain cost across at most N transactions
		 * before forcing eager drain, bounding peer's worst-case
		 * BAST-drain wait time.
		 *
		 * When BAST IS pending we drain immediately because the
		 * BAST work fn (scheduled below) needs the alloc bufs on
		 * disk before it can release the grant on the wire.
		 */
		if (mxfs_lazy_ag_drain && drain_alloc &&
		    !pag->pag_dlm_bast_pending) {
			if (pag->pag_dlm_yield_remaining > 0) {
				pag->pag_dlm_yield_remaining--;
				/*
				 * v0.3.133 BUG FIX: skip the SYNCHRONOUS WAIT
				 * but still SUBMIT the bufs.  Without this,
				 * dirty bufs sit in the delwri queue, AIL
				 * items stay pinned, log tail can't advance,
				 * log space exhausts, all transactions block
				 * in xlog_grant_head_wait.  Async submit lets
				 * bufs trickle to disk while we keep the
				 * cached AG-DLM grant — best of both worlds.
				 *
				 * The async submit is performed AFTER releasing
				 * pag_dlm_lock to avoid holding it across the
				 * (brief) bio submission path.
				 */
				drain_alloc = false;
				lazy_skip = true;
			} else {
				/*
				 * Quantum exhausted — force eager drain (sync)
				 * to cap accumulated dirty metadata + flush.
				 * Reset the counter so subsequent transactions
				 * can skip again until the next forced drain.
				 *
				 * v0.3.147 adaptive quantum — if no
				 * peer asked during this epoch, count it as a
				 * "non-contended" eager drain.  After
				 * MXFS_AG_YIELD_DOUBLE_THRESH consecutive
				 * non-contended drains, double the effective
				 * quantum (capped at the static
				 * mxfs_ag_yield_quantum).  Workloads with no
				 * cross-node pressure converge back to large
				 * quantum (fast); workloads under sustained
				 * contention stay at the halved level.
				 */
				if (mxfs_ag_yield_adaptive &&
				    !pag->pag_dlm_bast_pending) {
					if (++pag->pag_dlm_skips_no_bast >=
					    MXFS_AG_YIELD_DOUBLE_THRESH) {
						pag->pag_dlm_skips_no_bast = 0;
						if (pag->pag_dlm_yield_quantum_eff <
						    mxfs_ag_yield_quantum)
							pag->pag_dlm_yield_quantum_eff <<= 1;
						if (pag->pag_dlm_yield_quantum_eff >
						    mxfs_ag_yield_quantum)
							pag->pag_dlm_yield_quantum_eff =
								mxfs_ag_yield_quantum;
					}
				}
				if (pag->pag_dlm_yield_quantum_eff <= 0)
					pag->pag_dlm_yield_quantum_eff =
						mxfs_ag_yield_quantum;
				pag->pag_dlm_yield_remaining =
					pag->pag_dlm_yield_quantum_eff;
				/*
				 * FIX-J (instrumented ftrace-proven):
				 * on a SINGLE-NODE mount the quantum-exhausted
				 * eager drain fired xfs_log_force(SYNC)+sync
				 * drain 211× per 8.7k-file rsync (211 of 213
				 * traced log forces; blk trace: 378 standalone
				 * FLUSH + 215 FUA log writes vs native's 27+14)
				 * = the whole single_node_paired gap (3.4s vs
				 * 2.9s native, ratio 117-122%).  Invariant #1
				 * exists to make AG-meta durable BEFORE a PEER
				 * reads it — with no peers there is nothing to
				 * protect; local integrity is XFS's normal
				 * log/AIL job.  Take the lazy path instead
				 * (async submit — submission must still
				 * happen or AIL pins wedge the log tail).  A
				 * later peer join is covered by the BAST drain:
				 * bast_work_fn Phase 2 drains this AG fully
				 * before any on-disk release, regardless of how
				 * many eager drains were skipped here.
				 */
				if (mp->m_mxfs_dlm &&
				    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
					drain_alloc = false;
					lazy_skip = true;
				}
			}
		}
		/*
		 * v0.3.131: P39-INSTR is rate-limit-noisy at scale (~570/sec
		 * during steady-state rsync).  Gate the print to every 64th
		 * UNLOCK-LAST event to keep dmesg readable while still
		 * sampling the lazy_skip / yield_remaining state.  Always
		 * print when bast_pending or schedule_bast (rare events
		 * worth full visibility).
		 */
		{
			static atomic64_t p39_unlock_last_count = ATOMIC64_INIT(0);
			u64 n = atomic64_inc_return(&p39_unlock_last_count);
			if ((n & 63) == 1 || pag->pag_dlm_bast_pending ||
			    schedule_bast)
				mxfs_idbg("mxfs: P39-INSTR ag=%u UNLOCK-LAST cached=false→true bast_pending=%d schedule_bast=%d lazy_skip=%d yield_remaining=%d eff=%d skips_nb=%d realns=%llu (event#%llu)\n",
					pag_agno(pag),
					pag->pag_dlm_bast_pending,
					schedule_bast, lazy_skip,
					pag->pag_dlm_yield_remaining,
					pag->pag_dlm_yield_quantum_eff,
					pag->pag_dlm_skips_no_bast,
					(unsigned long long)ktime_get_real_ns(),
					(unsigned long long)n);
		}
		if (do_latch)
			mxfs_ag_handoff_commit(pag, "unlock",
					       &mxfs_dlm_stat_latch_unlock);
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	if (drain_alloc) {
		/*
		 * v0.3.138 force the log BEFORE the synchronous drain.
		 *
		 * mxfs_dlm_ag_drain_alloc_buflist calls xfs_buf_delwri_submit
		 * (sync), which calls xfs_buf_submit, which calls
		 * xfs_buf_wait_unpin.  Bufs we're draining were just logged by
		 * the trans whose commit invoked us via xfs_trans_free; they're
		 * pinned in CIL.  Without an explicit log force, wait_unpin
		 * blocks until xfs_log_worker's auto-tick fires (~30s+) — far
		 * longer than the peer's 120s CAW timeout once you account for
		 * BAST scheduling latency.  v0.3.137 cross-node bench
		 * caught this directly: T2 rsync 1316 wedged in
		 *   xfs_buf_wait_unpin
		 *    xfs_buf_submit
		 *     xfs_buf_delwri_submit
		 *      mxfs_dlm_ag_drain_alloc_buflist
		 *       mxfs_ag_dlm_unlock
		 *        mxfs_trans_drain_ag_unlocks
		 *         xfs_trans_free
		 *
		 * Synchronous force ensures CIL → log writes complete and
		 * xlog_cil_committed unpin callbacks fire before we wait on
		 * the drain.  Cost is incurred only on the eager-drain path
		 * (lazy_skip path uses async submit and doesn't wait).
		 */
		xfs_log_force(mp, XFS_LOG_SYNC);
		mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
	} else if (lazy_skip) {
		/*
		 * v0.3.133 BUG FIX (extended in v0.3.134): still submit dirty
		 * bufs async even on the lazy-skip path, so AIL items can
		 * unpin and log tail advances.  Skip the blkdev_flush WAIT,
		 * not the SUBMIT.
		 *
		 * Three things happen here:
		 *
		 * 1. Async submit of pag_mxfs_alloc_buflist (the AG-meta
		 *    bufs we just dirtied — AGF/AGI/btree blocks).  Without
		 *    this, AG-meta xfs_buf_log_items pin AIL forever.
		 *
		 * 2. Non-sync xfs_log_force kicks the in-core log to disk
		 *    so xfsaild has work to do.  Cheap (just submits log
		 *    writes async, doesn't wait).
		 *
		 * 3. xfsaild handles inode AIL items autonomously by walking
		 *    AIL and calling iop_push; we don't need to explicitly
		 *    drain inode_buffers here because xfsaild covers that
		 *    in normal operation.  The bug was that we weren't
		 *    submitting alloc_buflist, NOT that xfsaild was broken.
		 *
		 * Final-loop discovery: lazy unlock left dirty AG-meta
		 * bufs in the delwri queue without submission.  AIL items
		 * pinned to those bufs blocked log tail advancement.  Log
		 * grant exhausted -> xfs_trans_alloc blocked forever in
		 * xlog_grant_head_wait.  Bug was reproducible SOLO with
		 * single_node=true (proves it's purely local, not cross-node
		 * coordination).  Fix: async submit on the lazy path.
		 */
		mxfs_dlm_ag_drain_alloc_buflist_nowait(mp, pag);
	}

	/*
	 * v0.3.135/0.3.136 under lazy_ag_drain=1, fire
	 * xfs_log_force(mp, 0) periodically on holders==0 transitions
	 * so CIL gets pushed.  Most file-create transactions don't
	 * allocate new inode chunks; without log_force, btree-block
	 * BLI items stay pinned by unflushed CIL records and log fills.
	 *
	 * v0.3.135 fired log_force on EVERY unlock — that fixed the
	 * single-node SOLO bug but caused multi-node disklock heartbeat
	 * timeouts (likely SCSI queue contention between log_force
	 * writes and disklock heartbeat).
	 *
	 * v0.3.136: throttle to every Nth unlock under lazy=1.  Since
	 * unlock rate during heavy create is ~1000/s, this fires
	 * log_force ~8/s — frequent enough to keep CIL pushed, sparse
	 * enough to not contend with disklock heartbeat.
	 *
	 * v0.5.5: the original throttle used
	 * `& 99`, a bitwise AND with 0b1100011 — NOT modulo 100.  That
	 * passes for 8 of every 128 counter values (every ~16th unlock),
	 * 6x the documented rate.  ftrace stack aggregation showed
	 * ~1580 async log_force calls per scaling_curve rsync at
	 * ~500us each ≈ 0.8s/node of in-syscall commit latency.  Use a
	 * power-of-two mask so the AND is a real every-128th gate.
	 */
	/*
	 * FIX-J part 2 (ftrace-proven): THIS throttle — not
	 * the eager drain — was the single-node log-force emitter: ~27k
	 * unlocks / 128 = 211 async forces per 8.7k-file rsync (211 of 213
	 * traced), each a PREFLUSH+FUA iclog write on the iSCSI LUN (blk
	 * trace: 378 standalone FLUSH + 215 FUA log writes vs native's
	 * 27+14) = the single_node_paired 3.4s-vs-2.9s gap.  The force
	 * exists to keep the CIL pushed for the DRAIN machinery — a
	 * multi-node liveness aid (peers wait on BAST drains).  Single-node,
	 * CIL pushing is native XFS's own job (xlog background worker,
	 * log-space thresholds, xfsaild's pinned-item log force) — the same
	 * mechanisms the native baseline runs with.  The SOLO wedge
	 * this force once patched was root-fixed by the lazy-path async
	 * SUBMIT above (v0.3.133/134), which stays.
	 */
	if (mxfs_lazy_ag_drain && (drain_alloc || lazy_skip ||
	                            pag->pag_dlm_cached) &&
	    !(mp->m_mxfs_dlm &&
	      mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))) {
		static atomic_t log_force_throttle = ATOMIC_INIT(0);
		if ((atomic_inc_return(&log_force_throttle) & 127) == 0)
			xfs_log_force(mp, 0);
	}

	if (schedule_bast) {
		/*
		 * v0.3.147 route through dedicated ordered workqueue
		 * (m_mxfs_ag_bast_wq, alloc_ordered_workqueue).  Serializes
		 * bast_work_fn invocations across all AGs on this mount —
		 * only one xfs_ail_push_ag_sync runs at a time.  Fixes the
		 * multi-node deadlock where 7+ parallel bast workers
		 * each polling xfs_ail_push_ag_sync starved xfsaild and
		 * exhausted the system_wq event-pool concurrency budget.
		 * Falls back to schedule_work (system_wq) if the dedicated
		 * queue is unavailable (defensive — should always be set
		 * post-mount).
		 */
		mxfs_ag_bast_queue(mp, pag);
	}
	/*
	 * Note: an attempted G+ extension (post-unlock cooperative drain)
	 * regressed wall-clock progress in testing.
	 * cancel_work_sync waited up to ag_bast_stall_iters (200 ≈ 2s) on
	 * each kworker invocation it preempted, slowing user-process
	 * commit-rate enough that T1 (the busy-fast-path node) stopped
	 * finishing before the bench timeout.  Reverted; only the slow-
	 * path pre-CAW drain (prescription G) remains.
	 */
}

/*
 * Deferred AG DLM unlock — queue the unlock on the trans, fire it from
 * xfs_trans_free (after xlog_cil_commit on success, or with no commit on
 * cancel).  This holds the DLM grant for the lifetime of the transaction
 * so a peer's ACQ-FRESH cannot read pre-allocation disk content while our
 * trans's AG-meta modifications are still in flight in xfs_trans -> CIL.
 *
 * The pag reference is held by the caller's xfs_perag_get; we transfer
 * that reference into the queue entry and release it when the deferred
 * unlock fires.  If allocation of the queue entry fails, fall back to
 * immediate unlock (preserves correctness, loses the race-fix).
 */
/* struct mxfs_pending_ag_unlock moved to the top of this file (— the
 * P1-AGWAIT held-AG enumerator needs it much earlier). */

void
mxfs_ag_dlm_unlock_deferred(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag)
{
	struct mxfs_pending_ag_unlock	*pending;

	if (!tp || !pag)
		return;

	pending = mxfs_pal_alloc(sizeof(*pending));
	if (!pending) {
		/* Fallback: behave like the original immediate unlock. */
		mxfs_ag_dlm_unlock(pag_mount(pag), pag);
		return;
	}

	INIT_LIST_HEAD(&pending->list);
	pending->pag = pag;
	xfs_perag_hold(pag); /* extra ref for the pending entry */
	list_add_tail(&pending->list, &tp->t_mxfs_ag_unlocks);
}

void
mxfs_trans_drain_ag_unlocks(
	struct xfs_trans	*tp)
{
	struct mxfs_pending_ag_unlock	*pending, *next;

	if (!tp || list_empty(&tp->t_mxfs_ag_unlocks))
		return;

	list_for_each_entry_safe(pending, next, &tp->t_mxfs_ag_unlocks, list) {
		struct xfs_perag *pag = pending->pag;
		list_del(&pending->list);
		mxfs_ag_dlm_unlock(pag_mount(pag), pag);
		xfs_perag_put(pag);
		mxfs_pal_free(pending);
	}
}

/*
 * -488 third face seam (design-consult ruling): post-roll ILOCK handoff.
 *
 * A defer finish_item found its AG peer-held (t_mxfs_ag_want) while the
 * caller holds ILOCK_EXCL on the transaction's joined inode(s)
 * (ili_lock_flags == 0: the caller, not the trans, owns the unlock).
 * Blocking there wedges this node's own AGs: iflush of the caller's
 * committed inode log item needs that ILOCK, so the inode's home-AG AIL
 * drain — and with it the on-disk EX release a peer is waiting for — can
 * never complete (proven cross-node Coffman cycle, test3/test25 truncate
 * pair, zero retained grants).
 *
 * Called only at the post-roll clean seam (RELSAFE_SAFE, trans clean,
 * every intent durably relogged).  Protocol:
 *   1. drain retained AG grants (the hold-and-wait edge),
 *   2. detach each caller-locked joined inode from the trans BEFORE
 *      unlocking it (while unlocked, a third task may ijoin the inode to
 *      its own trans — e.g. xattr-set takes ILOCK without IOLOCK — and
 *      li_trans must be free for that), drop the ILOCK — the inode is
 *      borrowed against the caller's own lifetime guarantee, NOT
 *      refcounted (see the detach-loop comment),
 *   3. block for the wanted AG holding nothing, then release the grant
 *      to cached immediately (holding it across the ILOCK relock would
 *      recreate the inverted AG-then-ILOCK edge while the
 *      alloc-under-ILOCK face is still unfixed),
 *   4. relock ascending-ino via the FIX-L3 Phase A/B protocol
 *      (xfs_lock_inodes for 2+ inodes: all cross-node DLM grants first
 *      with no rwsems held, then rwsems nowait-only), rejoin; the defer
 *      loop's retry then lands on the cached grant.
 * Error exits still relock + rejoin so the caller's unlock/cancel unwind
 * stays valid; a failure escalates to shutdown in xfs_defer_finish_noroll
 * and recovery replays the logged intents.
 *
 * the mechanics are shared with the rename/remove preacquire
 * fourth face (mxfs_trans_preacquire_inode_ags) via
 * mxfs_trans_agwait_handoff below.  `why` distinguishes the probes
 * (P271-AGWAIT-SEAM / P271-AGWAIT-PREACQ); backoff_ms staggers competing
 * nodes during the ILOCK-free window (0 = none) and MUST only ever be
 * slept with every ILOCK already handed off.  Consumes the pag reference.
 */
static int
mxfs_trans_agwait_handoff(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	const char		*why,
	unsigned int		backoff_ms)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_inode	*ips[XFS_DEFER_OPS_NR_INODES];
	struct xfs_log_item	*lip, *n;
	int			nips = 0;
	int			i, j;
	int			error;

	ASSERT(!(tp->t_flags & XFS_TRANS_DIRTY));

	/* edge: nothing may stay granted while we block. */
	mxfs_trans_drain_ag_unlocks(tp);

	list_for_each_entry_safe(lip, n, &tp->t_items, li_trans) {
		struct xfs_inode_log_item	*iip;
		struct xfs_inode		*ip;

		if (lip->li_type != XFS_LI_INODE) {
			/*
			 * A held buffer surviving the roll locked would be a
			 * fourth poisoning face — audit only; the inode
			 * handoff proceeds regardless.
			 */
			if (lip->li_type == XFS_LI_BUF)
				pr_warn_ratelimited("mxfs: P271-AGWAIT-HELDBUF ag=%u comm=%s — buf item joined at seam (audit)\n",
					pag_agno(pag), current->comm);
			continue;
		}
		iip = container_of(lip, struct xfs_inode_log_item, ili_item);
		if (iip->ili_lock_flags != 0)
			continue;	/* trans-owned unlock: roll drops it */
		ip = iip->ili_inode;
		ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL));
		if (WARN_ON_ONCE(nips >= XFS_DEFER_OPS_NR_INODES))
			break;
		/*
		 * Detached inodes are BORROWED, not refcounted: the synchronous
		 * caller whose frame spans xfs_defer_finish owns each joined
		 * inode's lifetime through detach/unlock/relock/rejoin (in the
		 * inactivation path that owner is evict itself, with i_count==0
		 * and I_FREEING set — an ihold/irele pair here re-enters
		 * iput_final on an inode already inside evict: BUG).
		 */
		xfs_trans_del_item(lip);
		ips[nips++] = ip;
	}
	for (i = 0; i < nips; i++)
		xfs_iunlock(ips[i], XFS_ILOCK_EXCL);

	mxfs_probe_ratelimited("mxfs: P271-AGWAIT-%s ag=%u inodes=%d comm=%s — blocking for peer-held AG with ILOCKs handed off\n",
		why, pag_agno(pag), nips, current->comm);

	if (backoff_ms)
		msleep(backoff_ms);

	/* RESOURCE_FREE class — ILOCKs handed off above, no trans. */
	error = mxfs_ag_dlm_lock_resfree(mp, pag);
	if (!error)
		mxfs_ag_dlm_unlock(mp, pag);	/* pregrant: leave cached */
	xfs_perag_put(pag);

	/* Ascending-ino relock order. */
	for (i = 1; i < nips; i++)
		for (j = i; j > 0 && ips[j]->i_ino < ips[j - 1]->i_ino; j--)
			swap(ips[j], ips[j - 1]);
	/*
	 * D-AGWAIT-RELOCK-ILOCK-HOLDWAIT-CONVOY-500: relocking a
	 * multi-inode set with plain blocking xfs_ilock held earlier members'
	 * rwsems across later members' UNBOUNDED cross-node DLM waits — the
	 * FIX-L3 violation (see xfs_lock_inodes).  Proven 32/caw: mv relocked
	 * inode[0], waited 480s on inode[1]'s dir EX (31 waiters), and the
	 * held rwsem poisoned this node's home-AG AIL drain, so its cached AG
	 * EX never released and the fleet convoyed until the CAW liveness cap
	 * (rc=-110).  xfs_lock_inodes runs the Phase A/B protocol: every
	 * cross-node DLM grant first, ascending, with NO rwsems held, then
	 * rwsems nowait-only.  A single inode blocks holding nothing, so
	 * plain xfs_ilock stays correct there.  Rejoin only after the whole
	 * set is locked.  On shutdown the DLM begins are refused
	 * (P-SHUTDOWN-FENCE) but every rwsem is still taken and the caller's
	 * one xfs_iunlock per inode stays balanced (P71 tolerates the
	 * unpaired end) — same postcondition as the old loop.
	 */
	if (nips == 1)
		xfs_ilock(ips[0], XFS_ILOCK_EXCL);
	else if (nips >= 2)
		xfs_lock_inodes(ips, nips, XFS_ILOCK_EXCL);
	for (i = 0; i < nips; i++)
		xfs_trans_ijoin(tp, ips[i], 0);

	if (!error && xfs_is_shutdown(mp))
		error = -EIO;
	return error;
}

int
mxfs_defer_agwait(
	struct xfs_trans	*tp)
{
	struct xfs_perag	*pag = tp->t_mxfs_ag_want;

	if (!pag)
		return 0;
	tp->t_mxfs_ag_want = NULL;

	ASSERT(tp->t_mxfs_ag_relsafe == MXFS_AG_RELSAFE_SAFE);

	return mxfs_trans_agwait_handoff(tp, pag, "SEAM", 0);
}

/* FIX-21 helper: record a pending defer work item's AG in the bitmap.
 * Returns false when the item's group cannot be represented (agno out of
 * bitmap range) — caller must then retain ALL grants.  Non-AG groups
 * (realtime) hold no AG-DLM grant and contribute nothing. */
static bool
mxfs_migrate_mark_group(
	unsigned long		*bm,
	const struct xfs_group	*xg)
{
	if (!xg || xg->xg_type != XG_TYPE_AG)
		return true;
	if (xg->xg_gno >= MXFS_MIGRATE_MAX_AGS)
		return false;
	__set_bit(xg->xg_gno, bm);
	return true;
}

/*
 * FIX-21 — selective AG-grant migration at trans roll.
 *
 * Replaces the unconditional v0.3.106 list_splice of t_mxfs_ag_unlocks in
 * xfs_trans_dup.  The unconditional splice made every defer roll carry ALL
 * AG-DLM grants to the end of the chain, so a dirty rm/mv chain held (say)
 * AG-4 the whole time it blocked acquiring AG-0 — the run96/97-proven
 * cross-node hold-and-wait convoy behind dlm_fairness/tcp_dlm_scaling
 * (P1-AGWAIT ag=0 trans_held_ags=[4]); victims die at defer-finish with
 * rc=-110 -> error-path shutdown.
 *
 * The splice exists to protect defer-chain coordinate stability: a pending
 * EFI's (bno,len) was computed under the AG grant, and the grant must
 * outlive the EFI or a peer can mutate the AG between rolls ("ltbno+ltlen
 * > bno" double-free corruption).  That guard only needs the
 * grants for AGs that still have UNFINISHED defer work referencing them.
 *
 * So: walk the pendings that were just moved to the new trans
 * (xfs_defer_move runs before this in xfs_trans_dup) and build the set of
 * AGs referenced by remaining work items.  Migrate only those grants;
 * everything else stays on the old tp and releases at its trans_free —
 * i.e. immediately after this sub-trans's CIL insertion — which lets a
 * peer's pending BAST claim the AG (the BAST pipeline does the full
 * drain-before-unlock, preserving invariant 1).
 *
 * Defer types whose work items carry no fixed AG coordinate (attr,
 * exchmaps, anything unrecognized with work items) force the conservative
 * full migration, because their processing may legitimately depend on an
 * AG grant acquired earlier in the chain.
 */
void
mxfs_trans_migrate_ag_unlocks(
	struct xfs_trans	*tp,
	struct xfs_trans	*ntp)
{
	struct mxfs_pending_ag_unlock	*pe, *next;
	struct xfs_defer_pending	*dfp;
	DECLARE_BITMAP(pending_ags, MXFS_MIGRATE_MAX_AGS);
	bool				retain_all = false;
	int				kept = 0, dropped = 0;

	if (list_empty(&tp->t_mxfs_ag_unlocks))
		return;

	bitmap_zero(pending_ags, MXFS_MIGRATE_MAX_AGS);

	list_for_each_entry(dfp, &ntp->t_dfops, dfp_list) {
		if (dfp->dfp_ops == &xfs_extent_free_defer_type ||
		    dfp->dfp_ops == &xfs_agfl_free_defer_type ||
		    dfp->dfp_ops == &xfs_rtextent_free_defer_type) {
			struct xfs_extent_free_item *xefi;

			list_for_each_entry(xefi, &dfp->dfp_work, xefi_list)
				if (!mxfs_migrate_mark_group(pending_ags,
							     xefi->xefi_group))
					retain_all = true;
		} else if (dfp->dfp_ops == &xfs_rmap_update_defer_type ||
			   dfp->dfp_ops == &xfs_rtrmap_update_defer_type) {
			struct xfs_rmap_intent *ri;

			list_for_each_entry(ri, &dfp->dfp_work, ri_list)
				if (!mxfs_migrate_mark_group(pending_ags,
							     ri->ri_group))
					retain_all = true;
		} else if (dfp->dfp_ops == &xfs_refcount_update_defer_type ||
			   dfp->dfp_ops == &xfs_rtrefcount_update_defer_type) {
			struct xfs_refcount_intent *ri;

			list_for_each_entry(ri, &dfp->dfp_work, ri_list)
				if (!mxfs_migrate_mark_group(pending_ags,
							     ri->ri_group))
					retain_all = true;
		} else if (dfp->dfp_ops == &xfs_bmap_update_defer_type) {
			struct xfs_bmap_intent *bi;

			list_for_each_entry(bi, &dfp->dfp_work, bi_list)
				if (!mxfs_migrate_mark_group(pending_ags,
							     bi->bi_group))
					retain_all = true;
		} else if (!list_empty(&dfp->dfp_work)) {
			/* attr, exchmaps, unknown: no mappable coordinate. */
			retain_all = true;
		}
		if (retain_all)
			break;
	}

	list_for_each_entry_safe(pe, next, &tp->t_mxfs_ag_unlocks, list) {
		xfs_agnumber_t	agno = pag_agno(pe->pag);

		if (retain_all || agno >= MXFS_MIGRATE_MAX_AGS ||
		    test_bit(agno, pending_ags)) {
			list_move_tail(&pe->list, &ntp->t_mxfs_ag_unlocks);
			kept++;
		} else {
			dropped++;	/* stays on tp; releases at old tp's
					 * trans_free right after this
					 * sub-commit */
		}
	}

	if (dropped) {
		static DEFINE_RATELIMIT_STATE(mig_rl, 5 * HZ, 2);

		if (mxfs_probe_on() && __ratelimit(&mig_rl))
			mxfs_probe("mxfs: P1-AGDUP-DROP dropped=%d kept=%d retain_all=%d — early AG-grant release at defer roll\n",
				dropped, kept, retain_all);
	}
}

/*
 * Pre-acquire the per-AG DLM locks for a set of inodes BEFORE the
 * caller takes ANY inode ILOCK, in ascending AG-number order.  This breaks
 * the distributed hold-and-wait deadlock proven under the rsync_paired
 * workload (4-node concurrent rename):
 *
 *   Previously xfs_rename took all inode ILOCKs (xfs_lock_inodes) and THEN
 *   blocked up to 120s deep inside the allocator acquiring a SECOND AG's
 *   DLM grant (mxfs_ag_dlm_lock).  A peer running the mirror rename could
 *   not release the AG we waited on, because its bast_work_fn AIL drain
 *   needed the ILOCK that its own blocked rename thread held — and we held
 *   the AG it wanted, symmetrically.  Result: 120s timeout -> -ETIMEDOUT
 *   propagated into xfs_rename with the transaction already DIRTY ->
 *   xfs_trans_cancel on a dirty trans -> "Corruption of in-memory data
 *   (0x8)" -> whole-node FS shutdown.
 *
 * Acquiring all needed AGs up front, in a global order, with NO ILOCK held,
 * eliminates the cycle:
 *   - No user thread ever waits on an AG grant while holding an inode ILOCK,
 *     so a peer's BAST can ALWAYS be satisfied by our bast_work_fn (the AIL
 *     drain is never blocked by a stuck ILOCK holder).  Even sticky CACHED
 *     grants from prior transactions are reclaimable asynchronously.
 *   - All nodes acquire the pre-acquire set in the same ascending order, so
 *     there is no AB-BA among freshly-acquired AGs.
 *
 * Grants are registered for deferred release at trans commit/cancel (the
 * normal t_mxfs_ag_unlocks path).  The deep-allocator's later
 * mxfs_ag_dlm_lock calls for these same AGs then hit the nested fast-path
 * (holders>0 -> return 0, no CAW I/O, no blocking).
 *
 * FIX-C contract: callers (xfs_rename, xfs_remove) invoke this AFTER
 * their entry inode locks are held and while the transaction is still CLEAN.
 * Entry-locks-first is load-bearing: acquiring AG grants BEFORE the entry
 * locks parked the task holding AG-EX while waiting for an entry-lock DLM
 * grant (P12-HOLDERTASK ladder-r16 stack), starving peers' dirty defer_finish
 * AG acquires into rc=-110 dirty-cancel shutdowns.  With the trans clean, a
 * (rare) acquire failure here is a clean xfs_trans_cancel with no shutdown.
 *
 * (-488 fourth face): entry-locks-first does NOT license blocking
 * under them.  The acquire pass is trylock-only; a miss hands the ILOCKs
 * off (detach/unlock/relock/rejoin, seam mechanics) and blocks
 * holding nothing.  While a task blocks on an AG grant it holds neither
 * an ILOCK nor another AG grant — the combined /invariant.
 * -EAGAIN means the bounded handoff budget ran out: the caller must
 * clean-cancel and retry the whole operation (locks were relocked; the
 * normal unwind is valid).
 *
 * (D-501, design-consult ruled): phase-aware mandatory/optional AG
 * intent.  The blanket participating-inode preacquire falsely coupled
 * rename's dir-EX with the dir's home AG: dlm_fairness (32-way hot-dir
 * create/rename/delete) showed 1227 of ~1590 AG waits on the dir's home
 * AG, ~600ms handoff + ~600ms dir-EX requeue per rename that touches NO
 * AG metadata — makespan 32 × handoff ≈ 32s vs the 30s budget, while the
 * dir EX itself rotated fairly (P291: 887 grants, 23ms median gap).
 * The insurance was also never complete: a dir-grow/shrink can demand
 * ANY AG via the allocator, not just a participant's home AG.
 *
 * So: only mand_inodes' AGs (demands past a non-restartable boundary —
 * in-trans iunlink add/remove or difree: rename's existing target_ip,
 * RENAME_WHITEOUT's wip, remove's victim ip) keep the miss->handoff->
 * block protocol.  The remaining participants' home AGs are OPTIONAL: a
 * trylock hit still registers the cached grant (deep acquires nest on
 * the fast path, and the holder batches its loop), but a miss just
 * PROCEEDS — no ILOCK handoff, no blocking, no -EAGAIN.  If a deep path
 * then blocks on an AG with the trans already dirty, the P292-DIRTY-
 * AGWAIT tripwire at the P1-AGWAIT site records how often the skipped
 * insurance actually mattered.
 */
/*
 * 0.75.41 (D-TCP-PREACQUIRE-AG-STEAL-CONVOY-...-0917): a mandatory-AG miss
 * used to go straight to the hand-off, which releases every inode lock and
 * blocks for the AG holding nothing.  Against a peer writing a file in a
 * tight loop that is a convoy: the peer's round (truncate under the file's
 * ILOCK, then write) blocks for the same AG, our cached pre-grant is handed
 * to it at zero holders, its round completes and hands the file to us, and
 * the restart's trylock misses again because the AG is cached over there.
 * Measured on the two-node TCP rig: one such cycle is ~90 ms and the count
 * per unlink was 1, 1, 1, 1, 6 and 16 across six laps (s522k/n, s523a/d/e/f)
 * — nothing in the protocol bounds it.
 *
 * The peer's own order is inode-then-AG.  So before handing the inodes off
 * we now ask for the AG in that same order, bounded: one DEMANDING
 * non-blocking acquire (registers the waiter and BASTs the cacher, exactly
 * what the silent trylock never did), then silent retries every few ms for
 * at most preacq_poll_ms.  With both inode locks held here the peer's
 * writer is parked on the file, so its cached AG has no holder and the
 * release arrives in one hand-off (~25 ms measured).  A hit registers the
 * grant like a trylock hit; an expiry falls back to the hand-off unchanged.
 * The poll runs only while NO other AG grant is registered on the
 * transaction (a miss on a later AG of a multi-AG set keeps the old path),
 * so it adds no AG-then-AG hold-and-wait; the inode-held wait on one AG is
 * the pattern mxfs_ag_dlm_lock_bounded already uses under a dirty
 * transaction, and its bound is what keeps the fourth face's worst
 * case at the poll length instead of a request deadline.
 */
int mxfs_preacq_poll_ms = 100;
module_param_named(preacq_poll_ms, mxfs_preacq_poll_ms, int, 0644);
MODULE_PARM_DESC(preacq_poll_ms,
	"remove/rename pre-acquire: poll a peer-held mandatory AG this long with the inode locks held (demand once, then silent retries) before handing the inode locks off; 0=off (default 100)");
static unsigned long long mxfs_preacq_poll_hit_n, mxfs_preacq_poll_miss_n;
module_param_named(preacq_poll_hit_n, mxfs_preacq_poll_hit_n, ullong, 0444);
MODULE_PARM_DESC(preacq_poll_hit_n, "read-only: pre-acquire polls that obtained the AG without an inode hand-off");
module_param_named(preacq_poll_miss_n, mxfs_preacq_poll_miss_n, ullong, 0444);
MODULE_PARM_DESC(preacq_poll_miss_n, "read-only: pre-acquire polls that expired into the inode hand-off");

static int
mxfs_preacq_poll(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	u64			t0 = ktime_get_ns();
	unsigned int		waited_ms = 0;
	bool			demand = true;
	int			error;

	for (;;) {
		error = __mxfs_ag_dlm_lock(mp, pag, true, demand, false);
		demand = false;
		if (error != -EAGAIN && error != -EWOULDBLOCK)
			break;
		waited_ms = (ktime_get_ns() - t0) / NSEC_PER_MSEC;
		if (waited_ms >= (unsigned int)READ_ONCE(mxfs_preacq_poll_ms)) {
			error = -EAGAIN;
			break;
		}
		usleep_range(2000, 3000);
	}
	waited_ms = (ktime_get_ns() - t0) / NSEC_PER_MSEC;
	if (!error)
		WRITE_ONCE(mxfs_preacq_poll_hit_n, mxfs_preacq_poll_hit_n + 1);
	else if (error == -EAGAIN)
		WRITE_ONCE(mxfs_preacq_poll_miss_n, mxfs_preacq_poll_miss_n + 1);
	mxfs_probe_ratelimited("mxfs: P271-PREACQ-POLL ag=%u hit=%d waited_ms=%u rc=%d comm=%s — peer-held mandatory AG polled with the inode locks held\n",
		pag_agno(pag), error == 0 ? 1 : 0, waited_ms, error,
		current->comm);
	return error;
}

int
mxfs_trans_preacquire_inode_ags(
	struct xfs_trans	*tp,
	struct xfs_inode	**inodes,
	int			num_inodes,
	struct xfs_inode	**mand_inodes,
	int			num_mand)
{
	struct xfs_mount	*mp;
	xfs_agnumber_t		ags[8];
	bool			mand[8];
	int			nags = 0;
	int			i, j;
	int			error = 0;

	if (!tp || !inodes || num_inodes <= 0)
		return 0;
	mp = tp->t_mountp;
	if (!mp || !mp->m_mxfs_dlm)
		return 0;

	/*
	 * Collect unique AG numbers — mandatory inodes first so a shared
	 * AG (optional participant living in a mandatory AG) dedupes onto
	 * the mandatory entry and keeps the stronger protocol.
	 */
	for (i = 0; i < num_mand + num_inodes; i++) {
		struct xfs_inode *ip = (i < num_mand) ?
			mand_inodes[i] : inodes[i - num_mand];
		xfs_agnumber_t	agno;
		bool		dup = false;

		if (!ip)
			continue;
		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		for (j = 0; j < nags; j++) {
			if (ags[j] == agno) {
				dup = true;
				break;
			}
		}
		if (!dup && nags < (int)ARRAY_SIZE(ags)) {
			mand[nags] = (i < num_mand);
			ags[nags++] = agno;
		}
	}

	/* Sort ascending (insertion sort; nags is tiny, <= 5). */
	for (i = 1; i < nags; i++) {
		xfs_agnumber_t	key = ags[i];
		bool		mkey = mand[i];

		for (j = i - 1; j >= 0 && ags[j] > key; j--) {
			ags[j + 1] = ags[j];
			mand[j + 1] = mand[j];
		}
		ags[j + 1] = key;
		mand[j + 1] = mkey;
	}

	/*
	 * (-488 fourth face, design-consult ruled): the acquire pass is
	 * TRYLOCK-only.  The old blocking mxfs_ag_dlm_lock here ran with
	 * every rename/remove ILOCK_EXCL held AND with earlier iterations'
	 * grants registered on tp — both halves of the proven cross-node
	 * Coffman cycle (test3 held ag=6 + ILOCKs waiting ag=7; test26's
	 * ag=7 was cached-unreleasable because its drain needed an inode
	 * ILOCKed by its own blocked rename waiting ag=6).  On a miss, hand
	 * off: drain OUR registered grants, detach + unlock the joined
	 * inodes, block for the missed AG holding NOTHING, pregrant it to
	 * cached, relock + rejoin, and restart the sweep (which now lands
	 * on cached fast-paths).  The handoff mechanics are the verified
	 * seam (mxfs_trans_agwait_handoff).  A bounded number of
	 * handoffs; exhaustion returns -EAGAIN so the caller does a CLEAN
	 * cancel + full-operation retry (trans is still clean throughout).
	 */
	{
		int	handoffs = 0;

restart:
		for (i = 0; i < nags; i++) {
			struct xfs_perag *pag = xfs_perag_get(mp, ags[i]);

			if (!pag)
				continue;
			error = mxfs_ag_dlm_trylock(mp, pag);
			if (error == -EAGAIN || error == -EWOULDBLOCK) {
				unsigned int backoff = 0;

				if (!mand[i]) {
					/*
					 * (D-501): optional insurance
					 * AG is peer-held — proceed without
					 * it rather than serialize this op
					 * behind a cross-node AG handoff it
					 * will likely never need.
					 */
					static atomic_t p293_n = ATOMIC_INIT(0);

					if ((unsigned)atomic_inc_return(&p293_n) <= 256)
						mxfs_probe("mxfs: P293-PREACQ-OPTSKIP ag=%u comm=%s\n",
							ags[i], current->comm);
					xfs_perag_put(pag);
					error = 0;
					continue;
				}
				/*
				 * 0.75.41 (D-0917): ask in the peer's own order
				 * first — bounded, inode locks held, no other AG
				 * grant registered.  See mxfs_preacq_poll.
				 */
				if (READ_ONCE(mxfs_preacq_poll_ms) > 0 &&
				    list_empty(&tp->t_mxfs_ag_unlocks) &&
				    !(tp->t_flags & XFS_TRANS_DIRTY)) {
					int prc = mxfs_preacq_poll(mp, pag);

					if (prc == 0) {
						mxfs_ag_dlm_unlock_deferred(tp, pag);
						xfs_perag_put(pag);
						error = 0;
						continue;
					}
					if (prc != -EAGAIN && prc != -EWOULDBLOCK) {
						xfs_perag_put(pag);
						return prc;
					}
				}
				if (++handoffs > 8) {
					xfs_perag_put(pag);
					mxfs_probe_ratelimited("mxfs: P271-PREACQ-EXHAUST ag=%u handoffs=%d comm=%s — caller must clean-cancel and retry the operation\n",
						ags[i], handoffs - 1,
						current->comm);
					return -EAGAIN;
				}
				if (handoffs > 2)
					backoff = 2 + get_random_u32_below(
							8 * handoffs);
				error = mxfs_trans_agwait_handoff(tp, pag,
						"PREACQ", backoff);
				if (error)
					return error;
				goto restart;
			}
			if (error) {
				xfs_perag_put(pag);
				break;
			}
			mxfs_ag_dlm_unlock_deferred(tp, pag);
			xfs_perag_put(pag);
		}
	}
	return error;
}

bool
mxfs_inode_dlm_defer_bast(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct mxfs_pending_inode_unlock	*pending;

	if (!tp || !ip)
		return false;

	pending = mxfs_pal_alloc(sizeof(*pending));
	if (!pending)
		return false;

	INIT_LIST_HEAD(&pending->list);
	pending->ip = ip;

	/*
	 *  (instrumented — BUG3 hunt): mxfs_dlm_ilock_end's
	 * need_flush branch can defer for the SAME ip more than once within
	 * ONE transaction (e.g. lock/unlock/re-lock/unlock on the same inode
	 * inside one tp — the i_dlm_demoter==current fast path this function
	 * itself arms is exactly what makes the re-acquire cheap/silent). If
	 * that happens, mxfs_trans_drain_inode_unlocks will call
	 * mxfs_dlm_bast_process(ip) twice back-to-back at trans-free time.
	 * Each defer_bast call takes its own paired ihold (so the ref count
	 * itself stays balanced against this list), but bast_process has NO
	 * "already released" no-op guard (confirmed by reading its entry
	 * path) — a second back-to-back call may re-run release/unlock logic
	 * against a lock state the first call already tore down. Detect and
	 * log loudly; NOT yet changing behavior (still adds the duplicate)
	 * until this is proven to correlate with BUG3.
	 */
	{
		struct mxfs_pending_inode_unlock *p130_dup;
		int p130_ndup = 0;

		list_for_each_entry(p130_dup, &tp->t_mxfs_inode_unlocks, list) {
			if (p130_dup->ip == ip)
				p130_ndup++;
		}
		if (unlikely(p130_ndup)) {
			static atomic_t p130_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p130_n) <= 4000)
				mxfs_probe("mxfs: P130-DEFERBAST-DUP ino=%llu already_pending=%d i_count=%d i_state=0x%lx dlm_mode=%u dlm_state=%u tp=%px pid=%d comm=%s\n",
					(unsigned long long)ip->i_ino, p130_ndup,
					atomic_read(&VFS_I(ip)->i_count),
					mxfs_istate(VFS_I(ip)),
					(unsigned)ip->i_dlm_mode,
					(unsigned)ip->i_dlm_state, tp,
					current->pid, current->comm);
		}
	}

	/*
	 *  (PROVEN BY INSTRUMENT — BUG3 root cause): this can be
	 * reached RE-ENTRANTLY from within ip's OWN synchronous eviction
	 * cascade (xfs_irele -> iput -> evict -> destroy_inode -> xfs_inactive
	 * -> xfs_attr_inactive -> xfs_iunlock -> mxfs_dlm_ilock_end -> here via
	 * the need_flush branch), in which case i_count is legitimately 0 and
	 * I_FREEING is already set. A raw ihold() (the old code) blindly
	 * resurrects the count (WARN_ON fires but does not stop it), arming a
	 * phantom deferred release that mxfs_trans_drain_inode_unlocks later
	 * genuinely executes against an inode whose real teardown is already
	 * in flight — PROVEN via direct struct-inode-pointer match (identical
	 * RDI/RBX across 3 live crash stack traces) racing a concurrent user
	 * rm() of the SAME live file (do_unlinkat's own protective ihold/iput,
	 * crashing in iput()'s VFS_BUG_ON_INODE). igrab() safely refuses
	 * instead (checks I_FREEING/I_WILL_FREE atomically under i_lock) — if
	 * it refuses, there is nothing to defer: the in-flight eviction owns
	 * this inode's teardown already.
	 */
	if (!igrab(VFS_I(ip))) {
		mxfs_pal_free(pending);
		return false;
	}

	/*
	 * Mark ourselves as the demoter for this ip BEFORE returning so
	 * any same-thread re-entrant ilock_begin between now and the
	 * trans drain takes the i_dlm_demoter==current fast-path instead
	 * of blocking on the DEMOTING wait (which nothing would fire,
	 * since bast_process is now deferred to trans_free).  Cleared
	 * after bast_process completes in mxfs_trans_drain_inode_unlocks.
	 */
	MXFS_SET_DEMOTER(ip);
	atomic64_inc(&mxfs_dem_defer_set);	/* discriminator */

	list_add_tail(&pending->list, &tp->t_mxfs_inode_unlocks);
	return true;
}

void
mxfs_trans_drain_inode_unlocks(
	struct xfs_trans	*tp)
{
	struct mxfs_pending_inode_unlock	*pending, *next;

	if (!tp || list_empty(&tp->t_mxfs_inode_unlocks))
		return;

	list_for_each_entry_safe(pending, next, &tp->t_mxfs_inode_unlocks,
				 list) {
		struct xfs_inode *ip = pending->ip;
		list_del(&pending->list);
		/*
		 * SELF-DEADLOCK GUARD — PROVEN BY INSTRUMENT
		 * live on test8 (16/tcp tcp_dlm_scaling, mv pid 32573, dossier
		 * tests/logs/tcp16_dlmscaling_wedge_20260719/): xfs_rename —
		 * like every modern XFS op — ijoins its inodes with
		 * lock_flags=0 and iunlocks them MANUALLY only after
		 * xfs_trans_commit returns, so at THIS point (trans_free) the
		 * committing task can still hold ILOCK-EXCL on the very inode
		 * a deferred BAST wants to release.  bast_process's AIL drain
		 * then needs xfs_iflush_cluster to take that same inode's
		 * ILOCK_SHARED (P129-CLSKIP ILOCK_NOWAIT_FAIL owner==this mv,
		 * on BOTH the dir and the renamed file) — the flush can never
		 * run, the drain spins forever (P113-DRAIN-WEDGE iter 22k+),
		 * peers time out at 184s and SHUT DOWN (rc=-110).  When the
		 * current task owns ip's ILOCK, punt to the per-inode BAST
		 * dwork instead: it runs in a kworker microseconds after the
		 * syscall drops its locks, and the CIL-publish ordering this
		 * trans_free drain exists for is already satisfied
		 * (xlog_cil_commit precedes xfs_trans_free on the commit
		 * path).  Same hazard class + same remedy as the
		 * inline-path fix (caller-held dir DATA buffer vs the flush).
		 * Ref contract: our pending ref transfers to the dwork; if the
		 * dwork is already armed (owns its own ref), drop ours.
		 * i_dlm_demoter stays == current so the task's own post-commit
		 * iunlock path keeps its fast-path; the dwork fn re-stamps the
		 * kworker when it runs.
		 */
		{
			struct task_struct *ilock_owner = (struct task_struct *)
				(atomic_long_read(&ip->i_lock.owner) & ~0x7UL);
			/*
			 * ICLUSTER Phase-B root,
			 * LIVE-STACK PROVEN on test15 (dir_reuse@32/caw
			 * icluster_dlm=1, crash_consistency BLOCK
			 * sync-wedged): an unwritten-conversion commit frees
			 * its transaction INSIDE the xfs-conv ioend worker;
			 * running bast_process inline there deadlocks —
			 * the drain's filemap_write_and_wait parks on folios
			 * whose writeback-clearing ioends are LATER ENTRIES
			 * IN THE SAME BATCH this worker is processing
			 * (xfs_end_io drains a merged per-inode list, so no
			 * other conv worker can complete them).  Captured:
			 * kworker xfs-conv AND the ino-bast worker both
			 * D-state in folio_wait_writeback under
			 * bast_process+0x5ed, syncs piled on sync_inodes_sb.
			 * Same remedy as the ILOCK-owner punt: the dwork
			 * runs in its own kworker after this batch's
			 * completions land.  Pre-iclus this window was
			 * near-unreachable (a peer had to BAST this exact
			 * FILE mid-writeback); cluster-granular BASTs make
			 * it routine (any peer touching any co-clustered
			 * inode).  Writepages context punts for the same
			 * reason (folio lock held by the submitter).
			 */
			bool ctx_punt = xfs_task_in_ioend() ||
					xfs_task_in_writepages();

			if (ilock_owner == current || ctx_punt) {
				static atomic_t p152_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p152_n) <= 2000)
					mxfs_probe("mxfs: P152-TRANSDRAIN-PUNT ino=%llu dlm_mode=%u dlm_state=%u pid=%d comm=%s why=%s — BAST release punted to dwork\n",
						(unsigned long long)ip->i_ino,
						(unsigned)ip->i_dlm_mode,
						(unsigned)ip->i_dlm_state,
						current->pid, current->comm,
						ilock_owner == current ?
						"ilock-owner" : "ioend-ctx");
				/*
				 * The defer already consumed bast_pending and
				 * set DEMOTING (ilock_end's need_flush arm).
				 * The dwork's entry check requires
				 * CACHED+bast_pending — restore that shape or
				 * the punt is a no-op and the inode strands in
				 * DEMOTING (local acquires would block
				 * forever).  CACHED+pending is the documented
				 * dwork protocol: it re-arms while our (still
				 * live) outer hold is in flight and runs the
				 * real release once the syscall's manual
				 * iunlock lands.
				 */
				spin_lock(&ip->i_dlm_lock);
				ip->i_dlm_bast_pending = true;
				if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING) {
					u8 dtr_om = ip->i_dlm_mode;
					u8 dtr_os = ip->i_dlm_state;

					ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
					mxfs_dlmtr_rec(ip, dtr_om, dtr_os,
						       MXFS_SITE);
				}
				ip->i_dlm_bastq_src = ilock_owner == current ?
					16 : 17; /* trans-free punt: 16=owner 17=ioend-ctx */
				/*
				 *  — RECORD THE
				 * RETENTION.  This `continue` is the ONLY exit
				 * in the tree that returns with a demoter
				 * claim still held (see the design block at
				 * i_dlm_demoter_punt in xfs_inode.h).  The
				 * retention itself is deliberate and stays:
				 * the committing task must keep its exemption
				 * across the post-commit xfs_iunlock this punt
				 * exists to wait for.  What was missing is any
				 * record that the claim is now UNPAIRED, so
				 * nothing could ever release it — the dwork
				 * that inherits the release lands in the other
				 * slot and clears only that one.  Stamp which
				 * slot we are leaving claimed and when, so
				 * mxfs_demoter_punt_reclaim_check() can free it
				 * once the ILOCK-EXCL window provably closes.
				 */
				if (ip->i_dlm_demoter == current) {
					ip->i_dlm_demoter_punt |= 1;
					if (ip->i_dlm_punt_n[0] < U8_MAX)
						ip->i_dlm_punt_n[0]++;
				}
				if (ip->i_dlm_demoter2 == current) {
					ip->i_dlm_demoter_punt |= 2;
					if (ip->i_dlm_punt_n[1] < U8_MAX)
						ip->i_dlm_punt_n[1]++;
				}
				if (ip->i_dlm_demoter_punt) {
					ip->i_dlm_demoter_punt_ns =
						ktime_get_ns();
					atomic64_inc(&mxfs_dem_punt_retain);
				}
				spin_unlock(&ip->i_dlm_lock);
				if (!mxfs_bast_arm_queue_delayed(ip, 0))
					iput(VFS_I(ip));
				mxfs_pal_free(pending);
				continue;
			}
		}
		{
			struct mxfs_dirdrain_task dde;	/* FENCE-V1 bracket */

			mxfs_dirdrain_enter(&dde);
			mxfs_dlm_bast_process(ip);
			mxfs_dirdrain_exit(&dde);
		}
		/*  demoter must stay == current through
		 * this iput too — same self-deadlock fix as
		 * mxfs_dlm_bast_work_fn (see its comment). */
		/*
		 *  (instrumented — BUG3 hunt): log i_count/
		 * i_state immediately before this iput().  mxfs_inode_dlm_
		 * defer_bast (this list's sole producer) does its own ihold()
		 * per entry with NO dedup against an already-pending ip for
		 * the SAME transaction — if it can ever be called twice for
		 * one ip within one tp (unconfirmed, under audit), this loop
		 * would iput() it twice too.  i_count==1 here (about to hit
		 * zero) on an ip that ALSO still has a live external holder
		 * (e.g. the unlinking task's own dentry reference) would be
		 * the smoking gun for BUG3 — capture pid/comm to correlate
		 * against whichever task's dentry_unlink_inode->iput() BUG_ONs
		 * moments later.
		 */
		{
			int p_cnt = atomic_read(&VFS_I(ip)->i_count);
			unsigned long p_st = mxfs_istate(VFS_I(ip));
			static atomic_t p127_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p127_n) <= 8000)
				mxfs_probe("mxfs: P127-TRANSDRAIN ino=%llu i_count=%d i_state=0x%lx ip=%px pid=%d comm=%s\n",
					(unsigned long long)ip->i_ino, p_cnt,
					p_st, ip, current->pid,
					current->comm);
		}
		iput(VFS_I(ip));
		MXFS_CLEAR_DEMOTER(ip);
		atomic64_inc(&mxfs_dem_defer_clear);	/* discriminator */
		mxfs_pal_free(pending);
	}

	/*
	 * the loop above is the ONLY consumer of this list, so anything
	 * left on it is a claim (and an igrab ref, and a pending allocation)
	 * that nothing will ever release.  A re-entrant defer onto the SAME tp
	 * from inside mxfs_dlm_bast_process would append behind an iterator that
	 * has already passed the tail and produce exactly that.  Assert it here
	 * rather than inferring it from a stranded claim minutes later.
	 */
	if (unlikely(!list_empty(&tp->t_mxfs_inode_unlocks))) {
		struct mxfs_pending_inode_unlock *res;
		int n = 0;

		list_for_each_entry(res, &tp->t_mxfs_inode_unlocks, list)
			n++;
		atomic64_add(n, &mxfs_dem_drain_residue);
		mxfs_probe("mxfs: P215-DRAIN-RESIDUE tp=%px left=%d pid=%d comm=%s — deferred inode unlocks appended after the drain iterator passed; their demoter claims will never be cleared\n",
			tp, n, current->pid, current->comm);
	}
}

/*
 * BAST notification from the v5 DLM layer: a peer wants this AG.
 * Mark the BAST pending; if no local holder is active and the AG is in
 * cached state, schedule the BAST work fn (drain + release).
 */
void
mxfs_dlm_ag_bast_notify(
	void		*data,
	uint32_t	agno,
	uint8_t		mode)
{
	struct xfs_mount	*mp = data;
	struct xfs_perag	*pag;
	bool			schedule_bast = false;
	bool			orphan_nak = false;
	bool			stuck_requeue = false;

	(void)mode;

	if (!mp || !mp->m_mxfs_dlm)
		return;

	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return;

	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	if (!pag->pag_dlm_bast_pending) {
		pag->pag_dlm_bast_pending_since = jiffies;
		pag->pag_dlm_bast_rx_ns = ktime_get_ns();
		pag->pag_dlm_readopt_n = 0;
		/* new BAST generation — the latch re-arms only after
		 * the worker's prepass has run for THIS generation. */
		pag->pag_dlm_prepass_done = false;
		pag->pag_dlm_work_enter_ns = 0;	/* 0.22.2 latency split */
		pag->pag_dlm_armed_ns = 0;
		pag->pag_dlm_queued_ns = 0;	/* 0.22.3 */
		pag->pag_dlm_rx_holders = pag->pag_dlm_holders;
	}
	pag->pag_dlm_bast_pending = true;
	/*
	 * v0.3.147 adaptive quantum — halve effective quantum on
	 * peer BAST.  Peer asking means our cached-grant epoch was longer
	 * than is fair; shorten the next epoch (down to 1).  Reset the
	 * "no-BAST" doubling counter since we've now seen contention.
	 */
	if (mxfs_ag_yield_adaptive) {
		if (pag->pag_dlm_yield_quantum_eff > 1)
			pag->pag_dlm_yield_quantum_eff >>= 1;
		pag->pag_dlm_skips_no_bast = 0;
	}
	if (pag->pag_dlm_holders == 0 &&
	    pag->pag_dlm_cached &&
	    !pag->pag_dlm_bast_scheduled) {
		pag->pag_dlm_bast_scheduled = true;
		schedule_bast = true;
	}
	/*
	 * D-488 step 4 (ruling): rx-side watchdog.  bast_scheduled
	 * is a latch — if the queued worker was lost (or died before its
	 * bail paths cleared the latch), no future BAST can ever schedule
	 * the release again and the peer starves silently.  A revocation
	 * still pending >30s with the latch set gets the work requeued
	 * (queue_work on an already-pending item is a no-op, and every
	 * worker path either clears the latch or requeues itself, so a
	 * spurious extra run is harmless).  demoting >60s is only probed:
	 * it is either a slow drain or the deliberate UNKNOWN quarantine,
	 * and neither may be force-cleared from rx context.
	 */
	if (pag->pag_dlm_bast_scheduled &&
	    jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since)
		    > 30000)
		stuck_requeue = true;
	if (pag->pag_dlm_demoting &&
	    jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since)
		    > 60000)
		pr_warn_ratelimited(
			"mxfs: P275-AG-DEMOTE-STUCK ag=%u page_ms=%u release_pending=%d — demote in flight (or quarantined) past 60s\n",
			agno,
			jiffies_to_msecs(jiffies -
				pag->pag_dlm_bast_pending_since),
			pag->pag_dlm_release_pending ? 1 : 0);
	/*
	 *  — ORPHAN-GRANT NAK detection.  A bast for an
	 * AG we provably do NOT hold (no holders, not cached, no release work
	 * scheduled or running) that has been pending >3s is a master-side
	 * zombie: the membership-change purge ate our local record before our
	 * release could reach the master (test6 AG-9: master re-BASTed 1/s
	 * for 500+ s while P12-AGBAST-RX had nothing to schedule — the whole
	 * cluster starved behind it).  Tell the master to drop its GRANTED
	 * entry for us.  The dlm-layer helper re-verifies the local table
	 * (any-state, incl. in-flight acquires) before sending, so a racing
	 * local acquire is never released out from under.  The 3s floor
	 * keeps normal release transitions (RX while the work is mid-flight
	 * flips cached off briefly) out of this path; the send itself fires
	 * from the work handoff below, outside pag_dlm_lock.
	 */
	if (pag->pag_dlm_holders == 0 &&
	    !pag->pag_dlm_cached &&
	    !pag->pag_dlm_bast_scheduled &&
	    jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since) > 3000)
		orphan_nak = true;
	/* arrival visibility for the run31 AG-0 starve —
	 * names the state that decides whether the release work runs.
	 * UNGATED — the 190s AG-0 starve produced zero
	 * receiver-side evidence because every AG-BAST probe was instr-gated.
	 * Ratelimited; fires only under peer contention. */
	mxfs_probe_ratelimited(
		"mxfs: P12-AGBAST-RX ag=%u holders=%d cached=%d sched=%d schedule=%d readopt=%u page_ms=%u holder=%d/%s\n",
		agno, pag->pag_dlm_holders,
		pag->pag_dlm_cached ? 1 : 0,
		pag->pag_dlm_bast_scheduled ? 1 : 0,
		schedule_bast ? 1 : 0,
		pag->pag_dlm_readopt_n,
		jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since),
		pag->pag_dlm_holder_pid, pag->pag_dlm_holder_comm);
	/*
	 * a hold stuck >15s past a peer's BAST is the fence
	 * 60s-starve precursor.  The holder is often NOT in a DLM wait (no
	 * P36 from it), so dump ITS stack (capped 6/boot) — that names the
	 * blocking edge the waiter-side dumps cannot.
	 */
	if (pag->pag_dlm_holders > 0 &&
	    jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since)
		    > 15000) {
		static atomic_t p12_htask_cap = ATOMIC_INIT(0);
		if (atomic_inc_return(&p12_htask_cap) <= 6) {
			struct pid *hp = find_get_pid(pag->pag_dlm_holder_pid);
			struct task_struct *ht =
				hp ? get_pid_task(hp, PIDTYPE_PID) : NULL;
			mxfs_probe("mxfs: P12-HOLDERTASK ag=%u pid=%d comm=%s alive=%d — stack follows\n",
				agno, pag->pag_dlm_holder_pid,
				pag->pag_dlm_holder_comm, ht ? 1 : 0);
			if (ht) {
				if (mxfs_probe_on())
					sched_show_task(ht);
				put_task_struct(ht);
			}
			if (hp)
				put_pid(hp);
		}
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	/*  orphan-grant NAK — outside pag_dlm_lock (the
	 * send can sleep).  Fires at most once per incoming bast (~1/s from a
	 * stuck master) and stops as soon as the master drops the zombie. */
	if (orphan_nak) {
		int nak_rc = mxfs_v5_dlm_ag_orphan_nak(mp->m_mxfs_dlm, agno);
		/*
		 *  — CAW STRANDED-AG detection + repair
		 * (see mxfs_ag_strand_repair).  On CAW the NAK above is a no-op,
		 * so ask the platter directly: does our holder bit survive in the
		 * slot while we have no in-core tenure at all?  That is the state
		 * from which no BAST can ever schedule a release.
		 *
		 * The read is one CAW slot read, taken only on this branch (a
		 * BAST for an AG we do not hold, pending >3 s) and ratelimited by
		 * the print below, so it costs nothing on a healthy mount.
		 */
		extern int mxfs_ag_strand_repair;
		int held = -1;
		int readopt = 0;
		bool dm, rp;

		/*
		 * TCP has the same strand in a different place: a release that
		 * skipped its unlock leaves our GRANTED entry in the local grant
		 * table, so the NAK above refuses (-EBUSY, the entry is ours)
		 * and nothing else ever releases it — measured on 2/tcp, the
		 * peer's creates timing out for 400+ s.  The re-adopt below is
		 * transport-neutral (a real acquire, then the ordinary release
		 * pipeline), so it only needs the transport's own answer to
		 * "is it still ours": the slot on CAW, the grant table on TCP.
		 * A grant with an acquire or conversion in flight answers
		 * -EBUSY and is left alone.
		 */
		{
			held = mxfs_v5_dlm_ag_strand_held(mp->m_mxfs_dlm, agno);

			mxfs_pag_dlm_lock(pag, MXFS_SITE);
			dm = pag->pag_dlm_demoting;
			rp = pag->pag_dlm_release_pending;
			/*
			 * Re-check the whole condition under the lock: demoting
			 * and release_pending are LEGITIMATE "held on disk with
			 * cached=false" states (a release already in flight owns
			 * the grant and will unlock it), and the notify-side
			 * orphan test above does not look at them.  Only a node
			 * with no tenure in any of the four states is stranded.
			 */
			if (held == 1 && mxfs_ag_strand_repair &&
			    pag->pag_dlm_holders == 0 &&
			    !pag->pag_dlm_cached && !dm && !rp &&
			    !pag->pag_dlm_bast_scheduled &&
			    !pag->pag_dlm_readopt_pending) {
				/*
				 * (D-488 leg 7 part 1b, ruling):
				 * do NOT fabricate a cached tenure here.  The old
				 * pag_dlm_cached=true left the published authority
				 * epoch at 0 (the release-commit that stranded the
				 * bit zeroed it), so a local fast-path reclaim
				 * adopted WRITE authority with no epoch — every
				 * buffer that tenure logged was unauthorized and a
				 * foreign replayer must refuse it.  Mark the
				 * strand READOPT_PENDING instead; the bast worker
				 * performs the verified P294 READOPT mint off the
				 * rx path before any tenure or release proceeds.
				 */
				pag->pag_dlm_readopt_pending = true;
				pag->pag_dlm_bast_scheduled = true;
				pag->pag_dlm_bast_pending = true;
				readopt = 1;
			} else if (held == 0 && pag->pag_dlm_holders == 0 &&
				   mxfs_v5_dlm_is_caw(mp->m_mxfs_dlm) &&
				   !pag->pag_dlm_cached && !dm && !rp &&
				   !pag->pag_dlm_bast_scheduled) {
				/*
				 * The BAST is a multicast hint for an AG we
				 * provably do not hold (bast_recv_fn fires the
				 * callback on every node in the group).  Nothing
				 * will ever consume pag_dlm_bast_pending here, so
				 * leaving it set makes pag_dlm_bast_pending_since
				 * — and every page_ms in the AG logs — measure
				 * time since the first hint we ever saw instead of
				 * the age of a real revocation.  Clear it.
				 */
				pag->pag_dlm_bast_pending = false;
			}
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		}

		pr_warn_ratelimited(
			"mxfs: P5N-AG-ORPHAN-NAK ag=%u src=bast-rx rc=%d disk_held=%d repair=%d — CAW holder bit on the platter with no in-core tenure is a STRANDED AG: no peer BAST can schedule its release\n",
			agno, nak_rc, held, readopt);

		if (readopt) {
			mxfs_ag_bast_queue(mp, pag);
		}
	}

	if (stuck_requeue && !schedule_bast) {
		bool requeued;

		if (!READ_ONCE(pag->pag_dlm_queued_ns))
			WRITE_ONCE(pag->pag_dlm_queued_ns, ktime_get_ns());
		if (mp->m_mxfs_ag_bast_wq)
			requeued = queue_work(mp->m_mxfs_ag_bast_wq,
					      &pag->pag_dlm_bast_work);
		else
			requeued = schedule_work(&pag->pag_dlm_bast_work);
		pr_warn_ratelimited(
			"mxfs: P275-AG-STUCK-LATCH ag=%u page_ms=%u requeued=%d — bast_scheduled latched >30s with revocation still pending\n",
			agno,
			jiffies_to_msecs(jiffies -
				pag->pag_dlm_bast_pending_since),
			requeued ? 1 : 0);
	}

	if (schedule_bast) {
		/* v0.3.147 dedicated ordered wq — see other callsite. */
		mxfs_ag_bast_queue(mp, pag);
	}

	xfs_perag_put(pag);
}

/*
 * (D-488 leg 7 part 1b, ruling): resolve a READOPT_PENDING
 * strand off the rx path.  Single-flight: only the bast worker calls this,
 * and pag_dlm_bast_scheduled was latched in the same critical section that
 * set the pending state, so no second instance can run concurrently.
 *
 * Re-read the slot first: bit gone means a peer's recovery (or our own
 * late unlock completion) already resolved the strand — just clear the
 * pending state.  Bit still ours: take the REAL acquire path.  It attests
 * our published epoch (0 — no tenure survives a release commit) down to
 * the CAW already-held arm, which refuses to reaffirm the surrendered
 * epoch and CASes a fresh READOPT mint (P294-READOPT-MINT).
 * Then release through the ordinary unlock so the drain/release pipeline —
 * not this helper — services the peer's BAST.  The brief holders=1 window
 * can admit a local writer, but only AFTER the mint published a fresh
 * epoch, so any such tenure extension is ordinary and fully authorized.
 *
 * On mint failure nothing is published and the pending state is cleared:
 * the rx strand detector is the retry cadence (a waiting master re-BASTs
 * ~1/s), matching the pre-existing "rx readopt path is the backstop"
 * recovery philosophy at the deferred-release site.
 */
static void
mxfs_dlm_ag_rx_readopt_mint(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	int			held;
	int			lrc;

	held = mxfs_v5_dlm_ag_strand_held(dlm, pag_agno(pag));
	if (held != 1) {
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		pag->pag_dlm_readopt_pending = false;
		pag->pag_dlm_bast_pending = false;
		pag->pag_dlm_bast_scheduled = false;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		mxfs_probe("mxfs: P295-RX-READOPT-GONE ag=%u held=%d — stranded bit no longer ours; pending cleared\n",
			pag_agno(pag), held);
		return;
	}

	lrc = mxfs_ag_dlm_lock(mp, pag);

	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	pag->pag_dlm_readopt_pending = false;
	/*
	 * bast_scheduled is OUR latch — release it before the unlock below
	 * so the last-holder transition can reschedule the worker for the
	 * real drain+release cycle (it only schedules on pending&&!scheduled).
	 */
	pag->pag_dlm_bast_scheduled = false;
	pag->pag_dlm_bast_pending = true;
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	if (lrc == 0) {
		mxfs_probe("mxfs: P295-RX-READOPT-MINTED ag=%u gep=%llu — strand re-minted through the attested acquire; unlock schedules the release\n",
			pag_agno(pag),
			(unsigned long long)READ_ONCE(pag->pag_mxfs_grant_epoch));
		mxfs_ag_dlm_unlock(mp, pag);
	} else {
		pr_warn("mxfs: P295-RX-READOPT-FAIL ag=%u rc=%d — mint refused, nothing published; bit still on platter, rx watchdog re-arms on the next BAST\n",
			pag_agno(pag), lrc);
	}
}

/*
 * (0.39.2, D-0351 chain residual): census of this node's publication
 * obligations for @pag at the moment the on-disk grant is about to leave
 * (every mxfs_v5_dlm_ag_unlock site).  An actionable FREE / FREE_PENDING
 * entry crossing a release is the FREE-PUBLISH invariant being violated by
 * THIS path — s435 measured two P-FREEOB-CHAIN-BROKEN (ob_epoch=31,
 * epoch=33) with the inline audit silent, i.e. some release path let a
 * committed free through un-audited.  Loud, named by path.
 */
void
mxfs_pubob_unlock_census(
	struct xfs_perag	*pag,
	const char		*path)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct mxfs_pubob	*ob;
	int			 nfree = 0, npend = 0, nchain = 0, nunl = 0;
	uint64_t		 ino1 = 0;

	if (!mp->m_mxfs_pubob_count)
		return;
	spin_lock(&mp->m_mxfs_pubob_lock);
	list_for_each_entry(ob, &mp->m_mxfs_pubob_list, l) {
		if (ob->agno != pag_agno(pag))
			continue;
		switch (ob->kind) {
		case MXFS_PUBOB_FREE:
			if (!nfree)
				ino1 = ob->ino;
			nfree++;
			break;
		case MXFS_PUBOB_FREE_PENDING:
			npend++;
			break;
		case MXFS_PUBOB_CHAIN_LIVE:
			nchain++;
			break;
		default:
			nunl++;
			break;
		}
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	if (nfree || npend)
		mxfs_probe("mxfs: P-FREEOB-XRELEASE ag=%u path=%s free=%d pending=%d chain_live=%d unlink=%d first_ino=%llu rel_epoch=%llu — committed free obligation(s) still open as the grant leaves this node\n",
			pag_agno(pag), path, nfree, npend, nchain, nunl,
			(unsigned long long)ino1,
			(unsigned long long)READ_ONCE(pag->pag_mxfs_rel_epoch));
}

/*
 * P86/P87 + + the publication gate every AG release
 * passes before its unlock — what will the acquirer see?  Read it the way
 * they will, repair what is ours to repair, and refuse to publish a split
 * we could not fix.  Invariant 1: never unlock undrained.
 *
 * (0.39.2): factored out of mxfs_dlm_ag_bast_work_fn so the DEFERRED
 * release path (mxfs_dlm_ag_release_work_fn — taken whenever AG-metadata
 * writeback was still pending at the release COMMIT) runs the SAME gate.
 * It did not: a committed FREE obligation could cross a deferred release
 * un-audited (the tenure ended with the entry open; the next local
 * re-allocation logged P-FREEOB-CHAIN-BROKEN and every later free of that
 * number was misread as FOREIGN against the node's own unpublished image).
 */
void
mxfs_ag_release_publish_gate(
	struct xfs_perag	*pag,
	const char		*path)
{
	struct xfs_mount	*mp = pag_mount(pag);
	int p87_split = mxfs_p86_agi_unlinked_publish_audit(pag);

	/*
	 * design-consult ruling (refusal semantics): bounded DEFERRAL
	 * before any escalation.  The dominant unrepaired-split cause
	 * is a local thread holding the target's ILOCK across a DLM
	 * poll (measured: rm/rsync held it for the whole 3s budget);
	 * most such holds clear in seconds.  Two in-place retries with
	 * a 2s gap raise the repair ceiling to ~13s per split-carrying
	 * release — rare (1-4 per lap fleet-wide) and bounded well
	 * under the 120s peer grant timeout.  Only then escalate.
	 */
	if (p87_split > 0 && !xfs_is_shutdown(mp)) {
		int p87_retry;

		for (p87_retry = 0; p87_retry < 2 && p87_split > 0;
		     p87_retry++) {
			msleep(2000);
			p87_split = mxfs_p86_agi_unlinked_publish_audit(pag);
		}
		/*
		 * (D-0351): a FREE obligation this release cannot
		 * publish is the proven node-killer of a PEER (it allocates
		 * the free inobt bit and meets a live dinode).  Keep
		 * deferring — the pending/target-flush cases clear in ms —
		 * up to a budget well under the peer grant timeout, then
		 * fail CLOSED regardless of the P87 protest knob: our
		 * journal slice carries the committed free, so replay
		 * publishes it after a fence.
		 */
		/*
		 * (D-0524, design-consult ruling): a FREE_PENDING entry that is
		 * an orphan or belongs to another tenure is a bookkeeping
		 * violation, not in-flight work — deferring would only mask it.
		 * Refuse at once.
		 */
		if (p87_split > 0 && READ_ONCE(pag->pag_mxfs_freeob_fatal) > 0 &&
		    !xfs_is_shutdown(mp)) {
			pr_err("mxfs: P-FREEOB-REFUSED ag=%u path=%s fatal=%d — FREE obligation bookkeeping violated (orphan or cross-tenure FREE_PENDING, see P-FREEOB-PENDING-FATAL); refusing to hand the AG to a peer: shutting down (fail-closed, journal carries the free)\n",
				pag_agno(pag), path,
				READ_ONCE(pag->pag_mxfs_freeob_fatal));
			xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		}
		if (p87_split > 0 && READ_ONCE(pag->pag_mxfs_freeob_split) > 0 &&
		    !xfs_is_shutdown(mp)) {
			int fr;

			for (fr = 0; fr < 8 && !xfs_is_shutdown(mp) &&
			     READ_ONCE(pag->pag_mxfs_freeob_split) > 0; fr++) {
				msleep(2000);
				p87_split = mxfs_p86_agi_unlinked_publish_audit(pag);
			}
			if (READ_ONCE(pag->pag_mxfs_freeob_split) > 0 &&
			    !xfs_is_shutdown(mp)) {
				pr_err("mxfs: P-FREEOB-REFUSED ag=%u path=%s unpublished=%d — refusing to hand the AG to a peer with a committed free whose home dinode still reads LIVE; shutting down (fail-closed, journal carries the free)\n",
					pag_agno(pag), path,
					READ_ONCE(pag->pag_mxfs_freeob_split));
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
			}
		}
		if (p87_split > 0)
			mxfs_probe("mxfs: P87-PUBLISH-DEFER-EXHAUSTED ag=%u path=%s unrepaired=%d — split survived deferred repair; %s\n",
				pag_agno(pag), path, p87_split,
				mxfs_p87_refuse_unlock ?
				"escalating to refusal" :
				"publishing under protest (refuse knob off)");
	}
	if (p87_split > 0 && mxfs_p87_refuse_unlock &&
	    !xfs_is_shutdown(mp)) {
		pr_warn("mxfs: P87-PUBLISH-REFUSED ag=%u path=%s unrepaired_splits=%d — refusing to publish an unlinked-list head whose home dinode reads LINKED; shutting down rather than handing a peer metadata that will make it call this AGI corruption\n",
			pag_agno(pag), path, p87_split);
		xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
	}
	mxfs_pubob_unlock_census(pag, path);
}

/*
 * Worker that turns a cached-AG grant into an actual DLM release once a
 * peer-side BAST has fired and no local holder is active.
 *
 * Steps (must be in this order):
 *  1. Drain pag_mxfs_alloc_buflist (fresh cluster buffers for inodes
 *     allocated under this hold).
 *  2. Drain inode-cluster buffers in pag_bcache that have pending
 *     iflush items (b_li_list non-empty) — closes the cross-node
 *     cluster-buffer coherency window the v0.2.9 walk addressed.
 *  3. blkdev_issue_flush — order all writeback below the block layer.
 *  4. Under pag_dlm_lock: if a holder has reappeared, abandon (next
 *     unlock will reschedule).  Otherwise commit: clear pag_dlm_cached.
 *     If pag_dlm_meta_pending is non-zero, set release_pending and let
 *     mxfs_dlm_ag_meta_iodone fire the actual mxfs_v5_dlm_ag_unlock once
 *     it drains.  If already zero, fire the unlock here.
 */
void
mxfs_dlm_ag_bast_work_fn(
	struct work_struct	*work)
{
	struct xfs_perag	*pag = container_of(work, struct xfs_perag,
						    pag_dlm_bast_work);
	struct xfs_mount	*mp = pag_mount(pag);
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	bool			do_release = false;
	enum mxfs_unlock_state	us;
	/* 0.75.55 stage split (P12-AGREL-STAGES): entry, prepass end, COMMIT,
	 * first post-COMMIT force, second force, drains+flushes, second meta
	 * drain, phase-3 wait, final flushes, publish gate, unlock. */
	u64			ags_enter = ktime_get_ns(), ags_pre = 0, ags_commit = 0;
	u64			ags_f1 = 0, ags_f2 = 0, ags_dr1 = 0, ags_dr2 = 0;
	u64			ags_p3 = 0, ags_fl = 0, ags_gate = 0, ags_unlk = 0;
	unsigned int		ags_pin1 = 0, ags_ail1 = 0, ags_pin2 = 0, ags_ail2 = 0;

	if (!dlm)
		return;

	/* ungated entry stamp.  An entry with no matching
	 * bail/commit/stall print means this worker is STUCK below (publish,
	 * log_force, drain) — the shape that starves a peer for minutes. */
	mxfs_probe_ratelimited("mxfs: P12-WORK ag=%u enter holders=%d cached=%d page_ms=%u\n",
		pag_agno(pag), pag->pag_dlm_holders,
		pag->pag_dlm_cached ? 1 : 0,
		jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since));

	/*
	 * deferred-publish: a peer is acquiring this AG.  It may reach a
	 * locally-granted-but-unpublished inode via the inobt/AGI (inode alloc,
	 * bulkstat) without going through a directory.  Publish the unpublished
	 * list before we release the AG so those inodes get real slots and the
	 * peer coordinates with us.  No-op (no lock taken) when the list is
	 * empty — the node-affine rsync_paired case never BASTs a peer's AG.
	 * v0.5.6: scoped to inodes that LIVE in this AG (the peer's
	 * AGI/inobt walk can only surface those) plus parent-unknown entries.
	 */
	/*
	 * (design-consult ruling ag-handoff-
	 * latch-closing-restartable): if the release COMMIT was already taken
	 * outside this worker — by the last-holder unlock or by a would-be
	 * re-adopter (P12-LATCH) — admission is closed, the grant is detached
	 * and authority is invalidated.  Go straight to the post-COMMIT drains.
	 * The publish/prepass below MUST NOT run here: its data writeback
	 * allocates in this very AG and would sleep on our own demote.
	 */
	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	if (pag->pag_dlm_bast_pending && !pag->pag_dlm_work_enter_ns)
		pag->pag_dlm_work_enter_ns = ktime_get_ns();	/* 0.22.2 */
	if (pag->pag_dlm_latched) {
		mxfs_probe_ratelimited("mxfs: P12-WORK ag=%u LATCHED-ENTER latch_ms=%llu page_ms=%u\n",
			pag_agno(pag),
			(unsigned long long)((ktime_get_ns() -
				pag->pag_dlm_latch_ns) / NSEC_PER_MSEC),
			jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since));
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		goto committed;
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	mxfs_dlm_publish_unpublished(mp, 0, pag_agno(pag));

	/*
	 * Phase 1 (PREPASS): publish + bounded AIL push, with admission OPEN.
	 * The publish pass above does data writeback that re-calls
	 * mxfs_ag_dlm_lock for block allocation in this AG; with the COMMIT
	 * already taken that re-acquire would sleep on pag_dlm_demote_wq while
	 * we sleep waiting for it → circular wait (the deadlock the original
	 * "do NOT yet set demoting" comment described).  So the prepass runs
	 * before any COMMIT and tolerates local re-adoption.
	 *
	 * the prepass no longer requires holders==0.  Only the COMMIT
	 * does; a worker that bailed on holders>0 before its prepass could
	 * never arm the handoff latch under load (the measured 3 ms local op
	 * cadence beat every worker wakeup — P12-WORK bail1-holders on every
	 * run, peer starved).  Bail here only when this node provably has no
	 * tenure at all (holders==0 && !cached): strand mint or consumed
	 * pending.
	 */
	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	if (pag->pag_dlm_holders == 0 && !pag->pag_dlm_cached) {
		/*
		 * (D-488 leg 7 part 1b): a READOPT_PENDING strand
		 * parks here — no tenure, no cached hint, our bit on the
		 * platter.  Perform the verified mint outside pag_dlm_lock.
		 * If a release cycle owns the AG (demoting/release_pending,
		 * e.g. the quarantine arm), leave it to that machinery and
		 * drop the pending state — minting would race the in-flight
		 * platter unlock.
		 */
		bool mint = pag->pag_dlm_readopt_pending &&
			    !pag->pag_dlm_demoting &&
			    !pag->pag_dlm_release_pending;

		if (mint) {
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			mxfs_dlm_ag_rx_readopt_mint(mp, pag);
			return;
		}
		pag->pag_dlm_readopt_pending = false;
		pag->pag_dlm_bast_pending = false;
		pag->pag_dlm_bast_scheduled = false;
		mxfs_probe_ratelimited(
			"mxfs: P12-WORK ag=%u bail1-uncached (pending consumed)\n",
			pag_agno(pag));
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		return;
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	/*
	 * v0.3.45 attempted xfs_inodegc_flush(mp) here to drain pending
	 * inactive_ifree before peer ACQ-FRESH could see stale AGI.
	 * Reverted v0.3.48 — caused bnobt LEFT-FAIL regression at iter-1.
	 * Calling inodegc_flush in AG bast triggers re-entrant AG-DLM
	 * acquires from inactive_ifree's path that disrupts bnobt
	 * coordination.  Recovery in xfs_iunlink_insert (v0.3.47) handles
	 * the recycled-inode race more cleanly.
	 */

	/*
	 * Force log + AIL push BEFORE claiming the demote slot.  AIL push
	 * may issue writeback that allocates blocks → mxfs_ag_dlm_lock →
	 * (cached fast-path, holders++, cached=false).  This briefly hands
	 * the AG to the writeback thread; that's correct behavior.
	 *
	 * v0.3.112 Phase 1 (D8): per-AG drain replaces xfs_ail_push_all_sync.
	 * Whole-AIL drain at this point caused cross-AG deadlocks at
	 * 5×512MB+ workloads — items belonging to AGs other than the one
	 * being released would not drain (peer holds them) and we'd block
	 * indefinitely.  Per-AG filter waits only on items whose target
	 * (BUF daddr or INODE number) is in this AG.  See spec §11.3.
	 */
	xfs_log_force(mp, XFS_LOG_SYNC);
	if (mxfs_ag_prepass_push_iters > 0) {
		/*
		 * v0.3.147 introduced this as a bounded drain with a
		 * stall-and-ABORT (600 × 10 ms; on -EAGAIN keep the grant and
		 * retry next cycle) — from the era when this push WAS the
		 * drain.  the push is now OPPORTUNISTIC and non-fatal.
		 * Invariant 1 is carried by the post-COMMIT drains below
		 * (alloc buflist, inode clusters via xfs_iflush_cluster, AG
		 * meta, device flush); this only gives xfsaild a head start
		 * on committed-but-unflushed inode items.  With local holders
		 * admitted during the prepass the AG's AIL set need never
		 * reach zero, and an unbounded poll here would park the
		 * ORDERED bast workqueue — every AG's handoff on this mount —
		 * behind one busy AG.  Hard cap mxfs_ag_prepass_push_iters
		 * (10 ms iterations, 0 = skip); the result is not acted on.
		 * The latched entry above skips this whole prepass.
		 */
		extern int mxfs_ag_bast_stall_iters;
		int aerr = xfs_ail_push_ag_sync_bounded(mp->m_ail,
				pag_agno(pag),
				mxfs_ag_bast_stall_iters, 4,
				mxfs_ag_prepass_push_iters);
		if (aerr == -EAGAIN)
			pr_warn_ratelimited("mxfs: P67-AG-BAST-STALL ag=%u — prepass push hit its bound (%d iters); proceeding, post-COMMIT drains carry Invariant 1\n",
				pag_agno(pag), mxfs_ag_prepass_push_iters);
	}
	mxfs_blkdev_flush_epoch(mp);
	ags_pre = ktime_get_ns();

	/*
	 * Phase 2: claim demote slot.  Re-check state — the AIL push above
	 * may have triggered a re-acquire (writeback) that bumped holders
	 * and cleared cached, or cleared cached itself if the re-acquire
	 * also released back to a different state.
	 */
	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	pag->pag_dlm_prepass_done = true;	/* latch armed */
	if (!pag->pag_dlm_armed_ns)
		pag->pag_dlm_armed_ns = ktime_get_ns();	/* 0.22.2 */
	if (pag->pag_dlm_latched) {
		/* the COMMIT was taken during our prepass
		 * (P12-LATCH) — it is done; finish it. */
		mxfs_probe_ratelimited("mxfs: P12-WORK ag=%u LATCHED-PHASE2 latch_ms=%llu\n",
			pag_agno(pag),
			(unsigned long long)((ktime_get_ns() -
				pag->pag_dlm_latch_ns) / NSEC_PER_MSEC));
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		goto committed;
	}
	if (pag->pag_dlm_holders > 0) {
		/*
		 * ARMED, not abandoned.  prepass_done stays set; the
		 * next holders==0 transition — the last-holder unlock or a
		 * would-be re-adopter — takes the COMMIT once the grace is
		 * spent (mxfs_ag_handoff_closing) and re-queues this worker,
		 * which then enters via the LATCHED path above.  Only the
		 * schedule latch is released here.
		 */
		pag->pag_dlm_readopt_pending = false;	/* see bail1 */
		pag->pag_dlm_bast_scheduled = false;
		mxfs_probe_ratelimited(
			"mxfs: P12-WORK ag=%u bail2-holders n=%d readopt=%u page_ms=%u armed=%d\n",
			pag_agno(pag), pag->pag_dlm_holders,
			pag->pag_dlm_readopt_n,
			jiffies_to_msecs(jiffies -
				pag->pag_dlm_bast_pending_since),
			mxfs_ag_handoff_closing(pag) ? 1 : 0);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		return;
	}
	if (!pag->pag_dlm_cached) {
		pag->pag_dlm_readopt_pending = false;	/* defensive */
		pag->pag_dlm_bast_pending = false;
		pag->pag_dlm_bast_scheduled = false;
		pag->pag_dlm_prepass_done = false;
		mxfs_probe_ratelimited(
			"mxfs: P12-WORK ag=%u bail2-uncached (pending consumed)\n",
			pag_agno(pag));
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		return;
	}
	/*
	 * The release COMMIT (mxfs_ag_handoff_commit): cached=false,
	 * bast_pending consumed, strand marker cleared, demoting=true,
	 * and — step 5.1 — the in-core authority epoch/lineage
	 * INVALIDATED in the same pag_dlm_lock critical section that publishes
	 * the decision, so no item formatting between "release decided" and
	 * "grant gone" can stamp an epoch this node is surrendering (such items
	 * stamp class NONE and the recovery side taints/skips them; fail-closed).
	 * the same helper is what the unlock/acquire latch paths run.
	 */
	mxfs_ag_handoff_commit(pag, NULL, NULL);
	mxfs_probe_ratelimited(
		"mxfs: P12-WORK ag=%u COMMIT demoting readopt=%u page_ms=%u\n",
		pag_agno(pag), pag->pag_dlm_readopt_n,
		jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since));
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);
	mxfs_idbg("mxfs: P39-INSTR ag=%u BAST-WORK-PHASE2 cached=true→false demoting=true realns=%llu\n",
		pag_agno(pag),
		(unsigned long long)ktime_get_real_ns());

committed:
	ags_commit = ktime_get_ns();
	/*
	 * from here on this is a CLOSED-WORLD release path — admission
	 * to this AG is shut until mxfs_ag_demote_clear below, so nothing
	 * invoked here may try to re-acquire it.  (The latched entry above
	 * skips the publish pass for exactly that reason.)
	 */

	/*
	 * v0.3.23: SECOND flush AFTER demoting=true is set.  Closes the race
	 * where a fast-path acquire (mxfs_ag_dlm_lock when cached=true) +
	 * modify + unlock_deferred completed entirely in the gap between the
	 * Phase-1 flush and the Phase-2 holders re-check.  In that gap,
	 * holders briefly went 0→1→0; at the Phase-2 check holders==0 is
	 * unchanged, but the trans's modifications are now committed to CIL
	 * and not yet on disk.
	 *
	 * v0.3.24: the original v0.3.23 included
	 * `xfs_ail_push_all_sync` here, but that triggered cross-AG deadlock:
	 * once demoting=true is set, ail_push's writeback can re-call
	 * mxfs_ag_dlm_lock for ANY AG (not just this one) — if the writeback
	 * targets blocks in another AG that the peer holds, the peer's own
	 * bast_work_fn (for the AG WE want) is also stuck in
	 * ail_push_all_sync, deadlocking both nodes for 120s × 3 grant
	 * timeouts.  Empirically observed in iter-1: T1 wedged on
	 * AG=0 wait while T2 wedged on AG=1.
	 *
	 * Plain v0.3.24 (drop ail_push entirely) re-opens priority-2 bnobt
	 * corruption (iter-2: rm/perf_t1 → ltbno+ltlen>bno).  AIL
	 * items not yet xfsaild-pushed sit on disk stale; peer ACQ-FRESH
	 * reads stale.
	 *
	 * v0.3.25: targeted per-AG meta-buffer drain replaces
	 * ail_push.  `mxfs_dlm_ag_drain_meta_buffers(pag)` walks pag_bcache
	 * for AG-meta buf_ops (agf/agfl/agi/bnobt/cntbt/inobt/finobt) with
	 * pending BLI items (b_li_list non-empty), queues them, submits
	 * synchronously.  Bounded by AG-resident bufs; never touches other
	 * AGs' bufs, so cross-AG writeback can't trigger the deadlock.
	 *
	 * Order: log_force(SYNC) drains CIL → AIL (committed BLIs are now
	 * tracked in AIL with up-to-date buf content); drain_meta_buffers
	 * walks our AG's bufs and writes out the dirty ones; blkdev_flush
	 * commits the device cache.  Concurrent acquires are blocked on
	 * demoting=true so the buf content captured here matches what we
	 * will have written when the peer next reads.
	 */
	xfs_log_force(mp, XFS_LOG_SYNC);
	ags_f1 = ktime_get_ns();
	mxfs_ag_bcache_pin_census(pag, &ags_pin1, &ags_ail1);
	/*
	 * v0.3.94: xfs_log_force(SYNC) waits for the log write
	 * to complete, but the CIL → AIL transition happens in xlog_cil
	 * iodone work which runs ASYNCHRONOUSLY.  drain_meta_buffers's
	 * filter requires bli in AIL, so if we run drain before the
	 * async work fires, we miss items just committed by log_force.
	 *
	 * Sleep briefly to let xlog_cil_committed run, then drain.
	 * This is empirical — should be replaced with proper wait
	 * (e.g., capture LSN before log_force, wait for AIL to have
	 * items at that LSN) once the mechanism is identified.
	 */
	/*
	 * v0.3.95: double log_force + targeted ail wait.
	 * First force commits known CIL items.  msleep gives async
	 * completion path time.  Second force catches any items
	 * added in the gap.  Then drain.  Empirically v0.3.94 msleep
	 * was timing-sensitive; this aims to be more robust.
	 */
	/*
	 * v0.3.104: msleep + double force.  Empirical best.
	 */
	/*
	 * 0.75.57: the empirical sleep + second force above were written
	 * (v0.3.94-v0.3.104) for a CIL->AIL insertion the caller could not
	 * observe.  It can: a buffer whose commit has not yet been
	 * checkpointed and inserted is PINNED (xfs_buf_item_unpin runs from
	 * xfs_trans_committed_bulk, after the AIL insertion), and the census
	 * right after the first force reads that directly.  MEASURED on the
	 * 2-node TCP rig (P12-AGREL-STAGES,, 56 releases across
	 * ten peer-truncate laps): pin1=0 in every one, and the sleep +
	 * force cost 4.0-6.0 ms of a 10-15 ms release.  Keep the old path
	 * for the case the census says is real — a pinned buffer after a
	 * SYNC force — and name it when it happens.
	 */
	if (ags_pin1) {
		mxfs_probe_ratelimited("mxfs: P12-AGREL-PINNED ag=%u pinned=%u inail=%u after the first post-COMMIT log force; taking the settle path\n",
			pag_agno(pag), ags_pin1, ags_ail1);
		msleep(3);
		xfs_log_force(mp, XFS_LOG_SYNC);
	}
	ags_f2 = ktime_get_ns();
	mxfs_ag_bcache_pin_census(pag, &ags_pin2, &ags_ail2);

	/*
	 * Phase 2b: drain alloc buflist + convert/drain inode-cluster bufs.
	 * Local acquires now block on pag_dlm_demoting.  These drains are
	 * targeted (per-AG buffer cache walk) and never re-acquire the
	 * AG, so the wait-demote-while-demoting deadlock above does not
	 * apply.
	 *
	 * ORDERING — POINTEE BEFORE POINTER.  These two used to run
	 * AFTER the first drain_meta_buffers.  That published the AGI (the
	 * pointer) and flushed the device before the dinodes it points at (the
	 * pointees) had been written, which is the worst possible order for the
	 * AGI unlinked list: it maximises the window in which the medium holds
	 * an unlinked-list head whose dinode still reads LINKED.  Nothing is
	 * visible to a peer until the final unlock, so for the cooperative
	 * handoff this is not observable — but it is exactly the state a crash
	 * or a forced takeover would leave behind, and the reverse order costs
	 * nothing.  The AGI is now written after the inode buffers, with a
	 * device flush between them, and the second meta drain below still
	 * picks up the AG-meta these drains dirty (the fix).
	 */
	mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
	mxfs_dlm_ag_drain_inode_buffers(pag);
	mxfs_blkdev_flush_epoch(mp);
	mxfs_dlm_ag_drain_meta_buffers(pag);
	mxfs_blkdev_flush_epoch(mp);
	ags_dr1 = ktime_get_ns();

	/*
	 * FIX: re-drain AG-meta AFTER the alloc-buflist + inode-cluster
	 * drains.  Those drains finalise inode allocation (xfs_ialloc_inode_init
	 * etc.), which dirties AG-meta buffers — AGI (agi_unlinked / freecount),
	 * AGF (freeblks), inobt/finobt — AFTER the first drain_meta_buffers above
	 * already ran.  Without a second pass those just-dirtied AG-meta buffers
	 * are left in-core-ahead-of-disk at unlock (P81 REL-NONDURABLE: agf/cntbt
	 * differ from disk at release), so the peer's FUA read at acquire MISSES
	 * them → stale-behind AGI unlinked-list head (P71 in-core=NULLAGINO,
	 * disk=0x84) → xfs_iunlink_remove_inode corruption + shutdown.  A second
	 * meta drain (writes only dirty/in-AIL ones — cheap) closes the window;
	 * the Phase-3 meta_pending wait + triple blkdev_flush below then make it
	 * durable on the shared platter before mxfs_v5_dlm_ag_unlock.
	 */
	xfs_log_force(mp, XFS_LOG_SYNC);
	mxfs_dlm_ag_drain_meta_buffers(pag);
	ags_dr2 = ktime_get_ns();

	/*
	 * Phase 3 (v0.3.55): bounded inline wait for in-flight meta-buffer
	 * writes to complete, then a final blkdev_flush and synchronous
	 * release.  Replaces the defer-to-iodone path because that path
	 * cannot blkdev_issue_flush (xfs-buf workqueue deadlock —
	 * v0.3.26).  bast_work_fn runs on system_wq, not xfs-buf
	 * workqueue, so it can safely flush.
	 *
	 * Cap the wait at 2 seconds — meta_pending counts in-flight bios
	 * for AG-meta bufs registered via mxfs_ag_meta_track; at this
	 * point demoting=true so no NEW writes can be added (CIL flush
	 * already in Phase 1+2).  Any remaining ones are bios already
	 * submitted by xfsaild or the drain in Phase 2.
	 */
	{
		unsigned long	deadline = jiffies + 2 * HZ;
		int		pending;

		while ((pending = atomic_read(&pag->pag_dlm_meta_pending))
		       > 0) {
			if (time_after(jiffies, deadline)) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: AG %u Phase-3 meta_pending=%d "
					"timeout after 2s — forcing release",
					pag_agno(pag), pending);
				/*
				 * INSTRUMENTATION:
				 * meta_pending counts AG-meta buffers logged this
				 * tenure whose write bio has not completed (iodone
				 * not fired).  Under fua_disable=1 a peer's plain
				 * read at acquire hits the SCST write-back cache, so
				 * a buffer whose write bio has NOT been acked is
				 * STALE to the peer -> stale free-space/inode-btree
				 * -> dir-data block double-allocated over a live
				 * inode cluster (imap_to_bp rc=-5 shutdown).  To pick
				 * the fix we must know WHY the count is stuck: are
				 * these buffers (a) in-flight (XBF_WRITE set, bio
				 * submitted, SCST slow under 16-node storm) -> wait
				 * longer; (b) dirty/pinned/in-AIL (never pushed) ->
				 * drain harder; or (c) neither (counter LEAK: tracked
				 * but staled/freed without iodone) -> fix the leak.
				 * Enumerate every AG-meta buffer in the AG cache.
				 */
				{
					struct rhashtable_iter	s5_it;
					struct xfs_buf		*s5_bp;
					unsigned int	s5_write = 0, s5_dirty = 0;
					unsigned int	s5_ail = 0, s5_pin = 0;
					unsigned int	s5_delwri = 0, s5_done = 0;
					unsigned int	s5_total = 0, s5_stale = 0;
					unsigned int	s5_tracked = 0;
					xfs_daddr_t	s5_first = -1;

					rhashtable_walk_enter(
						&pag->pag_bcache.bc_hash, &s5_it);
					do {
						rhashtable_walk_start(&s5_it);
						while ((s5_bp = rhashtable_walk_next(&s5_it))) {
							struct xfs_buf_log_item *s5_bip;
							if (IS_ERR(s5_bp)) {
								if (PTR_ERR(s5_bp) == -EAGAIN)
									continue;
								break;
							}
							if (!mxfs_buf_is_ag_metadata(s5_bp))
								continue;
							s5_total++;
							s5_bip = s5_bp->b_log_item;
							if (s5_bp->b_flags & XBF_WRITE) {
								s5_write++;
								if (s5_first == (xfs_daddr_t)-1)
									s5_first = s5_bp->b_maps[0].bm_bn;
							}
							if (s5_bp->b_flags & XBF_DONE) s5_done++;
							if (s5_bp->b_flags & XBF_STALE) s5_stale++;
							if (atomic_read(&s5_bp->b_mxfs_agmeta_hold) == 1)
								s5_tracked++;
							if (s5_bp->b_flags & _XBF_DELWRI_Q) s5_delwri++;
							if (xfs_buf_ispinned(s5_bp)) s5_pin++;
							if (s5_bip && test_bit(XFS_LI_DIRTY,
								&s5_bip->bli_item.li_flags)) s5_dirty++;
							if (s5_bip && test_bit(XFS_LI_IN_AIL,
								&s5_bip->bli_item.li_flags)) s5_ail++;
						}
						rhashtable_walk_stop(&s5_it);
					} while (s5_bp == ERR_PTR(-EAGAIN));
					rhashtable_walk_exit(&s5_it);

					pr_warn("mxfs: P55-STUCKMETA agno=%u pending=%d agmeta_cached=%u write_inflight=%u dirty=%u inAIL=%u pinned=%u delwri=%u done=%u stale=%u tracked=%u first_write_daddr=%lld\n",
						pag_agno(pag), pending, s5_total,
						s5_write, s5_dirty, s5_ail, s5_pin,
						s5_delwri, s5_done, s5_stale, s5_tracked,
						(long long)s5_first);
				}
				break;
			}
			msleep(1);
		}
	}
	ags_p3 = ktime_get_ns();

	/*
	 * Final block-layer cache flush after the in-flight writes have
	 * completed.  blkdev_issue_flush from system_wq context is safe
	 * (only b_iodone-context flushes deadlock the xfs-buf workqueue).
	 *
	 * v0.3.102: do SECOND blkdev_flush + small sleep + THIRD
	 * blkdev_flush to ensure LIO target's write cache is fully
	 * committed to backing storage.  Single blkdev_flush returns when
	 * target acks SYNCHRONIZE CACHE, but under stress target may
	 * still have writes in-flight to backing platter.
	 */
	mxfs_blkdev_flush_epoch(mp);
	/*
	 * 0.75.60: with FUA reads disabled (mxfs_fua_disable=1, the default)
	 * mxfs_blkdev_flush_epoch issues no SYNCHRONIZE CACHE at all — peers
	 * read the shared target cache, so a completed write is already
	 * visible and there is no platter lag for a second flush to cover.
	 * The 2 ms sleep between the two flushes then guarded nothing and
	 * cost 3.0-5.0 ms per allocation-group release on the 2/tcp rig
	 * (P12-AGREL-STAGES fl, 22 releases).  Keep the settle only when a
	 * real flush is issued.
	 */
	{
		extern int mxfs_fua_disable;

		if (!mxfs_fua_disable) {
			msleep(2);
			mxfs_blkdev_flush_epoch(mp);
		}
	}
	ags_fl = ktime_get_ns();

	/*
	 * P75-INSTR: census of AG free-space btree buffers that are
	 * STILL pinned / in-AIL / dirty at the moment we hand the AG to a peer.
	 * If any bnobt/cntbt buffer is still pinned or in-AIL here, the drain
	 * did NOT fully checkpoint it → it survives to our next re-acquire in a
	 * stale/un-refreshable (pinned) state → the lost-update / inconsistent
	 * on-disk free-space corruption (P70/P74).  Fire only when >0.
	 */
	{
		struct rhashtable_iter	p75_iter;
		struct xfs_buf		*p75_bp;
		unsigned int		p75_pin = 0, p75_ail = 0, p75_dirty = 0;
		unsigned int		p75_bli = 0;	/* P131 sibling: CIL-resident */
		xfs_daddr_t		p75_first = -1;

		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &p75_iter);
		do {
			rhashtable_walk_start(&p75_iter);
			while ((p75_bp = rhashtable_walk_next(&p75_iter))) {
				struct xfs_buf_log_item *p75_bip;
				if (IS_ERR(p75_bp)) {
					if (PTR_ERR(p75_bp) == -EAGAIN)
						continue;
					break;
				}
				if (p75_bp->b_ops != &xfs_bnobt_buf_ops &&
				    p75_bp->b_ops != &xfs_cntbt_buf_ops)
					continue;
				p75_bip = p75_bp->b_log_item;
				if (xfs_buf_ispinned(p75_bp)) p75_pin++;
				if (p75_bip && test_bit(XFS_LI_IN_AIL,
						&p75_bip->bli_item.li_flags)) p75_ail++;
				if (p75_bip && test_bit(XFS_LI_DIRTY,
						&p75_bip->bli_item.li_flags)) p75_dirty++;
				/* 8ba7ae5c: CIL-resident window — bli
				 * attached (or li_list non-empty) but not yet
				 * in-AIL: committed state the drain's in-AIL
				 * filter can't see.  Handing the AG to a peer
				 * in this state = un-destaged alloc invisible
				 * to every existing release check. */
				if ((p75_bip && !test_bit(XFS_LI_IN_AIL,
						&p75_bip->bli_item.li_flags)) ||
				    (!p75_bip && !list_empty_careful(
						&p75_bp->b_li_list)))
					p75_bli++;
				if ((xfs_buf_ispinned(p75_bp) ||
				     (p75_bip && test_bit(XFS_LI_IN_AIL,
						&p75_bip->bli_item.li_flags))) &&
				    p75_first == (xfs_daddr_t)-1)
					p75_first = p75_bp->b_maps[0].bm_bn;
			}
			rhashtable_walk_stop(&p75_iter);
		} while (p75_bp == ERR_PTR(-EAGAIN));
		rhashtable_walk_exit(&p75_iter);

		if (p75_pin || p75_ail || p75_dirty || p75_bli)
			mxfs_probe("mxfs: P75-INSTR REL-LEFT-DIRTY agno=%u bno/cnt pinned=%u inAIL=%u dirty=%u cil_resident=%u first_daddr=%lld realns=%llu\n",
				pag_agno(pag), p75_pin, p75_ail, p75_dirty,
				p75_bli, (long long)p75_first,
				(unsigned long long)ktime_get_real_ns());
	}

	/*
	 * the P81 release-time FUA-readback + force-write was REMOVED —
	 * it did a FUA read (and possible xfs_bwrite) for every cached AG-meta
	 * buffer at EVERY AG release, which made releases so slow that a peer's
	 * disk-lock acquisition timed out after 120s ("another node may be
	 * holding the lock") → cluster grant-stall.  The real root fix is
	 * gen-stamp-on-fresh-read (pal/linux/xfs_buf.c mxfs_buf_read_fua): a
	 * freshly-FUA-read AG-meta buffer is stamped gen-current so the read-hook
	 * no longer reverts this node's own authoritative content.  Release
	 * durability is provided by the existing drain + double blkdev_issue_flush
	 * above.
	 */
	/*
	 * P90 (gen-bump-on-release) was TESTED here and REVERTED: it
	 * made the bnobt clobber WORSE (disk_differs=1 writes 6-20 → 24-60),
	 * not better.  More forced FUA re-reads → MORE hits of the read-vs-
	 * destage window where a peer's V1 is not yet on the platter → the
	 * FUA-read returns V0.  This PROVED the root is the read-vs-destage
	 * race (peer's V1 not platter-durable when the next node FUA-reads),
	 * NOT a stale-cache that more refreshes would fix.  Fix must be on the
	 * RELEASE side: guarantee V1 is destaged before unlock on EVERY peer
	 * release path (check the lighter L4169-4182 drain_alloc_buflist+unlock
	 * path skips the meta drain/flush).
	 */
	pag->pag_dlm_lineage_open = false;	/* P130: sanctioned release */
	if (unlikely(mxfs_ag_strand_inject_hit(pag_agno(pag), "bast_work_fn"))) {
		atomic64_inc(&mxfs_dlm_stat_ag_release);
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		pag->pag_dlm_release_pending = false;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);
		return;
	}
	/* v5: iunlink records are tenure-scoped — purge before the
	 * grant leaves us (drain above has made them durably home). */
	mxfs_iunl_store_purge_ag(pag_mount(pag), pag_agno(pag), "bast-inline");
	/*
	 * P86/P87: what will the acquirer see? Read it the way they
	 * will, repair what is ours to repair, and refuse to publish a split we
	 * could not fix.  Invariant 1: never unlock undrained.
	 */
	mxfs_ag_release_publish_gate(pag, "bast-inline");
	mxfs_agifc_release_audit(pag, "bast-inline");
	/*
	 * (design-consult ruling): CLEAN-RELEASE MARKER.  The COMMIT above
	 * (mxfs_ag_handoff_commit — here or on the latch path) detached the
	 * grant and invalidated in-core authority, the Phase-2 drains and
	 * flushes above landed every image this tenure logged, and no arm
	 * between here and the CAS keeps the tenure.  Publish the
	 * XFS_LI_MXFS_RELMARK for {AG, epoch, lineage} and force it durable
	 * BEFORE the CAS clears our holder bit.  A failure other than "no
	 * identity" is logged and the unlock proceeds: the only realistic
	 * cause is a shutdown, and holding the AG against the peer would
	 * convert one node's quarantine-risk into a cluster-wide grant stall.
	 */
	ags_gate = ktime_get_ns();
	mxfs_ag_relmark_before_unlock(pag, "ag-bast");
	us = mxfs_v5_dlm_ag_unlock(dlm, pag_agno(pag));
	atomic64_inc(&mxfs_dlm_stat_ag_release);
	ags_unlk = ktime_get_ns();
	{
		/* 0.75.55: every field is that stage's own duration in us;
		 * pin1/ail1 are read right after the first post-COMMIT log
		 * force, pin2/ail2 after the 3 ms sleep and the second force. */
		static atomic_t p12s_n = ATOMIC_INIT(0);
#define AGS_D(a, b) ((unsigned long long)(((a) && (b) && (b) >= (a)) ? ((b) - (a)) / 1000 : 0))
		if (atomic_inc_return(&p12s_n) <= 4000)
			mxfs_probe("mxfs: P12-AGREL-STAGES ag=%u pre=%llu commit=%llu f1=%llu pin1=%u ail1=%u f2=%llu pin2=%u ail2=%u dr1=%llu dr2=%llu p3=%llu fl=%llu gate=%llu unlk=%llu total=%llu us=%d realns=%llu\n",
				pag_agno(pag),
				AGS_D(ags_enter, ags_pre),
				AGS_D(ags_pre ? ags_pre : ags_enter, ags_commit),
				AGS_D(ags_commit, ags_f1), ags_pin1, ags_ail1,
				AGS_D(ags_f1, ags_f2), ags_pin2, ags_ail2,
				AGS_D(ags_f2, ags_dr1),
				AGS_D(ags_dr1, ags_dr2),
				AGS_D(ags_dr2, ags_p3),
				AGS_D(ags_p3, ags_fl),
				AGS_D(ags_fl, ags_gate),
				AGS_D(ags_gate, ags_unlk),
				AGS_D(ags_enter, ags_unlk),
				(int)us,
				(unsigned long long)ktime_get_real_ns());
#undef AGS_D
	}

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("P10-INSTR realns=%llu slot=%d agno=%u REL-INLINE-V55 us=%d\n",
			(unsigned long long)ktime_get_real_ns(),
			mxfs_v5_dlm_get_node_slot(dlm), pag_agno(pag), us);

	/*
	 * D-488 birth fix (ruling): the unlock outcome decides what
	 * the in-core state may become.  Before this, every outcome fell
	 * through to "demote complete" — an unlock that never cleared the
	 * platter bit stranded it with no in-core tenure, and no peer BAST
	 * could ever schedule the release again (the silent-orphan birth).
	 */
	if (us == MXFS_UNLOCK_UNKNOWN) {
		/* The wrapper's own read-back failed.  One slot read per
		 * second, bounded: almost any transient transport error
		 * resolves here; only a persistently unreadable slot
		 * quarantines below. */
		int vtry;

		for (vtry = 0; vtry < 10 && us == MXFS_UNLOCK_UNKNOWN;
		     vtry++) {
			int held;

			msleep(1000);
			held = mxfs_v5_dlm_ag_held(dlm, pag_agno(pag));
			if (held == 1)
				us = MXFS_UNLOCK_STILL_HELD;
			else if (held == 0)
				us = MXFS_UNLOCK_RELEASED;
		}
		mxfs_probe("mxfs: P275-AGUNLK-REVERIFY ag=%u tries=%d state=%d\n",
			pag_agno(pag), vtry, us);
	}

	switch (us) {
	case MXFS_UNLOCK_RELEASED: {
		/*
		 * handoff accounting (the ruling's acceptance numbers):
		 * b2c = BAST rx -> COMMIT (grace + drain of admitted holders +
		 * worker/latch latency), c2r = COMMIT -> on-disk release (the
		 * drains/publication/flush/CAW unlock).  Sums, maxima and >50 /
		 * >500 ms buckets land in the DLM stats line; P12-HANDOFF
		 * samples individual releases (ratelimited).
		 */
		u64 now = ktime_get_ns();
		s64 b2c = -1, c2r = -1;
		s64 r2e = -1, e2a = -1, a2c = -1, q = -1, wq = -1;
		int rxh = -1;
		u32 readopt;

		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		if (pag->pag_dlm_latch_ns) {
			u64 rx = pag->pag_dlm_bast_rx_ns;
			u64 qu = READ_ONCE(pag->pag_dlm_queued_ns);
			u64 en = pag->pag_dlm_work_enter_ns;
			u64 ar = pag->pag_dlm_armed_ns;
			u64 lt = pag->pag_dlm_latch_ns;

			c2r = (s64)((now - lt) / NSEC_PER_MSEC);
			if (rx && lt >= rx)
				b2c = (s64)((lt - rx) / NSEC_PER_MSEC);
			/* 0.22.2/0.22.3: where the BAST->COMMIT time went */
			if (rx && en >= rx)
				r2e = (s64)((en - rx) / NSEC_PER_MSEC);
			if (rx && qu >= rx)
				q = (s64)((qu - rx) / NSEC_PER_MSEC);
			if (qu && en >= qu)
				wq = (s64)((en - qu) / NSEC_PER_MSEC);
			if (en && ar >= en)
				e2a = (s64)((ar - en) / NSEC_PER_MSEC);
			if (ar && lt >= ar)
				a2c = (s64)((lt - ar) / NSEC_PER_MSEC);
			rxh = pag->pag_dlm_rx_holders;
		}
		readopt = pag->pag_dlm_readopt_n;
		pag->pag_dlm_latch_ns = 0;
		pag->pag_dlm_work_enter_ns = 0;
		pag->pag_dlm_armed_ns = 0;
		WRITE_ONCE(pag->pag_dlm_queued_ns, 0);
		mxfs_ag_demote_clear(pag);
		pag->pag_dlm_release_pending = false;
		/*
		 * 0.22.2: the revocation is HONORED — the grant left
		 * this node on the platter above.  A BAST that arrived during
		 * the post-COMMIT drains re-set bast_pending (rx does not
		 * schedule: holders==0 && !cached) and nothing consumed it, so
		 * the flag outlived the tenure: the next fresh acquire's first
		 * last-holder unlock saw a stale pending BAST (page_ms in the
		 * tens of seconds with ZERO rx lines in the window — measured
		 * test12 ag=5 b2c_ms=46449 at 25 AGs lap 2) and the worker
		 * committed a SPURIOUS release of a grant nobody was waiting
		 * for, and the stale rx/since stamps made every grace/cap
		 * decision of the next generation read as already spent.
		 */
		pag->pag_dlm_bast_pending = false;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);

		if (c2r >= 0) {
			atomic64_inc(&mxfs_dlm_stat_handoff_n);
			atomic64_add(c2r, &mxfs_dlm_stat_handoff_c2r_ms);
			mxfs_stat_max64(&mxfs_dlm_stat_handoff_c2r_max, c2r);
			if (c2r > 50)
				atomic64_inc(&mxfs_dlm_stat_handoff_c2r_gt50);
			if (c2r > 500)
				atomic64_inc(&mxfs_dlm_stat_handoff_c2r_gt500);
			if (b2c >= 0) {
				atomic64_add(b2c, &mxfs_dlm_stat_handoff_b2c_ms);
				mxfs_stat_max64(&mxfs_dlm_stat_handoff_b2c_max, b2c);
				if (b2c > 50)
					atomic64_inc(&mxfs_dlm_stat_handoff_b2c_gt50);
				if (b2c > 500)
					atomic64_inc(&mxfs_dlm_stat_handoff_b2c_gt500);
			}
			if (q > 500)
				atomic64_inc(&mxfs_dlm_stat_handoff_q_gt500);
			if (wq > 500)
				atomic64_inc(&mxfs_dlm_stat_handoff_wq_gt500);
			if (e2a > 500)
				atomic64_inc(&mxfs_dlm_stat_handoff_e2a_gt500);
			if (a2c > 500)
				atomic64_inc(&mxfs_dlm_stat_handoff_a2c_gt500);
			mxfs_stat_max64(&mxfs_dlm_stat_handoff_q_max, q);
			mxfs_stat_max64(&mxfs_dlm_stat_handoff_wq_max, wq);
			mxfs_stat_max64(&mxfs_dlm_stat_handoff_e2a_max, e2a);
			mxfs_stat_max64(&mxfs_dlm_stat_handoff_a2c_max, a2c);
			if (rxh > 0)
				atomic64_inc(&mxfs_dlm_stat_handoff_rxheld);
			/* tail events are rare and are the whole point: never
			 * let the shared ratelimit bucket swallow them */
			if (b2c > 1000)
				mxfs_probe("mxfs: P12-HANDOFF-TAIL ag=%u b2c_ms=%lld c2r_ms=%lld readopt=%u rxh=%d q=%lld wq=%lld r2e=%lld e2a=%lld a2c=%lld\n",
					pag_agno(pag), (long long)b2c, (long long)c2r,
					readopt, rxh, (long long)q, (long long)wq,
					(long long)r2e, (long long)e2a, (long long)a2c);
			else
				mxfs_probe_ratelimited("mxfs: P12-HANDOFF ag=%u b2c_ms=%lld c2r_ms=%lld readopt=%u rxh=%d q=%lld wq=%lld r2e=%lld e2a=%lld a2c=%lld\n",
					pag_agno(pag), (long long)b2c, (long long)c2r,
					readopt, rxh, (long long)q, (long long)wq,
					(long long)r2e, (long long)e2a, (long long)a2c);
		}
		break;
	}

	case MXFS_UNLOCK_STILL_HELD: {
		/*
		 * The bit is provably still ours: the grant never left this
		 * node, but the COMMIT above already invalidated the epoch.
		 * Re-arm tenure through the real acquire path.  the
		 * acquire attests our published epoch (now 0) down to the
		 * CAW already-held path, which refuses to reaffirm on it and
		 * instead CASes a fresh READOPT mint (P294-READOPT-MINT,
		 * Enew != the surrendered epoch — ruling; before
		 * this comment claimed a mint that did NOT exist and
		 * the re-arm silently republished the surrendered epoch).
		 * Then unlock back to cached.  bast_pending is re-set first
		 * so the last-holder unlock transition reschedules this
		 * worker: the release retries on a bounded cadence instead
		 * of stranding.
		 */
		int lrc;

		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		pag->pag_dlm_release_pending = false;
		pag->pag_dlm_bast_pending = true;	/* COMMIT cleared it */
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);

		lrc = mxfs_ag_dlm_lock(mp, pag);
		if (lrc == 0) {
			mxfs_probe("mxfs: P275-AGUNLK-REARM ag=%u — unlock left bit set, tenure re-minted, release will retry\n",
				pag_agno(pag));
			mxfs_ag_dlm_unlock(mp, pag);
		} else {
			/* Re-acquire refused: no epoch, no cached flag.  The
			 * rx readopt path is the backstop; requeue ourselves
			 * so the retry does not depend on the next BAST. */
			mxfs_probe("mxfs: P275-AGUNLK-REARM-FAIL ag=%u rc=%d — bit still set on platter with no in-core tenure, requeueing\n",
				pag_agno(pag), lrc);
			mxfs_ag_bast_queue(mp, pag);
		}
		break;
	}

	case MXFS_UNLOCK_UNKNOWN:
	default:
		/*
		 * Outcome unprovable after bounded re-verify: quarantine.
		 * demoting stays set (local acquires keep blocking on
		 * pag_dlm_demote_wq → no metadata authority can be issued
		 * on an AG whose platter state is unknown), release_pending
		 * marks the quarantine for unmount/force-release, and no
		 * waiter is woken.  The rx-side watchdog keeps this loud.
		 */
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		pag->pag_dlm_release_pending = true;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		pr_warn("mxfs: P275-AGUNLK-QUARANTINE ag=%u — unlock outcome UNPROVABLE after re-verify; AG quarantined (demoting held, acquires blocked)\n",
			pag_agno(pag));
		break;
	}
	(void)do_release;
}

/*
 * how many buffer submissions this mount has made so far, read from
 * the departure accounting.  The unmount release uses the difference across
 * its drains to decide whether a device flush is owed before the unlock: a
 * drain that wrote nothing has nothing to make durable, and a flush per AG
 * on every unmount would be paid for nothing.  A mount without accounting
 * (never clustered) returns false so the caller flushes unconditionally.
 */
static bool
mxfs_depart_submitted(
	struct xfs_mount	*mp,
	unsigned long		*n)
{
	struct mxfs_depart_acct	*acct = mp->m_mxfs_acct;

	if (!acct)
		return false;
	spin_lock(&acct->lock);
	*n = acct->submitted;
	spin_unlock(&acct->lock);
	return true;
}

/*
 * Called at unmount to flush state and release any AG that is still in
 * cached state.  After this returns, no work is pending, and the v5 DLM
 * layer is free to tear down.
 *
 * (D-0483): every unlock below is preceded by the same drain pipeline
 * the cooperative release runs — alloc buflist, inode clusters, AG metadata,
 * device flush — which architectural invariant 1 requires of any on-disk
 * unlock and which this path had skipped eight ninths of since it was
 * written.  put_super now quiesces the whole mount before calling here, so
 * the drains are expected to find nothing; ags_drained on the summary line
 * says how often they did, and a nonzero there means the quiesce above left
 * something behind and is worth reading before anything else.
 */
void
mxfs_dlm_ag_force_release_all(
	struct xfs_mount	*mp)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	struct xfs_perag	*pag = NULL;
	/*
	 * the coverage denominators for this path.  Both the release
	 * and the platter audit below sit inside `if (release_now)`, which
	 * needs pag_dlm_cached || pag_dlm_latched — so an AG handed off
	 * cooperatively before unmount is neither released nor audited here.
	 * Nothing counted that subset, which meant a clean audit at unmount
	 * could not be distinguished from an audit that never examined an AG.
	 */
	int			ags_seen = 0, ags_released = 0;
	int			ags_drained = 0;		/* */

	if (!dlm)
		return;

	/*
	 * PHASE 1: drain every AG while every grant is still held.
	 * Pointee before pointer: the fresh cluster buffers and the
	 * inode clusters first, then the AG metadata that points at them.  The
	 * drains only count what they wrote; nothing is published yet.
	 */
	while ((pag = xfs_perag_next(mp, pag))) {
		unsigned long sub0 = 0, sub1 = 0;
		bool tracked;

		ags_seen++;

		cancel_work_sync(&pag->pag_dlm_bast_work);
		cancel_work_sync(&pag->pag_dlm_release_work);	/* */

		tracked = mxfs_depart_submitted(mp, &sub0);
		mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
		mxfs_dlm_ag_drain_inode_buffers(pag);
		mxfs_dlm_ag_drain_meta_buffers(pag);
		if (!tracked || (mxfs_depart_submitted(mp, &sub1) && sub1 != sub0)) {
			ags_drained++;
			mxfs_probe("mxfs: P485-UMOUNT-DRAIN ag=%u wrote=%lu — the unmount release drain found and wrote buffers the put_super quiesce had left behind\n",
				pag_agno(pag), tracked ? sub1 - sub0 : 0UL);
		}
	}

	/*
	 * The second metadata pass after a log force — the alloc-buflist
	 * drains finalise inode allocation, which dirties the AGI/inobt they
	 * point at — then ONE device flush for the whole unmount, so that every
	 * write above, whether from these drains or from put_super's quiesce,
	 * has reached the platter before the first grant is published.  A
	 * flush per AG would cost the same guarantee sixty-four times over.
	 */
	xfs_log_force(mp, XFS_LOG_SYNC);
	while ((pag = xfs_perag_next(mp, pag)))
		mxfs_dlm_ag_drain_meta_buffers(pag);
	mxfs_blkdev_flush_epoch(mp);

	/*
	 * 0.87.14 (D-...-0924): the quiescent conservation check, PER AG.
	 * Every AG-metadata buffer this mount logged took a track hold and a
	 * per-AG pending count, and by here — producers stopped, log forced,
	 * every AG drained, device flushed — every one of them has completed
	 * or been retired, so every AG's pending count must read zero.  The
	 * module-wide counters (agmeta_acquires == returns_iodone +
	 * returns_reclaim) can balance while one AG is over and another under;
	 * only the per-AG counts can say which AG a stranded token pins.  A
	 * non-zero count here IS the leak the record describes, named at the
	 * one moment it can still be attributed to this mount.
	 */
	{
		int	agm_total = 0, agm_ags = 0;

		while ((pag = xfs_perag_next(mp, pag))) {
			int p = atomic_read(&pag->pag_dlm_meta_pending);

			if (p) {
				agm_ags++;
				agm_total += p;
				mxfs_probe("mxfs: P-AGMETA-PENDING-AT-UNMOUNT ag=%u pending=%d — an AG-meta track hold was never returned on this mount (buffer pinned for the module's life)\n",
					pag_agno(pag), p);
			}
		}
		mxfs_probe("mxfs: P-AGMETA-UNMOUNT-CENSUS ags=%d nonzero_ags=%d pending_total=%d\n",
			ags_seen, agm_ags, agm_total);
	}

	/*
	 * PHASE 2: publish.  Nothing on this mount may submit a buffer for any
	 * AG from here on — every producer is stopped, the SB summary is sealed
	 * and the inodegc queue is disabled — and the departure accounting
	 * counts anything that does anyway.
	 */
	while ((pag = xfs_perag_next(mp, pag))) {
		bool release_now = false;
		xfs_agnumber_t agno = pag_agno(pag);

		/* a BAST that landed between the phases queued new work */
		cancel_work_sync(&pag->pag_dlm_bast_work);
		cancel_work_sync(&pag->pag_dlm_release_work);

		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		/* a latched COMMIT whose worker was cancelled above
		 * still owns the on-disk grant — release it here too. */
		if (pag->pag_dlm_cached || pag->pag_dlm_latched) {
			pag->pag_dlm_cached = false;
			pag->pag_dlm_latched = false;
			pag->pag_dlm_prepass_done = false;
			pag->pag_dlm_bast_pending = false;
			pag->pag_dlm_bast_scheduled = false;
			pag->pag_dlm_release_pending = false;
			pag->pag_dlm_readopt_pending = false;	/* */
			/* step 5.1: unmount is a release-commit point
			 * too — invalidate in-core authority before the
			 * unlock below makes the grant transferable. */
			WRITE_ONCE(pag->pag_mxfs_grant_epoch, 0);
			WRITE_ONCE(pag->pag_mxfs_grant_lineage, 0);
			pag->pag_mxfs_grant_single = false;	/* (D-0353) */
			release_now = true;
		}
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);

		if (release_now) {
			enum mxfs_unlock_state us;

			pag->pag_dlm_lineage_open = false;	/* P130 */
			ags_released++;				/* */
			mxfs_iunl_store_purge_ag(mp, agno, "unmount");
			mxfs_agifc_release_audit(pag, "unmount");
			mxfs_pubob_unlock_census(pag, "unmount");
			us = mxfs_v5_dlm_ag_unlock(dlm, agno);
			if (us == MXFS_UNLOCK_STILL_HELD &&
			    mxfs_v5_dlm_is_poisoned(dlm)) {
				/* (D-0357): intended — the grant is
				 * manifest evidence for the survivor's replay of
				 * our WITHDRAWN slice; the v5 gate logged P306. */
			} else if (us != MXFS_UNLOCK_RELEASED)
				pr_warn("mxfs: P275-AGUNLK-UNMOUNT-NOTREL ag=%u state=%d — unmount release did not prove the bit clear; a dead-looking holder bit may survive this unmount\n",
					agno, us);
			atomic64_inc(&mxfs_dlm_stat_ag_release);

			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe("P10-INSTR realns=%llu slot=%d agno=%u REL-UNMOUNT\n",
					(unsigned long long)ktime_get_real_ns(),
					mxfs_v5_dlm_get_node_slot(dlm), agno);
		}

		/*
		 * Wake anyone still blocked on a demote wait.  cancel_work_sync
		 * above guarantees bast_work_fn has finished, so any leftover
		 * demoting=true is from a deferred release whose iodone may or
		 * may not have fired.  Force-clear so unmount can proceed.
		 */
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);
	}

	/*
	 * one line per unmount, not per AG.  `released` is how many
	 * AGs this path actually unlocked, and it is the population the
	 * platter audit could even look at — every other AG was handed off
	 * cooperatively earlier and is not covered here.  Read it together
	 * with the audit coverage line that follows: a RELEASE-MISMATCH count
	 * of zero says nothing unless `released` and the audit's `ran` are
	 * both non-zero.
	 */
	mxfs_probe("mxfs: P482-UMOUNT-AGREL ags_seen=%d ags_released=%d ags_drained=%d — AGs still held at put_super and unlocked here; the rest were released cooperatively and are NOT covered by the unmount audit; ags_drained is how many the release drains still found dirty after the quiesce\n",
		ags_seen, ags_released, ags_drained);
	mxfs_agifc_audit_coverage("unmount");
}
