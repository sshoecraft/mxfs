// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- durability: block-device flush epochs, AIL drains, inode cluster and directory inode durability
 */
#define MXFS_TU_ID 7	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * device flush + platter-coherence epoch advance.
 * Every mxfs coordination flush of the shared LUN routes through here so
 * m_mxfs_flush_epoch counts "platter caught up" events: a buffer whose last
 * write completed in the CURRENT epoch may still be ahead of the platter
 * (LIO drops FUA - bio completion means target write cache) and must never
 * be regressed from a platter/FUA read (xfs_iread_bmbt_block P34B guard);
 * after any flush here the platter is >= that write and platter-based
 * refresh is safe again.
 */
int
mxfs_blkdev_flush_epoch(struct xfs_mount *mp)
{
	extern int mxfs_fua_disable;
	int rc = 0;

	/*
	 *  (instrumented, dir_reuse@8/tcp P68-EVDECIDE
	 * undurable=1 b_epoch==cur_mep starvation): with FUA reads DISABLED
	 * (mxfs_fua_disable=1, default since) every peer read is a
	 * PLAIN read served from the shared target cache, so a buffer whose
	 * write has COMPLETED is already re-readable by every node — no
	 * platter lag exists for the epoch to certify against.  Advance the
	 * epoch without paying a SYNCHRONIZE CACHE (measured 2-30ms each on
	 * flush-honoring targets; the per-modify caller made it the dominant
	 * metadata-op cost and starving it froze the epoch clock, which
	 * turned EVERY refresh-evict into an undurable-skip -> stale-base
	 * RMW).  With FUA reads active the platter is the coherence point
	 * and the real flush stays.
	 */
	if (!mxfs_fua_disable)
		rc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	if (!rc)
		atomic64_inc(&mp->m_mxfs_flush_epoch);
	return rc;
}

/*
 * (design review item 1): the DURABILITY form of the above.
 *
 * mxfs_blkdev_flush_epoch()'s fua_disable fast path is a COHERENCY
 * argument — with plain reads served from the shared target cache a
 * completed write is already peer-visible, so no platter lag exists for
 * the epoch to certify against — plus a per-metadata-op COST argument
 * (2-30 ms each, measured as the dominant metadata-op cost).
 *
 * Neither argument covers a caller that needs the data to survive a
 * TARGET power loss.  The mount recovery barrier publishes "this slice
 * is recovered" by zeroing the dead node's heartbeat record and purging
 * its CAW authority bits: if the recovered buffer images are still only
 * in the target's write cache when the target loses power, both the
 * recovery AND the manifest that would have caused it to be re-done are
 * gone, and the slice is silently lost.  The cost argument does not
 * apply either — this runs once per mount, not once per modify.
 *
 * So this form ALWAYS issues the flush, regardless of mxfs_fua_disable,
 * and reports failure to the caller.  The epoch is advanced only on
 * success: a failed flush certifies nothing.
 */
int
mxfs_blkdev_flush_durable(struct xfs_mount *mp)
{
	int rc;

	if (!mp || !mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return -EINVAL;

	rc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	/*
	 * Write-through devices with no volatile cache answer -EINVAL;
	 * their data is durable on completion (same normalisation
	 * mxfs_pal_bdev_flush applies).
	 */
	if (rc == -EINVAL)
		rc = 0;
	if (!rc)
		atomic64_inc(&mp->m_mxfs_flush_epoch);
	else
		xfs_alert(mp,
			"MXFS P228-FLUSH-DURABLE-FAIL rc=%d — a cache flush "
			"of the shared device FAILED; recovery output cannot "
			"be certified durable", rc);
	return rc;
}

/*
 *  coalesced background destage kick (see xfs_mount.h
 * field comment).  One SYNC log force + a full (async) AIL push per debounce
 * window destages every recently freed/created inode cluster within ~ms,
 * replacing the per-unlink eager force+drain+flush (ifree_eager_durable=0)
 * without reopening the reuse-convergence stalls (VISNUDGE 55s spins,
 * dir_reuse reload livelock, uv-create barrier timeouts) that pure-lazy
 * xfsaild pacing produced.  xfs_ail_push_all is non-blocking (xfsaild does
 * the writes) — no whole-AIL *sync* wait, so none of the /
 * cross-AG deadlock shapes apply.
 */
void
mxfs_destage_kick_fn(struct work_struct *work)
{
	struct xfs_mount *mp = container_of(to_delayed_work(work),
				struct xfs_mount, m_mxfs_destage_kick);

	if (xfs_is_shutdown(mp))
		return;
	/* Async force: start the CIL push without waiting for iclog IO —
	 * the following push_all catches whatever has landed, and the next
	 * kick (storms refire every debounce window) sweeps stragglers.
	 * A SYNC force here at 2ms cadence taxed the slowest node's own
	 * commit stream ~15% (ds node1 rate 47/s vs floor 50). */
	xfs_log_force(mp, 0);
	if (mp->m_ail)
		xfs_ail_push_all(mp->m_ail);
}
EXPORT_SYMBOL(mxfs_destage_kick_fn);

void
mxfs_destage_kick(struct xfs_mount *mp)
{
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	/* queue (not mod): a pending timer keeps its deadline, so a storm
	 * coalesces into one firing per ~10ms instead of starving the kick.
	 * Convergence consumers (VISNUDGE/iget-retry) only need sub-second
	 * destage; 10ms + async force keeps the tax on the workload's own
	 * commit stream negligible. */
	queue_delayed_work(system_unbound_wq, &mp->m_mxfs_destage_kick,
			   msecs_to_jiffies(10));
}
EXPORT_SYMBOL(mxfs_destage_kick);

/*
 * TARGETED inode-cluster drain for the BAST release path.
 *
 * Replaces the whole-AG xfs_ail_push_ag_sync(AG(ip)) that bast_process used
 * to honor invariant #1 (flush ip's dirty metadata before releasing ip's
 * on-disk DLM lock).  The whole-AG drain DEADLOCKS under the NEWARCH
 * chokepoint: every -EDEADLK upgrade now routes through bast_process, and a
 * SIBLING inode in the same AG can be ILOCK-EXCL-held by the very thread that
 * is blocked in mxfs_dlm_ilock_begin waiting for THIS drain (e.g. xfs_remove
 * → xfs_lock_two_inodes locked the lower inode, then -EDEADLK'd on the
 * higher one).  xfs_iflush_cluster (xfs_inode.c) skips inodes it cannot
 * xfs_ilock_nowait(SHARED), so that sibling's AIL item never drains → the
 * whole-AG wait spins forever (P67-INSTR AG-AIL-STALL).
 *
 * Invariant #1 only requires IP's OWN metadata durable before releasing IP's
 * lock — siblings carry their own DLM locks and flush when those release.
 * IP's own ILOCK is FREE in the chokepoint path (the waiting thread blocks in
 * mxfs_dlm_ilock_begin BEFORE taking ip's local ILOCK), so xfsaild can flush
 * ip even while skipping the ILOCK-held sibling.  We therefore wait ONLY for
 * ip's own inode log item to leave the AIL.  XFS_LI_IN_AIL is cleared by
 * xfs_iflush_done on block-device IO completion, so !in_ail satisfies
 * invariant #1.
 *
 * Caller MUST have already done a settle (xfs_log_force(SYNC) + msleep +
 * xfs_log_force(SYNC)) so the async CIL→AIL insertion has happened — without
 * it a premature !in_ail would break early and release before ip is flushed
 * (the Mode A async-AIL-add race).
 *
 * Validated by design review (design-consult): cluster-buffer write is safe (the
 * in-core buffer holds the last-flushed content for skipped siblings, never a
 * torn/uncommitted sibling dinode); no bounded abort (the chokepoint caller
 * waits uninterruptibly and we are bound by invariant #1 not to release
 * without a completed drain — forward progress on ip is deterministic once
 * the inversion is broken).
 */
/*
 * Core drain loop.  deadline_ns==0 => unbounded (original behavior, invariant #1
 * forward-progress contract).  deadline_ns!=0 => bounded: return false if the
 * deadline elapses before the inode item is durable (caller must have an
 * alternate durability guarantee — see mxfs_ail_drain_inode_sync_bounded).
 * Returns true once the inode item is checkpointed AND written home.
 */
static bool
mxfs_ail_drain_inode_to(struct xfs_inode *ip, u64 deadline_ns)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_ail		*ailp = mp->m_ail;
	unsigned int		iter = 0;

	bool			redrained = false;
	bool			redrained2 = false;	/* P136 rescue fired */

	/*
	 * PASSIVE drain (machine stays UP; soft wedge is debuggable)
	 * + lock-HOLDER capture.  An ACTIVE flush from this BAST kworker
	 * (force-unlock, or xfs_imap_to_bp+xfs_bwrite) HARD-HANGS
	 * the node — design review (design consult) confirms: xfs_bwrite on a buffer still
	 * carrying _XBF_DELWRI_Q (linked into xfsaild's delwri list) corrupts XFS
	 * buffer-list invariants -> fatal; calling drain_alloc_buflist
	 * (xfs_buf_delwri_submit) in the loop compounds it.  So we DO NOT touch
	 * the buffer actively here.  Instead we wait passively and, when wedged,
	 * print b_lock_ip — the return address of whoever locked ip's cluster
	 * buffer and never relse'd it.  That names the leak site in ONE repro;
	 * the fix is a missing xfs_buf_relse at that caller.
	 */
	for (;;) {
		struct xfs_inode_log_item *iip = ip->i_itemp;
		bool			in_ail = false;
		struct xfs_buf		*held_lbp = NULL;

		if (iip) {
			spin_lock(&ailp->ail_lock);
			in_ail = test_bit(XFS_LI_IN_AIL,
					  &iip->ili_item.li_flags);
			/*
			 * P136: capture the li_buf reference under
			 * ail_lock while the item still pins it, so the
			 * rescue below can operate on it race-free.
			 */
			if (in_ail && iter >= 512 && !redrained2 &&
			    iip->ili_item.li_buf) {
				held_lbp = iip->ili_item.li_buf;
				xfs_buf_hold(held_lbp);
			}
			spin_unlock(&ailp->ail_lock);
		}
		/*
		 * v0.5.6: ALSO require pincount==0 — a pinned inode item is
		 * committed to the CIL but not yet checkpointed; its AIL
		 * insertion (xfs_trans_committed_bulk) happens BEFORE the
		 * iop_unpin that drops the pin, so pin==0 && !in_ail is a
		 * deterministic "checkpointed AND written home".  This closes
		 * the async CIL→AIL race INSIDE the drain itself,
		 * making the callers' blind settle sleeps (msleep(10)/(20))
		 * unnecessary — P137/P138 timing proved those sleeps were
		 * ~80% of the per-unlink and per-BAST-release cost.
		 */
		if (!in_ail && xfs_ipincount(ip) == 0)
			return true;

		/* P2D-DRAINWHY: the P138 stage bisect shows a
		 * release drain costs ~7ms even for inodes the entry predicate
		 * called CLEAN — fire once per looping drain (after the first
		 * sleep) with the exact blocking state so the payer is named:
		 * in_ail vs pinned, which ili_fields, IFLUSHING, and the
		 * cluster buffer's queue/lock state. */
		if (iter == 1) {
			struct xfs_buf *dwb = iip ? iip->ili_item.li_buf : NULL;

			mxfs_probe_ratelimited(
			    "mxfs: P2D-DRAINWHY ino=%llu in_ail=%d pin=%d fields=0x%x last=0x%x flushing=%d li_buf=%d bflags=0x%x delwri=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				in_ail ? 1 : 0, xfs_ipincount(ip),
				iip ? iip->ili_fields : 0,
				iip ? iip->ili_last_fields : 0,
				xfs_iflags_test(ip, XFS_IFLUSHING) ? 1 : 0,
				dwb ? 1 : 0, dwb ? dwb->b_flags : 0,
				dwb ? !!(dwb->b_flags & _XBF_DELWRI_Q) : 0,
				current->comm);
		}

		/*
		 * sess-tcp BOUNDED ifree drain: a freed inode's cluster buffer
		 * can stay orphaned in the AIL for tens of seconds while xfsaild
		 * is starved by a concurrent same-dir create storm (the dir inode
		 * re-flush churn).  When the inactivation path holds this drain it
		 * also holds the AG as an active DLM holder, deferring a peer's AG
		 * BAST for the whole wedge -> the peer's xfs_dialloc times out
		 * (-ETIMEDOUT, 60s).  When called with a deadline, give up the
		 * synchronous wait and let the BAST drain pipeline (invariant #1,
		 * Phase-2 drain_inode_buffers on actual contention) make the
		 * dinode durable before the on-disk AG release.  PROVEN root:
		 * P137-IFREE-TIME drain_us=62569 holding AG -> peer ino lock -110.
		 */
		if (deadline_ns && ktime_get_ns() >= deadline_ns)
			return false;

		/*
		 * P136-DRAIN-RESCUE (instrumented instrument+recover): the
		 * P113 wedge signature on test4 (ino=136 EX-release) was
		 * ili_fields=0, pin=0, li_buf XBF_DONE, NOT on any delwri
		 * list, unlocked — i.e. the inode was flushed into its
		 * cluster buffer (XFS_IFLUSHING, fields moved to
		 * ili_last_fields) but the buffer write was never submitted,
		 * so xfs_buf_inode_iodone never runs and the item is orphaned
		 * in the AIL forever → EX never released → all 15 peers
		 * starve 120s → cluster-wide shutdown.  Recover the NATIVE
		 * way: delwri-queue + submit the buffer so iodone clears
		 * IFLUSHING and removes the item from the AIL.  Guards keep
		 * us off the hazard (never touch a buffer that is
		 * already on someone's delwri list or locked).
		 */
		if (held_lbp) {
			struct xfs_buf	*lbp = held_lbp;
			bool		rescued = false;

			if (xfs_iflags_test(ip, XFS_IFLUSHING) &&
			    xfs_ipincount(ip) == 0 &&
			    !(lbp->b_flags & _XBF_DELWRI_Q) &&
			    xfs_buf_trylock(lbp)) {
				if (!(lbp->b_flags & _XBF_DELWRI_Q) &&
				    list_empty(&lbp->b_list)) {
					LIST_HEAD(rs_list);

					pr_warn("mxfs: P136-DRAIN-RESCUE ino=%llu iter=%u resubmitting orphaned IFLUSHING cluster buf flags=0x%x last_fields=0x%x\n",
						(unsigned long long)ip->i_ino,
						iter, lbp->b_flags,
						iip ? iip->ili_last_fields : 0);
					if (xfs_buf_delwri_queue(lbp, &rs_list)) {
						xfs_buf_relse(lbp);
						held_lbp = NULL;
						(void)xfs_buf_delwri_submit(&rs_list);
						mxfs_blkdev_flush_epoch(mp);
						rescued = true;
					} else {
						xfs_buf_unlock(lbp);
					}
				} else {
					xfs_buf_unlock(lbp);
				}
			}
			if (held_lbp)
				xfs_buf_rele(held_lbp);
			if (rescued)
				redrained2 = true;
		}

		xfs_ail_push_all(ailp);
		if ((iter++ & 3) == 0)
			xfs_log_force(mp, 0);

		/* break the _XBF_DELWRI_Q-collision case — re-submit the
		 * AG alloc-buflist once ip is unpinned (no-op if empty). */
		if (!redrained && iter >= 8 && xfs_ipincount(ip) == 0) {
			xfs_agnumber_t agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
			struct xfs_perag *pag = xfs_perag_get(mp, agno);

			if (pag) {
				mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
				xfs_perag_put(pag);
			}
			redrained = true;
		}

		if (iter && (iter & 255) == 0) {
			struct xfs_buf	*lbp = iip ? iip->ili_item.li_buf : NULL;
			unsigned int	lb_flags = lbp ? lbp->b_flags : 0;
			int		lb_hold = lbp ? (int)lbp->b_hold : -1;
			int		lb_onlist = lbp ? !list_empty(&lbp->b_list) : -1;
			int		lb_locked = lbp ? (lbp->b_sema.count == 0 ? 1 : 0) : -1;
			void		*lb_holder = lbp ? lbp->b_lock_ip : NULL;
			/*  wedge discriminators:
			 * igen!=bgen  => li_buf RECYCLED under the item (premature
			 *                free; P-BUF-FREE-WITH-ITEMS should have
			 *                screamed at the free);
			 * node_linked => the item's own list node is still linked
			 *                (into the DEAD list head if recycled);
			 * licnt       => items actually on the CURRENT buffer's
			 *                b_li_list (trylock-guarded; -1 no lock). */
			u64		ili_bgen = iip ? iip->ili_mxfs_buf_gen : 0;
			u64		lb_bgen = lbp ? lbp->b_mxfs_alloc_gen : 0;
			int		node_linked = iip ?
				!list_empty(&iip->ili_item.li_bio_list) : -1;
			int		licnt = -1;

			if (lbp && xfs_buf_trylock(lbp)) {
				struct xfs_log_item *cl;

				licnt = 0;
				list_for_each_entry(cl, &lbp->b_li_list,
						    li_bio_list) {
					if (++licnt >= 80)
						break;
				}
				xfs_buf_unlock(lbp);
			}

			/* The leak-site name: who locked the cluster buffer and
			 * never relse'd it (NULL ⇒ locked by an alloc/init path
			 * that bypasses xfs_buf_lock, e.g. fresh _xfs_buf_alloc). */
			pr_warn("mxfs: P113-DRAIN-WEDGE ino=%llu iter=%u still in_ail pin=%d ili_fields=0x%x last_fields=0x%x iflushing=%d rescued=%d libuf=%p lb_flags=0x%x lb_hold=%d lb_onlist=%d lb_locked=%d lb_err=%d igen=%llu bgen=%llu node_linked=%d licnt=%d holder=%pS\n",
				(unsigned long long)ip->i_ino, iter,
				xfs_ipincount(ip),
				iip ? iip->ili_fields : 0,
				iip ? iip->ili_last_fields : 0,
				xfs_iflags_test(ip, XFS_IFLUSHING) ? 1 : 0,
				redrained2 ? 1 : 0,
				lbp, lb_flags, lb_hold, lb_onlist, lb_locked,
				lbp ? lbp->b_error : 0,
				(unsigned long long)ili_bgen,
				(unsigned long long)lb_bgen,
				node_linked, licnt,
				lb_holder);
		}
		/*
		 * v0.5.6: fine-grained poll for the first iterations — the
		 * healthy case (xfsaild writes the cluster buffer ~1-3ms
		 * after the push above) converged on the OLD msleep(10) only
		 * at 10ms granularity, costing ~12ms per unlink inactivation
		 * (P137-IFREE-TIME drain_us≈12000 on every probe sample).
		 * Beyond 16 iterations fall back to the original 10ms cadence
		 * so the rescue (iter>=512) and wedge-log (iter&255)
		 * thresholds keep their effective time scale.
		 */
		if (iter < 16)
			usleep_range(500, 1000);
		else
			msleep(10);
	}
}

/*
 * Unbounded drain (invariant #1 forward-progress contract) — BAST release path.
 */
void
mxfs_ail_drain_inode_sync(struct xfs_inode *ip)
{
	(void)mxfs_ail_drain_inode_to(ip, 0);
}

/*
 * Bounded drain for the inode-inactivation (xfs_ifree) path.  Waits up to
 * max_ms for the freed inode's mode=0 dinode to land (healthy case ~1-3ms),
 * then gives up so the inactivation does not hold the AG as an active holder
 * for a wedge duration (which defers a peer's AG BAST -> peer alloc -110).
 * Cross-node dinode durability on an actual peer AG handoff is guaranteed by
 * the Phase-2 BAST drain pipeline regardless.  Returns true if durable.
 */
bool
mxfs_ail_drain_inode_sync_bounded(struct xfs_inode *ip, unsigned int max_ms)
{
	u64 deadline = max_ms ?
		ktime_get_ns() + (u64)max_ms * NSEC_PER_MSEC : 0;

	return mxfs_ail_drain_inode_to(ip, deadline);
}

/*
 * make a directory's INODE CLUSTER (the dinode itself) PLATTER-durable.
 *
 * A SHORTFORM (FMT_LOCAL) directory stores its dirents INLINE in the dinode, so
 * it has NO data-fork blocks for mxfs_dir_flush_data_blocks to flush — its
 * durability is entirely the durability of the inode-cluster buffer.  The
 * regular bast_process release path (L~1399) runs this same deterministic
 * sequence for dirs, but the RECLAIM release path (mxfs_dlm_evict) and the
 * no-inode BAST path skip it: when the shared shortform dir inode is reclaimed
 * mid-run, its DLM slot is released with the in-place dinode still only in the
 * SCST target write-cache (NOT destaged to the platter).  A peer then FUA-reads
 * the backing store (FUA pierces the target cache to the platter), sees the
 * STALE dinode missing this node's just-committed dirent, RMWs and DURABLY
 * clobbers it — the proven cross_visibility "node1.txt lost from every node"
 * (P-NOINO-BAST ino=2097281 timeline).
 *
 * Deterministic sequence (identical to the reg-file/bast_process flush):
 *   1. xfs_log_force(SYNC) flushes the CIL checkpoint and unpins the inode.
 *   2. xfs_imap_to_bp locks+reads the inode cluster buffer (waits in-flight bio).
 *   3. xfs_iflush_cluster copies the in-core inode into the buffer.
 *   4. xfs_bwrite writes it synchronously; blkdev_issue_flush destages the SCST
 *      write cache to the platter so the peer's FUA read sees our dirent.
 *
 * Caller must NOT hold a transaction.  May hold XFS_ILOCK_EXCL (== i_lock):
 * this path takes no inode ILOCK and does not recurse.  Returns true if the
 * cluster was made durable (or was already clean), false if it could not be
 * flushed (left for the caller to log).
 */
/*
 * which arm of mxfs_inode_cluster_durable a failure came from is the
 * whole question, and neither DURABLE-FAIL probe used to say.  On a RELEASE
 * (DEMOTING/BAST) the drain waits ~3 s because Architectural Invariant #1
 * forbids releasing the lock with the dinode stale -- giving up there hands the
 * peer a stale on-disk dinode whose FUA read durably resurrects a removed
 * dirent (the proof, quoted in the function below).  On the OP-SIDE
 * proactive path (CACHED, no peer waiting) the budget is ~50 ms and a miss is
 * harmless BY DESIGN, because the release-side drain catches the change at
 * handoff.  Same warning text for both, so a run with ten of them could not be
 * read either way.  Measured 0.64.37: 10 P13 on 7 of 32 nodes, and ZERO P68.
 */
static bool
mxfs_dir_durable_is_release(const struct xfs_inode *ip)
{
	return ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
	       ip->i_dlm_state == MXFS_DLM_ISTATE_BAST;
}

bool
mxfs_inode_cluster_durable(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_buf		*r_bp;
	int			rerr;
	int			rtry;
	int			icd_last_rerr = 0;	/* diag */
	int			icd_pin_bails = 0;	/* diag */
	bool			icd_releasing;		/* */
	int			icd_max_try;		/* */

	/* 8 was too short — a transient xfs_imap_to_bp failure or a brief
	 * pin/CIL window under continuous shared-dir churn exhausted the budget
	 * and the durable flush gave up (→ lost add / stale-handoff resurrection).
	 * 25×2ms (~50ms) rides out the transients.  Only shared (!self_created)
	 * dir flushes reach here, so rsync's node-private path pays nothing.
	 *
	 * — PROVEN BY INSTRUMENT (P55D self-skip 10x then
	 * P34D-RELOAD adopting stale disk; tcp_dlm_scaling/dlm_fairness leak):
	 * the short budget VIOLATES Architectural Invariant #1 ("no lock released
	 * until dirty data flushed") on the BAST-handoff path.  When this drain
	 * runs as part of a RELEASE (i_dlm_state == DEMOTING/BAST), new local dir
	 * ops are already diverted to the slow-path DEMOTING wait
	 * (mxfs_dlm_ilock_begin dir gate: state != CACHED), so the dir is
	 * QUIESCING: the one in-flight op that holds ip's ILOCK (which makes
	 * xfs_iflush_cluster trylock-SKIP ip and leaves the committed dirent
	 * change in the AIL) WILL finish, free the ILOCK, and let the next iflush
	 * destage ip.  Giving up after ~50ms hands the dir EX to the peer with a
	 * stale on-disk dinode — the peer's FUA read durably RESURRECTS our
	 * removed dirent, and our own next reacquire (P34D-RELOAD-FRESHSRC) adopts
	 * the stale platter and reverts the change too.  So on a release, WAIT
	 * (bounded ~3s, well under the peer's ACQUIRE_WAIT=6000ms) until ip
	 * actually leaves the AIL instead of releasing stale.  The op-side
	 * proactive durable (state == CACHED, no peer waiting) keeps the short
	 * best-effort budget — its miss is harmless because this release-side
	 * drain catches the change at handoff.  log_force only when PINNED so the
	 * long release wait does not storm the CIL (an already-in_ail change is
	 * past the CIL — re-iflushing destages it, no log_force needed). */
	/* instrumented lap-reason counters: P9-ICD-FAIL fired
	 * with pin_bails=0 last_rerr=0 in_ail=0 clean=1 on ino 128/131 (6s wedge
	 * -> mount-wide EIO) and the existing fields cannot say WHICH arm looped
	 * 1500x.  Count every continue-path and snapshot the cluster buffer's
	 * lock/flag state mid-loop. */
	int icd_imap_fails = 0, icd_eagain_inail = 0, icd_selfskip = 0;

	icd_releasing = (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
			 ip->i_dlm_state == MXFS_DLM_ISTATE_BAST);
	icd_max_try = icd_releasing ? 1500 : 25;
	for (rtry = 0; rtry < icd_max_try; rtry++) {
		if (rtry == 750) {
			struct xfs_buf	*s_bp = NULL;
			int		s_rc = xfs_imap_to_bp(mp, NULL,
							      &ip->i_imap, &s_bp);
			/* probe 2: plain bdev read of the same daddr —
			 * device-level failure vs buffer-layer refusal. */
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t p_len = BBTOB(ip->i_imap.im_len);
			void *p_tmp = ((p_len & 511) == 0 && p_len) ?
				kmalloc(p_len, GFP_NOFS) : NULL;
			int p_rc = -ENOMEM;
			uint32_t p_magic = 0;

			if (p_tmp) {
				p_rc = mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev,
					(uint64_t)ip->i_imap.im_blkno +
					mp->m_ddev_targp->bt_sector_offset,
					p_tmp, p_len);
				if (p_rc == 0)
					p_magic = be16_to_cpu(
						*(__be16 *)p_tmp);
				kfree(p_tmp);
			}
			pr_warn("mxfs: P9-ICD-MIDLOOP ino=%llu imap_rc=%d bp=%d flags=0x%x plainrd_rc=%d magic=0x%x imapf=%d eagain_ail=%d sskip=%d pinb=%d in_ail=%d shutdown=%d comm=%s\n",
				(unsigned long long)ip->i_ino, s_rc,
				s_bp ? 1 : 0,
				s_bp ? (unsigned int)s_bp->b_flags : 0,
				p_rc, p_magic,
				icd_imap_fails, icd_eagain_inail,
				icd_selfskip, icd_pin_bails,
				(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
				xfs_is_shutdown(mp) ? 1 : 0,
				current->comm);
			if (!s_rc && s_bp)
				xfs_buf_relse(s_bp);
		}
		if (atomic_read(&ip->i_pincount) > 0) {
			xfs_log_force(mp, XFS_LOG_SYNC);
			if (atomic_read(&ip->i_pincount) > 0) {
				icd_pin_bails++;
				msleep(2);
				continue;
			}
		} else if (rtry == 0) {
			/* First pass: push any just-committed change out of the
			 * CIL so the iflush below can see + destage it. */
			xfs_log_force(mp, XFS_LOG_SYNC);
		}
		r_bp = NULL;
		rerr = xfs_imap_to_bp(mp, NULL, &ip->i_imap, &r_bp);
		if (rerr || !r_bp) {
			icd_imap_fails++;	/* count + carry the rc */
			icd_last_rerr = rerr;
			msleep(2);
			continue;
		}
		/*
		 * v0.6.5 (186320ae) — DESTAGE-TIME TENURE VERIFY.
		 * PROVEN BY INSTRUMENT (dlm_fairness 4/caw run 022138Z, ino 6291584):
		 * test2's rename committed + per-op-destaged its dinode at
		 * .6060 while the on-disk slot ALREADY belonged to test3
		 * (P142 slot image 2ms later: holders_ex=0x4=test3, gen=27,
		 * lastex=test2, waiters=t1|t4) — the serve-time verify (P106
		 * BAIL) is check-then-act and cannot cover the serve→destage
		 * window.  A blind cluster write from a dead tenure lands
		 * INSIDE the new holder's tenure and regresses the dinode
		 * for everyone (the n2_r1/n4_r10.done ghost family; "df
		 * shared dir drained exp=0 got=1").  Verify the slot is
		 * still OURS before copying dinodes into the buffer (must
		 * run BEFORE xfs_iflush_cluster — refusing after it would
		 * orphan IFLUSHING, the P113-DRAIN-WEDGE).  On a
		 * lost tenure: do NOT write.  The change stays committed in
		 * the log/AIL; the dirty_seq ghost-skip keeps
		 * xfsaild from blind-flushing it, and the next acquire's
		 * reload MERGE (sf base/ours/theirs) re-lands it on top of
		 * the peer's image — no clobber, no loss.  Checked every
		 * 32nd lap (and lap 0) to bound the 512B slot-read cost on
		 * the 1500-lap release wait.
		 */
		if ((rtry & 31) == 0 && S_ISDIR(VFS_I(ip)->i_mode) &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) &&
		    /*  skip the on-disk tenure verify
		     * when holdership was granted/confirmed <100ms ago (the
		     * i_dlm_heldchk_j stamp) — under dirop_durable this read
		     * fired per dirop (801/round measured), and a
		     * milliseconds-old tenure cannot have been lost except
		     * via a protocol bug the 10Hz sampling still catches. */
		    time_after(jiffies,
			       ip->i_dlm_heldchk_j + msecs_to_jiffies(100)) &&
		    mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm, ip->i_ino) == 0) {
			xfs_buf_relse(r_bp);
			ip->i_dlm_stale = true;
			ip->i_dlm_stale_src = 9;
			/* Sticky until a successful destage: the ili may
			 * retire clean without writing (ghost-skip), and a
			 * clean reload would wholesale-adopt the lagging
			 * disk and REVERT our committed change (n3_r1
			 * ghost).  The reload merge gate honors this. */
			ip->i_dlm_icd_refused = true;
			pr_warn_ratelimited(
				"mxfs: P-ICD-TENURE-REFUSE ino=%llu rel=%d try=%d state=%u mode=%u — on-disk slot no longer ours at destage; refusing stale-tenure cluster write (committed change lands via next-acquire merge)\n",
				(unsigned long long)ip->i_ino,
				icd_releasing ? 1 : 0, rtry,
				ip->i_dlm_state, ip->i_dlm_mode);
			return false;
		}
		/*
		 * the "localized fresh-RMW" (SCSI-FUA
		 * re-read of the whole cluster into r_bp->b_addr before the flush) was
		 * REVERTED here.  Instrumented measurement (build 99A4E4905, full 2/tcp suite):
		 * it did NOT fix the tcp_dlm_scaling co-resident leak (still
		 * "drained got=1") AND it CAUSED a catastrophic dir_reuse_coherency
		 * regression — readdir returned 0/200 for 12 rounds.  Reading the
		 * platter over the cached buffer adopts a STALE/empty on-disk image for
		 * a freshly-reused dir inode whose just-created content is not yet
		 * durable (the same readdir=0 face v1 hit with disk_gen>incore_gen);
		 * xfs_iflush_cluster's per-inode overlay does NOT re-cover such inodes
		 * (P119 discards non-EX; clean co-residents are not re-copied), so the
		 * empty disk bytes win.  The real co-resident fix lives in the P119
		 * classified-handling path (xfs_inode.c), not a blind buffer refresh. */
		rerr = xfs_iflush_cluster(r_bp);
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    S_ISDIR(VFS_I(ip)->i_mode))
			mxfs_probe("mxfs: P-ICD ino=%llu incore_size=%lld clean=%d rerr=%d delwri_q=%d in_ail=%d pin=%d exh=%d prh=%d state=%u realns=%llu\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_disk_size,
				xfs_inode_clean(ip) ? 1 : 0, rerr,
				(r_bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
				(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
				atomic_read(&ip->i_pincount),
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_state,
				(unsigned long long)ktime_get_real_ns());
		/*
		 * ROOT FIX (PROVEN BY INSTRUMENT — P9-ICD-FAIL pin=0 in_ail=1
		 * clean=1): xfs_iflush_cluster returns -EAGAIN ("nothing dirty")
		 * when this inode was ALREADY iflushed into its cluster buffer but
		 * the buffer is still IN_AIL (delwri-queued, awaiting xfsaild).  The
		 * committed change (e.g. a shortform-dir REMOVAL) is in the in-core
		 * buffer but NOT on disk; under continuous churn xfsaild does not
		 * destage it within our retry window, so the old code spun 8×2ms and
		 * gave up → the dir-EX handoff released with a STALE on-disk cluster
		 * → a peer/self reload re-adopted it and durably RESURRECTED the
		 * removed dirent (the dlm_fairness/tcp_dlm_scaling residual).  The
		 * buffer already holds the committed image, so SUBMIT it now via the
		 * same native delwri path as a fresh iflush.  Treat this case as
		 * rerr==0 (submit the buffer) instead of retrying. */
		if (rerr == -EAGAIN && ip->i_itemp &&
		    test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags))
			rerr = 0;
		if (rerr == 0) {
			/*
			 * — instrumented + design-consult (design review).
			 * DO NOT xfs_bwrite(r_bp) here.  xfs_bwrite clears
			 * _XBF_DELWRI_Q but does NOT list_del(&r_bp->b_list): when a
			 * freshly-created CHILD inode shares this parent dir's 4 KiB
			 * inode cluster, mxfs's alloc path has queued the SHARED
			 * cluster buffer onto pag_mxfs_alloc_buflist with
			 * _XBF_DELWRI_Q|_XBF_MXFS_ALLOC_QUEUED.  A manual bwrite then
			 * leaves the buffer physically linked on the alloc-buflist
			 * with the delwri flag cleared — an inconsistent state that
			 * orphans the inode-log-items' IFLUSHING (no iodone path ever
			 * clears it for the siblings) and wedges mxfs_ail_drain_inode_
			 * sync forever (P113-DRAIN-WEDGE → SESS50-STARVE → SIGKILL).
			 * xfs_iflush_cluster has already copied the in-core dinodes
			 * (incl. our new dirent) into r_bp and set IFLUSHING.  Submit
			 * the buffer the NATIVE way so iodone deterministically clears
			 * IFLUSHING:
			 *   - if the buffer is trapped on the AG alloc-buflist
			 *     (_XBF_DELWRI_Q already set), relse and let
			 *     mxfs_dlm_ag_drain_alloc_buflist submit it (it calls
			 *     xfs_buf_delwri_submit, the correct list-aware path);
			 *   - otherwise queue it onto our own local list and
			 *     xfs_buf_delwri_submit it synchronously.
			 */
			if (r_bp->b_flags & _XBF_DELWRI_Q) {
				struct xfs_perag *d_pag;

				xfs_buf_relse(r_bp);
				d_pag = xfs_perag_get(mp,
					XFS_INO_TO_AGNO(mp, ip->i_ino));
				if (d_pag) {
					mxfs_dlm_ag_drain_alloc_buflist(mp, d_pag);
					xfs_perag_put(d_pag);
				}
			} else {
				LIST_HEAD(d_submit);

				if (xfs_buf_delwri_queue(r_bp, &d_submit)) {
					xfs_buf_relse(r_bp);
					(void)xfs_buf_delwri_submit(&d_submit);
				} else {
					/* already on some delwri list; the owning
					 * submitter (xfsaild or the AG drain) will
					 * push it — fall back to the AG drain. */
					struct xfs_perag *d_pag;

					xfs_buf_relse(r_bp);
					d_pag = xfs_perag_get(mp,
						XFS_INO_TO_AGNO(mp, ip->i_ino));
					if (d_pag) {
						mxfs_dlm_ag_drain_alloc_buflist(
							mp, d_pag);
						xfs_perag_put(d_pag);
					}
				}
			}
			mxfs_blkdev_flush_epoch(mp);
			/*
			 * (design-consult — the proven FACE 3
			 * root): xfs_iflush_cluster rc==0 means ">=1 inode in the cluster
			 * flushed", NOT necessarily THIS one.  xfs_iflush_cluster takes
			 * xfs_ilock_nowait(SHARED) per inode and SKIPS any whose ILOCK is
			 * held by a concurrent op, so under shared-dir churn it can flush a
			 * CO-RESIDENT and leave ip's own committed change in the AIL while
			 * still returning 0.  The old code declared durable and returned ->
			 * the release then lowered ip to NL with an un-destaged in_ail
			 * change -> a later unrelated cluster flush found ip at NL and the
			 * P119 non-EX guard DISCARDED it (PROVEN d6: P51-REL EX drain_ms=0
			 * immediately followed by P119-NONEX ino=DIR i_dlm_mode=0 in_ail=1
			 * comm=mv -> tcp_dlm_scaling "drained got=3", node2's n2_r1..r3
			 * removals lost).  Mirror the release-flush-loop
			 * P31-RELFLUSH-SELF-SKIPPED guard: if ip is STILL in the AIL after
			 * a "successful" cluster flush, OUR dinode was trylock-skipped --
			 * retry until it actually destages (xfs_iflush_done removes flushed
			 * inodes from the AIL in its ioend, so still-IN_AIL == this inode
			 * was skipped). */
			if (ip->i_itemp &&
			    test_bit(XFS_LI_IN_AIL,
				     &ip->i_itemp->ili_item.li_flags)) {
				icd_selfskip++;	/* lap-reason counter */
				mxfs_probe_ratelimited(
					"mxfs: P55D-ICD-SELF-SKIPPED ino=%llu try=%d/%d rel=%d state=%u exh=%d prh=%d pin=%d comm=%s — cluster flushed without this dinode (ILOCK trylock-skipped), retrying\n",
					(unsigned long long)ip->i_ino, rtry,
					icd_max_try, icd_releasing ? 1 : 0,
					ip->i_dlm_state, ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders,
					atomic_read(&ip->i_pincount),
					current->comm);
				msleep(2);
				continue;
			}
			ip->i_dlm_icd_refused = false;	/* v0.6.5: destaged under held tenure */
			return true;
		}
		if (rerr == -EAGAIN) {
			/* Nothing dirty: already iflushed (clean) or momentary
			 * ILOCK contention.  If no longer in the AIL it is
			 * durable in the buffer -> destage and done. */
			xfs_buf_relse(r_bp);
			if (!ip->i_itemp ||
			    !test_bit(XFS_LI_IN_AIL,
				      &ip->i_itemp->ili_item.li_flags)) {
				mxfs_blkdev_flush_epoch(mp);
				/* v0.6.5: do NOT clear i_dlm_icd_refused here —
				 * -EAGAIN+clean can mean the refused change was
				 * ghost-retired WITHOUT a write; only a real
				 * cluster write (rerr==0 exit) proves disk
				 * caught up. */
				return true;
			}
			icd_eagain_inail++;	/* lap-reason counter */
			msleep(2);
			continue;
		}
		/* EFSCORRUPTED: buffer already released + FS shut down. */
		icd_last_rerr = rerr;
		break;
	}
	/* instrumented diag: why did the durable flush give up? pin_bails==8
	 * => the inode stayed PINNED every retry (CIL/co-resident churn);
	 * last_rerr!=0 => imap/iflush error; in_ail tells if a committed-not-
	 * checkpointed change is still resident (the lost-update surface). */
	mxfs_probe_ratelimited(
		"mxfs: P9-ICD-FAIL ino=%llu rel=%d max_try=%d state=%u exh=%d prh=%d pin_bails=%d last_rerr=%d pin=%d in_ail=%d clean=%d imapf=%d eagain_ail=%d sskip=%d comm=%s\n",
		(unsigned long long)ip->i_ino, icd_releasing ? 1 : 0,
		icd_max_try, ip->i_dlm_state,
		ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
		icd_pin_bails, icd_last_rerr,
		atomic_read(&ip->i_pincount),
		(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
			&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
		xfs_inode_clean(ip) ? 1 : 0,
		icd_imap_fails, icd_eagain_inail, icd_selfskip,
		current->comm);
	mxfs_blkdev_flush_epoch(mp);
	return false;
}

/*
 * PROACTIVE shortform-parent-dir durability at create
 * time — the create-side sibling of the release-path cluster flush.
 *
 * PROVEN ROOT (instrumented, test_unlink_visibility): a node mkdir's a child dir under
 * a SHORTFORM parent (e.g. uv_diag under .mxfs_test).  The new dirent lives
 * INLINE in the parent's DINODE (shortform fork), not in any data-fork block.
 * xfs_create's publish-before-notify (mxfs_dlm_dir_durable_signal →
 * mxfs_dir_flush_data_blocks) flushes only DATA-fork blocks, so for a shortform
 * parent it makes nothing in-place durable (just a log_force).  The parent's
 * DLM grant stays cached EX on this node and — under CAW, where a peer's cold
 * read of the parent inode cluster does NOT BAST us — the new dirent is only
 * destaged on the next async xfsaild iflush.  Peers that resolve the parent in
 * that window cold-read the STALE on-disk cluster, miss the child dirent, and
 * every create UNDER the new child fails ENOENT (proven: all peers
 * create_errs=30/30 "No such file or directory"; forcing drop_caches on the
 * CREATOR after mkdir makes ALL peer creates succeed → test1-side durability).
 *
 * Fix: after xfs_create drops the parent ILOCK, make the parent's inode CLUSTER
 * platter-durable via the proven deterministic sequence (mxfs_inode_cluster_-
 * durable: log_force → imap_to_bp → iflush_cluster → bwrite → blkdev flush), so
 * a peer's first cold read of the parent sees the child dirent immediately.
 *
 * MUST be called with the parent ILOCK DROPPED — xfs_iflush_cluster takes
 * xfs_ilock_nowait(SHARED) per inode and SKIPS any it cannot lock, so a still-
 * EXCL-held parent would not be flushed.  Shortform parents only: block/leaf
 * dirs already destage their dirents via mxfs_dir_flush_data_blocks, and the
 * release path makes their cluster (di_size) durable on BAST.  No-op single-node.
 */
/*
 * ROOT FIX (instrumented, PROVEN run60 t8 277.0s + run61 all-node):
 * the ungated body, split out so the BAST-RELEASE drain can call it on EVERY
 * transport.  Road-B gate (mxfs_dirop_durable_needed) was placed
 * INSIDE mxfs_dlm_dir_inode_durable, which no-op'd not only the per-op
 * create/remove/rename barriers (intended) but ALSO the release-path call at
 * the bast_process sd stage (NOT intended — the param description itself says
 * "TCP relies on the BAST-release drain").  Result: the release drain
 * destaged dir DATA/leaf blocks (mxfs_dir_flush_data_blocks, ungated) but
 * NEVER the dir's own inode cluster, so a block->leaf converter handed off
 * with platter dinode nx=1/block-fmt while platter block 0 already carried
 * XDD3 — the next acquirer FUA-reloaded the stale dinode, block-read daddr 72
 * expecting XDB3, and every node shut down in a dirty trans
 * (xfs_dir3_block_verify daddr 0x48, run60 7/8 nodes + run61 6/8 nodes).
 * Per-op callers keep the gate (that is Road B's pace win: ~7-10ms x 800
 * ops/round); this release-path body runs per HANDOFF and is internally
 * dirty-gated, so read-only holders still pay nothing.
 */
void
__mxfs_dlm_dir_inode_durable(struct xfs_inode *dp)
{
	struct xfs_mount	*mp;

	if (!dp)
		return;
	mp = dp->i_mount;
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;
	/*
	 * PROVEN gap-B FIX (instrumented): for a grown
	 * EXTENTS/BTREE-format dir the extent MAP (di_size + di_nextents, and the
	 * bmbt root for BTREE) lives in the DINODE core, not in the data blocks.
	 * The release path flushes the dir DATA/leaf/bmbt BLOCKS (mxfs_dir_data_
	 * durable / mxfs_dir_bmbt_scan) but historically SKIPPED the inode cluster
	 * for non-LOCAL dirs (the old `fmt != LOCAL -> return`).  So a peer's
	 * post-handoff FUA read of the dinode saw a STALE (smaller) extent map and
	 * could not locate our just-grown data blocks → it RE-ALLOCATED a divergent
	 * block (single-entry durable loss, e.g. node2_f33.md5 round 17) or, under
	 * dir_epoch_adopt, ADOPTED the stale-small disk and tore leaf-vs-data
	 * (P33-FROMDISK-DIRSHRINK old_size=12288→4096 old_nx=4→1).  Make the dinode
	 * cluster platter-durable for ALL formats so the peer's FUA read sees the
	 * committed extent map.
	 *
	 * The attempt (C5BD4E04) was UNGATED — it iflushed on EVERY dir
	 * release incl. clean read-only holders (~30x perf), and predates
	 * force_block (block0 still diverged then).  Gate on the inode being
	 * genuinely DIRTY (pinned / logged fields / in-AIL): a clean inode is
	 * already on-disk, so a read-only / unchanged holder pays nothing. */
	if (dp->i_df.if_format != XFS_DINODE_FMT_LOCAL) {
		struct xfs_inode_log_item *iip = dp->i_itemp;
		bool dirty = atomic_read(&dp->i_pincount) > 0 ||
			(iip && (iip->ili_fields ||
				 test_bit(XFS_LI_IN_AIL,
					  &iip->ili_item.li_flags)));

		if (!dirty)
			return;			/* extent map already durable */
		if (!mxfs_inode_cluster_durable(dp))
			pr_warn_ratelimited(
				"mxfs: P68-DIRINODE-DURABLE-FAIL ino=%llu fmt=%u state=%d releasing=%d refused=%d held_mode=%u in_ail=%d pin=%d clean=%d — grown dir extent map not destaged\n",
				(unsigned long long)dp->i_ino,
				dp->i_df.if_format,
				(int)dp->i_dlm_state,
				mxfs_dir_durable_is_release(dp),
				dp->i_dlm_icd_refused ? 1 : 0,
				dp->i_dlm_mode,
				(dp->i_itemp && test_bit(XFS_LI_IN_AIL,
					&dp->i_itemp->ili_item.li_flags)) ? 1 : 0,
				atomic_read(&dp->i_pincount),
				xfs_inode_clean(dp) ? 1 : 0);
		return;
	}

	/*
	 * 336 of today's 341 P13 lines were the destage-time tenure
	 * verify refusing at try 0 (P-ICD-TENURE-REFUSE rel=1 try=0) on an
	 * orphan release whose in-core mode was already NL and whose dinode
	 * was clean — nothing was un-destaged, the slot was simply not ours.
	 * "not destaged" was therefore unreadable: it named a budget miss
	 * that never happened.  Print the refusal flag, the in-core mode and
	 * the dirty state so the line itself says which of the three exits
	 * (tenure refused / budget exhausted / clean but skipped) fired.
	 */
	if (!mxfs_inode_cluster_durable(dp))
		pr_warn_ratelimited(
			"mxfs: P13-SFPARENT-DURABLE-FAIL ino=%llu state=%d releasing=%d refused=%d held_mode=%u in_ail=%d pin=%d clean=%d — shortform parent cluster not destaged\n",
			(unsigned long long)dp->i_ino,
			(int)dp->i_dlm_state,
			mxfs_dir_durable_is_release(dp),
			dp->i_dlm_icd_refused ? 1 : 0,
			dp->i_dlm_mode,
			(dp->i_itemp && test_bit(XFS_LI_IN_AIL,
				&dp->i_itemp->ili_item.li_flags)) ? 1 : 0,
			atomic_read(&dp->i_pincount),
			xfs_inode_clean(dp) ? 1 : 0);
}
EXPORT_SYMBOL(__mxfs_dlm_dir_inode_durable);

/*
 * Per-op wrapper: the create/remove/rename call sites.  Transport-gated —
 * on TCP the BAST-release drain (__mxfs_dlm_dir_inode_durable at the sd
 * stage) is the durability point; per-op barriers stay CAW-only (Road B).
 */
void
mxfs_dlm_dir_inode_durable(struct xfs_inode *dp)
{
	if (!dp)
		return;
	/* per-op barrier is CAW-only (see mxfs_dirop_durable_tcp) */
	if (!mxfs_dirop_durable_needed(dp->i_mount))
		return;
	__mxfs_dlm_dir_inode_durable(dp);
}
EXPORT_SYMBOL(mxfs_dlm_dir_inode_durable);
