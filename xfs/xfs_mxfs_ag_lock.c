// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- AG lock acquisition and buffer drains
 */
#define MXFS_TU_ID 28	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
/* 0.85.0: acquires refused (-EAGAIN) / parked by the obligation freeze */
static atomic64_t mxfs_dlm_stat_oblf_eagain = ATOMIC64_INIT(0);
static atomic64_t mxfs_dlm_stat_oblf_wait = ATOMIC64_INIT(0);
/*
 * AG-grant acquires that were told "granted" while this clustered
 * mount had no DLM left to grant anything.  Not static: the departure summary
 * in xfs_fs_put_super reports it, because the window it measures opens and
 * closes inside that function.
 */
atomic64_t mxfs_dlm_stat_ag_nulldlm = ATOMIC64_INIT(0);
int mxfs_false_fresh_enforce = 1;
module_param_named(false_fresh_enforce, mxfs_false_fresh_enforce, int, 0644);
/*
 * diagnostic ONLY (tests/lone_mount_create.sh arm 'discard'): 0 =
 * re-create the pre-0.39.11 trigger — drop a single-node-era cached hint on
 * every re-acquire — so the fail-closed invalidation above can be exercised on
 * demand.  Default 1 (keep the hint).  Never run a workload with it at 0.
 */
int mxfs_single_era_hint_keep = 1;
module_param_named(single_era_hint_keep, mxfs_single_era_hint_keep, int, 0644);
/* v0.5.5: adaptive-cap default raised 32 ->
 * 512.  With the lazy path async-submitting dirty AG bufs on EVERY
 * skipped drain (v0.3.133/134), accumulated debt at BAST time is
 * bounded by writeback bandwidth, not by the quantum; the quantum-
 * exhaustion eager drain (xfs_log_force SYNC + sync delwri wait,
 * ~2-3ms) fired ~150x per 2-node scaling_curve rsync at cap 32 with
 * ZERO peer contention.  At 512 it fires ~50x (adaptive ramp 1->512
 * dominates).  2-node walls: test2 4812 -> 4492ms.  Contended AGs
 * still halve toward 1 on every peer BAST (adaptive logic unchanged);
 * MXFS_BAST_YIELD_QUANTUM (32, spec D10) remains the static-mode
 * (ag_yield_adaptive=0) default via the module param only if set. */
int mxfs_ag_yield_quantum = 512;

/*
 * record the task that took holders 0->1.  Caller holds
 * pag_dlm_lock.  Read by mxfs_dlm_ag_bast_notify's stuck-hold stack dump.
 */
static inline void
mxfs_ag_stamp_holder(struct xfs_perag *pag)
{
	pag->pag_dlm_holder_pid = current->pid;
	strscpy(pag->pag_dlm_holder_comm, current->comm,
		sizeof(pag->pag_dlm_holder_comm));
}

int
__mxfs_ag_dlm_lock(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	bool			nonblock,
	bool			demand,
	bool			resfree)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	int			error;
	bool			fresh_acquire = false;
	u64			acq_t0 = 0;	/* 0.22.4: fresh-acquire start */
	/*
	 * step 5.3 (ruling blocker 5): the authority provenance of the
	 * grant this acquire obtains, threaded out of the granting CAS.  Every
	 * ag_lock/_nb call below re-initialises it, and only the LAST one to
	 * return 0 can reach the epoch-publish block, so one local serves all
	 * three arms.  Non-proving until a granting CAS fills it.
	 */
	struct mxfs_grant_result ag_gres;

	mxfs_grant_result_init(&ag_gres);

	if (!dlm) {
		/*
		 * A NULL DLM means one of two very different things, and until
		 * they were the same code path.  Either the mount never
		 * needed cluster locking — a single-node or non-CAW device, and
		 * returning success is correct — or this is a clustered mount
		 * whose DLM context has already been torn down while a caller
		 * still wants an AG grant.  The departure accounting object is
		 * allocated iff the mount came up clustered, so its presence
		 * separates the two.
		 *
		 * The second case is reachable at unmount: xfs_fs_put_super
		 * clears m_mxfs_dlm well before it calls xfs_unmountfs, whose
		 * first act is to perform every on-disk metadata update needed
		 * to inactivate the inodes the VFS evicted — AGI and inode-btree
		 * mutation — followed by AG block unreservation and the final
		 * AIL push.  All of those arrive here and are told the AG is
		 * theirs.  Behaviour is deliberately unchanged: this counts the
		 * window and names its callers before anything is reordered.
		 */
		if (unlikely(mp->m_mxfs_acct)) {
			unsigned int	n;

			n = (unsigned int)atomic64_inc_return(&mxfs_dlm_stat_ag_nulldlm);
			if (n <= 32)
				mxfs_probe("mxfs: P483-AGLOCK-NULLDLM ag=%u n=%u comm=%s pid=%d — AG grant requested on a clustered mount whose DLM is already gone; the acquire reports success without acquiring anything\n",
					pag_agno(pag), n, current->comm,
					current->pid);
		}
		return 0;
	}

	/*
	 * an AG acquire after this mount published its grants at
	 * unmount, while the DLM still existed.  It would succeed — a fresh
	 * CAW acquire — and the grant it takes is swept by the v5 shutdown
	 * with no drain, so whatever it dirties is destaged with no exclusion.
	 * Since 0.69.3 no unmount step is supposed to arrive here after the
	 * publication; counted and named so that a nonzero can be traced.
	 */
	if (unlikely(mp->m_mxfs_acct) &&
	    unlikely(READ_ONCE(mp->m_mxfs_acct->ag_grants_published))) {
		spin_lock(&mp->m_mxfs_acct->lock);
		mp->m_mxfs_acct->aglock_after_agfree++;
		spin_unlock(&mp->m_mxfs_acct->lock);
		mxfs_probe_ratelimited("mxfs: P485-AGLOCK-AFTER-AGFREE ag=%u comm=%s pid=%d — AG grant requested after this mount published its grants at unmount; the grant it takes will be swept undrained\n",
			pag_agno(pag), current->comm, current->pid);
	}

	/*
	 * (D-513 enforcement point b): an AG inside a quarantined
	 * victim domain must fail fast with EIO — never wait out the dead
	 * holder's frozen grant into a timeout shutdown, never consume state
	 * whose committed redo was suppressed by the refused replay.
	 */
	if (unlikely(mxfs_quarantine_covers_agno(mp, pag_agno(pag)))) {
		pr_warn_ratelimited(
		    "mxfs: P240-QUAR-AG-EIO agno=%u comm=%s — AG in quarantined victim domain; failing acquire with EIO\n",
			pag_agno(pag), current->comm);
		return -EIO;
	}

	/*
	 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED): the OBLIGATION FREEZE,
	 * ahead of EVERY fast path.  While a dead node's OPEN obligation case
	 * names this AG, nothing but the custodian task completing that case
	 * may take a grant here — not even nested under a holder this node
	 * already has, because a caller admitted that way could allocate an
	 * extent the custodian has just freed, and a successor re-examining
	 * the case after the custodian's death would free it again over the
	 * new owner.  A non-blocking caller reports -EAGAIN (the allocator
	 * moves to another AG, a defer chain takes its -488 seam); a blocking
	 * caller waits for the case to reach OBLIGATIONS_DONE, bounded by the
	 * same 120 s budget as a dead holder's frozen grant: the completion
	 * takes milliseconds per extent, so a timeout here is a defect to
	 * diagnose, never a wait to widen.
	 *
	 * One exemption besides the custodian: a transaction that ALREADY
	 * retains this AG's grant (taken before the freeze landed, released at
	 * its commit).  Its re-acquire is the nested path it would have taken
	 * anyway, it cannot allocate anything the custodian freed (the
	 * custodian's quiesce wait does not begin its first transaction until
	 * this holder has committed and the holder count is zero), and
	 * refusing it would deadlock: the holder waits for OBLIGATIONS_DONE
	 * while the custodian waits for the holder to leave.
	 */
	if (unlikely(mxfs_oblf_covers_agno(mp, pag_agno(pag))) &&
	    READ_ONCE(mp->m_mxfs_oblf_task) != current &&
	    !mxfs_trans_retains_ag(pag)) {
		long	left;

		if (nonblock) {
			atomic64_inc(&mxfs_dlm_stat_oblf_eagain);
			mxfs_probe_ratelimited(
			    "mxfs: P-OBLF-AG-EAGAIN agno=%u comm=%s mask=0x%llx fswide=%d — AG frozen by an open obligation case; non-blocking acquire reports -EAGAIN\n",
				pag_agno(pag), current->comm,
				(unsigned long long)READ_ONCE(mp->m_mxfs_oblf_mask),
				READ_ONCE(mp->m_mxfs_oblf_fswide) ? 1 : 0);
			return -EAGAIN;
		}
		atomic64_inc(&mxfs_dlm_stat_oblf_wait);
		mxfs_probe_ratelimited(
		    "mxfs: P-OBLF-AG-WAIT agno=%u comm=%s pid=%d mask=0x%llx fswide=%d — AG frozen by an open obligation case; blocking acquire waits for OBLIGATIONS_DONE\n",
			pag_agno(pag), current->comm, current->pid,
			(unsigned long long)READ_ONCE(mp->m_mxfs_oblf_mask),
			READ_ONCE(mp->m_mxfs_oblf_fswide) ? 1 : 0);
		left = wait_event_timeout(mp->m_mxfs_oblf_wq,
				!mxfs_oblf_covers_agno(mp, pag_agno(pag)) ||
				READ_ONCE(mp->m_mxfs_oblf_task) == current ||
				xfs_is_shutdown(mp),
				msecs_to_jiffies(MXFS_OBLF_WAIT_BUDGET_MS));
		if (xfs_is_shutdown(mp))
			return -EIO;
		if (!left) {
			pr_warn("mxfs: P-OBLF-AG-TIMEOUT agno=%u comm=%s pid=%d mask=0x%llx — the obligation freeze outlived the %u ms budget; acquire fails -ETIMEDOUT (the case is stuck: diagnose, never widen)\n",
				pag_agno(pag), current->comm, current->pid,
				(unsigned long long)READ_ONCE(mp->m_mxfs_oblf_mask),
				MXFS_OBLF_WAIT_BUDGET_MS);
			return -ETIMEDOUT;
		}
	}

	/*
	 * NOTE: a "force pag_dlm_meta_gen++ on every PEER-AG acquire"
	 * fix was TRIED here (build B33AC3DD) to defeat the frozen-gen
	 * stale-pristine bnobt reuse on cross-node free.  It was NET-NEGATIVE:
	 * EIO on most cross-node frees + new corruption — forcing a re-read
	 * mid-free-batch disrupts the free transaction's own buffer state
	 * (consistent with exhaustive read-side-fix failures).
	 * REVERTED.  The real fix is upstream (CAW transient concurrent-EX /
	 * slot claim-race) or owner-side, NOT the acquirer's read path.
	 * See docs/history/session-46-lessons.md.
	 */

	/*
	 * Fast path: nested re-acquire, cached re-acquire, or cancel-
	 * deferred-release.  None needs CAW I/O.
	 */
	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	/*
	 * (D-474 / D-AGI split-under-protest root, 25-AG lap 2-3,
	 * stack-PROVEN on test17): a NONBLOCK acquire must not park in the
	 * demote window either.  rsync's inline inactivation of a just-
	 * unlinked inode (xfs_inactive_truncate -> defer_finish ->
	 * __xfs_free_extent -> mxfs_ag_dlm_trylock) reached wait_demote
	 * 9 ms after this AG's own "COMMIT demoting", and slept there
	 * holding ILOCK_EXCL on the unlinked inode — while the demote's
	 * publication stage needed exactly that ILOCK to land nlink=0
	 * before handing the AGI bucket head to the peer: P87-TARGET-
	 * TIMEOUT stage=ilock ocomm=rsync x2 per pass, P86 split published
	 * under protest, peer's AG wait 11.4 s.  The -488 seam already
	 * exists for -EAGAIN here (P271-AGWANT: relog the intent, roll,
	 * drop the ILOCKs, block holding nothing); the demote window just
	 * never reported it.  Same shape as the P-AGTRY-LOCALBUSY
	 * fix: "AG mid-handoff" == peer-held for a nonblock caller.
	 */
	if (nonblock && pag->pag_dlm_demoting) {
		static atomic_t p_trydemote_n = ATOMIC_INIT(0);

		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		atomic64_inc(&mxfs_dlm_stat_ag_trydemoting);
		if ((unsigned)atomic_inc_return(&p_trydemote_n) <= 64)
			mxfs_probe("mxfs: P-AGTRY-DEMOTING ag=%u comm=%s pid=%d — AG mid-demote (handoff to peer in progress); nonblock acquire reports -EAGAIN instead of parking in wait_demote with the caller's ILOCKs held\n",
				pag_agno(pag), current->comm, current->pid);
		return -EAGAIN;
	}
	mxfs_ag_dlm_wait_demote(pag);
	if (pag->pag_dlm_holders > 0) {
		mxfs_idbg("mxfs: P102-ACQ ag=%u NESTED holders=%d gen=%llu\n",
			pag_agno(pag), pag->pag_dlm_holders,
			(unsigned long long)pag->pag_dlm_meta_gen);
		pag->pag_dlm_holders++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	/*
	 * (D-488 leg 7 part 1b, ruling): P243 family — probe
	 * (and fail closed on) EVERY writable-tenure entry path, not just the
	 * fresh acquire.  A cached hint with NO published authority epoch is
	 * not a tenure: adopting it hands out write authority whose logged
	 * buffers a foreign replayer must refuse.  Every legitimate cached
	 * retention keeps the epoch published (all the WRITE_ONCE(...,0)
	 * clears sit at release-commit points, which also clear cached in the
	 * same critical section), so on CAW this state should be unreachable
	 * now that the rx strand detector no longer fabricates cached=true.
	 * If it ever appears, drop the hint and fall through to the fresh
	 * attested acquire below — with published epoch 0 the CAW already-
	 * held arm re-mints (P294-READOPT-MINT) instead of resurrecting
	 * whatever epoch the slot holds.  TCP mints no epochs; exempt.
	 */
	if (pag->pag_dlm_cached && mxfs_v5_dlm_is_caw(dlm) &&
	    READ_ONCE(pag->pag_mxfs_grant_epoch) == 0) {
		/*
		 * (D-0353, design-consult ruling): a SINGLE_NODE-provenance
		 * hint is a legitimate tenure for as long as the DLM is still
		 * single-node — nothing else can hold the AG, so the cached
		 * view (and the pinned AG-meta of the previous transaction)
		 * stands.  Dropping it here forced a false-fresh acquire whose
		 * invalidation discarded that pinned update: the lone-mount
		 * double allocation.  Once the DLM has left single-node mode
		 * the hint MUST NOT survive (the join barrier clears it; this
		 * is the fallback for an AG it could not clear because it was
		 * held at the time): drop it and attest on disk.
		 */
		if (pag->pag_mxfs_grant_single &&
		    mxfs_v5_dlm_is_single_node(dlm) &&
		    READ_ONCE(mxfs_single_era_hint_keep)) {
			/* keep the cached single-node tenure */
		} else {
			pag->pag_dlm_cached = false;
			mxfs_probe("mxfs: P243-AGAUTH-UNBOUND ag=%u src=%s — epochless cached hint dropped; forcing fresh attested acquire\n",
				pag_agno(pag),
				pag->pag_mxfs_grant_single ? "single-era-ended-fast" : "cached-fast");
			pag->pag_mxfs_grant_single = false;
		}
	}
	if (pag->pag_dlm_cached && unlikely(pag->pag_dlm_bast_pending) &&
	    mxfs_ag_handoff_closing(pag)) {
		/*
		 * (design-consult ruling
		 * ag-handoff-latch-closing-restartable): the handoff latch,
		 * ACQUIRE side.  A peer's BAST is pending, the worker's prepass
		 * ran, the grace is spent — this would-be re-adoption is
		 * exactly the race the worker kept losing (P12-READOPT-PINNED
		 * every ~3 ms at 25 AGs, 1.5-2.2 M per lap).  Take the release
		 * COMMIT here instead of adopting: nonblock callers report
		 * -EAGAIN (the -488 seam / next-AG skip, same contract as
		 * P-AGTRY-DEMOTING), blocking callers take the ordinary
		 * bounded demote wait (bracketed as an AG wait for the convoy-
		 * aware fence) and then queue behind the peer on a fresh
		 * attested acquire.  arm 3 failed because it made
		 * blocking callers wait for a handoff that had NOT been
		 * committed (holders kept bouncing, the worker kept bailing,
		 * ILOCK holders froze the fence); this wait is for a committed
		 * demote whose pipeline needs no further local admission.
		 */
		mxfs_ag_handoff_commit(pag, nonblock ? "acq-nb" : "acq",
				       nonblock ? &mxfs_dlm_stat_latch_acqnb :
						  &mxfs_dlm_stat_latch_acq);
		mxfs_ag_bast_queue(mp, pag);
		if (nonblock) {
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			atomic64_inc(&mxfs_dlm_stat_ag_trydemoting);
			return -EAGAIN;
		}
		mxfs_ag_dlm_wait_demote(pag);
		if (pag->pag_dlm_holders > 0) {
			pag->pag_dlm_holders++;
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			atomic64_inc(&mxfs_dlm_stat_ag_nested);
			return 0;
		}
		/* cached may have been re-established by a sibling's fresh
		 * acquire+release during the wait: adopting it now is a
		 * post-handoff adoption, not a cut-ahead. */
	}
	if (pag->pag_dlm_cached) {
		/* invariant: the COMMIT clears cached in the same
		 * critical section that sets latched — must stay 0. */
		if (unlikely(pag->pag_dlm_latched)) {
			atomic64_inc(&mxfs_dlm_stat_postlatch_adopt);
			WARN_ONCE(1, "mxfs: P12-POSTLATCH-ADOPT ag=%u comm=%s — cached hint observed while latched\n",
				  pag_agno(pag), current->comm);
		}
		/*
		 * Cached AG re-acquire: last-holder unlock kept the DLM grant
		 * on disk.  We still hold EX, so no peer has touched the AG.
		 * Just bump holders.
		 *
		 * tested an always-on AG-CACHED-DIVERGENCE detector here
		 * (mxfs_v5_dlm_ag_held on-disk check per fast-path acquire) —
		 * fired 0 times.  RE-TESTED it as a fix (P89: held-check +
		 * fall-through-to-fresh-acquire when not held) against the bnobt
		 * stale-V0-over-V1 clobber: P89 fired 0× and the corruption
		 * persisted → the cached fast-path genuinely holds the AG on disk;
		 * the stale-V0 write is NOT a cached-vs-disk divergence.  Reverted
		 * (one SCSI slot read per acquire is a perf killer; helper
		 * mxfs_v5_dlm_ag_held remains for targeted future use).
		 */
		pag->pag_dlm_cached = false;
		pag->pag_dlm_holders = 1;
		mxfs_ag_stamp_holder(pag);
		/*
		 * a re-adoption while a peer's BAST is
		 * pending extends our tenure past the peer's wait.  Count it
		 * and (ratelimited) name it — the 190s AG-0 starve is either
		 * thousands of these (ping-pong starvation) or none (lost/
		 * stuck work).
		 */
		if (unlikely(pag->pag_dlm_bast_pending)) {
			pag->pag_dlm_readopt_n++;
			mxfs_probe_ratelimited(
				"mxfs: P12-READOPT ag=%u n=%u page_ms=%u sched=%d comm=%s\n",
				pag_agno(pag), pag->pag_dlm_readopt_n,
				jiffies_to_msecs(jiffies -
					pag->pag_dlm_bast_pending_since),
				pag->pag_dlm_bast_scheduled ? 1 : 0,
				current->comm);
		}
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		mxfs_idbg("mxfs: P39-INSTR ag=%u FAST-PATH-ACQ cached=true→false holders=0→1 realns=%llu\n",
			pag_agno(pag),
			(unsigned long long)ktime_get_real_ns());
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	if (pag->pag_dlm_release_pending) {
		/*
		 * (P243 family, probe only): release_pending=true with
		 * demoting=false is believed unreachable today (the only setter
		 * is the unlock-quarantine arm, which keeps demoting held), and
		 * any such reclaim would adopt tenure AFTER the release COMMIT
		 * zeroed the epoch — an epochless writing tenure.  Detect
		 * loudly; a behavior change here must wait for evidence (the
		 * deferred-release iodone consults this flag).
		 */
		if (mxfs_v5_dlm_is_caw(dlm) &&
		    READ_ONCE(pag->pag_mxfs_grant_epoch) == 0)
			mxfs_probe("mxfs: P243-AGAUTH-UNBOUND ag=%u src=relpend-fast — release_pending reclaim adopting tenure with NO published epoch\n",
				pag_agno(pag));
		/*
		 * Cached release in flight: BAST work fn committed (cleared
		 * pag_dlm_cached) but is waiting on AG-meta writeback to
		 * finish before calling mxfs_v5_dlm_ag_unlock.  We still hold
		 * EX on disk, so cancel the pending release and adopt the
		 * grant.
		 *
		 * FIX (the bnobt durable lost-update root, ~10 sessions):
		 * the "we still hold EX on disk" assumption is NOT guaranteed.
		 * The inline release worker calls mxfs_v5_dlm_ag_unlock (yields
		 * the on-disk CAW slot, L6577) BEFORE it clears release_pending
		 * (L6586) — a reclaim that observes release_pending=true can race
		 * INTO that window where the CAW was already handed to the
		 * cluster and a PEER modified the AG.  Without bumping the meta
		 * gen, our cached AG-meta buffers (bnobt/cntbt/agf/...) stay
		 * gen-current (buf_gen==pag_gen, frozen at 1 — measured), so the
		 * read hook treats them FRESH, a new alloc/free txn builds on the
		 * STALE base, commits, and xfsaild later flushes that stale
		 * in-AIL bnobt over the peer's durable allocation -> double-free
		 * shutdown (P93-REVERT-CLOBBER: same bp persistently one version
		 * behind disk).  Bump the gen so the next read FUA-revalidates.
		 * Safe + cheap: drain-before-unlock (Invariant 1) guarantees no
		 * dirty/in-AIL AG-meta buffers exist once the CAW was yielded, so
		 * the read hook cleanly invalidates clean cached buffers; if the
		 * CAW was in fact retained (no yield), re-reading returns
		 * identical content (cost = one extra FUA read); in-AIL/pinned
		 * buffers are protected by the hook either way.
		 */
		pag->pag_dlm_release_pending = false;
		pag->pag_dlm_holders = 1;
		mxfs_ag_stamp_holder(pag);
		pag->pag_dlm_meta_gen++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		/* gen-independent acquire cold-read (peer may have
		 * modified the AG in the release worker's unlock->clear-flag
		 * window —). */
		mxfs_ag_meta_coldread_discard(pag, false);
		/* NOTE: do NOT reset pagf/pagi summary here.  This is a
		 * RECLAIM of our own pending/cached EX — INVARIANT #1 has NOT run
		 * (we never yielded the on-disk slot), so this node may hold
		 * this-node-ahead in_ail bnobt/cntbt that coldread_discard cannot
		 * drop.  Resetting AGF_INIT would rebuild pagf_longest from the
		 * lagging DISK agf while the cntbt is forward → longest>freeblks
		 * (PROVEN).  The pagf reset is only sound on a genuine
		 * fresh acquire from a peer (edit A), where INVARIANT #1 holds. */
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	/*
	 * Slow path — fresh acquire requires a CAW grant.  We MUST NOT hold
	 * pag_dlm_lock across mxfs_v5_dlm_ag_lock: the CAW poll loop sleeps
	 * for up to 120 s, and mxfs_dlm_ag_meta_iodone (xfs-buf workqueue)
	 * needs pag_dlm_lock to fire the deferred mxfs_v5_dlm_ag_unlock that
	 * the CAW grant may be waiting on.  Holding pag_dlm_lock across CAW
	 * deadlocks the iodone, which in turn never drains
	 * pag_dlm_meta_pending, which in turn never fires the deferred
	 * release, which the CAW is waiting for.
	 *
	 * pag_dlm_acquire_lock serializes concurrent fresh-acquire attempts
	 * on this node so only one thread drives the CAW grant.  iodone does
	 * not take this lock, so it remains free to fire deferred releases
	 * concurrently with our CAW poll.
	 */
	if (nonblock) {
		/*
		 * (D-474 AIL-freeze ROOT, stack-proven on test1/
		 * test27/test16, 0.19.33-34): a NONBLOCK caller must never
		 * park on pag_dlm_acquire_lock.  That mutex is held by a
		 * sibling local thread across its ENTIRE CAW poll (seconds to
		 * the deadline), so blocking here turned every
		 * mxfs_ag_dlm_trylock — issued by __xfs_free_extent /
		 * xfs_alloc_vextent_prepare_ag / dialloc with the caller's
		 * ILOCK held — into a blocking wait: P-AILMIN dumps showed the
		 * frozen AIL-min ILOCK owner (rsync in xfs_inactive_truncate →
		 * xfs_extent_free_finish_item → mxfs_ag_dlm_trylock) sitting in
		 * mutex_lock(pag_dlm_acquire_lock) for >5 s, the noino release
		 * fence froze across 8 pushes, and the node shut down
		 * (P-NOINO-RELFENCE-WEDGE).  The -488 post-roll seam exists so
		 * the caller can drop its ILOCKs and wait holding nothing —
		 * but only if trylock actually reports busy.  Report busy.
		 * The sibling's grant becomes our cached/nested fast path on
		 * retry; if its poll fails, our retry becomes the poller.
		 */
		if (!mutex_trylock(&pag->pag_dlm_acquire_lock)) {
			static DEFINE_RATELIMIT_STATE(lb_rl, 30 * HZ, 6);

			if (mxfs_probe_on() && __ratelimit(&lb_rl))
				mxfs_probe("mxfs: P-AGTRY-LOCALBUSY ag=%u comm=%s pid=%d — sibling thread mid-CAW-poll holds pag_dlm_acquire_lock; nonblock acquire reports -EAGAIN instead of parking\n",
					pag_agno(pag), current->comm,
					current->pid);
			atomic64_inc(&mxfs_dlm_stat_agtry_localbusy);
			return -EAGAIN;
		}
	} else {
		mutex_lock(&pag->pag_dlm_acquire_lock);
	}

	/*
	 * Re-check state after waiting on pag_dlm_acquire_lock — another
	 * thread may have acquired (and possibly already released back to
	 * release_pending) while we waited.
	 */
	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	mxfs_ag_dlm_wait_demote(pag);
	if (pag->pag_dlm_holders > 0) {
		pag->pag_dlm_holders++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		mutex_unlock(&pag->pag_dlm_acquire_lock);
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	/* same epochless-cached-hint guard as the fast path above
	 * (P243 family) — another thread may have installed a cached state
	 * while we waited on pag_dlm_acquire_lock. */
	if (pag->pag_dlm_cached && mxfs_v5_dlm_is_caw(dlm) &&
	    READ_ONCE(pag->pag_mxfs_grant_epoch) == 0) {
		/* (D-0353): same single-node-era exemption as the fast
		 * path above. */
		if (pag->pag_mxfs_grant_single &&
		    mxfs_v5_dlm_is_single_node(dlm)) {
			/* keep the cached single-node tenure */
		} else {
			pag->pag_dlm_cached = false;
			mxfs_probe("mxfs: P243-AGAUTH-UNBOUND ag=%u src=%s — epochless cached hint dropped; forcing fresh attested acquire\n",
				pag_agno(pag),
				pag->pag_mxfs_grant_single ? "single-era-ended-slow" : "cached-slow");
			pag->pag_mxfs_grant_single = false;
		}
	}
	if (pag->pag_dlm_cached && unlikely(pag->pag_dlm_bast_pending) &&
	    mxfs_ag_handoff_closing(pag)) {
		/* same latch as the fast path — a sibling installed a
		 * cached state while we waited on pag_dlm_acquire_lock, with a
		 * peer's BAST pending and the grace spent. */
		mxfs_ag_handoff_commit(pag, nonblock ? "acq-slow-nb" : "acq-slow",
				       nonblock ? &mxfs_dlm_stat_latch_acqnb :
						  &mxfs_dlm_stat_latch_acq);
		mxfs_ag_bast_queue(mp, pag);
		if (nonblock) {
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			mutex_unlock(&pag->pag_dlm_acquire_lock);
			atomic64_inc(&mxfs_dlm_stat_ag_trydemoting);
			return -EAGAIN;
		}
		mxfs_ag_dlm_wait_demote(pag);
		if (pag->pag_dlm_holders > 0) {
			pag->pag_dlm_holders++;
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			mutex_unlock(&pag->pag_dlm_acquire_lock);
			atomic64_inc(&mxfs_dlm_stat_ag_nested);
			return 0;
		}
	}
	if (pag->pag_dlm_cached) {
		if (unlikely(pag->pag_dlm_latched)) {
			atomic64_inc(&mxfs_dlm_stat_postlatch_adopt);
			WARN_ONCE(1, "mxfs: P12-POSTLATCH-ADOPT ag=%u comm=%s src=slow — cached hint observed while latched\n",
				  pag_agno(pag), current->comm);
		}
		pag->pag_dlm_cached = false;
		pag->pag_dlm_holders = 1;
		mxfs_ag_stamp_holder(pag);
		/* a peer may have modified this AG's free-space while we
		 * weren't holding it (the BAST cleared pag_dlm_cached); bump the
		 * meta gen so the AG-meta read path FUA-re-reads stale cached
		 * agf/bnobt/cntbt instead of double-allocating. */
		pag->pag_dlm_meta_gen++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		mutex_unlock(&pag->pag_dlm_acquire_lock);
		/* gen-independent acquire cold-read (peer modified AG
		 * while we weren't holding it; BAST cleared pag_dlm_cached). */
		mxfs_ag_meta_coldread_discard(pag, false);
		/* NOTE: no pagf/pagi reset here — reclaim of our own
		 * cached EX, INVARIANT #1 not run (see release_pending note). */
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	if (pag->pag_dlm_release_pending) {
		/* (P243 family, probe only): see the fast-path arm. */
		if (mxfs_v5_dlm_is_caw(dlm) &&
		    READ_ONCE(pag->pag_mxfs_grant_epoch) == 0)
			mxfs_probe("mxfs: P243-AGAUTH-UNBOUND ag=%u src=relpend-slow — release_pending reclaim adopting tenure with NO published epoch\n",
				pag_agno(pag));
		pag->pag_dlm_release_pending = false;
		pag->pag_dlm_holders = 1;
		mxfs_ag_stamp_holder(pag);
		/*
		 * FIX (see the matching release_pending reclaim above):
		 * the on-disk CAW may have already been yielded to the cluster
		 * in the release worker's unlock->clear-flag window, so a peer
		 * may have modified the AG.  Bump the meta gen to force FUA
		 * revalidation of cached AG-meta buffers (prevents the stale-base
		 * alloc/free txn -> xfsaild stale-bnobt clobber -> double-free).
		 */
		pag->pag_dlm_meta_gen++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		mutex_unlock(&pag->pag_dlm_acquire_lock);
		/* gen-independent acquire cold-read (release
		 * worker unlock->clear-flag race window). */
		mxfs_ag_meta_coldread_discard(pag, false);
		/* NOTE: no pagf/pagi reset here — reclaim of our own
		 * release_pending EX, INVARIANT #1 not run (see note above). */
		atomic64_inc(&mxfs_dlm_stat_ag_nested);
		mxfs_dlm_report_stats();
		return 0;
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);

	/*
	 * v0.3.147 prescription G, REDUCED (-488 fix):
	 * COOPERATIVE PRE-CAW KICK, no inline drain.
	 *
	 * Before issuing CAW for the AG we want, scan our cached AGs for
	 * any with bast_pending (a peer asked for them) whose BAST work
	 * was never scheduled, and schedule it.  This is pure bookkeeping
	 * recovery for a lost/unscheduled BAST; the drain itself always
	 * runs in the ordered workqueue.
	 *
	 * The old form ran mxfs_dlm_ag_bast_work_fn INLINE here, in the
	 * caller's ILOCKed context.  That was the proven -488 livelock
	 * burner: each restarted allocation attempt spent ~0.7s per AG in
	 * a drain that could not complete (the drain stalls on exactly the
	 * ILOCK our caller holds), so the retry loop starved forever while
	 * burning host CPU.  Inline execution adds nothing the worker
	 * doesn't already provide: the work fn self-requeues on stall, so
	 * scheduled drains are never lost.
	 *
	 * Invocation point: we hold pag_dlm_acquire_lock for our pag, but
	 * no other pag's pag_dlm_lock.  Each scanned pag is independently
	 * locked.  We don't recurse into our own pag.
	 */
	{
		struct xfs_perag	*scan;
		xfs_agnumber_t		scan_agno;

		for (scan_agno = 0; scan_agno < mp->m_sb.sb_agcount;
		     scan_agno++) {
			bool kick = false;

			if (scan_agno == pag_agno(pag))
				continue;
			scan = xfs_perag_get(mp, scan_agno);
			if (!scan)
				continue;
			/* lockless fast-skip: nothing pending, nothing to do */
			if (!READ_ONCE(scan->pag_dlm_bast_pending)) {
				xfs_perag_put(scan);
				continue;
			}
			mxfs_pag_dlm_lock(scan, MXFS_SITE);
			if (scan->pag_dlm_cached &&
			    scan->pag_dlm_bast_pending &&
			    scan->pag_dlm_holders == 0 &&
			    !scan->pag_dlm_demoting &&
			    !scan->pag_dlm_bast_scheduled) {
				scan->pag_dlm_bast_scheduled = true;
				kick = true;
			}
			mxfs_pag_dlm_unlock(scan, MXFS_SITE);
			if (kick) {
				mxfs_idbg("mxfs: P68-INSTR PRE-CAW-KICK want_agno=%u kicked_agno=%u\n",
					pag_agno(pag), scan_agno);
				if (mp->m_mxfs_ag_bast_wq)
					queue_work(mp->m_mxfs_ag_bast_wq,
						   &scan->pag_dlm_bast_work);
				else
					schedule_work(&scan->pag_dlm_bast_work);
			}
			xfs_perag_put(scan);
		}
	}

	/* CAW round-trip — only pag_dlm_acquire_lock held here. */
	acq_t0 = ktime_get_ns();	/* 0.22.4: see the stale-hint drop below */
	if (nonblock) {
		/*
		 * non-blocking fresh acquire for the allocator's
		 * XFS_ALLOC_FLAG_TRYLOCK first pass.  If a peer holds the AG,
		 * the CAW returns -EAGAIN/-EWOULDBLOCK immediately; we surface
		 * -EAGAIN so the dialloc / block-alloc iteration skips this AG
		 * rather than blocking up to 120s with inode ILOCKs held
		 * (the proven create/write-path deadlock).
		 *
		 * `demand` is what distinguishes the two nonblock callers:
		 * the allocator's TRYLOCK probe is silent, the bounded
		 * dirty-trans grow sweep leaves a sticky revoke behind
		 * (D-AGLOCK-...-LIVELOCK-488).
		 */
		error = mxfs_v5_dlm_ag_lock_nb(dlm, pag_agno(pag),
					       READ_ONCE(pag->pag_mxfs_grant_epoch),
					       &ag_gres, demand);
		if (error) {
			mutex_unlock(&pag->pag_dlm_acquire_lock);
			if (error == -EWOULDBLOCK)
				error = -EAGAIN;
			return error;
		}
	} else {
		u64 agt0 = ktime_get_ns();
		static atomic64_t ag_caw_n, ag_caw_ns;
		s64 acn;
		/*
		 * P1-AGWAIT attribution (instrumented): a BLOCKING fresh AG acquire on
		 * a peer-held AG is the waiter side of every AG<->dir stall
		 * (P36-RETRY type=3).  Probe non-blocking first: if the AG is
		 * free we just acquired it (identical bookkeeping below); if a
		 * peer holds it, name the caller path (first few per boot) then
		 * fall into the blocking wait as before.
		 *
		 * Always SILENT: the blocking wait immediately below registers
		 * a real on-disk waiter and multicasts, which is a strictly
		 * stronger signal than a sticky revoke.
		 */
		error = mxfs_v5_dlm_ag_lock_nb(dlm, pag_agno(pag),
					       READ_ONCE(pag->pag_mxfs_grant_epoch),
					       &ag_gres, false);
		if (error) {
			if (error == -EAGAIN || error == -EWOULDBLOCK) {
				static atomic_t p1_agwait_stacks = ATOMIC_INIT(0);

				/* cap raised 5→48 — the fatal dir-grow
				 * AG waits arrive rounds 9-15, well past the
				 * first five benign dialloc waits. */
				if (atomic_inc_return(&p1_agwait_stacks) <= 48) {
					char p1_held[64];

					mxfs_fmt_trans_held_ags(p1_held,
							sizeof(p1_held));
					mxfs_probe("mxfs: P1-AGWAIT ag=%u comm=%s pid=%d trans_dirty=%d trans_held_ags=[%s] — blocking on peer-held AG\n",
						pag_agno(pag), current->comm,
						current->pid,
						current->journal_info ?
						!!(((struct xfs_trans *)current->journal_info)->t_flags & XFS_TRANS_DIRTY) : -1,
						p1_held);
					/* stack only under instr — the
					 * held-set line is the convoy evidence;
					 * the "Call Trace" keyword fails soak's
					 * dmesg-clean criterion and costs ~2KB
					 * serial each. */
					if (unlikely(mxfs_instr_enabled))
						mxfs_probe_stack();
				} else {
					/* past the stack cap, keep a
					 * cheap capped line — the convoy
					 * evidence must survive late rounds. */
					static atomic_t p1w_n = ATOMIC_INIT(0);

					if ((unsigned)atomic_inc_return(&p1w_n) <= 4000) {
						char p1_held[64];

						mxfs_fmt_trans_held_ags(p1_held,
								sizeof(p1_held));
						mxfs_probe("mxfs: P1-AGWAIT ag=%u comm=%s trans_held_ags=[%s]\n",
							pag_agno(pag),
							current->comm, p1_held);
					}
				}
			}
			/*
			 * ABBA ROOT FIX (instrumented —
			 * PROVEN via run33 t490 -110 timelines: test7's dd
			 * blocked HERE in xfs_dialloc wanting AG-4 while its
			 * create trans carried dir-131's DEFERRED BAST
			 * (mxfs_dlm_ilock_end Approach-A defers bast_process
			 * to xfs_trans_free when journal_info is set — so
			 * the v0.3.148 dp-ILOCK drop never actually made the
			 * dir DLM EX yieldable); test6's dd held AG-4 via
			 * its own trans-deferred unlock while blocked
			 * re-locking dir-131.  Neither trans can end; both
			 * retry 60×1.02s; the AG side dies with -110 →
			 * dirty-cancel shutdown → dead-node cascade
			 * (readdir=0 + drc-FAIL 704/800, runs 30-33).
			 *
			 * Break the cycle on the dir side: before BLOCKING
			 * for a peer-held AG, fire this task's deferred
			 * inode BASTs so the dir lock hands off to the peer.
			 * Safe only while the trans is CLEAN — the deferral
			 * exists to keep peers from reading pre-modification
			 * disk state (Mode A), which requires a dirtying
			 * trans; xfs_create at the dialloc point has
			 * modified nothing (P1-AGWAIT trans_dirty=0), and
			 * the create re-acquires dp's DLM EX after dialloc
			 * with the modify-refresh + EEXIST
			 * re-validate handling any peer changes in the
			 * window.
			 */
			{
				struct xfs_trans *dtp = current->journal_info;

				if (dtp && !(dtp->t_flags & XFS_TRANS_DIRTY) &&
				    !list_empty(&dtp->t_mxfs_inode_unlocks)) {
					mxfs_probe_ratelimited(
						"mxfs: P5D-PREWAIT-DEFERRED-BAST ag=%u comm=%s — firing clean-trans deferred inode BASTs before blocking\n",
						pag_agno(pag), current->comm);
					mxfs_trans_drain_inode_unlocks(dtp);
				}
				/*
				 * (D-501 tripwire): the preacquire's
				 * optional-AG skip bets that this op never
				 * demands the skipped AG once dirty.  A DIRTY
				 * trans blocking here is that bet lost —
				 * count it (probe, not error: the wait can
				 * still succeed; the danger is the dirty-
				 * cancel if it times out).
				 */
				if (dtp && (dtp->t_flags & XFS_TRANS_DIRTY)) {
					char p292_held[64];

					mxfs_fmt_trans_held_ags(p292_held,
							sizeof(p292_held));
					mxfs_probe_ratelimited(
						"mxfs: P292-DIRTY-AGWAIT ag=%u comm=%s pid=%d trans_held_ags=[%s] — dirty trans blocking on peer-held AG\n",
						pag_agno(pag), current->comm,
						current->pid, p292_held);
				}
			}
			/*
			 * (D-474 convoy-aware fence): publish this
			 * blocking episode so the no-inode release fence can
			 * attribute a frozen AIL min (an EFI whose extents
			 * live in THIS AG, held by a peer) to a bounded wait
			 * instead of charging it as a wedge.
			 */
			if (atomic_inc_return(&pag->pag_mxfs_agwait_inflight) == 1)
				WRITE_ONCE(pag->pag_mxfs_agwait_since_ns, agt0);
			error = mxfs_v5_dlm_ag_lock(dlm, pag_agno(pag),
						    READ_ONCE(pag->pag_mxfs_grant_epoch),
						    &ag_gres);
			if (atomic_dec_return(&pag->pag_mxfs_agwait_inflight) == 0)
				WRITE_ONCE(pag->pag_mxfs_agwait_since_ns, 0);
		}
		acn = atomic64_inc_return(&ag_caw_n);
		atomic64_add(ktime_get_ns() - agt0, &ag_caw_ns);
		if ((acn & 255) == 0)
			mxfs_probe("mxfs: CAW-AGLOCK n=%lld tot_ms=%lld avg_us=%lld\n",
				(long long)acn,
				(long long)(atomic64_read(&ag_caw_ns) / 1000000),
				(long long)(atomic64_read(&ag_caw_ns) / 1000 / acn));
		if (error) {
			mutex_unlock(&pag->pag_dlm_acquire_lock);
			return error;
		}
	}

	/*
	 * shared on-disk AG epoch.  The local pag_dlm_meta_gen
	 * was effectively FROZEN — every prior session's careful read-hook
	 * invalidation was dead code because the gen never reflected a PEER's
	 * intervening modify.  Drive it from the CAW slot.generation (a uint32
	 * ABA counter bumped on every acquire+release CAS of this AG's slot by
	 * ANY node) so the epoch is genuinely cross-node.  Read it here while we
	 * hold EX (slot stable) and BEFORE taking pag_dlm_lock (no pag_dlm_lock
	 * across slot I/O).  TCP transport returns -ENODEV → fall back to the
	 * old unconditional bump. */
	{
		u64 disk_gen = 0;
		u64 grant_epoch = 0;
		u64 grant_lineage = 0;
		int gen_rc = mxfs_v5_dlm_ag_read_generation(dlm, pag_agno(pag),
							    &disk_gen);

		/*
		 * step 5.3 (ruling blocker 5): the durable
		 * exclusive-grant epoch comes from the GRANTING CAS itself,
		 * carried in ag_gres — not from a post-acquire re-read.
		 * re-read (mxfs_v5_dlm_ag_grant_epoch, now deleted)
		 * could not prove the epoch it returned belonged to the grant
		 * we hold: a release+regrant between the CAS and the read —
		 * our own bast drain, or a peer borrowing and returning the
		 * AG — returned a nonzero, current, WRONG token that then
		 * became durable write authority in our log records.
		 *
		 * The provenance check has three parts and all three must
		 * hold, or we publish 0 (= no authority, fail closed):
		 *   - proving:  a writing mode with a nonzero minted epoch
		 *               (a PR grant or a zero-epoch writing grant is
		 *               classified, non-proving, and never merged in)
		 *   - kind:     the result describes an AG slot, not an inode
		 *               or inode-cluster one (epoch namespaces are
		 *               per-class and must never be crossed)
		 *   - resource: it is THIS agno.  Binding the epoch to the
		 *               grant is the whole point of the blocker.
		 */
		if (mxfs_grant_result_proving(&ag_gres) &&
		    ag_gres.kind == MXFS_LTYPE_AG &&
		    ag_gres.resource == (u64)pag_agno(pag)) {
			grant_epoch = ag_gres.grant_epoch;
			/* lineage rides only with a proving epoch —
			 * an unproven grant publishes neither. */
			grant_lineage = ag_gres.resource_lineage;
		} else {
			grant_epoch = 0;
			grant_lineage = 0;
			/*
			 * A fresh EX acquire that yields no provable epoch is
			 * a real gap, not noise: every buffer this tenure
			 * dirties will be unauthorized and its images will be
			 * refused by a foreign replayer.  TCP mints no epoch
			 * and is expected here (status UNSET) — everything
			 * else is a defect signal, so carry the class.
			 */
			if (mxfs_v5_dlm_is_caw(dlm) &&
			    ag_gres.status != MXFS_GAUTH_SINGLE_NODE) {
				static atomic_t p243_n = ATOMIC_INIT(0);

				if ((unsigned)atomic_inc_return(&p243_n) <= 200)
					mxfs_probe("mxfs: P243-AGAUTH-UNBOUND ag=%u st=%u kind=%u res=%llu gep=%llu mode=%u reaff=%u — fresh EX acquire published NO authority epoch\n",
						pag_agno(pag), ag_gres.status,
						ag_gres.kind,
						(unsigned long long)ag_gres.resource,
						(unsigned long long)ag_gres.grant_epoch,
						ag_gres.mode, ag_gres.reaffirm);
			}
		}

		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		/*
		 * step 5.1 (grant-state lifecycle): PUBLISH the
		 * in-core authority epoch.  This is the only site that makes
		 * it nonzero, and it runs after the granting CAS has already
		 * succeeded — so a nonzero epoch means "this node positively
		 * holds AG <agno> EX at that durable epoch, and no release of
		 * it has begun".  Paired with the WRITE_ONCE(...,0) clears at
		 * every release-commit point below; the lock-free reader is
		 * xfs_buf_item_format_segment (READ_ONCE).
		 */
		WRITE_ONCE(pag->pag_mxfs_grant_epoch, grant_epoch);
		WRITE_ONCE(pag->pag_mxfs_grant_lineage, grant_lineage);
		/* (D-0353): record single-node provenance beside the
		 * (zero) epoch so the P243 guard can tell "no epoch because the
		 * DLM is single-node" from "no epoch = publication gap". */
		pag->pag_mxfs_grant_single =
			(ag_gres.status == MXFS_GAUTH_SINGLE_NODE);
		pag->pag_dlm_holders = 1;
		mxfs_ag_stamp_holder(pag);
		/*
		 * 0.22.4: a pending BAST that was RECEIVED BEFORE this
		 * acquire even started cannot be revoking the tenure we just won
		 * — it is the multicast hint of a revocation addressed to a
		 * previous holder (typically the waiter's last re-BASTs landing
		 * after our own release completed, or a third node's BAST while
		 * we held nothing).  Left in place it poisons the new tenure:
		 * mxfs_ag_handoff_closing reads stamps that are seconds old, so
		 * the FIRST last-holder unlock of the tenure COMMITs a release
		 * nobody asked for (measured 0.22.3 @25 AGs: all 265 handoff
		 * tail events had holders==0 at rx, q p90 2-5 s / max 18 s,
		 * every shared-AG tenure cut to one op).  A BAST that arrives
		 * from acq_t0 on (after the granting CAS is the only way one can
		 * be ours; the window before it costs one re-BAST, ~100 ms) is
		 * kept.  The rx-side orphan/strand detector is unaffected: it
		 * keys off the >3 s no-tenure window and re-arms on the next rx.
		 */
		if (pag->pag_dlm_bast_pending &&
		    !pag->pag_dlm_bast_scheduled &&
		    !pag->pag_dlm_readopt_pending &&
		    pag->pag_dlm_bast_rx_ns &&
		    pag->pag_dlm_bast_rx_ns < acq_t0) {
			pag->pag_dlm_bast_pending = false;
			pag->pag_dlm_prepass_done = false;
			atomic64_inc(&mxfs_dlm_stat_stale_hint);
			mxfs_probe_ratelimited("mxfs: P12-STALE-HINT ag=%u age_ms=%llu comm=%s — pre-acquire BAST hint dropped at fresh grant\n",
				pag_agno(pag),
				(unsigned long long)((acq_t0 -
					pag->pag_dlm_bast_rx_ns) / NSEC_PER_MSEC),
				current->comm);
		}
		/*
		 * (design review design-consult): a genuine fresh CAW grant opens a NEW
		 * tenure.  Invariant #1 drained our prior tenure before we yielded
		 * the slot, so no this-node-ahead AG-meta buffers survive; every
		 * cached buffer is now from a PRIOR tenure and must be re-validated
		 * (acquire-cold-read below handles the clean ones; the read hook
		 * handles in_ail log-tail artifacts).  Bumping here is what lets the
		 * read hook tell a prev-epoch artifact (old tenure id -> discard)
		 * from a current-tenure committed insert (current id -> preserve),
		 * fixing the AGI unlinked-list lost-update.  Reclaim paths above do
		 * NOT bump (same tenure — slot never yielded, Invariant #1 not run).
		 */
		pag->ag_dlm_tenure_id++;
		if (gen_rc == 0) {
			/* Only treat as a fresh peer-epoch when the shared
			 * on-disk gen actually advanced past what we last saw. */
			if (disk_gen != pag->pag_dlm_disk_gen_seen) {
				pag->pag_dlm_disk_gen_seen = disk_gen;
				pag->pag_dlm_meta_gen++;
				/* The missing piece every prior attempt skipped:
				 * reset the in-core PAG summary so the cold-read
				 * AGF/AGI rebuild the pagf and pagi summaries
				 * CONSISTENT with the re-read bnobt/cntbt (
				 * desynced = fresh AGF buffer + stale pagf summary). */
				clear_bit(XFS_AGSTATE_AGF_INIT, &pag->pag_opstate);
				clear_bit(XFS_AGSTATE_AGI_INIT, &pag->pag_opstate);
			}
		} else {
			/* TCP / read-fail: conservative — assume peer touched it. */
			pag->pag_dlm_meta_gen++;
			clear_bit(XFS_AGSTATE_AGF_INIT, &pag->pag_opstate);
			clear_bit(XFS_AGSTATE_AGI_INIT, &pag->pag_opstate);
		}
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited("mxfs: P102-ACQ ag=%u FRESH-CAW disk_gen=%llu seen=%llu rc=%d gen->%llu\n",
				pag_agno(pag), (unsigned long long)disk_gen,
				(unsigned long long)pag->pag_dlm_disk_gen_seen, gen_rc,
				(unsigned long long)pag->pag_dlm_meta_gen);
	}
	/*
	 * v0.3.131: arm the bounded yield quantum at fresh acquire.
	 * Subsequent unlock(holders==0) cycles may skip the per-trans
	 * drain up to MXFS_BAST_YIELD_QUANTUM times before forcing an
	 * eager drain.  Per docs/v6-cache-architecture-proposal.md §11
	 * + spec D10.
	 *
	 * v0.3.147 lazy-init pag_dlm_yield_quantum_eff (the
	 * adaptive effective quantum) at first fresh acquire.  Subsequent
	 * acquires reuse whatever value the adaptation logic has settled
	 * on (halved on peer BAST, doubled after non-contended epochs).
	 *
	 * In adaptive mode, START AT 1 and GROW.  Starting at the cap is
	 * too aggressive: by the time peer BASTs, we have already
	 * accumulated quantum-cap worth of dirty state per AG, and the
	 * resulting bast_work_fn drain pipeline can exceed peer's 120s
	 * CAW timeout.  Starting small ensures the first epoch is
	 * provably bounded; the doubling logic grows the quantum up to
	 * the cap only after MXFS_AG_YIELD_DOUBLE_THRESH consecutive
	 * non-contended eager drains.  SOLO converges to cap in O(seconds)
	 * (rapid back-to-back drains all non-contended).  Multi-node
	 * stays small under sustained contention.  Static mode (adaptive=0)
	 * keeps the historical behavior of starting at the cap.
	 */
	if (pag->pag_dlm_yield_quantum_eff <= 0)
		pag->pag_dlm_yield_quantum_eff = mxfs_ag_yield_adaptive
			? 1 : mxfs_ag_yield_quantum;
	pag->pag_dlm_yield_remaining = pag->pag_dlm_yield_quantum_eff;
	/*
	 * P130-FALSE-FRESH (design review lineage certificate).
	 * A genuine fresh CAW grant must only ever follow a CLOSED lineage:
	 * every sanctioned release path (bast_work_fn full drain, deferred
	 * release worker, force-release) clears pag_dlm_lineage_open right
	 * where it yields the on-disk slot.  Finding it still open here means
	 * the previous grant ended with NO release checkpoint (slot
	 * evaporated / phantom loss) — the acquire-side invalidation below
	 * (invalidate_ag_meta + coldread_discard(fresh_peer=true)) will then
	 * destructively discard local CIL/AIL free-space state that was never
	 * made durable = the silent bnobt lost-update / double-alloc
	 * prerequisite (uv-dir vs posix_multi double-allocation, 2026-07-16).
	 */
	if (pag->pag_dlm_lineage_open) {
		static atomic_t p130_n = ATOMIC_INIT(0);
		int p130_seq = atomic_inc_return(&p130_n);

		mxfs_probe("mxfs: P130-FALSE-FRESH agno=%u fresh CAW grant with lineage still OPEN (no release ran) tenure=%llu gen_seen=%llu cached=%d relpend=%d demoting=%d comm=%s realns=%llu\n",
			pag_agno(pag),
			(unsigned long long)pag->ag_dlm_tenure_id,
			(unsigned long long)pag->pag_dlm_disk_gen_seen,
			pag->pag_dlm_cached ? 1 : 0,
			pag->pag_dlm_release_pending ? 1 : 0,
			pag->pag_dlm_demoting ? 1 : 0,
			current->comm,
			(unsigned long long)ktime_get_real_ns());
		if (p130_seq <= 8)
			mxfs_probe_stack();
		/*
		 * (D-0353, design-consult ruling Q2): an open lineage at a
		 * fresh grant means this node's previous tenure never ran a
		 * release checkpoint, so its committed AG-meta may still be
		 * un-landed — and the invalidation that follows a fresh grant
		 * would discard it (the measured double allocation).  Nothing
		 * here can prove uninterrupted local ownership from the slot
		 * image, so the only fail-closed answer is to stop: loud, not
		 * silent.  The single-node era never reaches this (its cached
		 * hint is retained, D-0353 step 1) and the join barrier closes
		 * lineages administratively.
		 */
		if (READ_ONCE(mxfs_false_fresh_enforce)) {
			struct xfs_mount *ff_mp = pag_mount(pag);

			pr_err("mxfs: P130-FALSE-FRESH-REFUSED agno=%u — fresh grant over an OPEN lineage; refusing to invalidate un-landed local state; shutting down\n",
				pag_agno(pag));
			mxfs_pag_dlm_unlock(pag, MXFS_SITE);
			xfs_force_shutdown(ff_mp, SHUTDOWN_CORRUPT_INCORE);
			mxfs_pag_dlm_lock(pag, MXFS_SITE);
		}
	}
	pag->pag_dlm_lineage_open = true;
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);
	atomic64_inc(&mxfs_dlm_stat_ag_acquire);
	fresh_acquire = true;

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("P10-INSTR realns=%llu slot=%d agno=%u ACQ-FRESH\n",
			(unsigned long long)ktime_get_real_ns(),
			mxfs_v5_dlm_get_node_slot(dlm), pag_agno(pag));

	mutex_unlock(&pag->pag_dlm_acquire_lock);

	if (fresh_acquire) {
		/*
		 * Drop our local cache of any AG-metadata buffer for this AG:
		 * a peer may have modified the on-disk AGF/AGI/AGFL/btree
		 * blocks while we did not hold the lock.  Invalidating forces
		 * the next access to re-read fresh content from disk.  Done
		 * outside pag_dlm_lock so buffer locks never invert with it.
		 */
		mxfs_dlm_invalidate_ag_meta(pag, NULL);

		/*
		 * Inv-2 acquire-invalidation fix.
		 * mxfs_dlm_invalidate_ag_meta PRESERVES any in-AIL/dirty/pinned
		 * bnobt/cntbt buffer (the P47-INVAL-SKIP-INAIL guard) on
		 * the theory it is this-node-ahead un-destaged content.  On a
		 * GENUINE fresh-from-peer grant that theory is wrong: Invariant #1
		 * drained every legitimate this-node-ahead AG-meta before we
		 * released the AG to the peer, so a lingering in-AIL bnobt/cntbt
		 * here is a destaged prior-tenure log-tail artifact whose durable
		 * content the peer has since superseded.  invalidate left it
		 * cached+DONE -> xfsaild pushes it over the peer's allocation =
		 * P124-ALLOC-REVERT double-free.  coldread_discard(pag, true)
		 * discards those in-AIL bnobt/cntbt UNCONDITIONALLY on the
		 * fresh-peer path (it keeps the conservative undestaged guard on
		 * the reclaim path, fresh_peer=false).  Run outside pag_dlm_lock so
		 * buffer locks never invert with it.
		 */
		mxfs_ag_meta_coldread_discard(pag, true);

		/*
		 * instrumented decisive probe: does the medium's bnobt root
		 * change during our EX hold with no local write?  Splits the
		 * release-side async-drain leak (Theory D) from read-side
		 * staleness (Theory B).  Self-bounded; see helper.
		 *
		 * RESULT (7/7 samples differs=0): medium is COHERENT
		 * under our EX hold -> Theory D REFUTED.  The 100ms sleep ran
		 * mid-transaction (mxfs_ag_dlm_lock is called from inside
		 * xfs_create's allocation) and induced a spurious trans_cancel
		 * shutdown, so the call is disabled now that it has answered.
		 * Re-enable only to re-measure medium coherence.
		 */
		if (mxfs_instr_enabled)
			mxfs_acq_fresh_durability_probe(pag);
	}

	mxfs_dlm_report_stats();
	return 0;
}

/*
 * Public AG-DLM acquire — blocking (waits up to the CAW 120s timeout for a
 * peer to release).  Holder counting handles nesting.
 */
int
mxfs_ag_dlm_lock(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	return __mxfs_ag_dlm_lock(mp, pag, false, false, false);
}

/*
 * (design-consult ruling docs/rulings/readopt-close-shape.md):
 * RESOURCE_FREE blocking acquire — the caller provably holds NO inode lock
 * and NO transaction (the -488 pregrant and the P271-AGWAIT seam, both of
 * which dropped everything before calling).  Past the re-adoption admission
 * window it WAITS for the pending handoff to complete and then queues behind
 * the peer on a fresh attested acquire, instead of re-adopting the cached
 * grant ahead of the waiter.  Measured why this class must exist: with the
 * pinned rule applied to it, pregrant re-adopted, the restart's trylock was
 * refused by the gate, and the restart protocol spun 2.2 M times in one lap
 * (15 nodes blew the rsync budget on a FRESH fs).
 */
int
mxfs_ag_dlm_lock_resfree(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	/* The class is the CALLER's explicit contract (ruling: never infer it
	 * from ambient state).  The P271 seam arrives with a clean, rolled
	 * defer trans still current (journal_info != NULL) and ILOCKs handed
	 * off — resource-free by construction; a journal_info assertion here
	 * fired on every seam entry (0.21.3 kernel_health FAIL, 6 nodes). */
	return __mxfs_ag_dlm_lock(mp, pag, false, false, true);
}

/*
 * non-blocking AG-DLM acquire for the allocator's TRYLOCK pass.
 * Returns 0 if the AG is already held (nested/cached fast-path) or freshly
 * grantable without waiting; returns -EAGAIN if a peer holds it (caller
 * skips this AG).  Never blocks on a peer — this is what breaks the
 * ILOCK-vs-AG-DLM hold-and-wait deadlock in the create/write paths.
 */
int
mxfs_ag_dlm_trylock(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	return __mxfs_ag_dlm_lock(mp, pag, true, false, false);
}

/*
 * ABBA EDGE-2 FIX (instrumented — stack-PROVEN run36:
 * xfs_dir2_grow_inode → xfs_bmap_btalloc → xfs_alloc_vextent_start_ag with
 * trans_dirty=1 while the dir's DLM EX + ILOCK are necessarily held).  The
 * old blocking pass parked up to 61s (dlm.c 60×1.02s) on ONE peer-held AG;
 * when that peer's create held the AG via its trans-deferred unlock while
 * waiting for OUR dir, both -110'd at ~61s → dirty-cancel shutdowns (runs
 * 30/31/33/35).  A DIRTY trans can release neither the dir nor its AGs, so
 * the only deadlock-free move is to NOT insist on one AG: bounded nb-retry,
 * then report busy so xfs_alloc_vextent_prepare_ag's existing -EAGAIN path
 * skips to the NEXT AG (start_ag wraps all AGs).  Termination: the sweep
 * always reaches an AG this node already holds cached/active (own-affine at
 * minimum), whose fast-path acquire cannot block — so a full sweep cannot
 * come back empty-handed for lack of grants, only for lack of space.
 */
int
mxfs_ag_dlm_lock_bounded(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	int	tries = 40;	/* 40 × 100ms ≈ 4s per AG worst case */
	int	error;
	/*
	 * D-AGLOCK-...-LIVELOCK-488.  This loop is the caller that PROVED the
	 * livelock: 40 silent NOQUEUE probes generate no waiter bit and no
	 * BAST, so against peers that are merely CACHING their AGs (they
	 * release only when BASTed, by design) every try returns -EAGAIN, the
	 * sweep moves to the next AG, wraps, and repeats forever — measured at
	 * >190 laps over all 25 AGs on the 32-node rig with every peer idle.
	 *
	 * So this caller demands revocation.  Cadence is deliberately by WALL
	 * CLOCK rather than iteration count: the try interval is not the thing
	 * we want to bound, the rate of BAST-storm pressure on the fleet is.
	 * First try demands immediately (a real conflict should resolve in one
	 * demote round-trip), then no more often than ~500ms, jittered so 32
	 * nodes sweeping the same AG order do not synchronise their demands.
	 *
	 * Herd control lives here, at the requester, per the ruling: the sweep
	 * is sequential (~4s per AG), so at most one AG is under demand from
	 * this task at a time.
	 */
	u64	next_demand_ns = 0;

	do {
		u64	now = ktime_get_ns();
		bool	demand = (now >= next_demand_ns);

		if (demand)
			next_demand_ns = now + 500ULL * NSEC_PER_MSEC +
				(u64)get_random_u32_below(128) * NSEC_PER_MSEC;

		error = __mxfs_ag_dlm_lock(mp, pag, true, demand, false);
		if (error != -EAGAIN && error != -EWOULDBLOCK)
			return error;
		msleep(100);
	} while (--tries > 0);
	mxfs_probe_ratelimited(
		"mxfs: P5G-AGLOCK-BOUNDED-BUSY ag=%u comm=%s — peer-held past bound; skipping to next AG (dirty-trans grow path)\n",
		pag_agno(pag), current->comm);
	return -EAGAIN;
}

/*
 * -488 restart protocol: blocking, lock-neutral AG-DLM acquire+release.
 *
 * Called after the allocation's clean transaction has been CANCELLED and
 * every inode lock DROPPED — the caller holds NOTHING, so blocking here
 * cannot form a cycle: this node's own cached AGs remain drainable for
 * peers (their BAST workers only need locks we no longer hold).
 *
 * The blocking acquire registers a real waiter bit + demand multicast —
 * unlike the silent NOQUEUE probes of the trylock sweep, it BASTs the
 * idle cacher, which is the entire point.  On grant we immediately
 * release: mxfs_ag_dlm_unlock at holders 1->0 leaves the grant CACHED on
 * disk, so the caller's restarted allocation re-adopts this AG on the
 * fast path without another CAW round-trip.
 */
atomic64_t mxfs_dlm_stat_ag_pregrant = ATOMIC64_INIT(0);
int
xfs_mxfs_ag_pregrant(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_perag	*pag;
	int			error;

	/* Any live transaction here means the caller failed to cancel. */
	if (WARN_ON_ONCE(current->journal_info != NULL))
		return -EDEADLK;
	if (WARN_ON_ONCE(agno >= mp->m_sb.sb_agcount))
		return -EINVAL;

	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return -EINVAL;

	error = mxfs_ag_dlm_lock_resfree(mp, pag);
	if (!error) {
		mxfs_ag_dlm_unlock(mp, pag);
		atomic64_inc(&mxfs_dlm_stat_ag_pregrant);
		mxfs_probe_ratelimited(
			"mxfs: P270-AG-PREGRANT ag=%u comm=%s granted+cached (total=%lld)\n",
			agno, current->comm,
			(long long)atomic64_read(&mxfs_dlm_stat_ag_pregrant));
	} else {
		mxfs_probe_ratelimited(
			"mxfs: P270-AG-PREGRANT-FAIL ag=%u comm=%s rc=%d\n",
			agno, current->comm, error);
	}
	xfs_perag_put(pag);
	return error;
}

/*
 * Drain pag_mxfs_alloc_buflist (cluster buffers freshly initialized by
 * xfs_ialloc_inode_init under this AG's hold).  Splice to a local list,
 * submit synchronously, flush.  Bounded work, no global AIL drain.
 */
void
mxfs_dlm_ag_drain_alloc_buflist(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	LIST_HEAD(drain);
	/* P25-DRAIN (diagnostic): one node per
	 * multi-node run intermittently pays seconds per drain call
	 * (others ~2.5ms).  Attribute slow drains: mutex wait vs buf
	 * count vs submit wait vs device flush. */
	struct list_head *pos;
	unsigned int nbufs = 0;
	u64 tm0, t0, t1, t2;
	int werr;

	tm0 = ktime_get_ns();
	mutex_lock(&pag->pag_mxfs_alloc_buflist_lock);
	list_splice_init(&pag->pag_mxfs_alloc_buflist, &drain);
	pag->pag_mxfs_alloc_dirty = false;
	mutex_unlock(&pag->pag_mxfs_alloc_buflist_lock);

	if (!list_empty(&drain)) {
		list_for_each(pos, &drain)
			nbufs++;
		t0 = ktime_get_ns();
		/* v0.5.5: pin-aware submit — the plain blocking
		 * xfs_buf_delwri_submit sleeps in xfs_buf_wait_unpin with
		 * the buffer LOCK held when a concurrent create re-logs
		 * (re-pins) a hot cluster/AGI buf after our log force; the
		 * pinning CIL seq has no push driver until the 30 s log
		 * worker and the whole node convoys on the buf lock
		 * (stack-sample-proven 20-30 s scaling_curve stall). */
		werr = xfs_buf_delwri_submit_nopinwait(mp, &drain);
		t1 = ktime_get_ns();
		if (werr)
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: AG %u cluster delwri submit rc=%d",
				pag_agno(pag), werr);
		mxfs_blkdev_flush_epoch(mp);
		t2 = ktime_get_ns();
		if (t2 - tm0 > 20 * NSEC_PER_MSEC) {
			static atomic_t p25_drain_slow_cap = ATOMIC_INIT(0);
			if (atomic_inc_return(&p25_drain_slow_cap) <= 40)
				mxfs_probe("mxfs: P25-DRAIN-SLOW ag=%u bufs=%u mutex_ms=%llu submit_ms=%llu flush_ms=%llu\n",
					pag_agno(pag), nbufs,
					(unsigned long long)((t0 - tm0) / NSEC_PER_MSEC),
					(unsigned long long)((t1 - t0) / NSEC_PER_MSEC),
					(unsigned long long)((t2 - t1) / NSEC_PER_MSEC));
		}
	}
}

/*
 * v0.3.133 BUG FIX: async variant of drain_alloc_buflist for
 * the lazy_ag_drain=1 path.
 *
 * Final-loop discovery: the binary skip-or-drain in
 * mxfs_ag_dlm_unlock caused XFS log space exhaustion under heavy
 * create workloads (open-gpu rsync wedged in xlog_grant_head_wait).
 * Skipping the drain meant dirty AG-meta bufs sat in the per-AG
 * delwri queue without being submitted to disk; AIL items pinned to
 * those un-submitted bufs prevented log tail advancement; eventually
 * log space exhausted and all transactions blocked.
 *
 * The fix: lazy unlock should still SUBMIT bufs to disk (just async,
 * without waiting for completion).  Bufs trickle to disk in the
 * background; b_iodone fires; AIL items unpin; log tail advances;
 * no log starvation.  The "wait" is what we skip, not the "submit".
 *
 * This async variant uses xfs_buf_delwri_submit_nowait (same as
 * xfs_trans_ail.c:600 uses during AIL push) and skips the
 * blkdev_issue_flush.  Total cost per call is bounded by the size
 * of pag_mxfs_alloc_buflist, but the bufs are submitted async so
 * the caller doesn't block on their completion.
 */
void
mxfs_dlm_ag_drain_alloc_buflist_nowait(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	LIST_HEAD(drain);
	/* P25-DRAIN-NW: see P25-DRAIN-SLOW in the sync variant above. */
	u64 tm0, t0, t1;

	(void)mp;

	tm0 = ktime_get_ns();
	mutex_lock(&pag->pag_mxfs_alloc_buflist_lock);
	list_splice_init(&pag->pag_mxfs_alloc_buflist, &drain);
	pag->pag_mxfs_alloc_dirty = false;
	mutex_unlock(&pag->pag_mxfs_alloc_buflist_lock);
	t0 = ktime_get_ns();

	if (!list_empty(&drain)) {
		/*
		 * delwri_submit_nowait skips bufs that are currently pinned
		 * (BLI in CIL not yet flushed to log) and LEAVES THEM ON THE
		 * LIST.  See xfs_buf_delwri_submit_nowait at
		 * pal/linux/xfs_buf.c:2226-2229.
		 *
		 * v0.3.138 BUG FIX: if delwri_submit_nowait left bufs
		 * on the list (pinned), splice them back onto
		 * pag_mxfs_alloc_buflist so the next unlock cycle can retry
		 * draining them.  Without this, pinned bufs orphan: they
		 * still have _XBF_DELWRI_Q set, still referenced by AIL via
		 * BLI, but no longer reachable from any per-pag list — and
		 * the AG's bast work fn waiting in xfs_ail_push_ag_sync sees
		 * them as un-pushable forever.  This was the residual cause
		 * of the multi-node deadlock that survived v0.3.137's
		 * inode-bast per-AG fix.
		 */
		(void)xfs_buf_delwri_submit_nowait(&drain);
		t1 = ktime_get_ns();
		if (t1 - tm0 > 20 * NSEC_PER_MSEC) {
			static atomic_t p25_drainnw_slow_cap = ATOMIC_INIT(0);
			if (atomic_inc_return(&p25_drainnw_slow_cap) <= 40)
				mxfs_probe("mxfs: P25-DRAINNW-SLOW ag=%u mutex_ms=%llu submit_ms=%llu\n",
					pag_agno(pag),
					(unsigned long long)((t0 - tm0) / NSEC_PER_MSEC),
					(unsigned long long)((t1 - t0) / NSEC_PER_MSEC));
		}

		if (!list_empty(&drain)) {
			mutex_lock(&pag->pag_mxfs_alloc_buflist_lock);
			list_splice_tail(&drain, &pag->pag_mxfs_alloc_buflist);
			pag->pag_mxfs_alloc_dirty = true;
			mutex_unlock(&pag->pag_mxfs_alloc_buflist_lock);
		}
	}
}

/*
 * P85-INODE-DRAIN-SPLIT (instrumentation).
 *
 * mxfs_dlm_ag_drain_inode_buffers skips any inode-cluster buffer that is
 * already on somebody else's delwri queue (_XBF_DELWRI_Q) and any buffer
 * whose trylock fails.  BOTH skips were deliberately removed from the
 * AG-META drain years ago — v0.3.27 replaced trylock with a blocking lock
 * ("if xfsaild has the buf locked because it's mid-I/O, trylock would skip
 * and we'd release the DLM grant before xfsaild's I/O finishes"), and
 * v0.3.31 removed the delwri skip ("xfsaild runs asynchronously, may not
 * submit for seconds, and we release AG immediately after this drain").
 * They are still live in the INODE drain.
 *
 * That matters because the normal path by which a dinode's nlink=0 reaches
 * its cluster buffer IS xfsaild: xfs_inode_item_push -> xfs_iflush ->
 * xfs_buf_delwri_queue(bp, ail_buf_list).  At that instant _XBF_DELWRI_Q is
 * set, so the skipped buffer is the COMMON case, not the rare one.  Phase 3
 * then waits only on pag_dlm_meta_pending, which counts AG-META buffers
 * (mxfs_ag_meta_track) — inode-cluster buffers are not tracked there, so
 * nothing waits for them either.
 *
 * Meanwhile the AGI — carrying the new agi_unlinked bucket head — IS drained,
 * because it is an AG-meta buffer.  So AG release can publish an unlinked-list
 * head whose dinode home block still reads nlink!=0.  That is precisely the
 * split transition that makes the ACQUIRER's xfs_iunlink_reload_next see
 * i_nlink != 0 and return -EFSCORRUPTED inside an already-dirty rename
 * transaction (defect #361 / D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN);
 * see the design-consult ruling, interpretation "AGI new but dinode old on
 * the releaser -> release exposes a SPLIT transition".
 *
 * The probe FUA-reads each SKIPPED DIRTY inode buffer straight off the shared
 * LUN (piercing the iSCSI per-initiator cache) and reports every dinode in it
 * whose in-core image says nlink==0 while the medium still says nlink!=0 —
 * i.e. an inode this node has unlinked but whose home block has not yet been
 * published.  Runs only on the skip path, only when a dirty inode buffer was
 * actually skipped, and is gated by the `inode_drain_probe` module param.
 */
int mxfs_p85_drain_probe = 1;


/*
 * P86-AGI-UNLINKED-PUBLISH (instrumented).
 *
 * THE publication-point measurement for D-AGI-UNLINKED-CROSSNODE-RECOVERY-
 * SHUTDOWN / #361.  Run immediately before mxfs_v5_dlm_ag_unlock, i.e. at the
 * instant this AG becomes another node's to read.
 *
 * P85 measures whether a dirty inode-cluster BUFFER reached the medium.  It
 * cannot see the deeper hazard, because the two halves of xfs_iunlink travel
 * to the medium by DIFFERENT mechanisms:
 *
 *   - agi_unlinked[bucket] and the victim's di_next_unlinked are BUFFER-logged
 *     (xfs_trans_log_buf on the AGI buf / the inode cluster buf), so the
 *     existing drains cover them;
 *   - the victim's di_nlink = 0 comes from xfs_droplink, which dirties the
 *     INODE LOG ITEM.  It reaches the cluster buffer only when xfs_iflush runs
 *     — normally from xfsaild, asynchronously.  xfs_log_force(SYNC) at release
 *     makes it durable in OUR journal, which no peer ever replays.
 *
 * So if xfsaild has not pushed the inode yet, the cluster buffer is not dirty
 * at all: P85 records it as a clean skip, its in-core image and the medium
 * agree, and BOTH still say LINKED.  We then publish an AGI whose unlinked
 * bucket head points at an inode whose home dinode reads nlink != 0 — which is
 * exactly what makes the ACQUIRER's xfs_iunlink_reload_next return
 * -EFSCORRUPTED inside an already-dirty rename transaction.
 *
 * This probe therefore reads what the ACQUIRER will read: for every non-null
 * AGI unlinked bucket head, FUA-read that inode's home dinode straight off the
 * shared LUN and report its di_nlink.  It also reports the in-core inode's
 * i_nlink (radix-tree lookup, no reference taken — same existence argument as
 * xfs_iunlink_lookup) so the three views can be told apart:
 *
 *   disk_nlink != 0 && core_nlink == 0  -> SPLIT: we are publishing a linked
 *                                         home dinode as an unlinked-list head
 *   disk_nlink != 0 && core_nlink != 0  -> the AGI head itself is wrong
 *   disk_nlink == 0                     -> joint transition, correct
 *
 * Cost is bounded by the number of NON-EMPTY unlinked buckets, which is 0 for
 * an idle AG.  removed a release-time FUA readback that ran over every
 * cached AG-meta buffer at every release and stalled peer grants past 120s;
 * this is deliberately not that — it is gated, and it reads only the buckets a
 * peer is guaranteed to dereference.
 */
int mxfs_p86_agi_audit = 1;
/*
 * P87 enforcement.  The conversion stage in drain_inode_buffers uses
 * xfs_iflush_cluster, which is deliberately NON-blocking (xfs_ilock_nowait) so
 * it cannot re-enter the whole-AG ail_push deadlock.  That leaves a residual:
 * an inode whose ILOCK is held by another thread is skipped, and if it is still
 * skipped when the pass-until-quiescent loop hits its cap, we would unlock and
 * publish a split anyway.  Architectural Invariant 1 says a drain that did not
 * complete must never be followed by an on-disk unlock, and the design-consult ruling
 * is explicit: a timeout may diagnose, shut down or fence, but may NEVER be
 * followed by unlock.
 *
 * So the publication audit is also a REPAIR: for a head we KNOW is unlinked
 * (this node's in-core i_nlink == 0), retry the conversion for that one inode,
 * bounded, immediately before the unlock.
 */
int mxfs_p87_publish_retries = 3;
/*
 * aggregate repair budget per AG release, in ms.  Derivation (design-consult
 * ruling): every measured blocker was transient — an ILOCK held by a local
 * rm for ~tens of ms, a re-pin cleared by one log force — so 3000ms covers
 * them with two orders of magnitude of headroom, while the whole release
 * (drain + audit + repair) stays 40x under the 120s peer grant timeout the
 * timeout hierarchy must respect.  The one hold this can NOT outwait is an
 * ILOCK held across a CAW poll for a peer-held AG (up to 120s); waiting that
 * out from inside a release would risk the distributed circular wait, so the
 * deadline deliberately converts it into a refusal instead.
 */
int mxfs_p87_repair_budget_ms = 3000;
static atomic64_t mxfs_p86_heads = ATOMIC64_INIT(0);
static atomic64_t mxfs_p86_ok = ATOMIC64_INIT(0);
static atomic64_t mxfs_p86_split = ATOMIC64_INIT(0);
static atomic64_t mxfs_p86_badhead = ATOMIC64_INIT(0);
static atomic64_t mxfs_p86_repaired = ATOMIC64_INIT(0);
static unsigned long mxfs_p86_last;

/*
 * one bounded repair attempt for a single unlinked inode whose home
 * dinode still reads LINKED.  Returns true if the cluster buffer was found and
 * something was converted+written (caller re-reads the medium to decide).
 *
 * Only ever called for an inode this node holds in core with i_nlink == 0, i.e.
 * one we KNOW is unlinked — never on a head another node created, where our
 * in-core state carries no authority (see the SPLIT vs BADHEAD distinction).
 */
static bool
mxfs_p87_publish_repair(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	unsigned long		deadline)
{
	struct xfs_mount	*mp = pag_mount(pag);
	xfs_ino_t		ino = XFS_AGINO_TO_INO(mp, pag_agno(pag), agino);
	int			rc;

	/*
	 * REWRITE (design-consult ruling): the old body took the cluster
	 * buffer first and then let xfs_iflush_cluster TRYLOCK the target's
	 * ILOCK — measured losing all 3 tries to a local rm's ILOCK hold, with
	 * the flush landing 14ms after the third failure, post-unlock.  The
	 * mandatory target flush inverts the lock order (ILOCK before buffer)
	 * and makes every blocking stage deadline-aware, so a transient holder
	 * is WAITED OUT instead of raced.
	 */
	do {
		rc = mxfs_iflush_agino_target(pag, agino, deadline);
		if (rc != -EAGAIN)
			break;
		msleep(2);
	} while (time_before(jiffies, deadline));

	if (rc) {
		mxfs_probe_ratelimited("mxfs: P87-REPAIR-FAIL ino=%llu arm=target rc=%d\n",
				    (unsigned long long)ino, rc);
		return false;
	}
	mxfs_blkdev_flush_epoch(mp);
	return true;
}

/*
 * Read one inode's HOME dinode straight off the shared LUN, bypassing every
 * cache — this is exactly the read the ACQUIRER will perform.
 */
int
mxfs_p87_read_home_dinode(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	uint32_t		*nlink,
	uint32_t		*next_unl,
	uint32_t		*gen,
	uint16_t		*mode)
{
	struct xfs_mount	*mp = pag_mount(pag);
	uint32_t		isize = mp->m_sb.sb_inodesize;
	xfs_daddr_t		cdaddr;
	uint32_t		byteoff, secoff, len;
	uint64_t		lba;
	void			*tmp;
	struct xfs_dinode	*dp;
	int			rc;

	if (!isize)
		return -EINVAL;
	cdaddr = XFS_AGB_TO_DADDR(mp, pag_agno(pag),
				  XFS_AGINO_TO_AGBNO(mp, agino));
	byteoff = XFS_AGINO_TO_OFFSET(mp, agino) * isize;
	lba = (uint64_t)cdaddr + (byteoff >> BBSHIFT);
	secoff = byteoff & (BBSIZE - 1);
	len = roundup(secoff + isize, BBSIZE);
	lba += mp->m_ddev_targp->bt_sector_offset;

	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	/*
	 * read what the ACQUIRER reads.  Under mxfs_fua_disable
	 * (fleet default since) every peer read is a PLAIN read served
	 * from the shared target cache, so a COMPLETED conversion write is
	 * already visible cluster-wide; verifying with a FUA platter read here
	 * manufactured false "still LINKED" verdicts for every repair whose
	 * write sat in the target's write cache (the reread-linked loop then
	 * burned the whole aggregate budget and later heads failed rc=-110
	 * with tries=0).  Crash durability of the conversion is the journal's
	 * job, not this read's.
	 */
	{
		extern int mxfs_fua_disable;
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
							 uint64_t, void *,
							 uint32_t);

		rc = mxfs_fua_disable ?
			mxfs_pal_bdev_read_plain_bdev(mp->m_ddev_targp->bt_bdev,
						      lba, tmp, len) :
			mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev,
						    lba, tmp, len);
	}
	if (rc) {
		kfree(tmp);
		return rc < 0 ? rc : -EIO;
	}
	dp = (struct xfs_dinode *)((char *)tmp + secoff);
	if (be16_to_cpu(dp->di_magic) != MXFS_DINODE_MAGIC) {
		kfree(tmp);
		return -EFSCORRUPTED;
	}
	*nlink    = be32_to_cpu(dp->di_nlink);
	*next_unl = be32_to_cpu(dp->di_next_unlinked);
	*gen      = be32_to_cpu(dp->di_gen);
	*mode     = be16_to_cpu(dp->di_mode);
	kfree(tmp);
	return 0;
}

/*
 * P-AGIFC-RELEASE: platter-side AGI free-count audit at AG release.
 * Reads the AGI sector and the inobt / finobt ROOT blocks from the medium
 * exactly the way the next acquirer will (same read primitive as the P87
 * home-dinode read), sums the leaf records' ir_freecount (single-level trees
 * only — a leaf root) and compares with agi_freecount.  Fires only on a
 * disagreement: the 0.23.9 AG 0 / AG 5 "+1" divergence (agi_freecount ==
 * btree free + 1, published with ONE checkpoint LSN on all three blocks) is
 * either PUBLISHED here by the releaser — this audit names the tenure — or
 * IMPORTED by the acquirer (then this is clean and the in-core
 * P-AGIFC-MISMATCH at try_ag-entry fires on the peer).  Knob
 * agifc_release_audit (default 1) turns it off.  Diagnostic: three small
 * reads per release.
 */
int mxfs_agifc_release_audit_on = 1;
module_param_named(agifc_release_audit, mxfs_agifc_release_audit_on, int, 0644);
MODULE_PARM_DESC(agifc_release_audit,
	"platter AGI-freecount vs inobt/finobt audit at every AG release (0=off)");

/*
 * WHY THIS AUDIT'S SILENCE NEEDS A DENOMINATOR.
 *
 * The audit above prints only on a mismatch, and across all 938 retained
 * evidence directories it has never once printed with site=unmount.  That
 * reads as "the AGI was durable at every unmount release" -- but it equally
 * reads as "the audit declined every time", and until now nothing could tell
 * the two apart.  It has four silent exits: the mount is shutting down, the
 * mount is single-node, the read of the platter failed, or the btree has more
 * than one level and the leaf walk is not implemented.  Any of them returns
 * without a word.
 *
 * That matters because a critical open defect -- an AGI freecount that
 * disagrees with the inobt/finobt on the platter AFTER A CLEAN FLEET UNMOUNT
 * -- has carried an UNKNOWN mechanism for weeks while every clean sweep of
 * this audit was read as evidence against the unmount path.  A zero from an
 * instrument that may not have run is not evidence of anything.
 *
 * So count every exit by reason, and count the calls, and let the release
 * paths print the totals.  These are counters and not printks on purpose:
 * the audit runs per AG per release, and a per-call line would be another
 * six-figure tag in the row.
 */
static atomic64_t mxfs_agifc_audit_calls = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_ran = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_skip_off = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_skip_single = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_skip_shutdown = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_skip_read = ATOMIC64_INIT(0);
static atomic64_t mxfs_agifc_audit_skip_multilevel = ATOMIC64_INIT(0);

/*
 * the coverage line.  Printed by a release path once it has finished,
 * never per AG.  `ran` is the denominator every P-AGIFC-RELEASE-MISMATCH count
 * -- including a count of zero -- has to be quoted against.
 */
void
mxfs_agifc_audit_coverage(const char *site)
{
	mxfs_probe("mxfs: P482-AGIFC-AUDIT-COVERAGE site=%s calls=%lld ran=%lld skip_off=%lld skip_singlenode=%lld skip_shutdown=%lld skip_readfail=%lld skip_multilevel=%lld — 'ran' is the denominator for any RELEASE-MISMATCH count; a zero against ran=0 measures nothing\n",
		site,
		(long long)atomic64_read(&mxfs_agifc_audit_calls),
		(long long)atomic64_read(&mxfs_agifc_audit_ran),
		(long long)atomic64_read(&mxfs_agifc_audit_skip_off),
		(long long)atomic64_read(&mxfs_agifc_audit_skip_single),
		(long long)atomic64_read(&mxfs_agifc_audit_skip_shutdown),
		(long long)atomic64_read(&mxfs_agifc_audit_skip_read),
		(long long)atomic64_read(&mxfs_agifc_audit_skip_multilevel));
}

static int
mxfs_agifc_read_platter(
	struct xfs_mount	*mp,
	xfs_daddr_t		daddr,
	void			*buf,
	uint32_t		len)
{
	extern int mxfs_fua_disable;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	uint64_t		lba = (uint64_t)daddr +
					mp->m_ddev_targp->bt_sector_offset;

	return mxfs_fua_disable ?
		mxfs_pal_bdev_read_plain_bdev(mp->m_ddev_targp->bt_bdev, lba,
					      buf, len) :
		mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba,
					    buf, len);
}

/* Sum ir_freecount over a LEAF inobt/finobt block image; <0 = not a leaf. */
static int
mxfs_agifc_leaf_sum(
	struct xfs_mount	*mp,
	void			*blk,
	uint32_t		magic,
	int			*nrecs,
	uint64_t		*lsn)
{
	struct xfs_btree_block	*bb = blk;
	struct xfs_inobt_rec	*recs;
	int			n, i, sum = 0;

	if (be32_to_cpu(bb->bb_magic) != magic)
		return -1;
	if (be16_to_cpu(bb->bb_level) != 0)
		return -2;
	n = be16_to_cpu(bb->bb_numrecs);
	*nrecs = n;
	*lsn = be64_to_cpu(bb->bb_u.s.bb_lsn);
	recs = (struct xfs_inobt_rec *)((char *)blk + XFS_INOBT_BLOCK_LEN(mp));
	for (i = 0; i < n; i++)
		sum += recs[i].ir_u.sp.ir_freecount;
	return sum;
}

void
mxfs_agifc_release_audit(
	struct xfs_perag	*pag,
	const char		*site)
{
	static atomic_t		n_fired = ATOMIC_INIT(0);
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_agi		*agi;
	void			*agibuf = NULL, *ibt = NULL, *fin = NULL;
	struct xfs_buf		*bp = NULL;
	uint32_t		bsize = mp->m_sb.sb_blocksize;
	uint32_t		ibt_magic, fin_magic;
	int			ibt_sum = -9, fin_sum = -9, ibt_n = 0, fin_n = 0;
	uint64_t		ibt_lsn = 0, fin_lsn = 0;
	int			core_agi = -1, rc;

	/* the four silent exits, now counted by reason.  Order matters
	 * only for attribution, so test them separately rather than as one
	 * disjunction — a single combined skip count could not say whether the
	 * audit was off, alone, or shutting down. */
	atomic64_inc(&mxfs_agifc_audit_calls);
	if (!READ_ONCE(mxfs_agifc_release_audit_on) || !mp->m_mxfs_dlm) {
		atomic64_inc(&mxfs_agifc_audit_skip_off);
		return;
	}
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		atomic64_inc(&mxfs_agifc_audit_skip_single);
		return;
	}
	if (xfs_is_shutdown(mp)) {
		atomic64_inc(&mxfs_agifc_audit_skip_shutdown);
		return;
	}
	agibuf = kmalloc(BBSIZE, GFP_NOFS);
	ibt = kmalloc(bsize, GFP_NOFS);
	fin = kmalloc(bsize, GFP_NOFS);
	if (!agibuf || !ibt || !fin) {
		atomic64_inc(&mxfs_agifc_audit_skip_read);	/* */
		goto out;
	}
	rc = mxfs_agifc_read_platter(mp,
			XFS_AG_DADDR(mp, pag_agno(pag), XFS_AGI_DADDR(mp)),
			agibuf, BBSIZE);
	if (rc) {
		atomic64_inc(&mxfs_agifc_audit_skip_read);	/* */
		goto out;
	}
	agi = agibuf;
	if (be32_to_cpu(agi->agi_magicnum) != MXFS_AGI_MAGIC) {
		atomic64_inc(&mxfs_agifc_audit_skip_read);	/* */
		goto out;
	}
	if (be32_to_cpu(agi->agi_level) != 1 ||
	    (xfs_has_finobt(mp) && be32_to_cpu(agi->agi_free_level) != 1)) {
		/* multi-level: leaf walk not implemented.  counted,
		 * because on a grown filesystem this exit can silence the
		 * audit across every AG while its zero still reads as a pass. */
		atomic64_inc(&mxfs_agifc_audit_skip_multilevel);
		goto out;
	}
	/* past every early exit — this call actually inspects the
	 * platter, so it is one unit of the denominator. */
	atomic64_inc(&mxfs_agifc_audit_ran);
	ibt_magic = xfs_has_crc(mp) ? MXFS_IBT_CRC_MAGIC : MXFS_IBT_MAGIC;
	fin_magic = xfs_has_crc(mp) ? MXFS_FIBT_CRC_MAGIC : MXFS_FIBT_MAGIC;
	rc = mxfs_agifc_read_platter(mp,
			XFS_AGB_TO_DADDR(mp, pag_agno(pag),
					 be32_to_cpu(agi->agi_root)),
			ibt, bsize);
	if (rc)
		goto out;
	ibt_sum = mxfs_agifc_leaf_sum(mp, ibt, ibt_magic, &ibt_n, &ibt_lsn);
	if (xfs_has_finobt(mp)) {
		rc = mxfs_agifc_read_platter(mp,
				XFS_AGB_TO_DADDR(mp, pag_agno(pag),
						 be32_to_cpu(agi->agi_free_root)),
				fin, bsize);
		if (rc)
			goto out;
		fin_sum = mxfs_agifc_leaf_sum(mp, fin, fin_magic, &fin_n,
					      &fin_lsn);
	} else {
		fin_sum = ibt_sum;
	}
	if (ibt_sum < 0 || fin_sum < 0)
		goto out;
	if (ibt_sum == (int)be32_to_cpu(agi->agi_freecount) &&
	    fin_sum == ibt_sum)
		goto out;
	if (atomic_inc_return(&n_fired) > 400)
		goto out;
	/*
	 * In-core views, if resident and unlocked (trylock): the AGI buffer and
	 * the two root leaves.  core != platter on a leaf = an UNDRAINED leaf at
	 * unlock (Invariant #1); core == platter everywhere = the divergence is
	 * in the images themselves (stale-base RMW somewhere upstream).
	 */
	{
		struct {
			const char	*name;
			xfs_daddr_t	daddr;
			uint32_t	magic;
		} v[3] = {
			{ "agi", XFS_AG_DADDR(mp, pag_agno(pag), XFS_AGI_DADDR(mp)), 0 },
			{ "ibt", XFS_AGB_TO_DADDR(mp, pag_agno(pag), be32_to_cpu(agi->agi_root)), ibt_magic },
			{ "fin", XFS_AGB_TO_DADDR(mp, pag_agno(pag), be32_to_cpu(agi->agi_free_root)), fin_magic },
		};
		int	k;

		for (k = 0; k < (xfs_has_finobt(mp) ? 3 : 2); k++) {
			int	cval = -1, cn = 0;
			uint64_t clsn = 0;

			bp = NULL;
			if (xfs_buf_incore(mp->m_ddev_targp, v[k].daddr,
					   k == 0 ? XFS_FSS_TO_BB(mp, 1) :
						    XFS_FSB_TO_BB(mp, 1),
					   XBF_TRYLOCK, &bp) != 0 || !bp) {
				mxfs_probe("mxfs: P-AGIFC-RELEASE-COREBUF agno=%u %s=not-incore-or-locked\n",
					pag_agno(pag), v[k].name);
				continue;
			}
			if (k == 0) {
				struct xfs_agi *cagi = bp->b_addr;

				if (be32_to_cpu(cagi->agi_magicnum) == MXFS_AGI_MAGIC) {
					cval = be32_to_cpu(cagi->agi_freecount);
					clsn = be64_to_cpu(cagi->agi_lsn);
				}
				core_agi = cval;
			} else {
				cval = mxfs_agifc_leaf_sum(mp, bp->b_addr,
							   v[k].magic, &cn, &clsn);
			}
			mxfs_probe("mxfs: P-AGIFC-RELEASE-COREBUF agno=%u %s core_val=%d/%drecs core_lsn=%llx b_flags=0x%x pin=%d bli=%d bli_dirty=%d in_ail=%d li_lsn=%llx b_tenure=%llu b_gen=%llu\n",
				pag_agno(pag), v[k].name, cval, cn,
				(unsigned long long)clsn, bp->b_flags,
				atomic_read(&bp->b_pin_count),
				bp->b_log_item ? 1 : 0,
				(bp->b_log_item && (bp->b_log_item->bli_flags & XFS_BLI_DIRTY)) ? 1 : 0,
				(bp->b_log_item && test_bit(XFS_LI_IN_AIL, &bp->b_log_item->bli_item.li_flags)) ? 1 : 0,
				bp->b_log_item ? (unsigned long long)bp->b_log_item->bli_item.li_lsn : 0ULL,
				(unsigned long long)bp->b_tenure_id,
				(unsigned long long)bp->b_mxfs_ag_gen);
			xfs_buf_unlock(bp);
			xfs_buf_rele(bp);
		}
	}
	mxfs_probe("mxfs: P-AGIFC-RELEASE-MISMATCH site=%s agno=%u platter_agi_freecount=%u core_agi_freecount=%d pagi_freecount=%u ibt_sum=%d/%drecs fin_sum=%d/%drecs agi_count=%u agi_lsn=%llx ibt_lsn=%llx fin_lsn=%llx tenure=%llu mgen=%llu comm=%s realns=%llu — the AGI image about to be published disagrees with the btrees on the medium\n",
		site, pag_agno(pag), be32_to_cpu(agi->agi_freecount), core_agi,
		(unsigned)pag->pagi_freecount, ibt_sum, ibt_n, fin_sum, fin_n,
		be32_to_cpu(agi->agi_count),
		(unsigned long long)be64_to_cpu(agi->agi_lsn),
		(unsigned long long)ibt_lsn, (unsigned long long)fin_lsn,
		(unsigned long long)pag->ag_dlm_tenure_id,
		(unsigned long long)pag->pag_dlm_meta_gen,
		current->comm, (unsigned long long)ktime_get_real_ns());
out:
	kfree(agibuf);
	kfree(ibt);
	kfree(fin);
}

/*
 * Returns the number of unlinked-list heads we are about to publish that this
 * node KNOWS are unlinked but whose home dinode still reads LINKED, after
 * bounded repair.  Non-zero means we are about to violate the publication
 * invariant; the caller decides what to do about it.
 */
int
mxfs_p86_agi_unlinked_publish_audit(
	struct xfs_perag	*pag)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buf		*agibp = NULL;
	struct xfs_agi		*agi;
	unsigned int		i, heads = 0, split = 0, badhead = 0, ok = 0;
	unsigned int		repaired = 0;
	xfs_agino_t		bucket[XFS_AGI_UNLINKED_BUCKETS];
	bool			snapped = false;
	unsigned long		deadline = jiffies +
				msecs_to_jiffies(mxfs_p87_repair_budget_ms);

	const char		*headwalk_skip = NULL;

	if (mp->m_sb.sb_inodesize == 0)
		return 0;
	/*
	 * (0.39.3, instrumented — s436 P-FREEOB-XRELEASE path=bast-inline
	 * free=1 six ms after a P55C-FREE-DENIED, with NO audit line): the
	 * early returns below used to skip the WHOLE audit, obligations
	 * included, whenever the AGI buffer was not in core or its trylock
	 * lost a race.  The head walk needs the AGI snapshot; the obligation
	 * enforcement (unlink, FREE-PUBLISH) does not — it
	 * must run on every release.  Skip only the head walk, loudly.
	 */
	if (!mxfs_p86_agi_audit) {
		headwalk_skip = "knob-off";
		goto obligations;
	}
	if (xfs_buf_incore(mp->m_ddev_targp,
			   XFS_AG_DADDR(mp, pag_agno(pag), XFS_AGI_DADDR(mp)),
			   XFS_FSS_TO_BB(mp, 1), XBF_TRYLOCK, &agibp) != 0 ||
	    !agibp) {
		headwalk_skip = agibp ? "agi-trylock" : "agi-not-incore";
		agibp = NULL;
		goto obligations;
	}
	agi = agibp->b_addr;
	if (be32_to_cpu(agi->agi_magicnum) == MXFS_AGI_MAGIC) {
		for (i = 0; i < XFS_AGI_UNLINKED_BUCKETS; i++)
			bucket[i] = be32_to_cpu(agi->agi_unlinked[i]);
		snapped = true;
	}
	/*
	 * LOCK ORDER: snapshot the buckets and DROP the AGI buffer
	 * before doing anything else.  The repair path calls xfs_log_force and
	 * xfs_imap; with flags=0 xfs_imap still falls through to
	 * xfs_imap_lookup (an inobt btree read, which reads the AGI) whenever
	 * blocks_per_cluster > 1 and inoalign_mask == 0, and a log force can
	 * drive an AIL push that wants the AGI too.  Either one would deadlock
	 * against the buffer lock we are holding.  Nothing can change the list
	 * underneath us: we still hold the AG DLM EX and pag_dlm_demoting is
	 * set, so no peer and no local acquirer can touch this AG.
	 */
	xfs_buf_unlock(agibp);
	xfs_buf_rele(agibp);
	if (!snapped) {
		headwalk_skip = "agi-bad-magic";
		goto obligations;
	}

	for (i = 0; i < XFS_AGI_UNLINKED_BUCKETS; i++) {
		xfs_agino_t	agino = bucket[i];
		struct xfs_inode *ip;
		uint32_t	disk_nl = 0, disk_next = 0, dgen = 0;
		uint16_t	dmode = 0;
		int		core_nl = -1;
		int		tries;

		if (agino == NULLAGINO)
			continue;
		heads++;

		if (mxfs_p87_read_home_dinode(pag, agino, &disk_nl, &disk_next,
					      &dgen, &dmode) != 0)
			continue;
		if (disk_nl == 0) {
			ok++;
			continue;
		}

		/*
		 * The medium says LINKED.  Does THIS node know otherwise?
		 *
		 * CAREFUL: xfs_iunlink_lookup can take no reference
		 * because its caller holds the AGI buffer lock, which pins
		 * unlinked-list membership.  The lock-order fix above RELEASED
		 * the AGI, so that argument does NOT hold here and this cannot
		 * be a straight copy of it.  RCU keeps the xfs_inode memory
		 * alive (xfs_inode_free_callback frees it via call_rcu), but it
		 * does NOT stop the inode being reclaimed and REUSED for a
		 * different ino — and a reused inode that happens to read
		 * i_nlink == 0 would make us misclassify a BADHEAD as a SPLIT
		 * and "repair" on an authority we do not have.
		 *
		 * So re-check identity after the lookup and reject anything in
		 * or heading for reclaim.  Failing these leaves core_nl at -1,
		 * i.e. BADHEAD — report, do not touch.  Fail-safe direction:
		 * the only cost of being wrong here is declining to repair.
		 */
		rcu_read_lock();
		ip = radix_tree_lookup(&pag->pag_ici_root, agino);
		if (ip &&
		    ip->i_ino == XFS_AGINO_TO_INO(mp, pag_agno(pag), agino) &&
		    !__xfs_iflags_test(ip, XFS_IRECLAIM | XFS_IRECLAIMABLE))
			core_nl = (int)VFS_I(ip)->i_nlink;
		rcu_read_unlock();

		if (core_nl != 0) {
			/*
			 * BADHEAD: we never had this inode in core, so we have
			 * no authority to "repair" it — most likely we did not
			 * create this head and are merely re-publishing an AGI
			 * another node left bad.  Report, do not touch.
			 */
			badhead++;
			mxfs_probe("mxfs: P86-AGI-UNLINKED-BADHEAD ag=%u bucket=%u agino=0x%x ino=%llu disk_nlink=%u disk_next=0x%x core_nlink=%d disk_gen=%u disk_mode=0x%x — unlinked-list head reads LINKED on the medium and is NOT in this node's cache; we did not create it\n",
				pag_agno(pag), i, agino,
				(unsigned long long)XFS_AGINO_TO_INO(mp,
					pag_agno(pag), agino),
				disk_nl, disk_next, core_nl, dgen, dmode);
			continue;
		}

		/*
		 * SPLIT: this node unlinked it and has not published it.  Ours
		 * to fix, and Invariant 1 says we must not unlock until we do.
		 * one AGGREGATE deadline per audit walk (design-consult
		 * ruling — per-head deadlines can stack past the DLM grant
		 * timeout); the mandatory target flush inside waits out
		 * transient ILOCK/pin holders instead of racing them.
		 */
		for (tries = 0; ; tries++) {
			if (!mxfs_p87_publish_repair(pag, agino, deadline)) {
				if (time_after(jiffies, deadline))
					break;
				msleep(2);
				continue;
			}
			if (mxfs_p87_read_home_dinode(pag, agino, &disk_nl,
						      &disk_next, &dgen,
						      &dmode) == 0 &&
			    disk_nl == 0)
				break;
			/* Wrote the cluster buffer, flushed, and the medium
			 * STILL reads LINKED — the conversion wrote a stale
			 * in-core image or the FUA re-read raced.  A distinct
			 * arm from every repair-refused case above. */
			mxfs_probe_ratelimited("mxfs: P87-REPAIR-FAIL ino=%llu arm=reread-linked nl=%u\n",
					    (unsigned long long)XFS_AGINO_TO_INO(mp,
						pag_agno(pag), agino), disk_nl);
			if (time_after(jiffies, deadline))
				break;
			msleep(2);
		}
		if (disk_nl == 0) {
			repaired++;
			ok++;
			mxfs_probe_ratelimited("mxfs: P87-PUBLISH-REPAIRED ag=%u bucket=%u agino=0x%x tries=%d — home dinode converted and written before unlock\n",
				pag_agno(pag), i, agino, tries + 1);
			continue;
		}

		split++;
		pr_warn("mxfs: P86-AGI-UNLINKED-PUBLISH ag=%u bucket=%u agino=0x%x ino=%llu disk_nlink=%u disk_next=0x%x core_nlink=0 disk_gen=%u disk_mode=0x%x tries=%d — publishing an unlinked-list head whose HOME dinode still reads LINKED; the acquirer's xfs_iunlink_reload_next will call this AGI corruption\n",
			pag_agno(pag), i, agino,
			(unsigned long long)XFS_AGINO_TO_INO(mp, pag_agno(pag),
							     agino),
			disk_nl, disk_next, dgen, dmode, tries);
	}

obligations:
	if (headwalk_skip)
		mxfs_probe_ratelimited("mxfs: P86-HEADWALK-SKIPPED ag=%u reason=%s pubob=%d — unlinked-list head walk skipped (no AGI snapshot); obligation enforcement runs regardless\n",
			pag_agno(pag), headwalk_skip, mp->m_mxfs_pubob_count);
	/*
	 * enforce publication obligations for THIS AG — the head walk
	 * above cannot see mid-chain members (test22's killer was one).  Every
	 * inode this node put on the on-disk list whose conversion has not been
	 * verified written gets the mandatory target flush + FUA verify here;
	 * one that cannot be converted (shell gone — the inactivation-leak
	 * family — or repair timeout) counts as an unrepaired split so the
	 * refuse-unlock escalation covers it.
	 */
	if (mp->m_mxfs_pubob_count) {
		struct mxfs_pubob *ob;
		xfs_agino_t	*oag;
		uint64_t	*oino;
		uint8_t		*okind;
		uint32_t	*ogenv;
		uint64_t	*oepochv;
		uint16_t	*ochain;
		int		 nob = 0, cap, k;
		int		 free_split = 0;
		int		 free_fatal = 0;	/* D-0524 */
		uint64_t	 rel_ep = READ_ONCE(pag->pag_mxfs_rel_epoch);

		spin_lock(&mp->m_mxfs_pubob_lock);
		cap = mp->m_mxfs_pubob_count;
		spin_unlock(&mp->m_mxfs_pubob_lock);
		oag = kmalloc_array(cap, sizeof(*oag), GFP_NOFS);
		oino = kmalloc_array(cap, sizeof(*oino), GFP_NOFS);
		okind = kmalloc_array(cap, sizeof(*okind), GFP_NOFS);
		ogenv = kmalloc_array(cap, sizeof(*ogenv), GFP_NOFS);
		oepochv = kmalloc_array(cap, sizeof(*oepochv), GFP_NOFS);
		ochain = kmalloc_array(cap, sizeof(*ochain), GFP_NOFS);
		if (oag && oino && okind && ogenv && oepochv && ochain) {
			spin_lock(&mp->m_mxfs_pubob_lock);
			list_for_each_entry(ob, &mp->m_mxfs_pubob_list, l) {
				if (ob->agno != pag_agno(pag))
					continue;
				if (nob >= cap)
					break;
				oag[nob] = ob->agino;
				oino[nob] = ob->ino;
				okind[nob] = ob->kind;
				ogenv[nob] = ob->gen;
				oepochv[nob] = ob->epoch;
				ochain[nob] = ob->chain;
				nob++;
			}
			spin_unlock(&mp->m_mxfs_pubob_lock);
		}
		for (k = 0; k < nob; k++) {
			uint32_t	onl = 0, onext = 0, ogen = 0;
			uint16_t	omode = 0;
			bool		shell;
			struct xfs_inode *oip;

			/*
			 * (D-0351): FREE obligations — the FREE-PUBLISH
			 * invariant is enforced HERE, at the AG handoff.  A
			 * pending free (ifree in flight) only defers; a
			 * committed free is published through the mandatory
			 * target flush (P55C honours this worker's retiring
			 * token) after an out-of-cache predecessor check.
			 */
			if (okind[k] == MXFS_PUBOB_FREE_PENDING) {
				/*
				 * (D-0524, design-consult ruling Q5): a genuine
				 * in-flight ifree holds this AG's EX (holders > 0),
				 * so the release gate cannot be running — a
				 * FREE_PENDING entry seen HERE is failed
				 * bookkeeping, never ordinary work.  The one shape
				 * measured (chain 88): the ifree committed
				 * (MXFS_IF_FREE_COMMITTED on the shell) but the
				 * commit's FREE was overwritten.  Self-heal it —
				 * promote to FREE under the tenure the ifree began
				 * in, which must be the tenure this release retires
				 * — and audit it as FREE in this same lap, loudly.
				 * An orphan (no shell: impossible, reclaim refuses
				 * PUBOB inodes) or a cross-tenure pending entry is
				 * a protocol violation: refuse the release at once
				 * (pag_mxfs_freeob_fatal), no 20 s defer.  Only an
				 * UNCOMMITTED pending entry keeps the bounded
				 * deferral, because a hole in the holder reasoning
				 * would otherwise cost a node for a race that
				 * resolves in milliseconds.
				 */
				struct xfs_inode *pip;
				struct mxfs_pubob *pob;
				bool found = false, shell_ok = false, committed = false;
				bool promoted = false;
				uint64_t pend_ep = 0;
				uint32_t pgen = 0;
				const char *why;

				rcu_read_lock();
				pip = radix_tree_lookup(&pag->pag_ici_root, oag[k]);
				if (pip && pip->i_ino == oino[k]) {
					found = true;
					spin_lock(&pip->i_flags_lock);
					shell_ok = !__xfs_iflags_test(pip, XFS_IRECLAIM | XFS_INEW);
					committed = shell_ok &&
						__xfs_iflags_test(pip, MXFS_IF_FREE_COMMITTED);
					pgen = VFS_I(pip)->i_generation;
					spin_unlock(&pip->i_flags_lock);
				}
				spin_lock(&mp->m_mxfs_pubob_lock);
				pob = mxfs_pubob_find_locked(mp, oino[k]);
				if (pob && pob->kind == MXFS_PUBOB_FREE_PENDING) {
					pend_ep = pob->pending_epoch;
					if (committed && rel_ep && pend_ep == rel_ep) {
						pob->kind = MXFS_PUBOB_FREE;
						pob->gen = pgen;
						pob->epoch = pend_ep;
						pob->pending_epoch = 0;
						WRITE_ONCE(pip->i_mxfs_freeob, 2);
						promoted = true;
					}
				} else if (pob) {
					/* moved on since the snapshot (commit landed) */
					okind[k] = pob->kind;
					ogenv[k] = pob->gen;
					oepochv[k] = pob->epoch;
					ochain[k] = pob->chain;
					promoted = (pob->kind == MXFS_PUBOB_FREE);
					pgen = pob->gen;
					pend_ep = pob->epoch;
				}
				spin_unlock(&mp->m_mxfs_pubob_lock);
				rcu_read_unlock();
				if (promoted) {
					pr_err("mxfs: P-FREEOB-PENDING-COMMITTED ag=%u ino=%llu gen=%u epoch=%llu — FREE_PENDING at the release gate with the ifree already COMMITTED (D-0524 lost update); promoted to FREE and audited now\n",
						pag_agno(pag), (unsigned long long)oino[k],
						pgen, (unsigned long long)pend_ep);
					okind[k] = MXFS_PUBOB_FREE;
					ogenv[k] = pgen;
					oepochv[k] = pend_ep;
					/* fall through to the FREE arm below */
				} else if (!pob) {
					continue;	/* discharged meanwhile */
				} else if (okind[k] != MXFS_PUBOB_FREE_PENDING) {
					if (okind[k] == MXFS_PUBOB_CHAIN_LIVE)
						continue;
					/* UNLINK: audited by the tail of this loop */
				} else if (found && shell_ok && !committed) {
					free_split++;
					mxfs_probe_ratelimited("mxfs: P-FREEOB-PENDING ag=%u ino=%llu — ifree pending at AG release with no commit on the shell; deferring the unlock (should be unreachable: the ifree holds the AG EX)\n",
						pag_agno(pag), (unsigned long long)oino[k]);
					continue;
				} else {
					why = !found ? "no in-core shell" :
					      !shell_ok ? "shell in reclaim" :
					      !rel_ep ? "no retiring tenure" :
					      "pending tenure is not the retiring tenure";
					free_split++;
					free_fatal++;
					pr_err("mxfs: P-FREEOB-PENDING-FATAL ag=%u ino=%llu committed=%d pending_epoch=%llu rel_epoch=%llu — %s; FREE-PUBLISH bookkeeping violated, refusing the release without deferral\n",
						pag_agno(pag), (unsigned long long)oino[k],
						committed ? 1 : 0,
						(unsigned long long)pend_ep,
						(unsigned long long)rel_ep, why);
					continue;
				}
				/* FREE: the FREE arm below audits it now; UNLINK
				 * (re-snapshot) falls through to the unlink audit. */
			}
			/* a chained LIVE life owes nothing to FREE-PUBLISH
			 * (the inobt says allocated); the entry only carries the
			 * chain provenance for that life's later free. */
			if (okind[k] == MXFS_PUBOB_CHAIN_LIVE)
				continue;
			if (okind[k] == MXFS_PUBOB_FREE) {
				int frc = mxfs_p87_read_home_dinode(pag, oag[k], &onl,
								    &onext, &ogen, &omode);

				if (frc) {
					free_split++;
					mxfs_probe_ratelimited("mxfs: P-FREEOB-READ-FAIL ag=%u ino=%llu rc=%d — cannot verify the home dinode; deferring\n",
						pag_agno(pag), (unsigned long long)oino[k], frc);
					continue;
				}
				rcu_read_lock();
				oip = radix_tree_lookup(&pag->pag_ici_root, oag[k]);
				shell = oip && oip->i_ino == oino[k] &&
					!__xfs_iflags_test(oip, XFS_IRECLAIM);
				if (!shell)
					oip = NULL;
				rcu_read_unlock();
				/* mode 0 at ANY gen = published (random
				 * alloc gen + free ++ : a never-written short-lived
				 * incarnation leaves the OLDER free image at home) */
				if (omode == 0) {
					mxfs_pubob_drop_ino(mp, oino[k]);
					if (oip) {
						WRITE_ONCE(oip->i_mxfs_freeob, 0);
						xfs_iflags_clear(oip, MXFS_IF_PUBOB |
								 MXFS_IF_PUBOB_FLUSHED);
					}
					continue;
				}
				/* (D-0351 chain): a chained free's home image
				 * at another gen is one of this node's own earlier
				 * lives when the obligation's tenure is the one this
				 * release retires (rel_ep) — published like the exact
				 * predecessor.  FOREIGN only otherwise. */
				if (!(omode != 0 &&
				      (ogen == (uint32_t)(ogenv[k] - 1u) ||
				       (ochain[k] && rel_ep && oepochv[k] == rel_ep)))) {
					bool live = oip && VFS_I(oip)->i_mode != 0;

					mxfs_probe("mxfs: P-FREEOB-FOREIGN ag=%u ino=%llu gen=%u disk_gen=%u disk_mode=0%o chain=%u ob_epoch=%llu rel_epoch=%llu live_shell=%d — home dinode is not the incarnation this node freed (FREE-PUBLISH crossed earlier); never writing; discharging\n",
						pag_agno(pag), (unsigned long long)oino[k],
						ogenv[k], ogen, omode, ochain[k],
						(unsigned long long)oepochv[k],
						(unsigned long long)rel_ep, live ? 1 : 0);
					mxfs_pubob_drop_ino(mp, oino[k]);
					if (oip) {
						/* never write-poison a LIVE inode
						 * (s433: one P32D-DEADINCARN-SKIP on
						 * a live file after this branch) */
						if (!live)
							oip->i_mxfs_dead_incarn_gen = ogen ? ogen : 1;
						WRITE_ONCE(oip->i_mxfs_freeob, 0);
						xfs_iflags_clear(oip, MXFS_IF_PUBOB |
								 MXFS_IF_PUBOB_FLUSHED);
					}
					continue;
				}
				if (ochain[k] && ogen != (uint32_t)(ogenv[k] - 1u))
					mxfs_probe_ratelimited("mxfs: P-FREEOB-CHAIN ag=%u ino=%llu gen=%u disk_gen=%u chain=%u — chained free: home holds an earlier own life; publishing under the retiring tenure\n",
						pag_agno(pag), (unsigned long long)oino[k],
						ogenv[k], ogen, ochain[k]);
				if (!oip) {
					free_split++;
					mxfs_probe("mxfs: P-FREEOB-NOSHELL ag=%u ino=%llu gen=%u disk_gen=%u — committed free with no in-core shell (should be unreachable: P55C never launders a valid free); unrepairable from this node\n",
						pag_agno(pag), (unsigned long long)oino[k],
						ogenv[k], ogen);
					continue;
				}
				if (mxfs_p87_publish_repair(pag, oag[k], deadline) &&
				    mxfs_p87_read_home_dinode(pag, oag[k], &onl, &onext,
							      &ogen, &omode) == 0 &&
				    omode == 0 && ogen == ogenv[k]) {
					repaired++;
					mxfs_pubob_drop_ino(mp, oino[k]);
					WRITE_ONCE(oip->i_mxfs_freeob, 0);
					xfs_iflags_clear(oip, MXFS_IF_PUBOB |
							 MXFS_IF_PUBOB_FLUSHED);
					mxfs_probe_ratelimited("mxfs: P-FREEOB-PUBLISHED ag=%u ino=%llu gen=%u — free dinode written and verified before the unlock (FREE-PUBLISH)\n",
						pag_agno(pag), (unsigned long long)oino[k],
						ogenv[k]);
				} else {
					free_split++;
					mxfs_probe("mxfs: P-FREEOB-UNPUBLISHED ag=%u ino=%llu gen=%u disk_gen=%u disk_mode=0%o — free image still not at home after the mandatory target flush; deferring the unlock\n",
						pag_agno(pag), (unsigned long long)oino[k],
						ogenv[k], ogen, omode);
				}
				continue;
			}
			if (mxfs_p87_read_home_dinode(pag, oag[k], &onl,
						      &onext, &ogen,
						      &omode) != 0)
				continue;
			if (onl == 0) {
				/* Conversion is home: discharge lazily. */
				mxfs_pubob_drop_ino(mp, oino[k]);
				rcu_read_lock();
				oip = radix_tree_lookup(&pag->pag_ici_root,
							oag[k]);
				if (oip && oip->i_ino == oino[k])
					xfs_iflags_clear(oip, MXFS_IF_PUBOB |
							 MXFS_IF_PUBOB_FLUSHED);
				rcu_read_unlock();
				continue;
			}
			rcu_read_lock();
			oip = radix_tree_lookup(&pag->pag_ici_root, oag[k]);
			shell = oip && oip->i_ino == oino[k] &&
				!__xfs_iflags_test(oip, XFS_IRECLAIM);
			rcu_read_unlock();
			if (!shell) {
				split++;
				pr_warn("mxfs: P88-PUBOB-NOSHELL ag=%u agino=0x%x ino=%llu disk_nlink=%u disk_next=0x%x — obligation with no in-core inode; conversion is unrepairable from this node (inactivation-leak family), refusing counts it as a split\n",
					pag_agno(pag), oag[k],
					(unsigned long long)oino[k], onl, onext);
				continue;
			}
			if (mxfs_p87_publish_repair(pag, oag[k], deadline) &&
			    mxfs_p87_read_home_dinode(pag, oag[k], &onl,
						      &onext, &ogen,
						      &omode) == 0 &&
			    onl == 0) {
				repaired++;
				mxfs_pubob_drop_ino(mp, oino[k]);
				mxfs_probe_ratelimited("mxfs: P88-PUBOB-REPAIRED ag=%u agino=0x%x ino=%llu — mid-chain conversion written before unlock\n",
					pag_agno(pag), oag[k],
					(unsigned long long)oino[k]);
			} else {
				split++;
				mxfs_probe("mxfs: P88-PUBOB-UNREPAIRED ag=%u agino=0x%x ino=%llu disk_nlink=%u — obligation still LINKED on the medium after the mandatory target flush\n",
					pag_agno(pag), oag[k],
					(unsigned long long)oino[k], onl);
			}
		}
		kfree(oag);
		kfree(oino);
		kfree(okind);
		kfree(ogenv);
		kfree(oepochv);
		kfree(ochain);
		WRITE_ONCE(pag->pag_mxfs_freeob_split, free_split);
		WRITE_ONCE(pag->pag_mxfs_freeob_fatal, free_fatal);
		split += free_split;
	}

	if (heads || split || repaired) {
		atomic64_add(heads, &mxfs_p86_heads);
		atomic64_add(ok, &mxfs_p86_ok);
		atomic64_add(split, &mxfs_p86_split);
		atomic64_add(badhead, &mxfs_p86_badhead);
		atomic64_add(repaired, &mxfs_p86_repaired);
		if (printk_timed_ratelimit(&mxfs_p86_last, 30 * 1000))
			mxfs_probe("mxfs: P86-AGI-PUBLISH-TOTALS heads=%lld joint_ok=%lld REPAIRED=%lld SPLIT=%lld BADHEAD=%lld\n",
				(long long)atomic64_read(&mxfs_p86_heads),
				(long long)atomic64_read(&mxfs_p86_ok),
				(long long)atomic64_read(&mxfs_p86_repaired),
				(long long)atomic64_read(&mxfs_p86_split),
				(long long)atomic64_read(&mxfs_p86_badhead));
	}
	return split;
}

/*
 * Walk pag_bcache for inode cluster buffers with pending iflush activity
 * (b_li_list non-empty, not already on a delwri queue) and submit them
 * synchronously.  Bounded by AG-resident buffers; closes the cross-node
 * cluster-buffer coherency window before we release the DLM AG grant.
 */
int mxfs_p87_publish_inodes = 1;

/*
 * does this INODE cluster buffer have anything pending for the
 * medium?  See the predicate note in mxfs_dlm_ag_drain_inode_buffers.
 * Caller may hold the buffer lock or not; all three tests are single reads.
 */
static bool
mxfs_inode_buf_needs_write(struct xfs_buf *bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;

	return (bp->b_flags & _XBF_DELWRI_Q) || xfs_buf_ispinned(bp) || bip;
}

void
mxfs_dlm_ag_drain_inode_buffers(
	struct xfs_perag	*pag)
{
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		qd = 0;
	unsigned int		pass_writes, passes = 0;
	/* P85 census — the verification instrument for this fix. */
	unsigned int		p85_inode = 0, p85_clean = 0, p85_allocq = 0;
	unsigned int		p85_delwri = 0, p85_locked = 0, p85_nohold = 0;
	unsigned int		p85_pinned = 0, p85_werr = 0;
	unsigned int		p85_iflushed = 0, p85_ferr = 0;

	/*
	 * FIX (HOLE 1) — this drain is now structurally identical to
	 * mxfs_dlm_ag_drain_meta_buffers.  It previously skipped
	 *
	 *   (a) any buffer with _XBF_DELWRI_Q set,
	 *   (b) any buffer whose trylock failed,
	 *   (c) any buffer with an empty b_li_list, with no pinned/BLI
	 *       fallthrough,
	 *
	 * all three of which were removed from the AG-META drain years ago
	 * after they each caused cross-node corruption: (a) in v0.3.31
	 * ("xfsaild runs asynchronously, may not submit for seconds, and we
	 * release AG immediately after this drain"), (b) in v0.3.27 ("if
	 * xfsaild has the buf locked because it's mid-I/O, trylock would skip
	 * and we'd release the DLM grant before xfsaild's I/O finishes"), and
	 * (c) in / (the committed-to-CIL-but-not-yet-
	 * in-AIL window is PINNED or BLI-attached, not clean).
	 *
	 * They mattered more here than they did for AG-meta, because the normal
	 * route by which a dinode reaches its cluster buffer IS xfsaild:
	 * xfs_inode_item_push -> xfs_iflush -> xfs_buf_delwri_queue.  At that
	 * instant _XBF_DELWRI_Q is set and the buffer is locked for submit, so
	 * the skipped buffer was the COMMON case, not the rare one.  Nor did
	 * anything else wait for it: Phase 3 waits only on pag_dlm_meta_pending,
	 * which counts AG-META buffers registered via mxfs_ag_meta_track.
	 *
	 * MEASURED before this fix (P85, 32/caw, one all-PASS lap): 34 dirty
	 * inode-cluster buffers skipped at AG release, and 10 of the 23 that
	 * could be FUA-read back still differed from in-core at the instant of
	 * release.  Architectural Invariant 1 violated on a green board.
	 *
	 * xfs_bwrite is synchronous (waits the bio) and already calls
	 * xfs_force_shutdown(SHUTDOWN_META_IO_ERROR) on failure, so a write we
	 * cannot complete can no longer be followed by a DLM unlock that
	 * publishes stale metadata — the fail-closed property the previous
	 * xfs_buf_delwri_submit path did not have (it only logged).
	 *
	 * NOTE this fixes only buffers that xfs_iflush has ALREADY populated.
	 * The AG release path still has no inode-log-item -> cluster-buffer
	 * conversion stage at all (HOLE 2, probe P86) — see
	 * mxfs_p86_agi_unlinked_publish_audit.
	 */
	do {
	pass_writes = 0;
	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			bool	got;
			int	werr;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (bp->b_ops != &xfs_inode_buf_ops &&
			    bp->b_ops != &xfs_inode_buf_ra_ops)
				continue;
			p85_inode++;

			/*
			 * (ruling item 2c): _XBF_DELWRI_Q says "on some
			 * delwri protocol", not WHICH list owns the b_list
			 * linkage and its reference.  mxfs queues its own fresh
			 * cluster buffers to pag_mxfs_alloc_buflist and marks
			 * them _XBF_MXFS_ALLOC_QUEUED.  That list has its own
			 * sanctioned drain, which ran immediately before us
			 * (Phase 2b order); a partially initialised allocation
			 * buffer must not be submitted from here, and one
			 * b_list linkage must never be treated as belonging to
			 * both queues.  Assert ownership via the mxfs flag —
			 * never infer it from _XBF_DELWRI_Q.
			 */
			if (bp->b_flags & _XBF_MXFS_ALLOC_QUEUED) {
				p85_allocq++;
				continue;
			}
			if (bp->b_flags & _XBF_DELWRI_Q)
				p85_delwri++;

			/*
			 * PREDICATE (measured, P85-LATEPASS): a
			 * non-empty b_li_list does NOT mean an INODE cluster
			 * buffer needs writing.  For an AG-meta buffer
			 * b_li_list carries the buf log item, which iodone
			 * releases — so the meta drain's predicate self-clears.
			 * For an inode cluster buffer b_li_list carries the
			 * INODE log items attached by xfs_iflush, and those
			 * survive the write.  Copying the meta predicate here
			 * made the write condition permanently true: the drain
			 * rewrote the same buffer every pass and hit the pass
			 * cap on 133 of 423 releases while the meta drain hit
			 * it 0 times.  All 423 late-pass writes reported the
			 * identical post-write state — pin=0 bip=0 inail=0,
			 * li_empty=0 — i.e. nothing pending, list still there.
			 *
			 * XFS has no XBF_DIRTY flag; "needs writing" is
			 * expressed by being on a delwri queue, being pinned
			 * (committed to CIL, unwritten), or carrying a buf log
			 * item.  All three are cleared by a completed
			 * xfs_bwrite, so this predicate terminates.
			 */
			if (!mxfs_inode_buf_needs_write(bp)) {
				/*
				 * Cheap superset: keep looking at buffers that
				 * merely carry inode log items, because the
				 * precise test is re-applied under the lock
				 * below and the flusher can set _XBF_DELWRI_Q
				 * between our unlocked read and the lock.
				 */
				if (list_empty_careful(&bp->b_li_list)) {
					p85_clean++;
					continue;
				}
			}
			if (xfs_buf_ispinned(bp))
				p85_pinned++;

			got = false;
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				got = true;
			}
			spin_unlock(&bp->b_lock);
			if (!got) {
				p85_nohold++;
				continue;
			}

			/*
			 * RCU rule: leave the RCU-protected walk before
			 * the blocking lock + synchronous write, and re-enter
			 * after the rele.  A stop/start resume can skip entries
			 * that rehashed while stopped, which is why the whole
			 * walk repeats until a pass writes nothing.
			 */
			rhashtable_walk_stop(&iter);
			if (!xfs_buf_trylock(bp))
				p85_locked++;	/* census only; we still wait */
			else
				xfs_buf_unlock(bp);
			xfs_buf_lock(bp);

			/*
			 * FIX (HOLE 2) — THE MISSING STAGE.
			 *
			 * Until now the AG release path had no inode-log-item ->
			 * cluster-buffer conversion step at all.  di_nlink=0 from
			 * xfs_droplink lives in the INODE log item; it reaches the
			 * dinode only when xfs_iflush runs, normally from xfsaild,
			 * asynchronously.  xfs_log_force(SYNC) makes it durable in
			 * OUR journal — which no peer ever replays, because peers
			 * read only home blocks.  So we published an AGI whose
			 * unlinked bucket head pointed at a dinode still reading
			 * LINKED, and the acquirer's xfs_iunlink_reload_next called
			 * that AGI corruption and shut down from inside an already
			 * dirty rename transaction.
			 *
			 * MEASURED before this fix (P86, at the instant before
			 * mxfs_v5_dlm_ag_unlock, on all-PASS laps): 11 of 65
			 * published unlinked-list heads had disk_nlink!=0 while
			 * this node's in-core inode read nlink==0.
			 *
			 * xfs_trans_log_inode attaches every dirty inode's log item
			 * to its cluster buffer's b_li_list at first dirty, so a
			 * non-empty b_li_list is exactly the set of inodes needing
			 * conversion — no radix-tree walk required.
			 * xfs_iflush_cluster is the non-blocking converter: it
			 * takes ILOCK_SHARED with nowait and skips what it cannot
			 * get, which is what keeps this out of the whole-AG
			 * ail_push deadlock that killed the two previous attempts
			 * (a sibling in this AG can be ILOCK-EXCL-held by a thread
			 * blocked behind this very worker).  Anything it skips is
			 * retried by the enclosing pass-until-quiescent loop.
			 *
			 * Contract: on failure it has ALREADY unlocked and released
			 * the buffer and shut the filesystem down — we must not
			 * touch bp again, and must not drop our reference, because
			 * that failure path consumed it.
			 */
			if (mxfs_p87_publish_inodes &&
			    !list_empty_careful(&bp->b_li_list)) {
				int ferr = xfs_iflush_cluster(bp);

				if (ferr && ferr != -EAGAIN) {
					p85_ferr++;
					mxfs_probe("mxfs: P87-PUBLISH-IFLUSH-FAIL ag=%u rc=%d — inode conversion failed; xfs_iflush_cluster has shut the filesystem down\n",
						pag_agno(pag), ferr);
					rhashtable_walk_start(&iter);
					continue;
				}
				if (!ferr) {
					p85_iflushed++;
					/*
					 * At least one inode was converted, so the
					 * buffer now differs from the medium and
					 * MUST be written regardless of what the
					 * write predicate says.
					 */
					werr = xfs_bwrite(bp);
					goto wrote;
				}
			}

			/*
			 * Ruling item 2: re-evaluate under the lock — the state
			 * the unlocked scanner saw may have changed, in either
			 * direction.  This is also what makes the cheap superset
			 * above safe.
			 */
			if (!mxfs_inode_buf_needs_write(bp)) {
				p85_clean++;
				xfs_buf_unlock(bp);
				xfs_buf_rele(bp);
				rhashtable_walk_start(&iter);
				continue;
			}
			werr = xfs_bwrite(bp);
wrote:
			if (werr) {
				p85_werr++;
				pr_warn("mxfs: P85-INODE-DRAIN-WRITE-FAIL ag=%u daddr=%lld rc=%d — AG release cannot publish this inode cluster; xfs_bwrite has forced a META_IO_ERROR shutdown\n",
					pag_agno(pag),
					(long long)bp->b_maps[0].bm_bn, werr);
			} else {
				qd++;
				pass_writes++;
			}
			xfs_buf_unlock(bp);
			xfs_buf_rele(bp);
			rhashtable_walk_start(&iter);
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);
	} while (pass_writes && ++passes < 8);

	if (pass_writes && passes >= 8)
		pr_warn("mxfs: P85-INODE-DRAIN-PASSCAP ag=%u passes=%u last_pass_writes=%u — inode drain did not quiesce within the pass cap; releasing (bounded Invariant-1 exposure)\n",
			pag_agno(pag), passes, pass_writes);

	if (qd) {
		mxfs_blkdev_flush_epoch(pag_mount(pag));
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: AG %u BAST drain bwrote %u inode bufs",
			pag_agno(pag), qd);
	}

	/*
	 * print ONLY on an anomaly.  A line per AG release is ~1000
	 * lines per node per chunk; at 32 nodes that output goes out the guest
	 * serial port, and qemu writes it to the HOST's ext4 with a buffered
	 * pwrite.  During this session that wedged 12 guests with 63 qemu
	 * worker threads each stuck in ext4_buffered_write_iter and took the host
	 * to loadavg 750.  Instrumentation that cannot be left on is not
	 * instrumentation.
	 */
	if (mxfs_p85_drain_probe &&
	    (p85_werr || p85_ferr || p85_nohold || p85_allocq || passes > 0))
		mxfs_probe_ratelimited("mxfs: P85-INODE-DRAIN-CENSUS ag=%u inode_bufs=%u clean_skip=%u allocq_skip=%u nohold=%u delwri_seen=%u waited_lock=%u pinned_fallthru=%u iflushed=%u ferr=%u bwrote=%u werr=%u passes=%u\n",
			pag_agno(pag), p85_inode, p85_clean, p85_allocq,
			p85_nohold, p85_delwri, p85_locked, p85_pinned,
			p85_iflushed, p85_ferr, qd, p85_werr, passes + 1);
}

/*
 * v0.3.25: Targeted AG-meta buffer drain.  Walks pag_bcache for AG-meta
 * buffers (agf/agfl/agi/bnobt/cntbt/inobt/finobt) with pending log items,
 * queues them, and submits synchronously.  This replaces the global
 * `xfs_ail_push_all_sync` in `mxfs_dlm_ag_bast_work_fn`'s second flush.
 *
 * Why a targeted drain: the global ail_push deadlocks cross-AG.
 * With `pag_dlm_demoting=true` set on AG_X, ail_push's writeback can
 * issue I/O for ANY AG; if it touches AG_Y held by the peer (also stuck
 * in ail_push for AG_Y), both nodes wedge for 120s × 3 grant timeouts.
 * Restricting the drain to THIS AG's meta buffers keeps writeback
 * contained to bufs we already own — no cross-AG re-acquire path.
 *
 * Why we still need this drain: closes the priority-2 race where a
 * fast-path acquire + AG-meta modify + trans-commit (CIL only, not on
 * disk) + holders-- completes between Phase-1 flush and Phase-2 demote.
 * Without flushing the trans's BLI'd bnobt/cntbt buf to disk before
 * release, peer ACQ-FRESH reads pre-mod state → bnobt double-free →
 * `ltbno + ltlen > bno`.  Empirically observed on v0.3.24 iter-2 when
 * we dropped ail_push without replacement.
 */
/*
 * short type name for an AG-meta buffer, for the hard-barrier
 * evict log lines.  Buffer is guaranteed to be one of the AG-meta types
 * by the drain loop filter before this is called.
 */
const char *
mxfs_agmeta_name(struct xfs_buf *bp)
{
	const struct xfs_buf_ops *ops = bp->b_ops;

	if (ops == &xfs_agf_buf_ops)	return "agf";
	if (ops == &xfs_agi_buf_ops)	return "agi";
	if (ops == &xfs_agfl_buf_ops)	return "agfl";
	if (ops == &xfs_bnobt_buf_ops)	return "bnobt";
	if (ops == &xfs_cntbt_buf_ops)	return "cntbt";
	if (ops == &xfs_inobt_buf_ops)	return "inobt";
	if (ops == &xfs_finobt_buf_ops)	return "finobt";
	return "agmeta";
}

void
mxfs_dlm_ag_drain_meta_buffers(
	struct xfs_perag	*pag)
{
	LIST_HEAD(meta_drain);
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		qd = 0;
	/* P40-INSTR: drain census */
	unsigned int		p40_walked = 0;
	unsigned int		p40_meta = 0;
	unsigned int		p40_skip_no_li = 0;
	unsigned int		p40_skip_no_hold = 0;
	unsigned int		p40_drained = 0;
	unsigned int		p40_done_dirty = 0;
	unsigned int		pass_writes;
	unsigned int		p40_passes = 0;

	/*
	 * RCU fix: rhashtable_walk_start takes
	 * rcu_read_lock, and the write path below must sleep (blocking
	 * xfs_buf_lock; xfs_bwrite waits the bio) — the once-per-boot
	 * "Voluntary context switch within RCU read-side critical section"
	 * WARN from mxfs-ag-bast, and a real iterator-safety violation
	 * (a resize during the sleep invalidates the RCU-protected cursor).
	 * Each write now drops the walk (rhashtable_walk_stop) around the
	 * blocking section and resumes after.  A stop/start resume can skip
	 * entries that rehashed while stopped, so the whole walk repeats
	 * until a full pass writes nothing (pass-until-quiescent) — strictly
	 * more coverage than the old single pass, preserving Invariant 1
	 * (complete drain before on-disk unlock).
	 */
	do {
	pass_writes = 0;
	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			p40_walked++;
			if (bp->b_ops != &xfs_agf_buf_ops &&
			    bp->b_ops != &xfs_agfl_buf_ops &&
			    bp->b_ops != &xfs_agi_buf_ops &&
			    bp->b_ops != &xfs_bnobt_buf_ops &&
			    bp->b_ops != &xfs_cntbt_buf_ops &&
			    bp->b_ops != &xfs_inobt_buf_ops &&
			    bp->b_ops != &xfs_finobt_buf_ops)
				continue;
			p40_meta++;
			/*
			 * v0.3.93/101 attempted force-drain — both caused
			 * regressions.  Stick with original filter:
			 * drain only bufs with bli in AIL OR b_li_list non-empty.
			 */
			if (list_empty_careful(&bp->b_li_list)) {
				struct xfs_buf_log_item *bip = bp->b_log_item;

				if (!bip ||
				    !test_bit(XFS_LI_IN_AIL,
					      &bip->bli_item.li_flags)) {
					/*
					 * FIX (design review): a buffer with
					 * b_li_list empty AND bli not IN_AIL is in
					 * one of two states:
					 *  (a) genuinely CLEAN — no pending write,
					 *      on-disk == in-core → safe to skip; OR
					 *  (b) committed-to-CIL-but-not-yet-AIL —
					 *      PINNED, mid the ASYNC CIL→AIL transition
					 *      that the caller's xfs_log_force(SYNC)
					 *      kicked off but which completes in iclog
					 *      iodone AFTER log_force returns.
					 * The OLD code skipped BOTH, so a still-pinned
					 * bnobt/cntbt change (state b) was left
					 * UN-DURABLE at on-disk AG unlock → a peer's
					 * FUA read at acquire missed our just-committed
					 * allocation → cross-node bnobt LOST UPDATE →
					 * double-free at xfs_alloc.c:2244 (P47
					 * "DISK-LIVE-same-gen => A-lost-removal",
					 * P28 disk_differs=0).  This is THE deep
					 * recurring AG-corruption blocker.
					 *
					 * Fix: if the buffer is PINNED, do NOT skip —
					 * fall through to the lock+xfs_bwrite path.
					 * xfs_bwrite → __xfs_buf_submit waits for the
					 * pin to clear (xfs_buf_wait_unpin) before
					 * writing, and the caller already issued
					 * xfs_log_force(SYNC) so the pin WILL clear.
					 * Only a genuinely-clean (unpinned) buffer is
					 * skipped.
					 *
					 * (b62r4 ROOT): a live BLI
					 * that is unpinned and NOT in the AIL is in the
					 * async CIL→AIL window — committed-unwritten,
					 * exactly like pinned (state b) but
					 * invisible to the old pin-only test.  P117
					 * stale-cleaning such a bnobt at a deferred AG
					 * unlock cold-read the lagging platter over a
					 * committed free 3ms later (P110 undest=0
					 * has_bli=1 li_empty=1) → bnobt/cntbt divergence
					 * → peer i != 1 shutdown.  BLI-attached falls
					 * through to the write path too; only a
					 * BLI-free unpinned buffer is genuinely clean.
					 */
					if (!xfs_buf_ispinned(bp) && !bip) {
						if (bp->b_flags & XBF_DONE)
							p40_done_dirty++;
						p40_skip_no_li++;
						/*
						 * FIX (the GAP — design review
						 * "release-discard ALL bnobt/cntbt, not
						 * just drained ones"): a CLEAN free-space
						 * btree buffer (no li_list, not in-AIL, not
						 * pinned) has NO pending change, but it stays
						 * CACHED as a stale alias for the next tenure.
						 * After we hand this AG to a peer (peer splits
						 * bnobt → disk nr=3), a later RMW on THIS node
						 * builds on the cached nr=2 image and xfsaild
						 * flushes it over the peer's split =
						 * P93-REVERT-CLOBBER → `ltbno+ltlen>bno`
						 * shutdown.  The gen-based invalidate hook
						 * misses it (buf_gen==pag_gen, frozen at 1 —
						 * measured).  Discard it now (stale +
						 * clear DONE) so the next AG acquire cold-reads
						 * the peer's durable free-space tree.  Safe:
						 * no pending change to lose (clean), and we
						 * hold the buffer is unpinned/un-AIL.  Scoped
						 * to bnobt/cntbt = the proven P93 victims and
						 * the contended cross-node free-space RMW.
						 */
						/*
						 * REVERTED: generalizing this evict to all
						 * AG-meta (agf/agi/inobt/finobt) REINTRODUCED the
						 * bnobt double-free corruption shutdown (ltbno+ltlen
						 * >bno, agno=4) that 3CBB2553 had eliminated, plus a
						 * pathological 129s rename.  Evicting AGF desyncs the
						 * AGF freeblks/longest + btree-root cache from the
						 * bnobt/cntbt image.  Scope stays bnobt/cntbt = the
						 * proven P93 victims and the contended cross-node
						 * free-space RMW.
						 */
						if (bp->b_ops == &xfs_bnobt_buf_ops ||
						    bp->b_ops == &xfs_cntbt_buf_ops) {
							bool got = false;
							spin_lock(&bp->b_lock);
							if (bp->b_hold > 0) {
								bp->b_hold++;
								got = true;
							}
							spin_unlock(&bp->b_lock);
							if (got) {
								if (xfs_buf_trylock(bp)) {
									struct xfs_btree_block *p117bb =
										bp->b_addr;

									xfs_buf_stale(bp);
									bp->b_flags &= ~XBF_DONE;
									/* print the discarded
									 * image's identity (nr/lsn) so the offline
									 * P144 WR/RD join can tell whether this
									 * stale-clean dropped content the media
									 * never received. */
									mxfs_probe_ratelimited("mxfs: P117-AGMETA-STALE-CLEAN agno=%u daddr=%lld %s nr=%u lsn=%llx realns=%llu\n",
										pag_agno(pag),
										(long long)bp->b_maps[0].bm_bn,
										mxfs_agmeta_name(bp),
										p117bb ? be16_to_cpu(p117bb->bb_numrecs) : 0,
										p117bb ? (unsigned long long)be64_to_cpu(p117bb->bb_u.s.bb_lsn) : 0,
										(unsigned long long)ktime_get_real_ns());
									xfs_buf_unlock(bp);
								}
								xfs_buf_rele(bp);
							}
						}
						continue;
					}
					/* PINNED: fall through and drain it. */
					mxfs_probe_ratelimited("mxfs: P73-FIX drain-WRITE-pinned-no-li agno=%u daddr=%lld pin=%d bflags=0x%x realns=%llu\n",
						pag_agno(pag),
						(long long)bp->b_maps[0].bm_bn,
						atomic_read(&bp->b_pin_count),
						bp->b_flags,
						(unsigned long long)ktime_get_real_ns());
				}
			}
			/*
			 * v0.3.31: do NOT skip bufs already on a delwri queue
			 * (xfsaild's ail_buf_list).  Pre-fix, the skip meant
			 * that any buf xfsaild had queued for later writeback
			 * was deemed "someone else's problem" — but xfsaild
			 * runs asynchronously, may not submit for seconds, and
			 * we release AG immediately after this drain.  The
			 * window between "buf queued on xfsaild's list" and
			 * "buf actually on disk" was the residual priority-2
			 * sub-race source after v0.3.29 (iter-2:
			 * `bno+len>gtbno line 2151` RIGHT-FAIL).
			 *
			 * Instead: pin + blocking-lock + xfs_bwrite to force
			 * synchronous writeback NOW, regardless of delwri-queue
			 * state.  xfs_bwrite clears _XBF_DELWRI_Q and submits;
			 * the buf is still on xfsaild's list but xfsaild's
			 * subsequent submit will see it clean and skip.
			 */
			{
				bool got = false;
				spin_lock(&bp->b_lock);
				if (bp->b_hold > 0) {
					bp->b_hold++;
					got = true;
				}
				spin_unlock(&bp->b_lock);
				if (!got) {
					p40_skip_no_hold++;
					continue;
				}
			}
			/* RCU fix: hold taken — leave the RCU-protected
			 * walk before the blocking lock + synchronous write.
			 * Resumed after the rele below. */
			rhashtable_walk_stop(&iter);
			/*
			 * v0.3.27: blocking xfs_buf_lock instead of trylock.
			 * If xfsaild has the buf locked because it's mid-I/O
			 * (xfs_buf_submit holds the lock until bio completes),
			 * trylock would skip and we'd release the DLM grant
			 * before xfsaild's I/O finishes — peer ACQ-FRESH reads
			 * pre-write disk state.  Blocking lock waits for
			 * xfsaild to finish (its I/O completion releases the
			 * lock via xfs_buf_iodone), then we observe a buf with
			 * its on-disk state committed.  bast_work_fn runs in
			 * kworker context with no locks held; we do not block
			 * any thread that depends on us, so this is safe.
			 */
			xfs_buf_lock(bp);
			/*
			 * v0.3.32: drop the xfs_trans_buf_is_dirty check.  That
			 * test reads XFS_LI_DIRTY (the trans-private dirty bit),
			 * which is cleared post-commit.  But a bli in AIL with
			 * XFS_LI_DIRTY clear can STILL have pending writeback
			 * (xfsaild hasn't flushed it yet).  Our outer filter
			 * already ensured bli is in AIL — that's the authoritative
			 * "writeback pending" signal.  Just bwrite unconditionally.
			 *
			 * If the buf was concurrently flushed by xfsaild between
			 * our lock acquisition and bwrite, xfs_bwrite still works
			 * (re-writes the same content).  Idempotent.
			 */
			{
				int werr = xfs_bwrite(bp);
				if (werr)
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: AG %u xfs_bwrite "
						"blkno=%llu rc=%d",
						pag_agno(pag),
						(unsigned long long)
						bp->b_maps[0].bm_bn, werr);
				else {
					qd++;
					p40_drained++;
					pass_writes++;
					/*
					 * P80-INSTR: xfs_bwrite is
					 * synchronous (waits for bio completion).
					 * After it returns 0 the free-space btree
					 * block's content MUST be on disk.  FUA
					 * read it back and compare: if it differs,
					 * the storage ACKed but did NOT persist the
					 * write (LIO/SCST per-initiator cache drop)
					 * → disk keeps the OLD tree block while its
					 * sibling's write landed → on-disk bno/cnt
					 * inconsistency (P70 disk_differs=0).  Fires
					 * only on the anomaly, agno=1 bnobt/cntbt.
					 */
					if (pag_agno(pag) == 1 &&
					    (bp->b_ops == &xfs_bnobt_buf_ops ||
					     bp->b_ops == &xfs_cntbt_buf_ops)) {
						int d = mxfs_ag_buf_disk_differs(bp);
						if (d != 0)
							mxfs_probe("mxfs: P80-INSTR drain-WRITE-NOT-PERSISTED agno=1 %s daddr=%lld disk_differs=%d\n",
								bp->b_ops == &xfs_bnobt_buf_ops ? "bnobt" : "cntbt",
								(long long)bp->b_maps[0].bm_bn, d);
					}
				}
				/*
				 * P94 COMBINATION TEST DONE + REVERTED:
				 * fua_always=1 (always read medium) + this FUA-write-
				 * through (always write medium) STILL clobbered (ltbno=7,
				 * clobbers 58-120).  So with ALL caching eliminated on
				 * BOTH read and write sides the bnobt clobber PERSISTS.
				 * BUT: fua_always only forces FUA on reads that submit a
				 * bio; an XBF_DONE cache-HIT returns the cached buffer
				 * with NO read, so a stale buffer the gen-hook treats as
				 * "current" (buf_gen==pag_gen) is used regardless.  Next
				 * suspect: the buffer's b_pag / b_mxfs_ag_gen is compared
				 * against the WRONG AG's gen (perag mis-association) so it
				 * is never invalidated — see P95 in xfs_buf.c.
				 */
				/*
				 * RELEASE PUBLISH-AND-DISCARD for AG free-space
				 * btrees (the proven release-side dir fix, applied to the
				 * bnobt/cntbt run-killer — design review: "same fence applies to
				 * AGF/AGI/bnobt bufs").  xfs_bwrite above made this buffer
				 * DURABLE on the shared target (synchronous, waits the
				 * bio); the bli leaves the AIL on iodone.  But the in-core
				 * buffer stays CACHED and re-grant'able, so after we hand
				 * the AG to a peer (peer splits bnobt → disk nr=3), a later
				 * FAST-PATH AG re-grant on THIS node can RMW the stale
				 * cached image (nr=2) and xfsaild then flushes it over the
				 * peer's split = P93-REVERT-CLOBBER → `ltbno+ltlen>bno`
				 * shutdown.  xfs_buf_stale REMOVES the buffer from cache
				 * (next AG acquire — fast OR slow — cold-reads the peer's
				 * merged free-space tree) and drops _XBF_DELWRI_Q (xfsaild
				 * can never re-flush this superseded image).  Scoped to
				 * bnobt/cntbt: the proven P93 victims, and the free-space
				 * trees are the contended cross-node RMW.  Buffer is
				 * durable+locked here; force-clear XBF_DONE after stale
				 * (xfs_buf_stale does not — v0.3.99/). */
				/*
				 * REVERTED to bnobt/cntbt scope (see the clean-stale
				 * site above): generalizing to AGF/AGI/inobt/finobt
				 * reintroduced the bnobt double-free corruption shutdown.
				 */
				if (bp->b_ops == &xfs_bnobt_buf_ops ||
				    bp->b_ops == &xfs_cntbt_buf_ops) {
					xfs_buf_stale(bp);
					bp->b_flags &= ~XBF_DONE;
					mxfs_probe_ratelimited("mxfs: P99-AGMETA-STALE agno=%u daddr=%lld %s\n",
						pag_agno(pag),
						(long long)bp->b_maps[0].bm_bn,
						mxfs_agmeta_name(bp));
				}
				xfs_buf_unlock(bp);
			}
			xfs_buf_rele(bp);
			/* RCU fix: re-enter the walk (paired with the
			 * stop before the blocking section above). */
			rhashtable_walk_start(&iter);
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);
	} while (pass_writes && ++p40_passes < 8);
	if (pass_writes && p40_passes >= 8)
		pr_warn("mxfs: P-DRAIN-PASSCAP ag=%u passes=%u last_pass_writes=%u — meta drain did not quiesce within pass cap; releasing (bounded Invariant-1 exposure, was unbounded single-pass before)\n",
			pag_agno(pag), p40_passes, pass_writes);

	if (qd) {
		/*
		 * v0.3.31: bufs were submitted via xfs_bwrite (synchronous
		 * write completion) inside the loop; meta_drain list is unused
		 * but kept for interface stability.  blkdev_flush ensures the
		 * device write cache is committed before peer ACQ-FRESH reads.
		 */
		mxfs_blkdev_flush_epoch(pag_mount(pag));
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: AG %u BAST drain bwrote %u meta bufs",
			pag_agno(pag), qd);
	}
	mxfs_idbg("mxfs: P40-INSTR ag=%u DRAIN walked=%u meta=%u skip_no_li=%u "
		"done_dirty=%u skip_no_hold=%u drained=%u\n",
		pag_agno(pag), p40_walked, p40_meta, p40_skip_no_li,
		p40_done_dirty, p40_skip_no_hold, p40_drained);
	(void)meta_drain;
}

/*
 *  (instrumented): the P125-AG-DIVERGE assertion in
 * xfs_buf_submit_ex reads the on-disk AG CAW slot (a find_slot probe-chain
 * walk = several FUA SCSI reads) on EVERY bnobt/cntbt/agf/agi buffer write.
 * kprobe counts over a 20-create burst attributed 5.3 FUA slot reads per
 * create to xfsaild through this probe alone.  The divergence family it was
 * armed for (double-alloc root) was fixed by 0.10.120; keep the tripwire
 * available but off the hot writeback path by default.
 */
int mxfs_p125_ag_diverge;
module_param_named(p125_ag_diverge, mxfs_p125_ag_diverge, int, 0644);
MODULE_PARM_DESC(p125_ag_diverge,
                 "On-disk AG-slot divergence assertion per AG-metadata write "
                 "(P125-AG-DIVERGE): 0=off (default), 1=on for debugging");

/*
 * v0.3.132 tunable AG yield quantum.  Caps how many lazy
 * skips in mxfs_ag_dlm_unlock before forcing an eager drain.
 * Default 32 = MXFS_BAST_YIELD_QUANTUM (the validated spec D10
 * constant for the inode side).  Smaller values reduce accumulated
 * dirty AG metadata per cached-grant epoch — important if BAST
 * work fn drain time exceeds CAW poll timeout (120s).
 * disambiguation showed T1 shutdown reproducing at quantum=32;
 * try smaller values (8, 4, 2) to bound BAST drain duration.
 */
module_param_named(ag_yield_quantum, mxfs_ag_yield_quantum, int, 0644);
MODULE_PARM_DESC(ag_yield_quantum,
                 "AG-DLM yield quantum (max consecutive lazy unlock "
                 "skips before forced eager drain).  Default 32.  "
                 "Reduce to 4 or 8 if BAST work fn drain exceeds "
                 "CAW poll timeout under heavy lazy accumulation.  "
                 "When ag_yield_adaptive=1 (default) this is the upper "
                 "cap; the actual per-AG quantum auto-tunes between 1 "
                 "and this value.");
