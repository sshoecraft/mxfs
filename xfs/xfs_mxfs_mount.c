// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- the mount recovery barrier
 */
#define MXFS_TU_ID 34	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * (design-consult barrier ruling, item 4 — window arm): one-shot
 * hold at the top of the admission barrier, AFTER DLM init armed the
 * mount-phase death record and BEFORE the first drain.  A peer killed while
 * the hold runs is confirmed dead (~62 s) by this node's own monitor and
 * recorded as P233-MPHASE-DEATH; the barrier then drains it as a late death
 * and replays it inline — the deterministic late-death fold the timing-based
 * arm could not guarantee.  Self-clears when it fires.  0 = off (default).
 * tests/d_mount_window_death_verify.sh.
 */
static int mxfs_dbg_barrier_hold_ms;
module_param_named(dbg_barrier_hold_ms, mxfs_dbg_barrier_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_barrier_hold_ms,
	"TEST: one-shot hold (ms) at the top of the mount admission barrier; self-clears");

/*
 * 0.89.3 (D-0981) — TEST ONLY, one-shot, self-clears: refuse this mount the
 * moment its barrier has CLAIMED a slice's recovery lease (the fence is
 * certified and the fence-time manifest sealed), giving the lease back
 * durably so the descriptor is left at stage FENCED with no owner.  That is
 * the platter state a prover leaves when it seals a victim's fence and its
 * own mount is then refused at the admission bound (s66d/s66e), and it is
 * the precondition of tests/d0981_pending_victim_sweep.sh: the next mount
 * claims that recovery, and its orphan sweep must leave the victim's ledger
 * records alone until the replay has passed its manifest judgement.
 */
static int mxfs_dbg_barrier_refuse_after_claim;
module_param_named(dbg_barrier_refuse_after_claim,
		   mxfs_dbg_barrier_refuse_after_claim, int, 0644);
MODULE_PARM_DESC(dbg_barrier_refuse_after_claim,
	"TEST: one-shot: refuse the mount right after the barrier claims a recovery lease, giving it back durably; self-clears");

/*
 * sess330 (D-513 design-consult ruling): the admission barrier's terminal
 * classification.  A slice whose recovery was terminally REFUSED is not
 * pending work — no lease is ever obtainable over its quarantined
 * descriptor (the claim path's certificate evaluator refuses it), so
 * without this the barrier would poll the wait bound down and fail the
 * mount -EBUSY over a slot that is already disposed.  Classification
 * imports the quarantine and latches the slot exactly as the live reap
 * path does; the DISPOSITION then depends on the quarantine's scope:
 *
 *   1      terminal, AG-scoped — the mount may admit; operations
 *          touching the quarantined AGs fail with EIO until operator
 *          repair.  The caller retires the slot from the cut WITHOUT
 *          adding it to `replayed`: cohort completion purges a replayed
 *          slot's CAW manifest and zeroes its heartbeat sector, and
 *          that sector now carries the durable outcome record every
 *          peer converges on.
 *   0      nonterminal — proceed to acquire/replay as before.
 *   -EAGAIN transient classify state — retry in a later round.
 *   1 with *fswide set — terminal, FSWIDE: every operation this mount
 *          could ever admit would fail with EIO.  sess334 (sess333
 *          review item A): the FSWIDE case returns 1 like any terminal
 *          disposition — never a bare error — so the caller ALWAYS sets
 *          the slot's terminal bit FIRST and only then jumps to the
 *          common abort, which hands un-replayed late deaths back to the
 *          mphase record.  (The old -EIO return skipped both.)
 */
static int
mxfs_barrier_classify_slot(
	struct xfs_mount	*mp,
	unsigned int		slot,
	bool			*fswide)
{
	int			crc;

	*fswide = false;
	crc = mxfs_freplay_classify_terminal(mp, slot);
	if (crc <= 0)
		return crc;
	spin_lock(&mp->m_mxfs_quar_lock);
	*fswide = mp->m_mxfs_quar_fswide;
	spin_unlock(&mp->m_mxfs_quar_lock);
	if (*fswide)
		xfs_alert(mp,
			"MXFS mount ABORTED: slice slot=%u carries a terminal "
			"recovery refusal quarantining the WHOLE filesystem — "
			"every operation would fail with EIO.  Repair the "
			"victim's slice targets, clear the outcome record, "
			"and remount", slot);
	return 1;
}

/*
 * D-0980: the barrier's exit line, printed on every exit that follows the
 * admission wait.  wait_ms is the elapsed wall of the wait loop, bound_ms
 * the bound it was held to, and overrun_ms how far the wall ran past the
 * bound — which a deadline that is checked between slices can only do by
 * the length of the slice it could not preempt, so an overrun larger than
 * last_round_ms is itself a defect.  total_ms covers the whole barrier
 * (the cohort confirmation, the residue gate and the wait).
 */
static void
mxfs_barrier_clock(
	struct xfs_mount	*mp,
	const char		*result,
	unsigned long		t_entry,
	unsigned long		t_loop,
	unsigned int		bound_ms,
	int			rounds,
	unsigned int		last_round_ms)
{
	unsigned int		wait_ms = t_loop ?
					jiffies_to_msecs(jiffies - t_loop) : 0;

	xfs_notice(mp,
		"MXFS mount barrier: P-BARRIER-CLOCK result=%s wait_ms=%u "
		"bound_ms=%u overrun_ms=%u rounds=%d last_round_ms=%u "
		"total_ms=%u — the admission wait is bounded by elapsed time; "
		"an overrun larger than the last round is a defect",
		result, wait_ms, bound_ms,
		wait_ms > bound_ms ? wait_ms - bound_ms : 0, rounds,
		last_round_ms, jiffies_to_msecs(jiffies - t_entry));
}

int
mxfs_dlm_mount_recovery_barrier(
	struct xfs_mount	*mp)
{
	uint64_t		cohort = 0;
	uint64_t		todo = 0;
	uint64_t		seen = 0;
	uint64_t		pend;
	uint64_t		drained = 0;
	uint64_t		late;
	uint64_t		replayed = 0;
	uint64_t		terminal = 0;
	uint64_t		quarblocked = 0;
	uint64_t		published = 0;
	uint64_t		residue = 0;
	unsigned int		slot;
	unsigned int		waited_ms = 0;
	unsigned int		wait_bound = MXFS_BARRIER_ADMISSION_WAIT_MS;
	unsigned int		deadwin = 0;
	int			undecl = 0;
	bool			extend_logged = false;
	/*
	 * D-0980: the admission wait is bounded by ELAPSED time on the
	 * monotonic clock, never by a count of its own poll sleeps.  The
	 * work a round does between two polls — per-slot sector reads, PR
	 * commands, the 6 s abandonment observation inside every takeover,
	 * a slice stability proof of up to 45 s, the replay itself, the
	 * ledger-page takeover scan — used to be invisible to the bound, so
	 * a 122-poll extension could hold mount(2) in the kernel for as
	 * long as 122 rounds took (a joiner's mount outlived its 300 s
	 * timeout by more than a minute, s65f, and ignored SIGTERM for all
	 * of it).  `deadline` is the absolute bound; it is checked before a
	 * round starts, before every slice inside a round, and after every
	 * poll sleep.  A deadline cannot preempt a slice already being
	 * replayed, so the guaranteed property is "no new work is started
	 * past the bound", and the exit line names the overrun.
	 */
	unsigned long		t_entry = jiffies;
	unsigned long		t_loop = 0;
	unsigned long		t_round = 0;
	unsigned long		deadline = 0;
	unsigned int		last_round_ms = 0;
	bool			expired = false;
	int			round = 0;
	int			nreplayed = 0;
	int			nres = 0, nex = 0;
	int			blocking;
	int			rc;
	int			crc;
	int			error;
	bool			fswide;

	if (!mp)
		return 0;

	/*
	 * (review item 6): unconditional FSWIDE admission
	 * gate at the barrier's START.  A preexisting fswide quarantine —
	 * however it reached the map — must refuse the mount even when the
	 * recovery cut below comes up empty; a mount with a known-fswide
	 * quarantine that admits is a zombie whose every operation fails
	 * with EIO.
	 *
	 * review stop-ship 2: this gate sits BEFORE the
	 * !m_mxfs_dlm return below — that return used to precede it, a
	 * fail-open success path.  m_mxfs_quar_lock is initialized in
	 * xfs_init_mount_workqueues (fill_super), before this barrier can
	 * run, so taking it here is safe with m_mxfs_dlm still NULL.  No
	 * quarantine import can race in while m_mxfs_dlm is NULL — imports
	 * arrive from the DLM monitor, which does not exist yet — so one
	 * gate covers both returns.  abort_fswide is safe with a NULL
	 * m_mxfs_dlm: drained==0 there, so defer_late_deaths is not
	 * called.
	 */
	spin_lock(&mp->m_mxfs_quar_lock);
	fswide = mp->m_mxfs_quar_fswide;
	spin_unlock(&mp->m_mxfs_quar_lock);
	if (fswide)
		goto abort_fswide;

	if (!mp->m_mxfs_dlm)
		return 0;

	/*
	 * (design-consult ruling Q3, the structural half) — TERMINAL-GUARD
	 * SWEEP, independent of the recovery cut.
	 *
	 * The cut below comes from mxfs_v5_dlm_mount_pending_recovery(), which
	 * omits any slot whose descriptor has reached GRANTS_RELEASED
	 * ("complete, awaiting slot zeroing").  That is a correct rule for
	 * deciding what still needs REPLAY WORK.  It is the wrong rule for
	 * deciding what this mount may be ADMITTED over: a terminal refusal on
	 * such a slot is still the cluster's durable verdict, and its domain
	 * still covers everything this mount would touch.
	 *
	 * Before that gap was invisible, because the only other reader
	 * of those slots — the registration-time outcome scan — runs ~0.5 s
	 * LATER, from mxfs_dlm_cache_init, after xfs_mountfs has returned.  So
	 * a whole-filesystem refusal on a GRANTS_RELEASED slot was discovered
	 * only once the mount was already built, and the refusal had to be
	 * taken on the expensive unwind path, where tearing down a fully
	 * mounted log against an FSWIDE quarantine trips a log-IO shutdown on
	 * the way out (measured: "Filesystem has been shut down due to log
	 * error (0x2)" on an otherwise correct refusal).
	 *
	 * Classifying every slot HERE moves that decision back to the cheap
	 * exit.  The cost is one sector read per slot, which the sweep below
	 * pays every round anyway, and the classification is exactly the one
	 * the cut members get: it imports the verdict, latches the slot, and
	 * fails closed on anything it cannot validate.
	 */
	for (slot = 0; slot < 64; slot++) {
		crc = mxfs_barrier_classify_slot(mp, slot, &fswide);
		if (crc > 0) {
			terminal |= (1ULL << slot);
			if (fswide)
				goto abort_fswide;
		}
	}

	/*
	 * (a) Our own replay must be durable before any of its authority
	 *     bits can be released, and before a peer can be told the slices
	 *     below are recovered.
	 *
	 *     A log force / AIL push is NOT available here and is not
	 *     needed: xlog_recover's pass 2 already delwri-submitted every
	 *     buffer image it applied and waited for the I/O, so what
	 *     remains is only the device write cache.  The AIL at this point
	 *     holds recovered INTENT items that xfs_log_mount_finish has not
	 *     processed — pushing those would block forever (upstream
	 *     refuses the same push for the same reason).
	 *
	 *     design review item 1: this MUST be the durable form.  The
	 *     per-modify mxfs_blkdev_flush_epoch() skips the flush entirely
	 *     under mxfs_fua_disable (the default), which certifies
	 *     peer-visibility but not survival of a target power loss —
	 *     and everything below this line publishes recovery state on
	 *     the assumption that what precedes it is on the platter.  A
	 *     flush failure here means we cannot make that promise, so the
	 *     mount fails rather than publishing an uncertifiable recovery.
	 */
	error = mxfs_blkdev_flush_durable(mp);
	if (error) {
		xfs_alert(mp,
			"MXFS mount ABORTED: could not flush the shared "
			"device (%d) before recovery publication — our own "
			"replayed images are not certifiably durable",
			error);
		return error;
	}

	/*
	 * (b) Resolve the peers deferred at mount step 6.5: confirm each is
	 *     still the same frozen incarnation, fence it, and mark its
	 *     slice recovery durably pending.  No election and no purge —
	 *     WE are the node whose mount recovery collides with those
	 *     grants, so we cannot wait for another survivor to clear them,
	 *     and the CAW table is still the authority manifest each slice's
	 *     replay gate reads.
	 *
	 *     Cost: the confirmation window is dead_threshold heartbeat
	 *     samples (~62 s at the shipped 31 × 2 s) and is paid on the
	 *     mount path by design — see TIMEOUT_BUDGETS.md.  It is only
	 *     paid when a peer was ALREADY frozen when we mounted.
	 */
	error = mxfs_v5_dlm_mount_recovery_cohort(mp->m_mxfs_dlm, &cohort);
	if (error)
		xfs_alert(mp,
			"MXFS mount recovery cohort failed (%d) — deferred "
			"peer slices stay unreplayed", error);

	/*
	 * (b2) item 6A — the residue gate.  Anything the cohort could
	 *      not fence is still an on-disk grant holder that we are not
	 *      allowed to replay or purge.  Decide NOW, while a clean mount
	 *      failure is still available, whether it can block what comes
	 *      next.  Read failure counts as blocking: an unread slot may
	 *      hold anything, and guessing "clear" resumes exactly the stall
	 *      this gate exists to prevent.
	 */
	blocking = mxfs_v5_dlm_mount_residue_blocking(mp->m_mxfs_dlm, &residue,
						      &nres, &nex);
	if (blocking) {
		xfs_alert(mp,
			"MXFS mount ABORTED: peer slot mask 0x%llx confirmed "
			"dead but could not be fenced, and still owns %d "
			"resource(s) (%d EX/PW)%s.  Its slice may not be "
			"replayed and its grants may not be purged, so log "
			"recovery below would block on them and fail.  Fix "
			"the SCSI PR path (or clear the dead node) and retry "
			"the mount.",
			(unsigned long long)residue, nres, nex,
			blocking < 0 ? " [census incomplete — assumed "
				       "blocking]" : "");
		return -EIO;
	}
	if (residue)
		xfs_alert(mp,
			"MXFS mount recovery: peer slot mask 0x%llx confirmed "
			"dead but unfenceable — it owns nothing, so the mount "
			"proceeds; its slice stays unreplayed until the "
			"post-mount settle can fence it",
			(unsigned long long)residue);

	/*
	 * (c) Replay each confirmed slice inline.  This mirrors
	 *     mxfs_dlm_foreign_replay_work_fn, minus its log-force/AIL-push
	 *     bracket for the reason in (a): the invalidation is what the
	 *     replay actually needs (drop our cached views so pass 2's LSN
	 *     gate compares against current disk state, and drop them again
	 *     afterwards so later reads see the recovered metadata), and the
	 *     flush half of the peer-joined round is illegal here.
	 *
	 *     (design review item 6B) — IN BOUNDED ROUNDS.  The
	 *     cohort is a SNAPSHOT of the peers already frozen when we
	 *     arrived.  A peer that was healthy then and freezes during the
	 *     ~62 s confirmation window step (b) just paid is detected by the
	 *     heartbeat monitor, which fences it and marks its slice
	 *     recovery-pending — but cannot dispatch a replay, because the
	 *     slice-replay hook is registered only after xfs_mountfs returns.
	 *     It records the slot instead (P233-MPHASE-DEATH).  Such a slot
	 *     arrives in exactly the state a cohort slot is in, so fold each
	 *     drain into the next round: a death that lands while we are
	 *     replaying is then resolved by THIS mount, instead of leaving
	 *     frozen grants for xfs_log_mount_finish below to stall on.
	 *
	 *     Rounds are capped because the drain has no guaranteed quiet
	 *     point — a cluster losing a node every few seconds must not hold
	 *     the mount here forever.  Whatever is still outstanding at the
	 *     cap is handed BACK, and the post-mount settle dispatches it.
	 */
	/*
	 * (design-consult ruling): this loop is an ADMISSION barrier.
	 * Invariant: before a mount may read shared metadata or transition
	 * to LIVE it must establish a stable recovery cut and ensure every
	 * applicable dirty/dead slice preceding the cut is replay-complete.
	 * Pending / claimed / in-progress does not satisfy this.  The
	 * round cap bounds inline replay discovery — it is NOT permission
	 * to go live with leftovers; whatever remains holds the gate shut
	 * until it completes or the bounded wait expires and the mount
	 * fails.
	 */
	if (unlikely(mxfs_dbg_barrier_hold_ms > 0)) {
		int	hold = mxfs_dbg_barrier_hold_ms, slept = 0;

		mxfs_dbg_barrier_hold_ms = 0;	/* one shot */
		xfs_alert(mp,
			"MXFS mount recovery barrier: P-DBG-BARRIER-HOLD start "
			"ms=%d — TEST hold with the mount-phase death record "
			"armed, nothing drained yet", hold);
		while (slept < hold && !xfs_is_shutdown(mp)) {
			msleep(1000);
			slept += 1000;
		}
		xfs_alert(mp,
			"MXFS mount recovery barrier: P-DBG-BARRIER-HOLD released "
			"after %d ms (mphase_pending=0x%llx)", slept,
			(unsigned long long)mxfs_v5_dlm_mount_peek_late_deaths(
							mp->m_mxfs_dlm));
	}
	t_loop = jiffies;
	deadline = t_loop + msecs_to_jiffies(wait_bound);
	for (;;) {
		/*
		 * Shape A: drain the mount-phase death record at the TOP of
		 * every pass — a zero cohort must not bypass the drain.
		 * (measured root: the monitor consumed a WITHDRAWN
		 * stamp during DLM init, recorded the death in the mphase
		 * mask, and `for (round = 0; todo && ...)` with
		 * todo = cohort = 0 never ran — the death was never taken
		 * and its replay went async after the mount was live.)
		 */
		late = mxfs_v5_dlm_mount_take_late_deaths(mp->m_mxfs_dlm);
		drained |= late;

		/*
		 * Shape B: sweep the platter's requires-recovery evidence —
		 * WITHDRAWN stamps and sub-complete recovery descriptors.
		 * The mphase record only sees deaths OUR monitor processed;
		 * the durable evidence is what a peer's fence pipeline (or
		 * our own, racing this mount) leaves on disk.
		 */
		pend = 0;
		error = mxfs_v5_dlm_mount_pending_recovery(mp->m_mxfs_dlm,
							   &pend);
		if (error)
			xfs_alert(mp,
				"MXFS mount recovery: requires-recovery sweep "
				"failed (%d) — treating the cut as dirty",
				error);

		/*
		 * a slice a SURVIVOR completed while we waited is
		 * replay-complete — it satisfies the admission invariant
		 * without this mount doing anything, and must leave the cut
		 * (s423 window arm: the survivor's P163-RECOVERY-COMPLETE
		 * zeroed the sector, our monitor logged P163-RECOVERED, and
		 * the bit still aborted the mount after 4 rounds of
		 * "NOT replayed (-2)").  Proven per slot by the v5 helper
		 * (marker cleared + fresh sector no longer holds the victim);
		 * bits still in `pend` are never candidates.
		 */
		if (!error) {
			uint64_t	elsewhere =
				mxfs_v5_dlm_mount_resolved_elsewhere(
					mp->m_mxfs_dlm,
					(cohort | drained) & ~pend & ~replayed &
					~terminal);

			if (elsewhere) {
				xfs_notice(mp,
					"MXFS mount recovery: slot mask 0x%llx "
					"recovered by a survivor while this mount "
					"waited — retired from the admission cut",
					(unsigned long long)elsewhere);
				cohort &= ~elsewhere;
				drained &= ~elsewhere;
			}
		}
		/* a terminally-disposed slice is retired from the
		 * cut but NOT `replayed` — completion below must never purge
		 * the heartbeat sector now carrying its outcome record. */
		todo = (cohort | drained | pend) & ~replayed & ~terminal;
		seen |= todo;

		/*
		 * 0.75.80 (measured s567 on 0.75.77,
		 * tests/evidence/20260909T011714Z_ghost_s567): an EMPTY cut is
		 * not a CLEAN cut while this node is still watching a frozen
		 * foreign heartbeat record.
		 *
		 * The measured shape: both nodes of the two-node TCP rig were
		 * destroyed with their mounts in flight and came back onto the
		 * LUN.  The two leftover records were plain ACTIVE with no
		 * WITHDRAWN stamp and no recovery descriptor, so the platter
		 * sweep found nothing; the membership gate discounted them
		 * ("P-MEMB-GATE-GHOSTS 2 frozen foreign slot(s)"); and this
		 * node's monitor cannot call a frozen record dead until it has
		 * watched it stay frozen for the whole dead window (31 x 2 s).
		 * At 8 s the barrier therefore read cohort=0x0 late=0x0
		 * pend=0x0, declared the cut clean and admitted.  The root
		 * inode's AG-0 ledger page named one of those dead
		 * incarnations as its authority, so the AG DLM acquire could
		 * never be granted: five untrusted-iget budgets (~58 s) burned
		 * out at 01:21:02 with P-IMAP-UNTRUSTED-AGLOCK-GIVEUP and
		 * "Failed to read root inode 0x80, error 5" — while the
		 * monitor's own death declaration, fence (kind 21) and seal
		 * landed at 01:21:00-01:21:07, seconds too late, leaving
		 * P233-MPHASE-UNDISPATCHED mask=0xc0 at teardown.  Both mounts
		 * failed, every restart alike.
		 *
		 * mxfs_disklock_deaths_undeclared() counts exactly that set:
		 * monitored, not local, seen at least once, not yet live, not
		 * yet recovery-pending.  A genuinely live peer leaves it within
		 * a couple of heartbeats; a crash leftover leaves it when the
		 * monitor declares it dead, at which point the slot arrives in
		 * `pend` and the ordinary replay rounds below own it.  Holding
		 * admission until the count is zero is the same fail-closed
		 * rule the dirty cut already obeys, and the wait is bounded by
		 * the ghost extension below.
		 */
		undecl = mxfs_v5_dlm_deaths_undeclared(mp->m_mxfs_dlm, &deadwin);
		if (!todo && !error && undecl <= 0)
			break;		/* clean admission cut */
		if (xfs_is_shutdown(mp))
			break;

		/*
		 * 0.75.72 (D-...-0928/0929, measured s560 on 0.75.71): both
		 * nodes came back onto a LUN whose six pending slices carried
		 * FENCING descriptors of provers that had died with the
		 * previous boot.  Nothing can take a dead prover's attempt
		 * over until this node's monitor has DECLARED that prover
		 * dead, which takes the dead window (31 x 2 s), and the 30 s
		 * bound expired first: 34 rounds of P236-CLAIM-UNCERTIFIED,
		 * then 'mount ABORTED' on both nodes, every restart alike.
		 * While the monitor still has frozen records it has not
		 * declared dead, the bound is the dead window plus the fence
		 * + replay budget on top of the ordinary wait.
		 *
		 * D-0980 (design consult, design review 2026-09-19): the extension is
		 * a CAP, granted once from the loop's start and never
		 * re-derived — a second ghost appearing mid-wait does not buy
		 * a fresh window, and the bound is deliberately kept once
		 * every death is declared, so the replay that becomes
		 * possible at the declaration has its allowance (30 s) rather
		 * than expiring the mount at the moment it could proceed.
		 */
		if (undecl > 0 && !extend_logged) {
			extend_logged = true;
			if (deadwin > 0) {
				wait_bound = MXFS_BARRIER_ADMISSION_WAIT_MS +
					     deadwin +
					     MXFS_BARRIER_ADMISSION_WAIT_MS;
				deadline = t_loop + msecs_to_jiffies(wait_bound);
			}
			xfs_notice(mp,
				"MXFS mount barrier: P-BARRIER-GHOST-EXTEND undeclared=%d window_ms=%u bound_ms=%u — %d frozen heartbeat record(s) are not yet declared dead; admission is held until each is resolved (declared dead and replayed, or seen heartbeating), covering their dead window plus a fence and replay budget",
				undecl, deadwin, wait_bound, undecl);
		}
		/*
		 * D-0980: cancellation and the deadline are judged HERE, at a
		 * recovery-safe boundary — no lease is being claimed and no
		 * slice is mid-replay — before any round starts, including the
		 * first four inline ones.
		 */
		if (fatal_signal_pending(current))
			goto abort_cancelled;
		waited_ms = jiffies_to_msecs(jiffies - t_loop);
		expired = time_after_eq(jiffies, deadline);

		if (!todo || round >= MXFS_BARRIER_REPLAY_ROUNDS || expired) {
			/*
			 * Past the inline rounds (or a sweep failure with
			 * nothing actionable): whatever remains is owned by
			 * another survivor, awaiting the monitor's fence, or
			 * unresolvable.  Poll bounded for completion; a cut
			 * still dirty at the bound fails the mount — the
			 * same spirit as the (b2) residue gate.
			 *
			 * classify each remaining bit every poll
			 * pass.  The recovery's owner may PUBLISH a terminal
			 * refusal while we wait — without this, a quarantine
			 * landing after the round cap would ride the poll to
			 * the bound and fail the mount -EBUSY over a slice
			 * that is not pending work at all.
			 */
			for (slot = 0; slot < 64; slot++) {
				if (!(todo & (1ULL << slot)))
					continue;
				crc = mxfs_barrier_classify_slot(mp, slot,
								 &fswide);
				if (crc > 0) {
					/* item A: terminal bit FIRST,
					 * then the common abort — the abort's
					 * late-death defer must not treat
					 * this slot as an un-replayed death. */
					terminal |= (1ULL << slot);
					quarblocked &= ~(1ULL << slot);
					if (fswide)
						goto abort_fswide;
				} else if (crc == -EAGAIN) {
					quarblocked |= (1ULL << slot);
				} else {
					quarblocked &= ~(1ULL << slot);
				}
			}
			/* Retired bits re-enter via the top-of-loop cut
			 * recompute; only a genuinely dirty cut polls.  (A
			 * zero-todo entry — sweep failure — must still pay
			 * waited_ms or this branch would spin forever.) */
			if (todo & terminal) {
				todo &= ~terminal;
				if (!todo)
					continue;
			}
			/*
			 * The ghost extension is applied at the top of the
			 * loop (D-0980); here the elapsed-time bound is judged.
			 */
			if (expired) {
				mxfs_barrier_clock(mp, "bound", t_entry, t_loop,
						   wait_bound, round,
						   last_round_ms);
				if (drained & ~replayed & ~terminal)
					mxfs_v5_dlm_mount_defer_late_deaths(
						mp->m_mxfs_dlm,
						drained & ~replayed &
						~terminal);
				if (todo & quarblocked)
					xfs_alert(mp,
						"MXFS mount ABORTED: slot "
						"mask 0x%llx has a refusal "
						"verdict this node could not "
						"classify (unreadable or "
						"still landing) after %u ms "
						"— neither replayable nor "
						"provably quarantined.  "
						"Inspect the victim's "
						"heartbeat sector and retry "
						"the mount",
						(unsigned long long)
						(todo & quarblocked),
						waited_ms);
				if (!todo && undecl > 0) {
					xfs_alert(mp,
						"MXFS mount ABORTED: %d frozen "
						"heartbeat record(s) were still "
						"neither declared dead nor seen "
						"heartbeating after %u ms — "
						"admitting this mount would let "
						"it take locks over slices whose "
						"owner may be gone.  Inspect the "
						"heartbeat table and retry",
						undecl, waited_ms);
					return -EBUSY;
				}
				xfs_alert(mp,
					"MXFS mount ABORTED: slot mask 0x%llx "
					"still requires recovery after %d "
					"inline replay round(s) and %u ms — "
					"admitting this mount would let it "
					"take locks over unreplayed slices.  "
					"The slices stay frozen and pending; "
					"fix the blocker (fence path, or the "
					"recovery's owner) and retry",
					(unsigned long long)todo, round,
					waited_ms);
				return -EBUSY;
			}
			/*
			 * D-0980: the poll sleep is clipped to what remains of
			 * the bound and is KILLABLE — a fatal signal on the
			 * mount task (a `timeout` terminating it) ends it at
			 * once and the cancellation is judged right after.
			 * Only a fatal signal wakes it; a handled or ignored
			 * one does not shorten the poll.
			 */
			{
				unsigned int	left_ms = wait_bound > waited_ms ?
						wait_bound - waited_ms : 1;
				unsigned int	nap_ms = min_t(unsigned int,
						MXFS_BARRIER_ADMISSION_POLL_MS,
						left_ms);

				schedule_timeout_killable(
					msecs_to_jiffies(nap_ms ? nap_ms : 1));
			}
			if (fatal_signal_pending(current))
				goto abort_cancelled;
			/*
			 * (D-0355): FALL THROUGH into a replay round.
			 * The poll used to only classify and wait for a survivor
			 * to finish the slice — but when THIS mount is the only
			 * node (a lone remount after its own dirty shutdown, or
			 * the vergate loop device) nobody else exists, and the
			 * inline rounds above all ran ~50 ms BEFORE our own fence
			 * pipeline sealed the certificate (P236-CLAIM-UNCERTIFIED
			 * x4, then P-RMAN-SEALED): the "-1 not provably excluded"
			 * refusal was never retried and the mount aborted -EBUSY
			 * after 30 s over a slice it could have replayed.  One
			 * bounded attempt per poll interval; every acquire that
			 * still cannot certify fails fast exactly as before, so
			 * the wait bound is unchanged.
			 */
		}

		round++;
		t_round = jiffies;
		if (round > 1 && todo)
			xfs_notice(mp,
				"MXFS mount recovery: slot mask 0x%llx still "
				"requires recovery — replay round %d",
				(unsigned long long)todo, round);
		for (slot = 0; slot < 64; slot++) {
			unsigned int	budget_ms;

			if (!(todo & (1ULL << slot)))
				continue;
			if (xfs_is_shutdown(mp))
				break;
			/*
			 * D-0980: between slices is a recovery-safe boundary.
			 * Past the deadline no further slice is started (the
			 * loop top then refuses the mount); a pending fatal
			 * signal likewise stops the round there.  The acquire
			 * below is told what remains of the bound, so a
			 * takeover whose 6 s abandonment observation cannot
			 * finish inside it is refused up front instead of run.
			 */
			if (fatal_signal_pending(current) ||
			    time_after_eq(jiffies, deadline))
				break;
			budget_ms = jiffies_to_msecs(deadline - jiffies);
			if (!budget_ms)
				budget_ms = 1;

			/*
			 * — the same replay gate as the live path.  A
			 * cohort slot was confirmed dead over the full ~62 s
			 * heartbeat window and fenced by v5_settle_resolve, but
			 * "we tried to fence it" is not "it is provably
			 * excluded": on this rig 30 of 31 fence attempts reach a
			 * kind that proves nothing.  Only the certificate in the
			 * victim's own sector authorises the replay below.
			 */
			/*
			 * (design-consult ruling): classify BEFORE acquire —
			 * no lease is ever obtainable over a quarantined
			 * descriptor, so a terminal slot must be recognized
			 * and disposed from the platter snapshot, not from a
			 * lease this mount cannot get.
			 */
			crc = mxfs_barrier_classify_slot(mp, slot, &fswide);
			if (crc > 0) {
				/* item A: terminal bit FIRST, then
				 * the common abort. */
				terminal |= (1ULL << slot);
				quarblocked &= ~(1ULL << slot);
				if (fswide)
					goto abort_fswide;
				continue;
			}
			if (crc == -EAGAIN) {
				quarblocked |= (1ULL << slot);
				continue;
			}
			quarblocked &= ~(1ULL << slot);
			rc = mxfs_v5_dlm_recovery_acquire_bounded(mp->m_mxfs_dlm,
								  slot, budget_ms);
			if (rc == -EPERM) {
				/*
				 * ruling Q3: a quarantine may have
				 * landed between the classification read and
				 * the claim — reclassify ONCE; only a still-
				 * nonterminal slot keeps the ordinary
				 * wait-state handling below.
				 */
				crc = mxfs_barrier_classify_slot(mp, slot,
								 &fswide);
				if (crc > 0) {
					terminal |= (1ULL << slot);
					quarblocked &= ~(1ULL << slot);
					if (fswide)
						goto abort_fswide;
					continue;
				}
				/* sess333 item C cleanup: a transient
				 * reclassify here is the same "neither
				 * replayable nor provably quarantined"
				 * state the poll phase tracks.  sess335
				 * review: it is NOT the generic wait state —
				 * continue, so the "not provably excluded"
				 * alert below doesn't misdescribe it.  A
				 * crc==0 reclassify DOES fall through to
				 * that alert (deliberate: the claim refused
				 * -EPERM but the platter shows nonterminal —
				 * ordinary wait-state handling applies). */
				if (crc == -EAGAIN) {
					quarblocked |= (1ULL << slot);
					continue;
				}
			}
			if (rc == -EBUSY) {
				/* Owned by another survivor — EXPECTED, not
				 * a fault (ruling): the admission
				 * gate polls until the owner completes. */
				xfs_notice(mp,
					"MXFS mount recovery: slice slot=%u is "
					"being recovered by another survivor — "
					"waiting for completion", slot);
				continue;
			}
			if (rc) {
				xfs_alert(mp,
					"MXFS mount recovery: slice slot=%u NOT "
					"replayed (%d) — the dead node is not "
					"provably excluded from the LUN.  Its "
					"grants stay frozen; later rounds and "
					"the admission gate retry once a fence "
					"certificate exists",
					slot, rc);
				continue;
			}

			if (unlikely(mxfs_dbg_barrier_refuse_after_claim)) {
				int	lrc;

				mxfs_dbg_barrier_refuse_after_claim = 0;	/* one shot */
				lrc = mxfs_v5_dlm_recovery_relinquish(mp->m_mxfs_dlm,
								      slot);
				if (drained & ~replayed & ~terminal)
					mxfs_v5_dlm_mount_defer_late_deaths(
						mp->m_mxfs_dlm,
						drained & ~replayed & ~terminal);
				mxfs_barrier_clock(mp, "dbg-refused", t_entry,
						   t_loop, wait_bound, round,
						   last_round_ms);
				xfs_alert(mp,
					"MXFS mount ABORTED: P-DBG-BARRIER-REFUSE-AFTER-CLAIM slot=%u relinquish_rc=%d — TEST ONLY: the recovery lease was claimed and is given back; the descriptor stays certified and unowned for the next mount",
					slot, lrc);
				return -EBUSY;
			}
			/*
			 * design review item 2/5: unlike the live path, the barrier may
			 * not force the log or push the AIL (recovered intents are
			 * sitting in it), so there is no destage round available to
			 * retry with — an incomplete invalidation here can only be
			 * refused.  It should not happen: nothing has run on this
			 * mount yet, so no buffer can be carrying un-destaged
			 * committed content of ours.  If one is, replaying over it
			 * would let our writeback overwrite the recovered image.
			 */
			if (mxfs_dlm_invalidate_cached_views(mp)) {
				xfs_alert(mp,
					"MXFS mount recovery: slice slot=%u NOT "
					"replayed — cached views could not be dropped "
					"first, so replay could neither read current "
					"disk state nor survive our own writeback",
					slot);
				continue;
			}
			/* Pre-replay: coherency only.  Pass 2's LSN gate must compare
			 * against current disk state, which the epoch advance
			 * certifies; nothing is published on the strength of it. */
			mxfs_blkdev_flush_epoch(mp);
			/*
			 * design review item 6C: this return value used to be
			 * DISCARDED, so a slice whose replay FAILED was published
			 * exactly like one that succeeded — CAW manifest purged,
			 * heartbeat sector zeroed, every peer told the slice was
			 * recovered.  A refused slice must stay unpublished so its
			 * grants remain frozen and someone redoes it.
			 *
			 * An unsliced FS (no per-node journals) is the one case
			 * where there is genuinely nothing to replay: the dead
			 * peer's log IS the log we already recovered in
			 * xfs_log_mount, so the slot is publishable without a
			 * foreign replay.  Test that CONFIGURATION directly rather
			 * than inferring it from an errno.
			 */
			/*
			 * THE SAME GUARD THE LIVE REAP PATH ALREADY HAS, AND
			 * THE ONLY REASON IT IS WRITTEN TWICE IS THAT THIS PATH
			 * WAS LEFT WITHOUT IT.
			 *
			 * A survivor may take over a descriptor whose previous
			 * owner died part-way through, and the contract is that
			 * it RESUMES FROM THE RECORDED STAGE and never re-runs
			 * an earlier one, because peers may already have acted
			 * on the later one.  This loop took the lease and then
			 * replayed unconditionally, so a takeover at
			 * GRANTS_RELEASED re-issued a replay whose work was
			 * already durable -- and that replay cannot succeed,
			 * because passing that stage legitimately releases the
			 * two things it reads: the descriptor is no longer at
			 * FENCED, so token enforcement aborts it, and the
			 * authority manifest is gone.  The slice failed EIO, the
			 * round retried it for ever, and the mount never
			 * completed.
			 *
			 * Not merely wasted work, either.  Replay is idempotent
			 * against the state it was gated on, but re-running it
			 * over metadata legitimately written since could roll
			 * that metadata back.  The enforcement refusing is what
			 * stopped that; issuing the replay at all is the defect.
			 */
			{
				unsigned int	dstage = 0;

				if (mxfs_v5_dlm_recovery_stage(mp->m_mxfs_dlm,
							       slot,
							       &dstage) == 0 &&
				    dstage >= MXFS_RECOV_STAGE_IMAGES_REPLAYED) {
					xfs_notice(mp,
						"MXFS mount recovery: slice slot=%u descriptor already at stage %u (IMAGES_REPLAYED durable) — skipping the slice replay and completing the remaining ladder",
						slot, dstage);
					goto barrier_slice_replayed;
				}
			}
			if (mxfs_has_log_slices(mp)) {
				struct mxfs_freplay_verdict	fv;

				/*
				 * (review item D): the
				 * barrier holds the recovery lease from
				 * acquire() above, so a refusal here is
				 * PUBLISHED through the same state machine
				 * as the live reap path.  The old shape
				 * passed a NULL verdict and published
				 * nothing: a lone survivor cold-starting
				 * against a torn slice looped -EBUSY mount
				 * restarts forever without an operator-
				 * facing quarantine — the D-513 defect
				 * surviving on the mount path.
				 */
				/* start the NEXT victim's slice
				 * stability proof on a worker so its 2 s
				 * intervals overlap this slice's proof and
				 * replay (ruling: option A) */
				/* arm the next `depth` victims — the
				 * single-entry form dropped slot k's proof when
				 * k+1 was armed (chain 36: 30/31 inline) */
				{
					uint32_t nx;
					int armed = 0;
					int depth = READ_ONCE(mxfs_fr_stab_prefetch);

					for (nx = slot + 1; nx < 64 && armed < depth; nx++)
						if (todo & (1ULL << nx)) {
							mxfs_xlog_snap_prefetch(mp, nx);
							armed++;
						}
				}
				error = mxfs_xlog_recover_foreign_slice(mp, slot, &fv);
				if (error) {
					/* A refused replay may have applied a
					 * prefix before the gate tripped —
					 * drop cached views BEFORE the
					 * publish/continue so nothing reads
					 * the partial images.
					 *
					 * review stop-ship 1: the
					 * drop must SUCCEED before anything
					 * is published.  A failed drop with
					 * a published refusal would AG-admit
					 * this mount while stale partial-
					 * prefix images stay cached.  On
					 * failure publish nothing: the slot
					 * stays in the cut, later rounds
					 * retry, and the admission wait
					 * bound fails the mount -EBUSY. */
					if (mxfs_dlm_invalidate_cached_views(mp)) {
						xfs_alert(mp,
							"MXFS mount recovery: slice slot=%u "
							"replay refused but cached views could "
							"not be invalidated — nothing published, "
							"the slot stays in the cut",
							slot);
						continue;
					}
					if (fv.reason != MXFS_FREPLAY_REASON_NONE) {
						if (mxfs_freplay_publish_refusal(
								mp, slot, &fv,
								error)) {
							/* terminal bit FIRST
							 * (item A ordering);
							 * AG-scope admits,
							 * FSWIDE aborts. */
							terminal |= (1ULL << slot);
							/* (§6.6): under
							 * a bootstrap term a
							 * terminal slice refuses
							 * the whole term */
							mxfs_v5_dlm_bootstrap_terminal(
								mp->m_mxfs_dlm, slot);
							/* (design-consult review): a
							 * REFUSED term takes no more
							 * completion bits — stop here
							 * rather than run 30 more
							 * replays whose completion
							 * CASes all fail (chain 27:
							 * P-BOOT-COMPLETE-CASFAIL x24) */
							if (mxfs_v5_dlm_bootstrap_adopted(
								    mp->m_mxfs_dlm)) {
								xfs_alert(mp,
				"MXFS mount ABORTED: the whole-cluster bootstrap term is REFUSED by terminal slot %u — the barrier stops here; admission stays closed",
									  slot);
								goto abort_fswide;
							}
							spin_lock(&mp->m_mxfs_quar_lock);
							fswide = mp->m_mxfs_quar_fswide;
							spin_unlock(&mp->m_mxfs_quar_lock);
							if (fswide)
								goto abort_fswide;
							continue;
						}
						/* Transient publish state —
						 * nothing latched.  The slot
						 * stays in the cut; later
						 * rounds and the admission
						 * poll retry, and the wait
						 * bound fails the mount. */
						xfs_alert(mp,
							"MXFS mount recovery: slice slot=%u "
							"replay refused but the verdict could "
							"not be published — the slot stays in "
							"the cut and will be retried",
							slot);
						continue;
					}
					xfs_alert(mp,
						"MXFS mount recovery: slice slot=%u "
						"replay FAILED (%d) — the slot stays "
						"unpublished, its grants stay frozen "
						"and it will be replayed again",
						slot, error);
					continue;
				}
				/* 0.85.0: the census verdict for the ladder's
				 * IMAGES_REPLAYED milestone (see the live
				 * reap path); an unparked list publishes
				 * nothing and the slot stays in the cut. */
				if (mxfs_freplay_park_census(mp, slot, &fv)) {
					xfs_alert(mp,
						"MXFS mount recovery: slice slot=%u "
						"replayed but its obligation verdict "
						"could not be parked — the slot stays "
						"in the cut and will be retried", slot);
					continue;
				}
			} else {
				mxfs_v5_dlm_recovery_set_census_zero(
						mp->m_mxfs_dlm, (int)slot);
			}
barrier_slice_replayed:
			/* Post-replay: DURABILITY (design review item 1).  Step (d)
			 * below purges this slot's CAW manifest and zeroes its
			 * heartbeat record — the two pieces of evidence that would
			 * make a later mount re-run this replay.  If the images are
			 * still only in the target write cache when that happens, a
			 * target power loss loses the recovery AND the reason to
			 * redo it.  A failed flush therefore keeps the slot OUT of
			 * `replayed`: its grants stay frozen and its pending marker
			 * stays set, so the next mount (or a surviving peer's
			 * re-election sweep) replays it again — replay is LSN-gated
			 * and idempotent, so redoing it is always safe. */
			error = mxfs_blkdev_flush_durable(mp);
			if (error) {
				mxfs_dlm_invalidate_cached_views(mp);
				xfs_alert(mp,
					"MXFS mount recovery: slice slot=%u replayed "
					"but its durability flush FAILED (%d) — the "
					"slot stays unpublished and will be replayed "
					"again", slot, error);
				continue;
			}
			/* item 2/5: a view we could not drop after the replay
			 * is a buffer of ours that will be written back over the
			 * image the replay just recovered.  Do not publish. */
			error = mxfs_dlm_invalidate_cached_views(mp);
			if (error) {
				xfs_alert(mp,
					"MXFS mount recovery: slice slot=%u replayed "
					"but our cached views could not be dropped "
					"afterwards (%d) — a retained buffer would "
					"overwrite the recovered images, so the slot "
					"stays unpublished and will be replayed again",
					slot, error);
				continue;
			}

			/*
			 * C8: the dead slot's AGI unlinked bucket is now
			 * consistent but orphaned.  It CANNOT be swept here — the
			 * sweep does iget + transactions, and neither the root inode
			 * nor xfs_log_mount_finish's intent replay has run yet.
			 * Record it; mxfs_reap_worker consumes the bitmap once the
			 * mount is live (scheduled from the settle below).
			 */
			set_bit(slot, mp->m_mxfs_sweep_pending_slots);
			replayed |= (1ULL << slot);
			nreplayed++;

			/*
			 * 0.75.73 (measured s561 on 0.75.72, tests/evidence/
			 * 20260909T001304Z_ghost_s561): publish THIS slice now,
			 * inside the cut, the way the live reap path does after
			 * every foreign replay (mxfs_dlm_foreign_replay_work_fn
			 * completes each slot right behind its durable flush).
			 * Deferring every completion to the end of a clean cut
			 * deadlocked two concurrent joiners: each held the
			 * execution lease of one slice, replayed it, and then
			 * polled the other's — 'slice slot=N is being recovered
			 * by another survivor — waiting for completion', 66 polls
			 * per node, owner why='heartbeating' — until the bound,
			 * because neither published until its own cut was clean
			 * and neither cut could be clean before the other
			 * published.  Both mounts failed -EBUSY and the replays
			 * were lost (the descriptors stayed at FENCED, unowned).
			 *
			 * The end-of-cut ordering was kept for a cross-slice
			 * evidence rule that no longer holds: the replay gate
			 * judges every image against the VICTIM'S OWN sealed
			 * fence-time manifest and the victim's own live bits
			 * (xfs_log_recover.c, P-RMAN-EVAL / the current-safety
			 * check), never against another victim's grants, so
			 * purging slot A's manifest cannot change slice B's
			 * verdicts.  Completion below runs the same ladder the
			 * end-of-cut call ran, over one slot.  A failure here is
			 * not fatal yet: the slot stays in `replayed` and the
			 * end-of-cut completion retries it and fails the mount
			 * exactly as before if it still cannot publish.
			 *
			 * Under a whole-cluster bootstrap term the sealed set
			 * completes only after every manifest slice is replayed
			 * (docs/whole-cluster-restart.md, 6.6), so the per-slice
			 * publish is skipped there and the end-of-cut call keeps
			 * that ordering.
			 */
			if (!mxfs_v5_dlm_bootstrap_adopted(mp->m_mxfs_dlm)) {
				uint64_t	pub = 0, opn = 0;
				int		perr;

				perr = mxfs_v5_dlm_mount_cohort_complete(
						mp->m_mxfs_dlm, 1ULL << slot,
						&pub, &opn);
				published |= pub;
				if (opn)
					mxfs_barrier_note_open_cases(mp, opn,
								     &published);
				if (perr)
					xfs_alert(mp,
						"MXFS mount recovery: slice slot=%u "
						"replayed but its publication failed "
						"(%d) — retried when the cut is "
						"clean; until then its grants stay "
						"held and peers waiting on it keep "
						"waiting", slot, perr);
				else
					xfs_notice(mp,
						"MXFS mount recovery: P-BARRIER-SLICE-"
						"PUBLISHED slot=%u — replayed and "
						"published inside the cut; a peer "
						"waiting on this slice may now retire "
						"it", slot);
			}
		}
		/* Loop back: re-drain and re-sweep immediately.  A slot this
		 * round could not replay is retried by later rounds (the
		 * replay is LSN-gated and idempotent, and a fence certificate
		 * may have landed meanwhile); the round cap plus the bounded
		 * admission wait is what keeps a cap from becoming a spin. */
		last_round_ms = jiffies_to_msecs(jiffies - t_round);
	}

	/*
	 * slices that were pending at some point but that WE did not
	 * replay were completed by another survivor while we waited.  Our
	 * cached views (read under xfs_log_mount, before those recoveries
	 * finished) may hold pre-replay images — drop them before anything
	 * downstream reads shared metadata.  A failed invalidation here is a
	 * retained stale buffer over recovered metadata: the defect itself.
	 */
	if (seen & ~replayed) {
		error = mxfs_dlm_invalidate_cached_views(mp);
		if (error) {
			xfs_alert(mp,
				"MXFS mount ABORTED: slot mask 0x%llx was "
				"recovered by another survivor during this "
				"mount but our cached views could not be "
				"dropped (%d) — a retained buffer would carry "
				"pre-recovery images",
				(unsigned long long)(seen & ~replayed), error);
			return error;
		}
	}

	/*
	 * Anything drained but not durably replayed goes straight back to the
	 * DLM's late-death record: the post-mount settle dispatches it to a
	 * real replayer election once the slice-replay hook exists.  Dropping
	 * it here would leave the slice fenced and pending on disk with no
	 * live route to a replay — recoverable only by the next mount.
	 */
	if (drained & ~replayed & ~terminal) {
		xfs_alert(mp,
			"MXFS mount recovery: peer slot mask 0x%llx died during "
			"this mount but was not replayed in %d round(s) — "
			"deferred to the post-mount settle; their grants stay "
			"frozen and can stall log recovery below",
			(unsigned long long)(drained & ~replayed & ~terminal),
			MXFS_BARRIER_REPLAY_ROUNDS);
		mxfs_v5_dlm_mount_defer_late_deaths(mp->m_mxfs_dlm,
						    drained & ~replayed &
						    ~terminal);
	}

	/*
	 * (d) Complete what the loop replayed but could not publish inline:
	 *     a slot whose per-slice publication failed, and — under a
	 *     whole-cluster bootstrap term — every replayed slot, since that
	 *     path completes only after the whole sealed set is replayed
	 *     (docs/whole-cluster-restart.md, 6.6).  Before 0.75.73 this was
	 *     the ONLY completion call, deferred to a clean cut for a
	 *     cross-slice evidence rule that the per-victim sealed
	 *     manifest made obsolete; see the per-slice publish in the loop.
	 *
	 * design review item 6C: complete only what was ACTUALLY
	 * replayed, never the whole cohort.  A shutdown mid-loop leaves
	 * later slots unreplayed, and purging those would publish a slice
	 * nobody has recovered.  Their grants stay frozen — the safe
	 * direction — and mxfs_disklock's pending marker keeps them
	 * re-detectable by the survivors' re-election sweep.
	 */
	if (todo)
		xfs_alert(mp,
			"MXFS mount recovery barrier INCOMPLETE (shutdown): "
			"cohort=0x%llx late=0x%llx pending=0x%llx "
			"replayed=0x%llx — unreplayed slices stay frozen and "
			"unpublished",
			(unsigned long long)cohort,
			(unsigned long long)drained,
			(unsigned long long)todo,
			(unsigned long long)replayed);
	if (replayed & ~published) {
		uint64_t	pub = 0, opn = 0;

		/*
		 * design review item 6D: publication can fail.  A slot whose CAW
		 * purge, durability flush or heartbeat zero did not complete
		 * is NOT published — its pending marker and heartbeat record
		 * survive, so the next mount or a survivor's re-election
		 * sweep redoes it.  Its grants therefore also stay held, and
		 * xfs_log_mount_finish below may block on them exactly as the
		 * (b2) residue gate describes.  Fail the mount for the same
		 * reason (b2) does: a named failure in seconds beats a
		 * 120 s-per-acquire stall that fails anyway.
		 */
		error = mxfs_v5_dlm_mount_cohort_complete(mp->m_mxfs_dlm,
							  replayed & ~published,
							  &pub, &opn);
		published |= pub;
		if (opn)
			mxfs_barrier_note_open_cases(mp, opn, &published);
		if (error) {
			/* item 6B: a late death we DID replay but could
			 * not publish is about to be forgotten by a failing
			 * mount.  Put it back — if this mount is retried in the
			 * same DLM incarnation the settle still dispatches it,
			 * and the teardown census stays honest either way. */
			if (drained & replayed & ~published)
				mxfs_v5_dlm_mount_defer_late_deaths(
					mp->m_mxfs_dlm,
					drained & replayed & ~published);
			xfs_alert(mp,
				"MXFS mount ABORTED: replayed=0x%llx but only "
				"published=0x%llx (%d) — the unpublished "
				"slices' grants are still held by nodes that "
				"cannot release them, so log recovery below "
				"would block on them.  The slices stay marked "
				"pending and will be recovered on retry.",
				(unsigned long long)replayed,
				(unsigned long long)published, error);
			return error;
		}
	}

	/*
	 * (e) Finally reclaim OUR previous incarnation's un-adopted
	 *     authority bits and close the adopt window.  Last, because
	 *     every foreign replay above may consult the CAW table, and
	 *     because anything our own recovery genuinely needed has by now
	 *     adopted (xfs_log_mount ran in step (a)'s predecessor).
	 */
	error = mxfs_v5_dlm_settle_own_slot(mp->m_mxfs_dlm);
	if (error)
		xfs_alert(mp,
			"MXFS mount settle incomplete (%d) — some authority "
			"entries from a previous incarnation were not "
			"reclaimed; peers may block on them until this node "
			"unmounts", error);

	/*
	 * (review item 6): the unconditional FSWIDE gate at
	 * the successful-admission boundary.  Every fswide import above
	 * routes through an abort site already; this closes any path that
	 * imported without routing — belt and suspenders on the invariant
	 * that a known-fswide quarantine NEVER admits.
	 */
	spin_lock(&mp->m_mxfs_quar_lock);
	fswide = mp->m_mxfs_quar_fswide;
	spin_unlock(&mp->m_mxfs_quar_lock);
	if (fswide)
		goto abort_fswide;

	mxfs_barrier_clock(mp, "admitted", t_entry, t_loop, wait_bound, round,
			   last_round_ms);
	xfs_notice(mp,
		"MXFS mount recovery barrier complete: cohort=0x%llx "
		"late=0x%llx replayed=%d published=0x%llx quarantined=0x%llx",
		(unsigned long long)cohort, (unsigned long long)drained,
		nreplayed, (unsigned long long)published,
		(unsigned long long)terminal);
	/*
	 * (§6.6, shape B): the whole-cluster bootstrap completes
	 * HERE — every sealed foreign slice replayed and published behind
	 * its durable completion bit, our own adopted slice K mounted —
	 * with the READ KEYS reconciliation and the RECOVERY_COMPLETE CAS.
	 * A terminal slice above already refused the term; any other
	 * failure refuses this mount with the term standing.
	 */
	error = mxfs_v5_dlm_bootstrap_finish(mp->m_mxfs_dlm);
	if (error) {
		xfs_alert(mp,
			"MXFS mount ABORTED: whole-cluster bootstrap did not reach "
			"RECOVERY_COMPLETE (%d) — admission stays closed; see the "
			"P-BOOT-* lines", error);
		return error;
	}
	return 0;

abort_cancelled:
	/*
	 * D-0980: a fatal signal is pending on the mount task.  The same
	 * hand-back the bound's abort performs — un-replayed late deaths go
	 * back to the mphase record — and nothing else: every slice this
	 * mount did not publish stays frozen and durably pending on the
	 * platter, where the next mount or a survivor's sweep finds it, and
	 * a lease this mount claimed names an incarnation that ends with the
	 * failed mount, so a later owner takes it over through the lease
	 * protocol.  -EINTR, never -EBUSY: cancellation is not contention.
	 */
	if (drained & ~replayed & ~terminal)
		mxfs_v5_dlm_mount_defer_late_deaths(mp->m_mxfs_dlm,
						    drained & ~replayed &
						    ~terminal);
	mxfs_barrier_clock(mp, "cancelled", t_entry, t_loop, wait_bound, round,
			   last_round_ms);
	xfs_alert(mp,
		"MXFS mount ABORTED: P-BARRIER-CANCELLED a fatal signal is "
		"pending on the mount task after %u ms of the admission wait "
		"(slot mask 0x%llx still requires recovery) — nothing was "
		"admitted; the slices stay frozen and pending for the next "
		"mount or a survivor",
		waited_ms, (unsigned long long)todo);
	return -EINTR;

abort_fswide:
	/*
	 * Common FSWIDE abort (review item A): every barrier exit
	 * after `drained` accumulates must hand un-replayed late deaths
	 * back to the mphase record, or a death recorded during this
	 * barrier is forgotten by the failing mount and its slice loses
	 * its live route to a replay.  Callers set the aborting slot's
	 * terminal bit BEFORE jumping here, so a slice whose heartbeat
	 * sector now carries the durable outcome record is NOT re-deferred
	 * as a pending death.  (defer_late_deaths ORs into the mphase
	 * mask, so a mask a prior exit already deferred re-defers
	 * idempotently.)
	 */
	if (drained & ~replayed & ~terminal)
		mxfs_v5_dlm_mount_defer_late_deaths(mp->m_mxfs_dlm,
						    drained & ~replayed &
						    ~terminal);
	mxfs_barrier_clock(mp, "fswide", t_entry, t_loop, wait_bound, round,
			   last_round_ms);
	xfs_alert(mp,
		"MXFS mount ABORTED: a terminal recovery refusal quarantines "
		"the WHOLE filesystem (terminal=0x%llx) — every operation "
		"this mount could admit would fail with EIO.  Repair the "
		"refused slice targets, clear the outcome record, and "
		"remount",
		(unsigned long long)terminal);
	return -EIO;
}

void
mxfs_dlm_mount_recovery_settle(
	struct xfs_mount	*mp)
{
	int			error;

	if (!mp || !mp->m_mxfs_dlm)
		return;

	/*
	 * the flush/force/drain round that used to open this
	 * function moved into mxfs_dlm_mount_recovery_barrier() (as a bare
	 * device flush — see there).  What is left is the two things that
	 * genuinely require a LIVE mount:
	 *
	 *   - the deferred survivor sweeps the barrier recorded but could
	 *     not run (iget + transactions), and
	 *   - the asynchronous retry of whatever the barrier's cohort
	 *     resolution could not fence.
	 */
	if (!bitmap_empty(mp->m_mxfs_sweep_pending_slots, 64)) {
		set_bit(MXFS_REAPF_UBSCAN, &mp->m_mxfs_reap_duties);
		mxfs_reap_sched(mp, MXFS_REAP_FIRST_MS, "mount-barrier-sweep");
	}

	error = mxfs_v5_dlm_mount_settle(mp->m_mxfs_dlm);
	if (error)
		xfs_alert(mp,
			"MXFS mount settle residue retry failed (%d) — "
			"unfenced peer slices stay frozen and unreplayed",
			error);
}
