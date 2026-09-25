// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS — Multinode XFS
 * XFS-side DLM lock caching (Phase 3)
 *
 * Caches DLM lock grants per-inode. Releases only on BAST (blocking AST
 * from another node), inode eviction, or unmount.
 *
 * Design based on GFS2 glocks, OCFS2 dlmglue, and mxfs.1 inode_cache:
 *   - DLM lock ordering: DLM outer, VFS i_rwsem inner
 *   - BAST processing: deferred to workqueue, never inline
 *   - Holder counting: separate EX/PR counters
 *   - DEMOTING state: blocks new lock attempts during flush
 *
 * Copyright (c) 2026
 */
#define MXFS_TU_ID 1	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * (D-474 AIL-freeze anatomy): pag_dlm_lock hold/wait forensics.
 * See the field comment in xfs_ag.h.  Every mutex_lock/unlock of a
 * pag_dlm_lock in this file routes through these two helpers (mechanical
 * rewrite; the only other site is the mutex_init in xfs_ag.c).
 *
 *   P-AGMUTEX-WAIT  — a waiter waited >= mxfs_agmutex_warn_ms; names the
 *                     owner (pid/comm/lock-site) sampled when the wait began.
 *   P-AGMUTEX-HOLD  — a holder held it >= mxfs_agmutex_warn_ms; names the
 *                     lock site and unlock site and dumps the holder's stack
 *                     (ratelimited) so the blocking edge between them is read
 *                     off the kernel, not guessed.
 */
atomic64_t mxfs_dlm_stat_agtry_localbusy = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_ag_trydemoting = ATOMIC64_INIT(0);
/*
 * handoff-latch accounting (D-RSYNC-LAP-PACE-AG-SHARING-388).
 *   latch_unlock / latch_acq / latch_acqnb — who performed the COMMIT
 *     outside the worker (last-holder unlock, blocking acquirer, nonblock
 *     acquirer); worker COMMITs are the existing P12-WORK COMMIT path.
 *   handoff_n + b2c (BAST rx -> COMMIT) and c2r (COMMIT -> on-disk release)
 *     sums/maxima in ms, with >50 ms and >500 ms buckets — the ruling's
 *     acceptance numbers (p50 needs the sum/n; p99/max need the buckets and
 *     the max).
 *   demote_wait_n / _ms / _max / _trans / _dirty — blocking acquirers that
 *     slept in wait_demote (the ILOCK-holder hazard class the ruling wants
 *     counted), how long, and whether they carried a (dirty) transaction.
 *   postlatch_adopt — invariant counter, must stay 0: a cached fast-path
 *     adoption observed while latched.
 */
atomic64_t mxfs_dlm_stat_latch_unlock = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_latch_acq = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_latch_acqnb = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_n = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_b2c_ms = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_b2c_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_b2c_gt50 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_b2c_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_c2r_ms = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_c2r_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_c2r_gt50 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_c2r_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_demote_wait_n = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_demote_wait_ms = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_demote_wait_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_demote_wait_trans = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_demote_wait_dirty = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_postlatch_adopt = ATOMIC64_INIT(0);
/* 0.22.3: BAST->COMMIT split tails (rx->queued, queued->enter, enter->armed, armed->commit) */
atomic64_t mxfs_dlm_stat_handoff_q_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_q_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_wq_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_wq_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_e2a_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_e2a_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_a2c_gt500 = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_a2c_max = ATOMIC64_INIT(0);
atomic64_t mxfs_dlm_stat_handoff_rxheld = ATOMIC64_INIT(0);	/* holders>0 at first rx */
atomic64_t mxfs_dlm_stat_stale_hint = ATOMIC64_INIT(0);	/* 0.22.4: pre-acquire hints dropped */

/*
 * every demote-completion site clears the latch state with the
 * demoting flag — a latched COMMIT that completed (or was abandoned by an
 * inject/unmount path) must never leave pag_dlm_latched behind, or the
 * next worker run would re-enter the committed path on a released grant.
 */
void mxfs_ag_demote_clear(struct xfs_perag *pag)
{
	pag->pag_dlm_demoting = false;
	pag->pag_dlm_latched = false;
	pag->pag_dlm_prepass_done = false;
	/*
	 * 0.22.1: the schedule latch is released HERE, at demote
	 * completion — not at the COMMIT.  mxfs_ag_handoff_commit keeps
	 * pag_dlm_bast_scheduled set across the drains so the rx watchdog
	 * (P275-AG-STUCK-LATCH) can requeue a lost worker; 0.22.0 then never
	 * cleared it, so after the first completed handoff on an AG every
	 * later BAST saw sched=1, neither rx nor the last-holder unlock queued
	 * the worker, and each generation waited the full 30 s for the
	 * watchdog (measured 25 AGs lap 1: b2c_max=30031 ms, P275 requeued=1
	 * five times on one node, all three rows BUDGET_EXHAUSTED on 32/32).
	 * The pre-latch code cleared it at the COMMIT, i.e. strictly before
	 * every completion site, so clearing at completion is the same
	 * contract made explicit.
	 */
	pag->pag_dlm_bast_scheduled = false;
}

/*
 * 0.22.3: the one place the AG BAST worker is queued.  Stamps the
 * first queue of the current BAST generation (rx -> queued is the time a
 * pending revocation waited for a local holder to let go; queued -> enter is
 * the ordered-workqueue latency behind other AGs' workers on this mount).
 * Benign first-writer race on the stamp — instrumentation only.
 */
void mxfs_ag_bast_queue(struct xfs_mount *mp, struct xfs_perag *pag)
{
	if (!READ_ONCE(pag->pag_dlm_queued_ns))
		WRITE_ONCE(pag->pag_dlm_queued_ns, ktime_get_ns());
	if (mp->m_mxfs_ag_bast_wq)
		queue_work(mp->m_mxfs_ag_bast_wq, &pag->pag_dlm_bast_work);
	else
		schedule_work(&pag->pag_dlm_bast_work);
}

void mxfs_stat_max64(atomic64_t *v, s64 n)
{
	s64 old = atomic64_read(v);

	while (n > old) {
		s64 seen = atomic64_cmpxchg(v, old, n);

		if (seen == old)
			break;
		old = seen;
	}
}
/* lifecycle probe counters (defined with the machinery near
 * mxfs_dlm_bast_notify; tentative declarations here for the stats line). */
atomic64_t mxfs_noino_lifecycle_stat[XFS_ILC_NR];
atomic64_t mxfs_noino_lifecycle_requeued;
atomic64_t mxfs_noino_lifecycle_timeouts;
static int mxfs_agmutex_warn_ms = 300;
module_param_named(agmutex_warn_ms, mxfs_agmutex_warn_ms, int, 0644);
MODULE_PARM_DESC(agmutex_warn_ms,
	"warn when pag_dlm_lock is held or waited for >= this many ms (0=off)");

void
mxfs_pag_dlm_lock(struct xfs_perag *pag, int site)
{
	u64		t0 = 0;
	pid_t		opid = 0;
	int		osite = 0;
	char		ocomm[16] = "";

	if (!mutex_trylock(&pag->pag_dlm_lock)) {
		struct task_struct *own;

		t0 = ktime_get_ns();
		/* owner word: task pointer with the low 3 flag bits set. */
		rcu_read_lock();
		own = (struct task_struct *)
			(atomic_long_read(&pag->pag_dlm_lock.owner) & ~0x07UL);
		if (own) {
			opid = own->pid;
			strscpy(ocomm, own->comm, sizeof(ocomm));
		}
		rcu_read_unlock();
		osite = READ_ONCE(pag->pag_dlm_lock_site);
		mutex_lock(&pag->pag_dlm_lock);
		if (mxfs_agmutex_warn_ms > 0) {
			u64 w = ktime_get_ns() - t0;

			if (w >= (u64)mxfs_agmutex_warn_ms * NSEC_PER_MSEC)
				mxfs_probe("mxfs: P-AGMUTEX-WAIT ag=%u site=%u:%u waited_ms=%llu owner_at_start=%s/%d owner_site=%u:%u comm=%s pid=%d\n",
					pag_agno(pag), MXFS_SITE_ARGS(site),
					(unsigned long long)(w / NSEC_PER_MSEC),
					ocomm, opid, MXFS_SITE_ARGS(osite), current->comm,
					current->pid);
		}
	}
	pag->pag_dlm_lock_t0 = ktime_get_ns();
	pag->pag_dlm_lock_site = site;
	pag->pag_dlm_lock_pid = current->pid;
	strscpy(pag->pag_dlm_lock_comm, current->comm,
		sizeof(pag->pag_dlm_lock_comm));
}

void
mxfs_pag_dlm_unlock(struct xfs_perag *pag, int site)
{
	u64	held = ktime_get_ns() - pag->pag_dlm_lock_t0;
	int	lsite = pag->pag_dlm_lock_site;
	bool	warn = mxfs_agmutex_warn_ms > 0 &&
		       held >= (u64)mxfs_agmutex_warn_ms * NSEC_PER_MSEC;

	pag->pag_dlm_lock_site = 0;
	pag->pag_dlm_lock_pid = 0;
	mutex_unlock(&pag->pag_dlm_lock);
	if (warn) {
		static DEFINE_RATELIMIT_STATE(rs, 10 * HZ, 3);

		mxfs_probe("mxfs: P-AGMUTEX-HOLD ag=%u lock_site=%u:%u unlock_site=%u:%u held_ms=%llu comm=%s pid=%d\n",
			pag_agno(pag), MXFS_SITE_ARGS(lsite), MXFS_SITE_ARGS(site),
			(unsigned long long)(held / NSEC_PER_MSEC),
			current->comm, current->pid);
		if (mxfs_probe_on() && __ratelimit(&rs))
			dump_stack();
	}
}
static atomic_t mxfs_demev_seq = ATOMIC_INIT(0);

/*
 * D-DWORK-TEARDOWN-LASTREF-LEAK class fix: single gate for EVERY
 * per-inode bast work/dwork arm (each arm owns one igrab ref; queued-false
 * means the caller drops it — both for "already queued" and "gate closed",
 * the same contract every site already implements).  put_super closes the
 * gate under m_mxfs_arm_lock, flushes the wq, then sweeps s_inodes
 * sync-canceling armed works: a delayed work still on its timer is
 * invisible to flush_workqueue, and when its ref is the inode's LAST ref
 * the eviction whose P204 cancel would disarm it can never run (circular)
 * — the timer then outlives xfs_free_perag and the P142 last-ref guard
 * leaks the inode (captured live, ino 31457413).  Lock order:
 * callers may hold ip->i_dlm_lock; the sweep takes arm_lock only, never
 * i_dlm_lock, so i_dlm_lock -> arm_lock is the only edge.
 */
bool
mxfs_bast_arm_queue(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			queued = false;

	spin_lock(&mp->m_mxfs_arm_lock);
	if (unlikely(mp->m_mxfs_arms_off))
		pr_warn_ratelimited("mxfs: P6S-ARM-REFUSED ino=%llu src=%u — bast-arm gate closed (teardown)\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_bastq_src);
	else
		queued = queue_work(mp->m_mxfs_inode_bast_wq,
				    &ip->i_dlm_bast_work);
	if (queued)
		ip->i_dlm_bastq_qns = ktime_get_ns();
	spin_unlock(&mp->m_mxfs_arm_lock);
	return queued;
}

bool
mxfs_bast_arm_queue_delayed(
	struct xfs_inode	*ip,
	unsigned long		delay_j)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			queued = false;

	spin_lock(&mp->m_mxfs_arm_lock);
	if (unlikely(mp->m_mxfs_arms_off))
		pr_warn_ratelimited("mxfs: P6S-ARM-REFUSED ino=%llu src=%u — bast-dwork gate closed (teardown)\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_bastq_src);
	else
		queued = queue_delayed_work(mp->m_mxfs_inode_bast_wq,
					    &ip->i_dlm_bast_dwork, delay_j);
	if (queued)
		ip->i_dlm_bastq_qns = ktime_get_ns() +
				      jiffies_to_nsecs(delay_j);
	spin_unlock(&mp->m_mxfs_arm_lock);
	return queued;
}

/*
 * P296-BASTQLAT (D-503 instrumentation): measure the pure
 * queue-to-run EXCESS of every per-inode bast work/dwork on
 * m_mxfs_inode_bast_wq.  Hypothesis under test: during the post-load
 * sync-write pace collapse the shared-dir demote/handoff work sits queued
 * behind a torrent of sweep-release (src=16) works, so the dd writer's
 * ~1.7s/create EX-acquire wait (P36-MHT-REARM exh_ms=1672) is queue delay,
 * not lock-protocol delay.  Called at both work-fn entries right after the
 * ident check.  Logs only when the excess tops 100ms; capped per boot so a
 * genuine torrent cannot flood the ring.
 */
void
mxfs_bastq_lat_probe(
	struct xfs_inode	*ip,
	const char		*who)
{
	static atomic_t		p296_logged = ATOMIC_INIT(0);
	u64			qns = ip->i_dlm_bastq_qns;
	s64			excess;

	if (!qns)
		return;
	ip->i_dlm_bastq_qns = 0;
	excess = ktime_get_ns() - qns;
	if (excess < 100 * NSEC_PER_MSEC)
		return;
	if (atomic_inc_return(&p296_logged) > 400)
		return;
	mxfs_probe("mxfs: P296-BASTQLAT %s ino=%llu src=%u isdir=%d excess_ms=%lld\n",
		who, (unsigned long long)ip->i_ino, ip->i_dlm_bastq_src,
		S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
		div_s64(excess, NSEC_PER_MSEC));
}

/*
 * (ruling B): exponential backoff for the release-abort
 * re-arm loop.  The P15/P244/P95 defer arms re-fire the release pipeline
 * via a 25ms dwork; when the abort repeats with an UNCHANGED tenure gen
 * (no progress — the victim's fenced drain writes could never
 * land), each repeat doubles the delay toward a 1s cap so the loop cannot
 * hammer the node/target at 40Hz forever.  Gen movement (a fresh grant —
 * real progress) resets the streak, so healthy operation keeps today's
 * 25ms first-retry latency.  0-31ms jitter decorrelates a fleet of
 * victims re-firing in lockstep.  Fields are only touched here and at the
 * committed-release reset; the bast dwork is coalesced per inode, so
 * cross-call races are benign.
 */
unsigned int
mxfs_relab_backoff_ms(
	struct xfs_inode	*ip,
	uint32_t		now_gen)
{
	unsigned int		delay;

	if (ip->i_dlm_relab_gen != now_gen) {
		ip->i_dlm_relab_gen = now_gen;
		ip->i_dlm_relab_streak = 0;
	} else if (ip->i_dlm_relab_streak < 6) {
		ip->i_dlm_relab_streak++;
	}
	delay = 25U << ip->i_dlm_relab_streak;
	if (delay > 1000) {
		delay = 1000;
		pr_warn_ratelimited("mxfs: P279-RELAB-BACKOFF ino=%llu gen=%u streak=%u — release-abort re-arm at 1s cap (no tenure-gen progress)\n",
			(unsigned long long)ip->i_ino, now_gen,
			ip->i_dlm_relab_streak);
	}
	return delay + (get_random_u32() & 31);
}
/*
 * EXPOSURE counters for the `demoter_legacy_clobber` A/B arm.  The legacy
 * branches deliberately reproduce the pre-fix unconditional store/clear, so
 * they bypass the counters above.  Without their own instrumentation the
 * legacy arm has NO exposure measure, and "legacy armed, no wedge" is then
 * indistinguishable from "the race never happened" — which is precisely the
 * false-verification trap this whole campaign keeps hitting.
 */
/*
 * ROOT MEASUREMENT for the stranded demoter claim.  init_inherit counts
 * inodes that came out of xfs_inode_alloc with a claim ALREADY set — inherited
 * from the recycled slab object, because alloc_inode_sb does not zero it and
 * the initializer's MXFS_CLEAR_DEMOTER refuses a non-owner clear.  free_dirty
 * counts objects that went BACK to the slab still claimed, which is where the
 * inherited ones come from.  Exposure and source for one defect; both must
 * reach zero.  Declared here, with the other demoter counters, because
 * mxfs_dlm_inode_final_release is defined far above the punt-reclaim block.
 */
atomic64_t mxfs_dem_init_inherit;
atomic64_t mxfs_dem_free_dirty;

void
mxfs_demev_rec(struct xfs_inode *ip, uint8_t op, uint32_t line)
{
	uint8_t	h = ip->i_dlm_demev_head;

	if (h >= MXFS_DEMEV_N)
		h = 0;
	ip->i_dlm_demev_op[h] = op;
	ip->i_dlm_demev_line[h] = line;
	ip->i_dlm_demev_pid[h] = current->pid;
	ip->i_dlm_demev_state[h] = ip->i_dlm_state;
	ip->i_dlm_demev_cookie[h] = (uint32_t)atomic_inc_return(&mxfs_demev_seq);
	ip->i_dlm_demev_head = (h + 1) % MXFS_DEMEV_N;
}

/*
 * ROOT FIX for D-BAST-IRELE-INACTIVE-SELF-WEDGE (PROVEN by the
 * demoter ring, replayed off a live 32/caw wedge on test16):
 *
 *   P73-DEMEV[8]  SET   line=15980 pid=59368  cookie=446   <- bast_work_fn claims
 *   P73-DEMEV[9]  SET   line=16280 pid=56068  cookie=449   <- dwork_fn OVERWRITES it
 *   P73-DEMEV[10] CLEAR line=16292 pid=56068  cookie=450   <- dwork_fn CLEARS it
 *   P73-DEMEV[11] WAIT  line=25206 pid=59368  cookie=451   <- 59368 parks, demoter NULL
 *
 * mxfs_dlm_bast_work_fn (pid 59368) and mxfs_dlm_bast_dwork_fn (pid 56068)
 * both ran a release drain on the SAME inode.  The claim was an unqualified
 * single-slot `task_struct *`: the dwork stored itself over a live foreign
 * claim and then cleared the slot to NULL on its way out.  pid 59368's
 * trailing xfs_irele then cascaded into evict -> xfs_inactive ->
 * xfs_attr_inactive -> xfs_ilock, found i_dlm_demoter == NULL instead of
 * itself, lost the "demoter is exempt (it must re-enter during its own
 * drain)" exemption, and parked in the demote-wait FOREVER waiting for a
 * release that only it could drive.  Captured on 3 of 32 nodes at once,
 * 619-839 s and climbing, on a QUIESCED cluster.
 *
 * Two earlier candidate clobberers were refuted first, by their own probes
 * firing zero times: the orphan reclaim's demoter override
 * (P72-DEMOTER-OVERRIDE) and the EDEADLK-freeing self-clobber
 * (P60-EDEADLK-FREEING).  already fixed a DIFFERENT bug with
 * this same stack (clearing the claim before the trailing irele) and its
 * handoff warned the fix might be "necessary-but-not-sufficient".  This is
 * that second bug.
 *
 * THE FIX: the claim becomes OWNED and NESTABLE.
 *   - A task may claim only an unowned slot, or re-claim its own (depth++).
 *     A foreign LIVE claim is never overwritten.
 *   - Only the owner may release, and only the outermost release clears it.
 * cmpxchg rather than i_dlm_lock because the call sites disagree about
 * whether that spinlock is held (bast_work_fn and dwork_fn hold nothing here;
 * others are mid-critical-section), so taking it inside the macro would
 * deadlock some callers.  Depth is touched only by the owning task.
 */
/*
 * Is `current` one of the tasks currently draining this inode?  The demote-wait
 * exemption ("demoter is exempt — it must re-enter during its own drain") must
 * cover EVERY live drain of the inode, not just the first one to claim, or the
 * others stall 3s per nested ilock.  See i_dlm_demoter2 in xfs_inode.h.
 */
bool
mxfs_is_demoter(const struct xfs_inode *ip)
{
	return READ_ONCE(ip->i_dlm_demoter) == current ||
	       READ_ONCE(ip->i_dlm_demoter2) == current;
}

/*
 * Is some OTHER task currently draining this inode?
 *
 * With ONE claim slot this question was spelled inline at every call site as
 * `ip->i_dlm_demoter && !mxfs_is_demoter(ip)`.  Adding a second slot silently
 * broke that spelling: it reads FALSE whenever slot 1 has been released while
 * slot 2 is still draining.  That is a reachable and entirely ordinary state —
 * the two drains do not finish in claim order — so every "is a foreign drain
 * active?" test must consider BOTH slots.  Use this predicate for that
 * question and mxfs_is_demoter() only for "am *I* one of the drains?".
 */
bool
mxfs_foreign_demoter(const struct xfs_inode *ip)
{
	struct task_struct	*d1 = READ_ONCE(ip->i_dlm_demoter);
	struct task_struct	*d2 = READ_ONCE(ip->i_dlm_demoter2);

	/*
	 * SELF-EXEMPTION FIRST, and it is not optional.  The one-slot spelling
	 * this replaces was `ip->i_dlm_demoter && !mxfs_is_demoter(ip)`, whose
	 * second clause exempts US whenever we hold EITHER slot — so a task
	 * that is itself a drain never defers to another drain.
	 *
	 * A first cut of this helper wrote `(d1 && d1 != current) || (d2 && d2
	 * != current)`, which drops that exemption for the case "slot 1 foreign,
	 * slot 2 == me": a live drain then treats its peer as a reason to
	 * abandon its OWN reload.  Measured cost of getting this wrong at
	 * 32/caw: cache_coherency 0/32 (timed out at its 60 s budget, from 25 s
	 * passing), strong_consistency 25/32, posix_multi 1/32.
	 */
	if (d1 == current || d2 == current)
		return false;
	return d1 != NULL || d2 != NULL;
}

/*
 * Out-of-line claim/release for translation units that cannot see the macros
 * above (xfs_inode.c's inactivation upgrade path did its own raw
 * `i_dlm_demoter = current` / `= NULL` pair, which is the exact clobber shape
 * that produced D-BAST-IRELE-INACTIVE-SELF-WEDGE: it can overwrite a live
 * foreign claim and then NULL the slot, stranding the real owner).
 */
void
mxfs_dlm_claim_demoter(struct xfs_inode *ip)
{
	MXFS_SET_DEMOTER(ip);
}

void
mxfs_dlm_release_demoter(struct xfs_inode *ip)
{
	MXFS_CLEAR_DEMOTER(ip);
}

/*
 *  — THE SOURCE SIDE of the inherited-claim defect.
 *
 * Called from xfs_inode_free_callback immediately before
 * kmem_cache_free(xfs_inode_cache, ip).  A claim can still be set here through
 * no fault of its holder: the release paths deliberately keep i_dlm_demoter ==
 * current across their TRAILING xfs_irele/iput ( — the
 * cascade into evict -> xfs_inactive -> xfs_ilock must stay exempt or the
 * drain self-deadlocks), and if that irele is the LAST reference the object is
 * destroyed inside it.  The holder's MXFS_CLEAR_DEMOTER then runs against
 * memory that has already gone back to the slab.
 *
 * Whatever the path, an object must never re-enter the slab claimed: the next
 * xfs_inode_alloc does not zero it, so the claim becomes a permanent, unownable
 * strand on an unrelated inode.  Clear it here, where the object is provably
 * dead and unreachable, and count how often it was needed.
 */
void
mxfs_dlm_inode_final_release(struct xfs_inode *ip)
{
	if (unlikely(ip->i_dlm_demoter || ip->i_dlm_demoter2)) {
		static atomic_t p217n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_dem_free_dirty);
		if (atomic_inc_return(&p217n) <= 200)
			mxfs_probe("mxfs: P217-FREE-DIRTY-CLAIM ino=%llu s1=%d s2=%d s1_pid=%d s1_comm=%s s1_line=%u:%u s1_depth=%d s1_age_ms=%llu s2_pid=%d s2_line=%u:%u — inode returning to the slab still claimed; cleared so the next allocation cannot inherit it\n",
				(unsigned long long)ip->i_ino,
				!!ip->i_dlm_demoter, !!ip->i_dlm_demoter2,
				ip->i_dlm_demoter_pid, ip->i_dlm_demoter_comm,
				MXFS_SITE_ARGS(ip->i_dlm_demoter_line), ip->i_dlm_demoter_depth,
				(unsigned long long)(ip->i_dlm_demoter_set_ns ?
					(ktime_get_ns() - ip->i_dlm_demoter_set_ns)
						/ NSEC_PER_MSEC : 0ULL),
				ip->i_dlm_demoter2_pid,
				MXFS_SITE_ARGS(ip->i_dlm_demoter2_line));
	}
	ip->i_dlm_demoter = NULL;
	ip->i_dlm_demoter2 = NULL;
	ip->i_dlm_demoter_depth = 0;
	ip->i_dlm_demoter2_depth = 0;
	ip->i_dlm_demoter_punt = 0;
	ip->i_dlm_punt_n[0] = 0;
	ip->i_dlm_punt_n[1] = 0;
	ip->i_dlm_demoter_punt_ns = 0;
	ip->i_dlm_strand_named = false;
}

/*
 *  — RELEASE THE ONE CLAIM THAT OUTLIVES ITS CRITICAL
 * SECTION.  See the design block at i_dlm_demoter_punt in xfs_inode.h for the
 * proof; in short, mxfs_trans_drain_inode_unlocks' P152 punt is the only exit
 * in the tree that returns with a demoter claim still held, and nothing
 * downstream can clear it (the dwork that inherits the release lands in the
 * OTHER slot and clears only that one).  The claim then makes
 * mxfs_foreign_demoter() true for the life of the in-core inode.
 *
 * The retention is not a bug by itself — it is what keeps the committing task
 * exempt across its post-commit xfs_iunlock — so this bounds it rather than
 * removing it.  Two conditions must BOTH hold before a retained claim is
 * released, and together they mean "the window this claim exists to cover is
 * provably over":
 *
 *   1. the retaining task no longer owns ILOCK-EXCL on this inode.  That is
 *      the exact condition that CREATED the punt (mxfs_trans_drain_inode_
 *      unlocks reads the same rwsem owner field), so its negation is the
 *      window's own end.  Note xfs_iunlock does up_write(&ip->i_lock) BEFORE
 *      calling mxfs_dlm_ilock_end, so the owner clears slightly ahead of the
 *      DLM-side unlock — which is why condition 2 exists.
 *   2. the claim is older than mxfs.demoter_punt_grace_ms (default 200).  A
 *      real post-commit iunlock window is microseconds to a few ms; the
 *      leaked claim in evidence was 179907 ms.  Three orders of magnitude of
 *      headroom, so this can only fire on a claim that is genuinely stranded.
 *
 * NEVER dereferences i_dlm_demoter/2: they are bare task_struct pointers held
 * without a reference and dangle once the holder exits (which is precisely
 * what the evidence shows).  Only the pointer VALUE is compared, and only the
 * stamped scalars are printed.
 */
int mxfs_demoter_punt_reclaim = 1;
module_param_named(demoter_punt_reclaim, mxfs_demoter_punt_reclaim, int, 0644);
MODULE_PARM_DESC(demoter_punt_reclaim,
	"release a demoter claim retained past trans-free once its window has closed (1=on, 0=negative control)");

/*
 * THE GRACE IS A SAFETY MARGIN AGAINST A LIVE TASK, NOT A TUNING KNOB.
 *
 * xfs_iunlock does up_write(&ip->i_lock) BEFORE calling mxfs_dlm_ilock_end, so
 * between those two the retaining task is still executing, still owns its
 * claim, and NO LONGER matches the rwsem owner — it is indistinguishable by
 * inspection from a task that abandoned the claim.  If the sweep fires inside
 * that window it foreign-clears a live owner's claim, which is precisely the
 * event that produced D-BAST-IRELE-INACTIVE-SELF-WEDGE.
 *
 * That window is normally sub-microsecond, but nothing bounds it: the task can
 * be preempted, the vCPU descheduled by the host, or the guest paused.  Age
 * therefore cannot PROVE abandonment; it can only make a live-task false
 * positive implausible.  5 s is ~5 orders of magnitude above the window and far
 * above any real drain (22-23 ms), and it is not load-bearing for the fix: the
 * owner-driven clear in mxfs_dlm_ilock_end retires every retention in practice
 * (measured: 6 punts, 0 sweeps needed, 0 strands).  This exists only for a task
 * that never returns to its unlock at all.
 */
int mxfs_demoter_punt_grace_ms = 5000;
module_param_named(demoter_punt_grace_ms, mxfs_demoter_punt_grace_ms, int, 0644);
MODULE_PARM_DESC(demoter_punt_grace_ms,
	"minimum age of a trans-free-retained demoter claim before the SWEEP may reclaim it (ms); safety margin against clearing a live owner mid-unlock, not a tuning knob");
atomic64_t mxfs_dem_punt_reclaim_n;	/* retained claims released again */
atomic64_t mxfs_dem_punt_selfclear;	/* retained claim cleared normally */


void
mxfs_demoter_punt_reclaim_check(struct xfs_inode *ip, int site)
{
	struct task_struct	*owner;
	u64			age_ms;
	u8			punt;
	int			slot;

	punt = READ_ONCE(ip->i_dlm_demoter_punt);
	if (likely(!punt))
		return;

	/*
	 * Retire the bookkeeping for a slot that some other path already
	 * cleared — unconditionally, so the negative-control arm does not
	 * accumulate a permanently set mask and mis-report exposure.
	 */
	if ((punt & 1) && !READ_ONCE(ip->i_dlm_demoter)) {
		punt &= ~1;
		atomic64_inc(&mxfs_dem_punt_selfclear);
	}
	if ((punt & 2) && !READ_ONCE(ip->i_dlm_demoter2)) {
		punt &= ~2;
		atomic64_inc(&mxfs_dem_punt_selfclear);
	}
	WRITE_ONCE(ip->i_dlm_demoter_punt, punt);
	if (!punt)
		return;

	if (!mxfs_demoter_punt_reclaim)
		return;			/* A/B negative control: leak as before */

	age_ms = ip->i_dlm_demoter_punt_ns ?
		 (ktime_get_ns() - ip->i_dlm_demoter_punt_ns) / NSEC_PER_MSEC : 0;
	if (mxfs_demoter_punt_grace_ms > 0 &&
	    age_ms < (u64)mxfs_demoter_punt_grace_ms)
		return;			/* still inside a plausible unlock window */

	owner = (struct task_struct *)
		(atomic_long_read(&ip->i_lock.owner) & ~0x7UL);

	for (slot = 0; slot < 2; slot++) {
		struct task_struct	**cell;
		struct task_struct	*d;

		if (!(punt & (1u << slot)))
			continue;
		cell = slot ? &ip->i_dlm_demoter2 : &ip->i_dlm_demoter;
		d = READ_ONCE(*cell);
		if (!d || d == owner || d == current)
			continue;	/* window still open, or it is us */

		if (cmpxchg(cell, d, NULL) != d)
			continue;	/* the owner beat us to it — nothing to do */

		if (slot)
			ip->i_dlm_demoter2_depth = 0;
		else
			ip->i_dlm_demoter_depth = 0;
		punt &= ~(1u << slot);
		ip->i_dlm_punt_n[slot] = 0;
		WRITE_ONCE(ip->i_dlm_demoter_punt, punt);
		atomic64_inc(&mxfs_dem_punt_reclaim_n);
		mxfs_demev_rec(ip, 6, MXFS_SITE);
		mxfs_probe_ratelimited(
			"mxfs: P213-PUNT-RECLAIM ino=%llu slot=%d claim_pid=%d claim_comm=%s claim_line=%u:%u age_ms=%llu site=%d — trans-free-retained demoter claim released\n",
			(unsigned long long)ip->i_ino, slot + 1,
			ip->i_dlm_demoter_pid, ip->i_dlm_demoter_comm,
			MXFS_SITE_ARGS(ip->i_dlm_demoter_line), age_ms, site);
	}
}
static struct mxfs_dlmtr_ent mxfs_dlmtr[MXFS_DLMTR_N];
static atomic_t mxfs_dlmtr_idx = ATOMIC_INIT(0);
atomic64_t mxfs_auth_backstop_n = ATOMIC64_INIT(0);
/*
 * a lowering that arrives with the tenure already in RELEASING is
 * the release protocol finishing (begin_release ran first) — counted here,
 * silently.  mxfs_auth_backstop_n is then reserved for the violation: a
 * PROVING tenure (DURABLE_EX/UNPUBLISHED_EX) dropped by a lowering that never
 * announced release-begin, i.e. a path where a peer could have been granted
 * while our certificate still claimed the tenure (P246-AUTH-LATE-REVOKE).
 */
atomic64_t mxfs_auth_relclean_n = ATOMIC64_INIT(0);

/*
 * THE mode-transition chokepoint.
 *
 * PROVEN by exhaustive grep: all 19 real `ip->i_dlm_mode = ...`
 * stores in the tree live in xfs_mxfs_dlm.c and every one of them is wrapped
 * in the `{ u8 dtr_om = ...; store; mxfs_dlmtr_rec(...); }` idiom, so this
 * function sees every mode transition with the old mode in hand.  That makes
 * it the one place a mode LOWERING can be caught without relying on any
 * enumeration of release sites staying complete as the code changes.
 *
 * It is therefore no longer diagnostic-only: the authority backstop runs
 * BEFORE the watch-ino early return.  The primary revoke happens at
 * release-begin (earlier, and before anything outwardly visible — wired
 * at every deliberate release site); the lowering seen here then
 * finds the tenure in RELEASING and finishes it silently (relclean).  A
 * lowering that still finds a PROVING tenure is the violation this backstop
 * exists for: the mode dropped without the release protocol having been
 * announced, so the revoke is LATE — a peer may already have been granted
 * while our certificate still claimed the tenure.  As of (design-consult
 * ruling A) there is NO known population left: the phantom-recovery arms
 * (P108-REACQUIRE, P-TCPEX-REACQ, the phantom-undo) invalidate at detection
 * via mxfs_inode_authority_phantom_loss_locked, so any P246-AUTH-LATE-REVOKE
 * hit is an uninstrumented release path — a wiring bug to be closed, not a
 * signal to be tolerated.
 */
void
mxfs_dlmtr_rec(struct xfs_inode *ip, u8 om, u8 os, u32 line)
{
	struct mxfs_dlmtr_ent *e;

	if (unlikely(om > ip->i_dlm_mode) &&
	    ip->i_mxfs_auth_state != MXFS_AUTH_NONE) {
		if (ip->i_mxfs_auth_state == MXFS_AUTH_RELEASING) {
			atomic64_inc(&mxfs_auth_relclean_n);
		} else {
			atomic64_inc(&mxfs_auth_backstop_n);
			mxfs_probe_ratelimited("mxfs: P246-AUTH-LATE-REVOKE ino=%llu auth_state=%u om=%u nm=%u os=%u L%u:%u — proving certificate dropped by a mode lowering that never announced release-begin\n",
				(unsigned long long)ip->i_ino,
				ip->i_mxfs_auth_state, om, ip->i_dlm_mode,
				os, MXFS_SITE_ARGS(line));
		}
		mxfs_inode_authority_revoke_locked(ip, line);
	}

	/* #18 forensics: stamp the last granted->NL lowering on EVERY
	 * inode (the ring below is watch_ino-gated and useless for an
	 * unpredictable ino).  P95-OPEN-PROTECT-FAIL prints these to name the
	 * setter that left mode==NL after the open's ilock ride. */
	if (ip->i_dlm_mode == MXFS_LOCK_NL && om != MXFS_LOCK_NL) {
		ip->i_dlm_nl_line = line;
		ip->i_dlm_nl_pid = current->pid;
		ip->i_dlm_nl_ns = ktime_get_real_ns();
		ip->i_dlm_nl_om = om;
		strscpy(ip->i_dlm_nl_comm, current->comm,
			sizeof(ip->i_dlm_nl_comm));
		/* #18 near-miss survey: holders sit inside
		 * ilock_begin/ilock_end critical sections, so a granted->NL
		 * lowering while exh/prh != 0 is the P95-OPEN-PROTECT-FAIL
		 * hazard class firing REGARDLESS of whether an open loses the
		 * microsecond race — names the setter population without
		 * waiting for the EIO to reproduce. */
		if (ip->i_dlm_ex_holders || ip->i_dlm_pr_holders)
			mxfs_probe_ratelimited("mxfs: P95-NL-UNDER-HOLD ino=%llu L%u:%u om=%u os=%u ns=%u exh=%u prh=%u acq=%u open_n=%d imode=%o pid=%d comm=%s\n",
				(unsigned long long)ip->i_ino, MXFS_SITE_ARGS(line), om, os,
				ip->i_dlm_state, ip->i_dlm_ex_holders,
				ip->i_dlm_pr_holders, ip->i_dlm_acq_inflight,
				atomic_read(&ip->i_mxfs_open_n),
				VFS_I(ip)->i_mode, current->pid,
				current->comm);
	}

	/* #23 forensics (design-consult ruling): if the task recording this
	 * event is an open_protect admission mid-ride, stamp the call-site
	 * line.  Every ilock_begin admit arm ends in MXFS_DLMTR_H at its
	 * holder++, so the LAST line stamped before the admission re-read
	 * names the admit arm that registered the opener's holder (the arm
	 * that let it ride at mode==NL).  All callers hold i_dlm_lock. */
	if (unlikely(ip->i_mxfs_openprot_pid == current->pid &&
		     ip->i_mxfs_openprot_pid != 0))
		ip->i_mxfs_openprot_arm = line;

	if (likely(!mxfs_watch_ino) || ip->i_ino != mxfs_watch_ino)
		return;
	e = &mxfs_dlmtr[(u32)atomic_inc_return(&mxfs_dlmtr_idx) %
			MXFS_DLMTR_N];
	e->ns = ktime_get_real_ns();
	e->ino = ip->i_ino;
	e->line = line;
	e->pid = current->pid;
	e->om = om;
	e->nm = ip->i_dlm_mode;
	e->os = os;
	e->nst = ip->i_dlm_state;
	e->exh = ip->i_dlm_ex_holders;
	e->prh = ip->i_dlm_pr_holders;
	strscpy(e->comm, current->comm, sizeof(e->comm));
}

void
mxfs_dlmtr_dump(void)
{
	u32 idx = (u32)atomic_read(&mxfs_dlmtr_idx);
	int i;

	mxfs_probe("mxfs: P12-DLMTR-DUMP watch=%llu idx=%u\n",
		mxfs_watch_ino, idx);
	for (i = 0; i < MXFS_DLMTR_N; i++) {
		struct mxfs_dlmtr_ent *e =
			&mxfs_dlmtr[(idx + 1 + i) % MXFS_DLMTR_N];
		if (!e->ns)
			continue;
		mxfs_probe("mxfs: P12-DLMTR ino=%llu m%u>%u s%u>%u ex=%u pr=%u L%u:%u pid=%u %s ns=%llu\n",
			(unsigned long long)e->ino, e->om, e->nm, e->os,
			e->nst, e->exh, e->prh, MXFS_SITE_ARGS(e->line), e->pid, e->comm,
			(unsigned long long)e->ns);
	}
}

/*
 *  a864 (instrumented): the dir_reuse@32/caw wedge is an ORPHANED on-disk
 * EX holder bit — a peer holds a dir inode's EX bit on the CAW slot while its
 * cached i_dlm_mode==NL, so it swallows every peer BAST ("I hold nothing") and
 * 31 waiters block 360s -> rc=-110 cascade.  Prior sessions PROVED the bit is
 * set + frozen from the ACQUIRER's view (P-ACQ-STUCK) but never captured, from
 * the HOLDER's view at the swallow, three decisive facts:
 *   held_raw  = the HINTED find_slot read (what inode_held/the release gate see)
 *   scan_mine = a duplicate-immune FULL-CHAIN scan (does our bit exist ANYWHERE)
 *   nslots    = live-slot count for the ino (>1 == claim-race dup => the hinted
 *               read and the scan can disagree)
 * held_raw==0 && scan_mine==1 && nslots>1  => the dup-slot/hint blind spot is
 * root (the release gate reads the wrong slot).  held_raw>=EX (or scan_mine==1,
 * nslots==1) => held() is correct and the swallow is a STATE-MACHINE gating bug
 * (the release path never fires for this mode/state).  Either way the fix is
 * named.  The one-shot transition-ring dump adds the exact formation sequence.
 * Read-only; hard-capped (synchronous slot I/O).  site: 0=P72 DEMOTING-swallow,
 * 1=NONE/NL "no orphan" swallow.  Call with i_dlm_lock NOT held.
 */
void
mxfs_caw_orphan_forensic(struct xfs_inode *ip, int site)
{
	struct xfs_mount *mp = ip->i_mount;
	static atomic_t forensic_n = ATOMIC_INIT(0);
	static atomic_t ring_dumped = ATOMIC_INIT(0);
	static unsigned long last_j;
	uint8_t held_raw;
	int mine, nslots = 0;
	uint64_t hex_or = 0;
	unsigned n;

	if (!mp->m_mxfs_dlm || !mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return;
	n = (unsigned)atomic_inc_return(&forensic_n);
	if (n > 8000)
		return;			/* hard cap on synchronous scan I/O */
	/* light throttle so samples spread across the whole wedge (per node) */
	if (n > 1 && time_before(jiffies, last_j + msecs_to_jiffies(150)))
		return;
	last_j = jiffies;

	/* Cheap hinted read first.  Do the expensive full-chain scan (and log)
	 * for the ACTUAL holder (held_raw>=EX — the FROZEN holder that wedges the
	 * cluster and MUST be captured throughout the 360s wedge, not just at r2)
	 * OR for a bounded transient sample of non-holders (first 400). */
	held_raw = mxfs_v5_dlm_inode_held_rawmode(mp->m_mxfs_dlm, ip->i_ino);
	if (held_raw < MXFS_LOCK_EX && n > 400)
		return;
	mine = mxfs_v5_dlm_inode_self_held_scan(mp->m_mxfs_dlm, ip->i_ino,
						&nslots, &hex_or);
	mxfs_probe("mxfs: P-ORPH-FORENSIC ino=%llu site=%d incore_mode=%u state=%u ex=%u pr=%u pin=%u held_raw=%u scan_mine=%d nslots=%d hex_or=%llx\n",
		(unsigned long long)ip->i_ino, site, ip->i_dlm_mode,
		ip->i_dlm_state, ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
		ip->i_dlm_pin_count, held_raw, mine, nslots,
		(unsigned long long)hex_or);

	/* PROVEN orphan (our bit on disk while incore says NL): dump the full
	 * per-inode transition ring ONCE so the formation line sequence is in
	 * the snapshot. */
	if (mine == 1 && ip->i_dlm_mode == MXFS_LOCK_NL &&
	    atomic_cmpxchg(&ring_dumped, 0, 1) == 0) {
		pr_warn("mxfs: P-ORPH-FORENSIC ino=%llu PROVEN-DISK-ORPHAN (scan_mine=1, incore NL) — dumping transition ring (watch=%llu)\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)mxfs_watch_ino);
		mxfs_dlmtr_dump();
	}
}
int mxfs_dir_perf_probe;	/* when 1, log per dir-class FUA read (P15-DIRFUA) to diagnose the 8-node verify FUA-read storm. */
module_param_named(dir_perf_probe, mxfs_dir_perf_probe, int, 0644);

atomic64_t mxfs_dlm_stat_cache_hit;
atomic64_t mxfs_dlm_stat_cache_miss;
atomic64_t mxfs_dlm_stat_bast_immediate;
atomic64_t mxfs_dlm_stat_bast_deferred;
atomic64_t mxfs_dlm_stat_bast_no_inode;
atomic64_t mxfs_dlm_stat_ag_acquire;
atomic64_t mxfs_dlm_stat_ag_nested;
atomic64_t mxfs_dlm_stat_ag_release;
static uint64_t mxfs_dlm_stat_last_report;

/*
 * FUA-read instrumentation: count SCSI FUA reads by buffer class to
 * confirm the rsync_paired ~9.4s residual decomposition.  Incremented from
 * the FUA gate in pal/linux/xfs_buf.c via mxfs_fua_count().
 */
atomic64_t mxfs_fua_inode_reads;
atomic64_t mxfs_fua_dir_reads;
atomic64_t mxfs_fua_agmeta_reads;
atomic64_t mxfs_fua_inode_owned_skip;	/* inode FUA skipped because AG owned */
atomic64_t mxfs_fua_scsi_actual;	/* ACTUAL slow SCSI FUA reads issued */
atomic64_t mxfs_fua_p91_skip;		/* P91 in-core skips (cheap, no SCSI) */
atomic64_t mxfs_iget_cluster_staled;	/* cache-miss site DID stale the cluster */
atomic64_t mxfs_ccprev_reads;	/* /409: CREATE prev-changecount cluster reads (miss+recycle) */
atomic64_t mxfs_ccprev_nostale;	/* ... of which the cached cluster was locked (tp ICREATE/xfsaild) and read as cached */
atomic64_t mxfs_ccprev_tenure_hit;	/* ... of which the cached cluster was fresh under the current AG tenure (re-read skipped) */

/*
 * 0.84.16, test only (D-0947): the next N candidate validations in
 * xfs_dialloc read as magic-less whatever the platter holds, each consuming
 * one count, so the no-magic arm (kick the owed writes, cool the candidate
 * down, re-pick) can be driven on a healthy filesystem.  Read back as the
 * count still to consume; 0 in production.
 */
int mxfs_dbg_validate_nomagic_n = 0;
module_param_named(dbg_validate_nomagic_n, mxfs_dbg_validate_nomagic_n, int, 0644);
MODULE_PARM_DESC(dbg_validate_nomagic_n,
		 "TEST ONLY: make the next N inode-allocation candidates validate as magic-less (0=off)");
/* The persistent form: ONE inode number whose home always validates as
 * magic-less, for as long as the knob names it — the shape of the original
 * failure (one candidate, picked by every create in turn). */
unsigned long long mxfs_dbg_validate_nomagic_ino = 0;
module_param_named(dbg_validate_nomagic_ino, mxfs_dbg_validate_nomagic_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_validate_nomagic_ino,
		 "TEST ONLY: this inode number always validates as magic-less (0=off)");

bool
mxfs_dbg_validate_nomagic_take(unsigned long long ino)
{
	int n;

	if (ino && READ_ONCE(mxfs_dbg_validate_nomagic_ino) == ino)
		return true;
	n = READ_ONCE(mxfs_dbg_validate_nomagic_n);
	if (n <= 0)
		return false;
	WRITE_ONCE(mxfs_dbg_validate_nomagic_n, n - 1);
	return true;
}
EXPORT_SYMBOL(mxfs_dbg_validate_nomagic_take);

/*
 * A resettable exact counter as a module parameter: read gives the count,
 * write sets it (a harness writes 0 at the start of a window and reads at the
 * end, instead of counting print-budgeted dmesg lines).
 */
static int
mxfs_dbg_atomic_param_set(const char *val, const struct kernel_param *kp)
{
	int	v;
	int	rc = kstrtoint(val, 0, &v);

	if (rc)
		return rc;
	atomic_set((atomic_t *)kp->arg, v);
	return 0;
}

static int
mxfs_dbg_atomic_param_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%d\n", atomic_read((atomic_t *)kp->arg));
}

static const struct kernel_param_ops mxfs_dbg_atomic_param_ops = {
	.set = mxfs_dbg_atomic_param_set,
	.get = mxfs_dbg_atomic_param_get,
};

/*
 * D-0946: the allocator's own-obligation arm, counted exactly.  `refused` is
 * the fix (dialloc_pubpend_refuse=1), `allowed` the control arm; the
 * P946-VALIDATE-PUBPEND / -ALLOW lines print the first 32 and then one in
 * 500, so a harness that needs to know the arm was exercised reads these.
 */
atomic_t mxfs_dialloc_pubpend_refused = ATOMIC_INIT(0);
module_param_cb(dialloc_pubpend_refused, &mxfs_dbg_atomic_param_ops,
		&mxfs_dialloc_pubpend_refused, 0644);
MODULE_PARM_DESC(dialloc_pubpend_refused,
		 "count of allocation candidates refused because this node's own free of the number is not yet on the platter (write resets)");
atomic_t mxfs_dialloc_pubpend_allowed = ATOMIC_INIT(0);
module_param_cb(dialloc_pubpend_allowed, &mxfs_dbg_atomic_param_ops,
		&mxfs_dialloc_pubpend_allowed, 0644);
MODULE_PARM_DESC(dialloc_pubpend_allowed,
		 "count of such candidates ALLOWED under dialloc_pubpend_refuse=0, the A/B control arm (write resets)");
module_param_cb(p71_underflows, &mxfs_dbg_atomic_param_ops,
		&mxfs_p71_underflows, 0644);
MODULE_PARM_DESC(p71_underflows,
		 "count of inode DLM ends that found no holder to release (P71-UNDERFLOW), multi-node only (write resets)");
module_param_cb(noino_bast_reclaimable, &mxfs_dbg_atomic_param_ops,
		&mxfs_noino_bast_reclaimable, 0644);
MODULE_PARM_DESC(noino_bast_reclaimable,
		 "count of peer BASTs served by the no-inode release for an in-core RECLAIMABLE inode (write resets)");
module_param_cb(recycle_grant_cached, &mxfs_dbg_atomic_param_ops,
		&mxfs_recycle_grant_cached, 0644);
MODULE_PARM_DESC(recycle_grant_cached,
		 "count of reclaimable-inode recycles that found a cached DLM grant in core (write resets)");
module_param_cb(recycle_grant_phantom, &mxfs_dbg_atomic_param_ops,
		&mxfs_recycle_grant_phantom, 0644);
MODULE_PARM_DESC(recycle_grant_phantom,
		 "count of those recycles where the DLM mirror no longer held the cached mode (P-RECYCLE-PHANTOM) (write resets)");
/*
 * D-0532 item (c), the in-core half: xfs_iget_recycle clears the previous
 * incarnation's i_dlm_bast_pending unconditionally.  Count the recycles
 * where the flag was actually SET — a peer's BAST delivered to the corpse
 * before it went reclaimable, whose drain had not run yet — because that is
 * the case where the clear leaves the peer waiting on a request nobody on
 * this node remembers.
 */
atomic_t mxfs_recycle_bast_dropped = ATOMIC_INIT(0);
module_param_cb(recycle_bast_dropped, &mxfs_dbg_atomic_param_ops,
		&mxfs_recycle_bast_dropped, 0644);
MODULE_PARM_DESC(recycle_bast_dropped,
		 "count of xfs_iget_recycle clears of a SET i_dlm_bast_pending on the recycled corpse (P-RECYCLE-BAST-DROP) (write resets)");
atomic_t mxfs_recycle_bast_kept = ATOMIC_INIT(0);
module_param_cb(recycle_bast_kept, &mxfs_dbg_atomic_param_ops,
		&mxfs_recycle_bast_kept, 0644);
MODULE_PARM_DESC(recycle_bast_kept,
		 "count of xfs_iget_recycle keeps of a SET i_dlm_bast_pending on a corpse whose cached grant is live (P-RECYCLE-BAST-KEEP) (write resets)");
int mxfs_recycle_bast_keep = 1;
module_param_named(recycle_bast_keep, mxfs_recycle_bast_keep, int, 0644);
MODULE_PARM_DESC(recycle_bast_keep,
		 "xfs_iget_recycle keeps a pending peer BAST on a corpse whose cached grant is still live instead of clearing it (D-0532 item c); 1=on (default), 0=the unconditional clear for A/B");

atomic_t mxfs_recycle_bast_stale = ATOMIC_INIT(0);
module_param_cb(recycle_bast_stale, &mxfs_dbg_atomic_param_ops,
		&mxfs_recycle_bast_stale, 0644);
MODULE_PARM_DESC(recycle_bast_stale,
		 "count of xfs_iget_recycle clears of a BAST signal on a corpse whose grant was already NL (the stale signal the clear exists for; P-RECYCLE-BAST-STALE) (write resets)");

void
mxfs_dlm_recycle_bast_note(struct xfs_inode *ip, uint8_t prev_state,
			   uint8_t prev_mode, int outcome)
{
	static atomic_t p_rcbd_n = ATOMIC_INIT(0);
	static const char *const what[] = { "STALE", "DROP", "KEEP" };

	atomic_inc(outcome == 2 ? &mxfs_recycle_bast_kept :
		   outcome == 1 ? &mxfs_recycle_bast_dropped :
		   &mxfs_recycle_bast_stale);
	if (atomic_inc_return(&p_rcbd_n) <= 64)
		mxfs_probe("mxfs: P-RECYCLE-BAST-%s ino=%llu prev_state=%u prev_mode=%u now_state=%u mode=%u pending=%d nlink=%u imode=0%o comm=%s — recycle met a delivered BAST: %s\n",
			what[outcome],
			(unsigned long long)ip->i_ino, prev_state, prev_mode,
			ip->i_dlm_state, ip->i_dlm_mode,
			ip->i_dlm_bast_pending ? 1 : 0, VFS_I(ip)->i_nlink,
			VFS_I(ip)->i_mode, current->comm,
			outcome == 2 ? "the grant is live, the obligation stays with it" :
			outcome == 1 ? "the grant is live but recycle_bast_keep=0 cleared it" :
			"the grant is NL, the signal was stale");
}

/* Mappings refused under IOMAP_NOWAIT on a clustered mount (D-0532;
 * xfs_ilock_for_iomap): the coverage count proving the path was reached. */
atomic_t mxfs_iomap_nowait_refused = ATOMIC_INIT(0);
module_param_cb(iomap_nowait_refused, &mxfs_dbg_atomic_param_ops,
		&mxfs_iomap_nowait_refused, 0644);
MODULE_PARM_DESC(iomap_nowait_refused,
		 "count of IOMAP_NOWAIT mappings refused with -EAGAIN because the mount is clustered (write resets)");

/* D-0972: shared iomap mappings whose extent load asked the cluster for PR
 * (xfs_ilock_for_iomap through xfs_ilock_data_map_shared): the coverage
 * count proving a verification lap reached the load. */
atomic_t mxfs_iomap_iread_pr = ATOMIC_INIT(0);
module_param_cb(iomap_iread_pr, &mxfs_dbg_atomic_param_ops,
		&mxfs_iomap_iread_pr, 0644);
MODULE_PARM_DESC(iomap_iread_pr,
		 "count of shared iomap mappings whose extent-map load asked the cluster for PR, not EX (write resets)");

module_param_cb(bmbt_lookup_bad, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_lookup_bad, 0644);
MODULE_PARM_DESC(bmbt_lookup_bad,
		 "count of inode-rooted btree blocks a lookup refused (owner, level or empty node) on a clustered mount (write resets)");
module_param_cb(bmbt_rel_evicted, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_rel_evicted, 0644);
MODULE_PARM_DESC(bmbt_rel_evicted,
		 "count of cached bmbt blocks dropped at the end of a tenure (write resets)");
module_param_cb(bmbt_rel_busy, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_rel_busy, 0644);
MODULE_PARM_DESC(bmbt_rel_busy,
		 "count of cached bmbt blocks whose lock the tenure-end eviction could not take within its budget; that release is wedged (write resets)");
module_param_cb(bmbt_rel_localwork, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_rel_localwork, 0644);
MODULE_PARM_DESC(bmbt_rel_localwork,
		 "count of owned bmbt blocks found still carrying local work at the end of a tenure; that release is wedged (write resets)");
module_param_cb(bmbt_scan_stale_skip, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_scan_stale_skip, 0644);
MODULE_PARM_DESC(bmbt_scan_stale_skip,
		 "count of stale (freed) bmbt buffers a bmbt durability scan declined to write (write resets)");
module_param_cb(reg_bmbt_rel_flushed, &mxfs_dbg_atomic_param_ops,
		&mxfs_reg_bmbt_rel_flushed, 0644);
MODULE_PARM_DESC(reg_bmbt_rel_flushed,
		 "count of regular-file EX releases whose btree extent tree the release loop had to flush before the unlock (write resets)");
module_param_cb(reg_bmbt_rel_wedge, &mxfs_dbg_atomic_param_ops,
		&mxfs_reg_bmbt_rel_wedge, 0644);
MODULE_PARM_DESC(reg_bmbt_rel_wedge,
		 "count of regular-file releases that could not make the extent tree durable and shut down instead (write resets)");
module_param_cb(iflush_bmbt_capped, &mxfs_dbg_atomic_param_ops,
		&mxfs_iflush_bmbt_capped, 0644);
MODULE_PARM_DESC(iflush_bmbt_capped,
		 "count of owned bmbt blocks an inode flush's destage walk left unwritten because its hold array was full (write resets)");
module_param_cb(iflush_bmbt_notdone_needs, &mxfs_dbg_atomic_param_ops,
		&mxfs_iflush_bmbt_notdone_needs, 0644);
MODULE_PARM_DESC(iflush_bmbt_notdone_needs,
		 "count of owned bmbt blocks an inode flush's destage walk skipped for !XBF_DONE although they carried local work (write resets)");
module_param_cb(bmbt_evict_capped, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_evict_capped, 0644);
MODULE_PARM_DESC(bmbt_evict_capped,
		 "count of owned bmbt blocks a reload's eviction walk saw but left cached because its hold array was full (write resets)");
atomic_t mxfs_bmbt_write_unread = ATOMIC_INIT(0);
module_param_cb(bmbt_write_unread, &mxfs_dbg_atomic_param_ops,
		&mxfs_bmbt_write_unread, 0644);
MODULE_PARM_DESC(bmbt_write_unread,
		 "count of bmbt block writes whose in-core owner had unread btree extents (detector, write resets)");
module_param_cb(iflush_unread_clean_skip, &mxfs_dbg_atomic_param_ops,
		&mxfs_iflush_unread_clean_skip, 0644);
MODULE_PARM_DESC(iflush_unread_clean_skip,
		 "count of clean cached bmbt blocks an inode flush did not destage because the extents were unread (write resets)");
module_param_cb(iflush_unread_local, &mxfs_dbg_atomic_param_ops,
		&mxfs_iflush_unread_local, 0644);
MODULE_PARM_DESC(iflush_unread_local,
		 "count of bmbt blocks with local modifications found by an inode flush while the extents were unread (write resets)");

/* D-0970: write checks retaken exclusive on a clustered mount so the
 * timestamp update's EX never asks under this task's own shared ride. */
atomic_t mxfs_write_checks_excl = ATOMIC_INIT(0);
module_param_cb(write_checks_excl, &mxfs_dbg_atomic_param_ops,
		&mxfs_write_checks_excl, 0644);
MODULE_PARM_DESC(write_checks_excl,
		 "count of write checks retaken with the IOLOCK exclusive before the timestamp update on a clustered mount (write resets)");
module_param_cb(demote_survivor, &mxfs_dbg_atomic_param_ops,
		&mxfs_demote_survivor, 0644);
MODULE_PARM_DESC(demote_survivor,
		 "count of IOLOCK demotes performed on a sole survivor (write resets)");
module_param_cb(end_unpaired_single, &mxfs_dbg_atomic_param_ops,
		&mxfs_end_unpaired_single, 0644);
MODULE_PARM_DESC(end_unpaired_single,
		 "count of inode DLM ends on a sole survivor that found no holder (write resets)");
atomic_t mxfs_dio_hipri_refused = ATOMIC_INIT(0);
module_param_cb(rel_dio_waited, &mxfs_dbg_atomic_param_ops,
		&mxfs_rel_dio_waited, 0644);
MODULE_PARM_DESC(rel_dio_waited,
		 "count of inode grant releases that waited for this node's outstanding direct I/O before draining (write resets)");
module_param_cb(rel_dio_wait_max_us, &mxfs_dbg_atomic_param_ops,
		&mxfs_rel_dio_wait_max_us, 0644);
MODULE_PARM_DESC(rel_dio_wait_max_us,
		 "longest such wait in microseconds (write resets)");
module_param_cb(rel_dio_defer, &mxfs_dbg_atomic_param_ops,
		&mxfs_rel_dio_defer, 0644);
MODULE_PARM_DESC(rel_dio_defer,
		 "count of releases deferred at the terminal guard because direct I/O was still in flight (write resets)");
module_param_cb(dioend_admit, &mxfs_dbg_atomic_param_ops,
		&mxfs_dioend_admit, 0644);
MODULE_PARM_DESC(dioend_admit,
		 "count of direct-write completions admitted as nested holders during a release drain (write resets)");
module_param_cb(dio_hipri_refused, &mxfs_dbg_atomic_param_ops,
		&mxfs_dio_hipri_refused, 0644);
MODULE_PARM_DESC(dio_hipri_refused,
		 "count of polled direct I/Os refused on a clustered mount (write resets)");
/* Where the direct-write completion ran, and whether it ran while the
 * inode's release pipeline was in progress (state BAST/DEMOTING).  iomap
 * runs a completion that needs filesystem work — unwritten conversion, a
 * size update — on the direct-I/O completion workqueue, a kernel thread,
 * which the cached-grant fast path admits under the still-EX mode as a
 * counted holder; a completion in task context is the registry admission's
 * case.  A completion counted in_drain that returned (the wait then ended)
 * is the measured progress path. */
atomic_t mxfs_dioend_kthread = ATOMIC_INIT(0);
atomic_t mxfs_dioend_task = ATOMIC_INIT(0);
atomic_t mxfs_dioend_in_drain = ATOMIC_INIT(0);
module_param_cb(dioend_kthread, &mxfs_dbg_atomic_param_ops,
		&mxfs_dioend_kthread, 0644);
MODULE_PARM_DESC(dioend_kthread,
		 "count of direct-write completions that ran on a kernel thread (write resets)");
module_param_cb(dioend_task, &mxfs_dbg_atomic_param_ops,
		&mxfs_dioend_task, 0644);
MODULE_PARM_DESC(dioend_task,
		 "count of direct-write completions that ran in task context (write resets)");
module_param_cb(dioend_in_drain, &mxfs_dbg_atomic_param_ops,
		&mxfs_dioend_in_drain, 0644);
MODULE_PARM_DESC(dioend_in_drain,
		 "count of direct-write completions that began while the inode's grant release was in progress (write resets)");
module_param_cb(recov_tagged, &mxfs_dbg_atomic_param_ops, &mxfs_recov_tagged, 0644);
MODULE_PARM_DESC(recov_tagged, "count of buffers a foreign slice replay populated in this node's cache: every read the recovery task completed (write resets)");
module_param_cb(recov_queued, &mxfs_dbg_atomic_param_ops, &mxfs_recov_queued, 0644);
MODULE_PARM_DESC(recov_queued, "count of replayed images a foreign slice replay queued for write; tagged minus this is what it read and skipped (write resets)");
module_param_cb(recov_cache_hit, &mxfs_dbg_atomic_param_ops, &mxfs_recov_cache_hit, 0644);
MODULE_PARM_DESC(recov_cache_hit, "count of reads outside recovery served a recovery-populated image from the cache with no read (write resets)");
module_param_cb(recov_hit_in_recovery, &mxfs_dbg_atomic_param_ops, &mxfs_recov_hit_in_recovery, 0644);
MODULE_PARM_DESC(recov_hit_in_recovery, "count of the recovery task's own cache hits on images it populated, expected before retirement (write resets)");
module_param_cb(recov_bmbt_cached, &mxfs_dbg_atomic_param_ops, &mxfs_recov_bmbt_cached, 0644);
MODULE_PARM_DESC(recov_bmbt_cached, "census at recovery end: cached extent-tree images the replay wrote (write resets)");
module_param_cb(recov_dir_cached, &mxfs_dbg_atomic_param_ops, &mxfs_recov_dir_cached, 0644);
MODULE_PARM_DESC(recov_dir_cached, "census at recovery end: cached directory/attr/symlink images the replay wrote, plus unverified ones (write resets)");
module_param_cb(recov_agbt_cached, &mxfs_dbg_atomic_param_ops, &mxfs_recov_agbt_cached, 0644);
MODULE_PARM_DESC(recov_agbt_cached, "census at recovery end: cached AG btree images the replay wrote (write resets)");
module_param_cb(recov_other_cached, &mxfs_dbg_atomic_param_ops, &mxfs_recov_other_cached, 0644);
MODULE_PARM_DESC(recov_other_cached, "census at recovery end: cached fixed-address images the replay wrote, not evicted (write resets)");
module_param_cb(recov_evicted, &mxfs_dbg_atomic_param_ops, &mxfs_recov_evicted, 0644);
MODULE_PARM_DESC(recov_evicted, "count of recovery-written images retired at the recovery's end (write resets)");
module_param_cb(recov_busy, &mxfs_dbg_atomic_param_ops, &mxfs_recov_busy, 0644);
MODULE_PARM_DESC(recov_busy, "count of recovery-written images that could not be locked for retirement; the recovery is retried (write resets)");
module_param_cb(recov_localwork, &mxfs_dbg_atomic_param_ops, &mxfs_recov_localwork, 0644);
MODULE_PARM_DESC(recov_localwork, "count of recovery-written images still carrying local work at the recovery's end; the recovery is retried (write resets)");
void
mxfs_atomic_max(atomic_t *v, int n)
{
	int	o = atomic_read(v);

	while (o < n && !atomic_try_cmpxchg(v, &o, n))
		;
}
module_param_cb(rel_dio_inflight, &mxfs_dbg_atomic_param_ops,
		&mxfs_rel_dio_inflight, 0644);
MODULE_PARM_DESC(rel_dio_inflight,
		 "count of inode grant releases committed with direct I/O still in flight (write resets)");

/*
 * D-0948: a SPARSE inode record carries every hole bit SET in its free mask
 * (the carve stamps ir_free = ALL_FREE and describes the missing half with
 * ir_holemask), so a pick that walks ir_free without masking the holes hands
 * out an inode number whose home block was never carved -- it belongs to
 * whatever owns that block.  Upstream's xfs_inobt_first_free_inode masks the
 * holes; the MXFS pick in mxfs_dialloc_pick_in_rec (xfs/libxfs/xfs_ialloc.c)
 * did not, and on s572 handed out offset 0 of a record whose holemask was
 * 0xff, the home being a live directory data block.  The pick masks the
 * holes now.  dbg_dialloc_pick_holes=1 restores the hole-blind walk as the
 * control arm of an A/B: it re-opens the defect and is for measurement only.
 * dialloc_holemask_n counts records whose free mask had hole bits masked out
 * (the fixed path was exercised on a sparse record with holes below a free
 * inode); dialloc_holepick_n counts picks that landed inside a hole, which
 * only the control arm can produce.
 */
int mxfs_dbg_dialloc_pick_holes = 0;
module_param_named(dbg_dialloc_pick_holes, mxfs_dbg_dialloc_pick_holes, int, 0644);
MODULE_PARM_DESC(dbg_dialloc_pick_holes,
		 "TEST ONLY: 1 = walk a sparse inode record's free mask without masking its holes (the pre-fix D-0948 pick; re-opens the defect)");
atomic_t mxfs_dialloc_holemask_n = ATOMIC_INIT(0);
module_param_cb(dialloc_holemask_n, &mxfs_dbg_atomic_param_ops,
		&mxfs_dialloc_holemask_n, 0644);
MODULE_PARM_DESC(dialloc_holemask_n,
		 "count of sparse inode records whose free-mask walk masked out hole bits (write resets)");
int mxfs_dbg_force_sparse_carve = 0;
module_param_named(dbg_force_sparse_carve, mxfs_dbg_force_sparse_carve, int, 0644);
MODULE_PARM_DESC(dbg_force_sparse_carve,
		 "TEST ONLY: 1 = every inode-chunk carve takes the sparse path; 2 = and carves the UPPER half of the next chunk-aligned region first (holes below the inodes, the D-0948 shape)");
atomic_t mxfs_dialloc_holepick_n = ATOMIC_INIT(0);
module_param_cb(dialloc_holepick_n, &mxfs_dbg_atomic_param_ops,
		&mxfs_dialloc_holepick_n, 0644);
MODULE_PARM_DESC(dialloc_holepick_n,
		 "count of inode picks that landed inside a sparse record's hole (control arm only; write resets)");

/*
 * 0.84.17, test only (D-0946): read the platter dinode at EVERY create-path
 * inode recycle in xfs_iget_recycle and fail the recycle when it is LIVE.
 * The defect's chain ended at that read, but only a shell that still carried
 * a mode or blocks reached it; a locally freed shell has neither, so ordinary
 * churn never asserts on the number the allocator handed out.  With this on,
 * every recycled number is asserted: under the fixed allocator a fire is a
 * crossed FREE-PUBLISH invariant (a FREE obligation is retired only by the
 * completion of the write carrying the free image), and under the control
 * arm it reproduces the original shutdown on demand.  The two counters exist
 * so a harness can prove the check RAN -- a silent instrument and a clean
 * system are the same observation otherwise.  0 in production.
 */
int mxfs_dbg_recycle_platter_assert = 0;
module_param_named(dbg_recycle_platter_assert, mxfs_dbg_recycle_platter_assert,
		   int, 0644);
MODULE_PARM_DESC(dbg_recycle_platter_assert,
		 "TEST ONLY: read the platter dinode on every create-path inode recycle and fail a LIVE one (0=off)");
static atomic_t mxfs_dbg_recycle_platter_checked = ATOMIC_INIT(0);
module_param_cb(dbg_recycle_platter_checked, &mxfs_dbg_atomic_param_ops,
		&mxfs_dbg_recycle_platter_checked, 0644);
MODULE_PARM_DESC(dbg_recycle_platter_checked,
		 "TEST ONLY: recycles asserted on the platter (write resets)");
static atomic_t mxfs_dbg_recycle_platter_live = ATOMIC_INIT(0);
module_param_cb(dbg_recycle_platter_live, &mxfs_dbg_atomic_param_ops,
		&mxfs_dbg_recycle_platter_live, 0644);
MODULE_PARM_DESC(dbg_recycle_platter_live,
		 "TEST ONLY: recycles whose platter dinode read LIVE (write resets)");

void
mxfs_dbg_recycle_platter_note(bool live)
{
	atomic_inc(&mxfs_dbg_recycle_platter_checked);
	if (live)
		atomic_inc(&mxfs_dbg_recycle_platter_live);
}
EXPORT_SYMBOL(mxfs_dbg_recycle_platter_note);

/*
 * sess-pve DEBUG one-shot fault injection for the AGI umount-wedge reclaim
 * test.  Arm with `mxfs.dbg_dialloc_shutdown=1`; the next multi-node create
 * forces a DIRTY xfs_trans_cancel right after xfs_dialloc has logged +
 * mxfs_ag_meta_track'd the AGI/inobt/finobt — reproducing the natural
 * stale-inode dialloc corruption deterministically so the shutdown-abort
 * reclaim path fires under test.  Consumed atomically (one-shot).  Default 0.
 * NEVER enable in production — it deliberately shuts the filesystem down.
 */
int mxfs_dbg_dialloc_shutdown;
module_param_named(dbg_dialloc_shutdown, mxfs_dbg_dialloc_shutdown, int, 0644);
MODULE_PARM_DESC(dbg_dialloc_shutdown,
	"DEBUG one-shot: force a dirty dialloc trans_cancel on the next multi-node create (AGI umount-wedge reclaim test). Never enable in production.");

/*
 * True if this node currently owns (EX) the AG that contains this buffer's
 * blocks.  The AG DLM grant is EX-only, so ownership means no peer can be
 * concurrently mutating AG metadata.  Hint-only: a concurrent BAST clears
 * pag_dlm_cached early (before draining), so a false "owned" here is bounded
 * by the BAST commit point.  Used by the FUA gate.
 */
bool
mxfs_buf_ag_owned_ex(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	xfs_agnumber_t		agno;
	struct xfs_perag	*pag;
	bool			owned = false;

	if (!mp || !mp->m_sb.sb_agblocks || bp->b_map_count < 1)
		return false;
	agno = xfs_daddr_to_agno(mp, bp->b_maps[0].bm_bn);
	if (agno >= mp->m_sb.sb_agcount)
		return false;
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return false;
	if (pag->pag_dlm_holders > 0 || pag->pag_dlm_cached)
		owned = true;
	xfs_perag_put(pag);
	return owned;
}

/* Classify a FUA read by buffer ops and bump the matching counter.  Emits a
 * cumulative pr_warn every 1024 inode-cluster FUA reads so the composition is
 * reliably visible in dmesg (the rate-limited report_stats line does not
 * surface). */
void
mxfs_fua_count(
	struct xfs_buf	*bp)
{
	const struct xfs_buf_ops *ops = bp->b_ops;
	static atomic64_t total;
	int64_t t;

	if (mxfs_buf_is_ag_metadata(bp)) {
		atomic64_inc(&mxfs_fua_agmeta_reads);
	} else if (ops == &xfs_inode_buf_ops || ops == &xfs_inode_buf_ra_ops) {
		atomic64_inc(&mxfs_fua_inode_reads);
		/* PERF probe (instrumented): log inode-cluster FUA daddrs
		 * so we can count REPEAT reads of the same cluster (caching/stale
		 * thrash, fixable) vs distinct clusters (inherent).  Gated on the
		 * existing dir_perf_probe param; capped. */
		if (mxfs_dir_perf_probe) {
			extern int mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *);
			static atomic_t p19 = ATOMIC_INIT(0);
			if (atomic_inc_return(&p19) <= 4000)
				mxfs_probe("mxfs: P19-INOFUA daddr=%lld len=%u slot=%d comm=%s\n",
					(long long)bp->b_maps[0].bm_bn,
					(unsigned int)bp->b_maps[0].bm_len,
					bp->b_mount && bp->b_mount->m_mxfs_dlm ?
					mxfs_v5_dlm_get_node_slot(bp->b_mount->m_mxfs_dlm) : -1,
					current->comm);
		}
	} else if (ops == &xfs_dir3_data_buf_ops ||
		   ops == &xfs_dir3_block_buf_ops ||
		   ops == &xfs_dir3_leaf1_buf_ops ||
		   ops == &xfs_dir3_leafn_buf_ops ||
		   ops == &xfs_dir3_free_buf_ops) {
		atomic64_inc(&mxfs_fua_dir_reads);
	}

	/* Emit cumulative composition every 256 FUA reads (any class) so the
	 * inode/dir/agmeta split is reliably visible in dmesg. */
	t = atomic64_inc_return(&total);
	if ((t & 255) == 0)
		mxfs_probe("mxfs: FUA-COUNT total=%lld ino=%lld dir=%lld agm=%lld scsi=%lld p91skip=%lld oskip=%lld igstale=%lld ccprev=%lld ccprev_nostale=%lld ccprev_tenure_hit=%lld realns=%llu\n",
			t,
			(long long)atomic64_read(&mxfs_fua_inode_reads),
			(long long)atomic64_read(&mxfs_fua_dir_reads),
			(long long)atomic64_read(&mxfs_fua_agmeta_reads),
			(long long)atomic64_read(&mxfs_fua_scsi_actual),
			(long long)atomic64_read(&mxfs_fua_p91_skip),
			(long long)atomic64_read(&mxfs_fua_inode_owned_skip),
			(long long)atomic64_read(&mxfs_iget_cluster_staled),
			(long long)atomic64_read(&mxfs_ccprev_reads),
			(long long)atomic64_read(&mxfs_ccprev_nostale),
			(long long)atomic64_read(&mxfs_ccprev_tenure_hit),
			(unsigned long long)ktime_get_real_ns());
}

void mxfs_dlm_report_stats(void)
{
	uint64_t now = mxfs_pal_time_ms();
	int64_t hit, miss, imm, def, noino;
	int64_t ag_acq, ag_nest, ag_rel;

	if (mxfs_dlm_stat_last_report && now - mxfs_dlm_stat_last_report < 10000)
		return;
	mxfs_dlm_stat_last_report = now;

	hit = atomic64_read(&mxfs_dlm_stat_cache_hit);
	miss = atomic64_read(&mxfs_dlm_stat_cache_miss);
	imm = atomic64_read(&mxfs_dlm_stat_bast_immediate);
	def = atomic64_read(&mxfs_dlm_stat_bast_deferred);
	noino = atomic64_read(&mxfs_dlm_stat_bast_no_inode);
	ag_acq = atomic64_read(&mxfs_dlm_stat_ag_acquire);
	ag_nest = atomic64_read(&mxfs_dlm_stat_ag_nested);
	ag_rel = atomic64_read(&mxfs_dlm_stat_ag_release);

	if ((hit + miss > 0 || ag_acq > 0))
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs DLM cache: hit=%lld miss=%lld (%lld%%) "
			"bast: imm=%lld def=%lld noino=%lld "
			"ag: acq=%lld nest=%lld rel=%lld trybusy=%lld trydemote=%lld "
			"handoff: n=%lld latch_unlock=%lld latch_acq=%lld latch_acqnb=%lld b2c_ms=%lld b2c_max=%lld b2c_gt50=%lld b2c_gt500=%lld c2r_ms=%lld c2r_max=%lld c2r_gt50=%lld c2r_gt500=%lld dwait_n=%lld dwait_ms=%lld dwait_max=%lld dwait_trans=%lld dwait_dirty=%lld postlatch_adopt=%lld q_gt500=%lld q_max=%lld wq_gt500=%lld wq_max=%lld e2a_gt500=%lld e2a_max=%lld a2c_gt500=%lld a2c_max=%lld rxheld=%lld stale_hint=%lld "
			"resv: try=%lld ok=%lld cont=%lld cool=%lld err=%lld exh=%lld adv=%lld sweeps=%lld backoff_ms=%lld demand=%lld probe_us=%lld probe_max_us=%lld grow=%lld "
			"noino_lc: inact=%lld needinact=%lld inew=%lld ireclaim=%lld vfsteardown=%lld reclaimable=%lld requeued=%lld lc_timeouts=%lld "
			"fua: ino=%lld dir=%lld agm=%lld ino_skip=%lld ccprev=%lld ccprev_nostale=%lld ccprev_tenure_hit=%lld",
			hit, miss,
			(hit + miss) ? hit * 100 / (hit + miss) : 0,
			imm, def, noino,
			ag_acq, ag_nest, ag_rel,
			(long long)atomic64_read(&mxfs_dlm_stat_agtry_localbusy),
			(long long)atomic64_read(&mxfs_dlm_stat_ag_trydemoting),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_n),
			(long long)atomic64_read(&mxfs_dlm_stat_latch_unlock),
			(long long)atomic64_read(&mxfs_dlm_stat_latch_acq),
			(long long)atomic64_read(&mxfs_dlm_stat_latch_acqnb),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_b2c_ms),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_b2c_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_b2c_gt50),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_b2c_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_c2r_ms),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_c2r_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_c2r_gt50),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_c2r_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_demote_wait_n),
			(long long)atomic64_read(&mxfs_dlm_stat_demote_wait_ms),
			(long long)atomic64_read(&mxfs_dlm_stat_demote_wait_max),
			(long long)atomic64_read(&mxfs_dlm_stat_demote_wait_trans),
			(long long)atomic64_read(&mxfs_dlm_stat_demote_wait_dirty),
			(long long)atomic64_read(&mxfs_dlm_stat_postlatch_adopt),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_q_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_q_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_wq_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_wq_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_e2a_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_e2a_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_a2c_gt500),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_a2c_max),
			(long long)atomic64_read(&mxfs_dlm_stat_handoff_rxheld),
			(long long)atomic64_read(&mxfs_dlm_stat_stale_hint),
			(long long)atomic64_read(&mxfs_resv_stat_try),
			(long long)atomic64_read(&mxfs_resv_stat_ok),
			(long long)atomic64_read(&mxfs_resv_stat_contended),
			(long long)atomic64_read(&mxfs_resv_stat_cool),
			(long long)atomic64_read(&mxfs_resv_stat_err),
			(long long)atomic64_read(&mxfs_resv_stat_exhaust),
			(long long)atomic64_read(&mxfs_resv_stat_recadv),
			(long long)atomic64_read(&mxfs_resv_stat_sweeps),
			(long long)atomic64_read(&mxfs_resv_stat_backoff_ms),
			(long long)atomic64_read(&mxfs_resv_stat_demand),
			(long long)(atomic64_read(&mxfs_resv_stat_probe_ns) / 1000),
			(long long)(atomic64_read(&mxfs_resv_stat_probe_max_ns) / 1000),
			(long long)atomic64_read(&mxfs_resv_stat_grow),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_INACTIVATING]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_NEED_INACTIVE]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_INEW]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_IRECLAIM]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_VFS_TEARDOWN]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_stat[XFS_ILC_RECLAIMABLE]),
			(long long)atomic64_read(&mxfs_noino_lifecycle_requeued),
			(long long)atomic64_read(&mxfs_noino_lifecycle_timeouts),
			(long long)atomic64_read(&mxfs_fua_inode_reads),
			(long long)atomic64_read(&mxfs_fua_dir_reads),
			(long long)atomic64_read(&mxfs_fua_agmeta_reads),
			(long long)atomic64_read(&mxfs_fua_inode_owned_skip),
			(long long)atomic64_read(&mxfs_ccprev_reads),
			(long long)atomic64_read(&mxfs_ccprev_nostale),
			(long long)atomic64_read(&mxfs_ccprev_tenure_hit));
}

/* P71 instrumented probe: run68's wedge kept a leaked
 * i_dlm_ex_holders=1 with no live holder task, permanently blocking the
 * ilock_end/notify BAST re-fire (both require exact-zero counts).  Print
 * every holder-count transition taken while the lock state is in a
 * demote/BAST window (normal CACHED traffic stays silent) so the leaking
 * site+comm self-identify.  Caller holds i_dlm_lock.  Capped. */
void
mxfs_p71_hold(struct xfs_inode *ip, const char *site, int dex, int dpr)
{
	static atomic_t p71_n = ATOMIC_INIT(0);

	if (ip->i_dlm_state != MXFS_DLM_ISTATE_DEMOTING &&
	    ip->i_dlm_state != MXFS_DLM_ISTATE_BAST)
		return;
	if (atomic_inc_return(&p71_n) > 8000)
		return;
	mxfs_probe("mxfs: P71-HOLD ino=%llu %s d_ex=%d d_pr=%d now_ex=%u now_pr=%u mode=%u state=%u pin=%u comm=%s\n",
		(unsigned long long)ip->i_ino, site, dex, dpr,
		ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
		ip->i_dlm_mode, ip->i_dlm_state, ip->i_dlm_pin_count,
		current->comm);
}
atomic64_t mxfs_noino_lifecycle_stat[XFS_ILC_NR];
atomic64_t mxfs_noino_lifecycle_requeued = ATOMIC64_INIT(0);
atomic64_t mxfs_noino_lifecycle_timeouts = ATOMIC64_INIT(0);
module_param_cb(sf_own_image_hits, &mxfs_dbg_atomic_param_ops,
		&mxfs_sf_own_image_hits, 0644);
MODULE_PARM_DESC(sf_own_image_hits,
		 "refreshes that found this node's own flushed image on the platter and kept the in-core fork (write resets)");
module_param_cb(sf_own_image_recorded, &mxfs_dbg_atomic_param_ops,
		&mxfs_sf_own_image_recorded, 0644);
MODULE_PARM_DESC(sf_own_image_recorded,
		 "shortform dir images recorded at flush into the own-image ring (write resets)");
module_param_cb(sf_release_base, &mxfs_dbg_atomic_param_ops,
		&mxfs_sf_release_base, 0644);
MODULE_PARM_DESC(sf_release_base,
		 "merge bases captured from the platter at a shortform dir's EX release (write resets)");

/* ─── Inode init ─── */

/*
 * Initialize per-inode DLM fields.
 * Called from xfs_inode_alloc for every new xfs_inode.
 */
void
mxfs_dlm_inode_init(
	struct xfs_inode	*ip)
{
	/*
	 * FIRST, before anything that can reach mxfs_dlmtr_rec — the
	 * xfs_inode cache is not zeroing, so the authority backstop inside
	 * that chokepoint would otherwise read garbage state on a fresh
	 * allocation.  A fresh inode holds no authority by construction.
	 */
	/* tuple publication, associated with the writers' lock */
	seqcount_spinlock_init(&ip->i_mxfs_auth_seq, &ip->i_dlm_lock);
	ip->i_mxfs_auth_inact = MXFS_INACT_CERT_NONE;
	ip->i_mxfs_auth_state = MXFS_AUTH_NONE;
	ip->i_mxfs_auth_kind = 0;
	ip->i_mxfs_auth_reaffirm = 0;
	ip->i_mxfs_auth_gen = 1;	/* 0 is never a live snapshot value */
	ip->i_mxfs_auth_resource = 0;
	ip->i_mxfs_auth_epoch = 0;
	ip->i_mxfs_auth_lineage = 0;
	ip->i_mxfs_auth_incarn = 0;
	ip->i_mxfs_auth_line = MXFS_SITE;
	/*
	 * THE LAST-ATTEMPT RECORD IS PART OF THE SAME BLOCK AND MUST BE RESET
	 * WITH IT.  These five were the only members of the authority block
	 * left out, on a slab the comment above already states is not zeroing —
	 * so a recycled inode reported the PREVIOUS TENANT'S install attempt,
	 * and the documented reading of the pair ("try == NONE means no install
	 * was EVER attempted here", "try_gen < auth_gen means a revoke happened
	 * after the last attempt") was unsound for exactly the reused
	 * incarnations that need it most.  i_mxfs_auth_gen restarts at 1 here
	 * while try_gen carried an arbitrary older value, so the staleness
	 * comparison could read either way on evidence belonging to a different
	 * inode.  Nothing gates on these fields, but dispositions are made on
	 * them, and an instrument that reports a refusal that never happened
	 * sends the next investigation at the wrong code.
	 */
	ip->i_mxfs_auth_try = MXFS_AUTH_TRY_NONE;
	ip->i_mxfs_auth_try_mode = 0;
	ip->i_mxfs_auth_try_line = 0;
	ip->i_mxfs_auth_try_epoch = 0;
	ip->i_mxfs_auth_try_gen = 0;
	ip->i_mxfs_relmark_res = 0;	/* */
	ip->i_mxfs_relmark_epoch = 0;
	/* 0.84.18 (D-0963): no own-flushed shortform images yet.  The free
	 * callback releases them, so a recycled object arrives with NULLs. */
	{
		int	k;

		for (k = 0; k < MXFS_SF_OWN_RING; k++) {
			ip->i_dlm_dir_sf_own[k] = NULL;
			ip->i_dlm_dir_sf_own_bytes[k] = 0;
		}
		ip->i_dlm_dir_sf_own_next = 0;
	}

	spin_lock_init(&ip->i_dlm_lock);
	init_waitqueue_head(&ip->i_dlm_wait);
	INIT_WORK(&ip->i_dlm_bast_work, mxfs_dlm_bast_work_fn);
	INIT_DELAYED_WORK(&ip->i_dlm_bast_dwork, mxfs_dlm_bast_dwork_fn);
	ip->i_dlm_bast_pending = false;
	ip->i_dlm_drain_site = 0;	/* not inside a drain flush */
	ip->i_dlm_bast_starve_since_ns = 0;
	ip->i_dlm_dir_contended = false;	/* sticky shared-dir BAST flag */
	ip->i_dlm_dir_want_ex = false;		/* peer-wants-EX (modifier) BAST flag (design review) */
	ip->i_dlm_bast_during_acq = false;	/* deferred-during-ACQUIRING BAST */ ip->i_dlm_stale_src = 0; ip->i_dlm_bastq_src = 0;
	ip->i_dlm_self_demote = false;		/* EDEADLK self-demote tag */
	ip->i_dlm_bastq_qns = 0;		/* P296-BASTQLAT arm stamp */
	ip->i_dlm_ex_acquire_ns = 0;
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_mode = MXFS_LOCK_NL;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	ip->i_dlm_epoch_src = 0;
	ip->i_dlm_epoch = 1;	/* v0.5.1: != 0 so a fresh dentry (d_time==0) never epoch-fast-paths before one coordinated validation */
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	/* #18: AFTER the two init transitions above — they pass a
	 * recycled-slab om into mxfs_dlmtr_rec, which would garbage-stamp
	 * these.  0 = no granted->NL lowering in THIS incarnation. */
	ip->i_dlm_nl_line = 0;
	ip->i_dlm_nl_pid = 0;
	ip->i_dlm_nl_ns = 0;
	ip->i_dlm_nl_om = 0;
	ip->i_dlm_nl_comm[0] = '\0';
	ip->i_dlm_ex_holders = 0; MXFS_DLMTR_H(ip);
	ip->i_dlm_pr_holders = 0; MXFS_DLMTR_H(ip);
	ip->i_dlm_pin_count = 0;
	ip->i_dlm_acq_inflight = 0;	/* daf50d34 no slow-path acquire in flight */
	ip->i_dlm_acq_pid = 0;		/* ACQUIRING-setter forensics */
	ip->i_dlm_acq_comm[0] = '\0';
	ip->i_dlm_acq_set_ns = 0;
	ip->i_dlm_exh_pid = 0;		/* EX-admission holder forensics */
	ip->i_dlm_exh_comm[0] = '\0';
	ip->i_dlm_exh_since_ns = 0;
	ip->i_dlm_acq_strikes = 0;
	ip->i_dlm_yield_remaining = 0;
	ip->i_dlm_dwork_strikes = 0;	/* v0.10.31: dwork busy-re-arm strikeout */
	ip->i_dlm_phantom_bast_j = 0;	/* FIX-20: phantom-BAST strikes */
	ip->i_dlm_phantom_bast_n = 0;
	ip->i_dlm_orphan_gg = 0;	/* FIX-H2: orphan-live strikes */
	ip->i_dlm_orphan_strikes = 0;
	ip->i_dlm_orphan_since_ns = 0;	/*  a864 wall-clock strand escape clock */
	{
		static atomic_t init_seq_ctr = ATOMIC_INIT(0);
		ip->i_dlm_init_seq = (uint32_t)atomic_inc_return(&init_seq_ctr);
	}
	ip->i_dlm_p72_strikes = 0;	/*  a864 P72 orphan-reclaim strike */
	ip->i_dlm_reconcile_pending = false;
	ip->i_dlm_dir_gen = 0;	/* read-time block-dir invalidation gen */
	ip->i_dlm_dir_loaded_gen = 0;	/* shortform-fork load gen */
	ip->i_mxfs_iget_ns = ktime_get_ns();	/* cold-iget age for P14 */
	/* recycled slab memory must not inherit the previous
	 * occupant's defer episode (same class as the stranded-demoter-claim
	 * root below) — a fresh in-core inode has no release in flight. */
	ip->i_mxfs_reldefer_started_j = 0;
	ip->i_mxfs_reldefer_progress_j = 0;
	ip->i_mxfs_reldefer_causes = 0;
	ip->i_mxfs_reldefer_badness = 0;
	ip->i_mxfs_reldefer_tries = 0;
	ip->i_mxfs_relwedge_shot = false;
	ip->i_mxfs_dscan_clean_key = ~0ULL;	/* datascan gen-gate sentinel — first miss always scans */
	ip->i_dlm_handoff_acted_gen = 0;	/* no handoff acted on yet */
	ip->i_dlm_dir_valid_epoch = 0;	/* base predates any tracked handoff -> first dir grant refreshes */
	ip->i_dlm_dir_valid_incarn = 0;	/* NO baseline yet — mxfs_dir_epoch_superseded treats a mismatch against the live i_generation as "belongs to another incarnation" */
	ip->i_dlm_base_valid = 0;	/* Option B: no baseline for this in-core incarnation — first dir-EX authorization adopts (recycled slab memory would otherwise inherit the previous occupant's bit, exactly the class the demoter-claim root documents below) */
	ip->i_dlm_creator_base_state = MXFS_CBASE_UNSET;	/* no baseline established for this incarnation yet */
	ip->i_dlm_dir_acq_epoch = 0;	/* v0.6.5: never made coherent by an acquire-reload adopt yet */
	ip->i_dlm_icd_refused = false;	/* v0.6.5: no tenure-refused destage pending */
	ip->i_dlm_dir_evicted_gen = 0;	/* consumer eager-evict gen */
	ip->i_dlm_dir_evicted_incarn = 0;	/* ABA incarnation evict-key (0 != any real i_generation => first access force-evicts) */
	ip->i_dlm_dir_evict_mep = 0;	/* new-tenure evict baseline (0 => first multinode modify is a new tenure) */
	ip->i_dlm_adopt_ok_epoch = 0;	/* no clean adopt check under EX yet -> first modify reads */
	ip->i_dlm_adopt_ok_incarn = 0;
	ip->i_dlm_adopt_ok_dir_gen = 0;
	ip->i_dlm_leaf_scan_epoch = 0;	/* 0.75.61: first modify under EX scans the leaf range */
	ip->i_dlm_leaf_scan_incarn = 0;
	ip->i_mxfs_dir_hole_known = false;	/* 0.75.63: no legitimate data-region hole known for this incarnation */
	ip->i_mxfs_ex_grant_seq = 0;	/* DLM-epoch guard — no EX tenure yet */
	ip->i_mxfs_dirty_seq = 0;	/* no dirtying under EX yet */
	ip->i_mxfs_dirty_ns = 0;	/* P197: no dirtying timestamp yet */
	/*
	 *  — ROOT OF THE STRANDED DEMOTER CLAIM.
	 *
	 * xfs_inode_alloc gets its xfs_inode from alloc_inode_sb ->
	 * kmem_cache_alloc_lru.  That memory is NOT zeroed: it is a recycled
	 * slab object, and every MXFS field the initializer does not explicitly
	 * assign carries the PREVIOUS OCCUPANT's value.  i_dlm_demoter and
	 * i_dlm_demoter2 were "cleared" here by MXFS_CLEAR_DEMOTER, which — by
	 * deliberate design, and correctly for every other caller — REFUSES a
	 * clear by a task that owns neither slot (D-BAST-IRELE-INACTIVE-SELF-
	 * WEDGE: a non-owner clear is what stranded the real owner).  So an
	 * inherited claim was not cleared; it was logged as
	 * P76-DEMOTER-FOREIGN-CLEAR and left in place.
	 *
	 * The inode is then born with mxfs_foreign_demoter() already true, and
	 * it stays true for the life of the in-core inode: EVERY reload pays
	 * mxfs.reload_demote_wait_ms and abandons with i_dlm_stale set.  That is
	 * exactly the observed shape — a claim whose stamped holder PID no
	 * longer exists (it belongs to the slab object's previous life), the
	 * same stale pid across several unrelated inodes, ages of minutes, and
	 * P215-DEFER balance=0 proving the defer/drain accounting never lost
	 * anything.
	 *
	 * A FRESHLY ALLOCATED INODE CANNOT HAVE A DRAIN IN PROGRESS — it is not
	 * in the radix tree, so no other task can even name it.  The refusal has
	 * no meaning here.  Force both slots, unconditionally, and COUNT the
	 * inherited ones: that count is the direct measurement of the root.
	 */
	if (unlikely(ip->i_dlm_demoter || ip->i_dlm_demoter2)) {
		static atomic_t p216n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_dem_init_inherit);
		if (atomic_inc_return(&p216n) <= 200)
			mxfs_probe("mxfs: P216-INIT-INHERITED-CLAIM ino=%llu s1=%d s2=%d s1_pid=%d s1_comm=%s s1_line=%u:%u s1_depth=%d s2_pid=%d s2_line=%u:%u — fresh inode inherited a demoter claim from the recycled slab object; forced NULL\n",
				(unsigned long long)ip->i_ino,
				!!ip->i_dlm_demoter, !!ip->i_dlm_demoter2,
				ip->i_dlm_demoter_pid, ip->i_dlm_demoter_comm,
				MXFS_SITE_ARGS(ip->i_dlm_demoter_line), ip->i_dlm_demoter_depth,
				ip->i_dlm_demoter2_pid,
				MXFS_SITE_ARGS(ip->i_dlm_demoter2_line));
	}
	ip->i_dlm_demoter = NULL;
	ip->i_dlm_demoter2 = NULL;
	ip->i_dlm_demoter_depth = 0;
	ip->i_dlm_demoter2_depth = 0;
	MXFS_CLEAR_DEMOTER(ip);
	ip->i_dlm_demoter_punt = 0;		/* no trans-free-retained claim */
	ip->i_dlm_punt_n[0] = 0;
	ip->i_dlm_punt_n[1] = 0;
	ip->i_dlm_demoter_punt_ns = 0;
	ip->i_dlm_strand_named = false;		/* not yet named as stranded */
	ip->i_dlm_demoter2_pid = 0;		/* slot-2 forensics */
	ip->i_dlm_demoter2_comm[0] = '\0';
	ip->i_dlm_demoter2_set_ns = 0;
	ip->i_dlm_demoter2_line = 0;
	ip->i_dlm_clobber_victim_pid = 0;	/* no claim stolen on this incarnation */
	ip->i_dlm_clobber_victim_line = 0;
	ip->i_dlm_p6skip_n = 0;			/* H4: no P6 skip streak yet */
	ip->i_mxfs_self_created = false;	/* v0.5.4: only xfs_create's success path sets this */
	ip->i_mxfs_dead_incarn_gen = 0;	/* no dead-incarnation verdict */
	ip->i_mxfs_freeob = 0;		/* no FREE obligation */
	ip->i_mxfs_freeob_strikes = 0;
	ip->i_mxfs_freepub_epoch = 0;	/* no FREE-publication claim */
	ip->i_mxfs_freepub_bp = NULL;
	ip->i_mxfs_freepub_seq = 0;
	ip->i_mxfs_freepub_gen = 0;
	/* D3 residual: publication obligation counters start equal =
	 * "nothing owed" (see the design block at xfs_inode.h). */
	ip->i_mxfs_pub_pending_seq = 0;
	ip->i_mxfs_pub_durable_seq = 0;
	ip->i_mxfs_pub_flush_seq = 0;	/* no image in flight */
	ip->i_mxfs_pub_durable_fepoch = 0;	/* F3: no discharge yet */
	/*
	 * MUST be reset with the counters above, for the reason the
	 * comment below spells out — xfs_inode_alloc is kmem_cache_alloc, not
	 * zalloc, so a recycled inode would otherwise inherit a stale
	 * "a fence abandoned my publication" verdict and its reload budget,
	 * and the release-side reload would fire (or refuse to) on evidence
	 * belonging to a previous incarnation.
	 */
	ip->i_mxfs_pub_fenced = 0;
	ip->i_mxfs_reldefer_reloads = 0;
	/*
	 * MUST be reset here.  xfs_inode_alloc uses kmem_cache_alloc,
	 * NOT zalloc, so a recycled xfs_inode carries whatever the previous
	 * tenant left in any field this function does not clear.  The first
	 * P219 measurement read `stage_epoch=2 now_epoch=1` on 18 of 22 hits —
	 * an epoch that went DOWN, which a monotonic counter cannot do: those
	 * were recycled inodes whose i_dlm_epoch had been re-initialised to 1
	 * while the stale staging stamp survived.  Instrument artifact, not a
	 * lost tenure.
	 */
	ip->i_mxfs_pub_stage_epoch = 0;
	ip->i_mxfs_pub_stage_mode = 0;
	ip->i_mxfs_pub_stage_ns = 0;
	ip->i_mxfs_atomic_bypass_ns = 0;	/* P229/P230 */
	ip->i_mxfs_disk_nlink_seen = 0;	/* P186: fresh incarnation */
	ip->i_mxfs_disk_nlink_gen = 0;
	ip->i_mxfs_reused_create = false;	/* v0.5.4 set by rearm_unpublished only */
	ip->i_dlm_unpublished = false;	/* deferred-publish */
	ip->i_dlm_iclus_seen_seq = 0;	/* iclus coherency clock: never loaded */
	ip->i_dlm_routed_iclus = false;	/* no grant, no backing resource */
	INIT_LIST_HEAD(&ip->i_dlm_unpub_link);
	/* ILOCK last-locker forensics */
	atomic_set(&ip->i_mxfs_ilk_rd_held, 0);
	atomic_set(&ip->i_mxfs_ilk_wr_held, 0);	/* writer-quiescence census */
	ip->i_mxfs_pipe_relog = 0;		/* P234 tripwire gate */
	ip->i_mxfs_ilk_wr_ret = 0;
	ip->i_mxfs_ilk_rd_ret = 0;
	ip->i_mxfs_ilk_un_ret = 0;
	ip->i_mxfs_ilk_wr_pid = 0;
	ip->i_mxfs_ilk_rd_pid = 0;
	ip->i_mxfs_ilk_wr_comm[0] = '\0';
	ip->i_mxfs_ilk_rd_comm[0] = '\0';
	/*
	 * Start stale when DLM is active.  The in-memory inode is
	 * populated at iget/mount time before any DLM lock is held,
	 * so it may not reflect other nodes' changes.  The first
	 * DLM acquire (slow path) will see stale=true and reload
	 * from disk, ensuring we have the current on-disk state.
	 * Single-node mounts never check stale, so this is harmless.
	 */
	ip->i_dlm_stale = (ip->i_mount->m_mxfs_dlm != NULL);
}

/*
 * instrumented inode-lifecycle watch: mxfs.watch_ino=<ino>
 * traces every iflush / iflush-abort / DLM release-fence pass / reload-adopt
 * decision / dir-contraction event for one inode.  Hunting the run13 proven
 * loss: the rm-holder's committed dir contraction (block->SF) never reached
 * the on-disk dinode, yet its ILI looked clean at the next reload, which
 * adopted the stale EXTENTS map whose blocks the contraction had already
 * freed durably (bnobt) -> map-of-freed-blocks resurrected cluster-wide.
 */
unsigned long long mxfs_watch_ino;
module_param_named(watch_ino, mxfs_watch_ino, ullong, 0644);
MODULE_PARM_DESC(watch_ino,
		 "Trace iflush/abort/release-fence/reload for this inode number (0=off)");
EXPORT_SYMBOL(mxfs_watch_ino);

/*
 * D-STATFS-IFREE-NEGATIVE-RANK1 fix, part 1: cluster-coherent statfs
 * sums.  The percpu lazy SB counters (m_icount/m_ifree/m_fdblocks) receive
 * only LOCAL transaction deltas — foreign nodes' creates/frees never land, so
 * any cross-node asymmetry drifts them monotonically (measured: rank1, which
 * does cluster-wide cleanup rm, reached used = -10851 inodes and +38MB
 * phantom free space within hours).  The per-AG summaries, by contrast, ARE
 * cluster-coherent: a fresh cross-node AG acquire with an advanced disk
 * generation clears AGF/AGI_INIT so the next header read re-initializes
 * the pagf and pagi summaries from the FUA-fresh buffer (P102-ACQ block).  Sum
 * those instead.  Residual staleness is bounded (AGs this node hasn't
 * acquired recently), structurally sane (never negative), and self-heals on
 * every acquire — versus unbounded drift.  Per the design review review the
 * percpu ADMISSION counters are left untouched: there is no safe external
 * adjustment (reserved-pool/set-aside semantics), and the cross-node
 * delalloc-overcommit question is a separate ledgered thread.
 *
 * Returns false on single-node / no-DLM mounts — caller uses the upstream
 * percpu path (upstream semantics preserved exactly).
 */
bool
mxfs_statfs_perag_sums(
	struct xfs_mount	*mp,
	uint64_t		*icount,
	uint64_t		*ifree,
	uint64_t		*fdblocks)
{
	struct xfs_perag	*pag = NULL;
	uint64_t		ic = 0, ifr = 0, fdb = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	while ((pag = xfs_perag_next(mp, pag))) {
		uint32_t	pi_c = READ_ONCE(pag->pagi_count);
		uint32_t	pi_f = READ_ONCE(pag->pagi_freecount);

		/* An AGI must satisfy free <= count; a violation means a torn
		 * read against a concurrent re-init — degrade to count (sane)
		 * rather than propagate an underflow into f_ffree. */
		if (pi_f > pi_c)
			pi_f = pi_c;
		ic += pi_c;
		ifr += pi_f;
		fdb += READ_ONCE(pag->pagf_freeblks);
	}
	*icount = ic;
	*ifree = ifr;
	*fdblocks = fdb;
	return true;
}
EXPORT_SYMBOL(mxfs_statfs_perag_sums);

/*
 * part 2: mount-time init of every AGF+AGI so the statfs sums above
 * cover AGs this node never touches (uninitialized pagi and pagf fields read
 * as zero and would under-report).  ~2 reads per AG through the normal
 * DLM-aware verified paths, once per mount.  Errors are non-fatal: the AG
 * just stays uninitialized until first use, exactly as before.
 */
void
mxfs_init_all_perag_data(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;
	int			inited = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	while ((pag = xfs_perag_next(mp, pag))) {
		struct xfs_buf	*bp;

		if (!xfs_perag_initialised_agf(pag)) {
			if (!xfs_alloc_read_agf(pag, NULL, 0, &bp))
				xfs_buf_relse(bp);
		}
		if (!xfs_perag_initialised_agi(pag)) {
			if (!xfs_ialloc_read_agi(pag, NULL, 0, &bp))
				xfs_buf_relse(bp);
		}
		inited++;
	}
	pr_info("mxfs: statfs perag baseline initialized (%d AGs)\n", inited);
}
EXPORT_SYMBOL(mxfs_init_all_perag_data);
/*
 * (#1 design review Q5): one lock serializes every setter that can
 * change the foreign_replay_token_enforce prerequisite predicates with the
 * enforce setter's check-then-write and with the recovery preflight's
 * config sample — a prerequisite can then never flip between "validated"
 * and "written", and an armed knob can never be invalidated underneath a
 * concurrent validation.  release_proof_enforce is 0444 (immutable at
 * runtime) so only the two F2-domain params below need the guard.
 */
DEFINE_MUTEX(mxfs_fr_cfg_lock);
EXPORT_SYMBOL(mxfs_fr_cfg_lock);

static int
mxfs_fua_disable_set(const char *val, const struct kernel_param *kp)
{
	int v;
	int rc = kstrtoint(val, 0, &v);

	if (rc)
		return rc;
	mutex_lock(&mxfs_fr_cfg_lock);
	if (v && READ_ONCE(mxfs_foreign_replay_token_enforce) &&
	    !mxfs_target_cache_protected) {
		mutex_unlock(&mxfs_fr_cfg_lock);
		pr_err("mxfs: fua_disable=%d REFUSED while foreign_replay_token_enforce is armed without target_cache_protected — it would invalidate the F2 domain the enforcement arming was validated against.  Disarm foreign_replay_token_enforce first\n",
		       v);
		return -EBUSY;
	}
	WRITE_ONCE(mxfs_fua_disable, v);
	mutex_unlock(&mxfs_fr_cfg_lock);
	return 0;
}
static const struct kernel_param_ops mxfs_fua_disable_ops = {
	.set = mxfs_fua_disable_set,
	.get = param_get_int,
};
module_param_cb(fua_disable, &mxfs_fua_disable_ops, &mxfs_fua_disable, 0644);
MODULE_PARM_DESC(fua_disable,
                 "Disable SCSI-FUA reads; use normal bio (SCST shared cache "
                 "is coherent): 1=disable-FUA-reads (default, SCST-required), "
                 "0=use-FUA");

/*
 * on regular-file DLM release (BAST), iflush the dinode + flush the
 * device write cache so a peer's FUA read of the inode cluster sees the
 * writer's di_size (closes the cross-node empty-content failure).  Default
 * on; set 0 to A/B the correctness benefit vs the per-release flush cost.
 */
/*
 * DEFAULT OFF: tested =1 — it made cross-node empty-content WORSE
 * (40 fails vs ~15, 120 empty vs 36) and the test 10x slower (151s).  The
 * cross-node empty-content is a LATENCY-SENSITIVE RACE, not a missing-
 * durability problem: a per-release flush widens the race window rather than
 * closing it.  Kept off; the next session should NOT pursue durability fixes
 * for the empty-content — it is a coherence/race issue (see docs/history/session-39-lessons.md).
 */
/*
 * IRECLAIMABLE reused-inode DLM-coordinated reload in xfs_iget_cache_hit.
 * Default ON (needed for the create-race coherency: a peer-reused inode read as
 * mode=0 -> EACCES/ENOENT, blocks cache_coherency).  Param so it can be A/B'd:
 * it adds a reload (+ DLM round-trip for Type-A) per stale mode-0 iget, which
 * over-triggers on the unlink verify-gone phase (~480 igets of deleted files)
 * and pushes cache_coherency over its 900s budget.  The real fix is parent-
 * dir-block coherence so deleted dirents aren't followed at all.  Set
 * mxfs.reuse_reload=0 to isolate that perf cost / disable the create-race fix.
 */
int mxfs_reuse_reload = 1;
module_param_named(reuse_reload, mxfs_reuse_reload, int, 0644);
MODULE_PARM_DESC(reuse_reload,
                 "Cheap reload of IRECLAIMABLE reused inodes on iget "
                 "(1=on default, fixes create-race; 0=off, faster).");

/*
 * gate the EXPENSIVE Type-A DLM PR round-trip inside the reuse_reload
 * path (BAST the peer to force its flush when disk still reads free).  Default
 * OFF — it over-fires on unlink verify-gone (~480 deleted-file igets) and times
 * out cache_coherency.  Cheap-only relies on the creator's eventual flush.
 */
int mxfs_reuse_dlm;
module_param_named(reuse_dlm, mxfs_reuse_dlm, int, 0644);
MODULE_PARM_DESC(reuse_dlm,
                 "Force a DLM PR round-trip for a still-free reused inode "
                 "(1=on, more correct under create-race; 0=off default, fast).");

/*
 *  — STRANDED CAW AG GRANT repair.
 *
 * The AG BAST schedule gate (mxfs_dlm_ag_bast_notify) requires
 * pag_dlm_cached: a release is only ever driven from the "we hold it on
 * disk and know it" state.  If a node ever reaches
 *     holders == 0 && !cached && !demoting && !release_pending
 * while its CAW holder bit is STILL SET on the platter, nothing on this
 * node can ever release that AG again — every peer BAST hits the gate,
 * finds nothing to schedule, and the peers block until the 480 s
 * liveness-extended disk-lock cap, at which point mxfs_dlm_ilock_begin
 * force-shuts the filesystem down.  Observed 2026-07-28 (32/caw, storm):
 * one stranded AG starved 31 peers and shut 21 of 32 filesystems down.
 *
 * The orphan-NAK covers the TCP flavour of this (master-side zombie
 * GRANTED entry) and is a NO-OP on CAW by construction — CAW has no
 * remote master table, the on-disk slot IS the truth, so the CAW repair
 * has to be a real release.
 *
 * Repair (mxfs.ag_strand_repair=1, default on): when the orphan condition
 * holds AND the CAW slot says we do hold the AG, re-adopt the grant into
 * pag_dlm_cached and hand it to the normal bast_work_fn.  That path runs
 * the FULL Architectural-Invariant-1 pipeline (log force + meta drain +
 * alloc buflist + inode buffers + blkdev flush) before
 * mxfs_v5_dlm_ag_unlock, so the repair can never publish a
 * not-yet-durable AG to a peer.  Set 0 to A/B against the pre-repair
 * behaviour (detect + report only).
 */
/*
 *  — H4: do not let a buffer-wide completion declare
 * unsubmitted inode bytes durable.  See MXFS_IF_PUB_SKIPPED (xfs_inode.h) and
 * xfs_buf_inode_iodone.  Default on; set 0 for a paired A/B against the old
 * (silently-lossy) behaviour.
 */
/*
 * MEASURED 2026-07-28 (build 609652CB): default 1 LIVELOCKS, exactly
 * as the design-consult review predicted.  Re-arming is only half a fix — the skip
 * happens BECAUSE this node no longer has publication authority, so the
 * retry can never succeed: xfsaild re-pushes, the sector is dropped again,
 * and the item is re-armed forever.  Storm run 155743: P187-PUB-REARM hit
 * its 4000 cap, P56-NL-LOGGED-DIR-SKIP went 21 -> 490, and test12 wedged in
 * mxfs_dlm_ilock_begin (INFRA-FAIL, 300 s).
 *
 * The completion lying about durability is still a real defect, but the
 * actionable repair is UPSTREAM: never leave the tenure with an unlanded
 * committed change (see P188-REL-OBLIGATION-AT-UNLOCK).  Re-arming becomes
 * safe only once that barrier holds, or once the retry can re-acquire the
 * inode grant and rebase before publishing.  Default OFF; kept as the lever
 * to re-test once the barrier is in.
 */
/*
 * — D-RELEASE-BARRIER-OPEN containment, review-ruled.
 * When set, the inode-cluster masking loop refuses to publish a LOGGED slot
 * whose image was staged under a tenure that has since died and for which we
 * hold no publication authority now (P222-STALE-STAGE-SKIP; measured shape:
 * xfsaild writing orphan images at NL after the grant-lost release, the
 * cluster-write-reverts-a-freed/reused-inode corruption class).  DEFAULT ON
 * since 0.11.272: paired laps on one module load measured skip=0 putting dead-
 * tenure images on the wire while skip=1 masked every detection (cumulative
 * sskip_landed=36, sskip_unlanded=0, wire writes of the class = 0) with the
 * full guard board green at healthy walls; 0 = pre-fix control.  See ccmemory
 * docs/rulings/stale-stage-mask-conditions.md for the full
 * condition set (three-state bookkeeping, recovery-side gate, EX-side
 * epoch-validity gate) this first cut deliberately scopes down from.
 */
int mxfs_stale_stage_skip = 1;
EXPORT_SYMBOL(mxfs_stale_stage_skip);
module_param_named(stale_stage_skip, mxfs_stale_stage_skip, int, 0644);
/* EX-side epoch gate (design review condition 4).  Separate knob by ruling —
 * never overload the NL knob.  1 = skip dead-tenure staged images from
 * EX-held home writes and restage under the live grant (PUB_SKIPPED
 * unconditional; retry succeeds at EX); 0 = legacy publish-at-EX control. */
int mxfs_stale_stage_skip_ex = 1;
EXPORT_SYMBOL(mxfs_stale_stage_skip_ex);
module_param_named(stale_stage_skip_ex, mxfs_stale_stage_skip_ex, int, 0644);
MODULE_PARM_DESC(stale_stage_skip_ex,
		 "EX-side dead-tenure staged-image gate (1=skip+restage "
		 "default, 0=legacy publish control)");
MODULE_PARM_DESC(stale_stage_skip,
                 "mask dead-tenure staged inode images out of home writes "
                 "(1=skip default, 0=pre-fix control; P222 counters in "
                 "P219-LOGGED-AUTHORITY-TOTAL)");

/*
 * (design review condition-1 ruling): the unlanded arm of the mask is an
 * invariant assertion, not a recovery path — a committed change whose only
 * non-journal copy is staged under a dead tenure at NL cannot be published
 * (cross-node corruption), completed (lost write), or re-armed bare (measured
 * AIL livelock).  Fail closed: shutdown -> lease loss -> peer fence -> the
 * journal copy is republished by the recovery protocol.  Never observed
 * (sskip_unlanded=0 across all laps/boards); 0 = legacy count-and-skip for
 * same-build A/B and fault injection only.
 */
int mxfs_stale_stage_unlanded_shutdown = 1;
EXPORT_SYMBOL(mxfs_stale_stage_unlanded_shutdown);
module_param_named(stale_stage_unlanded_shutdown, mxfs_stale_stage_unlanded_shutdown, int, 0644);
MODULE_PARM_DESC(stale_stage_unlanded_shutdown,
                 "fail closed (force shutdown) when a committed change is "
                 "found unlanded under a dead tenure at NL (1=shutdown "
                 "default, 0=legacy count-and-skip for A/B)");

/*
 * — D-FOREIGN-REPLAY-UNGATED-IMAGES containment,
 * review-ruled stop-ship.  Live foreign-slice replay applied BUFFER (and dquot/
 * quotaoff/icreate) image records gated only by the upstream on-disk-LSN
 * compare — but per-node log slices have independent LSN cycle/block
 * numbering, so a cross-slice XFS_LSN_CMP is meaningless (the sb-LSN check in
 * xlog_recover already skips itself for exactly this reason).  False-APPLY
 * silently reverts survivor-written dir blocks / AG state; false-SKIP drops
 * the dead node's fsync-acked change.  Until log records carry authority
 * tokens (resource id + grant incarnation + tenure), the only sound verdict
 * for an untagged non-inode image is SKIP: inode records keep their
 * node-independent di_changecount gate and continue to replay.
 * 1 = legacy apply (unsafe, same-build A/B control only).
 */
int mxfs_foreign_replay_untagged_apply;
EXPORT_SYMBOL(mxfs_foreign_replay_untagged_apply);
module_param_named(foreign_replay_untagged_apply, mxfs_foreign_replay_untagged_apply, int, 0644);
MODULE_PARM_DESC(foreign_replay_untagged_apply,
                 "apply untagged buf/dquot/icreate images during live "
                 "foreign-slice replay (0=skip-safe default, 1=legacy "
                 "cross-slice-LSN apply — A/B control only)");

/*
 * (D-529 verification): fault-injection knob for the whole-txn
 * verdict.  When >0, mxfs_classify_untrusted_txn treats any untrusted
 * transaction with MORE than this many items as if a later-batch item
 * were unauthorized (forces the ATOMIC-SKIP arm, P-DBG-FR-TAINT-INJECT).
 * Under the pre-D-529 per-batch classifier this exact condition produced
 * ADMIT-batch-1 + SKIP-batch-2 = a partial apply; with the whole-txn
 * verdict the entire transaction must skip and ZERO of its images may
 * reach the home platter.  Default 0 = off.  Test only.
 */
int mxfs_dbg_fr_taint_items_over;
EXPORT_SYMBOL(mxfs_dbg_fr_taint_items_over);
module_param_named(dbg_fr_taint_items_over, mxfs_dbg_fr_taint_items_over, int, 0644);
MODULE_PARM_DESC(dbg_fr_taint_items_over,
                 "D-529 fault injection: force ATOMIC-SKIP for untrusted "
                 "transactions with more than N items (0=off, test only)");

/*
 * companion (mount-time arm of the same defect): a PASS-2 (fresh)
 * disklock claim inherits a log slice whose dirty records belong to an
 * already-recovered or foreign incarnation; xfs_log_mount marks that
 * recovery ADOPTED and the same untagged-image/intent suppression applies
 * (inode records keep the di_changecount gate).  A PASS-1 own-stamp reclaim
 * (nobody replayed us) always performs full recovery.  1 = legacy full
 * replay of adopted slices (unsafe, A/B control only).
 */
int mxfs_adopted_slice_full_replay;
EXPORT_SYMBOL(mxfs_adopted_slice_full_replay);
module_param_named(adopted_slice_full_replay, mxfs_adopted_slice_full_replay, int, 0644);
MODULE_PARM_DESC(adopted_slice_full_replay,
                 "fully replay an ADOPTED (fresh-claim) log slice at mount "
                 "(0=suppress untagged images+intents default, 1=legacy full "
                 "replay — A/B control only)");

/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED): the verdict flip.  1 (default)
 * = a dead node's slice whose only open intents are admitted EFIs replays
 * successfully and its extents are completed by the custodian; 0 = the
 * pre-0.85.0 terminal refusal (INTENTS_UNDISCHARGED), the A/B control of
 * tests/d_intents_2tcp_open_efi.sh.  Read at the census verdict only.
 */
int mxfs_obl_complete_enable = 1;
EXPORT_SYMBOL(mxfs_obl_complete_enable);
module_param_named(obl_complete_enable, mxfs_obl_complete_enable, int, 0644);
MODULE_PARM_DESC(obl_complete_enable,
                 "complete a dead peer's open EFI obligations on the TCP "
                 "transport (1=default, 0=terminal refusal — A/B control only)");

/*
 * (#1 D-FOREIGN-REPLAY-UNGATED-IMAGES, ruling): recovery-
 * time foreign-replay token enforcement.  Turns the shadow evaluator's
 * whole-transaction verdict into an APPLY decision for fully-tokenized
 * victim transactions during elected foreign-slice recovery.
 *
 * SEPARATE from replay_gate_enforce by design: that knob arms the live
 * release-certificate gate and fails closed on the F1/F3/F4 release
 * barriers, which are prerequisites of trusting the release predicate on
 * the LIVE path — not of the recovery-time token gate ruled here.  This
 * setter fails closed on the ruling's own set-time predicates:
 *   - F2 domain admission: under fua_disable=1 the tenure-boundary
 *     flush_epoch is a no-op, so the manifest hold/epoch state a token is
 *     checked against may survive a target write-cache loss that dropped
 *     the home writes it certifies.  Enforcement then requires the
 *     operator's explicit target_cache_protected=1 declaration — never
 *     inferred from fua_disable (/rulings).
 *   - release_proof_enforce=1: with the deferral OFF a failed completion
 *     proof does not block the release CAS, so a manifest slot can read
 *     released without the covering flush — the token gate would then
 *     credit "not_held" verdicts the platter does not back.
 * Per-mount predicates (proto_admitted, FENCED recovery descriptor) are
 * enforced at use time in xfs_log_recover.c, which also re-checks the
 * domain per replay because these params stay runtime-writable.
 */
/* (design-consult ruling, 0.54.0): DEFAULT 1.  The shipped default 0 was a
 * measured data-unavailability defect on the plain crash path (
 * ordinary death -> POLICY-REFUSED -> AG quarantine -> survivor ESTALE).
 * The durability domain that makes the gate sound is validated at mount
 * time (mxfs_durability_domain_admit, pal/linux/xfs_super.c); the setter
 * below still fails closed for runtime re-arming. */
int mxfs_foreign_replay_token_enforce = 1;
EXPORT_SYMBOL(mxfs_foreign_replay_token_enforce);
DEFINE_SHOW_ATTRIBUTE(mxfs_recovery_blocked);
DEFINE_SHOW_ATTRIBUTE(mxfs_inode_authority);

static const struct file_operations mxfs_caw_pw_selftest_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= mxfs_caw_pw_selftest_write,
};

static const struct file_operations mxfs_caw_samenode_selftest_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= mxfs_caw_samenode_selftest_write,
};

static const struct file_operations mxfs_inject_unheld_agmeta_dirty_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= mxfs_inject_unheld_agmeta_dirty_write,
};
module_param_cb(dbg_iflush_pause_n, &mxfs_dbg_atomic_param_ops,
		&mxfs_dbg_iflush_pause_n, 0644);
MODULE_PARM_DESC(dbg_iflush_pause_n,
		 "TEST ONLY: cluster writes held by dbg_iflush_pause_ino (write resets)");
module_param_cb(dbg_ail_push_n, &mxfs_dbg_atomic_param_ops,
		&mxfs_dbg_ail_push_n, 0644);
MODULE_PARM_DESC(dbg_ail_push_n,
		 "TEST ONLY: AIL pushes requested through debugfs ail_push (write resets)");

static const struct file_operations mxfs_dbg_ail_push_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= mxfs_dbg_ail_push_write,
};
DEFINE_SHOW_ATTRIBUTE(mxfs_ailpin_stats);
DEFINE_SHOW_ATTRIBUTE(mxfs_acquire_degraded);

static const struct file_operations mxfs_alloc_witness_fops = {
	.owner		= THIS_MODULE,
	.open		= mxfs_alloc_witness_open,
	.read		= seq_read,
	.write		= mxfs_alloc_witness_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations mxfs_alloc_witness_chunk_fops = {
	.owner		= THIS_MODULE,
	.open		= mxfs_alloc_witness_chunk_open,
	.read		= seq_read,
	.write		= mxfs_alloc_witness_chunk_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations mxfs_dbg_lu_reset_admit_fops = {
	.owner		= THIS_MODULE,
	.open		= simple_open,
	.write		= mxfs_dbg_lu_reset_admit_write,
	.llseek		= noop_llseek,
};

static const struct file_operations mxfs_dbg_lu_reset_barrier_fops = {
	.owner		= THIS_MODULE,
	.open		= simple_open,
	.write		= mxfs_dbg_lu_reset_barrier_write,
	.llseek		= noop_llseek,
};

static const struct file_operations mxfs_dbg_lu_reset_fence_fops = {
	.owner		= THIS_MODULE,
	.open		= simple_open,
	.write		= mxfs_dbg_lu_reset_fence_write,
	.llseek		= noop_llseek,
};

void
mxfs_dlm_cache_init(
	struct xfs_mount	*mp)
{
	if (!mp->m_mxfs_dlm)
		return;

	mxfs_v5_dlm_set_fence_notify(mp->m_mxfs_dlm,
				     mxfs_dlm_fence_notify, mp);

	if (mp->m_debugfs) {
		debugfs_create_file("recovery_blocked", 0400, mp->m_debugfs, mp,
				    &mxfs_recovery_blocked_fops);
		debugfs_create_file("inode_authority", 0400, mp->m_debugfs, mp,
				    &mxfs_inode_authority_fops);
		/* removed EARLY in put_super (before m_mxfs_dlm is
		 * NULLed) — see the m_mxfs_pwtest_dentry field comment. */
		mp->m_mxfs_pwtest_dentry = debugfs_create_file(
				    "caw_pw_selftest", 0200, mp->m_debugfs, mp,
				    &mxfs_caw_pw_selftest_fops);
		mp->m_mxfs_samenode_dentry = debugfs_create_file(
				    "caw_samenode_selftest", 0200, mp->m_debugfs,
				    mp, &mxfs_caw_samenode_selftest_fops);
		/* D-0487 verification injector (see the write handler) */
		debugfs_create_file("inject_unheld_agmeta_dirty", 0200,
				    mp->m_debugfs, mp,
				    &mxfs_inject_unheld_agmeta_dirty_fops);
		/* 0.70.2: the refusal retirement-age census */
		debugfs_create_file("ailpin_stats", 0400, mp->m_debugfs, mp,
				    &mxfs_ailpin_stats_fops);
		/* 0.83.0: remote lock waits the master has stopped confirming */
		debugfs_create_file("acquire_degraded", 0400, mp->m_debugfs, mp,
				    &mxfs_acquire_degraded_fops);
		/* 0.84.18, test only: kick xfsaild (D-0963 platter-lag harness) */
		debugfs_create_file("ail_push", 0200, mp->m_debugfs, mp,
				    &mxfs_dbg_ail_push_fops);
		/* 0.89.9: the allocation-coverage witness (read: per-AG
		 * transition counts; write: clear them) */
		debugfs_create_file("alloc_witness", 0600, mp->m_debugfs, mp,
				    &mxfs_alloc_witness_fops);
		/* 0.89.10: the inobt record covering a written inode number */
		debugfs_create_file("alloc_witness_chunk", 0600, mp->m_debugfs,
				    mp, &mxfs_alloc_witness_chunk_fops);
		/* 0.89.31: the LU-reset admission gate's verdict, issuing
		 * nothing (see the write handler) */
		debugfs_create_file("lu_reset_admit", 0200, mp->m_debugfs, mp,
				    &mxfs_dbg_lu_reset_admit_fops);
		debugfs_create_file("lu_reset_barrier", 0200, mp->m_debugfs, mp,
				    &mxfs_dbg_lu_reset_barrier_fops);
		debugfs_create_file("lu_reset_fence", 0200, mp->m_debugfs, mp,
				    &mxfs_dbg_lu_reset_fence_fops);
	}

	/* v0.5.0: foreign-slice replay of dead peers (elected survivor) */
	INIT_WORK(&mp->m_mxfs_foreign_replay_work,
		  mxfs_dlm_foreign_replay_work_fn);
	/*
	 * 0.85.1: the dead/torn slot bitmaps are NOT zeroed here.  This runs
	 * after xfs_mountfs, and the mount recovery barrier inside it has
	 * already written them: an OPEN obligation case met in the barrier
	 * (P-OBL-BARRIER-OPEN) leaves its dead bit set and the REAPF_FREPLAY
	 * duty armed so the post-mount worker completes it.  Measured s614b
	 * (tests/evidence/20260913T042107Z_intents2tcp_s614b, dmesg_test1.txt):
	 * the zeroing here emptied the set, the reap worker's replay duty saw
	 * nothing outstanding and cleared itself, the orphan sweep ran with
	 * dead_slots=0x0 into the case's frozen AG and timed out twice
	 * (P-OBLF-AG-TIMEOUT), and the engine never started.  The mount is
	 * allocated zeroed, so the first writer is the barrier, never this.
	 */
	mxfs_v5_dlm_set_dead_node_notify(mp->m_mxfs_dlm,
					 mxfs_dlm_dead_node_notify, mp);
	/* (#92): clean-release latch unwind — see the notify body. */
	mxfs_v5_dlm_set_clean_depart_notify(mp->m_mxfs_dlm,
					    mxfs_dlm_clean_depart_notify, mp);

	/* DLM-stuck escalation — see mxfs_dlm_stuck_work_fn.  Same
	 * lifecycle as foreign_replay_work: INIT'd here iff m_mxfs_dlm was
	 * set, canceled after mxfs_v5_dlm_shutdown on every path past this
	 * point. */
	INIT_WORK(&mp->m_mxfs_dlm_stuck_work, mxfs_dlm_stuck_work_fn);
	mxfs_v5_dlm_set_dlm_stuck_notify(mp->m_mxfs_dlm,
					 mxfs_dlm_stuck_notify, mp);
	/* D-0487: the pinned-item response, same lifecycle as stuck_work */
	INIT_WORK(&mp->m_mxfs_ailpin_work, mxfs_ailpin_work_fn);
	atomic_set(&mp->m_mxfs_ailpin_fired, 0);
	atomic64_set(&mp->m_mxfs_ailpin_refused_n, 0);
	atomic64_set(&mp->m_mxfs_ailpin_clear_n, 0);
	atomic64_set(&mp->m_mxfs_ailpin_clear_sum_ms, 0);
	atomic64_set(&mp->m_mxfs_ailpin_clear_slow_n, 0);
	atomic64_set(&mp->m_mxfs_ailpin_clear_shutdown_n, 0);
	atomic_set(&mp->m_mxfs_ailpin_clear_max_ms, 0);

	mxfs_v5_dlm_set_bast_notify(mp->m_mxfs_dlm,
				     mxfs_dlm_bast_notify, mp);

	mxfs_v5_dlm_set_ag_bast_notify(mp->m_mxfs_dlm,
					 mxfs_dlm_ag_bast_notify, mp);

	/* ICLUSTER (Phase 1 core): callback registered but no ICLUSTER
	 * resource is ever acquired until the call-site routing lands
	 * (mxfs.icluster_dlm stays 0) — see DLM_PLAN.md.  Next session:
	 * fan-out inside the handler + mxfs_iclus_purge_all at teardown. */
	mxfs_v5_dlm_set_iclus_bast_notify(mp->m_mxfs_dlm,
					  mxfs_iclus_bast_notify, mp);

	mxfs_v5_dlm_set_peer_joined_notify(mp->m_mxfs_dlm,
					     mxfs_dlm_join_prepare,
					     mxfs_dlm_join_commit, mp);

	/*
	 * register the inode-eviction-ring consumer (design review Part 1).
	 * The disklock heartbeat monitor invokes this for each inode a peer
	 * reports freeing, so we can invalidate a stale NL-cached copy.
	 */
	mxfs_v5_dlm_set_evict_cb(mp->m_mxfs_dlm,
				   mxfs_dlm_evict_inode_cb, mp);

	/*
	 * (D-513): terminal recovery-refusal consumer.  The disklock
	 * monitor fires this once per imported (victim_epoch, publish_seq)
	 * outcome record so every survivor folds the refused victim domain
	 * into its quarantine map instead of timing out into shutdown.
	 */
	/*
	 * (design-consult ruling Q3): open the admission transaction BEFORE
	 * the consumer can fire.  Everything imported from here until
	 * mxfs_dlm_admission_commit() runs belongs to a mount that has not
	 * been admitted yet and can still be refused.
	 */
	spin_lock(&mp->m_mxfs_quar_lock);
	mp->m_mxfs_quar_admitting = true;
	spin_unlock(&mp->m_mxfs_quar_lock);

	mxfs_v5_dlm_set_quarantine_cb(mp->m_mxfs_dlm,
				      mxfs_dlm_quarantine_cb, mp);
	/* 0.85.0: the obligation freeze observer + its registration scan, so
	 * an OPEN case another node published is frozen here before this
	 * mount's first allocation. */
	mxfs_v5_dlm_set_obl_cb(mp->m_mxfs_dlm, mxfs_dlm_obl_cb, mp);

	/*
	 * (ruling item B): the AG-domain judgement the
	 * survivor-side out-of-closure scrub asks before force-revoking a
	 * quarantined victim's blocking CAW state.  Registered here because
	 * only this layer knows the inode->AG mapping (invariant 4).
	 */
	mxfs_v5_dlm_set_closure_classify_fn(mp->m_mxfs_dlm,
					    mxfs_dlm_closure_classify_cb, mp);

	/*
	 * (ruling part 1, second half): so that a blocking
	 * acquire the quarantine OVERTAKES is cancelled with the same error a
	 * fresh one gets, instead of waiting out the DLM timeout against a
	 * grant that can never be released.
	 */
	mxfs_v5_dlm_set_quar_covers_fn(mp->m_mxfs_dlm,
				       mxfs_dlm_quar_covers_cb, mp);

	/*
	 * (ruling item 4): the monitor only delivers outcomes
	 * it sees AFTER this registration — a record already on the platter
	 * (published before this mount, or already dedup'd by our own
	 * monitor's earlier pass) would never import and this node would time
	 * out into the incident-513 suicide.  Synchronously scan every slot's
	 * descriptor NOW, before any filesystem ops are exposed, and replay
	 * existing terminal verdicts into the quarantine map.
	 */
	mxfs_v5_dlm_recovery_scan_outcomes(mp->m_mxfs_dlm);

	/* Reset stats */
	atomic64_set(&mxfs_dlm_stat_cache_hit, 0);
	atomic64_set(&mxfs_dlm_stat_cache_miss, 0);
	atomic64_set(&mxfs_dlm_stat_bast_immediate, 0);
	atomic64_set(&mxfs_dlm_stat_bast_deferred, 0);
	atomic64_set(&mxfs_dlm_stat_bast_no_inode, 0);
	atomic64_set(&mxfs_dlm_stat_ag_acquire, 0);
	atomic64_set(&mxfs_dlm_stat_ag_nested, 0);
	atomic64_set(&mxfs_dlm_stat_ag_release, 0);
	mxfs_dlm_stat_last_report = 0;

	mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: DLM lock caching enabled");
}

/*
 * (design-consult ruling Q3) — THE ADMISSION TRANSITION.
 *
 * The mount admission barrier gates on m_mxfs_quar_fswide twice, but both
 * gates run inside xfs_mountfs, and the registration-time outcome scan runs
 * ~0.5 s LATER (measured) from mxfs_dlm_cache_init.  So an FSWIDE quarantine
 * that only the scan discovers — precisely the late-mount case the scan was
 * built for — was never gated at all: measured, mount rc=0 with
 * fswide=1 imported, a zombie whose every operation fails with EIO.
 *
 * This closes the window at the other end.  It runs after every synchronous
 * registration-phase import has happened, flips ADMITTING -> ADMITTED under
 * the import lock so no import can slip between the test and the decision,
 * and refuses the mount if the filesystem is known unusable.  A quarantine
 * that arrives after this point meets an admitted mount and is handled the
 * only way it still can be: runtime EIO.
 *
 * Returns 0 to admit, -EIO to refuse.  On refusal the caller must unwind
 * through the post-cache_init path, which unregisters the DLM consumer and
 * drains the workers before the mount is freed.
 */
int
mxfs_dlm_admission_commit(
	struct xfs_mount	*mp)
{
	bool			fswide;
	uint64_t		ag_mask;

	if (!mp)
		return 0;

	spin_lock(&mp->m_mxfs_quar_lock);
	fswide = mp->m_mxfs_quar_fswide;
	ag_mask = mp->m_mxfs_quar_ag_mask;
	mp->m_mxfs_quar_admitting = false;
	spin_unlock(&mp->m_mxfs_quar_lock);

	if (fswide) {
		xfs_alert(mp,
			"MXFS mount ABORTED at admission: a terminal recovery "
			"refusal quarantines the WHOLE filesystem (found "
			"during DLM registration, after the recovery "
			"barrier) — every operation this mount could admit "
			"would fail with EIO.  Repair the refused slice "
			"targets, clear the outcome record, and remount");
		return -EIO;
	}
	if (ag_mask)
		xfs_alert(mp,
			"MXFS mount ADMITTED with AG mask 0x%llx quarantined "
			"by a terminal recovery refusal — operations touching "
			"those AGs fail with EIO until operator repair",
			(unsigned long long)ag_mask);
	return 0;
}
