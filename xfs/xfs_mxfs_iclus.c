// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode-cluster locks
 */
#define MXFS_TU_ID 35	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

static int mxfs_iclus_make_durable(struct xfs_mount *mp, uint64_t base, struct mxfs_release_cert *cert);
static void mxfs_iclus_defer_worker(struct work_struct *work);

/*
 * step-6 F1 (ruling): deferral enforcement knob — see the
 * header comment.  0444: load-time only, immutable once mounted so the
 * admission predicate cannot flip under a live defer episode.
 */
int mxfs_release_proof_enforce = 1;
EXPORT_SYMBOL(mxfs_release_proof_enforce);
module_param_named(release_proof_enforce, mxfs_release_proof_enforce, int, 0444);
MODULE_PARM_DESC(release_proof_enforce,
                 "defer ICLUS release CAS while the completion proof is "
                 "incomplete; bounded no-progress wedges the cluster "
                 "(1=enforce default, 0=telemetry-only baseline; load-time)");

static DEFINE_SPINLOCK(mxfs_iclus_glock);
static struct hlist_head mxfs_iclus_hash[MXFS_ICLUS_HASH_SIZE];

/*
 * step-6 admission predicate: may work be admitted under this
 * cluster's grant?  Under enforcement, DEMOTING (a deferred release is
 * owed) and WEDGED (unprovable release, grant pinned) close admission;
 * every other state admits (the transient DRAINING/PROVED/RELEASING
 * states only ever coexist with ic->busy, which the fast paths already
 * refuse).  Knob off = always open, the true pre-step-6 baseline.
 */
static inline bool mxfs_iclus_admission_open(struct mxfs_iclus *ic)
{
	uint8_t rs;

	if (!mxfs_release_proof_enforce)
		return true;
	rs = READ_ONCE(ic->rel_state);
	return rs != MXFS_RELSTATE_DEMOTING && rs != MXFS_RELSTATE_WEDGED;
}

/*
 * Close the release bookkeeping after a CONFIRMED disk clear (CAS rc 0).
 * Caller holds ic->lock.  release_epoch++ is the ABA guard the ruling
 * requires: any worker or waiter that captured state before this instant
 * belongs to a finished episode and must no-op.
 */
static inline void mxfs_iclus_release_done_locked(struct mxfs_iclus *ic)
{
	ic->disk_mode = MXFS_LOCK_NL;
	ic->auth_epoch = 0;	/* tenure over */
	ic->auth_lineage = 0;	/* cleared with the epoch */
	ic->bast_pending = false;
	ic->release_epoch++;
	ic->defer_started_j = 0;
	ic->defer_badness = 0;
	ic->defer_tries = 0;
	if (READ_ONCE(ic->rel_state) != MXFS_RELSTATE_WEDGED)
		WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_ACTIVE);
}

static inline uint64_t mxfs_iclus_base(struct xfs_mount *mp, uint64_t ino)
{
	return ino & ~((uint64_t)M_IGEO(mp)->inodes_per_cluster - 1);
}

static inline unsigned int mxfs_iclus_hashfn(uint64_t base)
{
	return hash_64(base, MXFS_ICLUS_HASH_BITS);
}

static struct mxfs_iclus *
mxfs_iclus_get(struct xfs_mount *mp, uint64_t base, bool create)
{
	unsigned int h = mxfs_iclus_hashfn(base);
	struct mxfs_iclus *ic, *nic = NULL;

again:
	spin_lock(&mxfs_iclus_glock);
	hlist_for_each_entry(ic, &mxfs_iclus_hash[h], hnode) {
		if (ic->mp == mp && ic->base == base) {
			spin_unlock(&mxfs_iclus_glock);
			kfree(nic);
			return ic;
		}
	}
	if (nic) {
		hlist_add_head(&nic->hnode, &mxfs_iclus_hash[h]);
		spin_unlock(&mxfs_iclus_glock);
		return nic;
	}
	spin_unlock(&mxfs_iclus_glock);
	if (!create)
		return NULL;
	nic = kzalloc(sizeof(*nic), GFP_NOFS);
	if (!nic)
		return NULL;
	nic->mp = mp;
	nic->base = base;
	spin_lock_init(&nic->lock);
	init_waitqueue_head(&nic->wq);
	INIT_DELAYED_WORK(&nic->dwork, mxfs_iclus_defer_worker);
	goto again;
}

/*
 * The release-decision sweep: true if any covered IN-CORE inode other than
 * skip_ino holds a granted mode or has a slow-path acquire in flight.
 * skip_ino exempts the caller performing its own release (the evict path
 * releases BEFORE setting its mode NL).  Pure-memory: INCORE igets only.
 */
/*
 * step 6: granted_only=true is the DEFER-WORKER's variant — it
 * ignores i_dlm_acq_inflight, counting only granted modes.  Sound at that
 * call site alone: admission is closed (DEMOTING), so an inflight marker
 * there can only be a PARKED slow acquirer waiting for this very release —
 * counting it would deadlock the retry against its own waiters (the ruling's
 * flagged drain-deadlock hazard).  No fast-admit window can be open at
 * deferral time (the strict sweep ran under ic->busy before disk_release)
 * and DEMOTING blocks new grant stamps, so granted-only loses no coverage.
 * Every other caller MUST pass false.
 */
static bool
mxfs_iclus_covered_active(struct xfs_mount *mp, uint64_t base,
			  uint64_t skip_ino, bool granted_only)
{
	unsigned int ipc = M_IGEO(mp)->inodes_per_cluster;
	uint64_t ino;

	for (ino = base; ino < base + ipc; ino++) {
		struct xfs_inode *ip = NULL;
		bool active;

		if (ino == skip_ino)
			continue;
		if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip) || !ip)
			continue;
		/* ROUTED inodes only: a covered DIRECTORY (e.g. the root dir
		 * and the test's shared dir both live in cluster base 128)
		 * holds its grant on its PER-INODE resource, not this
		 * cluster — counting it here deadlocks the release against a
		 * grant that this resource does not cover (proven: rm's
		 * PR->EX upgrade EDEADLK-livelocked 65 laps into a shutdown
		 * because dir 131's ever-present per-inode EX kept the sweep
		 * dirty forever). */
		spin_lock(&ip->i_dlm_lock);
		/* Sticky-bit truth: count grants BACKED BY this cluster
		 * (acq_inflight covers a routed acquire mid-flight before
		 * the stamp lands).
		 * history: a widening that ALSO counted covered REG
		 * inodes on mode-0-era LOCAL grants (cc `cwr` empty-md5
		 * autopsy) was REVERTED — it serialized every cluster
		 * handoff behind local-grant demote pipelines (drc 19→7
		 * rounds, crash over budget) and starved the -EDEADLK
		 * selfclear.  The cwr hole is instead closed at its source:
		 * the open-protect fast path refuses non-cluster-backed
		 * grants (every open converts), so a dirty local-grant
		 * covered file cannot exist — data arrives via write(fd)
		 * and the fd's open converted.  Never-opened local-grant
		 * inodes are metadata-only; their dinode bytes ride the
		 * cluster buffers make_durable drains. */
		active = (ip->i_dlm_routed_iclus &&
			  ip->i_dlm_mode != MXFS_LOCK_NL) ||
			 (!granted_only && mxfs_iclus_routed(ip) &&
			  ip->i_dlm_acq_inflight != 0);
		spin_unlock(&ip->i_dlm_lock);
		xfs_irele(ip);
		if (active)
			return true;
	}
	return false;
}

/*
 * Arm the existing per-inode BAST machinery on every covered in-core inode
 * that still holds a granted mode.  mxfs_dlm_bast_notify dedups via the
 * per-inode bast_pending/state flags; absent and NL inodes are SKIPPED —
 * their per-inode no-slot recovery paths issue per-inode DEVICE ops that do
 * not exist under cluster granularity (and would cost a slot walk each).
 */
static void
mxfs_iclus_fan_out(struct xfs_mount *mp, uint64_t base, uint8_t req_mode)
{
	unsigned int ipc = M_IGEO(mp)->inodes_per_cluster;
	uint64_t ino;

	for (ino = base; ino < base + ipc; ino++) {
		struct xfs_inode *ip = NULL;
		bool granted;

		if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip) || !ip)
			continue;
		/* ROUTED inodes only — a covered dir's per-inode grant is not
		 * this cluster's business; BASTing it from here thrashed the
		 * shared dir's EX once per EDEADLK lap (P-DIRBAST storm).
		 * (a local-grant widening here was reverted with the
		 * covered_active one — see that comment; opens now convert,
		 * so local grants are metadata-only.) */
		spin_lock(&ip->i_dlm_lock);
		granted = ip->i_dlm_routed_iclus &&
			  ip->i_dlm_mode != MXFS_LOCK_NL;
		spin_unlock(&ip->i_dlm_lock);
		xfs_irele(ip);
		if (granted)
			mxfs_dlm_bast_notify(mp, ino, req_mode);
	}
}

/*
 * ADMISSION GATE (design review soundness requirement for routed open
 * tracking): may a new protected activity (open/mmap) become usable under
 * this inode's CLUSTER grant right now?  Refused while a release sweep or
 * any slow-path transition is in flight (ic->busy) or the cluster's disk
 * grant is gone — the caller then takes the acquiring slow path, which
 * waits out the transition and lands a fresh grant.  ic->lock on both
 * sides gives the sweep-sees-our-count ordering (see mxfs_dlm_open_protect).
 */
bool
mxfs_iclus_open_admit(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, mxfs_iclus_base(mp, ino),
					       false);
	bool ok;

	/* matrix `basic` split-brain autopsy: for a COVERED inode
	 * (the only callers), ONLY a live CLUSTER grant is cross-node
	 * protection.  A mode-0-era per-inode-LOCAL grant (fresh create:
	 * unpublished, no disk slot) satisfies the caller's i_dlm_mode
	 * check, but a peer's routed rm acquires the CLUSTER resource —
	 * which nobody holds — and frees with no BAST, no release sweep,
	 * no bit (P19-B3DEC will_skip=0 on B with zero A-side interaction).
	 * No ic object ⇒ no cluster grant ⇒ REFUSE the fast path; the slow
	 * path's ilock ride routes the acquire (mxfs_iclus_lock), converts
	 * the local grant (conv_pi), and lands real coverage. */
	if (!ic)
		return false;
	spin_lock(&ic->lock);
	ok = !ic->busy && ic->disk_mode != MXFS_LOCK_NL &&
	     mxfs_iclus_admission_open(ic);
	spin_unlock(&ic->lock);
	return ok;
}

/*
 * RELEASE-PUBLICATION SWEEP (design review C9 ordering applied to iclus):
 * before the cluster resource's on-disk release CAS may be issued, every
 * covered ROUTED inode with protected activity must have its per-inode
 * open-holder bit DURABLY on disk (publication-before-release).  Runs under
 * ic->busy (the admission gate), after the covered-active check — so no
 * covered inode holds an active grant and no new open can become usable
 * until the release completes or aborts.  Each CAW is synchronous, so
 * "wait for all SET completions before the release CAW" holds by
 * construction.  ANY failure gates the release: the caller keeps
 * disk_mode/bast_pending and the existing release_check retry machinery
 * re-runs the sweep later (idempotent re-SETs are benign).
 *
 * The sweep also performs the C4-equivalent lazy CLEAR for covered inodes
 * whose published bit no longer protects anything (best-effort, safe
 * direction — a failed clear only delays a peer's deferred reap).
 */
static int
mxfs_iclus_publish_open_bits(struct xfs_mount *mp, uint64_t base)
{
	extern unsigned int mxfs_open_tracking;
	unsigned int ipc = M_IGEO(mp)->inodes_per_cluster;
	uint64_t ino;
	int rc = 0;

	if (!mxfs_open_tracking || !mp->m_mxfs_dlm)
		return 0;
	/*
	 * The census must name the reason it names.  Folding this into the
	 * test above would report every skip as a membership fast path,
	 * including the ones caused by open tracking simply being switched
	 * off -- and on this rig it usually is, so the site would have looked
	 * like the busiest sole-survivor skip in the tree while measuring the
	 * knob instead.
	 */
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		MXFS_SOLE_SKIP_NOTE(mp->m_mxfs_dlm, "iclus_publish_open_bits");
		return 0;
	}
	for (ino = base; ino < base + ipc; ino++) {
		struct xfs_inode *ip = NULL;
		bool prot, do_set = false, do_clear = false;

		if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip) || !ip)
			continue;
		if (!mxfs_iclus_routed(ip)) {
			/* dirs keep the per-inode C1 fold; non-routed regs
			 * (single-node era) have no cluster obligation */
			xfs_irele(ip);
			continue;
		}
		spin_lock(&ip->i_dlm_lock);
		prot = atomic_read(&ip->i_mxfs_open_n) > 0 ||
		       mapping_mapped(VFS_I(ip)->i_mapping);
		if (prot && !ip->i_mxfs_open_pub && !ip->i_mxfs_open_setting) {
			ip->i_mxfs_open_setting = true;
			do_set = true;
		} else if (!prot && ip->i_mxfs_open_pub &&
			   !ip->i_mxfs_open_setting) {
			do_clear = true;
		}
		spin_unlock(&ip->i_dlm_lock);
		if (do_set) {
			int src = mxfs_v5_dlm_inode_open_set(mp->m_mxfs_dlm,
							     ip->i_ino);

			spin_lock(&ip->i_dlm_lock);
			ip->i_mxfs_open_setting = false;
			if (src == 0) {
				ip->i_mxfs_open_pub = true;
				/* close-during-SETTING (design review): activity may
				 * have reached zero while our SET was in
				 * flight and C4 skipped its clear — recheck
				 * and clear here so no stale bit outlives
				 * the race. */
				prot = atomic_read(&ip->i_mxfs_open_n) > 0 ||
				       mapping_mapped(VFS_I(ip)->i_mapping);
				spin_unlock(&ip->i_dlm_lock);
				mxfs_probe_ratelimited(
				    "mxfs: P-ICLUS-OPENSET ino=%llu base=%llu opens=%d mapped=%d — routed open bit published pre-release\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)base,
				    atomic_read(&ip->i_mxfs_open_n),
				    mapping_mapped(VFS_I(ip)->i_mapping) ? 1 : 0);
				if (!prot) {
					mxfs_v5_dlm_inode_open_clear(
						mp->m_mxfs_dlm, ip->i_ino);
					spin_lock(&ip->i_dlm_lock);
					ip->i_mxfs_open_pub = false;
					spin_unlock(&ip->i_dlm_lock);
				}
			} else {
				spin_unlock(&ip->i_dlm_lock);
				mxfs_probe_ratelimited(
				    "mxfs: P-ICLUS-OPENSET-FAIL ino=%llu base=%llu rc=%d — release GATED (grant retained for retry)\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)base, src);
				rc = src;
			}
		} else if (do_clear) {
			mxfs_v5_dlm_inode_open_clear(mp->m_mxfs_dlm,
						     ip->i_ino);
			spin_lock(&ip->i_dlm_lock);
			if (!ip->i_mxfs_open_setting)
				ip->i_mxfs_open_pub = false;
			spin_unlock(&ip->i_dlm_lock);
		}
		xfs_irele(ip);
		if (rc)
			break;	/* fail closed — gate the release NOW */
	}
	return rc;
}

/*
 * step-6 WEDGE (ruling item 5): the bounded end of a defer
 * episode that made no progress.  One-shot per cluster: pin the wedged
 * grant on the DLM side so the unconditional teardown release_all cannot
 * strip our bits without proof (peers then refuse our clean departure and
 * their death-detection/recovery machinery fences and recovers us), close
 * admission permanently (WEDGED), and force-shutdown the mount — skipped
 * under teardown (no_retry), where the mount is already going away.
 * NEVER CASes.  Waiters wake and observe WEDGED → terminal -EIO.
 */
static int
mxfs_iclus_wedge(struct xfs_mount *mp, struct mxfs_iclus *ic,
		 struct mxfs_release_cert *cert)
{
	bool shoot = false, teardown;

	spin_lock(&ic->lock);
	WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_WEDGED);
	teardown = ic->no_retry;
	if (!ic->wedge_shot) {
		ic->wedge_shot = true;
		shoot = true;
	}
	spin_unlock(&ic->lock);
	if (shoot) {
		/* 0286: capture the pin rc — on TCP the pin is unsupported
		 * (-EOPNOTSUPP), so the teardown arm must fall back to the
		 * shutdown fence exactly like mxfs_inode_wedge does; a
		 * teardown that neither pins nor shuts down hands the
		 * unproven grant to release_all. */
		int pin_rc = mxfs_v5_dlm_iclus_pin(mp->m_mxfs_dlm, ic->base);

		cert->cas_attempted = 0;
		cert->defer_kind = MXFS_RELDEFER_WEDGE;
		cert->defer_reason = "no-progress bound exceeded";
		mxfs_release_cert_emit(cert);
		pr_err("mxfs: P-ICLUS-WEDGE base=%llu tries=%u oblig=%u pf=%u trip=%u pin_rc=%d — release unprovable within bounds; grant PINNED on disk, admission closed%s\n",
		       (unsigned long long)ic->base, ic->defer_tries,
		       cert->oblig_cas, cert->proof_failed, cert->tripwire,
		       pin_rc,
		       teardown ? " (teardown: departure will not be clean)" :
				  "; forcing shutdown");
		if (!teardown || pin_rc)
			xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
	}
	wake_up_all(&ic->wq);
	return -EIO;
}

/*
 * step-6 DEFER (ruling items 1/3/5): the release proof did
 * not complete — record the deferral on the certificate (cas_attempted=0),
 * enter/extend the episode, and arm the per-cluster retry worker with
 * exponential backoff + jitter.  Progress = badness DECREASE (a cause
 * retired); mere retries, new BASTs and repeated failures are not
 * progress.  Bounds: 60s without progress or 300s total → wedge.
 * Returns -EAGAIN (defer) or -EIO (wedged); callers keep
 * disk_mode/bast_pending on any nonzero rc, exactly as for a failed CAS.
 */
/*
 * Enter/extend the defer episode and arm the retry worker (both under
 * ic->lock — the queue-under-lock pairs with purge_all's no_retry-then-
 * cancel_sync teardown order so no retry can be queued after the latch).
 * Returns true when the bounds expired and the caller must WEDGE instead.
 */
static bool
mxfs_iclus_defer_arm(struct xfs_mount *mp, struct mxfs_iclus *ic,
		     unsigned int badness)
{
	bool wedge = false;

	spin_lock(&ic->lock);
	WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_DEMOTING);
	if (!ic->defer_started_j) {
		ic->defer_started_j = jiffies ?: 1;
		ic->last_progress_j = jiffies;
		ic->defer_badness = badness;
	} else {
		if (badness < ic->defer_badness) {
			ic->last_progress_j = jiffies;
			ic->defer_badness = badness;
		}
		if (time_after(jiffies, ic->last_progress_j + 60 * HZ) ||
		    time_after(jiffies, ic->defer_started_j + 300 * HZ))
			wedge = true;
	}
	if (!wedge) {
		unsigned int tries = ic->defer_tries++;

		if (!ic->no_retry) {
			unsigned int ms = min(25u << min(tries, 5u), 1000u);

			ms += get_random_u32_below(ms / 4 + 1);
			queue_delayed_work(mp->m_mxfs_inode_bast_wq,
					   &ic->dwork,
					   msecs_to_jiffies(ms));
		}
	}
	spin_unlock(&ic->lock);
	return wedge;
}

static int
mxfs_iclus_release_defer(struct xfs_mount *mp, struct mxfs_iclus *ic,
			 struct mxfs_release_cert *cert, bool pub_fail)
{
	unsigned int badness = (pub_fail ? 8 : 0) +
			       (cert->oblig_cas ? 4 : 0) +
			       (cert->proof_failed ? 2 : 0) +
			       (cert->tripwire ? 1 : 0);

	if (mxfs_iclus_defer_arm(mp, ic, badness))
		return mxfs_iclus_wedge(mp, ic, cert);
	cert->cas_attempted = 0;
	if (!cert->defer_kind) {
		if (cert->oblig_cas)
			cert->defer_kind = MXFS_RELDEFER_OBLIG;
		else if (cert->proof_failed)
			cert->defer_kind = MXFS_RELDEFER_FLUSH;
		else
			cert->defer_kind = MXFS_RELDEFER_IO;
	}
	if (!cert->defer_reason)
		cert->defer_reason = "proof incomplete, release deferred";
	mxfs_release_cert_emit(cert);
	return -EAGAIN;
}

/*
 * THE choke point for the on-disk ICLUSTER release.  Every path
 * that drops the cluster's disk grant comes through here — normal last-ref
 * release, BAST-notify immediate release, the -EDEADLK stale-self-hold
 * escape, the defer worker, and teardown — so
 * publication-before-release holds globally (design review invariant 2:
 * no cluster grant reaches NL while a required open-bit SET is pending or
 * failed).  A publish failure returns without touching the disk grant; the
 * caller's existing CAS-failure arm keeps disk_mode/bast_pending for retry.
 *
 * step 6: `ic` is passed by the caller (every caller holds it and
 * ic->busy) — the old internal lookup raced teardown's unhash, and the
 * defer gate must never silently disengage because a lookup missed.
 * Under mxfs_release_proof_enforce an incomplete proof DEFERS (-EAGAIN,
 * worker armed) instead of CASing, and a WEDGED cluster refuses instantly.
 */
static int
mxfs_iclus_disk_release(struct xfs_mount *mp, struct mxfs_iclus *ic,
			uint64_t base, bool is_free)
{
	struct mxfs_release_cert cert = {
		.res_id = base,
		.rclass = MXFS_RELCLASS_ICLUS,
		.path = "iclus_disk_release",
	};
	uint64_t t0;
	int rc;

	if (ic && mxfs_release_proof_enforce &&
	    READ_ONCE(ic->rel_state) == MXFS_RELSTATE_WEDGED)
		return -EIO;
	if (ic) {
		spin_lock(&ic->lock);
		cert.old_epoch = ic->auth_epoch;
		WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_DEMOTING);
		spin_unlock(&ic->lock);
	}
	rc = mxfs_iclus_publish_open_bits(mp, base);
	if (rc) {
		/* Publish failure gates the release (caller retries) — a
		 * deferral for an outstanding obligation, not a CAS.  State
		 * stays DEMOTING: requested, unproven, grant retained. */
		cert.defer_kind = MXFS_RELDEFER_OBLIG;
		cert.defer_reason = "open-bit publish failed";
		if (mxfs_release_proof_enforce && ic) {
			int drc = mxfs_iclus_release_defer(mp, ic, &cert,
							   true);
			return drc == -EIO ? drc : rc;
		}
		mxfs_release_cert_emit(&cert);
		return rc;
	}
	mxfs_relgate_fault(MXFS_RGF_DEMOTING, base);
	if (ic)
		WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_DRAINING);
	t0 = ktime_get_ns();
	/*
	 * step 2 records, step 6 will enforce: a timed-out settle means the
	 * cluster buffer is STILL DIRTY at the CAS below — one unretired
	 * obligation (the F1 finding).  The release proceeds unchanged this
	 * step; the certificate makes every occurrence countable.
	 */
	cert.oblig_cas = mxfs_iclus_make_durable(mp, base, &cert);
	cert.timeout = cert.oblig_cas;
	cert.drain_ns = ktime_get_ns() - t0;
	/*
	 * A tenure-boundary flush covering the settled writes is required
	 * unless the operator declared the target-cache-loss domain out of
	 * scope (F2 finding — counted as cas_noticket, never printed
	 * per-release).  Completion comes from the proof's ticket status
	 * REAL_FLUSH = a real flush verified over the keyed
	 * accounting; PROTECTED = operator-declared domain.
	 */
	cert.ticket_required = 1;
	cert.ticket_completed =
		cert.ticket_status == MXFS_TICKET_REAL_FLUSH ||
		cert.ticket_status == MXFS_TICKET_PROTECTED;
	/* a clean settle plus a clean keyed completion proof IS this path's
	 * proof; a timed-out settle or a failed proof goes to CAS unproved
	 * and P283/cas_noproof_v2 names it (F1/F3, same events cas_dirty
	 * and proof_failed count).  cert.proved is the per-instance
	 * attestation; ic->rel_state is diagnostic. */
	if (!cert.oblig_cas && !cert.proof_failed) {
		cert.proved = 1;
		if (ic)
			WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_PROVED);
	}
	/*
	 * Final pre-CAS tripwire (ruling item B): re-sample the
	 * keyed accounting captured by the proof.  Any movement — a write
	 * submitted or completed after the verified flush — invalidates the
	 * certificate: mark tripwire, drop back to DRAINING so the CAS
	 * counts as unproved (telemetry while the gate is off).
	 */
	if (cert.icwr_daddr) {
		struct mxfs_icwr_entry *twent =
			mxfs_icwr_get(mp, (xfs_daddr_t)cert.icwr_daddr, false);

		if (twent &&
		    ((uint32_t)atomic_read(&twent->ie_inflight) !=
		     cert.icwr_inflight_final ||
		     (uint64_t)atomic64_read(&twent->ie_complete_gen) !=
		     cert.icwr_gen_final)) {
			cert.tripwire = 1;
			/* tripwire invalidates THIS instance's
			 * attestation too, not just the diagnostic state */
			cert.proved = 0;
			if (ic)
				WRITE_ONCE(ic->rel_state,
					   MXFS_RELSTATE_DRAINING);
		}
	}
	/*
	 * step-6 F1 ENFORCEMENT GATE (ruling item 1): an
	 * incomplete proof — still-dirty settle (oblig_cas), failed keyed
	 * completion proof, or a tripped pre-CAS re-sample — DEFERS the
	 * release instead of CASing.  The F2-only ticket-absent case
	 * (NO_DOMAIN under fua_disable=1) is a domain policy, step 7 —
	 * it does NOT defer here.
	 */
	if (mxfs_release_proof_enforce && ic &&
	    (cert.oblig_cas || cert.proof_failed || cert.tripwire))
		return mxfs_iclus_release_defer(mp, ic, &cert, false);
	/*
	 * (design-consult ruling): the CLUSTER clean-release certificate.
	 * The closing barrier was raised before the proof (DEMOTING at the
	 * top closes admission under enforcement; ic->busy excludes the fast
	 * paths), the keyed proof and F4 census passed, so the tenure's last
	 * durable state is home.  Irrevocability FIRST (a grant image offering
	 * this {lineage, epoch} is refused as authority from here on, whether
	 * or not the publish below succeeds — an ambiguous log outcome is
	 * "possibly marked"), then the sync-committed marker under the SAME
	 * identity the routed inodes' tokens carry: class INODE, resource =
	 * cluster base, lineage, epoch.  Non-alias invariant: lineage is a
	 * per-slot 64-bit random mint (caw_mint_lineage), and the ICLUSTER
	 * resource and any per-inode resource at ino == base are distinct
	 * slots with distinct lineages, so the full tuple identifies exactly
	 * one tenure.  A publish failure proceeds counted: replay then
	 * REFUSES this tenure's records (fail-closed), never certifies them.
	 */
	if (ic && mxfs_release_proof_enforce) {
		uint64_t m_ep, m_lin;
		bool mark_fail;

		mxfs_relgate_fault(MXFS_RGF_PRE_MARK, base);
		mark_fail = mxfs_relgate_fault_forced(MXFS_RGF_MARK_PUBLISH,
						      base);
		spin_lock(&ic->lock);
		m_ep = ic->auth_epoch;
		m_lin = ic->auth_lineage;
		if (m_ep && m_lin) {
			ic->relmark_epoch = m_ep;
			ic->relmark_lineage = m_lin;
		}
		spin_unlock(&ic->lock);
		if (m_ep && m_lin) {
			int mrc = mark_fail ? -EIO :
				mxfs_relmark_publish(mp, MXFS_AUTH_CLASS_INODE,
						     base, m_lin, m_ep,
						     "iclus_disk_release");

			if (mrc == 0) {
				atomic64_inc(&mxfs_relmark_iclus_marked);
			} else if (mrc != -ENOENT) {
				static atomic_t p_n = ATOMIC_INIT(0);

				atomic64_inc(&mxfs_relmark_iclus_failed);
				if (atomic_inc_return(&p_n) <= 2000)
					pr_warn("mxfs: P-RELMARK-ICLUS-UNMARKED base=%llu gepoch=%llu rc=%d — releasing WITHOUT a clean-release marker; this cluster tenure's records will refuse at foreign replay\n",
						(unsigned long long)base,
						(unsigned long long)m_ep, mrc);
			}
		} else if (m_ep) {
			/* proving epoch without a lineage: legacy binding,
			 * cannot be certified (tokens non-lineage-bearing) */
			atomic64_inc(&mxfs_relmark_iclus_unmarked);
		}
		/* marker durable (or refused), before the CAS; force models a
		 * transport-failed CAS: the failed-CAS arm below must keep the
		 * episode (no admission reopen) and the tuple stays marked */
		if (mxfs_relgate_fault_forced(MXFS_RGF_POST_MARK, base)) {
			cert.cas_attempted = 1;
			cert.cas_result = -EIO;
			cert.rel_state_cas = READ_ONCE(ic->rel_state);
			mxfs_release_cert_emit(&cert);
			if (mxfs_iclus_defer_arm(mp, ic, 16))
				return mxfs_iclus_wedge(mp, ic, &cert);
			return -EIO;
		}
	}
	cert.cas_attempted = 1;
	cert.rel_state_cas = ic ? READ_ONCE(ic->rel_state) :
				  MXFS_RELSTATE_DRAINING;
	if (ic)
		WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_RELEASING);
	mxfs_relgate_fault(MXFS_RGF_PRE_CAS, base);
	rc = mxfs_v5_dlm_iclus_unlock_gen(mp->m_mxfs_dlm, base, 0, is_free);
	cert.cas_result = rc;
	mxfs_relgate_fault(MXFS_RGF_POST_HANDOFF, base);
	mxfs_release_cert_emit(&cert);
	if (ic && mxfs_release_proof_enforce && rc) {
		/*
		 * a failed CAS under enforcement must NOT reopen
		 * admission — the granted-only worker sweep is only sound
		 * while DEMOTING blocks new grant stamps for the whole
		 * episode, so a transport-failed CAS stays in the episode
		 * (badness 16, worst class) and retries under the same
		 * bounds instead of falling back to open-admission bast
		 * machinery.
		 */
		if (mxfs_iclus_defer_arm(mp, ic, 16))
			return mxfs_iclus_wedge(mp, ic, &cert);
	} else if (ic)
		WRITE_ONCE(ic->rel_state, MXFS_RELSTATE_ACTIVE);
	return rc;
}

/*
 * Acquire coverage for `ino` at `mode`.  Fast path: the cluster's on-disk
 * grant already covers the mode -> pure-memory admit.  Slow path: one v5
 * ICLUSTER acquire (or PR->EX upgrade) for the WHOLE cluster; ic->busy
 * serializes against concurrent slow acquirers and release sweeps.
 * -EDEADLK (cross-node upgrade standoff) marks a self-BAST so the caller's
 * existing demote pipeline (drain + release_check) drops our cluster grant
 * and the retry re-acquires from NL.
 */
/*
 * step 5.3(d): describe the cluster tenure ic is holding RIGHT NOW,
 * for the caller to install as this inode's durable authority.
 *
 * Must be called with ic->lock held — that is the whole point.  The pair
 * (disk_mode, auth_epoch) is only meaningful when read atomically: they are
 * set together by the granting CAS's critical section and cleared together
 * by the release's, so a torn read could pair a live mode with a dead epoch.
 *
 * Fail-closed rules, all of which leave gres non-proving:
 *   - mode below EX: a PR cluster grant authorises nothing;
 *   - auth_epoch == 0: either a PR-era claim, a tombstone-restarted epoch
 *     namespace (caw_grant_result_fill refuses those), or a release already
 *     cleared it.
 */
static void
mxfs_iclus_auth_snapshot_locked(struct mxfs_iclus *ic,
				struct mxfs_grant_result *gres, bool fresh)
{
	if (!gres)
		return;
	mxfs_grant_result_init(gres);
	/*
	 * classify at construction, and through the ONE mode helper.
	 * This site used `< MXFS_LOCK_PW` while the CAW site used exact
	 * EX||PW; they agree only by enum accident.  A cluster with no live
	 * grant at all is NO_RESOURCE, a read grant is NONWRITE_MODE, and a
	 * writing grant whose epoch is missing is the real gap.
	 */
	gres->mode = ic->disk_mode;
	gres->kind = MXFS_LTYPE_ICLUSTER;
	gres->resource = ic->base;
	if (ic->disk_mode == MXFS_LOCK_NL) {
		gres->status = MXFS_GAUTH_NO_RESOURCE;
		return;
	}
	if (!mxfs_mode_can_write(ic->disk_mode)) {
		gres->status = MXFS_GAUTH_NONWRITE_MODE;
		return;
	}
	if (ic->auth_epoch == 0) {
		gres->status = MXFS_GAUTH_WRITE_ZERO_EPOCH;
		return;
	}
	/* a tenure without a lineage cannot be certified (its
	 * tokens are non-lineage-bearing and refuse at replay) — report it
	 * as the same snapshot gap rather than a proving grant. */
	if (ic->auth_lineage == 0) {
		gres->status = MXFS_GAUTH_WRITE_ZERO_EPOCH;
		return;
	}
	/* irrevocability (ruling item 3): this ic's journal already
	 * certifies {lineage, epoch} as cleanly released (or the marker's
	 * outcome is ambiguous); never resurrect that tuple as authority. */
	if (ic->auth_epoch == ic->relmark_epoch &&
	    ic->auth_lineage == ic->relmark_lineage) {
		static atomic_t p_n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_relmark_iclus_reinstall_refused);
		if (atomic_inc_return(&p_n) <= 2000)
			pr_warn("mxfs: P-RELMARK-ICLUS-REINSTALL-REFUSED base=%llu gepoch=%llu lineage=%llx — tuple already marked clean-released by this node's journal; not resurrecting it as authority\n",
				(unsigned long long)ic->base,
				(unsigned long long)ic->auth_epoch,
				(unsigned long long)ic->auth_lineage);
		gres->status = MXFS_GAUTH_WRITE_ZERO_EPOCH;
		return;
	}
	gres->grant_epoch = ic->auth_epoch;
	gres->resource_lineage = ic->auth_lineage;
	gres->status = MXFS_GAUTH_WRITE_EPOCH;
	/*
	 * reaffirm=1 whenever the epoch was not minted by the CAS this very
	 * call issued — the fast-path admit runs no CAS at all, so it is
	 * always a re-affirmation of a tenure ic already held.  Kept honest
	 * rather than convenient: an installed tenure whose provenance is
	 * "already held" is a different evidence class from "just granted",
	 * and the ruling asked for the population.
	 */
	gres->reaffirm = fresh ? 0 : 1;
}

int
mxfs_iclus_lock(struct xfs_mount *mp, uint64_t ino, uint8_t mode,
		struct mxfs_grant_result *gres)
{
	uint64_t base = mxfs_iclus_base(mp, ino);
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, base, true);
	struct mxfs_grant_result lg;
	int rc;

	mxfs_grant_result_init(gres);	/* fail closed on every exit */
	if (!ic)
		return -ENOMEM;
	for (;;) {
		spin_lock(&ic->lock);
		/* step 6: a WEDGED cluster is terminal — its grant
		 * is pinned pending fence/recovery; admitting or acquiring
		 * under it would reopen the unproven tenure. */
		if (mxfs_release_proof_enforce &&
		    READ_ONCE(ic->rel_state) == MXFS_RELSTATE_WEDGED) {
			spin_unlock(&ic->lock);
			return -EIO;
		}
		if (ic->disk_mode >= mode && !ic->busy &&
		    mxfs_iclus_admission_open(ic)) {
			/* Pure-memory admit under a tenure this ic has held
			 * continuously since the CAS that stamped auth_epoch
			 * (see the struct comment).  Synthesising the result
			 * HERE, inside the same ic->lock section that proves
			 * disk_mode, is what makes it first-hand. */
			mxfs_iclus_auth_snapshot_locked(ic, gres, false);
			spin_unlock(&ic->lock);
			return 0;
		}
		if (ic->busy || !mxfs_iclus_admission_open(ic)) {
			spin_unlock(&ic->lock);
			/* Park until the transition/deferred release resolves
			 * (worker success reopens admission) or wedges (loop
			 * top returns -EIO).  The parked acquirer's
			 * i_dlm_acq_inflight cannot deadlock the worker: its
			 * sweep is granted-only. */
			wait_event(ic->wq, !READ_ONCE(ic->busy) &&
				   (mxfs_iclus_admission_open(ic) ||
				    READ_ONCE(ic->rel_state) ==
				    MXFS_RELSTATE_WEDGED));
			continue;
		}
		ic->busy = true;
		spin_unlock(&ic->lock);
		break;
	}

	rc = mxfs_v5_dlm_iclus_lock(mp->m_mxfs_dlm, base, mode, &lg);

	/* instrumented (phantom self-hold hunt): realns-stamped claim record
	 * for the watched cluster base, correlated with the host-side slot
	 * sampler.  Zero cost unless watch_ino is set to the base. */
	if (unlikely(mxfs_watch_ino && base == mxfs_watch_ino))
		mxfs_probe("mxfs: P-ICLUS-CLAIM base=%llu mode=%u rc=%d comm=%s realns=%llu\n",
			(unsigned long long)base, mode, rc, current->comm,
			(unsigned long long)ktime_get_real_ns());

	spin_lock(&ic->lock);
	if (rc == 0) {
		if (ic->disk_mode == MXFS_LOCK_NL)
			ic->grant_seq++;	/* fresh claim after a gap */
		ic->disk_mode = mode;
		/*
		 * Record the tenure this CAS established.  Only an EX-class
		 * grant carries one; a PR claim leaves auth_epoch 0 and the
		 * cluster stays non-proving until it upgrades.  lg is only
		 * proving when the CAS itself stamped the epoch.
		 *
		 * the "no proof" arm used `mode >= MXFS_LOCK_EX`,
		 * i.e. EX only, so a PW claim that failed to stamp kept
		 * whatever epoch was there.  Through the one write-mode
		 * helper both writing modes are held to the same standard;
		 * release zeroes auth_epoch (:44084, :44249), so a claim
		 * after a release starts from 0 either way.
		 */
		if (mxfs_grant_result_proving(&lg)) {
			ic->auth_epoch = lg.grant_epoch;
			/* the lineage of the SAME image (caw_grant_
			 * result_fill) — zero stays non-proving in the snapshot */
			ic->auth_lineage = lg.resource_lineage;
		} else if (mxfs_mode_can_write(mode)) {
			ic->auth_epoch = 0;	/* writing, no proof: honest */
			ic->auth_lineage = 0;
		}
		mxfs_iclus_auth_snapshot_locked(ic, gres,
				mxfs_grant_result_proving(&lg) && !lg.reaffirm);
	} else if (rc == -EDEADLK)
		ic->bast_pending = true;
	ic->busy = false;
	spin_unlock(&ic->lock);
	wake_up_all(&ic->wq);
	if (rc == -EDEADLK)
		/* Self-BAST must resolve like a PEER bast: drain the WHOLE
		 * cluster, not just the caller's inode.  PROVEN twice on
		 * 8-board (instrumented): the caller's P109 single-inode
		 * drain leaves sticky-covered SIBLINGS granted, so the
		 * release sweep stays dirty and the upgrade EDEADLKs
		 * forever — 65-lap livelock -> SHUTDOWN_CORRUPT_INCORE
		 * (bash ino=136 base=128 with create-claims; mv
		 * ino=8388760 base=8388736 WITHOUT them, plain publish-era
		 * stickies).  Local queued demotes only — no new blocking
		 * edge; the last covered release_check's clean sweep
		 * releases the disk grant and the caller's retry acquires
		 * fresh from NL. */
		mxfs_iclus_fan_out(mp, base, mode);
	/*
	 * — DIVERGED SELF-HOLD ESCAPE.  PROVEN at
	 * 32/cawd (cc NO_TERMINAL): a swallowed unlock-CAS failure left our
	 * EX bit on the disk slot while ic->disk_mode said NL.  The claim
	 * then self-EDEADLKs, but fan_out has NOTHING to arm (every covered
	 * inode is NL in this state) and release_check is gated on
	 * disk_mode > NL — so the stale bit had no clearer and 32 nodes
	 * starved 380s+ behind our live heartbeat ("DLM iclus lock failed
	 * rc=-35" x3 over 379s, test5 slot 8).  When the sweep confirms
	 * nothing covered is active, clear our stale bit directly (disk
	 * evidence outranks the lied-to disk_mode) so the caller's P109
	 * retry acquires fresh.  Busy-guarded; the sweep re-runs under busy
	 * so a racing fast-path admit is excluded.
	 */
	if (rc == -EDEADLK) {
		bool selfclear = false;

		spin_lock(&ic->lock);
		if (!ic->busy) {
			ic->busy = true;
			selfclear = true;
		}
		spin_unlock(&ic->lock);
		if (selfclear) {
			int urc = -EBUSY;

			/* SKIP THE ACQUIRING INODE.  The
			 * covered_active widening (local grants count, for
			 * release-drain correctness) starved this escape:
			 * the spinner's OWN mode-0-era local grant cannot
			 * demote while it holds the ILOCK, so covered_active
			 * stayed true, urc stayed -EBUSY, and the acquire
			 * exhausted into a 0x8 shutdown (test7/test29,
			 * load-63 burst).  Its grant is exactly what this
			 * acquire converts on success — never a reason to
			 * hold the escape hostage. */
			if (!mxfs_iclus_covered_active(mp, base, ino, false))
				urc = mxfs_iclus_disk_release(mp, ic, base,
							      false);
			spin_lock(&ic->lock);
			if (urc == 0)
				mxfs_iclus_release_done_locked(ic);
			ic->busy = false;
			spin_unlock(&ic->lock);
			wake_up_all(&ic->wq);
			mxfs_probe_ratelimited(
			    "mxfs: P-ICLUS-SELFCLEAR base=%llu want=%u urc=%d — stale self-hold %s\n",
				(unsigned long long)base, mode, urc,
				urc == 0 ? "cleared; retry will claim fresh" :
					   "NOT cleared (covered active or CAS fail)");
		}
	}
	return rc;
}

/*
 * ICLUSTER Invariant-1 analog (zero_silent_loss
 * root): no on-disk CLUSTER release until the cluster's in-place dinodes
 * are durable.  The per-inode release path guarantees this per inode via
 * the P146 durable loop — but a covered inode can be EVICTED before any
 * BAST (reclaim wrote its size update into the LOG only), leaving the
 * platter dinode stale (proven: node5_data1 mem_size=262144 disk_size=0,
 * every foreign reader read 0 bytes — the per-inode slot MIRROR used to
 * mask exactly this, and ICLUSTER resources have no mirror).  One
 * log-force + AIL settle of the cluster buffer + device flush per actual
 * cluster release — the batched-drain economics the design wants.
 * Runs under ic->busy (no concurrent admits), sleepable context.
 *
 * (step 2): returns 1 when the settle timed out with the cluster
 * buffer still dirty — the F1 invariant violation the certificate must
 * record — else 0.  Behavior is unchanged this step: the caller still
 * releases either way (the deferred-release worker is build-order step 6).
 *
 * (step 5 F3, ruling item B): the settle alone is
 * check-then-CAS — an async xfsaild destage between the dirty check and
 * the wire CAS could certify a proof no flush ever covered.  The proof is
 * now completion-driven against the cluster's OWN keyed write accounting
 * (mxfs_icwr_*): settle → keyed inflight 0 → capture generations → real
 * flush → verify inflight still 0 and generations UNCHANGED (plus a dirty
 * recheck for re-dirtied-not-yet-submitted state).  A generation change
 * gets ONE bounce with a fresh flush; any unprovable step sets
 * cert->proof_failed (telemetry release while the gate is off — the
 * release still proceeds, but never certifies PROVED).  TRYLOCK failure
 * in the settle is UNKNOWN, not clean (-EAGAIN vs -ENOENT — the
 * finding): bounded retry, then proof_failed.
 */
static int
mxfs_iclus_make_durable(struct xfs_mount *mp, uint64_t base,
			struct mxfs_release_cert *cert)
{
	extern int xfs_imap(struct xfs_perag *, struct xfs_trans *, xfs_ino_t,
			    struct xfs_imap *, uint);
	struct xfs_perag	*pag;
	struct xfs_imap		imap;
	struct mxfs_icwr_registry *reg = &mp->m_mxfs_icwr;
	struct mxfs_icwr_entry	*ent = NULL;
	uint64_t		sub_gen = 0, comp_gen = 0;
	xfs_daddr_t		daddr = 0;
	int			lap;
	int			bounce;
	int			still_dirty = 0;
	int			unknown = 0;
	int			proof_failed = 0;
	int			frc = 0;

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, base));
	if (!pag)
		return 0;
	/* CIL -> AIL: the covered dinodes' logged updates become pushable. */
	xfs_log_force(mp, XFS_LOG_SYNC);
	mxfs_relgate_fault(MXFS_RGF_LOGFORCED, base);
	memset(&imap, 0, sizeof(imap));
	if (xfs_imap(pag, NULL, base, &imap, 0) || !imap.im_len)
		goto out;
	daddr = imap.im_blkno;
	for (lap = 0; lap < 125; lap++) {
		struct xfs_buf		*bp = NULL;
		struct xfs_buf_log_item	*bip;
		bool			dirty;
		int			irc;

		/* PASSIVE settle by design (→5): an ACTIVE variant here
		 * (xfs_imap_to_bp blocking read + xfs_iflush_cluster + delwri
		 * submit inside release_check/bast_notify) produced a
		 * cross-node circular wait (D-state in caw_wait_for_grant
		 * while the same node held dir-EX with 7 waiters) — do not
		 * re-add it.  The settle is sound passively: logged dinodes
		 * pin the cluster buffer and sit on b_li_list until flushed,
		 * so the dirty check below sees them and xfsaild (kicked by
		 * ail_push_all) performs the actual iflush. */
		irc = xfs_buf_incore(mp->m_ddev_targp, imap.im_blkno,
				     imap.im_len, XBF_TRYLOCK, &bp);
		if (irc == -ENOENT || (!irc && !bp)) {
			unknown = 0;
			break;	/* not incore: settled (a write in flight is
				 * covered by the keyed proof below) */
		}
		if (irc) {
			/* -EAGAIN: the buffer exists but the trylock lost —
			 * its dirty state is UNKNOWN, which must never be
			 * read as clean (ruling hazard).  Bounded
			 * retry like a dirty lap. */
			unknown = 1;
			xfs_ail_push_all(mp->m_ail);
			if (lap == 124) {
				static atomic_t p_icu_n = ATOMIC_INIT(0);

				proof_failed = 1;
				if (atomic_inc_return(&p_icu_n) <= 200)
					mxfs_probe("mxfs: P289-ICLUS-SETTLE-UNKNOWN base=%llu daddr=%lld rc=%d — cluster buffer lock unavailable for 250ms; settle state unknowable, proof fails conservative\n",
						(unsigned long long)base,
						(long long)imap.im_blkno,
						irc);
			}
			msleep(2);
			continue;
		}
		unknown = 0;
		bip = bp->b_log_item;
		dirty = (bp->b_flags & (_XBF_DELWRI_Q | XBF_WRITE)) ||
			xfs_buf_ispinned(bp) ||
			(bip &&
			 (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
			  test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))) ||
			!list_empty_careful(&bp->b_li_list);
		if ((bp->b_flags & _XBF_DELWRI_Q) &&
		    (bp->b_flags & _XBF_MXFS_ALLOC_QUEUED)) {
			/* Trapped on the AG alloc-buflist: only the
			 * list-aware drain may submit it. */
			xfs_buf_relse(bp);
			mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
		} else {
			xfs_buf_relse(bp);
		}
		if (!dirty)
			break;
		xfs_ail_push_all(mp->m_ail);
		if (lap == 124) {
			static atomic_t p_icd_n = ATOMIC_INIT(0);

			still_dirty = 1;
			if (atomic_inc_return(&p_icd_n) <= 200)
				mxfs_probe("mxfs: P-ICLUS-DUR-TIMEOUT base=%llu daddr=%lld — cluster buffer still dirty after 250ms; releasing anyway (peer may read a lagging dinode)\n",
					(unsigned long long)base,
					(long long)imap.im_blkno);
		}
		msleep(2);
	}
out:
	xfs_perag_put(pag);
	if (!still_dirty && !unknown)
		mxfs_relgate_fault(MXFS_RGF_OBLIG_ZERO, base);
	/*
	 * Keyed completion proof (ruling item B).  The entry is
	 * looked up WITHOUT create: no entry means no counted home write has
	 * ever targeted this cluster since mount (entries are never freed),
	 * UNLESS the sticky untracked counter says an entry allocation
	 * failed — then an in-flight write may be invisible and the proof is
	 * poisoned conservative.
	 */
	if (daddr) {
		ent = mxfs_icwr_get(mp, daddr, false);
		if (!ent && atomic64_read(&reg->icwr_untracked) > 0)
			proof_failed = 1;
	}
	for (bounce = 0; bounce < 2; bounce++) {
		if (ent) {
			if (!wait_event_timeout(reg->icwr_wq,
					atomic_read(&ent->ie_inflight) == 0,
					msecs_to_jiffies(100))) {
				static atomic_t p_icw_n = ATOMIC_INIT(0);

				proof_failed = 1;
				if (atomic_inc_return(&p_icw_n) <= 200)
					mxfs_probe("mxfs: P289-ICLUS-INFLIGHT-TIMEOUT base=%llu daddr=%lld inflight=%d — counted cluster writes did not complete in 100ms; proof fails conservative\n",
						(unsigned long long)base,
						(long long)daddr,
						atomic_read(&ent->ie_inflight));
				/* still flush: the release proceeds and the
				 * settled portion deserves its barrier */
				frc = mxfs_blkdev_flush_epoch(mp);
				mxfs_relgate_fault(MXFS_RGF_FLUSH_DONE, base);
				break;
			}
			sub_gen = (uint64_t)atomic64_read(&ent->ie_submit_gen);
			comp_gen = (uint64_t)atomic64_read(&ent->ie_complete_gen);
		}
		frc = mxfs_blkdev_flush_epoch(mp);
		mxfs_relgate_fault(MXFS_RGF_FLUSH_DONE, base);
		if (!ent)
			break;
		/* Post-flush verify: nothing submitted or completed since
		 * the capture, so the flush covers every counted write. */
		if (atomic_read(&ent->ie_inflight) == 0 &&
		    (uint64_t)atomic64_read(&ent->ie_submit_gen) == sub_gen &&
		    (uint64_t)atomic64_read(&ent->ie_complete_gen) == comp_gen) {
			struct xfs_buf	*bp = NULL;
			int		irc;

			/* Dirty recheck: a re-dirtied-not-yet-submitted
			 * buffer moves no generation; only the buffer state
			 * shows it.  Trylock failure = unknown = fail. */
			irc = xfs_buf_incore(mp->m_ddev_targp, imap.im_blkno,
					     imap.im_len, XBF_TRYLOCK, &bp);
			if (irc == -ENOENT || (!irc && !bp))
				break;	/* proof holds */
			if (!irc && bp) {
				struct xfs_buf_log_item	*bip = bp->b_log_item;
				bool redirty =
				    (bp->b_flags & (_XBF_DELWRI_Q | XBF_WRITE)) ||
				    xfs_buf_ispinned(bp) ||
				    (bip &&
				     (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
				      test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))) ||
				    !list_empty_careful(&bp->b_li_list);
				xfs_buf_relse(bp);
				if (!redirty)
					break;	/* clean incore: proof holds */
			}
			proof_failed = 1;
			break;
		}
		if (bounce == 1) {
			static atomic_t p_icb_n = ATOMIC_INIT(0);

			proof_failed = 1;
			if (atomic_inc_return(&p_icb_n) <= 200)
				mxfs_probe("mxfs: P289-ICLUS-GEN-MOVED base=%llu daddr=%lld — cluster writes kept arriving across two flush proofs; proof fails conservative\n",
					(unsigned long long)base,
					(long long)daddr);
		}
		/* generation moved: one bounce with a fresh flush */
	}
	mxfs_relgate_fault(MXFS_RGF_PROOF, base);
	if (cert) {
		cert->icwr_daddr = (uint64_t)daddr;
		cert->icwr_inflight_final =
			ent ? (uint32_t)atomic_read(&ent->ie_inflight) : 0;
		cert->icwr_gen_final =
			ent ? (uint64_t)atomic64_read(&ent->ie_complete_gen) : 0;
		cert->proof_failed = proof_failed ? 1 : 0;
		if (!mxfs_fua_disable)
			cert->ticket_status = (frc == 0) ?
				MXFS_TICKET_REAL_FLUSH :
				MXFS_TICKET_FLUSH_FAILED;
		else
			cert->ticket_status = mxfs_target_cache_protected ?
				MXFS_TICKET_PROTECTED : MXFS_TICKET_NO_DOMAIN;
	}
	return still_dirty;
}

/*
 * Release check for one covered inode's demote/evict/free.  The on-disk
 * grant is RETAINED (grant caching — the whole point) unless a peer BAST
 * is pending; then, if the sweep shows no other covered inode active, THIS
 * call performs the on-disk release.  Callers have already drained their
 * own inode (existing per-inode drain ordering), so a clean sweep implies
 * every covered inode is drained — invariant #1 holds for the cluster.
 * `mode` is the caller's held mode (advisory); is_free piggybacks the
 * tombstone CAS iff this call performs the release.
 */
int
mxfs_iclus_unlock(struct xfs_mount *mp, uint64_t ino, uint8_t mode,
		  bool is_free)
{
	uint64_t base = mxfs_iclus_base(mp, ino);
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, base, false);
	bool sweep = false;
	bool busy_gate = false;

	(void)mode;
	if (!ic)
		return 0;	/* nothing ever claimed (e.g. single-node-era grant) */
	spin_lock(&ic->lock);
	if (ic->bast_pending && ic->disk_mode > MXFS_LOCK_NL && !ic->busy) {
		ic->busy = true;
		sweep = true;
	} else if (ic->bast_pending && ic->disk_mode > MXFS_LOCK_NL) {
		busy_gate = true;	/* another sweep in flight — undecided */
	}
	spin_unlock(&ic->lock);
	if (!sweep)
		/* (design-consult): HONEST rc — a peer is
		 * still owed the cluster (bast_pending with a live disk grant)
		 * but this call could not even attempt the release.  The old
		 * void return let the bast_process routed branch claim
		 * p6u_rc=0 "released", clearing the starvation-rescue clocks
		 * every 250ms => the 470s cc@32 ABBA wedge had NO last-resort
		 * escape.  No cluster obligation (no bast or already NL) stays
		 * rc 0. */
		return busy_gate ? -EBUSY : 0;

	if (!mxfs_iclus_covered_active(mp, base, ino, false)) {
		int urc;

		/* mxfs_iclus_disk_release = publish-before-release
		 * choke point.  A failed publish lands in the SAME failure
		 * arm as a failed unlock CAS: disk_mode/bast_pending kept,
		 * release_check retries, peers keep BASTing. */
		urc = mxfs_iclus_disk_release(mp, ic, base, is_free);
		if (unlikely(mxfs_watch_ino && base == mxfs_watch_ino))
			mxfs_probe("mxfs: P-ICLUS-UNLK base=%llu urc=%d comm=%s realns=%llu\n",
				(unsigned long long)base, urc, current->comm,
				(unsigned long long)ktime_get_real_ns());
		spin_lock(&ic->lock);
		/*
		 * the old (void) discard here
		 * MANUFACTURED the 32-node cc wedge — a CAS-exhausted unlock
		 * (-EIO) left our EX bit on disk while disk_mode went NL,
		 * which also gates every later release_check off
		 * (disk_mode > NL required), so the stale bit had NO clearer
		 * and 32 nodes starved behind a live heartbeat.  Only record
		 * NL when the disk actually cleared; on failure keep
		 * disk_mode/bast_pending so the next release_check retries.
		 */
		if (urc == 0)
			mxfs_iclus_release_done_locked(ic);
		else
			mxfs_probe_ratelimited(
			    "mxfs: P-ICLUS-UNLK-FAIL base=%llu rc=%d — disk bit NOT cleared; keeping disk_mode=%u bast_pending for retry\n",
				(unsigned long long)base, urc, ic->disk_mode);
		ic->busy = false;
		spin_unlock(&ic->lock);
		wake_up_all(&ic->wq);
		return urc;
	}
	spin_lock(&ic->lock);
	ic->busy = false;
	spin_unlock(&ic->lock);
	wake_up_all(&ic->wq);
	/* Still-covered inodes hold the grant: arm their demotes so the
	 * LAST one's release_check completes the handoff without waiting
	 * for a peer re-BAST period. */
	mxfs_iclus_fan_out(mp, base, MXFS_LOCK_EX);
	return -EBUSY;	/* covered-active decline — cluster NOT cleared */
}

/*
 * Non-blocking admit for xfs_ilock_nowait (IOLOCK-driven): succeed only
 * when the cluster's disk grant already covers the mode and no slow-path
 * transition is in flight.  The CALLER brackets this with
 * i_dlm_acq_inflight so the admit window is sweep-visible.
 */
bool
mxfs_iclus_try_admit(struct xfs_mount *mp, uint64_t ino, uint8_t mode)
{
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, mxfs_iclus_base(mp, ino),
					       false);
	bool ok;

	if (!ic)
		return false;
	spin_lock(&ic->lock);
	ok = ic->disk_mode >= mode && !ic->busy &&
	     mxfs_iclus_admission_open(ic);
	spin_unlock(&ic->lock);
	return ok;
}

/*
 * In-memory view of the cluster's granted disk mode, for verify paths that
 * would otherwise probe the (nonexistent) per-inode slot of a routed file:
 * the ioend nested-EX admit and the reload grant-held gate.
 */
uint8_t
mxfs_iclus_granted_mode(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, mxfs_iclus_base(mp, ino),
					       false);
	uint8_t m = MXFS_LOCK_NL;

	if (ic) {
		spin_lock(&ic->lock);
		m = ic->disk_mode;
		spin_unlock(&ic->lock);
	}
	return m;
}

/*
 * The cluster's coherency clock (see i_dlm_iclus_seen_seq).  0 = never
 * claimed on this node.
 */
uint64_t
mxfs_iclus_grant_seq(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, mxfs_iclus_base(mp, ino),
					       false);
	uint64_t seq = 0;

	if (ic) {
		spin_lock(&ic->lock);
		seq = ic->grant_seq;
		spin_unlock(&ic->lock);
	}
	return seq;
}

/*
 * ICLUSTER BAST entry (registered via mxfs_v5_dlm_set_iclus_bast_notify,
 * data = mp).  Marks the cluster contended, releases immediately when no
 * covered inode is active, otherwise fans the BAST out to the covered
 * in-core granted inodes so their per-inode drain machinery runs and the
 * last release_check performs the on-disk release.
 */
void
mxfs_iclus_bast_notify(void *data, uint64_t base_ino, uint8_t req_mode)
{
	struct xfs_mount *mp = data;
	struct mxfs_iclus *ic = mxfs_iclus_get(mp, base_ino, false);
	bool sweep = false;

	if (!ic)
		return;		/* we hold nothing on this cluster */
	spin_lock(&ic->lock);
	ic->bast_pending = true;
	if (ic->disk_mode > MXFS_LOCK_NL && !ic->busy) {
		ic->busy = true;
		sweep = true;
	}
	spin_unlock(&ic->lock);
	if (!sweep)
		return;		/* in-flight acquire/release owns the next step */

	if (!mxfs_iclus_covered_active(mp, base_ino, 0, false)) {
		int urc;

		urc = mxfs_iclus_disk_release(mp, ic, base_ino, false);
		if (unlikely(mxfs_watch_ino && base_ino == mxfs_watch_ino))
			mxfs_probe("mxfs: P-ICLUS-UNLK-BN base=%llu urc=%d realns=%llu\n",
				(unsigned long long)base_ino, urc,
				(unsigned long long)ktime_get_real_ns());
		spin_lock(&ic->lock);
		/* same honesty rule as mxfs_iclus_unlock — a failed
		 * disk clear must not zero disk_mode (that lie orphans the
		 * bit AND gates future release_checks off). */
		if (urc == 0)
			mxfs_iclus_release_done_locked(ic);
		else
			mxfs_probe_ratelimited(
			    "mxfs: P-ICLUS-UNLK-FAIL base=%llu rc=%d (bast_notify) — keeping disk_mode=%u for retry\n",
				(unsigned long long)base_ino, urc,
				ic->disk_mode);
		ic->busy = false;
		spin_unlock(&ic->lock);
		wake_up_all(&ic->wq);
		return;
	}
	spin_lock(&ic->lock);
	ic->busy = false;
	spin_unlock(&ic->lock);
	wake_up_all(&ic->wq);
	mxfs_iclus_fan_out(mp, base_ino, req_mode);
}

/*
 * step-6 RETRY WORKER (ruling item 3): drives a deferred
 * release to completion.  Enters the NORMAL busy-serialized release path —
 * no second CAS path — and disarms ONLY on a confirmed clear (rc 0, via
 * release_done_locked), wedge, or the teardown latch.  Never on apparent
 * disk_mode/busy change: a busy collision just retries short.
 */
static void
mxfs_iclus_defer_worker(struct work_struct *work)
{
	struct mxfs_iclus *ic = container_of(to_delayed_work(work),
					     struct mxfs_iclus, dwork);
	struct xfs_mount *mp = ic->mp;
	int rc;

	spin_lock(&ic->lock);
	if (ic->no_retry ||
	    READ_ONCE(ic->rel_state) == MXFS_RELSTATE_WEDGED) {
		spin_unlock(&ic->lock);
		return;
	}
	if (READ_ONCE(ic->rel_state) != MXFS_RELSTATE_DEMOTING ||
	    ic->disk_mode == MXFS_LOCK_NL) {
		/* episode closed by a competing sync release — done */
		spin_unlock(&ic->lock);
		return;
	}
	if (ic->busy) {
		/* a sync acquire/release owns the cluster right now — it
		 * either completes the release itself or re-defers (which
		 * re-arms us); retry short to cover the neither case */
		queue_delayed_work(mp->m_mxfs_inode_bast_wq, &ic->dwork,
				   msecs_to_jiffies(100));
		spin_unlock(&ic->lock);
		return;
	}
	ic->busy = true;
	spin_unlock(&ic->lock);

	/* granted-only sweep — see the covered_active comment: parked slow
	 * acquirers' inflight markers must not deadlock their own release */
	if (mxfs_iclus_covered_active(mp, ic->base, 0, true)) {
		/* shouldn't happen (DEMOTING blocks stamps) — arm the
		 * covered inodes' demote pipeline and try again */
		spin_lock(&ic->lock);
		ic->busy = false;
		if (!ic->no_retry)
			queue_delayed_work(mp->m_mxfs_inode_bast_wq,
					   &ic->dwork,
					   msecs_to_jiffies(100));
		spin_unlock(&ic->lock);
		wake_up_all(&ic->wq);
		mxfs_iclus_fan_out(mp, ic->base, MXFS_LOCK_EX);
		return;
	}
	rc = mxfs_iclus_disk_release(mp, ic, ic->base, false);
	spin_lock(&ic->lock);
	if (rc == 0)
		mxfs_iclus_release_done_locked(ic);
	ic->busy = false;
	spin_unlock(&ic->lock);
	wake_up_all(&ic->wq);
	/* nonzero rc: the defer/CAS-fail arms inside disk_release already
	 * rescheduled or wedged; nothing further to drive here */
}

/*
 * Unmount teardown.  (ruling item 7 checklist): unmount must not
 * cancel-then-release-wholesale — each cluster still owing a deferred
 * release gets its retries latched off (no_retry BEFORE cancel_sync, so
 * nothing can requeue), then ONE final proof-gated release attempt; a
 * cluster that still cannot prove is pinned on the DLM side so the caw
 * release_all cannot strip its bits, and the departure is not clean
 * (peers fence and recover us — the safe direction).  Runs BEFORE
 * v5_shutdown/caw release_all (pal/linux/xfs_super.c teardown order), so
 * the DLM transport is still alive for the final attempt and the pin.
 */
void
mxfs_iclus_purge_all(struct xfs_mount *mp)
{
	unsigned int h;
	struct mxfs_iclus *ic;
	struct hlist_node *tmp;
	HLIST_HEAD(purge);

	spin_lock(&mxfs_iclus_glock);
	for (h = 0; h < MXFS_ICLUS_HASH_SIZE; h++) {
		hlist_for_each_entry_safe(ic, tmp, &mxfs_iclus_hash[h],
					  hnode) {
			if (ic->mp != mp)
				continue;
			hlist_del(&ic->hnode);
			hlist_add_head(&ic->hnode, &purge);
		}
	}
	spin_unlock(&mxfs_iclus_glock);

	hlist_for_each_entry_safe(ic, tmp, &purge, hnode) {
		spin_lock(&ic->lock);
		ic->no_retry = true;
		spin_unlock(&ic->lock);
		cancel_delayed_work_sync(&ic->dwork);
		if (mxfs_release_proof_enforce &&
		    READ_ONCE(ic->rel_state) == MXFS_RELSTATE_DEMOTING &&
		    ic->disk_mode > MXFS_LOCK_NL) {
			int rc;

			spin_lock(&ic->lock);
			WARN_ON_ONCE(ic->busy);
			ic->busy = true;
			spin_unlock(&ic->lock);
			rc = mxfs_iclus_disk_release(mp, ic, ic->base,
						     false);
			spin_lock(&ic->lock);
			if (rc == 0)
				mxfs_iclus_release_done_locked(ic);
			ic->busy = false;
			spin_unlock(&ic->lock);
			if (rc) {
				/* 0286: pin rc matters — on TCP the pin is
				 * unsupported, so the shutdown is the only
				 * fence that stops the departure reading as
				 * clean while this grant is unproven. */
				int pin_rc = mxfs_v5_dlm_iclus_pin(
						mp->m_mxfs_dlm, ic->base);

				pr_err("mxfs: P-ICLUS-TEARDOWN-UNPROVEN base=%llu rc=%d pin_rc=%d — deferred release still unproven at unmount; grant pinned, departure NOT clean\n",
				       (unsigned long long)ic->base, rc,
				       pin_rc);
				if (pin_rc)
					xfs_force_shutdown(mp,
						SHUTDOWN_META_IO_ERROR);
			}
		}
		WARN_ON_ONCE(ic->busy);
		hlist_del(&ic->hnode);
		kfree(ic);
	}
}
