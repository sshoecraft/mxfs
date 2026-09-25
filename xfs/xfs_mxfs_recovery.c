// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- fencing, quarantine, foreign replay and replay gates
 */
#define MXFS_TU_ID 33	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * Per-class replay enforcement gate (build-order step 9 arms the
 * classes in this order): bit0=AG, bit1=inode, bit2=ICLUS, bit3=dir.
 * 0 = disabled (audit-only through build-order step 8).  Writable only
 * through the fail-closed setter below.
 */
int mxfs_replay_gate_enforce;
EXPORT_SYMBOL(mxfs_replay_gate_enforce);

/* Read helper for the future gate/certificate sites: current enforcement
 * bitmask, 0 while disabled or refused. */
int mxfs_replay_gate_mode(void)
{
	return READ_ONCE(mxfs_replay_gate_enforce);
}
EXPORT_SYMBOL(mxfs_replay_gate_mode);

/*
 * — D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE-0133, ruling
 * containment (design review item 4): FORBID every runtime non-counter
 * superblock mutation in cluster mode, rejecting BEFORE m_sb is touched.
 *
 * Why every producer and not just feature adds: xfs_log_sb serialises the
 * logger's ENTIRE private m_sb over the one shared SB sector, and the
 * routine lazy-counter sync at log cover / unmount is itself such a log.
 * So a peer that merely covers its log after this node grew the fs, set a
 * label, added a log-incompat bit or turned quota on durably REVERTS that
 * change from its stale copy (proven for ATTRBIT).  Counter-only
 * syncs stay allowed (the #94 clean-skip classifier handles them); every
 * other producer calls this first.  A coordination protocol for these
 * mutations, if one is ever built, must cover the same set.
 */
static atomic64_t mxfs_sb_mutation_refused_n = ATOMIC64_INIT(0);
int mxfs_sb_mutation_refuse(struct xfs_mount *mp, const char *what)
{
	if (!mp->m_mxfs_dlm)
		return 0;
	atomic64_inc(&mxfs_sb_mutation_refused_n);
	xfs_warn(mp,
"MXFS P-SB-MUTATION-REFUSED what=%s n=%llu — runtime superblock mutations are not coordinated across the cluster (every node logs its own whole m_sb over the shared sector; a peer's next counter sync would revert this change).  Refused before m_sb was modified; perform it OFFLINE with all nodes unmounted (D-0133)",
		 what,
		 (unsigned long long)atomic64_read(&mxfs_sb_mutation_refused_n));
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(mxfs_sb_mutation_refuse);

static int
mxfs_replay_gate_enforce_set(const char *val, const struct kernel_param *kp)
{
	int unmet = 0;
	int v;
	int rc = kstrtoint(val, 0, &v);

	if (rc)
		return rc;
	if (!v) {
		WRITE_ONCE(mxfs_replay_gate_enforce, 0);
		return 0;
	}
	if (mxfs_fua_disable && !mxfs_target_cache_protected) {
		pr_err("mxfs: replay_gate_enforce=%d REFUSED: fua_disable=1 with target_cache_protected=0 — tenure-boundary flushes are no-ops, so a target write-cache loss can persist the release CAS while dropping the home writes it certified (F2).  Run durable mode (fua_disable=0) or set mxfs.target_cache_protected=1 to declare target power loss out of scope\n",
		       v);
		unmet++;
	}
	if (!MXFS_RELGATE_F1_ICLUS_DEFERRED_RELEASE_READY) {
		pr_err("mxfs: replay_gate_enforce=%d REFUSED: F1 unmet — ICLUS make_durable still releases on 250ms settle timeout with a dirty cluster buffer; deferred-release drain worker (build-order step 6) not landed\n",
		       v);
		unmet++;
	}
	if (!MXFS_RELGATE_F3_COMPLETION_PROOF_READY) {
		pr_err("mxfs: replay_gate_enforce=%d REFUSED: F3 unmet — the completion-driven proof (keyed icwr accounting, flush tickets, pre-CAS tripwire) blocks ICLUS releases under release_proof_enforce=1, but an INODE-class flush-ticket proof failure (fua_disable=0 domain only) still CASes unproved; enforcement on a non-blocking proof would certify releases the proof itself flagged\n",
		       v);
		unmet++;
	}
	if (!MXFS_RELGATE_F4_OBLIGATION_REGISTRY_READY) {
		pr_err("mxfs: replay_gate_enforce=%d REFUSED: F4 unmet — no per-tenure obligation registry for committed-never-submitted dir buffers (build-order step 4); inflight counts fence submitted bios only\n",
		       v);
		unmet++;
	}
	if (unmet) {
		pr_err("mxfs: replay_gate_enforce stays 0 — %d prerequisite(s) unmet (fail closed, ruling)\n",
		       unmet);
		return -EINVAL;
	}
	WRITE_ONCE(mxfs_replay_gate_enforce, v);
	pr_warn("mxfs: replay_gate_enforce=%d ARMED (bit0=AG bit1=inode bit2=ICLUS bit3=dir)\n",
		v);
	return 0;
}
static const struct kernel_param_ops mxfs_replay_gate_enforce_ops = {
	.set = mxfs_replay_gate_enforce_set,
	.get = param_get_int,
};
module_param_cb(replay_gate_enforce, &mxfs_replay_gate_enforce_ops,
		&mxfs_replay_gate_enforce, 0644);
MODULE_PARM_DESC(replay_gate_enforce,
                 "per-class replay enforcement gate bitmask (bit0=AG "
                 "bit1=inode bit2=ICLUS bit3=dir; 0=disabled default; "
                 "setter fails closed while release-barrier prerequisites "
                 "F1-F4 are unmet)");

static int
mxfs_fr_token_enforce_set(const char *val, const struct kernel_param *kp)
{
	int unmet = 0;
	bool b;
	int v;
	/* (design review): 0/1 only — an armed/disarmed switch has no
	 * meaningful other values and accepting them invites typo-arming. */
	int rc = kstrtobool(val, &b);

	if (rc)
		return rc;
	v = b ? 1 : 0;
	if (!v) {
		/* Disarming affects FUTURE recovery attempts only: an attempt
		 * that preflighted while armed runs to completion under its
		 * attempt-local snapshot (l_mxfs_fr_enforce_mode). */
		WRITE_ONCE(mxfs_foreign_replay_token_enforce, 0);
		return 0;
	}
	/* (design review Q5): validate-and-write under the config lock
	 * so a concurrent F2-param setter cannot interleave. */
	mutex_lock(&mxfs_fr_cfg_lock);
	if (mxfs_fua_disable && !mxfs_target_cache_protected) {
		pr_err("mxfs: foreign_replay_token_enforce=%d REFUSED: fua_disable=1 with target_cache_protected=0 — tenure-boundary flushes are no-ops, so the manifest state tokens are checked against may survive a target cache loss that dropped the writes it certifies (F2).  Run durable mode (fua_disable=0) or set mxfs.target_cache_protected=1 to declare target power loss out of scope\n",
		       v);
		unmet++;
	}
	if (!mxfs_release_proof_enforce) {
		pr_err("mxfs: foreign_replay_token_enforce=%d REFUSED: release_proof_enforce=0 — a failed completion proof does not block the release CAS, so manifest hold/epoch state is not trustworthy release evidence for the token gate\n",
		       v);
		unmet++;
	}
	/* (D-FOREIGN-REPLAY-UNGATED-IMAGES default-on gate item 2,
	 * ruling: "ICLUS clean-release markers OR explicit refusal of
	 * ICLUS configs"): a cluster-routed tenure is released by the ICLUS
	 * pipeline, not by the per-inode release that logs the RELMARK
	 * certificate (mxfs_relmark_iclus_unmarked counts them), so under
	 * icluster_dlm=1 every clean cluster release is uncertified and the
	 * replay verdict for it can only be a fail-closed refusal.  Arming an
	 * APPLY gate into a configuration that cannot certify its own
	 * releases is refused here, explicitly, rather than discovered as a
	 * per-victim refusal at the first dirty death.  icluster_dlm is
	 * load-time only (0444), so this set-time check is complete. */
	if (mxfs_icluster_dlm) {
		pr_err("mxfs: foreign_replay_token_enforce=%d REFUSED: icluster_dlm=1 — cluster-routed inode tenures release through the ICLUS pipeline without a clean-release certificate (RELMARK), so their images can never earn an enforceable verdict; token enforcement requires icluster_dlm=0 (module load parameter)\n",
		       v);
		unmet++;
	}
	if (unmet) {
		mutex_unlock(&mxfs_fr_cfg_lock);
		pr_err("mxfs: foreign_replay_token_enforce stays 0 — %d prerequisite(s) unmet (fail closed, ruling)\n",
		       unmet);
		return -EINVAL;
	}
	WRITE_ONCE(mxfs_foreign_replay_token_enforce, v);
	mutex_unlock(&mxfs_fr_cfg_lock);
	pr_warn("mxfs: foreign_replay_token_enforce=%d ARMED — fully-tokenized victim transactions with enforceable v3 verdicts will be APPLIED during foreign-slice recovery\n",
		v);
	return 0;
}
static const struct kernel_param_ops mxfs_fr_token_enforce_ops = {
	.set = mxfs_fr_token_enforce_set,
	.get = param_get_int,
};
module_param_cb(foreign_replay_token_enforce, &mxfs_fr_token_enforce_ops,
		&mxfs_foreign_replay_token_enforce, 0644);
MODULE_PARM_DESC(foreign_replay_token_enforce,
                 "apply fully-tokenized victim transactions during foreign-"
                 "slice recovery (1=enforce DEFAULT since 0.54.0; 0=shadow-only "
                 "legacy, refused for clustered RW mounts; setter fails "
                 "closed on F2 domain admission, release_proof_enforce and "
                 "icluster_dlm=1)");
module_param_named(fr_stab_prefetch, mxfs_fr_stab_prefetch, int, 0644);
MODULE_PARM_DESC(fr_stab_prefetch,
	"/445: pipeline DEPTH of victim-slice snapshot stability proofs run on workers ahead of the mount-cohort barrier's replays (each holds ~68 MiB); 0 = inline only, default 3, max 8");
module_param_named(fr_stab_interval_ms, mxfs_fr_stab_interval_ms, int, 0644);
MODULE_PARM_DESC(fr_stab_interval_ms,
		 "delay between foreign-slice stabilization compare passes (ms)");
module_param_named(fr_stab_passes, mxfs_fr_stab_passes, int, 0644);
MODULE_PARM_DESC(fr_stab_passes,
		 "consecutive identical full-slice reads required before foreign replay may start");
module_param_named(fr_stab_deadline_ms, mxfs_fr_stab_deadline_ms, int, 0644);
MODULE_PARM_DESC(fr_stab_deadline_ms,
		 "abort the elected recovery (retryable, never terminal) if the victim's slice is still changing after this long (ms)");
atomic_t mxfs_freplay_work_inv = ATOMIC_INIT(0);	/* work fn invocations */

/*
 * self-fence: the DLM layer says this node must stop writing to the
 * shared device.  Force-shutdown — everything this node would write from here
 * on corrupts either a new filesystem generation or a recovery in flight.
 *
 * `reason` (enum mxfs_self_fence_reason) selects the message.  This
 * used to print "device reformatted under live mount" for every detector.
 * That is the correct diagnosis for exactly one of the four, and the wrong
 * one is not harmless: it tells an admin their shared LUN has been destroyed
 * and sends them hunting a rogue mkfs, when the true cause — being fenced by
 * a peer that is replaying this node's journal — leaves the device intact and
 * calls for an entirely different response.
 */
void
mxfs_dlm_fence_notify(
	void			*data,
	int			reason)
{
	struct xfs_mount	*mp = data;

	xfs_alert(mp,
		"P131-SELF-FENCE [%s]: %s — forcing shutdown",
		mxfs_self_fence_reason_name(reason),
		mxfs_self_fence_reason_desc(reason));
	xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
}

/*
 * (D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513,
 * Design-consult ruling): fold a terminal recovery-refusal domain into this
 * mount's quarantine map.  Monotonic under m_mxfs_quar_lock — entries
 * are only ever added; quarantine is terminal until remount.  The
 * (victim_epoch, publish_seq) TUPLE dedups the LOGGING per victim slot
 * (the disklock monitor re-imports every pass, and seq alone is wrong
 * across slot reuse — a new victim incarnation restarts publish_seq at
 * 1; ruling item 3); the map itself is idempotent.  Called both
 * by the publisher itself (immediately after a successful publish —
 * enforcement must not wait a monitor lap) and by the monitor import
 * callback for every survivor.
 */
static void
mxfs_quarantine_import(
	struct xfs_mount	*mp,
	unsigned int		victim_slot,
	bool			fswide,
	uint64_t		ag_mask,
	uint64_t		victim_epoch,
	uint64_t		publish_seq)
{
	bool			fresh = false;
	bool			admitting;

	spin_lock(&mp->m_mxfs_quar_lock);
	/*
	 * which side of the admission transition this import landed
	 * on.  Read under the SAME lock the transition flips it under, so the
	 * answer is never "it depends" — an import that sees ADMITTING is
	 * guaranteed to be visible to mxfs_dlm_admission_commit()'s test, and
	 * one that does not is guaranteed to be running against a mount that
	 * has already been admitted and can only be failed with runtime EIO.
	 */
	admitting = mp->m_mxfs_quar_admitting;
	if (fswide && !mp->m_mxfs_quar_fswide) {
		mp->m_mxfs_quar_fswide = true;
		fresh = true;
	}
	if (ag_mask & ~mp->m_mxfs_quar_ag_mask) {
		mp->m_mxfs_quar_ag_mask |= ag_mask;
		fresh = true;
	}
	if (victim_slot < 64 &&
	    (victim_epoch != mp->m_mxfs_quar_seen_epoch[victim_slot] ||
	     publish_seq > mp->m_mxfs_quar_seen_seq[victim_slot])) {
		mp->m_mxfs_quar_seen_epoch[victim_slot] = victim_epoch;
		mp->m_mxfs_quar_seen_seq[victim_slot] = publish_seq;
		fresh = true;
	}
	spin_unlock(&mp->m_mxfs_quar_lock);
	if (fresh)
		xfs_alert(mp,
			"MXFS P240-QUAR-IMPORT victim_slot=%u fswide=%d "
			"ag_mask=0x%llx vepoch=%llu seq=%llu phase=%s — victim "
			"recovery domain QUARANTINED: operations touching it "
			"fail with EIO until operator repair + remount",
			victim_slot, fswide,
			(unsigned long long)ag_mask,
			(unsigned long long)victim_epoch,
			(unsigned long long)publish_seq,
			admitting ? "ADMITTING" : "ADMITTED");
	if (fresh && fswide && admitting)
		xfs_alert(mp,
			"MXFS P240-QUAR-ADMIT-DENY victim_slot=%u — an FSWIDE "
			"quarantine landed while this mount was still being "
			"admitted; the admission transition will refuse it "
			"rather than admit a mount whose every operation fails",
			victim_slot);
}

/*
 * single import chokepoint for a canonical outcome record.  An
 * unknown domain_kind quarantines fswide — fail closed: a record we
 * cannot interpret still proves a suppressed committed redo somewhere.
 * oc == NULL is the ruling item-8 contract (QUARANTINED with unreadable
 * verdict state): no domain evidence exists, so FSWIDE, with epoch/seq 0
 * (nothing to dedup on; the map is idempotent).
 */
static void
mxfs_quarantine_import_oc(
	struct xfs_mount		*mp,
	unsigned int			victim_slot,
	const struct mxfs_recov_outcome	*oc)
{
	bool				fswide;
	uint64_t			ag_mask = 0;

	if (oc && oc->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK &&
	    oc->ag_mask) {
		fswide = false;
		ag_mask = oc->ag_mask;
	} else {
		fswide = true;
	}
	mxfs_quarantine_import(mp, victim_slot, fswide, ag_mask,
			       oc ? oc->victim_epoch : 0,
			       oc ? oc->publish_seq : 0);
	/*
	 * 0.75.25: a request for a grant the victim HOLDS fails fast like one
	 * to a blocked dead master.  0.75.30 (D-0910): the victim also leaves
	 * the membership view — its pages are remastered and taken over, with
	 * only its provably out-of-domain records retired (an FSWIDE verdict
	 * retires none); before this the survivor could not create anything
	 * whose new inode hashed to the dead master's pages.
	 */
	if (mp->m_mxfs_dlm)
		mxfs_v5_dlm_recovery_refused(mp->m_mxfs_dlm, (int)victim_slot,
					     oc ? oc->victim_node : 0,
					     oc ? oc->victim_epoch : 0,
					     fswide ? 1 : 0, ag_mask);
}

/*
 * (review item B): the ONE validating import for a
 * canonical outcome record read back from the platter.  Three sites used
 * to import with three different levels of scrutiny — the direct-read
 * classifier arm checked only the outcome kind, the legacy-backfill
 * return imported whatever record won the race unvalidated, and the
 * publish-conflict readback checked the kind alone.  A raced record with
 * a parseable AG-scoped domain but an unknown reason, an empty AG mask,
 * or a victim identity that does not match the sector it was read from
 * would import an enforcement domain nobody ever decided.  Everything a
 * caller is about to ENFORCE validates here; any failure imports NULL =
 * fail-closed FSWIDE, logging the ACTUAL record for forensics.
 */
static int
mxfs_freplay_import_verdict(
	struct xfs_mount		*mp,
	unsigned int			slot,
	const struct mxfs_recov_outcome	*oc,
	const char			*src)
{
	uint64_t			ag_bits;

	if (!oc) {
		mxfs_quarantine_import_oc(mp, slot, NULL);
		return MXFS_QUAR_INVALID_FSWIDE;
	}
	/*
	 * (design-consult ruling Q5.2): "nonzero" is not a valid AG mask.  A
	 * mask made only of bits for AGs this filesystem does not have
	 * quarantines nothing — a fail-OPEN domain dressed as an AG-scoped
	 * refusal.  Canonical form is FSWIDE => ag_mask == 0, AG_MASK => a
	 * nonempty SUBSET of the AGs that exist.  Rejecting a noncanonical
	 * FSWIDE mask also stops two consumers disagreeing about the domain;
	 * every in-tree producer already publishes 0 for FSWIDE
	 * (info.ag_mask = fv->fswide ? 0 : fv->ag_mask).  AGs >= 64 are not
	 * representable in the mask at all and force FSWIDE at collection
	 * time, so a 64-AG-wide filesystem simply has every bit legal.
	 */
	ag_bits = mp->m_sb.sb_agcount >= 64 ? ~0ULL :
			((1ULL << mp->m_sb.sb_agcount) - 1);
	if (oc->outcome != MXFS_RECOV_OUTCOME_TERMINAL_REFUSED ||
	    (oc->reason != MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE &&
	     oc->reason != MXFS_RECOV_REFUSAL_PHYSICALLY_TORN &&
	     oc->reason != MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE &&
	     oc->reason != MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED &&
	     oc->reason != MXFS_RECOV_REFUSAL_MANIFEST_INVALID &&
	     oc->reason != MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY &&
	     oc->reason != MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED &&
	     oc->reason != MXFS_RECOV_REFUSAL_OBLIGATION_UNRECONCILABLE) ||
	    (oc->domain_kind != MXFS_RECOV_DOMAIN_FSWIDE &&
	     oc->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK) ||
	    (oc->domain_kind == MXFS_RECOV_DOMAIN_FSWIDE && oc->ag_mask) ||
	    (oc->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK &&
	     (!oc->ag_mask || (oc->ag_mask & ~ag_bits))) ||
	    oc->victim_slot != slot) {
		xfs_alert(mp,
			"MXFS foreign replay slot=%u [%s]: outcome record "
			"fails validation (outcome=%u reason=%u domain=%u "
			"ag_mask=0x%llx victim_slot=%u owner=%u seq=%llu "
			"agcount=%u) — failing closed FSWIDE",
			slot, src, oc->outcome, oc->reason, oc->domain_kind,
			(unsigned long long)oc->ag_mask, oc->victim_slot,
			oc->owner_node,
			(unsigned long long)oc->publish_seq,
			mp->m_sb.sb_agcount);
		mxfs_quarantine_import_oc(mp, slot, NULL);
		return MXFS_QUAR_INVALID_FSWIDE;
	}
	xfs_alert(mp,
		"MXFS foreign replay slot=%u [%s]: terminal verdict durable "
		"(owner=%u reason=%u domain=%s ag_mask=0x%llx seq=%llu) — "
		"imported; a refused slice is never replayed",
		slot, src, oc->owner_node, oc->reason,
		oc->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK ?
			"AG-MASK" : "FSWIDE",
		(unsigned long long)oc->ag_mask,
		(unsigned long long)oc->publish_seq);
	mxfs_quarantine_import_oc(mp, slot, oc);
	return oc->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK ?
			MXFS_QUAR_VALID_AG : MXFS_QUAR_VALID_FSWIDE;
}

/*
 * Disklock monitor-thread consumer for imported terminal recovery
 * outcomes (registered via mxfs_v5_dlm_set_quarantine_cb).
 *
 * (ruling item 9): importing a terminal verdict must
 * ALSO stop this node's own replay churn — a non-publisher survivor
 * that was elected replayer keeps re-arming replay+refusal cycles
 * against a slice the cluster has already durably refused.  The torn
 * latch is the existing per-slot "do not replay again" gate the reap
 * worker honours; setting it here is race-safe (a new death notify for
 * the slot clears it, and a stale set against a slot whose descriptor
 * is gone only skips one replay attempt that acquire() would have
 * refused anyway).
 */
int
mxfs_dlm_quarantine_cb(
	void				*data,
	int				victim_slot,
	const struct mxfs_recov_outcome	*oc)
{
	struct xfs_mount		*mp = data;
	int				disp;

	if (victim_slot < 0 || victim_slot >= 64)
		return MXFS_QUAR_NOT_TERMINAL;
	/*
	 * (design-consult ruling Q1): this used to import the record with NO
	 * validation, which made it a second entry point past the one
	 * validator — the monitor and the registration-time scan both arrive
	 * here.  Every record now goes through mxfs_freplay_import_verdict,
	 * which fails closed FSWIDE on anything it rejects and tells the
	 * caller what it decided so the closure path cannot consume an
	 * invalid record.
	 */
	disp = mxfs_freplay_import_verdict(mp, (unsigned int)victim_slot, oc,
					   "import-cb");
	set_bit(victim_slot, mp->m_mxfs_foreign_torn_slots);
	return disp;
}

/*
 * (design-consult ruling): the SHARED terminal classifier — the one
 * routine that decides, from a stable descriptor+outcome snapshot and
 * WITHOUT any recovery lease, whether a pending slot is terminally
 * disposed.  Used by the reap loop and the mount admission barrier, both
 * BEFORE acquire (no lease is ever obtainable over a quarantined
 * descriptor — the claim path's certificate evaluator refuses it before
 * the owner-reacquire check, verified) and again when an acquire
 * returns -EPERM (a quarantine may land between the read and the claim).
 *
 * Every terminal disposition imports the verdict into the quarantine
 * map, latches the slot against replay re-arming, and drops any stale
 * local lease state (release is an idempotent local mask clear):
 *   - a valid TERMINAL_REFUSED outcome imports as-is;
 *   - an unknown outcome kind or unreadable verdict state imports
 *     fail-closed FSWIDE (ruling item 8);
 *   - a LEGACY intent-path quarantine (QUARANTINED, outcome all-zero)
 *     is first terminalized via the LEASELESS backfill and then imports
 *     the canonical record (ours or a racing backfiller's — first
 *     durable verdict wins).
 *
 * Returns 1 = terminally disposed (imported + latched; the caller marks
 * the slot resolved in its own admission/reap accounting), 0 = not
 * terminal (live descriptor or no descriptor at all — proceed to the
 * ordinary acquire+replay path), -EAGAIN = transient (unreadable
 * snapshot or the backfill raced out): re-arm and reclassify later.
 */
int
mxfs_freplay_classify_terminal(
	struct xfs_mount	*mp,
	unsigned int		slot)
{
	struct mxfs_recov_outcome	oc;
	int				orc;

	orc = mxfs_v5_dlm_recovery_read_outcome(mp->m_mxfs_dlm, slot, &oc);
	switch (orc) {
	case -ENOENT:	/* no recovery descriptor yet (fresh death) */
	case -EAGAIN:	/* live descriptor, no verdict */
		return 0;
	case -ESTALE:
		/*
		 * a recovery object from a DIFFERENT mkfs generation
		 * — a pre-mkfs ghost.  It is outside this filesystem's
		 * recovery namespace, so it is neither terminal nor a reason
		 * to fail closed; it authorizes nothing and must not be
		 * backfilled, imported or retired.  The requires-recovery
		 * sweep already skips such sectors, so this arm only fires if
		 * a slot's generation changed under a classification.
		 */
		xfs_notice(mp,
			"MXFS foreign replay slot=%u: recovery object belongs "
			"to a different mkfs generation — ignored (pre-mkfs "
			"ghost), nothing classified", slot);
		return 0;
	case 0:
		mxfs_freplay_import_verdict(mp, slot, &oc, "classify");
		break;
	case -EBADMSG:
	case -EPROTO:
		/* ruling item 8: unreadable verdict state is
		 * persistent corruption — fail closed FSWIDE, stop churning. */
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: verdict state UNREADABLE "
			"(%d) — PERSISTENT; failing closed FSWIDE until "
			"operator action", slot, orc);
		mxfs_quarantine_import_oc(mp, slot, NULL);
		break;
	case -ENODATA: {
		/*
		 * LEGACY intent-path quarantine: terminal but uncommunicated
		 * (a pre-outcome build wrote the flag alone).  Terminalize
		 * it LEASELESSLY — no auth can exist over a quarantined
		 * descriptor — then import the canonical record.
		 */
		struct mxfs_recov_outcome ocb;
		int brc = mxfs_v5_dlm_recovery_backfill_legacy(mp->m_mxfs_dlm,
							       slot, &ocb);
		if (brc == 0) {
			/* (review item B): "first durable
			 * verdict wins" can hand back a RACING publisher's
			 * record, not our deterministic synthesis — it gets
			 * the same validation as a direct read, and the log
			 * shows the ACTUAL record that won. */
			mxfs_freplay_import_verdict(mp, slot, &ocb,
						    "legacy-backfill");
			break;
		}
		if (brc == -EBADMSG || brc == -EPROTO) {
			/* (review item 5): -EPROTO —
			 * unparseable descriptor bytes or a victim identity
			 * that does not match the sector — is persistent
			 * state exactly like corrupt verdict bytes; retrying
			 * it forever never converges.  Fail closed. */
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: legacy backfill "
				"found unusable descriptor/verdict state (%d) "
				"— PERSISTENT; failing closed FSWIDE until "
				"operator action", slot, brc);
			mxfs_quarantine_import_oc(mp, slot, NULL);
			break;
		}
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: legacy-quarantine "
			"backfill did not land (%d) — will retry "
			"TERMINALIZATION (never replay)", slot, brc);
		return -EAGAIN;
	}
	default:
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: verdict read failed (%d) "
			"— reclassifying next pass; nothing latched",
			slot, orc);
		return -EAGAIN;
	}
	set_bit(slot, mp->m_mxfs_foreign_torn_slots);
	mxfs_v5_dlm_recovery_release(mp->m_mxfs_dlm, slot);
	return 1;
}

/*
 * fault injection (ruling hazard 7: "publisher death
 * post-publish").  Suppress the PUBLISHER half of the out-of-closure fix so a
 * run exercises the SURVIVOR demand scrub in isolation — the half that has to
 * work when the publisher dies mid-scan, or was itself the node that died.
 * Without this the publisher always gets there first and the scrub never
 * fires, so its only coverage would be accidental.  0 = off (default).
 * Test-only.
 */
static int mxfs_closure_skip_publisher_purge;
module_param_named(closure_skip_publisher_purge,
		   mxfs_closure_skip_publisher_purge, int, 0644);
MODULE_PARM_DESC(closure_skip_publisher_purge,
	"Fault injection: skip the publisher-side out-of-closure purge so the survivor demand scrub is exercised alone (0=off default)");

static int
mxfs_freplay_res_out_of_closure(
	void				*arg,
	const struct mxfs_resource_id	*res)
{
	struct mxfs_freplay_closure_arg	*ca = arg;
	struct xfs_mount		*mp = ca->mp;
	xfs_agnumber_t			agno;

	switch (res->type) {
	case MXFS_LTYPE_AG:
		agno = res->ag_number;
		break;
	case MXFS_LTYPE_INODE:
	case MXFS_LTYPE_ICLUSTER:
		if (!res->ino)
			return 0;
		if (res->type == MXFS_LTYPE_INODE &&
		    mxfs_sb_summary_key_is(mp, res->ino)) {
			mxfs_probe_ratelimited("mxfs: P487-SBSUM-OUT-OF-CLOSURE slot=%u ino=%llu ag_mask=0x%llx\n",
				mp->m_mxfs_node_slot,
				(unsigned long long)res->ino,
				(unsigned long long)ca->ag_mask);
			return 1;
		}
		agno = XFS_INO_TO_AGNO(mp, res->ino);
		break;
	default:
		return 0;
	}
	if (agno >= mp->m_sb.sb_agcount || agno >= 64)
		return 0;
	return !(ca->ag_mask & (1ULL << agno));
}

/*
 * (ruling item B): the same judgement, in the shape the
 * survivor-side scrub needs.  The scrub has no publisher to pass a domain in
 * — it reads the blocking node's own terminal verdict and hands us the mask
 * from it — so the closure argument is built per call.  Same predicate, same
 * conservative direction: anything not provably outside the mask stays frozen.
 */
/*
 * (ruling part 1): "is this resource inside a quarantined
 * victim domain?"  Consulted by the DLM on every poll lap of every blocking
 * acquire, so it is deliberately the same lockless monotonic map test the
 * acquire gates already use — two READ_ONCEs on a healthy filesystem.
 *
 * Only AG-scoped resource classes can be answered: an inode maps to its AG, an
 * AG lock names its own.  JOURNAL/SUPER/EXTENT are not AG-scoped, so a waiter
 * on one is left alone — the conservative direction, and identical to how the
 * closure classifier treats them.
 */
int
mxfs_dlm_quar_covers_cb(
	void				*data,
	const struct mxfs_resource_id	*res)
{
	struct xfs_mount		*mp = data;

	if (!mp || !res)
		return 0;
	switch (res->type) {
	case MXFS_LTYPE_AG:
		return mxfs_quarantine_covers_agno(mp, res->ag_number) ? 1 : 0;
	case MXFS_LTYPE_INODE:
	case MXFS_LTYPE_ICLUSTER:
		if (!res->ino)
			return 0;
		return mxfs_quarantine_covers_ino(mp, res->ino) ? 1 : 0;
	default:
		return 0;
	}
}

int
mxfs_dlm_closure_classify_cb(
	void				*data,
	const struct mxfs_resource_id	*res,
	uint64_t			ag_mask)
{
	struct mxfs_freplay_closure_arg	ca = {
		.mp		= (struct xfs_mount *)data,
		.ag_mask	= ag_mask,
	};

	if (!ca.mp || !res || !ag_mask)
		return 0;
	return mxfs_freplay_res_out_of_closure(&ca, res);
}

/*
 * (review item D): the terminal-refusal publish/conflict
 * state machine, shared by the live reap path and the mount admission
 * barrier.  Both hold the recovery lease from acquire() when a replay
 * refuses, and both must drive the SAME durable publication: before this
 * was shared, the barrier passed a NULL verdict and published nothing, so
 * a lone survivor cold-starting against a torn slice looped -EBUSY mount
 * restarts forever without ever writing the refusal the rest of the
 * cluster (and the operator) converge on — the D-513 defect surviving on
 * the mount path.
 *
 * (D-513) context: (#21) latched a TORN refusal locally;
 * proved a LOCAL latch is the all-32 suicide — every other
 * survivor still times out against the frozen grants and shuts down.  A
 * terminal refusal (TORN or policy-refused-complete) is PUBLISHED as a
 * durable outcome record in the victim's heartbeat sector — under the
 * recovery lease the caller holds — so all survivors converge on the same
 * quarantined victim domain and fail ops with EIO instead of suiciding.
 *
 * Returns 1 = the verdict is durably terminal (imported + latched + lease
 * released; the caller marks the slot terminal in its own accounting and
 * checks the quarantine scope for FSWIDE handling), 0 = transient
 * (nothing latched, nothing enforced; the caller re-arms its own retry —
 * the reap loop re-schedules, the barrier leaves the slot in the cut so
 * later rounds / the admission poll retry and the wait bound fails the
 * mount).
 */
/*
 * (item 5 increment 2): make the verdict's RECOVER extent list
 * durable as EVIDENCE next to the terminal outcome (MXFS_RECOV_OBL_F_TERMINAL:
 * it gates nothing; the descriptor is quarantined either way).  Returns 0
 * with *rec filled, -ENOENT when the verdict carries no list, or the write's
 * error — in every non-zero case the refusal publishes WITHOUT a record: the
 * evidence is optional, the verdict is not.  The list is consumed here; the
 * caller frees the verdict afterwards.
 */
static int
mxfs_freplay_obl_evidence(
	struct xfs_mount		*mp,
	unsigned int			slot,
	const struct mxfs_freplay_verdict *fv,
	struct mxfs_recov_obl		*rec)
{
	struct mxfs_recov_obl_geom	geom;
	int				rc;

	if (fv->obl_lost) {
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: P226-OBL-EVIDENCE-LOST recover=%u — the obligation list was not carried out of the replay; the terminal verdict publishes without it",
			slot, fv->obl_count);
		return -ENOENT;
	}
	if (!fv->obl_count || !fv->obl_list)
		return -ENOENT;
	geom.agcount  = mp->m_sb.sb_agcount;
	geom.agblocks = mp->m_sb.sb_agblocks;
	geom.agblklog = mp->m_sb.sb_agblklog;
	rc = mxfs_v5_dlm_recovery_obl_write(mp->m_mxfs_dlm, (int)slot,
					    fv->obl_list, fv->obl_count, &geom,
					    fv->digest_valid ? fv->slice_digest : 0,
					    MXFS_RECOV_OBL_F_TERMINAL, rec);
	if (rc) {
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: P226-OBL-EVIDENCE-FAIL rc=%d recover=%u ag_mask=0x%llx — the obligation list could not be made durable; the terminal verdict publishes without it",
			slot, rc, fv->obl_count,
			(unsigned long long)fv->obl_ag_mask);
		return rc;
	}
	xfs_notice(mp,
		"MXFS foreign replay slot=%u: P226-OBL-EVIDENCE count=%u ag_mask=0x%llx fswide=%d seq=%u list_crc=0x%08x quarantine=%u q_mask=0x%llx q_fswide=%d — RECOVER extents durable as terminal evidence (completion is not in this build)",
		slot, rec->count, (unsigned long long)rec->obl_ag_mask,
		(rec->flags & MXFS_RECOV_OBL_F_FSWIDE) ? 1 : 0, rec->pub_seq,
		rec->list_crc32c, fv->q_count,
		(unsigned long long)fv->q_mask, (int)fv->q_fswide);
	return 0;
}

/*
 * 0.85.0: park a SUCCESSFUL replay's census verdict for the ladder (the
 * OPEN extent list, or the explicit zero) and free the verdict.  Returns 0,
 * or -errno when the list could not be parked (the caller re-arms: nothing
 * is published until the verdict is).  A verdict that carries a lost list
 * with a non-zero count cannot succeed the replay (xfs_log.c refuses it), so
 * obl_count > 0 here always has a list.
 */
/* 0.85.0: the engine's home-write (contract in xfs_mxfs_dlm.h) */
int
mxfs_recov_obl_home_flush(
	struct xfs_mount		*mp)
{
	int				rc;

	rc = mxfs_dlm_peer_joined_flush(mp);
	if (rc)
		return rc;
	return mxfs_blkdev_flush_durable(mp);
}

/* 0.85.0: the engine's terminal outcome (contract in xfs_mxfs_dlm.h) */
int
mxfs_recov_obl_publish_terminal(
	struct xfs_mount		*mp,
	unsigned int			slot,
	uint64_t			ag_mask)
{
	struct mxfs_recov_refusal_info	info;
	struct mxfs_recov_outcome	ocanon;
	int				prc;

	memset(&info, 0, sizeof(info));
	info.reason = MXFS_RECOV_REFUSAL_OBLIGATION_UNRECONCILABLE;
	info.domain_kind = ag_mask ? MXFS_RECOV_DOMAIN_AG_MASK :
				     MXFS_RECOV_DOMAIN_FSWIDE;
	info.ag_mask = ag_mask;
	prc = mxfs_v5_dlm_recovery_publish_refusal(mp->m_mxfs_dlm, (int)slot,
						   &info, &ocanon);
	if (prc) {
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: P-OBL-TERMINAL-FAIL rc=%d — the unreconcilable-obligation verdict is not durable; the case stays OPEN (freeze retained) and retries",
			slot, prc);
		return prc;
	}
	mxfs_freplay_import_verdict(mp, slot, &ocanon, "obl-terminal");
	set_bit(slot, mp->m_mxfs_foreign_torn_slots);
	mxfs_oblf_note(mp, (int)slot, MXFS_OBL_NONE, 0, 0, 0, 0, false);
	mxfs_v5_dlm_recovery_release(mp->m_mxfs_dlm, slot);
	xfs_alert(mp,
		"MXFS foreign replay slot=%u: P-OBL-TERMINAL ag_mask=0x%llx — an obligation extent was unreconcilable; terminal outcome PUBLISHED, the victim domain is quarantined cluster-wide, freeze lifted, needs repair + remount",
		slot, (unsigned long long)ag_mask);
	return 0;
}

/*
 * 0.85.0: the mount barrier met an OPEN obligation case (its own takeover of
 * a dead custodian's descriptor, or a slice it replayed whose census owes
 * extents).  The dead node's grants are retired and the AGs are frozen, so
 * log recovery below cannot block on them — the mount proceeds; the
 * completion needs a live transaction context, so the case is handed to the
 * post-mount foreign-replay worker: the dead-slot bit is set and the reap
 * duty re-drives the worker once the mount settles.  For the barrier's own
 * accounting the slot counts as published (nothing of it holds admission).
 */
void
mxfs_barrier_note_open_cases(
	struct xfs_mount		*mp,
	uint64_t			open,
	uint64_t			*published)
{
	unsigned int			s;

	for (s = 0; s < 64; s++) {
		if (!(open & (1ULL << s)))
			continue;
		set_bit(s, mp->m_mxfs_foreign_dead_slots);
		clear_bit(s, mp->m_mxfs_foreign_torn_slots);
		xfs_notice(mp,
			"MXFS mount recovery: P-OBL-BARRIER-OPEN slot=%u — OPEN obligation case: grants retired, AGs frozen; the post-mount worker completes it",
			s);
	}
	set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
	*published |= open;
}

int
mxfs_freplay_park_census(
	struct xfs_mount		*mp,
	unsigned int			slot,
	struct mxfs_freplay_verdict	*fv)
{
	int				rc = 0;

	if (fv->obl_count && fv->obl_list && !fv->obl_lost) {
		struct mxfs_recov_obl_geom	geom;

		geom.agcount  = mp->m_sb.sb_agcount;
		geom.agblocks = mp->m_sb.sb_agblocks;
		geom.agblklog = mp->m_sb.sb_agblklog;
		rc = mxfs_v5_dlm_recovery_set_obligations(mp->m_mxfs_dlm,
				(int)slot, fv->obl_list, fv->obl_count, &geom,
				fv->digest_valid ? fv->slice_digest : 0);
		if (rc)
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: P-OBL-PARK-FAIL rc=%d count=%u — the OPEN obligation list could not be handed to the ladder; nothing published, will retry",
				slot, rc, fv->obl_count);
		else
			xfs_notice(mp,
				"MXFS foreign replay slot=%u: P-OBL-PARK count=%u ag_mask=0x%llx — OPEN obligation list handed to the ladder for the IMAGES_REPLAYED milestone",
				slot, fv->obl_count,
				(unsigned long long)fv->obl_ag_mask);
	} else if (fv->obl_count || fv->obl_lost) {
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: P-OBL-PARK-INCONSISTENT count=%u lost=%d list=%d — a successful replay handed out an unusable obligation verdict; nothing published, will retry",
			slot, fv->obl_count, (int)fv->obl_lost,
			fv->obl_list ? 1 : 0);
		rc = -EPROTO;
	} else {
		mxfs_v5_dlm_recovery_set_census_zero(mp->m_mxfs_dlm, (int)slot);
	}
	mxfs_freplay_verdict_free(fv);
	return rc;
}

/*
 * 0.85.0: the takeover dependency of an OPEN case (ruling: a dead prior
 * custodian's slice must be replayed and home before any bnobt query).  Any
 * OTHER dead slot in our dead set whose platter descriptor is not terminal
 * and not yet at IMAGES_REPLAYED blocks the case.  Returns that slot, or 64
 * when nothing blocks.  A terminal slot never blocks: its refused images are
 * not applied and the case's own re-examination (EMPTY => free again under a
 * freeze that never lapsed; a torn state => SPARSE => terminal) is the
 * fail-closed answer for it.
 */
static unsigned int
mxfs_freplay_open_case_blocked_by(
	struct xfs_mount		*mp,
	unsigned int			slot)
{
	unsigned int			o;

	for_each_set_bit(o, mp->m_mxfs_foreign_dead_slots, 64) {
		unsigned int	st = 0;
		bool		quar = false;
		int		rc;

		if (o == slot)
			continue;
		if (test_bit(o, mp->m_mxfs_foreign_torn_slots))
			continue;
		rc = mxfs_v5_dlm_recovery_platter_stage(mp->m_mxfs_dlm, o,
							&st, &quar);
		if (rc == -ESTALE || rc == -ENOENT)
			return o;	/* no descriptor: not even fenced yet */
		if (rc)
			return o;	/* unreadable: fail closed, wait */
		if (quar)
			continue;
		if (st < MXFS_RECOV_STAGE_IMAGES_REPLAYED)
			return o;
	}
	return 64;
}

int
mxfs_freplay_publish_refusal(
	struct xfs_mount		*mp,
	unsigned int			slot,
	struct mxfs_freplay_verdict	*fv,
	int				rrc)
{
	struct mxfs_recov_refusal_info	info;
	struct mxfs_recov_outcome	ocanon;
	struct mxfs_recov_obl		obl;
	const struct mxfs_recov_obl	*oblp = NULL;
	int				prc;

	/* the obligation evidence rides in the verdict's CAS */
	if (mxfs_freplay_obl_evidence(mp, slot, fv, &obl) == 0)
		oblp = &obl;
	mxfs_freplay_verdict_free(fv);

	/*
	 * (ruling item 5): a failed forensic digest reread
	 * must NOT gate the verdict — the refusal evidence is the gate
	 * decision itself, the digest is forensics.  Publish with
	 * digest_valid=false and a zero digest instead of retrying forever.
	 */
	memset(&info, 0, sizeof(info));
	info.reason = (fv->reason == MXFS_FREPLAY_REASON_TORN) ?
		MXFS_RECOV_REFUSAL_PHYSICALLY_TORN :
		(fv->reason == MXFS_FREPLAY_REASON_AUTHORITY_MUTATED) ?
		MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED :
		(fv->reason == MXFS_FREPLAY_REASON_MANIFEST_INVALID) ?
		MXFS_RECOV_REFUSAL_MANIFEST_INVALID :
		(fv->reason == MXFS_FREPLAY_REASON_ASSEMBLY_DISCONTINUITY) ?
		MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY :
		(fv->reason == MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED) ?
		MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED :
		MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE;
	info.domain_kind = fv->fswide ?
		MXFS_RECOV_DOMAIN_FSWIDE :
		MXFS_RECOV_DOMAIN_AG_MASK;
	info.ag_mask = fv->fswide ? 0 : fv->ag_mask;
	info.digest_valid = fv->digest_valid;
	info.slice_digest = fv->digest_valid ? fv->slice_digest : 0;
	info.refused = fv->refused_items;
	info.malformed = fv->malformed_items;
	prc = oblp ?
		mxfs_v5_dlm_recovery_publish_refusal_obl(mp->m_mxfs_dlm, slot,
							 &info, oblp, &ocanon) :
		mxfs_v5_dlm_recovery_publish_refusal(mp->m_mxfs_dlm, slot,
						     &info, &ocanon);
	if (prc == 0) {
		/*
		 * Publisher enforces immediately — the monitor import lap is
		 * for the OTHER survivors.  Import the CANONICAL record
		 * publish handed back (idempotent case: what an earlier
		 * publisher wrote), latch the slot against replay re-arming,
		 * and release the recovery lease WITHOUT advancing the
		 * descriptor (ruling item 1; the lease is cache-only
		 * local state — no renewal churn, no unmount wait, and
		 * reacquire re-proves against the platter, verified).
		 *
		 * review: import VALIDATED, like every other consumer
		 * of a canonical record — a lower-layer contract regression
		 * that hands back an invalid ocanon then fails closed FSWIDE
		 * instead of enforcing a domain nobody decided.
		 */
		mxfs_freplay_import_verdict(mp, slot, &ocanon, "publish");
		set_bit(slot, mp->m_mxfs_foreign_torn_slots);
		/*
		 * (ruling): with the verdict durable and
		 * imported, and while we STILL hold the recovery lease,
		 * force-revoke the victim's provably-out-of-closure grants so
		 * survivors' waits on out-of-domain resources (e.g. the root
		 * inode's EX from an AG-scoped refusal) unblock instead of
		 * timing out -110 into shutdown.  Classified against the
		 * CANONICAL record — the domain the cluster enforces, not our
		 * local draft.  A purge failure only leaves extra grants
		 * frozen (the pre-fix state); the verdict's durability and the
		 * lease release do not depend on it.
		 */
		if (unlikely(mxfs_closure_skip_publisher_purge)) {
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: P299-CLOSURE-SKIP "
				"— publisher purge suppressed by fault "
				"injection; the survivor demand scrub is the "
				"only repair path for this run",
				slot);
		} else if (ocanon.domain_kind == MXFS_RECOV_DOMAIN_AG_MASK &&
		    ocanon.ag_mask) {
			struct mxfs_freplay_closure_arg ca = {
				.mp = mp,
				.ag_mask = ocanon.ag_mask,
			};
			uint32_t cp = 0, ck = 0;
			int crc;

			crc = mxfs_v5_dlm_recovery_purge_out_of_closure(
				mp->m_mxfs_dlm, slot,
				ocanon.victim_node, ocanon.ag_mask,
				mxfs_freplay_res_out_of_closure, &ca,
				&cp, &ck);
			/*
			 * (ruling item C): a partial purge is NOT a
			 * purge, and must never read as "complete".
			 *
			 * The lease IS still released below, on purpose.  The
			 * ruling is explicit — "no retry loop, release
			 * lease regardless" — because the retry protocol for
			 * an incomplete purge is not a publisher-side loop at
			 * all: it is the SURVIVOR-side demand scrub (ruling
			 * item B), which needs no lease (none is obtainable
			 * over a quarantined descriptor) and repairs exactly
			 * the leftovers that actually block someone.  A
			 * leftover that blocks nobody costs nobody anything.
			 * The design-consult review argued for holding the
			 * lease here; that argument assumes the leftovers can
			 * only be cleared under a lease, which the leaseless
			 * gate is precisely what removes.
			 */
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: out-of-closure "
				"grant purge %s rc=%d purged=%u kept=%u "
				"(victim=%u ag_mask=0x%llx)",
				slot, crc ? "INCOMPLETE" : "complete", crc,
				cp, ck, ocanon.victim_node,
				(unsigned long long)ocanon.ag_mask);
		}
		mxfs_v5_dlm_recovery_release(mp->m_mxfs_dlm, slot);
		xfs_alert(mp,
			"MXFS foreign replay slot=%u: slice replay refused "
			"(%s, rc=%d refused=%u malformed=%u dvalid=%d) — "
			"terminal outcome PUBLISHED, victim domain (%s "
			"ag_mask=0x%llx) quarantined cluster-wide; grants "
			"stay frozen; needs repair + remount",
			slot,
			fv->reason == MXFS_FREPLAY_REASON_TORN ? "TORN" :
			fv->reason == MXFS_FREPLAY_REASON_AUTHORITY_MUTATED ?
				"AUTHORITY-MUTATED" :
			fv->reason == MXFS_FREPLAY_REASON_MANIFEST_INVALID ?
				"MANIFEST-INVALID" :
			fv->reason == MXFS_FREPLAY_REASON_ASSEMBLY_DISCONTINUITY ?
				"ASSEMBLY-DISCONTINUITY" :
			fv->reason == MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED ?
				"INTENTS-UNDISCHARGED" : "POLICY-REFUSED",
			rrc, fv->refused_items, fv->malformed_items,
			(int)fv->digest_valid,
			fv->fswide ? "FSWIDE" : "AG-MASK",
			(unsigned long long)(fv->fswide ? 0 : fv->ag_mask));
		return 1;
	}
	if (prc == -EPERM) {
		/*
		 * (ruling item 2): a conflicting verdict is
		 * already durable — we lost the publish race (or an
		 * intent-path quarantine got there first).  -EPERM is NEVER
		 * terminal by itself: synchronously READ the canonical
		 * outcome and import THAT.  Only a successful readback stops
		 * the retry churn; a failed readback re-arms the
		 * descriptor-read retry, not another full replay (the torn
		 * latch stays unset so the next pass re-reads, but acquire()
		 * will keep refusing a quarantined descriptor).
		 *
		 * (design-consult review): the local lease is released HERE,
		 * before the readback — -EPERM means our publication is
		 * defeated, the readback is leaseless anyway, and holding the
		 * dead lease across a transient readback failure (the default
		 * arm below) would keep the victim's grants frozen with no
		 * publisher, recreating the containment gap this fix exists
		 * to close.
		 */
		struct mxfs_recov_outcome oc2;
		int orc;

		mxfs_v5_dlm_recovery_release(mp->m_mxfs_dlm, slot);
		orc = mxfs_v5_dlm_recovery_read_outcome(mp->m_mxfs_dlm,
							slot, &oc2);
		switch (orc) {
		case 0:
			/* Lost the refusal-publish race — import the
			 * CANONICAL verdict, validated (item B). */
			mxfs_freplay_import_verdict(mp, slot, &oc2,
						    "publish-conflict");
			set_bit(slot, mp->m_mxfs_foreign_torn_slots);
			return 1;
		case -EBADMSG:
		case -EPROTO:
			/* Ruling item 8: unreadable verdict state is
			 * persistent corruption — fail closed FSWIDE, stop
			 * churning. */
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: conflicting "
				"verdict is UNREADABLE (%d) — PERSISTENT; "
				"failing closed FSWIDE until operator action",
				slot, orc);
			mxfs_quarantine_import_oc(mp, slot, NULL);
			set_bit(slot, mp->m_mxfs_foreign_torn_slots);
			return 1;
		case -ENODATA:
			/* ruling Q3: publish said "quarantined" but
			 * the readback says "no outcome bytes" — an
			 * inconsistent, unstable snapshot.  Never backfill
			 * from inside a publish conflict: drop the
			 * now-unusable lease and re-arm; the next pass's
			 * pre-acquire classification terminalizes it
			 * leaselessly if it is genuinely legacy state, and
			 * never replays. */
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: publish "
				"conflict but readback shows no outcome "
				"bytes — unstable snapshot; will reclassify "
				"(never replay)", slot);
			return 0;
		default:
			/* -EAGAIN / -ENOENT / I/O: the conflict we just hit
			 * is not visible in this read — keep the caller's
			 * retry armed and re-read next pass. */
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: conflicting "
				"verdict readback failed (%d) — will "
				"re-read; nothing latched", slot, orc);
			return 0;
		}
	}
	/* Any other rc = the CAS write itself failed: OUR verdict is not the
	 * published truth — do not enforce or latch it; the retry re-reads
	 * disk state. */
	xfs_alert(mp,
		"MXFS foreign replay slot=%u: terminal refusal publish "
		"FAILED (%d) — nothing latched; will retry", slot, prc);
	return 0;
}

/*
 * 0.89.14 — THE SEALED-BUT-UNREPLAYED WINDOW, made long enough to measure.
 *
 * A fence certificate is sealed (stage FENCED, descriptor unowned) some time
 * BEFORE the dead peer's slice is actually replayed: the seal happens on the
 * prover's proof path and the replay is dispatched afterwards onto this
 * workqueue.  Measured on the 2-node TCP rig, that window is about 8.6 s
 * (P236-FENCE-SEALED to P163-RECOVERY-COMPLETE), which is far too short to
 * steer a returning peer into.
 *
 * The hazard it exists to test: sealing only freezes the LIST of the dead
 * node's journal work.  If a returning incarnation were admitted on the seal
 * alone it could modify a shared metadata block that the survivor then
 * overwrites by replaying the dead node's OLDER update to it — the newer state
 * lost, silently.  The claim under test is that admission is gated on the
 * slice being RECOVERED rather than merely certified.
 *
 * The hold is taken AFTER the execution lease is claimed, so the returning
 * peer cannot simply claim the slice and replay it itself — that is a
 * different (and also correct) outcome, and holding before the claim would
 * measure it by accident instead of the case that matters.
 *
 * Safe to park here: this is workqueue context, not the heartbeat thread —
 * the dead-node notify only sets a bit and queues this work.  Sliced so the
 * task is never in uninterruptible sleep for more than a second at a time, and
 * abandoned early on shutdown.  One-shot: it self-clears when it fires, so a
 * single arming cannot stall every later replay.
 */
static int mxfs_dbg_replay_hold_ms;
module_param_named(dbg_replay_hold_ms, mxfs_dbg_replay_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_replay_hold_ms,
	"DEBUG one-shot: after the recovery execution lease is claimed, hold a dead peer's slice UNREPLAYED for this many ms, so a rejoining node can be driven at the sealed-but-unreplayed window");

/*
 * THE PARTIAL-REPLAY CUT (0.89.18, design-consult ruling
 * docs/rulings/fence-matrix-remaining-gates-and-partial-replay.md).
 *
 * The fence crash matrix has endpoint cuts around the PROOF.  It has nothing
 * around the REPLAY, and the ruling ranks that first among the gaps that can
 * actually corrupt: a durable prefix replayed twice performs a non-idempotent
 * update twice, and a completion marker that advances over an unapplied suffix
 * makes a successor skip work and then discard the only copy of it.
 *
 * Reaching that state is not a matter of picking a cut number, because a
 * foreign-slice replay does NOT write its effects incrementally.  Every image
 * it applies is held in core and submitted ONCE at the end of the pass
 * (l_mxfs_drain_deferred, xfs/xfs_log_recover.c): mid-pass submission can put
 * an intermediate image of a block on the platter ahead of the head
 * transaction that overlays it, which fails the write verifier and gets the
 * whole slice refused.  So the only place a nonempty durable prefix can
 * coexist with an unissued required suffix is INSIDE that final submission —
 * which is exactly where a real crash would leave it, since the submission is
 * many separate writes and nothing makes them atomic.
 *
 * The cut therefore splits the end-of-pass buffer list: the first
 * dbg_replay_cut_prefix buffers are submitted, WAITED FOR and flushed, the
 * remainder are left unissued, and the pass parks there.  Nothing downstream
 * runs, so no completion marker advances, no slice is retired or zeroed, and
 * the source journal is untouched — the harness destroys the node during the
 * park and a successor meets a half-applied replay.
 *
 * Filtered by victim slot AND victim incarnation, never by slot alone: a slot
 * number is reused, and a one-shot that fires on the wrong victim is not a
 * deterministic test.  If the hold expires without the crash the lap is
 * CONTAMINATED, the remainder is submitted so the filesystem is left
 * consistent, and the harness must reject the lap rather than read its
 * outcome.  Never set in production.
 */
int mxfs_dbg_replay_cut_prefix;
module_param_named(dbg_replay_cut_prefix, mxfs_dbg_replay_cut_prefix, int, 0644);
MODULE_PARM_DESC(dbg_replay_cut_prefix,
	"DEBUG one-shot: in a foreign-slice replay, make only the first N of the end-of-pass buffers durable, leave the rest unissued and park (0=off).  The suffix must be non-empty or the cut is refused as vacuous");
int mxfs_dbg_replay_cut_slot = -1;
module_param_named(dbg_replay_cut_slot, mxfs_dbg_replay_cut_slot, int, 0644);
MODULE_PARM_DESC(dbg_replay_cut_slot,
	"DEBUG: the victim SLOT dbg_replay_cut_prefix applies to (-1 = any)");
unsigned long long mxfs_dbg_replay_cut_epoch;
module_param_named(dbg_replay_cut_epoch, mxfs_dbg_replay_cut_epoch, ullong, 0644);
MODULE_PARM_DESC(dbg_replay_cut_epoch,
	"DEBUG: the victim INCARNATION dbg_replay_cut_prefix applies to (0 = any).  A slot number alone is reused, so a lap that must be deterministic sets this too");
int mxfs_dbg_replay_cut_hold_ms = 20000;
module_param_named(dbg_replay_cut_hold_ms, mxfs_dbg_replay_cut_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_replay_cut_hold_ms,
	"DEBUG: how long the replay parks at a dbg_replay_cut_prefix cut (default 20000 ms; keep it under the 62 s dead window)");

/*
 * v0.5.0 live foreign-slice replay of a dead peer's log slice.
 *
 * The dead node's fsync-acknowledged metadata may exist only in its
 * per-node log slice — without this, survivors serve stale data until a
 * future mount claims the slice (crash_consistency: 113 acked records,
 * survivors saw 1).  The flush before the replay is load-bearing twice
 * over: it (a) pushes OUR logged-but-unwritten versions of shared blocks
 * to disk so pass2's LSN gating compares against current disk state, and
 * (b) invalidates our cached AG/inode views.  The flush after drops any
 * cached view of ranges the replay rewrote, so subsequent FUA reads see
 * the recovered metadata.
 */
void
mxfs_dlm_foreign_replay_work_fn(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_foreign_replay_work);
	struct mxfs_recovtask	recov;
	unsigned int		slot;

	/*
	 * (incident474, design-consult b2/b3): this whole function runs as
	 * REGISTERED RECOVERY CONTEXT.  The inode DLM acquire path treats a
	 * registered task specially — an acquire timeout requeues instead of
	 * escalating to shutdown (b3), and the REPLAY phase asserts that
	 * slice replay never enters inode DLM acquisition at all (b2).
	 */
	mxfs_recovtask_enter(&recov, MXFS_RECOV_PHASE_CLEANUP);
	/* D-0514 provenance: one line per instance so the trail shows
	 * which instance a death was queued behind. */
	mxfs_probe("mxfs: P-FREPLAY-ENTER inv=%d dead_slots=0x%llx sweep_pending=0x%llx\n",
		atomic_inc_return(&mxfs_freplay_work_inv),
		(unsigned long long)mp->m_mxfs_foreign_dead_slots[0],
		(unsigned long long)mp->m_mxfs_sweep_pending_slots[0]);

	for_each_set_bit(slot, mp->m_mxfs_foreign_dead_slots, 64) {
		int	auth;
		int	crc;

		if (xfs_is_shutdown(mp)) {
			mxfs_recovtask_exit(&recov);
			return;
		}
		/*
		 * (#21): a TORN refusal is deterministic — the same
		 * slice replays to the same refusal.  The latch keeps the
		 * slot frozen (dead bit stays set, nothing published) without
		 * burning a replay+refusal cycle every 30s reap pass (#11).
		 * A new death notify for the slot clears it.
		 */
		if (test_bit(slot, mp->m_mxfs_foreign_torn_slots)) {
			pr_warn_ratelimited(
	"mxfs: foreign replay slot=%u latched TORN — slice stays frozen and unpublished; needs repair or token-authorized redo\n",
				slot);
			continue;
		}
		/*
		 * put_super NULLs m_mxfs_dlm and then frees the
		 * ctx in v5_shutdown.  An instance queued after the NULL
		 * (dead-node notify from the still-live heartbeat thread)
		 * must bail here rather than call into a freed ctx.  The
		 * dead-slot bit stays set — nothing is published, nothing
		 * is consumed; the unmounted node has no recovery duty.
		 */
		if (!mp->m_mxfs_dlm) {
			mxfs_recovtask_exit(&recov);
			return;
		}

		/*
		 * — THE REPLAY GATE, ahead of everything else.
		 *
		 * D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION: this loop used to
		 * replay a dead peer's journal slice with no evidence that the
		 * peer had actually been excluded from the LUN.  Measured on
		 * the 32-node rig, exactly ONE survivor's PREEMPT AND
		 * ABORT completes and 30 lose the race — and the replayer is
		 * elected by lowest_live_slot, so it is usually one of the
		 * losers.  In the captured run it dispatched replay 22 ms
		 * after its own proves_excl=0.  Replaying a journal into
		 * shared metadata while its owner may still be writing is how
		 * two nodes write the same blocks.
		 *
		 * The authority is a fence CERTIFICATE in the victim's own
		 * heartbeat sector, written by whichever node did prove the
		 * exclusion.  acquire() consumes it and takes the recovery
		 * execution lease, which we then hold for the whole replay.
		 *
		 * -EPERM is the WAIT state, not a failure: a prover may still
		 * be mid-attempt.  Re-arm and ask again — there is no timeout
		 * after which an unproven slice becomes replayable (design-consult
		 * ruling, Q1).
		 */
		/*
		 * (design-consult ruling): classify BEFORE acquire.  No lease
		 * is ever obtainable over a quarantined descriptor — the
		 * claim path's certificate evaluator refuses it before the
		 * owner-reacquire check — so a terminal slot must be
		 * recognized and disposed from the platter snapshot, not
		 * from a lease we cannot get.  (The shape checked
		 * AFTER acquire and was unreachable for exactly the legacy
		 * case it was built for.)
		 */
		crc = mxfs_freplay_classify_terminal(mp, slot);
		if (crc > 0)
			continue;	/* terminally disposed: imported+latched */
		if (crc < 0) {
			set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
			mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS,
					"freplay-classify");
			continue;
		}
		/*
		 * (design-consult ruling Q5, D-FSWIDE-TERMINAL-REPLAY-
		 * CONTINUES-407): once an FSWIDE terminal is in force — ours
		 * (the publisher imports at once) or imported from a peer —
		 * no new execution lease is taken and no replay starts; the
		 * slot stays frozen (dead bit set, nothing published, no
		 * re-arm: the state is terminal until remount, a retry would
		 * only churn).  Classification above still runs so other
		 * victims' terminal records are imported.
		 */
		if (READ_ONCE(mp->m_mxfs_quar_fswide)) {
			pr_warn_ratelimited(
	"mxfs: P-RMAN-FSWIDE-HALT foreign replay slot=%u NOT claimed — an FSWIDE terminal quarantine is in force; the slice stays frozen and unpublished until operator repair + remount\n",
				slot);
			continue;
		}
		auth = mxfs_v5_dlm_recovery_acquire(mp->m_mxfs_dlm, slot);
		if (auth == -EPERM) {
			/*
			 * ruling Q3: a quarantine may have landed
			 * between our classification read and the claim —
			 * reclassify ONCE; only a still-nonterminal slot
			 * keeps the ordinary wait-state handling below.
			 */
			crc = mxfs_freplay_classify_terminal(mp, slot);
			if (crc > 0)
				continue;
			/* review: a transient reclassify is classify
			 * churn, not a missing fence — re-arm under the
			 * classify label so the alert below doesn't
			 * misdescribe it.  crc==0 (claim refused but platter
			 * nonterminal) falls through to the fence re-arm,
			 * which is the correct wait state for it. */
			if (crc < 0) {
				set_bit(MXFS_REAPF_FREPLAY,
					&mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS,
						"freplay-classify");
				continue;
			}
		}
		if (auth) {
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: NOT replayed — "
				"no proven exclusion of the dead node (%d).  "
				"Its slice stays unreplayed and its grants "
				"stay frozen until a fence certificate exists; "
				"this is a refusal, not a retry-and-forget",
				slot, auth);
			set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
			mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-fence");
			continue;
		}

		/* See dbg_replay_hold_ms: the lease is ours, the certificate is
		 * sealed, and the slice is NOT yet replayed.  That is the state
		 * a rejoining node must not be admitted in. */
		if (mxfs_dbg_replay_hold_ms > 0) {
			int	want = mxfs_dbg_replay_hold_ms;
			int	held = 0;

			mxfs_dbg_replay_hold_ms = 0;		/* one-shot */
			xfs_alert(mp,
				"MXFS P-FREPLAY-HOLD slot=%u ms=%d — TEST ONLY: "
				"the recovery execution lease is CLAIMED and the "
				"fence certificate is sealed, but the slice is "
				"NOT replayed.  Holding here so a rejoining node "
				"meets exactly this window; it must not be "
				"admitted on the seal alone",
				slot, want);
			while (held < want && !xfs_is_shutdown(mp)) {
				msleep(1000);
				held += 1000;
			}
			xfs_alert(mp,
				"MXFS P-FREPLAY-HOLD-END slot=%u held_ms=%d "
				"shutdown=%d — releasing the slice to replay",
				slot, held, xfs_is_shutdown(mp) ? 1 : 0);
		}

		/*
		 * design review item 2/5: an incomplete invalidation BEFORE the
		 * replay means pass 2's gate compares against a cached view
		 * instead of current disk state; an incomplete one AFTER means
		 * an un-destaged buffer of ours will later be written over an
		 * image the replay just recovered.  Both silently corrupt, and
		 * both are re-armable — the dead slot's bit stays set and the
		 * pending marker survives, so refuse the slice instead.
		 */
		if (mxfs_dlm_peer_joined_flush(mp)) {
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: cached views "
				"could not be dropped before replay — slice "
				"NOT replayed; will retry", slot);
			set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
			mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-retry");
			continue;
		}
		/*
		 * design review item 6C: same discarded return value as the
		 * mount barrier had — a failed replay was published as a
		 * recovered one.  Refuse and re-arm instead; the dead slot's
		 * bit and its durable pending marker both survive, so the retry
		 * is a genuine retry and not a lost slice.  (mxfs_has_log_slices
		 * false = unsliced FS: the peer shares our log, which our own
		 * mount already recovered, so there is nothing to replay.)
		 */
		/*
		 * (D-RECOV-ADVANCE-UNBOUNDED-RETRY, ruling 5): once the
		 * durable descriptor WE hold proves IMAGES_REPLAYED, a retry of
		 * the completion ladder must not re-replay the slice — only the
		 * remaining milestones are owed.  Anything short of that (no
		 * lease, other owner, read failure) replays as before.
		 */
		{
			unsigned int	dstage = 0;

			if (mxfs_v5_dlm_recovery_stage(mp->m_mxfs_dlm, slot,
						       &dstage) == 0 &&
			    dstage >= MXFS_RECOV_STAGE_IMAGES_REPLAYED) {
				xfs_notice(mp,
					"MXFS foreign replay slot=%u: descriptor already at stage %u (IMAGES_REPLAYED durable) — skipping the slice replay, completing the remaining ladder",
					slot, dstage);
				goto complete_ladder;
			}
		}
		if (mxfs_has_log_slices(mp)) {
			struct mxfs_freplay_verdict	fv;
			int	rrc;

			/* b2: slice replay is buffer-level ONLY —
			 * stamp REPLAY so the inode DLM acquire path can
			 * assert it never gets entered from here. */
			mxfs_recovtask_set_phase(MXFS_RECOV_PHASE_REPLAY);
			rrc = mxfs_xlog_recover_foreign_slice(mp, slot, &fv);
			mxfs_recovtask_set_phase(MXFS_RECOV_PHASE_CLEANUP);
			if (rrc && fv.reason != MXFS_FREPLAY_REASON_NONE) {
				/*
				 * the publish/conflict state machine
				 * lives in mxfs_freplay_publish_refusal() so
				 * the mount barrier drives the IDENTICAL
				 * publication (review item D).  A
				 * terminal return already imported, latched
				 * and released inside the helper; a transient
				 * return latched nothing, so re-arm the reap.
				 */
				if (mxfs_freplay_publish_refusal(mp, slot,
								 &fv, rrc))
					continue;
				set_bit(MXFS_REAPF_FREPLAY,
					&mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS,
						"freplay-publish");
				continue;
			}
			if (rrc) {
				xfs_alert(mp,
					"MXFS foreign replay slot=%u: slice replay "
					"FAILED — recovery NOT published; will retry",
					slot);
				set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-retry");
				continue;
			}
			/*
			 * 0.85.0: park the census verdict for the ladder's
			 * IMAGES_REPLAYED milestone — the RECOVER extent
			 * list (the OPEN case) or the explicit zero.  The
			 * list is copied; the verdict is freed here.
			 */
			if (mxfs_freplay_park_census(mp, slot, &fv)) {
				set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-park");
				continue;
			}
		} else {
			/* unsliced: our own mount recovery covered the log */
			mxfs_v5_dlm_recovery_set_census_zero(mp->m_mxfs_dlm,
							     (int)slot);
		}
		if (mxfs_dlm_peer_joined_flush(mp)) {
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: slice replayed "
				"but our cached views could not be dropped "
				"afterwards — recovery NOT published; will "
				"retry", slot);
			set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
			mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-retry");
			continue;
		}
		/*
		 * design review item 1: "durably replayed" below was not true.
		 * The peer_joined_flush above bottoms out in
		 * mxfs_blkdev_flush_epoch(), which under mxfs_fua_disable
		 * (the default) issues NO device flush at all — it certifies
		 * peer-VISIBILITY, not survival of a target power loss.  The
		 * completion that follows purges the dead node's CAW
		 * authority bits and zeroes its heartbeat record, i.e.
		 * destroys the only two pieces of evidence that would make
		 * anyone redo this replay.  Losing the target's write cache
		 * at that moment loses the recovery permanently.  Make it
		 * genuinely durable first, and skip the completion if we
		 * cannot: the dead slot stays pending and re-arms.
		 */
		if (mxfs_blkdev_flush_durable(mp)) {
			xfs_alert(mp,
				"MXFS foreign replay slot=%u: durability "
				"flush FAILED — recovery NOT published; the "
				"slot stays pending and will be retried", slot);
			set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
			mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "freplay-retry");
			continue;
		}
		/*
		 * D2: only now — with the slice
		 * durably replayed — does the dead node's state become
		 * consumable.  recovery_complete purges the shared lock
		 * tables and zeroes the dead HB slot, which is the
		 * cluster-wide signal for every peer's deferred local purge
		 * (the old code purged in expire_cb BEFORE the async replay
		 * ran — peers promoted into the dead node's torn,
		 * unreplayed state; PROVEN drc@16 r13).  The pending bit is
		 * cleared only after: if we die mid-replay it stays set and
		 * the survivors' re-election sweep re-arms the replay
		 * (LSN-gated, idempotent).
		 *
		 * item 6D: the completion itself can fail.  Leave the
		 * dead-slot bit SET when it does, so the next dead-node
		 * notify (or re-election sweep) re-enters this loop rather
		 * than us believing the recovery landed.
		 */
complete_ladder:
		{
			struct mxfs_recov_complete_res	cres;

			mxfs_v5_dlm_recovery_complete2(mp->m_mxfs_dlm, slot,
						       &cres);
			switch (cres.outcome) {
			case MXFS_RECOV_COMPLETE_PUBLISHED:
				break;
			case MXFS_RECOV_COMPLETE_RETRY:
				/*
				 * bounded, classified retry — the DLM
				 * chose the delay (exponential, capped by its
				 * deadline; 0 = the milestone had committed).
				 */
				xfs_alert(mp,
					"MXFS foreign replay slot=%u: publication step '%s' failed rc=%d attempt=%u — retrying in %u ms (bounded; the dead node stays pending, its grants stay held)",
					slot, cres.site, cres.rc, cres.attempts,
					cres.retry_ms);
				set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, cres.retry_ms ? cres.retry_ms : 1,
						"freplay-retry");
				continue;
			case MXFS_RECOV_COMPLETE_SUPERSEDED:
				/*
				 * The descriptor changed hands, was published by
				 * another survivor, or is terminal by design.
				 * Our work on it is cancelled: nothing re-armed.
				 * The dead-slot bit is dropped — the monitor's
				 * recovered_cb / a later re-election re-arms it
				 * if this node is ever owed the slice again.
				 */
				xfs_alert(mp,
					"MXFS foreign replay slot=%u: publication step '%s' rc=%d — SUPERSEDED (owner changed, published elsewhere, or terminal); this node's recovery identity is cancelled, nothing re-armed",
					slot, cres.site, cres.rc);
				clear_bit(slot, mp->m_mxfs_foreign_dead_slots);
				continue;
			case MXFS_RECOV_COMPLETE_OBLIGATIONS_OPEN: {
				/*
				 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED):
				 * the descriptor is durably at IMAGES_REPLAYED
				 * with an OPEN obligation record, the dead
				 * node's grants are retired and its AGs are
				 * frozen.  Before completing: every OTHER dead
				 * slot that is neither terminal nor yet at
				 * IMAGES_REPLAYED must be replayed first — if
				 * one of them was this case's previous custodian
				 * its committed completion frees must be home
				 * before any bnobt query, or a freed extent
				 * reads EMPTY and is freed twice.  Deferred
				 * cases keep their freeze; the worker re-enters
				 * once the other slice lands.
				 */
				unsigned int	dep;
				int		erc;

				dep = mxfs_freplay_open_case_blocked_by(mp, slot);
				if (dep < 64) {
					xfs_alert(mp,
						"MXFS foreign replay slot=%u: P-OBL-DEFER — the OPEN obligation case waits for dead slot %u to reach IMAGES_REPLAYED (a prior custodian's completion frees must be home first); freeze retained",
						slot, dep);
					set_bit(MXFS_REAPF_FREPLAY,
						&mp->m_mxfs_reap_duties);
					mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS,
							"obl-defer");
					continue;
				}
				erc = mxfs_recov_obl_complete(mp, slot);
				if (erc == 0)
					goto complete_ladder;
				if (erc > 0) {
					/* a TERMINAL outcome was published: the
					 * next pass classifies and latches it */
					set_bit(MXFS_REAPF_FREPLAY,
						&mp->m_mxfs_reap_duties);
					mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS,
							"obl-terminal");
					continue;
				}
				xfs_alert(mp,
					"MXFS foreign replay slot=%u: obligation completion did not finish rc=%d — the case stays OPEN (freeze retained, grants retired), retrying",
					slot, erc);
				set_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
				mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "obl-retry");
				continue;
			}
			case MXFS_RECOV_COMPLETE_FATAL_INVARIANT:
			case MXFS_RECOV_COMPLETE_FATAL_WITHDRAW:
			default:
				/*
				 * ruling 1/3: the DLM has done its part
				 * (INVARIANT: descriptor untouched for
				 * inspection; WITHDRAW: lease durably given
				 * back).  This node must now stop being the
				 * positional elected owner: fail-stop the
				 * mount so the next-lowest survivor is elected
				 * and the recovery proceeds cluster-wide.  A
				 * loud, terminating service failure — never a
				 * quiet loop.
				 */
				xfs_alert(mp,
					"MXFS foreign replay slot=%u: publication step '%s' rc=%d — %s; WITHDRAWING this mount (fail-stop) so a survivor is elected to finish the recovery",
					slot, cres.site, cres.rc,
					cres.outcome == MXFS_RECOV_COMPLETE_FATAL_INVARIANT ?
					"INVARIANT VIOLATION (descriptor left untouched)" :
					"bounded completion deadline exceeded (lease given back)");
				clear_bit(slot, mp->m_mxfs_foreign_dead_slots);
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
				return;
			}
		}
		clear_bit(slot, mp->m_mxfs_foreign_dead_slots);
		/*
		 * C8 (design review invariant 8): the dead node's unlinked
		 * bucket is now consistent (slice replayed) but ORPHANED —
		 * no live node's mount recovery covers it until some future
		 * mount claims slot `slot`.  Its zombies (deferred
		 * open-unlink reaps, mid-flight unlinks) would leak
		 * unbounded.  This elected survivor adopts the bucket.
		 *
		 * (incident474, design-consult b2): but NOT here, between
		 * slice replays.  The sweep takes inode EX grants; running
		 * it while other victims' slices are still pending is the
		 * proven 474 ordering deadlock (sweep blocks on an unpurged
		 * victim's grant whose purge is queued behind this very work
		 * item).  Record the duty; (D-0514): the sweep runs in
		 * the reap worker's own work item, never in this one.
		 */
		set_bit(slot, mp->m_mxfs_sweep_pending_slots);
	}
	/*
	 * (D-TWO-VICTIM-DEATH-SECOND-SLICE-REPLAY-NOT-STARTED-0514,
	 * 0.53.3): the sweeps NEVER run inside this work item any more.
	 *
	 * PROVEN on the rig (chain 52, 0.53.2, tests/evidence/
	 * 20260829T130114Z_d0514_forced_s447b/recov_test1.txt): this work
	 * item is ONE work_struct.  When its tail sat in the inline bucket
	 * sweep of victim A, victim B's death notify printed P-FREPLAY-NOTIFY
	 * busy=RUNNING and B's instance could not ENTER until A's sweep
	 * returned — and a sweep step (read_agi / iget / inodegc_flush) that
	 * waits on a grant B still holds (B dead 62 s, undetected; chain 49
	 * lap 1: P97-SWEEP-START slot=29 at 12:27:23.907, no SWEEP-DONE, B
	 * elected 0.8 s later, no lease ever) returns only after B's replay
	 * purges that grant — which is queued behind this very work item.
	 * The between-slot bail below could never interrupt a sweep already
	 * inside a wait; the b2 hazard had merely moved to the far
	 * side of the batch.
	 *
	 * The reap worker (mxfs_reap_worker, a SEPARATE delayed work) already
	 * re-drives this work item FIRST and runs every m_mxfs_sweep_pending
	 * slot under the bitmap_empty(dead_slots) guard; a sweep blocked
	 * there on a fresh victim's grant is unblocked by that victim's
	 * replay running concurrently here.  The bits set above are the
	 * durable duty; the batch-complete reap_sched below is the wakeup.
	 */
	if (!bitmap_empty(mp->m_mxfs_sweep_pending_slots, 64))
		mxfs_probe("mxfs: P-FREPLAY-PHASE inv=%d phase=SWEEP-DEFERRED sweep_pending=0x%llx dead_slots=0x%llx — bucket sweeps handed to the reap worker (D-0514 fix)\n",
			atomic_read(&mxfs_freplay_work_inv),
			(unsigned long long)mp->m_mxfs_sweep_pending_slots[0],
			(unsigned long long)mp->m_mxfs_foreign_dead_slots[0]);
	mxfs_probe("mxfs: P-FREPLAY-EXIT inv=%d dead_slots=0x%llx sweep_pending=0x%llx\n",
		atomic_read(&mxfs_freplay_work_inv),
		(unsigned long long)mp->m_mxfs_foreign_dead_slots[0],
		(unsigned long long)mp->m_mxfs_sweep_pending_slots[0]);
	/* a completed recovery batch is a trigger for the guarded
	 * unclaimed-bucket pass — the batch may itself have left unclaimed
	 * residue (and covers the "survivor died mid-reap" composition). */
	set_bit(MXFS_REAPF_UBSCAN, &mp->m_mxfs_reap_duties);
	mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "batch-complete");
	mxfs_recovtask_exit(&recov);
}

/*
 * Heartbeat-thread context (must not block): record the dead slot and
 * punt the replay to a worker.  set_bit before queue_work — if the work
 * is already queued, the running/pending instance's for_each_set_bit
 * pass picks the new slot up.
 */
void
mxfs_dlm_dead_node_notify(
	void			*data,
	uint32_t		dead_slot)
{
	struct xfs_mount	*mp = data;

	if (dead_slot >= 64)
		return;
	/* (#21): a NEW death event means a new incarnation wrote the
	 * slice — a torn latch from the previous tenant's refusal no longer
	 * describes its content.  Clear before set so the work fn attempts
	 * exactly one fresh replay. */
	clear_bit(dead_slot, mp->m_mxfs_foreign_torn_slots);
	set_bit(dead_slot, mp->m_mxfs_foreign_dead_slots);
	{
		/* D-0514 provenance: was the work item already running
		 * (busy & WORK_BUSY_RUNNING) when this death arrived?  A
		 * running instance past its dead-slot pass cannot pick the
		 * slot up; the requeued instance runs only after it returns. */
		unsigned int busy = work_busy(&mp->m_mxfs_foreign_replay_work);
		bool q = queue_work(system_unbound_wq,
				    &mp->m_mxfs_foreign_replay_work);

		mxfs_probe("mxfs: P-FREPLAY-NOTIFY slot=%u qret=%d busy=%s%s inv=%d dead_slots=0x%llx\n",
			dead_slot, q ? 1 : 0,
			(busy & WORK_BUSY_RUNNING) ? "RUNNING" : "",
			(busy & WORK_BUSY_PENDING) ? "+PENDING" : "",
			atomic_read(&mxfs_freplay_work_inv),
			(unsigned long long)mp->m_mxfs_foreign_dead_slots[0]);
	}
}

/*
 * (#92): heartbeat-thread context (must not block).  The disklock
 * monitor FUA-confirmed the slot cleanly released — the tenant unmounted;
 * nothing died and its slice needs no replay.  Any dead/torn latch we hold
 * for the slot describes a tenancy that no longer exists (the observed
 * livelock: recovery-pending latched forever against a released slot), so
 * drop both.  Clearing a dead bit can complete the no-victim-pending
 * condition the deferred bucket sweeps wait on, and nothing else
 * re-evaluates it — re-drive the replay worker, whose tail runs the
 * deferred sweeps and re-arms the reap duties.
 */
void
mxfs_dlm_clean_depart_notify(
	void			*data,
	uint32_t		slot)
{
	struct xfs_mount	*mp = data;

	if (slot >= 64)
		return;
	clear_bit(slot, mp->m_mxfs_foreign_torn_slots);
	if (test_and_clear_bit(slot, mp->m_mxfs_foreign_dead_slots)) {
		xfs_notice(mp,
	"MXFS clean departure slot=%u: dead/torn latch dropped — peer released cleanly, no replay",
			   slot);
		queue_work(system_unbound_wq,
			   &mp->m_mxfs_foreign_replay_work);
	}
}

/*
 * (D-RELEASEALL stuck-notify wiring, design-consult ruling): the CAW
 * layer latched owed_failed — it has proven it can no longer clear this
 * node's bits out of the on-disk slot table.  Peers block behind those bits
 * forever, so this is a cluster-wide liveness fault and the one correct
 * local response is to stop writing.  SHUTDOWN_META_IO_ERROR, not
 * CORRUPT_INCORE: nothing in memory is wrong — the node lost its ability
 * to complete metadata coordination I/O.
 *
 * The CAW layer records the failure state SYNCHRONOUSLY before this fires
 * (ops_closed, departed_clean revoked), so a lost or canceled work item
 * cannot un-decide anything: stop()'s verdict reads the recorded state, and
 * this shutdown is the runtime response, not the safety latch.
 */
void
mxfs_dlm_stuck_work_fn(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_dlm_stuck_work);

	xfs_alert(mp,
	"mxfs: DLM cleanup permanently stuck — this node cannot clear its slot-table bits and peers block behind them; forcing shutdown");
	xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
}

/*
 * DLM worker/defer context.  Contractually queue-only (see
 * caw_teardown_escalate_work in dlm_caw.c): invoking the shutdown here
 * would make the DLM's teardown liveness depend on upper-layer behaviour.
 */
void
mxfs_dlm_stuck_notify(
	void			*data)
{
	struct xfs_mount	*mp = data;

	queue_work(system_unbound_wq, &mp->m_mxfs_dlm_stuck_work);
}
