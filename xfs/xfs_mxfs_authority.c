// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode authority tenures and inactive-release certificates
 */
#define MXFS_TU_ID 5	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * ─────────────────────────────────────────────────────────────────────────
 * MXFS DURABLE-AUTHORITY STATE MACHINE (step 5.3(c))
 *
 * Part of D-FOREIGN-REPLAY-UNGATED-IMAGES.  A logged metadata image may only
 * be replayed onto a foreign (dead peer's) journal slice if it carries proof
 * that the logging node durably held EX on the resource backing the object.
 * These helpers own the "did this node durably hold EX, and under which
 * tenure" question.  See the MXFS_AUTH_* block in xfs_inode.h for why
 * i_dlm_mode cannot answer it.
 *
 * Contract (design-consult ruling):
 *   - every field written under i_dlm_lock, only through these helpers;
 *   - i_mxfs_auth_gen bumped on EVERY revoke and EVERY release-begin, never
 *     on install — an acquire snapshots it BEFORE descending into the DLM
 *     and re-checks at install, which is the only thing that rejects a stale
 *     completion across a full EX -> NL -> EX cycle;
 *   - a tenure is installed ONLY from a struct mxfs_grant_result filled by
 *     the granting CAS itself (dlm/dlm_caw.c caw_grant_result_fill), never
 *     from a cache or a read-back;
 *   - RELEASING and UNPUBLISHED_EX are both non-proving.  Fail-closed: any
 *     doubt leaves the inode non-proving, which costs replay coverage but
 *     can never authorise a foreign apply.
 * ─────────────────────────────────────────────────────────────────────────
 */
atomic64_t mxfs_auth_install_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_install_advance_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_revoke_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_relbegin_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_unpub_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_publive_n = ATOMIC64_INIT(0);
/*
 * (design-consult ruling A): a phantom-recovery arm proved the wire lost a
 * grant the cache still believed in while the certificate was still proving.
 * The certificate is invalidated AT DETECTION (before any lock drop, log
 * formatting, or re-acquire attempt), not left for the lowering backstop —
 * the backstop stays reserved for genuinely uninstrumented lowering.
 */
atomic64_t mxfs_auth_phantom_n = ATOMIC64_INIT(0);
/* refusal reasons — the population measurements the ruling asked for */
atomic64_t mxfs_auth_ref_novalid_n = ATOMIC64_INIT(0);
/*
 * novalid was 100% of refusals on the 0.11.434 rig lap, which is a
 * useless answer — it conflates three DIFFERENT faults with three different
 * fixes.  Split at the point of refusal:
 *   nogres  — the acquire path passed no result struct at all (a caller that
 *             predates the out-parameter; a plumbing hole in THAT caller);
 *   notvalid— a result arrived but the granting CAS never marked it valid
 *             (caw_grant_result_fill declined — the grant path is the hole);
 *   noepoch — valid, but grant_epoch == 0 (the CAS filled a result without an
 *             epoch: the epoch source is the hole).
 * The three sum to novalid_n, which is kept so the totals stay comparable
 * with the snapshot.
 */
atomic64_t mxfs_auth_ref_nogres_n = ATOMIC64_INIT(0);
/*
 * the split above did NOT survive contact with the rig.
 * `notvalid` took 2863 of 2863 refusals because `gres->valid` was a boolean
 * whose false case meant BOTH "we held a read grant" (benign) and "we held a
 * writing grant with no epoch" (a real gap) — and the `shared` bucket that was
 * supposed to separate them was structurally UNREACHABLE, because the !valid
 * test returned before the mode test ever ran.  Its 0 was not a measurement.
 *
 * The classification now happens at snapshot construction (enum
 * mxfs_grant_auth_status) where the mode and the epoch are one coherent image,
 * and the refusal is counted by that tag.  Every bucket is reachable by
 * construction, and NONWRITE_MODE vs WRITE_ZERO_EPOCH — the two the boolean
 * fused — are now distinct populations.
 */
atomic64_t mxfs_auth_ref_status_n[MXFS_GAUTH_STATUS_MAX];
atomic64_t mxfs_auth_ref_stalegen_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_ref_releasing_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_ref_unpub_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_ref_routing_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_ref_reclaim_n = ATOMIC64_INIT(0);
/* acquires that made no provenance claim at all (probe/nudge callers) —
 * counted so the install denominator is the WHOLE acquire population and a
 * low install rate cannot be mistaken for a refusal problem. */
atomic64_t mxfs_auth_nosnap_n = ATOMIC64_INIT(0);

/* Population of install ATTEMPTS by outcome, the aggregate of the per-inode
 * i_mxfs_auth_try record.  Indexed by MXFS_AUTH_TRY_*. */
atomic64_t mxfs_auth_try_n[MXFS_AUTH_TRY_MAX];

/*
 * Record ONE install attempt on the inode (/ ruling item 2).
 *
 * Called on every exit from the install helper — refusals AND successes — so
 * the pair (i_mxfs_auth_try, i_mxfs_auth_try_gen) always answers "what
 * happened the last time anything tried to install authority here, and was
 * that before or after the event that left this inode non-proving".
 *
 * i_dlm_lock is held by every caller; the fields are also read under
 * i_flags_lock at the dirty point, so use WRITE_ONCE to keep that read from
 * tearing across a compiler-split store.
 */
static void
mxfs_inode_authority_note_try_locked(struct xfs_inode *ip, uint8_t why,
				     uint8_t mode, uint64_t epoch, u32 line)
{
	BUILD_BUG_ON(MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_STATUS_MAX >
		     MXFS_AUTH_TRY_MAX);
	if (why >= MXFS_AUTH_TRY_MAX)
		why = MXFS_AUTH_TRY_NONE;
	WRITE_ONCE(ip->i_mxfs_auth_try, why);
	WRITE_ONCE(ip->i_mxfs_auth_try_mode, mode);
	WRITE_ONCE(ip->i_mxfs_auth_try_line, line);
	WRITE_ONCE(ip->i_mxfs_auth_try_epoch, epoch);
	WRITE_ONCE(ip->i_mxfs_auth_try_gen, ip->i_mxfs_auth_gen);
	atomic64_inc(&mxfs_auth_try_n[why]);
}

/*
 * Drop every authority claim on ip.
 *
 * The gen bump is UNCONDITIONAL, even when no tenure is currently installed.
 * An acquire that has already completed its granting CAS but has not yet won
 * i_dlm_lock leaves this state machine reading NONE while a REAL on-disk
 * grant exists; if a release drops that grant inside that window, the late
 * completion would otherwise install a dead epoch.  The snapshot/re-check
 * pair is the only mechanism that sees that window, and it only works if
 * every relinquishment moves the counter.
 */
/*
 * fix shape A (design-consult ruling, STOP-SHIP 1 of the re-review): while
 * xfs_inactive is dirtying under its inactivation certificate (ACTIVE), no
 * release-side actor may move that certificate — the raw EX is held for the
 * whole truncate+ifree and nothing else owns this I_FREEING inode.  Record
 * the loss loudly; the INACT-EXREL revoke then finds GONE and fails closed
 * with this line as the forensic answer to "who moved it".
 */
static atomic64_t mxfs_inact_cert_lost_n;
static void
mxfs_inact_cert_note_loss_locked(struct xfs_inode *ip, const char *what,
				 u32 line)
{
	static atomic_t n = ATOMIC_INIT(0);

	if (ip->i_mxfs_auth_inact != MXFS_INACT_CERT_ACTIVE)
		return;
	ip->i_mxfs_auth_inact = MXFS_INACT_CERT_LOST;
	atomic64_inc(&mxfs_inact_cert_lost_n);
	if (atomic_inc_return(&n) <= 200)
		pr_err("mxfs: P-INACT-CERT-LOST ino=%llu by=%s L%u:%u auth_state=%u auth_epoch=%llu dlm_mode=%u dlm_state=%u comm=%s — a release-side actor moved an ACTIVE inactivation certificate under the raw EX\n",
			(unsigned long long)ip->i_ino, what, MXFS_SITE_ARGS(line),
			(unsigned)ip->i_mxfs_auth_state,
			(unsigned long long)ip->i_mxfs_auth_epoch,
			(unsigned)ip->i_dlm_mode, (unsigned)ip->i_dlm_state,
			current->comm);
}

void
mxfs_inode_authority_revoke_locked(struct xfs_inode *ip, u32 line)
{
	mxfs_inact_cert_note_loss_locked(ip, "revoke", line);
	ip->i_mxfs_auth_gen++;
	ip->i_mxfs_auth_line = line;
	if (ip->i_mxfs_auth_state == MXFS_AUTH_NONE)
		return;
	/* tuple publication — see i_mxfs_auth_seq */
	write_seqcount_begin(&ip->i_mxfs_auth_seq);
	ip->i_mxfs_auth_state = MXFS_AUTH_NONE;
	ip->i_mxfs_auth_kind = 0;
	ip->i_mxfs_auth_reaffirm = 0;
	ip->i_mxfs_auth_resource = 0;
	ip->i_mxfs_auth_epoch = 0;
	ip->i_mxfs_auth_lineage = 0;
	ip->i_mxfs_auth_incarn = 0;
	write_seqcount_end(&ip->i_mxfs_auth_seq);
	atomic64_inc(&mxfs_auth_revoke_n);
}

/*
 * Mark the start of a release.  Hooked at release-BEGIN — before the slot is
 * marked releasing, before any unlock/handoff is sent, before a peer can
 * begin acquiring, and before any routing change.  All of those precede the
 * i_dlm_mode = NL cleanup, which is why the mode-lowering backstop below is
 * a backstop and not the invariant.
 *
 * The tenure identity is retained (RELEASING is never proving, and install
 * refuses to resurrect it) purely so a forensic dump can still name the
 * tenure that was being given up.
 */
void
mxfs_inode_authority_begin_release_locked(struct xfs_inode *ip, u32 line)
{
	mxfs_inact_cert_note_loss_locked(ip, "begin_release", line);
	ip->i_mxfs_auth_gen++;
	ip->i_mxfs_auth_line = line;
	if (ip->i_mxfs_auth_state == MXFS_AUTH_NONE ||
	    ip->i_mxfs_auth_state == MXFS_AUTH_RELEASING)
		return;
	write_seqcount_begin(&ip->i_mxfs_auth_seq);
	ip->i_mxfs_auth_state = MXFS_AUTH_RELEASING;
	write_seqcount_end(&ip->i_mxfs_auth_seq);
	atomic64_inc(&mxfs_auth_relbegin_n);
}

/*
 * publication-point tripwire (ruling item 3).
 *
 * Called at the release call sites immediately before this node's slot
 * release becomes peer-visible on the wire.  By then the tenure must have
 * left the proving states — begin_release (or a mode-lowering store) must
 * already have run.  A PROVING certificate here means a peer can be granted
 * and mint a new tenure while our journal still carries authority claims the
 * replay gate would honour: exactly the pre-fix mxfs_dlm_evict shape.
 *
 * Diagnostic only, and deliberately lockless: publication sites sit outside
 * i_dlm_lock (they do I/O), and a torn/stale u8 read here can at worst
 * mis-fire one ratelimited warn.  The enforcement lives in the state machine
 * and the lowering backstop, not here.
 */
void
mxfs_inode_authority_check_published(struct xfs_inode *ip, u32 line)
{
	uint8_t st = READ_ONCE(ip->i_mxfs_auth_state);

	if (likely(st != MXFS_AUTH_DURABLE_EX &&
		   st != MXFS_AUTH_UNPUBLISHED_EX))
		return;
	atomic64_inc(&mxfs_auth_publive_n);
	mxfs_probe_ratelimited("mxfs: P246-AUTH-PUB-LIVE ino=%llu auth_state=%u mode=%u dlm_state=%u L%u:%u — slot release published while the authority certificate still proves; release protocol bypassed\n",
		(unsigned long long)ip->i_ino, st,
		ip->i_dlm_mode, ip->i_dlm_state, MXFS_SITE_ARGS(line));
}

/*
 * (design-consult ruling A on the wiring): phantom-loss invalidation.
 *
 * Called under i_dlm_lock by the phantom-recovery arms (P108-REACQUIRE,
 * P-TCPEX-REACQ, the phantom-undo) at the moment a raw wire read proves the
 * cached grant no longer exists.  These are not deliberate releases — the
 * tenure already died on the wire — but a certificate that keeps proving a
 * known-dead tenure permits stale authority tagging during any intervening
 * logging, retry, or lock drop, and re-acquire must never begin while the
 * old tenure still appears live.  So: name the anomaly (a proving
 * certificate lost its wire grant IS the authority-side signal these arms
 * exist to surface), then run the normal release-begin so the NL store that
 * follows classifies as clean protocol completion.  gen++ inside
 * begin_release guarantees the post-phantom re-acquire mints a fresh tenure
 * rather than resurrecting this one.
 */
void
mxfs_inode_authority_phantom_loss_locked(struct xfs_inode *ip, u32 line)
{
	if (ip->i_mxfs_auth_state == MXFS_AUTH_DURABLE_EX ||
	    ip->i_mxfs_auth_state == MXFS_AUTH_UNPUBLISHED_EX) {
		atomic64_inc(&mxfs_auth_phantom_n);
		pr_warn_ratelimited("mxfs: P247-AUTH-PHANTOM-LOSS ino=%llu auth_state=%u mode=%u dlm_state=%u L%u:%u — wire lost a grant the cache believed in while the certificate was proving; invalidated at detection\n",
			(unsigned long long)ip->i_ino,
			ip->i_mxfs_auth_state, ip->i_dlm_mode,
			ip->i_dlm_state, MXFS_SITE_ARGS(line));
	}
	mxfs_inode_authority_begin_release_locked(ip, line);
}

/*
 * (design-consult ruling ccloop-c7ee71c6-sess403-GPT-ruling-release-marker-
 * log-item-redundant-clean): CLEAN-RELEASE MARKER publication helpers for the
 * two EX release pipelines.  Both run at the last point before the on-disk
 * unlock CAS, after the Invariant-1 drain and after every "keep the tenure"
 * arm; the marker is forced durable inside mxfs_relmark_publish so it
 * precedes the bit clear.  Counters name every release that went UNMARKED so
 * the replay-side REDUNDANT_CLEAN population can be reconciled against them.
 */
atomic64_t mxfs_relmark_iclus_unmarked = ATOMIC64_INIT(0);
/* cluster-class markers (mxfs_iclus_disk_release) */
atomic64_t mxfs_relmark_iclus_marked = ATOMIC64_INIT(0);
atomic64_t mxfs_relmark_iclus_failed = ATOMIC64_INIT(0);
atomic64_t mxfs_relmark_iclus_reinstall_refused = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_ino_marked = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_ino_failed = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_ag_marked = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_ag_failed = ATOMIC64_INIT(0);

void
mxfs_inode_relmark_before_unlock(
	struct xfs_inode	*ip,
	uint64_t		rel_res,
	uint64_t		rel_epoch,
	uint64_t		rel_lineage,
	bool			*marked,
	const char		*who)
{
	int			rc;

	if (!rel_epoch || *marked)
		return;
	/*
	 * Irrevocability first: from here on an install that offers this
	 * {resource, epoch} is refused (see
	 * mxfs_inode_authority_install_durable_ex_locked), whether or not the
	 * publish below succeeds — refusing is the conservative direction.
	 */
	WRITE_ONCE(ip->i_mxfs_relmark_res, rel_res);
	WRITE_ONCE(ip->i_mxfs_relmark_epoch, rel_epoch);
	rc = mxfs_relmark_publish(ip->i_mount, MXFS_AUTH_CLASS_INODE, rel_res,
				  rel_lineage, rel_epoch, who);
	*marked = true;
	if (rc == 0) {
		atomic64_inc(&mxfs_relmark_ino_marked);
	} else if (rc != -ENOENT) {
		static atomic_t p_n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_relmark_ino_failed);
		if (atomic_inc_return(&p_n) <= 2000)
			pr_warn("mxfs: P-RELMARK-INO-UNMARKED ino=%llu res=%llu gepoch=%llu who=%s rc=%d — releasing WITHOUT a clean-release marker; this tenure's records will refuse at foreign replay\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)rel_res,
				(unsigned long long)rel_epoch, who, rc);
	}
}

void
mxfs_ag_relmark_before_unlock(
	struct xfs_perag	*pag,
	const char		*who)
{
	uint64_t		rel_ep = READ_ONCE(pag->pag_mxfs_rel_epoch);
	uint64_t		rel_lin = READ_ONCE(pag->pag_mxfs_rel_lineage);
	int			rc;

	if (!rel_ep)
		return;
	rc = mxfs_relmark_publish(pag_mount(pag), MXFS_AUTH_CLASS_AG,
				  (uint64_t)pag_agno(pag), rel_lin, rel_ep, who);
	if (rc == 0) {
		atomic64_inc(&mxfs_relmark_ag_marked);
	} else if (rc != -ENOENT) {
		static atomic_t p_n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_relmark_ag_failed);
		if (atomic_inc_return(&p_n) <= 2000)
			pr_warn("mxfs: P-RELMARK-AG-UNMARKED ag=%u gepoch=%llu who=%s rc=%d — releasing WITHOUT a clean-release marker; this tenure's records will refuse at foreign replay\n",
				pag_agno(pag), (unsigned long long)rel_ep, who,
				rc);
	}
}

void
mxfs_relmark_site_counters(
	uint64_t		*ino_marked,
	uint64_t		*ino_failed,
	uint64_t		*ag_marked,
	uint64_t		*ag_failed,
	uint64_t		*iclus_unmarked)
{
	if (ino_marked)
		*ino_marked = atomic64_read(&mxfs_relmark_ino_marked);
	if (ino_failed)
		*ino_failed = atomic64_read(&mxfs_relmark_ino_failed);
	if (ag_marked)
		*ag_marked = atomic64_read(&mxfs_relmark_ag_marked);
	if (ag_failed)
		*ag_failed = atomic64_read(&mxfs_relmark_ag_failed);
	if (iclus_unmarked)
		*iclus_unmarked = atomic64_read(&mxfs_relmark_iclus_unmarked);
}

/* cluster-class marker counters (P-RELMARK-ICLUS-*) */
void
mxfs_relmark_iclus_counters(
	uint64_t		*marked,
	uint64_t		*failed,
	uint64_t		*reinstall_refused)
{
	if (marked)
		*marked = atomic64_read(&mxfs_relmark_iclus_marked);
	if (failed)
		*failed = atomic64_read(&mxfs_relmark_iclus_failed);
	if (reinstall_refused)
		*reinstall_refused =
			atomic64_read(&mxfs_relmark_iclus_reinstall_refused);
}

/*
 * Record a brand-new inode granted LOCALLY with no on-disk slot behind it
 * (mxfs_dlm_grant_local_new / mxfs_dlm_rearm_unpublished).  This is EX at the
 * mode level and provably non-durable at the authority level: no CAS ever ran,
 * so there is nothing to prove with.  It becomes provable only when the lazy
 * publish worker's own acquire result is installed — an
 * UNPUBLISHED_EX -> DURABLE_EX transition, not a mode comparison.
 */
void
mxfs_inode_authority_note_unpublished_locked(struct xfs_inode *ip, u32 line)
{
	ip->i_mxfs_auth_gen++;
	ip->i_mxfs_auth_line = line;
	if (ip->i_mxfs_auth_state != MXFS_AUTH_UNPUBLISHED_EX) {
		write_seqcount_begin(&ip->i_mxfs_auth_seq);
		ip->i_mxfs_auth_state = MXFS_AUTH_UNPUBLISHED_EX;
		ip->i_mxfs_auth_kind = 0;
		ip->i_mxfs_auth_reaffirm = 0;
		ip->i_mxfs_auth_resource = 0;
		ip->i_mxfs_auth_epoch = 0;
		ip->i_mxfs_auth_lineage = 0;
		ip->i_mxfs_auth_incarn = VFS_I(ip)->i_generation;
		write_seqcount_end(&ip->i_mxfs_auth_seq);
		atomic64_inc(&mxfs_auth_unpub_n);
	}
}

/*
 * Install a DURABLE EX tenure from the result of the granting CAS.
 *
 * gen_snap MUST be the value of i_mxfs_auth_gen read under i_dlm_lock BEFORE
 * this acquire descended into the DLM.  routed_iclus is the routing this
 * acquire used, so a result minted against the other backing resource cannot
 * be installed onto it.
 *
 * Returns true if a tenure is installed (or advanced) on return.
 */
static bool __maybe_unused
mxfs_inode_authority_install_durable_ex_locked(struct xfs_inode *ip,
		const struct mxfs_grant_result *gres, uint64_t gen_snap,
		bool routed_iclus, u32 line)
{
	uint8_t want_kind = routed_iclus ? MXFS_LTYPE_ICLUSTER : MXFS_LTYPE_INODE;

	/*
	 * No first-hand proof.  The REASON is carried by the tagged status the
	 * snapshot was built with, so the refusal population separates the
	 * benign read grant from the epoch-publication gap without this site
	 * having to re-derive either from a boolean.
	 */
	if (!mxfs_grant_result_proving(gres)) {
		atomic64_inc(&mxfs_auth_ref_novalid_n);
		if (!gres) {
			atomic64_inc(&mxfs_auth_ref_nogres_n);
			mxfs_inode_authority_note_try_locked(ip,
					MXFS_AUTH_TRY_NOGRES, 0, 0, line);
			return false;
		}
		atomic64_inc(&mxfs_auth_ref_status_n[
			gres->status < MXFS_GAUTH_STATUS_MAX ?
			gres->status : MXFS_GAUTH_UNSET]);
		mxfs_inode_authority_note_try_locked(ip,
				MXFS_AUTH_TRY_STATUS_BASE + gres->status,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	/* THE stale-completion guard.  A gen that moved means authority was
	 * given up between the snapshot and this completion, so this result
	 * describes a tenure that no longer exists. */
	if (ip->i_mxfs_auth_gen != gen_snap) {
		atomic64_inc(&mxfs_auth_ref_stalegen_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_STALEGEN,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	if (ip->i_mxfs_auth_state == MXFS_AUTH_RELEASING) {
		atomic64_inc(&mxfs_auth_ref_releasing_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_RELEASING,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	/* An inode still on the unpublished list has no durable slot of its
	 * own; only the publish path may promote it, and it clears the flag
	 * before installing. */
	if (ip->i_dlm_unpublished) {
		atomic64_inc(&mxfs_auth_ref_unpub_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_UNPUB,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	/* The certificate's backing must agree with the routing in force. */
	if (gres->kind != want_kind || routed_iclus != ip->i_dlm_routed_iclus) {
		atomic64_inc(&mxfs_auth_ref_routing_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_ROUTING,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	if (xfs_iflags_test(ip, XFS_IRECLAIM | XFS_IRECLAIMABLE) ||
	    xfs_is_shutdown(ip->i_mount)) {
		atomic64_inc(&mxfs_auth_ref_reclaim_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_RECLAIM,
				gres->mode, gres->grant_epoch, line);
		return false;
	}
	/*
	 * (design-consult ruling: the release is IRREVOCABLE once its
	 * clean-release marker is durable).  This node's journal already
	 * certifies {resource, grant_epoch} as cleanly released; an image
	 * stamped with that epoch after this point would be classified
	 * REDUNDANT_CLEAN (skipped) at replay although it was never drained.
	 * The only way to offer the same epoch again is a memory-only
	 * already-held re-grant that raced the unlock CAS (no CAS, so
	 * caw_grant_epoch_update never minted); refuse to resurrect it as
	 * authority — the tenure writes fail-closed (class NONE) until a real
	 * grant CAS mints a fresh epoch.
	 */
	if (gres->grant_epoch &&
	    gres->grant_epoch == READ_ONCE(ip->i_mxfs_relmark_epoch) &&
	    gres->resource == READ_ONCE(ip->i_mxfs_relmark_res)) {
		static atomic_t p_relmark_reinst_n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_auth_ref_releasing_n);
		mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_RELEASING,
				gres->mode, gres->grant_epoch, line);
		if (atomic_inc_return(&p_relmark_reinst_n) <= 2000)
			pr_warn("mxfs: P-RELMARK-REINSTALL-REFUSED ino=%llu res=%llu gepoch=%llu L%u:%u — grant epoch already certified clean-released by this node's journal; not resurrecting it as authority\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)gres->resource,
				(unsigned long long)gres->grant_epoch, MXFS_SITE_ARGS(line));
		return false;
	}

	/*
	 * Same live tenure: a convert (PR -> EX) legitimately advances the
	 * epoch without any release in between, so take the MAX rather than
	 * letting a racing older completion regress the record.
	 */
	if (ip->i_mxfs_auth_state == MXFS_AUTH_DURABLE_EX &&
	    ip->i_mxfs_auth_resource == gres->resource &&
	    ip->i_mxfs_auth_kind == gres->kind &&
	    ip->i_mxfs_auth_incarn == VFS_I(ip)->i_generation) {
		if (gres->grant_epoch > ip->i_mxfs_auth_epoch) {
			write_seqcount_begin(&ip->i_mxfs_auth_seq);
			ip->i_mxfs_auth_epoch = gres->grant_epoch;
			/* the lineage travels with the epoch it was
			 * read beside.  Same binding => same value in the
			 * normal case; a difference means the slot binding
			 * was recycled mid-tenure and the NEWER image is the
			 * truth the tokens must match. */
			ip->i_mxfs_auth_lineage = gres->resource_lineage;
			ip->i_mxfs_auth_reaffirm = gres->reaffirm;
			write_seqcount_end(&ip->i_mxfs_auth_seq);
			ip->i_mxfs_auth_line = line;
			atomic64_inc(&mxfs_auth_install_advance_n);
			mxfs_inode_authority_note_try_locked(ip,
					MXFS_AUTH_TRY_ADVANCE, gres->mode,
					gres->grant_epoch, line);
		} else {
			mxfs_inode_authority_note_try_locked(ip,
					MXFS_AUTH_TRY_SAMETENURE, gres->mode,
					gres->grant_epoch, line);
		}
		return true;
	}

	write_seqcount_begin(&ip->i_mxfs_auth_seq);
	ip->i_mxfs_auth_state = MXFS_AUTH_DURABLE_EX;
	ip->i_mxfs_auth_kind = gres->kind;
	ip->i_mxfs_auth_reaffirm = gres->reaffirm;
	ip->i_mxfs_auth_resource = gres->resource;
	ip->i_mxfs_auth_epoch = gres->grant_epoch;
	ip->i_mxfs_auth_lineage = gres->resource_lineage;
	ip->i_mxfs_auth_incarn = VFS_I(ip)->i_generation;
	write_seqcount_end(&ip->i_mxfs_auth_seq);
	ip->i_mxfs_auth_line = line;
	atomic64_inc(&mxfs_auth_install_n);
	mxfs_inode_authority_note_try_locked(ip, MXFS_AUTH_TRY_INSTALL,
			gres->mode, gres->grant_epoch, line);
	return true;
}

/*
 * Caller-facing install wrapper.  Skips entirely for an acquire that did not
 * take a gen snapshot (probe/nudge callers pass MXFS_AUTH_GEN_NONE), so those
 * can never install a tenure they made no provenance claim about.
 */
void
mxfs_dlm_authority_install(struct xfs_inode *ip,
		const struct mxfs_grant_result *gres, uint64_t gen_snap,
		bool routed_iclus, u32 line)
{
	if (gen_snap == MXFS_AUTH_GEN_NONE) {
		atomic64_inc(&mxfs_auth_nosnap_n);
		return;
	}
	(void)mxfs_inode_authority_install_durable_ex_locked(ip, gres,
						gen_snap, routed_iclus, line);
}

/*
 * fix shape A (D-FOREIGN-SLICE-INTENTS-ABANDONED; design-consult ruling
 * ccmemory ccloop-c7ee71c6-sess467-GPT-ruling-intents-classless-images-fix-
 * shapes-A-B-Q3, Q1): the inactivation path takes its cluster-wide EX
 * through the RAW acquire (xfs_inactive: mxfs_v5_dlm_inode_lock /
 * mxfs_iclus_lock with a grant result, never mxfs_dlm_ilock_begin, because
 * an I_FREEING inode must not be reloaded), and that path never installed a
 * certificate — so every truncate/ifree image of a dying node's rm was
 * captured NONE/RELEASING at a writing mode (chain 93: 39 classless bmbt
 * images per rm burst, the whole transaction POLICY-REFUSED, FSWIDE
 * quarantine).  A certificate on an I_FREEING inode is sound: it attests a
 * real DLM EX tenure, not VFS reachability.
 *
 * The three entry points below give xfs_inactive exactly the ilock_begin
 * discipline and nothing more:
 *   - snapshot: i_mxfs_auth_gen under i_dlm_lock BEFORE the blocking
 *     acquire (re-taken before every retry, since bast_process in the
 *     -EDEADLK loop moves the counter);
 *   - install: ONLY from the completed grant result, through the one
 *     install routine — proving status, gen recheck, RELEASING/unpublished/
 *     routing/reclaim/relmark refusals all apply unchanged, so a recycled or
 *     rerouted inode aborts the install rather than mis-certifying;
 *     routed (ICLUS) inodes name the cluster resource the grant result
 *     carries.  Runs BEFORE the first truncate/ifree dirty.
 *   - revoke: at INACT-EXREL, by EXACT {kind, resource, epoch, lineage} of
 *     the grant this inactivation held, BEFORE the raw DLM release and after
 *     the ifree-end drain (no dirtying after the revoke).  A newer
 *     certificate (different identity) is left alone; a tenure the release
 *     side already moved to RELEASING/NONE needs nothing.  The raw unlock
 *     touches no xfs-side state, so without this the certificate would
 *     outlive its grant on a cached in-core inode.
 * MUST NOT (ruling): clear I_FREEING, iget/igrab/reload, imply ilock, publish
 * for other users, synthesize an epoch, enable any fast path — none of
 * which the install routine can do.  DURABLE_EX has no consumer beyond the
 * replay certificate (xfs_buf_item.c classifier, the publication tripwire,
 * phantom-loss and advance), so no INACT substate is needed.
 */
uint64_t
mxfs_dlm_authority_gen_snapshot(struct xfs_inode *ip)
{
	uint64_t gen;

	spin_lock(&ip->i_dlm_lock);
	gen = ip->i_mxfs_auth_gen;
	spin_unlock(&ip->i_dlm_lock);
	return gen;
}

bool
mxfs_dlm_inactive_authority_install(struct xfs_inode *ip,
		const struct mxfs_grant_result *gres, uint64_t gen_snap,
		bool routed_iclus, uint8_t *why, struct mxfs_inact_cert_id *id)
{
	bool ok;

	memset(id, 0, sizeof(*id));
	if (gen_snap == MXFS_AUTH_GEN_NONE) {
		atomic64_inc(&mxfs_auth_nosnap_n);
		*why = MXFS_AUTH_TRY_NONE;
		return false;
	}
	spin_lock(&ip->i_dlm_lock);
	ok = mxfs_inode_authority_install_durable_ex_locked(ip, gres, gen_snap,
							     routed_iclus,
							     MXFS_SITE);
	*why = READ_ONCE(ip->i_mxfs_auth_try);
	if (ok) {
		extern int mxfs_inact_cert_inject;

		/* TEST ONLY (verification arm 5): make the installed
		 * certificate differ from the grant result the way a
		 * same-tenure ADVANCE does, so the exact revoke is exercised. */
		if (unlikely(mxfs_inact_cert_inject == 4)) {
			write_seqcount_begin(&ip->i_mxfs_auth_seq);
			ip->i_mxfs_auth_epoch++;
			write_seqcount_end(&ip->i_mxfs_auth_seq);
		}
		/*
		 * (review STOP-SHIP 3): the revoke must name what was
		 * INSTALLED, which the same-tenure ADVANCE arm may have left
		 * at an epoch newer than this grant result's.  Read the exact
		 * identity back under the lock.
		 */
		id->kind = ip->i_mxfs_auth_kind;
		id->resource = ip->i_mxfs_auth_resource;
		id->epoch = ip->i_mxfs_auth_epoch;
		id->lineage = ip->i_mxfs_auth_lineage;
		ip->i_mxfs_auth_inact = MXFS_INACT_CERT_ACTIVE;
		if (ip->i_mxfs_auth_state != MXFS_AUTH_DURABLE_EX ||
		    id->epoch == 0)
			ok = false;	/* cannot happen: installer returned true */
	}
	spin_unlock(&ip->i_dlm_lock);
	return ok;
}

/* P128-INACT-DEFER kept the grant cached after the ifree commit: the
 * certificate is now legitimately the release side's to give up. */
void
mxfs_dlm_inactive_authority_defer(struct xfs_inode *ip)
{
	extern int mxfs_inact_cert_inject;

	/* TEST ONLY (verification arm 9, evictactive): an inactivation
	 * that exits without revoke or defer leaves the certificate ACTIVE; the
	 * evict assertion must class it 3 and fail closed. */
	if (unlikely(mxfs_inact_cert_inject == 7))
		return;
	spin_lock(&ip->i_dlm_lock);
	if (ip->i_mxfs_auth_inact == MXFS_INACT_CERT_ACTIVE)
		ip->i_mxfs_auth_inact = MXFS_INACT_CERT_DEFERRED;
	spin_unlock(&ip->i_dlm_lock);
}

static atomic64_t mxfs_inact_cert_revoke_n[3];

int
mxfs_dlm_inactive_authority_revoke(struct xfs_inode *ip,
		const struct mxfs_inact_cert_id *id, uint8_t *state_seen,
		uint64_t *epoch_seen)
{
	extern int mxfs_inact_cert_inject;
	int rv;

	spin_lock(&ip->i_dlm_lock);
	/* TEST ONLY (verification arm 7): a release-side actor
	 * moves the certificate before INACT-EXREL — must be LOST + GONE
	 * and the caller must fail closed. */
	if (unlikely(mxfs_inact_cert_inject == 5))
		mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
	/* the inactivation's own revoke is not a loss */
	if (ip->i_mxfs_auth_inact == MXFS_INACT_CERT_ACTIVE)
		ip->i_mxfs_auth_inact = MXFS_INACT_CERT_NONE;
	*state_seen = ip->i_mxfs_auth_state;
	*epoch_seen = ip->i_mxfs_auth_epoch;
	if (ip->i_mxfs_auth_state == MXFS_AUTH_DURABLE_EX &&
	    ip->i_mxfs_auth_kind == id->kind &&
	    ip->i_mxfs_auth_resource == id->resource &&
	    ip->i_mxfs_auth_epoch == id->epoch &&
	    ip->i_mxfs_auth_lineage == id->lineage) {
		mxfs_inode_authority_revoke_locked(ip, MXFS_SITE);
		rv = MXFS_INACT_REVOKED;
	} else if (ip->i_mxfs_auth_state == MXFS_AUTH_DURABLE_EX) {
		/* A proving certificate that is NOT the one this
		 * inactivation installed, on an I_FREEING inode we hold raw
		 * EX on: nothing else may install here.  Leave it for the
		 * caller's fail-closed handling; do not touch it. */
		rv = MXFS_INACT_REVOKE_FOREIGN;
	} else {
		rv = MXFS_INACT_REVOKE_GONE;
	}
	ip->i_mxfs_auth_inact = MXFS_INACT_CERT_NONE;
	atomic64_inc(&mxfs_inact_cert_revoke_n[rv]);
	spin_unlock(&ip->i_dlm_lock);
	return rv;
}


/*
 * the DEFER arm of xfs_inactive (P128-INACT-DEFER: freed dinode
 * still undestaged, grant kept cached) leaves the inactivation certificate in
 * place on purpose — the tenure is still held and its images may still be
 * relogged.  The grant is given up later by mxfs_dlm_evict through the normal
 * begin_release -> lowering path.  Assert there that the certificate the
 * evict is about to move is still that tenure's (state DURABLE_EX with the
 * epoch this node's raw grant carries), so a certificate that was lost or
 * replaced while the grant was cached is loud rather than silent.  Called
 * under i_dlm_lock immediately before begin_release.
 */
static atomic64_t mxfs_inact_cert_evict_n[4];	/* ok / gone / foreign-shaped / still-active */
void
mxfs_inact_cert_evict_check_locked(struct xfs_inode *ip, u32 line)
{
	extern int mxfs_inact_cert_inject;
	uint8_t st = ip->i_mxfs_auth_state;
	uint8_t was = ip->i_mxfs_auth_inact;
	int cls;

	if (was == MXFS_INACT_CERT_NONE)
		return;
	/* TEST ONLY (verification arm 8, evictforeign): chain 108
	 * s473c showed every free on this rig DEFERs its retirement (the eager
	 * durable chain is off), so the sync-path knob-2/5 injections never
	 * ran; the deferred retirement's own fail-closed class needs an
	 * injection too.  Make the deferred certificate look like another
	 * incarnation's (cls=2). */
	if (unlikely(mxfs_inact_cert_inject == 6) &&
	    was == MXFS_INACT_CERT_DEFERRED)
		ip->i_mxfs_auth_incarn ^= 0x80000000U;
	ip->i_mxfs_auth_inact = MXFS_INACT_CERT_NONE;
	if (was == MXFS_INACT_CERT_ACTIVE)
		cls = 3;	/* an inactivation exited without revoke or defer */
	else if (st == MXFS_AUTH_DURABLE_EX && ip->i_mxfs_auth_epoch &&
		 (ip->i_mxfs_auth_incarn == VFS_I(ip)->i_generation ||
		  /*
		   * (D-0529, first fleet run of the check): a DEFERRED
		   * certificate sits on an inode whose ifree has COMMITTED, and
		   * xfs_inode_uninit bumps i_generation by exactly one at the
		   * free — so the tenure's install-time incarnation is always
		   * gen-1 here, by construction, never "another incarnation".
		   * Design-consult ruling: recognise that ONE local
		   * transition, only for a DEFERRED certificate with the free
		   * committed, in u32 modulo arithmetic; auth_incarn itself
		   * stays the immutable install-time identity.  A reused inode
		   * number re-randomises the generation at create, so it does
		   * not fall into this window.
		   */
		  (was == MXFS_INACT_CERT_DEFERRED &&
		   xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED) &&
		   VFS_I(ip)->i_generation ==
			(uint32_t)(ip->i_mxfs_auth_incarn + 1U))))
		cls = 0;
	else if (st == MXFS_AUTH_DURABLE_EX)
		cls = 2;	/* malformed: epoch 0 or another incarnation */
	else
		cls = 1;	/* already RELEASING/NONE: the BAST durable loop or
				 * a lowering gave the deferred tenure up first */
	atomic64_inc(&mxfs_inact_cert_evict_n[cls]);
	if (cls) {
		static atomic_t n = ATOMIC_INIT(0);

		if (atomic_inc_return(&n) <= 200)
			mxfs_probe("mxfs: P-INACT-CERT-EVICT ino=%llu cls=%d was=%u auth_state=%u auth_epoch=%llu incarn=%u gen=%u dlm_mode=%u free_committed=%d L%u:%u — deferred inactivation certificate is not the held tenure at evict\n",
				(unsigned long long)ip->i_ino, cls, (unsigned)was,
				(unsigned)st,
				(unsigned long long)ip->i_mxfs_auth_epoch,
				ip->i_mxfs_auth_incarn, VFS_I(ip)->i_generation,
				(unsigned)ip->i_dlm_mode,
				xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED) ? 1 : 0,
				MXFS_SITE_ARGS(line));
	}
	/* design-consult ruling: a malformed certificate (or one an
	 * inactivation left ACTIVE) is authority-state corruption — fail
	 * closed before the release below becomes peer-visible. */
	if (cls == 2 || cls == 3) {
		pr_err("mxfs: P-INACT-CERT-EVICT-CORRUPT ino=%llu cls=%d — failing closed (shutdown)\n",
			(unsigned long long)ip->i_ino, cls);
		xfs_force_shutdown(ip->i_mount, SHUTDOWN_CORRUPT_INCORE);
	}
}

/* unmount census (printed beside P228-TOKCLASS) */
void
mxfs_inact_cert_report(void)
{
	mxfs_probe("mxfs: P-INACT-CERT-TOTAL revoked=%lld gone=%lld foreign=%lld lost=%lld evict_ok=%lld evict_gone=%lld evict_foreign=%lld evict_active=%lld\n",
		(long long)atomic64_read(&mxfs_inact_cert_revoke_n[0]),
		(long long)atomic64_read(&mxfs_inact_cert_revoke_n[1]),
		(long long)atomic64_read(&mxfs_inact_cert_revoke_n[2]),
		(long long)atomic64_read(&mxfs_inact_cert_lost_n),
		(long long)atomic64_read(&mxfs_inact_cert_evict_n[0]),
		(long long)atomic64_read(&mxfs_inact_cert_evict_n[1]),
		(long long)atomic64_read(&mxfs_inact_cert_evict_n[2]),
		(long long)atomic64_read(&mxfs_inact_cert_evict_n[3]));
}
