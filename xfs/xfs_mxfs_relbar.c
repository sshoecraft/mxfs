// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- release barrier, release certificates and release-gate faults
 */
#define MXFS_TU_ID 16	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 *  — D-RELEASE-BARRIER-OPEN OBLIGATION DETECTOR, AT THE
 * WIRE UNLOCK.
 *
 * The ledger's standing complaint about this defect is that the pending-vs-
 * durable predicate is evaluated on exactly ONE early-exit branch (P176) and
 * NEVER where it matters: the instant the grant is handed to a peer.  This is
 * that evaluation, at both release tails, for every inode (the existing
 * P147-PREUNLOCK probe is directory-only and capped).
 *
 * The predicate is XFS's own per-inode FLUSH LOCK.  XFS_IFLUSHING is set by
 * xfs_iflush when it copies the in-core image into a cluster buffer and is
 * cleared only by that buffer's iodone.  So `IFLUSHING at unlock` means
 * verbatim: **we are handing the tenure away while bytes produced under it are
 * staged in a buffer that has not reached home.**  Those bytes are then
 * published by xfsaild at an arbitrary later time, with no authority — which
 * is exactly what P219-LOGGED-NO-AUTHORITY catches downstream (32 nodes, one
 * clean run: stale_tenure=24, staged at EX, submitted at NL).
 *
 * Counting only; no behaviour change.  Establishing the numerator here is what
 * makes the barrier's A/B interpretable.
 */
static atomic64_t mxfs_relbar_unlocks;
static atomic64_t mxfs_relbar_flushing;	/* ...with a staged image outstanding */
static atomic64_t mxfs_relbar_inail;
static atomic64_t mxfs_relbar_pinned;
static atomic64_t mxfs_relbar_obligation;	/* pending != durable at unlock */
static atomic64_t mxfs_relbar_closed;	/* enforce closed the ledger pre-unlock */
static atomic64_t mxfs_relbar_deferred;	/* enforce deferred the wire unlock */
static atomic64_t mxfs_relbar_wrq_ok;	/* barrier observed writer-quiescence */
static atomic64_t mxfs_relbar_wrq_tmo;	/* wait budget exhausted, holder still in */
atomic64_t mxfs_relbar_gate_defer;	/* pre-NL obligation gate deferred a release */
atomic64_t mxfs_lognoex_nl;	/* P234: obligations stamped at DLM mode NL */
atomic64_t mxfs_lognoex_pr;	/* P234: obligations stamped at PR/CR (shared) */

/*
 * writer-quiescence barrier lever.  The open ledger at the unlock
 * tails is almost always the LAST admitted mutator committing (pend++
 * stamped, CIL insert in flight) — a durable pass has nothing to force yet.
 * .282 proved a down_write barrier convoys behind readdir's ILOCK_SHARED
 * (dd 240s vs 65s) and .283's bounded write-trylock rarely wins on hot
 * dirs.  This arm instead waits (bounded, shared budget across both
 * durable passes) for the i_mxfs_ilk_wr_held census to read 0 — writer-only
 * quiescence: the rwsem is never touched, readers are never waited on or
 * blocked.  wr_held covers EVERY local mutator class (xfs_trans_log_inode
 * requires local ILOCK_EXCL) — including the DLM-uncounted ones (other-
 * resource admissions, PR-admitted timestamp updates) that the P15
 * ex_holders gate cannot see.  0 = legacy .283 trylock arm (A/B control).
 */
int mxfs_relbar_wrq = 1;
module_param_named(relbar_wrq, mxfs_relbar_wrq, int, 0644);
MODULE_PARM_DESC(relbar_wrq,
		 "writer-quiescence admission barrier before relbar durable "
		 "passes (1=wait for ILOCK_EXCL census 0, default; "
		 "0=legacy bounded write-trylock)");

void
mxfs_dlm_relbar_check(struct xfs_inode *ip, const char *arm)
{
	bool flushing = xfs_iflags_test(ip, XFS_IFLUSHING);
	bool in_ail = ip->i_itemp &&
		test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags);
	bool pinned = atomic_read(&ip->i_pincount) > 0;

	atomic64_inc(&mxfs_relbar_unlocks);
	if (in_ail)
		atomic64_inc(&mxfs_relbar_inail);
	if (pinned)
		atomic64_inc(&mxfs_relbar_pinned);
	/*
	 * the ledger predicate, not the flush-lock one.  IFLUSHING
	 * measured 0 across 15199 unlocks while a P222 skip proved an unlock
	 * had happened with pend=12 dur=10 — the obligation escapes through
	 * exits the IFLUSHING probe cannot see (committed-but-uncopied state,
	 * or a landed-then-recommitted window).  Count pending != durable at
	 * the same instant; this is the numerator the real release barrier
	 * must drive to zero.
	 */
	if (READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
	    READ_ONCE(ip->i_mxfs_pub_durable_seq)) {
		static atomic_t p220lo_n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_relbar_obligation);
		/*
		 * Capped, NOT ratelimited: these are the release-barrier
		 * verdict events (the epoch-site count upstream is partly
		 * transient — the pipeline's dir durable flush runs AFTER the
		 * in-core NL transition — but an open ledger HERE survived the
		 * whole pipeline and is handing the tenure away).  lastrel
		 * says whether __mxfs_dlm_dir_inode_durable ran (1), was
		 * clean-skipped (2), or never reached (0 = non-dir arm).
		 */
		if (atomic_inc_return(&p220lo_n) <= 400)
			mxfs_probe(
		    "mxfs: P220-UNLOCK-LEDGER-OPEN ino=%llu arm=%s pend=%llu dur=%llu flush=%llu ili_f=0x%x ili_lf=0x%x iflushing=%d isdir=%d nlink=%u istale=%d lastrel=%u fmt=%d comm=%s — unlocking with a committed change not yet at home\n",
			(unsigned long long)ip->i_ino, arm,
			(unsigned long long)ip->i_mxfs_pub_pending_seq,
			(unsigned long long)ip->i_mxfs_pub_durable_seq,
			(unsigned long long)ip->i_mxfs_pub_flush_seq,
			ip->i_itemp ? ip->i_itemp->ili_fields : 0,
			ip->i_itemp ? ip->i_itemp->ili_last_fields : 0,
			flushing ? 1 : 0,
			S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
			VFS_I(ip)->i_nlink,
			xfs_iflags_test(ip, XFS_ISTALE) ? 1 : 0,
			(unsigned)ip->i_mxfs_lastrel_flag,
			ip->i_df.if_format,
			current->comm);
	}
	if (!flushing)
		return;
	atomic64_inc(&mxfs_relbar_flushing);
	mxfs_probe_ratelimited(
	    "mxfs: P220-UNLOCK-OBLIGATION-OPEN ino=%llu arm=%s isdir=%d in_ail=%d pin=%d ili_fields=0x%x last_fields=0x%x li_buf=%d stage_epoch=%lu now_epoch=%lu comm=%s realns=%llu — releasing the grant while a staged image of this tenure has not reached home\n",
		(unsigned long long)ip->i_ino, arm,
		S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
		in_ail ? 1 : 0, atomic_read(&ip->i_pincount),
		ip->i_itemp ? ip->i_itemp->ili_fields : 0,
		ip->i_itemp ? ip->i_itemp->ili_last_fields : 0,
		(ip->i_itemp && ip->i_itemp->ili_item.li_buf) ? 1 : 0,
		ip->i_mxfs_pub_stage_epoch, ip->i_dlm_epoch,
		current->comm, (unsigned long long)ktime_get_real_ns());
}

/*
 * — the same obligation predicate, evaluated at EVERY site that ENDS a
 * tenure (each i_dlm_epoch bump), not just the two bast_process unlock tails.
 *
 * The tails measured flushing=0 over 15199 unlocks across two 32-node runs, so
 * they are NOT where the leak is — yet P219 catches staged images being
 * published after the epoch moved.  The tenure therefore ends at one of the
 * other seven bump sites (bast_notify, ilock_begin x2, evict x2,
 * peer_joined_flush, and the two bast_process early exits), none of which runs
 * the release drain.  This names which.
 *
 * LOCKLESS BY DESIGN: several bump sites hold ip->i_dlm_lock, and
 * xfs_iflags_test() takes ip->i_flags_lock — nesting a second inode spinlock
 * inside the DLM lock for a diagnostic is not worth the lock-order risk.  A
 * plain read of i_flags is sufficient for a counter.
 */
static atomic64_t mxfs_relbar_ep_total;
static atomic64_t mxfs_relbar_ep_flushing;
static atomic64_t mxfs_relbar_ep_obligation;	/* pending != durable at epoch bump */

void
mxfs_relbar_epoch_check(struct xfs_inode *ip)
{
	atomic64_inc(&mxfs_relbar_ep_total);
	/* same ledger predicate at every tenure end; epsrc names the
	 * bump site so a nonzero count localizes WHICH exit leaks. */
	if (READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
	    READ_ONCE(ip->i_mxfs_pub_durable_seq)) {
		atomic64_inc(&mxfs_relbar_ep_obligation);
		mxfs_probe_ratelimited(
		    "mxfs: P220-EPOCH-LEDGER-OPEN ino=%llu epsrc=%u:%u pend=%llu dur=%llu flush=%llu mode=%u isdir=%d nlink=%u istale=%d dstale=%d dss=%u dinc=%u ili_f=0x%x comm=%s — tenure ended with a committed change not yet at home\n",
			(unsigned long long)ip->i_ino,
			MXFS_SITE_ARGS(ip->i_dlm_epoch_src),
			(unsigned long long)ip->i_mxfs_pub_pending_seq,
			(unsigned long long)ip->i_mxfs_pub_durable_seq,
			(unsigned long long)ip->i_mxfs_pub_flush_seq,
			(unsigned)ip->i_dlm_mode,
			S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
			VFS_I(ip)->i_nlink,
			/* lockless by design here — see the function comment */
			(READ_ONCE(ip->i_flags) & XFS_ISTALE) ? 1 : 0,
			/* the two FIX-A gate exemptions P220 could
			 * not see — a 14919 crossing with both zero means the
			 * commit raced the gate-to-store instruction window,
			 * nonzero names the exemption that admitted it. */
			ip->i_dlm_stale ? 1 : 0,
			(unsigned)ip->i_dlm_stale_src,
			(unsigned)ip->i_mxfs_dead_incarn_gen,
			ip->i_itemp ? ip->i_itemp->ili_fields : 0,
			current->comm);
	}
	if (!(READ_ONCE(ip->i_flags) & XFS_IFLUSHING))
		return;
	atomic64_inc(&mxfs_relbar_ep_flushing);
	mxfs_probe_ratelimited(
	    "mxfs: P220-EPOCH-OBLIGATION-OPEN ino=%llu epsrc=%u:%u isdir=%d mode=%u stage_epoch=%lu now_epoch=%lu comm=%s realns=%llu — tenure ENDED here while a staged image of it has not reached home\n",
		(unsigned long long)ip->i_ino,
		MXFS_SITE_ARGS(ip->i_dlm_epoch_src),
		S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
		(unsigned)ip->i_dlm_mode,
		ip->i_mxfs_pub_stage_epoch, ip->i_dlm_epoch,
		current->comm, (unsigned long long)ktime_get_real_ns());
}

static int
mxfs_relbar_dump_set(const char *val, const struct kernel_param *kp)
{
	(void)val; (void)kp;
	mxfs_probe("mxfs: P220-RELEASE-BARRIER-TOTAL unlocks=%lld flushing=%lld in_ail=%lld pinned=%lld obligation=%lld closed=%lld deferred=%lld gate_defer=%lld wrq_ok=%lld wrq_tmo=%lld lognoex_nl=%lld lognoex_pr=%lld epoch_ends=%lld epoch_flushing=%lld epoch_obligation=%lld\n",
		(long long)atomic64_read(&mxfs_relbar_unlocks),
		(long long)atomic64_read(&mxfs_relbar_flushing),
		(long long)atomic64_read(&mxfs_relbar_inail),
		(long long)atomic64_read(&mxfs_relbar_pinned),
		(long long)atomic64_read(&mxfs_relbar_obligation),
		(long long)atomic64_read(&mxfs_relbar_closed),
		(long long)atomic64_read(&mxfs_relbar_deferred),
		(long long)atomic64_read(&mxfs_relbar_gate_defer),
		(long long)atomic64_read(&mxfs_relbar_wrq_ok),
		(long long)atomic64_read(&mxfs_relbar_wrq_tmo),
		(long long)atomic64_read(&mxfs_lognoex_nl),
		(long long)atomic64_read(&mxfs_lognoex_pr),
		(long long)atomic64_read(&mxfs_relbar_ep_total),
		(long long)atomic64_read(&mxfs_relbar_ep_flushing),
		(long long)atomic64_read(&mxfs_relbar_ep_obligation));
	return 0;
}
static const struct kernel_param_ops mxfs_relbar_dump_ops = {
	.set = mxfs_relbar_dump_set,
};
module_param_cb(release_barrier_dump, &mxfs_relbar_dump_ops, NULL, 0644);

/*
 * D-512 T8 kind-3 (proven by instrument on rig evidence
 * tests/evidence/20260824T081049Z_d512t8/dmesg_k3.txt): WEDGED is a
 * TERMINAL rel_state — "CAS refused pre-submit" — but the relbar proof
 * body rewrote DRAINING and then PROVED over it unconditionally.  A
 * mid-pipeline wedge (the drain-site-2 fail-stop) was followed 0.7ms
 * later by the arm chain's proof body, which cleared WEDGED; the
 * pre-CAS WEDGED re-check then passed and P141-UNLK-EXCLR published
 * the on-disk unlock over the failed drain — the waiter was served ~1s
 * after the wedge, long before any fence/replay.  Every rel_state
 * transition must go through this setter: WEDGED can be entered (the
 * wedge writes it directly under i_dlm_lock), never left.  Lock-free
 * check-then-write matches the precision of the existing pre-CAS
 * re-check (a wedge landing between the final re-check and the CAS was
 * already outside the design's window).
 */
void
mxfs_rel_state_set(struct xfs_inode *ip, u8 state)
{
	if (READ_ONCE(ip->i_mxfs_rel_state) == MXFS_RELSTATE_WEDGED &&
	    state != MXFS_RELSTATE_WEDGED)
		return;
	WRITE_ONCE(ip->i_mxfs_rel_state, state);
}

/*
 * D-RELEASE-BARRIER-OPEN enforcement body, shared by BOTH wire-unlock
 * arms (anchored + noanchor).  Returns true when the publication ledger is
 * open and could not be closed by two in-place durable passes — the caller
 * must then DEFER the wire unlock through its own requeue path instead of
 * handing the grant away with a committed change not yet at home.  The wire
 * grant is still ours here, so the durable writes are fully authorized.
 *
 * (build-order step 3, ruling): this IS the per-inode
 * release-proof body, so it also fills the caller's release certificate —
 * ledger state at quiesce and after the drain passes, WRQ-budget timeout,
 * and the pass-bounce (tripwire-retry) count.  cert may be NULL (enforce=0
 * A/B callers).  Proof behavior is unchanged.
 */
/*
 * (step 5 F3, ruling item C): durable flush-ticket check.
 * In fua_disable=0 mode a closed pending/durable ledger is NOT yet a
 * proof — the discharge only means the bytes reached the target's write
 * cache.  The ticket demands the device flush epoch have advanced PAST
 * the epoch stamped at this inode's last durable discharge
 * (i_mxfs_pub_durable_fepoch): a real SYNCHRONIZE CACHE completed after
 * the settled bytes arrived.  Reader protocol pairs with the stamp sites
 * (stamp; smp_wmb; durable): read durable, smp_rmb, read stamp — so a
 * new durable value is never paired with a pre-discharge stamp.  In
 * fua_disable=1 mode the epoch never certifies a real flush; the domain
 * question (PROTECTED vs NO_DOMAIN) is recorded at the certificate
 * instead and the ticket check passes trivially.
 */
static bool
mxfs_relbar_ticket_ok(struct xfs_inode *ip)
{
	uint64_t stamp;

	if (mxfs_fua_disable)
		return true;
	(void)READ_ONCE(ip->i_mxfs_pub_durable_seq);
	smp_rmb();
	stamp = READ_ONCE(ip->i_mxfs_pub_durable_fepoch);
	return (uint64_t)atomic64_read(&ip->i_mount->m_mxfs_flush_epoch) >
	       stamp;
}

bool
mxfs_relbar_close_or_defer(struct xfs_inode *ip, const char *arm,
			   struct mxfs_release_cert *cert)
{
	int rb_try = 0;
	int rb_budget = 40;	/* shared wait budget (~40ms) across both passes */
	bool isdir = S_ISDIR(VFS_I(ip)->i_mode);
	long f4_open = 0;
	int f4_unknown = 0;

	/* F4: committed-never-submitted dir-class obligations owned
	 * by this dir (unknown-owner poison bucket counts for every dir). */
	if (isdir)
		f4_open = mxfs_f4_open_for_dir(ip->i_mount, ip->i_ino,
					       &f4_unknown);
	if (cert) {
		uint64_t rc_pend = READ_ONCE(ip->i_mxfs_pub_pending_seq);
		uint64_t rc_dur = READ_ONCE(ip->i_mxfs_pub_durable_seq);
		uint64_t rc_delta = rc_pend - rc_dur;

		cert->dirty_seq_quiesce = rc_pend;
		cert->oblig_quiesce = rc_delta > (uint64_t)U32_MAX ?
					U32_MAX : (uint32_t)rc_delta;
		cert->f4_quiesce = f4_open > (long)U32_MAX ?
					U32_MAX : (uint32_t)f4_open;
		cert->f4_unknown = f4_unknown ? 1 : 0;
	}
	/* step 3: the proof body owns DRAINING→PROVED/DEMOTING */
	mxfs_rel_state_set(ip, MXFS_RELSTATE_DRAINING);
	if (READ_ONCE(ip->i_mxfs_pub_pending_seq) ==
	    READ_ONCE(ip->i_mxfs_pub_durable_seq)) {
		if (isdir && (f4_open || f4_unknown))
			mxfs_relbar_f4_census(ip, f4_open, f4_unknown,
					      "quiesce");
		if (!(mxfs_f4_gate && isdir && (f4_open || f4_unknown)) &&
		    mxfs_relbar_ticket_ok(ip)) {
			/* per-instance attestation — THIS attempt's
			 * proof completed (the shared scalar is diagnostic) */
			if (cert)
				cert->proved = 1;
			mxfs_rel_state_set(ip, MXFS_RELSTATE_PROVED);
			return false;
		}
		/* gate=1 with F4 open, or no covering flush ticket (
		 * F3): fall into the durable passes so the flush below can
		 * retire the obligations / earn the ticket in place */
	}
	for (rb_try = 0; rb_try < 2; rb_try++) {
		/*
		 * WRITER-QUIESCENCE barrier (replaces the .283 bounded
		 * write-trylock, which rarely won on hot dirs): wait for the
		 * i_mxfs_ilk_wr_held census to observe 0 before EACH durable
		 * pass, sharing one ~40ms budget.  pend++ is stamped under
		 * local ILOCK_EXCL and CIL insertion completes before the
		 * holder's dec (mxfs_ilk_note_unlock, fully-ordered), so at 0
		 * the pass's log_force captures every finished mutator —
		 * including the DLM-uncounted classes P15 cannot see.  The
		 * rwsem is untouched: readers never waited on, never blocked
		 * (the .282 convoy).  0 is an observation, not a stable state
		 * (a writer queued in down_write has not inc'd yet); on budget
		 * exhaustion or a sneak-in the pass simply misses and the
		 * defer/requeue backstop below stays the safety mechanism.
		 */
		if (mxfs_relbar_wrq) {
			if (atomic_read_acquire(&ip->i_mxfs_ilk_wr_held) != 0) {
				while (rb_budget > 0) {
					usleep_range(800, 1200);
					rb_budget--;
					if (atomic_read_acquire(
						&ip->i_mxfs_ilk_wr_held) == 0)
						break;
				}
			}
			if (atomic_read_acquire(&ip->i_mxfs_ilk_wr_held) == 0)
				atomic64_inc(&mxfs_relbar_wrq_ok);
			else {
				atomic64_inc(&mxfs_relbar_wrq_tmo);
				/* writer-quiescence budget exhausted: the
				 * settle gave up on a timeout (certificate
				 * timeout field, ruling) */
				if (cert)
					cert->timeout = 1;
			}
		}
		/*
		 * ADMISSION BARRIER (the 119-defer hot-dir shape): the
		 * open ledger here is almost always the LAST admitted mutator
		 * committing between the pipeline's durable flush and this
		 * point — pend++ stamped at xfs_trans_log_inode while its
		 * commit is still in flight, so a durable pass has nothing to
		 * force yet.  An admitted op holds ILOCK_EXCL through commit
		 * end, and NEW admissions are diverted to the DEMOTING wait
		 * INSIDE mxfs_dlm_ilock_begin — which xfs_ilock calls BEFORE
		 * down_write(&i_lock), so no waiter ever parks holding the
		 * rwsem.  Taking the RAW rwsem (never xfs_ilock — that would
		 * re-enter ilock_begin from inside the pipeline) is therefore
		 * a safe, bounded barrier: once acquired, every previously
		 * admitted mutator has finished committing, and the durable
		 * pass that follows captures the final state.
		 */
		if (!mxfs_relbar_wrq && rb_try == 1) {
			/*
			 * LEGACY .283 arm (A/B control, relbar_wrq=0).
			 * BOUNDED: an unconditional down_write convoyed
			 * behind long ILOCK_SHARED readers (readdir holds
			 * the read side across iteration) and, worse, a
			 * queued write-waiter blocks NEW readers — on the
			 * hot shared parent that serialized the whole
			 * cluster (measured: dirent_durability 240s/240s,
			 * 4x its healthy 65s wall).  Trylock for ≤40ms; on
			 * timeout skip the barrier — pass 2 still runs and
			 * an open ledger still defers, which is the safe
			 * pre-barrier behavior.
			 */
			int rb_spin;

			for (rb_spin = 0; rb_spin < 40; rb_spin++) {
				if (down_write_trylock(&ip->i_lock)) {
					up_write(&ip->i_lock);
					break;
				}
				usleep_range(800, 1200);
			}
		}
		if (S_ISDIR(VFS_I(ip)->i_mode))
			__mxfs_dlm_dir_inode_durable(ip);
		else
			(void)mxfs_inode_cluster_durable(ip);
		if (READ_ONCE(ip->i_mxfs_pub_pending_seq) ==
		    READ_ONCE(ip->i_mxfs_pub_durable_seq)) {
			/* F4: under the enforcement gate a closed
			 * pending/durable ledger is not enough for a dir —
			 * committed-never-submitted buffers must also have
			 * retired.  Re-sample; another pass can flush them. */
			if (mxfs_f4_gate && isdir) {
				f4_open = mxfs_f4_open_for_dir(ip->i_mount,
							       ip->i_ino,
							       &f4_unknown);
				if (f4_open == 0 && f4_unknown == 0)
					break;
			} else {
				break;
			}
		}
		/* post-pass recheck observed a still-open ledger and is
		 * bouncing the release back for another drain pass — the
		 * ruling's tripwire-retry event */
		if (rb_try == 0)
			mxfs_relcert_count_tripwire_retry();
	}
	/* F4: post-pass state of the committed-never-submitted set */
	if (isdir)
		f4_open = mxfs_f4_open_for_dir(ip->i_mount, ip->i_ino,
					       &f4_unknown);
	if (cert) {
		uint64_t rc_pend = READ_ONCE(ip->i_mxfs_pub_pending_seq);
		uint64_t rc_dur = READ_ONCE(ip->i_mxfs_pub_durable_seq);
		uint64_t rc_delta = rc_pend - rc_dur;

		cert->dirty_seq_flush = rc_pend;
		cert->oblig_flush = rc_delta > (uint64_t)U32_MAX ?
					U32_MAX : (uint32_t)rc_delta;
		cert->f4_flush = f4_open > (long)U32_MAX ?
					U32_MAX : (uint32_t)f4_open;
		cert->f4_unknown |= f4_unknown ? 1 : 0;
	}
	/* (ruling item 10): INODE stage-7 fault — a forced
	 * OBLIG_ZERO hit models "last obligation did NOT retire": treat the
	 * ledger as open and take the defer branch deterministically. */
	if (cert && mxfs_relgate_fault_forced(MXFS_RGF_OBLIG_ZERO, ip->i_ino))
		cert->fault_forced = 1;
	if ((cert && cert->fault_forced) ||
	    READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
	    READ_ONCE(ip->i_mxfs_pub_durable_seq)) {
		static atomic_t p228_n = ATOMIC_INIT(0);

		/* deferred: the release stays requested but unproven */
		mxfs_rel_state_set(ip, MXFS_RELSTATE_DEMOTING);
		atomic64_inc(&mxfs_relbar_deferred);
		if (atomic_inc_return(&p228_n) <= 400)
			mxfs_probe("mxfs: P228-RELBAR-DEFER ino=%llu arm=%s pend=%llu dur=%llu flush=%llu isdir=%d — obligation would not close after %d durable passes; deferring the wire unlock (requeue)\n",
				(unsigned long long)ip->i_ino, arm,
				(unsigned long long)ip->i_mxfs_pub_pending_seq,
				(unsigned long long)ip->i_mxfs_pub_durable_seq,
				(unsigned long long)ip->i_mxfs_pub_flush_seq,
				S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
				rb_try);
		return true;
	}
	/* F4: pending/durable ledger closed, but the dir still owns
	 * committed-never-submitted buffers (or the unknown-owner poison
	 * bucket is non-empty).  Telemetry mode (gate=0): census probe P285
	 * and proceed — this is exactly the walked-clean-with-obligations
	 * occurrence the registry exists to surface.  Enforcement (gate=1):
	 * defer the wire unlock like an open ledger. */
	if (isdir && (f4_open || f4_unknown)) {
		mxfs_relbar_f4_census(ip, f4_open, f4_unknown, "post-pass");
		if (mxfs_f4_gate) {
			static atomic_t p228_f4_n = ATOMIC_INIT(0);

			if (cert)
				cert->f4_blocked = 1;
			mxfs_rel_state_set(ip, MXFS_RELSTATE_DEMOTING);
			atomic64_inc(&mxfs_relbar_deferred);
			if (atomic_inc_return(&p228_f4_n) <= 400)
				mxfs_probe("mxfs: P228-RELBAR-F4-DEFER ino=%llu arm=%s f4_open=%ld unknown=%d — committed-never-submitted obligations open after %d durable passes; deferring the wire unlock (requeue)\n",
					(unsigned long long)ip->i_ino, arm,
					f4_open, f4_unknown, rb_try);
			return true;
		}
	}
	/*
	 * (step 5 F3): the ledger is closed, but PROVED also
	 * requires the durable flush ticket.  The durable passes above ran
	 * under fua_disable=1 semantics for their epoch bumps only when a
	 * real flush happened; if the current epoch has not passed the
	 * discharge stamp, issue ONE direct flush here (no locks held) and
	 * recheck.  Still no ticket → the proof FAILED: record it on the
	 * certificate and DEFER the wire unlock exactly like an open ledger
	 * (D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516 prerequisite: the
	 * telemetry exit returned the non-defer value and both unlock
	 * arms CASed unproved; the ICLUS class has deferred on every failed
	 * proof since, the INODE class now matches).  Both callers
	 * route a true return through mxfs_inode_defer_causes, which derives
	 * TICKET_STALE from proof_failed/ticket_status, so the bounded episode
	 * (release_proof_enforce=1) or the stranded re-arm applies unchanged.
	 * Reachable only under fua_disable=0 (the ticket check passes
	 * trivially under fua_disable=1) or the forced stage-10 fault.
	 */
	/* (ruling item 10): INODE stage-9/10 faults.  A
	 * forced FLUSH_DONE hit fails the FIRST ticket check (the direct
	 * flush below then usually recovers it — the transient leg); a
	 * forced PROOF hit fails the post-flush recheck too (persistent
	 * proof failure).  Both stages consult the same one-shot matcher. */
	{
		bool rgf9 = cert &&
			mxfs_relgate_fault_forced(MXFS_RGF_FLUSH_DONE,
						  ip->i_ino);
		bool rgf10 = cert &&
			mxfs_relgate_fault_forced(MXFS_RGF_PROOF, ip->i_ino);

		if ((rgf9 || rgf10) && cert)
			cert->fault_forced = 1;
		if (rgf9 || rgf10 || !mxfs_relbar_ticket_ok(ip)) {
			(void)mxfs_blkdev_flush_epoch(ip->i_mount);
			if (rgf10 || !mxfs_relbar_ticket_ok(ip)) {
				static atomic_t p228_tk_n = ATOMIC_INIT(0);

				if (cert) {
					cert->proof_failed = 1;
					cert->ticket_status =
						MXFS_TICKET_FLUSH_FAILED;
				}
				mxfs_rel_state_set(ip, MXFS_RELSTATE_DEMOTING);
				atomic64_inc(&mxfs_relbar_deferred);
				if (atomic_inc_return(&p228_tk_n) <= 400)
					mxfs_probe("mxfs: P228-RELBAR-TICKET-DEFER ino=%llu arm=%s stamp=%llu epoch=%llu forced=%d — no covering durable flush ticket after the direct flush; deferring the wire unlock (requeue)\n",
						(unsigned long long)ip->i_ino, arm,
						(unsigned long long)READ_ONCE(
							ip->i_mxfs_pub_durable_fepoch),
						(unsigned long long)atomic64_read(
							&ip->i_mount->m_mxfs_flush_epoch),
						rgf10 ? 1 : 0);
				return true;
			}
		}
	}
	/* per-instance attestation — proof body ran to completion
	 * in THIS attempt (proof_failed exits above leave it 0) */
	if (cert)
		cert->proved = 1;
	mxfs_rel_state_set(ip, MXFS_RELSTATE_PROVED);
	atomic64_inc(&mxfs_relbar_closed);
	return false;
}

/*
 * (build-order step 3): complete and emit the per-inode release
 * certificate at the wire CAS.  Called immediately after
 * mxfs_v5_dlm_inode_unlock_open on both unlock arms — the moment the
 * grant becomes peer-claimable.  The final tripwire state (ledger delta,
 * IFLUSHING) is captured HERE, after the proof passes, so a commit that
 * raced the flush→unlock window shows up as oblig_cas != 0 (the F1
 * occurrence P281 names).  Observation only this step: the CAS already
 * happened when this runs.
 */
void
mxfs_inode_relcert_finish(struct xfs_inode *ip, struct mxfs_release_cert *cert,
			  int cas_result, uint64_t t0)
{
	uint64_t rc_pend = READ_ONCE(ip->i_mxfs_pub_pending_seq);
	uint64_t rc_dur = READ_ONCE(ip->i_mxfs_pub_durable_seq);
	uint64_t rc_delta = rc_pend - rc_dur;

	cert->cas_attempted = 1;
	cert->cas_result = cas_result;
	cert->drain_ns = ktime_get_ns() - t0;
	cert->dirty_seq_tripwire = rc_pend;
	cert->oblig_cas = rc_delta > (uint64_t)U32_MAX ?
				U32_MAX : (uint32_t)rc_delta;
	cert->inflight_cas = xfs_iflags_test(ip, XFS_IFLUSHING) ? 1 : 0;
	/*
	 * F2 domain fact, same terms as the ICLUS site: a tenure-boundary
	 * flush ticket is required unless the operator declared the target
	 * cache power-protected; under fua_disable=1 no real flush covered
	 * the settled writes (counted as cas_noticket, never printed).
	 *
	 * (step 5 F3, ruling item C): in fua_disable=0 mode
	 * the ticket is REVALIDATED here against the CURRENT durable_seq —
	 * the proof's ticket only counts if a real flush still covers the
	 * discharge stamp as of the CAS.  A durable_seq that advanced past
	 * the proof re-stamps the fepoch, so observed>stamp failing here
	 * means the ticket went STALE in the proof→CAS window (the F3
	 * check-then-CAS occurrence, now countable).
	 */
	cert->ticket_required = 1;
	{
		uint64_t stamp, observed;

		smp_rmb();	/* pair with the stamp sites: rc_dur above,
				 * then the stamp */
		stamp = READ_ONCE(ip->i_mxfs_pub_durable_fepoch);
		observed = (uint64_t)atomic64_read(
				&ip->i_mount->m_mxfs_flush_epoch);
		cert->ticket_seq = rc_dur;
		cert->stamp_epoch = stamp;
		cert->observed_epoch = observed;
		if (!mxfs_fua_disable) {
			cert->ticket_completed = observed > stamp;
			if (cert->ticket_status != MXFS_TICKET_FLUSH_FAILED)
				cert->ticket_status = cert->ticket_completed ?
					MXFS_TICKET_REAL_FLUSH :
					MXFS_TICKET_STALE;
		} else {
			cert->ticket_completed =
				mxfs_target_cache_protected ? 1 : 0;
			cert->ticket_status = mxfs_target_cache_protected ?
				MXFS_TICKET_PROTECTED : MXFS_TICKET_NO_DOMAIN;
		}
	}
	mxfs_release_cert_emit(cert);
	/* attempt over (whatever the CAS said) — tenure state returns to
	 * ACTIVE; a failed CAS re-enters via DEMOTING on the requeue.
	 * (ruling item 3): a SUCCESSFUL CAS closes the
	 * defer episode — the only reset point (never local reacquire,
	 * repeated BAST or cause change).  Build 1 still CASes unproved on
	 * proof_failed, so close keys on cas_result==0 mirroring the iclus
	 * release-done; the proved-only flip is build 2.  WEDGED is
	 * terminal: never overwrite it with ACTIVE. */
	{
		bool episode_closed = false;

		spin_lock(&ip->i_dlm_lock);
		if (cas_result == 0 && ip->i_mxfs_reldefer_started_j) {
			ip->i_mxfs_reldefer_started_j = 0;
			ip->i_mxfs_reldefer_progress_j = 0;
			ip->i_mxfs_reldefer_causes = 0;
			ip->i_mxfs_reldefer_badness = 0;
			ip->i_mxfs_reldefer_tries = 0;
			ip->i_mxfs_reldefer_reloads = 0;	/* */
			WRITE_ONCE(ip->i_mxfs_pub_fenced, 0);	/* */
			episode_closed = true;
		}
		/*
		 * (D-DUP-RELEASE-HANDOFF-INVARIANTS-UNVERIFIED,
		 * invariant 4): duplicate concurrent pipelines on one inode
		 * are legal (ruling); the LOSING instance's finish must
		 * not write ACTIVE over the winner's RELEASING.  Only the
		 * instance that last entered RELEASING (rel_instance stamp)
		 * resets; the other's reset is skipped and counted.
		 */
		if (READ_ONCE(ip->i_mxfs_rel_state) != MXFS_RELSTATE_WEDGED) {
			if (!cert->rel_instance ||
			    atomic_read(&ip->i_mxfs_rel_instance) ==
			    (int)cert->rel_instance)
				WRITE_ONCE(ip->i_mxfs_rel_state,
					   MXFS_RELSTATE_ACTIVE);
			else
				mxfs_probe_ratelimited("mxfs: P283-REL-FINISH-SKIP ino=%llu instance=%u current=%d state=%u cas=%d — a concurrent pipeline owns rel_state; not resetting\n",
					(unsigned long long)ip->i_ino,
					cert->rel_instance,
					atomic_read(&ip->i_mxfs_rel_instance),
					READ_ONCE(ip->i_mxfs_rel_state),
					cas_result);
		}
		spin_unlock(&ip->i_dlm_lock);
		if (episode_closed)
			wake_up_all(&ip->i_dlm_wait);
	}
}

/* Defer flavor: the relbar proof would not close the ledger and the arm
 * is requeueing the release instead of unlocking. */
void
mxfs_inode_relcert_defer(struct xfs_inode *ip, struct mxfs_release_cert *cert,
			 uint64_t t0)
{
	cert->defer_kind = MXFS_RELDEFER_OBLIG;
	cert->defer_reason = "relbar open after durable passes";
	cert->drain_ns = ktime_get_ns() - t0;
	mxfs_release_cert_emit(cert);
}

/*
 * (INODE-containment ruling item 7): derive the explicit
 * defer-cause mask for this attempt from its certificate.  A defer with NO
 * derivable cause is an invariant failure — certify it as UNKNOWN and say
 * so.  A fault-forced failure attributes to the cause the armed stage
 * models (an open obligation ledger) rather than tripping that probe.
 */
unsigned int
mxfs_inode_defer_causes(struct xfs_inode *ip,
			const struct mxfs_release_cert *cert)
{
	unsigned int causes = 0;

	if (cert->oblig_flush)
		causes |= MXFS_RELCAUSE_OBLIG_OPEN;
	if (cert->f4_blocked || cert->f4_flush)
		causes |= MXFS_RELCAUSE_F4_OPEN;
	if (cert->f4_unknown)
		causes |= MXFS_RELCAUSE_F4_UNKNOWN;
	if (cert->proof_failed ||
	    cert->ticket_status == MXFS_TICKET_FLUSH_FAILED)
		causes |= MXFS_RELCAUSE_TICKET_STALE;
	if (!causes && cert->fault_forced)
		causes |= MXFS_RELCAUSE_OBLIG_OPEN;
	if (!causes) {
		static atomic_t nocause_n = ATOMIC_INIT(0);

		causes = MXFS_RELCAUSE_UNKNOWN;
		if (atomic_inc_return(&nocause_n) <= 200)
			pr_err("mxfs: P-INODE-DEFER-NOCAUSE ino=%llu path=%s oblig=%u f4=%u/%u pf=%u tstat=%u — release deferred with no derivable cause (invariant failure)\n",
			       (unsigned long long)ip->i_ino,
			       cert->path ? cert->path : "-",
			       cert->oblig_flush, cert->f4_flush,
			       cert->f4_unknown, cert->proof_failed,
			       cert->ticket_status);
	}
	return causes;
}

/* Ruling item 3: badness weights the causes; a DECREASE between attempts
 * is genuine progress (a cause retired) and restamps the progress clock —
 * retries, new BASTs and cause oscillation are not. */
static unsigned int
mxfs_inode_defer_badness(unsigned int causes)
{
	return ((causes & MXFS_RELCAUSE_UNKNOWN) ? 8 : 0) +
	       ((causes & MXFS_RELCAUSE_OBLIG_OPEN) ? 4 : 0) +
	       ((causes & (MXFS_RELCAUSE_F4_OPEN |
			   MXFS_RELCAUSE_F4_UNKNOWN)) ? 2 : 0) +
	       ((causes & MXFS_RELCAUSE_TICKET_STALE) ? 1 : 0);
}

/*
 * Ruling items 4/5: 60s without progress or 300s total → wedge.  Caller
 * holds i_dlm_lock.
 *
 * the two bounds are now knobs, for TESTING, not for tuning.  The
 * natural fence-abandoned publications on this rig all resolve well inside 60s
 * — which is exactly why the wedge they can cause is luck-dependent and why
 * every attempt to reproduce it with a real workload failed.  Shrinking ONLY
 * the bound turns those same real, unmodified fences into observable wedges,
 * so a fix can be verified against the NATURAL cause instead of only against
 * fault injection (the design-consult ruling recommends exactly this: "shorten
 * only the test episode timeout").
 *
 * DO NOT raise these to make something pass.  A larger bound does not make an
 * unresolvable release resolvable; it only lengthens the window in which the
 * grant is held and peers are blocked.
 */
bool
mxfs_inode_episode_expired_locked(struct xfs_inode *ip)
{
	unsigned int np = READ_ONCE(mxfs_reldefer_noprogress_ms);
	unsigned int tot = READ_ONCE(mxfs_reldefer_total_ms);

	return ip->i_mxfs_reldefer_started_j &&
	       (time_after(jiffies,
			   ip->i_mxfs_reldefer_progress_j +
				msecs_to_jiffies(np)) ||
		time_after(jiffies,
			   ip->i_mxfs_reldefer_started_j +
				msecs_to_jiffies(tot)));
}

/*
 * (ruling, INODE analog of mxfs_iclus_defer_arm): enter or
 * extend the per-inode defer episode.  Unlike the ICLUS class this arms no
 * worker of its own — the existing stranded re-arm / bast dwork owns retry
 * scheduling (with episode-aware backoff at the arm site).  Returns true
 * when the bounds expired and the caller must WEDGE instead of deferring.
 */
bool
mxfs_inode_defer_arm(struct xfs_inode *ip, unsigned int causes)
{
	unsigned int badness = mxfs_inode_defer_badness(causes);
	bool wedge = false;

	spin_lock(&ip->i_dlm_lock);
	if (!ip->i_mxfs_reldefer_started_j) {
		ip->i_mxfs_reldefer_started_j = jiffies ?: 1;
		ip->i_mxfs_reldefer_progress_j = jiffies;
		ip->i_mxfs_reldefer_badness = badness;
		ip->i_mxfs_reldefer_reloads = 0;	/* */
	} else {
		if (badness < ip->i_mxfs_reldefer_badness) {
			ip->i_mxfs_reldefer_progress_j = jiffies;
			ip->i_mxfs_reldefer_badness = badness;
		}
		if (mxfs_inode_episode_expired_locked(ip))
			wedge = true;
	}
	ip->i_mxfs_reldefer_causes |= causes;
	if (!wedge)
		ip->i_mxfs_reldefer_tries++;
	spin_unlock(&ip->i_dlm_lock);
	return wedge;
}

/*
 * (ruling items 6/8/9): the bounded end of an INODE defer
 * episode.  One-shot per inode incarnation: pin the wedged grant on the
 * DLM side so the unconditional teardown release_all cannot strip our
 * unproven bits (peers then refuse our clean departure; their recovery
 * machinery fences and recovers us), mark the resource WEDGED (terminal —
 * admission refused in ilock_begin, CAS refused pre-submit), FREEZE the
 * episode fields as evidence, and force-shutdown the mount — skipped
 * under teardown, where the mount is already going away, UNLESS the pin
 * failed (then the shutdown is the only fence left).  NEVER CASes.
 */
void
mxfs_inode_wedge(struct xfs_inode *ip, struct mxfs_release_cert *cert,
		 bool teardown)
{
	struct xfs_mount *mp = ip->i_mount;
	bool shoot = false;
	int pin_rc;

	spin_lock(&ip->i_dlm_lock);
	WRITE_ONCE(ip->i_mxfs_rel_state, MXFS_RELSTATE_WEDGED);
	if (!ip->i_mxfs_relwedge_shot) {
		ip->i_mxfs_relwedge_shot = true;
		shoot = true;
	}
	spin_unlock(&ip->i_dlm_lock);
	if (shoot) {
		pin_rc = mp->m_mxfs_dlm ?
			mxfs_v5_dlm_inode_pin(mp->m_mxfs_dlm, ip->i_ino) :
			-ENODEV;
		if (cert) {
			cert->cas_attempted = 0;
			cert->defer_kind = MXFS_RELDEFER_WEDGE;
			cert->defer_reason = teardown ?
				"teardown with unproven release" :
				"no-progress bound exceeded";
			mxfs_release_cert_emit(cert);
		}
		pr_err("mxfs: P-INODE-WEDGE ino=%llu tries=%u causes=0x%x badness=%u pin_rc=%d teardown=%d — release unprovable within bounds; grant PINNED on disk, admission closed%s\n",
		       (unsigned long long)ip->i_ino,
		       ip->i_mxfs_reldefer_tries,
		       ip->i_mxfs_reldefer_causes,
		       ip->i_mxfs_reldefer_badness, pin_rc,
		       teardown ? 1 : 0,
		       (teardown && !pin_rc) ?
			   " (teardown: departure will not be clean)" :
			   "; forcing shutdown");
		if (!teardown || pin_rc)
			xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
	}
	wake_up_all(&ip->i_dlm_wait);
}

/*
 * (lap-6 typeflip, instrumented chain on test18 19:30:43Z; design-consult ruling
 * 2026-08-22): PRE-LOG AUTHORIZATION for every SYNTHETIC re-log — the tiny
 * tr_ichange transactions the release drain manufactures itself (the P146V
 * "clean-but-unlanded" arm, the P182 shortform pre-merge).  Those are not
 * user-driven metadata changes made under a held EX; they are the drain
 * deciding, from a comparison of its in-core object against the platter, to
 * make the in-core object the platter truth.  That is only legitimate while
 * THIS node owns the inode's write tenure RIGHT NOW.
 *
 * Measured violation: test18 kept a clean in-core DIRECTORY (gen 415329758)
 * for an inode number a peer had removed+freed and test27 had re-created as a
 * FILE (gen 348095055) two seconds earlier.  An orphan BAST drain ran at
 * held_mode=0: the destage-time tenure verify correctly refused
 * (P-ICD-TENURE-REFUSE, i_dlm_icd_refused set), and then the P146V arm —
 * which only knew "platter differs from core" — RE-LOGGED the dead dir core
 * (P58-DIRPIN-NONEX dlm_mode=0) and the next cluster write carried the now
 * LOGGED slot (P56-DIRWRITE relflush=1 logged=1 write=[]) over the live file:
 * dirent=file / dinode=dir cluster-wide -> P201-TYPEFLIP-UNRESOLVED-FAIL
 * -ESTALE.  Neither existing guard fired: P146D needs a dead-incarnation
 * marker that only a dirent-validated reload sets, P189 needs gen equality.
 *
 * Ruling: never synthesize a re-log while the node holds no EX on the inode —
 * gen equality/inequality must not create an exception (ABA-fragile); a
 * directory's core mutation needs EX, not merely PR; the drain's own tenure
 * refusal (i_dlm_icd_refused) must also veto.  Returns true when the re-log
 * may proceed.  On refusal it prints P146V-NOAUTH-REFUSE and leaves the
 * platter-differs state classified: a FOREIGN gen on disk means our in-core
 * object is a dead prior incarnation -> write-poison it (i_mxfs_dead_incarn_
 * gen, cleared only by validated adoption) + i_dlm_stale so the next access
 * adopts disk; the SAME gen means a committed change of ours may be unlanded
 * but we lost tenure -> i_dlm_stale + i_dlm_icd_refused stay set and the
 * v0.6.5 next-acquire merge is the sanctioned path to land it; the caller
 * must NOT report that as durable.  Sleeps (slot read on CAW): drain/worker
 * context only.
 */
bool
mxfs_dlm_relog_authorized(
	struct xfs_inode	*ip,
	const char		*site,
	uint32_t		disk_gen)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint8_t			held_mode;
	bool			foreign;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return true;
	held_mode = mxfs_v5_dlm_inode_held_rawmode(mp->m_mxfs_dlm, ip->i_ino);
	foreign = disk_gen != VFS_I(ip)->i_generation;
	/*
	 * 0.23.8 MEASURED (6 laps, 32/caw): the first cut also vetoed on
	 * i_dlm_icd_refused and refused 24-43 re-logs per node on the hot
	 * shared dirs (ino 696/708) at held_mode=EX foreign=0 — the flag is
	 * STICKY (cleared only by a real destage write, 7479) and the P146V
	 * re-log was the very thing that produced that write, so the veto
	 * self-perpetuated.  Authority is the on-disk slot mode, full stop;
	 * the flag is printed for forensics only.
	 *
	 * Under EX, a SAME-gen core is ours to publish.  A FOREIGN platter gen
	 * under EX is legitimate only with create provenance (our own unlanded
	 * create: i_mxfs_self_created); otherwise it is a dead in-core that a
	 * reacquire has not adopted yet, and re-logging it is the measured
	 * clobber with an EX label on it (ruling: "a newly reacquired EX alone
	 * must not allow an old cached inode to be re-logged before
	 * reload/adoption").
	 */
	if (held_mode >= MXFS_LOCK_EX &&
	    (!foreign || ip->i_mxfs_self_created))
		return true;

	pr_warn("mxfs: P146V-NOAUTH-REFUSE ino=%llu site=%s held_mode=%u icd_refused=%d self_created=%d dlm_mode=%u state=%u incore[gen=%u mode=0%o nlink=%u] disk_gen=%u foreign=%d comm=%s — synthetic re-log refused: %s\n",
		(unsigned long long)ip->i_ino, site, held_mode,
		ip->i_dlm_icd_refused ? 1 : 0, ip->i_mxfs_self_created ? 1 : 0,
		ip->i_dlm_mode, ip->i_dlm_state,
		VFS_I(ip)->i_generation, VFS_I(ip)->i_mode, VFS_I(ip)->i_nlink,
		disk_gen, foreign ? 1 : 0, current->comm,
		foreign ? (held_mode >= MXFS_LOCK_EX ?
			   "EX held but the platter holds a foreign incarnation and this is not our create: dead in-core not yet adopted (write-poisoned, stale)" :
			   "no EX tenure; platter holds a foreign incarnation, in-core is a dead prior life (write-poisoned, stale)") :
			  "no EX tenure; same incarnation, committed change (if any) re-lands via the next-acquire merge (stale, refused)");
	if (foreign) {
		ip->i_mxfs_dead_incarn_gen = disk_gen;
		ip->i_dlm_stale = true;
		ip->i_dlm_stale_src = 100;
	} else {
		ip->i_dlm_stale = true;
		ip->i_dlm_stale_src = 101;
		ip->i_dlm_icd_refused = true;
	}
	return false;
}

/*
 * Operator statement that the shared target's write cache is power-
 * protected (or that target power loss is explicitly outside the
 * deployment's durability scope), making coherence-only mode
 * (fua_disable=1, flush_epoch no-op) a sound domain for the gate.  Ruled a
 * SEPARATE knob — never overload mxfs_fua_disable.  0 = target
 * cache loss is in scope and coherence-only mode cannot arm the gate.
 */
int mxfs_target_cache_protected;
EXPORT_SYMBOL(mxfs_target_cache_protected);

/* (#1 design review Q5): guarded like fua_disable — withdrawing the
 * declaration while the token-enforce knob is armed under fua_disable=1
 * would invalidate the F2 domain that arming was validated against. */
static int
mxfs_target_cache_protected_set(const char *val, const struct kernel_param *kp)
{
	int v;
	int rc = kstrtoint(val, 0, &v);

	if (rc)
		return rc;
	mutex_lock(&mxfs_fr_cfg_lock);
	if (!v && READ_ONCE(mxfs_foreign_replay_token_enforce) &&
	    READ_ONCE(mxfs_fua_disable)) {
		mutex_unlock(&mxfs_fr_cfg_lock);
		pr_err("mxfs: target_cache_protected=0 REFUSED while foreign_replay_token_enforce is armed under fua_disable=1 — the declaration is the F2 predicate that arming was validated against.  Disarm foreign_replay_token_enforce first\n");
		return -EBUSY;
	}
	WRITE_ONCE(mxfs_target_cache_protected, v);
	mutex_unlock(&mxfs_fr_cfg_lock);
	return 0;
}
static const struct kernel_param_ops mxfs_target_cache_protected_ops = {
	.set = mxfs_target_cache_protected_set,
	.get = param_get_int,
};
module_param_cb(target_cache_protected, &mxfs_target_cache_protected_ops,
		&mxfs_target_cache_protected, 0644);
MODULE_PARM_DESC(target_cache_protected,
                 "operator declares the shared target's write cache power-"
                 "protected / target power loss out of durability scope "
                 "(0=in scope default; prerequisite for replay_gate_enforce "
                 "under fua_disable=1)");

/*
 * build-order step 2 — release certificates + aggregate counters
 * + deterministic fault injection (ruling).  Observation only:
 * no release path changes behavior this step.  The counter set is the
 * ruling's, verbatim; cas_invalid_proof splits into its two observable
 * causes so the F1 signal (dirty state at CAS — rare, per-release) is
 * not drowned by the F2 signal (no covering flush ticket — config-wide
 * under fua_disable=1 without target_cache_protected).
 */
static atomic64_t mxfs_relcert_attempts;
static atomic64_t mxfs_relcert_success;
static atomic64_t mxfs_relcert_defer_oblig;
static atomic64_t mxfs_relcert_defer_io;
static atomic64_t mxfs_relcert_defer_pincil;
static atomic64_t mxfs_relcert_defer_flush;
static atomic64_t mxfs_relcert_tripwire_retries;
static atomic64_t mxfs_relcert_drain_timeouts;
static atomic64_t mxfs_relcert_wedges;
static atomic64_t mxfs_relcert_cas_invalid_proof;
static atomic64_t mxfs_relcert_cas_dirty;	/* F1: obligations/inflight at CAS */
static atomic64_t mxfs_relcert_cas_noticket;	/* F2: required flush ticket absent */
static atomic64_t mxfs_relcert_cas_unproved;	/* DIAGNOSTIC: shared-scalar state != PROVED at CAS — aliased by legal concurrent releases */
static atomic64_t mxfs_relcert_cas_noproof_v2;	/* CAS with THIS instance's proof incomplete (per-instance, alias-immune) — the steps 9-10 gate input */
static atomic64_t mxfs_relcert_f4_open;		/* F4: cert saw committed-never-submitted open post-pass */
static atomic64_t mxfs_relcert_f4_blocked;	/* F4: enforcement gate deferred the unlock */
static atomic64_t mxfs_relcert_proof_failed;	/* F3: completion proof failed (unknown/timeout/gen-moved/no-ticket) */
static atomic64_t mxfs_relcert_ticket_stale;	/* F3: ticket went stale in the proof→CAS window */
static atomic64_t mxfs_relcert_tripwires;	/* F3: final pre-CAS keyed re-sample saw movement */
static atomic64_t mxfs_relgate_fault_hits;

/* proof_failed releases the enforcement DEFERRED (no CAS) — the
 * ruling requires this counted separately from CAS-with-failed-proof,
 * which must be 0 under enforcement. */
static atomic64_t mxfs_relcert_deferred_proof_failed;

/* 1 = print every certificate (P280); counters are always fed. */
static int mxfs_release_cert_log;
module_param_named(release_cert_log, mxfs_release_cert_log, int, 0644);
MODULE_PARM_DESC(release_cert_log,
                 "print a P280-RELEASE-CERT line per release attempt "
                 "(0=counters only default)");

void
mxfs_release_cert_emit(const struct mxfs_release_cert *rc)
{
	bool dirty_at_cas, noticket;

	atomic64_inc(&mxfs_relcert_attempts);
	if (rc->timeout)
		atomic64_inc(&mxfs_relcert_drain_timeouts);
	switch (rc->defer_kind) {
	case MXFS_RELDEFER_OBLIG:
		atomic64_inc(&mxfs_relcert_defer_oblig);
		break;
	case MXFS_RELDEFER_IO:
		atomic64_inc(&mxfs_relcert_defer_io);
		break;
	case MXFS_RELDEFER_PINCIL:
		atomic64_inc(&mxfs_relcert_defer_pincil);
		break;
	case MXFS_RELDEFER_FLUSH:
		atomic64_inc(&mxfs_relcert_defer_flush);
		break;
	case MXFS_RELDEFER_WEDGE:
		atomic64_inc(&mxfs_relcert_wedges);
		break;
	}
	/* F4: separate from the pending-durable oblig_* delta (ruling
	 * item 10) — count certs that closed the ledger but still carried
	 * committed-never-submitted obligations, and gate-blocked ones. */
	if (rc->f4_flush || rc->f4_unknown)
		atomic64_inc(&mxfs_relcert_f4_open);
	if (rc->f4_blocked)
		atomic64_inc(&mxfs_relcert_f4_blocked);
	/* step-5 F3 signals (fed from the keyed completion proof) */
	if (rc->proof_failed)
		atomic64_inc(&mxfs_relcert_proof_failed);
	/* F1 enforce: proof failed AND no CAS = the deferral worked */
	if (rc->proof_failed && !rc->cas_attempted)
		atomic64_inc(&mxfs_relcert_deferred_proof_failed);
	if (rc->ticket_status == MXFS_TICKET_STALE)
		atomic64_inc(&mxfs_relcert_ticket_stale);
	if (rc->tripwire)
		atomic64_inc(&mxfs_relcert_tripwires);
	dirty_at_cas = rc->cas_attempted &&
		       (rc->oblig_cas || rc->inflight_cas);
	noticket = rc->cas_attempted &&
		   rc->ticket_required && !rc->ticket_completed;
	if (dirty_at_cas || noticket) {
		atomic64_inc(&mxfs_relcert_cas_invalid_proof);
		if (dirty_at_cas)
			atomic64_inc(&mxfs_relcert_cas_dirty);
		if (noticket)
			atomic64_inc(&mxfs_relcert_cas_noticket);
	}
	if (rc->cas_attempted && rc->cas_result == 0 &&
	    !dirty_at_cas && !noticket && !rc->proof_failed && !rc->tripwire)
		atomic64_inc(&mxfs_relcert_success);
	/*
	 * step 3 / P283 fix: state-machine audit.  The
	 * legacy cas_unproved count samples the SHARED per-resource scalar,
	 * which two legal concurrent release pipelines (two-slot demoter)
	 * alias in both directions — it stays as a diagnostic only.  The
	 * sound audit is per-instance: cert->proved is stamped by THIS
	 * attempt's proof body and cannot be aliased, so cas_attempted
	 * without proved (cas_noproof_v2) is the count steps 9-10 require
	 * to be ZERO before the gate may enable for that class.  Orthogonal
	 * to dirty_at_cas: the ledger can read clean while the proof never
	 * ran.
	 */
	if (rc->cas_attempted && rc->rel_state_cas != MXFS_RELSTATE_PROVED)
		atomic64_inc(&mxfs_relcert_cas_unproved);
	if (rc->cas_attempted && !rc->proved) {
		atomic64_inc(&mxfs_relcert_cas_noproof_v2);
		mxfs_probe_ratelimited(
		    "mxfs: P283-RELCERT-CAS-UNPROVED class=%u res=%llu path=%s relstate=%u relgen=%u — wire CAS entered without a completed release proof (per-instance)\n",
			rc->rclass, (unsigned long long)rc->res_id,
			rc->path ? rc->path : "?", rc->rel_state_cas,
			rc->rel_gen);
	}
	/*
	 * F1 occurrence: the release went to CAS with unretired dirty
	 * state.  High-severity by ruling ("normally impossible");
	 * suppression arrives with the common proof helper (step 3+) —
	 * this step observes.  The F2-only case is a domain property,
	 * not a per-release event, so it never prints here.
	 */
	if (dirty_at_cas)
		pr_err_ratelimited(
		    "mxfs: P281-RELCERT-INVALID-PROOF class=%u res=%llu path=%s oblig=%u inflight=%u timeout=%u cas_rc=%d — release reached CAS with unretired dirty state (F1)\n",
			rc->rclass, (unsigned long long)rc->res_id,
			rc->path ? rc->path : "?", rc->oblig_cas,
			rc->inflight_cas, rc->timeout, rc->cas_result);
	if (mxfs_release_cert_log)
		mxfs_probe("mxfs: P280-RELEASE-CERT class=%u res=%llu path=%s relstate=%u proved=%u relgen=%u handoff=%u cas=%u rc=%d oldep=%llu newep=%llu dseq=%llu/%llu/%llu oblig=%u/%u/%u infl=%u tkt=%u/%u adm=%llu/%llu drain_us=%llu timeout=%u defer=%u:%s f4=%u/%u unk=%u blk=%u tstat=%u pf=%u trip=%u tseq=%llu sep=%llu oep=%llu icwr=%llu/%u/%llu\n",
			rc->rclass, (unsigned long long)rc->res_id,
			rc->path ? rc->path : "?", rc->rel_state_cas,
			rc->proved, rc->rel_gen,
			rc->handoff,
			rc->cas_attempted, rc->cas_result,
			(unsigned long long)rc->old_epoch,
			(unsigned long long)rc->new_epoch,
			(unsigned long long)rc->dirty_seq_quiesce,
			(unsigned long long)rc->dirty_seq_flush,
			(unsigned long long)rc->dirty_seq_tripwire,
			rc->oblig_quiesce, rc->oblig_flush, rc->oblig_cas,
			rc->inflight_cas, rc->ticket_required,
			rc->ticket_completed,
			(unsigned long long)rc->admission_before,
			(unsigned long long)rc->admission_after,
			(unsigned long long)(rc->drain_ns / 1000),
			rc->timeout, rc->defer_kind,
			rc->defer_reason ? rc->defer_reason : "-",
			rc->f4_quiesce, rc->f4_flush, rc->f4_unknown,
			rc->f4_blocked,
			rc->ticket_status, rc->proof_failed, rc->tripwire,
			(unsigned long long)rc->ticket_seq,
			(unsigned long long)rc->stamp_epoch,
			(unsigned long long)rc->observed_epoch,
			(unsigned long long)rc->icwr_daddr,
			rc->icwr_inflight_final,
			(unsigned long long)rc->icwr_gen_final);
}

/* External feeder for retry loops that do not build a full certificate
 * (final-tripwire recheck bouncing a release back to drain). */
void
mxfs_relcert_count_tripwire_retry(void)
{
	atomic64_inc(&mxfs_relcert_tripwire_retries);
}

static int
mxfs_relcert_dump_set(const char *val, const struct kernel_param *kp)
{
	(void)val; (void)kp;
	pr_warn("mxfs: P280-RELEASE-CERT-TOTAL attempts=%lld success=%lld defer_oblig=%lld defer_io=%lld defer_pincil=%lld defer_flush=%lld tripwire_retries=%lld drain_timeouts=%lld wedges=%lld cas_invalid_proof=%lld cas_dirty=%lld cas_noticket=%lld cas_unproved=%lld cas_noproof_v2=%lld f4_open=%lld f4_blocked=%lld proof_failed=%lld deferred_proof_failed=%lld ticket_stale=%lld tripwires=%lld fault_hits=%lld\n",
		(long long)atomic64_read(&mxfs_relcert_attempts),
		(long long)atomic64_read(&mxfs_relcert_success),
		(long long)atomic64_read(&mxfs_relcert_defer_oblig),
		(long long)atomic64_read(&mxfs_relcert_defer_io),
		(long long)atomic64_read(&mxfs_relcert_defer_pincil),
		(long long)atomic64_read(&mxfs_relcert_defer_flush),
		(long long)atomic64_read(&mxfs_relcert_tripwire_retries),
		(long long)atomic64_read(&mxfs_relcert_drain_timeouts),
		(long long)atomic64_read(&mxfs_relcert_wedges),
		(long long)atomic64_read(&mxfs_relcert_cas_invalid_proof),
		(long long)atomic64_read(&mxfs_relcert_cas_dirty),
		(long long)atomic64_read(&mxfs_relcert_cas_noticket),
		(long long)atomic64_read(&mxfs_relcert_cas_unproved),
		(long long)atomic64_read(&mxfs_relcert_cas_noproof_v2),
		(long long)atomic64_read(&mxfs_relcert_f4_open),
		(long long)atomic64_read(&mxfs_relcert_f4_blocked),
		(long long)atomic64_read(&mxfs_relcert_proof_failed),
		(long long)atomic64_read(&mxfs_relcert_deferred_proof_failed),
		(long long)atomic64_read(&mxfs_relcert_ticket_stale),
		(long long)atomic64_read(&mxfs_relcert_tripwires),
		(long long)atomic64_read(&mxfs_relgate_fault_hits));
	return 0;
}
static const struct kernel_param_ops mxfs_relcert_dump_ops = {
	.set = mxfs_relcert_dump_set,
};
module_param_cb(release_cert_dump, &mxfs_relcert_dump_ops, NULL, 0644);

/*
 * Fault engine (ruling): stage IDs are stable (header enum),
 * default off behind a static key so armed-off cost is a NOP patch site.
 * Arm by writing the stage number to mxfs.relgate_fault_stage; the hook
 * fires only when the (optional) resource filter matches, applies the
 * configured delay (sleepable context only — every placement site must
 * tolerate msleep), and one-shots by default so a board exercises one
 * deterministic boundary per arm.
 */
DEFINE_STATIC_KEY_FALSE(mxfs_relgate_fault_key);
static int mxfs_relgate_fault_stage;		/* 0 = disarmed, 1-18 armed */
static unsigned long long mxfs_relgate_fault_res; /* 0 = any resource */
static int mxfs_relgate_fault_delay_ms = 100;
static int mxfs_relgate_fault_oneshot = 1;
/* (ruling item 10): when set, an armed stage's placement
 * site FORCES the failure the stage models instead of only delaying —
 * required for deterministic INODE-class defer/wedge legs. */
static int mxfs_relgate_fault_force;

/*
 * — DETERMINISTIC FENCED-FLUSH FAULT (D-RELOG-BEHIND-DISK-OBLIGATION-
 * DEADLOCK-WEDGE-380).
 *
 * xfs_iflush has eleven "safe skip" fences that abandon a flush with
 * `error = 0; goto flush_out;` and DO NOT stamp i_mxfs_pub_flush_seq.  That
 * leaves the publication obligation (pending_seq != durable_seq) permanently
 * open, and the release drain then re-logs the clean-but-unlanded core
 * (P146V) forever — each re-log bumping pending_seq via xfs_trans_log_inode —
 * until the defer episode's no-progress bound fires P-INODE-WEDGE and force-
 * shuts down the whole mount.
 *
 * That chain is proven from rig captures, but every natural trigger for it is
 * luck-dependent: got ONE wedge in three attempts under the knob arms
 * that were supposed to force it, and the third attempt did not fire the fence
 * at all.  the zero-defect bar requires testing that EXERCISES THE CAUSE, so the cause needs
 * a switch.  Arming this makes a chosen inode's flush take exactly the fence
 * shape — no stamp, error 0, i_dlm_stale set — on demand.
 *
 * 0 = disarmed.  Set to an inode number to fence that inode's flushes; _n
 * bounds how many are fenced (0 = unlimited while armed), so a test can model
 * both "fenced until something reloads" and "fenced N times then recovers".
 */
/*
 * — release-side reload of a fence-abandoned publication.
 * A/B lever: 0 restores the pre-fix behaviour (i_dlm_stale has no release-path
 * consumer, so the obligation can only be reconciled by a coincidental local
 * reader) and is the negative control the fix is measured against.
 */
/* ruling-2 Q2: emit the canonical home-vs-owed comparison at every
 * fence-abandoned publication.  Telemetry only — no code acts on the verdict
 * until it has been validated against injected exact-match and single-field
 * mismatch cases. */
/* ruling-2 Q1: keep the drain's own gated re-log from advancing the
 * logical version / di_changecount.  0 = pre-fix control. */
/*
 * — the release-defer episode bounds, in ms.  Knobs for TESTING only
 * (see mxfs_inode_episode_expired_locked).  Defaults are the shipped 60s
 * no-progress / 300s total.
 */
unsigned int mxfs_reldefer_noprogress_ms = 60000;
unsigned int mxfs_reldefer_total_ms = 300000;
module_param_named(reldefer_noprogress_ms, mxfs_reldefer_noprogress_ms, uint, 0644);
MODULE_PARM_DESC(reldefer_noprogress_ms,
                 "release-defer episode no-progress bound in ms (default "
                 "60000).  Shrink to make naturally-transient fence-abandoned "
                 "publications reach the wedge observably; never raise it to "
                 "make a test pass");
module_param_named(reldefer_total_ms, mxfs_reldefer_total_ms, uint, 0644);
MODULE_PARM_DESC(reldefer_total_ms,
                 "release-defer episode total bound in ms (default 300000)");

/*
 * the drain's own gated re-log does not create a NEW publication
 * obligation (it re-logs an unchanged core purely to get it flushed).
 * A/B lever, 0 = pre-fix.  Kept separate from relog_holds_version because the
 * two counters answer different questions — this one is the obligation ledger,
 * that one is the cross-node freshness stamp — and needed to attribute
 * the disappearance of natural release deferrals to one of them.
 */
int mxfs_relog_holds_obligation = 1;
module_param_named(relog_holds_obligation, mxfs_relog_holds_obligation, int, 0644);
MODULE_PARM_DESC(relog_holds_obligation,
                 "the release drain's gated re-log does not increment "
                 "pub_pending_seq (a republication is not a new obligation); "
                 "0=pre-fix control");

/*
 * FAULT INJECTION (design-consult ruling verification item): make xfs_iflush
 * LAUNDER the next N PR-held owned-PUBOB conversions exactly the way the
 * pre-0.19.40 P119 gate did (clean, no write), so the F2 repair writer
 * (mxfs_iflush_agino_target -> mxfs_pubob_relog_core -> P245-RELOG) is
 * exercised on demand instead of waiting for the natural race.  Decrements
 * per injected launder; 0 (default) = off.  TESTING ONLY.
 */
int mxfs_pubob_launder_inject;
module_param_named(pubob_launder_inject, mxfs_pubob_launder_inject, int, 0644);
MODULE_PARM_DESC(pubob_launder_inject,
                 "fault-inject: launder the next N PR-held owned-PUBOB unlink "
                 "conversions at xfs_iflush (P55B-INJECT-LAUNDER) so the "
                 "re-log repair (P245-RELOG) is exercised; 0=off");

/*
 * fault injection for D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN
 * (design-consult ruling modes 1/2: core-only fossil, core+buffer fossil at an
 * EMPTY-bucket insert).  iunl_fossil_inject=N plants a prior-life-style
 * fossil (agino-1) in ip->i_next_unlinked at the next N empty-bucket
 * xfs_iunlink inserts on this node (every odd count also stamps it into the
 * in-buffer dinode, logged, so the F2 buffer arm is exercised); decrements
 * per injection; 0 (default) = off.  iunl_fossil_fix=0 disables the F1/F2
 * repair (CONTROL arm: the injected fossil must then reproduce the bucket
 * head poisoning -> P86 BADHEAD -> reload_next LIVE -> shutdown chain).
 * TESTING ONLY; never leave fix=0 on a production mount.
 */
int mxfs_iunl_fossil_inject;
module_param_named(iunl_fossil_inject, mxfs_iunl_fossil_inject, int, 0644);
MODULE_PARM_DESC(iunl_fossil_inject,
		 "fault-inject: plant a fossil i_next_unlinked at the next N "
		 "empty-bucket unlinked-list inserts (odd counts also stamp the "
		 "buffer dinode; P-IUNL-FOSSIL-INJECT); 0=off");
/*
 * negative-mismatch arm (same ledger item): the next N NON-INSERT
 * iunlink items on this node see a perturbed comparand at sorted precommit
 * (buffer untouched); each MUST log P53-IUNLINK-MISMATCH (then FOSSILFIX
 * repair or -EFSCORRUPTED).  Proves INSERT mode did not blind the strict
 * check.  TESTING ONLY; 0 (default) = off.
 */
int mxfs_iunl_mismatch_inject;
module_param_named(iunl_mismatch_inject, mxfs_iunl_mismatch_inject, int, 0644);
MODULE_PARM_DESC(iunl_mismatch_inject,
		 "fault-inject (negative arm): perturb the strict non-INSERT "
		 "iunlink precommit comparand for the next N items "
		 "(P-IUNL-MISMATCH-INJECT -> P53 must fire); 0=off");
/* A/B measurement knob ONLY (instrumented cost attribution of the
 * per-create prev-changecount cluster read).  0 restores the pre-0.26.5
 * restart-at-1 behaviour, i.e. re-opens D-FREPLAY-VICTIM-INODE-CORE-NOT-
 * APPLIED-BUCKET-TO-ZERO-CORE-408 — never run a correctness campaign with
 * it off. */
int mxfs_ccprev_enable = 1;
module_param_named(ccprev_enable, mxfs_ccprev_enable, int, 0644);
MODULE_PARM_DESC(ccprev_enable, "continue di_changecount across inode reincarnations from a fresh read of the freed core (1=on, default; 0=A/B measurement only, re-opens D-408)");
int mxfs_iunl_fossil_fix = 1;
module_param_named(iunl_fossil_fix, mxfs_iunl_fossil_fix, int, 0644);
MODULE_PARM_DESC(iunl_fossil_fix,
		 "1 (default): xfs_iunlink_insert_inode resets a fossil in-core "
		 "next pointer and clears a fossil buffer nu on empty-bucket "
		 "inserts (F1/F2); 0 = CONTROL arm, repair disabled");

int mxfs_relog_holds_version = 1;
module_param_named(relog_holds_version, mxfs_relog_holds_version, int, 0644);
MODULE_PARM_DESC(relog_holds_version,
                 "the release drain's gated re-log does not bump i_version / "
                 "di_changecount (a republication is not a new logical "
                 "modification); 0=pre-fix control");

int mxfs_home_equals_owed_probe = 1;
module_param_named(home_equals_owed_probe, mxfs_home_equals_owed_probe, int, 0644);
MODULE_PARM_DESC(home_equals_owed_probe,
                 "emit P383-HOME-VS-OWED, the canonical comparison of the home "
                 "dinode against the image owed, at each fence-abandoned "
                 "publication (telemetry only)");

unsigned long long mxfs_iflush_fence_fault_ino;
int mxfs_iflush_fence_fault_n;
atomic_t mxfs_iflush_fence_fault_hits = ATOMIC_INIT(0);
module_param_named(iflush_fence_fault_ino, mxfs_iflush_fence_fault_ino, ullong, 0644);
MODULE_PARM_DESC(iflush_fence_fault_ino,
                 "fence every xfs_iflush of this inode the way the real "
                 "safe-skip fences do (error=0, no flush_seq stamp, i_dlm_stale "
                 "set), to exercise the fenced-publication wedge chain "
                 "deterministically; 0=disarmed");
module_param_named(iflush_fence_fault_n, mxfs_iflush_fence_fault_n, int, 0644);
MODULE_PARM_DESC(iflush_fence_fault_n,
                 "bound the number of flushes iflush_fence_fault_ino fences "
                 "(0=unlimited while armed)");

module_param_named(relgate_fault_res, mxfs_relgate_fault_res, ullong, 0644);
MODULE_PARM_DESC(relgate_fault_res,
                 "restrict relgate fault injection to this resource id "
                 "(0=any default)");
module_param_named(relgate_fault_delay_ms, mxfs_relgate_fault_delay_ms, int, 0644);
MODULE_PARM_DESC(relgate_fault_delay_ms,
                 "delay injected at the armed relgate fault stage "
                 "(default 100)");
module_param_named(relgate_fault_oneshot, mxfs_relgate_fault_oneshot, int, 0644);
MODULE_PARM_DESC(relgate_fault_oneshot,
                 "disarm the relgate fault stage after its first hit "
                 "(1=oneshot default)");
module_param_named(relgate_fault_force, mxfs_relgate_fault_force, int, 0644);
MODULE_PARM_DESC(relgate_fault_force,
                 "FORCE the armed stage's modeled failure at force-capable "
                 "placement sites (forced still-dirty/ticket-stale/proof-"
                 "fail) instead of delay-only (0=delay-only default)");

int
mxfs_relgate_fault_slow(int stage, uint64_t res)
{
	unsigned long long want_res;
	int delay;

	if (READ_ONCE(mxfs_relgate_fault_stage) != stage)
		return 0;
	want_res = READ_ONCE(mxfs_relgate_fault_res);
	if (want_res && want_res != (unsigned long long)res)
		return 0;
	if (READ_ONCE(mxfs_relgate_fault_oneshot) &&
	    cmpxchg(&mxfs_relgate_fault_stage, stage, 0) != stage)
		return 0;	/* lost the one-shot race to another hitter */
	atomic64_inc(&mxfs_relgate_fault_hits);
	delay = READ_ONCE(mxfs_relgate_fault_delay_ms);
	mxfs_probe("mxfs: P282-RELGATE-FAULT stage=%d res=%llu delay=%dms force=%d comm=%s realns=%llu\n",
		stage, (unsigned long long)res, delay,
		READ_ONCE(mxfs_relgate_fault_force), current->comm,
		(unsigned long long)ktime_get_real_ns());
	if (delay > 0)
		msleep(delay);
	return 1;
}

/* (ruling item 10): the force variant fires the stage via
 * the same matcher (respecting the resource filter and the one-shot) and
 * reports whether the site must FORCE its modeled failure. */
bool
mxfs_relgate_fault_slow_forced(int stage, uint64_t res)
{
	bool force = READ_ONCE(mxfs_relgate_fault_force) != 0;

	if (!mxfs_relgate_fault_slow(stage, res))
		return false;
	return force;
}

static int
mxfs_relgate_fault_stage_set(const char *val, const struct kernel_param *kp)
{
	int v;
	int rc = kstrtoint(val, 0, &v);

	if (rc)
		return rc;
	if (v < 0 || v > MXFS_RGF_MAX)
		return -EINVAL;
	WRITE_ONCE(mxfs_relgate_fault_stage, v);
	if (v)
		static_branch_enable(&mxfs_relgate_fault_key);
	else
		static_branch_disable(&mxfs_relgate_fault_key);
	return 0;
}
static const struct kernel_param_ops mxfs_relgate_fault_stage_ops = {
	.set = mxfs_relgate_fault_stage_set,
	.get = param_get_int,
};
module_param_cb(relgate_fault_stage, &mxfs_relgate_fault_stage_ops,
		&mxfs_relgate_fault_stage, 0644);
MODULE_PARM_DESC(relgate_fault_stage,
                 "arm deterministic fault injection at this release/mint/"
                 "gate stage (1-18 per ruling; 19-21 ICLUS marker"
                 "stages per ruling; 0=disarmed default)");

int mxfs_pub_skip_rearm = 0;
EXPORT_SYMBOL(mxfs_pub_skip_rearm);
module_param_named(pub_skip_rearm, mxfs_pub_skip_rearm, int, 0644);
MODULE_PARM_DESC(pub_skip_rearm,
                 "When a partial inode-cluster write DROPS a logged inode's "
                 "sector, keep that inode dirty and in the AIL instead of "
                 "letting the buffer's completion mark it durable.  "
                 "MEASURED TO LIVELOCK on its own (the retry can never gain "
                 "publication authority) — 0=off (default), 1=re-arm.");

/*
 * the lookup-window read trace (P495-LKP-RD / P495-LKP-WIN).  When
 * lkp_trace=1 and the create-cost probe is armed, xfs_create opens a node-wide
 * window around its existence lookup and every buffer read bio (xfs_buf.c)
 * and FUA passthrough read (pal/linux/kern.c) submitted on the node while it
 * is open is printed with its task, block and verifier.  Diagnostic, capped,
 * default off.
 */
int mxfs_lkp_trace = 0;
int mxfs_lkp_trace_open = 0;
EXPORT_SYMBOL(mxfs_lkp_trace);
EXPORT_SYMBOL(mxfs_lkp_trace_open);
module_param_named(lkp_trace, mxfs_lkp_trace, int, 0644);
MODULE_PARM_DESC(lkp_trace,
                 "Print every buffer read bio and FUA read on the node while "
                 "an armed create's directory lookup is in progress "
                 "(P495-LKP-RD).  Diagnostic; capped 600 bio + 300 FUA lines "
                 "per node.  0=off (default), 1=on.");
