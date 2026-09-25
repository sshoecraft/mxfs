// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- open protection, close release and the PR sweep
 */
#define MXFS_TU_ID 29	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/* (D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO verification) — fault
 * injection: widen the proven 16us window between mxfs_dlm_open_protect's
 * ilock ride and its admission re-read so a pending BAST demote's terminal
 * NL store (bast_process, spinlock-only, needs no ILOCK) lands inside it
 * deterministically.  Applied only on the FIRST admission pass and only
 * when a demote is actually in flight on the inode, so the restart loop
 * under test runs at natural timing.  Default 0 = off; test-only. */
int mxfs_openprotect_race_delay_ms = 0;
module_param_named(openprotect_race_delay_ms, mxfs_openprotect_race_delay_ms, int, 0644);
MODULE_PARM_DESC(openprotect_race_delay_ms,
	"Fault injection: ms to sleep between open_protect's ilock ride and its admission re-read when a BAST demote is pending (default 0 = off)");

/* (ruling, deterministic exercise 2 — PRE-TERMINAL GATE):
 * with the epoch-aware wait landed, opens converge on their first restart
 * and the admission gate never arms naturally, so the gate's terminal-
 * store defer path (P95-OPEN-ADMIT-DEFER) is unreachable by plain load.
 * This knob arms the gate at open_protect ENTRY for every covered open —
 * the same counter the real 2-lost-races path arms, no DLM state
 * fabricated — so a release reaching its terminal store during any open
 * defers instead of storing NL.  Default 0 = off; test-only. */
int mxfs_openprotect_arm_gate = 0;
module_param_named(openprotect_arm_gate, mxfs_openprotect_arm_gate, int, 0644);
MODULE_PARM_DESC(openprotect_arm_gate,
	"Fault injection: arm the open-admission gate at open_protect entry so the terminal-store defer path is exercised (default 0 = off)");

/*
 * 0.75.59: a write open's protecting ride acquires EX outright.
 *
 * mxfs_dlm_open_protect rode ILOCK_SHARED for every open, so an open for
 * writing took PR and the first write or truncate converted PR->EX.  With
 * two nodes doing that on one file (the appender's open+write against the
 * peer's open+truncate) both hold PR and both ask to convert; the master
 * denies the later one (P-CONVBLK-DENY), which drops its PR and re-requests
 * EX from NL behind the winner's whole tenure.  Measured on the 2/tcp rig
 * (s539c truncate #3, 67 ms): 31 ms of the truncate was that lost
 * conversion — PR granted, convert denied, PR dropped, then the appender's
 * 15 ms window plus its release drain before the EX arrived.  Riding EX
 * for a write open asks for the mode the syscall needs anyway, so the
 * request enters the master's FIFO once, as an ordinary EX request that
 * BASTs the holder, and there is no PR to convert.  Read opens still ride
 * PR.  0 restores the PR ride for write opens.
 */
int mxfs_open_write_ex = 1;
module_param_named(open_write_ex, mxfs_open_write_ex, int, 0644);
MODULE_PARM_DESC(open_write_ex,
	"a write open's protecting DLM ride acquires EX directly (1) or PR then converts at the first write (0)");

/*
 * v0.10.36 read-once demote (default ON).  On the close of a PR-held clean
 * regular file, queue the inode's release worker so the cached PR grant does
 * not linger on the slot.  Without this, every node that ever read a file
 * stays a PR holder; a later unlink must BAST-strip up to N-1 holders whose
 * unlock CAS ops serialize on the one slot LBA — a ~45ms protocol floor per
 * unlink at 32 nodes (PROVEN: dir_reuse@32 rm phase 176s/round = 3200 ×
 * 45ms EX handoffs; P138-WAIT acquirer waits ≈ P138-BAST su unlock-CAS herd).
 * PR ⇒ no local modifications by construction, so the queued release is
 * drain-free and runs off the UNBOUND bast workqueue concurrently with the
 * reader's next file.  The next local read re-acquires and revalidates via
 * the same path a BAST-evicted reader takes — no coherency change, only
 * cache-retention policy for read-once files.
 */
int mxfs_close_release = 1;
module_param_named(close_release, mxfs_close_release, int, 0644);
MODULE_PARM_DESC(close_release,
                 "Release a clean PR inode DLM grant at last read-only "
                 "close (read-only demote): 1=on (default), 0=keep PR "
                 "cached until BAST");

/*
 * v0.10.38 dir-EX-BAST idle-PR sweep (default ON).  When a DIRECTORY we
 * hold in PR gets BAST-stripped, a writer (EX) is taking that dir — PR-PR
 * is compatible, so only an exclusive requester generates this BAST.  That
 * moment (an unlink storm / mass rename is starting) is exactly when this
 * node's idle REGULAR-file PR grants stop paying for their slot residency:
 * the writer's per-child EX acquires would otherwise BAST-strip us
 * one-by-one, serialized behind its op stream (~30-45ms per child at 32
 * nodes — dir_reuse rm at 140-190s/round).  Sweep the superblock's cached
 * inodes ONCE (rate-limited) and queue the drain-free demote for every
 * idle PR file grant, so the releases run in parallel across all peers'
 * workqueues while the writer's claims find already-empty slots.  Quiet
 * during create/verify phases: writers hold the dir EX (an EX-held dir
 * being BAST'd does not trigger), and readers BASTing readers does not
 * happen.
 */
int mxfs_dir_ex_bast_sweep = 1;
module_param_named(dir_ex_bast_sweep, mxfs_dir_ex_bast_sweep, int, 0644);
MODULE_PARM_DESC(dir_ex_bast_sweep,
                 "On losing a PR-held directory to a peer's EX request, "
                 "sweep-release this node's idle REGULAR-file PR grants "
                 "(1=on default, 0=off)");

/*
 * Queue the drain-free demote of an idle CACHED PR grant on a regular
 * file.  PR means no local modifications exist (writes need EX), so the
 * release is the measured drain_ms=0 pipeline.  A pending BAST or any
 * other state is already on its own release path; EX-held (writer) inodes
 * are left alone — their release is the durability fence's job at BAST
 * time.  Returns true if the demote was queued.
 */
static bool
mxfs_dlm_queue_pr_demote(struct xfs_inode *ip, unsigned int delay_ms,
			 uint8_t src)
{
	struct inode		*vip = VFS_I(ip);
	bool			queue = false;

	if (!S_ISREG(vip->i_mode))
		return false;

	spin_lock(&ip->i_dlm_lock);
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
	    ip->i_dlm_mode == MXFS_LOCK_PR &&
	    !ip->i_dlm_bast_pending &&
	    ip->i_dlm_ex_holders == 0 &&
	    ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_pin_count == 0) {
		ip->i_dlm_bast_pending = true;
		ip->i_dlm_dwork_strikes = 0;
		queue = true;
	}
	spin_unlock(&ip->i_dlm_lock);
	if (!queue)
		return false;

	/* 2026-07-16: igrab, never raw ihold (BUG3 family — see
	 * P134-BASTQ-FREEING at the orphan_rearm site).  On refusal, unwind
	 * the bast_pending we just set: nothing will consume it (no dwork
	 * queued) and the eviction owns this inode's DLM teardown. */
	if (!igrab(vip)) {
		spin_lock(&ip->i_dlm_lock);
		ip->i_dlm_bast_pending = false;
		spin_unlock(&ip->i_dlm_lock);
		mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=pr_demote src=%u i_state=0x%lx (inode evicting; skipping PR demote arm)\n",
			(unsigned long long)ip->i_ino, src, mxfs_istate(vip));
		return false;
	}
	ip->i_dlm_bastq_src = src;
	if (!mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies(delay_ms)))
		xfs_irele(ip);	/* dwork already armed */
	return true;
}

/*
 *  WRITE-ONCE demote (the produce-then-consume fix).
 * Symmetric to the v0.10.36 read-once PR demote: at the last close of a
 * WRITTEN regular file, arm a short-delay release of the creator's cached
 * EX grant.  Without it every fresh file keeps its creator as a cached EX
 * holder, and every first cross-node reader pays a full on-demand handoff
 * — microbenched 2026-07-18 at 8/cawd: cold foreign stat = 6.1ms avg
 * (33ms max) with ~0.8ms device time (the rest is BAST+release+poll), =
 * the dominant term of dir_reuse's verify phase.  With the creator
 * releasing ~ex_close_release_ms after close, readers find a free slot
 * and claim in ~1ms with NO handoff.
 *
 * Shape matters (learned from the REFUTED pr_idle_release_ms default):
 * that reaper armed a timer per STAT — 800 arms x 32 nodes fired DURING
 * the read phase and stormed the slot table.  This arm is per WRITTEN
 * FILE at CLOSE (one per file, creator only), fires during/after the
 * create phase, and the delay absorbs the common write-then-reread
 * burst (re-arms via the dwork protocol if the file is back in use).
 * The dwork runs the full Invariant-1 drain (same path MHT-deferred EX
 * releases take), so durability semantics are unchanged.
 */
int mxfs_ex_close_release_ms = 0;
/*  default 250 → 0.  A/B-PROVEN corruption trigger:
 * dlm_fairness's create→mv→rm churn with the demote on corrupts a fresh FS
 * in ~25s ("Free inode 0x85 has blocks allocated" → trans_cancel shutdown)
 * — the eager per-file EX release multiplies same-inode-cluster-buffer
 * handoffs until a concurrent RMW from a pre-free image clobbers an
 * ifree's dinode-zero; =0 → PASS 8/8 in 8s.  The cold-foreign-stat win it
 * bought (6.1ms → ~1ms) is superseded by ICLUSTER grant retention on CAW;
 * on TCP this reverts to the 0.11.10 keep-cached-until-BAST behavior. */
module_param_named(ex_close_release_ms, mxfs_ex_close_release_ms, int, 0644);
MODULE_PARM_DESC(ex_close_release_ms,
                 "Release a REGULAR file's idle cached EX DLM grant this "
                 "many ms after its last close (write-once demote; "
                 "0 = keep EX cached until BAST; default 0 — nonzero "
                 "reopens a proven ifree-clobber race, A/B only)");

static bool
mxfs_dlm_queue_ex_demote(struct xfs_inode *ip, unsigned int delay_ms,
			 uint8_t src)
{
	struct inode		*vip = VFS_I(ip);
	bool			queue = false;

	if (!S_ISREG(vip->i_mode))
		return false;

	spin_lock(&ip->i_dlm_lock);
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
	    ip->i_dlm_mode == MXFS_LOCK_EX &&
	    !ip->i_dlm_bast_pending &&
	    ip->i_dlm_ex_holders == 0 &&
	    ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_pin_count == 0) {
		ip->i_dlm_bast_pending = true;
		ip->i_dlm_dwork_strikes = 0;
		queue = true;
	}
	spin_unlock(&ip->i_dlm_lock);
	if (!queue)
		return false;

	/* igrab, never raw ihold (BUG3 family) — see mxfs_dlm_queue_pr_demote. */
	if (!igrab(vip)) {
		spin_lock(&ip->i_dlm_lock);
		ip->i_dlm_bast_pending = false;
		spin_unlock(&ip->i_dlm_lock);
		mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=ex_demote src=%u i_state=0x%lx (inode evicting; skipping EX demote arm)\n",
			(unsigned long long)ip->i_ino, src, mxfs_istate(vip));
		return false;
	}
	ip->i_dlm_bastq_src = src;
	if (!mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies(delay_ms)))
		xfs_irele(ip);	/* dwork already armed */
	return true;
}

void
mxfs_dlm_close_release(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;

	if (!mxfs_close_release || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	/*  an UNLINKED file is headed for xfs_inactive,
	 * which needs the EX again (ifree + on-disk slot tombstone).  A
	 * close-demote in between forces inactive to re-acquire from scratch
	 * — kprobe-counted at ~5 extra disk ops per rm'd file (find + grant
	 * wait + claim CAW + verify), the reason rm got SLOWER on 0.11.11.
	 * Keep the cached grant; unlock_free tombstones it moments later. */
	if (VFS_I(ip)->i_nlink == 0)
		return;
	if (mxfs_dlm_queue_pr_demote(ip, 2, 14 /* close_release */))
		return;
	if (mxfs_ex_close_release_ms > 0)
		mxfs_dlm_queue_ex_demote(ip,
			(unsigned int)mxfs_ex_close_release_ms,
			16 /* ex_close_release */);
}
int mxfs_dlm_open_protect(struct xfs_inode *ip, bool want_ex)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			ok;
	/* 0.75.59: a write open rides EX (see mxfs_open_write_ex); the fast
	 * path then admits only a cached EX, since a cached PR would just
	 * move the PR->EX conversion to the first write. */
	bool			ride_ex = want_ex && mxfs_open_write_ex;
	uint			ride_flags = ride_ex ? XFS_ILOCK_EXCL :
						 XFS_ILOCK_SHARED;
	/* (design-consult ruling, D-OPEN-PROTECT-DEMOTE-RACE-
	 * SPURIOUS-EIO): live-NL at the admission re-read is a benign race
	 * with the release worker's terminal store (proven 0.11.482 cc
	 * test23: nl_age_us=16 from xfs_mxfs_dlm.c terminal release), never
	 * a reason to fail the open.  Treat it as a COLD OPEN: restart the
	 * whole acquisition+admission protocol (the ilock ride's slow path
	 * waits out the old release epoch on DEMOTING and re-acquires via
	 * the routed protocol; tombstone/publication/route re-checked from
	 * scratch each lap).  After OPEN_PROTECT_PLAIN_RESTARTS lost races,
	 * arm the per-inode ADMISSION GATE (i_mxfs_open_admit_n) that the
	 * release worker's terminal store honors, bounding the loop.  -EIO
	 * remains only for real failures (shutdown fence / acquire that
	 * cannot converge with releases held off). */
	int			restarts = 0;
	bool			gated = false;
	int			ret = 0;
	/*
	 * Open is a fallible acquire boundary: at the ilock ride below nothing
	 * is dirty, no transaction is open, and the only thing that has
	 * happened is that a file was named.  Refusing the open here fails one
	 * syscall; the alternatives, when a live master never answers the
	 * request, are to block the caller for ever or to shut the mount down,
	 * and this function already has a fail-closed -EIO path for an acquire
	 * that cannot converge.
	 */
	struct mxfs_acqfallible	acqfall;
	bool			acqfall_on = false;
	/* #18 forensics: state snapshot taken under i_dlm_lock at the
	 * post-ride mode re-read; the fail print runs after xfs_iunlock, so it
	 * must not re-read live fields. */
	u8			sn_mode, sn_state, sn_ssrc, sn_nlom;
	u16			sn_exh, sn_prh, sn_acq;
	bool			sn_iclus, sn_unpub, sn_stale;
	u32			sn_nlline, sn_arm;
	pid_t			sn_nlpid;
	u64			sn_nlns;
	char			sn_nlcomm[16];

	if (!mxfs_open_tracking || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	/* injection (see mxfs_openprotect_arm_gate decl): arm the
	 * admission gate for this open's whole protocol; out: disarms. */
	if (unlikely(mxfs_openprotect_arm_gate) && !gated) {
		atomic_inc(&ip->i_mxfs_open_admit_n);
		gated = true;
	}
	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	acqfall_on = true;
restart:
	/* Fast path: cached grant, no release/BAST in flight. */
	spin_lock(&ip->i_dlm_lock);
	ok = ip->i_dlm_mode != MXFS_LOCK_NL &&
	     ip->i_dlm_state == MXFS_DLM_ISTATE_NONE;
	if (ok && ride_ex)
		ok = ip->i_dlm_mode == MXFS_LOCK_EX;
	/* ADMISSION GATE (design review soundness fix), covered inodes: the
	 * fast path may admit ONLY a CLUSTER-BACKED grant.  Two holes it
	 * closes: (1) a release sweep can be past its publication scan
	 * while our cached mode still reads granted (open would become
	 * usable unpublished) — refused via ic->busy/disk_mode below;
	 * (2) a mode-0-era per-inode-LOCAL grant satisfies the mode check
	 * while providing ZERO cross-node protection, and checking only the
	 * cluster's ic state let the cwr .md5 open fast-path on the
	 * NEIGHBOR data file's cluster grant while its own grant stayed
	 * local (dirty data invisible to the cluster handoff) — refused via
	 * the sticky bit, so the slow path converts (P95-OPEN-CLUSTER-
	 * CONVERT) and EVERY open is cluster-backed.  That invariant is
	 * what lets covered_active/fan_out stay sticky-keyed (no handoff-
	 * wide local-drain serialization): local grants then belong only to
	 * never-opened metadata-only inodes, whose dinode bytes ride the
	 * cluster buffers that make_durable already drains.  Ordering:
	 * i_mxfs_open_n was incremented before this call (C3 contract), and
	 * both sides pass through ic->lock, so a sweep that begins after
	 * our admit reads our count. */
	if (ok && mxfs_dlm_iclus_covered(ip))
		ok = ip->i_dlm_routed_iclus;
	spin_unlock(&ip->i_dlm_lock);
	if (ok && mxfs_dlm_iclus_covered(ip))
		ok = mxfs_iclus_open_admit(mp, ip->i_ino);
	if (ok)
		goto out;
	/* build-1 forensics: stamp this task as the opener BEFORE the
	 * ilock ride, so mxfs_dlmtr_rec records which ilock-path admit arm
	 * granted us (every admit arm ends in a MXFS_DLMTR_H record; the last
	 * stamp before the admission re-read below names the arm).  Cleared at
	 * out:.  Second opener racing on the same inode just overwrites the
	 * pid — the arm attribution then belongs to whichever rode last,
	 * acceptable for a diagnostic. */
	spin_lock(&ip->i_dlm_lock);
	ip->i_mxfs_openprot_pid = current->pid;
	ip->i_mxfs_openprot_arm = 0;
	spin_unlock(&ip->i_dlm_lock);
	/* fault injection (moved BEFORE the ilock ride — the
	 * placement AFTER the ride could not reproduce because the ride itself
	 * must land in the release's post-terminal-store tail): with the knob
	 * set and a demote in flight, hold the open HERE until the release
	 * worker's terminal NL store lands while the flush tail is still
	 * running ({mode==NL, RELFLUSH set} — the relflush-admit arm's
	 * window), or the knob's ms budget expires.  Entering the ilock ride
	 * inside that window is the 0.11.482 interleaving.  First pass only:
	 * the restart loop under test runs at natural timing. */
	if (unlikely(mxfs_openprotect_race_delay_ms) && restarts == 0) {
		bool demote_inflight;

		spin_lock(&ip->i_dlm_lock);
		demote_inflight = ip->i_dlm_bast_pending ||
				  ip->i_dlm_state != MXFS_DLM_ISTATE_NONE;
		spin_unlock(&ip->i_dlm_lock);
		if (demote_inflight) {
			int	waited = 0;
			bool	hit = false;

			while (waited < mxfs_openprotect_race_delay_ms && !hit) {
				usleep_range(1000, 1500);
				waited++;
				spin_lock(&ip->i_dlm_lock);
				hit = ip->i_dlm_mode == MXFS_LOCK_NL &&
				      xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH);
				spin_unlock(&ip->i_dlm_lock);
			}
			{
				static atomic_t p95i_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p95i_n) <= 200)
					mxfs_probe("mxfs: P95-OPEN-INJECT ino=%llu waited_ms=%d landed_window=%d comm=%s — fault-injection hold before ilock ride\n",
						(unsigned long long)ip->i_ino,
						waited, hit ? 1 : 0,
						current->comm);
			}
		}
	}
	xfs_ilock(ip, ride_flags);
	/* split-brain closure, part 2: the ilock hook does NOT
	 * re-acquire over a sufficient cached mode, so a covered inode
	 * sitting on a mode-0-era per-inode-LOCAL grant (fresh create)
	 * exits the ride still uncovered — and a peer's routed rm frees it
	 * through the untouched CLUSTER resource.  Force the conversion:
	 * a same-mode routed acquire (mxfs_dlm_inode_lock_routed = iclus
	 * claim + sticky bit + conv_pi drop of the old grant). */
	if (mxfs_dlm_iclus_covered(ip)) {
		uint8_t	cur;
		bool	local;

		spin_lock(&ip->i_dlm_lock);
		cur = ip->i_dlm_mode;
		local = cur != MXFS_LOCK_NL && !ip->i_dlm_routed_iclus;
		spin_unlock(&ip->i_dlm_lock);
		if (local && mxfs_dlm_inode_lock_routed(ip, cur,
						MXFS_AUTH_GEN_NONE) == 0)
			mxfs_probe_ratelimited(
			    "mxfs: P95-OPEN-CLUSTER-CONVERT ino=%llu mode=%u — local create-era grant converted to cluster coverage at open\n",
				(unsigned long long)ip->i_ino, cur);
	}
	/*
	 * Either acquire above may have given up rather than wait for a master
	 * that is a live member and has never acknowledged the request.  The
	 * local ilock was still taken — xfs_ilock cannot refuse — so drop it
	 * and fail the open before anything reads inode state this node holds
	 * no grant for.  The restart loop below is for CONTENTION, which must
	 * never become -EIO; this is not contention, and it must never become
	 * a restart.
	 */
	if (mxfs_acqfall_taken(&acqfall, &ret)) {
		xfs_iunlock(ip, ride_flags);
		pr_warn_ratelimited(
		    "mxfs: P912-OPEN-UNRECEIPTED ino=%llu killed=%d rc=%d comm=%s — open refused: the inode's master never acknowledged the lock request (or this task was killed, or the page's takeover stalled); failing the open instead of waiting on it\n",
			(unsigned long long)ip->i_ino,
			fatal_signal_pending(current) ? 1 : 0, ret, current->comm);
		ret = fatal_signal_pending(current) ? -EINTR : ret;
		goto out;
	}
	spin_lock(&ip->i_dlm_lock);
	ok = ip->i_dlm_mode != MXFS_LOCK_NL;
	sn_arm = ip->i_mxfs_openprot_arm;
	sn_mode = ip->i_dlm_mode;
	sn_state = ip->i_dlm_state;
	sn_exh = ip->i_dlm_ex_holders;
	sn_prh = ip->i_dlm_pr_holders;
	sn_acq = ip->i_dlm_acq_inflight;
	sn_iclus = ip->i_dlm_routed_iclus;
	sn_unpub = ip->i_dlm_unpublished;
	sn_stale = ip->i_dlm_stale;
	sn_ssrc = ip->i_dlm_stale_src;
	sn_nlline = ip->i_dlm_nl_line;
	sn_nlpid = ip->i_dlm_nl_pid;
	sn_nlns = ip->i_dlm_nl_ns;
	sn_nlom = ip->i_dlm_nl_om;
	memcpy(sn_nlcomm, ip->i_dlm_nl_comm, sizeof(sn_nlcomm));
	sn_nlcomm[sizeof(sn_nlcomm) - 1] = '\0';
	spin_unlock(&ip->i_dlm_lock);
	/* (iclus matrix `basic` race autopsy): the ilock ride's
	 * coherent acquire can ADOPT A PEER-FREED INCARNATION (P116-ZOMBIE-
	 * ADOPT → in-core mode 0) when our open raced the peer's rm+free —
	 * under iclus the open's acquire can queue behind the freer's whole
	 * unlink-under-cluster-EX, so the free lands first.  Completing the
	 * open would serve the tombstone (reads return zeros — observed
	 * DATA-LOST '' with defer=0).  -ESTALE: the VFS open path re-walks
	 * with LOOKUP_REVAL, finds the name gone, and the caller gets a
	 * clean ENOENT — the POSIX outcome for open-vs-unlink where the
	 * unlink won. */
	if (ok && (VFS_I(ip)->i_mode & S_IFMT) == 0) {
		xfs_iunlock(ip, ride_flags);
		mxfs_probe_ratelimited(
		    "mxfs: P95-OPEN-STALE-INCARNATION ino=%llu — acquire adopted a peer-freed image; -ESTALE for re-walk\n",
			(unsigned long long)ip->i_ino);
		ret = -ESTALE;
		goto out;
	}
	xfs_iunlock(ip, ride_flags);
	if (!ok) {
		u64 nl_age_us = sn_nlns ?
			(ktime_get_real_ns() - sn_nlns) / NSEC_PER_USEC : 0;

		/* cold-open restart (ruling): live-NL is
		 * contention, not failure.  (design-consult ruling,
		 * proven by instrument on 0.11.486: arm=29008 relflush-admit, 5
		 * restarts burning in µs inside a single release's post-
		 * terminal-store tail, admit_defers=0): a bare restart loop
		 * CANNOT converge — the ilock ride is re-admitted instantly
		 * by the relflush arm for the whole ms-long tail, and the
		 * admission gate only helps pipelines not yet at their
		 * terminal store.  So each lost race now performs an
		 * EPOCH-AWARE COMPLETION WAIT: capture the release epoch at
		 * the NL re-read, and wait on i_dlm_wait until THAT release
		 * pipeline fully exits (state leaves DEMOTING at the
		 * pipeline's tail, AFTER device flush + wire unlock) or the
		 * epoch moves (a newer cycle superseded it — ABA guard),
		 * then re-run the whole protocol from scratch.  Unbounded
		 * with capped STUCK warns: contention must NEVER become
		 * -EIO; only the shutdown fence fails the open. The gate
		 * still arms after the plain laps (it bounds pipelines that
		 * have not yet reached their terminal store). */
		if (!xfs_is_shutdown(mp)) {
			unsigned long	wait_epoch;
			bool		demoting;
			int		stuck = 0;

			restarts++;
			if (restarts > MXFS_OPEN_PROTECT_PLAIN_RESTARTS &&
			    !gated) {
				atomic_inc(&ip->i_mxfs_open_admit_n);
				gated = true;
			}
			spin_lock(&ip->i_dlm_lock);
			wait_epoch = ip->i_dlm_epoch;
			demoting = ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING;
			spin_unlock(&ip->i_dlm_lock);
			while (demoting && !xfs_is_shutdown(mp)) {
				if (wait_event_timeout(ip->i_dlm_wait,
				    READ_ONCE(ip->i_dlm_state) !=
						MXFS_DLM_ISTATE_DEMOTING ||
				    READ_ONCE(ip->i_dlm_epoch) != wait_epoch ||
				    xfs_is_shutdown(mp), 30 * HZ))
					break;
				stuck++;
				{
					static atomic_t p95s_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p95s_n) <= 500)
						pr_warn("mxfs: P95-OPEN-PROTECT-STUCK ino=%llu waited_s=%d epoch=%lu state=%u mode=%u comm=%s — open admission still waiting for release pipeline exit\n",
							(unsigned long long)ip->i_ino,
							stuck * 30, wait_epoch,
							ip->i_dlm_state,
							ip->i_dlm_mode,
							current->comm);
				}
			}
			{
				static atomic_t p95r_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p95r_n) <= 2000)
					mxfs_probe("mxfs: P95-OPEN-PROTECT-RESTART ino=%llu try=%d gated=%d nl_line=%u:%u nl_om=%u nl_age_us=%llu arm=%u comm=%s — live-NL at admission; cold-open restart\n",
						(unsigned long long)ip->i_ino,
						restarts, gated ? 1 : 0,
						MXFS_SITE_ARGS(sn_nlline), sn_nlom,
						(unsigned long long)nl_age_us,
						sn_arm, current->comm);
			}
			cond_resched();
			goto restart;
		}

		pr_warn_ratelimited(
		    "mxfs: P95-OPEN-PROTECT-FAIL ino=%llu mode=%u state=%u exh=%u prh=%u acq=%u iclus=%u unpub=%u stale=%u ssrc=%u imode=%o gen=%u open_n=%d selfc=%u reusedc=%u nl_line=%u:%u nl_om=%u nl_pid=%d nl_comm=%s nl_age_us=%llu restarts=%d gated=%d arm=%u — no DLM grant after ilock at shutdown fence; failing the open (fail closed)\n",
			(unsigned long long)ip->i_ino, sn_mode, sn_state,
			sn_exh, sn_prh, sn_acq, sn_iclus, sn_unpub,
			sn_stale, sn_ssrc, VFS_I(ip)->i_mode,
			VFS_I(ip)->i_generation,
			atomic_read(&ip->i_mxfs_open_n),
			ip->i_mxfs_self_created, ip->i_mxfs_reused_create,
			MXFS_SITE_ARGS(sn_nlline), sn_nlom, sn_nlpid, sn_nlcomm,
			(unsigned long long)nl_age_us, restarts,
			gated ? 1 : 0, sn_arm);
		ret = -EIO;
	}
out:
	if (acqfall_on)
		mxfs_acqfall_exit(&acqfall);
	spin_lock(&ip->i_dlm_lock);
	if (ip->i_mxfs_openprot_pid == current->pid)
		ip->i_mxfs_openprot_pid = 0;
	spin_unlock(&ip->i_dlm_lock);
	if (gated)
		atomic_dec(&ip->i_mxfs_open_admit_n);
	return ret;
}

static void
mxfs_open_clear_ride_fn(
	struct work_struct	*work)
{
	struct mxfs_open_clear_ride *r =
		container_of(work, struct mxfs_open_clear_ride, work);
	struct xfs_inode	*ip = r->ip;
	struct xfs_mount	*mp = ip->i_mount;
	bool			prot;
	int			rc = 0;

	prot = atomic_read(&ip->i_mxfs_open_n) > 0 ||
	       mapping_mapped(VFS_I(ip)->i_mapping);
	if (!prot && ip->i_mxfs_open_pub && !xfs_is_shutdown(mp) &&
	    !xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED)) {
		struct mxfs_acqfallible acqfall;

		mxfs_acqfall_enter(&acqfall, ip->i_ino);
		mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
		if (mxfs_acqfall_taken(&acqfall, &rc))
			rc = rc ? rc : -EIO;
		mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
		mxfs_acqfall_exit(&acqfall);
		if (rc == 0 &&
		    !mxfs_dlm_queue_pr_demote(ip, 0, 17 /* open_clear_ride */) &&
		    !mxfs_dlm_queue_ex_demote(ip, 0, 17))
			rc = -EBUSY;	/* a release is already on its way */
	}
	mxfs_probe_ratelimited(
	    "mxfs: P977-OPEN-CLEAR-RIDE ino=%llu prot=%d pub=%d dlm_mode=%u rc=%d — %s\n",
		(unsigned long long)ip->i_ino, prot ? 1 : 0,
		ip->i_mxfs_open_pub ? 1 : 0, ip->i_dlm_mode, rc,
		rc == 0 ? "demote queued; its release publishes the clear" :
		rc == -EBUSY ? "a release is already in flight and will publish it" :
		"no grant could be taken; the next release of this inode publishes it");
	xfs_irele(ip);
	kfree(r);
}

void
mxfs_dlm_open_clear_ride(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct mxfs_open_clear_ride *r;
	bool			queued = false;

	if (!mp->m_mxfs_inode_bast_wq)
		return;
	if (!igrab(VFS_I(ip)))
		return;		/* evicting: the evict release carries the clear */
	r = kzalloc(sizeof(*r), GFP_NOFS | __GFP_NOWARN);
	if (!r) {
		xfs_irele(ip);
		return;
	}
	r->ip = ip;
	INIT_WORK(&r->work, mxfs_open_clear_ride_fn);
	spin_lock(&mp->m_mxfs_arm_lock);
	if (!mp->m_mxfs_arms_off)
		queued = queue_work(mp->m_mxfs_inode_bast_wq, &r->work);
	spin_unlock(&mp->m_mxfs_arm_lock);
	if (!queued) {
		xfs_irele(ip);
		kfree(r);
	}
}

void mxfs_dlm_open_last_close(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;

	/* a sweep SET in flight — the setter's post-SET recheck
	 * observes activity==0 and performs this clear itself (its CAS may
	 * land after ours would, resurrecting the bit we just cleared). */
	if (READ_ONCE(ip->i_mxfs_open_setting))
		return;
	/*
	 * No "alone" early return.  A mark published while multi-node (P90) is
	 * durable in this node's slot, and a node that is alone at its last
	 * close still has to clear it: measured on 2/tcp, B published, A
	 * left, B closed alone, A rejoined and unlinked the file, and A then
	 * deferred the free on B's mark every reap retry with no fd open
	 * anywhere (P87-OPEN-DEFER open_holders=B, tests/open_mark_lone_close.sh
	 * s170a); the same close with A mounted cleared it (s170b).  A lone
	 * node that never published has i_mxfs_open_pub clear and still
	 * returns here at no cost.
	 */
	if (!ip->i_mxfs_open_pub || !mp->m_mxfs_dlm)
		return;
	if (atomic_read(&ip->i_mxfs_open_n) > 0 ||
	    mapping_mapped(VFS_I(ip)->i_mapping))
		return;
	if (xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED))
		return;
	if (ip->i_mxfs_open_pub &&
	    mxfs_v5_dlm_open_clear_rides_release(mp->m_mxfs_dlm)) {
		/*
		 * 0.89.0 (D-0977), TCP: the clear is durable only inside a
		 * release, so the last close DRIVES one: the ride below takes
		 * (or already caches) a grant on the inode and queues its
		 * demote, whose release publishes this node's absolute state
		 * — a clear, unless the file was reopened meanwhile, in which
		 * case the same release publishes the set that is then true.
		 * i_mxfs_open_pub stays set until that release runs.
		 */
		mxfs_dlm_open_clear_ride(ip);
		return;
	}
	if (ip->i_mxfs_open_pub) {
		mxfs_v5_dlm_inode_open_clear(mp->m_mxfs_dlm, ip->i_ino);
		ip->i_mxfs_open_pub = false;
		mxfs_probe_ratelimited(
		    "mxfs: P91-OPEN-EAGER-CLEAR ino=%llu — last close, published open bit cleared\n",
			(unsigned long long)ip->i_ino);
	}
	/*
	 * last close of a PEER-unlinked file.  Our dentry alias
	 * pins the zombie (a cross-node unlink never d_deletes the
	 * opener's dentry and nothing re-looks the path up), so without
	 * retirement the inode never reaches evict/inactivation until
	 * memory pressure — PROVEN leak (death-case ino=132 never
	 * re-issued).  Queue a retire-only reap entry: the worker prunes
	 * the alias and the normal iput/evict path takes over.
	 */
	if (VFS_I(ip)->i_nlink == 0)
		mxfs_defer_reap_add_mode(mp, ip->i_ino,
					 VFS_I(ip)->i_generation,
					 ip->i_unlinked_bucket,
					 MXFS_REAP_RETIRE);
}

void
mxfs_dlm_pr_sweep_work_fn(struct work_struct *work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_pr_sweep_work);
	struct super_block	*sb = mp->m_super;
	struct inode		*inode, *toput = NULL;
	int			swept = 0, seen = 0;
	unsigned long		visited = 0;
	/*
	 *  (instrumented — separate hang, NOT BUG3): P-PRSWEEP-CAP
	 * has been observed firing with seen=0 on a node whose real inode cache
	 * is far smaller than the 1M visit cap, which starves an unrelated
	 * concurrent drop_caches() (_raw_spin_lock on s_inode_list_lock) for
	 * minutes. Proven via live capture: sb->s_inodes can contain a node
	 * whose OWN i_sb_list has become self-referential (the standard
	 * post-list_del_init state of any evicted inode) while something
	 * upstream of it in the list still points there — list_for_each_entry
	 * then loops forever on that one node without ever comparing equal to
	 * the list head. A v1 detector that only compared against the WALK'S
	 * OWN first entry missed a recurrence where the stale node wasn't
	 * position 1 (confirmed: a second hang started ~30s after a clean v1
	 * bailout, same signature, different inode). Track the last
	 * P135_HIST_SZ visited pointers in a small ring and check the CURRENT
	 * entry against all of them every iteration — catches a self-loop (or
	 * any short cycle) starting anywhere in the walk, not just at the
	 * front. Root cause of the stale linkage is NOT yet found (worth its
	 * own instrumented pass later; unrelated to BUG3's ihold/igrab fix) — this
	 * is a safe mitigation for the OBSERVABLE hang, not a claim the
	 * underlying race is fixed.
	 */
#define MXFS_PRSWEEP_HIST_SZ	32
	struct inode		*p135_hist[MXFS_PRSWEEP_HIST_SZ] = { NULL };

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
		return;

	/*
	 *  unconditional entry/exit + in-loop heartbeat
	 * (instrumented — the sweep-pin tripwire proved pr_sweep is NOT the inode
	 * that gets evicted out from under it, but that leaves open whether
	 * pr_sweep is even still RUNNING during a P-PRSWEEP-CAP-class hang.
	 * Every other mxfs exit path already logs; this makes ALL of them
	 * (including the swept==0 natural-completion path, previously
	 * silent) log unconditionally, plus a periodic in-loop heartbeat, so
	 * a live dmesg capture can show invocation boundaries and confirm or
	 * refute "still actively iterating" during a stuck window without
	 * needing a live interactive session into an already-wedged node.
	 */
	mxfs_probe("mxfs: P137-PRSWEEP-ENTER\n");

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct xfs_inode *ip = NULL;
		bool is_candidate = false;
		bool force_yield;
		bool p135_cyc = false;
		int p135_i;

		if (!(mxfs_istate(inode) & (I_FREEING | I_WILL_FREE | I_NEW)) &&
		    S_ISREG(inode->i_mode)) {
			ip = XFS_I(inode);
			/* cheap unlocked prefilter — the demote helper
			 * re-checks everything under i_dlm_lock */
			is_candidate = ip->i_dlm_mode == MXFS_LOCK_PR &&
				ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
				!ip->i_dlm_bast_pending;
		}

		visited++;
		for (p135_i = 0; p135_i < MXFS_PRSWEEP_HIST_SZ; p135_i++) {
			if (p135_hist[p135_i] == inode) {
				p135_cyc = true;
				break;
			}
		}
		if (unlikely(p135_cyc)) {
			spin_unlock(&sb->s_inode_list_lock);
			WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, NULL);
			iput(toput);
			pr_warn("mxfs: P135-PRSWEEP-CYCLE visited=%lu ino=%lu ptr=%px comm=%s — s_inodes re-visited a recent entry WITHOUT reaching the head; bailing out (list corruption, not just a big cache)\n",
				visited, (unsigned long)inode->i_ino, inode,
				current->comm);
			return;
		}
		p135_hist[visited % MXFS_PRSWEEP_HIST_SZ] = inode;
		if (visited >= MXFS_PRSWEEP_VISIT_CAP) {
			/* iput() can recursively need s_inode_list_lock via
			 * eviction — must drop the lock first (same rule as
			 * every other exit path in this function). */
			spin_unlock(&sb->s_inode_list_lock);
			WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, NULL);
			iput(toput);
			mxfs_probe("mxfs: P-PRSWEEP-CAP visited=%lu seen=%d swept=%d — bailing out (suspiciously long/cyclic s_inodes walk)\n",
				visited, seen, swept);
			return;
		}

		/* v1 escape: contention-driven, zero cost on the common
		 * path.  v2 escape: unconditional, bounds worst-case
		 * uninterrupted runtime even with no other runnable work on
		 * this cpu (see comment above the #defines). */
		force_yield = (visited % MXFS_PRSWEEP_YIELD_EVERY) == 0;
		if (unlikely(force_yield))
			mxfs_probe_ratelimited("mxfs: P137-PRSWEEP-HEARTBEAT visited=%lu seen=%d swept=%d\n",
				visited, seen, swept);
		if (!is_candidate && !force_yield && !need_resched())
			continue;
		if (!igrab(inode))
			continue;
		spin_unlock(&sb->s_inode_list_lock);

		/*
		 *  sweep-pin tripwire (instrumented direct
		 * evidence probe for the P135-PRSWEEP-CYCLE root cause).  The
		 * igrab() above SHOULD make it impossible for `inode` to enter
		 * real eviction until our iput() below — if the P25-INSTR
		 * sync-inactive hook (xfs_icache.c) ever observes this exact
		 * inode entering eviction while it's still recorded here, that
		 * is direct proof something ELSE over-released a reference it
		 * did not hold.  Clear-before-iput / set-after-igrab so the
		 * window this tracks matches `toput`'s own live-reference
		 * window exactly.
		 */
		WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, NULL);
		iput(toput);
		toput = inode;
		WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, toput);

		if (is_candidate) {
			seen++;
			if (mxfs_dlm_queue_pr_demote(ip, 0, 16 /* dir_ex_sweep */))
				swept++;
		} else {
			cond_resched();
		}

		if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp)) {
			WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, NULL);
			iput(toput);
			pr_warn("mxfs: P-PRSWEEP aborted (shutdown/unmount) seen=%d swept=%d\n",
				seen, swept);
			return;
		}
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	WRITE_ONCE(mp->m_mxfs_pr_sweep_pinned, NULL);
	iput(toput);
	if (swept)
		mxfs_probe("mxfs: P-PRSWEEP released %d idle PR grants (of %d candidates) after losing a PR dir to a peer EX\n",
			swept, seen);
	else
		mxfs_probe("mxfs: P137-PRSWEEP-EXIT visited=%lu seen=%d swept=0 (reached list head, no candidates)\n",
			visited, seen);
}

/*
 * Trigger for the sweep — called from mxfs_dlm_bast_process when a
 * DIRECTORY this node held in PR is being demoted (only an exclusive
 * requester BASTs a PR holder).  Rate-limited; runs on the inode-bast wq.
 */
void
mxfs_dlm_pr_sweep_trigger(struct xfs_mount *mp)
{
	unsigned long last, now = jiffies;

	if (!mxfs_dir_ex_bast_sweep || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	last = READ_ONCE(mp->m_mxfs_pr_sweep_last);
	if (last && time_before(now, last + msecs_to_jiffies(3000)))
		return;
	if (cmpxchg(&mp->m_mxfs_pr_sweep_last, last, now) != last)
		return;	/* lost the race — someone else triggered */
	queue_work(mp->m_mxfs_inode_bast_wq, &mp->m_mxfs_pr_sweep_work);
}

/*
 * instrumented ROOT FIX (default ON): stamp a shared dir-metadata
 * buffer's b_mxfs_written_seq at I/O COMPLETION (__xfs_buf_ioend) rather than
 * at SUBMIT (xfs_buf_submit).  PROVEN cause of the dir_reuse readdir=799
 * insert-loss: submit-time stamping makes mxfs_dir_buf_is_undestaged() report
 * an in-flight (or skip-emulated) dirent write as durable, so the EX-release
 * fence hands the dir lock to a peer before the just-added block lands → peer
 * cold-reads the stale LUN and drops the entry.  Set 0 to A/B back to the old
 * submit-time stamp (diagnostic only).
 */
int mxfs_dir_wseq_at_completion = 1;	/* correct fix per design review, left
					 * default-0 pending validation.  run75
					 * PROVED the submit-time stamp is load-bearing for a
					 * durable content loss: a freshly-grown dir block's
					 * first write self-stamped wseq=lseq at submit, the
					 * NL-window suppressors (P3W nl_released / P12 ex_guard)
					 * then saw "destaged" and dropped the ONLY write, the
					 * release evict (P3D) destroyed the in-core copy, and
					 * the platter kept a PRIOR-mkfs image at that daddr
					 * (uuid-mismatch EFSCORRUPTED loop, run75 round 6).
					 * Honest completion-time stamping is required for every
					 * undestaged-content safety check.  DEFAULT ON. */
module_param_named(dir_wseq_at_completion, mxfs_dir_wseq_at_completion, int, 0644);
MODULE_PARM_DESC(dir_wseq_at_completion,
                 "Stamp dir-metadata b_mxfs_written_seq at I/O completion "
                 "not submit (default 0; correct but insufficient alone — "
                 "closes the in-flight/skip-emulated undestaged mis-report)");
