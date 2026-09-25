// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- test injectors, dump triggers and debugfs surfaces
 */
#define MXFS_TU_ID 10	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
atomic64_t mxfs_dem_wedge_precond;     /* victim of a steal reached the demote-wait */
atomic64_t mxfs_dem_inject_unclaim;    /* TEST-ONLY: forced unclaim before trailing irele */

/*
 * P34J-RELOAD-RACE-BAIL accounting — H2, now the only live hypothesis
 * for D-SILENT-MKDIR-LOSS.
 *
 * The bail abandons a reload and leaves i_dlm_stale set, on the comment's
 * promise that "caller retries post-drain".  proved for the DEMOTE
 * flavour of the same bail that no caller ever implemented that retry.  Nobody
 * has ever measured it for the RACE flavour, so measure it rather than assume
 * either way: stamp the inode at the bail, and clear the stamp at the next
 * COMPLETED reload of that inode.
 *
 *   unresolved = total - resolved   is the number of bails that no later reload
 *                                   ever followed — i.e. an in-core image left
 *                                   knowingly stale with nothing scheduled to
 *                                   fix it.  If that is >0 the promise is
 *                                   broken and the bail is a loss producer.
 *
 * Measured in a run that lost 8 dirents: race bail was the ONLY nonzero
 * mechanism marker (P32E/P195/P188/P177/P146V/P65/P194 all read 0 in the
 * scoped window), and every bail had epoch == entry_epoch, so the bail fired
 * exclusively on the foreign-drain arm.
 */
atomic64_t mxfs_rb_total;
atomic64_t mxfs_rb_resolved;
atomic64_t mxfs_rb_sum_us;
atomic64_t mxfs_rb_max_us;
/*
 * H2': does the P6-MIDTENURE-RELOAD-SKIP clear staleness on an image a race
 * bail discarded?  See the measurement block at the P6 skip site.
 */
atomic64_t mxfs_p6_skip_total;
atomic64_t mxfs_p6_skip_after_rb;
atomic64_t mxfs_p6_src_hist[MXFS_P6_SRC_N];
atomic64_t mxfs_p6_repeat_ge8;
atomic64_t mxfs_p6_repeat_max;

atomic64_t mxfs_dem_punt_retain;		/* claims retained by the punt */
atomic64_t mxfs_dem_punt_owner_clear;	/* retention ended by its own owner at ilock_end */

atomic64_t mxfs_dem_strand_n;		/* inodes named as stranded */

/*
 * DISCRIMINATOR for the strand's mechanism.  A claim taken at
 * mxfs_inode_dlm_defer_bast is released by exactly one of three outcomes, and
 * these three counters partition them:
 *
 *   defer_set   every MXFS_SET_DEMOTER the defer performs
 *   defer_clear every MXFS_CLEAR_DEMOTER the trans drain performs
 *   punt_retain the punt path, which deliberately retains (counted already)
 *
 * If defer_set == defer_clear + punt_retain, every deferred entry reached the
 * drain and a surviving claim must come from an UNBALANCED NESTED SET (depth
 * accounting), not a missed drain.  If defer_set > defer_clear + punt_retain,
 * entries are being lost before the drain — a leaked pending list.  The two
 * mechanisms need opposite fixes, so this decides it in one run instead of a
 * session of inference.
 */
atomic64_t mxfs_dem_defer_set;
atomic64_t mxfs_dem_defer_clear;
atomic64_t mxfs_dem_drain_residue;	/* entries left on the list */

/*
 * 0.75.35 (D-PHANTOM-GRANT-BAIL-SKIPS-EPOCH-BUMP-DCACHE-ABA-482) verification
 * knobs.  The P106 phantom bail (a cached dir EX whose backing grant is not
 * there) fired zero times on every row searched, so the path is forced:
 *   dbg_p106_inject_ino   the ONE directory inode the injection applies to
 *   dbg_p106_inject_shots one-shot budget consumed with atomic_dec_if_positive
 *                         at the backing-record check (and only when the
 *                         branch's own prerequisites already hold).  0.75.36:
 *                         a shot RELEASES THE GRANT ON THE WIRE behind the
 *                         cache and the check then reads the wire for real —
 *                         which is what a phantom is.  The 0.75.35 shot only
 *                         forged the check's answer while the transport still
 *                         held the grant; that divergence runs the other way
 *                         and wedged the node into shutdown when the peer
 *                         BASTed a grant the node could not prove it held.
 *                         P106-INJECT-CONSUMED names the consumption, the
 *                         release rc and the re-sampled answer
 *   dbg_p106_bail_pause_ms one-shot pause after the bail, BEFORE the slow
 *                         path re-acquires, so a peer can change the namespace
 *                         inside the authority gap the bail exposes
 *   p106_check_n          read-only: how often the check site ran with its
 *                         prerequisites met (the denominator the record asked
 *                         for; a probe count alone bounds nothing)
 */
static unsigned long long mxfs_dbg_p106_inject_ino;
module_param_named(dbg_p106_inject_ino, mxfs_dbg_p106_inject_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_p106_inject_ino, "DEBUG: directory inode the P106 phantom injection applies to (0=off)");
static int mxfs_dbg_p106_inject_shots;
module_param_named(dbg_p106_inject_shots, mxfs_dbg_p106_inject_shots, int, 0644);
MODULE_PARM_DESC(dbg_p106_inject_shots, "DEBUG one-shot budget: at the P106 backing-record check, release dbg_p106_inject_ino's grant on the wire behind the cache (a real phantom) this many times, then let the check read the wire");

bool mxfs_dbg_p106_inject_take(uint64_t ino)
{
	int left;

	if (likely(READ_ONCE(mxfs_dbg_p106_inject_ino) != ino))
		return false;
	do {
		left = READ_ONCE(mxfs_dbg_p106_inject_shots);
		if (left <= 0)
			return false;
	} while (cmpxchg(&mxfs_dbg_p106_inject_shots, left, left - 1) != left);
	return true;
}

static int mxfs_dbg_sb_late_dirty;
module_param_named(dbg_sb_late_dirty, mxfs_dbg_sb_late_dirty, int, 0644);
MODULE_PARM_DESC(dbg_sb_late_dirty,
	"DEBUG one-shot: log the root inode core after the SB summary seal at the next put_super (D-0133 late-dirty invariant arm; the departure must go DIRTY)");

/*
 * (D-0487): one-shot arm consumed by mxfs_sb_summary_final_sync AFTER
 * it has taken the cluster-wide SB summary lock and BEFORE its xfs_log_quiesce.
 * It commits an unchanged AG-header image for an AG this node does not hold
 * (the same injection as the debugfs inject_unheld_agmeta_dirty, starting at
 * this AG number and moving up until one is accepted), so the pinned-AIL
 * fail-stop is exercised while the lock is HELD — the case the pre-unmount
 * injector can never produce, because that pin is caught before the lock.
 * -1 = disarmed (default).  Scratch filesystems only.
 */
static int mxfs_dbg_sb_inject_unheld_agno = -1;
module_param_named(dbg_sb_inject_unheld_agno, mxfs_dbg_sb_inject_unheld_agno, int, 0644);
MODULE_PARM_DESC(dbg_sb_inject_unheld_agno,
	"DEBUG one-shot: at the next put_super, after the SB summary lock is taken and before its quiesce, commit an unchanged AG-header image for the first unheld AG >= this number (D-0487 under-lock pin); -1 = off");

/*
 * D-0532 directed concurrency arm (design-consult bar: one genuine DLM
 * holder + another task on the nowait/unlock path with a BAST pending —
 * holder count not decremented, no drain/unlock under the live holder,
 * release only at the genuine final-holder transition).  Three one-shot
 * knobs keyed by inode number, all default 0 (never in production):
 *   dbg_bast_pause_ino / dbg_bast_pause_ms: mxfs_dlm_bast_process parks
 *     right before its reg-durable loop (mode already NL, so a local
 *     acquire may materialize mid-drain — the P15H-LIVE-SKIP case);
 *   dbg_relog_force_ino: the reg-durable loop treats the dinode as
 *     clean-but-unlanded once (v_behind), forcing the P146V re-log arm
 *     (ILOCK_EXCL nowait -> tr_ichange -> xfs_iunlock_nodlm);
 *   dbg_iolock_hold_ino / dbg_iolock_hold_ms: xfs_ilock parks after a
 *     successful IOLOCK_EXCL admission (mxfs_dlm_ilock_begin done,
 *     i_dlm_ex_holders counted) — the genuine holder whose count the
 *     re-log's raw unlock must leave untouched.
 * Harness: tests/sess475_chain117_d0532_relog_concurrency.sh.
 */
static unsigned long long mxfs_dbg_bast_pause_ino;
module_param_named(dbg_bast_pause_ino, mxfs_dbg_bast_pause_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_bast_pause_ino, "DEBUG one-shot: park the BAST release drain of this inode before its reg-durable loop for dbg_bast_pause_ms (D-0532 arm)");
static int mxfs_dbg_bast_pause_ms = 4000;
module_param_named(dbg_bast_pause_ms, mxfs_dbg_bast_pause_ms, int, 0644);
MODULE_PARM_DESC(dbg_bast_pause_ms, "DEBUG: hold length for dbg_bast_pause_ino (ms)");
static unsigned long long mxfs_dbg_relog_force_ino;
module_param_named(dbg_relog_force_ino, mxfs_dbg_relog_force_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_relog_force_ino, "DEBUG one-shot: force the P146V clean-but-unlanded re-log arm for this inode in its next release drain (D-0532 arm)");
static unsigned long long mxfs_dbg_iolock_hold_ino;
module_param_named(dbg_iolock_hold_ino, mxfs_dbg_iolock_hold_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_iolock_hold_ino, "DEBUG one-shot: park xfs_ilock after this inode's next IOLOCK_EXCL DLM admission for dbg_iolock_hold_ms (D-0532 arm)");
static int mxfs_dbg_iolock_hold_ms = 8000;
module_param_named(dbg_iolock_hold_ms, mxfs_dbg_iolock_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_iolock_hold_ms, "DEBUG: hold length for dbg_iolock_hold_ino (ms)");

bool mxfs_dbg_ino_take(unsigned long long *knob, uint64_t ino)
{
	unsigned long long v = READ_ONCE(*knob);

	return unlikely(v && v == ino) && cmpxchg(knob, v, 0ULL) == v;
}

void mxfs_dbg_sliced_sleep(int ms)
{
	int left;

	for (left = ms; left > 0; left -= 100)
		msleep(left > 100 ? 100 : left);
}

void
mxfs_dbg_bast_pause(struct xfs_inode *ip)
{
	int ms;

	if (!mxfs_dbg_ino_take(&mxfs_dbg_bast_pause_ino, ip->i_ino))
		return;
	ms = READ_ONCE(mxfs_dbg_bast_pause_ms);
	mxfs_probe("mxfs: P-BAST-PAUSE ino=%llu ms=%d ex_h=%u pr_h=%u mode=%u state=%u — INJECTED: parking the release drain before its reg-durable loop\n",
		(unsigned long long)ip->i_ino, ms, ip->i_dlm_ex_holders,
		ip->i_dlm_pr_holders, ip->i_dlm_mode, ip->i_dlm_state);
	mxfs_dbg_sliced_sleep(ms);
	mxfs_probe("mxfs: P-BAST-PAUSE-END ino=%llu ex_h=%u pr_h=%u mode=%u state=%u\n",
		(unsigned long long)ip->i_ino, ip->i_dlm_ex_holders,
		ip->i_dlm_pr_holders, ip->i_dlm_mode, ip->i_dlm_state);
}

/*
 * D-0532 item (c) directed schedule: park the BAST work item for this inode
 * BEFORE it touches the in-core state (pending still set, state BAST, the
 * cached grant live), so the creator can free and recycle the number inside
 * that window.  One-shot, default 0; harness tests/d0532_pending_bast_recycle.sh.
 */
static unsigned long long mxfs_dbg_bast_defer_ino;
module_param_named(dbg_bast_defer_ino, mxfs_dbg_bast_defer_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_bast_defer_ino, "DEBUG one-shot: park this inode's next BAST work item for dbg_bast_defer_ms before it consumes the pending flag (D-0532 item c)");
static int mxfs_dbg_bast_defer_ms = 700;
module_param_named(dbg_bast_defer_ms, mxfs_dbg_bast_defer_ms, int, 0644);
MODULE_PARM_DESC(dbg_bast_defer_ms, "DEBUG: park length for dbg_bast_defer_ino (ms)");

void
mxfs_dbg_bast_defer(struct xfs_inode *ip, const char *who)
{
	int ms;

	if (!mxfs_dbg_ino_take(&mxfs_dbg_bast_defer_ino, ip->i_ino))
		return;
	ms = READ_ONCE(mxfs_dbg_bast_defer_ms);
	mxfs_probe("mxfs: P-BAST-DEFER ino=%llu who=%s ms=%d pending=%d mode=%u state=%u ex_h=%u pr_h=%u — INJECTED: parking the BAST work before it runs\n",
		(unsigned long long)ip->i_ino, who, ms,
		ip->i_dlm_bast_pending ? 1 : 0, ip->i_dlm_mode, ip->i_dlm_state,
		ip->i_dlm_ex_holders, ip->i_dlm_pr_holders);
	mxfs_dbg_sliced_sleep(ms);
	mxfs_probe("mxfs: P-BAST-DEFER-END ino=%llu pending=%d mode=%u state=%u nlink=%u imode=0%o\n",
		(unsigned long long)ip->i_ino, ip->i_dlm_bast_pending ? 1 : 0,
		ip->i_dlm_mode, ip->i_dlm_state, VFS_I(ip)->i_nlink,
		VFS_I(ip)->i_mode);
}

/*
 * Peek without consuming: the regular-file early-out ahead of the durable
 * loop (mxfs_dlm_bast_process) must fall through while the arm is armed,
 * or the loop that holds the injection is never entered — the drain's own
 * AIL flush lands the inode first, so a regular file reads clean at the
 * early-out every time (s49a/s49b: BAST delivered, drain ran, no P-BAST-PAUSE
 * and no P146V-FORCE in 4 laps).
 */
bool
mxfs_dbg_relog_force_armed(struct xfs_inode *ip)
{
	unsigned long long v = READ_ONCE(mxfs_dbg_relog_force_ino);

	return unlikely(v && v == ip->i_ino);
}

bool
mxfs_dbg_relog_force_take(struct xfs_inode *ip)
{
	if (!mxfs_dbg_ino_take(&mxfs_dbg_relog_force_ino, ip->i_ino))
		return false;
	mxfs_probe("mxfs: P146V-FORCE ino=%llu ex_h=%u pr_h=%u mode=%u state=%u — INJECTED: treating the dinode as clean-but-unlanded\n",
		(unsigned long long)ip->i_ino, ip->i_dlm_ex_holders,
		ip->i_dlm_pr_holders, ip->i_dlm_mode, ip->i_dlm_state);
	return true;
}

void
mxfs_dbg_iolock_hold(struct xfs_inode *ip)
{
	int ms;

	if (!mxfs_dbg_ino_take(&mxfs_dbg_iolock_hold_ino, ip->i_ino))
		return;
	ms = READ_ONCE(mxfs_dbg_iolock_hold_ms);
	mxfs_probe("mxfs: P-IOLOCK-HOLD ino=%llu ms=%d ex_h=%u pr_h=%u mode=%u state=%u bast_pending=%d comm=%s — INJECTED: genuine IOLOCK_EXCL holder parked after DLM admission\n",
		(unsigned long long)ip->i_ino, ms, ip->i_dlm_ex_holders,
		ip->i_dlm_pr_holders, ip->i_dlm_mode, ip->i_dlm_state,
		ip->i_dlm_bast_pending ? 1 : 0, current->comm);
	mxfs_dbg_sliced_sleep(ms);
	mxfs_probe("mxfs: P-IOLOCK-HOLD-END ino=%llu ex_h=%u pr_h=%u mode=%u state=%u bast_pending=%d\n",
		(unsigned long long)ip->i_ino, ip->i_dlm_ex_holders,
		ip->i_dlm_pr_holders, ip->i_dlm_mode, ip->i_dlm_state,
		ip->i_dlm_bast_pending ? 1 : 0);
}

int
mxfs_dbg_sb_late_dirty_take(void)
{
	int v = READ_ONCE(mxfs_dbg_sb_late_dirty);

	if (unlikely(v > 0) && xchg(&mxfs_dbg_sb_late_dirty, 0) == v)
		return v;
	return 0;
}

/* (D-0487): one-shot take of the under-lock injection arm; -1 = off. */
int
mxfs_dbg_sb_inject_unheld_take(void)
{
	int v = READ_ONCE(mxfs_dbg_sb_inject_unheld_agno);

	if (unlikely(v >= 0) && xchg(&mxfs_dbg_sb_inject_unheld_agno, -1) == v)
		return v;
	return -1;
}

/* ─── Instrumentation ─── */

/* phantom-EX measurement (instrumented): count dir-EX cached fast-path
 * serves and how many of them serve while the LOCAL DLM entry is NOT granted at
 * EX (held_rawmode < EX = the proven phantom-EX divergent-RMW root).
 * Breakdown by the gates that currently suppress the P-TCPEX-REACQ phantom
 * detector, so we learn WHY the storm serves the phantom.  No hot-path printk;
 * dumped on demand via the dirphantom_dump param. */
atomic64_t mxfs_dirEX_serve_total;
atomic64_t mxfs_dirEX_phantom_total;
atomic64_t mxfs_dirEX_phantom_pinned;
atomic64_t mxfs_dirEX_phantom_selfcr;
atomic64_t mxfs_dirEX_phantom_unpub;
/* N=8 serve-path counters: which acquire path serves a dir-EX
 * modify, and does it leave a STALE base (gen>loaded) for the RMW. */
atomic64_t mxfs_dirEX_fastret_total;   /* dir-EX fast-path serves (at return) */
atomic64_t mxfs_dirEX_fastret_stale;   /* ...ending gen>loaded (stale base) */
atomic64_t mxfs_dirEX_demoter_bypass;  /* dir-EX served via demoter-bypass (no refresh) */
atomic64_t mxfs_dirEX_slowpath;        /* dir-EX served via slow-path acquire */
atomic64_t mxfs_dirEX_gg_armed;        /* gg_refresh armed (grant token changed = handoff) */
atomic64_t mxfs_dirEX_gg_hgg0;         /* grant_gen query returned 0 (unreliable/no token) */

/* Per-reason armer counters (design review contract item 7): prove the gate stays
 * OCCASIONAL — an invalidation policy forcing an adopt on every grant would
 * live exactly where the 32-node dir-EX pace defects live. */
atomic64_t mxfs_b_adopt_sentinel;	/* armed: validity bit unset */
atomic64_t mxfs_b_adopt_epoch;		/* armed: valid_epoch != grant epoch */
atomic64_t mxfs_b_adopt_gen;		/* armed: cached_gen != grant gen */
atomic64_t mxfs_b_dirty_skip;		/* refused: tenure already dirty (fail-closed) */
atomic64_t mxfs_b_p34j_defer;		/* reload bailed on active demote with gate armed */
atomic64_t mxfs_b_stamp_n;		/* baselines stamped (adopt/keep/publish/rebase) */

/*
 * D-512 cycle-2 verification T2/T6 (ruling): deterministic
 * pausepoints in the release drain, so a harness can hold a victim node
 * mid-drain at a chosen stage and assert that NOTHING the barrier protects
 * (peer grant acquisition, unlink/free publication, ino/extent reuse) can
 * pass until the drain completes and the unlock publishes.  Debug-only:
 * zero cost unarmed.
 *   stage 1  before the site-1 dirty-page flush
 *   stage 2  after the flush, before invalidate_inode_pages2
 *   stage 3  after invalidate (site-1 drain done, pre-abort-gate)
 *   stage 4  before the site-2 post-NL data flush (REG only)
 *   stage 5  immediately before the on-disk unlock CAS
 * ("writeback outstanding" from the ruling's ladder has no deterministic
 * hook — it is covered probabilistically by stage 1 + load.)
 */
/*
 * (D-PURGE-NONATOMIC-PUBLICATION, ruling arm 1): writing a node id
 * here makes THIS node — expected to be a non-elected survivor — invoke the
 * normal disklock purge path for that (dead) node, every gate intact.  The
 * write blocks for the purge's duration and returns its rc (-EBUSY while
 * the elected owner holds the recovery descriptor).  Write-only, one-shot.
 */
static int
mxfs_dbg_purge_victim_set(const char *val, const struct kernel_param *kp)
{
	struct xfs_mount	*mp = READ_ONCE(mxfs_dbg_mp);
	unsigned int		id;
	int			rc = kstrtouint(val, 0, &id);

	if (rc)
		return rc;
	if (!id)
		return 0;
	if (!mp || !mp->m_mxfs_dlm)
		return -ENODEV;
	return mxfs_v5_dlm_dbg_purge_node(mp->m_mxfs_dlm, id);
}
static const struct kernel_param_ops mxfs_dbg_purge_victim_ops = {
	.set = mxfs_dbg_purge_victim_set,
};
module_param_cb(dbg_purge_victim, &mxfs_dbg_purge_victim_ops, NULL, 0200);
MODULE_PARM_DESC(dbg_purge_victim,
	"DEBUG one-shot (write-only): run the normal purge path for this dead node id from a non-elected survivor");

unsigned long long mxfs_dbg_rel_pause_ino;
module_param_named(dbg_rel_pause_ino, mxfs_dbg_rel_pause_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_rel_pause_ino,
	"DEBUG: inode whose release drain pauses at dbg_rel_pause_stage for dbg_rel_pause_ms");
unsigned int mxfs_dbg_rel_pause_stage;
module_param_named(dbg_rel_pause_stage, mxfs_dbg_rel_pause_stage, uint, 0644);
MODULE_PARM_DESC(dbg_rel_pause_stage,
	"DEBUG: release-drain pausepoint 1-5 (see source; 0=off)");
unsigned int mxfs_dbg_rel_pause_ms;
module_param_named(dbg_rel_pause_ms, mxfs_dbg_rel_pause_ms, uint, 0644);
MODULE_PARM_DESC(dbg_rel_pause_ms,
	"DEBUG: width of the release-drain pause in ms (0=off)");

void
mxfs_dbg_rel_pause(
	struct xfs_inode	*ip,
	unsigned int		stage)
{
	unsigned int	ms = READ_ONCE(mxfs_dbg_rel_pause_ms);

	if (likely(!ms) ||
	    READ_ONCE(mxfs_dbg_rel_pause_stage) != stage ||
	    READ_ONCE(mxfs_dbg_rel_pause_ino) != ip->i_ino)
		return;
	mxfs_probe("mxfs: P-D512-RELPAUSE ino=%llu stage=%u ms=%u — holding release drain\n",
		(unsigned long long)ip->i_ino, stage, ms);
	msleep(ms);
	mxfs_probe("mxfs: P-D512-RELPAUSE-END ino=%llu stage=%u\n",
		(unsigned long long)ip->i_ino, stage);
}

/*
 * D-512 cycle-2 T8 (ruling, item 11): synthetic drain-failure
 * injectors.  Each containment arm below (site-1 writeback fail-stop,
 * site-1 invalidate retry, site-2 post-NL flush fail-stop, protective-
 * reload dirty-mismatch) is dormant on a healthy rig — zero fires across
 * every green board — so T8 forces each predicate true ONCE for one
 * target inode and asserts the armed response actually contains (wedge/
 * poison/withdraw, unlock never published, cluster survives via fence+
 * recovery).  One-shot: the knob self-clears at the injection point so a
 * wedged mount cannot re-fire it.  Debug-only observation channel — the
 * injected rc never reaches the platter; only the RESPONSE is real.
 */
/*
 * (D-0941): poison every Nth cross-node lookup, so the SHELL
 * RETIREMENT machinery can be exercised on demand.  0 = off, and off is the
 * default and the shipped state.
 *
 * The defect this exists for is a property of retirement, not of how a shell
 * comes to be poisoned: once MXFS_IF_INCARN_STALE is set, the lookup arm must
 * retire the shell and re-iget, and it could not, so it returned -ESTALE for
 * files that existed.  Reaching that state NATURALLY needs a cross-incarnation
 * reload with the cluster buffer protected, which happened in 1 lap out of 18
 * and resisted three purpose-built reproducers.  Verifying a fix against a
 * 1-in-18 event is not verification.
 *
 * Poisoning a HEALTHY inode is a faithful and safe exercise of that machinery:
 * the retirement evicts the shell and re-igets the SAME, current incarnation,
 * so a correct implementation returns the right inode and the lookup succeeds.
 * A broken one returns -ESTALE for a file that plainly exists -- which is the
 * defect, reproduced deterministically.  The RESPONSE is entirely real; only
 * the trigger is synthetic.
 */
int mxfs_dbg_poison_nth;
module_param_named(dbg_poison_nth, mxfs_dbg_poison_nth, int, 0644);
MODULE_PARM_DESC(dbg_poison_nth,
	"DEBUG: poison every Nth multi-node lookup result to exercise shell retirement (0=off)");

/*
 * (D-0941): A/B lever for the poison-retirement wait.  1 (default) is
 * the fix -- eight attempts with an escalating sleep, sized from the measured
 * 2.9-68 ms poison-to-revocation latency.  0 reverts to the behaviour that
 * produced the defect: four back-to-back attempts with no delay, which measured
 * 23 microseconds end to end and therefore could not outlast the revocation it
 * was waiting on.  Kept as a lever so the control and the fix can be measured
 * on ONE build, rather than the control being an argument about a build that no
 * longer exists.
 */
int mxfs_poison_retire_wait = 1;
module_param_named(poison_retire_wait, mxfs_poison_retire_wait, int, 0644);
MODULE_PARM_DESC(poison_retire_wait,
	"poisoned-shell retirement: 1=both fixes, wait for the queued revocation AND retire on a watched drain (default); 0=pre-fix, neither; 2=no wait but retire on a watched drain (exercises the drain path, which mode 1 rarely reaches)");

unsigned long long mxfs_dbg_rel_fail_ino;
module_param_named(dbg_rel_fail_ino, mxfs_dbg_rel_fail_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_rel_fail_ino,
	"DEBUG: inode whose release path takes one synthetic failure (see dbg_rel_fail_kind)");
unsigned int mxfs_dbg_rel_fail_kind;
module_param_named(dbg_rel_fail_kind, mxfs_dbg_rel_fail_kind, uint, 0644);
MODULE_PARM_DESC(dbg_rel_fail_kind,
	"DEBUG: 1=site-1 writeback fail, 2=site-1 invalidate fail, 3=site-2 flush fail, 4=reload dirty-mismatch (one-shot; 0=off)");

bool
mxfs_dbg_rel_fail(
	struct xfs_inode	*ip,
	unsigned int		kind)
{
	if (likely(!READ_ONCE(mxfs_dbg_rel_fail_kind)))
		return false;
	if (READ_ONCE(mxfs_dbg_rel_fail_kind) != kind ||
	    READ_ONCE(mxfs_dbg_rel_fail_ino) != ip->i_ino)
		return false;
	WRITE_ONCE(mxfs_dbg_rel_fail_kind, 0);
	mxfs_probe("mxfs: P-D512-INJECT ino=%llu kind=%u — synthetic release failure injected (T8)\n",
		(unsigned long long)ip->i_ino, kind);
	return true;
}

/*
 * 0.75.52 (D-0922 c1 stall): stack watchdog around the release drain's
 * page flush.  On the appender node of the peer-truncate lap, one release
 * per truncate spends ~117-120 ms inside filemap_write_and_wait at drain
 * site 1 and then ends in a P244 terminal defer; the appender is parked
 * (P-FILE-YIELD) and the truncator waits the whole time.  Between the AG-2
 * remaster grant (P-TAUTH-REMASTER-RX) and the first AG-2 btree read
 * (P144-RD cntbt) the kernel log of that node is silent for ~110 ms, so no
 * existing probe names the wait site.  This timer fires while the flush
 * is still running and prints the drain task's stack, up to three times
 * per flush, so the wait site is read off the stack instead of guessed.
 * mxfs.drain_wb_watch_ms=0 disarms it; the default is below every healthy
 * flush measured (c1 <= 6 ms) and above none of the outliers.
 */
int mxfs_drain_wb_watch_ms = 50;
module_param_named(drain_wb_watch_ms, mxfs_drain_wb_watch_ms, int, 0644);
MODULE_PARM_DESC(drain_wb_watch_ms,
	"release-drain page flush watchdog: dump the drain task's stack every N ms it is still inside the flush (max 3 dumps per flush; 0=off)");

static void
mxfs_drain_watch_fire(
	struct timer_list	*t)
{
	struct mxfs_drain_watch	*w = container_of(t, struct mxfs_drain_watch, timer);

	w->fires++;
	pr_warn("mxfs: P-DRAINWB-STALL ino=%llu site=%d pid=%d waited_ms=%llu fire=%d realns=%llu — release drain still inside its page flush; drain task stack follows\n",
		(unsigned long long)w->ino, w->site, w->pid,
		(unsigned long long)((ktime_get_ns() - w->t0) / NSEC_PER_MSEC),
		w->fires, (unsigned long long)ktime_get_real_ns());
	mxfs_pal_dump_task_stack(w->pid);
	if (w->fires < 3)
		mod_timer(&w->timer,
			  jiffies + msecs_to_jiffies(mxfs_drain_wb_watch_ms));
}

void
mxfs_drain_watch_arm(
	struct mxfs_drain_watch	*w,
	struct xfs_inode	*ip,
	int			site)
{
	int			ms = READ_ONCE(mxfs_drain_wb_watch_ms);

	w->armed = false;
	if (ms <= 0)
		return;
	timer_setup_on_stack(&w->timer, mxfs_drain_watch_fire, 0);
	w->pid = task_pid_nr(current);
	w->ino = ip->i_ino;
	w->t0 = ktime_get_ns();
	w->site = site;
	w->fires = 0;
	w->armed = true;
	mod_timer(&w->timer, jiffies + msecs_to_jiffies(ms));
}

void
mxfs_drain_watch_disarm(
	struct mxfs_drain_watch	*w)
{
	if (!w->armed)
		return;
	timer_delete_sync(&w->timer);
	timer_destroy_on_stack(&w->timer);
	w->armed = false;
}
static int mxfs_dirring_dump_set(const char *val,
				 const struct kernel_param *kp)
{
	mxfs_wrtr_dump();
	return 0;
}
static const struct kernel_param_ops mxfs_dirring_dump_ops = {
	.set = mxfs_dirring_dump_set,
	.get = param_get_int,
};
static int mxfs_dirring_dump_poke;
module_param_cb(dirring_dump, &mxfs_dirring_dump_ops,
		&mxfs_dirring_dump_poke, 0644);
MODULE_PARM_DESC(dirring_dump,
                 "Write any value to dump the P172-WRTR write-provenance "
                 "ring to dmesg (post-detection harvest; no effect on state)");

/*
 *  (2026-07-18): deferred extent-free AG-DLM patience.
 * A peer-held AG can outlast the 120s CAW poll when the holder's release
 * drain is saturated (32/cawd fio_perf: AG pages held 10+ minutes, eight
 * defer-finish shutdowns).  xfs_extent_free_finish_item converts the
 * -ETIMEDOUT into up to this many -EAGAIN requeue cycles (re-log intent,
 * roll, re-register waiter) before letting the legacy fatal path stand.
 * 8 × 120s ≈ 16 min tolerance, covering the worst observed holder tenure.
 */
int mxfs_efi_agwait_max = 8;
module_param_named(efi_agwait_max, mxfs_efi_agwait_max, int, 0644);
MODULE_PARM_DESC(efi_agwait_max,
                 "Max EAGAIN-requeue cycles for a deferred extent-free whose "
                 "AG DLM acquire timed out (each cycle re-arms the 120s CAW "
                 "waiter). 0 = fail fatally on first timeout (legacy).");

/*
 * dir-block WRITEBACK LANDING-ORDER trace.  The
 * dir_reuse loss is PROVEN (this session) to be a POST-SUBMIT ordering / reuse
 * issue (in-core ⊇ disk at every write, so NOT a stale-base RMW).  P-DLAND logs,
 * at I/O COMPLETION (the moment a write physically lands), each dir3
 * data/leaf/block write's daddr + owner + read-time incarnation stamp + a
 * content fingerprint (FNV hash of the post-header bytes) + realns timestamp.
 * Merging all nodes' P-DLAND by daddr+realns reconstructs which CONTENT VERSION
 * of a reused daddr landed LAST — the smoking gun for "an older write wins".
 * Lighter than dirwr=2 (one line per completed dir write, not per submit+content
 * dump), so it perturbs timing far less.  Default 0.
 */
int mxfs_dirland_enabled;
module_param_named(dirland, mxfs_dirland_enabled, int, 0644);
MODULE_PARM_DESC(dirland,
                 "Dir writeback landing-order trace (P-DLAND at I/O completion): "
                 "0=off (default), 1=on");
static struct mxfs_dland_ent mxfs_dland_ring[MXFS_DLAND_RING];
static atomic_t mxfs_dland_head = ATOMIC_INIT(0);

void
mxfs_dland_record(u64 daddr, u64 owner, u32 incarn, u32 sum, int cnt,
		  const char *ops)
{
	u32			i;
	struct mxfs_dland_ent	*e;

	if (!mxfs_dirland_enabled)
		return;
	i = (u32)atomic_inc_return(&mxfs_dland_head) - 1;
	e = &mxfs_dland_ring[i & (MXFS_DLAND_RING - 1)];
	e->daddr = daddr;
	e->owner = owner;
	e->incarn = incarn;
	e->sum = sum;
	e->cnt = cnt;
	e->realns = ktime_get_real_ns();
	memcpy(e->comm, current->comm, sizeof(e->comm));
	e->comm[sizeof(e->comm) - 1] = 0;
	strncpy(e->ops, ops ? ops : "?", sizeof(e->ops) - 1);
	e->ops[sizeof(e->ops) - 1] = 0;
}

static int
mxfs_dirphantom_dump_set(const char *val, const struct kernel_param *kp)
{
	mxfs_probe("mxfs: P6-DIRPHANTOM serve_total=%lld phantom_total=%lld phantom_pinned=%lld phantom_selfcr=%lld phantom_unpub=%lld\n",
		(long long)atomic64_read(&mxfs_dirEX_serve_total),
		(long long)atomic64_read(&mxfs_dirEX_phantom_total),
		(long long)atomic64_read(&mxfs_dirEX_phantom_pinned),
		(long long)atomic64_read(&mxfs_dirEX_phantom_selfcr),
		(long long)atomic64_read(&mxfs_dirEX_phantom_unpub));
	mxfs_probe("mxfs: P6-DIRPATH fastret_total=%lld fastret_stale=%lld demoter_bypass=%lld slowpath=%lld gg_armed=%lld gg_hgg0=%lld\n",
		(long long)atomic64_read(&mxfs_dirEX_fastret_total),
		(long long)atomic64_read(&mxfs_dirEX_fastret_stale),
		(long long)atomic64_read(&mxfs_dirEX_demoter_bypass),
		(long long)atomic64_read(&mxfs_dirEX_slowpath),
		(long long)atomic64_read(&mxfs_dirEX_gg_armed),
		(long long)atomic64_read(&mxfs_dirEX_gg_hgg0));
	/* Option B per-reason gate counters (design review contract item 7):
	 * sentinel/epoch = armed adopts, gen = counted-only evidence,
	 * dirty_skip = fail-closed refusals, p34j = level-held defers,
	 * stamp = baselines published.  An arm rate near the serve rate
	 * would mean the invalidation policy is forcing an adopt per grant
	 * (the dir-EX pace hazard) — the A/B asserts these stay occasional. */
	mxfs_probe("mxfs: P216-B-STATS sentinel=%lld epoch=%lld gen_seen=%lld dirty_skip=%lld p34j_defer=%lld stamps=%lld\n",
		(long long)atomic64_read(&mxfs_b_adopt_sentinel),
		(long long)atomic64_read(&mxfs_b_adopt_epoch),
		(long long)atomic64_read(&mxfs_b_adopt_gen),
		(long long)atomic64_read(&mxfs_b_dirty_skip),
		(long long)atomic64_read(&mxfs_b_p34j_defer),
		(long long)atomic64_read(&mxfs_b_stamp_n));
	return 0;
}
static const struct kernel_param_ops mxfs_dirphantom_dump_ops = {
	.set = mxfs_dirphantom_dump_set,
};

/*
 * Exposure readout for the two-slot demoter claim
 * (D-BAST-IRELE-INACTIVE-SELF-WEDGE).  See the counter declarations for what
 * each field proves; `slot2` is the one that establishes the fix path ran.
 */
static int
mxfs_demoter_dump_set(const char *val, const struct kernel_param *kp)
{
	mxfs_probe("mxfs: P75-DEMOTER-CLAIM slot1=%lld slot1_nest=%lld slot2=%lld slot2_nest=%lld contest=%lld foreign_clear=%lld clear_noclaim=%lld\n",
		(long long)atomic64_read(&mxfs_dem_slot1),
		(long long)atomic64_read(&mxfs_dem_slot1_nest),
		(long long)atomic64_read(&mxfs_dem_slot2),
		(long long)atomic64_read(&mxfs_dem_slot2_nest),
		(long long)atomic64_read(&mxfs_dem_contest),
		(long long)atomic64_read(&mxfs_dem_foreign_clear),
		(long long)atomic64_read(&mxfs_dem_clear_noclaim));
	/*
	 * D-MOUNT-DEGRADES-WITH-USE exposure/effect pair.  `retain` is
	 * the exposure (how many times the trans-free punt left a claim
	 * unpaired) and is knob-INDEPENDENT, so the negative-control arm
	 * provably enters the same state; `reclaim` is the fix firing.
	 */
	mxfs_probe("mxfs: P213-PUNT retain=%lld owner_clear=%lld reclaim=%lld selfclear=%lld stranded=%lld\n",
		(long long)atomic64_read(&mxfs_dem_punt_retain),
		(long long)atomic64_read(&mxfs_dem_punt_owner_clear),
		(long long)atomic64_read(&mxfs_dem_punt_reclaim_n),
		(long long)atomic64_read(&mxfs_dem_punt_selfclear),
		(long long)atomic64_read(&mxfs_dem_strand_n));
	/*
	 * defer_set MUST equal defer_clear + punt_retain.  Any excess is
	 * a deferred entry that never reached the drain; residue names the tp it
	 * was left on.  See the counter declarations for what each excess means.
	 */
	/*
	 * ROOT pair for the stranded claim.  free_dirty is the source
	 * (objects returned to the slab still claimed) and init_inherit is the
	 * damage (fresh inodes born already claimed).  With the free-side clear
	 * in place init_inherit MUST be 0; free_dirty > 0 with init_inherit == 0
	 * means the source still happens but can no longer strand anyone.
	 */
	mxfs_probe("mxfs: P216-CLAIM-RECYCLE init_inherit=%lld free_dirty=%lld\n",
		(long long)atomic64_read(&mxfs_dem_init_inherit),
		(long long)atomic64_read(&mxfs_dem_free_dirty));
	mxfs_probe("mxfs: P215-DEFER set=%lld clear=%lld retain=%lld residue=%lld balance=%lld\n",
		(long long)atomic64_read(&mxfs_dem_defer_set),
		(long long)atomic64_read(&mxfs_dem_defer_clear),
		(long long)atomic64_read(&mxfs_dem_punt_retain),
		(long long)atomic64_read(&mxfs_dem_drain_residue),
		(long long)(atomic64_read(&mxfs_dem_defer_set) -
			    atomic64_read(&mxfs_dem_defer_clear) -
			    atomic64_read(&mxfs_dem_punt_retain)));
	pr_warn("mxfs: P75-DEMOTER-LEGACY legacy_steal=%lld legacy_clear_live=%lld wedge_precond=%lld inject_unclaim=%lld\n",
		(long long)atomic64_read(&mxfs_dem_legacy_steal),
		(long long)atomic64_read(&mxfs_dem_legacy_clear_live),
		(long long)atomic64_read(&mxfs_dem_wedge_precond),
		(long long)atomic64_read(&mxfs_dem_inject_unclaim));
	{
		long long t = atomic64_read(&mxfs_rb_total);
		long long r = atomic64_read(&mxfs_rb_resolved);

		mxfs_probe("mxfs: P79-RACEBAIL total=%lld resolved=%lld unresolved=%lld max_ms=%lld mean_ms=%lld p6skip=%lld p6skip_after_rb=%lld\n",
			t, r, t - r,
			atomic64_read(&mxfs_rb_max_us) / 1000,
			r ? (atomic64_read(&mxfs_rb_sum_us) / r) / 1000 : 0,
			atomic64_read(&mxfs_p6_skip_total),
			atomic64_read(&mxfs_p6_skip_after_rb));
	}
	{
		char buf[256];
		int n = 0, i;

		for (i = 0; i < MXFS_P6_SRC_N; i++) {
			long long v = atomic64_read(&mxfs_p6_src_hist[i]);

			if (v && n < (int)sizeof(buf) - 24)
				n += scnprintf(buf + n, sizeof(buf) - n,
					       "%s%d:%lld", n ? "," : "", i, v);
		}
		if (!n)
			scnprintf(buf, sizeof(buf), "none");
		mxfs_probe("mxfs: P81-P6-SRC repeat_ge8=%lld repeat_max=%lld hist[src:count]=%s\n",
			atomic64_read(&mxfs_p6_repeat_ge8),
			atomic64_read(&mxfs_p6_repeat_max), buf);
	}
	return 0;
}
static const struct kernel_param_ops mxfs_demoter_dump_ops = {
	.set = mxfs_demoter_dump_set,
};
module_param_cb(demoter_dump, &mxfs_demoter_dump_ops, NULL, 0644);
MODULE_PARM_DESC(demoter_dump,
	"write anything to print the P75-DEMOTER-CLAIM two-slot claim census to dmesg");

module_param_cb(dirphantom_dump, &mxfs_dirphantom_dump_ops, NULL, 0644);
MODULE_PARM_DESC(dirphantom_dump,
		 "Write any value to dump the dir-EX phantom-serve counters to dmesg");

static int
mxfs_dland_dump_set(const char *val, const struct kernel_param *kp)
{
	u32	head = (u32)atomic_read(&mxfs_dland_head);
	u32	cnt = head < MXFS_DLAND_RING ? head : MXFS_DLAND_RING;
	u32	start = head - cnt;
	u32	k;

	mxfs_probe("mxfs: P-DLAND-DUMP begin head=%u cnt=%u\n", head, cnt);
	for (k = 0; k < cnt; k++) {
		struct mxfs_dland_ent *e =
			&mxfs_dland_ring[(start + k) & (MXFS_DLAND_RING - 1)];

		mxfs_probe("mxfs: P-DLAND d=%llu o=%llu i=%u s=0x%08x n=%d t=%llu c=%s op=%s\n",
			(unsigned long long)e->daddr,
			(unsigned long long)e->owner, e->incarn, e->sum,
			e->cnt,
			(unsigned long long)e->realns, e->comm, e->ops);
	}
	mxfs_probe("mxfs: P-DLAND-DUMP end\n");
	return 0;
}
static const struct kernel_param_ops mxfs_dland_dump_ops = {
	.set = mxfs_dland_dump_set,
};
module_param_cb(dland_dump, &mxfs_dland_dump_ops, NULL, 0644);
MODULE_PARM_DESC(dland_dump,
		 "Write any value to dump the in-kernel dir-landing ring to dmesg");

/*
 * cheap gate for the inode-cluster partial-WRITE decision
 * trace (P28-IWR* in mxfs_submit_partial_inode_write, pal/linux/xfs_buf.c).
 * Logs (ratelimited) whether each inode-cluster write took the skip-NL path,
 * how many sectors were skipped, and why a write fell back to whole-buffer —
 * without the heavy per-write disk read that mxfs.dirwr enables.  0=off.
 */
int mxfs_iwr_enabled;
module_param_named(iwr, mxfs_iwr_enabled, int, 0644);
MODULE_PARM_DESC(iwr,
                 "Inode-cluster partial-write decision trace (P28-IWR*): "
                 "0=off (default), 1=ratelimited decision+reason");

/* xfs_iflush resurrection guard window (P25-RESURRECT-SKIP).
 * Skip flushing a stale-live in-core inode whose COHERENT on-disk copy a peer
 * FREED (di_mode=0 di_nlink=0) and is 1..N free-bumps ahead (disk_gen -
 * incore_gen in [1,N]) — preventing the dir_reuse_coherency leaf double-claim.
 * 0 disables the guard. Default 64 (covers an inode# reused a few dozen times
 * across rm-rf rounds; a chunk-init random gen lands in the window only
 * N/2^32 of the time). Runtime-tunable to characterize the chunk-reinit tail. */
int mxfs_resurrect_gen_window = 64;
module_param_named(resurrect_gen_window, mxfs_resurrect_gen_window, int, 0644);
MODULE_PARM_DESC(resurrect_gen_window,
                 "iflush resurrection guard: skip flushing a peer-freed inode "
                 "when (u32)(disk_gen - incore_gen) is in [1,N]; 0=off, default 64");

/*
 * gate for the dir DATA/leaf-block xfsaild-skip chokepoint
 * (the 2/tcp crash_consistency fix).  0=detector-only (P16-DIRBLK-SUBMIT logs
 * the skip-predicate state for every dir-block write, gated by dirwr/instr, but
 * no write is suppressed — instrumented instrument phase); 1=enforce (suppress an
 * NL-released or prior-tenure dir-block write at the single bio chokepoint,
 * mirroring the proven P61 bmbt guard).  Default 1 once proven.
 */
int mxfs_dirskip_enabled;	/* default 0: detect-only (enforce refuted) */
module_param_named(dirskip, mxfs_dirskip_enabled, int, 0644);
MODULE_PARM_DESC(dirskip,
                 "Suppress stale xfsaild dir-block writes (NL-released only): "
                 "0=detect-only (default), 1=enforce NL-released skip");

/* instrumented block watch — see xfs_buf_submit_bio. */
unsigned long long mxfs_watch_daddr;
module_param_named(watch_daddr, mxfs_watch_daddr, ullong, 0644);
MODULE_PARM_DESC(watch_daddr,
                 "Log every xfs_buf bio touching this envelope-relative daddr "
                 "(0=off): direction, content magic, ops, comm; stack on writes");
EXPORT_SYMBOL(mxfs_watch_daddr);

/*
 * write-side TENURE-gated dir DATA-block clobber
 * guard (P-DATACLOBBER-SKIP, pal/linux/xfs_buf.c).  The FIX for 2/tcp
 * dir_reuse_coherency Bug A (stale-tenure block-0 clobber).  Unlike dirskip
 * above (NL/ABA arms, both refuted/detect-only), this uses the PROVEN
 * discriminator — b_mxfs_dir_gen < owner i_dlm_dir_gen (prior EX tenure) — and
 * NEVER skips on the gen mismatch alone: it plain-reads the coherent on-disk
 * block and skips only when disk is a valid same-owner dir block with strictly
 * MORE live dirents (the buffer would erase peer-committed entries).
 * 0=off, 1=detect-only (log, still write), 2=enforce (default).
 */
/*
 * default 0 (OFF).  enforce=2 REFUTED (instrumented): under the dir_reuse
 * rm-rf+recreate churn the dir inode# AND its block daddrs are REUSED, so the
 * coherent on-disk image at a dir daddr can be a prior-incarnation GHOST with
 * the SAME owner ino and MORE dirents than the fresh current write — the
 * disk_cnt>buf_cnt skip then suppresses the CURRENT write and keeps the ghost
 * (rounds 1-6 went catastrophic: lookup_fail=150).  Content comparison cannot
 * tell a ghost from live peer data.  Kept only as a detector (mode 1).
 */
int mxfs_dataclobber;	/* default 0 */
module_param_named(dataclobber, mxfs_dataclobber, int, 0644);
MODULE_PARM_DESC(dataclobber,
                 "Tenure-gated dir DATA-block stale-RMW clobber DETECTOR: "
                 "0=off (default), 1=detect-only, 2=enforce (REFUTED — ghost reuse)");

/*
 * ROOT FIX for 4/tcp dir_reuse_coherency durable loss.
 *
 * PROVEN vector (raw-disk + P-LEAFWRITE): a STALE dir DATA/LEAF buffer
 * lingering in-AIL from a PRIOR EX tenure is re-flushed by background
 * xfsaild (comm=dd, bufgen=0) over the daddr a PEER has since grown on disk
 * — e.g. test2 wrote a leaf with buf_cnt=127 over disk_cnt=402, durably
 * dropping 275 peer hash entries (-> LOOKUP_ENOENT/REREAD_MISS, all nodes).
 * This is the ABA writeback-clobber (M3) for the dirent carriers.
 *
 * Why the existing guards miss it:
 *  - mxfs_dataclobber>=2 enforce was REFUTED ("keeps the ghost", lookup_fail
 *    150): it skips on dc_stale (bgen<dir_gen) regardless of grant mode, so a
 *    LEGIT dirent removal under EX (cache-hit block with a stale bgen stamp)
 *    is suppressed -> the deleted entry survives.
 *  - the dirskip NL arm only fires when the dir inode is still in-core; a
 *    reclaimed dir (comm=dd flush) has in_core=0 so it falls through.
 *
 * The SOUND discriminator: a dir metadata block may only be DESTAGED by the
 * node that currently holds the dir DLM EX (its in-core image is then
 * authoritative — incl. legit removes/conversions/fresh leaves, which ALL run
 * under EX).  A write submitted while we do NOT hold the dir EX (NL-released,
 * PR cacher, or the inode reclaimed) is by definition a superseded
 * prior-tenure image -> if a coherent on-disk read PROVES the disk carries
 * strictly more / divergent dirents, skip the write (the durable peer image
 * is authoritative).  The disk-proven check is the safety net: a legit write
 * whose content matches/leads disk is never skipped; the EX-gate is the
 * cheap pre-filter that keeps the refuted under-EX false-positives out.
 */
int mxfs_dir_ex_write_guard = 1;	/* default ON */
module_param_named(dir_ex_write_guard, mxfs_dir_ex_write_guard, int, 0644);
MODULE_PARM_DESC(dir_ex_write_guard,
                 "Skip a disk-proven clobbering dir DATA/LEAF write when this "
                 "node does NOT hold the dir DLM EX (1=on default, 0=off)");

int mxfs_dir_relepoch_skip = 0;	/* DEFAULT OFF — REFUTED (4/4 FAIL in reliability loop; loss occurs with 0 relepoch skips → not a pre-release reflush). Kept as dormant modarg. */

int mxfs_dir_relepoch_reread = 0;	/* DEFAULT OFF — INERT (P50-RD proved relepoch==i_dlm_epoch at EVERY read; acquire-evict keeps the base fresh, so this never fires. Base is NOT stale at modify → loss is a DLM serialization hole, not a coherency-cache bug). Kept as dormant modarg. */
module_param_named(dir_relepoch_reread, mxfs_dir_relepoch_reread, int, 0644);
MODULE_PARM_DESC(dir_relepoch_reread,
                 "Re-read (FUA) a CLEAN cached dir DATA/leaf buffer at read time "
                 "when its b_mxfs_relepoch < owner i_dlm_epoch (the cached image "
                 "predates a grant release by this node, so a peer may have "
                 "superseded the block — using it as an addname RMW base overwrites "
                 "the peer's dirent).  Reliable local release-epoch; clean-only so "
                 "no current-tenure work is tossed (1=on default, 0=off)");
module_param_named(dir_relepoch_skip, mxfs_dir_relepoch_skip, int, 0644);
MODULE_PARM_DESC(dir_relepoch_skip,
                 "Skip an xfsaild reflush of a CLEAN dir DATA/leaf buffer whose "
                 "b_mxfs_relepoch < owner i_dlm_epoch (the image predates a grant "
                 "release by this node, so a peer may have superseded the block on "
                 "the shared LUN — reflushing it durably reverts the peer's add). "
                 "Reliable local release-epoch gate; clean buffer = already durable "
                 "so nothing is lost (1=on default, 0=off)");

/*
 * (design review): the EX-HELD analogue of dir_ex_write_guard.
 * The dir_reuse readdir=799 residual is a node that STILL HOLDS dir EX
 * destaging a STALE-KEPT prior-tenure dir DATA block (bgen<dir_gen = dc_stale)
 * that it RMW'd without re-reading the peer's durable image — durably erasing a
 * peer's dirent (content-divergent, count-preserving; PROVEN not an addname
 * double-alloc since P22-FREESLOT-STALE fired 0x).  ex_write_guard's
 * dir_not_held_ex gate skips this case.  The refuted mxfs_dataclobber>=2
 * dc_stale skip caught it but ALSO false-skipped a prior-INCARNATION ghost at a
 * reused daddr (rm-rf recycles the dir inode#+daddrs).  This guard adds the
 * missing INCARNATION gate (b_mxfs_dir_incarn == i_generation) AND still
 * requires the disk-proven content-fingerprint clobber, so: a legit
 * current-tenure write re-reads first (bgen==dir_gen, never dc_stale); a ghost
 * has a different incarnation; only a genuine same-incarnation stale-base
 * clobber is suppressed (disk's peer image is authoritative).  Default ON.
 */
int mxfs_dir_stale_incarn_skip;	/* DEFAULT 0 — REFUTED. Enforce=1 caused
				 * MASSIVE loss (readdir 474/800, lookup_fail 124)
				 * + 4-node shutdown: dc_stale && same_incarn is NOT
				 * a tight enough discriminator, it suppresses LEGIT
				 * dir writes ("suppression is the corruptor").
				 * Kept as an inert lever only. */
module_param_named(dir_stale_incarn_skip, mxfs_dir_stale_incarn_skip, int, 0644);
MODULE_PARM_DESC(dir_stale_incarn_skip,
                 "Skip a disk-proven same-incarnation stale-base dir DATA/LEAF "
                 "write even under EX (1=on default, 0=off)");

/*
 * sess-tcp: lightweight gate for the DLM master lock-table entry-lifecycle
 * trace (P-LKT in dlm/dlm.c) — grant insert / removal / stale-removal for
 * INODE resources.  Used to catch the proven tcp_dlm_scaling DOUBLE-GRANT
 * (a spurious master-table entry removal lets both nodes hold dir-EX).
 * Cheaper than mxfs.instr (no 100x demote); leave on for a tcp_dlm_scaling
 * run.  0=off (default), 1=on.
 */
int mxfs_lockwr_enabled;
module_param_named(lockwr, mxfs_lockwr_enabled, int, 0644);
MODULE_PARM_DESC(lockwr,
                 "DLM lock-table entry-lifecycle ring (P-LKT, lock-free, no "
                 "hot-path printk): 0=off (default), 1=record");

/*
 * optional P-LKT recording filter.  The ring floods with child-inode
 * GRANT-LOCAL/UNLOCK churn (the n1_rN create/rm storm) and evicts the SHARED
 * DIR's cross-node grant events before a post-mortem dump.  Set lkt_ino to the
 * shared-dir inode number (settable at runtime once the test has created it) to
 * record ONLY that inode; 0 = record all (default).
 */
unsigned long long mxfs_lkt_ino;
module_param_named(lkt_ino, mxfs_lkt_ino, ullong, 0644);
MODULE_PARM_DESC(lkt_ino,
                 "P-LKT ring: record only this inode number (0=all, default)");
static int mxfs_lktdump_set(const char *val, const struct kernel_param *kp)
{
	unsigned long long ino = 0;
	int error;

	if (val) {
		error = kstrtoull(val, 0, &ino);
		if (error)
			return error;
	}
	mxfs_dlm_lkt_dump((uint64_t)ino);
	return 0;
}
static const struct kernel_param_ops mxfs_lktdump_ops = {
	.set = mxfs_lktdump_set,
	.get = NULL,
};
module_param_cb(lktdump, &mxfs_lktdump_ops, NULL, 0200);
MODULE_PARM_DESC(lktdump,
		 "write a dir inode number (0=all) to dump the P-LKT ring to dmesg");

/*
 * D-DWORK-RUNTIME-PIN probe: write 1 to walk this SB's s_inodes and
 * print every mxfs inode still carrying references — the survivors of a
 * drop_caches are exactly the pinned population (repro: 200 bulk creates +
 * sync + drop_caches x2 leaves slab +200; rm breaks the pin, peer dir BAST
 * does not; no dwork/rearm prints for the pinned inos).  Names the holder
 * class directly: i_count, i_state, dlm mode/state, armed work state.
 */
struct xfs_mount *mxfs_dbg_mp;	/* last multi-node mount, for write-
				 * triggered diagnostics; set in xfs_super.c
				 * after mount init, cleared at put_super. */
EXPORT_SYMBOL(mxfs_dbg_mp);
static int mxfs_pin_census_set(const char *val, const struct kernel_param *kp)
{
	struct xfs_mount	*mp = READ_ONCE(mxfs_dbg_mp);
	struct super_block	*sb;
	struct inode		*inode;
	int			n = 0;

	if (!mp || !mp->m_super)
		return 0;
	sb = mp->m_super;
	mxfs_probe("mxfs: PIN-CENSUS begin\n");
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct xfs_inode *ip;
		int cnt = atomic_read(&inode->i_count);

		if (mxfs_istate(inode) & (I_FREEING | I_WILL_FREE | I_NEW))
			continue;
		ip = XFS_I(inode);
		if (n++ > 400) {
			mxfs_probe("mxfs: PIN-CENSUS capped at 400\n");
			break;
		}
		mxfs_probe("mxfs: PIN-CENSUS ino=%llu i_count=%d i_state=0x%lx on_lru=%d nlink=%u mode_reg=%d dlm_mode=%u dlm_state=%u exh=%u prh=%u bpend=%d work_busy=%d dwork_busy=%d\n",
			(unsigned long long)ip->i_ino, cnt, mxfs_istate(inode),
			list_empty(&inode->i_lru) ? 0 : 1,
			inode->i_nlink, S_ISREG(inode->i_mode) ? 1 : 0,
			ip->i_dlm_mode, ip->i_dlm_state,
			ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
			ip->i_dlm_bast_pending ? 1 : 0,
			work_busy(&ip->i_dlm_bast_work) ? 1 : 0,
			work_busy(&ip->i_dlm_bast_dwork.work) ? 1 : 0);
	}
	spin_unlock(&sb->s_inode_list_lock);
	mxfs_probe("mxfs: PIN-CENSUS end walked=%d\n", n);
	return 0;
}
static const struct kernel_param_ops mxfs_pin_census_ops = {
	.set = mxfs_pin_census_set,
};
module_param_cb(pin_census, &mxfs_pin_census_ops, NULL, 0200);
MODULE_PARM_DESC(pin_census,
		 "write 1 to dump refcounts/DLM state of every cached mxfs inode");

/*
 * Register the BAST callback with the DLM layer.
 * Called after mxfs_v5_dlm_init succeeds.
 */
/*
 * -- /sys/kernel/debug/mxfs/<dev>/recovery_blocked ----------------
 *
 * Everything the 0.11.422-424 fence-evidence work added fails CLOSED: when
 * exclusion cannot be proved, or has lapsed, MXFS refuses to replay a dead
 * peer's journal slice, refuses to release its grants, and refuses to zero its
 * sector.  From outside, that is indistinguishable from a hang -- peers block
 * on the frozen victim's locks either way -- and MEASURED
 * (tests/excl_lapse_probe.sh) the refusal repeats every ~30 s indefinitely
 * with the whole story visible only in dmesg.
 *
 * design review (design-consult ruling, Q2): "Add an explicit durable and observable
 * state, not merely repeated log lines... Mount status should clearly say that
 * the filesystem is blocked on unproven exclusion, rather than appearing
 * hung."  This is that surface.  An empty file means nothing is blocked.
 */
int
mxfs_recovery_blocked_show(
	struct seq_file		*m,
	void			*data)
{
	struct xfs_mount	*mp = m->private;
	struct mxfs_recov_blocked b;
	int			slot;
	int			n = 0;

	if (!mp->m_mxfs_dlm)
		return 0;

	for (slot = mxfs_v5_dlm_blocked_iter(mp->m_mxfs_dlm, -1, &b);
	     slot >= 0;
	     slot = mxfs_v5_dlm_blocked_iter(mp->m_mxfs_dlm, slot, &b)) {
		if (!n++)
			seq_puts(m,
"RECOVERY_BLOCKED_FENCE - these journal slices cannot be recovered.\n"
"Their grants stay frozen and peers will block on them.  This is a REFUSAL,\n"
"not a hang: MXFS will not replay a dead peer's slice without proof that the\n"
"peer is excluded from the shared LUN.\n\n");
		seq_printf(m,
"slot=%u reason=%s rc=%d\n"
"  victim      node=%u incarnation=%llu key=0x%llx\n"
"  fence       kind=%s(%u) resv_type=0x%02x pr_gen=%u term=%u\n"
"  ownership   prover=%u recovery_owner=%u\n"
"  timing      blocked_for_ms=%llu attempts=%u last_attempt_ms_ago=%llu\n",
			b.victim_slot, mxfs_recov_blocked_reason(b.reason),
			b.last_rc,
			b.victim_node, (unsigned long long)b.victim_epoch,
			(unsigned long long)b.victim_key,
			mxfs_fence_kind_name((enum mxfs_fence_kind)b.fence_kind),
			b.fence_kind, b.resv_type, b.pr_generation,
			b.fence_term,
			b.prover_node, b.owner_node,
			(unsigned long long)(mxfs_pal_time_ms() - b.first_ms),
			b.attempts,
			(unsigned long long)(mxfs_pal_time_ms() - b.last_ms));

		switch (b.reason) {
		case MXFS_RBLK_CERT_UNRECORDED:
			seq_puts(m,
"  ACTION      the exclusion was PROVED but its certificate is not durable.\n"
"              The victim's PR key is already consumed, so no other node can\n"
"              prove it again.  This slice needs operator intervention: fence\n"
"              the victim externally and clear its slot.\n");
			break;
		case MXFS_RBLK_NO_PR:
			seq_puts(m,
"  ACTION      this LUN offers no SCSI persistent reservations, so exclusion\n"
"              can never be proved and automatic recovery cannot run here.\n"
"              Use a target that supports PR, or recover offline.\n");
			break;
		case MXFS_RBLK_EXCL_LAPSED:
			seq_puts(m,
"  ACTION      the fenced victim is REGISTERED AGAIN and can write to this\n"
"              LUN right now.  Stop it, or fence it at the target, before\n"
"              this slice can be recovered.\n");
			break;
		case MXFS_RBLK_SELF_FENCED:
			seq_puts(m,
"  ACTION      THIS node's own PR key is gone - we are the fenced one.  This\n"
"              mount must not write; unmount it.\n");
			break;
		case MXFS_RBLK_NO_CERTIFICATE:
		case MXFS_RBLK_OWNED_ELSEWHERE:
			seq_puts(m,
"  ACTION      another node is working on this recovery.  If it never\n"
"              finishes, that node is stuck: check it.\n");
			break;
		case MXFS_RBLK_FENCE_BLOCKED:
			seq_puts(m,
"  ACTION      every fencing attempt in a bounded series returned before\n"
"              submitting a command and proved nothing (the fence kind above\n"
"              is the last reason).  Path operations on this node's grants\n"
"              fail EIO instead of waiting; the attempt is re-driven every\n"
"              30 s.  Recovery completes by itself when the PR state changes\n"
"              (the victim's key is present again, the survivor is on ONE\n"
"              nexus, an all-registrants reservation is in force).\n"
"              single_node_exclusive=1 NO LONGER certifies this and setting it\n"
"              will not clear the block: that assertion says no other\n"
"              INITIATOR can write, and the victim is a previous INCARNATION\n"
"              whose already-accepted writes the target may still be\n"
"              finishing, so it cannot authorise replaying the slice.  Bring\n"
"              the victim's registration back - boot it - so a PREEMPT AND\n"
"              ABORT has something to name.  docs/dlm-protocol.md 'Recovery\n"
"              blocked'.\n");
			break;
		default:
			break;
		}
		seq_putc(m, '\n');
	}
	return 0;
}

/*
 * -- /sys/kernel/debug/mxfs/<dev>/inode_authority --------------------------
 *
 * The population measurement the design-consult ruling asked for, and which
 * four build-clean-but-unmeasured sessions (95-98) never produced.
 *
 * The question this file answers is NOT "does the code compile" but "how much
 * of the live acquire population can actually PROVE a durable EX tenure at
 * replay time".  Foreign-replay gating is only worth having if that fraction
 * is high; if installs are rare, the gate would refuse nearly every image and
 * the feature is a no-op dressed as safety.  Each refusal reason is separated
 * because they demand completely different follow-ups: `stalegen` is the
 * guard doing its job, `unpub` and `releasing` are coverage holes with known
 * fixes, `novalid` means the granting CAS never filled a result at all.
 *
 * Counters are module-global (not per-mount); the file is per-mount only
 * because that is where mxfs hangs its debugfs directory.
 */
int
mxfs_inode_authority_show(
	struct seq_file		*m,
	void			*data)
{
	uint64_t inst = atomic64_read(&mxfs_auth_install_n);
	uint64_t adv = atomic64_read(&mxfs_auth_install_advance_n);
	uint64_t novalid = atomic64_read(&mxfs_auth_ref_novalid_n);
	uint64_t stalegen = atomic64_read(&mxfs_auth_ref_stalegen_n);
	uint64_t releasing = atomic64_read(&mxfs_auth_ref_releasing_n);
	uint64_t unpub = atomic64_read(&mxfs_auth_ref_unpub_n);
	uint64_t routing = atomic64_read(&mxfs_auth_ref_routing_n);
	uint64_t reclaim = atomic64_read(&mxfs_auth_ref_reclaim_n);
	uint64_t nosnap = atomic64_read(&mxfs_auth_nosnap_n);
	uint64_t refused = novalid + stalegen + releasing + unpub +
			   routing + reclaim;
	uint64_t judged = inst + adv + refused;
	static const char * const trynames[MXFS_AUTH_TRY_MAX] = {
		[MXFS_AUTH_TRY_NONE]		= "never",
		[MXFS_AUTH_TRY_INSTALL]		= "install",
		[MXFS_AUTH_TRY_ADVANCE]		= "advance",
		[MXFS_AUTH_TRY_SAMETENURE]	= "sametenure",
		[MXFS_AUTH_TRY_NOGRES]		= "nogres",
		[MXFS_AUTH_TRY_STALEGEN]	= "stalegen",
		[MXFS_AUTH_TRY_RELEASING]	= "releasing",
		[MXFS_AUTH_TRY_UNPUB]		= "unpublished",
		[MXFS_AUTH_TRY_ROUTING]		= "routing",
		[MXFS_AUTH_TRY_RECLAIM]		= "reclaim",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_UNSET]	= "st:unset",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_EPOCH]
								= "st:write_epoch",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NONWRITE_MODE]
								= "st:nonwrite_mode",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_ZERO_EPOCH]
								= "st:write_zero_epoch",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NO_RESOURCE]
								= "st:no_resource",
		[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_SINGLE_NODE]
								= "st:single_node",
	};
	int i;

	seq_printf(m,
"installs            %llu\n"
"installs_advance    %llu\n"
"refusals            %llu\n"
"  novalid           %llu\n"
"    nogres          %llu\n"
"    nonwrite_mode   %llu\n"
"    write_zero_ep   %llu\n"
"    no_resource     %llu\n"
"    unset           %llu\n"
"    write_epoch     %llu\n"
"  stalegen          %llu\n"
"  releasing         %llu\n"
"  unpublished       %llu\n"
"  routing           %llu\n"
"  reclaim           %llu\n"
"no_snapshot         %llu\n"
"judged              %llu\n",
		(unsigned long long)inst, (unsigned long long)adv,
		(unsigned long long)refused,
		(unsigned long long)novalid,
		(unsigned long long)atomic64_read(&mxfs_auth_ref_nogres_n),
		(unsigned long long)atomic64_read(
			&mxfs_auth_ref_status_n[MXFS_GAUTH_NONWRITE_MODE]),
		(unsigned long long)atomic64_read(
			&mxfs_auth_ref_status_n[MXFS_GAUTH_WRITE_ZERO_EPOCH]),
		(unsigned long long)atomic64_read(
			&mxfs_auth_ref_status_n[MXFS_GAUTH_NO_RESOURCE]),
		(unsigned long long)atomic64_read(
			&mxfs_auth_ref_status_n[MXFS_GAUTH_UNSET]),
		(unsigned long long)atomic64_read(
			&mxfs_auth_ref_status_n[MXFS_GAUTH_WRITE_EPOCH]),
		(unsigned long long)stalegen,
		(unsigned long long)releasing, (unsigned long long)unpub,
		(unsigned long long)routing, (unsigned long long)reclaim,
		(unsigned long long)nosnap, (unsigned long long)judged);
	if (judged)
		seq_printf(m, "install_pct         %llu\n",
			   (unsigned long long)(((inst + adv) * 100) / judged));

	/*
	 * The per-inode last-install-ATTEMPT record, aggregated.  Same numbers
	 * as the refusal block above by construction; printed separately
	 * because THIS is the vocabulary the dirty-point classifier reports
	 * in, and the two must agree for that classification to be trusted.
	 */
	seq_puts(m, "\nlast_install_attempt\n");
	for (i = 0; i < MXFS_AUTH_TRY_MAX; i++) {
		uint64_t v = atomic64_read(&mxfs_auth_try_n[i]);

		if (v || (i == MXFS_AUTH_TRY_INSTALL))
			seq_printf(m, "  %-18s %llu\n",
				   trynames[i] ? trynames[i] : "?",
				   (unsigned long long)v);
	}

	seq_printf(m,
"\nrelinquish\n"
"  revoke            %llu\n"
"  release_begin     %llu\n"
"  release_clean     %llu\n"
"  phantom_loss      %llu\n"
"  backstop          %llu\n"
"  pub_live          %llu\n"
"unpublished_noted   %llu\n",
		(unsigned long long)atomic64_read(&mxfs_auth_revoke_n),
		(unsigned long long)atomic64_read(&mxfs_auth_relbegin_n),
		(unsigned long long)atomic64_read(&mxfs_auth_relclean_n),
		(unsigned long long)atomic64_read(&mxfs_auth_phantom_n),
		(unsigned long long)atomic64_read(&mxfs_auth_backstop_n),
		(unsigned long long)atomic64_read(&mxfs_auth_publive_n),
		(unsigned long long)atomic64_read(&mxfs_auth_unpub_n));
	/* clean-release marker production (see xfs_relmark_item.c) */
	{
		uint64_t pub = 0, fail = 0, noid = 0;
		uint64_t im = 0, ifl = 0, am = 0, afl = 0, icl = 0;
		uint64_t icm = 0, icf = 0, icr = 0;

		mxfs_relmark_counters(&pub, &fail, &noid);
		mxfs_relmark_site_counters(&im, &ifl, &am, &afl, &icl);
		mxfs_relmark_iclus_counters(&icm, &icf, &icr);
		seq_printf(m,
"\nrelmark\n"
"  published         %llu\n"
"  publish_fail      %llu\n"
"  skip_noident      %llu\n"
"  ino_marked        %llu\n"
"  ino_failed        %llu\n"
"  ag_marked         %llu\n"
"  ag_failed         %llu\n"
"  iclus_unmarked    %llu\n"
"  iclus_marked      %llu\n"
"  iclus_failed      %llu\n"
"  iclus_reinst_ref  %llu\n",
			(unsigned long long)pub, (unsigned long long)fail,
			(unsigned long long)noid, (unsigned long long)im,
			(unsigned long long)ifl, (unsigned long long)am,
			(unsigned long long)afl, (unsigned long long)icl,
			(unsigned long long)icm, (unsigned long long)icf,
			(unsigned long long)icr);
	}
	return 0;
}

/*
 * — debugfs trigger for the CAW tenure-token (PW/EX grant-epoch)
 * selftest, the D-EX-GRANT-EPOCH verification vehicle (design-consult approved
 * ).  Write-only; the written value is the resource ino to exercise,
 * 0 = the geometry-reserved auto key:
 *
 *   ino = (agcount + 1 + node_slot) << (agblklog + inopblog) | 1
 *
 * agno >= agcount makes the key unallocatable by format guarantee (no XFS
 * allocation path can ever mint this inode, so lock-only traffic on it can
 * never collide with real allocation state), and the node-slot term makes
 * it per-node unique (concurrent runs on different nodes never contend).
 * A key STABLE across runs is deliberate: re-running exercises the
 * tombstone-recycle re-mint edge, which is the defect's core claim.
 *
 * The run executes synchronously in write(2) context (seconds; every CAW
 * call inside gates shutdown via caw_op_enter).  Serialized by an atomic
 * IDLE->RUNNING gate; concurrent writers get -EBUSY, never a queue.  The
 * write rc IS the verdict: count on PASS, -EREMOTEIO on assertion failure,
 * other -errno on infra refusal (evidence on the P274-PWTEST log lines).
 */
static atomic_t mxfs_caw_pwtest_busy = ATOMIC_INIT(0);

ssize_t
mxfs_caw_pw_selftest_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			count,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	struct mxfs_v5_dlm	*v5 = mp->m_mxfs_dlm;
	uint64_t		ino;
	int			error;

	if (!v5)
		return -ENODEV;
	if (xfs_is_shutdown(mp))
		return -ESHUTDOWN;

	error = kstrtoull_from_user(ubuf, count, 0, &ino);
	if (error)
		return error;
	if (ino == 0)
		ino = ((uint64_t)(mp->m_sb.sb_agcount + 1 +
				  mp->m_mxfs_node_slot)
		       << (mp->m_sb.sb_agblklog + mp->m_sb.sb_inopblog)) | 1;

	if (atomic_cmpxchg(&mxfs_caw_pwtest_busy, 0, 1) != 0)
		return -EBUSY;
	error = mxfs_v5_dlm_caw_pw_selftest(v5, ino);
	atomic_set(&mxfs_caw_pwtest_busy, 0);

	return error ? error : count;
}

/*
 * — debugfs trigger for the CAW same-node reconcile exerciser
 * (D-SAMENODE-WAITER-CANCEL-COLLISION closure vehicle,
 * mxfs_v5_dlm_caw_samenode_selftest).  Write "<mode> [ino]": mode 1 = hold
 * (peer), 2 = collide, 3 = negative control.  ino 0/absent = the SHARED
 * reserved key
 *
 *   ino = (agcount + 1 + 64) << (agblklog + inopblog) | 1
 *
 * — same unallocatable-by-geometry argument as the pw selftest key, but
 * beyond every node-slot-derived key (slots 0..63) so ALL nodes contend on
 * ONE slot, which is what the exerciser needs.  Synchronous (up to ~20 s
 * for collide: 8 s peer hold + owed discharge); serialized by the same
 * IDLE->RUNNING gate shape as the pw selftest (-EBUSY, never a queue).
 * write rc = count on PASS, -EREMOTEIO on assertion failure, -ENOLCK when
 * no peer holds the key, -ETIMEDOUT on a stuck attempt thread.
 */
static atomic_t mxfs_caw_samenode_busy = ATOMIC_INIT(0);

ssize_t
mxfs_caw_samenode_selftest_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			count,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	struct mxfs_v5_dlm	*v5 = mp->m_mxfs_dlm;
	char			kbuf[64];
	unsigned int		mode = 0;
	unsigned long long	ino = 0;
	int			error;

	if (!v5)
		return -ENODEV;
	if (xfs_is_shutdown(mp))
		return -ESHUTDOWN;
	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	if (sscanf(kbuf, "%u %llu", &mode, &ino) < 1)
		return -EINVAL;
	if (ino == 0)
		ino = ((uint64_t)(mp->m_sb.sb_agcount + 1 + 64)
		       << (mp->m_sb.sb_agblklog + mp->m_sb.sb_inopblog)) | 1;

	if (atomic_cmpxchg(&mxfs_caw_samenode_busy, 0, 1) != 0)
		return -EBUSY;
	error = mxfs_v5_dlm_caw_samenode_selftest(v5, ino, mode);
	atomic_set(&mxfs_caw_samenode_busy, 0);

	return error ? error : count;
}

/*
 * D-0487 verification injector.  Write "<agno>" to
 * /sys/kernel/debug/xfs/<dev>/inject_unheld_agmeta_dirty: for an AG this
 * node does NOT hold, read its AGI through the ordinary transactional read
 * (real verifier, real b_ops, the AG's own buffer cache), log it UNCHANGED,
 * commit, and force the log.  The result is a committed AGI image in this
 * node's AIL whose grant the node never held — exactly the item the
 * pre-0.69.3 unmount ordering left behind, produced on demand and without
 * the unmount race, so the push's terminal behaviour can be measured in
 * isolation.  Only the DLM authorization is bypassed (this path never calls
 * mxfs_ag_dlm_lock); buffer locking, the verifier, the log reservation and
 * the reference counting are the normal ones.  A correct push never writes
 * the image home; it does sit in this node's log slice, so the slice is
 * poisoned for the replay gate to refuse — scratch filesystems only.
 * rc: count on success; -EBUSY when the node holds the AG (the injection
 * would be authorized and prove nothing); -ENODEV without a DLM; -ESHUTDOWN.
 *
 * (D-0487): the injection body is mxfs_inject_unheld_agmeta_dirty so
 * the under-lock arm in mxfs_sb_summary_final_sync can run the same thing.
 */
int
mxfs_inject_unheld_agmeta_dirty(struct xfs_mount *mp, unsigned int agno)
{
	struct xfs_perag	*pag;
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	xfs_daddr_t		daddr;
	uint64_t		epoch;
	bool			cached;
	int			holders;
	int			error;

	if (!mp->m_mxfs_dlm)
		return -ENODEV;
	if (xfs_is_shutdown(mp))
		return -ESHUTDOWN;
	if (agno >= mp->m_sb.sb_agcount)
		return -EINVAL;
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return -EINVAL;
	epoch = READ_ONCE(pag->pag_mxfs_grant_epoch);
	cached = READ_ONCE(pag->pag_dlm_cached);
	holders = READ_ONCE(pag->pag_dlm_holders);
	if (epoch || cached || holders > 0) {
		pr_warn("mxfs: P-INJECT-UNHELD-AGMETA-REFUSED agno=%u epoch=%llu cached=%d holders=%d — this node holds the AG; an injected image here would be authorized\n",
			agno, (unsigned long long)epoch, cached ? 1 : 0, holders);
		xfs_perag_put(pag);
		return -EBUSY;
	}
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_sb, 0, 0, 0, &tp);
	if (error) {
		xfs_perag_put(pag);
		return error;
	}
	daddr = XFS_AG_DADDR(mp, agno, XFS_AGI_DADDR(mp));
	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp, daddr,
				   XFS_FSS_TO_BB(mp, 1), 0, &bp,
				   &xfs_agi_buf_ops);
	if (error) {
		xfs_trans_cancel(tp);
		xfs_perag_put(pag);
		mxfs_probe("mxfs: P-INJECT-UNHELD-AGMETA agno=%u daddr=%lld — AGI read failed rc=%d; nothing injected\n",
			agno, (long long)daddr, error);
		return error;
	}
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_AGI_BUF);
	xfs_trans_log_buf(tp, bp, 0, sizeof(struct xfs_agi) - 1);
	error = xfs_trans_commit(tp);
	xfs_log_force(mp, XFS_LOG_SYNC);
	mxfs_probe("mxfs: P-INJECT-UNHELD-AGMETA agno=%u daddr=%lld commit_rc=%d epoch_now=%llu cached=%d holders=%d — INJECTED: committed an unchanged AGI image for a grant this node does not hold; a correct push must never write it home\n",
		agno, (long long)daddr, error,
		(unsigned long long)READ_ONCE(pag->pag_mxfs_grant_epoch),
		READ_ONCE(pag->pag_dlm_cached) ? 1 : 0,
		READ_ONCE(pag->pag_dlm_holders));
	xfs_perag_put(pag);
	return error;
}

ssize_t
mxfs_inject_unheld_agmeta_dirty_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			count,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	char			kbuf[32];
	unsigned int		agno;
	int			error;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	if (sscanf(kbuf, "%u", &agno) != 1)
		return -EINVAL;
	error = mxfs_inject_unheld_agmeta_dirty(mp, agno);
	return error ? error : count;
}

/*
 * 0.84.18, test only (D-0963): /sys/kernel/debug/mxfs/<dev>/ail_push --
 * any write asks xfsaild to push the whole AIL now, the way log pressure
 * does on a busy rig.  Paired with dbg_iflush_pause_ino it puts one inode's
 * cluster write in flight on demand, which is the platter lag the defect
 * needs and a quiet rig never produces.  Counted in dbg_iflush_pause_n's
 * sibling below so a harness can prove the kick happened.
 */
atomic_t mxfs_dbg_iflush_pause_n = ATOMIC_INIT(0);
atomic_t mxfs_dbg_ail_push_n = ATOMIC_INIT(0);

ssize_t
mxfs_dbg_ail_push_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			count,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;

	if (!mp || !mp->m_ail || xfs_is_shutdown(mp))
		return -EIO;
	xfs_ail_push_all(mp->m_ail);
	mxfs_probe("mxfs: P963-AIL-PUSH n=%d — whole-AIL push requested through debugfs\n",
		atomic_inc_return(&mxfs_dbg_ail_push_n));
	return count;
}

/*
 * /sys/kernel/debug/xfs/<dev>/ailpin_stats (0.70.2): the census behind the
 * D-0487 fail-stop.  `refused` counts buffer log items xfsaild refused at
 * least once (a coherent not-held observation); `cleared` those since
 * retired, with the sum, the maximum and the slow tail of their ages from
 * first refusal; `cleared_by_shutdown` the ones retired by a failed submit
 * after a shutdown rather than a home write.  A healthy fleet shows
 * max_ms in the low tens of milliseconds against a grace of 10 s; a max
 * approaching the grace means the grace is too short for this node's
 * release drain and the fail-stop would fire on a healthy handoff.
 * `fired` is the fail-stop claim (the mount is shut down once it is 1).
 */
int
mxfs_ailpin_stats_show(
	struct seq_file		*m,
	void			*data)
{
	struct xfs_mount	*mp = m->private;
	unsigned long long	n = atomic64_read(&mp->m_mxfs_ailpin_clear_n);
	unsigned long long	sum = atomic64_read(&mp->m_mxfs_ailpin_clear_sum_ms);

	seq_printf(m,
		"refused=%llu cleared=%llu cleared_by_shutdown=%llu slow=%llu "
		"sum_ms=%llu max_ms=%u mean_ms=%llu grace_ms=%u report_ms=%u fired=%d\n",
		(unsigned long long)atomic64_read(&mp->m_mxfs_ailpin_refused_n),
		n,
		(unsigned long long)atomic64_read(&mp->m_mxfs_ailpin_clear_shutdown_n),
		(unsigned long long)atomic64_read(&mp->m_mxfs_ailpin_clear_slow_n),
		sum, (unsigned int)atomic_read(&mp->m_mxfs_ailpin_clear_max_ms),
		n ? sum / n : 0ULL,
		READ_ONCE(mxfs_ailpin_grace_ms),
		READ_ONCE(mxfs_ailpin_clear_report_ms),
		atomic_read(&mp->m_mxfs_ailpin_fired));
	if (atomic_read(&mp->m_mxfs_ailpin_fired))
		seq_printf(m, "pinned arm=%s agno=%u daddr=%lld ops=%s lsn=0x%llx age_ms=%u count=%u\n",
			mp->m_mxfs_ailpin_arm ? mp->m_mxfs_ailpin_arm : "?",
			mp->m_mxfs_ailpin_agno, (long long)mp->m_mxfs_ailpin_daddr,
			mp->m_mxfs_ailpin_ops ? mp->m_mxfs_ailpin_ops : "?",
			(unsigned long long)mp->m_mxfs_ailpin_lsn,
			mp->m_mxfs_ailpin_age_ms, mp->m_mxfs_ailpin_count);
	return 0;
}

/*
 * /sys/kernel/debug/mxfs/<dev>/acquire_degraded — every remote lock wait on
 * this mount that its master has stopped confirming (dlm.h, the acq[] comment
 * and the status-delivery contract).  A caller that cannot be failed keeps
 * waiting; this is where that wait is visible without taking the lock it is
 * waiting for.  Empty means nothing is degraded.  Reads only the requester's
 * own acquisition table under its spinlock: no I/O, no inode, no DLM call
 * that could itself block on the stalled resource.
 */
int
mxfs_acquire_degraded_show(
	struct seq_file		*m,
	void			*data)
{
	struct xfs_mount	*mp = m->private;
	struct mxfs_dlm_acq_state a;
	u64			now = mxfs_pal_time_ms();
	int			i;
	int			n = 0;

	if (!mp->m_mxfs_dlm)
		return 0;

	for (i = mxfs_v5_dlm_acq_degraded_iter(mp->m_mxfs_dlm, -1, &a);
	     i >= 0;
	     i = mxfs_v5_dlm_acq_degraded_iter(mp->m_mxfs_dlm, i, &a)) {
		u64 anchor = a.confirm_ms > a.first_ms ? a.confirm_ms : a.first_ms;

		if (!n++)
			seq_puts(m,
"DEGRADED_UNCONFIRMED - these lock waits have a live master that has stopped\n"
"confirming them.  Each is re-sent every second and the master answers a\n"
"queued request every time; none of these has been answered for the whole\n"
"bound.  The request is being lost between here and the master, or the\n"
"master's lock service is not running.  The waiting operation continues,\n"
"because it cannot be failed safely; this is a REPORT of that wait, not a\n"
"verdict on which node is at fault.\n\n");
		seq_printf(m,
"acq=%llu type=%u ino=%llu ag=%u mode=%u master=%u\n"
"  time     age_ms=%llu unanswered_ms=%llu degraded_for_ms=%llu\n"
"  status   resends=%u last_confirmed_attempt_ms_ago=%s%llu rejected=%u\n"
"  waiter   pid=%d\n",
			(unsigned long long)a.acq_seq, a.resource.type,
			(unsigned long long)a.resource.ino, a.resource.ag_number,
			a.mode, a.master,
			(unsigned long long)(now - a.first_ms),
			(unsigned long long)(now - anchor),
			(unsigned long long)(now - a.degraded_ms),
			a.retx,
			a.confirm_ms ? "" : "never:",
			(unsigned long long)(a.confirm_ms ? now - a.confirm_ms : 0),
			a.rejected, a.owner_pid);
		seq_puts(m,
"  ACTION   check that the master's mxfs lock service is running and that\n"
"           this node's connection to it carries requests (dmesg on both:\n"
"           P958-ACQ-DEGRADED here, P958-ACQ-RETX / P912-QACK there).  The\n"
"           wait clears itself the moment the master confirms or grants it\n"
"           (P958-ACQ-RECONFIRMED / P958-ACQ-DEGRADED-END).\n\n");
	}
	return 0;
}

/*
 * /sys/kernel/debug/mxfs/<dev>/alloc_witness (0.89.9): the ALLOCATION-COVERAGE
 * WITNESS behind the cold structural audit's release verdict (design-consult
 * ruling docs/rulings/audit-gate-allocation-coverage-witness.md; the counter
 * semantics are on the pag_mxfs_wit_* fields in xfs_ag.h).  One header line,
 * then one line per AG with THIS node's successful transitions since the
 * last clear.  A write of anything clears every AG's counters and bumps
 * `clears`, so a snapshot pair taken across a clear can be told from a
 * genuine delta.  `now_ns` is this node's wall clock at the read, for the
 * clock-offset bound the stress row measures per node; `fsid` is the
 * filesystem incarnation the counts belong to.  The six atomics of one AG
 * are read one after another: the snapshot is consistent when the row takes
 * it at a phase boundary with its workload quiesced, which is the only time
 * the row is allowed to take one.
 */
static int
mxfs_alloc_witness_show(
	struct seq_file		*m,
	void			*data)
{
	struct xfs_mount	*mp = m->private;
	struct xfs_perag	*pag = NULL;
	unsigned int		stride = 1;
	int			multi = 0;

	/*
	 * 0.89.10: the configured ownership the row checks every carve
	 * against — the same fold mxfs_ag_inode_owned (xfs_ialloc.c) applies:
	 * a node owns agno %% stride == slot %% stride, with stride the on-disk
	 * node count folded to the AG count, and no constraint (stride 1) on a
	 * single-node or non-clustered mount.  `relaxed` counts the RELAXED
	 * ownership-dropping passes since the last clear.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		multi = 1;
		stride = mp->m_mxfs_log_node_count;
		if (stride <= 1)
			stride = 1;
		if (mp->m_maxagi && stride > mp->m_maxagi)
			stride = mp->m_maxagi;
	}
	seq_printf(m, "alloc_witness fsid=%pU agcount=%u clears=%d now_ns=%llu "
		   "slot=%u stride=%u multi=%d relaxed=%llu\n",
		   &mp->m_sb.sb_uuid, mp->m_sb.sb_agcount,
		   atomic_read(&mp->m_mxfs_wit_clears),
		   (unsigned long long)ktime_get_real_ns(),
		   (unsigned int)mp->m_mxfs_node_slot, stride, multi,
		   (unsigned long long)atomic64_read(&mp->m_mxfs_wit_relaxed));
	while ((pag = xfs_perag_next(mp, pag))) {
		seq_printf(m,
			"ag=%u carves=%llu releases=%llu fino_ins=%llu fino_del=%llu "
			"carve_first_ns=%llu carve_last_ns=%llu\n",
			pag_agno(pag),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_carves),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_releases),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_fino_ins),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_fino_del),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_carve_first_ns),
			(unsigned long long)atomic64_read(&pag->pag_mxfs_wit_carve_last_ns));
	}
	return 0;
}

int
mxfs_alloc_witness_open(
	struct inode		*inode,
	struct file		*file)
{
	return single_open(file, mxfs_alloc_witness_show, inode->i_private);
}

ssize_t
mxfs_alloc_witness_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			len,
	loff_t			*ppos)
{
	struct seq_file		*m = file->private_data;
	struct xfs_mount	*mp = m->private;
	struct xfs_perag	*pag = NULL;

	while ((pag = xfs_perag_next(mp, pag))) {
		atomic64_set(&pag->pag_mxfs_wit_carves, 0);
		atomic64_set(&pag->pag_mxfs_wit_releases, 0);
		atomic64_set(&pag->pag_mxfs_wit_fino_ins, 0);
		atomic64_set(&pag->pag_mxfs_wit_fino_del, 0);
		atomic64_set(&pag->pag_mxfs_wit_carve_first_ns, 0);
		atomic64_set(&pag->pag_mxfs_wit_carve_last_ns, 0);
	}
	atomic64_set(&mp->m_mxfs_wit_relaxed, 0);
	atomic_inc(&mp->m_mxfs_wit_clears);
	return len;
}

/*
 * /sys/kernel/debug/mxfs/<dev>/alloc_witness_chunk (0.89.10): write an inode
 * number, read the inobt record that covers it, straight from the AGI and
 * inode btree of that AG on this node.  The witness row's reuse lifecycle
 * needs a live observation that a chunk it emptied is FULLY free before it
 * asserts a later create reused the chunk in place: an unlink is not a free
 * (inactivation is deferred), and the final platter cannot say what the chunk
 * looked like in between.  The lookup is the one xfs_iwalk makes, with no
 * transaction; the row only asks about chunks in this node's own AG.
 *     chunk ino=<n> agno=<a> agino=<i> startino=<s> count=<c> freecount=<f>
 *           holemask=0x<h> free=0x<mask>
 *     chunk ino=<n> ... norec=1              no record covers the inode
 *     chunk ino=<n> error=<errno>
 */
static int
mxfs_alloc_witness_chunk_show(
	struct seq_file		*m,
	void			*data)
{
	struct xfs_mount	*mp = m->private;
	xfs_ino_t		ino = READ_ONCE(mp->m_mxfs_wit_query_ino);
	xfs_agnumber_t		agno = XFS_INO_TO_AGNO(mp, ino);
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ino);
	struct xfs_perag	*pag;
	struct xfs_buf		*agbp = NULL;
	struct xfs_btree_cur	*cur;
	struct xfs_inobt_rec_incore rec = { 0 };
	int			stat = 0;
	int			error;

	if (!ino || agno >= mp->m_sb.sb_agcount) {
		seq_printf(m, "chunk ino=%llu error=%d\n",
			   (unsigned long long)ino, -EINVAL);
		return 0;
	}
	pag = xfs_perag_get(mp, agno);
	if (!pag) {
		seq_printf(m, "chunk ino=%llu error=%d\n",
			   (unsigned long long)ino, -ENOENT);
		return 0;
	}
	error = xfs_ialloc_read_agi(pag, NULL, 0, &agbp);
	if (error) {
		xfs_perag_put(pag);
		seq_printf(m, "chunk ino=%llu agno=%u error=%d\n",
			   (unsigned long long)ino, agno, error);
		return 0;
	}
	cur = xfs_inobt_init_cursor(pag, NULL, agbp);
	error = xfs_inobt_lookup(cur, agino, XFS_LOOKUP_LE, &stat);
	if (!error && stat)
		error = xfs_inobt_get_rec(cur, &rec, &stat);
	xfs_btree_del_cursor(cur, error);
	xfs_buf_relse(agbp);
	xfs_perag_put(pag);
	if (error) {
		seq_printf(m, "chunk ino=%llu agno=%u error=%d\n",
			   (unsigned long long)ino, agno, error);
		return 0;
	}
	if (!stat || agino < rec.ir_startino ||
	    agino >= rec.ir_startino + XFS_INODES_PER_CHUNK) {
		seq_printf(m, "chunk ino=%llu agno=%u agino=%u norec=1\n",
			   (unsigned long long)ino, agno, agino);
		return 0;
	}
	seq_printf(m, "chunk ino=%llu agno=%u agino=%u startino=%u count=%u "
		   "freecount=%u holemask=0x%04x free=0x%016llx\n",
		   (unsigned long long)ino, agno, agino, rec.ir_startino,
		   (unsigned int)rec.ir_count, (unsigned int)rec.ir_freecount,
		   (unsigned int)rec.ir_holemask,
		   (unsigned long long)rec.ir_free);
	return 0;
}

int
mxfs_alloc_witness_chunk_open(
	struct inode		*inode,
	struct file		*file)
{
	return single_open(file, mxfs_alloc_witness_chunk_show,
			   inode->i_private);
}

ssize_t
mxfs_alloc_witness_chunk_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			len,
	loff_t			*ppos)
{
	struct seq_file		*m = file->private_data;
	struct xfs_mount	*mp = m->private;
	unsigned long long	ino;
	int			error;

	error = kstrtoull_from_user(ubuf, len, 0, &ino);
	if (error)
		return error;
	WRITE_ONCE(mp->m_mxfs_wit_query_ino, (xfs_ino_t)ino);
	return len;
}

/*
 * 0.89.31: ask the LOGICAL UNIT RESET admission gate for its verdict.
 *
 * Write "<victim-node-id> <victim-key>" (the key in any base kstrtoull
 * accepts, 0 for "no named victim").  NOTHING IS ISSUED: the gate decides
 * admission and the decision lands in the kernel log as one
 * P306-LURESET-ADMIT line carrying every number it was made from.  The write's
 * own status is the verdict — 0 admitted, -EPERM refused, anything else means
 * the target could not be asked, which is never "clear".
 *
 * It is a write and not a read because a read that issues SCSI commands to
 * decide what to print is a surprise nobody should meet in a debugfs file.
 */
ssize_t
mxfs_dbg_lu_reset_admit_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			len,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	char			line[64];
	char			*p, *node_tok;
	unsigned long long	victim_key = 0;
	unsigned int		victim_node = 0;
	size_t			take = len;
	int			error;

	if (!mp || !mp->m_mxfs_dlm)
		return -ENODEV;
	if (take == 0)
		return 0;
	if (take > sizeof(line) - 1)
		take = sizeof(line) - 1;
	if (copy_from_user(line, ubuf, take))
		return -EFAULT;
	line[take] = '\0';
	p = strchr(line, '\n');
	if (p)
		*p = '\0';

	p = line;
	node_tok = strsep(&p, " \t");
	if (node_tok && node_tok[0] && kstrtouint(node_tok, 0, &victim_node))
		return -EINVAL;
	while (p && (*p == ' ' || *p == '\t'))
		p++;
	if (p && *p && kstrtoull(p, 0, &victim_key))
		return -EINVAL;

	error = mxfs_v5_dlm_lu_reset_admit_probe(mp->m_mxfs_dlm, victim_node,
						 (uint64_t)victim_key);
	if (error)
		return error;
	*ppos += len;
	return len;
}

/*
 * 0.89.32: ask the POST-RESET CONVERGENCE BARRIER for its verdict.
 *
 * Same argument shape as the admission trigger above, and it issues no reset
 * either: the barrier is what a node must establish AFTER one, and every part
 * of it is meaningful over a quiet LUN — the command path answers, the whole
 * admission assertion set is re-established against the target, the PR
 * generation is unchanged, and a heartbeat issued after the call lands while
 * the authority lease is still live.  So this arm is the control the refusal
 * arms need: on a healthy cluster it must HOLD, and a barrier that refused
 * everything would be indistinguishable from one that works.
 *
 * The write's status is the verdict — 0 the barrier holds and replay would be
 * allowed, -EPERM STOP, anything else the question could not be put.  The
 * P307-LURESET-PROBE, P307-LURESET-CONVERGE and P307-LURESET-BARRIER lines in
 * the kernel log carry the numbers each half was decided from.
 */
ssize_t
mxfs_dbg_lu_reset_barrier_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			len,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	char			line[64];
	char			*p, *node_tok;
	unsigned long long	victim_key = 0;
	unsigned int		victim_node = 0;
	size_t			take = len;
	int			error;

	if (!mp || !mp->m_mxfs_dlm)
		return -ENODEV;
	if (take == 0)
		return 0;
	if (take > sizeof(line) - 1)
		take = sizeof(line) - 1;
	if (copy_from_user(line, ubuf, take))
		return -EFAULT;
	line[take] = '\0';
	p = strchr(line, '\n');
	if (p)
		*p = '\0';

	p = line;
	node_tok = strsep(&p, " \t");
	if (node_tok && node_tok[0] && kstrtouint(node_tok, 0, &victim_node))
		return -EINVAL;
	while (p && (*p == ' ' || *p == '\t'))
		p++;
	if (p && *p && kstrtoull(p, 0, &victim_key))
		return -EINVAL;

	error = mxfs_v5_dlm_lu_reset_barrier_probe(mp->m_mxfs_dlm, victim_node,
						   (uint64_t)victim_key);
	if (error)
		return error;
	*ppos += len;
	return len;
}

/*
 * 0.89.33: run the WHOLE witnessed-LU-reset fence and report its verdict.
 *
 * Same argument shape as the two triggers above, and unlike them THIS ONE
 * ISSUES A REAL LOGICAL UNIT RESET when the admission gate admits it — that
 * is the operation the certificate rests on, and a probe that skipped it
 * would be measuring everything except the thing in question.  The gate is
 * what bounds the damage: it admits only when this initiator is the sole
 * registrant on the unit under an excluding reservation, so no other
 * initiator's registered work is there to be terminated.
 *
 * Nothing durable is minted: no intent is armed, so a certified run leaves
 * the platter untouched and the verdict is read out of the one
 * P308-LURESET-FENCE line, which carries the kind, the phase, all three
 * retire fields, the admission, the witness verdict, the barrier and the
 * audited kernel release.  The write's status is 0 when a certificate WOULD
 * have been minted and -EPERM when it would not; anything else means the
 * question could not be put at all.
 */
ssize_t
mxfs_dbg_lu_reset_fence_write(
	struct file		*file,
	const char __user	*ubuf,
	size_t			len,
	loff_t			*ppos)
{
	struct xfs_mount	*mp = file->private_data;
	char			line[64];
	char			*p, *node_tok;
	unsigned long long	victim_key = 0;
	unsigned int		victim_node = 0;
	size_t			take = len;
	int			error;

	if (!mp || !mp->m_mxfs_dlm)
		return -ENODEV;
	if (take == 0)
		return 0;
	if (take > sizeof(line) - 1)
		take = sizeof(line) - 1;
	if (copy_from_user(line, ubuf, take))
		return -EFAULT;
	line[take] = '\0';
	p = strchr(line, '\n');
	if (p)
		*p = '\0';

	p = line;
	node_tok = strsep(&p, " \t");
	if (node_tok && node_tok[0] && kstrtouint(node_tok, 0, &victim_node))
		return -EINVAL;
	while (p && (*p == ' ' || *p == '\t'))
		p++;
	if (p && *p && kstrtoull(p, 0, &victim_key))
		return -EINVAL;

	error = mxfs_v5_dlm_fence_by_lu_reset_probe(mp->m_mxfs_dlm, victim_node,
						    (uint64_t)victim_key);
	if (error)
		return error;
	*ppos += len;
	return len;
}
