/*
 * MXFS — Multinode XFS
 * Portable DLM engine
 *
 * The core distributed lock manager, running in portable C.
 * Manages the lock table, processes lock requests from the local
 * cache and from remote peers, enforces the 6-mode compatibility
 * matrix, and handles lock queuing, granting, conversion, and BAST.
 *
 * Ported from kernel/mxfs_dlm.c — kernel APIs replaced with PAL:
 *   rw_semaphore     -> mxfs_rwlock_t
 *   mutex            -> mxfs_mutex_t
 *   spinlock         -> mxfs_mutex_t
 *   completion       -> mxfs_cond_t + mxfs_mutex_t + done flag
 *   kmem_cache/kzalloc -> mxfs_pal_alloc
 *   ktime_get_ns     -> mxfs_pal_time_ms
 *   sort()           -> mxfs_pal_sort
 *   pr_info/etc      -> mxfs_pal_log
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "dlm.h"
#include "dlm_shared.h"
#include "tauth_ledger.h"
#include "dlm_user_compat.h"

#define MXFS_DLM_DEFAULT_BUCKETS  4096

/* owner of a ledger-imported shared holder whose heartbeat slot
 * resolves to no live node (blocks EX until the recovery purge). */
#define MXFS_DLM_NODE_UNKNOWN   ((mxfs_node_id_t)0xFFFFFFFFu)

/*
 * 0.75.91 TEST ONLY (D-...-0940): answer the next N shared-bit slot lookups
 * during a ledger page import as unresolvable, so the bit is imported as an
 * MXFS_DLM_NODE_UNKNOWN blocker.  That is what genuinely happens when a page
 * is imported a moment before the peer claims its heartbeat slot, and it
 * deadlocked both mounts on 1 lap in 4.  A race at that rate cannot be
 * verified by running laps that pass, so it is made to happen on demand.
 * Consumable count; 0 (default) = off.  Never set in production.
 */
static int mxfs_dl_inject_import_unresolvable;
module_param_named(dl_inject_import_unresolvable,
		   mxfs_dl_inject_import_unresolvable, int, 0644);
MODULE_PARM_DESC(dl_inject_import_unresolvable,
		 "TEST ONLY: import the next N shared holder bits as "
		 "unresolvable-slot blockers (0 = off)");

/*
 * TEST ONLY: black-hole this node's outbound LOCK_REQ for ONE inode.
 *
 * The acquire path's post-budget classifier keeps waiting whenever the party
 * it waits on is live, and on the TCP transport "live" is answered for a
 * REMOTE master by membership alone — the requester cannot read the master's
 * holder table, so it cannot tell "queued behind a holder that is draining"
 * from "this request is never going to be answered".  The second case has to
 * be produced on demand to find out what the node does in it: a request that
 * is never sent reaches a master that creates no queue entry and no grant and
 * replies to nothing, which is what a silently dropped request, a lost grant
 * reply, or a master-side wedge looks like from here.
 *
 * Filtered to a single inode number so that heartbeats, lease renewals,
 * membership traffic, releases, and every other resource's requests are
 * untouched — the peer must stay a healthy live member for the measurement to
 * mean anything.  Writable at 0644 so a harness arms it on ONE node at
 * runtime without reloading the module.  Never set in production.
 */
unsigned long long mxfs_dl_drop_lockreq_ino;
static atomic_t mxfs_dl_drop_lockreq_n = ATOMIC_INIT(0);
/*
 * The drop count is the harness's evidence that the target is remotely
 * mastered and that the fault fired during the armed read; the probe LINE
 * is not, because it prints only the first 8 drops and every 64th after
 * them.  A harness that counted lines chose no target on two laps (s585c2,
 * s585e) once a module load's print budget was spent, and chose one on a
 * third (s585d) only because a hit landed on n=64.  So the count is
 * readable (dl_drop_lockreq_n) and every write of the knob — arm or
 * disarm — restarts both the count and the print budget, which makes the
 * count per arm and the printed n=1 the first drop of THIS arm.
 */
static int dl_drop_lockreq_ino_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_ullong(val, kp);

	if (!rc)
		atomic_set(&mxfs_dl_drop_lockreq_n, 0);
	return rc;
}
static const struct kernel_param_ops dl_drop_lockreq_ino_ops = {
	.set = dl_drop_lockreq_ino_set,
	.get = param_get_ullong,
};
module_param_cb(dl_drop_lockreq_ino, &dl_drop_lockreq_ino_ops,
		&mxfs_dl_drop_lockreq_ino, 0644);
MODULE_PARM_DESC(dl_drop_lockreq_ino,
		 "TEST ONLY: do not send this inode's LOCK_REQ to its remote "
		 "master; let the request time out unanswered (0 = off); "
		 "writing it resets dl_drop_lockreq_n");
module_param_named(dl_drop_lockreq_n, mxfs_dl_drop_lockreq_n.counter, int, 0444);
MODULE_PARM_DESC(dl_drop_lockreq_n,
		 "TEST ONLY: requests dropped since dl_drop_lockreq_ino was last written");

/*
 * TEST ONLY (D-...-0960): the two defences a request meets on a ledger page
 * whose dead authority a bootstrap node is taking over, made switchable so
 * each can be measured alone.  dl_no_ondemand_takeover=1 stops the bootstrap
 * taking a page over for the request that needs it (the request then waits,
 * progress-aware, for the bulk pass to reach the page).  dl_takeover_pause_ms
 * holds the bulk passes between pages for that long (slept in 100 ms slices,
 * ended by the mount leaving or the knob being cleared), so the progress a
 * parked request watches can be made to stall on demand.  Never set in
 * production.
 */
static int mxfs_dl_no_ondemand_takeover;
module_param_named(dl_no_ondemand_takeover, mxfs_dl_no_ondemand_takeover, int, 0644);
MODULE_PARM_DESC(dl_no_ondemand_takeover,
		 "TEST ONLY: 1 = the bootstrap node never takes a page over on "
		 "demand for a request; requests wait for the bulk pass (0 = off)");
static unsigned int mxfs_dl_takeover_pause_ms;
module_param_named(dl_takeover_pause_ms, mxfs_dl_takeover_pause_ms, uint, 0644);

/*
 * TEST ONLY (0.89.69, D-A-GRANT-COMPLETING-A-PENDING-ENTRY-RACES-THE-WAITERS-
 * TIMEOUT-FREE): hold a grant's completion of a pending entry for this long
 * between finding the entry and completing it.  On the ordering this build
 * replaces, that gap was the use-after-free window — the waiter's attempt
 * times out at MXFS_LOCK_ACQUIRE_WAIT_MS, removes the entry and frees it, and
 * the completion then locks a destroyed mutex.  On this build the gap is
 * spent holding the pending bucket lock, so the waiter's remove waits behind
 * the completion and finds its grant (P-PENDING-LATE-GRANT-KEPT).  Never set
 * in production.
 */
static unsigned int mxfs_dl_pending_complete_delay_ms;
module_param_named(dl_pending_complete_delay_ms, mxfs_dl_pending_complete_delay_ms, uint, 0644);
MODULE_PARM_DESC(dl_pending_complete_delay_ms,
		 "TEST ONLY: hold a grant's completion of a pending entry this many ms "
		 "after the lookup (0 = off)");
static atomic_t mxfs_dl_pending_late_kept = ATOMIC_INIT(0);
module_param_named(dl_pending_late_kept_n, mxfs_dl_pending_late_kept.counter, int, 0444);
MODULE_PARM_DESC(dl_pending_late_kept_n,
		 "grants that completed a pending entry after its waiter's attempt "
		 "had timed out and were kept by that waiter (read-only)");

/*
 * D-0962: run a BULK authority-takeover pass without its four-lines-a-page
 * logging.  One 7984-page pass emitted 31979 lines from inside the recovery
 * completion the whole cluster waits on, on nodes whose kernel log also goes
 * to a serial console and a netconsole listener.  Default 0 is exactly the
 * behaviour measured at ~13 ms a page, so this build's two arms differ only
 * by this knob and a pass can be timed against itself rather than against
 * another build.
 */
static unsigned int mxfs_dl_takeover_quiet;
module_param_named(dl_takeover_quiet, mxfs_dl_takeover_quiet, uint, 0644);
MODULE_PARM_DESC(dl_takeover_quiet,
    "1 = a bulk authority-takeover pass logs only its summary, not four lines per page (0 = every page, the default and the measured behaviour)");
MODULE_PARM_DESC(dl_takeover_pause_ms,
		 "TEST ONLY: hold a bulk page-takeover pass this long between "
		 "pages (0 = off)");

/*
 * TEST ONLY (dl_acq_gap_ino / dl_acq_gap_ms): after an attempt of this
 * inode's remote acquire times out, hold the requester for dl_acq_gap_ms
 * before it returns to its caller — with NO pending entry registered.  The
 * gap between two attempts is ordinarily 50 ms between descents and up to
 * five seconds of classifier backoff between restarts; widening it makes a
 * holder's release land in it predictably, which is the shape the
 * between-attempt grant adoption exists for.  Must stay under the
 * acquisition table's idle retirement (MXFS_DLM_ACQ_IDLE_MS) or the wait's
 * own record is retired under it.  Never set in production.
 */
unsigned long long mxfs_dl_acq_gap_ino;
module_param_named(dl_acq_gap_ino, mxfs_dl_acq_gap_ino, ullong, 0644);
MODULE_PARM_DESC(dl_acq_gap_ino,
		 "TEST ONLY: after a timed-out attempt of this inode's remote "
		 "acquire, hold the requester dl_acq_gap_ms with no pending "
		 "entry (0 = off)");
unsigned int mxfs_dl_acq_gap_ms;
module_param_named(dl_acq_gap_ms, mxfs_dl_acq_gap_ms, uint, 0644);
MODULE_PARM_DESC(dl_acq_gap_ms, "TEST ONLY: the gap dl_acq_gap_ino inserts, ms");
static atomic_t mxfs_dl_acq_gap_n = ATOMIC_INIT(0);

/* TEST ONLY (dl_no_cancel): abandon a wait WITHOUT telling the master — the
 * behaviour before LOCK_CANCEL existed, kept as the control arm so a lap can
 * show what the cancel changes on one build.  Never set in production. */
unsigned int mxfs_dl_no_cancel;
module_param_named(dl_no_cancel, mxfs_dl_no_cancel, uint, 0644);
MODULE_PARM_DESC(dl_no_cancel,
		 "TEST ONLY: 1 = abandon a lock wait without sending LOCK_CANCEL "
		 "(the pre-0.84.1 behaviour, as a control)");

/*
 * TEST ONLY (dl_stale_resend_ino, 0.84.13): the shape s594c caught by
 * chance — a re-send of a LOCK_REQ still in flight when its grant went out,
 * processed by the master AFTER the requester consumed the grant and
 * released it.  The requester keeps a copy of the last LOCK_REQ it sent for
 * this inode and sends that copy ONCE, unchanged, right after its next
 * LOCK_RELEASE of the inode; the master then meets exactly the stale
 * re-send.  dl_stale_resend_n counts the copies sent since the knob was
 * last written.  dl_no_consumed_tomb=1 on the MASTER disables the consumed
 * tombstone so the pre-0.84.13 outcome (a fresh queue entry, a second
 * grant, the requester's bounce) can be measured on the same build.  Never
 * set in production.
 */
unsigned long long mxfs_dl_stale_resend_ino;
static atomic_t mxfs_dl_stale_resend_n = ATOMIC_INIT(0);
static int dl_stale_resend_ino_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_ullong(val, kp);

	if (!rc)
		atomic_set(&mxfs_dl_stale_resend_n, 0);
	return rc;
}
static const struct kernel_param_ops dl_stale_resend_ino_ops = {
	.set = dl_stale_resend_ino_set,
	.get = param_get_ullong,
};
module_param_cb(dl_stale_resend_ino, &dl_stale_resend_ino_ops,
		&mxfs_dl_stale_resend_ino, 0644);
MODULE_PARM_DESC(dl_stale_resend_ino,
		 "TEST ONLY: re-send this inode's last LOCK_REQ once, after its "
		 "next LOCK_RELEASE (0 = off); writing it resets dl_stale_resend_n");
module_param_named(dl_stale_resend_n, mxfs_dl_stale_resend_n.counter, int, 0444);
MODULE_PARM_DESC(dl_stale_resend_n,
		 "TEST ONLY: stale re-sends issued since dl_stale_resend_ino was last written");
unsigned int mxfs_dl_no_consumed_tomb;
module_param_named(dl_no_consumed_tomb, mxfs_dl_no_consumed_tomb, uint, 0644);
MODULE_PARM_DESC(dl_no_consumed_tomb,
		 "TEST ONLY: 1 = as master, do not refuse a re-send of a consumed "
		 "acquisition (the pre-0.84.13 behaviour, as a control)");

/* TEST ONLY (dl_drop_grant_ino): see send_grant. */
unsigned long long mxfs_dl_drop_grant_ino;
static atomic_t mxfs_dl_drop_grant_n = ATOMIC_INIT(0);
/* Same shape as dl_drop_lockreq_ino: the count is readable and per arm. */
static int dl_drop_grant_ino_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_ullong(val, kp);

	if (!rc)
		atomic_set(&mxfs_dl_drop_grant_n, 0);
	return rc;
}
static const struct kernel_param_ops dl_drop_grant_ino_ops = {
	.set = dl_drop_grant_ino_set,
	.get = param_get_ullong,
};
module_param_cb(dl_drop_grant_ino, &dl_drop_grant_ino_ops,
		&mxfs_dl_drop_grant_ino, 0644);
MODULE_PARM_DESC(dl_drop_grant_ino,
		 "TEST ONLY: as master, record but never deliver a LOCK_GRANT "
		 "for this inode (0 = off); writing it resets dl_drop_grant_n");
module_param_named(dl_drop_grant_n, mxfs_dl_drop_grant_n.counter, int, 0444);
MODULE_PARM_DESC(dl_drop_grant_n,
		 "TEST ONLY: grants dropped since dl_drop_grant_ino was last written");

/*
 * dbg_probe_ino: an inode the master-side blocking-notification probe
 * (P7S-BAST-FIRE) and the holder-side one (P7B-BASTNOTIFY) print for
 * whatever its number.  Both were written for the hot directories of a
 * fresh filesystem and print only for inode numbers up to 256; on an aged
 * filesystem a harness that establishes which node masters an inode from
 * which node logs the notification read every candidate as undetermined
 * (s585a: candidates 3713..3720, nothing printed, lap aborted).  A harness
 * names the inode it is measuring here.  0 = only the low inodes print.
 */
unsigned long long mxfs_dbg_probe_ino;
module_param_named(dbg_probe_ino, mxfs_dbg_probe_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_probe_ino,
		 "inode the P7S-BAST-FIRE / P7B-BASTNOTIFY probes also print "
		 "for, whatever its number (0 = only inodes <= 256)");

/*
 * How long a wait on a REMOTE master may go without an accepted status
 * confirmation before it is marked DEGRADED_UNCONFIRMED (see the acq[] comment
 * and the status-delivery contract in dlm.h).  The default is H = N x P + D:
 * thirty consecutive one-second status opportunities unanswered plus the
 * fifteen-second response allowance.  A master that keeps confirming a long
 * queue never reaches it, because every accepted confirmation moves the
 * anchor forward; nothing else does — not a re-send, not a socket, not a
 * heartbeat.  Overrides the derivation when set; 0 disables the state.
 */
unsigned int mxfs_dlm_acq_degrade_ms =
    MXFS_DLM_ACQ_STATUS_MISSES * MXFS_LOCK_ACQUIRE_WAIT_MS +
    MXFS_DLM_ACQ_STATUS_LATENCY_MS;
module_param_named(acq_degrade_ms, mxfs_dlm_acq_degrade_ms, uint, 0644);
MODULE_PARM_DESC(acq_degrade_ms,
		 "ms a remote lock wait may go unreceipted before it is "
		 "reported DEGRADED (0 = never)");

/* holder-side release ACK retry cadence / give-up. */
#define MXFS_DLM_RELEASE_RETRY_MS   1000
#define MXFS_DLM_RELEASE_MAX_SENDS  10

/* Internal retry sentinel: membership changed, caller should retry.
 * This value is never propagated to external callers — the retry
 * loop in mxfs_dlm_lock() catches it and re-attempts the lock. */
#define MXFS_DLM_RETRY  (-1000)
/*
 * 0.84.5 (D-...-0960): the page the request needs is under a dead authority
 * a live bootstrap node is taking over.  Like MXFS_DLM_RETRY it never leaves
 * the engine, but the loop in mxfs_dlm_lock_retries treats it differently:
 * while the bootstrap's takeover count advances the retry budget is not
 * consumed, and MXFS_DLM_TRANSITION_STALL_MS without an advance ends the
 * wait with -EREMCHG — a retryable failure the caller classifies, never a
 * membership escalation.
 */
#define MXFS_DLM_RETRY_TRANSITION       (-1001)
#define MXFS_DLM_TRANSITION_STALL_MS    30000

/* Compatibility matrix + resource hash/equal: lifted to dlm_shared.c
 * (§11 step 3) — one copy shared with dlm_caw.c and the NET2 lock
 * plane. */

static const char * const lock_mode_names[] = {
	"NL", "CR", "CW", "PR", "PW", "EX"
};

static const char * const lock_state_names[] = {
	"UNLOCKED", "WAITING", "GRANTED", "CONVERTING", "BLOCKED",
	"PENDING_DURABLE", "PENDING_RELEASE"
};

/*
 * (step 3d): who counts as a HOLDER in a compatibility decision.
 * GRANTED / CONVERTING as before; PENDING_DURABLE (decided, ledger commit
 * in flight) and PENDING_RELEASE (released, retirement in flight) both
 * block new arrivals — the second only until its transition commits, so
 * that no grant is ever decided over a record the ledger still shows
 * ACTIVE for another holder.  Successor selection (promote_waiters) is the
 * one place a PENDING_RELEASE holder is ignored.
 */
static inline bool lk_is_holder(const struct mxfs_lock *lk)
{
	return lk->state == MXFS_LSTATE_GRANTED ||
	       lk->state == MXFS_LSTATE_PENDING_DURABLE ||
	       lk->state == MXFS_LSTATE_PENDING_RELEASE;
}

static inline bool lk_is_live_holder(const struct mxfs_lock *lk)
{
	return lk->state == MXFS_LSTATE_GRANTED ||
	       lk->state == MXFS_LSTATE_PENDING_DURABLE;
}

static inline const char *mode_name(uint8_t mode)
{
	if (mode < MXFS_LOCK_MODE_COUNT)
		return lock_mode_names[mode];
	return "??";
}

/*
 * sess-tcp: master lock-table entry-lifecycle trace (P-LKT) for the proven
 * tcp_dlm_scaling DOUBLE-GRANT.  Gated behind the lightweight mxfs.lockwr
 * param (kernel only; user-mode dlm builds compile it out).  Logs INODE
 * resource grant inserts and every entry removal so a spurious removal that
 * lets two nodes hold dir-EX is visible.
 */
#ifdef __KERNEL__
extern int mxfs_lockwr_enabled;
#define lockwr_on() (unlikely(mxfs_lockwr_enabled))
#define dlm_cur_comm() (current->comm)
#else
#define lockwr_on() (0)
#define dlm_cur_comm() "user"
#endif

/*
 * membership-settle gate.  mxfs_memb_settle_ms is the window (ms) for
 * which EX acquires are frozen after the active-node set changes.  Defined as a
 * module_param in v5_mount.c (kernel); user-mode builds disable the gate.
 *
 * ROOT (PROVEN, instrumented): during 8-node cluster FORMATION the membership ramps
 * 1->8 and nodes briefly hold DIVERGENT views (P-STALEMASTER-GRANT fired at
 * active_count=5 and =6, t=47s, on a fresh-boot run) -> inconsistent
 * mastership -> two nodes grant EX for the same dir -> mass dir corruption
 * (readdir=0/8 catastrophic).  Freezing EX acquires until the local view has
 * been stable for the settle window means every node defers its EX work until
 * membership has globally converged (all nodes observe the final set within
 * ~discovery-interval of each other, well under the window), so masters are
 * computed consistently and no split-brain EX is granted.  Steady-state has no
 * membership change, so the gate never fires (zero perf impact); combined with
 * the deferred-TCP-death fix (transient flaps no longer mutate membership) the
 * gate fires only on real formation / death events.
 */
#ifdef __KERNEL__
extern int mxfs_memb_settle_ms;
extern int mxfs_tauth_import_residue_release;
extern int mxfs_depart_wire_release;
#else
#define mxfs_memb_settle_ms 0
#define mxfs_tauth_import_residue_release 1
#define mxfs_depart_wire_release 1
#endif

/* Max time (ms) a single EX acquire will block waiting for membership to
 * settle — a backstop so pathological continuous churn cannot wedge a thread
 * forever (it falls through and the normal grant/retry path runs). */
#define MXFS_DLM_SETTLE_MAX_WAIT_MS 60000

/* v0.11.78 (D7): positive convergence proof.  TRUE iff every node in my
 * current active view has reported (via the lease beacon's piggybacked view
 * signature, ~500ms cadence) the SAME {count,hash} as mine, received AFTER
 * my last membership change.  Equal signatures over the sorted member list
 * mean every confirmer computes the identical nodes[hash%count] mastery
 * mapping — the exact property the wall-clock settle window approximates.
 * Runs only inside the (rare) settle window, so the mutex is off the hot
 * path.  A node whose beacons we cannot see keeps this FALSE and the
 * wall-clock fallback below behaves exactly as before. */
static bool dlm_view_confirmed(struct mxfs_dlm_ctx *ctx)
{
	bool ok = true;
	int i, j;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	if (ctx->my_view_hash == 0 || ctx->active_nodes.count <= 1) {
		mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
		return false;
	}
	for (i = 0; i < ctx->active_nodes.count && ok; i++) {
		mxfs_node_id_t n = ctx->active_nodes.nodes[i];
		bool found = false;

		if (n == ctx->local_node)
			continue;
		for (j = 0; j < MXFS_MAX_NODES; j++) {
			if (ctx->peer_views[j].node_id != n)
				continue;
			found = (ctx->peer_views[j].hash == ctx->my_view_hash &&
				 ctx->peer_views[j].count == ctx->my_view_count &&
				 ctx->peer_views[j].rx_ms >= ctx->last_memb_change_ms);
			break;
		}
		if (!found)
			ok = false;
	}
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return ok;
}

/*
 * 0.83.4 (D-0959): a member that IS beaconing since our last view change but
 * with a DIFFERENT view is alive and has not finished its own transition --
 * for a first join, that is the incumbent still draining and installing its
 * two-node view (its beacon carries the new view only after its prepare
 * succeeded).  Such a member is positive evidence that admission is not yet
 * safe, so the wall-clock settle window must not open the gate over it.  A
 * member that has not beaconed at all since our change proves nothing either
 * way and keeps the wall-clock behaviour below (the lease declares a silent
 * peer dead; that is a membership change and a new window).
 */
static bool dlm_view_pending_live(struct mxfs_dlm_ctx *ctx)
{
	bool pending = false;
	int i, j;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	if (ctx->my_view_hash == 0 || ctx->active_nodes.count <= 1) {
		mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
		return false;
	}
	for (i = 0; i < ctx->active_nodes.count && !pending; i++) {
		mxfs_node_id_t n = ctx->active_nodes.nodes[i];

		if (n == ctx->local_node)
			continue;
		for (j = 0; j < MXFS_MAX_NODES; j++) {
			if (ctx->peer_views[j].node_id != n)
				continue;
			if (ctx->peer_views[j].rx_ms >= ctx->last_memb_change_ms &&
			    (ctx->peer_views[j].hash != ctx->my_view_hash ||
			     ctx->peer_views[j].count != ctx->my_view_count))
				pending = true;
			break;
		}
	}
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return pending;
}

static inline bool dlm_membership_settling(struct mxfs_dlm_ctx *ctx)
{
	uint64_t since;
	if (mxfs_memb_settle_ms <= 0 || ctx->last_memb_change_ms == 0)
		return false;
	if (ctx->active_nodes.count <= 1)
		return false;   /* single node: mastership is trivially consistent */
	since = mxfs_pal_time_ms() - ctx->last_memb_change_ms;
	if (since >= (uint64_t)mxfs_memb_settle_ms) {
		/*
		 * 0.83.4 (D-0959): the window has elapsed, but a live member is
		 * still reporting a different view -- it has not admitted this
		 * membership yet.  Stay closed: the timer approximates
		 * convergence, and this is direct evidence against it.
		 */
		return dlm_view_pending_live(ctx) && !dlm_view_confirmed(ctx);
	}
	/* Inside the wall-clock window: a positive convergence proof ends the
	 * freeze early (v0.11.78 D7 — the 20s window was eating every first
	 * EX after any membership event, incl. a joiner's mount root-EX). */
	return !dlm_view_confirmed(ctx);
}

uint64_t mxfs_dlm_get_view_sig(struct mxfs_dlm_ctx *ctx, uint32_t *count)
{
	uint64_t h;

	if (!ctx) {
		if (count)
			*count = 0;
		return 0;
	}
	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	if (count)
		*count = ctx->my_view_count;
	h = ctx->my_view_hash;
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return h;
}

void mxfs_dlm_report_peer_view(struct mxfs_dlm_ctx *ctx,
			       mxfs_node_id_t node,
			       uint32_t count, uint64_t hash)
{
	int i, free_slot = -1;

	/*
	 * 0.84.8 (D-...-0960, measured s592e): a zero {count, hash} is a real
	 * report — the peer has installed no multi-node view.  For a joiner it
	 * is the incumbent saying "not admitted yet", and dlm_view_pending_live
	 * must see it: with the report dropped the settle gate had nothing
	 * against the wall clock, opened unconfirmed at 20 s, and the joiner's
	 * first cluster acquires were deferred by the incumbent's page handler
	 * (view mismatch) until every retry budget was gone and the mount was
	 * refused — 55 s into a join the incumbent was still preparing.
	 */
	if (!ctx || !node)
		return;
	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		if (ctx->peer_views[i].node_id == node)
			break;
		if (free_slot < 0 && ctx->peer_views[i].node_id == 0)
			free_slot = i;
	}
	if (i == MXFS_MAX_NODES) {
		if (free_slot < 0) {
			mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
			return;
		}
		i = free_slot;
		ctx->peer_views[i].node_id = node;
	}
	ctx->peer_views[i].count = count;
	ctx->peer_views[i].hash = hash;
	ctx->peer_views[i].rx_ms = mxfs_pal_time_ms();
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
}

/*
 * sess-tcp: LOCK-FREE master lock-table entry-lifecycle ring for the proven
 * tcp_dlm_scaling DOUBLE-GRANT.  Records {ts, action, ino, owner, mode} into a
 * fixed in-memory ring with NO printk in the hot path — printk (P-LKT / instr /
 * dirwr) PERTURBS the tight grant/release race and HIDES it (proven 6/6 pass
 * with mxfs.lockwr=1 printk).  All P_LKT() call sites already hold
 * ctx->table_rwlock (grant insert / remove / release), so a plain ring write is
 * safe without new locking; we use an atomic index only to be defensive.
 * Dump the ring post-mortem (after the leftover is observed) via the lktdump
 * param.  Recording is gated on mxfs.lockwr so default builds pay nothing.
 */
struct mxfs_lkt_ev {
	uint64_t        seq;        /* global monotonic event order (primary) */
	uint64_t        ts_ms;      /* mxfs_pal_time_ms (coarse, cross-node-ish) */
	uint64_t        ino;
	const char      *act;
	uint32_t        owner;
	uint8_t         mode;
	uint8_t         rtype;
};
#define MXFS_LKT_RING_SZ 16384          /* power of two */
#define MXFS_LKT_RING_MASK (MXFS_LKT_RING_SZ - 1)
static struct mxfs_lkt_ev mxfs_lkt_ring[MXFS_LKT_RING_SZ];
/* Plain counter: EVERY P_LKT() call site already holds ctx->table_rwlock
 * (grant insert / removal / release), so increments are serialized.  The dump
 * is post-mortem (churn stopped) so it needs no lock. */
static uint64_t mxfs_lkt_seq;

static inline void mxfs_lkt_record(const char *act,
				   const struct mxfs_resource_id *res,
				   uint32_t owner, uint8_t mode)
{
	uint64_t gseq;
	struct mxfs_lkt_ev *e;

	if (!lockwr_on() || !res || res->type != MXFS_LTYPE_INODE)
		return;
	/* optional single-inode filter to keep the shared dir's cross-node
	 * events from being evicted by the child-inode GRANT-LOCAL flood. */
	{
		extern unsigned long long mxfs_lkt_ino;
		if (mxfs_lkt_ino && res->ino != mxfs_lkt_ino)
			return;
	}
	gseq = ++mxfs_lkt_seq;
	e = &mxfs_lkt_ring[(gseq - 1) & MXFS_LKT_RING_MASK];
	e->seq   = gseq;
	e->ts_ms = mxfs_pal_time_ms();
	e->ino   = res->ino;
	e->act   = act;
	e->owner = owner;
	e->mode  = mode;
	e->rtype = res->type;
}

/* Post-mortem dump of the recorded events for one inode (or all if ino==0).
 * Runs AFTER the race on explicit trigger (lktdump param), so logging here
 * does not perturb the timing.  Uses mxfs_pal_log per dlm.c convention. */
void mxfs_dlm_lkt_dump(uint64_t want_ino)
{
	uint64_t cur = mxfs_lkt_seq;
	uint64_t n = cur < MXFS_LKT_RING_SZ ? cur : MXFS_LKT_RING_SZ;
	uint64_t i;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-LKT-DUMP begin ino=%llu total_events=%llu",
		     (unsigned long long)want_ino, (unsigned long long)cur);
	for (i = 0; i < n; i++) {
		struct mxfs_lkt_ev *e =
		    &mxfs_lkt_ring[(cur - n + i) & MXFS_LKT_RING_MASK];

		if (want_ino && e->ino != want_ino)
			continue;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			 "mxfs: P-LKT seq=%llu ts_ms=%llu %s ino=%llu owner=%u mode=%s",
			 (unsigned long long)e->seq,
			 (unsigned long long)e->ts_ms,
			 e->act ? e->act : "?",
			 (unsigned long long)e->ino, e->owner,
			 e->mode < MXFS_LOCK_MODE_COUNT ?
			     lock_mode_names[e->mode] : "??");
	}
	mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: P-LKT-DUMP end ino=%llu",
		     (unsigned long long)want_ino);
}

#define P_LKT(act, res, own, md) mxfs_lkt_record((act), (res), (own), (md))

static inline const char *state_name(uint8_t state)
{
	if (state <= MXFS_LSTATE_PENDING_RELEASE)
		return lock_state_names[state];
	return "??";
}

/* resource_hash_raw / resource_equal live in dlm_shared.c (step-3 lift). */

static uint32_t resource_hash(const struct mxfs_resource_id *res,
			      uint32_t bucket_count)
{
	return resource_hash_raw(res) % bucket_count;
}

/* ─── Pending remote request hash helpers ─── */

static uint32_t pending_hash(const struct mxfs_resource_id *res)
{
	return resource_hash_raw(res) & (MXFS_DLM_PENDING_SIZE - 1);
}

/* ─── Lock allocation ─── */

static struct mxfs_lock *lock_alloc(const struct mxfs_resource_id *resource,
				    mxfs_node_id_t owner,
				    uint8_t mode, uint8_t state, uint32_t flags)
{
	struct mxfs_lock *lk;

	lk = mxfs_pal_alloc(sizeof(*lk));
	if (!lk)
		return NULL;

	lk->resource = *resource;
	lk->owner = owner;
	lk->mode = mode;
	lk->state = state;
	lk->flags = flags;
	lk->queued_at = mxfs_pal_time_ms();
	if (state == MXFS_LSTATE_GRANTED)
		lk->granted_at = lk->queued_at;
	lk->grant_gen = 0;
	lk->acq_seq = 0;
	lk->acq_last_ms = lk->queued_at;
	lk->acq_bast_ms = 0;
	lk->acq_retx = 0;
	lk->handoff = false;   /* set true only by dg_grant_ex on handoff */
	lk->next = NULL;
	lk->work_next = NULL;
	lk->pend_waiter = NULL;
	/* POINTER-LIFECYCLE trace: run19 caught the -ETIMEDOUT
	 * lock_free(newlk) freeing a REMOTE holder's GRANTED entry (owner and
	 * state at free time belonged to test5's live EX gen 8210, yet the
	 * pointer matched OUR local WAITING newlk) -> live holder silently
	 * dropped from the table -> immediate re-grant -> concurrent EX ->
	 * stale-base RMW dirent loss.  Trace every alloc/free with %px for
	 * storm-range inodes so the alias/UAF chain is directly visible. */
	if (resource->type == MXFS_LTYPE_INODE && resource->ino <= 256) {
		static atomic_t p4l_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p4l_n) <= 400000)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P4L-ALLOC ino=%llu ptr=%px owner=%u mode=%u state=%u",
				     (unsigned long long)resource->ino, lk,
				     (unsigned)owner, (unsigned)mode, (unsigned)state);
	}
	return lk;
}

static void lock_free(struct mxfs_lock *lk)
{
	/* PHANTOM-EX probe: catch a GRANTED inode grant being FREED.
	 * The proven dir_reuse loss = a dir modify under i_dlm_mode=EX while the
	 * local DLM entry is gone (held=0).  bast_process couples its free with
	 * i_dlm_mode=NL; any OTHER path that frees our GRANTED entry leaves the XFS
	 * cached EX phantom.  Log ino + owner + mode + return address so the caller
	 * (which lock_free site) is identified and correlated with a P51-PHANTOM. */
	if (lk && lk->state == MXFS_LSTATE_GRANTED &&
	    lk->resource.type == MXFS_LTYPE_INODE &&
	    lk->resource.ino <= 256 && lk->mode >= MXFS_LOCK_EX)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P52-GRANT-FREE ino=%llu owner=%u mode=%u ret=%pS",
			     (unsigned long long)lk->resource.ino,
			     (unsigned)lk->owner, (unsigned)lk->mode,
			     __builtin_return_address(0));
	/* pointer-lifecycle trace, ALL states (see lock_alloc). */
	if (lk && lk->resource.type == MXFS_LTYPE_INODE &&
	    lk->resource.ino <= 256) {
		static atomic_t p4f_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p4f_n) <= 400000)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P4L-FREE ino=%llu ptr=%px owner=%u mode=%u state=%u gen=%u ret=%pS",
				     (unsigned long long)lk->resource.ino, lk,
				     (unsigned)lk->owner, (unsigned)lk->mode,
				     (unsigned)lk->state, lk->grant_gen,
				     __builtin_return_address(0));
	}
	mxfs_pal_free(lk);
}

/* ─── Pending entry helpers ─── */

static struct mxfs_dlm_pending *pending_alloc(
    const struct mxfs_resource_id *resource)
{
	struct mxfs_dlm_pending *p;

	p = mxfs_pal_alloc(sizeof(*p));
	if (!p)
		return NULL;

	p->resource = *resource;
	p->lock = mxfs_pal_mutex_create();
	p->cond = mxfs_pal_cond_create();
	p->done = false;
	p->granted_mode = MXFS_LOCK_NL;
	p->status = 0;
	p->request_epoch = 0;
	p->next = NULL;

	if (!p->lock || !p->cond) {
		if (p->lock) mxfs_pal_mutex_destroy(p->lock);
		if (p->cond) mxfs_pal_cond_destroy(p->cond);
		mxfs_pal_free(p);
		return NULL;
	}

	return p;
}

static void pending_free(struct mxfs_dlm_pending *p)
{
	if (!p)
		return;
	if (p->lock) mxfs_pal_mutex_destroy(p->lock);
	if (p->cond) mxfs_pal_cond_destroy(p->cond);
	mxfs_pal_free(p);
}

/* Signal a pending entry that its request is done */
static void pending_complete(struct mxfs_dlm_pending *p,
			     uint8_t mode, int status)
{
	mxfs_pal_mutex_lock(p->lock);
	p->granted_mode = mode;
	p->status = status;
	p->done = true;
	mxfs_pal_cond_signal(p->cond);
	mxfs_pal_mutex_unlock(p->lock);
}

/* Wait for a pending entry to be completed with timeout */
static int pending_wait(struct mxfs_dlm_pending *p, uint64_t timeout_ms)
{
	int ret = 0;

	mxfs_pal_mutex_lock(p->lock);
	while (!p->done) {
		ret = mxfs_pal_cond_timedwait(p->cond, p->lock, timeout_ms);
		if (ret == -ETIMEDOUT)
			break;
	}
	mxfs_pal_mutex_unlock(p->lock);

	return p->done ? 0 : ret;
}

/* Insert a pending entry into the hash table */
static void pending_insert(struct mxfs_dlm_ctx *ctx,
			   struct mxfs_dlm_pending *p)
{
	uint32_t ph = pending_hash(&p->resource);

	mxfs_pal_mutex_lock(ctx->pending_lock);
	p->next = ctx->pending_buckets[ph];
	ctx->pending_buckets[ph] = p;
	mxfs_pal_mutex_unlock(ctx->pending_lock);
}

/* Remove a pending entry from the hash table */
static void pending_remove(struct mxfs_dlm_ctx *ctx,
			   struct mxfs_dlm_pending *p)
{
	uint32_t ph = pending_hash(&p->resource);

	mxfs_pal_mutex_lock(ctx->pending_lock);
	if (ctx->pending_buckets[ph] == p) {
		ctx->pending_buckets[ph] = p->next;
	} else {
		struct mxfs_dlm_pending *cur;

		for (cur = ctx->pending_buckets[ph]; cur; cur = cur->next) {
			if (cur->next == p) {
				cur->next = p->next;
				break;
			}
		}
	}
	mxfs_pal_mutex_unlock(ctx->pending_lock);
}

/* Find and complete a pending entry for a resource.
 *
 * epoch parameter: if non-zero, only match a pending entry whose
 * request_epoch matches. This filters out stale grants from a
 * previous epoch's master that arrive after a membership change
 * caused the requester to retry with a new master (Bug 67).
 * Internal callers (promote_waiters, purge_node, etc.) pass 0
 * to match any pending entry regardless of epoch. */
static bool pending_signal_resource(struct mxfs_dlm_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    uint8_t mode, int status,
				    mxfs_epoch_t epoch)
{
	uint32_t ph = pending_hash(resource);
	struct mxfs_dlm_pending *p;

	mxfs_pal_mutex_lock(ctx->pending_lock);
	for (p = ctx->pending_buckets[ph]; p; p = p->next) {
		if (resource_equal(&p->resource, resource)) {
			/* If epoch is specified, only discard grants from a HIGHER
			 * epoch than the request (genuinely stale: the request was
			 * sent to an old master, and a newer master also granted).
			 * Accept grants from the SAME or LOWER epoch — a lower
			 * epoch means the master hasn't processed the membership
			 * change yet but the grant is still valid (Bug 74). */
			if (epoch != 0 && p->request_epoch != 0 &&
			    epoch > p->request_epoch) {
				mxfs_pal_mutex_unlock(ctx->pending_lock);
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "dlm: discarding stale grant for ino %llu "
					     "type %u (grant_epoch=%llu request_epoch=%llu)",
					     (unsigned long long)resource->ino,
					     resource->type,
					     (unsigned long long)epoch,
					     (unsigned long long)p->request_epoch);
				return false;
			}
			/*
			 * 0.89.69 (D-A-GRANT-COMPLETING-A-PENDING-ENTRY-RACES-THE-
			 * WAITERS-TIMEOUT-FREE): complete the entry while the bucket
			 * lock is still held.  The entry belongs to a waiter whose
			 * attempt lasts MXFS_LOCK_ACQUIRE_WAIT_MS and which, on
			 * timeout, takes this lock to unlink the entry and then frees
			 * it; completing after the unlock let that remove-and-free
			 * slip in ahead of pending_complete, which then locked a
			 * destroyed mutex in freed memory.  Under the lock the remove
			 * waits behind the completion and the waiter finds its grant.
			 * pending_lock -> p->lock is the only order anywhere:
			 * pending_wait holds p->lock only inside its timed wait and
			 * takes no other lock.
			 */
			if (unlikely(READ_ONCE(mxfs_dl_pending_complete_delay_ms)))
				mxfs_pal_sleep_ms(READ_ONCE(mxfs_dl_pending_complete_delay_ms));
			pending_complete(p, mode, status);
			mxfs_pal_mutex_unlock(ctx->pending_lock);
			return true;
		}
	}
	mxfs_pal_mutex_unlock(ctx->pending_lock);
	return false;
}

/*
 * Fail-complete ALL pending entries with MXFS_DLM_RETRY.
 *
 * Called from mxfs_dlm_update_active_nodes() after a membership change
 * purges the lock table. Threads sleeping in pending_wait() — both
 * remote-master requests waiting for a dead node's grant, and
 * local-master requests waiting for a BAST holder that was just purged
 * — must be woken immediately so they can retry with the new master
 * assignment.
 *
 * Without this, threads block for up to MXFS_LOCK_WAIT_TIMEOUT_MS
 * (120s) on a grant that will never arrive, causing D-state hangs
 * for filesystem operations like ls -la and rm -rf.
 */
static void fail_all_pending(struct mxfs_dlm_ctx *ctx)
{
	int woken = 0;
	int i;

	/*
	 * 0.89.69: complete every incomplete entry UNDER pending_lock.  The
	 * earlier shape collected them under the lock and completed them after
	 * it, and an entry whose waiter timed out in that gap was unlinked and
	 * freed before its completion touched it (the same race as a grant's
	 * completion; see pending_signal_resource).  Completing under the lock
	 * is safe here for the same reason: nothing takes pending_lock while
	 * holding an entry's own lock.  This also drops the MXFS_MAX_NODES cap
	 * on how many waiters one membership change could wake.
	 */
	mxfs_pal_mutex_lock(ctx->pending_lock);
	for (i = 0; i < MXFS_DLM_PENDING_SIZE; i++) {
		struct mxfs_dlm_pending *p;

		for (p = ctx->pending_buckets[i]; p; p = p->next) {
			if (!p->done) {
				pending_complete(p, MXFS_LOCK_NL, MXFS_DLM_RETRY);
				woken++;
			}
		}
	}
	mxfs_pal_mutex_unlock(ctx->pending_lock);

	if (woken > 0)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "dlm: membership change woke %d pending lock "
			     "requests", woken);
}

/* ─── Deferred BAST records ───
 *
 * BAST callbacks must be deferred until table_rwlock is released: the
 * BAST handler may call mxfs_dlm_unlock() which needs table_rwlock.
 *
 * CRITICAL: We must NOT iterate live lock entries (via work_next) after
 * releasing table_rwlock, because concurrent lock releases can trigger
 * promote_waiters()/collect_post_promotion_basts() which overwrite
 * work_next on those same entries.  With 3+ nodes, a fast holder can
 * release its lock (in response to a BAST) while we're still sending
 * BASTs to subsequent holders, corrupting the work_next chain.
 *
 * Fix: copy BAST targets into a stack-allocated array while under
 * table_rwlock, then iterate the copy after release.
 *
 * Grant dispatching (pending_signal_resource / send_grant) is safe to
 * call while holding table_rwlock, so grants are dispatched inline.
 */

/* Snapshot of a BAST target — copied while under table_rwlock.
 *
 * We only capture (owner, requested_mode) per record.  The resource
 * is the same for all BASTs in a single operation, so it's passed
 * separately to save stack space (avoids copying the full 32-byte
 * resource_id into each record). */
struct mxfs_bast_record {
	mxfs_node_id_t owner;
	uint8_t requested_mode;
};

/* Stack-safe limit: 8 bytes per record * 64 = 512 bytes.
 * Supports up to 64 conflicting holders on a single resource. */
#define MXFS_MAX_BAST_RECORDS  MXFS_MAX_NODES

/* Fire an array of captured BAST records.  Must be called WITHOUT
 * table_rwlock held.  All records share the same resource.
 *
 * The bast_cb callback (dlm_bast_cb in mount.c) handles both local
 * BASTs (queued to bast_worker) and remote BASTs (sent via peer_send
 * with retry).  Since the callback returns void, delivery errors are
 * handled inside the callback itself.  If a remote BAST ultimately
 * fails, the requesting node's pending_wait will timeout and retry. */
static void fire_bast_records(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      struct mxfs_bast_record *recs, int count);

/*
 * 0.75.42: MXFS_LKF_DEMAND on the TCP engine.  Until now only the CAW
 * engine honoured it (the sticky revoke bit in the slot); on TCP a NOQUEUE
 * request against a held resource was denied and nothing reached the
 * holder, so a demanding non-blocking probe could never succeed unless the
 * holder released of its own accord.  Measured (2 nodes/TCP, 0.75.41): the
 * remove path's bounded pre-acquire poll expired 84 of 84 times at its
 * full 100 ms, and holding the inode locks for those 100 ms per cycle
 * turned a 1.5 s unlink into 41 s with 51 request deadlines.
 *
 * DEMAND now means: BAST the conflicting granted holders exactly as a
 * queued request would, but do NOT queue the requester.  When the holders
 * release, promote_waiters finds nothing to promote and the resource is
 * simply free; the requester's next probe is then granted.  Called under
 * table_rwlock; the records are fired after it is dropped.
 */
static int demand_collect_holders(struct mxfs_dlm_ctx *ctx, int bucket,
				  const struct mxfs_resource_id *resource,
				  uint8_t mode,
				  struct mxfs_bast_record *recs)
{
	struct mxfs_lock *lk;
	int n = 0;

	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED)
			continue;
		if (lk->owner == MXFS_DLM_NODE_UNKNOWN)
			continue;
		if (lock_compat[lk->mode][mode])
			continue;
		if (n < MXFS_MAX_BAST_RECORDS) {
			recs[n].owner = lk->owner;
			recs[n].requested_mode = mode;
			n++;
		}
	}
	return n;
}

static void demand_fire(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *resource,
			mxfs_node_id_t requester,
			struct mxfs_bast_record *recs, int count)
{
	if (count <= 0)
		return;
	mxfs_probe_ratelimited(
	    "mxfs: P-DEMAND-BAST type=%u ino=%llu ag=%u requester=%u targets=%d first=%u — NOQUEUE+DEMAND denied; holders BASTed without queueing\n",
	    resource->type, (unsigned long long)resource->ino,
	    resource->ag_number, requester, count, recs[0].owner);
	fire_bast_records(ctx, resource, recs, count);
}

static void fire_bast_records(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      struct mxfs_bast_record *recs, int count)
{
	int i;

	if (!ctx->bast_cb) {
		if (count > 0)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "dlm: fire_bast_records: %d BASTs for ino %llu "
				     "but bast_cb is NULL",
				     count,
				     (unsigned long long)resource->ino);
		return;
	}

	for (i = 0; i < count; i++) {
		/* a ledger-imported holder whose slot has no live tenant
		 * cannot be BASTed; only the recovery purge retires it. */
		if (recs[i].owner == MXFS_DLM_NODE_UNKNOWN)
			continue;
		/* DLM_TRACE: log each BAST fire for inode 128 */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: BAST FIRE ino=128 target_node=%u "
				     "requested_mode=%s local_node=%u "
				     "bast_idx=%d/%d",
				     recs[i].owner,
				     mode_name(recs[i].requested_mode),
				     ctx->local_node, i, count);
		/* instrumented (run45 120s ino-131 wedge): make EVERY
		 * master-side BAST fire visible for the hot dirs — pairs with the
		 * receiver's P7B-BASTNOTIFY to prove whether a missing release is
		 * a master hole (no P7S) or a receiver swallow (P7S, no action). */
		if (resource->type == MXFS_LTYPE_INODE &&
		    (resource->ino <= 256 ||
		     resource->ino == READ_ONCE(mxfs_dbg_probe_ino))) {
			static atomic_t p7s_n = ATOMIC_INIT(0);
			if ((unsigned)atomic_inc_return(&p7s_n) <= 60000)
				mxfs_probe("mxfs: P7S-BAST-FIRE ino=%llu target=%u reqmode=%s\n",
					(unsigned long long)resource->ino, recs[i].owner,
					mode_name(recs[i].requested_mode));
		}
		ctx->bast_cb(ctx, resource,
			     recs[i].owner, recs[i].requested_mode);
	}
}

/* ROOT FIX for the dir_reuse 2/tcp ~6s handoff (PROVEN BY INSTRUMENT:
 * the holder honors a BAST in ~14us, yet the requester ALWAYS waits the full
 * MXFS_LOCK_ACQUIRE_WAIT_MS=6000ms — then its retry re-fires the BAST and wins,
 * so dur_ms clusters just above 6000).
 *
 * Root: a DIRECT grant that KEEPS the grantee holding — a PR->EX upgrade
 * (dlm_lock_impl / process_remote_request conv_compat paths) or a remote
 * REAFFIRM — is decided ONLY against conflicting GRANTED holders.  It ignores
 * any WAITING/BLOCKED entry and fires NO BAST.  So when a waiter had queued and
 * fired its BAST against the grantee's PRIOR (lower) grant, then the grantee
 * upgraded / re-acquired racing its own release ahead, the new grant carries no
 * BAST and the waiter is stranded — nothing tells the holder to release — until
 * the waiter's own 6000ms ACQUIRE_WAIT_MS timeout re-fires the BAST.  (The
 * RELEASE path already re-evaluates the queue via promote_waiters +
 * collect_post_promotion_basts; the direct-grant paths bypassed it.)
 *
 * After such a grant, scan for a conflicting WAITING/BLOCKED waiter; if one
 * exists, return a BAST record for the grantee so the caller fires it (after
 * dropping table_rwlock).  The grantee then releases promptly (microseconds,
 * batched by the Minimum-Hold-Time policy) instead of the waiter stalling 6s.
 * Caller holds table_rwlock.  Returns 1 and fills *rec if a BAST should fire. */
static int collect_grantee_bast_if_waiters(
    struct mxfs_lock *chain,
    const struct mxfs_resource_id *resource,
    mxfs_node_id_t grantee, uint8_t grantee_mode,
    struct mxfs_bast_record *rec)
{
	struct mxfs_lock *w;

	for (w = chain; w; w = w->next) {
		if (!resource_equal(&w->resource, resource))
			continue;
		if (w->state != MXFS_LSTATE_WAITING &&
		    w->state != MXFS_LSTATE_BLOCKED)
			continue;
		if (w->owner == grantee)
			continue;
		if (!lock_compat[grantee_mode][w->mode]) {
			rec->owner = grantee;
			rec->requested_mode = w->mode;
			return 1;
		}
	}
	return 0;
}

/* MX-DOUBLEGRANT auditor: clock-free master-side detector for the
 * dir_reuse lost-update double-grant hypothesis.  Scans the resource's GRANTED
 * holders in THIS master's table; if any two DIFFERENT-owner holders are
 * mode-incompatible (e.g. two EX, or EX+PR), the master has issued conflicting
 * grants = a serialization break that lets two nodes RMW the shared dir block
 * concurrently (the count=126->77 clobber).  Always-on, capped, loud.  Called
 * with table_rwlock held, AFTER a grant is committed.  Returns # of conflicting
 * pairs (0 = serialized correctly). */
static int mxfs_dlm_audit_double_grant(struct mxfs_lock *chain,
				       const struct mxfs_resource_id *resource)
{
	struct mxfs_lock *a, *b;
	int conflicts = 0;

	for (a = chain; a; a = a->next) {
		if (a->state != MXFS_LSTATE_GRANTED)
			continue;
		if (!resource_equal(&a->resource, resource))
			continue;
		for (b = a->next; b; b = b->next) {
			if (b->state != MXFS_LSTATE_GRANTED)
				continue;
			if (!resource_equal(&b->resource, resource))
				continue;
			if (b->owner == a->owner)
				continue;
			if (!lock_compat[a->mode][b->mode]) {
				static atomic_t dg_n = ATOMIC_INIT(0);
				conflicts++;
				if (atomic_inc_return(&dg_n) <= 2000)
					pr_warn("mxfs: MX-DOUBLEGRANT ino=%llu type=%u ownerA=%u modeA=%s ownerB=%u modeB=%s — master granted CONFLICTING holders (serialization break)\n",
						(unsigned long long)resource->ino,
						resource->type,
						a->owner, mode_name(a->mode),
						b->owner, mode_name(b->mode));
			}
		}
	}
	return conflicts;
}

/* ─── Waiter promotion helpers ─── */

#define MAX_WAITERS      MXFS_MAX_NODES

/* Comparison for sorting waiters by queued_at (oldest first = FIFO) */
static int waiter_cmp(const void *a, const void *b)
{
	const struct mxfs_lock *la = *(const struct mxfs_lock *const *)a;
	const struct mxfs_lock *lb = *(const struct mxfs_lock *const *)b;

	if (la->queued_at < lb->queued_at) return -1;
	if (la->queued_at > lb->queued_at) return 1;
	return 0;
}

/*
 * find_conflicting_waiter — arrival-time FIFO barrier (a16ec5f2)
 *
 * promote_waiters enforces FIFO at RELEASE time (an EX waiter blocks
 * younger PR waiters behind it), but the immediate-grant paths
 * (check_compat / remote_check_compat) only tested the new request
 * against GRANTED holders — so a steady stream of arriving PR requests
 * was granted straight past a queued EX waiter.  The EX never saw a
 * zero-PR window, timed out every MXFS_LOCK_ACQUIRE_WAIT_MS, was
 * removed and re-queued at the BACK of the FIFO (fresh queued_at), and
 * starved: the P36-RETRY 1s handoff stalls (~10/round on the 8-node
 * create/verify/rm workload, measured run39).
 *
 * Returns the first WAITING/BLOCKED entry from a DIFFERENT owner whose
 * requested mode conflicts with `mode`, or NULL.  A hit means the new
 * request must queue behind it instead of being granted on arrival.
 * Conversions/reaffirms are handled BEFORE the check_compat labels and
 * keep their priority (denying a holder's upgrade cannot help the
 * waiter — the holder's existing grant blocks it anyway — and queuing
 * upgrades behind waiters is the classic conversion deadlock).
 */
static struct mxfs_lock *find_conflicting_waiter(struct mxfs_lock *chain,
						 const struct mxfs_resource_id *resource,
						 mxfs_node_id_t requester,
						 uint8_t mode)
{
	struct mxfs_lock *lk;

	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_WAITING &&
		    lk->state != MXFS_LSTATE_BLOCKED)
			continue;
		if (lk->owner == requester)
			continue;
		if (!lock_compat[lk->mode][mode])
			return lk;
	}
	return NULL;
}

/*
 * promote_waiters — FIFO grant ordering
 *
 * Collects all waiters for a resource, sorts by queued_at (oldest first),
 * then grants in order. Stops at the first incompatible waiter to prevent
 * starvation: an EX waiter blocks younger PR waiters behind it, and a PR
 * waiter blocks younger EX waiters behind it.
 */
static uint32_t dlm_next_gen(struct mxfs_dlm_ctx *ctx);  /* sess-tcp fwd decl */

struct dlm_txn;
static bool dlm_txn_retires(const struct dlm_txn *txn, const struct mxfs_lock *lk);

static struct mxfs_lock *promote_waiters(struct mxfs_dlm_ctx *ctx,
					  struct mxfs_lock *chain,
					  const struct mxfs_resource_id *resource,
					  const struct dlm_txn *txn)
{
	struct mxfs_lock *lk, *other;
	struct mxfs_lock *waiters[MAX_WAITERS];
	int nwaiters = 0;
	struct mxfs_lock *grant_list = NULL;
	int i, ok;

	/* Pass 1: collect all waiters for this resource */
	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_WAITING &&
		    lk->state != MXFS_LSTATE_BLOCKED)
			continue;
		if (nwaiters < MAX_WAITERS)
			waiters[nwaiters++] = lk;
	}

	if (nwaiters == 0)
		return NULL;

	/* Sort waiters by queued_at — oldest first (FIFO) */
	mxfs_pal_sort(waiters, (size_t)nwaiters, sizeof(waiters[0]), waiter_cmp);

	/* Pass 2: grant in FIFO order, stop at first incompatible */
	for (i = 0; i < nwaiters; i++) {
		lk = waiters[i];

		ok = 1;
		for (other = chain; other; other = other->next) {
			if (!resource_equal(&other->resource, resource))
				continue;
			/* the PENDING_RELEASE holder being retired in THIS
			 * transition is chosen past; a PENDING_DURABLE holder blocks
			 * like a GRANTED one.
			 *
			 * (proven by instrument, tests/tauth/concurrent_release_test):
			 * any OTHER PENDING_RELEASE holder blocks too — its bit is
			 * still durable, and a grant decided over it is refused by the
			 * ledger (P-TAUTH-DOUBLE-GRANT), which wedged the whole bundled
			 * transition on the 32/tcp rig (0.35.0: page 1786 never
			 * drained, 26 mounts aborted).  The sibling's own retirement
			 * re-scans (dlm_promote_txn), so nothing is lost. */
			if (!lk_is_holder(other))
				continue;
			if (other->state == MXFS_LSTATE_PENDING_RELEASE &&
			    txn && dlm_txn_retires(txn, other))
				continue;
			if (other->owner == lk->owner)
				continue;
			if (!lock_compat[other->mode][lk->mode]) {
				ok = 0;
				break;
			}
		}

		if (ok) {
			/* the grant is DECIDED here and becomes GRANTED only
			 * in dlm_txn_finalize, after the ledger page transition
			 * verified (durable-before-deliver).  Every promote_waiters
			 * caller runs dlm_promote_txn, which commits and finalizes. */
			lk->state = MXFS_LSTATE_PENDING_DURABLE;
			lk->granted_at = mxfs_pal_time_ms();
			lk->grant_gen = dlm_next_gen(ctx);
			/* granted — the waiter is about to be signaled
			 * and no longer needs reap-protection; a GRANTED entry is the
			 * unlock primary target anyway. */
			lk->pend_waiter = NULL;
			lk->work_next = grant_list;
			grant_list = lk;
			/* pointer-lifecycle trace (see lock_alloc). */
			if (resource->type == MXFS_LTYPE_INODE &&
			    resource->ino <= 256) {
				static atomic_t p4p_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p4p_n) <= 400000)
					mxfs_pal_log(MXFS_LOG_DEBUG,
						     "mxfs: P4L-PROMOTE ino=%llu ptr=%px owner=%u mode=%u gen=%u",
						     (unsigned long long)resource->ino, lk,
						     (unsigned)lk->owner, (unsigned)lk->mode,
						     lk->grant_gen);
			}
			mxfs_dlm_audit_double_grant(chain, resource);
			/* DLM_TRACE: log each waiter promotion for ino 128 */
			if (resource->ino == 128 &&
			    resource->type == MXFS_LTYPE_INODE)
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "DLM_TRACE: promote_waiters GRANTED "
					     "ino=128 owner=%u mode=%s",
					     lk->owner, mode_name(lk->mode));
		} else {
			/* FIFO barrier: stop here. Younger waiters stay blocked
			 * even if they'd be compatible with current grants.
			 * This prevents starvation of this incompatible waiter. */
			/* DLM_TRACE: log FIFO barrier for ino 128 */
			if (resource->ino == 128 &&
			    resource->type == MXFS_LTYPE_INODE)
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "DLM_TRACE: promote_waiters BLOCKED "
					     "ino=128 owner=%u mode=%s "
					     "(FIFO barrier, %d remaining)",
					     lk->owner, mode_name(lk->mode),
					     nwaiters - i - 1);
			lk->state = MXFS_LSTATE_BLOCKED;
			/* Mark all remaining waiters as blocked too */
			for (i++; i < nwaiters; i++)
				waiters[i]->state = MXFS_LSTATE_BLOCKED;
			break;
		}
	}

	return grant_list;
}

/*
 * collect_post_promotion_basts — VMS DLM post-promotion BAST collection
 *
 * After promote_waiters grants some waiters, there may be remaining
 * BLOCKED waiters. The newly-granted holders need BASTs so they release
 * when done, allowing the blocked waiters to proceed.
 *
 * Without this, a promoted holder caches the lock indefinitely (per-inode
 * lock caching) and remaining waiters starve/timeout. This is the B→C→D
 * chain in the VMS DLM model: each promoted holder must be told that
 * someone is waiting behind it.
 *
 * Must be called with table_rwlock held.
 */
static struct mxfs_lock *collect_post_promotion_basts(
    struct mxfs_lock *chain,
    const struct mxfs_resource_id *resource,
    uint8_t *blocked_mode_out)
{
	struct mxfs_lock *lk, *blocked;
	struct mxfs_lock *bast_list = NULL;

	*blocked_mode_out = MXFS_LOCK_NL;

	/* Find the first BLOCKED waiter */
	blocked = NULL;
	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state == MXFS_LSTATE_BLOCKED) {
			blocked = lk;
			break;
		}
	}

	if (!blocked)
		return NULL;

	*blocked_mode_out = blocked->mode;

	/* Collect BASTs for GRANTED holders that conflict with the
	 * blocked waiter's requested mode (GRANTED only — a
	 * PENDING_DURABLE holder is BASTed by dlm_txn_finalize once it is
	 * delivered, a PENDING_RELEASE holder is already gone) */
	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED)
			continue;
		if (lk->owner == blocked->owner)
			continue;
		if (!lock_compat[lk->mode][blocked->mode]) {
			lk->work_next = bast_list;
			bast_list = lk;
		}
	}

	return bast_list;
}

/* sess-tcp double-grant fix: allocate the next monotonic grant generation.
 * Caller MUST hold table_rwlock (all grant sites do).  Never returns 0 so
 * a 0 grant_gen on the wire/mirror reliably means "no recorded grant". */
static uint32_t dlm_next_gen(struct mxfs_dlm_ctx *ctx)
{
	uint32_t g = ++ctx->grant_gen_next;
	if (g == 0)
		g = ctx->grant_gen_next = 1;
	return g;
}

/* Send a grant/deny response to a remote node.
 * Retries once after 10ms on failure.  If the retry also fails,
 * the requesting node's pending_wait will timeout and retry. */
/* double-grant detector — forward decls (defined below
 * process_remote_request); all callers hold ctx->table_rwlock. */
static bool dg_grant_ex(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *res,
			mxfs_node_id_t owner, uint32_t gen,
			uint32_t *epoch_out);
static void dg_release(const struct mxfs_resource_id *res,
		       mxfs_node_id_t owner);

/* the durable grant id + lineage + request id ride on the grant. */
struct dlm_grant_ids {
	uint64_t auth_epoch;
	uint64_t grant_seq;
	uint64_t lineage;
	uint32_t req_id;
	uint64_t open_holders;  /* 0.89.0: the record's open-holder marks at the decision */
};

static void send_grant(struct mxfs_dlm_ctx *ctx,
		       mxfs_node_id_t target,
		       const struct mxfs_resource_id *resource,
		       uint8_t mode, uint8_t status_code,
		       uint16_t msg_type, mxfs_epoch_t epoch,
		       uint32_t grant_gen, uint8_t handoff,
		       uint32_t dir_epoch, const struct dlm_grant_ids *ids)
{
	struct mxfs_dlm_lock_resp resp;
	int ret;

	if (!ctx->send_cb)
		return;

	memset(&resp, 0, sizeof(resp));
	resp.hdr.magic = MXFS_DLM_MAGIC;
	resp.hdr.version = MXFS_DLM_VERSION;
	resp.hdr.type = msg_type;
	resp.hdr.length = sizeof(resp);
	resp.hdr.sender = ctx->local_node;
	resp.hdr.target = target;
	resp.hdr.epoch = epoch;
	resp.resource = *resource;
	resp.mode = mode;
	resp.status = status_code;
	resp.handoff = handoff;   /* cross-node EX handoff signal */
	resp.grant_gen = grant_gen;
	resp.dir_epoch = dir_epoch;  /* monotonic cross-node handoff epoch */
	if (ids) {
		resp.authority_epoch = ids->auth_epoch;
		resp.grant_seq64 = ids->grant_seq;
		resp.lineage = ids->lineage;
		resp.req_id = ids->req_id;
		resp.open_holders = ids->open_holders;
	}

	/* instrumented: log the dir_epoch this master SENDS on an EX grant
	 * for the storm dir (ino 131).  Pairs with P44-GRANTDIREPOCH (the grantee's
	 * stored lk->dir_epoch) and P64-MASTER-HANDOFF (the master's dg_shadow.epoch)
	 * to localize WHERE the monotonic handoff epoch is lost (sent=0 => caller
	 * computed 0; sent>0 but P44 reads 0 => receive/store bug). */
	if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131 &&
	    mode == MXFS_LOCK_EX) {
		static atomic_t p51sg = ATOMIC_INIT(0);
		/* CAPPED (not ratelimited) — the deny-window grant
		 * (the P2-EPOCHPLACE master_ep=0 loss precursor) was ratelimit-
		 * suppressed in run37; every ino-131 EX grant's sent epoch must be
		 * visible to split master-computed-0 vs receiver-lost. */
		if ((unsigned)atomic_inc_return(&p51sg) <= 60000)
			mxfs_probe("mxfs: P51-SENDGRANT ino=131 target=%u grant_gen=%u handoff=%u dir_epoch_sent=%u\n",
					    target, grant_gen, handoff, dir_epoch);
	}

	/*
	 * TEST ONLY (dl_drop_grant_ino): a GRANT for this inode is decided,
	 * durable and recorded here, and never delivered.  The shape a lost
	 * delivery produces: the requester keeps re-sending (each re-send
	 * re-affirms and is dropped again), never sees a receipt, and its
	 * grant stays a blocker for every other node.  Nothing else is
	 * affected.  Never set in production.
	 */
	if (unlikely(READ_ONCE(mxfs_dl_drop_grant_ino)) &&
	    msg_type == MXFS_MSG_LOCK_GRANT &&
	    resource->type == MXFS_LTYPE_INODE &&
	    resource->ino == READ_ONCE(mxfs_dl_drop_grant_ino)) {
		int dropped = atomic_inc_return(&mxfs_dl_drop_grant_n);

		if (dropped <= 8 || (dropped % 64) == 0)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P958-DROP-GRANT n=%d type=%u ino=%llu ag=%u "
			    "target=%u mode=%s gen=%u — TEST ONLY: this grant is "
			    "recorded here and not delivered",
			    dropped, resource->type,
			    (unsigned long long)resource->ino, resource->ag_number,
			    target, mode_name(mode), grant_gen);
		return;
	}

	ret = ctx->send_cb(ctx, target, &resp, sizeof(resp));
	if (ret < 0) {
		mxfs_pal_sleep_ms(10);
		ret = ctx->send_cb(ctx, target, &resp, sizeof(resp));
		if (ret < 0)
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: lock grant to node %u failed (retried), "
				     "file operations on that node may be delayed",
				     target);
	}
}

/* ═══════════════════════════════════════════════════════════════════════
 * — TCP durable-authority ledger, master side
 * (docs/tcp-authority-ledger.md step 3; rulings in ccmemory
 * docs/rulings/tauth-step3-master-ledger-design.md).
 *
 * Every grant the master decides becomes visible to its owner only after
 * the ledger page transition that records it has verified on the platter
 * (durable-before-deliver).  Every release retires its record in ONE
 * transition with the successor grants it unblocks, and is ACKed only
 * after that transition.  The flow at every grant/release site is:
 *
 *   table_rwlock: decide, install PENDING_DURABLE / PENDING_RELEASE,
 *                 snapshot the transition (dlm_txn) ... unlock
 *   dlm_txn_commit:   ledger commit under the page mutex (I/O)
 *   dlm_txn_finalize: table_rwlock: re-find every pending entry by
 *                 {resource, owner, gen}; GRANTED (or removed on refusal),
 *                 re-check the page-ownership generation ... unlock
 *   deliver:      send / signal grants, denies and the release ACK
 * ═══════════════════════════════════════════════════════════════════════ */

static inline bool dlm_ledger_active(struct mxfs_dlm_ctx *ctx)
{
	return ctx->ledger != NULL && !ctx->ledger_failed;
}

/* Grants are refused (fail closed) while a required ledger is absent
 * (activation barrier) or after it fail-stopped. */
static inline bool dlm_ledger_refuses(struct mxfs_dlm_ctx *ctx)
{
	return (ctx->ledger_required && !ctx->ledger) || ctx->ledger_failed;
}

static inline bool dlm_mode_exclusive(uint8_t mode)
{
	return mode >= MXFS_LOCK_PW;
}

/* (D-0348 step 2): a resource's HOME PAGE under this ctx's routing
 * geometry (page_count / hash_seed: the region header's, via attach or
 * mxfs_dlm_set_ledger_geometry; the minimum geometry with seed 0 until then). */
static inline uint32_t dlm_res_page(struct mxfs_dlm_ctx *ctx,
				    const struct mxfs_resource_id *res)
{
	uint32_t np = ctx->page_count ? ctx->page_count : MXFS_TAUTH_NPAGES;

	return mxfs_tauth_home_page(mxfs_tauth_res_hash(res, sizeof(*res), ctx->hash_seed), np);
}

/* 3a: page-aligned mastership.  page = the resource's home page (
 * seeded hash % npages), master = active_nodes[page % N].  Caller holds
 * active_nodes.lock (or reads racily for a diagnostic). */
static inline mxfs_node_id_t dlm_page_master_locked(struct mxfs_dlm_ctx *ctx,
						    uint32_t page)
{
	if (ctx->active_nodes.count <= 0)
		return ctx->local_node;
	return ctx->active_nodes.nodes[page % (uint32_t)ctx->active_nodes.count];
}

static bool dlm_owns_page_cb(void *data, uint32_t page)
{
	struct mxfs_dlm_ctx *ctx = data;
	mxfs_node_id_t m;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	m = dlm_page_master_locked(ctx, page);
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return m == ctx->local_node;
}

static void send_release_ack(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target,
			     const struct mxfs_resource_id *resource,
			     uint32_t grant_gen, uint32_t rel_id,
			     uint64_t auth_epoch, uint64_t grant_seq,
			     uint8_t status)
{
	struct mxfs_dlm_release_ack ack;
	int ret;

	if (!ctx->send_cb)
		return;
	memset(&ack, 0, sizeof(ack));
	ack.hdr.magic = MXFS_DLM_MAGIC;
	ack.hdr.version = MXFS_DLM_VERSION;
	ack.hdr.type = MXFS_MSG_LOCK_RELEASE_ACK;
	ack.hdr.length = sizeof(ack);
	ack.hdr.sender = ctx->local_node;
	ack.hdr.target = target;
	ack.hdr.epoch = ctx->current_epoch;
	ack.resource = *resource;
	ack.grant_gen = grant_gen;
	ack.rel_id = rel_id;
	ack.authority_epoch = auth_epoch;
	ack.grant_seq64 = grant_seq;
	ack.status = status;
	ret = ctx->send_cb(ctx, target, &ack, sizeof(ack));
	if (ret < 0) {
		mxfs_pal_sleep_ms(10);
		ctx->send_cb(ctx, target, &ack, sizeof(ack));
	}
}

/* ── 3f: ledger-backed blocker import ── */

struct dlm_import_acc {
	struct mxfs_tauth_entry ent[MXFS_TAUTH_ENTRIES_PER_PAGE];
	int n;
};

static void dlm_import_scan_cb(void *data, uint32_t slot,
			       const struct mxfs_tauth_entry *e)
{
	struct dlm_import_acc *acc = data;

	(void)slot;
	if (acc->n < (int)MXFS_TAUTH_ENTRIES_PER_PAGE)
		acc->ent[acc->n++] = *e;
}

/* (D-0342): is this owner's ledger purge still incomplete? Caller
 * holds table_rwlock. */
static bool dlm_purge_pending(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	int k;

	for (k = 0; k < ctx->purge_pending_count; k++)
		if (ctx->purge_pending[k].node == node)
			return true;
	return false;
}

static bool dlm_owner_purged(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node, int slot)
{
	int i;

	/*
	 * (D-0344, proven by dlm_ledger_test 7b): the identity
	 * is the NODE ID (per-incarnation on the rig), never the slot.  The
	 * old slot clause poisoned a heartbeat slot for every later occupant:
	 * a node that mounted into a dead node's slot had its live records
	 * "lazily retired" from the platter on the next page import at the
	 * master (P-TAUTH-PURGE node=<live>) and its EX re-granted to someone
	 * else — concurrent EX.  An unnamed shared bit on a purged slot stays
	 * an UNKNOWN blocker (the ruling) until recovery names it.
	 */
	(void)slot;
	for (i = 0; i < ctx->purged_owner_count; i++)
		if (node != 0 && node != MXFS_DLM_NODE_UNKNOWN &&
		    ctx->purged_owners[i].node == node)
			return true;
	return false;
}

/*
 * 0.75.81 (D-...-0935, measured s570a): the purged owner recorded for a
 * heartbeat slot, or 0.  This is the ONLY way to attribute a shared holder
 * bit whose slot has since been emptied — a bit names a slot, and a
 * published recovery zeroes the slot's heartbeat record, so slot_node_cb
 * answers 0 and the node id the purge was keyed on is unreachable from the
 * bit.  Answering only for a slot with NO current occupant is what keeps
 * this clear of the D-0344 hazard the slot clause in dlm_owner_purged was
 * removed for: the caller checks that first, and
 * mxfs_dlm_ledger_purge_owner re-checks occupancy before honouring a slot.
 * Caller holds table_rwlock.
 */
static mxfs_node_id_t dlm_slot_purged_owner(struct mxfs_dlm_ctx *ctx, int slot)
{
	int i;

	if (slot < 0)
		return 0;
	for (i = 0; i < ctx->purged_owner_count; i++)
		if (ctx->purged_owners[i].slot == slot &&
		    ctx->purged_owners[i].node != 0 &&
		    ctx->purged_owners[i].node != MXFS_DLM_NODE_UNKNOWN)
			return ctx->purged_owners[i].node;
	return 0;
}

/* Remember `node` as a departed, settled owner: later page imports retire
 * its records instead of installing them.  Caller holds NO locks.
 * true = newly recorded. */
static bool dlm_owner_mark_purged(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node, int slot)
{
	bool added = false;

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	if (!dlm_owner_purged(ctx, node, -1) && ctx->purged_owner_count < MXFS_MAX_NODES) {
		ctx->purged_owners[ctx->purged_owner_count].node = node;
		ctx->purged_owners[ctx->purged_owner_count].slot = slot;
		ctx->purged_owner_count++;
		added = true;
	} else if (slot >= 0) {
		int i;

		/*
		 * 0.75.81: the same owner reaches this from two directions — the
		 * recovery purge, which knows its heartbeat slot, and the takeover
		 * of one of its pages (dlm_page_departed_authority), which passes
		 * -1.  Whichever arrives second must not leave the slot unnamed:
		 * dlm_slot_purged_owner is the only route from an emptied slot back
		 * to the owner whose bits it carries.
		 */
		for (i = 0; i < ctx->purged_owner_count; i++)
			if (ctx->purged_owners[i].node == node &&
			    ctx->purged_owners[i].slot < 0)
				ctx->purged_owners[i].slot = slot;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return added;
}

/*
 * 0.75.8 (D-TCP-TAKEOVER-PAGE-IMPORTS-DEPARTED-AUTHORITY-EX-AS-LIVE-BLOCKER-
 * JOINER-MOUNT-HANGS-0906): a page PREPARED to this node by a node that is
 * NOT its authority was taken over from a departed authority by the
 * certified successor (mxfs_dlm_handoff_takeover, bootstrap only), which
 * runs only after that incarnation's heartbeat record was settled and its
 * records purged on the successor.  The page still carries the departed
 * incarnation's ACTIVE records, and purged_owners is per node: this node
 * never observed the departure, so the import installed the departed EX as
 * a live blocker (P-TAUTH-IMPORT-ACTIVE owner=<dead>) and every request
 * behind it waited on a holder that no longer exists.  Measured on the
 * 2-node TCP rig (sameboot_remount arm 1 on 0.75.7): the joiner's mount
 * queued its AG 0 EX behind the last leaver's EX for the whole acquire
 * budget and beyond (P-LKTIMEOUT-HOLDER holder=<dead> x12, P36-RETRY x15,
 * mount pid 5 min in pending_wait).  Record the departed authority as
 * purged before the page is activated, on both ways a takeover reaches
 * this node: the FROZEN message (sender != auth) and the platter image
 * (writer != auth).  A live handoff is prepared by its own authority, so
 * writer == auth and nothing is recorded.
 */
static bool dlm_node_in_view(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node);
static int dlm_takeover_page(struct mxfs_dlm_ctx *ctx, uint32_t p, mxfs_node_id_t node,
			     uint64_t inc, const char *how,
			     mxfs_node_id_t hint_node, uint64_t hint_inc);
/* 0.75.30: is `owner` a terminally refused victim (records kept
 * selectively)?  *slot_out = its heartbeat slot or -1. */
static bool dlm_owner_refused(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t owner,
			      int *slot_out)
{
	int slot = -1;
	bool refused;

	if (slot_out)
		*slot_out = -1;
	if (!ctx->refused_owner_cb || owner == 0 || owner == MXFS_DLM_NODE_UNKNOWN ||
	    owner == ctx->local_node)
		return false;
	refused = ctx->refused_owner_cb(ctx->cb_data, owner, NULL, &slot) > 0;
	if (refused && slot_out)
		*slot_out = slot;
	return refused;
}

/* 0.75.30: the ledger's keep filter for a refused owner's selective purge —
 * asks the mount layer whether this record's resource lies inside the
 * owner's quarantined domain. */
struct dlm_refused_keep_arg {
	struct mxfs_dlm_ctx *ctx;
	mxfs_node_id_t       owner;
	uint32_t             kept;
};

static int dlm_refused_keep_entry(void *data, const struct mxfs_tauth_entry *e)
{
	struct dlm_refused_keep_arg *ka = data;
	struct mxfs_resource_id res;
	int keep;

	mxfs_tauth_entry_res(e, &res);
	keep = ka->ctx->refused_owner_cb(ka->ctx->cb_data, ka->owner, &res, NULL) > 0;
	if (keep)
		ka->kept++;
	return keep;
}

static void dlm_page_departed_authority(struct mxfs_dlm_ctx *ctx, uint32_t page,
					mxfs_node_id_t auth_node, uint64_t auth_inc,
					mxfs_node_id_t writer, const char *how)
{
	if (auth_node == 0 || auth_node == MXFS_DLM_NODE_UNKNOWN ||
	    auth_node == ctx->local_node || writer == 0 || writer == auth_node)
		return;
	/*
	 * 0.75.30: a terminally refused victim's pages are taken over the same
	 * way, but its records must NOT be retired wholesale at import — the
	 * grants inside its quarantined domain stay frozen until repair and
	 * remount.  The selective purge at activation and the per-record
	 * refused_owner_cb answer decide which of them go.
	 */
	if (dlm_owner_refused(ctx, auth_node, NULL)) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-REFUSED-AUTH page=%u auth=%u/%llu by=%u via=%s — "
			     "a page taken over from a terminally refused victim; its "
			     "in-domain records import as frozen blockers, never retired",
			     page, auth_node, (unsigned long long)auth_inc, writer, how);
		return;
	}
	if (dlm_owner_mark_purged(ctx, auth_node, -1))
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-DEPARTED-AUTH page=%u auth=%u/%llu by=%u via=%s "
			     "in_view=%d — a page prepared to us by a node other than its "
			     "authority came from a takeover; that authority's records "
			     "are retired at import, never installed as blockers",
			     page, auth_node, (unsigned long long)auth_inc, writer, how,
			     dlm_node_in_view(ctx, auth_node) ? 1 : 0);
}

/* Caller holds table_rwlock (any mode). */
static bool dlm_owner_sealed(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	int i;

	for (i = 0; i < ctx->sealed_owner_count; i++)
		if (node != 0 && ctx->sealed_owners[i].node == node)
			return true;
	return false;
}

/* 0.75.23: is `master` a sealed (fenced, records collected) dead node?
 * Takes the table lock (read); for callers that hold none. */
static bool dlm_master_sealed(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t master)
{
	bool sealed;

	if (master == ctx->local_node || ctx->sealed_owner_count == 0)
		return false;
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	sealed = dlm_owner_sealed(ctx, master);
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return sealed;
}

/* Caller holds table_rwlock (write). */
static void dlm_owner_unseal(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	int i;

	for (i = 0; i < ctx->sealed_owner_count; i++) {
		if (ctx->sealed_owners[i].node != node)
			continue;
		ctx->sealed_owners[i] = ctx->sealed_owners[ctx->sealed_owner_count - 1];
		ctx->sealed_owner_count--;
		i--;
	}
}

#define DLM_SEAL_SETTLE_MS      3000u
#define DLM_SEAL_POLL_MS        10u

int mxfs_dlm_seal_owner(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
			uint64_t inc)
{
	uint64_t t0;
	uint32_t i;
	int pending;

	if (!ctx || !node)
		return -EINVAL;
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	if (!dlm_owner_sealed(ctx, node)) {
		if (ctx->sealed_owner_count >= MXFS_MAX_NODES) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-SEAL-FULL node=%u — sealed-owner table full",
				     node);
			return -ENOSPC;
		}
		ctx->sealed_owners[ctx->sealed_owner_count].node = node;
		ctx->sealed_owners[ctx->sealed_owner_count].inc = inc;
		ctx->sealed_owner_count++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	/*
	 * Drain: a release of this owner that was accepted BEFORE the seal may
	 * still be committing (PENDING_RELEASE).  The commit either retires the
	 * record or restores the holder; either way the collector must read the
	 * settled image, so wait for the state to leave PENDING_RELEASE.
	 */
	t0 = mxfs_pal_time_ms();
	for (;;) {
		pending = 0;
		mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
		for (i = 0; i < ctx->bucket_count && !pending; i++) {
			struct mxfs_lock *lk;

			for (lk = ctx->buckets[i]; lk; lk = lk->next)
				if (lk->owner == node &&
				    lk->state == MXFS_LSTATE_PENDING_RELEASE) {
					pending = 1;
					break;
				}
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		if (!pending)
			break;
		if (mxfs_pal_time_ms() - t0 > DLM_SEAL_SETTLE_MS) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-SEAL-BUSY node=%u inc=%llu — a release of "
				     "the sealed owner is still committing after %u ms; the "
				     "snapshot is retried",
				     node, (unsigned long long)inc, DLM_SEAL_SETTLE_MS);
			return -EBUSY;
		}
		mxfs_pal_sleep_ms(DLM_SEAL_POLL_MS);
	}
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-TAUTH-SEAL node=%u inc=%llu settle_ms=%llu — owner sealed; "
		     "its releases are refused until the recovery purge",
		     node, (unsigned long long)inc,
		     (unsigned long long)(mxfs_pal_time_ms() - t0));
	return 0;
}

/* Caller holds table_rwlock (write).  Install one imported holder unless a
 * live table entry already represents it. */
static void dlm_import_holder(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *res,
			      mxfs_node_id_t owner, uint64_t inc, uint16_t slot,
			      uint8_t mode, const struct mxfs_tauth_entry *e,
			      bool exclusive)
{
	uint32_t bucket = resource_hash(res, ctx->bucket_count);
	struct mxfs_lock *lk;

	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, res))
			continue;
		if (lk->owner == owner &&
		    (lk_is_holder(lk) || lk->state == MXFS_LSTATE_CONVERTING))
			return;     /* live entry (or an earlier import) covers it */
		/* (ruling item 4): a shared bit imported while its slot
		 * was unresolvable (formation: the heartbeat table had not seen
		 * the claimant yet) is re-asked on every import; once the slot
		 * names its node the blocker gets its owner — it can then be
		 * BASTed and released by that node.  Never retired here. */
		if (!exclusive && lk->imported && lk->owner == MXFS_DLM_NODE_UNKNOWN &&
		    lk->owner_slot == slot && owner != MXFS_DLM_NODE_UNKNOWN && owner != 0 &&
		    lk_is_holder(lk)) {
			lk->owner = owner;
			lk->owner_inc = inc;
			ctx->ledger_imports_resolved++;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-TAUTH-IMPORT-RESOLVED type=%u ino=%llu ag=%u slot=%u -> "
				     "owner=%u inc=%llu",
				     res->type, (unsigned long long)res->ino, res->ag_number,
				     slot, owner, (unsigned long long)inc);
			return;
		}
	}
	lk = lock_alloc(res, owner, mode, MXFS_LSTATE_GRANTED, 0);
	if (!lk)
		return;
	lk->imported = true;
	lk->owner_inc = inc;
	lk->owner_slot = slot;
	lk->lineage = e->resource_lineage;
	if (exclusive) {
		lk->auth_epoch = e->authority_epoch;
		lk->grant_seq = e->grant_seq64;
	}
	/* 0.89.1 (D-0977): the imported entry carries the record's open-holder
	 * marks, so a re-affirm this master later sends for it names the same
	 * snapshot the old master granted, never an empty one. */
	lk->open_holders = e->open_holders;
	lk->open_snap = exclusive && dlm_ledger_active(ctx);
	lk->dir_epoch = (uint32_t)e->dir_epoch;
	lk->next = ctx->buckets[bucket];
	ctx->buckets[bucket] = lk;
	ctx->lock_count++;
	ctx->ledger_imports++;
	P_LKT("IMPORT-ACTIVE", res, owner, mode);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-TAUTH-IMPORT-ACTIVE type=%u ino=%llu ag=%u owner=%u inc=%llu "
		     "slot=%u mode=%s grant_id={%llu,%llu} — ledger-backed blocker",
		     res->type, (unsigned long long)res->ino, res->ag_number, owner,
		     (unsigned long long)inc, slot, mode_name(mode),
		     (unsigned long long)lk->auth_epoch,
		     (unsigned long long)lk->grant_seq);
}

/* Caller holds table_rwlock.  Does this node's table carry an entry of ANY
 * state for `res`?  Every grant this incarnation holds is here: a mirror
 * for a remotely-mastered grant, a holder entry for a locally-mastered one,
 * a WAITING/BLOCKED entry for a request in flight. */
static bool dlm_local_entry_any(struct mxfs_dlm_ctx *ctx,
				const struct mxfs_resource_id *res)
{
	struct mxfs_lock *lk;

	for (lk = ctx->buckets[resource_hash(res, ctx->bucket_count)]; lk;
	     lk = lk->next)
		if (lk->owner == ctx->local_node && resource_equal(&lk->resource, res))
			return true;
	return false;
}

/* Is a request of ours for `res` waiting on a remote master's answer?  The
 * pending is inserted before the request is sent and removed only after
 * the answer (or its timeout), so a grant the old master recorded on a page
 * that is handed to us before the GRANT message arrives is always covered.
 * Takes pending_lock; table_rwlock -> pending_lock is the established
 * order (the PENDING_DURABLE attach in dlm_lock_impl). */
static bool dlm_pending_exists(struct mxfs_dlm_ctx *ctx,
			       const struct mxfs_resource_id *res)
{
	struct mxfs_dlm_pending *p;
	bool found = false;

	mxfs_pal_mutex_lock(ctx->pending_lock);
	for (p = ctx->pending_buckets[pending_hash(res)]; p; p = p->next)
		if (resource_equal(&p->resource, res)) {
			found = true;
			break;
		}
	mxfs_pal_mutex_unlock(ctx->pending_lock);
	return found;
}

/* Make page `page_id` current under `gen` and import its ACTIVE records as
 * holders.  Records of a recovery-purged owner are retired instead.  Does
 * I/O; caller holds NO locks.
 *
 * 0.75.5 (D-TCP-SLOT-SUCCESSOR-IMPORTS-PREDECESSOR-SHARED-BIT-AS-OWN-...):
 * a shared holder bit names a heartbeat SLOT, not an incarnation.  When a
 * page is handed to the successor of a departed slot before the departed
 * incarnation's purge reaches it (the purge is on the old master's worker
 * and skips pages that are no longer its own; the successor never received
 * the goodbye, so it purges nothing), the predecessor's bit resolves to the
 * successor itself and is imported as a grant it holds.  Its own EX request
 * on that resource then reads as a blocked upgrade (-EDEADLK), and the
 * self-demote that follows has nothing to demote.  Measured on the 2-node
 * TCP rig: root inode 128, test2's rejoin mount hung in xfs_iget.
 *
 * This node knows what it holds: every grant of this incarnation has a
 * table entry (dlm_local_entry_any) or a request in flight
 * (dlm_pending_exists).  A bit for OUR slot with neither is residue: it is
 * imported as ours so the normal local-master unlock retires it through a
 * ledger transition, exactly as if the predecessor's release had landed.
 * An EX record on our slot under a different node id is the same residue
 * with its owner named; it is purged by that node id.  Bits of other slots
 * are left alone: they resolve to live nodes that answer the BAST for a
 * grant they do not hold, or to no node at all (an UNKNOWN blocker until
 * recovery names it, the ruling). */
static int dlm_ledger_import_page(struct mxfs_dlm_ctx *ctx, uint32_t page_id,
				  uint64_t gen)
{
	struct dlm_import_acc *acc;
	struct { mxfs_node_id_t node; int slot; } purge[MXFS_TAUTH_ENTRIES_PER_PAGE];
	struct mxfs_resource_id *residue;
	int npurge = 0, nresidue = 0, i, n, rc;

	rc = mxfs_tauth_ledger_ensure(ctx->ledger, page_id, gen);
	if (rc)
		return rc;
	if (ctx->page_import_gen && page_id < ctx->page_count &&
	    ctx->page_import_gen[page_id] == gen)
		return 0;
	acc = mxfs_pal_alloc(sizeof(*acc));
	residue = mxfs_pal_alloc(sizeof(*residue) * MXFS_TAUTH_ENTRIES_PER_PAGE);
	if (!acc || !residue) {
		mxfs_pal_free(acc);
		mxfs_pal_free(residue);
		return -ENOMEM;
	}
	acc->n = 0;
	n = mxfs_tauth_ledger_scan_active(ctx->ledger, page_id, gen,
					  dlm_import_scan_cb, acc);
	if (n < 0) {
		mxfs_pal_free(acc);
		mxfs_pal_free(residue);
		return n;
	}
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	for (i = 0; i < acc->n; i++) {
		const struct mxfs_tauth_entry *e = &acc->ent[i];
		struct mxfs_resource_id res;
		int s;

		mxfs_tauth_entry_res(e, &res);
		if (e->state == MXFS_TAUTH_ST_UNKNOWN) {
			/* authority could not be reconstructed: blocks everything */
			dlm_import_holder(ctx, &res, MXFS_DLM_NODE_UNKNOWN, 0, 0,
					  MXFS_LOCK_EX, e, true);
			continue;
		}
		if (e->ex_node) {
			if (dlm_owner_purged(ctx, e->ex_node, e->ex_slot)) {
				if (npurge < (int)MXFS_TAUTH_ENTRIES_PER_PAGE) {
					purge[npurge].node = e->ex_node;
					purge[npurge].slot = e->ex_slot;
					npurge++;
				}
			} else if (e->ex_slot == ctx->local_slot &&
				   e->ex_node != ctx->local_node && e->ex_node != 0 &&
				   e->ex_node != MXFS_DLM_NODE_UNKNOWN) {
				/* a predecessor of OUR slot: a live node never shares a
				 * slot with us, and this node id is not ours */
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: P-TAUTH-IMPORT-RESIDUE-EX type=%u ino=%llu ag=%u "
					     "page=%u slot=%u node=%u inc=%llu — an EX record on this "
					     "node's own slot under a predecessor's node id; its "
					     "departure purge never reached this page, purging it "
					     "by that node id",
					     res.type, (unsigned long long)res.ino, res.ag_number,
					     page_id, e->ex_slot, e->ex_node,
					     (unsigned long long)e->ex_inc);
				if (npurge < (int)MXFS_TAUTH_ENTRIES_PER_PAGE) {
					purge[npurge].node = e->ex_node;
					purge[npurge].slot = e->ex_slot;
					npurge++;
				}
			} else {
				dlm_import_holder(ctx, &res, e->ex_node, e->ex_inc, e->ex_slot,
						  e->ex_mode, e, true);
			}
		}
		for (s = 0; s < 64; s++) {
			mxfs_node_id_t node = 0;
			uint64_t inc = 0;

			if (!(e->holders & (1ULL << s)))
				continue;
			if (ctx->slot_node_cb)
				node = ctx->slot_node_cb(ctx->cb_data, s, &inc);
			/*
			 * 0.75.91 TEST ONLY (D-...-0940): answer the next N shared-bit
			 * slot lookups as UNRESOLVABLE, which is precisely what the
			 * heartbeat table returns when a page is imported a moment before
			 * the peer claims its slot.  Nothing about the ledger is faked —
			 * the bit and its slot are real; only the timing of the table's
			 * view is forced, and that timing is the race itself (1 lap in 4
			 * on 0.75.90).  A defect that reproduces once in four cannot be
			 * verified by laps that pass.  Consumed per use.
			 */
			if (node && mxfs_dl_inject_import_unresolvable > 0) {
				mxfs_dl_inject_import_unresolvable--;
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "mxfs: P-TAUTH-IMPORT-INJECT-UNRESOLVABLE type=%u "
					     "ino=%llu ag=%u slot=%d real_node=%u — TEST ONLY: "
					     "answering this slot lookup as unresolvable (%d "
					     "left)",
					     res.type, (unsigned long long)res.ino,
					     res.ag_number, s, node,
					     mxfs_dl_inject_import_unresolvable);
				node = 0;
				inc = 0;
			}
			/*
			 * 0.75.81 (D-...-0935, measured s570a on 0.75.80,
			 * tests/evidence/20260909T151428Z_ghost_s570a): a shared holder
			 * bit whose slot has NO occupant and whose owner was recovery-
			 * purged is retired here, not installed.
			 *
			 * The measured shape: both nodes came back onto the LUN after
			 * being destroyed mid-mount.  test1 replayed and published the
			 * dead slot 0 — which zeroes that heartbeat record — and its
			 * purge for {node 2904590811, slot 0} walked nothing, because at
			 * that instant it mastered no pages ('P-TAUTH-PURGE ... slot=0
			 * cleared=0 visited=0').  Three seconds later it took the root
			 * inode's page over on demand ('P-TAUTH-TAKEOVER-ONDEMAND
			 * page=24063 departed=2904590811') and imported the dead
			 * incarnation's PR bit for slot 0.  By then slot_node_cb could
			 * no longer name a node for slot 0, so dlm_owner_purged — which
			 * matches on node id only, and must, or a later occupant of the
			 * slot loses its live records (D-0344) — did not match, and the
			 * bit became 'P-TAUTH-IMPORT-ACTIVE type=1 ino=128 owner=
			 * 4294967295 mode=PR', an UNKNOWN blocker.  Nothing can retire
			 * one: demand_collect_holders and fire_bast_records both skip an
			 * UNKNOWN owner by design, and the rule that resolves it
			 * later needs a node to appear in a slot that a published
			 * recovery has emptied for good.  Both mounts then failed on the
			 * root inode — test1 waited its whole budget behind the phantom
			 * ('P-LKTIMEOUT-HOLDER ino=128 holder=4294967295 hmode=PR'
			 * x159) and shut the filesystem down at 120 s, while test2
			 * queued its AG 0 EX behind test1 and timed out at 62 s.
			 *
			 * An empty slot is what makes this safe.  D-0344's hazard is a
			 * LIVE successor in the slot losing its own records; there is
			 * none here, and mxfs_dlm_ledger_purge_owner re-checks occupancy
			 * before it honours a slot.  formation case is
			 * untouched: a slot nobody has been purged from carries no
			 * recorded owner, so its unattributed bit still blocks.
			 */
			if (!node) {
				mxfs_node_id_t pn = dlm_slot_purged_owner(ctx, s);

				if (pn) {
					mxfs_pal_log(MXFS_LOG_WARN,
						     "mxfs: P-TAUTH-IMPORT-RETIRE-VACANT-SLOT "
						     "type=%u ino=%llu ag=%u page=%u slot=%d "
						     "purged_owner=%u — a shared holder bit of a "
						     "recovery-purged owner whose heartbeat slot "
						     "is now empty; no node can ever own or "
						     "release it, so it is retired instead of "
						     "imported as a blocker",
						     res.type, (unsigned long long)res.ino,
						     res.ag_number, page_id, s, pn);
					if (npurge < (int)MXFS_TAUTH_ENTRIES_PER_PAGE) {
						purge[npurge].node = pn;
						purge[npurge].slot = s;
						npurge++;
					}
					continue;
				}
			}
			if (dlm_owner_purged(ctx, node, s)) {
				if (npurge < (int)MXFS_TAUTH_ENTRIES_PER_PAGE) {
					purge[npurge].node = node;
					purge[npurge].slot = s;
					npurge++;
				}
				continue;
			}
			if (node == ctx->local_node && node != 0 &&
			    !dlm_local_entry_any(ctx, &res) && !dlm_pending_exists(ctx, &res)) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: P-TAUTH-IMPORT-RESIDUE type=%u ino=%llu ag=%u "
					     "page=%u slot=%d mode=%s — a shared holder bit on this "
					     "node's own slot with no local entry and no request in "
					     "flight: a predecessor incarnation's grant whose "
					     "departure purge never reached this page; releasing it",
					     res.type, (unsigned long long)res.ino, res.ag_number,
					     page_id, s,
					     mode_name(e->shared_mode ? e->shared_mode : MXFS_LOCK_PR));
				ctx->ledger_import_residue++;
				if (mxfs_tauth_import_residue_release) {
					if (nresidue < (int)MXFS_TAUTH_ENTRIES_PER_PAGE)
						residue[nresidue++] = res;
					/* imported as ours below so the unlock finds a holder entry */
				} else {
					/* DEBUG: keep the phantom as a GRANTED entry of ours (the
					 * pre-fix shape) so the inode layer's own defence against
					 * a grant it does not hold can be exercised on demand. */
					mxfs_pal_log(MXFS_LOG_DEBUG,
						     "mxfs: P-TAUTH-IMPORT-RESIDUE-HELD type=%u ino=%llu "
						     "page=%u — DEBUG: residue kept as our grant",
						     res.type, (unsigned long long)res.ino, page_id);
				}
			}
			dlm_import_holder(ctx, &res, node ? node : MXFS_DLM_NODE_UNKNOWN,
					  inc, (uint16_t)s,
					  e->shared_mode ? e->shared_mode : MXFS_LOCK_PR,
					  e, false);
		}
	}
	if (ctx->page_import_gen && page_id < ctx->page_count)
		ctx->page_import_gen[page_id] = gen;
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	mxfs_pal_free(acc);
	/* lazy retirement of already-purged owners found on this page */
	for (i = 0; i < npurge; i++)
		mxfs_dlm_ledger_purge_owner(ctx, purge[i].node, purge[i].slot);
	/* our slot's residue: the local-master release retires the record in
	 * one ledger transition and promotes whoever waits behind it */
	for (i = 0; i < nresidue; i++) {
		int urc = mxfs_dlm_unlock(ctx, &residue[i]);

		if (urc)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-IMPORT-RESIDUE-RELEASE-FAIL type=%u ino=%llu "
				     "ag=%u page=%u rc=%d — the residue stays a blocker",
				     residue[i].type, (unsigned long long)residue[i].ino,
				     residue[i].ag_number, page_id, urc);
	}
	mxfs_pal_free(residue);
	return 0;
}

/* ── step 4: ordered page handoff ── */

#define DLM_HANDOFF_REQ_INTERVAL_MS   500     /* FREEZE_REQ retry cadence */
#define DLM_HANDOFF_DRAIN_MS          3000    /* freeze: wait for in-flight txns */

/* owner of `page` under the current view (the sorted active list) */
static mxfs_node_id_t dlm_page_owner(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	mxfs_node_id_t m;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	m = dlm_page_master_locked(ctx, page);
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return m;
}

static bool dlm_node_in_view(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	int i;
	bool in = false;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	for (i = 0; i < ctx->active_nodes.count; i++)
		if (ctx->active_nodes.nodes[i] == node) {
			in = true;
			break;
		}
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return in;
}

/*
 * 0.75.69 (D-TAKEOVER-TREATS-PREVIOUS-ERA-PREPARED-TARGET-AS-LIVE-...-0927):
 * is the incarnation {node, inc} a DEAD authority — one no live member
 * carries?  Decided from durable shared state, not from what this mount
 * happens to have seen: an incarnation this mount purged is dead; one that
 * is the current occupant of a heartbeat slot is alive (heartbeating, or
 * dead but not yet recovered — its pages wait for the recovery, exactly as
 * before); one in this mount's view is alive; anything else is an
 * incarnation of a previous era whose slot has moved on, and its pages are
 * nobody's until taken over.  Measured before this (tests/evidence/
 * 20260908T230313Z_restart_s556, 20260908T231212Z_restart_s557): the pages
 * left PREPARED across a whole-cluster restart were found by the takeover
 * of the settled predecessor and refused as 'a live target consumes it',
 * and once the mount that had settled them was gone no later mount ever
 * named those incarnations again — AG 0's page stayed under one for good
 * and every mount of the LUN hung on it.
 */
/*
 * 0.84.5 (D-...-0960): was {node, inc} handed to a bulk takeover by name?
 * Such an incarnation is settled and dead by the caller's own proof (a
 * settled heartbeat record, a goodbye); the slot map cannot say so for this
 * node's OWN predecessor — the node is in its own view and occupies its
 * own slot — and the purged list must not name this node's id at all.
 */
static bool dlm_authority_settled(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
				  uint64_t inc)
{
	int i;

	for (i = 0; i < ctx->settled_auth_count; i++)
		if (ctx->settled_auth[i].node == node && ctx->settled_auth[i].inc == inc)
			return true;
	return false;
}

static void dlm_authority_settle_record(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
					uint64_t inc)
{
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	if (!dlm_authority_settled(ctx, node, inc) &&
	    ctx->settled_auth_count < MXFS_MAX_NODES) {
		ctx->settled_auth[ctx->settled_auth_count].node = node;
		ctx->settled_auth[ctx->settled_auth_count].inc = inc;
		ctx->settled_auth_count++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
}

static bool dlm_authority_dead(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
			       uint64_t inc)
{
	if (node == 0 || node == MXFS_DLM_NODE_UNKNOWN)
		return false;
	if (node == ctx->local_node && inc == ctx->local_inc)
		return false;
	if (dlm_owner_purged(ctx, node, -1))
		return true;
	if (dlm_authority_settled(ctx, node, inc))
		return true;
	if (!ctx->occupant_cb)
		return false;           /* no slot map to ask: never steal */
	if (ctx->occupant_cb(ctx->cb_data, node, inc))
		return false;
	return !dlm_node_in_view(ctx, node);
}

/* ── 0.75.20 (D-TCP-VIEW-CHANGE-HANDOFF-PREPARES-PAGE-TO-THE-NODE-THAT-JUST-
 * SAID-GOODBYE-...-0909): departing members ──
 *
 * A clean departure hands its pages out BEFORE its goodbye, over the view
 * without itself.  Until the goodbye drops it from our view, the general
 * mapping (dlm_page_owner) still names it as the owner of those pages, so
 * the FROZEN receiver treated each such page as a relay and the eager pass
 * handed it straight back to the node that was leaving (measured s514k:
 * P-TAUTH-ACTIVATE seq=19 of the departer's hand-off, P-GOODBYE-RX,
 * P-TAUTH-PREPARED seq=20 target=<departer> why=view-change; once in twelve
 * departures at the 500 ms tick cadence).  The departer flags its FROZENs;
 * from the first one the receiver routes hand-offs over the view WITHOUT
 * the departing members — the departer's own mapping. */

/* Caller holds active_nodes.lock. */
static bool dlm_node_departing_locked(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	int i;

	for (i = 0; i < ctx->departing_count; i++)
		if (ctx->departing_nodes[i].node == node)
			return true;
	return false;
}

static bool dlm_node_departing(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	bool d;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	d = dlm_node_departing_locked(ctx, node);
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return d;
}

/* true = newly recorded */
static bool dlm_node_mark_departing(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
				    uint64_t inc)
{
	bool added = false;

	if (node == 0 || node == ctx->local_node)
		return false;
	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	if (!dlm_node_departing_locked(ctx, node) &&
	    ctx->departing_count < MXFS_MAX_NODES) {
		ctx->departing_nodes[ctx->departing_count].node = node;
		ctx->departing_nodes[ctx->departing_count].inc = inc;
		ctx->departing_count++;
		added = true;
	}
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	return added;
}

/* Caller holds active_nodes.lock: drop departing entries the new view
 * (`nodes`, `count`) no longer contains. */
static void dlm_departing_prune_locked(struct mxfs_dlm_ctx *ctx,
				       const mxfs_node_id_t *nodes, int count)
{
	int i = 0, j;

	while (i < ctx->departing_count) {
		bool in = false;

		for (j = 0; j < count; j++)
			if (nodes[j] == ctx->departing_nodes[i].node) {
				in = true;
				break;
			}
		if (in) {
			i++;
			continue;
		}
		ctx->departing_nodes[i] = ctx->departing_nodes[ctx->departing_count - 1];
		ctx->departing_count--;
	}
}

/* owner of `page` for HAND-OFF routing: the sorted active list WITHOUT the
 * members that have announced their departure.  Equals dlm_page_owner
 * whenever nobody is departing. */
static mxfs_node_id_t dlm_page_handoff_owner(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	mxfs_node_id_t live[MXFS_MAX_NODES];
	mxfs_node_id_t m;
	int i, n = 0;

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	if (ctx->departing_count == 0) {
		m = dlm_page_master_locked(ctx, page);
		mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
		return m;
	}
	for (i = 0; i < ctx->active_nodes.count; i++)
		if (!dlm_node_departing_locked(ctx, ctx->active_nodes.nodes[i]))
			live[n++] = ctx->active_nodes.nodes[i];
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	if (n == 0)
		return ctx->local_node;
	return live[page % (uint32_t)n];
}

static inline uint8_t dlm_page_state(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	return (ctx->page_state && page < ctx->page_count) ? ctx->page_state[page] :
	       DLM_PS_MINE;
}

/* takes table_rwlock (write) */
static void dlm_set_page_state(struct mxfs_dlm_ctx *ctx, uint32_t page, uint8_t st)
{
	if (!ctx->page_state || page >= ctx->page_count)
		return;
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	ctx->page_state[page] = st;
	if (st == DLM_PS_MINE && ctx->page_import_gen)
		ctx->page_import_gen[page] = ~0ULL;     /* re-import after activation */
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
}

/* any transaction on `page` still between decision and finalize? */
static bool dlm_page_has_pending(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	uint32_t i;
	bool busy = false;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (i = 0; i < ctx->bucket_count && !busy; i++) {
		struct mxfs_lock *lk;

		for (lk = ctx->buckets[i]; lk; lk = lk->next) {
			if ((lk->state == MXFS_LSTATE_PENDING_DURABLE ||
			     lk->state == MXFS_LSTATE_PENDING_RELEASE) &&
				dlm_res_page(ctx, &lk->resource) == page) {
				busy = true;
				break;
			}
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return busy;
}

/* diagnostic: how many table entries on `page` are between decision and
 * finalize (what dlm_page_freeze_drain waits for). */
int mxfs_dlm_page_pending_count(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	uint32_t i;
	int n = 0;

	if (!ctx)
		return 0;
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock *lk;

		for (lk = ctx->buckets[i]; lk; lk = lk->next)
			if ((lk->state == MXFS_LSTATE_PENDING_DURABLE ||
			     lk->state == MXFS_LSTATE_PENDING_RELEASE) &&
				dlm_res_page(ctx, &lk->resource) == page)
				n++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return n;
}

/* ruling 6: freeze = stop deciding, then drain every in-flight
 * transaction on the page (bounded).  true = drained. */
static bool dlm_page_freeze_drain(struct mxfs_dlm_ctx *ctx, uint32_t page)
{
	uint64_t t0 = mxfs_pal_time_ms();

	dlm_set_page_state(ctx, page, DLM_PS_FROZEN);
	while (dlm_page_has_pending(ctx, page)) {
		if (mxfs_pal_time_ms() - t0 > DLM_HANDOFF_DRAIN_MS) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-FREEZE-DRAIN-TIMEOUT page=%u — in-flight "
				     "transition did not finalize in %d ms; page stays frozen, "
				     "NOT prepared (fail closed)", page, DLM_HANDOFF_DRAIN_MS);
			return false;
		}
		mxfs_pal_sleep_ms(2);
	}
	return true;
}

static void dlm_send_handoff(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t to,
			     uint32_t page, uint8_t kind,
			     mxfs_node_id_t target_node, uint64_t target_inc,
			     uint64_t prepared_seq, mxfs_node_id_t auth_node,
			     uint64_t auth_inc)
{
	struct mxfs_dlm_page_handoff m;

	if (!ctx->send_cb || to == ctx->local_node)
		return;
	memset(&m, 0, sizeof(m));
	m.hdr.magic = MXFS_DLM_MAGIC;
	m.hdr.version = MXFS_DLM_VERSION;
	m.hdr.type = MXFS_MSG_PAGE_HANDOFF;
	m.hdr.length = sizeof(m);
	m.hdr.sender = ctx->local_node;
	m.hdr.target = to;
	m.hdr.epoch = ctx->current_epoch;
	m.page = page;
	m.kind = kind;
	if (kind == MXFS_HANDOFF_FROZEN && ctx->departing)
		m.flags |= MXFS_HANDOFF_F_DEPARTING;
	m.target_node = target_node;
	m.target_inc = target_inc;
	m.config_id = ctx->my_view_hash;
	m.prepared_seq = prepared_seq;
	m.auth_node = auth_node;
	m.auth_inc = auth_inc;
	ctx->send_cb(ctx, to, &m, sizeof(m));
}

/* the page became ours: adopt it (no I/O beyond what activate did) */
static void dlm_page_now_mine(struct mxfs_dlm_ctx *ctx, uint32_t page, const char *how)
{
	dlm_set_page_state(ctx, page, DLM_PS_MINE);
	ctx->handoff_activations++;
	if (!mxfs_tauth_pass_quiet)
		mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: P-TAUTH-PAGE-MINE page=%u via=%s owner_gen=%#llx",
			     page, how, (unsigned long long)ctx->ledger_gen);
}

/* The bootstrap node (lowest live heartbeat slot, settled) per the mount
 * layer; 0 = unknown / not settled. */
static mxfs_node_id_t dlm_bootstrap_node(struct mxfs_dlm_ctx *ctx)
{
	if (!ctx->bootstrap_cb)
		return 0;
	return ctx->bootstrap_cb(ctx->cb_data) ? ctx->local_node : 0;
}

/*
 * The view names this node owner of `page` but the page is not (known to
 * be) ours: read the platter and take the step the durable chain allows —
 * consume a PREPARED aimed at us, claim UNOWNED as the bootstrap node, or
 * ask the current authority (or the target it is prepared to) to hand it
 * over.  0 = ours now; -EAGAIN = parked (a request is in flight or a
 * takeover is owed); other = fail closed.
 */
static int dlm_page_acquire(struct mxfs_dlm_ctx *ctx, uint32_t page, uint64_t gen)
{
	struct mxfs_tauth_page_auth a;
	mxfs_node_id_t to;
	uint64_t now;
	int rc;

	rc = mxfs_tauth_ledger_page_auth(ctx->ledger, page, true, &a);
	if (rc == -EUCLEAN) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-PAGE-UNKNOWN-AUTH page=%u — no usable authority "
			     "image; every resource on it refuses (fail closed)", page);
		return -EIO;
	}
	if (rc)
		return rc;

	if (a.state == MXFS_TAUTH_PG_ACTIVE && a.auth_node == ctx->local_node &&
	    a.auth_inc == ctx->local_inc) {
		rc = mxfs_tauth_ledger_activate(ctx->ledger, page, gen, 0, false);
		if (rc == 0) {
			dlm_page_now_mine(ctx, page, "adopt");
			return 0;
		}
		return rc == -ESTALE ? -EAGAIN : rc;
	}
	if (a.state == MXFS_TAUTH_PG_PREPARED && a.target_node == ctx->local_node &&
	    a.target_inc == ctx->local_inc) {
		/* 0.75.8: a takeover's PREPARED image (written by the successor,
		 * not the authority) can be read here before its FROZEN arrives */
		dlm_page_departed_authority(ctx, page, a.auth_node, a.auth_inc,
					    a.writer_node, "prepared");
		rc = mxfs_tauth_ledger_activate(ctx->ledger, page, gen, a.seq, false);
		if (rc == 0) {
			dlm_page_now_mine(ctx, page, "prepared");
			return 0;
		}
		return rc == -ESTALE ? -EAGAIN : rc;
	}
	if (a.state == MXFS_TAUTH_PG_PREPARED && a.auth_node == ctx->local_node &&
	    a.auth_inc == ctx->local_inc) {
		/* we handed it off; only a recovery-purged target lets us take it
		 * back (ruling 2: never retarget while the target can write) */
		if (dlm_owner_purged(ctx, a.target_node, -1)) {
			rc = mxfs_tauth_ledger_prepare(ctx->ledger, page, gen, ctx->local_node,
						       ctx->local_inc, 0, 0, true, NULL);
			if (rc == 0) {
				struct mxfs_tauth_page_auth b;

				ctx->handoff_retargets++;
				if (mxfs_tauth_ledger_page_auth(ctx->ledger, page, false, &b) == 0 &&
				    mxfs_tauth_ledger_activate(ctx->ledger, page, gen, b.seq, false) == 0) {
					dlm_page_now_mine(ctx, page, "retarget-self");
					return 0;
				}
			}
		}
		return -EAGAIN;
	}
	if (a.state == MXFS_TAUTH_PG_UNOWNED) {
		mxfs_node_id_t bn = dlm_bootstrap_node(ctx);

		if (bn == ctx->local_node) {
			rc = mxfs_tauth_ledger_activate(ctx->ledger, page, gen, 0, true);
			if (rc == 0) {
				dlm_page_now_mine(ctx, page, "bootstrap");
				return 0;
			}
			return rc == -ESTALE ? -EAGAIN : rc;
		}
		/*
		 * (D-0345, proven by instrument in tests/tauth/unowned_page_test):
		 * an UNOWNED page has no auth_node to route to, so this branch
		 * used to park every request on it until the caller's budget was
		 * gone — remote requesters saw REMASTER x60, local ones prepare
		 * -EAGAIN x10 (rig: AG-1/2/3/33 during the 32-node ramp).  Ask the
		 * bootstrap node: its FREEZE_REQ handler claims UNOWNED as
		 * bootstrap and PREPAREs the page to us ("bootstrap-for-request").
		 */
		to = ctx->bootstrap_node_cb ? ctx->bootstrap_node_cb(ctx->cb_data, NULL) : 0;
		if (to == 0 || to == ctx->local_node || !dlm_node_in_view(ctx, to))
			return -EAGAIN;
		now = mxfs_pal_time_ms();
		if (ctx->page_req_ms && now - ctx->page_req_ms[page] >= DLM_HANDOFF_REQ_INTERVAL_MS) {
			ctx->page_req_ms[page] = now;
			ctx->handoff_reqs++;
			dlm_set_page_state(ctx, page, DLM_PS_WANTED);
			dlm_send_handoff(ctx, to, page, MXFS_HANDOFF_FREEZE_REQ, ctx->local_node,
					 ctx->local_inc, 0, 0, 0);
		}
		return -EAGAIN;
	}
	/* owned (or prepared) by someone else: ask along the chain */
	to = (a.state == MXFS_TAUTH_PG_PREPARED &&
	      !dlm_owner_purged(ctx, a.target_node, -1)) ? a.target_node : a.auth_node;
	if (to == 0 || to == ctx->local_node || !dlm_node_in_view(ctx, to)) {
		/*
		 * 0.75.6 (s510b arm 1): this branch parked every request
		 * on the page silently — the requester saw only 'prepare=60' /
		 * REMASTER x60 and the platter had to be read by hand to learn
		 * that the authority was a departed incarnation nobody had taken
		 * over.  Name the page, the authority and why it is not reachable.
		 */
		static atomic_t p_parked = ATOMIC_INIT(0);
		mxfs_node_id_t bn;
		bool stalled;

		/*
		 * 0.75.9 (D-...-0907): a settled, purged authority's pages were
		 * transferred ONLY by the departure worker's bulk takeover — a
		 * purge scan and a takeover scan over every page (~8 s at 26426
		 * pages over iSCSI) — and every request parked here until that
		 * pass reached its page.  Measured (sameboot_remount arm 2 on
		 * 0.75.8): the remounter's own put_super SB summary lock parked
		 * x60 on page 26066 (purged=1 bootstrap=1), exhausted its 60 x
		 * 100 ms budget one second before the bulk pass prepared the page,
		 * and a CLEAN unmount was recorded DIRTY (slot and PR key
		 * retained, same-boot remount refused).  The per-page transition
		 * the bulk pass makes is legal the moment the authority is in
		 * purged_owners; make it here, on demand, for the page asked for.
		 */
		/*
		 * 0.84.5 (D-...-0960, measured s588b/s588c and a plain deploy):
		 * the test above was the id-keyed purged list, which never names
		 * this node's OWN previous incarnation — the settled predecessor
		 * whose ~15k pages the takeover-only pass moves at ~10 ms each
		 * after every last-leaver remount.  For the whole of that pass
		 * (157 s) a request on one of its pages fell through to the ask
		 * below, and the ask went to nobody (bn == us); a joiner's
		 * root-inode request was answered REMASTER 60 times in 18 s and
		 * its mount shut its filesystem down.  Ask the slot-map question
		 * the FREEZE_REQ handler already asks (dlm_authority_dead), which
		 * now also names the incarnations a bulk takeover was handed.
		 */
		if (dlm_bootstrap_node(ctx) == ctx->local_node &&
		    dlm_authority_dead(ctx, a.auth_node, a.auth_inc)) {
			if (mxfs_dl_no_ondemand_takeover)
				return -EINPROGRESS;    /* TEST ONLY: wait for the bulk pass */
			rc = dlm_takeover_page(ctx, page, a.auth_node, a.auth_inc,
					       "takeover-ondemand", 0, 0);
			if (rc == 1 && ctx->page_state[page] == DLM_PS_MINE)
				return 0;
			/* prepared to its view owner (FROZEN sent), or the image
			 * moved under us: the next retry re-reads and re-routes.  A
			 * transition, not a routing disagreement: the requester waits
			 * on the takeover count, not on its retry budget. */
			return -EINPROGRESS;
		}
		/*
		 * Not the bootstrap node: the bootstrap node is the only writer
		 * of a takeover, so ask IT for the page, naming the authority we
		 * read; its FREEZE_REQ handler takes the page over on demand once
		 * that authority is purged there, and answers NOT_OWNER (naming
		 * the same authority) until then.
		 */
		bn = ctx->bootstrap_node_cb ? ctx->bootstrap_node_cb(ctx->cb_data, NULL) : 0;
		/*
		 * 0.75.10 (measured, sameboot_remount arm 1 x3 on 0.75.9): for the
		 * first ~2 s after a join the lowest-live-slot election names the
		 * JOINER itself — its heartbeat monitor has not yet read the lower
		 * slot's beat (one MXFS_DISKLOCK_HB_INTERVAL_MS) — while the
		 * bootstrap test above says it is not the bootstrap node.  The ask
		 * went nowhere and every request parked until the bulk pass.  An
		 * unsettled election asks every node in the view instead: the real
		 * bootstrap node takes the page over, the others answer NOT_OWNER.
		 */
		if (bn == ctx->local_node)
			bn = 0;
		now = mxfs_pal_time_ms();
		/* an ask that went a whole cadence unanswered (decided before the
		 * re-ask below moves the stamp) */
		stalled = ctx->page_req_ms && ctx->page_req_ms[page] &&
			  now - ctx->page_req_ms[page] >= DLM_HANDOFF_REQ_INTERVAL_MS;
		if (ctx->page_req_ms &&
		    now - ctx->page_req_ms[page] >= DLM_HANDOFF_REQ_INTERVAL_MS) {
			mxfs_node_id_t ask[MXFS_MAX_NODES];
			int nask = 0, i;

			if (bn != 0 && dlm_node_in_view(ctx, bn)) {
				ask[nask++] = bn;
			} else {
				mxfs_pal_mutex_lock(ctx->active_nodes.lock);
				for (i = 0; i < ctx->active_nodes.count && nask < MXFS_MAX_NODES; i++)
					if (ctx->active_nodes.nodes[i] != ctx->local_node &&
					    ctx->active_nodes.nodes[i] != 0)
						ask[nask++] = ctx->active_nodes.nodes[i];
				mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
			}
			if (nask) {
				ctx->page_req_ms[page] = now;
				ctx->handoff_reqs++;
				dlm_set_page_state(ctx, page, DLM_PS_WANTED);
				for (i = 0; i < nask; i++)
					dlm_send_handoff(ctx, ask[i], page, MXFS_HANDOFF_FREEZE_REQ,
							 ctx->local_node, ctx->local_inc, 0,
							 a.auth_node, a.auth_inc);
			}
		}
		/*
		 * 0.75.13: the line names a STALL — an ask that went a whole
		 * cadence unanswered — not the first pass through this branch,
		 * which every asynchronous ask makes once (one line per join on
		 * 0.75.12, ~100 ms, the request already in flight).
		 */
		if (stalled && atomic_inc_return(&p_parked) <= 400)
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-PAGE-PARKED page=%u state=%u auth=%u/%llu "
				     "target=%u/%llu to=%u in_view=%d purged=%d dead=%d bootstrap=%d "
				     "bn=%u bn_in_view=%d we=%u/%llu — the page's authority is "
				     "not reachable; waiting for a takeover that names it",
				     page, a.state, a.auth_node,
				     (unsigned long long)a.auth_inc, a.target_node,
				     (unsigned long long)a.target_inc, to,
				     to ? (dlm_node_in_view(ctx, to) ? 1 : 0) : 0,
				     dlm_owner_purged(ctx, a.auth_node, -1) ? 1 : 0,
				     dlm_authority_dead(ctx, a.auth_node, a.auth_inc) ? 1 : 0,
				     dlm_bootstrap_node(ctx) == ctx->local_node ? 1 : 0,
				     bn, bn ? (dlm_node_in_view(ctx, bn) ? 1 : 0) : 0,
				     ctx->local_node, (unsigned long long)ctx->local_inc);
		/*
		 * departed (or unreachable) authority: the certified successor's
		 * takeover (mxfs_dlm_handoff_takeover) re-prepares it; wait.
		 * 0.84.5: when the authority is dead by the slot map and a live
		 * bootstrap node other than us is in view, that wait is on a
		 * transition someone live is making (its NOT_OWNER answers relay
		 * its takeover count): report it as one, so the requester's budget
		 * is not spent on it.
		 */
		if (dlm_authority_dead(ctx, a.auth_node, a.auth_inc) &&
		    bn != 0 && dlm_node_in_view(ctx, bn))
			return -EINPROGRESS;
		/*
		 * instrument (D-...-0960, s592e): a joiner's mount spent nine
		 * 60-retry budgets on 'prepare' answers from this branch while
		 * its authority was dead and a bootstrap was in view at the
		 * PARKED lines — which are capped per load and had gone quiet.
		 * Name every term of the decision each time it answers -EAGAIN.
		 */
		pr_warn_ratelimited(
		    "mxfs: P960-PARK-NOT-TRANSITION page=%u state=%u auth=%u/%llu dead=%d "
		    "purged=%d settled=%d occupant=%d auth_in_view=%d bn=%u bn_in_view=%d "
		    "we=%u/%llu — parked on an unreachable authority without a transition to wait on\n",
		    page, a.state, a.auth_node, (unsigned long long)a.auth_inc,
		    dlm_authority_dead(ctx, a.auth_node, a.auth_inc) ? 1 : 0,
		    dlm_owner_purged(ctx, a.auth_node, -1) ? 1 : 0,
		    dlm_authority_settled(ctx, a.auth_node, a.auth_inc) ? 1 : 0,
		    ctx->occupant_cb ?
			(ctx->occupant_cb(ctx->cb_data, a.auth_node, a.auth_inc) ? 1 : 0) : -1,
			dlm_node_in_view(ctx, a.auth_node) ? 1 : 0,
			bn, bn ? (dlm_node_in_view(ctx, bn) ? 1 : 0) : 0,
			ctx->local_node, (unsigned long long)ctx->local_inc);
		return -EAGAIN;
	}
	now = mxfs_pal_time_ms();
	if (ctx->page_req_ms && now - ctx->page_req_ms[page] >= DLM_HANDOFF_REQ_INTERVAL_MS) {
		ctx->page_req_ms[page] = now;
		ctx->handoff_reqs++;
		dlm_set_page_state(ctx, page, DLM_PS_WANTED);
		dlm_send_handoff(ctx, to, page, MXFS_HANDOFF_FREEZE_REQ, ctx->local_node,
				 ctx->local_inc, 0, a.auth_node, a.auth_inc);
	}
	return -EAGAIN;
}

/* 0 = the page is ours under `gen` (decisions allowed); -EAGAIN = park. */
static int dlm_page_ensure_mine(struct mxfs_dlm_ctx *ctx, uint32_t page, uint64_t gen)
{
	if (!ctx->page_state || page >= ctx->page_count)
		return 0;
	if (ctx->page_state[page] == DLM_PS_MINE &&
	    mxfs_tauth_ledger_page_mine(ctx->ledger, page))
		return 0;
	if (dlm_page_owner(ctx, page) != ctx->local_node) {
		if (ctx->page_state[page] == DLM_PS_MINE)
			dlm_set_page_state(ctx, page, DLM_PS_FROZEN);
		/* instrument (D-...-0960, s592e): the silent park — the view no
		 * longer names us the page's owner */
		mxfs_probe_ratelimited(
		    "mxfs: P960-PARK-NOT-OWNER page=%u state=%u owner=%u we=%u — parked: the view names another owner\n",
		    page, ctx->page_state[page], dlm_page_owner(ctx, page), ctx->local_node);
		return -EAGAIN;
	}
	return dlm_page_acquire(ctx, page, gen);
}

/* freeze + PREPARE one of our pages to {target, inc}; tells the target.
 * 0 = prepared (or already), -EAGAIN = drain not complete, else error. */
static int dlm_page_hand_to(struct mxfs_dlm_ctx *ctx, uint32_t page,
			    mxfs_node_id_t target, uint64_t target_inc,
			    const char *why, bool departing)
{
	uint64_t seq = 0;
	int rc;

	if (!target_inc)
		return -ENOENT;
	if (!dlm_page_freeze_drain(ctx, page))
		return -EAGAIN;
	/*
	 * 0.75.18 (D-TCP-VIEW-CHANGE-HANDOFF-PREPARES-PAGE-TO-THE-NODE-THAT-
	 * JUST-SAID-GOODBYE-...-0909): the caller computed `target` under the
	 * view of its own pass, and the freeze drain above can wait seconds.
	 * A goodbye processed in between moves the view on: the target is no
	 * longer the owner and may already be a retired identity (measured
	 * s514d: P-GOODBYE-RX, MXFS-MEMBERSHIP active_count=1, then this
	 * function PREPARED page 16642 to the departed incarnation under the
	 * NEW config id; the successor's AG 0 request parked 13 s on it).
	 * Re-read the owner now, just before the record is written; a stale
	 * target leaves the page FROZEN for the next pass to route.
	 *
	 * 0.75.19: the re-check must use the CALLER's mapping.  The departing
	 * node maps its pages over the view WITHOUT itself (mxfs_dlm_handoff_
	 * depart), while dlm_page_owner still names this node for them; the
	 * 0.75.18 check refused every depart hand-off (measured s514g-i:
	 * P-TAUTH-HANDOFF-STALE-TARGET why=depart on every leave, pages_left=1,
	 * the root inode's page stranded under the departed authority until
	 * the successor's takeover, every armed rejoin 14 s).  A departing
	 * node only requires its target to be a live member.
	 */
	if (!dlm_node_in_view(ctx, target) ||
	    (!departing && (dlm_node_departing(ctx, target) ||
			    dlm_page_handoff_owner(ctx, page) != target))) {
		ctx->handoff_stale_targets++;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-HANDOFF-STALE-TARGET page=%u to=%u/%llu why=%s "
			     "in_view=%d departing=%d — the view moved during the freeze "
			     "drain; not prepared, re-routed on the next pass",
			     page, target, (unsigned long long)target_inc, why,
			     dlm_node_in_view(ctx, target) ? 1 : 0,
			     dlm_node_departing(ctx, target) ? 1 : 0);
		ctx->handoff_scan = true;
		return -ESTALE;
	}
	rc = mxfs_tauth_ledger_prepare(ctx->ledger, page, ctx->ledger_gen, target,
				       target_inc, 0, 0, false, &seq);
	if (rc)
		return rc;
	ctx->handoff_prepares++;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-TAUTH-HANDOFF page=%u to=%u/%llu seq=%llu why=%s",
		     page, target, (unsigned long long)target_inc,
		     (unsigned long long)seq, why);
	dlm_send_handoff(ctx, target, page, MXFS_HANDOFF_FROZEN, target, target_inc,
			 seq, ctx->local_node, ctx->local_inc);
	return 0;
}

int mxfs_dlm_process_page_handoff(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
				  const struct mxfs_dlm_page_handoff *msg)
{
	struct mxfs_tauth_page_auth a;
	uint32_t page;
	int rc;

	if (!ctx || !msg || !dlm_ledger_active(ctx) || !ctx->page_state)
		return -EINVAL;
	page = msg->page;
	if (page >= ctx->page_count)
		return -EINVAL;

	switch (msg->kind) {
	case MXFS_HANDOFF_FREEZE_REQ: {
		uint64_t seq = 0;

		if (msg->config_id != ctx->my_view_hash ||
		    dlm_page_owner(ctx, page) != sender ||
		    msg->target_node != sender) {
			ctx->handoff_defers++;
			/* (D-0345 instrumented): a DEFER that repeats forever is a
			 * view disagreement — name both sides' cookies and our owner */
			mxfs_probe_ratelimited(
			    "mxfs: P-TAUTH-HANDOFF-DEFER page=%u sender=%u my_owner=%u "
			    "cfg_match=%d my_view=%#llx/%u sender_cfg=%#llx\n",
			    page, sender, dlm_page_owner(ctx, page),
			    msg->config_id == ctx->my_view_hash ? 1 : 0,
			    (unsigned long long)ctx->my_view_hash, ctx->my_view_count,
			    (unsigned long long)msg->config_id);
			dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_DEFER, sender,
					 msg->target_inc, 0, 0, 0);
			return 0;
		}
		rc = mxfs_tauth_ledger_page_auth(ctx->ledger, page, true, &a);
		if (rc)
			return rc;      /* unreadable: nothing to say (fail closed) */
		if (a.state == MXFS_TAUTH_PG_UNOWNED) {
			if (dlm_bootstrap_node(ctx) != ctx->local_node) {
				ctx->handoff_not_owner++;
				dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_NOT_OWNER, sender,
						 msg->target_inc, 0, 0, 0);
				return 0;
			}
			/*
			 * (D-0349, design-consult ruling option (c)): one durable
			 * transition UNOWNED -> PREPARED(self, target=sender) instead
			 * of ACTIVE(self) then PREPARED — halves the serialized writes
			 * on the bootstrap node at formation.  The page is frozen here
			 * (we are its authority, prepared away); the sender activates.
			 */
			rc = mxfs_tauth_ledger_prepare_unowned(ctx->ledger, page, ctx->ledger_gen,
							       sender, msg->target_inc, &seq);
			if (rc == -EPERM) {
				ctx->handoff_not_owner++;
				dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_NOT_OWNER, sender,
						 msg->target_inc, 0, 0, 0);
				return 0;
			}
			if (rc)
				return rc;
			ctx->handoff_prepares++;
			dlm_set_page_state(ctx, page, DLM_PS_FROZEN);
			ctx->handoff_frozen++;
			dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_FROZEN, sender,
					 msg->target_inc, seq, ctx->local_node, ctx->local_inc);
			return 0;
		}
		if (a.auth_node != ctx->local_node || a.auth_inc != ctx->local_inc) {
			/*
			 * 0.75.9 (D-...-0907): the requester masters this page under
			 * the view (checked above) and its authority is a departed
			 * incarnation we have settled and purged: take the page over
			 * for the requester now (prepare to it, FROZEN) instead of
			 * leaving it to the bulk pass.  Any other authority, or one
			 * not yet purged here: NOT_OWNER naming it, as before.
			 */
			if (dlm_bootstrap_node(ctx) == ctx->local_node &&
			    a.auth_node != 0 && a.auth_node != MXFS_DLM_NODE_UNKNOWN) {
				/* 0.75.69 (D-...-0927): dead by the slot map, not only by
				 * this mount's own purge list */
				bool purged = dlm_authority_dead(ctx, a.auth_node, a.auth_inc);

				/* 0.75.11: the request names the sender's incarnation;
				 * the slot map may not yet (one heartbeat interval after
				 * its claim: DECLINED rc=-11 sender_inc_known=0, s513g 2f) */
				rc = (purged && !mxfs_dl_no_ondemand_takeover) ?
				     dlm_takeover_page(ctx, page, a.auth_node, a.auth_inc,
						       "takeover-request", sender,
						       msg->target_inc) : -ENOENT;
				if (rc == 1)
					return 0;
				/*
				 * 0.84.5 (D-...-0960): a dead authority this node could not
				 * (or was told not to) take over on demand is one the bulk
				 * pass will reach; the NOT_OWNER answer carries this
				 * node's takeover count so the asker can wait on progress
				 * rather than on its retry budget.
				 */
				if (purged) {
					ctx->handoff_not_owner++;
					pr_warn_ratelimited(
					    "mxfs: P960-AUTH-TRANSITION-DECLINE page=%u sender=%u/%llu "
					    "auth=%u/%llu rc=%d progress=%llu — dead authority not taken "
					    "over for this ask; NOT_OWNER carries the takeover count\n",
					    page, sender, (unsigned long long)msg->target_inc,
					    a.auth_node, (unsigned long long)a.auth_inc, rc,
					    (unsigned long long)ctx->takeover_pages_done);
					dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_NOT_OWNER, sender,
							 msg->target_inc, ctx->takeover_pages_done,
							 a.auth_node, a.auth_inc);
					return 0;
				}
				/* instrument (D-...-0907, s513aa1): the joiner parked ~2 s
				 * on requests this node answered NOT_OWNER; name why */
				pr_warn_ratelimited(
				    "mxfs: P-TAUTH-TAKEOVER-REQUEST-DECLINED page=%u sender=%u/%llu "
				    "auth=%u/%llu purged=%d rc=%d sender_inc_known=%llu — answering "
				    "NOT_OWNER; the requester asks again on its cadence\n",
				    page, sender, (unsigned long long)msg->target_inc,
				    a.auth_node, (unsigned long long)a.auth_inc, purged ? 1 : 0, rc,
				    (unsigned long long)(ctx->node_inc_cb ?
							 ctx->node_inc_cb(ctx->cb_data, sender) : 0));
			}
			ctx->handoff_not_owner++;
			dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_NOT_OWNER, sender,
					 msg->target_inc, 0, a.auth_node, a.auth_inc);
			return 0;
		}
		if (a.state == MXFS_TAUTH_PG_PREPARED &&
		    (a.target_node != sender || a.target_inc != msg->target_inc)) {
			if (!dlm_owner_purged(ctx, a.target_node, -1)) {
				ctx->handoff_defers++;
				dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_DEFER, sender,
						 msg->target_inc, 0, a.target_node, a.target_inc);
				return 0;
			}
			rc = mxfs_tauth_ledger_prepare(ctx->ledger, page, ctx->ledger_gen, sender,
						       msg->target_inc, 0, 0, true, &seq);
			if (rc == 0)
				ctx->handoff_retargets++;
		} else if (a.state == MXFS_TAUTH_PG_PREPARED) {
			seq = a.seq;    /* already prepared to the requester */
			rc = 0;
		} else {
			if (!dlm_page_freeze_drain(ctx, page))
				return -EAGAIN;
			rc = mxfs_tauth_ledger_prepare(ctx->ledger, page, ctx->ledger_gen, sender,
						       msg->target_inc, 0, 0, false, &seq);
			if (rc == 0)
				ctx->handoff_prepares++;
		}
		if (rc == -EPERM) {
			ctx->handoff_not_owner++;
			dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_NOT_OWNER, sender,
					 msg->target_inc, 0, 0, 0);
			return 0;
		}
		if (rc)
			return rc;      /* uncertain / refused: no FROZEN (fail closed) */
		dlm_set_page_state(ctx, page, DLM_PS_FROZEN);
		ctx->handoff_frozen++;
		dlm_send_handoff(ctx, sender, page, MXFS_HANDOFF_FROZEN, sender, msg->target_inc,
				 seq, ctx->local_node, ctx->local_inc);
		return 0;
	}
	case MXFS_HANDOFF_FROZEN:
		if (msg->target_node != ctx->local_node || msg->target_inc != ctx->local_inc)
			return 0;
		/*
		 * D-0953: this mount is leaving.  Activating the page now would
		 * make it ours AFTER our own departure pass froze and handed off
		 * everything we served, so it would leave with us as a dead
		 * authority.  Left PREPARED to this incarnation it is retargeted
		 * by the successor's takeover of our goodbye (a PREPARED page whose
		 * target is dead is consumed by nobody and retargetable), which is
		 * the state the same successor already handles for a crash.
		 */
		if (ctx->shutting_down) {
			ctx->handoff_refused_leaving++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-HANDOFF-REFUSED-LEAVING page=%u from=%u "
				     "auth=%u/%llu total=%llu — a page handed to a mount that is "
				     "leaving stays PREPARED to it for the successor's takeover",
				     page, sender, msg->auth_node,
				     (unsigned long long)msg->auth_inc,
				     (unsigned long long)ctx->handoff_refused_leaving);
			return 0;
		}
		/* 0.75.8: a takeover names the departed authority and is sent by
		 * the successor; a live handoff names its sender */
		dlm_page_departed_authority(ctx, page, msg->auth_node, msg->auth_inc,
					    sender, "frozen-msg");
		if (msg->flags & MXFS_HANDOFF_F_DEPARTING) {
			/* 0.75.20 (D-...-0909): the sender is leaving; route hand-offs
			 * over the view without it from here on, so this page is
			 * served here rather than relayed back to it on the next
			 * tick.  Its goodbye follows on the same stream. */
			ctx->handoff_depart_rx++;
			if (dlm_node_mark_departing(ctx, sender, msg->auth_inc))
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: P-TAUTH-DEPARTING-RX node=%u/%llu page=%u — the "
					     "sender announced its clean departure; hand-off routing "
					     "now maps over the view without it",
					     sender, (unsigned long long)msg->auth_inc, page);
		}
		if (dlm_page_handoff_owner(ctx, page) != ctx->local_node) {
			/* ruling 2: complete the exact chain as a NON-serving relay —
			 * activate, then hand onward on the next tick */
			rc = mxfs_tauth_ledger_activate(ctx->ledger, page, ctx->ledger_gen,
							msg->prepared_seq, false);
			if (rc == 0) {
				dlm_set_page_state(ctx, page, DLM_PS_FROZEN);
				ctx->handoff_scan = true;
			}
			return rc;
		}
		rc = mxfs_tauth_ledger_activate(ctx->ledger, page, ctx->ledger_gen,
						msg->prepared_seq, false);
		if (rc == 0)
			dlm_page_now_mine(ctx, page, "frozen-msg");
		return rc;
	case MXFS_HANDOFF_DEFER:
		ctx->handoff_defers++;
		return 0;
	case MXFS_HANDOFF_NOT_OWNER:
		ctx->handoff_not_owner++;
		/* 0.84.5 (D-...-0960): a decline naming a dead authority relays
		 * the bootstrap's takeover count in prepared_seq */
		if (msg->prepared_seq > ctx->transition_progress_rx)
			ctx->transition_progress_rx = msg->prepared_seq;
		/* re-read and re-route at once — unless the answer names an
		 * authority that is not in view: that is the bootstrap node
		 * saying the takeover is owed but not yet possible (0.75.9), and
		 * the ask keeps its DLM_HANDOFF_REQ_INTERVAL_MS cadence */
		if (ctx->page_req_ms &&
		    (msg->auth_node == 0 || dlm_node_in_view(ctx, msg->auth_node)))
			ctx->page_req_ms[page] = 0;
		return 0;
	default:
		return -EINVAL;
	}
}

void mxfs_dlm_handoff_tick(struct mxfs_dlm_ctx *ctx)
{
	uint32_t p;
	int left = 0;

	if (!ctx || !dlm_ledger_active(ctx) || !ctx->page_state || !ctx->handoff_scan)
		return;
	for (p = 0; p < ctx->page_count; p++) {
		struct mxfs_tauth_page_auth a;
		mxfs_node_id_t owner;
		int rc;

		if (mxfs_tauth_ledger_page_auth(ctx->ledger, p, false, &a))
			continue;       /* not loaded: nothing of ours to move */
		if (a.auth_node != ctx->local_node || a.auth_inc != ctx->local_inc)
			continue;
		owner = dlm_page_handoff_owner(ctx, p);
		if (a.state == MXFS_TAUTH_PG_ACTIVE) {
			if (owner == ctx->local_node) {
				if (ctx->page_state[p] != DLM_PS_MINE)
					dlm_page_now_mine(ctx, p, "view-returned");
				continue;
			}
			rc = dlm_page_hand_to(ctx, p, owner,
					      ctx->node_inc_cb ? ctx->node_inc_cb(ctx->cb_data, owner) : 0,
					      "view-change", false);
			if (rc)
				left++;
		} else if (a.state == MXFS_TAUTH_PG_PREPARED &&
			   (dlm_owner_purged(ctx, a.target_node, -1) ||
			    (a.target_node != ctx->local_node &&
			     !dlm_node_in_view(ctx, a.target_node)))) {
			/* our PREPARED aims at a recovery-purged target, or (0.75.18,
			 * D-...-0909) at a node no longer in the view — a departed
			 * identity nothing will consume from: retarget now, not after
			 * the departure purge has marked it */
			if (owner == ctx->local_node) {
				rc = mxfs_tauth_ledger_prepare(ctx->ledger, p, ctx->ledger_gen,
							       ctx->local_node, ctx->local_inc, 0, 0,
							       true, NULL);
				if (rc == 0) {
					struct mxfs_tauth_page_auth b;

					ctx->handoff_retargets++;
					if (mxfs_tauth_ledger_page_auth(ctx->ledger, p, false, &b) == 0 &&
					    mxfs_tauth_ledger_activate(ctx->ledger, p, ctx->ledger_gen,
								       b.seq, false) == 0)
						dlm_page_now_mine(ctx, p, "retarget-self");
					else
						left++;
				} else {
					left++;
				}
			} else {
				uint64_t seq = 0, tinc = ctx->node_inc_cb ?
					       ctx->node_inc_cb(ctx->cb_data, owner) : 0;

				if (!tinc) {
					left++;
					continue;
				}
				rc = mxfs_tauth_ledger_prepare(ctx->ledger, p, ctx->ledger_gen, owner,
							       tinc, 0, 0, true, &seq);
				if (rc == 0) {
					ctx->handoff_retargets++;
					dlm_send_handoff(ctx, owner, p, MXFS_HANDOFF_FROZEN, owner, tinc,
							 seq, ctx->local_node, ctx->local_inc);
				} else {
					left++;
				}
			}
		}
	}
	if (left == 0)
		ctx->handoff_scan = false;
}

/*
 * 0.75.1: the takeover's candidate set comes from ONE bulk pass over the
 * ledger (16-page runs, both copies) — a bitmap of the pages whose platter
 * image names the departed authority.  The per-page fresh read that decides
 * each candidate is kept, so the transition below is exactly the old one;
 * only the 2 x page_count single-page reads that found nothing are gone.
 * Measured before this: v5_clean_depart_cb on the heartbeat thread walked
 * 26426 pages one 4 KiB SCSI read at a time over iSCSI — 48.8 s in stage
 * MONITOR (P-HB-MONSLOW monitor_ms=48821, two P278-HB-STALL dumps in
 * tauth_page_read_both), 79% of the way to the peer's death threshold, and
 * every grant request from the rejoining node failed its retry budget
 * meanwhile.
 */
struct dlm_takeover_scan {
	mxfs_node_id_t  node;
	uint64_t        inc;
	uint8_t        *cand;       /* bitmap over page_count */
	uint32_t        ncand, bad;
};

static void dlm_takeover_scan_cb(void *data, uint32_t page_id,
				 const struct mxfs_tauth_page_auth *a, int rc)
{
	struct dlm_takeover_scan *s = data;

	if (rc || !a) {
		s->bad++;
		return;
	}
	if (a->auth_node != s->node || a->auth_inc != s->inc)
		return;
	s->cand[page_id >> 3] |= (uint8_t)(1u << (page_id & 7));
	s->ncand++;
}

/*
 * One page of the departed authority {node, inc} -> its owner under the
 * current view: fresh read, PREPARE to the owner (retargeting a PREPARED
 * image whose target is gone), then activate if the owner is us or FROZEN
 * to it.  Exactly the transition the bulk pass below makes; 0.75.9 also
 * runs it on demand for the page a parked request needs (`how` names the
 * path).  1 = prepared; 0 = not (or no longer) this authority's page, or a
 * live target consumes it; <0 = skipped (owner incarnation unknown, or the
 * ledger refused — a stale base means another writer got there first, and
 * a re-read decides whether that writer was a takeover).  {hint_node,
 * hint_inc}: an incarnation the caller already knows for the page's view
 * owner (a FREEZE_REQ names its sender's), used when it is that owner and
 * the slot map cannot name it yet; 0 = look it up.
 */
static int dlm_takeover_page(struct mxfs_dlm_ctx *ctx, uint32_t p, mxfs_node_id_t node,
			     uint64_t inc, const char *how,
			     mxfs_node_id_t hint_node, uint64_t hint_inc)
{
	struct mxfs_tauth_page_auth a;
	mxfs_node_id_t owner;
	uint64_t seq = 0, tinc;
	bool retarget;
	int rc;

	rc = mxfs_tauth_ledger_page_auth(ctx->ledger, p, true, &a);
	if (rc)
		return rc;
	if (a.auth_node != node || a.auth_inc != inc)
		return 0;
	/*
	 * 0.89.3 (D-0981, design consult design review 2026-09-19): the one guard every
	 * takeover path shares — the orphan sweep, an on-demand takeover for a
	 * request that needs the page, the named completion pass — judged HERE,
	 * before the prepare, the activation and the purge, because any of those
	 * is a proof-invalidating mutation.  A departed authority whose slice
	 * replay has not reached IMAGES_REPLAYED keeps its pages and its records:
	 * they are what the replay's current-safety check judges against the
	 * sealed fence-time manifest, and retiring one turns a healthy replay
	 * into "authority mutated after the seal" and a terminal whole-
	 * filesystem quarantine (s66e).  Dead is not reclaimable; this overrides
	 * every dead classification (settled, purged, off the slot map).  The
	 * completion ladder's own takeover runs after IMAGES_REPLAYED and passes.
	 * -EAGAIN: the caller retries when the recovery advances; a request on
	 * such a page parks under the recovery-blocked cutoff exactly as before.
	 */
	if (ctx->recovery_judging_cb &&
	    ctx->recovery_judging_cb(ctx->cb_data, node, inc)) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-TAKEOVER-UNDER-JUDGEMENT page=%u departed=%u/%llu "
			     "via=%s — the departed authority is a recovery victim whose "
			     "slice replay has not passed its manifest judgement; its "
			     "records stay until it has (retiring one now would refuse "
			     "the replay as a post-seal mutation)",
			     p, node, (unsigned long long)inc, how);
		return -EAGAIN;
	}
	retarget = (a.state == MXFS_TAUTH_PG_PREPARED);
	/*
	 * 0.75.68 (D-...-0927): a PREPARED page is consumed by its target only
	 * while that target is a LIVE member — in this mount's view and not
	 * purged.  The old test treated any target this mount had not itself
	 * purged as live, which every incarnation of a previous era is: a
	 * whole-cluster restart inherits pages PREPARED to targets that left
	 * with the era (a concurrent unmount drops the FROZENs at the peer's
	 * quiesce, so every hand-off of that shape ends this way), the
	 * successor's takeover of its settled predecessor found them all
	 * (cand=29) and prepared none, and the page carrying AG 0 stayed
	 * under a dead authority for good — both nodes' fourth-era mounts
	 * parked on it and hung (tests/evidence/20260908T230313Z_restart_s556).
	 */
	/*
	 * 0.75.69: 0.75.68's test (in view and not purged) still left a target
	 * that is neither in view nor purged — every previous era's incarnation
	 * — as "live"; the slot map now decides (dlm_authority_dead).
	 */
	if (retarget && a.target_node != node &&
	    !dlm_authority_dead(ctx, a.target_node, a.target_inc))
		return 0;       /* a live target consumes it */
	owner = dlm_page_owner(ctx, p);
	tinc = (owner == ctx->local_node) ? ctx->local_inc :
	       (ctx->node_inc_cb ? ctx->node_inc_cb(ctx->cb_data, owner) : 0);
	if (!tinc && hint_node != 0 && owner == hint_node)
		tinc = hint_inc;
	if (!tinc)
		return -EAGAIN;
	rc = mxfs_tauth_ledger_prepare(ctx->ledger, p, ctx->ledger_gen, owner, tinc,
				       node, inc, retarget, &seq);
	if (rc == -ESTALE || rc == -EBUSY) {
		if (mxfs_tauth_ledger_page_auth(ctx->ledger, p, true, &a) == 0 &&
		    (a.auth_node != node || a.auth_inc != inc))
			return 0;   /* taken over by the other path meanwhile */
		return rc;
	}
	if (rc)
		return rc;
	if (strcmp(how, "takeover") != 0 && strcmp(how, "orphan-sweep") != 0) {
		ctx->handoff_ondemand++;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-TAUTH-TAKEOVER-ONDEMAND page=%u departed=%u/%llu owner=%u "
			     "via=%s — one page of a settled authority taken over for the "
			     "request that needs it, ahead of the bulk pass",
			     p, node, (unsigned long long)inc, owner, how);
	}
	if (owner == ctx->local_node) {
		int arc = mxfs_tauth_ledger_activate(ctx->ledger, p, ctx->ledger_gen,
						     seq, false);

		/*
		 * ACTIVATE IS NOT SERVICE READINESS, AND A REFUSED ACTIVATE IS NOT A
		 * COMPLETION.  This used to be `if (activate(...) == 0) { ... }` with
		 * the page counted and `return 1` outside it, so a page left PREPARED
		 * under the departed authority — not ours, records not purged, not
		 * imported, every request on it parking — was reported in the pass's
		 * pages_prepared and, because the caller counts only rc<0 as skipped,
		 * the pass returned `done` instead of -EAGAIN and nothing retried it.
		 *
		 * It matters twice over: takeover_pages_done is also the progress
		 * signal the authority-transition wait keys on, so a pass that
		 * activated nothing still looked like progress to every waiter.
		 */
		if (arc) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-TAKEOVER-NOTACTIVE page=%u departed=%u/%llu "
				     "seq=%llu rc=%d via=%s — prepared to us but not activated; "
				     "the page stays under the departed authority and is NOT "
				     "counted as taken over",
				     p, node, (unsigned long long)inc,
				     (unsigned long long)seq, arc, how);
			return arc < 0 ? arc : -EAGAIN;
		}
		{
			struct dlm_refused_keep_arg ka = { .ctx = ctx, .owner = node, .kept = 0 };
			int cleared, irc, rslot = -1;
			bool refused = dlm_owner_refused(ctx, node, &rslot);

			dlm_page_now_mine(ctx, p, how);
			/*
			 * 0.75.14 (D-...-0906 hand-on hole, measured with the peer's
			 * join held 12 s): the departed authority's records are still
			 * on the page — the bulk purge before this takeover walked
			 * only the pages we already mastered — and a later hand-on
			 * (writer == authority == us) carries them to the next owner
			 * with no marker; it imported the dead AG 0 EX as a live
			 * blocker.  Retire them now, on this page only, and import the
			 * page so our own slot's residue is released too, before any
			 * decision or hand-on can see them.
			 *
			 * 0.75.30: for a terminally refused victim the retirement is
			 * SELECTIVE — by node id AND its heartbeat slot (its shared
			 * bits on out-of-domain resources would otherwise import as
			 * blockers of the dead node and deny every conflicting
			 * request), keeping every record inside its quarantined
			 * domain; the import that follows installs those as frozen
			 * blockers.
			 */
			/*
			 * The purge names the departed INCARNATION, not just its node
			 * id.  It has to: the activation above already published the
			 * page as ours, so between it and this line the ordinary grant
			 * path can serve a request on this page and write a record — and
			 * the node id it writes is the departed one whenever a mount
			 * carries that id, which the resumed-term identity and a pinned
			 * id both arrange, and which is the whole reason a departure of
			 * this mount's own id skips the id-keyed bulk purges.  Matching
			 * on the id alone retired that live tenure and the import below
			 * rebuilt the page without it: a lock lost with no error
			 * anywhere.  A record of the same id under another incarnation
			 * is now spared and logged instead.
			 */
			if (refused)
				cleared = mxfs_tauth_ledger_purge_owner_page_keep(ctx->ledger, node, inc,
										  rslot, ctx->ledger_gen,
										  (uint64_t)ctx->current_epoch,
										  p, dlm_refused_keep_entry, &ka);
			else
				cleared = mxfs_tauth_ledger_purge_owner_page(ctx->ledger, node, inc, -1,
									     ctx->ledger_gen,
									     (uint64_t)ctx->current_epoch, p);
			irc = dlm_ledger_import_page(ctx, p, ctx->ledger_gen);
			/*
			 * Suppress only the HEALTHY line.  A bulk pass run with per-page
			 * logging off (dl_takeover_quiet) must not be able to hide a
			 * failed import or a negative purge count — this is the only line
			 * that carries import_rc, and silencing it unconditionally would
			 * turn the case worth seeing into the one case nobody sees.
			 */
			if (!mxfs_tauth_pass_quiet || irc || cleared < 0)
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "mxfs: P-TAUTH-TAKEOVER-RETIRE page=%u departed=%u/%llu "
					     "cleared=%d kept=%u refused=%d import_rc=%d via=%s — the "
					     "departed authority's records retired on the page at activation",
					     p, node, (unsigned long long)inc, cleared, ka.kept,
					     refused ? 1 : 0, irc, how);
			/*
			 * The page is durably ours now, so it is never "undone" — but it
			 * is not SERVABLE until the import rebuilt our view of it, and an
			 * unimported page must not be counted as a completed transfer or
			 * reported as progress.  Surface it and let the pass answer
			 * -EAGAIN; the page's own state on disk is unchanged either way.
			 */
			if (irc)
				return irc < 0 ? irc : -EAGAIN;
		}
	} else {
		dlm_send_handoff(ctx, owner, p, MXFS_HANDOFF_FROZEN, owner, tinc, seq,
				 node, inc);
	}
	/*
	 * Reached only by a page that is genuinely transferred: activated, purged
	 * and imported here, or durably PREPARED to a remote owner that consumes
	 * it at its next request on the page.  Every refusal above returns a
	 * negative instead, because this counter is both the pass's success count
	 * and the progress signal a parked request waits on.
	 */
	ctx->takeover_pages_done++;
	return 1;
}

/* TEST ONLY (dl_takeover_pause_ms): hold a bulk pass between two pages.
 * Slept in slices so the mount leaving, or the knob being cleared, ends it. */
static void dlm_takeover_pause(struct mxfs_dlm_ctx *ctx)
{
	unsigned int left = mxfs_dl_takeover_pause_ms;

	while (left > 0 && mxfs_dl_takeover_pause_ms && !ctx->shutting_down) {
		unsigned int slice = left > 100 ? 100 : left;

		mxfs_pal_sleep_ms(slice);
		left -= slice;
	}
}

int mxfs_dlm_handoff_takeover(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
			      uint64_t inc)
{
	struct dlm_takeover_scan sc;
	uint32_t p, scanned = 0;
	uint64_t t0, scan_ms;
	int done = 0, skipped = 0, rc;

	if (!ctx || !dlm_ledger_active(ctx) || !ctx->page_state)
		return -EINVAL;
	if (ctx->shutting_down)
		return -ESHUTDOWN;  /* admission closed: this mount is leaving */
	if (dlm_bootstrap_node(ctx) != ctx->local_node)
		return -EPERM;      /* only the certified successor writes here */
	/* 0.84.5 (D-...-0960): from here on a request on one of this
	 * incarnation's pages is served on demand, ahead of the pass */
	dlm_authority_settle_record(ctx, node, inc);
	memset(&sc, 0, sizeof(sc));
	sc.node = node;
	sc.inc = inc;
	sc.cand = mxfs_pal_alloc(((size_t)ctx->page_count + 7) / 8);
	if (!sc.cand)
		return -ENOMEM;
	t0 = mxfs_pal_time_ms();
	rc = mxfs_tauth_ledger_scan_auth(ctx->ledger, dlm_takeover_scan_cb, &sc,
					 &scanned);
	scan_ms = mxfs_pal_time_ms() - t0;
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-TAKEOVER-SCAN-FAIL departed=%u/%llu rc=%d "
			     "scanned=%u scan_ms=%llu — the ledger could not be "
			     "bulk-read; the departed authority's pages stay frozen "
			     "until the next takeover",
			     node, (unsigned long long)inc, rc, scanned,
			     (unsigned long long)scan_ms);
		mxfs_pal_free(sc.cand);
		return rc;
	}
	mxfs_tauth_pass_quiet = mxfs_dl_takeover_quiet ? 1 : 0;
	for (p = 0; p < ctx->page_count; p++) {
		if (!(sc.cand[p >> 3] & (1u << (p & 7))))
			continue;
		/*
		 * D-0953: this pass is minutes long when the departed authority
		 * owned most of the ledger (a crashed peer of two, a sole
		 * survivor's ghost: ~30 ms a page over 13-26k pages), and a mount
		 * that unmounts inside it used to join the worker for 30 s, give
		 * up, and destroy the engine under it — the worker's next
		 * page_state store faulted on the freed array (netconsole, s574xm,
		 * page 9569).  Stop BETWEEN pages, never inside one: a page's
		 * takeover is prepare + activate + purge + import, and a page
		 * left after activate but before import would be one this node
		 * claims and cannot serve.  The pages not reached stay under the
		 * departed authority (frozen; every request on them parks) until
		 * the next bootstrap node's orphan sweep or a request's on-demand
		 * takeover moves them.
		 */
		if (ctx->shutting_down) {
			uint32_t q, remaining = 0;

			for (q = p; q < ctx->page_count; q++)
				if (sc.cand[q >> 3] & (1u << (q & 7)))
					remaining++;
			ctx->handoff_takeover_interrupted++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-TAKEOVER-INTERRUPTED departed=%u/%llu "
				     "at_page=%u pages_prepared=%d skipped=%d remaining=%u "
				     "cand=%u elapsed_ms=%llu — this mount is leaving; the "
				     "remaining pages stay under the departed authority "
				     "for the next bootstrap node's orphan sweep",
				     node, (unsigned long long)inc, p, done, skipped,
				     remaining, sc.ncand,
				     (unsigned long long)(mxfs_pal_time_ms() - t0));
			ctx->handoff_takeovers += done;
			mxfs_tauth_pass_quiet = 0;
			mxfs_pal_free(sc.cand);
			return -EINTR;
		}
		/*
		 * D-0962: CERTIFICATION IS TESTED EVERY PAGE, NOT ONCE.  While this
		 * pass ran inside the recovery completion the exclusive-write gate
		 * was still in force, so membership could not change under it and
		 * one test at entry was the same as a test per page.  Deferred to
		 * the worker the pass outlives the gate: the returned peer claims a
		 * heartbeat slot, and if that slot is lower than ours it — not this
		 * mount — is the node the cluster certifies to write authority
		 * transitions.  Nothing here is fencing (the departed incarnation is
		 * dead by proof and every write is a conditional commit), so this is
		 * placement: stop between pages and leave the rest to the certified
		 * node, which finds them in the orphan sweep its own mount queues.
		 */
		if (dlm_bootstrap_node(ctx) != ctx->local_node) {
			uint32_t q, remaining = 0;

			for (q = p; q < ctx->page_count; q++)
				if (sc.cand[q >> 3] & (1u << (q & 7)))
					remaining++;
			ctx->handoff_decertified++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-TAKEOVER-DECERTIFIED departed=%u/%llu "
				     "at_page=%u pages_prepared=%d skipped=%d remaining=%u "
				     "cand=%u elapsed_ms=%llu — this mount no longer holds "
				     "the lowest live slot; the remaining pages are the "
				     "certified node's to move, through its orphan sweep",
				     node, (unsigned long long)inc, p, done, skipped,
				     remaining, sc.ncand,
				     (unsigned long long)(mxfs_pal_time_ms() - t0));
			ctx->handoff_takeovers += done;
			mxfs_tauth_pass_quiet = 0;
			mxfs_pal_free(sc.cand);
			return -EAGAIN;
		}
		dlm_takeover_pause(ctx);
		rc = dlm_takeover_page(ctx, p, node, inc, "takeover", 0, 0);
		if (rc == 1)
			done++;
		else if (rc < 0)
			skipped++;
	}
	ctx->handoff_takeovers += done;
	mxfs_tauth_pass_quiet = 0;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-TAUTH-TAKEOVER departed=%u/%llu pages_prepared=%d skipped=%d by=%u "
		     "scanned=%u cand=%u bad=%u scan_ms=%llu total_ms=%llu",
		     node, (unsigned long long)inc, done, skipped, ctx->local_node,
		     scanned, sc.ncand, sc.bad, (unsigned long long)scan_ms,
		     (unsigned long long)(mxfs_pal_time_ms() - t0));
	mxfs_pal_free(sc.cand);
	return skipped ? -EAGAIN : done;
}

/*
 * 0.75.69 (D-...-0927): the ORPHAN SWEEP.  The takeover above runs for one
 * named incarnation — the one a settle or a goodbye handed this mount.  A
 * page whose authority was settled by a mount that then died or hung (the
 * s556 fourth era did exactly that, on this very bug) is named by nobody
 * ever again.  One bulk pass reads every page's authority, asks the slot
 * map whether that incarnation is still anyone's, and takes over every
 * page of the ones that are not.  Run by the bootstrap node once its
 * membership has settled after mount.
 */
struct dlm_orphan_scan {
	struct mxfs_dlm_ctx *ctx;
	struct {
		mxfs_node_id_t node;
		uint64_t       inc;
		bool           dead;
		bool           judging;    /* 0.89.3 (D-0981): a recovery victim
									* whose replay has not passed judgement */
		uint32_t       pages;
	} auth[MXFS_MAX_NODES];
	int             nauth;
	uint8_t        *idx;        /* per page: 1 + auth index; 0 = not a candidate */
	uint32_t        ncand, bad, live_pages, judging_pages, overflow;
};

static void dlm_orphan_scan_cb(void *data, uint32_t page_id,
			       const struct mxfs_tauth_page_auth *a, int rc)
{
	struct dlm_orphan_scan *s = data;
	int i;

	if (rc || !a) {
		s->bad++;
		return;
	}
	if (a->state == MXFS_TAUTH_PG_UNOWNED || a->auth_node == 0 ||
	    a->auth_node == MXFS_DLM_NODE_UNKNOWN)
		return;
	if (a->auth_node == s->ctx->local_node && a->auth_inc == s->ctx->local_inc)
		return;
	for (i = 0; i < s->nauth; i++)
		if (s->auth[i].node == a->auth_node && s->auth[i].inc == a->auth_inc)
			break;
	if (i == s->nauth) {
		if (s->nauth >= MXFS_MAX_NODES) {
			s->overflow++;
			return;
		}
		s->auth[i].node = a->auth_node;
		s->auth[i].inc = a->auth_inc;
		s->auth[i].dead = dlm_authority_dead(s->ctx, a->auth_node, a->auth_inc);
		/*
		 * 0.89.3 (D-0981): dead is not reclaimable.  A dead authority whose
		 * slice replay has not passed its judgement keeps its pages: the
		 * takeover would retire the very records the replay judges against
		 * the sealed manifest (measured s66e: this mount's own sweep did,
		 * two seconds after its barrier claimed the lease, and the replay
		 * published a whole-filesystem quarantine).  The choke point
		 * (dlm_takeover_page) refuses these too; the pre-filter keeps the
		 * sweep from issuing a refused takeover per page.
		 */
		s->auth[i].judging = s->auth[i].dead && s->ctx->recovery_judging_cb &&
				     s->ctx->recovery_judging_cb(s->ctx->cb_data,
								 a->auth_node, a->auth_inc);
		s->auth[i].pages = 0;
		s->nauth++;
	}
	s->auth[i].pages++;
	if (!s->auth[i].dead) {
		s->live_pages++;
		return;
	}
	if (s->auth[i].judging) {
		s->judging_pages++;
		return;
	}
	s->idx[page_id] = (uint8_t)(i + 1);
	s->ncand++;
}

int mxfs_dlm_takeover_orphans(struct mxfs_dlm_ctx *ctx)
{
	struct dlm_orphan_scan *s;
	uint32_t p, scanned = 0;
	uint64_t t0, scan_ms;
	int rc, done = 0, skipped = 0, waited = 0, i, ndead = 0;

	if (!ctx || !dlm_ledger_active(ctx) || !ctx->page_state)
		return -EINVAL;
	while (dlm_membership_settling(ctx) && !ctx->shutting_down &&
	       waited < MXFS_DLM_SETTLE_MAX_WAIT_MS) {
		mxfs_pal_sleep_ms(100);
		waited += 100;
	}
	if (ctx->shutting_down)
		return -ESHUTDOWN;
	if (dlm_bootstrap_node(ctx) != ctx->local_node)
		return -EPERM;      /* only the certified successor writes here */
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	memset(s, 0, sizeof(*s));
	s->ctx = ctx;
	s->idx = mxfs_pal_alloc(ctx->page_count);
	if (!s->idx) {
		mxfs_pal_free(s);
		return -ENOMEM;
	}
	memset(s->idx, 0, ctx->page_count);
	t0 = mxfs_pal_time_ms();
	rc = mxfs_tauth_ledger_scan_auth(ctx->ledger, dlm_orphan_scan_cb, s, &scanned);
	scan_ms = mxfs_pal_time_ms() - t0;
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-ORPHAN-SCAN-FAIL rc=%d scanned=%u scan_ms=%llu — "
			     "the ledger could not be bulk-read; pages under dead "
			     "authorities wait for the next sweep or an on-demand takeover",
			     rc, scanned, (unsigned long long)scan_ms);
		mxfs_pal_free(s->idx);
		mxfs_pal_free(s);
		return rc;
	}
	for (i = 0; i < s->nauth; i++) {
		if (s->auth[i].dead)
			ndead++;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-ORPHAN-AUTH node=%u inc=%llu pages=%u dead=%d "
			     "judging=%d in_view=%d purged=%d occupant=%d",
			     s->auth[i].node, (unsigned long long)s->auth[i].inc,
			     s->auth[i].pages, s->auth[i].dead ? 1 : 0,
			     s->auth[i].judging ? 1 : 0,
			     dlm_node_in_view(ctx, s->auth[i].node) ? 1 : 0,
			     dlm_owner_purged(ctx, s->auth[i].node, -1) ? 1 : 0,
			     ctx->occupant_cb ?
			     (ctx->occupant_cb(ctx->cb_data, s->auth[i].node,
					       s->auth[i].inc) ? 1 : 0) : -1);
	}
	for (p = 0; p < ctx->page_count; p++) {
		if (!s->idx[p])
			continue;
		/* D-0953: same stop-between-pages rule as the named takeover;
		 * the sweep is the pass that finishes what an interrupted one
		 * left, so it must itself be interruptible. */
		if (ctx->shutting_down) {
			uint32_t q, remaining = 0;

			for (q = p; q < ctx->page_count; q++)
				if (s->idx[q])
					remaining++;
			ctx->handoff_takeover_interrupted++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-ORPHAN-SWEEP-INTERRUPTED at_page=%u "
				     "prepared=%d skipped=%d remaining=%u cand=%u "
				     "elapsed_ms=%llu — this mount is leaving; the "
				     "remaining pages wait for the next bootstrap node's sweep",
				     p, done, skipped, remaining, s->ncand,
				     (unsigned long long)(mxfs_pal_time_ms() - t0));
			ctx->handoff_takeovers += done;
			mxfs_pal_free(s->idx);
			mxfs_pal_free(s);
			return -EINTR;
		}
		/* Same rule as the named pass: the sweep is minutes long and a peer
		 * joining on a lower slot becomes the node certified to write these
		 * transitions.  Stop between pages and leave the rest to it. */
		if (dlm_bootstrap_node(ctx) != ctx->local_node) {
			uint32_t q, remaining = 0;

			for (q = p; q < ctx->page_count; q++)
				if (s->idx[q])
					remaining++;
			ctx->handoff_decertified++;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-ORPHAN-SWEEP-DECERTIFIED at_page=%u "
				     "prepared=%d skipped=%d remaining=%u cand=%u elapsed_ms=%llu "
				     "— this mount no longer holds the lowest live slot; the "
				     "remaining pages are the certified node's to move",
				     p, done, skipped, remaining, s->ncand,
				     (unsigned long long)(mxfs_pal_time_ms() - t0));
			ctx->handoff_takeovers += done;
			mxfs_pal_free(s->idx);
			mxfs_pal_free(s);
			return -EAGAIN;
		}
		i = s->idx[p] - 1;
		dlm_takeover_pause(ctx);
		rc = dlm_takeover_page(ctx, p, s->auth[i].node, s->auth[i].inc,
				       "orphan-sweep", 0, 0);
		if (rc == 1)
			done++;
		else if (rc < 0)
			skipped++;
	}
	ctx->handoff_takeovers += done;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-TAUTH-ORPHAN-SWEEP by=%u scanned=%u authorities=%d dead=%d "
		     "cand=%u live_pages=%u judging_pages=%u prepared=%d skipped=%d "
		     "bad=%u overflow=%u settle_wait_ms=%d scan_ms=%llu total_ms=%llu",
		     ctx->local_node, scanned, s->nauth, ndead, s->ncand, s->live_pages,
		     s->judging_pages, done, skipped, s->bad, s->overflow, waited,
		     (unsigned long long)scan_ms,
		     (unsigned long long)(mxfs_pal_time_ms() - t0));
	mxfs_pal_free(s->idx);
	mxfs_pal_free(s);
	return skipped ? -EAGAIN : done;
}

int mxfs_dlm_handoff_depart(struct mxfs_dlm_ctx *ctx)
{
	mxfs_node_id_t others[MXFS_MAX_NODES];
	int n = 0, i, left = 0;
	uint32_t p;

	if (!ctx || !dlm_ledger_active(ctx) || !ctx->page_state)
		return 0;
	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	for (i = 0; i < ctx->active_nodes.count; i++)
		if (ctx->active_nodes.nodes[i] != ctx->local_node)
			others[n++] = ctx->active_nodes.nodes[i];
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
	if (n == 0)
		return 0;           /* last node: the pages stay ours; the next
							 * mount's bootstrap/takeover claims them */
	ctx->departing = true;  /* 0.75.20: every FROZEN from here carries the
							 * departing flag (see dlm_send_handoff) */
	for (p = 0; p < ctx->page_count; p++) {
		mxfs_node_id_t target = others[p % (uint32_t)n];
		int rc;

		if (!mxfs_tauth_ledger_page_mine(ctx->ledger, p))
			continue;
		rc = dlm_page_hand_to(ctx, p, target,
				      ctx->node_inc_cb ? ctx->node_inc_cb(ctx->cb_data, target) : 0,
				      "depart", true);
		if (rc)
			left++;
	}
	mxfs_pal_log(MXFS_LOG_WARN, "mxfs: P-TAUTH-DEPART node=%u pages_left=%d",
		     ctx->local_node, left);
	return left;
}

/* Before any decision on `resource`: the page must be current and imported
 * under the generation the decision will record.  0, or -EAGAIN when the
 * generation moved (retry), or a fail-closed error. */
static int dlm_ledger_prepare(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint64_t *gen_out)
{
	uint64_t gen;
	int rc;

	if (dlm_ledger_refuses(ctx)) {
		static atomic_t p_refuse = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_refuse) <= 2000)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-REFUSE type=%u ino=%llu ag=%u ledger=%d failed=%d — "
				     "grant refused (activation barrier / fail-stop)",
				     resource->type, (unsigned long long)resource->ino,
				     resource->ag_number, ctx->ledger ? 1 : 0,
				     ctx->ledger_failed ? 1 : 0);
		return -EIO;
	}
	gen = ctx->ledger_gen;
	*gen_out = gen;
	if (!dlm_ledger_active(ctx))
		return 0;
	/* (step 4): the page's durable authority must be THIS node
	 * before anything is imported or decided; otherwise the decision is
	 * parked (the requester retries / re-routes) while the handoff runs */
	{
		uint64_t od0 = ctx->handoff_ondemand;

		rc = dlm_page_ensure_mine(ctx, dlm_res_page(ctx, resource), gen);
		/* 0.84.5 (D-...-0960): names the resource an on-demand takeover
		 * served, so a lap can tell whether a joiner's root request met
		 * the transition HERE (this node masters its page) or at the
		 * joiner, which asks by FREEZE_REQ */
		if (ctx->handoff_ondemand != od0)
			pr_warn_ratelimited(
			    "mxfs: P960-ONDEMAND-SERVED type=%u ino=%llu ag=%u page=%u rc=%d "
			    "— a request on a page under a dead authority, served ahead of "
			    "the bulk pass\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, dlm_res_page(ctx, resource), rc);
	}
	if (rc) {
		ctx->handoff_parked++;
		return rc == -EAGAIN ? -EAGAIN : rc;
	}
	rc = dlm_ledger_import_page(ctx, dlm_res_page(ctx, resource), gen);
	if (rc == -ESTALE) {
		/* instrument (D-...-0960, s592e): the third silent park */
		mxfs_probe_ratelimited(
		    "mxfs: P960-PARK-IMPORT-STALE type=%u ino=%llu ag=%u page=%u — parked: the page image moved under the import\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, dlm_res_page(ctx, resource));
		return -EAGAIN;
	}
	if (rc)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-PREPARE-FAIL type=%u ino=%llu ag=%u page=%u rc=%d",
			     resource->type, (unsigned long long)resource->ino,
			     resource->ag_number, dlm_res_page(ctx, resource), rc);
	return rc;
}

/* ── 3d/3e: the transition ── */

#define DLM_TXN_MAX (MAX_WAITERS + 1)

struct dlm_txn_item {
	mxfs_node_id_t  owner;
	uint64_t        inc;
	uint16_t        slot;
	uint8_t         mode;
	uint8_t         prev_mode;      /* upgrade: mode to restore on refusal */
	uint32_t        prev_gen;
	uint32_t        gen;
	mxfs_epoch_t    request_epoch;
	uint32_t        req_id;
	uint8_t         handoff;
	bool            release;        /* PENDING_RELEASE item */
	bool            cancelled;      /* grant landed for an abandoned wait:
									 * retire it instead of delivering */
	bool            signal_local;   /* deliver via pending_signal_resource */
	bool            remote_rel;     /* release came over the wire (ACK it) */
	bool            ack_deferred;   /* a release-only re-commit
									 * follows this refused bundle — its
									 * finalize sends the ACK, not this one */
	uint32_t        dir_epoch;
	uint32_t        rel_id;
	uint64_t        rel_auth, rel_seq, rel_lineage;
	int8_t          open_op;        /* 0.89.0: the release's open-mark change */
	struct dlm_grant_ids ids;
	int             rc;             /* per-item outcome */
};

struct dlm_txn {
	struct mxfs_resource_id resource;
	uint64_t        gen;
	int             n;
	struct dlm_txn_item it[DLM_TXN_MAX];
};

static void dlm_txn_init(struct dlm_txn *txn, const struct mxfs_resource_id *res,
			 uint64_t gen)
{
	memset(txn, 0, sizeof(*txn));
	txn->resource = *res;
	txn->gen = gen;
}

/* is `lk` (a PENDING_RELEASE holder) the release item of this transition? */
static bool dlm_txn_retires(const struct dlm_txn *txn, const struct mxfs_lock *lk)
{
	int i;

	for (i = 0; i < txn->n; i++)
		if (txn->it[i].release && txn->it[i].owner == lk->owner &&
		    txn->it[i].gen == lk->grant_gen)
			return true;
	return false;
}

/* Caller holds table_rwlock; `lk` was just set PENDING_DURABLE. */
static struct dlm_txn_item *dlm_txn_add_grant(struct dlm_txn *txn,
					      struct mxfs_lock *lk,
					      uint8_t prev_mode, uint32_t prev_gen,
					      bool signal_local)
{
	struct dlm_txn_item *it;

	if (txn->n >= DLM_TXN_MAX)
		return NULL;
	it = &txn->it[txn->n++];
	memset(it, 0, sizeof(*it));
	it->owner = lk->owner;
	it->inc = lk->owner_inc;
	it->slot = lk->owner_slot;
	it->mode = lk->mode;
	it->prev_mode = prev_mode;
	it->prev_gen = prev_gen;
	it->gen = lk->grant_gen;
	it->request_epoch = lk->request_epoch;
	it->req_id = lk->req_id;
	it->handoff = lk->handoff ? 1 : 0;
	it->dir_epoch = lk->dir_epoch;
	it->signal_local = signal_local;
	it->ids.req_id = lk->req_id;
	it->rc = -EINPROGRESS;
	return it;
}

/* Caller holds table_rwlock; `lk` was just set PENDING_RELEASE. */
static struct dlm_txn_item *dlm_txn_add_release(struct dlm_txn *txn,
						struct mxfs_lock *lk,
						uint32_t rel_id, bool remote_rel)
{
	struct dlm_txn_item *it;

	if (txn->n >= DLM_TXN_MAX)
		return NULL;
	it = &txn->it[txn->n++];
	memset(it, 0, sizeof(*it));
	it->release = true;
	it->remote_rel = remote_rel;
	it->owner = lk->owner;
	it->inc = lk->owner_inc;
	it->slot = lk->owner_slot;
	it->mode = lk->mode;
	it->gen = lk->grant_gen;
	it->rel_id = rel_id;
	it->rel_auth = lk->auth_epoch;
	it->rel_seq = lk->grant_seq;
	it->rel_lineage = lk->lineage;
	it->open_op = lk->open_op;
	it->rc = -EINPROGRESS;
	return it;
}

/* Commit the transition.  0 = durable (per-item rc set); -ESTALE = the page
 * ownership generation moved (nothing written); other = refused. */
static int dlm_txn_commit(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn)
{
	struct mxfs_tauth_op *ops;
	int i, rc = 0, attempt;

	if (txn->n == 0)
		return 0;
	if (!dlm_ledger_active(ctx)) {
		/* no ledger on this mount (legacy / usermode): everything applies */
		for (i = 0; i < txn->n; i++)
			txn->it[i].rc = 0;
		return 0;
	}
	ops = mxfs_pal_alloc(sizeof(*ops) * (size_t)txn->n);
	if (!ops)
		return -ENOMEM;
	for (attempt = 0; attempt < 3; attempt++) {
		memset(ops, 0, sizeof(*ops) * (size_t)txn->n);
		for (i = 0; i < txn->n; i++) {
			struct dlm_txn_item *it = &txn->it[i];
			struct mxfs_tauth_op *op = &ops[i];

			op->res = txn->resource;
			op->node = it->owner;
			op->inc = it->inc;
			op->slot = it->slot;
			op->mode = it->mode;
			if (it->release) {
				op->kind = dlm_mode_exclusive(it->mode) ?
					   MXFS_TAUTH_OP_RELEASE_EX : MXFS_TAUTH_OP_RELEASE_PR;
				op->authority_epoch = it->rel_auth;
				op->grant_seq64 = it->rel_seq;
				op->lineage = it->rel_lineage;
				op->open_op = it->open_op;
			} else {
				op->kind = dlm_mode_exclusive(it->mode) ?
					   MXFS_TAUTH_OP_GRANT_EX : MXFS_TAUTH_OP_GRANT_PR;
				op->lineage = ((uint64_t)ctx->local_node << 32) | it->gen;
				op->dir_epoch = it->dir_epoch;
			}
		}
		rc = mxfs_tauth_ledger_commit(ctx->ledger, ops, txn->n, txn->gen,
					      (uint64_t)ctx->current_epoch);
		if (rc == -EPERM)
			rc = -ESTALE;   /* the page is no longer ours: remaster */
		if (rc == 0 || rc == -ESTALE || rc == -EEXIST || rc == -EBUSY ||
		    rc == -EDQUOT ||
		    rc == -ENOSPC || rc == -EUCLEAN || rc == -EINVAL || rc == -ENOMEM)
			break;
		/* -EIO (proven not committed) / -ENOTRECOVERABLE (poisoned):
		 * reconcile + retry a bounded number of times */
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-TAUTH-COMMIT-RETRY type=%u ino=%llu ag=%u rc=%d attempt=%d",
			     txn->resource.type, (unsigned long long)txn->resource.ino,
			     txn->resource.ag_number, rc, attempt + 1);
		if (mxfs_tauth_ledger_ensure(ctx->ledger, dlm_res_page(ctx, &txn->resource),
					     txn->gen) == -ESTALE) {
			rc = -ESTALE;
			break;
		}
	}
	if (rc == -EIO || rc == -ENOTRECOVERABLE) {
		/* fail stop: this master cannot make authority durable */
		ctx->ledger_failed = true;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-FAILSTOP rc=%d — ledger writes cannot be made durable; "
			     "no further grants from this master (fail closed)", rc);
	}
	for (i = 0; i < txn->n; i++) {
		struct dlm_txn_item *it = &txn->it[i];

		if (rc == 0) {
			it->rc = ops[i].rc;     /* 0 or -ESTALE (release superseded) */
			it->ids.auth_epoch = ops[i].authority_epoch;
			it->ids.grant_seq = ops[i].grant_seq64;
			it->ids.lineage = ops[i].lineage_out;
			it->ids.open_holders = ops[i].open_holders_out;
			if (it->release) {
				it->ids.auth_epoch = it->rel_auth;
				it->ids.grant_seq = it->rel_seq;
			}
			/* 0.89.1 (D-0977 instrument): a release that SETS a mark, or
			 * leaves the record marked, or is the genuine free's erase —
			 * with the ledger's verdict and the mask after it (the mark is
			 * durable only if rc=0 here).  The ordinary clear of an
			 * unmarked record is every inode release on TCP and stays
			 * silent.  The node whose ring carries a victim's op=1 line is
			 * that inode's master; tests/d0977_open_unlink_tcp.sh reads
			 * mastership from it. */
			if (it->release && txn->resource.type == MXFS_LTYPE_INODE &&
			    (it->open_op == MXFS_TAUTH_OPEN_SET ||
			     it->open_op == MXFS_TAUTH_OPEN_ZERO ||
			     ops[i].open_holders_out != 0))
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "mxfs: P977-REL-MARK ino=%llu node=%u slot=%u mode=%u op=%d "
					     "rc=%d mask=0x%llx remote=%d",
					     (unsigned long long)txn->resource.ino, it->owner,
					     it->slot, it->mode, it->open_op, it->rc,
					     (unsigned long long)ops[i].open_holders_out,
					     it->remote_rel ? 1 : 0);
		} else {
			it->rc = rc;
		}
	}
	if (rc == 0)
		ctx->ledger_grants++;
	else
		ctx->ledger_denies++;
	mxfs_pal_free(ops);
	return rc;
}

/*
 * 0.89.0 (D-0977): a releaser's open-mark change that found no table entry
 * to ride (mxfs_dlm_process_remote_release's ENOENT arm).  One durable
 * OPEN_MARK op against the resource's existing record.  0 = durable (or
 * already in that state), -ESTALE = the page has no record of the resource
 * (nothing a guard could read), other = the write was refused and the
 * releaser must keep re-sending.  Called outside the table lock; the ledger
 * page was prepared by the caller under `gen`.
 */
static int dlm_open_mark_only(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      mxfs_node_id_t sender,
			      const struct mxfs_dlm_lock_release *rel,
			      uint64_t gen)
{
	struct mxfs_tauth_op op;
	int rc;

	if (!dlm_ledger_active(ctx))
		return 0;
	memset(&op, 0, sizeof(op));
	op.kind = MXFS_TAUTH_OP_OPEN_MARK;
	op.res = *resource;
	op.node = sender;
	op.inc = rel->owner_inc;
	op.slot = rel->owner_slot;
	op.mode = rel->mode;
	op.open_op = rel->open_op;
	rc = mxfs_tauth_ledger_commit(ctx->ledger, &op, 1, gen,
				      (uint64_t)ctx->current_epoch);
	if (rc == -EPERM)
		rc = -ESTALE;
	if (rc == 0 && op.rc == -ESTALE)
		rc = -ESTALE;
	ctx->open_mark_only++;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P977-OPEN-MARK-ONLY type=%u ino=%llu sender=%u slot=%u op=%d rc=%d "
		     "mask=0x%llx — a mark change with no grant to ride, applied on its own",
		     resource->type, (unsigned long long)resource->ino, sender,
		     rel->owner_slot, rel->open_op, rc,
		     (unsigned long long)op.open_holders_out);
	return rc;
}

/* Caller holds table_rwlock: find the pending entry an item describes. */
static struct mxfs_lock **dlm_txn_find(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn,
				       const struct dlm_txn_item *it)
{
	uint32_t bucket = resource_hash(&txn->resource, ctx->bucket_count);
	struct mxfs_lock **pp;
	uint8_t want = it->release ? MXFS_LSTATE_PENDING_RELEASE :
				     MXFS_LSTATE_PENDING_DURABLE;

	for (pp = &ctx->buckets[bucket]; *pp; pp = &(*pp)->next) {
		struct mxfs_lock *lk = *pp;

		if (lk->state == want && lk->owner == it->owner &&
		    lk->grant_gen == it->gen &&
		    resource_equal(&lk->resource, &txn->resource))
			return pp;
	}
	return NULL;
}

static int dlm_promote_txn(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn);

/*
 * (proven by instrument, tests/tauth/concurrent_release_test s5): a LOCAL
 * requester whose budget ran out while its grant was PENDING_DURABLE has
 * no waiter left when the commit lands; the entry would stay GRANTED with
 * nobody holding it — a durable EX blocker for the whole cluster.  Release
 * it the way a remote grantee answers an unsolicited GRANT.  Race-free
 * against a concurrent local adopter: adoption clears `unclaimed` under
 * the table write lock, and so does this check.
 */
/*
 * A grant decided for an acquisition its requester had already abandoned
 * (LOCK_CANCEL arrived while the entry was PENDING_DURABLE) has just become
 * durable.  Nobody will install it, and delivering it so that the requester
 * can bounce it back assumes the delivery arrives — the case this exists for
 * is exactly the one where it does not.  Retire it here, in a transition of
 * its own, and promote whoever was queued behind it.
 */
static void dlm_retire_cancelled_grant(struct mxfs_dlm_ctx *ctx,
				       const struct mxfs_resource_id *res,
				       uint32_t gen, mxfs_node_id_t owner)
{
	uint32_t bucket = resource_hash(res, ctx->bucket_count);
	struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
	struct mxfs_lock *lk;

	if (!txn)
		return;
	dlm_txn_init(txn, res, ctx->ledger_gen);
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next)
		if (lk->owner == owner && lk->state == MXFS_LSTATE_GRANTED &&
		    lk->grant_gen == gen && lk->cancelled &&
		    resource_equal(&lk->resource, res))
			break;
	if (lk) {
		lk->cancelled = false;
		lk->state = MXFS_LSTATE_PENDING_RELEASE;
		lk->pend_waiter = NULL;
		dg_release(res, owner);
		dlm_txn_add_release(txn, lk, ++ctx->rel_id_next, false);
		ctx->cancel_grants_retired++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (lk) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P958-CANCEL-GRANT-RETIRED type=%u ino=%llu ag=%u gen=%u owner=%u total=%llu — "
			     "a grant that landed for an abandoned wait is retired instead of delivered",
			     res->type, (unsigned long long)res->ino, res->ag_number,
			     gen, owner, (unsigned long long)ctx->cancel_grants_retired);
		dlm_promote_txn(ctx, txn);
	}
	mxfs_pal_free(txn);
}

static void dlm_release_local_orphan(struct mxfs_dlm_ctx *ctx,
				     const struct mxfs_resource_id *res, uint32_t gen)
{
	uint32_t bucket = resource_hash(res, ctx->bucket_count);
	struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
	struct mxfs_lock *lk;

	if (!txn)
		return;
	dlm_txn_init(txn, res, ctx->ledger_gen);
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next)
		if (lk->owner == ctx->local_node && lk->state == MXFS_LSTATE_GRANTED &&
		    lk->grant_gen == gen && lk->unclaimed && resource_equal(&lk->resource, res))
			break;
	if (lk) {
		lk->unclaimed = false;
		lk->state = MXFS_LSTATE_PENDING_RELEASE;
		lk->pend_waiter = NULL;
		dg_release(res, ctx->local_node);
		dlm_txn_add_release(txn, lk, ++ctx->rel_id_next, false);
		ctx->ledger_local_orphans++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (lk) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-TAUTH-LOCAL-ORPHAN-RELEASE type=%u ino=%llu ag=%u gen=%u — "
			     "durable grant to a local requester that already gave up; released",
			     res->type, (unsigned long long)res->ino, res->ag_number, gen);
		dlm_promote_txn(ctx, txn);
	}
	mxfs_pal_free(txn);
}

/*
 * Finalize + deliver.  `commit_rc` is dlm_txn_commit's return.  Returns
 * the number of grants delivered.  Post-promotion BASTs for the resource
 * (blocked waiters behind the new holders) and the grantee BASTs
 * are collected under the lock and fired after delivery.
 */
struct dlm_txn_basts {
	struct mxfs_bast_record basts[MXFS_MAX_BAST_RECORDS];
	struct mxfs_bast_record post_basts[MXFS_MAX_BAST_RECORDS];
};

static int dlm_txn_finalize(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn,
			    int commit_rc)
{
	struct dlm_txn_basts *tb = mxfs_pal_alloc(sizeof(*tb));   /* off-stack */
	struct mxfs_bast_record *basts = tb ? tb->basts : NULL;
	struct mxfs_bast_record *post_basts = tb ? tb->post_basts : NULL;
	int nbast = 0, npost = 0, i, delivered = 0;
	bool remaster;
	uint32_t bucket = resource_hash(&txn->resource, ctx->bucket_count);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	/*
	 * (design-consult ruling ccmemory ccloop-c7ee71c6-sess424-GPT-ruling-
	 * ghost-grant-delivery-and-unresolved-pr-bits): a SUCCESSFUL commit is
	 * delivered whatever the view did afterwards.  The page write + exact
	 * readback is the proof of authority; the record is on the platter and
	 * every successor imports it naming the same holder, so delivering is
	 * always consistent with the disk.  Refusing delivery here (0.34.0)
	 * freed the entry and minted a GHOST: a durable holder bit nobody ever
	 * released — on the 32/tcp rig it left the root inode's record with a
	 * stuck PR bit and every later mount timed out on ino=128.  Only a
	 * commit the ledger itself refused as stale (-ESTALE: page not ours at
	 * write time) is a remaster.
	 */
	remaster = (commit_rc == -ESTALE);
	if (remaster)
		ctx->ledger_remaster++;
	else if (commit_rc == 0 &&
		 (ctx->ledger_gen != txn->gen ||
		  (ctx->page_state &&
		   ctx->page_state[dlm_res_page(ctx, &txn->resource)] != DLM_PS_MINE))) {
		ctx->ledger_late_deliveries++;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-TAUTH-LATE-DELIVERY type=%u ino=%llu ag=%u items=%d — the "
			     "view moved after a durable commit; delivering (the successor "
			     "imports the record)",
			     txn->resource.type, (unsigned long long)txn->resource.ino,
			     txn->resource.ag_number, txn->n);
	}
	for (i = 0; i < txn->n; i++) {
		struct dlm_txn_item *it = &txn->it[i];
		struct mxfs_lock **pp = dlm_txn_find(ctx, txn, it);
		struct mxfs_lock *lk = pp ? *pp : NULL;
		bool ok = (commit_rc == 0) && !remaster;

		if (it->release) {
			/* durable (or superseded: the releaser holds nothing) -> retire
			 * the table entry; refused -> keep PENDING_RELEASE (blocker),
			 * the releaser retries */
			if (commit_rc == 0 || remaster) {
				if (lk) {
					*pp = lk->next;
					ctx->lock_count--;
					P_LKT("RELEASE-DURABLE", &txn->resource, it->owner, it->mode);
					lock_free(lk);
				}
				it->rc = remaster && commit_rc != 0 ? -EAGAIN : 0;
			} else {
				it->rc = commit_rc;
			}
			continue;
		}
		if (!lk) {
			/* purged / timed out under us: a durable grant nobody will be
			 * told about is a GHOST — it stays a blocker in the ledger until
			 * its owner re-requests (and gets it back) or is purged */
			if (commit_rc == 0) {
				ctx->ledger_ghosts++;
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "mxfs: P-TAUTH-GHOST type=%u ino=%llu ag=%u owner=%u gen=%u "
					     "grant_id={%llu,%llu} — durable grant, no table entry",
					     txn->resource.type, (unsigned long long)txn->resource.ino,
					     txn->resource.ag_number, it->owner, it->gen,
					     (unsigned long long)it->ids.auth_epoch,
					     (unsigned long long)it->ids.grant_seq);
			}
			it->rc = -ENOENT;
			continue;
		}
		if (ok) {
			lk->state = MXFS_LSTATE_GRANTED;
			lk->granted_at = mxfs_pal_time_ms();
			lk->auth_epoch = it->ids.auth_epoch;
			lk->grant_seq = it->ids.grant_seq;
			lk->lineage = it->ids.lineage;
			/* 0.89.0: the open-mark snapshot of this grant (a local
			 * grantee reads it from its own entry, a remote one from
			 * the LOCK_GRANT this item sends below) */
			lk->open_holders = it->ids.open_holders;
			lk->open_snap = dlm_mode_exclusive(lk->mode) && dlm_ledger_active(ctx);
			lk->imported = false;
			lk->unclaimed = (it->owner == ctx->local_node && it->signal_local);
			/* The requester abandoned this wait while its grant was
			 * committing: the grant is durable now and is retired below
			 * instead of delivered. */
			it->cancelled = lk->cancelled;
			it->rc = 0;
			mxfs_dlm_audit_double_grant(ctx->buckets[bucket], &txn->resource);
			if (basts && nbast < MXFS_MAX_BAST_RECORDS &&
			    collect_grantee_bast_if_waiters(ctx->buckets[bucket], &txn->resource,
							    it->owner, it->mode, &basts[nbast]))
				nbast++;
			continue;
		}
		/* refused / remastered: undo the decision */
		if (commit_rc == 0 && remaster) {
			ctx->ledger_ghosts++;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-TAUTH-GHOST type=%u ino=%llu ag=%u owner=%u gen=%u "
				     "— committed under a superseded ownership generation; not delivered",
				     txn->resource.type, (unsigned long long)txn->resource.ino,
				     txn->resource.ag_number, it->owner, it->gen);
		}
		if (it->prev_mode) {
			lk->state = MXFS_LSTATE_GRANTED;
			lk->mode = it->prev_mode;
			lk->grant_gen = it->prev_gen;
		} else {
			*pp = lk->next;
			ctx->lock_count--;
			P_LKT("GRANT-REFUSED", &txn->resource, it->owner, it->mode);
			lock_free(lk);
		}
		it->rc = remaster ? -EAGAIN : (commit_rc ? commit_rc : -EIO);
	}
	{
		struct mxfs_lock *pb, *wk;
		uint8_t blocked_mode = MXFS_LOCK_NL;

		pb = collect_post_promotion_basts(ctx->buckets[bucket], &txn->resource,
						  &blocked_mode);
		for (wk = pb; post_basts && wk; wk = wk->work_next) {
			if (npost < MXFS_MAX_BAST_RECORDS) {
				post_basts[npost].owner = wk->owner;
				post_basts[npost].requested_mode = blocked_mode;
				npost++;
			}
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	/* deliver */
	for (i = 0; i < txn->n; i++) {
		struct dlm_txn_item *it = &txn->it[i];

		if (it->release) {
			if (it->remote_rel && it->owner != ctx->local_node && !it->ack_deferred)
				send_release_ack(ctx, it->owner, &txn->resource, it->gen, it->rel_id,
						 it->rel_auth, it->rel_seq,
						 it->rc == 0 ? MXFS_OK :
						 it->rc == -EAGAIN ? MXFS_ERR_REMASTER : MXFS_ERR_LEDGER);
			continue;
		}
		if (it->rc == 0) {
			delivered++;
			if (it->cancelled) {
				dlm_retire_cancelled_grant(ctx, &txn->resource, it->gen,
							   it->owner);
			} else if (it->owner == ctx->local_node) {
				if (it->signal_local &&
				    !pending_signal_resource(ctx, &txn->resource, it->mode, 0, 0))
					dlm_release_local_orphan(ctx, &txn->resource, it->gen);
			} else {
				send_grant(ctx, it->owner, &txn->resource, it->mode, MXFS_OK,
					   MXFS_MSG_LOCK_GRANT, it->request_epoch, it->gen,
					   it->handoff, it->dir_epoch, &it->ids);
			}
			continue;
		}
		if (it->rc == -ENOENT)
			continue;       /* nobody to tell */
		if (it->owner == ctx->local_node) {
			if (it->signal_local)
				pending_signal_resource(ctx, &txn->resource, MXFS_LOCK_NL,
							(it->rc == -EAGAIN || it->rc == -EBUSY ||
							 it->rc == -EDQUOT) ?
										MXFS_DLM_RETRY : -EIO, 0);
		} else {
			struct dlm_grant_ids ids = { 0, 0, 0, it->req_id };

			send_grant(ctx, it->owner, &txn->resource, MXFS_LOCK_NL,
				   it->rc == -EAGAIN ? MXFS_ERR_REMASTER :
				   it->rc == -EBUSY ? MXFS_ERR_LEDGER_BUSY :
				   it->rc == -EDQUOT ? MXFS_ERR_LEDGER_FULL : MXFS_ERR_LEDGER,
				   MXFS_MSG_LOCK_DENY, it->request_epoch, 0, 0, 0, &ids);
		}
	}
	if (nbast)
		fire_bast_records(ctx, &txn->resource, basts, nbast);
	if (npost)
		fire_bast_records(ctx, &txn->resource, post_basts, npost);
	if (tb)
		mxfs_pal_free(tb);
	return delivered;
}

/*
 * Release-and-promote driver (every promote_waiters site).  `txn` may
 * already carry the release item (its entry is PENDING_RELEASE).  Rounds:
 * select successors (PENDING_DURABLE) -> commit -> finalize/deliver; a
 * further round runs while new waiters became grantable meanwhile (they
 * queued behind the PENDING_RELEASE holder).  Caller holds NO locks.
 * Returns the release item's rc (0 when there was none).
 */
/* a refused bundled transition must never strand its release.
 * A release op is applied or superseded, never refused for conflict, so
 * re-commit the release items ALONE; the refused grants were denied by the
 * first finalize (their requesters retry).  Returns the release commit rc. */
static int dlm_txn_recommit_releases(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn)
{
	int i, nrel = 0, rc;

	for (i = 0; i < txn->n; i++) {
		if (!txn->it[i].release)
			continue;
		if (nrel != i)
			txn->it[nrel] = txn->it[i];
		txn->it[nrel].ack_deferred = false;
		txn->it[nrel].rc = -EINPROGRESS;
		nrel++;
	}
	txn->n = nrel;
	if (nrel == 0)
		return 0;
	ctx->ledger_release_recommits++;
	rc = dlm_txn_commit(ctx, txn);
	dlm_txn_finalize(ctx, txn, rc);
	return rc;
}

/* a release whose retirement could not be committed (neither
 * durable nor superseded) stays PENDING_RELEASE and is re-driven by the
 * MASTER from mxfs_dlm_release_retry_tick — never by the releaser, which
 * may be gone.  Caller holds table_rwlock. */
static void dlm_mark_release_stuck(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn)
{
	int i;

	for (i = 0; i < txn->n; i++) {
		struct dlm_txn_item *it = &txn->it[i];
		struct mxfs_lock **pp;

		if (!it->release)
			continue;
		pp = dlm_txn_find(ctx, txn, it);
		if (!pp)
			continue;
		(*pp)->rel_id = it->rel_id;
		(*pp)->rel_remote = it->remote_rel;
		(*pp)->rel_failed_ms = mxfs_pal_time_ms();
		ctx->ledger_release_stuck++;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-RELEASE-STUCK type=%u ino=%llu ag=%u owner=%u gen=%u "
			     "rc=%d — retirement not durable; the master re-drives it",
			     txn->resource.type, (unsigned long long)txn->resource.ino,
			     txn->resource.ag_number, it->owner, it->gen, it->rc);
	}
}

static int dlm_promote_txn(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn)
{
	int round, rel_rc = 0;
	bool had_release = false;

	for (round = 0; round < 6; round++) {
		uint32_t bucket = resource_hash(&txn->resource, ctx->bucket_count);
		struct mxfs_lock *grants, *wk;
		int rc, ngrant = 0, nrel = 0, i;
		bool retired = false;

		mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
		grants = promote_waiters(ctx, ctx->buckets[bucket], &txn->resource, txn);
		for (wk = grants; wk; wk = wk->work_next) {
			if (wk->mode == MXFS_LOCK_EX)
				wk->handoff = dg_grant_ex(ctx, &wk->resource, wk->owner,
							  wk->grant_gen, &wk->dir_epoch);
			wk->decide_gen = txn->gen;
			if (dlm_txn_add_grant(txn, wk, 0, 0, wk->owner == ctx->local_node))
				ngrant++;
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		if (txn->n == 0) {
			/* nothing to commit: still re-evaluate blocked waiters */
			struct mxfs_bast_record post_basts[MXFS_MAX_BAST_RECORDS];
			int npost = 0;
			struct mxfs_lock *pb;
			uint8_t blocked_mode = MXFS_LOCK_NL;

			mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
			pb = collect_post_promotion_basts(ctx->buckets[bucket], &txn->resource,
							  &blocked_mode);
			for (wk = pb; wk; wk = wk->work_next) {
				if (npost < MXFS_MAX_BAST_RECORDS) {
					post_basts[npost].owner = wk->owner;
					post_basts[npost].requested_mode = blocked_mode;
					npost++;
				}
			}
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			fire_bast_records(ctx, &txn->resource, post_basts, npost);
			break;
		}
		for (i = 0; i < txn->n; i++)
			if (txn->it[i].release)
				nrel++;
		rc = dlm_txn_commit(ctx, txn);
		if (rc != 0 && rc != -ESTALE && nrel && ngrant) {
			/* the bundle was refused for a grant reason (-EBUSY
			 * DOUBLE-GRANT, -EEXIST collision, ...): deny the grants, then
			 * re-commit the release alone below */
			for (i = 0; i < txn->n; i++)
				if (txn->it[i].release)
					txn->it[i].ack_deferred = true;
		}
		dlm_txn_finalize(ctx, txn, rc);
		if (rc != 0 && rc != -ESTALE && nrel && ngrant)
			rc = dlm_txn_recommit_releases(ctx, txn);
		for (i = 0; i < txn->n; i++) {
			if (!txn->it[i].release)
				continue;
			if (!had_release) {
				rel_rc = txn->it[i].rc;
				had_release = true;
			}
			if (txn->it[i].rc == 0 || txn->it[i].rc == -EAGAIN)
				retired = true;
		}
		if (nrel && !retired && rc != -ESTALE) {
			mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
			dlm_mark_release_stuck(ctx, txn);
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		}
		txn->n = 0;
		if (rc != 0)
			break;
		/* a retirement re-scans even when this round granted
		 * nothing — a sibling PENDING_RELEASE holder (blocking, see
		 * promote_waiters) may have been retired meanwhile, and whichever
		 * of the concurrent releases finalizes LAST must find the waiters
		 * it unblocked.  The finalize removed our entry under the write
		 * lock before this re-scan, so the last one sees every earlier
		 * retirement. */
		if (ngrant == 0 && !retired)
			break;
	}
	return rel_rc;
}

/* An immediate grant decided by the caller (entry already PENDING_DURABLE,
 * item added).  Caller holds NO locks.  Returns the item's rc. */
static int dlm_grant_txn(struct mxfs_dlm_ctx *ctx, struct dlm_txn *txn)
{
	int rc = dlm_txn_commit(ctx, txn);

	dlm_txn_finalize(ctx, txn, rc);
	return txn->n ? txn->it[0].rc : rc;
}

/* ── holder side: un-ACKed releases ── */

static void dlm_rel_pending_add(struct mxfs_dlm_ctx *ctx,
				const struct mxfs_resource_id *res,
				uint32_t rel_id, uint32_t gen, uint64_t auth,
				uint64_t seq, uint64_t lineage, uint8_t mode,
				int open_op)
{
	struct mxfs_dlm_pending_release *pr = mxfs_pal_alloc(sizeof(*pr));

	if (!pr || !ctx->rel_lock) {
		if (pr)
			mxfs_pal_free(pr);
		return;
	}
	memset(pr, 0, sizeof(*pr));
	pr->resource = *res;
	pr->rel_id = rel_id;
	pr->grant_gen = gen;
	pr->auth_epoch = auth;
	pr->grant_seq = seq;
	pr->lineage = lineage;
	pr->mode = mode;
	pr->open_op = (int8_t)open_op;
	pr->sends = 1;
	pr->sent_ms = mxfs_pal_time_ms();
	mxfs_pal_mutex_lock(ctx->rel_lock);
	pr->next = ctx->rel_pending;
	ctx->rel_pending = pr;
	mxfs_pal_mutex_unlock(ctx->rel_lock);
}

static int dlm_acq_live(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *resource, uint8_t mode);

static int dlm_send_release_msg(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t master,
				const struct mxfs_resource_id *res, uint32_t gen,
				uint32_t rel_id, uint64_t auth, uint64_t seq,
				uint64_t lineage, uint8_t mode, int open_op)
{
	struct mxfs_dlm_lock_release rel;
	int ret;

	if (!ctx->send_cb)
		return -ENOTCONN;
	memset(&rel, 0, sizeof(rel));
	rel.hdr.magic = MXFS_DLM_MAGIC;
	rel.hdr.version = MXFS_DLM_VERSION;
	rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
	rel.hdr.length = sizeof(rel);
	rel.hdr.sender = ctx->local_node;
	rel.hdr.target = master;
	rel.hdr.epoch = ctx->current_epoch;
	rel.resource = *res;
	rel.grant_gen = gen;
	rel.rel_id = rel_id;
	rel.authority_epoch = auth;
	rel.grant_seq64 = seq;
	rel.owner_inc = ctx->local_inc;
	rel.owner_slot = ctx->local_slot;
	rel.lineage = lineage;
	rel.mode = mode;
	rel.open_op = (int8_t)open_op;     /* 0.89.0 (D-0977): the mark change rides here */
	/*
	 * 0.84.13: tell the master whether the acquisition that took this grant
	 * is OVER.  A live record for the same resource and mode means a wait
	 * is still re-sending that acquisition's name (a grant kept for it was
	 * released under it before the claim) and must go on being served; no
	 * record means the name is retired and a re-send carrying it is stale.
	 */
	rel.acq_done = dlm_acq_live(ctx, res, mode) ? 0 : 1;
	ret = ctx->send_cb(ctx, master, &rel, sizeof(rel));
	/*
	 * TEST ONLY (dl_stale_resend_ino): the copy of this inode's last
	 * LOCK_REQ goes out now, after the release, exactly as a re-send that
	 * left before the grant arrived and reaches the master after it.
	 */
	if (unlikely(READ_ONCE(mxfs_dl_stale_resend_ino)) && ret == 0 &&
	    res->ino == READ_ONCE(mxfs_dl_stale_resend_ino) &&
	    ctx->dbg_stale_req_valid &&
	    resource_equal(&ctx->dbg_stale_req.resource, res)) {
		int n;

		ctx->dbg_stale_req_valid = 0;
		n = atomic_inc_return(&mxfs_dl_stale_resend_n);
		ctx->send_cb(ctx, master, &ctx->dbg_stale_req,
			     sizeof(ctx->dbg_stale_req));
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "mxfs: P958-STALE-RESEND-SENT n=%d type=%u ino=%llu ag=%u "
		    "master=%u acq=%llu mode=%s acq_done=%u — TEST ONLY: the last "
		    "LOCK_REQ for this inode re-sent after its release",
		    n, res->type, (unsigned long long)res->ino, res->ag_number,
		    master, (unsigned long long)ctx->dbg_stale_req.acq_seq,
		    mode_name(ctx->dbg_stale_req.mode), rel.acq_done);
	}
	return ret;
}

int mxfs_dlm_process_release_ack(struct mxfs_dlm_ctx *ctx,
				 const struct mxfs_dlm_release_ack *ack)
{
	struct mxfs_dlm_pending_release **pp, *found = NULL;

	if (!ctx || !ack || !ctx->rel_lock)
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	for (pp = &ctx->rel_pending; *pp; pp = &(*pp)->next) {
		if ((*pp)->rel_id == ack->rel_id &&
		    resource_equal(&(*pp)->resource, &ack->resource)) {
			found = *pp;
			if (ack->status == MXFS_OK) {
				*pp = found->next;
			} else {
				/* the master could not retire it: retry from the tick
				 * (REMASTER: the tick recomputes the master) */
				found->sent_ms = 0;
				found = NULL;
			}
			break;
		}
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	if (found) {
		ctx->release_acks++;
		mxfs_pal_free(found);
		return 0;
	}
	return -ENOENT;
}

/* master side — re-drive every stuck retirement (see
 * dlm_mark_release_stuck) older than the retry interval.  The releaser
 * may be gone; the master owns the record until it is retired or the
 * page is no longer ours (-ESTALE frees the entry in finalize). */
static void dlm_release_redrive_tick(struct mxfs_dlm_ctx *ctx, uint64_t now)
{
	struct {
		struct mxfs_resource_id res;
		mxfs_node_id_t owner;
		uint32_t gen;
	} stuck[16];
	uint32_t i;
	int n = 0, k;

	if (!ctx->ledger_release_stuck)
		return;
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (i = 0; i < ctx->bucket_count && n < 16; i++) {
		struct mxfs_lock *lk;

		for (lk = ctx->buckets[i]; lk && n < 16; lk = lk->next)
			if (lk->state == MXFS_LSTATE_PENDING_RELEASE && lk->rel_failed_ms &&
			    now - lk->rel_failed_ms >= MXFS_DLM_RELEASE_RETRY_MS) {
				stuck[n].res = lk->resource;
				stuck[n].owner = lk->owner;
				stuck[n].gen = lk->grant_gen;
				n++;
			}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	for (k = 0; k < n; k++) {
		uint32_t bucket = resource_hash(&stuck[k].res, ctx->bucket_count);
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
		struct mxfs_lock *lk;

		if (!txn)
			return;
		dlm_txn_init(txn, &stuck[k].res, ctx->ledger_gen);
		mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
		for (lk = ctx->buckets[bucket]; lk; lk = lk->next)
			if (lk->state == MXFS_LSTATE_PENDING_RELEASE && lk->rel_failed_ms &&
			    lk->owner == stuck[k].owner && lk->grant_gen == stuck[k].gen &&
			    resource_equal(&lk->resource, &stuck[k].res))
				break;
		if (lk) {
			lk->rel_failed_ms = 0;
			dlm_txn_add_release(txn, lk, lk->rel_id, lk->rel_remote);
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		if (lk) {
			ctx->ledger_release_redrives++;
			dlm_promote_txn(ctx, txn);
		}
		mxfs_pal_free(txn);
	}
}

/* (D-0342): re-run every incomplete owner purge older than the
 * retry interval over the pages we master NOW (the generation may have
 * moved: -ESTALE stopped the earlier walk).  mxfs_dlm_ledger_purge_owner
 * re-queues itself on failure and drops the blockers on success. */
static void dlm_purge_redrive_tick(struct mxfs_dlm_ctx *ctx, uint64_t now)
{
	struct { mxfs_node_id_t node; int slot; } run[MXFS_MAX_NODES];
	int n = 0, k;

	if (!ctx->purge_pending_count)
		return;
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (k = 0; k < ctx->purge_pending_count && n < MXFS_MAX_NODES; k++)
		if (now - ctx->purge_pending[k].since_ms >= MXFS_DLM_RELEASE_RETRY_MS) {
			run[n].node = ctx->purge_pending[k].node;
			run[n].slot = ctx->purge_pending[k].slot;
			n++;
		}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	for (k = 0; k < n; k++) {
		ctx->ledger_purge_redrives++;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-TAUTH-PURGE-REDRIVE node=%u slot=%d", run[k].node, run[k].slot);
		if (mxfs_dlm_ledger_purge_owner(ctx, run[k].node, run[k].slot) >= 0)
			mxfs_dlm_purge_node(ctx, run[k].node);   /* blockers gone: promote */
	}
}

/*
 * The two wire-release emitters that do not pass through mxfs_dlm_unlock_gen
 * or mxfs_dlm_send_unconditional_release — the re-send of an un-ACKed release
 * and the rejection of an unsolicited grant — are refused here once this
 * node's session is POISONED (log shut down, slot WITHDRAWN, key retained, a
 * survivor still to fence and replay the slice).  The invariant is the one
 * v5_tcp_release_gate enforces at the front end: an incarnation may remove a
 * durable grant of its own only while no replay-eligible image of that
 * incarnation can still require it, and after the shutdown that cannot be
 * proven for any grant.  A release the master has not acknowledged by the
 * time of the poison is, in the survivor's fence-time manifest, a held grant;
 * keeping it held only lets the replay admit images this incarnation logged
 * under it.  Nothing is lost by refusing: an un-ACKed record already stays a
 * ledger blocker until the recovery purge (P-TAUTH-RELEASE-UNACKED), and the
 * purge that follows the fence retires every record of the dead incarnation,
 * so the master's waiters are promoted by the recovery rather than by a
 * message from a node that is about to be fenced.
 *
 * Bounded log: the tick fires every second for the life of the poisoned mount.
 */
static bool dlm_refuse_release_while_poisoned(struct mxfs_dlm_ctx *ctx,
					      const char *fn,
					      const struct mxfs_resource_id *res)
{
	static mxfs_atomic32_t n;
	int32_t seen;

	if (!ctx->local_poisoned_cb || !ctx->local_poisoned_cb(ctx->cb_data))
		return false;
	seen = mxfs_atomic32_inc(&n);
	if (seen <= 16 || (seen & 255) == 0)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P945-RELEASE-REFUSED-POISONED fn=%s type=%u "
			     "ino=%llu ag=%u n=%d — wire release REFUSED: session "
			     "poisoned (the record stays in the master's table until "
			     "the recovery purge)", fn, res ? res->type : 0,
			     res ? (unsigned long long)res->ino : 0ULL,
			     res ? res->ag_number : 0, seen);
	return true;
}

static void dlm_cancel_retry_tick(struct mxfs_dlm_ctx *ctx, uint64_t now);

void mxfs_dlm_release_retry_tick(struct mxfs_dlm_ctx *ctx)
{
	struct mxfs_dlm_pending_release *resend[16];
	struct mxfs_dlm_pending_release **pp;
	uint64_t now;
	int n = 0, i;

	if (!ctx || !ctx->rel_lock)
		return;
	now = mxfs_pal_time_ms();
	dlm_release_redrive_tick(ctx, now);
	dlm_purge_redrive_tick(ctx, now);
	dlm_cancel_retry_tick(ctx, now);
	if (!ctx->rel_pending)
		return;
	/* The pending list is left as it is: those records are the survivor's
	 * manifest evidence now, and the recovery purge retires them. */
	if (dlm_refuse_release_while_poisoned(ctx, "release_retry",
					      &ctx->rel_pending->resource))
		return;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	pp = &ctx->rel_pending;
	while (*pp && n < 16) {
		struct mxfs_dlm_pending_release *pr = *pp;

		if (now - pr->sent_ms < MXFS_DLM_RELEASE_RETRY_MS) {
			pp = &pr->next;
			continue;
		}
		if (pr->sends >= MXFS_DLM_RELEASE_MAX_SENDS) {
			*pp = pr->next;
			ctx->release_unacked++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-RELEASE-UNACKED type=%u ino=%llu ag=%u rel_id=%u "
				     "grant_id={%llu,%llu} sends=%d — record stays a ledger blocker "
				     "until re-request or recovery purge",
				     pr->resource.type, (unsigned long long)pr->resource.ino,
				     pr->resource.ag_number, pr->rel_id,
				     (unsigned long long)pr->auth_epoch,
				     (unsigned long long)pr->grant_seq, pr->sends);
			mxfs_pal_free(pr);
			continue;
		}
		pr->sends++;
		pr->sent_ms = now;
		resend[n++] = pr;
		pp = &pr->next;
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	for (i = 0; i < n; i++) {
		struct mxfs_dlm_pending_release *pr = resend[i];
		mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, &pr->resource);

		ctx->release_resends++;
		if (master == ctx->local_node) {
			/* remastered onto us: the imported record is ours to retire */
			struct mxfs_dlm_lock_release rel;

			memset(&rel, 0, sizeof(rel));
			rel.resource = pr->resource;
			rel.grant_gen = pr->grant_gen;
			rel.rel_id = pr->rel_id;
			rel.authority_epoch = pr->auth_epoch;
			rel.grant_seq64 = pr->grant_seq;
			rel.owner_inc = ctx->local_inc;
			rel.owner_slot = ctx->local_slot;
			rel.lineage = pr->lineage;
			rel.mode = pr->mode;
			rel.open_op = pr->open_op;
			mxfs_dlm_process_remote_release(ctx, ctx->local_node, &rel);
		} else {
			dlm_send_release_msg(ctx, master, &pr->resource, pr->grant_gen,
					     pr->rel_id, pr->auth_epoch, pr->grant_seq,
					     pr->lineage, pr->mode, pr->open_op);
		}
	}
}

int mxfs_dlm_wait_release_acks(struct mxfs_dlm_ctx *ctx, uint64_t timeout_ms)
{
	uint64_t start;
	int left = 0;

	if (!ctx || !ctx->rel_lock)
		return 0;
	start = mxfs_pal_time_ms();
	for (;;) {
		struct mxfs_dlm_pending_release *pr;

		left = 0;
		mxfs_pal_mutex_lock(ctx->rel_lock);
		for (pr = ctx->rel_pending; pr; pr = pr->next)
			left++;
		mxfs_pal_mutex_unlock(ctx->rel_lock);
		if (left == 0 || mxfs_pal_time_ms() - start >= timeout_ms)
			break;
		mxfs_dlm_release_retry_tick(ctx);
		mxfs_pal_sleep_ms(20);
	}
	if (left) {
		struct mxfs_dlm_pending_release *pr;
		int shown = 0;

		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-RELEASE-WAIT unacked=%d after %llums", left,
			     (unsigned long long)timeout_ms);
		/* 0.75.17: name them — which resource, which master, how often sent */
		mxfs_pal_mutex_lock(ctx->rel_lock);
		for (pr = ctx->rel_pending; pr && shown < 8; pr = pr->next, shown++)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-RELEASE-WAIT-ENTRY type=%u ino=%llu ag=%u "
				     "rel_id=%u sends=%d master=%u",
				     pr->resource.type, (unsigned long long)pr->resource.ino,
				     pr->resource.ag_number, pr->rel_id, pr->sends,
				     mxfs_dlm_resource_master(ctx, &pr->resource));
		mxfs_pal_mutex_unlock(ctx->rel_lock);
	}
	return left;
}

/* ── attach / purge (mount-layer entry points) ── */

/* (D-0347): may the store take over a commit ticket left by
 * {node, inc}?  Only a recovery-purged incarnation — the purge follows the
 * SCSI-PR fence, so that incarnation can issue no further LUN command. */
static bool dlm_store_fenced_cb(void *data, uint32_t node, uint64_t inc)
{
	struct mxfs_dlm_ctx *ctx = data;

	(void)inc;
	return ctx && node && dlm_owner_purged(ctx, node, -1);
}

void mxfs_dlm_set_ledger_geometry(struct mxfs_dlm_ctx *ctx, uint32_t npages,
				  uint64_t hash_seed)
{
	if (!ctx)
		return;
	ctx->page_count = npages;
	ctx->hash_seed = hash_seed;
}

void mxfs_dlm_attach_ledger(struct mxfs_dlm_ctx *ctx,
			    struct mxfs_tauth_ledger *ledger,
			    uint64_t local_inc, uint16_t local_slot)
{
	if (!ctx)
		return;
	ctx->local_inc = local_inc;
	ctx->local_slot = local_slot;
	if (ledger) {
		ledger->store.fenced_cb = dlm_store_fenced_cb;
		ledger->store.fenced_data = ctx;
		ctx->page_count = ledger->npages;
		ctx->hash_seed = ledger->store.hash_seed;
		ctx->page_import_gen = mxfs_pal_alloc(sizeof(uint64_t) * ledger->npages);
		if (ctx->page_import_gen)
			memset(ctx->page_import_gen, 0xff, sizeof(uint64_t) * ledger->npages);
		ctx->page_state = mxfs_pal_alloc(ledger->npages);
		if (ctx->page_state)
			memset(ctx->page_state, DLM_PS_UNKNOWN, ledger->npages);
		ctx->page_req_ms = mxfs_pal_alloc(sizeof(uint64_t) * ledger->npages);
		if (ctx->page_req_ms)
			memset(ctx->page_req_ms, 0, sizeof(uint64_t) * ledger->npages);
		mxfs_tauth_ledger_set_config_id(ledger, ctx->my_view_hash);
		mxfs_pal_mutex_lock(ctx->active_nodes.lock);
		ctx->view_seq++;
		ctx->ledger_gen = (ctx->my_view_hash ^ local_inc) +
				  ctx->view_seq * 0x9E3779B97F4A7C15ULL;
		mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
		mxfs_tauth_ledger_set_owner_gen(ledger, ctx->ledger_gen);
	}
	ctx->ledger = ledger;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-TAUTH-ATTACH node=%u inc=%llu slot=%u ledger=%d gen=%#llx",
		     ctx->local_node, (unsigned long long)local_inc, local_slot,
		     ledger ? 1 : 0, (unsigned long long)ctx->ledger_gen);
}

int mxfs_dlm_ledger_purge_owner(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
				int slot)
{
	uint32_t i;
	int rc = 0, dropped = 0;

	if (!ctx)
		return -EINVAL;
	/*
	 * 0.75.8: the slot half of a purge clears that slot's shared holder
	 * bits on every page this node masters and drops that slot's imported
	 * shared blockers.  A shared bit names a slot, not an incarnation: once
	 * a DIFFERENT live incarnation occupies the departed node's slot, those
	 * bits are the successor's live grants.  Purge by node id only then;
	 * the departed incarnation's leftover bits resolve to the successor,
	 * which answers the BAST for a grant it does not hold.
	 */
	if (slot >= 0 && ctx->slot_node_cb) {
		mxfs_node_id_t occupant = ctx->slot_node_cb(ctx->cb_data, slot, NULL);

		if (occupant != 0 && occupant != MXFS_DLM_NODE_UNKNOWN && occupant != node) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-TAUTH-PURGE-SLOT-LIVE node=%u slot=%d occupant=%u — "
				     "the slot belongs to a live successor; purging by node id only",
				     node, slot, occupant);
			slot = -1;
		}
	}
	/* remember (dead ids never return): later page loads retire instead
	 * of importing */
	dlm_owner_mark_purged(ctx, node, slot);
	if (dlm_ledger_active(ctx)) {
		rc = mxfs_tauth_ledger_purge_owner(ctx->ledger, node, slot, ctx->ledger_gen,
						   (uint64_t)ctx->current_epoch,
						   dlm_owns_page_cb, ctx);
		if (rc < 0)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-PURGE-FAIL node=%u slot=%d rc=%d", node, slot, rc);
	}
	/*
	 * (D-0342, ruling ccmemory ccloop-c7ee71c6-sess425-GPT-ruling-
	 * partial-ledger-purge-held-failure): a purge that did not complete
	 * (a page commit failed, or the view moved and the walk stopped at a
	 * page that is no longer ours under this generation) leaves bits on
	 * the platter.  The imported blockers that mirror them STAY — dropping
	 * them made every survivor decide grants the ledger refuses (0.34.0
	 * test20: two partial purges rc=-5, completion published the slot over
	 * them) — and the master re-drives the purge from its tick until a
	 * whole pass over the pages it masters NOW returns 0.
	 */
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	if (rc < 0) {
		int k;

		for (k = 0; k < ctx->purge_pending_count; k++)
			if (ctx->purge_pending[k].node == node)
				break;
		if (k == ctx->purge_pending_count && k < MXFS_MAX_NODES) {
			ctx->purge_pending[k].node = node;
			ctx->purge_pending[k].slot = slot;
			ctx->purge_pending_count++;
			ctx->ledger_purge_partial++;
		}
		if (k < MXFS_MAX_NODES) {
			ctx->purge_pending[k].since_ms = mxfs_pal_time_ms();
			ctx->purge_pending[k].rc = rc;
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-PURGE-PENDING node=%u slot=%d rc=%d — blockers kept; "
			     "the master re-drives the purge", node, slot, rc);
		return rc;
	}
	{
		int k;

		for (k = 0; k < ctx->purge_pending_count; k++)
			if (ctx->purge_pending[k].node == node) {
				ctx->purge_pending[k] = ctx->purge_pending[ctx->purge_pending_count - 1];
				ctx->purge_pending_count--;
				break;
			}
	}
	/* drop the imported blockers that named this owner */
	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock **pp = &ctx->buckets[i];

		while (*pp) {
			struct mxfs_lock *lk = *pp;

			if (lk->imported &&
			    (lk->owner == node ||
			     (slot >= 0 && lk->owner_slot == (uint16_t)slot &&
			      !dlm_mode_exclusive(lk->mode)))) {
				*pp = lk->next;
				ctx->lock_count--;
				lock_free(lk);
				dropped++;
			} else {
				pp = &lk->next;
			}
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-TAUTH-PURGE-OWNER node=%u slot=%d ledger_rc=%d imported_dropped=%d",
		     node, slot, rc, dropped);
	return rc;
}

/*
 * 0.75.30 (D-TCP-REFUSED-VICTIM-KEEPS-MASTERSHIP-OUT-OF-MASK-RESOURCES-
 * UNAVAILABLE-0910): the selective counterpart of mxfs_dlm_ledger_purge_owner
 * for a terminally refused victim.  Measured s518i (2 nodes / TCP, AG-scoped
 * refusal sparing AG 0): the survivor could not create anything at the root
 * — 8 of 8 mkdirs timed out, 68 P-RBLK-DENY-DEAD-MASTER for the new inodes,
 * every one of whose pages was still mastered by the refused dead node —
 * because the refusal path never took the victim out of the view.  The
 * victim now leaves the view like a completed recovery's, and this purge
 * retires only what the verdict provably spares.  Contract in dlm.h.
 */
int mxfs_dlm_ledger_purge_owner_selective(struct mxfs_dlm_ctx *ctx,
					  mxfs_node_id_t node, int slot)
{
	struct dlm_refused_keep_arg ka;
	int rc = 0, rslot = -1;

	if (!ctx || !node)
		return -EINVAL;
	if (!dlm_owner_refused(ctx, node, &rslot)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-TAUTH-PURGE-SELECTIVE-NOTREFUSED node=%u slot=%d — the "
			     "mount layer does not name this owner as terminally refused; "
			     "nothing purged (the unconditional purge is the completion "
			     "ladder's, never this path's)",
			     node, slot);
		return -EINVAL;
	}
	if (slot < 0)
		slot = rslot;
	/* the 0.75.8 live-successor rule applies to the slot half here too */
	if (slot >= 0 && ctx->slot_node_cb) {
		mxfs_node_id_t occupant = ctx->slot_node_cb(ctx->cb_data, slot, NULL);

		if (occupant != 0 && occupant != MXFS_DLM_NODE_UNKNOWN && occupant != node) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-TAUTH-PURGE-SLOT-LIVE node=%u slot=%d occupant=%u — "
				     "the slot belongs to a live successor; purging by node id only",
				     node, slot, occupant);
			slot = -1;
		}
	}
	ka.ctx = ctx;
	ka.owner = node;
	ka.kept = 0;
	if (dlm_ledger_active(ctx)) {
		rc = mxfs_tauth_ledger_purge_owner_keep(ctx->ledger, node, slot, ctx->ledger_gen,
							(uint64_t)ctx->current_epoch,
							dlm_owns_page_cb, ctx,
							dlm_refused_keep_entry, &ka);
		if (rc < 0)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-PURGE-SELECTIVE-PARTIAL node=%u slot=%d rc=%d "
				     "kept=%u — out-of-domain records beyond the failed page "
				     "stay frozen (a leftover that blocks nobody costs nobody); "
				     "the in-domain ones were never candidates",
				     node, slot, rc, ka.kept);
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-TAUTH-PURGE-SELECTIVE node=%u slot=%d ledger_rc=%d kept=%u",
		     node, slot, rc, ka.kept);
	return rc;
}

/* ─── Compatibility check ─── */

int mxfs_dlm_modes_compatible(uint8_t held, uint8_t requested)
{
	if (held >= MXFS_LOCK_MODE_COUNT || requested >= MXFS_LOCK_MODE_COUNT)
		return 0;
	return lock_compat[held][requested];
}

/* ─── Per-mount create / destroy ─── */

struct mxfs_dlm_ctx *mxfs_dlm_create(mxfs_node_id_t local_node)
{
	struct mxfs_dlm_ctx *ctx;
	int i;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));

	ctx->bucket_count = MXFS_DLM_DEFAULT_BUCKETS;
	ctx->buckets = mxfs_pal_alloc(ctx->bucket_count *
				      sizeof(struct mxfs_lock *));
	if (!ctx->buckets) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm: failed to allocate %u hash buckets",
			     ctx->bucket_count);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->lock_count = 0;
	ctx->table_rwlock = mxfs_pal_rwlock_create();
	if (!ctx->table_rwlock) {
		mxfs_pal_free(ctx->buckets);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->local_node = local_node;
	ctx->shutting_down = false;
	ctx->grant_gen_next = 1;
	ctx->current_epoch = 1;
	ctx->epoch_lock = mxfs_pal_mutex_create();

	ctx->active_nodes.lock = mxfs_pal_mutex_create();
	ctx->active_nodes.nodes[0] = local_node;
	ctx->active_nodes.count = 1;

	/* Init pending remote request hash table */
	ctx->pending_lock = mxfs_pal_mutex_create();
	for (i = 0; i < MXFS_DLM_PENDING_SIZE; i++)
		ctx->pending_buckets[i] = NULL;

	ctx->grant_cb = NULL;
	ctx->bast_cb = NULL;
	ctx->send_cb = NULL;
	ctx->membership_cb = NULL;
	ctx->cb_data = NULL;

	/* holder-side un-ACKed release list */
	ctx->rel_lock = mxfs_pal_mutex_create();
	ctx->req_id_next = 1;
	ctx->rel_id_next = 1;

	/* The logical acquisitions this node has in flight.  Its own lock, taken
	 * innermost, because the local queue path needs a stamp while it already
	 * holds the sleeping table lock. */
	ctx->acq_lock = mxfs_pal_spinlock_create();
	ctx->acq_seq_next = 0;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: created for node %u with %u buckets",
		     ctx->local_node, ctx->bucket_count);
	return ctx;
}

void mxfs_dlm_destroy(struct mxfs_dlm_ctx *ctx)
{
	uint32_t i;
	uint32_t freed = 0;

	if (!ctx)
		return;

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock *lk = ctx->buckets[i];

		while (lk) {
			struct mxfs_lock *next = lk->next;

			lock_free(lk);
			freed++;
			lk = next;
		}
		ctx->buckets[i] = NULL;
	}

	ctx->lock_count = 0;
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	mxfs_pal_free(ctx->buckets);
	ctx->buckets = NULL;

	mxfs_pal_rwlock_destroy(ctx->table_rwlock);
	mxfs_pal_mutex_destroy(ctx->epoch_lock);
	mxfs_pal_mutex_destroy(ctx->active_nodes.lock);
	mxfs_pal_mutex_destroy(ctx->pending_lock);
	if (ctx->acq_lock) {
		mxfs_pal_spinlock_destroy(ctx->acq_lock);
		ctx->acq_lock = NULL;
	}

	/* ledger bookkeeping (the ledger object itself belongs to the
	 * mount layer, which closes it after destroying the DLM) */
	if (ctx->rel_lock) {
		struct mxfs_dlm_pending_release *pr = ctx->rel_pending;
		struct mxfs_dlm_pending_cancel *pc = ctx->cancel_pending;

		while (pr) {
			struct mxfs_dlm_pending_release *next = pr->next;

			mxfs_pal_free(pr);
			pr = next;
		}
		while (pc) {
			struct mxfs_dlm_pending_cancel *next = pc->next;

			mxfs_pal_free(pc);
			pc = next;
		}
		mxfs_pal_mutex_destroy(ctx->rel_lock);
	}
	if (ctx->page_import_gen)
		mxfs_pal_free(ctx->page_import_gen);
	if (ctx->page_state)
		mxfs_pal_free(ctx->page_state);
	if (ctx->page_req_ms)
		mxfs_pal_free(ctx->page_req_ms);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: destroyed, freed %u lock entries", freed);
	mxfs_pal_free(ctx);
}

/* ─── mxfs_dlm_lock — Local lock acquisition ─── */

/*
 * Implementation body for mxfs_dlm_lock — called from the retry
 * wrapper below. Returns MXFS_DLM_RETRY if the request was
 * interrupted by a membership change and should be retried.
 */
/*
 * (instrumentation, rig test3 'lock request failed after 10
 * retries' x14 with NO deny status in dmesg): every RETRY answer names its
 * site.  1 remote pending completed RETRY (membership purge / fail_all);
 * 2 remote DENY REMASTER; 3 remote DENY LEDGER_BUSY; 4 local
 * dlm_ledger_prepare -EAGAIN (page not ours / frozen); 5 own entry
 * PENDING_DURABLE, attach wait ended without a grant; 6 own entry
 * PENDING_RELEASE; 7 local decision refused (see site); 8 local grant txn
 * -EAGAIN (remaster); 9 local WAITING pending completed RETRY.
 */
static int dlm_retry(struct mxfs_dlm_ctx *ctx, int why)
{
	if (why > 0 && why < 11)
		ctx->retry_why[why]++;
	return MXFS_DLM_RETRY;
}

/*
 * ─── Logical acquisition identity (requester side) ───
 *
 * A remote acquire is a WAIT, and that wait outlives every transport attempt
 * inside it: three descents of sixty one-second re-sends, and then however
 * many times the acquire classifier restarts behind a live master.  Until now
 * nothing on the wire said so.  Each re-send carried a fresh req_id, so the
 * master could only read it as a new request — it freed the requester's queue
 * entry and inserted another one every second, discarding the entry's position
 * in the chain and its first-enqueue time, and firing another blocking
 * notification at a holder that was already draining.  Measured on 2 nodes /
 * TCP across one 244 s acquire behind one live holder: 238 notifications fired
 * at the holder against 234 re-sends by the requester, for a single wait.
 *
 * dlm_acq_begin hands back the name of the wait this attempt belongs to,
 * minting one only when the resource has no live acquisition.  dlm_acq_end
 * retires it when the attempt returns anything other than "no answer yet".
 */
static void dlm_acq_release_grant(struct mxfs_dlm_ctx *ctx,
				  const struct mxfs_resource_id *resource,
				  const struct mxfs_dlm_acq_grant *g,
				  const char *why);

static uint64_t dlm_acq_begin(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint8_t mode,
			      uint64_t *first_ms,
			      struct mxfs_dlm_acq_grant *grant_out)
{
	uint64_t now = mxfs_pal_time_ms();
	uint64_t seq = 0, first = now;
	int pid = mxfs_pal_current_pid();
	int i, freeslot = -1, oldest = -1;
	/* What this call had to destroy to proceed, reported outside the lock. */
	int lost_idle = 0, lost_evict = 0, collide_pid = 0;
	uint64_t lost_ms = 0;
	/* At most ONE adopted grant is released per call, outside the lock; a
	 * record holding one is otherwise left alone by the idle scan and by
	 * eviction, because retiring it silently would leak a live grant. */
	struct mxfs_dlm_acq_grant orphan;
	struct mxfs_resource_id orphan_res;

	if (grant_out)
		memset(grant_out, 0, sizeof(*grant_out));
	memset(&orphan, 0, sizeof(orphan));
	if (!ctx->acq_lock) {
		if (first_ms)
			*first_ms = now;
		return 0;
	}
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (!ctx->acq[i].in_use) {
			if (freeslot < 0)
				freeslot = i;
			continue;
		}
		/* The backstop for an acquire that ended without saying so.
		 *
		 * It cannot tell an abandoned record from a live wait whose next
		 * attempt was simply slow to arrive — one second bounds one
		 * pending_wait, not the turnaround to the next call in.  The case
		 * that costs something is narrow and is the one counted: the record
		 * this caller would have MATCHED is the record this scan retires,
		 * so the wait loses its own age and notification clock to its own
		 * next attempt.  Counted rather than assumed, because whether it
		 * ever happens under a real workload is a measurement. */
		if (now >= ctx->acq[i].last_ms &&
		    now - ctx->acq[i].last_ms > MXFS_DLM_ACQ_IDLE_MS) {
			/* An idle record holding an adopted grant is retired only when
			 * this call can release that grant on the way out; otherwise it
			 * waits for a later call (one release per call). */
			if (ctx->acq[i].grant.have) {
				if (orphan.have)
					continue;
				orphan = ctx->acq[i].grant;
				orphan_res = ctx->acq[i].resource;
			}
			if (resource_equal(&ctx->acq[i].resource, resource) &&
			    ctx->acq[i].mode == mode) {
				ctx->acq_idle_live++;
				lost_idle = 1;
				lost_ms = now - ctx->acq[i].last_ms;
			}
			ctx->acq[i].in_use = 0;
			ctx->acq_retired++;
			if (freeslot < 0)
				freeslot = i;
			continue;
		}
		/* Same resource AND same mode: one name must never come to mean
		 * two different requests, so a mode change starts a new wait.
		 *
		 * Deliberately NOT also the task.  The master keeps one entry per
		 * (resource, sender node), so this name must be the NODE's wait: a
		 * per-task name would make a second task's re-send fail the
		 * master's identity test and take the replace-and-requeue path,
		 * which is one notification per re-send for that shape.  The cost
		 * is that two tasks here share one age and one notification clock,
		 * and the first to finish retires it under the other.  Counted, so
		 * that a design change rests on how often it happens rather than on
		 * the fact that it can. */
		if (resource_equal(&ctx->acq[i].resource, resource) &&
		    ctx->acq[i].mode == mode) {
			if (ctx->acq[i].owner_pid != pid) {
				ctx->acq_key_collide++;
				collide_pid = ctx->acq[i].owner_pid;
			}
			ctx->acq[i].last_ms = now;
			seq = ctx->acq[i].acq_seq;
			first = ctx->acq[i].first_ms;
			if (grant_out)
				*grant_out = ctx->acq[i].grant;
			break;
		}
		/* A record holding an adopted grant is never the eviction victim:
		 * evicting it would leak the grant. */
		if (!ctx->acq[i].grant.have &&
		    (oldest < 0 ||
		     ctx->acq[i].last_ms < ctx->acq[oldest].last_ms))
			oldest = i;
	}
	if (!seq && freeslot < 0 && oldest < 0) {
		/* Every record holds an adopted grant nobody has claimed yet.  This
		 * attempt goes out unnamed (acq_seq 0, the pre-table behaviour);
		 * the next call retires one of them. */
		mxfs_pal_spinlock_unlock(ctx->acq_lock);
		if (orphan.have)
			dlm_acq_release_grant(ctx, &orphan_res, &orphan, "idle");
		if (first_ms)
			*first_ms = now;
		return 0;
	}
	if (!seq) {
		int slot = freeslot >= 0 ? freeslot : oldest;

		/* No free slot: this mint takes a live record away from whoever
		 * owns it, and that wait silently restarts its age and its
		 * notification clock on its next attempt. */
		if (freeslot < 0 && ctx->acq[slot].in_use) {
			ctx->acq_retired++;
			ctx->acq_evict_live++;
			lost_evict = 1;
		}
		seq = ++ctx->acq_seq_next;
		ctx->acq[slot].resource = *resource;
		ctx->acq[slot].acq_seq = seq;
		ctx->acq[slot].first_ms = now;
		ctx->acq[slot].last_ms = now;
		ctx->acq[slot].bast_ms = 0;
		ctx->acq[slot].mode = mode;
		ctx->acq[slot].owner_pid = pid;
		ctx->acq[slot].master = MXFS_DLM_NODE_UNKNOWN;
		ctx->acq[slot].receipt_ms = 0;
		ctx->acq[slot].confirm_ms = 0;
		ctx->acq[slot].degraded_ms = 0;
		ctx->acq[slot].retx = 0;
		ctx->acq[slot].rejected = 0;
		memset(ctx->acq[slot].attempt, 0, sizeof(ctx->acq[slot].attempt));
		ctx->acq[slot].attempt_next = 0;
		memset(&ctx->acq[slot].grant, 0, sizeof(ctx->acq[slot].grant));
		ctx->acq[slot].in_use = 1;
		ctx->acq_minted++;
		first = now;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	if (orphan.have)
		dlm_acq_release_grant(ctx, &orphan_res, &orphan, "idle");
	/* Every line carries the mount's running total, so a reader can never
	 * take the number of printed lines for the number of events. */
	if (lost_idle)
		pr_warn_ratelimited(
		    "mxfs: P958-ACQ-IDLE-LOST type=%u ino=%llu ag=%u mode=%s idle_ms=%llu total=%llu — a wait's own next attempt retired its record as abandoned; age and notification clock restart\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, mode_name(mode),
		    (unsigned long long)lost_ms,
		    (unsigned long long)ctx->acq_idle_live);
	if (lost_evict)
		mxfs_probe_ratelimited(
		    "mxfs: P958-ACQ-EVICT-LIVE type=%u ino=%llu ag=%u mode=%s slots=%d total=%llu — acquisition table full of live records; one was taken to make room\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, mode_name(mode),
		    MXFS_DLM_ACQ_SLOTS,
		    (unsigned long long)ctx->acq_evict_live);
	if (collide_pid)
		pr_warn_ratelimited(
		    "mxfs: P958-ACQ-KEY-COLLIDE type=%u ino=%llu ag=%u mode=%s pid=%d opened_by=%d total=%llu — a second task joined this resource's acquisition record; they now share one age and one notification clock\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, mode_name(mode), pid, collide_pid,
		    (unsigned long long)ctx->acq_key_collide);
	if (first_ms)
		*first_ms = first;
	return seq;
}

/*
 * May this wait fire a blocking notification now?
 *
 * The LOCAL-master path re-fires on every attempt because its waiting entry is
 * freed and re-created on every one-second timeout, so the entry's own
 * re-fire clock dies with it.  The acquisition record outlives both, which is
 * where the clock has to live.  A wait with no record (the acquisition table
 * is full, or this is the opening attempt) fires, because failing to notify a
 * holder is the one outcome that must never happen.
 */
static int dlm_acq_bast_due(struct mxfs_dlm_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t mode)
{
	uint64_t now = mxfs_pal_time_ms();
	int i, due = 1;

	if (!ctx->acq_lock)
		return 1;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (!ctx->acq[i].in_use || ctx->acq[i].mode != mode ||
		    !resource_equal(&ctx->acq[i].resource, resource))
			continue;
		if (ctx->acq[i].bast_ms && now >= ctx->acq[i].bast_ms &&
		    now - ctx->acq[i].bast_ms < MXFS_DLM_ACQ_BAST_REFIRE_MS)
			due = 0;
		else
			ctx->acq[i].bast_ms = now;
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	if (!due)
		ctx->acq_bast_refire++;
	return due;
}

/*
 * The wait ended.  `claimed` says the caller is taking the adopted grant the
 * record may hold (the claim path in dlm_lock_impl); any other ending — a
 * grant or denial that completed a pending entry, a send failure, a
 * membership retry — leaves an adopted grant with no owner, and it is
 * released here exactly as the unsolicited-grant bounce would have.
 */
static void dlm_acq_end(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *resource,
			uint8_t mode, int claimed)
{
	uint64_t degraded_for = 0, age = 0, seq = 0;
	uint32_t retx = 0;
	mxfs_node_id_t master = 0;
	struct mxfs_dlm_acq_grant orphan;
	int i;

	memset(&orphan, 0, sizeof(orphan));
	if (!ctx->acq_lock)
		return;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (ctx->acq[i].in_use &&
		    ctx->acq[i].mode == mode &&
		    resource_equal(&ctx->acq[i].resource, resource)) {
			if (ctx->acq[i].degraded_ms) {
				uint64_t now = mxfs_pal_time_ms();

				degraded_for = now - ctx->acq[i].degraded_ms;
				age = now - ctx->acq[i].first_ms;
				seq = ctx->acq[i].acq_seq;
				retx = ctx->acq[i].retx;
				master = ctx->acq[i].master;
			}
			if (!claimed && ctx->acq[i].grant.have)
				orphan = ctx->acq[i].grant;
			ctx->acq[i].in_use = 0;
			ctx->acq_retired++;
			break;
		}
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	if (orphan.have)
		dlm_acq_release_grant(ctx, resource, &orphan, "unclaimed");
	if (seq)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P958-ACQ-DEGRADED-END acq=%llu type=%u ino=%llu "
			     "ag=%u mode=%s master=%u retx=%u age_ms=%llu "
			     "degraded_for_ms=%llu — a wait that was reported "
			     "DEGRADED has ended (answered, failed, or abandoned by "
			     "its caller)",
			     (unsigned long long)seq, resource->type,
			     (unsigned long long)resource->ino, resource->ag_number,
			     mode_name(mode), master, retx,
			     (unsigned long long)age,
			     (unsigned long long)degraded_for);
}

/*
 * A grant arrived for a resource with no pending entry to complete.  If a
 * live wait on this node solicited it — same resource, a mode the grant
 * satisfies, no grant adopted yet — the wait keeps it: the mirror the
 * receiver already installed stays, and the wait's next attempt claims the
 * grant instead of sending.  Returns 1 when adopted.
 */
static int dlm_acq_adopt_grant(struct mxfs_dlm_ctx *ctx,
			       const struct mxfs_dlm_lock_resp *resp)
{
	int i, adopted = 0;

	if (!ctx->acq_lock)
		return 0;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (!ctx->acq[i].in_use ||
		    !resource_equal(&ctx->acq[i].resource, &resp->resource))
			continue;
		if (ctx->acq[i].grant.have)
			continue;
		if (resp->mode < ctx->acq[i].mode)
			continue;      /* the grant does not cover the mode asked for */
		ctx->acq[i].grant.have = 1;
		ctx->acq[i].grant.mode = resp->mode;
		ctx->acq[i].grant.handoff = resp->handoff;
		ctx->acq[i].grant.grant_gen = resp->grant_gen;
		ctx->acq[i].grant.dir_epoch = resp->dir_epoch;
		ctx->acq[i].grant.auth_epoch = resp->authority_epoch;
		ctx->acq[i].grant.grant_seq = resp->grant_seq64;
		ctx->acq[i].grant.lineage = resp->lineage;
		ctx->acq[i].grant.adopted_ms = mxfs_pal_time_ms();
		ctx->acq_grant_adopted++;
		adopted = 1;
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	return adopted;
}

/* The adopted grant's mirror is gone (released or purged under the wait):
 * forget the adoption so the next attempt sends. */
static void dlm_acq_clear_grant(struct mxfs_dlm_ctx *ctx,
				const struct mxfs_resource_id *resource,
				uint8_t mode)
{
	int i;

	if (!ctx->acq_lock)
		return;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (ctx->acq[i].in_use && ctx->acq[i].mode == mode &&
		    resource_equal(&ctx->acq[i].resource, resource)) {
			memset(&ctx->acq[i].grant, 0, sizeof(ctx->acq[i].grant));
			break;
		}
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
}

/*
 * Release an adopted grant no wait will claim: unlink the mirror it installed
 * (only if that exact grant episode is still the one in the table) and hand
 * the grant back to its master with the gen-stamped release the unsolicited-
 * grant path uses, so the master retires it and promotes the next waiter.
 */
static void dlm_acq_release_grant(struct mxfs_dlm_ctx *ctx,
				  const struct mxfs_resource_id *resource,
				  const struct mxfs_dlm_acq_grant *g,
				  const char *why)
{
	mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, resource);
	uint32_t bucket = resource_hash(resource, ctx->bucket_count);
	struct mxfs_lock **pp;
	int unlinked = 0;

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	pp = &ctx->buckets[bucket];
	while (*pp) {
		struct mxfs_lock *lk = *pp;

		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == ctx->local_node &&
		    lk->state == MXFS_LSTATE_GRANTED &&
		    lk->grant_gen == g->grant_gen) {
			*pp = lk->next;
			lock_free(lk);
			ctx->lock_count--;
			unlinked = 1;
			break;
		}
		pp = &(*pp)->next;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	ctx->acq_grant_released++;
	mxfs_probe_ratelimited(
	    "mxfs: P958-ACQ-GRANT-RELEASED type=%u ino=%llu ag=%u mode=%s gen=%u master=%u why=%s mirror_unlinked=%d total=%llu — an adopted grant no wait claimed is handed back to its master\n",
	    resource->type, (unsigned long long)resource->ino,
	    resource->ag_number, mode_name(g->mode), g->grant_gen, master, why,
	    unlinked, (unsigned long long)ctx->acq_grant_released);
	if (master != ctx->local_node && ctx->send_cb &&
	    !dlm_refuse_release_while_poisoned(ctx, "acq_grant_release",
					       resource)) {
		uint32_t rel_id = ++ctx->rel_id_next;

		if (rel_id == 0)
			rel_id = ctx->rel_id_next = 1;
		dlm_rel_pending_add(ctx, resource, rel_id, g->grant_gen,
				    g->auth_epoch, g->grant_seq, g->lineage, g->mode,
				    MXFS_TAUTH_OPEN_NONE);
		dlm_send_release_msg(ctx, master, resource, g->grant_gen, rel_id,
				     g->auth_epoch, g->grant_seq, g->lineage, g->mode,
				     MXFS_TAUTH_OPEN_NONE);
	}
}

/* ─── Abandonment: LOCK_CANCEL, its tombstones and its acknowledgement ─── */

/* Caller holds table_rwlock (either side). */
static int dlm_cancel_tombstoned(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
				 uint64_t owner_inc, uint64_t acq_seq)
{
	int i;

	for (i = 0; i < MXFS_DLM_CANCEL_TOMBS; i++) {
		if (ctx->cancel_tomb[i].ms &&
		    ctx->cancel_tomb[i].sender == sender &&
		    ctx->cancel_tomb[i].owner_inc == owner_inc &&
		    ctx->cancel_tomb[i].acq_seq == acq_seq)
			return 1;
	}
	return 0;
}

/* Caller holds table_rwlock for writing. */
static void dlm_cancel_tomb_add(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
				uint64_t owner_inc, uint64_t acq_seq)
{
	uint32_t i;

	if (dlm_cancel_tombstoned(ctx, sender, owner_inc, acq_seq))
		return;
	i = ctx->cancel_tomb_next % MXFS_DLM_CANCEL_TOMBS;
	ctx->cancel_tomb_next++;
	ctx->cancel_tomb[i].sender = sender;
	ctx->cancel_tomb[i].owner_inc = owner_inc;
	ctx->cancel_tomb[i].acq_seq = acq_seq;
	ctx->cancel_tomb[i].ms = mxfs_pal_time_ms();
}

/*
 * 0.84.13: the CONSUMED tombstones — acquisitions whose grant the sender
 * took and released with acq_done set.  Same contract as the cancel ring:
 * caller holds table_rwlock (either side to ask, writing to add).
 */
static int dlm_consumed_tombstoned(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
				   uint64_t owner_inc, uint64_t acq_seq)
{
	int i;

	for (i = 0; i < MXFS_DLM_CONSUMED_TOMBS; i++) {
		if (ctx->consumed_tomb[i].ms &&
		    ctx->consumed_tomb[i].sender == sender &&
		    ctx->consumed_tomb[i].owner_inc == owner_inc &&
		    ctx->consumed_tomb[i].acq_seq == acq_seq)
			return 1;
	}
	return 0;
}

static void dlm_consumed_tomb_add(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
				  uint64_t owner_inc, uint64_t acq_seq)
{
	uint32_t i;

	if (dlm_consumed_tombstoned(ctx, sender, owner_inc, acq_seq))
		return;
	i = ctx->consumed_tomb_next % MXFS_DLM_CONSUMED_TOMBS;
	ctx->consumed_tomb_next++;
	ctx->consumed_tomb[i].sender = sender;
	ctx->consumed_tomb[i].owner_inc = owner_inc;
	ctx->consumed_tomb[i].acq_seq = acq_seq;
	ctx->consumed_tomb[i].ms = mxfs_pal_time_ms();
	ctx->consumed_tomb_added++;
}

/* REQUESTER SIDE: is an acquisition of this resource and mode still live in
 * the acquisition table (a wait still re-sending that name)? */
static int dlm_acq_live(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *resource, uint8_t mode)
{
	int i, live = 0;

	if (!ctx->acq_lock)
		return 0;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (ctx->acq[i].in_use && ctx->acq[i].mode == mode &&
		    resource_equal(&ctx->acq[i].resource, resource)) {
			live = 1;
			break;
		}
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	return live;
}

static int dlm_send_cancel_msg(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t master,
			       const struct mxfs_resource_id *res,
			       uint64_t acq_seq, uint32_t cancel_id, uint8_t mode)
{
	struct mxfs_dlm_lock_cancel msg;

	if (!ctx->send_cb)
		return -ENOTCONN;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = MXFS_MSG_LOCK_CANCEL;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = ctx->local_node;
	msg.hdr.target = master;
	msg.hdr.epoch = ctx->current_epoch;
	msg.resource = *res;
	msg.owner_inc = ctx->local_inc;
	msg.acq_seq = acq_seq;
	msg.cancel_id = cancel_id;
	msg.mode = mode;
	return ctx->send_cb(ctx, master, &msg, sizeof(msg));
}

static void dlm_send_cancel_ack(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t target,
				const struct mxfs_dlm_lock_cancel *msg,
				uint8_t outcome)
{
	struct mxfs_dlm_cancel_ack ack;

	if (!ctx->send_cb || target == ctx->local_node)
		return;
	memset(&ack, 0, sizeof(ack));
	ack.hdr.magic = MXFS_DLM_MAGIC;
	ack.hdr.version = MXFS_DLM_VERSION;
	ack.hdr.type = MXFS_MSG_LOCK_CANCEL_ACK;
	ack.hdr.length = sizeof(ack);
	ack.hdr.sender = ctx->local_node;
	ack.hdr.target = target;
	ack.hdr.epoch = ctx->current_epoch;
	ack.resource = msg->resource;
	ack.owner_inc = msg->owner_inc;
	ack.acq_seq = msg->acq_seq;
	ack.cancel_id = msg->cancel_id;
	ack.outcome = outcome;
	ctx->send_cb(ctx, target, &ack, sizeof(ack));
}

/*
 * The caller has decided to fail its operation instead of waiting for this
 * resource any longer.  Nothing is installed.  The master is told by name
 * (retried from the release tick until it acknowledges, or given up after
 * the release send budget), the wait's record is retired, and a grant that
 * had been kept for the wait between attempts is handed back.  Engine-owned
 * from here: the abandoning task may be gone before the ack arrives.
 */
void mxfs_dlm_acq_abandon(struct mxfs_dlm_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint8_t mode)
{
	uint64_t seq = 0;
	mxfs_node_id_t master;
	int i;

	if (!ctx || !resource)
		return;
	master = mxfs_dlm_resource_master(ctx, resource);
	if (ctx->acq_lock) {
		mxfs_pal_spinlock_lock(ctx->acq_lock);
		for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
			if (ctx->acq[i].in_use && ctx->acq[i].mode == mode &&
			    resource_equal(&ctx->acq[i].resource, resource)) {
				seq = ctx->acq[i].acq_seq;
				if (ctx->acq[i].master != MXFS_DLM_NODE_UNKNOWN &&
				    ctx->acq[i].master != 0)
					master = ctx->acq[i].master;
				break;
			}
		}
		mxfs_pal_spinlock_unlock(ctx->acq_lock);
	}
	if (unlikely(READ_ONCE(mxfs_dl_no_cancel)) && seq) {
		mxfs_probe_ratelimited(
		    "mxfs: P958-ACQ-CANCEL-SUPPRESSED acq=%llu type=%u ino=%llu ag=%u mode=%s master=%u — TEST ONLY: abandoning without telling the master (control)\n",
		    (unsigned long long)seq, resource->type,
		    (unsigned long long)resource->ino, resource->ag_number,
		    mode_name(mode), master);
		seq = 0;
	}
	if (seq && master != ctx->local_node && ctx->rel_lock) {
		struct mxfs_dlm_pending_cancel *pc = mxfs_pal_alloc(sizeof(*pc));
		uint32_t cancel_id = ++ctx->cancel_id_next;

		if (cancel_id == 0)
			cancel_id = ctx->cancel_id_next = 1;
		if (pc) {
			memset(pc, 0, sizeof(*pc));
			pc->resource = *resource;
			pc->acq_seq = seq;
			pc->cancel_id = cancel_id;
			pc->mode = mode;
			pc->sends = 1;
			pc->sent_ms = mxfs_pal_time_ms();
			mxfs_pal_mutex_lock(ctx->rel_lock);
			pc->next = ctx->cancel_pending;
			ctx->cancel_pending = pc;
			mxfs_pal_mutex_unlock(ctx->rel_lock);
		}
		ctx->cancel_sent++;
		mxfs_probe_ratelimited(
		    "mxfs: P958-ACQ-CANCEL-SENT acq=%llu type=%u ino=%llu ag=%u mode=%s master=%u cancel_id=%u total=%llu — this wait is abandoned; the master is told so it holds nothing for it\n",
		    (unsigned long long)seq, resource->type,
		    (unsigned long long)resource->ino, resource->ag_number,
		    mode_name(mode), master, cancel_id,
		    (unsigned long long)ctx->cancel_sent);
		dlm_send_cancel_msg(ctx, master, resource, seq, cancel_id, mode);
	}
	dlm_acq_end(ctx, resource, mode, 0);
}

void mxfs_dlm_process_cancel_ack(struct mxfs_dlm_ctx *ctx,
				 const struct mxfs_dlm_cancel_ack *ack)
{
	struct mxfs_dlm_pending_cancel **pp, *found = NULL;

	if (!ctx || !ack || !ctx->rel_lock)
		return;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	for (pp = &ctx->cancel_pending; *pp; pp = &(*pp)->next) {
		struct mxfs_dlm_pending_cancel *pc = *pp;

		if (pc->acq_seq == ack->acq_seq && pc->cancel_id == ack->cancel_id &&
		    resource_equal(&pc->resource, &ack->resource)) {
			*pp = pc->next;
			found = pc;
			break;
		}
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	if (!found)
		return;
	ctx->cancel_acked++;
	mxfs_probe_ratelimited(
	    "mxfs: P958-ACQ-CANCEL-ACK acq=%llu type=%u ino=%llu ag=%u from=%u outcome=%u sends=%d total=%llu — the master answered the abandonment (1 absent, 2 waiter removed, 3 grant retired, 4 grant retiring, 5 not master)\n",
	    (unsigned long long)ack->acq_seq, ack->resource.type,
	    (unsigned long long)ack->resource.ino, ack->resource.ag_number,
	    ack->hdr.sender, ack->outcome, found->sends,
	    (unsigned long long)ctx->cancel_acked);
	mxfs_pal_free(found);
}

/* Re-send unacknowledged cancellations; give up after the release send
 * budget.  Called from the release retry tick. */
static void dlm_cancel_retry_tick(struct mxfs_dlm_ctx *ctx, uint64_t now)
{
	struct mxfs_dlm_pending_cancel *resend[16];
	struct mxfs_dlm_pending_cancel **pp;
	int n = 0, i;

	if (!ctx->cancel_pending)
		return;
	mxfs_pal_mutex_lock(ctx->rel_lock);
	pp = &ctx->cancel_pending;
	while (*pp && n < 16) {
		struct mxfs_dlm_pending_cancel *pc = *pp;

		if (now - pc->sent_ms < MXFS_DLM_RELEASE_RETRY_MS) {
			pp = &pc->next;
			continue;
		}
		if (pc->sends >= MXFS_DLM_RELEASE_MAX_SENDS) {
			*pp = pc->next;
			ctx->cancel_unacked++;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P958-ACQ-CANCEL-UNACKED acq=%llu type=%u ino=%llu ag=%u sends=%d total=%llu — the master never acknowledged this abandonment; whatever it holds for the wait stays until a re-request or the recovery purge",
				     (unsigned long long)pc->acq_seq, pc->resource.type,
				     (unsigned long long)pc->resource.ino,
				     pc->resource.ag_number, pc->sends,
				     (unsigned long long)ctx->cancel_unacked);
			mxfs_pal_free(pc);
			continue;
		}
		pc->sends++;
		pc->sent_ms = now;
		resend[n++] = pc;
		pp = &pc->next;
	}
	mxfs_pal_mutex_unlock(ctx->rel_lock);
	for (i = 0; i < n; i++) {
		struct mxfs_dlm_pending_cancel *pc = resend[i];
		mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, &pc->resource);

		ctx->cancel_resends++;
		if (master == ctx->local_node) {
			/* remastered onto us: whatever the old master held is gone
			 * with its view, and a re-send cannot reach us — done */
			mxfs_pal_mutex_lock(ctx->rel_lock);
			for (pp = &ctx->cancel_pending; *pp; pp = &(*pp)->next) {
				if (*pp == pc) {
					*pp = pc->next;
					break;
				}
			}
			mxfs_pal_mutex_unlock(ctx->rel_lock);
			mxfs_pal_free(pc);
			continue;
		}
		dlm_send_cancel_msg(ctx, master, &pc->resource, pc->acq_seq,
				    pc->cancel_id, pc->mode);
	}
}

/*
 * An attempt of a remote wait is about to be sent.  Record its nonce and its
 * issue time BEFORE it is handed to the transport, so a confirmation can only
 * ever be credited to an attempt this wait actually issued, and only against
 * the time it was issued — never against the time the answer happened to
 * arrive.
 */
static void dlm_acq_note_sent(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint8_t mode, mxfs_node_id_t master,
			      uint32_t req_id)
{
	uint64_t now = mxfs_pal_time_ms();
	int i;

	if (!ctx->acq_lock)
		return;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		uint8_t n;

		if (!ctx->acq[i].in_use || ctx->acq[i].mode != mode ||
		    !resource_equal(&ctx->acq[i].resource, resource))
			continue;
		n = ctx->acq[i].attempt_next % MXFS_DLM_ACQ_ATTEMPTS;
		ctx->acq[i].attempt[n].req_id = req_id;
		ctx->acq[i].attempt[n].sent_ms = now;
		ctx->acq[i].attempt_next = (uint8_t)(n + 1);
		ctx->acq[i].master = master;
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
}

/*
 * One more attempt of a remote wait has gone unanswered.  Evaluate the
 * degraded predicate against the anchor — the issue time of the attempt the
 * master last confirmed, or the first submission if it never has: past the
 * bound the wait is DEGRADED_UNCONFIRMED, said once here and visible in
 * debugfs from now on.  The wait itself is not touched.
 */
static void dlm_acq_note_unanswered(struct mxfs_dlm_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    uint8_t mode, mxfs_node_id_t master)
{
	uint64_t now = mxfs_pal_time_ms();
	uint64_t since = 0, seq = 0, first = 0, bound;
	uint32_t retx = 0;
	int pid = 0, i, newly = 0;

	bound = READ_ONCE(mxfs_dlm_acq_degrade_ms);
	if (!ctx->acq_lock || !bound)
		return;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (!ctx->acq[i].in_use || ctx->acq[i].mode != mode ||
		    !resource_equal(&ctx->acq[i].resource, resource))
			continue;
		ctx->acq[i].master = master;
		ctx->acq[i].retx++;
		since = ctx->acq[i].confirm_ms > ctx->acq[i].first_ms ?
			ctx->acq[i].confirm_ms : ctx->acq[i].first_ms;
		if (!ctx->acq[i].degraded_ms && now >= since &&
		    now - since >= bound) {
			ctx->acq[i].degraded_ms = now;
			newly = 1;
			seq = ctx->acq[i].acq_seq;
			first = ctx->acq[i].first_ms;
			retx = ctx->acq[i].retx;
			pid = ctx->acq[i].owner_pid;
		}
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	if (newly)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P958-ACQ-DEGRADED acq=%llu type=%u ino=%llu ag=%u "
			     "mode=%s master=%u retx=%u unanswered_ms=%llu "
			     "age_ms=%llu pid=%d bound_ms=%llu — DEGRADED_UNCONFIRMED: "
			     "the master is a live member and has not receipted this "
			     "wait for the whole bound; the request is being lost "
			     "between here and there, or the master's lock service "
			     "is not running.  The wait continues (this caller cannot "
			     "be failed safely) and is listed in "
			     "/sys/kernel/debug/mxfs/<dev>/acquire_degraded until a "
			     "receipt or a grant arrives",
			     (unsigned long long)seq, resource->type,
			     (unsigned long long)resource->ino, resource->ag_number,
			     mode_name(mode), master, retx,
			     (unsigned long long)(now - since),
			     (unsigned long long)(now - first), pid,
			     (unsigned long long)bound);
}

/*
 * A node said it has queued a request of ours on this resource, naming the
 * attempt it answers.  That is status for exactly one wait, and only if it
 * checks out: the answer must come from the node this wait's attempts went
 * to, must name an attempt this wait actually issued, and must arrive inside
 * the response allowance measured from that attempt's issue time.  Accepted,
 * it moves the anchor to that issue time (never to arrival time) and clears a
 * DEGRADED state, said once.  Anything else is counted and refreshes nothing:
 * a receipt for another wait on the same resource, from a node that is not
 * the master, or for an attempt no longer outstanding must not manufacture
 * evidence that this wait is being served.
 */
static void dlm_acq_note_receipt(struct mxfs_dlm_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 mxfs_node_id_t sender, uint32_t req_id)
{
	uint64_t now = mxfs_pal_time_ms();
	uint64_t back_seq = 0, back_for = 0;
	uint8_t back_mode = 0;
	int i, k, accepted = 0, rejected = 0;

	if (!ctx->acq_lock)
		return;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = 0; i < MXFS_DLM_ACQ_SLOTS; i++) {
		uint64_t issued = 0;

		if (!ctx->acq[i].in_use ||
		    !resource_equal(&ctx->acq[i].resource, resource))
			continue;
		for (k = 0; k < MXFS_DLM_ACQ_ATTEMPTS; k++) {
			if (ctx->acq[i].attempt[k].req_id == req_id &&
			    ctx->acq[i].attempt[k].sent_ms) {
				issued = ctx->acq[i].attempt[k].sent_ms;
				break;
			}
		}
		if (!issued)
			continue;               /* not an attempt of this wait */
		if (ctx->acq[i].master != sender || now < issued ||
		    now - issued > MXFS_DLM_ACQ_STATUS_LATENCY_MS) {
			ctx->acq[i].rejected++;
			rejected = 1;
			break;
		}
		ctx->acq[i].receipt_ms = now;
		if (issued > ctx->acq[i].confirm_ms)
			ctx->acq[i].confirm_ms = issued;
		accepted = 1;
		if (ctx->acq[i].degraded_ms) {
			back_seq = ctx->acq[i].acq_seq;
			back_for = now - ctx->acq[i].degraded_ms;
			back_mode = ctx->acq[i].mode;
			ctx->acq[i].degraded_ms = 0;
		}
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	if (rejected)
		mxfs_probe_ratelimited(
		    "mxfs: P958-ACQ-STATUS-REJECTED type=%u ino=%llu ag=%u from=%u "
		    "req_id=%u — a queue receipt named an attempt of a wait here but "
		    "came from a node that is not its master or later than the "
		    "response allowance; it refreshes nothing\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, sender, req_id);
	if (accepted && back_seq)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P958-ACQ-RECONFIRMED acq=%llu type=%u ino=%llu "
			     "ag=%u mode=%s master=%u degraded_for_ms=%llu — the "
			     "master has receipted a wait that was reported DEGRADED; "
			     "it is queued there and no longer listed",
			     (unsigned long long)back_seq, resource->type,
			     (unsigned long long)resource->ino, resource->ag_number,
			     mode_name(back_mode), sender,
			     (unsigned long long)back_for);
}

int mxfs_dlm_acq_degraded_iter(struct mxfs_dlm_ctx *ctx, int prev,
			       struct mxfs_dlm_acq_state *out)
{
	int i, found = -1;

	if (!ctx || !out || !ctx->acq_lock)
		return -1;
	mxfs_pal_spinlock_lock(ctx->acq_lock);
	for (i = prev + 1; i < MXFS_DLM_ACQ_SLOTS; i++) {
		if (!ctx->acq[i].in_use || !ctx->acq[i].degraded_ms)
			continue;
		out->resource    = ctx->acq[i].resource;
		out->acq_seq     = ctx->acq[i].acq_seq;
		out->first_ms    = ctx->acq[i].first_ms;
		out->last_ms     = ctx->acq[i].last_ms;
		out->receipt_ms  = ctx->acq[i].receipt_ms;
		out->confirm_ms  = ctx->acq[i].confirm_ms;
		out->degraded_ms = ctx->acq[i].degraded_ms;
		out->retx        = ctx->acq[i].retx;
		out->rejected    = ctx->acq[i].rejected;
		out->master      = ctx->acq[i].master;
		out->mode        = ctx->acq[i].mode;
		out->owner_pid   = ctx->acq[i].owner_pid;
		found = i;
		break;
	}
	mxfs_pal_spinlock_unlock(ctx->acq_lock);
	return found;
}

/*
 * `progress`: on MXFS_DLM_RETRY_TRANSITION, the bootstrap's page-takeover
 * count as this node last learned it (its own when it is the bootstrap, the
 * value relayed in the master's LOCK_DENY or the bootstrap's NOT_OWNER
 * otherwise) — what the retry loop watches instead of its budget.
 */
/*
 * TERMINAL AUTHORITY, ASKED WHERE THE WAIT LIVES.
 *
 * `shutting_down` is set at unmount and by nothing else, so a node whose
 * authority over the shared LUN has expired — and whose filesystem the
 * withdrawal has already shut down — still runs an acquire loop that sees no
 * reason to stop.  MEASURED (2 nodes, TCP, build 9C1BADD4E8D0DB6A039D23E,
 * tests/evidence/20260920T175325Z_lockreqbh_s88f): with a task blocked on a
 * request the master would never answer, the lease closed and the filesystem
 * shut down inside the same three-second sample, and the task stayed blocked
 * for a further 72 SECONDS, ending only when its own retry budget ran out.
 * Both stop signals were present and this loop saw neither.
 *
 * This is deliberately NOT routed through recovery_blocked_cb.  That one
 * answers "the resource's master is a dead node whose recovery is blocked",
 * which is a peer's problem and retryable in principle.  Losing our OWN
 * authority is terminal for this incarnation: there is nothing left to retry
 * under it, and no fallibility class is exempt — keeping the acquire alive
 * cannot give back the ability to complete what it was acquired for, and a
 * node that is otherwise healthy is not thereby authorised.  Health is not
 * authority.
 *
 * -ESHUTDOWN rather than a new code, on purpose: it is exactly what this
 * function already returns for `shutting_down`, so every caller's unwind
 * already treats it as terminal shutdown rather than as a failure to retry.
 *
 * WHAT THIS DOES NOT COVER, so nobody reads it as more than it is: a grant
 * that arrives and is accepted between one check and the next is still
 * installed, and it is the mutating-submission gate, not this, that stops it
 * being used.  Closure-aware grant acceptance is a separate obligation.
 */
static bool dlm_authority_lost(struct mxfs_dlm_ctx *ctx)
{
	return ctx->authority_lost_cb && ctx->authority_lost_cb(ctx->cb_data);
}

static int dlm_lock_impl(struct mxfs_dlm_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint8_t mode, uint32_t flags,
			  uint8_t *granted_mode, uint64_t *progress)
{
	mxfs_node_id_t master;
	uint32_t bucket;
	struct mxfs_lock *chain, *lk;
	int compat;
	uint64_t ledger_gen = 0;
	uint32_t req_id;

	if (ctx->shutting_down)
		return -ESHUTDOWN;
	if (unlikely(dlm_authority_lost(ctx))) {
		pr_warn_ratelimited(
		    "mxfs: P292-ACQ-AUTH-CLOSED type=%u ino=%llu ag=%u mode=%s we=%u comm=%s — this incarnation's authority over the shared LUN is closed; the acquire is REFUSED rather than sent, because nothing it could be granted could be completed under it\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, mode_name(mode), ctx->local_node,
		    dlm_cur_comm());
		return -ESHUTDOWN;
	}

	/* per-request id (idempotent retries return the durable grant) */
	req_id = ++ctx->req_id_next;
	if (req_id == 0)
		req_id = ctx->req_id_next = 1;

	/*
	 * membership-settle gate: do not acquire EX while the active-node
	 * set is still converging (formation ramp or a recent death).  Block this
	 * acquire until the view has been stable for mxfs_memb_settle_ms so the
	 * master mapping is globally consistent before any exclusive dir/AG/inode
	 * modification runs — closes the split-brain EX window that durably
	 * corrupts the shared directory.  Bounded by SETTLE_MAX_WAIT so continuous
	 * churn cannot wedge the thread.  Only EX (the mutual-exclusion mode that
	 * causes the divergent-base RMW); shared reads are not gated.
	 */
	/*
	 * 0.83.4 (D-0959): the gate covers EVERY acquiring mode, not only EX.
	 * A newcomer's first PR grant is the admission that matters for a
	 * first join: it reads the platter, and the incumbent's pre-join images
	 * reach the platter only when its prepare has run.  A shared read
	 * served before that is a stale base for the EX that follows it, and
	 * no BAST can ever correct it (the incumbent held no grant).  Measured
	 * (s584c, 2 nodes/TCP): the incumbent's unsynced appends in 32 files
	 * and the entries of 34 directories were lost across a first join.
	 * The gate is also fail-closed: when the bound expires while a live
	 * member still reports another view, the acquire is REFUSED rather
	 * than served on a view nobody has confirmed.
	 */
	if (mode != MXFS_LOCK_NL && dlm_membership_settling(ctx)) {
		int waited = 0;
		/* D7 instrumented probe: quantify the settle-gate share of slow EX
		 * acquires (joiner root-EX stall 4.7-20s).  Entry logs how long
		 * ago the view changed; exit logs the wall actually spent here. */
		uint64_t d7_since = mxfs_pal_time_ms() - ctx->last_memb_change_ms;
		bool still_settling;

		while (dlm_membership_settling(ctx) && !ctx->shutting_down &&
		       !dlm_authority_lost(ctx) &&
		       waited < MXFS_DLM_SETTLE_MAX_WAIT_MS) {
			mxfs_pal_sleep_ms(100);
			waited += 100;
		}
		still_settling = !ctx->shutting_down && dlm_membership_settling(ctx);
		if (waited > 0)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-D7-SETTLEGATE type=%u ino=%llu ag=%u mode=%u "
				     "since_change=%llums settle_ms=%d waited=%dms confirmed=%d "
				     "pending_live=%d%s",
				     resource->type,
				     (unsigned long long)resource->ino,
				     resource->ag_number, mode,
				     (unsigned long long)d7_since,
				     mxfs_memb_settle_ms, waited,
				     dlm_view_confirmed(ctx) ? 1 : 0,
				     dlm_view_pending_live(ctx) ? 1 : 0,
				     still_settling ?
				     " REFUSED (a live member still reports another view)" : "");
		if (ctx->shutting_down)
			return -ESHUTDOWN;
		if (still_settling)
			return -EAGAIN;
	}

	master = mxfs_dlm_resource_master(ctx, resource);

	/* ─── Remote master path ─── */
	if (master != ctx->local_node) {
		struct mxfs_dlm_lock_req req;
		struct mxfs_dlm_pending *pend;
		int ret;

		if (!ctx->send_cb)
			return -ENOTCONN;
		/*
		 * 0.75.19 (D-TCP-UMOUNT-HANGS-UNINTERRUPTIBLY-WHILE-PEER-RECOVERY-
		 * FENCE-BLOCKED-0904): a dead member leaves the view only when its
		 * recovery completes, so while its recovery is RECOVERY_BLOCKED it
		 * is still the master of 1/N of the pages and nothing can answer
		 * for them.  The 0.74.0 fail-fast covered a grant HELD by such a
		 * node (the master's deny, -EHOSTDOWN); a resource MASTERED by it
		 * fell through to the send retries, -ENOTCONN, and the central
		 * gate's park (measured s514f: umount(8)'s statx of the mountpoint
		 * and a stat of the victim's directory both parked on ino=128,
		 * P240-QUAR-PARK rc=-107, the umount SIGKILLed at 60 s).  Answer
		 * the same verdict before the send.
		 */
		if (ctx->recovery_blocked_cb &&
		    ctx->recovery_blocked_cb(ctx->cb_data, master)) {
			pr_warn_ratelimited(
			    "mxfs: P-RBLK-DENY-DEAD-MASTER type=%u ino=%llu ag=%u master=%u req=%s we=%u — the resource's master is a dead node whose recovery is blocked or terminally refused; failing the acquire instead of sending to it\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, master, mode_name(mode),
			    ctx->local_node);
			return -EHOSTDOWN;
		}

		/* Build the wire message */
		memset(&req, 0, sizeof(req));
		req.hdr.magic = MXFS_DLM_MAGIC;
		req.hdr.version = MXFS_DLM_VERSION;
		req.hdr.type = MXFS_MSG_LOCK_REQ;
		req.hdr.length = sizeof(req);
		req.hdr.sender = ctx->local_node;
		req.hdr.target = master;
		req.hdr.epoch = ctx->current_epoch;
		req.resource = *resource;
		req.mode = mode;
		req.flags = flags;
		req.owner_inc = ctx->local_inc;      /* ledger identity */
		req.owner_slot = ctx->local_slot;
		req.req_id = req_id;
		/* The wait this attempt belongs to.  Stable across every re-send
		 * and every restart of the acquire classifier, which is what lets
		 * the master absorb a re-send instead of re-queueing it. */
		{
			struct mxfs_dlm_acq_grant adopted;

			req.acq_seq = dlm_acq_begin(ctx, resource, mode, NULL, &adopted);
			/*
			 * The grant this wait asked for already arrived — between two
			 * of its attempts, when no pending entry stood — and was kept
			 * for it.  Take it now instead of sending again, provided the
			 * mirror it installed is still ours: a BAST the XFS layer
			 * answered on a not-yet-installed grant, or a membership purge,
			 * releases the mirror under the wait, and a claim on a grant
			 * the master has already retired would mint a phantom holder.
			 */
			if (adopted.have) {
				uint32_t abucket = resource_hash(resource, ctx->bucket_count);
				struct mxfs_lock *alk;
				int live = 0;

				mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
				for (alk = ctx->buckets[abucket]; alk; alk = alk->next) {
					if (resource_equal(&alk->resource, resource) &&
					    alk->owner == ctx->local_node &&
					    alk->state == MXFS_LSTATE_GRANTED &&
					    alk->grant_gen == adopted.grant_gen) {
						live = 1;
						break;
					}
				}
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				if (live) {
					ctx->acq_grant_claimed++;
					mxfs_probe_ratelimited(
					    "mxfs: P958-ACQ-GRANT-CLAIMED type=%u ino=%llu ag=%u mode=%s granted=%s gen=%u master=%u held_ms=%llu total=%llu — a grant that arrived between two attempts of this wait is taken by the next one; nothing sent, no re-queue\n",
					    resource->type, (unsigned long long)resource->ino,
					    resource->ag_number, mode_name(mode),
					    mode_name(adopted.mode), adopted.grant_gen, master,
					    (unsigned long long)(mxfs_pal_time_ms() -
								 adopted.adopted_ms),
						(unsigned long long)ctx->acq_grant_claimed);
					*granted_mode = adopted.mode;
					dlm_acq_end(ctx, resource, mode, 1);
					return 0;
				}
				ctx->acq_grant_vanished++;
				mxfs_probe_ratelimited(
				    "mxfs: P958-ACQ-GRANT-VANISHED type=%u ino=%llu ag=%u mode=%s gen=%u master=%u total=%llu — the grant kept for this wait was released under it before the claim; sending again\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, mode_name(mode), adopted.grant_gen,
				    master, (unsigned long long)ctx->acq_grant_vanished);
				dlm_acq_clear_grant(ctx, resource, mode);
			}
		}
		/* This attempt's nonce and issue time, before anything can stall. */
		dlm_acq_note_sent(ctx, resource, mode, master, req_id);

		/* Set up pending entry — stamp with current epoch so that
		 * stale grants from a previous master are rejected (Bug 67) */
		pend = pending_alloc(resource);
		if (!pend)
			return -ENOMEM;
		pend->request_epoch = ctx->current_epoch;
		pend->req_id = req_id;

		pending_insert(ctx, pend);

		/*
		 * TEST ONLY (dl_drop_lockreq_ino): report the send as successful and
		 * send nothing.  The pending entry stays, its wait times out, and the
		 * caller retries exactly as it would against a master that received
		 * the request and never answered it.  Only this one inode's requests
		 * are affected; everything else, including the traffic that keeps the
		 * peer a live member, goes out normally.
		 */
		if (unlikely(READ_ONCE(mxfs_dl_drop_lockreq_ino)) &&
		    resource->ino == READ_ONCE(mxfs_dl_drop_lockreq_ino)) {
			int dropped = atomic_inc_return(&mxfs_dl_drop_lockreq_n);

			ret = 0;
			if (dropped <= 8 || (dropped % 64) == 0)
				mxfs_pal_log(MXFS_LOG_DEBUG,
				    "mxfs: P912-DROP-LOCKREQ n=%d type=%u ino=%llu ag=%u "
				    "master=%u req=%s we=%u — TEST ONLY: this request is not "
				    "being sent; the master will create no queue entry and "
				    "answer nothing",
				    dropped, resource->type,
				    (unsigned long long)resource->ino,
				    resource->ag_number, master, mode_name(mode),
				    ctx->local_node);
			goto lockreq_sent;
		}

		/* TEST ONLY (dl_stale_resend_ino): keep a copy of this request; it is
		 * re-sent once after this inode's next LOCK_RELEASE. */
		if (unlikely(READ_ONCE(mxfs_dl_stale_resend_ino)) &&
		    resource->ino == READ_ONCE(mxfs_dl_stale_resend_ino)) {
			ctx->dbg_stale_req = req;
			ctx->dbg_stale_req_valid = 1;
		}

		/* Send to remote master (retry up to 3 times on transient failure) */
		{
			int send_retries = 3;
			do {
				ret = ctx->send_cb(ctx, master, &req, sizeof(req));
				if (ret == 0)
					break;
				if (--send_retries > 0) {
					mxfs_pal_log(MXFS_LOG_DEBUG,
						     "mxfs: lock request to node %u failed, "
						     "retrying (%d attempts remaining)",
						     master, send_retries);
					mxfs_pal_sleep_ms(100);
				}
			} while (send_retries > 0);
		}
lockreq_sent:
		if (ret) {
			pending_remove(ctx, pend);
			pending_free(pend);
			dlm_acq_end(ctx, resource, mode, 0);
			return ret;
		}

		/* Wait for remote grant/deny (sess-tcp: shorter per-attempt wait;
		 * mxfs_dlm_lock retries on -ETIMEDOUT to recover a lost grant msg). */
		ret = pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS);

		pending_remove(ctx, pend);

		/*
		 * 0.89.69: a completion that landed while this waiter was blocked
		 * in pending_remove (the grant found the entry under the bucket
		 * lock at the same instant the attempt timed out) is an answer,
		 * not a timeout.  The entry is out of the bucket now and nothing
		 * else can touch it, so the read is safe.
		 */
		if (ret == -ETIMEDOUT && pend->done) {
			int n = atomic_inc_return(&mxfs_dl_pending_late_kept);

			if (n <= 8 || (n % 64) == 0)
				mxfs_pal_log(MXFS_LOG_DEBUG,
				    "mxfs: P-PENDING-LATE-GRANT-KEPT n=%d type=%u ino=%llu "
				    "ag=%u master=%u req=%s status=%d — the answer landed as "
				    "this attempt timed out; kept for this attempt",
				    n, resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, master, mode_name(mode),
				    pend->status);
			ret = 0;
		}

		/*
		 * -ETIMEDOUT is "no answer yet", not "this wait ceased to exist":
		 * the caller re-sends under the SAME acquisition name.  Anything
		 * else ended the wait — a grant, a denial, or a membership change
		 * that may have moved the master — so the name is retired and the
		 * next attempt mints a fresh one.
		 */
		if (ret != -ETIMEDOUT)
			dlm_acq_end(ctx, resource, mode, 0);

		if (ret == -ETIMEDOUT) {
			/* One more unanswered re-send of this wait: past the bound
			 * with no receipt, the wait is reported DEGRADED. */
			dlm_acq_note_unanswered(ctx, resource, mode, master);
			/* remote-mastered timeout — the
			 * requester cannot see the holder table; at least name the
			 * resource + master so the master-side dmesg can be joined
			 * (rate-limited: the caller retries this ~60x/acquire). */
			mxfs_probe_ratelimited(
			    "mxfs: P-LKTIMEOUT-REMOTE type=%u ino=%llu ag=%u master=%u req=%s we=%u\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, master, mode_name(mode),
			    ctx->local_node);
			pending_free(pend);
			/* TEST ONLY: widen the gap before the next attempt, with no
			 * pending entry standing (see dl_acq_gap_ino). */
			if (unlikely(READ_ONCE(mxfs_dl_acq_gap_ino)) &&
			    resource->ino == READ_ONCE(mxfs_dl_acq_gap_ino) &&
			    READ_ONCE(mxfs_dl_acq_gap_ms)) {
				unsigned int gap = READ_ONCE(mxfs_dl_acq_gap_ms);
				int n = atomic_inc_return(&mxfs_dl_acq_gap_n);

				if (n <= 8 || (n % 64) == 0)
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P958-ACQ-GAP n=%d type=%u ino=%llu ag=%u "
					    "master=%u req=%s gap_ms=%u — TEST ONLY: holding "
					    "this attempt's caller with no pending entry",
					    n, resource->type,
					    (unsigned long long)resource->ino,
					    resource->ag_number, master, mode_name(mode), gap);
				mxfs_pal_sleep_ms(gap);
			}
			return -ETIMEDOUT;
		}

		if (pend->status == MXFS_DLM_RETRY) {
			/* Membership changed — retry with new master */
			pending_free(pend);
			return dlm_retry(ctx, 1);
		}

		if (pend->status != 0) {
			ret = pend->status;
			pending_free(pend);
			/*
			 * sess-tcp (PROVEN BY INSTRUMENT): pend->status carries the master's
			 * MXFS_ERR_* protocol code (positive enum), NOT a kernel errno.
			 * The master denies a NOQUEUE / TRYLOCK lock it cannot grant by
			 * sending MXFS_ERR_DEADLOCK (== 1).  Returned verbatim, that +1
			 * propagated up through mxfs_v5_dlm_ag_lock_nb (which only maps
			 * -EWOULDBLOCK) into xfs_dialloc as err=1 — and since 1 != -EAGAIN
			 * the allocator treated a busy peer-held AG as a FATAL error
			 * instead of skipping to the next AG, failing the create and
			 * NULL-dereferencing in do_open.  The local NOQUEUE path already
			 * returns -EAGAIN (see above); make the remote path agree.  Never
			 * leak a positive status to the kernel.
			 */
			if (ret == MXFS_ERR_DEADLOCK)
				return -EAGAIN;
			/* 0.74.0: the master holds this resource for a DEAD node whose
			 * recovery is terminally blocked — queueing would only wait out
			 * the acquire budget.  Fail fast; the xfs layer names it. */
			if (ret == MXFS_ERR_RECOVERY_BLOCKED) {
				pr_warn_ratelimited(
				    "mxfs: P-RBLK-DENY-REMOTE type=%u ino=%llu ag=%u master=%u req=%s we=%u — held by a dead node whose recovery is RECOVERY_BLOCKED; not queueing\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, master, mode_name(mode),
				    ctx->local_node);
				return -EHOSTDOWN;
			}
			/*
			 * (2/tcp double-grant root fix): the master denied a
			 * blocked INODE upgrade WITHOUT removing our grant (it stays
			 * visible so no peer double-grants).  Map to -EDEADLK so the
			 * XFS ilock layer (P109) drops our lower grant through the BAST
			 * drain pipeline and re-acquires the target mode fresh.
			 */
			if (ret == MXFS_ERR_UPGRADE_CONFLICT)
				return -EDEADLK;
			/* the master is no longer the page owner under the
			 * generation it decided in — retry against the current one. */
			/*
			 * 0.84.5 (D-...-0960): the master says the page is under a
			 * dead authority a live bootstrap is taking over; its deny
			 * carried the bootstrap's takeover count (stored by the grant
			 * receiver in transition_progress_rx).  The loop above waits
			 * on that count, not on its retry budget.
			 */
			if (ret == MXFS_ERR_AUTH_TRANSITION) {
				if (progress)
					*progress = ctx->transition_progress_rx;
				mxfs_probe_ratelimited(
				    "mxfs: P960-AUTH-TRANSITION-RX type=%u ino=%llu ag=%u master=%u "
				    "mode=%s progress=%llu — the page is being taken over by a live "
				    "bootstrap; waiting on its progress, not on the retry budget\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, master, mode_name(mode),
				    (unsigned long long)ctx->transition_progress_rx);
				return MXFS_DLM_RETRY_TRANSITION;
			}
			if (ret == MXFS_ERR_REMASTER) {
				uint32_t vc = 0;
				uint64_t vh = mxfs_dlm_get_view_sig(ctx, &vc);

				/* (D-0345 instrumented): which master we asked, under
				 * which view — pairs with P-TAUTH-REMASTER-VIEW/-PARKED */
				mxfs_probe_ratelimited(
				    "mxfs: P-TAUTH-REMASTER-RX type=%u ino=%llu ag=%u master=%u "
				    "mode=%s view=%#llx/%u\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, master, mode_name(mode),
				    (unsigned long long)vh, vc);
				return dlm_retry(ctx, 2);
			}
			/* a durable holder's retirement was in flight when
			 * the master decided — it retires it and we retry */
			if (ret == MXFS_ERR_LEDGER_BUSY)
				return dlm_retry(ctx, 3);
			/* (D-0348): the home page is full — wait, never EIO */
			if (ret == MXFS_ERR_LEDGER_FULL) {
				mxfs_pal_sleep_ms(50);
				return dlm_retry(ctx, 10);
			}
			if (ret > 0)
				return -EIO;
			return ret;
		}

		*granted_mode = pend->granted_mode;
		pending_free(pend);
		return 0;
	}

	/* ─── Local master path ─── */
	bucket = resource_hash(resource, ctx->bucket_count);

	/* the ledger page must be current + imported before any
	 * decision on this resource (activation barrier / fail-stop refuse). */
	{
		int prc = dlm_ledger_prepare(ctx, resource, &ledger_gen);

		if (prc == -EAGAIN)
			return dlm_retry(ctx, 4);
		/* 0.84.5 (D-...-0960): the page is in a takeover a live bootstrap
		 * (us, or the one whose NOT_OWNER answers relay its count) is
		 * making; wait on that count, not on the budget */
		if (prc == -EINPROGRESS) {
			if (progress)
				*progress = dlm_bootstrap_node(ctx) == ctx->local_node ?
					    ctx->takeover_pages_done : ctx->transition_progress_rx;
			return MXFS_DLM_RETRY_TRANSITION;
		}
		if (prc)
			return prc;
	}

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	chain = ctx->buckets[bucket];

	/* Check for existing lock: same resource, same owner */
	for (lk = chain; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == ctx->local_node) {
			if (lk->state == MXFS_LSTATE_WAITING ||
			    lk->state == MXFS_LSTATE_BLOCKED) {
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				return -EEXIST;
			}
			/* our own grant/release is mid-transition — the
			 * committing thread delivers; do not decide twice. */
			if (lk->state == MXFS_LSTATE_PENDING_DURABLE) {
				/*
				 * (instrumented: formation_test lap 'fails=1', rig test3
				 * 'lock request failed after 10 retries' x14): our OWN
				 * grant is mid-commit.  Spinning RETRY (10 ms) here burnt
				 * the whole retry budget under a slow page write and the
				 * request failed while its grant was landing — then the
				 * grant had no waiter (the local orphan).  Attach to the
				 * in-flight transition instead: register a pending so
				 * dlm_txn_finalize's signal reaches us, wait one acquire
				 * window.  The pending is inserted under the table lock,
				 * before finalize can take it, so the signal cannot be
				 * lost.
				 */
				struct mxfs_dlm_pending *pend = pending_alloc(resource);
				int ret;

				if (!pend) {
					mxfs_pal_rwlock_unlock(ctx->table_rwlock);
					return -ENOMEM;
				}
				pend->req_id = lk->req_id;
				lk->pend_waiter = pend;
				pending_insert(ctx, pend);
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				ret = pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS);
				pending_remove(ctx, pend);
				if (pend->done && pend->status == 0 &&
				    pend->granted_mode != MXFS_LOCK_NL) {
					*granted_mode = pend->granted_mode;
					pending_free(pend);
					return 0;
				}
				ret = pend->done ? pend->status : MXFS_DLM_RETRY;
				pending_free(pend);
				if (ret == MXFS_DLM_RETRY || ret == -ETIMEDOUT || ret == 0)
					return dlm_retry(ctx, 5);
				return ret;
			}
			if (lk->state == MXFS_LSTATE_PENDING_RELEASE) {
				/* our own release is mid-commit: it retires, then we
				 * queue afresh */
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				mxfs_pal_sleep_ms(10);
				return dlm_retry(ctx, 6);
			}
			if (lk->state == MXFS_LSTATE_GRANTED) {
				lk->unclaimed = false;      /* adopted (shortcut or upgrade) */
				/*
				 * D-0966: this entry may be a ledger record of OUR OWN
				 * incarnation imported on a page load (dlm_import_holder:
				 * GRANTED, imported, grant_gen 0) -- a grant whose release
				 * or response was lost against a departing master and that
				 * we took over as its new master.  The shortcut below used
				 * to hand it back as-is: the caller's inode went to EX on
				 * a mirror entry with grant_gen 0, and the gen-aware release
				 * (mxfs_dlm_bast_process, p_rel_gen == 0) then read "no held
				 * tenure" and skipped the unlock on every BAST for ever,
				 * while the master the page was later handed to kept the
				 * record ACTIVE.  Measured 2/tcp s616d: a rejoined peer's
				 * listing of the survivor's directory hung 300 s+ on ino
				 * 2133 (P-TAUTH-IMPORT-ACTIVE owner=self, P6Z-REL-NOTHING
				 * x42).  Adopting the record IS starting a tenure: mint the
				 * generation the release will name, exactly as the remote
				 * re-affirm does.  A record of a DIFFERENT incarnation of
				 * our node id is not ours: its departure purge retires it,
				 * and until then the request waits (fail closed).
				 */
				if (lk->imported) {
					if (lk->owner_inc && ctx->local_inc &&
					    lk->owner_inc != ctx->local_inc) {
						mxfs_pal_rwlock_unlock(ctx->table_rwlock);
						mxfs_pal_log(MXFS_LOG_DEBUG,
							     "mxfs: P-TAUTH-ADOPT-INC-MISMATCH type=%u ino=%llu ag=%u "
							     "record_inc=%llu our_inc=%llu mode=%s — an imported "
							     "record under our node id belongs to another "
							     "incarnation; not adopted, waiting for its purge",
							     resource->type, (unsigned long long)resource->ino,
							     resource->ag_number,
							     (unsigned long long)lk->owner_inc,
							     (unsigned long long)ctx->local_inc, mode_name(mode));
						return dlm_retry(ctx, 7);
					}
					lk->imported = false;
					lk->grant_gen = dlm_next_gen(ctx);
					lk->granted_at = mxfs_pal_time_ms();
					ctx->ledger_imports_adopted++;
					P_LKT("ADOPT-IMPORTED-LOCAL", resource, lk->owner, lk->mode);
					mxfs_pal_log(MXFS_LOG_DEBUG,
						     "mxfs: P-TAUTH-ADOPT-LOCAL type=%u ino=%llu ag=%u mode=%s "
						     "req=%s gen=%u grant_id={%llu,%llu} — a ledger record of "
						     "this incarnation with no live tenure is adopted by the "
						     "local request; its release will name this generation",
						     resource->type, (unsigned long long)resource->ino,
						     resource->ag_number, mode_name(lk->mode), mode_name(mode),
						     lk->grant_gen,
						     (unsigned long long)lk->auth_epoch,
						     (unsigned long long)lk->grant_seq);
				}
				if (lk->mode >= mode) {
					/* Bug 51 defense-in-depth: verify our existing
					 * grant is still safe before returning the "already
					 * granted" shortcut. Normally this is redundant for
					 * local master requests (unlock + lock are
					 * sequential on the same thread), but it prevents
					 * dual-EX grants if a stale entry survives. Check
					 * for conflicting GRANTED holders AND any
					 * WAITING/BLOCKED entries from other nodes. */
					{
						struct mxfs_lock *other;
						int still_safe = 1;

						for (other = chain; other; other = other->next) {
							if (other == lk)
								continue;
							if (!resource_equal(&other->resource,
									   resource))
								continue;
							if (other->owner == ctx->local_node)
								continue;
							if (lk_is_holder(other) &&
							    !lock_compat[other->mode][lk->mode]) {
								still_safe = 0;
								break;
							}
							/* FIX-17 (PROVEN BY INSTRUMENT, run90
							 * r10 cluster wedge): other-node WAITING/BLOCKED
							 * entries are NORMAL contention queued behind our
							 * live grant, NOT staleness evidence.  The old
							 * clause here (still_safe=0 on any waiter) made a
							 * same-mode re-request under contention free the
							 * ONLY GRANTED entry (P52-GRANT-FREE ret=
							 * dlm_lock_impl+0x560, test2 gen=16605) and
							 * re-queue itself fairly BEHIND the waiters —
							 * leaving zero granted holders and a promotion
							 * that only ever runs on release events that can
							 * no longer come: the whole cluster queued on
							 * ino=131 for 184.5s, timed out (rc=-110), and
							 * 6/8 nodes force-shutdown.  Only a CONFLICTING
							 * GRANTED entry (the check above) indicates a
							 * genuine dual-grant worth distrusting. */
						}
						if (still_safe) {
							/* DLM_TRACE: local "already granted" shortcut */
							if (resource->ino == 128 &&
							    resource->type == MXFS_LTYPE_INODE)
								mxfs_pal_log(MXFS_LOG_DEBUG,
								    "DLM_TRACE: dlm_lock LOCAL already-granted "
								    "shortcut ino=128 mode=%s owner=%u",
								    mode_name(lk->mode), lk->owner);
							*granted_mode = lk->mode;
							mxfs_pal_rwlock_unlock(ctx->table_rwlock);
							return 0;
						}
					}
					/* Existing grant conflicts — stale entry.
					 * Remove and re-check as fresh request. */
					{
						struct mxfs_lock **pp;

						mxfs_pal_log(MXFS_LOG_WARN,
							     "mxfs: lock contention detected, "
							     "re-queuing request (normal under "
							     "concurrent access)");
						pp = &ctx->buckets[bucket];
						while (*pp) {
							if (*pp == lk) {
								*pp = lk->next;
								lock_free(lk);
								ctx->lock_count--;
								break;
							}
							pp = &(*pp)->next;
						}
					}
					chain = ctx->buckets[bucket];
					goto check_compat;
				}
				/* Upgrade: check compat with OTHER holders */
				{
					struct mxfs_lock *other;
					int conv_compat = 1;

					for (other = chain; other; other = other->next) {
						if (other == lk)
							continue;
						if (!resource_equal(&other->resource, resource))
							continue;
						if (!lk_is_holder(other))
							continue;
						if (!lock_compat[other->mode][mode]) {
							conv_compat = 0;
							break;
						}
					}
					if (conv_compat) {
						/*
						 * EPOCH-HOLE FIX (instrumented —
						 * PROVEN run38: the MASTER node read master_ep=0 on
						 * 61 placements with valid_ep≈1258 (P2-EPOCHPLACE
						 * unestablished=1) — every one a local PR→EX upgrade
						 * whose mirror kept its PR-era dir_epoch=0 because
						 * THIS path, alone among the four upgrade/grant
						 * sites, never called dg_grant_ex.  With master_ep=0
						 * every epoch-gated dir coherence guard is inert for
						 * the master's own tenures → stale-base RMW → the
						 * residual dir_reuse single-dirent loss (run34 r9,
						 * run37 r18).  Mirror the remote-upgrade twin: fresh
						 * gen + dg_grant_ex stamps handoff/dir_epoch and
						 * advances the master handoff epoch.
						 *
						 * the upgrade is a ledger transition —
						 * PENDING_DURABLE (old mode restored on refusal),
						 * committed and delivered by dlm_grant_txn, which
						 * also fires the grantee BAST.
						 */
						uint8_t prev_mode = lk->mode;
						uint32_t prev_gen = lk->grant_gen;
						struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
						int grc;

						if (!txn) {
							mxfs_pal_rwlock_unlock(ctx->table_rwlock);
							return -ENOMEM;
						}
						dlm_txn_init(txn, resource, ledger_gen);
						lk->mode = mode;
						lk->grant_gen = dlm_next_gen(ctx);
						lk->state = MXFS_LSTATE_PENDING_DURABLE;
						lk->owner_inc = ctx->local_inc;
						lk->owner_slot = ctx->local_slot;
						lk->req_id = req_id;
						lk->decide_gen = ledger_gen;
						if (mode == MXFS_LOCK_EX)
							lk->handoff = dg_grant_ex(ctx, resource,
										  ctx->local_node,
										  lk->grant_gen,
										  &lk->dir_epoch);
						dlm_txn_add_grant(txn, lk, prev_mode, prev_gen, false);
						mxfs_pal_rwlock_unlock(ctx->table_rwlock);
						grc = dlm_grant_txn(ctx, txn);
						mxfs_pal_free(txn);
						if (grc == -EAGAIN)
							return dlm_retry(ctx, 7);
						if (grc)
							return grc;
						*granted_mode = mode;
						return 0;
					}
				}
				/*
				 * (2/tcp double-grant root fix): blocked INODE
				 * upgrade.  The OLD code removed our GRANTED entry and
				 * re-queued as a fresh WAITING request — but we still hold
				 * the lower grant LOCALLY (i_dlm_mode), so removing the table
				 * entry makes us INVISIBLE while still holding: a peer's
				 * subsequent request scans only GRANTED entries, sees no
				 * conflict, and is granted an incompatible mode -> two nodes
				 * hold conflicting grants = the proven P-CONVBLK-REMOVE
				 * double-grant -> stale-read / dir lost-update.
				 *
				 * Correct: KEEP our GRANTED entry (stay visible as a conflict)
				 * and return -EDEADLK.  The XFS ilock layer (P109) then drops
				 * our lower grant THROUGH the BAST drain pipeline (releasing
				 * it in sync with the table) and re-acquires the target mode
				 * FRESH via the clean FIFO path — no double-grant, no
				 * conversion deadlock.  Scoped to INODE resources (where the
				 * P109 -EDEADLK handling lives); other resource types keep the
				 * legacy remove+requeue behavior.
				 */
				if (resource->type == MXFS_LTYPE_INODE) {
					mxfs_pal_rwlock_unlock(ctx->table_rwlock);
					return -EDEADLK;
				}
				/* Conversion blocked — release existing, fall through */
				{
					struct mxfs_lock **pp;

					pp = &ctx->buckets[bucket];
					while (*pp) {
						if (*pp == lk) {
							*pp = lk->next;
							lock_free(lk);
							ctx->lock_count--;
							break;
						}
						pp = &(*pp)->next;
					}
				}
				chain = ctx->buckets[bucket];
				goto check_compat;
			}
		}
	}

check_compat:
	/* Check compatibility with all granted holders */
	compat = 1;
	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (!lk_is_holder(lk))
			continue;
		if (!lock_compat[lk->mode][mode]) {
			compat = 0;
			/* P1-AGCONFLICT (local-master mirror of the remote-path log):
			 * name the GRANTED holder blocking an AG request. */
			if (resource->type == MXFS_LTYPE_AG)
				mxfs_probe_ratelimited(
				    "mxfs: P1-AGCONFLICT ag=%u sender=LOCAL req=%s holder=%u hmode=%s hstate=%d nq=%d\n",
				    resource->ag_number, mode_name(mode),
				    lk->owner, mode_name(lk->mode), lk->state,
				    !!(flags & MXFS_LKF_NOQUEUE));
			break;
		}
	}

	/* arrival-time FIFO barrier: do not grant past an
	 * older conflicting waiter (see find_conflicting_waiter). */
	if (compat) {
		struct mxfs_lock *cw = find_conflicting_waiter(chain, resource,
							       ctx->local_node, mode);
		if (cw) {
			static atomic_t p6f_n = ATOMIC_INIT(0);
			compat = 0;
			if (atomic_inc_return(&p6f_n) <= 60000)
				mxfs_probe("mxfs: P6-FAIRQ site=local ino=%llu type=%u ag=%u req=%s we=%u behind waiter=%u wmode=%s wage_ms=%llu nq=%d\n",
					(unsigned long long)resource->ino,
					resource->type, resource->ag_number,
					mode_name(mode), ctx->local_node,
					cw->owner, mode_name(cw->mode),
					(unsigned long long)(cw->queued_at ?
					    mxfs_pal_time_ms() - cw->queued_at : 0),
						!!(flags & MXFS_LKF_NOQUEUE));
		}
	}

	if (!compat && (flags & MXFS_LKF_NOQUEUE)) {
		struct mxfs_bast_record dm_recs[MXFS_MAX_BAST_RECORDS];
		int dm_n = 0;

		if (flags & MXFS_LKF_DEMAND)
			dm_n = demand_collect_holders(ctx, bucket, resource, mode,
						      dm_recs);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		demand_fire(ctx, resource, ctx->local_node, dm_recs, dm_n);
		return -EAGAIN;
	}

	if (!compat && (flags & MXFS_LKF_TRYLOCK)) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		return -EWOULDBLOCK;
	}

	if (compat) {
		/* Grant immediately (decided here, durable + delivered by
		 * dlm_grant_txn — the entry is PENDING_DURABLE until then) */
		struct mxfs_lock *newlk;
		struct dlm_txn *txn;
		int grc;

		/* DLM_TRACE: local master new grant (no conflict) */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: dlm_lock LOCAL new-grant ino=128 "
				     "mode=%s owner=%u",
				     mode_name(mode), ctx->local_node);

		txn = mxfs_pal_alloc(sizeof(*txn));
		newlk = txn ? lock_alloc(resource, ctx->local_node, mode,
					 MXFS_LSTATE_PENDING_DURABLE, flags) : NULL;
		if (!newlk) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			if (txn)
				mxfs_pal_free(txn);
			return -ENOMEM;
		}
		dlm_txn_init(txn, resource, ledger_gen);
		newlk->owner_inc = ctx->local_inc;
		newlk->owner_slot = ctx->local_slot;
		newlk->req_id = req_id;
		newlk->decide_gen = ledger_gen;

		/* PROVEN BY INSTRUMENT (run44 wedge): this was the
		 * ONE grant path that never stamped grant_gen — every uncontended
		 * locally-mastered tenure carried gen=0, so (a) the gen-aware
		 * release capture read 0 ("nothing held") and skipped the master's
		 * own releases -> cluster wedge, and (b) the owner-scan peer-held-
		 * in-between detector (cur_gg != cached_gg) was INERT on the master
		 * (0 == 0 forever).  Stamp like every other grant site (793, 1368,
		 * 3304, 3356, 3529): every tenure gets a unique non-zero gen. */
		newlk->grant_gen = dlm_next_gen(ctx);

		newlk->next = ctx->buckets[bucket];
		ctx->buckets[bucket] = newlk;
		ctx->lock_count++;
		P_LKT("GRANT-LOCAL", resource, ctx->local_node, mode);
		if (mode == MXFS_LOCK_EX)
			newlk->handoff = dg_grant_ex(ctx, resource, ctx->local_node,
						     newlk->grant_gen, &newlk->dir_epoch);
		dlm_txn_add_grant(txn, newlk, 0, 0, false);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		/* ROOT FIX (the grantee BAST for a jumped older waiter) now
		 * fires from dlm_txn_finalize once the grant is delivered. */
		grc = dlm_grant_txn(ctx, txn);
		mxfs_pal_free(txn);
		if (grc == -EAGAIN)
			return dlm_retry(ctx, 8);
		if (grc)
			return grc;
		*granted_mode = mode;
		return 0;
	}

	/* Incompatible — queue and wait */
	{
		struct mxfs_lock *newlk;
		struct mxfs_dlm_pending *pend;
		struct mxfs_bast_record bast_recs[MXFS_MAX_BAST_RECORDS];
		int bast_count = 0;
		int ret;

		/* DLM_TRACE: local master queuing as waiter */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: dlm_lock LOCAL add-to-waiters ino=128 "
				     "requested_mode=%s owner=%u",
				     mode_name(mode), ctx->local_node);

		/* allocate the pending FIRST so the queued entry
		 * can carry its waiter identity (pend_waiter) from the instant it
		 * becomes visible in the table — the unlock fallback keys off it. */
		pend = pending_alloc(resource);
		if (!pend) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			return -ENOMEM;
		}

		newlk = lock_alloc(resource, ctx->local_node, mode,
				   MXFS_LSTATE_WAITING, flags);
		if (!newlk) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			pending_free(pend);
			return -ENOMEM;
		}

		newlk->pend_waiter = pend;
		newlk->owner_inc = ctx->local_inc;      /* ledger identity */
		newlk->owner_slot = ctx->local_slot;
		newlk->req_id = req_id;
		pend->req_id = req_id;
		/*
		 * THIS ENTRY IS USUALLY NOT A NEW WAIT.
		 *
		 * A locally mastered acquire re-queues here once a second: the
		 * one-second timeout below frees this entry, and the next attempt
		 * builds another one.  Waiters are promoted oldest-queued_at first,
		 * so a queued_at stamped at allocation made this wait permanently
		 * one second old however long it had really been waiting — it went
		 * to the BACK of its own queue on every attempt, and any waiter
		 * whose age does not reset outranked it indefinitely.
		 *
		 * The acquisition record outlives the entry, so the age comes from
		 * there: queued_at becomes when the WAIT began, not when this
		 * attempt allocated.  (The entry is still briefly absent between
		 * attempts, so a newly arriving compatible request can still be
		 * granted in that window; that is unchanged from before and is a
		 * separate question from the ordering of waiters that ARE queued.)
		 */
		{
			uint64_t acq_first = 0;

			newlk->acq_seq = dlm_acq_begin(ctx, resource, mode, &acq_first, NULL);
			if (acq_first && acq_first < newlk->queued_at)
				newlk->queued_at = acq_first;
		}
		newlk->next = ctx->buckets[bucket];
		ctx->buckets[bucket] = newlk;
		ctx->lock_count++;

		/* Capture BAST targets into a snapshot array while under
		 * table_rwlock.  We must NOT iterate live lock entries via
		 * work_next after releasing the lock — concurrent releases
		 * can corrupt the work_next chain at 3+ nodes. */
		for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
			if (!resource_equal(&lk->resource, resource))
				continue;
			if (lk->state != MXFS_LSTATE_GRANTED)
				continue;
			if (!lock_compat[lk->mode][mode]) {
				if (bast_count < MXFS_MAX_BAST_RECORDS) {
					bast_recs[bast_count].owner = lk->owner;
					bast_recs[bast_count].requested_mode = mode;
					bast_count++;
				}
			}
		}

		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		/* Set up pending entry BEFORE firing BASTs.
		 *
		 * Critical ordering: the pending entry must be in the hash
		 * table before any BAST is sent. Otherwise, a fast BAST
		 * recipient can release its lock and trigger promote_waiters
		 * + pending_signal_resource before we insert the pending
		 * entry — the signal is lost and we wait forever (timeout).
		 *
		 * At 4+ nodes with 3 PR holders, all 3 can process BASTs
		 * and release concurrently. If the last release promotes
		 * our WAITING entry and signals the pending before it's
		 * inserted, the grant is lost. */
		/* pend was allocated (and linked via
		 * newlk->pend_waiter) BEFORE the entry became visible in the
		 * table; only the hash insert remains here. */
		pending_insert(ctx, pend);

		/* P37: local request queued WAITING for the contended dir. */
		if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
			mxfs_probe_ratelimited(
			    "mxfs: P37-LREQ-QUEUE ino=131 owner=%u mode=%s bast_targets=%d\n",
			    ctx->local_node, mode_name(mode), bast_count);

		/* Fire deferred BASTs from snapshot — pending entry is
		 * already in the hash table, so promote_waiters can signal
		 * us even if all holders release before we reach pending_wait.
		 *
		 * On its own interval, not on every attempt.  This path re-queues
		 * once a second for the whole wait, and firing here each time
		 * notified a holder that was already draining once per second for
		 * the length of its drain: measured 237 notifications across one
		 * 243 s wait.  A notification that was lost is still recovered
		 * within the interval. */
		if (bast_count && dlm_acq_bast_due(ctx, resource, mode))
			fire_bast_records(ctx, resource, bast_recs, bast_count);

		/* sess-tcp: shorter per-attempt wait; mxfs_dlm_lock retries on
		 * -ETIMEDOUT (re-fires the BAST) to recover a lost grant/release. */
		ret = pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS);

		pending_remove(ctx, pend);

		/* 0.89.69: same as the remote path — an answer that landed while
		 * the timed-out waiter was blocked in pending_remove is kept. */
		if (ret == -ETIMEDOUT && pend->done) {
			int n = atomic_inc_return(&mxfs_dl_pending_late_kept);

			if (n <= 8 || (n % 64) == 0)
				mxfs_pal_log(MXFS_LOG_DEBUG,
				    "mxfs: P-PENDING-LATE-GRANT-KEPT n=%d type=%u ino=%llu "
				    "ag=%u master=%u req=%s status=%d — the answer landed as "
				    "this attempt timed out; kept for this attempt",
				    n, resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, ctx->local_node, mode_name(mode),
				    pend->status);
			ret = 0;
		}

		if (pend->status == MXFS_DLM_RETRY) {
			/* Membership changed — the WAITING lock entry was already
			 * freed by update_active_nodes' table purge. Do NOT try
			 * to find/free newlk (use-after-free). Just retry. */
			pending_free(pend);
			return dlm_retry(ctx, 9);
		}

		if (ret == -ETIMEDOUT) {
			int blocked_holder = 0;     /* 0.74.0 */

			/* Timeout — remove the queued lock */
			mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
			{
				struct mxfs_lock **pp = &ctx->buckets[bucket];
				struct mxfs_lock *wlk;

				/* name the blockers.  A 60s
				 * acquire timeout (the run16 test6 AG2 -110 -> dirty
				 * trans_cancel shutdown) BASTed the granted holder(s)
				 * ~60 times in vain; without their identity the ABBA
				 * (holder stuck waiting for a resource OUR caller
				 * holds) cannot be attributed.  Dump every entry on
				 * this resource with owner/mode/state/age. */
				for (wlk = ctx->buckets[bucket]; wlk; wlk = wlk->next) {
					if (!resource_equal(&wlk->resource, resource) ||
					    wlk == newlk)
						continue;
					/* 0.74.0: a GRANTED holder that is a dead node in
					 * RECOVERY_BLOCKED will not release by waiting; the
					 * caller fails fast instead of the whole budget. */
					if (ctx->recovery_blocked_cb && lk_is_holder(wlk) &&
					    ctx->recovery_blocked_cb(ctx->cb_data, wlk->owner))
						blocked_holder = 1;
					/*
					 * 0.75.91 (D-...-0940): MXFS_DLM_NODE_UNKNOWN means the
					 * slot was unresolvable AT IMPORT — the heartbeat table
					 * had not yet seen the claimant — not that it is
					 * unresolvable for good.  dlm_import_holder already knows
					 * how to attribute such a bit once the slot names its
					 * node, but it only runs on a re-import of that page, and
					 * a page imported once at mount is never re-imported.  So
					 * a shared bit imported a moment before the peer claimed
					 * its slot became permanent: demand_collect_holders and
					 * fire_bast_records both skip an UNKNOWN owner by design,
					 * so nothing could BAST it and nothing could release it.
					 * Measured s584c: test2's mount queued the root inode EX
					 * behind 'P-TAUTH-IMPORT-ACTIVE type=1 ino=128 owner=
					 * 4294967295 slot=0', slot 0 having been claimed by test1
					 * in that very era; test1's mount then queued AG 0 behind
					 * test2, and neither mount ever returned.
					 *
					 * A waiter timing out is exactly the moment to re-ask.
					 * This only ATTRIBUTES the bit to the node that owns it,
					 * which is the same rule dlm_import_holder applies; it
					 * retires nothing and drops nothing, so the D-0344 hazard
					 * (a live successor in the slot losing its own records) is
					 * not in play.  The next retry can then BAST the owner.
					 */
					if (wlk->imported && lk_is_holder(wlk) &&
					    wlk->owner == MXFS_DLM_NODE_UNKNOWN &&
					    wlk->mode != MXFS_LOCK_EX && ctx->slot_node_cb) {
						uint64_t rinc = 0;
						mxfs_node_id_t rn =
						    ctx->slot_node_cb(ctx->cb_data, wlk->owner_slot,
								      &rinc);

						if (rn != 0 && rn != MXFS_DLM_NODE_UNKNOWN) {
							wlk->owner = rn;
							wlk->owner_inc = rinc;
							ctx->ledger_imports_resolved++;
							mxfs_pal_log(MXFS_LOG_DEBUG,
							    "mxfs: P-TAUTH-IMPORT-RESOLVED-ONTIMEOUT type=%u "
							    "ino=%llu ag=%u slot=%u -> owner=%u inc=%llu — an "
							    "imported shared bit whose slot was unresolvable at "
							    "import now names a node; attributing it so it can "
							    "be BASTed and released instead of blocking EX for "
							    "good",
							    resource->type,
							    (unsigned long long)resource->ino,
							    resource->ag_number, wlk->owner_slot, rn,
							    (unsigned long long)rinc);
						} else {
							mxfs_pal_log(MXFS_LOG_WARN,
							    "mxfs: P-TAUTH-IMPORT-UNRESOLVED-ONTIMEOUT type=%u "
							    "ino=%llu ag=%u slot=%u — an imported shared bit is "
							    "blocking this EX and its slot STILL names no node; "
							    "it cannot be BASTed or released and this request "
							    "cannot succeed until a recovery purge clears it",
							    resource->type,
							    (unsigned long long)resource->ino,
							    resource->ag_number, wlk->owner_slot);
						}
					}
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P-LKTIMEOUT-HOLDER type=%u ino=%llu ag=%u holder=%u hmode=%s hstate=%u held_ms=%llu queued_ms=%llu (we=%u req=%s)",
					    resource->type,
					    (unsigned long long)resource->ino,
					    resource->ag_number, wlk->owner,
					    mode_name(wlk->mode), wlk->state,
					    (unsigned long long)(wlk->granted_at ?
						mxfs_pal_time_ms() - wlk->granted_at : 0),
						(unsigned long long)(wlk->queued_at ?
						    mxfs_pal_time_ms() - wlk->queued_at : 0),
						ctx->local_node, mode_name(mode));
				}
				while (*pp) {
					if (*pp == newlk) {
						/* INVARIANT GUARD (instrumented, proven in
						 * run19): this free may ONLY drop OUR OWN still-
						 * waiting request.  run19 caught this exact site
						 * (P52-GRANT-FREE ret=dlm_lock_impl+0x10cd) freeing
						 * a REMOTE holder's GRANTED entry (owner=test5 gen
						 * 8210) through the newlk pointer -> live holder
						 * vanished from the table -> immediate re-grant ->
						 * CONCURRENT EX -> stale-base RMW -> durable dirent
						 * loss (round-6 node1_f34.md5).  If the entry at
						 * *pp is not ours-and-waiting, the pointer is
						 * stale/aliased: log and DO NOT free live state. */
						if (newlk->owner != ctx->local_node ||
						    (newlk->state != MXFS_LSTATE_WAITING &&
						     newlk->state != MXFS_LSTATE_BLOCKED) ||
							newlk->pend_waiter != pend) {
							mxfs_pal_log(MXFS_LOG_DEBUG,
							    "mxfs: P4G-TIMEOUT-FREE-ALIAS ino=%llu type=%u ptr=%px owner=%u mode=%u state=%u gen=%u pw_match=%d (we=%u) — NOT freeing non-local/non-waiting entry",
							    (unsigned long long)resource->ino,
							    resource->type, newlk,
							    (unsigned)newlk->owner,
							    (unsigned)newlk->mode,
							    (unsigned)newlk->state,
							    newlk->grant_gen,
							    newlk->pend_waiter == pend ? 1 : 0,
							    ctx->local_node);
							break;
						}
						newlk->pend_waiter = NULL;
						*pp = newlk->next;
						ctx->lock_count--;
						lock_free(newlk);
						break;
					}
					pp = &(*pp)->next;
				}
			}
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			pending_free(pend);
			if (blocked_holder) {
				pr_warn_ratelimited(
				    "mxfs: P-RBLK-DENY-LOCAL type=%u ino=%llu ag=%u req=%s we=%u — held by a dead node whose recovery is RECOVERY_BLOCKED; failing the acquire instead of re-queueing for the budget\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, mode_name(mode), ctx->local_node);
				dlm_acq_end(ctx, resource, mode, 0);
				return -EHOSTDOWN;
			}
			/* -ETIMEDOUT is "no answer yet": the caller re-sends under the
			 * same acquisition, so the record — and with it this wait's age
			 * and its notification clock — deliberately survives. */
			return -ETIMEDOUT;
		}

		/* Granted via promote_waiters path */
		pending_free(pend);
		dlm_acq_end(ctx, resource, mode, 0);
		*granted_mode = mode;
		return 0;
	}
}

/*
 * 0.74.0: is this resource, mastered HERE, granted to a dead node whose
 * recovery is RECOVERY_BLOCKED?  The synchronous predicate behind the xfs
 * entry gates: true means the grant will not be released by waiting, so the
 * operation fails now.  A resource mastered by a live peer answers false
 * (the holder table is not visible here; the master denies such a request
 * on the wire instead); one mastered by the blocked dead node answers true
 * (0.75.21).  Cheap when nothing is blocked: the callback answers
 * from an O(1) count before any slot walk, and the walk here is one bucket.
 */
int mxfs_dlm_resource_held_by_blocked(struct mxfs_dlm_ctx *ctx,
				      const struct mxfs_resource_id *resource)
{
	struct mxfs_lock *lk;
	mxfs_node_id_t master;
	uint32_t bucket;
	int hit = 0;

	if (!ctx || !resource || !ctx->recovery_blocked_cb)
		return 0;
	master = mxfs_dlm_resource_master(ctx, resource);
	if (master != ctx->local_node) {
		/*
		 * 0.75.21 (D-TCP-UMOUNT-HANGS-UNINTERRUPTIBLY-WHILE-PEER-RECOVERY-
		 * FENCE-BLOCKED-0904): a resource MASTERED by the blocked dead node
		 * has no holder table anyone can read and no master that can
		 * answer; 0.75.19 made the acquire fail fast for it
		 * (P-RBLK-DENY-DEAD-MASTER), but the entry gates answered "not
		 * covered" here, so a stat served the cached attributes with rc=0
		 * after the acquire had already failed (measured s514m: the arm's
		 * stat of the victim's directory returned its inode number, the
		 * kernel logged P240-RBLK-EIO-ABORT ino=8388742 comm=stat for the
		 * same call).  Same verdict as a blocked holder: the operation
		 * fails now.
		 */
		if (ctx->recovery_blocked_cb(ctx->cb_data, master)) {
			pr_warn_ratelimited(
			    "mxfs: P-RBLK-COVERS-DEAD-MASTER type=%u ino=%llu ag=%u master=%u — "
			    "the resource's master is a dead node whose recovery is "
			    "RECOVERY_BLOCKED; the operation fails at the entry gate\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, master);
			return 1;
		}
		return 0;
	}
	bucket = resource_hash(resource, ctx->bucket_count);
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource) || !lk_is_holder(lk))
			continue;
		if (lk->owner != ctx->local_node &&
		    ctx->recovery_blocked_cb(ctx->cb_data, lk->owner)) {
			hit = 1;
			/* 0.75.24: name this path too — the s515d/s515h probes refused
			 * here (rblk=1) with no line, since only the dead-master arm
			 * above logged; which node masters ino 128 changes per lap */
			pr_warn_ratelimited(
			    "mxfs: P-RBLK-COVERS-DEAD-HOLDER type=%u ino=%llu ag=%u holder=%u — "
			    "a grant on the resource is held by a dead node whose recovery is "
			    "RECOVERY_BLOCKED; the operation fails at the entry gate\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, lk->owner);
			break;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return hit;
}

/*
 * 0.75.28 (D-ACQUIRE-TIMEOUT-BEHIND-LIVE-HOLDER-FAILSTOPS-REQUESTER-0912): the
 * question the acquire path asks after its retry budget is gone.  A remote
 * master that is a live member accepted every re-sent request and answered
 * none of them with a grant or a deny, so the request is queued behind a
 * holder it knows about; a local master can name the holders directly.  Either
 * way the wait is on a live node's release, which ends when that node
 * releases or dies — never a reason for the requester to shut itself down.
 * "No holder" on a local master is a genuine coordination failure and stays
 * one (0).
 */
int mxfs_dlm_resource_wait_is_live(struct mxfs_dlm_ctx *ctx,
				   const struct mxfs_resource_id *resource)
{
	struct mxfs_lock *lk;
	mxfs_node_id_t master;
	uint32_t bucket;
	int holders = 0, live = 1;

	if (!ctx || !resource || !ctx->node_live_cb)
		return 0;
	master = mxfs_dlm_resource_master(ctx, resource);
	if (master != ctx->local_node)
		return ctx->node_live_cb(ctx->cb_data, master) ? 1 : 0;
	bucket = resource_hash(resource, ctx->bucket_count);
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource) || !lk_is_holder(lk))
			continue;
		holders++;
		if (lk->owner != ctx->local_node &&
		    !ctx->node_live_cb(ctx->cb_data, lk->owner)) {
			live = 0;
			break;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return (holders > 0 && live) ? 1 : 0;
}

/*
 * A master told us it has queued our request for this resource.  Record when,
 * so the acquire path's post-budget decision can rest on the master having
 * answered rather than on the master merely being a member.
 *
 * Newest-wins into a small ring.  A receipt is evidence that decays: nothing
 * here expires an entry, because a stale entry and a missing one lead to the
 * same answer from mxfs_dlm_resource_wait_is_receipted.
 */
void mxfs_dlm_process_queued_ack(struct mxfs_dlm_ctx *ctx,
				 mxfs_node_id_t sender,
				 const struct mxfs_dlm_lock_resp *resp)
{
	uint32_t slot;
	int i;

	if (!ctx || !resp)
		return;

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	slot = MXFS_DLM_QACK_SLOTS;
	for (i = 0; i < MXFS_DLM_QACK_SLOTS; i++) {
		if (ctx->qack[i].ms &&
		    resource_equal(&ctx->qack[i].resource, &resp->resource)) {
			slot = (uint32_t)i;
			break;
		}
	}
	if (slot == MXFS_DLM_QACK_SLOTS) {
		slot = ctx->qack_next % MXFS_DLM_QACK_SLOTS;
		ctx->qack_next++;
		ctx->qack[slot].resource = resp->resource;
	}
	ctx->qack[slot].ms = mxfs_pal_time_ms();
	ctx->qack[slot].master = sender;
	ctx->qack[slot].req_id = resp->req_id;
	ctx->qack_rx++;
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	dlm_acq_note_receipt(ctx, &resp->resource, sender, resp->req_id);

	{
		static atomic_t qrx_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&qrx_n);

		/* rx= is the mount's TRUE receipt total, carried on every printed
		 * line because the print itself is budgeted: without it a reader
		 * counts the LINES and reports the first 16 as though they were all
		 * that arrived.  That reading was made here once already — ten lines
		 * over a 244 s wait read as "about one receipt per re-send, ten of
		 * them", when printing had simply stopped at n=16 while receipts kept
		 * coming for another 176 s. */
		if (n <= 16 || (n % 256) == 0)
			mxfs_probe("mxfs: P912-QACK-RX n=%d rx=%llu type=%u ino=%llu ag=%u master=%u holder_mode=%s req_id=%u — the master has this request queued\n",
				n, (unsigned long long)ctx->qack_rx, resp->resource.type,
				(unsigned long long)resp->resource.ino,
				resp->resource.ag_number, sender,
				mode_name(resp->mode), resp->req_id);
	}
}

/*
 * The second half of the post-budget question.  wait_is_live asks whether the
 * party we wait on is alive; this asks whether that party has ever told us it
 * has our request.  Both are needed, and only together: on this transport a
 * requester cannot read a REMOTE master's holder table (see the comment at the
 * remote-master timeout below), so "the master is a live member" alone is
 * satisfied just as well by a master that received nothing and by one that is
 * holding our request behind a drain.
 *
 * A locally mastered resource needs no receipt: its holder table is right
 * here, and wait_is_live already required a live holder in it.
 */
int mxfs_dlm_resource_wait_is_receipted(struct mxfs_dlm_ctx *ctx,
					const struct mxfs_resource_id *resource,
					uint64_t stale_ms)
{
	mxfs_node_id_t master;
	uint64_t now, ms = 0;
	int i;

	if (!ctx || !resource)
		return 0;
	master = mxfs_dlm_resource_master(ctx, resource);
	if (master == ctx->local_node)
		return 1;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (i = 0; i < MXFS_DLM_QACK_SLOTS; i++) {
		if (ctx->qack[i].ms &&
		    ctx->qack[i].master == master &&
		    resource_equal(&ctx->qack[i].resource, resource)) {
			ms = ctx->qack[i].ms;
			break;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (!ms)
		return 0;
	now = mxfs_pal_time_ms();
	return (now >= ms && (now - ms) <= stale_ms) ? 1 : 0;
}

/* ─── mxfs_dlm_lock — Local lock acquisition ─── */

int mxfs_dlm_lock(struct mxfs_dlm_ctx *ctx,
		  const struct mxfs_resource_id *resource,
		  uint8_t mode, uint32_t flags,
		  uint8_t *granted_mode)
{
	/* raised 10 -> 60 to keep the TOTAL acquire budget
	 * (retries * MXFS_LOCK_ACQUIRE_WAIT_MS) at ~60s after lowering the
	 * per-attempt wait to 1000ms — still covers a release-fence drain while
	 * recovering a stranded dir-EX waiter in ~1s instead of ~6s. */
	return mxfs_dlm_lock_retries(ctx, resource, mode, flags, granted_mode, 60);
}

/*
 * retry-budget variant.  The xfs-layer inode-DLM
 * acquire slow path (mxfs_dlm_ilock_begin) drives this with a SMALL budget so
 * it returns to the caller every ~retries seconds — long enough for one
 * grant-wait window, short enough that the caller can re-run its cooperative
 * cached-AG yield (mxfs_dlm_yield_basted_cached_ags) DURING the ~60s acquire
 * rather than only once before it.  Without that, a node blocked here on a dir
 * inode EX never releases a cached AG a peer is BAST'ing -> the proven
 * inode<->AG ABBA deadlock -> -ETIMEDOUT -> dirty trans_cancel -> shutdown
 * (the tcp_dlm_scaling within-window/drain failure).
 */
int mxfs_dlm_lock_retries(struct mxfs_dlm_ctx *ctx,
		  const struct mxfs_resource_id *resource,
		  uint8_t mode, uint32_t flags,
		  uint8_t *granted_mode, int max_retries)
{
	int ret;
	int retries = max_retries > 0 ? max_retries : 1;
	int retries0 = retries;
	uint32_t why0[11];
	int n_timeout = 0, n_xport = 0;
	/*
	 * 0.75.53 (D-0922, instrumented stack-proven on the two-node TCP rig): a
	 * parked decision used to sleep a flat 100 ms per retry.  The
	 * appender's release-drain writeback converted its delayed allocation
	 * through the allocator's non-blocking AG probe; the AG's ledger page
	 * was being handed to its view master on first touch after a
	 * membership change, the master answered REMASTER, and the probe slept
	 * the full 100 ms while the handoff itself completed in a fraction of
	 * that — 117-121 ms inside filemap_write_and_wait on every first-touch
	 * AG, twice per truncate lap, with the appender parked and the
	 * truncator waiting.  Back off from 4 ms and double, so a short park
	 * is re-tried within about its own duration, and settle at the old
	 * 100 ms cadence so a long park (a multi-second takeover during a
	 * ramp) still does not turn into a message loop on the master.
	 */
	int park_ms = 4;
	/*
	 * 0.84.5 (D-...-0960): a request on a page whose dead authority a live
	 * bootstrap is taking over is answered MXFS_DLM_RETRY_TRANSITION with
	 * the bootstrap's page-takeover count.  While that count advances the
	 * retry budget is not spent — the wait is bounded by the pass, whose
	 * every page is a visible completion, not by a budget a 157 s pass
	 * exceeds eight times over — and MXFS_DLM_TRANSITION_STALL_MS without an
	 * advance ends it with -EREMCHG: a retryable failure of this operation
	 * for the caller to classify, never a shutdown.
	 */
	uint64_t tprog = 0, trans_prog = 0, trans_t0 = 0;
	bool trans_seen = false;
	int n_trans = 0;

	if (!ctx || !resource || mode >= MXFS_LOCK_MODE_COUNT)
		return -EINVAL;
	memcpy(why0, ctx->retry_why, sizeof(why0));   /* per-request tally */

	/* DLM_TRACE: log entry for inode 128 debugging */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: dlm_lock ENTRY ino=128 "
			     "requested_mode=%s flags=0x%x local_node=%u",
			     mode_name(mode), flags, ctx->local_node);

	/* Retry loop: membership changes during a lock request cause
	 * MXFS_DLM_RETRY (the request was sent to a now-dead master, or
	 * the WAITING entry was purged from the table). Retry with the
	 * updated master assignment — the surviving node is now master
	 * for all (or most) resources and the retry typically succeeds
	 * immediately on an empty lock table.
	 *
	 * Bounded to 10 retries to handle multiple rapid membership
	 * changes (e.g. several nodes joining/leaving in quick succession).
	 * Bug 67: increased from 3 to 10 to prevent lock starvation
	 * under repeated epoch changes. */
	do {
		/*
		 * The wait is bounded here rather than woken from elsewhere: every
		 * attempt below returns to this line within one
		 * MXFS_LOCK_ACQUIRE_WAIT_MS, so a closure is discovered within about
		 * that long without any broadcast, and without a registry of waiters
		 * that a new wait site could forget to join.
		 */
		if (unlikely(dlm_authority_lost(ctx))) {
			mxfs_probe_ratelimited(
			    "mxfs: P292-ACQ-AUTH-CLOSED type=%u ino=%llu ag=%u mode=%s we=%u retries_left=%d comm=%s — this incarnation's authority closed while the acquire was waiting; the wait is ENDED with a terminal error instead of running out its retry budget\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, mode_name(mode), ctx->local_node,
			    retries, dlm_cur_comm());
			return -ESHUTDOWN;
		}
		ret = dlm_lock_impl(ctx, resource, mode, flags, granted_mode, &tprog);
		if (ret == MXFS_DLM_RETRY_TRANSITION) {
			uint64_t now = mxfs_pal_time_ms();

			/*
			 * A request that asked not to queue does not wait on a
			 * transition either: "would block" now, and the caller's
			 * blocking acquire (or its next AG) follows.  Measured s590g:
			 * the blocking AG acquire's non-blocking probe waited out a
			 * whole page cycle plus the watchdog (52 s) before the
			 * blocking acquire even started.
			 */
			if (flags & MXFS_LKF_NOQUEUE) {
				mxfs_probe_ratelimited(
				    "mxfs: P960-AUTH-TRANSITION-NOQUEUE type=%u ino=%llu ag=%u mode=%s progress=%llu comm=%s — a no-queue request on a page in transition answers would-block\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, mode_name(mode),
				    (unsigned long long)tprog, dlm_cur_comm());
				return -EAGAIN;
			}
			n_trans++;
			if (!trans_seen || tprog != trans_prog) {
				trans_seen = true;
				trans_prog = tprog;
				trans_t0 = now;
			} else if (now - trans_t0 >= MXFS_DLM_TRANSITION_STALL_MS) {
				/*
				 * Only a caller that registered as fallible — one sitting
				 * at a boundary with nothing dirty and no transaction
				 * open — is failed by a stalled transition; every other
				 * caller keeps waiting and says so every 30 s.  An AG
				 * acquire inside a dirty transaction handed -EREMCHG
				 * would cancel dirty and shut the filesystem down, which
				 * is the escalation this whole path exists to avoid.
				 */
				bool fallible = ctx->acq_fallible_cb &&
						ctx->acq_fallible_cb(ctx->cb_data, resource);

				mxfs_pal_log(MXFS_LOG_ERR,
					     "mxfs: P960-AUTH-TRANSITION-STALLED type=%u ino=%llu ag=%u "
					     "mode=%s progress=%llu stalled_ms=%llu waits=%d "
					     "retries_left=%d fallible=%d comm=%s — the takeover this "
					     "request waits on made no progress; %s",
					     resource->type, (unsigned long long)resource->ino,
					     resource->ag_number, mode_name(mode),
					     (unsigned long long)tprog,
					     (unsigned long long)(now - trans_t0), n_trans, retries,
					     fallible ? 1 : 0, dlm_cur_comm(),
					     fallible ? "failing THIS operation (retryable), not the mount" :
							"this caller cannot be failed; waiting on");
				if (fallible) {
					/* the caller that must classify this: the first stalls
					 * of a boot dump their wait site */
					static atomic_t p960_stack_cap = ATOMIC_INIT(0);

					if (atomic_inc_return(&p960_stack_cap) <= 8 &&
					    mxfs_probe_on())
						mxfs_pal_dump_stack();
					return -EREMCHG;
				}
				trans_t0 = now;
			}
			if (ctx->shutting_down)
				return -ESHUTDOWN;
			if (ctx->acq_fallible_cb && ctx->acq_fallible_cb(ctx->cb_data, resource) &&
			    mxfs_pal_fatal_signal_pending()) {
				mxfs_probe_ratelimited(
				    "mxfs: P958-ACQ-FATAL-SIGNAL ino=%llu type=%u ag=%u mode=%s retries_left=%d comm=%s — a killed task at a fallible boundary leaves its transition wait\n",
				    (unsigned long long)resource->ino, resource->type,
				    resource->ag_number, mode_name(mode), retries,
				    dlm_cur_comm());
				return -EINTR;
			}
			if (n_trans == 1)
				pr_warn_ratelimited(
				    "mxfs: P960-AUTH-TRANSITION-WAIT type=%u ino=%llu ag=%u mode=%s progress=%llu comm=%s — waiting on a live bootstrap's takeover of this page; the retry budget is not spent while it advances\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, mode_name(mode),
				    (unsigned long long)tprog, dlm_cur_comm());
			retries++;              /* undone by the loop's --retries */
			mxfs_pal_sleep_ms(park_ms);
			park_ms = park_ms * 2 > 100 ? 100 : park_ms * 2;
			continue;
		}
		/*
		 * FIX-23 attempt REVERTED (a9a03929, run107 11/17 vs run106
		 * 15/17): sending the gen-0 unconditional release on EVERY
		 * -ETIMEDOUT kills a LIVE grant in the re-affirm case — the FS
		 * layer holds cached EX (i_dlm_mode=EX) while a re-request times
		 * out; the release removed our own GRANTED master entry, the
		 * master granted a peer, and mutual exclusion broke (run107:
		 * dlm_scaling node3 P26-IGET-FAIL .dlm_scaling err=-2, fence 7/8,
		 * fault 5/8).  The no-mirror discard case is already covered by
		 * the receiver-side GRANT-REJECT-UNSOLICITED below; do NOT add a
		 * blind release here.
		 */
		if (ret != MXFS_DLM_RETRY) {
			/* Bug 85: also retry on transport errors.  When a peer
			 * disconnects, fail_all_pending() wakes waiters with
			 * MXFS_DLM_RETRY.  But the retry may try to send to the
			 * same dead master (active node list not yet updated),
			 * getting -ENOTCONN.  Retry with a short sleep to give
			 * update_active_nodes() time to remap the master. */
			if ((ret == -ENOTCONN || ret == -EPIPE ||
			     ret == -ECONNRESET) && retries > 1) {
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "dlm: lock retry after transport error %d "
					     "(mode=%s, retries_left=%d)",
					     ret, mode_name(mode), retries - 1);
				n_xport++;
				mxfs_pal_sleep_ms(500);
			} else if (ret == -ETIMEDOUT && retries > 1 &&
				   ctx->acq_fallible_cb &&
				   ctx->acq_fallible_cb(ctx->cb_data, resource) &&
				   mxfs_pal_fatal_signal_pending()) {
				/*
				 * The task was killed while waiting, and its caller can
				 * fail the operation cleanly (it said so by registering).
				 * Leave the wait now rather than at the end of the budget;
				 * the classifier abandons the acquisition by name and the
				 * engine owns whatever the master still holds for it.
				 */
				mxfs_probe_ratelimited(
				    "mxfs: P958-ACQ-FATAL-SIGNAL ino=%llu type=%u ag=%u mode=%s retries_left=%d comm=%s — a killed task at a fallible boundary leaves its lock wait\n",
				    (unsigned long long)resource->ino, resource->type,
				    resource->ag_number, mode_name(mode), retries - 1,
				    dlm_cur_comm());
				return -EINTR;
			} else if (ret == -ETIMEDOUT && retries > 1) {
				n_timeout++;
				/*
				 * sess-tcp (PROVEN root): a contended dir-EX handoff whose
				 * grant/release notification was dropped/delayed leaves this
				 * waiter timed out after MXFS_LOCK_ACQUIRE_WAIT_MS even though
				 * the holder has released.  Retry: dlm_lock_impl re-checks
				 * compatibility (now free -> immediate grant) and re-fires the
				 * BAST if still held.  This recovers the lost-message stall in
				 * seconds instead of the old 60s MXFS_LOCK_WAIT_TIMEOUT_MS.
				 * Bounded by `retries`; a genuinely-unavailable lock still
				 * eventually returns -ETIMEDOUT on the last attempt.
				 */
				mxfs_probe_ratelimited(
					     "mxfs: P36-RETRY ino=%llu type=%u ag=%u mode=%s retries_left=%d comm=%s (acquire timeout)\n",
					     (unsigned long long)resource->ino,
					     resource->type,
					     resource->ag_number,
					     mode_name(mode), retries - 1,
					     dlm_cur_comm());
				/* ABBA forensics: on the FIRST timeout of an
				 * episode, dump this waiter's call chain (capped 8/boot).  The
				 * fence 60s AG-0<->dir-EX cycle needs the wait SITE (which
				 * path acquired AG before dir, or vice versa) — comm alone
				 * cannot name the inverted edge. */
				{
					static atomic_t p36_stack_cap = ATOMIC_INIT(0);
					if (retries == retries0 &&
					    atomic_inc_return(&p36_stack_cap) <= 8) {
						mxfs_probe("mxfs: P36-STACK ino=%llu type=%u ag=%u mode=%s comm=%s (first timeout, dumping wait site)\n",
							(unsigned long long)resource->ino,
							resource->type, resource->ag_number,
							mode_name(mode), dlm_cur_comm());
						if (mxfs_probe_on())
							mxfs_pal_dump_stack();
					}
				}
			} else {
				return ret;
			}
		} else {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "dlm: lock retry after membership change "
				     "(mode=%s, retries_left=%d)",
				     mode_name(mode), retries - 1);
			/* a parked decision (page handoff in flight) must not
			 * retry in a tight loop; 0.75.53: nor sleep a whole cadence
			 * when the handoff takes a tenth of it (see park_ms above) */
			if (retries > 1) {
				mxfs_pal_sleep_ms(park_ms);
				park_ms = park_ms * 2 > 100 ? 100 : park_ms * 2;
			}
		}
	} while (--retries > 0);

	mxfs_pal_log(MXFS_LOG_ERR,
		     "mxfs: lock request failed after %d retries during "
		     "cluster membership changes — file operation will "
		     "return an error (type=%u ino=%llu ag=%u mode=%s last_rc=%d "
		     "timeouts=%d transport=%d "
		     "why[pend-retry=%u remaster=%u ledger-busy=%u prepare=%u "
		     "own-pending=%u own-release=%u refused=%u grant-again=%u "
		     "wait-retry=%u capacity=%u transition-waits=%d])",
		     retries0, resource->type, (unsigned long long)resource->ino,
		     resource->ag_number, mode_name(mode), ret, n_timeout, n_xport,
		     ctx->retry_why[1] - why0[1], ctx->retry_why[2] - why0[2],
		     ctx->retry_why[3] - why0[3], ctx->retry_why[4] - why0[4],
		     ctx->retry_why[5] - why0[5], ctx->retry_why[6] - why0[6],
		     ctx->retry_why[7] - why0[7], ctx->retry_why[8] - why0[8],
		     ctx->retry_why[9] - why0[9], ctx->retry_why[10] - why0[10],
		     n_trans);
	return -EAGAIN;
}

/* ─── mxfs_dlm_unlock — Release lock held by local node ─── */

/* GEN-AWARE RELEASE: the BAST-driven release pipeline
 * (drain -> NL -> durability barrier -> unlock) is ASYNC and long (ms-to-s for
 * dirs).  A local re-acquire can complete a FULL DLM acquire inside that
 * window (i_dlm_mode already NL), inserting a FRESH GRANTED mirror carrying
 * the new grant_gen + dir_epoch.  The old gen-blind unlock then unlinked the
 * FIRST matching GRANTED entry — the fresh grant at the LIFO chain head — and
 * echoed ITS gen (rel_gen below) in LOCK_RELEASE, which the master ACCEPTS
 * (gen matches current!) -> master hands the resource to a peer while our FS
 * layer believes it holds EX with an emptied local mirror: concurrent EX that
 * P-DOUBLEGRANT cannot see + mxfs_v5_dlm_inode_dir_epoch()==0 (the run42-t4
 * P5H insert dir_epoch=647 -> 4ms -> P2-EPOCHPLACE master_ep=0 signature) ->
 * every epoch coherence guard inert -> stale-base RMW -> durable dirent loss.
 * expected_gen != 0 makes the unlock release ONLY the tenure it was queued
 * for: if the intended entry is gone and a NEWER-gen entry owns the resource,
 * refuse with -ESTALE (caller re-arms the BAST; the new tenure's own release
 * cycle serves the peer). */
/*
 * THE AUDIT THAT CANNOT BE FORGOTTEN, AS A MEASUREMENT.
 *
 * D-0945 was one release primitive out of eight that had no poison gate on its
 * TCP arm.  It was found by reading, after the damage it caused had already
 * been chased through a survivor's replay — and reading is exactly what had
 * missed it for as long as it existed, because the gate lives at each CALLER
 * and a caller nobody thought of has no gate to notice missing.
 *
 * So ask the question here instead, at the two primitives every release funnels
 * through, where the set of callers does not have to be known in advance.  This
 * only LOGS: whether a given path releasing while poisoned is a defect depends
 * on what that path is (a survivor purging a DEAD PEER's slots is the opposite
 * operation and must not be gated), so the line names the call site and the
 * disposition is made per site with evidence in hand.  The refusals stay where
 * they are; this is the instrument that says where a refusal is still owed.
 *
 * Bounded: reachable only after a log shutdown has poisoned the session, and
 * capped so a teardown that releases thousands cannot flood the log.
 */
static void dlm_note_release_while_poisoned(struct mxfs_dlm_ctx *ctx,
					    const char *fn,
					    const struct mxfs_resource_id *res,
					    void *caller)
{
	static mxfs_atomic32_t n;
	int32_t seen;

	if (!ctx->local_poisoned_cb || !ctx->local_poisoned_cb(ctx->cb_data))
		return;
	seen = mxfs_atomic32_inc(&n);
	if (seen > 64 && (seen & 255) != 0)
		return;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P945-RELEASE-WHILE-POISONED fn=%s type=%u ino=%llu "
		     "ag=%u comm=%s n=%d caller=%pS", fn, res->type,
		     (unsigned long long)res->ino, res->ag_number,
		     dlm_cur_comm(), seen, caller);
}

/*
 * D-0966: release a GRANTED entry of ours that carries NO generation -- a
 * ledger record of this incarnation imported on a page load
 * (dlm_import_holder) that no local request has adopted.  The gen-aware
 * release path names tenures by generation and reads 0 as "nothing held",
 * so such an entry is invisible to every ordinary release while it stays a
 * live holder in the master's queue.  Adopt it here (mint the generation)
 * and hand exactly that generation to mxfs_dlm_unlock_gen, so the normal
 * release machinery retires it through a ledger transition (local master)
 * or a LOCK_RELEASE carrying its grant id (remote master), and a fresh
 * grant that landed meanwhile -- it has a generation -- is never touched.
 * -ENOENT: no generation-less entry of ours exists.
 */
int mxfs_dlm_unlock_genless(struct mxfs_dlm_ctx *ctx,
			    const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	uint32_t gen = 0;
	struct mxfs_lock *lk;

	if (!ctx || !resource || !ctx->buckets)
		return -EINVAL;
	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner == ctx->local_node &&
		    lk->state == MXFS_LSTATE_GRANTED &&
		    lk->grant_gen == 0 &&
		    resource_equal(&lk->resource, resource)) {
			gen = lk->grant_gen = dlm_next_gen(ctx);
			lk->imported = false;
			ctx->ledger_imports_adopted++;
			P_LKT("ADOPT-IMPORTED-RELEASE", resource, lk->owner, lk->mode);
			break;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (!gen)
		return -ENOENT;
	return mxfs_dlm_unlock_gen(ctx, resource, gen);
}

int mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *resource,
			uint32_t expected_gen)
{
	return mxfs_dlm_unlock_open(ctx, resource, expected_gen, MXFS_TAUTH_OPEN_NONE);
}

int mxfs_dlm_unlock_open(struct mxfs_dlm_ctx *ctx,
			 const struct mxfs_resource_id *resource,
			 uint32_t expected_gen, int open_op)
{
	uint32_t bucket;
	struct mxfs_lock **pp;
	struct mxfs_lock *found = NULL;
	bool found_holder = false;
	mxfs_node_id_t master;
	uint32_t rel_gen = 0;   /* sess-tcp: gen to echo in LOCK_RELEASE */
	uint64_t rel_auth = 0, rel_seq = 0, rel_lineage = 0;   /* */
	uint8_t rel_mode = 0;
	uint32_t other_gen = 0; /* gen of a same-owner GRANTED entry we skipped */
	bool ag_orphan_nak = false; /*  AG unlock-ENOENT heal */
	bool master_blocked = false, master_sealed = false;   /* 0.75.22/23 */

	if (!ctx || !resource)
		return -EINVAL;

	dlm_note_release_while_poisoned(ctx, "unlock_gen", resource,
					__builtin_return_address(0));

	bucket = resource_hash(resource, ctx->bucket_count);

	/* Get master before acquiring table_rwlock to avoid lock ordering
	 * deadlock (active_nodes.lock -> table_rwlock in update_active_nodes) */
	master = mxfs_dlm_resource_master(ctx, resource);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	/* Find (prefer GRANTED/CONVERTING).  the entry is unlinked
	 * below — a remote-mastered mirror at once, a locally-mastered holder
	 * only after its release transition commits (PENDING_RELEASE until
	 * then, dlm_txn_finalize retires it). */
	pp = &ctx->buckets[bucket];
	while (*pp) {
		struct mxfs_lock *lk = *pp;

		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == ctx->local_node &&
		    (lk->state == MXFS_LSTATE_GRANTED ||
		     lk->state == MXFS_LSTATE_CONVERTING)) {
			if (expected_gen && lk->grant_gen != expected_gen) {
				/* Not the tenure this release belongs to — skip it. */
				other_gen = lk->grant_gen;
				pp = &lk->next;
				continue;
			}
			found = lk;
			found_holder = true;
			break;
		}
		/* our own release of this tenure is already in flight */
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == ctx->local_node &&
		    lk->state == MXFS_LSTATE_PENDING_RELEASE &&
		    (!expected_gen || lk->grant_gen == expected_gen)) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			return 0;
		}
		pp = &lk->next;
	}

	/* Gen-aware refusal: the tenure we meant to release is gone and a
	 * DIFFERENT tenure (normally newer — a re-acquire that completed during
	 * our release window) owns the resource now.  Do NOT touch it, do NOT
	 * dg_release, do NOT send LOCK_RELEASE. */
	if (!found && expected_gen && other_gen) {
		if (resource->type == MXFS_LTYPE_INODE) {
			static atomic_t p6g_n = ATOMIC_INIT(0);
			if ((unsigned)atomic_inc_return(&p6g_n) <= 20000)
				pr_warn("mxfs: P6G-STALE-RELEASE-SKIP ino=%llu rel_gen=%u cur_gen=%u comm=%s — release outlived its tenure; refused\n",
					(unsigned long long)resource->ino,
					expected_gen, other_gen, dlm_cur_comm());
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		return -ESTALE;
	}

	/* Also try waiting/blocked if no granted lock found.
	 *
	 * ROOT FIX (instrumented, proven runs 19+20 by P4L pointer
	 * lifecycle trace): this fallback used to reap ANY same-owner entry —
	 * including a CONCURRENT local thread's live in-flight request queued
	 * milliseconds earlier (bucket chains are LIFO, so the newest request
	 * matches first).  The requester's newlk pointer then dangled; kmalloc
	 * recycled the memory for a peer's entry; the requester's inevitable
	 * 1000ms timeout freed the recycled LIVE entry (run19: the peer's
	 * GRANTED EX gen 8210) -> holder vanished from the master table ->
	 * immediate re-grant -> CONCURRENT EX -> stale-base dir RMW -> durable
	 * dirent loss (round-6 node1_f34.md5).  Skip any entry with a live
	 * waiter attached (pend_waiter) — only truly abandoned WAITING/BLOCKED
	 * leftovers may be reaped here. */
	if (!found) {
		pp = &ctx->buckets[bucket];
		while (*pp) {
			struct mxfs_lock *lk = *pp;

			if (resource_equal(&lk->resource, resource) &&
			    lk->owner == ctx->local_node) {
				if (lk->pend_waiter) {
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P4U-SKIP-INFLIGHT ino=%llu type=%u ptr=%px mode=%u state=%u — unlock fallback skipping live in-flight request",
					    (unsigned long long)resource->ino,
					    resource->type, lk,
					    (unsigned)lk->mode, (unsigned)lk->state);
					pp = &lk->next;
					continue;
				}
				found = lk;
				break;
			}
			pp = &lk->next;
		}
	}

	if (!found) {
		/* DLM_TRACE: unlock found no entry for inode 128 */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: dlm_unlock ENOENT ino=128 "
				     "local_node=%u", ctx->local_node);
		/* AG unlock that found nothing to release —
		 * the local table thinks we hold nothing while the master may
		 * still carry our GRANTED entry (run31 AG-0 wedge shape).
		 *  no longer just logged — heal it.  The
		 * shape went live (test6 AG-9: membership-change purge ate the
		 * local GRANTED record; this ENOENT then sent nothing and the
		 * master's zombie starved the cluster for 500+ s).  Set the flag;
		 * the guarded orphan NAK is sent after table_rwlock drops. */
		if (resource->type == MXFS_LTYPE_AG) {
			mxfs_probe_ratelimited(
			    "mxfs: P5U-AGUNLOCK-ENOENT ag=%u master=%u local=%u\n",
			    resource->ag_number, master, ctx->local_node);
			ag_orphan_nak = true;
		}
		/* count storm-dir unlocks that found nothing —
		 * the residue an eaten mirror leaves behind (the FS layer believed
		 * it held; the local table disagrees). */
		if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131) {
			static atomic_t p6e_n = ATOMIC_INIT(0);
			if ((unsigned)atomic_inc_return(&p6e_n) <= 20000)
				mxfs_probe("mxfs: P6E-UNLOCK-ENOENT ino=131 expected_gen=%u comm=%s\n",
					expected_gen, dlm_cur_comm());
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		/*  guarded orphan NAK — outside the rwlock
		 * (the helper re-scans under rdlock; the send can sleep).  The
		 * caller is the release path, so the FS layer no longer believes
		 * it holds this grant; if a concurrent local acquire raced in,
		 * the helper's any-state scan sees its entry and refuses. */
		if (ag_orphan_nak) {
			int nak_rc = mxfs_dlm_release_orphan_if_unheld(ctx, resource);

			pr_warn_ratelimited(
			    "mxfs: P5N-AG-ORPHAN-NAK ag=%u master=%u src=unlock-enoent rc=%d\n",
			    resource->ag_number, master, nak_rc);
		}
		return -ENOENT;
	}

	/* DLM_TRACE: log which entry is being removed */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: dlm_unlock REMOVING ino=128 "
			     "owner=%u mode=%s state=%s local_node=%u "
			     "master=%u",
			     found->owner, mode_name(found->mode),
			     state_name(found->state), ctx->local_node,
			     master);

	P_LKT(found->state == MXFS_LSTATE_GRANTED ?
		  "UNLOCK-GRANTED" : "UNLOCK-OTHER",
		  resource, found->owner, found->mode);

	/* mirror-lifecycle tracer: every local-mirror removal
	 * for the storm dir, so a dangerous-unest P2-EPOCHPLACE (master_ep=0
	 * with valid_ep>0) can be joined to the removal that emptied the local
	 * table (or to its absence — insert-side loss).  Capped, ino 131. */
	if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE) {
		static atomic_t p6u_n = ATOMIC_INIT(0);
		if ((unsigned)atomic_inc_return(&p6u_n) <= 60000)
			mxfs_probe("mxfs: P6U-UNLOCK ino=131 mode=%s state=%u gen=%u dir_epoch=%u comm=%s\n",
				mode_name(found->mode), (unsigned)found->state,
				found->grant_gen, found->dir_epoch, dlm_cur_comm());
	}

	rel_gen = found->grant_gen;     /* echo our held gen in the release */
	rel_auth = found->auth_epoch;
	rel_seq = found->grant_seq;
	rel_lineage = found->lineage;
	rel_mode = found->mode;
	found->open_op = (int8_t)open_op;   /* 0.89.0: rides this release and its re-sends */

	dg_release(resource, ctx->local_node);  /* genuine local release */

	if (master == ctx->local_node && found_holder) {
		/*
		 * (step 3e): we master this resource — retire our record
		 * and grant the successors in ONE ledger transition.  The entry
		 * stays a holder (PENDING_RELEASE) for new arrivals until then.
		 */
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
		uint32_t rel_id = ++ctx->rel_id_next;
		int rrc;

		if (!txn) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			return -ENOMEM;
		}
		dlm_txn_init(txn, resource, ctx->ledger_gen);
		found->state = MXFS_LSTATE_PENDING_RELEASE;
		found->pend_waiter = NULL;
		dlm_txn_add_release(txn, found, rel_id, false);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		/* P37: local-release for the contended dir. */
		if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
			mxfs_probe_ratelimited("mxfs: P37-LREL ino=131 releaser=%u master=%u\n",
					    ctx->local_node, master);
		rrc = dlm_promote_txn(ctx, txn);
		mxfs_pal_free(txn);
		if (rrc == -ESTALE || rrc == -EAGAIN)
			rrc = 0;    /* superseded / remastered: we hold nothing either way */
		if (rrc)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-LOCAL-RELEASE-FAIL type=%u ino=%llu ag=%u gen=%u rc=%d "
				     "— record stays a blocker (PENDING_RELEASE) until the "
				     "master's re-drive retires it",
				     resource->type, (unsigned long long)resource->ino,
				     resource->ag_number, rel_gen, rrc);
		if (resource->type == MXFS_LTYPE_AG)
			mxfs_probe_ratelimited(
			    "mxfs: P5U-AGUNLOCK ag=%u master=%u local=%u relgen=%u rc=%d\n",
			    resource->ag_number, master, ctx->local_node, rel_gen, rrc);
		return rrc;
	}

	/* unlink: a remote-mastered mirror, or an abandoned WAITING/BLOCKED
	 * entry of ours (no ledger record) */
	*pp = found->next;
	ctx->lock_count--;
	lock_free(found);

	if (master == ctx->local_node) {
		/* a removed FIFO-barrier waiter may unblock younger waiters */
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));

		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		if (txn) {
			dlm_txn_init(txn, resource, ctx->ledger_gen);
			dlm_promote_txn(ctx, txn);
			mxfs_pal_free(txn);
		}
		return 0;
	}

	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	/* Handle remote unlock: send LOCK_RELEASE to the remote master with the
	 * durable grant id (retry up to 3 times on transient failure); the
	 * release stays pending until the master's RELEASE_ACK (step
	 * 3e: mxfs_dlm_release_retry_tick re-sends, mxfs_dlm_wait_release_acks
	 * gates unmount). */
	if (found_holder && ctx->send_cb &&
	    (master_blocked = (ctx->recovery_blocked_cb &&
			       ctx->recovery_blocked_cb(ctx->cb_data, master)),
		 master_sealed = dlm_master_sealed(ctx, master),
		 master_blocked || master_sealed)) {
		/*
		 * 0.75.22 (D-TCP-UMOUNT-HANGS-UNINTERRUPTIBLY-WHILE-PEER-RECOVERY-
		 * FENCE-BLOCKED-0904): the master is a dead node whose recovery is
		 * RECOVERY_BLOCKED — it will neither receive the release nor ACK
		 * it.  Sending costs three attempts and the un-ACKed release then
		 * holds the departure's ACK wait for its whole budget (measured
		 * s514m: the survivor's umount spent 8 s in dlm_wire_release_all
		 * -> mxfs_dlm_unlock_gen sleeping on the dead master).  Our grant
		 * is frozen in that master's table anyway; the recovery purge that
		 * completes its recovery retires it.  Drop the mirror and go.
		 *
		 * 0.75.23: the same for a SEALED master — a fenced dead node whose
		 * ledger records are the replay gate's authority.  After a refused
		 * replay it stays sealed for the life of the mount (the quarantine
		 * is terminal), and the survivor's umount sent every remaining
		 * grant's release to it (measured s515g: 34 releases, 4 sends
		 * each, 19 never acknowledged, P-RELALL-WIRED ack_rc=19, umount
		 * parked 5-10 s in mxfs_dlm_wait_release_acks).
		 */
		pr_warn_ratelimited(
		    "mxfs: P-RBLK-RELEASE-SKIP-DEAD-MASTER type=%u ino=%llu ag=%u master=%u gen=%u "
		    "blocked=%d sealed=%d — the master is a dead node (recovery blocked or "
		    "its records sealed); release not sent\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, master, rel_gen,
		    master_blocked ? 1 : 0, master_sealed ? 1 : 0);
	} else if (found_holder && ctx->send_cb) {
		uint32_t rel_id = ++ctx->rel_id_next;
		int send_ret;
		int send_retries = 3;

		if (rel_id == 0)
			rel_id = ctx->rel_id_next = 1;
		dlm_rel_pending_add(ctx, resource, rel_id, rel_gen, rel_auth, rel_seq,
				    rel_lineage, rel_mode, open_op);
		do {
			send_ret = dlm_send_release_msg(ctx, master, resource, rel_gen, rel_id,
							rel_auth, rel_seq, rel_lineage, rel_mode,
							open_op);
			if (send_ret == 0)
				break;
			if (--send_retries > 0) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: lock release to node %u failed, "
					     "retrying (%d attempts remaining)",
					     master, send_retries);
				mxfs_pal_sleep_ms(100);
			}
		} while (send_retries > 0);
	}

	/* AG unlock visibility — pairs with P5R-AGREL at the
	 * master; a P5U with no matching P5R names a lost release message. */
	if (resource->type == MXFS_LTYPE_AG)
		mxfs_probe_ratelimited(
		    "mxfs: P5U-AGUNLOCK ag=%u master=%u local=%u relgen=%u\n",
		    resource->ag_number, master, ctx->local_node, rel_gen);

	return 0;
}

/* Legacy unconditional unlock — releases whatever tenure the local node
 * currently holds (expected_gen=0 disables the tenure check). */
int mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx,
		    const struct mxfs_resource_id *resource)
{
	return mxfs_dlm_unlock_gen(ctx, resource, 0);
}

/*
 * FIX-20b (PROVEN BY INSTRUMENT, run91/94): send an UNCONDITIONAL
 * (gen=0) LOCK_RELEASE for `resource` to its remote master, bypassing the
 * local mirror entirely.  For a PHANTOM grant — master's table holds our
 * GRANTED entry while the local mirror has no record (the requester's
 * ACQUIRE_WAIT retry raced the late grant and discarded it, or the mirror
 * was eaten) — the normal unlock is a local -ENOENT no-op and the master
 * keeps the entry forever: every peer queues behind it for 184s and shuts
 * down (run91 held_ms=499427s-shape; run94 ino=16781703).
 * process_remote_release treats gen==0 as unconditional for the sender's
 * entry and promotes the queue; if the master has nothing it logs
 * RREL-ENOENT and no-ops.  Callers MUST have established that no live local
 * tenure exists (mirror empty + no in-flight local acquire) — the caller in
 * mxfs_dlm_bast_process gates on the serialized DEMOTING state plus a fresh
 * grant_gen==0 re-check.  NOT called on the common eviction/ENOENT unlock
 * paths (the first FIX-20 cut did that and the bulk wire flood regressed
 * dlm_fairness — one targeted message per detected phantom only).
 */
int mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx,
					const struct mxfs_resource_id *resource)
{
	struct mxfs_dlm_lock_release rel;
	mxfs_node_id_t master;

	if (!ctx || !resource || !ctx->send_cb)
		return -EINVAL;
	dlm_note_release_while_poisoned(ctx, "uncond_release", resource,
					__builtin_return_address(0));
	master = mxfs_dlm_resource_master(ctx, resource);
	if (master == ctx->local_node)
		return 0;   /* local master: the local table IS authoritative */

	memset(&rel, 0, sizeof(rel));
	rel.hdr.magic = MXFS_DLM_MAGIC;
	rel.hdr.version = MXFS_DLM_VERSION;
	rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
	rel.hdr.length = sizeof(rel);
	rel.hdr.sender = ctx->local_node;
	rel.hdr.target = master;
	rel.hdr.epoch = ctx->current_epoch;
	rel.resource = *resource;
	rel.grant_gen = 0;
	rel.owner_inc = ctx->local_inc;     /* the master validates the
										 * record against OUR incarnation and
										 * takes the grant id from its table */
	rel.owner_slot = ctx->local_slot;
	return ctx->send_cb(ctx, master, &rel, sizeof(rel));
}

/*
 *  — ORPHAN-GRANT NAK (zombie AG grant, captured live).
 *
 * mxfs_dlm_update_active_nodes purges the ENTIRE local lock table on every
 * membership change, and nodes process membership events at different
 * times.  During the 1->N mount ramp a node can acquire a grant whose
 * master's table then SURVIVES (the master's view had already settled)
 * while the holder's own record is purged moments later by its next
 * membership event.  The holder's eventual release then hits local -ENOENT
 * and — before this fix — sent NOTHING: the master carried the zombie
 * GRANTED entry forever, every requester queued behind it retrying 1/s,
 * and the whole cluster starved on that AG (test6 AG-9 17:28:15
 * P5U-AGUNLOCK-ENOENT -> test2 master holder=test6 hstate=2 re-BASTing
 * 1/s for 500+ s -> test1 rm-rf stuck in mxfs_trans_preacquire_inode_ags
 * holding the dir ILOCK -> every dir_reuse run DNF).
 *
 * Heal: when we can PROVE we hold nothing locally — no entry of ANY state
 * (granted / converting / waiting / in-flight pend_waiter) for the
 * resource in the local table — send the FIX-20b unconditional (gen=0)
 * LOCK_RELEASE to the resource's current master.  If the master has a
 * zombie entry for us it is cleared and the queue promotes; if it has
 * nothing it logs RREL-ENOENT and no-ops.  The any-state scan is the
 * safety gate: a live in-flight acquire (WAITING + pend_waiter) blocks
 * the NAK, so a late grant can never be released out from under a local
 * waiter.  Callers must additionally ensure the FS layer does not believe
 * it holds the grant (pag cached=0 / release path already committed).
 */
int mxfs_dlm_release_orphan_if_unheld(struct mxfs_dlm_ctx *ctx,
				      const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	bool held = false;
	uint8_t st = 0, md = 0;
	uint32_t gg = 0;
	uint64_t age = 0;

	if (!ctx || !resource)
		return -EINVAL;

	bucket = resource_hash(resource, ctx->bucket_count);
	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == ctx->local_node) {
			held = true;
			st = lk->state;
			md = lk->mode;
			gg = lk->grant_gen;
			age = lk->granted_at ? mxfs_pal_time_ms() - lk->granted_at : 0;
			break;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	if (held) {
		/* What entry refuses the NAK: its state decides whether an orphan
		 * can be healed without releasing a live acquire.  Capped. */
		static int p_orph_busy_cap;

		if (p_orph_busy_cap < 40) {
			p_orph_busy_cap++;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-ORPH-NAK-BUSY type=%u ag=%u ino=%llu "
				     "local entry state=%u mode=%u grant_gen=%u "
				     "granted_age_ms=%llu",
				     resource->type, resource->ag_number,
				     (unsigned long long)resource->ino, st, md, gg,
				     (unsigned long long)age);
		}
		return -EBUSY;
	}
	return mxfs_dlm_send_unconditional_release(ctx, resource);
}

/* ─── mxfs_dlm_lock_convert — Mode upgrade/downgrade ─── */

int mxfs_dlm_lock_convert(struct mxfs_dlm_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  mxfs_node_id_t owner, uint8_t new_mode)
{
	uint32_t bucket;
	struct mxfs_lock *target_lk = NULL;
	struct mxfs_lock *chain, *lk;
	uint8_t old_mode;

	if (!ctx || !resource || new_mode >= MXFS_LOCK_MODE_COUNT)
		return -EINVAL;

	bucket = resource_hash(resource, ctx->bucket_count);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	chain = ctx->buckets[bucket];

	for (lk = chain; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == owner &&
		    lk->state == MXFS_LSTATE_GRANTED) {
			target_lk = lk;
			break;
		}
	}

	if (!target_lk) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		return -ENOENT;
	}

	old_mode = target_lk->mode;

	/* Downgrade is always allowed */
	if (new_mode <= old_mode) {
		struct dlm_txn *txn;
		uint8_t prev_mode = target_lk->mode;
		uint32_t prev_gen = target_lk->grant_gen;

		/*
		 * FIX: this DOWNGRADE→promote path was the ONLY
		 * one of the 4 promote_waiters dispatch sites that did NOT call
		 * dg_grant_ex, so an EX grant promoted here got dir_epoch=0 (the
		 * 8/tcp dir_reuse intra-block double-alloc).  the
		 * downgrade is itself a ledger transition (EX record -> holder
		 * bit) and the successors ride in the same dlm_promote_txn rounds,
		 * which stamp dg_grant_ex and deliver local + remote grantees.
		 */
		txn = mxfs_pal_alloc(sizeof(*txn));
		if (!txn) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			return -ENOMEM;
		}
		dlm_txn_init(txn, resource, ctx->ledger_gen);
		target_lk->mode = new_mode;
		target_lk->granted_at = mxfs_pal_time_ms();
		target_lk->grant_gen = dlm_next_gen(ctx);
		target_lk->state = MXFS_LSTATE_PENDING_DURABLE;
		target_lk->decide_gen = ctx->ledger_gen;
		dlm_txn_add_grant(txn, target_lk, prev_mode, prev_gen, false);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		dlm_promote_txn(ctx, txn);
		mxfs_pal_free(txn);
		return 0;
	}

	/* Upgrade — check compatibility with other holders */
	{
		int conv_compat = 1;

		for (lk = chain; lk; lk = lk->next) {
			if (!resource_equal(&lk->resource, resource))
				continue;
			if (!lk_is_holder(lk))
				continue;
			if (lk->owner == owner)
				continue;
			if (!lock_compat[lk->mode][new_mode]) {
				conv_compat = 0;
				break;
			}
		}

		if (conv_compat) {
			struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
			uint8_t prev_mode = target_lk->mode;
			uint32_t prev_gen = target_lk->grant_gen;
			int grc;

			if (!txn) {
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				return -ENOMEM;
			}
			dlm_txn_init(txn, resource, ctx->ledger_gen);
			target_lk->mode = new_mode;
			target_lk->granted_at = mxfs_pal_time_ms();
			target_lk->grant_gen = dlm_next_gen(ctx);
			target_lk->state = MXFS_LSTATE_PENDING_DURABLE;
			target_lk->decide_gen = ctx->ledger_gen;
			if (new_mode == MXFS_LOCK_EX)
				target_lk->handoff = dg_grant_ex(ctx, resource, owner,
								 target_lk->grant_gen,
								 &target_lk->dir_epoch);
			dlm_txn_add_grant(txn, target_lk, prev_mode, prev_gen, false);
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			grc = dlm_grant_txn(ctx, txn);
			mxfs_pal_free(txn);
			return grc == -EAGAIN ? -EAGAIN : grc;
		}

		/* Upgrade blocked — mark as converting */
		target_lk->state = MXFS_LSTATE_CONVERTING;
		target_lk->mode = new_mode;
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		return -EINPROGRESS;
	}
}

/* ─── mxfs_dlm_purge_node — Release all locks for a dead node ─── */

/*
 * 0.75.30: `selective` = the owner is a terminally refused victim — its
 * authority stays sealed and only the entries whose resource the mount layer
 * classifies as provably outside its quarantined domain are dropped; the
 * rest stay as frozen blockers (denied fast by the recovery_blocked_cb gate).
 */
static int dlm_purge_node_impl(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
			       bool selective)
{
	uint32_t i;
	int purged = 0, kept = 0;
	struct mxfs_resource_id *promote = NULL;
	uint32_t npromote = 0, cap = 0;
	int grant_count = 0;

	if (!ctx)
		return -EINVAL;
	if (selective && !dlm_owner_refused(ctx, node, NULL))
		return -EINVAL;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: purging all locks for dead node %u", node);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	/* the recovery purge is the sanctioned retirement of a sealed owner's
	 * authority; nothing of it remains to protect */
	if (!selective)
		dlm_owner_unseal(ctx, node);

	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock **pp = &ctx->buckets[i];

		while (*pp) {
			struct mxfs_lock *lk = *pp;

			if (selective && lk->owner == node &&
			    ctx->refused_owner_cb(ctx->cb_data, node, &lk->resource, NULL) > 0) {
				kept++;
				pp = &lk->next;
				continue;
			}
			/* (D-0342): an imported blocker of an owner whose
			 * ledger purge has not completed mirrors a bit still on the
			 * platter — it stays until the purge re-drive retires it */
			if (lk->owner == node &&
			    !(lk->imported && dlm_purge_pending(ctx, node))) {
				*pp = lk->next;
				lock_free(lk);
				ctx->lock_count--;
				purged++;
			} else {
				pp = &lk->next;
			}
		}
	}

	/*
	 * successors are granted through the ledger — collect every
	 * resource that has a waiter, then run dlm_promote_txn per resource
	 * OUTSIDE the table lock (each one is a page transition).  The dead
	 * node's ledger records were retired by mxfs_dlm_ledger_purge_owner
	 * before this call; anything still ACTIVE for it refuses the grant
	 * (fail closed) rather than granting over it.
	 */
	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock *lk_iter;

		for (lk_iter = ctx->buckets[i]; lk_iter; lk_iter = lk_iter->next) {
			uint32_t k;
			bool seen = false;

			if (lk_iter->state != MXFS_LSTATE_WAITING &&
			    lk_iter->state != MXFS_LSTATE_BLOCKED)
				continue;
			for (k = 0; k < npromote; k++)
				if (resource_equal(&promote[k], &lk_iter->resource)) {
					seen = true;
					break;
				}
			if (seen)
				continue;
			if (npromote == cap) {
				struct mxfs_resource_id *bigger;
				uint32_t ncap = cap ? cap * 2 : 64;

				bigger = mxfs_pal_alloc(ncap * sizeof(*bigger));
				if (!bigger)
					break;
				if (promote) {
					memcpy(bigger, promote, npromote * sizeof(*bigger));
					mxfs_pal_free(promote);
				}
				promote = bigger;
				cap = ncap;
			}
			promote[npromote++] = lk_iter->resource;
		}
	}

	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	if (promote) {
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
		uint32_t k;

		if (txn) {
			for (k = 0; k < npromote; k++) {
				dlm_txn_init(txn, &promote[k], ctx->ledger_gen);
				dlm_promote_txn(ctx, txn);
				grant_count++;
			}
			mxfs_pal_free(txn);
		}
		mxfs_pal_free(promote);
	}

	mxfs_pal_log(selective ? MXFS_LOG_WARN : MXFS_LOG_DEBUG,
		     "dlm: purged %d locks from node %u, re-evaluated %d resources "
		     "(selective=%d kept=%d)",
		     purged, node, grant_count, selective ? 1 : 0, kept);

	/* Bug 85: wake ALL pending lock waiters (not just promoted ones).
	 *
	 * When a remote-master node dies, threads waiting in pending_wait()
	 * for a LOCK_GRANT from that master would stall for up to 120s
	 * (MXFS_LOCK_WAIT_TIMEOUT_MS).  The deferred update_active_nodes()
	 * path may not call fail_all_pending() if the lease table still
	 * includes the dead node (lease expiry takes ~6 min, but TCP
	 * disconnect is detected in seconds).
	 *
	 * By waking all pending waiters here with MXFS_DLM_RETRY, threads
	 * immediately retry.  If the master mapping hasn't updated yet,
	 * the send will fail fast (-ENOTCONN) and the retry loop in
	 * mxfs_dlm_lock() will catch it and retry with a sleep, giving
	 * update_active_nodes() time to remap the master. */
	if (purged > 0)
		fail_all_pending(ctx);

	return purged;
}

int mxfs_dlm_purge_node(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	return dlm_purge_node_impl(ctx, node, false);
}

int mxfs_dlm_purge_node_selective(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
	return dlm_purge_node_impl(ctx, node, true);
}

/* ─── mxfs_dlm_purge_stale_for_resource — Remove stale remote holders ─── */

int mxfs_dlm_purge_stale_for_resource(struct mxfs_dlm_ctx *ctx,
				       const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock **pp;
	int purged = 0;

	if (!ctx || !resource)
		return 0;

	bucket = resource_hash(resource, ctx->bucket_count);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	/* Remove all entries for this resource owned by remote nodes.
	 * These are stale holders from a defunct master that will never
	 * release via BAST because the new master doesn't know about them. */
	pp = &ctx->buckets[bucket];
	while (*pp) {
		struct mxfs_lock *lk = *pp;

		if (resource_equal(&lk->resource, resource) &&
		    lk->owner != ctx->local_node) {
			*pp = lk->next;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "dlm: purging stale %s lock for node %u "
				     "on resource (type=%u, ino=%llu)",
				     mode_name(lk->mode), lk->owner,
				     resource->type,
				     (unsigned long long)resource->ino);
			lock_free(lk);
			ctx->lock_count--;
			purged++;
		} else {
			pp = &lk->next;
		}
	}

	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	if (purged == 0)
		return 0;

	/* Promote any waiters that were blocked by the purged holders
	 * (through the ledger, outside the table lock) */
	{
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));

		if (txn) {
			dlm_txn_init(txn, resource, ctx->ledger_gen);
			dlm_promote_txn(ctx, txn);
			mxfs_pal_free(txn);
		}
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: purged %d stale entries for resource "
		     "(type=%u, ino=%llu)",
		     purged, resource->type,
		     (unsigned long long)resource->ino);

	return purged;
}

/* ─── mxfs_dlm_withdraw_release_all — wire-release every grant we hold ───
 *
 * (PROVEN BY INSTRUMENT 32/tcp fio cascade): a node whose
 * FS force-shut down cannot serve BASTs any more (the release drain needs
 * the live FS), but its GRANTED entries remain in every master's table —
 * so any peer's conflicting request starves to terminal -ETIMEDOUT and
 * that peer ALSO force-shuts down (test29 dirty-trans-cancel first, then
 * 5 nodes died rc=-110 on ino=128 whose PR holders included dead nodes;
 * the dead master's service itself kept answering — the un-releasable
 * GRANTS were the block).  A dead FS holds no valid cache: release
 * EVERYTHING on withdrawal so peers promote immediately.
 *
 * Walk ctx->buckets snapshotting every resource with an owner==local entry
 * (GRANTED/CONVERTING mirrors of remote masters AND locally-mastered own
 * grants AND our queued WAITING entries — nobody will ever consume those
 * either), then run the standard mxfs_dlm_unlock per resource (local:
 * remove + promote_waiters + post-promotion grants/BASTs; remote: send
 * LOCK_RELEASE).  Unlocks are done OUTSIDE the table lock. */
static int dlm_wire_release_all(struct mxfs_dlm_ctx *ctx)
{
	struct mxfs_resource_id *list = NULL;
	uint32_t i, n = 0, cap = 0;
	int pass;

	if (!ctx)
		return 0;

	/* pass 0: count; pass 1: fill (table can shrink between passes — the
	 * fill re-checks bounds; a second walk missing new entries is fine,
	 * the FS is dead and creates nothing new). */
	for (pass = 0; pass < 2; pass++) {
		uint32_t seen = 0;

		mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
		for (i = 0; i < ctx->bucket_count; i++) {
			struct mxfs_lock *lk;

			for (lk = ctx->buckets[i]; lk; lk = lk->next) {
				if (lk->owner != ctx->local_node)
					continue;
				if (pass == 1) {
					if (seen < cap)
						list[seen] = lk->resource;
				}
				seen++;
			}
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		if (pass == 0) {
			cap = seen;
			if (cap == 0)
				return 0;
			list = mxfs_pal_alloc(cap * sizeof(*list));
			if (!list) {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "dlm: wire_release_all alloc failed (%u entries leak until unmount)",
				    cap);
				return -ENOMEM;
			}
		} else {
			n = seen < cap ? seen : cap;
		}
	}

	for (i = 0; i < n; i++)
		mxfs_dlm_unlock(ctx, &list[i]);

	mxfs_pal_free(list);
	return (int)n;
}

void mxfs_dlm_withdraw_release_all(struct mxfs_dlm_ctx *ctx)
{
	int n = dlm_wire_release_all(ctx);

	if (n > 0)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-WITHDRAW-RELALL released %d held/queued grants (dead-FS holder cannot serve BASTs)",
			     n);
}

/* ─── mxfs_dlm_release_all — Release all locks held by local node ─── */

void mxfs_dlm_release_all(struct mxfs_dlm_ctx *ctx)
{
	uint32_t i;
	int released = 0;

	if (!ctx)
		return;

	/* (step 3e): unmount may not complete with a release un-ACKed
	 * — every un-ACKed record would stay a ledger blocker.  Bounded:
	 * 3 s (> 2 retry intervals); what is left is logged, and the clean-
	 * departure purge at the masters retires it. */
	mxfs_dlm_wait_release_acks(ctx, 3000);

	/*
	 * 0.75.15 (D-TCP-MASTER-IMPORTS-PREDECESSOR-SLOT-SHARED-BIT-AS-CURRENT-
	 * OCCUPANT-GRANT-...-0908, measurement): what this clean departure
	 * leaves in the table is exactly what it leaves on the platter for the
	 * peers' departure purge — freed below without a wire release.  Name
	 * it, so the purge's cleared count and the residue a successor on our
	 * slot imports can be matched against it.
	 */
	{
		struct {
			struct mxfs_resource_id res;
			uint8_t mode, state;
		} left[12];
		uint32_t nleft = 0, nheld = 0, npr = 0, nex = 0, nother = 0, k;

		mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
		for (i = 0; i < ctx->bucket_count; i++) {
			struct mxfs_lock *lk;

			for (lk = ctx->buckets[i]; lk; lk = lk->next) {
				if (lk->owner != ctx->local_node)
					continue;
				if (lk_is_holder(lk)) {
					nheld++;
					if (lk->mode == MXFS_LOCK_EX)
						nex++;
					else if (lk->mode == MXFS_LOCK_PR)
						npr++;
					else
						nother++;
				} else {
					nother++;
				}
				if (nleft < 12) {
					left[nleft].res = lk->resource;
					left[nleft].mode = lk->mode;
					left[nleft].state = lk->state;
					nleft++;
				}
			}
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-RELALL-LEFT node=%u held=%u pr=%u ex=%u other=%u — "
			     "grants this clean departure leaves to the peers' purge",
			     ctx->local_node, nheld, npr, nex, nother);
		for (k = 0; k < nleft; k++)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P-RELALL-LEFT-ENTRY type=%u ino=%llu ag=%u mode=%s "
				     "state=%u master=%u",
				     left[k].res.type, (unsigned long long)left[k].res.ino,
				     left[k].res.ag_number, mode_name(left[k].mode),
				     left[k].state,
				     mxfs_dlm_resource_master(ctx, &left[k].res));
		/*
		 * 0.75.16 (the fix): measured on 0.75.15 (rejoin_residue s514a,
		 * every clean leave): the leftovers were the root inode's PR and
		 * one more directory's PR, one of them mastered by a peer; the
		 * peer's departure purge then cleared NOTHING (cand=0) because a
		 * successor had already claimed our heartbeat slot when the purge
		 * ran, which drops the slot half of the purge (a live slot's bits
		 * are the successor's), and the successor imported our bit on its
		 * own slot as residue.  A clean departure leaves nothing for the
		 * purge: release every remaining grant through the DLM before the
		 * GOODBYE — LOCK_RELEASE to a remote master, a ledger transition on
		 * a local one — and wait for the acks as before.  The purge stays
		 * as the backstop for a death and for an unacked release.
		 */
		if (nheld && mxfs_depart_wire_release) {
			int wired = dlm_wire_release_all(ctx);
			int arc = wired > 0 ? mxfs_dlm_wait_release_acks(ctx, 3000) : 0;
			uint32_t after = 0;

			mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
			for (i = 0; i < ctx->bucket_count; i++) {
				struct mxfs_lock *lk;

				for (lk = ctx->buckets[i]; lk; lk = lk->next)
					if (lk->owner == ctx->local_node && lk_is_holder(lk))
						after++;
			}
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-RELALL-WIRED node=%u released=%d ack_rc=%d held_after=%u "
				     "— the clean departure released its remaining grants through the DLM",
				     ctx->local_node, wired, arc, after);
		} else if (nheld) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-RELALL-UNWIRED node=%u held=%u — DEBUG depart_wire_release=0: "
				     "the grants are left to the peers' purge (the pre-0.75.16 shape)",
				     ctx->local_node, nheld);
		}
	}

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	for (i = 0; i < ctx->bucket_count; i++) {
		struct mxfs_lock **pp = &ctx->buckets[i];

		while (*pp) {
			struct mxfs_lock *lk = *pp;

			if (lk->owner == ctx->local_node) {
				*pp = lk->next;
				lock_free(lk);
				ctx->lock_count--;
				released++;
			} else {
				pp = &lk->next;
			}
		}
	}

	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: released %d local locks on unmount", released);
	/* the master-side ledger counters (the ledger's own
	 * P-TAUTH-STATS covers the page store) */
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-TAUTH-DLM-STATS node=%u grants=%llu denies=%llu imports=%llu "
		     "imports_resolved=%llu import_residue=%llu imports_adopted=%llu ghosts=%llu remaster=%llu late=%llu "
		     "rel_acks=%llu rel_resends=%llu rel_unacked=%llu rel_recommits=%llu "
		     "rel_stuck=%llu rel_redrives=%llu local_orphans=%llu "
		     "purge_partial=%llu purge_redrives=%llu purge_pending=%d "
		     "handoff_parked=%llu",
		     ctx->local_node, (unsigned long long)ctx->ledger_grants,
		     (unsigned long long)ctx->ledger_denies,
		     (unsigned long long)ctx->ledger_imports,
		     (unsigned long long)ctx->ledger_imports_resolved,
		     (unsigned long long)ctx->ledger_import_residue,
		     (unsigned long long)ctx->ledger_imports_adopted,
		     (unsigned long long)ctx->ledger_ghosts,
		     (unsigned long long)ctx->ledger_remaster,
		     (unsigned long long)ctx->ledger_late_deliveries,
		     (unsigned long long)ctx->release_acks,
		     (unsigned long long)ctx->release_resends,
		     (unsigned long long)ctx->release_unacked,
		     (unsigned long long)ctx->ledger_release_recommits,
		     (unsigned long long)ctx->ledger_release_stuck,
		     (unsigned long long)ctx->ledger_release_redrives,
		     (unsigned long long)ctx->ledger_local_orphans,
		     (unsigned long long)ctx->ledger_purge_partial,
		     (unsigned long long)ctx->ledger_purge_redrives,
		     ctx->purge_pending_count,
		     (unsigned long long)ctx->handoff_parked);
}

/* ─── Distributed per-resource mastering ─── */

static int node_id_cmp(const void *a, const void *b)
{
	mxfs_node_id_t na = *(const mxfs_node_id_t *)a;
	mxfs_node_id_t nb = *(const mxfs_node_id_t *)b;

	if (na < nb) return -1;
	if (na > nb) return 1;
	return 0;
}

mxfs_node_id_t mxfs_dlm_resource_master(struct mxfs_dlm_ctx *ctx,
					const struct mxfs_resource_id *resource)
{
	uint32_t hash;
	mxfs_node_id_t master;

	if (!ctx || !resource)
		return 0;

	/* (step 3a): PAGE-ALIGNED mastership — every resource on one
	 * ledger page has the same master, so a page has exactly one writer.
	 * (D-0348 step 2): home_page = seeded_hash % npages with the
	 * geometry the attached ledger read from the region header.  Before the
	 * ledger is attached (CAW transport; the mount's own pre-attach window in
	 * v5_mount.c) the minimum geometry with seed 0 routes — the TCP lock
	 * paths only run after mxfs_dlm_attach_ledger. */
	hash = dlm_res_page(ctx, resource);

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);
	master = dlm_page_master_locked(ctx, hash);
	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);

	return master;
}

bool mxfs_dlm_is_resource_master(struct mxfs_dlm_ctx *ctx,
				 const struct mxfs_resource_id *resource)
{
	return mxfs_dlm_resource_master(ctx, resource) == ctx->local_node;
}

int mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx,
				 const mxfs_node_id_t *nodes, int count)
{
	mxfs_node_id_t sorted[MXFS_MAX_NODES];
	int old_count, i;
	bool changed = false;

	if (!ctx || !nodes || count <= 0 || count > MXFS_MAX_NODES)
		return -EINVAL;

	/* Sort into a temp buffer for comparison */
	memcpy(sorted, nodes, (size_t)count * sizeof(mxfs_node_id_t));
	mxfs_pal_sort(sorted, (size_t)count, sizeof(mxfs_node_id_t),
		      node_id_cmp);

	/* Remove duplicates from sorted array */
	if (count > 1) {
		int j = 0;
		for (i = 1; i < count; i++) {
			if (sorted[i] != sorted[j])
				sorted[++j] = sorted[i];
		}
		count = j + 1;
	}

	mxfs_pal_mutex_lock(ctx->active_nodes.lock);

	old_count = ctx->active_nodes.count;

	if (old_count != count) {
		changed = true;
	} else {
		for (i = 0; i < count; i++) {
			if (ctx->active_nodes.nodes[i] != sorted[i]) {
				changed = true;
				break;
			}
		}
	}

	if (changed) {
		uint64_t h = 0xcbf29ce484222325ULL;   /* FNV-1a 64 over sorted ids */

		memcpy(ctx->active_nodes.nodes, sorted,
		       (size_t)count * sizeof(mxfs_node_id_t));
		ctx->active_nodes.count = count;
		/* 0.75.20: a departing member that left the view is forgotten */
		dlm_departing_prune_locked(ctx, sorted, count);
		/* v0.11.78 (D7): my view signature — deterministic across nodes
		 * because the list is sorted.  Peers echo theirs on the lease
		 * beacon; equality proves identical mastery mapping. */
		for (i = 0; i < count; i++) {
			uint32_t id = sorted[i];
			int b;

			for (b = 0; b < 4; b++) {
				h ^= (id >> (8 * b)) & 0xff;
				h *= 0x100000001b3ULL;
			}
		}
		h ^= (uint32_t)count;
		h *= 0x100000001b3ULL;
		ctx->my_view_count = (uint32_t)count;
		ctx->my_view_hash = h;
	}

	mxfs_pal_mutex_unlock(ctx->active_nodes.lock);

	if (changed) {
		/* Mastering has shifted — purge all lock table entries */
		int purged = 0;
		mxfs_epoch_t new_epoch;

		/* stamp the change time so the grant path freezes EX grants
		 * until membership settles (no split-brain during convergence). */
		ctx->last_memb_change_ms = mxfs_pal_time_ms();

		/* ALWAYS-ON membership-count beacon.  Fires
		 * only on an actual membership change (low frequency), so it is free on
		 * the hot path.  The test harness (run.sh prep) greps the LATEST count
		 * per node and gates the workload until ALL N nodes report active_count
		 * == N — eliminating the FORMATION-RAMP split-brain (8/tcp dir_reuse MASS
		 * loss): the master = nodes[hash%count] diverges while nodes hold
		 * different counts during the 1->N ramp.  A real deployment forms the
		 * cluster before serving I/O; this beacon lets the harness establish
		 * that converged precondition. */
		mxfs_probe("mxfs: MXFS-MEMBERSHIP local=%u active_count=%d view=%#llx\n",
			ctx->local_node, count, (unsigned long long)ctx->my_view_hash);

		mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
		/*
		 * (step 3): the page-ownership generation moves with the
		 * membership; every cached ledger page and every import is stale
		 * from here (re-read from both copies on next use), and a decision
		 * or delivery made under the old generation is refused.
		 */
		ctx->view_seq++;
		ctx->ledger_gen = (ctx->my_view_hash ^ ctx->local_inc) +
				  ctx->view_seq * 0x9E3779B97F4A7C15ULL;
		if (ctx->ledger) {
			mxfs_tauth_ledger_set_owner_gen(ctx->ledger, ctx->ledger_gen);
			mxfs_tauth_ledger_set_config_id(ctx->ledger, ctx->my_view_hash);
		}
		/*
		 * (step 4): pages the new view moves away from us stop
		 * deciding NOW (frozen); the eager pass (mxfs_dlm_handoff_tick)
		 * drains and PREPAREs them to their new owners.  Pages the view
		 * hands to us are examined on first use (dlm_page_acquire).
		 * `sorted`/`count` are the new view.
		 */
		if (ctx->page_state) {
			uint32_t p;

			for (p = 0; p < ctx->page_count; p++) {
				mxfs_node_id_t owner = sorted[p % (uint32_t)count];

				if (ctx->page_state[p] == DLM_PS_MINE && owner != ctx->local_node) {
					ctx->page_state[p] = DLM_PS_FROZEN;
					ctx->handoff_scan = true;
				} else if (ctx->page_state[p] == DLM_PS_WANTED) {
					ctx->page_state[p] = DLM_PS_UNKNOWN;
				}
			}
			ctx->handoff_scan = true;   /* relays / retargets are re-examined too */
		}
		for (i = 0; i < (int)ctx->bucket_count; i++) {
			struct mxfs_lock **pp = &ctx->buckets[i];

			while (*pp) {
				struct mxfs_lock *lk = *pp;

				/*
				 * (D-0287, step 3): what THIS node holds survives
				 * the purge.  Its ledger records persist across the
				 * remaster and carry the grant id; the mirror is what lets
				 * the eventual release name them.  Master-role entries for
				 * other owners are dropped and re-imported from the
				 * ledger on the next decision (blocker import); our own
				 * queued requests are dropped and retried by
				 * fail_all_pending.  An in-flight transition (PENDING_*)
				 * is left for its finalize, which sees the generation
				 * moved and does not deliver.
				 */
				if (lk->owner == ctx->local_node &&
				    (lk->state == MXFS_LSTATE_GRANTED ||
				     lk->state == MXFS_LSTATE_CONVERTING ||
				     lk->state == MXFS_LSTATE_PENDING_DURABLE ||
				     lk->state == MXFS_LSTATE_PENDING_RELEASE)) {
					lk->imported = false;
					pp = &lk->next;
					continue;
				}
				if (lk->owner != ctx->local_node &&
				    (lk->state == MXFS_LSTATE_PENDING_DURABLE ||
				     lk->state == MXFS_LSTATE_PENDING_RELEASE)) {
					pp = &lk->next;
					continue;
				}
				*pp = lk->next;
				mxfs_pal_free(lk);
				ctx->lock_count--;
				purged++;
			}
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		/* Wake all threads sleeping in pending_wait().
		 *
		 * The lock table purge above freed all WAITING lock entries,
		 * but threads may still be blocked in pending_wait() in two
		 * scenarios:
		 *
		 * 1. Remote-master path: thread sent LOCK_REQ to a now-dead
		 *    node and is waiting for a LOCK_GRANT that will never
		 *    arrive. Without this wake-up, the thread blocks for
		 *    MXFS_LOCK_WAIT_TIMEOUT_MS (120s), causing D-state hangs.
		 *
		 * 2. Local-master path (incompatible queue): thread created
		 *    a WAITING lock entry and sent BASTs to holders that are
		 *    now dead. The WAITING entry was freed by the table purge
		 *    above, but the pending entry is still in pending_buckets.
		 *
		 * Completing with MXFS_DLM_RETRY causes mxfs_dlm_lock() to retry
		 * the request from scratch with the updated master assignment.
		 * The retry will typically succeed immediately because the
		 * surviving node is now master for all resources. */
		fail_all_pending(ctx);

		/* Advance epoch so that inode cache entries acquired under
		 * the old membership are detected as stale on next access.
		 * Without this, a node that processed the membership change
		 * later than its peers could hold a cached lock that the new
		 * master doesn't know about, causing BASTs to miss that node
		 * at 3+ nodes. */
		new_epoch = mxfs_dlm_advance_epoch(ctx);

		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "dlm: membership changed (%d->%d nodes), "
			     "purged %d stale locks, epoch=%llu",
			     old_count, count, purged,
			     (unsigned long long)new_epoch);

		/* Notify mount code to invalidate all caches, since cached
		 * lock_mode values are now stale after the table purge */
		if (ctx->membership_cb)
			ctx->membership_cb(ctx);
	}

	return changed ? 1 : 0;
}

bool mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx)
{
	if (!ctx)
		return true;

	/*
	 * FIX-K (a9a03929): LOCKLESS read.  This is the gate at the top
	 * of every hot XFS-overlay hook (buf lookup/submit/release, ilock
	 * begin/end, trans commit) — ftrace measured 2,276,687 calls in ONE
	 * single_node_paired rsync leg, all serializing on active_nodes.lock
	 * (the single-node residual vs native, ~+5%).  count is an int written
	 * only at ctx init and inside mxfs_dlm_update_active_nodes (under the
	 * mutex); a bare load is atomic on every supported arch and sees either
	 * the old or new value — indistinguishable from having taken the mutex
	 * just before/after the membership change (same race window as before).
	 * dlm_membership_settling() reads it the same lockless way.
	 */
	return ctx->active_nodes.count <= 1;
}

/*
 * sess-tcp phantom-EX detection (TCP transport).  Return the highest mode at
 * which THIS node currently holds `resource` in its LOCAL mirror (a
 * GRANTED/CONVERTING entry owned by local_node), or MXFS_LOCK_NL (0) if we
 * hold nothing.  mxfs_v5_dlm_inode_held() hardcoded 1 for the TCP transport
 * (it only ever consulted the CAW slot table), so the xfs-layer phantom-EX
 * probe — cached i_dlm_mode==EX vs. the real grant — was INERT on TCP, the
 * exact transport the 2/tcp criterion exercises.  A dir-EX fast-path that
 * trusts a stale cached EX while the grant is actually gone is the proven
 * mutual-exclusion violation (concurrent divergent-base RMW -> durable
 * dir lost-update).  Read-only walk under table_rwlock(read); cheap, no I/O.
 */
/*
 * ccloop c7ee71c6 sess21 — ATOMIC-CONTEXT-SAFE variant of
 * mxfs_dlm_held_mode.
 *
 * ROOT (proven byte-exact, 32/tcp rsync_paired, test31 + 7 more nodes):
 * mxfs_dlm_held_mode takes ctx->table_rwlock with mxfs_pal_rwlock_rdlock,
 * and in the kernel PAL that is a struct rw_semaphore.  Under contention
 * down_read() enters rwsem_down_read_slowpath -> schedule().  The sess20
 * "non-blocking" helper mxfs_v5_dlm_inode_held_nb called straight into
 * here on the TCP arm, from inside spin_lock(&pag->pag_ici_lock):
 *
 *   mxfs_pal_rwlock_rdlock <- down_read <- rwsem_down_read_slowpath <- schedule()
 *   mxfs_dlm_held_mode
 *   mxfs_v5_dlm_inode_held_nb
 *   mxfs_submit_partial_inode_write     (preempt_count 0x2)
 *   xfs_buf_submit_bio ... xfsaild
 *
 * -> "BUG: scheduling while atomic", which leaves pag_ici_lock held across
 * the schedule and corrupts preempt_count (the immediately following BUG
 * reports 0x00000000).  A peer CPU then spins on that spinlock forever:
 * test31 logged "soft lockup - CPU#2 stuck for 522s! [rsync]" with zero
 * context switches, stopped answering sshd, and never released its AG
 * grants -- so all 31 peers starved (9210 P-LKTIMEOUT-REMOTE, 8590
 * P36-RETRY) and rsync_paired never terminated.
 *
 * Fix: acquire with the trylock, which never schedules.  Returns 0 and
 * stores the held mode on success, -EWOULDBLOCK if the table was busy.
 * Callers must treat -EWOULDBLOCK as "cannot tell", never as "not held".
 */
int mxfs_dlm_held_mode_nb(struct mxfs_dlm_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint8_t *out_mode)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;

	if (!ctx || !resource || !ctx->buckets || !out_mode)
		return -EWOULDBLOCK;

	if (!mxfs_pal_rwlock_tryrdlock(ctx->table_rwlock))
		return -EWOULDBLOCK;

	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode > best)
			best = lk->mode;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	*out_mode = best;
	return 0;
}

/*
 * Is this node's claim on @resource a settled grant and nothing else?
 * Returns 1 when every entry of ours is GRANTED (at least one), 0 when we
 * have none, -EBUSY when any entry of ours is in flight (waiting, converting
 * or blocked: an acquire or conversion that must not be released under), and
 * -EWOULDBLOCK when the table was busy — never scheduling, like
 * mxfs_dlm_held_mode_nb.  The TCP stranded-AG repair uses it to tell a grant
 * the filesystem walked away from (heal it) from one still being acquired
 * (leave it alone).
 */
int mxfs_dlm_settled_grant_nb(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	int granted = 0, inflight = 0;

	if (!ctx || !resource || !ctx->buckets)
		return -EWOULDBLOCK;
	if (!mxfs_pal_rwlock_tryrdlock(ctx->table_rwlock))
		return -EWOULDBLOCK;

	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node ||
		    !resource_equal(&lk->resource, resource))
			continue;
		if (lk->state == MXFS_LSTATE_GRANTED)
			granted++;
		else
			inflight++;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (inflight)
		return -EBUSY;
	return granted ? 1 : 0;
}

uint8_t mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx,
			   const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;

	if (!ctx || !resource || !ctx->buckets)
		return MXFS_LOCK_NL;

	/*
	 *  — P191: SLEEP-IN-ATOMIC TRIPWIRE.
	 *
	 * table_rwlock is a sleeping lock, so reaching here with a spinlock
	 * held corrupts preempt state and soft-locks whichever peer CPU is
	 * spinning on that spinlock (proven: 32/tcp rsync_paired, test31
	 * rsync stuck 522 s, whole cluster starved).  That defect reached the
	 * tree twice — through a blocking SCSI read, through
	 * this rwsem — because nothing checked.  Name the caller loudly
	 * instead of wedging 500 s later somewhere unrelated.  Callers in
	 * atomic context must use mxfs_dlm_held_mode_nb.
	 */
	if (unlikely(!mxfs_pal_may_sleep())) {
		mxfs_probe_ratelimited(
		    "mxfs: P191-SLEEP-IN-ATOMIC fn=mxfs_dlm_held_mode type=%u ino=%llu ag=%u comm=%s — BLOCKING DLM query from atomic context; use mxfs_dlm_held_mode_nb\n",
		    resource->type, (unsigned long long)resource->ino,
		    resource->ag_number, dlm_cur_comm());
		return MXFS_LOCK_NL;
	}

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode > best)
			best = lk->mode;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return best;
}

/* (plan): the per-grant generation token THIS node currently holds
 * for `resource` in its local mirror — the highest-mode GRANTED/CONVERTING entry
 * owned by local_node, or 0 if none.  grant_gen is the RELIABLE (acked-TCP)
 * "did the lock change hands" signal stamped by the master on every grant
 * episode (dlm_next_gen).  The dir-EX fast path compares it to a per-inode cached
 * value to detect a tenure change without depending on the lossy DIR_MODIFY
 * eviction-ring, forcing a reload-on-reacquire before a stale-base RMW. */
uint32_t mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx,
			    const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;
	uint32_t gen = 0;

	if (!ctx || !resource || !ctx->buckets)
		return 0;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode >= best) {
			best = lk->mode;
			gen = lk->grant_gen;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return gen;
}

/* the DURABLE grant id {authority_epoch, grant_seq64} and lineage
 * of the highest-mode grant THIS node holds for `resource` (0s if none, or
 * a shared-mode grant — those carry a holder bit, not a grant id).  The
 * token the image-authority plumbing records on TCP. */
bool mxfs_dlm_grant_id(struct mxfs_dlm_ctx *ctx,
		       const struct mxfs_resource_id *resource,
		       uint64_t *auth_epoch, uint64_t *grant_seq,
		       uint64_t *lineage)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;
	bool found = false;

	*auth_epoch = 0;
	*grant_seq = 0;
	*lineage = 0;
	if (!ctx || !resource || !ctx->buckets)
		return false;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode >= best) {
			best = lk->mode;
			*auth_epoch = lk->auth_epoch;
			*grant_seq = lk->grant_seq;
			*lineage = lk->lineage;
			found = true;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return found;
}

/* FIX-1 support: the highest mode THIS node currently holds
 * for `resource` in the local mirror (MXFS_LOCK_NL if none).  Used by the
 * nested-hold admit arm in mxfs_dlm_ilock_begin to restore i_dlm_mode from
 * the mirror when an abort path left it NL while the grant is retained. */
uint8_t mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx,
			      const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;

	if (!ctx || !resource || !ctx->buckets)
		return MXFS_LOCK_NL;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode > best)
			best = lk->mode;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return best;
}

int mxfs_dlm_open_holders(struct mxfs_dlm_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint64_t *oh_out)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	int rc = -EIO;

	if (oh_out)
		*oh_out = 0;
	if (!ctx || !resource || !oh_out || !ctx->buckets)
		return -EINVAL;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (!dlm_mode_exclusive(lk->mode) || !lk->open_snap)
			continue;
		*oh_out = lk->open_holders;
		rc = 0;
		break;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	return rc;
}

/* did the EX grant THIS node currently holds for `resource` arrive as a
 * cross-node handoff?  Reads the handoff bit the master stamped on this grant
 * (delivered via the grant response / set locally on a local grant).  Returns
 * the bit for the highest-mode GRANTED/CONVERTING entry owned by local_node;
 * *gen_out (if non-NULL) gets that entry's grant_gen so the caller can consume
 * the handoff exactly once per grant episode. */
bool mxfs_dlm_grant_was_handoff(struct mxfs_dlm_ctx *ctx,
				const struct mxfs_resource_id *resource,
				uint32_t *gen_out)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;
	bool handoff = false;
	uint32_t gen = 0;

	if (gen_out)
		*gen_out = 0;
	if (!ctx || !resource || !ctx->buckets)
		return false;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode >= best) {
			best = lk->mode;
			handoff = lk->handoff;
			gen = lk->grant_gen;
		}
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	if (gen_out)
		*gen_out = gen;
	return handoff;
}

/* (design review): the MONOTONIC cross-node handoff epoch the master stamped
 * on our currently-held grant.  Returns the epoch of the highest-mode
 * GRANTED/CONVERTING entry local_node owns for `resource`, or 0 if not held. */
uint32_t mxfs_dlm_grant_dir_epoch(struct mxfs_dlm_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	uint32_t bucket;
	struct mxfs_lock *lk;
	uint8_t best = MXFS_LOCK_NL;
	uint32_t epoch = 0;

	if (!ctx || !resource || !ctx->buckets)
		return 0;

	mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
	bucket = resource_hash(resource, ctx->bucket_count);
	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (lk->owner != ctx->local_node)
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->mode > best)
			best = lk->mode;
		/* PROVEN-ROOT FIX: return the MAXIMUM dir_epoch across
		 * ALL local granted mirrors of this resource, not the last-iterated
		 * highest-mode one.  The dir_epoch is a MONOTONIC cross-node handoff
		 * counter (the master sends it correctly — P51-SENDGRANT reaches 190,
		 * never 0), but under the dir_reuse storm the local node can hold
		 * DUPLICATE granted mirrors for the same dir inode (rapid fast-path
		 * re-grants / re-affirms insert a fresh mirror whose advance-only store
		 * at dlm.c:3317 updates only the FIRST match), so the old
		 * "pick last highest-mode mirror" returned a STALE/zero epoch (P44
		 * read 0/8/22 while the master was at 190).  A zero master-epoch
		 * DISABLES every epoch-gated dir coherence guard (prior_tenure /
		 * tenure_stale / newtenure evict all require master_ep != 0) → the
		 * node RMW's a stale cached dir-data base → the dir_reuse readdir
		 * undercount (100/400 dirents durably clobbered).  Max is correct:
		 * a higher epoch strictly means a more-recent coherent handoff. */
		if (lk->dir_epoch > epoch)
			epoch = lk->dir_epoch;
	}
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	/* PROBE: P68-EVDECIDE shows cur_mep=0 dominant at the
	 * modifying node though the master computes epoch->515 (P64).  Log what the
	 * LOCAL granted lock for the storm dir actually carries — best (mode) and
	 * epoch — to see whether the local lock is absent (best=NL) or present with
	 * a stale/0 epoch.  Capped; ino 131 only. */
	/* only ZERO reads are anomalies (absent mirror when
	 * best==0, or present-with-0).  Capped, NOT ratelimited — run42's
	 * failure-moment reads were ratelimit-suppressed exactly when needed. */
	if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131 &&
	    epoch == 0) {
		static atomic_t p44ge = ATOMIC_INIT(0);
		/* cap 60000 -> 2000.  At the observed ~700/s verify-phase
		 * rate this print alone was ~6MB of serial-console traffic per run
		 * (115200 baud = 11.5KB/s) — a real pace tax.  PR-grant lookups
		 * legitimately read epoch=0 (only EX handoffs stamp it), so the
		 * bulk was noise; 2000 still covers the anomaly window per boot. */
		if ((unsigned)atomic_inc_return(&p44ge) <= 2000)
			mxfs_probe("mxfs: P44-GRANTDIREPOCH ino=131 local=%u best_mode=%u epoch=0 comm=%s\n",
				ctx->local_node, best, dlm_cur_comm());
	}
	return epoch;
}

/* ─── Epoch management ─── */

mxfs_epoch_t mxfs_dlm_advance_epoch(struct mxfs_dlm_ctx *ctx)
{
	mxfs_epoch_t epoch;

	if (!ctx)
		return 0;

	mxfs_pal_mutex_lock(ctx->epoch_lock);
	ctx->current_epoch++;
	epoch = ctx->current_epoch;
	mxfs_pal_mutex_unlock(ctx->epoch_lock);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm: epoch advanced to %llu",
		     (unsigned long long)epoch);
	return epoch;
}

mxfs_epoch_t mxfs_dlm_get_epoch(struct mxfs_dlm_ctx *ctx)
{
	mxfs_epoch_t epoch;

	if (!ctx)
		return 0;

	mxfs_pal_mutex_lock(ctx->epoch_lock);
	epoch = ctx->current_epoch;
	mxfs_pal_mutex_unlock(ctx->epoch_lock);

	return epoch;
}

/* ─── DOUBLE-GRANT detector (instrumentation only) ───
 *
 * Tracks current EX holders for INODE resources in a small shadow table,
 * SEPARATE from the lock table (the lock table entry is exactly what gets
 * removed by an administrative removal — convblk/stale/conversion-blocked —
 * leaving a "ghost" holder that the table can no longer show).  The shadow is
 * SET on every EX grant the master dispatches and CLEARED only on a GENUINE
 * release (process_remote_release / mxfs_dlm_unlock) — NOT on administrative
 * removals.  At each EX grant we check for an existing active EX held by a
 * DIFFERENT node on the same resource: that is a true double-grant (two nodes
 * hold EX concurrently), the proven 2/tcp shortform-dir lost-update root.
 *
 * ALL callers hold ctx->table_rwlock (write), so the shadow is consistent with
 * no new lock and no ordering risk.  A bookkeeping miss only mislogs — it can
 * never wedge the DLM.  Master-side only: the master is the single arbiter for
 * a resource, so its shadow captures every grant for the resources it masters
 * (the dir inode is mastered by one node, which is where the check fires). */
/* dg_grant_ex/dg_release LINEAR-SCAN this table per grant, so it
 * must stay small (enlarging to 16384 caused O(N)-per-grant acquire timeouts).
 * The bug it had at 512 was EVICTION POLICY, not size: it recycled the FIRST
 * inactive slot, so the HOT shared dir inode's briefly-inactive slot was evicted
 * by the ~800 file-inode grants between two of its grants — LOSING last_owner
 * (handoff under-fires ~80% on TCP) and resetting epoch to 0.  Fixed by LRU
 * eviction (evict the least-recently-GRANTED inactive slot): the dir inode is
 * granted ~800×/round (every file create takes the parent-dir EX), so its
 * last_grant_seq is always near the top → never the LRU victim → never evicted. */
#define DG_SHADOW_N 8192	/* 512->8192.  The 8-node x 100-file storm
				 * grants 800+ distinct inodes/round; at 512 the
				 * shadow table can overflow (no empty/inactive slot)
				 * so dg_grant_ex records nothing -> epoch_out=0 ->
				 * cur_mep=0 -> acquire-side coherency evict inert.
				 * A/B for the dir_epoch=0 root. */
struct dg_shadow_ent {
	struct mxfs_resource_id res;
	mxfs_node_id_t          owner;       /* current active EX owner */
	mxfs_node_id_t          last_owner;  /* most-recent EX owner,
										  * RETAINED across release so the next
										  * grant can tell same-node re-grant
										  * (no handoff) from cross-node handoff */
	uint32_t                gen;
	uint32_t                epoch;       /* (design review): MONOTONIC count of
										  * cross-node EX handoffs for this resource.
										  * Bumped in dg_grant_ex whenever handoff is
										  * computed true.  Stamped on every grant and
										  * compared level-triggered by the grantee. */
	bool                    active;
	bool                    used;        /* slot ever populated (res +
										  * last_owner valid even when !active) */
	uint64_t                last_grant_seq; /* monotonic seq of this slot's
										  * most recent grant — for LRU eviction so a
										  * HOT resource (frequently re-granted) is
										  * never recycled out from under its peers */
	uint64_t                grant_count; /* total EX grants this slot's
										  * resource has received.  Eviction prefers the
										  * COLDEST (lowest grant_count) inactive slot, so
										  * the hot shared-dir inode (granted ~800x/round)
										  * is NEVER evicted while cold file inodes
										  * (granted 1-2x) are — preserving the dir's
										  * handoff epoch reliably (LRU-by-seq alone let a
										  * briefly-inactive hot dir be evicted, resetting
										  * its epoch to 0 -> dir_reuse flaky clobber). */
};
static struct dg_shadow_ent dg_shadow[DG_SHADOW_N];
static uint64_t dg_shadow_grant_seq;     /* ++ on every dg_grant_ex (under
										  * table_rwlock write — already held) */

/* Caller holds ctx->table_rwlock.  Record that `owner` was granted EX on
 * `res`; first flag any pre-existing active EX held by a different node.
 *
 * RETURNS the HANDOFF bit: true iff a DIFFERENT node was the most-recent
 * EX owner of `res` (last_owner != owner).  This is the reliable acked-protocol
 * "the dir base changed under us" signal the XFS reload layer needs — far
 * better than grant_gen (which bumps on benign same-node re-grants) and the
 * lossy DIR_MODIFY evict-ring (which drops messages on TCP).  last_owner is
 * RETAINED across dg_release so a release+reacquire by the same node with no
 * peer in between correctly reports NO handoff (no resurrection). */
static bool dg_grant_ex(struct mxfs_dlm_ctx *ctx,
			const struct mxfs_resource_id *res,
			mxfs_node_id_t owner, uint32_t gen,
			uint32_t *epoch_out)
{
	int i, empty = -1, evict = -1, mine = -1;
	uint64_t evict_seq = 0;	/* last_grant_seq of the current LRU victim */
	uint64_t evict_gc = 0;	/* grant_count of the current victim (coldest-first) */
	bool handoff = false;

	if (epoch_out)
		*epoch_out = 0;
	if (res->type != MXFS_LTYPE_INODE)
		return false;

	/* SPLIT-BRAIN MASTERSHIP probe: recompute the master LOCKLESSLY
	 * (plain reads — a torn read only mislogs a diagnostic, never wedges; no
	 * new lock so no ordering risk vs the held table_rwlock).  This node only
	 * reaches a master-side EX grant for a resource it believed it mastered;
	 * if it is NOT the master NOW, mastership flipped under it (membership
	 * flap) → two nodes can be master at once → concurrent EX that the
	 * per-node P-DOUBLEGRANT cannot see.  Decisive for the flap hypothesis. */
	{
		int cnt = ctx->active_nodes.count;
		if (cnt > 0) {
			uint32_t h = dlm_res_page(ctx, res);   /* page-aligned */
			mxfs_node_id_t m = ctx->active_nodes.nodes[h % (uint32_t)cnt];
			if (m != ctx->local_node)
				mxfs_probe_ratelimited(
				    "mxfs: P-STALEMASTER-GRANT ino=%llu owner=%u "
				    "local=%u computed_master=%u active_count=%d\n",
				    (unsigned long long)res->ino, owner,
				    ctx->local_node, m, cnt);
		}
	}

	for (i = 0; i < DG_SHADOW_N; i++) {
		if (dg_shadow[i].used && resource_equal(&dg_shadow[i].res, res)) {
			mine = i;
			/* Double-grant: a DIFFERENT node still holds an ACTIVE EX. */
			if (dg_shadow[i].active && dg_shadow[i].owner != owner) {
				mxfs_probe_ratelimited(
				    "mxfs: P-DOUBLEGRANT ino=%llu type=%u "
				    "owner_existing=%u gen_existing=%u "
				    "owner_new=%u gen_new=%u\n",
				    (unsigned long long)res->ino, res->type,
				    dg_shadow[i].owner, dg_shadow[i].gen,
				    owner, gen);
				/* (instrumented): dump the master's live lock chain for this
				 * resource at the double-grant instant.  If the prior EX owner
				 * has a GRANTED chain entry here, the compat check is buggy
				 * (it should have queued+BAST'd); if NO chain entry for it,
				 * the shadow and the chain have desynced (the chain entry was
				 * removed without a matching dg_release) — pinpoints which. */
				{
					uint32_t b = resource_hash(res, ctx->bucket_count);
					struct mxfs_lock *cl;
					int nh = 0;
					for (cl = ctx->buckets[b]; cl; cl = cl->next) {
						if (!resource_equal(&cl->resource, res))
							continue;
						nh++;
						mxfs_probe_ratelimited(
						    "mxfs: P48-DG-CHAIN ino=%llu holder=%u mode=%s state=%s grant_gen=%u\n",
						    (unsigned long long)res->ino, cl->owner,
						    mode_name(cl->mode),
						    (cl->state < 5 ? lock_state_names[cl->state] : "?"),
						    cl->grant_gen);
					}
					if (nh == 0)
						mxfs_probe_ratelimited(
						    "mxfs: P48-DG-CHAIN ino=%llu EMPTY (no chain entry — shadow/chain desync)\n",
						    (unsigned long long)res->ino);
				}
			}
			break;
		}
		if (!dg_shadow[i].used) {
			if (empty < 0)
				empty = i;
		} else if (!dg_shadow[i].active) {
			/* evict the COLDEST inactive slot — lowest
			 * grant_count first, breaking ties by oldest last_grant_seq.  A hot
			 * resource (the shared dir, granted ~800x/round) has a huge
			 * grant_count so it is NEVER the victim even when briefly inactive
			 * between its rapid grants; cold file inodes (granted 1-2x) are
			 * evicted instead.  Pure LRU-by-seq let a briefly-inactive hot dir
			 * be evicted by the ~800 file-inode grants between two of its grants
			 * -> epoch reset to 0 -> dir_reuse durable clobber (flaky). */
			if (evict < 0 ||
			    dg_shadow[i].grant_count < evict_gc ||
			    (dg_shadow[i].grant_count == evict_gc &&
			     dg_shadow[i].last_grant_seq < evict_seq)) {
				evict = i;
				evict_seq = dg_shadow[i].last_grant_seq;
				evict_gc = dg_shadow[i].grant_count;
			}
		}
	}
	if (mine >= 0) {
		/* HANDOFF iff the prior EX owner was a different node.  last_owner==0
		 * means never granted (shouldn't happen for a used slot) -> no handoff. */
		handoff = (dg_shadow[mine].last_owner != 0 &&
			   dg_shadow[mine].last_owner != owner);
		/* instrumented under-fire probe: the grantee logs
		 * P51-HANDOFF-UNDERFIRE (grant_gen advanced but ho=FALSE).  Capture the
		 * master's computation INPUTS so we see WHY handoff is false on a real
		 * cross-node handoff: stale last_owner (==owner) vs active_b4=1 (grant
		 * while prior owner still ACTIVE = a re-grant w/o intervening release =
		 * dg_release missed) vs a NEWSLOT (mine<0, eviction). storm dir only. */
		if (res->ino <= 256 && res->type == MXFS_LTYPE_INODE) {
			static atomic_t pdgex = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdgex) <= 6000)
				mxfs_probe("mxfs: P-DGEX ino=%llu owner=%u last_owner=%u active_b4=%d gen=%u handoff=%d epoch=%u\n",
					(unsigned long long)res->ino, owner,
					dg_shadow[mine].last_owner,
					dg_shadow[mine].active ? 1 : 0, gen,
					handoff ? 1 : 0, dg_shadow[mine].epoch);
		}
		/* (design review): a cross-node handoff advances the MONOTONIC
		 * per-resource epoch.  The grantee compares this absolute value against
		 * its valid_epoch (level-triggered), so even if it missed intermediate
		 * handoffs (served fast-path, or a one-shot signal was consumed
		 * elsewhere) it still observes epoch > valid_epoch and refreshes its
		 * stale dir base exactly once. */
		if (handoff) {
			dg_shadow[mine].epoch++;
			mxfs_probe_ratelimited(
			    "mxfs: P64-MASTER-HANDOFF ino=%llu owner=%u last_owner=%u gen=%u epoch=%u\n",
			    (unsigned long long)res->ino, owner,
			    dg_shadow[mine].last_owner, gen, dg_shadow[mine].epoch);
		}
		if (epoch_out)
			*epoch_out = dg_shadow[mine].epoch;
		dg_shadow[mine].owner = owner;
		dg_shadow[mine].last_owner = owner;
		dg_shadow[mine].gen = gen;
		dg_shadow[mine].active = true;
		dg_shadow[mine].last_grant_seq = ++dg_shadow_grant_seq;	/* LRU */
		dg_shadow[mine].grant_count++;	/* hot-slot eviction immunity */
	} else {
		/* First grant we've recorded for this resource.  Prefer a never-used
		 * slot; else recycle an inactive (released) slot — recycling loses that
		 * resource's last_owner, but the inode whose last_owner is lost simply
		 * reports "no handoff" next time (conservative: no false adopt). */
		int slot = (empty >= 0) ? empty : evict;
		if (slot >= 0) {
			dg_shadow[slot].res = *res;
			dg_shadow[slot].owner = owner;
			dg_shadow[slot].last_owner = owner;
			dg_shadow[slot].gen = gen;
			/* REVERTED epoch-never-0 (was =1) — it made new_tenure
			 * fire SPURIOUSLY in the first tenure (cur_mep=1 != evict_mep=0),
			 * so P34-NEWTENURE-RETIRE retired in-AIL UNDESTAGED BLIs that were
			 * THIS tenure's own un-landed creates (Inv 1 only holds at RELEASE,
			 * not mid-tenure) → readdir=0 catastrophe (proven keeper run iter1
			 * round2 readdir=0).  Fresh resource restarts epoch at 0 = the
			 * grantee operates in the untracked regime but never spuriously
			 * force-retires its own work.  The real fix is release-side
			 * ordered publish (design review), not making new_tenure over-fire. */
			dg_shadow[slot].epoch = 0;
			dg_shadow[slot].active = true;
			dg_shadow[slot].used = true;
			dg_shadow[slot].last_grant_seq = ++dg_shadow_grant_seq;	/* LRU */
			dg_shadow[slot].grant_count = 1;	/* fresh resource */
		}
		if (epoch_out)
			*epoch_out = 0;	/* REVERTED to 0 (epoch-never-0 caused readdir=0) */
		/* Unknown prior owner -> NOT a handoff (avoid false adopt/resurrection). */
		handoff = false;
		if (res->ino <= 256 && res->type == MXFS_LTYPE_INODE) {
			static atomic_t pdgn = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdgn) <= 6000)
				mxfs_probe("mxfs: P-DGEX-NEWSLOT ino=%llu owner=%u slot=%d (no prior dg_shadow -> handoff FORCED false; eviction/first-grant under-fire?)\n",
					(unsigned long long)res->ino, owner, slot);
		}
	}
	return handoff;
}

/* Caller holds ctx->table_rwlock.  Genuine release of `res` by `owner`. */
static void dg_release(const struct mxfs_resource_id *res, mxfs_node_id_t owner)
{
	int i;

	if (res->type != MXFS_LTYPE_INODE)
		return;
	for (i = 0; i < DG_SHADOW_N; i++) {
		if (dg_shadow[i].active && dg_shadow[i].owner == owner &&
		    resource_equal(&dg_shadow[i].res, res)) {
			dg_shadow[i].active = false;
			return;
		}
	}
}

/* ─── Remote request processing ─── */

int mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx,
				    mxfs_node_id_t sender,
				    const struct mxfs_dlm_lock_req *req)
{
	const struct mxfs_resource_id *resource;
	uint8_t mode;
	uint32_t flags;
	mxfs_epoch_t request_epoch;
	uint32_t bucket;
	struct mxfs_lock *chain, *lk;
	struct mxfs_lock *newlk;
	int compat;
	uint64_t ledger_gen = 0;
	struct dlm_grant_ids deny_ids;

	if (!ctx || !req || req->mode >= MXFS_LOCK_MODE_COUNT)
		return -EINVAL;
	resource = &req->resource;
	mode = req->mode;
	flags = req->flags;
	request_epoch = req->hdr.epoch;
	memset(&deny_ids, 0, sizeof(deny_ids));
	deny_ids.req_id = req->req_id;

	/* DLM_TRACE: log remote request entry for inode 128 */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: process_remote_request ENTRY ino=128 "
			     "sender=%u requested_mode=%s flags=0x%x "
			     "local_node=%u",
			     sender, mode_name(mode), flags, ctx->local_node);

	bucket = resource_hash(resource, ctx->bucket_count);

	/* not the page master under the current membership -> the
	 * requester must re-route (its own view lags or led); never decide. */
	if (mxfs_dlm_resource_master(ctx, resource) != ctx->local_node) {
		uint32_t vc = 0;
		uint64_t vh = mxfs_dlm_get_view_sig(ctx, &vc);

		ctx->ledger_remaster++;
		/* (D-0345 instrumented): name the disagreement — the sender's
		 * view routed here, ours names another master */
		mxfs_probe_ratelimited(
			     "mxfs: P-TAUTH-REMASTER-VIEW type=%u ino=%llu ag=%u sender=%u "
			     "my_master=%u view=%#llx/%u\n",
			     resource->type, (unsigned long long)resource->ino,
			     resource->ag_number, sender,
			     mxfs_dlm_resource_master(ctx, resource),
			     (unsigned long long)vh, vc);
		send_grant(ctx, sender, resource, MXFS_LOCK_NL, MXFS_ERR_REMASTER,
			   MXFS_MSG_LOCK_DENY, request_epoch, 0, 0, 0, &deny_ids);
		return -EREMOTE;
	}
	/* page current + blockers imported before any decision */
	{
		int prc = dlm_ledger_prepare(ctx, resource, &ledger_gen);

		if (prc) {
			if (prc == -EAGAIN) {
				uint32_t pg = dlm_res_page(ctx, resource);
				struct mxfs_tauth_page_auth a;
				int arc = ctx->ledger ?
					  mxfs_tauth_ledger_page_auth(ctx->ledger, pg, false, &a) : -ENOENT;

				/* (D-0345 instrumented): we ARE the master under our view
				 * but the page is not ours to decide on — say why */
				mxfs_probe_ratelimited(
					     "mxfs: P-TAUTH-REMASTER-PARKED type=%u ino=%llu ag=%u page=%u "
					     "sender=%u page_state=%u cached_auth=%d/%u/%llu st=%u "
					     "target=%u/%llu\n",
					     resource->type, (unsigned long long)resource->ino,
					     resource->ag_number, pg, sender,
					     ctx->page_state ? ctx->page_state[pg] : 255, arc,
					     arc == 0 ? a.auth_node : 0,
					     arc == 0 ? (unsigned long long)a.auth_inc : 0ULL,
					     arc == 0 ? a.state : 0,
					     arc == 0 ? a.target_node : 0,
					     arc == 0 ? (unsigned long long)a.target_inc : 0ULL);
			}
			/*
			 * 0.84.5 (D-...-0960): the page is under a dead authority a
			 * live bootstrap (this node, or the one this node asked) is
			 * taking over.  Answer that by name, with this node's takeover
			 * count in grant_gen, so the requester waits on progress
			 * instead of spending 60 retries on REMASTER (18 s, s588b).
			 */
			if (prc == -EINPROGRESS) {
				uint64_t prog = dlm_bootstrap_node(ctx) == ctx->local_node ?
						ctx->takeover_pages_done : ctx->transition_progress_rx;

				ctx->transition_answers++;
				mxfs_probe_ratelimited(
				    "mxfs: P960-AUTH-TRANSITION-TX type=%u ino=%llu ag=%u page=%u "
				    "sender=%u progress=%llu bootstrap=%d — the page's dead authority "
				    "is being taken over; answering AUTH_TRANSITION, not REMASTER\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, dlm_res_page(ctx, resource), sender,
				    (unsigned long long)prog,
				    dlm_bootstrap_node(ctx) == ctx->local_node ? 1 : 0);
				send_grant(ctx, sender, resource, MXFS_LOCK_NL,
					   MXFS_ERR_AUTH_TRANSITION, MXFS_MSG_LOCK_DENY,
					   request_epoch, (uint32_t)prog, 0, 0, &deny_ids);
				return prc;
			}
			send_grant(ctx, sender, resource, MXFS_LOCK_NL,
				   prc == -EAGAIN ? MXFS_ERR_REMASTER : MXFS_ERR_LEDGER,
				   MXFS_MSG_LOCK_DENY, request_epoch, 0, 0, 0, &deny_ids);
			return prc;
		}
	}

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	chain = ctx->buckets[bucket];

	/*
	 * A request for an acquisition its sender has already abandoned: a
	 * re-send still in flight when the CANCEL was processed, or one a
	 * transport reconnect replayed.  Queueing it would recreate a waiter
	 * nobody is waiting on; granting it would mint a grant nobody installs.
	 * Refuse it by name.
	 */
	if (req->acq_seq &&
	    dlm_cancel_tombstoned(ctx, sender, req->owner_inc, req->acq_seq)) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		ctx->cancel_resend_refused++;
		pr_warn_ratelimited(
		    "mxfs: P958-CANCEL-RESEND-REFUSED acq=%llu type=%u ino=%llu ag=%u from=%u mode=%s total=%llu — a request for an acquisition its sender already abandoned; refused, nothing queued\n",
		    (unsigned long long)req->acq_seq, resource->type,
		    (unsigned long long)resource->ino, resource->ag_number, sender,
		    mode_name(mode), (unsigned long long)ctx->cancel_resend_refused);
		/* Answered with SILENCE, deliberately: the sender is not waiting
		 * for this acquisition any more, and a DENY would complete
		 * whatever pending entry it has on this resource NOW — its next
		 * acquisition — with an error that belongs to the old one. */
		return -ECANCELED;
	}
	/*
	 * 0.84.13: a request for an acquisition whose grant its sender already
	 * took and released (the release said acq_done).  A re-send that left
	 * before the grant arrived and lands here after the release used to be
	 * queued as a fresh request — the sender's entry was gone — and, when
	 * compatible, granted at once to a wait that no longer existed; the
	 * requester bounced it (P958-ACQ-GRANT-BOUNCED, s594c).  Refuse it by
	 * name, with the same silence as a cancelled one.
	 */
	if (req->acq_seq && !READ_ONCE(mxfs_dl_no_consumed_tomb) &&
	    dlm_consumed_tombstoned(ctx, sender, req->owner_inc, req->acq_seq)) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		ctx->consumed_resend_refused++;
		pr_warn_ratelimited(
		    "mxfs: P958-CONSUMED-RESEND-REFUSED acq=%llu type=%u ino=%llu ag=%u from=%u mode=%s total=%llu — a re-send of an acquisition whose grant its sender already took and released; refused, nothing queued\n",
		    (unsigned long long)req->acq_seq, resource->type,
		    (unsigned long long)resource->ino, resource->ag_number, sender,
		    mode_name(mode), (unsigned long long)ctx->consumed_resend_refused);
		return -ECANCELED;
	}

	/* DLM_TRACE: dump all existing holders for inode 128 */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE) {
		int holder_idx = 0;
		for (lk = chain; lk; lk = lk->next) {
			if (resource_equal(&lk->resource, resource))
				mxfs_pal_log(MXFS_LOG_DEBUG,
				    "DLM_TRACE: process_remote_request EXISTING "
				    "ino=128 [%d] owner=%u mode=%s state=%s",
				    holder_idx++, lk->owner,
				    mode_name(lk->mode), state_name(lk->state));
		}
		if (holder_idx == 0)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "DLM_TRACE: process_remote_request EXISTING "
			    "ino=128 (none)");
	}

	/* Check for existing lock from same sender — handle conversion */
	for (lk = chain; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == sender) {
			if (lk->state == MXFS_LSTATE_WAITING ||
			    lk->state == MXFS_LSTATE_BLOCKED) {
				uint8_t old_state = lk->state;

				/*
				 * A RE-SEND OF A WAIT THIS ENTRY ALREADY SERVES.
				 *
				 * The requester's one-second pending_wait expiring means
				 * "no answer yet", not "that request is gone": the acquire
				 * above it re-sends the SAME logical acquisition, and says
				 * so in acq_seq.  Keep the entry.  It keeps its position in
				 * this chain and it keeps queued_at, so its age stays the
				 * age of the WAIT rather than the age of the last re-send —
				 * and nothing downstream that orders waiters or reports
				 * their age is reset once a second.
				 *
				 * The old code freed this entry and inserted another one on
				 * every re-send, which also re-fired a blocking
				 * notification at the holder each time.  Measured on 2
				 * nodes / TCP: 238 notifications at a holder in a single
				 * 244 s release drain, for ONE requester's wait.  A
				 * notification can still be lost, so re-sends still recover
				 * one — but on their own interval, not on the re-send
				 * cadence.
				 *
				 * Identity is {acq_seq, owner_inc, mode} and all three must
				 * match: a different incarnation of the requester is a
				 * different node-lifetime, and a different mode is a
				 * different request that must never inherit this one's
				 * name.  Anything that does not match falls through to the
				 * original replace-and-requeue.
				 */
				if (req->acq_seq && lk->acq_seq == req->acq_seq &&
				    lk->owner_inc == req->owner_inc &&
				    lk->mode == mode) {
					struct mxfs_bast_record rx_recs[MXFS_MAX_BAST_RECORDS];
					struct dlm_grant_ids rx_ids;
					uint8_t rx_hold = MXFS_LOCK_NL;
					uint64_t nowms = mxfs_pal_time_ms();
					uint64_t age, retx, kept, rqd;
					int rx_n = 0, refire;
					struct mxfs_lock *ok2;

					lk->req_id = req->req_id;
					lk->request_epoch = request_epoch;
					lk->acq_last_ms = nowms;
					lk->acq_retx++;
					ctx->acq_retx_kept++;
					retx = lk->acq_retx;
					kept = ctx->acq_retx_kept;
					rqd = ctx->acq_requeued;
					age = nowms >= lk->queued_at ? nowms - lk->queued_at : 0;
					refire = (nowms >= lk->acq_bast_ms) &&
						 (nowms - lk->acq_bast_ms >=
						  MXFS_DLM_ACQ_BAST_REFIRE_MS);

					/* The blocking holder's mode is needed for the receipt
					 * whether or not a notification is re-fired, and is
					 * only readable under the table lock. */
					for (ok2 = chain; ok2; ok2 = ok2->next) {
						if (!resource_equal(&ok2->resource, resource))
							continue;
						if (ok2->state != MXFS_LSTATE_GRANTED)
							continue;
						if (ok2->owner == MXFS_DLM_NODE_UNKNOWN)
							continue;
						if (lock_compat[ok2->mode][mode])
							continue;
						if (rx_hold == MXFS_LOCK_NL)
							rx_hold = ok2->mode;
						if (refire && rx_n < MXFS_MAX_BAST_RECORDS) {
							rx_recs[rx_n].owner = ok2->owner;
							rx_recs[rx_n].requested_mode = mode;
							rx_n++;
						}
					}
					if (refire)
						lk->acq_bast_ms = nowms;
					if (refire && rx_n)
						ctx->acq_bast_refire++;
					mxfs_pal_rwlock_unlock(ctx->table_rwlock);

					/* Budgeted print, but every line carries the mount's
					 * true totals — a reader must never take the number of
					 * lines for the number of re-sends. */
					if (retx <= 8 || (retx % 64) == 0)
						mxfs_probe(
						    "mxfs: P958-ACQ-RETX acq=%llu type=%u ino=%llu ag=%u from=%u mode=%s retx=%llu kept_total=%llu requeued_total=%llu wait_age_ms=%llu refired=%d — re-send of a wait already queued here; entry and queue position kept\n",
						    (unsigned long long)req->acq_seq,
						    resource->type,
						    (unsigned long long)resource->ino,
						    resource->ag_number, sender, mode_name(mode),
						    (unsigned long long)retx,
						    (unsigned long long)kept,
						    (unsigned long long)rqd,
						    (unsigned long long)age,
						    (refire && rx_n) ? 1 : 0);

					memset(&rx_ids, 0, sizeof(rx_ids));
					rx_ids.req_id = req->req_id;
					send_grant(ctx, sender, resource, rx_hold, MXFS_OK,
						   MXFS_MSG_LOCK_QUEUED, request_epoch,
						   0, 0, 0, &rx_ids);
					if (refire && rx_n)
						fire_bast_records(ctx, resource, rx_recs, rx_n);
					return -EINPROGRESS;
				}
				ctx->acq_requeued++;
				/* Stale entry from a previous timed-out request.
				 * The remote node's pending_wait expired and it
				 * retried, but we still have the old WAITING lock.
				 * Remove it and fall through to re-queue fresh. */
				struct mxfs_lock **pp = &ctx->buckets[bucket];
				while (*pp) {
					if (*pp == lk) {
						*pp = lk->next;
						lock_free(lk);
						ctx->lock_count--;
						break;
					}
					pp = &(*pp)->next;
				}
				chain = ctx->buckets[bucket];
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "dlm: removed stale %s entry for "
					     "node %u on retry",
					     state_name(old_state), sender);
				goto remote_check_compat;
			}
			/* the sender's grant / release is mid-transition —
			 * the committing thread delivers (grant) or the sender's
			 * retry lands after the ACK (release).  Decide nothing. */
			if (lk->state == MXFS_LSTATE_PENDING_DURABLE ||
			    lk->state == MXFS_LSTATE_PENDING_RELEASE) {
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				return -EINPROGRESS;
			}
			if (lk->state == MXFS_LSTATE_GRANTED) {
				/* Bug 51: always verify the existing grant is safe
				 * before taking the "already granted" shortcut.
				 *
				 * Race condition: the sender's LOCK_REQ can arrive at
				 * the master BEFORE a preceding LOCK_RELEASE when
				 * mxfs_dlm_unlock (BAST handler, recv thread) and
				 * mxfs_dlm_lock (new request, main thread) race for
				 * the peer send_lock. When the LOCK_REQ arrives first,
				 * the master finds the sender's OLD GRANTED entry and
				 * returns "already granted" without checking for
				 * conflicts. The subsequent LOCK_RELEASE removes the
				 * old entry, leaving the master with no record of the
				 * sender's grant while the sender believes it has EX
				 * — both nodes hold EX simultaneously and BASTs stop.
				 *
				 * Fix: check that no other node has a conflicting
				 * GRANTED lock AND no other node has a WAITING/BLOCKED
				 * request. The WAITING check catches the common case:
				 * another node requested the lock, got queued behind
				 * the sender's old grant, and is waiting for the BAST
				 * release cycle. Sending "already granted" would
				 * short-circuit that cycle, leaving both nodes with
				 * effective EX access. */
				if (lk->mode >= mode) {
					/*
					 * sess-tcp DOUBLE-GRANT FIX (replaces the Bug-51
					 * still_safe re-affirm + the stale-removal+promote
					 * branch).  The sender ALREADY HOLDS a grant of
					 * sufficient mode.  This re-request is its -ETIMEDOUT
					 * retry (the original grant was slow), or a re-acquire
					 * whose LOCK_REQ raced ahead of its LOCK_RELEASE.  The
					 * OLD code removed the holder's entry and promoted a
					 * conflicting waiter whenever a waiter existed — but
					 * the holder did NOT release (it has the grant cached),
					 * so promoting the waiter created a SECOND EX holder:
					 * the PROVEN tcp_dlm_scaling double-grant.
					 *
					 * Correct behaviour: ALWAYS RE-AFFIRM — keep the
					 * holder's entry, stamp a FRESH generation (a new grant
					 * episode), and re-send the grant.  NEVER remove +
					 * promote a waiter here.  Any waiter stays queued with
					 * its BAST and is promoted only when the holder
					 * genuinely releases (process_remote_release).
					 *
					 * Bug-51 (release-in-flight) stays fixed by the gen:
					 * if the sender had released the OLD grant and is
					 * re-acquiring, the stale LOCK_RELEASE that follows
					 * carries the OLD gen; process_remote_release ignores
					 * it on gen-mismatch, so it can neither drop this
					 * re-affirmed entry nor promote a conflicting waiter.
					 */
					uint32_t gen = lk->grant_gen = dlm_next_gen(ctx);
					uint8_t reaff_mode = lk->mode;
					struct mxfs_bast_record pg_rec;
					int pg = collect_grantee_bast_if_waiters(
					    chain, resource, sender, reaff_mode, &pg_rec);
					uint8_t ho = 0;
					uint32_t de = 0;
					struct dlm_grant_ids ids;

					/* the record is already durable (a live entry
					 * or a ledger-imported one for this very owner — the
					 * ruling's idempotent retry / ghost return): re-affirm
					 * carries the SAME grant id, no page write.  The
					 * requester's identity must match the record's. */
					if (lk->owner_inc && req->owner_inc &&
					    lk->owner_inc != req->owner_inc) {
						mxfs_pal_rwlock_unlock(ctx->table_rwlock);
						mxfs_pal_log(MXFS_LOG_ERR,
							     "mxfs: P-TAUTH-INC-MISMATCH sender=%u ino=%llu type=%u "
							     "record_inc=%llu req_inc=%llu — refused",
							     sender, (unsigned long long)resource->ino,
							     resource->type,
							     (unsigned long long)lk->owner_inc,
							     (unsigned long long)req->owner_inc);
						send_grant(ctx, sender, resource, MXFS_LOCK_NL,
							   MXFS_ERR_LEDGER, MXFS_MSG_LOCK_DENY,
							   request_epoch, 0, 0, 0, &deny_ids);
						return -EPERM;
					}
					lk->imported = false;
					lk->req_id = req->req_id;
					/* The entry now serves THIS acquisition: a CANCEL
					 * naming the previous one must not retire it. */
					lk->acq_seq = req->acq_seq;
					if (!lk->owner_inc)
						lk->owner_inc = req->owner_inc;
					if (!lk->owner_slot)
						lk->owner_slot = req->owner_slot;
					ids.auth_epoch = lk->auth_epoch;
					ids.grant_seq = lk->grant_seq;
					ids.lineage = lk->lineage;
					ids.req_id = req->req_id;
					/*
					 * 0.89.1 (D-0977): the re-affirm carries the SAME
					 * open-holder snapshot as the grant it re-affirms —
					 * the chain entry's mask, stamped from the record at
					 * the commit (finalize) or the import.  Measured
					 * s64a: this field was left unassigned, the re-affirm
					 * delivered a zero mask on the exclusive re-grant the
					 * unlinker's certify re-acquire triggers, the holder's
					 * mirror adopted it, and the free-or-defer guard read
					 * "no peer holds it open" for a file the peer had two
					 * descriptors on.
					 */
					ids.open_holders = lk->open_holders;
					P_LKT("REAFFIRM-REMOTE", resource, sender, lk->mode);
					if (lk->mode == MXFS_LOCK_EX) {
						ho = lk->handoff =
						    dg_grant_ex(ctx, resource, sender, gen, &de);
						lk->dir_epoch = de;
					}
					mxfs_pal_rwlock_unlock(ctx->table_rwlock);
					send_grant(ctx, sender, resource, reaff_mode,
						   0, MXFS_MSG_LOCK_GRANT,
						   request_epoch, gen, ho, de, &ids);
					if (pg) {
						mxfs_probe_ratelimited(
						    "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u mode=%s site=remote-reaffirm\n",
						    (unsigned long long)resource->ino,
						    sender, mode_name(reaff_mode));
						fire_bast_records(ctx, resource, &pg_rec, 1);
					}
					return 0;
				}

				/* Upgrade: check compat with others */
				{
					struct mxfs_lock *other;
					int conv_compat = 1;

					for (other = chain; other; other = other->next) {
						if (other == lk)
							continue;
						if (!resource_equal(&other->resource, resource))
							continue;
						if (!lk_is_holder(other))
							continue;
						if (!lock_compat[other->mode][mode]) {
							conv_compat = 0;
							break;
						}
					}
					if (conv_compat) {
						/* upgrade = ledger transition; the old
						 * mode is restored if it is refused */
						uint8_t prev_mode = lk->mode;
						uint32_t prev_gen = lk->grant_gen;
						struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
						int grc;

						if (!txn) {
							mxfs_pal_rwlock_unlock(ctx->table_rwlock);
							return -ENOMEM;
						}
						dlm_txn_init(txn, resource, ledger_gen);
						lk->mode = mode;
						lk->grant_gen = dlm_next_gen(ctx);
						lk->state = MXFS_LSTATE_PENDING_DURABLE;
						lk->request_epoch = request_epoch;
						lk->req_id = req->req_id;
						lk->imported = false;
						if (!lk->owner_inc)
							lk->owner_inc = req->owner_inc;
						if (!lk->owner_slot)
							lk->owner_slot = req->owner_slot;
						lk->decide_gen = ledger_gen;
						if (mode == MXFS_LOCK_EX)
							lk->handoff = dg_grant_ex(ctx, resource, sender,
										  lk->grant_gen,
										  &lk->dir_epoch);
						dlm_txn_add_grant(txn, lk, prev_mode, prev_gen, false);
						mxfs_pal_rwlock_unlock(ctx->table_rwlock);
						grc = dlm_grant_txn(ctx, txn);
						mxfs_pal_free(txn);
						return grc;
					}
				}
				/* Conversion (upgrade) blocked by another holder.
				 *
				 * /(2/tcp) DOUBLE-GRANT ROOT (PROVEN BY INSTRUMENT via
				 * P-CONVBLK-REMOVE firing at a crash_consistency failure):
				 * the OLD code REMOVED the sender's GRANTED entry here and
				 * re-queued it as a fresh WAITING request — but the sender
				 * still LOCALLY holds the old (lower) grant (it requested an
				 * UPGRADE, it did NOT release).  Removing the table entry makes
				 * the sender INVISIBLE as a holder: a different node's
				 * subsequent request scans only GRANTED entries (compat checks
				 * skip non-GRANTED), sees no conflict, and is granted a
				 * conflicting mode -> two nodes hold incompatible grants ->
				 * the stale-read / dir lost-update.
				 *
				 * FIX: KEEP the sender's GRANTED entry (it stays visible
				 * as a conflict, so no peer can be granted an incompatible mode
				 * behind its back) and DENY the upgrade with
				 * MXFS_ERR_UPGRADE_CONFLICT.  The sender maps that to -EDEADLK,
				 * and the XFS ilock layer (P109) drops its lower grant THROUGH
				 * the BAST drain pipeline (releasing it in sync with the table)
				 * and re-acquires the target mode FRESH via the clean FIFO
				 * path — no invisible-holder window, no conversion deadlock.
				 * Scoped to INODE resources (where the P109 -EDEADLK handling
				 * lives); other types keep the legacy remove+requeue. */
				if (resource->type == MXFS_LTYPE_INODE) {
					mxfs_probe_ratelimited(
					    "mxfs: P-CONVBLK-DENY sender=%u ino=%llu held_mode=%s req_mode=%s (keep grant; deny->EDEADLK)\n",
					    sender, (unsigned long long)resource->ino,
					    mode_name(lk->mode), mode_name(mode));
					mxfs_pal_rwlock_unlock(ctx->table_rwlock);
					send_grant(ctx, sender, resource, MXFS_LOCK_NL,
						   MXFS_ERR_UPGRADE_CONFLICT, MXFS_MSG_LOCK_DENY,
						   request_epoch, 0, 0, 0, &deny_ids);
					return 0;
				}
				mxfs_probe_ratelimited(
				    "mxfs: P-CONVBLK-REMOVE sender=%u type=%u ino=%llu held_mode=%s req_mode=%s\n",
				    sender, resource->type,
				    (unsigned long long)resource->ino,
				    mode_name(lk->mode), mode_name(mode));
				{
					struct mxfs_lock **pp = &ctx->buckets[bucket];
					while (*pp) {
						if (*pp == lk) {
							*pp = lk->next;
							lock_free(lk);
							ctx->lock_count--;
							break;
						}
						pp = &(*pp)->next;
					}
				}
				chain = ctx->buckets[bucket];
				goto remote_check_compat;
			}
		}
	}

remote_check_compat:
	/* Check compatibility */
	compat = 1;
	for (lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (!lk_is_holder(lk))
			continue;
		if (!lock_compat[lk->mode][mode]) {
			compat = 0;
			/* DLM_TRACE: log which holder caused incompatibility */
			if (resource->ino == 128 &&
			    resource->type == MXFS_LTYPE_INODE)
				mxfs_pal_log(MXFS_LOG_DEBUG,
				    "DLM_TRACE: process_remote_request CONFLICT "
				    "ino=128 sender=%u req_mode=%s vs "
				    "holder owner=%u mode=%s",
				    sender, mode_name(mode),
				    lk->owner, mode_name(lk->mode));
			/* P1-AGCONFLICT (instrumented, master-side attribution for the
			 * P36-RETRY type=3 stalls): name the GRANTED holder that
			 * blocks an AG request, so the stall's holder node is
			 * identifiable in default runs.  Ratelimited; AG requests
			 * only conflict under real contention. */
			if (resource->type == MXFS_LTYPE_AG)
				mxfs_probe_ratelimited(
				    "mxfs: P1-AGCONFLICT ag=%u sender=%u req=%s holder=%u hmode=%s hstate=%d nq=%d\n",
				    resource->ag_number, sender, mode_name(mode),
				    lk->owner, mode_name(lk->mode), lk->state,
				    !!(flags & MXFS_LKF_NOQUEUE));
			break;
		}
	}

	/* arrival-time FIFO barrier: do not grant past an
	 * older conflicting waiter (see find_conflicting_waiter). */
	if (compat) {
		struct mxfs_lock *cw = find_conflicting_waiter(chain, resource,
							       sender, mode);
		if (cw) {
			static atomic_t p6fr_n = ATOMIC_INIT(0);
			compat = 0;
			if (atomic_inc_return(&p6fr_n) <= 60000)
				mxfs_probe("mxfs: P6-FAIRQ site=remote ino=%llu type=%u ag=%u req=%s sender=%u behind waiter=%u wmode=%s wage_ms=%llu nq=%d\n",
					(unsigned long long)resource->ino,
					resource->type, resource->ag_number,
					mode_name(mode), sender,
					cw->owner, mode_name(cw->mode),
					(unsigned long long)(cw->queued_at ?
					    mxfs_pal_time_ms() - cw->queued_at : 0),
						!!(flags & MXFS_LKF_NOQUEUE));
		}
	}

	/* DLM_TRACE: log compat result for inode 128 */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: process_remote_request COMPAT_RESULT "
			     "ino=128 compat=%d sender=%u mode=%s",
			     compat, sender, mode_name(mode));

	/*
	 * 0.74.0: the conflicting holder is a DEAD node whose recovery this
	 * node's prover has declared RECOVERY_BLOCKED.  Its grant is not going
	 * to be released by the requester waiting, so deny with the named code
	 * instead of queueing the requester behind it for its whole budget.
	 */
	if (!compat && ctx->recovery_blocked_cb) {
		for (lk = chain; lk; lk = lk->next) {
			if (!resource_equal(&lk->resource, resource) ||
			    !lk_is_holder(lk) || lock_compat[lk->mode][mode])
				continue;
			if (lk->owner != ctx->local_node &&
			    ctx->recovery_blocked_cb(ctx->cb_data, lk->owner)) {
				mxfs_pal_rwlock_unlock(ctx->table_rwlock);
				pr_warn_ratelimited(
				    "mxfs: P-RBLK-DENY-MASTER type=%u ino=%llu ag=%u sender=%u req=%s holder=%u — holder is a dead node in RECOVERY_BLOCKED; denying instead of queueing\n",
				    resource->type, (unsigned long long)resource->ino,
				    resource->ag_number, sender, mode_name(mode),
				    lk->owner);
				send_grant(ctx, sender, resource, MXFS_LOCK_NL,
					   MXFS_ERR_RECOVERY_BLOCKED, MXFS_MSG_LOCK_DENY,
					   request_epoch, 0, 0, 0, &deny_ids);
				return -EHOSTDOWN;
			}
		}
	}

	if (!compat && (flags & MXFS_LKF_NOQUEUE)) {
		struct mxfs_bast_record dm_recs[MXFS_MAX_BAST_RECORDS];
		int dm_n = 0;

		if (flags & MXFS_LKF_DEMAND)
			dm_n = demand_collect_holders(ctx, bucket, resource, mode,
						      dm_recs);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		send_grant(ctx, sender, resource, MXFS_LOCK_NL,
			   MXFS_ERR_DEADLOCK, MXFS_MSG_LOCK_DENY,
			   request_epoch, 0, 0, 0, &deny_ids);
		demand_fire(ctx, resource, sender, dm_recs, dm_n);
		return -EAGAIN;
	}

	if (!compat && (flags & MXFS_LKF_TRYLOCK)) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		send_grant(ctx, sender, resource, MXFS_LOCK_NL,
			   MXFS_ERR_DEADLOCK, MXFS_MSG_LOCK_DENY,
			   request_epoch, 0, 0, 0, &deny_ids);
		return -EWOULDBLOCK;
	}

	/* Allocate and insert (an immediate grant is PENDING_DURABLE
	 * until its ledger transition verifies) */
	newlk = lock_alloc(resource, sender, mode,
			   compat ? MXFS_LSTATE_PENDING_DURABLE : MXFS_LSTATE_WAITING,
			   flags);
	if (!newlk) {
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		return -ENOMEM;
	}

	/* Store requester's epoch so waiter promotions echo it back.
	 * Bug 106: nodes observe different membership change counts,
	 * so master and requester epochs may differ. */
	newlk->request_epoch = request_epoch;
	newlk->owner_inc = req->owner_inc;      /* ledger identity */
	newlk->owner_slot = req->owner_slot;
	newlk->req_id = req->req_id;
	newlk->acq_seq = req->acq_seq;
	/* The notification this insertion is about to fire counts as this
	 * entry's first, so the earliest a re-send may fire another is one
	 * re-fire interval from now.  Stamped under the table lock because
	 * the entry must not be touched once it is released. */
	newlk->acq_bast_ms = mxfs_pal_time_ms();
	newlk->decide_gen = ledger_gen;
	newlk->next = ctx->buckets[bucket];
	ctx->buckets[bucket] = newlk;
	ctx->lock_count++;

	if (compat) {
		struct dlm_txn *txn = mxfs_pal_alloc(sizeof(*txn));
		uint32_t gen = newlk->grant_gen = dlm_next_gen(ctx);
		int grc;

		if (!txn) {
			ctx->buckets[bucket] = newlk->next;
			ctx->lock_count--;
			lock_free(newlk);
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			return -ENOMEM;
		}
		/* DLM_TRACE: remote request granted immediately */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: process_remote_request GRANT_IMMEDIATE "
				     "ino=128 sender=%u mode=%s",
				     sender, mode_name(mode));
		P_LKT("GRANT-REMOTE", resource, sender, mode);
		dlm_txn_init(txn, resource, ledger_gen);
		if (mode == MXFS_LOCK_EX)
			newlk->handoff = dg_grant_ex(ctx, resource, sender, gen,
						     &newlk->dir_epoch);
		dlm_txn_add_grant(txn, newlk, 0, 0, false);
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		/* ROOT FIX (the grantee BAST for a jumped older waiter)
		 * fires from dlm_txn_finalize once the grant is delivered. */
		grc = dlm_grant_txn(ctx, txn);
		mxfs_pal_free(txn);
		return grc;
	}

	/* DLM_TRACE: remote request queued, collecting BAST targets */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: process_remote_request QUEUED_WAITING "
			     "ino=128 sender=%u mode=%s",
			     sender, mode_name(mode));

	/* Capture BAST targets into snapshot array while under
	 * table_rwlock.  Must NOT iterate live lock entries via work_next
	 * after releasing the lock — concurrent releases from fast holders
	 * corrupt the work_next chain at 3+ nodes. */
	{
		struct mxfs_bast_record rr_bast_recs[MXFS_MAX_BAST_RECORDS];
		int rr_bast_count = 0;
		/* The blocking holder's mode, for the queue receipt below.  Captured
		 * here because it is only readable under the table lock. */
		uint8_t rr_hold_mode = MXFS_LOCK_NL;
		struct dlm_grant_ids qk_ids;

		for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
			if (!resource_equal(&lk->resource, resource))
				continue;
			if (lk->state != MXFS_LSTATE_GRANTED)
				continue;   /* pending holders get theirs at finalize */
			if (lk->owner == MXFS_DLM_NODE_UNKNOWN)
				continue;   /* nobody to BAST; the purge retires it */
			if (!lock_compat[lk->mode][mode]) {
				if (rr_hold_mode == MXFS_LOCK_NL)
					rr_hold_mode = lk->mode;
				if (rr_bast_count < MXFS_MAX_BAST_RECORDS) {
					rr_bast_recs[rr_bast_count].owner = lk->owner;
					rr_bast_recs[rr_bast_count].requested_mode = mode;
					rr_bast_count++;
				}
			}
		}

		/* DLM_TRACE: log BAST target count for ino 128 */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "DLM_TRACE: process_remote_request "
				     "BAST_TARGETS ino=128 count=%d sender=%u",
				     rr_bast_count, sender);

		/* P37: a remote request queued WAITING for the contended dir;
		 * bast_targets=0 here would mean NO holder was told to release (the
		 * waiter would stall to timeout). */
		if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
			mxfs_probe_ratelimited(
			    "mxfs: P37-RREQ-QUEUE ino=131 sender=%u mode=%s bast_targets=%d\n",
			    sender, mode_name(mode), rr_bast_count);

		mxfs_pal_rwlock_unlock(ctx->table_rwlock);

		/*
		 * Tell the requester its request is HERE.  Until this existed the
		 * master answered a queued request with silence, and the requester
		 * had no way to separate that from a request that never arrived —
		 * so an acquire whose budget ran out could only guess whether
		 * waiting longer would ever end.  Sent after the entry is in the
		 * table, so the receipt never runs ahead of the thing it attests
		 * to, and outside the table lock like every other send on this
		 * path.
		 *
		 * This is an acceptance receipt, not a promise of progress: a
		 * master can keep queueing a request behind a holder that never
		 * releases.  What it rules out is the case where nothing at the
		 * other end has the request at all.
		 */
		memset(&qk_ids, 0, sizeof(qk_ids));
		qk_ids.req_id = req->req_id;
		send_grant(ctx, sender, resource, rr_hold_mode, MXFS_OK,
			   MXFS_MSG_LOCK_QUEUED, request_epoch, 0, 0, 0, &qk_ids);

		/* Fire deferred BASTs from snapshot */
		fire_bast_records(ctx, resource, rr_bast_recs, rr_bast_count);
	}

	return -EINPROGRESS;
}

int mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx,
				  const struct mxfs_dlm_lock_resp *resp)
{
	const struct mxfs_resource_id *resource;
	uint8_t mode, handoff;
	int status;
	mxfs_epoch_t grant_epoch;
	uint32_t grant_gen, dir_epoch;
	bool matched;
	bool have_mirror = false;
	bool inserted_provisional = false;

	if (!ctx || !resp)
		return -EINVAL;
	resource = &resp->resource;
	mode = resp->mode;
	status = resp->status;
	grant_epoch = resp->hdr.epoch;
	grant_gen = resp->grant_gen;
	handoff = resp->handoff;
	dir_epoch = resp->dir_epoch;

	/*
	 * ROOT FIX — GRANT-EPOCH VISIBILITY ORDER
	 * (PROVEN BY INSTRUMENT, run5 r23 node4_f1.md5 clobber): the OLD order
	 * signaled the pending waiter FIRST and reconciled the local mirror
	 * (which stores dir_epoch) AFTER.  The woken acquirer's first dir
	 * modify then read mxfs_v5_dlm_inode_dir_epoch()==0 (P2-EPOCHPLACE
	 * master_ep=0 unestablished=1 at the exact collide), so EVERY
	 * epoch-gated dir coherence guard (addname epoch refresh,
	 * prior-tenure evict, tenure-stale bypass) was INERT for the first
	 * op(s) after a cross-node EX handoff -> stale-base RMW -> durable
	 * peer-dirent clobber (P13-COLLIDE our=[node6_f2]
	 * disk=[node4_f1.md5] at the same aoff).  Reconcile the mirror
	 * BEFORE signaling so the epoch is visible the moment the waiter
	 * wakes.  For a first grant (no existing mirror) insert the mirror
	 * provisionally; if the signal then finds NO pending request
	 * (unsolicited re-affirm), remove it again and send the
	 * gen-stamped reject-release exactly as before — the µs-scale
	 * provisional window is harmless because no FS-layer path believes
	 * it holds this resource (nothing is waiting on it).
	 *
	 * the mirror also carries the DURABLE grant id + lineage the
	 * master minted (resp->authority_epoch / grant_seq64 / lineage) so the
	 * eventual LOCK_RELEASE names the exact record.
	 */
	if (status == 0) {
		uint32_t bucket = resource_hash(resource, ctx->bucket_count);
		struct mxfs_lock *lk, *newlk;

		mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

		/* sess-tcp: a re-affirm GRANT for a lock we still hold — UPDATE the
		 * existing mirror's gen/mode in place rather than inserting a
		 * duplicate (which would leak and confuse the release gen-match). */
		for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
			if (resource_equal(&lk->resource, resource) &&
			    lk->owner == ctx->local_node &&
			    (lk->state == MXFS_LSTATE_GRANTED ||
			     lk->state == MXFS_LSTATE_CONVERTING)) {
				/* 0.89.1 (D-0977): a grant naming a NEW durable grant id
				 * is a fresh ledger commit and its mask replaces the
				 * snapshot; a re-affirm of the grant already mirrored
				 * (same id, no commit behind it) can only ADD bits.  No
				 * peer can publish a mark while this node holds the EX,
				 * so a bit the mirror has and the message lacks is a
				 * lost bit, never a cleared one — and the guard fails
				 * toward "still open" (a defer, retried under a fresh
				 * grant), never toward the free. */
				bool fresh_commit = resp->grant_seq64 &&
						    (resp->grant_seq64 != lk->grant_seq ||
						     resp->authority_epoch != lk->auth_epoch);

				if (mode > lk->mode)
					lk->mode = mode;
				lk->grant_gen = grant_gen;
				lk->handoff = handoff;   /* cross-node handoff signal */
				/* monotonic cross-node handoff epoch.  Only advance it
				 * (never let a stray PR grant carrying 0 clobber a higher value
				 * already delivered by an EX handoff). */
				if (dir_epoch > lk->dir_epoch)
					lk->dir_epoch = dir_epoch;
				if (resp->grant_seq64) {
					lk->auth_epoch = resp->authority_epoch;
					lk->grant_seq = resp->grant_seq64;
				}
				if (resp->lineage)
					lk->lineage = resp->lineage;
				/* 0.89.0: an exclusive (re-)grant carries the mask
				 * snapshot the guard reads; a shared grant does not
				 * touch an existing exclusive snapshot */
				if (dlm_mode_exclusive(mode)) {
					if (fresh_commit || !lk->open_snap)
						lk->open_holders = resp->open_holders;
					else
						lk->open_holders |= resp->open_holders;
					lk->open_snap = true;
				}
				lk->owner_inc = ctx->local_inc;
				lk->owner_slot = ctx->local_slot;
				have_mirror = true;
				break;
			}
		}

		if (!have_mirror) {
			/* First grant — insert the mirror BEFORE waking the waiter
			 * (provisional: removed below if the grant turns out
			 * unsolicited). */
			newlk = lock_alloc(resource, ctx->local_node, mode,
					   MXFS_LSTATE_GRANTED, 0);
			if (newlk) {
				newlk->grant_gen = grant_gen;
				newlk->handoff = handoff;  /* */
				newlk->dir_epoch = dir_epoch;  /* */
				newlk->auth_epoch = resp->authority_epoch;   /* */
				newlk->grant_seq = resp->grant_seq64;
				newlk->lineage = resp->lineage;
				newlk->open_holders = resp->open_holders;     /* 0.89.0 */
				newlk->open_snap = dlm_mode_exclusive(mode);
				newlk->req_id = resp->req_id;
				newlk->owner_inc = ctx->local_inc;
				newlk->owner_slot = ctx->local_slot;
				newlk->next = ctx->buckets[bucket];
				ctx->buckets[bucket] = newlk;
				ctx->lock_count++;
				have_mirror = true;
				inserted_provisional = true;
			}
		}
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
	}

	/* Signal the pending waiter, passing the grant epoch so that
	 * stale grants from a previous epoch's master are discarded
	 * rather than completing the wrong pending entry (Bug 67).
	 * matched == true iff this grant completed a request WE issued. */
	/* 0.84.5 (D-...-0960): an AUTH_TRANSITION deny carries the bootstrap's
	 * page-takeover count in grant_gen; keep the highest seen for the
	 * waiter to read (a 32-bit wire field: the count only grows) */
	if (status == MXFS_ERR_AUTH_TRANSITION &&
	    (uint64_t)grant_gen > ctx->transition_progress_rx)
		ctx->transition_progress_rx = grant_gen;
	matched = pending_signal_resource(ctx, resource, mode, status,
					  grant_epoch);

	/* P37: trace grant receipt for the contended dir.  matched=0 means
	 * the grant arrived but completed NO pending request we issued (epoch
	 * mismatch / already-timed-out / wrong resource) -> the requester is NOT
	 * woken and will sit until its 6000ms ACQUIRE_WAIT_MS timeout+retry. */
	if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
		mxfs_probe_ratelimited(
		    "mxfs: P37-GRANT-RECV ino=131 mode=%s status=%d gen=%u matched=%d\n",
		    mode_name(mode), status, grant_gen, matched ? 1 : 0);
	/* P74: run68 — the master granted a fresh EX the
	 * grantee never visibly processed (no local trace; ino!=131 was
	 * blind here).  Trace EVERY inode grant receipt: matched=0 with
	 * have_mirror=1 is the silent re-affirm ABSORB (mirror updated,
	 * nobody woken, no reject sent) — the local/master divergence
	 * producer.  Capped. */
	if (resource->type == MXFS_LTYPE_INODE) {
		static atomic_t p74_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p74_n) <= 8000)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P74-GRANT ino=%llu mode=%s status=%d gen=%u matched=%d have_mirror=%d prov=%d grant_id={%llu,%llu} oh=0x%llx",
			    (unsigned long long)resource->ino, mode_name(mode),
			    status, grant_gen, matched ? 1 : 0,
			    have_mirror ? 1 : 0, inserted_provisional ? 1 : 0,
			    (unsigned long long)resp->authority_epoch,
			    (unsigned long long)resp->grant_seq64,
			    (unsigned long long)resp->open_holders);
	}
	/* CAPPED receive-side epoch trace — pairs with the
	 * capped P51-SENDGRANT.  dir_epoch_rx=0 on an EX here names the message
	 * as the loss point; dir_epoch_rx>0 with a later master_ep=0 read names
	 * the mirror store/lifecycle (drop-reacquire window). */
	if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE &&
	    mode == MXFS_LOCK_EX && status == 0) {
		static atomic_t p5hrx = ATOMIC_INIT(0);
		if ((unsigned)atomic_inc_return(&p5hrx) <= 60000)
			mxfs_probe("mxfs: P5H-GRANT-EPOCH-RX ino=131 gen=%u dir_epoch_rx=%u handoff=%u have_mirror=%d inserted=%d matched=%d\n",
				grant_gen, dir_epoch, handoff,
				have_mirror ? 1 : 0, inserted_provisional ? 1 : 0,
				matched ? 1 : 0);
	}

	if (status == 0) {
		uint32_t bucket = resource_hash(resource, ctx->bucket_count);

		/*
		 * No pending entry completed, but a live wait on this node may have
		 * solicited this grant: the requester registers a pending entry only
		 * for the one second each attempt waits, so a grant landing between
		 * attempts (50 ms between descents, up to 5 s of classifier backoff
		 * between restarts) has nothing to complete and used to be bounced —
		 * mirror unwound, release sent, the master retiring the grant and
		 * promoting the next waiter, and this wait's own next re-send
		 * queueing again at the back.  Keep it for the wait instead: the
		 * provisional mirror stays and the wait's next attempt claims it.
		 * Only from the node this view names master; anything else is the
		 * stale-master case the bounce below exists for.
		 */
		if (inserted_provisional && !matched &&
		    mxfs_dlm_resource_master(ctx, resource) == resp->hdr.sender &&
		    dlm_acq_adopt_grant(ctx, resp)) {
			mxfs_probe_ratelimited(
			    "mxfs: P958-ACQ-GRANT-ADOPTED type=%u ino=%llu ag=%u mode=%s gen=%u master=%u total=%llu — a grant arrived between two attempts of a live wait; kept for that wait instead of bounced\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, mode_name(mode), grant_gen,
			    resp->hdr.sender,
			    (unsigned long long)ctx->acq_grant_adopted);
			return 0;
		}

		/* Unwind the provisional first-grant mirror if nothing we issued
		 * was waiting for it (unsolicited re-affirm). */
		if (inserted_provisional && !matched) {
			struct mxfs_lock **pp;

			mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
			pp = &ctx->buckets[bucket];
			while (*pp) {
				struct mxfs_lock *lk = *pp;

				if (resource_equal(&lk->resource, resource) &&
				    lk->owner == ctx->local_node &&
				    lk->state == MXFS_LSTATE_GRANTED &&
				    lk->grant_gen == grant_gen) {
					*pp = lk->next;
					lock_free(lk);
					ctx->lock_count--;
					break;
				}
				pp = &(*pp)->next;
			}
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			have_mirror = false;
		}

		if (!have_mirror && !matched) {
			/*
			 * sess-tcp DOUBLE-GRANT FIX (receiver half): an UNSOLICITED
			 * grant — no pending request of ours AND no held mirror.  This
			 * is a re-affirm of our -ETIMEDOUT retry that reached the master
			 * AFTER we already got, used, and RELEASED the original grant.
			 * Accepting it would resurrect a PHANTOM EX holder (we and the
			 * master would both believe we hold, while our FS layer has
			 * released) — the conflicting waiter would starve / a second EX
			 * holder appears.  REJECT it: send a gen-stamped LOCK_RELEASE so
			 * the master drops the phantom entry and promotes the real
			 * waiter.  Harmless if the master already moved on (gen-checked
			 * there too).
			 *
			 * the reject carries the durable grant id the master
			 * just minted, so the ledger record is retired with it and the
			 * release is tracked to its ACK like any other.
			 */
			mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, resource);

			P_LKT("GRANT-REJECT-UNSOLICITED", resource, ctx->local_node, mode);
			ctx->acq_grant_bounced++;
			mxfs_probe_ratelimited(
			    "mxfs: P958-ACQ-GRANT-BOUNCED type=%u ino=%llu ag=%u mode=%s gen=%u from=%u master=%u total=%llu — a grant with no pending entry and no live wait on this node; released back to its master\n",
			    resource->type, (unsigned long long)resource->ino,
			    resource->ag_number, mode_name(mode), grant_gen,
			    resp->hdr.sender, master,
			    (unsigned long long)ctx->acq_grant_bounced);
			/* A poisoned node sends no release, not even to bounce a grant
			 * it never used: the fence that follows purges the phantom entry
			 * and promotes the real waiter (see
			 * dlm_refuse_release_while_poisoned). */
			if (master != ctx->local_node && ctx->send_cb &&
			    !dlm_refuse_release_while_poisoned(ctx, "grant_reject",
							       resource)) {
				uint32_t rel_id = ++ctx->rel_id_next;

				if (rel_id == 0)
					rel_id = ctx->rel_id_next = 1;
				dlm_rel_pending_add(ctx, resource, rel_id, grant_gen,
						    resp->authority_epoch, resp->grant_seq64,
						    resp->lineage, mode, MXFS_TAUTH_OPEN_NONE);
				dlm_send_release_msg(ctx, master, resource, grant_gen, rel_id,
						     resp->authority_epoch, resp->grant_seq64,
						     resp->lineage, mode, MXFS_TAUTH_OPEN_NONE);
			}
		}
	}

	return 0;
}

/*
 * MASTER SIDE of an abandonment.  The sender says it will never install a
 * grant for the acquisition {sender, owner_inc, acq_seq}.  Under this
 * master's table lock, in one place: remember the acquisition so a late
 * re-send cannot recreate it; remove the waiter it may have; retire a grant
 * already decided for it (delivered and lost, or never delivered) and promote
 * whoever was queued behind it; mark a grant still committing so finalize
 * retires it instead of delivering.  Identity must match on all of
 * {owner_inc, acq_seq} and on mode: an entry that has since been re-affirmed
 * for the sender's NEXT acquisition carries that acquisition's name and is
 * left alone.  Always acknowledged, with what was found.
 */
int mxfs_dlm_process_cancel(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
			    const struct mxfs_dlm_lock_cancel *msg)
{
	const struct mxfs_resource_id *resource;
	uint32_t bucket;
	struct mxfs_lock **pp, *lk;
	struct dlm_txn *txn = NULL;
	uint64_t ledger_gen = 0;
	uint8_t outcome = MXFS_CANCEL_ABSENT;
	int promote = 0;

	if (!ctx || !msg)
		return -EINVAL;
	resource = &msg->resource;
	ctx->cancel_rx++;

	if (mxfs_dlm_resource_master(ctx, resource) != ctx->local_node) {
		dlm_send_cancel_ack(ctx, sender, msg, MXFS_CANCEL_NOT_MASTER);
		return -EREMOTE;
	}
	if (dlm_ledger_active(ctx)) {
		int prc = dlm_ledger_prepare(ctx, resource, &ledger_gen);

		if (prc) {
			/* the page is not ours to decide on right now: the sender
			 * retries on its tick, and a later view answers */
			dlm_send_cancel_ack(ctx, sender, msg, MXFS_CANCEL_NOT_MASTER);
			return prc;
		}
	} else {
		ledger_gen = ctx->ledger_gen;
	}
	txn = mxfs_pal_alloc(sizeof(*txn));
	if (!txn)
		return -ENOMEM;
	dlm_txn_init(txn, resource, ledger_gen);
	bucket = resource_hash(resource, ctx->bucket_count);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
	dlm_cancel_tomb_add(ctx, sender, msg->owner_inc, msg->acq_seq);
	for (pp = &ctx->buckets[bucket]; *pp; pp = &(*pp)->next) {
		lk = *pp;
		if (lk->owner != sender || !resource_equal(&lk->resource, resource))
			continue;
		/* identity: the entry must serve THIS acquisition */
		if (lk->acq_seq != msg->acq_seq || lk->mode != msg->mode ||
		    (lk->owner_inc && msg->owner_inc && lk->owner_inc != msg->owner_inc))
			continue;
		if (lk->state == MXFS_LSTATE_WAITING ||
		    lk->state == MXFS_LSTATE_BLOCKED) {
			*pp = lk->next;
			ctx->lock_count--;
			P_LKT("CANCEL-WAITER", resource, sender, lk->mode);
			lock_free(lk);
			ctx->cancel_waiters_removed++;
			outcome = MXFS_CANCEL_WAITER_REMOVED;
			/* a waiter ahead in FIFO order may have been the only thing
			 * holding a compatible younger waiter back */
			promote = 1;
			break;
		}
		if (lk->state == MXFS_LSTATE_PENDING_DURABLE) {
			lk->cancelled = true;
			ctx->cancel_grants_retiring++;
			outcome = MXFS_CANCEL_GRANT_RETIRING;
			break;
		}
		if (lk->state == MXFS_LSTATE_GRANTED ||
		    lk->state == MXFS_LSTATE_CONVERTING) {
			lk->cancelled = false;
			lk->unclaimed = false;
			lk->state = MXFS_LSTATE_PENDING_RELEASE;
			lk->pend_waiter = NULL;
			dg_release(resource, sender);
			dlm_txn_add_release(txn, lk, ++ctx->rel_id_next, false);
			ctx->cancel_grants_retired++;
			outcome = MXFS_CANCEL_GRANT_RETIRED;
			promote = 1;
			break;
		}
		/* PENDING_RELEASE: already on its way out */
		break;
	}
	if (outcome == MXFS_CANCEL_ABSENT)
		ctx->cancel_absent++;
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	mxfs_probe_ratelimited(
	    "mxfs: P958-CANCEL-RX acq=%llu type=%u ino=%llu ag=%u from=%u mode=%s outcome=%u total=%llu — abandonment processed (1 absent, 2 waiter removed, 3 grant retired, 4 grant retiring)\n",
	    (unsigned long long)msg->acq_seq, resource->type,
	    (unsigned long long)resource->ino, resource->ag_number, sender,
	    mode_name(msg->mode), outcome, (unsigned long long)ctx->cancel_rx);
	if (promote)
		dlm_promote_txn(ctx, txn);
	mxfs_pal_free(txn);
	dlm_send_cancel_ack(ctx, sender, msg, outcome);
	return 0;
}

int mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx,
				    mxfs_node_id_t sender,
				    const struct mxfs_dlm_lock_release *rel)
{
	const struct mxfs_resource_id *resource;
	uint32_t grant_gen;
	uint32_t bucket;
	struct mxfs_lock *lk;
	struct mxfs_lock *found = NULL;
	struct dlm_txn *txn;
	uint64_t ledger_gen = 0;
	int rrc;

	if (!ctx || !rel)
		return -EINVAL;
	resource = &rel->resource;
	grant_gen = rel->grant_gen;

	/* DLM_TRACE: log remote release entry */
	if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "DLM_TRACE: process_remote_release ENTRY ino=128 "
			     "sender=%u local_node=%u",
			     sender, ctx->local_node);

	bucket = resource_hash(resource, ctx->bucket_count);

	/* not the page master any more -> the releaser re-routes
	 * (the ACK says so); never retire a record we do not own. */
	if (mxfs_dlm_resource_master(ctx, resource) != ctx->local_node) {
		ctx->ledger_remaster++;
		if (sender != ctx->local_node)
			send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
					 rel->authority_epoch, rel->grant_seq64,
					 MXFS_ERR_REMASTER);
		return -EREMOTE;
	}
	/* the page must be current + imported: the record we retire may be a
	 * ledger-imported blocker of this very sender (mirror purged on its
	 * side by a membership change, record still ACTIVE) */
	if (dlm_ledger_active(ctx)) {
		int prc = dlm_ledger_prepare(ctx, resource, &ledger_gen);

		if (prc) {
			if (sender != ctx->local_node)
				send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
						 rel->authority_epoch, rel->grant_seq64,
						 (prc == -EAGAIN || prc == -EINPROGRESS) ?
						 MXFS_ERR_REMASTER : MXFS_ERR_LEDGER);
			return prc;
		}
	} else {
		ledger_gen = ctx->ledger_gen;
	}

	txn = mxfs_pal_alloc(sizeof(*txn));
	if (!txn)
		return -ENOMEM;
	dlm_txn_init(txn, resource, ledger_gen);

	mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

	/*
	 * The seal cut: the sender was fenced and its ledger records are the
	 * replay gate's authority.  A late release (queued before the death,
	 * delivered after the seal) must not retire a record the sealed
	 * manifest lists — the replay's current-safety check would then read
	 * a mutated authority and abort the attempt.  The releaser is dead:
	 * no ACK, the record stays a blocker until the recovery purge.
	 */
	if (dlm_owner_sealed(ctx, sender)) {
		ctx->sealed_releases_refused++;
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		mxfs_pal_free(txn);
		if (ctx->sealed_releases_refused <= 50)
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P-TAUTH-SEALED-RELEASE-REFUSED node=%u type=%u "
				     "ino=%llu ag=%u — release from a sealed (fenced) owner "
				     "ignored; the record stays until the recovery purge",
				     sender, resource->type,
				     (unsigned long long)resource->ino, resource->ag_number);
		return 0;
	}

	for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource) || lk->owner != sender)
			continue;
		if (lk->state == MXFS_LSTATE_PENDING_RELEASE) {
			/* duplicate release (retry before our ACK reached it).
			 * NOT ACKed OK — an ACK is valid only once the
			 * retirement is durable or superseded (0.35.0 ACKed here
			 * while the refused transition had stranded the entry, so
			 * the releaser stopped and the bit stayed forever).  The
			 * in-flight transition ACKs this rel_id itself; a stuck
			 * retirement is re-driven right now with this message. */
			if (lk->rel_failed_ms) {
				lk->rel_failed_ms = 0;
				ctx->ledger_release_redrives++;
				found = lk;
				break;
			}
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_free(txn);
			return 0;
		}
		if (lk->state == MXFS_LSTATE_PENDING_DURABLE) {
			/* a grant to the sender is still committing: this release
			 * predates it (raced ahead) — it cannot name that grant's id,
			 * so it applies to nothing; ACK (the sender holds nothing it
			 * believes released) */
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_free(txn);
			if (sender != ctx->local_node)
				send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
						 rel->authority_epoch, rel->grant_seq64, MXFS_OK);
			return 0;
		}
		if (lk->state != MXFS_LSTATE_GRANTED &&
		    lk->state != MXFS_LSTATE_CONVERTING)
			continue;
		/*
		 * sess-tcp DOUBLE-GRANT FIX: ignore a STALE release.  If the
		 * holder re-acquired (a NEWER grant gen was issued by a
		 * re-affirm) since this release was sent, the release carries
		 * an OLD gen.  Removing the entry + promoting a waiter now would
		 * grant a SECOND EX holder while the sender still believes it
		 * holds the re-affirmed grant (Bug-51).  Keep the entry; the
		 * sender's CURRENT-gen release will arrive and free it properly.
		 * gen==0 on either side falls back to unconditional removal so
		 * a pre-gen message can never wedge a lock.
		 *
		 * the durable grant id is the stronger key — a release
		 * naming an older grant id than the record's is stale whatever
		 * its gen says (and gets an ACK: the releaser holds nothing).
		 */
		if ((grant_gen != 0 && lk->grant_gen != 0 &&
		     lk->grant_gen != grant_gen) ||
			(rel->grant_seq64 != 0 && lk->grant_seq != 0 &&
			 (lk->grant_seq != rel->grant_seq64 ||
			  lk->auth_epoch != rel->authority_epoch))) {
			P_LKT("REMOTE-RELEASE-STALEGEN", resource, sender, lk->mode);
			if (resource->ino == 131 &&
			    resource->type == MXFS_LTYPE_INODE)
				mxfs_probe_ratelimited(
				    "mxfs: P37-RREL-STALEGEN ino=131 sender=%u relgen=%u lkgen=%u (release dropped, NO promote)\n",
				    sender, grant_gen, lk->grant_gen);
			/* AG twin — a dropped AG release wedges
			 * the AG for every peer (run31: AG-0 EX starve 120s →
			 * create -110 → dirty-cancel shutdown).  Name it. */
			if (resource->type == MXFS_LTYPE_AG)
				mxfs_probe_ratelimited(
				    "mxfs: P5R-AGREL-STALEGEN ag=%u sender=%u relgen=%u lkgen=%u (release dropped, NO promote)\n",
				    resource->ag_number, sender, grant_gen,
				    lk->grant_gen);
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_free(txn);
			if (sender != ctx->local_node)
				send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
						 rel->authority_epoch, rel->grant_seq64, MXFS_OK);
			return 0;
		}
		/* the releaser's incarnation must be the record's */
		if (rel->owner_inc && lk->owner_inc && rel->owner_inc != lk->owner_inc) {
			mxfs_pal_rwlock_unlock(ctx->table_rwlock);
			mxfs_pal_free(txn);
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-TAUTH-RELEASE-INC-MISMATCH sender=%u ino=%llu type=%u "
				     "record_inc=%llu rel_inc=%llu — refused",
				     sender, (unsigned long long)resource->ino, resource->type,
				     (unsigned long long)lk->owner_inc,
				     (unsigned long long)rel->owner_inc);
			if (sender != ctx->local_node)
				send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
						 rel->authority_epoch, rel->grant_seq64,
						 MXFS_ERR_LEDGER);
			return -EPERM;
		}
		/* DLM_TRACE: log which entry is being released */
		if (resource->ino == 128 &&
		    resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "DLM_TRACE: process_remote_release FOUND ino=128 "
			    "sender=%u mode=%s state=%s",
			    sender, mode_name(lk->mode),
			    state_name(lk->state));
		/*
		 * 0.84.13: the sender says the acquisition that took this grant is
		 * over — remember its name, so a re-send of it that is still in
		 * flight is refused instead of queued afresh (see
		 * mxfs_dlm_process_remote_request).  Under table_rwlock here.
		 */
		if (rel->acq_done && lk->acq_seq)
			dlm_consumed_tomb_add(ctx, sender,
					      lk->owner_inc ? lk->owner_inc : rel->owner_inc,
					      lk->acq_seq);
		found = lk;
		break;
	}

	if (!found) {
		P_LKT("REMOTE-RELEASE-ENOENT", resource, sender, 0);
		if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
			mxfs_probe_ratelimited(
			    "mxfs: P37-RREL-ENOENT ino=131 sender=%u (no GRANTED entry; NO promote)\n",
			    sender);
		if (resource->type == MXFS_LTYPE_AG)
			mxfs_probe_ratelimited(
			    "mxfs: P5R-AGREL-ENOENT ag=%u sender=%u (no GRANTED entry; NO promote)\n",
			    resource->ag_number, sender);
		/* DLM_TRACE: log ENOENT for ino 128 */
		if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "DLM_TRACE: process_remote_release ENOENT ino=128 "
			    "sender=%u (no GRANTED entry)",
			    sender);
		/* Bug 51: do NOT fall back to removing WAITING/BLOCKED entries.
		 *
		 * When LOCK_REQ arrives before LOCK_RELEASE due to the
		 * send_lock ordering race, process_remote_request detects
		 * the stale grant, removes it, and creates a fresh WAITING
		 * entry. The subsequent LOCK_RELEASE finds no GRANTED entry.
		 * If we removed the WAITING entry here, the sender's new
		 * lock request would be silently destroyed — it would never
		 * get promoted, and the sender's pending_wait would time out.
		 *
		 * The LOCK_RELEASE with no matching GRANTED entry is harmless:
		 * it means the entry was already cleaned up.  with the
		 * page imported, "no entry" also means "no ACTIVE record for this
		 * owner" — ACK so the releaser stops retrying. */
		mxfs_pal_rwlock_unlock(ctx->table_rwlock);
		mxfs_pal_free(txn);
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "dlm: LOCK_RELEASE from node %u — no GRANTED "
			     "entry found (likely already removed by stale "
			     "re-request handling)",
			     sender);
		/*
		 * 0.89.0 (D-0977): no grant to ride, but the releaser's mark
		 * change must still land — a set that is dropped here is a
		 * peer's free under a live descriptor.  Apply it to the
		 * resource's existing record on its own (never allocating) and
		 * ACK only once it is durable; -ESTALE (no record at all) means
		 * there is nothing a guard could read, and a refused write
		 * keeps the releaser re-sending.
		 */
		if (rel->open_op == MXFS_TAUTH_OPEN_SET ||
		    rel->open_op == MXFS_TAUTH_OPEN_CLEAR) {
			int mrc = dlm_open_mark_only(ctx, resource, sender, rel, ledger_gen);

			if (mrc && mrc != -ESTALE) {
				if (sender != ctx->local_node)
					send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
							 rel->authority_epoch, rel->grant_seq64,
							 MXFS_ERR_LEDGER);
				return mrc;
			}
		}
		if (sender != ctx->local_node)
			send_release_ack(ctx, sender, resource, grant_gen, rel->rel_id,
					 rel->authority_epoch, rel->grant_seq64, MXFS_OK);
		return -ENOENT;
	}

	/*
	 * (step 3e): retire the record and grant the successors in
	 * ONE ledger transition; the ACK follows the commit.  The entry stays
	 * a holder (PENDING_RELEASE) for new arrivals until then.  An
	 * unconditional (gen 0, FIX-20b) release names no grant id: the
	 * table's is used.
	 */
	found->state = MXFS_LSTATE_PENDING_RELEASE;
	if (rel->grant_seq64) {
		found->auth_epoch = rel->authority_epoch;
		found->grant_seq = rel->grant_seq64;
	}
	if (rel->lineage)
		found->lineage = rel->lineage;
	if (!found->owner_inc)
		found->owner_inc = rel->owner_inc;
	if (!found->owner_slot)
		found->owner_slot = rel->owner_slot;
	found->open_op = rel->open_op;      /* 0.89.0 (D-0977) */
	P_LKT("REMOTE-RELEASE", resource, sender, found->mode);
	dg_release(resource, sender);
	dlm_txn_add_release(txn, found, rel->rel_id, sender != ctx->local_node);
	mxfs_pal_rwlock_unlock(ctx->table_rwlock);

	rrc = dlm_promote_txn(ctx, txn);
	mxfs_pal_free(txn);

	/* P37 / P5R: release visibility at the master. */
	if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
		mxfs_probe_ratelimited("mxfs: P37-RREL ino=131 sender=%u rc=%d\n", sender, rrc);
	if (resource->type == MXFS_LTYPE_AG)
		mxfs_probe_ratelimited("mxfs: P5R-AGREL ag=%u sender=%u rc=%d\n",
				    resource->ag_number, sender, rrc);
	return rrc == -ESTALE ? 0 : rrc;
}
