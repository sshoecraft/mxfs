// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode lock admission: ilock begin, end, try and demote
 */
#define MXFS_TU_ID 21	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
static int mxfs_dbg_p106_bail_pause_ms;
module_param_named(dbg_p106_bail_pause_ms, mxfs_dbg_p106_bail_pause_ms, int, 0644);
MODULE_PARM_DESC(dbg_p106_bail_pause_ms, "DEBUG one-shot: pause (ms) after a P106 bail before the slow-path re-acquire (0=off)");
static unsigned long long mxfs_p106_check_n;
module_param_named(p106_check_n, mxfs_p106_check_n, ullong, 0444);
MODULE_PARM_DESC(p106_check_n, "count of dir-EX fast-path serves that reached the backing-record (phantom) check");

/*
 * 0.89.63: the stranded-grant injector.  One-shot, by inode: the next
 * slow-path acquire of this inode that the DLM GRANTS is dropped by the XFS
 * layer at the point where it would publish the mode — the mirror entry stays
 * granted, the in-core mode stays NL, nothing is consumed and nothing is
 * released.  That is the shape the 280-sample strike escape
 * (P15H-STRANDED-RELEASE) exists to free, which had no known producer and
 * therefore no lap; harness tests/stranded_grant_escape.sh.  Taken at the
 * grant in mxfs_dlm_ilock_begin's slow path.
 */
static unsigned long long mxfs_dbg_strand_ino;
module_param_named(dbg_strand_ino, mxfs_dbg_strand_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_strand_ino, "TEST ONLY one-shot: drop this inode's next granted slow-path acquire unconsumed (mirror granted, in-core NL) to produce a stranded grant; 0=off");
/*
 * 0.89.64: the strand has TWO shapes on TCP.  With the acquirer GONE
 * (i_dlm_acq_inflight back to 0) the grant is abandoned and the
 * P15-TCP-ORPH-PROCEED arm frees it after tcp_orphan_force_ms of persistence
 * — that is what s142a measured (885 ms).  hold_ms > 0 makes the injector
 * produce the OTHER shape, an acquirer still in flight (its count standing,
 * state NONE): the acquiring task keeps its count, sleeps for hold_ms, and
 * only then exits — without ever consuming.
 *
 * 0.89.65, MEASURED (s143b): the in-flight shape is NOT freed by the
 * same-gen strike escape — it was written expecting that, and the strike
 * sampler is never reached while the acquirer lives, because every gate
 * upstream of it treats acq_inflight > 0 as a live acquirer to protect
 * (P-ACQWIN-PARK in bast_notify, the busy re-arm in the dwork).  The strand
 * is parked for exactly the acquirer's lifetime and becomes the abandoned
 * shape when the count drops, which the arm then frees (1.4 s after
 * the injector's END line).  The harness asserts that design.
 */
static int mxfs_dbg_strand_hold_ms;
module_param_named(dbg_strand_hold_ms, mxfs_dbg_strand_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_strand_hold_ms, "TEST ONLY: with dbg_strand_ino, keep the dropped acquire IN FLIGHT (acq_inflight held) for this many ms before it exits, producing the in-flight strand shape; 0=exit at once (abandoned shape)");

/*
 * (D-TMPFILE-CHURN-the budget rule-PERF-400 term (c), instrument step 2): per-site
 * shadow counters for the four mxfs_dlm_verify_rawmode call sites, so a
 * workload's verify reads can be attributed (the ftrace saw 0.31 ms of
 * verify per linkat on a brand-new inode; the P108 site skips
 * self_created, the dir-EX CAW site deliberately does not).  Racy
 * WRITE_ONCE increments — telemetry, not invariants.
 */
unsigned long mxfs_verify_site_p108_n, mxfs_verify_site_direx_n,
	      mxfs_verify_site_s6_n, mxfs_verify_site_s7_n;
module_param_named(verify_site_p108_n, mxfs_verify_site_p108_n, ulong, 0444);
module_param_named(verify_site_direx_n, mxfs_verify_site_direx_n, ulong, 0444);
module_param_named(verify_site_s6_n, mxfs_verify_site_s6_n, ulong, 0444);
module_param_named(verify_site_s7_n, mxfs_verify_site_s7_n, ulong, 0444);

/*
 * (instrumented — block-dir concurrent-create durable WHOLE-BLOCK loss):
 * the modify-path dir refresh (mxfs_dlm_dir_modify_refresh) only drops cached
 * clean dir DATA blocks when the LOCAL per-node i_dlm_dir_gen advanced past
 * i_dlm_dir_evicted_gen.  That gen is a purely LOCAL slow-acquire counter
 * (measured DIVERGENT across nodes: test1 gen=4 vs test2 gen=33 for the same
 * reused dir inode), NOT a cross-node coherency signal — so a node holding a
 * clean-but-STALE cached dir block (a peer durably committed newer dirents into
 * it) whose local gen did not advance SKIPs the evict (P106-MR-SKIP) and RMWs
 * its own dirent onto the stale base, durably dropping the peer's whole block's
 * worth of just-created dirents (proven: a contiguous creation-order name range
 * = one dir DATA block vanishes from BOTH nodes).
 *
 * When set, force mxfs_dir_evict_data_blocks UNCONDITIONALLY on every cross-node
 * dir modify (not gated on the unreliable local gen).  SAFE: the evict only
 * drops DURABLE (clean / destaged-in-AIL) blocks — it SKIPS genuinely undurable
 * (dirty / pinned / delwri / un-destaged) blocks, so this node never loses its
 * own un-checkpointed in-flight work; it merely guarantees the next RMW
 * cold-FUA-rereads any clean cached block the peer may have superseded.
 */
/*
 * MASTER-AUTHORITATIVE dir-EX revalidate.  PROVEN root (
 * content-fingerprint timeline): the dir_reuse single-dirent loss is a
 * count-preserving DIVERGENT RMW under correct master serialization (monotonic
 * epoch, zero master double-grants, stable master) => a NON-MASTER node modifies
 * a shared dir under a CACHED i_dlm_mode==EX whose grant the master has already
 * moved to a peer (a phantom: the master's chain is authoritative, the node's
 * LOCAL mirror is stale, so the local held-check at :13965 cannot see it — TCP
 * has no on-disk-slot equivalent of the CAW phantom check).  When set, a
 * PUBLISHED, peer-reachable (!self_created) directory EX-MODIFY does NOT take the
 * cached fast path: it falls through to a real slow-path DLM acquire which (on a
 * non-master node) ALWAYS round-trips the master.  The master either REAFFIRMS
 * (we genuinely hold -> cheap, no eviction) or, if a peer holds, SERIALIZES
 * (queue+BAST the peer, grant us fresh) — restoring mutual exclusion exactly like
 * the existing unpublished-dir divert (14070) does for unpublished inodes.
 * Default OFF; A/B test on 8/tcp dir_reuse.  pin_count==0 (checked at the divert
 * site) guarantees no AGF is held so the blocking acquire cannot ABBA-deadlock.
 */
int mxfs_dir_ex_revalidate;
module_param_named(dir_ex_revalidate, mxfs_dir_ex_revalidate, int, 0644);

/*
 * RELIABLE-HANDOFF REFRESH.  The fast-path dir-EX refresh is armed
 * by the master's dg_shadow handoff bit (lk->handoff), which /proved
 * UNDER-FIRES ~80% on TCP (P51-HANDOFF-UNDERFIRE: the per-grant token advanced =
 * lock changed hands, but the handoff bit was FALSE) — so a cross-node handoff
 * serves a STALE cached dir base and the addname RMW durably clobbers the peer's
 * whole committed block (dir_reuse readdir undercount, PROVEN node2's
 * entire 100-entry contribution lost).  The per-grant token (grant_gen) is the
 * RELIABLE "lock changed hands" signal the handoff bit is not.  When set, arm the
 * loss-safe drain_evict refresh on EVERY grant_gen change — but with
 * dir_ex_handoff=false (EVICT-ONLY, NOT the post_release disk-superset ADOPT):
 * grant_gen also advances on a re-affirm we hold CONTINUOUSLY (our work not yet
 * durable), where a disk-adopt would REVERT our uncommitted dirents (the
 * over-fire that resurrected deletes).  drain_evict evicts only CLEAN/destaged
 * blocks and SKIPS undestaged/dirty/pinned ones, so it refreshes a peer-superseded
 * clean base while keeping our in-flight work in BOTH cases — reliable AND safe.
 */
int mxfs_dir_gg_refresh = 1;
module_param_named(dir_gg_refresh, mxfs_dir_gg_refresh, int, 0644);
MODULE_PARM_DESC(dir_gg_refresh,
	"arm the loss-safe evict-only dir base refresh on every grant_gen change (reliable cross-node handoff signal); 1=on (default)");
MODULE_PARM_DESC(dir_ex_revalidate,
	"force a master-authoritative slow-path re-acquire on every published shared-dir EX modify (kills the TCP phantom cached-EX divergent RMW); 1=on");

/*
 *  — how long mxfs_dlm_reload_inode waits for an active
 * release drain before giving up on the reload (P34J).  See the long note at
 * the bail: abandoning that reload leaves i_dlm_dir_valid_epoch behind the
 * master dir epoch, and P32E-DIREPOCH-FENCE then silently drops every flush of
 * whatever the operation goes on to commit.  0 restores the earlier
 * bail-immediately behaviour for A/B.  Bounded so a drain blocked on a lock we
 * hold costs only the bound, never a deadlock.
 */
/*
 *  — divert a dir EX MODIFY to the slow path when this
 * inode's grant is actively being drained away (i_dlm_demoter set by another
 * task).  See the long note at the divert gate: serving a cached EX in that
 * window is what produces the epoch-stale-base mutation (P195) that no later
 * freshness gate can undo, because the tenure is already dirty by then.
 *
 * MEASURED AND REFUTED, which is why the default is 0.  Paired
 * fresh-prep 60-round storms on 0.11.177:
 *     dir_ex_divert_on_demote=1 : P195=11
 *     dir_ex_divert_on_demote=0 : P195= 5      (durable losses 0 in BOTH)
 * The divert makes the epoch-stale-base mutation MORE frequent, not less --
 * the slow-path acquire it forces takes longer, which gives peers more time to
 * advance the dir epoch before we look.  So the demoter-active fast-path serve
 * is NOT the producer of P195.  Kept at 0 (code + lever retained: the analysis
 * in the divert-gate comment is the evidence for what the producer is NOT).
 * Do not re-enable without a measurement that moves P195 DOWN.
 */
int mxfs_dir_ex_divert_on_demote;	/* REFUTED, default OFF — see below */
module_param_named(dir_ex_divert_on_demote, mxfs_dir_ex_divert_on_demote, int, 0644);
MODULE_PARM_DESC(dir_ex_divert_on_demote,
	"divert a dir EX modify to the slow path while a release drain owns this inode; 1=on (default)");
static unsigned long long mxfs_file_yield_n;
module_param_named(file_yield_n, mxfs_file_yield_n, ullong, 0444);
MODULE_PARM_DESC(file_yield_n, "read-only: how many file fast-path admissions yielded to a peer's pending request");
int mxfs_dir_gen_per_handoff = 1;	/* DEFAULT 0.  The fast-path epoch-handoff gen-bump is CAPPED by `i_dlm_dir_gen <= i_dlm_dir_loaded_gen` → it bumps only ONCE per reload cycle, so the 2nd+ intra-round fast-path handoff does NOT re-invalidate (cached block stays bgen==dirgen==N and aliases a peer-superseded image as fresh = the readdir=799/whole-block clobber, PROVEN dataclobber=1: bufgen==dirgen==379).  When set, bump i_dlm_dir_gen on EVERY cross-node epoch handoff (uncapped) so the read-path pre-read invalidation (bgen<dir_gen) fires on every handoff and the holder never RMWs/destages a stale base.  Safe: the master epoch advances ONLY on a real cross-node handoff (a peer held EX) — never while we hold EX continuously — so it cannot spuriously re-read mid-tenure.  TCP write-through stack only (the refutation — FUA-refresh misses own target-write-cached dirent — does NOT apply: emulate_write_cache=0, writes are platter-durable). */
module_param_named(dir_gen_per_handoff, mxfs_dir_gen_per_handoff, int, 0644);

int mxfs_dir_stalegen_adopt = 1;
module_param_named(dir_stalegen_adopt, mxfs_dir_stalegen_adopt, int, 0644);
MODULE_PARM_DESC(dir_stalegen_adopt,
                 "Rebuild a shortform dir fork from disk on the cached-EX "
                 "fast path when dir_gen > loaded_gen: 1=on (default)");
/* 32-node cache_coherency shared-dir reload-storm gate.
 * The slow-path fresh dir grant unconditionally stales+bumps-gen+reloads (FUA
 * re-read); measured as the storm (RELOAD-STALE-SPLIT modeN=511 ~75% dirs).
 * When on, skip that reload iff there was NO genuine cross-node EX handoff on
 * the dir since our last adopt (Invariant 1: peer modify needs EX+drain, so
 * !peer_ex => our cached dir is authoritative).  Default 0. */
int mxfs_dir_slow_handoff_gate;
atomic64_t mxfs_dir_slow_skip;	/* count of averted slow-path dir reloads */

/*
 * (design review DLM-epoch lineage guard): node-global
 * monotonic counter, bumped every time ANY inode on this node transitions into
 * a fresh EX grant.  Each inode snapshots it into i_mxfs_ex_grant_seq on EX
 * acquire and into i_mxfs_dirty_seq when logged under EX.  At flush time a
 * mismatch proves the dirty state predates the current EX tenure (we yielded EX
 * and re-took it, so a peer may have freed/reused the on-disk inode) -> skip the
 * flush rather than clobber the peer's live incarnation.  Starts at 1 so the
 * zero-initialized "never granted EX" state never spuriously matches a real
 * tenure.
 */
atomic64_t mxfs_ex_epoch = ATOMIC64_INIT(1);

/*
 * (b56r1 double shutdown) — HARD dir-EX tenure cap while a
 * peer BAST is pending.  The MHT batch arm keeps a BASTed dir grant CACHED
 * (fast path open) so the local create burst amortizes the handoff, and the
 * dwork is supposed to end the window — but its quiet-age gate re-arms while
 * the local burst is live, so under CONTINUOUS hot-dir churn the window never
 * closes: b56r1 test1 batched 78 episodes on dir 131 without one release for
 * 184s while both of test2's ops starved to -110/dirty-cancel/shutdown (and
 * test2's stalled create held a child-ino reservation that starved test1's
 * lookups right back — a cross-node cycle whose every edge traces to the
 * unbounded tenure).  Once a pending BAST's tenure exceeds this cap, the dir
 * fast path stops admitting (state flips to BAST) so holders drain and the
 * normal refire/redrive machinery hands the grant over.  Sits well above the
 * batching floor (inode_mht_ms=300 + grace) and far below the ~60s acquire
 * timeout.
 */
int mxfs_dir_ex_tenure_cap_ms = 1000;
module_param_named(dir_ex_tenure_cap_ms, mxfs_dir_ex_tenure_cap_ms, int, 0644);

/*
 * — the ino-131 PR self-revoke storm lever (instrumented A/B).
 * i_dlm_stale is the NEEDS-RELOAD signal; the peer-revoke signal is carried
 * EXCLUSIVELY by i_dlm_bast_during_acq since (bast_notify's ACQUIRING
 * branch sets BOTH).  The slow-path grant-completion check nonetheless
 * self-BASTs (state=BAST + queue bast_process = full DLM release) whenever
 * i_dlm_stale survives to it — every keep-stale reload bail or a concurrent
 * prior release's bast_process (which re-marks stale) converts a healthy
 * fresh grant into an immediate release; the released tenure's bast_process
 * re-poisons stale, so the next path-walk repeats it.  dlm_scaling FAIL
 * 20260703T210920Z: 11,445 PR release/reacquire cycles on ino 131 on test1
 * in 13s with ZERO real BASTs (P7S-BAST-FIRE=0, P7B-BASTNOTIFY=0) -> every
 * walk pays a full TCP DLM round-trip + dir-block invalidation + drain ->
 * <50 ops/s rate-floor FAIL (peers: 212 ops/s).
 * 1 = legacy: self-BAST on stale alone (the storm).  0 = keep the grant
 * CACHED; leave i_dlm_stale set for the on-use reload paths (ilock_try
 * rejects on stale -> slow-path reload; readdir/lookup/modify-prelock
 * re-check it).  Real deferred BASTs (acq_bast) are honored either way.
 */
int mxfs_acq_stale_selfbast = 1;
module_param_named(acq_stale_selfbast, mxfs_acq_stale_selfbast, int, 0644);

/* close the CAW phantom-EX window — run the
 * un-throttled dir-EX held-verify (one 512B slot read per pin-free dir-EX
 * cache-hit) on the CAW transport too, exactly as sess-tcp added for TCP.
 * See the transport gate in mxfs_dlm_ilock_begin.  0 = CAW keeps only the
 * throttled 1/100ms P108 verify (earlier behavior, phantom window open). */
int mxfs_dir_ex_verify_caw = 1;
module_param_named(dir_ex_verify_caw, mxfs_dir_ex_verify_caw, int, 0644);
MODULE_PARM_DESC(dir_ex_verify_caw,
	"un-throttled dir-EX on-disk held-verify on CAW (closes the phantom cached-EX divergent-RMW window); 1=on");

/*
 * D-0532: every unpaired inode DLM end, counted exactly.  P71-UNDERFLOW
 * prints at most 300 lines per load, so once a workload has spent that
 * budget a later window reads zero whatever happens; a verification arm
 * resets this and reads it instead.  Counts only while the cluster is
 * multi-node, the same condition under which the line prints.
 */
atomic_t mxfs_p71_underflows = ATOMIC_INIT(0);

/* D-0970 follow-up, on a sole survivor (single-node now, but it has had a
 * peer, so its begin counts holders): IOLOCK demotes performed there, and
 * ends that found no holder (p71_underflows counts multi-node only). */
atomic_t mxfs_demote_survivor = ATOMIC_INIT(0);
atomic_t mxfs_end_unpaired_single = ATOMIC_INIT(0);
atomic_t mxfs_dioend_admit = ATOMIC_INIT(0);

/*
 * How old a master's queue receipt may be and still count as evidence that
 * the master has this acquire's request.
 *
 * Derived, not chosen: a requester re-sends the request every
 * MXFS_LOCK_ACQUIRE_WAIT_MS (1000 ms) for as long as it is waiting, and the
 * master answers every re-queue with a receipt, so receipts arrive about once
 * a second while the wait is healthy.  The window has to absorb a burst of
 * lost messages and the scheduling and response jitter of both ends: ten
 * missed sends plus a five-second allowance.  It is NOT derived from how long
 * a release drain takes — a drain of any length keeps refreshing receipts, so
 * the two are independent, and tying this to drain duration would blind the
 * check for exactly as long as the longest drain.
 */
unsigned int mxfs_acq_receipt_stale_ms = 15000;
module_param_named(acq_receipt_stale_ms, mxfs_acq_receipt_stale_ms, uint, 0644);
MODULE_PARM_DESC(acq_receipt_stale_ms,
	"how old a master's queue receipt may be and still justify waiting on it (ms)");
/*
 * ROOT FIX for the tcp_dlm_scaling / dlm_fairness
 * durable shortform-dirent RESURRECTION.
 *
 * PROVEN (instrumented, P-SFM-READD with state+gen): the resurrected dirent
 * (e.g. n1_i2_r119 -> ino 132, node's OWN file) is re-added by the cached-EX
 * FAST PATH (i_dlm_state == CACHED, peer_mod=0) sf_refresh 3-way merge.  On a
 * continuous-hold fast path NO peer could have modified the dir (a peer modify
 * needs EX, which BASTs us off CACHED), so the in-core fork is AUTHORITATIVE.
 * The on-disk image can only LAG it — specifically when xfsaild async-destages
 * an intermediate create that this node has since removed in-core WITHOUT a
 * release/drain (no BAST between create and remove).  The merge then sees that
 * entry "in theirs, !ours, !base" and mis-classifies the node's own
 * durable-but-removed entry as a peer-add -> re-adds it -> the node later
 * flushes it back durably -> resurrection (the peer then adopts it on its
 * slow-path reload).  The SLOW path (reacquire after BAST) drains on release so
 * disk is consistent there — which is why node1-churn + node2-READ-only never
 * leaks (node1 only ever takes the drained slow path).
 *
 * FIX: on the cached fast path the in-core fork is authoritative; do NOT adopt
 * the (lagging) on-disk image.  Peer changes are adopted on the slow-path
 * reacquire reload, which the BAST-demote forces and which is already correct.
 * Default 0 = fixed (no fast-path adopt).  Set =1 to restore the old
 * fast-path sf_refresh (pre-fix behaviour) for A/B comparison.
 */
int mxfs_sf_fastpath_adopt;	/* 0=in-core authoritative on fast path (fix) */

/* ─── Lock path ─── */

/*
 * (PROVEN BY INSTRUMENT): cooperative cached-AG yield to break the
 * cross-resource dir-inode-EX <-> AG-DLM distributed deadlock that shuts
 * down tcp_dlm_scaling (nodes_pass=0/2).
 *
 * PROVEN deadlock (both nodes UTC, dir ino=131, AG0):
 *   node A: holds the shared-dir inode EX inside a DIRTIED remove/create txn,
 *           then blocks ~60s acquiring AG_k's DLM grant -> -ETIMEDOUT ->
 *           xfs_trans_cancel on a DIRTY trans -> "Corruption of in-memory
 *           data" -> FILESYSTEM SHUTDOWN (xfs_trans.c:1060).
 *   node B: holds AG_k CACHED (from a PRIOR op; no active holder, not in any
 *           txn) and blocks acquiring the SAME dir inode EX for its next op.
 * The cycle exists only because AG DLM locks are CACHED across ops: B
 * effectively holds AG_k "before" the dir inode, inverting A's [inode, AG]
 * acquisition order.  The existing PRE-CAW cooperative drain only runs
 * from the AG acquire path; nothing yields a cached AG while we block on an
 * INODE lock.  So when B is the one stuck on the inode, it never lets go of
 * AG_k and A wedges to shutdown.
 *
 * Fix: when an inode-DLM acquire is contended, yield any cached AG a peer has
 * BAST'd (cached && bast_pending && holders==0 && !demoting) that we are not
 * actively using.  B yields AG_k -> A's AG acquire completes -> A finishes its
 * txn and releases the dir inode -> B acquires it.  This mirrors the
 * prescription-G drain body exactly (bounded stall, inline bast_work_fn);
 * only the call site is new.  Eligibility requires holders==0, so an AG the
 * current op is actively holding is never yielded.  Returns #AGs drained.
 */
static int
mxfs_dlm_yield_basted_cached_ags(
	struct xfs_mount	*mp)
{
	xfs_agnumber_t		scan_agno;
	int			drained = 0;
	extern int		mxfs_ag_bast_stall_iters;
	int			saved_stall;

	if (!mp->m_mxfs_dlm)
		return 0;

	saved_stall = mxfs_ag_bast_stall_iters;
	/* Short stall (~2s) so a stuck drain doesn't hold up our own acquire. */
	mxfs_ag_bast_stall_iters = 200;
	for (scan_agno = 0; scan_agno < mp->m_sb.sb_agcount; scan_agno++) {
		struct xfs_perag	*scan;
		bool			eligible;

		scan = xfs_perag_get(mp, scan_agno);
		if (!scan)
			continue;
		/* PERF: lockless fast-skip.  This runs before
		 * EVERY slow-path inode DLM acquire (57k+ in 8-node dir_reuse);
		 * the overwhelmingly common case is NO cached AG has a pending
		 * BAST.  Read pag_dlm_bast_pending without the mutex (a stale
		 * read just means we re-confirm under the lock); only pay the
		 * mutex when a BAST actually looks pending.  Removes ~agcount
		 * mutex ops per acquire on the uncontended path. */
		if (!READ_ONCE(scan->pag_dlm_bast_pending)) {
			xfs_perag_put(scan);
			continue;
		}
		mxfs_pag_dlm_lock(scan, MXFS_SITE);
		eligible = scan->pag_dlm_cached &&
			   scan->pag_dlm_bast_pending &&
			   scan->pag_dlm_holders == 0 &&
			   !scan->pag_dlm_demoting;
		/* instrumented diagnostic: when an AG is held/cached but NOT
		 * yieldable, log WHY — so the inode<->AG deadlock (test1 stuck on
		 * an AG test2 holds) reveals whether the blocker is holders>0
		 * (active op, e.g. inodegc), missing bast_pending (BAST not
		 * delivered), or demoting.  Gated behind instr: it was
		 * firing 2.4M× (always-on pr_warn_ratelimited takes a spinlock
		 * even when suppressed) on the dir_reuse hot path. */
		if (unlikely(mxfs_instr_enabled) && !eligible &&
		    (scan->pag_dlm_cached || scan->pag_dlm_bast_pending ||
		     scan->pag_dlm_holders > 0 || scan->pag_dlm_demoting))
			mxfs_probe_ratelimited(
			    "mxfs: P58-AGSTATE ag=%u cached=%d bast_pending=%d holders=%d demoting=%d rel_pend=%d (not yieldable)\n",
				scan_agno, scan->pag_dlm_cached ? 1 : 0,
				scan->pag_dlm_bast_pending ? 1 : 0,
				scan->pag_dlm_holders,
				scan->pag_dlm_demoting ? 1 : 0,
				scan->pag_dlm_release_pending ? 1 : 0);
		mxfs_pag_dlm_unlock(scan, MXFS_SITE);
		if (eligible) {
			/* D1 ROOT FIX: NEVER wait for
			 * an in-flight bast_work_fn here.  The caller can hold
			 * an ILOCK the drain needs (inode-DLM acquire runs deep
			 * inside ILOCKed alloc paths); cancel_work_sync then
			 * deadlocks: the drain stall-aborts and re-arms every
			 * BAST cycle, so the sync wait never ends (P67-STALL
			 * stack capture: bash parked in __flush_work under
			 * xfs_bmapi_convert_one_delalloc — the E 222s
			 * silent park / spurious-shutdown chain).  Steal a
			 * PENDING work with non-blocking cancel_work(); if the
			 * work is RUNNING it already owns this drain — skip.
			 */
			if (!cancel_work(&scan->pag_dlm_bast_work) &&
			    (work_busy(&scan->pag_dlm_bast_work) &
			     WORK_BUSY_RUNNING)) {
				mxfs_probe_ratelimited(
				    "mxfs: P67-NOWAIT-SKIP ag=%u yield-scan — in-flight bast work owns drain; not waiting (ILOCK deadlock guard)\n",
					scan_agno);
				xfs_perag_put(scan);
				continue;
			}
			mxfs_pag_dlm_lock(scan, MXFS_SITE);
			eligible = scan->pag_dlm_cached &&
				   scan->pag_dlm_bast_pending &&
				   scan->pag_dlm_holders == 0 &&
				   !scan->pag_dlm_demoting;
			if (eligible)
				scan->pag_dlm_bast_scheduled = true;
			mxfs_pag_dlm_unlock(scan, MXFS_SITE);
		}
		if (eligible) {
			mxfs_idbg("mxfs: P13-INODE-YIELD-AG draining cached-basted ag=%u to break inode<->AG deadlock\n",
				scan_agno);
			mxfs_dlm_ag_bast_work_fn(&scan->pag_dlm_bast_work);
			drained++;
		}
		xfs_perag_put(scan);
	}
	mxfs_ag_bast_stall_iters = saved_stall;
	return drained;
}

/*
 * FIX-25 (a9a03929, run109 test6 LIVE-STACK PROVEN): admit the
 * xfs-conv ioend completion worker to a nested EX while a BAST/DEMOTING
 * drain is in flight and the DLM mirror still holds EX.
 *
 * The 3-task cycle it breaks (all three stacks captured live on test6,
 * wedged 150s+, fence_during_write 0/8):
 *   bast_process → filemap_write_and_wait → folio_wait_writeback
 *   ← the folio's writeback only ends when xfs_end_ioend converts the
 *     unwritten extent, which does xfs_trans_alloc_inode → xfs_ilock(EX)
 *   ← which sat in this demote-wait because state was BAST/DEMOTING.
 *
 * While the mirror is still EX-granted to us, a nested EX admit is exactly
 * the P15-REL-ABORT re-acquire case: the release pipeline aborts at its
 * holders!=0 gate and re-arms, the conversion finishes, writeback ends,
 * the drain completes on the next pass.  Called and returns with
 * ip->i_dlm_lock held (may drop/retake it for the mirror query); true =
 * admitted (caller unlocks and returns).
 */
static bool
mxfs_ilock_admit_ioend(struct xfs_inode *ip, uint8_t mode)
{
	uint8_t g2;
	bool in_wb;
	bool in_dio;

	/* FIX-26 (test8 live capture): writeback
	 * SUBMISSION tasks (bdi flusher / sync / fsync inside
	 * xfs_vm_writepages) hold the FOLIO LOCK across ->map_blocks'
	 * delalloc conversion, which takes xfs_ilock(EX) -> here.  Parking
	 * them in the demote-wait while state=BAST deadlocks permanently:
	 * the bast drain's filemap_write_and_wait sits in __folio_lock on
	 * the folio the submitter holds (both workers captured D-state:
	 * kworker+flush-8:0 in mxfs_dlm_ilock_begin under
	 * iomap_writepage_map <-> mxfs-ino-bast in __folio_lock under
	 * mxfs_dlm_bast_process; P73 ino=10485894 req=5 mode=3 state=3
	 * work_busy=3 every 30s for 70+ min).  Admit them exactly like
	 * ioend completion: nested EX under a still-granted EX/PR mirror,
	 * counted in ex_holders so the release pipeline aborts at its
	 * holders!=0 gate and re-arms after the conversion lands. */
	in_wb = xfs_task_in_writepages();
	/* D-0971: this inode's own direct-write completion (unwritten
	 * conversion / size update under ILOCK_EXCL), which the release
	 * pipeline's direct-I/O wait depends on.  Admitted exactly like the
	 * ioend worker: EX request only, nested under the granted mirror. */
	in_dio = xfs_task_in_dio_end(ip);
	/*
	 * FIX-27 (test27 live capture): FIX-26 above
	 * admitted the writeback SUBMITTER only when it asked for EX, but the
	 * submitter's FIRST ilock in that path is SHARED, not exclusive —
	 * xfs_map_blocks() does xfs_ilock(ip, XFS_ILOCK_SHARED) to read the
	 * extent map (pal/linux/xfs_aops.c:532) and needs EX only later, for a
	 * delalloc conversion.  So a submitter reaching ->map_blocks on an
	 * inode whose extents need no conversion requests PR, fails the
	 * EX-only gate, parks in the demote-wait while still holding the folio
	 * lock, and deadlocks against the drain waiting for that folio.
	 *
	 * Captured live on test27 (32/caw, 0.11.201), both legs:
	 *   kworker/u9:29+mxfs-ino-bast/dm-1  wchan=folio_wait_bit_common
	 *     filemap_write_and_wait_range <- mxfs_dlm_bast_process
	 *   kworker/u12:30+flush-252:1       wchan=mxfs_dlm_ilock_begin
	 *     xfs_ilock <- xfs_map_blocks <- iomap_writepage_map
	 * plus 4+ `sync` piled on wb_wait_for_completion / sync_inodes_sb,
	 * loadavg 20.4, 21 tasks in D state, unchanged PIDs over many minutes.
	 * The node stayed mounted and readable, so it passed every liveness
	 * check while being permanently unable to finish a sync — and because
	 * barrier criteria need every rank, that ONE node made seven criteria
	 * report nodes_pass=0/32.
	 *
	 * Admitting a SHARED request is strictly safer than the EX admit this
	 * function already performs: the submitter only READS the extent map,
	 * under a mirror still holding EX or PR (verified by the g2 query
	 * below), so no peer can be mutating it — a granted PR excludes any
	 * peer EX, and the pending writeback is by construction OUR data from
	 * OUR tenure.  Refusing is not the conservative choice: our own drain
	 * is already blocked on that task's folio, so refusing is a GUARANTEED
	 * deadlock rather than a possible one.
	 *
	 * Scope: widened for the writeback-submission context ONLY.  The ioend
	 * completion worker genuinely needs EX and is already covered.
	 */
	if (!xfs_task_in_ioend() && !in_wb && !in_dio)
		return false;
	{
		extern int mxfs_fix27_shared_admit;

		if (mode != MXFS_LOCK_EX &&
		    !(mxfs_fix27_shared_admit && in_wb &&
		      (mode == MXFS_LOCK_PR || mode == MXFS_LOCK_CR)))
			return false;
	}
	if (!ip->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		return false;
	if (ip->i_dlm_state != MXFS_DLM_ISTATE_DEMOTING &&
	    ip->i_dlm_state != MXFS_DLM_ISTATE_BAST)
		return false;
	spin_unlock(&ip->i_dlm_lock);
	/* ICLUSTER-routed files have no per-inode mirror entry — the cluster
	 * object's disk_mode is the equivalent granted-mode truth (in-memory
	 * either way). */
	g2 = ip->i_dlm_routed_iclus ?
		mxfs_iclus_granted_mode(ip->i_mount, ip->i_ino) :
		mxfs_v5_dlm_inode_granted_mode(ip->i_mount->m_mxfs_dlm,
					       ip->i_ino);
	spin_lock(&ip->i_dlm_lock);
	/*
	 * FIX-25 WIDENING (test2 live wedge, all three stacks
	 * captured): the same 3-task cycle recurred with the mirror at PR —
	 * bast_process(folio_wait_writeback) ← xfs_end_ioend needs EX ←
	 * demote-wait refused because g2==PR failed the EX-only check, and the
	 * ino's own queued bast sat behind the stuck ORDERED-wq head forever
	 * (P73-WAITSTALL req=5 mode=3 state=3 for 900s+; fence+tds 0/4).
	 * Admitting under PR is cluster-safe: a granted PR excludes any peer
	 * EX, so no remote mutator can race the conversion; the pending
	 * writeback is by construction OUR data from OUR tenure.  Do NOT
	 * elevate i_dlm_mode for the PR case — the nested admit is scoped to
	 * this in-ioend task via ex_holders; leaving mode=PR keeps every other
	 * local thread off the EX fast path.
	 */
	if ((ip->i_dlm_state != MXFS_DLM_ISTATE_DEMOTING &&
	     ip->i_dlm_state != MXFS_DLM_ISTATE_BAST) ||
	    (g2 != MXFS_LOCK_EX && g2 != MXFS_LOCK_PR))
		return false;
	/*
	 * 0.75.43 (D-0918): count the admit in the counter the matching
	 * ilock_end will decrement.  FIX-27 admits the writeback submitter's
	 * SHARED request but every admit was booked in i_dlm_ex_holders, so
	 * the PR unlock underflowed pr_holders (P71-UNDERFLOW mode=PR
	 * un=xfs_map_blocks) and one EX hold leaked for the life of the
	 * in-core inode.  The leaked hold deferred every later BAST on the
	 * file forever; the peer's unlink then held the parent directory
	 * while waiting for the file, this node's next lookup waited for the
	 * parent, and both nodes sat parked behind a "live holder" that did
	 * not exist (two-node TCP, 0.75.41, s523h/s523m: 476 and 479 request
	 * deadlines over eight minutes, prep unable to unmount either node).
	 */
	if (in_dio) {
		atomic_inc(&mxfs_dioend_admit);
		/* A direct write's ride is EX by submission on a clustered
		 * mount (0.87.2), so its completion meets an EX mirror; a PR
		 * mirror here is an invariant failure worth naming.  Admitting
		 * under it is still cluster-safe (a granted PR excludes any
		 * peer EX) and refusing would deadlock the wait. */
		if (g2 != MXFS_LOCK_EX)
			mxfs_probe_ratelimited("mxfs: P971-DIOEND-UNDER-PR ino=%llu g2=%u mode=%u state=%u comm=%s — a direct-write completion met a PR mirror\n",
				(unsigned long long)ip->i_ino, g2,
				ip->i_dlm_mode, ip->i_dlm_state, current->comm);
	}
	if (mode == MXFS_LOCK_EX) {
		ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
		if (g2 == MXFS_LOCK_EX && ip->i_dlm_mode < MXFS_LOCK_EX)
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_EX;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		mxfs_p71_hold(ip, "begin-ioend", 1, 0);
	} else {
		ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
		mxfs_p71_hold(ip, "begin-ioend", 0, 1);
	}
	{
		static atomic_t p25io = ATOMIC_INIT(0);

		if (atomic_inc_return(&p25io) <= 2000)
			mxfs_probe("mxfs: P25-IOEND-ADMIT ino=%llu state=%u g2=%u req=%u now_ex=%u now_pr=%u src=%s — admitted during drain (deadlock breaker)\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_state, g2, mode,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				in_wb ? "writepages" : "ioend");
	}
	return true;
}

/*
 * ( a864) shutdown withdrawal.  xfs_do_force_shutdown must not
 * sleep, so it queues this work; the work fn runs the sleeping v5 withdraw
 * (fence all new acquires + stop the disklock heartbeat so peers' dead-node
 * purge reclaims our slots).  put_super NULLs m_mxfs_dlm and cancels the
 * work before freeing the ctx, so the run-time pointer read here is safe.
 */
void
mxfs_dlm_withdraw_work_fn(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_withdraw_work);

	mxfs_v5_dlm_shutdown_withdraw(mp->m_mxfs_dlm);
}

void
mxfs_dlm_shutdown_withdraw(
	struct xfs_mount	*mp)
{
	if (!mp->m_mxfs_dlm)
		return;
	/*
	 * (D-0286): poison the DLM session SYNCHRONOUSLY, here, before
	 * the work is even queued.  The sleeping half (heartbeat withdraw,
	 * discovery stop) still runs from the workqueue, but the departure
	 * state and the acquire/master/goodbye gates must not depend on
	 * workqueue timing: a teardown or a release walker that observes the
	 * shutdown observes the poison in the same instant.  Non-sleeping
	 * (one xchg + printk).
	 */
	mxfs_v5_dlm_poison(mp->m_mxfs_dlm, "force-shutdown");
	pr_warn("mxfs: P-WITHDRAW-QUEUE — FS shut down; scheduling cluster DLM withdrawal\n");
	schedule_work(&mp->m_mxfs_withdraw_work);
}

/*
 * Called from xfs_ilock() before VFS i_rwsem acquisition.
 * Fast path: if DLM lock already cached at sufficient mode,
 * just increment holder count (zero DLM I/O).
 */

/* ICLUSTER routing (DLM_PLAN.md): regular files
 * under mxfs.icluster_dlm=1 on the CAW transport acquire/release their
 * dinode coherence through the inode-cluster mediating layer (defined at
 * end of file); everything else keeps the per-inode resource.  With the
 * knob at 0 (default) these compile to the legacy calls exactly. */
bool
mxfs_iclus_routed(struct xfs_inode *ip)
{
	return mxfs_icluster_dlm && S_ISREG(VFS_I(ip)->i_mode) &&
	       ip->i_mount->m_mxfs_dlm &&
	       mxfs_v5_dlm_transport_caw(ip->i_mount->m_mxfs_dlm);
}

/* Non-static twin for out-of-file callers (xfs_inactive's double-free
 * guard): is this inode's dinode coherence carried by its inode-cluster
 * resource? */
bool
mxfs_dlm_iclus_covered(struct xfs_inode *ip)
{
	return mxfs_iclus_routed(ip);
}

/*
 * step 5.3(d): `gen_snap` is i_mxfs_auth_gen sampled under i_dlm_lock
 * BEFORE this acquire descended into the DLM.  It is the stale-completion
 * guard: any relinquishment between the sample and the install moves the
 * counter and the tenure is refused.  Pass MXFS_AUTH_GEN_NONE to acquire
 * without installing authority (probe/nudge callers).
 */
int
mxfs_dlm_inode_lock_routed(struct xfs_inode *ip, uint8_t mode, uint64_t gen_snap)
{
	struct mxfs_grant_result gres;

	if (mxfs_iclus_routed(ip)) {
		int rc = mxfs_iclus_lock(ip->i_mount, ip->i_ino, mode, &gres);

		if (rc == 0) {
			bool conv_pi;

			spin_lock(&ip->i_dlm_lock);
			/* Sticky routing: this grant is cluster-backed from
			 * here on.  A LIVE per-inode grant from a mode-0-era
			 * acquire (dead-shell recycle) must be dropped NOW or
			 * its slot bits orphan forever (release routes by the
			 * sticky bit).  Only PR grants can exist in that
			 * window (mode-0 shells are read/reload paths), so
			 * the raw drop needs no drain. */
			conv_pi = !ip->i_dlm_routed_iclus &&
				  ip->i_dlm_mode != MXFS_LOCK_NL &&
				  !ip->i_dlm_unpublished &&
				  !ip->i_mxfs_self_created;
			/* unpublished/self-created grants are LOCAL-only
			 * (no slot was ever claimed) — nothing to drop;
			 * gating avoids a wasted device CAS per create. */
			/*
			 * A BACKING CHANGE IS AN AUTHORITY-TENURE TRANSITION
			 * (ruling, coverage gap iii).  Whatever the
			 * per-inode slot proved dies here, BEFORE the drop
			 * below makes the relinquishment visible.  Absorb our
			 * own gen bump into gen_snap so this acquire can
			 * still install the NEW cluster-backed tenure — but
			 * only when nobody ELSE had already moved the counter,
			 * which is what the equality test preserves.
			 */
			if (!ip->i_dlm_routed_iclus) {
				bool mine = (ip->i_mxfs_auth_gen == gen_snap);

				mxfs_inode_authority_revoke_locked(ip,
								   MXFS_SITE);
				if (mine)
					gen_snap = ip->i_mxfs_auth_gen;
			}
			ip->i_dlm_routed_iclus = true;
			/*
			 * A routed disk claim IS the publish.  De-list HERE,
			 * inside i_dlm_lock and BEFORE the install, because the
			 * install refuses any inode still flagged unpublished
			 * (it has no durable slot of its own) — the very
			 * UNPUBLISHED_EX -> DURABLE_EX promotion this claim
			 * earns.  conv_pi above was already computed from the
			 * pre-de-list value, so the wasted-CAS gate is intact.
			 * Nesting i_dlm_lock -> m_mxfs_unpub_lock is a new but
			 * consistent order: no m_mxfs_unpub_lock section in the
			 * tree takes i_dlm_lock (verified over all 10 sites).
			 * The sweep design has no per-grant count to unbalance,
			 * so the de-list is bookkeeping hygiene that stops the
			 * deferred-publish walkers re-claiming a covered inode.
			 */
			if (ip->i_dlm_unpublished) {
				spin_lock(&ip->i_mount->m_mxfs_unpub_lock);
				ip->i_dlm_unpublished = false;
				list_del_init(&ip->i_dlm_unpub_link);
				spin_unlock(&ip->i_mount->m_mxfs_unpub_lock);
			}
			mxfs_dlm_authority_install(ip, &gres, gen_snap, true,
						   MXFS_SITE);
			spin_unlock(&ip->i_dlm_lock);
			if (conv_pi) {
				mxfs_v5_dlm_inode_unlock(
					ip->i_mount->m_mxfs_dlm, ip->i_ino);
				mxfs_probe_ratelimited(
				    "mxfs: P-ICLUS-CONV ino=%llu mode=%u — mode-0-era per-inode grant dropped; coverage now cluster-backed\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode);
			}
		}
		return rc;
	}
	{
		int rc;

		/* ABBA breaker: xfs_lock_two_inodes bounds
		 * its SECOND inode's acquire (it holds the first's grant-hold;
		 * an unbounded wait here while the peer symmetrically waits on
		 * OUR first inode is the proven 184s cross-node deadlock). */
		if (ip->i_dlm_tries_owner == current && ip->i_dlm_tries > 0)
			rc = mxfs_v5_dlm_inode_lock_retries(
				ip->i_mount->m_mxfs_dlm, ip->i_ino, mode,
				ip->i_dlm_tries, &gres);
		else
			rc = mxfs_v5_dlm_inode_lock(ip->i_mount->m_mxfs_dlm,
						ip->i_ino, mode, &gres);

		if (rc == 0) {
			spin_lock(&ip->i_dlm_lock);
			/* Mirror of the routed arm: a cluster -> per-inode
			 * backing change ends the old tenure first. */
			if (ip->i_dlm_routed_iclus) {
				bool mine = (ip->i_mxfs_auth_gen == gen_snap);

				mxfs_inode_authority_revoke_locked(ip,
								   MXFS_SITE);
				if (mine)
					gen_snap = ip->i_mxfs_auth_gen;
			}
			ip->i_dlm_routed_iclus = false;
			mxfs_dlm_authority_install(ip, &gres, gen_snap, false,
						   MXFS_SITE);
			spin_unlock(&ip->i_dlm_lock);
		}
		return rc;
	}
}

/*
 * 0.74.0 (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904): is this
 * inode's cluster grant held by a DEAD node whose journal-slice recovery is
 * RECOVERY_BLOCKED?  Then no amount of waiting releases it: the entry gate
 * refuses the acquire and the central incarnation gate fails the operation
 * with -EIO, both synchronously with the prover's state (no per-inode latch
 * to go stale — the moment the slow re-drive proves exclusion and the purge
 * releases the grant, the next operation acquires normally).  O(1) while
 * nothing is blocked.
 */
/* 0.75.33 (D-0915): the post-ilock backstop's single-node question, asked
 * through the mount so xfs_inode.h needs no DLM type. */
bool
mxfs_dlm_mount_is_single_node(
	const struct xfs_mount	*mp)
{
	return mp->m_mxfs_dlm && mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);
}

bool
mxfs_recovery_blocked_covers_ino(
	struct xfs_mount	*mp,
	uint64_t		ino)
{
	if (likely(!mp->m_mxfs_dlm ||
		   !mxfs_v5_dlm_any_recovery_blocked(mp->m_mxfs_dlm)))
		return false;
	return mxfs_v5_dlm_inode_held_by_blocked(mp->m_mxfs_dlm, ino) != 0;
}

/*
 * Does this inode own METADATA BLOCKS OUTSIDE ITS CORE — a bmap btree, a
 * non-shortform attribute fork, a remote symlink target?
 *
 * Such a block's only possible authority is the owning inode's own EX grant:
 * it lives inside an allocation group, but the AG grant does not vouch for its
 * contents (mxfs_buf_ag_authorized lists the AG structures and nothing else).
 * While the inode is still on the deferred-publish list that EX grant is
 * local-only — MXFS_AUTH_UNPUBLISHED_EX, no on-disk slot, no durable epoch —
 * so the capture point has no epoch to name, the image ships
 * MXFS_AUTH_ST_AUTH_NOT_HELD, and a peer replaying this node's slice after a
 * death must refuse the whole transaction that carried it.  A refused
 * transaction is atomically skipped and every AG it touched is quarantined;
 * when that set includes AG 0 the root inode becomes unreadable and nobody can
 * mount the filesystem again ("Failed to read root inode 0x80, error 5").
 *
 * Measured on a HEALTHY two-node lap with nothing killed (0.75.109,
 * tests/agmeta_stale_leak_2node.sh): 6662 of 27413 logged buffer images — 24%,
 * every one a bmap-btree block of a single fallocate'd file — captured
 * UNPUBLISHED authority, and not one of them captured a durable one.  Live
 * coherency was never at risk (an unpublished inode is unreachable by a peer,
 * and every path by which a peer could name it publishes first); recovery was,
 * on every lap, and only the timing of a death decided whether it cost the
 * cluster its mount.
 *
 * So an unpublished inode must not reach the point of logging such a block.
 * Directories already divert to a real acquire at their first EX modify (the
 * unpublished-dir arm below); this asks the same question for every other
 * inode, and answers it "yes" one step early: a single operation adds at most
 * one extent to a fork, and the conversion to btree format happens on the add
 * that no longer fits inline, so a two-extent margin cannot be stepped over.
 *
 * Deliberately NOT "any inode that has data".  A file whose extents all fit in
 * the inode core logs no block a peer could ever have to replay, and making
 * every created file take a synchronous on-disk grant is exactly the cost that
 * had publish-on-create removed (one slot read+write per file, ~25 s of a 32 s
 * rsync of 8714 files).  The trigger is ownership of external metadata, which
 * is a small minority of created files.
 */
int mxfs_unpub_publish_owned_meta = 1;
module_param_named(unpub_publish_owned_meta, mxfs_unpub_publish_owned_meta,
		   int, 0644);
MODULE_PARM_DESC(unpub_publish_owned_meta,
	"publish a deferred-publish inode before it logs a metadata block outside its core (default 1; 0 restores the pre-fix behaviour for A/B)");

static atomic64_t	mxfs_unpub_owned_meta_n;

/*
 * Name and count each diversion, so a lap can prove the gate fired here and
 * not by luck, and so the residual — a first-dirty that still reaches the
 * capture point unpublished, counted there as P239-OWNAUTH unpub — can be read
 * against it.  Always true: it is the last term of the gate's conjunction and
 * exists only to observe it.
 */
static bool
mxfs_unpub_owned_meta_note(
	struct xfs_inode	*ip)
{
	long long		n = atomic64_inc_return(&mxfs_unpub_owned_meta_n);

	if (n <= 64 || (n & 1023) == 0)
		pr_warn("mxfs: P-UNPUB-OWNED-META n=%lld ino=%llu fmt=%d nextents=%llu forkoff=%u af_fmt=%d af_nextents=%llu mode=%u comm=%s — unpublished inode owns metadata outside its core; taking a real grant before it can log an unreplayable image\n",
			n, (unsigned long long)ip->i_ino,
			(int)ip->i_df.if_format,
			(unsigned long long)ip->i_df.if_nextents,
			(unsigned)ip->i_forkoff,
			xfs_inode_has_attr_fork(ip) ? (int)ip->i_af.if_format : -1,
			xfs_inode_has_attr_fork(ip) ?
				(unsigned long long)ip->i_af.if_nextents : 0ULL,
			ip->i_dlm_mode, current->comm);
	return true;
}

static bool
mxfs_inode_owns_logged_metadata(
	struct xfs_inode	*ip)
{
	xfs_extnum_t		nex, maxex;
	int8_t			fmt;

	fmt = READ_ONCE(ip->i_df.if_format);
	if (fmt == XFS_DINODE_FMT_BTREE)
		return true;

	/*
	 * One add away from the conversion.  xfs_inode_fork_size() reads
	 * i_forkoff, which an attr-fork reservation can move under us; a stale
	 * answer only mis-times this gate by one operation and the next EX
	 * modify asks again, so no lock is taken for it.
	 */
	if (fmt == XFS_DINODE_FMT_EXTENTS) {
		nex = READ_ONCE(ip->i_df.if_nextents);
		maxex = XFS_IFORK_MAXEXT(ip, XFS_DATA_FORK);
		if (maxex <= 2 ? nex > 0 : nex + 2 >= maxex)
			return true;
	}

	/*
	 * The attr fork owns logged blocks once it has one — a btree, or extents
	 * with at least one extent — and may gain its first inside a single
	 * xattr set, which xfs_attr_change announces in i_mxfs_attr_setting.
	 * Without a set in flight, a fork with no block (LOCAL, or the EXTENTS
	 * fork with zero extents that create sets up for a possible xattr) owns
	 * nothing.  Treating that empty fork as owning cost nearly every created
	 * file a durable grant (0.89.85 rsync: af_fmt=2 af_nextents=0 on every
	 * P-UNPUB-OWNED-META, one ledger page commit per file); narrowing it
	 * WITHOUT the in-flight count let a 3000-byte xattr's leaf ship
	 * unauthorized (tests/lone_mount_crash_replay.sh: blft=ATTR_LEAF class=0
	 * st=11, the adopted slice refused).
	 */
	if (atomic_read(&ip->i_mxfs_attr_setting) > 0)
		return true;
	if (xfs_inode_has_attr_fork(ip)) {
		int8_t	afmt = READ_ONCE(ip->i_af.if_format);

		if (afmt == XFS_DINODE_FMT_BTREE ||
		    (afmt == XFS_DINODE_FMT_EXTENTS &&
		     READ_ONCE(ip->i_af.if_nextents) > 0))
			return true;
	}

	/* A remote symlink's target block is logged and inode-owned. */
	if (S_ISLNK(VFS_I(ip)->i_mode) && fmt != XFS_DINODE_FMT_LOCAL)
		return true;

	return false;
}

/* BATCHING: a deferred-during-ACQUIRING BAST on a fresh EX dir
 * grant was kept CACHED so this node's create burst fast-paths; arm the
 * MHT dwork (mxfs_dlm_bast_dwork_fn) to honor the BAST when the bounded
 * window expires.  Owns a fresh igrab ref for the dwork (dropped if the
 * dwork was already armed by a prior BAST). */
static void mxfs_ilock_batch_deferred_bast(bool batch_arm, struct xfs_inode *ip)
{
	if (batch_arm) {
		/* shortform dirs use the reduced dir_sf_mht_ms (inline
		 * data → handoff coherent via whole-inode reload; no long hold needed). */
		/* 0.75.58: the inode's own window (dir MHT, shortform dir
		 * window, or the file window). */
		int eff_mht_ms = mxfs_ex_tenure_window_ms(ip);
		u64 mht_ns = (u64)eff_mht_ms * NSEC_PER_MSEC;
		u64 held = ktime_get_ns() - ip->i_dlm_ex_acquire_ns;
		unsigned long delay_j =
			(held < mht_ns) ? nsecs_to_jiffies(mht_ns - held) + 1 : 1;

		/* FRONT-A FIX: arm in GRACE SLICES here
		 * too — this site (ACQUIRING-deferred BAST honor) was the one arm
		 * left parking the dwork for the whole window.  At 32/tcp round
		 * open every node's first dir claim got its peer BAST 22-75µs
		 * after grant (P74-GRANT→P-DIRBAST measured), was deferred via
		 * bast_during_acq, and then slept the FULL 300ms window before
		 * release (P70-BP held_ms=301-307 staircase → 10s create phases,
		 * drc@32 6 rounds/120s vs MIN 8).  Same clamp as the src=9 site;
		 * the dwork's quiet-age gate re-arms while the local burst is
		 * live and releases at the first >=grace idle sample. */
		if (mxfs_dir_ex_batch_grace_ms > 0) {
			unsigned long slice_j =
				msecs_to_jiffies(mxfs_dir_ex_batch_grace_ms) + 1;
			if (delay_j > slice_j)
				delay_j = slice_j;
		}

		/* 2026-07-16 (test26 mid-cc panic, radix_tree_tag_set BUG via
		 * dwork xfs_irele of a recycled i_ino=0 inode): igrab's return
		 * MUST be checked — an unchecked igrab on an evicting inode
		 * takes NO reference, and queueing anyway arms a phantom
		 * dwork that later fires on freed/recycled inode memory
		 * (BUG3 family; every sibling arm site already guards). */
		if (igrab(VFS_I(ip))) {
			ip->i_dlm_bastq_src = 11;
			if (!mxfs_bast_arm_queue_delayed(ip, delay_j))
				xfs_irele(ip);	/* dwork already armed — drop duplicate ref */
		} else {
			mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=batch_arm i_state=0x%lx (inode evicting; skipping MHT dwork arm — eviction serves the parked BAST)\n",
				(unsigned long long)ip->i_ino,
				mxfs_istate(VFS_I(ip)));
		}
	}
}

/*
 * NEWARCH Phase 1.3 (design review chokepoint): end of the ACQUIRING
 * window.  Decide CACHED vs BAST based on whether a peer BAST
 * arrived while we were inside caw_lock (bast_notify recorded
 * that by setting i_dlm_stale = true on the ACQUIRING branch).
 *
 * If stale: transition to BAST and schedule the drain — the
 * caller will hold the lock briefly to do its work, then
 * ilock_end will trip the BAST drain at the last holder.
 *
 * If not stale: clean CACHED.
 *
 * Either way, wake any threads piled up in the wait loop above.
 */
static void mxfs_ilock_end_acquiring_window(struct xfs_inode *ip, uint8_t mode,
					    bool *batch_arm_io)
{
	bool batch_arm = *batch_arm_io;

	if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING) {
		/* ROOT FIX: honor a BAST that arrived while we were
		 * ACQUIRING via the DEDICATED i_dlm_bast_during_acq flag.  i_dlm_stale
		 * is unreliable here — reload_inode() above clears it (it doubles as
		 * the "needs reload" signal), so a BAST deferred during ACQUIRING was
		 * lost and the peer stalled the full 6000ms ACQUIRE_WAIT_MS. */
		bool acq_bast = ip->i_dlm_bast_during_acq;
		ip->i_dlm_bast_during_acq = false;
		/* P11-ACQSTALE-SELFBAST: make the previously
		 * SILENT stale-only self-BAST visible (the !acq_bast arm below
		 * printed nothing).  src names the last i_dlm_stale=true setter
		 * (see xfs_inode.h) — the storm engine discriminator. */
		if (unlikely((ip->i_dlm_stale || acq_bast) &&
			     ip->i_ino <= 256)) {
			static atomic_t p11sb_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p11sb_n) <= 8000)
				mxfs_probe("mxfs: P11-ACQSTALE-SELFBAST ino=%llu mode=%u stale=%d src=%u acq_bast=%d en=%d comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino, mode,
					ip->i_dlm_stale ? 1 : 0,
					ip->i_dlm_stale_src,
					acq_bast ? 1 : 0,
					mxfs_acq_stale_selfbast,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		if ((mxfs_acq_stale_selfbast && ip->i_dlm_stale) || acq_bast) {
			/* BATCHING (design review plan item 3 — bounded fairness window):
			 * honoring the deferred BAST by releasing after a SINGLE op leaves
			 * the 24-round concurrent-create workload ping-ponging the dir-EX
			 * once per create (~65ms/op handoff, ~16s/round → 300s timeout).
			 * For a FRESH EX dir grant, instead keep the grant CACHED and arm
			 * the MHT dwork: our queued create burst fast-paths within the
			 * bounded mxfs_inode_mht_ms window, then the dwork honors the BAST.
			 * Coherency is preserved (the peer cannot read until it gets the
			 * grant); starvation is bounded by the MHT window.  The i_dlm_stale
			 * (needs-reload) case and PR/non-dir grants release promptly. */
			/* 0.75.58: regular files batch under their own window
			 * too (mxfs_file_ex_tenure_ms); see the tenure floor. */
			if (acq_bast && !ip->i_dlm_stale &&
			    mode == MXFS_LOCK_EX &&
			    mxfs_ex_tenure_window_ms(ip) > 0 &&
			    (S_ISDIR(VFS_I(ip)->i_mode) ||
			     S_ISREG(VFS_I(ip)->i_mode))) {
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				if (!ip->i_dlm_bast_pending)
					ip->i_dlm_dwork_strikes = 0;	/* v0.10.31 */
				ip->i_dlm_bast_pending = true;
				batch_arm = true;
				mxfs_probe_ratelimited(
					"mxfs: P35-ACQBAST-BATCH ino=%llu mode=%u (batch creates within MHT window, then release)\n",
					(unsigned long long)ip->i_ino, mode);
			} else {
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				if (acq_bast)
					mxfs_probe_ratelimited(
						"mxfs: P35-ACQBAST-HONOR ino=%llu mode=%u (deferred-during-ACQUIRING BAST now honored)\n",
						(unsigned long long)ip->i_ino, mode);
				/* Pin + schedule the drain so the BAST is honored
				 * AFTER the caller's brief in-flight work completes.
				 *
				 * ROOT FIX (see EDEADLK site above): if the
				 * inode is being evicted (I_FREEING), igrab() returns
				 * NULL.  We hold i_dlm_lock here and are mid-grant, so
				 * we cannot drain inline — just DO NOT queue the async
				 * bast_work_fn (queuing without a pinning ref makes its
				 * unconditional xfs_irele crash on the freed inode,
				 * BUG_ON(I_CLEAR)).  state stays BAST; the caller's
				 * ilock_end honors it via its INLINE drain path (no
				 * igrab there), and reclaim's mxfs_dlm_inode_teardown
				 * releases the on-disk DLM slot regardless of state. */
				if (igrab(VFS_I(ip))) {
					ip->i_dlm_bastq_src = 7;
					if (!mxfs_bast_arm_queue(ip))
						iput(VFS_I(ip));
				} else {
					mxfs_probe_ratelimited(
					    "mxfs: P60-ACQBAST-FREEING ino=%llu i_state=0x%lx (inode evicting; ilock_end/teardown will release)\n",
						(unsigned long long)ip->i_ino,
						mxfs_istate(VFS_I(ip)));
				}
			}
		} else {
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		}
	}

	*batch_arm_io = batch_arm;
}

/*
 * 32-node cache_coherency shared-dir reload-storm
 * gate (PARAM-GATED mxfs_dir_slow_handoff_gate, default off).  reload_inode
 * ALWAYS reads disk then conditionally adopts; when NO peer held EX since
 * our last adopt (no genuine handoff) it keeps our in-core anyway, so the
 * read is pure waste — at 32 nodes on the 4 shared coherency dirs that
 * waste IS the storm (RELOAD-STALE-SPLIT modeN=511/node ~75% dirs).  Skip
 * the reload+gen-bump when there is no peer handoff.  Coherency-preserving
 * per Invariant 1 (peer modify requires EX + drain-at-release), and a real
 * peer EX advances the CAW dir-epoch / sets the P63 handoff bit -> peer_ex
 * -> we still reload.  acq_epoch advances only at reload_inode's adopt
 * point, so this pre-reload comparison mirrors reload_inode's own gate. */
static void mxfs_ilock_reload_storm_gate(struct xfs_inode *ip, uint8_t mode)
{
	{
		bool dir_slow_skip = false;

		if (mxfs_dir_slow_handoff_gate &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    (VFS_I(ip)->i_mode != 0 || ip->i_nblocks != 0) &&
		    ip->i_mount->m_mxfs_dlm) {
			uint32_t ep = mxfs_v5_dlm_inode_dir_epoch(
					ip->i_mount->m_mxfs_dlm, ip->i_ino);
			uint32_t gg = 0;
			bool peer_ex;

			peer_ex = mxfs_v5_dlm_transport_caw(ip->i_mount->m_mxfs_dlm)
				? (ep != ip->i_dlm_dir_acq_epoch)
				: (ep > ip->i_dlm_dir_valid_epoch);
			if (!peer_ex &&
			    mxfs_v5_dlm_inode_grant_handoff(ip->i_mount->m_mxfs_dlm,
							    ip->i_ino, &gg) &&
			    gg != 0 && gg != ip->i_dlm_handoff_acted_gen)
				peer_ex = true;
			dir_slow_skip = !peer_ex;
			/* Option B: a reload skip is only permitted over
			 * an ESTABLISHED baseline — with the validity bit unset
			 * the epoch/handoff compares above ran against sentinel
			 * state and prove nothing. */
			if (mxfs_dir_adopt_at_acquire &&
			    !smp_load_acquire(&ip->i_dlm_base_valid))
				dir_slow_skip = false;
			if (dir_slow_skip && unlikely(mxfs_read_attr_probe)) {
				long long sk =
					atomic64_inc_return(&mxfs_dir_slow_skip);

				if ((sk & 255) == 0)
					mxfs_probe("mxfs: DIR-SLOW-SKIP n=%lld ino=%llu — no peer handoff, cached dir kept (reload+FUA averted)\n",
						sk, (unsigned long long)ip->i_ino);
			}
		}

		if (dir_slow_skip) {
			/* cached dir authoritative: do NOT stale/bump-gen/reload */
			ip->i_dlm_dir_want_ex = false;
		} else {
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 7;
			/* bump dir-data generation on slow-path re-acquire
			 * (peer may have modified this dir while we didn't hold the
			 * DLM); the dir-block read path FUA re-reads when a cached
			 * buf's stamp is older than this. */
			if (S_ISDIR(VFS_I(ip)->i_mode)) {
				if (mode == MXFS_LOCK_EX)
					atomic64_inc(&mxfs_dirEX_slowpath); /* */
				ip->i_dlm_dir_gen++;
				/* reset peer-wants-EX so it reflects only EX BASTs
				 * that arrive AFTER this grant. */
				ip->i_dlm_dir_want_ex = false;
				if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-DIR-SEQ ACQ-SLOW ino=%llu mode=%u gen=%llu realns=%llu",
						(unsigned long long)ip->i_ino, mode,
						(unsigned long long)ip->i_dlm_dir_gen,
						(unsigned long long)ktime_get_real_ns());
			}
			if (VFS_I(ip)->i_mode != 0 || ip->i_nblocks != 0) {
				/* slow-path fresh DLM grant = post-release reacquire;
				 * on-disk is a superset (Invariant 1) — post_release.
				 * ICLUSTER: seen_seq == current grant_seq means the
				 * cluster grant was held (by us or nobody took EX)
				 * continuously since our last load of THIS inode —
				 * no peer write possible, the in-core image is
				 * coherent and the FUA re-read is pure cost.  Capture
				 * seq BEFORE the reload; stamp after — if a fresh
				 * claim lands mid-reload the stamp stays behind and
				 * the next acquire reloads (conservative). */
				uint64_t pre_seq = 0;
				bool iclus_skip = false;

				if (mxfs_iclus_routed(ip)) {
					pre_seq = mxfs_iclus_grant_seq(
						ip->i_mount, ip->i_ino);
					iclus_skip = !ip->i_dlm_stale &&
						ip->i_dlm_iclus_seen_seq != 0 &&
						ip->i_dlm_iclus_seen_seq ==
							pre_seq;
				}
				if (!iclus_skip) {
					/* The one reload taken under a fresh
					 * wire grant: the previous holder has
					 * drained, so a freed image here is the
					 * platter's truth and may condemn a
					 * clean shell of a prior incarnation. */
					mxfs_dlm_reload_inode_under(ip,
						XFS_DIR3_FT_UNKNOWN, true, true);
					if (mxfs_iclus_routed(ip))
						ip->i_dlm_iclus_seen_seq =
							pre_seq;
				}
			}
		}
	}
}

/*
 * 0.89.63 TEST-ONLY STRAND INJECTOR (D-THE-ONLY-STRAND-ESCAPE-TCP-HAS-
 * IS-A-U8-COUNTER-TESTED-AGAINST-280).  The stranded-grant shape has no
 * known producer and is real; the only way to exercise the escape that
 * frees it is to manufacture the shape: the DLM engine has granted this
 * acquire and linked the mirror entry, and the XFS layer now drops it —
 * publishes no mode, consumes nothing, releases nothing — exactly as an
 * acquirer that went away between the grant and its consumption would.
 * One-shot, by inode.  The caller's operation fails as a refused acquire
 * does (the fallible registry is told, the namespace backstop is set),
 * and what happens next is the peer's business: its request BASTs this
 * node and the cleanup pipeline meets a granted mirror under an in-core
 * NL.  0.89.65, MEASURED: what frees it is the abandoned arm
 * (P15-TCP-ORPH-PROCEED) once no acquirer holds i_dlm_acq_inflight —
 * at once in the abandoned shape, at the acquirer's exit in the held
 * one.  The 280-sample strike counter is never reached in either.
 */
static int mxfs_ilock_test_strand_inject(struct xfs_inode *ip, uint8_t mode)
{
	int outcome = MXFS_BLOCK_NEXT;

	if (unlikely(READ_ONCE(mxfs_dbg_strand_ino) != 0) &&
	    ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm) &&
	    mxfs_dbg_ino_take(&mxfs_dbg_strand_ino, ip->i_ino)) {
		int strand_hold_ms = READ_ONCE(mxfs_dbg_strand_hold_ms);
		uint32_t strand_gen = mxfs_v5_dlm_inode_grant_gen(
					ip->i_mount->m_mxfs_dlm, ip->i_ino);

		mxfs_probe("mxfs: P-DBG-STRAND-INJECT ino=%llu mode=%u gen=%u hold_ms=%d comm=%s — TEST ONLY: the DLM granted this acquire and the XFS layer is dropping it unconsumed: the mirror stays granted, the in-core mode stays NL, nothing is released.  This operation fails; the peer's BAST must free it through the abandoned-grant arm once no acquirer is in flight\n",
			(unsigned long long)ip->i_ino, mode, strand_gen,
			strand_hold_ms, current->comm);
		xfs_iflags_set(ip, MXFS_IF_ACQ_REFUSED);
		spin_lock(&ip->i_dlm_lock);
		if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		if (strand_hold_ms <= 0 && ip->i_dlm_acq_inflight)
			ip->i_dlm_acq_inflight--;
		spin_unlock(&ip->i_dlm_lock);
		if (strand_hold_ms > 0) {
			/*
			 * The in-flight shape: this task IS the acquirer, its
			 * count stands, its state reads NONE, and it consumes
			 * nothing for the whole hold.  Every BAST that lands
			 * meanwhile meets a granted mirror under an in-core NL
			 * with acq_inflight > 0, and (0.89.65, measured s143b)
			 * is PARKED for the acquirer — P-ACQWIN-PARK, no release
			 * sample — until the count is dropped when this task
			 * exits, exactly as a failing slow-path exit does.
			 */
			mxfs_dbg_sliced_sleep(strand_hold_ms);
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			mxfs_probe("mxfs: P-DBG-STRAND-INJECT-END ino=%llu gen=%u now_gen=%u mode=%u state=%u — TEST ONLY: the held acquirer exits without consuming; its in-flight count is dropped\n",
				(unsigned long long)ip->i_ino, strand_gen,
				mxfs_v5_dlm_inode_grant_gen(
					ip->i_mount->m_mxfs_dlm, ip->i_ino),
				ip->i_dlm_mode, ip->i_dlm_state);
		}
		wake_up_all(&ip->i_dlm_wait);
		if (mxfs_acqfall_armed_for(ip->i_ino))
			mxfs_acqfall_give_up_rc(ip->i_ino, -EIO);
		{ outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_test_strand_inject_exit; }
	}
mxfs_ilock_test_strand_inject_exit:
	return outcome;
}

/*
 * The slow path: take the lock from the cluster DLM, retrying as the transport
 * requires. An unpublished inode is first dropped from the unpublished list,
 * because this acquire is its publish.
 */
static int mxfs_ilock_acquire_from_dlm(struct xfs_inode *ip,
				       bool *slowpath_publish_io, uint8_t mode,
				       uint64_t auth_gen_snap,
				       int *relock_laps_io, int *recov_laps_io,
				       int *trans_laps_io, int *park_laps_io,
				       u64 *live_t0_io, int *live_laps_io)
{
	int block_outcome = MXFS_BLOCK_NEXT;
	bool slowpath_publish = *slowpath_publish_io;
	int relock_laps = *relock_laps_io;
	int recov_laps = *recov_laps_io;
	int trans_laps = *trans_laps_io;
	int park_laps = *park_laps_io;
	u64 live_t0 = *live_t0_io;
	int live_laps = *live_laps_io;

	{
		int rc = 0;
		int attempt;
		u64 t0, dt;
		static atomic64_t caw_n, caw_ns, caw_new_n;
		s64 cn;
		bool is_new = (mxfs_istate(VFS_I(ip)) & I_NEW) ||
			      (ip->i_flags & XFS_INEW);

		/*
		 * an UNPUBLISHED inode reaching the slow path (e.g. via
		 * the unpublished-dir-modify backstop above) has NO on-disk
		 * CAW slot.  Drop it from the unpublished list (atomic under
		 * m_mxfs_unpub_lock) so this and future ops stop treating it as
		 * locally-granted and a concurrent mxfs_dlm_publish_unpublished
		 * (peer BAST) doesn't keep it listed.  We then do a REAL on-disk EX
		 * acquire below.  mxfs_dlm_caw_lock is idempotent-safe if a racing
		 * publisher already set our bit: its "already held" path returns
		 * success (dlm_caw.c:1413) and self-heals a peer-conflict
		 * divergence — it does NOT force-shutdown — so always acquiring
		 * (rather than skipping) guarantees on-disk EX is confirmed held
		 * before the caller's RMW, with no double-acquire hazard.
		 */
		if (ip->i_dlm_unpublished) {
			mxfs_dlm_unpublish_drop(ip);
			/* this acquire IS this inode's publish — remember
			 * it so the creator baseline can be stamped once the
			 * grant completes (site 4, the live path for a fresh
			 * self-created dir: the comment on the divert gate above
			 * measures its first EX op ~30 us after mkdir, which no
			 * async publish worker can win). */
			slowpath_publish = true;
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe_ratelimited(
					"mxfs: P107-PUBLISH ino=%llu mode=%u (unpublished-modify backstop: acquiring real on-disk slot)\n",
					(unsigned long long)ip->i_ino, mode);
		}

		/* P23-SLOWPATH (instrumented): name every
		 * slow-path inode DLM acquire — the 2-node parallel rsync
		 * spends ~26/68 in-line samples here on inodes that should
		 * have stayed cached EX from their own create.  Capped, not
		 * ratelimited, so the early burst is fully visible. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			static atomic_t p23_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p23_n) <= 3000)
				mxfs_probe("mxfs: P23-SLOWPATH ino=%llu isdir=%d req=%u had_mode=%u state=%u stale=%d new=%d comm=%s\n",
					(unsigned long long)ip->i_ino,
					S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
					mode, ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_stale ? 1 : 0,
					is_new ? 1 : 0, current->comm);
		}

		/*
		 * serialize this fresh acquire behind any
		 * PENDING no-inode async release for the same ino.  The
		 * release work (queued at a BAST for our PRIOR, reclaimed
		 * tenure) ends in a slot CAS that clears our node bit —
		 * letting it land AFTER this acquire is granted strips the
		 * NEW tenure's bit (proven: mkdir-storm double-EX, 15K
		 * P135-HELD-MISS/3min, durable dirent loss).  Bounded wait:
		 * the work's own live-inode re-check covers the long-fence
		 * tail if we time out and proceed.
		 */
		{
			int nino_w = 0;

			while (nino_w < 2000 &&
			       mxfs_noino_inflight_contains(ip->i_mount,
							    ip->i_ino)) {
				msleep(1);
				nino_w++;
			}
			if (nino_w > 0) {
				static atomic_t p_acqw_cap = ATOMIC_INIT(0);

				if (atomic_inc_return(&p_acqw_cap) <= 200)
					mxfs_probe("mxfs: P-NOINO-ACQ-WAIT ino=%llu waited_ms=%d%s — fresh acquire serialized behind pending no-inode release\n",
						(unsigned long long)ip->i_ino,
						nino_w,
						nino_w >= 2000 ?
						" (TIMEOUT, proceeding)" : "");
			}
		}

		/* (incident474, design-consult b2): foreign-slice REPLAY is
		 * buffer-level by design and must never enter ordinary inode
		 * DLM acquisition — a replay task blocking here on a fenced
		 * victim's grant is the proven cascade deadlock. */
		WARN_ONCE(mxfs_task_recovery_phase() == MXFS_RECOV_PHASE_REPLAY,
			  "mxfs: P-REPLAY-INODE-LOCK ino=%llu mode=%u comm=%s — replay context in inode DLM acquire\n",
			  (unsigned long long)ip->i_ino, mode, current->comm);

		t0 = ktime_get_ns();
		for (attempt = 0; attempt < 3; attempt++) {
			/*
			 * break the proven dir-inode-EX <-> AG-DLM
			 * cross-resource deadlock.  If a peer is blocked
			 * acquiring an AG we hold CACHED (no active holder),
			 * it cannot release the inode lock WE are about to
			 * wait for until it gets that AG.  Yield those cached
			 * basted AGs before (and between) each blocking inode
			 * acquire.  No-op unless a cached AG actually has a
			 * pending BAST, so uncontended acquires pay only a
			 * cheap per-AG flag scan.
			 */
			mxfs_dlm_yield_basted_cached_ags(ip->i_mount);

			rc = mxfs_dlm_inode_lock_routed(ip, mode, auth_gen_snap);
			if (rc == 0 || rc == -EDEADLK)
				break;
			/* 0.84.2: a killed task at a fallible boundary left the
			 * wait; another attempt would only re-send for it. */
			if (rc == -EINTR)
				break;
			/* 0.84.5 (D-...-0960): the engine already waited out a
			 * stalled authority transition (30 s of no progress);
			 * another descent would only wait it out again. */
			if (rc == -EREMCHG)
				break;
			/* bounded acquire (lock_two's
			 * second inode) — first timeout bails to the caller's
			 * backoff loop; do not burn 3 blocking attempts. */
			if (ip->i_dlm_tries_owner == current &&
			    ip->i_dlm_tries > 0)
				break;
			msleep(50);
		}
		dt = ktime_get_ns() - t0;
		/* instrumented: pin the per-handoff slow inode-EX/PR
		 * acquire (dir_reuse 2/tcp ~6s dir-131 handoff).  Always-on,
		 * ratelimited; names the ino so dir-vs-file is unambiguous. */
		if (dt > 1000000000ULL)
			mxfs_probe_ratelimited(
				"mxfs: P34-ACQ-SLOW ino=%llu isdir=%d req_mode=%u dur_ms=%llu attempts=%d rc=%d\n",
				(unsigned long long)ip->i_ino,
				S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
				mode, (unsigned long long)(dt / 1000000),
				attempt + 1, rc);
		cn = atomic64_inc_return(&caw_n);
		atomic64_add(dt, &caw_ns);
		if (is_new)
			atomic64_inc(&caw_new_n);
		if ((cn & 511) == 0)
			mxfs_probe("mxfs: CAW-ILOCK n=%lld new=%lld tot_ms=%lld avg_us=%lld\n",
				(long long)cn,
				(long long)atomic64_read(&caw_new_n),
				(long long)(atomic64_read(&caw_ns) / 1000000),
				(long long)(atomic64_read(&caw_ns) / 1000 / cn));

		/*
		 * NEWARCH Phase 1.3 (design review chokepoint): caw_lock returned
		 * -EDEADLK because we hold a lower mode on disk and a peer
		 * holds an incompatible mode for the upgrade we want.  Drop
		 * our cached lock THROUGH THE BAST DRAIN PIPELINE
		 * (invariant #1: no on-disk unlock without flush+invalidate),
		 * then retry the whole acquire from a clean NL state.
		 *
		 * State machine: transition ACQUIRING → BAST, schedule the
		 * existing bast_work_fn to drain + invalidate + clear the
		 * on-disk bit + set i_dlm_mode = NL.  Recursive ilock_begin
		 * call hits the wait loop above (state == BAST) and blocks
		 * until bast_process completes (state → NONE + wake), then
		 * falls through to fresh slow path that acquires from NL —
		 * which cannot hit -EDEADLK because our_mode = NL has no
		 * upgrade conflict.
		 */
		if (rc == -EDEADLK) {
			bool phantom = false;

			/*
			 * 0.75.6 (D-EDEADLK-SELF-DEMOTE-ON-NL-HELD-INODE-IN-IGET-
			 * NO-WAKER-0904): the blocked-upgrade refusal presumes this
			 * node holds a lower mode.  When the inode layer holds
			 * NOTHING (mode NL, no release in flight) the DLM table
			 * entry is a phantom of this node's own making — a
			 * predecessor incarnation's shared bit imported on the
			 * same heartbeat slot, or any stale own entry — and the
			 * demote path below has nothing to drain: bast_work_fn
			 * bails (P142-BWORK-STALE on an inode not yet in the
			 * radix tree, or a no-op drain) and the wait it enters has
			 * no waker (63 re-drives over 180 s on s509d, the mount in
			 * D state).  Release the phantom through the DLM and retry
			 * the acquire from the clean NL state.  A release that IS
			 * in flight (DEMOTING/BAST, a demoter tagged) stores NL
			 * before its unlock, so it is excluded here: unlocking
			 * under it would hand the grant to a peer ahead of the
			 * drain.
			 */
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING &&
			    ip->i_dlm_mode == MXFS_LOCK_NL &&
			    !ip->i_dlm_routed_iclus &&
			    !ip->i_dlm_demoter && !ip->i_dlm_demoter2)
				phantom = true;
			spin_unlock(&ip->i_dlm_lock);
			if (phantom) {
				pr_warn(
				    "mxfs: P109-EDEADLK-NL ino=%llu req=%u lap=%d comm=%s — blocked-upgrade refusal while holding NL: the table entry is a phantom; releasing it via the DLM and retrying\n",
					(unsigned long long)ip->i_ino, mode,
					relock_laps + 1, current->comm);
				{
					int urc = mxfs_v5_dlm_inode_unlock_gen(
							ip->i_mount->m_mxfs_dlm,
							ip->i_ino, 0);
					int nrc;

					/*
					 * 0.75.11 (D-0904, rejoin_residue s513a arm 2):
					 * the phantom can live on the REMOTE MASTER only —
					 * a predecessor incarnation's shared bit on our
					 * heartbeat slot, imported there after the slot map
					 * named us (P-TAUTH-IMPORT-ACTIVE owner=<us>) — and
					 * the unlock above finds no local entry and sends
					 * nothing: 65 laps of P-CONVBLK-DENY, then the
					 * livelock shutdown.  Send the gen-0 unconditional
					 * release (FIX-20b) to the master, gated on the
					 * local table holding no entry of any state; the
					 * master retires the record with a ledger
					 * transition so the bit leaves the platter.
					 */
					nrc = mxfs_v5_dlm_inode_orphan_nak(
							ip->i_mount->m_mxfs_dlm,
							ip->i_ino);
					mxfs_probe(
					    "mxfs: P109-EDEADLK-NL-RELEASE ino=%llu lap=%d rc=%d nak_rc=%d\n",
						(unsigned long long)ip->i_ino,
						relock_laps + 1, urc, nrc);
				}
				if (++relock_laps > 64) {
					mxfs_pal_log(MXFS_LOG_ERR,
						"mxfs: EDEADLK-NL retry livelock: ino=%llu mode=%u laps=%d comm=%s — shutting down filesystem",
						(unsigned long long)ip->i_ino, mode,
						relock_laps, current->comm);
					spin_lock(&ip->i_dlm_lock);
					if (ip->i_dlm_acq_inflight)
						ip->i_dlm_acq_inflight--;
					spin_unlock(&ip->i_dlm_lock);
					xfs_force_shutdown(ip->i_mount,
							   SHUTDOWN_CORRUPT_INCORE);
					{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
				}
				if (relock_laps > 4)
					msleep(min(50 * relock_laps, 1000));
				spin_lock(&ip->i_dlm_lock);
				if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
					{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
					ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
					mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				if (ip->i_dlm_acq_inflight)
					ip->i_dlm_acq_inflight--;
				spin_unlock(&ip->i_dlm_lock);
				wake_up_all(&ip->i_dlm_wait);
				{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
			}
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe_ratelimited(
				    "mxfs: P109-EDEADLK ino=%llu req=%u (orchestrating release via BAST drain, then retry)\n",
					(unsigned long long)ip->i_ino, mode);
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			/* tag this as a SELF-demote (no peer reads our
			 * state) so bast_process may skip the durability drain on
			 * a clean read-only drop — the tcp_dlm_scaling upgrade-
			 * livelock amplifier — without dropping the coherency-
			 * masking barrier on genuine peer handoffs. */
			ip->i_dlm_self_demote = true;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			/*
			 * bast_work_fn owns the inode ref via igrab so this
			 * works the same as a peer-BAST arrival.  Pin to keep
			 * the inode alive across the async work.
			 *
			 * ROOT FIX (instrumented, PROVEN by P-IGRAB-NULL
			 * site=EDEADLK + P-BWFN-PREIRELE i_count=0 i_state=0x60
			 * I_CLEAR=1 immediately before BUG_ON(I_CLEAR) in iput):
			 * this acquire can run on an inode the VFS is already
			 * evicting (I_FREEING|I_CLEAR — a reused dir inode mid
			 * rm-rf under dir_reuse_coherency).  igrab() then returns
			 * NULL (it refuses a freeing inode), but the old code
			 * ignored the NULL and queued bast_work_fn anyway, whose
			 * unconditional xfs_irele dropped a ref that was never
			 * taken -> use-after-free -> BUG_ON(I_CLEAR) crash on the
			 * mxfs-ino-bast kworker.  We are NOT holding i_dlm_lock
			 * here (dropped at the spin_unlock above) and bast_process
			 * is re-entrant-safe via the i_dlm_demoter tag (same as
			 * the ilock_end inline path), so when the inode cannot be
			 * pinned, run the demote/drain INLINE in this thread (no
			 * queue, no irele) instead of scheduling it on a corpse.
			 * The inline drain sets state -> NONE, so the recursive
			 * ilock_begin below proceeds from a clean NL state without
			 * waiting on a BAST that would never be honored.
			 */
			if (igrab(VFS_I(ip))) {
				ip->i_dlm_bastq_src = 6;
				if (!mxfs_bast_arm_queue(ip))
					iput(VFS_I(ip));	/* already queued */
			} else {
				mxfs_probe_ratelimited(
				    "mxfs: P60-EDEADLK-FREEING ino=%llu i_state=0x%lx (inode evicting; draining inline)\n",
					(unsigned long long)ip->i_ino,
					mxfs_istate(VFS_I(ip)));
				MXFS_SET_DEMOTER(ip);
				{
					struct mxfs_dirdrain_task dde;

					mxfs_dirdrain_enter(&dde);
					mxfs_dlm_bast_process(ip);
					mxfs_dirdrain_exit(&dde);
				}
				MXFS_CLEAR_DEMOTER(ip);
			}
			/* Retry from the top (bounded loop, NOT recursion — see
			 * the restart label) — the entry will wait on
			 * state=BAST until the drain completes, then take the
			 * slow path from a clean NL/NONE state (or fast-path
			 * on a mid-drain-granted mode left CACHED by the
			 * release abort). */
			if (++relock_laps > 64) {
				mxfs_pal_log(MXFS_LOG_ERR,
					"mxfs: EDEADLK retry livelock: ino=%llu mode=%u laps=%d comm=%s — shutting down filesystem",
					(unsigned long long)ip->i_ino, mode,
					relock_laps, current->comm);
				spin_lock(&ip->i_dlm_lock);
				if (ip->i_dlm_acq_inflight)
					ip->i_dlm_acq_inflight--;
				spin_unlock(&ip->i_dlm_lock);
				xfs_force_shutdown(ip->i_mount,
						   SHUTDOWN_CORRUPT_INCORE);
				{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
			}
			if (relock_laps > 4)
				msleep(min(50 * relock_laps, 1000));
			/* daf50d34 restart re-enters the slow path (or
			 * fast-paths on a mid-drain grant) — drop the in-flight
			 * count; the slow path re-bumps if re-entered. */
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
		}

		/*
		 * xfs_ilock is void — there is no way to refuse the lock to
		 * the caller.  Proceeding without the cluster-wide DLM grant
		 * lets the caller modify shared metadata uncoordinated with
		 * peers, which is exactly the corruption path we are trying
		 * to prevent (v0.3.2 iter-7 xfs_defer_finish_noroll shutdown
		 * was a downstream effect of silently ignoring rc=-ENOENT
		 * here).  Force-shutdown the FS so userspace sees the error
		 * instead of an undetected on-disk corruption.
		 */
		/*
		 * ABBA breaker: a BOUNDED acquire (issued by
		 * xfs_lock_two_inodes for its second inode while it holds the
		 * first's grant-hold) that timed out is NOT unrecoverable —
		 * the caller drops its other grant-hold (letting the deferred
		 * BAST fire and unblock the peer), backs off, and retries
		 * both.  Report via i_dlm_tries_rc and return with no hold
		 * registered; acquire-state cleanup mirrors the failure path
		 * below minus the shutdown.
		 */
		if (rc && ip->i_dlm_tries_owner == current &&
		    ip->i_dlm_tries > 0) {
			ip->i_dlm_tries_rc = -ETIMEDOUT;
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			mxfs_probe_ratelimited(
			    "mxfs: P-ABBA-BOUNDED-TIMEOUT ino=%llu mode=%u rc=%d comm=%s — bounded second-inode acquire; caller backs off\n",
				(unsigned long long)ip->i_ino, mode, rc,
				current->comm);
			{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		/*
		 * (incident474, design-consult b3): a recovery-context task —
		 * post-replay cleanup sweep on the elected replayer — must
		 * NEVER escalate an acquire timeout to its own shutdown.  In
		 * incident474 the survivor's sweep blocked on an EX grant
		 * naming a still-unpurged fenced victim, whose purge was
		 * queued BEHIND the blocked sweep; the timeout then shut the
		 * last survivor down, completing the fleet-wide cascade.
		 * Requeue and retry with backoff instead: progress arrives
		 * when the recovery machinery purges the dead holder's
		 * grants.  Ordinary threads keep the fail-fast shutdown.
		 */
		if (rc && mxfs_task_recovery_phase() &&
		    !xfs_is_shutdown(ip->i_mount)) {
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			recov_laps++;
			pr_warn_ratelimited(
			    "mxfs: P-RECOV-ACQ-REQUEUE ino=%llu mode=%u rc=%d laps=%d pending=%d comm=%s — recovery-context acquire timeout; requeueing, not shutting down\n",
				(unsigned long long)ip->i_ino, mode, rc,
				recov_laps,
				!bitmap_empty(ip->i_mount->m_mxfs_foreign_dead_slots, 64),
				current->comm);
			msleep(min(500 * recov_laps, 5000));
			{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		/*
		 * (D-513 enforcement point e): the timeout classifier.
		 * Incident 513 proved the old unconditional escalation is the
		 * all-32 suicide: ONE victim's refused replay froze its
		 * grants, every survivor's acquire timed out here, and each
		 * timeout was answered with a LOCAL shutdown — serial fleet
		 * death.  Three-way split, in evidence order:
		 *
		 * (1) The inode's domain is QUARANTINED (terminal refusal
		 *     already imported): the timeout is the quarantine doing
		 *     its job.  Poison + fail the op with EIO; NO shutdown.
		 */
		/*
		 * 0.74.0 (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-
		 * STATE-0904): the DLM answered -EHOSTDOWN — the holder is a
		 * dead node whose recovery is RECOVERY_BLOCKED (local master:
		 * P-RBLK-DENY-LOCAL; remote: the master's LOCK_DENY).  Waiting
		 * cannot release that grant, so the op fails -EIO now at the
		 * central gate.  NOT a shutdown and NOT a poison: the state is
		 * re-read on the next entry and clears itself when the slow
		 * re-drive proves exclusion and the purge lands.
		 */
		/*
		 * 0.84.5 (D-JOINER-MOUNT-DURING-BOOTSTRAP-ORPHAN-SWEEP-EXHAUSTS-
		 * REMASTER-RETRIES-SELF-SHUTDOWN-WITHDRAW-0960): the engine
		 * answered -EREMCHG — the resource's ledger page is under a
		 * dead authority a live bootstrap node is taking over, and
		 * that takeover made no progress for 30 s.  Measured (s588b,
		 * s588c, a plain deploy): a joiner's root-inode acquire at
		 * mount, answered REMASTER 60 times in 18 s while the
		 * bootstrap's 157 s takeover-only pass ran, reached arm (3)
		 * below and shut its own filesystem down; the mount then
		 * withdrew, retired its PR key and was fenced and replayed by
		 * the peer it had just joined.  A stalled transition is a
		 * retryable failure of THIS operation and never a membership
		 * escalation: a caller that registered as fallible (the mount's
		 * root acquire is one) fails with -EAGAIN — the mount unwinds
		 * through its ordinary failure path, which releases its slot
		 * and registration cleanly because nothing was shut down — and
		 * a caller that cannot be failed keeps waiting, with backoff,
		 * exactly as it does behind a live holder.
		 */
		if (rc == -EREMCHG && !xfs_is_shutdown(ip->i_mount)) {
			bool fallible = mxfs_acqfall_armed_for(ip->i_ino);
			bool mounting = !ip->i_mount->m_super ||
					!ip->i_mount->m_super->s_root;

			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			trans_laps++;
			if (fallible) {
				mxfs_acqfall_give_up_rc(ip->i_ino, -EAGAIN);
				pr_warn(
				    "mxfs: P960-AUTH-TRANSITION-FAIL ino=%llu mode=%u laps=%d mounting=%d comm=%s — the takeover this acquire waits on stalled; failing THIS OPERATION with -EAGAIN, not the mount, and not shutting down\n",
					(unsigned long long)ip->i_ino, mode,
					trans_laps, mounting ? 1 : 0,
					current->comm);
				{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
			}
			pr_warn(
			    "mxfs: P960-AUTH-TRANSITION-PARK ino=%llu mode=%u laps=%d mounting=%d comm=%s — the takeover this acquire waits on stalled; this caller cannot be failed, waiting again, NOT shutting down\n",
				(unsigned long long)ip->i_ino, mode, trans_laps,
				mounting ? 1 : 0, current->comm);
			msleep(min(500 * trans_laps, 5000));
			{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		if (rc == -EHOSTDOWN) {
			/* 0.75.33 (D-0915): make the denial visible to the
			 * post-ilock backstop (mxfs_quar_gate_locked); cleared
			 * at every grant install below. */
			xfs_iflags_set(ip, MXFS_IF_ACQ_REFUSED);
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			/*
			 * 0.87.23 (D-STAT-ABORTED-...-UNPAIRED): a caller that
			 * registered as fallible must be TOLD it got nothing —
			 * the flag above serves only the namespace backstop, and
			 * a fallible site (stat, open, the read envelope, readdir,
			 * lookup) has no backstop: it returned 0 with the local
			 * lock held and no grant, read cached attributes under a
			 * dead holder, and its end then ran with no begin behind
			 * it (P71-UNDERFLOW un=mxfs_getattr_dlm_unlock, s53d/s53e).
			 * Same shape as the transition-stall arm above.
			 */
			if (mxfs_acqfall_armed_for(ip->i_ino))
				mxfs_acqfall_give_up_rc(ip->i_ino, -EIO);
			pr_warn_ratelimited(
			    "mxfs: P240-RBLK-EIO-ABORT ino=%llu mode=%u comm=%s — grant held by a dead node in RECOVERY_BLOCKED; op fails EIO, NOT shutting down, NOT parking\n",
				(unsigned long long)ip->i_ino, mode,
				current->comm);
			{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		if (rc && mxfs_quarantine_covers_ino(ip->i_mount, ip->i_ino)) {
			xfs_iflags_set(ip, MXFS_IF_QUAR_EIO);
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			pr_warn_ratelimited(
			    "mxfs: P240-QUAR-EIO-ABORT ino=%llu mode=%u rc=%d comm=%s — acquire timed out inside quarantined victim domain; op fails EIO, NOT shutting down\n",
				(unsigned long long)ip->i_ino, mode, rc,
				current->comm);
			{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		/*
		 * (2) A dead peer's recovery is still PENDING (dead-slot bit
		 *     set): the frozen grant may belong to the victim and the
		 *     verdict — replayed OR refused — is not in yet.  Killing
		 *     ourselves now is premature and repeating incident 513;
		 *     park with backoff instead.  Self-releasing on every
		 *     outcome: replay completes → purge frees the grant and
		 *     the next lap acquires; refusal publishes → the import
		 *     lands and the next lap refuses at the entry gate (c),
		 *     failing the op with EIO; our own FS dies → the restart
		 *     shutdown fence returns.  No lap cap by design — the
		 *     bounded-ABBA and recovery-context cases already
		 *     returned above, and an unbounded wait on a pending
		 *     recovery is the ruling's chosen alternative to a
		 *     cluster-wide cascade.
		 *
		 *     ruling item 6, both halves, verified 
		 *     (i) The predicate is deliberately BROAD — any dead slot
		 *     parks this acquire, not only one whose victim domain
		 *     covers this inode.  Impact attribution before the
		 *     verdict lands is guesswork (the victim's frozen grants
		 *     are not enumerable until replay or refusal resolves),
		 *     and a false park costs seconds while a false shutdown
		 *     costs the fleet: containment over diagnosis, accepted
		 *     as a documented trade.
		 *     (ii) Parking here leaves NO outstanding DLM request:
		 *     the CAW acquire is synchronous polled CAS, and every
		 *     -ETIMEDOUT exit (grant-wait, claim-exhaustion, convert)
		 *     drops its own waiter bit via caw_drop_own_waiter with
		 *     confirm-until-clear + the owed-obligation registry, so
		 *     the restart lap re-enters acquire with a clean slate.
		 */
		if (rc &&
		    !bitmap_empty(ip->i_mount->m_mxfs_foreign_dead_slots, 64) &&
		    !xfs_is_shutdown(ip->i_mount)) {
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			park_laps++;
			pr_warn_ratelimited(
			    "mxfs: P240-QUAR-PARK ino=%llu mode=%u rc=%d laps=%d comm=%s — acquire timed out with peer recovery pending; parking until a verdict (replay/refusal) lands, NOT shutting down\n",
				(unsigned long long)ip->i_ino, mode, rc,
				park_laps, current->comm);
			msleep(min(500 * park_laps, 5000));
			{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		/*
		 * (2b) 0.75.28 (D-ACQUIRE-TIMEOUT-BEHIND-LIVE-HOLDER-FAILSTOPS-
		 *     REQUESTER-0912): the budget ran out behind a LIVE party —
		 *     the resource's remote master is a lease member that
		 *     accepted every re-sent request (TCP), or its granted
		 *     holders are all heartbeating (local master, CAW).  A
		 *     live holder's release ends when its drain ends or when
		 *     it dies (membership -> RETRY -> recovery -> purge);
		 *     neither is hastened by the requester destroying its own
		 *     mount.  Measured s517g on 2 nodes / TCP: the survivor
		 *     held ino 131 with its release drain paused for 323 s,
		 *     the rejoined peer's read spent 3 x 60 retries (184 s)
		 *     and took the shutdown below, was fenced for the
		 *     withdraw, and the holder released normally 140 s later.
		 *     Park with backoff and re-ask; the lap log keeps the slow
		 *     release visible as the performance fact it is.  The
		 *     dead-holder cases never reach here live: a blocked or
		 *     refused one answered -EHOSTDOWN above, a pending one is
		 *     parked by (2), and the bounded second-inode acquire of
		 *     an ABBA pair returned before this classifier.
		 */
		/*
		 * (2a) 0.84.2: the engine left the wait early because THIS task
		 *     was sent a fatal signal and had registered as fallible
		 *     (acq_fallible_cb).  Nothing is installed; abandon the
		 *     acquisition by name and let the caller return -EINTR.
		 *     Only a registered task ever sees -EINTR here — the
		 *     engine asks before it interrupts — so a bare -EINTR
		 *     from an unregistered path is a coordination failure and
		 *     falls through to the arms below like any other error.
		 */
		if (rc == -EINTR && !xfs_is_shutdown(ip->i_mount) &&
		    mxfs_acqfall_armed_for(ip->i_ino)) {
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			mxfs_acqfall_give_up(ip->i_ino);
			pr_warn(
			    "mxfs: P958-ACQ-KILLED ino=%llu mode=%u comm=%s — a killed task at a fallible boundary abandons its lock wait; nothing installed, the operation returns -EINTR\n",
				(unsigned long long)ip->i_ino, mode, current->comm);
			mxfs_v5_dlm_inode_acq_abandon(ip->i_mount->m_mxfs_dlm,
						      ip->i_ino, mode);
			{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		if (rc == -ETIMEDOUT && !xfs_is_shutdown(ip->i_mount) &&
		    mxfs_v5_dlm_inode_wait_is_live(ip->i_mount->m_mxfs_dlm,
						   ip->i_ino)) {
			u64 beyond_ms;
			bool receipted, give_up;

			/*
			 * "The party we wait on is live" was the whole of this
			 * test until now, and on this transport that is
			 * answered for a REMOTE master by membership alone —
			 * the requester cannot read a remote master's holder
			 * table, so it cannot see whether anything is queued,
			 * let alone draining.  Measured on 2 nodes / TCP: with
			 * one inode's requests black-holed at the sender, the
			 * peer stayed a healthy member serving its own I/O in
			 * 5 ms while the requester's open() re-sent for 495 s
			 * — 2.7 acquire budgets — logging this line and never
			 * reaching any other outcome.  Nothing in that loop
			 * decreases, expires or escalates, so it does not end.
			 *
			 * Ask the second question too: has the master told us
			 * it HAS this request?  A locally mastered resource
			 * and the CAW transport answer yes by construction
			 * (the holder table is readable here).  A remote TCP
			 * master answers yes only while a queue receipt newer
			 * than the staleness window stands.
			 *
			 * Silence is not on its own grounds to stop: a caller
			 * that cannot be failed safely still waits, and says
			 * so in the log.  Only a caller that registered as
			 * fallible — one sitting at a boundary with nothing
			 * dirty and no transaction open — gives up, and it
			 * fails its own operation rather than the mount.
			 */
			receipted = mxfs_v5_dlm_inode_wait_is_receipted(
					ip->i_mount->m_mxfs_dlm, ip->i_ino,
					mxfs_acq_receipt_stale_ms);
			/* A registered caller also leaves on a fatal signal:
			 * the wait may be legitimate and receipted, but the
			 * task is dead and can unwind. */
			give_up = mxfs_acqfall_armed_for(ip->i_ino) &&
				  (!receipted || fatal_signal_pending(current));

			if (!live_t0)
				live_t0 = ktime_get_ns();
			beyond_ms = (ktime_get_ns() - live_t0) / 1000000ULL;
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			live_laps++;
			if (give_up) {
				mxfs_acqfall_give_up(ip->i_ino);
				mxfs_probe(
				    "mxfs: P912-ACQ-UNRECEIPTED ino=%llu mode=%u rc=%d laps=%d beyond_budget_s=%llu receipted=%d killed=%d comm=%s — the master is a live member but has never said it has this request (or this task was killed); failing THIS OPERATION, not the mount, and not waiting further\n",
					(unsigned long long)ip->i_ino, mode, rc,
					live_laps,
					(unsigned long long)(beyond_ms / 1000ULL),
					receipted ? 1 : 0,
					fatal_signal_pending(current) ? 1 : 0,
					current->comm);
				/*
				 * Abandon it EXACTLY.  Until now the master learned
				 * nothing: the re-sends just stopped, and a waiter or
				 * a committed grant it held for this wait stayed a
				 * blocker for everyone else — with delivery lost, for
				 * ever.  The engine tells the master by name, retries
				 * until acknowledged, and owns the cleanup after this
				 * task has returned its error.
				 */
				mxfs_v5_dlm_inode_acq_abandon(ip->i_mount->m_mxfs_dlm,
							      ip->i_ino, mode);
				{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
			}
			mxfs_probe(
			    "mxfs: P-LKWAIT-LIVE ino=%llu mode=%u rc=%d laps=%d beyond_budget_s=%llu receipted=%d comm=%s — acquire budget exhausted behind a live master/holder; waiting for its release, NOT shutting down\n",
				(unsigned long long)ip->i_ino, mode, rc,
				live_laps,
				(unsigned long long)(beyond_ms / 1000ULL),
				receipted ? 1 : 0,
				current->comm);
			msleep(min(500 * live_laps, 5000));
			{ block_outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
		/*
		 * (3) No quarantine, no pending recovery, nothing live to wait
		 *     for: the timeout is a genuine local coordination failure
		 *     — keep the fail-fast shutdown.
		 */
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
				"mxfs: DLM inode lock unrecoverable: ino=%llu mode=%u rc=%d comm=%s — shutting down filesystem",
				(unsigned long long)ip->i_ino, mode, rc,
				current->comm);
			/* Clear ACQUIRING so subsequent ops see a deterministic
			 * post-shutdown state, and wake any waiters so they
			 * unblock and observe the shutdown via the normal
			 * fs-shutdown checks rather than hanging. */
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			if (ip->i_dlm_acq_inflight)	/* daf50d34 */
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			wake_up_all(&ip->i_dlm_wait);
			xfs_force_shutdown(ip->i_mount,
					   SHUTDOWN_CORRUPT_INCORE);
			{ block_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_acquire_from_dlm_exit; }
		}
	}
mxfs_ilock_acquire_from_dlm_exit:
	*slowpath_publish_io = slowpath_publish;
	*relock_laps_io = relock_laps;
	*recov_laps_io = recov_laps;
	*trans_laps_io = trans_laps;
	*park_laps_io = park_laps;
	*live_t0_io = live_t0;
	*live_laps_io = live_laps;
	return block_outcome;
}

/*
 * Wait while another thread is demoting, acquiring or processing a BAST on this
 * inode, or while an open release-defer episode is parking new EX admissions;
 * return when the inode is free to take, or with the refusal that ends the
 * wait.
 */
static int mxfs_ilock_wait_for_transition(struct xfs_inode *ip, uint8_t mode,
					  int *p73_waits_io)
{
	int mxfs_ilock_wait_for_transition_outcome = MXFS_BLOCK_NEXT;
	int p73_waits = *p73_waits_io;

	while (((ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
		 ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
		 ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) &&
		!mxfs_is_demoter(ip)) ||
	       /* (ruling item 1): an open release-defer
		* episode parks NEW EX admissions here until it closes
		* (successful CAS wakes i_dlm_wait) or wedges (terminal
		* refuse below).  Demoter/ioend/pinned chains exempt. */
	       (mxfs_release_proof_enforce && mode == MXFS_LOCK_EX &&
		ip->i_mxfs_reldefer_started_j &&
		ip->i_dlm_pin_count == 0 &&
		READ_ONCE(ip->i_mxfs_rel_state) != MXFS_RELSTATE_WEDGED &&
		!mxfs_is_demoter(ip))) {
		spin_unlock(&ip->i_dlm_lock);
		/* P73: run68's awk sat here 180s+ invisibly
		 * (hung-task warns only, no mxfs state).  Same wait, but
		 * self-report every ~30s with the FULL dlm state + whether a
		 * bast work/dwork is actually pending — the wedge signature
		 * (state=BAST, ex leaked >0, no work pending) in one line.
		 *
		 * FIX-18 (PROVEN BY INSTRUMENT, run91 ino=8388742):
		 * this was `while (wait_event_timeout(...) == 0)` — on a
		 * PERMANENT wedge the inner while re-slept forever and the
		 * rescue arms below this wait were UNREACHABLE (test6's
		 * awk printed P73 every 30s for 500s with state=BAST ex=1
		 * bast_pend=0 work_busy=0 — a ghost ex_holder kept every
		 * bast_process in P15-abort→re-arm limbo with nothing left to
		 * requeue it — and zero P79 rescues fired cluster-wide while
		 * 7 nodes timed out on the master's still-granted EX and
		 * shut down).  `if` instead: each timeout falls through
		 * to the rescue arms, then the outer while re-evaluates.
		 *
		 * FIX-24 (a9a03929, run106 PROVEN): poll every 3s, not
		 * 30s.  The rescue arms are the CURE for a zombie
		 * DEMOTING/BAST instance (run106 r10: test6's awk slept the
		 * full 30s on ino=10488255 state=2 ex=1 bast_pend=0
		 * work_busy=0, then the arms repaired it instantly — that
		 * single sleep made test6 a 28s create-phase straggler and
		 * blew the dir_reuse in-suite budget; ~5 such stalls/run).
		 * The arms are state-gated no-ops on a live drain, so the
		 * only cost of polling sooner is a cheap mirror re-check. */
		if (wait_event_timeout(ip->i_dlm_wait,
			   ip->i_dlm_state != MXFS_DLM_ISTATE_DEMOTING &&
			   ip->i_dlm_state != MXFS_DLM_ISTATE_ACQUIRING &&
			   ip->i_dlm_state != MXFS_DLM_ISTATE_BAST &&
			   /* keep sleeping while the episode is
			    * open (close and wedge both wake this queue) */
			   !(mxfs_release_proof_enforce &&
			     mode == MXFS_LOCK_EX &&
			     READ_ONCE(ip->i_mxfs_reldefer_started_j) &&
			     READ_ONCE(ip->i_mxfs_rel_state) !=
				MXFS_RELSTATE_WEDGED),
			   3 * HZ) == 0) {
			static atomic_t p73_n = ATOMIC_INIT(0);
			if ((++p73_waits % 10) == 0 &&
			    atomic_inc_return(&p73_n) <= 1000)
				/*
				 * WHO owns the demoter exemption.
				 *
				 * The permanent wedge captured on test7/8/13
				 * (32/caw, 600-840s and climbing, 3 nodes,
				 * identical stacks) is mxfs_dlm_bast_work_fn's
				 * OWN trailing xfs_irele cascading into
				 * evict -> xfs_inactive -> xfs_attr_inactive ->
				 * xfs_ilock and then parking HERE.  That path is
				 * supposed to be covered: 0.10.76 moved
				 * `i_dlm_demoter = NULL` below the irele
				 * precisely so the exemption spans it, and that
				 * ordering is still in the tree.  So either the
				 * claim was cleared/overwritten by another
				 * task, or the exemption is being evaluated
				 * against a different owner than we think.
				 * demoter_pid=0 says CLEARED; a foreign pid says
				 * CLOBBERED and by whom; demoter_line says which
				 * MXFS_SET_DEMOTER made the surviving claim.
				 * Without these three the next occurrence is
				 * another session of inference.
				 */
				pr_warn("mxfs: P73-WAITSTALL ino=%llu req=%u mode=%u state=%u ex=%u pr=%u pin=%u bast_pend=%d work_busy=%d dwork_pend=%d relflush=%d demoter_pid=%d demoter_comm=%s demoter_line=%u:%u demoter_age_ms=%llu acq_inflight=%u acq_pid=%d acq_comm=%s acq_age_ms=%llu me=%d comm=%s\n",
					(unsigned long long)ip->i_ino, mode,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders,
					ip->i_dlm_pin_count,
					ip->i_dlm_bast_pending ? 1 : 0,
					work_busy(&ip->i_dlm_bast_work),
					delayed_work_pending(&ip->i_dlm_bast_dwork) ? 1 : 0,
					xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
					ip->i_dlm_demoter ? ip->i_dlm_demoter_pid : 0,
					ip->i_dlm_demoter ? ip->i_dlm_demoter_comm : "-",
					MXFS_SITE_ARGS(ip->i_dlm_demoter ? ip->i_dlm_demoter_line : 0),
					ip->i_dlm_demoter_set_ns ?
						(ktime_get_ns() - ip->i_dlm_demoter_set_ns) / 1000000ULL : 0,
					/*
					 * (D-MASS-UMOUNT-ROOT-EX-
					 * SERIALIZE-100S-526B, instrument step 2):
					 * THE DISCRIMINATOR.  This wait parks
					 * on state=ACQUIRING as well as on
					 * BAST/DEMOTING, but the line above
					 * names only the DEMOTER — so an
					 * ACQUIRING stall prints demoter_pid=0
					 * and says nothing about who owns it.
					 * i_dlm_acq_inflight is the untrampled
					 * in-flight count: >0 means a real
					 * caw_lock is running and the stall is
					 * transport latency; ==0 with
					 * state=ACQUIRING is a LEAKED state
					 * whose only reclaim (P-ACQ-ORPHAN-
					 * RECLAIM) lives in bast_notify and
					 * therefore cannot fire when no peer
					 * is left to BAST — the
					 * 302-second quiescent-fleet shape.
					 */
					ip->i_dlm_acq_inflight,
					ip->i_dlm_acq_pid,
					ip->i_dlm_acq_comm,
					ip->i_dlm_acq_set_ns ?
						(ktime_get_ns() - ip->i_dlm_acq_set_ns) / 1000000ULL : 0,
					current->pid,
					current->comm);
			/* Replay the claim ring oldest-first.  The CLEAR
			 * between the SET this waiter was relying on and its
			 * own WAIT entry is the culprit, named by source
			 * line and the task that executed it. */
			{
				int k;

				for (k = 0; k < MXFS_DEMEV_N; k++) {
					int idx = (ip->i_dlm_demev_head + k) %
							MXFS_DEMEV_N;
					static const char * const opn[] = {
						"SET", "CLEAR", "WAIT",
						"SET-REFUSED", "CLEAR-NEST",
						"CLEAR-REFUSED",
						"PUNT-RECLAIM" };
					uint8_t o = ip->i_dlm_demev_op[idx];

					if (!ip->i_dlm_demev_cookie[idx])
						continue;
					mxfs_probe("mxfs:   P73-DEMEV[%d] %s line=%u:%u pid=%d state=%u cookie=%u\n",
						k, o < ARRAY_SIZE(opn) ? opn[o] : "?",
						MXFS_SITE_ARGS(ip->i_dlm_demev_line[idx]),
						ip->i_dlm_demev_pid[idx],
						ip->i_dlm_demev_state[idx],
						ip->i_dlm_demev_cookie[idx]);
				}
			}
		}
		spin_lock(&ip->i_dlm_lock);
		/* FIX-25 in-loop arm: the drain may have entered BAST/DEMOTING
		 * after we started waiting; the ioend worker must still be
		 * admitted or the folio-writeback cycle wedges (run109). */
		if (mxfs_ilock_admit_ioend(ip, mode)) {
			spin_unlock(&ip->i_dlm_lock);
			{ mxfs_ilock_wait_for_transition_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_wait_for_transition_exit; }
		}
		/* (ruling item 2): a waiter that parked
		 * BEFORE the wedge fired wakes here — terminal refuse, same
		 * as the entry gate (the op dies at the trans layer). */
		if (mxfs_release_proof_enforce &&
		    READ_ONCE(ip->i_mxfs_rel_state) == MXFS_RELSTATE_WEDGED) {
			spin_unlock(&ip->i_dlm_lock);
			pr_warn_ratelimited(
			    "mxfs: P-INODE-WEDGE-FENCE ino=%llu mode=%u — release wedged; refusing DLM acquire (postwait)\n",
				(unsigned long long)ip->i_ino, mode);
			{ mxfs_ilock_wait_for_transition_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_wait_for_transition_exit; }
		}
		/* Re-check fast path — a peer thread's caw_lock may have
		 * fetched/upgraded the lock and our cached mode now satisfies
		 * the request.  never re-admit EX while the defer
		 * episode is still open (the park exists to close it). */
		if ((ip->i_dlm_mode == MXFS_LOCK_EX ||
		     (ip->i_dlm_mode == MXFS_LOCK_PR && mode == MXFS_LOCK_PR)) &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		    !(mxfs_release_proof_enforce && mode == MXFS_LOCK_EX &&
		      ip->i_mxfs_reldefer_started_j &&
		      ip->i_dlm_pin_count == 0)) {
			if (mode == MXFS_LOCK_EX) {
				ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
				mxfs_p71_hold(ip, "begin-postwait", 1, 0);
			} else {
				ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
				mxfs_p71_hold(ip, "begin-postwait", 0, 1);
			}
			spin_unlock(&ip->i_dlm_lock);
			{ mxfs_ilock_wait_for_transition_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_wait_for_transition_exit; }
		}
		/* FIX-1 (in-loop form): a waiter that was
		 * ALREADY asleep when the P15 abort flipped DEMOTING->BAST
		 * wakes here, sees BAST, and would re-sleep — the deadlock
		 * arm.  Same admit as the pre-loop arm: holders counted +
		 * mirror still granted >= request -> admit; empty mirror ->
		 * stale BAST, clear to NONE (loop exits, slow path runs). */
		if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST &&
		    (ip->i_dlm_ex_holders > 0 || ip->i_dlm_pr_holders > 0) &&
		    !mxfs_is_demoter(ip) &&
		    ip->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
			uint8_t g2;

			spin_unlock(&ip->i_dlm_lock);
			g2 = mxfs_v5_dlm_inode_granted_mode(
				ip->i_mount->m_mxfs_dlm, ip->i_ino);
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST &&
			    (ip->i_dlm_ex_holders > 0 ||
			     ip->i_dlm_pr_holders > 0)) {
				if (g2 >= mode && g2 != MXFS_LOCK_NL) {
					static atomic_t p79l_n = ATOMIC_INIT(0);

					if (ip->i_dlm_mode < g2)
						{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
						ip->i_dlm_mode = g2;
						mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
					if (mode == MXFS_LOCK_EX) {
						ip->i_dlm_ex_holders++; MXFS_DLMTR_H(ip);
						mxfs_exh_stamp_locked(ip);
					} else {
						ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
					}
					if (atomic_inc_return(&p79l_n) <= 4000)
						mxfs_probe("mxfs: P79-NESTADMIT-LOOP ino=%llu req=%u granted=%u now_ex=%u now_pr=%u comm=%s\n",
							(unsigned long long)ip->i_ino,
							mode, g2,
							ip->i_dlm_ex_holders,
							ip->i_dlm_pr_holders,
							current->comm);
					spin_unlock(&ip->i_dlm_lock);
					{ mxfs_ilock_wait_for_transition_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_wait_for_transition_exit; }
				}
				if (g2 < mode) {
					/* run71: also the insufficient-
					 * mirror (PR-held, EX-wanted) upgrade
					 * case — escape to the slow path. */
					{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
					ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
					mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
					mxfs_probe("mxfs: P79-STALEBAST-CLEAR-LOOP ino=%llu req=%u granted=%u\n",
						(unsigned long long)ip->i_ino,
						mode, g2);
					wake_up_all(&ip->i_dlm_wait);
				}
			}
		}
		/* FIX-18b: dead demote instance with NO local
		 * holders — the ilock_end refire only triggers on a holder's
		 * 1→0 transition, so state BAST/DEMOTING with holders==0 and
		 * the bast work neither pending nor running is permanent:
		 * nothing will ever complete the release (run91's shape when
		 * the ghost holder is absent).  Re-drive the release through
		 * the normal machinery — the work fn re-runs its own gates. */
		if ((ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
		     ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) &&
		    ip->i_dlm_ex_holders == 0 && ip->i_dlm_pr_holders == 0 &&
		    !mxfs_is_demoter(ip) &&
		    !work_busy(&ip->i_dlm_bast_work)) {
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			pr_warn("mxfs: P-DEMWAIT-REDRIVE ino=%llu req=%u mode=%u — dead demote instance (no holders, work idle); re-driving release\n",
				(unsigned long long)ip->i_ino, mode,
				ip->i_dlm_mode);
			spin_unlock(&ip->i_dlm_lock);
			/* 2026-07-16: igrab, never raw ihold (BUG3 family —
			 * see P134-BASTQ-FREEING at the orphan_rearm site). */
			if (igrab(VFS_I(ip))) {
				ip->i_dlm_bastq_src = 2;
				if (!mxfs_bast_arm_queue(ip))
					xfs_irele(ip);	/* raced pending — drop ref */
			} else {
				/*
				 * PROVEN BY INSTRUMENT live on
				 * test4 (32/tcp drc, ino 25705550, 29-minute
				 * 3s-cycle): the igrab refusal is correct for
				 * the BUG3 phantom-ref hazard, but when the
				 * inode is FREEING the task blocked in THIS
				 * wait loop is the eviction itself
				 * (xfs_inactive -> xfs_free_eofblocks ->
				 * ilock_begin) — skipping the re-drive leaves
				 * NOBODY to clear the dead DEMOTING instance
				 * and the teardown deadlocks against its own
				 * guard (P-DEMWAIT-REDRIVE / P134 ping-pong
				 * forever, peers starve).  Run the release
				 * INLINE, ref-free: this frame pins the struct
				 * (the eviction that owns teardown is the one
				 * standing here), we hold no ILOCK on ip (we
				 * are waiting to take it), and the eviction
				 * path carries no buffer locks into xfs_ilock
				 * — none of the inline hazards apply.
				 */
				pr_warn_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=demwait_redrive i_state=0x%lx — evicting; running dead-demote release INLINE\n",
					(unsigned long long)ip->i_ino,
					mxfs_istate(VFS_I(ip)));
				{
					struct mxfs_dirdrain_task dde;

					mxfs_dirdrain_enter(&dde);
					mxfs_dlm_bast_process(ip);
					mxfs_dirdrain_exit(&dde);
				}
			}
			spin_lock(&ip->i_dlm_lock);
		}
	}
mxfs_ilock_wait_for_transition_exit:
	*p73_waits_io = p73_waits;
	return mxfs_ilock_wait_for_transition_outcome;
}

/*
 * Report, rate-limited, which admission precondition failed when a
 * non-directory inode is asked for while another thread is demoting, acquiring
 * or processing a BAST on it.
 */
static void mxfs_ilock_report_admit_refusal(struct xfs_inode *ip, uint8_t mode)
{
	if (!S_ISDIR(VFS_I(ip)->i_mode) &&
	    (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
	     ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
	     ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) &&
	    !mxfs_is_demoter(ip)) {
		static atomic_t p47fb = ATOMIC_INIT(0);
		/*
		 *  print WHICH admit precondition failed.
		 *
		 * D-BAST-WRITEBACK-ABBA-DEADLOCK was captured as two kernel
		 * stacks and nothing more, so it is still unknown whether the
		 * wedged writeback submitter asked for EX (in which case FIX-26
		 * should have admitted it and some OTHER condition failed) or for
		 * SHARED (FIX-27's case).  xfs_convert_blocks is static and very
		 * likely inlined into xfs_map_blocks, so the stack alone cannot
		 * distinguish them -- and a census of 3613 shared demote-wait
		 * blocks under a healthy 32-node workload produced ZERO admits,
		 * i.e. essentially none of the ordinary blocks come from the
		 * writeback-submission context at all.
		 *
		 * mxfs_ilock_admit_ioend refuses on exactly four things: not in
		 * writepages/ioend context, wrong requested mode, state not
		 * BAST/DEMOTING, or the mirror's granted mode (g2) being neither
		 * EX nor PR.  req/mode/state are already here; in_wb, in_ioend and
		 * g2 are what is missing.  With all six, the NEXT occurrence names
		 * the failing condition instead of requiring another session of
		 * inference.
		 */
		if (atomic_inc_return(&p47fb) <= 4000) {
			uint8_t p47g2;

			spin_unlock(&ip->i_dlm_lock);
			p47g2 = ip->i_dlm_routed_iclus ?
				mxfs_iclus_granted_mode(ip->i_mount, ip->i_ino) :
				mxfs_v5_dlm_inode_granted_mode(
					ip->i_mount->m_mxfs_dlm, ip->i_ino);
			spin_lock(&ip->i_dlm_lock);
			mxfs_probe("mxfs: P47-FILEBLOCK ino=%llu req=%u mode=%u state=%u g2=%u dsite=%u in_wb=%d in_ioend=%d ex_h=%u pr_h=%u pin=%u comm=%s — file blocking on demote-wait (fast path did not admit)\n",
				(unsigned long long)ip->i_ino, mode,
				ip->i_dlm_mode, ip->i_dlm_state, p47g2,
				ip->i_dlm_drain_site,
				xfs_task_in_writepages() ? 1 : 0,
				xfs_task_in_ioend() ? 1 : 0,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count, current->comm);
		}
	}
}

/*
 * FIX-1 (PROVEN BY INSTRUMENT, run68 + run69): nested-hold
 * self-deadlock breaker.
 *
 * xfs_ilock maps IOLOCK and ILOCK onto this ONE per-inode DLM lock.
 * A buffered write holds IOLOCK_EXCL (counted in i_dlm_ex_holders)
 * and then takes ILOCK nested inside it (xfs_file_write_checks ->
 * file_remove_privs getxattr / file_update_time).  When a BAST lands
 * between the two acquires, the nested acquire used to fall into the
 * DEMOTING/BAST wait below — waiting for a release that itself waits
 * for holders==0, i.e. for this task's own outer hold: deadlock.
 * PROVEN twice: P73-WAITSTALL ino=8388765 state=BAST ex=1 comm=awk
 * (run69, 300s+) with the same awk blocked in remove_privs' PR while
 * its own write held the IOLOCK-EX count; identically run68
 * ino=6293428.  The stuck node's retained/phantom master grant then
 * convoys EVERY peer's create on that inum (all-node 0/8 timeout).
 *
 * At state==BAST no drain is in flight (the release is DEFERRED until
 * holders drain — bast_notify/P15-abort semantics) and local
 * task-vs-task exclusion is the rwsems' job, not the DLM's — the DLM
 * layer only answers "does this NODE hold a sufficient grant".  So
 * while ANY local holder is counted and the v5 mirror still records a
 * granted mode >= the request, admit the request and restore
 * i_dlm_mode from the mirror (an abort path may have left it NL,
 * which would otherwise trip the non-EX authority guards).  The last
 * ilock_end then re-fires the deferred BAST with a FULL fresh drain,
 * so peer coherency is unchanged.  If the mirror holds NOTHING the
 * BAST state is stale (nothing to release): clear to NONE and wake,
 * letting waiters take the real slow path.
 */
static int mxfs_ilock_nested_hold_guard(struct xfs_inode *ip, uint8_t mode)
{
	int mxfs_ilock_nested_hold_guard_outcome = MXFS_BLOCK_NEXT;

	if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST &&
	    (ip->i_dlm_ex_holders > 0 || ip->i_dlm_pr_holders > 0) &&
	    !mxfs_is_demoter(ip) &&
	    ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
		uint8_t g;

		spin_unlock(&ip->i_dlm_lock);
		g = mxfs_v5_dlm_inode_granted_mode(ip->i_mount->m_mxfs_dlm,
						   ip->i_ino);
		spin_lock(&ip->i_dlm_lock);
		/* re-verify under the lock — state may have moved */
		if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST &&
		    (ip->i_dlm_ex_holders > 0 || ip->i_dlm_pr_holders > 0)) {
			if (g >= mode && g != MXFS_LOCK_NL) {
				static atomic_t p79_n = ATOMIC_INIT(0);

				if (ip->i_dlm_mode < g)
					{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
					ip->i_dlm_mode = g;
					mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				if (mode == MXFS_LOCK_EX) {
					ip->i_dlm_ex_holders++; MXFS_DLMTR_H(ip);
					mxfs_exh_stamp_locked(ip);
				} else {
					ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
				}
				if (atomic_inc_return(&p79_n) <= 4000)
					mxfs_probe("mxfs: P79-NESTADMIT ino=%llu req=%u granted=%u now_ex=%u now_pr=%u comm=%s\n",
						(unsigned long long)ip->i_ino,
						mode, g,
						ip->i_dlm_ex_holders,
						ip->i_dlm_pr_holders,
						current->comm);
				spin_unlock(&ip->i_dlm_lock);
				{ mxfs_ilock_nested_hold_guard_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_nested_hold_guard_exit; }
			}
			if (g < mode) {
				/* run71: ALSO the g>NL-but-insufficient
				 * case (mirror=PR, request=EX): the PR->EX
				 * upgrade cannot go through the local release
				 * (it waits for our own outer hold) — send the
				 * waiter to the slow path, which issues a
				 * proper convert to the master.  The peers'
				 * BAST is re-delivered by their 1s retries
				 * once we hold EX. */
				static atomic_t p79s_n = ATOMIC_INIT(0);

				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				if (atomic_inc_return(&p79s_n) <= 2000)
					mxfs_probe("mxfs: P79-STALEBAST-CLEAR ino=%llu req=%u granted=%u ex=%u pr=%u — BAST wait unsatisfiable; cleared to NONE for slow path\n",
						(unsigned long long)ip->i_ino,
						mode, g, ip->i_dlm_ex_holders,
						ip->i_dlm_pr_holders);
				wake_up_all(&ip->i_dlm_wait);
				/* fall through — the checks below re-evaluate
				 * at state NONE and take the slow path. */
			}
		}
	}
mxfs_ilock_nested_hold_guard_exit:
	return mxfs_ilock_nested_hold_guard_outcome;
}

/*
 * STEP 1 (PROVE): on-disk ownership verify for the
 * dir-EX fast-path.  inode_held()==0 means the in-memory
 * i_dlm_mode==EX is STALE (CAW slot already released) — the
 * proven stale-cached-EX mutual-exclusion violation that lets
 * this node RMW the dir inside a peer's EX window and durably
 * clobber the peer's committed dirent.  Probe-only; no
 * behavior change yet (the fix falls through to slow-path
 * re-acquire once this is confirmed firing).
 */
static int mxfs_ilock_verify_dir_ex_ownership(bool dir_ex_verify_held,
					      int s6_raw_snap,
					      struct mxfs_v5_dlm *dlm,
					      struct xfs_inode *ip,
					      int *phantom_laps_io, uint8_t mode,
					      int *mxfs_ilock_fast_path_outcome_io)
{
	int outcome = MXFS_BLOCK_NEXT;
	int phantom_laps = *phantom_laps_io;
	int mxfs_ilock_fast_path_outcome = *mxfs_ilock_fast_path_outcome_io;

	if (dir_ex_verify_held) {
		/*  reuse the snapshot
		 * (same slot, read moments ago) instead of a second
		 * on-disk probe-chain walk. */
		bool held_sampled = true;
		int held;

		if (s6_raw_snap >= 0) {
			held = s6_raw_snap > MXFS_LOCK_NL ? 1 : 0;
		} else {
			/* the snapshot-miss fallback is
			 * the same synchronous slot read and gets
			 * the same deadline. */
			MXFS_VERIFY_SITE_INC(mxfs_verify_site_s7_n);
			held = mxfs_dlm_verify_rawmode(dlm, ip->i_ino,
				&held_sampled) > MXFS_LOCK_NL
				? 1 : 0;
		}
		/* 0.75.35 (D-482): the denominator, and the one-shot
		 * injection at the "not present" decision. */
		WRITE_ONCE(mxfs_p106_check_n, mxfs_p106_check_n + 1);
		if (unlikely(mxfs_dbg_p106_inject_take(ip->i_ino))) {
			/*
			 * 0.75.36: the 0.75.35 form of this injection
			 * only LIED to the check (held = 0) while the
			 * transport still recorded this node as the EX
			 * holder.  That is the opposite divergence
			 * from a phantom: the bail then dropped the
			 * cached grant with no wire release, the peer's
			 * request BASTed a node that had nothing it
			 * could prove to release, and the bounded
			 * release episode wedged, shut the mount down
			 * and self-withdrew it (s521a).  A phantom is
			 * the wire having LOST a grant the cache still
			 * believes in, so the injection now produces
			 * exactly that: release the grant on the wire
			 * behind the cache, then let the real check
			 * read the wire.  Only a genuine sample may
			 * demote, as always.
			 */
			int inj_rc = mxfs_v5_dlm_inode_unlock_gen(dlm,
						ip->i_ino, 0);

			held = mxfs_dlm_verify_rawmode(dlm, ip->i_ino,
				&held_sampled) > MXFS_LOCK_NL ? 1 : 0;
			mxfs_probe("mxfs: P106-INJECT-CONSUMED ino=%llu epoch=%lu mode=%u state=%u ex_h=%u pr_h=%u pin=%d unlock_rc=%d resample_held=%d sampled=%d — INJECTED: wire grant released behind the cache; the backing-record check read the wire for real\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_epoch, ip->i_dlm_mode,
				ip->i_dlm_state, ip->i_dlm_ex_holders,
				ip->i_dlm_pr_holders, ip->i_dlm_pin_count,
				inj_rc, held, held_sampled ? 1 : 0);
		}
		/* only a REAL sample may demote. */
		if (held_sampled && held == 0) {
			mxfs_probe(
			"mxfs: P106-STALE-EX ino=%llu cached_mode=EX on_disk_held=0 state=%u pin=%d unpub=%d gen=%llu realns=%llu\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_state,
				ip->i_dlm_pin_count,
				ip->i_dlm_unpublished ? 1 : 0,
				(unsigned long long)ip->i_dlm_dir_gen,
				(unsigned long long)ktime_get_real_ns());
			/* v0.6.4 P142: raw image at the exact
			 * phantom moment — the mechanism reads
			 * off the slot bytes. */
			mxfs_v5_dlm_inode_dump_slot(dlm,
						    ip->i_ino);
			/* v0.6.5 (186320ae) — ENFORCE.  Instrumented
			 * PROVEN (dlm_fairness 4/caw run 015448Z, ino
			 * 6291584 @:27.692995): the probe fired mid-mv
			 * (P142: holders bitmap EMPTY, lastex=self) and
			 * the phantom tenure's RMWs let a peer acquire
			 * EX concurrently -> dual-writer -> the n2_r1.done
			 * ghost rode test2's in-core sf for 49 rounds ->
			 * "df shared dir drained(exp=0 got=1)".  The
			 * comment above documents this exact fix:
			 * do NOT serve a phantom grant — undo the serve,
			 * demote the cached grant to NL, and take the
			 * slow path for a REAL on-disk acquire (+ reload).
			 * Gates: unpublished inodes legitimately have no
			 * slot (handles their EX-modify before the
			 * serve); pin_count==0 rules out a held AGF so the
			 * blocking CAW acquire cannot ABBA-deadlock (the
			 * /design review proof); only a clean CACHED state
			 * with no active demoter is unwound (a mid-demote
			 * BAST worker owns the transition otherwise);
			 * bounded laps so a pathological slot flap cannot
			 * livelock (falls back to probe-only behavior). */
			if (!ip->i_dlm_unpublished &&
			    ip->i_dlm_pin_count == 0 &&
			    phantom_laps < 3) {
				bool undone = false;

				spin_lock(&ip->i_dlm_lock);
				if (ip->i_dlm_state ==
					MXFS_DLM_ISTATE_CACHED &&
				    !ip->i_dlm_demoter &&
				    ((mode == MXFS_LOCK_EX &&
				      ip->i_dlm_ex_holders > 0) ||
				     (mode != MXFS_LOCK_EX &&
				      ip->i_dlm_pr_holders > 0))) {
					u8 dtr_om, dtr_os;

					mxfs_inode_authority_phantom_loss_locked(
						ip, MXFS_SITE);
					if (mode == MXFS_LOCK_EX) {
						ip->i_dlm_ex_holders--; MXFS_DLMTR_H(ip);
					} else {
						ip->i_dlm_pr_holders--; MXFS_DLMTR_H(ip);
					}
					dtr_om = ip->i_dlm_mode;
					dtr_os = ip->i_dlm_state;
					ip->i_dlm_mode = MXFS_LOCK_NL;
					ip->i_dlm_state =
						MXFS_DLM_ISTATE_NONE;
					/*
					 * this is a grant LOSS and must
					 * advance the epoch like every other one.
					 * i_dlm_epoch's own declaration states the
					 * invariant -- "bumped every time this node
					 * LOSES the inode's DLM grant (mode -> NL)"
					 * -- and d_revalidate's zero-I/O fast path
					 * rests entirely on it: a dentry whose
					 * d_time still equals the parent's epoch is
					 * returned VALID with no lookup at all.
					 *
					 * Of the nine sites that set mode to NL this
					 * was the only one that did not bump, which
					 * left the counter able to return to a value
					 * it already had.  A dentry stamped E while
					 * the cache believed in this phantom grant
					 * survived the discovery that the grant was
					 * never real: mode went NL and back to EX
					 * with E unchanged, so the fast path went on
					 * blessing a binding earned under authority
					 * the code had just disavowed.  Neither
					 * helper below covers it --
					 * mxfs_dir_base_invalidate clears only the
					 * directory-block baseline bit, and the
					 * authority-loss call touches only the
					 * certificate; nothing on this path drops a
					 * dentry.
					 *
					 * Under i_dlm_lock, as at the four other
					 * bump sites that hold it.
					 */
					ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
					mxfs_dlmtr_rec(ip, dtr_om,
						       dtr_os,
						       MXFS_SITE);
					undone = true;
				}
				spin_unlock(&ip->i_dlm_lock);
				if (undone) {
					phantom_laps++;
					/* Option B: the
					 * cached EX was phantom —
					 * whatever the baseline
					 * vouched for is void. */
					if (S_ISDIR(VFS_I(ip)->i_mode))
						mxfs_dir_base_invalidate(ip, 3);
					mxfs_probe(
					"mxfs: P106-STALE-EX-BAIL ino=%llu lap=%d epoch=%lu epoch_src=%u:%u — phantom cached EX demoted to NL (epoch advanced); re-acquiring on-disk via slow path\n",
						(unsigned long long)ip->i_ino,
						phantom_laps, ip->i_dlm_epoch,
						MXFS_SITE_ARGS(ip->i_dlm_epoch_src));
					/* 0.75.35 (D-482): one-shot authority
					 * gap for the reproducer — the mode is
					 * NL and no holder is counted, so a
					 * peer's EX request is served meanwhile. */
					{
						int pms = xchg(&mxfs_dbg_p106_bail_pause_ms, 0);

						if (unlikely(pms > 0)) {
							mxfs_probe("mxfs: P106-BAIL-PAUSE ino=%llu ms=%d — INJECTED: parking in the authority gap before the re-acquire\n",
								(unsigned long long)ip->i_ino, pms);
							while (pms > 0) {
								msleep(pms > 100 ? 100 : pms);
								pms -= 100;
							}
							mxfs_probe("mxfs: P106-BAIL-PAUSE-END ino=%llu\n",
								(unsigned long long)ip->i_ino);
						}
					}
					{ mxfs_ilock_fast_path_outcome = MXFS_BLOCK_GOTO + 0; { outcome = MXFS_BLOCK_GOTO + 0; goto mxfs_ilock_verify_dir_ex_ownership_exit; } }
				}
			}
		}
		/* P-TDS: full picture on EVERY dir-EX-modify
		 * serve under dirwr — held + stale-base + the base we
		 * are about to RMW.  Cross-node correlate by ino+realns:
		 * a held=0 OR stale_base=1 here on the survivor node is
		 * the durable clobber of the peer's committed change. */
		if (mxfs_dirwr_enabled)
			mxfs_probe(
			"mxfs: P-TDS-RMW ino=%llu held=%d mode=%u state=%u pin=%d ex_h=%u pr_h=%u fmt=%d dir_gen=%llu loaded_gen=%u stale_base=%d unpub=%d selfc=%d comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino,
				held, ip->i_dlm_mode, ip->i_dlm_state,
				ip->i_dlm_pin_count,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_df.if_format,
				(unsigned long long)ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen,
				(ip->i_dlm_dir_gen >
				 ip->i_dlm_dir_loaded_gen) ? 1 : 0,
				ip->i_dlm_unpublished ? 1 : 0,
				ip->i_mxfs_self_created ? 1 : 0,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
	}
mxfs_ilock_verify_dir_ex_ownership_exit:
	*phantom_laps_io = phantom_laps;
	*mxfs_ilock_fast_path_outcome_io = mxfs_ilock_fast_path_outcome;
	return outcome;
}

/*
 * RE-ENABLED (the "DEAD END" verdict was
 * conditioned on a premise that is now FALSE).
 * disabled this fast-path acquire-side evict because the
 * cold-read returned a STALE image MISSING this node's OWN
 * just-committed dir change (own writes were NOT durable on
 * the shared LUN at evict time — note_dir_modified bumped
 * peers' gen at commit but the modified block sat in-core
 * until xfsaild/BAST), which regressed rename_visibility
 * 0->40.  then landed PUBLISH-BEFORE-NOTIFY
 * (mxfs_dlm_dir_durable_signal: post-commit log_force +
 * bwrite each dir DATA block + blkdev_issue_flush, EX held,
 * in xfs_remove/xfs_create/xfs_rename) — so own dir changes
 * are now DURABLE on the LUN before any peer's gen is bumped.
 * That removes the exact failure that disabled this evict.
 *
 * The asymmetry this closes (PROVEN gen-hole): the
 * SLOW-path dir acquire calls mxfs_dir_drain_evict_data_blocks
 * (line ~3504) giving a FRESH base, but a FAST-path cached-EX
 * re-grant did NO evict -> RMWs a STALE cached dir block ->
 * durably clobbers a peer's committed removal (the
 * unlink_visibility lost-update; P-DIRFASTEX stale_base=1 on
 * the survivor node).  Gen-gated (i_dlm_dir_gen >
 * i_dlm_dir_loaded_gen) so it fires only when a peer actually
 * modified the dir (~10x/run), not every dir-EX op.
 *
 * NO blkdev_issue_flush barrier on the reader: PROVED
 * the transport is coherent (raw O_DIRECT dir-block bytes are
 * byte-identical across initiators), and publish-before-notify
 * already SYNCHRONIZE-CACHEs the WRITER, so a plain cold-read
 * after the evict observes the peer's durable image without a
 * second flush here (avoids flush-storm 24s->500s).
 */
static void mxfs_ilock_refresh_stale_dir_ex(bool dir_ex_stale_refresh,
					    struct xfs_inode *ip,
					    bool dir_ex_handoff)
{
	if (dir_ex_stale_refresh) {
		u64 want_gen = ip->i_dlm_dir_gen;
		int left;

		/*
		 * FIX — a fast-path EX
		 * re-grant with stale_base must REBUILD THE EXTENT
		 * MAP, not just evict data blocks.  drain_evict
		 * below re-reads blocks at daddrs the cached extent
		 * fork already names, but when the peer GREW the dir
		 * (block->leaf adds a leaf block at dir-logical
		 * offset 0x800000, or block->shortform->block moved
		 * the data block to a new daddr) the extent MAP
		 * itself changed.  Without a fork rebuild the next
		 * RMW maps a dir offset onto a HOLE / a freed block
		 * -> xfs_dabuf_map "XFS_DABUF_MAP_HOLE_OK" internal
		 * error (xfs_da_btree.c:2814, Caller xfs_create) ->
		 * xfs_trans_cancel -> FS shutdown -> posix barriers
		 * hang -> >600s.  The slow-path acquire already
		 * reloads here (line ~5847); mirror it on the
		 * fast path.  reload takes i_lock via down_write_
		 * trylock and we hold no ILOCK here (only released
		 * i_dlm_lock above), matching the slow path.
		 */
		/*
		 * FIX: the evict-ring arms
		 * MXFS_IF_DIR_RELOAD WITHOUT bumping i_dlm_dir_gen when
		 * gen==0 (line ~8633), so a fast-path EX modify that
		 * keys only on the gen never rebuilt the extent map and
		 * decided FMT_BLOCK on a block->leaf-grown dir
		 * (PROVEN: P56-FMT-BLOCK-RELOAD-PENDING ino=133
		 * nextents=2 -> xfs_dir3_block_verify on the XDD3 data
		 * block -> Metadata I/O Error -> shutdown).  Consume the
		 * flag here on the EX-acquire fast path too; re-arm if
		 * the reload bailed (i_lock contended) so the next
		 * access retries.  Mirrors the consumer path at ~L1192.
		 */
		xfs_iflags_clear(ip, MXFS_IF_DIR_RELOAD);
		ip->i_dlm_stale = true; ip->i_dlm_stale_src = 8;
		/* on a RELIABLE cross-node handoff
		 * (grant_gen change / dir_epoch advance) a different
		 * node held EX since our last grant, so our own prior
		 * work was drained at that release — force a disk-
		 * SUPERSET adopt (post_release=true) that OVERRIDES the
		 * keep-stale guards, so a stale in-core shortform base is
		 * replaced by the peer's committed image BEFORE any
		 * sf->block conversion (fixes the round-1 node2_f1 durable
		 * loss / sf<->block flip-flop).  For the lossy/self-echo
		 * gen/RELOAD-flag setter keep post_release=false (
		 * own-mods self-skip — our in-flight grow must not revert). */
		mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN,
				      dir_ex_handoff);
		if (ip->i_dlm_stale)
			xfs_iflags_set(ip, MXFS_IF_DIR_RELOAD);

		left = mxfs_dir_drain_evict_data_blocks(ip);
		/* the design review "must-complete
		 * invalidation barrier" (log_force+retry until left==0
		 * on grant_gen handoff) was TESTED here and did NOT
		 * improve N=8 dir_reuse (1/5, same as without) — the
		 * residual 1-3 dirent loss survives a FULLY-EVICTED
		 * cold-read base, so it is NOT the pin/undestaged skip.
		 * Reverted (it only added handoff latency).  Next
		 * suspects: a gg_refresh-BYPASS acquire path (demoter-
		 * bypass ~15106 serves without refresh), or a
		 * release-durability gap for a peer's late commit. */
		/* this IS the reliable cross-node handoff
		 * (dir_ex_handoff: grant_gen advanced / dir_epoch
		 * up).  The extent-map evict above misses a clean
		 * stale cached dir block out of the current in-core
		 * map -> the imminent RMW reads it stale and durably
		 * reverts the peer's add (the readdir=799 loss that
		 * SURVIVED the release-side owner-scan).  Drop every
		 * CLEAN owned dir block, map-independent, so the RMW
		 * cold-reads the peer's durable image. */
		mxfs_dir_evict_owned_data_blocks(ip);
		/* Advance loaded_gen ONLY on a COMPLETE refresh:
		 * no newer peer mod raced in (gen unchanged) AND
		 * drain_evict left no undurable block cached
		 * (left==0).  If a stale block was skipped (our own
		 * dirty/pinned work still present), keep stale_base
		 * true so a later read/acquire re-attempts the evict
		 * once that block checkpoints — otherwise we would
		 * serve the skipped stale block forever (
		 * unlink reader-staleness root). */
		if (ip->i_dlm_dir_gen == want_gen && left == 0)
			ip->i_dlm_dir_loaded_gen = want_gen;
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited(
				"mxfs: P101-FASTEX-EVICT ino=%llu want_gen=%llu loaded_gen=%u left=%d\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)want_gen,
				ip->i_dlm_dir_loaded_gen, left);
	}
}

/*
 * (plan) RELIABLE tenure-change check.  The lossy
 * DIR_MODIFY eviction-ring (i_dlm_dir_gen) misses peer modifies on
 * TCP, so dir_ex_stale_refresh above can be FALSE while a peer grew
 * the dir — the fast-path EX RMW then clobbers the peer's dirents
 * off a STALE base (PROVEN dirty bufgen=0 block0, core
 * behind disk).  The acked-TCP per-grant token (grant_gen) changes
 * ONLY when the lock changed hands; if it differs from the value
 * cached at our last slow-path grant, a peer held EX since -> our
 * dir base is stale -> force the stale-base refresh below + bump
 * i_dlm_dir_gen so the dir-DATA read hook re-reads.  MHT preserved:
 * within one tenure grant_gen is unchanged so the fast path keeps
 * serving.  Query after spin_unlock (table_rwlock not allowed under
 * the i_dlm spinlock), same as the dir_ex_verify_held path below. */
static void mxfs_ilock_tenure_change_check(struct xfs_inode *ip, uint8_t mode,
					   bool *dir_ex_stale_refresh_io,
					   bool *dir_ex_handoff_io,
					   bool dir_ex_verify_held,
					   int *s6_raw_snap_io)
{
	bool dir_ex_stale_refresh = *dir_ex_stale_refresh_io;
	bool dir_ex_handoff = *dir_ex_handoff_io;
	int s6_raw_snap = *s6_raw_snap_io;

	if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX &&
	    ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
		/* the REFINED signal asked for.  grant_gen
		 * alone over-fired (it bumps on benign same-node re-grants),
		 * so refreshing on every grant_gen change resurrected
		 * deletes (2/24 -> 16/24).  The master now exposes the PRIOR
		 * EX OWNER via dg_shadow: handoff==true iff a DIFFERENT node
		 * held EX since our last grant.  Only THEN is our cached-EX
		 * dir base stale (and our prior tenure was drained at
		 * release, so the reload's disk-superset adopt cannot
		 * resurrect).  Consumed once per grant episode via
		 * i_dlm_handoff_acted_gen (the reload below advances it).
		 * Within one tenure handoff stays false -> fast path keeps
		 * serving (no dlm_fairness starvation). */
		uint32_t hgg = 0;
		bool ho = mxfs_v5_dlm_inode_grant_handoff(
			ip->i_mount->m_mxfs_dlm, ip->i_ino, &hgg);
		if (ho && hgg != 0 &&
		    hgg != ip->i_dlm_handoff_acted_gen) {
			dir_ex_stale_refresh = true;
			dir_ex_handoff = true;	/* reliable handoff */
			if (mxfs_dir_gen_per_handoff ||
			    ip->i_dlm_dir_gen <=
			    ip->i_dlm_dir_loaded_gen)
				ip->i_dlm_dir_gen++;
			mxfs_probe_ratelimited("mxfs: P63-FASTEX-HANDOFF ino=%llu grant_gen=%u acted_gen=%u — peer held EX since our last grant; forcing disk-superset reload\n",
				(unsigned long long)ip->i_ino,
				hgg, ip->i_dlm_handoff_acted_gen);
		}
		/*
		 * instrumented UNDER-FIRE DETECTOR (pure instrument,
		 * ratelimited, NO behavior change): the live per-grant token
		 * (hgg) ADVANCED past what we cached at our last coherent grant
		 * (i_dlm_cached_grant_gen) — i.e. the inode lock CHANGED HANDS
		 * since — yet the master's handoff bit (ho) is FALSE, so the
		 * stale-base refresh below is NOT armed and this fast-path EX
		 * serve proceeds on a possibly-stale cached dir base.  This is
		 * the suspected serialization-visibility hole behind the
		 * dir_reuse count-preserving single-dirent loss (FINAL):
		 * a peer modified under its own EX tenure, our grant_gen moved,
		 * but handoff under-fired so we never reloaded.  hgg==0 (master
		 * self-grant / no token) excluded. */
		if (hgg != 0 && hgg != ip->i_dlm_cached_grant_gen && !ho)
			mxfs_probe_ratelimited(
			    "mxfs: P51-HANDOFF-UNDERFIRE ino=%llu hgg=%u cached_gg=%u acted=%u dir_gen=%llu loaded=%u — grant token advanced (lock changed hands) but handoff bit FALSE; fast-path EX serve on un-refreshed base\n",
				(unsigned long long)ip->i_ino, hgg,
				ip->i_dlm_cached_grant_gen,
				ip->i_dlm_handoff_acted_gen,
				(unsigned long long)ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen);
		/* RELIABLE-HANDOFF REFRESH: the grant token
		 * advanced since our last coherent grant = the inode lock
		 * changed hands (a peer, or us after a release, held EX
		 * since).  Either way our CLEAN cached dir blocks may be a
		 * base a peer superseded.  Arm the loss-safe EVICT-ONLY
		 * refresh (dir_ex_handoff stays as computed above — false
		 * unless a real cross-node handoff was also detected, so we
		 * never force a disk-adopt that reverts uncommitted work).
		 * Fires once per grant_gen change (cached_grant_gen updated
		 * just below), so within one tenure the fast path keeps
		 * serving (no dlm_fairness starvation, MHT preserved). */
		/* candidate-A counters: does the grant_gen
		 * handoff signal fire reliably at N=8? hgg0 = query
		 * returned 0 (no/stale token = unreliable). */
		if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX) {
			if (hgg == 0)
				atomic64_inc(&mxfs_dirEX_gg_hgg0);
			else if (hgg != ip->i_dlm_cached_grant_gen)
				atomic64_inc(&mxfs_dirEX_gg_armed);
		}
		/* arm on a real token change (hgg !=
		 * cached).  NOTE: candidate-A (also arm on hgg==0 &&
		 * !self_created) was REVERTED in — it fired the
		 * drain_evict on nearly every consumer/EX serve (test7
		 * gg_hgg0=87) and wedged a node hard (D-state 700s+ in
		 * mxfs_dir_drain_evict_data_blocks under ILOCK).  The
		 * DECISIVE N=8 measurement (fastret_stale=0) already
		 * ruled out missed-handoff as the root; the real root is
		 * the release-side durability gap (candidate-B). */
		/* Option B: the gen evidence is consumed by the
		 * restamp just below — capture the comparison first
		 * for the adopt-at-acquire gate further down. */
		bool b_gen_moved = (hgg != 0 &&
			hgg != ip->i_dlm_cached_grant_gen);

		if (mxfs_dir_gg_refresh &&
		    (hgg != 0 && hgg != ip->i_dlm_cached_grant_gen)) {
			dir_ex_stale_refresh = true;
			if (mxfs_dir_gen_per_handoff ||
			    ip->i_dlm_dir_gen <= ip->i_dlm_dir_loaded_gen)
				ip->i_dlm_dir_gen++;
		}
		if (hgg != 0)
			ip->i_dlm_cached_grant_gen = hgg;
		/*
		 * instrumented DECISIVE PROBE (always-on,
		 * storm-dir ino<=256, ratelimited, NO behavior change):
		 * we just SERVED a cached dir-EX (i_dlm_ex_holders++ above)
		 * and are about to RMW the dir.  Query whether we CURRENTLY
		 * hold the on-disk/master EX grant.  If held==0 here, a peer
		 * holds the grant RIGHT NOW while we modify under a stale
		 * cached EX = the divergent-RMW that durably drops a dirent
		 * (readdir=799).  CONFIRMS the grant-divergence root: the
		 * fast-path handoff machinery above only REFRESHES the data
		 * base, it never re-acquires the grant, so a moved/lost grant
		 * (lossy TCP BAST) lets both nodes RMW the same block.  ho =
		 * dg_shadow handoff bit (a peer held EX since our last grant);
		 * held=0 with mods-this-tenure is the smoking gun. */
		/* phantom-EX counters.  
		 * on CAW each of these was its OWN on-disk
		 * probe-chain read per serve (2 rawmode + 1 held +
		 * 1 p42-held = ~4 disk walks/serve).  Ride the
		 * dir_ex_verify_held throttle and do the raw read
		 * ONCE; p42 + the enforce below reuse it. */
		if (dir_ex_verify_held) {
			bool s6_sampled;

			/* bounded under the verify
			 * governor.  A skipped/abandoned probe
			 * leaves s6_raw_snap at the fail-open
			 * EX, so neither the phantom counters
			 * below nor the enforce further
			 * down can act on a non-sample; the
			 * throttle stamp set above is rolled
			 * back so the next serve retries. */
			MXFS_VERIFY_SITE_INC(mxfs_verify_site_s6_n);
			s6_raw_snap = mxfs_dlm_verify_rawmode(
				ip->i_mount->m_mxfs_dlm,
				ip->i_ino, &s6_sampled);
			if (!s6_sampled)
				ip->i_dlm_heldchk_j = jiffies -
					msecs_to_jiffies(1000);
			atomic64_inc(&mxfs_dirEX_serve_total);
			if (s6_raw_snap < MXFS_LOCK_EX) {
				atomic64_inc(&mxfs_dirEX_phantom_total);
				if (ip->i_dlm_pin_count > 0)
					atomic64_inc(&mxfs_dirEX_phantom_pinned);
				if (ip->i_mxfs_self_created)
					atomic64_inc(&mxfs_dirEX_phantom_selfcr);
				if (ip->i_dlm_unpublished)
					atomic64_inc(&mxfs_dirEX_phantom_unpub);
			}
		}
		if (ip->i_ino <= 256 && dir_ex_verify_held) {
			int p42_held = (s6_raw_snap > MXFS_LOCK_NL)
					? 1 : 0;
			if (p42_held == 0)
				mxfs_probe_ratelimited("mxfs: P42-STALEEX-SERVE ino=%llu held=0 ho=%d hgg=%u cached_gg=%u ex_holders=%d dir_gen=%llu state=%u comm=%s — SERVED cached EX but grant NOT held (divergent-RMW window)\n",
					(unsigned long long)ip->i_ino,
					ho ? 1 : 0, hgg,
					ip->i_dlm_cached_grant_gen,
					ip->i_dlm_ex_holders,
					(unsigned long long)ip->i_dlm_dir_gen,
					ip->i_dlm_state, current->comm);
		}
		/*
		 * (epoch, LEVEL-triggered, on the
		 * FAST path): the handoff BIT above is edge-triggered
		 * (consumed once via acted_gen) and under-fires ~80% on
		 * TCP, leaving a stale cached-EX dir base that addname
		 * RMWs -> the dir_reuse single-dirent free-slot double-
		 * allocation (the residual 399/400).  The monotonic
		 * per-resource dir_epoch is LEVEL-triggered: if it
		 * EXCEEDS the epoch our base is known coherent with, a
		 * peer modified this dir since we last adopted — force
		 * the SAME data-block stale refresh (bump i_dlm_dir_gen
		 * so the dir-DATA read hook re-reads).  This is a DATA-
		 * block re-read, NOT the in-place fork adopt (which is
		 * gated post_release only because an in-place rollback
		 * corrupts).  Within one tenure the epoch is unchanged ->
		 * fast path keeps serving (no dlm_fairness starvation,
		 * MHT preserved).  Gated on mxfs_dir_epoch_adopt (the
		 * converged config).  Unlike raw grant_gen (over-
		 * fired, resurrected deletes) the epoch advances ONLY on a
		 * real cross-node handoff, so it cannot over-fire. */
		if (mxfs_dir_epoch_adopt) {
			uint32_t fe = mxfs_v5_dlm_inode_dir_epoch(
				ip->i_mount->m_mxfs_dlm, ip->i_ino);
			if (fe > ip->i_dlm_dir_valid_epoch) {
				uint32_t oldve =
					ip->i_dlm_dir_valid_epoch;
				dir_ex_stale_refresh = true;
				dir_ex_handoff = true;	/* reliable epoch handoff */
				if (mxfs_dir_gen_per_handoff ||
				    ip->i_dlm_dir_gen <=
				    ip->i_dlm_dir_loaded_gen)
					ip->i_dlm_dir_gen++;
				ip->i_dlm_dir_valid_epoch = fe;
				ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;	/* the baseline belongs to THIS incarnation */
				mxfs_probe_ratelimited("mxfs: P-FASTEX-EPOCH ino=%llu epoch=%u valid=%u — peer modified dir since (level-triggered); forcing data-block refresh\n",
					(unsigned long long)ip->i_ino,
					fe, oldve);
			}
		}
		/*
		 *  — OPTION B ADOPT-AT-EX-ACQUIRE
		 * gate (design review gpt_ruling_sess44; see the contract block at
		 * mxfs_dir_adopt_at_acquire).  This is the authorization
		 * boundary for a cached-EX dir serve: decide need_adopt
		 * from the EXPLICIT validity bit plus != compares, and
		 * arm the same reload pipeline the proven armers above
		 * use.  Cost discipline: when the bit is set and the
		 * grant token is live and unchanged, the lock never
		 * changed hands, so the epoch cannot have moved — no
		 * extra DLM query at all.  The epoch query is paid only
		 * on the no-token (hgg==0) leg.
		 *
		 * Unpublished inodes are excluded: the creator's in-core
		 * image is the authority and the DLM has no grant record
		 * for the number (mxfs_dir_epoch_superseded branch 1);
		 * their baseline is stamped at publish (creator sites).
		 *
		 * A tenure that already mutated (dirty_here) is NEVER
		 * adopted over (contract item 3, fail-closed): count it,
		 * leave the bit unset, and let the write-side backstops
		 * reconcile — the recalibration proved that path
		 * loss-free.  Reached only if this tenure's first-op
		 * authorization was missed (bypass serve paths), since
		 * within one thread this gate runs before the op mutates.
		 */
		if (mxfs_dir_adopt_at_acquire &&
		    !ip->i_dlm_unpublished) {
			int breason = 0;
			uint32_t bfe = 0;

			/*
			 * Gen movement is COUNTED but does not arm
			 * the superset adopt on its own: grant_gen
			 * bumps on benign same-node re-grants
			 * (PROVEN: refreshing on every gen
			 * change resurrected deletes 2/24 -> 16/24),
			 * and the contract's own release-time
			 * invalidation clause makes the gen leg
			 * redundant — any handoff that matters
			 * passed through our release, which cleared
			 * the validity bit.  gg_refresh above still
			 * owns the loss-safe evict-only refresh for
			 * gen changes.
			 */
			if (b_gen_moved)
				atomic64_inc(&mxfs_b_adopt_gen);
			if (!smp_load_acquire(&ip->i_dlm_base_valid))
				breason = 1;
			else if (hgg == 0) {
				bfe = mxfs_v5_dlm_inode_dir_epoch(
					ip->i_mount->m_mxfs_dlm,
					ip->i_ino);
				if (ip->i_dlm_dir_valid_epoch != bfe)
					breason = 2;
			}
			if (breason && !dir_ex_stale_refresh) {
				bool bdirty =
				    ip->i_mxfs_dirty_seq != 0 &&
				    ip->i_mxfs_dirty_seq ==
				    ip->i_mxfs_ex_grant_seq;

				if (bdirty) {
					atomic64_inc(&mxfs_b_dirty_skip);
					pr_warn_ratelimited(
					    "mxfs: P216-B-DIRTY-SKIP ino=%llu reason=%d valid=%d hgg=%u cached_gg=%u fe=%u valid_epoch=%u comm=%s — need_adopt on a tenure that already mutated; refusing adopt (fail-closed), backstops own recovery\n",
						(unsigned long long)ip->i_ino,
						breason,
						ip->i_dlm_base_valid,
						hgg,
						ip->i_dlm_cached_grant_gen,
						bfe,
						ip->i_dlm_dir_valid_epoch,
						current->comm);
				} else {
					if (breason == 1)
						atomic64_inc(&mxfs_b_adopt_sentinel);
					else
						atomic64_inc(&mxfs_b_adopt_epoch);
					dir_ex_stale_refresh = true;
					dir_ex_handoff = true;
					if (mxfs_dir_gen_per_handoff ||
					    ip->i_dlm_dir_gen <=
					    ip->i_dlm_dir_loaded_gen)
						ip->i_dlm_dir_gen++;
					mxfs_probe_ratelimited(
					    "mxfs: P216-B-ADOPT-ARM ino=%llu reason=%d hgg=%u fe=%u valid_epoch=%u fmt=%d comm=%s — dir-EX authorization gate: adopting before exposure\n",
						(unsigned long long)ip->i_ino,
						breason, hgg, bfe,
						ip->i_dlm_dir_valid_epoch,
						ip->i_df.if_format,
						current->comm);
				}
			}
		}
	}

	*dir_ex_stale_refresh_io = dir_ex_stale_refresh;
	*dir_ex_handoff_io = dir_ex_handoff;
	*s6_raw_snap_io = s6_raw_snap;
}

/* P-DIRFASTEX: block/leaf-format dir EX fast-path
 * re-grant — the non-shortform sibling of P-SFDIR-FASTEX
 * above.  This cached-EX grant does NO reload + NO gen-bump
 * + NO evict, so the imminent RMW uses whatever dir blocks
 * are already cached in-core.  If i_dlm_dir_gen advanced past
 * i_dlm_dir_loaded_gen a peer modified this dir while we held
 * the cached grant => STALE base => the block/leaf-format
 * lost-update the write-side P-DIRWR trace catches.  Correlate
 * across nodes by ino + realns.  Ratelimited; EX writers only. */
static void mxfs_ilock_block_leaf_dir_fast_ex(struct xfs_inode *ip, uint8_t mode,
					      bool *dir_ex_stale_refresh_ref)
{
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL) {
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    mode == MXFS_LOCK_EX)
		mxfs_probe_ratelimited(
			"mxfs: P-DIRFASTEX ino=%llu fmt=%d dir_gen=%u loaded_gen=%u stale_base=%d pin=%d state=%u realns=%llu\n",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			ip->i_dlm_dir_gen,
			ip->i_dlm_dir_loaded_gen,
			(ip->i_dlm_dir_gen >
			 ip->i_dlm_dir_loaded_gen) ? 1 : 0,
			ip->i_dlm_pin_count,
			ip->i_dlm_state,
			(unsigned long long)ktime_get_real_ns());
		/*
		 * FIX (instrumented, proven root): a block/leaf-
		 * format dir EX fast-path re-grant with stale_base
		 * (i_dlm_dir_gen advanced past the gen our blocks
		 * were loaded at — a peer modified this dir while we
		 * did not hold EX) RMWs/reads a STALE cached dir
		 * block with NO refresh.  PROVEN producer: the stale
		 * reader (node1) logged 10x stale_base=1 here and
		 * was the only node still seeing a peer's durably-
		 * deleted dirent (unlink_visibility survivor).  The
		 * SLOW path already refreshes via
		 * mxfs_dir_drain_evict_data_blocks (clear-DONE evict
		 * of CLEAN blocks -> next read cold-fetches the
		 * peer's committed image; drains a transiently-pinned
		 * stale block, skips genuinely-dirty local work).
		 * That evict is the PROVEN, non-regressing baseline
		 * (regression was converting it to
		 * xfs_buf_stale, NOT the evict).  Under fua_disable=1
		 *  plain reads are cheap, so FUA
		 * timing wall no longer applies.  Run the SAME evict
		 * here, but only when genuinely stale (gen-gated, so
		 * it fires rarely — ~10x/run, not every dir-EX op).
		 */
		/* v0.5.4 (ftrace-proven): on a SELF-CREATED
		 * never-BASTed dir, gen > loaded_gen is purely the
		 * 0->1 arming artifact of our OWN first read
		 * (xfs_da_read_buf), not a peer modify — a peer mod
		 * requires taking this dir's lock, which BASTs us
		 * and clears i_mxfs_self_created.  Without this gate
		 * the refresh refires on EVERY parent-dir EX acquire
		 * while we populate the dir (own dirty blocks keep
		 * left>0, so loaded_gen never catches up): 31305
		 * drain_evict calls + ~2.3k FUA cold re-reads per
		 * node in a 2-node parallel rsync, evicting clean
		 * blocks of dirs no peer ever touched. */
		if ((ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen &&
		     !ip->i_mxfs_self_created) ||
		    (ip->i_flags & MXFS_IF_DIR_RELOAD))
			(*dir_ex_stale_refresh_ref) = true;
	}
}

/* ALWAYS-ON (ratelimited): a dir EX fast-path
 * re-grant RMWs the CACHED shortform image with NO
 * reload.  Dump the cached dirent names used as the RMW
 * base so a cross-node timeline (vs P-SFDIR-RELOAD) shows
 * a node clobbering a peer's just-committed entry from a
 * stale cached fork.  EX writers on LOCAL dirs only. */
static void mxfs_ilock_report_cached_dir_ex_rmw(struct xfs_inode *ip,
						uint8_t mode)
{
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    mode == MXFS_LOCK_EX &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    ip->i_df.if_data) {
		struct xfs_dir2_sf_hdr *sfh = ip->i_df.if_data;
		struct xfs_dir2_sf_entry *e =
			xfs_dir2_sf_firstentry(sfh);
		char names[200];
		int  pos = 0, k;

		names[0] = '\0';
		for (k = 0; k < sfh->count &&
		     pos < (int)sizeof(names) - 12; k++) {
			int nl = min_t(int, e->namelen, 10);
			pos += scnprintf(names + pos,
				sizeof(names) - pos,
				"%.*s ", nl, e->name);
			e = (void *)e +
			    xfs_dir2_sf_entsize(ip->i_mount,
					sfh, e->namelen);
		}
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited(
				"mxfs: P-SFDIR-FASTEX ino=%llu count=%u names=[%s] state=%u pin=%d size=%lld realns=%llu\n",
				(unsigned long long)ip->i_ino,
				sfh->count, names, ip->i_dlm_state,
				ip->i_dlm_pin_count,
				(long long)ip->i_disk_size,
				(unsigned long long)ktime_get_real_ns());
		/* DETECTION (instrumented prove-first): this
		 * cached-EX fast-path is about to RMW the
		 * shortform fork.  If i_dlm_dir_gen advanced past
		 * the gen the fork was loaded at, a PEER modified
		 * this dir while we held the cached grant — the
		 * fork is STALE and this RMW will clobber the
		 * peer's dirents (unlink_visibility lost-update).
		 * No behavior change yet; just confirm it fires. */
		if (ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen)
			mxfs_probe_ratelimited(
				"mxfs: P-SFDIR-STALE-RMW ino=%llu dir_gen=%u loaded_gen=%u count=%u pin=%d — STALE shortform fork RMW (peer modified; would clobber)\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen,
				sfh->count,
				ip->i_dlm_pin_count);
	}
}

/*
 * 2026-07-14: the PR==PR branch below never consulted i_dlm_stale,
 * so a repeat PR (read-only) request always fast-pathed through
 * unconditionally regardless of the flag — staleness was only ever
 * consumed on the EX (write) side further down, even though
 * i_dlm_stale is set by ~20 legitimate signals across this file
 * (P106/P108 phantom-grant verify, TCPEX mirror mismatch, the
 * epoch_convert_gate, etc.) that apply equally to PR holders. A
 * cached-PR reader that any of those mechanisms had already flagged
 * stale would keep being served straight from cache anyway. This is
 * a real gap independent of any specific bug: add !i_dlm_stale to
 * the PR arm only (EX already has its own downstream stale handling
 * and is untouched). Confirmed not a one-way trap: mxfs_dlm_reload_
 * inode() clears i_dlm_stale at every one of its exit points once a
 * fresh reload has run, so a flagged inode falls to the slow path
 * exactly once per staleness event, not forever.
 */
static int mxfs_ilock_fast_path(struct xfs_inode *ip, uint8_t mode,
				struct mxfs_v5_dlm *dlm, int *phantom_laps_io)
{
	int mxfs_ilock_fast_path_outcome = MXFS_BLOCK_NEXT;
	int phantom_laps = *phantom_laps_io;

	if (ip->i_dlm_mode == MXFS_LOCK_EX ||
	    (ip->i_dlm_mode == MXFS_LOCK_PR && mode == MXFS_LOCK_PR &&
	     !ip->i_dlm_stale)) {
		/*
		 * Dir-strict: for directories, also require state==CACHED.
		 * If state is BAST or DEMOTING, a peer is requesting the
		 * lock and another thread on this node is mid-bast (or
		 * about to start).  Allowing a fast-path acquire here lets
		 * a concurrent dir mutation commit AFTER bast_process's
		 * log_force+ail_push and BEFORE its on-disk DLM unlock —
		 * peer reads stale dir → xfs_dir_removename ENOENT.  No
		 * additional flush rounds can close this window; the only
		 * fix is to gate fast-path on state.  v0.3.13.
		 *
		 * Files keep the looser mode-only check: v0.3.5's cross-
		 * thread writeback recursion fix relies on bast_process's
		 * filemap_write_and_wait dispatching xfs-conv kworkers
		 * that re-enter ilock_begin on the same inode.  Those
		 * kworkers must fast-path through (mode is still EX on
		 * disk) — gating files on state==CACHED would deadlock the
		 * kworker on DEMOTING wait while bast_process waits for
		 * its writeback to drain.  Directories don't have the page-
		 * cache writeback path, so no kworker re-entry.
		 *
		 * Same-thread (the demoter task itself) is still served
		 * by the i_dlm_demoter belt-and-suspenders below.
		 */
		/*
		 * hard tenure cap — a BASTed dir grant that
		 * has been held past mxfs_dir_ex_tenure_cap_ms stops admitting
		 * new fast-path ops.  Flip the state to BAST (semantically
		 * true: a peer BAST IS pending) so this op and all subsequent
		 * ones take the normal BAST wait; the release then fires via
		 * the existing ilock_end 1→0 refire (holders draining) or the
		 * P-DEMWAIT-REDRIVE arm (already idle).  Without this the MHT
		 * batch window re-arms forever under continuous local churn
		 * and the peer starves to -110 (b56r1 double shutdown).
		 */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_pin_count == 0 &&
		    ip->i_dlm_bast_pending &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		    mxfs_dir_ex_tenure_cap_ms > 0 &&
		    ip->i_dlm_ex_acquire_ns &&
		    ktime_get_ns() - ip->i_dlm_ex_acquire_ns >
			(u64)mxfs_dir_ex_tenure_cap_ms * NSEC_PER_MSEC) {
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			mxfs_probe_ratelimited(
			    "mxfs: P-EX-TENURE-CAP ino=%llu mode=%u ex=%u pr=%u tenure_ms=%llu — BASTed dir grant past cap; closing fast path for handoff\n",
				(unsigned long long)ip->i_ino, ip->i_dlm_mode,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				(unsigned long long)((ktime_get_ns() -
					ip->i_dlm_ex_acquire_ns) /
					NSEC_PER_MSEC));
		}
		/* (ruling item 1): DEFER-TIME ADMISSION
		 * CONTAINMENT — while a release-defer episode is open on
		 * this inode, the fast path must not serve NEW EX
		 * admissions (any file class): local churn would reopen
		 * obligations forever and turn the 300s cumulative bound
		 * into a false wedge.  Fall through to the demote-wait,
		 * which parks on the episode until it closes or wedges.
		 * pin_count>0 keeps the fast path (an op mid-flight; the
		 * BUSY dwork re-arm owns that window, and parking a pinned
		 * chain risks ABBA on held AG bufs). */
		if (mxfs_file_yield_gate(ip, mode) ||
		    (mxfs_release_proof_enforce && mode == MXFS_LOCK_EX &&
		     ip->i_dlm_pin_count == 0 &&
		     READ_ONCE(ip->i_mxfs_reldefer_started_j) != 0) ||
		    /*
		     * An UNPUBLISHED non-directory about to MODIFY, which already
		     * owns (or is one extent from owning) metadata blocks outside
		     * its core.  Its local-only EX cannot name a durable epoch, so
		     * every image of those blocks would ship AUTH_NOT_HELD and be
		     * refused by a peer's replay, quarantining the AGs of the whole
		     * transaction.  Fall through to the real acquire, which claims
		     * the slot and promotes UNPUBLISHED_EX -> DURABLE_EX before the
		     * first such image can be captured.  See
		     * mxfs_inode_owns_logged_metadata.  pin_count==0 for the same
		     * reason as the arms around it: no AG buffer is held, so the
		     * acquire cannot ABBA against a peer's AG release.
		     */
		    (mxfs_unpub_publish_owned_meta &&
		     !S_ISDIR(VFS_I(ip)->i_mode) &&
		     mode == MXFS_LOCK_EX &&
		     ip->i_dlm_pin_count == 0 &&
		     ip->i_dlm_unpublished &&
		     mxfs_inode_owns_logged_metadata(ip) &&
		     mxfs_unpub_owned_meta_note(ip)) ||
		    (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_pin_count == 0 &&
		    (ip->i_dlm_state != MXFS_DLM_ISTATE_CACHED ||
		     /* v0.5.4 the synchronous unpublished-EX backstop
		      * is required only when a peer could already NAME this
		      * ino — a reused in-core incarnation (stale peer dcache/
		      * icache can resolve the number; i_mxfs_reused_create) or
		      * observed peer interest (any BAST clears
		      * i_mxfs_self_created).  A FRESH cache-miss create is
		      * unreachable by peers before the pre-commit async
		      * publish worker claims its slot (~1 ms): dirent paths
		      * transit a lock we hold (the BAST publishes the unpub
		      * list before release) and a lookup-iget of the not-yet-
		      * flushed dinode reads FREE and bails ENOENT with no
		      * slot acquire.  Without this gate every fresh dir paid
		      * a ~1.5 ms in-syscall CAW claim+reload at its first
		      * pin-free EX op (rsync's per-dir chmod/utimensat, ~+1
		      * s/node on a 2-node parallel rsync; dmesg-proven the
		      * first EX op arrives ~30 µs after mkdir, so no async
		      * worker can win that race). */
		     (ip->i_dlm_unpublished && mode == MXFS_LOCK_EX
		      /* sess-tcp ROOT FIX: divert EVERY unpublished dir EX-modify,
		       * not just reused/peer-observed ones.  An unpublished inode is
		       * INVISIBLE to the DLM, so a peer that NAMEs it (via a shared
		       * parent dirent) acquires the lock CLEANLY and never BASTs us
		       * -> i_mxfs_self_created is NEVER cleared, the old
		       * (reused||!self_created) gate never fires, and BOTH nodes hold
		       * EX (PROVEN: P106-STALE-EX 45x on TCP, on_disk_held=0
		       * cached_mode=EX unpub=1).  A real DLM EX acquire (publish)
		       * before the RMW restores mutual exclusion. */ ) ||
		     /* master-authoritative revalidate of a PUBLISHED,
		      * peer-reachable (!self_created) dir EX-modify — the TCP phantom
		      * cached-EX fix (see mxfs_dir_ex_revalidate decl).  Gated. */
		     (mxfs_dir_ex_revalidate && mode == MXFS_LOCK_EX &&
		      !ip->i_mxfs_self_created && !ip->i_dlm_unpublished) ||
		     /*
		      *  — DO NOT SERVE A CACHED EX WHILE
		      * THIS INODE'S GRANT IS BEING DRAINED AWAY.
		      *
		      * PROVEN (sfstorm_20260729_005540 r39 ino=56623307, and
		      * the identical r32 ino=44040321 capture): the state stays
		      * CACHED while i_dlm_demoter is set, so none of the gates
		      * above fire, and the fast path serves EX to a mkdir
		      * *while the release drain is handing the grant to a peer*:
		      *
		      *   P15-REL-ABORT gen_moved=1 entry_gen=7043 now_gen=7044
		      *   P51-HANDOFF-UNDERFIRE hgg=2 cached_gg=0 — lock changed
		      *       hands, handoff bit FALSE; fast-path EX serve on an
		      *       un-refreshed base
		      *   P195-STALE-BASE-ALREADY-DIRTY grant_epoch=2 valid_epoch=0
		      *
		      * That serve is what makes the tenure ALREADY DIRTY on an
		      * epoch-stale base by the time any freshness gate can look
		      * (measured: dirty_here=1 in 100% of genuine forward-stale
		      * hits), which is precisely why a gate at xfs_dir_lookup
		      * was measured to never engage.  The design review requires
		      * "assert no current-tenure mutation exists" BEFORE the
		      * adopt — the only place that assertion can still hold is
		      * here, at the grant, before the operation is exposed to
		      * the base.
		      *
		      * Falling through costs the demote-wait the comment below
		      * already describes (measured drain ~22 ms) and then takes
		      * a real acquire, which reloads and adopts.  Bounded by the
		      * existing demote-wait; pin_count==0 above guarantees no
		      * AGF is held, so this cannot ABBA-deadlock.
		      */
		     (mxfs_dir_ex_divert_on_demote && mode == MXFS_LOCK_EX &&
		      mxfs_foreign_demoter(ip))))) {
			/* 0.75.39: count and (ratelimited) name every file
			 * fall-through the yield gate produced — the harness's
			 * proof that the hand-off happened here and not by luck. */
			if (!S_ISDIR(VFS_I(ip)->i_mode)) {
				WRITE_ONCE(mxfs_file_yield_n, mxfs_file_yield_n + 1);
				mxfs_probe_ratelimited("mxfs: P-FILE-YIELD ino=%llu req=%u mode=%u state=%u ex=%u pr=%u comm=%s — cached grant yields to a peer's pending request\n",
					(unsigned long long)ip->i_ino, mode,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
					current->comm);
			}
			/* P24-DIRSLOW (instrumented): name the
			 * GATE REASON for every dir fall-through while the entry
			 * state is still unmodified (P23 below logs after this
			 * thread has already set ACQUIRING).  Capped. */
			if (S_ISDIR(VFS_I(ip)->i_mode)) {
				static atomic_t p24_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p24_n) <= 2000)
					if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
						mxfs_probe("mxfs: P24-DIRSLOW ino=%llu req=%u mode=%u state=%u unpub=%d selfc=%d comm=%s\n",
							(unsigned long long)ip->i_ino,
							mode, ip->i_dlm_mode,
							ip->i_dlm_state,
							ip->i_dlm_unpublished ? 1 : 0,
							ip->i_mxfs_self_created ? 1 : 0,
							current->comm);
			}
			/*
			 * Fall through to demoter check + demote-wait.
			 *
			 * (PROVEN BY INSTRUMENT root, design-consult design review design):
			 * also fall through for an UNPUBLISHED dir about to be
			 * MODIFIED (mode==EX).  A locally-granted unpublished inode
			 * (mxfs_dlm_grant_local_new) holds i_dlm_mode==EX in memory
			 * but has NO on-disk CAW slot.  Deferred-publish only
			 * publishes on an incoming BAST — but a peer reaching this
			 * inode (e.g. via a cached parent dirent) acquires the empty
			 * on-disk slot CLEANLY and never BASTs us, so publish never
			 * fires.  Both nodes then believe they hold EX → concurrent
			 * RMW of the same dir block → durable lost-update + inobt/
			 * defer corruption (P106-STALE-EX proved on_disk_held=0 while
			 * cached_mode=EX).  Forcing the slow path here does a real
			 * on-disk EX acquire (blocking until any peer releases) +
			 * fresh reload/evict before the RMW, restoring mutual
			 * exclusion.  pin_count==0 guarantees no AGF is held, so the
			 * blocking CAW acquire cannot ABBA-deadlock (design review proof).
			 */
		} else {
			/*
			 * refresh a stale cached dir base on the EX
			 * fast-path (see the P-DIRFASTEX site below).  Set under
			 * the spinlock; the actual drain/evict runs after
			 * spin_unlock (sleepable ctx), mirroring the slow path.
			 */
			bool dir_ex_stale_refresh = false;
			/* set ONLY by a RELIABLE cross-node handoff
			 * signal (grant_gen change / dir_epoch advance) — NOT by the
			 * lossy/self-echo gen/RELOAD-flag setter.  A genuine handoff
			 * means a DIFFERENT node held EX since our last grant, so our
			 * own prior work was already drained at our release; the
			 * fast-path reload may then force a disk-SUPERSET adopt
			 * (post_release=true) without resurrecting our own work.  This
			 * stops a converter freezing a STALE shortform base over a
			 * peer's committed first-dirent (the round-1 node2_f1 durable
			 * loss / sf<->block flip-flop). */
			bool dir_ex_handoff = false;
			/*
			 * instrumented STEP 1 (PROVE): when this dir-EX fast-path
			 * cache-hit trusts an in-memory i_dlm_mode==EX, verify (after
			 * spin_unlock — disk I/O sleeps) that the on-disk CAW slot is
			 * still held by us.  proved node1 RMW'd ino 131 INSIDE
			 * node3's EX-held window via this fast-path: its in-memory EX
			 * was STALE (on-disk holders_ex bit already clear) — a
			 * mutual-exclusion violation that durably clobbers the peer.
			 * Probe-only this build (no behavior change): confirm
			 * mxfs_v5_dlm_inode_held()==0 fires on the losing create.
			 */
			bool dir_ex_verify_held = false;
			/*  one shared raw-mode snapshot
			 * per verified serve — counters, p42 and the
			 * enforce all read the same slot; -1 = not
			 * sampled this serve. */
			int s6_raw_snap = -1;
			/*
			 * SHORTFORM dir EX fast-path coherency check.
			 * Set under the spinlock; the coherent disk-compare +
			 * conditional reload runs after spin_unlock (sleeps).
			 */
			bool sf_disk_check = false;
			/*
			 * when a D9 pin is held, the DLM token is
			 * definitively still held at its cached mode (an incoming
			 * BAST was DEFERRED by mxfs_dlm_bast_notify, not processed)
			 * and the cached dir content is still valid (no demote
			 * happened).  So even though state==BAST, fast-path the
			 * re-acquire (holder++) instead of taking the slow path,
			 * which would issue a CAW re-acquire of a slot we already
			 * own EX -> CAW compare mismatch -> dlm_caw I/O error ->
			 * force shutdown.  This is what made the pin/check approach
			 * shut down the FS under contention.
			 */
			/* write-acquire gen-bump candidate REVERTED — it TIMED
			 * OUT rename_visibility (>180s): bumping gen on every cached
			 * dir-EX re-acquire → every rename FUA-refreshes all dir blocks →
			 * too slow under 4-node contention.  ALL three refresh approaches
			 * (read-side gen-0, bast-release, write-acquire) hit the same
			 * timing wall: cross-node dir coherency via FUA re-reads is
			 * fundamentally too slow at scale.  The fix needs a NON-FUA
			 * coherency mechanism (or much-faster FUA). */
			if (mode == MXFS_LOCK_EX) {
				ip->i_dlm_ex_holders++; MXFS_DLMTR_H(ip);
				mxfs_exh_stamp_locked(ip);
			} else {
				ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
			}
			/*
			 * ROBUST FIX (both PR reads and EX writes): a
			 * SHARED (peer-reachable) shortform dir taking the cached
			 * fast-path may serve a STALE in-core fork — for a READ
			 * (PR) this is the transient stale-readdir (rank1's `ls`
			 * sees an entry a peer already removed; self-heals later);
			 * for a WRITE (EX) it is the stale-base RMW.  Defer a
			 * coherent disk-compare to after spin_unlock.  Self-created
			 * dirs are peer-unreachable → skip (no solo-path cost). */
			if (S_ISDIR(VFS_I(ip)->i_mode) &&
			    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
			    ip->i_df.if_data &&
			    !ip->i_mxfs_self_created)
				sf_disk_check = true;
			/*
			 * Hypothesis-1 instrumentation: log fast-path
			 * acquires for dir inodes.  If T2 takes fast-path on
			 * inode 128 BEFORE doing reload (which only fires on
			 * slow-path), T2 uses cached XBF_DONE buf with stale
			 * content.  Each P63 event is a "no FUA-read happened
			 * here" event for to correlate with Mode A.
			 */
			if (S_ISDIR(VFS_I(ip)->i_mode))
				mxfs_idbg("mxfs: P63-INSTR ino=%llu FAST-PATH-DIR "
					"req_mode=%u cached_mode=%u state=%u "
					"realns=%llu\n",
					(unsigned long long)ip->i_ino,
					mode, ip->i_dlm_mode, ip->i_dlm_state,
					(unsigned long long)ktime_get_real_ns());
			/* diag: a dir EX-acquire that fast-paths uses
			 * the CACHED shortform image with NO reload — if a peer
			 * modified this dir while we held it cached, this is the
			 * lost-update write path.  GATED behind mxfs.instr:
			 * it was always-on and fired an UNRATELIMITED printk on
			 * EVERY dir-EX op, costing real wall under metadata-heavy
			 * load (rsync) — a perf drag, not a correctness aid. */
			if (mxfs_instr_enabled &&
			    S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX)
				mxfs_pal_log(MXFS_LOG_DEBUG,
					"mxfs: P-DIR-SEQ FASTEX ino=%llu cached_mode=%u state=%u pin=%d gen=%llu realns=%llu",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_pin_count,
					(unsigned long long)ip->i_dlm_dir_gen,
					(unsigned long long)ktime_get_real_ns());
			mxfs_ilock_report_cached_dir_ex_rmw(ip, mode);
			mxfs_ilock_block_leaf_dir_fast_ex(ip, mode,
							  &dir_ex_stale_refresh);
			/* STEP 1: every dir-EX fast-path cache-hit gets an
			 * on-disk ownership verify after unlock (probe-only). */
			/* v0.5.2: throttled to one slot read per 100ms per inode
			 * (same rationale as the P108 ilock_begin verify — a
			 * per-op synchronous 512B slot read dominated the
			 * create-heavy profile; the stale-EX condition it
			 * detects persists until acted on, so a 100ms-late
			 * detection is equivalent). */
			if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX) {
				/* sess-tcp: self_created + 1000ms-throttle gates DROPPED.
				 * They existed only because the CAW held-check did a 512B
				 * on-disk slot read; on TCP the check was a no-op (returned
				 * 1) so a sub-second mid-create-burst phantom-EX was NEVER
				 * seen.  The TCP held-check is now a cheap local-mirror
				 * lookup -> verify EVERY dir-EX fast-path.
				 *
				 *  (instrumented kprobe-counted): on CAW
				 * that per-serve check is still a synchronous on-disk
				 * probe-chain read — 4.8 FUA reads/create, the single
				 * largest term in the create profile.  Re-throttle on CAW
				 * ONLY (100ms/inode, shared stamp with the P108 gate):
				 * the phantom-EX condition persists until acted on, so
				 * sampled detection is equivalent (same TOCTOU class as
				 * P108's 1000ms argument above).  TCP keeps every-serve. */
				/* jittered throttle (verify governor). */
				if (!mxfs_v5_dlm_transport_caw(dlm) ||
				    mxfs_verify_throttle_elapsed(
					    ip->i_dlm_heldchk_j, 100)) {
					dir_ex_verify_held = true;
					ip->i_dlm_heldchk_j = jiffies;
				}
			}
			/* P-TDS (instrumented instrument-first): probe the
			 * SMOKING GUN only — a dir-EX-modify fast-path serve about
			 * to RMW a STALE base (dir_gen>loaded_gen).  The stale-base
			 * test is a free in-memory compare, so the common (correct)
			 * path pays nothing and is not slowed; only the rare
			 * suspicious op does the on-disk-slot read + log after
			 * unlock.  Gated behind the dirwr runtime flag. */
			if (mxfs_dirwr_enabled &&
			    S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX &&
			    ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen)
				dir_ex_verify_held = true;
			spin_unlock(&ip->i_dlm_lock);
			mxfs_ilock_tenure_change_check(ip, mode,
						       &dir_ex_stale_refresh,
						       &dir_ex_handoff,
						       dir_ex_verify_held,
						       &s6_raw_snap);
			/*
			 * coherent-disk compare + conditional reload for a
			 * SHARED shortform dir on the cached-EX fast path (sleeps;
			 * runs after spin_unlock, holders already incremented).
			 *
			 * FIX (default): on a continuous-hold fast path the
			 * in-core fork is AUTHORITATIVE (no peer could have modified
			 * while we held the grant cached — a peer modify BASTs us off
			 * CACHED).  Adopting the lagging on-disk image here re-adds
			 * our own async-destaged-then-removed dirents = the durable
			 * resurrection (P-SFM-READD state=CACHED peer_mod=0).  Skip
			 * the adopt; peer changes are picked up by the slow-path
			 * reacquire reload (which the BAST forces).  Gate restores the
			 * old behaviour when mxfs_sf_fastpath_adopt=1.
			 */
			/*
			 *  (D3 acquire-side ROOT, design review
			 * Design-consult design "rebuild the fork from the authoritative
			 * image before the first mutation of a tenure"):
			 * the premise — "on a continuous-hold fast path
			 * no peer could have modified the dir" — is FALSIFIABLE
			 * and was measured false.  i_dlm_dir_gen is bumped when
			 * we LEARN of a peer modification; i_dlm_dir_loaded_gen
			 * records the generation our fork was last rebuilt to.
			 * dir_gen > loaded_gen therefore PROVES peer changes
			 * exist that our in-core fork has never seen, and the
			 * captured loss shows exactly that state reaching the
			 * platter: P56-DIRWRITE ... mode=0 relflush=1 dgen=8
			 * lgen=5 published a 9-name image over a platter that
			 * had more, permanently erasing peers' files (the
			 * cache_coherency cv losses, 3-5 files per hit).
			 * In that proven-stale case the adopt is MANDATORY —
			 * the resurrection concern does not apply
			 * because it was argued from peer_mod=0 (dir_gen ==
			 * loaded_gen), which we explicitly exclude here.
			 */
			if (sf_disk_check &&
			    (mxfs_sf_fastpath_adopt ||
			     (mxfs_dir_stalegen_adopt &&
			      ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen))) {
				if (!mxfs_sf_fastpath_adopt)
					mxfs_probe_ratelimited(
					    "mxfs: P174-STALEGEN-ADOPT ino=%llu dir_gen=%u loaded_gen=%u — fast-path fork never rebuilt across peer modifications; forcing disk adopt before mutation\n",
						(unsigned long long)ip->i_ino,
						ip->i_dlm_dir_gen,
						ip->i_dlm_dir_loaded_gen);
				mxfs_dir_sf_refresh_if_disk_differs(ip);
			}
			mxfs_ilock_refresh_stale_dir_ex(dir_ex_stale_refresh, ip,
							dir_ex_handoff);
			{
				int outcome;

				outcome = mxfs_ilock_verify_dir_ex_ownership(dir_ex_verify_held,
									     s6_raw_snap,
									     dlm,
									     ip,
									     &phantom_laps,
									     mode,
									     &mxfs_ilock_fast_path_outcome);
				if (outcome == MXFS_BLOCK_GOTO + 0)
					goto mxfs_ilock_fast_path_exit;
			}
			/* dir-EX fast-path serve about to return —
			 * count it and whether the base is STALE (gen>loaded) for
			 * the imminent RMW.  No printk. */
			if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX) {
				atomic64_inc(&mxfs_dirEX_fastret_total);
				if (ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen)
					atomic64_inc(&mxfs_dirEX_fastret_stale);
			}
			atomic64_inc(&mxfs_dlm_stat_cache_hit);
			mxfs_dlm_report_stats();
			{ mxfs_ilock_fast_path_outcome = MXFS_BLOCK_RETURN; goto mxfs_ilock_fast_path_exit; }
		}
	}
mxfs_ilock_fast_path_exit:
	*phantom_laps_io = phantom_laps;
	return mxfs_ilock_fast_path_outcome;
}

/*
 * sess-tcp ROOT FIX: un-throttled dir-EX held verify (TCP only — the
 * mirror lookup is a cheap in-mem walk, NOT the CAW 512B slot read the
 * throttled P108 verify above guards against).  P108 is throttled 1/sec
 * AND skips self_created, leaving a sub-second window where a node
 * modifies its self-created shared dir under a CACHED EX whose real DLM
 * grant is gone (PROVEN: P106-STALE-EX; both nodes durably agree on the
 * lost contiguous range = concurrent divergent RMW).  Check EVERY
 * pin-free PUBLISHED dir-EX cache hit: if the mirror says we do NOT hold
 * EX, demote in-core so the slow path re-acquires a real exclusive grant
 * before the RMW.  (Unpublished dirs are diverted by the backstop
 * above.)  pin==0 => no AGF held => the blocking re-acquire cannot
 * ABBA-deadlock.
 */
static void mxfs_ilock_tcp_dir_ex_held_verify(struct xfs_inode *ip, uint8_t mode,
					      struct mxfs_v5_dlm *dlm)
{
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    mode == MXFS_LOCK_EX &&
	    !ip->i_dlm_unpublished &&
	    ip->i_dlm_pin_count == 0 &&
	    ip->i_dlm_ex_holders == 0 &&
	    ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
	    ip->i_dlm_mode == MXFS_LOCK_EX &&
	    /* extend this un-throttled verify to CAW.
	     * On CAW only the THROTTLED (1/100ms) P108 verify above ran, and it
	     * skips self_created — leaving the documented sub-second phantom-EX
	     * window (P106-STALE-EX: on_disk_held=0 while cached_mode=EX) OPEN on
	     * the CAW transport.  During the cache_coherency@32 rename storm two
	     * nodes RMW the shared dir concurrently through that window and give
	     * birth to DIVERGENT dir layouts (P33-FROMDISK-DIRSHRINK incore nx=47
	     * vs disk nx=39 at the SAME di_gen; P60-RELAUDIT leafsum!=di_nextents
	     * INCONSISTENT-AT-RELEASE) whose alternating re-publish keeps every
	     * reload a real adopt -> forks keep unloading -> iread EXes BAST all
	     * PR readers continuously -> ~570ms/op verify -> 0/32 at budget.
	     * mxfs_v5_dlm_inode_held on CAW is one 512B slot read (~0.2-1ms) —
	     * cheap next to the divergence it prevents.  Also do NOT skip
	     * self_created here: the phantom arises from our own demote racing a
	     * re-grant (no peer BAST involved), so the "self_created can't
	     * have lost the bit" proof does not cover it.
	     * A/B: dir_ex_verify_caw=0 reverts CAW to throttled-only. */
	    (mxfs_v5_dlm_is_tcp(dlm) ||
	     (mxfs_dir_ex_verify_caw &&
	      mxfs_v5_dlm_transport_caw(dlm)))) {
		int tcpex_held;
		bool tcpex_sampled;
		uint8_t tcpex_raw;

		spin_unlock(&ip->i_dlm_lock);
		/*
		 * same bounded governor as the P108 verify above.
		 * On TCP this is an in-memory mirror walk and the governor is
		 * a few atomics; on CAW it is the 512B slot read that blocked
		 * `statx` for 181 s during the mass-unmount storm.
		 * mxfs_v5_dlm_inode_held() is exactly
		 * (inode_held_rawmode() >= MXFS_LOCK_EX), reproduced here so
		 * the probe runs under the deadline.
		 */
		MXFS_VERIFY_SITE_INC(mxfs_verify_site_direx_n);
		tcpex_raw = mxfs_dlm_verify_rawmode(dlm, ip->i_ino,
						    &tcpex_sampled);
		tcpex_held = (tcpex_raw >= MXFS_LOCK_EX) ? 1 : 0;
		spin_lock(&ip->i_dlm_lock);
		if (tcpex_sampled && tcpex_held == 0 &&
		    ip->i_dlm_pin_count == 0 &&
		    ip->i_dlm_ex_holders == 0 &&
		    ip->i_dlm_pr_holders == 0 &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		    ip->i_dlm_mode == MXFS_LOCK_EX) {
			static atomic_t ptcpex = ATOMIC_INIT(0);
			if (atomic_inc_return(&ptcpex) <= 800)
				mxfs_probe("mxfs: P-TCPEX-REACQ ino=%llu unpub=%d selfc=%d (cached EX, mirror !held -> re-acquire)\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_unpublished ? 1 : 0,
					ip->i_mxfs_self_created ? 1 : 0);
			mxfs_inode_authority_phantom_loss_locked(ip, MXFS_SITE);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_NL;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 11;
		}
	}
}

/*
 * (PROVEN BY INSTRUMENT root: P106-STALE-EX): before trusting a
 * CACHED dir lock on the fast path, verify we STILL hold the on-disk
 * CAW slot.  A node can lose its on-disk holder bit (its own demote
 * clears the bit before bast_process; a later re-grant racing a demote
 * can leave i_dlm_mode/state stale) while in-core state still claims
 * CACHED at EX/PR.  The fast path would then RMW/read a STALE cached
 * dir block with NO cluster-wide serialization -> durable lost update
 * (rename) or a stale read that still sees a peer's durably-removed
 * dirent (unlink_visibility's "file unexpectedly exists").  This is the
 * directly-probed P106-STALE-EX condition (on_disk_held=0 cached_mode=EX,
 * unpub=0, pin=0, state=CACHED).
 *
 * caw_held() reads ONE 512B slot sector (single-node already bypassed
 * above, so no cost on the single-node perf path).  Gate to dir inodes
 * at pin==0 with NO active local holders (no AGF held -> the slow-path
 * blocking re-acquire cannot ABBA-deadlock; no in-flight thread relies
 * on the cached grant) that would otherwise take the cached fast path.
 * Skip unpublished inodes (handled by the publish backstop).
 * If we do NOT hold the slot, demote in-core to NL/NONE so the slow
 * path below re-acquires from disk + reloads/evicts -> fresh, serialized
 * access.  This is the disk-resident-truth equivalent of a GFS2 glock
 * never being trusted without DLM confirmation.
 */
static void mxfs_ilock_verify_cached_dir_ex(struct xfs_inode *ip, uint8_t mode,
					    struct mxfs_v5_dlm *dlm)
{
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_dlm_pin_count == 0 &&
	    ip->i_dlm_ex_holders == 0 &&
	    ip->i_dlm_pr_holders == 0 &&
	    !ip->i_dlm_unpublished &&
	    /* v0.5.4: a SELF-CREATED inode that has
	     * never received a peer BAST cannot have lost its on-disk holder
	     * bit — once published, a peer can only take the lock by BASTing
	     * us (which clears i_mxfs_self_created), and only our own demote
	     * (BAST-driven) clears the bit.  The stale-EX condition this
	     * verify detects is therefore impossible while the flag holds.
	     * Skipping it removes ~200us of synchronous slot-read I/O per
	     * verify on the create-heavy multi-node path (ftrace-proven:
	     * mxfs_v5_dlm_inode_held 1610 calls / 320ms per node in a 2-node
	     * parallel rsync, all on self-created dirs). */
	    !ip->i_mxfs_self_created &&
	    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
	    /*
	     * v0.5.2 throttle: this verify is one synchronous 512B slot read
	     * per idle dir-ilock cache hit — under create-heavy workloads it
	     * fires several times per file and dominated the solo-rsync
	     * profile (read_slot under xfs_dir_open/xfs_rename ilock chains).
	     * One verify per 100ms per inode keeps the stale-EX detection
	     * (the demote races it catches persist until acted on) without
	     * the per-op cost.  Same correctness class: the verify is
	     * TOCTOU-bounded with or without the throttle.
	     */
	    /* v0.5.3: 100ms -> 1000ms.  The P108 producer is root-fixed
	     * (xfs_mxfs_dlm.c:3017); this verify is defense-in-
	     * depth and was still 2160 of 3947 slot reads in a 2-node
	     * rsync (~3 serialized FUA reads per created file via the
	     * dir-ilock chain).  Detection latency 1s instead of 100ms —
	     * the stale-EX condition persists until acted on, so the
	     * detector still fires; it just samples less often.
	     *
	     * (2/tcp) NOTE: removing this throttle for dirs was TESTED and
	     * is NOT the fix — P108-REACQUIRE fired ZERO times at a lost-update,
	     * i.e. the holder NEVER lost its on-disk slot.  The rotating
	     * shortform-dir lost-update is therefore NOT the P106/P108 stale-EX
	     * (lost-slot) condition this verify detects; it is a DOUBLE-GRANT
	     * (both nodes hold a valid EX concurrently — undetectable from the
	     * disk heartbeat slot) or a transient read-staleness.  Throttle kept. */
	    /* jittered, so 32 nodes do not sample the same hot slot
	     * on the same cadence (see the verify governor above). */
	    mxfs_verify_throttle_elapsed(ip->i_dlm_heldchk_j, 1000) &&
	    (ip->i_dlm_mode == MXFS_LOCK_EX ||
	     (ip->i_dlm_mode == MXFS_LOCK_PR && mode == MXFS_LOCK_PR))) {
		int p108_held;
		uint8_t p108_raw;
		bool p108_sampled;

		spin_unlock(&ip->i_dlm_lock);
		MXFS_VERIFY_SITE_INC(mxfs_verify_site_p108_n);
		p108_raw = mxfs_dlm_verify_rawmode(dlm, ip->i_ino,
						   &p108_sampled);
		spin_lock(&ip->i_dlm_lock);
		/*
		 * re-arm the throttle only on a REAL sample.  A
		 * skipped/abandoned probe must not buy the inode another
		 * second of unverified fast-path serves — the next operation
		 * retries it as soon as the breaker closes.
		 */
		if (p108_sampled)
			ip->i_dlm_heldchk_j = jiffies;
		/* PHANTOM-LOCK CHECK FIX: a phantom lock
		 * is when we hold STRICTLY LESS than the mode we have cached.  The
		 * old check used mxfs_v5_dlm_inode_held() == 0, i.e. held_mode >= EX,
		 * which FALSE-NEGATIVED a legitimately-held PR (held_mode=PR < EX) and
		 * demoted it -> both nodes thrashed PR re-acquires on the shortform
		 * PARENT dir (ino=128), starving node1's mkdir/rm EX-acquire (rc=-35
		 * after the 60-retry budget) -> the 65s round-9 verify stall that
		 * preceded the round-10 dir_reuse data loss.  Validate against the
		 * mode we actually cached: phantom iff held_raw < cached mode. */
		p108_held = (p108_raw >= ip->i_dlm_mode) ? 1 : 0;
		/* Re-validate under the lock after the I/O window: only act if
		 * still idle (no holders raced in) and still claiming a cached
		 * grant we provably do not hold at the cached mode.
		 * and only on a REAL sample — "the device did not
		 * answer inside the budget" proves nothing in either
		 * direction and must never demote a valid grant. */
		if (p108_sampled && p108_held == 0 &&
		    ip->i_dlm_pin_count == 0 &&
		    ip->i_dlm_ex_holders == 0 &&
		    ip->i_dlm_pr_holders == 0 &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		    (ip->i_dlm_mode == MXFS_LOCK_EX ||
		     ip->i_dlm_mode == MXFS_LOCK_PR)) {
			mxfs_probe_ratelimited(
			    "mxfs: P108-REACQUIRE ino=%llu cached_mode=%u req=%u state=%u held_raw=%u (real phantom: hold < cached; forcing slow-path re-acquire)\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode, mode, ip->i_dlm_state, p108_raw);
			mxfs_inode_authority_phantom_loss_locked(ip, MXFS_SITE);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_NL;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 10;
		}
	}
}

void
mxfs_dlm_ilock_begin(
	struct xfs_inode	*ip,
	uint8_t			mode)
{
	struct mxfs_v5_dlm	*dlm;
	int			relock_laps = 0;
	int			recov_laps = 0;		/* b3: recovery-context requeues */
	int			park_laps = 0;		/* D-513: parked on pending recovery */
	int			live_laps = 0;		/* 0.75.28: budget exhausted behind a live holder */
	int			trans_laps = 0;		/* 0.84.5: stalled authority transitions waited out */
	u64			live_t0 = 0;		/* 0.75.28: first such exhaustion, ns */
	int			phantom_laps = 0;	/* v0.6.5: P106 phantom-EX bail retries */
	bool			slowpath_publish = false; /* this acquire IS the publish (creator baseline site 4) */
	/* step 5.3(d): i_mxfs_auth_gen as it stood BEFORE this acquire
	 * descended into the DLM.  Re-checked at install; a relinquishment in
	 * between moves it and the completion is refused as stale. */
	uint64_t		auth_gen_snap = MXFS_AUTH_GEN_NONE;

	/*
	 * the EDEADLK self-demote retry used to TAIL-RECURSE
	 * into this function.  Under a retry storm (each lap's re-request is
	 * granted mid-drain and the release aborts) the recursion reached
	 * ~35 frames and blew the 16KB kernel stack inside the TCP send at
	 * the bottom (test1 serial log: stack guard page -> "Fatal exception
	 * in interrupt", RIP virtqueue_add_split, comm=bash open()).  Retry
	 * via this label instead — constant stack — with a lap counter:
	 * backoff after a few laps, force-shutdown (not panic) if it will
	 * not converge.
	 */
restart:
	dlm = ip->i_mount->m_mxfs_dlm;
	if (!dlm)
		return;

	/*
	 * ( a864) SHUTDOWN FENCE — dir_reuse@32/caw r13 collapse:
	 * a mount that has been force-shut-down MUST NOT keep participating in
	 * the cluster DLM.  PROVEN (run 150528Z rank8/test8): shutdown at
	 * 1993s, yet its dd/bash retry loops kept contending and at 2359s it
	 * ACQUIRED the hot dir's EX (P34-ACQ-SLOW rc=0, last_ex_slot=20 on
	 * disk) — a tenure its dead FS can never use or cleanly release.  The
	 * 27 shut-down nodes' continued acquires drove the slot's CAS
	 * generation 512 -> 130k in ~350s and starved the surviving nodes
	 * (rank1 SESS50-STARVE for minutes).  On shutdown: acquire nothing
	 * (every op fails at the trans/buffer layer anyway) — and the
	 * shutdown hook (mxfs_dlm_shutdown_withdraw) stops our disklock
	 * heartbeat so peers' existing dead-node purge reclaims whatever we
	 * still hold.  ilock_end tolerates the unpaired end (P71 guards).
	 */
	if (xfs_is_shutdown(ip->i_mount)) {
		pr_warn_ratelimited(
		    "mxfs: P-SHUTDOWN-FENCE ino=%llu mode=%u — FS shut down; refusing DLM acquire\n",
			(unsigned long long)ip->i_ino, mode);
		return;
	}

	/* (ruling item 2): explicit WEDGED admission gate.
	 * The mount-shutdown fence above is NOT sufficient — the wedge→
	 * shutdown transition has a visibility window, and a teardown wedge
	 * never shuts down at all.  Terminal: the release on this inode is
	 * unprovable, its grant is pinned, and no new acquire may be built
	 * on it; the op dies at the trans/buffer layer like any shutdown. */
	if (mxfs_release_proof_enforce &&
	    READ_ONCE(ip->i_mxfs_rel_state) == MXFS_RELSTATE_WEDGED) {
		pr_warn_ratelimited(
		    "mxfs: P-INODE-WEDGE-FENCE ino=%llu mode=%u — release wedged; refusing DLM acquire\n",
			(unsigned long long)ip->i_ino, mode);
		return;
	}

	/*
	 * (D-513 enforcement point c): inode in a quarantined victim
	 * domain — refuse the acquire and poison the inode so the op fails
	 * deterministically with EIO at the central incarnation gate (plus
	 * the P95 NL fail-closed check) instead of waiting out a frozen
	 * grant.  Inside the restart loop deliberately: a task parked on the
	 * timeout classifier's quarantine-pending branch re-checks here
	 * every lap and self-releases the moment the import lands.
	 */
	if (unlikely(mxfs_quarantine_covers_ino(ip->i_mount, ip->i_ino))) {
		xfs_iflags_set(ip, MXFS_IF_QUAR_EIO);
		pr_warn_ratelimited(
		    "mxfs: P240-QUAR-REFUSE ino=%llu mode=%u comm=%s — inode in quarantined victim domain; refusing DLM acquire\n",
			(unsigned long long)ip->i_ino, mode, current->comm);
		return;
	}

	/*
	 * 0.74.0: the grant is held by a dead node in RECOVERY_BLOCKED.
	 * Refuse the acquire; the operation fails -EIO at the central gate
	 * (mxfs_inode_incarn_estale) instead of parking for the budget.
	 * Not a poison: the predicate is re-evaluated on every entry.
	 */
	if (unlikely(mxfs_recovery_blocked_covers_ino(ip->i_mount, ip->i_ino))) {
		pr_warn_ratelimited(
		    "mxfs: P240-RBLK-REFUSE ino=%llu mode=%u comm=%s — grant held by a dead node whose recovery is RECOVERY_BLOCKED; refusing DLM acquire (op fails EIO)\n",
			(unsigned long long)ip->i_ino, mode, current->comm);
		return;
	}

	/*
	 * There is NO membership exemption from the ownership protocol.  A
	 * mount that is alone takes real grants from the master (itself)
	 * exactly like a multi-node member, whether it is the sole survivor
	 * of a peer's death (0.83.3, D-0955) or has never had a peer
	 * (0.87.16, D-LONE-MOUNT-DIRECTORY-BLOCK-IMAGE-SHIPS-AUTH-NOT-HELD).
	 *
	 * History.  A single-node bypass returned here for years: first for
	 * every single-node mount (0.72.2 taught it to service the dead
	 * peer's pending invalidations inline), then, from 0.83.3, only for
	 * a mount that had never had a peer, on the argument that its caches
	 * hold nothing but its own images and "no successor writer can exist
	 * for anything it logs".  That argument covers live coherency only.
	 * After a death the replayer of the victim's slice -- a survivor, or
	 * this node's own next incarnation -- IS the successor writer for
	 * everything the victim logged, and it authorizes each inode-owned
	 * buffer image (a directory block, a bmap-btree block, a remote
	 * symlink or attribute block) only against the durable grant the
	 * victim's inode held when the image was captured.  With the bypass
	 * no inode on a lone mount ever had a DLM mode, an authority state or
	 * an on-disk grant, so every such image shipped AUTH_NOT_HELD.
	 * Measured (s53f, 2 nodes/TCP, 0.87.14): a lone mount's mkdir + 40
	 * creates + fsync, killed within a second; the returning node refused
	 * the directory-block image, atomically skipped the only transaction
	 * in the slice, quarantined AG 0 cluster-wide and answered EIO to
	 * every root lookup -- 40 fsynced files lost from view.  Proven by
	 * instrument (s54a/s54b): 45 non-durable captures (authority NONE,
	 * DLM mode NL) of the directory's block on the lone mount, zero with
	 * a peer mounted.  The AG path had no such exemption since 0.41.0,
	 * which is why the same transaction's six AG images were VALID.
	 *
	 * Being alone permits omitting coordination with live peers (the
	 * peer-signalling shortcuts stay keyed on mxfs_v5_dlm_is_single_node:
	 * heartbeat notes, the CAW barrier, the leaf-before-dinode flush --
	 * they have nobody to signal).  It does not permit omitting the
	 * durable authority a future incarnation or foreign replayer needs.
	 * Every ownership, freshness and publication decision below runs
	 * unconditionally: the local unpublished-EX tenure on create, the
	 * deferred-publish list, the directory's real acquire at its first
	 * EX modify, the metadata-owning file's publish before its first
	 * out-of-core image, the release drain at exit.
	 */

	/*
	 * v0.3.122: P67-INSTR — entry log for every ilock_begin
	 * call on dir inode 128.  Cross-correlate count with P63
	 * (fast-path), reload (slow-path), and demoter-bypass to find
	 * the missing reload path.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) && ip->i_ino == 128)
		mxfs_idbg("mxfs: P67-INSTR ino=%llu ILOCK-BEGIN-DIR "
			"req_mode=%u cached_mode=%u state=%u stale=%d "
			"realns=%llu\n",
			(unsigned long long)ip->i_ino,
			mode, ip->i_dlm_mode, ip->i_dlm_state,
			ip->i_dlm_stale,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * Reclaim path: xfs_reclaim_inode (xfs_icache.c) sets i_ino=0 under
	 * i_flags_lock, then calls xfs_ilock+xfs_iunlock as an "almost
	 * spurious" coordination point against concurrent radix-tree lookups
	 * before __xfs_inode_free.  Triggered visibly by drop_caches under
	 * memory pressure (xfs_reclaim_inodes_nr → xfs_icwalk_ag → xfs_ilock).
	 * The DLM lock for this inode was already released by mxfs_dlm_evict
	 * earlier in the reclaim path; there is no remote coordination work
	 * to do.  Skip cleanly.
	 */
	if (unlikely(ip->i_ino == 0))
		return;

	spin_lock(&ip->i_dlm_lock);

	/*
	 * NEWARCH Phase 0 force_coherent NOTE: an earlier version of this
	 * measurement instrument clobbered i_dlm_mode/state here under
	 * force_coherent, forcing every cached acquire through the slow path.
	 * That raced the slow-path inode reload against the SF-dir read path
	 * (xfs_dir2_sf_lookup) and produced a NULL deref on test1..test4
	 * during test_unlink_visibility's mkdir sequence (reload momentarily
	 * cleared if_data while a concurrent thread iterated sf entries).
	 * The buffer-level invalidation in xfs_da_read_buf and xfs_iget_cache_hit
	 * is the safer instrument: it forces a refetch from the SCST-coherent
	 * shared target without touching the in-core lock-state machine.
	 */

	mxfs_ilock_verify_cached_dir_ex(ip, mode, dlm);

	mxfs_ilock_tcp_dir_ex_held_verify(ip, mode, dlm);

	/*
	 * Cached-mode fast path checked BEFORE the DEMOTING wait.
	 *
	 * While bast_process is mid-flush (state==DEMOTING), the on-disk
	 * DLM grant is still held until mxfs_v5_dlm_inode_unlock runs;
	 * bast_process clears i_dlm_mode to NL just before that unlock.
	 * So if i_dlm_mode is still sufficient, the cluster invariant is
	 * satisfied — any local thread can take the cached lock and
	 * proceed.  This unblocks two recursion patterns that previously
	 * self-deadlocked on the DEMOTING wait:
	 *
	 *   1. bast_process → filemap_write_and_wait → iomap_writepages →
	 *      xfs_map_blocks → xfs_ilock (same thread).
	 *   2. xfs end-of-IO completion (xfs_iomap_write_unwritten) on
	 *      a kworker, while the dd thread is in bast_process waiting
	 *      for that very writeback to drain (cross-thread cycle).
	 */
	{
		int mxfs_ilock_fast_path_outcome;

		mxfs_ilock_fast_path_outcome = mxfs_ilock_fast_path(ip, mode,
								    dlm,
								    &phantom_laps);
		if (mxfs_ilock_fast_path_outcome == MXFS_BLOCK_RETURN)
			return;
		if (mxfs_ilock_fast_path_outcome == MXFS_BLOCK_GOTO + 0)
			goto restart;
	}

	/*
	 * Recursive demoter belt-and-suspenders: even if the mode-check
	 * above didn't catch us (e.g. a needed upgrade), don't block on
	 * the DEMOTING wait if we're the thread driving bast_process —
	 * that would self-deadlock.
	 */
	if (mxfs_is_demoter(ip)) {
		/* dir-EX served via demoter-bypass = NO refresh. */
		if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX)
			atomic64_inc(&mxfs_dirEX_demoter_bypass);
		if (mode == MXFS_LOCK_EX) {
			ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "begin-demoter", 1, 0);
		} else {
			ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "begin-demoter", 0, 1);
		}
		/*
		 * v0.3.123 P68-INSTR: demoter belt-and-suspenders
		 * path for dir inodes.  This branch acquires WITHOUT reload.
		 * P67 counts showed ~30% of dir ilock entries take this
		 * path on the failing node.  If a non-bast_process
		 * operation happens to set i_dlm_demoter==current somehow
		 * (incorrectly), this acquires stale-mem dir.
		 */
		if (S_ISDIR(VFS_I(ip)->i_mode))
			mxfs_idbg("mxfs: P68-INSTR ino=%llu DEMOTER-BYPASS-DIR "
				"req_mode=%u cached_mode=%u state=%u "
				"realns=%llu\n",
				(unsigned long long)ip->i_ino,
				mode, ip->i_dlm_mode, ip->i_dlm_state,
				(unsigned long long)ktime_get_real_ns());
		spin_unlock(&ip->i_dlm_lock);
		return;
	}

	/*
	 * instrumented INSTRUMENT: capture WHY a NON-dir
	 * (file) op is about to block on the DEMOTING/ACQUIRING/BAST wait when
	 * the cached-mode fast path above did NOT admit it.  The 8/tcp dir_reuse
	 * release-pipeline deadlock is: bast_process releasing a file does
	 * filemap_write_and_wait, whose writeback completion (xfs_end_io ->
	 * xfs_iomap_write_unwritten, req EX) reaches here and blocks — proving
	 * i_dlm_mode is NOT EX at that moment (else the 13954 fast path admits).
	 * Log mode/state/req/comm so the next repro shows the exact mode state
	 * (PR-downgrade? NL-already? ACQUIRING?) that the fix must admit.  Capped.
	 */
	/*
	 * (PROVEN BY INSTRUMENT — DEADLOCK CAPTURED) — admit an
	 * in-flight REG-FILE op during the DEMOTING release-flush window.
	 *
	 * bast_process releasing a written reg file does filemap_write_and_wait
	 * (reg-durable flush, ~9966) AFTER it cleared i_dlm_mode=NL (~9266).  That
	 * wait blocks on folio_wait_writeback for the inode's pages; the page
	 * writeback completion is the xfs_end_io -> xfs_iomap_write_unwritten
	 * unwritten-extent conversion, which needs an EX ILOCK and re-enters here
	 * on the xfs-conv kworker.  The mode==EX fast path above (which the design
	 * relies on to admit exactly this xfs-conv re-entry, see its comment) no
	 * longer matches because mode was cleared to NL -> the conversion falls to
	 * the DEMOTING wait below -> PageWriteback never clears -> bast_process
	 * deadlocks (PROVEN: u10 bast in filemap_write_and_wait + xfs-conv kworker
	 * in ilock_begin DEMOTING wait, both D-state >18s; P47 mode=0 state=3).
	 *
	 * The on-disk DLM grant is STILL HELD in this window — MXFS_IF_DLM_RELFLUSH
	 * is set from ~9222 until ~10137 and the on-disk unlock is later (~10312) —
	 * so completing in-flight work under that held grant is safe (identical
	 * safety to the mode==EX fast path; we are merely covering the sub-window
	 * where bast_process pre-cleared mode to NL).  Files ONLY: dirs have no
	 * page-cache writeback / unwritten-extent conversion and keep the strict
	 * coherency gate (admitting a dir op mid-demote would let a peer read a
	 * pre-commit dir — the v0.3.13 hazard).
	 */
	if (!S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING &&
	    !mxfs_is_demoter(ip) &&
	    xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    /* 0.75.39: the re-entry this covers is the release's own
	     * writeback completion, a kernel thread; a user task starting
	     * new work waits for the hand-off (see file_yield_on_demote). */
	    ((current->flags & PF_KTHREAD) ||
	     !READ_ONCE(mxfs_file_yield_on_demote))) {
		if (mode == MXFS_LOCK_EX) {
			ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "begin-relflush", 1, 0);
		} else {
			ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "begin-relflush", 0, 1);
		}
		spin_unlock(&ip->i_dlm_lock);
		return;
	}

	{
		int mxfs_ilock_nested_hold_guard_outcome;

		mxfs_ilock_nested_hold_guard_outcome = mxfs_ilock_nested_hold_guard(ip,
										    mode);
		if (mxfs_ilock_nested_hold_guard_outcome == MXFS_BLOCK_RETURN)
			return;
	}

	mxfs_ilock_report_admit_refusal(ip, mode);

	/*
	 * DLM grant has been released (mode==NL) but bast_process hasn't
	 * yet cleared the state to NONE.  Wait for it.
	 */
	/*
	 * NEWARCH Phase 1.3 (design review chokepoint design): also wait while
	 * ACQUIRING — another thread on this node has the slow-path
	 * caw_lock in flight.  Racing into our own slow-path here would
	 * make concurrent same-node callers each call caw_lock for the
	 * same resource, which is the failure shape of the v1 fence
	 * attempt.  Also wait on BAST — the drain pipeline is about to
	 * run; if we ran caw_lock now we'd compete with our own drain
	 * for the on-disk slot.  Demoter is exempt (it must re-enter
	 * during its own drain).
	 */
	/* FIX-25: never let the ioend completion worker queue behind a
	 * drain that is waiting for ITS folio (see mxfs_ilock_admit_ioend). */
	if (mxfs_ilock_admit_ioend(ip, mode)) {
		spin_unlock(&ip->i_dlm_lock);
		return;
	}

	int p73_waits = 0;

	/* stamp the ring at the moment we decide to park, so the
	 * replay below reads SET(who) ... CLEAR(who) ... WAIT(me). */
	if ((ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
	     ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
	     ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) &&
	    !mxfs_is_demoter(ip)) {
		mxfs_demev_rec(ip, 2, MXFS_SITE);
		/*
		 * THE WEDGE PRECONDITION, named.  We are about to park on a
		 * release, and we are not a recognised demoter — yet a steal
		 * recorded US as the victim of a claim clobber on this inode.
		 * That is exactly the captured wedge: the drain's own trailing
		 * xfs_irele cascades to inactivation, re-takes the lock, has
		 * lost its exemption, and waits for a release only it can
		 * drive.  Only reachable with demoter_legacy_clobber armed; the
		 * two-slot claim makes the steal impossible, so this counter
		 * is zero BY CONSTRUCTION in a shipping build.  Its value in
		 * the legacy arm is the exposure the A/B needs.
		 */
		if (ip->i_dlm_clobber_victim_pid == current->pid) {
			static atomic_t p77n = ATOMIC_INIT(0);

			atomic64_inc(&mxfs_dem_wedge_precond);
			if (atomic_inc_return(&p77n) <= 200)
				pr_warn("mxfs: P77-WEDGE-PRECOND ino=%llu me=%d comm=%s stolen_from_line=%u:%u state=%u req=%u — parking on a release this task was draining; its claim was stolen\n",
					(unsigned long long)ip->i_ino,
					current->pid, current->comm,
					MXFS_SITE_ARGS(ip->i_dlm_clobber_victim_line),
					ip->i_dlm_state, mode);
		}
	}

	{
		int mxfs_ilock_wait_for_transition_outcome;

		mxfs_ilock_wait_for_transition_outcome = mxfs_ilock_wait_for_transition(ip,
											mode,
											&p73_waits);
		if (mxfs_ilock_wait_for_transition_outcome == MXFS_BLOCK_RETURN)
			return;
	}

	/*
	 * NEWARCH Phase 1.3 chokepoint (design review design): mark this inode as
	 * having a slow-path caw_lock in flight.  Effects:
	 *   - Concurrent same-node ilock_begin callers observe ACQUIRING
	 *     and wait in the loop above.
	 *   - bast_notify treats ACQUIRING as "defer the BAST via i_dlm_stale
	 *     flag, do NOT queue bast_process" — queuing bast_process now
	 *     would strip the on-disk slot out from under our in-flight
	 *     caw_lock poll loop.  We honor the BAST on caw_lock return.
	 *   - On caw_lock success → state becomes CACHED (or BAST if a
	 *     peer BAST arrived while we were acquiring).
	 *   - On caw_lock -EDEADLK → state becomes BAST + queue bast_process,
	 *     which flushes/invalidates/clears the on-disk bit + sets
	 *     i_dlm_mode = NL atomically.  Then we retry from a clean NL
	 *     state and re-acquire.
	 *
	 * Skip for the demoter (it must self-reenter during drain) and for
	 * single-node mounts.
	 */
	/* daf50d34 count the in-flight slow-path acquire in a field the
	 * concurrent state writers CANNOT trample (unlike ISTATE_ACQUIRING,
	 * which a stale pipeline exit overwrote to NONE in the proven
	 * mkdir-storm kill).  Balanced at every slow-path exit below. */
	if (ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		ip->i_dlm_acq_inflight++;
	auth_gen_snap = ip->i_mxfs_auth_gen;	/* under i_dlm_lock */
	if (ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm) &&
	    !mxfs_is_demoter(ip))
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_ACQUIRING;
		/* leaked-ACQUIRING forensics (b54r1 dir 131,
		 * 184s orphaned ACQUIRING -> peer starvation shutdown).  Stamp
		 * the setter; the bast_notify orphan-reclaim prints it. */
		ip->i_dlm_acq_pid = current->pid;
		strscpy(ip->i_dlm_acq_comm, current->comm,
			sizeof(ip->i_dlm_acq_comm));
		ip->i_dlm_acq_set_ns = ktime_get_ns();
		ip->i_dlm_acq_strikes = 0;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	else if (ip->i_mount->m_mxfs_dlm &&
		 !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		/* instrumented probe: a demoter-context thread is
		 * issuing a REAL slow-path DLM acquire WITHOUT the ACQUIRING
		 * serialization (by design it must self-reenter) — the prime
		 * suspect for the same-node concurrent-request collision that
		 * produced run61's -EEXIST (P3A-EEXIST-WAIT names the waiter;
		 * this names the bypass issuer). */
		mxfs_probe_ratelimited(
			"mxfs: P3A-DEMOTER-SLOWACQ ino=%llu mode=%u state=%u comm=%s\n",
			(unsigned long long)ip->i_ino, mode,
			ip->i_dlm_state, current->comm);

	/* Slow path: need DLM lock (CAW round-trip) */
	spin_unlock(&ip->i_dlm_lock);

	{
		int block_outcome;

		block_outcome = mxfs_ilock_acquire_from_dlm(ip,
							    &slowpath_publish,
							    mode, auth_gen_snap,
							    &relock_laps,
							    &recov_laps,
							    &trans_laps,
							    &park_laps, &live_t0,
							    &live_laps);
		if (block_outcome == MXFS_BLOCK_RETURN)
			return;
		if (block_outcome == MXFS_BLOCK_GOTO + 0)
			goto restart;
	}

	/*
	 * v0.3.15: publish i_dlm_mode immediately after the caw_lock grant,
	 * BEFORE the slow reload_inode I/O.  Without this, an incoming BAST
	 * during reload sees state=NONE && mode=NL and the bast_notify
	 * NONE_mode_NL branch calls mxfs_v5_dlm_inode_unlock — wiping the
	 * holder bit we just legitimately acquired on disk.  The deferred-BAST
	 * branch (mode != NL → set state=BAST, return) is the intended
	 * handling; setting the mode here makes that branch fire.
	 */
	/*
	 * (D-513 enforcement point d): the quarantine may have been
	 * imported while this acquire was polling — the grant itself came
	 * back fine, but the domain it names is now terminally refused.
	 * Poison only: the op fails EIO at the central gate, and the grant
	 * is released normally on the regular path (no leaked holder bit).
	 */
	{
		int outcome;

		outcome = mxfs_ilock_test_strand_inject(ip, mode);
		if (outcome == MXFS_BLOCK_RETURN)
			return;
	}
	if (unlikely(mxfs_quarantine_covers_ino(ip->i_mount, ip->i_ino)))
		xfs_iflags_set(ip, MXFS_IF_QUAR_EIO);
	xfs_iflags_clear(ip, MXFS_IF_ACQ_REFUSED);	/* 0.75.33 D-0915: granted */
	spin_lock(&ip->i_dlm_lock);
	if (mode > ip->i_dlm_mode) {
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_mode = mode;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		/* (design review DLM-epoch guard): a real upgrade INTO EX is a
		 * fresh EX tenure -> snapshot a new epoch so any dirty state left
		 * from a previous tenure is detectable as stale at flush time. */
		/*  a FRESH grant is trivially "held on
		 * disk" — stamp the held-verify clock so p108 (1000ms), the
		 * dir-serve verify (100ms) and the cluster_durable tenure
		 * check (100ms) all skip their on-disk probe for a grant this
		 * young.  kprobe-counted: those probes were ~2 FUA chain
		 * walks per one-shot inode (create/unlink/cold-stat), pure
		 * cost on inodes whose grant is milliseconds old. */
		ip->i_dlm_heldchk_j = jiffies;
		if (mode == MXFS_LOCK_EX) {
			mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
			ip->i_mxfs_ex_grant_seq =
				atomic64_inc_return(&mxfs_ex_epoch);
			/* stamp fresh-EX acquire time for MHT batching */
			ip->i_dlm_ex_acquire_ns = ktime_get_ns();
			ip->i_dlm_tenure_ops = 0;
			ip->i_dlm_tenure_firstop_ns = 0;
		}
	}
	spin_unlock(&ip->i_dlm_lock);

	/* CREATOR BASELINE STAMP site 4 — the acquire that just completed
	 * WAS this inode's publish (the unpublished-modify backstop
	 * dropped it from the unpub list above).  Sleepable, no lock held, `ip`
	 * is the caller's referenced inode.  Measured 2/caw: sites 2 and 3
	 * between them covered only reused-create dirs and read bep=0, while
	 * every inode that actually fired P195 came through HERE — do not drop
	 * this site because the others exist. */
	if (slowpath_publish)
		mxfs_dlm_creator_baseline_query(ip, 4);

	mxfs_idbg("mxfs: P13-INSTR ino=%llu mode=%u ACQ-FRESH realns=%llu\n",
		(unsigned long long)ip->i_ino, mode,
		(unsigned long long)ktime_get_real_ns());

	/* (instrumented): bracket the cross-node ON-DISK-slot EX-held window
	 * for a DIR inode.  Paired with P106-EXREL at inode_unlock, a cross-node
	 * realns timeline shows whether two nodes hold the SAME dir inode EX
	 * OVERLAPPING (mutual-exclusion / CAW double-grant failure) vs serialized.
	 * This decides the concurrent-mkdir-divergence fix direction. */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (S_ISDIR(VFS_I(ip)->i_mode) || S_ISREG(VFS_I(ip)->i_mode)) &&
	    mode == MXFS_LOCK_EX) {
		/* v0.6.3 double-EX discriminator: popcount(holders_ex) over
		 * the WHOLE probe chain, read from the shared LUN at grant
		 * completion — clock-free disk truth.  expop>1 == another
		 * node's EX bit is live while ours just got granted (broken
		 * mutual exclusion); nslots>1 == claim-race (same resource
		 * in two live slots). */
		int p106_nslots = 0;
		int p106_expop = mxfs_v5_dlm_inode_ex_count(
						ip->i_mount->m_mxfs_dlm,
						ip->i_ino, &p106_nslots);

		mxfs_probe("mxfs: P106-EXGRANT ino=%llu dir=%d expop=%d nslots=%d realns=%llu\n",
			(unsigned long long)ip->i_ino,
			S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
			p106_expop, p106_nslots,
			(unsigned long long)ktime_get_real_ns());
	}

	atomic64_inc(&mxfs_dlm_stat_cache_miss);

	/*
	 * Reload on slow-path acquire — but ONLY when the in-memory inode
	 * has populated state (mode != 0 || nblocks != 0).  For a fresh ip
	 * (mode == 0, nblocks == 0), we are either in xfs_iget cache_miss
	 * for IGET_CREATE (single-node v3 XFS deliberately skips the disk
	 * read here — the on-disk content of a freed cluster slot is
	 * stale-by-design per xfs_inactive_ifree's stale-and-cancel
	 * protocol) or accessing a genuinely-freed inode where the disk
	 * content is also useless.  Reading disk in either case pulls in
	 * prior-cycle alloc'd bytes (mode=0x81a4 etc.) and trips
	 * xfs_iget_check_free_state's "Free inode N not marked free"
	 * verifier — bug B residual.  Skip the reload; the caller
	 * (xfs_init_new_inode for CREATE) will populate fresh state.
	 */
	mxfs_ilock_reload_storm_gate(ip, mode);

	/* (design review design-consult consult): PROVE the stale-inode-core hole.
	 * Right after the slow-path reload (which rebuilt i_df + i_disk_size
	 * from the on-disk home block), log this dir's size + extent count.
	 * If it is SMALLER than a peer's P105-REL-DIRINODE for the same ino
	 * earlier in the realns timeline, the home block we read was STALE
	 * (peer's dir-grow not yet iflushed) → our imminent RMW will see the
	 * dir as too short, re-grow it, and orphan the peer's overflow block.
	 * run14d: gated mxfs.dirwr/mxfs.instr for ship. */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    S_ISDIR(VFS_I(ip)->i_mode))
		mxfs_probe_ratelimited(
			"mxfs: P105-ACQ-DIRINODE ino=%llu disk_size=%lld nextents=%llu fmt=%d realns=%llu\n",
			(unsigned long long)ip->i_ino,
			(long long)ip->i_disk_size,
			(unsigned long long)ip->i_df.if_nextents,
			ip->i_df.if_format,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * EAGER INVALIDATION on ACQUIRE.  reload_inode above stales only
	 * the dinode CLUSTER buffer, not the dir DATA blocks; the gen bump just
	 * above defers those to the lazy read-path hook (xfs_da_read_buf), which
	 * PROVABLY loses the race when the stale cached block is transiently
	 * pinned by the async CIL unpin workqueue (DIR-STALE-SKIP pin=1
	 * disk_differs=1 — disk holds the peer's renames, the cached block does
	 * not, and the hook must skip a pinned buffer).  This is the dominant
	 * failure mode under CAW, whose disk-polling does NOT actively BAST a
	 * peer's silent dir modification, so the demote-side eviction never
	 * fires for it.  Here we have just completed a fresh slow-path DLM grant
	 * (a multi-ms CAW round-trip — the previous release's async unpin has
	 * long drained), so the peer's dir is durable on disk and our cached
	 * data blocks are unambiguously stale.  Evict them now so the caller's
	 * imminent read is a clean cache miss that FUA-fetches the peer's block.
	 * mxfs_dir_evict_data_blocks re-checks per-block durability and uses
	 * XBF_TRYLOCK, so any block still genuinely carrying un-logged local
	 * work is left for the lazy hook.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		/* DRAIN-then-evict (handles i_lock internally).  Unlike
		 * the plain evict, this drains a transiently-pinned stale block
		 * (the proven DIR-STALE-SKIP pin=1 lost-update window) instead of
		 * skipping it, so the caller's first read FUA/cache-miss fetches
		 * the peer's durable merged dir image. */
		mxfs_dir_drain_evict_data_blocks(ip);
		/* extent-map-independent owner-EVICT on a real cross-node
		 * handoff (grant_gen advanced since our last grant = a peer held
		 * EX in between) — drop every CLEAN cached dir block owned by this
		 * inode, INCLUDING blocks the extent-map evict above missed (out
		 * of the current in-core map), so the imminent RMW cold-reads the
		 * peer's durable image instead of a stale out-of-map base (the
		 * surviving readdir=799 mechanism after the release-side
		 * owner-scan).  A continuous same-node tenure keeps grant_gen so
		 * this is skipped (no cost, no resurrection of our own work). */
		if (mxfs_dir_owner_scan && mode == MXFS_LOCK_EX &&
		    ip->i_mount->m_mxfs_dlm) {
			uint32_t cur_gg = mxfs_v5_dlm_inode_grant_gen(
				ip->i_mount->m_mxfs_dlm, ip->i_ino);
			if (cur_gg != ip->i_dlm_cached_grant_gen)
				mxfs_dir_evict_owned_data_blocks(ip);
		}
	}

	bool batch_arm = false;	/* arm MHT dwork after unlock (batching) */
	/* (plan): cache the RELIABLE per-grant generation token for
	 * this fresh slow-path grant.  Queried BEFORE the spinlock (the grant is
	 * already in the DLM table; the query takes table_rwlock, not allowed under
	 * i_dlm_lock).  The dir-EX fast path compares the live grant_gen to this to
	 * detect a tenure change (lock changed hands) without the lossy eviction
	 * ring — the RELIABLE staleness signal for the stale-base RMW clobber. */
	uint32_t fresh_gg = 0;
	if (S_ISDIR(VFS_I(ip)->i_mode) && mode == MXFS_LOCK_EX &&
	    ip->i_mount->m_mxfs_dlm)
		fresh_gg = mxfs_v5_dlm_inode_grant_gen(ip->i_mount->m_mxfs_dlm,
						       ip->i_ino);
	xfs_iflags_clear(ip, MXFS_IF_ACQ_REFUSED);	/* 0.75.33 D-0915: granted */
	spin_lock(&ip->i_dlm_lock);
	/* Another thread may have raced us — take the higher mode */
	if (mode > ip->i_dlm_mode) {
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_mode = mode;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		if (mode == MXFS_LOCK_EX && fresh_gg)
			ip->i_dlm_cached_grant_gen = fresh_gg;
		/* (design review DLM-epoch guard): a real upgrade INTO EX is a
		 * fresh EX tenure -> snapshot a new epoch so any dirty state left
		 * from a previous tenure is detectable as stale at flush time. */
		if (mode == MXFS_LOCK_EX) {
			mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
			ip->i_mxfs_ex_grant_seq =
				atomic64_inc_return(&mxfs_ex_epoch);
			/* stamp fresh-EX acquire time for MHT batching */
			ip->i_dlm_ex_acquire_ns = ktime_get_ns();
			ip->i_dlm_tenure_ops = 0;
			ip->i_dlm_tenure_firstop_ns = 0;
		}
	}
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE)
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	mxfs_ilock_end_acquiring_window(ip, mode, &batch_arm);
	if (mode == MXFS_LOCK_EX) {
		ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
		mxfs_p71_hold(ip, "begin-slow", 1, 0);
	} else {
		ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
		mxfs_p71_hold(ip, "begin-slow", 0, 1);
	}
	/* daf50d34 grant consumed — holders registered in the SAME
	 * locked section, so bast_notify never samples (granted, holders==0)
	 * on this tenure.  Drop the in-flight acquire count. */
	if (ip->i_dlm_acq_inflight)
		ip->i_dlm_acq_inflight--;
	spin_unlock(&ip->i_dlm_lock);

	mxfs_ilock_batch_deferred_bast(batch_arm, ip);
	wake_up_all(&ip->i_dlm_wait);

	mxfs_dlm_report_stats();
}

/*
 * — keep a dir's DLM-EX grant pinned across an
 * ILOCK-dropped durable flush.  The caller (xfs_remove / xfs_create) commits a
 * dirent change under ILOCK_EXCL, then DROPS ILOCK and calls
 * mxfs_dlm_dir_inode_durable() to push the change to the shared LUN — the flush
 * needs ILOCK dropped because xfs_iflush_cluster co-acquires i_lock SHARED.
 *
 * PROVEN ROOT (instrumented, dlm_fairness/tcp_dlm_scaling "shared dir drained
 * got=1"): in the window between the iunlock and the flush, a concurrent peer
 * BAST can release/demote this dir (mode -> NL), so the durable flush runs at
 * non-EX and the P119 authority guard DISCARDS the just-committed
 * removal (marks the inode clean WITHOUT writing it -> P119-NONEX-FLUSH-SKIP
 * comm=rm).  The stale on-disk dirent then survives, and a peer/self reload
 * adopts it -> durable resurrection (n2_rN.done leftover, durable on both nodes,
 * P-SFM-READD=0 so it is NOT the 3-way merge).
 *
 * FIX (GFS2 drain-before-downconvert): bump an extra EX holder while the caller
 * STILL holds ILOCK_EXCL (which proves we hold EX — a dir modify needs it, and
 * bast_process cannot have released because it requires holders==0 and we are a
 * holder).  bast_notify then DEFERS any incoming BAST (active holder) instead of
 * releasing, so i_dlm_mode stays EX across the flush and P119 passes.  The
 * caller pairs this with mxfs_dlm_ilock_end(dp, EX) AFTER the flush, which drops
 * the extra holder and fires the deferred BAST through the sanctioned RELFLUSH
 * drain.  No clobber risk: a peer cannot acquire EX (and thus cannot have a
 * newer image) until our holder drops, i.e. after our flush is on the platter.
 */
void
mxfs_dlm_dir_hold_ex(struct xfs_inode *dp)
{
	struct mxfs_v5_dlm	*dlm = dp->i_mount->m_mxfs_dlm;

	/* Same gate as begin: the paired mxfs_dlm_ilock_end runs its count on
	 * every mount with a DLM (no membership exemption, 0.87.16), so the pin
	 * must be counted here too (measured on a sole survivor: mkdir/rmdir
	 * each left an unpaired EX end on the parent). */
	if (!dlm)
		return;
	spin_lock(&dp->i_dlm_lock);
	dp->i_dlm_ex_holders++; mxfs_exh_stamp_locked(dp); MXFS_DLMTR_H(dp);
	mxfs_p71_hold(dp, "dirhold", 1, 0);
	spin_unlock(&dp->i_dlm_lock);
}
EXPORT_SYMBOL(mxfs_dlm_dir_hold_ex);

/*
 * Called from xfs_iunlock() after VFS i_rwsem has been released.
 * Decrements holder count. If last holder and BAST pending,
 * processes the deferred BAST (flush + invalidate + DLM unlock).
 */
void
mxfs_dlm_ilock_end(
	struct xfs_inode	*ip,
	uint8_t			mode)
{
	struct mxfs_v5_dlm	*dlm;
	bool			need_flush = false;
	bool			idle_arm = false;
	unsigned long		sf_keep_j = 0;

	/* Reclaim path coordination ilock: see mxfs_dlm_ilock_begin comment. */
	if (unlikely(ip->i_ino == 0))
		return;

	/* P229: a bypass grant that unlocks without logging leaves no
	 * stale stamp behind (P230's read-then-clear covers the logged case;
	 * this covers the benign read-mostly one). */
	if (unlikely(READ_ONCE(ip->i_mxfs_atomic_bypass_ns)))
		WRITE_ONCE(ip->i_mxfs_atomic_bypass_ns, 0);

	spin_lock(&ip->i_dlm_lock);

	/*
	 * v0.11.81 (P125 root fix, instrumented ring-proven): the holder-count
	 * bookkeeping below must run UNCONDITIONALLY — it pairs with an
	 * increment ilock_begin already made.  The old !dlm /
	 * is_single_node early-returns above it leaked one holder whenever
	 * membership collapsed to single-node (peer death) or the DLM was
	 * torn down (umount) BETWEEN an op's begin and its end: the begin
	 * incremented in the multi-node era, the end skipped the decrement,
	 * and the leaked count then blocked the reclaim gates
	 * (i_dlm_ex_holders>0 checks) — the busy-inodes-after-unmount /
	 * P125-EVICT-SUSPECT family.  Only the multi-node machinery after
	 * the decrement (BAST fire, flush arming) keeps the gates.
	 */
	/*
	 * Guard against underflow: ILOCK may be taken via xfs_ilock_nowait
	 * without DLM (atomic context), but xfs_iunlock still calls us.
	 * Skip the decrement if holders is already zero.
	 */
	/* every op completion re-arms the tenure
	 * quiet clock — the MHT dwork's quiet-age gate reads this to release
	 * a young-window tenure at the first >=grace idle instead of
	 * sleeping out the full window. */
	ip->i_dlm_tenure_lastop_ns = ktime_get_ns();
	dlm = ip->i_mount->m_mxfs_dlm;
	if (mode == MXFS_LOCK_EX) {
		if (ip->i_dlm_ex_holders > 0) {
			ip->i_dlm_ex_holders--; MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "end", -1, 0);
			/* (D-503): first op completed by this tenure */
			if (ip->i_dlm_tenure_ops == 0)
				ip->i_dlm_tenure_firstop_ns =
					ip->i_dlm_tenure_lastop_ns;
			/* ops served by this EX tenure (adaptive MHT) */
			if (ip->i_dlm_tenure_ops < 0xffff)
				ip->i_dlm_tenure_ops++;
		} else if (dlm && mxfs_v5_dlm_is_single_node(dlm)) {
			int n = atomic_inc_return(&mxfs_end_unpaired_single);

			/* detector: name the unpaired site on a lone mount (a
			 * survivor or a never-multi mount -- both count holders
			 * on entry since 0.87.16) */
			if (n <= 16)
				mxfs_probe("mxfs: P71-SURVIVOR-UNPAIRED ino=%llu mode=EX state=%u dlm_mode=%u pr_h=%u comm=%s un=%pS n=%d\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_state, ip->i_dlm_mode,
					ip->i_dlm_pr_holders, current->comm,
					(void *)ip->i_mxfs_ilk_un_ret, n);
			if (n <= 2)
				mxfs_probe_stack();
		} else if (dlm && !mxfs_v5_dlm_is_single_node(dlm)) {
			/* P71: a guarded skip here = a
			 * mispaired begin/end (the leak's mirror image).
			 * v0.11.81: printed only in multi-node — a
			 * single-node/torn-down end is EXPECTED unpaired
			 * (begin's bypass never incremented). */
			/* 2000→300 — printk-storm DoS (see P82-ADD). */
			static atomic_t p71u_n = ATOMIC_INIT(0);

			atomic_inc(&mxfs_p71_underflows);
			if (atomic_inc_return(&p71u_n) <= 300)
				/* (D-0532 item 3): name the unlock site —
				 * xfs_iunlock records its caller before calling us. */
				mxfs_probe("mxfs: P71-UNDERFLOW ino=%llu mode=EX state=%u dlm_mode=%u comm=%s un=%pS\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_state, ip->i_dlm_mode,
					current->comm,
					(void *)ip->i_mxfs_ilk_un_ret);
		}
	} else {
		if (ip->i_dlm_pr_holders > 0) {
			ip->i_dlm_pr_holders--; MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "end", 0, -1);
		} else if (dlm && mxfs_v5_dlm_is_single_node(dlm)) {
			int n = atomic_inc_return(&mxfs_end_unpaired_single);

			if (n <= 16)
				mxfs_probe("mxfs: P71-SURVIVOR-UNPAIRED ino=%llu mode=PR state=%u dlm_mode=%u ex_h=%u comm=%s un=%pS n=%d\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_state, ip->i_dlm_mode,
					ip->i_dlm_ex_holders, current->comm,
					(void *)ip->i_mxfs_ilk_un_ret, n);
			if (n <= 2)
				mxfs_probe_stack();
		} else if (dlm && !mxfs_v5_dlm_is_single_node(dlm)) {
			/* 2000→300 — printk-storm DoS (see P82-ADD). */
			static atomic_t p71u2_n = ATOMIC_INIT(0);

			atomic_inc(&mxfs_p71_underflows);
			if (atomic_inc_return(&p71u2_n) <= 300)
				mxfs_probe("mxfs: P71-UNDERFLOW ino=%llu mode=PR state=%u dlm_mode=%u comm=%s un=%pS\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_state, ip->i_dlm_mode,
					current->comm,
					(void *)ip->i_mxfs_ilk_un_ret);
		}
	}

	/* v0.11.81: gates moved here from the function head (see comment
	 * above) — bookkeeping done, the rest is the release machinery.
	 * 0.83.3 (D-0955) / 0.87.16: paired with the entry -- every mount with
	 * a DLM takes a real grant on entry, so its exit runs the release
	 * machinery; there is no membership exemption. */
	if (!dlm) {
		spin_unlock(&ip->i_dlm_lock);
		return;
	}

	/*
	 * If BAST is pending and we're the last holder, process it now.
	 * We're in process context with no VFS locks held — safe to sleep.
	 *
	 * v3: also fire when the state is CACHED with the
	 * pending-BAST flag armed — the gen-moved release abort keeps the
	 * fresh grant CACHED so its waiter can proceed, and parks the peer's
	 * outstanding request behind this flag.  Without this arm the peer
	 * only recovers via its 6s ACQUIRE_WAIT retry (tds pace collapse:
	 * 18/150 rounds).
	 */
	if ((ip->i_dlm_state == MXFS_DLM_ISTATE_BAST ||
	     (ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
	      ip->i_dlm_bast_pending)) &&
	    ip->i_dlm_ex_holders == 0 && ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_pin_count == 0) {
		/*
		 * only release if not pinned by a multi-step op.  If a
		 * pin is held (e.g. xfs_create mid-sequence), leave state=BAST;
		 * mxfs_inode_unpin will fire the release when the pin drains.
		 */
		/*
		 * PROVEN BY INSTRUMENT storm engine (P70-BP qsrc=1
		 * bpend=1 ×5991 on t2, run 21:53:54Z; 11,445-cycle
		 * ino-131 PR revoke storm, ZERO real BASTs P7S=P7B=0):
		 * i_dlm_bast_pending had NO consumer on this path — the
		 * dwork protocol assumes the dwork is the SOLE bpend releaser
		 * and only IT clears the flag, while this v3 CACHED&&bpend
		 * arm ALSO releases on it but left it set.  A bpend whose
		 * release completed via any work-channel path (seed: an MHT
		 * batch_arm racing a stale-only self-BAST release) then refired
		 * a full DLM release+reacquire after EVERY subsequent use — the
		 * dlm_scaling rate-floor storm (<50 ops/s vs peers' 212, ~5
		 * walks/op each paying a TCP DLM round-trip + dir-block
		 * invalidation).  CONSUME the flag when this gate commits to
		 * the release: the obligation is discharged by the release
		 * itself.  The abort paths (P15 gen-moved) re-SET it after
		 * aborting, so a truly still-owed BAST re-arms; a stray flag
		 * now costs at most ONE extra release instead of a storm.
		 */
		/*
		 * SF-DIR TENURE FLOOR: for a young shortform
		 * dir EX tenure (held < dir_sf_mht_ms), do NOT hand off at
		 * this idle boundary — the caller's next syscall (mv/rm of
		 * the same round) re-enters in ~2-5ms and would pay a full
		 * ~20ms cross-node handoff.  Leave bast_pending set and let
		 * the MHT dwork serve the peer at window expiry.  Only the
		 * CACHED&&bpend arm is floored; state==BAST means the MHT
		 * window already elapsed at BAST-notify time.
		 */
		/*
		 * DIR-EX TENURE FLOOR: the floor
		 * below covered only CACHED&&bpend on SHORTFORM dirs; a mid-op
		 * BAST (bast_notify's busy-holder park, state==BAST) was honored
		 * HERE unconditionally at op end = one dir op per cluster EX
		 * rotation under continuous contention (the crash_consistency@32
		 * write-phase collapse: 107 EX releases for 100 creates on
		 * test1).  Floor BOTH arms with mxfs_dlm_dir_tenure_keep_delay
		 * (all dir formats; window = inode_mht_ms, shortform keeps
		 * dir_sf_mht_ms).  A kept state==BAST tenure reverts to
		 * CACHED&&bast_pending so our own queued ops keep fast-pathing;
		 * the armed dwork honors the peer at window expiry (same
		 * protocol the /floors already use).
		 */
		sf_keep_j = mxfs_dlm_dir_tenure_keep_delay(ip);
		if (sf_keep_j &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_BAST) {
			if (!ip->i_dlm_bast_pending)
				ip->i_dlm_dwork_strikes = 0;	/* v0.10.31 */
			ip->i_dlm_bast_pending = true;
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		}
		if (!sf_keep_j) {
			ip->i_dlm_bast_pending = false;
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			need_flush = true;
		}
	}

	/*
	 * v0.10.37 idle-PR reaper: this unlock left a REGULAR file's PR grant
	 * CACHED with zero local holders and no BAST owed.  Arm the release
	 * dwork with a short idle window so the grant self-demotes instead of
	 * lingering until a peer BAST-strips it.  PROVEN cost of lingering:
	 * dir_reuse@32 verify stats every file on every node (PR per file per
	 * node, no open/close so close_release never fires); rank1's rm then
	 * pays BAST-strip of up to 31 holders per unlink whose unlock CAS ops
	 * serialize on the one slot LBA — 30-45ms per unlink, 140-190s of the
	 * 250s round.  With the reaper the stat-PRs evaporate ~idle_ms after
	 * verify and rm claims empty slots (~2-5ms per unlink).  Same dwork
	 * protocol as the MHT/stranded arms (dwork is the sole bpend
	 * consumer; re-arms while local holders are in flight, so a busy
	 * inode is never stripped mid-use — the arm only delays, never
	 * blocks, local ops).  PR ⇒ nothing local to drain; the release is
	 * the measured drain_ms=0 pipeline.
	 */
	{
		extern int mxfs_pr_idle_release_ms;

		if (mxfs_pr_idle_release_ms > 0 &&
		    !need_flush && !sf_keep_j &&
		    S_ISREG(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_state == MXFS_DLM_ISTATE_CACHED &&
		    ip->i_dlm_mode == MXFS_LOCK_PR &&
		    !ip->i_dlm_bast_pending &&
		    ip->i_dlm_ex_holders == 0 &&
		    ip->i_dlm_pr_holders == 0 &&
		    ip->i_dlm_pin_count == 0) {
			ip->i_dlm_bast_pending = true;
			ip->i_dlm_dwork_strikes = 0;
			idle_arm = true;
		}
	}

	spin_unlock(&ip->i_dlm_lock);

	if (idle_arm) {
		extern int mxfs_pr_idle_release_ms;

		/*
		 *  (PROVEN BY INSTRUMENT — BUG3 root cause): this
		 * function can run RE-ENTRANTLY from within ip's OWN synchronous
		 * eviction cascade (xfs_irele -> iput -> evict -> destroy_inode
		 * -> xfs_inactive -> xfs_attr_inactive -> xfs_iunlock -> here),
		 * in which case i_count is legitimately 0 and I_FREEING is
		 * already set. A raw ihold() (the old code) blindly resurrects
		 * the count (WARN_ON fires but does not stop it), arming a
		 * phantom deferred release that a LATER, independent work item
		 * then genuinely executes against an inode whose real teardown
		 * is already in flight — proven via direct struct-inode-pointer
		 * match (same RDI/RBX across 3 live crash stack traces) racing a
		 * concurrent user rm() of the SAME live file (do_unlinkat's own
		 * protective ihold/iput, crashing in iput()'s
		 * VFS_BUG_ON_INODE). igrab() safely refuses instead (checks
		 * I_FREEING/I_WILL_FREE atomically under i_lock) — same pattern
		 * already used by mxfs_dlm_ilock_begin and
		 * mxfs_dlm_sf_tenure_arm for this exact hazard class.
		 */
		if (igrab(VFS_I(ip))) {
			ip->i_dlm_bastq_src = 15;	/* pr_idle_release */
			if (!mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies((unsigned int) mxfs_pr_idle_release_ms)))
				xfs_irele(ip);	/* dwork already armed */
		} else {
			mxfs_probe_ratelimited("mxfs: P134-ILEND-FREEING ino=%llu site=idle_arm i_state=0x%lx (inode evicting; skipping idle-release arm — in-flight eviction owns teardown)\n",
				(unsigned long long)ip->i_ino,
				mxfs_istate(VFS_I(ip)));
		}
	}

	if (sf_keep_j)
		mxfs_dlm_sf_tenure_arm(ip, sf_keep_j);

	if (need_flush) {
		/*
		 * Approach A — defer bast_process to xfs_trans_free if a
		 * trans is active on this task.  current->journal_info is
		 * unused by upstream XFS; MXFS publishes the active trans
		 * there in __xfs_trans_alloc/dup/free so iunlock paths can
		 * find it without plumbing tp through every xfs_iunlock
		 * caller.  Hypothesis: bast_process firing while inode log
		 * items are still mid-trans / not yet in AIL lets a peer
		 * read pre-modification disk state (dir-stale Mode A,
		 * "Free inode N has blocks allocated").  See header
		 * comment for mxfs_inode_dlm_defer_bast.
		 *
		 * If no trans context, or alloc fails, fall through to the
		 * inline path — preserves existing behavior.
		 */
		struct xfs_trans *tp = current->journal_info;

		if (tp && mxfs_inode_dlm_defer_bast(tp, ip))
			return;

		/*
		 * (PROVEN BY INSTRUMENT — NFS-stream hung-task
		 * capture): the OLD inline path ran mxfs_dlm_bast_process HERE, in
		 * the caller's context.  But ilock_end is called from xfs_iunlock,
		 * and a readdir (xfs_dir2_leaf_getdents) is STILL HOLDING a dir DATA
		 * buffer locked at the iunlock point.  bast_process's release flush
		 * (mxfs_dir_flush_data_blocks_relsafe -> flush_one_daddr) then does a
		 * BLOCKING xfs_buf_lock on that same dir's data buffers — and
		 * self-deadlocks on the buffer the caller already holds (captured:
		 * `ls` + the mxfs-ino-bast kworker BOTH D-state in
		 * flush_one_daddr->xfs_buf_lock, 8/tcp dir_reuse MASS wedge).  This
		 * was latent before — masked because the flush walked a lock-free
		 * GARBAGE extent map that failed every get fast (the WARN flood) — and
		 * was exposed once that walk was made ILOCK-correct.
		 *
		 * Defer the release to the bast workqueue, which runs in a clean
		 * kworker context holding NO caller buffers (mxfs_dlm_bast_work_fn
		 * sets i_dlm_demoter = kworker itself, so the writeback re-entry skip
		 * is preserved; it owns the iget ref via xfs_irele).  state is already
		 * DEMOTING (set under i_dlm_lock above), which blocks a same-node
		 * re-acquire fast path, so no re-acquire can clobber it before the
		 * kworker runs — promptness is a sub-ms kworker dispatch.
		 */
		/*
		 *  (PROVEN BY INSTRUMENT — BUG3 root cause): same
		 * re-entrant-eviction hazard as the idle_arm branch above (see
		 * its comment) — this inline fallback also armed a phantom
		 * release via raw ihold() when reached from within ip's own
		 * synchronous eviction cascade. igrab() safely refuses instead.
		 */
		if (igrab(VFS_I(ip))) {
			ip->i_dlm_bastq_src = 1;
			if (!mxfs_bast_arm_queue(ip)) {
				mxfs_probe("mxfs: P76-QW-FALSE ino=%llu site=ilock-end — work already pending; DEMOTING set on top\n",
					(unsigned long long)ip->i_ino);
				xfs_irele(ip);	/* already queued — drop our extra ref */
			}
		} else {
			mxfs_probe_ratelimited("mxfs: P134-ILEND-FREEING ino=%llu site=need_flush i_state=0x%lx (inode evicting; release owned by in-flight eviction)\n",
				(unsigned long long)ip->i_ino,
				mxfs_istate(VFS_I(ip)));
		}
	}

	/*
	 *  — END THE RETENTION AT ITS OWNER, NOT BY SWEEP.
	 *
	 * The P152 trans-free punt returns holding this inode's demoter claim on
	 * purpose: the committing task still owns ILOCK across the punt, and the
	 * claim keeps it exempt through the punt's own iput and through the
	 * post-commit xfs_iunlock that brought us here.  THIS IS THAT UNLOCK —
	 * the exact end of the window the claim exists to cover — and we are the
	 * task that took it, so ending it here needs no grace period, no
	 * liveness heuristic and no foreign-clear: MXFS_CLEAR_DEMOTER releases
	 * only the caller's own slot.
	 *
	 * Measured why the sweep alone is not enough: with the reclaim ON, a
	 * claim still reached P214-DEMOTER-STRANDED at 1504 ms, because
	 * mxfs_demoter_punt_reclaim_check runs only from the two bast workers
	 * and the reload demote-wait, and nothing guarantees any of them is
	 * entered while the claim is outstanding.  Measured why it matters:
	 * P215-DEFER reported set=2 clear=0 retain=2 on four separate nodes —
	 * on those nodes EVERY deferral took the punt and the inline drain-clear
	 * never ran at all, so the retained path is the normal path, not an edge
	 * case.
	 *
	 * The sweep stays as the safety net for a task that never returns here
	 * (exit, oops, or an unlock that skips this path).
	 */
	if (unlikely(READ_ONCE(ip->i_dlm_demoter_punt)) &&
	    mxfs_demoter_punt_reclaim) {	/* 0 = pre-fix negative control */
		/*
		 * Consume EXACTLY as many retained acquisitions as the punt
		 * recorded.  One clear is not enough: the claim nests, and one
		 * transaction can defer the same inode twice
		 * (P130-DEFERBAST-DUP), so both entries can punt and each one
		 * incremented depth.  A single MXFS_CLEAR_DEMOTER would only
		 * decrement depth and leave the slot held — the same defect one
		 * nesting level down.  The loop terminates on its own: once the
		 * outermost level is released the slot is no longer ours.
		 */
		while (ip->i_dlm_punt_n[0] &&
		       READ_ONCE(ip->i_dlm_demoter) == current) {
			ip->i_dlm_punt_n[0]--;
			atomic64_inc(&mxfs_dem_punt_owner_clear);
			MXFS_CLEAR_DEMOTER(ip);
		}
		while (ip->i_dlm_punt_n[1] &&
		       READ_ONCE(ip->i_dlm_demoter2) == current) {
			ip->i_dlm_punt_n[1]--;
			atomic64_inc(&mxfs_dem_punt_owner_clear);
			MXFS_CLEAR_DEMOTER(ip);
		}
		/*
		 * If a slot is no longer ours, some other path already released
		 * it; drop the residual bookkeeping so the mask cannot go stale
		 * and be mistaken for a live retention by the sweep.
		 */
		if (READ_ONCE(ip->i_dlm_demoter) != current)
			ip->i_dlm_punt_n[0] = 0;
		if (READ_ONCE(ip->i_dlm_demoter2) != current)
			ip->i_dlm_punt_n[1] = 0;
		WRITE_ONCE(ip->i_dlm_demoter_punt,
			   (ip->i_dlm_punt_n[0] ? 1 : 0) |
			   (ip->i_dlm_punt_n[1] ? 2 : 0));
	}
}

/*
 * Non-blocking lock for xfs_ilock_nowait.
 * Returns true if lock acquired, false if unavailable.
 */
bool
mxfs_dlm_ilock_try(
	struct xfs_inode	*ip,
	uint8_t			mode)
{
	struct mxfs_v5_dlm	*dlm;
	int			ret;

	dlm = ip->i_mount->m_mxfs_dlm;
	if (!dlm)
		return true;

	/*
	 * Bypass only where begin bypasses -- and since 0.87.16 begin bypasses
	 * on no membership state at all.  Every mount's begin takes real grants
	 * and counts holders (a sole survivor since 0.83.3, a never-multi
	 * mount since 0.87.16), and every caller of this try releases with
	 * xfs_iunlock, which runs the end — so returning true here without
	 * counting made every survivor's nowait IOLOCK an unpaired end.
	 * Measured: xfs_file_release's IOLOCK_EXCL trylock at each close(),
	 * 200 of 200 direct writes on a survivor (P71-SURVIVOR-UNPAIRED
	 * mode=EX, end_unpaired_single), consuming whatever EX count another
	 * task on the inode held.
	 */

	/* Reclaim path coordination ilock: see mxfs_dlm_ilock_begin comment. */
	if (unlikely(ip->i_ino == 0))
		return true;

	/*
	 * DLM lock acquire does CAW disk I/O which can sleep.
	 * If we're in atomic context (e.g., xfs_iget holds pag_ici_lock),
	 * skip the DLM — local locks provide sufficient protection.
	 *
	 * AUDIT: "sufficient protection" is only true for READS.
	 * This arm precedes every state check, so an atomic-context trylock
	 * is invisible to the release pipeline: no DEMOTING gate, no holder
	 * count (P15 blind), no tenure.  A path that acquires EX this way and
	 * then LOGS the inode commits with no cluster authority — candidate
	 * root for the flush->unlock recommit window (P228 hot-dir defers).
	 * DETECTION FIRST (instrumented): count + stamp; xfs_trans_log_inode
	 * reports any mutation under a live bypass (P230).  Fix decision
	 * (refuse EX here — callers fall back to blocking xfs_ilock) waits
	 * on this measurement + a design-consult consult.
	 */
	if (preempt_count() > 0) {
		static atomic_t p229_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&p229_n);

		if (n <= 200)
			mxfs_probe("mxfs: P229-ILOCK-TRY-ATOMIC-BYPASS ino=%llu mode=%u state=%u pcnt=%d comm=%s caller=%pS n=%d — DLM skipped in atomic context%s\n",
				(unsigned long long)ip->i_ino, mode,
				ip->i_dlm_state, preempt_count(),
				current->comm,
				__builtin_return_address(0), n,
				mode == MXFS_LOCK_EX ?
				"; EX REFUSED (no tenure possible here)" : "");
		/*
		 * an EX granted here would be an uncoordinated
		 * writer — no tenure, no DEMOTING gate, no holder count
		 * (the paired ilock_end decrement then eats a concurrent
		 * holder's count: P15 sees 0 with a live holder).  REFUSE;
		 * nowait callers fall back to blocking xfs_ilock in
		 * process context, which takes the full DLM path.
		 * Measured 0 firings on the 32-node producer workload, so
		 * this is invisible today and closes the latent hole.
		 * PR (read) keeps the bypass: local locks genuinely
		 * suffice for reading state we hold cached, and the read
		 * side takes no tenure the release pipeline must see.
		 */
		if (mode == MXFS_LOCK_EX)
			return false;
		WRITE_ONCE(ip->i_mxfs_atomic_bypass_ns, ktime_get_ns());
		return true;
	}

	spin_lock(&ip->i_dlm_lock);

	/* Can't proceed if BAST flush in progress */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING) {
		spin_unlock(&ip->i_dlm_lock);
		return false;
	}

	/*
	 * If the inode is stale (needs reload from disk), reject the
	 * trylock.  The caller will fall back to xfs_ilock() which
	 * calls mxfs_dlm_ilock_begin() — that path handles the
	 * reload.  We cannot reload here because it sleeps and
	 * trylock callers may not expect blocking I/O.
	 */
	if (ip->i_dlm_stale) {
		spin_unlock(&ip->i_dlm_lock);
		return false;
	}

	/*
	 * v0.3.121: dir-strict for ilock_try too.  ilock_BEGIN
	 * has a dir-strict check (state != CACHED → fall through to
	 * slow-path).  ilock_TRY didn't.  P64 trace at iter-2 fail
	 * showed T2 had only 1 P6 reload across 2 P55 releases — meaning
	 * T2 acquired dir 128 multiple times via a path that bypassed
	 * reload.  ilock_try fast path at state=BAST/NONE could have
	 * served stale-mem dir contents.  Gate on state==CACHED for
	 * dirs to force fallback to ilock_begin (which reloads).
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_dlm_state != MXFS_DLM_ISTATE_CACHED) {
		spin_unlock(&ip->i_dlm_lock);
		return false;
	}

	/* Fast path: cached at sufficient mode */
	if (ip->i_dlm_mode == MXFS_LOCK_EX ||
	    (ip->i_dlm_mode == MXFS_LOCK_PR && mode == MXFS_LOCK_PR)) {
		if (mode == MXFS_LOCK_EX) {
			ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "try-fast", 1, 0);
		} else {
			ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
			mxfs_p71_hold(ip, "try-fast", 0, 1);
		}
		/*
		 * P65-INSTR: log fast-path-try for dir inodes.
		 * Should be matched 1:1 with subsequent reload (none —
		 * ilock_try doesn't reload; caller may not need fresh
		 * disk content if state==CACHED holding our writes).
		 */
		if (S_ISDIR(VFS_I(ip)->i_mode))
			mxfs_idbg("mxfs: P65-INSTR ino=%llu ILOCK-TRY-DIR "
				"req_mode=%u cached_mode=%u state=%u "
				"realns=%llu\n",
				(unsigned long long)ip->i_ino,
				mode, ip->i_dlm_mode, ip->i_dlm_state,
				(unsigned long long)ktime_get_real_ns());
		spin_unlock(&ip->i_dlm_lock);
		atomic64_inc(&mxfs_dlm_stat_cache_hit);
		return true;
	}

	spin_unlock(&ip->i_dlm_lock);

	/* Slow path: try non-blocking DLM acquire */
	if (mxfs_iclus_routed(ip)) {
		/* ICLUSTER: admit only against an already-covering cluster
		 * grant (no disk I/O in a nowait path).  Bracket with
		 * acq_inflight so a concurrent release sweep cannot release
		 * the cluster between the admit and the mode-merge below;
		 * dropped in the merge block.  A refused admit falls back to
		 * the caller's blocking path (ilock_begin -> routed slow
		 * acquire). */
		bool admit;

		spin_lock(&ip->i_dlm_lock);
		ip->i_dlm_acq_inflight++;
		spin_unlock(&ip->i_dlm_lock);
		admit = mxfs_iclus_try_admit(ip->i_mount, ip->i_ino, mode);
		if (!admit) {
			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_acq_inflight)
				ip->i_dlm_acq_inflight--;
			spin_unlock(&ip->i_dlm_lock);
			return false;
		}
	} else {
		ret = mxfs_v5_dlm_inode_lock_try(dlm, ip->i_ino, mode, NULL);
		if (ret != 0)
			return false;
	}

	atomic64_inc(&mxfs_dlm_stat_cache_miss);

	xfs_iflags_clear(ip, MXFS_IF_ACQ_REFUSED);	/* 0.75.33 D-0915: granted */
	spin_lock(&ip->i_dlm_lock);
	if (mxfs_iclus_routed(ip)) {
		if (ip->i_dlm_acq_inflight)
			ip->i_dlm_acq_inflight--;	/* ICLUSTER admit bracket */
		ip->i_dlm_routed_iclus = true;	/* admit was cluster-backed */
	} else
		ip->i_dlm_routed_iclus = false;
	if (mode > ip->i_dlm_mode) {
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_mode = mode;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		/* (design review DLM-epoch guard): a real upgrade INTO EX is a
		 * fresh EX tenure -> snapshot a new epoch so any dirty state left
		 * from a previous tenure is detectable as stale at flush time. */
		if (mode == MXFS_LOCK_EX) {
			mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
			ip->i_mxfs_ex_grant_seq =
				atomic64_inc_return(&mxfs_ex_epoch);
			/* stamp fresh-EX acquire time for MHT batching */
			ip->i_dlm_ex_acquire_ns = ktime_get_ns();
			ip->i_dlm_tenure_ops = 0;
			ip->i_dlm_tenure_firstop_ns = 0;
		}
	}
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE)
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	if (mode == MXFS_LOCK_EX) {
		ip->i_dlm_ex_holders++; mxfs_exh_stamp_locked(ip); MXFS_DLMTR_H(ip);
		mxfs_p71_hold(ip, "try-slow", 1, 0);
	} else {
		ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
		mxfs_p71_hold(ip, "try-slow", 0, 1);
	}
	spin_unlock(&ip->i_dlm_lock);

	return true;
}

/*
 * IOLOCK demote (EX → SHARED). Adjust holder counts.
 * DLM lock stays at EX — no cost to hold a cached grant at higher mode.
 */
void
mxfs_dlm_ilock_demote(
	struct xfs_inode	*ip)
{
	struct mxfs_v5_dlm	*dlm;

	dlm = ip->i_mount->m_mxfs_dlm;
	if (!dlm)
		return;

	/*
	 * Skip only where begin skips -- and since 0.87.16 begin skips on no
	 * membership state at all.  A lone mount's begin counts holders like
	 * any member (a sole survivor since 0.83.3, a never-multi mount since
	 * 0.87.16), and the shared unlock after this demote ends PR — so
	 * returning here on "single-node" left one EX count per demote: 200 of
	 * 200 direct writes on a survivor were skipped here and each shared
	 * unlock's PR end then found no holder (end_unpaired_single=200).
	 * Every clustered direct write demotes since the D-0970 write-checks
	 * change, so the gate must match begin and end.
	 */
	if (mxfs_v5_dlm_is_single_node(dlm))
		atomic_inc(&mxfs_demote_survivor);	/* coverage: taken on a survivor */

	/* Reclaim path coordination ilock: see mxfs_dlm_ilock_begin comment. */
	if (unlikely(ip->i_ino == 0))
		return;

	spin_lock(&ip->i_dlm_lock);
	/* UNGUARDED dec — if this ever runs with ex==0 it
	 * wraps to ~4G and permanently poisons the re-fire conditions.
	 * Guard + shout instead (mirror of the ilock_end guard). */
	if (ip->i_dlm_ex_holders > 0) {
		ip->i_dlm_ex_holders--; MXFS_DLMTR_H(ip);
	} else {
		static atomic_t p71d_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p71d_n) <= 2000)
			mxfs_probe("mxfs: P71-UNDERFLOW ino=%llu mode=EX site=demote state=%u dlm_mode=%u comm=%s\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_state, ip->i_dlm_mode,
				current->comm);
	}
	ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
	mxfs_p71_hold(ip, "demote", -1, 1);
	spin_unlock(&ip->i_dlm_lock);
}

/*
 * v0.10.37 idle-PR reaper window (ms; 0 = off).  See the arm in
 * mxfs_dlm_ilock_end.  Covers the PR grants close_release cannot see:
 * lookup/stat-acquired PRs have no file open/close, yet they make every
 * node a holder that a later unlink must BAST-strip one-by-one.
 */
int mxfs_pr_idle_release_ms;
module_param_named(pr_idle_release_ms, mxfs_pr_idle_release_ms, int, 0644);
MODULE_PARM_DESC(pr_idle_release_ms,
                 "Self-demote a REGULAR file's idle PR DLM grant this many "
                 "ms after its last local use (default 0 = keep until "
                 "BAST).  REFUTED at 32 nodes as a default: per-stat timer "
                 "releases storm the slot table DURING the read phase "
                 "(verify 66->416s, PR acquires 2.5-5s, one node starved "
                 "to rc=-110 shutdown).  Kept as an A/B lever only.");

/* 32-node cache_coherency shared-dir reload-storm gate. */
module_param_named(dir_slow_handoff_gate, mxfs_dir_slow_handoff_gate, int, 0644);
MODULE_PARM_DESC(dir_slow_handoff_gate,
                 "Skip the slow-path fresh-grant dir reload when there was no "
                 "genuine cross-node EX handoff since our last adopt (no peer "
                 "modified the dir -> cached image authoritative); 0=off default");

/* 0.84.18 (D-0963 harness): the lever, exposed so a harness can make
 * every cached-EX shortform RMW take the platter refresh (the path the
 * stale-gen gate takes on its own only after a peer tenure and a skipped
 * rebuild).  0=in-core authoritative on the fast path (default). */
module_param_named(sf_fastpath_adopt, mxfs_sf_fastpath_adopt, int, 0644);
MODULE_PARM_DESC(sf_fastpath_adopt,
                 "Refresh a shared shortform dir against the platter on EVERY cached-EX fast path, not only when stale-gen (0=off default)");

/*
 * v0.3.147 deadlock-stall threshold for AG bast_work_fn's
 * AIL drain.  Default 600 ≈ 6s at 10ms poll.  If the per-AG AIL
 * items can't drain (xfsaild's iop_push trylock fails because the
 * inode's ILOCK is held by a process blocked in this node's own
 * AG-DLM CAW poll waiting for the peer), abort the bast_work_fn
 * WITHOUT releasing.  Set 0 to disable the abort (unbounded legacy
 * behavior, vulnerable to lock-inversion deadlock).
 */
int mxfs_ag_bast_stall_iters = 600;
EXPORT_SYMBOL(mxfs_ag_bast_stall_iters);
module_param_named(ag_bast_stall_iters, mxfs_ag_bast_stall_iters, int, 0644);
MODULE_PARM_DESC(ag_bast_stall_iters,
                 "AG bast_work_fn AIL drain stall-abort threshold "
                 "(iterations of 10ms each without items leaving the AG). "
                 "Default 600 (~6s).  Aborts release on stall to break "
                 "lock-inversion deadlock with peer's CAW poll.  Set 0 "
                 "to disable (unbounded legacy, vulnerable to deadlock).");
