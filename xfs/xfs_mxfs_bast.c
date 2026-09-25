// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode BAST processing and notification
 */
#define MXFS_TU_ID 17	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

static void mxfs_iclus_pi_reconcile(struct xfs_inode *ip, int clus_rc);

/*
 * Cluster-wide EXPOSURE counters for the two-slot claim.
 *
 * The per-inode ring above is forensics for a wedge that already happened; it
 * cannot answer "did the fix path actually run?".  That question has to be
 * answered separately, because the failure mode is a fix that is verified only
 * by the ABSENCE of a symptom — and an absent symptom is equally consistent
 * with the workload never having built the race at all.  (Exactly that trap
 * cost three sessions on D-BAST-WRITEBACK-ABBA-DEADLOCK: "200/200 collisions"
 * was measured against the wrong flush site, so the real site had zero
 * exposure and the fix looked verified while doing nothing.)
 *
 *   slot2 > 0   proves a SECOND concurrent drain on one inode was admitted and
 *               kept its demote-wait exemption — the state that used to strand
 *               the first drain's trailing xfs_irele forever.
 *   contest > 0 means a THIRD concurrent drain was refused a slot, i.e. two
 *               slots are not enough and the wedge is still reachable.
 *   foreign_clear > 0 is a non-owner clear reaching a slot that a DIFFERENT
 *               task currently owns: the exact event that produced the wedge.
 *               It must be zero.
 *
 * clear_noclaim is deliberately a SEPARATE counter, not folded into
 * foreign_clear.  The inode DLM-state initializer calls MXFS_CLEAR_DEMOTER as a
 * plain field reset on an inode nobody is draining, which is a non-owner clear
 * by the letter of the macro but cannot strand anyone.  Measured at ~62 per
 * node per run with both slot pids zero at every single occurrence.  Folding
 * the two together produced a permanently nonzero "MUST be 0" counter — a
 * standing false alarm pointing at a non-defect.
 */
atomic64_t mxfs_dem_slot1;	/* fresh claims of slot 1 */
atomic64_t mxfs_dem_slot1_nest;	/* re-entrant claims by slot 1's owner */
atomic64_t mxfs_dem_slot2;	/* fresh claims of slot 2  <-- EXPOSURE */
atomic64_t mxfs_dem_slot2_nest;	/* re-entrant claims by slot 2's owner */
atomic64_t mxfs_dem_contest;	/* 3rd concurrent drain, refused */
atomic64_t mxfs_dem_foreign_clear; /* clear while ANOTHER task owns a slot */
atomic64_t mxfs_dem_clear_noclaim; /* clear with both slots empty (benign reset) */

atomic64_t mxfs_dem_legacy_steal;      /* legacy store overwrote a LIVE foreign claim */
atomic64_t mxfs_dem_legacy_clear_live; /* legacy clear NULLed another task's live slot */

/* PACE: skip the two release-path blkdev flushes for a
 * PROVABLY-CLEAN regular file (inode item clean, not in AIL, unpinned, no
 * dirty/writeback pages).  P138 stage split proved a clean file EX release
 * costs 13.3ms avg, of which 9.2ms = the stage-b coalesced device flush and
 * 2.8ms = the unconditional reg_durable_done flush — with NOTHING new to
 * make durable (run51/52: the rm phase is 800 such pulls = 10.6s of the
 * 25.6s round).  A clean inode's dinode+data already match the backing
 * store; peers read through the same target cache, and crash-durability of
 * long-completed writeback is the same guarantee as local XFS without
 * fsync.  The P15 holders re-check aborts any release that raced a local
 * re-acquire, so the predicate cannot go stale across a completed handoff. */
int mxfs_reg_clean_release_fast = 1;
module_param_named(reg_clean_release_fast, mxfs_reg_clean_release_fast, int, 0644);
MODULE_PARM_DESC(reg_clean_release_fast,
	"Skip release-path device flushes for provably-clean regular files (default 1)");

/* (D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO) instrumented build-1 fault
 * injection, arm 2 of 2: park bast_process right AFTER the terminal NL
 * store, prolonging the natural {mode=NL, DEMOTING, RELFLUSH-set} tail
 * the opener's admission re-read can land in.  With the ride injection
 * above widening the opener side and this park widening the release
 * side, the sess238-hypothesized interleave (relflush-admit arm at the
 * ilock ride + NL at the re-read) becomes deterministic.  No spinlock
 * held across the park.  Default 0 = off; test-only, capped 5000ms. */
int mxfs_openprotect_park_ms = 0;
module_param_named(openprotect_park_ms, mxfs_openprotect_park_ms, int, 0644);
MODULE_PARM_DESC(openprotect_park_ms,
	"Fault injection: ms to park bast_process after the terminal NL store, before the release flush tail (default 0 = off, cap 5000)");
/* D-0974: regular-file EX releases whose btree extent tree needed the release
 * loop's flush before the unlock, and releases that could not make it
 * durable and shut down instead. */
atomic_t mxfs_reg_bmbt_rel_flushed = ATOMIC_INIT(0);
atomic_t mxfs_reg_bmbt_rel_wedge = ATOMIC_INIT(0);
/*
 * (chain 116 v2 holderfail, D-0537): the SB summary key has NO
 * in-core inode, so a peer's BAST for it took __mxfs_dlm_bast_notify's
 * "inode not in cache — release the orphan lock" arm and the no-inode work
 * UNLOCKED it from under the live put_super holder (Y's LOCK epoch=2 in
 * 255 ms while X was parked inside its critical section at epoch=1 for a
 * 60 s hold).  The key is locked from exactly one place (put_super's
 * mxfs_sb_summary_final_sync) and m_mxfs_sb_lock_held brackets that window,
 * so a BAST that arrives while it is set names a LIVE holder: refuse the
 * release and let the peer keep waiting on its own bounded CAW poll.
 * 0 = measure only (P-SB-SUMMARY-BAST still prints; the release proceeds —
 * the instrumented proof lap), 1 = refuse (default).
 */
int mxfs_sb_summary_bast_refuse = 1;
module_param_named(sb_summary_bast_refuse, mxfs_sb_summary_bast_refuse, int, 0644);
MODULE_PARM_DESC(sb_summary_bast_refuse,
	"BAST for the SB summary key while this node's put_super holds it: 0=release as an orphan (measure only), 1=refuse the release, the peer waits (default 1)");
atomic64_t mxfs_sb_summary_bast_seen = ATOMIC64_INIT(0);
atomic64_t mxfs_sb_summary_bast_refused = ATOMIC64_INIT(0);

int mxfs_caw_orphan_reclaim = 1;	/* default ON with GATE
				 * v2 at the reclaim site — v1 regressed by
				 * strikes-overriding LIVE demoters (trans-deferred
				 * releases); v2 never overrides a demoter and also
				 * requires the MHT dwork idle + persistence.  OFF
				 * left the measured phantom (P72-SWALLOW-DEAD,
				 * DEMOTING+NL+bit-set, zero live release paths)
				 * wedging all 8 nodes for 330s on dir 6291585. */
module_param_named(caw_orphan_reclaim, mxfs_caw_orphan_reclaim, int, 0644);
MODULE_PARM_DESC(caw_orphan_reclaim,
		 "Force-clear a stuck-DEMOTING orphaned CAW holder bit at BAST "
		 "(dir_reuse@32 wedge recovery) (1=on default, 0=off)");

int mxfs_dir_release_stale;	/* GFS2 demote-invalidate — default OFF (fired
				 * but did NOT fix the loss; the stale buffer re-enters
				 * cache+AIL during the next tenure.  Kept as a modarg.
				 * The effective fix is the write-side zombie-BLI retire
				 * (dir_reflush_skip).  design review: acquire-side is better
				 * than release-side here). */
module_param_named(dir_release_stale, mxfs_dir_release_stale, int, 0644);
MODULE_PARM_DESC(dir_release_stale,
		 "At EX release, hard-stale (drop from cache) a directory's "
		 "clean+durable data/leaf blocks so no stale buffer survives "
		 "the handoff to be reflushed (GFS2 demote-invalidate); fixes "
		 "the dir_reuse stale-reflush durable dirent loss "
		 "(1=on default, 0=off)");

/*
 * (design review WRITEBACK-COMPLETION-BARRIER) — DEFAULT ON.
 * The architectural fix for the dir_reuse readdir=799 durable single-dirent
 * loss (the residual that survived the membership split-brain fix).
 * ROOT (PROVEN instrumented + design review): a dir DATA/leaf write bio THIS node submitted
 * in a tenure can complete AFTER it released the dir EX and a peer cold-read +
 * RMW'd + rewrote that block — the late bio lands an older image, durably
 * reverting the peer's committed dirent.  The submit-time disk-superset
 * detector and the release-time disk==incore probe are BOTH blind to it (the
 * stale write is harmless at submit/sample but clobbers at COMPLETION).  Fix =
 * the canonical clustered-FS invariant (GFS2 glock / OCFS2 / CXFS token): the
 * EX tenure owns the writeback LIFETIME.  At EX release, after the existing
 * durability drain, BLOCK the handoff until every in-flight dir-metadata write
 * bio (mp->m_mxfs_dir_wr_inflight, inc at xfs_buf_submit_bio, dec at
 * __xfs_buf_ioend) has physically completed.  This does NOT drop/suppress any
 * write (the refuted approaches did, causing leaf corruption / bnobt
 * double-free / AIL hangs) — it only DELAYS the lock handoff until I/O quiesce.
 */
int mxfs_dir_wr_barrier = 1;	/* was DEFAULT 0 — refuted then because
				 * m_mxfs_dir_wr_inflight was always 0 at release (dir blocks
				 * publish synchronously), kept "if an async dir-write path
				 * ever appears".  (46efd8b6, run 110411Z): that path
				 * exists — bmbt-leaf writes are xfsaild-ASYNC plain bios on
				 * multipath (SCSI FUA passthrough EOPNOTSUPP) and are now
				 * counted; an in-flight committed leaf bio crossing the EX
				 * handoff manufactured the peer-side stale-iext i!=1
				 * shutdown.  DEFAULT 1. */
module_param_named(dir_wr_barrier, mxfs_dir_wr_barrier, int, 0644);
MODULE_PARM_DESC(dir_wr_barrier,
		 "At dir EX release, wait for all in-flight dir-metadata write "
		 "bios to physically complete before handing the lock to a peer "
		 "so no prior-tenure stale dir-block write can land after the "
		 "next holder begins (fixes dir_reuse readdir=799; 1=on, 0=off)");

/*
 * EAGER evict-on-BAST.  PROVEN this session: the acquire/read-
 * side prior-tenure invalidation (epoch/gen-gated) is structurally racy and
 * under-fires, so a re-acquiring node keeps a STALE cached dir DATA base and
 * RMW-clobbers a peer's durable entry (the 8-node dir_reuse residual).  The
 * RELIABLE fix is on the LOSING side: when THIS node is BAST'd off the dir EX
 * (a peer is about to modify the dir), after the release fence has drained our
 * dir blocks DURABLE (Inv 1, so they are clean/non-AIL/non-pinned), EAGERLY
 * evict every clean cached dir DATA block.  Then this node has NOTHING stale
 * cached, so its NEXT re-acquire cold-FUA-reads the peer's current image as the
 * RMW base — no epoch/gen gate to under-fire, no acquire-side TOCTOU.  Runs only
 * on a real cross-node BAST release (the peer WILL modify), so no perf cost on
 * the uncontended/single-node path.  Default 0 for A/B; keeper inert.
 */
int mxfs_dir_bast_evict;
module_param_named(dir_bast_evict, mxfs_dir_bast_evict, int, 0644);
MODULE_PARM_DESC(dir_bast_evict,
	"on a cross-node BAST release of a dir EX, eagerly evict clean cached dir DATA blocks (post-drain) so the next re-acquire cold-reads coherent — the reliable release-side sibling of the racy acquire-side invalidation; 1=on");

/* D2: the per-dirop synchronous parent-durability
 * barrier (mxfs_dlm_dir_inode_durable at create/remove/rename) costs
 * ~1.2ms×2 per op FOREVER once a dir has any peer-contact history
 * (A/B-proven 7.6× collapse: 0.36 → 2.74 ms/op after one peer ls).  This
 * lever lets the barrier be disabled at runtime to measure whether the
 * demote-drain flush + destage_kick now cover the visibility/lost-update
 * cases it was added for (sess13-4eef uv root, 16-node SF add loss).
 * Default 1 = legacy synchronous barrier. */
/* D3 ROOT FIX: refuse to publish a DIRECTORY inode
 * slot from our cached cluster buffer once the grant is released (NL), even
 * when the slot was logged/buf-dirtied under our prior tenure.  PROVEN
 * byte-exact (cache_coherency cv 18:39:39): test5's 3-name image written at
 * mode=0 reverted the platter from test27's 7 names, permanently erasing 4
 * peers' files.  Default ON. */
/* (D5): bound on mxfs_dlm_reload_inode's down_write_trylock spin.
 * Was a hard-coded 1000 (~3.5 ms of cond_resched yielding) per bail; with
 * 100k+ bails per 32-node chain lap that is ~350 CPU-seconds of pure waste,
 * and a long reader (readdir) never releases inside any affordable spin. */
/* (D3 acquire-side): force the cached-EX fast path to rebuild a
 * shortform dir fork from disk when i_dlm_dir_gen > i_dlm_dir_loaded_gen
 * (proof that peer modifications exist which our fork never saw).  Without
 * it the tenure RMWs a stale base and its authorized release-drain publish
 * durably erases the peers' entries (P56-DIRWRITE dgen=8 lgen=5). */
/* D3 residual — publication-obligation ENFORCEMENT
 * (wiring step 3; design at xfs_inode.h i_mxfs_pub_pending_seq, evidence in
 * ccmemory sess14-K).  When set, the release drain refuses to report success
 * while a committed inode-core change is unlanded: it routes into the P146V
 * re-log arm so the normal machinery submits it, retries, and only reports
 * flushed=true once the write is confirmed.  Measured need: P176 fired 116×
 * across 6 nodes in a single PASSING cache_coherency run — the unsafe
 * release is pervasive, not rare.
 *
 * that 116x figure was measured with BROKEN discharge
 * wiring (durable advanced only at the drain's own bwrite, so every inode
 * landed by xfsaild/reclaim read "open" forever).  The discharge now happens
 * at the real write completion for all flush paths (xfs_iflush_finish), which
 * changes what this predicate MEANS — so the default drops back to 0 and the
 * corrected P176 rate gets re-measured before enforcement is switched on
 * (instrumented: measure, then enforce).  Runtime-writable for the A/B. */
/* (design review design-consult consult #2, 2b): DEFAULT ON.  The re-log-under-
 * current-tenure arm is the principled convergence mechanism for a
 * committed change whose copy-in was (or will be) condemned by the merge
 * mask — re-stamping provenance through the journal, crash-consistent.
 * This is the partner of the blind-close fix set: the P236 pre-NL
 * gate defers the release while pend != durable, and THIS arm is what
 * lands the stranded change so the deferred release converges.  The
 * re-measurement happened implicitly across sess33-34: with the
 * corrected discharge wiring, P176 fires only for genuinely-unlanded
 * changes (the 20260731 incident's exact class). */
int mxfs_pub_obligation_enforce = 1;
module_param_named(pub_obligation_enforce, mxfs_pub_obligation_enforce, int, 0644);
MODULE_PARM_DESC(pub_obligation_enforce,
                 "Release drain must land committed inode-core changes before "
                 "reporting success: 1=enforce (re-log + retry, default), "
                 "0=measure-only/legacy silent release");

/*
 *  a864 — WALL-CLOCK orphan-strand force deadline (ms).  When a
 * bast_process release enters the orphan-live shape (in-core mode==NL with a
 * live grant token) and stays there CONTINUOUSLY for this long, force the
 * stranded release even though the CAW grant_seq keeps churning (which defeats
 * the same-gen 280-strike escape — PROVEN: 0 P15H fired in 1748 stuck-waits,
 * one node held the shared dir EX idle for 119s).  A genuine mid-completion
 * grant resumes (mode->EX) in microseconds on CAW, so seconds of continuous
 * mode==NL is unambiguously a strand; the value sits far above any legitimate
 * MHT tenure (inode_mht_ms=300) and post-drain unlock window, and far below the
 * 120s barrier.  The gen-aware unlock still refuses (-ESTALE, re-queue) if a
 * real re-grant landed, so forcing is data-safe.
 */
int mxfs_caw_orphan_force_ms = 3000;
module_param_named(caw_orphan_force_ms, mxfs_caw_orphan_force_ms, int, 0644);

/* TCP abandoned-mirror-grant escape.  Persistence
 * required (continuous orphan shape, acq_inflight==0, mode==NL) before the
 * serialized release proceeds on an unconsumed TCP mirror grant.  See the
 * P15-TCP-ORPH-PROCEED arm. */
int mxfs_tcp_orphan_force_ms = 500;
module_param_named(tcp_orphan_force_ms, mxfs_tcp_orphan_force_ms, int, 0644);

/* apply the MHT tenure floor to a BUSY dir-EX
 * tenure at the ilock_end deferred-BAST refire (state==BAST) and to
 * non-shortform dirs on the CACHED&&bpend arm — see
 * mxfs_dlm_dir_tenure_keep_delay.  0 = pre-sess1 one-op-per-tenure
 * handoff under continuous contention (A/B). */
int mxfs_dir_ex_tenure_floor = 1;
module_param_named(dir_ex_tenure_floor, mxfs_dir_ex_tenure_floor, int, 0644);
MODULE_PARM_DESC(dir_ex_tenure_floor,
	"floor a contended dir-EX tenure to the MHT window before honoring BASTs (op batching); 1=on");

/* SLIDING batch grace: the first floor cut (full
 * 300ms window per keep) let 31 waiters pile onto the hot slot during one
 * tenure — the resulting grant/abort churn tripped the pre-existing
 * orphan-live release-abort loop (P15-REL-ABORT orph=1 x27-52/node) and
 * ended in a STRANDED on-disk EX (slot gm=5, no in-core holder) that
 * starved the whole cluster on .cache_coherency's rename_visibility dir
 * (32x mode=5 rc=-110 waves).  Batching only needs to bridge the ~5-15ms
 * inter-op gap of a busy writer, not the whole MHT window: each op end
 * re-arms the dwork at min(grace, window-remaining), so back-to-back ops
 * keep the tenure (crash_consistency's 100-create bursts) while a
 * one-op-then-barrier phase (cv/uv) hands off within ~25ms and the waiter
 * queue stays shallow. */
int mxfs_dir_ex_batch_grace_ms = 10;	/* default 40→10: three same-day A/Bs at 32/caw dir_reuse show turn p50 81→50ms and +1 round (9 fresh vs 8), bash inter-op gap is 1.2-1.3ms so 10ms still batches consecutive local ops; identical sysfs finding was lost at module reload — hence the default change.  (History: A/B at cc@32 quiet-age gate: 25=68s, 40=61s/56s PASS, 60=78s — that gate has since been reworked; 326-board cc=38s at 40, re-verified green at 10 on the 327 protective board.) */
module_param_named(dir_ex_batch_grace_ms, mxfs_dir_ex_batch_grace_ms, int, 0644);
MODULE_PARM_DESC(dir_ex_batch_grace_ms,
	"sliding per-op grace (ms) a contended dir-EX tenure stays held awaiting the holder's next op");

/*
 * cheap clean/PR-release bounce.  PROVEN ROOT of the
 * tcp_dlm_scaling residual (live dmesg): a hot shared dir under symmetric 2-node
 * create/rename/unlink churn livelocks on the PR->EX upgrade — both nodes cache
 * PR (from bash open(O_CREAT)'s lookup half), both want EX (create half), the
 * master denies the upgrade (-EDEADLK, dlm.c:2574), and the loser drops PR->NL
 * through the FULL bast_process drain pipeline (mxfs_dlm_dir_inode_durable ->
 * mxfs_inode_cluster_durable: log_force SYNC + iflush + blkdev_flush) before
 * re-requesting.  But a PR holder is READ-ONLY: it cannot have dirtied the dir,
 * so that ~hundreds-of-ms durability flush on a CLEAN/PR release is pure waste
 * that amplifies the livelock to ~440ms/op (>60s window blown).
 *
 * When set, skip the release-side durability flush when the inode is PROVABLY
 * clean (held mode != EX AND xfs_inode_clean AND not in the AIL AND unpinned) —
 * nothing this node committed is awaiting destage.  This CANNOT regress the
 * sess-tcp dirent-resurrection fix (that path requires a DIRTY / in-AIL dinode,
 * excluded here).
 *
 * SCOPE (the clean release's log_force is ALSO an incidental coherency-
 * masking barrier the dir-heavy tests rely on, so skipping it on EVERY clean
 * release exposed dir_reuse/rsync_paired stale-block RMW):
 *   0 = always drain (old behavior).
 *   1 = skip a clean release that is EITHER a SELF-demote (P109 EDEADLK
 *       upgrade-recovery; no peer reads our state) OR a SHORTFORM dir (dirents
 *       inline in the inode → no separate data/leaf blocks to mask) — kills the
 *       tcp_dlm_scaling upgrade-livelock amplifier while KEEPING the drain on
 *       BLOCK/LEAF-dir peer handoffs (dir_reuse/rsync_paired masking).  DEFAULT.
 *   2 = skip on EVERY clean release (broad; fastest but removes the masking).
 */
int mxfs_dir_pr_release_fast = 1;
module_param_named(dir_pr_release_fast, mxfs_dir_pr_release_fast, int, 0644);

/*
 * (design review consult): the dir EX-release fence's
 * xfs_ail_push_ag_sync(d_agno) drains only the dir INODE's AG.  A grown dir's
 * DATA/leaf blocks are scattered across OTHER AGs (agcount=50, 800-entry fill),
 * so a committed-but-not-home-written dir DATA block sitting in the AIL in a
 * DIFFERENT AG than the inode is NOT drained by the per-AG push, and the
 * extent-map walk (mxfs_dir_flush_data_blocks_relsafe) MISSES it if it left the
 * in-core map (freed/converted mid-tenure).  PROVEN root (name-level
 * offset trace): that escaped block is the node's own in-AIL UNDESTAGED base
 * that, on the peer's next tenure, gets cold-read STALE → intra-block freespace
 * double-allocation (4 nodes wrote distinct dirents at the same byte offset).
 *
 * When set, the release fence ALSO pushes the WHOLE AIL to completion (bounded,
 * ms) so EVERY dir block this tenure committed — in ANY AG, on or off the
 * current extent map — is home-written before the on-disk DLM unlock.  This is
 * design review's "DLM EX unlock is a metadata home-block visibility fence" invariant.
 * Runs on system_wq / holder process ctx (NOT the CAW poll thread) with i_lock
 * dropped, so blocking is safe; bounded so a wedged AIL can't hang the node
 * (the existing data_durable re-check + ~15s shutdown backstop keeps Inv 1).
 * Default 0 (A/B); value = bound in ms (0 = off).
 */
int mxfs_dir_release_ail_all;	/* default 0.  PROVEN this session NOT
				 * the fix — a whole-AIL push-to-completion before
				 * unlock still loses an entry (release durability is
				 * NOT the gap; bug is acquire-side/concurrency).  Infra
				 * kept (kill-switchable; value = bound ms) for the
				 * next session to combine with an acquire-side fix. */
module_param_named(dir_release_ail_all, mxfs_dir_release_ail_all, int, 0644);
MODULE_PARM_DESC(dir_release_ail_all,
	"dir EX release: also push the WHOLE AIL to completion (bounded ms) so dir blocks in OTHER AGs / off the extent map are home-written before DLM unlock; 0=off");

/*
 * D-0532 item (c): a reclaimable in-core inode still carrying a cached grant.
 * A peer's BAST for it is refused by xfs_iget(XFS_IGET_INCORE) and served by
 * the no-inode path, which releases the on-disk grant without touching the
 * corpse's in-core grant fields; the next local lookup recycles the corpse
 * and the fast path serves the cached mode.  Three exact counters: BASTs the
 * no-inode path served for an inode whose lifecycle class was RECLAIMABLE,
 * recycles that found i_dlm_mode != NL, and those where the DLM mirror said
 * the node no longer holds that mode (P-RECYCLE-PHANTOM).
 */
atomic_t mxfs_noino_bast_reclaimable = ATOMIC_INIT(0);

/* Releases committed while the inode had direct I/O in flight
 * (P-REL-DIO-INFLIGHT, detector only). */
/* D-0971 fix counters: releases that waited for the inode's direct I/O
 * before draining, the longest such wait, releases deferred at the terminal
 * guard, direct-write completions admitted during a drain, and polled
 * direct I/Os refused on a clustered mount. */
atomic_t mxfs_rel_dio_waited = ATOMIC_INIT(0);
atomic_t mxfs_rel_dio_wait_max_us = ATOMIC_INIT(0);
atomic_t mxfs_rel_dio_defer = ATOMIC_INIT(0);
/* A/B switch for the release-side barrier only (the pre-drain wait and the
 * terminal defer); 0 restores the release that committed over in-flight
 * direct I/O so the detector can reproduce the defect on this build.  The
 * completion admission and the polled-I/O refusal stay on either way. */
int mxfs_rel_dio_wait = 1;
module_param_named(rel_dio_wait, mxfs_rel_dio_wait, int, 0644);
MODULE_PARM_DESC(rel_dio_wait,
		 "wait for the inode's in-flight direct I/O before releasing its grant; 0=off (control: reproduces the release over in-flight I/O), 1=on (default)");
atomic_t mxfs_rel_dio_inflight = ATOMIC_INIT(0);

/*
 * D-RELEASE-BARRIER-OPEN enforcement lever (see the P228 block in the
 * anchored-unlock tail).  0 = measure only (P220-UNLOCK-LEDGER-OPEN counts);
 * 1 = close the ledger in place (durable re-pass ×2) and DEFER the wire
 * unlock (-ESTALE requeue) when it will not close.  DEFAULT ON since
 * 0.11.280: same-build A/B measured enforce=0 leaking 10-12 open-ledger
 * unlocks/lap vs enforce=1 zero, with 6/26551 (0.02%) bounded deferrals
 * concentrated on in-window recommits of shared base dirs, all laps + the
 * guard board green at unchanged walls (dd 65-66s, cache 28s, crash 69s,
 * dir_reuse 101s).
 */
int mxfs_relbar_enforce = 1;
module_param_named(relbar_enforce, mxfs_relbar_enforce, int, 0644);
/*
 * D-CRASH-COLDREAD-STALE-SPLIT FIX-2 — the PRE-NL
 * obligation gate.  The close_or_defer tails run AFTER the in-core NL
 * transition, so a deferred release retries as a cleanup flavor with no
 * publish authority; and the proven incident closed the ledger BLINDLY
 * between the NL transition and the tail (merge-erased staged image,
 * FIX-1).  Gate at the bast_process commit point instead, where the
 * tenure is still owned: a non-dir inode with pend != durable defers via
 * the existing abort machinery (CACHED + bast_pending + 25ms dwork), and
 * the re-fired pipeline's drain lands the change WITH authority.
 */
int mxfs_rel_obligation_gate = 1;
module_param_named(rel_obligation_gate, mxfs_rel_obligation_gate, int, 0644);
MODULE_PARM_DESC(rel_obligation_gate,
		 "Defer a non-dir inode DLM release while its publication "
		 "ledger is open (pending != durable) so an acknowledged "
		 "change can never be stranded unpublishable at NL "
		 "(D-CRASH-COLDREAD-STALE-SPLIT; 1=on, 0=off)");
MODULE_PARM_DESC(relbar_enforce,
                 "close the publication ledger before the wire unlock "
                 "(1=enforce default: durable re-pass + defer-on-open, "
                 "0=measure-only pre-fix control)");

void
mxfs_dlm_bast_process(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct inode		*vip = VFS_I(ip);
	/* P131-REL: decompose the per-handoff release cost (the
	 * zero_silent_loss storm spends ~100ms+ of EX tenure per single
	 * create; this measures how much of it is the drain pipeline). */
	u64			p131_t0 = ktime_get_ns();
	u64			p131_t1 = 0;
	/* P138 stage split: attribute the measured ~9-12ms
	 * holder-side cost of a CLEAN regular-file EX release (run51: 800
	 * rm-phase pulls × 13ms = the whole 10.6s rm wall) to its stages:
	 * a=first log_force+alloc-drain, b=settle+dir-flush+ail-drain+
	 * coalesced-flush, c=pagecache flush+invalidate, d=durable sections,
	 * u=DLM unlock+wire. */
	u64			p2s_a = 0, p2s_b = 0, p2s_c = 0, p2s_d = 0;
	u64			p2s_e = 0, p2s_f = 0;	/* su split — pre-unlock tail / wire unlock */
	u64			p2s_c1 = 0;	/* 0.75.51: stage c split — after filemap_write_and_wait */
	struct mxfs_drain_watch	p2_drain_watch;	/* 0.75.52: stage-c stall stack watchdog */
	/* provably-clean REG release (see mxfs_reg_clean_release_fast).
	 * Computed once after the unmount early-exit; any local re-acquire
	 * that would invalidate it is caught by the P15 holders re-check
	 * (release aborted).  p2_loop_wrote tracks whether the reg-durable
	 * loop actually bwrote a cluster buffer (then the tail flush must
	 * run regardless). */
	bool			p2_reg_clean = false;
	bool			p2_loop_wrote = false;
	u64			p2s_b1 = 0, p2s_b2 = 0;
	/* mode held at release entry (PR=read-only=clean; EX=may be dirty).
	 * Captured before line ~4744 clears i_dlm_mode to NL. */
	uint8_t			p_held_mode = ip->i_dlm_mode;
	/* identity of the EX tenure this pipeline is giving up,
	 * captured at the terminal store (release committed) for the
	 * clean-release marker published right before the unlock CAS.
	 * p_rel_epoch == 0 means nothing to certify (PR tenure, unpublished,
	 * cluster-routed, or no durable epoch). */
	uint64_t		p_rel_res = 0, p_rel_epoch = 0, p_rel_lineage = 0;
	bool			p_rel_marked = false;
	bool			p_clean_release = false;	/* set just before the durable flush */
	bool			p_shortform = false;
	bool			p_self_demote;
	uint32_t		p_rel_gen = 0;	/* tenure gen this release belongs to */
	bool			p_iclus_declined = false; /* routed release_check declined (covered active / busy) — the iclus fan_out protocol owns the retry; pipeline completes normally but must NOT clear the starvation-rescue clocks (that lie disarmed the ABBA escape; -ESTALE-stranding it instead retry-stormed 1000+/node) */
	int			p_open_op = 0; /* C1: open-holder bit op riding the release CAS (+1 publish, -1 clear, 0 none) */
	bool			p15h_reap = false;	/* this instance is a strand-reap — log wire state + unlock outcome */
	uint32_t		p_entry_gen = 0; /* tenure gen at bast ENTRY (pre-drain) */
	/* D-512 cycle-2 (ruling): drain site 1 return codes.  A failed
	 * drain must refuse the on-disk unlock — see the drain site and the
	 * abort gate. */
	int			rel_drain_wb_err = 0;
	int			rel_drain_inv_err = 0;
	/* D-0971: holders at entry, read under i_dlm_lock with admission
	 * already closed by the BAST state.  Zero means no local task can
	 * start another direct I/O, so the in-flight count can only fall. */
	unsigned int		p_entry_holders = 0;
	/* 0.75.49 (D-0922): publication sequence at drain entry, so the
	 * terminal obligation gate can tell a commit that arrived DURING this
	 * drain (a live local writer — re-run at once with the fast path
	 * closed) from an obligation that will not land (keep the backoff). */
	uint64_t		p_pend_entry = READ_ONCE(ip->i_mxfs_pub_pending_seq);
	/*
	 *  (P196) — CLASSIFY the release-barrier defect.
	 *
	 * P188 proved the barrier is open (pending != durable AT THE WIRE
	 * UNLOCK, 1-4 per storm run) while P176 — the drain's own
	 * silent-success exit — fires 0 times in the same runs.  Those two
	 * facts together mean the obligation is NOT one the drain declared
	 * away; it appeared, or survived, somewhere between the drain and the
	 * unlock.  Three mutually-exclusive causes need three different fixes,
	 * so name which one before building anything (instrumented):
	 *
	 *   NODRAIN  the drain block never ran for this inode at all
	 *            -> fix is the entry condition, not the barrier
	 *   REDIRTY  pending advanced AFTER the drain exited
	 *            -> a local op committed a change into a tenure that was
	 *               already being handed away.  Fix = step 1 of the
	 *               barrier: CLOSE the tenure to new mutations before
	 *               draining (a drain-to-zero that races a fresh commit
	 *               can never converge).
	 *   INFLIGHT flush_seq == pending: the image WAS copied into a cluster
	 *            buffer and submitted, the write just has not completed
	 *            -> fix = step 4: wait for completion before unlock.
	 *   UNCOPIED flush_seq < pending and pending unchanged since the drain
	 *            -> the drain returned with a committed change never even
	 *               copied into an outgoing image; fix = submit + retry
	 *               while STILL HOLDING the grant.
	 *
	 * Snapshot only; no I/O, no lock, nothing on the drain's latency path.
	 */
	u64			p196_dr_pending = 0;
	u64			p196_dr_durable = 0;
	u64			p196_dr_flush = 0;
	bool			p196_dr_ran = false;
	bool			p196_dr_flushed = false;

	/* read+clear the self-demote tag (set by the P109 EDEADLK
	 * recovery before it queued this work).  A self-demote drops our own
	 * cached PR->NL to re-request EX; no peer reads our state across it, so a
	 * clean drop can skip the durability drain (the upgrade-livelock
	 * amplifier) while genuine peer handoffs keep the coherency barrier. */
	/*
	 * — UNSERVICEABLE-BUT-BEATING FAULT (incident474 hole (c),
	 * D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474).
	 *
	 * That entry's hole (c) says the liveness oracle cannot tell "HB thread
	 * alive" from "filesystem serviceable": an arm-A victim wedged in AIL
	 * drain keeps beating its disklock HB, so v5_caw_holders_alive
	 * truthfully reports the holder alive and P-WAIT-EXTEND stretches
	 * survivors' waits toward the 480s liveness-extended cap on a lock
	 * whose holder is a dead filesystem.
	 *
	 * That shape could not be reproduced: inode-wedge injection
	 * makes the victim force-shutdown and WITHDRAW immediately, which stops
	 * the HB — measured, 31 survivors stayed mounted and the fleet logged
	 * ZERO P-WAIT-EXTEND.  So the premise needs its own switch: a node that
	 * holds a grant forever while remaining mounted and beating.
	 *
	 * Armed, the release drain for this inode never releases.  The node
	 * stays mounted, its HB thread keeps beating (the sleep is here, not in
	 * the HB thread), and peers requesting the inode must wait on a holder
	 * that will never hand off — exactly the hole (c) shape.
	 *
	 * INTERRUPTIBLE by construction: mxfs_pal_sleep_ms() is msleep(), which
	 * is TASK_UNINTERRUPTIBLE, and a long-lived kernel thread idling in it
	 * shows as a permanent D-state task — +1 to loadavg per node, forever,
	 * and indistinguishable from the wedged-in-I/O tasks the rig's
	 * readiness check exists to catch (shipped exactly that
	 * regression).  Disarming the knob releases the drain.
	 */
	{
		extern unsigned long long mxfs_hold_grant_fault_ino;

		if (unlikely(READ_ONCE(mxfs_hold_grant_fault_ino) ==
			     (unsigned long long)ip->i_ino)) {
			unsigned int hg_n = 0;

			pr_warn("mxfs: P384-HOLD-GRANT-FAULT ino=%llu mode=%u — INJECTED: holding the grant, refusing to release; node stays mounted and beating\n",
				(unsigned long long)ip->i_ino, ip->i_dlm_mode);
			while (READ_ONCE(mxfs_hold_grant_fault_ino) ==
			       (unsigned long long)ip->i_ino &&
			       !xfs_is_shutdown(mp)) {
				mxfs_pal_sleep_ms_interruptible(200);
				if (++hg_n % 50 == 0)
					mxfs_probe("mxfs: P384-HOLD-GRANT-FAULT ino=%llu held_s=%u — still holding\n",
						(unsigned long long)ip->i_ino,
						hg_n / 5);
			}
			mxfs_probe("mxfs: P384-HOLD-GRANT-FAULT ino=%llu — released after %u.%us\n",
				(unsigned long long)ip->i_ino,
				hg_n / 5, (hg_n % 5) * 2);
		}
	}

	spin_lock(&ip->i_dlm_lock);
	p_self_demote = ip->i_dlm_self_demote;
	ip->i_dlm_self_demote = false;
	p_entry_holders = ip->i_dlm_ex_holders + ip->i_dlm_pr_holders;
	spin_unlock(&ip->i_dlm_lock);

	/* FENCE-V1: stamp the caller's dir-drain bracket with the outgoing
	 * held mode — only an EX tenure's drain is a sanctioned sub-EX
	 * dir-block publisher (see the registry block above). */
	mxfs_dirdrain_set_mode(p_held_mode);

	/* P70 instrumented probe: run68 wedge — a bast_process
	 * instance set mode=NL then exited without the master unlock and
	 * without a visible print (P15/P6Z ratelimit-suppressed), leaving
	 * state=DEMOTING/BAST + a leaked ex_holder; every later BAST was
	 * swallowed by the notify DEMOTING arm -> phantom master EX ->
	 * 7-node convoy on the reused inum.  Tag ENTRY and EVERY exit so
	 * the next occurrence names the exit deterministically.  Capped. */
	{
		static atomic_t p70_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p70_n) <= 6000) {
			/* (D-503 ruling step 1) tenure decomposition:
			 * fo_ms = grant→first completed op (adoption/setup
			 * cost), lo_ms = last completed op→this release entry
			 * (idle tail).  With held_ms and tops, marginal per-op
			 * cost = (held_ms - fo_ms - lo_ms) / (tops - 1). */
			u64 p70_now = ktime_get_ns();
			u64 p70_fo = 0, p70_lo = 0;

			if (ip->i_dlm_ex_acquire_ns &&
			    ip->i_dlm_tenure_firstop_ns >
			    ip->i_dlm_ex_acquire_ns)
				p70_fo = (ip->i_dlm_tenure_firstop_ns -
					  ip->i_dlm_ex_acquire_ns) /
					 NSEC_PER_MSEC;
			if (ip->i_dlm_tenure_lastop_ns &&
			    ip->i_dlm_tenure_lastop_ns >
			    ip->i_dlm_ex_acquire_ns &&
			    p70_now > ip->i_dlm_tenure_lastop_ns)
				p70_lo = (p70_now -
					  ip->i_dlm_tenure_lastop_ns) /
					 NSEC_PER_MSEC;
			mxfs_probe("mxfs: P70-BP ino=%llu ENTRY mode=%u state=%u ex=%u pr=%u pin=%u selfdem=%d qsrc=%u bpend=%d held_ms=%llu tops=%u fo_ms=%llu lo_ms=%llu comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino, ip->i_dlm_mode,
				ip->i_dlm_state, ip->i_dlm_ex_holders,
				ip->i_dlm_pr_holders, ip->i_dlm_pin_count,
				p_self_demote ? 1 : 0,
				ip->i_dlm_bastq_src,
				ip->i_dlm_bast_pending ? 1 : 0,
				(unsigned long long)(ip->i_dlm_ex_acquire_ns ?
					(p70_now - ip->i_dlm_ex_acquire_ns)
						/ NSEC_PER_MSEC : 0),
				ip->i_dlm_tenure_ops,
				(unsigned long long)p70_fo,
				(unsigned long long)p70_lo,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/* v0.10.38: losing a held DIRECTORY to a peer's request marks the
	 * start of a mutation storm on that dir (a PR-held dir is only ever
	 * BAST'd by a writer; an EX-held dir is being taken over) —
	 * sweep-release this node's idle file PR grants so the writer's
	 * per-child EX claims find empty slots instead of BAST-stripping us
	 * one-by-one (see mxfs_dir_ex_bast_sweep).  v0.10.39: EX-held dirs
	 * included — after a node's own create wave it holds the dir EX
	 * (MHT-cached), so rm-start reaches most peers via an EX strip, and
	 * the PR-only trigger fired once per run instead of once per round.
	 * Rate-limited inside the trigger; a no-op when nothing is idle. */
	if ((p_held_mode == MXFS_LOCK_PR || p_held_mode == MXFS_LOCK_EX) &&
	    !p_self_demote && S_ISDIR(VFS_I(ip)->i_mode))
		mxfs_dlm_pr_sweep_trigger(ip->i_mount);

	/*
	 * — capture the tenure gen at ENTRY, before the drain.
	 * The P15 holders re-check below cannot see an UPGRADE grant that lands
	 * mid-drain whose waiter has not yet resumed (holders still 0): run
	 * 20260703T141319Z PROVEN — bast_process entered for the PR tenure,
	 * the pending EX (gen=98) was granted during the drain, the holders
	 * re-check passed, and the release unlocked the JUST-GRANTED EX
	 * (P51-REL held_mode=3 vs P6U-UNLOCK mode=EX gen=98).  The woken
	 * waiter then modified the dir on a phantom cached EX while the master
	 * granted gen=99 to a peer -> two writers allocated the SAME dirent
	 * slot (aoff=184) 1.8ms apart -> durable one-name loss
	 * (dir_reuse readdir=399/400 node4_f27.md5).  The gen comparison at
	 * the release decision aborts the release when the tenure advanced
	 * under the drain, exactly like the P15 holder abort.
	 */
	p_entry_gen = mp->m_mxfs_dlm ?
		mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm, ip->i_ino) : 0;

	/*
	 * UNMOUNT-TEARDOWN guard.  PROVEN crash —
	 * a queued bast_work_fn that runs after xfs_log_unmount has torn down
	 * the log NULL-derefs in the first xfs_log_force(mp,...) below:
	 *   struct xlog *log = mp->m_log;  (== NULL)
	 *   spin_lock(&log->l_icloglock);  -> fault at 0x10 (CR2=0x10,
	 *   RIP xfs_log_force+0x84, from mxfs_dlm_bast_process+0xef ->
	 *   mxfs_dlm_bast_work_fn).  This wedges the module at refcount -1
	 *   (observed during cache_coherency final teardown on test1).
	 * A flush to an unmounting/shutdown FS is pointless anyway: data
	 * cannot be written and the DLM is being torn down (which releases
	 * every CAW slot this node holds).  So skip the whole flush/drain
	 * path.  Still drop the per-inode DLM lock if the DLM is alive, mark
	 * the cached mode NL + state NONE, and wake any ilock_begin waiter.
	 */
	if (!mp->m_log || xfs_is_unmounting(mp)) {
		if (mp->m_mxfs_dlm) {
			spin_lock(&ip->i_dlm_lock);
			mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_NL;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
			spin_unlock(&ip->i_dlm_lock);
			/* ICLUSTER-routed files hold no per-inode slot; the
			 * cluster grant is released wholesale at dlm destroy
			 * (or by a later release_check sweep). */
			if (!ip->i_dlm_routed_iclus) {
				mxfs_inode_authority_check_published(ip,
								     MXFS_SITE);
				mxfs_v5_dlm_inode_unlock(mp->m_mxfs_dlm,
							 ip->i_ino);
			}
		} else {
			spin_lock(&ip->i_dlm_lock);
			mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_NL;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
			spin_unlock(&ip->i_dlm_lock);
		}
		spin_lock(&ip->i_dlm_lock);
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		spin_unlock(&ip->i_dlm_lock);
		wake_up_all(&ip->i_dlm_wait);
		mxfs_probe("mxfs: P70-BP ino=%llu EXIT=unmount\n",
			(unsigned long long)ip->i_ino);
		return;
	}

	/* compute the clean-REG predicate for the flush
	 * skips below.  Must hold ALL of: fast-path param on, regular file,
	 * log item clean + not in AIL + unpinned (dinode on disk == in core),
	 * and no dirty/writeback pages (data on backing store == in core). */
	p2_reg_clean = mxfs_reg_clean_release_fast &&
		S_ISREG(vip->i_mode) &&
		xfs_inode_clean(ip) &&
		!(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					  &ip->i_itemp->ili_item.li_flags)) &&
		atomic_read(&ip->i_pincount) == 0 &&
		vip->i_mapping &&
		!mapping_tagged(vip->i_mapping, PAGECACHE_TAG_DIRTY) &&
		!mapping_tagged(vip->i_mapping, PAGECACHE_TAG_WRITEBACK);

	/* instrumented H1/H2 probe: timestamp when the holder ACTUALLY
	 * honors a DIR BAST (about to drain+unlock).  Correlate realns with the
	 * P-DIRBAST arrival realns for the same ino: gap≈6000ms => holder defers
	 * ~6s (H1, fix holder side); gap≈ms but requester still waits 6000ms =>
	 * release/grant notify-back lost (H2, fix delivery).  Always-on. */
	if (S_ISDIR(vip->i_mode))
		mxfs_probe_ratelimited(
			"mxfs: P35-DIRHONOR ino=%llu realns=%llu (bast_process drain+unlock)\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * v0.3.111 P56-INSTR — for directory inodes, capture
	 * the in-memory size at BAST entry.  Compared against P55-INSTR
	 * (post-flush disk size), tells us whether (a) memory has the
	 * dir entry but flush failed (memory > disk), or (b) memory is
	 * also missing the entry (caller flow bug — the create
	 * commit didn't reach our in-memory inode).  Pure diagnostic.
	 */
	if (S_ISDIR(vip->i_mode)) {
		struct xfs_inode_log_item *p59_iip = ip->i_itemp;
		bool p59_in_ail = false;
		bool p59_pinned = false;
		uint p59_fields = 0;

		if (p59_iip) {
			p59_in_ail = test_bit(XFS_LI_IN_AIL,
					      &p59_iip->ili_item.li_flags);
			p59_fields = p59_iip->ili_fields;
		}
		p59_pinned = (atomic_read(&ip->i_pincount) > 0);

		mxfs_idbg("mxfs: P56-INSTR ino=%llu BAST-MEM-PRE "
			"vfs_size=%llu disk_size=%lld i_dlm_state=%u "
			"realns=%llu\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)i_size_read(vip),
			(long long)ip->i_disk_size,
			ip->i_dlm_state,
			(unsigned long long)ktime_get_real_ns());
		mxfs_idbg("mxfs: P59-INSTR ino=%llu BAST-LOGITEM "
			"in_ail=%d pinned=%d ili_fields=0x%x iip=%px\n",
			(unsigned long long)ip->i_ino,
			p59_in_ail, p59_pinned, p59_fields,
			p59_iip);

		/*
		 * v0.3.111 EXPERIMENT: P56 evidence shows
		 * vfs_size > disk_size in some Mode A failure cases.
		 * Hypothesis: xfs_create's dir add bumped VFS i_size
		 * but didn't propagate to ip->i_disk_size, so iflush
		 * writes the lagging value losing the new entry.
		 * Force-sync here BEFORE the flush so iflush captures
		 * the actual size.  For SF dirs (fmt=LOCAL), use
		 * if_bytes as the authoritative size.
		 *
		 * Wrap in a brief transaction to log the disk_size
		 * update properly.  Without log entry, the change is
		 * not persisted across crashes.  TODO verify
		 * if this experiment helps.
		 */
		if (ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_disk_size != ip->i_df.if_bytes) {
			mxfs_idbg("mxfs: P58-INSTR ino=%llu DISK_SIZE_MISMATCH "
				"if_bytes=%lld disk_size=%lld vfs_size=%llu\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_df.if_bytes,
				(long long)ip->i_disk_size,
				(unsigned long long)i_size_read(vip));
		}
	}

	/*
	 * Flush all metadata to the inode's home disk location.
	 *
	 * xfs_log_force writes committed transactions to the on-disk
	 * log, ensuring crash recovery.  But the inode cluster buffer
	 * at its home LBA is NOT updated — AIL checkpoints buffers
	 * asynchronously.  The other node reads the home LBA directly,
	 * so we must also push the AIL to write all dirty buffers to
	 * their final on-disk locations.
	 *
	 * v0.3.38 attempted xfs_log_force_seq(ili_commit_seq) — net no
	 * effect (ili_commit_seq usually 0 by bast time per
	 * xfs_inode_item_unpin) and trade-off introduced CAW grant
	 * timeouts on peers.  Reverted v0.3.41.  v0.3.39 attempted
	 * mxfs_dlm_ag_drain_inode_buffers — same regression family.
	 * Reverted v0.3.40.
	 */
	/*
	 * v0.3.137 per-AG drain (matches AG bast v0.3.112 pattern).
	 * Whole-AIL drain (xfs_ail_push_all_sync) caused cross-AG deadlock
	 * under multi-node lazy_ag_drain=1: kworker stuck in this call for
	 * 360s+ while peer's CAW wait timed out.  Same architectural reason
	 * the AG-bast path was changed: ail_push's writeback can re-acquire
	 * an AG held by the peer who is itself stuck in ail_push.
	 *
	 * Trade-off: dir blocks for this inode whose extents lie in OTHER
	 * AGs will not be drained here; they drain via xfsaild's normal
	 * push or via the owning AG's bast.  For the typical case (root
	 * directory at ino=128 with dir blocks allocated near the inode in
	 * its home AG) this is a no-op semantic change.  Worst case
	 * exposes a low-rate Mode A on cross-node deep-dir lookups, which
	 * is preferable to the 100% multi-node deadlock under lazy=1.
	 */
	/*
	 * D-0971: this node's asynchronous direct I/O outlives its IOLOCK
	 * ride — io_uring drops the ride when submission returns
	 * -EIOCBQUEUED with the bios still in flight — and nothing here
	 * waited for it: measured, 13-19 releases per lap committed with
	 * i_dio_count=1 under an io_uring workload with a peer conflicting
	 * (P-REL-DIO-INFLIGHT).  A release that commits then lets the peer's
	 * tenure overlap bios this node is still landing.
	 *
	 * Wait for the inode's direct I/O before the drain, so the log force
	 * and the AIL drain below cover whatever a completion commits
	 * (unwritten conversion, size update) — those may still be in the
	 * CIL when the wait returns.  Only with no holder at entry: the BAST
	 * state parks new rides, so with none admitted nobody can begin
	 * another direct I/O and the count can only fall; a ride that is
	 * still admitted may be mid-submission and about to park on its own
	 * nested ILOCK, so waiting for it here would deadlock — the holders
	 * gate below aborts and re-arms instead, and the terminal guard
	 * defers anything that slipped in.  A direct-write completion that
	 * needs ILOCK_EXCL is admitted as this inode's own nested holder
	 * (xfs_task_in_dio_end, mxfs_ilock_admit_ioend).  Unbounded like the
	 * page writeback wait, and for the same reason: an I/O the device
	 * still owns is not over because a clock ran out, and the grant is
	 * ours until it is; the drain watch names a stall.
	 */
	if (mp->m_mxfs_dlm && mxfs_rel_dio_wait && !p_entry_holders &&
	    atomic_read(&vip->i_dio_count) > 0 && !xfs_is_shutdown(mp)) {
		u64	dw0 = ktime_get_ns();
		u64	dwus;

		mxfs_drain_watch_arm(&p2_drain_watch, ip, 4);
		inode_dio_wait(vip);
		mxfs_drain_watch_disarm(&p2_drain_watch);
		dwus = (ktime_get_ns() - dw0) / NSEC_PER_USEC;
		atomic_inc(&mxfs_rel_dio_waited);
		mxfs_atomic_max(&mxfs_rel_dio_wait_max_us,
				(int)min_t(u64, dwus, INT_MAX));
		{
			static atomic_t p971w = ATOMIC_INIT(0);

			if (atomic_inc_return(&p971w) <= 200 || dwus > 1000000)
				mxfs_probe("mxfs: P971-REL-DIO-WAIT ino=%llu mode=%u wait_us=%llu comm=%s — release waited for this node's outstanding direct I/O before draining\n",
					(unsigned long long)ip->i_ino,
					p_held_mode, (unsigned long long)dwus,
					current->comm);
		}
	}
	{
		/*
		 * TARGETED drain (replaces whole-AG xfs_ail_push_ag_sync,
		 * which deadlocked vs an ILOCK-held sibling inode under the
		 * chokepoint — see mxfs_ail_drain_inode_sync header).
		 *
		 * 1. log_force: commit ip's txns to the on-disk log (unpins ip).
		 * 2. drain ip's AG alloc-buflist: freshly-allocated inode cluster
		 *    buffers sit LOCKED on pag_mxfs_alloc_buflist (the buf_locked=1
		 *    stall signature); xfsaild can't trylock ip's cluster buffer
		 *    to flush it until they are submitted.  Bounded; operates on
		 *    already-locked bufs, no ILOCK wait.
		 * 3. dirs: flush ip's own dir DATA blocks (targeted).
		 */
		xfs_agnumber_t agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		struct xfs_perag *pag;

		xfs_log_force(mp, XFS_LOG_SYNC);

		pag = xfs_perag_get(mp, agno);
		if (pag) {
			mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
			xfs_perag_put(pag);
		}
		p2s_a = ktime_get_ns();

		/*
		 * the dir DATA-block flush MOVED below the
		 * settle (msleep(20)+log_force).  It used to run HERE,
		 * inside the async CIL→AIL insertion window, where a dir block
		 * committed in the current checkpoint is already unpinned but
		 * not yet IN_AIL — so mxfs_dir_flush_data_blocks' needs_flush
		 * gate saw it CLEAN and skipped it; the block then landed in the
		 * AIL during the msleep and was destaged by xfsaild AFTER the
		 * DLM handoff (in_ail prior-tenure dir-block ghost), so a peer
		 * (and this node on re-acquire) read the stale lagging dir block
		 * → test_unlink_visibility saw 0 entries incl. its own files.
		 * The targeted ip-only AIL wait runs AFTER the settle for the
		 * same reason; the dir flush must too.
		 */
	}

	/*
	 * 0.75.54 (D-PEER-TRUNCATE-UNDER-HOT-APPENDER-167-236MS-0922): the
	 * data-page flush runs HERE, before the settle and the targeted inode
	 * drain, not after them.
	 *
	 * MEASURED on the 2-node TCP rig (tests/peer_truncate_under_append_
	 * 2node.sh s533a-c, tools/timeline_2node.py over the appender's
	 * capture): with the inode drained first, the page writeback's
	 * completion re-dirtied the inode — xfs_setfilesize commits the new
	 * size from the ioend, under ILOCK_EXCL, only once the data is on
	 * disk — so every release of a file with dirty pages reached the
	 * terminal obligation gate with exactly that one commit unlanded
	 * (P244 live=1, P-SFS a few tens of microseconds earlier, c1 the
	 * only stage with time in it).  The gate deferred, the re-fire
	 * coalesced onto the pending minimum-hold slice, and the drain
	 * re-entered 11-12 ms later to spend another ~5 ms landing that one
	 * commit.  Per hand-off: 6 ms drain + 12 ms idle + 6 ms drain, with
	 * the local writer parked and the peer waiting throughout.  A peer
	 * truncate is three such hand-offs.
	 *
	 * Data before metadata is the order XFS itself keeps: the ioend's
	 * size and unwritten-extent updates exist only after the pages are
	 * written, so writing the pages first lets the settle wait for those
	 * commits to checkpoint, the targeted drain write the inode carrying
	 * them, and the coalesced device flush cover the data pages as well
	 * — one pass, nothing left for the terminal gate to find.  The
	 * writeback-error and invalidate-error captures and the drain-site
	 * nest-admission (i_dlm_mode is still the granted mode here) are
	 * unchanged.
	 */
	/* Flush dirty pages to disk.  Drain site 1: i_dlm_mode is still the
	 * granted mode here, so a writeback submitter that collides with us on
	 * a folio is nest-admitted through the ilock rather than parked — see
	 * i_dlm_drain_site in xfs_inode.h. */
	/*
	 * D-512 cycle-2 (design-consult ruling, drain-error fail-stop): both
	 * calls below used to discard their return codes.  A release that
	 * proceeds past a FAILED drain publishes the on-disk unlock over
	 * pages that never reached the LUN (writeback error: the peer then
	 * reads a platter missing data this node's apps observed — silent
	 * cross-node lost update) or over pages still resident/mapped here
	 * (invalidate failure: a pinned folio survives the tenure and can
	 * serve a dead incarnation later).  Capture both; the abort gate
	 * below refuses the unlock on either.  Writeback failure is terminal
	 * (fail-stop: the tenure's data cannot be made coherent); a residual
	 * invalidate failure is retried via the CACHED+bast_pending re-arm —
	 * pinning the grant for as long as the pages stay pinned is the
	 * ruling's required behavior for unrevokable references.
	 */
	mxfs_dbg_rel_pause(ip, 1);
	ip->i_dlm_drain_site = 1;
	mxfs_drain_watch_arm(&p2_drain_watch, ip, 1);
	rel_drain_wb_err = filemap_write_and_wait(vip->i_mapping);
	mxfs_drain_watch_disarm(&p2_drain_watch);
	p2s_c1 = ktime_get_ns();
	if (unlikely(mxfs_dbg_rel_fail(ip, 1)))
		rel_drain_wb_err = -EIO;
	ip->i_dlm_drain_site = 0;
	mxfs_dbg_rel_pause(ip, 2);

	/* Drop cached pages so next read comes from disk */
	if (!rel_drain_wb_err) {
		rel_drain_inv_err = invalidate_inode_pages2(vip->i_mapping);
		if (unlikely(mxfs_dbg_rel_fail(ip, 2)))
			rel_drain_inv_err = -EBUSY;
	}
	mxfs_dbg_rel_pause(ip, 3);
	p2s_c = ktime_get_ns();

	/*
	 * v0.3.124 msleep + double-log_force + ail_push_all_sync.
	 *
	 * Mirrors the v0.3.94 AG-side fix at mxfs_dlm_ag_bast_work_fn.
	 * The race: xfs_log_force(SYNC) waits for log WRITE completion but
	 * the AFTER-completion callback (xlog_cil_committed) which adds the
	 * BLI to AIL fires asynchronously on a kworker.  If ail_push_all_sync
	 * runs immediately after log_force returns, it can see empty AIL
	 * (item not yet added) and declare done.  Item gets added to AIL
	 * later, xfsaild iflushes it later, write hits disk POST-DLM-unlock.
	 *
	 * Captured P64 trace at iter-1 fail: P64 (xfs_iflush)
	 * fired ~2ms AFTER P55 (post-bast_process disk read).  Smoking gun.
	 *
	 * Sess27 v0.3.111 attempted this ONCE without msleep (just double
	 * log_force + ail_push) and got 2/5 vs 3/5 baseline.  The msleep
	 * is the key — gives async committed-callback time to run.
	 *
	 * v0.3.124 used msleep(3) (matching AG-side v0.3.94).  Result:
	 * 2/6 PASS, but failures shifted to later iters.  v0.3.125 tries
	 * msleep(20) to confirm timing-vs-correctness boundary.
	 *
	 * v0.3.128 raised this to msleep(50) for a 4-node TCP
	 * tuning experiment.  Sess30 reverted to msleep(20) — TCP is no
	 * longer the production path (CAW is, per spec §11.5 D16) and
	 * msleep(50) didn't actually help 4-node TCP either.  msleep(20)
	 * is the validated 2-node value (270/270 iters at end).
	 *
	 * v0.5.6: the blind msleep(20) is REPLACED by a precise settle —
	 * P138-BAST timing proved it was ~20ms of the ~22.5ms holder-side
	 * release cost on every cross-node inode migration (the cleanup-rm
	 * storms that blow the cluster-phase 600s budget are thousands of
	 * these).  The race it guarded (xlog_cil_committed inserting the
	 * item into the AIL asynchronously AFTER xfs_log_force(SYNC)
	 * returns) is now closed deterministically: pincount drops only
	 * AFTER the AIL insertion (xfs_trans_committed_bulk inserts, then
	 * iop_unpin), so waiting for xfs_ipincount(ip)==0 guarantees the
	 * inode item is in the AIL before the targeted drain checks it —
	 * and mxfs_ail_drain_inode_sync itself now also requires pin==0.
	 * The dir-data fence below is independently immune: a block in the
	 * insertion window still has its BLI pin elevated, which
	 * mxfs_dir_data_durable treats as not-durable.  Bounded fallback:
	 * a wedged log gets one extra sync force and proceeds to the
	 * drain's own rescue/backstop machinery.
	 */
	{
		int p138_settle = 0;
		extern int mxfs_relsettle_skip;	/* diagnostic A/B */

		/*
		 * kick an ASYNC CIL push BEFORE polling for unpin.
		 * The inode stays pinned until its CIL commit is checkpointed (log
		 * write completes -> async AIL insertion -> iop_unpin).  Without a
		 * force, the settle loop below idle-polls (usleep 250-500us) waiting
		 * for the CIL to push on its own timer — that idle wait was ~35% of
		 * the holder-side dir-EX release cost (tcp_dlm_scaling max 45s->29s
		 * when the loop is skipped).  A non-blocking xfs_log_force(0) starts
		 * the checkpoint immediately so the unpin happens ASAP; the loop then
		 * exits after far fewer iterations.  Correctness UNCHANGED: we still
		 * wait for pincount==0 (the AIL-insertion guarantee, /).
		 */
		if (!mxfs_relsettle_skip && xfs_ipincount(ip) > 0)
			xfs_log_force(mp, 0);
		while (!mxfs_relsettle_skip &&
		       xfs_ipincount(ip) > 0 && p138_settle++ < 8000)
			usleep_range(250, 500);
		if (xfs_ipincount(ip) > 0)
			xfs_log_force(mp, XFS_LOG_SYNC);
	}
	p2s_b1 = ktime_get_ns();
	{
		/*
		 * settle complete (the msleep(20) above + this
		 * log_force ensure ip's committed item is in the AIL, closing
		 * the async CIL→AIL add race), then TARGETED wait for
		 * ip's own inode log item to leave the AIL.  Replaces the
		 * deadlock-prone whole-AG xfs_ail_push_ag_sync.
		 */
		/*
		 * a PR (read-only) holder of a NON-DIR inode
		 * committed NOTHING — there is nothing of ours awaiting destage,
		 * so the whole release drain (global log_force + targeted AIL
		 * drain + blkdev flush) is pure waste.  Skipping it is safe: a
		 * read-only holder never modified the inode/data (modification
		 * needs EX, which p_held_mode would then report).  This is the
		 * dir_reuse 8/tcp rm-storm cost: after the verify phase ALL 8
		 * nodes hold PR on all ~800 files, so rank1's rm-rf revokes
		 * ~5600 PR grants — each paying an unnecessary log_force+flush,
		 * the inodegc backlog a later `sync` drains for ~60-120 s.
		 * DIR PR releases KEEP the drain (the dir_pr_release_fast=1
		 * incidental block/leaf masking barrier — see that knob).
		 */
		bool skip_pr_drain = (p_held_mode != MXFS_LOCK_EX) &&
				     !S_ISDIR(vip->i_mode);
		/*
		 * a CLEAN inode (unpinned + its log item not in
		 * the AIL) has everything it committed already checkpointed to
		 * disk, so the global xfs_log_force(SYNC) here does nothing for
		 * THIS release's coherency (the settle block above already
		 * force+waits when pincount>0).  Skipping it for a clean release
		 * removes a global per-release log-force barrier from the
		 * dir_reuse 8/tcp verify-demote storm (8 nodes × ~800 cold cross-
		 * node file reads each BAST-demote a creator's clean EX file
		 * inode).  The data-cache flush below is still issued for non-PR
		 * releases (LIO drops FUA; a peer's FUA read needs the platter).
		 */
		bool clean_release = (xfs_ipincount(ip) == 0) &&
			(!ip->i_itemp ||
			 !test_bit(XFS_LI_IN_AIL,
				   &ip->i_itemp->ili_item.li_flags));

		if (!skip_pr_drain && !clean_release)
			xfs_log_force(mp, XFS_LOG_SYNC);
		/*
		 * flush ip's dir DATA blocks HERE, AFTER the
		 * settle — the async CIL→AIL insertion has now completed, so a
		 * dir block committed in the current checkpoint is visible as
		 * IN_AIL to needs_flush and is synchronously xfs_bwrite'n (which
		 * removes its BLI from the AIL via xfs_buf_item_done) BEFORE the
		 * on-disk DLM handoff.  No in_ail prior-tenure dir-block ghost
		 * survives for xfsaild to destage post-handoff.  See the moved
		 * pre-settle comment above for the failure this closes.
		 */
		extern int mxfs_relflush_skip;	/* diagnostic A/B */
		if (S_ISDIR(vip->i_mode)) {
			/*
			 * (PROVEN BY INSTRUMENT — NFS-stream
			 * hung-task capture): this used to call the LOCK-FREE
			 * mxfs_dir_flush_data_blocks(ip), which walks
			 * for_each_xfs_iext(&ip->i_df) WITHOUT holding ip->i_lock.
			 * On a REUSED dir inode (dir_reuse rm-rf+recreate churn) a
			 * concurrent extent-fork mutation races that lock-free iext
			 * walk: the cursor reads freed/realloc'd extent btree memory
			 * and yields a GARBAGE br_startblock -> a garbage out-of-range
			 * daddr (captured live: daddr 0x1e0d648fc6f390, EOFS 0x63cffb0,
			 * varying every iter).  flush_one_daddr's blocking buffer get
			 * then trips xfs_buf_map_verify's WARN_ON(1) at xfs_buf.c:423,
			 * which fired 410727x -> the synchronous console printk flood
			 * burns the CPU, the node stops servicing TCP for >25s ->
			 * TCP_USER_TIMEOUT -> peers declare it dead -> its round work is
			 * never published (the DOMINANT 8/tcp MASS entry loss).
			 * The extent fork MUST be read under ip->i_lock.  Use the
			 * ABBA-safe relsafe variant: take i_lock(read), snapshot daddrs
			 * under it, DROP i_lock, then do the blocking gets unlocked
			 * (identical pattern already used at the relfence loop below).
			 */
			if (mxfs_drain_ilock_read(ip))
				mxfs_dir_flush_data_blocks_relsafe(ip);
		}
		/* (instrumented DECISIVE): immediately AFTER the release
		 * flush, count dir DATA/LEAF buffers STILL in the AIL — these are
		 * the zombies that survive the handoff for xfsaild to reflush
		 * (the PROVEN readdir=799 root).  If this is >0 the release flush
		 * is NOT achieving "no in_ail dir buffer survives EX release"
		 * (design review invariant) — and p_held_mode/p_self_demote/clean_release
		 * say on which path.  Gated mxfs.dirwr so the keeper pays nothing. */
		if (unlikely(mxfs_dirwr_enabled) && S_ISDIR(vip->i_mode) &&
		    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
		     ip->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
		    !xfs_need_iread_extents(&ip->i_df) &&
		    mxfs_drain_ilock_read(ip)) {
			/*
			 * (PROVEN BY INSTRUMENT - 32/caw
			 * dir_reuse round-9 cluster meltdown): this walked
			 * for_each_xfs_iext(&ip->i_df) WITHOUT holding
			 * ip->i_lock - the exact lock-free-iext-on-a-reused-
			 * dir-inode hazard already proved unsafe and
			 * fixed for the main flush path 10 lines above (see
			 * that comment).  This P38 diagnostic block was added
			 * later and reintroduced the identical race: a
			 * concurrent extent-fork mutation on the SAME reused
			 * dir inode raced this lock-free cursor, yielding a
			 * garbage br_startblock -> daddr 0xbe7ce65d67090 (EOFS
			 * 0x63cffb0) -> xfs_buf_map_verify's WARN_ON(1) fired
			 * 7977x+ in one capture window with the inner loop
			 * never bounding on the failures, burning CPU on the
			 * PR holder (test3, bit3) long enough that its
			 * mxfs_dlm_bast_process release for ino=131 (the
			 * shared dir) never completed -> 30 peers starved on
			 * EX -> 360s timeout -> cascading force-shutdown on
			 * 28/32 nodes.  Take i_lock(read) like the fixed path;
			 * safe to hold across this whole loop (unlike the
			 * relsafe split above) because every buffer get here
			 * is XBF_TRYLOCK (non-blocking) - no ABBA risk.
			 */
			struct xfs_iext_cursor	zcur;
			struct xfs_bmbt_irec	zgot;
			unsigned int		zbb = XFS_FSB_TO_BB(mp,
						mp->m_dir_geo->fsbcount);
			int			zinail = 0, zfirst = -1;

			for_each_xfs_iext(&ip->i_df, &zcur, &zgot) {
				xfs_daddr_t zd, zds, zde;
				if (zgot.br_startblock == HOLESTARTBLOCK)
					continue;
				zds = XFS_FSB_TO_DADDR(mp, zgot.br_startblock);
				zde = zds + XFS_FSB_TO_BB(mp, zgot.br_blockcount);
				for (zd = zds; zd + zbb <= zde; zd += zbb) {
					struct xfs_buf *zbp = NULL;
					struct xfs_buf_log_item *zbi;
					if (xfs_buf_incore(mp->m_ddev_targp, zd,
							   zbb, XBF_TRYLOCK,
							   &zbp) != 0 || !zbp)
						continue;
					zbi = zbp->b_log_item;
					if (zbi && test_bit(XFS_LI_IN_AIL,
						    &zbi->bli_item.li_flags)) {
						zinail++;
						if (zfirst < 0)
							zfirst = (int)zd;
					}
					xfs_buf_relse(zbp);
				}
			}
			up_read(&ip->i_lock);
			if (zinail > 0)
				mxfs_probe_ratelimited("mxfs: P38-POSTREL-ZOMBIE ino=%llu inail=%d first_daddr=%d held_mode=%u self_demote=%d clean_rel=%d skip_pr=%d — dir buffers STILL in_ail after release flush\n",
					(unsigned long long)ip->i_ino, zinail,
					zfirst, p_held_mode, p_self_demote ? 1 : 0,
					clean_release ? 1 : 0, skip_pr_drain ? 1 : 0);
		}
		if (!skip_pr_drain) {
			p2s_b2 = ktime_get_ns();
			mxfs_ail_drain_inode_sync(ip);
			/* a provably-clean REG release submitted no new
			 * writes — the device flush is pure overhead (9.2ms of
			 * the 13.3ms clean-file pull, P138 stage b). */
			if (likely(!mxfs_relflush_skip) && !p2_reg_clean)
				mxfs_release_coalesced_flush(mp);
		}
	}
	p2s_b = ktime_get_ns();

	/*
	 * P-SFREL probe (dirwr-gated): for a SHORTFORM dir, after the full
	 * release drain (invariant #1: dinode written home + blkdev flush), read
	 * the inode cluster back through the SAME coherence point a peer's
	 * acquire-reload uses (PLAIN bio when mxfs_fua_disable=1 = the SCST/LIO
	 * write cache; FUA otherwise) and log the on-disk shortform count + names.
	 * DECIDES the shortform last-committer lost-update (root): if this
	 * shows our just-committed entry PRESENT but the peer's acquire-reload
	 * (P-SFDIR-RELOAD) shows it ABSENT => acquire-side stale read; if ABSENT
	 * here => release-side durability gap (we released before it was durable).
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    S_ISDIR(vip->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		uint32_t	clen = BBTOB(ip->i_imap.im_len);
		void		*rb = ((clen & 511) == 0 && clen) ?
					kmalloc(clen, GFP_NOFS) : NULL;
		int		rrc = -1;

		if (rb) {
			uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset;
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *, uint32_t);
			extern int mxfs_pal_scsi_read_fua_bdev(
				struct block_device *, uint64_t, void *, uint32_t);

			if (mxfs_fua_disable)
				rrc = mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev, lba, rb, clen);
			else
				rrc = mxfs_pal_scsi_read_fua_bdev(
					mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		}
		if (rrc == 0) {
			struct xfs_dinode *rdip = (struct xfs_dinode *)
				((char *)rb + ip->i_imap.im_boffset);
			char names[200];
			int  pos = 0, k;
			unsigned cnt = 0;

			names[0] = '\0';
			if (rdip->di_format == XFS_DINODE_FMT_LOCAL) {
				struct xfs_dir2_sf_hdr *sfh =
					(struct xfs_dir2_sf_hdr *)((char *)rdip +
					    xfs_dinode_size(rdip->di_version));
				struct xfs_dir2_sf_entry *e =
					xfs_dir2_sf_firstentry(sfh);
				cnt = sfh->count;
				for (k = 0; k < sfh->count &&
				     pos < (int)sizeof(names) - 12; k++) {
					int nl = min_t(int, e->namelen, 10);
					pos += scnprintf(names + pos,
						sizeof(names) - pos, "%.*s ",
						nl, e->name);
					e = (void *)e +
					    xfs_dir2_sf_entsize(mp, sfh, e->namelen);
				}
			}
			mxfs_probe_ratelimited(
				"mxfs: P-SFREL ino=%llu ondisk_fmt=%u count=%u names=[%s] src=%s realns=%llu\n",
				(unsigned long long)ip->i_ino, rdip->di_format,
				cnt, names, mxfs_fua_disable ? "plain" : "fua",
				(unsigned long long)ktime_get_real_ns());
		}
		kfree(rb);
	}

	/*
	 * v0.3.111 tested adding a SECOND log_force + ail_push +
	 * blkdev_issue_flush here on the hypothesis that items might be
	 * added to AIL between the first log_force (CIL→log) and first
	 * ail_push.  Result: 2/5 PASS (worse than baseline 3/5 = 60%).
	 * Reverted.  Mode A is NOT a CIL→AIL race; to look elsewhere.
	 */

	/*
	 * P-RELDIR diagnostic (gated): after the full release flush
	 * sequence, FUA-read this directory's home dir block back from disk
	 * and count "modea_" dirents on disk.  Compared against the next
	 * acquirer's P-H16 modea_count, this distinguishes:
	 *   - release-side write bug (home block on disk is MISSING the
	 *     just-committed dirent), vs
	 *   - acquire-side read/cache bug (on disk but acquirer reads stale).
	 */
	if (mxfs_instr_enabled && S_ISDIR(vip->i_mode) &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL) {
		struct xfs_ifork	*ifp = &ip->i_df;
		struct xfs_bmbt_irec	irec;
		struct xfs_iext_cursor	icur;
		if (xfs_iext_lookup_extent(ip, ifp, 0, &icur, &irec) &&
		    irec.br_startblock != HOLESTARTBLOCK) {
			void *page = (void *)__get_free_page(GFP_KERNEL);
			if (page) {
				uint64_t lba = (uint64_t)
					XFS_FSB_TO_DADDR(mp, irec.br_startblock)
					+ mp->m_ddev_targp->bt_sector_offset;
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *bdev,
					uint64_t lba_512, void *buf, uint32_t len);
				int rrc = mxfs_pal_scsi_read_fua_bdev(
					mp->m_ddev_targp->bt_bdev, lba, page, 4096);
				if (rrc == 0) {
					unsigned char *p = page;
					uint32_t magic = ((uint32_t)p[0] << 24) |
						((uint32_t)p[1] << 16) |
						((uint32_t)p[2] << 8) | (uint32_t)p[3];
					int j, modea_count = 0;
					for (j = 0; j < 4096 - 6; j++)
						if (p[j]=='m' && p[j+1]=='o' && p[j+2]=='d' &&
						    p[j+3]=='e' && p[j+4]=='a' && p[j+5]=='_')
							modea_count++;
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-RELDIR REL-DISK-DIR3 ino=%llu lba=%llu magic=0x%x modea_count=%d realns=%llu",
						(unsigned long long)ip->i_ino,
						(unsigned long long)lba, magic, modea_count,
						(unsigned long long)ktime_get_real_ns());
				}
				free_page((unsigned long)page);
			}
		}
	}

	/*
	 * v0.3.111 P55-INSTR — for directory inodes, snapshot
	 * the on-disk inode size + first byte of dir data immediately
	 * AFTER the AIL drain.  Compared against the next acquirer's
	 * reload, this catches cases where (a) our flush didn't reach
	 * disk or (b) the next acquirer reads stale.  Sess28 to compare
	 * P55-INSTR (this) against P6-INSTR (reload-post on next side).
	 * No behavior change, pure diagnostic.  Skip on non-dirs to keep
	 * fast-path fast.
	 */
	if (S_ISDIR(vip->i_mode)) {
		struct xfs_buf	*p55_bp = NULL;
		if (xfs_imap_to_bp(mp, NULL, &ip->i_imap, &p55_bp) == 0) {
			struct xfs_dinode *p55_dip =
				xfs_buf_offset(p55_bp, ip->i_imap.im_boffset);
			char p55_first[32] = "";
			/*
			 * Sess29 v0.3.115b: also dump first entry name from the
			 * post-flush on-disk SF dir contents.  This distinguishes
			 * "our flush didn't persist what we wrote" from "we wrote
			 * a stale view back" when cross-correlated with P6-INSTR
			 * reload-pre/post on the next acquirer.
			 */
			if (p55_dip->di_format == XFS_DINODE_FMT_LOCAL &&
			    be64_to_cpu(p55_dip->di_size) > 6) {
				char *ondisk = (char *)p55_dip +
					sizeof(struct xfs_dinode);
				struct xfs_dir2_sf_hdr *sfh =
					(struct xfs_dir2_sf_hdr *)ondisk;
				struct xfs_dir2_sf_entry *sfe =
					xfs_dir2_sf_firstentry(sfh);
				int len = min_t(int, sfe->namelen, 31);
				memcpy(p55_first, sfe->name, len);
				p55_first[len] = '\0';
			}
			if (p55_dip->di_format == XFS_DINODE_FMT_EXTENTS) {
				/* (instrumented) DECISIVE B-vs-C: decode the on-disk
				 * dinode data-fork extent[0] daddr AFTER the release
				 * drain — what a PEER FUA-reloads.  If it equals the
				 * daddr this node grew logical-block0 to, the RELEASE
				 * published the map (=> bug is acquire-side adoption, C);
				 * if missing/stale, release did NOT publish block0
				 * (=> bug B) and peers re-grow their own block0 = the
				 * 4-way logical-block0 split. */
				uint64_t p55_nx =
					(be64_to_cpu(p55_dip->di_flags2) &
					 XFS_DIFLAG2_NREXT64) ?
					be64_to_cpu(p55_dip->di_big_nextents) :
					be32_to_cpu(p55_dip->di_nextents);
				long long p55_d0 = -1, p55_o0 = -1;

				if (p55_nx > 0) {
					struct xfs_bmbt_irec p55_irec;
					xfs_bmbt_disk_get_all(
						(struct xfs_bmbt_rec *)
						XFS_DFORK_PTR(p55_dip, XFS_DATA_FORK),
						&p55_irec);
					p55_o0 = p55_irec.br_startoff;
					p55_d0 = XFS_FSB_TO_DADDR(mp,
						p55_irec.br_startblock);
				}
				static atomic_t p62re = ATOMIC_INIT(0);
				if (atomic_inc_return(&p62re) <= 3000)
				mxfs_probe("mxfs: P62-REL-DIREXT ino=%llu disk_nx=%llu ext0_off=%lld ext0_daddr=%lld disk_size=%lld disk_gen=%u\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)p55_nx,
					p55_o0, p55_d0,
					(long long)be64_to_cpu(p55_dip->di_size),
					be32_to_cpu(p55_dip->di_gen));
			}
			mxfs_idbg("mxfs: P55-INSTR ino=%llu BAST-DISK "
				"disk_fmt=%u disk_size=%lld disk_nlink=%u "
				"first=\"%s\" realns=%llu\n",
				(unsigned long long)ip->i_ino,
				p55_dip->di_format,
				(long long)be64_to_cpu(p55_dip->di_size),
				be32_to_cpu(p55_dip->di_nlink),
				p55_first,
				(unsigned long long)ktime_get_real_ns());
			/*
			 * Sess29 v0.3.117-118 added a surgical FUA-rewrite
			 * here, then v0.3.118 verified WRITE(16) FUA persists
			 * correctly (match=1 always).  Mode A turned out to be
			 * the async-AIL-add race fixed by msleep+double-flush
			 * above, NOT a write-side persistence issue.  The
			 * surgical FUA-rewrite is therefore redundant — sess30
			 * cleanup removed it.  mxfs_pal_scsi_write_fua_bdev
			 * helper kept in tree for future use.
			 */
			xfs_buf_relse(p55_bp);
		}
	}

	/*
	 * v0.3.35 (sess19): REVERTED v0.3.33 cluster-buf bwrite + v0.3.34
	 * second log_force.  The cluster-buf xfs_buf_lock cascaded deadlock
	 * via xfsaild (cluster buf is shared by multiple inodes — root
	 * dir 128 + ino=131 at boffset=1536 etc; b_sema serializes ALL
	 * operations on the buf incl. sibling iflushes and rm-side
	 * xfs_inode_item_precommit).  Same failure mode state.md sess16
	 * v0.3.21b documented and rejected.
	 *
	 * Returning to existing pre-v0.3.33 logic: just stale the cluster
	 * buf so next read re-fetches from disk.  Not enough to close
	 * Mode A on its own — needs Approach A (per-trans inode-DLM defer
	 * list firing from xfs_trans_free) — but at least no deadlock.
	 */
	{
		struct xfs_buf	*stale_bp = NULL;

		if (xfs_buf_incore(mp->m_ddev_targp, ip->i_imap.im_blkno,
				   ip->i_imap.im_len, 0, &stale_bp) == 0) {
			/*
			 * WEDGE ROOT FIX (instrumented —
			 * PROVEN via run30 t7 ino=8388770: P113-DRAIN-WEDGE
			 * iflushing=1 lb_flags=0x50(ASYNC|STALE) lb_onlist=0
			 * rescued=0, and 255 site=bast P20 fires with
			 * li_empty=0 in one run).  This site staled the
			 * cluster buffer UNGUARDED.  When a CO-RESIDENT
			 * inode's committed-not-yet-written log item is
			 * attached (b_li_list non-empty — e.g. a just-created
			 * neighbor's IALLOC image queued on xfsaild's delwri
			 * list), xfs_buf_stale clears _XBF_DELWRI_Q, the
			 * delwri walker drops the buffer without writing,
			 * xfs_buf_inode_iodone never runs, and the neighbor
			 * wedges IFLUSHING-in-AIL forever: its create never
			 * destages (readers FUA-read mode=0 → permanent
			 * lookup-ENOENT dangler), every later drain on it
			 * spins seconds (P138-BAST dur_us=3.6e6, and the
			 * P136 rescue cannot delwri-requeue a STALE buffer),
			 * cascading to DLM acquire -110 → dirty-cancel
			 * shutdowns.  Apply the same guard the
			 * iget-miss/recycle/reload twins carry: skip the
			 * stale while the in-core buffer is authoritative;
			 * per-ino handoff durability is unaffected (each
			 * ino's own BAST drain flushes it before unlock),
			 * and once writeback completes the items detach so
			 * a later invalidate proceeds normally.
			 */
			if (mxfs_buf_has_uncheckpointed_mods(stale_bp)) {
				mxfs_probe_ratelimited(
				    "mxfs: P91-BAST-PROTECT ino=0x%llx blkno=0x%llx pin=%d li_empty=%d flags=0x%x comm=%s — keeping in-core authoritative cluster buffer (would-be iflush-strand averted)\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_imap.im_blkno,
				    xfs_buf_ispinned(stale_bp) ? 1 : 0,
				    list_empty(&stale_bp->b_li_list) ? 1 : 0,
				    stale_bp->b_flags, current->comm);
				xfs_buf_relse(stale_bp);
				goto skip_bast_cluster_stale;
			}
			/* P20 forensic — see reload-site twin.  sess38
			 * run14d: gated mxfs.dirwr/mxfs.instr for ship. */
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe_ratelimited(
				    "mxfs: P20-CLUSTER-INVAL site=bast ino=0x%llx blkno=0x%llx flags=0x%x li_empty=%d pin=%d comm=%s\n",
			    (unsigned long long)ip->i_ino,
			    (unsigned long long)ip->i_imap.im_blkno,
			    stale_bp->b_flags,
			    list_empty(&stale_bp->b_li_list) ? 1 : 0,
			    xfs_buf_ispinned(stale_bp),
			    current->comm);
			xfs_buf_stale(stale_bp);
			/* v0.3.99: force-clear XBF_DONE so re-read goes to disk */
			stale_bp->b_flags &= ~XBF_DONE;
			xfs_buf_relse(stale_bp);
		}
	}
skip_bast_cluster_stale:
	/*
	 * For directories, reread the cluster from disk and then force a
	 * second block-layer ordering barrier.  blkdev_issue_flush() is
	 * submit_bio_wait() on a zero-length REQ_OP_WRITE|REQ_PREFLUSH
	 * bio (block/blk-flush.c:blkdev_issue_flush).  This replaces a
	 * previous empirical 1.05 ms usleep_range (binary-search floor:
	 * 1.025ms fails, 1.05ms passes 20/20).  Hypothesis: the race is
	 * post-reread completion ordering on the tcm_loop stack, closed
	 * by forcing the block queue to drain.  If this fails to pass
	 * 20/20, the visibility gap lives below the block layer (LIO /
	 * qemu / target-side caching) — pivot to approach (b) in
	 * state.md.
	 */
	if (S_ISDIR(vip->i_mode)) {
		struct xfs_buf	*verify_bp = NULL;
		int		flush_err;

		if (xfs_imap_to_bp(mp, NULL, &ip->i_imap, &verify_bp) == 0)
			xfs_buf_relse(verify_bp);

		flush_err = mxfs_blkdev_flush_epoch(mp);
		if (flush_err)
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: post-reread flush err=%d ino=%llu",
				flush_err,
				(unsigned long long)ip->i_ino);
	}

	/*
	 * v0.3.84: stale cached directory block bufs across the
	 * dir's extent map.  These bufs (xfs_dir3_data/block/leaf/leafn/free
	 * buf_ops) live in pag_bcache but are NOT covered by
	 * mxfs_buf_is_ag_metadata (AG-meta only) or the FUA hook
	 * (mxfs_buf_in_fua_window scopes to pag_dlm_fua_window).  Without
	 * staling here, after peer modifies dir contents and grants the
	 * lock back, our next xfs_buf_get returns the cached XBF_DONE buf
	 * → pre-modification view → xfs_dir_lookup misses peer-added entry
	 * (not the failure mode here) or sees peer-removed entry as still
	 * present → xfs_dir_removename returns -ENOENT (Mode A, sess20-22).
	 *
	 * Sess24 P33/P35 confirmed the cache-divergence root cause.  Sess24
	 * bast_poll self-correct experiment (premature cache-invalidation
	 * approach) triggered Mode A iter-1 — that is THIS bug surfacing
	 * because cached dir bufs were never staled.
	 *
	 * Existing reload_inode L524-543 staled only the FIRST FSB of the
	 * FIRST extent — incomplete for any leaf/node-format dir.  Walking
	 * here at release time uses our (still-correct) extent map to
	 * cover all dir blocks.
	 *
	 * EXTENTS format only.  BTREE format requires xfs_iread_extents
	 * which can issue I/O — skip; large dirs are rare in stress and
	 * would also drain via reload_inode after re-acquire.  LOCAL
	 * format is in the dinode itself (no separate dir bufs).
	 */
	if (S_ISDIR(vip->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS) {
		struct xfs_iext_cursor	icur;
		struct xfs_bmbt_irec	got;
		unsigned int		dir_blk_bb;
		unsigned int		n_extents = 0;
		unsigned int		n_dirblks = 0;
		unsigned int		n_cached = 0;
		unsigned int		n_staled = 0;
		unsigned int		n_skip_locked = 0;

		dir_blk_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

		down_read(&ip->i_lock);
		for_each_xfs_iext(&ip->i_df, &icur, &got) {
			xfs_daddr_t	d_start, d_end, d;

			n_extents++;
			if (got.br_startblock == HOLESTARTBLOCK)
				continue;

			d_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
			d_end = d_start +
				XFS_FSB_TO_BB(mp, got.br_blockcount);

			for (d = d_start;
			     d + dir_blk_bb <= d_end;
			     d += dir_blk_bb) {
				struct xfs_buf	*dbp = NULL;

				n_dirblks++;
				if (xfs_buf_incore(mp->m_ddev_targp, d,
						   dir_blk_bb, 0,
						   &dbp) != 0 || !dbp)
					continue;
				n_cached++;
				if (xfs_buf_trylock(dbp)) {
					xfs_buf_stale(dbp);
					/* v0.3.99: force-clear XBF_DONE */
					dbp->b_flags &= ~XBF_DONE;
					xfs_buf_unlock(dbp);
					n_staled++;
				} else {
					/* P-H12-INSTR: characterize WHO
					 * holds the buf at skip_locked moment.
					 * Captures: pincount (CIL/log/AIL pending),
					 * io_count (in-flight bio), b_flags, BLI's
					 * AIL membership.  Helps next session
					 * design the right wait/coordination.
					 *
					 * P-H12b: also log b_transp and
					 * b_hold to identify WHO actually holds
					 * the b_sema at this moment. If b_transp
					 * != NULL, an active transaction holds
					 * it (likely the cause). If b_transp ==
					 * NULL but b_hold > 1, some other
					 * non-transaction context.
					 */
					if (mxfs_instr_enabled) {
					struct xfs_buf_log_item *bip = dbp->b_log_item;
					int bip_in_ail = bip ?
						test_bit(XFS_LI_IN_AIL,
							 &bip->bli_item.li_flags) : -1;
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-H12b-INSTR ino=%llu blkno=%llu "
						"b_transp=%px b_hold=%u",
						(unsigned long long)ip->i_ino,
						(unsigned long long)dbp->b_maps[0].bm_bn,
						dbp->b_transp,
						dbp->b_hold);
					/* P-H25-MEM: dump first 32 bytes of in-memory
					 * dir3 buf content. If memory has entries but disk
					 * doesn't, bug is durability below kernel block
					 * layer. If memory doesn't have entries, bug is
					 * upstream. */
					unsigned char mem[32];
					if (dbp->b_addr) {
						memcpy(mem, dbp->b_addr, 32);
					} else {
						memset(mem, 0xff, 32);
					}
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-H12-INSTR ino=%llu blkno=%llu skip_locked: pin=%d flags=0x%x bip_in_ail=%d",
						(unsigned long long)ip->i_ino,
						(unsigned long long)dbp->b_maps[0].bm_bn,
						atomic_read(&dbp->b_pin_count),
						dbp->b_flags,
						bip_in_ail);
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-H25-MEM ino=%llu blkno=%llu mem0..31="
						"%02x%02x%02x%02x%02x%02x%02x%02x"
						"%02x%02x%02x%02x%02x%02x%02x%02x"
						"%02x%02x%02x%02x%02x%02x%02x%02x"
						"%02x%02x%02x%02x%02x%02x%02x%02x",
						(unsigned long long)ip->i_ino,
						(unsigned long long)dbp->b_maps[0].bm_bn,
						mem[0], mem[1], mem[2], mem[3],
						mem[4], mem[5], mem[6], mem[7],
						mem[8], mem[9], mem[10], mem[11],
						mem[12], mem[13], mem[14], mem[15],
						mem[16], mem[17], mem[18], mem[19],
						mem[20], mem[21], mem[22], mem[23],
						mem[24], mem[25], mem[26], mem[27],
						mem[28], mem[29], mem[30], mem[31]);
					}
					n_skip_locked++;
				}
				xfs_buf_relse(dbp);
			}
		}
		up_read(&ip->i_lock);

		if (n_cached || n_extents > 1)
			mxfs_idbg("mxfs: P36-INSTR ino=%llu BAST-DIR-STALE "
				"ext=%u dirblks=%u cached=%u staled=%u "
				"skip_locked=%u\n",
				(unsigned long long)ip->i_ino,
				n_extents, n_dirblks, n_cached,
				n_staled, n_skip_locked);
	}

	/*
	 * 0.75.54: the page flush and invalidate (stage c) now run BEFORE
	 * the settle and inode drain (stage b) — see the block ahead of the
	 * settle.  Nothing of the data drain remains here.
	 */

	/*
	 * Mark inode as stale — in-memory fork data (inline directory
	 * content, extent list) may be outdated when we re-acquire
	 * this lock.  mxfs_dlm_ilock_begin will reload from disk on
	 * the next cache miss.
	 */
	ip->i_dlm_stale = true; ip->i_dlm_stale_src = 5;
	mxfs_idbg(
		"mxfs: BAST set stale ino=%llu",
		(unsigned long long)ip->i_ino);

	/*
	 * ROOT FIX (instrument step 2b, PROVEN via the
	 * test9 self-double-map timeline, gen230 release):  authorize the
	 * release-window flush BEFORE clearing i_dlm_mode below.  The old
	 * order opened a window [mode=NL .. flush-loop sets RELFLUSH] in
	 * which a CONCURRENT xfsaild iflush of this inode hit the P119
	 * non-EX guard (xfs_inode.c), which CONSUMES the dirty state
	 * (ili_fields=0, error=0 → flush_out) WITHOUT copying the new core
	 * into the cluster buffer.  The tenure's last dinode mods (e.g. a
	 * dir-grow extent record: size 36864 → disk kept 28672) were thereby
	 * silently discarded; the drain's own iflush_cluster then found
	 * nothing dirty, declared durable, and released — the next acquire
	 * reloaded the stale platter dinode, the in-core extent map went
	 * backward, and the very next dir grow re-mapped offsets this node
	 * had already mapped (P34C: startoff 7/8 → 0x48000b/c then
	 * 0x48000d/e 160ms later), orphaning its own committed dirent
	 * blocks = zero_silent_loss.  Setting RELFLUSH first makes any
	 * concurrent flush in the release window write the REAL in-core
	 * state — safe, because this node logically owns the tenure until
	 * the on-disk unlock at the end of this function.  Cleared at
	 * reg_durable_done as before.
	 */
	if (S_ISREG(vip->i_mode) || S_ISDIR(vip->i_mode))
		xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);

	/*
	 * capture the grant_gen of the tenure this
	 * release belongs to, BEFORE the mode goes NL.  Everything from the
	 * NL-set to the mxfs_v5_dlm_inode_unlock call at the end of this
	 * function is an open window in which a local thread can complete a
	 * FULL re-acquire (new gen, fresh mirror + dir_epoch); the gen-aware
	 * unlock uses this capture to refuse to release that newer tenure
	 * (run42-t4: gen-blind unlock ate the fresh EX mirror, the master
	 * accepted the echoed current gen, and a peer got concurrent EX ->
	 * stale-base RMW -> durable dirent loss).
	 */
	p_rel_gen = mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm, ip->i_ino);

	/*
	 * Set i_dlm_mode = NL BEFORE calling mxfs_v5_dlm_inode_unlock so
	 * the cached-mode fast-path in ilock_begin sees an accurate view:
	 * once mode is NL, the DLM grant is no longer assumed to be held.
	 * Without this, a window exists where the on-disk DLM has been
	 * released but i_dlm_mode still claims EX/PR — a concurrent
	 * ilock_begin on this node would fast-path through and operate
	 * without cluster-wide serialization.
	 */
	spin_lock(&ip->i_dlm_lock);
	/*
	 * PROVEN ROOT FIX (instrumented, P15-NL-WHILE-HOLDER fired:
	 * ino=14680192 mode=EX ex=1 state=DEMOTING on the mxfs-ino-bast kworker)
	 * for the tcp_dlm_scaling P58-DIRPIN-NONEX durable-dirent RESURRECTION at
	 * 8 nodes.  bast_process is queued only when ex_holders==0, but a
	 * fast-path acquire can re-increment ex_holders DURING the async drain
	 * above.  The OLD code then set i_dlm_mode=NL + released the on-disk slot
	 * UNCONDITIONALLY -> the active holder's transaction commits the dir at
	 * NL (no cluster-wide EX authority -> xfs_inode_item_pin P58-DIRPIN-NONEX)
	 * -> a peer reads the lagging LUN, RMWs it, and durably resurrects the
	 * holder's just-removed dirent.  FIX: re-check holders here under the
	 * lock; if a holder re-appeared, ABORT the release entirely — keep the
	 * grant (do NOT set NL, do NOT unlock), clear the release-window flush
	 * authorization, and RE-ARM the deferred BAST (state=BAST).  The holder's
	 * mxfs_dlm_ilock_end (or unpin) re-fires bast_process once ex_holders
	 * drops back to 0, so the peer is served promptly AFTER our committed
	 * change is durable — never mid-transaction.  The drain already done
	 * above is harmless to leave (we still own the tenure).
	 */
	/*
	 * FIX-A (PROVEN BY INSTRUMENT, r10 round-4 t2 trace):
	 * i_dlm_pin_count MUST count as a live holder here.  FIX3's create
	 * pattern is EX begin -> mxfs_inode_pin(dp) -> iunlock -> dialloc ->
	 * re-lock; during dialloc the counters read ex=0 pr=0 pin=1.  An
	 * idle-release/bast_process already past its entry check (P74 grant
	 * gen=10298 landed .162703, pipeline ENTRY .162838, dd begin-slow
	 * .163125 + pin .163130, P51-REL .164115 unlocked gen=10298 with
	 * pin=1) sailed through this abort because it tested only ex/pr/gen
	 * -> the wire unlock stripped the grant FIX3's pin was holding ->
	 * master granted peers mid-create (fence AG<->dir ABBA returns; dir
	 * concurrent-EX windows).  A pinned grant is exactly "BASTs defer
	 * until unpin" (pinned_resource.c) — an in-flight release must defer
	 * the same way: abort + state=BAST; the unpin's quiescent transition
	 * re-fires bast_process (proven arm in mxfs_inode_unpin).
	 */
	/*
	 * FIX-H (PROVEN BY INSTRUMENT, r10 round-4 t6 capture): an
	 * instance that ENTERED with i_dlm_mode==NL is a CLEANUP flavor
	 * (P135 orphan / phantom reconcile / double-queue re-run) — it was
	 * queued to clear a hold that had no in-core tenure.  If the mirror
	 * now carries a LIVE grant (p_rel_gen != 0), that grant belongs to a
	 * just-granted tenure whose acquiring thread has not resumed yet
	 * (TCP receive kworker links the mirror before the blocked acquirer
	 * wakes; inode_held reads that same mirror, so bast_notify's P135
	 * gate misread the grant-completion window as an orphan).  PROVEN:
	 * t6 P135 @334.1924 -> grant gen=9252 linked @.1928 -> this pipeline
	 * passed every abort check (entry_gen==rel_gen==9252, holders==pin==0
	 * because dd was still in its post-grant reload) and wire-released
	 * the live tenure @~.1930 -> master granted t4 gen=9253 0.7ms later
	 * -> DOUBLE-EX -> both nodes added a dirent at the same offset ->
	 * t6's writeback durably swallowed node4_f9 (the 799/800 one-dirent
	 * loss).  t4 ran the same shape in the same second and survived only
	 * because its dd's pin landed before this recheck (P15 pin abort).
	 * A cleanup instance must NEVER release a live-gen tenure: abort like
	 * the pin/gen aborts (CACHED + bast_pending) and let the materializing
	 * tenure's own lifecycle (ilock_end/unpin/dwork) serve the peer.
	 * CAW unaffected (grant_gen is 0 on CAW).
	 */
	{
	/*
	 * FIX-H3 (r13 instrumented lesson, test2: 1009x rc=-35 + orph=1
	 * abort streaks on ino 159 -> cluster LKTIMEOUT cascade): the P109
	 * EDEADLK self-demote IS the legitimate resolver for a grant our own
	 * retry loop stranded — it enters with in-core NL and a live mirror
	 * gen (exactly the orphan_live signature) and must RELEASE that
	 * grant so the re-request can succeed.  Blocking it re-strands the
	 * inode forever (each master re-grant is a fresh gen, so the strike
	 * counter never converges).  Exempt self-demote instances; the r10
	 * double-EX killer (P135-queued orphan release) never sets
	 * i_dlm_self_demote and stays blocked.
	 */
	bool orphan_live = (p_held_mode == MXFS_LOCK_NL && p_rel_gen != 0 &&
			    !p_self_demote);

	/*
	 * FIX-H2 strike escalation (r12 instrumented lesson): the abort-only
	 * version of FIX-H turned a genuinely STRANDED grant (mirror entry
	 * never consumed by any acquirer — no known producer, but real:
	 * ino 6291632 wedged 184s across two holders, PR waiters rc=-110,
	 * 6-node shutdown cascade in netpartition/tds) into a livelock: every
	 * release attempt aborted forever.  Discriminate mid-completion from
	 * stranded: same gen, still NL in-core, no live ACQUIRING slow path,
	 * across >=N samples (~25ms dwork re-arm each) -> stranded; release
	 * it (pre-FIX-H semantics are CORRECT for a true strand).  Any gen
	 * turnover or consumption progress resets the count.
	 *
	 * THRESHOLD 4->280 (PROVEN BY INSTRUMENT): the 4x25ms
	 * (~100ms) window was calibrated to the 0.5-2ms grant-completion of a
	 * HEALTHY cluster.  Under the dir-EX tenure floor (32-node
	 * cache_coherency, run 060826Z), a granted-but-unconsumed mirror is
	 * LEGITIMATE for up to the 6s ACQUIRE_WAIT retry gap (requester between
	 * slow-path retries) and for the post-CAS check_exclusion/
	 * verify_grant_persisted SCSI reads that stall 100ms+ in the CAW IO
	 * storm.  Result: 45 P15H reaps on the hot dir in 35s across 23 nodes —
	 * each reap wire-releases a grant a live consumer may be mid-consuming
	 * (test14/test20 dark-branch double-EX victims, chg fork 512..649 vs
	 * published 512..727).  280x25ms (~7s) sits above every legitimate
	 * unconsumed window; a TRUE strand (netpartition wedge) still
	 * heals in ~7s instead of livelocking forever.
	 *
	 * 0.89.65, MEASURED (tests/stranded_grant_escape.sh s143a/s143b on
	 * 0.89.64, 2/tcp): this 280-sample escape has NO reachable shape on
	 * TCP, and the record that restored it (the counter had been uint8_t)
	 * was wrong that it is TCP's only strand escape.  The strand has two
	 * shapes and the pipeline discriminates them by i_dlm_acq_inflight:
	 *   - ABANDONED (acq_inflight == 0): the P15-TCP-ORPH-PROCEED
	 *     arm below proceeds to the gen-anchored unlock after 500 ms of
	 *     persistence — about the 5th sample — so this counter never
	 *     passes single digits (s143a: freed in 901 ms, 5 samples).
	 *   - IN FLIGHT (acq_inflight > 0): a live acquirer is protected at
	 *     every gate UPSTREAM of this sampler — __mxfs_dlm_bast_notify
	 *     parks the BAST (P-ACQWIN-PARK / P-ACQWIN-DEFER) and
	 *     mxfs_dlm_bast_dwork_fn's busy check re-arms without running the
	 *     release — so the pipeline never reaches this line while the
	 *     acquirer lives (s143b: 0 samples across a 20 s hold), and the
	 *     strand becomes the abandoned shape the instant the acquirer
	 *     exits (freed 1.4 s after P-DBG-STRAND-INJECT-END).  That
	 *     protection is the daf50d34 design: releasing under a live
	 *     acquirer is the double-EX that lost dirents.
	 * The CAW twin is the resource-scoped clock below (this counter's
	 * per-inode gen churns there).  The branch stays as the census it
	 * also is; nothing may be argued from it firing or not firing.
	 */
	if (orphan_live) {
		if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
		    ip->i_dlm_mode != MXFS_LOCK_NL ||
		    ip->i_dlm_orphan_gg != p_rel_gen) {
			ip->i_dlm_orphan_gg = p_rel_gen;
			ip->i_dlm_orphan_strikes = 1;
		} else if (++ip->i_dlm_orphan_strikes >= 280) {
			ip->i_dlm_orphan_strikes = 0;
			ip->i_dlm_orphan_gg = 0;
			orphan_live = false;	/* proceed with the release */
			p15h_reap = true;	/* tag for unlock-outcome forensics */
			mxfs_probe("mxfs: P15H-STRANDED-RELEASE ino=%llu gen=%u state=%u — granted mirror entry never consumed across 280 samples (~7s); releasing stranded grant\n",
				(unsigned long long)ip->i_ino, p_rel_gen,
				ip->i_dlm_state);
		} else if ((ip->i_dlm_orphan_strikes % 70) == 0) {
			/*
			 * 0.89.63: the convergence census.  The comment above
			 * asserts that on TCP the gen is a per-episode token
			 * that does not churn, so the strikes accumulate on
			 * one gen; that had never been measured.  Four lines
			 * per episode say whether they do, and on which gen.
			 */
			mxfs_probe_ratelimited("mxfs: P15H-STRIKES ino=%llu gen=%u strikes=%u state=%u — same-gen unconsumed samples accumulating toward the 280-sample escape\n",
				(unsigned long long)ip->i_ino, p_rel_gen,
				ip->i_dlm_orphan_strikes, ip->i_dlm_state);
		}
		/*
		 *  a864 — WALL-CLOCK strand escape (PROVEN BY INSTRUMENT):
		 * the same-gen strike counter above NEVER converges on CAW.
		 * p_rel_gen is caw_grant_seq32 (v5_mount.c:1558), a LOCAL
		 * per-node counter bumped on every successful acquire/promote of
		 * this resource; under 32-node single-hot-dir contention the
		 * holder's own re-acquire cycling churns it, so `orphan_gg !=
		 * p_rel_gen` resets the strikes to 1 on nearly every ~26ms dwork
		 * re-arm and the 280-sample threshold is never reached.  PROVEN
		 * (backoff repro): node17 held dir ino131 EX on-disk while idle
		 * (ex=pr=pin=0), bast_process re-entered 2352x at mode=NL/DEMOTING
		 * without ever completing the release, a single peer stalled
		 * 119.3s (P-ACQ-STUCK el_ms=119268) — and 0 P15H-STRANDED-RELEASE
		 * fired across 1748 stuck-waits.  A genuinely mid-completing grant
		 * resumes in microseconds on CAW (the acquirer sets i_dlm_mode=EX
		 * immediately after the CAS-promote), so any window of CONTINUOUS
		 * in-core mode==NL longer than a few seconds is a true strand, not
		 * a live grant.  Time it directly (reset only on genuine
		 * consumption — ACQUIRING or mode!=NL — NOT on gen churn) so the
		 * escape converges regardless of grant_seq movement.
		 */
		/*
		 * CAW ONLY.  On TCP a granted-but-unconsumed mirror is LEGITIMATE
		 * for up to the 6s ACQUIRE_WAIT retry gap (see the threshold
		 * comment above, and 11891) — a sub-6s wall-clock force would
		 * release a live-but-slow TCP grant -> double-EX.  TCP keeps the
		 * same-gen 280-strike escape (grant_gen is a real per-episode token
		 * there, so it converges).  The churn defect is CAW-specific
		 * (grant_seq bumps on every local acquire), so scope the timer to
		 * CAW where the mid-completion window is microseconds.
		 */
		if (orphan_live && mp->m_mxfs_dlm &&
		    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
			u64 orph_now = ktime_get_ns();

			/* interactive session 2026-07-13: this per-inode clock is now
			 * DIAGNOSTIC ONLY (see age_orph_ms/age_starve_ms in the
			 * P15-REL-ABORT print).  PROVEN BY INSTRUMENT via init_seq
			 * instrumentation (ino=131, fence_during_write@8/caw) that it
			 * gets silently reset to 0 whenever the in-core VFS inode is
			 * evicted and reinstantiated — the hot-dir create/unlink storm
			 * churns icache faster than mxfs_caw_orphan_force_ms, so
			 * neither this wall-clock nor the same-gen strike counter
			 * (i_dlm_orphan_gg, also per-inode) ever accumulates enough
			 * CONTINUOUS observation to fire — P15H-PEER-STARVE-TIMEOUT
			 * measured 0 fires across thousands of aborts on the affected
			 * ino.  The force DECISION below now uses the resource-scoped
			 * clock (dlm_caw.c grant_meta table, keyed by resource hash,
			 * not VFS inode identity) instead. */
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
			    ip->i_dlm_mode != MXFS_LOCK_NL) {
				ip->i_dlm_orphan_since_ns = 0;
			} else if (ip->i_dlm_orphan_since_ns == 0) {
				ip->i_dlm_orphan_since_ns = orph_now;
			}
			if (ip->i_dlm_bast_starve_since_ns == 0)
				ip->i_dlm_bast_starve_since_ns = orph_now;

			/* Resource-scoped clock: survives both local re-acquire churn
			 * (caw_grant_seq_prebump preserves this grant_meta bucket's
			 * other fields on a same-resource reacquire, only claims via
			 * memset on a genuine foreign collision) and VFS inode
			 * eviction (not stored on the xfs_inode at all).  Drives the
			 * actual force decision. */
			{
				u64 rs_orphan = mxfs_v5_dlm_inode_orphan_clock_get(
					mp->m_mxfs_dlm, ip->i_ino, false);
				u64 rs_starve = mxfs_v5_dlm_inode_orphan_clock_get(
					mp->m_mxfs_dlm, ip->i_ino, true);

				if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING ||
				    ip->i_dlm_mode != MXFS_LOCK_NL) {
					if (rs_orphan)
						mxfs_v5_dlm_inode_orphan_clock_set(
							mp->m_mxfs_dlm, ip->i_ino,
							false, 0);
				} else if (rs_orphan == 0) {
					mxfs_v5_dlm_inode_orphan_clock_set(
						mp->m_mxfs_dlm, ip->i_ino, false,
						orph_now);
				} else if (orph_now - rs_orphan >=
					   (u64)mxfs_caw_orphan_force_ms * NSEC_PER_MSEC) {
					mxfs_v5_dlm_inode_orphan_clock_set(
						mp->m_mxfs_dlm, ip->i_ino, false, 0);
					ip->i_dlm_orphan_since_ns = 0;
					ip->i_dlm_orphan_strikes = 0;
					ip->i_dlm_orphan_gg = 0;
					orphan_live = false;	/* proceed with the release */
					p15h_reap = true;	/* force gen-blind unlock below */
					pr_warn("mxfs: P15H-STRAND-TIMEOUT ino=%llu gen=%u entry_gen=%u state=%u \xe2\x80\x94 orphan-live mode==NL held %ums continuously (idle on-disk hold, resource-scoped clock); forcing stranded release\n",
						(unsigned long long)ip->i_ino, p_rel_gen,
						p_entry_gen, ip->i_dlm_state,
						mxfs_caw_orphan_force_ms);
				}

				if (rs_starve == 0) {
					mxfs_v5_dlm_inode_orphan_clock_set(
						mp->m_mxfs_dlm, ip->i_ino, true,
						orph_now);
				} else if (orphan_live &&
					   orph_now - rs_starve >=
					   (u64)mxfs_caw_orphan_force_ms * NSEC_PER_MSEC) {
					mxfs_v5_dlm_inode_orphan_clock_set(
						mp->m_mxfs_dlm, ip->i_ino, true, 0);
					mxfs_v5_dlm_inode_orphan_clock_set(
						mp->m_mxfs_dlm, ip->i_ino, false, 0);
					ip->i_dlm_bast_starve_since_ns = 0;
					ip->i_dlm_orphan_since_ns = 0;
					ip->i_dlm_orphan_strikes = 0;
					ip->i_dlm_orphan_gg = 0;
					orphan_live = false;	/* proceed with the release */
					p15h_reap = true;	/* force gen-blind unlock below */
					mxfs_probe("mxfs: P15H-PEER-STARVE-TIMEOUT ino=%llu gen=%u entry_gen=%u state=%u peer starved %ums despite local re-acquire churn (resource-scoped clock); forcing release\n",
						(unsigned long long)ip->i_ino, p_rel_gen,
						p_entry_gen, ip->i_dlm_state,
						mxfs_caw_orphan_force_ms);
				}
			}
		}
	} else {
		ip->i_dlm_orphan_since_ns = 0;	/* not orphan-shape — reset clock */
		/* i_dlm_bast_starve_since_ns is deliberately NOT reset here.
		 * PROVEN (fence_during_write@8caw dmesg, one node): P15-REL-ABORT
		 * fired 4480x/run with orph=1 on 2632 samples and orph=0 on 1848 —
		 * i.e. this "not orphan-shape" branch (a local re-acquire
		 * momentarily holding ex/pr/pin) fires on ~41% of samples for the
		 * SAME contended inodes, interleaved with orphan-shape samples.
		 * Resetting the starve clock here reproduces the exact defeated-
		 * timer bug this clock exists to fix (i_dlm_orphan_since_ns was
		 * already proven defeated the same way by continuous mode churn).
		 * This clock tracks peer starvation across the WHOLE abort
		 * episode regardless of which specific reason blocked release on
		 * any single sample; it is only cleared where a REAL release
		 * actually completes, below. */
	}

	/*
	 * (design-consult consult) — CAW: an orphan-live
	 * entry with ZERO holders/pins and the grant gen UNMOVED must
	 * PROCEED to the (gen-anchored) unlock, not abort into the strike/
	 * wall-clock dance.  Measured: every hot-dir handoff paid the full
	 * 3s starve-force (P15-REL-ABORT orph=1 age climbing to ~3s, then
	 * P15H-PEER-STARVE-TIMEOUT — 519 forced releases on one node), so
	 * an 8-node mkdir/stat race convoyed 100-220s and cc@8 blew its
	 * budget.  The abort was CIRCULAR: the live on-disk token is the
	 * very thing this release exists to clear; with no local users and
	 * no gen movement there is no consumer to protect.  Proceeding with
	 * the ENTRY-ANCHORED unlock is strictly SAFER than the 3s escape it
	 * replaces (which unlocks GEN-BLIND — the proven 32-node double-EX
	 * hazard): a genuinely mid-completing local acquire bumps the gen
	 * and the anchored unlock refuses -ESTALE -> re-queue as before.
	 * TCP keeps the abort: a granted-but-unconsumed mirror is
	 * legitimate for up to the 6s ACQUIRE_WAIT retry gap there.
	 */
	if (orphan_live && mp->m_mxfs_dlm &&
	    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) &&
	    ip->i_dlm_ex_holders == 0 && ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_pin_count == 0 &&
	    !(p_rel_gen != 0 && p_rel_gen != p_entry_gen)) {
		/* fairness lesson (A/B measured): proceeding with NO
		 * time qualifier released JUST-WON grants their winners had
		 * not yet discovered (winner polls the slot at <=25ms; the
		 * nudge-driven bast lands in us) — dlm_fairness starved
		 * nodes to 10/50 rounds (gen churn 200/s on the hot ino as
		 * wins kept being stolen).  Require the orphan shape to have
		 * PERSISTED >=250ms on the resource-scoped clock (survives
		 * icache eviction + local gen churn): 10x the worst poll
		 * gap, so a live winner always consumes first — while the
		 * hot-dir convoy's per-handoff tax drops 3000ms -> ~250ms. */
		u64 p15o_rs = mxfs_v5_dlm_inode_orphan_clock_get(
					mp->m_mxfs_dlm, ip->i_ino, false);

		if (p15o_rs != 0 &&
		    ktime_get_ns() - p15o_rs >= 250ULL * NSEC_PER_MSEC) {
			static atomic_t p15o_n = ATOMIC_INIT(0);

			orphan_live = false;	/* proceed: anchored unlock below */
			if (atomic_inc_return(&p15o_n) <= 100)
				pr_warn("mxfs: P15-ORPH-PROCEED ino=%llu gen=%u age_ms=%llu — persistent idle orphan; proceeding to anchored release\n",
					(unsigned long long)ip->i_ino, p_rel_gen,
					(unsigned long long)((ktime_get_ns() - p15o_rs) /
							     NSEC_PER_MSEC));
		}
	}
	/* — TCP twin of P15-ORPH-PROCEED.  Instrumented
	 * PROVEN at 32/tcp drc r6 (test2 ino=48234625): an ABANDONED mirror
	 * grant (gen 2448, never consumed — no P74-GRANT for it) aborted the
	 * serialized release 5993x over 126s.  The starving reader's own
	 * perpetual ACQUIRING reset every existing escape (280-strike counter
	 * never passed ~38; wall clocks pinned at 0 — P15H fired 0x), while
	 * the master starved 8 PR waiters behind our phantom EX
	 * (P-LKTIMEOUT-HOLDER held_ms=126854) = the cluster-wide 125s verify
	 * stalls.  With acq_inflight==0 there is NO local consumer to protect
	 * (slow-path acquires hold acq_inflight for their whole lifetime incl.
	 * internal retries, and DEMOTING blocks new entries), so the "6s
	 * legitimate retry gap" does not apply — nobody is between retries.
	 * Persistence on the per-inode clock (the release work's iget ref
	 * keeps the inode alive across the loop); reset ONLY on genuine
	 * consumption (mode!=NL), never on ACQUIRING. */
	if (orphan_live && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) &&
	    mxfs_tcp_orphan_force_ms > 0 &&
	    ip->i_dlm_ex_holders == 0 && ip->i_dlm_pr_holders == 0 &&
	    ip->i_dlm_pin_count == 0 &&
	    ip->i_dlm_acq_inflight == 0 &&
	    !(p_rel_gen != 0 && p_rel_gen != p_entry_gen)) {
		u64 p15t_now = ktime_get_ns();

		if (ip->i_dlm_mode != MXFS_LOCK_NL) {
			ip->i_dlm_orphan_since_ns = 0;
		} else if (ip->i_dlm_orphan_since_ns == 0) {
			ip->i_dlm_orphan_since_ns = p15t_now;
		} else if (p15t_now - ip->i_dlm_orphan_since_ns >=
			   (u64)mxfs_tcp_orphan_force_ms * NSEC_PER_MSEC) {
			static atomic_t p15t_n = ATOMIC_INIT(0);

			ip->i_dlm_orphan_since_ns = 0;
			ip->i_dlm_orphan_strikes = 0;
			ip->i_dlm_orphan_gg = 0;
			orphan_live = false;	/* proceed: anchored unlock below */
			if (atomic_inc_return(&p15t_n) <= 200)
				mxfs_probe("mxfs: P15-TCP-ORPH-PROCEED ino=%llu gen=%u — abandoned mirror grant (no local acquirer, %ums persistent); proceeding to anchored release\n",
					(unsigned long long)ip->i_ino, p_rel_gen,
					mxfs_tcp_orphan_force_ms);
		}
	}
	/*
	 * FIX-2 — PRE-NL OBLIGATION GATE (see the knob decl
	 * for the design; PROVEN incident: crash_consistency 20260731T131837Z
	 * ino 18876678).  dd's O_SYNC append committed during the abort/
	 * re-entry window via the sub-EX writeback path (P26PRE family — no
	 * DLM holder registered), so every holder/pin/gen check below passed
	 * while pend=11 dur=6 stood at this exact point (P220-EPOCH printed
	 * it).  A release that proceeds here strands the committed change at
	 * NL where every publish path correctly refuses it; the in-core copy
	 * is then the ONLY copy until a reload adopts the stale platter and
	 * the acknowledged data is gone cluster-wide.  Defer instead — the
	 * tenure stays owned, and the re-fired pipeline's drain lands the
	 * change with authority.  Dirs keep their existing post-NL fence +
	 * close_or_defer tails (RELFLUSH authorizes that window for them).
	 * Exemptions: ISTALE (freed cluster — the image never lands by
	 * design), dead-incarnation and dlm_stale (in-core not authoritative,
	 * nothing of ours to land), shutdown (no peer obligation), and
	 * entry-NL cleanup flavors (no authority to publish anyway).
	 */
	{
		bool p236_gate = mxfs_rel_obligation_gate &&
			!S_ISDIR(vip->i_mode) &&
			ip->i_dlm_mode != MXFS_LOCK_NL &&
			READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
				READ_ONCE(ip->i_mxfs_pub_durable_seq) &&
			!xfs_iflags_test(ip, XFS_ISTALE) &&
			!ip->i_mxfs_dead_incarn_gen &&
			!ip->i_dlm_stale &&
			!xfs_is_shutdown(mp);

	if (ip->i_dlm_ex_holders > 0 || ip->i_dlm_pr_holders > 0 ||
	    ip->i_dlm_pin_count > 0 ||
	    (!p15h_reap && p_rel_gen != 0 && p_rel_gen != p_entry_gen) ||
	    orphan_live || p236_gate ||
	    rel_drain_wb_err || rel_drain_inv_err) {
		bool gen_moved = (p_rel_gen != 0 && p_rel_gen != p_entry_gen);
		bool pin_only = !gen_moved &&
				ip->i_dlm_ex_holders == 0 &&
				ip->i_dlm_pr_holders == 0 &&
				ip->i_dlm_pin_count > 0;
		bool obligation_only = p236_gate && !gen_moved &&
				ip->i_dlm_ex_holders == 0 &&
				ip->i_dlm_pr_holders == 0 &&
				ip->i_dlm_pin_count == 0 &&
				!orphan_live;
		/* D-512 cycle-2 (ruling): drain-error fail-stop.
		 * drain_hard  = writeback of this tenure's dirty pages FAILED —
		 *   the unlock must never publish (the peer would adopt a
		 *   platter missing data this node's apps observed); terminal.
		 * drain_retry = residual pages survived invalidate (pinned
		 *   folio / re-dirty race) — keep the grant and retry via the
		 *   CACHED+bast_pending dwork re-arm; an unrevokable pin holds
		 *   the grant for as long as it exists. */
		bool drain_hard = rel_drain_wb_err != 0;
		bool drain_retry = !drain_hard && rel_drain_inv_err != 0;

		/*
		 * LIVELOCK FIX (test1 panic, serial-log proven:
		 * ~35-deep mxfs_dlm_ilock_begin recursion -> stack guard page ->
		 * "Fatal exception in interrupt"): when the abort fires because a
		 * grant arrived MID-DRAIN (gen_moved), that grant is OURS and
		 * LIVE — the correct post-abort state is CACHED, not BAST.
		 * Leaving state=BAST sends the woken EDEADLK waiter back to the
		 * slow path (dir fast path is state-gated), whose re-request
		 * EDEADLKs against our own held grant and self-demotes again ->
		 * every lap grants gen+1 mid-drain -> abort -> unbounded
		 * recursion.  With CACHED the waiter fast-paths on the granted
		 * mode.  A peer whose request is still queued re-BASTs via its
		 * ACQUIRE_WAIT retry (<=6s), so no starvation.  The plain
		 * holders-race abort (gen unchanged) keeps the proven BAST
		 * re-arm.
		 */
		/*
		 * FIX-A state choice: a PIN-ONLY abort must ALSO leave
		 * CACHED (not BAST) — state=BAST gates the dir fast path, so
		 * the pinned creator's FIX3 re-lock would take the slow path
		 * and EDEADLK against its own grant (the recursion
		 * storm).  CACHED + bast_pending gives the fast re-lock AND
		 * defers the release to the unpin quiescent arm
		 * (pinned_resource.c CACHED&&bast_pending).
		 */
		/*
		 * FIX-H2 state choice: a PURE orphan-live abort (no
		 * holders/pin/gen-move — the grant is mid-completion or
		 * stranded) must go back to NONE, not CACHED: with CACHED the
		 * next peer BAST lands in a mode==NL arm that parks it as
		 * state=BAST with zero holders — the run46 dead-end nothing
		 * ever consumes (r12: hstate=2 wedge, 184s hold).  With NONE
		 * the next BAST re-enters the NONE/NL P135 arm -> GRANTWIN-
		 * PARK -> dwork -> strike escalation terminates the loop.
		 */
		bool orphan_only = orphan_live && !gen_moved &&
				   ip->i_dlm_ex_holders == 0 &&
				   ip->i_dlm_pr_holders == 0 &&
				   ip->i_dlm_pin_count == 0;
		/* FIX-2: an obligation-only defer keeps the tenure and
		 * must leave the dir/file fast path open (CACHED, like the pin
		 * abort) — the 25ms dwork re-fire below re-runs the pipeline
		 * whose drain lands the change, then the release completes. */
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = orphan_only ? MXFS_DLM_ISTATE_NONE :
				  (gen_moved || pin_only || obligation_only ||
				   drain_hard || drain_retry) ?
					MXFS_DLM_ISTATE_CACHED :
					MXFS_DLM_ISTATE_BAST;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		/*
		 * v3 (tds pace: node1 18/150 rounds, ~3.3s/handoff):
		 * CACHED alone left the requesting PEER waiting for its 6s
		 * ACQUIRE_WAIT retry — nothing on this node re-fired the
		 * release once the admitted waiter finished.  Arm the pending-
		 * BAST flag; the last ilock_end fires bast_process (see the
		 * CACHED&&bast_pending arm there), so the peer is served right
		 * after the waiter's op instead of on its timeout.
		 */
		if (gen_moved || pin_only || orphan_live || obligation_only ||
		    drain_retry) {
			if (!ip->i_dlm_bast_pending)
				ip->i_dlm_dwork_strikes = 0;	/* v0.10.31 */
			ip->i_dlm_bast_pending = true;
		}
		spin_unlock(&ip->i_dlm_lock);
		/*
		 * FIX-H2: keep the strike sampler alive without peer
		 * traffic — re-arm the MHT dwork so the next sample runs in
		 * ~25ms (completion typically lands in 0.5-2ms; a strand hits
		 * 4 strikes in ~100ms and gets released).
		 */
		if (orphan_only || obligation_only || drain_retry) {
			/* 2026-07-16 (32/caw test4 panic, P-DBLRECLAIM assert):
			 * igrab, never raw ihold — this can race ip's own
			 * eviction; resurrecting i_count arms a phantom dwork
			 * whose final xfs_irele runs a SECOND evict (BUG3
			 * family; same pattern as P134-ILEND-FREEING). */
			if (igrab(vip)) {
				ip->i_dlm_bastq_src = orphan_only ? 14 :
						      drain_retry ? 22 : 21;
				if (!mxfs_bast_arm_queue_delayed(ip,
					msecs_to_jiffies(
					    mxfs_relab_backoff_ms(ip, p_rel_gen))))
					xfs_irele(ip);	/* dwork already armed */
			} else {
				mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=%s i_state=0x%lx (inode evicting; skipping dwork re-arm)\n",
					(unsigned long long)ip->i_ino,
					orphan_only ? "orphan_rearm" :
					drain_retry ? "drain_rearm" :
						      "obligation_rearm",
					mxfs_istate(vip));
			}
		}
		/* design-consult ruling (c): a deferred obligation LIVELOCKS if
		 * nothing converts it — once this bast returns, i_dlm_demoter is
		 * NULL and the P119 non-EX fence blocks every xfsaild flush of
		 * the committed change (measured: unlink conversions stranded
		 * until the shell died and an adjacent remove shut the node
		 * down).  Convert it HERE, inside the protected release context:
		 * the tenure is KEPT (this abort refuses the unlock), the
		 * on-disk grant is still ours, no peer grant can become
		 * effective — exactly the continuous-exclusion window the
		 * RELFLUSH sanction exists for.  Scoped: sanction set only
		 * around the call, nlink==0 conversions only (the helper
		 * declines anything else).  The 25ms dwork re-fire then finds
		 * pend==dur and the release completes. */
		if (obligation_only && !xfs_is_shutdown(mp) &&
		    VFS_I(ip)->i_nlink == 0) {
			struct xfs_perag *fpag = xfs_perag_get(mp,
					XFS_INO_TO_AGNO(mp, ip->i_ino));

			if (fpag) {
				int frc;

				xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);
				frc = mxfs_iflush_agino_target(fpag,
					XFS_INO_TO_AGINO(mp, ip->i_ino),
					jiffies + msecs_to_jiffies(500));
				xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
				mxfs_probe_ratelimited("mxfs: P245-REL-OBLIGATION-CONVERT ino=%llu rc=%d pend=%llu dur=%llu flush=%llu\n",
					(unsigned long long)ip->i_ino, frc,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq);
				xfs_perag_put(fpag);
			}
		}
		/* FIX-2: the defer verdict, always-on + capped (this is
		 * the fix engaging — each line is one averted stranding). */
		if (obligation_only) {
			static atomic_t p236_n = ATOMIC_INIT(0);

			atomic64_inc(&mxfs_relbar_gate_defer);
			if (atomic_inc_return(&p236_n) <= 2000)
				mxfs_probe("mxfs: P236-REL-OBLIGATION-DEFER ino=%llu mode=%u pend=%llu dur=%llu flush=%llu ili_f=0x%x pin=%d in_ail=%d comm=%s realns=%llu — release deferred: committed change not yet at home (pre-NL gate)\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					atomic_read(&ip->i_pincount),
					(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					    &ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		/* D-512 cycle-2 (ruling): drain-error containment.
		 * Hard (writeback) failure: the tenure's dirty data never
		 * reached the LUN; no retry can make the release coherent and
		 * continuing to serve local state a peer can never see is the
		 * cross-node lost-update face — fail-stop.  xfs_force_shutdown
		 * withdraws this node from the DLM (D-409), so the tenure is
		 * disposed of through death/recovery (journal replay), never
		 * through a silent unlock over missing data. */
		if (drain_hard) {
			pr_err("mxfs: P-D512-REL-DRAIN-WBFAIL ino=%llu mode=%u rc=%d dirty=%d wb=%d — release drain writeback FAILED; refusing on-disk unlock and wedging\n",
				(unsigned long long)ip->i_ino, p_held_mode,
				rel_drain_wb_err,
				mapping_tagged(vip->i_mapping,
					PAGECACHE_TAG_DIRTY) ? 1 : 0,
				mapping_tagged(vip->i_mapping,
					PAGECACHE_TAG_WRITEBACK) ? 1 : 0);
			/* mxfs_inode_wedge, not bare shutdown: the wedge PINS the
			 * grant on disk so the teardown release_all cannot strip
			 * it as a clean departure — peers then fence and RECOVER
			 * this node (journal replay) instead of silently adopting
			 * a platter missing this tenure's data.  It also closes
			 * admission, refuses the pre-CAS unlock on both arms, and
			 * force-shutdowns the mount. */
			mxfs_inode_wedge(ip, NULL, false);
		} else if (drain_retry) {
			static atomic_t p34j_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p34j_n) <= 2000)
				mxfs_probe("mxfs: P-D512-REL-DRAIN-INVFAIL ino=%llu mode=%u rc=%d nrpages=%lu — residual pages survived the release invalidate; unlock refused, grant kept, dwork retry armed\n",
					(unsigned long long)ip->i_ino,
					p_held_mode, rel_drain_inv_err,
					vip->i_mapping->nrpages);
		}
		/* A holder raced in during the drain — keep the grant.
		 * OR the tenure gen ADVANCED during the drain
		 * (an upgrade grant landed whose waiter has not incremented
		 * holders yet) — releasing now would unlock the waiter's fresh
		 * grant and let the master hand EX to a peer while the waiter
		 * modifies on a phantom cached EX (the dir_reuse same-aoff
		 * concurrent-add loss).  Keep the new tenure; the waiter's
		 * ilock_end re-fires this bast once it finishes. */
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		/* capped, NOT ratelimited — run68's wedge
		 * post-mortem was blinded exactly here (the abort print was
		 * ratelimit-suppressed during the rm/create storm). */
		{
			static atomic_t p15_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p15_n) <= 6000) {
				u64 dbg_now = ktime_get_ns();
				u64 age_orph_ms = ip->i_dlm_orphan_since_ns ?
					(dbg_now - ip->i_dlm_orphan_since_ns) / NSEC_PER_MSEC : 0;
				u64 age_starve_ms = ip->i_dlm_bast_starve_since_ns ?
					(dbg_now - ip->i_dlm_bast_starve_since_ns) / NSEC_PER_MSEC : 0;
				mxfs_probe(
			    "mxfs: P15-REL-ABORT ino=%llu held_mode=%u ex=%u pr=%u pin=%u gen_moved=%d orph=%d entry_gen=%u now_gen=%u init_seq=%u age_orph_ms=%llu age_starve_ms=%llu — holder re-acquired during drain; release aborted, BAST re-armed (P58 averted)\n",
				(unsigned long long)ip->i_ino, p_held_mode,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count, gen_moved ? 1 : 0,
				orphan_live ? 1 : 0,
				p_entry_gen, p_rel_gen, ip->i_dlm_init_seq,
				age_orph_ms, age_starve_ms);
			}
		}
		wake_up_all(&ip->i_dlm_wait);
		return;
	}
	}	/* FIX-2 p236_gate scope */
	}
	/*
	 * FIX-A (design review priority-2, D-RELEASE-BARRIER TOCTOU) — the
	 * LAST gate, at the terminal store itself.  The P236 gate above and
	 * the holders checks pass on a snapshot; the release drain's own
	 * writeback then generates ioend-conversion commits (FIX-25 admit)
	 * that advance pend AFTER the gate evaluated — P220 measured pend=9
	 * dur=5 crossing here 0.4ms after xfs_iomap_write_unwritten
	 * committed, and the board census showed 9 blind discharges at NL
	 * (P241, three with in-core strictly ahead of the platter) that are
	 * unreachable by the EX-only merge protections.  P220 was
	 * print-and-proceed; this makes the condition DEFER exactly like
	 * the P236 obligation arm: keep the tenure, re-arm the 25ms dwork,
	 * let the re-fired pipeline's drain land the change, then release.
	 * The FIX-25 admit takes i_dlm_lock, so no new admit can begin
	 * inside this held section; an existing admit holds ex_holders and
	 * aborted above.  Residue = a bare sub-EX committer (no DLM holder
	 * registered) racing the few instructions to the store — P220 stays
	 * armed after this fix precisely to measure that residue.
	 * Exemptions mirror P236 (dirs keep their post-NL fence tails;
	 * ISTALE/dead-incarnation/dlm_stale/shutdown have nothing of ours
	 * to land).
	 */
	if (mxfs_rel_obligation_gate && !S_ISDIR(vip->i_mode) &&
	    READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
	    READ_ONCE(ip->i_mxfs_pub_durable_seq) &&
	    !xfs_iflags_test(ip, XFS_ISTALE) &&
	    !ip->i_mxfs_dead_incarn_gen &&
	    /* the i_dlm_stale exemption is GONE — dss census proved
	     * 459/459 leaked tenure-ends carried dstale=1 dss=5, i.e. the
	     * release pipeline's OWN next-tenure cache-invalidate mark at
	     * mxfs_dlm_bast_process (src=5) — the gate disarmed itself on
	     * every release it was built for (P244=0 across two boards).
	     * i_dlm_stale is read-cache staleness of the NEXT tenure; it
	     * says nothing about whether OUR committed writes landed.  The
	     * true nothing-to-land classes stay exempt: ISTALE (cluster
	     * freed), dead_incarn_gen (landing would clobber a peer's live
	     * reuse — P32D refuses those flushes), shutdown.  design review:
	     * no legitimate class with pend!=dur, dstale=1, dinc=0,
	     * !ISTALE where the handoff is correct; safe default for an
	     * unexplained open obligation is retain-the-grant. */
	    !xfs_is_shutdown(mp)) {
		/*
		 * 0.75.49 (D-PEER-TRUNCATE-UNDER-HOT-APPENDER-167-236MS-0922,
		 * and the s528p acquire deadline behind a live holder).
		 *
		 * MEASURED on the 2-node TCP rig (tests/peer_truncate_under_
		 * append_2node.sh s527h, appender-side trace for ino 5740): the
		 * peer's truncate waited 167-236 ms while this gate deferred
		 * 21 times in a row, ~4 ms apart, every time with exactly ONE
		 * commit unlanded (pend = dur + 1).  The shape of every retry
		 * was the same: the drain ENTERED with the local appender
		 * already admitted (ex=1), landed everything but that holder's
		 * commit, deferred here with the state reset to CACHED, and the
		 * appender's own ilock_end re-fired the pipeline ~100 us later
		 * — by which time the appender was inside its next write again,
		 * because CACHED had reopened the fast path to it.  The loop
		 * ended only when a scheduling gap let one retry enter with
		 * ex=0.  With both nodes appending (append_contention s528p)
		 * the same loop drove the re-arm backoff to its 1 s cap and,
		 * once the holder's writer paused, the peer sat behind a 1 s
		 * dwork and its acquire deadline expired (P-LKTIMEOUT-REMOTE,
		 * the D-0912 fail-stop family).
		 *
		 * The obligation is REAL but LIVE: it is the commit the local
		 * writer made while this drain ran, and one more flush lands
		 * it — provided the writer is not admitted again in between.
		 * So when the pending sequence advanced during THIS drain on a
		 * regular file, leave the state at BAST (the file yield gate
		 * parks new user admissions there; the demote-wait wakes on
		 * the release) and re-fire the pipeline at once, streak
		 * untouched.  A defer whose obligation did NOT advance during
		 * the drain is the genuinely stuck case the backoff was built
		 * for (a fenced victim whose writes cannot land) and keeps the
		 * CACHED + backoff re-arm.  Directories never reach this gate.
		 */
		bool live_commit = S_ISREG(vip->i_mode) &&
			READ_ONCE(mxfs_file_yield_on_demote) &&
			READ_ONCE(ip->i_mxfs_pub_pending_seq) != p_pend_entry;

		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = live_commit ? MXFS_DLM_ISTATE_BAST :
					       MXFS_DLM_ISTATE_CACHED;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		if (!ip->i_dlm_bast_pending)
			ip->i_dlm_dwork_strikes = 0;
		ip->i_dlm_bast_pending = true;
		/* 0.75.50: a live defer is progress, not the stuck case the
		 * backoff streak measures — do not let it count toward the
		 * 1 s cap a later genuine stall would inherit. */
		if (live_commit)
			ip->i_dlm_relab_streak = 0;
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		spin_unlock(&ip->i_dlm_lock);
		atomic64_inc(&mxfs_relbar_gate_defer);
		{
			static atomic_t p244_n = ATOMIC_INIT(0);
			u64 p244_now = ktime_get_ns();

			/* 0.75.50: the P138 stage split, on the defer exit too —
			 * s529a showed two drains of ~120 ms ending here with no
			 * way to name the stage.  a=log_force+alloc-drain,
			 * b=settle+ail-drain+flush, c=pagecache, d=durable loop,
			 * t=entry->here; all us. */
			if (atomic_inc_return(&p244_n) <= 2000)
				mxfs_probe("mxfs: P244-REL-TERMINAL-DEFER ino=%llu pend=%llu dur=%llu flush=%llu pend_entry=%llu live=%d ili_f=0x%x t_us=%llu a=%llu b=%llu b1=%llu b2=%llu c=%llu c1=%llu c2=%llu d=%llu comm=%s realns=%llu — obligation landed between the pre-NL gate and the terminal store; release deferred at the last gate\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					(unsigned long long)p_pend_entry,
					live_commit ? 1 : 0,
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					(unsigned long long)((p244_now - p131_t0) / 1000),
					/* 0.75.54 stage order: a, c (pages), b (settle+
					 * drain+flush), d — each field is its own stage's
					 * duration. */
					(unsigned long long)(p2s_a ? (p2s_a - p131_t0) / 1000 : 0),
					(unsigned long long)((p2s_b && p2s_c) ? (p2s_b - p2s_c) / 1000 : 0),
					(unsigned long long)((p2s_b1 && p2s_c) ? (p2s_b1 - p2s_c) / 1000 : 0),
					(unsigned long long)((p2s_b2 && p2s_b1) ? (p2s_b2 - p2s_b1) / 1000 : 0),
					(unsigned long long)((p2s_c && p2s_a) ? (p2s_c - p2s_a) / 1000 : 0),
					(unsigned long long)((p2s_c1 && p2s_a) ? (p2s_c1 - p2s_a) / 1000 : 0),
					(unsigned long long)((p2s_c && p2s_c1) ? (p2s_c - p2s_c1) / 1000 : 0),
					(unsigned long long)((p2s_d && p2s_b) ? (p2s_d - p2s_b) / 1000 : 0),
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		/*
		 * 0.75.51: the live re-fire goes through the ordinary delayed
		 * arm with delay 0 — immediate when nothing is pending, and
		 * COALESCED onto a pending arm's timer otherwise.  0.75.50
		 * pulled a pending arm forward (mod_delayed_work) and was
		 * MEASURED to change nothing for the peer truncate (240/138/
		 * 227 ms vs 220/119) while making the two-node alternating
		 * line append 4.5x slower (18.4 vs 4.1 ms per append, s530e vs
		 * s529d): with the writer parked and the release re-fired at
		 * once, every append became its own hand-off, where the
		 * pending arm's ~10 ms had let each node batch a run of
		 * appends per tenure.  The residual truncate cost is in the
		 * drain's stage c (page flush/invalidate, ~120 ms once per
		 * lap) and stage b, named by the split on the P244 line.
		 */
		if (igrab(vip)) {
			ip->i_dlm_bastq_src = 22;
			if (!mxfs_bast_arm_queue_delayed(ip, live_commit ? 0 :
				msecs_to_jiffies(
				    mxfs_relab_backoff_ms(ip, p_rel_gen))))
				xfs_irele(ip);	/* dwork already armed */
		} else {
			mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=terminal_rearm i_state=0x%lx (inode evicting; skipping dwork re-arm)\n",
				(unsigned long long)ip->i_ino, mxfs_istate(vip));
		}
		wake_up_all(&ip->i_dlm_wait);
		return;
	}
	/*
	 * (D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO, design-consult
	 * ruling) — ADMISSION GATE, honored at the terminal store.  An open
	 * whose admission re-read keeps losing the race to this store (proven
	 * 0.11.482 cache_coherency test23: NL landed 16us before the re-read
	 * on a live published file, cat got fail-closed -EIO) arms
	 * i_mxfs_open_admit_n after a few plain cold-open restarts.  While
	 * armed, ONLY the terminal demotion is delayed: the grant is kept
	 * (CACHED), the BAST stays pending and the 25ms dwork re-fires the
	 * pipeline, exactly like the P236/P244 obligation defers.  Checked
	 * under i_dlm_lock — open_protect arms it before its re-acquire, so
	 * a release reaching this gate after the arm defers, which bounds
	 * the open's restart loop.  Contention must never become -EIO.
	 * Shutdown exempt: the open fails at the shutdown fence anyway and
	 * releases must not strand at teardown.
	 */
	if (atomic_read(&ip->i_mxfs_open_admit_n) > 0 && !xfs_is_shutdown(mp)) {
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		if (!ip->i_dlm_bast_pending)
			ip->i_dlm_dwork_strikes = 0;
		ip->i_dlm_bast_pending = true;
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		spin_unlock(&ip->i_dlm_lock);
		{
			static atomic_t p95g_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p95g_n) <= 2000)
				mxfs_probe("mxfs: P95-OPEN-ADMIT-DEFER ino=%llu mode=%u admits=%d comm=%s realns=%llu — open admission in critical section; terminal demotion deferred\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode,
					atomic_read(&ip->i_mxfs_open_admit_n),
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		if (igrab(vip)) {
			ip->i_dlm_bastq_src = 23;
			if (!mxfs_bast_arm_queue_delayed(ip,
				msecs_to_jiffies(
				    mxfs_relab_backoff_ms(ip, p_rel_gen))))
				xfs_irele(ip);	/* dwork already armed */
		} else {
			mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=admit_gate_rearm i_state=0x%lx (inode evicting; skipping dwork re-arm)\n",
				(unsigned long long)ip->i_ino, mxfs_istate(vip));
		}
		wake_up_all(&ip->i_dlm_wait);
		return;
	}
	/*
	 * D-0971 terminal guard, under i_dlm_lock and BEFORE the NL store:
	 * direct I/O still in flight here means the pre-drain wait was
	 * skipped (a holder at entry that has since finished its ride with
	 * its bios outstanding) — the release does not commit.  Keep the
	 * grant and the BAST state, so the completion is admitted and no new
	 * ride starts, and re-fire the pipeline at once; the next pass enters
	 * with no holder and waits.  The detector after the store stays as
	 * telemetry and must now read zero.
	 */
	if (mxfs_rel_dio_wait && atomic_read(&vip->i_dio_count) > 0 &&
	    !xfs_is_shutdown(mp)) {
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		if (!ip->i_dlm_bast_pending)
			ip->i_dlm_dwork_strikes = 0;
		ip->i_dlm_bast_pending = true;
		ip->i_dlm_relab_streak = 0;	/* progress, not a stuck release */
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		spin_unlock(&ip->i_dlm_lock);
		atomic_inc(&mxfs_rel_dio_defer);
		{
			static atomic_t p971d = ATOMIC_INIT(0);

			if (atomic_inc_return(&p971d) <= 200)
				mxfs_probe("mxfs: P971-REL-DIO-DEFER ino=%llu mode=%u dio=%d entry_holders=%u comm=%s — direct I/O still in flight at the terminal store; release deferred, grant kept\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode,
					atomic_read(&vip->i_dio_count),
					p_entry_holders, current->comm);
		}
		if (igrab(vip)) {
			ip->i_dlm_bastq_src = 24;
			if (!mxfs_bast_arm_queue_delayed(ip, 0))
				xfs_irele(ip);	/* dwork already armed */
		} else {
			mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=dio_rearm i_state=0x%lx (inode evicting; skipping dwork re-arm)\n",
				(unsigned long long)ip->i_ino, mxfs_istate(vip));
		}
		wake_up_all(&ip->i_dlm_wait);
		return;
	}
	/* every abort arm has passed — the release is now committed.
	 * Announce release-begin BEFORE the mode store and (further below) the
	 * peer-visible slot release, so the certificate leaves the proving
	 * states ahead of anything a peer can observe. */
	mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
	/*
	 * capture the tenure identity the tokens of this tenure
	 * carry (same fields the buf-item capture reads: resource, epoch,
	 * lineage) in the SAME critical section that commits the release.
	 * begin_release retains them; the NL store's revoke backstop clears
	 * them.  A cluster-routed tenure is NOT certified here: its slot is
	 * released by the cluster pipeline when the last covered inode goes,
	 * and a per-inode marker would certify a tenure still writing
	 * (counted; fail-closed at replay until the cluster path marks).
	 */
	if (ip->i_mxfs_auth_epoch &&
	    ip->i_mxfs_auth_kind == MXFS_LTYPE_INODE &&
	    !ip->i_dlm_routed_iclus) {
		p_rel_res = ip->i_mxfs_auth_resource;
		p_rel_epoch = ip->i_mxfs_auth_epoch;
		p_rel_lineage = ip->i_mxfs_auth_lineage;
	} else if (ip->i_mxfs_auth_epoch) {
		atomic64_inc(&mxfs_relmark_iclus_unmarked);
	}
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_mode = MXFS_LOCK_NL;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);	/* v0.5.1: grant lost — invalidate epoch-stamped dentries */
	ip->i_dlm_bast_starve_since_ns = 0;	/* a real release just completed */
	ip->i_dlm_relab_streak = 0;	/* release committed — abort-backoff episode over */
	spin_unlock(&ip->i_dlm_lock);

	/*
	 * Detector (measure before deciding a fix): an asynchronous direct I/O
	 * drops its IOLOCK — and with it the DLM holder count — when submission
	 * returns -EIOCBQUEUED, while its bios are still in flight; nothing in
	 * this pipeline waits for i_dio_count.  Count every release committed
	 * with direct I/O still outstanding on the inode.
	 */
	if (unlikely(atomic_read(&vip->i_dio_count) > 0)) {
		static atomic_t p_reldio_n = ATOMIC_INIT(0);

		atomic_inc(&mxfs_rel_dio_inflight);
		if (atomic_inc_return(&p_reldio_n) <= 64)
			mxfs_probe("mxfs: P-REL-DIO-INFLIGHT ino=%llu dio=%d qsrc=%u comm=%s — release committed with direct I/O still in flight\n",
				(unsigned long long)ip->i_ino,
				atomic_read(&vip->i_dio_count),
				ip->i_dlm_bastq_src, current->comm);
	}

	/* build-1 injection (see mxfs_openprotect_park_ms decl):
	 * prolong the natural {NL, DEMOTING, RELFLUSH-set} post-store tail so
	 * the opener's admission ride deterministically lands inside it.  50ms
	 * slices so a shutdown mid-park is honored promptly. */
	if (unlikely(mxfs_openprotect_park_ms) && !xfs_is_shutdown(mp)) {
		int park = min(mxfs_openprotect_park_ms, 5000);
		int slept = 0;
		static atomic_t p95p_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p95p_n) <= 500)
			mxfs_probe("mxfs: P95-OPEN-PARK ino=%llu park_ms=%d comm=%s realns=%llu — bast_process parked post-terminal-store (injection)\n",
				(unsigned long long)ip->i_ino, park,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
		while (slept < park && !xfs_is_shutdown(mp)) {
			msleep(50);
			slept += 50;
		}
	}

	/* SEQUENCE TRACE (always-on, dir only): record every real
	 * release-to-NL so we can reconstruct release->re-grant ordering vs
	 * the fast-path re-acquires and the peers' commits.  Resolves the
	 * contradiction (does the clobberer ever release EX?).
	 * run14d: gated mxfs.dirwr/mxfs.instr for ship. */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    S_ISDIR(vip->i_mode))
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: P-DIR-SEQ REL ino=%llu gen=%llu realns=%llu",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ip->i_dlm_dir_gen,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * sess38: close the async CIL->AIL flush race (P64) for dir inodes.
	 *
	 * The earlier log_force+ail_push pair can run BEFORE this dir
	 * inode's buffer log item is added to the AIL — xlog_cil_committed
	 * runs on a kworker AFTER xfs_log_force(SYNC) returns, so at flush
	 * time the dinode is not yet dirty-in-AIL and never gets iflushed;
	 * the quiesce-buf barrier below then finds a clean buf with no
	 * in-flight bio and passes.  xfsaild iflushes the inode AFTER we
	 * release the DLM (captured: P64 xfs_iflush ~2ms post-release), so
	 * the dirent change lands on disk after the peer has already
	 * reloaded a stale copy.  For concurrent same-name mkdir this is
	 * the split-brain: the peer misses our just-committed entry and
	 * allocates a SECOND inode for the same name.
	 *
	 * Wait (bounded) until the inode is no longer pinned (changes still
	 * in the CIL) and no longer in the AIL (dirty buffer not yet
	 * written), re-driving the per-AG push each round.  We do NOT
	 * release early while still dirty — proceeding on a dirty inode is
	 * the invariant-#1 violation that regressed Mode A (sess32
	 * v0.3.141-142).  A single inode flush converges in a few ms; the
	 * bound only guards against a wedged item.
	 */
	if (S_ISDIR(vip->i_mode)) {
		xfs_agnumber_t	d_agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		int		w;
		bool		data_durable = false;
		long long	p_loopexit_size = -1;

		{
			extern unsigned long long mxfs_watch_ino;

			if (unlikely(mxfs_watch_ino) &&
			    ip->i_ino == mxfs_watch_ino)
				mxfs_probe("mxfs: PW-RELFENCE-IN ino=%llu fmt=%d nx=%llu size=%lld pin=%d in_ail=%d fields=0x%x comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format,
					(unsigned long long)ip->i_df.if_nextents,
					(long long)ip->i_disk_size,
					atomic_read(&ip->i_pincount),
					ip->i_itemp && test_bit(XFS_LI_IN_AIL,
						&ip->i_itemp->ili_item.li_flags) ? 1 : 0,
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}

		for (w = 0; ; w++) {
			struct xfs_inode_log_item *d_iip;
			bool in_ail;
			bool pinned;
			bool pre_in_ail = ip->i_itemp &&
				test_bit(XFS_LI_IN_AIL,
					 &ip->i_itemp->ili_item.li_flags);
			bool pre_pinned = atomic_read(&ip->i_pincount) > 0;

			/*
			 * the break condition must cover the dir DATA
			 * blocks, not just the dinode.  A dir block still dirty
			 * / pinned / in-flight at release races a peer's FUA
			 * read (-> missing dirent or EFSBADCRC shutdown).  Check
			 * data durability under i_lock and keep draining (incl.
			 * cross-AG dir extents) until both inode and data blocks
			 * are durable.  (regular-file dinode-flush wait
			 * tested here — NO correctness gain + latency/shutdown
			 * regression, so the file empty-content is reader-side,
			 * not writer di_size durability.  Kept dir-only.)
			 */
			if (!mxfs_drain_ilock_read(ip))
				break;	/* FS shutdown — no peer obligation */
			/*
			 * sess57 (ccloop 8ddb16a2) — instrumented race fix for the
			 * residual tcp_dlm_scaling/dlm_fairness durable dirent
			 * RESURRECTION.  Sample in_ail/pinned UNDER the ilock,
			 * AFTER the (blocking) acquire — NOT before it.
			 * mxfs_drain_ilock_read SPINS (down_read_trylock+msleep)
			 * until an mv that holds ILOCK_EXCL for its rename
			 * finishes: xfs_trans_commit PINS the dir inode (CIL)
			 * then releases the ILOCK.  The OLD code sampled
			 * in_ail/pinned BEFORE this acquire, so a sub-ms rename
			 * that committed while we spun was read as its pre-commit
			 * CLEAN value -> the loop broke "clean" with the just-
			 * committed dirent REMOVAL stranded in the AIL at NL ->
			 * released stale -> P119-NONEX in_ail=1 -> P-CLMERGE
			 * overlaid stale disk and RESURRECTED it (PROVEN sess56
			 * ino=8929665, P51-REL drain_ms=0).  Sampling after the
			 * acquire makes the committed change visible (pinned in
			 * the CIL) so the drain destages it before handoff.
			 */
			d_iip = ip->i_itemp;
			in_ail = d_iip &&
				test_bit(XFS_LI_IN_AIL,
					 &d_iip->ili_item.li_flags);
			pinned = atomic_read(&ip->i_pincount) > 0;
			data_durable = mxfs_dir_data_durable(ip);
			up_read(&ip->i_lock);

			/* instrumented PROOF probe: the blocking ilock acquire
			 * waited out an in-flight rename whose commit landed
			 * AFTER our pre-acquire sample.  The OLD code would have
			 * released this dir stale -> resurrection.  Always-on,
			 * ratelimited. */
			if ((in_ail || pinned) && !pre_in_ail && !pre_pinned)
				mxfs_probe_ratelimited(
				    "mxfs: P57-DRAIN-RACE-CAUGHT ino=%llu w=%d in_ail=%d pinned=%d — commit landed during blocking ilock acquire (old code released stale)\n",
				    (unsigned long long)ip->i_ino, w,
				    in_ail, pinned);

			if (!in_ail && !pinned && data_durable) {
				if (mxfs_dir_relverify &&
				    mxfs_drain_ilock_read(ip)) {
					mxfs_dir_data_release_verify(ip);
					up_read(&ip->i_lock);
				}
				/*
				 * GFS2-style demote-invalidate.  Every
				 * dir block is now durable + out of the AIL, so
				 * drop the cache copies (hard-stale) — no stale
				 * buffer survives this handoff to be reflushed
				 * over a peer's later add (the dir_reuse 799 loss).
				 * Consumes i_lock(read); re-acquire via the same
				 * ABBA-safe trylock idiom as the flush path.
				 */
				if (mxfs_dir_release_stale &&
				    mxfs_drain_ilock_read(ip))
					mxfs_dir_stale_clean_data_blocks_relsafe(ip);
				/*
				 * (design review WRITEBACK-COMPLETION-
				 * BARRIER) — the decisive fix.  data_durable proved
				 * every dir block is clean + out of the AIL + (with
				 * relverify) disk==incore AT THIS INSTANT, but that is
				 * blind to a dir-metadata write bio THIS node already
				 * SUBMITTED that has not yet PHYSICALLY completed: if
				 * it lands after we hand EX to a peer (who cold-reads +
				 * RMWs + rewrites the block) it durably reverts the
				 * peer's committed dirent (dir_reuse readdir=799 ->
				 * DABUF_MAP_HOLE).  Block the handoff until every
				 * in-flight dir-metadata write bio has completed.
				 * Bounded (10s); a shutting-down/unmounting FS has no
				 * coherency obligation so it bails.  Runs off
				 * the bast/CAW worker (process ctx) so blocking is
				 * safe; the bio ioend that decrements the counter runs
				 * independently of this thread (no deadlock).
				 */
				if (mxfs_dir_wr_barrier) {
					int wb;
					for (wb = 0; wb < 5000 &&
						     atomic_read(&mp->m_mxfs_dir_wr_inflight) > 0 &&
						     !xfs_is_shutdown(mp) &&
						     !xfs_is_unmounting(mp); wb++)
						msleep(2);
					/* ( a864): ALWAYS-ON when the wait was
					 * substantial — a FULL-bound (10s) wait with inflight
					 * still >0 is the wr-count LEAK signature (P51-REL
					 * drain_ms=20s convoy freeze); it must be visible in
					 * default runs, not only under instr. */
					if (wb * 2 >= 1000)
						pr_warn_ratelimited(
						    "mxfs: P40-WRBARRIER-LONG ino=%llu waited=%dms inflight=%d — leak-suspect: dir EX release stalled on the wr-count barrier\n",
						    (unsigned long long)ip->i_ino,
						    wb * 2,
						    atomic_read(&mp->m_mxfs_dir_wr_inflight));
					else if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
						mxfs_probe_ratelimited(
						    "mxfs: P40-WRBARRIER ino=%llu waited=%dms inflight=%d — dir EX release drained in-flight dir-block writes before handoff\n",
						    (unsigned long long)ip->i_ino,
						    wb * 2,
						    atomic_read(&mp->m_mxfs_dir_wr_inflight));
				}
				break;
			}

			/*
			 * never let the fence wedge teardown.  If the FS
			 * is shutting down or unmounting, writeback can't complete
			 * (device targp being torn down) — stop spinning + leaking
			 * a module ref (proven this session: unbounded waits left
			 * refcnt>0 after umount -> wedged unmount).  A shutdown FS
			 * has no coherency obligation to a peer.
			 */
			if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
				break;

			/*
			 * RELEASE CHECKPOINT FENCE (design review, design-consult).
			 * The proven durable lost-update root: the OLD
			 * bounded loop (w<100, ~200ms) pushed via
			 * xfs_ail_push_ag_sync / mxfs_dir_push_data_ags, but the
			 * AIL push CANNOT write a PINNED buffer (the async
			 * xlog_cil_committed unpin tail) — it skips it.  So a dir
			 * block committed-but-not-checkpointed stayed pinned, the
			 * loop gave up at w==100 (P-SF-DURABLE-FAIL), and the DLM
			 * lock was handed to a peer with the block NEVER landed on
			 * the shared store.  The peer then reads a stale block, and
			 * our late checkpoint writes our (now divergent) image over
			 * the peer's committed dirent = lost update.
			 *
			 * Fix: actively xfs_bwrite every dir DATA block.  xfs_bwrite
			 * WAITS for the buffer's own pin to drain (xfs_buf_wait_unpin)
			 * then writes it synchronously to the shared SCST target, so
			 * the block is genuinely landed (visible to a peer's plain
			 * read under fua_disable=1) before we release.  This is the
			 * loop CONDITION now (data_durable), so unlike the reverted
			 * Fix A (which kept the bounded loop and could still
			 * proceed un-durable) we NEVER release with an un-landed dir
			 * block.  Runs on system_wq (immediate BAST) or the holder's
			 * process ctx (deferred) — NOT the CAW poll thread — so the
			 * blocking xfs_bwrite is safe here.  UNBOUNDED with a ~30s
			 * hard backstop that SHUTS DOWN (never hands off an un-durable
			 * lock — design review Inv 1) rather than silently releasing stale.
			 */
			xfs_log_force(mp, XFS_LOG_SYNC);
			xfs_ail_push_ag_sync(mp->m_ail, d_agno);
			/* (design review): the per-AG push above drains only the
			 * dir INODE's AG; a grown dir's DATA/leaf blocks live in
			 * OTHER AGs.  Push the WHOLE AIL to completion so every
			 * dir block this tenure committed is home-written (visible
			 * to the peer's cold-read) before the DLM unlock — closing
			 * the multi-AG / off-extent-map enumeration gap that leaves
			 * an undestaged stale base for the intra-block double-alloc.
			 * Bounded so a wedged AIL can't hang; the data_durable
			 * re-check + ~15s shutdown backstop below keeps Invariant 1. */
			if (mxfs_dir_release_ail_all > 0)
				xfs_ail_push_all_sync_bounded(mp->m_ail,
						(unsigned int)mxfs_dir_release_ail_all);
			if (!mxfs_drain_ilock_read(ip))
				break;	/* FS shutdown — no peer obligation */
			/* ABBA-safe — snapshots daddrs under i_lock,
			 * DROPS i_lock, then flushes (consumes the lock). */
			mxfs_dir_flush_data_blocks_relsafe(ip);

			if (w >= 15000) {
				pr_warn_ratelimited("mxfs: P97-RELFENCE-WEDGE ino=%llu in_ail=%d pinned=%d data_durable=%d — shutdown (un-durable dir lock NOT released)\n",
					(unsigned long long)ip->i_ino,
					in_ail, pinned, data_durable);
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
				break;
			}
			msleep(2);
		}
		{
			extern unsigned long long mxfs_watch_ino;

			if (unlikely(mxfs_watch_ino) &&
			    ip->i_ino == mxfs_watch_ino)
				mxfs_probe("mxfs: PW-RELFENCE-OUT ino=%llu w=%d fmt=%d nx=%llu size=%lld pin=%d in_ail=%d fields=0x%x data_durable=%d realns=%llu\n",
					(unsigned long long)ip->i_ino, w,
					ip->i_df.if_format,
					(unsigned long long)ip->i_df.if_nextents,
					(long long)ip->i_disk_size,
					atomic_read(&ip->i_pincount),
					ip->i_itemp && test_bit(XFS_LI_IN_AIL,
						&ip->i_itemp->ili_item.li_flags) ? 1 : 0,
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					data_durable ? 1 : 0,
					(unsigned long long)ktime_get_real_ns());
		}

		/* DIAGNOSTIC (always-on, rate-limited): catch a dir
		 * BAST-release that proceeds with the dir block NOT durable
		 * — that releases a stale dir block to a peer (the rename
		 * missing-dirent: peer reads disk missing our later entries).
		 * the loop is now unbounded (breaks only on durability
		 * or the 15000 shutdown backstop), so a high w is NOT itself a
		 * failure — only !data_durable is. */
		if (!data_durable)
			mxfs_probe_ratelimited("mxfs: P-SF-DURABLE-FAIL ino=%llu waited=%d "
				"in_ail=%d pinned=%d data_durable=%d\n",
				(unsigned long long)ip->i_ino, w,
				ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags),
				atomic_read(&ip->i_pincount) > 0,
				data_durable);
		mxfs_idbg("mxfs: P-SF-DURABLE ino=%llu waited=%d "
			"in_ail=%d pinned=%d data_durable=%d realns=%llu\n",
			(unsigned long long)ip->i_ino, w,
			ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags),
			atomic_read(&ip->i_pincount) > 0,
			data_durable,
			(unsigned long long)ktime_get_real_ns());

		/*
		 * (design review demote-drain assertion, instrumented): dump EVERY dir
		 * data-fork buffer's destage state at the moment we are about to
		 * release the dir EX lock.  Per design review, the release fence discovers
		 * blocks by the CURRENT format walk, which can miss a block across
		 * the sf<->block boundary, leaving it committed-unwritten
		 * (in_ail && logged_seq!=written_seq) at handoff -> peer RMWs a
		 * stale base -> durable lost update.  If P16-RELEASE-UNDESTAGED
		 * fires, the demote-drain gap is CONFIRMED.
		 */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    mxfs_drain_ilock_read(ip)) {
			struct xfs_iext_cursor	icur16;
			struct xfs_bmbt_irec	got16;
			unsigned int		bb16 =
				XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

			mxfs_probe("mxfs: P16-RELEASE-DUMP ino=%llu fmt=%d dir_gen=%u "
				"inode_in_ail=%d\n",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format, ip->i_dlm_dir_gen,
				ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags));
			if (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
			    (ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
			     !xfs_need_iread_extents(&ip->i_df))) {
				for_each_xfs_iext(&ip->i_df, &icur16, &got16) {
					xfs_daddr_t ds, de, d;

					if (got16.br_startblock == HOLESTARTBLOCK)
						continue;
					ds = XFS_FSB_TO_DADDR(mp, got16.br_startblock);
					de = ds + XFS_FSB_TO_BB(mp, got16.br_blockcount);
					for (d = ds; d + bb16 <= de; d += bb16) {
						struct xfs_buf *b16 = NULL;
						struct xfs_buf_log_item *bi16;

						if (xfs_buf_incore(mp->m_ddev_targp,
						    d, bb16, 0, &b16) != 0 || !b16)
							continue;
						bi16 = b16->b_log_item;
						mxfs_probe("mxfs: P16-RELEASE-UNDESTAGED ino=%llu daddr=%lld in_ail=%d dirty=%d pin=%d delwri=%d done=%d lseq=%u wseq=%u undest=%d buf_gen=%u\n",
						    (unsigned long long)ip->i_ino,
						    (long long)d,
						    !!(bi16 && test_bit(XFS_LI_IN_AIL,
							&bi16->bli_item.li_flags)),
						    !!(bi16 && test_bit(XFS_LI_DIRTY,
							&bi16->bli_item.li_flags)),
						    xfs_buf_ispinned(b16),
						    !!(b16->b_flags & _XBF_DELWRI_Q),
						    !!(b16->b_flags & XBF_DONE),
						    b16->b_mxfs_logged_seq,
						    b16->b_mxfs_written_seq,
						    mxfs_dir_buf_is_undestaged(b16),
						    b16->b_mxfs_dir_gen);
						xfs_buf_relse(b16);
					}
				}
			}
			up_read(&ip->i_lock);
		}

		/*
		 * (D-0491) instrumented instrument, always on, capped: the
		 * same committed-unwritten census as the reclaim-side probe, at
		 * the point the release pipeline has finished draining and is
		 * about to hand the grant off.  A nonzero count here with the
		 * entry mode below EX is the lost-dirent shape one step before
		 * the fence refuses the re-land; a nonzero count at EX is a
		 * drain that did not finish its job.
		 */
		if (mxfs_drain_ilock_read(ip)) {
			struct mxfs_dir_undest_census	rc491;
			int	rc491rc = mxfs_dir_undest_census(ip, &rc491);
			int	rf4_unknown = 0;
			long	rf4 = mxfs_f4_open_for_dir(mp, ip->i_ino,
						       &rf4_unknown);

			up_read(&ip->i_lock);
			if (rc491rc != 0 || rc491.undest || rc491.inail ||
			    rc491.locked || rf4) {
				static atomic_t p491r_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p491r_n) <= 400)
					mxfs_probe("mxfs: P491-REL-UNDEST ino=%llu fmt=%d held_mode=%u gmode=%u rc=%d undest=%d inail=%d locked=%d cached=%d f4_open=%ld f4_unknown=%d first_daddr=%lld lseq=%llu wseq=%llu has_bli=%d done=%d data_durable=%d comm=%s — release pipeline past its drain with committed-unwritten data blocks cached\n",
						(unsigned long long)ip->i_ino,
						ip->i_df.if_format, p_held_mode,
						mxfs_v5_dlm_inode_granted_mode(
							mp->m_mxfs_dlm, ip->i_ino),
						rc491rc, rc491.undest, rc491.inail,
						rc491.locked, rc491.cached,
						rf4, rf4_unknown,
						(long long)rc491.first_daddr,
						(unsigned long long)rc491.first_lseq,
						(unsigned long long)rc491.first_wseq,
						rc491.first_has_bli, rc491.first_done,
						data_durable ? 1 : 0,
						current->comm);
			}
		}

		/*
		 * sess-tcp (instrumented, PROVEN — tcp_dlm_scaling durable lost-update):
		 * a SHORTFORM dir stores its dirents INLINE in the dinode, so the
		 * data-block drain above lands NOTHING (data_durable is vacuously
		 * true for fmt!=EXTENTS/BTREE) and the loop exits as soon as the dir
		 * INODE item leaves the AIL.  But an inode leaving the AIL only means
		 * the cluster buffer reached the SCST target WRITE-CACHE — a peer's
		 * FUA read pierces that cache to the PLATTER and sees the stale
		 * dinode.  PROVEN root: node2's `mv n2_rN n2_rN.done` removal of the
		 * source dirent never reached the platter before the dir-EX handoff;
		 * a self/peer reacquire-reload FUA-read the stale platter image and
		 * the removed dirent was durably RESURRECTED (leftover n2_r6 nlink=1,
		 * both nodes agree, survives drop_caches; P62-RELOAD-FORK-SHRINK
		 * disk_size=19 at the reload).  Block/leaf dirs are covered by
		 * mxfs_dir_flush_data_blocks (xfs_bwrite + blkdev flush) above;
		 * SHORTFORM dirs were NOT.  Make the inode cluster platter-durable
		 * via the same deterministic sequence the create path uses
		 * (mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_durable: log_force
		 * → imap_to_bp → iflush_cluster → delwri_submit → blkdev_issue_flush)
		 * BEFORE the on-disk DLM unlock, so the peer's first FUA read after
		 * handoff sees our committed shortform image.  This is a FLUSH (in-
		 * core → platter), NOT an evict — it cannot lose data and cannot
		 * resurrect a stale entry (the force-evict-on-release was
		 * REFUTED for exactly that reason).  i_lock is NOT held here (the
		 * drain loop up_read'd it); the helper self-guards LOCAL + multinode. */
		p_loopexit_size = (long long)ip->i_disk_size;
		/*
		 * skip this ~hundreds-of-ms log_force+iflush+blkdev_flush
		 * when the dir is PROVABLY clean (we held it read-only / non-EX, no
		 * dirty inode item, not awaiting destage in the AIL, unpinned).  A
		 * read-only holder committed nothing, so there is nothing to make
		 * durable before handoff — the flush is pure waste and it amplifies
		 * the symmetric PR->EX upgrade livelock to ~440ms/op.  Excludes every
		 * dirty/in-AIL/pinned case, so the sess-tcp resurrection fix (which
		 * needs a committed-but-undestaged dinode) is untouched.
		 */
		p_clean_release = (p_held_mode != MXFS_LOCK_EX) &&
			xfs_inode_clean(ip) &&
			!(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags)) &&
			atomic_read(&ip->i_pincount) == 0;
		/*
		 * skip the drain on a clean SELF-demote (P109 EDEADLK upgrade
		 * recovery; no peer reads our state) — kills the tcp_dlm_scaling PR->EX
		 * upgrade-livelock amplifier.  A genuine peer handoff keeps the drain:
		 * its log_force/destage is the coherency-masking barrier the BLOCK/LEAF
		 * dir-heavy tests (dir_reuse, rsync_paired) rely on to not RMW/flush a
		 * stale dir block.  (p_shortform is logged for analysis only — a
		 * SHORTFORM skip was TESTED and REGRESSED dir_reuse, whose sf->block
		 * conversion-divergence race is exactly the shortform-growth phase.)
		 * param>=2 = broad (skip every clean release; fastest, removes masking).
		 */
		p_shortform = S_ISDIR(vip->i_mode) &&
			ip->i_df.if_format == XFS_DINODE_FMT_LOCAL;
		/* ROOT FIX: call the UNGATED variant.  The gated
		 * wrapper no-ops on TCP (Road B per-op gate), which silently
		 * disabled THIS release-path destage too — the run60/61 all-node
		 * dir3_block_verify daddr-0x48 tear (platter dinode stale nx=1
		 * while platter block 0 already XDD3 from a block->leaf convert).
		 * Invariant #1 requires the inode cluster durable before unlock. */
		if (!(mxfs_dir_pr_release_fast && p_clean_release &&
		      (mxfs_dir_pr_release_fast >= 2 || p_self_demote))) {
			__mxfs_dlm_dir_inode_durable(ip);
			ip->i_mxfs_lastrel_flag = 1;
		} else {
			ip->i_mxfs_lastrel_flag = 2;
		}
		/* last-release ledger for P-SFDIR-REVERT. */
		ip->i_mxfs_lastrel_ns = ktime_get_real_ns();
		ip->i_mxfs_lastrel_size = (uint64_t)ip->i_disk_size;

		/* sess-tcp instrumented VERIFY: after the shortform cluster flush, FUA-read
		 * the on-disk dinode and compare its di_size to our in-core di_size.
		 * MATCH => release-side durability works (the platter reflects our
		 * committed dir image before handoff).  disk < incore => the flush did
		 * NOT land our latest committed dirents (the durable lost-update root).
		 * Gated; fires per dir release. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled ||
			     mxfs_dir_relverify) &&
		    S_ISDIR(vip->i_mode) &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL) {
			extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);
			uint64_t p_disk = mxfs_inode_disk_di_size(ip, NULL, NULL);

			mxfs_probe("mxfs: P-SFREL-VERIFY ino=%llu loopexit_size=%lld incore_size=%lld disk_size=%llu %s exh=%d prh=%d state=%u realns=%llu\n",
				(unsigned long long)ip->i_ino,
				p_loopexit_size,
				(long long)ip->i_disk_size,
				(unsigned long long)p_disk,
				((uint64_t)ip->i_disk_size == p_disk) ? "DURABLE" : "STALE-DISK",
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_state,
				(unsigned long long)ktime_get_real_ns());
		}

		/* (instrumented, gap-B VERIFY, ALWAYS-ON): for a GROWN (non-LOCAL)
		 * dir, FUA-read the on-disk dinode AFTER the release flush and compare
		 * di_size AND di_nextents to in-core.  disk < incore => the extent map
		 * was NOT made durable at release (gap-B broken / not reached) and the
		 * peer's FUA read will see a stale-small map (re-alloc/tear root).
		 * This is the decisive measurement of whether gap-B holds for the
		 * grown-dir case the test actually hits. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_dir_relverify) &&
		    S_ISDIR(vip->i_mode) && p_held_mode == MXFS_LOCK_EX &&
		    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);
			uint64_t p_disk = mxfs_inode_disk_di_size(ip, NULL, NULL);
			bool stale = p_disk != (uint64_t)-1 &&
				     p_disk < (uint64_t)ip->i_disk_size;

			mxfs_probe_ratelimited("mxfs: P68-GROWREL-VERIFY ino=%llu incore_size=%lld disk_size=%llu incore_nx=%llu %s\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_disk_size,
				(unsigned long long)p_disk,
				(unsigned long long)ip->i_df.if_nextents,
				stale ? "STALE-DISK(gap-B-broken)" : "DURABLE");
		}

		/* instrumented decisive probe — see mxfs_dir_bmbt_release_audit. */
		mxfs_dir_bmbt_release_audit(ip);

		/*
		 * DECISIVE DETECTOR (gated mxfs.instr): the drain loop
		 * above claims data_durable, and the dir blocks were just
		 * bwritten (so disk and in-core share the same LSN — no LSN
		 * skew to confuse a whole-block FUA compare).  If a dir block
		 * still DIFFERS from disk here, the release-side durability
		 * GUARANTEE IS BROKEN: we are about to hand the dir lock to a
		 * peer whose FUA-read will MISS our committed dirents (the
		 * durable lost-update root).  Direction-aware in practice: at
		 * this point in-core can only be AHEAD of disk (our committed
		 * entries not on the platter).  Reuses the AG FUA-compare.
		 * run14d: re-gated behind mxfs.dirwr/mxfs.instr for
		 * ship — one synchronous FUA read per cached dir block per
		 * release, diagnostic only. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled ||
			     mxfs_dir_relverify) &&
		    ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS) {
			extern int mxfs_ag_buf_disk_differs(struct xfs_buf *);
			extern int mxfs_diff_detail;
			struct xfs_iext_cursor	dcur;
			struct xfs_bmbt_irec	dgot;
			unsigned int		dbb =
				XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

			down_read(&ip->i_lock);
			for_each_xfs_iext(&ip->i_df, &dcur, &dgot) {
				xfs_daddr_t	ds, de, d;

				if (dgot.br_startblock == HOLESTARTBLOCK)
					continue;
				ds = XFS_FSB_TO_DADDR(mp, dgot.br_startblock);
				de = ds + XFS_FSB_TO_BB(mp, dgot.br_blockcount);
				for (d = ds; d + dbb <= de; d += dbb) {
					struct xfs_buf	*xbp = NULL;
					int		diff;

					if (xfs_buf_incore(mp->m_ddev_targp, d,
							   dbb, XBF_TRYLOCK,
							   &xbp) != 0 || !xbp)
						continue;
					diff = mxfs_ag_buf_disk_differs(xbp);
					if (diff != 0) {
						int	diff2;

						mxfs_probe_ratelimited("mxfs: P-DIRREL-DIFFERS ino=%llu daddr=%lld diff=%d in_ail=%d pin=%d delwri=%d done=%d\n",
							(unsigned long long)ip->i_ino,
							(long long)d, diff,
							!!(xbp->b_log_item && test_bit(XFS_LI_IN_AIL, &xbp->b_log_item->bli_item.li_flags)),
							xfs_buf_ispinned(xbp),
							!!(xbp->b_flags & _XBF_DELWRI_Q),
							!!(xbp->b_flags & XBF_DONE));
						/*
						 * P35C (instrumented, run14d): the bwrite
						 * completed yet the FUA compare still sees the
						 * old medium image.  Distinguish "write parked
						 * in the SCST write cache" (SYNCHRONIZE CACHE
						 * destages it; diff2=0) from "write lost
						 * outright" (diff2 stays 1).  The verdict picks
						 * the fix: flush-before-stale vs hunting a lost
						 * write.
						 */
						mxfs_blkdev_flush_epoch(mp);
						mxfs_diff_detail = 1;
						diff2 = mxfs_ag_buf_disk_differs(xbp);
						mxfs_diff_detail = 0;
						mxfs_probe("mxfs: P35C-DIFF-AFTER-FLUSH ino=%llu daddr=%lld diff2=%d\n",
							(unsigned long long)ip->i_ino,
							(long long)d, diff2);
					}
					xfs_buf_relse(xbp);
				}
			}
			up_read(&ip->i_lock);
		}

		/*
		 * NOTE (instrument step 2a — REVERTED): adding a deterministic
		 * xfs_log_force(SYNC)+mxfs_dir_flush_data_blocks here BEFORE the evict
		 * DID eliminate DIR-STALE-SKIP/P-EVICT-SKIP (pinned blocks became
		 * durable+unpinned), but it made rename_visibility WORSE (2→24 fails):
		 * unpinning let the evict below invalidate MANY more blocks, and the
		 * post-evict re-reads returned STALE content under fua_disable=1
		 * (the reread does not reliably pull a peer's just-committed dir block
		 * from the SCST target) → node4 lost ALL its renames on every node.
		 * Conclusion: the evict+reread coherency premise is broken under
		 * fua_disable=1; the real blocker is dir-block reread staleness, NOT
		 * the pinned-skip alone.  Reverted.
		 */
		/*
		 * RELEASE PUBLISH-AND-DISCARD (design-consult design,
		 * `docs/history/session-98-gpt-fix-design.md`): now that the dir data blocks are
		 * durable on the shared target, xfs_buf_stale() them rather than
		 * merely clearing XBF_DONE.  The proven root is that a
		 * cleared-DONE buffer stays on the per-node delwri/AIL writeback
		 * path, so xfsaild later re-flushes a SUPERSEDED in-core image
		 * over a peer's newer committed dirents (active-count oscillates).
		 * Staling drops _XBF_DELWRI_Q (no future writeback of this image)
		 * and removes the buffer from cache (next acquire cold-reads the
		 * peer's merged block) — buffer-level coherency that makes even
		 * fast-path EX grants safe.  (Old behavior: mxfs_dir_evict_data_
		 * blocks, clear-DONE only — failed ~4× because the buffer could
		 * still be re-flushed/re-dirtied.)
		 */
		/*
		 * run14d (PROVEN, P35E lineage + 189 P99-STALE-SKIPs):
		 * fast-path EX creates keep re-dirtying dir blocks between the
		 * durability fence's last check and this stale pass (TOCTOU).
		 * A skipped block survives on this node's writeback path with
		 * committed-unwritten dirents; the lock is handed off anyway,
		 * the peer RMWs the on-disk image, and one side's dirents are
		 * durably lost.  Iterate flush→stale until a pass skips
		 * nothing.  The fastex window is bounded by the yield quantum,
		 * so this converges; the bound only guards a wedge (on
		 * exhaustion we proceed = old behavior, but logged).
		 */
		{
			int	sretry, nskip = 0;

			for (sretry = 0; sretry < 500; sretry++) {
				down_read(&ip->i_lock);
				nskip = mxfs_dir_stale_data_blocks(ip);
				up_read(&ip->i_lock);
				if (nskip == 0)
					break;
				if (xfs_is_shutdown(mp) ||
				    xfs_is_unmounting(mp))
					break;
				xfs_log_force(mp, XFS_LOG_SYNC);
				if (!mxfs_drain_ilock_read(ip))
					break;
				/* ABBA-safe snapshot+drop+flush. */
				mxfs_dir_flush_data_blocks_relsafe(ip);
				msleep(1);
			}
			if (nskip)
				mxfs_probe_ratelimited("mxfs: P35F-STALE-RETRY-EXHAUSTED ino=%llu nskip=%d tries=%d\n",
					(unsigned long long)ip->i_ino,
					nskip, sretry);
		}
	}

	/*
	 * CANDIDATE FIX (rename_visibility dir-miss): bump this dir
	 * inode's i_dlm_dir_gen as we release it to a peer on BAST.  This node
	 * is GIVING UP the dir to a peer that may modify it, so our cached dir
	 * blocks become potentially stale.  The per-read hook (xfs_da_read_buf)
	 * refreshes blocks whose stamp < i_dlm_dir_gen — but i_dlm_dir_gen only
	 * bumped on the slow-path ACQUIRE (mxfs_dlm_ilock_begin), which a
	 * lock_flags=0 lookup/readdir SKIPS.  So a peer renames, BASTs us, we
	 * release here, then our verify-phase lookup (lock_flags=0) reads our
	 * STALE cached dir block (gen unchanged) and misses the peer's rename
	 * (the test_rename_visibility miss).  Bumping the gen HERE (on the
	 * BAST-release, the node being demoted) makes our next lookup's read
	 * hook invalidate+refresh.  SAFE vs the gen-0 regression: (1) only fires
	 * on a real BAST (peer took the lock), not a blanket read, so a
	 * same-node create+stat (cross_write_read) is NOT bumped between → own
	 * target-cached dirent stays visible (no FUA re-read of own undurable
	 * writes); (2) the dir-data durability wait above already flushed our
	 * own changes to the platter, so a later refresh re-reads durable
	 * content.  NEEDS TESTING (next session): rename_visibility should
	 * improve; cross_write_read + unlink_visibility are the regression
	 * canaries and must still PASS.
	 */
	/* VALIDATION RESULT: the combo (this gen-bump + sync_iflush=1) gave
	 * STILL ~45 rename_visibility misses (NOT 0) AND timed out cross_write_read
	 * → the two-part theory is INCOMPLETE (a residual dir-miss persists even
	 * with own-durability + BAST-refresh) AND sync_iflush is too slow. Both
	 * REVERTED. (gen-bump removed below.)
	 * the bast-gen-bump candidate (ip->i_dlm_dir_gen++ here) was
	 * REVERTED — it reduced rename_visibility misses ~3× BUT broke
	 * cross_write_read (rc=1, EACCES) just like the gen-0 fix: cross_write_read
	 * DOES get BAST'd (4 nodes contend the shared dir), so the gen bumps, then
	 * a node's create-after-BAST dirent (target-cached, not platter-durable)
	 * is MISSED by the gen-bump-triggered FUA refresh (FUA pierces the
	 * per-initiator iSCSI cache to the platter).  CONFIRMS the dual constraint
	 * is fundamental: ANY dir-block refresh misses own target-cached writes.
	 * Real fix needs dir WRITES platter-durable (FUA-write / per-op flush) so
	 * FUA reads see own writes — NOT a refresh mechanism. */

	/*
	 * v0.3.124 FIX: wait for any in-flight inode-cluster-buf
	 * iflush to complete before releasing DLM.
	 *
	 * Captured trace at iter-1 fail: P64 (xfs_iflush) for ino
	 * 128 fired ~2ms AFTER P55 (post-bast_process disk read).  An
	 * iflush bio was still in flight (or triggered after) when
	 * bast_process thought it was done.  After release, the bio
	 * completes and writes to disk — by which time the peer has
	 * already acquired and modified.  T1's late write overwrites
	 * T2's just-released content.
	 *
	 * Fix: take an xfs_buf_lock on the inode cluster buf (waits for
	 * any in-flight bio), then immediately release.  This is a
	 * cheap barrier — if no bio is in flight, it returns instantly.
	 * If one is in flight, we wait for completion.  After this
	 * barrier, we can safely release the DLM lock.
	 */
	if (S_ISDIR(vip->i_mode)) {
		struct xfs_buf	*p_quiesce_bp = NULL;
		if (xfs_imap_to_bp(mp, NULL, &ip->i_imap, &p_quiesce_bp) == 0) {
			/* xfs_imap_to_bp auto-locks.  At this point any
			 * in-flight bio on this buf has completed (lock
			 * was held by writer thread for the duration of
			 * its submission, but bios complete asynchronously
			 * so the lock may not be the right barrier).
			 *
			 * Be more aggressive: explicitly wait for completion
			 * via xfs_buf_iowait if the buf has XBF_ASYNC.
			 */
			mxfs_idbg("mxfs: P70-INSTR ino=%llu PRE-UNLOCK-BARRIER "
				"flags=0x%x realns=%llu\n",
				(unsigned long long)ip->i_ino,
				p_quiesce_bp->b_flags,
				(unsigned long long)ktime_get_real_ns());
			xfs_buf_relse(p_quiesce_bp);
		}
	}

	/*
	 * cross-node di_size durability for REGULAR FILES.  Metadata
	 * writes are NOT FUA, so a just-created file's dinode reaches the SCST
	 * write cache (or only the AIL) but not the backing store; a peer that
	 * BASTs us and FUA-reads the inode cluster from the backing store reads
	 * di_size=0 -> EMPTY file.  Mirror the dir-inode release durability
	 * SAFELY (no raw out-of-band write — that corrupts): drive the dinode
	 * iflush (log_force + per-AG AIL push) so the normal write path writes
	 * the cluster (CRC/verify intact), quiesce any in-flight bio on the
	 * cluster buffer, then blkdev_issue_flush so the write reaches the
	 * platter before the peer's FUA read.  gated mxfs_reg_release_durable
	 * (default on) so it can be A/B'd against the perf cost.
	 */
	/*
	 * PROVEN shortform-dir lost-update FIX.  The dir drain loop
	 * above (mxfs_dir_data_durable) flushes a dir's DATA-fork blocks, but a
	 * SHORTFORM (LOCAL) directory has NO data blocks — its dirents live
	 * inline in the DINODE.  The loop's break condition (!in_ail && !pinned)
	 * is met while the committing transaction is still in the CIL (neither
	 * flag set transiently), so the LAST committer's just-added dirent is
	 * released to a peer with the in-place dinode still STALE on the platter
	 * → the peer FUA-reads the old dinode and the entry vanishes (proven
	 * P-SFDIR-RELOAD timeline: count=4 add → peer/self re-reads count=3,
	 * node's own file durably lost — the 90/120 "lost its own files").  The
	 * async xfs_ail_push the loop uses is trylock-based and can skip the
	 * in-place write entirely.  Run the SAME deterministic inode-cluster
	 * flush the regular-file path uses (log_force → imap_to_bp →
	 * iflush_cluster → bwrite → blkdev_flush) so the dinode (carrying the
	 * shortform dirents) is PLATTER-durable before the DLM release.  The
	 * early-out below skips a clean inode, so no rsync_paired regression.
	 * Applies to all directory inodes: for EXTENTS dirs it makes the
	 * dinode (di_size / extent map) durable too, complementing the
	 * data-block drain.
	 */
	if ((S_ISREG(vip->i_mode) && mxfs_reg_release_durable) ||
	    S_ISDIR(vip->i_mode) ||
	    /*
	     *  FIX-1: FREED inodes (mode=0) whose ifree
	     * is still CIL/AIL-only.  The inactivation unlock now DEFERS for
	     * these (P128-INACT-DEFER, grant kept cached), so the peer's BAST
	     * arrives here with the corpse undestaged — the platter still
	     * carries the prior ALIVE incarnation and the acquirer would
	     * certify a corpse as alive.  Run the same deterministic cluster
	     * flush so mode=0 lands before the unlock.  Clean freed inodes
	     * skip (condition false) — no cost on the common path.
	     */
	    ((vip->i_mode & S_IFMT) == 0 &&
	     (atomic_read(&ip->i_pincount) > 0 ||
	      (ip->i_itemp &&
	       (ip->i_itemp->ili_fields ||
		test_bit(XFS_LI_IN_AIL,
			 &ip->i_itemp->ili_item.li_flags)))))) {
		struct xfs_buf	*r_bp = NULL;
		int		rerr = 0;
		int		rtry;
		bool		flushed = false;

		/*
		 * FIX — cross_write_read empty-content
		 * (design review design-consult).  The deterministic loop below flushes the
		 * inode CLUSTER (di_size + extent map) but NOT the dirty DATA
		 * PAGES.  A small regular file written but not fsync'd (e.g. the
		 * 33-byte .md5 sidecar) keeps its content in the local dirty
		 * page cache; on BAST-release we made di_size durable but never
		 * wrote the data block, so the peer's FUA read of the platter
		 * hits an unwritten/zeroed block and reads EMPTY.  Flush + wait
		 * the page cache FIRST (resolves delalloc/unwritten extents and
		 * updates the in-core extent map) so the subsequent cluster
		 * flush exposes a fully-resolved map pointing at destaged data.
		 * No-op (cheap) when the mapping is clean — preserves the
		 * rsync_paired already-durable early-out perf for private files.
		 * Data-before-metadata ordering: pages out here, blkdev flush at
		 * reg_durable_done destages them before the DLM slot is released.
		 */
		/*
		 * DRAIN SITE 2 — the ABBA site (D-BAST-WRITEBACK-ABBA-DEADLOCK).
		 * `ip->i_dlm_mode = MXFS_LOCK_NL` has already run above, so every
		 * nest-admit in mxfs_dlm_ilock_begin now fails (mode NL < any
		 * request) and a concurrent writeback SUBMITTER holding a folio
		 * lock parks in the demote-wait.  This flush then takes folio
		 * locks — write_cache_pages -> writeback_get_folio ->
		 * folio_lock() is UNCONDITIONAL and operates on a batch fetched
		 * by dirty tag, so it blocks on a folio the parked submitter
		 * holds even after that submitter cleared the dirty bit.  The
		 * cycle is closed by mxfs_ilock_admit_ioend admitting the
		 * submitter (FIX-26 for EX, FIX-27 for the SHARED first lock
		 * xfs_map_blocks actually takes).
		 */
		if (S_ISREG(vip->i_mode)) {
			static atomic_t p28s2 = ATOMIC_INIT(0);

			/* Site-2 ENTRY counter.  Distinguishes "the ABBA
			 * collision was set up and survived" from "the drain
			 * never had a dirty folio to walk, so nothing could
			 * collide" — without it, an A/B arm that simply never
			 * reached the hazard reads identically to one the fix
			 * protected.  dirty= is the precondition: an already
			 * clean mapping takes no folio locks at all. */
			if (atomic_inc_return(&p28s2) <= 2000)
				mxfs_probe("mxfs: P28-DRAINSITE2 ino=%llu dirty=%d writeback=%d — entering the post-mode-clear page flush (ABBA site)\n",
					(unsigned long long)ip->i_ino,
					mapping_tagged(vip->i_mapping,
						PAGECACHE_TAG_DIRTY) ? 1 : 0,
					mapping_tagged(vip->i_mapping,
						PAGECACHE_TAG_WRITEBACK) ? 1 : 0);
			mxfs_dbg_rel_pause(ip, 4);
			ip->i_dlm_drain_stalled = 0;
			ip->i_dlm_drain_site = 2;
			/*
			 * Wake the demote-wait before taking folio locks.
			 * A writeback submitter that parked earlier (e.g. while
			 * this inode was ACQUIRING, when the mirror still read
			 * NL and mxfs_ilock_admit_ioend therefore had to refuse
			 * it) is holding a folio we are about to block on.  Its
			 * in-loop admit re-check is otherwise driven only by
			 * FIX-24's 3s poll, so the cycle would persist for up
			 * to 3s per round even with FIX-27 on -- measured: the
			 * arm-0 wedge's waiter had P47 state=4 g2=0 and was
			 * admitted only later at state=3 g2=5.  Waking here
			 * makes it re-evaluate against the state that admits
			 * it (DEMOTING + mirror EX/PR) immediately.  Spurious
			 * wakeups on a wait_event are free.
			 */
			wake_up_all(&ip->i_dlm_wait);
			mxfs_drain_watch_arm(&p2_drain_watch, ip, 2);
			rel_drain_wb_err = filemap_write_and_wait(vip->i_mapping);
			mxfs_drain_watch_disarm(&p2_drain_watch);
			if (unlikely(mxfs_dbg_rel_fail(ip, 3)))
				rel_drain_wb_err = -EIO;
			ip->i_dlm_drain_site = 0;
			/*
			 * D-512 cycle-2 (ruling): drain site 2 is the
			 * data-page flush the peer's post-release read DEPENDS on
			 * (the cross_write_read empty-content fix above).  A
			 * failure here means the peer will read zero/stale blocks
			 * for data this node's apps observed.  i_dlm_mode is
			 * already NL at this point, so no abort/re-arm surgery:
			 * wedge — pin the grant on disk (teardown cannot strip
			 * it; peers fence + recover us via journal replay), close
			 * admission, refuse the downstream unlock CAS (both arms
			 * check WEDGED pre-CAS), and force-shutdown.
			 */
			if (rel_drain_wb_err) {
				pr_err("mxfs: P-D512-DRAIN2-WBFAIL ino=%llu rc=%d — post-NL data flush FAILED; wedging (unlock CAS will be refused)\n",
					(unsigned long long)ip->i_ino,
					rel_drain_wb_err);
				mxfs_inode_wedge(ip, NULL, false);
			}
		}

		/*
		 * (design review design-consult design, Priority 1): make this regular
		 * file's di_size DETERMINISTICALLY durable on the platter before
		 * we release the inode DLM, so the peer that BAST'd us FUA-reads
		 * the real size (not 0 -> empty content; cross_write_read).
		 *
		 * The old 50x/100ms (log_force + xfs_ail_push_ag_sync) loop was
		 * NOT deterministic: xfsaild's push uses xfs_buf_trylock, so
		 * under concurrent load the in-place dinode writeback could be
		 * skipped for the whole 100ms window; we then released with the
		 * on-disk di_size still 0 and the peer read empty (the residual
		 * cross_write_read failure, build F7BEB353).  note here
		 * proved this is cross-node inode-cluster coherency that needs
		 * the peer's inode PLATTER-DURABLE before the peer reads it.
		 *
		 * Deterministic sequence (no ILOCK held here -> no recursion;
		 * bast_process runs on the CAW poll thread):
		 *   1. xfs_log_force(SYNC) flushes the CIL checkpoint to the
		 *      journal and UNPINS the inode (xfs_iflush_cluster skips
		 *      pinned inodes, so this must precede it).
		 *   2. xfs_imap_to_bp locks + reads the inode CLUSTER buffer
		 *      (waiting out any in-flight bio) and gives us the in-core
		 *      buffer with its attached inode log items (b_li_list).
		 *   3. xfs_iflush_cluster copies the in-core inode (real
		 *      di_size) INTO the cluster buffer for every dirty inode it
		 *      can lock without blocking -- the step the trylock-based
		 *      AIL push kept skipping.  rc 0 = >=1 flushed (caller must
		 *      write+release); -EAGAIN = nothing dirty/ILOCK-contended;
		 *      other = EFSCORRUPTED (buffer already released + shutdown).
		 *   4. xfs_bwrite writes the buffer SYNCHRONOUSLY (waits for IO);
		 *      blkdev_issue_flush then destages the SCST write cache to
		 *      the platter.  Only THEN do we release the DLM, so the
		 *      peer's FUA read of the backing store sees the real size.
		 */
		/*
		 * Already-durable early-out (rsync_paired perf).  If
		 * the inode is neither in the AIL nor pinned, its in-place
		 * dinode has already been written back and is durable -> nothing
		 * to flush.  This is the common case for node-PRIVATE files
		 * (rsync_paired): a release of an already-clean inode must NOT
		 * pay a synchronous xfs_log_force + iflush + bwrite (that was a
		 * 105%->137% rsync_paired regression).  Only the genuinely-dirty
		 * case (a peer BAST'd us off a just-written file before
		 * writeback) runs the deterministic flush below.
		 */
		/*
		 * the early-out is SAFE for regular files but WRONG for
		 * directories.  A shortform dirent add commits into the CIL;
		 * for a brief window the inode log item is NOT yet in the AIL
		 * and NOT pinned, yet the in-place dinode is STALE on disk.  The
		 * early-out would declare it "durable" and skip the flush — the
		 * proven shortform lost-update (last committer's entry vanishes).
		 * For dirs, ALWAYS fall through to the deterministic loop whose
		 * first action (xfs_log_force SYNC) pushes the CIL→AIL and makes
		 * the subsequent iflush_cluster+bwrite write the real dinode.
		 */
		/* ICLUSTER batching NOTE: a cut that
		 * skipped this per-inode durable pipeline for routed inodes
		 * (deferring to make_durable at the cluster release) LOST
		 * writer data: the deferred window let a stale-disk adopt
		 * (grant_seq handoff) revert an in-core size still in
		 * log/AIL — the writer's OWN .md5 went size-0 durably,
		 * cluster-wide (cache_coherency@8 8 fails/node).  Any future
		 * batching must first make the adopt path log/AIL-aware
		 * (never adopt over committed-not-in-place state).  Keep the
		 * per-inode pipeline until then. */
		if (S_ISREG(vip->i_mode) &&
		    (!ip->i_itemp ||
		     !test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags)) &&
		    atomic_read(&ip->i_pincount) == 0 &&
		    !mxfs_dbg_relog_force_armed(ip)) {
			flushed = true;
			goto reg_durable_done;
		}

		/*
		 * authorize THIS inode's sanctioned
		 * release flush past the P119 non-EX guard.  i_dlm_mode
		 * was set NL above (release bookkeeping) before this durable
		 * flush, so xfs_iflush_int would otherwise skip writing di_size
		 * into the cluster buffer (P119-NONEX-FLUSH-SKIP) and the peer
		 * would FUA-read di_size=0 -> empty content (cross_write_read).
		 * Cleared at reg_durable_done so the window is exactly this
		 * flush.
		 *
		 * extended to DIRECTORIES.  The
		 * "reg files only" caution left the dir release flush a
		 * NO-OP: the fall-through runs the loop for dirs, but
		 * xfs_iflush_int then refuses the copy-in at the P119 non-EX
		 * guard (P119-NONEX-FLUSH-SKIP ino=131 observed live in every
		 * release window), so the dir's grown extent map NEVER reaches
		 * the platter before the DLM handoff while its dir DATA blocks
		 * (flushed by mxfs_dir_flush_data_blocks) DO.  The acquiring
		 * peer's reload then imports the torn pair — fresh dir/freeindex
		 * blocks referencing data block N + a dinode whose extent map
		 * lacks it — and its very next create hits the dabuf-map HOLE
		 * (EFSCORRUPTED shutdown; proven: P106-EXGRANT 88.3687 →
		 * P-SFDIR-RELOAD nx=9 88.3691 → HOLE 88.3701, zero_silent_loss
		 * storm).  The release flush is sanctioned current-tenure for
		 * dirs by the same argument as reg files.
		 */
		/*
		 *  (instrumented, cross-node publish ledger).
		 *
		 * The release drain is about to publish this inode's in-core
		 * image with RELFLUSH authority — which the write-side NL guard
		 * (P56-NL-LOGGED-DIR-SKIP) deliberately exempts from every
		 * staleness check, on the argument that the on-disk grant is
		 * still held so no successor image can exist.  For a SHORTFORM
		 * directory that argument does not hold: the drain runs from a
		 * queued BAST worker, and by the time it flushes, peers have
		 * taken the dir EX and published names this node never learned
		 * about (i_dlm_dir_gen only advances on OUR OWN acquires, so
		 * dgen==lgen and every acquire-side staleness predicate reads
		 * "current").  Publishing our fork then REVERTS them.
		 *
		 * Proven by ordering every P56-DIRWRITE of one parent across all
		 * 32 nodes by wall-clock realns (tests/sf_storm_ledger.py).  In
		 * three separate rounds the dropping publish was this drain,
		 * with the same signature every time:
		 *   round 24  test2  mode=0 rf=1 comm=kworker n=3 DROPPED 4 names
		 *   round 25  test27 mode=0 rf=1 comm=kworker n=6 DROPPED 3 names
		 *   round 30  test12 mode=0 rf=1 comm=kworker n=6 DROPPED 4 names
		 * Names usually reappear (some later peer republishes a superset)
		 * but the parent's LINK COUNT never does — which is why the
		 * observable damage is a directory whose nlink under-counts its
		 * children, and, once those children are removed, underflows to
		 * nlink=1 or wraps to 4294967295 and can never be rmdir'd.
		 * (tests/logs/sfstorm_20260728_133018.)
		 *
		 * Refusing the write is not an option — it strands this node's
		 * own committed dirent (the "skip every NL dir slot"
		 * attempt stranded a freshly created dir into permanent ESTALE).
		 * The image simply has to be CORRECT: reconcile against the
		 * platter first, so what we publish is the merge of the peers'
		 * durable state with our unlanded work rather than a revert to
		 * our tenure's snapshot.  The 3-way merge (base/ours/theirs) is
		 * the existing acquire-side machinery and honours peer REMOVES
		 * via the captured base, so it cannot resurrect.
		 *
		 * Also REFUTED here, do not retry: mxfs.pub_obligation_enforce=1
		 * (land-before-release on the obligation counters) measured 4
		 * failing rounds vs 5 for the same storm with it off — the drain
		 * landing its change is not the issue; the change it lands is.
		 */
		if (S_ISDIR(vip->i_mode))
			mxfs_dir_sf_premerge_for_release(ip);

		if (S_ISREG(vip->i_mode) || S_ISDIR(vip->i_mode) ||
		    (vip->i_mode & S_IFMT) == 0)
			xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);
		/*
		 * DETECTOR (D-RELEASE-DRAIN-RELOGS-DEAD-INCARNATION-
		 * WITHOUT-TENURE-TYPEFLIP-398, second arm, measure before
		 * enforcing): the RELFLUSH publication token is granted here
		 * unconditionally, and the logged-slot write filter (P219/P222,
		 * pal/linux/xfs_buf.c) treats rf=1 as authority.  test18's
		 * clobbering write carried relflush=1 at held_mode=0 — the dir
		 * tenure verify a few lines earlier had already refused
		 * (i_dlm_icd_refused).  Count every drain that enters its durable
		 * loop with the token while the verify said the slot is not ours.
		 */
		if (ip->i_dlm_icd_refused) {
			static atomic_t p_rfnt_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p_rfnt_n) <= 2000)
				pr_warn("mxfs: P-RELFLUSH-NOTENURE ino=%llu held_mode=%u dlm_mode=%u state=%u ex_h=%d pr_h=%d orph=%d gen=%u mode=0%o — durable loop entered with the RELFLUSH token after the tenure verify refused (detector)\n",
					(unsigned long long)ip->i_ino, p_held_mode,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
					p15h_reap ? 1 : 0,
					VFS_I(ip)->i_generation, VFS_I(ip)->i_mode);
		}

		mxfs_dbg_bast_pause(ip);	/* D-0532 arm (no-op unless armed) */
		for (rtry = 0; rtry < 8; rtry++) {
			xfs_log_force(mp, XFS_LOG_SYNC);
			if (atomic_read(&ip->i_pincount) > 0) {
				msleep(2);
				continue;
			}
			r_bp = NULL;
			rerr = xfs_imap_to_bp(mp, NULL, &ip->i_imap, &r_bp);
			if (rerr || !r_bp) {
				msleep(2);
				continue;
			}
			rerr = xfs_iflush_cluster(r_bp);
			if (rerr == 0) {
				/* >=1 inode flushed into the buffer; write it
				 * out synchronously to the in-place dinode. */
				xfs_bwrite(r_bp);
				p2_loop_wrote = true;
				/*
				 * (D3 residual) wiring step 2 CORRECTED.
				 * discharged the obligation HERE with
				 * `durable = pending`.  That was wrong twice over
				 * and both errors mattered:
				 *
				 * (a) TOO EAGER.  Per the hole documented
				 *     just below, rc==0 means ">=1 inode in the
				 *     cluster flushed", NOT this one.  When our
				 *     inode was ILOCK-trylock-skipped the slot
				 *     was never written, yet the obligation was
				 *     marked discharged — erasing exactly the
				 *     signal the counter exists to carry.
				 * (b) TOO NARROW.  It was the ONLY discharge
				 *     site, so an inode landed by xfsaild or
				 *     reclaim never cleared and read "obligation
				 *     open" forever.
				 *
				 * Both are fixed by discharging at the real write
				 * completion instead: xfs_iflush stamps
				 * i_mxfs_pub_flush_seq at copy-in and
				 * xfs_iflush_finish promotes it to durable when
				 * the buffer completes without error.  xfs_bwrite
				 * is synchronous and runs that completion inline,
				 * so by the time it returns the discharge has
				 * already happened — for THIS inode only if this
				 * inode was actually in the written image.
				 */
				xfs_buf_relse(r_bp);
				/*
				 * PROVEN HOLE:
				 * xfs_iflush_cluster rc==0 means ">=1 inode in
				 * the cluster flushed", NOT "THIS inode
				 * flushed".  ino 131 (.mxfs_test, shortform
				 * parent) was ILOCK-trylock-skipped while a
				 * concurrent local stat held its ILOCK; the
				 * loop bwrote the cluster WITHOUT the new
				 * shortform dirent, declared flushed=true, and
				 * released the DLM.  The acquiring peer FUA-
				 * read the stale 36-byte fork 12ms later
				 * (t2 P-SFDIR-RELOAD count=1 @001.192 vs t1
				 * P105-REL disk_size=61 @001.183), missed the
				 * rename_visibility dirent, and double-created
				 * the dir -> the victim's whole create batch
				 * orphaned (cache_coherency 40/240).  bwrite is
				 * synchronous and xfs_iflush_done removes
				 * flushed inodes from the AIL in its ioend, so
				 * "still IN_AIL here" == "this inode was
				 * skipped" -> retry until OUR dinode is in the
				 * written buffer.
				 */
				if (!ip->i_itemp ||
				    !test_bit(XFS_LI_IN_AIL,
					      &ip->i_itemp->ili_item.li_flags)) {
					flushed = true;
					break;
				}
				mxfs_probe_ratelimited(
					"mxfs: P31-RELFLUSH-SELF-SKIPPED ino=%llu try=%d pin=%d — cluster flushed without this dinode, retrying\n",
					(unsigned long long)ip->i_ino, rtry,
					atomic_read(&ip->i_pincount));
				msleep(2);
				continue;
			}
			if (rerr == -EAGAIN) {
				/* Nothing dirty to flush: either genuinely
				 * clean (already durable) or a momentary ILOCK
				 * contention.  If the inode is no longer in the
				 * AIL it is durable -> done; else retry. */
				if (ip->i_itemp &&
				    test_bit(XFS_LI_IN_AIL,
					     &ip->i_itemp->ili_item.li_flags)) {
					xfs_buf_relse(r_bp);
					msleep(2);
					continue;
				}
				/*
				 *  (instrumented, PROVEN via
				 * P-SFDIR-REVERT ino=152 fua_cnt=0 vs
				 * P146-RELDUR flushed=1 wrote=0): "clean +
				 * not-in-AIL" is NOT proof of durable.  A
				 * P119/P17B skip in the NL window completes an
				 * iflush WITHOUT copying the dinode — the AIL
				 * item retires while the cluster buffer/LUN
				 * keep prior-incarnation bytes, and trusting
				 * that here handed the corpse to the peer
				 * (round-4 node1_f1 loss).  VERIFY: we hold
				 * the cluster buffer — compare its dinode
				 * identity against in-core.  Match => truly
				 * durable.  Mismatch => the committed state
				 * was phantom-retired and nothing will ever
				 * write it again (ili_fields were cleared):
				 * RE-LOG the core in a tiny transaction so
				 * the normal machinery lands it, then retry.
				 */
				{
					struct xfs_dinode *vdip = xfs_buf_offset(
						r_bp, ip->i_imap.im_boffset);
					uint32_t v_dgen =
						be32_to_cpu(vdip->di_gen);
					bool v_behind =
					    be32_to_cpu(vdip->di_gen) !=
						VFS_I(ip)->i_generation ||
					    (be16_to_cpu(vdip->di_mode) & S_IFMT) !=
						(VFS_I(ip)->i_mode & S_IFMT) ||
					    be32_to_cpu(vdip->di_nlink) !=
						VFS_I(ip)->i_nlink ||
					    (long long)be64_to_cpu(vdip->di_size) !=
						(long long)ip->i_disk_size ||
					    ((VFS_I(ip)->i_mode & S_IFMT) != 0 &&
					     vdip->di_format !=
						ip->i_df.if_format);

					/* D-0532 arm: force the re-log
					 * once (no-op unless armed). */
					if (mxfs_dbg_relog_force_take(ip))
						v_behind = true;

					/*
					 *  (D3 residual,
					 * PROVEN byte-exact): the test above
					 * compares DINODE HEADER fields only.  A
					 * SHORTFORM directory holds its dirents
					 * INSIDE the fork, so an unlink that
					 * changes the name set can leave every
					 * compared field equal while fork and
					 * platter differ — the drain then
					 * declares success WITHOUT writing and
					 * releases the grant:
					 *   P146-RELDUR ino=27263113 size=181
					 *   dsize=105 flushed=1 wrote=0 rerr=-11
					 * then P51-REL.  node9's 4 unlinks never
					 * reached the platter; peers faithfully
					 * re-adopted the stale disk image and the
					 * removed names stayed resolvable
					 * cluster-wide (unlink_visibility "uv
					 * gone", tests/logs/firstcc_205730).
					 * Compare the SF fork bytes too: if ours
					 * differs from the on-disk image we still
					 * owe a publication (design review land-before-
					 * release: "nothing dirty" is not success
					 * while an obligation remains).
					 */
					if (!v_behind &&
					    S_ISDIR(VFS_I(ip)->i_mode) &&
					    ip->i_df.if_format ==
						XFS_DINODE_FMT_LOCAL &&
					    ip->i_df.if_data &&
					    ip->i_df.if_bytes > 0) {
						void *ddata = XFS_DFORK_PTR(
							vdip, XFS_DATA_FORK);
						int dlen = XFS_DFORK_DSIZE(
							vdip, mp);

						if (dlen < (int)ip->i_df.if_bytes ||
						    memcmp(ddata, ip->i_df.if_data,
							   ip->i_df.if_bytes)) {
							v_behind = true;
							mxfs_probe_ratelimited(
							    "mxfs: P175-SFCONTENT-UNLANDED ino=%llu if_bytes=%lld dfork_dsize=%d — header fields match but SHORTFORM CONTENT differs from platter; publication still owed (drain would have released silently)\n",
								(unsigned long long)ip->i_ino,
								(long long)ip->i_df.if_bytes, dlen);
						}
					}

					xfs_buf_relse(r_bp);
					if (!v_behind) {
						/*
						 * (D3 residual) wiring
						 * step 3 MEASUREMENT: this is
						 * the silent-success exit — the
						 * drain declares durability and
						 * the caller then releases the
						 * grant.  Report whether a
						 * publication obligation is
						 * STILL outstanding here.  If
						 * this fires in a run that then
						 * loses dirents, the obligation
						 * counter is the correct
						 * discriminator and the fix is
						 * to convert this print into
						 * "submit instead of return
						 * success" (+ fail the handoff
						 * when it cannot land).  If it
						 * never fires while losses
						 * continue, the obligation is
						 * being cleared too eagerly —
						 * suspect step 2's placement
						 * (the ">=1 inode"
						 * hole).  Either outcome is
						 * decisive; measure before
						 * enforcing (instrumented).
						 */
						if (ip->i_mxfs_pub_pending_seq !=
						    ip->i_mxfs_pub_durable_seq) {
							extern int mxfs_pub_obligation_enforce;

							/*
							 * instrumented CLASSIFIER.
							 * pending != durable has two
							 * very different causes and
							 * they need opposite fixes,
							 * so name which one this is
							 * before enforcing anything:
							 *
							 *  cls=INFLIGHT (flush_seq ==
							 *    pending): the image WAS
							 *    copied into a cluster
							 *    buffer and submitted; the
							 *    write just has not
							 *    completed yet.  Nothing is
							 *    missing — the correct
							 *    action is to WAIT for the
							 *    completion, and re-logging
							 *    would be pure waste.
							 *  cls=UNCOPIED (flush_seq <
							 *    pending): a committed
							 *    change was never even
							 *    copied into an outgoing
							 *    image.  THIS is the
							 *    land-before-release
							 *    violation; it needs a
							 *    submit + retry.
							 *
							 * ili state is printed because
							 * it is what the drain's own
							 * EAGAIN ("nothing dirty")
							 * verdict was based on — the
							 * whole reason this defect hid.
							 */
							mxfs_probe_ratelimited(
							    "mxfs: P176-OBLIGATION-OPEN ino=%llu cls=%s pending=%llu durable=%llu flush=%llu mode=%u fmt=%d size=%lld ili_f=0x%x ili_lf=0x%x in_ail=%d iflushing=%d pin=%d enforce=%d — drain declaring success with an UNLANDED committed change\n",
								(unsigned long long)ip->i_ino,
								(ip->i_mxfs_pub_flush_seq ==
								 ip->i_mxfs_pub_pending_seq)
									? "INFLIGHT" : "UNCOPIED",
								(unsigned long long)ip->i_mxfs_pub_pending_seq,
								(unsigned long long)ip->i_mxfs_pub_durable_seq,
								(unsigned long long)ip->i_mxfs_pub_flush_seq,
								ip->i_dlm_mode,
								ip->i_df.if_format,
								(long long)ip->i_disk_size,
								ip->i_itemp ? ip->i_itemp->ili_fields : 0,
								ip->i_itemp ? ip->i_itemp->ili_last_fields : 0,
								(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
								    &ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
								xfs_iflags_test(ip, XFS_IFLUSHING) ? 1 : 0,
								atomic_read(&ip->i_pincount),
								mxfs_pub_obligation_enforce);
							/*
							 * wiring step 3
							 * (ENFORCE): "nothing
							 * dirty" is NOT success
							 * while an obligation
							 * remains.  Fall through
							 * to the P146V re-log arm
							 * below — it re-logs the
							 * core in a tiny trans so
							 * the normal machinery
							 * lands it, then this
							 * loop retries (up to
							 * rtry<8) and step 2
							 * clears the obligation
							 * on the confirmed write.
							 * If the retries are
							 * exhausted the caller
							 * sees flushed=false,
							 * which is the honest
							 * "could not land"
							 * signal the handoff
							 * decision needs.
							 * Param-gated for A/B:
							 * the pre-existing
							 * behaviour was to
							 * declare success here.
							 */
							if (mxfs_pub_obligation_enforce)
								v_behind = true;
						}
						if (!v_behind) {
							flushed = true;
							break;
						}
					}
					/* (D3 ROOT FIX, PROVEN ino-167):
					 * a dirent-validated reload marked this
					 * in-core object a DEAD PRIOR
					 * INCARNATION and the disk still holds
					 * that newer incarnation — there is
					 * NOTHING of ours to land.  The old
					 * arm re-logged the corpse at NL
					 * (P58-DIRPIN-NONEX) and
					 * iflush_cluster clobbered the peer's
					 * live slot durably (22/32-node rename
					 * loss, ring #4008/#4009).  Skip;
					 * i_dlm_stale stays set so the post-
					 * drain access adopts disk. */
					/* +design review: WRITE-POISON semantics —
					 * the marker alone forbids the re-log
					 * (di_gen equality is ABA-fragile and
					 * must not re-authorize a corpse); the
					 * gens are diagnostics only. */
					if (ip->i_mxfs_dead_incarn_gen) {
						pr_warn_ratelimited(
						    "mxfs: P146D-DEADINCARN ino=%llu incore_gen=%u disk_gen=%u poison_gen=%u incore_mode=0%o — write-poisoned dead incarnation; NOT re-logging over peer's live slot\n",
							(unsigned long long)ip->i_ino,
							VFS_I(ip)->i_generation,
							v_dgen,
							ip->i_mxfs_dead_incarn_gen,
							VFS_I(ip)->i_mode);
						flushed = true;
						break;
					}
					/*
					 *  — WRITE-SIDE
					 * BACKSTOP (P189).
					 *
					 * This arm re-logs the in-core core so
					 * the normal machinery lands it.  It has
					 * the platter image (vdip) right here and
					 * used it only for reporting — so when the
					 * in-core object was a whole tenure behind
					 * disk it re-logged that, and the drain
					 * published it with full authority.  The
					 * captured revert (test23 ino=44040339)
					 * printed the proof in its OWN message one
					 * line before the damage:
					 *   incore[nlink=5  size=53   fmt=LOCAL]
					 *   disk  [nlink=34 size=4096 fmt=EXTENTS]
					 *
					 * A core that is BEHIND the platter on the
					 * same incarnation has nothing of ours
					 * worth landing — re-logging it can only
					 * revert a peer.  Same disposition as the
					 * P146D dead-incarnation guard beside it:
					 * do not re-log, leave i_dlm_stale set so
					 * the post-drain access adopts disk.
					 */
					if (be32_to_cpu(vdip->di_gen) ==
						VFS_I(ip)->i_generation &&
					    (VFS_I(ip)->i_nlink <
						be32_to_cpu(vdip->di_nlink) ||
					     inode_peek_iversion(VFS_I(ip)) <
						be64_to_cpu(vdip->di_changecount) ||
					     (ip->i_df.if_format ==
						XFS_DINODE_FMT_LOCAL &&
					      vdip->di_format !=
						XFS_DINODE_FMT_LOCAL))) {
						pr_warn_ratelimited(
						    "mxfs: P189-RELOG-BEHIND-DISK ino=%llu incore[nlink=%u chg=%llu size=%lld fmt=%d] disk[nlink=%u chg=%llu size=%lld fmt=%d] — in-core core is BEHIND the platter; refusing to re-log it over a peer's newer image\n",
							(unsigned long long)ip->i_ino,
							VFS_I(ip)->i_nlink,
							(unsigned long long)inode_peek_iversion(VFS_I(ip)),
							(long long)ip->i_disk_size,
							ip->i_df.if_format,
							be32_to_cpu(vdip->di_nlink),
							(unsigned long long)be64_to_cpu(vdip->di_changecount),
							(long long)be64_to_cpu(vdip->di_size),
							vdip->di_format);
						ip->i_dlm_stale = true;
						ip->i_dlm_stale_src = 22;
						flushed = true;
						break;
					}
					/*
					 * PRE-LOG AUTHORIZATION (see
					 * mxfs_dlm_relog_authorized).  On refusal
					 * a foreign platter gen means nothing of
					 * ours exists to land (dead incarnation,
					 * poisoned) -> this drain is done; the
					 * same gen means a possibly-unlanded
					 * committed change we no longer have
					 * tenure to write -> NOT durable, leave
					 * flushed=false so the handoff decision
					 * sees the honest "could not land" and
					 * the next-acquire merge re-lands it.
					 */
					if (!mxfs_dlm_relog_authorized(ip,
							"P146V", v_dgen)) {
						if (v_dgen !=
						    VFS_I(ip)->i_generation)
							flushed = true;
						break;
					}
					mxfs_probe_ratelimited(
					    "mxfs: P146V-UNLANDED ino=%llu try=%d incore[gen=%u mode=0%o nlink=%u size=%lld fmt=%d] disk[gen=%u mode=0%o nlink=%u size=%lld fmt=%d] — clean-but-unlanded dinode (phantom retire); re-logging core\n",
						(unsigned long long)ip->i_ino,
						rtry,
						VFS_I(ip)->i_generation,
						VFS_I(ip)->i_mode,
						VFS_I(ip)->i_nlink,
						(long long)ip->i_disk_size,
						ip->i_df.if_format,
						be32_to_cpu(vdip->di_gen),
						be16_to_cpu(vdip->di_mode),
						be32_to_cpu(vdip->di_nlink),
						(long long)be64_to_cpu(vdip->di_size),
						vdip->di_format);
					if (!xfs_is_shutdown(mp)) {
						struct xfs_trans *vtp;

						WRITE_ONCE(ip->i_mxfs_pipe_relog, 1);
						if (!xfs_trans_alloc(mp,
							&M_RES(mp)->tr_ichange,
							0, 0, 0, &vtp)) {
							/* D-0532 arm probe:
							 * the holder counts must
							 * be identical on both
							 * sides of the raw unlock. */
							uint16_t p_exb =
							    ip->i_dlm_ex_holders;
							uint16_t p_prb =
							    ip->i_dlm_pr_holders;

							if (xfs_ilock_nowait(ip,
							    XFS_ILOCK_EXCL)) {
								/* D-0532: join
								 * with 0 so the commit
								 * does not xfs_iunlock
								 * (no DLM begin was
								 * taken); raw release. */
								xfs_trans_ijoin(vtp,
								    ip, 0);
								xfs_trans_log_inode(
								    vtp, ip,
								    XFS_ILOG_CORE);
								(void)xfs_trans_commit(
								    vtp);
								xfs_iunlock_nodlm(ip,
								    XFS_ILOCK_EXCL);
								mxfs_probe_ratelimited(
								    "mxfs: P146V-RELOG-HOLDERS ino=%llu ex_before=%u ex_after=%u pr_before=%u pr_after=%u mode=%u state=%u bast_pending=%d\n",
									(unsigned long long)ip->i_ino,
									p_exb,
									ip->i_dlm_ex_holders,
									p_prb,
									ip->i_dlm_pr_holders,
									ip->i_dlm_mode,
									ip->i_dlm_state,
									ip->i_dlm_bast_pending ? 1 : 0);
							} else {
								mxfs_probe_ratelimited(
								    "mxfs: P146V-RELOG-NOWAIT-BUSY ino=%llu ex_h=%u pr_h=%u — ILOCK_EXCL held elsewhere; re-log skipped this try\n",
									(unsigned long long)ip->i_ino,
									p_exb, p_prb);
								xfs_trans_cancel(vtp);
							}
						}
						WRITE_ONCE(ip->i_mxfs_pipe_relog, 0);
					}
					msleep(2);
					continue;
				}
			}
			/* EFSCORRUPTED: buffer already released + FS shut down
			 * inside xfs_iflush_cluster. */
			break;
		}
reg_durable_done:
		/* close the release-flush authorization
		 * window opened before the flush loop.  dirs too. */
		if (S_ISREG(vip->i_mode) || S_ISDIR(vip->i_mode) ||
		    (vip->i_mode & S_IFMT) == 0)
			xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
		/*
		 * D-0974: a regular file's extent tree must be home before the
		 * unlock, as a directory's is.  Nothing above guarantees it: the
		 * AIL wait covers only the inode's own item, the inode flush's
		 * destage holds at most 64 owned bmbt blocks, and a clean inode
		 * skips the flush entirely.  Measured: a 20000-extent file (two
		 * levels, ~97 bmbt blocks) released with 33 of them unwritten;
		 * the peer followed the published root to a block that was not a
		 * bmbt block on disk (3644 CRC failures, 361 failed writes), and
		 * this node's xfsaild wrote the old image long after, over the
		 * peer's.  The directory release loop's check-and-flush pair runs
		 * here too — mxfs_dir_bmbt_scan's needs predicate (dirty, in the
		 * AIL, pinned, queued, or logged since last written; no XBF_DONE
		 * requirement; a stale buffer's free is retired by the log force,
		 * never written), repeated until the check finds nothing.  A lock
		 * that cannot be made durable within 30 s is never released: the
		 * release is wedged — the wire CAS refused, the grant pinned on
		 * disk, the mount shut down — as the other unprovable releases
		 * are.  The mode store to NL above has closed the fast path, so no
		 * local operation can add work between the last check and the
		 * unlock.  Only an EX release can owe this: the release path has
		 * no EX-to-PR downgrade, and a PR holder logs no extent changes.
		 */
		if (S_ISREG(vip->i_mode) && p_held_mode == MXFS_LOCK_EX &&
		    (ip->i_df.if_format == XFS_DINODE_FMT_BTREE ||
		     (xfs_inode_has_attr_fork(ip) &&
		      ip->i_af.if_format == XFS_DINODE_FMT_BTREE)) &&
		    !xfs_is_shutdown(mp)) {
			u64	bdeadline = ktime_get_ns() + 30ULL * NSEC_PER_SEC;
			int	bw;

			for (bw = 0; !mxfs_dir_bmbt_scan(ip, false); bw++) {
				if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
					break;
				if (ktime_get_ns() > bdeadline) {
					atomic_inc(&mxfs_reg_bmbt_rel_wedge);
					pr_err("mxfs: P974-REG-BMBT-WEDGE ino=%llu nx=%llu rounds=%d — extent tree not durable within 30 s; release wedged, not unlocked\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)ip->i_df.if_nextents,
						bw);
					mxfs_inode_wedge(ip, NULL, false);
					break;
				}
				xfs_log_force(mp, XFS_LOG_SYNC);
				mxfs_dir_bmbt_scan(ip, true);
				p2_loop_wrote = true;	/* the device flush below */
				if (bw)
					msleep(2);
			}
			if (bw)
				atomic_inc(&mxfs_reg_bmbt_rel_flushed);
		}
		/* Push the device write cache to the platter so the peer's FUA
		 * read of the backing store sees our di_size.
		 * skipped for a provably-clean REG release that wrote
		 * nothing in the loop above (2.8ms of the 13.3ms clean pull,
		 * P138 stage d); any loop bwrite forces the flush. */
		if (!p2_reg_clean || p2_loop_wrote)
			mxfs_blkdev_flush_epoch(mp);

		/* Always-on, rate-limited: a release that proceeds with the
		 * inode STILL dirty/pinned hands a stale (di_size=0) dinode to
		 * the peer -> empty-content read.  This is the writer-side
		 * cross_write_read failure signal. */
		if (!flushed &&
		    ip->i_itemp &&
		    test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags))
			mxfs_probe_ratelimited(
				"mxfs: P-REG-DURABLE-FAIL ino=%llu rerr=%d pin=%d size=%lld — released NOT durable\n",
				(unsigned long long)ip->i_ino, rerr,
				atomic_read(&ip->i_pincount),
				(long long)ip->i_disk_size);
		/*
		 * P146 — iter_13 lost-final-shrink probe.
		 * The uv dir's nx 4->3 shrink (chg=1922) vanished: the durable
		 * loop above concluded "flushed" yet NO nx=3 dinode image was
		 * ever submitted (P-DIRDW timeline) and the peer's grant-side
		 * reload read the pre-shrink chg=1921 platter image.  Record the
		 * loop OUTCOME with the in-core identity it was responsible for
		 * making durable, so the next reproduction shows whether the
		 * loop (a) saw the post-shrink fork and failed to write it, or
		 * (b) ran before the shrink committed (late local mutation).
		 */
		/*
		 * 0.84.18 (D-0963): the EX is leaving this node and its last
		 * image is on the platter -- capture that image as the merge
		 * base for the next stale-gen re-acquire, and retire this
		 * tenure's own-image ring.  Only an EX release: a PR holder
		 * published nothing.
		 */
		if (S_ISDIR(vip->i_mode))
			mxfs_dir_sf_release_base(ip, p_held_mode == MXFS_LOCK_EX);
		if (S_ISDIR(vip->i_mode)) {
			static atomic_t p146_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p146_n) <= 20000)
				mxfs_probe("mxfs: P146-RELDUR ino=%llu nx=%llu chg=%llu size=%lld dsize=%lld flushed=%d wrote=%d rerr=%d in_ail=%d pin=%d ili_fields=0x%x comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)ip->i_df.if_nextents,
					(unsigned long long)inode_peek_iversion(vip),
					(long long)i_size_read(vip),
					(long long)ip->i_disk_size,
					flushed ? 1 : 0,
					p2_loop_wrote ? 1 : 0, rerr,
					(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
						&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
					atomic_read(&ip->i_pincount),
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}

		/* P196: freeze the obligation counters at the drain's
		 * exit so the wire unlock can tell "the drain left it open"
		 * apart from "a local op re-dirtied us afterwards".  See the
		 * classifier note at the declarations. */
		p196_dr_ran = true;
		p196_dr_flushed = flushed;
		p196_dr_pending = ip->i_mxfs_pub_pending_seq;
		p196_dr_durable = ip->i_mxfs_pub_durable_seq;
		p196_dr_flush = ip->i_mxfs_pub_flush_seq;
	}

	/*
	 * P21-INSTR: minimal pre-unlock log for dirs.  Captures pincount
	 * (>0 means item still in CIL/log/AIL pending — flush incomplete)
	 * and ili_commit_seq (non-zero means modifications haven't reached
	 * disk yet).  No disk read here to minimize timing perturbation.
	 */
	/*
	 * H26: second blkdev_issue_flush right before unlock.
	 * The earlier flush at ~line 368 runs BEFORE the BAST-DIR-STALE
	 * walk and the cluster-buf barrier; any bio that completes after
	 * that flush but before this point isn't guaranteed durable.
	 * Adding a flush here closes that window.
	 *
	 * Falsifiable: if peer's FUA-read still sees magic=0x0 after this
	 * fix, durability is below the kernel block layer (LIO ignoring
	 * REQ_PREFLUSH).
	 */
	if (S_ISDIR(vip->i_mode)) {
		int h26_err = mxfs_blkdev_flush_epoch(mp);
		mxfs_idbg("mxfs: P-H26-FLUSH ino=%llu pre_unlock_flush rc=%d realns=%llu\n",
			(unsigned long long)ip->i_ino, h26_err,
			(unsigned long long)ktime_get_real_ns());
		/*
		 * Option B (design review contract item 1/5): the EX is leaving this
		 * node — clear the base-validity bit BEFORE the wire unlock so a
		 * later same-epoch/same-gen re-grant can never skip a needed
		 * adopt (CAW epochs can return to old values across slot
		 * reclamation, so the != compares alone are not sufficient).
		 * Unconditional on format/params, unlike the buffer invalidation
		 * below (which early-returns for shortform — the exact shape of
		 * the captured P195 hit, fmt=1).
		 */
		mxfs_dir_base_invalidate(ip, 1);
		/*
		 * (design review Option-1): now that every dir block is on
		 * the platter (fence + H26 flush), invalidate this node's cached
		 * clean+durable dir DATA/leaf buffers so the next re-acquire
		 * cold-reads the coherent LUN — no dir buffer survives the EX
		 * handoff with a bestfree[] that predates a peer's later add.
		 * i_lock (read) for extent-list stability across the walk.
		 */
		down_read(&ip->i_lock);
		mxfs_dir_release_invalidate_data_blocks(ip);
		up_read(&ip->i_lock);
	}

	/*
	 * D-0975: this tenure is ending, whatever mode it held.  Every clean
	 * cached extent-tree block the inode owns is dropped now, after the
	 * durable block above landed anything of ours and before the wire
	 * unlock lets a peer free and reuse those addresses (see the helper).
	 * A block that cannot be retired in the budget, or that still carries
	 * local work, means the release must not unlock: wedge it like the
	 * other unprovable releases.
	 */
	if (p_held_mode != MXFS_LOCK_NL && !xfs_is_shutdown(mp)) {
		int	terc = mxfs_bmbt_tenure_end_evict(ip, "release");

		if (terc) {
			pr_err("mxfs: P975-REL-WEDGE ino=%llu rc=%d mode=%u — cached extent-tree blocks could not be retired at the end of the tenure; release wedged, not unlocked\n",
				(unsigned long long)ip->i_ino, terc, p_held_mode);
			mxfs_inode_wedge(ip, NULL, false);
		}
	}

	/*
	 * deferred-publish: a peer is acquiring this inode's lock and is
	 * blocked behind our release.  If this inode is a directory, the peer is
	 * about to read our dirents and chase the child inode numbers therein —
	 * any of which may be locally-granted-but-unpublished.  Publish the
	 * ENTIRE unpublished list now (acquire real on-disk EX slots) so the
	 * peer's subsequent ilock of each child BASTs us and we flush its data
	 * before the peer reads it.
	 *
	 * v0.5.6: the drain is SCOPED to this dir's
	 * own children (i_mxfs_unpub_parent == ip->i_ino) plus parent-unknown
	 * entries — NOT the whole list.  Recursive top-down discovery still
	 * publishes everything a peer can reach: each child dir's OWN release
	 * publishes ITS children when the peer descends (the peer must take
	 * the child's lock — which now exists, we just published it — before
	 * it can read the child's dirents).  The whole-list drain claimed
	 * ~8.7k slots per release at 16 nodes (~96k cluster-wide vs the
	 * 65536-slot CAW table), took minutes, and starved the blocked EX
	 * waiter into 3×120s timeouts + forced shutdown (scaling_curve).
	 * For a non-dir release nothing is reachable through the lock, so
	 * only parent-unknown entries are published.
	 */
	p131_t1 = ktime_get_ns();
	mxfs_dlm_publish_unpublished(mp,
			S_ISDIR(vip->i_mode) ? ip->i_ino : 0, NULLAGNUMBER);

	/* (design review design-consult consult): PROVE the stale-inode-core hole.
	 * Log the dir inode's authoritative size + data-fork extent count at
	 * RELEASE.  A peer's ACQUIRE-side P105-ACQ probe that shows a SMALLER
	 * size/nextents than this (correlated by realns) proves the peer's
	 * reload read a STALE on-disk inode home block (our dir-grow was only
	 * LOGGED, not iflushed to the cluster buffer) → peer re-allocates the
	 * overflow block → durably orphans our dirents (the multi-block dir
	 * lost-update). run14d: gated mxfs.dirwr/mxfs.instr for ship
	 * (fires per dir-inode release; low-ino arm is un-ratelimited). */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    S_ISDIR(vip->i_mode)) {
		/* un-ratelimited for the storm dir (low inos) — the
		 * ratelimit hid whether ANY release ever carried the node-
		 * format fork (nx≥5) in s36 iter3.  nlink included so the
		 * (nlink, nx) pair can be matched against P36-DINO-WR. */
		if (ip->i_ino <= 256)
			mxfs_probe(
				"mxfs: P105-REL-DIRINODE ino=%llu disk_size=%lld nextents=%llu fmt=%d nlink=%u realns=%llu\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_disk_size,
				(unsigned long long)ip->i_df.if_nextents,
				ip->i_df.if_format,
				VFS_I(ip)->i_nlink,
				(unsigned long long)ktime_get_real_ns());
		else {
			/* capped, not ratelimited —
			 * the storm dir is a HIGH ino here (48234650 family);
			 * the ratelimit was dropping the exact release under
			 * investigation. */
			static atomic_t p105h_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p105h_n) <= 20000)
				mxfs_probe(
					"mxfs: P105-REL-DIRINODE ino=%llu disk_size=%lld nextents=%llu fmt=%d chg=%llu realns=%llu\n",
					(unsigned long long)ip->i_ino,
					(long long)ip->i_disk_size,
					(unsigned long long)ip->i_df.if_nextents,
					ip->i_df.if_format,
					(unsigned long long)inode_peek_iversion(VFS_I(ip)),
					(unsigned long long)ktime_get_real_ns());
		}
	}

	/* Release the DLM lock (CAW I/O) */
	mxfs_idbg("mxfs: P13-INSTR ino=%llu REL-INLINE-PRE realns=%llu\n",
		(unsigned long long)ip->i_ino,
		(unsigned long long)ktime_get_real_ns());
	mxfs_idbg("mxfs: P-H22-CALL site=BAST_RELEASE ino=%llu\n",
		(unsigned long long)ip->i_ino);
	/*
	 * (D-CROSSNODE-OPEN-UNLINK): a peer is taking this inode away
	 * from us — the ONLY moment its destructive inactivation can be
	 * imminent, because it must BAST every holder off before it can take
	 * EX.  Publish whether THIS node still has protected activity (open
	 * fds or a live mapping) so its B6 guard defers the free instead of
	 * truncating our data away.
	 *
	 * (design review audit C1): the bit change now RIDES THE RELEASE CAS
	 * (p_open_op threaded into the unlock below) instead of a separate
	 * best-effort open_set first.  The two-CAS shape had a silent-failure
	 * window: the set could exhaust its 8 tries, the release still
	 * landed, and the peer freed a file we hold open.  Folded, either
	 * both land or the grant is retained.  i_mxfs_open_pub tracks the
	 * INTENDED published state; a failed unlock leaves it optimistic,
	 * which only costs an idempotent extra clear later — never safety.
	 */
	/* ROUTED inodes are excluded — their unlock below routes to
	 * mxfs_iclus_unlock, which ignores p_open_op, so setting
	 * i_mxfs_open_pub here recorded an intent NO CAS would ever carry;
	 * the icluster release-publication sweep then saw pub==true, believed
	 * the bit durable, and skipped its SET — the cluster released with
	 * nothing on disk (openunlink_matrix `basic` DATA LOST, defer=0,
	 * P90 fired + zero P-ICLUS-OPENSET).  Routed publication belongs to
	 * mxfs_iclus_publish_open_bits exclusively.
	 *
	 * GATE ON THE CONFIG PREDICATE, NOT THE STICKY BIT: a fresh create's
	 * first grant is a mode-0-era PER-INODE local grant (sticky routing
	 * lands on the NEXT acquire), so gating on i_dlm_routed_iclus let
	 * P90 poison pub=true for exactly the just-created-then-rm'd files —
	 * matrix `basic` failed on a fresh prep and passed standalone, the
	 * difference being whether an intermediate acquire had converted the
	 * grant.  The sweep and B6 both key on the config predicate
	 * (mxfs_dlm_iclus_covered); publication ownership must match. */
	/*
	 * The CLEAR half is not membership-gated.  A mark published while
	 * multi-node stays in this node's slot after the peer leaves, and a
	 * lone node's release must still carry the absolute (clear) state:
	 * measured on 2/tcp, the lone last close queued its release but the
	 * release went out with no open op (P977-REL-MARK op=0 mask=0x2
	 * unchanged), and the rejoined peer deferred the free on that mark
	 * every reap retry (tests/open_mark_lone_close.sh s170c).  The SET half
	 * keeps its multi-node gate here.
	 */
	if (mxfs_open_tracking && mp->m_mxfs_dlm &&
	    !mxfs_dlm_iclus_covered(ip)) {
		bool mxfs_prot = atomic_read(&ip->i_mxfs_open_n) > 0 ||
			mapping_mapped(VFS_I(ip)->i_mapping);
		bool mxfs_alone = mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);

		if (mxfs_prot && mxfs_alone) {
			/* unchanged: no publication while alone and protected */
		} else if (mxfs_prot) {
			mxfs_probe_ratelimited(
			    "mxfs: P90-OPEN-PUBLISH ino=%llu opens=%d mapped=%d — releasing under BAST while still open here\n",
				(unsigned long long)ip->i_ino,
				atomic_read(&ip->i_mxfs_open_n),
				mapping_mapped(VFS_I(ip)->i_mapping) ? 1 : 0);
			p_open_op = 1;
			ip->i_mxfs_open_pub = true;
		} else {
			/*
			 * 0.89.0 (D-0977): every release publishes this
			 * node's ABSOLUTE protected state, not a delta —
			 * a clear is sent whether or not this shell
			 * remembers publishing.  A mark this node's slot
			 * carries that its shell does not know about (a
			 * lost clear, a mark inherited from a retired
			 * tenancy of the same slot) is repaired by the next
			 * release instead of deferring a peer's reap for
			 * ever.  On CAW the op is a mask clear in the
			 * release CAS: free when the bit is already clear.
			 */
			p_open_op = -1;
			ip->i_mxfs_open_pub = false;
		}
	}
	/* (instrumented): close the on-disk-slot EX-held window (paired with
	 * P106-EXGRANT) so a cross-node timeline reveals concurrent-EX. */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    (S_ISDIR(vip->i_mode) || S_ISREG(vip->i_mode))) {
		u64 p131_now = ktime_get_ns();
		int p106_nslots = 0;
		int p106_expop = mxfs_v5_dlm_inode_ex_count(mp->m_mxfs_dlm,
						ip->i_ino, &p106_nslots);

		mxfs_probe("mxfs: P106-EXREL ino=%llu dir=%d rel_gen=%u expop=%d nslots=%d realns=%llu drain_ms=%llu tail_ms=%llu\n",
			(unsigned long long)ip->i_ino,
			S_ISDIR(vip->i_mode) ? 1 : 0, p_rel_gen,
			p106_expop, p106_nslots,
			(unsigned long long)ktime_get_real_ns(),
			(unsigned long long)((p131_t1 - p131_t0) / NSEC_PER_MSEC),
			(unsigned long long)((p131_now - p131_t1) / NSEC_PER_MSEC));
	}
	/* instrumented: ALWAYS-ON (ratelimited) per-dir-release cost decomposition
	 * at instr=0 — held mode, provably-clean-skip flag, and the drain pipeline
	 * wall time.  drain_ms is the symmetric-livelock amplifier we are killing. */
	if (S_ISDIR(vip->i_mode))
		mxfs_probe_ratelimited(
			"mxfs: P51-REL ino=%llu held_mode=%u selfdemote=%d sf=%d clean_skip=%d drain_ms=%llu\n",
			(unsigned long long)ip->i_ino, p_held_mode, p_self_demote ? 1 : 0,
			p_shortform ? 1 : 0,
			(mxfs_dir_pr_release_fast && p_clean_release &&
			 (mxfs_dir_pr_release_fast >= 2 || p_self_demote || p_shortform)) ? 1 : 0,
			(unsigned long long)((p131_t1 - p131_t0) / NSEC_PER_MSEC));
	/* instrumented residual-window probe: in_ail/pinned at the LAST
	 * moment before the on-disk DLM unlock.  If this shows dirty for a
	 * dir, a committed change landed AFTER the release drain + durable
	 * flush (the gate->ILOCK gap or a post-durable commit) and would be
	 * released stale -> resurrection.  Always-on, ratelimited. */
	if (S_ISDIR(vip->i_mode) &&
	    ((ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				      &ip->i_itemp->ili_item.li_flags)) ||
	     atomic_read(&ip->i_pincount) > 0))
		mxfs_probe_ratelimited(
		    "mxfs: P57-PREUNLOCK-DIRTY ino=%llu held_mode=%u in_ail=%d pinned=%d — releasing dir with committed change NOT durable\n",
		    (unsigned long long)ip->i_ino, p_held_mode,
		    (ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					     &ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
		    atomic_read(&ip->i_pincount));
	/*
	 * EAGER evict-on-BAST (gated dir_bast_evict).  We are
	 * about to hand the dir EX to a peer that will modify it; the release
	 * fence above has drained our dir blocks durable (Inv 1), so any cached
	 * dir DATA block is now clean.  Drop them so our NEXT re-acquire cold-
	 * FUA-reads the peer's current image as the RMW base (the reliable
	 * release-side cure for the racy acquire-side stale-base clobber).
	 * ILOCK not held here (fence did up_read); take it nowait + best-effort
	 * (the lazy modify/consumer refresh still covers a missed eviction).
	 */
	if (mxfs_dir_bast_evict && S_ISDIR(vip->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		if (xfs_ilock_nowait(ip, XFS_ILOCK_SHARED)) {
			mxfs_dir_evict_data_blocks(ip);
			/* D-0532: nowait ILOCK had no DLM begin */
			xfs_iunlock_nodlm(ip, XFS_ILOCK_SHARED);
		}
	}
	p2s_d = ktime_get_ns();

	/*
	 * instrumented INVARIANT-1 AUDIT (always-on, capped): the
	 * drain above is about to be followed by the DLM unlock.  run62's
	 * cluster kill was a dir DATA block (daddr 0x3fe1c70) whose extent was
	 * in the durable dinode map while its CONTENT never reached the
	 * platter (CRC-garbage on every reader, no write lineage in any log).
	 * Re-check dir data durability at this exact moment and SHOUT if the
	 * handoff is about to leak unlanded content — names the leaking
	 * release (P3W-DIRWR names the writes; absence of both = the block
	 * was never submitted).
	 */
	/*
	 * FIX-2 (PROVEN BY INSTRUMENT, run70 r1 node7_f45.md5 loss):
	 * this audit used to be PRINT-ONLY.  A create that fast-path-admitted
	 * during a queued self-demote release committed its dirent (P13-NADD
	 * wall .690) AFTER the release fence's durability pass but BEFORE the
	 * unlock (P6U wall .6907); the block write only landed at wall .6996.
	 * The peer (test3) acquired EX in that window, cold-read the pre-add
	 * platter, placed its own entry at the SAME data-block offset (1376),
	 * and its later image durably dropped ours.  The 9918 holders-recheck
	 * cannot catch this (the creator already iunlock'd); only THIS point
	 * sees the final truth.  ENFORCE Invariant #1 here: while the dir has
	 * unlanded committed state (data not durable / inode in AIL / pinned),
	 * flush and re-check — never unlock stale.  Bounded by ~10s then
	 * shutdown (P97 policy: an undurable dir lock must NOT be released).
	 */
	if (S_ISDIR(vip->i_mode) && !xfs_is_shutdown(mp)) {
		int p3b_try;
		/* PROVEN BY INSTRUMENT (run 114157Z, test3/test12
		 * i!=1): this loop's re-drain (relsafe -> bmbt_scan bwrite)
		 * and the in-flight barrier below run AFTER the release
		 * path's last device flush (H26, above) — a leaf image
		 * written here completes only into the LIO/SCST write cache
		 * (the target drops the FUA bit), the DLM unlock hands off,
		 * and the acquirer's FUA-read leaf refresh reads the PLATTER
		 * = the pre-write image, "confirms" its stale cached leaf,
		 * and decodes a stale iext (bunmapi i!=1 family).  Track
		 * whether this loop did ANY late work and re-flush the device
		 * before the unlock. */
		bool p3b_reflush = false;

		for (p3b_try = 0; ; p3b_try++) {
			bool p3b_durable, p3b_in_ail;

			if (!mxfs_drain_ilock_read(ip))
				break;	/* FS shutdown — no peer obligation */
			p3b_durable = mxfs_dir_data_durable(ip);
			p3b_in_ail = ip->i_itemp &&
				test_bit(XFS_LI_IN_AIL,
					 &ip->i_itemp->ili_item.li_flags);
			up_read(&ip->i_lock);

			if (p3b_durable && !p3b_in_ail &&
			    atomic_read(&ip->i_pincount) == 0) {
				/* PROVEN BY INSTRUMENT (run 110411Z,
				 * test26 i!=1): a committed bmbt-leaf bio this
				 * node submitted (xfsaild async, multipath
				 * plain-bio path) can still be IN FLIGHT here —
				 * durable-looking state, but the image lands
				 * on the LUN after the peer's acquire-iread
				 * cold-read, so the peer decodes the pre-write
				 * leaf into its iext and later trips
				 * xfs_bmap_del_extent_real i!=1.  Hold the
				 * unlock until every counted dir-metadata/bmbt
				 * write bio has physically completed (bounded;
				 * shutdown/unmount bail — no peer obligation). */
				int p3b_wb;

				for (p3b_wb = 0; p3b_wb < 5000 &&
				     atomic_read(&mp->m_mxfs_dir_wr_inflight) > 0 &&
				     !xfs_is_shutdown(mp) &&
				     !xfs_is_unmounting(mp); p3b_wb++)
					msleep(2);
				if (p3b_wb > 0) {
					/* bios completed during the wait
					 * landed in the target's write cache
					 * AFTER the H26 flush — re-flush
					 * before unlock. */
					p3b_reflush = true;
					mxfs_probe_ratelimited(
					    "mxfs: P3B-WRBARRIER ino=%llu waited=%dms inflight=%d — held DLM unlock for in-flight metadata write bios\n",
					    (unsigned long long)ip->i_ino,
					    p3b_wb * 2,
					    atomic_read(&mp->m_mxfs_dir_wr_inflight));
				}
				break;	/* clean — safe to unlock */
			}
			p3b_reflush = true;	/* re-drain iteration runs below */

			{
				static atomic_t p3b_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p3b_n) <= 2000)
					mxfs_probe("mxfs: P3B-UNLOCK-UNDESTAGED ino=%llu try=%d data_durable=%d in_ail=%d pin=%d nx=%llu size=%lld comm=%s realns=%llu — re-draining before DLM unlock\n",
						(unsigned long long)ip->i_ino,
						p3b_try,
						p3b_durable ? 1 : 0,
						p3b_in_ail ? 1 : 0,
						atomic_read(&ip->i_pincount),
						(unsigned long long)ip->i_df.if_nextents,
						(long long)ip->i_disk_size,
						current->comm,
						(unsigned long long)ktime_get_real_ns());
			}

			if (p3b_try >= 5000) {
				pr_warn("mxfs: P3B-RELFENCE-WEDGE ino=%llu — shutdown (un-durable dir lock NOT released)\n",
					(unsigned long long)ip->i_ino);
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
				break;
			}

			/* land the stragglers: CIL force (unpin), inode
			 * cluster (AIL), then the map-independent owner-scan
			 * flush (BTREE-blind-window safe). */
			xfs_log_force(mp, XFS_LOG_SYNC);
			xfs_ail_push_ag_sync(mp->m_ail,
					     XFS_INO_TO_AGNO(mp, ip->i_ino));
			/*
			 * run74 ROOT FIX: relsafe CONSUMES the
			 * caller's i_lock read hold (every path in it up_reads)
			 * — it was called here WITHOUT the hold, so every
			 * non-clean audit iteration underflowed the dir's
			 * i_lock reader count by one (run74: try=0/try=1 ->
			 * cnt=-510 = readers=-2 + waiters).  The rwsem then
			 * rejects all takers forever: next release wedged in
			 * mxfs_drain_ilock_read 400s+, dir EX never released,
			 * 7-peer convoy EIO'd the cluster.  Take the hold
			 * first, exactly like the 10212/10575 sites.
			 */
			if (!mxfs_drain_ilock_read(ip))
				break;	/* FS shutdown — no peer obligation */
			mxfs_dir_flush_data_blocks_relsafe(ip);
			msleep(2);
		}
		if (p3b_reflush && !xfs_is_shutdown(mp) &&
		    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
			int p3b_frc = mxfs_blkdev_flush_epoch(mp);

			mxfs_probe_ratelimited(
			    "mxfs: P3B-REFLUSH ino=%llu rc=%d — device flush re-issued after post-H26 late drain/barrier work so the platter is coherent at unlock\n",
			    (unsigned long long)ip->i_ino, p3b_frc);
		}
	}
	/*
	 * gen-aware release: only release the tenure
	 * this bast_process was queued for (p_rel_gen, captured before the
	 * NL-set above).  -ESTALE = a local re-acquire completed a FULL DLM
	 * acquire inside the release window (mode was already NL) and a NEWER
	 * grant owns the resource now — releasing it would hand the lock to a
	 * peer while OUR fs layer believes it holds EX (concurrent EX,
	 * unestablished dir_epoch, durable dirent loss: run42-t4).
	 *
	 * p_rel_gen==0 on TCP = the capture found NO held tenure: this work
	 * item is a stale/duplicate release (a prior instance already
	 * unlocked).  "Release whatever is there" could only eat a concurrent
	 * fresh grant — skip the DLM unlock entirely.
	 *
	 * RE-ARM (run46 instrumented lesson): the first version set state=BAST here
	 * and returned.  With ZERO holders nothing ever consumes BAST state
	 * (only a holder's ilock_end/unpin does) and state=BAST refuses new
	 * fast-path admits — the inode STRANDED: a local getattr blocked 117s
	 * in ilock_begin (md5sum pid 3455), that rank never finished its
	 * create wave, the round barrier held the whole cluster, and the idle
	 * dir holder was never asked to release (the run45/46 120s wedge).
	 * Instead re-arm through the MHT dwork channel (i_dlm_bast_pending +
	 * i_dlm_bast_dwork): it survives fast-path state clobbers, samples
	 * until holders==pin==0, and runs a FRESH bast_process (fresh gen
	 * capture) that releases the CURRENT tenure with its own full drain.
	 * state goes NONE so blocked ilock_begin waiters proceed normally.
	 */
	{
		bool stranded = false;
		/* (ruling item 8): a relbar defer happened in
		 * THIS pipeline — the teardown no-arm branch must then wedge
		 * pin-only instead of letting release_all strip the slot. */
		bool p_rb_deferred = false;

		if (p_rel_gen == 0 && mp->m_mxfs_dlm &&
		    mxfs_v5_dlm_is_tcp(mp->m_mxfs_dlm)) {
			/* capped, NOT ratelimited — run68's
			 * wedge exit was most plausibly this arm, its print
			 * suppressed by a P6Z 1.1s earlier for another ino. */
			static atomic_t p6z_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p6z_n) <= 4000)
				mxfs_probe(
			    "mxfs: P6Z-REL-NOTHING ino=%llu mode=%u state=%u ex=%u pr=%u — no held tenure at release decision; DLM unlock skipped\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode, ip->i_dlm_state,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders);
			/* A grant may have landed between the capture and now
			 * (same window as ESTALE) — if the table holds a
			 * tenure NOW, the peer BAST we were queued for must
			 * not be dropped. */
			stranded = (mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm,
							ip->i_ino) != 0);
			/* FIX-20b: phantom reconcile — this instance was
			 * queued by the repeated-no-mirror-BAST detector.  The
			 * master's table holds our GRANTED entry (that's what
			 * drives the BAST storm) while the mirror has nothing
			 * to unlock: send the mirror-bypassing gen=0 release
			 * so the master frees the phantom and promotes the
			 * starved queue.  Skip when a REAL grant landed
			 * meanwhile (stranded) — never eat a live tenure. */
			{
				bool p20_rec;
				bool p6z_mirror_held = false;

				spin_lock(&ip->i_dlm_lock);
				p20_rec = ip->i_dlm_reconcile_pending;
				ip->i_dlm_reconcile_pending = false;
				spin_unlock(&ip->i_dlm_lock);
				/*
				 * D-0966, second site: the mirror holds a GRANTED
				 * entry of ours with NO generation — a ledger
				 * record of this incarnation imported on a page
				 * load (dlm_import_holder) that no local request
				 * adopted (the adopt site in dlm_lock mints one)
				 * — and a peer is asking for the resource.  No
				 * local release will ever name it, so the peer
				 * would wait for ever behind a record only we can
				 * retire.  Answer the BAST with the same
				 * mirror-bypassing release the reconcile uses.
				 */
				if (!stranded && !p20_rec &&
				    mxfs_v5_dlm_inode_granted_mode(mp->m_mxfs_dlm,
								   ip->i_ino) !=
				    MXFS_LOCK_NL) {
					static atomic_t p6zm_n = ATOMIC_INIT(0);
					int p6zm_rc;

					p6z_mirror_held = true;
					p6zm_rc = mxfs_v5_dlm_inode_unlock_genless(
							mp->m_mxfs_dlm, ip->i_ino);
					if (atomic_inc_return(&p6zm_n) <= 2000)
						mxfs_probe("mxfs: P-REL-NOTHING-MIRROR-HELD ino=%llu mode=%u state=%u rc=%d — the mirror held a generation-less grant of ours (an imported record nobody adopted); adopted and released so the peer's request is served\n",
							(unsigned long long)ip->i_ino,
							ip->i_dlm_mode, ip->i_dlm_state,
							p6zm_rc);
				}
				if (p20_rec && !stranded && !p6z_mirror_held) {
					int p20_rc =
					    mxfs_v5_dlm_inode_release_unconditional(
						mp->m_mxfs_dlm, ip->i_ino);
					mxfs_probe("mxfs: P-PHANTOM-RECONCILE-SENT ino=%llu rc=%d — mirror-bypassing release sent to master\n",
						(unsigned long long)ip->i_ino,
						p20_rc);
				}
			}
		} else if (p_rel_gen == 0 && mp->m_mxfs_dlm &&
			   mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
			/*
			 * HOLE-1: on CAW, p_rel_gen==0
			 * (no grant-meta tenure at the release decision — the
			 * bucket was evicted by a colliding resource, or this
			 * is a cleanup flavor) used to fall into
			 * unlock_gen(expected=0) with a MILLISECONDS-wide
			 * unguarded window back at the capture.  First cut of
			 * this arm SKIPPED the unlock entirely — that leaked
			 * held wire bits (run 065143Z: 213 re-BAST loops on
			 * one ino).  Correct shape: re-read the tenure gen
			 * NOW; a live tenure → defer to a fresh dwork (its
			 * capture gets the real anchor).  No tenure → do the
			 * unconditional unlock after all: its entry-snapshot
			 * in-loop seq abort (ungated, dlm_caw.c) still parries
			 * any mid-CAS local grant, and the no-wipe bucket
			 * hardening keeps that snapshot trustworthy.
			 */
			uint32_t p6zc_now = mxfs_v5_dlm_inode_grant_gen(
						mp->m_mxfs_dlm, ip->i_ino);
			static atomic_t p6zc_n = ATOMIC_INIT(0);
			/* step 3: per-inode release certificate for
			 * this unconditional-unlock arm (class=INODE) */
			struct mxfs_release_cert p282c = {
				.res_id = ip->i_ino,
				.rclass = MXFS_RELCLASS_INODE,
				.path = "noanchor",
				.old_epoch = ip->i_dlm_epoch,
			};
			uint64_t p282_t0 = ktime_get_ns();

			/* daf50d34 grant_gen reads the collision-LOSSY
			 * grant_meta (can be 0 with a live tenure).  in-core
			 * mode != NL is the untramplable local truth that a
			 * grant materialized since this pipeline NL'd its own
			 * tenure — never wire-unlock a live grant. */
			if (p6zc_now != 0 ||
			    READ_ONCE(ip->i_dlm_mode) != MXFS_LOCK_NL) {
				stranded = true;
			} else if (mxfs_relbar_enforce &&
				   mxfs_relbar_close_or_defer(ip, "noanchor",
							      &p282c)) {
				/* same released=>landed enforcement as
				 * the anchored sibling — an open ledger defers
				 * this unconditional unlock via the stranded
				 * re-arm instead of publishing the grant with
				 * a committed change not yet at home.
				 * under the proof gate the defer
				 * enters/extends the bounded episode; expired
				 * bounds WEDGE instead (no re-arm). */
				p_rb_deferred = true;
				if (mxfs_release_proof_enforce &&
				    mxfs_inode_defer_arm(ip,
					mxfs_inode_defer_causes(ip, &p282c))) {
					p282c.drain_ns =
						ktime_get_ns() - p282_t0;
					mxfs_inode_wedge(ip, &p282c, false);
				} else {
					mxfs_inode_relcert_defer(ip, &p282c,
								 p282_t0);
					stranded = true;
				}
			} else {
				/* P147 — see the
				 * anchored-unlock sibling below. */
				if (S_ISDIR(VFS_I(ip)->i_mode)) {
					static atomic_t p147z_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p147z_n) <= 20000)
						mxfs_probe("mxfs: P147-PREUNLOCK ino=%llu nx=%llu chg=%llu in_ail=%d pin=%d ili_fields=0x%x comm=%s realns=%llu arm=noanchor\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)ip->i_df.if_nextents,
							(unsigned long long)inode_peek_iversion(VFS_I(ip)),
							(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
								&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
							atomic_read(&ip->i_pincount),
							ip->i_itemp ? ip->i_itemp->ili_fields : 0,
							current->comm,
							(unsigned long long)ktime_get_real_ns());
				}
				mxfs_dlm_relbar_check(ip, "noanchor");
				mxfs_inode_authority_check_published(ip,
								     MXFS_SITE);
				if (ip->i_dlm_routed_iclus &&
				    !ip->i_dlm_unpublished) {
					/* ICLUSTER: release_check — the disk
					 * release fires only when the sweep
					 * shows no covered inode active
					 * (Phase 1 has no gen-anchor
					 * semantics).  Unpublished inodes
					 * never claimed the cluster; skip.
					 * honest rc (decline => skip
					 * the clock clear; fan_out owns the
					 * retry) + per-ino orphan-bit
					 * recovery — see the anchored sibling
					 * below. */
					int zrc = mxfs_iclus_unlock(mp,
						ip->i_ino,
						p_held_mode == MXFS_LOCK_EX ?
						MXFS_LOCK_EX : MXFS_LOCK_PR,
						false);
					if (zrc)
						p_iclus_declined = true;
					/* entry-orphan pipelines only — see
					 * the anchored sibling. */
					if (p_held_mode == MXFS_LOCK_NL)
						mxfs_iclus_pi_reconcile(ip,
									zrc);
				} else if (mxfs_release_proof_enforce &&
					   READ_ONCE(ip->i_mxfs_rel_state) ==
						MXFS_RELSTATE_WEDGED) {
					/* (ruling item 9): pre-CAS
					 * WEDGED re-check — never submit,
					 * never re-arm. */
					p282c.cas_attempted = 0;
					p282c.defer_kind = MXFS_RELDEFER_WEDGE;
					p282c.defer_reason =
						"wedged — CAS refused";
					p282c.drain_ns =
						ktime_get_ns() - p282_t0;
					mxfs_release_cert_emit(&p282c);
				} else {
					/* rc capture is for the certificate
					 * only — this arm's unlock outcome
					 * was always discarded (in-loop seq
					 * abort parries mid-CAS grants) */
					int p282_rc;

					p282c.rel_state_cas = READ_ONCE(
						ip->i_mxfs_rel_state);
					mxfs_rel_state_set(ip,
						MXFS_RELSTATE_RELEASING);
					p282c.rel_instance = atomic_inc_return(
						&ip->i_mxfs_rel_instance);
					/* clean-release marker, durable
					 * BEFORE the unlock CAS (see the
					 * anchored arm for the full note). */
					mxfs_inode_relmark_before_unlock(ip,
						p_rel_res, p_rel_epoch,
						p_rel_lineage, &p_rel_marked,
						"ino-noanchor");
					mxfs_dbg_rel_pause(ip, 5);
					p282_rc =
						mxfs_v5_dlm_inode_unlock_open(
						mp->m_mxfs_dlm, ip->i_ino, 0,
						p_open_op);
					mxfs_inode_relcert_finish(ip, &p282c,
								  p282_rc,
								  p282_t0);
				}
			}
			if (atomic_inc_return(&p6zc_n) <= 2000)
				mxfs_probe("mxfs: P6ZC-REL-NOANCHOR ino=%llu mode=%u state=%u ex=%u pr=%u reap=%d now_gen=%u %s\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders,
					p15h_reap ? 1 : 0, p6zc_now,
					p6zc_now ? "live tenure — deferred" :
						   "no tenure — unconditional unlock (in-loop guarded)");
		} else {
			int p6u_rc;

			/*
			 * P15H forensics: for a
			 * strand-reap, record the raw wire state BEFORE the
			 * anchored unlock and the unlock's outcome — the
			 * missing observable of the run-060826Z double-EX
			 * chain (which interleave lets a reap clear a
			 * mid-consumption grant).  One probe-chain read per
			 * reap; reaps are ~rare after the 280-strike floor.
			 */
			if (p15h_reap) {
				int p15h_nslots = 0;
				int p15h_exn = mxfs_v5_dlm_inode_ex_count(
					mp->m_mxfs_dlm, ip->i_ino,
					&p15h_nslots);
				mxfs_probe("mxfs: P15H-PRE-UNLOCK ino=%llu rel_gen=%u cur_gen=%u wire_ex_popcount=%d nslots=%d\n",
					(unsigned long long)ip->i_ino,
					p_rel_gen,
					mxfs_v5_dlm_inode_grant_gen(
						mp->m_mxfs_dlm, ip->i_ino),
					p15h_exn, p15h_nslots);
			}
			/*
			 * a strand-reap is only legitimate
			 * for a mode==NL orphan.  The gen anchor alone can
			 * degrade to unconditional under grant-meta bucket
			 * churn (collision-lossy), so re-check the LIVE
			 * in-core mode at the last instant: if a re-acquire
			 * won a tenure since the reap decision, defer (the
			 * stranded re-arm below handles it) instead of
			 * stripping the fresh grant's slot bit (the
			 * mkdir-storm double-EX family; root ino=128
			 * P135-HELD-MISS).
			 */
			/* daf50d34 extend the LIVE-SKIP beyond strand
			 * reaps to EVERY anchored unlock.  A normal pipeline
			 * NL'd its own mode at entry, so mode != NL here means
			 * a fresh grant materialized mid-drain (the acquire's
			 * early publish) — this instance would wire-strip a
			 * tenure it does not own (the proven mkdir-storm
			 * fresh-grant kill).  The gen anchor alone cannot be
			 * trusted: grant_meta buckets are collision-lossy. */
			/*
			 * D-RELEASE-BARRIER-OPEN ENFORCEMENT (review-ruled
			 * design, measured basis: P220-UNLOCK-LEDGER-OPEN =
			 * 10-12 of ~8234 unlocks/lap carry pending != durable
			 * HERE, after the whole pipeline — typed as shared
			 * parent dirs whose durable flush RAN (lastrel=1) and
			 * that were re-committed in the flush→unlock window).
			 * The wire grant is still ours at this point, so the
			 * close is fully authorized: re-run the deterministic
			 * durable sequence and re-check; if the ledger still
			 * will not close, DEFER the wire unlock exactly like
			 * the LIVE-SKIP arm (-ESTALE → requeue) instead of
			 * handing the grant away with the obligation open.
			 * Bounded: 2 attempts; the requeue retries later.
			 * Default OFF pending the same-build A/B.
			 */
			{
				/* step 3: per-inode release
				 * certificate for the anchored arm */
				struct mxfs_release_cert p282c = {
					.res_id = ip->i_ino,
					.rclass = MXFS_RELCLASS_INODE,
					.path = "anchored",
					.old_epoch = ip->i_dlm_epoch,
				};
				uint64_t p282_t0 = ktime_get_ns();
				bool rb_defer = mxfs_relbar_enforce ?
					mxfs_relbar_close_or_defer(ip, "anchored",
								   &p282c) :
					false;

			if (READ_ONCE(ip->i_dlm_mode) != MXFS_LOCK_NL || rb_defer) {
				static atomic_t p15h_live_cap = ATOMIC_INIT(0);

				p6u_rc = -ESTALE;
				if (rb_defer) {
					/* bounded episode — expired
					 * bounds WEDGE (no re-arm; -EIO is
					 * not -ESTALE so no strand). */
					p_rb_deferred = true;
					if (mxfs_release_proof_enforce &&
					    mxfs_inode_defer_arm(ip,
						mxfs_inode_defer_causes(ip,
								&p282c))) {
						p282c.drain_ns =
						    ktime_get_ns() - p282_t0;
						mxfs_inode_wedge(ip, &p282c,
								 false);
						p6u_rc = -EIO;
					} else {
						mxfs_inode_relcert_defer(ip,
							&p282c, p282_t0);
					}
				}
				if (!rb_defer &&
				    atomic_inc_return(&p15h_live_cap) <= 400)
					mxfs_probe("mxfs: P15H-LIVE-SKIP ino=%llu mode=%u reap=%d — live tenure appeared before unlock; deferring\n",
						(unsigned long long)ip->i_ino,
						ip->i_dlm_mode,
						p15h_reap ? 1 : 0);
			} else {
				/* P147 — the on-disk
				 * unlock is the moment the peer's grant-side
				 * disk read becomes legal.  Pair with P146
				 * (durable-loop exit): a HIGHER chg here than
				 * at P146 proves a local op mutated the dir
				 * between the durable flush and the unlock
				 * (the lost-final-shrink window). */
				/*
				 *  (P188) — IS THE
				 * PUBLICATION BARRIER ACTUALLY CLOSED HERE?
				 *
				 * Design-consult design review of this defect: "before
				 * publishing unlock, every committed change the
				 * next owner is expected to observe must be
				 * present in the home location".  MXFS has the
				 * predicate for that (pending vs durable), but
				 * it is only ever evaluated on ONE early-exit
				 * branch of the flush loop (P176) — which fires
				 * 1x per storm run — and NOT at the wire unlock,
				 * which is the moment that actually matters.
				 *
				 * So ask the question exactly here, where the
				 * grant is about to leave this node.  If this
				 * fires while P176 does not, the barrier is in
				 * the wrong place and the "release drain
				 * declared success" evidence (6228 of 6234) is
				 * measuring a checkpoint that no longer holds by
				 * the time we unlock.  Measurement only — no
				 * behaviour change, and no I/O on the drain
				 * path, whose latency this defect family is
				 * measurably sensitive to.
				 */
				if (S_ISDIR(VFS_I(ip)->i_mode) &&
				    ip->i_mxfs_pub_pending_seq !=
					    ip->i_mxfs_pub_durable_seq) {
					static atomic_t p188_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p188_n) <= 8000)
						mxfs_probe("mxfs: P188-REL-OBLIGATION-AT-UNLOCK ino=%llu pending=%llu durable=%llu flush=%llu nlink=%u fmt=%d in_ail=%d pin=%d ili_fields=0x%x comm=%s realns=%llu — about to hand the grant to a peer with a committed change that is NOT at its home location\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)ip->i_mxfs_pub_pending_seq,
							(unsigned long long)ip->i_mxfs_pub_durable_seq,
							(unsigned long long)ip->i_mxfs_pub_flush_seq,
							VFS_I(ip)->i_nlink,
							ip->i_df.if_format,
							(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
								&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
							atomic_read(&ip->i_pincount),
							ip->i_itemp ? ip->i_itemp->ili_fields : 0,
							current->comm,
							(unsigned long long)ktime_get_real_ns());
					/*
					 * P196 — name the cause.  See the
					 * classifier note at the declarations of
					 * p196_dr_*.  This is the discriminator
					 * between four different fixes, and it is
					 * the reason P188's raw count has been
					 * un-actionable for two sessions.
					 */
					{
						const char *p196_cls;

						if (!p196_dr_ran)
							p196_cls = "NODRAIN";
						else if (ip->i_mxfs_pub_pending_seq >
							 p196_dr_pending)
							p196_cls = "REDIRTY";
						else if (ip->i_mxfs_pub_flush_seq ==
							 ip->i_mxfs_pub_pending_seq)
							p196_cls = "INFLIGHT";
						else if (ip->i_mxfs_pub_flush_seq <
							 ip->i_mxfs_pub_pending_seq)
							p196_cls = "UNCOPIED";
						else
							p196_cls = "REGRESS";

						mxfs_probe("mxfs: P196-UNLOCK-OBLIGATION-CLASS ino=%llu cls=%s drain_ran=%d drain_flushed=%d dr_pend=%llu dr_dur=%llu dr_flush=%llu now_pend=%llu now_dur=%llu now_flush=%llu iflushing=%d selfdem=%d held_mode=%u comm=%s\n",
							(unsigned long long)ip->i_ino,
							p196_cls,
							p196_dr_ran ? 1 : 0,
							p196_dr_flushed ? 1 : 0,
							(unsigned long long)p196_dr_pending,
							(unsigned long long)p196_dr_durable,
							(unsigned long long)p196_dr_flush,
							(unsigned long long)ip->i_mxfs_pub_pending_seq,
							(unsigned long long)ip->i_mxfs_pub_durable_seq,
							(unsigned long long)ip->i_mxfs_pub_flush_seq,
							xfs_iflags_test(ip, XFS_IFLUSHING) ? 1 : 0,
							p_self_demote ? 1 : 0,
							p_held_mode,
							current->comm);
					}
				}
				if (S_ISDIR(VFS_I(ip)->i_mode)) {
					static atomic_t p147_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&p147_n) <= 20000)
						mxfs_probe("mxfs: P147-PREUNLOCK ino=%llu nx=%llu chg=%llu in_ail=%d pin=%d ili_fields=0x%x comm=%s realns=%llu\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)ip->i_df.if_nextents,
							(unsigned long long)inode_peek_iversion(VFS_I(ip)),
							(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
								&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
							atomic_read(&ip->i_pincount),
							ip->i_itemp ? ip->i_itemp->ili_fields : 0,
							current->comm,
							(unsigned long long)ktime_get_real_ns());
				}
				mxfs_dlm_relbar_check(ip, "anchored");
				p2s_e = ktime_get_ns();	/* su split */
				mxfs_inode_authority_check_published(ip,
								     MXFS_SITE);
				if (ip->i_dlm_routed_iclus &&
				    !ip->i_dlm_unpublished) {
					/* ICLUSTER routed release_check: no
					 * -ESTALE regrant path (the iclus
					 * busy-gate serializes local
					 * acquire/release instead).  See the
					 * unpublished note above.
					 * (design-consult):
					 * HONEST rc — a covered-active decline
					 * must not claim success (it cleared
					 * the rescue clocks every 250ms and
					 * disarmed the ABBA escape; captured
					 * 470s cc@32 wedge).  Declines are
					 * NORMAL under storm (cluster-mates
					 * active; fan_out owns the retry), so
					 * complete the pipeline as before —
					 * just remember not to clear the
					 * clocks below. */
					if (mxfs_iclus_unlock(mp,
						ip->i_ino,
						p_held_mode == MXFS_LOCK_EX ?
						MXFS_LOCK_EX : MXFS_LOCK_PR,
						false))
						p_iclus_declined = true;
					p6u_rc = 0;
					/* per-ino orphan-bit recovery
					 * (see mxfs_iclus_pi_reconcile).
					 * ONLY for entry-orphan pipelines
					 * (held_mode NL = the wedge shape) —
					 * a normal EX/PR demote pays no wire
					 * read here (the probe cost showed up
					 * as +10-15s on cc@32 when applied to
					 * every routed release). */
					if (p_held_mode == MXFS_LOCK_NL)
						mxfs_iclus_pi_reconcile(ip,
							p_iclus_declined ?
							-EBUSY : 0);
				} else if (mxfs_release_proof_enforce &&
					   READ_ONCE(ip->i_mxfs_rel_state) ==
						MXFS_RELSTATE_WEDGED) {
					/* (ruling item 9): pre-CAS
					 * WEDGED re-check — never submit,
					 * never re-arm (-EIO, not -ESTALE). */
					p282c.cas_attempted = 0;
					p282c.defer_kind = MXFS_RELDEFER_WEDGE;
					p282c.defer_reason =
						"wedged — CAS refused";
					p282c.drain_ns =
						ktime_get_ns() - p282_t0;
					mxfs_release_cert_emit(&p282c);
					p6u_rc = -EIO;
				} else {
					p282c.rel_state_cas = READ_ONCE(
						ip->i_mxfs_rel_state);
					p282c.rel_gen = p_rel_gen;
					mxfs_rel_state_set(ip,
						MXFS_RELSTATE_RELEASING);
					p282c.rel_instance = atomic_inc_return(
						&ip->i_mxfs_rel_instance);
					/*
					 * (design-consult ruling): CLEAN-RELEASE
					 * MARKER.  Every abort arm has passed, the
					 * drain above has landed every image this
					 * tenure logged, and the terminal store
					 * already made the release irrevocable
					 * (mode NL, authority RELEASING, later
					 * installs of this epoch refused).  Publish
					 * the XFS_LI_MXFS_RELMARK for the tenure and
					 * force it, so it is durable BEFORE the CAS
					 * below clears our holder bit: a crash now
					 * leaves the bit (APPLY at replay), a crash
					 * after the CAS finds the marker
					 * (REDUNDANT_CLEAN, no quarantine).
					 */
					mxfs_inode_relmark_before_unlock(ip,
						p_rel_res, p_rel_epoch,
						p_rel_lineage, &p_rel_marked,
						"ino-anchored");
					mxfs_dbg_rel_pause(ip, 5);
					p6u_rc = mxfs_v5_dlm_inode_unlock_open(
						mp->m_mxfs_dlm, ip->i_ino,
						p_rel_gen, p_open_op);
					mxfs_inode_relcert_finish(ip, &p282c,
								  p6u_rc,
								  p282_t0);
				}
				p2s_f = ktime_get_ns();	/* su split */
			}
			}	/* rb_defer scope */
			if (p15h_reap)
				mxfs_probe("mxfs: P15H-UNLOCK-DONE ino=%llu rel_gen=%u rc=%d\n",
					(unsigned long long)ip->i_ino,
					p_rel_gen, p6u_rc);
			if (p6u_rc == -ESTALE)
				stranded = true;
			else if (unlikely(mxfs_rel_stale_inject) &&
				 (xfs_is_unmounting(mp) ||
				  xfs_is_shutdown(mp))) {
				/* A/B injector: the natural teardown-
				 * era strand (release failing -ESTALE after
				 * shutdown) is a race tail — force the verdict
				 * so the P6G arm decision below is exercised
				 * deterministically on demand. */
				mxfs_probe_ratelimited("mxfs: P6G-INJECT-STALE ino=%llu rc=%d — forcing teardown-era strand (test injector)\n",
					(unsigned long long)ip->i_ino, p6u_rc);
				stranded = true;
			}
		}

		if (stranded) {
			spin_lock(&ip->i_dlm_lock);
			if (!ip->i_dlm_bast_pending)
				ip->i_dlm_dwork_strikes = 0;	/* v0.10.31 */
			ip->i_dlm_bast_pending = true;
			/* daf50d34 STATE OWNERSHIP: this pipeline may
			 * only clear a state it owns (DEMOTING/BAST).  A
			 * concurrent slow-path acquire (ACQUIRING) or a
			 * completed grant (CACHED) owns the field now —
			 * trampling it to NONE is what let bast_notify's
			 * NONE-idle branch kill the fresh tenure (proven
			 * mkdir-storm r5 chain). */
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
			    ip->i_dlm_state == MXFS_DLM_ISTATE_BAST)
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			spin_unlock(&ip->i_dlm_lock);
			mxfs_probe("mxfs: P6G-REL-STALE ino=%llu rel_gen=%u — newer grant owns the resource; release deferred to bast dwork\n",
				(unsigned long long)ip->i_ino, p_rel_gen);
			/*
			 * D-DWORK-TEARDOWN-LASTREF-LEAK: during unmount
			 * (or after shutdown / DLM teardown) this deferral can
			 * accomplish nothing — put_super's v5_shutdown sweep
			 * owns the on-disk grants and m_mxfs_dlm may already be
			 * NULL — while the armed dwork's igrab ref becomes the
			 * inode's LAST ref: eviction then never runs, the P204
			 * cancel never engages, the 4ms timer outlives
			 * xfs_free_perag, ident_ok fails (pag=NULL) and the
			 * P142 last-ref guard leaks the inode at unload
			 * (captured live: ino 31457413, P6G -> P142-DWORK-
			 * STALE -> P142-DWORK-LASTREF).  The put_super entry
			 * flush cannot see a timer-pending delayed work, so
			 * the arm itself must not happen in this window.
			 */
			if (mxfs_teardown_arm_gate &&
			    (xfs_is_unmounting(mp) || xfs_is_shutdown(mp) ||
			     !mp->m_mxfs_dlm)) {
				pr_warn("mxfs: P6G-REL-STALE-TEARDOWN ino=%llu unmounting=%d shutdown=%d dlm=%d — stranded at teardown; no dwork arm (release_all sweep owns the slot)\n",
					(unsigned long long)ip->i_ino,
					xfs_is_unmounting(mp) ? 1 : 0,
					xfs_is_shutdown(mp) ? 1 : 0,
					mp->m_mxfs_dlm ? 1 : 0);
				/* (ruling item 8): an
				 * UNPROVEN release abandoned here would let
				 * release_all strip the slot without proof —
				 * the same latent hole the ICLUS teardown
				 * pin closed for class 2.  Pin-only wedge. */
				if (mxfs_release_proof_enforce &&
				    (p_rb_deferred ||
				     READ_ONCE(ip->i_mxfs_reldefer_started_j))) {
					struct mxfs_release_cert p6gt_cert = {
						.res_id = ip->i_ino,
						.rclass = MXFS_RELCLASS_INODE,
						.path = "teardown",
						.old_epoch = ip->i_dlm_epoch,
					};

					mxfs_inode_wedge(ip, &p6gt_cert, true);
				}
				wake_up_all(&ip->i_dlm_wait);
				return;
			}
			/* 2026-07-16: igrab, never raw ihold (BUG3 family —
			 * see P134-BASTQ-FREEING at the orphan_rearm site). */
			if (igrab(vip)) {
				unsigned long p6g_delay =
					msecs_to_jiffies(4) + 1;

				/* (ruling item 5): once an
				 * episode is open, exponential backoff +
				 * jitter owns the retry pace, clamped to the
				 * remaining episode deadline so the bound is
				 * checked ON TIME, not one backoff late. */
				spin_lock(&ip->i_dlm_lock);
				if (mxfs_release_proof_enforce &&
				    ip->i_mxfs_reldefer_started_j) {
					unsigned int p6g_tries =
						ip->i_mxfs_reldefer_tries;
					unsigned int p6g_ms =
						min(25u << min(p6g_tries, 5u),
						    1000u);
					unsigned long p6g_dl, p6g_rem;

					p6g_ms += get_random_u32_below(
							p6g_ms / 4 + 1);
					/* same knobs as
					 * mxfs_inode_episode_expired_locked —
					 * this deadline exists so the bound is
					 * checked ON TIME, so it must shrink
					 * with the bound or a shortened test
					 * bound would simply be slept past. */
					p6g_dl = min(
					    ip->i_mxfs_reldefer_progress_j +
						msecs_to_jiffies(READ_ONCE(
						  mxfs_reldefer_noprogress_ms)),
					    ip->i_mxfs_reldefer_started_j +
						msecs_to_jiffies(READ_ONCE(
						  mxfs_reldefer_total_ms)));
					p6g_rem = time_after(p6g_dl, jiffies) ?
						p6g_dl - jiffies : 1;
					p6g_delay = min_t(unsigned long,
						msecs_to_jiffies(p6g_ms) + 1,
						p6g_rem);
				}
				spin_unlock(&ip->i_dlm_lock);
				ip->i_dlm_bastq_src = 10;
				if (!mxfs_bast_arm_queue_delayed(ip, p6g_delay))
					xfs_irele(ip);	/* dwork already armed */
			} else {
				mxfs_probe_ratelimited("mxfs: P134-BASTQ-FREEING ino=%llu site=rel_stale_defer i_state=0x%lx (inode evicting; skipping deferred release)\n",
					(unsigned long long)ip->i_ino,
					mxfs_istate(vip));
			}
			wake_up_all(&ip->i_dlm_wait);
			return;
		}
	}
	/* PROVEN BY INSTRUMENT: the resource-scoped orphan/
	 * starve clocks were armed by any single abort sample and cleared
	 * ONLY by their own 3s forces — never by a completed release (the
	 * starve-clock arm comment always claimed "cleared where a REAL
	 * release actually completes" but only the in-core clock was).  On a
	 * hot contended dir every bit-owner node therefore fired a spurious
	 * gen-blind P15H-PEER-STARVE-TIMEOUT force every ~3s all test long
	 * (cc@32: 72 forces/73s run, all on the 2 rv dirs, spread over 25
	 * nodes; dmesg-proven force 0.4s after a successful EXIT=full
	 * rel_gen=1411, and force lines carried state=ACQUIRING — stomping
	 * just-won live grants).  A completed wire unlock ends any starvation
	 * episode by definition; the next episode re-arms from its own first
	 * abort sample.  addendum: a routed release whose cluster
	 * release_check DECLINED (p_iclus_declined) did NOT end the peer's
	 * wait — keep the clocks armed so the 3s last-resort force can still
	 * fire on a genuinely stuck decline loop (the captured 470s ABBA). */
	if (!p_iclus_declined &&
	    mp->m_mxfs_dlm && mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
		mxfs_v5_dlm_inode_orphan_clock_set(mp->m_mxfs_dlm, ip->i_ino,
						   false, 0);
		mxfs_v5_dlm_inode_orphan_clock_set(mp->m_mxfs_dlm, ip->i_ino,
						   true, 0);
	}
	/* audit the platter RIGHT AFTER our wire unlock —
	 * a nonzero refs_into_holes here convicts THIS release (see
	 * mxfs_dir_platter_audit).  Contended dirs only; capped inside. */
	if (S_ISDIR(vip->i_mode) && p_held_mode == MXFS_LOCK_EX &&
	    ip->i_dlm_dir_contended && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_dir_platter_audit(ip);

	mxfs_idbg("mxfs: P13-INSTR ino=%llu REL-INLINE-POST realns=%llu\n",
		(unsigned long long)ip->i_ino,
		(unsigned long long)ktime_get_real_ns());
	/*
	 * v0.5.6 P138 (always-on, >5ms, ratelimited): holder-side cost of one
	 * BAST-driven release, slot now free on disk (realns marks that
	 * moment).  Correlate with the requesting node's P138-WAIT grant line
	 * to split a slow cross-node lock migration into holder-release vs
	 * delivery/discovery dead time.
	 */
	if (ktime_get_ns() - p131_t0 > 5 * NSEC_PER_MSEC) {
		u64 p2now = ktime_get_ns();

		mxfs_probe_ratelimited(
		    "mxfs: P138-BAST ino=%llu dur_us=%llu dir=%d clean=%d sa=%llu sb=%llu b1=%llu b2=%llu sc=%llu c1=%llu sd=%llu su=%llu sw=%llu sx=%llu realns=%llu\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)((p2now - p131_t0) / 1000),
			S_ISDIR(vip->i_mode) ? 1 : 0,
			p2_reg_clean ? 1 : 0,
			/* 0.75.54 stage order: a, c (pages), b (settle+drain+
			 * flush), d — each field is its own stage's duration. */
			(unsigned long long)(p2s_a ? (p2s_a - p131_t0) / 1000 : 0),
			(unsigned long long)((p2s_b && p2s_c) ? (p2s_b - p2s_c) / 1000 : 0),
			(unsigned long long)((p2s_b1 && p2s_c) ? (p2s_b1 - p2s_c) / 1000 : 0),
			(unsigned long long)((p2s_b2 && p2s_b1) ? (p2s_b2 - p2s_b1) / 1000 : 0),
			(unsigned long long)((p2s_c && p2s_a) ? (p2s_c - p2s_a) / 1000 : 0),
			(unsigned long long)((p2s_c1 && p2s_a) ? (p2s_c1 - p2s_a) / 1000 : 0),
			(unsigned long long)((p2s_d && p2s_b) ? (p2s_d - p2s_b) / 1000 : 0),
			(unsigned long long)(p2s_d ? (p2now - p2s_d) / 1000 : 0),
			/* su split: sw = drain-end -> unlock entry
			 * (pre-unlock tail incl. P3B/P196 machinery); sx =
			 * the wire unlock proper.  Zero when the pipeline
			 * exited via another arm. */
			(unsigned long long)((p2s_e && p2s_d) ? (p2s_e - p2s_d) / 1000 : 0),
			(unsigned long long)((p2s_f && p2s_e) ? (p2s_f - p2s_e) / 1000 : 0),
			(unsigned long long)ktime_get_real_ns());
	}

	/* Clear cached state */
	spin_lock(&ip->i_dlm_lock);
	/* daf50d34 STATE OWNERSHIP: only clear a state this pipeline
	 * owns (DEMOTING/BAST).  Writing NONE over a concurrent slow-path
	 * acquire's ACQUIRING (or a completed grant's CACHED) is the PROVEN
	 * trample that let bast_notify's NONE-idle branch release a fresh
	 * grant before its acquiring op ever used it (mkdir-storm r5,
	 * durable node1 loss). */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING ||
	    ip->i_dlm_state == MXFS_DLM_ISTATE_BAST)
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	else
		mxfs_probe_ratelimited(
		    "mxfs: P-BP-EXIT-KEEP ino=%llu state=%u mode=%u — pipeline exit leaving foreign state untouched\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_state,
			ip->i_dlm_mode);
	spin_unlock(&ip->i_dlm_lock);

	/* Wake any threads blocked in ilock_begin waiting on DEMOTING */
	wake_up_all(&ip->i_dlm_wait);

	/* P70: full-pipeline exit (master unlock done/skipped
	 * via gen path above).  Pairs with ENTRY; a missing FULL/P15/P6Z/P6G
	 * tag between ENTRY and the next ENTRY = the instance died mid-flush. */
	{
		static atomic_t p70f_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p70f_n) <= 6000)
			mxfs_probe("mxfs: P70-BP ino=%llu EXIT=full rel_gen=%u ex=%u pr=%u comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino, p_rel_gen,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
	}
}

/*
 * P142: identity cross-check for the two BAST work
 * fns.  Two live panics (test26 21:15Z ino=0, test5 21:40Z agino=0xb7 —
 * radix_tree_tag_set BUG via dwork xfs_irele → destroy_inode on an inode
 * ABSENT from pag_ici_root) prove a work item can fire against an xfs_inode
 * object that is no longer the radix-current inode for its claimed number
 * (freed+recycled mid-iget-setup, or i_ino already zeroed by reclaim).  The
 * i_count/I_CLEAR guards cannot catch that: a recycled object looks LIVE.
 * Authoritative check: the pag_ici_root slot for the claimed ino must point
 * back at THIS object.  (A ref-holding work item keeps its inode out of
 * reclaim, and iget-recycle of a RECLAIMABLE inode keeps it in the radix
 * tree, so a mismatch here is never a false positive.)  On mismatch, log
 * the arming site and bail without touching the object — leak-not-crash,
 * the same tradeoff as the P60/P124 guards.
 */
static bool
mxfs_dlm_work_ident_ok(struct xfs_inode *ip, const char *which)
{
	struct xfs_mount	*mp = READ_ONCE(ip->i_mount);
	xfs_ino_t		ino = READ_ONCE(ip->i_ino);
	struct xfs_perag	*pag = NULL;
	struct xfs_inode	*cur = NULL;
	struct xfs_inode	*cur2 = NULL;
	static atomic_t		p142_stale_n = ATOMIC_INIT(0);
	static atomic_t		p142_rcumiss_n = ATOMIC_INIT(0);
	int			n;

	if (!mp || !ino)
		goto stale;
	if (XFS_INO_TO_AGNO(mp, ino) >= mp->m_sb.sb_agcount)
		goto stale;
	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
	if (!pag)
		goto stale;
	rcu_read_lock();
	cur = radix_tree_lookup(&pag->pag_ici_root,
				XFS_INO_TO_AGINO(mp, ino));
	rcu_read_unlock();
	if (cur == ip) {
		xfs_perag_put(pag);
		return true;
	}
	/* RCU miss — retake under the ici lock (serialized vs insert/
	 * delete) before declaring the object stale. */
	mxfs_ici_lock(pag);
	cur2 = radix_tree_lookup(&pag->pag_ici_root,
				 XFS_INO_TO_AGINO(mp, ino));
	spin_unlock(&pag->pag_ici_lock);
	if (cur2 == ip) {
		n = atomic_inc_return(&p142_rcumiss_n);
		if (n <= 40)
			mxfs_probe("mxfs: P142-%s-RCUMISS ino=%llu agno=%u agino=%u ip=%px (rcu lookup missed, locked lookup hit — proceeding)\n",
				which, (unsigned long long)ino,
				XFS_INO_TO_AGNO(mp, ino),
				XFS_INO_TO_AGINO(mp, ino), ip);
		xfs_perag_put(pag);
		return true;
	}
stale:
	n = atomic_inc_return(&p142_stale_n);
	if (n <= 60) {
		mxfs_probe("mxfs: P142-%s-STALE ip=%px ino=%llu rcu_cur=%px locked_cur=%px agno=%u agino=%u agcount=%u pag=%px pag_agno=%d src=%u i_count=%d i_state=0x%lx — work fired on non-current inode object; bailing (ref not dropped)\n",
			which, ip, (unsigned long long)ino, cur, cur2,
			mp ? XFS_INO_TO_AGNO(mp, ino) : (xfs_agnumber_t)-1,
			mp ? XFS_INO_TO_AGINO(mp, ino) : (xfs_agino_t)-1,
			mp ? mp->m_sb.sb_agcount : 0,
			pag, pag ? (int)pag_agno(pag) : -1,
			ip->i_dlm_bastq_src,
			atomic_read(&VFS_I(ip)->i_count), mxfs_istate(VFS_I(ip)));
		if (n <= 4)
			mxfs_probe_stack();
	}
	if (pag)
		xfs_perag_put(pag);
	return false;
}

/*
 * Work function for deferred BAST processing.
 * The xfs_iget(INCORE) ref is transferred to us — we must xfs_irele.
 */
void
mxfs_dlm_bast_work_fn(
	struct work_struct	*work)
{
	struct xfs_inode	*ip;

	ip = container_of(work, struct xfs_inode, i_dlm_bast_work);
	if (unlikely(!mxfs_dlm_work_ident_ok(ip, "BWORK"))) {
		/* Live pre-insert placeholder (freed placeholders are
		 * cancel_sync'd in xfs_iget_cache_miss's out_destroy):
		 * drop our arm ref unless it is the last — a last-ref
		 * iput would VFS-destroy an uninserted inode (the
		 * inodegc radix-tag BUG this guard exists to prevent). */
		if (!atomic_add_unless(&VFS_I(ip)->i_count, -1, 1))
			pr_warn("mxfs: P142-BWORK-LASTREF ino=%llu — ref intentionally leaked\n",
				(unsigned long long)ip->i_ino);
		return;
	}
	mxfs_bastq_lat_probe(ip, "BWORK");
	mxfs_dbg_bast_defer(ip, "BWORK");	/* D-0532 item (c) arm; no-op unless armed */
	/* same retirement as the dwork sibling — a claim stranded by
	 * the trans-free punt can equally be found by the immediate bast_work
	 * path, and retiring it BEFORE our own MXFS_SET_DEMOTER is what lets us
	 * take slot 1 instead of being pushed into slot 2 (being pushed into
	 * slot 2 is how the stranded claim survived every release). */
	mxfs_demoter_punt_reclaim_check(ip, 2);
	/*
	 * TEST-ONLY INJECTOR (mxfs.bast_qfalse_inject): self-requeue
	 * with our OWN donated ref so WORK_STRUCT_PENDING stays set for the
	 * duration of this run — every bast_notify dispatch in that window
	 * deterministically takes its queue_work-false branch, exercising the
	 * P226 extra-ref drop (the D-UNMOUNT-BUSY-INODES leak site).  The
	 * requeued instance runs as a harmless no-op release pass and ireles
	 * the ref donated here.  NEVER ship on.
	 */
	if (unlikely(mxfs_bast_qfalse_inject)) {
		if (igrab(VFS_I(ip))) {
			if (!mxfs_bast_arm_queue(ip))
				iput(VFS_I(ip));	/* already pending */
		}
	}
	MXFS_SET_DEMOTER(ip);
	{
		struct mxfs_dirdrain_task dde;	/* FENCE-V1 sanction bracket */

		mxfs_dirdrain_enter(&dde);
		mxfs_dlm_bast_process(ip);
		mxfs_dirdrain_exit(&dde);
	}
	/*
	 * detector (always-on, cheap): a healthy bast_work_fn always
	 * holds a pinning ref (i_count >= 1) and the inode is never I_CLEAR.
	 * i_count==0 or I_CLEAR here means a queue site scheduled us without a
	 * valid igrab ref (the freeing-inode UAF the EDEADLK/ACQBAST fixes
	 * close) — log it loudly instead of crashing in iput's BUG_ON.
	 *
	 *  i_dlm_demoter MUST stay == current through
	 * this xfs_irele, not just through mxfs_dlm_bast_process above.  If
	 * this is the last reference, xfs_irele cascades synchronously into
	 * evict -> destroy_inode -> xfs_inode_mark_reclaimable's MXFS
	 * synchronous-inactivation path -> xfs_inactive -> xfs_attr_inactive,
	 * which takes its OWN xfs_ilock/xfs_iunlock on this SAME ip.
	 * mxfs_dlm_ilock_begin's DEMOTING/ACQUIRING/BAST wait loop exempts
	 * i_dlm_demoter==current for exactly this re-entry ("Demoter is
	 * exempt (it must re-enter during its own drain)") — but with
	 * demoter already cleared here, that nested ilock is treated as a
	 * brand-new external acquisition and blocks forever waiting for a
	 * release this very thread was driving: a self-deadlock.  Instrumented
	 * proven live: kworker/uN+mxfs-ino-bast caught via /proc/pid/stack
	 * permanently stuck (900s+, monotonically growing) in exactly
	 * mxfs_dlm_ilock_begin under this call chain, immediately preceded
	 * by a kernel fs/inode.c:451 ihold() WARN_ON on the same PID (grabbing
	 * a reference on an inode whose count was already 0 mid-eviction) —
	 * the soft lockup first seen at fence_during_write@8/caw
	 * (P-DBLRECLAIM in xfs_icache.c).  Moved below the irele so the
	 * exemption window covers it.
	 */
	{
		int cnt = atomic_read(&VFS_I(ip)->i_count);
		unsigned long st = mxfs_istate(VFS_I(ip));
		if (unlikely(cnt < 1 || (st & I_CLEAR)))
			mxfs_probe("mxfs: P60-BWFN-BADREF ino=%llu i_count=%d i_state=0x%lx I_CLEAR=%d (phantom bast queue — NOT releasing)\n",
				(unsigned long long)ip->i_ino, cnt, st,
				!!(st & I_CLEAR));
		else {
			/*
			 * TEST-ONLY INJECTOR (mxfs.bast_irele_unclaim_inject).
			 *
			 * Drops our own claim immediately before the trailing
			 * irele, which is byte-for-byte the state a stolen claim
			 * leaves us in.  It exists because the WEDGE and the
			 * THEFT have different rates: a legacy-clobber arm
			 * measured 30 live-claim steals and 19 live clears in one
			 * 32-node run and still produced wedge_precond=0, because
			 * the wedge additionally needs THIS irele to be the last
			 * reference so it cascades into inactivation.  Waiting
			 * for all three to coincide is not a test.  This forces
			 * the third condition, so the wedge itself becomes
			 * demonstrable on demand and the fix can be shown to
			 * prevent it rather than merely to coexist with its
			 * absence.  NEVER ship on.
			 */
			if (unlikely(mxfs_bast_irele_unclaim_inject)) {
				static atomic_t p78n = ATOMIC_INIT(0);

				atomic64_inc(&mxfs_dem_inject_unclaim);
				if (atomic_inc_return(&p78n) <= 200)
					mxfs_probe("mxfs: P78-UNCLAIM-INJECT ino=%llu me=%d i_count=%d state=%u — dropping own claim before trailing irele (TEST-ONLY)\n",
						(unsigned long long)ip->i_ino,
						current->pid, cnt,
						ip->i_dlm_state);
				MXFS_CLEAR_DEMOTER(ip);
			}
			xfs_irele(ip);
		}
	}
	MXFS_CLEAR_DEMOTER(ip);
}

/*
 * Minimum Hold Time (MHT) timer expiry.  Scheduled by bast_notify
 * when a peer BAST arrives within the MHT window of a fresh inode-EX grant
 * (see mxfs_inode_mht_ms).  During the window state was kept CACHED so our own
 * queued ops kept fast-pathing through the cached grant; now the window has
 * elapsed and we honor the deferred BAST.  Owns the xfs_iget ref that
 * bast_notify transferred to us — must xfs_irele on every path.
 */
/*
 *  (PROVEN BY INSTRUMENT — live crash on test6,
 * fence_during_write@8/caw, addr2line-confirmed RIP at the xfs_irele call
 * that used to sit at xfs_mxfs_dlm.c:14135): mxfs_dlm_bast_work_fn already
 * guards its own ihold()-owned xfs_irele against a phantom/already-freeing
 * inode (see its "detector" comment a few hundred lines above) —
 * mxfs_dlm_bast_dwork_fn never got the same guard on any of its 4 exit
 * paths, so the identical race crashed in iput()'s own
 * VFS_BUG_ON_INODE(state & (I_FREEING|I_CLEAR)) (fs/inode.c:1980) instead of
 * degrading to a warning like its sibling.  Mirrors that exact condition,
 * widened to ALSO check I_FREEING (bast_work_fn's check only tests
 * I_CLEAR; I_FREEING is set first and is what iput() actually asserts on).
 * Returns true if it was safe to drop the ref (and did); false if the inode
 * looked already-freeing (logged, ref intentionally leaked rather than
 * risking a UAF/double-free — this mirrors bast_work_fn's own tradeoff:
 * "NOT releasing" a live-inode ref is a diagnosable leak, not a crash).
 */
/*
 * (design-consult scoped): targeted old-layer recovery for
 * a STICKY-routed inode carrying an orphaned PER-INO holder bit from its
 * mode-0-shell era.  The sticky conversion (mxfs_dlm_inode_lock_routed)
 * drops a live per-ino grant only when in-core mode != NL — an NL-orphaned
 * EX bit (strand aborts) becomes permanently unreachable: every release
 * routes cluster-ward while peers wait on the per-ino slot (captured 470s
 * cc@32 ABBA: test29 bit + test5 create).  Called ONLY from the release
 * pipeline's unlock stage, where this inode's FULL drain has already run
 * (invariant #1 satisfied); gated on no local consumer and no in-flight
 * slow-path acquire, both under i_dlm_lock; one wire read when gated in.
 */
static void
mxfs_iclus_pi_reconcile(struct xfs_inode *ip, int clus_rc)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			pi_ok;

	spin_lock(&ip->i_dlm_lock);
	pi_ok = ip->i_dlm_acq_inflight == 0 &&
		ip->i_dlm_mode == MXFS_LOCK_NL &&
		ip->i_dlm_ex_holders == 0 &&
		ip->i_dlm_pr_holders == 0;
	spin_unlock(&ip->i_dlm_lock);
	if (!pi_ok || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm, ip->i_ino) != 1)
		return;
	{
		int pirc = mxfs_v5_dlm_inode_unlock_gen(mp->m_mxfs_dlm,
							ip->i_ino, 0);

		pr_warn("mxfs: P-ICLUS-PI-RECON ino=%llu rc=%d clus_rc=%d — routed inode's orphaned per-ino bit cleared post-drain\n",
			(unsigned long long)ip->i_ino, pirc, clus_rc);
	}
}

static bool
mxfs_dlm_dwork_safe_irele(struct xfs_inode *ip, int site)
{
	int cnt = atomic_read(&VFS_I(ip)->i_count);
	unsigned long st = mxfs_istate(VFS_I(ip));

	if (unlikely(cnt < 1 || (st & (I_FREEING | I_CLEAR)))) {
		mxfs_probe("mxfs: P124-DWFN-BADREF ino=%llu site=%d i_count=%d i_state=0x%lx (phantom dwork queue — NOT releasing)\n",
			(unsigned long long)ip->i_ino, site, cnt, st);
		return false;
	}
	xfs_irele(ip);
	return true;
}

void
mxfs_dlm_bast_dwork_fn(
	struct work_struct	*work)
{
	struct xfs_inode	*ip;

	ip = container_of(work, struct xfs_inode, i_dlm_bast_dwork.work);
	if (unlikely(!mxfs_dlm_work_ident_ok(ip, "DWORK"))) {
		/* See the BWORK sibling: drop the arm ref unless last. */
		if (!atomic_add_unless(&VFS_I(ip)->i_count, -1, 1))
			pr_warn("mxfs: P142-DWORK-LASTREF ino=%llu — ref intentionally leaked\n",
				(unsigned long long)ip->i_ino);
		return;
	}

	mxfs_bastq_lat_probe(ip, "DWORK");
	mxfs_dbg_bast_defer(ip, "DWORK");	/* D-0532 item (c) arm; no-op unless armed */

	/*
	 *  this dwork IS the release the trans-free punt
	 * handed off to, so it is the natural place to retire the claim the
	 * punt retained.  Checked at the TOP, before any of the four early
	 * returns below (bast already consumed / strikeout / busy re-arm /
	 * quiet-age re-arm) — a claim stranded by a punt whose dwork then
	 * strikes out is exactly the shape that produced the 179-second
	 * straggler.  No-op (one predictable branch) unless a punt happened.
	 */
	mxfs_demoter_punt_reclaim_check(ip, 1);

	/*
	 * ROOT FIX — D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380.
	 *
	 * THE BUG.  xfs_iflush has eleven "safe skip" fences that abandon a
	 * flush with `error = 0; goto flush_out;` and WITHOUT stamping
	 * i_mxfs_pub_flush_seq (P32E/P189/P17B/P25/P119/P65/P67/...).  Every one
	 * of them says "reload on next acquire" and sets i_dlm_stale to ask for
	 * it.  But i_dlm_stale had NO RELEASE-PATH CONSUMER — only ACCESS paths
	 * (xfs_iget/lookup, readdir) honored it.  So the publication obligation
	 * (pending_seq != durable_seq) stayed open forever, the drain re-logged
	 * the clean-but-unlanded core on every attempt (P146V), and each re-log
	 * bumped pending_seq through xfs_trans_log_inode — the drain's own
	 * repair feeding the counter it was waiting on.  Badness stayed pinned
	 * at OBLIG_OPEN, the 60s no-progress bound expired, and
	 * mxfs_inode_wedge pinned the grant and force-shut-down the WHOLE MOUNT.
	 * Measured (injected fence, ino 132): pending 6 -> 730 while flush
	 * stayed frozen at 6, then P-INODE-WEDGE tries=714 causes=0x1, mount
	 * down.  Whether it recovered was pure luck: the ONLY path that
	 * reconciles the ledger is the adopt inside mxfs_dlm_reload_inode, so
	 * survival depended on an unrelated local reader touching the inode
	 * inside the 60s window.
	 *
	 * THE FIX.  Drive the reload the fence asked for, from the release side.
	 * This worker is the right place per the design-consult ruling: it is
	 * OUTSIDE the drain, so it is not the documented ABBA site that takes
	 * folio locks while a parked writeback submitter waits on our demote,
	 * and it runs before the deadline check below — so a reload that lands
	 * prevents the wedge instead of racing it.
	 *
	 * WHAT THIS DOES NOT DO.  It does not invent a "superseded" verdict and
	 * it never touches durable_seq directly.  It calls the same adopt every
	 * access path already calls, so the same keep-guards (P3 changecount
	 * time-travel, P33/P43, P177 obligation merge, P34J demote-wait) remain
	 * the sole authority on whether the platter image may be installed, and
	 * a dropped committed change is still reported by
	 * P177-OBLIGATION-DROPPED-AT-ADOPT rather than laundered.  If the adopt
	 * bails, the obligation stays open and the wedge still fires — the
	 * fail-closed escalation is preserved, only its FALSE firings are
	 * removed.
	 *
	 * BOUNDED.  An inode whose reload keeps bailing must still reach the
	 * wedge rather than spin here forever, so the attempts are counted
	 * against the episode and stop at MXFS_RELDEFER_RELOAD_MAX.
	 */
	if (mxfs_reldefer_reload && READ_ONCE(ip->i_mxfs_pub_fenced) &&
	    READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
	    READ_ONCE(ip->i_mxfs_pub_durable_seq) &&
	    READ_ONCE(ip->i_mxfs_rel_state) != MXFS_RELSTATE_WEDGED) {
		bool do_reload = false;
		unsigned int rl_n;

		spin_lock(&ip->i_dlm_lock);
		rl_n = ip->i_mxfs_reldefer_reloads;
		if (ip->i_dlm_bast_pending && rl_n < MXFS_RELDEFER_RELOAD_MAX) {
			ip->i_mxfs_reldefer_reloads = rl_n + 1;
			do_reload = true;
		}
		spin_unlock(&ip->i_dlm_lock);

		if (do_reload) {
			uint64_t rl_p0 = READ_ONCE(ip->i_mxfs_pub_pending_seq);
			uint64_t rl_d0 = READ_ONCE(ip->i_mxfs_pub_durable_seq);
			uint64_t rl_p1, rl_d1;
			bool closed;

			/*
			 * design-consult ruling: an UNLINK conversion must never
			 * be closed by ADOPTION — the platter image is the
			 * pre-unlink dinode while the on-disk AGI entry
			 * (committed by the same transaction) remains, so
			 * adopting strands a list entry that the next adjacent
			 * remove/reload calls AGI corruption (the measured
			 * P177 -> P84-UNL-RELOAD-LIVE -> shutdown chain).  We
			 * are in the deferred-release worker: the tenure is
			 * kept, the on-disk grant is ours, no peer grant can
			 * become effective — the continuous-exclusion window
			 * the RELFLUSH sanction exists for.  Convert first;
			 * adopt only what conversion cannot claim.
			 */
			if (xfs_iflags_test(ip, MXFS_IF_PUBOB) &&
			    VFS_I(ip)->i_nlink == 0 &&
			    !xfs_is_shutdown(ip->i_mount)) {
				struct xfs_mount *cmp = ip->i_mount;
				struct xfs_perag *fpag = xfs_perag_get(cmp,
					XFS_INO_TO_AGNO(cmp, ip->i_ino));
				int frc = -EINVAL;

				if (fpag) {
					xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);
					frc = mxfs_iflush_agino_target(fpag,
						XFS_INO_TO_AGINO(cmp,
								 ip->i_ino),
						jiffies +
						msecs_to_jiffies(500));
					xfs_iflags_clear(ip,
							 MXFS_IF_DLM_RELFLUSH);
					xfs_perag_put(fpag);
				}
				mxfs_probe_ratelimited("mxfs: P245-REL-OBLIGATION-CONVERT ino=%llu rc=%d site=reldefer pend=%llu dur=%llu\n",
					(unsigned long long)ip->i_ino, frc,
					(unsigned long long)READ_ONCE(ip->i_mxfs_pub_pending_seq),
					(unsigned long long)READ_ONCE(ip->i_mxfs_pub_durable_seq));
			}

			if (READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
			    READ_ONCE(ip->i_mxfs_pub_durable_seq))
				mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN,
						      false);

			rl_p1 = READ_ONCE(ip->i_mxfs_pub_pending_seq);
			rl_d1 = READ_ONCE(ip->i_mxfs_pub_durable_seq);
			closed = (rl_p1 == rl_d1);

			/*
			 * Retiring a cause IS progress, and the deadline below
			 * is time-based, so an obligation we just closed must
			 * restamp the clock or the very next check wedges on a
			 * cause that no longer exists.  Restamp ONLY on an
			 * actual close: a bailed adopt must not buy time.
			 */
			if (closed) {
				/* obligation resolved — the abandonment is
				 * settled, so re-arm the detector for the next
				 * one instead of leaving it latched. */
				WRITE_ONCE(ip->i_mxfs_pub_fenced, 0);
				spin_lock(&ip->i_dlm_lock);
				if (ip->i_mxfs_reldefer_started_j)
					ip->i_mxfs_reldefer_progress_j = jiffies;
				spin_unlock(&ip->i_dlm_lock);
			}
			pr_warn_ratelimited(
			    "mxfs: P382-RELDEFER-RELOAD ino=%llu n=%u/%u stale_src=%u pend=%llu->%llu dur=%llu->%llu closed=%d — release-side reload of a fence-abandoned publication\n",
				(unsigned long long)ip->i_ino, rl_n + 1,
				MXFS_RELDEFER_RELOAD_MAX, ip->i_dlm_stale_src,
				(unsigned long long)rl_p0,
				(unsigned long long)rl_p1,
				(unsigned long long)rl_d0,
				(unsigned long long)rl_d1, closed ? 1 : 0);
		}
	}

	spin_lock(&ip->i_dlm_lock);
	if (!ip->i_dlm_bast_pending) {
		/*
		 * The deferred BAST was already consumed by another path
		 * (eviction, unmount, or a state transition that ran the
		 * drain).  Nothing to do.
		 */
		spin_unlock(&ip->i_dlm_lock);
		mxfs_dlm_dwork_safe_irele(ip, 1);
		return;
	}

	/* (ruling item 5): episode deadlines carry across
	 * ALL dwork branches — BUSY included.  Checked at every re-entry so
	 * a reacquired holder cannot park an expired episode in the strike
	 * machinery (~30 min) while the bound claims 300s. */
	if (mxfs_release_proof_enforce &&
	    READ_ONCE(ip->i_mxfs_rel_state) != MXFS_RELSTATE_WEDGED &&
	    mxfs_inode_episode_expired_locked(ip)) {
		struct mxfs_release_cert dwedge_cert = {
			.res_id = ip->i_ino,
			.rclass = MXFS_RELCLASS_INODE,
			.path = "dwork-deadline",
			.old_epoch = ip->i_dlm_epoch,
		};

		spin_unlock(&ip->i_dlm_lock);
		mxfs_inode_wedge(ip, &dwedge_cert, false);
		mxfs_dlm_dwork_safe_irele(ip, 5);
		return;
	}

	/*
	 * If an op is in flight (active holder or a multi-step pin), we cannot
	 * release the grant yet.
	 *
	 * ROOT FIX of the dir_reuse 2/tcp residual ~6s stall:
	 * the prior code CONSUMED i_dlm_bast_pending here and set state=BAST,
	 * relying on the last ilock_end / mxfs_inode_unpin (holders==pin==0) to
	 * run the drain+unlock.  But a subsequent SAME-NODE create re-acquires
	 * the cached grant via the fast path, which resets i_dlm_state back to
	 * CACHED — losing the BAST hint — so the last holder's ilock_end never
	 * sees state==BAST and the fresh EX grant is held IDLE until the
	 * waiting peer's 6000ms ACQUIRE_WAIT retry re-fires the BAST.  PROVEN:
	 * the batching holder sat idle holding EX for ~6.1s after finishing its
	 * 100-file burst (peer P34-ACQ-SLOW dur_ms~6198), on ~10/24 rounds,
	 * pushing the 24-round test over its 300s budget.
	 *
	 * Fix: do NOT consume i_dlm_bast_pending and do NOT set state=BAST
	 * (which a re-acquire would clobber).  Keep the grant CACHED so our own
	 * queued burst keeps fast-pathing, and RE-ARM this dwork to retry
	 * shortly.  We release at the first quiescent sample (holders==pin==0),
	 * i.e. ~MHT + one inter-op gap (~tens of ms) instead of 6s.  i_dlm_
	 * bast_pending survives re-acquire (the ilock_begin fast path never
	 * touches it), so it stays the authoritative "BAST owed" signal; the
	 * dwork remains the SOLE releaser (state never goes BAST here), so
	 * there is no double-release race with ilock_end/unpin.
	 */
	if (ip->i_dlm_pin_count > 0 ||
	    ip->i_dlm_ex_holders > 0 || ip->i_dlm_pr_holders > 0 ||
	    /* daf50d34 a slow-path acquire between grant and first
	     * hold is BUSY, not quiescent — releasing now strips the
	     * materializing tenure (proven mkdir-storm kill). */
	    ip->i_dlm_acq_inflight > 0) {
		/*
		 * v0.10.31 STRIKEOUT: ~8ms per re-arm, so 2500 strikes ~= 20s
		 * of CONTINUOUS busy within one deferral episode.  No genuine
		 * op holds ex/pr/pin that long without a quiescent sample; a
		 * counter that never drops is a LEAKED holder (create-path
		 * oops killed the task in place holding the dir locks, test9
		 * 2026-07-10).  Spinning forever holds our iget ref => the
		 * inode leaks at unmount ("Objects remaining") => post-rmmod
		 * bio completions panic the node.  Strike out: keep
		 * i_dlm_bast_pending set (ilock_end/unpin refire or a peer's
		 * ~1s BAST retry re-arms a fresh episode), drop the ref, stop
		 * re-arming.  The dir stays unusable if the holder truly
		 * leaked — that node is already lost — but the mount can
		 * unmount and the module can unload safely.
		 */
		u16 strikes = ++ip->i_dlm_dwork_strikes;

		spin_unlock(&ip->i_dlm_lock);
		if (strikes >= 2500) {
			/*
			 * STARVATION ROOT FIX,
			 * intervention-PROVEN on the live rig: stopping here
			 * with bast_pending set relied on "ilock_end/unpin
			 * refire or a peer's ~1s BAST retry" — but an IDLE
			 * holder has no local refire and CAW cannot push a
			 * BAST, so a holder that went quiet after striking
			 * out stranded its peer INDEFINITELY (captured:
			 * 4 idle PR holders all post-strikeout on dir
			 * ino=1959; test1's EX waiter starved 23.7 min with
			 * P-WAIT-EXTEND "holders alive" liveness extensions,
			 * then was granted seconds after a manual `ls` on
			 * one holder ran the release; fleet strikeouts all
			 * showed 20s+ of continuous ex=1 busy from
			 * collision-injection parking).  DOWNSHIFT instead
			 * of stopping: keep pending and re-arm at 1s — a
			 * quiescent holder releases at its next tick, a
			 * still-busy one costs one no-op/s.  The stop's
			 * ref-leak rationale (leaked holder => iget held
			 * forever => unmount leak) is bounded by the hard
			 * cap below (~30 min), and mxfs_dlm_evict cancels
			 * both BAST arms at teardown regardless.
			 */
			if (strikes < 2500 + 1800) {	/* ~30 min at 1s */
				if ((strikes - 2500) % 60 == 0)
					mxfs_probe("mxfs: P36-STRIKEOUT-SLOW ino=%llu ex=%u pr=%u pin=%u mode=%u state=%u strikes=%u — busy past strikeout; downshifted to 1s keep-alive (bast_pending stays set)\n",
						(unsigned long long)ip->i_ino,
						ip->i_dlm_ex_holders,
						ip->i_dlm_pr_holders,
						ip->i_dlm_pin_count,
						ip->i_dlm_mode,
						ip->i_dlm_state, strikes);
				if (mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies(1000)))
					return;	/* re-armed slow — keep ref */
				mxfs_dlm_dwork_safe_irele(ip, 3);
				return;
			}
			mxfs_probe("mxfs: P36-STRIKEOUT ino=%llu ex=%u pr=%u pin=%u mode=%u state=%u strikes=%u — dwork giving up this episode (bast_pending stays set)\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count, ip->i_dlm_mode,
				ip->i_dlm_state, strikes);
			mxfs_dlm_dwork_safe_irele(ip, 2);
			return;
		}
		mxfs_probe_ratelimited(
			"mxfs: P36-MHT-REARM ino=%llu busy ex=%u pr=%u pin=%u mode=%u state=%u strikes=%u exh_pid=%d exh_comm=%s exh_ms=%llu (re-arm dwork; peer NOT stranded)\n",
			(unsigned long long)ip->i_ino,
			ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
			ip->i_dlm_pin_count, ip->i_dlm_mode,
			ip->i_dlm_state, strikes,
			ip->i_dlm_exh_pid, ip->i_dlm_exh_comm,
			ip->i_dlm_exh_since_ns ?
				(ktime_get_real_ns() - ip->i_dlm_exh_since_ns) /
					NSEC_PER_MSEC : 0);
		/* (b58r1 184s stall): after ~1.6s of continuous refusal
		 * with a live EX admission, dump the HOLDER's kernel stack —
		 * the blocked holder's wait site is the missing edge of the
		 * cross-node cycle.  Re-dump every ~40s while the episode
		 * persists. */
		if (ip->i_dlm_ex_holders && ip->i_dlm_exh_pid &&
		    (strikes == 200 || strikes % 5000 == 0)) {
			mxfs_probe("mxfs: P36-EXH-STACK ino=%llu exh_pid=%d exh_comm=%s exh_ms=%llu strikes=%u — dumping blocked EX-admission holder\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_exh_pid, ip->i_dlm_exh_comm,
				ip->i_dlm_exh_since_ns ?
					(ktime_get_real_ns() -
					 ip->i_dlm_exh_since_ns) /
						NSEC_PER_MSEC : 0,
				strikes);
			mxfs_pal_dump_task_stack(ip->i_dlm_exh_pid);
		}
		if (mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies(4) + 1))
			return;		/* re-armed — keep our iget ref */
		mxfs_dlm_dwork_safe_irele(ip, 3);	/* already armed — drop the duplicate ref */
		return;
	}

	/* QUIET-AGE GATE: no holder/pin right now is
	 * NOT "batch over" — mid-burst op gaps (bash fork/exec between the
	 * storm's create/mv/rm syscalls, 2-10ms) look idle to an
	 * instantaneous sample, and releasing there is the proven
	 * per-syscall-handoff collapse (sf=2: 72s FAIL@8).  A tenure
	 * still inside its MHT window releases only once it has gone
	 * UNCONSUMED for >= the batch grace (one-shot tenures: the 15ms
	 * adaptive floor); otherwise re-arm for the quiet remainder.  Window
	 * expiry keeps today's semantics (release at first idle sample) so
	 * the MHT stays the hard anti-monopoly bound. */
	if (ip->i_dlm_mode == MXFS_LOCK_EX && ip->i_dlm_ex_acquire_ns &&
	    mxfs_dir_ex_batch_grace_ms > 0) {
		/* 0.75.58: the window is the inode's own (dir MHT, shortform
		 * dir window, or the file window). */
		int	eff_ms = mxfs_ex_tenure_window_ms(ip);
		u64	now, held_ns, quiet_ref, quiet_ns, q_ns;

		now = ktime_get_ns();
		held_ns = now - ip->i_dlm_ex_acquire_ns;
		quiet_ref = ip->i_dlm_tenure_lastop_ns > ip->i_dlm_ex_acquire_ns ?
			    ip->i_dlm_tenure_lastop_ns : ip->i_dlm_ex_acquire_ns;
		quiet_ns = now - quiet_ref;
		q_ns = (u64)(ip->i_dlm_tenure_ops <= 1 ? 15 :
			     mxfs_dir_ex_batch_grace_ms) * NSEC_PER_MSEC;
		if (eff_ms > 0 && held_ns < (u64)eff_ms * NSEC_PER_MSEC &&
		    quiet_ns < q_ns) {
			u64 rem_ns = q_ns - quiet_ns;
			u64 wrem_ns = (u64)eff_ms * NSEC_PER_MSEC - held_ns;

			if (rem_ns > wrem_ns)
				rem_ns = wrem_ns;
			ip->i_dlm_bastq_src = 9;
			spin_unlock(&ip->i_dlm_lock);
			if (mxfs_bast_arm_queue_delayed(ip, nsecs_to_jiffies(rem_ns) + 1))
				return;	/* re-armed — keep our iget ref */
			mxfs_dlm_dwork_safe_irele(ip, 3);
			return;
		}
	}

	ip->i_dlm_dwork_strikes = 0;	/* v0.10.31: quiescent — episode over */

	/* Quiescent — release now (mirror the bast_notify immediate path). */
	ip->i_dlm_bast_pending = false;
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	spin_unlock(&ip->i_dlm_lock);
	mxfs_idbg("mxfs: P124-MHT-EXPIRE ino=%llu releasing", (unsigned long long)ip->i_ino);
	MXFS_SET_DEMOTER(ip);
	{
		struct mxfs_dirdrain_task dde;	/* FENCE-V1 sanction bracket */

		mxfs_dirdrain_enter(&dde);
		mxfs_dlm_bast_process(ip);
		mxfs_dirdrain_exit(&dde);
	}
	/*  demoter must stay == current through this
	 * xfs_irele too — same self-deadlock fix as mxfs_dlm_bast_work_fn
	 * above (see its comment). */
	mxfs_dlm_dwork_safe_irele(ip, 4);
	MXFS_CLEAR_DEMOTER(ip);
}

/*
 * SF-DIR TENURE FLOOR — tcp_dlm_scaling 8-node window.
 *
 * The eager idle-release arms in mxfs_dlm_ilock_end / mxfs_inode_unpin
 * (sess9-v3 +) serve a parked BAST at the FIRST quiescent moment of
 * the tenure.  For a hot SHORTFORM dir under all-node churn (tds: 8 nodes
 * x 150 create/mv/rm rounds in ONE shared dir) that is every syscall
 * boundary: the ~2-5ms exec gap between a round's own create -> mv -> rm
 * hands the EX away 2-3x PER ROUND, and every handoff costs ~13ms of
 * release drain (P138-BAST p50=8.9ms) + ~7ms grant/reload — the cluster
 * serializes at ~20ms/op (measured 72s vs the 60s window: 2889 slow
 * releases for 1200 rounds).  KEEP the grant across idle gaps while the
 * tenure is younger than dir_sf_mht_ms: leave bast_pending SET (do not
 * consume) and make sure the MHT dwork is armed for the window remainder —
 * the dwork protocol then releases at the first quiescent sample
 * after expiry (re-arming every 4ms while ops are in flight).  Peer wait
 * stays bounded by dir_sf_mht_ms + one release drain; a full local round
 * now completes in ONE tenure.  Floor is EX + shortform-dir only:
 * block/leaf dirs keep the eager serve (dir_reuse's create storms batch
 * via in-flight ops + trans pins), and PR grants revoke as cheaply as
 * before.
 *
 * Returns the dwork delay (jiffies, > 0) if the caller must KEEP the
 * grant and arm the dwork via mxfs_dlm_sf_tenure_arm() after dropping
 * i_dlm_lock; 0 = release now (floor not applicable or window elapsed).
 * Caller holds ip->i_dlm_lock.
 */
unsigned long
mxfs_dlm_sf_tenure_keep_delay(
	struct xfs_inode	*ip)
{
	u64			mht_ns, held_ns;

	if (mxfs_dir_sf_mht_ms <= 0)
		return 0;
	if (ip->i_dlm_mode != MXFS_LOCK_EX || !ip->i_dlm_ex_acquire_ns)
		return 0;
	if (!S_ISDIR(VFS_I(ip)->i_mode) ||
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL)
		return 0;
	mht_ns = (u64)mxfs_dir_sf_mht_ms * NSEC_PER_MSEC;
	/* ADAPTIVE FLOOR: a tenure that served only ONE op is a
	 * one-shot (32-node cv-write storm: every node creates exactly one
	 * entry) — the full floor is pure serial tax on the 31 waiters
	 * (measured 65-90ms/handoff, phase 12s).  Grace it at 5ms: a
	 * genuine burst's next op lands in 2-5ms and upgrades the tenure
	 * to >=2 ops, which keeps the full batching floor. */
	if (ip->i_dlm_tenure_ops <= 1 && mht_ns > 15 * NSEC_PER_MSEC)
		mht_ns = 15 * NSEC_PER_MSEC;
	held_ns = ktime_get_ns() - ip->i_dlm_ex_acquire_ns;
	if (held_ns >= mht_ns)
		return 0;
	return nsecs_to_jiffies(mht_ns - held_ns) + 1;
}

/*
 * DIR-EX TENURE FLOOR — the shortform floor
 * generalized to EVERY dir format and to the state==BAST (mid-op BAST) arm.
 *
 * PROVEN BY INSTRUMENT root of the crash_consistency@32 budget FAIL (0/32): 32
 * nodes create 100 files each in ONE shared dir; a peer BAST arrives while
 * an op is in flight (holders>0), bast_notify parks it (state=BAST), and
 * ilock_end honored it UNCONDITIONALLY at op end — the floor only
 * covered the CACHED&&bpend arm, and its "state==BAST means the MHT window
 * already elapsed" assumption is FALSE for the busy-holder path (no MHT
 * check runs there).  Measured on test1 (run 20260710T004227Z): 107 dir-EX
 * full releases for its 100 creates = ONE create per cluster EX rotation
 * (~55-60ms/handoff x 4800 cluster ops ≈ 280s in write phase alone).
 * Flooring the tenure to the MHT window batches ~20-50 ops per tenure and
 * turns the write phase into ~2 rotations (~10-25s).
 *
 * Returns the dwork delay (jiffies) to KEEP a young dir-EX tenure, 0 to
 * release now.  Window: shortform dirs keep the short window
 * (dir_sf_mht_ms); block/leaf/btree dirs use inode_mht_ms (the "MHT 300ms
 * block-dirs" setting).  Caller holds ip->i_dlm_lock.
 */
unsigned long
mxfs_dlm_dir_tenure_keep_delay(
	struct xfs_inode	*ip)
{
	u64			mht_ns, held_ns;
	int			eff_ms;

	if (!mxfs_dir_ex_tenure_floor)
		return 0;
	if (ip->i_dlm_mode != MXFS_LOCK_EX || !ip->i_dlm_ex_acquire_ns)
		return 0;
	/* 0.75.58: regular files carry their own window (see
	 * mxfs_file_ex_tenure_ms); anything else has no floor. */
	if (!S_ISDIR(VFS_I(ip)->i_mode) && !S_ISREG(VFS_I(ip)->i_mode))
		return 0;
	eff_ms = mxfs_ex_tenure_window_ms(ip);
	if (eff_ms <= 0)
		return 0;
	mht_ns = (u64)eff_ms * NSEC_PER_MSEC;
	/* ADAPTIVE FLOOR — see the shortform twin above. */
	if (ip->i_dlm_tenure_ops <= 1 && mht_ns > 15 * NSEC_PER_MSEC)
		mht_ns = 15 * NSEC_PER_MSEC;
	held_ns = ktime_get_ns() - ip->i_dlm_ex_acquire_ns;
	if (held_ns >= mht_ns)
		return 0;
	/*
	 * SLIDING GRACE (see mxfs_dir_ex_batch_grace_ms): keep only long
	 * enough to bridge the holder's next op, capped by the window
	 * remainder.  Full-window keeps let 31 waiters pile up per tenure and
	 * tripped the orphan-live release-abort strand.
	 */
	{
		u64 rem_ns = mht_ns - held_ns;
		u64 grace_ns = (u64)(mxfs_dir_ex_batch_grace_ms > 0 ?
				     mxfs_dir_ex_batch_grace_ms : 1) *
			       NSEC_PER_MSEC;

		if (rem_ns > grace_ns)
			rem_ns = grace_ns;
		return nsecs_to_jiffies(rem_ns) + 1;
	}
}

/*
 * Arm the MHT dwork for a kept tenure (i_dlm_lock NOT held).  The dwork
 * owns an inode ref (mirrors the batch_arm protocol); if it is already
 * armed the duplicate ref is dropped.  igrab failure means the inode is
 * being evicted — eviction's own release path serves the parked BAST.
 */
void
mxfs_dlm_sf_tenure_arm(
	struct xfs_inode	*ip,
	unsigned long		delay_j)
{
	struct inode		*vip = VFS_I(ip);

	if (!igrab(vip))
		return;
	ip->i_dlm_bastq_src = 12;
	if (!mxfs_bast_arm_queue_delayed(ip, delay_j))
		iput(vip);
}

/*
 * try to defer a peer BAST under the Minimum Hold Time policy.
 * Caller holds ip->i_dlm_lock and has verified there is no in-flight ACQUIRING
 * slow path.  Returns true (lock DROPPED) if the BAST was deferred — state is
 * left CACHED and i_dlm_bast_dwork is scheduled for the remainder of the
 * window; the caller's iget ref is transferred to the dwork.  Returns false
 * (lock STILL HELD) if MHT does not apply (disabled, not EX, or window already
 * elapsed) — the caller falls through to its normal immediate/deferred path.
 */
static bool
mxfs_dlm_mht_defer_bast(
	struct xfs_inode	*ip)
{
	u64		held_ns, mht_ns, now;
	unsigned long	delay_j;
	int		eff_mht_ms;

	/*
	 * FORMAT-GATED MHT: a SHORTFORM (LOCAL-format) directory
	 * keeps its entire content INLINE in the dinode, so a cross-node EX
	 * handoff is made coherent by the ordinary whole-inode DLM reload — there
	 * are NO separate dir DATA/leaf/extent blocks for the handoff to leave
	 * stale (that is the LEAF/BTREE-format coherency bug that high mht masks).
	 * So a shortform dir does NOT need the long hold for correctness; a short
	 * hold lets a high-churn small shared dir (tcp_dlm_scaling: create→rename
	 * →rm, dir stays ~1-3 entries = shortform) hand off fast and fit its 60s
	 * window, while a large leaf/btree dir (dir_reuse: 800 entries) keeps the
	 * full mht.  Principled signal (dir on-disk format = real coherency risk),
	 * not a per-test knob.  dir_sf_mht_ms<0 disables (use global mht for all).
	 *
	 * 0.75.58: regular files use their own short window
	 * (mxfs_file_ex_tenure_ms) instead of the directory MHT; other inode
	 * types keep no window here.
	 */
	eff_mht_ms = mxfs_ex_tenure_window_ms(ip);

	if (eff_mht_ms <= 0)
		return false;
	if (ip->i_dlm_mode != MXFS_LOCK_EX)
		return false;
	if (ip->i_dlm_state != MXFS_DLM_ISTATE_CACHED)
		return false;	/* only a clean cached grant can stay cached */
	if (!ip->i_dlm_ex_acquire_ns)
		return false;

	now = ktime_get_ns();
	held_ns = now - ip->i_dlm_ex_acquire_ns;
	mht_ns = (u64)eff_mht_ms * NSEC_PER_MSEC;
	if (held_ns >= mht_ns)
		return false;	/* held long enough — release normally */

	/*
	 * Defer.  Keep state CACHED so our own queued ops keep fast-pathing,
	 * but record that a BAST is pending so the dwork (and the unlock/evict
	 * paths) know to honor it.  If a previous BAST already armed the dwork,
	 * queue_delayed_work returns false and we drop the duplicate ref.
	 */
	if (!ip->i_dlm_bast_pending)
		ip->i_dlm_dwork_strikes = 0;	/* v0.10.31: fresh episode */
	ip->i_dlm_bast_pending = true;
	delay_j = nsecs_to_jiffies(mht_ns - held_ns) + 1;
	/* arm in GRACE SLICES, not the full window
	 * remainder.  With 31 waiters a fresh tenure's BAST lands within
	 * ~1ms, so this used to park the dwork for the whole 300ms window;
	 * later ilock_end sliding-grace arms hit "already armed" and were
	 * dropped, so an idle grant slept out the full floor (cc@32 rv
	 * rotation measured at held_ms=300-307/hop => 3-7.7s peer waits).
	 * The dwork's quiet-age gate now re-arms while the tenure is being
	 * consumed and releases at the first >=grace idle sample. */
	if (mxfs_dir_ex_batch_grace_ms > 0) {
		unsigned long slice_j =
			msecs_to_jiffies(mxfs_dir_ex_batch_grace_ms) + 1;
		if (delay_j > slice_j)
			delay_j = slice_j;
	}
	spin_unlock(&ip->i_dlm_lock);

	ip->i_dlm_bastq_src = 9;
	if (!mxfs_bast_arm_queue_delayed(ip, delay_j))
		xfs_irele(ip);	/* dwork already armed — release the extra ref */

	return true;
}

/*
 * dir_reuse@16 WEDGE fix PART 2 — dedup no-inode BASTs
 * per (mp,ino).  Under a 16-node hot-shared-dir storm the reclaimed-inode BAST
 * path (below) queues HUNDREDS of work items for the SAME inode; each retries an
 * on-disk unlock CAS on the SAME slot, so they SELF-COMPETE and the slot mutates
 * faster than any single unlock can read-modify-write it -> CAS livelock (the
 * unlock exhausts even the 5s caw_unlock_backoff deadline; PROVEN BY INSTRUMENT:
 * retry~156 on ino=131, unlock_exhausted climbing 285->755, load ~60).
 * Collapsing to ONE in-flight release per inode removes the self-competition, so
 * the single unlock faces only the (bounded) legit-acquirer contention and wins.
 * Dropping a duplicate BAST is safe: the peer keeps BASTing while our bit is
 * set, so a fresh work re-queues after the in-flight one clears its entry.
 * Gated (default 0) for A/B; the ship default should be 1.
 */
/*  ship default 1 (the comment above always said "ship
 * default should be 1").  PROVEN needed at 16 (dir_reuse CAS-livelock wedge) AND
 * 32 (coherency EIO).  Dropping a duplicate no-inode BAST is safe (peer re-BASTs
 * while our bit is set). */
int mxfs_noino_bast_dedup = 1;
module_param_named(noino_bast_dedup, mxfs_noino_bast_dedup, int, 0644);
MODULE_PARM_DESC(noino_bast_dedup,
	"collapse concurrent no-inode BASTs for the same inode to one in-flight release (default 1; avoids hot-inode unlock-CAS livelock)");

/*
 * BAST notification callback from DLM layer.
 * Called when another node needs a lock we're caching.
 *
 * data = struct xfs_mount *
 */
/*
 * (design-consult ruling item 1): the no-inode BAST path
 * must not treat a LOCALLY ACTIVE lifecycle state as "no inode".
 * xfs_iget(XFS_IGET_INCORE) returns -EAGAIN for INEW / IRECLAIM /
 * INACTIVATING / VFS teardown and -ENOENT for NEED_INACTIVE nlink==0; only
 * IRECLAIMABLE (also -EAGAIN) and a radix miss (-ENODATA) mean no local owner.
 * Today every one of those takes the whole-AIL noino fence and can release
 * the inode's on-disk grant while this node's own inactivation of that inode
 * is still committing (between the truncate's last EFD and xfs_inactive_ifree
 * at the latest).  With noino_lifecycle_requeue=1 a BAST that finds such a
 * state is RE-QUEUED (delayed work, 20 ms, bounded by
 * noino_lifecycle_max_ms) until the inode is LIVE (normal in-core BAST
 * handling), RECLAIMABLE or ABSENT (noino fence).  The grant stays held
 * meanwhile; the peer keeps waiting on its own bounded timeouts.  Probe
 * P-NOINO-LIFECYCLE names the class either way (knob 0 = measure only).
 */
/* A/B at 25 AGs: probe-only laps 1-2 = 0 INACTIVATING/NEED_INACTIVE, 5-8
 * IRECLAIM, 7091 RECLAIMABLE; requeue=1 lap 3 clean (1 INEW->LIVE in 20 ms).
 * Ship default 1 (design-consult ruling item 1). */
int mxfs_noino_lifecycle_requeue = 1;
module_param_named(noino_lifecycle_requeue, mxfs_noino_lifecycle_requeue, int, 0644);
MODULE_PARM_DESC(noino_lifecycle_requeue,
	"no-inode BAST on an INEW/IRECLAIM/INACTIVATING/NEED_INACTIVE inode: 0=fence as before (probe only), 1=requeue until the local lifecycle op completes (default 1)");

void
__mxfs_dlm_bast_notify(
	struct xfs_mount	*mp,
	uint64_t		ino,
	uint8_t			requested_mode,
	bool			allow_requeue)
{
	struct xfs_inode	*ip;
	int			error;
	uint32_t		noino_rel_gen;

	mxfs_idbg("mxfs: MX-INSTR bast_notify ENTRY ino=%llu req_mode=%u",
		(unsigned long long)ino, requested_mode);

	/*
	 * (D-0537): the SB summary key never has an in-core inode, so
	 * every BAST for it would fall into the no-inode orphan release below
	 * — including one that arrives while THIS node's put_super is inside
	 * the summary critical section (chain 116 v2 holderfail: the peer was
	 * granted epoch+1 in 255 ms under a parked 60 s hold).  A live holder
	 * is named by m_mxfs_sb_lock_held; refuse the release and the peer
	 * keeps waiting on its own bounded poll (see mxfs_sb_summary_bast_refuse).
	 */
	if (unlikely(ino == mxfs_sb_summary_key(mp))) {
		bool held = READ_ONCE(mp->m_mxfs_sb_lock_held);
		bool refuse = held && READ_ONCE(mxfs_sb_summary_bast_refuse);
		long long n = atomic64_inc_return(&mxfs_sb_summary_bast_seen);

		if (refuse)
			atomic64_inc(&mxfs_sb_summary_bast_refused);
		if (n <= 200)
			mxfs_probe("mxfs: P-SB-SUMMARY-BAST slot=%u req=%u held=%d epoch=%llu action=%s (n=%lld)\n",
				mp->m_mxfs_node_slot, requested_mode, held ? 1 : 0,
				(unsigned long long)mp->m_mxfs_sb_grant_epoch,
				refuse ? "REFUSED-live-holder" :
				held ? "RELEASE-under-live-holder(measure-only)" :
				"orphan-release",
				n);
		if (refuse)
			return;
	}

	/* tenure anchor for the no-inode release, captured
	 * BEFORE the in-core probe.  Any local re-acquire that lands after
	 * this line bumps the grant gen, so the async release below refuses
	 * (-ESTALE) instead of stripping the fresh grant's slot bit (the
	 * mkdir-storm double-EX root).  Capturing after the iget check would
	 * leave a window where a re-acquire between the check and the
	 * capture anchors the NEW tenure and defeats the guard. */
	noino_rel_gen = mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm, ino);

	/* Look up the inode in XFS's existing radix tree cache */
	error = xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip);
	if (error || !ip) {
		/*
		 * lifecycle classification (see the block comment at
		 * mxfs_noino_lifecycle_requeue): -ENODATA is a radix miss;
		 * anything else is an IN-CORE inode in a transient state.
		 */
		if (error && error != -ENODATA) {
			unsigned long lfl = 0, lst = 0;
			unsigned int lnl = 0;
			enum xfs_ino_lifecycle lc =
				xfs_icache_ino_lifecycle(mp, ino, &lfl, &lnl,
							 &lst);
			bool active = (lc == XFS_ILC_INEW ||
				       lc == XFS_ILC_IRECLAIM ||
				       lc == XFS_ILC_INACTIVATING ||
				       lc == XFS_ILC_NEED_INACTIVE ||
				       lc == XFS_ILC_VFS_TEARDOWN);
			static atomic_t p_lc_n = ATOMIC_INIT(0);

			if (lc < XFS_ILC_NR)
				atomic64_inc(&mxfs_noino_lifecycle_stat[lc]);
			/* D-0532 item (c): a RECLAIMABLE inode is in core and may
			 * still carry the grant this path is about to release. */
			if (lc == XFS_ILC_RECLAIMABLE) {
				static atomic_t p_norc_n = ATOMIC_INIT(0);

				atomic_inc(&mxfs_noino_bast_reclaimable);
				if (atomic_inc_return(&p_norc_n) <= 64)
					mxfs_probe("mxfs: P-NOINO-RECLAIMABLE ino=%llu err=%d req=%u nlink=%u — BAST for a reclaimable in-core inode; served by the no-inode release\n",
						(unsigned long long)ino, error,
						requested_mode, lnl);
			}
			if (active &&
			    (unsigned)atomic_inc_return(&p_lc_n) <= 96)
				mxfs_probe("mxfs: P-NOINO-LIFECYCLE ino=%llu err=%d class=%s iflags=0x%lx istate=0x%lx nlink=%u req=%u requeue=%d — BAST for an inode whose LOCAL lifecycle op is still running\n",
					(unsigned long long)ino, error,
					xfs_ino_lifecycle_name(lc), lfl, lst,
					lnl, requested_mode,
					(mxfs_noino_lifecycle_requeue &&
					 allow_requeue) ? 1 : 0);
			if (active && mxfs_noino_lifecycle_requeue &&
			    allow_requeue &&
			    mxfs_noino_lifecycle_park(mp, ino, requested_mode,
						      lc))
				return;
		}
		/*
		 * Inode not in cache — it was evicted but the DLM lock
		 * wasn't released (race). Release the orphan lock now.
		 */
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu NO_INODE error=%d — calling unlock",
			(unsigned long long)ino, error);
		mxfs_idbg("mxfs: P-H22-CALL site=BAST_NOTIFY_NO_INODE ino=%llu\n",
			(unsigned long long)ino);
		/* PROOF: a BAST for an inode that has been RECLAIMED from
		 * the in-core cache.  We release the on-disk DLM slot with NO
		 * durability drain — if this is a DIRECTORY whose dir DATA blocks
		 * are still dirty in the AIL (reclaim flushes only the inode
		 * cluster, not the dir-data xfs_buf's), the peer FUA-reads stale
		 * disk and clobbers our committed dirents (the durable dir-block
		 * lost-update).  Always-on so it surfaces at instr=0.  Cross-ref
		 * the ino against the shared test-dir inode to confirm. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited("mxfs: P-NOINO-BAST ino=%llu req_mode=%u\n",
				(unsigned long long)ino, requested_mode);
		atomic64_inc(&mxfs_dlm_stat_bast_no_inode);
		/*
		 * collapse concurrent no-inode BASTs
		 * for the SAME inode to ONE in-flight release (see
		 * mxfs_noino_bast_dedup).  A duplicate is dropped — the
		 * in-flight work handles the current slot state and the peer
		 * re-BASTs while our bit stays set, so no release is lost.  This
		 * removes the hot-inode unlock-CAS self-competition/livelock.
		 */
		if (mxfs_noino_bast_dedup &&
		    !mxfs_noino_inflight_try_add(mp, ino))
			return;
		/*
		 * FIX — durable dir-block lost-update (proven by instrument,
		 * Design-consult Gemini-designed).  The in-core inode is GONE
		 * (reclaimed) but its dir DATA blocks may still be dirty / in
		 * the AIL: reclaim flushes only the inode CLUSTER, and the
		 * dir-data xfs_buf's are tracked independently.  Releasing the
		 * DLM slot here WITHOUT flushing violates Architectural
		 * Invariant #1 — a peer FUA-reads the stale platter (missing
		 * our committed dirents), RMWs it, and DURABLY clobbers our
		 * entry.  Proven this exact run: DIR-STALE-SKIP in_ail=1
		 * disk_differs=1 on the shared rename_visibility dir
		 * (ino 14680193), with P-NOINO-BAST firing 11-15x/node on the
		 * SAME inode — the only release path that skips the dir-data
		 * drain.  We have no extent map (no inode), so flush by the
		 * inode's AG: a BOUNDED AG-AIL drain (writes + AIL-detaches the
		 * lingering dir blocks) + log force + platter destage BEFORE
		 * the unlock.  A small dir's data blocks live in the inode's
		 * AG.  Bounded (stall_iters=50) so a wedged item can't pin this
		 * CAW bast thread; on stall-abort we unlock anyway — no worse
		 * than the prior behavior, and the per-node journal slot still
		 * records the txn for replay.  A healthy AG drains in a few
		 * iters and returns immediately.
		 */
		/*
		 * offload the heavy release (log-force + AG
		 * drain + flush + publish_unpublished + on-disk unlock) to the
		 * inode bast wq so it does NOT block the per-peer TCP recv
		 * thread.  Under dir_reuse 8/tcp this recv-thread serialization
		 * of ~800 reused-inode releases/round was the ~60 s create-phase
		 * stall.  Correctness preserved: the work fn drains before the
		 * unlock (invariant #1).  On allocation failure, fall back to
		 * the inline path so the slot is never leaked.
		 */
		{
			struct mxfs_noino_bast_work *w =
				kmalloc(sizeof(*w), GFP_NOFS);

			if (w) {
				INIT_WORK(&w->work, mxfs_dlm_noino_bast_work_fn);
				w->mp = mp;
				w->ino = ino;
				w->rel_gen = noino_rel_gen;
				if (queue_work(mp->m_mxfs_inode_bast_wq,
					       &w->work))
					return;	/* work fn frees w + unlocks */
				kfree(w);	/* already queued? fall through */
			}

			/* the async work won't run (OOM/wq gone) — drop
			 * the dedup entry so the inline release below isn't
			 * gated out and a later BAST can re-queue. */
			if (mxfs_noino_bast_dedup)
				mxfs_noino_inflight_remove(mp, ino);

			/* Fallback: inline release (rare — OOM / wq gone).
			 * FIX-12: same whole-AIL LSN-targeted fence as
			 * the work fn (the single-AG push provably misses
			 * peer-AG dir data blocks); on failure never unlock
			 * undrained.  progress-based fence,
			 * same policy as the work fn. */
			{
				int landed_inl;

				/* FIX-16: land never-AIL'd committed dir
				 * blocks first (see work fn); the fence's flush
				 * covers the writes. */
				landed_inl = mxfs_dir_noino_land_scan(mp, ino, true);
				if (!mxfs_noino_drain_fence(mp, ino,
							    landed_inl) &&
				    !xfs_is_shutdown(mp)) {
					pr_warn("mxfs: P-NOINO-RELFENCE-WEDGE ino=%llu (inline) — shutdown\n",
						(unsigned long long)ino);
					xfs_force_shutdown(mp,
						SHUTDOWN_META_IO_ERROR);
					return;
				}
				if (mp->m_ddev_targp &&
				    mp->m_ddev_targp->bt_bdev)
					mxfs_blkdev_flush_epoch(mp);
			}
			mxfs_dlm_publish_unpublished(mp, ino, NULLAGNUMBER);
			/* same tenure guard as the work fn —
			 * the drain fence above sleeps, so a local re-acquire
			 * can win a new tenure mid-fence even on this inline
			 * path. */
			mxfs_v5_dlm_inode_unlock_gen(mp->m_mxfs_dlm, ino,
						     noino_rel_gen);
		}
		return;
	}

	spin_lock(&ip->i_dlm_lock);
	/* v0.5.4: a peer BAST = proven peer interest in this inode; from now
	 * on the create-time shortform-parent durability barrier must fire
	 * for it (see i_mxfs_self_created in xfs_inode.h). */
	ip->i_mxfs_self_created = false;
	mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu state=%u mode=%u ex_h=%u pr_h=%u",
		(unsigned long long)ino, ip->i_dlm_state, ip->i_dlm_mode,
		ip->i_dlm_ex_holders, ip->i_dlm_pr_holders);
	/* sess-tcp (instrumented): always-on (ratelimited) branch-input capture for
	 * DIR-inode BASTs — the contended dir-EX handoff is the posix_multi /
	 * cache_coherency 2-node stall site.  Names the state/mode/holders so a
	 * dead-deferred BAST (peer waits 60s) is visible without instr=1. */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		/* STICKY — this dir has now been contended by a peer.  Arms
		 * mxfs_dir_ail_push_defer for the rest of this incarnation so the
		 * create-phase cold window (dir_gen still 0) still defers background
		 * dir-block destages to the release-drain. */
		ip->i_dlm_dir_contended = true;
		/*  (design review design): record whether the BAST'ing
		 * peer wants EX (a MODIFIER).  Only an EX peer can change the
		 * dir's blocks, so only an EX request makes our cached image
		 * stale.  A PR (reader) BAST, an MHT self-demote, or a noino
		 * collateral drain must NOT force us to cold-reread on the next
		 * acquire (the 32-node dlm_scaling read storm).  Consumed at the
		 * release-invalidate site under mxfs_dir_release_skip_nonex. */
		if (requested_mode == MXFS_LOCK_EX)
			ip->i_dlm_dir_want_ex = true;
		mxfs_probe_ratelimited(
			"mxfs: P-DIRBAST ino=%llu state=%u mode=%u ex=%u pr=%u pin=%u realns=%llu\n",
			(unsigned long long)ino, ip->i_dlm_state, ip->i_dlm_mode,
			ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
			ip->i_dlm_pin_count,
			(unsigned long long)ktime_get_real_ns());
	}

	/* instrumented (run45 120s wedge): capped, unratelimited
	 * arrival record for hot-inode BASTs — pairs with the master's
	 * P7S-BAST-FIRE.  A P7S with no P7B = lost message; P7B with no
	 * release = the branch below swallowed it. */
	{
	extern unsigned long long mxfs_dbg_probe_ino;
	/* dbg_probe_ino: a harness names the inode it measures, whatever its
	 * number (the low-inode scope is fresh-filesystem only). */
	if (ino <= 256 || ino == READ_ONCE(mxfs_dbg_probe_ino)) {
		static atomic_t p7b_n = ATOMIC_INIT(0);
		if ((unsigned)atomic_inc_return(&p7b_n) <= 60000)
			mxfs_probe("mxfs: P7B-BASTNOTIFY ino=%llu state=%u mode=%u ex=%u pr=%u pin=%u\n",
				(unsigned long long)ino, ip->i_dlm_state,
				ip->i_dlm_mode, ip->i_dlm_ex_holders,
				ip->i_dlm_pr_holders, ip->i_dlm_pin_count);
	}
	}

	/* Already processing a BAST — redundant, ignore */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING) {
		/* P72: run68 — this swallow has NO liveness
		 * check.  When DEMOTING is stale (the instance long exited /
		 * clobbered), EVERY master re-BAST lands here and the peer
		 * convoy starves forever.  Print when the swallow happens
		 * with NO bast work pending/running — the lost-BAST shape. */
		int p72_busy = work_busy(&ip->i_dlm_bast_work);

		/*
		 *  work_busy(&ip->i_dlm_bast_work) is
		 * blind to a release driven via mxfs_inode_dlm_defer_bast
		 * (Approach A, deferred to xfs_trans_free ->
		 * mxfs_trans_drain_inode_unlocks) or via mxfs_dlm_bast_dwork_fn
		 * (MHT timer) — NEITHER touches i_dlm_bast_work, so p72_busy
		 * reads false while a demoter is genuinely, actively draining
		 * this inode via one of those paths.  If mode!=NL (drain not
		 * yet reached the point of setting NL), the CAW-orphan shape
		 * check below also does not apply (requires mode==NL), so this
		 * falls straight to P72-STALE-REQUEUE and re-queues a SECOND,
		 * concurrent mxfs_dlm_bast_process on the same ip — a double-
		 * demote race.  Hypothesis for BUG3 (cc87 rare
		 * VFS_BUG_ON_INODE crash via plain rm/iput, no static bug found
		 * in bast_notify/bast_process/bast_dwork_fn's OWN irele pairing
		 * — this checks a DIFFERENT mechanism, a live demoter this
		 * function is about to ignore).  Diagnostic only, no behavior
		 * change — instrument step 2.
		 */
		if (!p72_busy && ip->i_dlm_demoter != NULL) {
			static atomic_t p126_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p126_n) <= 3000)
				mxfs_probe("mxfs: P126-DEMOTE-RACE ino=%llu mode=%u state=%u ex=%u pr=%u pin=%u bast_pending=%d work_busy=0 demoter_set=1 comm=%s dem_pid=%d dem_comm=%s dem_line=%u:%u dem_age_ms=%llu — live demoter with idle i_dlm_bast_work\n",
					(unsigned long long)ino, ip->i_dlm_mode,
					ip->i_dlm_state, ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders, ip->i_dlm_pin_count,
					ip->i_dlm_bast_pending, current->comm,
					ip->i_dlm_demoter_pid,
					ip->i_dlm_demoter_comm,
					MXFS_SITE_ARGS(ip->i_dlm_demoter_line),
					(unsigned long long)((ktime_get_ns() -
						ip->i_dlm_demoter_set_ns) /
						NSEC_PER_MSEC));
		}

		spin_unlock(&ip->i_dlm_lock);
		if (!p72_busy) {
			static atomic_t p72_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p72_n) <= 3000)
				pr_warn("mxfs: P72-SWALLOW-DEAD ino=%llu state=DEMOTING work_busy=0 mode=%u ex=%u pr=%u pin=%u — BAST swallowed with no live demote instance\n",
					(unsigned long long)ino,
					ip->i_dlm_mode, ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders,
					ip->i_dlm_pin_count);
		}
		if (!p72_busy)
			mxfs_caw_orphan_forensic(ip, 0);
		if (!p72_busy && mxfs_caw_orphan_reclaim && mp->m_mxfs_dlm &&
		    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
			/*
			 *  a864 ROOT RECOVERY (instrumented, PROVEN by
			 * P-ORPH-FORENSIC held_raw=5 scan_mine=1 nslots=1
			 * state=DEMOTING): a release deferred to xfs_trans_free /
			 * run inline left this node stuck in DEMOTING with its
			 * on-disk holder bit STILL set — bast_process's seq-gated
			 * unlock ignored its return and never cleared it — so every
			 * peer BAST is swallowed and the cluster wedges.  The
			 * v0.10.45 re-queue below just re-runs that same failing
			 * release forever.  work_busy==0 => no live worker will
			 * finish it.  CLAIM the release via i_dlm_demoter (NULL ==
			 * no live inline drain in progress), which keeps state at
			 * DEMOTING — blocking this node's acquire fast path
			 * (ilock_begin waits on DEMOTING) across the scan+clear so
			 * no legitimate local re-grant can race; cross-node only
			 * THIS node ever sets our bit.  Then force-clear the bit
			 * unconditionally (bypassing the seq-gated hinted unlock
			 * that keeps leaving it) and finish the release.  Idle
			 * holder shape only (no active holders/pin); on any other
			 * shape the owning op's ilock_end fires the release. */
			bool claimed = false, shape_held = false;
			/*
			 * (design-consult ruling item 7): the quiescence
			 * this site establishes, stated in the DLM's terms so
			 * the scan-based self-release can refuse a call that
			 * has not established it.  Filled from the values read
			 * under i_dlm_lock below — never from literals, because
			 * the struct only means anything if it re-states facts
			 * the caller actually checked.
			 *
			 * Why each field holds here:
			 *   no_local_grant     — i_dlm_mode == NL: this mount
			 *       believes it holds nothing on this inode.
			 *   no_dependent_users — the holder and pin counts are
			 *       zero, so no admitted user is mid-operation.
			 *   new_users_blocked  — state == DEMOTING and the
			 *       demoter claim taken below KEEPS it DEMOTING;
			 *       ilock_begin waits on DEMOTING, so this node's
			 *       acquire fast path is held off for the whole
			 *       scan+clear.  Cross-node, only THIS node ever
			 *       sets our bit.
			 *   writeback_drained  — implied by DEMOTING+NL, and it
			 *       is the reason mode==NL is load-bearing here: a
			 *       release sets NL only AFTER its Phase-2
			 *       durability drain (bast_process drains, then
			 *       sets NL, then unlocks).  A stuck-DEMOTING
			 *       orphan at NL has already destaged this tenure,
			 *       so clearing the bit cannot expose a peer to
			 *       un-drained state.  A DEMOTING+EX stuck holder
			 *       may NOT have drained and is excluded by the
			 *       mode==NL test.
			 */
			struct mxfs_forcerel_attest frel_att = {
				.basis = MXFS_FORCEREL_BASIS_QUIESCED,
				.site  = "p72-orphan-reclaim",
			};

			spin_lock(&ip->i_dlm_lock);
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING &&
			    ip->i_dlm_mode == MXFS_LOCK_NL &&
			    ip->i_dlm_ex_holders == 0 &&
			    ip->i_dlm_pr_holders == 0 &&
			    ip->i_dlm_pin_count == 0) {
				frel_att.no_local_grant =
					(ip->i_dlm_mode == MXFS_LOCK_NL);
				frel_att.no_dependent_users =
					(ip->i_dlm_ex_holders == 0 &&
					 ip->i_dlm_pr_holders == 0 &&
					 ip->i_dlm_pin_count == 0);
				frel_att.new_users_blocked =
					(ip->i_dlm_state ==
					 MXFS_DLM_ISTATE_DEMOTING);
				frel_att.writeback_drained =
					(ip->i_dlm_state ==
					 MXFS_DLM_ISTATE_DEMOTING &&
					 ip->i_dlm_mode == MXFS_LOCK_NL);
				/*
				 * Orphan shape.  mode==NL is load-bearing: a release
				 * only sets NL AFTER its Phase-2 durability drain
				 * (bast_process drains, then sets i_dlm_mode=NL, then
				 * unlocks), so a stuck-DEMOTING orphan at NL has ALREADY
				 * destaged this tenure's dir blocks — clearing the bit
				 * cannot expose a peer to un-drained state.  A
				 * DEMOTING+mode==EX stuck holder may not have drained
				 * yet, so it falls through to the re-queue below.
				 *
				 * i_dlm_demoter set == a bast_process is/was releasing
				 * this inode.  A LIVE inline drain clears demoter within
				 * 1-2 peer BASTs; a STUCK one (blocked past mode==NL, so
				 * demoter=NULL never runs; work_busy==0 because it is
				 * inline, not on the workqueue) never does and wedges the
				 * cluster.  Claim immediately when there is no demoter;
				 * otherwise wait out MXFS_P72_ORPHAN_STRIKES sustained
				 * swallows (< ~1s) to PROVE it is wedged before
				 * overriding the stuck demoter and force-clearing.
				 */
				shape_held = true;
				/* GATE v2 — the v1
				 * regression was the strikes OVERRIDE of a
				 * LIVE demoter: trans-deferred releases mark
				 * i_dlm_demoter and can legitimately outlive
				 * 16 swallows under log-grant pressure, and
				 * v1 force-cleared under them (transient-
				 * window livelock).  v2: NEVER override a
				 * demoter; also require the MHT dwork idle
				 * (the other work_busy-blind release path);
				 * and even the demoter==NULL shape must
				 * persist MXFS_P72_ORPHAN_STRIKES swallows
				 * (~0.5s) — every legitimate release path is
				 * then provably absent (inline+trans-defer =
				 * demoter, queued/running work = p72_busy,
				 * MHT timer = dwork), which is exactly the
				 * measured phantom (P72-SWALLOW-DEAD ×27 on
				 * dir 6291585, 330s wedge, all-8-node
				 * convoy). */
				if (!work_busy(&ip->i_dlm_bast_dwork.work) &&
				    ++ip->i_dlm_p72_strikes >=
					    MXFS_P72_ORPHAN_STRIKES &&
				    (ip->i_dlm_demoter == NULL ||
				     ktime_get_ns() -
					     ip->i_dlm_demoter_set_ns >
						     10ULL * NSEC_PER_SEC)) {
					/* GATE v3: a demoter CAN leak
					 * (measured: set-but-returned task,
					 * idle shape, 25-min 8-node convoy).
					 * Every legitimate demote with this
					 * shape (mode=NL, no holders/pins, no
					 * queued work, no dwork) finishes in
					 * ms; 10s + 16 swallows proves the
					 * leak.  Name the leaker loudly — the
					 * print IS the root-cause lead. */
					if (ip->i_dlm_demoter != NULL) {
						static atomic_t p72ov_n =
							ATOMIC_INIT(0);

						if (atomic_inc_return(&p72ov_n) <= 200)
							pr_warn("mxfs: P72-DEMOTER-OVERRIDE ino=%llu dem_pid=%d dem_comm=%s dem_line=%u:%u dem_age_ms=%llu — leaked demoter overridden; reclaiming orphan\n",
								(unsigned long long)ino,
								ip->i_dlm_demoter_pid,
								ip->i_dlm_demoter_comm,
								MXFS_SITE_ARGS(ip->i_dlm_demoter_line),
								(unsigned long long)((ktime_get_ns() -
									ip->i_dlm_demoter_set_ns) /
									NSEC_PER_MSEC));
					}
					ip->i_dlm_p72_strikes = 0;
					MXFS_SET_DEMOTER(ip);	/* claim; keeps DEMOTING */
					claimed = true;
					/* the force-release below
					 * publishes on the wire BEFORE the
					 * NL store — announce release-begin
					 * here, still under i_dlm_lock, so
					 * the certificate stops proving
					 * ahead of the publication. */
					mxfs_inode_authority_begin_release_locked(
						ip, MXFS_SITE);
				}
			} else {
				ip->i_dlm_p72_strikes = 0;	/* shape gone — reset */
			}
			spin_unlock(&ip->i_dlm_lock);

			if (claimed) {
				int mine = 0, nslots = 0, cleared = 0;
				uint64_t hex_or = 0;

				/* ICLUSTER-routed files have no per-inode
				 * slot: the scan/force-release would walk
				 * device sectors for nothing.  The NL-reset
				 * below is enough — the cluster release
				 * converges via the next release_check
				 * sweep or peer re-BAST. */
				if (!ip->i_dlm_routed_iclus) {
					mine = mxfs_v5_dlm_inode_self_held_scan(
						mp->m_mxfs_dlm, ino, &nslots,
						&hex_or);
					if (mine == 1) {
						mxfs_inode_authority_check_published(
							ip, MXFS_SITE);
						cleared =
						  mxfs_v5_dlm_inode_force_release_self(
							mp->m_mxfs_dlm, ino,
							&frel_att);
					}
				}
				{
					static atomic_t p72f_n = ATOMIC_INIT(0);
					if (atomic_inc_return(&p72f_n) <= 3000)
						pr_warn("mxfs: P72-ORPHAN-FORCEREL ino=%llu mine=%d nslots=%d hex_or=%llx cleared=%d — stuck-DEMOTING orphan finished\n",
							(unsigned long long)ino,
							mine, nslots,
							(unsigned long long)hex_or,
							cleared);
				}
				spin_lock(&ip->i_dlm_lock);
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_mode = MXFS_LOCK_NL;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				ip->i_dlm_ex_holders = 0; MXFS_DLMTR_H(ip);
				ip->i_dlm_pr_holders = 0; MXFS_DLMTR_H(ip);
				MXFS_CLEAR_DEMOTER(ip);
				ip->i_dlm_stale = true; ip->i_dlm_stale_src = 20;
				xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
				spin_unlock(&ip->i_dlm_lock);
				wake_up_all(&ip->i_dlm_wait);
				/* Orphan finished — swallow this BAST. */
				xfs_irele(ip);
				return;
			}
			if (shape_held) {
				/*
				 * Orphan shape, but a demoter is set and we have not
				 * yet reached the strike threshold that proves it is a
				 * stuck (not a transient live) drain — swallow this BAST;
				 * a subsequent one crosses the threshold and reclaims.
				 * Re-queuing here would just spawn a competing worker
				 * against the (possibly still-live) drain.
				 */
				static atomic_t p72w_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p72w_n) <= 2000)
					pr_warn_ratelimited("mxfs: P72-ORPHAN-WAIT ino=%llu strikes=%u/%d demoter_set=1 — awaiting stuck-drain proof\n",
						(unsigned long long)ino,
						ip->i_dlm_p72_strikes,
						MXFS_P72_ORPHAN_STRIKES);
				xfs_irele(ip);
				return;
			}
			/* Not the orphan shape (mode==EX not-yet-drained, or active
			 * holders) — fall through to the re-queue below, which drains
			 * a mode==EX holder and transitions it toward a NL orphan. */
		}
		if (!p72_busy) {
			/* v0.10.45 STALE-DEMOTING RECOVERY: DEMOTING with the demote
			 * work neither running nor queued is a lost-work race that
			 * left this node stuck holding the on-disk bit, swallowing
			 * every peer BAST and wedging the cluster (dir_reuse@32 r4:
			 * test28 held EX, 3000 swallowed BASTs, 30 nodes rc=-110).
			 * RE-QUEUE the demote to finish the release instead of
			 * swallowing.  work_busy==0 means the work is idle so
			 * queue_work succeeds; if it races false, drop our iget ref.
			 * bast_process is re-entrant-safe and drains before unlock. */
			static atomic_t p72r_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p72r_n) <= 3000)
				mxfs_probe("mxfs: P72-STALE-REQUEUE ino=%llu mode=%u ex=%u pr=%u\n",
					(unsigned long long)ino, ip->i_dlm_mode,
					ip->i_dlm_ex_holders, ip->i_dlm_pr_holders);
			ip->i_dlm_bastq_src = 14;
			if (!mxfs_bast_arm_queue(ip))
				xfs_irele(ip);
			return;
		}
		xfs_irele(ip);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=DEMOTING_already", (unsigned long long)ino);
		return;
	}

	/*
	 * NEWARCH Phase 1.3 (design review chokepoint): slow-path caw_lock is in
	 * flight on this node.  We MUST NOT queue bast_process here —
	 * doing so would strip our on-disk holder bit out from under
	 * caw_lock's polling loop, causing it to spin then time out.
	 *
	 * Instead, record the BAST via i_dlm_stale.  The slow-path's
	 * post-acquire publish (xfs_mxfs_dlm.c) checks i_dlm_stale; if
	 * set, it transitions ACQUIRING → BAST and queues bast_process
	 * itself, so the BAST is honored AFTER the in-flight caw_lock
	 * completes.  Same deferred-honor pattern as the pinned-AGF and
	 * active-holder branches below.
	 */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_ACQUIRING) {
		atomic64_inc(&mxfs_dlm_stat_bast_deferred);
		/*
		 * ccloop-4dd7 (b54r1 dir 131, PROVEN BY INSTRUMENT shape): a
		 * LIVE slow-path acquirer always holds i_dlm_acq_inflight >= 1
		 * — the counter is bumped before ACQUIRING is set and dropped
		 * at every slow-path exit, all under i_dlm_lock.  So
		 * ACQUIRING with inflight==0 is a LEAKED state: the setter
		 * exited without transitioning, no acquire completion will
		 * ever honor the defer below, and every peer BAST lands here
		 * forever (observed: 184 one-per-second P-DIRBASTs, peer
		 * rmdir -110 with a dirty tx -> cluster shutdown).  The
		 * inflight==0 test alone is already conclusive under
		 * i_dlm_lock; the strike threshold only adds margin against
		 * unknown exit orderings.  Reclaim exactly like
		 * P-DEMWAIT-REDRIVE: name the leaker, transition to DEMOTING,
		 * queue the serialized release pipeline (drains invariant #1,
		 * then hands the grant to the peer).
		 */
		if (ip->i_dlm_acq_inflight == 0 &&
		    ++ip->i_dlm_acq_strikes >= 8) {
			u64 acq_age_ms = ip->i_dlm_acq_set_ns ?
				(ktime_get_ns() - ip->i_dlm_acq_set_ns) /
					NSEC_PER_MSEC : 0;

			pr_warn("mxfs: P-ACQ-ORPHAN-RECLAIM ino=%llu mode=%u ex=%u pr=%u pin=%u strikes=%u setter_pid=%d setter_comm=%s set_age_ms=%llu — leaked ACQUIRING (no acquire in flight); honoring BAST via release pipeline\n",
				(unsigned long long)ino, ip->i_dlm_mode,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count, ip->i_dlm_acq_strikes,
				ip->i_dlm_acq_pid, ip->i_dlm_acq_comm,
				(unsigned long long)acq_age_ms);
			ip->i_dlm_acq_strikes = 0;
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			spin_unlock(&ip->i_dlm_lock);
			if (igrab(VFS_I(ip))) {
				ip->i_dlm_bastq_src = 4;
				if (!mxfs_bast_arm_queue(ip))
					xfs_irele(ip);	/* raced pending — drop ref */
			} else {
				pr_warn_ratelimited(
				    "mxfs: P-ACQ-ORPHAN-FREEING ino=%llu i_state=0x%lx (inode evicting; teardown will release)\n",
					(unsigned long long)ino,
					mxfs_istate(VFS_I(ip)));
			}
			xfs_irele(ip);
			return;
		}
		if (ip->i_dlm_acq_inflight > 0)
			ip->i_dlm_acq_strikes = 0;
		ip->i_dlm_stale = true; ip->i_dlm_stale_src = 6;
		/* ROOT FIX of the dir_reuse 2/tcp ~6s handoff:
		 * record the deferred BAST in a DEDICATED flag.  i_dlm_stale alone
		 * is INSUFFICIENT — the slow-path post-acquire reload_inode clears
		 * i_dlm_stale before the post-publish reads it, so the revoke was
		 * silently swallowed and the peer stalled 6000ms (PROVEN: 9
		 * ACQUIRING-EX BASTs lost/run, holder honored only the retry's
		 * BAST 6s later in ~14us).  This flag survives the reload and is
		 * honored at post-publish. */
		ip->i_dlm_bast_during_acq = true;
		spin_unlock(&ip->i_dlm_lock);
		xfs_irele(ip);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=ACQUIRING — defer via i_dlm_bast_during_acq",
			(unsigned long long)ino);
		return;
	}

	/*
	 * state==NONE normally means no lock cached.  But a race between
	 * mxfs_dlm_bast_process (self-BAST work thread setting mode=NL,
	 * state=NONE) and mxfs_dlm_ilock_begin (setting mode=EX,
	 * state=CACHED) can leave state=NONE while the DLM lock is
	 * actually held on disk.  If mode != NL, another thread just
	 * acquired the lock — defer this BAST instead of releasing
	 * without flush, which would let the other node read stale data.
	 */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE) {
		if (ip->i_dlm_mode != MXFS_LOCK_NL) {
			/*
			 * sess-tcp ROOT FIX (instrumented, PROVEN): an IDLE cached
			 * holder (state lost to NONE but mode still EX/PR held,
			 * NO active holders, not pinned) used to just set BAST
			 * and return — but with no holders and no further ops
			 * NOTHING ever fires the deferred BAST, so the peer's
			 * lock request waits the full 60s
			 * MXFS_LOCK_WAIT_TIMEOUT_MS and only its post-timeout
			 * retry succeeds (PROVEN: posix_multi / cache_coherency
			 * 2-node TCP — holder fully idle after its burst, peer
			 * create#1 stuck in pending_wait 62s on the dir-EX).  A
			 * concurrent acquire would be ACQUIRING (handled above),
			 * so NONE+held+idle is a quiescent cached grant: release
			 * NOW via the serialized DEMOTING + bast_process pipeline
			 * (drains per invariant #1), exactly like the P135
			 * NL-orphan path and the holders==0 "immediate" branch
			 * below.  Only DEFER (set BAST) when a holder is active
			 * or the inode is pinned — there ilock_end / unpin fires
			 * it.
			 */
			/* daf50d34 ROOT FIX (mkdir_storm r5 PROVEN): this
			 * "idle" sample can be the GRANT-COMPLETION WINDOW — a
			 * slow-path acquire published mode=EX (v0.3.15 early
			 * publish) but has not yet registered its holder, and
			 * state ACQUIRING was trampled to NONE by a stale
			 * pipeline exit.  Releasing here strips a 0ms-old
			 * tenure the acquiring op never used; the op then
			 * RMWs on a phantom cached EX and its late destage
			 * clobbers the successor tenure (durable dirent loss).
			 * i_dlm_acq_inflight is the untramplable in-flight
			 * signal: defer via i_dlm_bast_during_acq, which the
			 * acquire completion honors (P35-ACQBAST-HONOR). */
			if (ip->i_dlm_acq_inflight > 0) {
				ip->i_dlm_bast_during_acq = true;
				spin_unlock(&ip->i_dlm_lock);
				mxfs_probe_ratelimited(
				    "mxfs: P-ACQWIN-DEFER ino=%llu mode=%u acq_inflight=%u (idle-release suppressed; slow-path acquire in flight)\n",
					(unsigned long long)ino, ip->i_dlm_mode,
					ip->i_dlm_acq_inflight);
				xfs_irele(ip);
				return;
			}
			if (ip->i_dlm_ex_holders == 0 &&
			    ip->i_dlm_pr_holders == 0 &&
			    ip->i_dlm_pin_count == 0) {
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				spin_unlock(&ip->i_dlm_lock);
				mxfs_probe_ratelimited(
				    "mxfs: P-NONE-HELD-IDLE-RELEASE ino=%llu mode=%u (cached idle holder, releasing now)\n",
					(unsigned long long)ino, ip->i_dlm_mode);
				ip->i_dlm_bastq_src = 3;
				if (!mxfs_bast_arm_queue(ip)) {
					mxfs_probe("mxfs: P76-QW-FALSE ino=%llu site=none-held-idle — work already pending; DEMOTING set on top; extra ref dropped (P226)\n",
						(unsigned long long)ino);
					/* see site=immediate — the
					 * pending instance owns one ref;
					 * ours is extra (leak root). */
					xfs_irele(ip);
				}
				return;	/* queued: work fn owns the ref */
			}
			/* holder active / pinned — ilock_end or unpin fires it */
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			spin_unlock(&ip->i_dlm_lock);
			xfs_irele(ip);
			mxfs_probe_ratelimited(
			    "mxfs: P-NONE-HELD-DEFER ino=%llu mode=%u ex=%u pr=%u pin=%u\n",
				(unsigned long long)ino, ip->i_dlm_mode,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count);
			return;
		}
		/*
		 * P108 ROOT FIX.  This branch used
		 * to call mxfs_v5_dlm_inode_unlock INLINE — with NO in-core
		 * serialization (state stayed NONE) and NO drain pipeline.
		 * P135 instrumentation proved the inline unlock's CAS-retry
		 * loop racing this node's own concurrent slow-path acquire:
		 * the cleanup entered at t=88.3794, the acquire's EX grant
		 * landed at t=88.3806 (P106-EXGRANT, in-core CACHED/EX), and
		 * the cleanup's retry re-read the slot and stripped the
		 * fresh bit at t=88.3814 (P135-SLOTWR hex=1->0) -> P108
		 * "on-disk slot lost" 0.7ms later -> forced slow-path reload
		 * that discards the dir's logged-but-not-yet-durable growth
		 * (its dinode iflush is then refused by the P119 non-EX
		 * authority guard) -> dabuf-map HOLE / EFSCORRUPTED shutdown
		 * and the zero_silent_loss dir tears.
		 *
		 * Fix: never unlock inline here.  First verify an orphaned
		 * on-disk bit actually exists (one slot read; in the common
		 * stale-BAST case — 2441/run measured — there is nothing to
		 * release and we now do NOTHING).  If a genuine orphan
		 * exists, route the release through the serialized
		 * DEMOTING + bast_process pipeline exactly like the
		 * "immediate" branch below: DEMOTING blocks ilock_begin's
		 * slow path (and bast_notify re-entry), and any acquire
		 * already in flight would have published ACQUIRING (handled
		 * above), so the strip race cannot recur.  bast_process also
		 * restores Architectural Invariant #1 (drain before unlock)
		 * for this path.
		 */
		{
			int p135_held;

			spin_unlock(&ip->i_dlm_lock);
			p135_held = mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm,
							   ino);
			/* FIX-H queue-time gate: on TCP,
			 * inode_held reads the LOCAL MIRROR — a held bit with
			 * a live grant_gen while in-core is NONE/NL is the
			 * GRANT-COMPLETION WINDOW (receive kworker linked the
			 * grant; the blocked acquirer has not resumed), NOT an
			 * orphan.  Queuing the serialized release here is what
			 * wire-released t6's just-granted gen=9252 tenure in
			 * the r10 capture (double-EX, one-dirent swallow).
			 * Park the BAST for the materializing tenure instead:
			 * bast_pending + MHT dwork (the protocol then
			 * serves the peer at the tenure's first quiescent
			 * sample).  CAW: grant_gen is always 0 -> the orphan
			 * release below keeps its disk-slot semantics. */
			spin_lock(&ip->i_dlm_lock);
			/* (design-consult): the gg-based
			 * park is TCP-ONLY.  The comment below assumed "CAW:
			 * grant_gen is always 0" — FALSE: CAW's grant_seq
			 * populates the same collision-lossy bucket and can
			 * FREEZE at a leftover value (captured: gg=1533, 1500
			 * park loops on test29 suppressed the orphan release
			 * for 350s and wedged 32 nodes).  CAW's reliable
			 * mid-completion signal is i_dlm_acq_inflight — the
			 * very next arm. */
			/* FIX — TCP abandoned-grant leak:
			 * the gg!=0 park had NO age/liveness bound, so a mirror
			 * grant whose requester was GONE (retry dup-grant /
			 * timed-out acquirer) parked the orphan release FOREVER.
			 * PROVEN BY INSTRUMENT at 32/tcp drc r5: test12 mirror gg=2048
			 * unconsumed (no P74-GRANT for it), in-core NONE/NL,
			 * P15-REL-ABORT(orph=1)→P135 park loop ×397 for 124s;
			 * master P-LKTIMEOUT-HOLDER held_ms=123498 starved 8 PR
			 * waiters (the cluster-wide 125s verify).  Same class
			 * the CAW fix cured (frozen gg=1533, 350s).  The
			 * REAL mid-completion signal on BOTH transports is
			 * i_dlm_acq_inflight>0 (bumped before the request is
			 * sent, dropped only at slow-path exit) — the ACQWIN
			 * arm below parks that case.  acq_inflight==0 with a
			 * held mirror grant = abandoned → fall through to the
			 * serialized orphan release (drain + wire unlock). */
			/* daf50d34 on CAW the claim-won-but-mode-unpublished
			 * microgap looks EXACTLY like an NL orphan (disk bit set,
			 * in-core NONE/NL) — the same grant-completion window the
			 * TCP GRANTWIN-PARK above handles via grant_gen (always 0
			 * on CAW).  A serialized orphan release here strips the
			 * fresh claim.  acq_inflight>0 = a slow-path acquire is
			 * mid-flight: park to the dwork like GRANTWIN-PARK. */
			if (p135_held == 1 &&
			    ip->i_dlm_acq_inflight > 0 &&
			    ip->i_dlm_state == MXFS_DLM_ISTATE_NONE &&
			    ip->i_dlm_mode == MXFS_LOCK_NL) {
				if (!ip->i_dlm_bast_pending)
					ip->i_dlm_dwork_strikes = 0;
				ip->i_dlm_bast_pending = true;
				ip->i_dlm_bast_during_acq = true;
				ip->i_dlm_bastq_src = 13;
				spin_unlock(&ip->i_dlm_lock);
				pr_warn_ratelimited(
				    "mxfs: P-ACQWIN-PARK ino=%llu acq_inflight (claim mid-completion; orphan release suppressed, BAST parked)\n",
					(unsigned long long)ino);
				if (!mxfs_bast_arm_queue_delayed(ip, msecs_to_jiffies(4) + 1))
					xfs_irele(ip);	/* dwork already armed */
				return;	/* dwork owns the iget ref */
			}
			if (p135_held == 1 &&
			    /* on CAW a frozen leftover gg must not
			     * veto the orphan release (acq_inflight above
			     * already screened the real mid-completion
			     * window).  TCP's gg==0 gate dropped for
			     * the same reason — acq_inflight==0 (checked by
			     * falling past the ACQWIN arm) IS the abandoned
			     * signal; a leftover gg parked releases 124s+. */
			    ip->i_dlm_acq_inflight == 0 &&
			    ip->i_dlm_state == MXFS_DLM_ISTATE_NONE &&
			    ip->i_dlm_mode == MXFS_LOCK_NL &&
			    ip->i_dlm_ex_holders == 0 &&
			    ip->i_dlm_pr_holders == 0 &&
			    ip->i_dlm_pin_count == 0) {
				{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
				ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
				mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
				spin_unlock(&ip->i_dlm_lock);
				pr_warn_ratelimited(
				    "mxfs: P135-ORPHAN-RELEASE ino=%llu (NONE/NL with on-disk bit; serialized release)\n",
				    (unsigned long long)ino);
				ip->i_dlm_bastq_src = 4;
				if (!mxfs_bast_arm_queue(ip)) {
					pr_warn("mxfs: P76-QW-FALSE ino=%llu site=orphan-release — work already pending; DEMOTING set on top; extra ref dropped (P226)\n",
						(unsigned long long)ino);
					/* see site=immediate. */
					xfs_irele(ip);
				}
				return;	/* queued: work fn owns the ref */
			}
			/*
			 * FIX-20 (PROVEN BY INSTRUMENT, run91/94): the
			 * p135_held==0 swallow was mirror-blind — a PHANTOM
			 * grant (master GRANTED us, local mirror empty: the
			 * requester's ACQUIRE_WAIT retry raced the late grant
			 * and discarded it) draws a BAST STORM from the
			 * starved waiters' ~1/s retries, and every BAST landed
			 * here and was swallowed; the master held our EX
			 * 499s (run91) until the whole cluster timed out.
			 * The BAST itself is master-side evidence we hold
			 * SOMETHING.  One stale BAST is common (2441/run) and
			 * stays cheap; a REPEAT within 15s escalates to the
			 * serialized bast_process release, whose final unlock
			 * (mirror empty) now sends the unconditional
			 * LOCK_RELEASE to the master (dlm.c FIX-20 arm),
			 * clearing the phantom and promoting the queue.
			 * Invariant 1 holds: bast_process drains this inode's
			 * blocks before the unlock, covering the eaten-mirror
			 * flavor where we DID modify under a real tenure.
			 */
			if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE &&
			    ip->i_dlm_mode == MXFS_LOCK_NL) {
				if (ip->i_dlm_phantom_bast_j &&
				    time_before(jiffies,
						ip->i_dlm_phantom_bast_j +
						15 * HZ)) {
					ip->i_dlm_phantom_bast_n++;
				} else {
					ip->i_dlm_phantom_bast_n = 1;
				}
				ip->i_dlm_phantom_bast_j = jiffies;
				/* v0.6.0: FIX-20 escalation is TCP-ONLY.  It cures a
				 * TCP master-mirror phantom (master GRANTED us, local
				 * mirror empty) that a targeted BAST evidences.  On CAW
				 * the BAST "hint" is a MULTICAST every waiter re-sends
				 * ~100ms while blocked, received by every NON-holder
				 * too — and p135_held==0 above already read the DISK
				 * slot (the CAW ground truth): our bit is NOT set, so
				 * there is nothing to reconcile.  Escalating here made
				 * every bystander of a hot-dir handoff run a serialized
				 * release pipeline ~9/s, each CASing the very slot the
				 * real contenders are negotiating (4/caw dir_reuse:
				 * 1548 phantom releases in one 330s run, round pace
				 * 13.5s vs 6s healthy). */
				if (!mxfs_v5_dlm_transport_caw(ip->i_mount->m_mxfs_dlm) &&
				    ip->i_dlm_phantom_bast_n >= 2 &&
				    ip->i_dlm_ex_holders == 0 &&
				    ip->i_dlm_pr_holders == 0 &&
				    ip->i_dlm_pin_count == 0) {
					ip->i_dlm_phantom_bast_n = 0;
					ip->i_dlm_reconcile_pending = true;
					ip->i_dlm_state =
						MXFS_DLM_ISTATE_DEMOTING;
					spin_unlock(&ip->i_dlm_lock);
					mxfs_probe("mxfs: P-PHANTOM-RECONCILE ino=%llu — repeated no-mirror BAST; serialized reconcile release\n",
						(unsigned long long)ino);
					if (!mxfs_bast_arm_queue(ip)) {
						mxfs_probe("mxfs: P76-QW-FALSE ino=%llu site=phantom-reconcile — work already pending; extra ref dropped (P226)\n",
							(unsigned long long)ino);
						/* see site=immediate. */
						xfs_irele(ip);
					}
					return;	/* queued: work fn owns the ref */
				}
			}
			spin_unlock(&ip->i_dlm_lock);
		}
		mxfs_caw_orphan_forensic(ip, 1);
		xfs_irele(ip);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=NONE_mode_NL — no orphan, nothing to release", (unsigned long long)ino);
		return;
	}

	/*
	 * Mode A fix: honor the D9 multi-step pin.  A pinned inode is
	 * in the middle of a read-modify-flush operation (e.g. xfs_create has
	 * verified the name does not exist and is about to add it) and MUST
	 * keep its DLM token until the op completes — otherwise a peer steals
	 * the lock between our existence check and our dir modification and
	 * both nodes create the same name (the canonical Mode A lost-update).
	 * Defer the BAST; mxfs_inode_unpin fires the release when pin (and any
	 * holders / yield quantum) drain.  This branch must precede the
	 * holders==0 "immediate" branch so a pinned-but-unheld inode defers.
	 */
	if (ip->i_dlm_pin_count > 0) {
		atomic64_inc(&mxfs_dlm_stat_bast_deferred);
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		spin_unlock(&ip->i_dlm_lock);
		xfs_irele(ip);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=pinned (pin=%u) — set BAST, defer to unpin",
			(unsigned long long)ino, ip->i_dlm_pin_count);
		return;
	}

	/*
	 * Minimum Hold Time: if we acquired this EX grant very recently,
	 * defer the release (keep CACHED, arm the dwork) so this node batches its
	 * remaining queued ops in one tenure instead of ping-ponging the lock per
	 * op.  Applies whether or not a holder is currently active — in both cases
	 * keeping CACHED lets our own ops keep fast-pathing during the window.
	 * mxfs_dlm_mht_defer_bast drops i_dlm_lock and consumes our iget ref when
	 * it returns true.
	 */
	if (mxfs_dlm_mht_defer_bast(ip)) {
		atomic64_inc(&mxfs_dlm_stat_bast_deferred);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=MHT-defer", (unsigned long long)ino);
		return;
	}

	/* daf50d34 a slow-path acquire is between grant-publish and
	 * holder-registration (or between claim-win and mode-publish) —
	 * holders==0 does NOT mean idle.  Queuing the immediate release here
	 * strips the materializing tenure (the proven mkdir-storm kill via
	 * the NONE-idle sibling branch).  Defer via i_dlm_bast_during_acq;
	 * the acquire completion honors it (P35-ACQBAST-HONOR). */
	if (ip->i_dlm_acq_inflight > 0) {
		ip->i_dlm_bast_during_acq = true;
		spin_unlock(&ip->i_dlm_lock);
		mxfs_probe_ratelimited(
		    "mxfs: P-ACQWIN-DEFER ino=%llu mode=%u state=%u (immediate-release suppressed; slow-path acquire in flight)\n",
			(unsigned long long)ino, ip->i_dlm_mode,
			ip->i_dlm_state);
		xfs_irele(ip);
		return;
	}

	if (ip->i_dlm_ex_holders == 0 && ip->i_dlm_pr_holders == 0) {
		/*
		 * No active holders — process BAST immediately via workqueue.
		 * Transfer the xfs_iget reference to the work function.
		 */
		atomic64_inc(&mxfs_dlm_stat_bast_immediate);
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_DEMOTING;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
		spin_unlock(&ip->i_dlm_lock);
		mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=immediate — schedule work", (unsigned long long)ino);
		/* dedicated inode-bast wq (flushable at unmount) */
		ip->i_dlm_bastq_src = 5;
		if (!mxfs_bast_arm_queue(ip)) {
			/*
			 * D-UNMOUNT-BUSY-INODES ROOT (kprobe ref-trace
			 * proven, ino 8391890): queue_work false = an earlier
			 * donor's instance is pending and owns exactly ONE
			 * ref; it will irele ONCE.  Returning here without
			 * dropping OUR iget ref leaked one inode per
			 * collision (icount=1 at unload, dentry_count=0, no
			 * pending works — every historical capture).  Same
			 * pattern as the ilock-end arm's queue-false drop.
			 */
			mxfs_probe("mxfs: P76-QW-FALSE ino=%llu site=immediate — work already pending; DEMOTING set on top; extra ref dropped (P226)\n",
				(unsigned long long)ino);
			xfs_irele(ip);
		}
		return;	/* queued: work fn owns the ref */
	}

	/*
	 * Active holders — defer BAST to unlock path.
	 * When the last holder calls mxfs_dlm_ilock_end, it will
	 * see BAST state and process the flush+release.
	 */
	atomic64_inc(&mxfs_dlm_stat_bast_deferred);
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	spin_unlock(&ip->i_dlm_lock);
	xfs_irele(ip);
	mxfs_idbg("mxfs: MX-INSTR bast_notify ino=%llu BRANCH=deferred (active holders) — set BAST", (unsigned long long)ino);
}

/*
 * P70 diagnostic: FUA-read this AG-meta buffer's block straight from
 * disk (pierces the iSCSI per-initiator cache) and compare against the
 * in-core content.  Returns 1 if they DIFFER (in-core is STALE vs the true
 * on-disk content -> read-coherency bug), 0 if IDENTICAL (in-core matches
 * disk -> any btree inconsistency is genuinely ON DISK -> write/durability
 * bug), negative on error.  Caller must hold the buffer locked.  Runs only on
 * the rare corruption path, so allocation cost is irrelevant.
 */
int mxfs_diff_detail;	/* P35D: dump byte-level diff detail when set */

int mxfs_relflush_skip;	/* DIAGNOSTIC default 0: when 1, SKIP the per-dir-EX-release blkdev_issue_flush (xfs_mxfs_dlm.c ~5818) to MEASURE its share of the ~22.5ms holder-side release cost that bounds tcp_dlm_scaling throughput. UNSAFE for correctness (peer FUA-reads may miss un-destaged writes) — measurement only. */
module_param_named(relflush_skip, mxfs_relflush_skip, int, 0644);

int mxfs_relsettle_skip;	/* DEFAULT 0 (settle REQUIRED). TESTED default-1 (skip): broke dir_reuse 0/4 + fence/netpartition 3/4 — the settle's pincount==0 wait protects the dir-DATA flush (mxfs_dir_flush_data_blocks, which runs BEFORE the inode drain), not just the inode; the drain only covers the dinode. So the settle is NOT redundant. Kept as a diagnostic A/B lever (the async log-kick before the loop trims its cost ~10%). */
module_param_named(relsettle_skip, mxfs_relsettle_skip, int, 0644);

int mxfs_reg_release_durable = 1;	/* default ON — with RELOAD-SIZE-DROP-SKIP guarding the clobber-own-size race, this flushes a reg file's di_size to its cluster on BAST-release so a peer's FUA-read sees real content (fixes cross_write_read empty-content; validated PASS on fresh mounts). */
module_param_named(reg_release_durable, mxfs_reg_release_durable, int, 0644);
MODULE_PARM_DESC(reg_release_durable,
                 "Flush a regular file's dinode to backing store on DLM "
                 "release: 0=off (default; =1 tested WORSE+slower)");

int mxfs_reldefer_reload = 1;
module_param_named(reldefer_reload, mxfs_reldefer_reload, int, 0644);
MODULE_PARM_DESC(reldefer_reload,
                 "drive the reload a flush fence asked for from the release-side "
                 "retry worker, so a fence-abandoned publication reconciles its "
                 "obligation instead of wedging the mount; 0=pre-fix control");

/*
 * — see the P384 block in mxfs_dlm_bast_process.  Holds a chosen
 * inode's grant forever while the node stays mounted and beating, so
 * incident474 hole (c) — "HB alive" mistaken for "fs serviceable" — can be
 * exercised.  0 = disarmed.
 */
unsigned long long mxfs_hold_grant_fault_ino;
module_param_named(hold_grant_fault_ino, mxfs_hold_grant_fault_ino, ullong, 0644);
MODULE_PARM_DESC(hold_grant_fault_ino,
                 "refuse to release this inode's grant while staying mounted "
                 "and heartbeating, to exercise the liveness oracle's "
                 "alive-vs-serviceable hole; 0=disarmed");
