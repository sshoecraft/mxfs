---
name: sess17-crash-consistency-root-and-foreign-replay-design
description: sess17: crash_consistency ROOT = no live replay of dead peer's XFS log slice. Foreign-replay design + edit list; 3 of 6 edits DONE, build/wiring pend…
metadata:
  type: project
tags: [crash-consistency, foreign-replay, journal, sess17]
---

# sess17 — crash_consistency root cause + live foreign-slice replay (IN PROGRESS)

## Session results so far (all on build 9C2D4FA6, quiet cluster)
- **zero_silent_loss: PASS** (3/3 iters, 0 loss, 355s wall; budget row updated).
  The earlier 4800-loss FAIL was contamination from the duplicate-ccloop window
  ([[sess93-duplicate-ccloop-incident]]) PLUS an accounting bug (mount_cluster
  fail booked as N*DPN loss) — both fixed in
  scripts/sess88_workload_a_modeN_baseline.sh (infra retry + iters_completed) and
  tests/criteria/zero_silent_loss.sh (fail reason=infra; timeout 1800→480 per RULE 0).
- **mkfs_timing: PASS** (531ms).
- **crash_consistency: FAIL, ROOT-CAUSED.** acked=113 fsync'd records, reader
  sees visible=1. PROOF: fresh mount on test5 claimed freed slice 0 → XFS
  "Starting/Ending recovery" → file has ALL 114 records on disk. The data was
  durable in the dead writer's per-node log slice; **v5 has NO live replay of a
  dead peer's slice** — v5_lease_expire_cb (dlm/v5_mount.c:485) only purges CAW
  locks + disklock. The lazy-drain correctness comment (xfs_mxfs_dlm.c:8459
  "surviving peer replays our journal slot") is an UNIMPLEMENTED promise; the
  portable dlm/journal.c is vestigial in v5 (journal: destroyed commits=0).
- **Secondary (16-node only): false-fence storm.** With criterion's
  mxfs_lease_duration_ms=10000, 15 survivors' replay/fence I/O delays heartbeats
  → mutual PR preempts (kern.c:842 comment documents ">62s false-fence") → mass
  reservation-conflict storm → 12/16 guests livelocked hard (no net, no sysrq),
  test12/test16 watchdog-panic-rebooted. Diagnose AFTER the replay fix; 4-node
  repro shows the same visible=1 WITHOUT the storm.

## Foreign-replay design (decided, partially implemented)
Live replay of dead slice on ONE survivor via shadow xlog. Safety pillars:
1. **Private dummy AIL** for the shadow log — xlog_find_tail WRITES
   l_ailp->ail_head_lsn (xfs_log_recover.c:1182/1217/1289); sharing mp->m_ail
   would clobber live log accounting. kzalloc + INIT lists/locks, NO xfsaild.
2. **Skip intent family in pass2** (EFI/EFD 0x1236/7, 0x1240..0x124f) under
   foreign flag — keeps live AIL untouched; slice left DIRTY so the next
   mount-time claimer replays intents exactly as today (LSN gating makes buffer
   re-replay a no-op → double replay is SAFE → election is perf-only).
3. **Skip mount-only steps in xlog_do_recover** under foreign flag:
   xfs_ail_assign_tail_lsn + sb re-read + xfs_reinit_percpu_counters.
4. **Skip sb_lsn check in xlog_recover** under foreign (cross-slice LSN cycles
   incomparable).
5. Election: lowest-live-disklock-slot survivor runs replay (helper needed in
   dlm/disklock.c; fields: ctx->monitored[]/node_track[].live/local_slot;
   called from heartbeat thread ctx = lock-safe).
6. Cache invalidation: call mxfs_dlm_peer_joined_flush(mp) (xfs_mxfs_dlm.c:10572,
   takes void* mp) BEFORE replay (flush own dirty + invalidate perags so pass2
   reads fresh disk) and AFTER (drop stale views of replayed ranges).
7. Slice geometry: daddr = XFS_FSB_TO_DADDR(mp, sb_logstart) +
   dead_slot * mp->m_mxfs_log_slice_bblks; bblks = m_mxfs_log_slice_bblks
   (mirror xfs_mount.c:1038). Guard m_mxfs_log_node_count/slice_bblks > 0.
8. xlog_alloc_log/xlog_dealloc_log are STATIC in xfs/xfs_log.c → orchestrator
   `mxfs_xlog_recover_foreign_slice(struct xfs_mount *mp, uint32_t dead_slot)`
   lives in xfs_log.c; declare in xfs/xfs_log.h. Set XLOG_MXFS_FOREIGN_REPLAY
   bit + shadow->l_ailp = private ail BEFORE xlog_recover(shadow).
9. Trigger chain: v5_lease_expire_cb (after purges, if local==lowest live slot)
   → new callback mxfs_v5_dlm_set_dead_node_notify(ctx, fn, data) (mirror
   set_fence_notify, v5_mount.c:1109, struct fields at v5_mount.c:130) →
   xfs_mxfs_dlm.c handler queues work item (system_unbound_wq; expire_cb runs
   in heartbeat thread, must not block) → work fn does flush/replay/flush.
   Register in mxfs_dlm_cache_init (xfs_mxfs_dlm.c:10731-10750).

## Edits DONE (this session, not yet built)
- xfs/xfs_log_priv.h: XLOG_MXFS_FOREIGN_REPLAY bit 5 + xlog_is_mxfs_foreign_replay().
- xfs/xfs_log_recover.c: pass2 intent-family skip in xlog_recover_items_pass2;
  early-return gate in xlog_do_recover after xlog_do_log_recovery; sb_lsn check
  gate in xlog_recover.

## Edits REMAINING
- xfs/xfs_log.c: mxfs_xlog_recover_foreign_slice orchestrator (+ decl in xfs_log.h).
- dlm/disklock.c/.h: mxfs_disklock_lowest_live_slot(ctx, skip_slot).
- dlm/v5_mount.h/.c: dead_node_notify typedef/setter/fields; invoke in
  v5_lease_expire_cb after purges with election (dead_slot already computed there).
- xfs/xfs_mxfs_dlm.c: work struct + handler + registration.
- VERSION: 0.4.11 → 0.5.0 (new functionality). make modules; deploy
  cluster_reset_n.sh 16 (75s budget); re-run crash_consistency --nodes 4
  (budget 210s, expect PASS), then 16 (watch for false-fence storm — separate
  bug if it persists), then fence_during_write, scaling_curve,
  posix_semantics --nodes 16, then full verify_ship.sh.
- Update .claude/awareness/subsystems/xfs.md + dlm.md (and docs per BEHAVIOR rule).

## Environment notes
- HARD RULE 2 added to CLAUDE.md: NEVER reboot clyde ([[never-reboot-clyde]]).
- cluster_reset_n.sh 16 measured 35s (budget 75s, TIMEOUT_BUDGETS.md row added);
  verify loop parallelized. /tmp/.mxfs_pass = '<REDACTED-ROTATED>' (recreate after host reset).
- crash_consistency.sh now reports READER_NOT_MOUNTED/READER_NO_FILE sentinel
  in its FAIL line (was swallowed).
- test2 console screenshots/sysrq via virsh qemu-monitor-command work; serial
  consoles are unlogged ptys (no panic capture).

Related: [[sess15-run14d-wedge-recurrence-and-silent1]], [[sess135-p108-strip-race-and-dir-relflush]], [[feedback-parallelize-and-derive-timeouts]]
