---
name: AAA-ccloop7251-sess1-END-0.11.7-bufguards-disklock-board-relaunched
description: sess1 END: 0.11.7 B9D459F0 = EFI-agwait + buf double-free guards + disklock join fix; 32/cawd board RUNNING (PID 2596127). Ladders cawd→cawp→tcp→caw…
metadata:
  type: project
tags: [ccloop-72513a13, sess1-end, 0.11.7, buffer-lifecycle, disklock]
---

# ccloop 72513a13 sess1 END — 0.11.7 stability build, 32/cawd board relaunched

## Build lineage this session (final: 0.11.7 srcversion B9D459F0EF5F1D9FDC22E44)
1. 0.11.6: defer extent-free AG-DLM -ETIMEDOUT → capped -EAGAIN requeue
   (mxfs.efi_agwait_max=8). PROVEN: same fio saturation, 0 shutdowns (was 8),
   P-EFI-AGWAIT rode out 6-min AG holds.
2. b_mxfs_freeflag tripwire (xfs_buf_free chokepoint — agent proved ALL frees
   funnel there): second free = P-BUF-DOUBLEFREE alert+stack+no-op.
3. P-BUF-RELE-ZERO poison guards in xfs_buf_rele_cached/_uncached: rele on
   b_hold==0 zombie = WARN+return (stops wrap→resurrection→2nd free AND the
   perag double-put / double hash-remove side effects).
4. disklock.c stop_heartbeat: Bug-99 5s join now ESCALATES to blocking join
   (never abandon a kthread running module code). Root of the recurring
   bio_endio-into-unloaded-text panics (4-20/node in serial history; 512B
   peer-slot reads via bdev_pipelined_read, end_clone_bio frames on mpath).
   Also closes the abandoned-thread park-loop leak + disklock ctx
   free-while-live UAF (both agent-confirmed).

## Agent-report facts worth keeping
- Double-free ranked producers (UNPROVEN hypotheses, guards now catch them
  live): #1 P-RAFIX hold-steal in _xfs_buf_read (marker stole_hold, b_hold>1
  heuristic can steal the LRU's hold → b_hold==0 zombie on LRU → drain/shrink
  wrap-resurrection); #2 sync-credit completion misroute (3-router protocol,
  handle_error wake-vs-relse at ~:1887, XBF_ASYNC RMW race under b_lock-only
  writers); #3 stale b_iowait token. If a guard fires, its stack IS the
  RULE-4 proof for the next fix.
- rcu_barrier at module exit is present+ordered — post-rmmod callback crash
  was the double-call_rcu corruption, NOT a missing barrier.
- Backlog (low): kern.c build_bio first-page add failure → batch_len=0 →
  caller infinite loop.
- test25's death mid-dir_reuse CRC-tore dir da3_node daddr 43957744 → 8-node
  EFSBADCRC (-117) read storm at 13:49:26 → shutdowns. Torn-write recovery
  semantics NOT separately investigated — if CRC storms recur WITHOUT a
  panic, that's a fresh RULE-4 loop (crash-during-write hole).

## Live state at relay
- 32/cawd full board RUNNING: PID 2596127, nohup, log
  tests/logs/ladder_rung_32cawd.log (truncated per launch), on 0.11.7.
  fio_perf budget now 30*N linear (manifest+criteria.json); dlm_scaling
  floor 50/N≤16, 30/N>16 (measured bands, two rigs).
- Direct rig LIVE and clean: SCST single portal .1 (allowed_portal* sweep
  bug FIXED in scst_setup.sh — sysfs numbers extra values allowed_portal1..;
  old reset only cleared the first), all 32 nodes single-session by-path,
  serial 2e476d07.
- criteria.json: 32/cawd rows from the aborted runs show FAILs (fio_perf,
  dir_reuse aborted-marker, soak) — the running board re-records everything.

## Remaining to criteria (tasks 4-8)
cawd rungs 32,16,8,4,2,1 → rig.sh pass 32 + cawp ladder → rig.sh tcp 32 +
tcp ladder (16/32 NEVER tested!) → rig.sh mpath 32 + caw ladder — ALL on
0.11.7 (or later if new fixes land → re-run affected boards).
scripts/ladder.sh <cond> runs all rungs. matrix_check.py --cond all = oracle.
Marker only when all four columns are 100%:
echo YES > /src/mxfs/.ccloop/runs/72513a13-f875-4685-8b0a-0cce8c3aaeeb/criteria-met
