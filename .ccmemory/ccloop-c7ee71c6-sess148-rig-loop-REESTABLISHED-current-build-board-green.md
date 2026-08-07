---
name: ccloop-c7ee71c6-sess148-rig-loop-REESTABLISHED-current-build-board-green
description: sess148: after breaking the host-jam rabbit hole, re-established the 32/caw rig on 0.11.453. Fresh board: cache_coherency, node_responsive, kernel_he…
metadata:
  type: project
tags: [rig, board, sess148, 0.11.453, D-INODE-CLUSTER, measurement-loop]
---

# sess148 — rig measurement loop re-established on the current build

After sessions 141–147 were consumed by a host-loop0 jam, sess148 abandoned
that surgery (see ccloop-c7ee71c6-sess148-STOP-host-jam-surgery-ABANDONED)
and PROVED the actual mission rig is healthy and usable on the current build.

## What was proven (all measured this session)
- Rig plumbing intact: 32/caw (dm-multipath, 64 SCST sessions) still wired
  from Aug 4. `scripts/rig.sh status` confirms.
- Current tree = **0.11.453**, srcversion **F20024E38213A9E64DB6718**,
  mxfs.ko built Aug 4 15:30. This IS what the rig deploys.
- `./run.sh 32 caw prep_cluster` → OK in **71s**: mxfs mounted on all 32
  nodes, all report active_count=32, converged stable 12s. (Markers were
  stale/unmounted since Aug 4; plumbing did NOT need rebuild — fast path.)
- Fresh board on 0.11.453 @ 32/caw, DEFAULT knob (cluster_passenger_skip=3,
  the D-INODE-CLUSTER fix ON):
  - cache_coherency  PASS 32/32  (654/654 checks, 23s/60s)
  - node_responsive  PASS 32/32  (dstate=0 on ALL nodes — jam is host-only)
  - kernel_health    PASS 32/32  (hits=0, kinds=[] — zero WARN/BUG/oops)
- hostload≈525 (the host jam) was present during every run and did NOT
  impede the rig: cache_coherency still finished in 23s. Confirms the jam
  is cosmetic w.r.t. the mission.

## RULE-6 honesty
NONE of this closes any ledger defect. A clean board is not a disposition.
It re-establishes the *capability* to verify, and gives a current-build
regression baseline. 28 defects remain OPEN (17 critical).

## Cluster STATE at end of session
LEFT UP: 32/caw prepped + mounted + converged on 0.11.453, knob=3. The
prep marker is current, so the next session can run tests directly with
`./run.sh 32 caw <test>` (NO re-prep needed) — saves the 71s.

## Mechanics learned (for the next session)
- `./run.sh <N> <dlm> [test...]` runs explicit tests; with a test filter it
  will NOT auto-prep — must `./run.sh <N> <dlm> prep_cluster` first if the
  marker is stale (symptom: "marker stale: testX live='' want='<srcver> MOUNTED'").
- Knob set via insmod modarg: `MXFS_EXTRA_MODARGS="cluster_passenger_skip=0" ./run.sh 32 caw prep_cluster`
  (prep re-insmods with the arg). Default is 3 (bits: 1=held-PR passenger
  skip, 2=no-incore skip). `pal/linux/xfs_buf.c:1088`.
- Manifest `tests/suite/manifest`: many P2 coherency tests (strong_consistency,
  posix_multi, mmap_coherency, dlm_fairness) cap at max_nodes=30 → NOT
  applicable at 32. cache_coherency (max 60) is the primary 32-node coherency test.
- RULE-0 gotcha: `dir_reuse_coherency` at 32/caw is budgeted 140×32 ≈ 4480s
  (~75 min) — NOT foreground-runnable. Run it at 8/caw (~1120s) or background it.

## Suggested next steps (ledger, not the jam)
1. Continue the D-INODE-CLUSTER knob board: run the knob=0 regression arm
   (`MXFS_EXTRA_MODARGS="cluster_passenger_skip=0"` prep, then the coherency
   workload) and capture P218 authority telemetry
   (`echo 1 > /sys/module/mxfs/parameters/cluster_authority_dump`,
   `tests/cluster_authority_census.sh`) to A/B no_write_tenure fix-on vs off.
2. OR broaden the current-build snapshot with more 32-node tests
   (rsync_paired → D-RSYNC-361; crash_consistency → recovery defects) to find
   any regression before deep per-defect work.
3. Do NOT run fence_during_write / the fence_inflight harness on loop0 (wedged).
   Use a fresh loop device if fence work is needed.
