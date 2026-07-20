---
name: sess15run-HANDOFF-state-and-next-steps
description: sess15 HANDOFF: build 0F1666F1 (H3+P15I+I+J2). Multi-node columns strong (17-of-18 pre-J). 1/tcp blockers: paired ~5% floor + fio noisy protocol.
metadata:
  type: project
---

# sess15 HANDOFF — state, tally, and the exact next moves

## Build lineage this session
- 3C674F70 FIX-H3 (orphan-release/grant-window family — see
  sess15run-FIXH3-final-shape-and-validation-ladder)
- 3AD15DA9 = +P15I probe
- 61FE57FD = +FIX-I (evicted-unpub-child durable-before-handoff — see
  sess15run-FIXI-*)
- 0F1666F1 = +FIX-J1/J2 (single-node log-force gates — see sess15run-FIXJ-*)
  J gates are is_single_node-only; multi-node validation on 0F1666F1:
  8/tcp r21 launched at session end (check /tmp/iter8_r21.log).

## Suite tally (17 tests; 1/tcp = 16)
- 3C674F70: 8/tcp 17/17 ×5 (r14-r18), 4/tcp ×2, 2/tcp ×2 + r3 FAIL
  (crash_consistency face → FIX-I), 1/tcp 16/16 ×2
- 3AD15DA9: 8/tcp r19 ✓, 2/tcp r4 ✓, 4/tcp r3 ✓, 1/tcp r3 ✓, 2/tcp r5 ✓,
  1/tcp r4 15/16 (paired 106% — led to the FIX-J investigation), cc_loop
  standalone ×14 clean
- 61FE57FD: 2/tcp r7 ✓ (P15J fired 126×), 8/tcp r20 ✓, 4/tcp r4b ✓
  (r4a aborted: leftover test5-8 held the LUN during mkfs — suite_iter now
  destroys all 8 always)
- 0F1666F1: 1/tcp r6 14/16 (paired 106%; fio_vs seqW 46% = host-noise,
  PASSed ×2 standalone right after with swings 210%/107%)

## What blocks the criteria marker ("1/2/4/8 tcp 100%")
1. single_node_paired: honest ~5% floor over native after FIX-J2
   (was 17%).  Protocol now position-balanced 4 rounds/trimmed mean —
   measurements stable (106,106,107,112).  Need ~3-5% more mxfs speed
   (or a proven fairness bug in the remaining protocol).  Leads in
   sess15run-FIXJ-* (deferred-unlock kmalloc inline, l_logsize check,
   disklock-heartbeat interference — 64 sync 512B reads rode along the
   3s bench window).
2. fio_vs_xfs_baseline: single-shot fio legs, host-cache swings 3× both
   directions (seqW mxfs/xfs: 686/1471 FAIL then 1505/715, 1488/1383
   PASS).  Needs the same balanced-rounds treatment as paired if it keeps
   flapping.
3. Multi-node re-validation depth on 0F1666F1: r21 pending; then 2/tcp +
   4/tcp once each, then accumulate streaks on the FINAL build only.

## Watchpoints (probes armed, do not lose)
- P15I-CRCFAIL (sector CRCs) for the r3 inobt flavor; P126 in_ail=1 discard
  is suspect #1 (vs sess43 invariant).
- P15J-PUBSKIP-FLUSH settled=0 lines would mean the 250ms wait is too short.
- P135-GRANTWIN-PARK same-ino streaks (stranded-grant ping-pong).
- fence_during_write own-data face: gone since FIX-H3 (was H/H2 collateral);
  fdw forensics remain in the test script.

## Harness notes
- tests/cc_loop.sh = targeted crash_consistency reproducer (N, dlm, laps,
  optional pre-test).
- suite_iter.sh now destroys test1-8 regardless of N.
- single_node_paired.sh: legs echo "ms files"; 4 balanced rounds; leaves
  node mounted on fresh mxfs (round order XM MX MX XM + final mxfs_leg).
