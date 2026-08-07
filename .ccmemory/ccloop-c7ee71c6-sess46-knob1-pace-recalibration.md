---
name: ccloop-c7ee71c6-sess46-knob1-pace-recalibration
description: sess46: knob=1 drc has ZERO margin vs its 8-round floor even on 362 (58 checks = 8 rounds, NOT 19 — 3/round + fixed checks); crash-after-drc = backlo…
metadata:
  type: project
tags: [ccloop, sess46, iclus, pace]
---

# sess46 pace recalibration — knob=1 margins, not sess46 regressions

## The arithmetic trap (do not repeat)
dir_reuse_coherency checks = 3/round + ~27-30 FIXED checks. "58 checks"
on 362-knob1 = EIGHT rounds (floor is >=8, i.e. ZERO margin), not 58/3=19.
Misreading this cost half a session chasing a "3× regression" that was
mostly load noise on a zero-margin row.

## Measured facts (all 32/caw, 2026-08-02)
- 362-knob1 drc: 8 rounds/109s PASS (hostload 15-20). Floor >=8. NO margin.
- 370-knob1 (serial-walk B6 probe): drc 13 checks + lookup_fail=103 storm
  (iget-miss exhaustion — creators' destages starved behind rm-rf ifree
  waves paying chain-length serial sector reads). REAL regression; fixed in
  371 by find_slot-based probe (hint+span; bits provably live on the
  canonical LIVE slot — all tombstone sites gate on bits==0).
- 371 (probe fixed, widenings in): 7 rounds/107s. 372 (widenings reverted,
  admit sticky-check added): 6-7 rounds at hostload 30, **17-round-equiv
  check count at tracking=0 same load**... final word: 372+tracking0 ==
  7 rounds at load 30 too — tracking on/off DOESN'T move drc; the mover is
  HOSTLOAD 20 vs 30 (±1-2 rounds) on a zero-margin row.
- crash_consistency knob=1: 84s/90s standalone on 362 (6s margin);
  15s after 100s idle; 39s standalone on 372; >90s NO_TERMINAL when run
  back-to-back after drc. **drc's aftermath (reap/inactivation backlog)
  decays in ~100s and poisons the next pace row at knob=1.** knob=0 boards
  run the same sequence green — the backlog cost is knob=1-specific
  (cluster-EX cycle per reap-driven free).
- Phase censuses: crash stalls at md5write-done/dropcaches-done (datawrite
  32s + md5write 56s in-sequence vs 2s+15s standalone — 16× phase
  inflation from the backlog, NOT the budget being fundamentally short).
- sess46 runtime taxes measured SMALL: conversions (P95-OPEN-CLUSTER-
  CONVERT, 47-216/node/run) mostly memory-fast-path; B6 probe now 1 find_slot
  (hint miss for never-published = one span walk); sweep = 32 INCORE igets
  per release.

## Open questions for the default-ON checklist (knob=1)
1. drc zero-margin: either knob=1 must gain a round of pace (dir-EX tenure
   cohorting — DLM_PLAN Phase 2 — targets exactly the wrbar 7.8s slowest-
   creator wait) or the row stays load-flaky at 25-35 hostload.
2. crash-after-drc backlog: reap/inactivation trickle at knob=1 contends
   ~100s post-workload. Options: reap batching under one cluster EX,
   backlog drain acceleration, or board sequencing awareness (NOT a test
   weakening — knob=0 handles the same sequence).
3. Both are PACE items on the candidate config, not correctness. Matrix
   9/9 and coherency rows all green at knob=1-372 clean-load.

## Rig discipline addendum
Game-server bursts all day (load 17→88 cycles, ~20-40min period).
Pace rows at hostload>25 are coin flips on zero-margin rows. Gate EVERY
pace-sensitive run on load<20 now (was <30).
