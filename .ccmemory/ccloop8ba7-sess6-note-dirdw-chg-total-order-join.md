---
name: ccloop8ba7-sess6-note-dirdw-chg-total-order-join
description: iter_13 join method: P136 is gated OFF (needs mxfs_dirwr>=2/instr). Use P-DIRDW chg= (di_changecount, TOTAL ORDER) instead: sort uv-ino P-DIRDW by ch…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess6, join-method, performance, rule0]
---

# Two handoff notes (sess6 tail)

## 1. iter_13 resurrection-writer join — corrected method
P136-DIRINO-WRDONE printed NOTHING in iter_13 (it is gated on `mxfs_dirwr_enabled >= 2 || mxfs_instr_enabled`, which the repro does not set — only dblalloc_probe=1). Two options:
- (a) No new run needed: **P-DIRDW lines carry `chg=` = di_changecount — a monotonic TOTAL ORDER on dinode images.** Extract all `P-DIRDW .*ino=48234650` from tests/logs/dblalloc_repro/iter_13/full_test*.log as (wall-ts, node, nx=, chg=), sort by chg. test25's post-rm truth = the first nx=3 image (chg=C). The resurrection writer = any write with wall-time AFTER that but chg <= C, or an nx=4 image with chg > C whose content re-includes blk0_fsb=6029607 (P-DIRIFLUSH incore_blk0_fsb prints identify that). Note pre-free P-DIRIFLUSH on test25 was nx=4 blk0=6029607 chg=1918 at 23:11:53.
- (b) If (a) is ambiguous, re-run repro with MXFS_EXTRA_MODARGS='dblalloc_probe=1 dirwr=2' (check the actual modarg name for mxfs_dirwr_enabled) to light up P136-DIRINO-WRDONE (ino/fmt/gen/size/nx/daddr/realns at dinode WRITE COMPLETION) and P-DIRWR/P-DIRRD, then redo the join with realns precision.

## 2. USER DIRECTIVE (sess6 interjection, verbatim intent): dir_reuse@32 = 3242s is NOT acceptable
3242s ≈ 32 × 110s single-node = fully-serialized cluster; budget 4480s was a calibration ceiling, not a derived budget — treating that PASS as fine violated RULE 0. Direct evidence of pathological handoff cost already captured: P34-ACQ-SLOW dur_ms=10184 (10s dir EX acquire, iter_13, on the uv dir) and 6s P138-BAST drain phases. Honest handoff floor ~10-20ms (CAW CAS + targeted drain + flush).
Plan of record: (1) finish the dir-fork resurrection correctness fix (same dir-handoff machinery), (2) profile round pace on the fixed build via P138 phase breakdown (sa/sb/b1/b2/sc/sd/su) + P34-ACQ-SLOW, kill the dominant stall (suspect ACQUIRE_WAIT ~1s retry × MHT interaction), (3) decompose per-node 110s into legitimately-dir-EX-serialized vs overlappable, derive the real 32-node floor, set the manifest budget from THAT (not calibration), and flag any test whose elapsed is a large multiple of single-node time as a perf FAIL even when checks pass. Applies to the whole suite (posix_multi budget 30s flat is also miscalibrated, measured 62-71s @32).
