---
name: ccloop-c7ee71c6-sess37-FINAL-drc-first-pass-8-rounds-bounce-proven
description: sess37 FINAL: dir_reuse FIRST PASS in 11 runs (58/58, exactly 8 rounds, zero margin) on 317; create bounce PROVEN (PR,PR,PR→EX→PR,PR→EX per wave — EX…
metadata:
  type: project
---

# sess37 final addendum

## dir_reuse_coherency: FIRST PASS in 11 runs
0.11.317, 32/caw, lap after the four protocol fixes: **PASS 58/58 = exactly 8 rounds** (floor 8, margin ZERO — sess24 healthy baseline was 9-10; the FLAKY pattern will persist until ~2s more comes off the round). The board FAIL streak (10 of 11) is broken but the defect stays OPEN per RULE 0/6 (zero margin ≠ fixed; D-DIR-REUSE-COHERENCY-32-FLAKY unchanged).

## CREATE-BOUNCE MECHANISM PROVEN (instr=1 on test5/test12 during the lap)
GRANT-WAIT-START sequence on the shared dir (ino 537845) inside test5's r=6 create window (4 creates in 2 waves): `PR,PR,PR, EX, PR,PR, EX` — 8 slow-path acquires for 4 creates.
KEY INFERENCE: a SLOW-PATH PR acquire after an EX means the EX was ALREADY STRIPPED (cached EX subsumes PR with zero wire ops). So the node's dir-EX tenure dies after EVERY SINGLE INSERT, despite dir_ex_tenure_floor=1 (MHT floor at the state==BAST ilock_end refire) and dir_ex_batch_grace_ms=40 (sliding per-op grace) — and grace 40→120 was A/B-refuted (no change).
NEXT HYPOTHESES (ranked, with code sites):
1. The streak-yield PR-batch grant (sess37's own 315 change!) strips the holder: with 31 EX waiters + PR waiters, every release does streak accounting; when the holder's insert ends and ANY release path runs with streak>=MXFS_CAW_EX_STREAK_YIELD, yield_to=pr_w (or now BATCH-GRANTS the PR class) — the creator's own next-lookup PR then queues behind the granted class. Check: is the holder VOLUNTARILY releasing at insert-end (ilock_end deferred-BAST refire honoring bast_pending immediately because the tenure-keep gate doesn't cover the between-syscall gap)?
2. mxfs_dlm_dir_tenure_keep_delay path: floor applies at state==BAST refire — measure whether the refire is even reached vs the release happening via a different arm (e.g., the demoter/MHT dwork src census: i_dlm_bastq_src distribution on the dir during create).
MEASUREMENT NEXT SESSION: watch_ino=dir + trace the RELEASE arm (which src/site releases the EX after each insert — P70-BP EXIT lines with src + the bastq_src at each release) for ONE wave. Then fix = keep the tenure across the insert→lookup→insert chain (the gap is <5ms of script time).

## Also this lap
- TIMEOUT_BUDGETS.md gained the 317 board healthy-wall record + tightening candidates (crash_consistency 86-88/90 = thinnest margin on the board).
- instr knob = mxfs.instr (maps caw_instr_on); enabling on 2 of 32 nodes is cheap and doesn't distort (lap PASSED with it on).
- pal.md awareness: hook needed a TOOL-registered edit (bash appends didn't clear it) — done.

## Criteria: NO — 8 OPEN. Fronts: pace margin (this thread), authority family (3 entries, untouched), MATRIX-UNMEASURED (rig), DIRVIEW-NONCONVERGE.
