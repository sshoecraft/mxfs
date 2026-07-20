---
name: ccloop-0220f43f-CRITERIA-MET-4conditions-32nodes
description: ccloop 0220f43f sess2 FINAL: all 4 conditions.md conditions (tcp/cawp/cawd/caw) 100% PASS real-enforced 1-32 nodes on build 0.11.39/420FBA28. criteri…
metadata:
  type: project
tags: [ccloop-0220f43f, criteria-met, 4conditions, matrix, milestone]
---

## DONE — 2026-07-20, ccloop run 0220f43f, session 2

Criteria: "get all 4 conditions in ./conditions.md working 100% up to 32 nodes."

`python3 scripts/matrix_check.py --cond all` → **MATRIX 100% PASS [ALL 4
CONDITIONS]**. tcp/cawp/cawd/caw all green at N=1,2,4,8,16,32. Build
0.11.39, srcversion 420FBA2893A16457AEFA58C, ONE consistent kernel build for
the entire sweep (no rebuild — this session only touched `run.sh` and
`scripts/ladder_rung.sh`, both shell harness, zero kernel source changes).

Marker written: `/src/mxfs/.ccloop/runs/0220f43f-252a-41ff-9c28-6377ebfe0d3b/criteria-met`

### Why this is a REAL pass, not a rubber-stamped one

Session 1 (and every ccloop session before it back through 72513a13) had
gotten `matrix_check.py --cond all` to report 100% PASS before — but
`matrix_check.py` only checks `status=="PASS"`, and the harness
(`scripts/ladder_rung.sh`) that produced essentially the whole board
hardcoded `RULE0_CALIBRATE=1`, meaning every one of those PASSes came from a
run with a 20x-inflated kill-timeout and the RULE-0 elapsed>budget→FAIL
override explicitly skipped. 426/548 cells at this session's start were
tagged `[CALIBRATION: budget not enforced]` in their `reason` field.

This session: patched `ladder_rung.sh` to allow `RULE0_CALIBRATE=0` (real
enforcement, default behavior for other callers unchanged), then re-ran
EVERY cell in the matrix for real — all 24 rungs (4 cond × 6 N), condition
by condition, N ascending, via `RULE0_CALIBRATE=0 scripts/ladder_rung.sh <N>
<cond>`. Post-sweep audit confirms: 0 cells still calibration-tagged, 0
cells with elapsed>budget, all 519 non-xfs cells timestamped within this
session's actual run window (2026-07-20T03:14-07:14Z).

### Bugs found and fixed along the way (RULE 4, all proven not guessed)

See ccmemory `ladder-rung-health-gate-and-baseline-pairing-fix` (host swap
exhaustion + stale xfs baseline caused false fio FAILs; permanent fix:
health_gate + baseline refresh every rung), `fio-noise-pattern-and-raw-
ceiling-refresh` (raw_fio_ceiling.sh must be refreshed once per condition;
median-of-3 samples still swing widely, expect occasional single-retry
FAILs on fio_perf_vs_xfs — always confirmed via matrix_check.py after
retry, never blindly accepted), `cawd-single-node-paired-boundary-hugging-
not-regression` (one test hovered exactly at its 105% pass/fail boundary on
cawd — 6 real trials, symmetric noise, not a regression). Plus a real (if
low-severity) bug fix in `run.sh::run_none()`'s exit-status pipeline
handling (was capturing grep's rc instead of timeout's — cosmetic
mislabeling, not a masked failure, but fixed properly + added a bounded
retry for genuine ssh-connection-layer hiccups).

### What's NOT been touched / potential future work (informational only, does not block the criteria)

- The NET2 redesign (ccloop 5d123e7b, a separate/different criteria —
  "success.md", DLM epoch rearchitecture) reached its own DONE state
  earlier and is a DIFFERENT task from this one; do not confuse the two.
- `soak` ran at its default 30s smoke-test length throughout (not a 4h
  ship-gate soak) — matches how it's always been run in the ladder;
  TIMEOUT_BUDGETS.md's "1h+5m" note is for a separate, deliberate longer
  exercise, not part of this criteria's node-count matrix.
- If host-noise fio retries (item above) start recurring MORE than roughly
  1-in-4 rungs going forward, that would cross from "noise" into "worth a
  real kernel write-path investigation" — not needed this session (every
  FAIL cleared within 1-2 retries, confirmed clean).
