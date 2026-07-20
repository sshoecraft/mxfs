---
name: AAA-sess6-HEAD-fua_disable-plus-fair_handoff-state
description: sess6 HEAD/ENTRY: build 96C5CF1F (fua_disable=1 DEFAULT). fua_disable fixes read-storm (cache_coh@4/@16 PASS). fair_handoff=1 fixes dir_reuse STALL b…
metadata:
  type: project
---

## sess6 HEAD — ENTRY POINT for next session (ccloop 12e0d157, criteria: 1/2/4/8/16/32 caw 100%)

### THE FIX (two levers, both now understood)
Root of the 32-node "storm" = **misconfiguration**: CAW multipath target is SCST (`SCST_FIO`), but
`mxfs_fua_disable` defaulted to 0 (a LIO-era setting). On SCST, FUA reads pierce to the stale platter
(slow); plain-bio reads hit the coherent shared cache (fast+correct).
1. **fua_disable=1 — NOW THE DEFAULT (build 96C5CF1F, xfs_mxfs_dlm.c:24661).** Fixes the READ-storm.
   PROVEN: cache_coherency@4 4/4, strong_consistency@4 4/4, dir_reuse@4 4/4, **cache_coherency@16 16/16**.
2. **caw_fair_handoff=1 (param, dlm/dlm_caw.c, default 0).** dir_reuse@16/@32 have a SEPARATE root: CAW
   grant STARVATION on the shared reused dir inode (stat→xfs_ilock→caw_wait_for_grant msleep, proven).
   fair_handoff (round-robin EX ticket) **FIXES THE STALL** — PROVEN this session: with
   fua_disable=1+fair_handoff=1, dir_reuse@16 advanced PAST round 2 (the prior hang point) to round 2+.

### REMAINING ISSUE: dir_reuse@16 is SLOW (~4 min/round, verify-dominated) — RULE-0 fail
Stall fixed but ~4 min/round (verify ~2.5 min = per-entry DLM PR-grant overhead for 16 nodes × ~1600
stats/round; NOT read I/O since fua_disable makes reads cached). 24 rounds ≈ 90 min >> budget. This is
a SPEED bug to DIAGNOSE (RULE 0), not time-out around. Candidate angles: (a) the verify does per-entry
stat → a DLM grant each; batch/cache the dir PR so 1600 stats don't each round-trip; (b) profile which
phase (create vs verify vs rm) dominates at steady-state (round 1 had setup overhead — get round 2-3
rate); (c) fair_handoff helps EX but the stuck op was a PR reader — maybe PR readers still wait behind
EX creates; check if a PR-priority tweak helps. dir_reuse@8 PASSES (baseline ~530s per budget doc).

### IMMEDIATE NEXT STEP (script ready): validate @32 non-dir_reuse — BIG win (32/caw 13→16)
`/tmp/.../scratchpad/valfua32.sh` (fresh-boot 32 + `MXFS_EXTRA_MODARGS="fua_disable=1 caw_fair_handoff=1"
./run.sh 32 caw cache_coherency crash_consistency dlm_scaling`, NO flat timeout — run.sh enforces
per-test budgets). Expect all 3 PASS fast with fua_disable=1. Was NOT run yet (hit relay boundary).
Then: dir_reuse speed fix, then full ladder `scripts/caw_ladder_fua.sh` (uses fua_disable+fair_handoff,
no flat wrappers now).

### CRITERIA STATE
- 1/2/4/8 caw = 17/17 (restored this session; re-confirm under new default build before final marker).
- 16 caw: cache_coherency PASS(fua). dir_reuse = stall-fixed-but-SLOW (only holdout).
- 32 caw: 13 PASS. cache_coherency+crash_consistency+dlm_scaling PENDING validation (valfua32).
  dir_reuse@32 = same starvation+speed as @16.

### RULES REINFORCED THIS SESSION (user directive)
- NO flat/big timeout wrappers (user angry at a 3000s wrapper). run.sh enforces per-test RULE-0 budgets
  (tests/criteria/TIMEOUT_BUDGETS.md). A slow test is a FAIL to diagnose. I removed the wrappers from
  caw_ladder_fua.sh. Actively KILL slow runs (don't wait out a loose timeout).
- INFRA: MXFS_DEV=/dev/mapper/mpatha always. MXFS_EXTRA_MODARGS DOES propagate. `make clean` (user)
  wipes mxfs.ko+tools → `make modules && make tools`. Fresh-boot nodes before trusting results.
- Refuted this session (do NOT retry): dir_slow_handoff_gate (reload-skip, broke dir_reuse@4). All
  reload-skip signal approaches are dead for reuse cells.
See [[caw-sess6-PIVOT-scst-confirmed-fua_disable-is-the-storm-fix]]
[[caw-sess6-dir_reuse16-is-CAW-grant-starvation-not-readstorm]].
</body>
