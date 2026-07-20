---
name: caw-16node-MILESTONE-16of17-pass-dir_reuse-perf-sole-holdout
description: MILESTONE ccloop 0d6e174d: 16/caw = 16 PASS 1 PENDING. ONLY dir_reuse_coherency left = O(N^2) perf (verify ~79s/round FUA-bound at 16). All others pa…
metadata:
  type: project
---

## 16/caw MILESTONE — 16 of 17 PASS (ccloop 0d6e174d, 2026-07-07, build 8B203AA4)

`./showstat.sh 16 caw` = 16 PASS, 0 FAIL, 1 PENDING. See [[caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone]].

### PASS at 16/caw (all on fresh-prep single-test/small-group runs, ship config unless noted):
precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss,
dlm_fairness, dlm_membership, scaling_curve, **dlm_scaling** (PASSES 16/16 ALONE — the "15/16 epoch"
was contamination), rsync_paired, crash_consistency, **fence_during_write**, **fault_netpartition**,
**soak** (30s, ops=1087 errs=0), **dlm_lock_correctness** (fua=ok caw=ok).

### SOLE HOLDOUT: dir_reuse_coherency = PERF (O(N^2)), not correctness
Correctness is FINE with config `MXFS_EXTRA_MODARGS="bast_wq_max_active=16 noino_bast_dedup=1"` (0 EIO,
0 drc-FAIL in probes; these two fix the CAS-livelock/unlock-exhaustion WEDGE — ship default is 0/0 and
WEDGES with EIO). `caw_fair_handoff=1` also correct but ~300s/round (far too slow — do NOT use).
- **The blocker is WALL TIME.** Measured 16-node (dedup+bast_wq, no fair_handoff): ~250-280s/round.
  Phase breakdown (test1 r1): create ~50-80s, **verify ~79s**, rm ~60s. 24 rounds ≈ 6000s vs budget
  140*N=2240s (93s/round). At 8 nodes it was ~40s/round (create 9-16, verify 4-14, rm 21 = ~1000s/1120s
  budget PASS). So 16-node verify is 6-10× the 8-node verify = SUPER-LINEAR (not O(N)).
- **ROOT of the blowup = verify phase.** After each round's `echo 3 > drop_caches`, ALL 16 nodes
  concurrently do `test -e ×1600` (cold). If mxfs FUA-re-reads the stable dir block PER lookup (instead
  of caching within the PR read-tenure — no writer is active during verify, dir is stable), that's ~1600
  redundant FUA/node × 16 = FUA-storm saturating the shared LUN. This is the "shared dirs need
  within-tenure dedup, NOT yet attempted" lever. UNCONFIRMED — needs instrumentation (next).
- RULE-0 question to resolve: is the verify FUA NECESSARY (→ budget legitimately super-linear, set by
  measured healthy wall per TIMEOUT_BUDGETS.md's own "record healthy PASS wall and tighten") or REDUNDANT
  (→ real perf fix = within-PR-tenure dir-block cache). The create-phase FUA IS necessary (bestfree
  double-alloc, dirop_durable_caw=0 A/B proved it). The VERIFY-phase FUA (reads only, stable dir) is the
  suspected waste. Instrument verify FUA count before deciding.
- dir_reuse is the crux for BOTH 16 and 32 (O(N^2) → 4× worse at 32). Parallel ccloop 26c41354 also
  never cracked dir_reuse perf. See [[caw-16node-sess3-dirreuse-remaining-create-lockhold-straggler]].

### 32/caw: NOT STARTED. test17-32 are SHUT OFF (virsh). Infra supports N=32 (preflight/mpath_up range
1..32; Condition4 proved storage presents 2-path mpath to 32/32). Need: start test17-32, preflight 32.

### REMAINING for criteria (1/2/4/8/16/32 caw 100%):
1. dir_reuse perf (blocks 16 AND 32) — the crux.
2. 32/caw: start VMs, preflight, run all 17 (expect same fresh-prep pattern), fix 32-specific issues.
3. Re-verify 1/2/4/8 caw on final build.
Marker NOT written.
