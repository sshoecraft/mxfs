---
name: sess20-SCOPE-sole-blocker-is-8node-tcp_dlm_scaling-makespan
description: sess20(ccloop) CRITICAL SCOPING: at default mht=300, dir_reuse PASSES all node counts + tcp_dlm_scaling PASSES at 1/2/4 nodes (4-node worst=45s<60).…
metadata:
  type: project
---

## sess20 (ccloop) — the entire 1/2/4/8 tcp criteria reduces to ONE failing test at ONE node count

### Measured at DEFAULT mht=300 (build 5C08C626, clean reboots, 8/8 or 4/4):
- **dir_reuse_coherency**: PASS 8/8 @ 8 nodes (~270s). Passes at all node counts (correctness improves with fewer nodes). NOT a blocker at mht=300.
- **tcp_dlm_scaling** (`tests/tcp/tcp_dlm_scaling.sh`, shared /dev/sda, 150 rounds, ≤60s window):
  - 4 nodes mht=300 → **PASS 4/4**, elapsed worst=45.1s (test1=12.9, test2=44.9, test3=45.1, test4=42.8).
  - 8 nodes mht=300 → **FAIL 1/8**, rounds=150/150 ALL nodes (CORRECT) but elapsed worst=126s (rank1=126, rank3=125, rank2=86, rank8=33). Pure WINDOW/speed fail.
  - 8 nodes mht=100 → **PASS 8/8**, worst=43s.

### IMPLICATION: `./run.sh 1 tcp`, `2 tcp`, `4 tcp` FULL suites should PASS at default mht=300 (tcp_dlm_scaling passes ≤4 nodes, dir_reuse passes). **The SOLE blocker for the whole criteria is 8-node tcp_dlm_scaling makespan** (126s serialized vs 60s).

### WHY 8-node is slow (serialized exclusive holding): the shared dir-EX lock serializes ALL dir modifies; 8 nodes × 150 rounds, each node holds the lock and rips through its rounds (~16s each holding) → makespan = SUM ≈ 126s. At low mht the commits PIPELINE/interleave across nodes → 43s. So low mht is fundamentally faster for this single-shared-dir churn; high mht serializes. dir_reuse needs high mht (masks its handoff coherency bug, see [[sess20-mht-tradeoff-no-single-value-coherency-fix-required]]). Genuine conflict ONLY at 8 nodes.

### TWO PATHS to close 8/tcp (next session):
1. **Fix dir_reuse coherency at LOW mht** → set default mht low → both pass at 8. Root chain proven: stale leaf (FIXED, postread leaf_only) → stale extent map (fsb 14 / daddr 0x70) → AG free-space double-free. Deep (sess38-47 class). See [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]].
2. **Cut 8-node tcp_dlm_scaling makespan at high mht** WITHOUT speeding dir_reuse handoffs — needs a signal that distinguishes tcp_dlm_scaling (unique write-only churn, no cross-node read) from dir_reuse (persisted cross-node-read dirents). No clean contention-based signal found (both have 8 waiters). Per-inode/adaptive mht risks gaming/regression.

### FIRST ACTION NEXT SESSION: confirm `./run.sh 1 tcp`, `2 tcp`, `4 tcp` FULL suites are GREEN at default (build 5C08C626, MXFS_EXTRA_MODARGS=''). If yes, the problem is provably ONLY 8-node tcp_dlm_scaling — focus 100% there.
</body>
</invoke>
