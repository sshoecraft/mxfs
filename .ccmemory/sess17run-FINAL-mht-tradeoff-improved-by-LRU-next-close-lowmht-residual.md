---
name: sess17run-FINAL-mht-tradeoff-improved-by-LRU-next-close-lowmht-residual
description: sess17(ccloop) FINAL: dg_shadow LRU hugely improved the mht tradeoff (data loss 799/800→0 at mht=300, →2-7 at mht=50). mht=300 correct-but-starves; m…
metadata:
  type: project
---

## sess17 (ccloop) FINAL — major breakthrough + precise remaining tradeoff

### KEEP build 544A912E9356E96A39F24E2 (fork-adopt + dg_shadow LRU, default mht=300)
VALIDATED: 1/tcp 16/16 ✅, 2/tcp 17/17 ✅, 4/tcp focused dir_reuse 4/4 ✅. The dg_shadow LRU fix [[sess17run-MILESTONE-dgshadow-LRU-fixes-dataloss-newresidual-timeout-leaf]] made the cross-node handoff RELIABLE and eliminated the bulk of the 100+ session dir_reuse data-block lost-update.

### 8/tcp = the mht tradeoff, HUGELY improved by the LRU fix (profiled this session)
Baseline (pre-fix): 799/800 lost EVERY round at all mht. Now:
- **mht=300 (default): RDMISS=0 (data loss ELIMINATED), but 8-node dir-EX STARVATION** → P34-ACQ-SLOW ~2s queue wait (release-drain is fast 0-1ms, fua_disable=1 so reads are plain — the cost is the QUEUE, not the reload read) → some acquire hits the hard 120s timeout → force_shutdown (rc=-110) → ~67s/round (round 6 of 24) = RULE-0 slowness + shutdown fail.
- **mht=50: fast (round 15), but small data loss returns (RDMISS=2-7) + leaf holes (P21H=400)**. The reliable handoff doesn't fully close the race under 50ms rapid handoffs.

### So neither mht passes 8/tcp, but the gap is now SMALL (2-7 entries at mht=50, 0 at mht=300). Two convergent paths for the next session:
1. **Close the low-mht (50) residual data loss (2-7 entries) + leaf holes** so fast mht is also correct. The residual is a fast-handoff-window race the fork-adopt/LRU doesn't fully cover; investigate the leaf coherency (P21H, enable dir_leaf_rebuild=1 helped partially) and the sub-50ms handoff window.
2. **Fix the high-mht (300) 8-node EX STARVATION** so the correct config is also fast/non-shutdown. The dlm_fairness test passes in isolation but starves under the dir_reuse storm — investigate why a node waits 120s for dir EX (P36-RETRY storm on ino=131). A fairness/anti-starvation fix in the DLM grant queue.

### Profiling facts (RULE 4): acquire (P34-ACQ-SLOW) ino=131 median ~1.85s/max 2.8s = queue wait; release drain_ms 0-1ms (fast); fua_disable=1 (plain reads); hard rc=-110 → shutdown on hot-dir masters (test1/test2). The dir-EX serialization (8 nodes, one dir) is the inherent bottleneck.

### Do NOT revert LRU/fork-adopt (eliminated the data loss). Do NOT re-try per-modify epoch invalidation or acquire-side bulk evict (timeouts/drops-work). Reboot clean between runs; DRC_STREAM=1 for capture. Criterion NOT met; marker NOT written.</body>
