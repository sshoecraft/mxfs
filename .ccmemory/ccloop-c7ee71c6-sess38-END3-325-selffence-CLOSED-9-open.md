---
name: ccloop-c7ee71c6-sess38-END3-325-selffence-CLOSED-9-open
description: sess38 END3: D-RELABORT-SELFFENCE FIXED AND VERIFIED in 0.11.325 (per-slot disklock lock; lockwait 26726->0 live A/B; 10/10 green) — 9 OPEN; cluster…
metadata:
  type: project
---

# sess38 END3 — self-fence defect CLOSED, 9 OPEN

## The closure (full RULE-4 arc inside one session)
1. 324's new P-HB-SLOW probe caught the mechanism LIVE within an hour: test1 hb writer lockwait_ms=26726 (write_ms=0) during board load.
2. Root: THREE disklock read loops held ctx->lock across full slot scans (read_all ×64; get_stale_slot_mask snapshot ×63 + poll ×63×N — runtime v5_mount acquire/join paths) — ~25s continuous holds at saturated ~400ms/read vs the 62s lease.
3. Fix 0.11.325 (9905C45A): per-slot lock/unlock (monitor-pass precedent). NEW INVARIANT in dlm.md: never hold disklock ctx->lock across a multi-slot I/O loop.
4. Verified same-saturation: lockwait=0 on every event; residual = raw write ≤2.5s (25× lease margin); 10/10 tests green INCLUDING crash_consistency (its NO_TERMINAL_RECORD×32 pattern rode the same starvation — 77s clean now) and fence_during_write (32/32).
- Bonus insight: the 323/324 crash_consistency NO_TERMINAL_RECORD×32 events and the fence_during_write 2-node FAIL were the SAME starvation surfacing elsewhere — all green post-fix.

## Cluster: 32/caw on 0.11.325, defaults, healthy. 15 board-roster tests green on 325 this session (fio, cc, zsl, scaling, rsync, crash, fence, netpartition, soak, dirent + earlier smoke); REMAINING for a complete 325 board: dir_reuse_coherency, strong_consistency, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, dlm_scaling, dirent_publish/type_integrity, node_responsive, kernel_health, ag_strand_repair, sustained_load, dlm_lock_correctness, precond.

## 9 OPEN
Pace: D-DIR-REUSE (bimodal), D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE.
Authority: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN, D-AGI-UNLINKED (canary armed).
Other: D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED.

## NEXT
1. Complete the 325 board (remaining ~15 tests, 2 foreground chunks) — the starvation fix may ALSO have moved dir_reuse's bimodality (its stragglers' LOCKTOTAL events could have been hb-scan mutex victims via shared device queue... measure, don't assume).
2. dir_reuse ×3 on 325 — re-baseline the pace defects post-fix.
3. Then authority family / drain design per earlier memories.
