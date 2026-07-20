---
name: sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap
description: sess6(run6614) DECISIVE (P6-DIRPATH counters, N=8 fail): fastret_stale=0 + demoter_bypass=0 on ALL nodes → NOT stale-base-RMW, NOT bypass. Gen-cohere…
metadata:
  type: project
---

## sess6 (run 6614) — N=8 dir_reuse ROOT NARROWED (decisive, build 97E09EE8)

### DECISIVE MEASUREMENT (P6-DIRPATH atomic counters, behavior-neutral, at a real N=8 FAIL 0/8):
ALL 8 nodes: **fastret_stale=0** (no dir-EX fast-path serve returned with gen>loaded = stale base) + **demoter_bypass=0** (demoter-bypass path NEVER used) + fastret_total 700-7130 + slowpath 20-26 + phantom_total=0.

### CONCLUSION — REFUTES the two leading hypotheses:
1. NOT a stale-base RMW at the serve: gen==loaded at EVERY dir-EX serve (fastret_stale=0). The gg_refresh keeps gen-coherence perfectly. The RMW never sees a gen-stale base.
2. NOT a gg_refresh-bypass path: demoter_bypass=0.
⇒ **The base is gen-FRESH but content-STALE**: when the acquirer cold-reads the (evicted) dir block from the LUN, the DISK IMAGE is BEHIND the gen — the peer's just-committed dirent is not yet durable on the platter. loaded_gen advances on the reload/evict bookkeeping, not on proof-of-durable-disk-content. So a gen-fresh cold-read of a not-yet-durable block RMWs a content-stale base → drops the peer's late dirent. = **RELEASE-SIDE / PUBLISH DURABILITY GAP** (GPT-5.5's secondary hypothesis, now the PRIMARY).

### NEXT FIX TARGET (RULE 4): ensure a peer's committed dir DATA/LEAF blocks are DURABLE on the LUN before the gen is bumped / before EX release lets the next node cold-read.
- `mxfs_dlm_dir_durable_signal` (xfs_mxfs_dlm.c:18481) is publish-before-notify (synchronous xfs_bwrite of modified DATA+leaf + blkdev_issue_flush) BUT gated `i_dlm_dir_gen>0 && fmt EXTENTS/BTREE`. SUSPECT: round-1 / early creates run while gen==0 (fresh dir before first cross-node read bumps gen at xfs_da_btree.c:3208) → durable_signal SKIPPED → block reaches the LUN only via lazy xfsaild → a peer that acquires+cold-reads (FUA/platter) before xfsaild lands it sees the stale platter → loss. Losses ARE early/scattered, consistent.
- Also check the EX-release drain (bast_process Phase 2 for dirs): does it synchronously write + WAIT-completion + blkdev_flush the dir DATA/LEAF blocks before mxfs_v5_dlm_ag_unlock? (Invariant #1.)
- CANDIDATE FIX: drop/loosen the durable_signal `gen>0` gate for a multinode SHARED (peer-reachable, !self_created) dir so EVERY committed dir modify is fenced to the LUN before notify — even at gen==0. Watch RULE-0 perf (the gen>0 gate exists to spare solo rsync ~60s; scope the change to peer-reachable dirs only). Test at N=8 (drc_reliability 8 6) AND re-confirm 4/tcp 12/12 + 2/tcp 17/17 no regress.

### REFUTED this session (don't retry): must-complete acquire barrier (1/5), dir_release_flush_all_done (trans_cancel shutdown), dir_tenure_evict (DABUF shutdown). Build for measurement = 97E09EE8 (adds P6-DIRPATH counters, harmless); shippable = 9AA569A0.
See [[sess6-ccloop-8node-barrier-refuted-release-or-bypass-next]] [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]]</body>
