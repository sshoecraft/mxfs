---
name: sess17run-MILESTONE-dgshadow-LRU-fixes-dataloss-newresidual-timeout-leaf
description: sess17(ccloop) MILESTONE: dg_shadow LRU eviction (dlm.c) makes cross-node handoff RELIABLE → dir_reuse data-block lost-update ELIMINATED (RDMISS=0).…
metadata:
  type: project
---

## sess17 (ccloop) MILESTONE — handoff under-fire ROOT found & fixed

### ROOT of the 80%-handoff-under-fire (the multi-session core wall)
`dg_shadow` (dlm/dlm.c) — the master-side table that computes the cross-node EX-handoff bit + per-resource epoch — is a fixed array (DG_SHADOW_N=512) walked by LINEAR SCAN per grant. Its eviction recycled the FIRST INACTIVE slot. dir_reuse creates ~800 file inodes/round; between two consecutive grants of the HOT shared dir inode (briefly inactive), those 800 file-inode grants RECYCLED its slot → last_owner LOST (handoff under-fires) AND epoch reset to 0 (level-triggered epoch goes backwards → grantee never adopts). BOTH reliable handoff signals corrupted → the dir reload under-fired → stale-base RMW → durable lost-update.

### FIX (dlm.c, builds CA23BB74=N1024 / 544A912E=N512): LRU eviction
Added `last_grant_seq` (monotonic, ++ per grant) to dg_shadow_ent; evict the inactive slot with the OLDEST last_grant_seq instead of the first. The dir inode is granted ~800×/round (every file create takes parent-dir EX) → its seq is always near the top → never the LRU victim → never evicted → handoff/epoch stay reliable. Keep DG_SHADOW_N small (512) because dg_grant_ex/dg_release LINEAR-SCAN it per grant (N=16384 caused O(N) acquire timeouts).
**RESULT: dir_reuse 8/tcp RDMISS=0 on ALL nodes (was 799/800 every round). The durable DATA-BLOCK lost-update is ELIMINATED.** Combined with fork-adopt [[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]] (which keys dir_ex_handoff on the now-reliable handoff/epoch).

### NEW residual (build with LRU): acquire timeouts + unhealed leaf-hash holes
- acquire timeouts 120-318/node (concentrated on hot-dir masters). NOT from the dg_shadow scan (512 had MORE timeouts than 1024). It's the RELOAD STORM: reliable handoff → fork-adopt reload (FUA dinode read + drain_evict cold-read) fires on EVERY cross-node handoff, and the workload ping-pongs the dir EX ~800×/round → reload per acquire → slow → 120s acquire timeouts (RULE-0). fork-adopt-only (9AF854E6, no LRU) had NO timeouts but had the data loss.
- P21H-LEAFHOLE fires (leaf-hash holes) and P22-DATASCAN-HIT heal = 0 (healer not firing — likely lookups time out before healing, OR a genuine leaf-block staleness the data-fork reload doesn't cover). This is the actual ckeq failure (leaf-hash lookup_fail) at round 5-9.

### NEXT: make the per-handoff response CHEAP (the reload storm is the cost of strong per-dir coherency under 8-node EX ping-pong). Options: (a) lighter per-handoff refresh (evict dir blocks lazily via read-path, skip full xfs_inode_from_disk when extent map unchanged); (b) MHT batching (hold dir EX longer per node → fewer handoffs); (c) fix leaf coherency (leaf-rebuild from coherent data) so lookups don't datascan-storm. Verify 2/tcp full suite still passes with the LRU build (must not regress). Builds: CA23BB74 (N1024 LRU, reached round 9), 544A912E (N512 LRU). Criterion NOT met.</body>
