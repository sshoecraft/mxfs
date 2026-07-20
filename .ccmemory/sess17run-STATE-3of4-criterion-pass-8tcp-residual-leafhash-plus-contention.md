---
name: sess17run-STATE-3of4-criterion-pass-8tcp-residual-leafhash-plus-contention
description: sess17(ccloop) STATE OF PLAY: 3 of 4 criterion node-counts PASS (1/tcp 16/16, 2/tcp 17/17, 4/tcp 17/17). Only 8/tcp left. Build 544A912E KEEP. 8/tcp…
metadata:
  type: project
---

## sess17 (ccloop) STATE OF PLAY — biggest progress in many sessions

### CRITERION: 3 of 4 node-counts now PASS (full ./run.sh <N> tcp), build 544A912E9356E96A39F24E2:
- **1/tcp = 16/16 ✅**
- **2/tcp = 17/17 ✅**
- **4/tcp = 17/17 ✅** (was failing in-suite on the inherited build; the dg_shadow LRU fix RESOLVED it)
- **8/tcp = FAIL** (dir_reuse_coherency only; the rest cascade from it)

### The two KEEP fixes that got here (do NOT revert):
1. **dg_shadow LRU eviction** (dlm/dlm.c, DG_SHADOW_N=512 + last_grant_seq): makes cross-node EX-handoff signal RELIABLE (the hot dir inode's master-table slot is never recycled by the ~800 file-inode grants/round). ELIMINATED the dir_reuse DATA-block lost-update (was 799/800 lost EVERY round for 100+ sessions → now RDMISS=0 at mht≥150).
2. **fork-adopt** (xfs_mxfs_dlm.c): fast-path dir reload post_release=dir_ex_handoff on the now-reliable handoff. See [[sess17run-MILESTONE-dgshadow-LRU-fixes-dataloss-newresidual-timeout-leaf]] [[sess17run-FINAL-mht-tradeoff-improved-by-LRU-next-close-lowmht-residual]].

### 8/tcp residual — TWO remaining sub-blockers (both at 8 nodes only; 4 nodes fine):
1. **Leaf-hash lost-update** (P21H-LEAFHOLE=400, P22-DATASCAN-HEAL=0, P26-DSCAN-MISS): an entry is in the data block but its hashval is durably dropped from the LEAF index — a node RMWs a STALE leaf base (the leaf is a separate dir block; the fork-adopt/LRU fixed the DATA block but not the leaf's content-level RMW). dir_leaf_rebuild=1 fires (P26-REBUILD-OK) but does NOT close the holes (once-per-tenure rebuild insufficient under rapid 8-node handoffs; or the rebuild itself RMWs a stale leaf). THE leaf needs the same reliable-handoff coherence the data block got — evict/cold-read the LEAF block on genuine handoff (it IS in the extent map / drain_evict, but kept when undestaged). NEXT: apply the reliable-handoff leaf eviction/rebuild so the leaf hash index is reconstructed from coherent data EVERY handoff, not once per tenure.
2. **Hot-dir-master EX contention/starvation**: at mht=300 RDMISS=0 but P36-RETRY storm on ino=131 → 120s hard timeout → force_shutdown on the NODES THAT MASTER ino 131 (test1/test2, hash-distributed) → ~67s/round slowness (RULE-0). Lower mht (50-150) is faster (round 8-15) and avoids most shutdowns but reintroduces a SMALL data loss (RDMISS 2-7 at mht=50) and the leaf holes persist. The hot-dir master is a DLM scaling bottleneck (single master handles all grants for the hot resource + participates). NEXT: reduce master load / anti-starvation in the DLM grant queue, OR close the low-mht residual so a fast mht works.

### mht sweet-spot search (8/tcp dir_reuse focused, LRU build): mht=300 → RDMISS=0 but starve/shutdown/slow (round 6); mht=150 → RDMISS=0, no shutdown, but leaf holes + acqTO=236 on masters (round 5-8); mht=50 → fast (round 15) but RDMISS=2-7 + shutdown. Default kept at 300.

### Reboot ALL clean between runs. DRC_STREAM=1 + tests/tcp/drc_cap for NFS capture. Criterion NOT met (3/4); marker NOT written.</body>
