---
name: sess22-build-1FE2C2DA-reorder-plus-holeskip-144of145-noshutdown
description: sess22(ccloop) HEAD build 1FE2C2DA: reorder-remove + rebuild hole-skip. 8/tcp dir_reuse NO shutdowns, 144/145 or PASS (flaky on round-1 create-visibi…
metadata:
  type: project
---

## sess22 (ccloop) — HEAD build 1FE2C2DA18FD1616914F1BD. KEEP.

= keeper 7B66691E + sess21 diagnostics + TWO sess22 fixes:
1. **Reorder xfs_dir_remove_child non-dir path** (xfs/libxfs/xfs_dir2.c): xfs_dir_removename runs FIRST while trans is CLEAN → -ENOENT (leaf-hash hole) becomes a benign skip, not a dirty-cancel SHUTDOWN. See [[sess22-FIX-remove-reorder-eliminates-dirty-cancel-shutdown]].
2. **Rebuild hole-skip** (xfs/libxfs/xfs_dir2_leaf.c mxfs_dir_rebuild_leaf_from_data): skip db where `bestsp[db]==cpu_to_be16(NULLDATAOFF)` (a freed/hole data block) instead of xfs_dir3_data_read'ing it (→EFSCORRUPTED→dirty-cancel shutdown in xfs_create). Dormant when leaf_rebuild OFF.

## 8/tcp dir_reuse RESULTS (default params, leaf_rebuild OFF):
- NO shutdowns on any node (was 0/8 cascade-shutdown before).
- Run1 = 144/145 (single fail: r1 readdir count exp=800 got=700 — round-1 create-visibility miss, one node's 100 entries missing from node1's DATA view).
- Run2 = PASS 8/8.
- Flaky around the ROUND-1 concurrent-create coherency miss (readdir SHORTFALL = data-block create miss, NOT leaf-hash, NOT phantom-drift).

## leaf_rebuild=1 is a NET NEGATIVE — keep OFF (default 0):
- With leaf_rebuild=1: hit `Metadata CRC error xfs_dir3_data_read_verify block 0x78` (high-entropy garbage on-disk = dir data block double-allocated w/ file data, sess39/42 family) → 4-node shutdown. The aggressive leaf relog appears to expose/trigger the deep dir-data-block on-disk corruption. Without it (default), no CRC shutdowns observed across runs.

## REMAINING 8/tcp dir_reuse BLOCKER (the deep one, 21-sess core):
Round-1 concurrent 8-node create into the fresh shared dir: occasionally ONE node's 100 entries (NF=50 ×2) are MISSING from node1's readdir (got=700/800). = create-phase dir-block lost-update / coherency miss. Flaky (~1/2 runs). NEXT: capture drc-RDMISS missing names + which node + whether durably lost on disk (readdir cold=?) or stale-cached on the reader. The deepest residual = on-disk dir-data-block double-allocation/CRC corruption (rare) exposed under leaf_rebuild.

## NEXT after dir_reuse: must run FULL ./run.sh {1,2,4,8} tcp suites for the criteria (not just dir_reuse). Verify reorder+holeskip fixes don't regress 1/2/4.
