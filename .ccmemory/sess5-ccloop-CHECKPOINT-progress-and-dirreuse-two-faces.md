---
name: sess5-ccloop-CHECKPOINT-progress-and-dirreuse-two-faces
description: sess5(run6614) CHECKPOINT build 3EF92062: 2/tcp=17/17 solid. 4/tcp=13/17, blocker=dir_reuse ~20% flaky w/ TWO faces (EX-holder cold-read shutdown + n…
metadata:
  type: project
---

## sess5 (run 6614) CHECKPOINT — build 3EF92062

### Column status (tree default force_block=1, all fixes KEPT):
- **1/tcp**: not re-run yet (expect tooling residuals: online_resize/dkms_install/fault_io_error — orthogonal to DLM).
- **2/tcp = 17/17 ✓ SOLID** (salvage fix, build 59784327). cache_coherency + soak + dir_reuse all PASS.
- **4/tcp = 13/17**: cache_coherency now 4/4 ✓. FAIL: dir_reuse_coherency (~20% flaky) + fault_netpartition/fence_during_write/tcp_dlm_scaling (3/4 each — CASCADE from dir_reuse's node-shutdown face).
- **8/tcp**: unrun.

### dir_reuse_coherency has TWO distinct failure faces (build w/ salvage 59784327):
1. **SHUTDOWN face** (cascades): `xfs_dir3_data_verify` fail on daddr=120 (dir131 block0) → node4 shuts down → 3 tests cascade. This is the EX-holder cold-reading a reused block0's stale disk. My original salvage (in xfs_da_read_buf) sits inside a gate SKIPPED when the creating node holds EX (owned_ex=1) → missed this. FIX just added (build 3EF92062): standalone owned_ex-INDEPENDENT salvage that restores XBF_DONE on any undestaged self-owned dir DATA block before the read. Probe P5-UNDEST-SALVAGE-EX.
2. **readdir-UNDERCOUNT face** (no shutdown): readdir=300 exp=400, lookup_fail=0 = 100 dirents DURABLY LOST. This is the sess52 node-addname stale-epoch RMW clobber: addname free-index search reads a stale-epoch cached DATA block; the "free" slot is free only in the stale image (peer filled it on disk) → RMW clobbers peer's dirents. Read gate misses because (a) gen-based not epoch-based, (b) xfs_trans_read_buf txn-cache-hit bypasses the gate entirely. See [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]].

### A/B REFUTED: dir_tenure_evict=1 dir_tenure_stale_bypass=1 → 4/5 dir_reuse (no clear improvement; lost-update persists). Epoch-gate lever insufficient — the txn-cache-hit gap remains.

### NEXT: (a) measure if the owned_ex-independent salvage (3EF92062) kills the SHUTDOWN face → recovers 3 cascades → 4/tcp 16/17. (b) Then the readdir-undercount lost-update needs the addname free-index read to be epoch-coherent even on txn-cache-hit (hook xfs_dir2_node_addname / xfs_dir2_data_use_free, not just xfs_da_read_buf). 8/tcp + 1/tcp after.
See [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]] [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]]
