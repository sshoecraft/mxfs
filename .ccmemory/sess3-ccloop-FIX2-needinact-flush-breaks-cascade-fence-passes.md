---
name: sess3-ccloop-FIX2-needinact-flush-breaks-cascade-fence-passes
description: sess3(ccloop) FIX2 build 24EDC1F3: create_needinact_flush breaks the 2/tcp cascade — IGET_CREATE on NEED_INACTIVE reused inode → inodegc_flush+EAGAIN…
metadata:
  type: project
---

## sess3 (ccloop) FIX2 — build 24EDC1F369E957AFB36E3F7 (KEEP). The 2/tcp cascade is FIXED.

### THE FIX (xfs/xfs_icache.c, xfs_iget_cache_hit ~line 866, gated `mxfs_create_needinact_flush` default 1):
When an IGET_CREATE finds an in-core inode still `XFS_NEED_INACTIVE` with `nlink==0`, upstream returns -ENOENT ("unlinked inodes cannot be re-grabbed"), which fatally cancels an already-DIRTY xfs_create trans → shutdown. The fix: for a multi-node CREATE, `goto out_inodegc_flush` (queue inodegc + return -EAGAIN → retry) instead — the pending inactivation completes and the inode recycles cleanly. Param defn in xfs_mxfs_dlm.c after dir_keep_middle_block.

### PROVEN (RULE 4): probe P-CR3-NEEDINACT fired 10× (the reused-while-NEED_INACTIVE race DID occur) but was handled gracefully → NO P-CR3-CANCEL, NO shutdown. `./run.sh 2 tcp dir_reuse_coherency fence_during_write` → BOTH PASS (was dir_reuse PASS / fence FAIL cascade). Root confirmed = the sess3-CASCADE ENOENT site was line 869. See [[sess3-ccloop-CASCADE-root-reused-inode-iget-ENOENT-create-dirty-cancel]].

### TWO FIXES THIS SESSION (both KEEP, both in build 24EDC1F3):
1. `mxfs_dir_keep_middle_block` (xfs_dir2_leaf.c:2252) — dir torn-map → dir_reuse 4/8 PASS. See [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]].
2. `mxfs_create_needinact_flush` (xfs_icache.c:866) — reused-inode create ENOENT cascade → fault tests PASS.
Both need `MXFS_EXTRA_MODARGS='dir_force_block=0'` (force_block default still 1 in source).

### VALIDATING NOW: full ./run.sh 2 tcp force_block=0 build 24EDC1F3 — expect 17/17.
### NEXT: full 4/tcp + 8/tcp suites; 1/tcp tooling (online_resize, dkms_install stale dumps); bake force_block default 1→0; drop force_block modarg once default flipped.
### Probes left in tree (harmless): P-CR3-CANCEL (xfs_inode.c out_trans_cancel), P-CR3-NEEDINACT (xfs_icache.c).
See [[sess3-ccloop-FINAL-status-table-all-columns]]
