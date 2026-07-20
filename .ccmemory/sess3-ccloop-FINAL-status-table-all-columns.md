---
name: sess3-ccloop-FINAL-status-table-all-columns
description: sess3(ccloop) FINAL status: build 5726D17A keep_middle fix solved dir_reuse 4/8. Per-column 1/2/4/8 tcp status + prioritized remaining work. Criterio…
metadata:
  type: project
---

## sess3 (ccloop) FINAL — build 5726D17A42642B8F8E629CE (KEEP, deployed). Criterion NOT met; marker NOT written.

### THE SESSION'S WIN: `mxfs_dir_keep_middle_block` fix (xfs_dir2_leaf.c:2252) SOLVED the multi-session dir torn-map blocker → dir_reuse_coherency 4/tcp=4/4, 8/tcp=8/8 (default mht, within 480s). See [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]]. Run everything with `MXFS_EXTRA_MODARGS='dir_force_block=0'` (force_block default still 1 in source; keep_middle default 1).

### STATUS TABLE (build 5726D17A, force_block=0):
- **1/tcp**: 14/16 PASS. FAIL: online_resize (resize_mxfs tool fails), dkms_install (broken by 80MB stale sess13 dump files in tests/tcp/loss_cap2/ + leftover /var/crash/mxfs.0.crash — ENVIRONMENTAL, clean these up). Both are single-node TOOLING tests, orthogonal to DLM.
- **2/tcp**: 14/17 PASS. FAIL: fence_during_write, fault_netpartition, tcp_dlm_scaling — all via the INODE-REUSE DLM EAGAIN CASCADE (see below). Each PASSES standalone.
- **4/tcp**: dir_reuse=4/4, cache_coherency=PASS confirmed. Full suite NOT yet run (expect same 3 fault-test cascade + tooling).
- **8/tcp**: dir_reuse=8/8 confirmed. Full suite NOT yet run.

### REMAINING BLOCKER #1 (biggest) — INODE-REUSE DLM EAGAIN CASCADE:
PROVEN: `./run.sh 2 tcp dir_reuse_coherency fence_during_write` → fence FAILS (passes alone). dir_reuse's create+rm-rf churn frees inode numbers whose peer DLM EX lock LINGERS (cached-until-BAST). Next test's xfs_create reuses the inode, EX acquire returns rc=-35 (EAGAIN). The slow-path acquire loop (xfs_mxfs_dlm.c:15255) retries only 3×/50ms then the path is fatal (either ilock_begin force-shutdown @15384, OR an error return to xfs_create → out_trans_cancel on a DIRTY trans → "Corruption of in-memory data" shutdown). The peer's BAST-release takes >150ms (P34-ACQ-SLOW shows seconds) so 3 retries give up too early.
- CANDIDATE FIX: for a freshly-dialloc'd inode (is_new), the peer's lock MUST be stale (reused number, dead incarnation) and will release on BAST — so extend the retry budget substantially (loop keeps calling mxfs_dlm_yield_basted_cached_ags each iter = ABBA-safe) instead of giving up at 3. OR identify the exact caller (16210/16446/16544 or ilock_begin) that returns -35 to xfs_create and make it block/retry. Trace which acquire returns -35 in xfs_create context (add a probe). Risk: don't reintroduce ABBA hang — the yield mitigates.
- NOTE: sess58 (build 60EFBE5E, 9d ago) had 2/tcp 17/17 incl these 3 → REGRESSED since, or exposed by heavier churn. Unused retry infra exists: mxfs_v5_dlm_inode_lock_retries (dlm/v5_mount.c:1311, NO callers).

### REMAINING #2: online_resize (resize_mxfs tool), dkms_install (clean tests/tcp/loss_cap2/*.txt 80MB + /var/crash/mxfs.0.crash).
### REMAINING #3: run full 4/tcp + 8/tcp suites force_block=0; verify no other regression.
### REMAINING #4 (final): bake force_block default 1→0 (xfs_mxfs_dlm.c:6560) + rebuild → clean `./run.sh N tcp` records PASS in criteria.json.

### CRITICAL: criteria.json's pre-existing "50 PASS" includes STALE older-build records (e.g. cache_coherency 4/8 PASS 06-27 was force_block-different/older — current build must RE-validate). Don't trust recorded PASSes without a current-build re-run.

### Infra: scripts/ccloop_reset.sh <N> (virsh-reboots wedged VMs after corruption-shutdown umount D-state wedge).
See [[sess3-ccloop-STATE-keepmiddle-fixes-dir_reuse-remaining-is-inode-reuse-cascade]] [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]
