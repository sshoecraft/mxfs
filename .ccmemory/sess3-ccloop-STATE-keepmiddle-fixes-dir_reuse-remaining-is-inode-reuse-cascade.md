---
name: sess3-ccloop-STATE-keepmiddle-fixes-dir_reuse-remaining-is-inode-reuse-cascade
description: sess3(ccloop) STATE: build 5726D17A keep_middle fix → dir_reuse 4/8 PASS, 2/tcp 14/17. Remaining 2/tcp blocker = inode-reuse DLM EAGAIN cascade (crea…
metadata:
  type: project
---

## sess3 (ccloop) — STATE after the keep_middle_block breakthrough. Criterion NOT met; marker NOT written.

### BUILD 5726D17A42642B8F8E629CE (KEEP, deployed /src/mxfs/mxfs.ko). Run all tests with `MXFS_EXTRA_MODARGS='dir_force_block=0'` (force_block default is still 1 in source; keep_middle default is 1).

### CONFIRMED PASSING (build 5726D17A, force_block=0):
- **dir_reuse_coherency 4/tcp = 4/4, 8/tcp = 8/8** (within 480s budget, default mht). THE multi-session blocker — SOLVED by keep_middle_block. See [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]].
- Full ./run.sh 2 tcp = **14/17 PASS**: precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, dir_reuse_coherency, soak.
- fence_during_write 2/tcp **PASSES STANDALONE** (2/2).

### REMAINING 2/tcp BLOCKER = INODE-REUSE DLM EAGAIN CASCADE (3 tests: fence_during_write, fault_netpartition, tcp_dlm_scaling all FAIL 1/2 in full suite):
- PROVEN cascade (RULE 4): `./run.sh 2 tcp dir_reuse_coherency fence_during_write` → dir_reuse PASS, fence_during_write FAIL. But fence_during_write ALONE = PASS. So dir_reuse's massive create+rm-rf churn leaves freed inode numbers with STALE peer DLM state; the next test's xfs_create reuses those inodes and the EX acquire returns **rc=-35 (EAGAIN)**.
- Failure mechanism: node2 dmesg = `mxfs: DLM inode lock failed: ino=NNN mode=5 rc=-35` (mode 5=EX) → `xfs_create+0x708 → xfs_trans_cancel at xfs_trans.c:1060 (trans already DIRTY from xfs_dialloc) → Corruption of in-memory data (0x8) → Shutting down filesystem`. You cannot cancel a dirty trans → fatal.
- Emit: dlm/v5_mount.c:1286 (mxfs_v5_dlm_inode_lock, flags=0 → NOQUEUE-ish, returns EAGAIN immediately on peer contention). A RETRY variant exists: `mxfs_v5_dlm_inode_lock_retries` (dlm/v5_mount.c:1311, sess58, TCP only) used by the inode-acquire slow path to break the inode<->AG ABBA deadlock.
- LIKELY FIX: a freshly xfs_dialloc'd inode (allocated free from an AG WE hold) CANNOT be legitimately held EX by a peer — any peer lock is STALE (prior incarnation, different di_gen). So the new-inode EX acquire in xfs_create/xfs_icreate must RETRY/BLOCK (or force-steal) instead of failing EAGAIN into a dirty-trans cancel. Trace mxfs_dlm_ilock_begin (the ILOCK acquire) and make the create-path/new-inode acquire use the retry variant or force-grant. (sess58 fixed a RELATED ABBA deadlock the same way — retry variant.)
- NOTE: sess58 (build 60EFBE5E, 9d ago) had 2/tcp 17/17 incl. these 3. So this cascade REGRESSED since sess58, OR is exposed only after dir_reuse's heavier churn.

### NOT YET VALIDATED (next session):
1. Fix the inode-reuse EAGAIN cascade → full 2/tcp 17/17.
2. Full 4/tcp + 8/tcp suites at force_block=0 (verify no OTHER regression; dir-heavy = rsync_paired, crash_consistency).
3. 1/tcp suite (single node, trivial).
4. BAKE force_block default 1→0 (xfs_mxfs_dlm.c:6560) + rebuild → clean `./run.sh N tcp` (no modarg) records PASS in criteria.json → criterion.
5. Verify dir_reuse 8/tcp doesn't need the node-format keep-middle (xfs_dir2_node.c:1387) — 8/8 PASS suggests not.

### Reset infra: `scripts/ccloop_reset.sh <N>`. Criterion = all tcp-applicable tests PASS at 1/2/4/8 in criteria.json (the recorded 4/8 PASSes are STALE older-build — must re-validate with current build).
See [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]] [[sess58-FIX-create-remove-AG-dir-ABBA-deadlock]]
