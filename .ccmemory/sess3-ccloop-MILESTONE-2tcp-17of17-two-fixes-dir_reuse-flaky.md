---
name: sess3-ccloop-MILESTONE-2tcp-17of17-two-fixes-dir_reuse-flaky
description: sess3(ccloop) MILESTONE build 24EDC1F3: full ./run.sh 2 tcp = 17/17 PASS (force_block=0). Two fixes: keep_middle_block + create_needinact_flush. dir_…
metadata:
  type: project
---

## sess3 (ccloop) MILESTONE — full ./run.sh 2 tcp = 17/17 PASS. Build 24EDC1F369E957AFB36E3F7 (KEEP). Criterion NOT yet met (flaky + 4/8/1 columns).

### CONFIG: `MXFS_EXTRA_MODARGS='dir_force_block=0'` + two new default-on fixes:
1. `mxfs_dir_keep_middle_block` (xfs_dir2_leaf.c:2252) — dir torn-map (dir_reuse corruption/shutdown). See [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]].
2. `mxfs_create_needinact_flush` (xfs_icache.c:866) — reused-inode CREATE ENOENT cascade (fence_during_write/fault_netpartition/tcp_dlm_scaling). See [[sess3-ccloop-FIX2-needinact-flush-breaks-cascade-fence-passes]].

### RESULT: `./run.sh 2 tcp` (force_block=0) = **17/17 PASS** on a clean run. Recovers the sess58 milestone. All fault/scaling tests pass (cascade fixed); all coherency tests pass.

### REMAINING ISSUE — dir_reuse_coherency 2/tcp is FLAKY:
- One full-suite run: dir_reuse FAILED 0/2 "leaf-hash lookup_fail(exp=0 got=1)" rounds 16-20 (single-dirent read-side miss). Standalone re-run: PASS 2/2. Full-suite re-run: PASS 2/2 (17/17). So ~1-in-2-3 in-suite flake.
- This is the KNOWN residual single-dirent-loss (leaf-hash hole / write-side) that 90+ sessions battled. keep_middle fixed the deterministic CORRUPTION/shutdown; a rare single-dirent-loss remains. Possibly a keep_middle/leaf-hash reuse interaction (new dirent added to a REUSED empty middle-block whose leaf-hash entry is cross-node-incoherent) — investigate: does the flake rate change with keep_middle=0 (but keep_middle=0 reintroduces 4/8 corruption)? OR it's the pre-existing epoch/write-side residual independent of keep_middle.
- For reliable 100%, this flake must be closed. It's now RARE (not deterministic), so needs many runs to characterize rate + a targeted read-side leaf-hash-heal or write-side serialization fix.

### NEXT (priority):
1. Characterize dir_reuse 2/tcp flake rate (run full 2/tcp ~5-8× consecutive; count dir_reuse failures). Then fix the leaf-hash residual.
2. Full 4/tcp + 8/tcp suites (needinact fix should fix their fault-test cascades too). dir_reuse 4/8 already PASS with keep_middle.
3. 1/tcp: online_resize (resize_mxfs tool), dkms_install (clean tests/tcp/loss_cap2/*.txt 80MB + /var/crash/mxfs.0.crash).
4. Bake force_block default 1→0 (xfs_mxfs_dlm.c:6560) → clean `./run.sh N tcp` records criteria.json PASS.

### Probes in tree (harmless): P-CR3-CANCEL, P-CR3-NEEDINACT. Reset infra: scripts/ccloop_reset.sh <N>.
See [[sess3-ccloop-FINAL-status-table-all-columns]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]
