---
name: sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS
description: sess3(ccloop) BREAKTHROUGH build 5726D17A: keep-middle-block fix + force_block=0 → dir_reuse 4/tcp 4/4 AND 8/tcp 8/8 (within 480s budget, default mht…
metadata:
  type: project
---

## sess3 (ccloop) — BREAKTHROUGH. Unified torn-map root FIXED. dir_reuse 4/tcp AND 8/tcp PASS.

### Build 5726D17A42642B8F8E629CE (KEEP). New fix: `mxfs_dir_keep_middle_block` (DEFAULT 1, module_param dir_keep_middle_block).

### THE FIX (xfs/libxfs/xfs_dir2_leaf.c, xfs_dir2_leaf_removename ~line 2252):
Stock removename calls xfs_dir2_shrink_inode to free a now-empty data block. For a NON-LAST (middle) block that removes the extent but leaves di_size unchanged → GAP in the data-region extent map (sess49b's PROVEN DABUF_MAP_HOLE torn-map root). FIX: under MULTI-NODE, if `dp->i_disk_size > xfs_dir2_db_off_to_byte(geo, db+1, 0)` (block exists after db = middle), DO NOT shrink — leave it a valid EMPTY data block, mapped, bests[db] all-free; `dbp=NULL; return xfs_dir2_leaf_to_block(...)`. No extent removed → no gap → no cross-node tear. Reused by later adds; freed normally when it becomes the tail. Param defn in xfs_mxfs_dlm.c ~line 5465.

### MEASURED (MXFS_EXTRA_MODARGS='dir_force_block=0', build 5726D17A):
- **dir_reuse_coherency 4/tcp → PASS 4/4** (was 0/4 torn-map FAIL).
- **dir_reuse_coherency 8/tcp → PASS 8/8** WITHIN the 480s run_coord budget at DEFAULT mht=300. (run_coord enforces the timeout as a hard FAIL, so a PASS = within budget. No need for the slow mht=1500 stopgap — satisfies BOTH correctness AND RULE-0.)

### WINNING CONFIG: **force_block=0 + keep_middle_block=1** makes BOTH conflicting tests pass (force_block=0→cache_coherency; keep_middle→dir_reuse). Removes the need for sess67's force_block=1 (which regressed cache_coherency).

### REMAINING TO MEET CRITERION (1/2/4/8 tcp 100%):
1. Full ./run.sh 2 tcp force_block=0 build 5726D17A (RUNNING) — expect 17/17 (fence_during_write hot-dir churn was the SAME middle-block torn-map → should pass now).
2. Full 4/tcp + 8/tcp suites force_block=0 — verify no OTHER test regresses at force_block=0 (most are dir-format-agnostic; dir-heavy = rsync_paired, crash_consistency, cache_coherency).
3. 1/tcp suite (single node, trivial; force_block/keep_middle inert single-node).
4. If 8-node dir hits NODE format (~800 entries), apply same keep-middle to xfs_dir2_node.c:1387 (skip shrink AND xfs_dir3_data_block_free, keep free-index all-free). 8/8 PASS suggests NOT needed (storm dir stayed LEAF).
5. **FINAL**: bake force_block default 1→0 (xfs_mxfs_dlm.c:6560) so clean `./run.sh N tcp` (no modarg) passes natively → rebuild → record into criteria.json → criterion met. (keep_middle already defaults 1.)

### Reset infra: `scripts/ccloop_reset.sh <N>` (virsh-reboots wedged VMs). Build on /src/mxfs/mxfs.ko.
See [[sess49b-BREAKTHROUGH-torn-disk-reload-gate-partial-8tcp]] [[sess3-ccloop-UNIFIED-root-divergent-extentmap-and-forceblock-conflict]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]
