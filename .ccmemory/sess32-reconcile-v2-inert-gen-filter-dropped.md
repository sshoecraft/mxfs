---
name: sess32-reconcile-v2-inert-gen-filter-dropped
description: sess32: PROVED v2 reconcile gen-filter inert (P31=0 vs SKIP flag 160-270x). Dropped gen-filter → broad reconcile, build F36166BE, testing.
metadata:
  type: project
---

## sess32 — v2 reconcile was INERT; dropped the gen-filter

### PROVEN (RULE 4, live dmesg with dirwr=1)
Build 8E4B6D08 v2 `dir_stale_reconcile=1`: **P31-RECONCILE fired 0×** across all 8 nodes during a full dir_reuse 8/tcp round, while the SKIP-branch flag-set (`P-DE-BLK disp=SKIP leaf=0`, sets MXFS_IF_DIR_DATA_STALE) fired **160-270×/node**. So the reconcile RAN (flag consumed) but its Phase-1 read-filter `dbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen` matched NO in-core block → stale_blk=0, did nothing.

### Why the gen-filter is wrong
The SKIP flag-set condition (block kept stale at acquire: in-AIL-undestaged / pinned) and a per-block gen mismatch do NOT coincide at reconcile time: between the acquire SKIP and the create-time reconcile, the block is re-read + re-stamped to current dir_gen (xfs_da_btree.c:3426 stamps `b_mxfs_dir_gen=i_dlm_dir_gen` on read), so bgen==dir_gen at reconcile even though the on-disk block carries a peer add we lack. NOTE: P31-RECONCILE print gates on param `dirwr` (mxfs_dirwr_enabled), NOT `dir_writeprobe` — set `dirwr=1` (runtime-writable 0644) to see it.

### FIX (build F36166BE, testing)
xfs/xfs_mxfs_dlm.c mxfs_dir_reconcile_stale_data_blocks Phase-1: dropped the `b_mxfs_dir_gen != i_dlm_dir_gen` clause → reconcile EVERY cached DONE DATA/BLOCK dir block (FUA-read + lookup-guarded re-add, fully idempotent). Cost bounded: flag is test_and_clear'd so reconcile runs ~once per EX reacquire (per tenure), ~6 FUA reads (800-entry dir). Gated dir_stale_reconcile (default 0).

### Validating now
Loop: `tests/tcp/drc_repro_loop.sh 5 "dir_stale_reconcile=1 dirwr=1 dir_writeprobe=1" 24`. Expect P31-RECONCILE with re-added>=1 AND no loss. Then A/B reconcile=0 must lose; then make default + full 8/tcp ×3. [[sess31-IMPL-stale-block-reconcile-fix-needs-validation]]
</body>
</invoke>
