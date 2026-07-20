---
name: sess68-LEAD-evict-data-blocks-never-runs-EVDECIDE0
description: sess68 SHARP LEAD: P68-EVDECIDE=0 — mxfs_dir_evict_data_blocks inner loop NEVER iterates for the minimal-repro dir → block0 never evicted before RMW…
metadata:
  type: project
---

## sess68 SHARP LEAD (relay boundary) — modify-path data-block evict never runs (EVDECIDE=0)

### Probe: P68-EVDECIDE (xfs_mxfs_dlm.c, always-on, inside mxfs_dir_evict_data_blocks' per-block loop, just before the undurable/keep decision). Logs every data-block evict decision for a multinode dir.

### RESULT on the MINIMAL repro (`DRC_NFILES=3 DRC_ROUNDS=12 ./run.sh 4 tcp dir_reuse_coherency`, build A81DB821, floods gated off): **P68-EVDECIDE total=0 on ALL 4 nodes.** The evict loop NEVER iterates a block for this dir across the whole failing test.

### IMPLICATION: a node never evicts block0 before its RMW on the single-block dir → it RMWs whatever is cached (potentially a stale base) → the durable single-entry lost-update. This is the most concrete lead yet for the 4/tcp residual.

### WHY total=0 — candidates for next session to check (RULE 4):
1. **mxfs_dir_evict_data_blocks returns EARLY**: for SHORTFORM it `return true` (line ~2241, `else if (if_format != EXTENTS) return true`); for BTREE-needs-iread it returns false. If the 24-entry tiny dir is actually SHORTFORM (not block — 4×3×2=24 entries; depends on inode literal-area size, may still be shortform if inode size is large), the loop never runs and the lost-update is a SHORTFORM-dir lost-update, not a block one. CHECK: is the dir shortform or block? (force_block=1 forces block at mkdir, but verify the REUSED dir after rm-rf+recreate is actually block — P62-DATAINIT-BLK0 fired at mkdir in 50-file runs, suggesting block; confirm for the 3-file case via P62-SF2BLK / the dir format at modify).
2. **modify_refresh not reaching evict_data_blocks**: the prelock `mxfs_dlm_dir_modify_reload_prelock` returns early at `if (dp->i_dlm_mode == MXFS_LOCK_EX) return;` (line ~3143) — but that's the PRELOCK (reload), not evict_data_blocks (which is in mxfs_dlm_dir_modify_refresh). Confirm modify_refresh is called and reaches the evict for a cached-EX holder.
3. If the dir IS shortform: the shortform-dir cross-node lost-update (sess84/sess14 3-way-merge territory) is the root for the minimal repro — the inline dirents in the dinode are RMW'd from a stale base. The shortform merge (mxfs_dir_sf_3way_merge) / reload-on-acquire must be the fix locus. NOTE 2/tcp passes, so the 2-node shortform merge works; 4-node breaks it.

### CONFIRMED next-session repro (fast, simple): `DRC_NFILES=3 DRC_ROUNDS=12 ./run.sh 4 tcp dir_reuse_coherency` FAILS (~313s, slow=separate RULE-0 concern). Reduce probe flood (P68-DWR/DATAINIT/GROWREL now gated behind mxfs.dirwr; P68-EVDECIDE always-on). dmesg ring rotates under many probes + the per-run dmesg -c; for clean capture keep probes minimal AND consider DRC_ROUNDS=6.

### Whole sess68 carry-forward: gap-B FIXED+KEEP (extent-map durability at release, P68-GROWREL DURABLE 48/48). Refuted: extent-map divergence (MAPDIVERGE=0), cached-block survival (drop_caches), read-side stale/target-cache (fua_disable=0 still fails → write-side). BOUND: single-block dirs fail (no grow needed). Build HEAD `A81DB821` (gap-B + EVDECIDE always-on + other probes gated behind mxfs.dirwr; MAPDIVERGE/owner-evict gated off). Shipped-proven baseline 91962D4A. CRITERION NOT MET. Cluster healthy test1-4 mounted. [[sess68-BOUND-single-block-dir-fails-simplest-repro]] [[sess68-FUA-refutes-readside-loss-is-writeside-same-incarn]]</body>
