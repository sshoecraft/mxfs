---
name: sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail
description: sess14(ccloop) FIX: dir_reuse round-23 DABUF_MAP_HOLE shutdown = readdir bumped i_dlm_dir_gen BEFORE reload, and reload trylock-bailed → fresh leaf +…
metadata:
  type: project
---

## sess14 (ccloop) — DABUF_MAP_HOLE root + fix (the in-suite dir_reuse 4/tcp residual)

### Symptom
Full in-suite `./run.sh 4 tcp` (build 83CAA038): 16/17 PASS, ONLY dir_reuse_coherency FAIL 0/4. Standalone dir_reuse passed (got lucky). Root: test4 reached round 23/24, stalled ~124s at a barrier (peers grew the dir during the stall), then on the verify-phase readdir hit `XFS (sda): Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at line 2817 of xfs_da_btree.c` (xfs_dabuf_map) → EFSCORRUPTED whole-FS shutdown → test4 absent from subsequent barriers → all nodes time out → NORESULT → 0/4 cascade.

### Root (PROVEN by code path)
`xfs_dabuf_map` maps a dir logical block via `xfs_bmapi_read` against the in-core data-fork EXTENT MAP; a HOLE for a block a leaf entry references → `invalid_mapping` → `!HOLE_OK` → EFSCORRUPTED. In `xfs_readdir` (xfs/xfs_dir2_readdir.c ~695), a non-EX reader with dir_gen>0 BUMPED `i_dlm_dir_gen` (which forces xfs_da_read_buf to re-fetch FRESH leaf/data blocks) and THEN called `mxfs_dlm_reload_inode` (which refreshes the extent map). But reload uses a trylock and can BAIL under contention (leaves i_dlm_stale=true). On a bail: gen already bumped → getdents re-reads a FRESH leaf (references peer's grown block N) while the extent map stays STALE (no mapping for N) → inconsistent in-core view → DABUF_MAP_HOLE shutdown. The 124s stall made the dir grow a lot on peers, maximizing the fresh-leaf/stale-map gap.

### FIX (build 70F91E1B, xfs/xfs_dir2_readdir.c)
Reorder: compute `want_block_refresh` but do the reload FIRST; bump `i_dlm_dir_gen` ONLY if reload SUCCEEDED (i_dlm_stale cleared). On bail, do NOT bump gen — keep leaf+extent map CONSISTENT-stale (at worst a transient readdir miss that self-heals next round; NO hole, NO shutdown, NO cascade). When reload succeeds, bump gen after so leaf/data are re-fetched consistently with the now-fresh map.

### STATE
Validating with a fresh full `./run.sh 4 tcp` (log scratchpad/full4tcp_v2.log). If reload-bail still yields a transient readdir miss (round FAIL without shutdown), next step is a bounded retry of the reload in readdir so the extent map is always refreshed before getdents. Still TODO: 2/tcp, 8/tcp, 1/tcp full suites.
See [[sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix]].
