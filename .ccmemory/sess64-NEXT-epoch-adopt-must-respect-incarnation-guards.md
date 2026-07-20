---
name: sess64-NEXT-epoch-adopt-must-respect-incarnation-guards
description: sess64 KEY next-step: epoch-driven genuine_handoff bypasses P33/P43 incarnation keep-stale guards → adopts stale REUSED-inode extent map → bnobt doub…
metadata:
  type: project
---

## sess64 — WHY enabling the epoch adopt shut down with bnobt corruption (the precise next fix)

### Mechanism (RULE 4, code-traced)
`genuine_handoff` in mxfs_dlm_reload_inode (xfs_mxfs_dlm.c ~6848) deliberately **BYPASSES** the P33 dir-grow-revert and P43/P43B fmt-revert keep-stale guards (the code reads `... && !genuine_handoff`). Those guards exist to REFUSE adopting a disk image from a DIFFERENT/older inode INCARNATION. dir_reuse rm-rf+recreates the SAME inode number every round (dirino 131 stable), so the dir inode is constantly freed+reallocated — cross-incarnation.

With the lossy edge-bit handoff, genuine_handoff fired ~58×/run, so the guard bypass rarely hit a cross-incarnation case → rare corruption. The monotonic EPOCH fires the adopt ~270×/run (level-triggered, catches all). That bypasses the incarnation guards far more often → adopts a STALE-incarnation dir extent map → the subsequent rm-rf `xfs_free_ag_extent` frees blocks our in-core bnobt already shows free → `bno+len>gtbno` double-free corruption (xfs_alloc.c:2428), OR `xfs_dabuf_map HOLE` in xfs_create when post_release=0 (extent map points at a freed block).

### THE FIX (next session): make the epoch-driven adopt INCARNATION-AWARE
The disk-superset invariant ("disk strictly contains our work+peer's, safe to adopt") holds only WITHIN ONE INCARNATION. A handoff across a free+realloc is NOT a superset. So:
1. Before letting `genuine_handoff` bypass the P33/P43 incarnation guards, REQUIRE the disk di_gen / i_generation to match (or strictly supersede) our in-core incarnation. If the incarnation differs, this is a reused inode — do NOT epoch-adopt (let the normal iget/reuse path handle it; or fall through to the incarnation guards).
2. Alternatively, only epoch-adopt the DATA-BLOCK CONTENT (invalidate+FUA-reread clean dir data blocks, NO xfs_idestroy_fork rebuild) when disk nextents == in-core nextents (same extent map, only content differs = the single-dirent-loss case). Skip the fork rebuild that churns AG state. This sidesteps bnobt entirely for the common loss.
3. Keep the epoch gated to post_release=true (proven: P64-EPOCH-OBS fires EXCLUSIVELY post_release=1, so no loss of coverage; and post_release=0 adopt = the xfs_create/dabuf-HOLE corruption).

### Current repo state: build 22F1D7BE (on disk) = baseline-equivalent (epoch ADOPT disabled, observe-only P64-EPOCH-OBS). 2/tcp = 13/13 PASS this session (dir_reuse/cache_coherency/crash_consistency all PASS — plumbing non-regressing; run hit harness 480s wall before the last ~4 single-node P1 tests). 4/tcp dir_reuse = 2 dirent-loss rounds, shutdown=0 (same as baseline). 1/tcp unaffected.

### To enable the fix next session: in mxfs_dlm_reload_inode, change the disabled block (search "P64-EPOCH-OBS") to set genuine_handoff=true again BUT add the incarnation check, and gate post_release. Test 4/tcp dir_reuse: expect dirent loss → 0 AND no bnobt/dabuf shutdown. Then verify 2/tcp 17/17 + run 8/tcp. See [[sess64-epoch-plumbing-done-adopt-surfaces-bnobt-corruption]] [[sess64-GPT-design-per-dir-monotonic-epoch-replaces-handoff]].</body>
