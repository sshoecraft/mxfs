---
name: sess37-FINAL-state-bnobt-doublefree-is-severest-AG-root
description: sess37 FINAL: clean baseline build A695EC5C. dir_reuse 2/tcp flaky across 3 modes (data loss / leaf hole / bnobt double-free SHUTDOWN). All 3 = AG fr…
metadata:
  type: project
---

## sess37 FINAL state — dir_reuse_coherency 2/tcp

**Clean baseline build: `A695EC5C`** (functionally identical to sess36's 4D56CB92 — ONLY adds
diagnostics, all gated behind mxfs.instr: P31E/P31F/P37-STALEBMAP/P37D. No functional change, no
regression. Read-hook bounded-retry reverted.) Timing solved (MHT=300 via MXFS_EXTRA_MODARGS). Marker
NOT written. Criterion (full ./run.sh 2 tcp 17/17) NOT met.

### The test is FLAKY across THREE failure modes — ALL one root (AG free-space + dir-extent coherency):
1. **DATA loss**: readdir short, node1_f1..fN contiguous block-0 entries gone (both nodes).
2. **LEAF-HASH hole**: readdir=200 lookup_fail=N (P21H-LEAFHOLE); leaf-rebuild exists but DISABLED
   (mxfs_dir_leaf_rebuild=0); enabling it fills holes but trips mode 3.
3. **bnobt double-free SHUTDOWN** (PROVEN this session in a NORMAL run, no leaf_rebuild): "Internal
   error ltbno + ltlen > bno at xfs_alloc.c:2254, Caller xfs_free_ag_extent" + EFSBADCRC (err74) at
   xfs_trans_read_buf_map + "!(flags & XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2814" (stale dir
   extent map maps a block to a HOLE) + xfs_group_free xg_ref!=0. This is the classic 37-session
   "Mode A / bnobt double-free" AG free-space corruption.

### Hypotheses REFUTED this session (RULE 4 step 2a — do NOT re-chase):
- P31E datainit clobbers = BENIGN prior-incarnation reuse (on-disk inode shortform at clobber).
- Read-hook bounded-retry (xfs_da_btree.c ~3101): wrong path (gated !owned_ex), P34R-RETRY-OK=0.
- Stale in-core BMAP at modify: P37-STALEBMAP-MODIFY=0 (reload refreshes bmap).
- Evict KEEPS stale undestaged block-0 (FACE A): P37D-KEPT-STALE-DATA=0 (in-core always >= disk).
- Storage durability/FUA: medium COHERENT under EX hold (sess69 differs=0). 2/tcp target = LIO
  write-through.

### So the loss is NOT: datainit clobber, stale bmap, evict-keep-stale, read-hook, or storage. It IS
the AG free-space allocator double-allocating/double-freeing because a node's cached free-space tree
(bnobt/cntbt/AGF + the dir extent map) is inconsistent across the cross-node handoff DESPITE the
fresh-acquire invalidation (mxfs_dlm_invalidate_ag_meta + mxfs_ag_meta_coldread_discard(pag,true) +
pagf reset, xfs_mxfs_dlm.c ~12362). The fresh path LOOKS thorough; the bug is subtler (a specific
buffer/summary slips through, or a non-fresh acquire path — nested/cached/release_pending ~11966-12049
— skips the full invalidation when it shouldn't).

### NEXT SESSION: instrument the bnobt double-free directly.
At xfs_free_ag_extent (the ltbno+ltlen>bno site, xfs_alloc.c:2254) and the allocator, capture the AG#,
the extent being freed/allocated, and whether the cached bnobt/cntbt/AGF disagrees with a coherent
plain-read of the on-disk free-space tree AT THAT MOMENT. That pinpoints which buffer is stale and
whether the acquire was fresh vs cached/nested. Cross-ref P102-ACQ (fresh vs cached/nested/reclaim
acquire) + P117-AGMETA-STALE-CLEAN + pag_dlm_meta_gen freeze. Likely fix: close the non-fresh acquire
gap or add the missing buffer to the fresh discard set (carefully — sess118 reverted generalizing to
AGF/AGI/inobt due to pagf desync; must reset pagf/pagi consistently). See
[[sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root]] [[sess37-NEXT-action-plan-dir-evict-keepguard-and-leafrebuild]].
Tools: tests/drc_cap2.sh (instr off, true-speed); reset nodes between runs if a shutdown leaves a
wedged mount.
