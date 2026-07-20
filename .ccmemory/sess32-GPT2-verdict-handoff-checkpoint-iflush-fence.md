---
name: sess32-GPT2-verdict-handoff-checkpoint-iflush-fence
description: sess32: dir_reuse 2/tcp — root (a) extent-revert REFUTED (P32-NXSHRINK only on legit rm). Loss is (b) AG free-space double-alloc OR (c) AG-metadata n…
metadata:
  type: project
---

## sess32 — dir_reuse_coherency 2/tcp: narrowed to AG free-space coherency ((b)/(c)), root (a) REFUTED

### Failure: durable leaf-vs-data inconsistency. dir LEAF index references ~213 names but DATA fork holds only ~120 (one block worth missing) → ~93 names readdir-listed but dirent in NO data block (P26-DSCAN-MISS: test1=20, test2=69) → lookup_fail. Cold-read (drop_caches) ⇒ durable on-disk. Single-writer CLEAN ⇒ cross-node.

### Root (a) [stale iflush reverting dir extent map nx2→1] = REFUTED this session.
Added P32-IFLUSH-NXSHRINK probe (xfs_inode.c, just before xfs_inode_to_disk): fires ONLY on `comm=rm` with `incore_nx=0 incore_size=6 disk_nx=3` = the LEGIT `rm -rf $D` emptying the dir at end-of-round (AFTER the verify already failed). NO non-rm flush writes a smaller extent map over a larger one. So the extent-map is not reverted by a stale background/reclaim iflush. (KEEP P32 probe; harmless, log-only.)

### Remaining: (b) AG free-space DOUBLE-ALLOC or (c) AG metadata not durable/coherent at the dir handoff.
- The dir EX RELEASE drain (mxfs_dlm_bast_process) DOES flush the full dir-INODE closure: xfs_log_force(SYNC) + mxfs_dir_flush_data_blocks (flushes ALL data-fork extents = data+leaf+node blocks) + mxfs_ail_drain_inode_sync (dinode) + blkdev_issue_flush. So inode+data+leaf ARE durable at release.
- The GAP (GPT-5.5 #1): the dir-grow's BLOCK ALLOCATION modified the AGF/bnobt/cntbt of some AG, and that AG free-space is coordinated by the SEPARATE AG-DLM, not the inode-DLM. If node B's cached AG free-space is stale vs node A's allocations (AG-DLM coherency gap on TCP), node B's dir-grow allocates a block node A already used for its dir data → xfs_dir3_data_init zeroes node A's committed data block → entries vanish from DATA, persist in LEAF → P26-DSCAN-MISS. P31E (data_init zeroing a live owner=131 block) is consistent but AMBIGUOUS (names+daddrs reused per round → can't tell current vs prior-incarnation by name).

### NEXT (RULE 4 — prove (b) AG double-alloc, then fix the AG free-space coherency):
1. Decisive (b) probe: at xfs_dir3_data_init, query whether the daddr being allocated is marked FREE in the AG bnobt/cntbt (it should be free for a legit new block). If the allocator handed out a block the bnobt says ALLOCATED, or a block currently mapped by THIS dir's in-core extent map at another lblk → double-alloc CONFIRMED. (Alternatively stamp dir blocks with i_generation to disambiguate reuse.)
2. If (b): the fix is in the AG free-space cross-node coherency — ensure node B's AGF/bnobt is current (drain on AG release + invalidate/reload on AG acquire) so a grow never allocates an in-use block. Prior AG-free-space fixes: sess42 (C6970FF9 b_mxfs_ag_gen), sess43 (BB54A138 in-AIL AG-meta not discarded), sess24/47. This dir-block-grow case may be uncovered on TCP. See subsystem doc xfs.md (bast_work_fn drain pipeline, pag_mxfs_alloc_buflist, _XBF_MXFS_ALLOC_QUEUED).
3. GPT (c) fallback fix: extend dir EX release to also flush the AGF/bnobt buffers for AGs touched by the dir's block allocs (cross-domain). Risk: xfs_ail_push_all_sync DEADLOCKS (awareness Invariant #1) — use targeted per-buffer bwrite, not whole-AIL push.

### CAUTION: the publish-at-create fix this session SHUT DOWN the FS (xfs_create trans_cancel). Delicate-path fixes can corrupt — TEST each + watch for shutdown; keep tests/drc_single_node.sh as the single-node regression guard (must stay CLEAN). [[sess32-reused-dir-dualEX-gap-sync-publish-fix]] [[sess42_lessons]] [[sess47_lessons]]
