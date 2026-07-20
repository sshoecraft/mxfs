---
name: sess33-PROVEN-ROOT-inode-data-block-double-alloc
description: sess33: dir_reuse 2/tcp root = data-over-inode-cluster (block double-ownership). sess30/55 = M2 stale-extent-map (NOT allocator M1, but cross-node M1…
metadata:
  type: project
---

## sess33 ROOT — dir_reuse_coherency 2/tcp = data-over-inode-cluster (block double-OWNERSHIP)

### PROOF (unambiguous): xfs_inode_buf_verify EFSCORRUPTED at inode cluster 0xc40; buffer = RANDOM
urandom file data, no "IN" magic. P26-IGET-FAIL inum=3136..3143 (==0xc40) = the exact .md5 files
(node1_f43..f50) that fail stat. A file's DATA block and an inode cluster share a daddr.

### THIS IS SESS30/SESS55 TERRITORY — read [[sess30-FACEC-bnobt-double-alloc-deep-dive]] +
[[sess55-faceB-is-M2-stale-bmap-not-allocator]] FIRST next session. Their conclusion:
- M1 (INTRA-node allocator double-alloc): RULED OUT — P55-ALLOC-OVER-INODE ring + P55-ALLOC-OVER-
  CACHEDINODE both 0× (xfs/libxfs/xfs_alloc.c ~4092). Those CANNOT see a PEER's inode chunk.
- M1 CROSS-node allocator double-alloc: NOT fully ruled out — the on-disk plain-read check
  (P55/P33-ALLOC-OVER-DISKINODE) was removed for perf. **sess33 re-added it but EVERY-alloc sync read
  TIMES OUT the test (RULE 0, ~19k reads holding AGF → 300s no-result). REVERTED.** Need a CHEAP
  variant (see NEXT).
- M2 (stale extent-map mis-WRITE): the leading theory — a node's in-core dir/file extent map points
  at a reused daddr now backing an inode cluster; the write lands urandom over the cluster. File-data
  writes BYPASS the xfs_buf metadata chokepoint, so metadata-buffer guards can't catch it.

### sess33 NEW EVIDENCE for M2: P62-RELOAD-FORK-SHRINK ino=131 **incore_nx=1 incore_size=4096 (stale
BLOCK-format) vs disk_nx=3 disk_size=8192 (correct LEAF)**, post_release=1 — test1's in-core dir
inode is stale-SMALL while disk is correct-large (the reload then grows it; benign WHEN it runs).
And **P26-RDDIR ino=131 ... reload_armed=0** while dir_gen advanced (5,18) — the cross-node
MXFS_IF_DIR_RELOAD signal is NOT armed, so modify/consumer reload may not fire → stale extent map
used → FMT_BLOCK mis-decision (dir3_block_verify 0x78 face) or mis-write (data-over-cluster face).

### AG COHERENCY AUDIT (sess33) — both sides look correct, so M1-cross-node is less likely than M2:
- READ: TCP mxfs_v5_dlm_ag_read_generation=-ENODEV → acquire bumps pag_dlm_meta_gen UNCONDITIONALLY
  (xfs_mxfs_dlm.c ~12091) → read hook (mxfs_ag_meta_invalidate_stale, called from xfs_alloc.c:3733,
  xfs_ialloc.c:3171, xfs_btree.c:1420) FUA-re-reads bnobt every acquire. b_tenure_id is MODIFY-time
  (sess125), not read-time.
- RELEASE: mxfs_dlm_ag_drain_meta_buffers (12465) drains AGF/AGI/bnobt/cntbt/inobt; called at
  release (~13980/14008) + deferred release_work_fn (15235) w/ blkdev_issue_flush before unlock.

### EXTREME VARIANCE: each run a different face — data-over-inode-cluster(0xc40) shutdown / dir3_block_
verify(0x78) shutdown / lookup_fail(stale leaf) / hang(no-result). Run MULTIPLE times before concluding.

### NEXT (RULE 4), in priority order:
1. CHEAP cross-node M1 check: instead of per-alloc disk read, keep a per-AG ring/bitmap of daddrs THIS
   node FREED this round (xfs_free_extent/xfs_bunmapi) and cross-ref at alloc — OR check only the
   cluster-START block once per allocation (not every block) + ratelimit the read. If P33-ALLOC-OVER-
   DISKINODE fires → cross-node alloc double-alloc → fix AG free-space coherency. If 0 → M2.
2. M2 fix: the reload_armed=0 gap — make the dir reload (extent-map rebuild) fire reliably for the
   reused/grown dir WITHOUT depending on the flaky MXFS_IF_DIR_RELOAD heartbeat flag (e.g. arm on
   i_dlm_dir_gen advance, or unconditional reload for the shared dir on modify/lookup).
3. sess30 SOUND FIX candidate (both faces): EVICT-ON-FREE — on xfs_free_extent/xfs_bunmapi, xfs_buf_stale
   any cached buffer at the freed daddr cluster-wide so no stale buffer/extent survives reuse.

### State: tree CLEAN/BUILDABLE (DBD3A375). Probes left: P33-DSCAN-ONDISK (ratelimited, xfs_dir2_leaf.c),
P33-FROMDISK/TODISK-DIRSHRINK (xfs_inode_buf.c), P33-DIRGROW-REVERT-SKIP reload guard (xfs_mxfs_dlm.c,
NO-OP fires 0× — candidate revert). alloc.c probe REVERTED. tests/reset2.sh = virsh reboot both VMs
before EVERY run (D-state unmount wedge). [[sess33-dirreuse-faces-and-instrumentation-lessons]]
</body>
