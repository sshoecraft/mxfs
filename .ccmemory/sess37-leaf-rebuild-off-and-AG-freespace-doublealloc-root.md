---
name: sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root
description: sess37 dir_reuse 2/tcp: leaf-hash hole fixable by dir_leaf_rebuild=1 (default OFF) BUT rebuild trips bnobt/inode-cluster double-alloc shutdown. Deep…
metadata:
  type: project
---

## sess37 — dir_reuse_coherency 2/tcp: two faces, shared AG-free-space root (RULE 4)

Continues [[sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit]]. Build this session ended at
3BDA8147 (all heavy plain-read detectors P31E/P31F/P37 now gated behind mxfs.instr — NO functional
change, clean diagnostic baseline). Read-hook bounded-retry REVERTED (was wrong path).

### Hypotheses REFUTED this session (RULE 4 step 2a):
1. **P31E datainit clobbers harmful** — REFUTED. on-disk inode shortform/small at clobber → benign
   prior-incarnation freed-block reuse. (P31F-BMAP disk_fmt=1/disk_nx=0.)
2. **Read-hook bounded retry** (cond_resched on -EAGAIN, xfs_da_btree.c ~3101) — REFUTED. P34R-RETRY-OK=0
   (never recovered); the read hook is gated `!owned_ex` = NON-modify path anyway (lookup/readdir),
   where stale is recoverable by the verify drop_caches. Reverted.
3. **Stale in-core bmap at modify** — REFUTED. Added P37-STALEBMAP-MODIFY (in mxfs_dir_evict_data_blocks:
   coherent on-disk di_nextents vs in-core if_nextents) → fired 0×. The reload refreshes the bmap
   correctly; the loss is a CONTENT RMW with a CORRECT bmap.

### Two distinct FLAKY failure faces (both must be fixed):
- **DATA loss**: readdir short (182/184/187/188), node1_f1..fN **contiguous first** files gone (block-0
  content). Both nodes agree (durable).
- **LEAF-HASH hole**: readdir=200 lookup_fail=N, node's last entries present in DATA but missing from
  the LEAF hash (P21H-LEAFHOLE hv_in_leaf=0, fired 36-400×). STUCK / both nodes.

### KEY: the leaf-hash face has an EXISTING fix that is DISABLED.
`mxfs_dir_leaf_rebuild` (xfs_mxfs_dlm.c:2029, module_param dir_leaf_rebuild) **defaults 0 (OFF)**.
It gates `mxfs_dir_rebuild_leaf_from_data` (consumer xfs_dir2.c:564, armed once-per-tenure via
MXFS_IF_DIR_LEAF_STALE in the evict ~2280 + mxfs_dlm_dir_modify_refresh). The evict KEEPS an undurable
(in-AIL-undestaged) stale leaf (P21S-EVICTSKIP-LEAF 375-1200×) → leaf-hash hole. With the rebuild OFF,
nothing reconstructs the leaf → durable hole.

### BUT enabling dir_leaf_rebuild=1 trips a SHUTDOWN (the deep root surfaces):
Ran `MXFS_EXTRA_MODARGS='inode_mht_ms=300 dir_leaf_rebuild=1'`: P26-REBUILD-OK fired 400×/181× (rebuild
WORKS, fills holes) BUT → **FS SHUTDOWN**: "Metadata corruption xfs_inode_buf_verify, xfs_inode block
0xc00" (50×) + "metadata I/O error daddr 0xc00 err117" (15×) + **P117-AGMETA-STALE-CLEAN agno=1 bnobt**
(3×) + P33-INSTR fail-bnobt-snap. The rebuild's leaf growth ALLOCATES a block that DOUBLE-ALLOCS onto
an inode cluster (block 0xc00) = sess39's "dir block shares a daddr with an inode cluster → corruption".

### DEEP ROOT (shared, the real blocker): AG FREE-SPACE COHERENCY.
A node's cached AGF/bnobt/cntbt is STALE (doesn't reflect the peer's allocations) → the allocator
DOUBLE-ALLOCATES: a daddr in use (dir data block, leaf block, OR inode cluster) is handed out again.
Manifests as: data-block clobber (readdir short), leaf-block clobber (leaf-hash hole), inode-cluster
clobber (xfs_inode_buf_verify shutdown). This is the 37-session "Mode A / bnobt double-alloc" family.
P117-AGMETA-STALE-CLEAN detector exists (agno=1, bnobt cached-clean-but-stale).

### NEXT SESSION: attack AG free-space coherency at AG-EX acquire.
Check whether AGF/bnobt/cntbt cached buffers are invalidated+FUA-reloaded when a node acquires the AG
EX after a peer allocated (analogous to the dir-block evict, but for AG meta). If a node reuses a stale
free-space view, it double-allocs. Look at the AG-DLM acquire path + P117-AGMETA-STALE-CLEAN site.
Likely fix: force AG-meta (AGF + bnobt/cntbt roots) FUA-reread/evict at AG-EX slow-path acquire so the
allocator never works off a stale free-space tree. THEN the leaf-rebuild can be safely enabled to fix
the leaf-hash face. Verify: drc_cap2.sh (instr off) ≥3× clean PASS + no shutdown, then full run.sh 2 tcp.
Tools: tests/drc_cap2.sh; grep P117-AGMETA-STALE-CLEAN/P33/xfs_inode_buf_verify/drc-FAIL/P21H-LEAFHOLE.
Marker NOT written.
