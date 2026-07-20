---
name: sess55-faceB-is-M2-stale-bmap-not-allocator
description: sess55 (run14d): posix_multi16 Face B = dir-data clobbers an inode cluster. RULED OUT decisively: allocator double-alloc (M1) AND dir-buffer-get mis-…
metadata:
  type: project
---

## sess55 (ccloop 14d31183) — Face B: dir-data clobbers inode cluster; M1 AND M2 ruled out

Continues [[sess54-dir-coherency-and-bnobt-dblalloc-faces]]. Only `posix_semantics_multi16`
FAILs (`elapsed>600s`) from FS **shutdowns** under the 16-node shared-dir storm. Fast repro:
`tests/reset4.sh 16` then `tests/repro_agi_unlink_storm.sh 16 6` — shutdown in round 1-2.

### PROVEN SHUTDOWN SIGNATURE (consistent every run)
`inode 0x87 (=ino 135) xfs_iformat_extents(2)` corruption + `from_disk FAILED ino=135 rc=-117`
+ `imap_to_bp ino=135 rc=-5`. Hexdump of ino 135's on-disk cluster = **dirent bytes**
(`78 6e 31 33 5f 72 31 5f` = "xn13_r1_", node13 storm filename). => directory dirent data
physically overwrote ino 135's inode cluster. ino 135 = a storm-created dir.

### RULED OUT this session (RULE-4, 4 ungated detectors, all 0× while shutdowns persisted)
All in `xfs/libxfs/xfs_alloc.c` `xfs_alloc_vextent_finish` (multi-node DATA-fork allocs) +
`xfs/libxfs/xfs_da_btree.c` `xfs_da_get_buf`:
1. **P55-ALLOC-OVER-INODE** (per-AG 256-ring of this node's inode-chunk extents) — 0×: no
   intra-node alloc of a DATA block over an inode chunk.
2. **P55-ALLOC-OVER-CACHEDINODE** (xfs_buf_incore TRYLOCK for live xfs_inode_buf_ops at the
   allocated daddr) — 0×.
3. **P55-ALLOC-OVER-DISKINODE** (plain-bio read of the allocated block = COHERENT SCST cache
   under fua_disable=1; check di_magic 0x494e) — 0× on ALL 16 nodes. DECISIVE: the allocator
   NEVER hands a DATA request a block holding a live inode cluster. (REMOVED after proving —
   one 512B read/alloc slowed the storm past the 360s budget.)
4. **P55-DIRWRITE-OVER-INODE** (`xfs_da_get_buf`: check the dir-block WRITE buffer; cheap
   di_magic on cached XBF_DONE buffers, plus a plain-bio read of the mapped daddr on
   cache-miss !XBF_DONE) — **0×**. => the dir-block buffer-get path does NOT map a dir block
   onto an inode-cluster daddr (neither locally-cached nor peer-on-disk).

Round 1 runs on a FRESH fs (creates only) yet shuts down => not free->realloc aliasing.

### => M3 (writeback-time clobber) is the leading remaining hypothesis
Neither the allocator (M1) nor the logical dir-write mapping (M2) targets an inode cluster.
Yet dirent bytes land on ino 135's cluster. So the clobber is most likely at **bio
submission / writeback**: a STALE cached dir-data buffer (b_maps daddr) is flushed by
xfsaild (or BAST drain) onto a daddr that now backs an inode cluster; OR the inode-cluster
init path collides. The bad daddr is computed/held by the BUFFER, not re-derived from the
(possibly-fixed) extent fork at write time — so the get-path detector misses it.

### NEXT (RULE 4): instrument WRITEBACK, not the logical paths
Add a guard/detector in `pal/linux/xfs_buf.c` at bio submission (`xfs_buf_submit` /
mxfs write path): when a buffer with **dir-block ops** (xfs_dir3_*/xfs_da3_*) is about to be
WRITTEN to a daddr, or symmetrically when ANY non-inode buffer's target daddr matches a
cached/disk inode cluster, fire + (ideally) skip. Cheapest decisive probe: at write submit
of a dir/data buffer, plain-read the target daddr's CURRENT disk di_magic — if it's a live
inode, this write would clobber it. Also check the inverse: inode-cluster-init
(xfs_ialloc_inode_init in xfs/libxfs/xfs_ialloc.c) writing over a daddr that holds live dir
data. Identify whether the stale buffer is from a deleted dir (inode-number/dir reuse,
[[sess48]]/[[sess128]] family) or a never-invalidated cross-node alias.

### Other notes
- Force-release Invariant#1 hole IS real (`AG N Phase-3 meta_pending=K timeout after 2s —
  forcing release`, detector P55-STUCKMETA at xfs_mxfs_dlm.c ~L10976) but fired 0× on the
  actual shutdown rounds — NOT this clobber's cause. Keep the enumerator (cheap).
- Builds this session: D9BA766C -> 75F63922 -> 069E6432 -> 5C7F0742 -> 3D83E2B2 ->
  26D4F790 (current, all 16 nodes). All P55 detectors KEPT except DISKINODE (removed).
  The xfs_da_get_buf cache-miss plain-read in 26D4F790 is bounded but slightly heavy — gate
  behind mxfs.instr if it perturbs functional runs.
- ikeep (xfs_ialloc.c chunk-keep multi-node) still in tree; not load-bearing for M3.
- Marker NOT written (criterion still fails).
</body>
