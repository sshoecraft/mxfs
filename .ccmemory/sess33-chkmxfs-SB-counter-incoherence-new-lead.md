---
name: sess33-chkmxfs-SB-counter-incoherence-new-lead
description: sess33 chk_mxfs on corrupted dir_reuse device: btrees CONSISTENT (no btree double-alloc, favors M2 over M1) but SB summary counters DURABLY WRONG (if…
metadata:
  type: project
---

## sess33 — chk_mxfs of a CORRUPTED dir_reuse_coherency 2/tcp device (NEW decisive evidence)

After a run that corrupted both nodes (`xfs_inode_buf_verify` at inode cluster **block 0xcc0** =
startino 3264), I `umount -l`'d the shut-down FS and ran `tools/chk_mxfs -v /dev/sda` on the frozen
on-disk image (zero hot-path cost — the MOVE-1 decisive test from
[[sess33-NEXT-action-plan-cheap-decisive-and-AG-separation-fix]]):

### RESULT 1 — all per-AG BTREES internally CONSISTENT:
AGF/AGI OK, BNO/CNT btrees OK, inobt/finobt OK on every AG. `AG 0 inobt rec 2: startino=3264 count=64
freecount=52` — the inobt records inode 3264's chunk (the corrupted 0xcc0 cluster) as a normally
ALLOCATED chunk. chk_mxfs's per-inode check passed (11/11 key inodes). So there is **NO btree-level
block double-allocation** detectable by chk_mxfs → weakly FAVORS M2 (stale file extent-map mis-write
clobbering a legitimately-allocated inode cluster) over M1 (allocator double-alloc). CAVEAT: this
chk_mxfs does per-btree internal validation, NOT a full xfs_repair-style block-ownership cross-map, so
a true double-OWNERSHIP (inode-chunk block also claimed by a file extent) would NOT be flagged — and
the runtime-observed 0xcc0 garbage was NOT reproduced by chk_mxfs's plain read (likely the garbage was
in a cached/FUA buffer, or that inode wasn't deep-checked). So M1 not 100% excluded, but M2 leads.

### RESULT 2 (NEW, CONCRETE BUG) — SUPERBLOCK SUMMARY COUNTERS durably INCOHERENT with the btrees:
```
ERROR: AGF freeblks sum 13015695 > superblock fdblocks 12990486   (SB undercounts free blocks by ~25209)
ERROR: inobt total inodes 1856 != superblock icount 1728           (SB undercounts inodes by 128)
ERROR: inobt total free inodes 1616 != superblock ifree 0          (SB says ZERO free inodes; really 1616)
```
The SB lazy summary counters (sb_fdblocks / sb_icount / sb_ifree) are DURABLY WRONG vs the AG btrees.
**ifree=0 is the smoking detail**: a node reading ifree=0 believes there are NO free inodes → on the
next create it allocates a NEW inode chunk (xfs_dialloc → xfs_ialloc_ag_alloc) instead of reusing a
free inode → extra inode-chunk block allocations in the contended dir AG → more reuse churn / more
chances for the data-over-inode-cluster clobber. Stale fdblocks similarly skews block alloc.

### HYPOTHESIS (next session, RULE 4): the SB lazy summary counters are NOT kept coherent cross-node.
XFS keeps sb_fdblocks/sb_icount/sb_ifree as per-mount in-core percpu counters, folded to the on-disk SB
periodically. Two nodes each maintain their OWN in-core counters and write the SB — without cross-node
coordination, they DRIFT and clobber each other (last writer wins with its local-only view). A node
then allocates using a wrong free-count.
- PROBE: log sb_fdblocks/icount/ifree (in-core percpu vs on-disk) at alloc-time on each node; compare
  cross-node. Or just re-run chk_mxfs after a clean (non-corrupting) run to see if the SB drift exists
  even WITHOUT corruption (=> it's a standing coherency bug, not a corruption artifact).
- FIX direction: make the SB summary counters cross-node coherent — either re-read sb counters
  coherently (FUA) at AG/inode alloc, or drive allocation decisions from the per-AG AGF/AGI counts
  (which ARE coherent via the AG-DLM) instead of the global SB summary, or coordinate SB writeback.
  This is distinct from (and may be MORE tractable than) the per-buffer dir/extent coherency patches.

### Recovery note: chk_mxfs needs the FS unmounted; after a shutdown `umount -l /mnt/shared` works (FS
frozen, no flush). Device is /dev/sda on the node. tools/chk_mxfs is at /src/mxfs/tools (NFS-visible).
[[sess33-PROVEN-ROOT-inode-data-block-double-alloc]] [[sess33-NEXT-action-plan-cheap-decisive-and-AG-separation-fix]]
</body>
