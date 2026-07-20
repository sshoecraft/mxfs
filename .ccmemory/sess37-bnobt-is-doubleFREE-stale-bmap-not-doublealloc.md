---
name: sess37-bnobt-is-doubleFREE-stale-bmap-not-doublealloc
description: sess37 DECISIVE: dir_reuse 2/tcp bnobt shutdown is a double-FREE (inactivation frees already-free block 297 agno=1), NOT allocator double-alloc (sess…
metadata:
  type: project
---

## sess37 DECISIVE — the bnobt shutdown is a stale-bmap double-FREE, not a double-ALLOC

Refines [[sess37-FINAL-state-bnobt-doublefree-is-severest-AG-root]] and confirms
[[sess30-FACEC-bnobt-double-alloc-deep-dive]] + [[sess55-faceB-is-M2-stale-bmap-not-allocator]].

### The corruption, captured (P15-INSTR at xfs_alloc.c:2254):
`FREE-AG-EXTENT-FAIL-LEFT agno=1 bno=297 len=1 ltbno=248 ltlen=261405 agf_freeblks=261628`
→ freeing block 297 (len 1) in agno=1, but the left free extent [248, 248+261405=261653) ALREADY
covers 297 (the AG is ~empty, 261405 free blocks). So **block 297 is freed while already free =
DOUBLE-FREE**. Happens during rm-rf inactivation (P25-INSTR sync-inactive-DONE ino=0xae..0xb5 = file
inodes 174-181).

### NOT an allocator double-alloc — RULED OUT (do not re-chase):
- `P55-ALLOC-OVER-DISKINODE = 0` and `P55-ALLOC-OVER-CACHEDINODE = 0` this run (the coherent on-disk +
  cached-inode probes at the DATA-alloc site, xfs_alloc.c ~4060-4210). The allocator NEVER hands a DATA
  request a block holding a live inode cluster. sess55 proved this too (0× while shutdowns persisted).
- So the daddr-0xc00 "data over inode cluster" symptom + the bnobt err are BOTH the **M2 class**: a
  STALE in-core EXTENT MAP under inode/daddr REUSE. An inode's bmap claims a block that is already free
  (freed by a prior incarnation / peer / earlier op and not reflected in-core) → inactivation frees it
  again (bnobt double-free) OR a file data write goes to the now-reused daddr (inode-cluster clobber).

### Why stale bmap: the dir_reuse test rm-rf's + recreates every round, RECYCLING inode numbers and
their block daddrs. A file inode created fresh has a correct bmap, but a RECYCLED inode (freed prior
incarnation, re-allocated this round) can inherit/retain a stale in-core bmap if the reuse path does
not fully reset the data fork. The inactivation then double-frees the prior incarnation's blocks.
Related prior fixes: sess103 (inode REUSE: gate size-drop-skip on di_gen), sess47 (skip inactivation of
STALE cached inode via di_mode/di_gen check), sess19 (clear MXFS_IF_LOCAL_UNLINK on reload), sess40
(IRECLAIMABLE reused-inode iget). The gap persists for this 2/tcp reuse churn.

### NEXT: inode-reuse fork-reset coherency.
1. Instrument: at inactivation (xfs_inactive/xfs_ifree free path), before freeing each extent, verify
   (coherent) the block is actually allocated; log when freeing an already-free block + the inode#,
   di_gen, and whether the inode was recycled. PROVE which inode has the stale bmap.
2. Likely fix locus: xfs_iget_recycle / xfs_init_new_inode (reused inode must xfs_idestroy_fork +
   rebuild the data fork from the fresh on-disk dinode, not inherit the prior incarnation's bmap), OR a
   defensive inactivation guard (skip freeing an extent the bnobt says is already free — prevents the
   shutdown, lets the test continue). The defensive guard is lower-risk and directly stops the
   shutdown; pair with the root fix.
This is the SEVEREST flaky mode. The data-loss + leaf-hash faces are the same stale-reuse root on dir
blocks. Build A695EC5C (clean baseline). Marker NOT written.
