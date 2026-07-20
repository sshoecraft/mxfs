---
name: sess121-dir-block-lost-update-next
description: sess121 NEXT BLOCKER: concurrent dir-block RMW lost-update (rename_visibility). Decisive evidence + fix direction. Build E9963FFA (bnobt fix in place…
metadata:
  type: project
---

# sess121 (ccloop) — NEXT BLOCKER: dir-block concurrent-RMW lost-update

Read [[sess121-bnobt-clobber-writeside-fix]] first (bnobt SHUTDOWN now fixed,
build `E9963FFA`, P122 write-side interlock — KEEP). With corruption gone,
rename_visibility now exposes the underlying coherency bug and TIMES OUT (124).

## DECISIVE evidence (RULE-4, 4-node clean run)
- Final state ALL nodes agree: `.mxfs_test/rename_visibility` has **after=60,
  before=0** (should be 80). **node1's entire 20-rename add-set PERMANENTLY
  LOST on disk** (node1_after_1..20 MISSING everywhere; unlink-side persisted).
- Directory is **block-format**, single block `daddr=4174760` owner inode
  `4194433`. P-DIRWR shows ALL 4 nodes RMW the SAME block concurrently within
  ms, all ending `count=63 active=62`, buffer `in_ail=1 dirty=0 pin=0 delwri=0`,
  comm=mv AND comm=xfsaild. **maxcount never exceeds 63; NEVER converts to
  leaf** (80 entries WOULD fit in the block — so NOT a capacity/conversion
  issue; it's pure lost-update). 60 survivors = nodes 2/3/4; node1 (earliest
  committer) clobbered by 2/3/4 building on a stale pre-node1 base.
- = exact DIRECTORY analog of the bnobt clobber: a node RMWs/pushes a STALE
  in_ail dir block (missing peers' committed dirents) over the durable version.

## Mechanism (same root as bnobt)
Dir coherency uses per-inode `i_dlm_dir_gen` + per-buffer `b_mxfs_dir_gen`
read-time invalidation in `xfs_da_read_buf` (xfs/libxfs/xfs_da_btree.c:2987-3028;
v0.4.7). Like the FROZEN `pag_dlm_meta_gen`, the dir gen likely isn't bumping /
the in_ail dir block isn't refreshed on dir-inode EX re-acquire → node RMWs a
stale base. gen bump sites: xfs_mxfs_dlm.c:4396, 6369 (also 729/799/4085
evicted-gen compares); init :5057.

## FIX DIRECTIONS (pick via RULE-4)
1. **Dir-block write-side interlock** (mirror P122): at xfs_buf_submit for
   xfs_dir3_block/data_buf_ops, if buffer is in_ail+clean+destaged
   (`!mxfs_buf_is_undestaged`) and on-disk block has active dirents WE LACK
   (content diff, not just count — renames are net-zero count), refresh
   bp->b_addr from `mxfs_pal_bdev_read_plain_bdev` (coherent) + ioend without
   write. Harder than bnobt: need entry-level "disk has names we don't" check.
2. **Dir-inode EX-acquire coldread** (mirror mxfs_ag_meta_coldread_discard):
   on dir-inode EX (re)acquire, discard cached dir DATA/block buffers (incl.
   in_ail destaged ones) so the RMW re-reads fresh. Check why i_dlm_dir_gen
   read-hook (xfs_da_read_buf) doesn't already do this — frozen gen? in_ail
   protect? block-dir path bypass?
3. Verify whether block-format dir reads actually traverse the
   xfs_da_read_buf invalidation hook in this RMW path.

## NEXT STEPS
- Power-cycle ALL 4 (virsh -c qemu:///system destroy+start) + `bash
  tests/reset4.sh 4`, confirm `E9963FFA`.
- Run rename alone (cmd in [[sess121-bnobt-clobber-writeside-fix]]). Confirm
  P122 keeps ltbno/shutdown=0 (bnobt fix holds) while attacking the dir loss.
- Add a dir-block clobber-direction probe (does on-disk block hold dirents the
  in-core write lacks at submit?) to confirm mechanism, then apply fix 1 or 2.
- Goal: after=80 on all nodes, barriers don't wedge, rename_visibility PASS,
  then run full `tests/criteria/cache_coherency.sh` (4 subtests) + verify_ship.sh.
- Related history: [[sess106_lessons]] (concurrent same-name mkdir, parent dir
  inode lost-update), [[sess88_lessons]]/[[sess83_lessons]] (dir-block durable
  lost-update drain-before-unlock fixes — evidently incomplete).
