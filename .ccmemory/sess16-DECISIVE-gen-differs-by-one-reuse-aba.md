---
name: sess16-DECISIVE-gen-differs-by-one-reuse-aba
description: sess16 DECISIVE: at the crash_consistency shrink-adoption, in-core di_gen vs on-disk di_gen DIFFER BY EXACTLY 1 (incore=prev incarnation block+entrie…
metadata:
  type: project
---

## sess16 DECISIVE measurement (build 171D846C, enriched P62-RELOAD-FORK-SHRINK with gens). crash_consistency probe failed iter 14, 5 md5 entries lost durably (test2 195/200, no +8s recovery).

## THE NUMBERS (test2, the losing node):
`P62-RELOAD-FORK-SHRINK ino=131 incore_fmt=2 incore_nx=3 incore_size=8192 disk_fmt=1 disk_nx=0 disk_size=22 shrink=1 in_ail=0 pin=0 incore_gen=2276945648 disk_gen=2276945649 post_release=1 self_created=0`

## INTERPRETATION: incore_gen and disk_gen DIFFER BY EXACTLY 1 (648 vs 649). XFS bumps di_gen +1 on every inode reallocation. So:
- in-core ino 131 = PREVIOUS incarnation (gen 648), BLOCK format, nx=3, 8192 bytes = the PRIOR iter's dir (.ccb_13) grown state, still cached.
- on-disk ino 131 = NEW incarnation (gen 649), empty shortform (size=22) = the freshly mkdir'd current dir (.ccb_14).
=> INODE-NUMBER REUSE ABA is central to the crash_consistency failure (the probe rm-rf's .ccb_N each iter, freeing ino 131; next mkdir reuses it, di_gen+1). This P62 (648->649, post_release=1) ADOPTED the new incarnation = CORRECT; it is the incarnation switch, NOT itself the loss. The 5 lost entries belong to the NEW incarnation (gen 649) = a SAME-incarnation (gen 649==649) concurrent-create clobber that happens AFTER this switch.

## NOTE: earlier P133-DINO-READSTALE showed gen IDENTICAL — that was a DIFFERENT moment (a same-incarnation reload). So BOTH happen: (1) cross-incarnation cache lingering (gen 648 vs 649) and (2) same-incarnation concurrent-create races. The crash_consistency failure couples them: reuse (gen+1) provides fresh-shortform-restart timing each iter, and the concurrent sf->block create on the fresh incarnation loses entries.

## NEXT (RULE 4): the loss is on the NEW incarnation (gen 649). Instrument to catch the SAME-incarnation (incore_gen==disk_gen) clobber on gen 649: (a) does test2's stale gen-648 in-core inode get FLUSHED (xfsaild dinode write) over the gen-649 on-disk inode (ABA inode-cluster clobber — sess87/sess90/sess128 family: mxfs_buf_has_uncheckpointed_mods / P91-RELOAD-PROTECT guards)? Add a dinode WRITE trace (inode-cluster write in pal/linux/xfs_buf.c) dumping di_gen + di_format, watch for a gen-648 write landing after gen-649. (b) OR the gen-649 concurrent create loses entries via the dir-data-block path (P35E-DIRWR names on gen-649 blocks). Reference the reused-inode fixes: [[sess128-root-fix-phantom-ex-rearm-unpublished]] (phantom-EX rearm at cache-hit IGET_CREATE), [[sess90_lessons]] (two gen signatures: off-by-one=reuse, same-gen=cluster stale-flush), [[sess40 IRECLAIMABLE reused inode iget]]. The iget-recycle path (xfs_iget_cache_hit/recycle) must fully drop the gen-648 incarnation when ino 131 is reallocated to gen 649. Cluster on 171D846C (== 15/16 baseline + enriched P62 log, behaviorally neutral). Repro tests/cc_blockdir_probe.sh (ino 131, <15 iter, foreground timeout 280). [[sess16-HEAD-status]]
