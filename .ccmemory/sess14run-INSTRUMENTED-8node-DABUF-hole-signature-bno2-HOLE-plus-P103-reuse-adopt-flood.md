---
name: sess14run-INSTRUMENTED-8node-DABUF-hole-signature-bno2-HOLE-plus-P103-reuse-adopt-flood
description: sess14(ccloop) INSTRUMENTED 8-node DABUF: hole = dir ino 537965 logical block 2 = HOLESTARTBLOCK(-2) in extent map while a leaf references it. Contex…
metadata:
  type: project
---

## sess14 (ccloop) — INSTRUMENTED 8-node DABUF_MAP_HOLE signature (RULE 4)

The existing xfs_alert at xfs_da_btree.c:2817 ALREADY logs the hole detail (xfs_error_level default LOW). Captured on test4/test8 during in-suite dir_reuse 8/tcp (build 1A0A8F9C):
```
XFS (sda): xfs_dabuf_map: bno 2 inode 537965
XFS (sda): [00] br_startoff 2 br_startblock -2 br_blockcount 1 br_state 0
```
- `br_startblock -2` = HOLESTARTBLOCK → logical dir block 2 is a HOLE (unmapped) in this node's data-fork extent map.
- Yet a LEAF/freespace pointer references logical block 2 → !HOLE_OK → EFSCORRUPTED shutdown.
- inode 537965 (the dir; low ino = AG0). Repeats hundreds of times (test4: 251-668 events).

### Surrounding context: P103-RELOAD-REUSE-ADOPT FLOOD
Hundreds of lines like:
`P103-RELOAD-REUSE-ADOPT ino=83886259 mem_size=33 disk_size=0 incore_gen=1950009583 disk_gen=1950009584 disk_mode=00 — adopting peer's reused incarnation (gen differs)`
- These are the FILES (high inos; mem_size=33 = the .md5 sidecars, others=data sizes). gen differs by EXACTLY 1 = the inode was freed+realloc'd (ABA). The node ADOPTS the disk incarnation (disk_size=0, mode=00 = freshly-allocated/empty).
- Heavy ABA inode-reuse churn at 8-way (rm-rf+recreate each round frees+reallocs all the files AND the dir).

### Working hypothesis (NOT yet proven — instrument further)
The DIR inode 537965 is, like the files, being reloaded across an ABA reuse (gen bump). When the dir reload adopts a reused incarnation whose extent map has FEWER blocks (e.g. 2 blocks, no block 2) than the LEAF block still cached references (the prior incarnation grew to ≥3 blocks), block 2 resolves to a HOLE. So it is a LEAF-vs-extent-map incarnation MISMATCH under ABA dir reuse: either (a) a STALE cached leaf from the prior incarnation references block 2, or (b) the extent map was reloaded to the wrong (smaller) incarnation while the leaf is current.
NEXT (RULE 4): at the hole site, also log dp->i_df.if_format, if_nextents, i_disk_size, VFS_I(dp)->i_generation, i_dlm_dir_gen, i_dlm_dir_evicted_incarn, and the LEAF block's b_mxfs_dir_incarn that referenced block 2 — to prove leaf-incarn vs map-incarn mismatch. Then the fix is to invalidate the leaf when its incarn != the dir's current i_generation (the b_mxfs_dir_incarn check at xfs_da_btree.c ~3246 may not be catching the LEAF block, only data blocks).

### Build 1A0A8F9C deployed (runtime == validated AA8C4934). Criterion NOT met (1/2/4 tcp ✅, 8/tcp 12/17).
See [[sess14run-CORRECTION-8node-DABUF-NOT-modify-time-extent-staleness-instrument-next]] [[sess13run-RELAY-test-does-rm-rf-each-round-ABA-daddr-reuse-verify-digen]].
