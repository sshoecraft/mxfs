---
name: sess53-agi-insert-stale-head-shutdown-fix
description: sess53 (run14d): posix_multi16 >600s = FS shutdowns. Fixed rmdir AGI-insert (9C3D67D7); create-path = inode-chunk-free->reuse DOUBLE-ALLOC, ikeep gat…
metadata:
  type: project
---

## sess53 (ccloop 14d31183) — posix_semantics_multi16 >600s: two FS-shutdown roots

State: 18/19 criteria PASS; only `posix_semantics_multi16` FAIL (`elapsed>600s`, hard 600s cap
in tests/criteria/posix_semantics.sh). `.criteria_results.json` is source of truth; the `p`
prompt file is STALE (says cache_coherency, which now PASSES). A shut-down node makes every
test barrier hang 120s -> blows the 600s budget, so FS shutdowns ARE the timeout cause.

### ROOT 1 (FIXED, build 9C3D67D7B2CA7F2CD4C91D6, UNVERIFIED): rmdir AGI-insert stale head
xfs_remove(rmdir) -> xfs_droplink -> xfs_iunlink -> xfs_iunlink_insert_inode chains onto an
AGI unlinked bucket head that names an inode FREE on disk -> reload ENOENT -> dirty-trans
cancel (xfs_trans_cancel line 1060) -> shutdown. FIX in xfs/libxfs/xfs_inode_util.c
xfs_iunlink_insert_inode: on `error==-ENOENT && next_agino!=NULLAGINO`, FUA-read the disk
bucket head (mxfs_agi_disk_bucket_head); adopt it if stale, else self-heal (our inode = sole
head). Logs `P-INS-STALE`. (Did NOT fire in repro — ROOT 2 shut nodes down first.)

### ROOT 2 (NOT fixed — the deep ship blocker): inode-chunk-free -> block-reuse DOUBLE-ALLOC
`repro_agi_unlink_storm.sh 16 4` (40 dirs/node x 4 shared parents, then concurrent rm -rf) on
a FRESH-mkfs'd 16-node cluster shut down 3 nodes in ROUND 1 (~10s) on the CREATE path:
```
xfs_create -> xfs_dir_lookup -> xfs_dabuf_map: bno 8388608 (=XFS_DIR2_LEAF_OFFSET) inode 135 br_startblock -2 (HOLE)
DLM inode from_disk FAILED ino=135 rc=-117
inode 0x87(=135) data fork: Bmap BTree record corruption, xfs_iformat_extents(2)
hexdump of the "extent record": 0b 00 00 00 00 84 08 00 60 6e 35 5f 72 31 5f 64 = "`n5_r1_d" (a FILENAME)
```
**Inode 135's on-disk inode cluster was OVERWRITTEN with dir-data block content (a dirent).**
A dir-data block was allocated over inode 135's inode cluster = AG free-space double-alloc.
Detectors that fired: `P103-CHUNKFREE` (inode chunks freed under rm-rf storm: all-64-free chunk
returned its 8 inode-cluster blocks to AG free space) + `P117-AGMETA-STALE-CLEAN ... bnobt
daddr=8`. Mechanism: rm-rf frees an inode chunk -> its inode-cluster blocks go back to bnobt
free space -> reallocated as dir-data for new dirs -> but a stale cached inode / stale AG view
clobbers a still-referenced inode cluster. This is the sess39/42/43/81 AG double-alloc family
(tenure_id sess123 fixed the AGI unlinked list; the bnobt/inode-chunk-reuse sibling persists at
16 nodes). cache_coherency(4 nodes) PASSES because 4-node load rarely frees+reuses chunks fast.

### PROPOSED FIX for ROOT 2 (next session, RULE 4 — verify with the fast repro):
Eliminate the class by NOT freeing inode chunks in multi-node mode (XFS `ikeep` behavior):
inode-cluster blocks then never return to general allocation, so dir data can't alias an inode
cluster. GATE: `xfs/libxfs/xfs_ialloc.c:2442` —
`if (rec.ir_free == XFS_INOBT_ALL_FREE && mp->m_sb.sb_inopblock <= XFS_INODES_PER_CHUNK)`
selects the chunk-removal branch (xic->deleted=true; xfs_difree_inode_chunk returns blocks).
Add a multi-node/`mxfs.ikeep` guard so this branch is NOT taken (fall to else: just update
inobt freecount, keep chunk allocated). Cost = inode blocks not reclaimed (fine; 20GB dev,
correctness>space). Then `bash tests/reset4.sh 16` + `bash tests/repro_agi_unlink_storm.sh 16 4`;
expect 0 shutdowns. If clean, run posix_semantics --nodes 16 end-to-end.
PROVE FIRST (RULE 4): confirm the clobbered block was a just-freed-chunk block before trusting
ikeep is the whole root — but ikeep is low-risk and class-eliminating regardless.

### Fast reproducer (NEW, KEEP): tests/repro_agi_unlink_storm.sh [N] [ROUNDS]
16-node concurrent create+rm-rf in shared parents; checks each node for SHUTDOWN per round;
greps P-INS-STALE/trans_cancel/Shutting-down. Reproduces ROOT 2 in round 1 (~10s). MUCH faster
than the full cluster phase.

### Cluster/infra
- SCST CAW<->READ wedge recurred (mkfs HANGS, 3 D-state iscsi_conn_cleanup, no PR conflict).
  Cleared per [[sess47-scst-wedge-pr-recovery-procedure]]: gdb edges (scripts/scst_atomic_edges.py)
  -> READ 0x..82c0 <-> CAW 0x..7bc0 -> scst_unwedge.ko blocker=READ blocked=CAW -> 0 edges. insmod
  returns EBUSY by design = success.
- After this session: test3/test5/test13 (and possibly others) SHUT DOWN from ROOT 2 repro.
  Next session MUST `bash tests/reset4.sh 16` (clear SCST wedge first if mkfs hangs) before any run.
- Build 9C3D67D7 is on /src/mxfs/mxfs.ko (NFS-visible to all nodes); INSMOD_OPTS="fua_disable=1 instr=0".
Related: [[sess15_agi_xnode_corruption]] [[sess42_lessons]] [[sess81_lessons]] [[sess24-PROVEN-inobt-incoherent-at-alloc]] [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]]
</body>
