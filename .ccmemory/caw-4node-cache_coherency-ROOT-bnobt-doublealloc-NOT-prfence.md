---
name: caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence
description: CORRECTION: 4/caw cache_coherency FAIL root = cross-node bnobt DOUBLE-ALLOC (daddr72 dir-block clobbered by delalloc-writeback file alloc), NOT PR-fe…
metadata:
  type: project
---

## 4/caw cache_coherency ROOT — CORRECTED (ccloop 12e0d157, sess3, 2026-07-07, build 0510FC3E)

### The previous session's diagnosis was WRONG
[[caw-4node-cache_coherency-REGRESSION-empty-content]] called this a "real coherency
regression / empty cross-node content." It is NOT. The empty `got=` reads are a
**downstream cascade**: a node's FS force-**shuts down** (all reads→EIO→test sees empty).

### PROVEN root (RULE 4, instrumented, this session)
Fresh CLEAN 4/caw run (fresh mkfs, all nodes power-cycled, converged 4/4 stable, no PR
conflict at steady state) → cache_coherency + zero_silent_loss BOTH FAIL 0/4. Live probe
BEFORE the run proved coherency CODE is fine (nodes 2/3/4 had perfect cross-node
visibility; only a leftover-wedged node1 EIO'd).

The killer, from a shut-down node's dmesg:
```
mxfs: P-BLKRV-CRC daddr=72 blkno=<garbage> owner=0 — dir3 block CRC fail on read (multinode)
  xfs_dir3_block_read_verify <- mxfs_pal_scsi_read_fua_bdev <- xfs_dir_lookup <- xfs_lookup
XFS (dm-1): Metadata CRC error ... xfs_dir3_block block 0x48 ... Shutting down filesystem
First 128 bytes of corrupted buffer: "hello from node 1\n" 00 00 ...
```
daddr 72 (=agbno 9, AG0) is the `.cache_coherency` DIR block (ino 131). But its on-disk
content is the FILE DATA "hello from node 1" that node1 wrote to cross_visibility/node1.txt.
**Same physical block aliased as both a dir-metadata block AND a file-data block** =
cross-node bnobt (AG free-space) DOUBLE-ALLOCATION. Read as dir → CRC fail → shutdown →
cascade → all peers' reads of that node's files empty → 0/4.

### Caught in the act (un-gated P-DBLALLOC, xfs_alloc.c:4318)
`mxfs: P-DBLALLOC agno=0 agbno=9 len=1 daddr=72 holds=dir-block magic0=58444233(XDB3)
tenure=1 node=0 wasfromfl=0 comm=kworker/u12:3` on test1 (node0, AG0's affine owner).
So test1 allocated daddr 72 for a FILE data block **in a kworker = DELALLOC WRITEBACK**
(xfs_bmapi_convert_delalloc→btalloc) while daddr 72 held the live shared-dir block. The
writeback allocator's bnobt view showed daddr 72 free. new_owner_ino=-1 (owner not threaded
on the bmap-data path; mxfs_diag_owner also unset here).

### This is the well-known cross-node AG free-space double-alloc family
sess3/4/5/22/30/32/37/117... [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]]
[[sess4-ccloop-REFINE-owner-mismatch-is-disk-level-bnobt-not-dirgen]]
[[sess22-ccloop-inv2-fresh-acquire-coldread-hole]]. Default `dir_force_block=1`
(xfs_mxfs_dlm.c:7908) makes cache_coherency dirs use BLOCK format → allocate dir blocks →
exposes it (sess4: force_block=0 hides it but breaks dir_reuse — config tension, not a fix).
Acquirer-side coldread fix IS present (fresh CAW-grant path calls
mxfs_ag_meta_coldread_discard(pag,true) at xfs_mxfs_dlm.c:23074). Suspected remaining gap =
OWNER-SIDE bnobt durability before AG release, OR the DELALLOC-WRITEBACK alloc path
(kworker) not fresh-acquiring/coldreading the AG. NEXT: confirm whether the writeback
btalloc path holds AG-DLM + coldreads, or allocates from a stale cached bnobt.

### Also seen (separate, transient, self-recovering): PR-UA register race
During the concurrent 4-node join, nodes briefly lose PR registration (reservation conflict
on both paths) then re-register & recover (test3/test4 did). test2 additionally hit the CRC
shutdown so stayed dead. The PR-UA race [[pr-ua-register-fence-out-rootcause]] is real but
SECONDARY — the double-alloc CRC shutdown is the 0/4 cause. Fix double-alloc first.
See [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]].
</body>
