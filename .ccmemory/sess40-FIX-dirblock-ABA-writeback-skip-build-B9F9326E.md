---
name: sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E
description: sess40 FIX (build B9F9326E, UNVERIFIED): dir-block ABA writeback skip — suppress xfsaild flush of a dir DATA/leaf buffer whose b_mxfs_dir_incarn != o…
metadata:
  type: project
---

## sess40 (ccloop 8ddb16a2) — FIX for dir_reuse 2/tcp Bug A (dir-block ABA writeback clobber). Build **B9F9326E0E9490E9F83866B**. UNVERIFIED at write time. Marker NOT written.

### What it fixes (Bug A, PROVEN root, sess36/sess28 + sess40 iter3 evidence):
node1's xfsaild durably flushes a DEAD prior-incarnation block-0 (daddr 120) over the live incarnation's block → readdir short (node1_f1..f13 lost, lookup_fail=0). The dir inode (ino=131) is rm-rf'd+recreated each round → i_generation bumps; a lingering cached dir DATA buffer at the reused daddr keeps the OLD incarnation's stamp (b_mxfs_dir_incarn=1517736483) while the live gen is 2642423927. The READ-path ABA bypass (xfs_da_btree.c:3213/3484) catches it on a read, but xfsaild WRITEBACK never reads → the dead image is flushed (P29-DATAWRITE CLOBBER, detector-only, didn't prevent).

### The fix (6 edits, all sess40-tagged):
1. **xfs/xfs_mxfs_dlm.c `mxfs_buf_xfsaild_skip_dir_write`** (~15545): at the writeback chokepoint, set skip=true when `bp->b_mxfs_dir_incarn != 0 && != VFS_I(ip)->i_generation` (owner dir found in-core). The dead-incarnation buffer belongs to a FREED inode → its content is garbage that can only corrupt; emulate-clean-ioend (existing NL-skip pattern at pal/linux/xfs_buf.c:2004) drops the bio. Fires for NL/PR/EX alike.
2. **xfs/xfs_mxfs_dlm.c `mxfs_dir_data_track`** (~15439, modify-time hook from xfs_trans_log_buf): also stamp `bp->b_mxfs_dir_incarn = VFS_I(ip)->i_generation` so any block carrying THIS incarnation's logged work has the live stamp → never false-skipped.
3. **xfs/libxfs/xfs_dir2_data.c `xfs_dir3_data_init`** (~1048): stamp incarn on a freshly get_buf'd+init'd block (xfs_da_get_buf can return a LINGERING old-incarnation buffer at a reused daddr) → the first block-0 of a recreated dir isn't mistaken for a leftover.
4. struct `mxfs_dir_skip_info` += incarn_aba/buf_incarn/cur_incarn (xfs_mxfs_dlm.h).
5. **pal/linux/xfs_buf.c**: P16-DIRBLK-SUBMIT += aba/bincarn/cincarn fields; NEW always-on (ratelimited) **P40-INCARN-ABA-DIRSKIP** when the skip suppresses a write (provable at dirwr=0).
6. **xfs/xfs_mxfs_dlm.c:3718** `mxfs_inode_mht_ms` default 50→300 (memories: required for dir_reuse timing; canonical ./run.sh 2 tcp uses module defaults).

### Safety reasoning: a current-incarnation block always has incarn==live gen (stamped at modify AND init); only a never-re-modified dead-incarnation leftover mismatches. `incarn != 0` guard spares unstamped-fresh. Owner-not-in-core → conservative fall-through (no false skip). Well-scoped to reused-inode dirs (only ino=131 here); stable dirs never mismatch → low regression risk. Differs from the REFUTED fence (that was the INODE CLUSTER slot in xfs_inode.c; this is the DIR DATA block).

### VERIFY: MXFS_EXTRA_MODARGS='dirwr=1' bash tests/drc_loop.sh N → expect P40-INCARN-ABA-DIRSKIP fires, P29-DATAWRITE CLOBBER daddr=120 →0, readdir-short gone. THEN production (dirwr=0) full ./run.sh 2 tcp.

### CAVEAT: Bug B (AG free-space DOUBLE-ALLOC → file data over inode cluster @0xb40 → xfs_inode_buf_verify EFSCORRUPTED, P117-AGMETA-STALE-CLEAN bnobt) is INDEPENDENT and NOT addressed by this fix. If the test still fails on EFSCORRUPTED after Bug A is fixed, Bug B needs a separate allocator-coherency fix (enable instr for P32B-DOUBLEMAP/P31E evidence). See [[sess40-fence-REFUTED-real-root-dirdata-clobber-plus-AG-doublealloc]] [[sess36-correctness-aba-dirblock-clobber-fix-plan]].
