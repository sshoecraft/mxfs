---
name: sess50-cwr-torn-dir444-extents-content-tear
description: sess50 (run14d): after phantom-EX fix, posix cluster tests 1-4 PASS; blocker = test_cross_write_read FS shutdown from torn dir-444 dinode (di_format=…
metadata:
  type: project
---

# sess50 (ccloop 14d31183) — cross_write_read torn dir-444 dinode (FS shutdown)

Continues [[sess50-phantom-ex-waiter-recompute-rootfix]]. After the phantom-EX-waiter fix (build 5276B108), the 16-node posix cluster phase gets through tests 1-4 (mkdir/touch/write/cross_visibility) but **test_cross_write_read FAILs**: ~246s (≈ two 120s barrier timeouts) and on-disk **metadata corruption → FS shutdown** on test15/test16 (others EUCLEAN "Structure needs cleaning").

## SYMPTOM (PROVEN)
- Reading dir inode **444 (0x1bc)** = the `.mxfs_test/cross_write_read` directory: `DLM inode from_disk FAILED: ino=444 rc=-117 (EUCLEAN)`; `xfs_bmap_validate_extent_raw` "Bmap BTree record corruption in inode 0x1bc **data fork**"; then `xfs_dabuf_map: bno 8388608 inode 444` HOLE → `xfs_trans_cancel` corruption → **Shutting down filesystem**.
- Corrupted-buffer first 16 bytes: `01 00 00 00 00 83 0a 00 60 64 61 74 61 5f 6e 6f` = ASCII **"`data_no"** — i.e. the dinode's **extent-record area holds shortform dir-entry bytes** ("data_node…"). Decoded bogus extent: "start block 0x303230ba30a" = ASCII "0230…". So dir-444's dinode core says **di_format=EXTENTS** but the literal area still holds **LOCAL (shortform) dir content**. A torn LOCAL→EXTENTS conversion image.

## RULED OUT / KEY FACTS
- **inodesize=512 = sectsize=512** (chk_mxfs, mkfs_mxfs.c XFS_INODESIZE 512). A dinode is exactly ONE sector → atomic at storage → **intra-dinode sector-interleave tearing is IMPOSSIBLE**. The torn 512B dinode was written as a unit by **software**.
- **No P133-DIRINO-WR / REVERT fired for ino=444** (dirwr=1 was on) → the torn EXTENTS image did NOT go through the instrumented inode-log-item write path (P133 only logs EXTENTS/BTREE dir writes in pal/linux/xfs_buf.c ~2554).
- `mxfs_iflush_cluster_merge_dirs` (xfs/xfs_inode.c:4332) overlays FOREIGN slots via `memcpy(dbuf,ddisk,inodesize)` — copies a WHOLE dinode, so it **cannot mix** a fresh core with a stale literal. Its SF-ahead guard (4539) only covers BOTH-LOCAL; the LOCAL→EXTENTS transition is unguarded but overlay still can't create the mix.
- Reload path (xfs/xfs_mxfs_dlm.c ~4320) ALREADY runs `xfs_dinode_verify(snap)` + re-reads up to 8× (RELOAD-VERIFY) and BAILs if bad. from_disk STILL failed → the source dinode **passes xfs_dinode_verify** (structural: di_nextents vs forkoff OK, CRC valid) but **fails xfs_iformat_extents→xfs_bmap_validate_extent** (extent CONTENT garbage). xfs_dinode_verify_fork does NOT decode extent block numbers; iformat does.

## LEADING HYPOTHESIS (next to prove, RULE 4)
The **iflush copy-in** (xfs_iflush_int, xfs/xfs_inode.c) writes a dir-444 dinode where the in-core `i_df.if_format==EXTENTS`/`di_nextents` set but the fork bytes copied are stale LOCAL — an in-core torn fork (sess114-class: [[sess114_lessons]] — reload left torn LOCAL fork) but on the LOCAL→EXTENTS dir-growth transition. Produces a structurally-valid, valid-CRC, extent-content-garbage dinode that the buffer write-verifier (xfs_dinode_verify, structural only) PASSES → reaches disk → every reader's iformat fails.

## NEXT STEP (write-side producer probe)
Add to the dir-inode flush path (xfs_iflush_int end, for S_ISDIR with di_format EXTENTS/BTREE): after building the dinode in the buffer, DECODE the first data-fork extent (xfs_bmbt_disk_get_all / xfs_bmap_validate_extent on rec 0); if it fails, `pr_warn` `P-IFLUSH-DIRTORN ino=%llu di_format=%u nextents=%u forkoff=%u first16=<hex> comm=%s` + `dump_stack()` (gate dirwr=1). This catches the PRODUCER at write time (the structural write-verifier misses content). Then deploy 16-node, run `POSIX_PHASE=cluster posix_phase_timing.sh --nodes 16`, watch for P-IFLUSH-DIRTORN on ino=444 + its stack. Also consider: does dir-444 ever legitimately reach EXTENTS, or should it stay LOCAL? 34 entries (16 data_node + 16 .md5 + . + ..) → it MUST convert to block/extents; the conversion is the hazard.

## Repro / ops
- Probe: `POSIX_PHASE=cluster stdbuf -oL bash tests/criteria/posix_phase_timing.sh --nodes 16 >/tmp/log 2>&1 &` (it self-mounts; ~80s mount, then 14 tests). Poll for `[PASS]/[FAIL]`. cross_write_read is test 5.
- Cluster recover: `scripts/cluster_reset_n.sh 16` (virsh destroy+start+prep, ~40s) then `tests/reset4.sh 16` then bind `mount --bind /src/mxfs /mnt/mxfs-src` on all 16. Nodes test1..test16, pass /tmp/.mxfs_pass.
- Build 5276B108 (VERSION 0.5.7) has the phantom-EX fix — KEEP.
