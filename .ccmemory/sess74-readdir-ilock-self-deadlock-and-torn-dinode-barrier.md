---
name: sess74-readdir-ilock-self-deadlock-and-torn-dinode-barrier
description: sess74 (run14d): zsl verify-hang ROOT = readdir SHARED→EXCL self-deadlock in xfs_file_readdir; FIXED (67597818). Plus write-boundary torn-dinode barr…
metadata:
  type: project
---

## sess74 (ccloop 14d31183) — zero_silent_loss: TWO fixes landed (NOT yet end-to-end verified). Marker NOT written.

Build progression: 64932978 (sess73) → 3E4F5777 (P74-DINEXT-REGRESS detector, BTREE-only, inert) → 01A3F1A7 (P74-IFNEXT-SKEW write-boundary torn-dinode barrier in xfs_inode.c) → **67597818 (readdir self-deadlock fix in pal/linux/xfs_file.c — CURRENT, built, NOT yet reset/deployed/tested)**.

### FIX 1 (verify-HANG root, DECISIVELY PROVEN via P73-ILOCK-STUCK, KEEP): readdir ILOCK self-deadlock
`pal/linux/xfs_file.c xfs_file_readdir` took `xfs_ilock(ip, XFS_ILOCK_SHARED)` UNCONDITIONALLY across `xfs_readdir()`. For a NON-shortform dir whose data-fork extents are not loaded (`need_iread=1` — the state a peer-driven `mxfs_dlm_reload_inode` leaves via xfs_idestroy_fork+xfs_inode_from_disk), `xfs_readdir`→`xfs_ilock_data_map_shared` takes `ILOCK_EXCL`. Upgrading SHARED→EXCL on the same rwsem by the same thread DEADLOCKS forever. Proof: `P73-ILOCK-STUCK ino=131 want=EX rd_held=1 wr_last=xfs_ilock_data_map_shared wr_pid=1353=find rd_last=xfs_file_readdir pid 1353` (same pid holds SHARED + wants EXCL). The BMBT reload then BAILs "DLM reload BAIL i_lock contended" so need_iread NEVER clears → permanent wedge; `ls wa_iter1` hangs forever; threads spin R-state in the P73 trylock loop. FIX: hold the outer SHARED ONLY for LOCAL/shortform dirs (xfs_dir2_sf_getdents takes no ILOCK + reads inline if_data, never wants EXCL); for all other formats let xfs_readdir take its own lock (SHARED, or EXCL when it must xfs_iread_extents) with NO outer lock held. consumer_refresh() above already settles peer reloads + fires the DLM hook. Residual race: a LOCAL→block conversion inside xfs_readdir's own reload while we hold SHARED could re-trip it (rare; P73 would show it).

### FIX 2 (write-side torn-dinode barrier, Gemini-designed, KEEP): P74-IFNEXT-SKEW
`xfs/xfs_inode.c xfs_iflush`, BEFORE mxfs_iflush_force_bmbt_durable + xfs_inode_to_disk: for a multi-node DIR with extents loaded (!need_iread), WALK the iext tree counting real extents; if `real != if_nextents`, log `P74-IFNEXT-SKEW` (+ one-shot dump_stack) and RECONCILE `if_nextents = real`. This restores the upstream invariant (di_nextents == records actually written) so a TORN dinode is never published → no EFSCORRUPTED/CORRUPT_INCORE shutdown → no SCSI-PR reservation-conflict cascade. Addresses sess60/65 PROVEN root (in-core if_nextents diverges from iext tree; xfs_inode_to_disk then packs a torn dinode). NOTE: P74 fired 0× in the one instrumented run (corruption avoided by timing that run), so the barrier is UNCONFIRMED-as-triggered but correct-by-construction.

### KEY MEASUREMENTS (build 01A3F1A7, dirwr=1, 16-node 1-iter)
- Run with FIX2 only: NO shutdown, NO corruption, NO P74-skew, all 16 mounted — but verify `find` HUNG (the FIX-1 deadlock). So FIX2's timing eliminated the corruption face and EXPOSED the pre-existing readdir wedge as the dominant blocker → led to FIX 1.
- Prior run (3E4F5777): corruption face = `xfs_iformat_extents`/`xfs_bmap_validate_extent_raw` on EXTENTS-format ino=131 (di_format=2 growing), then `xfs_trans_cancel` CORRUPT_INCORE shutdown on test12 → host SCST `Reservation conflict (dev disk1)` storm across 15 initiators → `connection1:0 conn error (1020)` cluster-wide EIO → all 1600 mkdirs fail = 1600 silent. So the cascade (1 node corruption → cluster-wide EIO via PR fencing) is the loss MULTIPLIER (Gemini fix (c): contain force_shutdown so it doesn't trigger the PR storm — NOT yet done).

### NEXT SESSION (clear path)
1. Deploy 67597818 (or rebuild): `make modules` then `bash scripts/cluster_reset_n.sh 16`.
2. `INSMOD_OPTS="dirwr=1" ./tests/criteria/zero_silent_loss.sh --iters 1 --dpn 100 --mode 1`. Expect: NO verify hang now (FIX 1). Check `dmesg | grep P73-ILOCK-STUCK` == 0 cluster-wide; grep `P74-IFNEXT-SKEW` to see if the barrier triggered.
3. If still silent loss: check whether it's residual corruption (grep `Corruption|corrupt dinode|trans_cancel`) → harden FIX2 / pursue Gemini fix (c) cascade containment; or genuine dirent loss (dir reads but entries missing) → reload/coherency.
4. Then full `--iters 3`, then the other 3 FAILs: fence_during_write (lost=400), rsync_paired (148%), posix_semantics_multi16 (>600s — same hot-dir family, likely helped by FIX 1).

### Gemini consult (RULE 5, justified) summary
DLM serializes mkdir ENTRY not the metadata writeback lifecycle across N buffer caches. (a) release fence should be LSN-based: xfs_log_force_lsn + xfs_ail_push_sync(lsn) destages EVERYTHING up to the inode's last LSN (not guess which buffers). (b) assert real-iext-count==if_nextents at write boundary (→ FIX 2, but reconcile instead of BUG to avoid the cascade). (c) contain force_shutdown: don't write log/unmount, don't disturb PR keys → no reservation storm. (d) bigger: delegation/RPC so only the lock owner ever caches/writes the hot dir.

Links: [[sess73-zsl-ondisk-dinode-bmbt-inconsistent-writer-torn]] [[sess65-zsl-dlm-handoff-metadata-coherency-root]] [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]]
