---
name: sess57-dir2format-disize-corruption-modify-gap
description: sess57: DOMINANT clean-gate root = xfs_dir2.c:287 di_size!=blksize EFSCORRUPT in xfs_create; modify_refresh evicts data blocks but NOT di_size/extent…
metadata:
  type: project
---

# sess57 — DOMINANT clean-gate shutdown root: dir2_format di_size corruption (MODIFY-path reload gap)

Supersedes the ino=128 EX-starvation theory as the PRIMARY blocker (that was test1
only, contaminated by an earlier harsh rm-rf repro). The CLEAN gate's real shutdowns:
6 nodes (test7/8/10/12/14/16) shut down WITHIN 1s of each other during a concurrent
create storm, identical signature:
```
XFS (sda): Internal error dp->i_disk_size != geo->blksize at line 287 of xfs/libxfs/xfs_dir2.c
           Caller xfs_dir2_format+0x1f2
XFS (sda): Internal error xfs_trans_cancel at line 1060   Caller xfs_create+0x5da
Corruption of in-memory data (0x8) -> Shutting down filesystem
```
Breaks **zero_silent_loss** (#13) and **posix_semantics_multi16** (#19).

## Mechanism (PROVEN by code + signature; one probe away from full proof)
`xfs_dir2_format` (xfs/libxfs/xfs_dir2.c:266) for a non-shortform dir:
- `eof = xfs_bmap_last_offset(DATA_FORK)`; if `eof == 1 block` it's treated BLOCK format.
- Line 287: `XFS_IS_CORRUPT(dp->i_disk_size != geo->blksize)` -> for BLOCK fmt di_size MUST==4096.

The MODIFY paths (create/remove/rename) call `mxfs_dlm_dir_modify_refresh` (xfs_mxfs_dlm.c:1248)
which ONLY does `mxfs_dir_evict_data_blocks(dp)` — evicts cached dir DATA blocks so the next
read cold-fetches the peer's image. It does NOT rebuild the data-fork EXTENT MAP and does NOT
refresh `di_size`. A full `mxfs_dlm_reload_inode` WOULD fix both but self-deadlocks on
`down_write(i_lock)` under the held ILOCK_EXCL (documented at xfs_dir2.c:296-300 and dlm.c:1181).

Result: peer grows dir shortform->block (di_size 67->4096, 0->1 extent). This node has stale
di_size (still ~67) but its xfs_create cold-reads block 0 and xfs_bmap rebuilds the extent map
to eof==1 block -> `eof==1 && di_size!=4096` -> EFSCORRUPTED -> trans_cancel -> shutdown.
i.e. di_size and the extent map come from DIFFERENT incarnations (extent map fresh via cold
read, di_size stale because evict doesn't touch it).

sess56's A1F53770 fixed the LOOKUP/READDIR reload (MXFS_IF_DIR_RELOAD consumed at dlm.c:1192)
but the MODIFY path reload gap REMAINS — this is that gap biting.

## NEXT (RULE 4)
1. PROBE at xfs_dir2.c:287 (fire on the corrupt branch, NOT gated — rare): dump di_size,
   if_format, if_nextents, eof, i_dlm_dir_gen, i_dlm_dir_loaded_gen, MXFS_IF_DIR_RELOAD,
   i_dlm_dir_evicted_gen, comm. Confirms di_size stale vs extent map fresh + reload pending.
2. FIX candidates (need to refresh di_size+extent-map WITHOUT down_write self-deadlock under
   ILOCK_EXCL): (a) in modify_refresh, after evict, re-read the on-disk dinode core (di_size +
   format + extent map) directly from the inode-cluster buffer via xfs_imap_to_bp + a
   lightweight in-place core/fork refresh that does NOT take i_lock (the caller already holds
   ILOCK_EXCL, which is the XFS inode lock; the deadlock is on the mxfs i_dlm down_write, so an
   xfs_iread-style fork rebuild that skips the dlm lock may be safe); OR (b) check whether
   xfs_inode.c:3388 calls modify_refresh BEFORE xfs_ilock(ILOCK_EXCL) — if so a real reload is
   possible there. VERIFY caller lock state first.

## Caller sites of mxfs_dlm_dir_modify_refresh
xfs/xfs_inode.c:1323, 3388 (create), 3775/3777 (rename src/target). Check ILOCK state at each.

Related: [[sess57-clean-rerun-true-state-ino128-deadlock]] (the gate dashboard + secondary roots),
[[sess53-agi-insert-stale-head-shutdown-fix]], sess56 dir-format fix (build A1F53770).
Secondary blockers still open: fence_during_write lost=400, rsync_paired 148%.
