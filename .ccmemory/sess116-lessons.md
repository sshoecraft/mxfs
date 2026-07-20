---
name: sess116-lessons
description: sess116 (ccloop 4eef1f39 s8) — cache_coherency 1/4→3/4. 3 fixes: bast NULL-deref unmount crash, inode self-clobber on reused-ino create. Last fail =…
metadata:
  type: project
---

# sess116 (ccloop run 4eef1f39, session 8)

**cache_coherency: 1/4 → 3/4 passing.** cross_visibility, rename_visibility,
unlink_visibility now PASS. Only **cross_write_read** still FAILS.
Current build head: `86420BFE` (clean, deployed on test1-4).

## Fixes landed this session (all KEEP)

1. **bast NULL-deref unmount crash → module wedge (FIXED, verified).**
   A pending inode bast work (`mxfs_dlm_bast_work_fn`) holds an inode ref
   (xfs_irele at end) → that inode stays "Busy inodes after unmount" → reclaim
   skips it → its work never cancelled → fires after `xfs_unmountfs` freed
   `mp->m_log` → `xfs_log_force` does `spin_lock(&log->l_icloglock)` with
   log=NULL → CR2=0x10, RIP xfs_log_force+0x84, wedges module at refcount -1.
   FIX: dedicated per-mount workqueue `m_mxfs_inode_bast_wq` (xfs_mount.h)
   created in xfs_super.c (alloc_workqueue UNBOUND|MEM_RECLAIM), 3 inode-bast
   `schedule_work` sites in xfs_mxfs_dlm.c now `queue_work` it, and
   `xfs_fs_put_super` does `flush_workqueue(m_mxfs_inode_bast_wq)` BEFORE DLM
   shutdown / xfs_unmountfs. Plus a top-of-`mxfs_dlm_bast_process` guard
   (`!mp->m_log || xfs_is_unmounting`) as defense-in-depth. Verified: all
   nodes unload cleanly, zero BUG/Oops after a full run.

2. **Inode SELF-CLOBBER on reused-ino create (FIXED, the big one).**
   PROVEN via minimal reproducer: test1 `mkdir /mnt/shared/rx`, test2 can't
   see rx. On the CREATOR: P106-MKDIR new_ino=157 → P108-REACQUIRE "on-disk
   slot lost; forcing slow-path re-acquire" → reload reads on-disk cluster for
   157 which is STILL FREE (di_mode=0, create only LOGGED not checkpointed) →
   xfs_inode_from_disk clobbers the fresh in-core dir to mode=0
   (P-RELOAD-IOPS-REWIRE old=040000 new=00) → rx vanishes even on creator.
   Existing `dip->di_format==0` skip MISSES it when the ino was REUSED
   (rm+mkdir): on-disk cluster keeps prior incarnation's nonzero di_format
   while di_mode reads 0. FIX (xfs_mxfs_dlm.c, `mxfs_dlm_reload_inode`, just
   before the di_format==0 guard ~line 2751): if on-disk `di_mode & S_IFMT==0`
   but in-core `i_mode & S_IFMT!=0` AND in-core is dirty (i_pincount>0 ||
   ili_fields || XFS_LI_IN_AIL) → skip reload, keep in-core. Log
   `P116-RELOAD-SELFCLOBBER-SKIP`. Verified: concurrent 4-node mkdir -p+touch
   20/20 OK (was test2/3/4 rounds 2-5 all FAIL).

## REMAINING BLOCKER — cross_write_read (1-2 fails / 6 asserts)

Each node writes 1MB `data_nodeN` + tiny `data_nodeN.md5`, barrier, peers read
+ verify md5. Failures are NOT the 1MB data (reads correct everywhere). They
are: **node1's small `.md5` file read as EMPTY (`expected=''`) by peers 2/3/4.**
i.e. a small/shortform-data file written by node1 is read zero-length/empty on
peers (stale di_size=0 / empty data fork in peer's reloaded inode). Same family
as sess45 (di_size=0 cwr = atime EX clobber), sess85 (shortform lost-update).
Only node1's .md5 affected, not node2/3/4's — node1 is the TESTDIR creator / ran
first.

## NEXT SESSION
Build a fast reproducer: node1 writes a tiny file, peer cats it (expect empty).
Trace peer's iget/reload of node1's file inode — likely di_size=0 / empty
if_data on the peer's read. Then fix, re-run cache_coherency (must hit 4/4),
then full `tests/criteria/verify_ship.sh` end-to-end for the marker.
Reproducer infra: `tests/reset4.sh 4` to deploy+mount; minimal repro is just
ssh mkdir/cat across test1→test2. cache_coherency.sh runs all 4 subtests in
~20s when healthy (no crash). NODE OFFSET: criteria use test1-4 directly.

Marker NOT written (3/4).
