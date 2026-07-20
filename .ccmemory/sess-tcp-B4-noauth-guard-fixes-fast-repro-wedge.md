---
name: sess-tcp-B4-noauth-guard-fixes-fast-repro-wedge
description: FIX (build B4168BB5): B4 no-authority inact guard skips destructive free when local_unlink=0 + dlm_mode=NL + coh_nlink=0 outside log recovery → fast-…
metadata:
  type: project
---

## FIX for the deep stale-INODE double-free wedge (the last 2/tcp blocker)
Build **B4168BB57ABD4ED3936F637** (xfs/xfs_inode.c, ~line 2763).

### Root (proven by P19-B3DEC instrumentation, sess-tcp fast repro):
Killer inode signature at the shutdown: `disk_mode=0100644 (live), disk_gen==incore_gen
(match), coh_nlink=0, local_unlink=0, dlm_mode=0 (NL)`. The old guard cases all MISS:
b1_diskfree=0, b2_genmis=0, b3_tornlive=0 (B3 requires coh_nlink>0). So it fell through to
xfs_ifree → frees blocks the peer's on-disk inode still owns → inobt -117 → FS shutdown.
This is a node destructively inactivating a STALE CACHED copy of a peer's inode (instantiated
via readdir/lookup of the shared dir, then driven to nlink==0 by a peer-coherent reload) that
the PEER actually unlinked and will free itself.

### Fix = B4 "no-authority" skip:
```
bool mxfs_b4_no_authority = !mxfs_local_unlink &&
    ip->i_dlm_mode == MXFS_LOCK_NL &&   /* hold no grant */
    mxfs_coh_nlink == 0 &&
    !xlog_recovery_needed(mp->m_log);   /* gate: see below */
```
Added to the INACT-SKIP-STALE condition (reason="no-authority-unlocked-not-unlinked").
A node with no local-unlink intent AND no DLM lock has no authority to free the inode; the
unlinking peer (holds EX, local_unlink=1) frees it. **Gate on !xlog_recovery_needed**: during
MOUNT-TIME iunlink log recovery the survivor MUST free a dead peer's orphaned inodes (also
local_unlink=0 + NL + coh_nlink=0 by construction) — must NOT skip then. NOTE: mxfs dead-peer
recovery is `mxfs_journal_replay` (dlm/mount.c recover_dead_node_journal), NOT xfs_inactive, so
the only legit xfs_inactive free-of-not-locally-unlinked is mount-time iunlink recovery.

### PROVEN: fast repro (2-node 3000 create+unlink storm in shared dir, ×4 rounds) — NO wedge,
both nodes mounted+writable. Captured `ino=2100207 ... b4_noauth=1 will_skip=1` = the exact
killer caught & skipped. Previously test2 shut down in ~seconds on round 1.

### Possible cost: a leaked inode if the unlinking peer dies AFTER we cache it and AFTER mount
recovery already ran (rare). A leak (fsck-recoverable) is strictly better than a double-free
shutdown. Watch crash_consistency for regressions. Next: full `./run.sh 2 tcp` (16 tests).
See [[sess-tcp-FAST-REPRO-wedge-and-classification]] [[sess-tcp-HANDOFF-deep-inode-wedge-is-last-blocker]].
