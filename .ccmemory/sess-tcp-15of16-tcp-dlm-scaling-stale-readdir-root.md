---
name: sess-tcp-15of16-tcp-dlm-scaling-stale-readdir-root
description: 2/tcp now 15/16 (build F053F523, B4 !=EX fix). Sole FAIL=tcp_dlm_scaling: stale readdir leftover dirent (nlink=0) — event-driven reload misses lost D…
metadata:
  type: project
---

## STATE: 2-node TCP suite = 15/16 PASS (build F053F523, srcversion F053F52324088587BD3D703)
ALL pass except **tcp_dlm_scaling** (1/2 nodes). The B4 inode guard (below) cleared the
shutdown cascade; cache_coherency/posix_multi/crash_consistency/soak all PASS now.

### B4 fix (KEEP, in xfs/xfs_inode.c ~2763): broaden the no-authority inactivation skip.
`mxfs_b4_no_authority = !local_unlink && ip->i_dlm_mode != MXFS_LOCK_EX && coh_nlink==0 &&
!xlog_recovery_needed(mp->m_log)`. (Started as ==NL; broadened to !=EX after a 2nd shutdown
case showed dlm_mode=3/PR also slips through.) A node with no local-unlink intent and not
holding EX has no authority to destructively free a coh_nlink==0 inode (peer that unlinked it,
holding EX, frees it; mount-time iunlink recovery handles dead-peer orphans — hence the
!recovery gate). PROVEN: 8-iter 2-node rename storm no longer shuts down (was instant wedge).

### tcp_dlm_scaling SOLE BLOCKER = STALE READDIR (not a shutdown, not a double-free):
Test: each node does 150× `create+rename(.done)+rm` of its OWN files in a SHARED dir, then
node1 checks `ls $D` drained to 0. FAIL: node1 sees 1 leftover dirent (e.g. n2_r112.done or
n2_r1) that is a NODE2 file, **nlink=0** (inode IS freed — stat reads fresh nlink=0 — but the
DIRENT persists in node1's cached dir). Persistent: survives drop_caches. DIR-STALE-SKIP=0 (NOT
the known dirty-block lost-update window).

ROOT: `xfs_readdir` (xfs/xfs_dir2_readdir.c:554-561) reloads the dir ONLY when MXFS_IF_DIR_RELOAD
is set — armed solely by a peer's DIR_MODIFY evict-ring event. SHORTFORM dirs (line 563) bypass
even the i_dlm_dir_gen block-invalidation (xfs_da_read_buf). When node2's FINAL dir-modify's
DIR_MODIFY event is lost/not-delivered (intermittent in TCP — see
[[sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg]], sess82 evict-ring-never-delivered),
node1 never arms reload and serves a stale cached dir. After churn ends nothing re-triggers a
refresh → persistent.

### FIX DIRECTION (event-INDEPENDENT, GFS2 pattern): in xfs_readdir multi-node mode, when the
node holds NO current grant (dp->i_dlm_mode == MXFS_LOCK_NL → a peer COULD have modified since
we released), force a coherent reload instead of relying on the async event. Sound because if we
held PR/EX no peer could have modified (inode-EX is exclusive; the last dir-modifier holds EX,
the reader sits at NL). MUST verify readdir actually ACQUIRES a PR grant (NL→PR) so repeated
readdirs of a hot dir don't reload every time (the sess38/91 per-readdir-poll 100x regression).
Check the xfs_ilock→mxfs DLM hook (xfs_inode.c ~177/299) for whether getdents acquires the grant.
Repro: tests/tcp/repro_rename_drain.sh (150 8). See
[[sess-tcp-B4-noauth-guard-fixes-fast-repro-wedge]] [[sess41-shortform-dir-evict-gap-root]].
