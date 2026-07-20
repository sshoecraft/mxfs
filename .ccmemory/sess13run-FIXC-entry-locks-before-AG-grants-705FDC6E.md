---
name: sess13run-FIXC-entry-locks-before-AG-grants-705FDC6E
description: sess13 FIX-C (705FDC6E): remove/rename park-hold eliminated — entry locks FIRST, AG grants after under clean trans. Old-build baseline: face 1-in-4 i…
metadata:
  type: project
---

# sess13 FIX-C — no task holds AG grants while parked on entry locks

## The proven defect (r16 stack, P12-HOLDERTASK + P36-STACK)
sess58's p58 pre-lock child-AG hold in xfs_remove PARKED the task holding AG-0 EX
while waiting for the hot dir's inode DLM lock inside xfs_trans_alloc_dir →
xfs_lock_two_inodes. Peer rm holding that dir in defer_finish starved 60s on AG-0
→ rc=-110 → dirty-cancel shutdown = fence/netpartition/tcp_dlm_scaling triple-FAIL.
The pre-acquire INVERTED the hold-and-wait edge instead of removing it.
xfs_rename's mxfs_trans_preacquire_inode_ags had the same shape (held AG grants
across xfs_lock_inodes).

## FIX-C (build 705FDC6E1362E3FA65EFF62, both sites, one mechanism)
- **Invariant**: entry (inode/dir) locks FIRST; AG grants acquired AFTER, while
  trans is still CLEAN → acquire timeout = clean cancel (+ bounded retry in
  remove, `P13-CLEANRETRY` pr_warn, 3 tries), never a dirty-cancel shutdown.
- xfs_remove: p58 block deleted; `mxfs_trans_preacquire_inode_ags(tp, &ip, 1)`
  right after xfs_trans_alloc_dir; release deferred to commit/cancel
  (t_mxfs_ag_unlocks) — replaces both manual unlock blocks; retry label
  `p13_retry` re-runs prelock-reload + trans_alloc_dir.
- xfs_rename: preacquire call MOVED from before xfs_lock_inodes to after the
  ijoins (error → out_trans_cancel which unlocks via xfs_iunlock_rename).
- Helper contract comment updated (xfs_mxfs_dlm.c ~23788).

## Why the system converges now
Dirty defer_finish AG waits (dir→AG, unavoidable) succeed because every AG holder
is either actively working (bounded ms) or BAST-releasable (holders==0 cached).
create's pinned-dir-grant-across-dialloc (FIX3) is the mirror direction
(hold dir, wait AG) and is harmless once no one holds-AG-waits-dir.

## Residual audit items (NOT fixed, no evidence yet)
- xfs_inactive_ifree holds AG across xfs_ilock(dying inode) — bounded (no peer
  parks holding a dead inode's grant); never in holder stacks.
- Dirty AG-AG ABBA across DIFFERENT dirs (cross-AG dir-block frees) —
  theoretically possible if upstream AGF ascending order is violated by defer
  intents; never observed.
- xfs_link: dir→AG dirty edge on dirent-block alloc, no preacquire; converges
  post-FIX-C for the same reason defer_finish does.

## State
- Old-build (5BE16AA5) ladder final: 17/17, 14/17(face), 17/17, 17/17 → face
  fires ~1-in-4 iters. New 6-iter ladder on 705FDC6E launched 03:57Z
  (/tmp/suite_ladder_20260704T035744Z.log), ~11 min/iter.
- Next: 6× clean on 4/tcp → then 8/tcp ×2-3, 2/tcp, 1/tcp on SAME build.
- Probe greps for the face: `P12-HOLDERTASK`, `P36-STACK`, `DLM AG lock failed`,
  `P13-CLEANRETRY` (new, should be ~0), in /tmp/run_*/kernlog_test* and
  /tmp/suite_iter_probes_*.log.
