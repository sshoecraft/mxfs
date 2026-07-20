---
name: sess53-CRITICAL-idempotent-iunlink-may-mask-real-unlinked-list-corruption
description: sess53 CRITICAL: p2 shutdown = xfs_inactive_ifree -117 "unrecovered unlinked inode" — idempotent-iunlink no-op (sess53) likely MASKS real unlinked-li…
metadata:
  type: project
---

## sess53 CRITICAL CAVEAT — re-examine the idempotent-iunlink fix

### p2 (build 21C36EEA) shutdown on node1:
```
P19-B3DEC ino=8389594 agno=4 ... disk_mode=0100644 dlm_mode=5
XFS (sda): Found unrecovered unlinked inode 0x39a in AG 0x4.  Initiating recovery.
XFS (sda): xfs_inactive_ifree: xfs_ifree returned error -117
XFS (sda): Metadata I/O Error (0x1) at xfs_inactive_ifree+0x2e9/0x410 (xfs/xfs_inode.c:2526). Shutting down.
```
This is a genuine UNLINKED-LIST (AGI di_next_unlinked chain) corruption surfacing at ifree (-117 = EFSCORRUPTED), NOT the precommit old_ptr mismatch.

### HYPOTHESIS (next session verify): the sess53 idempotent-iunlink no-op (xfs/xfs_iunlink_item.c xfs_iunlink_log_dinode: when old_ptr==next_agino==i_next_unlinked → no-op instead of force-shutdown) is MASKING a REAL unlinked-list corruption rather than handling a benign stale-item. The free/reuse race that makes old_ptr already==next_agino may indicate the chain is genuinely inconsistent (a duplicate/lost link), so skipping the precommit lets a corrupt chain persist → xfs_ifree later finds an "unrecovered unlinked inode" → shutdown. i.e. the precommit old_ptr check was catching a REAL bug; the no-op defers the crash to ifree.

### ACTION for next session:
1. Consider REVERTING the idempotent-iunlink no-op and instead root-cause the unlinked-list corruption under rapid free→reuse→free on a SHARED dir's child inodes (multi-node AGI/unlinked-bucket coherency). The P53-IUNLINK-MISMATCH diag (still in tree) shows old_ptr/old_agino/i_next_unlinked/uncp at the mismatch.
2. Net reliability of 21C36EEA: p1=16/17 (fence_during_write dirent leak), p2=14/17 (this shutdown + cascade). So the build is NOT clearly better than the d1-d5 baseline (4/5, leak-only, NO shutdowns). The GPT EX-gate + clean-adopt (merge suppression) are sound and KEEP; but idempotent-iunlink is SUSPECT.
3. Two independent residuals remain: (a) durable dirent leak = release-side shortform durability race ([[sess53-FINAL-residual-is-release-durability-race-with-churn]]); (b) unlinked-list corruption under inode reuse (this memory). BOTH must be fixed for reliable 17/17.
4. Baseline to compare against: D67776EC (plain defaults + P52, NO sess53 code changes) = 4/5 leak-only. If sess53 changes don't beat that, revert to D67776EC and attack the leak + iunlink roots fresh.
Related: [[sess53-FINAL-residual-is-release-durability-race-with-churn]] [[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]]
