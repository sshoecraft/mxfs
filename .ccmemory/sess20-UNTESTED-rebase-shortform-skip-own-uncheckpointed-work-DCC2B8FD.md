---
name: sess20-UNTESTED-rebase-shortform-skip-own-uncheckpointed-work-DCC2B8FD
description: sess20(ccloop) UNTESTED build DCC2B8FD: added guard to mxfs_dir_rebase_shortform (xfs_mxfs_dlm.c ~3838) - SKIP the disk-reload rebase when the dir in…
metadata:
  type: project
---

## sess20 (ccloop) — UNTESTED fix at relay boundary: rebase-shortform own-work guard

### Build `DCC2B8FD` (from 4E047A49, builds clean). TEST THIS FIRST next session.

### Change (1 hunk, xfs/xfs_mxfs_dlm.c `mxfs_dir_rebase_shortform` ~line 3838, right after the `if_format != LOCAL` return):
```c
if (xfs_ipincount(dp) > 0 ||
    (dp->i_itemp &&
     (test_bit(XFS_LI_IN_AIL, &dp->i_itemp->ili_item.li_flags) ||
      test_bit(XFS_LI_DIRTY, &dp->i_itemp->ili_item.li_flags))))
        return;
```
Skips the wholesale disk-shortform adopt when the node holds its OWN un-checkpointed dir work (in-AIL / pinned / dirty log item).

### WHY (root PROVEN this session, see [[sess20-rename-miss-root-rebase-shortform-clobbers-own-uncheckpointed-create]]): rebase_shortform adopted the peer's disk image which LACKED the node's own just-created (committed-not-checkpointed) dirent → clobbered it → rename src lookup ENOENT → RENAME-REVALIDATE-MISS false-abort → tcp_dlm_scaling 0 rounds (4/tcp test2 3/4). A clean PR/NL cacher (sess49 P43 fix) has no log item/unpinned → still rebases → no regression.

### TEST PLAN next session:
1. Deploy DCC2B8FD. Clean reboot. Run `./run.sh 4 tcp tcp_dlm_scaling` several times (flaky — needs repeats) — confirm test2/all nodes complete 150 rounds (no RENAME-REVALIDATE-MISS). Also `./run.sh 8 tcp tcp_dlm_scaling` (still 8/8, <60s).
2. Re-verify NO regression: `./run.sh 8 tcp cache_coherency` + `strong_consistency` + `dir_reuse_coherency` (the rebase is load-bearing for cross-node shortform coherency — the guard must not break peer-change adoption; it only defers while WE have un-checkpointed work, so cross-node reads (clean inode) still rebase).
3. If clean: FULL `./run.sh 8 tcp` + `4 tcp` + re-verify `1 tcp`/`2 tcp` on this build.

### REMAINING 8/tcp residuals after this (if it works): dir_reuse in-suite 348s TIMEOUT (speed, [[sess20-8tcp-residuals-dir_reuse-348s-and-dlm_scaling-flaky]]) + dlm_scaling window flake. Build 4E047A49 = last KNOWN-GOOD (format-gate, 16/17). The format-gated mht ([[sess20-BREAKTHROUGH-format-gated-mht-shortform-dirs-low-mht]]) is the core KEEP.
</body>
</invoke>
