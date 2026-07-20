---
name: sess12-convblk-doublegrant-fix
description: sess12: FIXED a PROVEN 2/tcp double-grant root (P-CONVBLK-REMOVE) — blocked inode-upgrade now denies->EDEADLK instead of removing holder. Build F967E…
metadata:
  type: project
---

## Criterion = full `./run.sh 2 tcp` 100% (all 16). NOT met yet. Marker NOT written. Build **F967E0F587960FC0EC155CB** (deployed via run.sh prep, both nodes).

## PROVEN ROOT FIXED THIS SESSION (RULE 4): TCP DLM blocked-upgrade DOUBLE-GRANT (P-CONVBLK-REMOVE)
- `dlm/dlm.c` process_remote_request (~2383) AND local mxfs_dlm_lock (~1056): on a BLOCKED upgrade (sender holds GRANTED lower mode e.g. PR, requests EX, conflicts with another holder), the OLD code REMOVED the sender's GRANTED entry and re-queued it WAITING — but the sender still LOCALLY holds the lower grant (i_dlm_mode), so removal made it INVISIBLE to other nodes' compat scans (which skip non-GRANTED). A peer then gets granted a conflicting mode -> two nodes hold incompatible grants -> stale-read/dir lost-update.
- **PROVEN**: `P-CONVBLK-REMOVE sender=... type=1(INODE) held_mode=PR req_mode=EX` fired on test2 (master) during a crash_consistency FAILURE. The failing reader (test1) had its PR entry removed while still holding PR -> read a dir missing the peer's newly-added dirent (node2_f50.md5 invisible, converged later = transient stale, not durable loss).
- **FIX** (3 edits): (1) include/mxfs/mxfs_common.h: new enum `MXFS_ERR_UPGRADE_CONFLICT`. (2) dlm.c sender return map (~936): `MXFS_ERR_UPGRADE_CONFLICT -> -EDEADLK`. (3) both blocked-upgrade sites: for `resource->type==MXFS_LTYPE_INODE`, KEEP the grant visible + return/deny with the new code (P-CONVBLK-DENY). The XFS ilock layer's EXISTING P109 path (xfs_mxfs_dlm.c ~7182) then drops the lower grant THROUGH the BAST drain pipeline (in sync) and re-acquires FRESH via clean FIFO — no double-grant, no conversion deadlock. Scoped to INODE (AG keeps legacy remove+requeue).
- **RESULT**: P-CONVBLK-REMOVE=0 now; P-CONVBLK-DENY active (2-7/run). crash_consistency PASSES 3/3 runs (was the baseline failure). dlm_fairness no starvation regression.

## REMAINING RESIDUAL (rotating ~1 test/full-suite-run): shared-hot-dir shortform STALE-BASE RMW resurrection
- Same root across {tcp_dlm_scaling, fence_during_write, crash_consistency, dlm_fairness}: a shared dir where BOTH nodes rapidly create→rename→remove their OWN entries; rank1 asserts dir empty; a REMOVED entry RESURRECTS (durable, both nodes see it). e.g. tcp_dlm_scaling left `n2_r5`/`n2_r6.done`; fdw left got=2.
- **P-DOUBLEGRANT=0, P9-ICD-FAIL=0** at failure (NOT a master-table double-grant, NOT an inode-cluster-durable fail). This is sess9's identified residual [[sess9-root-durable-revert-and-publish-only-regression]]: cached-EX-outlives-grant / shortform refresh skipped under own-churn (mxfs_dir_sf_refresh_if_disk_differs IN_AIL-gated skips exactly when the node has uncommitted mods).
- bast_process DOES make the shortform dinode durable before unlock (ail_drain_inode_sync + blkdev_issue_flush) — release-side durability looks OK. So the gap is ACQUIRE/serve-side: node serves a dir EX RMW on a stale cached base.
- Refuted (sess9, do NOT repeat): force slow-path on i_dlm_stale -> STARVATION (dlm_fairness got=7); drop IN_AIL gate -> destage-race reverts own removal.
- NEXT: GPT verdict [[sess10-gpt-verdict-serialize-tenure-not-epoch]] = reload-on-reacquire made reliable; sess9 next-step = race-safe reload via di_lsn/gen (adopt disk only if it post-dates our last committed change). Validate FULL `./run.sh 2 tcp` x3 FOREGROUND, watch dlm_fairness (no starvation) + RULE-0 timing. Baseline pre-fix=5EC1F0BF. Cluster bringup after reboot: [[env-cluster-bringup-after-host-reboot]].
