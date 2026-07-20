---
name: sess9-root-durable-revert-and-publish-only-regression
description: sess9: FIXED 2 proven roots of 2/tcp shortform lost-update (xfs_remove/rename now destage the cluster; mxfs_inode_cluster_durable now submits -EAGAIN…
metadata:
  type: project
---

## STATE: build **427DB5AF5E91C4624087630** (best; deployed via reboot). Full 2/tcp ~15/16, dlm_fairness 29/30. Residual rotates: dlm_fairness/crash_consistency/tcp_dlm_scaling all `durable got=N` / `exp= got=hash`. Criterion NOT met. Marker NOT written. Fallbacks: D50C9CF4, 1AB8C27A.

## ENV (see [[storage-backend-is-lio-fileio-not-scst]]): LIO fileio/disk.img/virtio-scsi single-host COHERENT; QNAP iSCSI disabled. NOT storage.

## FIXED THIS SESSION (KEEP, in 427DB5AF) — failure rate down ~3× (was ~1/8, now ~1/30)
1. **xfs_remove + xfs_rename never destaged the shortform dir cluster** (only xfs_create did). Added `if(!dp->i_mxfs_self_created) mxfs_dlm_dir_inode_durable(dp/src_dp/target_dp);` after the ILOCK drop in both (xfs_inode.c).
2. **`mxfs_inode_cluster_durable` (xfs_mxfs_dlm.c:1513) bailed on -EAGAIN+IN_AIL** — RULE-4 PROVEN (P9-ICD-FAIL pin=0 in_ail=1 clean=1): inode already iflushed into the cluster buffer but buffer still delwri/IN_AIL = committed image in-core, NOT on disk; old code retried 8×2ms and gave up. FIX: `if(rerr==-EAGAIN && IN_AIL) rerr=0;` → submits the buffer via the native delwri path. Also retry 8→25.
3. (carried) P9 shortform coherency check `mxfs_dir_sf_refresh_if_disk_differs` (xfs_mxfs_dlm.c ~6175) on the dir fast-path (PR+EX), clean-gated (pin/ili_fields/IN_AIL). KEEP.

## RESIDUAL ROOT (~1/30): cached-EX-outlives-grant STALE-BASE RMW
Durable resurrection, **P9-ICD-FAIL=0, P-DOUBLEGRANT=0**. A node holds i_dlm_mode==EX CACHED but a deferred BAST (bast_notify ACQUIRING/pin branch) set i_dlm_stale WITHOUT demoting; the dir EX fast-path (xfs_mxfs_dlm.c ~6530 dir-strict gate) doesn't honor i_dlm_stale, so it RMWs the stale shortform fork and durably re-writes a peer's removed dirent. There is also a DESTAGE RACE: disk is transiently mid-update right after a removal, so a reload in that window can revert.

## TWO FIXES TRIED THIS SESSION AND REFUTED (do NOT repeat)
- **A) Force slow-path when i_dlm_stale** (added `i_dlm_stale ||` to the ~6530 dir-strict gate, build 58EB95A8): REGRESSED to STARVATION — dlm_fairness `got=7` (node1 only 7/50 rounds). i_dlm_stale is set frequently under churn → every op a DLM round-trip+reload → SESS50-STARVE timing wall (sess43). Reverted.
- **B) Relax P9 clean-gate (drop the IN_AIL skip)** (build 223CA589): WORSE — 27/30 (more reverts). With IN_AIL dropped, P9 reloads while disk is transiently mid-destage and reverts our own committed removal. The IN_AIL skip is PROTECTIVE against the destage race. Reverted.

## NEXT SESSION (new angles — A and B are dead ends)
1. Fix the DEFERRED-BAST so it is eventually HONORED (demote) instead of letting the node fast-path indefinitely on a stale cached EX — without forcing a reload on every op. I.e. when i_dlm_stale has been set for >T, force ONE demote+reload at a natural boundary, not every acquire. Look at bast_notify deferral (xfs_mxfs_dlm.c ~4540) + why the node keeps re-grabbing (fairness/defer_for_waiter sess50).
2. Make P9's reload RACE-SAFE vs destage: only adopt disk if the on-disk dinode's di_lsn/gen proves it post-dates our last committed change (avoid reverting on a mid-destage read). Then the IN_AIL skip can be dropped safely.
3. True shortform MERGE in the reload (keep our committed adds by di_lsn, drop entries disk lacks).
Validate: dlm_fairness 30x + full suite 3x (reboot between) 16/16; rsync wall RULE-0. Related [[sess84_lessons]] [[sess85_lessons]] [[sess88_lessons]].
