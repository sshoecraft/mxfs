---
name: ccloop-c7ee71c6-sess48-STEP2b-AUDIT-PASS-cil-barrier-exists
description: sess48 STEP-2b AUDIT PASS: CIL-stability barrier already exists (double xfs_log_force(SYNC) pre-drain in bast Phase 2); step-3 directive = capture to…
metadata:
  type: project
---

# Step 2b — CIL-drain-at-release audit: PASS (no code needed)

## Evidence (xfs/xfs_mxfs_dlm.c bast_work_fn Phase 2, ~38955-39000)
Release sequence before mxfs_v5_dlm_ag_unlock:
```
xfs_log_force(mp, XFS_LOG_SYNC);   // CIL push formats EVERY resident item; waits for log I/O
msleep(3);                          // v0.3.104: async CIL→AIL completion window
xfs_log_force(mp, XFS_LOG_SYNC);   // catches gap items
mxfs_dlm_ag_drain_meta_buffers(pag);
mxfs_blkdev_flush_epoch(mp);
```
Plus a second force at ~38833 before the bounded per-AG AIL drain. This satisfies the GPT ruling's non-negotiable ("force and wait for all CIL/log items authorized by the grant to be formatted and stable before release"):
- Every G1-tenure item is FORMATTED (CIL push) and log-stable (SYNC wait) before unlock.
- Phase 2 sets demoting=true blocking concurrent local acquires, and release proceeds only at holders==0 ⇒ no new AG-item commits between the force and the unlock.
- Deferred release path (mxfs_dlm_ag_release_work_fn): entered only when pag_dlm_meta_pending==0 = every logged AG-meta buffer completed WRITEBACK (which requires prior CIL formatting) ⇒ covered.
- Unmount force_release_all: log quiesced before it runs ⇒ covered.

## The G1→G2 relog question (ruling's misattribution hazard) — resolved
An item relogged after reacquire formats under G2 while the node ACTUALLY holds G2 — correct attribution (the image is authorized by the current grant). The hazard would need an item formatted while the authorizing grant was already gone; excluded by the sequence above.

## Step-3 design directive that falls out
**Capture the token at CIL FORMAT time** — in xfs_buf_item_format (iop_format, CIL push context): daddr→agno→xfs_perag_get (atomic) → read pag->pag_mxfs_grant_epoch (+ resource_class by b_ops/daddr: AG vs GLOBAL_SB vs other). NOT at xfs_trans_log_buf time (an item can be relogged across tenures; format time is when the emitted image is fixed). pag epoch is stable at any format: post-release formats of that AG cannot exist (above), and the epoch field only changes at the next fresh acquire under pag_dlm_lock.
Remaining step-3 work: extend xfs_buf_log_format encoding (new blf_flags bit + trailing token after the dirty bitmap — check how blf size is computed in xlog_copy... / recovery's item parse), log-incompat feature flag, replay-side parse into a token struct; then steps 4-5 per ...-STEP2a-SHIPPED memory.

## Criteria: NO — 11 OPEN of 39 (4 critical). 0.11.396 fleet-wide, 13 clean cycles standing.
