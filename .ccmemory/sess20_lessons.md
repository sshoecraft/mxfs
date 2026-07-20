---
name: Sess20 MXFS debugging — Mode A is multiple races, not dir-stale
description: 16-version sess20 (v0.3.37→v0.3.52) explored Mode A. KEY FINDING: bast_process IS persisting dir content correctly (P21-INSTR proven). Mode A is actually 4+ distinct inode/AG-side races.
type: project
originSessionId: 3905302f-bf9b-43ab-bcac-fce02895bef0
---
# Sess20 (2026-05-02) MXFS — 16 versions, Mode A debugging

**Final state**: v0.3.52 in tree ≈ v0.3.36 baseline + Approach A scaffolding (no behavioral change). All other sess20 attempts reverted.

## THE BIG FINDING — invalidates 3 prior sessions of work

**bast_process IS persisting dir content to disk correctly.**

v0.3.44 with P21-INSTR added a pr_warn at PRE-UNLOCK that read disk dinode and logged mem_size vs DISK_size. Result: every PRE-UNLOCK in the captured stress run showed `mem_size == DISK_size`. The dir content WAS on disk before the DLM grant was released.

**Sess14, 16, 19 spent enormous effort on the "dir-stale Mode A" hypothesis. The hypothesis was WRONG.** Mode A's external symptom (`xfs_remove → xfs_trans_cancel(0x8)`) actually has multiple distinct root causes:

1. **AGI bucket recycled-inode** (`xfs_droplink rc=-117 → xfs_iunlink_insert next_agino==agino`): same-node inode 131 unlinked + recycled before xfs_inactive_ifree completed.
2. **bnobt corruption** (`xfs_free_ag_extent ltbno+ltlen > bno`): cross-node bnobt staleness in free path. Sess19 v0.3.36 supposedly closed but recurs.
3. **Free-inode-has-blocks** (`xfs_create`): inobt-says-free but disk-dinode-has-content.
4. **dir_removename ENOENT** (rare): hash-table or dirent staleness, NOT actual disk-dir-stale.

## What was tried in sess20 (16 versions)

| Version | Change | Result |
|---|---|---|
| v0.3.37 | Approach A: per-trans inode-DLM defer list (current->journal_info) | iter-1 fail. Premise wrong: xfs_create's iunlock fires AFTER trans_commit returns. journal_info NULL at iunlock time. Defer never fires. |
| v0.3.38 | + xfs_log_force_seq(ili_commit_seq) in bast_process | Caused CAW grant timeouts in peers. ili_commit_seq usually 0 by bast time. |
| v0.3.39 | + mxfs_dlm_ag_drain_inode_buffers in inode bast | Same regression family. |
| v0.3.40-41 | partial reverts | iter-12 best (within v0.3.36 variance). |
| v0.3.42-44 | Added P21-INSTR diagnostics | Revealed the BIG FINDING above. |
| v0.3.45 | xfs_inodegc_flush in AG bast Phase 1 | iter-13 best run, but caused bnobt regressions. |
| v0.3.46 | + CAW exponential backoff (1ms→32ms) | Eliminated CAW timeouts but caused dd HANGS. |
| v0.3.47 | + AGI bucket recycled-inode recovery (re-read AGI after inodegc_flush, retry) | Caused bnobt regression at iter-1. |
| v0.3.48-49 | partial reverts | dd hung in v0.3.49. |
| v0.3.50-51 | full revert (test if Approach A scaffolding caused regression) | Approach A NOT the cause. |
| v0.3.52 | re-enabled Approach A scaffolding (= v0.3.36 + harmless A) | Final stable. |

## Don't-repeat list (critical)

1. **xfs_buf_lock on cluster buf in bast_process** — sess16 v0.3.21b, sess19 v0.3.33/34. Cascading deadlock via xfsaild on shared cluster buf b_sema (root 128 + ino=131 share blkno=128).
2. **xfs_buftarg_wait in bast_process** — sess16. bt_io_count never drains under concurrent dd.
3. **blkdev_issue_flush from xfs-buf workqueue context** — sess18 v0.3.26. Serializes the queue.
4. **Adding waits/diagnostics to bast_process** — sess14, sess20. Triggers CAW timeout regression on peer (peer's grant retries hit MAX_RETRIES=100 in tight loop).
5. **CAW exponential backoff** (sess20 v0.3.46) — causes dd hangs under sustained contention. Total backoff time >100ms per acquire is too much.
6. **xfs_inodegc_flush from AG bast** (sess20 v0.3.45) — re-entrant AG-DLM acquires from inactive_ifree path disrupts bnobt coordination.
7. **Approach A premise** (sess20 v0.3.37) — xfs_create/xfs_remove don't have trans active when iunlock fires. Defer-to-trans-free doesn't help dir paths.
8. **xfs_log_force_seq with ili_commit_seq in bast** — by bast time, commit_seq is usually 0 (cleared in xfs_inode_item_unpin after iflush completes). Wait is no-op.

## Real next-session strategy

1. **Don't add to bast_process.** Period.
2. **Diagnostic for AGI recycled-inode race** at xfs_iunlink_insert when next_agino==agino: log agino, prev next_agino value, bucket_index, recent xfs_iunlink_remove activity for this AG. Determine WHO inserted the stale entry.
3. **Likely real fix candidate** for AGI recycled-inode: synchronously force inactive_ifree (not just queue inodegc) when an inode is recycled within same AG. OR add per-AG counter of pending inodegc work and gate ACQ-FRESH on counter == 0.
4. **CAW timeout root cause**: 100 retries with no delay is insufficient under contention. Backoff causes hangs. Need to understand WHY peer's slot churns rapidly enough to defeat 100 retries — maybe a different coordination problem.
5. Verify any fix with **5 fresh-mkfs runs of 15 iters before declaring closed.**

## Test cluster state at sess20 final handoff

- v0.3.52 module loaded on .186 + .182. Fresh mkfs + mounted.
- /tmp/v347_run1.log through /tmp/v351_run1.log have stress logs from this session.
- /tmp/mxfs_stress_v033.sh is the stress test script (15 iters x 512MB each, ~7-10 min per run).
