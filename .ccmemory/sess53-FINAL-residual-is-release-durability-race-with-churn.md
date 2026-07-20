---
name: sess53-FINAL-residual-is-release-durability-race-with-churn
description: sess53 FINAL: build 21C36EEA. KEEP idempotent-iunlink + GPT EX-gate + clean-adopt (merges suppressed, iunlink fixed). Residual = release-side shortfo…
metadata:
  type: project
---

## sess53 FINAL HANDOFF — criterion NOT met. Build 21C36EEA (KEEP all below). Marker NOT written.

### CONFIG (overturned sess52): PLAIN `./run.sh 2 tcp` pure defaults (dir_pr_release_fast=1, sf_merge=1) + P52 guards. Do NOT use option B (=2) or MXFS_EXTRA_MODARGS. Reliability now ~4/5. Validate with `PLAIN=1 bash tests/tcp/fg_one_run.sh <lbl>` (foreground, reboots, ~540s, ~1/5 fails). See [[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]].

### FIXES THAT LANDED + ARE KEEP (build 21C36EEA = D67776EC + P52 + these):
1. **idempotent-iunlink** (xfs/xfs_iunlink_item.c xfs_iunlink_log_dinode): VALIDATED (h1/h2 fired P53-IUNLINK-IDEMPOTENT, shutdown=0). Fixes the tcp_dlm_scaling iunlink trans_commit corruption shutdown (free/reuse race leaves item's old_agino stale; chain already correct → no-op not shutdown).
2. **EX-tenure reload suppression** (xfs/xfs_mxfs_dlm.c mxfs_dlm_dir_modify_reload_prelock ~2646): `if (dp->i_dlm_mode==MXFS_LOCK_EX) return;`
3. **clean-adopt at acquire** (xfs/xfs_mxfs_dlm.c reload merge ~7746): merge only if `!xfs_inode_clean(ip)`; a clean inode ADOPTS disk.
(2)+(3) = GPT-5.5's confirmed invariant "disk authoritative only at EX-acquire; in-core authoritative under EX." RESULT: dir SF merges SUPPRESSED (sfmerge=0), the merge resurrection vector CLOSED. P53-IUNLINK diag also present (harmless). REVERTED dead-ends: DIRGEN-BUMP, DIRAHEAD-overlay (was a confound — could revert release flush), sf_merge=0.

### THE RESIDUAL (now the ONLY blocker) = release-side SHORTFORM dir durability RACES with concurrent churn.
Durable dirent leak (`<test> shared hot dir drained got=1`, leftover survives drop_caches both nodes) hits ANY shared-hot-dir test — tcp_dlm_scaling AND fence_during_write (p1: tcp_dlm_scaling PASS but fence_during_write leaked). NOT merge-driven (suppressed), NOT test-specific.
DECISIVE PROOF (dirwr=1 run n1): node2 `P-SFREL-VERIFY ino=8930275 incore_size=25 disk_size=20 STALE-DISK` — after node2's release flush, disk is BEHIND in-core (committed dir change not landed). P-ICD trace for that ino: `mxfs_inode_cluster_durable` retries 25× while `incore_size` OSCILLATES 35→40→20 (dir churned concurrently DURING the flush), `clean=1 in_ail=1 rerr=0` — the flush chases a moving target and intermittently lands a superseded image. The FINAL release was DURABLE (churn settled); an earlier one STALE. P51-REL `drain_ms=0`.

### NEXT SESSION — fix the release-durability race (xfs/xfs_mxfs_dlm.c mxfs_inode_cluster_durable):
- ROOT: the shortform dir is being modified by LOCAL ops while/just-after the release durable-flush runs, so the flushed image is superseded → peer reads stale → dirent leak. `clean=1 in_ail=1` = inode already iflushed into the cluster buffer but buffer IN_AIL (not destaged); the sess9 -EAGAIN→submit path runs but the LATEST in-core change may not be the one in the submitted buffer.
- IDEAS: (a) before the final release flush, ensure NO local holder can still be modifying (quiesce) and re-iflush the LATEST in-core image, then bwrite-and-WAIT (synchronous) so disk == final in-core; (b) the P-SFREL-VERIFY STALE-DISK detector (gated dirwr=1) is the ground-truth oracle — loop the durable flush until P-SFREL-VERIFY reads DURABLE (disk==incore) before releasing EX; (c) investigate why `clean=1` (inode reports clean) when the in-core dirent set differs from disk — the shortform dirent change may not mark the inode dirty in a way iflush re-flushes.
- Reproduce: PLAIN full suite ~1/5; OR `MXFS_EXTRA_MODARGS="dirwr=1"` to get P-SFREL-VERIFY STALE-DISK (but dirwr perturbs timing → more fails). warm-FS repeat driver INVALID.
- Once a PLAIN run is reliably 17/17 across ~6-8 reboots → write marker `echo YES > /src/mxfs/.ccloop/runs/8ddb16a2-17d4-43b8-83e5-5c4c0cbcd9d6/criteria-met`.
Related: [[sess53-HANDOFF-ex-gate-clean-adopt-merges-suppressed-leak-now-pure-disk]] [[sess53-dirent-resurrection-multinode-stale-flush-plus-merge-union]]
