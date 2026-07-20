---
name: sess18-merge-perf-doomed-pivot-to-format-transition
description: sess18 CONCLUSION: ALL merge variants fail — v1/v2 crash (extra DLM acquire), fold-into-tp wedges (I/O under EX grant, RULE 0), split-snapshot blocke…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) FINAL CONCLUSION on the 2/tcp durable dir lost-update. Cluster left HEALTHY at baseline (dir_merge=0, both nodes mounted, build AA741B4E behavior == 492C8EB7). Marker NOT written (durable loss confirmed live: cc_blockdir_probe lost 4 entries iter14/16, 1 entry iter4, all unrecoverable).

## ALL MERGE VARIANTS EXHAUSTED (do NOT re-try merge without solving perf):
- v1 (per-entry fresh txn+ilock at pre-lock): FS SHUTDOWN — extra dir-EX DLM acquire churn → timeout [[sess17-merge-v1-REFUTED-dlm-shutdown]].
- v2 (single-tenure xfs_trans_roll, ONE ilock at pre-lock): FS SHUTDOWN — still an extra dir-EX acquire on hot dir → rc=-110 timeout → mxfs_dlm_ilock_begin SHUTDOWN_CORRUPT_INCORE [[sess18-merge-v2-single-tenure-REFUTED-dlm-timeout]].
- v3 fold-into-create-tp (mxfs_dir_merge_peer_into_tp, wired at xfs_inode.c after xfs_trans_ijoin@~1569, before xfs_dir_create_child; NO extra DLM acquire): does NOT crash (breakthrough) BUT WEDGES under concurrent create — it does plain-bdev dir-block reads WHILE HOLDING the create's EX grant, blocking the dir-EX handoff → SESS50-STARVE wedge. Clean-cluster probe wedged at iter 2 (PROBE_EXIT=124, touch/drop_caches hung full timeout). gen-gated version (AA741B4E) helped iters 1-2 then wedged. RULE 0 fail. [[sess18-foldtp-merge-no-shutdown-BREAKTHROUGH-perf-wall]]
- v4 split-snapshot (I/O at pre-lock, fast re-add under EX): BLOCKED — the create pre-lock hook (mxfs_dlm_dir_modify_reload_prelock, xfs_inode.c ~1309) runs with NO ILOCK held, so a snapshot there must either walk dp->i_df extents lock-free (crash-racy) or take its OWN ILOCK_SHARED (→ PR-then-EX upgrade churn = the same DLM-acquire hazard). No clean placement.

## WHY MERGE IS PERF-DOOMED: the fix burdens the HOT create path (per-create dir-block I/O). RULE 0 = ≤2× native XFS, which does ZERO cross-node coordination. Any per-create peer-state read on the contended dir either crashes (extra acquire) or starves the lock handoff (I/O under grant). The merge code remains in-tree but GATED OFF (dir_merge=0 default, SAFE/dormant) — leave it; do not enable.

## REFUTATIONS THIS SESSION (solid): (a) read-side staleness RULED OUT — fua_disable=0 (FUA reads) still lost at iter4 [[sess18-readside-ruled-out-writeside-clobber-confirmed]]; (b) release path does NOT escape — no P35F/P-SF-DURABLE-FAIL/P-DIRREL-DIFFERS on the failing iter, so the release fence (flush-until-data_durable + mxfs_dir_stale_data_blocks publish-and-discard) completes CLEAN, yet the block is written durable-but-STALE.

## THE PARADOX TO RESOLVE NEXT (fresh angle): the release fence stales ALL durable blocks (loops flush→stale until nskip==0; no P35F exhaustion on the failing iter) — so after a proper release there should be NO cached stale block at the next acquire, and the cold-read should get the peer's image. Yet the clobber happens. The simple keep-guard-keeps-stale theory does NOT fully hold given the clean release. STRONGEST LEAD: the loss is in the **shortform→block FORMAT TRANSITION**, not steady block-dir. P62-RELOAD-FORK-SHRINK on the failing iter showed ADJACENT-GEN FORMAT DIVERGENCE: test2 incore fmt=2(block) gen433 vs disk fmt=1(shortform) gen434 (disk NEWER + DIFFERENT format), and the reverse. The sf↔block conversion under concurrent 2-node create is where the two nodes durably diverge on format and one clobbers the other. Note mxfs_dir_stale_data_blocks RETURNS 0 for non-EXTENTS format (a real coverage hole during/after a format flip).

## NEXT ITERATION PLAN (non-merge, perf-safe — fix is in cold release/transition path, not per-create):
1. Use a 4-NODE deterministic repro (user's suggestion — more concurrent creators = race fires iter-1 every time; tests/reset4.sh takes a node count; criterion is still 2/tcp so VALIDATE there). Faster RULE-4 capture loop.
2. Instrument the shortform↔block transition: when a dir crosses sf→block under concurrent create, capture which node converts, the gens, and whether a node RMWs a stale shortform base over a peer's block image (or vice versa). The shortform 3-way merge (sess14 mxfs_dir_sf_3way_merge) may not cover the in-flight TRANSITION.
3. Likely fix locus: the acquire-side reload/format-reconcile (mxfs_dlm_reload_inode / P62 path) or mxfs_dir_stale_data_blocks' non-EXTENTS hole — a COLD-path fix that does not burden every create (RULE 0 safe).

## BUILDS this session (all in-tree, dir_merge default 0 = safe): B0C5862, F5F46A31, AA741B4E. xfs_inode.c carries the fold-into-tp wiring (gated). xfs_mxfs_dlm.c carries mxfs_dir_merge_peer_blocks + mxfs_dir_merge_peer_into_tp (both dormant). [[sess17-CONFIRMED-staleflush-clobber-P17]] [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]]
