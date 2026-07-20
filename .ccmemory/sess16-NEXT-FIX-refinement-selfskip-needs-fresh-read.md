---
name: sess16-NEXT-FIX-refinement-selfskip-needs-fresh-read
description: sess16 refinement to the NEXT-FIX: the format-blind self-skip CANNOT be fixed with a cached-buffer peek (cached cluster buffer IS the stale shortform…
metadata:
  type: project
---

## sess16 refinement to [[sess16-NEXT-FIX-format-blind-selfskip-gate]].

## WHY a quick peek won't work: I considered adding a disk di_format peek before the self-skip (xfs_mxfs_dlm.c ~5213) to detect a block-format upgrade and force adoption. BUT xfs_imap_to_bp returns the CACHED cluster buffer if XBF_DONE is set — and that cached buffer IS the stale shortform copy (the very thing causing the bug). So a peek sees stale shortform → misses the upgrade. The code only gets the REAL disk image at line 5328 (xfs_imap_to_bp) which is reached AFTER the stale-buffer invalidation at 5284 (clear XBF_DONE) — and BOTH are after the self-skip return at 5273. On this TCP/SCST stack FUA is unsupported (plain-read fallback), so a fresh read REQUIRES invalidating (clear XBF_DONE) first.

## CORRECT FIX (GPT's "invalidate + reread on acquire, THEN decide"): RESTRUCTURE mxfs_dlm_reload_inode so the cluster-buffer invalidation (currently ~5284) + fresh disk read (currently ~5328, dip assigned 5337) happen BEFORE the self-skip decision (~5189-5275). Then the self-skip / adopt logic can compare in-core fork vs FRESH on-disk dip:
 - disk format UPGRADE (disk EXTENTS/BTREE vs in-core LOCAL) => ADOPT (strict superset; dir only grows sf->block by adds; our own committed adds were drained at the release that let the peer get EX). Re-apply our in-flight delta (extend merge_ours ~5935 to shortform-in-core -> block-disk).
 - disk format DOWNGRADE (disk LOCAL vs in-core block/leaf) => KEEP in-core unless post_release (a real drained remove).
 - same format => existing gen/post_release/peer_modified logic + sf-merge.
 - PRESERVE the sess8 resurrection guard: a shortform in-core with a committed-not-durable DELETE must not be reverted by adopting disk; gate force-adopt on "no delete in flight" or re-apply the delete delta.

## RISK: mxfs_dlm_reload_inode is the MOST regression-prone function (P91-RELOAD-PROTECT cluster-buffer guard at 5302, snap/verify at 5790-5823, sess8/36/49/58/59/87 fixes all layered here). The invalidation at 5284 has a guard (mxfs_buf_has_uncheckpointed_mods => kept_protected) to avoid clobbering co-resident inodes' logged mods — moving the read earlier must preserve that. MUST validate with FULL ./run.sh 2 tcp x3 + watch cache_coherency/strong_consistency/dlm_fairness/zero_silent_loss/rename for regressions. Build/repro: tests/cc_blockdir_probe.sh (isolated per-iter; ino reused; <15 iter). Fallback 17DCD050=15/16. Cluster currently on instrumented 03A6D084. [[sess16-HEAD-status]] [[sess16-gpt-architecture-demote-drain-by-lock-ownership]]
