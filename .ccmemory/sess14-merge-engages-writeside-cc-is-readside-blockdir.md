---
name: sess14-merge-engages-writeside-cc-is-readside-blockdir
description: sess14 build 3017D9DF: 3-way SF merge now ENGAGES (P-SFMERGE fires in reload). Splits the flake: write-side shortform (dlm_fairness/tcp_dlm_scaling)…
metadata:
  type: project
---

## sess14 build 3017D9DF2FF242A93713E5D (merge in BOTH sf_refresh AND mxfs_dlm_reload_inode). Criterion still NOT met; marker NOT written.

## VALIDATION (tests/cc_df_capture.sh 6, reboot+full ./run.sh 2 tcp, dirwr=1):
- iter1: 16/16 PASS (incl all churn family). P-SFMERGE=0.
- iter2: crash_consistency FAIL 1/2 (reader test1). **test2 P-SFMERGE fires: 2** → the merge ENGAGES now (was 0 with the sf_refresh-only build 917BE2AD; moving it into mxfs_dlm_reload_inode where P62-RELOAD-FORK-SHRINK fires made it engage). dlm_fairness + tcp_dlm_scaling PASSED iter1+2.

## SPLIT DIAGNOSIS:
- WRITE-side shortform resurrection (dlm_fairness `drained got=1`, tcp_dlm_scaling silent-loss): the SF dirs stay small (create+mv+rm churn). 3-way merge addresses this (P-SFMERGE engaging). Confirm reliability over more iters / A-B with sf_merge=0.
- **crash_consistency = READ-side BLOCK/LEAF-format dir**: cc writes 50 data + 50 md5 files/node = 200 entries = BLOCK/LEAF dir (NOT shortform → SF merge does NOT apply). Reader (test1) misses peer's entries after `sync`+`drop_caches`. P-SFMERGE=0 on the failing reader. This is the block-dir read-side visibility lag [[sess-tcp-cc-ROOT-dir-entry-visibility-lag]]: after drop_caches the reader re-reads the LUN via xfs_da_read_buf, but either (CASE B) test2's block-dir blocks aren't durable at final location after sync (publish-only design, sess97 mxfs_dlm_dir_durable_signal is PUBLISH-ONLY — no block flush), or (CASE A) reader stale. Likely CASE B: sync/syncfs must push dir DATA blocks to final location; check mxfs syncfs/AIL-push path + _XBF_DELWRI_Q/pag_mxfs_alloc_buflist deferral.

## NEXT: (1) finish 6-iter tally → is write-side now 6/6 for dlm_fairness+tcp_dlm_scaling? (2) focused cc reproducer (200 files block dir, sync, drop_caches, cross-read + touch CASE A/B probe). (3) fix cc read-side (likely writer block-dir durability on sync). Build base 3017D9DF. sf_merge=1 default; sf_merge=0 reverts merge. [[sess14-IMPL-3way-sf-merge-build-917BE2AD]] [[sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck]]
