---
name: sess14-HEAD-status
description: sess14 HEAD: build 3017D9DF deployed. 3-way SF merge FIXED dlm_fairness 6/6 (write-side shortform). Sole remaining 2/tcp blocker = crash_consistency…
metadata:
  type: project
---

## HEAD sess14. Criterion `./run.sh 2 tcp` 100% x3 = NOT met. Marker NOT written.

## BUILD 3017D9DF2FF242A93713E5D deployed both nodes (test1 .114, test2 .182), sf_merge=1. = CF359E6C + sess14 3-way shortform-dir merge. KEEP (net positive: dlm_fairness 6/6, was flaky).

## WHAT THE MERGE DID (xfs_mxfs_dlm.c): new i_dlm_dir_sf_base snapshot (xfs_inode.h) + mxfs_dir_sf_merge_into (i_lock-held core) called from BOTH mxfs_dir_sf_refresh_if_disk_differs AND mxfs_dlm_reload_inode (after xfs_inode_from_disk, re-applies pre-reload OUR delta so a reload no longer reverts our committed-not-durable dirents). Per-name: ours!=base→keep OURS, else THEIRS. module_param sf_merge (1=on). xfs_icache.c frees base. Engages (P-SFMERGE fires on test2). Validated: 6-iter full-suite reboot run → dlm_fairness 6/6, tcp_dlm_scaling 5/6, crash_consistency 3/6. [[sess14-IMPL-3way-sf-merge-build-917BE2AD]]

## SOLE REMAINING BLOCKER = crash_consistency = BLOCK/LEAF-format dir concurrent-create durable dirent LOSS (NOT shortform, NOT read-staleness). PROVEN [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]]: node2_f49 (test2's OWN data file) clobbered durably on BOTH nodes (test2 has N for its own file); its .md5 survives; not eventual (+8s gone); pureLUN+direx don't restore. A peer's stale-base block-dir RMW overwrote the data block dropping node2_f49's dirent.

## FAST REPRODUCER (KEY ASSET): `tests/cc_blockdir_probe.sh 60 50` — 2 nodes write 50 data(oflag=sync)+50 md5 into ONE shared dir (=200 entries=block dir), test1 readdir-counts; caught the loss on iter 1 (×2). Identifies the missing entry + CASE A/B. NO 6-min full-suite needed. Use this to iterate the block-dir fix.

## BLOCK-DIR FIX DIRECTION (next): the modify-path block-dir refresh (mxfs_dlm_dir_modify_refresh @2155, evict gated on i_dlm_dir_gen!=evicted_gen — LAGGY heartbeat gen → P106-MR-SKIP → stale-base RMW). Release DOES flush block-dir data blocks (mxfs_dir_flush_data_blocks in bast_process ~3760). So root is fast-path/gen-lag: a node RMWs a stale dir data block because i_dlm_dir_gen wasn't bumped before the create read it (or a deferred-BAST left cached EX). Candidate: in modify_refresh, ALSO evict on i_dlm_stale (immediate BAST signal, not laggy gen) — BUT eviction alone needs the peer's block durable (it is, via release flush) AND requires the modifier actually re-acquired (BAST'd peer). CAUTION sess9: force-slow-path-on-stale → starvation; per-op FUA → rsync wall. INSTRUMENT FIRST (RULE 4): catch which node clobbers + whether fast-path vs gen-lag, via cc_blockdir_probe + a block-dir-RMW-stale-base detector.

## HARNESSES (in-tree): tests/cc_blockdir_probe.sh (FAST cc repro+discriminator), tests/cc_df_capture.sh (full-suite + dirwr detector capture, tallies churn fails+P-SFMERGE), tests/tcp2_characterize.sh, tests/cc_dirvis_probe.sh. crash_consistency.sh has A/B discriminator. Always virsh destroy+start BOTH (tests/reboot_cluster.sh 2) before a trusted run. mxfs.dirwr=1 enables always-on dir detectors (P58/P-SFDIR-REVERT/P62/P91/P104/P-SFMERGE); instr=1 = 100x slow, hides races (avoid). [[sess14-merge-engages-writeside-cc-is-readside-blockdir]] [[sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck]]
