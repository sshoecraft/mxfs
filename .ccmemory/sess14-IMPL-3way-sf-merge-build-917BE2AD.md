---
name: sess14-IMPL-3way-sf-merge-build-917BE2AD
description: sess14 IMPLEMENTED 3-way shortform-dir merge (build 917BE2AD). New i_dlm_dir_sf_base snapshot + mxfs_dir_sf_3way_merge in xfs_mxfs_dlm.c. Gated by mo…
metadata:
  type: project
---

## sess14 FIX IMPLEMENTED — build 917BE2ADD1BC65485ABE88E (was CF359E6C). Validating.
Addresses the PROVEN write-side shortform resurrection [[sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck]] via the convergent 3-way merge [[sess13-FIX-REQUIRED-3way-sf-merge]].

## CHANGES
- xfs/xfs_inode.h: added `void *i_dlm_dir_sf_base` + `uint32_t i_dlm_dir_sf_base_bytes` (after i_dlm_dir_loaded_gen). Snapshot of the SF dirent image at last coherent disk sync = merge BASE.
- xfs/xfs_icache.c xfs_inode_free_callback: kfree(i_dlm_dir_sf_base).
- xfs/xfs_mxfs_dlm.c:
  - mxfs_sf_find(), mxfs_dir_sf_capture_base(), mxfs_dir_sf_3way_merge() (before mxfs_dir_sf_refresh_if_disk_differs).
  - mxfs_dir_sf_3way_merge: takes i_lock EXCL (bounded trylock), builds merged SF (per-name: ours!=base→keep OURS, else follow THEIRS/disk; +peer-added from theirs not in base/ours), assigns fresh sequential offsets, xfs_dir2_sf_verify, installs via xfs_idestroy_fork+xfs_init_local_fork iff changed. base advances to THEIRS. P-SFMERGE log on change.
  - mxfs_dir_sf_refresh_if_disk_differs REWRITTEN: removed the early-return CLEAN gate; on differs → try merge FIRST (safe even when dirty — keeps our delta); fall back to clean-gated adopt-disk reload only when no base / SF-overflow / disk format changed. Captures base on !differs and after fallback-adopt.
  - mxfs_dlm_reload_inode: capture base after adopting disk (forward-decl added).
  - module_param_named(sf_merge,...) default 1 (=on). Set 0 to revert behavior at runtime.

## WHY safe vs sess9 refutations: merge keeps OUR delta (base-vs-ours) so a destage-lagging disk read can't revert our own rm (refutes Fix-B failure); it's read-only-coherent for names we didn't touch; no forced DLM re-acquire so no starvation (refutes Fix-A).

## VALIDATION: tests/cc_df_capture.sh 6 (reboot+full ./run.sh 2 tcp each, dirwr=1, tallies churn-family fails + P-SFMERGE fires). Baseline = ~1 churn fail/iter. NEXT: if clean, run more iters + full criterion x3 clean-reboot for 100%. If regressed, set sf_merge=0 to confirm it's the merge, then debug. Repro detail [[sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck]].
