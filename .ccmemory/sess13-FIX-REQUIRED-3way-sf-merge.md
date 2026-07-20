---
name: sess13-FIX-REQUIRED-3way-sf-merge
description: sess13 CONCLUSION: MODE-B fix MUST be a 3-way shortform-dir merge (base/ours/theirs). Adopt-disk AND flush-then-adopt are BOTH proven wrong (single d…
metadata:
  type: project
---

## DEFINITIVE FIX CONCLUSION for the 2/tcp shared shortform-dir lost-update (MODE-B). All cheaper fixes are proven insufficient; the correct fix is a 3-WAY MERGE.

## WHY adopt-disk is wrong: existing mxfs_dir_sf_refresh_if_disk_differs (xfs_mxfs_dlm.c:6293, called on the cached-EX fast path via sf_disk_check @6802) DOES coherent-read disk and reload-adopt — but ONLY when in-core is CLEAN (clean gate: returns if pincount>0 || ili_fields || IN_AIL). When the modifying node has its OWN committed-not-checkpointed SF mods (ili_fields set), it SKIPS → RMWs the stale base → P58-STALE-BASE-ADD. Relaxing the clean gate to adopt-disk-anyway would DROP the node's own uncommitted entries.

## WHY flush-then-adopt is ALSO wrong (analyzed sess13): the shortform dir is ONE dinode (whole dirent set inline). Disk = the LAST writer's FULL image = {our-prior-durable + peer-current}. Our in-core = {our-current-uncommitted + our-STALE-view-of-peer} (stale because the EVICT-RING heartbeat is laggy/bursty — proven 6 gens/10us). So:
- Flushing our in-core to disk OVERWRITES disk with our stale peer-view → REVERTS the peer's current changes (the resurrection). WRONG.
- Adopting disk wholesale DROPS our uncommitted entries. WRONG.
- NEITHER in-core nor disk is a superset → only a 3-way merge reconciles them.

## REQUIRED FIX = 3-WAY SHORTFORM MERGE (Option B; GPT-endorsed for disjoint-name churn = exactly tcp_dlm_scaling/dlm_fairness/crash_consistency):
1. **base snapshot**: when the SF fork is loaded/reloaded (loaded_gen set, e.g. end of mxfs_dlm_reload_inode and at iget), store a copy of the SF dirent set (name->ino) as `i_dlm_dir_sf_base` (+ a gen stamp). New per-inode field; freed on evict/reload.
2. **at a shortform-dir modify** (in mxfs_dir_sf_refresh_if_disk_differs or a new pre-RMW hook, under the conditions sf_disk_check already gates): coherent-read disk SF (theirs). If theirs != ours (in-core): compute MERGE = for each name in (base ∪ ours ∪ theirs): if ours differs from base for that name (we added/removed/changed it) → take OURS; else → take THEIRS. Rebuild the in-core SF fork from MERGE (xfs_idestroy_fork + reformat, or in-place dirent edits). Then the RMW proceeds on the merged base; commit; release-barrier flushes durable (already sound).
3. base is refreshed to the post-merge state after install (so the next merge is relative to current).
4. Disjoint names ⇒ "ours wins for our names, theirs for theirs" is exact, no conflicts. For the general (same-name) case, document it as last-writer per-name (acceptable; the criterion tests are disjoint).

## This is essentially GPT Option A's intent (per-tenure reconcile) made correct for the single-dinode shortform case. The release barrier (bast_process 3638-3748) already guarantees durable handoff; the missing half is the ACQUIRE/modify-side MERGE instead of adopt-or-skip.

## SUPPORTING PROOF (build CF359E6C, dir-filtered P-LKT): grants serialized (no double-grant [[sess13-doublegrant-REFUTED-serialized-stale]]); P62-RELOAD-FORK-SHRINK ino=2097280 incore_size=51 disk_size=32 in_ail=0 pin=0 (in-core ahead of disk AND clean = the divergence); leftover = node's OWN n1_rN. [[sess13-modeB-MECHANISM-shortform-merge-conflict]]

## NEXT SESSION: implement the 3-way SF merge (above). Files: xfs_mxfs_dlm.c (mxfs_dir_sf_refresh_if_disk_differs + base snapshot in reload + new i_dlm_dir_sf_base field in the xfs_inode mxfs section, include/mxfs or xfs_inode.h). Validate full run.sh 2 tcp x3 clean-reboot (watch dlm_fairness/tcp_dlm_scaling/crash_consistency = the rotating residual; also no regression on cache_coherency/zero_silent_loss). Build base = CF359E6C. [[sess13-HEAD-status]]
