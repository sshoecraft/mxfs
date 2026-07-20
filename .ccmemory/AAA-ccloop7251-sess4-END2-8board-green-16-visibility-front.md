---
name: AAA-ccloop7251-sess4-END2-8board-green-16-visibility-front
description: sess4 END2 @48B08138: FULL 8/cawd board green (20/20, fio 135% native, drc 111s in-budget); 16/cawd front = cache_coherency visibility (nudge fallthr…
metadata:
  type: project
---

# sess4 closing state — 8/cawd COMPLETE, 16/cawd is the front

Build lineage this session: 0.11.16 core → `48B0813859643FD208808FF` (final).
Knob: `MXFS_EXTRA_MODARGS="icluster_dlm=1"`. Demote: ex_close_release_ms
DEFAULT 0 now (A/B-proven ifree-clobber trigger; also fixed drc budget +
fairness ghosts).

## MILESTONE: entire 8/cawd board green (all 20 rows incl. soak-smoke,
fault_netpartition, dlm_lock_correctness). Highlights: fio vs native XFS
worst=135% (bar ≥70%); dir_reuse 111s/120s IN BUDGET; crash/zsl/fairness
all root-fixed this session (see sess4 memory chain).

## 16/cawd rung status (prep 39-40s works; knob passthrough fine)
- PASS: precond, strong_consistency, posix_multi 26s, mmap, zsl 9s.
- FAIL: cache_coherency — fresh-file visibility at scale. Root chain:
  reader's cached cluster-buffer serves FREE image → miss_reload
  invalidates (returns acted=1) every lap → nudge short-circuited → 8 laps
  burn → exp="" reads. FIX LANDED: nudge fallthrough from lap≥2
  (xfs_inode.c ~1116). Partial: 6→4 fails/node, 70s→32s, VISNUDGE 78.
  Residual shapes: cwr exp-empty (2/node) + rv content (rename_visibility)
  — see state.md hypotheses; next probe = iclus disk_mode before/after in
  the nudge + match failed inos to nudge outcomes.
- NOT RUN @16: dir_reuse, crash, fio×2, dlm_fairness/membership/scaling,
  scaling_curve, rsync_paired, fence, fault, soak, lock_correctness.

## Round-trip costs (for budget math)
prep@8 30s, prep@16 40s. 8-suite total ≈5min chunked. cache_coherency@16
repro 32s. Foreground calls ≤9.5min; NEVER kill run.sh mid-flight.
