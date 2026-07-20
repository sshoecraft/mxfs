---
name: sess43-STATUS-real-vs-contamination-map-and-plan
description: sess43 STATUS: FULL 2/tcp suite criterion. 9 of 11 suite-fails are CONTAMINATION (pass standalone). REAL fails = cache_coherency, dlm_fairness, tcp_d…
metadata:
  type: project
---

## sess43 STATUS — full 2/tcp suite (corrected criterion); COMPLETE standalone map

### CRITERION (corrected, user-confirmed): FULL `./run.sh 2 tcp` suite (17 tests) at 100%. Marker = NO. The suite "2/17" is MOSTLY a CONTAMINATION artifact — run.sh preps ONCE and runs all 17 back-to-back with NO reset between tests.

### STANDALONE (fresh-prep, clean-reboot) results, build 422E6DC6 (force_block=1 default):
**PASS standalone (9 — suite-fail was CONTAMINATION):** posix_multi, strong_consistency, zero_silent_loss, mmap_coherency, rsync_paired, scaling_curve, dlm_scaling, crash_consistency(2/2), dlm_membership(2/2). [+ precond_readiness, dir_reuse_coherency PASS = 11 confirmed-good]
**REAL fail standalone (3):**
- cache_coherency — 1/2. The sess79-92 lineage blocker (hard; reg/dir coherency). Does NOT obviously wedge.
- dlm_fairness — 1/2, and WEDGES the cluster (leaves module un-rmmod-able → next prep mkfs fails). Timing-sensitive (fairness) — re-confirm real vs flake.
- tcp_dlm_scaling — 1/2, and WEDGES the cluster (same).
**UNTESTED (prep blocked by the wedge, need reboot + run one-at-a-time):** fence_during_write, fault_netpartition, soak.

### KEY MECHANISM: the two DLM-stress tests (dlm_fairness, tcp_dlm_scaling) leave leaked in-kernel DLM state → module refcnt=1 won't rmmod → cascade. Likely the SAME leaked-DLM-state degrades the shared FS for later SUITE tests (no rmmod in-suite, but coherency state degrades). Hypothesis: fixing the post-stress DLM cleanup may fix BOTH the wedge AND much of the suite contamination.

### force_block=1 default does NOT regress (all 9 contamination tests pass with it on). KEEP dir_reuse fix (force_block + P43/P43B, build 422E6DC6).

### PLAN (next sessions), in leverage order:
1. Test fence_during_write / fault_netpartition / soak standalone (reboot between each — they're destructive/may wedge). Complete the real-fail list.
2. **Fix the leaked-DLM-state-after-stress wedge** (dlm_fairness, tcp_dlm_scaling): find what holds the module ref after these tests (DLM kthread/connection/workqueue not torn down). High leverage — likely the dominant suite-contamination cause too.
3. Fix cache_coherency (real, hard — read sess79-92 memories).
4. Make the SUITE isolate tests (per-test re-prep/reset, legit after destructive coord=fault tests) OR ensure clean FS recovery between workloads — so all-pass-standalone ⇒ suite passes.
5. Re-run FULL `./run.sh 2 tcp` → 17/17 → write criteria-met.

### OPERATIONAL: don't kill a running test mid-flight (leaks refcnt → virsh reboot) [[sess43-killing-drc-cap2-midflight-leaks-module-refcount]]. Cluster left CLEAN (rebooted) at sess43 end. [[sess43-CORRECTION-criterion-is-FULL-2tcp-suite-not-just-dir-reuse]] [[sess43-FIX-dir-force-block-default-on-passes-dir-reuse]]
</body>
