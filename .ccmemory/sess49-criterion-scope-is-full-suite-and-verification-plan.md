---
name: sess49-criterion-scope-is-full-suite-and-verification-plan
description: sess49(ccloop): criterion "1/2/4/8 node tcp dlm test 100%" = FULL ./run.sh N tcp suite (~17 tests) per node count, NOT just dir_reuse. epoch_adopt=0…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — criterion scope + verification plan

### SCOPE: the criterion "get 1/2/4/8 node tcp dlm test working 100%" = the FULL `./run.sh N tcp` suite (~17 tests: cache_coherency, zero_silent_loss, dir_reuse_coherency, posix_multi, mmap_coherency, dlm_fairness/membership/scaling, tcp_dlm_scaling, fence_during_write, rsync_paired, crash_consistency, soak, fault_netpartition, strong_consistency, scaling_curve, precond_readiness) passing at EACH of N=1,2,4,8. (User-confirmed for the sibling 2-node criterion: [[sess43-CORRECTION-criterion-is-FULL-2tcp-suite-not-just-dir-reuse]].) NOT just dir_reuse — though dir_reuse was the headline 8-node blocker.

### DONE THIS SESSION: dir_epoch_adopt=0 (build 3B0EB406) fixes the 8-node dir_reuse SHUTDOWN (AG double-free from epoch-adopt stale-disk fork-shrink) → dir_reuse 8/8 PASS. See [[sess49-BREAKTHROUGH-epoch-adopt-0-fixes-8node-shutdown]].

### HISTORICAL full-8node landscape (sess22, build DFDBAAFE): 13/17, 4 coherency fails = cache_coherency, zero_silent_loss, dir_reuse_coherency, fault_netpartition (the "130-session coherency core"). Sessions 23-48 worked these; sess92 head said 11/12 criteria pass (cache_coherency historical blocker, FIX1/FIX2 builds). CURRENT full-suite state UNKNOWN — must measure on build 3B0EB406 (epoch_adopt=0).

### VERIFICATION PLAN (RULE 4, in order):
1. [in flight] Confirm dir_reuse 8-node baked default (build 3B0EB406, no modargs) = 8/8.
2. RELIABILITY: tests/drc_reliability.sh "" 24 3 8 (3× consecutive clean-reboot 8-node dir_reuse).
3. FULL SUITE landscape: `TEST_TIMEOUT=480 ./run.sh 8 tcp` on 3B0EB406 — capture PASS/FAIL per test (use a reboot-clean wrapper). Watch: does epoch_adopt=0 regress cache_coherency/zsl deletion-visibility? (Risk: epoch_adopt=0 keeps-stale on SHRINK/delete; but GROWS still adopt, and these tests passed pre-sess14 before epoch_adopt existed.)
4. Fix remaining full-suite 8-node fails.
5. Repeat full suite at 1/2/4.
6. Only then write criteria-met marker.

### Tools: tests/drc_reliability.sh (sess49, multi-run tally), tests/drc_dirtyskip.sh (single reboot+run). RULE 0: 8-node dir_reuse ~near 300s TEST_TIMEOUT (sess18 needed 480); watch for timing-induced FAIL.
</body>
</invoke>
