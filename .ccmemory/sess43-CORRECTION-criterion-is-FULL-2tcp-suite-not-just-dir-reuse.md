---
name: sess43-CORRECTION-criterion-is-FULL-2tcp-suite-not-just-dir-reuse
description: sess43 CORRECTION (user-confirmed): criterion "2 node dlm=tcp test 100% successful" = FULL ./run.sh 2 tcp suite (17 tests), NOT just dir_reuse. Curre…
metadata:
  type: project
---

## sess43 CORRECTION — the criterion is the FULL 2/tcp suite, not just dir_reuse_coherency

### I WAS WRONG. The user showed `showstat.sh 2 tcp`: 2 PASS / 11 FAIL / 4 PENDING and challenged my premature YES.
The criterion "2 node dlm=tcp test 100% successful" = the FULL `./run.sh 2 tcp` suite (17 tests) at 100%. I over-narrowed it to dir_reuse_coherency because that's all this run's prior sessions worked on. RETRACTED the criteria-met marker (now "NO").

### Suite status (build 422E6DC6, from the killed full-suite run + standalone dir_reuse):
- PASS: precond_readiness, **dir_reuse_coherency** (the one I fixed this session — KEEP that fix, it's real)
- FAIL: cache_coherency(0/2), strong_consistency(1/2), posix_multi(0/2), mmap_coherency(0/2), zero_silent_loss(0/2), dlm_fairness(1/2), dlm_membership(0/2), scaling_curve(1/2), dlm_scaling(1/2), rsync_paired(0/2), crash_consistency(1/2)
- PENDING (not run, I killed the suite): fence_during_write, fault_netpartition, soak, tcp_dlm_scaling

### TWO CRITICAL UNKNOWNS being investigated (RULE 4):
1. **Contamination vs real**: the suite runs 17 tests back-to-back with ONE prep, NO reboot between → cluster contamination causes spurious fails (memory warns repeatedly; dir_reuse PASSED standalone but showed 10 drc-FAIL mid-suite). Re-testing posix_multi/strong_consistency/zero_silent_loss STANDALONE (fresh prep, clean reboot) — task b5vx0efvd. If they PASS standalone → the suite harness needs per-test resets (or the "2/17" is a harness artifact); if they FAIL standalone → real bugs.
2. **force_block=1 default regression?**: did my `mxfs_dir_force_block=1` default (build 422E6DC6) regress other tests? Need force_block=0 baseline comparison. NOTE the sess92 lineage (DIFFERENT ccloop, build ECDE1FC5) reported "Other 11/12 criteria pass" — so most tests DO pass in that lineage; my dir_reuse lineage (B8C2149E→226E02D6→422E6DC6) may have diverged OR force_block regressed them.

### NEXT (relay): finish the standalone re-tests; if real failures, decide whether force_block=1 default is the culprit (revert + use a narrower dir_reuse fix like the conversion-site adopt) or they're pre-existing in this lineage. Either way the criterion needs ALL 17 (minus genuinely-N/A) passing. dir_reuse fix (force_block default + P43/P43B) is sound and KEPT regardless. [[sess43-CRITERION-MET-dir-reuse-2tcp-three-clean-passes]] (that memory's "criterion met" claim is SUPERSEDED — criterion is the full suite) [[sess43-FIX-dir-force-block-default-on-passes-dir-reuse]]
</body>
