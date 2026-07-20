---
name: sess43-PASS2-default-config-422E6DC6-dir-reuse
description: sess43: SECOND dir_reuse 2/tcp PASS with DEFAULT config (build 422E6DC6, force_block=1 default, no modarg). drc-FAIL=0/RDMISS=0/doubles=0. Now runnin…
metadata:
  type: project
---

## sess43 — dir_reuse_coherency 2/tcp: SECOND PASS, default config (build 422E6DC6)

### Two PASSes now with force_block ON:
1. build 226E02D6 + `MXFS_EXTRA_MODARGS=dir_force_block=1` (clean reboot): PASS, drc-FAIL=0, doubles=0. archived tests/_cap/PASS_226E02D6_test{1,2}.log
2. build 422E6DC6 (`mxfs_dir_force_block=1` DEFAULT in code, NO modarg): PASS, drc-FAIL=0, drc-RDMISS=0, doubles=0, P42-SFCONV=24 (single-node mkdir force-conversion only), ~277s. archived tests/_cap/PASS_422E6DC6_default_test{1,2}.log. Confirmed on nodes: dir_force_block=1 active by default.

### Builds:
- 226E02D6 = P43 + P43B reload format-revert guards.
- 422E6DC6 = 226E02D6 + `int mxfs_dir_force_block = 1;` (default flipped 0→1 in xfs/xfs_mxfs_dlm.c ~2768, with rationale comment). KEEP.

### REMAINING for criterion "2 node dlm=tcp test 100% successful":
- FULL `./run.sh 2 tcp` suite (17 tests) must be 100% — confirm force_block=1 default does NOT regress the other 16 (cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition, soak, tcp_dlm_scaling, precond_readiness). RUNNING now (task b0gr73di5, timeout 1800s background).
- Then ≥1 more full-suite or dir_reuse repeat for stability (bug was intermittent).
- Only write criteria-met marker after a cited full-suite 17/17 PASS (third-party-verifiable).

### If full suite shows a regression from force_block: the mxfs_dir_should_force_block guard (multi-node + DIR + shortform mkdir only) limits blast radius; a regressing test would reveal a force_block interaction to fix or narrow. [[sess43-FIX-dir-force-block-default-on-passes-dir-reuse]]
</body>
