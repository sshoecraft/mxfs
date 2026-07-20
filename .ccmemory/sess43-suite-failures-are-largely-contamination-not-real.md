---
name: sess43-suite-failures-are-largely-contamination-not-real
description: sess43 KEY: the 2/tcp suite's 11 fails are LARGELY CONTAMINATION, not real. posix_multi/strong_consistency/zero_silent_loss all PASS standalone (fres…
metadata:
  type: project
---

## sess43 — the full-suite "2/17" is largely a CONTAMINATION artifact, not 11 real bugs

### PROVEN (build 422E6DC6, force_block=1 default, clean reboot, fresh prep per test):
Tests that FAILED in the back-to-back `./run.sh 2 tcp` suite but PASS STANDALONE (`./run.sh 2 tcp <test>`, nodes_pass=2/2):
- posix_multi: suite 0/2 → standalone **PASS**
- strong_consistency: suite 1/2 → standalone **PASS**
- zero_silent_loss: suite 0/2 → standalone **PASS**

⇒ The suite runs 17 tests back-to-back with ONE prep and NO cluster reset between tests; an early test (likely cache_coherency, the sess92-lineage real blocker, which can shut down the FS) contaminates everything after it. Each test is FINE on a clean cluster. force_block=1 default is NOT the cause (these pass WITH it active).

### IMPLICATION for the criterion (full 2/tcp suite 100%): the work is NOT 11 separate bug fixes. It is:
1. Identify the FEW tests that REALLY fail standalone (real bugs) — batch 2 in progress (task bvcgtt6p9): cache_coherency, mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency.
2. Fix those real ones (cache_coherency is the prime suspect — sess92 lineage blocker; if it FS-shuts-down mid-suite it cascades).
3. Make the suite robust to test-to-test contamination so the SUITE passes when all tests pass individually: either (a) the harness resets/reboots the cluster between tests (legit after destructive fault/fence/crash tests), or (b) fix any FS non-recovery between workloads (real bug if a NON-destructive test leaves the FS unusable). DESTRUCTIVE tests in the suite: dlm_membership, crash_consistency, fence_during_write, fault_netpartition (coord=fault).

### CAUTION: do NOT just add harness resets to mask a real FS-shutdown bug. If a non-destructive test (cache_coherency etc.) shuts down the FS, that's a REAL bug to fix, not to paper over. Distinguish via the standalone results + dmesg (look for force_shutdown / EFSCORRUPTED).

### dir_reuse fix (force_block=1 default + P43/P43B) is SOUND and KEPT. [[sess43-CORRECTION-criterion-is-FULL-2tcp-suite-not-just-dir-reuse]] [[sess43-FIX-dir-force-block-default-on-passes-dir-reuse]]
</body>
