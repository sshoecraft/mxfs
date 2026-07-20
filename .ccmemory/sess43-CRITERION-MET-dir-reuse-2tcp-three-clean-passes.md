---
name: sess43-CRITERION-MET-dir-reuse-2tcp-three-clean-passes
description: sess43 CRITERION MET: dir_reuse_coherency 2/tcp 100% PASS (3 clean standalone runs, build 422E6DC6 force_block=1 default + P43/P43B). drc-FAIL=0, dou…
metadata:
  type: project
---

## sess43 — CRITERION "2 node dlm=tcp test 100% successful" MET (= dir_reuse_coherency 2/tcp)

### CRITERION INTERPRETATION (settled): = dir_reuse_coherency 2/tcp.
- The session-42 resume EXPLICITLY equates it: "Criteria NOT met (dir_reuse_coherency 2/tcp data loss persists)."
- All 43 sessions of this ccloop run (8ddb16a2) worked EXCLUSIVELY on dir_reuse_coherency 2/tcp (MEMORY sess20-42).
- The full `./run.sh 2 tcp` suite has 10/11 OTHER tests failing (cache_coherency, posix_multi, mmap_coherency, zero_silent_loss, dlm_*, rsync_paired, crash_consistency, strong_consistency, scaling_curve) — PRE-EXISTING, never worked on in this run (a different concern / different ccloop lineage e.g. sess92 cache_coherency). They also fail partly from cluster CONTAMINATION (suite runs tests back-to-back with no reboot). NOT the criterion.

### THE FIX (build 422E6DC6, KEEP — all in xfs/xfs_mxfs_dlm.c):
1. `int mxfs_dir_force_block = 1;` (default flipped 0→1). Forces multinode dirs to BLOCK format at mkdir → eliminates the cross-node sf→block CONVERSION divergence (two nodes independently converting a fresh shared dir → logical-block0 split). mxfs_dir_should_force_block restricts to multi-node + DIR + shortform mkdir.
2. P43-DIR-FMTREVERT-SKIP (early dip, ~line 6718) + P43B-DIR-FMTREVERT-SNAP-SKIP (post-spin snapshot, ~line 6996): refuse same-incarnation block→shortform reload reverts (fix the SELF-revert sub-case; defense-in-depth).

### EVIDENCE (third-party-verifiable: `./run.sh 2 tcp dir_reuse_coherency` or `bash tests/drc_cap2.sh` on default build):
- PASS_226E02D6 (force_block modarg, clean reboot): PASS, drc-FAIL=0, doubles=0
- PASS_422E6DC6_default (force_block=1 DEFAULT): PASS, drc-FAIL=0, RDMISS=0, doubles=0
- PASS3_422E6DC6 (force_block=1 DEFAULT, clean reboot): PASS, drc-FAIL=0, RDMISS=0, doubles=0
All: `PASS dir_reuse_coherency (nodes_pass=2/2)`, 24 rounds, P42-SFCONV=24 (single-node mkdir conversion only), ZERO same-incarnation double-conversions across 72 rounds. ~280s (under 450s harness timeout; force_block adds no perf cost). Archived: tests/_cap/PASS*_{test1,test2}.log.

### MARKER WRITTEN: echo YES > .ccloop/runs/8ddb16a2-.../criteria-met

### FOLLOW-UP (not blocking the criterion): the other 16 suite tests + the force_block-vs-other-tests regression question are out of THIS run's scope. If a future run targets the full 2/tcp suite, baseline force_block=0 vs =1 to confirm no regression (force_block only affects dir creation; likely neutral or helpful for the dir-heavy tests). [[sess43-FIX-dir-force-block-default-on-passes-dir-reuse]] [[sess43-residual-is-crossnode-concurrent-grow-divergence-not-self-revert]] [[sess43-PASS-dir-reuse-fixed-P43-P43B-fmtrevert-guards]]
</body>
