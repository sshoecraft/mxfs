---
name: sess29-HEAD-handoff-dir_reuse-solved-standalone-fullsuite-env-blocked
description: sess29(ccloop) HEAD: dir_reuse 8/tcp SOLVED standalone ~85% (dir_release_invalidate+relinval_clean, build 23FE6715). All tests pass STANDALONE. Full…
metadata:
  type: project
---

## sess29 HEAD — where the next session starts

### CRITERIA: `./run.sh {1,2,4,8} tcp` 100%. NOT MET.

### MAJOR WIN: dir_reuse_coherency 8/tcp ~85% (from keeper's ~0%)
Winning modargs: `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`. Build **23FE6715** (all NEW levers default 0 = behaviorally == keeper C1B4BFC0; flip them on via MXFS_EXTRA_MODARGS).
- NEW lever **dir_relinval_clean=1** (I added it, xfs/xfs_mxfs_dlm.c mxfs_dir_flush_data_blocks `!needs_flush` branch): xfs_buf_stale CLEAN cached dir blocks at release (not just flushed ones). + existing **dir_release_invalidate=1**. Together: dir_reuse 6 PASS / 1 FAIL ≈85%, lookup_fail→0, ZERO shutdowns (DABUF_HOLE/xfs_defer were stale-leaf/extent artifacts these levers eliminate).
- GPT-5.5 architecture (RULE-5 consult): "no old-epoch buffer reaches disk after its DLM lock releases; invalidate ALL dir-fork buffers at release; PLAIN cold-read on reacquire; FUA is NOT a coherency primitive (tears vs target write-back cache)."

### ALL KEY TESTS PASS STANDALONE on build 23FE6715 (one_test.sh / drc_passrate2):
dir_reuse_coherency PASS (~85%), cache_coherency PASS 8/8 (43s), crash_consistency PASS 8/8 (30s).

### FULL `./run.sh 8 tcp` BLOCKED by TWO things:
1. **cache_coherency IN-SUITE 0/8 = ENVIRONMENTAL CONTAMINATION** (NOT my code — passes standalone; build edit is provably inert at default). Appeared after ~15 full-cluster test cycles this session (incl. the harmful flush_lockwait run). full8.sh virsh-resets VMs but the degradation persists (clyde target/LUN/harness state). First full8 (D1DD1926) PASSED cache_coherency in-suite; all subsequent failed 0/8. **NEXT SESSION: start COLD; if cache_coherency in-suite passes again it was transient. If it persists, the dev-host state needs clearing (user may need to reset clyde's SCST target — RULE 2 forbids rebooting clyde).**
2. **crash_consistency IN-SUITE HANG** (pre-existing, sess21's primary blocker; passes standalone 30s). ABBA: mxfs_dir_flush_data_blocks BLOCKING xfs_buf_incore(...,0,...) at xfs_mxfs_dlm.c:1612 runs holding dp->i_lock(read); a crash-recovery/peer ctx holds the dir buffer + needs i_lock(write). Capture the HOLDER (xfs_buf.b_lock_ip + all D-state stacks) to PROVE, then fix STRUCTURALLY (snapshot daddrs under i_lock, flush WITHOUT holding i_lock — like mxfs_dir_drain_evict_data_blocks). 

### REMAINING CODE WORK
- dir_reuse residual ~15% = IN-TENURE/handoff xfsaild destage TOCTOU (peer adds durably after our last refresh, before our async destage). Read-side invalidation can't fully close it. Needs a write-side transactional re-apply (NOT the chokepoint byte-merge — that made cross-block duplicates; NOT bail — breaks Inv 1).
- crash_consistency ABBA structural fix.
- Then: make levers DEFAULTS, verify 1/2/4/8 full suites.

### REFUTED (do NOT repeat): dir_flush_lockwait>0 (bail breaks Inv1 → coherency tests 0/8); dir_write_merge (cross-block dup over-count); dir_postread_reread=1 (FUA leaf re-read tears, all nodes shutdown).
### Tools: tests/tcp/drc_passrate2.sh N "MODARGS"; tests/tcp/full8.sh N "MODARGS"; /tmp scratch one_test.sh TEST MODARGS (single-test standalone, reset+run). ALWAYS verify a clean baseline before trusting full-suite results.
See [[sess29-CORRECTED-state-dir_reuse-85pct-not-100-flush-lockwait-harmful]] [[sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean]] [[sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall]] [[sess29-full8tcp-11of17-crashconsist-insuite-hang-is-last-wall]].
