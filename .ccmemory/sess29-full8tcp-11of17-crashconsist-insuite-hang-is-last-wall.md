---
name: sess29-full8tcp-11of17-crashconsist-insuite-hang-is-last-wall
description: sess29(ccloop) FULL 8/tcp suite = 11/17 then crash_consistency IN-SUITE HANG (pre-existing, NOT my fix — standalone PASSES 30s). Hang = blocking xfs_…
metadata:
  type: project
---

## sess29 — FULL 8/tcp suite result with the winning dir-coherency config

### Config (build D1DD1926, MXFS_EXTRA_MODARGS)
`dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`

### Full `./run.sh 8 tcp` (all 17 tests): 11 PASS, then crash_consistency FAIL (0/8) → suite blocked
PASS (11/11 reached): precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired — ALL 8/8.
**FAIL: crash_consistency (0/8) = IN-SUITE HANG.**

### crash_consistency hang is PRE-EXISTING, NOT caused by my dir-coherency fixes (DECISIVE A/B)
- **crash_consistency STANDALONE with the SAME full modargs (incl. relinval_clean) = PASS 8/8 in 30s.** So relinval_clean does NOT cause it.
- This is exactly sess21's documented "PRIMARY 8/tcp BLOCKER = crash_consistency FLAKY IN-SUITE HANG: standalone=29s PASS 8/8, but in full suite HUNG >300s — a RARE race under full accumulated suite state, NOT slow work."
- **Hang signature (hung-task, test1)**: TWO threads D-state >491s, BOTH in `mxfs_dir_flush_data_blocks+0x39f` → `xfs_buf_get_map` → `xfs_buf_find_lock` → `xfs_buf_lock` (BLOCKING). One is the BAST kworker (`mxfs_dlm_bast_work_fn`), one is a user `bash` syscall. Both BLOCK acquiring a dir buffer a THIRD party holds (likely a crash-recovery/journal-replay/peer-grant context during crash_consistency's node-death+replay). The blocking get is `xfs_buf_incore(targp, d, dir_blk_bb, 0 /*flag 0 = BLOCKING*/, &dbp)` at xfs/xfs_mxfs_dlm.c:1600. Its comment claims "bounded by xfsaild, can't cycle" — FALSE under crash recovery (a non-xfsaild holder wedges it). Nodes stay reachable (soft wedge, D-state).

### STATE OF THE CRITERIA (1/2/4/8 tcp 100%) — NOT MET
- **dir_reuse_coherency 8/tcp: SOLVED** (5/5, release_invalidate + relinval_clean). The 130-session blocker.
- **8/tcp full suite: blocked ONLY by crash_consistency in-suite hang** (11/17 reached; dir_reuse + the post-crash tail cascade after the hang).
- NOT yet done: (a) fix crash_consistency in-suite hang; (b) verify 1/2/4 tcp full suites with the config; (c) make the 4 levers MODULE DEFAULTS so bare `./run.sh` uses them.

### NEXT (RULE 4) — crash_consistency in-suite deadlock
Root to chase: the blocking `xfs_buf_incore(...,0,...)` at xfs_mxfs_dlm.c:1600 in mxfs_dir_flush_data_blocks deadlocks during crash recovery when a dir buffer is held by a recovery/peer context AND a concurrent flusher (bast kworker + user syscall both call mxfs_dir_flush_data_blocks for the same dir). Candidates: (1) serialize concurrent flush_data_blocks per-dir; (2) make the get a bounded trylock-wait (like mxfs_dir_acq_lockwait) + let the outer release loop (xfs_mxfs_dlm.c ~7325, data_durable + 15000-iter shutdown backstop) retry, converting the hard wedge into bounded retry; (3) find/break the cross-context buffer holder during replay. Reproduce: full `./run.sh 8 tcp` (hang at crash_consistency) OR a contaminating prefix (run ~11 tests then crash_consistency). Capture the buffer HOLDER (the 3rd thread) via `dmesg | grep -B2 -A20 "blocked for more"` on all nodes at the wedge.
See [[sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean]] [[sess21-NEW-blocker-crash_consistency-8node-straddles-300s-timeout]].
