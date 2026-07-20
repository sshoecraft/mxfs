---
name: sess3-ccloop-DEFENSIVE-SKIP-dblfree-build-D567EC9A-inflight
description: sess3(ccloop) build D567EC9A adds ag_skip_dblfree (default 1): xfs_free_ag_extent skips a FULLY-already-free redundant free (stale-map double-free) i…
metadata:
  type: project
---

## sess3 (ccloop) — DEFENSIVE SKIP for the bnobt double-free. Build D567EC9A8A01CFFD2B36803. Experiment IN-FLIGHT at relay boundary (results not yet in).

### THIRD FIX (experimental, default-on, gated `mxfs_ag_skip_dblfree`): xfs/libxfs/xfs_alloc.c in xfs_free_ag_extent, at the "already free" overlap detection (~line 2248, before the XFS_IS_CORRUPT @2254): when multi-node AND the freed range is FULLY contained in the already-free left neighbour (`ltbno+ltlen >= bno+len`, ltbno<=bno guaranteed by lookup_le), log `P3-SKIP-DBLFREE` and `error=0; goto error0` (clean cursor cleanup + return 0) — SKIP the redundant free instead of the shutdown. Rationale: sess30/sess55 PROVED it's a stale-extent-map double-FREE, NOT a double-ALLOC → the blocks are genuinely already free cluster-wide → skipping is safe + correct (agf_freeblks not double-incremented since we skip before the accounting). Partial overlap keeps the hard corruption (would leak blocks). Param defn in xfs_mxfs_dlm.c after create_needinact_flush.

### GOAL: turn the catastrophic dir_reuse 4/8 double-free SHUTDOWN (which cascades the fault tests) into a safe no-op → dir_reuse should stop shutting down (may still hit the SEPARATE non-fatal single-dirent-loss 399/400 residual).

### IN-FLIGHT: /tmp/drc_skip.sh runs dir_reuse 4/tcp ×5 (reset between), reporting PASS/FAIL + P3-SKIP-DBLFREE + shutdown counts. NEXT SESSION: read /tmp/claude-1000/.../tasks/bel18hrwe.output (or re-run /tmp/drc_skip.sh) for results.
- IF pass rate ↑ and shutdowns→0 with P3-SKIP-DBLFREE firing: the skip WORKS — keep it, then re-run full 4/tcp + 8/tcp suites (fault cascades should clear), then 2/tcp ×several, 1/tcp tooling, bake force_block default 1→0. Also close the residual single-dirent-loss for true 100%.
- IF pass rate unchanged / new corruption: the skip is insufficient or unsafe (e.g. the double-free is partial-overlap, or masks a real issue that surfaces elsewhere) → revert (ag_skip_dblfree=0) and pursue the AG-coherence root (fresh AGF/bnobt on alloc) per [[sess3-ccloop-NEXT-bnobt-doublefree-site-and-hypothesis]].

### FULL SESSION STATE: build carries 3 fixes (keep_middle_block, create_needinact_flush, ag_skip_dblfree) + probes (P-CR3-CANCEL, P-CR3-NEEDINACT, P3-EFREE-Q, P3-SKIP-DBLFREE, P15-INSTR). 2/tcp=17/17 (with first 2 fixes). Run all with MXFS_EXTRA_MODARGS='dir_force_block=0'. Reset: scripts/ccloop_reset.sh <N>.
See [[sess3-ccloop-MILESTONE-2tcp-17of17-two-fixes-dir_reuse-flaky]] [[sess3-ccloop-NEXT-bnobt-doublefree-site-and-hypothesis]]
