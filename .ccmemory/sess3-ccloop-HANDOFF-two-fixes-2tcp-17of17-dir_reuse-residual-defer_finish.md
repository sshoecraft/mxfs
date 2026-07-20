---
name: sess3-ccloop-HANDOFF-two-fixes-2tcp-17of17-dir_reuse-residual-defer_finish
description: sess3(ccloop) HANDOFF: build 24EDC1F3, 2 net-positive fixes, 2/tcp=17/17. NEXT TARGET=bnobt AG-extent double-free (deterministic dir_reuse 4/tcp bloc…
metadata:
  type: project
---

## sess3 (ccloop) HANDOFF — build 24EDC1F369E957AFB36E3F7 (KEEP). Criterion NOT met; marker NOT written.

### TWO FIXES LANDED (default-on, KEEP, NET-POSITIVE — proven not regressions), run with `MXFS_EXTRA_MODARGS='dir_force_block=0'`:
1. `mxfs_dir_keep_middle_block` (xfs_dir2_leaf.c:2252) — dir torn-map deterministic corruption FIXED.
2. `mxfs_create_needinact_flush` (xfs_icache.c:866) — reused-inode CREATE ENOENT cascade FIXED (2/tcp fault tests). **A/B PROVEN not the dir_reuse regressor**: dir_reuse 4/tcp fails 0/4 with create_needinact_flush=0 too.

### RESULTS: **2/tcp = 17/17** (clean run, recovers sess58). 4/tcp = 12/17 (cache_coherency 4/4 — was 0/4 pre-fix!). 8/tcp: dir_reuse passed standalone once. 1/tcp: 14/16 (tooling).

### NEXT TARGET (THE deterministic gating blocker) = bnobt AG-EXTENT DOUBLE-FREE:
- dir_reuse 4/tcp standalone FAILS ~3/3 now (deterministic; the earlier build-5726D17A 4/4 pass was a lucky run — flaky/degraded). Shutdown root PROVEN by the in-tree P15-INSTR probe:
  `P15-INSTR FREE-AG-EXTENT-FAIL-LEFT caller=__xfs_free_extent comm=dd agno=0 bno=67552 len=2 ltbno=67552 ltlen=2` → `xfs_defer_finish_noroll xfs_defer.c:721 Corruption of in-memory data → SHUTDOWN`.
  = freeing a 2-block FILE extent that is ALREADY free (bno==ltbno && len==ltlen, exact double-free). comm=dd = file write/truncate path, NOT a dir block (so NOT keep_middle).
- This is the deep pre-existing bnobt double-free family (freed-and-realloc'd block cross-node coherence). PRIOR FIXES to study/extend: sess42 (C6970FF9 "only advance b_mxfs_ag_gen when genuinely fresh"), sess43 (BB54A138 "in-AIL AG-meta must not be discarded — committed-not-written = this-node-ahead"), sess47 (29977E5D "node inactivates STALE cached inode; FUA-check di_mode/di_gen, skip if stale"), sess44/46/81. Likely: a stale cached AGF/AGFL/inode-extent-map being freed → double-free. Use P15-INSTR to catch the exact producer; add a probe at the FILE inactivation/truncate that frees bno=X to see if it's a stale-incarnation inode's extents.
- SECONDARY residual: leaf-hash single-dirent-loss (readdir 399/400), read-side P22-DATASCAN heals most, 1 slips.

### PLAN: fix the bnobt double-free → dir_reuse becomes reliable → 4/8 full suites pass (fault cascades are downstream) → re-run 2/4/8 ×several → 1/tcp tooling → bake force_block default 1→0 (xfs_mxfs_dlm.c:6560) → criterion.
### Infra: scripts/ccloop_reset.sh <N>. Probes: P-CR3-CANCEL, P-CR3-NEEDINACT, P15-INSTR (AG-free double-free), P22-DATASCAN (leaf-hash heal).
See [[sess3-ccloop-MILESTONE-2tcp-17of17-two-fixes-dir_reuse-flaky]] [[sess47-BREAKTHROUGH-3-wedge-fixes-8tcp-passes-sometimes-final-blocker-p13-collide]] [[sess42]] [[sess43]]
