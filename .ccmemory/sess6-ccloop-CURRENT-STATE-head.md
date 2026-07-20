---
name: sess6-ccloop-CURRENT-STATE-head
description: CURRENT STATE head sess6(run6614): build 9AA569A0, 1/2/4 tcp=100%, 8/tcp=11/17 (divergent-grow torn-map + cache_coherency/zsl/rsync). Marker NOT writ…
metadata:
  type: project
---

## CURRENT STATE — head sess6 (run 6614), build 9AA569A0 (clean, builds, deployed to test1-8)

Criterion "get 1/2/4/8 node tcp dlm test 100%": **3 of 4 columns done.**
- 1/tcp = 100% ✓ | 2/tcp = 100% ✓ | 4/tcp = 100% ✓ | **8/tcp = 11/17 ✗** (only blocker).
- **Marker NOT written.**

### What shipped this session (KEEP, both DEFAULT-ON, no 2/tcp regression):
- `mxfs_dir_gg_refresh=1` + `mxfs_dir_release_flush_leaf=1` → fixed dir_reuse_coherency (the ~50-session blocker) at 4/tcp (12/12). Full detail: [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]].
- Also fixed 1/tcp (disk-space env). Refuted phantom-EX root: [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]].

### 8/tcp remaining (NEXT SESSION): [[sess6-ccloop-HANDOFF-3of4-columns-100pct-8tcp-divergent-grow]]
8-node failures: cache_coherency 0/8, zero_silent_loss 0/8, rsync_paired 4/8, dir_reuse 0/8, fence_during_write 7/8, soak. Two+ roots:
1. dir_reuse **divergent-grow torn extent map** (P-IFLUSH-GAP-DETECT → DABUF_MAP_HOLE xfs_da_btree.c:2885 shutdown) — likely stale-dinode reload → re-grow. Cascades to fence/soak (all tests share one mount, no per-test remkfs). Candidate: iflush dinode (extent map) before EX release in durable_signal.
2. cache_coherency/zsl/rsync 0/8 — separate 8-node coherency/scaling issue (passed at 2/4 nodes); check if shutdown/timeout(RULE 0)/loss.
Start: `scripts/ccloop_reset.sh 8; ./run.sh 8 tcp dir_reuse_coherency` then isolate cache_coherency. FAST: `scripts/drc_reliability.sh 8 6`.</body>
