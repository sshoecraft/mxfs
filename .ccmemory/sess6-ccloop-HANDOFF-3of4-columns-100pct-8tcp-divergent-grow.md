---
name: sess6-ccloop-HANDOFF-3of4-columns-100pct-8tcp-divergent-grow
description: sess6(run6614) HANDOFF build 9AA569A0: 1/2/4 tcp = 100% (dir_reuse FIXED). ONLY 8/tcp left (11/17): divergent-grow torn extent-map (DABUF_MAP_HOLE) +…
metadata:
  type: project
---

## sess6 (run 6614) HANDOFF — build 9AA569A0. 3 of 4 columns at 100%.

### CRITERION STATUS (get 1/2/4/8 tcp dlm test 100%):
- **1/tcp = 16/16 = 100% ✓** (verified; was disk-space env — logs filled /var → /tmp full. Truncate /var/log/{syslog,kern.log} if it regresses.)
- **2/tcp = 17/17 = 100% ✓** (re-verified on FINAL build 9AA569A0.)
- **4/tcp = 17/17 = 100% ✓** (full suite; + dir_reuse 12/12 reliability.)
- **8/tcp = 11/17 ✗** — the ONLY remaining blocker. Marker NOT written.

### THE FIX THAT WON 4/tcp (build 9AA569A0, both DEFAULT-ON, KEEP — verified no 2/tcp regress):
1. `mxfs_dir_gg_refresh=1`: arm evict-only drain_evict refresh on grant_gen change (reliable handoff signal; dg_shadow handoff bit under-fires ~80% on TCP). Fixes whole-block (100-entry) loss.
2. `mxfs_dir_release_flush_leaf=1` (was silently 0): force-complete LEAF/NODE/FREE blocks at release so next acquirer cold-reads a self-consistent fork. Fixes single leaf-hash hole. Safe ONLY with gg_refresh (fresh leaf base each handoff). Details: [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]].

### 8/tcp FAILURES (full suite, build 9AA569A0): cache_coherency 0/8, zero_silent_loss 0/8, rsync_paired 4/8, dir_reuse 0/8, fence_during_write 7/8, soak. (PASS: precond, strong_consistency, posix_multi, mmap, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, crash_consistency, fault_netpartition, tcp_dlm_scaling.)

### 8/tcp FAULT FACES (dmesg):
1. **DABUF_MAP_HOLE / divergent-grow torn extent map** (PRIMARY): test1 `P-IFLUSH-GAP-DETECT ino=131 nextents=8 — in-core dir data fork has a HOLE between data blocks (divergent-grow torn map; DABUF_MAP_HOLE / leaf-addname-oops source)` → `XFS Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2885 xfs_dabuf_map` → shutdown. This is a CONCURRENT DIR-GROW at 8 nodes: a node reloads a STALE on-disk dinode (peer's dir-grow not yet IFLUSHED = sess105 stale-inode-core hole), sees the dir too short, RE-GROWS it → torn/holey extent map. My gg_refresh reload rebuilds the fork from disk but adopts the STALE on-disk dinode (extent map / di_nextents not durable). LIKELY NEXT FIX: durable_signal (mxfs_dlm_dir_durable_signal, xfs_mxfs_dlm.c:18481) flushes data+leaf BLOCKS but NOT the DINODE — the growing node must xfs_iflush the dinode (extent map) BEFORE release so the next acquirer reloads a CURRENT map. Test a dinode-flush in durable_signal / release drain (careful: don't regress 4/tcp).
2. **mxfs_dlm_fence_notify shutdown** (test5-8): `Metadata I/O Error at mxfs_dlm_fence_notify+0x3c xfs_mxfs_dlm.c:23348 Shutting down` — the fence_during_write test face; may cascade.
3. alloc btree corruption (test5): `Internal error i != 1 at xfs_alloc.c:657 xfs_alloc_fixup_trees` — AG-level, at higher node count.
4. dir_reuse residual single-dirent (799/800) still at 8 nodes.

### NEXT SESSION: focus 8/tcp. Start: reset 8, run `./run.sh 8 tcp dir_reuse_coherency` isolated; the torn-map (DABUF_MAP_HOLE) is the highest-leverage — fix the stale-dinode-reload / dir-grow durability (sess105/sess54 fork-rebuild + iflush-before-release). Also determine if cache_coherency/zsl/rsync/soak 0/8 are independent or cascade from one early shutdown (run.sh runs all tests on one mount — an early shutdown breaks later tests). FAST repro: scripts/drc_reliability.sh 8 6. Watch RULE 0 timing (runs got slower with gg_refresh+leaf-flush — ~4-5min/run; check 8-node wall vs budget).
See [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]] [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]]</body>
