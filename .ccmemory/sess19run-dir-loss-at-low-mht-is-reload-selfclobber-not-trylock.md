---
name: sess19run-dir-loss-at-low-mht-is-reload-selfclobber-not-trylock
description: sess19(ccloop): dir_reuse loss at mht=50 = deep dir-data-block handoff-reload race (P63/P64-HANDOFF), NOT P34-TRYLOCK (5-32x) nor P116/P103 (those ar…
metadata:
  type: project
---

## sess19 (ccloop) — the dir-reload loss mechanism at low mht (path to resolving the mht tradeoff)

### Final build = `15447D0C` (mht default = 300; inode-skip fix KEEP). Marker NOT written.

### The mht tradeoff is the core full-8/tcp-suite blocker. CONFIRMED:
- tcp_dlm_scaling **PASS 8/8 @ mht=50** (40s); **FAIL @ mht=275** (150 rounds take 115s vs 60s window → AG-acquire-timeout + test5 iSCSI conn-error 1020 cascade).
- dir_reuse **PASS @ mht=275** (~294s); **FAIL @ mht=50**: durable dirent loss round7=797/800, round8=670/800 (130 lost), ALL nodes agree (durable on-disk), lookup_fail=0 (readdir SHORTFALL = data-block dirent clobber). 18/24 failrounds.
- ONLY resolution: make dir-heavy tests CORRECT @ low mht, then default mht=50.

### LOSS MECHANISM (RULE-4 probe counts from a failing mht=50 run):
- **P34-TRYLOCK-STALE = 5-32× → NOT the cause** (refutes sess18's TRYLOCK-skip lead as the main driver; a bounded-retry fix would not stop the 130-entry loss).
- **P116-RELOAD-SELFCLOBBER / P103-RELOAD-REUSE-ADOPT are INODE reload paths (mxfs_dlm_reload_inode, di_size/di_mode/gen), NOT the dirent loss.** P116 is a `-SKIP` GUARD (prevents clobber), high count = inode-reuse churn, a red herring for the dirent loss.
- **The dirent loss is in the DIR-DATA-BLOCK handoff reload: P63-HANDOFF/P64-MASTER-HANDOFF (~138-160×), P62-RELOAD (280×), P65-EPOCH (~138×).** At mht=50 the dir-EX handoff frequency is ~10× mht=275 → the per-handoff reload race (rare at 275) becomes heavy.

### LEAD for the fix (next session): the durable dirent loss across a dir-EX handoff = either (a) the RELEASING node releases the dir-EX (BAST) before its just-added dir-DATA blocks are durably on the shared LUN (Invariant #1 "no DLM unlock without drain" — at low mht the release-fast-path may skip/rush the dir-data drain), so the acquirer's FUA reload reads a disk image MISSING the peer's entry → addname picks that "free" slot → durable clobber; OR (b) the acquirer's reload doesn't refresh ALL data/free/bests blocks. Instrument: at a failing round, compare the releasing node's dir-data on-disk image vs in-core at BAST time (is the entry durable before release?). Check the dir-data drain in the dir-EX BAST/release path (bast_work_fn Phase-2 drain_meta/alloc/inode + blkdev_flush) actually covers dir DATA/leaf/free blocks at low mht. See [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]], [[sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead]].

### KEEP (build 15447D0C): inode-cluster cached-allocated skip (xfs_icache.c `mxfs_dinode_cached_allocated` + param `inode_cluster_owned_skip`=1) — inverse of the sess38 cached-FREE ENOENT bug; cut inode FUA ~30%, validated SAFE across ALL coherency tests (cache_coherency/zero_silent_loss/strong_consistency/crash_consistency all 8/8). Diagnostic counters + dir_perf_probe-gated probes retained.
</body>
