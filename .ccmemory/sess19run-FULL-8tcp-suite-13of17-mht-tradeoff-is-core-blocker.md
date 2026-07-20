---
name: sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker
description: sess19(ccloop): FULL 8/tcp suite = 13/17. dir_reuse + tcp_dlm_scaling blocked by the mht tradeoff (opposite needs). Inode-skip fix KEEP, all coherenc…
metadata:
  type: project
---

## sess19 (ccloop) — first FULL 8/tcp suite characterization; mht tradeoff is THE blocker

### FULL `./run.sh 8 tcp` = 13 PASS / 4 FAIL (build 0A6350A1, mht=275 default)
PASS (13): precond_readiness, **cache_coherency, strong_consistency, zero_silent_loss, crash_consistency** (all coherency-critical — proves my inode fix is SAFE), posix_multi, mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, soak.
FAIL (4):
- **dir_reuse_coherency 0/8** = "no-result" = KILLED by 300s TEST_TIMEOUT. Passes STANDALONE at ~294s (6s margin too thin to survive in-suite slowdown). Cascade root.
- **fence_during_write 7/8, fault_netpartition 7/8** = CONTAMINATION (both PASS 8/8 standalone after clean reboot). test5 cited — cascade from dir_reuse timeout wedging the cluster.
- **tcp_dlm_scaling 1/8** = REAL 8-node failure, FAILS even truly-standalone. test5 `connection1:0: detected conn error (1020)` (iSCSI drop) + test2 `P36-RETRY ino=0 type=3 mode=EX (acquire timeout)` and `TDS rank=2 rounds=150 window=60` but elapsed=115s → 2× too slow for the 60s window.

### THE CORE BLOCKER = the mht tradeoff (confirms [[sess15run-MHT-tradeoff-tcpdlm-wants-low-dirreuse-wants-high]]):
- **tcp_dlm_scaling needs LOW mht (~50)** — at mht=275 each node holds DLM locks 275ms → 150-round window blows (115s vs 60s) → acquire-timeouts cascade → test5 iSCSI conn-drop wedge.
- **dir_reuse needs HIGH mht (≥275)** — at low mht more dir-EX handoffs → dir free-slot reload race → durable dirent loss.
- ONE global `inode_mht_ms`, opposite needs → NO single mht passes both. My default 300→275 helps dir_reuse, breaks tcp_dlm_scaling.
- **RESOLUTION = make dir_reuse CORRECT at LOW mht (the dir reload-reliability fix, [[sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead]]), then default mht=50 → BOTH pass.** My inode-skip fix does NOT address dir reload (it's inode coherency, not dir free-slot).

### KEEP (build 0A6350A1):
1. **inode-cluster cached-allocated skip** (xfs_icache.c `mxfs_dinode_cached_allocated` + param `inode_cluster_owned_skip`=1): the sess38 per-inode cluster re-stale fired on EVERY iget, re-FUA-reading the whole 32-inode cluster (igstale 5376/8rounds → 0). Skip when cached cluster shows THIS inode ALLOCATED (inverse of the sess38 cached-FREE ENOENT bug; content still refreshed at ilock). Cut inode FUA ~30%, validated safe across ALL coherency tests.
2. mht default 300→275 (xfs_mxfs_dlm.c:5402) — RECONSIDER: breaks tcp_dlm_scaling; the real target is low mht + reload fix.
3. Diagnostic counters (FUA-COUNT scsi/p91skip/oskip/igstale) + gated probes (P19-INOFUA, P15-DIRFUA comm, P19-DIRINVAL) behind dir_perf_probe.

### dir_reuse speed: ~294s standalone (was ~315 pre-fix). Cost = FUA-read latency (~150k SCSI FUA/node/run, ~0.93ms each). DIR-block thrash dominates: same ~17 blocks re-read ~336×/round during rm+verify, with **DIRINVAL=0** (NOT the gen-invalidation) → blocks reach read NOT-XBF_DONE via EVICTION (mechanism unfound). Cracking it could cut rm 3.5s→0.5s = huge margin. Next: find the dir-buffer eviction source (xfs_buf_stale on live blocks? LRU b_lru_ref=0?).
</body>
