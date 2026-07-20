---
name: sess14run-STATUS-2tcp-17of17-4tcp-16of17-tdscaling-marginal
description: sess14(ccloop) STATUS build 70F91E1B: 2/tcp FULL suite = 17/17 PASS. 4/tcp = 16/17 (only tcp_dlm_scaling marginal: ~44s/60s window, flaky in-suite).…
metadata:
  type: project
---

## sess14 (ccloop) STATUS — build 70F91E1B (fua_always=1 + readdir DABUF_MAP_HOLE fix + barrier perf fix)

### Final config (SOURCE DEFAULTS, no modargs needed by harness)
- xfs_mxfs_dlm.c: `fua_disable=0`, `fua_always=1`, `dir_epoch_adopt=1`, `dir_epoch_convert_gate=1` (LIO cluster requires FUA reads; gated fua_always=0 is NOT reliable — gated defaults run = crash_consistency 3/4 + dir_reuse 0/4).
- xfs/xfs_dir2_readdir.c: readdir bumps i_dlm_dir_gen ONLY after a successful reload (fixes round-23 DABUF_MAP_HOLE shutdown).
- tests/suite/coord.sh: coord_barrier uses `-C $MXFS_NODES` (instant rendezvous; was -W 2 fixed wait = ~10s/round). Speeds ALL coordinated tests.
- tests/tcp/tcp_dlm_scaling.sh: added a `mxfs-TDS ... elapsed=` /dev/kmsg diagnostic (harmless).

### Results
- **2/tcp FULL = 17/17 PASS** (tcp_dlm_scaling 2/2, all coherency+fault+soak).
- **4/tcp = 16/17**: all PASS except tcp_dlm_scaling, which is MARGINAL — standalone passes 4/4 but elapsed is ~44s for ranks 2-4 (rank1 ~7s; one node always finishes fast = DLM unfairness) vs the 60s window; in-suite (after soak) the extra contention pushes 2/4 nodes >60s → FAIL. fua_always vs gated makes NO difference to this (~44s both) — it is pure DLM dir-EX handoff throughput (1800 serialized cross-node ops; per-release Invariant-#1 drain = settle-loop + 2× log_force + mxfs_dir_flush_data_blocks + mxfs_ail_drain_inode_sync + blkdev_issue_flush(~25ms) at xfs_mxfs_dlm.c ~5788-5818).
- dir_reuse_coherency 4/tcp now PASS reliably in-suite (readdir fix).

### NEXT
1. 8/tcp + 1/tcp full suites (not yet run; 8/tcp will stress tcp_dlm_scaling MORE = 8-way contention, likely the hardest).
2. Make tcp_dlm_scaling reliable: reduce dir-EX handoff latency WITHOUT breaking Invariant #1. The per-release blkdev_issue_flush + settle loop dominate. Candidate: FUA-write dir blocks so the full-device flush can be elided; or tighten the settle loop. HIGH RISK (coherency-critical) — measure carefully.
See [[sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix]] [[sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail]].
