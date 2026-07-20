---
name: sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix
description: sess14(ccloop) BREAKTHROUGH: cluster is LIO not SCST → FUA-read defaults required; AND coord_barrier -W 2 polling was the 18s/round bottleneck. dir_r…
metadata:
  type: project
---

## sess14 (ccloop 4cb2d0a2) — two root fixes land dir_reuse 4/tcp PASS within budget

### FIX 1 (correctness): the current cluster is a LIO target, NOT SCST
`lsscsi` on test1 = `LIO-ORG mxfs`; host has `iscsi_target_mod`/`target_core_mod` (LIO), no scst_tgt. On LIO each initiator has its own read cache → normal bio reads see STALE peer state; SCSI-FUA reads pierce to the coherent shared backstore. The sess63 default `fua_disable=1` (SCST shared-write-cache assumption) is WRONG here → default dir_reuse 4/tcp = readdir 0/400 & 322/400 (massive coherency fail, NO shutdown). The project memory `project_test_cluster_scst` describes an OLDER/different cluster generation.
CHANGED SOURCE DEFAULTS in xfs/xfs_mxfs_dlm.c (so the harness, which passes no modargs, gets coherency):
- `mxfs_fua_disable = 0` (was 1) — use FUA reads (LIO-required).
- `mxfs_fua_always = 1` (was 0) — the `_XBF_FUA_FRESH` amortization gate does NOT invalidate on cross-node dir handoff (gated config fua_always=0 fails IDENTICALLY to no-FUA: 0/400, 322/400 from round ~8), so force FUA on every coherency-metadata read. NOTE: fua_always costs NO extra wall vs gated (both ~same round time) — FUA is NOT the perf bottleneck (see FIX 2).
- `mxfs_dir_epoch_adopt = 1`, `mxfs_dir_epoch_convert_gate = 1` (were 0) — reliable cross-node EX-handoff detection + sf->block convert serialization.
Build srcversion `83CAA038`. With these, dir_reuse 4/tcp full 24-round = PASS 4/4, ZERO failrounds; corruption/shutdowns ELIMINATED.

### FIX 2 (perf, THE budget blocker): coord_barrier polling latency, NOT MXFS
Single-node FS ops for a whole round (50 files+sync+drop_caches+readdir+50 stat+rm+sync) = **0.45s total**. Yet a real round took ~18s. ROOT: `tests/suite/coord.sh` coord_barrier looped `mosquitto_sub -W $COORD_POLL --retained-only` with COORD_POLL=2 → it BLOCKS the full 2s window every poll even when all nodes already arrived. 5 barriers/round × 2s = ~10s/round of pure artificial polling, masquerading as MXFS slowness.
FIX: replaced with `mosquitto_sub -t "$base/r/+" -C "$MXFS_NODES" -W "$COORD_TIMEOUT"` — exits the INSTANT all NODES retained markers are received (broker delivers retained publishes to live subscribers too). Same barrier semantics. Result: dir_reuse 4/tcp WALL 465s → **205s** (≈7s/round), well within the 300s TEST_TIMEOUT. This speeds up ALL coordinated tests (cache_coherency, etc.).

### STATE / NEXT
- dir_reuse 4/tcp: PASS 4/4 in 205s (criterion conditions: default config, TEST_TIMEOUT=300). 3 consecutive full runs had 0 failrounds — the historical residual (1 .md5/run) did NOT reproduce with the new stack; confirm reliability over more runs.
- REMAINING for "1/2/4/8 tcp 100%": run FULL suites at 1/2/4/8 tcp, fix whatever else fails. 8/tcp NEVER run. Residual reliability TBD.
- Deploy: run.sh prep rmmods+insmods /src/mxfs/mxfs.ko (NFS-shared); boot auto-loads a stale ko but prep overrides it. Cluster test1-8 via `virsh -c qemu:///system`.
See [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]] [[sess13run-RELAY-test-does-rm-rf-each-round-ABA-daddr-reuse-verify-digen]].</body>
