---
name: ccloop-c7ee71c6-sess12-B-dlm-scaling-harness-and-32tcp-green
description: sess12-B: 32/tcp spot tier green at .114 (join 24flap/24heal/0death); dlm_scaling FAIL = harness fork overhead (proven via fork-free probes); red-lis…
metadata:
  type: project
tags: [dlm-scaling, 32-node, harness, perf, red-list]
---

# sess12-B: 32/tcp tier + dlm_scaling harness root-cause + remaining red-list

## 32/tcp at v0.11.114 (71ABF349) — all PASS
prep 65-201s (32/32 converge), join storm 24 flaps/24 heals/0 false deaths/0 P164 —
the sess12-A fix validated at 496 pairs. Rows: precond, cache_coherency (654 checks),
fence_during_write, dlm_scaling (33s), dir_reuse_coherency (113s, 72 checks),
tcp_dlm_scaling (48s), withdraw@32 (190s episode, 30 purges, 0 dangles).
test17-32 required scripts/wire_vms.sh attach 17..32 + restart (XML detached since flip).

## dlm_scaling@32 FAIL root (RULE 4 chain, all measured)
- Test pace 21.4 ops/s/node (uniform, no laggard) vs floor 30 → NO_TERMINAL_RECORD.
- Fork-free python probe: solo 1805 ops/s; K=32 median 60 ops/s, aggregate ~2044 —
  60/s CLEARS floor 30 and window (2000 ops = 33s < 60s). Local-ext4 K=32 control:
  24.7k/node (host CPU exonerated). iostat during storm: ~2000 w/s + ~1000 flush/s on
  nvme = per-op durable publish through single fileio backstore = the aggregate ceiling
  (capacity-fair convoy; K=32 latency 16.7ms ≈ 32× solo 0.55ms).
- The test's op forked stat+rm binaries (~30ms/op on 128vcpu/56thread oversubscription)
  — harness, not SUT. FIX: op loop → single python3 process (same ops/checkpoints/
  first-fail forensics; assertions untouched). Re-run: 2/tcp 1s, 16/tcp 16s, 32/tcp 33s
  ALL PASS. Same correction class as sess11-C fio_perf_vs_xfs native-baseline fix.
- DESIGN NOTE (real, not bug): mxfs metadata aggregate ≈ shared-LUN sync-write+flush
  rate (~2000/s this rig); per-node fair share shrinks 1/K. cawd similar (~1600 agg).

## tcp column COMPLETE at .114
1/tcp 29/29 (incl fio_vs_xfs_baseline 79% worst-write ≥ gate, single_node_paired 82%),
2 and 4 19/19+withdraw, 16 20/20+withdraw, 32 spot(7)+withdraw.

## Remaining red-list (14 cells, ALL pre-SCST-era records needing SCST re-runs)
16/cawp ×7 rows (03:46-51, tcm_loop era = disproven-infra family, never re-run on SCST);
16/caw prep_cluster (3s infra); 1/cawd single_node_paired; 1/cawp single_node_paired +
fio_vs_xfs_baseline (07-25 old rig); 32/caw dlm_scaling; 32/cawp dlm_scaling +
dir_reuse_coherency (07-25, pre-harness-fix + old rig).
Plan: rig flips — (A) SCST direct → 1/cawd row; (B) SCST passthrough 16 → 16/cawp
board+withdraw, 1/cawp rows; extend wiring 17-32 → 32/cawp 2 rows; (C) multipath →
16/caw prep+spot, 32/caw dlm_scaling. CAW cells re-run at .114 (TCP-only delta, inert).

## fence-mkdir one-shot — disposition argument (document, keep tripwire)
The single 8/cawd silent mkdir-ENOENT PREDATED the P95D ghost-dirent fix; same trigger
(drc+fence), same subsystem (stale SF dir body → path-walk miss). Post-P95D: 14+ board
fence runs (2/4/8/16 caw+tcp + 32 today) + 50 targeted repros = zero recurrence with
tripwire armed. Disposition: fixed-by-P95D-family; tripwire stays as regression guard.
