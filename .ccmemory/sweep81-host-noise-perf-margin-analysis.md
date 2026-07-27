---
name: sweep81-host-noise-perf-margin-analysis
description: v0.11.81 sweep: ALL cawp correctness green ×6 rungs. Perf-margin FAILs = host neighbors (RTT p50 1.85→6.6ms proven); quiet-window list + rtt_gate.sh
metadata:
  type: project
tags: [sweep-v81, host-noise, rtt-gate, raw-ceiling, ccloop-c7ee71c6]
---

# v0.11.81 matrix sweep — host-noise perf-margin analysis (ccloop c7ee71c6 sess2)

## Environment finding (RULE 4, PROVEN)
Clyde carries neighbor workloads absent from the 7/20 green-sweep host state (host rebooted Jul 24 ~14:52 CDT): Wow.exe ~355% CPU, worldserver ~84%, VLLM workers ~120%, loadavg 12-40 idle, 50-150 during fio chunks. 32 VMs × 4 vCPU = 128 vCPU on 56 cores was fine on 7/20; + neighbors it collides.

**Proof**: raw dd-direct 4k read RTT on /dev/sda inside guests (mxfs NOT in path): idle-fleet p50 = 1.85ms (even with neighbors); during 32-node dlm_scaling storm p50 = 6.6ms, p90 11ms (test26+test1 probes, 400 samples each). Per-op wall ≈ 5.5-6.5 round-trips × RTT at every measured point (uncontended 10-12ms/op @1.85ms; 7/20 structural 19-21ms/op @~3.3ms; today contended ~30ms/op @6.6ms). v0.11.81 issues the SAME ~6 round-trips/op as the 7/20 build — mxfs exonerated twice over. Also: printk instrumentation cost measured 30µs/line ≈ 0.45ms/op (kmsg probe) — negligible; guest console loglevel already 1.

## Failure signatures (all correctness-clean, pace-only)
- 32/cawp dlm_scaling: node26 2000/2000 ops, rate≥floor, 61.6s vs 60s window (×2 runs; 3rd run at load-39 decay had many nodes miss). End-of-quota sprint to 80-90 ops/s proves capacity. checkpoints uniform ~7s/200ops — no discrete stall.
- 32/cawp dir_reuse_coherency: 50/50 coherency checks PASS, 7 rounds in 108s vs ≥8 bar.
- fio_perf_vs_xfs 8/2 cawp: mxfs randW swings 2-3x run-to-run (8n: 59/91/178K; 2n: 23/30/64K) vs raw-ceiling medians 89K/54K — distributions overlap the 70% bar. STALE CEILING TRAP: .raw_fio_ceiling.<cond>.json files were 5d old (quiet-host); refreshed cawp via scripts/raw_fio_ceiling.sh (destructive, unmount first, re-prep after). Fresh cawp ceilings: 2→54296 4→39054 8→88952 16→91809 32→218653 randW.
- 1/cawp single_node_paired 112% (bar 105%), fio_vs_xfs_baseline worst 51% w/ rounds 40→99% trend + randW 139% — SAME signature ladder-rung-health-gate memory root-caused to host noise before.

## Quiet-window re-verification list (OPEN, needs rtt_gate green)
scripts/rtt_gate.sh (NEW): p50≤2500µs && load1≤12 = storm cells have 7/20 margin. Re-run when open:
1. 32/cawp dlm_scaling  2. 32/cawp dir_reuse_coherency  3. 2/cawp fio_perf+vs_xfs (board PASS rode lucky sample 64429=119%; my 3-sample median 55% — NOT settled)  4. 8/cawp fio_perf+vs_xfs (final PASS 200%, samples 102/67/200% — confirm)  5. 1/cawp single_node_paired + fio_vs_xfs_baseline
Also refresh raw ceiling + xfs baseline PER CONDITION at each rig switch (both stale-pairing traps).

## Board state after cawp condition (v0.11.81 = 9674E330)
All 6 cawp rungs: every correctness/fault/membership/coherency/tooling row PASS except the perf-margin rows above. 16/cawp fully green including dlm_scaling(32s) dir_reuse(105s 86/86) fio pair (88% then 213% vs fresh ceiling). Logs: tests/logs/sweep81_cawp{32,16,8,4,2,1}.log.
