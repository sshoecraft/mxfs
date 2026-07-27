---
name: sweep81-progress-board
description: v0.11.81 sweep progress: cawp done (6 perf-margin rows→quiet list), cawd ALL GREEN ×6 rungs (exc single_node_paired 1/cawd=noise-proven), caw next
metadata:
  type: project
tags: [sweep-v81, progress, ccloop-c7ee71c6]
---

# v0.11.81 matrix sweep — progress board (ccloop c7ee71c6 sess2)

## Condition status (build 9674E330, all runs RULE0-enforced, foreground chunks)
- **cawp (6 rungs)**: DONE. All correctness/fault/membership/coherency/tooling green. Perf-margin rows on quiet-window list: 32 dlm_scaling, 32 dir_reuse, 2+8 fio_vs (see sweep81-host-noise-perf-margin-analysis), 1 single_node_paired + fio_vs_xfs_baseline.
- **cawd (6 rungs)**: DONE — **ALL GREEN including 32-node dlm_scaling (60s) + dir_reuse (65/65)** at loadavg~30 (in-guest iSCSI path amortizes host noise better than cawp's qemu passthrough). Only 1/cawd single_node_paired FAIL (128%): mxfs rounds ballooned 2928→6902ms mid-test BUT standalone probe (4 consecutive mkfs+mount+rsync legs on test1) measured 3577/3106/3008/3619ms FLAT ≈ native — no accumulation effect, transient noise hit proven. → quiet-window item.
- **caw (mpath)**: rig up 32/32 2-path mpatha; ceiling re-capture in flight; rungs next.
- **tcp**: after caw. Must refresh .raw_fio_ceiling.tcp.json (7/19-era stale) + xfs baseline at switch.

## Measurement-infrastructure fixes this session (RULE 3, in scripts/)
1. **raw_fio_ceiling.sh legs now time_based** (ramp 5s + measure 15s): old size-bounded legs completed sub-second on fast paths and reported in-flight burst absorption as "ceiling" (cawd measured 95GiB/s = 24x physical NVMe).
2. **fio --filename colon-split trap FIXED in script** (DEV="${DEV//:/\\:}"): unescaped by-path names made fio CREATE regular files (one in guest devtmpfs=RAM) and benchmark memory; junk files cleaned from all 32 guests (/dev/disk/by-path type-f + /root relative-path leftovers).
3. **rtt_gate.sh** (new): objective quiet-window gate (raw dd p50≤2500µs && load1≤12) for storm-sensitive cells.
4. Fresh cawd ceilings (sane, nvme-bound): randW 4→70813 8→63606 16→51052 32→57516; seqW 176-713MiB/s.
5. Ceiling+baseline refresh MUST happen per-condition at rig switch (both stale-pairing traps); ladder_rung.sh does baseline only — do ceiling manually while unmounted post-switch.

## Sequence per condition
rig.sh {pass|direct|mpath|tcp} 32 → raw_fio_ceiling.sh <cond> (unmounted; RAWCEIL_DEV: cawp/cawd/tcp=/dev/sda default, caw=/dev/mapper/mpatha) → health gate + run.sh 1 xfs prep+fio_perf w/ XFS_BASELINE=.xfs_fio_baseline.<cond>.json (MXFS_DEV per cond) → rungs 32,16,8,4,2,1: MXFS_FORCE_PREP prep_cluster then ladder_rung.sh chunk lists as foreground run.sh calls; N=1 adds tooling chunk last. NOTE: xfs baseline run flips cluster marker to 1/xfs — always re-prep the mxfs rung after.
