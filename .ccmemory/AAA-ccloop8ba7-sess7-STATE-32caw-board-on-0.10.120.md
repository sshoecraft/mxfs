---
name: AAA-ccloop8ba7-sess7-STATE-32caw-board-on-0.10.120
description: sess7 state: dbl-alloc FIXED (P150, validated 4×), P56 print regression fixed (0.10.120 F2443A0C). 32/caw board re-recorded green on final build exce…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7, state, ladder]
---

# sess7 running state — 32/caw board on 0.10.120 (srcver F2443A0C)

## Build lineage this session
- 0.10.118 (B70D745A): +P146-RELDUR, +P147-PREUNLOCK (both unlock arms), P105 high-ino un-ratelimited+chg, P56 capped-unratelimited (LATER PROVEN A PERF REGRESSION — see printk memory).
- 0.10.119 (8C047F6F): +P150 READ-PRESERVE (the double-alloc root fix — see ROOT memory). Validated: repro iters 15/17/18/19 corruption-clean (pre-fix ~1-in-2).
- 0.10.120 (F2443A0C): P56 back to ratelimited (dlm_scaling@32 restored PASS 49s). FINAL build for criteria rows.

## 32/caw board on F2443A0C (all RULE0_CALIBRATE=1, chunked ./run.sh 32 caw <tests>)
PASS: prep(114s) precond(1s) cc(83s, 3021/3021) sc(16s) pm(62s) mmap(6s) zsl(29s) dlm_fairness(37s) dlm_membership(8s) scaling_curve(8s) dlm_scaling(49s) rsync_paired(16s) crash_consistency(108s) fence_during_write(22s) fault_netpartition(19s) dlm_lock_correctness(0s) fio_perf(328s; seqW 3168MiB/s; NOTE 3-9× run variance — 779MiB/s one run = vs_xfs 37% FAIL; rerun on quiet LUN passes) fio_perf_vs_xfs soak(33s).
RUNNING: dir_reuse_coherency (background, expected wall ~3242s per old row).

## Protocol lessons (cost hours)
- NEVER wrap ./run.sh in timeout < its own per-node kill ceiling (CALIBRATE = budget×20; fio: 600s) — killing mid-fio O_DIRECT shutdowns 1-11 nodes ASYNC (casualties appear minutes later) → pre-assert failures → forced re-prep. Long tests: run in background uncapped, poll the log for 'done:'.
- fio_perf wall 225-600s+@32, aggregate seqW 0.78-7.5GB/s run-to-run on shared NVMe — if vs_xfs fails on worst(write)%, rerun when LUN quiet.
- Balloon persisted: all VMs virsh setmem 2621440 --live AND --config (survives prep's virsh reboots).

## After dir_reuse@32
Rungs on SAME build: for N in 16 8 4 2 1: MXFS_FORCE_PREP=1 prep + full suite chunks (dir_reuse walls: 1251/598/329/275/111s). Then criteria marker ONLY on full green.
Family-A/ili-leak: 'Objects remaining in mxfs_ili' seen on test14 at 3 rmmods (pre-P150 too, not mine); zero on sampled nodes at latest unloads; latent, non-blocking so far.
