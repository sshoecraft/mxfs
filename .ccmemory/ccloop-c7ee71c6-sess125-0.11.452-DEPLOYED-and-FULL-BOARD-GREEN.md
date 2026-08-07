---
name: ccloop-c7ee71c6-sess125-0.11.452-DEPLOYED-and-FULL-BOARD-GREEN
description: sess125 BROKE THE 20-SESSION VERIFICATION DROUGHT: deployed 0.11.452 to 32 nodes and re-ran the ENTIRE board. 26/26 functional PASS, no regressions.
metadata:
  type: reference
tags: [rig, board, 0.11.452, verification, deploy]
---

# sess125 — 0.11.452 deployed, full 32-node board GREEN

## The drought is over

Sessions ~105–135 landed 12 versions (0.11.440 → 0.11.452) of DLM-core
change WITHOUT EVER DEPLOYING. Fleet was pinned at srcversion
`DF0E1ABC1CEA16331E2DF6C` (0.11.440). Under RULE 6 nothing could close,
by construction, because closure requires a test that exercises the cause
and no test had run against the code.

sess125 deployed and re-boarded.

## Build identity
- tree VERSION **0.11.452**, srcversion **A1C4A05CB6356F02B8625F6**
- deployed to test1..test32, all mounted, converged active_count=32

## Timings (all inside RULE-0 budget)
- `./run.sh 2 caw prep_cluster` — **28s**
- `./run.sh 32 caw prep_cluster` — **73s**, converged 13s
- Full board, 4 chunks — ~15 min wall total

## Result: 26/26 functional tests PASS on 0.11.452

Chunk 1 (2m48): precond_readiness 1s, fio_perf 17s (seqW=10966MiB/s
seqR=7117MiB/s randW=408969iops randR=618956iops), fio_perf_vs_xfs 1s,
cache_coherency 24s/654 checks, strong_consistency 3s, posix_multi 5s/80,
mmap_coherency 4s/35, zero_silent_loss 28s/644.

Chunk 2 (4m00): dlm_fairness 19s, dlm_membership 4s, scaling_curve 6s,
dlm_scaling 14s, rsync_paired 15s, **crash_consistency 83s/90s, 204
checks, 32/32** (node kill + recovery — the heaviest exerciser of the
fencing/recovery paths), reconverged 32.

Chunk 3 (3m57): **dir_reuse_coherency 105s/120s, 79 checks**,
fence_during_write 20s (reconverged 32), fault_netpartition 9s
(reconverged 32), soak 32s.

Chunk 4 (4m16): dirent_durability 65s (rounds=30 durable_loss=0
late_ok=15 mkdir_err=0), node_responsive 11s dstate=0, **kernel_health
3s hits=0 kinds=[] across all 32**, ag_strand_repair 78s (strands=1
repaired=2 declined=0 abandoned=0 faults=0), sustained_load 4s errs=0,
dirent_publish_integrity 3s (stale_base_mutations=0
unlanded_at_unlock=0), dirent_type_integrity 3s (unresolved=0
total_flips=0), dlm_lock_correctness 1s.

## What this proves and does NOT prove

PROVES: the 12 versions of landed lifecycle/teardown/lreq/owed-worker
change do not regress ANY board criterion, produce ZERO dmesg hits on 32
nodes, and mount/unmount 32 nodes cleanly.

DOES NOT PROVE: any individual open defect is fixed. The board is the
regression detector, not the defect exerciser. Closure still needs a
per-defect test that exercises that defect's cause.

## Board verdict
27 PASS / 1 POLICY (`open_defects`, red by design under RULE 6).
The ONLY thing between MXFS and production-ready is the ledger.

## Process lesson (the important one)
Do not land more than ONE version without deploying. A landed-but-
undeployed change is worth less than nothing: it cannot close its defect,
and it silently accumulates regression risk that the next deploy has to
bisect. Deploy every version.
