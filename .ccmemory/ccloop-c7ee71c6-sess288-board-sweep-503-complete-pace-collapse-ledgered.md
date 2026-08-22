---
name: ccloop-c7ee71c6-sess288-board-sweep-503-complete-pace-collapse-ledgered
description: sess288: FULL board sweep coherent on 0.11.503 — 27/27 applicable PASS 32/caw; one-off chunk-2 pace collapse ledgered as D-POSTLOAD-SYNCWRITE-PACE-CO…
metadata:
  type: project
---

# sess288 — coherent-build board sweep on 0.11.503 complete

Build 0.11.503 sv 6ED390FBE6CC511CDFEDA31, all 32 nodes converged.

## Sweep result (all 32/caw, run ids 20260814T220720Z..223617Z)
Every applicable cell PASS: prep, dlm_fairness(19s), dlm_membership, dlm_scaling,
rsync_paired(17s), scaling_curve(36s), precond, fio_perf(34s), fio_perf_vs_xfs,
cache_coherency(35s), strong_consistency, posix_multi, mmap_coherency,
zero_silent_loss(23-33s), crash_consistency(22-28s), dir_reuse_coherency(100-102s),
dlm_lock_correctness, fence_during_write(22s), fault_netpartition(9s), soak(31s),
node_responsive, kernel_health(hits=0), dirent_durability(64s rounds=30 loss=0),
ag_strand_repair(240s strands=1 repaired=2), sustained_load(8s), 
dirent_publish_integrity, dirent_type_integrity. open_defects red by design.

## New defect D-POSTLOAD-SYNCWRITE-PACE-COLLAPSE-503 (high, OPEN)
First chunk-2 run (immediately after chunk 1's 13 cells ≈30min continuous load):
crash_consistency 0/32 NO_TERMINAL_RECORD — all nodes stuck in datawrite/md5write
(test17: 50 O_SYNC dd = 88s ≈ 1.8s/op vs 13ms solo/115ms@8-node); dir_reuse 0/32
pace 5/8 rounds, correctness clean. NOT reproduced by standalone, pair, or chunk
re-runs (all PASS). Failing-window observables: P70-BP release torrent ~1ms cadence
(kworkers releasing PRIOR tests' inodes) through the whole window; P286-F4-ORPHAN
ino=67639234 repeating gen-increasing; P292=0 fleet-wide (the .503 tripwire is
clean); P271=60 on test1 only. Suspects (unproven): background release churn
competing for CAW/LUN bandwidth; tri-state unlock read-back (.496+) doubling
release cost; P291-EXWIN ungated printk flood (dlm/dlm_caw.c:5577, 20k cap —
gating candidate now that D-501 is closed).

## Traps
- Test log tmpdirs (/tmp/tmp.XXXX printed by run.sh) are deleted after the run —
  criteria.json 'reason' + per-node dmesg kmsg markers (mxfs-CCph PHASE=...) are
  the durable evidence.
- crash_consistency has a HISTORY of standalone-PASS/in-suite-flake (sess21/29
  memories, and Aug-10 23:13Z FAIL with identical NO_TERMINAL_RECORD=32 signature
  followed by PASS at 00:16Z) — this defect has been intermittent for weeks.
