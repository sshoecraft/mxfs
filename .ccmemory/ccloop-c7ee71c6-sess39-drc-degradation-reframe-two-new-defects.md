---
name: ccloop-c7ee71c6-sess39-drc-degradation-reframe-two-new-defects
description: sess39: dir_reuse bimodality REFRAMED = deterministic run-over-run decay (fresh 8-9r, plateau 7r, idle 25m recovers); +2 new defects (statfs ifree<0…
metadata:
  type: project
---

# sess39 — dir_reuse degradation reframe + two new defects

## The reframe (biggest win)
D-DIR-REUSE "bimodality" is NOT stochastic: it is **deterministic run-over-run degradation with idle recovery**:
- fresh run after ≥25min idle: 8-9 rounds (PASS); consecutive runs: 7 (plateau, FAIL bar=8). Proven twice today: [8]→7,7,7→(25m idle)→8; earlier 8→9(g10)→7→6. Prior sessions' 8/7/6 laps = same signature, order was the hidden variable.
- grace=10 vs 40 (dir_ex_batch_grace_ms, sysfs-only; code default 40; RESET ON MODULE RELOAD — sess38's setting was lost at 325 deploy): turn p50 81→50ms, +1 round. Worth folding into default after a board.

## Mechanism candidates REFUTED by measurement
- Device queue convoys: await 0.6ms fresh / 0.8-1.0ms plateau, IOPS ~140/node — flat, tiny.
- CAW table state: byte-identical (13,425 live/6,542 tomb) before a FAST run and before a SLOW run.
- Tombstone probe chains: p99=5, max=13 (PROBE_SPAN=16 covers).
- AGI unlinked chains: empty across all 50 AGs post-run.
- Host SSD (21µs probe), host aggregate CPU (55% idle flat), THP (frozen counters).
- P139-LOCKTOTAL 2-3s tails = fair-rotation waits (31 waiters × ~60-95ms/turn), NOT device inflation. P138 stage split: drain stages ~1.6ms p50; wire unlock (CAS storm + rand backoff ≤20ms) p50 9.7ms p90 44ms = dominant bast_process slice.
- Degrading phases (n1 barrier-view): presync 1.1→2.4s, cold-lookups 0.5→1.7s, wave2 1.1→2.9s. Flat: wave1, wrbar, rm, verify.
- GPT ranking of remaining: 1) per-node 1MB journal slice tail/AIL pressure (check push_ail line deltas: try/sleep_logspace, pinned; grant_head bytes; log LSNs — /sys/fs/mxfs/dm-1/log/*, /proc/fs/mxfs/stat), 2) host sched/thermal (turbostat armed; Wow.exe+worldserver burn ~8 cores ambient — do NOT kill, user's live processes), 3) guest-local cache aging.
- xs_sleep_logspace=0 LIFETIME on n1 pre-lap (log-grant sleeps never happened → weakens #1 pre-emptively).
- IN FLIGHT: fresh-vs-plateau lap with tests/drc_lap_probe.sh snapshots (tests/logs/sess39_lap/), iosamp3 on n1/16/32, turbostat.

## New defect 1: D-STATFS-IFREE-NEGATIVE-RANK1
df -i on n1: used=-10851 (in-memory percpu m_ifree > m_icount); n16/n32 sane; platter consistent (icount=768=ifree). Suspect cross-node lazy-sb delta merge or replay double-apply on rank1.

## New defect 2: D-EVICT-RETAINED-EX-SLOT-PIN
13,348 live EX inode slots (~435/node) on .rsync_paired files (sess38 board leftovers, nlink>0, files exist). Survive drop_caches every round for days → inodes PINNED in icache (suspect armed dwork igrab, D-DWORK-adjacent) or evict-unlock fails. Design forbids EX retention across evict. Leak fills 65536-slot table (~24 laps). Cheap A/B: rm .rsync_paired → all 13K slots must tombstone.

## Facts bank
- dir dirino=537937 constant across runs/laps. 800 files/round (25×32). checks/round≈7.25.
- turn anatomy @grace=40: p50 81ms; @10: 50ms. Handoffs/round ≈ 82.
- monitor scan: 63×512B reads/2s/node = 32 r/s/node idle floor (~1008/s aggregate) — NOT a convoy source at current await levels.
- clyde root 100% full (~660MB free after cleanup) — watch it; disk.img/disk-1.img preallocated so no growth risk from images.
- envelope: disklock_offset=67117056, lock table at 67149824 (65536×512), xfs at 100704256; journal slices 1MB/node (64 slices after super sector).
- /proc/fs/mxfs/stat + /sys/fs/mxfs/dm-1/log/{log_head_lsn,log_tail_lsn,reserve_grant_head_bytes,write_grant_head_bytes} exposed per node.
- 11 OPEN. Criteria NO.
