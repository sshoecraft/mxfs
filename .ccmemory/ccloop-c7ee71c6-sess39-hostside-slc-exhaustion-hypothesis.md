---
name: ccloop-c7ee71c6-sess39-hostside-slc-exhaustion-hypothesis
description: sess39 mid: drc degradation narrowed to WRITE-path service growth; lead hypothesis = clyde nvme SLC-cache exhaustion (990 EVO Plus 93% full + myse 37…
metadata:
  type: project
---

# sess39 mid-session — degradation mechanism hunt state

## Where the evidence stands (dir_reuse run-over-run decay)
- Lap 2 (instrumented): fresh 8r PASS → 7r → 7r, on schedule after 25min idle.
- Growing phases lap2: wrbar 3.03→4.71s, presync 1.00→2.17s, rm 2.67→3.52s (all WRITE/durability phases). Lap1 growers: presync/lookups/wave2. presync grows in BOTH laps.
- Guest write awaits grow: n32 w_await 0.84→3.33ms, n1 0.48→0.77ms fresh→plateau. Read awaits nearly flat.
- steal "2.5x growth" was an ARTIFACT: per-second timeline shows two 40-87 ticks/s spikes ONLY in the last ~20s of each FAILING run = the fail-path 32-node dmesg evidence collection. Body steal 1-6/s all runs. EXCLUDE end-of-run windows from aggregates.
- Host turbostat: Busy% 24 (fresh) → 25 → 40 avg (p2), no throttle (2400MHz, ≤62C). Growth beyond guest demand (+0.6 core) ≈ +5 cores — host-side work.
- Guest own CPU flat per-second (17.4→17.9%/s). Log pressure REFUTED: xs_sleep_logspace=0 on all nodes both runs; push_ail/log_force flat (snapshots in tests/logs/sess39_lap/, analyzer tests/drc_lap_analyze.py).
- KSM off. THP: guests 36-66% coverage (sudo smaps_rollup; unprivileged read lies). jbd2 lifetime avg commit 4.3ms.

## LEAD HYPOTHESIS: clyde nvme SLC write-cache exhaustion
- Drive: Samsung 990 EVO Plus 2TB (consumer TLC, dynamic TurboWrite SLC), root fs 93% FULL (~400-660MB free!), spare 100%, 6% used, 89TB lifetime.
- AMBIENT WRITER: `python3 -m myse` (user's project, /src/myse, up since 05:08) — 1.19TB written in ~9h = ~37MB/s SUSTAINED to the same nvme, 130-160% CPU. worldserver+Wow.exe ambient ~7 cores (user is PLAYING — never touch these processes).
- Mechanism: fresh run rides SLC; consecutive runs exhaust the (small, because drive ~full) dynamic cache → TLC-direct writes + GC → host fsync/commit latency up → every guest FLUSH (SCST SYNC CACHE = vfs_fsync(disk.img)) and FUA write slows → mxfs flush-amplified protocol (~85 handoffs/round × drain flush + wrbar + presync) multiplies it → rounds slow. ~25min idle drains SLC → recovery. Fits ALL signatures incl. cross-node-correlated stalls.
- fsync probe on root at idle: 5.7-8ms for 4K O_DSYNC (dd) — already elevated; fio 4K direct (no fsync) 21us.

## Samplers ARMED for the decisive lap (fresh vs plateau with host attribution)
- tests/host_write_sampler.sh → scratchpad/hostsamp.txt: 1Hz nvme0n1 write ops/time + 4K dsync fsync probe + write_bytes deltas for myse/worldserver/journald (qemu needs sudo — reads 0 as steve).
- Guests n1/16/32: /tmp/iosamp5.txt (1Hz r/w awaits + steal).
- Expected confirmation: nvme write await + fsync probe degrade during p1/p2, flat during fresh, recover after idle; myse rate ~constant; guest w_await tracks host fsync.
- If confirmed: D-DIR-REUSE run-over-run component = RIG artifact (host SSD + ambient writer) → disposition path DISPROVED-as-mxfs-defect for the decay component; residual mxfs work = grace default 10 (fresh+g10=9 rounds) + drain-pipelining to reduce flush amplification.

## Queued next (after lap)
1. Analyze lap correlations; if confirmed, ledger disposition + consider relocating disk.img to a less-contended device as rig fix (user call — root 100% full is also an operational hazard).
2. LIVE repro of slot leak (renamed defect D-CRASH-REJOIN-STALE-OWN-EX-SLOTS — misnamed, NOT crash-related: n1 never rebooted): create file on n12 → find slot (host parse of /home/steve/disk.img @67149824) → drop_caches → wait reclaim → re-check slot. P140-RECLAIM-COMMIT=0 in n1's 80K-line journal span covering creation+evictions → reclaim label (and mxfs_dlm_evict) never ran → find where inodes actually die.
3. df -i drift defect D-STATFS-IFREE-NEGATIVE-RANK1 (n1 in-memory ifree>icount by 10851).
4. grace=10 → code default candidate (needs full board first per sess38 note).
5. Leaked-slot count check cmd: python3 parse of disk.img offset 67149824, 65536×512 slots, magic 0x4D584357 live/0x4D58444C tomb.
- 11 OPEN. Criteria NO.
