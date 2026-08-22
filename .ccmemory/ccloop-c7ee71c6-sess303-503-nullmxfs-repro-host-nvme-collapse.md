---
name: ccloop-c7ee71c6-sess303-503-nullmxfs-repro-host-nvme-collapse
description: sess303: D-503 residual — AIL refuted (fleet ≤16 blk); NULL-MXFS repro PROVEN: 17MB root-fs write+sync ×32 reproduces settled/b2b/idle triad; cause =…
metadata:
  type: project
---

# sess303 — D-503 residual: presync slowdown proven host-side, not mxfs

## Refuted (measurement)
- AIL/dirty-metadata hypothesis: extended tests/drc_stat_sampler.sh with
  /sys/fs/mxfs/*/log/{log_head_lsn,log_tail_lsn,reserve/write_grant_head_bytes}
  + vnodes; all 32 nodes through PASS/FAIL/idle/PASS triplet. AIL depth ≤16
  blocks on every node in every window; grant heads flat ~440KB during runs,
  1536 idle; vnodes flat ~18k. No metadata backlog. (b2b repro now 7/7.)

## Proven (null-mxfs reproduction)
tests/drc_synth_sync.sh: on all 32 nodes, 8 "rounds" of 17MB /dev/urandom to
node ROOT fs + timed sync(1), 13s cadence, fleet-aligned — zero mxfs ops.
Fleet medians: A settled 0.5s early→2.4-2.7s late; B b2b(+45s) STARTS 2.3-3.0s;
C after 190s idle 0.3-0.4s ×6 rounds then 2.4-3.3s. Exactly the real test's
presync signature (0.6→3s step at r4, b2b persistence, ~3min idle recovery).

## Mechanism
dir_reuse_coherency.sh:235 dumps the full 16.9MB dmesg ring to /root every
round on every node (ring saturated => constant 16.9MB) = 540MB/round fleet,
forced through vda→qcow2(writeback)→nvme0n1 (89% full, hosts VM images AND
SCST LUN backing) by the test's own 3 syncs/round. Host sampler
(tests/drc_host_sampler.sh): clyde Dirty ~0 between rounds (not OS dirty
accumulation); per-round bursts 100-400MB dirty, NVMe awaits 100-400ms;
suspect NVMe pseudo-SLC write-cache exhaustion (~3-4GB fast-write budget,
~3min recovery) — matches C's 6-fast-rounds budget (6×540MB≈3.2GB).
Arithmetic: without the 3s presync term run2 = ~76s → PASS; harness IO is the
but-for cause of the b2b FAIL. Note sess301's "host IO refuted (flat awaits)"
only covered r/w awaits — flush/burst path was never measured; flushes are
elided guest-side (LUN advertises write-through, flush_ios=1 ever).

## Closure step (next session)
Move line 235 snapshot (and line 36 `dmesg --follow > /root/...` stream) to
/dev/shm; run b2b pair; predict PASS+PASS → disposition DISPROVED (not an MXFS
defect). If run2 still fails: create-phase +1.5s term (one ~2s hot-dir EX
stall/round) is independent — check if EX-release drain (LUN on same NVMe) is
the same collapse. Node cleanup owed: /root/synth_*_r*.dat (~400MB/node).
