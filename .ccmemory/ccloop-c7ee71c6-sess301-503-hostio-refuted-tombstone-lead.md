---
name: ccloop-c7ee71c6-sess301-503-hostio-refuted-tombstone-lead
description: sess301: D-503 residual — host/node block IO REFUTED (flat awaits both runs); phases NOT uniform (wrbar/presync/rm grow, dc flat); new lead = 18.6k C…
metadata:
  type: project
---

# sess301 — D-503 residual: IO exoneration + tombstone lead

## Reproduction (5/5 now)
0.11.509, 32/caw. Settled (≥3min idle) dir_reuse PASS 103s; immediate
rerun FAIL 7 rounds. Round costs (test1 DRCph): run1 9.7/9.9/10.4/14.0/
14.5/19.7/13.1/~13; run2 15.9/15.8/14.6/13.9/12.9/13.5/... — run2 STARTS
elevated ~+6s/round, doesn't climb further within its 7 rounds.

## Refuted with measurements (this pair, 03:12-03:18Z 2026-08-15)
1. Clyde nvme sustained-write GC (sess300 hyp a): correct re-parse of
   .ccloop/clyde_io_sess300.txt — run1 w_await avg 17.1ms / run2 21.7ms,
   f_await 4.3/5.8ms, NO in-run climb (worst run1 burst mid-run then
   improves). Periodic ~110MB/15s bursts in BOTH runs (test's own sync
   traffic). Post-FAIL harvest w_await 460ms Dirty 4.6GB — AFTER runs.
2. Harvest dirty backlog (hyp b): inter-run gap quiet (w_await 2-6ms,
   Dirty ≤27MB).
3. Node-side block IO: sampler extended (tests/drc_stat_sampler.sh now
   samples /sys/block/sda/stat raw + O_DIRECT 4k probes vs sda and idle
   LUN sdb). test1 sda r_await 0.2-0.9ms w_await ~0.25ms in BOTH runs,
   in_flight 0, probes 3-4ms no climb. log force rate ~100/s busy,
   force_sleep/force ~28% CONSTANT.
4. "Uniform across phases" (sess300 claim): WRONG at finer grain. Flat:
   dc (~0.95s), sync1 (0.04s), verify, ls. Growing: wrbar 2.3→4.7s,
   presync 0.65→3.6s, rm 1.6→3s, lookups spikes. Run2 starts with those
   elevated. test1's own busy bursts don't lengthen — its WAITS do
   (wrbar = slowest peer's create; presync = own sync, 2-3.6s!).

## New lead — CAW slot-table tombstone probe chains
- Slot table: open addressing, linear probe, deletes = TOMBSTONE (MXDL)
  that probes WALK (dlm_caw.c:3112). Probe IO = SCSI READ FUA span 64
  slots/32KB (caw_probe_span_enable=1). find_slot ~3043-3345; tombstone
  write caw_tombstone_slot:1313 (carries gen/res/epoch/lineage/
  open_holders); same-resource inherit caw_claim_inherit_epoch:1347.
- Idle dump (test1:/root/caw_slotdump /dev/sda --all, 15min post-fail):
  18,645 TOMB (all INODE) + 53 LIVE of 65536 = 28% occupancy.
  tools/caw_slotdump deployed at test1:/root/caw_slotdump; idle baseline
  at test1:/root/slotdump_idle.txt.
- Mechanism: 800 files/round × create+rm; if new inos → new tombstones
  every round → chains grow → every find_slot pays more FUA reads; few
  ms × 1000s ops = seconds/round; each op <800ms → invisible to P298
  census. Persists across b2b.
- GAP in hypothesis: pace recovers with ~3min idle but tombstones are
  ON DISK; no TOMB→EMPTY sweeper found in first grep. Either a sweeper
  exists (find it: caw_epoch_free_reset? claim of foreign tombstone at
  empty_out?) or the idle-recovering accumulator is elsewhere (in-mem
  grant_meta table keyed by resource hash) and tombstones only set the
  BASE level. Resolve by reading find_slot_skip + measuring dumps
  after-run1/after-run2/after-idle in the next pair.

## Tools added
tests/drc_clyde_io_sampler.sh (clyde iostat+Dirty sampler, field map in
header). tests/drc_stat_sampler.sh extended (sda stat + latency probes).
