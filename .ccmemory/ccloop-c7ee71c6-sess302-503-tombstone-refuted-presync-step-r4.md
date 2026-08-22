---
name: ccloop-c7ee71c6-sess302-503-tombstone-refuted-presync-step-r4
description: sess302: D-503 residual — tombstone hyp REFUTED (no TOMB→EMPTY anywhere, monotonicity); real signal = presync sync STEPS 0.6→3s at run1-r4 fleet-wide…
metadata:
  type: project
---

# sess302 — D-503 residual: tombstone refuted, presync step found

## Refutations (no rig run needed)
1. **CAW slot-table tombstone chains — REFUTED by code + monotonicity.**
   All 5 TOMBSTONE_MAGIC sites in dlm_caw.c either write tombstones,
   compare, or recycle TOMB→LIVE. NO code path anywhere converts
   TOMB→EMPTY (only mkfs zeroes). Therefore probe-chain length is
   monotone non-decreasing over disk lifetime, and idle writes nothing
   to the table — a run after 3min idle starts from the same-or-worse
   table as the failing b2b run2 and PASSES (5/5 pairs, 18.6k tombstones
   accumulated). Hint cache is warmest immediately after run1, predicting
   run2 faster — opposite of observed. Disk-table state cannot be the
   discriminator; the recovering state is node-side/in-memory/in-flight.
2. **Single straggler node — REFUTED.** DRCph fleet harvest (new
   tests/drc_phase_harvest.sh): last-create-done rank rotates per round
   (25,24,14,17,32,8…), create durations uniform fleet-wide (top3 within
   0.1s of each other every round).
3. **test1-local backlog at run2 start — REFUTED.** sess301 sampler
   deltas: post-run1 residual AIL-flushing tail (ail[2] ~20/s) ends 25s
   after run1; all counters flat 20s before run2 starts; run2 slow anyway.

## Measurements (from sess301 pair's fleet dmesg, 03:12-03:18Z)
Per-round phase medians across 32 ranks:
- **presync (post-wrbar `sync`, dir_reuse_coherency.sh:256): 0.6s →
  STEPS to 2.6-3.8s at RUN1 ROUND 4 and never recovers** (run2 r1 =
  2.4s). Dominant delta ~3s/round.
- create: 3.3→5.3s med; from r2 onward EVERY create window has exactly
  ONE ~2s hot-dir EX grant stall (settled r1: zero stalls, 225ms max).
- wrbar med flat ~2.2s, dc flat 1.0s, ls flat ~0.1s.
- Round totals (create-start→lookups-done, med): run1
  7.7/7.8/8.2/11.5/11.3/12.2/10.6/9.2 — the step is at r4, and r8
  partially recovers; run2 flat 10.2-12.4 from r1. **run2 FAILs because
  it STARTS at the plateau** (~12s+rm≈15s/round, 7 rounds in 100s box),
  not because it degrades further.
- P291-EXWIN hot-dir (ino 1076037) grant cadence: gap_med 11-22ms both
  runs, path mix mint(1172)/adopt(1130) — fix C direct handoff healthy.
  ~300 EX tenures per round (lock caching batches ~2-3 creates/tenure).
- P297-TKT el_ms distributions overlap run1 vs run2 — nomination wait
  not the growth term.

## Open hypothesis (next session)
State builds rounds 1-3 → plateau; survives 45s gap; drains ~3min idle.
Suspect AIL/dirty-metadata backlog: 32 SIMULTANEOUS post-barrier syncs
contend via DLM (cluster-buf/AG locks) during flush. sess18 comment at
xfs_mxfs_dlm.c:15513: "inodegc backlog a later sync drains for 60-120s"
— matching time constant. Alt: inodegc flush inside sync_fs; icache
growth (test1 vnodes 19187).

## Tooling (RULE 3, in tree)
- tests/drc_phase_harvest.sh <out> [n] — DRCph marks from fleet dmesg
  (wall-clock ISO), one file/node.
- tests/drc_p297_harvest.sh <out> [n] [pattern] — probe-line harvest
  (P297-TKT default; pass "P291-EXWIN" for grant census). NOTE: output
  files are named p297_test*.txt regardless of pattern.
- Node stats surface (no build needed): /proc/fs/mxfs/stat (full xfs
  stats), /sys/fs/mxfs/dm-1/log/{log_head_lsn,log_tail_lsn,
  reserve_grant_head_bytes,write_grant_head_bytes} — AIL depth = head
  minus tail. P291/P297 hard cap 20000 lines/module-load (test1 at
  7076/757 after the sess301 pair).

## Next: fleet AIL-depth sampling
Extend tests/drc_stat_sampler.sh with log LSNs + vnodes, deploy to ALL
32 nodes, run b2b pair + idle + run3, test prediction: AIL depth steps
at r4, persists through gap+run2, decays over idle, low at run3.
