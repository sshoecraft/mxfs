---
name: fio-noise-pattern-and-raw-ceiling-refresh
description: Recurring pattern: perf-comparison tests (fio_perf_vs_xfs at N>1, fio_vs_xfs_baseline, single_node_paired) occasionally FAIL on host noise alone, PAS…
metadata:
  type: project
tags: [ccloop-0220f43f, fio_perf_vs_xfs, raw_fio_ceiling, host-noise, matrix-sweep]
---

## Pattern (confirmed 3x during the real-enforcement matrix sweep, sess2 ccloop 0220f43f)

Three DIFFERENT perf-comparison tests have each shown one-off FAILs that
instantly PASS on retry with zero code changes, same cluster state:
- 1/tcp `fio_perf_vs_xfs` + `fio_vs_xfs_baseline` (root cause: stale xfs
  baseline + host swap pressure — see memory
  `ladder-rung-health-gate-and-baseline-pairing-fix`).
- 1/cawp `single_node_paired`: FAILed 107%>105% (round_ratios 81,90,124,134 —
  huge spread), instant PASS (33s/90s) on manual retry seconds later, right
  after a rig switch. This test already does 4 position-balanced rounds +
  trimmed mean (same anti-noise design as the other two) but a truly noisy
  window (right after a rig switch's 32-VM power-cycle storm) can still push
  it over.
- 2/cawp `fio_perf_vs_xfs`: FAILed randW=31% (worst) against `wsrc=raw-ceiling`
  (NOT xfs-baseline — see below), instant PASS (92%+) after refreshing
  `.raw_fio_ceiling.cawp.json` and re-running `fio_perf` + `fio_perf_vs_xfs`
  back to back.

**All three are measurement noise on a shared, heavily-loaded host (clyde
runs a vLLM inference server + a game server + a trading bot alongside the 32
test VMs — see the other memory), not mxfs functional regressions.** Every
retry-confirmed PASS landed comfortably (92-158%+), never a marginal squeak —
this is NOT "lowering the bar to pass," it's "the first sample was unlucky."

## New finding this session: `.raw_fio_ceiling.<cond>.json` is a SECOND stale-baseline risk

`tests/suite/fio_perf_vs_xfs.sh` uses TWO different comparison sources
depending on N:
- N=1: `.xfs_fio_baseline.<cond>.json` (1-stream native-XFS baseline) — this
  is what `scripts/ladder_rung.sh`'s health-gate now refreshes every rung
  (see the other memory).
- N>1 (when `.raw_fio_ceiling.<cond>.json` has a matching key): the RAW
  N-sharer concurrent-write ceiling (bypasses any filesystem — deliberate
  design, sess8/sess10 ccloop 72513a13: a shared device physically cannot
  deliver its 1-stream bandwidth to N concurrent sharers, so comparing N>1
  mxfs against the 1-stream baseline is the WRONG yardstick by physics, not
  a bug). Captured by `scripts/raw_fio_ceiling.sh <cond> [Nlist]` (default
  Nlist=2,4,8,16,32; median-of-3 samples per N, still noisy — one cawp N=32
  seqW sample this session ranged 224-2580 MiB/s across 3 samples of the
  SAME condition/N back to back).

**`ladder_rung.sh`'s health-gate does NOT refresh this second file** — it's
too expensive to run per-rung (raw_fio_ceiling.sh takes ~5 min for all 5 N
values combined, needs the ENTIRE cluster unmounted on all 32 nodes first
since it writes raw block I/O to the shared LUN, refuses to run with anything
mounted). Practical fix used this session: run
`scripts/raw_fio_ceiling.sh <cond>` ONCE per condition, right after the rig
switch (before starting that condition's N=1 rung, or right after hitting a
suspicious N>1 fio_perf_vs_xfs FAIL) — it captures ALL of 2/4/8/16/32 in one
shot, so it does not need to repeat per-N within a condition's sweep.

**Procedure per condition** (tcp doesn't need this — its fio_perf_vs_xfs
never used a raw-ceiling file in practice, only cawp/cawd/caw did so far):
1. `for i in <nodes currently mounted>; do teardown (unmount+rmmod) that node; done`
   (raw_fio_ceiling.sh's own safety check scans all 32 nodes for any mount
   and refuses if it finds one; RAWCEIL_FORCE=1 overrides but don't — the
   check is real safety).
2. `scripts/raw_fio_ceiling.sh <cond>` (~5 min, all N in one shot).
3. `MXFS_FORCE_PREP=1 ./run.sh <N> <cond> prep_cluster` to resume the sweep.

If a mid-sweep N>1 `fio_perf_vs_xfs` FAIL shows `wsrc=raw-ceiling` and the
worst% is not close (e.g. 31%, not 65-69%), suspect a stale/unlucky ceiling
sample first (RULE 4: re-run `fio_perf` + `fio_perf_vs_xfs` back to back
before concluding it's a real regression) — but if a FRESH ceiling +
fresh mxfs measurement, paired in time, STILL lands under 70% more than
once, that graduates to a real investigation (kernel write-path perf), not
noise.

## Do NOT

- Do not widen FIO_MIN_PCT / RATIO_THRESHOLD to make these pass — every
  case so far was a genuine noise artifact confirmed by a clean retry, not
  a bar that's actually unreachable.
- Do not skip re-verifying after a retry — always confirm via
  `python3 scripts/matrix_check.py --cond <cond> --nodes <N>` that the cell
  is real (non-CALIBRATION) PASS before moving on.
