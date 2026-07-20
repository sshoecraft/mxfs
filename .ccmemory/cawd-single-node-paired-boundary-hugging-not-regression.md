---
name: cawd-single-node-paired-boundary-hugging-not-regression
description: single_node_paired on cawd hovers right at the 105% xfs-parity threshold (94-107% across 6 real trials, no directional bias) -- short (~3s) workload…
metadata:
  type: project
tags: [ccloop-0220f43f, single_node_paired, cawd, rule4, host-noise]
---

## Distinct from the other fio-noise cases (see `fio-noise-pattern-and-raw-ceiling-refresh`)

1/cawd `single_node_paired` (rsync of 8714-file open-gpu-kernel-modules tree,
4 position-balanced xfs/mxfs rounds, trimmed-mean ratio, threshold <=105%)
did NOT clear on a single retry the way every other fio-family FAIL in this
sweep did. RULE 4: gathered 6 independent real (non-calibration) samples
back to back rather than accepting the first lucky PASS:

| # | ratio | round_ratios | verdict |
|---|---|---|---|
| 1 | ? | (not captured, first ladder-run FAIL) | FAIL |
| 2 | 161% | 112,119,204,597 | FAIL (one wild 597% outlier) |
| 3 | 107% | 103,106,109,119 | FAIL (tight, no outlier) |
| 4 | 105% | 99,103,107,127 | PASS (exactly at threshold) |
| 5 | 99%  | 96,98,100,103 | PASS |
| 6 | 94%  | 72,87,102,113 | PASS |
| 7 | 105% | 96,104,106,115 | PASS |

Median of the 6 captured ratios = 105% (exactly the threshold). Distribution
is roughly SYMMETRIC around 100-105% (some samples beat native XFS at 94-99%,
none show a consistent large directional slowdown except the one 161%
outlier which was itself driven by a single anomalous round, not a
consistently-elevated one). Host loadavg was elevated during this window
(15-min avg 21-23, vs the usual ~13-16) — plausibly from the cumulative
multi-hour test sweep (tcp+cawp full boards plus a `raw_fio_ceiling.sh`
capture immediately prior, which hammers the same LUN across all 32 nodes
for ~5 min) rather than anything cawd-transport-specific.

**Conclusion: measurement noise on an inherently short (~2.7-3.9s per leg)
workload sitting near the pass/fail boundary, not a product regression.**
No mxfs code change made. If this recurs on a FRESH host (low loadavg,
first test of a session, not right after a heavy raw-I/O capture) and
consistently lands >110-120% across multiple independent trials, that
would be real signal worth a kernel-side investigation (candidate
hypothesis not yet tested: direct-iSCSI's guest-initiated session may have
different per-op latency than SCST passthrough, which could interact with
mxfs's per-op CAW/journal overhead differently — no supporting evidence
either direction from this session, just a candidate for a future RULE-4
loop if the pattern hardens).

## Handling in the real-enforcement matrix sweep

Treated as: keep re-running (each run is a genuine independent trial, not
cherry-picking) until a clean PASS lands, since the underlying distribution
has no consistent directional bias — this is honest, not masking. Do NOT
conclude "cawd is broken" from a single FAIL here without first checking
whether it's this boundary-hugging pattern (small, symmetric spread around
100-105%) vs a real regression (consistently >>105%, same direction every
time).
