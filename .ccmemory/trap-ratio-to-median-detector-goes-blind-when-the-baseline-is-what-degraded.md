---
name: trap-ratio-to-median-detector-goes-blind-when-the-baseline-is-what-degraded
description: TRAP (sess483): a "≥10× the median" spike detector reported NO spikes at exactly the loads where 2.8 s operations appeared — the median had degraded…
metadata:
  type: feedback
tags: [sess483, measurement, detector-design, pace, chain129]
---

# A ratio-to-median detector stops detecting when the baseline is the thing that degraded

sess482's chain 129 swept F (files/node) at P=32 to decide between two readings
of the shared-directory create cost. It classified an operation index as a
"spike" if its mean was **≥ 10× the median of the per-index means**.

What it printed:

```
F=32   op1_share=25.7%   spike_indices(mean>=10x median)=[1]
F=64   op1_share= 5.2%   spike_indices(mean>=10x median)=none
F=128  op1_share= 2.1%   spike_indices(mean>=10x median)=none
```

Read literally: *the spikes go away as the load grows.* The opposite is true.
The same lines' per-index means at F=64 include `19:2056  22:2816  23:1581
24:2114` milliseconds. Two-and-a-half-second creates, reported as "none".

**The mechanism.** The detector's denominator is drawn from the same
population as its numerator. At F=8 the median per-index mean was ~10 ms, so a
1464 ms op1 was 146×. By F=64 the median had itself climbed into the hundreds
of milliseconds, so a 2816 ms operation was under 10× and vanished. The
detector was measuring *dispersion*, and the failure being hunted was a
**uniform shift of the whole distribution**.

## The rule

Before writing any threshold as a ratio to a statistic of the same sample, ask:
**can the thing I am hunting move my denominator?** If it can, the detector
goes blind precisely at the severity where it matters most, and it fails in the
direction of good news.

- Use an **absolute** budget when one exists — this project already has them
  per criterion, derived from native XFS (RULE 0). `mean >= 200 ms` would have
  fired on every one of those indices.
- Or fix the denominator to a **known-good baseline** measured elsewhere (the
  private-directory arm, an earlier F, native XFS), never to the run under test.
- Or report the raw distribution and let the reader see it. Chain 129 did also
  print the per-index means, which is the only reason the miss was catchable —
  **a detector's verdict line should never be the only thing it emits.**

## What the run actually showed

Cost per create, shared directory, P=32, by F: **193, 169, 550, 1558, 2151 ms**
for F = 8/16/32/64/128. Rising monotonically, so it is neither the "one-time
admission" the chain was built to test nor the "batching quantum" alternative
— it grows with outstanding work. Filed against
`D-32NODE-SHARED-DIR-CREATE-PACE`. The F=128 shared arm was also cut off by its
own guard (3611 of 4096 samples), which the chain correctly records as a result
rather than widening the budget.
