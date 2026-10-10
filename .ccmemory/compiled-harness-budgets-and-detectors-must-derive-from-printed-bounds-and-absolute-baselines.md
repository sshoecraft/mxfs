---
name: compiled-harness-budgets-and-detectors-must-derive-from-printed-bounds-and-absolute-baselines
description: Harness measurement traps: derive mount budgets from barrier bound_ms, bucket knob probes by mechanism field, never use ratio-to-own-median detectors.
metadata:
  type: feedback
tags: [compiled, harness, measurement, budget, detector-design, print-budget]
---

Three harness-measurement lessons that share one failure: a number or verdict derived from the wrong source (design prose, a knob's comment, the sample under test) reads as evidence while measuring something else.

## Mount budgets come from the barrier's printed bound

[[technique-derive-a-mount-budget-from-the-barriers-printed-bound-not-from-the-windows-it-is-built-from]]: `tests/fence_kind_matrix.sh` set a 96 s mount budget summed from observation windows in design comments (abandon observation, takeover observation, 45 s stability proof, refused claims). Seven of eight arms FAILed with rc=TIMEOUT at 96 s. The code was fine.

- The mount barrier prints its own deadline when it extends it: `P-BARRIER-GHOST-EXTEND undeclared=1 window_ms=62000 bound_ms=122000`. Read that line from the evidence capture.
- Derivation: `MXFS_BARRIER_ADMISSION_WAIT_MS` (30 s) + dead window (`MXFS_DISKLOCK_DEAD_THRESHOLD` 31 heartbeats x 2 s = 62 s) + admission wait again = 122 s, granted once from the loop start.
- Derive the budget from the constants or the printed `bound_ms`, and name them in the budget comment so it is re-derivable when a constant moves. A budget summed from prose is an estimate dressed as a derivation.
- A forged or leftover GUARD slot is an undeclared death: any harness that plants one gets the 122 s bound, not 30 s. A mount budget under ~140 s fails such a lap on the harness's own assertion.
- Contrast: a descriptor whose VERSION the build cannot validate was refused in 1 s with rc=32. The barrier waits for a class-refused certificate (a prover may appear) and does not wait for one it cannot parse.

## A knob's designed mechanism can fail while its fallback produces the shape

[[trap-a-knobs-designed-mechanism-can-fail-every-time-while-its-fallback-still-produces-the-shape-and-a-per-load-print-budget-is-spent-before-the-first-round]] (D-0948 verification, 2-node TCP):

- `dbg_force_sparse_carve=2` requests the upper half of the next chunk-aligned region as an exact allocation; every request was refused (`P-DIALLOC-FORCE-SPARSE ... got=no`, 110/110). Holes-below records (holemask 0xff) appeared anyway, because `=1|2` also forces every carve sparse and the ordinary near-bno search lands a half-chunk extent in the upper half of any region whose lower half is occupied. A verdict keyed on `got=yes` would have called the lap vacuous; trusting the design doc would have attributed the shape to the wrong mechanism. Bucket probe lines by the field that says which mechanism produced the record (holemask value, got=yes/no) before crediting a knob.
- A "first N per load" print budget is consumed by whatever runs first, usually not the measured window. Knobs armed before the harness started let the aging phase (1200 fallocates) spend all 200 `P-DIALLOC-HOLEPICK` lines; rounds read `HOLEPICKLINES=0` while the exact resettable counter read 176383. Zero lines next to a nonzero counter is the budget, not a contradiction. The counter is the evidence; the line count is not. The ring also retained under 10 s at that logging rate.

## A ratio-to-median detector goes blind when the baseline degraded

[[trap-ratio-to-median-detector-goes-blind-when-the-baseline-is-what-degraded]]: chain 129 swept files/node F at P=32 and flagged an op index as a spike if its mean was >= 10x the median of per-index means. Output said spikes vanish as F grows (`spike_indices=none` at F=64 and 128) while the same run's per-index means included 2056, 2816, 1581, 2114 ms. The median had climbed into the hundreds of ms, so a 2.8 s create was under 10x. The detector measured dispersion; the failure was a uniform shift of the whole distribution.

- Before writing any threshold as a ratio to a statistic of the same sample, ask whether the thing hunted can move the denominator. If it can, the detector goes blind at exactly the severity that matters, in the direction of good news.
- Use an absolute budget when one exists (per-criterion budgets derived from native XFS; `mean >= 200 ms` would have fired on every one of those indices), or fix the denominator to a known-good baseline measured elsewhere (private-directory arm, earlier F, native XFS), never the run under test.
- A detector's verdict line must never be the only thing it emits; the printed per-index means are the only reason the miss was catchable.
- The run's real result: shared-directory create cost at P=32 for F = 8/16/32/64/128 was 193, 169, 550, 1558, 2151 ms, rising with outstanding work. Filed against `D-32NODE-SHARED-DIR-CREATE-PACE`. The F=128 arm was cut off by its own guard (3611 of 4096 samples), recorded as a result rather than widened.

## Common rule

Take the figure from the system's own printed value or a fixed absolute baseline, and cross-check any verdict against a second emission (counter, field bucket, raw distribution). A budget, knob credit or detector that cannot be re-derived from something the system printed is a guess.
