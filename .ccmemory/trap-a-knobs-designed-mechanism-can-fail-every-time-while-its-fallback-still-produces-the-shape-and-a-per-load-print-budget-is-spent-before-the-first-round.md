---
name: trap-a-knobs-designed-mechanism-can-fail-every-time-while-its-fallback-still-produces-the-shape-and-a-per-load-print-budget-is-spent-before-the-first-round
description: TRAP (sess616, D-0948): dbg_force_sparse_carve=2's exact upper-half request was refused 110/110 yet the arm produced holes-below records via the near…
metadata:
  type: feedback
tags: [harness, measurement, knob, print-budget, D-0948, dialloc]
---

# A knob's designed mechanism can fail every time while its fallback still produces the shape; a per-load print budget can be spent before the first round

**Context (sess616, D-0948 verification on 2/tcp, 0.85.3, module 414769E4F12DC54FE526BA6).**

## Two things that would have produced a wrong reading

1. **The knob did not do what its comment says, and the arm still worked.**
   `dbg_force_sparse_carve=2` requests the upper half of the next chunk-aligned
   region as an exact allocation, to carve records with holes BELOW the inodes
   (holemask 0xff). Every request the ring still held was refused
   (`P-DIALLOC-FORCE-SPARSE ... got=no`, 110 of 110): the region above the hint
   is never free on this workload. The holes-below records appeared anyway,
   because `=1|2` also forces every carve sparse, and the ordinary near-bno
   search then lands a half-chunk extent in the upper half of any region whose
   lower half is occupied -- which is the placement the s572 incident's carve
   took, with a directory block in the lower half. Had the verdict been keyed
   on `got=yes`, the lap would have read as vacuous; had the design doc been
   trusted, the shape would have been attributed to the wrong mechanism.
   **Bucket the probe lines by the field that says WHICH mechanism produced the
   record (holemask value, got=yes/no) before crediting a knob.**

2. **A "first N per load" print budget is consumed by whatever runs first,
   and that is usually not the measured window.** The control arm's knobs were
   armed before the harness started, so the harness's aging phase (1200
   fallocates) spent the 200 `P-DIALLOC-HOLEPICK` lines; by round 1 the budget
   was gone, and by the post-lap query those lines had rolled out of a ring
   that retained under 10 s at that logging rate. Every round window read
   `HOLEPICKLINES=0` while the exact resettable counter read 176383 for the
   same round. The counter is the evidence; the line count is not, and a zero
   line count next to a non-zero counter is the budget, not a contradiction.

## Related
- `technique-a-test-knob-a-harness-selects-by-must-expose-a-counter-that-resets-on-write`
- `trap-the-nth-printed-line-of-a-budgeted-probe-is-not-the-nth-event`
- `trap-an-inobt-record-corruption-line-after-a-pick-is-the-allocator-naming-a-hole-decode-holemask-before-hunting-a-stale-write`
