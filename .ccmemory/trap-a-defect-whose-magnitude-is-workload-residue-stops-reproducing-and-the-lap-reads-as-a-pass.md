---
name: trap-a-defect-whose-magnitude-is-workload-residue-stops-reproducing-and-the-lap-reads-as-a-pass
description: TRAP (D-0962): the 103 s recovery stall was 7984 ledger pages of residue; on a filesystem that had lost it the pass was 27 pages / 285 ms and both ar…
metadata:
  type: feedback
tags: [measurement, dlm, tauth, vacuity, D-0962]
---

# When the defect's magnitude is workload residue, an A/B can be vacuous and look clean

D-0962: a dead peer's authority-page takeover ran inside the recovery
completion — **7984 pages × ~13 ms = 103-107 s** during which the survivor held
the exclusive-write gate and the rebooted victim could not rejoin.

Two laps run 2026-09-17 to measure where the per-page time went came back
`cand=27` and `cand=28`. The pass finished in **285 ms**. Both laps PASSed in
~118 s. Nothing was wrong with the laps; the **7984 pages were residue** from
earlier `join_during_takeover` work (32000 creates, ~4 ledger entries a page) on
a preserved filesystem, and intervening preps and takeovers had consumed it.

The record had even said so — *"the 7984 pages are the residue of the
join_during_takeover laps on the preserved filesystem; a fresh mkfs would shrink
the count, not the per-page cost"* — and it was still possible to run the A/B
without first checking the count.

## What is and is not reproducible here

- **The per-page cost reproduced**: 27 pages in `total_ms − scan_ms` = 285 ms ≈
  **10.6 ms/page**, against the 13 ms the record was filed on. The mechanism is
  intact.
- **The magnitude did not**, because the magnitude is `pages × per-page`, and
  `pages` is a property of the workload history, not of the code.

A fix measured only against 27 pages proves nothing: the unfixed build also
publishes promptly at that size.

## What to do

- **Check the population before the arms, and make the harness refuse to report
  a verdict when it is too small.** `tests/d0962_takeover_offpath.sh` builds the
  residue itself and fails with `VACUOUS: cand=N < MIN` rather than passing.
  Raise the creates; never lower the threshold to get a green.
- **Build the residue on the node that will die**, and keep the peer mounted
  while it does — a lone mount takes no grants and so writes no ledger pages.
- **Prefer a same-build control knob over an older tree.** The residue moves
  between laps, so a control built from a different tree is not a control. A
  runtime knob that restores the pre-fix shape (`dl_recovery_takeover_inline`)
  puts both arms on one build and one filesystem, and the control arm must be
  asserted to REPRODUCE the defect or the fixed arm means nothing.

## And check which probe carries the field

`handoff_ms` is on **`P-COMPLETE-RETIRE-TIMING`**. `P-COMPLETE-TIMING` is a
different line carrying `disklock_purge_ms` and no `handoff_ms` at all. Grepping
the wrong one of the two returns an empty field, which a harness that does not
distinguish "empty" from "zero" reports as a fast completion.
