---
name: technique-a-budgeted-probe-must-carry-its-own-true-total-on-every-line
description: TECHNIQUE: a probe that prints only its first N occurrences must print the running total too — otherwise its author reads the line count as the event…
metadata:
  type: project
tags: [probe, instrumentation, measurement-integrity]
---

# Print the total, not just the sample

The `if (n <= 16 || (n % 256) == 0)` print budget is correct and necessary — an
unbudgeted per-event `pr_warn` floods the ring and destroys the evidence around
it. But a budgeted probe whose line does not carry the true total is an
instrument that lies by omission, and the person most likely to misread it is
**the person who wrote the budget**, minutes later, while writing up the result.

## How it went wrong (sess578, D-0912)

I added `P912-QACK-RX` with a 16-line budget, ran a 244 s wait, saw 10 lines in
the run-scoped window, and wrote "ten receipts arrived, about one per re-send"
into both the changelog and the ledger. The 10 lines were `n=7..16`: printing
stopped at 47077.76 while receipts kept arriving for another **176 seconds**.

What actually established the continuation was a different line entirely — the
classifier's `receipted=1` stamped at 47254.06 against a 15 s staleness window,
which cannot hold unless a receipt landed in the final 15 s. That is better
evidence than a count, and I nearly published a weaker, wrong claim instead.

## The rule

- A probe with a print budget prints a **running total on every line**
  (`n=%d rx=%llu`). Then 10 lines showing `rx=214` is self-describing and no
  reconstruction is needed.
- When reading someone's probe output, check for a budget in the source
  **before** treating a line count as an event count. `n=` values that stop at a
  round number (16, 20, 64, 200) are the tell.
- Prefer a **derived assertion over a count** where one exists. "The decision
  line says receipted=1, 176 s after the last printed receipt, against a 15 s
  window" is a proof; "I counted ten lines" is an artifact of the logging.

## Related

`trap-a-probe-count-is-meaningless-when-the-print-budget-and-the-ring-buffer-both-truncate-it`
records the same failure from the *reading* side (a first-20 budget plus ring
rollover made 2 SYNCINIT lines look like 51 skipped carves). This one is the
*authoring* side: the budget was mine and I still read the lines as the count.
Knowing the trap did not prevent it; carrying the total on the line does.
