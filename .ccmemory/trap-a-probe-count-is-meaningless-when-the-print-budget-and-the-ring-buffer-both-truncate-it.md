---
name: trap-a-probe-count-is-meaningless-when-the-print-budget-and-the-ring-buffer-both-truncate-it
description: TRAP (sess572): I read "2 SYNCINIT lines against 53 carves" as 51 carves skipping their durable init. Both ends were truncated — a first-20 print bud…
metadata:
  type: feedback
tags: [measurement, dmesg, probe-budget, d0947, d0948]
---

# Two independent truncations, one ratio, one wrong conclusion

## What I claimed

test1's dmesg had **2** `P133-ICLUSTER-SYNCINIT` lines and **53**
`P-AGIFC-MOD site=ag_alloc` lines. I concluded that 51 inode-chunk carves had
skipped their durable FUA initialisation — which would have been a large,
central defect — and wrote it into a ledger record as "measured and
unexplained".

## Why it was wrong, twice over

1. **The probe has a print budget.** `if (atomic_inc_return(&p133_n) <= 20 || rc)`
   — it prints its first 20 occurrences and is silent thereafter. So the count
   can never exceed 20 no matter how many carves happen. I had even reasoned
   "prints the first 20 unconditionally, so 2 is the true total" — which is only
   valid if the buffer still holds all 20.

2. **The ring buffer had rolled over.** Its earliest retained line was
   `[14966.960385] mxfs: P82-REM ino=336214` — already mid-workload, with the
   mount banner gone. The 2 surviving lines were the *tail* of a spent 20-line
   budget.

The numerator was capped by the probe and then truncated by the buffer; the
denominator was truncated by the buffer alone. The ratio of two differently
truncated counts means nothing.

## How to catch it before it costs a turn

- **Check `dmesg | head -1` before believing any whole-log count.** If the first
  retained line is not the boot/mount banner, every "total" is a lower bound and
  every ratio is unusable.
- **Read the probe's own print condition** before quoting its count. A `<= N`
  budget, a `% 500`, or a `pr_warn_ratelimited` each mean the number on screen
  is not the number of events. (This project has already been bitten by
  `pr_warn_ratelimited` reporting exactly 10 = DEFAULT_RATELIMIT_BURST.)
- Two probes with *different* truncation rules can never be divided by each
  other. If a ratio matters, count both sides with the same unbudgeted
  instrument, or with a counter that is incremented always and read once.

## What it cost

A ledger record asserting a defect that does not exist, retracted in the same
session, plus a detour before the real finding — a directory data block still
sitting at the home of a freshly carved inode chunk (D-0948).
