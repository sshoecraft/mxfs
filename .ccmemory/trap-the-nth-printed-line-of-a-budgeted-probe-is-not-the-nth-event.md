---
name: trap-the-nth-printed-line-of-a-budgeted-probe-is-not-the-nth-event
description: TRAP (sess581): a harness took "the first armed drop" as the (baseline+1)-th P912-DROP-LOCKREQ line; the probe prints only n<=8 and n%64, so that lin…
metadata:
  type: feedback
tags: [harness, measurement, probes]
---

## What happened

`tests/tcp_lockreq_blackhole.sh` (EXPECT=degraded, s581b) wanted the time between the first request dropped after arming and the P958-ACQ-DEGRADED line. It counted drop lines before arming (8), then took the 9th `P912-DROP-LOCKREQ` line as the first armed drop. The probe prints only its first 8 hits and every 64th (`dropped <= 8 || dropped % 64 == 0`), so the 9th LINE was the 64th EVENT, stamped 8 s after the detector fired. Latency scored -8 s and the lap FAILed on a correct build.

## The lesson

- A budgeted probe's line index is not an event index. Any "the Nth occurrence" taken from a print-budgeted probe is the wrong occurrence unless N is inside the always-printed prefix.
- When a detector reports its own measurement in its line (`unanswered_ms=`, `age_ms=`, `bound_ms=`), score THAT. It is the number the code acted on, taken on the code's own clock, and it does not depend on which other lines happened to print.
- Related: `trap-a-probe-count-is-meaningless-when-the-print-budget-and-the-ring-buffer-both-truncate-it` (counts); this one is about ORDER/identity of a printed line.

Fixed in the same session: the degraded arm now parses the DEGRADED line's fields and asserts `bound <= unanswered_ms <= bound + 6000`.
