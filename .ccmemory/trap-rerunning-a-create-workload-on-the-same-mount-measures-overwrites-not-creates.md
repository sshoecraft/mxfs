---
name: trap-rerunning-a-create-workload-on-the-same-mount-measures-overwrites-not-creates
description: TRAP (sess489): chain 139's armed crash_consistency re-ran on the mount its failed rows left behind — its 23-29 s PASS was 3200 overwrites, zero crea…
metadata:
  type: feedback
tags: [trap, vacuous-pass, crash_consistency, pace, chain139, sess489]
---

# A second run of a create workload on an un-re-prepped mount measures overwrites

Chain 139 (sess487/488, tests/sess487_chain139_persig_ab.sh) ran the 9-row set (crash_consistency FAILED inside it, BUDGET_EXHAUSTED) and then, on the SAME mount with no prep, crash_consistency once more with `create_cost_ms=1` armed. Both legs' armed rows PASSED in 23 s and 29 s of the 90 s budget and were about to be read as "the row passes on a quiet fleet".

They measured nothing: `.crash_consistency/node<R>_f<i>` already existed from the failed row, so every `dd ... oflag=sync` was an O_TRUNC overwrite of an existing inode, not a shared-directory create. The probe that fires on EVERY create >= 1 ms logged 102 lines on 9 nodes in leg A and 1 line on 1 node in leg B instead of ~3200 on 32. Leg B's in-tenure sample set was empty (n=0), so the A/B on dirsig_ms had no B.

Rules that follow:
- A create-pace measurement needs a directory that does not exist yet: prep, or `CC_TAG=<word>` (sess489, tests/suite/crash_consistency.sh) which puts the run in `.crash_consistency_<word>`.
- Read the probe COUNT against the planned population (3200) before reading any per-sample statistic; a count an order of magnitude low is the harness measuring something else.
- The board's crash_consistency always runs right after rsync_paired on the row's first (fresh) directory; a standalone re-run on the same mount is not the board condition twice over.
