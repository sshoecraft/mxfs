---
name: trap-tee-dev-stderr-into-a-log-opened-with-truncate-reopens-it-at-offset-zero-and-overwrites-the-head
description: TRAP (0.90.39): a harness piping through `tee /dev/stderr` with stderr on a log file truncates that log; tee opens O_TRUNC even if launched with >>.…
metadata:
  type: feedback
---

**What bit:** tests/demoter_claim_fix_verify.sh piped board rows through `tee /dev/stderr`. Launched as `... > log 2>&1`, the log lost its prep and self-test header lines and one row line was spliced into a node summary line. Relaunched with `>> log 2>&1`, the logs were EMPTY a few minutes in.

**Why:** `/dev/stderr` is `/proc/self/fd/2`; tee opens it as a NEW file description with O_WRONLY|O_CREAT|O_TRUNC and no O_APPEND. That truncates the log whatever mode the shell opened it with, and tee then writes from offset 0 while the shell's own appends go to the end.

**Do:** in a harness, `tee -a /dev/stderr` (O_APPEND, no truncate) or `tee >(cat >&2)`. Never edit the harness while a run of it is live (bash reads scripts incrementally). A log whose head is missing lines the harness always prints is this, not a harness that skipped steps.
