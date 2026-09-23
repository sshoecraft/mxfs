---
name: trap-a-retryable-injected-failure-is-retried-before-the-lap-can-snapshot-so-assert-on-log-order-not-on-a-later-capture
description: TRAP (s137): fence_live_prover_faults modes 1 and 2 both FAILed 4 assertions because the injected failure is retried WITHIN THE SAME TERM, so no log-…
metadata:
  type: feedback
tags: [measurement-integrity, fencing, harness, injector, attribution]
---

# An injector whose contract is "safe to repeat" is repeated before you can look

Measured s137, laps `s133c1` (mode 1, "precommand") and `s133c2` (mode 2,
"armfail") of `tests/fence_live_prover_faults.sh`, 2/tcp, build
`F3199FE2112E215C2FBB787`. The first live-prover fault modes ever to reach a
verdict. Both FAILed the **same four** assertions:

```
FAIL the victim's key is STILL registered (no PREEMPT AND ABORT was issued) got=0 want=1
FAIL the PR generation did not move (no PERSISTENT RESERVE OUT landed)
FAIL no completed preempt-and-abort is claimed in this window got=1 want=0
FAIL no durable marker says a command may have run (may_have_run clear) got=8 want=0
```

**Neither is an MXFS defect.** The prover's own log, in order, identical in both
modes:

```
P236-FENCE-INTENT      slot=1 victim=... term=1
P-PR-FENCE-INJECT      mode=N ... "nothing was issued ... it is safe to repeat"
P-PR-FENCE             preempt-and-aborted dead node ...      <- the RETRY
P236-FENCE-CERTIFIED   kind=PREEMPT_ABORT_PROVEN_V1
```

The injector is correctly placed (`dlm/scsipr.c:2062`, at the command-submission
boundary, above everything that can change target state), it is one-shot, and
the fence machinery retried — which is what the mode's own message *guarantees*.
The whole sequence is milliseconds, so the lap's "at the injection" snapshot,
taken after polling dmesg for the inject line, can only ever describe the
attempt that won.

## The part that makes this harder than it looks

**The retry does not open a new term.** There is no second
`P236-FENCE-INTENT` — the same attempt re-arms and issues. So "count the P&As
between the inject line and the next intent" does NOT isolate the injected
attempt either. Nor can userspace sample the durable arm state in between.

So the assertion set has to change subject rather than change scope. What the
injected modes can honestly assert:

- the mode's own refusal probe fired at its stated boundary (already asserted);
- **no PREEMPT AND ABORT was issued without a durable arm naming it** — which is
  the property the arm exists for ("a preempt whose having happened cannot later
  be established consumes the victim key and leaves the slice provably
  unrecoverable, which is strictly worse than not fencing at all"), and is
  observable by comparing arm markers against P&A completions rather than by
  demanding zero of either;
- nothing ended `P238-FENCE-UNRECORDED` or `-BLOCKED`, and the settled
  descriptor names a proof of the prover's own term.

"Assert that nothing happened" is the wrong shape for a fault whose contract is
that the system recovers from it. The right shape is "assert nothing happened
*unrecorded*" — which is what the fence-crash-matrix ruling's
MAY_HAVE_SUBMITTED entries are actually about.

**Do not edit this harness while a sweep is executing it** — bash re-reads a
script by byte offset, and modes 3-5 run from the same file.
