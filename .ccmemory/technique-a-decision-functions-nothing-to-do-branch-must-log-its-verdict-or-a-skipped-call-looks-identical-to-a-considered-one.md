---
name: technique-a-decision-functions-nothing-to-do-branch-must-log-its-verdict-or-a-skipped-call-looks-identical-to-a-considered-one
description: TECHNIQUE (s86): the whole-cluster bootstrap returned 0 silently, so "the scan decided not a total outage" and "the scan never ran" were indistinguis…
metadata:
  type: feedback
tags: [instrumentation, logging, diagnosis]
---

# Log the verdict on the boring branch, or you cannot diagnose the interesting one

**The case.** `v5_bootstrap_run()` decides whether a mount is the first node
back from a whole-cluster outage. On the "no, ordinary path follows" branch it
returned 0 and logged nothing — which is the reasonable-looking choice, because
that branch is taken on every healthy mount and nobody wants a line per mount.

**What that cost.** A two-node cold restart — both slices dirty, both nodes
destroyed, one node back — is exactly the shape the path exists for, and it did
not take it. The log showed the record read, then an ordinary heartbeat slot
claimed **12 ms later**, then 122 s of admission-barrier replay rounds and a
refused mount. Between the read and the claim: nothing. So from the log,
"the survivor scan ran for a full dead window and concluded a member was live"
and "the scan never ran at all" and "the function returned at its null guard"
are the same observation — and the scan's own 62 s duration ruled out only one
of them.

Every hypothesis after that was inference over source code, and inference is
what an instrument is for.

**The rule.** A function whose job is to DECIDE must log the decision and the
inputs it decided on, including on the branch that does nothing. If a line per
mount is too much, log it at the level that is on for the failure case, or log
it only when the inputs are non-trivial — but do not let the quiet branch and
the un-called function produce identical evidence.

**The shape that works**: one line, the counted inputs, and the verdict in
words — `victims=N moved=N unread=N noident=N window_ms=N — <what this means>`.
The counted inputs are what let the next reader check the verdict rather than
believe it, and the same line then serves the healthy case as the baseline the
broken one is compared against.

**Also cover the early guard.** `if (!a || !b) return 0;` at the top of such a
function is the one return that means "this subsystem was never consulted", and
it is the one most likely to be silent.
