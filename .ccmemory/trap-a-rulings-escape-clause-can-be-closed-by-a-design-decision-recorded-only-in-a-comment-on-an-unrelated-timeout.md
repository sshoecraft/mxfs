---
name: trap-a-rulings-escape-clause-can-be-closed-by-a-design-decision-recorded-only-in-a-comment-on-an-unrelated-timeout
description: TRAP (s133): the fence-matrix ruling lets the in-flight entries be omitted "once pending I/O has drained" — but the tree rejected that drain by desig…
metadata:
  type: feedback
tags: [fencing, crash-matrix, rulings, scsipr]
---

# A ruling's escape clause can already be closed, and the proof may sit in an unrelated comment

`docs/rulings/fence-crash-matrix-cuts.md` :30-32 offers what looks like a cheap
way out of the most expensive tranche of the fence crash matrix:

> Those need fault injection or delayed completion, and the matrix may omit
> them as crash laps **only once it establishes that pending I/O has drained
> before a successor acts**.

That would have covered the in-flight PREEMPT AND ABORT in all three forms, the
late certify completion, outstanding I/O at an ownership change and the
competing/stale-owner entries — most of Tranche B — for the price of one
drain measurement instead of a new injector.

**It is not available, and the module says so about itself.** `dlm/scsipr.c`,
in the comment sizing `mxfs_lu_reset_converge_ms` (the post-reset probe bound),
explains why that bound is NOT taken from the worst-case stranded-command
rescue:

> waiting that out here would be this barrier doing **the pre-reset drain the
> design ruling rejected**.

There is no drain to establish because an earlier ruling decided there would
not be one. The escape clause is dead on arrival, and the live-prover faults
have to be injected. `mxfs.pr_fence_submit_inject` (0.89.55) is that injector.

## The general lesson

When a ruling grants an exemption conditional on some property holding, do not
go measure the property first. Check whether the tree has already DECIDED
against it — a rejected design is not a property that might happen to hold, and
the decision is often recorded nowhere near the subject, as a sentence
explaining why some unrelated constant is sized the way it is. One grep for the
property's name across the subsystem found it here in a timeout comment, after
a reading of the ruling had made it look like the cheapest path forward.
