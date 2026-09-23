---
name: design-an-ambiguous-fencing-attempt-needs-a-read-only-revisit-not-a-retry-and-not-a-takeover
description: DESIGN (0.89.12, D-381, verified flr_s75e fails=0): the lockout after a lost P&A response was REACHABILITY — nothing ever revisited the slot. The fix…
metadata:
  type: project
tags: [fencing, dlm, recovery, design]
---

# An ambiguous fencing attempt needs a revisit, not a retry

When a PREEMPT AND ABORT executes and its response is lost, the prover is left
holding a durable "may have run" arm with no proving response. The safe half of
that is correct and must not be touched: ordinary retry stays closed, because
re-issuing a command against a victim key whose predecessor may still be in
flight is the hazard the phase distinction exists for.

**The defect was that nothing ever looked again.** Three closed doors and no
fourth:

- the slot is deliberately **not armed for retry**, so the retry worker, which
  visits only armed slots, never sees it;
- **takeover is refused** because the attempt's holder is alive — it is us;
- every other proof mechanism (self succession, boot succession, the
  sole-survivor gate) is reachable **only** from `fres.kind ==
  KEY_ABSENT_UNPROVEN` inside `v5_pr_fence_prove_locked`, and an ERROR at
  MAY_HAVE_SUBMITTED never becomes that.

So the slice stayed unreplayable *even after a proof became available*, and —
this is the part worth remembering — **the returning victim could not mount its
own filesystem**, because the prover's standing attempt blocked the claim and
the successor rightly declines to take it over from a live holder. The lockout
is not "A cannot recover B"; it is that nobody can, including B.

## The shape that works

A **read-only same-owner resume**, dispatched from the place that already
judges the attempt's holder periodically and previously only logged
`state=LIVE why='our current incarnation'`:

- fires only when the holder is **this node's own current incarnation**, the
  descriptor is still at FENCING with the durable arm, no proving kind, blocked
  and unarmed;
- issues **no state-changing command at all**;
- **cannot reach the sole-survivor gate** — that gate's `sark=0` PREEMPT AND
  ABORT retires nothing belonging to a registration our own predecessor already
  removed, so it is admission without retirement;
- asks only self succession and boot succession, both pure observation;
- on finding no proof, returns **before** the point where falling through would
  arm a retry. That early return is the whole safety of the design: the
  observation it starts from classifies as retryable.

Re-laying the intent is safe: at stage FENCING with our own prover,
`mxfs_disklock_recovery_fence_intent` returns 0 — *"our own attempt — resume
it"* — so repeated passes do not churn the platter.

**Bound it.** The first build asked on every claim retry: 68 passes in one
790 s lap, each a READ KEYS plus a READ RESERVATION, while the rate-limited log
line suggested three. The bound must stay well inside the returning peer's
mount barrier (30 s), or a fixed liveness defect becomes a lockout again.

Verified `flr_s75e`: `fails=0`, phase A/B/C all zero — certificate
`BOOT_SUCCESSION_ABSENT`, peer mounts, 64/64 files byte-identical, no
descriptor standing. And blocking while the victim is still alive in its
original incarnation stayed correct throughout, which is the point: liveness is
owed from the boot boundary, not before it.
