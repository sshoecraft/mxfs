---
name: technique-verify-a-timestamp-anchor-by-asserting-on-the-two-timestamps-the-kernel-prints-not-on-the-downstream-behaviour
description: TECHNIQUE (s87): the lease's issue-time anchor was proved by deadline_ms - issued_ms == 30000 exactly; asserting only "the write was refused" would h…
metadata:
  type: feedback
tags: [measurement-integrity, harness, authority-lease]
---

# Assert on the anchor itself, not on what the anchor happens to cause

The authority lease derives its deadline from the instant a heartbeat is
**issued**, never from when its completion is delivered. Anchoring at completion
would hand a node authority measured from an instant that had already passed for
its peers.

## The weak test, and why it passes for the wrong reason

The obvious lap is: withhold the completion for longer than the lease, then try
a write and assert it is refused. That passes on a **completion**-anchored
implementation too, as soon as anything else has closed the epoch first — the
periodic evaluator, a bounced write, a detector. What the refusal proves is
stickiness, not the anchor.

Two things are needed to make it discriminating:

1. **Park every other closer.** Here that meant parking the periodic evaluator,
   so the only thing that could set the deadline was the renewal under test.
2. **Assert on the timestamps directly.** The kernel already prints the instant
   the beat was issued (when it starts withholding the completion) and the
   deadline it later closed against. Their difference IS the anchor:

       issued_ms=265959  delivered_ms=312039  deadline_ms=295959
       deadline - issued == 30000   ← one lease, from the ISSUE
       (a completion anchor would have read 342039)

   `ck "the lease deadline was derived from the ISSUE instant" $((DEADLINE - ISSUED)) 30000`

   One line, exact, and it fails loudly on the implementation the design consult
   warned about.

## The companion technique: reaching a guard no live path can reach

The same harness had a guard — refuse a renewal whose beat was issued after
authority had lapsed — that **nothing can exercise**, because a check further up
stops the heartbeat before such a beat can be sent. A guard nothing can exercise
is a guard nobody knows works.

The injection to reach it removes the **primary check** for exactly one cycle
(`dbg_hb_skip_auth_check`), leaving the guard and every other test intact. That
is the right shape: never weaken the thing under test, take away the thing that
was hiding it. Compare the s83 rule for a refusal against records this build
cannot produce — inject at the write, not at the check.
