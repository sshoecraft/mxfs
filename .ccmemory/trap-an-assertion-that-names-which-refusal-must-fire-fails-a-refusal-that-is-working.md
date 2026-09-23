---
name: trap-an-assertion-that-names-which-refusal-must-fire-fails-a-refusal-that-is-working
description: TRAP (s83): the certificate is classified at the CLAIM gate, before the replay gate; asserting on the replay gate alone failed a refusal that was wor…
metadata:
  type: feedback
tags: [harness, measurement-integrity, fencing]
---

# Assert the property, not which gate prints it

s83, verifying that a corrected reader refuses a revoked fence certificate: the
lap injected a retired fence kind onto the platter, then asserted
`P236-REPLAY-REFUSED` appeared. Both arms FAILed with `replay_refusals=0`.

The refusal was working perfectly. The certificate is classified at the **claim
gate** — `P236-CLAIM-UNCERTIFIED` (`dlm/disklock.c`) — which fires *before*
anything reaches the replay gate, and it prints the whole reason:

```
P236-CLAIM-UNCERTIFIED slot=1 victim=… stage=3 kind=16 — RETIRED code point 16:
… ; refusing the claim.  Nothing on this slice may be replayed, purged,
repaired or published
```

The companion failure hid it: the lap's other assertion, *"the victim's slice
was NOT replayed"*, PASSED — and would also pass if the lap had never got that
far. A refusal test that only counts what did NOT happen cannot tell a working
refusal from a stalled one.

**Write the assertion about the property, and let any legitimate site satisfy
it.** Here: a refusal happened *somewhere* (accept the claim gate OR the replay
gate), it NAMES the revoked class, it names the kind that was actually on the
platter, and the slice is untouched. Naming one expected token is a prediction
about the implementation's internal ordering, and when the prediction is wrong
the lap reports a defect that does not exist — and the reflex that follows,
loosening the assertion, is how a real regression later walks through the same
check.

The same shape bit twice in one session: a kernel-log window taken with no mark
counted an event from a previous session's probe, and this. Both are the
instrument being more specific than the thing it measures.
