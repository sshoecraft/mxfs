---
name: trap-co-occurrence-of-two-probes-is-not-a-race-waking-is-not-acting
description: TRAP (sess578): a harness scored "a takeover happened AND the old worker woke" as two actors under one attempt; neither acted, and the branch it blam…
metadata:
  type: feedback
tags: [harness, fencing, false-positive, measurement-integrity]
---

# Two probes firing in one lap is not evidence they interacted

A safety check written as `if (event_A_count >= 1 && event_B_count >= 1) FAIL`
asserts a *relationship* it has not measured. It will fire on any lap where both
things merely happened.

## What it cost (sess578, D-0932)

The hypothesis: a node publishes `RETIRE_PENDING` at clean teardown while one of
its own fencing workers is parked mid-attempt, so a peer reads that as revoked,
takes the attempt over, and the parked worker wakes and acts under it too.

The check: `takeovers >= 1 && P236-FENCE-INTENT-RESUME >= 1` → "TWO ACTORS UNDER
ONE ATTEMPT".

It fired, and it was wrong in **three** independent ways:

1. `RETIRE_PENDING` was never published — the assertion two lines above had
   already FAILED saying so. The takeover therefore did not come from the branch
   the message blamed; it came from a certified `PREEMPT_ABORT_DONE(16)
   proves_excl=1` → `FENCE-CERTIFIED` → `P-DEAD-INC`, which is correct.
2. The resumed worker **issued nothing**: `KEY_ABSENT_UNPROVEN(6)
   proves_excl=0`. Waking is not acting.
3. The in-node guard had already refused it five times —
   `P304-FENCE-PROVE-BUSY ... not issuing a second PREEMPT AND ABORT under this
   attempt` — which is precisely the protection the hypothesis assumed absent.

## The rule

- Count the **violation**, not its ingredients. Here the real violation is the
  old prover *proving exclusion* under the **old term** after a takeover raised
  it — the term is the cross-node guard, so the term is what the check must
  read.
- A FAIL message must not narrate a mechanism the lap did not establish. Mine
  said "after reading RETIRE_PENDING as revoked" on a lap whose own output said
  RETIRE_PENDING was absent.
- When an earlier assertion in the same lap has already failed, later
  assertions that depend on the state it was checking are **unscoreable**, not
  failing. Consider exiting VACUOUS instead of reporting downstream FAILs that
  describe a state that was never reached.

## The other half: a bound shorter than the injection it must outlast

The same lap bounded an unmount at 90 s while the test-only hold it had to wait
through was 300 s. The unmount "failed" by construction. A bound that races an
injected delay measures the injection, not the system — derive it from the
injection (`HOLD_MS/1000 + slack`).

And the outcome inverted the test's purpose usefully: the unmount *blocking* was
the system doing the right thing — the release serialises against the node's own
outstanding attempt, which is why the hazardous state could not be created. When
a lap refutes its own hypothesis, assert the safe property directly rather than
deleting the test.
