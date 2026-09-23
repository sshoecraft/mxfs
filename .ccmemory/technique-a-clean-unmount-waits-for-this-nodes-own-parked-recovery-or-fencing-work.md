---
name: technique-a-clean-unmount-waits-for-this-nodes-own-parked-recovery-or-fencing-work
description: MEASURED 3x (sess578): MXFS's clean unmount blocks until this node's parked fence/recovery worker finishes — so no clean departure can strand its own…
metadata:
  type: project
tags: [disklock, fencing, recovery, unmount, harness-design]
---

# A clean unmount waits for this node's own parked work

Measured three times on 2/tcp, on one build, with two different test knobs:

| lap | parked worker | unmount |
|---|---|---|
| s578j | fence prover, 300 s hold | blocked past its 90 s bound (rc=124) |
| s578k | fence prover, 60 s hold | waited 56 655 ms, then rc=0 |
| s578m | recovery owner, 90 s purge pause | waited 89 598 ms, then rc=0 |

`put_super` does not return while this node has a fencing attempt or a recovery
purge parked. That is a safety property, not a stall — a node must not vanish
leaving its own unresolved work on the platter.

## Two consequences that cost several laps to learn

**1. No clean departure can strand its own descriptor.** The unmount waits, the
parked work completes, and completing it consumes the descriptor. So any
experiment needing "a descriptor whose holder departed cleanly" is
unreachable by an unmount — only a crash strands one. Worth checking before
designing a lap around a clean departure.

**2. A bound that races an injected delay measures the injection.** Derive the
unmount bound from the hold it has to outlast (`HOLD_MS/1000 + slack`). s578j
bounded it at 90 s against a 300 s hold and "failed" by construction.

## The prover/owner asymmetry, measured on one build

- **Recovery owner, clean departure**: publishes `RETIRE_PENDING`
  (`P304-RETIRE-PENDING-RELEASED heartbeat slot N (clean teardown; consumable
  once the PR key is proven retired)`), slot reads `flags=RETIRE_PENDING`.
- **Fencing prover holding a standing attempt, clean departure**: publishes
  **nothing**. Its retire worker finds the attempt
  (`P304-FENCE-RETRY-FOUND`), retries 3×, is refused each time by its own
  parked worker (`P304-FENCE-PROVE-BUSY ... not issuing a second PREEMPT AND
  ABORT under the same attempt`), and exits. The slot is left `ACTIVE`, so
  peers must fence a node that left normally.

The difference is whether the departing node still owns unresolved work — not
anything about the release path. Note the internal inconsistency: the *unmount*
waits for the parked worker, but the *retire worker* gives up three attempts
earlier. Recorded on `D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-...-0356`.

## Related

`recov_desc_names_node` (dlm/disklock.c) compares `d->victim_node`, so the purge
freeze gate covers descriptors naming a node as **victim**, never as **holder**
— which is why a crash *can* leave a descriptor standing whose holder's slot was
later zeroed.
