---
name: trap-a-revisit-gate-keyed-on-volatile-state-that-the-same-function-overwrites-fires-exactly-once
description: TRAP (0.89.14): the acquire path's generic NO_CERTIFICATE fall-through erased the specific CERT_UNRECORDED the revisit gate read, so the gate fired o…
metadata:
  type: feedback
tags: [fencing, recovery, revisit, measurement, state-machine]
---

# A gate that reads volatile state the same function then overwrites fires once

## The shape, which is general

A recovery-revisit gate was keyed on an **in-core** blocked-reason enum.  The
same function that evaluated the gate fell through, a few hundred lines later,
to record a *generic* verdict over the *specific* one the gate had just read.
So the gate could fire exactly once per event, and the code that read it
destroyed what it read.  Nothing logged anything wrong; the slot was visited
on schedule forever and simply did nothing.

`NO_CERTIFICATE` ("there is no certificate for this slice") is not an
alternative to `CERT_UNRECORDED` ("exclusion was PROVED and only the
certificate's durability is unconfirmed") — the first is *implied by* the
second.  Writing the implication over the cause is what destroyed the state.

## How it presented, and the counts that proved it

Harness `tests/fence_cert_publish.sh <label> spent` (2/tcp), build
`A11EAB2908153F53BE9C69A`.  The publication window is spent deliberately
(`dbg_cert_fail_n=99`); blocking is correct, but it must not be terminal.
Result: `certificates=0 retries=4 unrecorded=1`, and the returning peer got
`MOUNT_RC=32 MOUNTED=0`.

The prover's own log over the 154 s that followed:

| line | count |
|---|---|
| `P238-FENCE-UNRECORDED` | 1 |
| `P238-FENCE-RESUME` | **1** |
| `P238-FENCE-RESUME-NOPROOF` | 1 |
| `P238-FENCE-HOLDER-STATE` | **6** |
| `P238-FENCE-RESUME-BOOTLIVE` | **0** |

Six visits, one resume.  The first visit saw `CERT_UNRECORDED`, resumed,
found no independent proof (the victim's host was still down — correct), then
fell through and recorded `NO_CERTIFICATE`.  Every later visit found neither
arm of the gate's disjunction true.

**The second arm was unavailable for a structural reason worth remembering:**
this attempt proved exclusion through the sole-survivor exclusive-write gate,
which submits no command needing a durable pre-submission boundary, so the
`MAY_HAVE_RUN` bit was never armed.  A gate written as
`(durable_arm || in_core_reason)` therefore rested entirely on the in-core
half in exactly the case that mattered.

## What to check when a periodic revisit "looks and does nothing"

1. Count the visits and the actions separately.  `6 visits / 1 action` is a
   different defect from `0 visits`, and the log looks healthy in both.
2. Find every writer of the state the gate reads, not just the one that sets
   it.  Grep the setter, not the enum.
3. Ask whether the two values are alternatives or whether one implies the
   other.  A generic verdict overwriting its own cause is the bug.
4. The file said the answer already: *"a dedicated worker, whose queue is the
   ON-DISK DESCRIPTOR.  The in-memory array is only an accelerator."*  A gate
   keyed on the accelerator alone is not crash-closed and, as measured here,
   is not even restart-closed within one incarnation.

## The fix

Refuse the downgrade: for the same victim, a standing `CERT_UNRECORDED` is
kept when a generic `NO_CERTIFICATE` is recorded, refreshing only the liveness
fields.  The durable direction — carrying "proved but unpublished" on the
on-disk descriptor so it survives the prover too — remains the stronger shape
and is not what this change does.
