---
name: design-storage-authority-is-a-lease-held-to-a-deadline-not-a-loss-a-node-is-told-about
description: DESIGN (Astra s87, 0.89.20): every MXFS fence detector needed the LUN to answer, so a quiet fenced node wrote to an unreserved LUN; the fix is a loca…
metadata:
  type: project
tags: [fencing, design-ruling, authority-lease, scsi-pr]
---

# Storage authority is a lease this node holds, not a loss it is told about

Design-consult ruling, session 87, shipped as 0.89.20. Full text:
`docs/rulings/local-authority-lease-and-the-limits-of-a-software-gate.md`.

## What was wrong, and it was structural

Every containment path MXFS had needed the LUN to answer: a data write that
bounced with RESERVATION CONFLICT, or a periodic PR IN that found this node's
key gone. Both are DETECTION. A node issuing nothing, whose audit tick has not
come round (60 s for an auditor, which in a two-node cluster the victim usually
is), is fenced and knows nothing — and once the prover dies the appliance purges
the last registration and releases the reservation with it, so nothing is left
to bounce anything. Measured: the fenced incarnation's bytes read back off the
raw LUN.

**Eventual detection of ownership loss is insufficient if stale I/O can become
admissible before detection.** Polling PR state more often is not a fix — a PR
read is not an atomic ownership check bound to the writes that follow it.

## The three details that make a lease sound

Getting the *idea* (expire authority locally) is easy; these are the parts that
were wrong in the obvious implementation.

1. **Anchor the deadline BEFORE the heartbeat is issued, never at completion.**
   A beat can become visible at the target, have its completion delayed, be aged
   out by peers meanwhile, and only then be stamped "now" — making local
   authority look *younger* than the authority peers can observe. Anchoring at
   issue makes the local deadline expire no later than the remote one.
2. **Accept a renewal only while the previous authority is still valid.** A
   heartbeat CAS succeeds perfectly well against a target that has released its
   reservation and stopped refusing anyone — which is exactly the state the
   defect leaves behind. A beat issued after the lease lapsed renews nothing.
   `CLOSED` is sticky: a heartbeat that starts working again is not a grant.
3. **Check where authority is USED, not only in a timer.** A timer and a
   heartbeat thread can be stalled along with the rest of the VM. The check must
   be on the submission path, must close the epoch itself from whatever context
   finds it expired, and must reach no lock the withdrawal needs, no allocation
   and no LUN.

## What the gate must cover, and what it must not do

Four producers mutate the LUN and all four are gated: metadata buffer submission
(which is also xfsaild and the delwri queue), the journal, buffered writeback and
direct I/O. **Coordination I/O counts** and bypasses the filesystem entirely — an
expired heartbeat worker must not refresh its slot, and an expired
reservation-health worker must not REGISTER or re-RESERVE, which would be an
incarnation undoing its own fence.

The journal gets **no exemption**. An "essential log write" carve-out reopens the
hazard; a dirty log is the correct outcome, because this is a forced-shutdown
path and a node whose authority expired must not make its filesystem look clean
by issuing more writes. Refusals go through each layer's existing error
completion so references are released and waiters wake — otherwise the gate only
converts writes into hung tasks.

## The number is derived from two directions, never as a ratio

"Half the remote timeout" is not sound. Derive the lease from availability (it
must outlast a heartbeat cycle plus scheduling and completion delays) and from
safety (it must expire before a peer can complete a conflicting handoff), and
show the remaining budget covers closure lateness, clock error and in-flight
drain. `R` is **not** automatically the configured death window — the peer's
counting, sampling and alternate death paths have to be audited first.

## The limit that no lease closes

**Completing a Linux request with an error is not proof that the corresponding
SCSI command can never execute later.** A software check cannot retract a command
already handed below it, so if the worst-case command lifetime is unbounded no
finite timeout ratio completes the proof. Closing that needs exclusion surviving
the fencer's disappearance, a proven target quiescence mechanism, or a handoff
that keeps protection until quiescence is established. Say so rather than letting
unallocated budget read as margin.
