---
name: trap-a-survivors-own-exclusive-write-gate-locks-the-victim-out-of-the-heartbeat-that-would-prove-it-dead
description: TRAP (0.89.14): the sole-survivor WE(1) gate blocks the returning peer from writing the LUN, so it can never heartbeat, so boot succession can never…
metadata:
  type: feedback
tags: [fencing, persistent-reservations, deadlock, recovery, liveness]
---

# A proof route that depends on the victim doing something your own fence forbids

## The deadlock

The sole-survivor exclusive-write gate is a SINGLE-HOLDER Write Exclusive
reservation (`type 0x01`) under the survivor's own key.  Under it, no other
initiator may write the LUN at all.

The survivor installs it, proves exclusion, and then fails to publish the
certificate.  Its recovery therefore never completes, so the gate is never
converted back to WE-AR.  Now:

- the returning victim registers, then tries to publish its PR key to the
  on-LUN ledger — a WRITE — and gets `sd N:0:0:0: reservation conflict`;
- `P-PRKEY-PUBLISHED ... rc=-52 — the registration stands but is UNATTRIBUTED
  on the LUN; refusing`, then `TCP SCSI PR register failed — aborting mount`;
- so it never claims a disklock slot and **never heartbeats**;
- so `mxfs_disklock_host_live_other_boot()` is false forever;
- so boot succession — the survivor's only remaining proof route — can never
  become available.

Measured (s81d spent-arm, 2/tcp): the survivor asked seven times and logged
`P238-BOOTSUCC-HOST-NOT-LIVE` seven times, `BOOTLIVE=0`, `CERTIFIED=0`, and
the cluster stayed at one node permanently.

**The general shape, which is the part worth remembering:** a liveness route
whose precondition is an action the node's own exclusion mechanism forbids is
not a slow route, it is a dead one.  Before relying on "the victim will come
back and show us X", check whether the fence in force permits the victim to
produce X at all.

## Why the obvious diagnosis was wrong

The first reading was "the revisit gate is polled, not event-driven, and the
peer's 30 s barrier wins the race".  That IS a real defect — it is the one the
`fence_lost_response` harness hits — but it is a DIFFERENT one.  Distinguish
them by a single count in the survivor's log:

| `P238-FENCE-RESUME-BOOTLIVE` | what it means |
|---|---|
| non-zero, certificate lands late | a timing race: the observation is sampled on the ~30 s acquire pass while the peer's barrier is 30 s |
| **zero**, with `HOST-NOT-LIVE` repeating | the victim cannot heartbeat at all — look at what the reservation forbids |

In the timing case the prover is fast once it notices: certify came 2.6 s after
`BOOTLIVE` (s81da).  Proving was never the slow part; noticing was.

## The fix, and why it is not a new proof

The answer is still standing on the target.  The survivor's own completed
PREEMPT AND ABORT installed that gate, and the gate is still held under its own
key — what was lost is the certificate WRITE, not the exclusion.  So the
revisit RE-READS it (PERSISTENT RESERVE IN only, no command issued) and
republishes the kind it already proved, guarded on remembering that this
attempt proved the gate (`blocked[].fence_kind`), on the reservation still
being the single-holder form under our key, and never for a victim key that is
our own.  Anything else leaves the verdict standing.

That is publication, not re-proof, which is the distinction the banked ruling
insists on: retry the publication of the proof already held, never re-prove.

## Harness trap that hid it

`dbg_cert_fail_n=99` fails EVERY certificate CAS, not just the window's — so
the arm that spends the publication window was also failing the certificate the
recovery afterwards depends on, making "the peer gets its filesystem back"
unreachable rather than merely unmet.  Four consecutive laps read as a product
failure.  The tell is in the injector's own line: `left=64` at the end of the
lap.  An injected fault that models a transient must be CLEARED at the point the
transient ends, or the second half of the arm asserts a fantasy.
