---
name: trap-an-election-that-elects-the-lowest-live-slot-does-no-work-when-that-node-is-the-one-that-left
description: TRAP (sess41, D-0381): repair authority pinned to the lowest live heartbeat slot does nothing when THAT node departs — its worker exits and its slot…
metadata:
  type: feedback
tags: [fencing, scsipr, election, disklock, reservation]
---

# An election that answers "am I the one" leaves the work undone when the elected node is the one that left

## The shape

`mxfs_disklock_lowest_live_slot()` elects the node holding the lowest live
heartbeat slot, and jobs are gated on it with `elected = (low == local_slot)`.
That is correct when the elected node is always able to do the job. It is a
hole whenever the job must still happen **if that node is gone**: every other
node reads "not me" and nothing is performed by anybody.

The failure is invisible in the log of the node that notices, because it
notices correctly and reports correctly. It just declines to act.

## The measured instance (D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381)

Only the elected maintainer could repair a lost WE-AR fencing reservation,
deliberately, so 32 nodes could not race a cluster-wide write. But the
maintainer is the LOWEST live slot, i.e. exactly the node whose departure
removes the repairer:

- its per-mount PR worker exits with it (`P304-PR-WORKER exiting`);
- its slot keeps reading **live** afterwards, because a clean teardown logs
  `P304-RETIRE-PENDING-RELEASED heartbeat slot N (consumable once the PR key is
  proven retired)`, and the slot lineage is retired only when a successor
  proves the clean release (`P163-CLEAN-DEPART-LINEAGE`) — which needs somebody
  to mount.

Measured on the 2-node TCP rig, 0.86.1: test1 (slot 0) unmounted cleanly, the
reservation was released out of band 2 s later, test2 reported
`P305-RESV-HEALTH state=ABSENT role=auditor` and did not repair. The LU stayed
unreserved — unfenceable — until test1 REMOUNTED and its own admission
re-established the reservation. Nothing bounded that window.

## The fix shape that worked

Make the election a **head start, not an exclusive right**. Added
`mxfs_disklock_live_slot_rank()` beside the election, using the *same*
liveness predicate in the same place (a rank derived from a second, drifting
copy of "is that slot live" would put two nodes at rank 0). Stand-ins act after
`grace + rank * step`, so they queue instead of racing. Fixed build measured
the takeover at exactly the designed 20.50 s, and with the maintainer present
it still repaired at t+6 s as `role=maintainer rank=0` with no takeover.

## What to check elsewhere

Every other `lowest_live_slot` call site is a candidate for the same question:
**is this job still required when the elected node is absent?** If yes, a
boolean election is the wrong primitive. In v5_mount.c the call sites at the
time of writing were the resv-health tick, foreign-slice replay election, and
several fence/recovery paths — the replay ones pass a `skip_slot` for the dead
node, which is the other correct answer to this problem.

## The sibling trap it teaches

When an operation is deliberately restricted to one actor for
race-safety, ask separately who performs it when that actor is missing.
"Must not be done by everyone" and "will be done by someone" are two
requirements, and satisfying only the first reads as a safe design.
