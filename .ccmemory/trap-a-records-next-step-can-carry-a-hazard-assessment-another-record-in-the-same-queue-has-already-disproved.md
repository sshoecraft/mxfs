---
name: trap-a-records-next-step-can-carry-a-hazard-assessment-another-record-in-the-same-queue-has-already-disproved
description: TRAP (s102): the top blocker's next-step said an LU reset wedges a bystander "until power-cycled"; a DIFFERENT queue record had already measured EH r…
metadata:
  type: feedback
---

# A record's next-step can carry a hazard assessment another record in the same queue has already disproved

## What happened
`D-NO-TASK-MANAGEMENT-PATH-...`'s next-step justified the sole-initiator admission
gate with: "a bystander's command is aborted at the target with NO completion ever
sent (it waits in blk_io_schedule inside __iomap_dio_rw, D state, until
power-cycled)."

I spent a long stretch designing around a permanent wedge — weighing whether MXFS
must move its reservation from Write Exclusive - All Registrants (0x07) to an
Exclusive Access form so a non-registrant's READ could not be stranded either,
which would have meant a MXFS_PROTO_GEN bump and a cross-version cluster break.

`tools/defects.py` line 53, `D-A-BYSTANDER-INITIATOR-HANGS-ON-AN-UNANNOUNCED-LU-RESET`,
already held the disproof, measured the same day: ten resets six seconds apart with
a peer writing O_DIRECT at ~1600/s stranded exactly ONE command; libiscsi's timeout
ladder rescued it after 538 s (three expiries of the 180 s device command timeout
plus the abort), the write was retried and completed, zero application errors, no
shutdown, no node declared dead. Its `impact_why` opens "THE 'FOREVER' IS DISPROVED
BY DIRECT MEASUREMENT" and states that the original reading reasoned from a 30 s
command timeout that MXFS itself sets to 180.

## Lesson
Before designing around a hazard a record's prose asserts, grep the WHOLE queue for
that hazard. A next-step is written at one moment and is not revised when a later lap
recorded in a different record settles the same question — the queue has no
cross-reference and nothing makes a stale justification look stale.

`tools/defects.py | grep -i <hazard word>` costs one command. The hazard word here was
"bystander".

## What it changed
The gate's justification, not its shape. It is not standing between the cluster and a
wedge; it is the rule that says when an LU-scope operation is the right tool at all —
another registrant's work can be retired by the precisely-scoped PREEMPT AND ABORT, so
an LU reset there strands a live member's I/O for nothing. The reservation type was
left alone.
