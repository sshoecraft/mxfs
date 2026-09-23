---
name: trap-a-records-next-step-can-declare-a-route-closed-on-reasoning-a-later-version-made-obsolete-by-building-it-another-way
description: TRAP (s117): the crash-matrix record said route 1 was closed because scsi_ioctl_reset is unexported; 0.89.33/34 built it through a userspace upcall a…
metadata:
  type: feedback
tags: [fencing, queue, evidence, planning]
---

# A "this route is closed" verdict expires when the route is built another way

**What happened.** `D-FENCE-CRASH-MATRIX-UNTESTED` carried, as its next step,
that nothing in the record was runnable until a retirement route existed, and
that of the three routes the design ruling named, **route 1 (a witnessed SCSI
LOGICAL UNIT RESET) was closed on this kernel** — "there is no in-kernel SCSI
task-management path an out-of-tree module can reach on 6.8, `scsi_ioctl_reset`
is unexported and the `try_*_reset` helpers are static." That reasoning was
correct and it was about **in-kernel reach only**.

Route 1 was then built anyway, through a userspace upcall:
`mxfs_pal_lu_reset_witness()` calls `call_usermodehelper` into a helper that
issues one `ioctl(SG_SCSI_RESET, SG_SCSI_RESET_DEVICE|SG_SCSI_RESET_NO_ESCALATE)`
and returns a nonce-framed report the module judges. It mints a fence kind that
proves exclusion with `retire_basis = completed-target-op`, and it is called
from the ordinary dead-peer prover — in exactly the branch whose refusal had
blocked the record.

Nothing updated the record. A session planning from it would have skipped the
one lap that settles whether the whole work queue behind it is open.

**Why it is not just "old evidence goes stale".** The stale thing was not a
measurement; it was a **feasibility judgement about the implementation**, stated
in terms of one mechanism (an exported kernel symbol) when the requirement was
a capability (a witnessed task-management operation). A judgement phrased as
"there is no X" survives being read long after someone built the same capability
without X.

**What to do.** When a record's next step says a route, mechanism or approach is
closed, check whether the *capability* still has no implementation before
planning around the closure — not whether the specific mechanism named is still
absent. The cheap check is to grep for the capability's own vocabulary (here:
`lu_reset`, `LURESET`, the fence-kind enum) rather than for the symbol the
record said was missing.

And when a route IS built, sweep the queue for records whose next step was
written while it was closed. This is the mirror image of the withdrawal case
already recorded in
`trap-banked-lap-evidence-stops-describing-the-build-when-an-intervening-change-withdraws-the-mechanism-the-lap-depended-on`:
withdrawing a mechanism expires banked passes, and ADDING one expires banked
blockers.
