---
name: technique-verify-a-hang-fix-by-timing-the-operation-that-hung-not-by-the-absence-of-the-hang
description: TECHNIQUE (0.89.11, D-381): a hang fix is verified by running the exact operation that hung, bounded, and timing it — 764s retry loop became a 4s EIO…
metadata:
  type: feedback
tags: [verification, rig, hang, technique]
---

# Verifying that a hang is gone needs the operation that hung, not a clean run

A lap that completes without hanging is weak evidence: it may simply not have
attempted the operation that blocks. The strong form is to run the **exact
operation that hung**, under a derived bound, and record its wall time and
return code on both sides of the fix.

For D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381 that was:

| | before (build C12E…) | after (build A0C7…) |
|---|---|---|
| `stat` through the mount | retried for 764 693 ms and climbing (`P-LKTIMEOUT-HOLDER`, `P36-RETRY` counting down) | **EIO in 4 s** |
| `umount` + `rmmod` | both hung; module unreleasable; prep reported "unusable after power cycle"; only `virsh destroy` cleared it | `UMOUNT_RC=0 MOUNTED_AFTER=0 RMMOD_RC=0 MODULE_PRESENT=0`, **3 s** |
| `P240-RBLK-EIO-ABORT` | 0 | 1 |
| `P238-FENCE-BLOCKED` | 0 | (new) `P238-FENCE-BLOCKED-AMBIGUOUS` 1 |

Same rig, same reproducer, same harness — only the build differs. Each number is
re-checkable by anyone with the two builds.

Two things that made it stick:

- **A probe counter that was 0 before and 1 after** (`P240-RBLK-EIO-ABORT`) is
  worth more than any wall-clock number, because it names the *mechanism* that
  changed rather than the symptom.
- **Fold the check into the harness afterwards**, bounded, so the fix cannot
  regress unnoticed. A verification run in a shell once is evidence for that
  session only.

Always wrap the hanging operation in `timeout` when testing it — an unbounded
`umount` against a wedged filesystem is how the check becomes the next wedge.
