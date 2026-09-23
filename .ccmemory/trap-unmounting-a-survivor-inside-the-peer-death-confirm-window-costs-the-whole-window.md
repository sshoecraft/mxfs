---
name: trap-unmounting-a-survivor-inside-the-peer-death-confirm-window-costs-the-whole-window
description: TRAP (s91a): destroying the peer and THEN unmounting the survivor put the unmount inside the 62 s dead-confirm window — rc=124 at a 60 s bound.
metadata:
  type: feedback
tags: [rig, harness, budget, unmount, peer-death]
---

# Unmount the survivor BEFORE you destroy the peer, not after

## What happened

`tests/authtail_mount_unwind.sh` lap s91a staged a dirty abandoned journal slice
the obvious way:

1. peer writes a continuing load,
2. `virsh destroy` the peer,
3. unmount the survivor "before it can recover the slice".

Step 3 returned `UMOUNT rc=124 still=1` against a 60 s inner bound, and the lap
ABORTed at its quiesce stage having measured nothing. Evidence:
`tests/evidence/20260920T201606Z_authunwind_s91a/A_umount.txt`.

## Why

The survivor had already started confirming the peer's death when the unmount
was issued. The disklock dead window on this rig is 62 s (31 missed beats at the
2000 ms heartbeat interval), and an unmount entering that window has to pass
through it before it can release. A 60 s bound cannot be met by construction —
the budget was derived from "an unmount takes a few seconds" instead of from the
barrier the operation actually has to cross.

## The fix, and it costs nothing

Reverse the two steps. The survivor leaves while the peer is still healthy, and
the peer is destroyed afterwards. The staging left behind is IDENTICAL for any
lap whose subject is the next mount — a peer that died dirty with nobody up to
recover it — because the slice is replayed by whoever mounts next, not by
whoever was mounted at the time of death. The unmount then runs on a healthy
cluster and finishes in seconds.

Only reverse it when the lap's subject is the NEXT mount. A lap whose subject is
the survivor's own reaction to the death obviously cannot.

## The general form

`tests/d513_fswide_abort_preserves_death.sh` does destroy-then-unmount and works
only because its ssh bound is 90 s with no inner timeout — it pays the window
rather than avoiding it. If a harness must unmount inside the window, derive the
bound from the window (62 s) plus the unmount's own work, not from the unmount
alone.
