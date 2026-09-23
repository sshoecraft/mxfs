---
name: feedback-the-2tcp-rigs-iscsi-target-is-never-restarted-measure-restart-behaviour-on-a-bench-target
description: USER 2026-09-22: the 2/tcp rig's iSCSI target is never restarted and never asked about again; target-restart laps run on a bench target (serv or loca…
metadata:
  type: feedback
tags: [rig, fencing, user-directive, privacy, iscsi]
---

# The 2/tcp rig's iSCSI target is never restarted; restart laps run on a bench target

User, 2026-09-22 (run 98c3ef65, session 63), after three sessions reported the
fence-matrix target-restart tranche as "blocked on appliance access" and asked
for a credential to the rig's iSCSI target or a hand restart of it: that target
will never be restarted, not by a script and not by hand, and no session asks
again. The user then corrected the first write-up of that directive twice:

1. It is a property of THAT device, not of the tranche. "It may be forbidden for
   that specific device, but it's not forbidden at all." Other iSCSI targets
   can be started freely, on serv or locally, and restarted for the test. A
   memory or record that says the tranche "cannot be measured" biases later
   sessions into giving up on measurable work.
2. Nothing about the device's other role, and no private network address, goes
   into a tree artifact. The repo is published. Name the device by its role
   ("the rig's iSCSI target") or its data/rigs.json tag, never by address or by
   what else it serves.

What holds now:

- data/rigs.json `qnap.restart_forbidden` records the per-device directive.
  tests/target_restart_pr.sh reads it first and ABORTs at stage=forbidden
  before it resolves any credential; the guard is not removed or bypassed.
- The lap resolves its target-host credential under the RIG TAG, so it runs
  unchanged against any restartable target declared under its own tag.
- The next step for D-FENCE-CRASH-MATRIX-UNTESTED is to stand up a restartable
  iSCSI target (LIO or SCST on serv or another bench host, APTPL on), declare
  it in data/rigs.json under its own tag, point the two TCP-rig nodes at it and
  run the lap in both modes twice. Never propose restarting the 2/tcp rig's
  target, and never write "blocked on appliance access".
