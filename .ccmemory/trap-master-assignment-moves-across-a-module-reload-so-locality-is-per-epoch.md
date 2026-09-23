---
name: trap-master-assignment-moves-across-a-module-reload-so-locality-is-per-epoch
description: TRAP (sess580): which node masters an inode is re-decided when the cluster re-forms, so a locality established before a deploy is void after it.
metadata:
  type: feedback
tags: [dlm, rig, measurement, locality]
---

## What bit us

Master locality is a hash of the resource id, which is already written down. What was NOT written down is that the hash's ANSWER changes when the cluster re-forms.

Measured, 2 nodes / TCP, sess580:

- Lap s580a, build E0A5F1CF: ino 139 was mastered by test2 (test2 itself logged 26 `P7S-BAST-FIRE ino=139`).
- A `scripts/module_swap_deploy.sh 2 tcp` in between — module reload, cluster re-formed on the same filesystem, same inode numbers.
- Lap s580b, build 54ACC426: ino 139 was mastered by test1 (test1 logged the fire, test2 logged none).

Same inode number, same filesystem, opposite master. So a locality determined in one lap is void in the next lap if anything re-formed the cluster in between — and a module swap is exactly that. Never carry a target's locality across a deploy; re-establish it inside the lap that uses it.

## The second half, which is the one that actually scored a wrong result

A probe that determines locality by arming the request-drop knob and calling the candidate LOCAL when the knob does not fire is reading an ABSENCE as an answer. The drop site sits on the remote-master send path, so its FIRING proves remote; its SILENCE proves nothing, because silence has more than one cause.

s580b picked ino 140 that way, declared it local, and measured the remote path: test1 fired 26 notifications for it while test2 — the node the lap was counting on — fired zero. The lap would have scored a clean pass on a number taken from a node that never acted, except that an assertion added the lap before ("the fire count came from a node that actually fired") caught it.

The fix is to make BOTH branches first-hand: have the holder take a conflicting grant, have the waiter read, and see which node LOGS the blocking notification. The master says which it is in its own log, for either answer.

## How to check it cheaply

Per candidate inode, scoped to this run's kernel-log mark:

    grep -ac "P7S-BAST-FIRE ino=$ino " dmesg_test1.txt
    grep -ac "P7S-BAST-FIRE ino=$ino " dmesg_test2.txt

Exactly one side non-zero is the master. Both or neither is UNDETERMINED — skip that candidate, do not guess. Also assert after the lap that the other node fired zero for that inode, so a mid-lap remaster is loud instead of silent.

Note `P7S-BAST-FIRE` only prints for `MXFS_LTYPE_INODE` with `ino <= 256` (dlm/dlm.c, in `fire_bast_records`), so this method works for the low inode numbers a fresh test filesystem hands out and not for arbitrary ones.

## Related counting trap in the same harness

`P7B-BASTNOTIFY` was being counted unscoped on the holder. That counts notifications for every resource, so it read 27 for a lap whose target accounted for one of them — and it made a fire count taken on the wrong node look corroborated. Scope every such count by `ino=$ino ` with the trailing space, or `ino=140` also matches `ino=1400`.

`P36-RETRY` is `pr_warn_ratelimited`, so its line count is not a retry count and two laps' values must never be compared as if they were.
