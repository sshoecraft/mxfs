---
name: trap-node-death-replay-row-unrunnable-below-32-nodes-slotmap-empty-and-32-node-geometry
description: TRAP (2026-09-04): node_death_replay FAILs in 3 s at 4/caw without killing anyone: slot map reads slot=? (claim line not retrievable from a P291-EXWI…
metadata:
  type: feedback
tags: [harness, node_death_replay, tmpfile_churn_kill, small-N, vacuity]
---

# node_death_replay is not runnable below 32 nodes as written

Observed 2026-09-04, board run 20260904T144717Z at 4/caw on 0.70.18: the row FAILED after 3 s with
`FAIL: could not pick 2 victims of class 'shared'` and every node listed as `slot=?`.

Two independent causes in `tests/tmpfile_churn_kill.sh` (lines ~143-168):
1. The slot map is built by grepping `disklock: claimed heartbeat slot N` out of `journalctl -k --since -20min` + dmesg. On this mount neither log held the line (the journal was dominated by `P291-EXWIN` per-inode probe lines); the harness therefore had no slot for any node and could not pick victims. Fix direction: read the slot from sysfs / the disklock table, not the kernel log.
2. Victim classes are hard-wired to the 32-node rig: `slot 7..24 = single`, everything else `shared`, `ag = slot % 25`. At N=4 (slots 0-3) every node is "shared" by that rule, which is meaningless at 4 nodes on 25 AGs. Victim selection must come from declared geometry.

Consequence: a small-N board has ZERO death/replay coverage even when every other row is green. A 4-node ship gate cannot use this row until both are fixed. A FAIL here is a harness verdict, not a filesystem verdict — do not file it as a replay defect.
