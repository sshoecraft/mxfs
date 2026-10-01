---
name: trap-a-rare-board-corruption-was-chased-with-stress-laps-while-the-board-had-kept-every-nodes-kernel-log-of-it
description: TRAP (0.90.37): 7+ laps tried to reproduce one board corruption; the board's run_<row>_<id>/kernlog_*.gz already named the cause in 289 lines.
metadata:
  type: feedback
tags: [rig, evidence, investigation, kernel-log, dlm]
---

## What happened

One 8/net/mesh/direct board audit found a directory entry naming a freed inode
(D-8TCP-RM-OF-A-CHILD). Two sessions shaped new stress arms and ran 7 idle-host
runs, 3 parallel waves and 4 forced-overlap laps. None reproduced it, and the
record said "suspected mechanism (not proven)".

The board run had kept every node's kernel log: `tests/evidence/run_<row>_<run id>/kernlog_test*.gz`,
one per node, for every row of that run. Grepping them for the two inode numbers
the image named gave 289 lines. In time order they showed the whole chain on
the remover: a 10 s stale demoter claim (P126 dem_age_ms), the release run by
another task, the modification committed at mode NL (P152 dlm_mode=0), the
write fence restoring the platter image (P239 arm=restore), and the change
dropped at the next adopt (P177-OBLIGATION-DROPPED-AT-ADOPT). That pointed
straight at the demoter bypass in mxfs_dlm_ilock_begin.

## How to apply

- When an audit names damaged inodes, grep the run's own `kernlog_*.gz` for
  those inode numbers BEFORE shaping any reproducer. Find the run directory by
  the run id in the board log.
- Sort by node and wall-clock second, keep the per-node log order inside a
  second, and print tag plus key=value fields only (no raw lines: raw kernel
  logs in tool output trip the safeguard classifier).
- Tags printed with pr_debug-level helpers still land in these logs because the
  rig loads mxfs with dyndbg=+p.
- Count the precondition tags across every other run of the same board too. Here
  the precondition occurred exactly once in five waves, in the corrupted wave
  only. That is the evidence a stress lap without the precondition cannot give.
- A stress shape that does not reproduce the precondition proves nothing about
  the mechanism. Make the precondition on demand with a test-only injector,
  then run the control and fix arms on one build.
