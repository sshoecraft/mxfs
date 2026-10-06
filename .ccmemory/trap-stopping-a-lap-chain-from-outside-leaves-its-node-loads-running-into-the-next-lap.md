---
name: trap-stopping-a-lap-chain-from-outside-leaves-its-node-loads-running-into-the-next-lap
description: TRAP (0.90.53): TaskStop of a lap chain left pathload.py looping on nodes whose mount released at the next prep; it ran 7.3M ops into the next lap.
metadata:
  type: feedback
tags: [harness, mpath, orphan-load, taskstop]
---

A path-row load (tests/mpath/pathload.py run) stops only when its stop file appears; it counts every failed
operation and keeps looping.  Stopping the chain from outside (TaskStop, a killed run.sh) never touches the stop
file.  The next `prep_cluster` power-cycles nodes whose mount will not release — which kills their loads — but a
node whose mount released cleanly is NOT rebooted, and its orphan load resumes on the new mount.

Measured 2026-10-05 (0.90.53): after the g4 and g2 chains were stopped mid path_flap, test6's orphan (pid 9269)
ran until 21:14 (7,334,412 ops logged) through the new lap's first three rows, then held /mnt/shared so
path_mount_degraded's first umount returned 32 (EBUSY) in 5 ms; on g2 test2's orphan ran 13 min into the new lap.
The new lap's failures were a harness artifact, not the filesystem.

Since 0.90.53 every row's pf_start_gate (tests/mpath/lib.sh) kills such a load on each node via
tools/mxfs_pgrep.sh '^python3 /src/mxfs/tests/mpath/pathload[.]py run ', logs "INFO <node>: load left running",
and ABORTs the row if it cannot.  When reading a lap that follows a stopped chain, check the old run's
load_<node>/ops.log tail times against the new lap's start before believing its early rows.
