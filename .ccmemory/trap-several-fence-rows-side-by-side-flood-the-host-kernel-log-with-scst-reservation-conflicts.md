---
name: trap-several-fence-rows-side-by-side-flood-the-host-kernel-log-with-scst-reservation-conflicts
description: TRAP (0.90.51): 6 chains of path/fence laps at once; SCST logs each refused command, preflight (40/s) refused laps, guard halted the rig (FLOOD).
metadata:
  type: feedback
---

Running fence-heavy rows (path_fence_degraded, path_fenced_return, path_all_lost,
path_peer_withdrawn) on several rig groups at once makes clyde's own kernel log
the bottleneck: SCST prints one `scst_set_cmd_error_status ... Reservation conflict`
line per command a fenced node sends, and a node that keeps retrying sends tens
per second.

Measured 2026-10-05 (0.90.51, six chains g2,g2b,g4,g4b,g8,g8b):
- `clyde_preflight` refused lap starts: "kernel log is producing ~85 lines/s (max 40)"
  -> run.sh rc=3, and the chain read the STANDING board back, so the stage looked
  like a result (9 of 11 g8 stages were never run).
- one wedged 8-node cluster (test9, UNMOUNT_FAIL, still sending I/O) produced
  1607 conflict lines in one minute; `mxfs-clyde-guard` halted the rig
  (`.rig_halt`, reason FLOOD, 60 lines/s for 60 s).

How to apply:
- After a chain, check every stage log for `clyde_preflight: FAIL` / `rc=3` before
  reading any board row as measured: `grep -c 'clyde_preflight: FAIL' board_*<label>*.log`.
- Do not stack more than two or three fence-row lap chains; full boards whose
  path rows are a small share are fine.
- A node hammering a LUN it is fenced from is itself a finding (it should have
  stopped); look at that node before blaming the rig.
- Never widen the preflight or guard thresholds to get the laps through.
