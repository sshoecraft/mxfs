---
name: trap-a-background-bash-task-dies-with-the-session-at-a-ccloop-relay-so-a-rig-chain-must-be-nohup-setsid
description: TRAP (0.90.9): a run_in_background Bash task (and its run.sh) is killed when ccloop relays the session; the board row in flight finalizes ABORTED.
metadata:
  type: feedback
---

# A background Bash task dies with the session at a ccloop relay

**What happened (session 6963ae57, 2026-09-28).** `tests/board_4node_chain.sh s2a tcp cawd`
was launched as a plain `bash ...` inside a `run_in_background` Bash call. The session
ended its turn saying the chain "runs in its own process session (it survives this
session's end)". It did not: the relay killed the tool's task at 17:36:38Z (task
notification `status: killed`), `run.sh` finalized the row in flight as
`crash_audit[4/tcp] ABORTED`, the crash-test victim test2 was left shut off, and the
4/cawd board never started. Every earlier row's PASS survived; only the in-flight
row and everything queued after it were lost.

**Why.** A `run_in_background` task belongs to the Claude Code process; the relay kills
that process tree. Only a process in its OWN session survives — `nohup setsid <cmd>
> <log> 2>&1 < /dev/null &` — which is exactly how `tests/lap_queue.sh` is launched
(see `trap-a-detached-lap-queue-outlives-the-session-that-launched-it...`). A
Workflow dies the same way (`trap-a-workflow-is-invisible-to-the-ccloop-stop-gate...`).

**Rules that follow.**
- Launch any rig chain longer than one turn detached (`nohup setsid`), logging to
  `tests/evidence/`, and read its progress from the log and `tools/criteria.py`.
- A detached chain counts ZERO toward the Stop gate: keep working in the foreground
  while it runs (read code, design the next lap); never end the turn "to wait".
- Before believing a handoff that says a chain is running, check its log's tail and
  `/proc/<pid>/comm` for the pid in `/tmp/mxfs_run.lock` (a flock — a dead pid there is
  harmless).
- A killed board leaves the fleet as the row left it (here: the victim destroyed, not
  restarted); start the VM and force a fresh prep before the next run.
