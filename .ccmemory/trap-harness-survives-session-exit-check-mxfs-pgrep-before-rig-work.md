---
name: trap-harness-survives-session-exit-check-mxfs-pgrep-before-rig-work
description: CORRECTED sess413: a rig harness launched as a Bash child DIES at the relay teardown (sess412 board died mid-run at the exact relay moment). setsid+n…
metadata:
  type: feedback
---

# TRAP (sess410, CORRECTED sess413): rig runs vs session/relay teardown

## sess413 correction — the important half
A harness launched as a plain Bash child of the claude process (foreground OR `run_in_background`, directly or via a rig-runner agent's Bash) **DIES when the session is torn down at a relay boundary**. Proven 2026-08-24: sess412's full board (`run.sh 32 caw`, run_id 20260824T004012Z) died at 00:43:26Z — the exact relay teardown moment — 3 minutes into a ~17-minute run, mid-board, leaving no summary row in criteria.json and never starting the chained second job. A grind-agent /proc sweep (comm-based, RULE-2c-safe) found zero surviving harness processes.

**The fix: launch long rig work with `setsid nohup sh -c '...' &`.** The setsid detaches it from the session's process group so relay teardown cannot kill it, and per-stage `STAGE <name> rc=N` lines appended to an evidence chain-log make the next session's harvest trivial. Evidence files MUST live under tests/evidence/ (never scratchpad — host reboots wipe /tmp, sess400 trap).

## sess410 original (still true for setsid'd/ssh'd work)
Work that IS detached (setsid, or running on the test nodes via ssh) keeps running invisibly after the session ends. At session start, BEFORE any rig work (esp. rebuilds — srcversion split trap): check for a live orphan (tools/mxfs_pgrep.sh — note it can race/report stale pids; verify /proc/<pid> exists) and harvest its evidence files first.

## Corollary
`tools/mxfs_pgrep.sh` output is a point-in-time snapshot with no liveness guarantee — always confirm `/proc/<pid>` still exists before treating a pid as a live run.
