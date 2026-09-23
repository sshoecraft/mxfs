---
name: trap-a-kill-list-from-mxfs-pgrep-includes-the-shell-that-ran-it-and-kills-the-harness-mid-lap
description: TRAP (sess593): `for p in $(tools/mxfs_pgrep.sh 'harness s593b'); do kill $p; done` matched the Bash tool's own shell (its command text carries the p…
metadata:
  type: feedback
tags: [trap, harness, process, rig]
---

# A kill list built from a command-line pattern includes the shell that built it

**What happened (sess593, lap s593b):** to stop a harness lap between iterations I ran, from the Bash tool, `pids=$(tools/mxfs_pgrep.sh 'join_during_takeover.sh s593b'); for p in $pids; do kill $p; done; <cleanup…>`. The pattern matched the Bash tool's own `sh -c` chain (the command text contains the pattern), so the kill signalled my own shell first: the tool returned exit 144, the cleanup after the loop never ran, and the harness — which had just matched its wanted shape and was 2 minutes from its verdict — died at the directory-read step. The two iterations' figures survived in the log; the scored verdict did not.

**Also:** every long-lived Bash-tool shell whose command text ever contained the pattern (earlier launches, earlier greps) matches too — `mxfs_pgrep.sh 'join_during_takeover'` later listed seven Claude-session bash/binary pids and no harness at all.

**Do instead:**
- Launch a lap with its PID recorded: `setsid nohup bash -c '… tests/x.sh …' & echo $! > tests/evidence/<label>.pid` — then `kill $(cat …pid)` names exactly one process tree and nothing else.
- Or wait for the lap: a WANT= shape that has just matched ends the lap on its own; read the log's `INFO iterations=… matched=1` before deciding to stop anything.
- A `kill` in a chain goes LAST, or in its own call, so that a self-kill cannot skip the cleanup.

Related: `never-pgrep-f-on-clyde-mmap-lock-wedge`, `trap-killing-a-harness-run-midflight-leaks-the-module-refcount`.
