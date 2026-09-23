---
name: trap-the-tool-host-kills-a-long-background-rig-task-under-its-own-memory-threshold-mid-deploy
description: TRAP (sess594): a run_in_background module_swap_deploy was killed by the Claude Code host ('system is running low on memory') with 62 GB available on…
metadata:
  type: feedback
---

## What happened
- `scripts/module_swap_deploy.sh 2 tcp` launched with `run_in_background` (bound 900 s) was reported `killed` — "stopped because the system is running low on memory" — while clyde had 62 GB available (`free -m`: used 33 GB of 96, buff/cache 63 GB, 650 MB truly free). The threshold is the tool host's, not the kernel's, and it reads the cache-heavy `free` column.
- The deploy had already brought both nodes down ("all 2 nodes down (fs preserved)") and died before forming test1: both nodes sat with no mxfs module loaded (`sv=5A0C... m=0` reported by the nodes because the module file was still on disk; `lsmod` empty). Nothing else announced it.

## Lesson
- A long rig step in the background can be killed by the host at any point and leaves the rig in whatever intermediate state the script had reached. Prefer the FOREGROUND for deploys and laps: the Bash tool allows up to 600 s per call, which covers module_swap_deploy (3-5 min) and every 2-node lap whose derived bound is ≤ 560 s. Split anything longer at a safe boundary.
- After any killed background rig task: check both nodes' `srcversion` and mount count and the script's own log tail before launching the next step; re-run the deploy rather than assuming the marker.
- Do not read "low on memory" as a host problem to fix: `free`'s available column is the truth; the tool host's kill is a session hazard, not a clyde hazard.
