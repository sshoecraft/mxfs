---
name: Director scope calibration
description: Director can do small-scope checks in main session; multi-node work always goes to teams with parallel workers
type: feedback
---

Small-scope work in the main Director session is acceptable — SSH to one node, run one command, check a file. The overhead of spawning an agent for trivial checks is wasteful.

Multi-target operations (deploy to 16 nodes, configure 32 VMs, etc.) MUST use a team with parallel workers — one worker per node. Never loop through N targets sequentially in a single subagent.

**Why:** Context conservation + wall-clock time. Sequential 16-node operations burn tokens and take 16x longer than parallel.

**How to apply:** When the task is "do X on N targets", spawn a team lead who spawns N parallel workers. Director gets one consolidated report back. For single-target checks that inform a decision, just do it directly.
