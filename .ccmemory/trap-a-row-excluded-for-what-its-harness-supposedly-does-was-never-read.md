---
name: trap-a-row-excluded-for-what-its-harness-supposedly-does-was-never-read
description: TRAP (0.90.40): 5 suite rows were skipped on DRBD as "they virsh start a killed node"; none of them kills or restarts a node. Read the row first.
metadata:
  type: feedback
tags: [harness, board, drbd]
---

**What happened.** A session reported that `dlm_membership`, `crash_consistency`, `fence_during_write`, `fault_netpartition` and `soak` "restart a killed node with a plain virsh start", and left them out of the DRBD board.

A file:line sweep of the rows showed otherwise:
- `dlm_membership` and `fault_netpartition` only iptables-block the DLM port 7600.
- `fence_during_write` injects nothing; it asserts that no fence happens.
- `crash_consistency` only drops caches (its own header says a real kill needs host orchestration).
- `soak` has no fault at all.

The only `virsh destroy/start` on that path is `run.sh`'s prep-time `power_cycle_node`. A misleading `run.sh:542` comment ("crash_consistency deliberately virsh destroys a node") is probably where the claim came from.

**Rule.** Before excluding a row from a board, or labelling it inapplicable, read what the row's script actually does. A comment in the harness is not evidence of what a row does. The real node-kill rows are `coord=host` (e.g. `node_death_replay`).
