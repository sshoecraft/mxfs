---
name: trap-run-sh-reprints-the-stored-board-after-a-failed-run-so-its-verdict-line-is-not-this-runs
description: TRAP: run.sh that dies at setup (no pool LUN, node fenced off) still prints the STORED board + "VERDICT: every criterion green"; grade by its rc line.
metadata:
  type: feedback
---

0.90.115 release gates (2026-10-10): tests/release_rig_gates.sh graded each board from its log's `VERDICT:` line. 2/net/mesh/direct@g2 and 16/disk/caw/direct@g16 read "every criterion green" — but run.sh had exited in 28 s with `ERROR: no pool LUN for [test1 test2]` / `=== rc=1 run.sh ...` because test2 was held off by the rig fence (libvirt hook: "inhibited ... its survivor releases it with rig_fence_virsh.sh release", left by a failed drbd outage-test). run.sh prints the board from data/criteria.json after ANY exit, so the green was a previous build's stored cells.

**How to apply:** a board run counts only if its own `=== rc=0 run.sh <cfg> ...` line is present AND the verdict is green; also sanity-check the log size (a real 31-row board log is ~11-12 KB, a setup failure ~4.5 KB). tools/boards_stage_chain.sh exits 0 whatever its boards found. After any failed DRBD rig test, check `virsh domstate` of both nodes and `tools/rig_fence_virsh.sh status <node>`; release a fenced node with `rig_fence_virsh.sh release <node> <episode> <survivor>` (only once the survivor has nothing to recover), then `scripts/drbd_rig.sh down`.
