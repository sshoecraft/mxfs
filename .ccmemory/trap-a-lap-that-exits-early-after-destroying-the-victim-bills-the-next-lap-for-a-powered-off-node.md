---
name: trap-a-lap-that-exits-early-after-destroying-the-victim-bills-the-next-lap-for-a-powered-off-node
description: TRAP (s82): a VACUOUS exit between destroy and restart left test2 off; the next lap burned its whole 580 s budget on boot-wait plus a power-cycling p…
metadata:
  type: feedback
tags: [harness, rig, budget, trap]
---

# An early exit after `virsh destroy` bills the NEXT lap

Measured 2026-09-20 (`fence_gate_basis.sh`, s82b → s82c).

`fence_gate_basis` destroys the victim, grades the prover, then starts it again.
A non-vacuity check between those two points exited VACUOUS — so the restart
never ran and **test2 stayed powered off**.

The next lap then:

- `waitboot` polled ssh on a corpse: 48 polls × 5 s = **240 s** of its budget,
  because a node that is powered off never becomes ready and the poll loop had
  no way to notice;
- `prep_cluster` then had to power-cycle it, and the lap hit the caller's 580 s
  timeout at the *files* stage having measured nothing. `B_files.txt` was
  0 bytes; `prep.log` was written 578 s in.

A budget failure with no product in it, manufactured entirely by the previous
lap's exit path.

## What to write instead

- **Restore the rig on EVERY exit**, not on the happy path: set a flag at the
  destroy, clear it at the restart, and `trap` a restorer on EXIT. That covers
  FAIL, VACUOUS, ABORT and the caller's own timeout.
- **Ask the hypervisor before polling ssh.** `virsh domstate` answers in
  milliseconds; if the domain is not `running`, start it and say so. Four
  minutes of ssh polling is not a liveness check, it is a budget leak.

Generalises: any harness that takes the rig down owes its restoration to
whatever runs next, and the exit paths that skip it are exactly the failing
ones — the laps whose evidence you most need to read next.
