---
name: technique-derive-a-mount-budget-from-the-barriers-printed-bound-not-from-the-windows-it-is-built-from
description: TECHNIQUE (s84): seven arms FAILed at a 96s budget estimated from design prose; the barrier prints bound_ms=122000 in its own log line — read that.
metadata:
  type: feedback
---

# The mount barrier prints the bound it will hold to — use that number

Session 84's `tests/fence_kind_matrix.sh` set a 96 s mount budget, derived by
adding up the observation windows named in design comments (a 6 s abandon
observation, a takeover observation, a 45 s stability proof, a few refused
claims). Seven of eight arms then FAILed:

```
STAGE the reader's mount answered at +109s: rc=TIMEOUT wall=96s (budget 96s)
  FAIL <the mount was still running at its 96s budget…>
```

Nothing was wrong with the code. The evidence capture held the answer:

```
XFS (sda): MXFS mount barrier: P-BARRIER-GHOST-EXTEND undeclared=1
  window_ms=62000 bound_ms=122000 — 1 frozen heartbeat record(s) are not yet
  declared dead; admission is held until each is resolved
```

**The barrier announces its own deadline, in milliseconds, at the moment it
extends it.** The derivation behind that number is
`MXFS_BARRIER_ADMISSION_WAIT_MS` (30 s, `xfs/xfs_mxfs_dlm.c`) + the dead window
(`MXFS_DISKLOCK_DEAD_THRESHOLD` 31 heartbeats x 2 s = 62 s) +
`MXFS_BARRIER_ADMISSION_WAIT_MS` again = 122 s, granted ONCE from the loop's
start.

Two things follow for any harness that mounts into a barrier wait:

- **Derive from the constants or from the printed `bound_ms`, and name them in
  the budget comment** so the number is re-derivable when a constant moves. A
  budget summed from prose is an estimate wearing a derivation's clothes.
- **A forged or leftover GUARD slot IS an undeclared death**, so any harness
  that plants one gets the extended 122 s bound, not the base 30 s. A mount
  budget under ~140 s will fail such a lap on the harness's own assertion.

Contrast worth keeping: in the same matrix, a descriptor whose VERSION this
build cannot validate was refused in **1 s with rc=32**. The barrier waits for
a class-refused certificate (a prover might still appear) and does not wait for
one it cannot parse. Same refusal, two very different walls.
