---
name: trap-a-harness-header-describes-the-shape-not-the-prep
description: TRAP (sess565): sess493_d0492_crash_durability.sh reads as a 2-node harness but hardcodes `run.sh 32 caw prep_cluster`; it booted all 32 VMs and left…
metadata:
  type: feedback
tags: [trap, harness, rig-safety, 2node-tcp, d0496, d0492]
---

# A harness header describes the SHAPE, not the PREP — check the prep call

sess565, working D-0496 under the two-node TCP directive. Ran
`tests/sess493_d0492_crash_durability.sh` because its header opens with:

> "Two nodes alternate creating fsync'd files in ONE shared directory..."

That is an accurate description of the *workload*. It is not what the harness
brings up. At line ~142 it calls, hardcoded:

    timeout 300 ./run.sh 32 caw prep_cluster

**32 nodes, CAW transport.** Both out of scope under the 2026-09-05 directive.

## What it cost

- All 32 test VMs were started. `run.sh`'s own escalation then power-cycled
  test3..test32 (`virsh destroy+start`) when they failed to release mxfs, and
  every one came back without `/dev/mapper/mpatha`.
- clyde went to **0 GB free** (94 total, 58 used). The known failure mode from
  `trap-32-idle-vms-running-exhausts-clyde-ram...` is exactly this.
- test1/test2 were left UNMOUNTED with the module unloaded — the two-node rig
  was down and needed a prep to come back.
- Total cost ~5 minutes of rig time and a cleanup pass, for zero measurement:
  the run aborted at prep and never reached a round, a crash, or a verify.

## The check that would have prevented it, in one command

Before running ANY harness from `tests/` that this session has not run before:

    grep -n 'run\.sh [0-9]* \(caw\|tcp\)\|MXFS_NODE_LIST\|^A=\|^B=\|^C=' tests/<harness>.sh

`sess493_d0492_crash_durability.sh` also defaults `A=test3 B=test2 C=test4` —
node names that are not even in the two-node rig. Either signal alone is
enough to reject it.

## Other landmines in that same harness

- `KO` defaults to a FROZEN build (`tests/evidence/sess493_frozen_07011/mxfs.ko`),
  so running it without `KO=` measures a five-day-old module, not the tree.
- It does `cp "$KO" mxfs.ko` — passing `KO=/src/mxfs/mxfs.ko` makes that a
  same-file copy (harmless, but it means KO must be a *different* path to work
  as intended).
- `RESTORE_KO` defaults to `tests/evidence/sess488_frozen_0695_tree/mxfs.ko`,
  **which does not exist**. On the abort path it tries to restore that over
  `mxfs.ko` and fails. If KO had been a real frozen build, the tree's `mxfs.ko`
  would have been left as the frozen one with the restore silently failing.
- Its whole body is wrapped `{ ... } >> "$LOG" 2>&1`, so the invoking shell sees
  NOTHING. An agent reporting "no output" is not a hung run — read the log at
  `tests/evidence/<name>_<label>.log`.

## The general rule

A test harness in this tree encodes the rig shape it was WRITTEN for, and most
of them were written during the 32-node era. Under a narrowed directive, the
harness's own prep is the thing to verify — not its prose.
