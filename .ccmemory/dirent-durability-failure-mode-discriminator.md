---
name: dirent-durability-failure-mode-discriminator
description: How to tell a GENUINE dirent_durability durable loss from a straggler-timeout artifact: late_ok and the wall are the discriminators, not durable_loss.
metadata:
  type: reference
tags: [dirent_durability, silent-mkdir-loss, false-red, measurement, harness]
---

# dirent_durability: two failure modes, and how to tell them apart

`durable_loss=8` appears in BOTH, so the count alone does not tell you which you
have. Read `late_ok` and the wall.

| field | GENUINE durable loss | STRAGGLER-TIMEOUT artifact |
|---|---|---|
| wall | ~116-124 s (normal) | **240s/240s — hit the budget** |
| `late_ok` | **12-21** (reconciliation ran) | **0** |
| nodes | 1 of 32 (`states:FAIL=1`) | 31 of 32 + `NO_TERMINAL_RECORD=1` |
| `mkdir_err` | 0 | 0 |

`late_ok` counts entries that were not visible at first check but became visible
on a later one. In a healthy run it is always nonzero. **`late_ok=0` together
with a 240 s wall means the run was cut off before reconciliation could run** —
so the "lost" entries were never given the chance to appear, and the loss count
is an artifact of the truncation, not evidence of durable loss.

## Confirmed instances

- **Genuine**: test19 `durable_loss=8 late_ok=4` at 119s (1 of 32 failing);
  test4 `durable_loss=8 late_ok=14` at 120s (1 of 32 failing).
- **Artifact**: test1 `durable_loss=8 late_ok=0` at **240s/240s**, 31 of 32
  failing. A clean `MXFS_FORCE_PREP=1` re-prep immediately followed by the same
  criterion returned **PASS 32/32 durable_loss=0 late_ok=14 at 116s**.

## What caused the artifact, and how to avoid manufacturing it

Residual cluster state from harness runs that an outer `timeout` had killed
mid-iteration. The token differential on the artifact run named the straggler
directly — all ONLY-LOSER or extreme on the stalled node:

    P-ACQ-STUCK 3 (peers 0)      P1-AGWAIT 110  (x27.8)
    P128-INACT-DEFER 153 (x154)  P-DIRFLUSH 773 (x24.2)
    P-BLOCK0-CONVGATE 61 (peers 0)   P-IGET-ENOENT 54 (peers 0)

and, inversely, it had done NONE of the ordinary eviction work its peers did
(`EVICT-RING-FLAG` 0 vs median 33, `P128-REARM-UNPUB` 0 vs 17,
`P-EVICT-RESULT` 0 vs 2). A node that is stuck on acquires and doing 20x the
flush work is a straggler, not a coherency failure.

**Rule: after killing any harness mid-run, `MXFS_FORCE_PREP=1 ./run.sh N caw
prep_cluster` before believing the next red.** And when a differential shows the
"losing" node elevated across MANY unrelated probes at once (flush, AG wait,
inactivation defer) rather than on one specific path, suspect a straggler; a
real producer shows up as a departure on a narrow set. Compare: the genuine
test4 loss put P6-MIDTENURE-RELOAD-SKIP at 17.4x with almost nothing else moving
in that direction.
