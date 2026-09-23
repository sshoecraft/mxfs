---
name: trap-a-knob-set-before-the-churn-is-gone-by-the-rmmod-insmod-later-in-the-same-lap
description: TRAP (sess571): I set a knob on the live mount, the lap then rmmod+insmod'd, and the operation under test ran at the default — ten laps void, all rep…
metadata:
  type: feedback
tags: [knob, harness, void-experiment, d0946]
---

# A knob set on the live mount does not survive the lap's own module reload

## What happened

Testing whether eager publication of an inode free contains D-0946, I added
`MXFS_PRECHURN_KNOBS` to `agmeta_shutdown_retire.sh` — it writes the sysfs
parameter on the live mount immediately before the churn and reports the value
**read back**. All ten laps printed `ifree_eager_durable=1`. The defect
reproduced anyway, and I wrote that up as a negative result that "eliminates the
most attractive fix".

It eliminated nothing. The lap ordering is:

1. prechurn knob → 1
2. churn + injected death
3. umount + **rmmod**
4. **insmod** ← every module parameter back to its compiled default
5. mount
6. `rm -rf $D` ← **this is the free under test**, running with the knob at 0

The operation whose durability the whole experiment turned on ran at the default
on every single lap. I had placed the knob correctly relative to the *churn* and
never asked what else in the lap mattered.

## How it was caught, and how it hid

- `/sys/module/mxfs/parameters/ifree_eager_durable` read **0** after the run.
- `P9-INSTR ifree DONE ... flushed` is printed **unconditionally** at the end of
  the eager block and appears **zero** times.
- The near-miss: `P137-IFREE-TIME` was also zero, and I nearly took that as the
  proof — it is gated on the block exceeding 10 ms, so zero proves nothing.
  **Pick the unconditional probe, not the convenient one.**
- The evidence dirs could not have shown it anyway: every dmesg capture in that
  harness closes before step 6, so the closing free was outside every window.

## The rules

1. **"Read back = 1" proves the write landed, not that it was in force when the
   operation ran.** Ask where in the lap the operation under test actually is,
   and what the lap does to the module in between.
2. **Any rmmod/insmod resets every module parameter.** A knob that must span it
   has to go on the insmod line. `agmeta_shutdown_retire.sh` now takes
   `MXFS_EXTRA_INSMOD_PARAMS` for that; set BOTH it and `MXFS_PRECHURN_KNOBS`
   when a knob must hold for a whole lap.
3. **An operation with no dmesg window is unfalsifiable.** The closing `rm -rf`
   now opens its own marker and emits `CLOSINGFREE-MEASURE ... eager_done=N
   drain_bound=N inact_defer=N ifree_eager_durable=N`, so a lap states whether
   the path under test was even in force.

## Also learned from source while chasing it

`mxfs_ifree_eager_durable` is **not** a publication guarantee even when it does
run: its AIL drain is bounded by `mxfs_ifree_drain_ms` (default 200) and on
expiry it only warns `P-IFREE-DRAIN-BOUND … deferring to BAST drain pipeline`
and proceeds (`xfs_inode.c:5108-5113`). Its own comment says cross-node dinode
durability is guaranteed by the Phase-2 BAST drain, not by that path. It does
end with `xfs_buftarg_wait` + `blkdev_issue_flush`, so a *successful* bounded
drain should land the dinode.

## Family

Same family as the recorded traps about a knob not surviving a board prep, and
about a fix landing outside the A/B knob. All three share one shape: **the arm
you believe you are running is not the arm that ran.**
