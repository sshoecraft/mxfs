---
name: trap-a-refused-mount-unwind-has-nothing-to-write-so-its-zero-is-not-a-measurement-of-the-gate
description: TRAP (s92): the mount-failure unwind counted zero post-detach submissions AND zero on the positive control — the refused mount had nothing to write a…
metadata:
  type: feedback
tags: [harness, measurement-integrity, mount-unwind, authority-gate, positive-control]
---

# A refused mount's unwind writes nothing, and a zero there measures the staging

## What happened

`tests/authtail_mount_unwind.sh` lap s92 (0.89.24, 2/tcp) reached the
mount-failure unwind exactly as designed — `P240-QUAR-IMPORT` then
`P240-QUAR-ADMIT-DENY`, mount rc=32 in 9 s, `mounted=0` — and counted **zero**
`P291-AUTH-META-DETACHED`. That looks like the gate arm being unreachable.

It was not. The lap's POSITIVE CONTROL (`P291-AUTH-TAIL-ADMIT`, which the
already-converted log arm emits for any post-detach submission) was **also
zero**, so the window never opened. The refused mount had nothing to write:

- Its own log slice was clean — `adopted log slice (fresh disklock claim)`,
  `P309-LOGTAIL ... clean=1`, no `Starting recovery` — so the AIL was empty
  when `out_unmount` ran.
- The one metadata write the unwind's quiesce would otherwise make is
  suppressed **by name**: `MXFS: P960-REFUSED-MOUNT-NOCOVER slot=%u — the mount
  never completed; its quiesce writes no SB summary and takes no cluster lock
  for one` (`xfs/xfs_log.c:2367-2372`, gated on `!mp->m_mxfs_mount_complete`).

## Why the path looked promising and still is

`out_unmount` (`pal/linux/xfs_super.c:5203`) detaches the DLM at `:5207` and
calls `xfs_unmountfs` at `:5234`, and `xfs_log_quiesce`
(`xfs/xfs_log.c:2321-2334`) runs the log force, `xfs_ail_push_all_sync` and
`xfs_buftarg_wait` AFTER that detach — unlike `put_super`, which drains before
it. The window is real. The staging just gave it an empty AIL.

## The lesson

A teardown-path measurement needs its staging to have produced the population
being measured, and the only thing that proves it did is a positive control
emitted from the SAME window by a path already known to work. Without one,
"zero" and "the window never opened" are the same number. Design the control in
from the start and FAIL the lap on a zero control rather than reporting the
measurement.

Corollary specific to this filesystem: a mount that never completed is
deliberately mute. To make its unwind write anything, the staging has to give
it a dirty log to recover — that is where `out_unmount`'s own comment says this
mount's writes come from ("unlinked-inode processing at minimum",
`xfs_super.c:5211-5214`).
