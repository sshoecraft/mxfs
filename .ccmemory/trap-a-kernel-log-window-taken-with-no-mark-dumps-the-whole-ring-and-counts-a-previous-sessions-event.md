---
name: trap-a-kernel-log-window-taken-with-no-mark-dumps-the-whole-ring-and-counts-a-previous-sessions-event
description: TRAP (s83): window_into with an empty mark runs plain `dmesg`, so a lap counted an LU Reset the PREVIOUS session's probe had issued five hours earlie…
metadata:
  type: feedback
tags: [harness, measurement-integrity, dmesg]
---

# A kernel-log window with no mark is not a window

`window_into <file> <host> <timeout> <mark>` (tests/lib/rig.sh) takes the mark
as an OPTIONAL fourth argument. With a mark it runs `dmesg | sed -n
"/$mark/,\$p"` and **aborts the lap if the mark is absent**. With the mark
omitted or empty it runs a plain `dmesg` — the entire ring since boot.

s83, fence_retire_basis: a new check asserted "MXFS issued no LOGICAL UNIT
RESET on this node" over a mark-less window. It FAILed with 9 hits. All nine
were at uptimes 16548-17580 s; the lap started near 19000 s. They were
`iscsi_eh_device_reset LU Reset` lines from the *previous session's*
`tests/lu_reset_probe.sh`, which deliberately issues one — on a node that had
been through module reloads but no reboot, so the ring still held them. The
module reload does not clear dmesg; only a reboot does, and the whole point of
the surviving node is that it does not reboot.

**Pass the lap's own mark to every window that feeds a count**, and keep the
mark-less form only for "dump everything for forensics". The existing
crash/shutdown checks in these harnesses use the mark-less form too — they get
away with it because a BUG or a shutdown anywhere in the ring is worth failing
on, but a count of a NORMAL operation is not.

Second half of the same lesson: `Power-on or device reset occurred` is a target
UNIT ATTENTION the initiator *reports*, and a node that just rebooted logs one
on its first access to the LUN. A pattern meant to catch "we issued a reset"
must match the issuing side (`iscsi_eh_device_reset`, `LU Reset`) and not that.
