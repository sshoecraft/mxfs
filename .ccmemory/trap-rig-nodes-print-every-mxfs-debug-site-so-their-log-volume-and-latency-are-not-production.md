---
name: trap-rig-nodes-print-every-mxfs-debug-site-so-their-log-volume-and-latency-are-not-production
description: TRAP (0.90.57): tests/setup/prep_node.sh loads mxfs with dyndbg=+p (1591/1593 sites on): a rig node logged ~165k lines in 4 min of I/O. Never read it…
metadata:
  type: feedback
tags: [rig, dyndbg, kernel-log, measurement]
---

**What happened (2026-10-06, 0.90.57 on the 2/net/mesh/drbd rig pair test1/test2):** after a few minutes of
`tests/drbd_vmimage_contention.sh`, test1's `dmesg` held 190,001 lines, ~165k of them written during the run:
`mxfs: iomap addr` 64k, `mxfs: buf_io R/W daddr` 12k, `P71-HOLD`, `P239/P240/P241` authority lines, etc.  It looked
like the kernel-log flood the user complains about on the physical PVE pair.

**Why it is not:** `tests/setup/prep_node.sh` (the rig's module load, used by run.sh prep and `drbd_rig.sh mxfs`)
passes `dyndbg=+p` in MODARGS for both transports, so every `mxfs_probe`/`pr_debug` site prints.  Measured:
`awk '$2 ~ /^\[mxfs\]/ {n++; if ($3 == "=p") p++}' /proc/dynamic_debug/control` → 1593 sites, 1591 enabled.
A `make install` / package node loads mxfs with no dyndbg: those lines do not print there.

**How to apply:**
- Never cite a rig node's kernel-log volume as production behavior, and never compare rig I/O latency or IOPS with a
  production node's without saying the rig prints a line per iomap call.  Measure log volume on a node loaded the
  way users load it (physical PVE pair, or a rig node after `echo "module mxfs -p" > /proc/dynamic_debug/control`).
- Conversely, on the rig any probe line DOES print, so a missing probe there is real absence (if the run's window
  was read correctly).
- Count flags with awk on field 3, never `grep '=p'` (see trap-grep-equals-p-on-dynamic-debug-control-...).
