---
name: rig-test19-23-log-ring-drift-fixed
description: RIG: test19-23 booted without log_buf_len=16M (256KB ring, wraps in ~40s) — poisoned ALL dmesg-window scans incl. ag_strand_repair 3-of-5+2/2 FAILs;…
metadata:
  type: project
---

# test19-23 kernel-ring drift (found+fixed sess34)

## Symptom
ag_strand_repair FAIL 27/32, states:FAIL=5 (test19-23 every time,
strands=0 all-zeros), 292-era 3-of-5 history + 2/2 on 293/294. write_ok=1,
repair itself fine on 27 nodes.

## Root (infra, NOT filesystem)
test19-23 booted with GRUB_CMDLINE_LINUX lacking `log_buf_len=16M
loglevel=3` (image/bootcfg drift vs the rest of the fleet — check
osimager lineage). Default ~256KB ring wraps in ~40s under mxfs print
load → the test's `MXFS_AGSTRAND_WINDOW` /dev/kmsg marker is ejected
before the scan → empty window → strands=0 → honest FAIL.

## Blast radius beyond this test
ANY dmesg-window/marker scan on those 5 nodes silently under-reports:
kernel_health, dirent integrity probes, harness kernlog captures
(kernlog_test19 = 1833 lines vs test18 = 105349), and ad-hoc fleet
`dmesg | grep -c` sweeps (sess34's early P236/237/238 sweep undercounted
on 19-23; the ATOMIC counters in P220/P219 dumps are ring-independent —
trust those). journalctl -k retains what the ring loses.

## Fix applied
sed GRUB_CMDLINE_LINUX += ` log_buf_len=16M loglevel=3` on test19-23,
update-grub, guest reboot, re-prep. Verified /proc/cmdline; ag_strand
32/32 PASS (strands=1 repaired=1 on ex-failing nodes). Also scaled
ag_strand rounds with T (sess34 edit, 16→T at T>16) — keep.

## Standing lesson
When exactly-N specific nodes fail a dmesg-scan criterion with all-zero
measurements, CHECK /proc/cmdline + dmesg ring span FIRST (dmesg -s 1 |
wc -c; first-timestamp age) before touching the filesystem.
