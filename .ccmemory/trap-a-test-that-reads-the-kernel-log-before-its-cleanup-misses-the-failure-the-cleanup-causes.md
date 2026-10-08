---
name: trap-a-test-that-reads-the-kernel-log-before-its-cleanup-misses-the-failure-the-cleanup-causes
description: TRAP (0.90.102): pve_pair_write_bound.sh took kernel logs, then rm -rf'd its files; pve2 shut down 1 s after PASS in that rm (AG lock -EAGAIN). Check…
metadata:
  type: feedback
---

tests/pve_pair_write_bound.sh captured each host's kernel log and judged it, then removed
the run's files (KEEP=0) and printed PASS. Removing large files frees their extents, which
takes every AG lock they touched — real filesystem work. On the physical DRBD pair
2026-10-07 20:14:54 that removal hit 'DLM AG lock failed: ag=2 rc=-11' inside
xfs_defer_finish_noroll and pve2's mount shut down, one second after the run printed PASS;
the run's own evidence showed nothing, and the shutdown was found only by reading the host's
whole-boot log hours later (auto-rejoin had hidden it).

Rule for any harness here: the cleanup is part of the workload. Capture and judge kernel
logs AFTER cleanup, and assert the mounts are still live at the very end. (Fixed in the
script in 0.90.102.) When auditing a host, read the whole boot's log for P-WITHDRAW /
'Shutting down filesystem' — mxfs-drbd-fence-self rejoins silently.
