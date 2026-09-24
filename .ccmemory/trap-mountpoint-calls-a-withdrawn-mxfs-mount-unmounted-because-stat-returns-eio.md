---
name: trap-mountpoint-calls-a-withdrawn-mxfs-mount-unmounted-because-stat-returns-eio
description: TRAP (0.89.80): a fenced node's withdrawn MXFS mount answers stat() with EIO, so `mountpoint -q` says "not mounted"; prep never unmounts, mkdir fails.
metadata:
  type: feedback
tags: [harness, fencing, mount]
---

After a fence the victim's MXFS mount stays in /proc/mounts but is withdrawn: `stat /mnt/mxfs` returns EIO. `mountpoint -q` stats the path, gets the error and reports "not a mountpoint", so a prep of the form `mountpoint -q $MNT && umount $MNT` skips the unmount, and the following `mkdir -p $MNT` fails with "cannot stat: Input/output error" — two freeze-test laps died in setup this way, reading like a node that could not rejoin.

**How to apply:** detect an MXFS mount with `grep -q " $MNT mxfs " /proc/mounts` (which does not touch the dead filesystem) and unmount with a bounded `timeout 30 umount $MNT`. tests/tcp_peer_freeze_death.sh does this in both its rig and PVE prep. A victim left running with a writer also holds the withdrawn mount busy — kill the writer by its recorded PID before unmounting.
