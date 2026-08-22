---
name: never-mountpoint-q-on-a-quarantined-mxfs-mount
description: `mountpoint -q` stats the mount root (ino 128, AG 0), so an AG-0 quarantine EIOs it and a healthy mount reads as unmounted. Use /proc/mounts.
metadata:
  type: project
tags: [mxfs, harness-trap, quarantine, rule-6, testing]
---

# `mountpoint -q` lies on a quarantined MXFS mount — use /proc/mounts

Measured sess383, and it cost six bogus FAILs in one matrix run.

`mountpoint -q /mnt/shared` works by **stat()ing the mount root**. On MXFS the
root inode is **ino 128, which lives in AG 0**. Any AG-scoped quarantine whose
mask covers AG 0 makes that stat fail with EIO — *correctly*, that is the
quarantine doing its job:

```
mxfs: P240-QUAR-REFUSE ino=128 mode=5 comm=mount — inode in quarantined
      victim domain; refusing DLM acquire
```

So `mountpoint -q` returns non-zero and a **perfectly mounted filesystem reads
as unmounted**. In the D-513 forged-record harness that produced a clean
cascade of nonsense:

1. the shape's own assertions all PASSED (mount admitted, AG-scoped
   quarantine imported, no shutdown);
2. the cleanup step `mountpoint -q $MNT && umount $MNT; mount ...` skipped the
   umount, so the remount hit `already mounted on /mnt/shared` →
   `REMOUNT_FAILED`;
3. the next five shapes' own start-of-run guard used the same probe, saw
   "not mounted", and refused to run — reported as five more FAILs.

Net: 6 FAIL of 17, **none of them a filesystem defect**. The give-away is a
FAIL whose only evidence is about the *harness's* mount bookkeeping, plus
`umount` succeeding by hand a minute later.

## The rule

Any liveness/mountedness probe in an MXFS harness must read **/proc/mounts**,
which the VFS answers without touching the filesystem:

```sh
is_mounted() { ssh "$1" "grep -qs ' /mnt/shared mxfs ' /proc/mounts && echo YES || echo NO"; }
```

Verified format: `/dev/mapper/mpatha /mnt/shared mxfs rw,relatime,... 0 0`.

The same reasoning applies to **any** probe that touches the filesystem to
decide whether the filesystem is healthy — `ls`, `stat`, `df`, `test -d` are
all EIO-able by a quarantine, a withdraw, or a shutdown, and every one of them
turns "the containment worked" into "the harness failed". `mount | grep`,
`/proc/mounts`, and dmesg are the safe channels.

Note this is NOT a reason to weaken a quarantine's reach. AG 0 holding the
root inode is why an AG-0 refusal is close to fs-wide in practice, and that
is the intended semantics.
