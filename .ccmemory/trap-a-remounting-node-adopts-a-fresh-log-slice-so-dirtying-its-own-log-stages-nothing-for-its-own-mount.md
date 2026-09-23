---
name: trap-a-remounting-node-adopts-a-fresh-log-slice-so-dirtying-its-own-log-stages-nothing-for-its-own-mount
description: TRAP (s95): staging a node's own dirty log to give its next mount recovery work produces "Ending clean mount" — MXFS claims a NEW slot and adopts a f…
metadata:
  type: feedback
tags: [staging, recovery, disklock, mount, harness]
---

# A node does not recover its own dirty log at its next mount

## What was staged, and what happened

To give a mount's AIL something to hold, `tests/authtail_mount_unwind.sh` s95
dirtied test1's own log: 48 inodes opened, unlinked while open and `sync`'d (a
durable on-disk unlinked list), 2000 unsynced creates, then
`XFS_IOC_GOINGDOWN` with `XFS_FSOP_GOING_FLAGS_NOLOGFLUSH`, then `umount`.
The expectation was that test1's next mount would recover that log inside
`xfs_mountfs` — the mount unwind's own comment says the log carries "this
mount's writes (unlinked-inode processing at minimum)".

The next mount printed:

```
disklock: claimed heartbeat slot 2 for node 897001145 (attempt 0, fresh claim — slice ADOPTED)
P-SLIFE slot=2 slice=2 before=INIT_REQUIRED after=READY zeroed_bytes=66781184
per-node log slice 2/32 offset=52244616 bblks=130432
XFS (sda): Mounting V5 Filesystem ...
adopted log slice (fresh disklock claim) — image records in prior dirty content will not be re-applied
...
XFS (sda): Ending clean mount
```

`Starting recovery` count 0. The AIL was empty at the admission commit.

## Why

MXFS gives each *incarnation* a journal slice out of the disklock slot table.
A node that comes back does not reclaim its previous slot and slice — it makes
a **fresh claim**, and a freshly claimed slice is zeroed through the FUA path
before the log is mounted (`P-SLIFE-ZEROING` / `P-SLIFE-READY`). The dirty
slice of the previous incarnation is a *foreign* slice from the new mount's
point of view, and it is recovered by whoever fences that dead incarnation —
in s95 the surviving peer, which printed

```
MXFS mount recovery: slice slot=0 is being recovered by another survivor — waiting for completion
P233-MPHASE-RESOLVED-ELSEWHERE slot=0 ... a survivor completed this slice's recovery while this mount waited
```

so the mounting node replayed nothing at all (`barrier complete: ...
replayed=0`).

## What to do instead

Dirty metadata inside a specific mount has to be **foreign dirt that this mount
is the only candidate to replay**:

- stage the dirt on the PEER, shut it down forced, unmount it — its slot stays
  ACTIVE over an unreplayed slice and its heartbeat stops with it;
- make sure **no survivor exists**: unmount the measured node FIRST, while the
  peer is still healthy (also the cheap ordering — unmounting a survivor inside
  a peer-death window costs the whole window);
- then mount the measured node. It pays the dead-confirmation window, fences,
  replays the peer's slice, and runs the deferred unlinked-inode sweep that
  `mxfs_dlm_mount_recovery_settle` schedules.

The discriminator for "did this mount actually replay something" is
`P163-RECOVERED` and the `replayed=` field of `MXFS mount recovery barrier
complete`, NOT `Starting recovery` — that line is about the mount's own log and
is expected to be absent.
