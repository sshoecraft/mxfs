---
name: trap-a-background-holders-sleep-child-inherits-its-open-descriptors-and-keeps-the-mount-busy-after-the-holder-is-killed
description: TRAP (s93): killing the fd-holding bash by pidfile left its `sleep` child holding all 48 inherited fds, so the unmount was "target is busy" and the l…
metadata:
  type: feedback
tags: [harness, staging, unmount, unlinked-inodes, process-group]
---

# Killing the holder is not releasing the descriptors

## What happened

`tests/authtail_mount_unwind.sh` lap s93 staged a dirty log by opening 48 files
under `/mnt/shared`, unlinking them while open, and parking the holder:

```
nohup bash -c '
   for i in $(seq 1 48); do exec {fd}> "$d/u$i"; ...; unlink "$d/u$i"; done
   sync; echo $$ > PIDF; touch HELDF
   sleep 900
' "$d" &
```

After `XFS_IOC_GOINGDOWN`, the lap killed the holder by pidfile and verified it
was gone:

```
PASS the unlinked-inode holder released its descriptors (0)   # [ -d /proc/$p ] == 0
STAGE victim unmounted rc=32 still=1
FAIL the victim released /mnt/shared got=1 want=0
umount: /mnt/shared: target is busy.
```

The parent bash really was gone. **`sleep 900` was not.** It is a separate
process that inherited all 48 descriptors at fork, so killing its parent
released nothing — and because the inodes are unlinked, nothing else names them
to find them by.

## Why the check passed anyway

`[ -d /proc/$p ]` asks about the PID in the pidfile, which is the bash. A holder
that forks ANY child — `sleep`, a pipeline, a subshell — has more than one
process holding the fds, and a single-PID liveness check cannot see the others.

## What to do instead

- Put the holder in its own session (`setsid`) so its PID is the process-group
  leader, and signal the GROUP: `kill -TERM -"$pid"`.
- Then assert on the MOUNT, not on the PID: the thing being claimed is "nothing
  holds the mount any more", and only the unmount can establish that.
- A cheap alternative that needs no group signalling: park on a short loop
  (`while [ ! -e RELEASE ]; do sleep 2; done`) so any inherited child is at most
  a couple of seconds from exiting on its own.

## Not a filesystem verdict

The lap ABORTed at its quiesce stage, BEFORE the forge, so nothing was written
to the LUN — but the mount was left shut down and busy, and only `umount -l`
cleared it for the next prep. A staging step that can leave the rig holding a
mount needs its own bounded fallback on the failure path.
