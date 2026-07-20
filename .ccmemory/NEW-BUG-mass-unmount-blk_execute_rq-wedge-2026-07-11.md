---
name: NEW-BUG-mass-unmount-blk_execute_rq-wedge-2026-07-11
description: NEW, previously-uncharacterized bug: simultaneous clean-unmount of all 32 nodes wedged 21/32 D-state in blk_execute_rq (block layer, not xfs_buf_iowa…
metadata:
  type: project
tags: [new-bug, unmount, blk_execute_rq, caw, block-layer, unconfirmed-root-cause]
---

## What happened

2026-07-11, discovered incidentally while cleanly unmounting the 32-node
CAW cluster (build v0.10.61 / 65CA8C4E) after the SB-counter recheck (see
`sb-counter-recheck-2026-07-11-live-drift-confirmed`). Cluster was healthy
and idle (no active test workload, no wedge, no prior corruption — this
was a fresh mkfs'd cluster that had only run `precond_readiness` + a light
2-node inode churn test). Issued a plain coordinated unmount:
`umount /mnt/shared` on all 32 nodes in parallel (simple loop, backgrounded
per-node SSH calls, no fanciness — NOT via run.sh's own teardown path).

## Result: 21 of 32 nodes wedged D-state, ALL on the exact same two-thread signature

On each of the 21 affected nodes (1,2,3,4,6,11,12,14,15,17,18,19,20,22,23,
25,26,27,29,30,32 — roughly two-thirds of the cluster):
```
   <pid> D    blk_execute_rq           mxfs-worker
   <pid> D    blk_execute_rq           umount
```
Both the `umount` process itself AND a kernel `mxfs-worker` thread stuck in
`blk_execute_rq` — a block-layer function for a synchronously-dispatched
request (used for management/passthrough-style SCSI commands, NOT regular
buffered filesystem I/O — that would show `xfs_buf_iowait` or similar,
which is the signature of the OTHER, already-well-characterized wedge
family this project has been chasing for weeks). **This looks like a
different mechanism** — something at the block/SCSI dispatch layer,
possibly: the CAW disklock heartbeat/slot-release path issuing a final
compare-and-write or similar command as part of unmount's cluster-leave
sequence; a PR (persistent reservation) unregister command; or multipath
failover/path-verification thrash triggered by 32 simultaneous
cluster-leave events hitting the shared LIO/SCST target's command queue
at once. NOT diagnosed further this session — this is a hypothesis list,
not a finding.

The other 11/32 nodes unmounted cleanly with no issue.

## Recovery

D-state cannot be killed (SIGKILL has no effect on an uninterruptible
in-kernel wait). Recovered by power-cycling the 21 affected test VMs
(`virsh destroy` + `virsh start` — permitted for test VMs per project RULE
2; never the host). All 32 came back clean after ~20s settle.

## Why this matters / next steps for whoever picks it up

This was found by accident, doing something the existing test suite may
never have specifically exercised: **unmounting all N nodes at
(approximately) the exact same instant**, outside of any active create/rm
workload. The existing `dir_reuse_coherency`/wedge investigation history
is all about hangs DURING active create/rm churn under a held directory
lock — this is a different trigger (mass simultaneous cluster-leave at
idle) and a different stuck function (`blk_execute_rq` vs `xfs_buf_iowait`).
Worth determining:
1. Is this reproducible on-demand (repeat the same "unmount all N nodes in
   parallel" against a fresh idle cluster a few times)?
2. Does it scale with N (does a 2-node or 8-node simultaneous unmount also
   wedge, just less often, or is 32-way simultaneity required)?
3. What is `mxfs-worker` actually doing at the point it wedges — kernel
   stack via `/proc/<pid>/stack` or a kprobe on `blk_execute_rq` callers
   would settle whether this is CAW slot-release, PR unregister, or
   something else (RULE 4: instrument before hypothesizing further).
4. Does `run.sh`'s own TEARDOWN path (which does staggered/sequential-ish
   per-node teardown with retries, not a bare parallel loop) already avoid
   this, or does it have the same exposure and nobody's noticed because
   suite runs rarely tear down all N nodes at the exact same wall-clock
   moment outside of a `run.sh` invocation?

Flagging as a standalone new-bug note rather than folding into the
existing dir_reuse wedge investigation because the signature (stuck
function, trigger condition, affected-node fraction) doesn't obviously
match anything in that history — treat as unconfirmed-root-cause and
distinct until proven otherwise.
