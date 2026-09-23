---
name: technique-read-the-shell-dump-fields-to-identify-what-object-the-defect-needs
description: TECHNIQUE (sess572): three harness modes failed to reproduce D-0946 until the captured shell's own fields (mode=00 nblk=11) said the object was a dir…
metadata:
  type: project
tags: [d0946, reproducer, technique, deadshell]
---

# The failing object's identity is written in the probe you already captured

## The problem

D-0946's shutdown needs `xfs_iget_recycle`'s deferred-deadshell path, whose
entry condition (xfs_icache.c) is an in-core shell that is `XFS_IRECLAIMABLE`,
`nlink == 0`, and `i_mode != 0 || i_nblocks != 0`. Three harness modes ran and
every round reported `DEADSHELL=0`:

- `local` and `peer`, 8 rounds each — vacuous, the pubob arm never even fired
  (a `sync -f` between passes closed the window).
- `tight` with `: > f` — gate fired 40 times, still `DEADSHELL=0`: a zero-length
  file leaves mode 0 AND nblocks 0, so the entry condition fails on both terms.
- `tight` with `fallocate -l 1M` — gate fired, still `DEADSHELL=0`.

## What the captured failure had already said

    P-CR63-SHELL ino=0x84 mode=00 nlink=0 nblk=11 iflags=0x48080004
                 istate=0x60 reclaimable=1 dlm_mode=5 dlm_state=1 stale=0 src=7

`mode=00` — the free had already zeroed it, so the entry condition was satisfied
by the *other* term. `nblk=11`. Eleven blocks.

The workload's file was `fallocate -l 8M`, which at 4K blocks is **2048**
blocks, not 11. Eleven blocks is not that file at all — it is a **directory**
that had outgrown shortform. The object whose free the allocator was racing was
the churn *directory*, removed by the lap's `rm -rf`, not any of the files in
it.

## Why that matters beyond this defect

It converts the reproducer from "inject a log shutdown, kill a node, wait for it
to rejoin" — 3 hits in 16 laps at ~150 s each — into a plain
`mkdir` / fill / `rm -rf` / `mkdir` loop with no sync, no death, no fault
injection and no rejoin.

## The habit

When a reproducer will not fire, do not reach for a bigger workload. Re-read the
one captured instance's own dump and ask what object each field describes.
`nblk` is an identity, not a detail: it says how big the thing was, and a number
that does not match the file you were churning means you were churning the wrong
object.
