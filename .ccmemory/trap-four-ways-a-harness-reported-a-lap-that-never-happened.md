---
name: trap-four-ways-a-harness-reported-a-lap-that-never-happened
description: TRAP (sess570): four distinct instruments each reported success for work that never ran — stale build, stale dmesg, substring grep, an over-long syml…
metadata:
  type: feedback
tags: [trap, harness, sess570, vacuity, mis-reporting]
---

# Four ways one session's instruments reported laps that never happened

All four failed silently and in the direction of **good news**. None produced an
error. Each was caught only by going to a different source of truth.

## 1. The nodes were running a different build

`d0944_death_rejoin_ab.sh` re-prepped only when a node was unmounted or the knob
differed. After a rebuild the nodes still ran the OLD module, so no prep fired,
the inner harness failed its own "both nodes mounted with the tree build"
precondition, and **twelve laps completed in 102 seconds** reporting identical
numbers.

**Rule:** the srcversion the nodes are running is part of readiness, not a
detail. Compare `cat /sys/module/mxfs/srcversion` on every node against
`modinfo mxfs.ko` before every lap, and prep when they differ.

## 2. dmesg is a ring buffer, and a module reload does not clear it

Counting `ATOMIC-SKIP` from a node's whole `dmesg` gives a number cumulative over
every lap since the node last **booted** — a prep's module reload does not reset
it. Six laps reported `atomic_skips=19`, all of it from earlier laps.

**Rule:** stamp a marker into `/dev/kmsg` at lap start and read
`dmesg | sed -n '/MARKER/,$p'`. Every harness in this tree already does this;
drivers that wrap them must too.

## 3. `mount_rc=` is a substring of `umount_rc=`

`grep -o 'mount_rc=[0-9]*' | head -1` matched inside the `INFO UNLOAD
umount_rc=0` line printed just before the `REJOIN mount_rc=32` line. Every lap
read as success. Five control laps that had failed at rc=32 were reported clean.
Anchor it: `sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p'`.

## 4. The workload was rejected and the stage still passed

A completeness probe created 40 symlinks with 3000-character targets to force a
REMOTE target block. `XFS_SYMLINK_MAXLEN` is **1024**, so every `ln -s` failed
ENAMETOOLONG, zero symlinks existed, and the stage reported PASS — "no
unauthorized image was logged" is trivially true when nothing was logged.

**Rule:** a stage must report what it actually PRODUCED, not that it ran —
`made=`, `links=`, `extents=`, `attrs_on_xa0=`, `entries_in_d0=` — and the
assertion must read those. A negative result from a stage that made nothing is
not evidence.

## The shape

Every one of these is the same defect in different clothing: **an instrument
that cannot distinguish "the condition is absent" from "the condition was never
created."** When a fix arm comes back clean, the first question is not "is the
fix good" but "did this lap do the thing at all" — and the harness has to answer
it from its own output, not from the reader's memory of what it was supposed to
do.
