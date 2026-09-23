---
name: trap-a-post-mountfs-init-that-zeroes-state-the-mount-barrier-already-wrote-drops-the-barriers-handoff
description: TRAP (sess614, D-FOREIGN-SLICE-INTENTS-ABANDONED): mxfs_dlm_cache_init runs AFTER xfs_mountfs (the barrier) and zeroed m_mxfs_foreign_dead_slots, so…
metadata:
  type: feedback
tags: [mount, barrier, reap-worker, ordering, trap, obligation]
---

# A post-mountfs initializer that zeroes state the barrier already wrote

## What was measured (s614b, tests/evidence/20260913T042107Z_intents2tcp_s614b, dmesg_test1.txt)
The mount recovery barrier (inside xfs_mountfs) met an OPEN obligation case for a
taken-over slot and recorded the handoff: `P-OBL-BARRIER-OPEN slot=1`, dead bit set,
REAPF_FREPLAY armed.  `pal/linux/xfs_super.c` then called `mxfs_dlm_cache_init(mp)`
AFTER xfs_mountfs, and that function did `bitmap_zero(m_mxfs_foreign_dead_slots)`.
At the 20 s mount-settle the reap worker found the dead set empty, cleared the
replay duty (`bitmap_subset(dead, torn)` on two empty sets is true), and ran the
orphan sweep with `dead_slots=0x0` straight into the case's frozen AG:
`P-OBLF-AG-WAIT` → `P-OBLF-AG-TIMEOUT` after 120 s, twice, kworker in D state
with a hung-task report, and the engine never printed `P-OBL-ENGINE-START`.

## The rule
- An initializer that runs after a phase which legitimately writes the same
  state must not re-zero it.  Check the call order in xfs_super.c
  (`mxfs_defer_reap_init` BEFORE xfs_mountfs, `mxfs_dlm_cache_init` AFTER) before
  handing anything from the barrier to a post-mount worker through mount fields.
- `struct xfs_mount` is kzalloc'ed; a bitmap_zero in a later init is not
  "initialization", it is a discard.
- The reap worker's guard "no sweep while any dead slot is pending" only protects
  what is still IN the dead set; anything that empties the set silently opens the
  sweep onto frozen AGs.  A sweep blocked on a freeze is the symptom, never the
  cause: look for who emptied the set.

## How it hid
The live replay path (a death observed by the monitor after mount) never goes
through this window; only a case first met INSIDE the mount barrier does, and
the first lap that reached that state was s614b.
