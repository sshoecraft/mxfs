---
name: trap-the-iflush-pause-knob-misses-cluster-passengers-and-holds-xfsailds-whole-delayed-write-list
description: TRAP (sess610, D-0346): dbg_iflush_pause_ino fires only when xfsaild pushes THAT inode (a same-cluster sibling's push carries it unpaused) and the sl…
metadata:
  type: feedback
tags: [D-0346, harness, xfsaild, dbg_iflush_pause_ino, technique]
---

# Two ways the iflush-pause knob silently fails to open a window

Context: making D-0346's window deterministic (creator's new dinode must stay
undestaged while the reader looks). Two vacuous ten-round laps before it worked.

1. **Keyed on the pushed inode, not on the cluster.** The check sits in
   xfs_inode_item_push after xfs_iflush_cluster and compares `ip->i_ino` of the
   item xfsaild is pushing. When the parent directory (dirtied by the same mkdir)
   shares the child's inode cluster and is pushed first, the child's image is
   copied in as a passenger and written unpaused; the child's own push then finds
   nothing to flush. s610a: pause_n=0 on every round. Fix in the harness: pad the
   parent with 64 files so the child's number lands in another cluster.

2. **The sleep holds xfsaild's whole delayed-write list.** The paused push happens
   inside the AIL push loop; buffers already queued (the parent's cluster write)
   are submitted only after the loop returns. A release drain on that node that
   waits for its own in-flight flush (P2D-DRAINWHY ... flushing=1 delwri=1) waits
   out the pause, so the parent's dirent and the child's dinode land together and
   the window never opens. s610b: pause_n=1 every round, drain_ms=2537, the reader's
   first read already saw the new image. Fix in the harness: pin the child off
   xfsaild (dbg_ail_pin_ino) for one ail_push kick so the parent lands, then unpin,
   arm the pause, kick again.

Also learned: the pin knob is honoured inside xfs_iflush_cluster too, and the
release drain calls xfs_iflush_cluster (xfs_mxfs_dlm.c:8427, 21948), so a pinned
inode cannot be destaged by a BAST drain either — a pin left armed across the
peer's coordination makes the fix look broken.
