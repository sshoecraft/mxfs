---
name: technique-hold-xfsaild-cluster-write-after-copy-in-to-make-a-platter-lag-race-deterministic
description: TECHNIQUE (sess605, D-0963): a race between xfsaild's async inode-cluster write and a coherent platter read is made deterministic with dbg_iflush_pau…
metadata:
  type: feedback
tags: [D-0963, harness, xfsaild, technique]
---

# Make a "lagging flush" race deterministic instead of hunting it

Context: D-0963. The board criterion reproduced the resurrected-dirent defect once
(1 of ~5 laps on a busy board) and then 0 of 40 laps on a quiet rig, with the fix
off. The mechanism needed xfsaild's write of a directory inode to be IN FLIGHT
across one removal's platter refresh and landed by the next — a window of a few
ms that log pressure on a busy board opens and a quiet rig never does.

Three test knobs (0.84.18) turn it into a scripted sequence on the real path:

- `mxfs.dbg_ail_pin_ino=<ino>` (existing): xfsaild never flushes that inode, so the
  platter keeps the pre-churn image while the in-core fork churns (base stays old).
- `mxfs.dbg_iflush_pause_ino=<ino>`, `dbg_iflush_pause_ms`: xfs_inode_item_push
  sleeps AFTER xfs_iflush_cluster copied the image into the (locked) cluster buffer
  and BEFORE it is queued for write — the in-flight state, held as long as needed.
  Counter `dbg_iflush_pause_n` proves it fired.
- `/sys/kernel/debug/mxfs/<dev>/ail_push`: any write calls xfs_ail_push_all, i.e.
  starts the flush on demand (sync(2) does NOT push the whole AIL in this tree —
  its push is per-AG and bounded).

Harness shape: unpin, arm the pause, kick, wait for `dbg_iflush_pause_n>=1`, do the
operation that must see the OLD platter, wait past the pause, do the operation that
must see the NEW (own, lagging) image. `tests/d0963_sf_lagging_flush.sh` reproduced
the defect 3/3 with the fix off and 3/3 clean with it on, in under a minute.

Also learned: `sf_fastpath_adopt` was a bare int with no module_param — a lever the
code documents as an A/B is not usable by a harness until it is exposed.
