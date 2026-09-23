---
name: trap-an-inobt-record-corruption-line-after-a-pick-is-the-allocator-naming-a-hole-decode-holemask-before-hunting-a-stale-write
description: TRAP (sess572→615, D-0948): the evidence held "start inode 0x41f1c0, count 0x20, freemask 0x…fffe, holemask 0xff" 15 ms before the shutdown; three se…
metadata:
  type: feedback
tags: [D-0948, allocator, sparse-inodes, holemask, evidence, trap]
---

# Decode the inobt record before hunting a write that put a directory image back

## What the evidence said all along (tests/evidence/sess572_agino_provenance/evidence.txt:172-173)
```
XFS (sda): inobt record corruption in AG 0 detected at xfs_inobt_check_irec!
XFS (sda): start inode 0x41f1c0, count 0x20, free 0x1f freemask 0xfffffffffffffffe, holemask 0xff
```
printed 15 ms after the carve and immediately after the pick. Decoded:
- `count 0x20` + `holemask 0xff` = a SPARSE record; holemask bit i covers offsets 4i..4i+3, so
  offsets 0-31 are HOLES (never carved) and 32-63 are the real inodes.
- `freemask 0x…fffe` = offset 0 was just marked allocated — inside the hole. That is what the
  kernel's own record check flagged, and it is the whole defect: the pick handed out an inode
  number whose "home" block was never part of the chunk. The block belonged to a live directory,
  so the create read XDD3 where it expected an inode cluster and the dirty transaction shut down.
- The carve's FUA init and read-back (P948-SYNCINIT-READBACK-OK) were fine: they cover the
  carved half. chk_mxfs found no aliasing because its chunk bitmap honours the holemask and the
  directory block was allocated, not free.

Three sessions read the shutdown as "a stale cached directory buffer written back over a fresh
inode cluster" (the P93-REVERT-CLOBBER class) and instrumented the carve and the writeback path.
The cause was `mxfs_dialloc_pick_in_rec` (xfs/libxfs/xfs_ialloc.c) walking `ir_free` without
masking `xfs_inobt_irec_to_allocmask()`; upstream's `xfs_inobt_first_free_inode` masks it. A
sparse record stamps `ir_free = ALL_FREE`, so every hole bit reads as a free inode.

## Rules
- When the kernel prints an inobt/finobt record right before a failure, decode
  startino/count/holemask/freemask arithmetic FIRST. `count < 64` means sparse; a cleared free
  bit under a set holemask bit is a pick inside a hole, and nothing on the platter is wrong.
- A verdict of "no magic at the home" or "foreign metadata at the home" on a candidate is not
  evidence about the platter until the candidate is shown to be a carved inode: check the
  record's holemask for that offset.
- Any MXFS code that walks `ir_free` (candidate picks, re-picks, validators, chunk-free scans)
  must mask holes; the 0.85.3 pick fix carries exact counters `dialloc_holemask_n` /
  `dialloc_holepick_n` and the control knob `dbg_dialloc_pick_holes`.
- The later s574dv lap's 398/702 failed creates with "P-CR62 … disk_di_mode=0177777
  verdict=disk-read-err/badmagic" and 26501 quarantine refusals on a 1M-fallocate churn are
  the same shape seen through the validator (a hole candidate's home read as garbage), not the
  D-0947 "un-destaged chunk" explanation the harness comment gave them.
