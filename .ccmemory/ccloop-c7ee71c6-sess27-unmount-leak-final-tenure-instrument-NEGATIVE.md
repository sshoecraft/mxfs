---
name: ccloop-c7ee71c6-sess27-unmount-leak-final-tenure-instrument-NEGATIVE
description: sess27: built GPT's final-tenure narrowing for the unmount leak; it MEASURED ITS OWN FAILURE (tenure_grabs=499). Pairing is a dead end; use the owner…
metadata:
  type: reference
tags: [D-UNMOUNT-BUSY-INODES, sess27, negative-result, instrument]
---

# sess27 — the final-tenure instrument, and why it did NOT narrow the leak

## What was built (build 0.11.236, `8A3F18EEAA6BC0B9475F4C1`)

GPT's RULE-5 angle: an inode joins the inode LRU ONLY at `i_count==0` — verified
in `/src/linux/fs/inode.c`, `__inode_lru_list_add()` returns early
`if (icount_read(inode))`. The leaked inode is always `lru_linked=1 icount=1`, so
it provably passed through zero and the survivor belongs to a NEW tenure.

`xfs_fs_drop_inode()` runs from `iput_final()` at exactly that transition, so the
FILESYSTEM CAN OBSERVE IT — no kernel patch needed for this part. Added
`mxfs_inode_tenure_reset()` (xfs_inode.h) called from `xfs_fs_drop_inode`
(pal/linux/xfs_super.c): bumps `i_mxfs_zero_seq`, clears `i_mxfs_grabst[]`, zeroes
`i_mxfs_tenure_grabs`, stamps `i_mxfs_zero_jiffies`. P203-GRABLEVELS now prints
`zero_seq / tenure_grabs / tenure_age_ms` and a verdict string.

Also verified GPT's first check: **the unmount diagnostic does NOT manufacture the
count.** `mxfs_report_leaked_inodes()` walks a list under a spinlock and only
does `atomic_read(&vip->i_count)`; it takes no reference. `icount=1` is real.
Separately, `evict_inodes()` (fs/inode.c:919) skips any inode with
`icount_read(inode)` nonzero — so the survivor is a genuine unreleased reference,
not a sweep bug.

## THE RESULT — the narrowing FAILED, and the probe says so

Reproduced first cycle at 16/caw (test9, ino 8391875, the usual signature:
DIRECTORY, icount=1, dentries=0, hashed=1, lru_linked=1, dlm_mode=3 PR,
dlm_state=1 CACHED, itemp=1, in_ail=0, bastq_src=1, stale_src=2):

    P203-GRABLEVELS ino=8391875 icount=1 over=0 zero_seq=1 tenure_grabs=499
                    tenure_age_ms=57533 lru_linked=1 verdict=MXFS-SIDE

**`zero_seq=1`** — the inode hit `i_count==0` exactly ONCE in its life, 57.5 s
before unmount, and took **499** tracked grabs afterwards without ever returning
to zero. So "the final tenure" is a 57-second, 499-grab window: the LIFO
objection that made the sess25/26 level table unsound is fully back, and
LEVEL[1] is still just "some grab that observed level 1".

This is a genuine negative result, not a broken probe — `tenure_grabs` was added
precisely so a failed narrowing is visible instead of being read as an answer.

## Sites named, and REFUTED on inspection

- `LEVEL[1]`/`LEVEL[2]` = `xfs_lookup+0x170` = `xfs_inode.c:1229`, the return from
  `xfs_iget()`. Already eliminated by source verification in sess26
  (`d_splice_alias` consumes that ref on every path).
- `LEVEL[4]` = `file1:line27181` = `xfs_mxfs_dlm.c:27181`, the ilock-end BAST arm
  that sets `bastq_src = 1` — and the leaked inode reports `bastq_src=1`, which
  looked like a hit. **REFUTED by reading it:** line 27187 does
  `xfs_irele(ip)` on the `queue_work`-returns-false path. It pairs correctly.
  NOTE for the record: this is a *different* site from the `~27113` one sess26
  audited as "src=1"; there are at least TWO sites assigning `bastq_src = 1`,
  the same one-of-two-variants trap sess26 caught with P142. Both are correct.
- `GRAB=file2:line1768` = `xfs_icache.c:1768`, the `igrab` in
  `xfs_iget_cache_hit`'s live-inode branch. Expected and legitimate.

## THE CONCLUSION FOR THE NEXT SESSION

Stop trying to PAIR increments with decrements — every variant of that has now
failed (global balance, refcount-level table, final-tenure scoping). GPT's own
words: *"Do not try to pair generic increments with generic decrements by stack.
Instead ask: which owner object appeared during the final 0->1 tenure and still
contains the inode at unmount?"*

That is the **ownership** question, and it needs track 2: preserve a vmcore or
run **drgn against the LIVE kernel while the leak exists** (the inode survives
the unmount but before `rmmod`, so catch it there — `unmount_leak_check.sh`
currently unmounts AND removes the module before reporting, so it must be split
to leave a window). Reverse-search kernel memory for the inode pointer and
classify the containing object: dentry not represented by the alias count, struct
file, fsnotify mark, work/timer payload, **the MXFS DLM object itself**, aio/
io_uring, or an RCU-retired object. Given `dlm_state=CACHED` and `itemp=1`,
inspect the DLM object and the inode log item's reverse pointers first.
