---
name: trap-directory-scoped-coherency-fixes-silently-skip-regular-files-with-btree-extent-maps
description: TRAP (D-0973, 0.87.4): reload bmbt eviction, iread FUA refresh and the bmbt tenure write gate were all S_ISDIR-gated; a regular file's btree fork got…
metadata:
  type: feedback
tags: [D-0973, bmbt, reload, coherency, regular-file, trap, detector]
---

# Directory-scoped coherency fixes silently skip regular files with btree extent maps

The zero_silent_loss campaign (sess59-sess68, sess4 46efd8b6) built every
extent-map coherency fix for the storm DIRECTORY and gated each on `S_ISDIR`:

- the reload's cached-bmbt eviction (`mxfs_dir_evict_bmbt_blocks` +
  `mxfs_dir_evict_bmbt_by_root` inside `mxfs_dlm_reload_inode`);
- the iread-time FUA refresh of a stale cached leaf (`xfs_iread_bmbt_block`,
  P34B/P68 in xfs_bmap.c);
- the bmbt tenure write gate (`mxfs_buf_xfsaild_skip_bmbt_write`).

None of them is directory-specific in substance. A regular file whose data fork
goes BTREE (a sparse file extended by two nodes; aligned O_DIRECT writes at
random offsets in 1 MiB reach it) got none of them. Measured on 2/tcp
(tests/dio_write_conversion_deadlock.sh EXTEND=1): the node that reloaded kept
its pre-reload 15-record leaf, so 3620 of 3635 writes failed EFSCORRUPTED
(P59-IREAD-MISMATCH), and its inode flushes — `mxfs_iflush_force_bmbt_durable`
destages EVERY cached bmbt block the inode owns, clean ones included, and IS
file-inclusive — wrote that leaf over the peer's while publishing the peer's
di_nextents (1818 torn flushes). It had never been seen because every earlier
multi-node lap on regular files used EXTENTS-format files.

What to do with this:
- When a coherency mechanism is gated on inode type, ask what the other types
  do on the same path. The write side here was file-inclusive while the
  read/invalidate side was dir-only — the asymmetry is the bug.
- A regular-file workload that reaches BTREE format is needed to exercise any
  extent-map coherency: EXTEND=1 on a sparse span, EXTSPAN for multi-leaf and
  two-level trees.

Companion detector trap from the same lap set: P63-TORN-FLUSH,
P63-INSERT-DESYNC and the P64 rebuild all read "if_broot numrecs == 1" as
"single leaf". That holds only when the root is LEVEL 1; a level-2 root with one
pointer names an interior node over many leaves (the root overflows at ~11-20
children). On a two-level file tree the torn-flush detector reported 42 false
tears and the insert detector printed on every insert (5791 lines / 90 s,
unratelimited). Check `bb_level == 1` wherever a one-record root is meant to
mean one leaf.
