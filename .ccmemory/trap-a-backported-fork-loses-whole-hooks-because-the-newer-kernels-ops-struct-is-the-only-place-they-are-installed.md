---
name: trap-a-backported-fork-loses-whole-hooks-because-the-newer-kernels-ops-struct-is-the-only-place-they-are-installed
description: TRAP (s137/s138): MXFS forks 7.1 XFS and builds for 6.8; four separate mechanisms existed in the source, were installed only in an ops struct 6.8 do…
metadata:
  type: feedback
tags: [compiler, backport, kernel-version, integrity, class]
---

# A backported fork loses whole hooks, not lines

MXFS is a fork of upstream 7.1 XFS built for 6.8. Every VFS or iomap hook that
moved between those versions is a place where the fork can carry the NEWER
mechanism, gate it behind `#if LINUX_VERSION_CODE >= KERNEL_VERSION(x, y, 0)`,
and drop the one this kernel actually calls. The function is then present,
correct, and referenced by nothing — so the compiler deletes it and the
mechanism is **absent from the shipped module**, not merely unreached.

Four of these were found in one week, all by asking gcc and none visible in any
amount of source reading:

| mechanism | installed only in | what 6.8 calls instead |
|---|---|---|
| authority gate's buffered-data arm | `xfs_writeback_submit` (6.17+ ops) | `xfs_prepare_ioend` |
| iomap mapping revalidation | `iomap_write_ops` (6.15+) | `iomap->folio_ops` |
| lazytime timestamp completion | `inode_operations.sync_lazytime` (6.19+) | `super_operations.dirty_inode` |
| delalloc release scan | n/a — a compat macro replaced the whole function | `iomap_file_buffered_write_punch_delalloc` |

Three of the four are integrity defects: buffered writeback ungated on a node
whose authority closed; buffered writes never revalidating a cached extent map;
a lazytime timestamp `fsync()` reports as persisted and never writes.

## How to find them

`tools/warn_sweep.sh` — `defined but not used` is the compiler naming a whole
function it dropped. It replays each object's recorded compile command with
`-o /dev/null`, so it never relinks and is safe against a live rig.

## The three traps inside the trap

- **Initialisers do not mean "used".** `xfs_vn_sync_lazytime` had FOUR
  `.sync_lazytime = …` lines and was still reported unused — every one of them
  sat inside the same version guard. Counting references with grep answers the
  wrong question; the compiler answers the right one.
- **A compat struct defined to make the fork compile will happily stay empty.**
  `xfs/xfs_platform.h` defines a fake `struct iomap_write_ops` for < 6.15 so the
  fork builds, and the macro that calls `iomap_file_buffered_write()` then
  *expands the argument away* because the older prototype has nowhere to put it.
  Both halves look deliberate in isolation.
- **Half a mechanism is the tell.** `iomap->validity_cookie` was stamped on
  every mapping and read by nobody. When one half of a pair is wired and the
  other is not, the wired half is doing nothing.

## Where to look next in this fork

Any `#if LINUX_VERSION_CODE >= KERNEL_VERSION(…)` around an ops-struct member,
and any compat shim in `xfs/xfs_platform.h` that replaces an upstream FUNCTION
rather than renaming one. The second class is worse: a macro that reduces a
careful upstream algorithm to a one-liner reads as a port and is a behaviour
change. `iomap_write_delalloc_release` was
`do { if (punch) (punch)(inode, start, (end)-(start), iomap); } while (0)` in
place of a page-cache scan whose entire purpose was to NOT punch the parts that
are still dirty.
