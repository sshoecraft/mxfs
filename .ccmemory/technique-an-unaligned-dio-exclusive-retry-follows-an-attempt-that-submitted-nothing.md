---
name: technique-an-unaligned-dio-exclusive-retry-follows-an-attempt-that-submitted-nothing
description: REFERENCE (sess595, D-0958): under IOMAP_OVERWRITE_ONLY the direct-write mapping must span the whole request or answer -EAGAIN at the first iomap_beg…
metadata:
  type: reference
tags: [dio, iomap, D-0958, fallible-acquire, reference]
---

# The unaligned direct-write retry never follows a partial submit

0.84.10 left the exclusive retry of `xfs_file_dio_write_unaligned` and the COW retry of `xfs_file_dio_write_atomic` as blocking acquires, on the written assumption that the -EAGAIN / -ENOPROTOOPT they follow "may come after part of the range was submitted", so a refusal there might have to report bytes written.

Read from the reference tree and the fork (`/src/linux/fs/iomap/direct-io.c`, `pal/linux/xfs_iomap.c:1020-1053`):
- `__iomap_dio_rw` pre-checks OVERWRITE_ONLY against i_size before building any bio and sets `IOMAP_OVERWRITE_ONLY` on the iter.
- `xfs_direct_write_iomap_begin` under `IOMAP_NOWAIT | IOMAP_OVERWRITE_ONLY` requires the FIRST mapping to span the ENTIRE requested range with one written extent ("so that we avoid partial IO failures due to the rest of the I/O range not covered by this map triggering an EAGAIN condition when it is subsequently mapped and aborting the I/O"), returns -EAGAIN for an unwritten/unaligned or allocating mapping, and asserts OVERWRITE_ONLY is never seen on the allocation path.
- So the -EAGAIN that sends XFS to `retry_exclusive` is decided at the first `->iomap_begin`, before a single bio exists; the retry's re-acquire sits behind an attempt that moved no bytes.  An atomic write is a single extent or `-ENOPROTOOPT` at the same first mapping.

Consequence: both retries are clean fallible boundaries (a refusal is -EIO with nothing landed), converted in 0.84.13 with stage names `unaligned-excl-retry` and `atomic-cow-retry`.  The atomic arm cannot be measured on the lab LUN (no atomic-write support); the unaligned one is measured with a pwrite of 4096 bytes at a 512-aligned, block-unaligned offset inside an fallocated (unwritten) region.
