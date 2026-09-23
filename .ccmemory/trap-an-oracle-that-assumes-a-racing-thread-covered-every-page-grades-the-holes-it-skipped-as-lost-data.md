---
name: trap-an-oracle-that-assumes-a-racing-thread-covered-every-page-grades-the-holes-it-skipped-as-lost-data
description: TRAP (s138b2/s139): a data-loss FAIL was the reproducer's oracle expecting bytes on pages its own toucher never reached; native XFS as control expose…
metadata:
  type: feedback
tags: [harness, oracle, delalloc, mmap, control, kprobes]
---

# The trap

`tests/delalloc_dirty_tail_race.c` expected every odd page to hold `(i & 0xff)` because "the toucher stores every odd page in the closing pass". It does not: when the pass restarts the toucher is still finishing the previous pass's last window at the far end of the file, and by the time it re-reads `writer_at` the writer is at page N. Pages 1..N-1 are never stored to in the pass; they are holes the punch left. The old check graded them as lost data (s138b2 on MXFS: FAIL; every run's "lost" set — 1..9, 1..13, 1..23 — ended exactly where the writer was when the toucher caught up).

# What told the difference, in order of cost

1. **Native XFS on the same kernel, same reproducer** (a loop device on a spare node, `tests/delalloc_dirty_tail_loop_control.sh`) produced the identical verdict in one 14 s lap. A control on the reference implementation is the cheapest way to separate "the filesystem lost it" from "the test expected it wrongly", and it comes before any code reading.
2. **Kprobes reading the folio's own per-block bitmaps** (`tests/delalloc_dirty_tail_kprobe.sh`: `ifs_alloc`, `ifs_set_range_dirty`, `iomap_writepage_map`, `iomap_add_to_ioend`, folio flags/private at +0x0/+0x20/+0x28, ifs words at +0x10/+0x18) showed every block dirty, submitted and written — so the zeros were in the page cache at submission, and the kernel was exonerated.
3. **The reproducer stamping its own progress into `trace_marker`** put "first closing-pass store = page 4039" next to the kernel events and named the cause.

# The fix shape

A reproducer whose oracle depends on a racing thread's coverage must **record the coverage** (a per-page manifest written beside the data) and the verifier must check only what was covered, reporting the rest (`UNTOUCHED`) — `tests/ddtr_verify.py`. With it native XFS passes 3/3 and MXFS 2/2 with the subject occurring (P313 ×60).

# Side facts that cost time

- A loop device cannot host a single-node MXFS mount on 0.89.60 even on TCP: admission needs `fence_capability_override=1` AND `single_node_exclusive=1`, and the page-authority ledger still needs COMPARE AND WRITE (`P304-CAS-NOCAW`, -95). Use the real LUN.
- In 6.8's `xfs_iomap_found` tracepoint `startblock`, DELAYSTARTBLOCK is -1 (…ffff) and HOLESTARTBLOCK is -2 (…fffe). Reading them swapped inverted the whole extent story for an hour.
- The `iomap_iter` tracepoint fires BEFORE the iterator advances: each line shows the previous iteration's pos and the previous iomap's remaining length (0 on the first call).
- `mm_filemap_*` tracepoints print the inode as bare hex (`ino 83`), the xfs/iomap ones as `ino 0x83`; a filter on `ino` does not apply to them (field is `i_ino`).
