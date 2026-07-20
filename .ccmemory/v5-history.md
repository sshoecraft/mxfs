---
name: MXFS v5 Project History
description: Why v5 exists and what failed in previous attempts (mxfs.1-mxfs.4). Reference for avoiding past mistakes.
type: project
---

## Previous Attempts

### mxfs.1 (~/src/mxfs.1) — v0.14.0
- Custom XFS format handling, 34K lines in libmxfs
- Hand-written block/inode/dir caches, custom btree engine, custom alloc.c
- Single-node: 19/19 PASS, 103 bugs fixed, 32-node CAW DLM tested
- **Problem**: rsync 29s vs native XFS 7s. Root cause: all metadata I/O was synchronous submit_bio_wait. Session 71 found 43,000 small sync writes at ~550us each. Sessions 72-73 added writeback caching and batched flush, cutting 60s→29s, but still 4x native XFS.
- **Key asset**: DLM (dlm.c 84K, dlm_caw.c 48K) — battle-tested at 32 nodes

### mxfs.2 (~/src/mxfs.2) — v0.6.0→v0.9.19
- Started as stacking FS wrapping XFS at VFS layer
- Later morphed into btree rewrite using XFS cursor engine
- **Problem**: Scope creep, no clear direction, abandoned

### mxfs.3 (~/src/mxfs.3 = /src/mxfs.new) — v0.3.2
- Attempted to use xfsprogs/libxfs as the XFS implementation
- **CRITICAL MISTAKE**: xfsprogs/libxfs is the USERSPACE format library for mkfs/fsck/resize. It is NOT the kernel XFS code. Has no iomap, no xfs_buf async I/O, no page cache, no writeback.
- Result: 45x slower than native XFS (11.4 MB/s vs 509 MB/s)
- project.md documents the full analysis

### mxfs.4 (within mxfs.2, sessions 60-62)
- Tried replacing alloc.c with XFS cursor-based btree engine from libxfs
- **CAUSED REGRESSION**: concurrent PVE VM builds broke (stale dir cache, BASTs not firing)
- Rolled back to v0.9.18

## Why v5 Will Work

v5 uses the ACTUAL Linux kernel XFS source code from ~/src/linux/fs/xfs/ (kernel 6.19.0-rc0). This gives us:
- xfs_buf.c — async buffer cache with LRU, writeback, I/O scheduling
- xfs_iomap.c — iomap integration for buffered/direct I/O
- xfs_log.c/xfs_log_cil.c — write-ahead log with CIL batching
- xfs_aops.c — address space ops (page cache integration)
- xfs_icache.c — inode lifecycle, reclaim, writeback

These are the exact subsystems that made native XFS 4x faster than our custom code.

**How to apply:** Never attempt to reimplement XFS I/O paths. Use the kernel code as-is. DLM hooks go INTO the existing XFS infrastructure (xfs_buf, xfs_icache), not around it.
