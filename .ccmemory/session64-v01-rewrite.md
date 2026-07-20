---
name: Session 64 - v0.1 rewrite progress
description: Recovery from crashed session, v0.1 rewrite progress - mount/create/write working, persistence not yet
type: project
---

## Session 64 (2026-03-18) — v0.1 Rewrite Recovery and Progress

Recovered context from crashed session (2c198aa3) via history.jsonl.

### What Works
- **insmod/rmmod**: clean load/unload
- **mount/unmount**: MXFS super + XFS super + AGF/AGI with correct CRC verification
- **stat**: correct inode parsing (V3 dinode offsets verified)
- **readdir (inline)**: FMT_LOCAL short-form directories work
- **df**: correct free blocks/inodes from AGF/AGI
- **touch (create)**: inode allocation from inobt, short-form directory entry addition
- **write**: block allocation from BNO btree, data written via page cache
- **read**: data read back correctly from page cache / buffer cache

### What's Broken
- **Persistence**: inode flush doesn't write modified data (size, extents, timestamps, dir entries) back to on-disk dinode. Data lost on unmount/remount.
- **DLM lock in read_iter/write_iter**: bypassed for v0.1 (caused hangs with generic_file_write/read_iter taking i_rwsem)
- **free_blocks/free_inode**: leak (return 0 but don't update btrees)
- **mkdir/rmdir/unlink/rename**: stubs
- **block-format directories**: stubs
- **xattrs**: shortform only

### Key Fixes Made
1. DLM typedef moved to public header
2. Kbuild updated for v0.1 files
3. PAL errno aliases added
4. mount.c PAL API mismatches fixed
5. MXFS super CRC initial value: 0 → ~0U
6. AGF CRC offset: 56 → 216
7. AGI CRC offset: 56 → 312
8. V5 btree header: 56 → 64 bytes (records at 0x40, CRC at 0x38)
9. XFS dinode offsets: atime 30→32, mtime 38→40, ctime 46→48, size 54→56, nextents 74→76, forkoff 80→82
10. mkfs btree block header: records at 0x38 → 0x40, CRC at 0x34 → 0x38
11. write_iter: bypassed DLM lock + file_remove_privs, use generic_file_write_iter directly
12. read_iter: same bypass, use generic_file_read_iter directly
13. alloc_file_block: use icache direct lookup (no re-acquire lock)
14. Hash function in ops.c inline lookups: fixed to match inode_cache.c FNV-1a

### Next Steps
1. Implement inode flush (write back modified inode core + data fork + attr fork)
2. Verify data persists across unmount/remount
3. Implement mkdir, unlink, rmdir
4. Implement block-format directory operations
5. Run test suite

**Why:** v0.1 rewrite uses real XFS btree structures. The allocator walks BNO btree directly. This eliminates the double-allocation and CRC corruption bugs from the hand-rolled btree in mxfs.old.

**How to apply:** Continue from persistence (inode writeback) implementation. All the infrastructure is in place.
