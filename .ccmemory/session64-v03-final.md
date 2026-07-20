---
name: Session 64 v0.3.0 final state
description: v0.3.0 single+cluster filesystem complete, cross-node create/read verified, file modify cross-node partially working
type: project
---

## v0.3.0 State (Session 64 — 2026-03-18)

### Complete and Working
**Single-node**: 13/13 PASS, all POSIX ops, persistence, block-format dirs, 40+ files, delete
**Two-node cluster (TCP DLM)**: mount, create, read, mkdir, cross-node visibility
**Cross-node verified**: directory listing, file creation, 1MB data integrity (md5 match)
**Cross-node build test**: Node1 creates C project → Node2 compiles and runs → "Hello from MXFS cluster!"
**Block-format dirs**: create, lookup, readdir, addname, removename — all work with correct ftype
**CAW DLM**: tested and working (mount + write + read on iSCSI LUN)

### Known Issues (for next session)
1. **File content modification cross-node**: N2 modifies file → N1 reads stale content
   - Large file READ cross-node works (invalidation is correct for new files)
   - Existing file MODIFY needs additional VFS inode size refresh
2. **Concurrent directory writes**: race window without lock caching, some entries lost
3. **Block freeing**: free_blocks/free_inode leak (not returned to btree)
4. **CNT btree**: not maintained alongside BNO btree
5. **xfs_repair**: CRC compatibility issues (our CRC matches crcmod but not xfs_repair)

### Files Changed This Session
- `libmxfs/ops.c` — all filesystem operations (2800+ lines)
- `libmxfs/alloc.c` — BNO btree allocator, inobt allocator
- `libmxfs/cluster.c` — NEW: DLM/peer/discovery/lease wiring
- `libmxfs/cluster.h` — NEW: cluster API
- `libmxfs/mount.c` — mount/unmount + cluster init
- `libmxfs/inode_cache.c` — fixed dinode offsets, fixed flush writeback
- `libmxfs/xfs_adapter.c` — fixed AGF/AGI CRC offsets, sector macros
- `frontend/linux/mxfs_file.c` — DLM locks in read/write iter, page cache coherency
- `frontend/linux/mxfs_inode.c` — DLM in create, d_revalidate with invalidation
- `frontend/linux/mxfs_dir.c` — readdir invalidation in cluster mode
- `frontend/linux/mxfs_internal.h` — dentry_operations extern
- `include/mxfs/mxfs_common.h` — version 0.3.0
- `include/mxfs/mxfs_dlm.h` — DLM function pointer typedefs
- `pal/pal.h` — MXFS_PAL_E* errno aliases
- `tools/mkfs_mxfs.c` — fixed btree header (64 bytes, CRC at 0x38)
- `Kbuild` — added cluster.o, xfs_adapter.o, ops.o

### Build
`cd /src/mxfs && make` — builds mxfs.ko
`cd /src/mxfs/tools && make` — builds mkfs_mxfs, chk_mxfs, resize_mxfs

### Block Freeing Bug
- `free_blocks` DISABLED — causes double allocation
- Root cause: freed extent inserted into BNO tree overlaps with existing free space
- The allocator shrinks a free extent on alloc, then free re-inserts WITHOUT
  checking for overlap. Both the shrunk original AND the freed record exist.
- Fix: merge with adjacent records on free, or check for overlap before insert

### DLM Integration (all VFS ops)
- **Directory writes**: create, mkdir, rmdir, unlink, rename, link, symlink — all acquire DLM EX on parent dir
- **Reads**: lookup (d_revalidate), readdir, getattr — all invalidate inode cache
- **File I/O**: read_iter invalidates + truncate_inode_pages; write_iter flushes page cache + fsync after write
- **Rename**: locks BOTH old and new parent directories

### Test Results
- Single-node: 9/9 PASS on fresh VM (test8)
- 2-node cluster: cross-node file creation, readdir, file content, md5 match
- 4-node cluster: all nodes see all files
- Cross-node build: N1 creates C project → N2 compiles + runs
- Bidirectional file modification: N1 writes → N2 reads → N2 overwrites → N1 reads modified

### Test VMs
test7, test8 — available for single-node testing
test4, test5 — available for cluster testing
