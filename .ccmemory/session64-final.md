---
name: Session 64 final state
description: v0.2.0 single-node filesystem complete and tested, ready for DLM wiring
type: project
---

## v0.2.0 State (Session 64 — 2026-03-18)

### Complete and Working
- Mount/unmount with MXFS super + XFS V5 superblock + AGF/AGI CRC verification
- All file operations: create, read, write, stat, chmod, chown, utimes, truncate, fsync
- All directory operations: mkdir, rmdir, readdir, lookup (short-form AND block-format)
- Symlinks, hardlinks, mknod, rename, unlink
- Block allocation from BNO btree (first-fit, AG affinity)
- Inode allocation from inobt (bitmap-based)
- Short-form → block-format directory auto-conversion when inline overflows
- Inode writeback with correct V3 dinode CRC at offset 0x64
- Buffered read/write via generic VFS functions
- 20/20 test battery PASS, 60+ files per directory, md5 integrity across double remount

### Key Offsets (verified and correct)
- MXFS super CRC: stored as `crc32c(~0U, data, len)` — raw, no complement
- XFS AGF CRC: offset 216 within AGF sector
- XFS AGI CRC: offset 312 within AGI sector
- XFS btree block CRC: offset 56, header 64 bytes, records at 64
- XFS dinode: atime=32, mtime=40, ctime=48, size=56, nextents=76, forkoff=82, CRC=100(0x64)
- XFS dinode core size: 176 (V3), data fork at 0xB0

### Build
- `cd /src/mxfs && make` — kernel module mxfs.ko
- `cd /src/mxfs/tools && make` — mkfs_mxfs, chk_mxfs, resize_mxfs
- Version: 0.2.0

### Known Issues
- DLM bypassed (single-node only) — write_iter and read_iter use generic_file_*_iter directly
- free_blocks/free_inode leak (btree not updated on free, recovered by xfs_repair)
- CNT btree not maintained (only BNO btree updated on alloc)
- xfs_repair reports CRC errors (investigation inconclusive, functional correctness proven)
- Block-format directory removename not implemented (unlink from block dirs)

### Next: DLM Wiring
Port mount sequence from mxfs.old/libmxfs/mount.c lines 1850-2300.
The DLM/peer/discovery/lease/journal code is already in libmxfs/.
Need to wire function pointers and re-enable DLM in file ops.
