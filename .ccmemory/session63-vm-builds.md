---
name: session63-vm-builds
description: Session 63 — VM build debugging, Bug 140/141 fixes, stale block root cause found
type: project
---

## Session 63 — v0.9.19 Bug Fixes and VM Build Debugging

### Bugs Fixed (ported from state.md reference)
- Bug 132: DLM epoch check in lock_ag (double allocation on membership change)
- Bug 133: SB sector-only write in flush_superblock_counters
- Bug 134: recount_counters from on-disk AGF/AGI for accurate df
- Bug 139: inflight_lock_ino clear on DLM retry failure

### Kernel Compat (new in this session)
- `MXFS_EFFECTIVE_VERSION` macro in mxfs_internal.h: RHEL 9 → 6.2 (frontend) / 6.9 (pal bdev), Debian 12 → 6.1.99
- `MXFS_HAS_MNT_IDMAP`, `MXFS_ACL_BACKPORT_61`, `MXFS_USE_BLOCK_WRITE_FULL_PAGE`
- bdev API threshold changed from 6.17 to 6.9 for bdev_file_open_by_path
- Builds verified on: clyde (6.8), serv (5.10), pve2 (6.17), Debian 12 (6.1), AlmaLinux (5.14/RHEL 9)

### New Node: Debian 12 (192.168.120.155)
- kernel 6.1.0-39, root/<REDACTED-ROTATED>
- NFS, iSCSI, build tools all configured
- iSCSI device: /dev/sdb (50GB QNAP LUN)

### FALLOC_FL_ZERO_RANGE (new implementation)
- QEMU with detect-zeroes=on calls fallocate(ZERO_RANGE) — we returned -EOPNOTSUPP
- Added MXFS_FALLOC_FL_ZERO_RANGE support, routes to punch_hole (both produce zeros)
- Fixed: ZERO_RANGE does NOT require KEEP_SIZE (unlike PUNCH_HOLE)

### Bug 140: io_uring concurrent access race
- **Root cause**: QEMU with io_uring submits write + fallocate simultaneously to same file
- Two threads modify ci->extents (extent map) with no mutex → corrupt binary search, stale data
- DLM returns -EEXIST when second thread tries to lock same inode
- **Fix**: Added `io_lock` (per-inode mutex) to `struct mxfs_cached_inode`
- Taken in: write_bulk (around write_pinned), mxfs_fallocate, mxfs_alloc_file_block
- Also taken in: flush_inode_to_disk (all callers) to prevent fsync racing with writes
- -EEXIST from DLM handled with retry in cache_get_locked

### Bug 141: Stale block data on newly allocated extents — ROOT CAUSE OF VM FAILURES
- **Root cause**: When blocks are allocated (speculatively preallocated), the physical blocks on disk contain stale data from before mkfs. XFS never zeroes the data area during mkfs — only metadata.
- Buffered I/O masks this because the page cache has correct data (zeros from set_buffer_new)
- O_DIRECT reads (QEMU) bypass the page cache and read physical blocks directly → see old data
- This causes: GRUB booting from empty disk, RPM cpio "Bad file descriptor" errors, guest filesystem corruption
- **Temporary fix**: `zero_new_blocks()` function zeroes every newly allocated block on disk before it's readable
- **Temporary fix**: `filemap_write_and_wait()` before O_DIRECT reads/writes for page cache coherency
- **Proper fix needed**: Unwritten extents — allocate as unwritten, return zeros on read, convert to written on actual write. Infrastructure partially exists (MXFS_EXTENT_F_UNWRITTEN, read_bulk zeros for unwritten). Need: allocate-as-unwritten + convert-on-write.
- **Performance concern**: Block zeroing adds significant I/O overhead (up to 8MB zeros per allocation with speculative prealloc). Unwritten extents have zero overhead.

### VM Build Test Results
- Disk label error: FIXED (ZERO_RANGE + coherency flush)
- Grub on empty disk: FIXED (coherency flush)
- RPM scriptlet failures (Bad file descriptor): Root cause identified (stale blocks), fix deployed but UNTESTED
- **Status**: Fix deployed on pve2, user went to bed before testing. Next session: test VM build with block zeroing.

### Test Environment State
- pve1 (192.168.1.80): powered off
- pve2 (192.168.1.81): powered off. Has v0.9.19+zeroing deployed, fresh mkfs, ready to test
- Other nodes: unmounted, modules unloaded
- Version bump to 0.9.19 done earlier (VERSION + mxfs_common.h)

### Debug Logging Still Active
- pr_info for DIRECT_WRITE, FALLOCATE, GET_BLOCK, BUFFERED_WRITE in mxfs_file.c
- Timing instrumentation (>100ms lock, >500ms write) in write_bulk and fallocate
- extent.c INSERT VERIFY check
- Should be removed before release
