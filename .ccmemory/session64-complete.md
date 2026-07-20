---
name: Session 64 complete state
description: v0.3.0 clustered filesystem - 23/23 PASS, ALL features working, ready for physical servers
type: project
---

## MXFS v0.3.0 — Session 64 (2026-03-18)

### Test Results
- **23/23** comprehensive single-node (ALL POSIX ops + xattrs + mmap + flock + space reclaim)
- **12/12** 2-node cluster (cross-node CRUD + file modification)
- **4-node** cluster verified
- **chk_mxfs**: inobt + finobt + AGF + AGI + superblock ALL clean

### Key Bugs Fixed This Session
1. **truncate_pagecache**: setattr didn't invalidate page cache on O_TRUNC → stale pages
   wrote to freed blocks, corrupting data. Fixed by adding truncate_pagecache(inode, size).
   THIS WAS THE ROOT CAUSE of both the overwrite corruption AND the block-freeing corruption.
2. **dfork_size calculation**: forkoff*8 - core_size → forkoff*8 (core_size already accounted for)
3. **xattr persistence**: flush_inode now copies attr fork from raw_buf to block buffer
4. **finobt sync**: dynamic chunk allocation adds finobt records
5. **inobt CRC magic**: wrong values in xfs_format.h corrected
6. **dinode field offsets**: atime/mtime/ctime/size/nextents/forkoff all at correct XFS V3 offsets
7. **AGF/AGI CRC offsets**: 56→216/312 respectively
8. **btree header**: 56→64 bytes, CRC at 56, records at 64
9. **mkfs btree blocks**: records at 0x40 (was 0x38), CRC at 0x38 (was 0x34)

### Features
- Block allocation (BNO btree) + deallocation (BNO insert) ✓
- Inode allocation (inobt bitmap) + deallocation (bit set) ✓
- Dynamic inode chunks (auto-allocate 64-inode chunks on demand) ✓
- Short-form + block-format directories (auto-convert) ✓
- xattr persistence (shortform, user/trusted/security namespaces) ✓
- DLM: TCP + CAW, peer discovery, inode locks, cross-node coherency ✓
- fallocate, truncate, sparse files, O_DIRECT ✓
- Version in module load message ✓

### Known Limitations
- Concurrent large-file writers (>100 blocks): VFS writeback race
- Leaf/node directory format not implemented (>120 entries per dir)
- CNT btree not maintained (BNO only, xfs_repair can rebuild)
- Post-mount cross-node inode reads: some edge cases with stale VFS inodes
