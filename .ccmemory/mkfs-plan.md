---
name: mkfs-plan
description: mkfs.mxfs implementation details (COMPLETED) — superseded by the shipped tool.
metadata:
  type: project
---

# mkfs.mxfs — Implementation Details (COMPLETED)

## Status: DONE (Session 13, 2026-03-06)

## Disk Layout
```
|<-- XFS data -->|<-- journal ~64MB -->|<-- disklock ~32MB -->|<-- super 4KB -->|
0                journal_offset        disklock_offset        super_offset  dev_end
```

## Region Sizes
- Journal: 512B super + 64 x 1MB slots = 67,109,376 bytes
- Disklock: 32KB heartbeat + 32MB locks = 33,587,200 bytes
- MXFS super: 4,096 bytes
- Total reserved: 100,700,672 bytes (~96MB)

## On-Disk MXFS Super (last 4KB of device)
- Magic: 0x4D585346 ("MXSF") — distinct from VFS MXFS_SUPER_MAGIC (0x4D584653)
- Struct: `mxfs_ondisk_super` in `include/mxfs/mxfs_super.h`
- Fields: magic, version, crc, fs_uuid, device_size, xfs_data_size, journal_offset, journal_size, disklock_offset, disklock_size, max_nodes, journal_slot_sectors
- CRC32C with crc field zeroed

## Files Created
- `include/mxfs/mxfs_super.h` — shared on-disk super struct
- `tools/mkfs_mxfs.c` — standalone format tool (~400 lines, no libmxfs linkage)
- `tools/Makefile` — `gcc -Wall -O2 -I../include -o mkfs.mxfs mkfs_mxfs.c`
- `tools/mkfs_mxfs.md` — documentation

## Files Modified
- `pal/pal.h` — added mxfs_pal_bdev_size()
- `pal/pal_linux_kern.c` — bdev_nr_bytes() with 5.16 compat fallback
- `pal/pal_linux_user.c` — BLKGETSIZE64 ioctl + stat fallback, added sys/stat.h + linux/fs.h
- `libmxfs/mount.h` — added mxfs_super.h include
- `libmxfs/mount.c` — auto-detect after bdev_open, changed opts-> to mnt->opts. for offset refs
- `include/mxfs/mxfs_common.h` — version 1.2.0 → 1.3.0

## Key Design Decisions
- Standalone tool (no libmxfs link) — inline CRC32C table, duplicate journal constants
- On-disk super at END of device (last 4KB) — won't conflict with XFS at start
- Auto-detect in mount.c: read last 4KB, validate magic+CRC, populate offsets
- All offset references changed from opts-> to mnt->opts. so auto-detected values propagate

## Test Results
- Single-node (test1): PASS — format, mount without offsets, touch, persistence
- Four-node (test1-4): 4/4 PASS — auto-detected, cross-node visibility
- Builds clean on 6.8 (dev) and 6.1 (test nodes)
