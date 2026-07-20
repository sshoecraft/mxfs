# resize_mxfs -- MXFS Resize Tool

## Overview

`resize_mxfs` grows an MXFS filesystem after the underlying block device has been expanded. It appends new XFS allocation groups at the end of the XFS data area, then updates the XFS and MXFS superblocks to reflect the new geometry.

## How Growing Works

```
Before:
|<-- MXFS reserved (~96MB) -->|<-- XFS data (AG 0, AG 1) -->|
0                              xfs_data_offset               old_dev_end

After:
|<-- MXFS reserved (~96MB) -->|<-- XFS data (AG 0, AG 1, AG 2, AG 3, ...) -->|
0                              xfs_data_offset                                 new_dev_end
```

The MXFS super, journal, and disklock regions are at fixed offsets at the start of the device and are never moved. Only the XFS data area grows by adding new AGs at the end.

## Usage

```bash
resize_mxfs [-v] [-n] [-V] /dev/sdX
```

Options:
- `-v` -- Verbose output (show per-AG details)
- `-n` -- Dry run (show what would be done, don't write)
- `-V` -- Print version and exit

Returns 0 on success, 1 on error.

## How It Works

1. Opens device and reads MXFS super from offset 0
2. Validates MXFS magic (0x5346584D), version, and CRC32C
3. Gets new device size via `BLKGETSIZE64` (block device) or `fstat` (regular file)
4. Validates new size > old size (stored in MXFS super `device_size`)
5. Reads existing XFS superblock at `xfs_data_offset`
6. Calculates new geometry:
   - Computes available blocks starting from `old_agcount * agblocks` (respecting XFS address space)
   - Determines number of full new AGs + optional partial last AG
   - Drops remainder if < 64 blocks (MIN_AG_BLOCKS)
7. For each new AG, writes: SB copy + AGF + AGI + AGFL (in one 4KB block), BNO btree root, CNT btree root, INO btree root (empty), FINO btree root (empty)
8. Updates primary XFS superblock: dblocks, agcount, fdblocks
9. Updates secondary SB copies in all existing AGs (1 through old_agcount-1)
10. Updates MXFS super: device_size, xfs_data_size, CRC
11. Syncs and closes

## New AG Layout

Each new AG has 5 header blocks and the rest is free space:

| Block | Contents |
|-------|----------|
| 0 | SB (secondary copy) + AGF + AGI + AGFL (4 sectors) |
| 1 | BNO btree root (1 record: free_start to end) |
| 2 | CNT btree root (1 record: same free extent) |
| 3 | INO btree root (empty, 0 records) |
| 4 | FINO btree root (empty, 0 records -- free inode btree) |
| 5+ | Free space |

Free blocks per AG = aglen - 5.

The AGI includes finobt fields: `agi_free_root = 4` (finobt root block), `agi_free_level = 1`.

## XFS Address Space

In XFS, AG offsets are computed as `agno * agblocks`. If the old last AG was shorter than `agblocks`, there is an address-space gap between the old data end and where new AGs begin. This is standard XFS behavior -- the "missing" blocks are simply not part of the filesystem.

## CRC Conventions

- **XFS CRC**: `crc32c(~0U, buf, len)`, final complement (`~crc`), stored as native `uint32_t`
- **MXFS super CRC**: `crc32c(~0U, buf, 4096)` with crc field zeroed, NOT complemented (raw CRC value)
- **Btree block CRC**: same as XFS CRC, at offset 0x34 in the 4KB block

## Build

```bash
cc -Wall -Wextra -O2 -I../include -o resize_mxfs resize_mxfs.c
```

No external dependencies. No libmxfs linkage -- standalone program.

## Key Files

- `tools/resize_mxfs.c` -- source code
- `tools/mkfs_mxfs.c` -- reference for AG structure formatting patterns
- `include/mxfs/mxfs_super.h` -- shared on-disk super struct

## Safety

- Refuses to run if new device size <= old device size
- Dry run mode (`-n`) shows plan without modifying disk
- Writes new AG structures first, then updates superblocks (crash before SB update = old FS still valid)
- Supports both block devices (BLKGETSIZE64) and regular files (fstat)

## History

- v0.6.0 (2026-03-10): Added FINOBT root block (block 4) to new AGs. AGI now includes finobt fields (free_root=4, free_level=1). NEW_AG_HEADER_BLOCKS increased from 4 to 5.
- v0.6.0 (2026-03-06): Initial implementation. Adds new XFS AGs after existing data, updates XFS and MXFS superblocks. Supports dry run, verbose mode, block devices and regular files. Iterative resize (multiple grow operations) tested and working.
