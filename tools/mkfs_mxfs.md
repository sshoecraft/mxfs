# mkfs.mxfs — MXFS Format Tool

## Overview

`mkfs.mxfs` formats a block device for use with MXFS (Multinode XFS). It creates the on-disk layout that enables `mount -t mxfs /dev/sdX /mnt/shared` without any manual offset options.

## Disk Layout

```
|<-- super 4KB -->|<-- journal ~64MB -->|<-- disklock ~32MB -->|<-------- XFS data -------->|
0                 journal_offset        disklock_offset         xfs_data_offset          dev_end
```

- **MXFS super**: 4KB on-disk superblock at the very start of the device (sector 0 has MXFS magic, not XFSB)
- **Journal**: Per-node circular journals (64 slots x 1MB = 64MB + 512B super)
- **Disklock/CAW**: Heartbeat region (32KB) + lock slots (32MB) for disk-based DLM
- **XFS data**: Standard XFS v5 filesystem formatted natively (no external tools), grows toward end of device

## Usage

```bash
mkfs.mxfs [-f] [-v] [-V] /dev/sdX
```

Options:
- `-f` — Force, skip confirmation prompt
- `-v` — Verbose output (show per-slot journal formatting)
- `-V` — Print version and exit

## How It Works

1. Opens device with `O_EXCL` (rejects if mounted)
2. Gets device size via `BLKGETSIZE64`
3. Calculates region offsets (all 4KB-aligned from the start)
4. Generates filesystem UUID
5. Writes journal super + 64 slot headers
6. Zeros disklock region
7. Formats XFS v5 natively at xfs_data_offset: writes superblock, AGF/AGI/AGFL per AG, btree roots, inode chunk, zeroes log
8. Writes MXFS on-disk superblock (4KB) at offset 0
9. Syncs and closes

## Mount Auto-Detection

When `mount -t mxfs /dev/sdX /mnt` is called without offset options, the kernel module:
1. Reads the first 4KB of the device (offset 0)
2. Validates MXFS magic (0x5346584D), version, and CRC32C
3. Extracts `journal_offset`, `disklock_offset`, and `xfs_data_offset` from the superblock
4. Creates an xfs_dev clone (PAL bdev with base_offset = xfs_data_offset) for all XFS I/O
5. Proceeds with normal mount using the detected offsets

Manual offset options (`journal_offset=`, `disklock_offset=`) still work and take precedence.

## Region Sizes

| Region | Size | Contents |
|--------|------|----------|
| Journal | 67,109,376 bytes (~64MB) | 512B super + 64 x 1MB slots |
| Disklock | 33,587,200 bytes (~32MB) | 32KB heartbeat + 32MB lock slots |
| MXFS super | 4,096 bytes (4KB) | On-disk format metadata |
| **Total reserved** | **100,700,672 bytes (~96MB)** | |

## Build

```bash
cd tools && make
```

Produces `mkfs.mxfs` binary. Install to `/sbin/` with `make install`.

## Dependencies

- Linux block device (BLKGETSIZE64 ioctl)
- `/dev/urandom` for UUID generation
- No external tools required (no mkfs.xfs dependency)
- No libmxfs linkage — standalone program

## Key Files

- `tools/mkfs_mxfs.c` — source code
- `include/mxfs/mxfs_super.h` — shared on-disk super struct (used by mkfs and kernel mount)
- `libmxfs/mount.c` — auto-detect logic in `mxfs_mount()`

## XFS Native Format Details

The native XFS formatter writes a minimal but valid XFS v5 filesystem:

- **Feature flags**: CRC, ATTR2, FTYPE, SPINODES, LAZYSBCOUNT, PROJID32, FINOBT
- **Geometry**: 2+ AGs (~1GB each target), 4096-byte blocks, 512-byte inodes
- **Per-AG structures**: Superblock (primary + secondary), AGF, AGI, AGFL, BNO/CNT/INO/FINO btree roots
- **Inode chunk**: 64 inodes in AG 0 at block 16 (root dir ino 128, rbmino 129, rsumino 130, 61 free)
- **Log**: Zeroed (kernel initializes on first mount), minimum 1024 blocks
- **CRC**: CRC32C with seed ~0U, final complement, stored as native uint32_t

### Per-AG Block Layout

```
Block 0:  SB + AGF + AGI + AGFL (4 sectors in one 4KB block)
Block 1:  BNO btree root (free space by block number)
Block 2:  CNT btree root (free space by size)
Block 3:  INO btree root (inode allocation)
Block 4:  FINO btree root (free inode tracking)
Block 5-8: AGFL blocks (free list reserve)
```

AG 0 additionally has the inode chunk at blocks 16-23 (8-block aligned per INOALIGNMT=8), creating two free extents: blocks 9-15 (gap) and blocks 24+ (main free space).

### FINOBT (Free Inode BTree)

The finobt (magic FIB3 = 0x46494233) tracks inode chunks that contain free inodes. It mirrors the inobt record format: `[startino, holemask, count, freecount, free_bitmap]`.

- **AG 0**: Contains one record matching the inobt (the 64-inode chunk has 61 free inodes)
- **Other AGs**: Empty at format time (no inode chunks allocated yet)
- **AGI fields**: `agi_free_root = 4` (block number), `agi_free_level = 1`
- **Superblock**: `features_ro_compat` bit 0 (`XFS_SB_FEAT_RO_COMPAT_FINOBT`) is set

The finobt speeds up inode allocation by allowing the kernel to find free inodes without scanning the full inobt. This is especially important for large filesystems with many allocation groups.

## History

- v0.1.0 (2026-03-23): Three bugs in `format_xfs_native()`. (1) AG geometry: `agblocks` via floor division, last AG larger than agblocks. Fix: ceiling division. (2) FSB encoding: `logstart` as linear `log_ag * agblocks + 5`, but XFS packs as `(agno << agblklog) | agbno`. Fix: packed encoding. (3) Log zeroing: used `packed_fsb * blocksize` for physical offset, but packed FSB != linear address when agblocks != 2^agblklog. Fix: use `(log_ag * agblocks + 5) * blocksize`. CRC32C was already correct.
- v0.9.27 (2026-03-18): Fixed fdblocks calculation — was adding 4 AGFL blocks per AG to sb_fdblocks, but AGFL blocks are reserved (not allocatable) and not counted in AGF.freeblks. Caused mount-time warning: "free_blocks from AGF sum differs from sb->fdblocks (stale sb)". Discrepancy was exactly 4 x agcount blocks (196 blocks on a 50GB device with 49 AGs).
- v0.9.13 (2026-03-12): Cleaned up output — removed duplicate post-format summary (layout already shown pre-format), removed mount hint.
- v0.7.1 (2026-03-10): Added FINOBT (free inode btree) initialization. Each AG now gets a FINO btree root block (block 4). AG 0 finobt mirrors the inobt record. Superblock features_ro_compat includes FINOBT bit. Inode chunk moved to block 16 (8-block aligned after FINOBT+AGFL), rootino changed from 64 to 128. AG 0 BNO/CNT btrees now have two free extent records (gap + main). Fixed sb_fdblocks to include AGFL blocks. resize_mxfs also updated.
- v0.7.1 (2026-03-06): Reversed on-disk layout. MXFS super now at offset 0 (prevents `mount -t xfs`). XFS data at end (enables future resize). Added `xfs_data_offset` to on-disk super. UUID generated upfront (not inside format_xfs_native). format_xfs_native takes `base_offset` parameter.
- v0.7.0 (2026-03-06): Native XFS v5 formatting. Eliminates mkfs.xfs dependency entirely.
- v0.6.4 (2026-03-06): Initial implementation. Replaces manual `disklock_offset=`/`journal_offset=` mount options.
