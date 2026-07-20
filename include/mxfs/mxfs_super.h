/*
 * MXFS — Multinode XFS
 * On-disk MXFS superblock definition
 *
 * Written by mkfs.mxfs at the first 4KB of the block device.
 * Read by the mount path to auto-detect journal, disklock, and XFS data offsets.
 *
 * Shared between:
 *   - tools/mkfs_mxfs.c (userspace format tool)
 *   - libmxfs/mount.c   (kernel/userspace auto-detect on mount)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_SUPER_H
#define MXFS_SUPER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* On-disk MXFS format magic — reads "MXFS" in hexdump (LE).
 * Distinct from the VFS MXFS_SUPER_MAGIC (0x4D584653)
 * used for statfs f_type. */
#define MXFS_FORMAT_MAGIC       0x5346584D
#define MXFS_FORMAT_VERSION     1
#define MXFS_SUPER_SIZE         4096

/*
 * On-disk MXFS superblock — first 4KB of the block device.
 *
 * Layout on device:
 *   [this 4KB super] [journal region] [disklock region] [XFS data to end]
 *
 * All offsets are absolute byte offsets from the start of the device.
 * All multi-byte fields are native byte order (x86 = little-endian).
 */
struct mxfs_ondisk_super {
    uint32_t    magic;              /* MXFS_FORMAT_MAGIC (0x5346584D) */
    uint32_t    version;            /* MXFS_FORMAT_VERSION */
    uint32_t    flags;              /* reserved, must be 0 */
    uint32_t    crc;                /* CRC32C of this 4KB (with crc=0) */
    uint8_t     fs_uuid[16];        /* copy of XFS sb_uuid */
    uint64_t    device_size;        /* total device size in bytes */
    uint64_t    xfs_data_size;      /* XFS data area in bytes */
    uint64_t    journal_offset;     /* byte offset of journal region */
    uint64_t    journal_size;       /* journal region size in bytes */
    uint64_t    disklock_offset;    /* byte offset of disklock region */
    uint64_t    disklock_size;      /* disklock region size in bytes */
    uint32_t    max_nodes;          /* max node count at format time */
    uint32_t    journal_slot_sectors; /* sectors per journal slot */
    uint64_t    xfs_data_offset;    /* byte offset where XFS data starts */
    uint32_t    xfs_log_node_count; /* per-node XFS log slices (0=legacy) */
    uint32_t    xfs_log_slice_bblks;/* basic blocks (512B) per log slice */
    uint8_t     reserved[3992];     /* pad to 4096 bytes */
};

/* Compile-time size check */
#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_SUPER() \
    BUILD_BUG_ON(sizeof(struct mxfs_ondisk_super) != MXFS_SUPER_SIZE)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_ondisk_super) == MXFS_SUPER_SIZE,
               "mxfs_ondisk_super must be exactly 4096 bytes");
#endif

#endif /* MXFS_SUPER_H */
