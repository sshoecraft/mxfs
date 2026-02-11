/*
 * MXFS — Multinode XFS
 * Common definitions shared between kernel module (mxfs.ko) and daemon (mxfsd)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_COMMON_H
#define MXFS_COMMON_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#define MXFS_VERSION_MAJOR      0
#define MXFS_VERSION_MINOR      3
#define MXFS_VERSION_PATCH      0

#define MXFS_MAX_NODES          64
#define MXFS_MAX_VOLUMES        256
#define MXFS_NODE_NAME_MAX      64
#define MXFS_VOLUME_NAME_MAX    128
#define MXFS_PATH_MAX           4096

#define MXFS_NETLINK_FAMILY     "mxfs"
#define MXFS_NETLINK_VERSION    1

/* Node identifier — unique per cluster */
typedef uint32_t mxfs_node_id_t;

/* Lease epoch — monotonically increasing, survives restarts via disk */
typedef uint64_t mxfs_epoch_t;

/* Volume identifier — derived from XFS superblock UUID */
typedef uint64_t mxfs_volume_id_t;

/* Lock resource identifier — uniquely identifies a lockable resource */
struct mxfs_resource_id {
	mxfs_volume_id_t volume;
	uint64_t         ino;        /* inode number, 0 for non-inode resources */
	uint64_t         offset;     /* extent start block, 0 if not extent */
	uint32_t         ag_number;  /* allocation group, 0 if not AG lock */
	uint8_t          type;       /* mxfs_lock_type */
	uint8_t          pad[3];
};

/* Error codes beyond standard errno */
enum mxfs_error {
	MXFS_OK = 0,
	MXFS_ERR_DEADLOCK,
	MXFS_ERR_LEASE_EXPIRED,
	MXFS_ERR_NODE_DEAD,
	MXFS_ERR_NO_QUORUM,
	MXFS_ERR_STALE_LOCK,
	MXFS_ERR_RECOVERY_NEEDED,
	MXFS_ERR_VERSION_MISMATCH,
	MXFS_ERR_VOLUME_UNKNOWN,
	MXFS_ERR_NOT_MOUNTED,
};

/* Node state as seen by the DLM */
enum mxfs_node_state {
	MXFS_NODE_UNKNOWN = 0,
	MXFS_NODE_JOINING,
	MXFS_NODE_ACTIVE,
	MXFS_NODE_SUSPECT,       /* missed lease renewal, not yet dead */
	MXFS_NODE_DEAD,
	MXFS_NODE_RECOVERING,    /* journal replay in progress */
};

#endif /* MXFS_COMMON_H */
