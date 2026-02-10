/*
 * MXFS — Multinode XFS
 * Netlink protocol definitions for kernel module <-> daemon communication
 *
 * Uses Generic Netlink (genetlink) for structured, versioned messaging
 * between mxfs.ko and mxfsd on the same node.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_NETLINK_H
#define MXFS_NETLINK_H

#include "mxfs_common.h"

/* Generic netlink commands — kernel <-> mxfsd */
enum mxfs_nl_cmd {
	MXFS_NL_CMD_UNSPEC = 0,
	MXFS_NL_CMD_LOCK_REQ,        /* kernel -> daemon: request distributed lock */
	MXFS_NL_CMD_LOCK_GRANT,      /* daemon -> kernel: lock granted */
	MXFS_NL_CMD_LOCK_RELEASE,    /* kernel -> daemon: releasing distributed lock */
	MXFS_NL_CMD_LOCK_DENY,       /* daemon -> kernel: lock denied */
	MXFS_NL_CMD_CACHE_INVAL,     /* daemon -> kernel: invalidate page cache range */
	MXFS_NL_CMD_NODE_STATUS,     /* daemon -> kernel: peer node state change */
	MXFS_NL_CMD_VOLUME_MOUNT,    /* kernel -> daemon: XFS volume mounted with mxfs */
	MXFS_NL_CMD_VOLUME_UMOUNT,   /* kernel -> daemon: XFS volume unmounted */
	MXFS_NL_CMD_STATUS_REQ,      /* either direction: request status */
	MXFS_NL_CMD_STATUS_RESP,     /* either direction: status response */
	MXFS_NL_CMD_RECOVERY_START,  /* daemon -> kernel: freeze I/O, recovery starting */
	MXFS_NL_CMD_RECOVERY_DONE,   /* daemon -> kernel: recovery complete, resume I/O */
	__MXFS_NL_CMD_MAX,
};

#define MXFS_NL_CMD_MAX (__MXFS_NL_CMD_MAX - 1)

/* Generic netlink attributes */
enum mxfs_nl_attr {
	MXFS_NL_ATTR_UNSPEC = 0,
	MXFS_NL_ATTR_NODE_ID,        /* u32: node ID */
	MXFS_NL_ATTR_NODE_STATE,     /* u8: mxfs_node_state */
	MXFS_NL_ATTR_LOCK_TYPE,      /* u8: mxfs_lock_type */
	MXFS_NL_ATTR_LOCK_MODE,      /* u8: mxfs_lock_mode */
	MXFS_NL_ATTR_LOCK_FLAGS,     /* u32: MXFS_LKF_* */
	MXFS_NL_ATTR_LOCK_STATUS,    /* u8: mxfs_error */
	MXFS_NL_ATTR_RESOURCE,       /* binary: struct mxfs_resource_id */
	MXFS_NL_ATTR_VOLUME_ID,      /* u64: volume identifier */
	MXFS_NL_ATTR_INODE,          /* u64: inode number */
	MXFS_NL_ATTR_OFFSET,         /* u64: byte offset for extent/cache */
	MXFS_NL_ATTR_LENGTH,         /* u64: byte length for extent/cache */
	MXFS_NL_ATTR_AG_NUMBER,      /* u32: allocation group number */
	MXFS_NL_ATTR_EPOCH,          /* u64: lease epoch */
	MXFS_NL_ATTR_STATUS_CODE,    /* u32: mxfs_error */
	MXFS_NL_ATTR_DEV_PATH,       /* string: block device path */
	MXFS_NL_ATTR_MOUNT_PATH,     /* string: mount point path */
	__MXFS_NL_ATTR_MAX,
};

#define MXFS_NL_ATTR_MAX (__MXFS_NL_ATTR_MAX - 1)

/* Multicast groups for unsolicited notifications */
enum mxfs_nl_mcast_groups {
	MXFS_NL_MCAST_LOCKS = 0,    /* lock state changes */
	MXFS_NL_MCAST_STATUS,       /* node/volume status changes */
};

#endif /* MXFS_NETLINK_H */
