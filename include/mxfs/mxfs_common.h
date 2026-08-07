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
#include <stdbool.h>
#endif

/* Version is injected by the build system from the VERSION file.
 * Kbuild passes -DMXFS_VERSION_MAJOR=X -DMXFS_VERSION_MINOR=Y -DMXFS_VERSION_PATCH=Z
 * Tools Makefile does the same.
 * Fallback values here only apply if building without the build system. */
#ifndef MXFS_VERSION_MAJOR
#define MXFS_VERSION_MAJOR      0
#define MXFS_VERSION_MINOR      10
#define MXFS_VERSION_PATCH      0
#endif

#define MXFS_MAX_NODES          64
#define MXFS_MAX_VOLUMES        256
#define MXFS_NODE_NAME_MAX      64
#define MXFS_VOLUME_NAME_MAX    128
#define MXFS_PATH_MAX           4096

#define MXFS_NETLINK_FAMILY     "mxfs"
#define MXFS_NETLINK_VERSION    1

/* Default daemon binary path */
#define MXFSD_PATH              "/usr/sbin/mxfsd"

/* Timeout for daemon to signal readiness after spawn (seconds) */
#define MXFS_DAEMON_STARTUP_TIMEOUT_S   30

/* Mount option flags (bitfield for mxfs_sb_info) */
#define MXFS_MNT_IFACE         (1 << 0)  /* iface= was specified */
#define MXFS_MNT_PORT          (1 << 1)  /* port= was specified */
#define MXFS_MNT_MULTICAST     (1 << 2)  /* multicast= was specified */
#define MXFS_MNT_BROADCAST     (1 << 3)  /* broadcast= was specified */

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
	/*
	 * sess12 (2/tcp double-grant root fix): a blocked INODE upgrade
	 * (sender holds GRANTED lower mode, requests higher, conflicts with
	 * another holder).  The master KEEPS the sender's grant visible (so no
	 * peer can be granted a conflicting mode = the P-CONVBLK-REMOVE double-
	 * grant) and denies the upgrade with this code, which the sender maps to
	 * -EDEADLK so the XFS ilock layer (P109) releases its lower grant through
	 * the BAST drain pipeline and re-acquires the target mode FRESH (in sync,
	 * via clean FIFO — no double-grant, no conversion deadlock).
	 */
	MXFS_ERR_UPGRADE_CONFLICT,
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

/* ─── self-fence reasons ─────────────────────────────────────────────────
 *
 * A self-fence is the most severe event this node can emit: it force-shuts
 * down a LIVE mount.  Four independent detectors can fire it, and until
 * sess79 all four reported the SAME cause to the operator — the sess131 one,
 * "device reformatted under live mount".  Three of the four were therefore
 * lying: a node fenced by a peer told its admin the shared LUN had been
 * re-mkfs'd, which is a data-loss panic response to what is actually normal
 * cluster fencing.  The reason travels with the callback so every layer
 * (disklock → v5_mount → XFS) names the detector that actually fired.
 */
enum mxfs_self_fence_reason {
	/* disklock HB: on-disk MXFS super fs_uuid no longer matches our
	 * volume — the device really was re-mkfs'd under this live mount. */
	MXFS_SELF_FENCE_FS_IDENTITY = 0,
	/* disklock HB: own-slot CAS miscompared against a foreign image — a
	 * survivor laid a recovery guard/descriptor on our heartbeat slot and
	 * is replaying our journal slice. */
	MXFS_SELF_FENCE_SLOT_TAKEOVER,
	/* SCSI PR: our own reservation key was gone when we tried to fence a
	 * peer — somebody preempted us while we thought we were the fencer. */
	MXFS_SELF_FENCE_PR_KEY_LOST_FENCING,
	/* SCSI PR: periodic self-check found our key preempted. */
	MXFS_SELF_FENCE_PR_KEY_PREEMPTED,
};

static inline const char *mxfs_self_fence_reason_name(int reason)
{
	switch (reason) {
	case MXFS_SELF_FENCE_FS_IDENTITY:
		return "FS_IDENTITY";
	case MXFS_SELF_FENCE_SLOT_TAKEOVER:
		return "SLOT_TAKEOVER";
	case MXFS_SELF_FENCE_PR_KEY_LOST_FENCING:
		return "PR_KEY_LOST_FENCING";
	case MXFS_SELF_FENCE_PR_KEY_PREEMPTED:
		return "PR_KEY_PREEMPTED";
	default:
		return "UNKNOWN";
	}
}

/* One-line operator-facing explanation of what actually happened.  Kept next
 * to the enum so a new detector cannot be added without writing one. */
static inline const char *mxfs_self_fence_reason_desc(int reason)
{
	switch (reason) {
	case MXFS_SELF_FENCE_FS_IDENTITY:
		return "device was reformatted under this live mount (MXFS "
		       "super fs_uuid no longer matches the mounted volume)";
	case MXFS_SELF_FENCE_SLOT_TAKEOVER:
		return "a surviving peer declared this node dead and is "
		       "replaying its journal slice — this mount has been "
		       "fenced by the cluster, the device is intact";
	case MXFS_SELF_FENCE_PR_KEY_LOST_FENCING:
		return "this node's SCSI PR reservation key was already gone "
		       "when it tried to fence a peer — it was preempted by "
		       "the cluster, the device is intact";
	case MXFS_SELF_FENCE_PR_KEY_PREEMPTED:
		return "this node's SCSI PR reservation key was preempted by "
		       "a peer — this mount has been fenced by the cluster, "
		       "the device is intact";
	default:
		return "unknown self-fence detector";
	}
}

/* ─── FNV-1a hash: UUID → volume_id ─── */

#define MXFS_FNV1A_64_INIT   0xcbf29ce484222325ULL
#define MXFS_FNV1A_64_PRIME  0x100000001b3ULL

static inline mxfs_volume_id_t mxfs_uuid_to_volume_id(
	const uint8_t *uuid, unsigned int len)
{
	mxfs_volume_id_t hash = MXFS_FNV1A_64_INIT;
	unsigned int i;

	for (i = 0; i < len; i++) {
		hash ^= uuid[i];
		hash *= MXFS_FNV1A_64_PRIME;
	}

	return hash;
}

#endif /* MXFS_COMMON_H */
