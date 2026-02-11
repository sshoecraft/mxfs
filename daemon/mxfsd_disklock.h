/*
 * MXFS — Multinode XFS
 * On-disk lock state persistence
 *
 * Persists lock state and node heartbeats to a reserved file on the shared
 * XFS volume (.mxfs/lockstate). Uses O_DIRECT for sector-aligned atomic I/O.
 *
 * File layout:
 *   Offset 0 .. 32767:      heartbeat records (64 slots x 512 bytes)
 *   Offset 32768 .. end:     lock records (65536 slots x 512 bytes)
 *
 * This enables:
 *   - Lock state survives daemon restarts and master failover
 *   - Self-fencing: if you can't write locks, you can't write data
 *   - New master reads disk to reconstruct the lock table
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_DISKLOCK_H
#define MXFSD_DISKLOCK_H

#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include <stdbool.h>
#include <pthread.h>

#define MXFS_DISKLOCK_RECORD_SIZE  512
#define MXFS_DISKLOCK_MAX_SLOTS    65536
#define MXFS_DISKLOCK_HB_SLOTS     64
#define MXFS_DISKLOCK_MAGIC        0x4D584C4B  /* "MXLK" */

#define MXFS_DISKLOCK_FLAG_ACTIVE  1
#define MXFS_DISKLOCK_FLAG_EMPTY   0

/* Offset where lock records begin (after heartbeat region) */
#define MXFS_DISKLOCK_HB_SIZE      (MXFS_DISKLOCK_HB_SLOTS * MXFS_DISKLOCK_RECORD_SIZE)
#define MXFS_DISKLOCK_LOCK_OFFSET  MXFS_DISKLOCK_HB_SIZE

/* Total file size: heartbeat region + lock region */
#define MXFS_DISKLOCK_FILE_SIZE    (MXFS_DISKLOCK_HB_SIZE + \
                                    (uint64_t)MXFS_DISKLOCK_MAX_SLOTS * MXFS_DISKLOCK_RECORD_SIZE)

/*
 * On-disk lock record — exactly 512 bytes, one sector.
 *
 * Layout (64 bytes used, 448 reserved):
 *   magic            4
 *   flags            4
 *   resource        32  (mxfs_resource_id)
 *   owner            4
 *   mode             1
 *   state            1
 *   pad1             2
 *   granted_at_ms    8
 *   epoch            8
 *   reserved       448
 *   total          512
 */
struct mxfsd_disklock_record {
	uint32_t                magic;
	uint32_t                flags;
	struct mxfs_resource_id resource;
	mxfs_node_id_t          owner;
	uint8_t                 mode;
	uint8_t                 state;
	uint8_t                 pad1[2];
	uint64_t                granted_at_ms;
	mxfs_epoch_t            epoch;
	uint8_t                 reserved[448];
};

/*
 * On-disk heartbeat record — exactly 512 bytes, one sector.
 *
 * Layout (40 bytes used, 472 reserved):
 *   magic            4
 *   flags            4
 *   node_id          4
 *   pad1             4  (alignment for uint64_t)
 *   timestamp_ms     8
 *   epoch            8
 *   lock_count       8
 *   reserved       472
 *   total          512
 */
struct mxfsd_disklock_heartbeat {
	uint32_t        magic;
	uint32_t        flags;
	mxfs_node_id_t  node_id;
	uint32_t        pad1;
	uint64_t        timestamp_ms;
	mxfs_epoch_t    epoch;
	uint64_t        lock_count;
	uint8_t         reserved[472];
};

/* Disk lock subsystem context */
struct mxfsd_disklock_ctx {
	int             fd;
	char            path[MXFS_PATH_MAX];
	mxfs_node_id_t  local_node;
	pthread_mutex_t lock;
	pthread_t       heartbeat_thread;
	bool            running;
};

/* Lifecycle */
int  mxfsd_disklock_init(struct mxfsd_disklock_ctx *ctx,
                         const char *mount_point,
                         mxfs_node_id_t local_node);
void mxfsd_disklock_shutdown(struct mxfsd_disklock_ctx *ctx);

/* Lock record operations */
int  mxfsd_disklock_write_grant(struct mxfsd_disklock_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner,
                                enum mxfs_lock_mode mode,
                                mxfs_epoch_t epoch);

int  mxfsd_disklock_clear_grant(struct mxfsd_disklock_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner);

/* Read all active lock records from disk (for recovery / master failover) */
int  mxfsd_disklock_read_all(struct mxfsd_disklock_ctx *ctx,
                             struct mxfsd_disklock_record *records,
                             int *count, int max);

/* Purge all records owned by a dead node */
int  mxfsd_disklock_purge_node(struct mxfsd_disklock_ctx *ctx,
                               mxfs_node_id_t node);

/* Heartbeat operations */
int  mxfsd_disklock_write_heartbeat(struct mxfsd_disklock_ctx *ctx);
int  mxfsd_disklock_read_heartbeat(struct mxfsd_disklock_ctx *ctx,
                                   mxfs_node_id_t node,
                                   struct mxfsd_disklock_heartbeat *hb);

/* Start/stop the heartbeat writer thread */
int  mxfsd_disklock_start_heartbeat(struct mxfsd_disklock_ctx *ctx);
void mxfsd_disklock_stop_heartbeat(struct mxfsd_disklock_ctx *ctx);

#endif /* MXFSD_DISKLOCK_H */
