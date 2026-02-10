/*
 * MXFS — Multinode XFS
 * Volume management
 *
 * Tracks which XFS volumes are shared via MXFS, their mount state,
 * and coordinates mount/unmount across the cluster.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_VOLUME_H
#define MXFSD_VOLUME_H

#include <mxfs/mxfs_common.h>
#include <stdbool.h>
#include <pthread.h>

enum mxfsd_volume_state {
	MXFSD_VOL_UNKNOWN = 0,
	MXFSD_VOL_CONFIGURED,   /* in config but not mounted */
	MXFSD_VOL_MOUNTING,
	MXFSD_VOL_ACTIVE,       /* mounted and sharing */
	MXFSD_VOL_UNMOUNTING,
	MXFSD_VOL_ERROR,
};

struct mxfsd_volume {
	mxfs_volume_id_t          id;
	char                      name[MXFS_VOLUME_NAME_MAX];
	char                      device[MXFS_PATH_MAX];
	char                      mount_point[MXFS_PATH_MAX];
	enum mxfsd_volume_state   state;
	uint32_t                  mount_nodes;  /* bitmask of nodes with this mounted */
	uint32_t                  journal_slots;
};

struct mxfsd_volume_ctx {
	struct mxfsd_volume volumes[MXFS_MAX_VOLUMES];
	int                 volume_count;
	mxfs_node_id_t      local_node;
	pthread_mutex_t     lock;
};

int  mxfsd_volume_init(struct mxfsd_volume_ctx *ctx, mxfs_node_id_t local_node);
void mxfsd_volume_shutdown(struct mxfsd_volume_ctx *ctx);

int  mxfsd_volume_add(struct mxfsd_volume_ctx *ctx, const char *name,
                     const char *device);

int  mxfsd_volume_set_mounted(struct mxfsd_volume_ctx *ctx,
                              mxfs_volume_id_t id, const char *mount_point);
int  mxfsd_volume_set_unmounted(struct mxfsd_volume_ctx *ctx,
                                mxfs_volume_id_t id);

struct mxfsd_volume *mxfsd_volume_find_by_id(struct mxfsd_volume_ctx *ctx,
                                             mxfs_volume_id_t id);
struct mxfsd_volume *mxfsd_volume_find_by_device(struct mxfsd_volume_ctx *ctx,
                                                 const char *device);

#endif /* MXFSD_VOLUME_H */
