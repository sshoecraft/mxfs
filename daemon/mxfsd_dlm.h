/*
 * MXFS — Multinode XFS
 * DLM protocol engine (daemon side)
 *
 * Manages the lock table, processes lock requests from the local kernel
 * module and from remote peers, enforces the compatibility matrix, and
 * handles lock queuing, granting, and conversion.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_DLM_H
#define MXFSD_DLM_H

#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include <pthread.h>

/* A single lock held or requested by a node */
struct mxfsd_lock {
	struct mxfs_resource_id resource;
	mxfs_node_id_t          owner;
	enum mxfs_lock_mode     mode;
	enum mxfs_lock_state    state;
	uint32_t                flags;
	uint64_t                granted_at_ms;
	struct mxfsd_lock      *next;     /* hash chain / queue link */
};

/* Lock table — the core DLM data structure */
struct mxfsd_lock_table {
	struct mxfsd_lock     **buckets;    /* hash table of locks */
	uint32_t                bucket_count;
	uint32_t                lock_count;
	pthread_rwlock_t        rwlock;
};

/* Callback fired when a queued lock gets promoted to GRANTED */
typedef void (*mxfsd_dlm_grant_cb)(const struct mxfs_resource_id *resource,
                                    mxfs_node_id_t owner,
                                    enum mxfs_lock_mode mode,
                                    void *user_data);

/* DLM engine context */
struct mxfsd_dlm_ctx {
	struct mxfsd_lock_table  table;
	mxfs_node_id_t           local_node;
	mxfs_epoch_t             current_epoch;
	pthread_mutex_t          epoch_lock;
	mxfsd_dlm_grant_cb      grant_cb;
	void                    *grant_cb_data;
};

/* Lifecycle */
int  mxfsd_dlm_init(struct mxfsd_dlm_ctx *ctx, mxfs_node_id_t local_node,
                    uint32_t table_size);
void mxfsd_dlm_shutdown(struct mxfsd_dlm_ctx *ctx);

/* Lock operations */
int  mxfsd_dlm_lock_request(struct mxfsd_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource,
                            mxfs_node_id_t requester,
                            enum mxfs_lock_mode mode, uint32_t flags);

int  mxfsd_dlm_lock_release(struct mxfsd_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource,
                            mxfs_node_id_t owner);

int  mxfsd_dlm_lock_convert(struct mxfsd_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource,
                            mxfs_node_id_t owner,
                            enum mxfs_lock_mode new_mode);

/* Compatibility check */
int  mxfsd_dlm_modes_compatible(enum mxfs_lock_mode held,
                                enum mxfs_lock_mode requested);

/* Node failure — release all locks held by a dead node */
int  mxfsd_dlm_purge_node(struct mxfsd_dlm_ctx *ctx, mxfs_node_id_t node);

/* Grant callback — fires when a queued lock is promoted */
void mxfsd_dlm_set_grant_cb(struct mxfsd_dlm_ctx *ctx,
                              mxfsd_dlm_grant_cb cb, void *data);

/* Epoch management */
mxfs_epoch_t mxfsd_dlm_advance_epoch(struct mxfsd_dlm_ctx *ctx);
mxfs_epoch_t mxfsd_dlm_get_epoch(struct mxfsd_dlm_ctx *ctx);

#endif /* MXFSD_DLM_H */
