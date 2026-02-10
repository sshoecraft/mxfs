/*
 * MXFS — Multinode XFS
 * Lease management
 *
 * Tracks lease state for all known nodes. A node is alive if and only if
 * its lease is current. Lease expiry is the sole fencing mechanism:
 * expired lease = node is dead, its locks are invalid, its journal
 * must be replayed before anyone else touches those resources.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_LEASE_H
#define MXFSD_LEASE_H

#include <mxfs/mxfs_common.h>
#include <stdbool.h>
#include <pthread.h>

/* Per-node lease state */
struct mxfsd_node_lease {
	mxfs_node_id_t      node_id;
	mxfs_epoch_t        epoch;
	uint64_t            granted_at_ms;    /* monotonic */
	uint64_t            duration_ms;
	uint64_t            last_renewal_ms;  /* monotonic */
	enum mxfs_node_state state;
	int                 missed_renewals;
};

/* Lease subsystem context */
struct mxfsd_lease_ctx {
	struct mxfsd_node_lease nodes[MXFS_MAX_NODES];
	int                     node_count;
	uint64_t                default_duration_ms;
	uint64_t                renew_interval_ms;
	uint64_t                timeout_ms;
	mxfs_node_id_t          local_node;
	pthread_t               renew_thread;     /* local lease renewal */
	pthread_t               monitor_thread;   /* remote lease monitoring */
	pthread_mutex_t         lock;
	bool                    running;
};

/* Callback when a node's lease expires */
typedef void (*mxfsd_lease_expire_fn)(mxfs_node_id_t node, void *user_data);

int  mxfsd_lease_init(struct mxfsd_lease_ctx *ctx, mxfs_node_id_t local_node,
                     uint64_t duration_ms, uint64_t renew_ms,
                     uint64_t timeout_ms);
void mxfsd_lease_shutdown(struct mxfsd_lease_ctx *ctx);

int  mxfsd_lease_set_expire_callback(struct mxfsd_lease_ctx *ctx,
                                     mxfsd_lease_expire_fn fn,
                                     void *user_data);

int  mxfsd_lease_register_node(struct mxfsd_lease_ctx *ctx,
                               mxfs_node_id_t node);

int  mxfsd_lease_renew_local(struct mxfsd_lease_ctx *ctx);
int  mxfsd_lease_process_renewal(struct mxfsd_lease_ctx *ctx,
                                 mxfs_node_id_t node, mxfs_epoch_t epoch);

bool mxfsd_lease_is_valid(struct mxfsd_lease_ctx *ctx, mxfs_node_id_t node,
                          uint64_t now_ms);

struct mxfsd_node_lease *mxfsd_lease_get(struct mxfsd_lease_ctx *ctx,
                                         mxfs_node_id_t node);

#endif /* MXFSD_LEASE_H */
