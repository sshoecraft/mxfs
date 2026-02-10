/*
 * MXFS — Multinode XFS
 * Userspace netlink interface
 *
 * Handles the userspace end of the genetlink socket connecting mxfsd
 * to the mxfs.ko kernel module on the same node.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_NETLINK_H
#define MXFSD_NETLINK_H

#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include <mxfs/mxfs_netlink.h>
#include <stdbool.h>
#include <pthread.h>

/* Callback for incoming kernel messages */
typedef int (*mxfsd_nl_callback)(enum mxfs_nl_cmd cmd, void *attrs,
                                void *user_data);

/* Netlink subsystem context */
struct mxfsd_netlink_ctx {
	int                  nl_fd;        /* netlink socket */
	int                  family_id;    /* resolved genetlink family ID */
	mxfsd_nl_callback    callback;
	void                *callback_data;
	pthread_t            recv_thread;
	bool                 running;
};

int  mxfsd_netlink_init(struct mxfsd_netlink_ctx *ctx);
void mxfsd_netlink_shutdown(struct mxfsd_netlink_ctx *ctx);

int  mxfsd_netlink_set_callback(struct mxfsd_netlink_ctx *ctx,
                                mxfsd_nl_callback cb, void *user_data);

/* Send messages to kernel module */
int  mxfsd_netlink_send_lock_grant(struct mxfsd_netlink_ctx *ctx,
                                   const struct mxfs_resource_id *resource,
                                   enum mxfs_lock_mode mode);

int  mxfsd_netlink_send_lock_deny(struct mxfsd_netlink_ctx *ctx,
                                  const struct mxfs_resource_id *resource,
                                  enum mxfs_error status);

int  mxfsd_netlink_send_cache_inval(struct mxfsd_netlink_ctx *ctx,
                                    const struct mxfs_resource_id *resource,
                                    uint64_t offset, uint64_t len);

int  mxfsd_netlink_send_node_status(struct mxfsd_netlink_ctx *ctx,
                                    mxfs_node_id_t node,
                                    enum mxfs_node_state state);

int  mxfsd_netlink_send_recovery_start(struct mxfsd_netlink_ctx *ctx);
int  mxfsd_netlink_send_recovery_done(struct mxfsd_netlink_ctx *ctx);

#endif /* MXFSD_NETLINK_H */
