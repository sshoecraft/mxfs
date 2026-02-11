/*
 * MXFS — Multinode XFS
 * SCSI-3 Persistent Reservations for I/O fencing
 *
 * Provides hardware-level I/O fencing by controlling access to shared
 * block devices through SCSI-3 Persistent Reservations (PR). When a
 * node is declared dead, its registration key is preempted, which
 * causes the storage target to reject all further I/O from that node
 * until it re-registers.
 *
 * Uses the SG_IO ioctl to issue PERSISTENT RESERVE IN/OUT commands
 * directly to the device. Reservation type is WRITE EXCLUSIVE —
 * REGISTRANTS ONLY (type 5): all registered nodes can do I/O, but
 * unregistered nodes are fenced off.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_SCSI_PR_H
#define MXFSD_SCSI_PR_H

#include <mxfs/mxfs_common.h>
#include <stdint.h>
#include <pthread.h>

/* SCSI-3 PR context for a single shared device */
struct mxfsd_scsi_pr_ctx {
	char            device[MXFS_PATH_MAX];
	int             fd;          /* O_RDWR to the raw device */
	uint64_t        local_key;   /* this node's registration key */
	pthread_mutex_t lock;
};

/* Lifecycle */
int  mxfsd_scsi_pr_init(struct mxfsd_scsi_pr_ctx *ctx, const char *device,
                         uint64_t key);
void mxfsd_scsi_pr_shutdown(struct mxfsd_scsi_pr_ctx *ctx);

/* Register this node's key with the device */
int  mxfsd_scsi_pr_register(struct mxfsd_scsi_pr_ctx *ctx);

/* Acquire WRITE EXCLUSIVE - REGISTRANTS ONLY reservation (type 5) */
int  mxfsd_scsi_pr_reserve(struct mxfsd_scsi_pr_ctx *ctx);

/* Fence a dead node by preempting its registration key */
int  mxfsd_scsi_pr_preempt(struct mxfsd_scsi_pr_ctx *ctx, uint64_t victim_key);

/* Read all currently registered keys */
int  mxfsd_scsi_pr_read_keys(struct mxfsd_scsi_pr_ctx *ctx, uint64_t *keys,
                              int *count, int max);

/* Read current reservation holder */
int  mxfsd_scsi_pr_read_reservation(struct mxfsd_scsi_pr_ctx *ctx,
                                     uint64_t *key, uint8_t *type);

/* Clean unregister on shutdown */
int  mxfsd_scsi_pr_unregister(struct mxfsd_scsi_pr_ctx *ctx);

#endif /* MXFSD_SCSI_PR_H */
