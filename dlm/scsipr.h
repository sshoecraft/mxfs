/*
 * MXFS — Multinode XFS
 * Portable SCSI-3 Persistent Reservations for I/O fencing
 *
 * Hardware-level I/O fencing using SCSI-3 PR. With WRITE EXCLUSIVE -
 * REGISTRANTS ONLY (type 5), all registered nodes can perform I/O
 * while unregistered nodes are fenced off by storage target hardware.
 *
 * Ported from kernel/mxfs_scsipr.{c,h} — kernel pr_ops replaced
 * with PAL SCSI PR functions.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_SCSIPR_H
#define MXFS_LIBMXFS_SCSIPR_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"

struct mxfs_scsipr_ctx {
    mxfs_bdev_t     *dev;
    char            dev_name[MXFS_PATH_MAX];
    uint64_t        local_key;
    bool            reserved;
};

/* Lifecycle */
struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
                                            const char *dev_name,
                                            mxfs_node_id_t node_id);
void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx);

/* Register this node's key (idempotent, uses REGISTER_AND_IGNORE) */
int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx);

/* Acquire WRITE EXCLUSIVE - REGISTRANTS ONLY reservation */
int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx);

/* Preempt a dead node's key */
int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key);

/* Unregister this node's key on clean shutdown */
int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx);

/* Read all currently registered keys */
int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
                           int max_keys, int *count);

#endif /* MXFS_LIBMXFS_SCSIPR_H */
