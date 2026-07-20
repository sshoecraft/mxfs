/*
 * MXFS — Multinode XFS
 * Portable SCSI-3 Persistent Reservations for I/O fencing
 *
 * Ported from kernel/mxfs_scsipr.c — all pr_ops calls replaced
 * with PAL SCSI PR functions. The PAL layer handles platform-specific
 * details (SG_IO on Linux userspace, pr_ops in kernel, IOKit on macOS).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "scsipr.h"

struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
                                            const char *dev_name,
                                            mxfs_node_id_t node_id)
{
    struct mxfs_scsipr_ctx *ctx;

    if (!dev)
        return NULL;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->dev = dev;
    ctx->local_key = (uint64_t)node_id;
    ctx->reserved = false;

    if (dev_name)
        snprintf(ctx->dev_name, sizeof(ctx->dev_name), "%s", dev_name);
    else
        snprintf(ctx->dev_name, sizeof(ctx->dev_name), "(unknown)");

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: initialized for '%s' key=0x%llx",
                 ctx->dev_name, (unsigned long long)ctx->local_key);

    return ctx;
}

void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->local_key) {
        int ret = mxfs_scsipr_unregister(ctx);
        if (ret)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: unregister on shutdown failed: %d", ret);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: shutdown for '%s'", ctx->dev_name);

    mxfs_pal_free(ctx);
}

int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_register(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping register",
                     ctx->dev_name);
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: SCSI persistent reservation register failed "
                     "on '%s': %d (hardware fencing unavailable)",
                     ctx->dev_name, ret);
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: registered key 0x%llx on '%s'",
                 (unsigned long long)ctx->local_key, ctx->dev_name);

    return 0;
}

int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping reserve",
                     ctx->dev_name);
        return 0;
    }

    if (ret == -EBUSY) {
        /*
         * Another node holds the reservation. With type 5
         * (WRITE EXCLUSIVE - REGISTRANTS ONLY), we only need
         * to be registered to do I/O. The reservation holder
         * is irrelevant for data access.
         */
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "scsipr: '%s' reservation held by another node "
                     "(we are registered)", ctx->dev_name);
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: reserve failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: reservation acquired on '%s'", ctx->dev_name);

    return 0;
}

int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key)
{
    int ret;

    if (!ctx || !ctx->dev || victim_key == 0)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, victim_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR preempt support",
                     ctx->dev_name);
        return ret;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: preempt of key 0x%llx failed on '%s': %d",
                     (unsigned long long)victim_key, ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: preempted key 0x%llx on '%s'",
                 (unsigned long long)victim_key, ctx->dev_name);

    return 0;
}

int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_unregister(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping unregister",
                     ctx->dev_name);
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: unregister failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = false;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: unregistered key 0x%llx from '%s'",
                 (unsigned long long)ctx->local_key, ctx->dev_name);

    return 0;
}

int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
                           int max_keys, int *count)
{
    int ret;

    if (!ctx || !ctx->dev || !keys || !count || max_keys <= 0)
        return -EINVAL;

    *count = 0;

    ret = mxfs_pal_scsi_pr_read_keys(ctx->dev, keys, max_keys, count);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR read_keys support",
                     ctx->dev_name);
        return ret;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: read_keys failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: read_keys on '%s': %d keys",
                 ctx->dev_name, *count);

    return 0;
}
