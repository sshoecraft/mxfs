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

    /* v0.11.80 (D4): safety-net unregister only if the key is still
     * believed registered — the normal teardown paths unregister
     * explicitly first, and re-issuing PROUT for an absent key is a
     * spec-level RESERVATION CONFLICT (observed as bare conflicts on
     * the QNAP battery). */
    if (ctx->local_key && ctx->registered) {
        int ret = mxfs_scsipr_unregister(ctx);
        if (ret)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: unregister on shutdown failed: %d", ret);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: shutdown for '%s'", ctx->dev_name);

    mxfs_pal_free(ctx);
}

uint64_t mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx)
{
    return ctx ? ctx->local_key : 0;
}

void mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: abandoned for '%s' (deferred unregister)",
                 ctx->dev_name);

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

    ctx->registered = true;
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

int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
                           mxfs_node_id_t victim_node, int live_members)
{
    uint64_t victim_key = (uint64_t)victim_node;
    uint64_t keys[MXFS_MAX_NODES];
    int count = 0, i, ret;
    bool victim_present = false, own_present = false;

    if (!ctx || !ctx->dev || !victim_key)
        return -EINVAL;

    /* SPC hygiene: READ KEYS before PREEMPT.  Preempting a key that is
     * not registered is a RESERVATION CONFLICT by spec; classify first. */
    ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_MAX_NODES, &count);
    if (ret == -EOPNOTSUPP) {
        /* No PR support — nothing to fence at the target level. */
        return 0;
    }
    if (ret) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-FENCE read_keys failed on '%s': %d "
                     "(cannot classify; skipping preempt)",
                     ctx->dev_name, ret);
        return ret;
    }

    for (i = 0; i < count; i++) {
        if (keys[i] == victim_key)
            victim_present = true;
        if (keys[i] == ctx->local_key)
            own_present = true;
    }

    /* Topology sanity: per-node PR needs one registration per live
     * member.  Fewer keys than live members means the rig cannot hold
     * per-node registrations (shared I_T nexus: each node's REGISTER
     * overwrites the previous one's — measured on the tcm_loop VM rig,
     * where ALL VMs funnel through one host block device) or the target
     * purged registrations wholesale.  In that state key-bookkeeping
     * proves nothing about fencing: no preempt (removing the single
     * shared registration would fence EVERYONE incl. us), no self-fence
     * (our key being "missing" is expected, not a preemption).  PR is
     * ADVISORY here — D1 (EBADE on write = fencing event) plus
     * lease/disklock exclusion carry the fencing duty. */
    if (count < live_members) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-ADVISORY '%s' has %d key(s) for %d live "
                     "member(s) — per-node PR not usable on this topology; "
                     "skipping preempt/self-fence (D1+lease fencing apply)",
                     ctx->dev_name, count, live_members);
        return 0;
    }

    if (!own_present) {
        if (ctx->registered && live_members >= 2) {
            /* UNAMBIGUOUS preemption: every other live member's key is
             * accounted for and OURS specifically vanished (another node
             * preempted us, or the target removed exactly us).  We may
             * be FENCED: every write can bounce off a WE-RO reservation
             * we are no longer part of.  NEVER auto-re-register (that
             * would resurrect a deliberately-fenced node) — the caller
             * must self-fence. */
            mxfs_pal_log(MXFS_LOG_ERR,
                         "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                         "'%s' (%d key(s) present, %d live) — node was "
                         "preempted",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         count, live_members);
            return -ESTALE;
        }
        if (ctx->registered) {
            /* Sole survivor with our key gone: nobody live is left to
             * have excluded us on purpose, and a lone stale key (the
             * victim's, or a shared-nexus overwrite) cannot prove a
             * preemption.  Log and rely on D1: if the target really
             * fenced us, the next write bounces EBADE and shuts us
             * down reactively. */
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                         "'%s' (%d key(s), sole survivor) — ambiguous; "
                         "relying on reactive D1 fencing",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         count);
            return 0;
        }
        /* We never registered (PR not in use for this mount) — a PREEMPT
         * from an unregistered initiator is itself a conflict; leave
         * fencing to lease/disklock exclusion. */
        return 0;
    }

    if (!victim_present) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-FENCE victim key 0x%llx already absent "
                     "on '%s' (fenced elsewhere or never registered)",
                     (unsigned long long)victim_key, ctx->dev_name);
        return 0;
    }

    ret = mxfs_scsipr_preempt(ctx, victim_key);
    if (ret == 0)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-FENCE preempted dead node %u "
                     "(key 0x%llx) on '%s'",
                     victim_node, (unsigned long long)victim_key,
                     ctx->dev_name);
    return ret;
}

int mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members)
{
    uint64_t keys[MXFS_MAX_NODES];
    int count = 0, i, ret;
    bool own_present = false;

    if (!ctx || !ctx->dev)
        return -EINVAL;
    if (!ctx->registered)
        return 0;       /* not participating in PR — nothing to check */

    ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_MAX_NODES, &count);
    if (ret == -EOPNOTSUPP)
        return 0;
    if (ret) {
        /* Transient READ KEYS failure — retry next tick, but never
         * silently: a persistently failing self-check looks identical
         * to a healthy one otherwise. */
        static int d8_rk_fail_logs;

        if (d8_rk_fail_logs < 8) {
            d8_rk_fail_logs++;
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: P-PR-SELFCHECK read_keys failed on '%s': %d",
                         ctx->dev_name, ret);
        }
        return ret;
    }

    for (i = 0; i < count; i++)
        if (keys[i] == ctx->local_key)
            own_present = true;

    if (own_present) {
        ctx->advisory_logged = false;
        return 0;
    }

    /* Same classification as fence_node: self-fence only on the
     * UNAMBIGUOUS preemption signature. */
    if (count >= live_members && live_members >= 2) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                     "'%s' (self-check: %d key(s), %d live) — node was "
                     "preempted",
                     (unsigned long long)ctx->local_key, ctx->dev_name,
                     count, live_members);
        return -ESTALE;
    }
    if (!ctx->advisory_logged) {
        ctx->advisory_logged = true;
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-ADVISORY '%s' self-check: own key gone, "
                     "%d key(s) for %d live member(s) — per-node PR not "
                     "trustworthy on this topology; D1+lease fencing apply",
                     ctx->dev_name, count, live_members);
    }
    return 0;
}

int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx)
{
    uint64_t keys[MXFS_MAX_NODES];
    int count = 0, i, ret;
    bool own_present = false;

    if (!ctx || !ctx->dev || !ctx->registered)
        return 0;

    ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_MAX_NODES, &count);
    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-PROBE '%s': READ KEYS unsupported — "
                     "PR state not verifiable (advisory)", ctx->dev_name);
        return 0;
    }
    if (ret)
        return ret;

    for (i = 0; i < count; i++)
        if (keys[i] == ctx->local_key)
            own_present = true;

    if (!own_present)
        /* Register reported success but our key is not visible: the
         * target either shares one I_T nexus across nodes (each
         * register overwrites the last) or silently drops
         * registrations.  Fencing must not trust PR here. */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-PROBE '%s': own key 0x%llx NOT visible "
                     "after successful register (%d key(s)) — per-node PR "
                     "unusable on this target/topology (advisory only)",
                     ctx->dev_name,
                     (unsigned long long)ctx->local_key, count);
    else
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-PROBE '%s': own key 0x%llx visible, "
                     "%d key(s) registered — per-node PR active",
                     ctx->dev_name,
                     (unsigned long long)ctx->local_key, count);
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
        ctx->registered = false;
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: unregister failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = false;
    ctx->registered = false;
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
