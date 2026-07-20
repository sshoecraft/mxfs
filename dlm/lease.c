/*
 * MXFS — Multinode XFS
 * Portable lease management
 *
 * Three threads: one to periodically send a UDP multicast lease
 * heartbeat, one to receive heartbeats from other nodes, and one
 * to monitor remote nodes for lease expiry.
 *
 * Lease heartbeats were originally sent via TCP through the DLM peer
 * connections.  At 16+ nodes (120 TCP peer connections), DLM traffic
 * congests TCP, blocking lease sends and causing false node-death
 * declarations.  A single UDP multicast packet now replaces N TCP
 * unicast sends.
 *
 * Ported from kernel/mxfs_lease.c — delayed_work replaced with PAL
 * threads + sleep loops, ktime_get_ns replaced with mxfs_pal_time_ms.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "lease.h"

/*
 * Find a node in the lease table by node_id.
 * Caller must hold ctx->lock.
 */
static struct mxfs_node_lease *lease_find(struct mxfs_lease_ctx *ctx,
                                           mxfs_node_id_t node_id)
{
    int i;

    for (i = 0; i < ctx->node_count; i++) {
        if (ctx->nodes[i].node_id == node_id)
            return &ctx->nodes[i];
    }
    return NULL;
}

/*
 * Renewal thread: sends a single UDP multicast heartbeat packet to
 * the lease multicast group, then sleeps for the renewal interval.
 * A single multicast send replaces N TCP unicast sends, eliminating
 * head-of-line blocking under DLM traffic congestion.
 */
static void mxfs_lease_renew_fn(void *arg)
{
    struct mxfs_lease_ctx *ctx = arg;
    struct mxfs_lease_udp_msg msg;
    struct mxfs_node_lease *nl;
    uint64_t start;
    uint64_t elapsed;
    uint32_t sleep_ms;

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: renew thread started (RT, "
                 "interval=%llu ms, UDP multicast %s:%u)",
                 (unsigned long long)ctx->renew_interval_ms,
                 ctx->send_addr, ctx->udp_port);

    while (ctx->running) {
        start = mxfs_pal_time_ms();

        /* Build UDP heartbeat packet */
        memset(&msg, 0, sizeof(msg));
        msg.magic = mxfs_cpu_to_le32(MXFS_LEASE_UDP_MAGIC);
        msg.version = mxfs_cpu_to_le16(MXFS_LEASE_UDP_VERSION);
        msg.node_id = ctx->local_node;
        memcpy(msg.volume_uuid, ctx->volume_uuid, 16);
        msg.lease_duration_ms = mxfs_cpu_to_le64(ctx->default_duration_ms);

        /* Update local node's lease timestamp */
        mxfs_pal_mutex_lock(ctx->lock);
        nl = lease_find(ctx, ctx->local_node);
        if (nl) {
            nl->last_renewal = mxfs_pal_time_ms();
            nl->state = MXFS_NODE_ACTIVE;
            nl->missed_renewals = 0;
        }
        mxfs_pal_mutex_unlock(ctx->lock);

        /* Single UDP multicast send — replaces N TCP unicast sends */
        if (ctx->udp_sock) {
            mxfs_pal_udp_sendto(ctx->udp_sock, &msg, sizeof(msg),
                                ctx->send_addr, ctx->udp_port);
        }

        /* Sleep for the remainder of the renewal interval.
         * Use condvar timed wait instead of sleep so that
         * mxfs_lease_stop() can wake us immediately. */
        elapsed = mxfs_pal_time_ms() - start;
        if (elapsed < ctx->renew_interval_ms)
            sleep_ms = (uint32_t)(ctx->renew_interval_ms - elapsed);
        else
            sleep_ms = 1;   /* yield but don't skip entirely */
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running)
            mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                    ctx->shutdown_lock, sleep_ms);
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: renew thread exiting");
}

/*
 * UDP receiver thread: listens for multicast lease heartbeats
 * from other nodes. Validates magic/version/volume UUID and
 * feeds renewals into the lease state machine.
 */
static void mxfs_lease_udp_recv_fn(void *arg)
{
    struct mxfs_lease_ctx *ctx = arg;
    struct mxfs_lease_udp_msg pkt;
    char sender_host[64];
    uint16_t sender_port;
    int ret;

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: UDP recv thread started on %s:%u",
                 ctx->use_broadcast ? "broadcast" : ctx->mcast_addr,
                 ctx->udp_port);

    while (ctx->running) {
        memset(&pkt, 0, sizeof(pkt));
        memset(sender_host, 0, sizeof(sender_host));
        sender_port = 0;

        ret = mxfs_pal_udp_recvfrom(ctx->udp_sock,
                                     &pkt, sizeof(pkt),
                                     sender_host, sizeof(sender_host),
                                     &sender_port);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -ETIMEDOUT || ret == -EINTR)
                continue;
            if (!ctx->running)
                break;
            mxfs_pal_log(MXFS_LOG_WARN,
                         "lease: UDP recvfrom failed: %d", ret);
            continue;
        }
        if (ret == 0) {
            if (!ctx->running)
                break;
            continue;
        }

        if (ret < (int)sizeof(pkt))
            continue;

        /* Validate magic and version */
        if (mxfs_le32_to_cpu(pkt.magic) != MXFS_LEASE_UDP_MAGIC)
            continue;
        if (mxfs_le16_to_cpu(pkt.version) != MXFS_LEASE_UDP_VERSION)
            continue;

        /* Ignore our own heartbeats */
        if (pkt.node_id == ctx->local_node)
            continue;

        /* Check volume UUID matches ours */
        if (memcmp(pkt.volume_uuid, ctx->volume_uuid, 16) != 0)
            continue;

        /* Process the renewal */
        mxfs_lease_process_renewal(ctx, pkt.node_id, 0);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: UDP recv thread exiting");
}

/*
 * Monitor thread: checks all registered remote nodes for lease
 * expiry. Transitions ACTIVE -> SUSPECT -> DEAD and fires the
 * expire callback when a node is declared dead.
 */
static void mxfs_lease_monitor_fn(void *arg)
{
    struct mxfs_lease_ctx *ctx = arg;
    struct mxfs_node_lease *nl;
    mxfs_node_id_t dead_node;
    uint64_t now;
    uint64_t elapsed;
    int i;

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: monitor thread started");

    while (ctx->running) {
        now = mxfs_pal_time_ms();

        mxfs_pal_mutex_lock(ctx->lock);

        for (i = 0; i < ctx->node_count; i++) {
            nl = &ctx->nodes[i];

            /* Skip local node and already-dead/recovering nodes */
            if (nl->node_id == ctx->local_node)
                continue;
            if (nl->state == MXFS_NODE_DEAD ||
                nl->state == MXFS_NODE_RECOVERING)
                continue;

            if (nl->last_renewal == 0)
                continue;

            elapsed = now - nl->last_renewal;

            if ((nl->state == MXFS_NODE_ACTIVE ||
                 nl->state == MXFS_NODE_JOINING) &&
                elapsed > nl->duration_ms) {
                /*
                 * Missed a renewal window.  Under I/O load the
                 * sending node's renewal thread (msleep-based) may
                 * be delayed by scheduler pressure from block I/O
                 * completions.  A single missed renewal is not
                 * grounds for SUSPECT.  Only transition after
                 * MXFS_LEASE_SUSPECT_MISSES consecutive misses.
                 *
                 * JOINING nodes are monitored identically to ACTIVE:
                 * a node that was discovered but never sent a lease
                 * renewal (or whose UDP heartbeat was lost) must
                 * still be detected as dead rather than lingering
                 * in JOINING forever.
                 */
                nl->missed_renewals++;
                if (nl->missed_renewals >= MXFS_LEASE_SUSPECT_MISSES) {
                    nl->state = MXFS_NODE_SUSPECT;
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: node %u may be unreachable "
                                 "(missed %d heartbeats, "
                                 "%llu ms since last contact)",
                                 nl->node_id,
                                 nl->missed_renewals,
                                 (unsigned long long)elapsed);
                } else {
                    mxfs_pal_log(MXFS_LOG_DEBUG,
                                 "lease: node %u missed "
                                 "renewal %d/%d "
                                 "(elapsed %llu ms)",
                                 nl->node_id,
                                 nl->missed_renewals,
                                 MXFS_LEASE_SUSPECT_MISSES,
                                 (unsigned long long)elapsed);
                }
            } else if ((nl->state == MXFS_NODE_ACTIVE ||
                        nl->state == MXFS_NODE_JOINING) &&
                       elapsed <= nl->duration_ms) {
                /* On-time renewal received — reset miss counter */
                nl->missed_renewals = 0;
            }

            if (nl->state == MXFS_NODE_SUSPECT &&
                elapsed > ctx->timeout_ms) {
                /* Lease fully expired — node is dead */
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: node %u has left the cluster "
                             "(no heartbeat for %llu seconds)",
                             nl->node_id,
                             (unsigned long long)(elapsed / 1000));

                nl->state = MXFS_NODE_DEAD;
                nl->missed_renewals = 0;
                dead_node = nl->node_id;

                /* Fire expire callback outside the lock */
                mxfs_pal_mutex_unlock(ctx->lock);

                if (ctx->expire_cb) {
                    mxfs_pal_log(MXFS_LOG_DEBUG,
                                 "lease: firing expire callback "
                                 "for node %u", dead_node);
                    ctx->expire_cb(ctx->expire_cb_data, dead_node);
                }

                mxfs_pal_mutex_lock(ctx->lock);
            }
        }

        mxfs_pal_mutex_unlock(ctx->lock);

        /* Use condvar timed wait so mxfs_lease_stop() can wake us */
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running)
            mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                    ctx->shutdown_lock,
                                    MXFS_LEASE_MONITOR_INTERVAL_MS);
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: monitor thread exiting");
}

struct mxfs_lease_ctx *mxfs_lease_create(mxfs_node_id_t local_node,
                                          const uint8_t *volume_uuid,
                                          const char *mcast_addr,
                                          uint16_t lease_port,
                                          bool use_broadcast)
{
    struct mxfs_lease_ctx *ctx;
    struct mxfs_node_lease *nl;
    int ret;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->local_node = local_node;
    ctx->default_duration_ms = MXFS_LEASE_DURATION_DEFAULT_MS;
    ctx->renew_interval_ms = MXFS_LEASE_RENEW_DEFAULT_MS;
    ctx->timeout_ms = MXFS_LEASE_TIMEOUT_DEFAULT_MS;
    ctx->node_count = 0;
    ctx->running = false;
    ctx->renew_thread = NULL;
    ctx->monitor_thread = NULL;
    ctx->udp_recv_thread = NULL;
    ctx->udp_sock = NULL;

    /* Store volume UUID for heartbeat validation */
    if (volume_uuid)
        memcpy(ctx->volume_uuid, volume_uuid, 16);

    /* UDP multicast/broadcast configuration */
    ctx->udp_port = lease_port > 0 ? lease_port : MXFS_LEASE_PORT;
    ctx->use_broadcast = use_broadcast;

    if (mcast_addr && mcast_addr[0] != '\0')
        snprintf(ctx->mcast_addr, sizeof(ctx->mcast_addr), "%s", mcast_addr);
    else
        snprintf(ctx->mcast_addr, sizeof(ctx->mcast_addr), "%s",
                 MXFS_LEASE_MCAST);

    if (use_broadcast)
        snprintf(ctx->send_addr, sizeof(ctx->send_addr), "255.255.255.255");
    else
        snprintf(ctx->send_addr, sizeof(ctx->send_addr), "%s",
                 ctx->mcast_addr);

    ctx->lock = mxfs_pal_mutex_create();
    if (!ctx->lock) {
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_lock = mxfs_pal_mutex_create();
    if (!ctx->shutdown_lock) {
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_cond = mxfs_pal_cond_create();
    if (!ctx->shutdown_cond) {
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    /* Open UDP socket for lease heartbeats */
    ctx->udp_sock = mxfs_pal_udp_open(ctx->udp_port);
    if (!ctx->udp_sock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "lease: failed to open UDP socket on port %u",
                     ctx->udp_port);
        mxfs_pal_cond_destroy(ctx->shutdown_cond);
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    /* Set receive timeout for clean shutdown */
    mxfs_pal_udp_set_recv_timeout(ctx->udp_sock, 500);

    if (use_broadcast) {
        ret = mxfs_pal_udp_set_broadcast(ctx->udp_sock);
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "lease: SO_BROADCAST failed: %d", ret);
            mxfs_pal_udp_close(ctx->udp_sock);
            mxfs_pal_cond_destroy(ctx->shutdown_cond);
            mxfs_pal_mutex_destroy(ctx->shutdown_lock);
            mxfs_pal_mutex_destroy(ctx->lock);
            mxfs_pal_free(ctx);
            return NULL;
        }
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "lease: broadcast mode, target %s:%u",
                     ctx->send_addr, ctx->udp_port);
    } else {
        ret = mxfs_pal_udp_join_multicast(ctx->udp_sock, ctx->mcast_addr);
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "lease: multicast join failed: %d", ret);
            mxfs_pal_udp_close(ctx->udp_sock);
            mxfs_pal_cond_destroy(ctx->shutdown_cond);
            mxfs_pal_mutex_destroy(ctx->shutdown_lock);
            mxfs_pal_mutex_destroy(ctx->lock);
            mxfs_pal_free(ctx);
            return NULL;
        }
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "lease: multicast mode, group %s:%u",
                     ctx->mcast_addr, ctx->udp_port);
    }

    /* Register the local node as ACTIVE */
    nl = &ctx->nodes[0];
    nl->node_id = local_node;
    nl->epoch = 0;
    nl->granted_at = mxfs_pal_time_ms();
    nl->duration_ms = ctx->default_duration_ms;
    nl->last_renewal = mxfs_pal_time_ms();
    nl->state = MXFS_NODE_ACTIVE;
    nl->missed_renewals = 0;
    ctx->node_count = 1;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "lease: initialized for node %u "
                 "(duration=%llu ms, renew=%llu ms, timeout=%llu ms, "
                 "UDP %s:%u)",
                 local_node,
                 (unsigned long long)ctx->default_duration_ms,
                 (unsigned long long)ctx->renew_interval_ms,
                 (unsigned long long)ctx->timeout_ms,
                 use_broadcast ? "broadcast" : ctx->mcast_addr,
                 ctx->udp_port);

    return ctx;
}

void mxfs_lease_destroy(struct mxfs_lease_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_lease_stop(ctx);

    if (ctx->udp_sock) {
        mxfs_pal_udp_close(ctx->udp_sock);
        ctx->udp_sock = NULL;
    }

    if (ctx->shutdown_cond)
        mxfs_pal_cond_destroy(ctx->shutdown_cond);
    if (ctx->shutdown_lock)
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
    mxfs_pal_mutex_destroy(ctx->lock);
    mxfs_pal_free(ctx);

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: shutdown complete");
}

int mxfs_lease_start(struct mxfs_lease_ctx *ctx)
{
    if (!ctx)
        return -EINVAL;

    ctx->running = true;

    /*
     * Create lease threads with real-time (low) priority.
     * Under heavy iSCSI I/O, normal CFS threads get starved for
     * 90-142 seconds by block I/O completions.  RT priority
     * ensures lease renewals are sent even when the system is
     * saturated with data I/O.
     */
    ctx->renew_thread = mxfs_pal_thread_create_rt(mxfs_lease_renew_fn, ctx);
    if (!ctx->renew_thread) {
        ctx->running = false;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "lease: failed to start renew thread");
        return -ENOMEM;
    }

    ctx->monitor_thread = mxfs_pal_thread_create_rt(mxfs_lease_monitor_fn, ctx);
    if (!ctx->monitor_thread) {
        ctx->running = false;
        mxfs_pal_thread_join(ctx->renew_thread);
        ctx->renew_thread = NULL;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "lease: failed to start monitor thread");
        return -ENOMEM;
    }

    /* Start the UDP receiver thread for incoming heartbeats.
     * Must be RT-priority like renew/monitor — under heavy metadata I/O,
     * a normal CFS thread gets starved for 60+ seconds, causing buffered
     * heartbeats to go unprocessed and triggering false SUSPECT. */
    ctx->udp_recv_thread = mxfs_pal_thread_create_rt(mxfs_lease_udp_recv_fn, ctx);
    if (!ctx->udp_recv_thread) {
        ctx->running = false;
        mxfs_pal_thread_join(ctx->renew_thread);
        ctx->renew_thread = NULL;
        mxfs_pal_thread_join(ctx->monitor_thread);
        ctx->monitor_thread = NULL;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "lease: failed to start UDP recv thread");
        return -ENOMEM;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "lease: started renew, monitor, and UDP recv threads (all RT)");
    return 0;
}

void mxfs_lease_stop(struct mxfs_lease_ctx *ctx)
{
    if (!ctx || !ctx->running)
        return;

    ctx->running = false;

    /* Wake renew and monitor threads from their condvar timed waits */
    mxfs_pal_mutex_lock(ctx->shutdown_lock);
    mxfs_pal_cond_broadcast(ctx->shutdown_cond);
    mxfs_pal_mutex_unlock(ctx->shutdown_lock);

    /* Shut down the UDP socket to unblock the recv thread.
     * Without this, the recv thread stays blocked in
     * kernel_recvmsg until the 500ms timeout expires.
     * With the shutdown, it wakes immediately with an error. */
    if (ctx->udp_sock)
        mxfs_pal_udp_shutdown(ctx->udp_sock);

    if (ctx->renew_thread) {
        mxfs_pal_thread_join(ctx->renew_thread);
        ctx->renew_thread = NULL;
    }

    if (ctx->monitor_thread) {
        mxfs_pal_thread_join(ctx->monitor_thread);
        ctx->monitor_thread = NULL;
    }

    if (ctx->udp_recv_thread) {
        mxfs_pal_thread_join(ctx->udp_recv_thread);
        ctx->udp_recv_thread = NULL;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "lease: stopped");
}

int mxfs_lease_register_node(struct mxfs_lease_ctx *ctx,
                              mxfs_node_id_t node_id)
{
    struct mxfs_node_lease *nl;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    /* Check for duplicate */
    nl = lease_find(ctx, node_id);
    if (nl) {
        mxfs_pal_mutex_unlock(ctx->lock);
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "lease: node %u already registered", node_id);
        return 0;
    }

    if (ctx->node_count >= MXFS_MAX_NODES) {
        mxfs_pal_mutex_unlock(ctx->lock);
        mxfs_pal_log(MXFS_LOG_ERR,
                     "lease: cannot register node %u, max nodes reached",
                     node_id);
        return -ENOSPC;
    }

    nl = &ctx->nodes[ctx->node_count];
    memset(nl, 0, sizeof(*nl));
    nl->node_id = node_id;
    nl->duration_ms = ctx->default_duration_ms;
    nl->state = (node_id == ctx->local_node) ?
        MXFS_NODE_ACTIVE : MXFS_NODE_JOINING;
    nl->granted_at = mxfs_pal_time_ms();
    nl->last_renewal = mxfs_pal_time_ms();
    nl->epoch = 0;
    nl->missed_renewals = 0;

    ctx->node_count++;

    mxfs_pal_mutex_unlock(ctx->lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "lease: registered node %u (state=%s)",
                 node_id,
                 node_id == ctx->local_node ? "ACTIVE" : "JOINING");
    return 0;
}

int mxfs_lease_unregister_node(struct mxfs_lease_ctx *ctx,
                                mxfs_node_id_t node_id)
{
    int i;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    for (i = 0; i < ctx->node_count; i++) {
        if (ctx->nodes[i].node_id == node_id) {
            /* Shift remaining entries down */
            if (i < ctx->node_count - 1)
                memmove(&ctx->nodes[i], &ctx->nodes[i + 1],
                        (ctx->node_count - i - 1) *
                        sizeof(struct mxfs_node_lease));
            ctx->node_count--;
            mxfs_pal_mutex_unlock(ctx->lock);
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "lease: unregistered node %u", node_id);
            return 0;
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: node %u already removed from cluster "
                 "(duplicate removal ignored)", node_id);
    return -ENOENT;
}

int mxfs_lease_process_renewal(struct mxfs_lease_ctx *ctx,
                                mxfs_node_id_t node_id, mxfs_epoch_t epoch)
{
    struct mxfs_node_lease *nl;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    nl = lease_find(ctx, node_id);
    if (!nl) {
        mxfs_pal_mutex_unlock(ctx->lock);
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: heartbeat received from unknown node %u "
                     "(may be joining or was recently removed)", node_id);
        return -ENOENT;
    }

    nl->last_renewal = mxfs_pal_time_ms();
    nl->epoch = epoch;
    nl->missed_renewals = 0;

    /* Transition to ACTIVE if was JOINING or SUSPECT */
    if (nl->state == MXFS_NODE_JOINING ||
        nl->state == MXFS_NODE_SUSPECT) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "lease: node %u transitioned to ACTIVE (was %s)",
                     node_id,
                     nl->state == MXFS_NODE_JOINING ? "JOINING" : "SUSPECT");
        nl->state = MXFS_NODE_ACTIVE;
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    return 0;
}

bool mxfs_lease_has_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id)
{
    bool found;

    if (!ctx)
        return false;

    mxfs_pal_mutex_lock(ctx->lock);
    found = (lease_find(ctx, node_id) != NULL);
    mxfs_pal_mutex_unlock(ctx->lock);
    return found;
}

bool mxfs_lease_is_valid(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id)
{
    struct mxfs_node_lease *nl;
    uint64_t elapsed;
    bool valid;

    if (!ctx)
        return false;

    mxfs_pal_mutex_lock(ctx->lock);

    nl = lease_find(ctx, node_id);
    if (!nl) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return false;
    }

    if (nl->state == MXFS_NODE_DEAD ||
        nl->state == MXFS_NODE_RECOVERING) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return false;
    }

    if (nl->last_renewal == 0) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return false;
    }

    elapsed = mxfs_pal_time_ms() - nl->last_renewal;
    valid = elapsed < nl->duration_ms;

    mxfs_pal_mutex_unlock(ctx->lock);
    return valid;
}

int mxfs_lease_get_active_nodes(struct mxfs_lease_ctx *ctx,
                                 mxfs_node_id_t *out, int max_count)
{
    int i, count = 0;

    if (!ctx || !out || max_count <= 0)
        return 0;

    mxfs_pal_mutex_lock(ctx->lock);
    for (i = 0; i < ctx->node_count && count < max_count; i++) {
        if (ctx->nodes[i].state == MXFS_NODE_ACTIVE ||
            ctx->nodes[i].state == MXFS_NODE_JOINING)
            out[count++] = ctx->nodes[i].node_id;
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    return count;
}

void mxfs_lease_set_expire_cb(struct mxfs_lease_ctx *ctx,
                               mxfs_lease_expire_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->expire_cb = cb;
    ctx->expire_cb_data = data;
}
