/*
 * MXFS — Multinode XFS
 * Portable UDP peer discovery
 *
 * Two execution paths: a sender thread that periodically sends
 * announcement packets via UDP multicast/broadcast, and a receiver
 * thread that receives packets and fires a callback when a new peer
 * with a matching volume UUID is detected.
 *
 * Ported from kernel/mxfs_discovery.c — kernel sockets, delayed_work,
 * kthreads replaced with PAL UDP, threading, and timer APIs.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "discovery.h"

/*
 * Find a peer in the seen list by node_id.
 * Caller must hold ctx->seen_lock.
 * Returns index, or -1 if not found.
 */
static int seen_find(struct mxfs_discovery_ctx *ctx, mxfs_node_id_t node_id)
{
    int i;

    for (i = 0; i < ctx->seen_count; i++) {
        if (ctx->seen[i].node_id == node_id)
            return i;
    }
    return -1;
}

/*
 * Add or update a peer in the seen list.
 * Caller must hold ctx->seen_lock.
 * Returns 1 if this is a newly added peer, 0 if already known.
 */
static int seen_update(struct mxfs_discovery_ctx *ctx,
                        mxfs_node_id_t node_id, uint64_t ts)
{
    int idx = seen_find(ctx, node_id);

    if (idx >= 0) {
        ctx->seen[idx].last_seen = ts;
        return 0;
    }

    if (ctx->seen_count >= MXFS_MAX_NODES) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "discovery: seen list full, cannot track node %u",
                     node_id);
        return 0;
    }

    ctx->seen[ctx->seen_count].node_id = node_id;
    ctx->seen[ctx->seen_count].last_seen = ts;
    ctx->seen_count++;
    return 1;
}

/*
 * Sender thread: sends the local announcement packet to the
 * multicast group or broadcast address, then sleeps for the interval.
 */
static void mxfs_discovery_send_fn(void *arg)
{
    struct mxfs_discovery_ctx *ctx = arg;
    int ret;
    int burst_remaining = MXFS_DISCOVERY_BURST_COUNT;

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: sender thread started");

    while (ctx->running) {
        ret = mxfs_pal_udp_sendto(ctx->sock,
                                   &ctx->local_announce,
                                   sizeof(ctx->local_announce),
                                   ctx->send_addr,
                                   ctx->port);
        if (ret < 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: discovery broadcast failed: %d "
                         "(cluster nodes may not detect this node)", ret);

        /*
         * Startup burst: send announcements rapidly for the first
         * BURST_COUNT iterations so that all existing nodes discover
         * us quickly, even if some UDP packets are lost.  After the
         * burst, settle to the normal interval.
         *
         * Use condvar timed wait instead of sleep so that
         * mxfs_discovery_stop() can wake us immediately.
         */
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running) {
            if (burst_remaining > 0) {
                burst_remaining--;
                mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                        ctx->shutdown_lock,
                                        MXFS_DISCOVERY_BURST_INTERVAL_MS);
            } else {
                mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                        ctx->shutdown_lock,
                                        MXFS_DISCOVERY_INTERVAL_MS);
            }
        }
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: sender thread exiting");
}

/*
 * Receiver thread: loops reading packets from the UDP socket.
 * Uses a 500ms receive timeout to wake up for clean shutdown.
 * Validates packets, ignores self and wrong volume, fires the
 * peer callback for newly discovered peers.
 */
static void mxfs_discovery_recv_fn(void *arg)
{
    struct mxfs_discovery_ctx *ctx = arg;
    struct mxfs_discovery_announce pkt;
    char sender_host[64];
    uint16_t sender_port;
    int ret;
    int is_new;

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: receiver thread started");

    while (ctx->running) {
        memset(&pkt, 0, sizeof(pkt));
        memset(sender_host, 0, sizeof(sender_host));
        sender_port = 0;

        ret = mxfs_pal_udp_recvfrom(ctx->sock,
                                     &pkt, sizeof(pkt),
                                     sender_host, sizeof(sender_host),
                                     &sender_port);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -ETIMEDOUT || ret == -EINTR)
                continue;
            /* Socket was shut down — exit */
            if (!ctx->running)
                break;
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: discovery receive failed: %d "
                         "(will retry automatically)", ret);
            continue;
        }
        if (ret == 0) {
            if (!ctx->running)
                break;
            continue;
        }

        if (ret < (int)sizeof(pkt))
            continue;

        /* Validate magic */
        if (mxfs_le32_to_cpu(pkt.magic) != MXFS_DISCOVERY_MAGIC)
            continue;

        /* Validate version */
        if (mxfs_le16_to_cpu(pkt.version) != MXFS_DISCOVERY_VERSION)
            continue;

        /* Ignore our own announcements */
        if (memcmp(pkt.node_uuid,
                   ctx->local_announce.node_uuid, 16) == 0)
            continue;

        /* Check volume UUID matches ours */
        if (memcmp(pkt.volume_uuid,
                   ctx->local_announce.volume_uuid, 16) != 0)
            continue;

        /* Track whether this is a newly discovered peer */
        mxfs_pal_mutex_lock(ctx->seen_lock);
        is_new = seen_update(ctx, pkt.node_id, mxfs_pal_time_ms());
        mxfs_pal_mutex_unlock(ctx->seen_lock);

        /*
         * Overwrite hostname with the actual source IP from
         * the UDP packet — PAL already provides this as a string.
         */
        snprintf(pkt.hostname, sizeof(pkt.hostname),
                 "%s", sender_host);

        if (is_new) {
            mxfs_pal_log(MXFS_LOG_INFO,
                         "discovery: new peer -- node %u (%s) tcp_port %u",
                         pkt.node_id, pkt.hostname,
                         mxfs_le16_to_cpu(pkt.tcp_port));
        }

        /*
         * Always fire the callback — not just for new peers. This
         * allows the peer layer to reconnect if a TCP connection
         * was dropped (ECONNRESET). The callback handles duplicates
         * gracefully: mxfs_peer_add returns -EEXIST, and
         * mxfs_peer_connect returns 0 if already connected.
         */
        if (ctx->peer_cb)
            ctx->peer_cb(ctx->peer_cb_data, &pkt);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: receiver thread exiting");
}

struct mxfs_discovery_ctx *mxfs_discovery_create(
    mxfs_node_id_t node_id,
    const uint8_t *node_uuid,
    const uint8_t *volume_uuid,
    mxfs_volume_id_t volume_id,
    uint16_t tcp_port,
    const char *mcast_addr,
    uint16_t disc_port,
    bool use_broadcast)
{
    struct mxfs_discovery_ctx *ctx;
    char hostname[64];
    int ret;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->running = false;
    ctx->sender_thread = NULL;
    ctx->recv_thread = NULL;
    ctx->peer_cb = NULL;
    ctx->peer_cb_data = NULL;
    ctx->seen_count = 0;
    ctx->use_broadcast = use_broadcast;

    ctx->port = disc_port > 0 ? disc_port : MXFS_DISCOVERY_PORT;

    if (mcast_addr && mcast_addr[0] != '\0')
        snprintf(ctx->mcast_addr, sizeof(ctx->mcast_addr), "%s", mcast_addr);
    else
        snprintf(ctx->mcast_addr, sizeof(ctx->mcast_addr), "%s",
                 MXFS_DISCOVERY_MCAST);

    /* In broadcast mode, send to the subnet broadcast address
     * instead of the multicast group. Multicast may not traverse
     * vSwitch boundaries between ESXi hosts. */
    if (use_broadcast)
        snprintf(ctx->send_addr, sizeof(ctx->send_addr), "255.255.255.255");
    else
        snprintf(ctx->send_addr, sizeof(ctx->send_addr), "%s",
                 ctx->mcast_addr);

    ctx->seen_lock = mxfs_pal_mutex_create();
    if (!ctx->seen_lock) {
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_lock = mxfs_pal_mutex_create();
    if (!ctx->shutdown_lock) {
        mxfs_pal_mutex_destroy(ctx->seen_lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_cond = mxfs_pal_cond_create();
    if (!ctx->shutdown_cond) {
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
        mxfs_pal_mutex_destroy(ctx->seen_lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    /* Populate local announcement */
    ctx->local_announce.magic = mxfs_cpu_to_le32(MXFS_DISCOVERY_MAGIC);
    ctx->local_announce.version = mxfs_cpu_to_le16(MXFS_DISCOVERY_VERSION);
    ctx->local_announce.flags = mxfs_cpu_to_le16(MXFS_DISCOVERY_FLAG_HAS_VOLUME);
    if (node_uuid)
        memcpy(ctx->local_announce.node_uuid, node_uuid, 16);
    ctx->local_announce.node_id = node_id;
    ctx->local_announce.tcp_port = mxfs_cpu_to_le16(tcp_port);
    ctx->local_announce.dlm_transport = 0;  /* set by mount after transport resolved */
    ctx->local_announce.pad = 0;
    if (volume_uuid)
        memcpy(ctx->local_announce.volume_uuid, volume_uuid, 16);
    ctx->local_announce.volume_id = volume_id;

    memset(hostname, 0, sizeof(hostname));
    mxfs_pal_get_hostname(hostname, sizeof(hostname));
    snprintf(ctx->local_announce.hostname,
             sizeof(ctx->local_announce.hostname),
             "%s", hostname);

    /* Create and configure the UDP socket */
    ctx->sock = mxfs_pal_udp_open(ctx->port);
    if (!ctx->sock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "discovery: failed to open UDP socket on port %u",
                     ctx->port);
        mxfs_pal_mutex_destroy(ctx->seen_lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    /* Set receive timeout for clean shutdown */
    mxfs_pal_udp_set_recv_timeout(ctx->sock, 500);

    if (use_broadcast) {
        ret = mxfs_pal_udp_set_broadcast(ctx->sock);
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "discovery: SO_BROADCAST failed: %d", ret);
            mxfs_pal_udp_close(ctx->sock);
            mxfs_pal_mutex_destroy(ctx->seen_lock);
            mxfs_pal_free(ctx);
            return NULL;
        }
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "discovery: broadcast mode, target %s:%u",
                     ctx->send_addr, ctx->port);
    } else {
        ret = mxfs_pal_udp_join_multicast(ctx->sock, ctx->mcast_addr);
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "discovery: multicast join failed: %d", ret);
            mxfs_pal_udp_close(ctx->sock);
            mxfs_pal_mutex_destroy(ctx->seen_lock);
            mxfs_pal_free(ctx);
            return NULL;
        }
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "discovery: multicast mode, group %s:%u",
                     ctx->mcast_addr, ctx->port);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "discovery: initialized for node %u on %s:%u",
                 node_id,
                 use_broadcast ? "broadcast" : ctx->mcast_addr,
                 ctx->port);

    return ctx;
}

void mxfs_discovery_destroy(struct mxfs_discovery_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_discovery_stop(ctx);

    if (ctx->sock) {
        mxfs_pal_udp_close(ctx->sock);
        ctx->sock = NULL;
    }

    if (ctx->shutdown_cond)
        mxfs_pal_cond_destroy(ctx->shutdown_cond);
    if (ctx->shutdown_lock)
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
    mxfs_pal_mutex_destroy(ctx->seen_lock);

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: shutdown complete");

    mxfs_pal_free(ctx);
}

int mxfs_discovery_start_recv_only(struct mxfs_discovery_ctx *ctx)
{
    if (!ctx)
        return -EINVAL;

    if (!ctx->sock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "discovery: cannot start, socket not initialized");
        return -EBADF;
    }

    ctx->running = true;

    ctx->recv_thread = mxfs_pal_thread_create(mxfs_discovery_recv_fn, ctx);
    if (!ctx->recv_thread) {
        ctx->running = false;
        return -ENOMEM;
    }

    return 0;
}

int mxfs_discovery_start(struct mxfs_discovery_ctx *ctx)
{
    if (!ctx)
        return -EINVAL;

    if (!ctx->sock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "discovery: cannot start, socket not initialized");
        return -EBADF;
    }

    ctx->running = true;

    /* Start the receiver thread */
    ctx->recv_thread = mxfs_pal_thread_create(mxfs_discovery_recv_fn, ctx);
    if (!ctx->recv_thread) {
        ctx->running = false;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "discovery: failed to start recv thread");
        return -ENOMEM;
    }

    /* Start the sender thread */
    ctx->sender_thread = mxfs_pal_thread_create(mxfs_discovery_send_fn, ctx);
    if (!ctx->sender_thread) {
        ctx->running = false;
        mxfs_pal_thread_join(ctx->recv_thread);
        ctx->recv_thread = NULL;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "discovery: failed to start sender thread");
        return -ENOMEM;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "discovery: started sender and receiver");
    return 0;
}

void mxfs_discovery_stop(struct mxfs_discovery_ctx *ctx)
{
    if (!ctx || !ctx->running)
        return;

    ctx->running = false;

    /* Wake the sender thread from its condvar timed wait */
    mxfs_pal_mutex_lock(ctx->shutdown_lock);
    mxfs_pal_cond_broadcast(ctx->shutdown_cond);
    mxfs_pal_mutex_unlock(ctx->shutdown_lock);

    /* Shut down the UDP socket to unblock the recv thread.
     * Without this, the recv thread stays blocked in
     * kernel_recvmsg until the 500ms timeout expires.
     * With the shutdown, it wakes immediately with an error. */
    if (ctx->sock)
        mxfs_pal_udp_shutdown(ctx->sock);

    if (ctx->sender_thread) {
        mxfs_pal_thread_join(ctx->sender_thread);
        ctx->sender_thread = NULL;
    }

    if (ctx->recv_thread) {
        mxfs_pal_thread_join(ctx->recv_thread);
        ctx->recv_thread = NULL;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "discovery: stopped");
}

void mxfs_discovery_set_peer_cb(struct mxfs_discovery_ctx *ctx,
                                 mxfs_discovery_peer_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->peer_cb = cb;
    ctx->peer_cb_data = data;
}

void mxfs_discovery_set_transport(struct mxfs_discovery_ctx *ctx,
                                   uint8_t transport)
{
    if (!ctx)
        return;
    ctx->local_announce.dlm_transport = transport;
}
