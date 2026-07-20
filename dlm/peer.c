/*
 * MXFS — Multinode XFS
 * Portable TCP peer connection management
 *
 * Port of kernel/mxfs_peer.c to portable C. Uses PAL TCP APIs,
 * PAL threads for accept and per-peer receive loops, and PAL
 * mutex-serialized sends. Wire protocol is the same mxfs_dlm_msg_hdr
 * framing with NODE_JOIN handshake.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "peer.h"

#define MXFS_PEER_MAX_MSG_SIZE  8192

/* ---- Internal helpers ---- */

static struct mxfs_peer *peer_find_locked(struct mxfs_peer_ctx *ctx,
                                           mxfs_node_id_t node_id)
{
    int i;

    for (i = 0; i < ctx->peer_count; i++) {
        if (ctx->peers[i].node_id == node_id)
            return &ctx->peers[i];
    }
    return NULL;
}

/*
 * Handle peer disconnect: shutdown socket, set DISCONNECTED, fire callback.
 * Caller must NOT hold peer->send_lock.
 *
 * Bug 80: Use shutdown instead of close.  The socket is NOT freed here
 * because the recv thread may still be unwinding from kernel_recvmsg
 * after getting woken by the shutdown.  The socket will be properly
 * freed by the next connection setup (peer_connect_impl or accept
 * thread) which joins the recv thread first, or during mxfs_peer_shutdown.
 * Keeping peer->sock non-NULL also lets the next connection code know
 * it needs to join the recv thread and free the old socket.
 */
static void peer_handle_disconnect(struct mxfs_peer_ctx *ctx,
                                    struct mxfs_peer *peer)
{
    mxfs_node_id_t node = peer->node_id;

    mxfs_pal_mutex_lock(peer->send_lock);
    if (peer->sock)
        mxfs_pal_tcp_shutdown(peer->sock);
    peer->state = MXFS_CONN_DISCONNECTED;
    mxfs_pal_mutex_unlock(peer->send_lock);

    if (ctx->disconnect_cb)
        ctx->disconnect_cb(ctx->disconnect_cb_data, node);
}

/* ---- Per-peer receive thread ---- */

struct mxfs_recv_data {
    struct mxfs_peer_ctx *ctx;
    mxfs_node_id_t node_id;
};

static void mxfs_peer_recv_fn(void *arg)
{
    struct mxfs_recv_data *rd = arg;
    struct mxfs_peer_ctx *ctx = rd->ctx;
    mxfs_node_id_t node_id = rd->node_id;
    struct mxfs_peer *peer;
    struct mxfs_dlm_msg_hdr hdr;
    uint8_t *msgbuf = NULL;
    int ret;

    mxfs_pal_free(rd);

    msgbuf = mxfs_pal_alloc(MXFS_PEER_MAX_MSG_SIZE);
    if (!msgbuf) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: recv thread node %u: out of memory", node_id);
        return;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: recv thread started for node %u", node_id);

    while (ctx->running) {
        mxfs_pal_mutex_lock(ctx->peer_lock);
        peer = peer_find_locked(ctx, node_id);
        if (!peer || peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
            mxfs_pal_mutex_unlock(ctx->peer_lock);
            break;
        }
        mxfs_pal_mutex_unlock(ctx->peer_lock);

        /* Read message header */
        ret = mxfs_pal_tcp_recv(peer->sock, &hdr, sizeof(hdr));
        if (ret == -EAGAIN) {
            /* Receive timeout -- peer may be slow. Loop back. */
            continue;
        }
        if (ret < 0) {
            if (!ctx->running)
                break;
            mxfs_pal_log(MXFS_LOG_INFO,
                         "peer: node %u disconnected",
                         node_id);
            peer_handle_disconnect(ctx, peer);
            break;
        }

        /* Validate magic */
        if (hdr.magic != MXFS_DLM_MAGIC) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: bad magic 0x%08x from node %u",
                         hdr.magic, node_id);
            peer_handle_disconnect(ctx, peer);
            break;
        }

        /* Validate length */
        if (hdr.length < sizeof(hdr) ||
            hdr.length > MXFS_PEER_MAX_MSG_SIZE) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: bad length %u from node %u",
                         hdr.length, node_id);
            peer_handle_disconnect(ctx, peer);
            break;
        }

        /* Copy header into msgbuf, then read remaining payload */
        memcpy(msgbuf, &hdr, sizeof(hdr));

        if (hdr.length > sizeof(hdr)) {
            ret = mxfs_pal_tcp_recv(peer->sock,
                                     msgbuf + sizeof(hdr),
                                     hdr.length - sizeof(hdr));
            if (ret < 0) {
                if (!ctx->running)
                    break;
                mxfs_pal_log(MXFS_LOG_INFO,
                             "peer: node %u disconnected",
                             node_id);
                peer_handle_disconnect(ctx, peer);
                break;
            }
        }

        peer->last_seen = mxfs_pal_time_ms();

        /* Dispatch to message callback */
        if (ctx->msg_cb)
            ctx->msg_cb(ctx->msg_cb_data, hdr.sender,
                        msgbuf, hdr.length);
    }

    mxfs_pal_free(msgbuf);
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: recv thread exiting for node %u", node_id);
}

/*
 * Start a receive thread for a peer. The peer must already have
 * an active socket.
 */
static int start_recv_thread(struct mxfs_peer_ctx *ctx, struct mxfs_peer *peer)
{
    struct mxfs_recv_data *rd;

    rd = mxfs_pal_alloc(sizeof(*rd));
    if (!rd)
        return -ENOMEM;

    rd->ctx = ctx;
    rd->node_id = peer->node_id;

    peer->recv_thread = mxfs_pal_thread_create_rt(mxfs_peer_recv_fn, rd);
    if (!peer->recv_thread) {
        mxfs_pal_free(rd);
        return -ENOMEM;
    }

    return 0;
}

/* ---- Accept thread ---- */

static void mxfs_peer_accept_fn(void *arg)
{
    struct mxfs_peer_ctx *ctx = arg;
    mxfs_sock_t *newsock;
    struct mxfs_dlm_node_msg join;
    struct mxfs_dlm_node_msg reply;
    struct mxfs_peer *peer;
    mxfs_node_id_t sender;
    int ret;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: accept thread started on port %u",
                 ctx->local_port);

    while (ctx->running) {
        newsock = mxfs_pal_tcp_accept(ctx->listen_sock);
        if (!newsock) {
            if (!ctx->running)
                break;
            /* Accept failed or timeout — retry */
            mxfs_pal_sleep_ms(100);
            continue;
        }

        /* Check running again — shutdown may have fired between
         * kernel_accept returning and here */
        if (!ctx->running) {
            mxfs_pal_tcp_close(newsock);
            break;
        }

        mxfs_pal_tcp_set_opts(newsock);

        /* Publish newsock so shutdown can wake us if we block
         * in the handshake recv below. Without this, the accept
         * thread can hang forever in tcp_recv on a socket that
         * the shutdown path doesn't know about. */
        ctx->pending_sock = newsock;

        /* Read NODE_JOIN handshake */
        ret = mxfs_pal_tcp_recv(newsock, &join, sizeof(join));
        if (ret < 0) {
            ctx->pending_sock = NULL;
            if (!ctx->running) {
                mxfs_pal_tcp_close(newsock);
                break;
            }
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: handshake read failed: %d", ret);
            mxfs_pal_tcp_close(newsock);
            continue;
        }

        /* Handshake received — clear pending before further processing */
        ctx->pending_sock = NULL;

        if (!ctx->running) {
            mxfs_pal_tcp_close(newsock);
            break;
        }

        if (join.hdr.magic != MXFS_DLM_MAGIC) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: bad handshake magic 0x%08x",
                         join.hdr.magic);
            mxfs_pal_tcp_close(newsock);
            continue;
        }

        if (join.hdr.type != MXFS_MSG_NODE_JOIN) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: expected NODE_JOIN, got %u",
                         join.hdr.type);
            mxfs_pal_tcp_close(newsock);
            continue;
        }

        /* Multi-LUN: reject connections for a different volume.
         * With SO_REUSEPORT, the kernel may deliver a connection
         * intended for another mount's accept loop to us.  If the
         * sender's volume_id is non-zero and doesn't match ours,
         * close immediately — the sender will retry and the kernel
         * will probabilistically deliver it to the correct listener. */
        if (join.volume_id != 0 &&
            ctx->local_volume_id != 0 &&
            join.volume_id != ctx->local_volume_id) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "peer: rejecting node %u "
                         "(volume 0x%llx != ours 0x%llx)",
                         join.hdr.sender,
                         (unsigned long long)join.volume_id,
                         (unsigned long long)ctx->local_volume_id);
            mxfs_pal_tcp_close(newsock);
            continue;
        }

        sender = join.hdr.sender;

        /* Send NODE_JOIN reply */
        memset(&reply, 0, sizeof(reply));
        reply.hdr.magic = MXFS_DLM_MAGIC;
        reply.hdr.version = MXFS_DLM_VERSION;
        reply.hdr.type = MXFS_MSG_NODE_JOIN;
        reply.hdr.length = sizeof(reply);
        reply.hdr.sender = ctx->local_node_id;
        reply.hdr.target = sender;
        reply.port = ctx->local_port;
        reply.volume_id = ctx->local_volume_id;
        memcpy(reply.name, ctx->local_node_uuid,
               sizeof(ctx->local_node_uuid) < sizeof(reply.name) ?
               sizeof(ctx->local_node_uuid) : sizeof(reply.name));

        ret = mxfs_pal_tcp_send(newsock, &reply, sizeof(reply));
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "peer: handshake reply to node %u failed: %d",
                         sender, ret);
            mxfs_pal_tcp_close(newsock);
            continue;
        }

        mxfs_pal_mutex_lock(ctx->peer_lock);

        /* Find or dynamically add this peer */
        peer = peer_find_locked(ctx, sender);
        if (!peer) {
            if (ctx->peer_count >= MXFS_MAX_NODES) {
                mxfs_pal_mutex_unlock(ctx->peer_lock);
                mxfs_pal_log(MXFS_LOG_WARN,
                             "peer: cannot add node %u, max peers reached",
                             sender);
                mxfs_pal_tcp_close(newsock);
                continue;
            }
            peer = &ctx->peers[ctx->peer_count];
            memset(peer, 0, sizeof(*peer));
            peer->node_id = sender;
            peer->port = join.port;
            peer->state = MXFS_CONN_DISCONNECTED;
            peer->send_lock = mxfs_pal_mutex_create();
            ctx->peer_count++;
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "peer: dynamically added node %u", sender);
        }

        /* Replace any existing connection.
         * IMPORTANT: shutdown the old socket BEFORE closing it —
         * the recv thread may be blocking in tcp_recv.  Shutdown
         * unblocks the recv thread; we join it, then close. */
        mxfs_pal_mutex_lock(peer->send_lock);
        {
            mxfs_sock_t *old_sock = NULL;

            if (peer->sock) {
                old_sock = peer->sock;
                mxfs_pal_tcp_shutdown(peer->sock);
                peer->sock = NULL;
            }

            /* Stop old recv thread if any */
            if (peer->recv_thread) {
                mxfs_thread_t *old_thread = peer->recv_thread;
                peer->recv_thread = NULL;
                mxfs_pal_mutex_unlock(peer->send_lock);
                mxfs_pal_mutex_unlock(ctx->peer_lock);
                mxfs_pal_thread_join(old_thread);
                mxfs_pal_mutex_lock(ctx->peer_lock);
                mxfs_pal_mutex_lock(peer->send_lock);
            }

            /* Safe to free old socket — recv thread has exited */
            if (old_sock)
                mxfs_pal_tcp_close(old_sock);
        }

        peer->sock = newsock;
        peer->state = MXFS_CONN_ACTIVE;
        peer->last_seen = mxfs_pal_time_ms();

        /* Bug 65: Extract the remote IP from the accepted socket
         * and store it in the peer entry. Without this, if the
         * connection drops and outbound fallback reconnection is
         * attempted, peer->host is empty and the connect call
         * fails (connects to ":7600"). Always update the host
         * field to reflect the current IP of this peer. */
        {
            char addr[64];
            if (mxfs_pal_tcp_getpeername(newsock, addr,
                                         sizeof(addr)) == 0) {
                snprintf(peer->host, sizeof(peer->host), "%s", addr);
            }
        }

        mxfs_pal_mutex_unlock(peer->send_lock);
        mxfs_pal_mutex_unlock(ctx->peer_lock);

        /* Start recv thread for this peer */
        ret = start_recv_thread(ctx, peer);
        if (ret < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "peer: failed to start recv thread "
                         "for node %u: %d", sender, ret);
            peer_handle_disconnect(ctx, peer);
            continue;
        }

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "peer: node %u connected (inbound) from %s",
                     sender, peer->host);

        /* Notify mount layer about the new inbound peer so it can
         * register with lease manager and update DLM active nodes.
         * This is essential for fallback connections where the
         * higher-ID node connects to us but we never discovered
         * it via multicast (asymmetric multicast). */
        if (ctx->connect_cb)
            ctx->connect_cb(ctx->connect_cb_data, sender);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "peer: accept thread exiting");
}

/* ---- Public API ---- */

struct mxfs_peer_ctx *mxfs_peer_init(mxfs_node_id_t node_id,
                                      const uint8_t *uuid,
                                      uint16_t port,
                                      mxfs_volume_id_t volume_id)
{
    struct mxfs_peer_ctx *ctx;
    int i;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->local_node_id = node_id;
    if (uuid)
        memcpy(ctx->local_node_uuid, uuid, 16);
    ctx->local_port = port;
    ctx->local_volume_id = volume_id;
    ctx->running = false;
    ctx->peer_count = 0;
    ctx->listen_sock = NULL;
    ctx->accept_thread = NULL;
    ctx->pending_sock = NULL;

    ctx->peer_lock = mxfs_pal_mutex_create();
    if (!ctx->peer_lock) {
        mxfs_pal_free(ctx);
        return NULL;
    }

    /* Initialize all peer slots */
    for (i = 0; i < MXFS_MAX_NODES; i++) {
        ctx->peers[i].state = MXFS_CONN_DISCONNECTED;
        ctx->peers[i].sock = NULL;
        ctx->peers[i].recv_thread = NULL;
        ctx->peers[i].send_lock = mxfs_pal_mutex_create();
    }

    /* Create TCP listen socket */
    ctx->listen_sock = mxfs_pal_tcp_listen(port);
    if (!ctx->listen_sock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: listen on port %u failed", port);
        for (i = 0; i < MXFS_MAX_NODES; i++) {
            if (ctx->peers[i].send_lock)
                mxfs_pal_mutex_destroy(ctx->peers[i].send_lock);
        }
        mxfs_pal_mutex_destroy(ctx->peer_lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->running = true;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: listening on port %u for node %u",
                 port, node_id);
    return ctx;
}

int mxfs_peer_start(struct mxfs_peer_ctx *ctx)
{
    if (!ctx || !ctx->running)
        return -EINVAL;

    ctx->accept_thread = mxfs_pal_thread_create_rt(mxfs_peer_accept_fn, ctx);
    if (!ctx->accept_thread) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: failed to start accept thread");
        return -ENOMEM;
    }

    return 0;
}

void mxfs_peer_shutdown(struct mxfs_peer_ctx *ctx)
{
    int i;

    if (!ctx)
        return;

    ctx->running = false;

    /* Phase 0: shutdown ALL peer sockets BEFORE joining the accept thread.
     *
     * With 3+ nodes, the accept thread may be in mxfs_pal_thread_join()
     * joining an old recv thread (when replacing a reconnected peer at
     * line ~293 of the accept loop).  That old recv thread is blocked in
     * mxfs_pal_tcp_recv() on the OLD socket.  If we try to join the
     * accept thread first (before shutting down peer sockets), the
     * accept thread hangs waiting for the recv thread, which hangs
     * waiting for data on a socket nobody ever shuts down.
     *
     * Fix: shut down all peer sockets first so any recv thread blocked
     * in tcp_recv will wake up and exit.  Then the accept thread (which
     * may be joining one of those recv threads) can proceed and exit
     * when it checks running==false. */
    for (i = 0; i < ctx->peer_count; i++) {
        struct mxfs_peer *peer = &ctx->peers[i];

        mxfs_pal_mutex_lock(peer->send_lock);
        if (peer->sock)
            mxfs_pal_tcp_shutdown(peer->sock);
        mxfs_pal_mutex_unlock(peer->send_lock);
    }

    /* Shutdown the listen socket to wake the accept thread blocked
     * in kernel_accept.  We must NOT free the socket yet because
     * the accept thread still references it.  The shutdown unblocks
     * kernel_accept so the thread can notice running==false and exit. */
    if (ctx->listen_sock)
        mxfs_pal_tcp_shutdown(ctx->listen_sock);

    /* Shutdown the pending socket if the accept thread is blocked
     * in tcp_recv reading a NODE_JOIN handshake from a newly
     * accepted connection.  With 3+ nodes, inbound connections
     * arrive frequently and the accept thread spends significant
     * time blocked here.  Without this, the accept thread hangs
     * forever because nobody else knows about this socket. */
    if (ctx->pending_sock)
        mxfs_pal_tcp_shutdown(ctx->pending_sock);

    /* Join the accept thread — it will exit after seeing running==false.
     * Safe now because all recv threads have been woken (Phase 0). */
    if (ctx->accept_thread) {
        mxfs_pal_thread_join(ctx->accept_thread);
        ctx->accept_thread = NULL;
    }

    /* Now safe to close and free the listen socket */
    if (ctx->listen_sock) {
        mxfs_pal_tcp_close(ctx->listen_sock);
        ctx->listen_sock = NULL;
    }

    /* Phase 1 (already done in Phase 0 above): peer sockets are shut down.
     *
     * Phase 2: join recv threads, then close+free sockets.
     * Some recv threads may have already been joined by the accept thread
     * during replacement — their recv_thread pointer is NULL. */
    for (i = 0; i < ctx->peer_count; i++) {
        struct mxfs_peer *peer = &ctx->peers[i];

        if (peer->recv_thread) {
            mxfs_pal_thread_join(peer->recv_thread);
            peer->recv_thread = NULL;
        }

        mxfs_pal_mutex_lock(peer->send_lock);
        if (peer->sock) {
            mxfs_pal_tcp_close(peer->sock);
            peer->sock = NULL;
        }
        mxfs_pal_mutex_unlock(peer->send_lock);

        peer->state = MXFS_CONN_DISCONNECTED;
    }

    /* Clean up mutexes */
    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->peers[i].send_lock) {
            mxfs_pal_mutex_destroy(ctx->peers[i].send_lock);
            ctx->peers[i].send_lock = NULL;
        }
    }

    mxfs_pal_mutex_destroy(ctx->peer_lock);
    mxfs_pal_free(ctx);

    mxfs_pal_log(MXFS_LOG_DEBUG, "peer: shutdown complete");
}

int mxfs_peer_add(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
                   const uint8_t *uuid, const char *host, uint16_t port)
{
    struct mxfs_peer *peer;
    int i;

    if (!ctx || !host)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->peer_lock);

    if (ctx->peer_count >= MXFS_MAX_NODES) {
        mxfs_pal_mutex_unlock(ctx->peer_lock);
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: cannot add node %u, max peers reached",
                     node_id);
        return -ENOSPC;
    }

    /* Check for duplicate */
    for (i = 0; i < ctx->peer_count; i++) {
        if (ctx->peers[i].node_id == node_id) {
            mxfs_pal_mutex_unlock(ctx->peer_lock);
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "peer: node %u already registered", node_id);
            return -EEXIST;
        }
    }

    peer = &ctx->peers[ctx->peer_count];
    memset(peer, 0, sizeof(*peer));
    peer->node_id = node_id;
    if (uuid)
        memcpy(peer->node_uuid, uuid, 16);
    snprintf(peer->host, sizeof(peer->host), "%s", host);
    peer->port = port;
    peer->sock = NULL;
    peer->state = MXFS_CONN_DISCONNECTED;
    peer->recv_thread = NULL;
    peer->last_seen = 0;
    peer->send_lock = mxfs_pal_mutex_create();

    ctx->peer_count++;

    mxfs_pal_mutex_unlock(ctx->peer_lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: added node %u at %s:%u", node_id, host, port);
    return 0;
}

/*
 * peer_connect_impl — shared implementation for peer connect.
 * If skip_id_check is true, bypass the lower-ID-initiates rule
 * (used as a fallback when multicast is asymmetric).
 */
static int peer_connect_impl(struct mxfs_peer_ctx *ctx,
                              mxfs_node_id_t node_id,
                              bool skip_id_check)
{
    struct mxfs_peer *peer;
    mxfs_sock_t *sock;
    struct mxfs_dlm_node_msg join;
    struct mxfs_dlm_node_msg reply;
    int ret;

    if (!ctx)
        return -EINVAL;

    /*
     * Lower-ID-initiates convention: only the node with the lower
     * node_id initiates the outbound connection. Skip when caller
     * requests force mode (asymmetric multicast fallback).
     */
    if (!skip_id_check && ctx->local_node_id >= node_id)
        return 0;

    mxfs_pal_mutex_lock(ctx->peer_lock);
    peer = peer_find_locked(ctx, node_id);
    if (!peer) {
        mxfs_pal_mutex_unlock(ctx->peer_lock);
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: cannot connect to unknown node %u", node_id);
        return -ENOENT;
    }
    mxfs_pal_mutex_unlock(ctx->peer_lock);

    mxfs_pal_mutex_lock(peer->send_lock);

    /* Already connected */
    if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
        mxfs_pal_mutex_unlock(peer->send_lock);
        return 0;
    }

    /* Shutdown stale socket — do NOT free yet, recv thread may
     * be blocking in tcp_recv.  Join recv thread first. */
    {
        mxfs_sock_t *old_sock = NULL;

        if (peer->sock) {
            old_sock = peer->sock;
            mxfs_pal_tcp_shutdown(peer->sock);
            peer->sock = NULL;
        }

        peer->state = MXFS_CONN_CONNECTING;

        /* Join old recv thread — must complete before we free
         * the old socket or start a new connection */
        if (peer->recv_thread) {
            mxfs_thread_t *old_thread = peer->recv_thread;
            peer->recv_thread = NULL;
            mxfs_pal_mutex_unlock(peer->send_lock);
            mxfs_pal_thread_join(old_thread);
        } else {
            mxfs_pal_mutex_unlock(peer->send_lock);
        }

        /* Safe to free old socket — recv thread has exited */
        if (old_sock)
            mxfs_pal_tcp_close(old_sock);
    }

    /* Bug 80: Re-check under send_lock after dropping it for the
     * thread join above.  While we were joining the old recv thread,
     * the accept thread may have already accepted a new inbound
     * connection from this peer, installed a new socket, and started
     * a new recv thread.  If so, skip the outbound connect to avoid
     * overwriting peer->sock (leaking the accept thread's socket)
     * and orphaning the accept thread's recv thread.  An orphaned
     * recv thread blocked in kernel_recvmsg on a freed socket causes
     * a NULL-pointer deref in remove_wait_queue -> spinlock. */
    mxfs_pal_mutex_lock(peer->send_lock);
    if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
        mxfs_pal_mutex_unlock(peer->send_lock);
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "peer: node %u already reconnected (inbound) "
                     "while joining old thread, skipping outbound connect",
                     node_id);
        return 0;
    }
    mxfs_pal_mutex_unlock(peer->send_lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: %sconnecting to node %u at %s:%u",
                 skip_id_check ? "fallback " : "",
                 node_id, peer->host, peer->port);

    /* Create TCP connection */
    sock = mxfs_pal_tcp_connect(peer->host, peer->port);
    if (!sock) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: connection to cluster node %u failed "
                     "(will retry on next discovery)", node_id);
        mxfs_pal_mutex_lock(peer->send_lock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);
        return -ECONNREFUSED;
    }

    mxfs_pal_tcp_set_opts(sock);

    /* Send NODE_JOIN handshake */
    memset(&join, 0, sizeof(join));
    join.hdr.magic = MXFS_DLM_MAGIC;
    join.hdr.version = MXFS_DLM_VERSION;
    join.hdr.type = MXFS_MSG_NODE_JOIN;
    join.hdr.length = sizeof(join);
    join.hdr.sender = ctx->local_node_id;
    join.hdr.target = node_id;
    join.port = ctx->local_port;
    join.volume_id = ctx->local_volume_id;
    memcpy(join.name, ctx->local_node_uuid,
           sizeof(ctx->local_node_uuid) < sizeof(join.name) ?
           sizeof(ctx->local_node_uuid) : sizeof(join.name));

    ret = mxfs_pal_tcp_send(sock, &join, sizeof(join));
    if (ret < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: handshake write to node %u failed: %d",
                     node_id, ret);
        mxfs_pal_tcp_close(sock);
        mxfs_pal_mutex_lock(peer->send_lock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);
        return ret;
    }

    /* Read NODE_JOIN reply */
    ret = mxfs_pal_tcp_recv(sock, &reply, sizeof(reply));
    if (ret < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: handshake reply from node %u failed: %d",
                     node_id, ret);
        mxfs_pal_tcp_close(sock);
        mxfs_pal_mutex_lock(peer->send_lock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);
        return ret;
    }

    if (reply.hdr.magic != MXFS_DLM_MAGIC ||
        reply.hdr.type != MXFS_MSG_NODE_JOIN) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "peer: bad handshake reply from node %u", node_id);
        mxfs_pal_tcp_close(sock);
        mxfs_pal_mutex_lock(peer->send_lock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);
        return -EPROTO;
    }

    /* Multi-LUN: verify reply is from the correct volume.
     * SO_REUSEPORT may have delivered us to the wrong listener. */
    if (reply.volume_id != 0 &&
        ctx->local_volume_id != 0 &&
        reply.volume_id != ctx->local_volume_id) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "peer: reply from node %u is for volume 0x%llx "
                     "(ours 0x%llx), retrying",
                     node_id,
                     (unsigned long long)reply.volume_id,
                     (unsigned long long)ctx->local_volume_id);
        mxfs_pal_tcp_close(sock);
        mxfs_pal_mutex_lock(peer->send_lock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);
        return -EAGAIN;
    }

    mxfs_pal_mutex_lock(peer->send_lock);

    /* Bug 80: Check again before installing the new socket.  The accept
     * thread may have accepted an inbound connection from this peer
     * during the handshake (which runs without locks).  If the accept
     * thread already installed a socket and started a recv thread,
     * we must discard our outbound socket to avoid overwriting the
     * accept thread's state (which would leak its socket and orphan
     * its recv thread, leading to a use-after-free crash). */
    if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
        mxfs_pal_mutex_unlock(peer->send_lock);
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "peer: node %u already reconnected (inbound) "
                     "during outbound handshake, discarding outbound",
                     node_id);
        mxfs_pal_tcp_close(sock);
        return 0;
    }

    peer->sock = sock;
    peer->state = MXFS_CONN_ACTIVE;
    peer->last_seen = mxfs_pal_time_ms();
    mxfs_pal_mutex_unlock(peer->send_lock);

    /* Start recv thread for this peer */
    ret = start_recv_thread(ctx, peer);
    if (ret < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "peer: failed to start recv thread "
                     "for node %u: %d", node_id, ret);
        peer_handle_disconnect(ctx, peer);
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "peer: connected to node %u at %s:%u",
                 node_id, peer->host, peer->port);
    return 0;
}

int mxfs_peer_connect(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id)
{
    return peer_connect_impl(ctx, node_id, false);
}

int mxfs_peer_connect_force(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id)
{
    return peer_connect_impl(ctx, node_id, true);
}

int mxfs_peer_send(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
                    const void *msg, size_t len)
{
    struct mxfs_peer *peer;
    int ret;

    if (!ctx || !msg || len == 0)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->peer_lock);
    peer = peer_find_locked(ctx, node_id);
    mxfs_pal_mutex_unlock(ctx->peer_lock);

    if (!peer)
        return -ENOENT;

    mxfs_pal_mutex_lock(peer->send_lock);

    if (peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
        mxfs_pal_mutex_unlock(peer->send_lock);
        return -ENOTCONN;
    }

    ret = mxfs_pal_tcp_send(peer->sock, msg, (uint32_t)len);
    if (ret < 0) {
        /* Bug 83: quick retries for transient TCP hiccups.
         * Old code: 5 retries, 3.2s total, held send_lock across sleeps.
         * New code: 3 retries, 1.7s total, drops send_lock during sleep. */
        {
            int retry;
            int retry_delays[] = {200, 500, 1000};
            for (retry = 0; retry < 3; retry++) {
                mxfs_pal_mutex_unlock(peer->send_lock);
                mxfs_pal_sleep_ms(retry_delays[retry]);
                mxfs_pal_mutex_lock(peer->send_lock);
                if (peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
                    mxfs_pal_mutex_unlock(peer->send_lock);
                    return -ENOTCONN;
                }
                ret = mxfs_pal_tcp_send(peer->sock, msg, (uint32_t)len);
                if (ret == (int)len) {
                    mxfs_pal_mutex_unlock(peer->send_lock);
                    return 0;
                }
            }
        }
        /*
         * sess40 (ccloop 4cb2d0a2) FLAP FIX — do NOT tear down the socket on a
         * TRANSIENT send failure (sndtimeo / EAGAIN = the peer's receiver is
         * slow / its socket buffer is full under the 8-node create storm, NOT a
         * dead peer).  The OLD code shut the socket down + fired disconnect_cb
         * on ANY exhausted-retry error, which (a) DROPS every DLM grant/release/
         * BAST message buffered in that socket — fire-and-forget, never
         * retransmitted — directly causing the dir_reuse readdir=799 durable
         * single-dirent loss (PROVEN sess40: the loss correlates 1:1 with a
         * ~500ms "TCP peer disconnected/reconnected (transient flap absorbed)"),
         * and (b) churns the membership SUSPECT machinery.  A genuinely DEAD
         * peer is still caught promptly by TCP keepalive (~19s) and the UDP
         * lease (~75s), both well under the DLM lock-wait timeout, and by a hard
         * socket error below.  So on a transient timeout keep the connection up
         * and return an error; the DLM caller retries on the SAME live socket
         * (its bytes are still buffered in TCP and reach the peer once it
         * drains).  Only a HARD error (peer reset/closed the connection) is a
         * real break that must tear down + reconnect.
         */
        if (ret == -ETIMEDOUT || ret == -EAGAIN || ret == -EWOULDBLOCK) {
            mxfs_pal_mutex_unlock(peer->send_lock);
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: send to node %u timed out (slow peer under "
                         "load) — keeping connection, caller will retry "
                         "(keepalive/lease detect true death)", node_id);
            return -EAGAIN;
        }

        /* Hard error (ECONNRESET/EPIPE/ENOTCONN/...) — real break, disconnect. */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: communication with node %u lost (err %d) "
                     "(node will be reconnected automatically if still "
                     "available)", node_id, ret);
        mxfs_pal_tcp_shutdown(peer->sock);
        peer->state = MXFS_CONN_DISCONNECTED;
        mxfs_pal_mutex_unlock(peer->send_lock);

        if (ctx->disconnect_cb)
            ctx->disconnect_cb(ctx->disconnect_cb_data, node_id);

        return -ENOTCONN;
    }

    mxfs_pal_mutex_unlock(peer->send_lock);
    return 0;
}

int mxfs_peer_broadcast(struct mxfs_peer_ctx *ctx, const void *msg,
                         size_t len)
{
    int i;
    int sent = 0;
    int errors = 0;

    if (!ctx || !msg || len == 0)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->peer_lock);

    for (i = 0; i < ctx->peer_count; i++) {
        struct mxfs_peer *peer = &ctx->peers[i];

        if (peer->state != MXFS_CONN_ACTIVE || !peer->sock)
            continue;

        mxfs_pal_mutex_unlock(ctx->peer_lock);

        if (mxfs_peer_send(ctx, peer->node_id, msg, len) == 0)
            sent++;
        else
            errors++;

        mxfs_pal_mutex_lock(ctx->peer_lock);
    }

    mxfs_pal_mutex_unlock(ctx->peer_lock);

    return sent > 0 ? 0 : (errors > 0 ? -EIO : -ENOENT);
}

struct mxfs_peer *mxfs_peer_find(struct mxfs_peer_ctx *ctx,
                                  mxfs_node_id_t node_id)
{
    struct mxfs_peer *peer;

    if (!ctx)
        return NULL;

    mxfs_pal_mutex_lock(ctx->peer_lock);
    peer = peer_find_locked(ctx, node_id);
    mxfs_pal_mutex_unlock(ctx->peer_lock);

    return peer;
}

bool mxfs_peer_is_connected(struct mxfs_peer_ctx *ctx,
                              mxfs_node_id_t node_id)
{
    struct mxfs_peer *peer;
    bool connected;

    if (!ctx)
        return false;

    mxfs_pal_mutex_lock(ctx->peer_lock);
    peer = peer_find_locked(ctx, node_id);
    connected = peer && peer->state == MXFS_CONN_ACTIVE && peer->sock;
    mxfs_pal_mutex_unlock(ctx->peer_lock);

    return connected;
}

void mxfs_peer_set_msg_cb(struct mxfs_peer_ctx *ctx,
                            mxfs_peer_msg_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->msg_cb = cb;
    ctx->msg_cb_data = data;
}

void mxfs_peer_set_disconnect_cb(struct mxfs_peer_ctx *ctx,
                                   mxfs_peer_disconnect_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->disconnect_cb = cb;
    ctx->disconnect_cb_data = data;
}

void mxfs_peer_set_connect_cb(struct mxfs_peer_ctx *ctx,
                                mxfs_peer_connect_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->connect_cb = cb;
    ctx->connect_cb_data = data;
}
