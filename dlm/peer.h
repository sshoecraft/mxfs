/*
 * MXFS — Multinode XFS
 * Portable TCP peer connection management
 *
 * Manages TCP connections between cluster nodes for DLM lock traffic.
 * Per-peer receive threads handle message framing and dispatch.
 * An accept thread handles inbound connections with NODE_JOIN handshake.
 *
 * Ported from kernel/mxfs_peer.{c,h} — kernel socket API, kthreads,
 * and mutexes replaced with PAL TCP, threading, and mutex APIs.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_PEER_H
#define MXFS_LIBMXFS_PEER_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"

/* Connection state for a single peer */
enum mxfs_conn_state {
    MXFS_CONN_DISCONNECTED = 0,
    MXFS_CONN_CONNECTING,
    MXFS_CONN_ACTIVE,
};

/* Per-peer connection state */
struct mxfs_peer {
    mxfs_node_id_t      node_id;
    uint8_t             node_uuid[16];
    char                host[64];
    uint16_t            port;
    mxfs_sock_t         *sock;
    enum mxfs_conn_state state;
    mxfs_mutex_t        *send_lock;
    mxfs_thread_t       *recv_thread;
    uint64_t            last_seen;  /* mxfs_pal_time_ms() */
};

/* Message received callback */
typedef void (*mxfs_peer_msg_cb)(void *data, mxfs_node_id_t sender,
                                  void *msg, size_t len);

/* Peer disconnected callback */
typedef void (*mxfs_peer_disconnect_cb)(void *data, mxfs_node_id_t node_id);

/* Peer connected callback — fired when an inbound connection is accepted */
typedef void (*mxfs_peer_connect_cb)(void *data, mxfs_node_id_t node_id);

/* Per-mount peer networking context */
struct mxfs_peer_ctx {
    struct mxfs_peer    peers[MXFS_MAX_NODES];
    int                 peer_count;
    mxfs_sock_t         *listen_sock;
    mxfs_thread_t       *accept_thread;
    mxfs_node_id_t      local_node_id;
    uint8_t             local_node_uuid[16];
    uint16_t            local_port;
    mxfs_volume_id_t    local_volume_id; /* multi-LUN: reject wrong-volume peers */
    volatile bool       running;
    mxfs_mutex_t        *peer_lock;
    mxfs_sock_t         *pending_sock; /* accept thread's in-progress socket */

    mxfs_peer_msg_cb        msg_cb;
    void                    *msg_cb_data;
    mxfs_peer_disconnect_cb disconnect_cb;
    void                    *disconnect_cb_data;
    mxfs_peer_connect_cb    connect_cb;
    void                    *connect_cb_data;
};

/* Lifecycle */
struct mxfs_peer_ctx *mxfs_peer_init(mxfs_node_id_t node_id,
                                      const uint8_t *uuid,
                                      uint16_t port,
                                      mxfs_volume_id_t volume_id);
int  mxfs_peer_start(struct mxfs_peer_ctx *ctx);
void mxfs_peer_shutdown(struct mxfs_peer_ctx *ctx);

/* Peer management */
int  mxfs_peer_add(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
                    const uint8_t *uuid, const char *host, uint16_t port);
int  mxfs_peer_connect(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id);
int  mxfs_peer_connect_force(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id);
int  mxfs_peer_send(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
                     const void *msg, size_t len);
int  mxfs_peer_broadcast(struct mxfs_peer_ctx *ctx, const void *msg,
                          size_t len);

/* Query */
struct mxfs_peer *mxfs_peer_find(struct mxfs_peer_ctx *ctx,
                                  mxfs_node_id_t node_id);
bool mxfs_peer_is_connected(struct mxfs_peer_ctx *ctx,
                              mxfs_node_id_t node_id);

/* Callback registration */
void mxfs_peer_set_msg_cb(struct mxfs_peer_ctx *ctx,
                            mxfs_peer_msg_cb cb, void *data);
void mxfs_peer_set_disconnect_cb(struct mxfs_peer_ctx *ctx,
                                   mxfs_peer_disconnect_cb cb, void *data);
void mxfs_peer_set_connect_cb(struct mxfs_peer_ctx *ctx,
                                mxfs_peer_connect_cb cb, void *data);

#endif /* MXFS_LIBMXFS_PEER_H */
