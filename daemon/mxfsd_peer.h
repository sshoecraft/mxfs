/*
 * MXFS — Multinode XFS
 * Peer connection management
 *
 * Manages TCP connections to all peer mxfsd daemons. Handles connection
 * establishment, reconnection, message framing, and send/receive.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_PEER_H
#define MXFSD_PEER_H

#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include <stdbool.h>
#include <pthread.h>

/* Connection state for a single peer */
enum mxfsd_conn_state {
	MXFSD_CONN_DISCONNECTED = 0,
	MXFSD_CONN_CONNECTING,
	MXFSD_CONN_HANDSHAKE,
	MXFSD_CONN_ACTIVE,
	MXFSD_CONN_DRAINING,
};

/* Per-peer connection context */
struct mxfsd_peer {
	mxfs_node_id_t      node_id;
	char                name[MXFS_NODE_NAME_MAX];
	char                host[256];
	uint16_t            port;
	int                 sockfd;
	enum mxfsd_conn_state state;
	mxfs_epoch_t        last_epoch;
	uint64_t            last_seen_ms;     /* monotonic timestamp */
	uint32_t            send_seq;
	uint32_t            recv_seq;
	pthread_mutex_t     send_lock;
};

/* Called when a peer TCP connection drops */
typedef void (*mxfsd_peer_disconnect_cb)(mxfs_node_id_t node, void *user_data);

/* Called when a complete message is received from a peer */
typedef void (*mxfsd_peer_msg_cb)(mxfs_node_id_t sender,
                                   const struct mxfs_dlm_msg_hdr *hdr,
                                   const void *payload, uint32_t payload_len,
                                   void *user_data);

/* Peer subsystem context */
struct mxfsd_peer_ctx {
	struct mxfsd_peer   peers[MXFS_MAX_NODES];
	int                 peer_count;
	int                 listen_fd;
	mxfs_node_id_t      local_node_id;
	pthread_t           accept_thread;
	pthread_t           recv_thread;
	bool                running;
	mxfsd_peer_disconnect_cb disconnect_cb;
	void               *disconnect_cb_data;
	mxfsd_peer_msg_cb   msg_cb;
	void               *msg_cb_data;
};

int  mxfsd_peer_init(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t local_id,
                     const char *bind_addr, uint16_t bind_port);
void mxfsd_peer_shutdown(struct mxfsd_peer_ctx *ctx);

int  mxfsd_peer_add(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id,
                    const char *host, uint16_t port);
int  mxfsd_peer_connect(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id);
void mxfsd_peer_disconnect(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id);

int  mxfsd_peer_send(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t target,
                     const struct mxfs_dlm_msg_hdr *msg);
int  mxfsd_peer_broadcast(struct mxfsd_peer_ctx *ctx,
                          const struct mxfs_dlm_msg_hdr *msg);

struct mxfsd_peer *mxfsd_peer_find(struct mxfsd_peer_ctx *ctx,
                                   mxfs_node_id_t id);
bool mxfsd_peer_is_alive(const struct mxfsd_peer *peer, uint64_t now_ms,
                         uint64_t timeout_ms);
void mxfsd_peer_set_disconnect_cb(struct mxfsd_peer_ctx *ctx,
                                  mxfsd_peer_disconnect_cb cb, void *data);
void mxfsd_peer_set_msg_cb(struct mxfsd_peer_ctx *ctx,
                            mxfsd_peer_msg_cb cb, void *data);

#endif /* MXFSD_PEER_H */
