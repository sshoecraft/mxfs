/*
 * MXFS — Multinode XFS
 * UDP peer discovery
 *
 * Automatic peer discovery over UDP multicast or broadcast.
 * Nodes periodically announce themselves on a group address.
 * Other nodes with the same XFS volume UUID automatically
 * detect each other and establish TCP connections via callback.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_DISCOVERY_H
#define MXFSD_DISCOVERY_H

#include <mxfs/mxfs_common.h>
#include <stdbool.h>
#include <pthread.h>

#define MXFS_DISCOVERY_MAGIC        0x4D584644  /* "MXFD" */
#define MXFS_DISCOVERY_VERSION      1
#define MXFS_DISCOVERY_PORT         7601
#define MXFS_DISCOVERY_MCAST        "239.66.83.1"
#define MXFS_DISCOVERY_INTERVAL_MS  2000
#define MXFS_DISCOVERY_TIMEOUT_MS   (MXFS_DISCOVERY_INTERVAL_MS * 3)

/* Announcement packet sent periodically over UDP */
struct mxfsd_discovery_announce {
	uint32_t           magic;
	uint16_t           version;
	uint16_t           flags;           /* 0x01 = has_volume */
	uint8_t            node_uuid[16];   /* persistent node UUID */
	mxfs_node_id_t     node_id;         /* derived from UUID */
	uint16_t           tcp_port;        /* TCP port for DLM traffic */
	uint16_t           pad;
	uint8_t            volume_uuid[16]; /* XFS sb_uuid of shared device */
	mxfs_volume_id_t   volume_id;       /* derived from sb_uuid */
	char               hostname[64];    /* for display/logging */
};

/* Callback fired when a new peer is discovered */
typedef void (*mxfsd_discovery_peer_cb)(
	const uint8_t *node_uuid,
	mxfs_node_id_t node_id,
	const char *host,             /* IP address string of the sender */
	uint16_t tcp_port,
	const uint8_t *volume_uuid,
	mxfs_volume_id_t volume_id,
	void *user_data);

/* Discovery subsystem context */
struct mxfsd_discovery_ctx {
	int                sockfd;          /* UDP socket */
	uint16_t           port;            /* discovery port */
	char               mcast_addr[64];  /* multicast group or bcast addr */
	bool               use_broadcast;   /* true = broadcast mode */
	char               iface[64];       /* interface name (e.g. "eth0") */

	struct mxfsd_discovery_announce local_announce;

	pthread_t          sender_thread;
	pthread_t          receiver_thread;
	bool               running;

	mxfsd_discovery_peer_cb peer_cb;
	void              *peer_cb_data;

	/* Track already-seen peers to avoid duplicate callbacks */
	struct {
		mxfs_node_id_t node_id;
		uint64_t       last_seen_ms;
	} seen[MXFS_MAX_NODES];
	int                seen_count;
	pthread_mutex_t    lock;
};

/* Lifecycle */
int  mxfsd_discovery_init(struct mxfsd_discovery_ctx *ctx,
                           const struct mxfsd_discovery_announce *local,
                           const char *mcast_addr,  /* NULL = default */
                           uint16_t port,           /* 0 = default */
                           const char *iface,       /* NULL = all ifaces */
                           bool use_broadcast);
void mxfsd_discovery_shutdown(struct mxfsd_discovery_ctx *ctx);

/* Start sender/receiver threads */
int  mxfsd_discovery_start(struct mxfsd_discovery_ctx *ctx);
void mxfsd_discovery_stop(struct mxfsd_discovery_ctx *ctx);

/* Set callback for new peer discovery */
void mxfsd_discovery_set_peer_cb(struct mxfsd_discovery_ctx *ctx,
                                  mxfsd_discovery_peer_cb cb, void *data);

#endif /* MXFSD_DISCOVERY_H */
