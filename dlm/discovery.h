/*
 * MXFS — Multinode XFS
 * Portable UDP peer discovery
 *
 * Automatic peer discovery over UDP multicast or broadcast.
 * Nodes periodically announce themselves on a group address.
 * Other nodes with the same XFS volume UUID automatically
 * detect each other and trigger TCP connection establishment.
 *
 * Ported from kernel/mxfs_discovery.{c,h} — kernel sockets,
 * delayed_work, and kthreads replaced with PAL calls.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_DISCOVERY_H
#define MXFS_LIBMXFS_DISCOVERY_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_ports.h"

#define MXFS_DISCOVERY_MAGIC            0x4D584644  /* "MXFD" */
#define MXFS_DISCOVERY_VERSION          1
#define MXFS_DISCOVERY_PORT             MXFS_PORT_DISCOVERY
#define MXFS_DISCOVERY_MCAST            "239.66.83.1"
#define MXFS_DISCOVERY_INTERVAL_MS      2000
#define MXFS_DISCOVERY_TIMEOUT_MS       6000
#define MXFS_DISCOVERY_BURST_COUNT      10
#define MXFS_DISCOVERY_BURST_INTERVAL_MS 500

#define MXFS_DISCOVERY_FLAG_HAS_VOLUME  0x01

/* Announcement packet sent periodically over UDP — wire-compatible */
#pragma pack(push, 1)
struct mxfs_discovery_announce {
    uint32_t        magic;
    uint16_t        version;
    uint16_t        flags;
    uint8_t         node_uuid[16];
    mxfs_node_id_t  node_id;
    uint16_t        tcp_port;
    uint8_t         dlm_transport;  /* 0=CAW, 1=TCP (from enum mxfs_dlm_transport) */
    uint8_t         pad;
    uint8_t         volume_uuid[16];
    mxfs_volume_id_t volume_id;
    char            hostname[64];
};
#pragma pack(pop)

/* Per-peer tracking entry in the seen list */
struct mxfs_discovery_seen {
    mxfs_node_id_t  node_id;
    uint64_t        last_seen;  /* mxfs_pal_time_ms() */
};

/* Callback fired when a new peer is discovered */
typedef void (*mxfs_discovery_peer_cb)(void *data,
                                        const struct mxfs_discovery_announce *ann);

/* Per-mount discovery context */
struct mxfs_discovery_ctx {
    mxfs_sock_t             *sock;
    struct mxfs_discovery_announce local_announce;
    char                    mcast_addr[64];
    char                    send_addr[64];
    uint16_t                port;
    bool                    use_broadcast;

    struct mxfs_discovery_seen seen[MXFS_MAX_NODES];
    int                     seen_count;
    mxfs_mutex_t            *seen_lock;

    mxfs_thread_t           *sender_thread;
    mxfs_thread_t           *recv_thread;
    volatile bool           running;

    /* Shutdown signaling: condvar wakes sleeping sender thread */
    mxfs_mutex_t            *shutdown_lock;
    mxfs_cond_t             *shutdown_cond;

    mxfs_discovery_peer_cb  peer_cb;
    void                    *peer_cb_data;
};

/* Lifecycle */
struct mxfs_discovery_ctx *mxfs_discovery_create(
    mxfs_node_id_t node_id,
    const uint8_t *node_uuid,
    const uint8_t *volume_uuid,
    mxfs_volume_id_t volume_id,
    uint16_t tcp_port,
    const char *mcast_addr,
    uint16_t disc_port,
    bool use_broadcast);

void mxfs_discovery_destroy(struct mxfs_discovery_ctx *ctx);
int  mxfs_discovery_start(struct mxfs_discovery_ctx *ctx);
int  mxfs_discovery_start_recv_only(struct mxfs_discovery_ctx *ctx);
void mxfs_discovery_stop(struct mxfs_discovery_ctx *ctx);

/* Callback registration */
void mxfs_discovery_set_peer_cb(struct mxfs_discovery_ctx *ctx,
                                 mxfs_discovery_peer_cb cb, void *data);

/* Set the DLM transport field in outgoing announcements */
void mxfs_discovery_set_transport(struct mxfs_discovery_ctx *ctx,
                                   uint8_t transport);

#endif /* MXFS_LIBMXFS_DISCOVERY_H */
