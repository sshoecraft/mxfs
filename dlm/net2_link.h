/*
 * MXFS — Multinode XFS
 * NET2 transport — link layer surface (engine-internal)
 *
 * TCP neighbor links: accept/connect + SYN/SYN_ACK TLV handshake
 * (lower-SLOT-initiates), per-link recv thread, per-link prioritized
 * egress worker (weighted deficit round-robin).  Fork of peer.c's
 * lifecycle discipline; the reconnect policy deliberately departs from
 * peer.c (sess40 keep-socket-up) because the retransmit ring owns
 * delivery — a link event is a routing event, never node death.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_LINK_H
#define MXFS_LIBMXFS_NET2_LINK_H

#include "net2_ctx.h"

int  net2_link_listen_start(struct mxfs_net2_ctx *ctx);

/* Outbound connect + handshake for `slot` (lower-slot side only;
 * RT-thread context).  No-op unless the link is DOWN, addr known,
 * desired, and self_slot < slot. */
void net2_link_connect(struct mxfs_net2_ctx *ctx, uint16_t slot);

/* Tear a link down (send/recv error, test surface).  Shuts the socket
 * down and marks DOWN; threads unwind and are reaped by the next
 * connect/accept/stop.  Sessions survive (reset counted). */
void net2_link_down(struct mxfs_net2_ctx *ctx, struct net2_link *link);

/* Join exited/exit-pending threads + close the socket of a DOWN link.
 * Caller must NOT hold link->lock. */
void net2_link_reap(struct mxfs_net2_ctx *ctx, struct net2_link *link);

/* Advisory backpressure probe: is dst's class queue at its cap?
 * (Pre-send check for GRANT/DISCOVERY only.) */
bool net2_link_class_full(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                          uint8_t pri);

/* Enqueue a reliable ring reference on dst's current route.
 * Returns -ENOTCONN when no route, -EAGAIN on GRANT/DISCOVERY
 * queue-cap overflow (coherence classes always accept + count). */
int  net2_link_enqueue_ref(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                           struct net2_session *sess, uint64_t seq,
                           uint8_t pri, bool retx, uint16_t inner_type);

/* Enqueue an owned pre-packed frame (unreliable DATA / FIN / ACK-now).
 * Takes ownership of `frame` on success (returns 0); caller frees on
 * error. */
int  net2_link_enqueue_frame(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                             uint8_t *frame, uint32_t frame_len,
                             uint8_t frame_class, uint8_t pri,
                             uint16_t inner_type);

/* Wake dst's egress worker (delayed-ack kick / retransmit enqueue). */
void net2_link_kick(struct mxfs_net2_ctx *ctx, uint16_t dst_slot);

/* Stop path, in order: stop listener, down every link, join all link
 * threads, free queues.  ctx->running must already be false. */
void net2_link_shutdown_all(struct mxfs_net2_ctx *ctx);

#endif /* MXFS_LIBMXFS_NET2_LINK_H */
