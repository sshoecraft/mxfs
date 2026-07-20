/*
 * MXFS — Multinode XFS
 * NET2 transport — midcomms surface (engine-internal)
 *
 * Sessions, seq/ack/sack, retransmit ring, in-order delivery + dedup.
 * Called by net2.c (send/lifecycle), net2_link.c (rx + egress packing)
 * and the RT thread.  See net2_ctx.h for structs + locking order.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_MIDCOMMS_H
#define MXFS_LIBMXFS_NET2_MIDCOMMS_H

#include "net2_ctx.h"

/* Session refcounting: the ctx table/GC list, a link's handshake
 * binding, and every egress queue reference hold one ref each. */
void net2_sess_ref(struct net2_session *sess);
void net2_sess_unref(struct net2_session *sess);

/* mxfs_net2_send() body: session lookup/create, ring append, enqueue. */
int  net2_midcomms_send(struct mxfs_net2_ctx *ctx,
                        const struct mxfs_net2_id *dst,
                        enum net2_priority pri, bool reliable,
                        uint32_t msg_id, const void *buf, uint32_t len);

/*
 * Bind the live session for a handshaken peer: resume when {inc, nonce}
 * match the existing one, adopt when the existing one is EMBRYONIC with
 * matching inc, supersede + create otherwise.  Returns NULL only on
 * allocation failure.  Caller must NOT hold ctx->lock.
 */
struct net2_session *net2_midcomms_bind(struct mxfs_net2_ctx *ctx,
                                        uint16_t slot, uint32_t inc,
                                        uint64_t nonce, uint32_t features);

/* Enqueue everything buffered-but-unqueued (post-handshake flush). */
void net2_midcomms_resume_flush(struct mxfs_net2_ctx *ctx,
                                struct net2_session *sess);

/* Full DATA/ACK/FIN frame arrived on a link (recv thread context).
 * `sess` is the link's handshake-bound session; payload is borrowed. */
void net2_midcomms_rx(struct mxfs_net2_ctx *ctx, struct net2_session *sess,
                      const struct mxfs_net2_hdr *hdr,
                      const uint8_t *payload, uint32_t len);

/* RT-thread duties. */
void net2_midcomms_rto_scan(struct mxfs_net2_ctx *ctx, uint64_t now_ms);
void net2_midcomms_gc(struct mxfs_net2_ctx *ctx, uint64_t now_ms);

/* The link under `sess` died: count the reset (entries stay — the ring
 * owns delivery; reconnect resumes the session). */
void net2_midcomms_link_reset(struct mxfs_net2_ctx *ctx,
                              struct net2_session *sess);

/* Stop path: abort every outstanding entry (explicit disposition),
 * free sessions.  All engine threads must already be joined. */
void net2_midcomms_shutdown(struct mxfs_net2_ctx *ctx);

/* Earliest pending standalone-ACK deadline; false if none pending.
 * (Feeds the egress worker's cond_timedwait deadline.) */
bool net2_midcomms_ack_deadline(struct net2_session *sess,
                                uint64_t *deadline_ms);

/*
 * Build a standalone ACK frame into frame_out (MXFS_NET2_HDR_SIZE
 * bytes) if one is due (deadline passed, owed count reached, or force).
 * Returns frame length or 0.
 */
uint32_t net2_midcomms_make_ack(struct mxfs_net2_ctx *ctx,
                                struct net2_session *sess, bool force,
                                uint64_t now_ms, uint8_t *frame_out);

/*
 * Pack the ring entry {sess, seq} into frame_out (hdr + payload, with
 * piggybacked fresh ack/sack).  Returns frame length, or 0 if the entry
 * retired while queued (ACKed, SACK'd retransmit, or session aborted).
 * Sets *inner_type for the fault-injection boundary.
 */
uint32_t net2_midcomms_pack_entry(struct mxfs_net2_ctx *ctx,
                                  struct net2_session *sess, uint64_t seq,
                                  bool retx, uint8_t *frame_out,
                                  uint16_t *inner_type);

#endif /* MXFS_LIBMXFS_NET2_MIDCOMMS_H */
