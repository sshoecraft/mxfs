/*
 * MXFS — Multinode XFS
 * NET2 transport — TCP neighbor links
 *
 * Fork of peer.c's connection lifecycle with three deliberate changes:
 *
 *  1. LOWER-SLOT-INITIATES (peer.c uses lower node_id, 657-668): NET2
 *     identity is slot+incarnation.  A pair therefore has a fixed
 *     direction — links[slot < self] are inbound-only, links[slot >
 *     self] outbound-only — which removes peer.c's accept/connect
 *     cross-races entirely.
 *  2. Per-link EGRESS WORKER draining 5 priority queues by weighted
 *     deficit round-robin (quanta from tun.quantum_pct, strict class
 *     order inside a round, fresh:retx 3:1 alternation inside a class,
 *     standalone ACKs first).  Replaces mxfs_peer_send's caller-context
 *     send under send_lock (peer.c:884).
 *  3. Reconnect tears down freely (departure from peer.c:914-940
 *     sess40 keep-socket-up): the retransmit ring owns delivery, the
 *     session survives, a link event is a routing event.
 *
 * Handshake: connector sends an FC_SYN frame whose payload is the TLV
 * block (UUID, volume, fs_gen, nonce, features, wire version); acceptor
 * validates fail-closed and replies FC_SYN_ACK with its own TLVs.  Both
 * sides then bind the session (net2_midcomms_bind) and start the link
 * worker threads.  A rejected handshake applies a short accept backoff
 * (interim per-source rate limiting until the membership plane, step 5).
 *
 * Listen port = cfg.base_port + self_slot (one process per node in the
 * kernel, N nodes per process in the harness — per-slot ports serve
 * both and avoid SO_REUSEPORT listener ambiguity).  Peer addresses come
 * from mxfs_net2_set_peer_addr (discovery feeds this at step 7); the
 * port defaults to cfg.base_port + peer_slot when unset.
 *
 * Fault injection (net2_fault) evaluates at this frame boundary on both
 * sides, including handshake frames.  Recv-side TRUNC is modeled as a
 * stream desync => link reset (the §13.1 reset-at-framing-point family);
 * recv-side CORRUPT with no payload degrades to drop.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_link.h"
#include "net2_midcomms.h"
#include "net2_overlay.h"
#include "../include/mxfs/mxfs_dlm.h"

#ifndef __KERNEL__
#include <stdio.h>          /* snprintf; the kernel build gets it from
                             * linux/kernel.h via pal.h */
#endif

#define NET2_CONNECT_BACKOFF_MS      200
#define NET2_CONNECT_BACKOFF_MAX_MS  2000
#define NET2_HANDSHAKE_DEADLINE_MS   5000
#define NET2_ACCEPT_REJECT_SLEEP_MS  10
#define NET2_EGRESS_IDLE_WAIT_MS     100
#define NET2_SYN_TLV_MAX             256

struct net2_thread_arg {
	struct mxfs_net2_ctx *ctx;
	struct net2_link *link;
	struct net2_session *sess;        /* holds one ref; unref at exit */
};

/* ─── small helpers ─── */

static void net2_count_malformed(struct mxfs_net2_ctx *ctx,
                                 enum mxfs_net2_hdr_err err)
{
	mxfs_pal_mutex_lock(ctx->stats_lock);
	ctx->stats.malformed_frames++;
	if ((int)err >= 0 && (int)err < 8)
		ctx->stats.malformed[err]++;
	mxfs_pal_mutex_unlock(ctx->stats_lock);
}

static uint16_t net2_inner_type(uint8_t frame_class, const uint8_t *payload,
                                uint32_t len)
{
	if (frame_class == MXFS_NET2_FC_DATA && payload &&
	    len >= sizeof(struct mxfs_dlm_msg_hdr))
		return ((const struct mxfs_dlm_msg_hdr *)payload)->type;
	return 0;
}

static int net2_fault_check(struct mxfs_net2_ctx *ctx,
                            enum mxfs_net2_fault_dir dir,
                            uint8_t frame_class, uint16_t inner_type,
                            struct mxfs_net2_fault_hit *hit)
{
	int rc;

	mxfs_pal_mutex_lock(ctx->fault_lock);
	rc = mxfs_net2_fault_eval(&ctx->fault, dir, frame_class, inner_type,
	                          hit);
	mxfs_pal_mutex_unlock(ctx->fault_lock);
	return rc;
}

/* ─── SYN / SYN_ACK build + parse ─── */

static uint32_t net2_build_hello(struct mxfs_net2_ctx *ctx,
                                 uint8_t frame_class, uint16_t dst_slot,
                                 uint32_t dst_inc, uint8_t *frame)
{
	struct mxfs_net2_hdr h;
	uint8_t tlv[NET2_SYN_TLV_MAX];
	uint8_t le[8];
	int off = 0;
	uint16_t wire_ver = MXFS_NET2_WIRE_VERSION;

	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off, MXFS_NET2_TLV_UUID,
	                        ctx->cfg.uuid, 16);
	mxfs_net2_put_le32(le, ctx->cfg.volume_id);
	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off,
	                        MXFS_NET2_TLV_VOLUME_ID, le, 4);
	mxfs_net2_put_le32(le, ctx->cfg.fs_gen);
	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off, MXFS_NET2_TLV_FS_GEN,
	                        le, 4);
	mxfs_net2_put_le64(le, ctx->cfg.boot_nonce);
	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off, MXFS_NET2_TLV_NONCE,
	                        le, 8);
	mxfs_net2_put_le32(le, ctx->cfg.features);
	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off, MXFS_NET2_TLV_FEATURES,
	                        le, 4);
	mxfs_net2_put_le16(le, wire_ver);
	off = mxfs_net2_tlv_put(tlv, sizeof(tlv), off, MXFS_NET2_TLV_WIRE_VER,
	                        le, 2);
	if (off < 0)
		return 0;

	memset(&h, 0, sizeof(h));
	h.magic = MXFS_NET2_MAGIC;
	h.version = MXFS_NET2_WIRE_VERSION;
	h.frame_class = frame_class;
	h.priority = NET2_PRI_FENCE;
	h.payload_len = (uint16_t)off;
	h.cluster_uuid_hash = ctx->cfg.uuid_hash;
	h.membership_epoch = ctx->membership_epoch;
	h.src_slot = ctx->cfg.self_slot;
	h.dst_slot = dst_slot;
	h.src_incarnation = ctx->cfg.self_incarnation;
	h.dst_incarnation = dst_inc;
	mxfs_net2_hdr_pack(&h, frame);
	memcpy(frame + MXFS_NET2_HDR_SIZE, tlv, (size_t)off);
	return MXFS_NET2_HDR_SIZE + (uint32_t)off;
}

struct net2_hello {
	uint16_t slot;
	uint32_t inc;
	uint64_t nonce;
	uint32_t features;
	uint16_t wire_ver;
};

/*
 * Validate a received SYN/SYN_ACK payload.  Fail-closed: all six
 * required TLVs must be present and the cluster identity (UUID, volume,
 * fs_gen) must match ours exactly.  Returns 0 or -EPROTO/-EREMOTE
 * (-EREMOTE = identity mismatch, counted as cross-cluster).
 */
static int net2_parse_hello(struct mxfs_net2_ctx *ctx,
                            const struct mxfs_net2_hdr *hdr,
                            const uint8_t *payload, uint32_t len,
                            struct net2_hello *out)
{
	int off = 0, rc;
	uint16_t type, tlen;
	const uint8_t *val;
	bool got_uuid = false, got_vol = false, got_gen = false;
	bool got_nonce = false, got_feat = false, got_ver = false;

	memset(out, 0, sizeof(*out));
	out->slot = hdr->src_slot;
	out->inc = hdr->src_incarnation;

	while ((rc = mxfs_net2_tlv_next(payload, (int)len, &off, &type,
	                                &tlen, &val)) == 1) {
		switch (type) {
		case MXFS_NET2_TLV_UUID:
			if (tlen != 16)
				return -EPROTO;
			if (memcmp(val, ctx->cfg.uuid, 16) != 0)
				return -EREMOTE;
			got_uuid = true;
			break;
		case MXFS_NET2_TLV_VOLUME_ID:
			if (tlen != 4)
				return -EPROTO;
			if (mxfs_net2_get_le32(val) != ctx->cfg.volume_id)
				return -EREMOTE;
			got_vol = true;
			break;
		case MXFS_NET2_TLV_FS_GEN:
			if (tlen != 4)
				return -EPROTO;
			if (mxfs_net2_get_le32(val) != ctx->cfg.fs_gen)
				return -EREMOTE;
			got_gen = true;
			break;
		case MXFS_NET2_TLV_NONCE:
			if (tlen != 8)
				return -EPROTO;
			out->nonce = mxfs_net2_get_le64(val);
			got_nonce = true;
			break;
		case MXFS_NET2_TLV_FEATURES:
			if (tlen != 4)
				return -EPROTO;
			out->features = mxfs_net2_get_le32(val);
			got_feat = true;
			break;
		case MXFS_NET2_TLV_WIRE_VER:
			if (tlen != 2)
				return -EPROTO;
			out->wire_ver = mxfs_net2_get_le16(val);
			got_ver = true;
			break;
		default:
			break;                    /* unknown: skip (fwd compat) */
		}
	}
	if (rc < 0)
		return -EPROTO;                   /* truncated TLV block */
	if (!got_uuid || !got_vol || !got_gen || !got_nonce || !got_feat ||
	    !got_ver)
		return -EPROTO;                   /* required set missing */
	if (out->wire_ver < MXFS_NET2_WIRE_VERSION)
		return -EPROTO;
	if (out->slot >= MXFS_MAX_NODES)
		return -EPROTO;
	return 0;
}

/* Read one whole frame (hdr + payload) during a handshake.  Applies
 * validation and structural counters, NOT fault injection (the caller
 * does that — directions differ).  Returns payload length (>=0) or
 * negative errno.  hdr_out is unpacked+validated on success. */
static int net2_read_frame(struct mxfs_net2_ctx *ctx, mxfs_sock_t *sock,
                           struct mxfs_net2_hdr *hdr_out, uint8_t *payload,
                           uint32_t payload_cap)
{
	uint8_t hdrbuf[MXFS_NET2_HDR_SIZE];
	enum mxfs_net2_hdr_err err;
	int ret;

	ret = mxfs_pal_tcp_recv(sock, hdrbuf, MXFS_NET2_HDR_SIZE);
	if (ret < 0)
		return ret;
	mxfs_net2_hdr_unpack(hdrbuf, hdr_out);
	err = mxfs_net2_hdr_validate(hdr_out);
	if (err != MXFS_NET2_HDR_OK) {
		net2_count_malformed(ctx, err);
		return -EBADMSG;
	}
	if (hdr_out->payload_len > payload_cap)
		return -EBADMSG;
	if (hdr_out->payload_len) {
		ret = mxfs_pal_tcp_recv(sock, payload, hdr_out->payload_len);
		if (ret < 0)
			return ret;
	}
	return (int)hdr_out->payload_len;
}

/* ─── egress queues ─── */

static void net2_linkq_push(struct net2_linkq *q, struct net2_eqent *ent,
                            bool retx)
{
	ent->next = NULL;
	if (retx) {
		if (q->retx_tail)
			q->retx_tail->next = ent;
		else
			q->retx_head = ent;
		q->retx_tail = ent;
	} else {
		if (q->fresh_tail)
			q->fresh_tail->next = ent;
		else
			q->fresh_head = ent;
		q->fresh_tail = ent;
	}
	q->depth++;
}

static struct net2_eqent *net2_linkq_pop_list(struct net2_linkq *q, bool retx)
{
	struct net2_eqent *ent;

	if (retx) {
		ent = q->retx_head;
		if (ent) {
			q->retx_head = ent->next;
			if (!q->retx_head)
				q->retx_tail = NULL;
		}
	} else {
		ent = q->fresh_head;
		if (ent) {
			q->fresh_head = ent->next;
			if (!q->fresh_head)
				q->fresh_tail = NULL;
		}
	}
	if (ent) {
		ent->next = NULL;
		q->depth--;
	}
	return ent;
}

/* Pick the next sendable entry from a class queue: fresh:retx 3:1
 * alternation so retransmits never starve first transmissions and vice
 * versa (§7.A); entries with a future not_before are not sendable. */
static struct net2_eqent *net2_linkq_pick(struct net2_linkq *q,
                                          uint64_t now_ms)
{
	bool fresh_ok = q->fresh_head &&
	                q->fresh_head->not_before_ms <= now_ms;
	bool retx_ok = q->retx_head && q->retx_head->not_before_ms <= now_ms;

	if (fresh_ok && (q->fresh_burst < 3 || !retx_ok)) {
		q->fresh_burst++;
		return net2_linkq_pop_list(q, false);
	}
	if (retx_ok) {
		q->fresh_burst = 0;
		return net2_linkq_pop_list(q, true);
	}
	if (fresh_ok) {
		q->fresh_burst++;
		return net2_linkq_pop_list(q, false);
	}
	return NULL;
}

/* Free one entry: drop its ring reference or its owned frame.
 * Caller holds link->lock (sess lock nests below it). */
static void net2_eqent_free(struct mxfs_net2_ctx *ctx,
                            struct net2_eqent *ent, bool clear_enqueued)
{
	if (ent->sess) {
		if (clear_enqueued) {
			mxfs_pal_mutex_lock(ent->sess->lock);
			{
				struct net2_txent *e =
					&ent->sess->tx.ring[ent->seq %
					                    ctx->tun.tx_win];
				if (e->occupied && e->seq == ent->seq)
					e->enqueued = false;
			}
			mxfs_pal_mutex_unlock(ent->sess->lock);
		}
		net2_sess_unref(ent->sess);
	}
	if (ent->frame)
		mxfs_pal_free(ent->frame);
	mxfs_pal_free(ent);
}

/* Drop every queued entry (link death / shutdown).  link->lock held. */
static void net2_link_flush_locked(struct mxfs_net2_ctx *ctx,
                                   struct net2_link *link)
{
	int c;

	for (c = 0; c < NET2_PRI_COUNT; c++) {
		struct net2_eqent *ent;

		while ((ent = net2_linkq_pop_list(&link->q[c], false)) != NULL)
			net2_eqent_free(ctx, ent, true);
		while ((ent = net2_linkq_pop_list(&link->q[c], true)) != NULL)
			net2_eqent_free(ctx, ent, true);
		link->q[c].deficit = 0;
		link->q[c].fresh_burst = 0;
	}
}

/* ─── link teardown ─── */

void net2_link_down(struct mxfs_net2_ctx *ctx, struct net2_link *link)
{
	struct net2_session *sess;

	mxfs_pal_mutex_lock(link->lock);
	if (link->sock)
		mxfs_pal_tcp_shutdown(link->sock);
	link->state = NET2_LINK_DOWN;
	link->egress_stop = true;
	sess = link->sess;
	link->sess = NULL;
	net2_link_flush_locked(ctx, link);
	mxfs_pal_cond_broadcast(link->egress_cond);
	mxfs_pal_mutex_unlock(link->lock);

	if (sess) {
		net2_midcomms_link_reset(ctx, sess);
		net2_sess_unref(sess);
		mxfs_pal_log(MXFS_LOG_INFO,
		             "net2: link to slot %u down (session survives)",
		             link->peer_slot);
	}
}

/* Join exited/exit-pending threads and close the socket of a DOWN link.
 * Caller must NOT hold link->lock (joins block). */
void net2_link_reap(struct mxfs_net2_ctx *ctx, struct net2_link *link)
{
	mxfs_thread_t *recv_t, *egress_t, *conn_t;
	mxfs_sock_t *sock;

	(void)ctx;
	mxfs_pal_mutex_lock(link->lock);
	recv_t = link->recv_thread;
	egress_t = link->egress_thread;
	conn_t = link->conn_thread;
	link->recv_thread = NULL;
	link->egress_thread = NULL;
	link->conn_thread = NULL;
	mxfs_pal_mutex_unlock(link->lock);

	if (recv_t)
		mxfs_pal_thread_join(recv_t);
	if (egress_t)
		mxfs_pal_thread_join(egress_t);
	if (conn_t)
		mxfs_pal_thread_join(conn_t);

	mxfs_pal_mutex_lock(link->lock);
	sock = link->sock;
	link->sock = NULL;
	mxfs_pal_mutex_unlock(link->lock);
	if (sock)
		mxfs_pal_tcp_close(sock);
}

/* ─── per-link receive thread ─── */

static void net2_link_recv_fn(void *arg)
{
	struct net2_thread_arg *ta = arg;
	struct mxfs_net2_ctx *ctx = ta->ctx;
	struct net2_link *link = ta->link;
	struct net2_session *sess = ta->sess;
	uint8_t *payload;
	struct {
		bool present;
		struct mxfs_net2_hdr hdr;
		uint8_t *payload;
		uint32_t len;
	} held = { .present = false };

	mxfs_pal_free(ta);
	payload = mxfs_pal_alloc(MXFS_NET2_MAX_MSG_SIZE);
	if (!payload) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2: recv thread slot %u: out of memory",
		             link->peer_slot);
		net2_sess_unref(sess);
		return;
	}

	while (ctx->running) {
		struct mxfs_net2_hdr hdr;
		struct mxfs_net2_fault_hit hit = { 0, 0 };
		mxfs_sock_t *sock;
		uint16_t inner_type;
		int ret, hitrc;

		mxfs_pal_mutex_lock(link->lock);
		if (link->egress_stop || link->state != NET2_LINK_ACTIVE ||
		    !link->sock) {
			mxfs_pal_mutex_unlock(link->lock);
			break;
		}
		sock = link->sock;
		mxfs_pal_mutex_unlock(link->lock);

		ret = net2_read_frame(ctx, sock, &hdr, payload,
		                      MXFS_NET2_MAX_MSG_SIZE);
		if (ret == -EAGAIN)
			continue;         /* kernel-pal recv timeout */
		if (ret < 0) {
			if (!ctx->running)
				break;
			/* -EBADMSG = malformed/desynced stream; anything
			 * else = connection error.  Both reset the link;
			 * the session + ring make it a routing event. */
			net2_link_down(ctx, link);
			break;
		}

		if (hdr.cluster_uuid_hash != ctx->cfg.uuid_hash) {
			net2_stat_bump(ctx, &ctx->stats.cross_cluster_rejects);
			net2_link_down(ctx, link);
			break;
		}

		inner_type = net2_inner_type(hdr.frame_class, payload,
		                             (uint32_t)ret);
		hitrc = net2_fault_check(ctx, MXFS_NET2_FAULT_RECV,
		                         hdr.frame_class, inner_type, &hit);
		if (hitrc) {
			if (hit.action == MXFS_NET2_FAULT_DROP)
				continue;
			if (hit.action == MXFS_NET2_FAULT_TRUNC) {
				/* modeled as stream desync => reset */
				net2_link_down(ctx, link);
				break;
			}
			if (hit.action == MXFS_NET2_FAULT_DELAY)
				mxfs_pal_sleep_ms(hit.delay_ms);
			if (hit.action == MXFS_NET2_FAULT_CORRUPT) {
				if (ret > 0)
					payload[ret / 2] ^= 0x5A;
				else
					continue;      /* degrade to drop */
			}
			if (hit.action == MXFS_NET2_FAULT_REORDER &&
			    !held.present) {
				held.payload = mxfs_pal_alloc(ret ? (uint32_t)ret : 1);
				if (held.payload) {
					memcpy(held.payload, payload,
					       (size_t)ret);
					held.hdr = hdr;
					held.len = (uint32_t)ret;
					held.present = true;
					continue;    /* delivered after next */
				}
			}
		}

		if (hdr.frame_class == MXFS_NET2_FC_SYN ||
		    hdr.frame_class == MXFS_NET2_FC_SYN_ACK) {
			mxfs_pal_log(MXFS_LOG_WARN,
			             "net2: unexpected mid-stream handshake "
			             "frame from slot %u", hdr.src_slot);
			continue;
		}

		net2_midcomms_rx(ctx, sess, &hdr, payload, (uint32_t)ret);
		if (hitrc && hit.action == MXFS_NET2_FAULT_DUP)
			net2_midcomms_rx(ctx, sess, &hdr, payload,
			                 (uint32_t)ret);

		if (held.present) {
			net2_midcomms_rx(ctx, sess, &held.hdr, held.payload,
			                 held.len);
			mxfs_pal_free(held.payload);
			held.present = false;
		}
	}

	if (held.present)
		mxfs_pal_free(held.payload);
	mxfs_pal_free(payload);
	net2_sess_unref(sess);
	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: recv thread slot %u exiting",
	             link->peer_slot);
}

/* ─── per-link egress worker ─── */

static uint64_t net2_linkq_earliest_blocked(struct net2_link *link)
{
	uint64_t earliest = 0;
	int c;

	for (c = 0; c < NET2_PRI_COUNT; c++) {
		struct net2_eqent *heads[2] = {
			link->q[c].fresh_head, link->q[c].retx_head
		};
		int i;

		for (i = 0; i < 2; i++)
			if (heads[i] && heads[i]->not_before_ms &&
			    (earliest == 0 ||
			     heads[i]->not_before_ms < earliest))
				earliest = heads[i]->not_before_ms;
	}
	return earliest;
}

/* Send `len` bytes outside link->lock.  Returns 0 or negative errno.
 * Safe because the socket is closed only after this thread is joined. */
static int net2_link_send_bytes(struct net2_link *link, mxfs_sock_t *sock,
                                const uint8_t *frame, uint32_t len)
{
	(void)link;
	return mxfs_pal_tcp_send(sock, frame, len);
}

static void net2_link_egress_fn(void *arg)
{
	struct net2_thread_arg *ta = arg;
	struct mxfs_net2_ctx *ctx = ta->ctx;
	struct net2_link *link = ta->link;
	struct net2_session *sess = ta->sess;
	uint8_t *frame;
	int32_t quantum[NET2_PRI_COUNT];
	int c;
	bool dead = false;

	mxfs_pal_free(ta);
	frame = mxfs_pal_alloc(MXFS_NET2_MAX_FRAME);
	if (!frame) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2: egress thread slot %u: out of memory",
		             link->peer_slot);
		net2_sess_unref(sess);
		return;
	}
	for (c = 0; c < NET2_PRI_COUNT; c++)
		quantum[c] = (int32_t)(NET2_WDRR_ROUND_BYTES *
		                       ctx->tun.quantum_pct[c] / 100);

	mxfs_pal_mutex_lock(link->lock);
	while (ctx->running && !link->egress_stop &&
	       link->state == NET2_LINK_ACTIVE && !dead) {
		mxfs_sock_t *sock = link->sock;
		uint64_t now = mxfs_pal_time_ms();
		bool have_work = false;
		bool sent_any = false;

		if (!sock)
			break;

		/* 1. Standalone ACK first: tiny, unblocks peer flow. */
		{
			uint32_t alen;

			mxfs_pal_mutex_unlock(link->lock);
			alen = net2_midcomms_make_ack(ctx, sess, false, now,
			                              frame);
			if (alen) {
				struct mxfs_net2_fault_hit hit;
				bool drop = false;

				if (net2_fault_check(ctx,
				                     MXFS_NET2_FAULT_SEND,
				                     MXFS_NET2_FC_ACK, 0,
				                     &hit) &&
				    hit.action == MXFS_NET2_FAULT_DROP)
					drop = true;
				if (!drop &&
				    net2_link_send_bytes(link, sock, frame,
				                         alen) < 0) {
					mxfs_pal_mutex_lock(link->lock);
					dead = true;
					break;
				}
				sent_any = true;
			}
			mxfs_pal_mutex_lock(link->lock);
			if (link->egress_stop ||
			    link->state != NET2_LINK_ACTIVE)
				break;
		}

		/* 2. One WDRR round over the class queues. */
		for (c = 0; c < NET2_PRI_COUNT && !dead; c++) {
			struct net2_linkq *q = &link->q[c];

			if (!q->fresh_head && !q->retx_head)
				continue;
			have_work = true;
			q->deficit += quantum[c];
			if (q->deficit > 2 * quantum[c])
				q->deficit = 2 * quantum[c];

			while (q->deficit > 0) {
				struct net2_eqent *ent;
				struct mxfs_net2_fault_hit hit;
				uint32_t len = 0;
				uint16_t itype;
				bool retx;
				int hitrc;

				now = mxfs_pal_time_ms();
				ent = net2_linkq_pick(q, now);
				if (!ent)
					break;
				retx = ent->retx;
				itype = ent->inner_type;

				if (ent->sess) {
					len = net2_midcomms_pack_entry(ctx,
						ent->sess, ent->seq, retx,
						frame, &itype);
					if (!len) {
						net2_eqent_free(ctx, ent,
						                false);
						continue;   /* retired */
					}
				} else {
					len = ent->frame_len;
					memcpy(frame, ent->frame, len);
				}

				hitrc = net2_fault_check(ctx,
						MXFS_NET2_FAULT_SEND,
						ent->frame_class, itype,
						&hit);
				if (hitrc &&
				    hit.action == MXFS_NET2_FAULT_DELAY) {
					/* Hold the packed bytes; requeue
					 * as an owned frame at the tail. */
					struct net2_eqent *d =
						mxfs_pal_alloc(sizeof(*d));
					uint8_t *copy =
						mxfs_pal_alloc(len);

					if (d && copy) {
						memcpy(copy, frame, len);
						memset(d, 0, sizeof(*d));
						d->frame = copy;
						d->frame_len = len;
						d->frame_class =
							ent->frame_class;
						d->pri = ent->pri;
						d->inner_type = itype;
						d->enq_ms = now;
						d->not_before_ms =
							now + hit.delay_ms;
						net2_linkq_push(q, d, retx);
					} else {
						if (d)
							mxfs_pal_free(d);
						if (copy)
							mxfs_pal_free(copy);
					}
					net2_eqent_free(ctx, ent, false);
					continue;
				}
				if (hitrc &&
				    hit.action == MXFS_NET2_FAULT_REORDER) {
					/* Behind the next entry: tail. */
					struct net2_eqent *d =
						mxfs_pal_alloc(sizeof(*d));
					uint8_t *copy =
						mxfs_pal_alloc(len);

					if (d && copy) {
						memcpy(copy, frame, len);
						memset(d, 0, sizeof(*d));
						d->frame = copy;
						d->frame_len = len;
						d->frame_class =
							ent->frame_class;
						d->pri = ent->pri;
						d->inner_type = itype;
						d->enq_ms = now;
						net2_linkq_push(q, d, retx);
					} else {
						if (d)
							mxfs_pal_free(d);
						if (copy)
							mxfs_pal_free(copy);
					}
					net2_eqent_free(ctx, ent, false);
					continue;
				}
				if (hitrc &&
				    hit.action == MXFS_NET2_FAULT_CORRUPT)
					frame[len / 2] ^= 0x5A;
				if (hitrc &&
				    hit.action == MXFS_NET2_FAULT_TRUNC)
					len = len / 2;   /* peer desyncs */

				if (hitrc &&
				    hit.action == MXFS_NET2_FAULT_DROP) {
					/* Sent-and-lost: tx accounting
					 * already happened in pack. */
					net2_eqent_free(ctx, ent, false);
					q->deficit -= (int32_t)len;
					sent_any = true;
					continue;
				}

				mxfs_pal_mutex_unlock(link->lock);
				{
					int src = net2_link_send_bytes(link,
							sock, frame, len);

					if (src == 0 && hitrc &&
					    hit.action == MXFS_NET2_FAULT_DUP)
						src = net2_link_send_bytes(
							link, sock, frame,
							len);
					mxfs_pal_mutex_lock(link->lock);
					if (src < 0) {
						dead = true;
						net2_eqent_free(ctx, ent,
						                true);
						break;
					}
				}
				if (retx)
					link->cls[ent->pri].retx++;
				else
					link->cls[ent->pri].first_tx++;
				{
					uint64_t res = now > ent->enq_ms ?
						now - ent->enq_ms : 0;

					if (res > link->cls[ent->pri]
					              .max_residency_ms)
						link->cls[ent->pri]
						    .max_residency_ms = res;
				}
				q->deficit -= (int32_t)len;
				sent_any = true;
				net2_eqent_free(ctx, ent, false);
				if (link->egress_stop ||
				    link->state != NET2_LINK_ACTIVE) {
					dead = true;
					break;
				}
			}
		}

		if (dead)
			break;

		if (!have_work && !sent_any) {
			uint64_t deadline = 0, blocked, wait_ms;
			uint64_t now2 = mxfs_pal_time_ms();
			bool ack_due;

			mxfs_pal_mutex_unlock(link->lock);
			ack_due = net2_midcomms_ack_deadline(sess, &deadline);
			mxfs_pal_mutex_lock(link->lock);
			if (link->egress_stop ||
			    link->state != NET2_LINK_ACTIVE)
				break;
			blocked = net2_linkq_earliest_blocked(link);
			wait_ms = NET2_EGRESS_IDLE_WAIT_MS;
			if (ack_due)
				wait_ms = deadline > now2 ?
					deadline - now2 : 1;
			if (blocked && blocked > now2 &&
			    blocked - now2 < wait_ms)
				wait_ms = blocked - now2;
			if (wait_ms > 0)
				mxfs_pal_cond_timedwait(link->egress_cond,
				                        link->lock, wait_ms);
		}
	}
	mxfs_pal_mutex_unlock(link->lock);

	if (dead)
		net2_link_down(ctx, link);

	mxfs_pal_free(frame);
	net2_sess_unref(sess);
	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: egress thread slot %u exiting",
	             link->peer_slot);
}

/* ─── link install (post-handshake) ─── */

/* Bind the session, install the socket, start the worker threads.
 * On failure the socket is closed and the link is DOWN. */
static int net2_link_install(struct mxfs_net2_ctx *ctx,
                             struct net2_link *link, mxfs_sock_t *sock,
                             const struct net2_hello *hello)
{
	struct net2_session *sess;
	struct net2_thread_arg *ra, *ea;

	sess = net2_midcomms_bind(ctx, hello->slot, hello->inc, hello->nonce,
	                          hello->features);
	if (!sess)
		goto fail_close;

	ra = mxfs_pal_alloc(sizeof(*ra));
	ea = mxfs_pal_alloc(sizeof(*ea));
	if (!ra || !ea) {
		if (ra)
			mxfs_pal_free(ra);
		if (ea)
			mxfs_pal_free(ea);
		goto fail_close;
	}

	mxfs_pal_mutex_lock(link->lock);
	link->sock = sock;
	link->state = NET2_LINK_ACTIVE;
	link->egress_stop = false;
	link->connect_backoff_ms = NET2_CONNECT_BACKOFF_MS;
	link->sess = sess;
	net2_sess_ref(sess);              /* the link binding's ref */

	ra->ctx = ctx;
	ra->link = link;
	ra->sess = sess;
	net2_sess_ref(sess);              /* recv thread's ref */
	ea->ctx = ctx;
	ea->link = link;
	ea->sess = sess;
	net2_sess_ref(sess);              /* egress thread's ref */

	link->recv_thread = mxfs_pal_thread_create_rt(net2_link_recv_fn, ra);
	if (!link->recv_thread) {
		net2_sess_unref(sess);
		net2_sess_unref(sess);
		net2_sess_unref(sess);
		link->sess = NULL;
		link->sock = NULL;
		link->state = NET2_LINK_DOWN;
		link->egress_stop = true;
		mxfs_pal_mutex_unlock(link->lock);
		mxfs_pal_free(ra);
		mxfs_pal_free(ea);
		goto fail_close;
	}
	link->egress_thread = mxfs_pal_thread_create_rt(net2_link_egress_fn,
	                                                ea);
	if (!link->egress_thread) {
		net2_sess_unref(sess);    /* egress thread's ref back */
		mxfs_pal_free(ea);
		/* recv thread is live: shut the socket, let it exit;
		 * reap happens on the next connect/accept/stop. */
		mxfs_pal_tcp_shutdown(sock);
		link->state = NET2_LINK_DOWN;
		link->egress_stop = true;
		{
			struct net2_session *bound = link->sess;

			link->sess = NULL;
			if (bound)
				net2_sess_unref(bound);
		}
		mxfs_pal_mutex_unlock(link->lock);
		return -ENOMEM;
	}
	mxfs_pal_mutex_unlock(link->lock);

	net2_midcomms_resume_flush(ctx, sess);
	net2_link_kick(ctx, link->peer_slot);
	mxfs_pal_log(MXFS_LOG_INFO,
	             "net2: link slot %u <-> %u up (peer inc %u)",
	             ctx->cfg.self_slot, hello->slot, hello->inc);
	return 0;

fail_close:
	mxfs_pal_tcp_close(sock);
	mxfs_pal_mutex_lock(link->lock);
	link->state = NET2_LINK_DOWN;
	mxfs_pal_mutex_unlock(link->lock);
	return -ENOMEM;
}

/* ─── accept thread ─── */

static void net2_link_accept_fn(void *arg)
{
	struct mxfs_net2_ctx *ctx = arg;

	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: accept thread on port %u",
	             (unsigned)(ctx->cfg.base_port + ctx->cfg.self_slot));

	while (ctx->running) {
		mxfs_sock_t *newsock;
		struct mxfs_net2_hdr hdr;
		struct mxfs_net2_fault_hit hit;
		struct net2_hello hello;
		uint8_t payload[NET2_SYN_TLV_MAX];
		uint8_t reply[MXFS_NET2_HDR_SIZE + NET2_SYN_TLV_MAX];
		struct net2_link *link;
		uint32_t rlen;
		int plen, rc;

		newsock = mxfs_pal_tcp_accept(ctx->listen_sock);
		if (!newsock) {
			if (!ctx->running)
				break;
			mxfs_pal_sleep_ms(100);
			continue;
		}
		if (!ctx->running) {
			mxfs_pal_tcp_close(newsock);
			break;
		}
		mxfs_pal_tcp_set_opts(newsock);

		/* Publish so shutdown can wake a blocked handshake read
		 * (peer.c pending_sock discipline). */
		ctx->pending_sock = newsock;
		plen = net2_read_frame(ctx, newsock, &hdr, payload,
		                       sizeof(payload));
		ctx->pending_sock = NULL;
		if (!ctx->running) {
			mxfs_pal_tcp_close(newsock);
			break;
		}
		if (plen < 0 || hdr.frame_class != MXFS_NET2_FC_SYN ||
		    hdr.dst_slot != ctx->cfg.self_slot) {
			mxfs_pal_tcp_close(newsock);
			mxfs_pal_sleep_ms(NET2_ACCEPT_REJECT_SLEEP_MS);
			continue;
		}
		if (net2_fault_check(ctx, MXFS_NET2_FAULT_RECV,
		                     MXFS_NET2_FC_SYN, 0, &hit) &&
		    hit.action == MXFS_NET2_FAULT_DROP) {
			mxfs_pal_tcp_close(newsock);
			continue;
		}
		rc = net2_parse_hello(ctx, &hdr, payload, (uint32_t)plen,
		                      &hello);
		if (rc) {
			if (rc == -EREMOTE)
				net2_stat_bump(ctx,
					&ctx->stats.cross_cluster_rejects);
			mxfs_pal_log(MXFS_LOG_WARN,
			             "net2: rejecting SYN from slot %u (%d)",
			             hdr.src_slot, rc);
			mxfs_pal_tcp_close(newsock);
			mxfs_pal_sleep_ms(NET2_ACCEPT_REJECT_SLEEP_MS);
			continue;
		}
		/* Lower-slot-initiates: an inbound SYN must come from a
		 * LOWER slot (and never our own). */
		if (hello.slot >= ctx->cfg.self_slot) {
			mxfs_pal_log(MXFS_LOG_WARN,
			             "net2: SYN from slot %u violates "
			             "lower-slot-initiates (self %u)",
			             hello.slot, ctx->cfg.self_slot);
			mxfs_pal_tcp_close(newsock);
			mxfs_pal_sleep_ms(NET2_ACCEPT_REJECT_SLEEP_MS);
			continue;
		}

		rlen = net2_build_hello(ctx, MXFS_NET2_FC_SYN_ACK, hello.slot,
		                        hello.inc, reply);
		if (!rlen) {
			mxfs_pal_tcp_close(newsock);
			continue;
		}
		if (net2_fault_check(ctx, MXFS_NET2_FAULT_SEND,
		                     MXFS_NET2_FC_SYN_ACK, 0, &hit) &&
		    hit.action == MXFS_NET2_FAULT_DROP) {
			mxfs_pal_tcp_close(newsock);
			continue;
		}
		if (mxfs_pal_tcp_send(newsock, reply, rlen) < 0) {
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		/* Replace any stale connection for this slot, then
		 * install (shutdown -> join -> close -> install). */
		link = &ctx->links[hello.slot];
		net2_link_down(ctx, link);
		net2_link_reap(ctx, link);
		{
			char addr[NET2_HOST_MAX];

			if (mxfs_pal_tcp_getpeername(newsock, addr,
			                             sizeof(addr)) == 0) {
				mxfs_pal_mutex_lock(link->lock);
				snprintf(link->host, sizeof(link->host),
				         "%s", addr);
				link->addr_known = true;
				mxfs_pal_mutex_unlock(link->lock);
			}
		}
		net2_link_install(ctx, link, newsock, &hello);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: accept thread exiting");
}

/* ─── outbound connect (lower-slot side) ─── */

struct net2_conn_arg {
	struct mxfs_net2_ctx *ctx;
	struct net2_link *link;
};

static void net2_link_conn_fn(void *arg)
{
	struct net2_conn_arg *ca = arg;
	struct mxfs_net2_ctx *ctx = ca->ctx;
	struct net2_link *link = ca->link;
	struct mxfs_net2_hdr hdr;
	struct mxfs_net2_fault_hit hit;
	struct net2_hello hello;
	uint8_t syn[MXFS_NET2_HDR_SIZE + NET2_SYN_TLV_MAX];
	uint8_t payload[NET2_SYN_TLV_MAX];
	char host[NET2_HOST_MAX];
	mxfs_sock_t *sock;
	uint16_t port;
	uint32_t slen;
	int plen, rc;

	mxfs_pal_free(ca);

	mxfs_pal_mutex_lock(link->lock);
	snprintf(host, sizeof(host), "%s", link->host);
	port = link->port ? link->port :
	       (uint16_t)(ctx->cfg.base_port + link->peer_slot);
	mxfs_pal_mutex_unlock(link->lock);

	sock = mxfs_pal_tcp_connect(host, port);
	if (!sock)
		goto fail;
	mxfs_pal_tcp_set_opts(sock);

	/* Register before the blocking handshake so stop/reset paths can
	 * wake us via tcp_shutdown. */
	mxfs_pal_mutex_lock(link->lock);
	if (link->egress_stop || !ctx->running) {
		mxfs_pal_mutex_unlock(link->lock);
		mxfs_pal_tcp_close(sock);
		goto fail_noclose;
	}
	link->sock = sock;
	mxfs_pal_mutex_unlock(link->lock);

	slen = net2_build_hello(ctx, MXFS_NET2_FC_SYN, link->peer_slot, 0,
	                        syn);
	if (!slen)
		goto fail_detach;
	if (net2_fault_check(ctx, MXFS_NET2_FAULT_SEND, MXFS_NET2_FC_SYN, 0,
	                     &hit) && hit.action == MXFS_NET2_FAULT_DROP)
		goto fail_detach;         /* dropped SYN: retry later */
	if (mxfs_pal_tcp_send(sock, syn, slen) < 0)
		goto fail_detach;

	plen = net2_read_frame(ctx, sock, &hdr, payload, sizeof(payload));
	if (plen < 0 || hdr.frame_class != MXFS_NET2_FC_SYN_ACK ||
	    hdr.src_slot != link->peer_slot ||
	    hdr.dst_slot != ctx->cfg.self_slot)
		goto fail_detach;
	if (net2_fault_check(ctx, MXFS_NET2_FAULT_RECV,
	                     MXFS_NET2_FC_SYN_ACK, 0, &hit) &&
	    hit.action == MXFS_NET2_FAULT_DROP)
		goto fail_detach;
	rc = net2_parse_hello(ctx, &hdr, payload, (uint32_t)plen, &hello);
	if (rc) {
		if (rc == -EREMOTE)
			net2_stat_bump(ctx,
			               &ctx->stats.cross_cluster_rejects);
		goto fail_detach;
	}

	/* Detach the socket from the link for the install path (install
	 * re-attaches under the lock with the full state flip). */
	mxfs_pal_mutex_lock(link->lock);
	link->sock = NULL;
	if (link->egress_stop || !ctx->running) {
		mxfs_pal_mutex_unlock(link->lock);
		mxfs_pal_tcp_close(sock);
		goto fail_noclose;
	}
	mxfs_pal_mutex_unlock(link->lock);

	if (net2_link_install(ctx, link, sock, &hello) == 0)
		return;
	goto fail_noclose;

fail_detach:
	mxfs_pal_mutex_lock(link->lock);
	link->sock = NULL;
	mxfs_pal_mutex_unlock(link->lock);
	mxfs_pal_tcp_close(sock);
	goto fail_noclose;
fail:
fail_noclose:
	mxfs_pal_mutex_lock(link->lock);
	link->state = NET2_LINK_DOWN;
	link->connect_backoff_ms *= 2;
	if (link->connect_backoff_ms > NET2_CONNECT_BACKOFF_MAX_MS)
		link->connect_backoff_ms = NET2_CONNECT_BACKOFF_MAX_MS;
	mxfs_pal_mutex_unlock(link->lock);
}

void net2_link_connect(struct mxfs_net2_ctx *ctx, uint16_t slot)
{
	struct net2_link *link = &ctx->links[slot];
	struct net2_conn_arg *ca;
	uint64_t now = mxfs_pal_time_ms();

	if (slot >= MXFS_MAX_NODES || slot == ctx->cfg.self_slot)
		return;
	if (ctx->cfg.self_slot > slot)
		return;                    /* lower slot initiates */

	mxfs_pal_mutex_lock(link->lock);
	if (link->state == NET2_LINK_CONNECTING) {
		/* Bounded handshake: a wedged attempt is cut loose. */
		if (now - link->last_connect_ms >
		    NET2_HANDSHAKE_DEADLINE_MS && link->sock)
			mxfs_pal_tcp_shutdown(link->sock);
		mxfs_pal_mutex_unlock(link->lock);
		return;
	}
	if (link->state != NET2_LINK_DOWN || !link->desired ||
	    !link->addr_known ||
	    now - link->last_connect_ms < link->connect_backoff_ms) {
		mxfs_pal_mutex_unlock(link->lock);
		return;
	}
	link->last_connect_ms = now;
	link->state = NET2_LINK_CONNECTING;
	link->egress_stop = false;
	mxfs_pal_mutex_unlock(link->lock);

	/* Join leftovers from the previous connection first. */
	net2_link_reap(ctx, link);

	ca = mxfs_pal_alloc(sizeof(*ca));
	if (!ca)
		goto revert;
	ca->ctx = ctx;
	ca->link = link;
	mxfs_pal_mutex_lock(link->lock);
	link->conn_thread = mxfs_pal_thread_create_rt(net2_link_conn_fn, ca);
	if (!link->conn_thread) {
		mxfs_pal_mutex_unlock(link->lock);
		mxfs_pal_free(ca);
		goto revert;
	}
	mxfs_pal_mutex_unlock(link->lock);
	return;

revert:
	mxfs_pal_mutex_lock(link->lock);
	link->state = NET2_LINK_DOWN;
	mxfs_pal_mutex_unlock(link->lock);
}

/* ─── enqueue API ─── */

bool net2_link_class_full(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                          uint8_t pri)
{
	struct net2_link *link;
	bool full;

	link = ctx->prov->route(ctx, dst_slot);
	if (!link)
		return false;              /* no route: buffering handles it */
	mxfs_pal_mutex_lock(link->lock);
	full = link->q[pri].depth >= ctx->tun.queue_cap[pri];
	mxfs_pal_mutex_unlock(link->lock);
	return full;
}

int net2_link_enqueue_ref(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                          struct net2_session *sess, uint64_t seq,
                          uint8_t pri, bool retx, uint16_t inner_type)
{
	struct net2_link *link;
	struct net2_eqent *ent;
	bool overflow, fire_ambiguous = false;

	link = ctx->prov->route(ctx, dst_slot);
	if (!link)
		return -ENOTCONN;

	ent = mxfs_pal_alloc(sizeof(*ent));
	if (!ent)
		return -ENOMEM;
	memset(ent, 0, sizeof(*ent));
	ent->sess = sess;
	ent->seq = seq;
	ent->retx = retx;
	ent->pri = pri;
	ent->frame_class = MXFS_NET2_FC_DATA;
	ent->inner_type = inner_type;
	ent->enq_ms = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(link->lock);
	if (link->state != NET2_LINK_ACTIVE) {
		mxfs_pal_mutex_unlock(link->lock);
		mxfs_pal_free(ent);
		return -ENOTCONN;
	}
	overflow = link->q[pri].depth >= ctx->tun.queue_cap[pri];
	net2_sess_ref(sess);
	net2_linkq_push(&link->q[pri], ent, retx);
	if (overflow) {
		link->cls[pri].queue_full++;
		if (pri != NET2_PRI_GRANT && pri != NET2_PRI_DISCOVERY) {
			/* Coherence overflow: never a drop — ambiguity
			 * signal + (step 6) freeze. */
			mxfs_pal_mutex_lock(sess->lock);
			if (!sess->comm_ambiguous) {
				sess->comm_ambiguous = true;
				fire_ambiguous = true;
			}
			mxfs_pal_mutex_unlock(sess->lock);
		}
	}
	link->cls[pri].enqueued++;
	mxfs_pal_mutex_unlock(link->lock);

	if (fire_ambiguous) {
		net2_stat_bump(ctx, &ctx->stats.comm_ambiguous_events);
		if (ctx->ambiguous_cb)
			ctx->ambiguous_cb(ctx->ambiguous_cb_data,
			                  sess->peer_slot, sess->peer_inc, 0);
	}
	return 0;
}

int net2_link_enqueue_frame(struct mxfs_net2_ctx *ctx, uint16_t dst_slot,
                            uint8_t *frame, uint32_t frame_len,
                            uint8_t frame_class, uint8_t pri,
                            uint16_t inner_type)
{
	struct net2_link *link;
	struct net2_eqent *ent;

	link = ctx->prov->route(ctx, dst_slot);
	if (!link)
		return -ENOTCONN;

	ent = mxfs_pal_alloc(sizeof(*ent));
	if (!ent)
		return -ENOMEM;
	memset(ent, 0, sizeof(*ent));
	ent->frame = frame;
	ent->frame_len = frame_len;
	ent->frame_class = frame_class;
	ent->pri = pri;
	ent->inner_type = inner_type;
	ent->enq_ms = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(link->lock);
	if (link->state != NET2_LINK_ACTIVE) {
		mxfs_pal_mutex_unlock(link->lock);
		ent->frame = NULL;         /* caller keeps ownership */
		mxfs_pal_free(ent);
		return -ENOTCONN;
	}
	if ((pri == NET2_PRI_GRANT || pri == NET2_PRI_DISCOVERY) &&
	    link->q[pri].depth >= ctx->tun.queue_cap[pri]) {
		link->cls[pri].queue_full++;
		mxfs_pal_mutex_unlock(link->lock);
		ent->frame = NULL;
		mxfs_pal_free(ent);
		return -EAGAIN;
	}
	net2_linkq_push(&link->q[pri], ent, false);
	link->cls[pri].enqueued++;
	mxfs_pal_mutex_unlock(link->lock);
	return 0;
}

void net2_link_kick(struct mxfs_net2_ctx *ctx, uint16_t dst_slot)
{
	struct net2_link *link;

	link = ctx->prov->route(ctx, dst_slot);
	if (!link)
		return;
	mxfs_pal_mutex_lock(link->lock);
	mxfs_pal_cond_signal(link->egress_cond);
	mxfs_pal_mutex_unlock(link->lock);
}

/* ─── listener + shutdown ─── */

int net2_link_listen_start(struct mxfs_net2_ctx *ctx)
{
	uint16_t port = (uint16_t)(ctx->cfg.base_port + ctx->cfg.self_slot);

	ctx->listen_sock = mxfs_pal_tcp_listen(port);
	if (!ctx->listen_sock) {
		mxfs_pal_log(MXFS_LOG_ERR, "net2: listen on port %u failed",
		             port);
		return -EADDRINUSE;
	}
	ctx->accept_thread = mxfs_pal_thread_create_rt(net2_link_accept_fn,
	                                               ctx);
	if (!ctx->accept_thread) {
		mxfs_pal_tcp_close(ctx->listen_sock);
		ctx->listen_sock = NULL;
		return -ENOMEM;
	}
	return 0;
}

void net2_link_shutdown_all(struct mxfs_net2_ctx *ctx)
{
	int i;

	/* Phase 0 (peer.c:498 discipline): shut down every link socket
	 * FIRST so any thread blocked in tcp_recv/tcp_send wakes up. */
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		struct net2_link *link = &ctx->links[i];

		mxfs_pal_mutex_lock(link->lock);
		link->egress_stop = true;
		if (link->sock)
			mxfs_pal_tcp_shutdown(link->sock);
		mxfs_pal_cond_broadcast(link->egress_cond);
		mxfs_pal_mutex_unlock(link->lock);
	}

	/* Wake the accept thread: listener + any handshake-pending sock. */
	if (ctx->listen_sock)
		mxfs_pal_tcp_shutdown(ctx->listen_sock);
	if (ctx->pending_sock)
		mxfs_pal_tcp_shutdown(ctx->pending_sock);
	if (ctx->accept_thread) {
		mxfs_pal_thread_join(ctx->accept_thread);
		ctx->accept_thread = NULL;
	}
	if (ctx->listen_sock) {
		mxfs_pal_tcp_close(ctx->listen_sock);
		ctx->listen_sock = NULL;
	}

	/* Phase 2: per link — join threads, close socket, flush queues,
	 * drop the session binding. */
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		struct net2_link *link = &ctx->links[i];
		struct net2_session *sess;

		net2_link_reap(ctx, link);
		mxfs_pal_mutex_lock(link->lock);
		sess = link->sess;
		link->sess = NULL;
		net2_link_flush_locked(ctx, link);
		link->state = NET2_LINK_DOWN;
		mxfs_pal_mutex_unlock(link->lock);
		if (sess)
			net2_sess_unref(sess);
	}
}
