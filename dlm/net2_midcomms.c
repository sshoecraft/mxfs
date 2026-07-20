/*
 * MXFS — Multinode XFS
 * NET2 transport — midcomms: sessions, seq/ack/sack, retransmit, dedup
 *
 * The reliability boundary is the end-to-end session (§3): per-peer-
 * incarnation, nonce-matched at handshake.  A TCP link dropping is a
 * routing event — the retransmit ring owns delivery and the session
 * survives reconnects.  Contract: at-least-once + dedup hint; effect
 * idempotency lives in the lock handlers (§6, step 4).
 *
 * Sequence space: u64 per direction, starts at 1; hdr.ack==0 means
 * "nothing received yet".  Delivery is ON-RECEIPT, never held for seq
 * order (see net2_ctx.h: ordering would defeat the priority classes);
 * the rcvd_mask dedups the transport level and the msg_id ring (of
 * dedup_ring ids) suppresses caller-level retries that reuse an id.
 *
 * Epoch is stamped into each entry at ENQUEUE time and never restamped
 * on retransmit: the receiver's E-1 bridge window (§7.A) must see the
 * epoch the operation was issued under, not the current one.
 *
 * Locking: see net2_ctx.h.  Session pointers are kept alive by
 * refcounts (sess->refs under sess->lock): the ctx table/GC list, a
 * link's handshake binding, and every egress queue reference hold one.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_midcomms.h"
#include "net2_link.h"
#include "../include/mxfs/mxfs_dlm.h"

/* Snapshot-enqueue chunk size: link->lock ranks above sess->lock, so
 * enqueue runs with sess->lock dropped and the ring is snapshotted in
 * chunks this size (full-ring snapshots blew the 1KB kernel frame cap). */
#define NET2_ENQ_BATCH 16

/* ─── refcounting ─── */

void net2_sess_ref(struct net2_session *sess)
{
	mxfs_pal_mutex_lock(sess->lock);
	sess->refs++;
	mxfs_pal_mutex_unlock(sess->lock);
}

void net2_sess_unref(struct net2_session *sess)
{
	mxfs_pal_mutex_lock(sess->lock);
	if (sess->refs > 0)
		sess->refs--;
	mxfs_pal_mutex_unlock(sess->lock);
}

/* ─── session construction / destruction ─── */

static struct net2_session *sess_create(struct mxfs_net2_ctx *ctx,
                                        uint16_t slot, uint32_t inc,
                                        uint64_t nonce,
                                        enum net2_sess_state state)
{
	struct net2_session *sess;

	sess = mxfs_pal_alloc(sizeof(*sess));
	if (!sess)
		return NULL;
	memset(sess, 0, sizeof(*sess));
	sess->lock = mxfs_pal_mutex_create();
	if (!sess->lock) {
		mxfs_pal_free(sess);
		return NULL;
	}
	sess->peer_slot = slot;
	sess->peer_inc = inc;
	sess->peer_nonce = nonce;
	sess->state = state;
	sess->refs = 1;                    /* the ctx table/GC-list ref */
	sess->tx.next_seq = 1;
	sess->tx.unacked_base = 1;
	sess->last_ack_progress_ms = mxfs_pal_time_ms();
	net2_stat_bump(ctx, &ctx->stats.sessions_created);
	return sess;
}

/* Free a session whose refs have reached 0 (threads quiesced). */
static void sess_destroy(struct net2_session *sess)
{
	int i;

	for (i = 0; i < NET2_TX_RING_MAX; i++)
		if (sess->tx.ring[i].occupied && sess->tx.ring[i].payload)
			mxfs_pal_free(sess->tx.ring[i].payload);
	mxfs_pal_mutex_destroy(sess->lock);
	mxfs_pal_free(sess);
}

/* ─── tx-ring internals (sess->lock held) ─── */

static struct net2_txent *txent_lookup(struct mxfs_net2_ctx *ctx,
                                       struct net2_session *sess,
                                       uint64_t seq)
{
	struct net2_txent *e = &sess->tx.ring[seq % ctx->tun.tx_win];

	if (!e->occupied || e->seq != seq)
		return NULL;
	return e;
}

static void txent_retire(struct net2_session *sess, struct net2_txent *e,
                         bool acked)
{
	if (e->payload)
		mxfs_pal_free(e->payload);
	memset(e, 0, sizeof(*e));
	if (acked)
		sess->stats.acked++;
	else
		sess->stats.aborts++;
}

/* Abort every outstanding entry with an explicit disposition (§13
 * invariant: every retired retransmit entry has ACK or session-abort). */
static void tx_abort_all(struct net2_session *sess)
{
	int i;

	for (i = 0; i < NET2_TX_RING_MAX; i++)
		if (sess->tx.ring[i].occupied)
			txent_retire(sess, &sess->tx.ring[i], false);
	sess->tx.unacked_base = sess->tx.next_seq;
}

/*
 * Process the ack/sack fields of any frame from the peer.
 * Returns true when the cumulative base advanced (ack progress).
 */
static bool ack_process(struct mxfs_net2_ctx *ctx, struct net2_session *sess,
                        uint64_t ack, uint32_t sack, uint64_t now_ms)
{
	bool progressed = false;
	uint32_t b;

	while (!net2_seq_after(sess->tx.unacked_base, ack) &&
	       net2_seq_before(sess->tx.unacked_base, sess->tx.next_seq)) {
		struct net2_txent *e = txent_lookup(ctx, sess,
		                                    sess->tx.unacked_base);

		if (e)
			txent_retire(sess, e, true);
		sess->tx.unacked_base++;
		progressed = true;
	}

	for (b = 0; b < 32; b++) {
		if (sack & (1u << b)) {
			struct net2_txent *e = txent_lookup(ctx, sess,
			                                    ack + 1 + b);

			if (e)
				e->sacked = true;
		}
	}

	if (progressed) {
		sess->last_ack_progress_ms = now_ms;
		if (sess->comm_ambiguous) {
			sess->comm_ambiguous = false;
			mxfs_pal_log(MXFS_LOG_INFO,
			             "net2: session slot %u inc %u recovered "
			             "from COMM_AMBIGUOUS",
			             sess->peer_slot, sess->peer_inc);
		}
	}
	return progressed;
}

/* Fold a dying session's stats into the mount aggregate so abort
 * dispositions stay observable after the table moves on. */
static void sess_fold_retired(struct mxfs_net2_ctx *ctx,
                              const struct mxfs_net2_session_stats *st)
{
	struct mxfs_net2_session_stats *r;

	mxfs_pal_mutex_lock(ctx->stats_lock);
	r = &ctx->stats.retired;
	r->msgs_created += st->msgs_created;
	r->first_tx += st->first_tx;
	r->retx += st->retx;
	r->acked += st->acked;
	r->dup_seq_suppressed += st->dup_seq_suppressed;
	r->dup_op_idempotent += st->dup_op_idempotent;
	r->out_of_window_drops += st->out_of_window_drops;
	r->stale_incarnation_drops += st->stale_incarnation_drops;
	r->stale_epoch_drops += st->stale_epoch_drops;
	r->stale_term_drops += st->stale_term_drops;
	r->resets += st->resets;
	r->resumes += st->resumes;
	r->aborts += st->aborts;
	mxfs_pal_mutex_unlock(ctx->stats_lock);
}

/* Supersede a live session (ctx->lock held): abort its entries, move it
 * to the GC list.  The table slot is cleared by the caller. */
static void sess_supersede(struct mxfs_net2_ctx *ctx,
                           struct net2_session *sess, uint64_t now_ms)
{
	struct mxfs_net2_session_stats snap;

	mxfs_pal_mutex_lock(sess->lock);
	sess->state = NET2_SESS_SUPERSEDED;
	sess->superseded_at_ms = now_ms;
	tx_abort_all(sess);
	snap = sess->stats;
	mxfs_pal_mutex_unlock(sess->lock);
	sess_fold_retired(ctx, &snap);
	sess->gc_next = ctx->sess_gc;
	ctx->sess_gc = sess;
}

/* ─── handshake binding ─── */

struct net2_session *net2_midcomms_bind(struct mxfs_net2_ctx *ctx,
                                        uint16_t slot, uint32_t inc,
                                        uint64_t nonce, uint32_t features)
{
	struct net2_session *sess;
	uint64_t now = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(ctx->lock);
	sess = ctx->sessions[slot];
	if (sess) {
		mxfs_pal_mutex_lock(sess->lock);
		if (sess->peer_inc == inc && sess->peer_nonce == nonce &&
		    sess->state != NET2_SESS_EMBRYONIC) {
			/* Same identity: the session survived (reconnect
			 * or orderly-close undone by a fresh handshake). */
			sess->state = NET2_SESS_ESTABLISHED;
			sess->peer_features = features;
			sess->stats.resumes++;
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_mutex_unlock(ctx->lock);
			return sess;
		}
		if (sess->peer_inc == inc &&
		    sess->state == NET2_SESS_EMBRYONIC) {
			/* Buffered sends waiting for this handshake. */
			sess->peer_nonce = nonce;
			sess->peer_features = features;
			sess->state = NET2_SESS_ESTABLISHED;
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_mutex_unlock(ctx->lock);
			return sess;
		}
		mxfs_pal_mutex_unlock(sess->lock);
		/* Different incarnation or nonce: a different session,
		 * full stop (§5).  The old one freezes and is GC'd. */
		ctx->sessions[slot] = NULL;
		sess_supersede(ctx, sess, now);
	}

	sess = sess_create(ctx, slot, inc, nonce, NET2_SESS_ESTABLISHED);
	if (sess) {
		sess->peer_features = features;
		ctx->sessions[slot] = sess;
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	return sess;
}

/* ─── send path ─── */

int net2_midcomms_send(struct mxfs_net2_ctx *ctx,
                       const struct mxfs_net2_id *dst,
                       enum net2_priority pri, bool reliable,
                       uint32_t msg_id, const void *buf, uint32_t len)
{
	struct net2_session *sess;
	struct net2_txent *e;
	uint8_t *copy;
	uint64_t seq, epoch;
	uint16_t inner_type = 0;
	bool ambiguous_fired = false;
	int rc;

	if (!ctx || !dst || !buf || len == 0)
		return -EINVAL;
	if (len > MXFS_NET2_MAX_MSG_SIZE)
		return -EMSGSIZE;
	if (pri >= NET2_PRI_COUNT)
		return -EINVAL;
	if (dst->slot >= MXFS_MAX_NODES || dst->slot == ctx->cfg.self_slot)
		return -EINVAL;
	if (!ctx->running)
		return -ESHUTDOWN;

	if (len >= sizeof(struct mxfs_dlm_msg_hdr))
		inner_type = ((const struct mxfs_dlm_msg_hdr *)buf)->type;

	if (!reliable) {
		/* Outside the seq space: needs a live link right now. */
		uint8_t *frame = mxfs_pal_alloc(MXFS_NET2_HDR_SIZE + len);
		struct mxfs_net2_hdr h;

		if (!frame)
			return -ENOMEM;
		memset(&h, 0, sizeof(h));
		h.magic = MXFS_NET2_MAGIC;
		h.version = MXFS_NET2_WIRE_VERSION;
		h.frame_class = MXFS_NET2_FC_DATA;
		h.priority = (uint8_t)pri;
		h.payload_len = (uint16_t)len;
		h.cluster_uuid_hash = ctx->cfg.uuid_hash;
		h.membership_epoch = ctx->membership_epoch;
		h.src_slot = ctx->cfg.self_slot;
		h.dst_slot = dst->slot;
		h.src_incarnation = ctx->cfg.self_incarnation;
		h.dst_incarnation = dst->incarnation;
		h.msg_id = msg_id;
		mxfs_net2_hdr_pack(&h, frame);
		memcpy(frame + MXFS_NET2_HDR_SIZE, buf, len);
		rc = net2_link_enqueue_frame(ctx, dst->slot, frame,
		                             MXFS_NET2_HDR_SIZE + len,
		                             MXFS_NET2_FC_DATA, (uint8_t)pri,
		                             inner_type);
		if (rc) {
			mxfs_pal_free(frame);
			return rc;
		}
		net2_link_kick(ctx, dst->slot);
		return 0;
	}

	/* GRANT/DISCOVERY only: advisory class-cap backpressure before
	 * the ring insert (coherence classes are never refused here). */
	if (pri == NET2_PRI_GRANT || pri == NET2_PRI_DISCOVERY) {
		if (net2_link_class_full(ctx, dst->slot, (uint8_t)pri))
			return -EAGAIN;
	}

	mxfs_pal_mutex_lock(ctx->lock);
	epoch = ctx->membership_epoch;
	sess = ctx->sessions[dst->slot];
	if (sess) {
		mxfs_pal_mutex_lock(sess->lock);
		if (sess->peer_inc > dst->incarnation) {
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_mutex_unlock(ctx->lock);
			return -ESTALE;      /* caller's view is behind */
		}
		if (sess->peer_inc < dst->incarnation) {
			/* Caller knows a newer incarnation: the old
			 * session is dead — supersede, start fresh. */
			mxfs_pal_mutex_unlock(sess->lock);
			ctx->sessions[dst->slot] = NULL;
			sess_supersede(ctx, sess, mxfs_pal_time_ms());
			sess = NULL;
		} else {
			mxfs_pal_mutex_unlock(sess->lock);
		}
	}
	if (!sess) {
		sess = sess_create(ctx, dst->slot, dst->incarnation, 0,
		                   NET2_SESS_EMBRYONIC);
		if (!sess) {
			mxfs_pal_mutex_unlock(ctx->lock);
			return -ENOMEM;
		}
		ctx->sessions[dst->slot] = sess;
	}
	net2_sess_ref(sess);
	mxfs_pal_mutex_unlock(ctx->lock);

	copy = mxfs_pal_alloc(len);
	if (!copy) {
		net2_sess_unref(sess);
		return -ENOMEM;
	}
	memcpy(copy, buf, len);

	mxfs_pal_mutex_lock(sess->lock);
	if (sess->state == NET2_SESS_PEER_CLOSED ||
	    sess->state == NET2_SESS_SUPERSEDED) {
		mxfs_pal_mutex_unlock(sess->lock);
		mxfs_pal_free(copy);
		net2_sess_unref(sess);
		return -ENOTCONN;
	}
	if (sess->tx.next_seq - sess->tx.unacked_base >= ctx->tun.tx_win) {
		/* Flow window full. */
		if (pri == NET2_PRI_GRANT || pri == NET2_PRI_DISCOVERY) {
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_free(copy);
			mxfs_pal_mutex_lock(ctx->stats_lock);
			ctx->stats.cls[pri].queue_full++;
			mxfs_pal_mutex_unlock(ctx->stats_lock);
			net2_sess_unref(sess);
			return -EAGAIN;
		}
		/* Coherence class: NEVER a silent drop — the op stays
		 * with the caller, the session goes ambiguous and the
		 * freeze hook (step 6) takes the scope (§7.A). */
		if (!sess->comm_ambiguous) {
			sess->comm_ambiguous = true;
			ambiguous_fired = true;
		}
		mxfs_pal_mutex_unlock(sess->lock);
		mxfs_pal_free(copy);
		mxfs_pal_mutex_lock(ctx->stats_lock);
		ctx->stats.cls[pri].queue_full++;
		if (ambiguous_fired)
			ctx->stats.comm_ambiguous_events++;
		mxfs_pal_mutex_unlock(ctx->stats_lock);
		if (ambiguous_fired && ctx->ambiguous_cb)
			ctx->ambiguous_cb(ctx->ambiguous_cb_data,
			                  sess->peer_slot, sess->peer_inc, 0);
		net2_sess_unref(sess);
		return -ENOBUFS;
	}

	if (msg_id == 0) {
		if (++sess->msg_id_next == 0)
			++sess->msg_id_next;
		msg_id = sess->msg_id_next;
	}
	seq = sess->tx.next_seq++;
	e = &sess->tx.ring[seq % ctx->tun.tx_win];
	memset(e, 0, sizeof(*e));
	e->occupied = true;
	e->pri = (uint8_t)pri;
	e->frame_class = MXFS_NET2_FC_DATA;
	e->inner_type = inner_type;
	e->msg_id = msg_id;
	e->seq = seq;
	e->epoch = epoch;
	e->payload = copy;
	e->len = len;
	e->enq_ms = mxfs_pal_time_ms();
	e->rto_ms = ctx->tun.rto_initial_ms;
	sess->stats.msgs_created++;
	{
		bool established = (sess->state == NET2_SESS_ESTABLISHED);

		if (established)
			e->enqueued = true;   /* optimistic; rolled back */
		mxfs_pal_mutex_unlock(sess->lock);

		if (!established) {
			/* EMBRYONIC: buffered; flushed at handshake. */
			net2_sess_unref(sess);
			return 0;
		}
	}
	{
		rc = net2_link_enqueue_ref(ctx, dst->slot, sess, seq,
		                           (uint8_t)pri, false, inner_type);
		if (rc) {
			/* No route yet: stays buffered in the ring; the
			 * RT sweep enqueues it once the link is up. */
			mxfs_pal_mutex_lock(sess->lock);
			e = txent_lookup(ctx, sess, seq);
			if (e)
				e->enqueued = false;
			mxfs_pal_mutex_unlock(sess->lock);
		} else {
			net2_link_kick(ctx, dst->slot);
		}
	}
	net2_sess_unref(sess);
	return 0;
}

/* Enqueue everything buffered-but-unqueued (post-handshake flush). */
void net2_midcomms_resume_flush(struct mxfs_net2_ctx *ctx,
                                struct net2_session *sess)
{
	struct {
		uint64_t seq;
		uint8_t pri;
		bool retx;
		uint16_t inner_type;
	} batch[NET2_ENQ_BATCH];
	int scan = 0, n, i;
	bool kicked = false, done = false;

	mxfs_pal_mutex_lock(sess->lock);
	if (sess->state != NET2_SESS_ESTABLISHED) {
		mxfs_pal_mutex_unlock(sess->lock);
		return;
	}
	while (!done) {
		n = 0;
		for (; sess->state == NET2_SESS_ESTABLISHED &&
		       scan < NET2_TX_RING_MAX &&
		       n < NET2_ENQ_BATCH; scan++) {
			struct net2_txent *e = &sess->tx.ring[scan];

			if (e->occupied && !e->enqueued && !e->sacked) {
				batch[n].seq = e->seq;
				batch[n].pri = e->pri;
				batch[n].retx = (e->first_tx_ms != 0);
				batch[n].inner_type = e->inner_type;
				e->enqueued = true;
				n++;
			}
		}
		if (scan >= NET2_TX_RING_MAX ||
		    sess->state != NET2_SESS_ESTABLISHED)
			done = true;
		mxfs_pal_mutex_unlock(sess->lock);

		for (i = 0; i < n; i++) {
			if (net2_link_enqueue_ref(ctx, sess->peer_slot, sess,
			                          batch[i].seq, batch[i].pri,
			                          batch[i].retx,
			                          batch[i].inner_type)) {
				mxfs_pal_mutex_lock(sess->lock);
				{
					struct net2_txent *e =
						txent_lookup(ctx, sess,
						             batch[i].seq);
					if (e)
						e->enqueued = false;
				}
				mxfs_pal_mutex_unlock(sess->lock);
			} else {
				kicked = true;
			}
		}
		if (!done)
			mxfs_pal_mutex_lock(sess->lock);
	}
	if (kicked)
		net2_link_kick(ctx, sess->peer_slot);
}

/* ─── receive path (link recv thread) ─── */

static bool rx_dedup_seen(struct mxfs_net2_ctx *ctx,
                          struct net2_session *sess, uint32_t msg_id)
{
	uint32_t i;

	if (msg_id == 0)
		return false;
	for (i = 0; i < ctx->tun.dedup_ring; i++)
		if (sess->rx.dedup[i] == msg_id)
			return true;
	sess->rx.dedup[sess->rx.dedup_pos] = msg_id;
	sess->rx.dedup_pos = (sess->rx.dedup_pos + 1) % ctx->tun.dedup_ring;
	return false;
}

void net2_midcomms_rx(struct mxfs_net2_ctx *ctx, struct net2_session *sess,
                      const struct mxfs_net2_hdr *hdr,
                      const uint8_t *payload, uint32_t len)
{
	bool deliver_frame = false;
	bool immediate_ack = false;
	uint64_t now = mxfs_pal_time_ms();

	if (!sess)
		return;

	mxfs_pal_mutex_lock(sess->lock);

	/* Identity guards — the ABA protection for slot reuse (§5). */
	if (hdr->src_slot != sess->peer_slot ||
	    hdr->src_incarnation != sess->peer_inc) {
		sess->stats.stale_incarnation_drops++;
		goto out_unlock;
	}
	if (hdr->dst_slot != ctx->cfg.self_slot)
		goto out_unlock;
	if (hdr->dst_incarnation != ctx->cfg.self_incarnation) {
		sess->stats.stale_incarnation_drops++;
		goto out_unlock;
	}
	if (sess->state == NET2_SESS_SUPERSEDED) {
		sess->stats.stale_incarnation_drops++;
		goto out_unlock;
	}
	/* Epoch: accept E and E-1 (bridge window §7.A); older is stale. */
	if (hdr->membership_epoch + 1 < ctx->membership_epoch) {
		sess->stats.stale_epoch_drops++;
		goto out_unlock;
	}

	/* Every frame carries the peer's rx state: process ack/sack. */
	ack_process(ctx, sess, hdr->ack, hdr->sack_mask, now);

	switch (hdr->frame_class) {
	case MXFS_NET2_FC_ACK:
		break;

	case MXFS_NET2_FC_FIN:
		if (sess->state == NET2_SESS_ESTABLISHED ||
		    sess->state == NET2_SESS_EMBRYONIC) {
			sess->state = NET2_SESS_PEER_CLOSED;
			tx_abort_all(sess);
			mxfs_pal_log(MXFS_LOG_DEBUG,
			             "net2: peer slot %u inc %u closed (FIN)",
			             sess->peer_slot, sess->peer_inc);
		}
		break;

	case MXFS_NET2_FC_DATA:
		if (!(hdr->flags & MXFS_NET2_F_RELIABLE)) {
			deliver_frame = true;     /* unsequenced: as-is */
			break;
		}
		{
			uint64_t seq = hdr->seq;
			uint64_t off;

			if (seq == 0)
				break;
			off = net2_seq_after(seq, sess->rx.cum_ack) ?
				seq - sess->rx.cum_ack : 0;
			if (off == 0 ||
			    (off <= 64 &&
			     (sess->rx.rcvd_mask & (1ULL << (off - 1))))) {
				/* Transport dup: re-ACK promptly (the
				 * lost-ACK healing path). */
				sess->stats.dup_seq_suppressed++;
				sess->rx.ack_pending = true;
				sess->rx.acks_owed =
					ctx->tun.delayed_ack_frames;
				if (sess->rx.ack_deadline_ms == 0)
					sess->rx.ack_deadline_ms = now;
				immediate_ack = true;
				break;
			}
			if (off > ctx->tun.rx_win) {
				sess->stats.out_of_window_drops++;
				break;
			}
			sess->rx.rcvd_mask |= 1ULL << (off - 1);
			/* Advance over the contiguous received prefix. */
			while (sess->rx.rcvd_mask & 1) {
				sess->rx.cum_ack++;
				sess->rx.rcvd_mask >>= 1;
			}
			/* Deliver NOW (never held for reordering — see
			 * net2_ctx.h on priority vs ordering); the
			 * msg_id ring suppresses caller-level retries. */
			if (rx_dedup_seen(ctx, sess, hdr->msg_id))
				sess->stats.dup_seq_suppressed++;
			else
				deliver_frame = true;
			sess->rx.acks_owed++;
			sess->rx.ack_pending = true;
			if (sess->rx.ack_deadline_ms == 0) {
				sess->rx.ack_deadline_ms =
					now + ctx->tun.delayed_ack_ms;
				/* Egress may be idle-sleeping with no
				 * deadline in view: kick it so its
				 * timedwait re-computes, else the ack
				 * waits out the idle interval and the
				 * peer's RTO fires first (retx ≈ every
				 * message on one-way flows). */
				immediate_ack = true;
			}
			if (hdr->flags & MXFS_NET2_F_ACKREQ)
				sess->rx.acks_owed =
					ctx->tun.delayed_ack_frames;
			if (sess->rx.acks_owed >= ctx->tun.delayed_ack_frames)
				immediate_ack = true;
		}
		break;

	default:
		break;
	}

out_unlock:
	mxfs_pal_mutex_unlock(sess->lock);

	if (deliver_frame)
		net2_deliver(ctx, sess, payload, len);
	if (immediate_ack)
		net2_link_kick(ctx, sess->peer_slot);
}

/* ─── egress support (link egress worker) ─── */

uint32_t net2_midcomms_pack_entry(struct mxfs_net2_ctx *ctx,
                                  struct net2_session *sess, uint64_t seq,
                                  bool retx, uint8_t *frame_out,
                                  uint16_t *inner_type)
{
	struct mxfs_net2_hdr h;
	struct net2_txent *e;
	uint32_t len;
	uint64_t now = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(sess->lock);
	e = txent_lookup(ctx, sess, seq);
	if (!e || sess->state == NET2_SESS_SUPERSEDED ||
	    sess->state == NET2_SESS_PEER_CLOSED) {
		if (e)
			e->enqueued = false;
		mxfs_pal_mutex_unlock(sess->lock);
		return 0;                /* retired/aborted while queued */
	}
	if (retx && e->sacked) {
		e->enqueued = false;     /* peer has it; await cum-ack */
		mxfs_pal_mutex_unlock(sess->lock);
		return 0;
	}

	memset(&h, 0, sizeof(h));
	h.magic = MXFS_NET2_MAGIC;
	h.version = MXFS_NET2_WIRE_VERSION;
	h.frame_class = e->frame_class;
	h.priority = e->pri;
	h.flags = MXFS_NET2_F_RELIABLE;
	if (sess->tx.next_seq - sess->tx.unacked_base >= ctx->tun.tx_win / 2)
		h.flags |= MXFS_NET2_F_ACKREQ;   /* window pressure */
	h.payload_len = (uint16_t)e->len;
	h.cluster_uuid_hash = ctx->cfg.uuid_hash;
	h.membership_epoch = e->epoch;
	h.src_slot = ctx->cfg.self_slot;
	h.dst_slot = sess->peer_slot;
	h.src_incarnation = ctx->cfg.self_incarnation;
	h.dst_incarnation = sess->peer_inc;
	h.seq = e->seq;
	h.msg_id = e->msg_id;
	/* Piggyback: this frame carries our freshest rx state. */
	h.ack = sess->rx.cum_ack;
	h.sack_mask = (uint32_t)sess->rx.rcvd_mask;
	sess->rx.ack_pending = false;
	sess->rx.acks_owed = 0;
	sess->rx.ack_deadline_ms = 0;

	mxfs_net2_hdr_pack(&h, frame_out);
	memcpy(frame_out + MXFS_NET2_HDR_SIZE, e->payload, e->len);
	len = MXFS_NET2_HDR_SIZE + e->len;
	*inner_type = e->inner_type;

	if (e->first_tx_ms == 0) {
		e->first_tx_ms = now;
		sess->stats.first_tx++;
	} else {
		sess->stats.retx++;
	}
	e->last_tx_ms = now;
	e->tx_count++;
	e->enqueued = false;
	mxfs_pal_mutex_unlock(sess->lock);
	return len;
}

bool net2_midcomms_ack_deadline(struct net2_session *sess,
                                uint64_t *deadline_ms)
{
	bool pending;

	mxfs_pal_mutex_lock(sess->lock);
	pending = sess->rx.ack_pending;
	if (pending)
		*deadline_ms = sess->rx.ack_deadline_ms;
	mxfs_pal_mutex_unlock(sess->lock);
	return pending;
}

uint32_t net2_midcomms_make_ack(struct mxfs_net2_ctx *ctx,
                                struct net2_session *sess, bool force,
                                uint64_t now_ms, uint8_t *frame_out)
{
	struct mxfs_net2_hdr h;

	mxfs_pal_mutex_lock(sess->lock);
	if (!sess->rx.ack_pending && !force) {
		mxfs_pal_mutex_unlock(sess->lock);
		return 0;
	}
	if (!force && now_ms < sess->rx.ack_deadline_ms &&
	    sess->rx.acks_owed < ctx->tun.delayed_ack_frames) {
		mxfs_pal_mutex_unlock(sess->lock);
		return 0;
	}
	memset(&h, 0, sizeof(h));
	h.magic = MXFS_NET2_MAGIC;
	h.version = MXFS_NET2_WIRE_VERSION;
	h.frame_class = MXFS_NET2_FC_ACK;
	h.priority = NET2_PRI_FENCE;
	h.cluster_uuid_hash = ctx->cfg.uuid_hash;
	h.membership_epoch = ctx->membership_epoch;
	h.src_slot = ctx->cfg.self_slot;
	h.dst_slot = sess->peer_slot;
	h.src_incarnation = ctx->cfg.self_incarnation;
	h.dst_incarnation = sess->peer_inc;
	h.ack = sess->rx.cum_ack;
	h.sack_mask = (uint32_t)sess->rx.rcvd_mask;
	sess->rx.ack_pending = false;
	sess->rx.acks_owed = 0;
	sess->rx.ack_deadline_ms = 0;
	mxfs_pal_mutex_unlock(sess->lock);

	mxfs_net2_hdr_pack(&h, frame_out);
	return MXFS_NET2_HDR_SIZE;
}

/* ─── RT-thread duties ─── */

void net2_midcomms_rto_scan(struct mxfs_net2_ctx *ctx, uint64_t now_ms)
{
	struct {
		uint64_t seq;
		uint8_t pri;
		bool retx;
		uint16_t inner_type;
	} batch[NET2_ENQ_BATCH];
	uint16_t slot;

	for (slot = 0; slot < MXFS_MAX_NODES; slot++) {
		struct net2_session *sess;
		int scan = 0, n, i;
		bool kicked = false, done = false;
		bool amb_raise = false;
		uint64_t amb_age = 0;

		mxfs_pal_mutex_lock(ctx->lock);
		sess = ctx->sessions[slot];
		if (!sess) {
			mxfs_pal_mutex_unlock(ctx->lock);
			continue;
		}
		net2_sess_ref(sess);
		mxfs_pal_mutex_unlock(ctx->lock);

		mxfs_pal_mutex_lock(sess->lock);
		if (sess->state != NET2_SESS_ESTABLISHED &&
		    sess->state != NET2_SESS_EMBRYONIC) {
			mxfs_pal_mutex_unlock(sess->lock);
			net2_sess_unref(sess);
			continue;
		}
		while (!done) {
			n = 0;
			for (; sess->state == NET2_SESS_ESTABLISHED &&
			       scan < NET2_TX_RING_MAX &&
			       n < NET2_ENQ_BATCH; scan++) {
				struct net2_txent *e = &sess->tx.ring[scan];

				if (!e->occupied || e->enqueued || e->sacked)
					continue;
				if (e->first_tx_ms == 0) {
					/* buffered, never sent (no route then) */
					batch[n].seq = e->seq;
					batch[n].pri = e->pri;
					batch[n].retx = false;
					batch[n].inner_type = e->inner_type;
					e->enqueued = true;
					n++;
				} else if (now_ms - e->last_tx_ms >= e->rto_ms) {
					e->rto_ms = e->rto_ms * 2;
					if (e->rto_ms > ctx->tun.rto_max_ms)
						e->rto_ms = ctx->tun.rto_max_ms;
					batch[n].seq = e->seq;
					batch[n].pri = e->pri;
					batch[n].retx = true;
					batch[n].inner_type = e->inner_type;
					e->enqueued = true;
					n++;
				}
			}
			if (scan >= NET2_TX_RING_MAX ||
			    sess->state != NET2_SESS_ESTABLISHED) {
				done = true;
				/* COMM_AMBIGUOUS: oldest unacked entry past
				 * the budget (never-transmitted entries age
				 * from acceptance — a peer we cannot even
				 * reach is MORE ambiguous). */
				if (!sess->comm_ambiguous) {
					for (i = 0; i < NET2_TX_RING_MAX; i++) {
						struct net2_txent *e =
							&sess->tx.ring[i];
						uint64_t born;

						if (!e->occupied)
							continue;
						born = e->first_tx_ms ?
						       e->first_tx_ms :
						       e->enq_ms;
						if (born && now_ms - born >=
						    ctx->tun.ambiguity_ms) {
							sess->comm_ambiguous = true;
							amb_raise = true;
							amb_age = now_ms - born;
							break;
						}
					}
				}
			}
			mxfs_pal_mutex_unlock(sess->lock);

			for (i = 0; i < n; i++) {
				if (net2_link_enqueue_ref(ctx, slot, sess,
				                          batch[i].seq,
				                          batch[i].pri,
				                          batch[i].retx,
				                          batch[i].inner_type)) {
					mxfs_pal_mutex_lock(sess->lock);
					{
						struct net2_txent *e =
							txent_lookup(ctx, sess,
							             batch[i].seq);
						if (e)
							e->enqueued = false;
					}
					mxfs_pal_mutex_unlock(sess->lock);
				} else {
					kicked = true;
				}
			}
			if (!done)
				mxfs_pal_mutex_lock(sess->lock);
		}
		if (kicked)
			net2_link_kick(ctx, slot);
		if (amb_raise) {
			/* peer_slot/peer_inc are immutable session identity */
			net2_stat_bump(ctx, &ctx->stats.comm_ambiguous_events);
			mxfs_pal_log(MXFS_LOG_WARN,
			             "net2: session slot %u inc %u COMM_AMBIGUOUS "
			             "(unacked %llu ms)", sess->peer_slot,
			             sess->peer_inc,
			             (unsigned long long)amb_age);
			if (ctx->ambiguous_cb)
				ctx->ambiguous_cb(ctx->ambiguous_cb_data,
				                  sess->peer_slot,
				                  sess->peer_inc, amb_age);
		}
		net2_sess_unref(sess);
	}
}

void net2_midcomms_link_reset(struct mxfs_net2_ctx *ctx,
                              struct net2_session *sess)
{
	(void)ctx;
	if (!sess)
		return;
	mxfs_pal_mutex_lock(sess->lock);
	sess->stats.resets++;
	mxfs_pal_mutex_unlock(sess->lock);
}

void net2_midcomms_gc(struct mxfs_net2_ctx *ctx, uint64_t now_ms)
{
	struct net2_session **prev, *sess;

	mxfs_pal_mutex_lock(ctx->lock);
	prev = &ctx->sess_gc;
	while ((sess = *prev) != NULL) {
		bool reap = false;

		mxfs_pal_mutex_lock(sess->lock);
		/* refs==1: only the GC-list ref remains.  The grace
		 * window is an interim stand-in for the step-5 epoch-
		 * observation bridge exit (docs/net2.md). */
		if (sess->refs == 1 &&
		    now_ms - sess->superseded_at_ms >=
		            ctx->tun.suspect_grace_ms)
			reap = true;
		mxfs_pal_mutex_unlock(sess->lock);

		if (reap) {
			*prev = sess->gc_next;
			sess_destroy(sess);
			mxfs_pal_mutex_lock(ctx->stats_lock);
			ctx->stats.sessions_gcd++;
			mxfs_pal_mutex_unlock(ctx->stats_lock);
		} else {
			prev = &sess->gc_next;
		}
	}
	mxfs_pal_mutex_unlock(ctx->lock);
}

void net2_midcomms_shutdown(struct mxfs_net2_ctx *ctx)
{
	uint16_t slot;
	struct net2_session *sess, *next;

	mxfs_pal_mutex_lock(ctx->lock);
	for (slot = 0; slot < MXFS_MAX_NODES; slot++) {
		sess = ctx->sessions[slot];
		ctx->sessions[slot] = NULL;
		if (!sess)
			continue;
		mxfs_pal_mutex_lock(sess->lock);
		tx_abort_all(sess);
		sess->refs--;            /* drop the table ref */
		if (sess->refs != 0) {
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_log(MXFS_LOG_ERR,
			             "net2: session slot %u leaked at "
			             "shutdown (refs %u)", slot, sess->refs);
			continue;        /* leak loudly, never UAF */
		}
		mxfs_pal_mutex_unlock(sess->lock);
		sess_destroy(sess);
	}
	sess = ctx->sess_gc;
	ctx->sess_gc = NULL;
	while (sess) {
		next = sess->gc_next;
		mxfs_pal_mutex_lock(sess->lock);
		sess->refs--;
		if (sess->refs != 0) {
			mxfs_pal_mutex_unlock(sess->lock);
			mxfs_pal_log(MXFS_LOG_ERR,
			             "net2: GC session slot %u leaked at "
			             "shutdown (refs %u)",
			             sess->peer_slot, sess->refs);
			sess = next;
			continue;
		}
		mxfs_pal_mutex_unlock(sess->lock);
		sess_destroy(sess);
		sess = next;
	}
	mxfs_pal_mutex_unlock(ctx->lock);
}
