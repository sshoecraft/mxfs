/*
 * MXFS — Multinode XFS
 * NET2 transport — internal context (engine-private)
 *
 * Shared structs for net2.c / net2_link.c / net2_overlay.c /
 * net2_midcomms.c.  This header is NOT part of the public surface —
 * net2.h is; nothing outside dlm/net2_*.c may include it.  Everything
 * builds user-mode (Invariant 4): platform access only via mxfs_pal_*.
 *
 * Locking order (never inverted, never two session locks at once):
 *   ctx->lock  >  link->lock  >  sess->lock  >  ctx->stats_lock
 * The fault state has its own lock (leaf).  Only a link's egress worker
 * writes to a live link socket; handshake I/O happens before the
 * worker threads exist, and teardown follows peer.c's discipline
 * (shutdown -> join threads -> close -> install).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_CTX_H
#define MXFS_LIBMXFS_NET2_CTX_H

#include "net2.h"
#include "net2_stats.h"
#include "net2_fault.h"
#include "../include/mxfs/mxfs_ports.h"

/*
 * Static bounds.  Rings are sized at the spec maxima; the live window is
 * the tunable (tun.tx_win/rx_win <= these).  MXFS_MAX_NODES == 64 ==
 * MXFS_DISKLOCK_HB_SLOTS: links and live sessions are indexed by slot.
 */
#define NET2_TX_RING_MAX    64
#define NET2_RX_HOLD_MAX    64
#define NET2_DEDUP_MAX      1024
#define NET2_HOST_MAX       64

/* Weighted-deficit-RR round budget (bytes credited across one round). */
#define NET2_WDRR_ROUND_BYTES  32768

/* Serial-number arithmetic (u64 seq space; wrap unreachable but the
 * comparisons are wrap-correct anyway and asserted by the harness). */
static inline bool net2_seq_before(uint64_t a, uint64_t b)
{
	return (int64_t)(a - b) < 0;
}
static inline bool net2_seq_after(uint64_t a, uint64_t b)
{
	return (int64_t)(a - b) > 0;
}

enum net2_sess_state {
	NET2_SESS_EMBRYONIC = 0,   /* tx buffered; peer nonce unknown yet  */
	NET2_SESS_ESTABLISHED,     /* handshake bound; frames flow         */
	NET2_SESS_SUPERSEDED,      /* newer incarnation/nonce seen; frozen */
	NET2_SESS_PEER_CLOSED,     /* orderly FIN from peer                */
};

/* One retransmit-ring slot (canonical copy of a reliable frame). */
struct net2_txent {
	bool     occupied;
	bool     enqueued;         /* referenced by an egress queue entry  */
	uint8_t  pri;
	uint8_t  frame_class;      /* DATA (or FIN when reliable teardown) */
	uint16_t inner_type;       /* for fault matching; 0 if unknown     */
	uint32_t msg_id;
	uint64_t seq;
	uint64_t epoch;            /* stamped at ENQUEUE (bridge rule §7.A)*/
	uint8_t *payload;          /* owned; freed on retire               */
	uint32_t len;
	uint64_t enq_ms;           /* accepted into the ring (ambiguity
	                            * ages from here when never sent)     */
	uint64_t first_tx_ms;      /* 0 until first transmission          */
	uint64_t last_tx_ms;
	uint32_t tx_count;
	uint32_t rto_ms;           /* current backoff value               */
	bool     sacked;           /* SACK'd: suppress retransmit; retire
	                            * only on cumulative-ack advance      */
};

struct net2_dir_tx {
	uint64_t next_seq;         /* next seq to allocate (starts at 1)  */
	uint64_t unacked_base;     /* lowest unacked seq                  */
	struct net2_txent ring[NET2_TX_RING_MAX];
};

/*
 * RX side: DELIVER-ON-RECEIPT.  There is deliberately no reorder-hold:
 * holding frames for seq order would let a congested lower class delay
 * a higher one end-to-end and defeat §7.A's priority guarantee (the
 * whole point of RELEASE > REVOKE).  The transport contract is
 * at-least-once + dedup hint; ordering tolerance lives in the handlers
 * (op identity + completed-op cache, §6/§7.B).  rcvd_mask bit b marks
 * seq cum_ack+1+b received; the wire SACK is its low 32 bits; cum_ack
 * advances over the contiguous received prefix.
 */
struct net2_dir_rx {
	uint64_t cum_ack;          /* every seq <= this has been received */
	uint64_t rcvd_mask;        /* bits for cum_ack+1 .. cum_ack+64    */
	uint32_t dedup[NET2_DEDUP_MAX];   /* recent delivered msg_ids     */
	uint32_t dedup_pos;
	uint32_t acks_owed;        /* deliveries since last ACK sent      */
	bool     ack_pending;
	uint64_t ack_deadline_ms;  /* mxfs_pal_time_ms() deadline         */
};

struct net2_session {
	struct net2_session *gc_next;     /* superseded-list linkage      */
	uint16_t peer_slot;
	uint32_t peer_inc;
	uint64_t peer_nonce;              /* 0 while EMBRYONIC            */
	uint32_t peer_features;
	uint32_t refs;                    /* egress/link references; the
	                                   * session is freed only at 0
	                                   * (guarded by sess->lock)      */
	enum net2_sess_state state;
	uint64_t superseded_at_ms;
	uint32_t msg_id_next;             /* auto-alloc counter (skips 0) */
	bool     comm_ambiguous;
	uint64_t last_ack_progress_ms;
	struct net2_dir_tx tx;
	struct net2_dir_rx rx;
	struct mxfs_net2_session_stats stats;
	mxfs_mutex_t *lock;
};

enum net2_link_state {
	NET2_LINK_DOWN = 0,
	NET2_LINK_CONNECTING,
	NET2_LINK_ACTIVE,
};

/* Egress queue entry.  Reliable frames reference their ring slot (the
 * ring copy is canonical; if the slot retires before dequeue the entry
 * is dropped on the floor); unreliable frames own a packed wire image. */
struct net2_eqent {
	struct net2_eqent *next;
	struct net2_session *sess;        /* NULL => own-frame entry      */
	uint64_t seq;                     /* valid when sess != NULL      */
	bool     retx;
	uint8_t *frame;                   /* packed hdr+payload (own)     */
	uint32_t frame_len;
	uint16_t inner_type;              /* fault matching               */
	uint8_t  frame_class;
	uint8_t  pri;
	uint64_t enq_ms;
	uint64_t not_before_ms;           /* fault delay action           */
};

struct net2_linkq {
	struct net2_eqent *fresh_head, *fresh_tail;
	struct net2_eqent *retx_head, *retx_tail;
	uint16_t depth;                   /* fresh + retx entries         */
	int32_t  deficit;                 /* WDRR running credit (bytes)  */
	uint8_t  fresh_burst;             /* fresh:retx 3:1 alternation   */
};

struct net2_link {
	uint16_t peer_slot;
	char     host[NET2_HOST_MAX];
	uint16_t port;
	bool     addr_known;
	bool     desired;                 /* provider wants this link up  */
	enum net2_link_state state;
	mxfs_sock_t *sock;
	struct net2_session *sess;        /* handshake-bound session (holds
	                                   * one ref); egress/recv use this
	                                   * under link->lock — never the
	                                   * ctx->sessions table           */
	mxfs_thread_t *recv_thread;
	mxfs_thread_t *egress_thread;
	mxfs_thread_t *conn_thread;       /* one-shot outbound handshake  */
	bool     egress_stop;             /* this link's worker must exit */
	mxfs_mutex_t *lock;
	mxfs_cond_t  *egress_cond;
	struct net2_linkq q[NET2_PRI_COUNT];
	bool     ack_kick;                /* immediate standalone-ACK ask */
	uint64_t last_connect_ms;
	uint32_t connect_backoff_ms;
	struct mxfs_net2_class_stats cls[NET2_PRI_COUNT];
};

struct net2_provider {
	const char *name;
	/* Returns the link to transmit on for dst_slot, or NULL. */
	struct net2_link *(*route)(struct mxfs_net2_ctx *ctx, uint16_t dst_slot);
	struct net2_link *(*route_alt)(struct mxfs_net2_ctx *ctx,
	                               uint16_t dst_slot);
	/* View changed: recompute desired link set (ctx->lock held). */
	void (*view_update)(struct mxfs_net2_ctx *ctx);
};

struct mxfs_net2_ctx {
	struct mxfs_net2_cfg cfg;
	struct mxfs_net2_tunables tun;    /* == cfg.tun (clamped)         */
	volatile bool running;

	uint64_t membership_epoch;        /* committed view (update_view) */
	uint64_t member_mask;

	mxfs_sock_t *listen_sock;
	mxfs_thread_t *accept_thread;
	mxfs_sock_t * volatile pending_sock;  /* handshake-in-progress    */

	struct net2_link links[MXFS_MAX_NODES];
	struct net2_session *sessions[MXFS_MAX_NODES];  /* live, by slot  */
	struct net2_session *sess_gc;                   /* superseded     */

	mxfs_mutex_t *lock;               /* tables + view + provider     */
	mxfs_thread_t *rt_thread;

	const struct net2_provider *prov;

	mxfs_net2_recv_cb recv_cb;
	void *recv_cb_data;
	mxfs_net2_ambiguous_cb ambiguous_cb;
	void *ambiguous_cb_data;

	struct mxfs_net2_stats stats;
	mxfs_mutex_t *stats_lock;

	struct mxfs_net2_fault_state fault;
	mxfs_mutex_t *fault_lock;
};

/* ─── net2.c internals shared with the engine files ─── */

void net2_deliver(struct mxfs_net2_ctx *ctx, struct net2_session *sess,
                  const void *payload, uint32_t len);
void net2_stat_bump(struct mxfs_net2_ctx *ctx, uint64_t *field);

#endif /* MXFS_LIBMXFS_NET2_CTX_H */
