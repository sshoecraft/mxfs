/*
 * MXFS — Multinode XFS
 * Portable lease management
 *
 * Tracks lease state for all known nodes. A node is alive if and only
 * if its lease is current. Lease expiry is the sole liveness detection
 * mechanism: expired lease = node is dead, its locks are invalid, its
 * journal must be replayed before anyone else touches those resources.
 *
 * Heartbeats are sent/received via UDP multicast (port 7602) instead
 * of TCP through the DLM peer connections.  At 16+ nodes, DLM traffic
 * congests TCP, blocking lease sends and causing false node-death
 * declarations.  A single multicast packet replaces N TCP unicast sends.
 *
 * Ported from kernel/mxfs_lease.{c,h} — delayed_work replaced with
 * PAL threads + sleep loops, ktime_get_ns replaced with mxfs_pal_time_ms.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_LEASE_H
#define MXFS_LIBMXFS_LEASE_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"
#include "../include/mxfs/mxfs_ports.h"
#include "static_peers.h"

/*
 * Lease timing constants.
 *
 * Under heavy iSCSI I/O (e.g. concurrent 50MB reads at 4+ nodes),
 * the lease renewal kthread can be starved by block I/O completions
 * for 90-142 seconds.  Under 4-node concurrent metadata I/O on a
 * single ESXi host, cascading membership flapping occurs: missed
 * renewals -> SUSPECT -> cache flush + lock purge -> I/O storm ->
 * more missed renewals on other nodes -> cluster death spiral.
 *
 * Fix: 500ms renewals (more attempts per window), 60s duration
 * before miss counting starts, 600s hard timeout, and require
 * 150 consecutive misses (monitor checks every 2s, so 150
 * misses = 300s of continuous missed renewals after the 60s
 * duration window).  Total time before SUSPECT: ~360s (6 min).
 *
 * Dead nodes are detected much faster via TCP disconnect (seconds,
 * not minutes).  The lease is a safety net, not the primary
 * detection mechanism.  A 6-minute timeout prevents cascading
 * membership flapping under heavy I/O while still catching truly
 * dead nodes that somehow evade TCP disconnect detection.
 *
 * Combined with RT-priority lease kthreads (sched_set_fifo_low)
 * and membership change cooldown (30s dampening in mount.c),
 * this eliminates false SUSPECT declarations under load.
 */
#define MXFS_LEASE_DURATION_DEFAULT_MS   60000
#define MXFS_LEASE_RENEW_DEFAULT_MS      500
#define MXFS_LEASE_TIMEOUT_DEFAULT_MS    600000
#define MXFS_LEASE_MONITOR_INTERVAL_MS   2000

/* UDP multicast lease heartbeat.
 * DEPRECATED alias: this is the LEGACY mount path's lease port only.
 * Both v5 mount paths pass MXFS_PORT_LEASE_V5 (7603) explicitly.
 * Do not "fix" the split here — unifying legacy onto 7603 is a
 * separately-versioned change (see mxfs_ports.h). */
#define MXFS_LEASE_PORT                  MXFS_PORT_LEASE_LEGACY
#define MXFS_LEASE_MCAST                 "239.66.83.1"
#define MXFS_LEASE_UDP_MAGIC             0x4D584C48  /* "MXLH" */
#define MXFS_LEASE_UDP_VERSION           1

/*
 * Number of consecutive missed renewals before transitioning to
 * SUSPECT.  The monitor thread checks every 2s, so 150 misses =
 * 300 seconds (5 minutes) of continuous missed renewals after
 * the 60s duration window expires.  Total time before SUSPECT:
 * ~360s (6 minutes).
 *
 * This is deliberately generous because dead nodes are detected
 * much faster via TCP disconnect (seconds).  The lease timeout
 * is a safety net for the rare case where TCP disconnect is
 * missed.  The high threshold prevents cascading membership
 * flapping under heavy I/O: each false SUSPECT triggers cache
 * flush + lock purge on all nodes, creating an I/O storm that
 * starves lease renewals on more nodes, causing a death spiral.
 *
 * A genuinely dead node is still detected as SUSPECT within
 * ~6 minutes and DEAD within 10 minutes (600s hard timeout).
 */
#define MXFS_LEASE_SUSPECT_MISSES        150

/* UDP lease heartbeat packet — multicast wire format.
 * v0.11.78 (D7): grew view_count/view_hash — the sender's DLM membership
 * view signature (0 = sender has no TCP DLM / no view yet).  RX treats a
 * packet of the ORIGINAL length as a valid beacon without a view report
 * (see MXFS_LEASE_UDP_MSG_V1_LEN), so a short packet never fakes a
 * confirmation; all cluster nodes run the same build per the support
 * contract, this is just defensive parsing. */
/*
 * 0.89.68 (D-POST-CLOSURE-MEMBERSHIP-RENEWAL-HAS-NO-DEFINED-MEANING-AT-THE-PEER):
 * a renewal says WHAT the sender is, not only that it is running.  The
 * former pad word carries the sender's authority state — every earlier
 * sender wrote zero there, so zero means "unstated" and is read exactly as
 * before — and the sender's incarnation is appended after view_hash, so a
 * packet of the earlier full length is still a complete view report and a
 * longer one also names the incarnation.  The receiver keeps a withdrawn
 * sender's entry (mastership stays with it until its slice is replayed) but
 * takes nothing else from the packet: no liveness stamp, no promotion.  A
 * renewal naming a different incarnation than the entry holds is not
 * liveness at all — the epoch argument on this path is the literal 0, so
 * this is the only way two incarnations of one node id can be told apart.
 */
#define MXFS_LEASE_STATE_UNSTATED        0   /* sender older than this field */
#define MXFS_LEASE_STATE_MEMBER          1   /* authority live: a functioning member */
#define MXFS_LEASE_STATE_WITHDRAWN       2   /* authority closed: renewing only to hold mastership */

#pragma pack(push, 1)
struct mxfs_lease_udp_msg {
	uint32_t        magic;
	uint16_t        version;
	uint16_t        state;          /* MXFS_LEASE_STATE_* (was pad; older senders write 0) */
	mxfs_node_id_t  node_id;
	uint8_t         volume_uuid[16];
	uint64_t        lease_duration_ms;
	uint32_t        view_count;
	uint32_t        pad2;
	uint64_t        view_hash;
	uint64_t        incarnation;    /* 0.89.68: the sender's mount incarnation (0 = unstated) */
};
#pragma pack(pop)
#define MXFS_LEASE_UDP_MSG_V1_LEN \
	(offsetof(struct mxfs_lease_udp_msg, view_count))
/* the full pre-0.89.68 packet: a complete view report, no incarnation */
#define MXFS_LEASE_UDP_MSG_VIEW_LEN \
	(offsetof(struct mxfs_lease_udp_msg, incarnation))

/* Per-node lease state */
struct mxfs_node_lease {
	mxfs_node_id_t          node_id;
	mxfs_epoch_t            epoch;
	uint64_t                granted_at;     /* mxfs_pal_time_ms() */
	uint64_t                duration_ms;
	uint64_t                last_renewal;   /* mxfs_pal_time_ms() */
	enum mxfs_node_state    state;
	int                     missed_renewals;
	uint64_t                incarnation;    /* 0.89.68: taken from the first renewal that names one; 0 = none yet */
	uint16_t                sender_state;   /* 0.89.68: MXFS_LEASE_STATE_* from the last renewal read */
};

/* Callback fired when a node's lease expires (node declared dead) */
typedef void (*mxfs_lease_expire_cb)(void *data, mxfs_node_id_t dead_node);

/* Per-mount lease context */
struct mxfs_lease_ctx {
	struct mxfs_node_lease  nodes[MXFS_MAX_NODES];
	int                     node_count;
	uint64_t                default_duration_ms;
	uint64_t                renew_interval_ms;
	uint64_t                timeout_ms;
	mxfs_node_id_t          local_node;

	mxfs_thread_t           *renew_thread;
	mxfs_thread_t           *monitor_thread;
	mxfs_mutex_t            *lock;
	volatile bool           running;

	/* Shutdown signaling: condvar wakes sleeping threads */
	mxfs_mutex_t            *shutdown_lock;
	mxfs_cond_t             *shutdown_cond;

	/* UDP multicast heartbeat (replaces TCP send_cb) */
	mxfs_sock_t             *udp_sock;
	mxfs_thread_t           *udp_recv_thread;
	char                    mcast_addr[64];
	char                    send_addr[64];
	uint16_t                udp_port;
	bool                    use_broadcast;
	struct mxfs_static_peers peers;     /* count 0 = multicast/broadcast */
	uint8_t                 volume_uuid[16];

	mxfs_lease_expire_cb    expire_cb;
	void                    *expire_cb_data;

	/* v0.11.78 (D7): view-signature piggyback.  view_sig_cb supplies the
	 * local DLM's {count,hash} for each outgoing beacon; view_report_cb
	 * delivers a peer's received signature (only called when the packet
	 * actually carried one). */
	uint64_t (*view_sig_cb)(void *data, uint32_t *count);
	void     *view_sig_cb_data;
	void     (*view_report_cb)(void *data, mxfs_node_id_t node,
				   uint32_t count, uint64_t hash);
	void     *view_report_cb_data;
	/* 0.89.68: what this node IS, for each outgoing beacon — its authority
	 * state (MXFS_LEASE_STATE_*) and its incarnation.  Unset: unstated, 0. */
	uint16_t (*member_state_cb)(void *data, uint64_t *incarnation);
	void     *member_state_cb_data;
};

/* Lifecycle */
struct mxfs_lease_ctx *mxfs_lease_create(mxfs_node_id_t local_node,
					  const uint8_t *volume_uuid,
					  const char *mcast_addr,
					  uint16_t lease_port,
					  bool use_broadcast,
					  const struct mxfs_static_peers *peers);
void mxfs_lease_destroy(struct mxfs_lease_ctx *ctx);
int  mxfs_lease_start(struct mxfs_lease_ctx *ctx);
void mxfs_lease_stop(struct mxfs_lease_ctx *ctx);

/* Node management */
int  mxfs_lease_register_node(struct mxfs_lease_ctx *ctx,
			       mxfs_node_id_t node_id);
int  mxfs_lease_unregister_node(struct mxfs_lease_ctx *ctx,
				 mxfs_node_id_t node_id);

/* Renewal processing.  state is MXFS_LEASE_STATE_*, incarnation 0 = unstated. */
int  mxfs_lease_process_renewal(struct mxfs_lease_ctx *ctx,
				 mxfs_node_id_t node_id, mxfs_epoch_t epoch,
				 uint16_t state, uint64_t incarnation);

/* Query */
bool mxfs_lease_is_valid(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id);
bool mxfs_lease_has_node(struct mxfs_lease_ctx *ctx, mxfs_node_id_t node_id);
int  mxfs_lease_get_active_nodes(struct mxfs_lease_ctx *ctx,
				  mxfs_node_id_t *out, int max_count);

/* Callback registration */
void mxfs_lease_set_expire_cb(struct mxfs_lease_ctx *ctx,
			       mxfs_lease_expire_cb cb, void *data);

/* v0.11.78 (D7): view-signature piggyback wiring */
void mxfs_lease_set_view_provider(struct mxfs_lease_ctx *ctx,
				  uint64_t (*cb)(void *data, uint32_t *count),
				  void *data);
void mxfs_lease_set_member_state_provider(struct mxfs_lease_ctx *ctx,
					  uint16_t (*cb)(void *data, uint64_t *incarnation),
					  void *data);
void mxfs_lease_set_view_report_cb(struct mxfs_lease_ctx *ctx,
				   void (*cb)(void *data, mxfs_node_id_t node,
					      uint32_t count, uint64_t hash),
								   void *data);

#endif /* MXFS_LIBMXFS_LEASE_H */
