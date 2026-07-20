/*
 * MXFS — Multinode XFS
 * NET2 transport — public API, identity, priorities, tunables
 *
 * Third DLM transport behind the mxfs_v5_dlm_* seam (DLM_PLAN.md v2).
 * This header pins the API surface; net2.c / net2_link.c / net2_midcomms.c
 * (§11 step 2) implement it.  Everything builds user-mode (Invariant 4):
 * no kernel API here, platform access only via mxfs_pal_*.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_H
#define MXFS_LIBMXFS_NET2_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "net2_wire.h"

/* ─── Node identity (§5) ───
 *
 * incarnation is a per-slot monotonic counter PERSISTED in the node's own
 * disklock heartbeat record (single-writer sector): read own record at
 * mount/slot-claim, +1, write back BEFORE joining.  "Newer" is decided
 * ONLY by this counter — never by any timestamp.  The per-boot random
 * nonce is exchanged in the SYN TLV and matched by EQUALITY; a mismatch
 * in any of {uuid, epoch-domain, slot, incarnation, nonce} is a different
 * session, full stop.
 */
struct mxfs_net2_id {
	uint64_t membership_epoch;
	uint32_t cluster_uuid_hash;   /* FNV1a; full UUID rides the SYN TLV */
	uint32_t incarnation;
	uint16_t slot;                /* disklock heartbeat slot 0..63 */
};

/* ─── Priority classes (§7.A) ───
 *
 * RELEASE outranks REVOKE (BAST) deliberately: a BAST storm must not
 * delay the completed releases that make progress.  Scheduling is
 * weighted deficit round-robin with guaranteed minimum quanta — never
 * strict-only.  FENCE/RELEASE/REVOKE queue overflow is NEVER a drop:
 * the session enters COMM_AMBIGUOUS and the affected scope freezes.
 */
enum net2_priority {
	NET2_PRI_FENCE     = 0,   /* fencing / MEPOCH control            */
	NET2_PRI_RELEASE   = 1,   /* RELEASE / RELEASE_ACK / their retx  */
	NET2_PRI_REVOKE    = 2,   /* BAST / revoke                       */
	NET2_PRI_GRANT     = 3,   /* GRANT / ACQUIRE / APPEND            */
	NET2_PRI_DISCOVERY = 4,   /* discovery / stats                   */
	NET2_PRI_COUNT
};

_Static_assert(NET2_PRI_COUNT == MXFS_NET2_WIRE_PRI_COUNT,
               "scheduler classes must match the wire-protocol class count");

/* ─── Freeze scopes / reasons (§7.E; implemented in net2_freeze.c, step 6;
 *     declared here because stats and API surface them) ─── */
enum mxfs_net2_freeze_scope {
	MXFS_NET2_FZ_NONE = 0,
	MXFS_NET2_FZ_RESOURCE,
	MXFS_NET2_FZ_SHARD,
	MXFS_NET2_FZ_FS,
};
enum mxfs_net2_freeze_reason {
	MXFS_NET2_FZR_SUSPECT = 0,
	MXFS_NET2_FZR_ELECTION,
	MXFS_NET2_FZR_XFER,
	MXFS_NET2_FZR_QUORUM_LOSS,
	MXFS_NET2_FZR_NOFENCE,
	MXFS_NET2_FZR_COMM_AMBIGUOUS,
	MXFS_NET2_FZR_RECOVERY,
	MXFS_NET2_FZR_COUNT
};

/* ─── Tunables ───
 *
 * Every time/window constant in one struct so (a) defaults are spec
 * values in one place, (b) the user-mode harness can compress time for
 * scenario breadth (a pinned subset always runs at real defaults —
 * compression can mask races).  Kernel builds use the defaults; these
 * are NOT modparams (except where a step explicitly adds one).
 */
struct mxfs_net2_tunables {
	uint32_t rto_initial_ms;      /* 200: first retransmit timeout      */
	uint32_t rto_max_ms;          /* 2000: exponential backoff cap      */
	uint32_t rt_tick_ms;          /* 50: retransmit thread tick         */
	uint32_t delayed_ack_ms;      /* 5: standalone-ACK delay            */
	uint32_t delayed_ack_frames;  /* 8: pending deliveries forcing ACK  */
	uint32_t ambiguity_ms;        /* 10000: unacked age -> COMM_AMBIGUOUS */
	uint32_t suspect_grace_ms;    /* 8000: SUSPECT reconnect grace      */
	uint32_t mepoch_lease_ms;     /* 10000: epoch-view stall -> freeze  */
	uint16_t tx_win;              /* 64: retransmit ring (segments)     */
	uint16_t rx_win;              /* 64: receive window (segments)      */
	uint16_t dedup_ring;          /* 1024: msg_id dedup entries         */
	uint8_t  quantum_pct[NET2_PRI_COUNT];   /* {20,30,25,20,5}          */
	uint16_t queue_cap[NET2_PRI_COUNT];     /* {64,256,256,1024,64}     */
};

#define MXFS_NET2_TUNABLES_DEFAULT {                                    \
	.rto_initial_ms     = 200,                                      \
	.rto_max_ms         = 2000,                                     \
	.rt_tick_ms         = 50,                                       \
	.delayed_ack_ms     = 5,                                        \
	.delayed_ack_frames = 8,                                        \
	.ambiguity_ms       = 10000,                                    \
	.suspect_grace_ms   = 8000,                                     \
	.mepoch_lease_ms    = 10000,                                    \
	.tx_win             = 64,                                       \
	.rx_win             = 64,                                       \
	.dedup_ring         = 1024,                                     \
	.quantum_pct        = { 20, 30, 25, 20, 5 },                    \
	.queue_cap          = { 64, 256, 256, 1024, 64 },               \
}

/* ─── Topology selection (§7.A; modparam net2_topology at step 7) ─── */
enum mxfs_net2_topology {
	MXFS_NET2_TOPO_AUTO    = 0,   /* = mesh until the overlay gate (§11
	                               * step 8) is green at largest tested N */
	MXFS_NET2_TOPO_MESH    = 1,
	MXFS_NET2_TOPO_OVERLAY = 2,
};

/* ─── Lifecycle (implemented step 2) ─── */

struct mxfs_net2_ctx;             /* opaque; net2_ctx.h is internal */

struct mxfs_net2_cfg {
	mxfs_node_id_t node_id;
	uint8_t  uuid[16];
	uint32_t uuid_hash;
	uint32_t volume_id;
	uint32_t fs_gen;
	uint16_t self_slot;
	uint32_t self_incarnation;    /* caller persisted+bumped it (§5) */
	uint64_t boot_nonce;          /* caller-supplied: harness injects
	                               * deterministic nonces; kernel uses
	                               * mxfs_pal_get_random_bytes         */
	uint16_t base_port;           /* link listen port base             */
	uint16_t membership_port;     /* MXFS_PORT_NET2_MEMBERSHIP         */
	uint8_t  topology;            /* enum mxfs_net2_topology           */
	uint32_t features;            /* MXFS_NET2_FEAT_* offered          */
	struct mxfs_net2_tunables tun;
};

/* Delivers one inner message (opaque payload = mxfs_dlm_msg_hdr + body). */
typedef void (*mxfs_net2_recv_cb)(void *data, const struct mxfs_net2_id *src,
                                  const void *payload, uint32_t len);

int  mxfs_net2_create(const struct mxfs_net2_cfg *cfg,
                      struct mxfs_net2_ctx **ctx_out);
int  mxfs_net2_start(struct mxfs_net2_ctx *ctx);
void mxfs_net2_stop(struct mxfs_net2_ctx *ctx);
void mxfs_net2_destroy(struct mxfs_net2_ctx *ctx);
void mxfs_net2_register_recv_cb(struct mxfs_net2_ctx *ctx,
                                mxfs_net2_recv_cb cb, void *data);

/*
 * Send one inner message.  Contract: at-least-once + dedup hint for
 * reliable sends; handlers are effect-idempotent (op identity lives in
 * the net2_msg envelope, NOT the inert inner hdr.seq).  GRANT/DISCOVERY
 * class may return -EAGAIN on backpressure; FENCE/RELEASE/REVOKE
 * overflow never drops (COMM_AMBIGUOUS + scoped freeze instead).
 */
int  mxfs_net2_send(struct mxfs_net2_ctx *ctx,
                    const struct mxfs_net2_id *dst,
                    enum net2_priority pri, bool reliable,
                    uint32_t msg_id, const void *buf, uint32_t len);

/* Membership-committed view update: recompute links/neighbor sets. */
void mxfs_net2_update_view(struct mxfs_net2_ctx *ctx,
                           uint64_t member_mask, uint64_t membership_epoch);

/* ─── Step-2 engine surface (implementation-driven additions) ─── */

/*
 * Inner-message-type -> priority class map (§7.A).  The seam's send
 * callback (step 7) and the harness both use it; NET2-native MEPOCH_/
 * FENCE_ messages (steps 5-6) map to NET2_PRI_FENCE when they exist.
 */
enum net2_priority net2_pri_for_type(uint16_t inner_type);

/*
 * Peer address book.  Discovery feeds this at step 7 ({host, node_id}
 * hint only — never identity, which rides the SYN TLV).  When the port
 * is 0 the link dials cfg.base_port + slot (the same rule the listener
 * uses for itself).
 */
int  mxfs_net2_set_peer_addr(struct mxfs_net2_ctx *ctx, uint16_t slot,
                             const char *host, uint16_t port);

/*
 * COMM_AMBIGUOUS notification (§7.A: >ambiguity_ms unacked, or a
 * coherence-class overflow).  Step 2 ships this as counter + callback;
 * step 6 registers the freeze module here.  Called without engine
 * locks held; may not call back into mxfs_net2_* destroy/stop.
 */
typedef void (*mxfs_net2_ambiguous_cb)(void *data, uint16_t peer_slot,
                                       uint32_t peer_inc,
                                       uint64_t unacked_age_ms);
void mxfs_net2_set_ambiguous_cb(struct mxfs_net2_ctx *ctx,
                                mxfs_net2_ambiguous_cb cb, void *data);

/*
 * Evidence counters (§13): mount aggregate + per-live-session.
 * Definitions in net2_stats.h.
 */
struct mxfs_net2_stats;
struct mxfs_net2_session_stats;
void mxfs_net2_get_stats(struct mxfs_net2_ctx *ctx,
                         struct mxfs_net2_stats *out);
int  mxfs_net2_get_session_stats(struct mxfs_net2_ctx *ctx, uint16_t slot,
                                 struct mxfs_net2_session_stats *out);

/*
 * Fault-injection control (net2_fault.h engine, evaluated at the link
 * frame boundary).  The harness drives these directly; the kernel gains
 * modparams with the same rule syntax at its wiring step.
 */
struct mxfs_net2_fault_rule;
int  mxfs_net2_fault_rule_set(struct mxfs_net2_ctx *ctx, int idx,
                              const struct mxfs_net2_fault_rule *rule);
void mxfs_net2_fault_reset(struct mxfs_net2_ctx *ctx, uint64_t seed);

/* Force a link teardown (test/ops surface).  The session MUST survive:
 * reconnect + retransmit ring recover delivery — that property is what
 * the §13.1 reset-at-framing-point scenarios assert. */
int  mxfs_net2_link_reset(struct mxfs_net2_ctx *ctx, uint16_t slot);

#ifdef __KERNEL__
/* Gate-2 kernel smoke (net2.c bottom): modparam-gated 2-node echo
 * selftest.  Called from module init (after the fs registers) and
 * module exit (first — joins the selftest thread). */
void mxfs_net2_selftest_maybe_start(void);
void mxfs_net2_selftest_stop(void);
#endif

#endif /* MXFS_LIBMXFS_NET2_H */
