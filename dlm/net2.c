/*
 * MXFS — Multinode XFS
 * NET2 transport — lifecycle, recv demux, priority map
 *
 * Public API implementation (net2.h).  The engine splits into:
 *   net2_link.c      TCP links, handshake, recv + egress workers
 *   net2_overlay.c   routing provider (mesh; overlay at step 8)
 *   net2_midcomms.c  sessions, seq/ack/sack, retransmit, dedup
 * plus this file: mxfs_net2_create/start/stop/destroy, the single RT
 * thread (retransmit scan, connect sweep, lazy link close, session GC),
 * delivery to the registered callback, and net2_pri_for_type().
 *
 * Thread inventory per ctx (mesh, N peers): 1 accept + 1 RT + per
 * active link {1 recv + 1 egress} (+ short-lived outbound handshake
 * threads).  Shutdown order: running=false -> join RT (it never blocks
 * unboundedly: it only joins exited threads and cuts wedged handshakes
 * by socket shutdown) -> link_shutdown_all (listener, links, workers)
 * -> midcomms_shutdown (abort dispositions) -> destroy frees.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_ctx.h"
#include "net2_link.h"
#include "net2_overlay.h"
#include "net2_midcomms.h"
#include "../include/mxfs/mxfs_dlm.h"
#include "../include/mxfs/mxfs_ports.h"

#ifdef __KERNEL__
#include <linux/moduleparam.h>   /* gate-2 smoke selftest params; dlm
                                  * modparam precedent = v5_mount.c */
#else
#include <stdio.h>          /* snprintf; the kernel build gets it from
                             * linux/kernel.h via pal.h */
#endif

void net2_stat_bump(struct mxfs_net2_ctx *ctx, uint64_t *field)
{
	mxfs_pal_mutex_lock(ctx->stats_lock);
	(*field)++;
	mxfs_pal_mutex_unlock(ctx->stats_lock);
}

/* ─── inner-type -> priority map (§11 step 2 spec) ─── */

enum net2_priority net2_pri_for_type(uint16_t inner_type)
{
	switch (inner_type) {
	case MXFS_MSG_LOCK_RELEASE:
		return NET2_PRI_RELEASE;
	case MXFS_MSG_JOURNAL_RECOVER:
	case MXFS_MSG_JOURNAL_DONE:
		return NET2_PRI_RELEASE;   /* recovery progress */
	case MXFS_MSG_LOCK_BAST:
	case MXFS_MSG_CACHE_INVAL:
		return NET2_PRI_REVOKE;
	case MXFS_MSG_LOCK_REQ:
	case MXFS_MSG_LOCK_GRANT:
	case MXFS_MSG_LOCK_DENY:
	case MXFS_MSG_LOCK_CONVERT:
		return NET2_PRI_GRANT;
	case MXFS_MSG_LEASE_RENEW:
	case MXFS_MSG_LEASE_ACK:
	case MXFS_MSG_LEASE_EXPIRE:
	case MXFS_MSG_NODE_JOIN:
	case MXFS_MSG_NODE_LEAVE:
	case MXFS_MSG_NODE_ALIVE:
		return NET2_PRI_DISCOVERY;
	default:
		/* MD_* RPCs and anything unknown ride the general
		 * acquire class.  NET2-native MEPOCH_/FENCE_ messages
		 * (steps 5-6) map to NET2_PRI_FENCE when they exist. */
		return NET2_PRI_GRANT;
	}
}

/* ─── delivery (recv-thread context, no locks held) ─── */

void net2_deliver(struct mxfs_net2_ctx *ctx, struct net2_session *sess,
                  const void *payload, uint32_t len)
{
	struct mxfs_net2_id src;

	if (!ctx->recv_cb)
		return;
	src.membership_epoch = ctx->membership_epoch;
	src.cluster_uuid_hash = ctx->cfg.uuid_hash;
	src.incarnation = sess->peer_inc;
	src.slot = sess->peer_slot;
	ctx->recv_cb(ctx->recv_cb_data, &src, payload, len);
}

/* ─── RT thread: retransmit, connect sweep, lazy close, GC ─── */

static bool net2_session_drained(struct mxfs_net2_ctx *ctx, uint16_t slot)
{
	struct net2_session *sess;
	bool drained = true;
	int i;

	mxfs_pal_mutex_lock(ctx->lock);
	sess = ctx->sessions[slot];
	if (sess) {
		mxfs_pal_mutex_lock(sess->lock);
		for (i = 0; i < NET2_TX_RING_MAX; i++)
			if (sess->tx.ring[i].occupied) {
				drained = false;
				break;
			}
		mxfs_pal_mutex_unlock(sess->lock);
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	return drained;
}

static void net2_rt_fn(void *arg)
{
	struct mxfs_net2_ctx *ctx = arg;

	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: rt thread started (tick %u ms)",
	             ctx->tun.rt_tick_ms);

	while (ctx->running) {
		uint64_t now = mxfs_pal_time_ms();
		uint64_t mask;
		uint16_t slot;

		net2_midcomms_rto_scan(ctx, now);

		mxfs_pal_mutex_lock(ctx->lock);
		mask = ctx->member_mask;
		mxfs_pal_mutex_unlock(ctx->lock);

		for (slot = 0; slot < MXFS_MAX_NODES; slot++) {
			struct net2_link *link = &ctx->links[slot];
			enum net2_link_state st;
			bool desired;

			if (slot == ctx->cfg.self_slot)
				continue;

			mxfs_pal_mutex_lock(link->lock);
			st = link->state;
			desired = link->desired;
			mxfs_pal_mutex_unlock(link->lock);

			if (desired && (mask & (1ULL << slot)) &&
			    slot > ctx->cfg.self_slot &&
			    st == NET2_LINK_DOWN) {
				net2_link_connect(ctx, slot);
			} else if (st == NET2_LINK_DOWN) {
				/* Reap exited worker threads promptly so
				 * a replacement connect never stalls. */
				bool stale;

				mxfs_pal_mutex_lock(link->lock);
				stale = link->recv_thread ||
				        link->egress_thread ||
				        link->conn_thread || link->sock;
				mxfs_pal_mutex_unlock(link->lock);
				if (stale)
					net2_link_reap(ctx, link);
			} else if (st == NET2_LINK_CONNECTING) {
				/* Cut a wedged handshake loose (bounded). */
				net2_link_connect(ctx, slot);
			} else if (!desired && st == NET2_LINK_ACTIVE &&
			           net2_session_drained(ctx, slot)) {
				/* Lazy retirement after drain (§7.A). */
				net2_link_down(ctx, &ctx->links[slot]);
			}
		}

		net2_midcomms_gc(ctx, now);
		mxfs_pal_sleep_ms(ctx->tun.rt_tick_ms);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "net2: rt thread exiting");
}

/* ─── tunables clamping ─── */

static void net2_tunables_clamp(struct mxfs_net2_tunables *t)
{
	static const struct mxfs_net2_tunables defs =
		MXFS_NET2_TUNABLES_DEFAULT;
	int i, sum = 0;

	if (t->tx_win == 0 || t->tx_win > NET2_TX_RING_MAX)
		t->tx_win = defs.tx_win;
	if (t->rx_win == 0 || t->rx_win > NET2_RX_HOLD_MAX)
		t->rx_win = defs.rx_win;
	if (t->dedup_ring == 0 || t->dedup_ring > NET2_DEDUP_MAX)
		t->dedup_ring = defs.dedup_ring;
	if (t->rt_tick_ms == 0)
		t->rt_tick_ms = defs.rt_tick_ms;
	if (t->rto_initial_ms == 0)
		t->rto_initial_ms = defs.rto_initial_ms;
	if (t->rto_max_ms < t->rto_initial_ms)
		t->rto_max_ms = t->rto_initial_ms;
	if (t->delayed_ack_frames == 0)
		t->delayed_ack_frames = defs.delayed_ack_frames;
	if (t->ambiguity_ms == 0)
		t->ambiguity_ms = defs.ambiguity_ms;
	if (t->suspect_grace_ms == 0)
		t->suspect_grace_ms = defs.suspect_grace_ms;
	for (i = 0; i < NET2_PRI_COUNT; i++) {
		sum += t->quantum_pct[i];
		if (t->queue_cap[i] == 0)
			t->queue_cap[i] = defs.queue_cap[i];
	}
	if (sum == 0)
		memcpy(t->quantum_pct, defs.quantum_pct,
		       sizeof(t->quantum_pct));
}

/* ─── lifecycle ─── */

int mxfs_net2_create(const struct mxfs_net2_cfg *cfg,
                     struct mxfs_net2_ctx **ctx_out)
{
	struct mxfs_net2_ctx *ctx;
	int i;

	if (!cfg || !ctx_out)
		return -EINVAL;
	if (cfg->self_slot >= MXFS_MAX_NODES || cfg->base_port == 0)
		return -EINVAL;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));
	ctx->cfg = *cfg;
	ctx->tun = cfg->tun;
	net2_tunables_clamp(&ctx->tun);
	ctx->membership_epoch = 1;
	ctx->prov = net2_provider_get(cfg->topology);

	ctx->lock = mxfs_pal_mutex_create();
	ctx->stats_lock = mxfs_pal_mutex_create();
	ctx->fault_lock = mxfs_pal_mutex_create();
	if (!ctx->lock || !ctx->stats_lock || !ctx->fault_lock)
		goto fail;
	mxfs_net2_fault_init(&ctx->fault, cfg->boot_nonce ?
	                     cfg->boot_nonce : 1);

	for (i = 0; i < MXFS_MAX_NODES; i++) {
		struct net2_link *link = &ctx->links[i];

		link->peer_slot = (uint16_t)i;
		link->state = NET2_LINK_DOWN;
		link->connect_backoff_ms = 200;
		link->lock = mxfs_pal_mutex_create();
		link->egress_cond = mxfs_pal_cond_create();
		if (!link->lock || !link->egress_cond)
			goto fail;
	}

	*ctx_out = ctx;
	return 0;

fail:
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		if (ctx->links[i].lock)
			mxfs_pal_mutex_destroy(ctx->links[i].lock);
		if (ctx->links[i].egress_cond)
			mxfs_pal_cond_destroy(ctx->links[i].egress_cond);
	}
	if (ctx->lock)
		mxfs_pal_mutex_destroy(ctx->lock);
	if (ctx->stats_lock)
		mxfs_pal_mutex_destroy(ctx->stats_lock);
	if (ctx->fault_lock)
		mxfs_pal_mutex_destroy(ctx->fault_lock);
	mxfs_pal_free(ctx);
	return -ENOMEM;
}

int mxfs_net2_start(struct mxfs_net2_ctx *ctx)
{
	int rc;

	if (!ctx || ctx->running)
		return -EINVAL;

	ctx->running = true;
	rc = net2_link_listen_start(ctx);
	if (rc) {
		ctx->running = false;
		return rc;
	}
	ctx->rt_thread = mxfs_pal_thread_create_rt(net2_rt_fn, ctx);
	if (!ctx->rt_thread) {
		ctx->running = false;
		net2_link_shutdown_all(ctx);
		return -ENOMEM;
	}
	mxfs_pal_log(MXFS_LOG_INFO,
	             "net2: started (slot %u inc %u port %u topo %s)",
	             ctx->cfg.self_slot, ctx->cfg.self_incarnation,
	             (unsigned)(ctx->cfg.base_port + ctx->cfg.self_slot),
	             ctx->prov->name);
	return 0;
}

void mxfs_net2_stop(struct mxfs_net2_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return;

	ctx->running = false;
	/* RT first: it only joins exited threads (see net2_rt_fn), and
	 * with running false it spawns nothing new. */
	if (ctx->rt_thread) {
		mxfs_pal_thread_join(ctx->rt_thread);
		ctx->rt_thread = NULL;
	}
	net2_link_shutdown_all(ctx);
	net2_midcomms_shutdown(ctx);
	mxfs_pal_log(MXFS_LOG_INFO, "net2: stopped (slot %u)",
	             ctx->cfg.self_slot);
}

void mxfs_net2_destroy(struct mxfs_net2_ctx *ctx)
{
	int i;

	if (!ctx)
		return;
	mxfs_net2_stop(ctx);
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		mxfs_pal_mutex_destroy(ctx->links[i].lock);
		mxfs_pal_cond_destroy(ctx->links[i].egress_cond);
	}
	mxfs_pal_mutex_destroy(ctx->lock);
	mxfs_pal_mutex_destroy(ctx->stats_lock);
	mxfs_pal_mutex_destroy(ctx->fault_lock);
	mxfs_pal_free(ctx);
}

/* ─── callbacks / view / addressing ─── */

void mxfs_net2_register_recv_cb(struct mxfs_net2_ctx *ctx,
                                mxfs_net2_recv_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->recv_cb = cb;
	ctx->recv_cb_data = data;
}

void mxfs_net2_set_ambiguous_cb(struct mxfs_net2_ctx *ctx,
                                mxfs_net2_ambiguous_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->ambiguous_cb = cb;
	ctx->ambiguous_cb_data = data;
}

int mxfs_net2_set_peer_addr(struct mxfs_net2_ctx *ctx, uint16_t slot,
                            const char *host, uint16_t port)
{
	struct net2_link *link;

	if (!ctx || !host || slot >= MXFS_MAX_NODES ||
	    slot == ctx->cfg.self_slot)
		return -EINVAL;
	link = &ctx->links[slot];
	mxfs_pal_mutex_lock(link->lock);
	snprintf(link->host, sizeof(link->host), "%s", host);
	link->port = port;
	link->addr_known = true;
	mxfs_pal_mutex_unlock(link->lock);
	return 0;
}

void mxfs_net2_update_view(struct mxfs_net2_ctx *ctx, uint64_t member_mask,
                           uint64_t membership_epoch)
{
	if (!ctx)
		return;
	mxfs_pal_mutex_lock(ctx->lock);
	if (membership_epoch < ctx->membership_epoch) {
		mxfs_pal_mutex_unlock(ctx->lock);
		mxfs_pal_log(MXFS_LOG_WARN,
		             "net2: ignoring stale view epoch %llu (< %llu)",
		             (unsigned long long)membership_epoch,
		             (unsigned long long)ctx->membership_epoch);
		return;
	}
	ctx->membership_epoch = membership_epoch;
	ctx->member_mask = member_mask;
	ctx->prov->view_update(ctx);
	mxfs_pal_mutex_unlock(ctx->lock);
}

/* ─── send ─── */

int mxfs_net2_send(struct mxfs_net2_ctx *ctx, const struct mxfs_net2_id *dst,
                   enum net2_priority pri, bool reliable, uint32_t msg_id,
                   const void *buf, uint32_t len)
{
	return net2_midcomms_send(ctx, dst, pri, reliable, msg_id, buf, len);
}

/* ─── evidence surface (harness + step-6 stats registration) ─── */

void mxfs_net2_get_stats(struct mxfs_net2_ctx *ctx,
                         struct mxfs_net2_stats *out)
{
	int i, c;

	if (!ctx || !out)
		return;
	mxfs_pal_mutex_lock(ctx->stats_lock);
	*out = ctx->stats;
	mxfs_pal_mutex_unlock(ctx->stats_lock);
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		struct net2_link *link = &ctx->links[i];

		mxfs_pal_mutex_lock(link->lock);
		for (c = 0; c < NET2_PRI_COUNT; c++) {
			out->cls[c].enqueued += link->cls[c].enqueued;
			out->cls[c].first_tx += link->cls[c].first_tx;
			out->cls[c].retx += link->cls[c].retx;
			out->cls[c].queue_full += link->cls[c].queue_full;
			if (link->cls[c].max_residency_ms >
			    out->cls[c].max_residency_ms)
				out->cls[c].max_residency_ms =
					link->cls[c].max_residency_ms;
		}
		mxfs_pal_mutex_unlock(link->lock);
	}
}

int mxfs_net2_get_session_stats(struct mxfs_net2_ctx *ctx, uint16_t slot,
                                struct mxfs_net2_session_stats *out)
{
	struct net2_session *sess;

	if (!ctx || !out || slot >= MXFS_MAX_NODES)
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->lock);
	sess = ctx->sessions[slot];
	if (!sess) {
		mxfs_pal_mutex_unlock(ctx->lock);
		return -ENOENT;
	}
	mxfs_pal_mutex_lock(sess->lock);
	*out = sess->stats;
	mxfs_pal_mutex_unlock(sess->lock);
	mxfs_pal_mutex_unlock(ctx->lock);
	return 0;
}

/* ─── fault control (harness API; kernel modparams arrive at their
 *     wiring step with the same rule syntax) ─── */

int mxfs_net2_fault_rule_set(struct mxfs_net2_ctx *ctx, int idx,
                             const struct mxfs_net2_fault_rule *rule)
{
	int rc;

	if (!ctx)
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->fault_lock);
	rc = mxfs_net2_fault_set(&ctx->fault, idx, rule);
	mxfs_pal_mutex_unlock(ctx->fault_lock);
	return rc;
}

void mxfs_net2_fault_reset(struct mxfs_net2_ctx *ctx, uint64_t seed)
{
	if (!ctx)
		return;
	mxfs_pal_mutex_lock(ctx->fault_lock);
	mxfs_net2_fault_init(&ctx->fault, seed ? seed : 1);
	mxfs_pal_mutex_unlock(ctx->fault_lock);
}

/* ─── test/ops surface: force a link reset (session must survive) ─── */

int mxfs_net2_link_reset(struct mxfs_net2_ctx *ctx, uint16_t slot)
{
	if (!ctx || slot >= MXFS_MAX_NODES || slot == ctx->cfg.self_slot)
		return -EINVAL;
	net2_link_down(ctx, &ctx->links[slot]);
	return 0;
}

/* ═══ Gate-2 kernel smoke: modparam-gated 2-node echo selftest ═══
 *
 * On both nodes (slots swapped):
 *   insmod mxfs.ko net2_selftest=1 net2_selftest_slot=0 \
 *          net2_selftest_peer=<other-ip> net2_selftest_peer_slot=1
 * Creates a standalone net2 ctx (no mount, no seam), sends
 * net2_selftest_msgs reliable PINGs; PONG replies are sent from
 * recv-cb context — the same shape the step-7 seam dispatch uses.
 * PASS = peer's pings all delivered, all our pings answered, and every
 * tx entry (pings + pongs) ACKed.  Exactly one dmesg marker line:
 *   mxfs: net2_selftest: PASS|FAIL ...
 * Fault injection stays off.  The thread is joined at module exit;
 * rmmod mid-run aborts promptly via the stop latch.  The cap on msgs
 * keeps ping+pong tx entries ≤ 48 < tx ring 64, so the recv cb never
 * sees window backpressure (the cb must not block/retry: it runs on
 * the link recv thread, which also processes incoming ACKs).
 */
#ifdef __KERNEL__

static int net2_selftest;
module_param(net2_selftest, int, 0444);
MODULE_PARM_DESC(net2_selftest,
                 "Run NET2 2-node echo selftest at load (gate-2 smoke)");
static int net2_selftest_slot;
module_param(net2_selftest_slot, int, 0444);
MODULE_PARM_DESC(net2_selftest_slot, "NET2 selftest: own slot (0..63)");
static char *net2_selftest_peer = "";
module_param(net2_selftest_peer, charp, 0444);
MODULE_PARM_DESC(net2_selftest_peer, "NET2 selftest: peer IPv4 address");
static int net2_selftest_peer_slot = -1;
module_param(net2_selftest_peer_slot, int, 0444);
MODULE_PARM_DESC(net2_selftest_peer_slot, "NET2 selftest: peer slot (0..63)");
static int net2_selftest_msgs = 16;
module_param(net2_selftest_msgs, int, 0444);
MODULE_PARM_DESC(net2_selftest_msgs, "NET2 selftest: pings each way (1..24)");
static int net2_selftest_port_base;
module_param(net2_selftest_port_base, int, 0444);
MODULE_PARM_DESC(net2_selftest_port_base,
                 "NET2 selftest: listen port base (0 = registry 7610)");

#define NET2_ST_MAGIC     0x4e325354u   /* "N2ST" */
#define NET2_ST_KIND_PING 1u
#define NET2_ST_KIND_PONG 2u
#define NET2_ST_MSGS_MAX  24
#define NET2_ST_WAIT_MS   60000         /* covers insmod stagger across nodes */
#define NET2_ST_LINGER_MS 3000          /* post-pass grace for peer tail ACKs */

struct net2_selftest_st {
	struct mxfs_net2_ctx *ctx;
	mxfs_mutex_t *lock;
	uint32_t pings_rcvd;
	uint32_t pongs_rcvd;
	uint32_t send_fail;
};
static struct net2_selftest_st net2_st;
static mxfs_thread_t *net2_selftest_thread;
static volatile bool net2_selftest_abort_latch;   /* peer.c stop-latch idiom */

static void net2_selftest_pack(uint8_t buf[12], uint32_t kind, uint32_t seq)
{
	uint32_t le;

	le = mxfs_cpu_to_le32(NET2_ST_MAGIC);
	memcpy(buf, &le, 4);
	le = mxfs_cpu_to_le32(kind);
	memcpy(buf + 4, &le, 4);
	le = mxfs_cpu_to_le32(seq);
	memcpy(buf + 8, &le, 4);
}

static int net2_selftest_unpack(const void *payload, uint32_t len,
                                uint32_t *kind, uint32_t *seq)
{
	const uint8_t *buf = payload;
	uint32_t le;

	if (len != 12)
		return -EINVAL;
	memcpy(&le, buf, 4);
	if (mxfs_le32_to_cpu(le) != NET2_ST_MAGIC)
		return -EINVAL;
	memcpy(&le, buf + 4, 4);
	*kind = mxfs_le32_to_cpu(le);
	memcpy(&le, buf + 8, 4);
	*seq = mxfs_le32_to_cpu(le);
	return 0;
}

static void net2_selftest_recv_cb(void *data, const struct mxfs_net2_id *src,
                                  const void *payload, uint32_t len)
{
	struct net2_selftest_st *st = data;
	uint32_t kind, seq;

	if (net2_selftest_unpack(payload, len, &kind, &seq)) {
		mxfs_pal_log(MXFS_LOG_WARN,
		             "net2_selftest: unexpected payload len %u", len);
		return;
	}
	if (kind == NET2_ST_KIND_PING) {
		uint8_t buf[12];
		int rc;

		mxfs_pal_mutex_lock(st->lock);
		st->pings_rcvd++;
		mxfs_pal_mutex_unlock(st->lock);
		net2_selftest_pack(buf, NET2_ST_KIND_PONG, seq);
		rc = mxfs_net2_send(st->ctx, src, NET2_PRI_GRANT, true,
		                    0x40000000u + seq, buf, sizeof(buf));
		if (rc) {
			mxfs_pal_mutex_lock(st->lock);
			st->send_fail++;
			mxfs_pal_mutex_unlock(st->lock);
			mxfs_pal_log(MXFS_LOG_WARN,
			             "net2_selftest: pong %u send rc=%d",
			             seq, rc);
		}
	} else if (kind == NET2_ST_KIND_PONG) {
		mxfs_pal_mutex_lock(st->lock);
		st->pongs_rcvd++;
		mxfs_pal_mutex_unlock(st->lock);
	}
}

static void net2_selftest_fn(void *arg)
{
	static const uint8_t st_uuid[16] = {
		'N', '2', 'S', 'T', '-', 'k', 's', 'm',
		'o', 'k', 'e', '-', 'v', '0', '0', '1'
	};
	struct net2_selftest_st *st = &net2_st;
	struct mxfs_net2_cfg cfg;
	struct mxfs_net2_id peer;
	struct mxfs_net2_session_stats ss;
	uint16_t self_slot = (uint16_t)net2_selftest_slot;
	uint16_t peer_slot = (uint16_t)net2_selftest_peer_slot;
	uint32_t nmsgs = (uint32_t)net2_selftest_msgs;
	uint32_t pi = 0, po = 0, sf = 0, seq;
	uint64_t t0;
	bool ok = false;
	int rc;

	(void)arg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.node_id = (mxfs_node_id_t)self_slot + 1;
	memcpy(cfg.uuid, st_uuid, sizeof(cfg.uuid));
	cfg.uuid_hash = NET2_ST_MAGIC;
	cfg.volume_id = 1;
	cfg.fs_gen = 1;
	cfg.self_slot = self_slot;
	cfg.self_incarnation = 1;
	mxfs_pal_get_random_bytes(&cfg.boot_nonce, sizeof(cfg.boot_nonce));
	cfg.base_port = net2_selftest_port_base ?
	                (uint16_t)net2_selftest_port_base :
	                (uint16_t)MXFS_PORT_NET2_LINK_BASE;
	cfg.membership_port = MXFS_PORT_NET2_MEMBERSHIP;
	cfg.topology = MXFS_NET2_TOPO_MESH;
	cfg.tun = (struct mxfs_net2_tunables)MXFS_NET2_TUNABLES_DEFAULT;

	memset(&ss, 0, sizeof(ss));
	st->pings_rcvd = 0;
	st->pongs_rcvd = 0;
	st->send_fail = 0;
	st->lock = mxfs_pal_mutex_create();
	if (!st->lock) {
		mxfs_pal_log(MXFS_LOG_ERR, "net2_selftest: FAIL (no mutex)");
		return;
	}
	rc = mxfs_net2_create(&cfg, &st->ctx);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2_selftest: FAIL (create rc=%d)", rc);
		goto out_mutex;
	}
	peer.membership_epoch = 1;
	peer.cluster_uuid_hash = cfg.uuid_hash;
	peer.incarnation = 1;      /* both sides load with incarnation 1 */
	peer.slot = peer_slot;
	mxfs_net2_register_recv_cb(st->ctx, net2_selftest_recv_cb, st);
	rc = mxfs_net2_set_peer_addr(st->ctx, peer_slot,
	                             net2_selftest_peer, 0);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2_selftest: FAIL (peer_addr rc=%d)", rc);
		goto out_ctx;
	}
	mxfs_net2_update_view(st->ctx,
	                      (1ULL << self_slot) | (1ULL << peer_slot), 1);
	rc = mxfs_net2_start(st->ctx);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2_selftest: FAIL (start rc=%d)", rc);
		goto out_ctx;
	}

	/* Reliable sends buffer in the ring pre-handshake (EMBRYONIC)
	 * and flush when the peer comes up — insmod order is free. */
	for (seq = 1; seq <= nmsgs && !net2_selftest_abort_latch; seq++) {
		uint8_t buf[12];

		net2_selftest_pack(buf, NET2_ST_KIND_PING, seq);
		rc = mxfs_net2_send(st->ctx, &peer, NET2_PRI_GRANT, true,
		                    seq, buf, sizeof(buf));
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
			             "net2_selftest: ping %u send rc=%d",
			             seq, rc);
			break;
		}
	}

	t0 = mxfs_pal_time_ms();
	while (!net2_selftest_abort_latch &&
	       mxfs_pal_time_ms() - t0 < NET2_ST_WAIT_MS) {
		mxfs_pal_mutex_lock(st->lock);
		pi = st->pings_rcvd;
		po = st->pongs_rcvd;
		sf = st->send_fail;
		mxfs_pal_mutex_unlock(st->lock);
		if (pi >= nmsgs && po >= nmsgs && sf == 0 &&
		    mxfs_net2_get_session_stats(st->ctx, peer_slot,
		                                &ss) == 0 &&
		    ss.acked >= (uint64_t)2 * nmsgs) {
			ok = true;
			break;
		}
		mxfs_pal_sleep_ms(100);
	}
	if (!ok)
		(void)mxfs_net2_get_session_stats(st->ctx, peer_slot, &ss);

	mxfs_pal_log(ok ? MXFS_LOG_INFO : MXFS_LOG_ERR,
	             "net2_selftest: %s slot=%u peer_slot=%u msgs=%u "
	             "pings_rcvd=%u pongs_rcvd=%u send_fail=%u "
	             "created=%llu acked=%llu retx=%llu resumes=%llu "
	             "wall_ms=%llu",
	             ok ? "PASS" : "FAIL", self_slot, peer_slot, nmsgs,
	             pi, po, sf,
	             (unsigned long long)ss.msgs_created,
	             (unsigned long long)ss.acked,
	             (unsigned long long)ss.retx,
	             (unsigned long long)ss.resumes,
	             (unsigned long long)(mxfs_pal_time_ms() - t0));

	/* Linger before teardown: the PEER needs this ctx alive to get
	 * its tail ACKs (first 2-node run proved it: the early finisher
	 * closed within ms of its own pass and the other side's last 6
	 * entries could never be acked — COMM_AMBIGUOUS as designed).
	 * Teardown grace only, not protocol; abort latch keeps rmmod
	 * prompt. */
	if (ok) {
		for (seq = 0; seq < NET2_ST_LINGER_MS / 100 &&
		              !net2_selftest_abort_latch; seq++)
			mxfs_pal_sleep_ms(100);
	}

out_ctx:
	mxfs_net2_stop(st->ctx);
	mxfs_net2_destroy(st->ctx);
	st->ctx = NULL;
out_mutex:
	mxfs_pal_mutex_destroy(st->lock);
	st->lock = NULL;
}

void mxfs_net2_selftest_maybe_start(void)
{
	if (!net2_selftest)
		return;
	if (net2_selftest_slot < 0 || net2_selftest_slot >= MXFS_MAX_NODES ||
	    net2_selftest_peer_slot < 0 ||
	    net2_selftest_peer_slot >= MXFS_MAX_NODES ||
	    net2_selftest_peer_slot == net2_selftest_slot ||
	    !net2_selftest_peer || !net2_selftest_peer[0]) {
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2_selftest: FAIL (bad params slot=%d "
		             "peer_slot=%d peer='%s')",
		             net2_selftest_slot, net2_selftest_peer_slot,
		             net2_selftest_peer ? net2_selftest_peer : "");
		return;
	}
	if (net2_selftest_msgs < 1)
		net2_selftest_msgs = 1;
	if (net2_selftest_msgs > NET2_ST_MSGS_MAX) {
		mxfs_pal_log(MXFS_LOG_WARN,
		             "net2_selftest: msgs clamped %d -> %d "
		             "(ping+pong must fit the tx ring)",
		             net2_selftest_msgs, NET2_ST_MSGS_MAX);
		net2_selftest_msgs = NET2_ST_MSGS_MAX;
	}
	net2_selftest_abort_latch = false;
	net2_selftest_thread = mxfs_pal_thread_create(net2_selftest_fn, NULL);
	if (!net2_selftest_thread)
		mxfs_pal_log(MXFS_LOG_ERR,
		             "net2_selftest: FAIL (thread create)");
}

void mxfs_net2_selftest_stop(void)
{
	if (!net2_selftest_thread)
		return;
	net2_selftest_abort_latch = true;
	mxfs_pal_thread_join(net2_selftest_thread);
	net2_selftest_thread = NULL;
}

#endif /* __KERNEL__ */
