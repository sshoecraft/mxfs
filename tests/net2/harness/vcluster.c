/*
 * MXFS — NET2 user-mode protocol harness: in-process virtual cluster.
 *
 * N real mxfs_net2_ctx instances over localhost TCP (see harness.h).
 * Deterministic identity: uuid, nonces and incarnations derive from the
 * scenario seed; the per-ctx fault PRNG is seeded from the node nonce.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "harness.h"
#include "dlm/net2_wire.h"
#include "include/mxfs/mxfs_dlm.h"

/* Distinct port range per vc_create so back-to-back scenarios never
 * collide on lingering sockets (SO_REUSEADDR covers TIME_WAIT).
 * Stride 16 (VC_MAX_NODES=8 ports used + 8 spare): every listener in a
 * full suite stays far BELOW the ephemeral range (32768+), where a
 * transient outbound source port can own the address and fail the bind
 * with EADDRINUSE — proven cause of a rare last-cluster env-start
 * failure at the old 256 stride (42 clusters reached port 33496). */
static uint16_t vc_next_base = 23000;

struct vc_inner {
	struct mxfs_dlm_msg_hdr hdr;
	uint32_t tag;
	uint32_t pad;
};

static uint32_t vc_fnv1a(const uint8_t *p, size_t len)
{
	uint32_t h = 2166136261u;

	while (len--) {
		h ^= *p++;
		h *= 16777619u;
	}
	return h;
}

static uint64_t vc_mix(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xFF51AFD7ED558CCDULL;
	x ^= x >> 33;
	x *= 0xC4CEB9FE1A85EC53ULL;
	x ^= x >> 33;
	return x ? x : 1;
}

static uint64_t vc_node_nonce(const struct vcluster *vc, int slot,
                              uint32_t inc)
{
	return vc_mix(vc->seed ^ ((uint64_t)slot << 32) ^ inc);
}

static uint32_t vc_div(uint32_t v, uint32_t d)
{
	uint32_t r = v / d;

	return r ? r : 1;
}

static void vc_recv_cb(void *data, const struct mxfs_net2_id *src,
                       const void *payload, uint32_t len)
{
	struct vc_node *node = data;
	struct vc_rec rec;

	memset(&rec, 0, sizeof(rec));
	rec.src_slot = src->slot;
	rec.src_inc = src->incarnation;
	rec.len = len;
	if (len >= sizeof(struct mxfs_dlm_msg_hdr))
		rec.type = ((const struct mxfs_dlm_msg_hdr *)payload)->type;
	if (len >= sizeof(struct vc_inner))
		rec.tag = ((const struct vc_inner *)payload)->tag;

	mxfs_pal_mutex_lock(node->log_lock);
	if (node->log_n < VC_LOG_CAP)
		node->log[node->log_n++] = rec;
	else
		node->log_overflow++;
	mxfs_pal_mutex_unlock(node->log_lock);
}

static void vc_ambiguous_cb(void *data, uint16_t peer_slot,
                            uint32_t peer_inc, uint64_t age_ms)
{
	struct vc_node *node = data;

	(void)peer_slot;
	(void)peer_inc;
	(void)age_ms;
	mxfs_pal_mutex_lock(node->log_lock);
	node->ambiguous_hits++;
	mxfs_pal_mutex_unlock(node->log_lock);
}

int vc_node_start(struct vcluster *vc, int i)
{
	struct vc_node *node = &vc->nodes[i];
	struct mxfs_net2_cfg cfg;
	int j, rc;

	if (node->up)
		return -EBUSY;

	memset(&cfg, 0, sizeof(cfg));
	cfg.node_id = (mxfs_node_id_t)(i + 1);
	memcpy(cfg.uuid, vc->uuid, 16);
	cfg.uuid_hash = vc->uuid_hash;
	cfg.volume_id = 0x564F4C31;
	cfg.fs_gen = 7;
	cfg.self_slot = node->slot;
	cfg.self_incarnation = node->inc;
	cfg.boot_nonce = node->nonce;
	cfg.base_port = vc->base_port;
	cfg.membership_port = 0;
	cfg.topology = MXFS_NET2_TOPO_MESH;
	cfg.features = MXFS_NET2_FEAT_MEMBFENCE;
	cfg.tun = vc->tun;

	node->log_n = 0;
	node->log_overflow = 0;
	node->ambiguous_hits = 0;
	memset(node->unrel_sent, 0, sizeof(node->unrel_sent));

	rc = mxfs_net2_create(&cfg, &node->ctx);
	if (rc)
		return rc;
	mxfs_net2_register_recv_cb(node->ctx, vc_recv_cb, node);
	mxfs_net2_set_ambiguous_cb(node->ctx, vc_ambiguous_cb, node);
	for (j = 0; j < vc->n; j++)
		if (j != i)
			mxfs_net2_set_peer_addr(node->ctx,
			                        vc->nodes[j].slot,
			                        "127.0.0.1", 0);
	rc = mxfs_net2_start(node->ctx);
	if (rc) {
		mxfs_net2_destroy(node->ctx);
		node->ctx = NULL;
		return rc;
	}
	node->up = 1;
	return 0;
}

int vc_create(struct vcluster **vc_out, int n, uint64_t seed,
              uint32_t compress, uint16_t tx_win_override)
{
	static const struct mxfs_net2_tunables defs =
		MXFS_NET2_TUNABLES_DEFAULT;
	struct vcluster *vc;
	uint64_t mask = 0;
	int i, rc;

	if (n < 1 || n > VC_MAX_NODES)
		return -EINVAL;
	vc = mxfs_pal_alloc(sizeof(*vc));
	if (!vc)
		return -ENOMEM;
	memset(vc, 0, sizeof(*vc));
	vc->n = n;
	vc->seed = seed ? seed : 1;
	vc->compress = compress ? compress : 1;
	vc->base_port = vc_next_base;
	vc_next_base = (uint16_t)(vc_next_base + 16);
	if (vc_next_base >= 32000)
		vc_next_base = 23000;
	vc->epoch = 1;

	for (i = 0; i < 16; i++)
		vc->uuid[i] = (uint8_t)(vc_mix(vc->seed + i) & 0xff);
	vc->uuid_hash = vc_fnv1a(vc->uuid, 16);

	vc->tun = defs;
	if (vc->compress > 1) {
		vc->tun.rto_initial_ms = vc_div(defs.rto_initial_ms,
		                                vc->compress);
		vc->tun.rto_max_ms = vc_div(defs.rto_max_ms, vc->compress);
		vc->tun.rt_tick_ms = vc_div(defs.rt_tick_ms, vc->compress);
		vc->tun.delayed_ack_ms = vc_div(defs.delayed_ack_ms,
		                                vc->compress);
		vc->tun.ambiguity_ms = vc_div(defs.ambiguity_ms,
		                              vc->compress);
		vc->tun.suspect_grace_ms = vc_div(defs.suspect_grace_ms,
		                                  vc->compress);
		vc->tun.mepoch_lease_ms = vc_div(defs.mepoch_lease_ms,
		                                 vc->compress);
	}
	if (tx_win_override) {
		vc->tx_win_override = tx_win_override;
		vc->tun.tx_win = tx_win_override;
	}

	for (i = 0; i < n; i++) {
		struct vc_node *node = &vc->nodes[i];

		node->vc = vc;
		node->slot = (uint16_t)i;
		node->inc = 1;
		node->nonce = vc_node_nonce(vc, i, node->inc);
		node->log_lock = mxfs_pal_mutex_create();
		node->log = mxfs_pal_alloc(VC_LOG_CAP *
		                           sizeof(struct vc_rec));
		if (!node->log_lock || !node->log) {
			vc_destroy(vc);
			return -ENOMEM;
		}
		mask |= 1ULL << i;
	}
	for (i = 0; i < n; i++) {
		rc = vc_node_start(vc, i);
		if (rc) {
			fprintf(stderr, "  vc: node %d start failed: %d\n",
			        i, rc);
			vc_destroy(vc);
			return rc;
		}
	}
	vc_view_all(vc, mask, vc->epoch);
	*vc_out = vc;
	return 0;
}

void vc_node_kill(struct vcluster *vc, int i)
{
	struct vc_node *node = &vc->nodes[i];

	if (!node->up)
		return;
	mxfs_net2_destroy(node->ctx);
	node->ctx = NULL;
	node->up = 0;
}

int vc_node_restart(struct vcluster *vc, int i)
{
	struct vc_node *node = &vc->nodes[i];
	int rc;
	uint64_t mask = 0;
	int j;

	vc_node_kill(vc, i);
	node->inc++;                      /* §5: persisted bump per mount */
	node->nonce = vc_node_nonce(vc, i, node->inc);
	rc = vc_node_start(vc, i);
	if (rc)
		return rc;
	for (j = 0; j < vc->n; j++)
		if (vc->nodes[j].up)
			mask |= 1ULL << j;
	vc_view_node(vc, i, mask, vc->epoch);
	return 0;
}

void vc_view_node(struct vcluster *vc, int i, uint64_t mask, uint64_t epoch)
{
	if (vc->nodes[i].up)
		mxfs_net2_update_view(vc->nodes[i].ctx, mask, epoch);
}

void vc_view_all(struct vcluster *vc, uint64_t mask, uint64_t epoch)
{
	int i;

	vc->epoch = epoch;
	for (i = 0; i < vc->n; i++)
		vc_view_node(vc, i, mask, epoch);
}

void vc_destroy(struct vcluster *vc)
{
	int i;

	if (!vc)
		return;
	for (i = 0; i < vc->n; i++) {
		vc_node_kill(vc, i);
		if (vc->nodes[i].log)
			mxfs_pal_free(vc->nodes[i].log);
		if (vc->nodes[i].log_lock)
			mxfs_pal_mutex_destroy(vc->nodes[i].log_lock);
	}
	mxfs_pal_free(vc);
}

int vc_send_inc(struct vcluster *vc, int from, int to, uint32_t inc,
                uint16_t type, uint32_t tag, int reliable, uint32_t msg_id)
{
	struct vc_node *src = &vc->nodes[from];
	struct mxfs_net2_id dst;
	struct vc_inner msg;
	int rc;

	if (!src->up)
		return -ESHUTDOWN;
	memset(&dst, 0, sizeof(dst));
	dst.membership_epoch = vc->epoch;
	dst.cluster_uuid_hash = vc->uuid_hash;
	dst.incarnation = inc;
	dst.slot = vc->nodes[to].slot;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = type;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = (mxfs_node_id_t)(from + 1);
	msg.hdr.target = (mxfs_node_id_t)(to + 1);
	msg.tag = reliable ? tag : (tag | VC_TAG_UNREL);

	rc = mxfs_net2_send(src->ctx, &dst, net2_pri_for_type(type),
	                    reliable != 0, msg_id, &msg, sizeof(msg));
	if (rc == 0 && !reliable)
		src->unrel_sent[to]++;
	return rc;
}

int vc_send(struct vcluster *vc, int from, int to, uint16_t type,
            uint32_t tag, int reliable, uint32_t msg_id)
{
	return vc_send_inc(vc, from, to, vc->nodes[to].inc, type, tag,
	                   reliable, msg_id);
}

int vc_count(struct vcluster *vc, int node, int from_slot, uint16_t type,
             uint32_t tag)
{
	struct vc_node *n = &vc->nodes[node];
	int i, cnt = 0;

	mxfs_pal_mutex_lock(n->log_lock);
	for (i = 0; i < n->log_n; i++) {
		const struct vc_rec *r = &n->log[i];

		if (from_slot >= 0 && r->src_slot != (uint16_t)from_slot)
			continue;
		if (type != 0 && r->type != type)
			continue;
		if (tag != UINT32_MAX && r->tag != tag)
			continue;
		cnt++;
	}
	mxfs_pal_mutex_unlock(n->log_lock);
	return cnt;
}

int vc_wait_count(struct vcluster *vc, int node, int from_slot,
                  uint16_t type, uint32_t tag, int want, int timeout_ms)
{
	uint64_t deadline = mxfs_pal_time_ms() + (uint64_t)timeout_ms;
	int cnt;

	for (;;) {
		cnt = vc_count(vc, node, from_slot, type, tag);
		if (cnt >= want)
			return cnt;
		if (mxfs_pal_time_ms() >= deadline)
			return cnt;
		mxfs_pal_sleep_ms(2);
	}
}

int vc_unique_from(struct vcluster *vc, int node, int from_slot, int *dups)
{
	struct vc_node *n = &vc->nodes[node];
	uint8_t *seen;
	int i, uniq = 0, d = 0;

	seen = mxfs_pal_alloc(VC_TAG_MAX);
	if (!seen)
		return -ENOMEM;
	memset(seen, 0, VC_TAG_MAX);

	mxfs_pal_mutex_lock(n->log_lock);
	for (i = 0; i < n->log_n; i++) {
		const struct vc_rec *r = &n->log[i];

		if (from_slot >= 0 && (r->src_slot != (uint16_t)from_slot ||
		    /* count only the sender's CURRENT incarnation — a
		     * restarted sender's counters restart with it */
		    r->src_inc != vc->nodes[from_slot].inc))
			continue;
		if (r->tag & VC_TAG_UNREL)
			continue;
		if (r->tag >= VC_TAG_MAX)
			continue;
		if (seen[r->tag] == 0)
			uniq++;
		else if (seen[r->tag] == 1)
			d++;
		if (seen[r->tag] < 255)
			seen[r->tag]++;
	}
	mxfs_pal_mutex_unlock(n->log_lock);
	mxfs_pal_free(seen);
	if (dups)
		*dups = d;
	return uniq;
}

int vc_quiesce(struct vcluster *vc, int timeout_ms)
{
	uint64_t deadline = mxfs_pal_time_ms() + (uint64_t)timeout_ms;

	for (;;) {
		int i, j, pending = 0;

		for (i = 0; i < vc->n; i++) {
			if (!vc->nodes[i].up)
				continue;
			for (j = 0; j < vc->n; j++) {
				struct mxfs_net2_session_stats st;

				if (j == i)
					continue;
				if (mxfs_net2_get_session_stats(
					    vc->nodes[i].ctx,
					    vc->nodes[j].slot, &st))
					continue;
				if (st.msgs_created != st.acked + st.aborts)
					pending++;
			}
		}
		if (!pending)
			return 1;
		if (mxfs_pal_time_ms() >= deadline)
			return 0;
		mxfs_pal_sleep_ms(5);
	}
}

void vc_dump_stats(struct vcluster *vc)
{
	int i, j;

	for (i = 0; i < vc->n; i++) {
		struct mxfs_net2_stats st;

		if (!vc->nodes[i].up)
			continue;
		mxfs_net2_get_stats(vc->nodes[i].ctx, &st);
		printf("  node%d(slot %u inc %u): log=%d amb=%llu "
		       "sess=%llu/%llu malformed=%llu xcluster=%llu "
		       "commamb=%llu\n",
		       i, vc->nodes[i].slot, vc->nodes[i].inc,
		       vc->nodes[i].log_n,
		       (unsigned long long)vc->nodes[i].ambiguous_hits,
		       (unsigned long long)st.sessions_created,
		       (unsigned long long)st.sessions_gcd,
		       (unsigned long long)st.malformed_frames,
		       (unsigned long long)st.cross_cluster_rejects,
		       (unsigned long long)st.comm_ambiguous_events);
		for (j = 0; j < vc->n; j++) {
			struct mxfs_net2_session_stats ss;

			if (j == i || !vc->nodes[i].up)
				continue;
			if (mxfs_net2_get_session_stats(vc->nodes[i].ctx,
			                                vc->nodes[j].slot,
			                                &ss))
				continue;
			printf("    ->slot%u: created=%llu ftx=%llu "
			       "retx=%llu acked=%llu aborts=%llu dup=%llu "
			       "oow=%llu staleinc=%llu staleep=%llu "
			       "resets=%llu resumes=%llu\n",
			       vc->nodes[j].slot,
			       (unsigned long long)ss.msgs_created,
			       (unsigned long long)ss.first_tx,
			       (unsigned long long)ss.retx,
			       (unsigned long long)ss.acked,
			       (unsigned long long)ss.aborts,
			       (unsigned long long)ss.dup_seq_suppressed,
			       (unsigned long long)ss.out_of_window_drops,
			       (unsigned long long)ss.stale_incarnation_drops,
			       (unsigned long long)ss.stale_epoch_drops,
			       (unsigned long long)ss.resets,
			       (unsigned long long)ss.resumes);
		}
	}
}

int vc_assert_invariants(struct scenario_ctx *sc, struct vcluster *vc,
                         unsigned flags)
{
	int i, j;
	int before = sc->failed;

	for (i = 0; i < vc->n; i++) {
		if (!vc->nodes[i].up)
			continue;

		ck(sc, vc->nodes[i].log_overflow == 0,
		   "harness log never overflows");

		for (j = 0; j < vc->n; j++) {
			struct mxfs_net2_session_stats st;
			char what[128];
			int uniq, dups = 0;

			if (j == i || !vc->nodes[j].up)
				continue;
			if (mxfs_net2_get_session_stats(vc->nodes[i].ctx,
			                                vc->nodes[j].slot,
			                                &st))
				continue;

			/* delivered_effects <= unique_operation_ids */
			uniq = vc_unique_from(vc, j, vc->nodes[i].slot,
			                      &dups);
			snprintf(what, sizeof(what),
			         "delivered(%d<-%d)=%d <= created=%llu",
			         j, i, uniq,
			         (unsigned long long)st.msgs_created);
			ck(sc, uniq >= 0 &&
			       (uint64_t)uniq <= st.msgs_created, what);

			/* dedup: no reliable tag delivered twice */
			if (!(flags & VC_INV_ALLOW_DUPTAGS)) {
				snprintf(what, sizeof(what),
				         "no duplicate deliveries "
				         "(%d<-%d dups=%d)", j, i, dups);
				ck(sc, dups == 0, what);
			}

			/* every retired entry has ACK or abort disposition
			 * (quiesced callers only: created fully retired) */
			snprintf(what, sizeof(what),
			         "retire disposition (%d->%d) "
			         "created=%llu acked=%llu aborts=%llu",
			         i, j,
			         (unsigned long long)st.msgs_created,
			         (unsigned long long)st.acked,
			         (unsigned long long)st.aborts);
			ck(sc, st.acked + st.aborts <= st.msgs_created,
			   what);
		}

		if (!(flags & VC_INV_ALLOW_QFULL)) {
			struct mxfs_net2_stats st;
			char what[96];

			mxfs_net2_get_stats(vc->nodes[i].ctx, &st);
			snprintf(what, sizeof(what),
			         "no coherence queue_full on node %d", i);
			ck(sc, st.cls[NET2_PRI_FENCE].queue_full == 0 &&
			       st.cls[NET2_PRI_RELEASE].queue_full == 0 &&
			       st.cls[NET2_PRI_REVOKE].queue_full == 0,
			   what);
		}
	}
	return sc->failed - before;
}
