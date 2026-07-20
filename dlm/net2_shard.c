/*
 * MXFS — Multinode XFS
 * NET2 lock plane — shard replication machinery (§7.B, §11 step 4)
 *
 * This file owns: lockspace lifecycle + dispatch, the HRW config
 * derivation, the bounded replicated log (append / ack / in-order
 * commit / truncation / backfill), election, state transfer
 * (snapshot), reconfiguration on epoch commit, and the closed-set
 * recovery barrier.  Lock-record SEMANTICS (validate / apply / emit /
 * follow-on grants / client side) live in net2_lock.c.
 *
 * Consensus shape (2-of-quorum over an epoch-derived replica set):
 *  - only the leader appends; entries commit IN ORDER once
 *    quorum-acked; the table mutates only at commit-apply, so every
 *    replica applies the same entries in the same order.
 *  - commit watermark rides APPEND frames (lazy on idle replicas —
 *    safe: election completeness compares (term, commit_seq,
 *    last_seq) and the winner re-commits its suffix via the TERM
 *    barrier, so acked-but-unpublished commits survive).
 *  - a replica NACKs out-of-chain appends with its last_seq; the
 *    leader backfills from the ring or, past the window, snapshots
 *    (the lagging replica is ineligible until the CAUGHT_UP entry).
 *  - divergent uncommitted suffixes (a partitioned old leader
 *    rejoining) are truncated by a higher-term append at that seq.
 *  - elections start ONLY on a membership SUSPECT signal or an epoch
 *    change — never on a mere link drop (§7.B).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_shard.h"
#include "net2_lock.h"
#include "net2_ctx.h"     /* engine-internal: cluster uuid for shard ids */

/* temporary gate-4 bring-up tracing (user build only; removed after) */
#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
static int n2dbg(void)
{
	static int on = -1;

	if (on < 0)
		on = getenv("N2_DEBUG") != NULL;
	return on;
}
#define N2DBG(fmt, ...) do { if (n2dbg()) fprintf(stderr, \
	"N2DBG " fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define N2DBG(fmt, ...) do { } while (0)
#endif

/* ─── small utilities ─── */

void net2_ls_stat_bump(struct net2_lockspace *ls, uint64_t *field)
{
	mxfs_pal_mutex_lock(ls->stats_lock);
	(*field)++;
	mxfs_pal_mutex_unlock(ls->stats_lock);
}

void net2_ls_stat_max(struct net2_lockspace *ls, uint64_t *field, uint64_t v)
{
	mxfs_pal_mutex_lock(ls->stats_lock);
	if (v > *field)
		*field = v;
	mxfs_pal_mutex_unlock(ls->stats_lock);
}

bool net2_ls_hook(struct net2_lockspace *ls, enum n2_hook_point p,
                  uint32_t shard_id, uint16_t detail)
{
	if (ls->hook && ls->hook(ls->hook_data, p, shard_id, detail)) {
		ls->poisoned = true;
		mxfs_pal_log(MXFS_LOG_INFO,
		             "net2_ls: slot %u POISONED at hook %d shard %u",
		             ls->self_slot, (int)p, shard_id);
		return true;
	}
	return false;
}

static uint64_t ls_prng(struct net2_lockspace *ls)
{
	/* xorshift64*, seeded deterministically per cfg. */
	uint64_t x = ls->prng ? ls->prng : (ls->seed | 1);

	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	ls->prng = x;
	return x * 0x2545F4914F6CDD1DULL;
}

static uint64_t fnv1a64(uint64_t h, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 0x100000001B3ULL;
	}
	return h;
}

uint32_t net2_shard_id_for(const struct net2_lockspace *ls,
                           const struct mxfs_resource_id *res)
{
	uint64_t h = 0xCBF29CE484222325ULL;

	h = fnv1a64(h, ls->net->cfg.uuid, sizeof(ls->net->cfg.uuid));
	h = fnv1a64(h, res, sizeof(*res));
	return (uint32_t)(h & (N2_SHARD_COUNT - 1));
}

/* ─── HRW replica-set derivation ─── */

struct hrw_ent { uint64_t score; uint16_t slot; uint32_t inc; };

static int hrw_cmp(const void *a, const void *b)
{
	const struct hrw_ent *x = a, *y = b;

	if (x->score != y->score)
		return (x->score > y->score) ? -1 : 1;   /* descending */
	return (x->slot < y->slot) ? -1 : 1;
}

/* Compute R_E(s) into out[]; returns count (min(3, |members|)). */
static int hrw_top(uint64_t epoch, uint32_t shard_id, uint64_t member_mask,
                   const uint32_t *member_incs, struct n2_replica *out)
{
	struct hrw_ent ents[MXFS_MAX_NODES];
	int n = 0, i, want;

	for (i = 0; i < MXFS_MAX_NODES; i++) {
		uint64_t key[4];

		if (!(member_mask & (1ULL << i)))
			continue;
		key[0] = epoch; key[1] = shard_id;
		key[2] = (uint64_t)i; key[3] = member_incs[i];
		ents[n].score = fnv1a64(0xCBF29CE484222325ULL, key,
		                        sizeof(key));
		ents[n].slot = (uint16_t)i;
		ents[n].inc = member_incs[i];
		n++;
	}
	if (n == 0)
		return 0;
	mxfs_pal_sort(ents, (size_t)n, sizeof(ents[0]), hrw_cmp);
	want = (n < N2_REPLICAS_MAX) ? n : N2_REPLICAS_MAX;
	for (i = 0; i < want; i++) {
		out[i].slot = ents[i].slot;
		out[i].inc = ents[i].inc;
	}
	return want;
}

static uint8_t quorum_of(uint8_t nreplicas)
{
	return (uint8_t)(nreplicas / 2 + 1);
}

void net2_shard_derive_config(struct net2_lockspace *ls,
                              struct net2_shard *sh, uint64_t epoch)
{
	sh->nreplicas = (uint8_t)hrw_top(epoch, sh->shard_id,
	                                 ls->member_mask, ls->member_inc,
	                                 sh->replicas);
	sh->memb_epoch = epoch;
	sh->leader_slot = sh->nreplicas ? sh->replicas[0].slot
	                                : ls->self_slot;
}

int net2_shard_replica_index(const struct net2_shard *sh, uint16_t slot)
{
	int i;

	for (i = 0; i < sh->nreplicas; i++)
		if (sh->replicas[i].slot == slot)
			return i;
	return -1;
}

bool net2_shard_i_am_leader(const struct net2_lockspace *ls,
                            const struct net2_shard *sh)
{
	return sh->leader_slot == ls->self_slot &&
	       net2_shard_replica_index(sh, ls->self_slot) >= 0;
}

/* ─── shard instantiation ─── */

struct net2_shard *net2_shard_get(struct net2_lockspace *ls,
                                  uint32_t shard_id, bool create)
{
	struct net2_shard *sh;
	uint64_t solicit_mask = 0;
	uint32_t solicit_term = 0;

	if (shard_id >= N2_SHARD_COUNT)
		return NULL;
	mxfs_pal_mutex_lock(ls->lock);
	sh = ls->shards[shard_id];
	if (!sh && create) {
		sh = mxfs_pal_alloc(sizeof(*sh));
		if (sh) {
			memset(sh, 0, sizeof(*sh));
			sh->shard_id = shard_id;
			sh->grant_gen_next = 1;      /* never 0 */
			sh->dir_epoch_next = 1;
			sh->enq_seq_next = 1;
			sh->term = 1;
			sh->state = SH_ACTIVE;
			sh->eligible = true;
			sh->caught_up_mask = ~0ULL;
			sh->xfer_src = 0xFFFF;
			sh->opcache = mxfs_pal_alloc(sizeof(*sh->opcache) *
			                             MXFS_MAX_NODES);
			sh->lock = mxfs_pal_mutex_create();
			if (!sh->lock || !sh->opcache) {
				if (sh->lock)
					mxfs_pal_mutex_destroy(sh->lock);
				if (sh->opcache)
					mxfs_pal_free(sh->opcache);
				mxfs_pal_free(sh);
				sh = NULL;
			} else {
				memset(sh->opcache, 0,
				       sizeof(*sh->opcache) * MXFS_MAX_NODES);
				net2_shard_derive_config(ls, sh, ls->epoch);
				N2DBG("slot%u shard%u LAZY-CREATE ep%llu leader%u self-leader%d",
				      ls->self_slot, shard_id,
				      (unsigned long long)ls->epoch,
				      sh->leader_slot,
				      sh->leader_slot == ls->self_slot ? 1 : 0);
				if (sh->leader_slot == ls->self_slot &&
				    (ls->member_mask &
				     ~(1ULL << ls->self_slot))) {
					/* Designated rank-0 seeing this
					 * shard for the first time: it
					 * cannot tell "never existed"
					 * from "state lives on peers I
					 * lost at restart" — pull from
					 * every live member (old R is
					 * unknown here), then barrier.
					 * Empty answers are "no state"
					 * votes; the best base wins. */
					sh->state = SH_XFER;
					sh->xfer_active = true;
					sh->eligible = false;
					sh->xfer_await_mask =
					    ls->member_mask &
					    ~(1ULL << ls->self_slot);
					sh->xfer_deadline_ms =
					    mxfs_pal_time_ms() +
					    2 * ls->elect_base_ms;
					solicit_mask = sh->xfer_await_mask;
					solicit_term = sh->term;
				} else if (sh->leader_slot ==
				           ls->self_slot) {
					sh->term_proven = true;  /* solo */
				}
				ls->shards[shard_id] = sh;
			}
		}
	}
	mxfs_pal_mutex_unlock(ls->lock);
	if (solicit_mask) {
		uint16_t s;

		for (s = 0; s < MXFS_MAX_NODES; s++) {
			struct mxfs_n2msg m;

			if (!(solicit_mask & (1ULL << s)))
				continue;
			memset(&m, 0, sizeof(m));
			m.type = N2_SNAPSHOT_REQ;
			m.shard_term = solicit_term;
			m.shard_id = shard_id;
			m.req_slot = ls->self_slot;
			m.req_inc = ls->self_inc;
			net2_shard_send(ls, s, &m, NULL, 0);
		}
	}
	return sh;
}

/* ─── send helper (fresh msg_id per physical send; effect idempotency
 *      is the opcache's job, not the transport's) ─── */

void net2_shard_send(struct net2_lockspace *ls, uint16_t dst_slot,
                     struct mxfs_n2msg *m, const uint8_t *recs,
                     uint32_t recs_len)
{
	uint8_t buf[MXFS_NET2_MAX_MSG_SIZE];
	struct mxfs_net2_id dst;
	enum net2_priority pri;
	int len;

	if (ls->poisoned || dst_slot >= MXFS_MAX_NODES)
		return;
	m->membership_epoch = ls->epoch;
	len = mxfs_n2msg_pack(m, buf, sizeof(buf));
	if (len < 0)
		return;
	if (recs_len) {
		if ((uint32_t)len + recs_len > sizeof(buf))
			return;
		memcpy(buf + len, recs, recs_len);
		len += (int)recs_len;
	}
	if (dst_slot == ls->self_slot) {
		/* Local loopback: the engine has no self-link (connect
		 * sweep skips self), and a lock service constantly talks
		 * to itself (client on the leader node; leader emitting
		 * to a local requester).  Client-bound types re-enter
		 * via client_rx (cl_lock ranks below shard locks, safe
		 * under a held shard lock); ACQUIRE/RELEASE re-enter the
		 * dispatch — their only callers hold no lock-plane
		 * locks. */
		struct mxfs_n2msg lm;
		struct mxfs_net2_id lsrc;
		uint32_t recs_off = 0;

		if (mxfs_n2msg_unpack(buf, (uint32_t)len, &lm, &recs_off))
			return;
		lsrc.membership_epoch = ls->epoch;
		lsrc.cluster_uuid_hash = ls->net->cfg.uuid_hash;
		lsrc.incarnation = ls->self_inc;
		lsrc.slot = ls->self_slot;
		switch (lm.type) {
		case N2_GRANT:
		case N2_DENY:
		case N2_RELEASE_ACK:
		case N2_BAST:
			net2_lock_client_rx(ls, &lsrc, &lm);
			break;
		case N2_ACQUIRE:
		case N2_RELEASE:
			net2_shard_dispatch(ls, &lsrc, &lm, buf,
			                    (uint32_t)len, recs_off);
			break;
		default:
			/* replication traffic never targets self (append
			 * loops, vote solicits and recovery requests all
			 * skip self by construction — and re-entering the
			 * dispatch under a held shard lock would
			 * deadlock) */
			break;
		}
		return;
	}
	dst.membership_epoch = ls->epoch;
	dst.cluster_uuid_hash = ls->net->cfg.uuid_hash;
	dst.incarnation = ls->member_inc[dst_slot];
	dst.slot = dst_slot;
	switch (m->type) {
	case N2_RELEASE:
	case N2_RELEASE_ACK:
		pri = NET2_PRI_RELEASE;
		break;
	case N2_BAST:
		pri = NET2_PRI_REVOKE;
		break;
	case N2_APPEND:
		pri = (m->op == N2L_RELEASE) ? NET2_PRI_RELEASE
		                             : NET2_PRI_GRANT;
		break;
	default:
		pri = NET2_PRI_GRANT;
		break;
	}
	/* Reliable send; -EAGAIN (window) is absorbed by the client
	 * re-issue / leader retransmit-from-state paths. */
	{
		int src = mxfs_net2_send(ls->net, &dst, pri, true, 0, buf,
		                         (uint32_t)len);

		if (src && src != -EAGAIN)
			N2DBG("slot%u SENDFAIL to%u type%u rc%d inc%u",
			      ls->self_slot, dst_slot, m->type, src,
			      dst.incarnation);
	}
}

/* ─── log machinery (leader) ─── */

static struct n2_log_ent *log_slot(struct net2_shard *sh, uint64_t seq)
{
	return &sh->log[seq % N2_LOG_WIN];
}

static void shard_send_append(struct net2_lockspace *ls,
                              struct net2_shard *sh,
                              const struct n2_log_ent *e, uint16_t dst)
{
	struct mxfs_n2msg m;

	memset(&m, 0, sizeof(m));
	m.type = N2_APPEND;
	m.shard_term = sh->term;     /* leader authority */
	m.entry_term = e->term;      /* entry's origin term */
	m.shard_id = sh->shard_id;
	m.req_slot = e->req_slot;
	m.req_inc = e->req_inc;
	m.request_id = e->request_id;
	m.flags = e->msg_flags;
	m.op = e->op;
	m.entry_seq = e->seq;
	m.commit_watermark = sh->commit_seq;
	m.resource = e->resource;
	m.mode = e->mode;
	m.grant_gen = e->grant_gen;
	m.dir_epoch = e->dir_epoch;
	net2_ls_stat_bump(ls, &ls->stats.appends_sent);
	net2_shard_send(ls, dst, &m, NULL, 0);
}

/* Advance the in-order commit watermark and apply + emit every newly
 * committed entry.  Caller holds sh->lock. */
static void shard_advance_commit(struct net2_lockspace *ls,
                                 struct net2_shard *sh)
{
	N2DBG("slot%u shard%u ADV commit%llu last%llu",
	      ls->self_slot, sh->shard_id,
	      (unsigned long long)sh->commit_seq,
	      (unsigned long long)sh->last_seq);
	while (sh->commit_seq < sh->last_seq) {
		struct n2_log_ent *e = log_slot(sh, sh->commit_seq + 1);
		uint8_t acks;

		if (!e->used || e->seq != sh->commit_seq + 1) {
			N2DBG("slot%u shard%u ADV-GAP want%llu used%d eseq%llu ecom%d",
			      ls->self_slot, sh->shard_id,
			      (unsigned long long)(sh->commit_seq + 1),
			      e->used ? 1 : 0,
			      (unsigned long long)e->seq,
			      e->committed ? 1 : 0);
			break;
		}
		if (e->committed) {
			sh->commit_seq = e->seq;
			continue;
		}
		/* leader self-ack is implicit */
		acks = (uint8_t)(__builtin_popcount(e->ack_mask) + 1);
		if (acks < quorum_of(sh->nreplicas)) {
			N2DBG("slot%u shard%u COMMIT-STALL seq%llu acks%u",
			      ls->self_slot, sh->shard_id,
			      (unsigned long long)e->seq, acks);
			break;
		}
		if (net2_ls_hook(ls, N2H_POST_QUORUM_ACK, sh->shard_id,
		                 e->op))
			return;
		e->committed = true;
		sh->commit_seq = e->seq;
		net2_ls_stat_bump(ls, &ls->stats.commits);
		net2_ls_stat_max(ls, &ls->stats.commit_seq_high_water,
		                 sh->commit_seq);
		if (e->term == sh->term &&
		    sh->leader_slot == ls->self_slot)
			/* quorum committed an entry of MY term: my
			 * leadership + completeness are proven for
			 * this tenure (§7.B) */
			sh->term_proven = true;
		net2_lock_apply_entry(ls, sh, e);
		if (net2_ls_hook(ls, N2H_POST_COMMIT_PRE_EMIT, sh->shard_id,
		                 e->op))
			return;
		net2_lock_emit_result(ls, sh, e);
		if (net2_ls_hook(ls, N2H_POST_EMIT, sh->shard_id, e->op))
			return;
		if (e->op == N2L_RELEASE ||
		    (e->op == N2L_GRANT && (e->msg_flags & N2F_FROM_WAITQ)))
			/* a committed release frees capacity; a committed
			 * waitq grant may leave further compatible
			 * waiters (several PRs) — keep draining */
			net2_lock_post_release_grants(ls, sh, &e->resource);
		if (e->op == N2L_TERM && sh->state == SH_ELECTING &&
		    sh->leader_slot == ls->self_slot) {
			sh->state = SH_ACTIVE;
			N2DBG("slot%u shard%u BARRIER-ACTIVE term%u commit%llu",
			      ls->self_slot, sh->shard_id, sh->term,
			      (unsigned long long)sh->commit_seq);
			net2_ls_stat_bump(ls, &ls->stats.term_barriers);
			if (net2_ls_hook(ls, N2H_ELECTED, sh->shard_id,
			                 (uint16_t)sh->term))
				return;
			/* takeover: resume granting queued waiters from
			 * the replicated state */
			net2_lock_post_release_grants(ls, sh, NULL);
		}
		if (e->op == N2L_CAUGHT_UP) {
			sh->caught_up_mask |= 1ULL << e->req_slot;
			if (e->req_slot == ls->self_slot) {
				sh->eligible = true;
				if (sh->state == SH_XFER)
					sh->state = SH_ACTIVE;
			}
			net2_ls_stat_bump(ls, &ls->stats.caught_up_logged);
		}
	}
}

/* Leader-side append: assigns seq/term, stores, replicates.
 * Caller holds sh->lock.  Returns 0 or -ENOSPC (window wedged). */
int net2_shard_append(struct net2_lockspace *ls, struct net2_shard *sh,
                      const struct n2_log_ent *tmpl)
{
	struct n2_log_ent *e;
	uint64_t seq = sh->last_seq + 1;
	int i, sent = 0;

	if (net2_ls_hook(ls, N2H_PRE_APPEND, sh->shard_id, tmpl->op))
		return -EPERM;
	/* Ring capacity: the slot we are about to take must not hold a
	 * live (uncommitted or un-retired) entry.  Entries retire once
	 * committed and every caught-up replica has acked; a lagging
	 * replica is snapshotted instead of blocking the window. */
	e = log_slot(sh, seq);
	if (e->used && !e->committed)
		return -ENOSPC;
	if (e->used && e->committed) {
		for (i = 0; i < sh->nreplicas; i++) {
			uint16_t rs = sh->replicas[i].slot;

			if (rs == ls->self_slot)
				continue;
			if (!(e->ack_mask & (1u << i)) &&
			    (sh->caught_up_mask & (1ULL << rs))) {
				/* replica now lags past the window */
				sh->caught_up_mask &= ~(1ULL << rs);
			}
		}
	}
	*e = *tmpl;
	e->used = true;
	e->committed = false;
	e->ack_mask = 0;
	e->seq = seq;
	e->term = sh->term;
	sh->last_seq = seq;
	if (net2_ls_hook(ls, N2H_POST_LOCAL_APPEND, sh->shard_id, e->op))
		return -EPERM;
	for (i = 0; i < sh->nreplicas; i++) {
		uint16_t rs = sh->replicas[i].slot;

		if (rs == ls->self_slot)
			continue;
		if (!(sh->caught_up_mask & (1ULL << rs)))
			continue;               /* being snapshotted */
		shard_send_append(ls, sh, e, rs);
		sent++;
		if (sent == 1 &&
		    net2_ls_hook(ls, N2H_POST_SEND_ONE, sh->shard_id, e->op))
			return -EPERM;
	}
	/* Single-replica config (2-node cluster shard with R={self} or
	 * quorum==1): commit immediately. */
	shard_advance_commit(ls, sh);
	return 0;
}

/* ─── snapshot / state transfer ─── */

#define N2_SNAP_RECS_PER_CHUNK \
	((MXFS_NET2_MAX_MSG_SIZE - MXFS_N2MSG_HDR_SIZE - 16) / \
	 MXFS_N2MSG_SNAPREC_SIZE)

struct snap_build {
	uint8_t *recs;
	uint32_t count, cap;
};

static void snap_put(struct snap_build *b, const struct mxfs_n2snap_rec *r)
{
	if (b->count >= b->cap)
		return;                      /* bounded: cap checked by caller */
	mxfs_n2snap_rec_pack(r, b->recs + (size_t)b->count *
	                     MXFS_N2MSG_SNAPREC_SIZE);
	b->count++;
}

/* Serialize the whole shard state.  Caller holds sh->lock. */
static int snap_serialize(struct net2_shard *sh, struct snap_build *b)
{
	struct mxfs_n2snap_rec r;
	int i, c;

	for (i = 0; i < N2_REC_HASH; i++) {
		struct n2_lock_rec *rec;

		for (rec = sh->recs[i]; rec; rec = rec->next) {
			struct n2_waiter *w;

			memset(&r, 0, sizeof(r));
			r.resource = rec->resource;
			r.kind = N2SR_RECMETA;
			r.mode = rec->handoff;
			r.slot = rec->last_ex_slot;
			r.gen_or_enqseq = rec->grant_gen;
			r.request_id = rec->pending_revoke_mask;
			r.aux = rec->dir_epoch;
			snap_put(b, &r);
			{
				const uint8_t modes[5] = {
					MXFS_LOCK_EX, MXFS_LOCK_PW,
					MXFS_LOCK_PR, MXFS_LOCK_CW,
					MXFS_LOCK_CR
				};
				const uint64_t masks[5] = {
					rec->holders_ex, rec->holders_pw,
					rec->holders_pr, rec->holders_cw,
					rec->holders_cr
				};
				int m;

				for (m = 0; m < 5; m++) {
					if (!masks[m])
						continue;
					memset(&r, 0, sizeof(r));
					r.resource = rec->resource;
					r.kind = N2SR_HOLDERS;
					r.mode = modes[m];
					r.aux = masks[m];
					snap_put(b, &r);
				}
			}
			for (w = rec->waitq; w; w = w->next) {
				memset(&r, 0, sizeof(r));
				r.resource = rec->resource;
				r.kind = N2SR_WAITER;
				r.mode = w->mode;
				r.slot = w->slot;
				r.inc = w->inc;
				r.request_id = w->request_id;
				r.gen_or_enqseq = w->enq_seq;
				snap_put(b, &r);
			}
		}
	}
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		struct n2_opcache_client *oc = &sh->opcache[i];

		if (!oc->used)
			continue;
		for (c = 0; c < N2_OPCACHE_RING; c++) {
			struct n2_opcache_ent *oe = &oc->ring[c];

			if (!oe->used)
				continue;
			memset(&r, 0, sizeof(r));
			r.kind = N2SR_OPCACHE;
			r.mode = oe->mode;
			r.slot = oc->slot;
			r.inc = oc->inc;
			r.request_id = oe->request_id;
			r.gen_or_enqseq = oe->gen;
			r.aux = oe->status;
			snap_put(b, &r);
		}
	}
	return (int)b->count;
}

/* Send the full state as chunks to dst.  Caller holds sh->lock. */
static void shard_send_snapshot(struct net2_lockspace *ls,
                                struct net2_shard *sh, uint16_t dst)
{
	struct snap_build b;
	uint32_t nchunks, ci, nsuf;
	uint8_t *suf;

	b.cap = 4096;                        /* 256 KB scratch, harness scale */
	b.count = 0;
	b.recs = mxfs_pal_alloc((size_t)b.cap * MXFS_N2MSG_SNAPREC_SIZE);
	if (!b.recs)
		return;
	snap_serialize(sh, &b);
	if (net2_ls_hook(ls, N2H_SNAPSHOT, sh->shard_id, dst)) {
		mxfs_pal_free(b.recs);
		return;
	}
	/* Un-applied log suffix (commit+1..last): these entries may be
	 * committed cluster-wide (watermark lag) — the pulling leader
	 * must inherit them or its barrier truncates committed state. */
	nsuf = 0;
	suf = NULL;
	if (sh->last_seq > sh->commit_seq) {
		uint64_t s;

		suf = mxfs_pal_alloc((size_t)N2_LOG_WIN *
		                     MXFS_N2MSG_LOGREC_SIZE);
		if (!suf) {
			mxfs_pal_free(b.recs);
			return;
		}
		for (s = sh->commit_seq + 1;
		     s <= sh->last_seq && nsuf < N2_LOG_WIN; s++) {
			struct n2_log_ent *e = log_slot(sh, s);
			struct mxfs_n2log_rec lr;

			if (!e->used || e->seq != s)
				continue;
			memset(&lr, 0, sizeof(lr));
			lr.resource = e->resource;
			lr.seq = e->seq;
			lr.term = e->term;
			lr.op = e->op;
			lr.mode = e->mode;
			lr.slot = e->req_slot;
			lr.inc = e->req_inc;
			lr.request_id = e->request_id;
			lr.grant_gen = e->grant_gen;
			lr.dir_epoch = e->dir_epoch;
			lr.msg_flags = e->msg_flags;
			mxfs_n2log_rec_pack(&lr, suf + (size_t)nsuf *
			                    MXFS_N2MSG_LOGREC_SIZE);
			nsuf++;
		}
	}
	nchunks = (b.count + N2_SNAP_RECS_PER_CHUNK - 1) /
	          N2_SNAP_RECS_PER_CHUNK;
	if (nchunks == 0)
		nchunks = 1;                 /* empty snapshot still lands */
	if (nsuf)
		nchunks++;                   /* suffix rides its own chunk */
	for (ci = 0; ci < nchunks; ci++) {
		struct mxfs_n2msg m;
		bool sufchunk = nsuf && ci == nchunks - 1;
		uint32_t first = ci * N2_SNAP_RECS_PER_CHUNK;
		uint32_t n = 0;

		if (!sufchunk && first < b.count) {
			n = b.count - first;
			if (n > N2_SNAP_RECS_PER_CHUNK)
				n = N2_SNAP_RECS_PER_CHUNK;
		}
		memset(&m, 0, sizeof(m));
		m.type = N2_SNAPSHOT_CHUNK;
		m.shard_term = sh->term;
		m.shard_id = sh->shard_id;
		m.req_slot = ls->self_slot;
		m.req_inc = ls->self_inc;
		m.entry_seq = sh->commit_seq;    /* snapshot base */
		m.last_seq = sh->last_seq;       /* completeness vote */
		m.chunk_idx = ci;
		m.chunk_count = nchunks;
		m.rec_count = n;
		m.log_count = sufchunk ? nsuf : 0;
		net2_shard_send(ls, dst, &m,
		                sufchunk ? suf :
		                b.recs + (size_t)first *
		                MXFS_N2MSG_SNAPREC_SIZE,
		                sufchunk ? nsuf * MXFS_N2MSG_LOGREC_SIZE :
		                n * MXFS_N2MSG_SNAPREC_SIZE);
	}
	if (suf)
		mxfs_pal_free(suf);
	mxfs_pal_free(b.recs);
	net2_ls_stat_bump(ls, &ls->stats.xfers_started);
}

/* Install one snapshot record into the (cleared) shard.  sh->lock held. */
static void snap_install_rec(struct net2_shard *sh,
                             const struct mxfs_n2snap_rec *r)
{
	struct n2_lock_rec *rec;

	switch (r->kind) {
	case N2SR_RECMETA:
		rec = net2_rec_get(sh, &r->resource, true);
		if (!rec)
			return;
		rec->grant_gen = r->gen_or_enqseq;
		rec->dir_epoch = r->aux;
		rec->last_ex_slot = r->slot;
		rec->handoff = r->mode;
		rec->pending_revoke_mask = r->request_id;
		if (rec->grant_gen >= sh->grant_gen_next)
			sh->grant_gen_next = rec->grant_gen + 1;
		if (rec->dir_epoch >= sh->dir_epoch_next)
			sh->dir_epoch_next = rec->dir_epoch + 1;
		break;
	case N2SR_HOLDERS:
		rec = net2_rec_get(sh, &r->resource, true);
		if (!rec)
			return;
		switch (r->mode) {
		case MXFS_LOCK_EX: rec->holders_ex = r->aux; break;
		case MXFS_LOCK_PW: rec->holders_pw = r->aux; break;
		case MXFS_LOCK_PR: rec->holders_pr = r->aux; break;
		case MXFS_LOCK_CW: rec->holders_cw = r->aux; break;
		case MXFS_LOCK_CR: rec->holders_cr = r->aux; break;
		}
		break;
	case N2SR_WAITER: {
		struct n2_waiter *w = mxfs_pal_alloc(sizeof(*w));

		rec = net2_rec_get(sh, &r->resource, true);
		if (!rec || !w) {
			if (w)
				mxfs_pal_free(w);
			return;
		}
		w->slot = r->slot;
		w->inc = r->inc;
		w->request_id = r->request_id;
		w->mode = r->mode;
		w->enq_seq = r->gen_or_enqseq;
		w->next = NULL;
		if (rec->waitq_tail)
			rec->waitq_tail->next = w;
		else
			rec->waitq = w;
		rec->waitq_tail = w;
		if (w->enq_seq >= sh->enq_seq_next)
			sh->enq_seq_next = w->enq_seq + 1;
		break;
	}
	case N2SR_OPCACHE: {
		struct n2_opcache_client *oc = &sh->opcache[r->slot %
		                                            MXFS_MAX_NODES];
		struct n2_opcache_ent *oe;

		if (!oc->used || oc->inc != r->inc) {
			memset(oc, 0, sizeof(*oc));
			oc->used = true;
			oc->slot = r->slot;
			oc->inc = r->inc;
		}
		oe = &oc->ring[oc->next_idx];
		oc->next_idx = (oc->next_idx + 1) % N2_OPCACHE_RING;
		oe->used = true;
		oe->request_id = r->request_id;
		oe->status = (uint8_t)r->aux;
		oe->mode = r->mode;
		oe->gen = r->gen_or_enqseq;
		break;
	}
	default:
		break;
	}
}

/* ─── election ─── */

static void shard_arm_election(struct net2_lockspace *ls,
                               struct net2_shard *sh)
{
	int rank = net2_shard_replica_index(sh, ls->self_slot);
	uint64_t jitter;

	if (rank < 0 || !sh->eligible)
		return;
	jitter = ls_prng(ls) % (ls->elect_base_ms / 2 + 1);
	sh->state = SH_ELECTING;
	sh->elect_deadline_ms = mxfs_pal_time_ms() + ls->elect_base_ms +
	                        (uint64_t)rank * ls->elect_rank_ms + jitter;
}

/* Serve-gate kick: an ACTIVE self-leader whose term is not yet
 * quorum-proven starts (or re-checks) its TERM barrier.  Idempotent —
 * an uncommitted barrier of this term in the window means one is
 * already in flight.  sh->lock held. */
void net2_shard_prove_term(struct net2_lockspace *ls,
                           struct net2_shard *sh)
{
	struct n2_log_ent t;
	uint64_t s;

	if (sh->leader_slot != ls->self_slot || sh->state != SH_ACTIVE ||
	    sh->term_proven)
		return;
	for (s = sh->commit_seq + 1; s <= sh->last_seq; s++) {
		struct n2_log_ent *e = log_slot(sh, s);

		if (e->used && e->seq == s && e->op == N2L_TERM &&
		    e->term == sh->term)
			return;              /* barrier already in flight */
	}
	memset(&t, 0, sizeof(t));
	t.op = N2L_TERM;
	t.req_slot = ls->self_slot;
	t.req_inc = ls->self_inc;
	(void)net2_shard_append(ls, sh, &t);
}

static void shard_become_leader(struct net2_lockspace *ls,
                                struct net2_shard *sh)
{
	struct n2_log_ent t;

	sh->term = sh->cand_term;
	sh->leader_slot = ls->self_slot;
	sh->elect_deadline_ms = 0;
	sh->term_proven = false;             /* until the barrier commits */
	N2DBG("slot%u shard%u WON term%u commit%llu last%llu",
	      ls->self_slot, sh->shard_id, sh->term,
	      (unsigned long long)sh->commit_seq,
	      (unsigned long long)sh->last_seq);
	/* Re-replicate the suffix under the new term via the barrier:
	 * committing N2L_TERM at last_seq+1 forces backfill of every
	 * earlier entry (NACK protocol) and implicitly re-commits
	 * acked-but-unpublished entries (leader completeness). */
	memset(&t, 0, sizeof(t));
	t.op = N2L_TERM;
	t.req_slot = ls->self_slot;
	t.req_inc = ls->self_inc;
	(void)net2_shard_append(ls, sh, &t);
}

static void shard_solicit_votes(struct net2_lockspace *ls,
                                struct net2_shard *sh)
{
	struct mxfs_n2msg m;
	int i;

	/* Each candidacy round must use a FRESH term above anything this
	 * node has seen or voted for (Raft term escalation) — re-arming
	 * at a constant term+1 livelocks two simultaneous self-voted
	 * candidates forever (both refuse each other at the same term). */
	sh->cand_term = (sh->cand_term > sh->term ? sh->cand_term
	                                          : sh->term) + 1;
	if (sh->cand_term <= sh->voted_term)
		sh->cand_term = sh->voted_term + 1;
	sh->votes = 1;                       /* self */
	sh->voted_term = sh->cand_term;      /* vote for self */
	N2DBG("slot%u shard%u SOLICIT term%u commit%llu last%llu nrep%u",
	      ls->self_slot, sh->shard_id, sh->cand_term,
	      (unsigned long long)sh->commit_seq,
	      (unsigned long long)sh->last_seq, sh->nreplicas);
	net2_ls_stat_bump(ls, &ls->stats.elections_started);
	if (sh->votes >= quorum_of(sh->nreplicas)) {
		shard_become_leader(ls, sh);
		return;
	}
	for (i = 0; i < sh->nreplicas; i++) {
		if (sh->replicas[i].slot == ls->self_slot)
			continue;
		memset(&m, 0, sizeof(m));
		m.type = N2_TERM_VOTE;
		m.shard_term = sh->term;
		m.shard_id = sh->shard_id;
		m.req_slot = ls->self_slot;
		m.req_inc = ls->self_inc;
		m.cand_term = sh->cand_term;
		m.cand_commit_seq = sh->commit_seq;
		m.cand_last_seq = sh->last_seq;
		net2_shard_send(ls, sh->replicas[i].slot, &m, NULL, 0);
	}
	/* re-arm: if quorum never answers, back off and retry */
	sh->elect_deadline_ms = mxfs_pal_time_ms() + 2 * ls->elect_base_ms +
	                        (ls_prng(ls) % ls->elect_base_ms);
}

/* ─── dispatch: shard-bound messages ─── */

static void shard_rx_append(struct net2_lockspace *ls, struct net2_shard *sh,
                            const struct mxfs_n2msg *m, uint16_t src_slot)
{
	struct mxfs_n2msg ack;
	bool ok = false;

	if (m->shard_term < sh->term) {
		net2_ls_stat_bump(ls, &ls->stats.stale_term_denies);
		N2DBG("slot%u shard%u STALE-APPEND seq%llu mterm%u myterm%u",
		      ls->self_slot, sh->shard_id,
		      (unsigned long long)m->entry_seq, m->shard_term,
		      sh->term);
		return;
	}
	/* The APPEND envelope's req identity is the ENTRY's requester
	 * (op identity §6) — the LEADER is the frame source. */
	if (m->shard_term > sh->term) {
		/* new leader proved itself to a quorum */
		sh->term = m->shard_term;
		sh->leader_slot = src_slot;
		sh->term_proven = false;     /* I am not that leader */
		if (sh->state == SH_ELECTING)
			sh->state = SH_ACTIVE;
		sh->elect_deadline_ms = 0;
	} else {
		sh->leader_slot = src_slot;
	}

	if (sh->state == SH_XFER) {
		/* transferring: never ack (ineligible) */
		ok = false;
	} else if (m->entry_seq == sh->last_seq + 1) {
		struct n2_log_ent *e = log_slot(sh, m->entry_seq);

		memset(e, 0, sizeof(*e));
		e->used = true;
		e->op = m->op;
		e->term = m->entry_term;
		e->seq = m->entry_seq;
		e->resource = m->resource;
		e->mode = m->mode;
		e->req_slot = m->req_slot;
		e->req_inc = m->req_inc;
		e->request_id = m->request_id;
		e->grant_gen = m->grant_gen;
		e->dir_epoch = m->dir_epoch;
		e->msg_flags = m->flags;
		sh->last_seq = m->entry_seq;
		ok = true;
	} else if (m->entry_seq <= sh->last_seq) {
		struct n2_log_ent *e = log_slot(sh, m->entry_seq);

		if (e->used && e->seq == m->entry_seq &&
		    e->term == m->entry_term && e->op == m->op &&
		    e->req_slot == m->req_slot &&
		    e->req_inc == m->req_inc &&
		    e->request_id == m->request_id) {
			ok = true;           /* duplicate — re-ack */
		} else if (e->used && e->seq == m->entry_seq &&
		           m->entry_seq <= sh->commit_seq) {
			/* Committed entries are IMMUTABLE.  A leader
			 * writing different content here has an
			 * incomplete log (empty restart self-appointed
			 * rank-0) — NACK; the ack carries my last_seq +
			 * commit_seq so it learns it must pull from me,
			 * never the reverse. */
			ok = false;
		} else if (e->used && e->seq == m->entry_seq) {
			/* same seq, different origin term: divergent
			 * uncommitted suffix (partitioned old leader
			 * wrote it) — the current leader's log wins;
			 * truncate from here and take its entry */
			uint64_t s;

			for (s = m->entry_seq; s <= sh->last_seq; s++)
				memset(log_slot(sh, s), 0,
				       sizeof(struct n2_log_ent));
			sh->last_seq = m->entry_seq;
			e = log_slot(sh, m->entry_seq);
			e->used = true;
			e->op = m->op;
			e->term = m->entry_term;
			e->seq = m->entry_seq;
			e->resource = m->resource;
			e->mode = m->mode;
			e->req_slot = m->req_slot;
			e->req_inc = m->req_inc;
			e->request_id = m->request_id;
			e->grant_gen = m->grant_gen;
			e->dir_epoch = m->dir_epoch;
			e->msg_flags = m->flags;
			net2_ls_stat_bump(ls, &ls->stats.truncations);
			ok = true;
		}
		/* else: seq fell out of the ring — treat as gap/NACK */
	} else {
		/* gap: we lag; leader will backfill or snapshot */
		sh->eligible = false;
	}

	/* Apply up to the leader's watermark (replicas apply silently —
	 * only the leader emits). */
	if (ok) {
		uint64_t w = m->commit_watermark;

		if (w > sh->last_seq)
			w = sh->last_seq;
		while (sh->commit_seq < w) {
			struct n2_log_ent *e = log_slot(sh,
			                                sh->commit_seq + 1);

			if (!e->used || e->seq != sh->commit_seq + 1)
				break;
			e->committed = true;
			sh->commit_seq = e->seq;
			net2_ls_stat_max(ls,
			                 &ls->stats.commit_seq_high_water,
			                 sh->commit_seq);
			net2_lock_apply_entry(ls, sh, e);
			if (e->op == N2L_CAUGHT_UP &&
			    e->req_slot == ls->self_slot) {
				sh->eligible = true;
				if (sh->state == SH_XFER)
					sh->state = SH_ACTIVE;
			}
		}
	}

	N2DBG("slot%u shard%u RXAPPEND seq%llu term%u op%u req%u rid%llu ok%d last%llu",
	      ls->self_slot, sh->shard_id,
	      (unsigned long long)m->entry_seq, m->shard_term, m->op,
	      m->req_slot, (unsigned long long)m->request_id,
	      ok ? 1 : 0, (unsigned long long)sh->last_seq);
	memset(&ack, 0, sizeof(ack));
	ack.type = N2_APPEND_ACK;
	ack.shard_term = sh->term;
	ack.shard_id = sh->shard_id;
	ack.req_slot = ls->self_slot;
	ack.req_inc = ls->self_inc;
	ack.entry_seq = m->entry_seq;
	ack.ack_ok = ok ? 1 : 0;
	ack.last_seq = sh->last_seq;
	ack.commit_watermark = sh->commit_seq;
	net2_shard_send(ls, src_slot, &ack, NULL, 0);
}

static void shard_rx_append_ack(struct net2_lockspace *ls,
                                struct net2_shard *sh,
                                const struct mxfs_n2msg *m,
                                uint16_t src_slot)
{
	int ri = net2_shard_replica_index(sh, src_slot);

	N2DBG("slot%u shard%u RXACK from%u seq%llu ok%u ldr%d ri%d mterm%u myterm%u",
	      ls->self_slot, sh->shard_id, src_slot,
	      (unsigned long long)m->entry_seq, m->ack_ok,
	      net2_shard_i_am_leader(ls, sh) ? 1 : 0, ri,
	      m->shard_term, sh->term);
	if (!net2_shard_i_am_leader(ls, sh) || ri < 0)
		return;
	if (m->shard_term != sh->term)
		return;
	if (m->ack_ok) {
		uint64_t s;

		net2_ls_stat_bump(ls, &ls->stats.append_acks);
		/* An in-chain ack of seq N means the replica holds the
		 * matching prefix up to N (chain discipline) — count it
		 * for every still-uncommitted entry ≤ N, not just N: a
		 * leader elected mid-flight inherits entries whose acks
		 * went to the dead leader and would stall otherwise. */
		for (s = sh->commit_seq + 1;
		     s <= m->entry_seq && s <= sh->last_seq; s++) {
			struct n2_log_ent *e = log_slot(sh, s);

			if (e->used && e->seq == s)
				e->ack_mask |= (uint8_t)(1u << ri);
		}
		/* A caught-up ack from a replica we were snapshotting
		 * completes the transfer: log the eligibility flip. */
		if (!(sh->caught_up_mask & (1ULL << src_slot)) &&
		    m->last_seq >= sh->commit_seq &&
		    m->entry_seq == 0) {
			struct n2_log_ent t;

			memset(&t, 0, sizeof(t));
			t.op = N2L_CAUGHT_UP;
			t.req_slot = src_slot;
			t.req_inc = sh->replicas[ri].inc;
			(void)net2_shard_append(ls, sh, &t);
			net2_ls_stat_bump(ls, &ls->stats.xfers_completed);
		}
		shard_advance_commit(ls, sh);
	} else {
		net2_ls_stat_bump(ls, &ls->stats.append_nacks);
		if (m->commit_watermark > sh->commit_seq) {
			/* The NACKing follower has committed state I
			 * lack — I may not lead from an incomplete log
			 * (and I must NOT "backfill" it with mine):
			 * abdicate into a snapshot pull from it, then
			 * re-barrier at a higher term. */
			if (!sh->xfer_active) {
				struct mxfs_n2msg req;

				N2DBG("slot%u shard%u ABDICATE to%u theirs%llu mine%llu",
				      ls->self_slot, sh->shard_id, src_slot,
				      (unsigned long long)m->commit_watermark,
				      (unsigned long long)sh->commit_seq);
				sh->state = SH_XFER;
				sh->xfer_active = true;
				sh->xfer_src = 0xFFFF;
				sh->xfer_stream_done = false;
				sh->eligible = false;
				sh->term_proven = false;
				sh->xfer_await_mask = 1ULL << src_slot;
				sh->xfer_deadline_ms =
				    mxfs_pal_time_ms() +
				    2 * ls->elect_base_ms;
				memset(&req, 0, sizeof(req));
				req.type = N2_SNAPSHOT_REQ;
				req.shard_term = sh->term;
				req.shard_id = sh->shard_id;
				req.req_slot = ls->self_slot;
				req.req_inc = ls->self_inc;
				net2_shard_send(ls, src_slot, &req,
				                NULL, 0);
			}
			return;
		}
		if (m->last_seq + 1 >= (sh->last_seq >= N2_LOG_WIN ?
		                        sh->last_seq - N2_LOG_WIN + 1 : 1) &&
		    m->last_seq < sh->last_seq &&
		    log_slot(sh, m->last_seq + 1)->used &&
		    log_slot(sh, m->last_seq + 1)->seq == m->last_seq + 1) {
			/* backfill from the ring (the first needed entry
			 * must be materializable — below a snapshot base
			 * the ring is empty and only a snapshot helps) */
			uint64_t s;

			for (s = m->last_seq + 1; s <= sh->last_seq; s++) {
				struct n2_log_ent *e = log_slot(sh, s);

				if (e->used && e->seq == s)
					shard_send_append(ls, sh, e,
					                  src_slot);
			}
		} else {
			/* lagging past the window — snapshot */
			sh->caught_up_mask &= ~(1ULL << src_slot);
			shard_send_snapshot(ls, sh, src_slot);
		}
	}
}

static void shard_rx_vote(struct net2_lockspace *ls, struct net2_shard *sh,
                          const struct mxfs_n2msg *m, uint16_t src_slot)
{
	struct mxfs_n2msg g;

	if (m->flags & N2F_VOTE_GRANT) {
		if (sh->state != SH_ELECTING || m->cand_term != sh->cand_term)
			return;
		sh->votes++;
		if (sh->votes >= quorum_of(sh->nreplicas))
			shard_become_leader(ls, sh);
		return;
	}
	/* solicit */
	if (net2_shard_replica_index(sh, src_slot) < 0)
		return;
	if (!sh->eligible || sh->state == SH_XFER) {
		net2_ls_stat_bump(ls, &ls->stats.votes_refused_xfer);
		return;
	}
	if (m->cand_term <= sh->term || m->cand_term <= sh->voted_term) {
		net2_ls_stat_bump(ls, &ls->stats.votes_refused_tuple);
		return;
	}
	if (m->cand_commit_seq < sh->commit_seq ||
	    (m->cand_commit_seq == sh->commit_seq &&
	     m->cand_last_seq < sh->last_seq)) {
		net2_ls_stat_bump(ls, &ls->stats.votes_refused_tuple);
		return;
	}
	sh->voted_term = m->cand_term;
	net2_ls_stat_bump(ls, &ls->stats.votes_granted);
	memset(&g, 0, sizeof(g));
	g.type = N2_TERM_VOTE;
	g.flags = N2F_VOTE_GRANT;
	g.shard_term = sh->term;
	g.shard_id = sh->shard_id;
	g.req_slot = ls->self_slot;
	g.req_inc = ls->self_inc;
	g.cand_term = m->cand_term;
	net2_shard_send(ls, src_slot, &g, NULL, 0);
}

static void shard_rx_snapshot_req(struct net2_lockspace *ls,
                                  struct net2_shard *sh,
                                  const struct mxfs_n2msg *m,
                                  uint16_t src_slot)
{
	/* Source duty: any member with state may serve (a frozen old
	 * replica is a legitimate source — no grant authority needed). */
	(void)m;
	N2DBG("slot%u shard%u SNAPREQ from%u st%d base%llu last%llu",
	      ls->self_slot, sh->shard_id, src_slot, (int)sh->state,
	      (unsigned long long)sh->commit_seq,
	      (unsigned long long)sh->last_seq);
	shard_send_snapshot(ls, sh, src_slot);
}

static void shard_start_recovery(struct net2_lockspace *ls,
                                 struct net2_shard *sh);

/* Finish a solicited pull: the claimed stream is fully installed and
 * every solicited peer has answered (or the deadline reaped the
 * silent ones).  sh->lock held. */
static void shard_xfer_finalize(struct net2_lockspace *ls,
                                struct net2_shard *sh)
{
	sh->xfer_active = false;
	sh->xfer_src = 0xFFFF;
	sh->xfer_await_mask = 0;
	sh->xfer_deadline_ms = 0;
	sh->xfer_stream_done = false;
	sh->xfer_adv_base = 0;
	sh->xfer_adv_last = 0;
	if (sh->leader_slot == ls->self_slot &&
	    sh->commit_seq == 0 && sh->last_seq == 0) {
		/* The pull found NO server state anywhere alive.  That
		 * does not prove the shard never existed — the state may
		 * have died with its replicas (total loss).  §7.B: never
		 * conclude an empty table by fiat — run the closed-set
		 * recovery barrier; clients report their held records
		 * (a genuinely virgin shard just rebuilds empty). */
		shard_start_recovery(ls, sh);
		return;
	}
	if (sh->leader_slot == ls->self_slot) {
		/* Designated rank-0 pulled the best surviving copy:
		 * now assert leadership over the NEW quorum — term
		 * above the source's, barrier commit re-proves
		 * everything (fresh followers NACK → backfill/
		 * snapshot; MORE-complete followers NACK → abdicate,
		 * pull again). */
		struct n2_log_ent t;

		sh->term = sh->term + 1;
		sh->state = SH_ELECTING;
		sh->caught_up_mask = ~0ULL;
		sh->eligible = true;
		sh->term_proven = false;
		memset(&t, 0, sizeof(t));
		t.op = N2L_TERM;
		t.req_slot = ls->self_slot;
		t.req_inc = ls->self_inc;
		(void)net2_shard_append(ls, sh, &t);
		net2_ls_stat_bump(ls, &ls->stats.xfers_completed);
		N2DBG("slot%u shard%u PULL-DONE base%llu term%u",
		      ls->self_slot, sh->shard_id,
		      (unsigned long long)sh->commit_seq, sh->term);
	} else {
		struct mxfs_n2msg ack;

		/* installed: report readiness (entry_seq 0 marks the
		 * transfer-complete ack; leader logs CAUGHT_UP) */
		memset(&ack, 0, sizeof(ack));
		ack.type = N2_APPEND_ACK;
		ack.shard_term = sh->term;
		ack.shard_id = sh->shard_id;
		ack.req_slot = ls->self_slot;
		ack.req_inc = ls->self_inc;
		ack.entry_seq = 0;
		ack.ack_ok = 1;
		ack.last_seq = sh->last_seq;
		ack.commit_watermark = sh->commit_seq;
		net2_shard_send(ls, sh->leader_slot, &ack, NULL, 0);
	}
}

static void shard_rx_snapshot_chunk(struct net2_lockspace *ls,
                                    struct net2_shard *sh,
                                    const struct mxfs_n2msg *m,
                                    const uint8_t *payload, uint32_t len,
                                    uint32_t recs_off)
{
	bool install = false;
	uint32_t i;

	(void)len;
	if (sh->xfer_active) {
		/* Solicited pull.  One install stream at a time, but
		 * §7.B says "collect from each, max commit_seq wins":
		 * every peer's chunk0 is its vote (base = its
		 * commit_seq; an EMPTY answer is a "no state" vote),
		 * and a higher-base chunk0 PREEMPTS the claimed
		 * stream — the empty restarted peer answers fastest
		 * and must not win by speed. */
		if (m->chunk_idx == 0) {
			sh->xfer_await_mask &= ~(1ULL << m->req_slot);
			if (sh->xfer_src == 0xFFFF) {
				sh->xfer_src = m->req_slot;
				install = true;
			} else if (m->req_slot == sh->xfer_src) {
				install = true;   /* source restarted */
			} else if (m->entry_seq > sh->xfer_adv_base ||
			           (m->entry_seq == sh->xfer_adv_base &&
			            m->last_seq > sh->xfer_adv_last)) {
				sh->xfer_src = m->req_slot;  /* preempt */
				install = true;
			}
			N2DBG("slot%u shard%u CHUNK0 from%u base%llu srclast%llu cnt%u install%d src%u",
			      ls->self_slot, sh->shard_id, m->req_slot,
			      (unsigned long long)m->entry_seq,
			      (unsigned long long)m->last_seq,
			      m->chunk_count, install ? 1 : 0,
			      sh->xfer_src);
		} else if (m->req_slot == sh->xfer_src) {
			install = true;
		}
	} else {
		/* Unsolicited (leader-pushed to a lagging replica):
		 * accept only state ahead of ours, and never let a
		 * stray chunk wipe a serving leader. */
		if (sh->leader_slot == ls->self_slot)
			return;
		if (m->entry_seq <= sh->commit_seq)
			return;
		if (m->chunk_idx != 0 && m->req_slot != sh->xfer_src)
			return;
		if (m->chunk_idx == 0)
			sh->xfer_src = m->req_slot;
		install = true;
	}
	if (install && m->chunk_idx == 0) {
		net2_shard_free_recs(sh);
		memset(sh->opcache, 0,
		       sizeof(*sh->opcache) * MXFS_MAX_NODES);
		memset(sh->log, 0, sizeof(sh->log));
		sh->xfer_chunks_seen = 0;
		sh->xfer_chunk_count = m->chunk_count;
		sh->xfer_stream_done = false;
		sh->xfer_adv_base = m->entry_seq;
		sh->xfer_adv_last = m->last_seq;
		sh->commit_seq = m->entry_seq;   /* snapshot base */
		sh->last_seq = m->entry_seq;
		sh->term = m->shard_term;
		if (!sh->xfer_active)
			sh->leader_slot = m->req_slot;
	}
	if (install) {
		for (i = 0; i < m->rec_count; i++) {
			struct mxfs_n2snap_rec r;

			mxfs_n2snap_rec_unpack(payload + recs_off +
			                       (size_t)i *
			                       MXFS_N2MSG_SNAPREC_SIZE,
			                       &r);
			snap_install_rec(sh, &r);
		}
		for (i = 0; i < m->log_count; i++) {
			struct mxfs_n2log_rec lr;
			struct n2_log_ent *e;

			mxfs_n2log_rec_unpack(payload + recs_off +
			                      (size_t)m->rec_count *
			                      MXFS_N2MSG_SNAPREC_SIZE +
			                      (size_t)i *
			                      MXFS_N2MSG_LOGREC_SIZE,
			                      &lr);
			if (lr.seq <= sh->commit_seq)
				continue;
			/* inherit the source's un-applied suffix
			 * UNCOMMITTED — the barrier (or the pushing
			 * leader's watermark) re-commits it */
			e = log_slot(sh, lr.seq);
			memset(e, 0, sizeof(*e));
			e->used = true;
			e->op = lr.op;
			e->term = lr.term;
			e->seq = lr.seq;
			e->resource = lr.resource;
			e->mode = lr.mode;
			e->req_slot = lr.slot;
			e->req_inc = lr.inc;
			e->request_id = lr.request_id;
			e->grant_gen = lr.grant_gen;
			e->dir_epoch = lr.dir_epoch;
			e->msg_flags = (uint16_t)lr.msg_flags;
			if (lr.seq > sh->last_seq)
				sh->last_seq = lr.seq;
		}
		sh->xfer_chunks_seen++;
		if (sh->xfer_chunks_seen >= sh->xfer_chunk_count) {
			if (sh->xfer_active) {
				sh->xfer_stream_done = true;
			} else {
				struct mxfs_n2msg ack;

				/* leader-pushed install complete:
				 * report readiness (entry_seq 0 marks
				 * the transfer-complete ack; leader
				 * logs CAUGHT_UP) */
				sh->xfer_src = 0xFFFF;
				memset(&ack, 0, sizeof(ack));
				ack.type = N2_APPEND_ACK;
				ack.shard_term = sh->term;
				ack.shard_id = sh->shard_id;
				ack.req_slot = ls->self_slot;
				ack.req_inc = ls->self_inc;
				ack.entry_seq = 0;
				ack.ack_ok = 1;
				ack.last_seq = sh->last_seq;
				ack.commit_watermark = sh->commit_seq;
				net2_shard_send(ls, m->req_slot, &ack,
				                NULL, 0);
			}
		}
	}
	if (sh->xfer_active && sh->xfer_stream_done &&
	    sh->xfer_await_mask == 0)
		shard_xfer_finalize(ls, sh);
}

static void shard_rx_recovery_report(struct net2_lockspace *ls,
                                     struct net2_shard *sh,
                                     const struct mxfs_n2msg *m,
                                     const uint8_t *payload, uint32_t len,
                                     uint32_t recs_off, uint16_t src_slot);

void net2_shard_dispatch(struct net2_lockspace *ls,
                         const struct mxfs_net2_id *src,
                         const struct mxfs_n2msg *m,
                         const uint8_t *payload, uint32_t len,
                         uint32_t recs_off)
{
	struct net2_shard *sh;

	if (m->membership_epoch + 1 < ls->epoch) {
		/* Same bridge window as midcomms (§7.A): E-1 flows during
		 * the commit wave; E+1 arrives when the SENDER got its
		 * epoch_commit first (the wave is not atomic across
		 * nodes) — dropping those wedges the new leader's barrier
		 * (its appends have no transport-level retry; the drop
		 * here is past the reliable layer).  Only deep-stale is
		 * refused; term/seq rules police everything else. */
		N2DBG("slot%u shard%u EPOCH-DROP type%u from%u mep%llu myep%llu",
		      ls->self_slot, m->shard_id, m->type, src->slot,
		      (unsigned long long)m->membership_epoch,
		      (unsigned long long)ls->epoch);
		net2_ls_stat_bump(ls, &ls->stats.stale_epoch_denies);
		if (m->type == N2_ACQUIRE || m->type == N2_RELEASE) {
			struct mxfs_n2msg d;

			memset(&d, 0, sizeof(d));
			d.type = N2_DENY;
			d.shard_id = m->shard_id;
			d.req_slot = m->req_slot;
			d.req_inc = m->req_inc;
			d.request_id = m->request_id;
			d.resource = m->resource;
			d.mode = m->mode;
			d.status = N2D_STALE_EPOCH;
			net2_ls_stat_bump(ls, &ls->stats.denies_sent);
			net2_shard_send(ls, src->slot, &d, NULL, 0);
		}
		return;
	}
	sh = net2_shard_get(ls, m->shard_id, true);
	if (!sh)
		return;
	mxfs_pal_mutex_lock(sh->lock);
	switch (m->type) {
	case N2_ACQUIRE:
	case N2_RELEASE:
		net2_lock_leader_validate(ls, sh, m, src);
		break;
	case N2_APPEND:
		shard_rx_append(ls, sh, m, src->slot);
		break;
	case N2_APPEND_ACK:
		shard_rx_append_ack(ls, sh, m, src->slot);
		break;
	case N2_TERM_VOTE:
		shard_rx_vote(ls, sh, m, src->slot);
		break;
	case N2_SNAPSHOT_REQ:
		shard_rx_snapshot_req(ls, sh, m, src->slot);
		break;
	case N2_SNAPSHOT_CHUNK:
		shard_rx_snapshot_chunk(ls, sh, m, payload, len, recs_off);
		break;
	case N2_RECOVERY_REPORT:
		shard_rx_recovery_report(ls, sh, m, payload, len, recs_off,
		                         src->slot);
		break;
	default:
		break;
	}
	mxfs_pal_mutex_unlock(sh->lock);
}

/* ─── recovery barrier (§7.B reconfiguration step 3) ─── */

static void shard_install_held_report(struct net2_lockspace *ls,
                                      struct net2_shard *sh,
                                      uint16_t src_slot,
                                      const struct mxfs_n2snap_rec *r);

static void shard_start_recovery(struct net2_lockspace *ls,
                                 struct net2_shard *sh)
{
	struct mxfs_n2msg m;
	int i;

	sh->state = SH_RECOVERY;
	sh->recov_active = true;
	sh->recov_reports = 1ULL << ls->self_slot;   /* own report implicit */
	N2DBG("slot%u shard%u RECOV-START mask%llx term%u",
	      ls->self_slot, sh->shard_id,
	      (unsigned long long)ls->member_mask, sh->term);
	net2_ls_stat_bump(ls, &ls->stats.recovery_barriers);
	/* The implicit own report must still INSTALL: the recovering
	 * leader's own client-held grants are part of the closed set
	 * (survivor-holds-and-leads is the common two-survivor case). */
	{
		uint32_t h;

		mxfs_pal_mutex_lock(ls->cl_lock);
		for (h = 0; h < N2_HELD_HASH; h++) {
			struct n2_held *hd;

			for (hd = ls->held[h]; hd; hd = hd->next) {
				struct mxfs_n2snap_rec r;

				if (!hd->used)
					continue;
				if (net2_shard_id_for(ls, &hd->resource) !=
				    sh->shard_id)
					continue;
				memset(&r, 0, sizeof(r));
				r.resource = hd->resource;
				r.kind = N2SR_HELD;
				r.mode = hd->mode;
				r.slot = ls->self_slot;
				r.inc = ls->self_inc;
				r.gen_or_enqseq = hd->gen;
				shard_install_held_report(ls, sh,
				                          ls->self_slot, &r);
			}
		}
		mxfs_pal_mutex_unlock(ls->cl_lock);
	}
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		if (!(ls->member_mask & (1ULL << i)) || i == ls->self_slot)
			continue;
		memset(&m, 0, sizeof(m));
		m.type = N2_RECOVERY_REPORT;
		m.shard_term = sh->term;
		m.shard_id = sh->shard_id;
		m.req_slot = ls->self_slot;
		m.req_inc = ls->self_inc;
		net2_shard_send(ls, (uint16_t)i, &m, NULL, 0);
	}
	/* single-member cluster: barrier closes immediately */
}

/* Rebuild from own held table + finish if all members reported.
 * sh->lock held. */
static void shard_recovery_maybe_finish(struct net2_lockspace *ls,
                                        struct net2_shard *sh)
{
	if ((sh->recov_reports & ls->member_mask) != ls->member_mask)
		return;
	/* Closed set complete: apply gen slack, barrier, activate. */
	sh->grant_gen_next += 1024;          /* §7.B slack */
	sh->dir_epoch_next += 1;
	sh->recov_active = false;
	sh->term = 1;
	sh->leader_slot = ls->self_slot;
	sh->state = SH_ELECTING;             /* barrier flips to ACTIVE */
	{
		struct n2_log_ent t;

		memset(&t, 0, sizeof(t));
		t.op = N2L_TERM;
		t.req_slot = ls->self_slot;
		t.req_inc = ls->self_inc;
		(void)net2_shard_append(ls, sh, &t);
	}
}

static void shard_install_held_report(struct net2_lockspace *ls,
                                      struct net2_shard *sh, uint16_t slot,
                                      const struct mxfs_n2snap_rec *r)
{
	struct n2_lock_rec *rec = net2_rec_get(sh, &r->resource, true);
	uint64_t bit = 1ULL << slot;

	if (!rec)
		return;
	switch (r->mode) {
	case MXFS_LOCK_EX: rec->holders_ex |= bit; break;
	case MXFS_LOCK_PW: rec->holders_pw |= bit; break;
	case MXFS_LOCK_PR: rec->holders_pr |= bit; break;
	case MXFS_LOCK_CW: rec->holders_cw |= bit; break;
	case MXFS_LOCK_CR: rec->holders_cr |= bit; break;
	default: return;
	}
	if (r->gen_or_enqseq > rec->grant_gen)
		rec->grant_gen = r->gen_or_enqseq;
	if (rec->grant_gen >= sh->grant_gen_next)
		sh->grant_gen_next = rec->grant_gen + 1;
	net2_ls_stat_bump(ls, &ls->stats.recovery_recs_rebuilt);
}

static void shard_rx_recovery_report(struct net2_lockspace *ls,
                                     struct net2_shard *sh,
                                     const struct mxfs_n2msg *m,
                                     const uint8_t *payload, uint32_t len,
                                     uint32_t recs_off, uint16_t src_slot)
{
	uint32_t i;

	(void)len;
	if (m->flags & N2F_REPLY) {
		N2DBG("slot%u shard%u RECOV-REPLY from%u recs%u active%d",
		      ls->self_slot, sh->shard_id, src_slot, m->rec_count,
		      sh->recov_active ? 1 : 0);
		if (!sh->recov_active)
			return;
		net2_ls_stat_bump(ls, &ls->stats.recovery_reports_rcvd);
		for (i = 0; i < m->rec_count; i++) {
			struct mxfs_n2snap_rec r;

			mxfs_n2snap_rec_unpack(payload + recs_off +
			                       (size_t)i *
			                       MXFS_N2MSG_SNAPREC_SIZE, &r);
			if (r.kind == N2SR_HELD)
				shard_install_held_report(ls, sh, src_slot,
				                          &r);
		}
		sh->recov_reports |= 1ULL << src_slot;
		shard_recovery_maybe_finish(ls, sh);
		return;
	}
	/* request: reply with every locally-held grant hashing to this
	 * shard (client-side held table — gen-stamped, §7.B). */
	{
		uint8_t recs[32 * MXFS_N2MSG_SNAPREC_SIZE];
		uint32_t n = 0, h;
		struct mxfs_n2msg rep;

		mxfs_pal_mutex_lock(ls->cl_lock);
		for (h = 0; h < N2_HELD_HASH; h++) {
			struct n2_held *hd;

			for (hd = ls->held[h]; hd;
			     hd = hd->next) {
				struct mxfs_n2snap_rec r;

				if (!hd->used)
					continue;
				if (net2_shard_id_for(ls, &hd->resource) !=
				    sh->shard_id)
					continue;
				if (n >= 32)
					break;
				memset(&r, 0, sizeof(r));
				r.resource = hd->resource;
				r.kind = N2SR_HELD;
				r.mode = hd->mode;
				r.slot = ls->self_slot;
				r.inc = ls->self_inc;
				r.gen_or_enqseq = hd->gen;
				mxfs_n2snap_rec_pack(&r, recs + (size_t)n *
				                     MXFS_N2MSG_SNAPREC_SIZE);
				n++;
			}
		}
		mxfs_pal_mutex_unlock(ls->cl_lock);
		N2DBG("slot%u shard%u RECOV-REQ from%u replying%u",
		      ls->self_slot, sh->shard_id, src_slot, n);
		memset(&rep, 0, sizeof(rep));
		rep.type = N2_RECOVERY_REPORT;
		rep.flags = N2F_REPLY;
		rep.shard_term = sh->term;
		rep.shard_id = sh->shard_id;
		rep.req_slot = ls->self_slot;
		rep.req_inc = ls->self_inc;
		rep.chunk_idx = 0;
		rep.chunk_count = 1;
		rep.rec_count = n;
		net2_shard_send(ls, src_slot, &rep, recs,
		                n * MXFS_N2MSG_SNAPREC_SIZE);
	}
}

/* ─── reconfiguration on epoch commit ─── */

static void shard_reconfigure(struct net2_lockspace *ls,
                              struct net2_shard *sh, uint64_t new_epoch)
{
	struct n2_replica old_r[N2_REPLICAS_MAX];
	uint8_t old_n = sh->nreplicas;
	bool was_replica, is_replica, r_changed = false;
	int i;

	if (net2_ls_hook(ls, N2H_RECONFIG, sh->shard_id,
	                 (uint16_t)new_epoch))
		return;
	memcpy(old_r, sh->replicas, sizeof(old_r));
	was_replica = net2_shard_replica_index(sh, ls->self_slot) >= 0;
	net2_shard_derive_config(ls, sh, new_epoch);
	is_replica = net2_shard_replica_index(sh, ls->self_slot) >= 0;

	if (old_n != sh->nreplicas)
		r_changed = true;
	else
		for (i = 0; i < old_n; i++)
			if (old_r[i].slot != sh->replicas[i].slot ||
			    old_r[i].inc != sh->replicas[i].inc)
				r_changed = true;

	if (!r_changed) {
		/* unchanged-R shards keep serving through the transition
		 * (no wholesale purge — the central fix, §7.B step 4) */
		return;
	}

	sh->elect_deadline_ms = 0;
	sh->voted_term = 0;
	sh->cand_term = 0;
	sh->votes = 0;
	sh->term_proven = false;             /* new config, re-prove */

	if (was_replica && !is_replica) {
		/* Source-only: freeze at C; serve snapshots, grant
		 * nothing.  State is dropped when the new group's
		 * barrier lands... we keep it until then (harness scale
		 * makes keeping it indefinitely acceptable; a purge tick
		 * arrives with step 5's real membership plane). */
		sh->state = SH_FROZEN;
		net2_ls_stat_bump(ls, &ls->stats.shards_frozen);
		return;
	}

	if (!is_replica) {
		sh->state = SH_ACTIVE;       /* pure client view */
		return;
	}

	/* I am in the new R. */
	if (sh->leader_slot == ls->self_slot) {
		bool old_survivor = false;

		/* Does any old-R member survive into the new epoch with
		 * state (including me)? */
		for (i = 0; i < old_n; i++)
			if (ls->member_mask & (1ULL << old_r[i].slot))
				old_survivor = true;
		if (was_replica) {
			/* I have the state: barrier to the new quorum at
			 * a term above anything the old group could hold
			 * (followers' terms never exceed their leader's);
			 * fresh replicas NACK → backfill/snapshot path. */
			sh->term = sh->term + 1;
			sh->caught_up_mask = ~0ULL;
			sh->state = SH_ELECTING;
			{
				struct n2_log_ent t;

				memset(&t, 0, sizeof(t));
				t.op = N2L_TERM;
				t.req_slot = ls->self_slot;
				t.req_inc = ls->self_inc;
				(void)net2_shard_append(ls, sh, &t);
			}
		} else if (old_survivor) {
			/* Pull from the surviving old group (max
			 * commit_seq wins — collect from each). */
			struct mxfs_n2msg m;

			sh->state = SH_XFER;
			sh->xfer_active = true;
			sh->xfer_src = 0xFFFF;
			sh->xfer_stream_done = false;
			sh->xfer_await_mask = 0;
			sh->xfer_deadline_ms = mxfs_pal_time_ms() +
			                       2 * ls->elect_base_ms;
			sh->eligible = false;
			sh->term = 1;
			for (i = 0; i < old_n; i++) {
				uint16_t s = old_r[i].slot;

				if (!(ls->member_mask & (1ULL << s)) ||
				    s == ls->self_slot)
					continue;
				sh->xfer_await_mask |= 1ULL << s;
				memset(&m, 0, sizeof(m));
				m.type = N2_SNAPSHOT_REQ;
				m.shard_term = sh->term;
				m.shard_id = sh->shard_id;
				m.req_slot = ls->self_slot;
				m.req_inc = ls->self_inc;
				m.entry_seq = 0;
				net2_shard_send(ls, s, &m, NULL, 0);
			}
		} else {
			/* total shard-state loss — closed-set barrier */
			shard_start_recovery(ls, sh);
		}
	} else {
		/* follower in the new R: wait for the new leader's
		 * barrier/snapshot; keep serving nothing meanwhile */
		if (!was_replica) {
			sh->eligible = (sh->commit_seq == 0);
			sh->term = 1;
		}
		sh->state = SH_ACTIVE;
	}
}

void net2_lockspace_epoch_commit(struct net2_lockspace *ls, uint64_t epoch,
                                 uint64_t member_mask,
                                 const uint32_t *member_incs)
{
	int i;

	mxfs_pal_mutex_lock(ls->lock);
	if (epoch < ls->epoch) {
		mxfs_pal_mutex_unlock(ls->lock);
		return;
	}
	ls->epoch = epoch;
	ls->member_mask = member_mask;
	memcpy(ls->member_inc, member_incs,
	       sizeof(uint32_t) * MXFS_MAX_NODES);
	mxfs_pal_mutex_unlock(ls->lock);

	mxfs_net2_update_view(ls->net, member_mask, epoch);

	for (i = 0; i < N2_SHARD_COUNT; i++) {
		struct net2_shard *sh;

		mxfs_pal_mutex_lock(ls->lock);
		sh = ls->shards[i];
		mxfs_pal_mutex_unlock(ls->lock);
		if (!sh)
			continue;
		mxfs_pal_mutex_lock(sh->lock);
		if (sh->memb_epoch != epoch)
			shard_reconfigure(ls, sh, epoch);
		mxfs_pal_mutex_unlock(sh->lock);
	}
}

void net2_lockspace_suspect(struct net2_lockspace *ls, uint16_t slot)
{
	int i;

	for (i = 0; i < N2_SHARD_COUNT; i++) {
		struct net2_shard *sh;

		mxfs_pal_mutex_lock(ls->lock);
		sh = ls->shards[i];
		mxfs_pal_mutex_unlock(ls->lock);
		if (!sh)
			continue;
		mxfs_pal_mutex_lock(sh->lock);
		if (sh->leader_slot == slot && slot != ls->self_slot &&
		    sh->state == SH_ACTIVE)
			shard_arm_election(ls, sh);
		mxfs_pal_mutex_unlock(sh->lock);
	}
}

/* ─── recv plumbing + RT thread ─── */

static void ls_recv_cb(void *data, const struct mxfs_net2_id *src,
                       const void *payload, uint32_t len)
{
	struct net2_lockspace *ls = data;
	struct mxfs_n2msg m;
	uint32_t recs_off = 0;

	if (ls->poisoned || !ls->running)
		return;
	if (!mxfs_n2msg_is_lockplane(payload, len))
		return;
	if (mxfs_n2msg_unpack(payload, len, &m, &recs_off)) {
		N2DBG("slot%u UNPACK-FAIL from%u len%u",
		      ls->self_slot, src->slot, len);
		return;
	}
	N2DBG("slot%u LSRX from%u type%u rid%llu", ls->self_slot,
	      src->slot, m.type, (unsigned long long)m.request_id);
	switch (m.type) {
	case N2_GRANT:
	case N2_DENY:
	case N2_RELEASE_ACK:
	case N2_BAST:
		net2_lock_client_rx(ls, src, &m);
		break;
	default:
		net2_shard_dispatch(ls, src, &m, payload, len, recs_off);
		break;
	}
}

/* Solicited-pull deadline: reap silent peers.  sh->lock held. */
static void shard_xfer_tick(struct net2_lockspace *ls,
                            struct net2_shard *sh, uint64_t now)
{
	if (sh->xfer_stream_done) {
		/* stream landed; only stragglers were missing */
		shard_xfer_finalize(ls, sh);
		return;
	}
	if (sh->xfer_src == 0xFFFF) {
		/* Nobody answered at all.  If I was pulling as the
		 * designated leader, no live member holds server
		 * state — rebuild it from the CLIENTS via the
		 * closed-set recovery barrier (§7.B: total loss must
		 * never conclude an empty table by fiat). */
		sh->xfer_active = false;
		sh->xfer_await_mask = 0;
		sh->xfer_deadline_ms = 0;
		if (sh->leader_slot == ls->self_slot) {
			shard_start_recovery(ls, sh);
		} else {
			sh->state = SH_ACTIVE;
		}
		return;
	}
	/* Stream stalled mid-flight (snapshot chunks have no per-chunk
	 * retransmit): restart it and keep waiting. */
	{
		struct mxfs_n2msg m;
		uint64_t ask = sh->xfer_await_mask |
		               (1ULL << sh->xfer_src);
		uint16_t s;

		for (s = 0; s < MXFS_MAX_NODES; s++) {
			if (!(ask & (1ULL << s)) || s == ls->self_slot)
				continue;
			memset(&m, 0, sizeof(m));
			m.type = N2_SNAPSHOT_REQ;
			m.shard_term = sh->term;
			m.shard_id = sh->shard_id;
			m.req_slot = ls->self_slot;
			m.req_inc = ls->self_inc;
			net2_shard_send(ls, s, &m, NULL, 0);
		}
		sh->xfer_deadline_ms = now + 2 * ls->elect_base_ms;
	}
}

static void ls_rt_fn(void *arg)
{
	struct net2_lockspace *ls = arg;

	while (ls->running) {
		uint64_t now = mxfs_pal_time_ms();
		int i;

		if (!ls->poisoned) {
			for (i = 0; i < N2_SHARD_COUNT; i++) {
				struct net2_shard *sh;

				mxfs_pal_mutex_lock(ls->lock);
				sh = ls->shards[i];
				mxfs_pal_mutex_unlock(ls->lock);
				if (!sh)
					continue;
				mxfs_pal_mutex_lock(sh->lock);
				if (sh->state == SH_ELECTING &&
				    sh->elect_deadline_ms &&
				    now >= sh->elect_deadline_ms)
					shard_solicit_votes(ls, sh);
				if (sh->xfer_active &&
				    sh->xfer_deadline_ms &&
				    now >= sh->xfer_deadline_ms)
					shard_xfer_tick(ls, sh, now);
				mxfs_pal_mutex_unlock(sh->lock);
			}
			net2_lock_client_tick(ls, now);
		}
		mxfs_pal_sleep_ms(ls->rt_tick_ms);
	}
}

/* ─── lifecycle ─── */

int net2_lockspace_create(struct mxfs_net2_ctx *net,
                          const struct net2_lockspace_cfg *cfg,
                          struct net2_lockspace **out)
{
	struct net2_lockspace *ls;

	if (!net || !cfg || !out)
		return -EINVAL;
	ls = mxfs_pal_alloc(sizeof(*ls));
	if (!ls)
		return -ENOMEM;
	memset(ls, 0, sizeof(*ls));
	ls->net = net;
	ls->self_slot = cfg->self_slot;
	ls->self_inc = cfg->self_inc;
	ls->elect_base_ms = cfg->elect_base_ms ? cfg->elect_base_ms : 150;
	ls->elect_rank_ms = cfg->elect_rank_ms ? cfg->elect_rank_ms : 80;
	ls->client_retry_ms = cfg->client_retry_ms ? cfg->client_retry_ms
	                                           : 400;
	ls->rt_tick_ms = cfg->rt_tick_ms ? cfg->rt_tick_ms : 20;
	ls->max_held = cfg->max_held ? cfg->max_held : 32768;
	ls->seed = cfg->seed ? cfg->seed : 1;
	ls->request_id_next = 1;
	ls->epoch = 1;
	ls->member_mask = 1ULL << cfg->self_slot;
	ls->member_inc[cfg->self_slot] = cfg->self_inc;
	ls->lock = mxfs_pal_mutex_create();
	ls->cl_lock = mxfs_pal_mutex_create();
	ls->cl_cond = mxfs_pal_cond_create();
	ls->stats_lock = mxfs_pal_mutex_create();
	if (!ls->lock || !ls->cl_lock || !ls->cl_cond || !ls->stats_lock) {
		net2_lockspace_destroy(ls);
		return -ENOMEM;
	}
	mxfs_net2_register_recv_cb(net, ls_recv_cb, ls);
	*out = ls;
	return 0;
}

int net2_lockspace_start(struct net2_lockspace *ls)
{
	if (!ls || ls->running)
		return -EINVAL;
	ls->running = true;
	ls->rt_thread = mxfs_pal_thread_create(ls_rt_fn, ls);
	if (!ls->rt_thread) {
		ls->running = false;
		return -ENOMEM;
	}
	return 0;
}

void net2_lockspace_stop(struct net2_lockspace *ls)
{
	if (!ls || !ls->running)
		return;
	ls->running = false;
	mxfs_pal_mutex_lock(ls->cl_lock);
	mxfs_pal_cond_broadcast(ls->cl_cond);   /* wake blocked clients */
	mxfs_pal_mutex_unlock(ls->cl_lock);
	if (ls->rt_thread) {
		mxfs_pal_thread_join(ls->rt_thread);
		ls->rt_thread = NULL;
	}
}

void net2_shard_free_recs(struct net2_shard *sh)
{
	int i;

	for (i = 0; i < N2_REC_HASH; i++) {
		struct n2_lock_rec *rec = sh->recs[i];

		while (rec) {
			struct n2_lock_rec *next = rec->next;
			struct n2_waiter *w = rec->waitq;

			while (w) {
				struct n2_waiter *wn = w->next;

				mxfs_pal_free(w);
				w = wn;
			}
			mxfs_pal_free(rec);
			rec = next;
		}
		sh->recs[i] = NULL;
	}
}

void net2_lockspace_destroy(struct net2_lockspace *ls)
{
	int i, h;

	if (!ls)
		return;
	net2_lockspace_stop(ls);
	if (ls->net)
		mxfs_net2_register_recv_cb(ls->net, NULL, NULL);
	for (i = 0; i < N2_SHARD_COUNT; i++) {
		struct net2_shard *sh = ls->shards[i];

		if (!sh)
			continue;
		net2_shard_free_recs(sh);
		if (sh->opcache)
			mxfs_pal_free(sh->opcache);
		if (sh->lock)
			mxfs_pal_mutex_destroy(sh->lock);
		mxfs_pal_free(sh);
	}
	for (h = 0; h < N2_HELD_HASH; h++) {
		struct n2_held *hd = ls->held[h];

		while (hd) {
			struct n2_held *n = hd->next;

			mxfs_pal_free(hd);
			hd = n;
		}
	}
	if (ls->lock)
		mxfs_pal_mutex_destroy(ls->lock);
	if (ls->cl_lock)
		mxfs_pal_mutex_destroy(ls->cl_lock);
	if (ls->cl_cond)
		mxfs_pal_cond_destroy(ls->cl_cond);
	if (ls->stats_lock)
		mxfs_pal_mutex_destroy(ls->stats_lock);
	mxfs_pal_free(ls);
}

void net2_lockspace_set_bast_cb(struct net2_lockspace *ls, net2_bast_cb cb,
                                void *data)
{
	ls->bast_cb = cb;
	ls->bast_cb_data = data;
}

void net2_lockspace_set_hook(struct net2_lockspace *ls, net2_test_hook hook,
                             void *data)
{
	ls->hook = hook;
	ls->hook_data = data;
}

void net2_lockspace_poison(struct net2_lockspace *ls)
{
	ls->poisoned = true;
}

void net2_lockspace_get_stats(struct net2_lockspace *ls,
                              struct net2_lockspace_stats *out)
{
	mxfs_pal_mutex_lock(ls->stats_lock);
	*out = ls->stats;
	mxfs_pal_mutex_unlock(ls->stats_lock);
}

int net2_lockspace_shard_probe(struct net2_lockspace *ls, uint32_t shard_id,
                               struct net2_shard *snap_out)
{
	struct net2_shard *sh;

	if (shard_id >= N2_SHARD_COUNT)
		return -EINVAL;
	mxfs_pal_mutex_lock(ls->lock);
	sh = ls->shards[shard_id];
	mxfs_pal_mutex_unlock(ls->lock);
	if (!sh)
		return -ENOENT;
	mxfs_pal_mutex_lock(sh->lock);
	*snap_out = *sh;                     /* shallow: pointers are NOT
	                                      * safe to chase in the copy */
	mxfs_pal_mutex_unlock(sh->lock);
	return 0;
}
