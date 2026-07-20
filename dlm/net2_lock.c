/*
 * MXFS — Multinode XFS
 * NET2 lock plane — lock-record semantics + client (§7.B, §11 step 4)
 *
 * Leader side: validate requests, build log entries (the table, the
 * waiter queue and the completed-op cache mutate ONLY at commit-apply
 * — net2_shard.c drives that), emit committed results, and grant
 * queued waiters after releases with the CAW-mirrored ex_streak
 * fairness rule.  Compatibility decisions go through the step-3
 * dlm_shared lift (is_compatible / recompute_granted_mode /
 * lock_compat) over a temporary CAW-slot view of the holder masks —
 * one compatibility matrix for every transport.
 *
 * Client side: blocking acquire/release with §6 op identity, re-issue
 * on silence (rotating over the replica set — a dead leader must not
 * strand a request), redirect on NOT_LEADER, and the client-held
 * table that (a) answers local queries and (b) is the gen-stamped
 * source for the §7.B closed-set recovery reports.
 *
 * Release gen rule (documented deviation, docs/net2.md): a release is
 * valid iff the requester's holder bit is set — bits mutate only via
 * committed entries, so the bit IS the tenure truth and the ABA case
 * a CAW gen-CAS guards against cannot arise inside one (E, term)
 * order.  A release for a resource the requester no longer holds
 * (post-recovery, superseded tenure) returns N2D_STALE_GEN and the
 * client drops its held entry — the XFS -ESTALE re-arm contract.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_shard.h"
#include "net2_lock.h"

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

/* ─── record hash ─── */

struct n2_lock_rec *net2_rec_get(struct net2_shard *sh,
                                 const struct mxfs_resource_id *res,
                                 bool create)
{
	uint32_t b = resource_hash_raw(res) % N2_REC_HASH;
	struct n2_lock_rec *rec;

	for (rec = sh->recs[b]; rec; rec = rec->next)
		if (resource_equal(&rec->resource, res))
			return rec;
	if (!create)
		return NULL;
	rec = mxfs_pal_alloc(sizeof(*rec));
	if (!rec)
		return NULL;
	memset(rec, 0, sizeof(*rec));
	rec->resource = *res;
	rec->last_ex_slot = N2_LAST_EX_NONE;
	rec->next = sh->recs[b];
	sh->recs[b] = rec;
	return rec;
}

/* Temporary CAW-slot view so the shared compatibility code applies. */
static void rec_slot_view(const struct n2_lock_rec *rec, uint64_t exclude_bit,
                          struct mxfs_caw_lock_slot *v)
{
	memset(v, 0, sizeof(*v));
	v->holders_ex = rec->holders_ex & ~exclude_bit;
	v->holders_pw = rec->holders_pw & ~exclude_bit;
	v->holders_pr = rec->holders_pr & ~exclude_bit;
	v->holders_cw = rec->holders_cw & ~exclude_bit;
	v->holders_cr = rec->holders_cr & ~exclude_bit;
}

static bool rec_compatible(const struct n2_lock_rec *rec, uint8_t mode,
                           uint16_t requester)
{
	struct mxfs_caw_lock_slot v;

	rec_slot_view(rec, 1ULL << requester, &v);
	return is_compatible(&v, mode);
}

static void rec_clear_holder(struct n2_lock_rec *rec, uint64_t bit)
{
	rec->holders_ex &= ~bit;
	rec->holders_pw &= ~bit;
	rec->holders_pr &= ~bit;
	rec->holders_cw &= ~bit;
	rec->holders_cr &= ~bit;
}

static void rec_set_holder(struct n2_lock_rec *rec, uint8_t mode,
                           uint64_t bit)
{
	switch (mode) {
	case MXFS_LOCK_EX: rec->holders_ex |= bit; break;
	case MXFS_LOCK_PW: rec->holders_pw |= bit; break;
	case MXFS_LOCK_PR: rec->holders_pr |= bit; break;
	case MXFS_LOCK_CW: rec->holders_cw |= bit; break;
	case MXFS_LOCK_CR: rec->holders_cr |= bit; break;
	}
}

static uint64_t rec_all_holders(const struct n2_lock_rec *rec)
{
	return rec->holders_ex | rec->holders_pw | rec->holders_pr |
	       rec->holders_cw | rec->holders_cr;
}

/* ─── completed-op cache ─── */

static struct n2_opcache_client *opcache_client(struct net2_shard *sh,
                                                uint16_t slot, uint32_t inc,
                                                bool create)
{
	struct n2_opcache_client *oc = &sh->opcache[slot % MXFS_MAX_NODES];

	if (oc->used && oc->slot == slot && oc->inc == inc)
		return oc;
	if (!create)
		return NULL;
	/* new incarnation supersedes the ring (stale-inc results are
	 * unreachable anyway — the envelope inc must match) */
	memset(oc, 0, sizeof(*oc));
	oc->used = true;
	oc->slot = slot;
	oc->inc = inc;
	return oc;
}

static struct n2_opcache_ent *opcache_find(struct net2_shard *sh,
                                           uint16_t slot, uint32_t inc,
                                           uint64_t request_id)
{
	struct n2_opcache_client *oc = opcache_client(sh, slot, inc, false);
	int i;

	if (!oc)
		return NULL;
	for (i = 0; i < N2_OPCACHE_RING; i++)
		if (oc->ring[i].used &&
		    oc->ring[i].request_id == request_id)
			return &oc->ring[i];
	return NULL;
}

static void opcache_store(struct net2_shard *sh, uint16_t slot, uint32_t inc,
                          uint64_t request_id, uint8_t status, uint8_t mode,
                          uint64_t gen)
{
	struct n2_opcache_client *oc = opcache_client(sh, slot, inc, true);
	struct n2_opcache_ent *oe;

	if (!oc)
		return;
	oe = &oc->ring[oc->next_idx];
	oc->next_idx = (oc->next_idx + 1) % N2_OPCACHE_RING;
	oe->used = true;
	oe->request_id = request_id;
	oe->status = status;
	oe->mode = mode;
	oe->gen = gen;
}

/* ─── waiters ─── */

static bool waitq_has(const struct n2_lock_rec *rec, uint16_t slot,
                      uint32_t inc, uint64_t request_id)
{
	const struct n2_waiter *w;

	for (w = rec->waitq; w; w = w->next)
		if (w->slot == slot && w->inc == inc &&
		    w->request_id == request_id)
			return true;
	return false;
}

static void waitq_push(struct net2_shard *sh, struct n2_lock_rec *rec,
                       uint16_t slot, uint32_t inc, uint64_t request_id,
                       uint8_t mode, uint64_t enq_seq)
{
	struct n2_waiter *w;

	if (waitq_has(rec, slot, inc, request_id))
		return;
	w = mxfs_pal_alloc(sizeof(*w));
	if (!w)
		return;
	w->slot = slot;
	w->inc = inc;
	w->request_id = request_id;
	w->mode = mode;
	w->enq_seq = enq_seq;
	w->next = NULL;
	if (rec->waitq_tail)
		rec->waitq_tail->next = w;
	else
		rec->waitq = w;
	rec->waitq_tail = w;
	if (enq_seq >= sh->enq_seq_next)
		sh->enq_seq_next = enq_seq + 1;
}

static void waitq_remove(struct n2_lock_rec *rec, uint16_t slot, uint32_t inc,
                         uint64_t request_id)
{
	struct n2_waiter **pw = &rec->waitq, *prev = NULL;

	while (*pw) {
		struct n2_waiter *w = *pw;

		if (w->slot == slot && w->inc == inc &&
		    w->request_id == request_id) {
			*pw = w->next;
			if (rec->waitq_tail == w)
				rec->waitq_tail = prev;
			mxfs_pal_free(w);
			return;
		}
		prev = w;
		pw = &w->next;
	}
}

/* ─── deterministic apply (every replica, commit order) ─── */

void net2_lock_apply_entry(struct net2_lockspace *ls, struct net2_shard *sh,
                           const struct n2_log_ent *e)
{
	struct n2_lock_rec *rec;
	uint64_t bit = 1ULL << e->req_slot;

	switch (e->op) {
	case N2L_GRANT:
		rec = net2_rec_get(sh, &e->resource, true);
		if (!rec)
			return;
		if (e->msg_flags & N2F_FROM_WAITQ)
			waitq_remove(rec, e->req_slot, e->req_inc,
			             e->request_id);
		rec_clear_holder(rec, bit);       /* convert-safe */
		rec_set_holder(rec, e->mode, bit);
		rec->grant_gen = e->grant_gen;
		if (e->dir_epoch)
			rec->dir_epoch = e->dir_epoch;
		if (e->mode == MXFS_LOCK_EX) {
			rec->handoff = (rec->last_ex_slot != N2_LAST_EX_NONE &&
			                rec->last_ex_slot != e->req_slot);
			rec->last_ex_slot = e->req_slot;
		}
		if (e->mode == MXFS_LOCK_EX || e->mode == MXFS_LOCK_PW) {
			if (rec->ex_streak < 255)
				rec->ex_streak++;
		} else {
			rec->ex_streak = 0;
		}
		rec->pending_revoke_mask &= ~bit;
		if (e->grant_gen >= sh->grant_gen_next)
			sh->grant_gen_next = e->grant_gen + 1;
		if (e->dir_epoch && e->dir_epoch >= sh->dir_epoch_next)
			sh->dir_epoch_next = e->dir_epoch + 1;
		net2_ls_stat_max(ls, &ls->stats.gen_high_water, e->grant_gen);
		opcache_store(sh, e->req_slot, e->req_inc, e->request_id,
		              0, e->mode, e->grant_gen);
		break;
	case N2L_WAIT:
		rec = net2_rec_get(sh, &e->resource, true);
		if (!rec)
			return;
		/* enq_seq rides the entry's grant_gen field */
		waitq_push(sh, rec, e->req_slot, e->req_inc, e->request_id,
		           e->mode, e->grant_gen);
		break;
	case N2L_RELEASE:
		rec = net2_rec_get(sh, &e->resource, false);
		if (!rec)
			return;
		rec_clear_holder(rec, bit);
		rec->pending_revoke_mask &= ~bit;
		if (e->dir_epoch) {
			rec->dir_epoch = e->dir_epoch;
			if (e->dir_epoch >= sh->dir_epoch_next)
				sh->dir_epoch_next = e->dir_epoch + 1;
		}
		opcache_store(sh, e->req_slot, e->req_inc, e->request_id,
		              0, e->mode, e->grant_gen);
		break;
	case N2L_EX_PENDING:
		rec = net2_rec_get(sh, &e->resource, true);
		if (!rec)
			return;
		/* conflicting holders at apply time — deterministic:
		 * every replica applies against identical state */
		{
			struct mxfs_caw_lock_slot v;
			uint64_t conflict = 0;
			int m;

			rec_slot_view(rec, bit, &v);
			for (m = MXFS_LOCK_CR; m <= MXFS_LOCK_EX; m++) {
				uint64_t mask = holders_for_mode_const(&v,
				                                (uint8_t)m);

				if (mask && !lock_compat[m][e->mode])
					conflict |= mask;
			}
			rec->pending_revoke_mask = conflict;
		}
		waitq_push(sh, rec, e->req_slot, e->req_inc, e->request_id,
		           e->mode, e->grant_gen);
		break;
	case N2L_TERM:
	case N2L_CAUGHT_UP:
	default:
		/* shard machinery owns these */
		break;
	}
}

/* ─── leader: emit committed results ─── */

static void send_result(struct net2_lockspace *ls, struct net2_shard *sh,
                        uint16_t type, uint16_t flags,
                        const struct n2_log_ent *e, uint8_t status)
{
	struct mxfs_n2msg m;

	memset(&m, 0, sizeof(m));
	m.type = type;
	m.flags = flags;
	m.shard_term = sh->term;
	m.shard_id = sh->shard_id;
	m.req_slot = e->req_slot;
	m.req_inc = e->req_inc;
	m.request_id = e->request_id;
	m.resource = e->resource;
	m.mode = e->mode;
	m.status = status;
	m.grant_gen = e->grant_gen;
	m.dir_epoch = e->dir_epoch;
	N2DBG("slot%u shard%u RESULT type%u to%u rid%llu st%u",
	      ls->self_slot, sh->shard_id, type, e->req_slot,
	      (unsigned long long)e->request_id, status);
	net2_shard_send(ls, e->req_slot, &m, NULL, 0);
}

void net2_lock_emit_result(struct net2_lockspace *ls, struct net2_shard *sh,
                           const struct n2_log_ent *e)
{
	if (!net2_shard_i_am_leader(ls, sh))
		return;
	switch (e->op) {
	case N2L_GRANT:
		net2_ls_stat_bump(ls, &ls->stats.grants_sent);
		send_result(ls, sh, N2_GRANT, e->msg_flags, e, 0);
		break;
	case N2L_RELEASE:
		send_result(ls, sh, N2_RELEASE_ACK, 0, e, 0);
		break;
	case N2L_EX_PENDING: {
		struct n2_lock_rec *rec = net2_rec_get(sh, &e->resource,
		                                       false);
		uint64_t mask;
		int s;

		if (net2_ls_hook(ls, N2H_REVOKE_PENDING, sh->shard_id,
		                 e->req_slot))
			return;
		if (!rec)
			return;
		mask = rec->pending_revoke_mask;
		for (s = 0; s < MXFS_MAX_NODES; s++) {
			struct mxfs_n2msg b;

			if (!(mask & (1ULL << s)))
				continue;
			memset(&b, 0, sizeof(b));
			b.type = N2_BAST;
			b.shard_term = sh->term;
			b.shard_id = sh->shard_id;
			b.req_slot = e->req_slot;   /* who wants it */
			b.req_inc = e->req_inc;
			b.request_id = e->request_id;
			b.resource = e->resource;
			b.mode = e->mode;           /* wanted mode */
			b.grant_gen = rec->grant_gen;
			net2_ls_stat_bump(ls, &ls->stats.basts_sent);
			net2_shard_send(ls, (uint16_t)s, &b, NULL, 0);
		}
		break;
	}
	default:
		break;
	}
}

/* ─── leader: waiter grants after a release (fairness per §7.B) ─── */

static struct n2_waiter *pick_next_waiter(struct n2_lock_rec *rec)
{
	struct n2_waiter *head = rec->waitq, *w;

	if (!head)
		return NULL;
	/* ex_streak fairness (CAW mirror): after 3 consecutive EX/PW
	 * grants with PR-class waiters queued, grant the PR class. */
	if ((head->mode == MXFS_LOCK_EX || head->mode == MXFS_LOCK_PW) &&
	    rec->ex_streak >= 3) {
		for (w = head; w; w = w->next)
			if (w->mode == MXFS_LOCK_PR ||
			    w->mode == MXFS_LOCK_CR)
				return w;
	}
	return head;
}

static void grant_waiters(struct net2_lockspace *ls, struct net2_shard *sh,
                          struct n2_lock_rec *rec)
{
	int guard = 0;

	while (guard++ < MXFS_MAX_NODES * 2) {
		struct n2_waiter *w = pick_next_waiter(rec);
		struct n2_log_ent g;
		uint16_t wslot;
		uint32_t winc;
		uint64_t wrid;

		if (!w)
			return;
		if (rec->pending_revoke_mask)
			return;              /* drain still in progress */
		if (!rec_compatible(rec, w->mode, w->slot))
			return;
		wslot = w->slot;
		winc = w->inc;
		wrid = w->request_id;
		memset(&g, 0, sizeof(g));
		g.op = N2L_GRANT;
		g.resource = rec->resource;
		g.mode = w->mode;
		g.req_slot = wslot;
		g.req_inc = winc;
		g.request_id = wrid;
		g.grant_gen = sh->grant_gen_next;
		g.msg_flags = N2F_FROM_WAITQ;
		if (net2_shard_append(ls, sh, &g))
			return;
		/* apply (on commit) pops the waiter — w may be freed
		 * now.  If the id is still queued the entry has not
		 * committed yet (multi-replica): stop; the commit path
		 * re-enters here via post_release/emit ordering. */
		if (waitq_has(rec, wslot, winc, wrid))
			return;
	}
}

void net2_lock_post_release_grants(struct net2_lockspace *ls,
                                   struct net2_shard *sh,
                                   const struct mxfs_resource_id *res)
{
	struct n2_lock_rec *rec;
	int b;

	if (!net2_shard_i_am_leader(ls, sh))
		return;
	if (res) {
		rec = net2_rec_get(sh, res, false);
		if (rec)
			grant_waiters(ls, sh, rec);
		return;
	}
	/* resume after takeover: scan everything */
	for (b = 0; b < N2_REC_HASH; b++)
		for (rec = sh->recs[b]; rec; rec = rec->next)
			grant_waiters(ls, sh, rec);
}

/* ─── leader: request validation ─── */

static void deny(struct net2_lockspace *ls, struct net2_shard *sh,
                 const struct mxfs_n2msg *m, uint8_t reason, uint16_t hint)
{
	struct mxfs_n2msg d;

	memset(&d, 0, sizeof(d));
	d.type = N2_DENY;
	d.shard_term = sh->term;
	d.shard_id = sh->shard_id;
	d.req_slot = m->req_slot;
	d.req_inc = m->req_inc;
	d.request_id = m->request_id;
	d.resource = m->resource;
	d.mode = m->mode;
	d.status = reason;
	d.leader_hint = hint;
	N2DBG("slot%u shard%u DENY to%u rid%llu reason%u hint%u st%d term%u",
	      ls->self_slot, sh->shard_id, m->req_slot,
	      (unsigned long long)m->request_id, reason, hint,
	      (int)sh->state, sh->term);
	net2_ls_stat_bump(ls, &ls->stats.denies_sent);
	net2_shard_send(ls, m->req_slot, &d, NULL, 0);
}

void net2_lock_leader_validate(struct net2_lockspace *ls,
                               struct net2_shard *sh,
                               const struct mxfs_n2msg *m,
                               const struct mxfs_net2_id *src)
{
	struct n2_lock_rec *rec;
	struct n2_opcache_ent *oe;
	struct n2_log_ent e;
	uint64_t bit = 1ULL << m->req_slot;

	(void)src;
	if (!net2_shard_i_am_leader(ls, sh)) {
		deny(ls, sh, m, N2D_NOT_LEADER, sh->leader_slot);
		return;
	}
	if (sh->state != SH_ACTIVE) {
		deny(ls, sh, m, N2D_RETRY, sh->leader_slot);
		return;
	}
	if (!sh->term_proven) {
		/* Leadership not yet quorum-proven for this tenure: no
		 * authoritative answer may leave this node (an empty
		 * restarted rank-0 would deny releases it simply cannot
		 * see).  Kick the barrier; the client's cadence retries
		 * land after it commits — or after the NACK exchange
		 * forces a pull from a more-complete follower. */
		net2_shard_prove_term(ls, sh);
		deny(ls, sh, m, N2D_RETRY, sh->leader_slot);
		return;
	}
	/* effect idempotency: completed op → original result */
	oe = opcache_find(sh, m->req_slot, m->req_inc, m->request_id);
	if (oe) {
		struct n2_log_ent r;

		net2_ls_stat_bump(ls, &ls->stats.dup_op_idempotent);
		memset(&r, 0, sizeof(r));
		r.resource = m->resource;
		r.mode = oe->mode;
		r.req_slot = m->req_slot;
		r.req_inc = m->req_inc;
		r.request_id = m->request_id;
		r.grant_gen = oe->gen;
		if (m->type == N2_ACQUIRE)
			send_result(ls, sh, N2_GRANT, 0, &r, oe->status);
		else
			send_result(ls, sh, N2_RELEASE_ACK, 0, &r,
			            oe->status);
		return;
	}

	if (m->type == N2_ACQUIRE) {
		uint8_t held;

		net2_ls_stat_bump(ls, &ls->stats.acquires);
		rec = net2_rec_get(sh, &m->resource, true);
		if (!rec)
			return;
		/* already the holder at this mode (client re-issue of a
		 * NEW request_id after recovery rebuilt its bit): re-ack
		 * the existing tenure without a new entry. */
		held = MXFS_LOCK_NL;
		if (rec->holders_ex & bit) held = MXFS_LOCK_EX;
		else if (rec->holders_pw & bit) held = MXFS_LOCK_PW;
		else if (rec->holders_pr & bit) held = MXFS_LOCK_PR;
		else if (rec->holders_cw & bit) held = MXFS_LOCK_CW;
		else if (rec->holders_cr & bit) held = MXFS_LOCK_CR;
		if (held == m->mode) {
			struct n2_log_ent r;

			memset(&r, 0, sizeof(r));
			r.resource = m->resource;
			r.mode = m->mode;
			r.req_slot = m->req_slot;
			r.req_inc = m->req_inc;
			r.request_id = m->request_id;
			r.grant_gen = rec->grant_gen;
			r.dir_epoch = rec->dir_epoch;
			send_result(ls, sh, N2_GRANT, 0, &r, 0);
			return;
		}
		if (waitq_has(rec, m->req_slot, m->req_inc, m->request_id))
			return;              /* re-issue while queued */
		memset(&e, 0, sizeof(e));
		e.resource = m->resource;
		e.mode = m->mode;
		e.req_slot = m->req_slot;
		e.req_inc = m->req_inc;
		e.request_id = m->request_id;
		if (rec_compatible(rec, m->mode, m->req_slot)) {
			e.op = N2L_GRANT;
			e.grant_gen = sh->grant_gen_next;
			if (m->mode == MXFS_LOCK_EX)
				e.dir_epoch = sh->dir_epoch_next;
		} else if (!rec->pending_revoke_mask) {
			/* first blocked request marks the conflicting
			 * holders and BASTs them (§7.B EX-against-PR is
			 * one instance; a PR want against an EX holder
			 * pokes the holder just the same) */
			e.op = N2L_EX_PENDING;
			e.grant_gen = sh->enq_seq_next;   /* enq order */
		} else {
			e.op = N2L_WAIT;
			e.grant_gen = sh->enq_seq_next;   /* enq order */
		}
		(void)net2_shard_append(ls, sh, &e);
		return;
	}

	/* N2_RELEASE */
	net2_ls_stat_bump(ls, &ls->stats.releases);
	rec = net2_rec_get(sh, &m->resource, false);
	if (!rec || !(rec_all_holders(rec) & bit)) {
		struct n2_log_ent r;

		N2DBG("slot%u shard%u REL-STALE from%u rid%llu rec%d holders%llx",
		      ls->self_slot, sh->shard_id, m->req_slot,
		      (unsigned long long)m->request_id, rec ? 1 : 0,
		      rec ? (unsigned long long)rec_all_holders(rec) : 0);
		net2_ls_stat_bump(ls, &ls->stats.stale_gen_denies);
		memset(&r, 0, sizeof(r));
		r.resource = m->resource;
		r.req_slot = m->req_slot;
		r.req_inc = m->req_inc;
		r.request_id = m->request_id;
		r.grant_gen = m->grant_gen;
		send_result(ls, sh, N2_RELEASE_ACK, 0, &r, N2D_STALE_GEN);
		return;
	}
	if (net2_ls_hook(ls, N2H_PRE_RELEASE_COMMIT, sh->shard_id,
	                 m->req_slot))
		return;
	memset(&e, 0, sizeof(e));
	e.op = N2L_RELEASE;
	e.resource = m->resource;
	e.mode = m->mode;
	e.req_slot = m->req_slot;
	e.req_inc = m->req_inc;
	e.request_id = m->request_id;
	e.grant_gen = m->grant_gen;
	if (rec->holders_ex & bit)
		e.dir_epoch = sh->dir_epoch_next;   /* EX release publishes */
	(void)net2_shard_append(ls, sh, &e);
}

/* ─── client side ─── */

static int creq_alloc(struct net2_lockspace *ls, struct n2_creq **out);

static struct n2_creq *creq_find(struct net2_lockspace *ls,
                                 uint64_t request_id)
{
	int i;

	for (i = 0; i < N2_CREQ_MAX; i++)
		if (ls->creqs[i].used &&
		    ls->creqs[i].request_id == request_id)
			return &ls->creqs[i];
	return NULL;
}

static uint32_t held_bucket(const struct mxfs_resource_id *res)
{
	return resource_hash_raw(res) % N2_HELD_HASH;
}

static void held_insert(struct net2_lockspace *ls,
                        const struct mxfs_resource_id *res, uint8_t mode,
                        uint64_t gen)
{
	uint32_t b = held_bucket(res);
	struct n2_held *hd;

	for (hd = ls->held[b]; hd; hd = hd->next) {
		if (hd->used && resource_equal(&hd->resource, res)) {
			hd->mode = mode;
			hd->gen = gen;
			return;
		}
	}
	hd = mxfs_pal_alloc(sizeof(*hd));
	if (!hd)
		return;
	hd->used = true;
	hd->resource = *res;
	hd->mode = mode;
	hd->gen = gen;
	hd->next = ls->held[b];
	ls->held[b] = hd;
	ls->held_count++;
}

static void held_remove(struct net2_lockspace *ls,
                        const struct mxfs_resource_id *res)
{
	uint32_t b = held_bucket(res);
	struct n2_held **p = &ls->held[b];

	while (*p) {
		struct n2_held *hd = *p;

		if (hd->used && resource_equal(&hd->resource, res)) {
			*p = hd->next;
			mxfs_pal_free(hd);
			if (ls->held_count)
				ls->held_count--;
			return;
		}
		p = &hd->next;
	}
}

uint8_t net2_lock_held_mode(struct net2_lockspace *ls,
                            const struct mxfs_resource_id *resource,
                            uint64_t *gen_out)
{
	uint32_t b = held_bucket(resource);
	struct n2_held *hd;
	uint8_t mode = MXFS_LOCK_NL;

	mxfs_pal_mutex_lock(ls->cl_lock);
	for (hd = ls->held[b]; hd; hd = hd->next) {
		if (hd->used && resource_equal(&hd->resource, resource)) {
			mode = hd->mode;
			if (gen_out)
				*gen_out = hd->gen;
			break;
		}
	}
	mxfs_pal_mutex_unlock(ls->cl_lock);
	return mode;
}

/* Target for a request: the shard's replica ranked (retries mod n) —
 * rank 0 is the leader by default and rotation survives a silent dead
 * leader.  Redirect hints override via creq->target_slot. */
static uint16_t creq_pick_target(struct net2_lockspace *ls,
                                 const struct mxfs_resource_id *res,
                                 uint32_t retries)
{
	uint32_t sid = net2_shard_id_for(ls, res);
	struct net2_shard *sh = net2_shard_get(ls, sid, true);
	uint16_t t;

	if (!sh)
		return ls->self_slot;
	mxfs_pal_mutex_lock(sh->lock);
	if (sh->nreplicas == 0)
		t = ls->self_slot;
	else if (retries == 0)
		t = sh->leader_slot;
	else
		t = sh->replicas[retries % sh->nreplicas].slot;
	mxfs_pal_mutex_unlock(sh->lock);
	return t;
}

static void creq_send(struct net2_lockspace *ls, struct n2_creq *cr)
{
	struct mxfs_n2msg m;

	memset(&m, 0, sizeof(m));
	m.type = cr->is_release ? N2_RELEASE : N2_ACQUIRE;
	m.shard_id = net2_shard_id_for(ls, &cr->resource);
	m.req_slot = ls->self_slot;
	m.req_inc = ls->self_inc;
	m.request_id = cr->request_id;
	m.resource = cr->resource;
	m.mode = cr->mode;
	m.grant_gen = cr->rel_gen;
	N2DBG("slot%u CSEND rid%llu to%u rel%d", ls->self_slot,
	      (unsigned long long)cr->request_id, cr->target_slot,
	      cr->is_release ? 1 : 0);
	net2_shard_send(ls, cr->target_slot, &m, NULL, 0);
}

void net2_lock_client_rx(struct net2_lockspace *ls,
                         const struct mxfs_net2_id *src,
                         const struct mxfs_n2msg *m)
{
	struct n2_creq *cr;
	bool do_bast = false;
	struct mxfs_resource_id bast_res;
	uint8_t bast_mode = 0;
	uint64_t bast_gen = 0;

	(void)src;
	mxfs_pal_mutex_lock(ls->cl_lock);
	switch (m->type) {
	case N2_GRANT:
		cr = creq_find(ls, m->request_id);
		if (cr && !cr->is_release && cr->state != CR_DONE) {
			held_insert(ls, &m->resource, m->mode,
			            m->grant_gen);
			cr->state = CR_DONE;
			cr->status = m->status;
			cr->gen = m->grant_gen;
			cr->dir_epoch = m->dir_epoch;
			mxfs_pal_cond_broadcast(ls->cl_cond);
		} else {
			/* No live acquire waiter for this grant. */
			uint32_t b = held_bucket(&m->resource);
			struct n2_held *hd;
			bool holder = false;

			for (hd = ls->held[b]; hd; hd = hd->next)
				if (hd->used &&
				    resource_equal(&hd->resource,
				                   &m->resource)) {
					holder = true;
					break;
				}
			if (holder) {
				/* duplicate re-delivery of a hold we
				 * own (failover re-emit) — refresh */
				held_insert(ls, &m->resource, m->mode,
				            m->grant_gen);
			} else {
				/* Orphan: a canceled/timed-out acquire
				 * got granted anyway.  The leader now
				 * counts us as holder — release it at
				 * once or it is a phantom hold nobody
				 * ever clears.  Deferred to the tick:
				 * sending here would take the shard
				 * lock under cl_lock (order is
				 * shard > cl). */
				struct n2_creq *oc;

				if (creq_alloc(ls, &oc) == 0) {
					oc->resource = m->resource;
					oc->is_release = true;
					oc->detached = true;
					oc->rel_gen = m->grant_gen;
					oc->state = CR_PENDING;
					oc->target_slot = src->slot;
					oc->last_tx_ms = 0;
					net2_ls_stat_bump(ls,
					    &ls->stats.client_reissues);
				}
			}
		}
		break;
	case N2_RELEASE_ACK:
		cr = creq_find(ls, m->request_id);
		if ((m->status == 0 || m->status == N2D_STALE_GEN) &&
		    !(cr && cr->detached))
			held_remove(ls, &m->resource);
		if (cr && cr->is_release && cr->state != CR_DONE) {
			if (cr->detached) {
				cr->used = false;   /* self-reap */
			} else {
				cr->state = CR_DONE;
				cr->status = m->status;
				cr->gen = m->grant_gen;
				mxfs_pal_cond_broadcast(ls->cl_cond);
			}
		}
		break;
	case N2_DENY:
		cr = creq_find(ls, m->request_id);
		if (cr && cr->state == CR_PENDING) {
			switch (m->status) {
			case N2D_NOT_LEADER:
				if (m->leader_hint < MXFS_MAX_NODES &&
				    m->leader_hint != ls->self_slot) {
					cr->target_slot = m->leader_hint;
					net2_ls_stat_bump(ls,
					        &ls->stats.redirects_followed);
					cr->last_tx_ms = 0;   /* resend now */
				}
				break;
			case N2D_STALE_GEN:
				if (cr->is_release && cr->detached) {
					cr->used = false;   /* self-reap */
				} else if (cr->is_release) {
					cr->state = CR_DONE;
					cr->status = m->status;
					held_remove(ls, &m->resource);
					mxfs_pal_cond_broadcast(ls->cl_cond);
				}
				break;
			default:
				/* STALE_EPOCH/STALE_TERM/RETRY: cadence
				 * re-issue restamps the current epoch */
				break;
			}
		}
		break;
	case N2_BAST:
		do_bast = ls->bast_cb != NULL;
		bast_res = m->resource;
		bast_mode = m->mode;
		bast_gen = m->grant_gen;
		break;
	default:
		break;
	}
	mxfs_pal_mutex_unlock(ls->cl_lock);
	if (do_bast)
		ls->bast_cb(ls->bast_cb_data, &bast_res, bast_mode, bast_gen);
}

void net2_lock_client_tick(struct net2_lockspace *ls, uint64_t now_ms)
{
	struct { uint64_t rid; } pend[N2_CREQ_MAX];
	int npend = 0, i;

	mxfs_pal_mutex_lock(ls->cl_lock);
	for (i = 0; i < N2_CREQ_MAX; i++) {
		struct n2_creq *cr = &ls->creqs[i];

		if (cr->used && cr->state == CR_PENDING &&
		    now_ms - cr->last_tx_ms >= ls->client_retry_ms)
			pend[npend++].rid = cr->request_id;
	}
	mxfs_pal_mutex_unlock(ls->cl_lock);

	for (i = 0; i < npend; i++) {
		struct n2_creq *cr;
		struct n2_creq copy;
		bool send = false;
		uint32_t retries = 0;
		uint16_t t;

		mxfs_pal_mutex_lock(ls->cl_lock);
		cr = creq_find(ls, pend[i].rid);
		if (cr && cr->state == CR_PENDING) {
			cr->retries++;
			retries = cr->retries;
			copy = *cr;
			send = true;
		}
		mxfs_pal_mutex_unlock(ls->cl_lock);
		if (!send)
			continue;
		/* rotate target over the replica set on repeated
		 * silence (dead leader pre-election must not strand
		 * the request); a NOT_LEADER redirect took effect via
		 * target_slot and survives until the next rotation */
		t = creq_pick_target(ls, &copy.resource, retries);
		mxfs_pal_mutex_lock(ls->cl_lock);
		cr = creq_find(ls, pend[i].rid);
		if (cr && cr->state == CR_PENDING) {
			if (cr->target_slot == copy.target_slot &&
			    retries > 1)
				cr->target_slot = t;
			cr->last_tx_ms = now_ms;
			copy = *cr;
		} else {
			send = false;
		}
		mxfs_pal_mutex_unlock(ls->cl_lock);
		if (send) {
			net2_ls_stat_bump(ls, &ls->stats.client_reissues);
			creq_send(ls, &copy);
		}
	}
}

static int creq_alloc(struct net2_lockspace *ls, struct n2_creq **out)
{
	int i;

	for (i = 0; i < N2_CREQ_MAX; i++) {
		if (!ls->creqs[i].used) {
			memset(&ls->creqs[i], 0, sizeof(ls->creqs[i]));
			ls->creqs[i].used = true;
			ls->creqs[i].request_id = ls->request_id_next++;
			*out = &ls->creqs[i];
			return 0;
		}
	}
	return -ENOSPC;
}

static int creq_wait(struct net2_lockspace *ls, uint64_t request_id,
                     uint32_t deadline_ms, struct n2_creq *result)
{
	uint64_t t0 = mxfs_pal_time_ms();
	struct n2_creq *cr;

	mxfs_pal_mutex_lock(ls->cl_lock);
	for (;;) {
		uint64_t left;

		cr = creq_find(ls, request_id);
		if (!cr) {
			mxfs_pal_mutex_unlock(ls->cl_lock);
			return -EINVAL;
		}
		if (cr->state == CR_DONE) {
			*result = *cr;
			cr->used = false;
			mxfs_pal_mutex_unlock(ls->cl_lock);
			return 0;
		}
		if (!ls->running) {
			cr->used = false;
			mxfs_pal_mutex_unlock(ls->cl_lock);
			return -ESHUTDOWN;
		}
		left = mxfs_pal_time_ms() - t0;
		if (left >= deadline_ms) {
			/* ACQUIRE: cancel — a request whose caller gave
			 * up must never be granted later (phantom hold
			 * nobody releases; a racing in-flight GRANT is
			 * auto-released by the orphan path in client_rx).
			 * RELEASE: detach — it must still clear the
			 * holder bit eventually, so it keeps re-issuing
			 * and self-reaps on RELEASE_ACK/STALE_GEN. */
			if (cr->is_release)
				cr->detached = true;
			else
				cr->used = false;
			mxfs_pal_mutex_unlock(ls->cl_lock);
			return -ETIMEDOUT;
		}
		(void)mxfs_pal_cond_timedwait(ls->cl_cond, ls->cl_lock,
		                              (uint32_t)(deadline_ms - left) <
		                              50 ? (uint32_t)(deadline_ms -
		                                              left) : 50);
	}
}

int net2_lock_acquire(struct net2_lockspace *ls,
                      const struct mxfs_resource_id *resource, uint8_t mode,
                      uint32_t deadline_ms, uint64_t *gen_out,
                      uint64_t *dir_epoch_out)
{
	struct n2_creq *cr, copy, result;
	uint16_t target;
	int rc;

	if (!ls || !resource || mode > MXFS_LOCK_EX)
		return -EINVAL;
	if (ls->held_count >= ls->max_held)
		return -EAGAIN;
	target = creq_pick_target(ls, resource, 0);
	mxfs_pal_mutex_lock(ls->cl_lock);
	rc = creq_alloc(ls, &cr);
	if (rc) {
		mxfs_pal_mutex_unlock(ls->cl_lock);
		return rc;
	}
	cr->resource = *resource;
	cr->mode = mode;
	cr->state = CR_PENDING;
	cr->target_slot = target;
	cr->last_tx_ms = mxfs_pal_time_ms();
	copy = *cr;
	mxfs_pal_mutex_unlock(ls->cl_lock);
	creq_send(ls, &copy);
	rc = creq_wait(ls, copy.request_id, deadline_ms, &result);
	if (rc)
		return rc;
	if (result.status != 0)
		return -EACCES;
	if (gen_out)
		*gen_out = result.gen;
	if (dir_epoch_out)
		*dir_epoch_out = result.dir_epoch;
	return 0;
}

int net2_lock_release(struct net2_lockspace *ls,
                      const struct mxfs_resource_id *resource, uint64_t gen,
                      uint32_t deadline_ms)
{
	struct n2_creq *cr, copy, result;
	uint16_t target;
	int rc;

	if (!ls || !resource)
		return -EINVAL;
	target = creq_pick_target(ls, resource, 0);
	mxfs_pal_mutex_lock(ls->cl_lock);
	rc = creq_alloc(ls, &cr);
	if (rc) {
		mxfs_pal_mutex_unlock(ls->cl_lock);
		return rc;
	}
	cr->resource = *resource;
	cr->is_release = true;
	cr->rel_gen = gen;
	cr->state = CR_PENDING;
	cr->target_slot = target;
	cr->last_tx_ms = mxfs_pal_time_ms();
	copy = *cr;
	mxfs_pal_mutex_unlock(ls->cl_lock);
	creq_send(ls, &copy);
	rc = creq_wait(ls, copy.request_id, deadline_ms, &result);
	if (rc)
		return rc;
	if (result.status == N2D_STALE_GEN)
		return -ESTALE;
	return result.status ? -EIO : 0;
}
