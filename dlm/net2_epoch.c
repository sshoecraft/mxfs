// SPDX-License-Identifier: GPL-2.0
/*
 * net2_epoch — MEPOCH single-decree membership-epoch authority (§7.C).
 * See net2_epoch.h for the model.  Both builds, PAL only.
 */
#include "net2_epoch.h"
#include "net2_msg.h"

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#endif

static int n2edbg(void)
{
#ifndef __KERNEL__
	static int v = -1;

	if (v < 0) {
		const char *e = getenv("N2_DEBUG");

		v = (e && *e && *e != '0') ? 1 : 0;
	}
	return v;
#else
	return 0;
#endif
}

#ifndef __KERNEL__
#define MEDBG(fmt, ...) do { if (n2edbg()) fprintf(stderr, \
	"MEDBG " fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define MEDBG(fmt, ...) do { } while (0)
#endif

struct net2_mepoch {
	struct net2_mepoch_cfg cfg;
	mxfs_mutex_t *lock;

	bool have_committed;
	struct mxfs_mepoch_rec committed;
	uint32_t member_incs[MXFS_MAX_NODES];

	/* voter-side staged candidate (single-decree promise) */
	bool have_prepared;
	struct mxfs_mepoch_rec prepared;
	uint32_t prep_incs[MXFS_MAX_NODES];

	/* proposer-side round */
	bool round_active;
	struct mxfs_mepoch_rec cand;
	uint32_t cand_incs[MXFS_MAX_NODES];
	uint64_t cand_fence_ok;
	uint64_t acks;                     /* voter slots that ACKed      */
	uint64_t round_last_tx_ms;
	uint8_t  last_reason;              /* latest NACK reason seen     */

	/* observer input for proposer determinism */
	uint64_t suspect_since_ms[MXFS_MAX_NODES];

	/* lease self-freeze */
	uint64_t lease_deadline_ms;
	bool frozen;
	uint64_t last_scan_ms;
	bool self_fenced;
};

/* ─── record seal/validate ─── */

void mxfs_mepoch_rec_seal(struct mxfs_mepoch_rec *r)
{
	r->magic = MXFS_MEPOCH_MAGIC;
	r->crc32c = 0;
	r->crc32c = mxfs_pal_crc32c(0, r, 40);
}

bool mxfs_mepoch_rec_valid(const struct mxfs_mepoch_rec *r)
{
	struct mxfs_mepoch_rec c;

	if (r->magic != MXFS_MEPOCH_MAGIC)
		return false;
	c = *r;
	c.crc32c = 0;
	return mxfs_pal_crc32c(0, &c, 40) == r->crc32c;
}

/* ─── voter derivation (§7.C: lowest slots of the epoch's mask) ─── */

static int mepoch_voters(uint64_t member_mask, uint16_t *out /* [5] */)
{
	int want = 3, n = 0, s, pop = 0;

	for (s = 0; s < MXFS_MAX_NODES; s++)
		if (member_mask & (1ULL << s))
			pop++;
	if (pop >= 16)
		want = 5;
	if (pop < want)
		want = pop;
	for (s = 0; s < MXFS_MAX_NODES && n < want; s++)
		if (member_mask & (1ULL << s))
			out[n++] = (uint16_t)s;
	return n;
}

static int mepoch_majority(int nvoters)
{
	return nvoters / 2 + 1;
}

static bool slot_alive(struct net2_mepoch *mp, uint16_t slot, uint64_t now)
{
	uint64_t since = mp->suspect_since_ms[slot];

	if (slot == mp->cfg.self_slot)
		return true;
	if (!since)
		return true;
	return now - since < 2ULL * mp->cfg.probe_interval_ms;
}

/* The deterministic proposer: lowest ALIVE voter of the committed epoch. */
static uint16_t mepoch_proposer(struct net2_mepoch *mp, uint64_t now)
{
	uint16_t v[5];
	int n, i;

	n = mepoch_voters(mp->committed.member_mask, v);
	for (i = 0; i < n; i++)
		if (slot_alive(mp, v[i], now))
			return v[i];
	return n ? v[0] : mp->cfg.self_slot;
}

/* ─── persistence ─── */

/* Publish `r` into MY OWN HB record with MY incarnation stamped. */
static int mepoch_write_own(struct net2_mepoch *mp,
                            const struct mxfs_mepoch_rec *r)
{
	struct mxfs_mepoch_rec w = *r;

	w.self_incarnation = mp->cfg.self_inc;
	mxfs_mepoch_rec_seal(&w);
	return mp->cfg.st.write_rec(mp->cfg.st.data, &w);
}

/* ─── messaging ─── */

static void mepoch_send(struct net2_mepoch *mp, uint16_t slot,
                        struct mxfs_n2msg *m)
{
	uint8_t buf[MXFS_N2MSG_HDR_SIZE + 300];
	struct mxfs_net2_id dst;
	int len;

	if (slot == mp->cfg.self_slot || slot >= MXFS_MAX_NODES)
		return;
	m->req_slot = mp->cfg.self_slot;
	m->req_inc = mp->cfg.self_inc;
	m->membership_epoch = mp->committed.epoch;
	len = mxfs_n2msg_pack(m, buf, sizeof(buf));
	if (len < 0)
		return;
	memset(&dst, 0, sizeof(dst));
	dst.slot = slot;
	dst.incarnation = mp->member_incs[slot];
	dst.membership_epoch = mp->committed.epoch;
	(void)mxfs_net2_send(mp->cfg.net, &dst, NET2_PRI_FENCE, true, 0,
	                     buf, (uint32_t)len);
}

static void mepoch_fill_from_cand(struct net2_mepoch *mp,
                                  struct mxfs_n2msg *m, uint16_t type)
{
	int i;

	memset(m, 0, sizeof(*m));
	m->type = type;
	m->mep_epoch = mp->cand.epoch;
	m->mep_member = mp->cand.member_mask;
	m->mep_fenced = mp->cand.fenced_mask;
	m->mep_fence_ok = mp->cand_fence_ok;
	m->mep_voters[0] = mp->cand.voter_slots[0];
	m->mep_voters[1] = mp->cand.voter_slots[1];
	m->mep_voters[2] = mp->cand.voter_slots[2];
	m->mep_flags = mp->cand.flags;
	for (i = 0; i < MXFS_MAX_NODES; i++)
		m->mep_incs[i] = mp->cand_incs[i];
}

/* ─── commit application (mp->lock held; returns cb args) ─── */

struct commit_fire {
	bool fire;
	struct mxfs_mepoch_rec rec;
	uint32_t incs[MXFS_MAX_NODES];
	bool fence_fire;
	uint64_t fence_epoch;
};

static void mepoch_adopt_committed(struct net2_mepoch *mp,
                                   const struct mxfs_mepoch_rec *r,
                                   const uint32_t *incs, uint64_t now,
                                   struct commit_fire *cf)
{
	bool was_member = mp->have_committed &&
		(mp->committed.member_mask & (1ULL << mp->cfg.self_slot));

	mp->committed = *r;
	mp->committed.flags &= ~MXFS_MEPOCH_F_PREPARED;
	memcpy(mp->member_incs, incs,
	       sizeof(uint32_t) * MXFS_MAX_NODES);
	mp->member_incs[mp->cfg.self_slot] = mp->cfg.self_inc;
	mp->have_committed = true;
	mp->have_prepared = false;
	mp->round_active = false;
	(void)mepoch_write_own(mp, &mp->committed);
	mp->lease_deadline_ms = now + mp->cfg.lease_ms;
	if (mp->frozen) {
		mp->frozen = false;
		if (mp->cfg.freeze_cb)
			mp->cfg.freeze_cb(mp->cfg.cb_data, false);
	}
	MEDBG("slot%u ADOPT epoch%llu members%llx fenced%llx",
	      mp->cfg.self_slot,
	      (unsigned long long)mp->committed.epoch,
	      (unsigned long long)mp->committed.member_mask,
	      (unsigned long long)mp->committed.fenced_mask);
	cf->fire = true;
	cf->rec = mp->committed;
	memcpy(cf->incs, mp->member_incs,
	       sizeof(uint32_t) * MXFS_MAX_NODES);

	/* §7.C exclusion: I was a member and the adopted record removes
	 * me with my fence bit set → disk/rx-visible self-fence.  A
	 * bootstrap adoption (no prior view) is a REJOIN of a bumped
	 * incarnation, never a self-fence — the fence hit the old
	 * incarnation. */
	if (was_member && !mp->self_fenced &&
	    !(mp->committed.member_mask & (1ULL << mp->cfg.self_slot)) &&
	    (mp->committed.fenced_mask & (1ULL << mp->cfg.self_slot))) {
		mp->self_fenced = true;
		cf->fence_fire = true;
		cf->fence_epoch = mp->committed.epoch;
		MEDBG("slot%u SELF-FENCE epoch%llu", mp->cfg.self_slot,
		      (unsigned long long)mp->committed.epoch);
	}
}

static void mepoch_fire(struct net2_mepoch *mp, struct commit_fire *cf)
{
	if (cf->fire && mp->cfg.committed_cb)
		mp->cfg.committed_cb(mp->cfg.cb_data, &cf->rec, cf->incs);
	if (cf->fence_fire && mp->cfg.self_fence_cb)
		mp->cfg.self_fence_cb(mp->cfg.cb_data, cf->fence_epoch);
	cf->fire = false;
	cf->fence_fire = false;
}

/* ─── round machinery (mp->lock held) ─── */

/* Voter-side validation of a candidate against MY committed view. */
static uint8_t mepoch_validate(struct net2_mepoch *mp,
                               const struct mxfs_n2msg *m)
{
	uint16_t v[5];
	int n, i;
	bool voter = false;
	uint64_t removed;

	n = mepoch_voters(mp->committed.member_mask, v);
	for (i = 0; i < n; i++)
		if (v[i] == mp->cfg.self_slot)
			voter = true;
	if (!voter)
		return N2ME_NOT_VOTER;
	if (m->mep_epoch != mp->committed.epoch + 1)
		return N2ME_NOT_MONOTONIC;
	if ((m->mep_fenced & mp->committed.fenced_mask) !=
	    mp->committed.fenced_mask)
		return N2ME_FENCED_SHRANK;
	removed = mp->committed.member_mask & ~m->mep_member;
	if (removed & ~m->mep_fence_ok)
		return N2ME_NO_FENCE_PROOF;
	if (mp->have_prepared && mp->prepared.epoch == m->mep_epoch &&
	    (mp->prepared.member_mask != m->mep_member ||
	     mp->prepared.fenced_mask != m->mep_fenced))
		return N2ME_STALE_ROUND;   /* promised a different value */
	return N2ME_OK;
}

/* Stage + ACK a valid candidate (voter side). */
static void mepoch_stage(struct net2_mepoch *mp, const struct mxfs_n2msg *m)
{
	int i;

	memset(&mp->prepared, 0, sizeof(mp->prepared));
	mp->prepared.epoch = m->mep_epoch;
	mp->prepared.member_mask = m->mep_member;
	mp->prepared.fenced_mask = m->mep_fenced;
	mp->prepared.voter_slots[0] = m->mep_voters[0];
	mp->prepared.voter_slots[1] = m->mep_voters[1];
	mp->prepared.voter_slots[2] = m->mep_voters[2];
	mp->prepared.flags = m->mep_flags | MXFS_MEPOCH_F_PREPARED;
	for (i = 0; i < MXFS_MAX_NODES; i++)
		mp->prep_incs[i] = m->mep_incs[i];
	mp->have_prepared = true;
	(void)mepoch_write_own(mp, &mp->prepared);
}

static void mepoch_round_commit(struct net2_mepoch *mp, uint64_t now,
                                struct commit_fire *cf)
{
	uint64_t targets;
	uint16_t s;
	struct mxfs_n2msg m;

	targets = (mp->committed.member_mask | mp->cand.member_mask) &
	          ~(1ULL << mp->cfg.self_slot);
	mepoch_fill_from_cand(mp, &m, N2_MEPOCH_COMMIT);
	mepoch_adopt_committed(mp, &mp->cand, mp->cand_incs, now, cf);
	for (s = 0; s < MXFS_MAX_NODES; s++)
		if (targets & (1ULL << s))
			mepoch_send(mp, s, &m);
	MEDBG("slot%u COMMIT epoch%llu", mp->cfg.self_slot,
	      (unsigned long long)mp->committed.epoch);
}

/* Count ACKs against the majority of the COMMITTED epoch's voters. */
static void mepoch_round_check(struct net2_mepoch *mp, uint64_t now,
                               struct commit_fire *cf)
{
	uint16_t v[5];
	int n, i, got = 0;

	if (!mp->round_active)
		return;
	n = mepoch_voters(mp->committed.member_mask, v);
	for (i = 0; i < n; i++)
		if (mp->acks & (1ULL << v[i]))
			got++;
	if (got >= mepoch_majority(n))
		mepoch_round_commit(mp, now, cf);
}

/* Start (or restart, for adoption) a round for `cand`/`cand_incs`.
 * Self-votes inline when this node is a voter. */
static void mepoch_round_start(struct net2_mepoch *mp, uint64_t now,
                               struct commit_fire *cf)
{
	uint16_t v[5];
	int n, i;
	struct mxfs_n2msg m;

	mp->round_active = true;
	mp->acks = 0;
	mp->last_reason = N2ME_OK;
	mp->round_last_tx_ms = now;
	n = mepoch_voters(mp->committed.member_mask, v);
	mepoch_fill_from_cand(mp, &m, N2_MEPOCH_PROPOSE);
	for (i = 0; i < n; i++) {
		if (v[i] == mp->cfg.self_slot) {
			uint8_t rc = mepoch_validate(mp, &m);

			if (rc == N2ME_OK) {
				mepoch_stage(mp, &m);
				mp->acks |= 1ULL << v[i];
			} else {
				mp->last_reason = rc;
				mp->round_active = false;
				MEDBG("slot%u SELF-NACK reason%u",
				      mp->cfg.self_slot, rc);
				return;
			}
		} else {
			mepoch_send(mp, v[i], &m);
		}
	}
	MEDBG("slot%u PROPOSE epoch%llu members%llx",
	      mp->cfg.self_slot, (unsigned long long)mp->cand.epoch,
	      (unsigned long long)mp->cand.member_mask);
	mepoch_round_check(mp, now, cf);
}

/* ─── public API ─── */

int net2_mepoch_create(const struct net2_mepoch_cfg *cfg,
                       struct net2_mepoch **out)
{
	struct net2_mepoch *mp;

	if (!cfg || !out || !cfg->st.read_rec || !cfg->st.write_rec ||
	    !cfg->net || cfg->self_slot >= MXFS_MAX_NODES)
		return -EINVAL;
	mp = mxfs_pal_alloc(sizeof(*mp));
	if (!mp)
		return -ENOMEM;
	memset(mp, 0, sizeof(*mp));
	mp->cfg = *cfg;
	if (!mp->cfg.lease_ms)
		mp->cfg.lease_ms = 10000;
	if (!mp->cfg.probe_interval_ms)
		mp->cfg.probe_interval_ms = 1000;
	if (!mp->cfg.round_retry_ms)
		mp->cfg.round_retry_ms = 500;
	mp->lock = mxfs_pal_mutex_create();
	if (!mp->lock) {
		mxfs_pal_free(mp);
		return -ENOMEM;
	}
	*out = mp;
	return 0;
}

void net2_mepoch_destroy(struct net2_mepoch *mp)
{
	if (!mp)
		return;
	mxfs_pal_mutex_destroy(mp->lock);
	mxfs_pal_free(mp);
}

int net2_mepoch_bootstrap(struct net2_mepoch *mp)
{
	struct commit_fire cf = { .fire = false };
	struct mxfs_mepoch_rec r, best;
	uint32_t incs[MXFS_MAX_NODES];
	bool found = false;
	uint16_t s;
	uint64_t now = mxfs_pal_time_ms();

	memset(&best, 0, sizeof(best));
	memset(incs, 0, sizeof(incs));
	mxfs_pal_mutex_lock(mp->lock);
	for (s = 0; s < MXFS_MAX_NODES; s++) {
		if (mp->cfg.st.read_rec(mp->cfg.st.data, s, &r))
			continue;
		if (!mxfs_mepoch_rec_valid(&r))
			continue;
		incs[s] = r.self_incarnation;
		if (r.flags & MXFS_MEPOCH_F_PREPARED)
			continue;              /* not committed authority */
		if (!r.epoch)
			continue;              /* inc-bump carrier only */
		if (!found || r.epoch > best.epoch) {
			best = r;
			found = true;
		}
	}
	if (found) {
		mepoch_adopt_committed(mp, &best, incs, now, &cf);
	} else {
		/* fresh cluster: epoch 1, self-quorum (§7.C bootstrap) */
		memset(&r, 0, sizeof(r));
		r.epoch = 1;
		r.member_mask = 1ULL << mp->cfg.self_slot;
		r.fenced_mask = 0;
		r.voter_slots[0] = mp->cfg.self_slot;
		memset(incs, 0, sizeof(incs));
		incs[mp->cfg.self_slot] = mp->cfg.self_inc;
		mepoch_adopt_committed(mp, &r, incs, now, &cf);
	}
	mxfs_pal_mutex_unlock(mp->lock);
	mepoch_fire(mp, &cf);
	return 0;
}

int net2_mepoch_propose(struct net2_mepoch *mp, uint64_t member_mask,
                        uint64_t fenced_mask, uint64_t fence_ok_mask,
                        const uint32_t *incs)
{
	struct commit_fire cf = { .fire = false };
	uint64_t now = mxfs_pal_time_ms();
	uint16_t v[5];
	int i;

	mxfs_pal_mutex_lock(mp->lock);
	if (!mp->have_committed) {
		mxfs_pal_mutex_unlock(mp->lock);
		return -EINVAL;
	}
	if (mepoch_proposer(mp, now) != mp->cfg.self_slot) {
		mxfs_pal_mutex_unlock(mp->lock);
		return -EPERM;
	}
	memset(&mp->cand, 0, sizeof(mp->cand));
	mp->cand.epoch = mp->committed.epoch + 1;
	mp->cand.member_mask = member_mask;
	mp->cand.fenced_mask = fenced_mask;
	i = mepoch_voters(mp->committed.member_mask, v);
	mp->cand.voter_slots[0] = i > 0 ? v[0] : 0;
	mp->cand.voter_slots[1] = i > 1 ? v[1] : 0;
	mp->cand.voter_slots[2] = i > 2 ? v[2] : 0;
	{
		int pop = 0, s;

		for (s = 0; s < MXFS_MAX_NODES; s++)
			if (member_mask & (1ULL << s))
				pop++;
		if (pop >= 16)
			mp->cand.flags |= MXFS_MEPOCH_F_VOTERS5;
	}
	if (incs)
		memcpy(mp->cand_incs, incs,
		       sizeof(uint32_t) * MXFS_MAX_NODES);
	else
		memcpy(mp->cand_incs, mp->member_incs,
		       sizeof(uint32_t) * MXFS_MAX_NODES);
	mp->cand_incs[mp->cfg.self_slot] = mp->cfg.self_inc;
	mp->cand_fence_ok = fence_ok_mask;
	mepoch_round_start(mp, now, &cf);
	mxfs_pal_mutex_unlock(mp->lock);
	mepoch_fire(mp, &cf);
	return 0;
}

void net2_mepoch_rx(struct net2_mepoch *mp, const struct mxfs_net2_id *src,
                    const void *payload, uint32_t len)
{
	struct commit_fire cf = { .fire = false };
	struct mxfs_n2msg m;
	uint32_t recs_off = 0;
	uint64_t now = mxfs_pal_time_ms();
	uint16_t v[5];
	int n, i;
	bool from_voter = false;

	if (mxfs_n2msg_unpack(payload, len, &m, &recs_off))
		return;
	mxfs_pal_mutex_lock(mp->lock);
	n = mepoch_voters(mp->committed.member_mask, v);
	for (i = 0; i < n; i++)
		if (v[i] == src->slot)
			from_voter = true;
	if (from_voter)
		mp->lease_deadline_ms = now + mp->cfg.lease_ms;
	switch (m.type) {
	case N2_MEPOCH_PROPOSE: {
		uint8_t rc = mepoch_validate(mp, &m);
		struct mxfs_n2msg a;

		if (rc == N2ME_OK)
			mepoch_stage(mp, &m);
		MEDBG("slot%u RX-PROPOSE epoch%llu from%u -> %s%u",
		      mp->cfg.self_slot, (unsigned long long)m.mep_epoch,
		      src->slot, rc == N2ME_OK ? "ack" : "nack", rc);
		memset(&a, 0, sizeof(a));
		a.type = N2_MEPOCH_ACK;
		a.mep_epoch = m.mep_epoch;
		a.ack_ok = rc == N2ME_OK ? 1 : 0;
		a.status = rc;
		mepoch_send(mp, src->slot, &a);
		break;
	}
	case N2_MEPOCH_ACK:
		if (!mp->round_active || m.mep_epoch != mp->cand.epoch)
			break;
		if (m.ack_ok) {
			mp->acks |= 1ULL << src->slot;
			mepoch_round_check(mp, now, &cf);
		} else {
			mp->last_reason = m.status;
			MEDBG("slot%u RX-NACK reason%u from%u",
			      mp->cfg.self_slot, m.status, src->slot);
			if (m.status == N2ME_NO_FENCE_PROOF ||
			    m.status == N2ME_FENCED_SHRANK)
				mp->round_active = false;   /* dead round */
		}
		break;
	case N2_MEPOCH_COMMIT: {
		struct mxfs_mepoch_rec r;
		uint32_t incs[MXFS_MAX_NODES];

		if (m.mep_epoch <= mp->committed.epoch)
			break;
		memset(&r, 0, sizeof(r));
		r.epoch = m.mep_epoch;
		r.member_mask = m.mep_member;
		r.fenced_mask = m.mep_fenced;
		r.voter_slots[0] = m.mep_voters[0];
		r.voter_slots[1] = m.mep_voters[1];
		r.voter_slots[2] = m.mep_voters[2];
		r.flags = m.mep_flags & ~MXFS_MEPOCH_F_PREPARED;
		for (i = 0; i < MXFS_MAX_NODES; i++)
			incs[i] = m.mep_incs[i];
		mepoch_adopt_committed(mp, &r, incs, now, &cf);
		break;
	}
	default:
		break;
	}
	mxfs_pal_mutex_unlock(mp->lock);
	mepoch_fire(mp, &cf);
}

void net2_mepoch_suspect(struct net2_mepoch *mp, uint16_t slot,
                         bool suspected)
{
	if (slot >= MXFS_MAX_NODES)
		return;
	mxfs_pal_mutex_lock(mp->lock);
	if (!suspected)
		mp->suspect_since_ms[slot] = 0;
	else if (!mp->suspect_since_ms[slot])
		mp->suspect_since_ms[slot] = mxfs_pal_time_ms();
	mxfs_pal_mutex_unlock(mp->lock);
}

void net2_mepoch_tick(struct net2_mepoch *mp, uint64_t now_ms)
{
	struct commit_fire cf = { .fire = false };
	bool freeze_fire = false;

	mxfs_pal_mutex_lock(mp->lock);
	if (!mp->have_committed) {
		mxfs_pal_mutex_unlock(mp->lock);
		return;
	}

	/* round retry (proposer) */
	if (mp->round_active &&
	    now_ms - mp->round_last_tx_ms >= mp->cfg.round_retry_ms) {
		uint16_t v[5];
		int n, i;
		struct mxfs_n2msg m;

		n = mepoch_voters(mp->committed.member_mask, v);
		mepoch_fill_from_cand(mp, &m, N2_MEPOCH_PROPOSE);
		for (i = 0; i < n; i++)
			if (v[i] != mp->cfg.self_slot &&
			    !(mp->acks & (1ULL << v[i])))
				mepoch_send(mp, v[i], &m);
		mp->round_last_tx_ms = now_ms;
	}

	/* periodic disk scan: catch-up adoption, PREPARED takeover,
	 * disk-visible self-fence (works with zero network, §7.C) */
	if (now_ms - mp->last_scan_ms >= mp->cfg.probe_interval_ms) {
		struct mxfs_mepoch_rec r, best, prep;
		uint32_t incs[MXFS_MAX_NODES];
		bool bfound = false, pfound = false;
		uint16_t s;

		mp->last_scan_ms = now_ms;
		memset(incs, 0, sizeof(incs));
		memset(&best, 0, sizeof(best));
		memset(&prep, 0, sizeof(prep));
		for (s = 0; s < MXFS_MAX_NODES; s++) {
			if (mp->cfg.st.read_rec(mp->cfg.st.data, s, &r))
				continue;
			if (!mxfs_mepoch_rec_valid(&r))
				continue;
			incs[s] = r.self_incarnation;
			if (!r.epoch)
				continue;      /* inc-bump carrier only */
			if (r.flags & MXFS_MEPOCH_F_PREPARED) {
				if (r.epoch == mp->committed.epoch + 1 &&
				    s != mp->cfg.self_slot) {
					prep = r;
					pfound = true;
				}
				continue;
			}
			if (!bfound || r.epoch > best.epoch) {
				best = r;
				bfound = true;
			}
		}
		if (bfound && best.epoch > mp->committed.epoch)
			mepoch_adopt_committed(mp, &best, incs, now_ms,
			                       &cf);
		/* proposer takeover: adopt a stranded PREPARED candidate
		 * (mine or one found on disk) and complete the decree */
		if (!mp->round_active &&
		    mepoch_proposer(mp, now_ms) == mp->cfg.self_slot) {
			if (mp->have_prepared &&
			    mp->prepared.epoch ==
			    mp->committed.epoch + 1) {
				mp->cand = mp->prepared;
				mp->cand.flags &= ~MXFS_MEPOCH_F_PREPARED;
				memcpy(mp->cand_incs, mp->prep_incs,
				       sizeof(uint32_t) * MXFS_MAX_NODES);
				mp->cand_fence_ok =
					mp->committed.member_mask &
					~mp->cand.member_mask;
				MEDBG("slot%u TAKEOVER own-prepared e%llu",
				      mp->cfg.self_slot,
				      (unsigned long long)mp->cand.epoch);
				mepoch_round_start(mp, now_ms, &cf);
			} else if (pfound) {
				int i;

				mp->cand = prep;
				mp->cand.flags &= ~MXFS_MEPOCH_F_PREPARED;
				for (i = 0; i < MXFS_MAX_NODES; i++)
					mp->cand_incs[i] = incs[i];
				mp->cand_fence_ok =
					mp->committed.member_mask &
					~mp->cand.member_mask;
				MEDBG("slot%u TAKEOVER disk-prepared e%llu",
				      mp->cfg.self_slot,
				      (unsigned long long)mp->cand.epoch);
				mepoch_round_start(mp, now_ms, &cf);
			}
		}
	}

	/* lease self-freeze (visible, never silent — §7.E) */
	if (!mp->frozen && now_ms > mp->lease_deadline_ms) {
		mp->frozen = true;
		freeze_fire = true;
		MEDBG("slot%u LEASE-FREEZE", mp->cfg.self_slot);
	}
	mxfs_pal_mutex_unlock(mp->lock);

	mepoch_fire(mp, &cf);
	if (freeze_fire && mp->cfg.freeze_cb)
		mp->cfg.freeze_cb(mp->cfg.cb_data, true);
}

bool net2_mepoch_committed(struct net2_mepoch *mp,
                           struct mxfs_mepoch_rec *out, uint32_t *incs_out)
{
	bool have;

	mxfs_pal_mutex_lock(mp->lock);
	have = mp->have_committed;
	if (have && out)
		*out = mp->committed;
	if (have && incs_out)
		memcpy(incs_out, mp->member_incs,
		       sizeof(uint32_t) * MXFS_MAX_NODES);
	mxfs_pal_mutex_unlock(mp->lock);
	return have;
}

void net2_mepoch_round_status(struct net2_mepoch *mp, bool *active,
                              uint8_t *last_reason)
{
	mxfs_pal_mutex_lock(mp->lock);
	if (active)
		*active = mp->round_active;
	if (last_reason)
		*last_reason = mp->last_reason;
	mxfs_pal_mutex_unlock(mp->lock);
}
