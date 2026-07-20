// SPDX-License-Identifier: GPL-2.0
/*
 * net2_membership — observer aggregation + SUSPECT machine (§7.C).
 * See net2_membership.h for the model.  Both builds, PAL only.
 */
#include "net2_membership.h"

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#endif

static int n2mbdbg(void)
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
#define MBDBG(fmt, ...) do { if (n2mbdbg()) fprintf(stderr, \
	"MBDBG " fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define MBDBG(fmt, ...) do { } while (0)
#endif

struct member_slot {
	enum net2_member_state state;
	uint32_t inc;
	uint64_t nonce;
	uint64_t last_seen_ms[N2OBS_COUNT];
	uint64_t suspect_since_ms;
};

struct net2_membership {
	struct net2_membership_cfg cfg;
	mxfs_mutex_t *lock;
	struct member_slot slots[MXFS_MAX_NODES];
};

/* Transition log collected under the lock, fired after unlock. */
struct mb_fires {
	int n;
	struct {
		uint16_t slot;
		enum net2_member_state from, to;
	} f[MXFS_MAX_NODES];
};

static void mb_set_state(struct net2_membership *mb, uint16_t slot,
                         enum net2_member_state to, struct mb_fires *fires)
{
	struct member_slot *ms = &mb->slots[slot];

	if (ms->state == to)
		return;
	MBDBG("slot%u: %u -> %u (peer%u)", mb->cfg.self_slot,
	      ms->state, to, slot);
	if (fires->n < MXFS_MAX_NODES) {
		fires->f[fires->n].slot = slot;
		fires->f[fires->n].from = ms->state;
		fires->f[fires->n].to = to;
		fires->n++;
	}
	ms->state = to;
}

static void mb_fire(struct net2_membership *mb, struct mb_fires *fires)
{
	int i;

	if (!mb->cfg.state_cb)
		return;
	for (i = 0; i < fires->n; i++)
		mb->cfg.state_cb(mb->cfg.cb_data, fires->f[i].slot,
		                 fires->f[i].from, fires->f[i].to);
	fires->n = 0;
}

int net2_membership_create(const struct net2_membership_cfg *cfg,
                           struct net2_membership **out)
{
	struct net2_membership *mb;

	if (!cfg || !out || cfg->self_slot >= MXFS_MAX_NODES)
		return -EINVAL;
	mb = mxfs_pal_alloc(sizeof(*mb));
	if (!mb)
		return -ENOMEM;
	memset(mb, 0, sizeof(*mb));
	mb->cfg = *cfg;
	if (!mb->cfg.miss_ms)
		mb->cfg.miss_ms = 3000;
	if (!mb->cfg.grace_ms)
		mb->cfg.grace_ms = 10000;
	mb->lock = mxfs_pal_mutex_create();
	if (!mb->lock) {
		mxfs_pal_free(mb);
		return -ENOMEM;
	}
	*out = mb;
	return 0;
}

void net2_membership_destroy(struct net2_membership *mb)
{
	if (!mb)
		return;
	mxfs_pal_mutex_destroy(mb->lock);
	mxfs_pal_free(mb);
}

void net2_membership_track(struct net2_membership *mb, uint16_t slot,
                           uint32_t inc, uint64_t nonce)
{
	struct mb_fires fires = { .n = 0 };
	struct member_slot *ms;
	uint64_t now = mxfs_pal_time_ms();
	int o;

	if (slot >= MXFS_MAX_NODES || slot == mb->cfg.self_slot)
		return;
	mxfs_pal_mutex_lock(mb->lock);
	ms = &mb->slots[slot];
	ms->inc = inc;
	ms->nonce = nonce;
	ms->suspect_since_ms = 0;
	for (o = 0; o < N2OBS_COUNT; o++)
		ms->last_seen_ms[o] = now;
	mb_set_state(mb, slot, N2MB_ACTIVE, &fires);
	mxfs_pal_mutex_unlock(mb->lock);
	mb_fire(mb, &fires);
}

void net2_membership_untrack(struct net2_membership *mb, uint16_t slot)
{
	struct mb_fires fires = { .n = 0 };

	if (slot >= MXFS_MAX_NODES)
		return;
	mxfs_pal_mutex_lock(mb->lock);
	mb_set_state(mb, slot, N2MB_UNTRACKED, &fires);
	memset(&mb->slots[slot], 0, sizeof(mb->slots[slot]));
	mxfs_pal_mutex_unlock(mb->lock);
	mb_fire(mb, &fires);
}

void net2_membership_observe(struct net2_membership *mb, uint16_t slot,
                             enum net2_observer obs, uint32_t inc,
                             uint64_t nonce, uint64_t now_ms)
{
	struct mb_fires fires = { .n = 0 };
	struct member_slot *ms;

	if (slot >= MXFS_MAX_NODES || obs >= N2OBS_COUNT)
		return;
	mxfs_pal_mutex_lock(mb->lock);
	ms = &mb->slots[slot];
	if (ms->state == N2MB_UNTRACKED || ms->state == N2MB_DEAD)
		goto out;
	if (ms->inc != inc || ms->nonce != nonce) {
		/* a different incarnation is NOT this peer resuming */
		MBDBG("slot%u: peer%u identity mismatch (inc %u/%u)",
		      mb->cfg.self_slot, slot, inc, ms->inc);
		goto out;
	}
	ms->last_seen_ms[obs] = now_ms;
	if (ms->state == N2MB_SUSPECT &&
	    now_ms - ms->suspect_since_ms < mb->cfg.grace_ms) {
		ms->suspect_since_ms = 0;
		mb_set_state(mb, slot, N2MB_ACTIVE, &fires);
	}
out:
	mxfs_pal_mutex_unlock(mb->lock);
	mb_fire(mb, &fires);
}

void net2_membership_tick(struct net2_membership *mb, uint64_t now_ms)
{
	struct mb_fires fires = { .n = 0 };
	uint16_t s;
	int o, missing;

	mxfs_pal_mutex_lock(mb->lock);
	for (s = 0; s < MXFS_MAX_NODES; s++) {
		struct member_slot *ms = &mb->slots[s];

		if (ms->state == N2MB_UNTRACKED || ms->state == N2MB_DEAD)
			continue;
		missing = 0;
		for (o = 0; o < N2OBS_COUNT; o++)
			if (now_ms - ms->last_seen_ms[o] > mb->cfg.miss_ms)
				missing++;
		if (ms->state == N2MB_ACTIVE && missing >= 2) {
			ms->suspect_since_ms = now_ms;
			mb_set_state(mb, s, N2MB_SUSPECT, &fires);
		} else if (ms->state == N2MB_SUSPECT &&
		           now_ms - ms->suspect_since_ms >=
		           mb->cfg.grace_ms) {
			mb_set_state(mb, s, N2MB_FENCING, &fires);
		}
	}
	mxfs_pal_mutex_unlock(mb->lock);
	mb_fire(mb, &fires);
}

void net2_membership_fence_done(struct net2_membership *mb, uint16_t slot,
                                uint32_t inc)
{
	struct mb_fires fires = { .n = 0 };

	if (slot >= MXFS_MAX_NODES)
		return;
	mxfs_pal_mutex_lock(mb->lock);
	if (mb->slots[slot].state != N2MB_UNTRACKED &&
	    mb->slots[slot].inc == inc)
		mb_set_state(mb, slot, N2MB_DEAD, &fires);
	mxfs_pal_mutex_unlock(mb->lock);
	mb_fire(mb, &fires);
}

enum net2_member_state net2_membership_state(struct net2_membership *mb,
                                             uint16_t slot)
{
	enum net2_member_state st;

	if (slot >= MXFS_MAX_NODES)
		return N2MB_UNTRACKED;
	mxfs_pal_mutex_lock(mb->lock);
	st = mb->slots[slot].state;
	mxfs_pal_mutex_unlock(mb->lock);
	return st;
}

int net2_membership_inc_bump(const struct net2_mepoch_storage *st,
                             uint16_t self_slot, uint32_t *inc_out)
{
	struct mxfs_mepoch_rec r;
	int rc;

	if (!st || !st->read_rec || !st->write_rec ||
	    self_slot >= MXFS_MAX_NODES)
		return -EINVAL;
	if (st->read_rec(st->data, self_slot, &r) ||
	    !mxfs_mepoch_rec_valid(&r))
		memset(&r, 0, sizeof(r));
	r.self_incarnation++;
	if (!r.self_incarnation)
		r.self_incarnation = 1;
	mxfs_mepoch_rec_seal(&r);
	rc = st->write_rec(st->data, &r);
	if (!rc && inc_out)
		*inc_out = r.self_incarnation;
	return rc;
}

uint64_t net2_membership_boot_nonce(void)
{
	uint64_t n = 0;

	do {
		mxfs_pal_get_random_bytes(&n, sizeof(n));
	} while (!n);
	return n;
}
