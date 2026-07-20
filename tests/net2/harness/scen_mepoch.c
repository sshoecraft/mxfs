/*
 * MXFS — NET2 gate-5 scenarios: MEPOCH membership plane (§7.C).
 *
 * Every node runs a real net2_mepoch instance over a shared file-backed
 * 64×512 B disklock image (records live at the true on-disk offset of
 * struct mxfs_disklock_heartbeat.mepoch) and a real vcluster ctx for
 * the wire.  The seven gate-5 checks (success criteria):
 *   1 bootstrap: fresh image → epoch 1 self-quorum
 *   2 join/leave increments (leave = removal WITHOUT the fenced bit)
 *   3 proposer crash mid-round → next proposer adopts PREPARED
 *   4 voter-minority loss → no commit + visible lease freeze
 *   5 whole-cluster restart → max valid committed record adopted
 *   6 excluded node with ZERO network → disk-scan self-fence
 *   7 exclusion without fence proof → NACK, round dead, no commit
 * plus the §7.C observer/SUSPECT machine + persisted-incarnation bump.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "harness.h"
#include "dlm/net2_epoch.h"
#include "dlm/net2_membership.h"
#include "dlm/net2_msg.h"
#include "dlm/disklock.h"

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* The harness image must use the true kernel layout. */
_Static_assert(offsetof(struct mxfs_disklock_heartbeat, mepoch) == 456,
               "mepoch record moved inside the HB sector");
#define MEP_OFF   ((uint64_t)offsetof(struct mxfs_disklock_heartbeat, mepoch))
#define MEP_IMG_SLOTS 64

struct mepenv;

struct mepnode {
	int idx;
	struct mepenv *env;
	struct net2_mepoch *mp;

	/* evidence, under env->lock */
	int commits;
	struct mxfs_mepoch_rec last;
	uint32_t last_incs[MXFS_MAX_NODES];
	int freezes;
	int unfreezes;
	int frozen;
	int self_fences;
	uint64_t fence_epoch;
	uint64_t rx_frames;           /* deliveries that reached the cb */
};

struct mepenv {
	struct scenario_ctx *sc;
	struct vcluster *vc;
	int n;
	int fd;
	char img[96];
	mxfs_mutex_t *lock;
	struct mepnode nodes[VC_MAX_NODES];
};

/* ─── file-backed storage vtable ─── */

static int mep_st_read(void *data, uint16_t slot, struct mxfs_mepoch_rec *out)
{
	struct mepnode *mn = data;
	ssize_t r;

	if (slot >= MEP_IMG_SLOTS)
		return -EINVAL;
	r = pread(mn->env->fd, out, sizeof(*out),
	          (off_t)slot * 512 + (off_t)MEP_OFF);
	return r == (ssize_t)sizeof(*out) ? 0 : -EIO;
}

static int mep_st_write(void *data, const struct mxfs_mepoch_rec *rec)
{
	struct mepnode *mn = data;
	uint16_t slot = mn->env->vc->nodes[mn->idx].slot;
	ssize_t r;

	r = pwrite(mn->env->fd, rec, sizeof(*rec),
	           (off_t)slot * 512 + (off_t)MEP_OFF);
	return r == (ssize_t)sizeof(*rec) ? 0 : -EIO;
}

/* Raw disk peek for assertions (any slot). */
static int mep_disk(struct mepenv *env, uint16_t slot,
                    struct mxfs_mepoch_rec *out)
{
	ssize_t r = pread(env->fd, out, sizeof(*out),
	                  (off_t)slot * 512 + (off_t)MEP_OFF);

	if (r != (ssize_t)sizeof(*out))
		return -EIO;
	return mxfs_mepoch_rec_valid(out) ? 0 : -ENOENT;
}

/* ─── callbacks (evidence) ─── */

static void mep_committed_cb(void *cb_data, const struct mxfs_mepoch_rec *r,
                             const uint32_t *member_incs)
{
	struct mepnode *mn = cb_data;
	struct mepenv *env = mn->env;

	mxfs_pal_mutex_lock(env->lock);
	mn->commits++;
	mn->last = *r;
	memcpy(mn->last_incs, member_incs,
	       sizeof(uint32_t) * MXFS_MAX_NODES);
	mxfs_pal_mutex_unlock(env->lock);
	/* §7.C consumer contract: the committed view drives the overlay. */
	vc_view_node(env->vc, mn->idx, r->member_mask, r->epoch);
}

static void mep_freeze_cb(void *cb_data, bool frozen)
{
	struct mepnode *mn = cb_data;

	mxfs_pal_mutex_lock(mn->env->lock);
	if (frozen)
		mn->freezes++;
	else
		mn->unfreezes++;
	mn->frozen = frozen ? 1 : 0;
	mxfs_pal_mutex_unlock(mn->env->lock);
}

static void mep_fence_cb(void *cb_data, uint64_t epoch)
{
	struct mepnode *mn = cb_data;

	mxfs_pal_mutex_lock(mn->env->lock);
	mn->self_fences++;
	mn->fence_epoch = epoch;
	mxfs_pal_mutex_unlock(mn->env->lock);
}

static void mep_recv_cb(void *data, const struct mxfs_net2_id *src,
                        const void *payload, uint32_t len)
{
	struct mepnode *mn = data;
	struct mxfs_n2msg m;
	uint32_t off = 0;

	mxfs_pal_mutex_lock(mn->env->lock);
	mn->rx_frames++;
	mxfs_pal_mutex_unlock(mn->env->lock);
	if (!mn->mp || !mxfs_n2msg_is_lockplane(payload, len))
		return;
	if (mxfs_n2msg_unpack(payload, len, &m, &off))
		return;
	if (m.type == N2_MEPOCH_PROPOSE || m.type == N2_MEPOCH_ACK ||
	    m.type == N2_MEPOCH_COMMIT)
		net2_mepoch_rx(mn->mp, src, payload, len);
}

/* ─── env lifecycle ─── */

static int mep_node_up(struct mepenv *env, int i, uint32_t lease_ms)
{
	struct net2_mepoch_cfg cfg;
	struct mepnode *mn = &env->nodes[i];
	int rc;

	memset(&cfg, 0, sizeof(cfg));
	cfg.self_slot = env->vc->nodes[i].slot;
	cfg.self_inc = env->vc->nodes[i].inc;
	cfg.lease_ms = lease_ms;
	cfg.probe_interval_ms = 100;
	cfg.round_retry_ms = 100;
	cfg.st.data = mn;
	cfg.st.read_rec = mep_st_read;
	cfg.st.write_rec = mep_st_write;
	cfg.net = env->vc->nodes[i].ctx;
	cfg.committed_cb = mep_committed_cb;
	cfg.freeze_cb = mep_freeze_cb;
	cfg.self_fence_cb = mep_fence_cb;
	cfg.cb_data = mn;
	rc = net2_mepoch_create(&cfg, &mn->mp);
	if (rc)
		return rc;
	mxfs_net2_register_recv_cb(env->vc->nodes[i].ctx, mep_recv_cb, mn);
	return 0;
}

static void mep_node_down(struct mepenv *env, int i)
{
	struct mepnode *mn = &env->nodes[i];

	if (env->vc->nodes[i].up)
		mxfs_net2_register_recv_cb(env->vc->nodes[i].ctx,
		                           NULL, NULL);
	if (mn->mp) {
		net2_mepoch_destroy(mn->mp);
		mn->mp = NULL;
	}
}

static void mep_env_stop(struct mepenv *env)
{
	int i;

	for (i = 0; i < env->n; i++)
		if (env->vc)
			mep_node_down(env, i);
	if (env->vc) {
		vc_destroy(env->vc);
		env->vc = NULL;
	}
	if (env->fd >= 0) {
		close(env->fd);
		unlink(env->img);
		env->fd = -1;
	}
	if (env->lock) {
		mxfs_pal_mutex_destroy(env->lock);
		env->lock = NULL;
	}
}

static int mep_env_start(struct scenario_ctx *sc, struct mepenv *env, int n,
                         uint32_t lease_ms)
{
	int i, rc;

	memset(env, 0, sizeof(*env));
	env->sc = sc;
	env->n = n;
	env->fd = -1;
	env->lock = mxfs_pal_mutex_create();
	if (!env->lock)
		return -ENOMEM;
	snprintf(env->img, sizeof(env->img), "/tmp/mxfs_mep_%d.img",
	         (int)getpid());
	env->fd = open(env->img, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (env->fd < 0 ||
	    ftruncate(env->fd, (off_t)MEP_IMG_SLOTS * 512) != 0) {
		fprintf(stderr, "  ENV-FAIL: image %s errno=%d\n",
		        env->img, errno);
		mep_env_stop(env);
		return -EIO;
	}
	rc = vc_create(&env->vc, n, sc->seed, 10, 0);
	if (rc) {
		fprintf(stderr, "  ENV-FAIL: vc_create rc=%d\n", rc);
		mep_env_stop(env);
		return rc;
	}
	for (i = 0; i < n; i++) {
		env->nodes[i].idx = i;
		env->nodes[i].env = env;
		rc = mep_node_up(env, i, lease_ms);
		if (rc) {
			fprintf(stderr, "  ENV-FAIL: node %d up rc=%d\n",
			        i, rc);
			mep_env_stop(env);
			return rc;
		}
	}
	return 0;
}

/* ─── drive + wait helpers ─── */

static void mep_pump(struct mepenv *env, uint32_t ms)
{
	uint64_t end = mxfs_pal_time_ms() + ms;

	do {
		int i;

		for (i = 0; i < env->n; i++)
			if (env->nodes[i].mp && env->vc->nodes[i].up)
				net2_mepoch_tick(env->nodes[i].mp,
				                 mxfs_pal_time_ms());
		usleep(5000);
	} while (mxfs_pal_time_ms() < end);
}

static uint64_t mep_epoch_of(struct mepenv *env, int i)
{
	uint64_t e;

	mxfs_pal_mutex_lock(env->lock);
	e = env->nodes[i].last.epoch;
	mxfs_pal_mutex_unlock(env->lock);
	return e;
}

static int mep_wait_epoch(struct mepenv *env, int i, uint64_t epoch,
                          uint32_t timeout_ms)
{
	uint64_t end = mxfs_pal_time_ms() + timeout_ms;

	while (mxfs_pal_time_ms() < end) {
		if (mep_epoch_of(env, i) >= epoch)
			return 1;
		mep_pump(env, 20);
	}
	return mep_epoch_of(env, i) >= epoch;
}

/* Wait until `slot`'s DISK record is valid at `epoch` with the given
 * PREPARED flag state. */
static int mep_wait_disk(struct mepenv *env, uint16_t slot, uint64_t epoch,
                         int prepared, uint32_t timeout_ms)
{
	uint64_t end = mxfs_pal_time_ms() + timeout_ms;
	struct mxfs_mepoch_rec r;

	while (mxfs_pal_time_ms() < end) {
		if (!mep_disk(env, slot, &r) && r.epoch == epoch &&
		    !!(r.flags & MXFS_MEPOCH_F_PREPARED) == !!prepared)
			return 1;
		mep_pump(env, 20);
	}
	return 0;
}

static uint64_t mep_mask(struct mepenv *env, int upto)
{
	uint64_t m = 0;
	int i;

	for (i = 0; i < upto; i++)
		m |= 1ULL << env->vc->nodes[i].slot;
	return m;
}

static void mep_incs(struct mepenv *env, uint32_t *incs)
{
	int i;

	memset(incs, 0, sizeof(uint32_t) * MXFS_MAX_NODES);
	for (i = 0; i < env->n; i++)
		incs[env->vc->nodes[i].slot] = env->vc->nodes[i].inc;
}

/* Form a cluster of nodes 0..count-1: genesis on 0, then serial joins
 * proposed by 0 (the lowest slot = deterministic proposer throughout).
 * Ends at epoch `count` with everyone caught up. */
static int mep_form(struct mepenv *env, int count)
{
	uint32_t incs[MXFS_MAX_NODES];
	int i, j, rc;

	rc = net2_mepoch_bootstrap(env->nodes[0].mp);
	if (rc)
		return rc;
	if (!mep_wait_epoch(env, 0, 1, 2000))
		return -ETIMEDOUT;
	for (i = 1; i < count; i++) {
		rc = net2_mepoch_bootstrap(env->nodes[i].mp);
		if (rc)
			return rc;
		if (!mep_wait_epoch(env, i, (uint64_t)i, 3000))
			return -ETIMEDOUT;
		mep_incs(env, incs);
		rc = net2_mepoch_propose(env->nodes[0].mp,
		                         mep_mask(env, i + 1), 0, 0, incs);
		if (rc)
			return rc;
		for (j = 0; j <= i; j++)
			if (!mep_wait_epoch(env, j, (uint64_t)i + 1, 3000))
				return -ETIMEDOUT;
	}
	return 0;
}

/* Drop every ingress frame on node i (the wire goes dark one-way). */
static int mep_drop_all_rx(struct mepenv *env, int i)
{
	struct mxfs_net2_fault_rule r;

	memset(&r, 0, sizeof(r));
	r.active = 1;
	r.action = MXFS_NET2_FAULT_DROP;
	r.dir = MXFS_NET2_FAULT_RECV;
	r.frame_class = MXFS_NET2_FAULT_ANY_CLASS;
	r.inner_type = MXFS_NET2_FAULT_ANY_TYPE;
	r.prob_ppm = 1000000;
	r.count = MXFS_NET2_FAULT_UNLIMITED;
	return mxfs_net2_fault_rule_set(env->vc->nodes[i].ctx, 0, &r);
}

/* ─── check 1: bootstrap ─── */

static int scen_mep_bootstrap(struct scenario_ctx *sc)
{
	struct mepenv env;
	struct mxfs_mepoch_rec r;
	uint16_t slot;

	if (mep_env_start(sc, &env, 1, 5000))
		return 1;
	slot = env.vc->nodes[0].slot;

	ck(sc, net2_mepoch_bootstrap(env.nodes[0].mp) == 0, "bootstrap rc");
	ck(sc, mep_wait_epoch(&env, 0, 1, 2000), "fresh image -> epoch 1");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[0].last.member_mask == (1ULL << slot),
	   "self-quorum member mask");
	ck(sc, env.nodes[0].last.fenced_mask == 0, "genesis fenced empty");
	ck(sc, env.nodes[0].last_incs[slot] == env.vc->nodes[0].inc,
	   "self incarnation in table");
	mxfs_pal_mutex_unlock(env.lock);

	/* the committed record must be on disk, sealed and valid */
	ck(sc, mep_disk(&env, slot, &r) == 0, "own HB record valid");
	ck(sc, r.epoch == 1 && r.member_mask == (1ULL << slot),
	   "disk record content");
	ck(sc, r.self_incarnation == env.vc->nodes[0].inc,
	   "disk record incarnation");
	ck(sc, r.voter_slots[0] == slot, "genesis voter is self");
	ck(sc, !(r.flags & MXFS_MEPOCH_F_PREPARED), "committed not PREPARED");

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 2: join + clean leave ─── */

static int scen_mep_join_leave(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint32_t incs[MXFS_MAX_NODES];
	uint64_t full;
	int i;

	if (mep_env_start(sc, &env, 3, 5000))
		return 1;
	full = mep_mask(&env, 3);

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");
	for (i = 0; i < 3; i++) {
		mxfs_pal_mutex_lock(env.lock);
		ck(sc, env.nodes[i].last.epoch == 3, "joins reached epoch 3");
		ck(sc, env.nodes[i].last.member_mask == full,
		   "full member mask everywhere");
		ck(sc, env.nodes[i].last_incs[env.vc->nodes[1].slot] ==
		   env.vc->nodes[1].inc, "joiner incarnation carried");
		mxfs_pal_mutex_unlock(env.lock);
	}

	/* clean leave of node 2: removal WITH proof, WITHOUT the fenced
	 * bit — a drained unmount is not a fence (§7.C/§7.D) */
	mep_incs(&env, incs);
	ck(sc, net2_mepoch_propose(env.nodes[0].mp, mep_mask(&env, 2), 0,
	                           1ULL << env.vc->nodes[2].slot,
	                           incs) == 0, "leave propose rc");
	for (i = 0; i < 2; i++)
		ck(sc, mep_wait_epoch(&env, i, 4, 3000),
		   "leave commits epoch 4");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[0].last.member_mask == mep_mask(&env, 2),
	   "leave removed the member");
	ck(sc, env.nodes[0].last.fenced_mask == 0,
	   "clean leave sets no fenced bit");
	mxfs_pal_mutex_unlock(env.lock);

	/* the leaver adopts the epoch that removed it and must NOT
	 * self-fence (no fenced bit) */
	ck(sc, mep_wait_epoch(&env, 2, 4, 3000), "leaver adopts epoch 4");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[2].self_fences == 0,
	   "clean leave never self-fences");
	mxfs_pal_mutex_unlock(env.lock);

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 3: proposer crash mid-round → PREPARED adoption ─── */

static int scen_mep_prepared_adoption(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint32_t incs[MXFS_MAX_NODES];
	uint64_t goal_mask;
	uint16_t s1, s2;
	int i;

	if (mep_env_start(sc, &env, 3, 5000))
		return 1;
	s1 = env.vc->nodes[1].slot;
	s2 = env.vc->nodes[2].slot;

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");

	/* node 0 proposes E4 excluding node 2 (with fence proof), but its
	 * ingress is dark: ACKs never arrive, commit can never happen */
	ck(sc, mep_drop_all_rx(&env, 0) == 0, "rx-drop rule on proposer");
	goal_mask = mep_mask(&env, 2);
	mep_incs(&env, incs);
	ck(sc, net2_mepoch_propose(env.nodes[0].mp, goal_mask,
	                           1ULL << s2, 1ULL << s2, incs) == 0,
	   "propose rc");

	/* both remote voters stage PREPARED E4 in their OWN records */
	ck(sc, mep_wait_disk(&env, s1, 4, 1, 3000),
	   "voter 1 staged PREPARED on disk");
	ck(sc, mep_wait_disk(&env, s2, 4, 1, 3000),
	   "voter 2 staged PREPARED on disk");
	ck(sc, mep_epoch_of(&env, 0) == 3, "no commit while acks dark");

	/* proposer dies pre-commit; survivors suspect it */
	mep_node_down(&env, 0);
	vc_node_kill(env.vc, 0);
	net2_mepoch_suspect(env.nodes[1].mp, env.vc->nodes[0].slot, true);
	net2_mepoch_suspect(env.nodes[2].mp, env.vc->nodes[0].slot, true);

	/* next-lowest voter must adopt the PREPARED candidate and finish
	 * the SAME decree — never invent a different E4 */
	for (i = 1; i < 3; i++)
		ck(sc, mep_wait_epoch(&env, i, 4, 5000),
		   "takeover completes epoch 4");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[1].last.member_mask == goal_mask,
	   "adopted candidate value (mask)");
	ck(sc, env.nodes[1].last.fenced_mask == (1ULL << s2),
	   "adopted candidate value (fenced)");
	/* node 2 was a member, is now excluded+fenced: self-fence */
	ck(sc, env.nodes[2].self_fences == 1 &&
	   env.nodes[2].fence_epoch == 4, "excluded voter self-fenced");
	mxfs_pal_mutex_unlock(env.lock);

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 4: voter-minority alive → stall + visible freeze ─── */

static int scen_mep_stall(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint32_t incs[MXFS_MAX_NODES];
	bool active = false;
	uint8_t reason = 0xff;
	int i;

	if (mep_env_start(sc, &env, 3, 800))
		return 1;

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");

	/* kill a majority of E3's voters (nodes 1+2) */
	for (i = 1; i < 3; i++) {
		mep_node_down(&env, i);
		vc_node_kill(env.vc, i);
		net2_mepoch_suspect(env.nodes[0].mp,
		                    env.vc->nodes[i].slot, true);
	}
	mep_incs(&env, incs);
	ck(sc, net2_mepoch_propose(env.nodes[0].mp, mep_mask(&env, 2),
	                           1ULL << env.vc->nodes[2].slot,
	                           1ULL << env.vc->nodes[2].slot,
	                           incs) == 0, "propose rc");

	/* no quorum: the round must stay open with no commit, and the
	 * lease must freeze VISIBLY (§7.E: never silent) */
	mep_pump(&env, 2200);
	ck(sc, mep_epoch_of(&env, 0) == 3, "no commit without majority");
	net2_mepoch_round_status(env.nodes[0].mp, &active, &reason);
	ck(sc, active, "round still open (stalled, not dead)");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[0].freezes >= 1 && env.nodes[0].frozen,
	   "lease freeze fired and holds");
	mxfs_pal_mutex_unlock(env.lock);

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 5: whole-cluster restart → max committed adopted ─── */

static int scen_mep_restart_all(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint64_t full;
	int i;

	if (mep_env_start(sc, &env, 3, 5000))
		return 1;
	full = mep_mask(&env, 3);

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");

	/* stop every instance, then re-adopt from the surviving image */
	for (i = 0; i < 3; i++)
		mep_node_down(&env, i);
	mxfs_pal_mutex_lock(env.lock);
	for (i = 0; i < 3; i++) {
		env.nodes[i].commits = 0;
		memset(&env.nodes[i].last, 0, sizeof(env.nodes[i].last));
	}
	mxfs_pal_mutex_unlock(env.lock);

	for (i = 0; i < 3; i++) {
		ck(sc, mep_node_up(&env, i, 5000) == 0, "restart instance");
		ck(sc, net2_mepoch_bootstrap(env.nodes[i].mp) == 0,
		   "restart bootstrap rc");
	}
	for (i = 0; i < 3; i++) {
		ck(sc, mep_wait_epoch(&env, i, 3, 2000),
		   "restart adopts epoch 3");
		mxfs_pal_mutex_lock(env.lock);
		ck(sc, env.nodes[i].last.member_mask == full,
		   "restart mask preserved");
		ck(sc, env.nodes[i].last_incs[env.vc->nodes[1].slot] ==
		   env.vc->nodes[1].inc, "restart incs preserved");
		ck(sc, env.nodes[i].commits == 1,
		   "exactly one adoption, no re-genesis");
		mxfs_pal_mutex_unlock(env.lock);
	}

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 6: excluded node, zero network → disk self-fence ─── */

static int scen_mep_disk_self_fence(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint32_t incs[MXFS_MAX_NODES];
	uint16_t s2;
	uint64_t e2, rx_before;
	int i;

	if (mep_env_start(sc, &env, 3, 30000))
		return 1;
	s2 = env.vc->nodes[2].slot;

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");

	/* node 2 goes network-dark BOTH ways: every ingress frame drops
	 * and every peer drops it from the desired view */
	ck(sc, mep_drop_all_rx(&env, 2) == 0, "rx-drop rule on victim");
	mxfs_pal_mutex_lock(env.lock);
	rx_before = env.nodes[2].rx_frames;
	mxfs_pal_mutex_unlock(env.lock);
	vc_view_node(env.vc, 2, 1ULL << s2, 3);
	vc_view_node(env.vc, 0, mep_mask(&env, 2), 3);
	vc_view_node(env.vc, 1, mep_mask(&env, 2), 3);

	/* survivors commit the exclusion (fence proof supplied) */
	mep_incs(&env, incs);
	ck(sc, net2_mepoch_propose(env.nodes[0].mp, mep_mask(&env, 2),
	                           1ULL << s2, 1ULL << s2, incs) == 0,
	   "exclusion propose rc");
	for (i = 0; i < 2; i++)
		ck(sc, mep_wait_epoch(&env, i, 4, 3000),
		   "survivors commit epoch 4");

	/* the victim can ONLY learn from the LUN: its periodic disk scan
	 * must adopt E4 and fire the self-fence */
	ck(sc, mep_wait_epoch(&env, 2, 4, 3000),
	   "victim adopts via disk scan");
	mxfs_pal_mutex_lock(env.lock);
	ck(sc, env.nodes[2].self_fences == 1 &&
	   env.nodes[2].fence_epoch == 4,
	   "disk-visible self-fence fired");
	mxfs_pal_mutex_unlock(env.lock);
	/* zero network really means zero: nothing was delivered to 2
	 * after it went dark (its recv cb counts every delivery; frames
	 * the fault engine drops never reach it) */
	mxfs_pal_mutex_lock(env.lock);
	e2 = env.nodes[2].rx_frames - rx_before;
	mxfs_pal_mutex_unlock(env.lock);
	ck(sc, e2 == 0, "no wire delivery reached the victim");

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── check 7: exclusion without fence proof → NACK, dead round ─── */

static int scen_mep_no_fence_proof(struct scenario_ctx *sc)
{
	struct mepenv env;
	uint32_t incs[MXFS_MAX_NODES];
	struct mxfs_mepoch_rec r;
	bool active = true;
	uint8_t reason = 0;
	uint16_t s;
	int i;

	if (mep_env_start(sc, &env, 3, 5000))
		return 1;

	ck(sc, mep_form(&env, 3) == 0, "form 3-node cluster");

	/* exclusion carrying NO fence_done proof: the voters must refuse
	 * it — quorum without fencing can never commit (§7.C R4) */
	mep_incs(&env, incs);
	ck(sc, net2_mepoch_propose(env.nodes[0].mp, mep_mask(&env, 2),
	                           1ULL << env.vc->nodes[2].slot,
	                           0 /* no proof */, incs) == 0,
	   "propose rc (round starts then dies)");
	mep_pump(&env, 500);
	net2_mepoch_round_status(env.nodes[0].mp, &active, &reason);
	ck(sc, !active, "round dead, not retrying");
	ck(sc, reason == N2ME_NO_FENCE_PROOF, "NACK reason recorded");
	for (i = 0; i < 3; i++)
		ck(sc, mep_epoch_of(&env, i) == 3, "epoch unchanged");
	for (i = 0; i < 3; i++) {
		s = env.vc->nodes[i].slot;
		ck(sc, mep_disk(&env, s, &r) == 0 && r.epoch == 3 &&
		   !(r.flags & MXFS_MEPOCH_F_PREPARED),
		   "no PREPARED E4 leaked to disk");
	}

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── §7.C observer/SUSPECT machine + persisted incarnation ─── */

struct mb_ev {
	int n;
	struct {
		uint16_t slot;
		enum net2_member_state from, to;
	} ev[16];
};

static void mb_state_cb(void *cb_data, uint16_t slot,
                        enum net2_member_state from,
                        enum net2_member_state to)
{
	struct mb_ev *e = cb_data;

	if (e->n < 16) {
		e->ev[e->n].slot = slot;
		e->ev[e->n].from = from;
		e->ev[e->n].to = to;
		e->n++;
	}
}

static int scen_mep_membership(struct scenario_ctx *sc)
{
	struct net2_membership_cfg cfg;
	struct net2_membership *mb = NULL;
	struct mb_ev ev = { .n = 0 };
	struct mepenv env;
	struct mxfs_mepoch_rec r;
	uint32_t inc = 0;
	uint64_t t, n1, n2;
	const uint16_t peer = 3;

	/* storage-only env (no wire traffic in this scenario) */
	if (mep_env_start(sc, &env, 1, 5000))
		return 1;

	memset(&cfg, 0, sizeof(cfg));
	cfg.self_slot = env.vc->nodes[0].slot;
	cfg.miss_ms = 60;
	cfg.grace_ms = 200;
	cfg.state_cb = mb_state_cb;
	cfg.cb_data = &ev;
	ck(sc, net2_membership_create(&cfg, &mb) == 0, "membership create");

	t = mxfs_pal_time_ms();
	net2_membership_track(mb, peer, 7, 0x1111);
	ck(sc, net2_membership_state(mb, peer) == N2MB_ACTIVE,
	   "tracked -> ACTIVE");

	/* one observer silent, two alive: never SUSPECT */
	t += 100;
	net2_membership_observe(mb, peer, N2OBS_PROBE, 7, 0x1111, t);
	net2_membership_observe(mb, peer, N2OBS_DISK, 7, 0x1111, t);
	net2_membership_tick(mb, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_ACTIVE,
	   "1 missing observer stays ACTIVE");

	/* two observers silent: SUSPECT */
	t += 100;
	net2_membership_observe(mb, peer, N2OBS_DISK, 7, 0x1111, t);
	net2_membership_tick(mb, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_SUSPECT,
	   ">=2 missing -> SUSPECT");

	/* same-identity reconnect within grace: back to ACTIVE */
	t += 100;
	net2_membership_observe(mb, peer, N2OBS_LEASE, 7, 0x1111, t);
	net2_membership_observe(mb, peer, N2OBS_PROBE, 7, 0x1111, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_ACTIVE,
	   "same inc+nonce within grace -> ACTIVE");

	/* silence again; a DIFFERENT incarnation must NOT resume it */
	t += 100;
	net2_membership_tick(mb, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_SUSPECT,
	   "silent again -> SUSPECT");
	net2_membership_observe(mb, peer, N2OBS_PROBE, 8, 0x2222, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_SUSPECT,
	   "new incarnation never resumes old");

	/* grace elapses -> FENCING; DEAD only via matching fence_done */
	t += 250;
	net2_membership_tick(mb, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_FENCING,
	   "grace elapsed -> FENCING");
	net2_membership_fence_done(mb, peer, 99);
	ck(sc, net2_membership_state(mb, peer) == N2MB_FENCING,
	   "wrong-incarnation fence_done ignored");
	net2_membership_fence_done(mb, peer, 7);
	ck(sc, net2_membership_state(mb, peer) == N2MB_DEAD,
	   "incarnation-qualified fence_done -> DEAD");
	net2_membership_observe(mb, peer, N2OBS_PROBE, 7, 0x1111, t);
	ck(sc, net2_membership_state(mb, peer) == N2MB_DEAD,
	   "DEAD is terminal for that incarnation");
	ck(sc, ev.n == 6, "each transition fired exactly once");

	net2_membership_destroy(mb);

	/* persisted incarnation bump (§5) through the storage vtable */
	{
		struct net2_mepoch_storage st = {
			.data = &env.nodes[0],
			.read_rec = mep_st_read,
			.write_rec = mep_st_write,
		};

		ck(sc, net2_membership_inc_bump(&st,
		   env.vc->nodes[0].slot, &inc) == 0, "bump rc");
		ck(sc, inc == 1, "fresh record bumps to 1");
		ck(sc, net2_membership_inc_bump(&st,
		   env.vc->nodes[0].slot, &inc) == 0, "bump rc 2");
		ck(sc, inc == 2, "second bump to 2");

		/* bump must preserve committed content + PREPARED flag */
		memset(&r, 0, sizeof(r));
		r.epoch = 9;
		r.member_mask = 0x7;
		r.fenced_mask = 0x4;
		r.self_incarnation = 2;
		r.flags = MXFS_MEPOCH_F_PREPARED;
		mxfs_mepoch_rec_seal(&r);
		ck(sc, mep_st_write(&env.nodes[0], &r) == 0, "seed write");
		ck(sc, net2_membership_inc_bump(&st,
		   env.vc->nodes[0].slot, &inc) == 0, "bump rc 3");
		ck(sc, inc == 3, "bump over committed content");
		ck(sc, mep_disk(&env, env.vc->nodes[0].slot, &r) == 0,
		   "bumped record still sealed");
		ck(sc, r.epoch == 9 && r.member_mask == 0x7 &&
		   r.fenced_mask == 0x4 &&
		   (r.flags & MXFS_MEPOCH_F_PREPARED),
		   "bump preserved content incl. PREPARED");
	}

	n1 = net2_membership_boot_nonce();
	n2 = net2_membership_boot_nonce();
	ck(sc, n1 && n2 && n1 != n2, "boot nonces nonzero and distinct");

	mep_env_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── table ─── */

const struct scenario net2_scen_mepoch[] = {
	{ "mep_bootstrap",         scen_mep_bootstrap,         0 },
	{ "mep_join_leave",        scen_mep_join_leave,        0 },
	{ "mep_prepared_adoption", scen_mep_prepared_adoption, 0 },
	{ "mep_stall",             scen_mep_stall,             0 },
	{ "mep_restart_all",       scen_mep_restart_all,       0 },
	{ "mep_disk_self_fence",   scen_mep_disk_self_fence,   0 },
	{ "mep_no_fence_proof",    scen_mep_no_fence_proof,    0 },
	{ "mep_membership",        scen_mep_membership,        0 },
};
const int net2_scen_mepoch_count =
	(int)(sizeof(net2_scen_mepoch) / sizeof(net2_scen_mepoch[0]));
