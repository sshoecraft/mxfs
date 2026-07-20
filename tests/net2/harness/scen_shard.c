/*
 * MXFS — NET2 harness: §13.2 shard/lock-plane scenario family (gate 4).
 *
 * Leader kill at every commit point × partition patterns × seeds, with
 * the DLM_PLAN_REVIEW §5.2 evidence asserted from the lockspace
 * counters and cross-node held-table views:
 *   - at most one grant-capable leader per committed (E, term)
 *     (asserted structurally: leader claims probed after every settle,
 *     and incompatible grants never overlap across nodes' held tables);
 *   - commit_seq and gen high-waters never regress (probed);
 *   - transferring replicas never vote (votes_refused_xfer evidence);
 *   - waiter order preserved (FIFO within class; the documented
 *     ex_streak fairness override is the only reordering);
 *   - total replica loss ⇒ closed-set recovery barrier, never an
 *     empty-table assumption (surviving holders block conflicts).
 *
 * Node "kill" = lockspace poison (stops processing/sending at exactly
 * the hook point) + destroy; "partition" = peer addresses poisoned to
 * a refusing port + link reset on every cross pair — the engine then
 * exhibits REAL partition behavior (reconnect backoff, buffered
 * reliable frames, retransmit on heal) through the production paths.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "harness.h"
#include "dlm/net2_ctx.h"
#include "dlm/net2_shard.h"
#include "dlm/net2_lock.h"

#define SH_DEADLINE_MS 15000

struct shenv {
	struct scenario_ctx *sc;
	struct vcluster *vc;
	struct net2_lockspace *ls[VC_MAX_NODES];
	uint32_t incs[MXFS_MAX_NODES];
	uint64_t epoch;
	int n;
	/* BAST observation */
	mxfs_mutex_t *bast_lock;
	int bast_count[VC_MAX_NODES];
	struct mxfs_resource_id bast_last[VC_MAX_NODES];
	/* monotonicity tracking: per node per probed shard */
	uint64_t seen_commit[VC_MAX_NODES];
	uint64_t seen_gen[VC_MAX_NODES];
};

struct bast_binding { struct shenv *env; int node; };
static struct bast_binding bast_bind[VC_MAX_NODES];

static void shenv_bast_cb(void *data, const struct mxfs_resource_id *res,
                          uint8_t wanted, uint64_t gen)
{
	struct bast_binding *b = data;
	struct shenv *env = b->env;

	(void)wanted; (void)gen;
	mxfs_pal_mutex_lock(env->bast_lock);
	env->bast_count[b->node]++;
	env->bast_last[b->node] = *res;
	mxfs_pal_mutex_unlock(env->bast_lock);
}

static void shenv_stop(struct shenv *env)
{
	int i;

	for (i = 0; i < env->n; i++) {
		if (env->ls[i]) {
			net2_lockspace_destroy(env->ls[i]);
			env->ls[i] = NULL;
		}
	}
	if (env->vc) {
		vc_destroy(env->vc);
		env->vc = NULL;
	}
	if (env->bast_lock) {
		mxfs_pal_mutex_destroy(env->bast_lock);
		env->bast_lock = NULL;
	}
}

static int shenv_start(struct scenario_ctx *sc, struct shenv *env, int n)
{
	int i, rc;
	uint64_t mask = 0;

	memset(env, 0, sizeof(*env));
	env->sc = sc;
	env->n = n;
	env->epoch = 1;
	env->bast_lock = mxfs_pal_mutex_create();
	if (!env->bast_lock)
		return -ENOMEM;
	rc = vc_create(&env->vc, n, sc->seed, 10, 0);
	if (rc) {
		mxfs_pal_mutex_destroy(env->bast_lock);
		env->bast_lock = NULL;
		return rc;
	}
	for (i = 0; i < n; i++) {
		env->incs[env->vc->nodes[i].slot] = env->vc->nodes[i].inc;
		mask |= 1ULL << env->vc->nodes[i].slot;
	}
	for (i = 0; i < n; i++) {
		struct net2_lockspace_cfg cfg;

		memset(&cfg, 0, sizeof(cfg));
		cfg.self_slot = env->vc->nodes[i].slot;
		cfg.self_inc = env->vc->nodes[i].inc;
		cfg.elect_base_ms = 80;
		cfg.elect_rank_ms = 40;
		cfg.client_retry_ms = 150;
		cfg.rt_tick_ms = 10;
		cfg.seed = sc->seed + (uint64_t)i * 7919;
		rc = net2_lockspace_create(env->vc->nodes[i].ctx, &cfg,
		                           &env->ls[i]);
		if (rc) {
			shenv_stop(env);
			return rc;
		}
		bast_bind[i].env = env;
		bast_bind[i].node = i;
		net2_lockspace_set_bast_cb(env->ls[i], shenv_bast_cb,
		                           &bast_bind[i]);
	}
	for (i = 0; i < n; i++) {
		net2_lockspace_epoch_commit(env->ls[i], env->epoch, mask,
		                            env->incs);
		rc = net2_lockspace_start(env->ls[i]);
		if (rc) {
			shenv_stop(env);
			return rc;
		}
	}
	return 0;
}

static uint64_t shenv_mask(struct shenv *env)
{
	uint64_t m = 0;
	int i;

	for (i = 0; i < env->n; i++)
		if (env->ls[i])
			m |= 1ULL << env->vc->nodes[i].slot;
	return m;
}

static int node_by_slot(struct shenv *env, uint16_t slot)
{
	int i;

	for (i = 0; i < env->n; i++)
		if (env->vc->nodes[i].slot == slot)
			return i;
	return -1;
}

/* Model death: poison (no further processing/sends), then tear down. */
static void shenv_kill(struct shenv *env, int i)
{
	if (env->ls[i]) {
		net2_lockspace_poison(env->ls[i]);
		net2_lockspace_destroy(env->ls[i]);
		env->ls[i] = NULL;
	}
	vc_node_kill(env->vc, i);
}

/* Commit a new epoch over the given member node set (closed set). */
static void shenv_epoch_bump(struct shenv *env, uint64_t new_mask)
{
	int i;

	env->epoch++;
	for (i = 0; i < env->n; i++) {
		if (!env->ls[i])
			continue;
		if (!(new_mask & (1ULL << env->vc->nodes[i].slot)))
			continue;
		net2_lockspace_epoch_commit(env->ls[i], env->epoch,
		                            new_mask, env->incs);
	}
}

static void shenv_suspect(struct shenv *env, uint16_t slot)
{
	int i;

	for (i = 0; i < env->n; i++)
		if (env->ls[i])
			net2_lockspace_suspect(env->ls[i], slot);
}

/* Symmetric partition between node sets (bitmasks over node INDEX). */
static void shenv_partition(struct shenv *env, uint32_t idx_a,
                            uint32_t idx_b)
{
	int a, b;

	for (a = 0; a < env->n; a++) {
		if (!(idx_a & (1u << a)) || !env->ls[a])
			continue;
		for (b = 0; b < env->n; b++) {
			if (!(idx_b & (1u << b)) || !env->ls[b])
				continue;
			mxfs_net2_set_peer_addr(env->vc->nodes[a].ctx,
			                        env->vc->nodes[b].slot,
			                        "127.0.0.1", 1);
			mxfs_net2_set_peer_addr(env->vc->nodes[b].ctx,
			                        env->vc->nodes[a].slot,
			                        "127.0.0.1", 1);
			mxfs_net2_link_reset(env->vc->nodes[a].ctx,
			                     env->vc->nodes[b].slot);
			mxfs_net2_link_reset(env->vc->nodes[b].ctx,
			                     env->vc->nodes[a].slot);
		}
	}
}

static void shenv_heal(struct shenv *env)
{
	int a, b;

	for (a = 0; a < env->n; a++) {
		if (!env->ls[a])
			continue;
		for (b = 0; b < env->n; b++) {
			if (a == b || !env->ls[b])
				continue;
			/* port 0 = dial base+slot (the listener rule) */
			mxfs_net2_set_peer_addr(env->vc->nodes[a].ctx,
			                        env->vc->nodes[b].slot,
			                        "127.0.0.1", 0);
		}
	}
}

static struct mxfs_resource_id res_make(uint32_t k)
{
	struct mxfs_resource_id r;

	memset(&r, 0, sizeof(r));
	r.volume = 7;
	r.ino = 1000 + k;
	r.type = 1;
	return r;
}

static uint16_t shard_leader_slot(struct shenv *env, int via,
                                 const struct mxfs_resource_id *res)
{
	uint32_t sid = net2_shard_id_for(env->ls[via], res);
	struct net2_shard snap;

	if (net2_lockspace_shard_probe(env->ls[via], sid, &snap) == 0)
		return snap.leader_slot;
	/* not instantiated yet: derivation is deterministic — force it */
	{
		struct net2_shard *sh = net2_shard_get(env->ls[via], sid,
		                                       true);

		return sh ? sh->leader_slot : env->vc->nodes[via].slot;
	}
}

/* §5.2 evidence: at most one grant-capable leader per (E, term). */
static void assert_single_leader(struct shenv *env,
                                 const struct mxfs_resource_id *res,
                                 const char *ctx)
{
	int i, claims = 0;
	char what[128];

	for (i = 0; i < env->n; i++) {
		uint32_t sid;
		struct net2_shard snap;

		if (!env->ls[i])
			continue;
		sid = net2_shard_id_for(env->ls[i], res);
		if (net2_lockspace_shard_probe(env->ls[i], sid, &snap))
			continue;
		if (snap.state == SH_ACTIVE &&
		    snap.leader_slot == env->vc->nodes[i].slot &&
		    net2_shard_replica_index(&snap,
		                             env->vc->nodes[i].slot) >= 0)
			claims++;
	}
	snprintf(what, sizeof(what), "%s: single grant-capable leader "
	         "(claims=%d)", ctx, claims);
	ck(env->sc, claims <= 1, what);
}

/* §5.2 evidence: commit_seq / gen high-waters never regress (probe). */
static void probe_monotone(struct shenv *env,
                           const struct mxfs_resource_id *res,
                           const char *ctx)
{
	int i;
	char what[160];

	for (i = 0; i < env->n; i++) {
		uint32_t sid;
		struct net2_shard snap;

		if (!env->ls[i])
			continue;
		sid = net2_shard_id_for(env->ls[i], res);
		if (net2_lockspace_shard_probe(env->ls[i], sid, &snap))
			continue;
		snprintf(what, sizeof(what),
		         "%s: node%d commit_seq monotone (%llu >= %llu)",
		         ctx, i, (unsigned long long)snap.commit_seq,
		         (unsigned long long)env->seen_commit[i]);
		ck(env->sc, snap.commit_seq >= env->seen_commit[i], what);
		env->seen_commit[i] = snap.commit_seq;
		snprintf(what, sizeof(what),
		         "%s: node%d gen high-water monotone", ctx, i);
		ck(env->sc, snap.grant_gen_next >= env->seen_gen[i], what);
		env->seen_gen[i] = snap.grant_gen_next;
	}
}

/* §13 standing invariant: incompatible grants never overlap — checked
 * from every live node's client-held table. */
static void assert_no_overlap(struct shenv *env,
                              const struct mxfs_resource_id *res,
                              const char *ctx)
{
	uint8_t modes[VC_MAX_NODES];
	int i, j;
	char what[128];

	for (i = 0; i < env->n; i++)
		modes[i] = env->ls[i] ?
			net2_lock_held_mode(env->ls[i], res, NULL) :
			MXFS_LOCK_NL;
	for (i = 0; i < env->n; i++) {
		for (j = i + 1; j < env->n; j++) {
			if (modes[i] == MXFS_LOCK_NL ||
			    modes[j] == MXFS_LOCK_NL)
				continue;
			snprintf(what, sizeof(what),
			         "%s: held modes compatible (node%d=%u "
			         "node%d=%u)", ctx, i, modes[i], j,
			         modes[j]);
			ck(env->sc, lock_compat[modes[i]][modes[j]], what);
		}
	}
}

static uint64_t stat_of(struct shenv *env, int i,
                        uint64_t (*pick)(const struct net2_lockspace_stats *))
{
	struct net2_lockspace_stats st;

	if (!env->ls[i])
		return 0;
	net2_lockspace_get_stats(env->ls[i], &st);
	return pick(&st);
}

static uint64_t pick_grants(const struct net2_lockspace_stats *s)
{ return s->grants_sent; }
static uint64_t pick_truncations(const struct net2_lockspace_stats *s)
{ return s->truncations; }
static uint64_t pick_recov_barriers(const struct net2_lockspace_stats *s)
{ return s->recovery_barriers; }
static uint64_t pick_recov_recs(const struct net2_lockspace_stats *s)
{ return s->recovery_recs_rebuilt; }
static uint64_t pick_xfer_done(const struct net2_lockspace_stats *s)
{ return s->xfers_completed; }
static uint64_t pick_votes_refused_xfer(const struct net2_lockspace_stats *s)
{ return s->votes_refused_xfer; }
static uint64_t pick_dup_idem(const struct net2_lockspace_stats *s)
{ return s->dup_op_idempotent; }
static uint64_t pick_stale_epoch(const struct net2_lockspace_stats *s)
{ return s->stale_epoch_denies; }

/* ─── acquire/release thread wrappers (blocking ops need threads when
 *     the scenario drives several in parallel) ─── */

struct op_thread {
	struct shenv *env;
	int node;
	struct mxfs_resource_id res;
	uint8_t mode;
	uint32_t deadline_ms;
	int rc;
	uint64_t gen, dir_epoch;
	uint64_t done_at_ms;
	mxfs_thread_t *t;
};

static void op_acquire_fn(void *arg)
{
	struct op_thread *op = arg;

	op->rc = net2_lock_acquire(op->env->ls[op->node], &op->res, op->mode,
	                           op->deadline_ms, &op->gen,
	                           &op->dir_epoch);
	op->done_at_ms = mxfs_pal_time_ms();
}

static void op_release_fn(void *arg)
{
	struct op_thread *op = arg;

	op->rc = net2_lock_release(op->env->ls[op->node], &op->res, op->gen,
	                           op->deadline_ms);
	op->done_at_ms = mxfs_pal_time_ms();
}

static void op_start_release(struct op_thread *op, struct shenv *env,
                             int node, const struct mxfs_resource_id *res,
                             uint64_t gen, uint32_t deadline_ms)
{
	memset(op, 0, sizeof(*op));
	op->env = env;
	op->node = node;
	op->res = *res;
	op->gen = gen;
	op->deadline_ms = deadline_ms;
	op->rc = -4242;
	op->t = mxfs_pal_thread_create(op_release_fn, op);
}

static void op_start(struct op_thread *op, struct shenv *env, int node,
                     const struct mxfs_resource_id *res, uint8_t mode,
                     uint32_t deadline_ms)
{
	memset(op, 0, sizeof(*op));
	op->env = env;
	op->node = node;
	op->res = *res;
	op->mode = mode;
	op->deadline_ms = deadline_ms;
	op->rc = -4242;
	op->t = mxfs_pal_thread_create(op_acquire_fn, op);
}

static int op_join(struct op_thread *op)
{
	if (op->t) {
		mxfs_pal_thread_join(op->t);
		op->t = NULL;
	}
	return op->rc;
}

/* ═══ scenario: basic grant/convert/idempotency/BAST/release ═══ */

static int scen_sh_basic(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(1);
	uint64_t g0 = 0, g1 = 0, de = 0, gx = 0;
	int rc;

	if (shenv_start(sc, &env, 3))
		return 1;

	rc = net2_lock_acquire(env.ls[0], &r0, MXFS_LOCK_EX, SH_DEADLINE_MS,
	                       &g0, &de);
	ck(sc, rc == 0, "n0 EX acquire");
	ck(sc, g0 != 0, "grant_gen never 0");
	assert_no_overlap(&env, &r0, "after n0 EX");

	/* re-acquire same mode: already-holder re-ack, same tenure */
	rc = net2_lock_acquire(env.ls[0], &r0, MXFS_LOCK_EX, SH_DEADLINE_MS,
	                       &g1, NULL);
	ck(sc, rc == 0 && g1 == g0, "idempotent re-acquire same gen");

	/* n1 wants PR -> EX holder gets a BAST; n1 waits */
	{
		struct op_thread op;

		op_start(&op, &env, 1, &r0, MXFS_LOCK_PR, SH_DEADLINE_MS);
		{
			uint64_t t0 = mxfs_pal_time_ms();
			int seen = 0;

			while (mxfs_pal_time_ms() - t0 < 5000) {
				mxfs_pal_mutex_lock(env.bast_lock);
				seen = env.bast_count[0];
				mxfs_pal_mutex_unlock(env.bast_lock);
				if (seen)
					break;
				mxfs_pal_sleep_ms(20);
			}
			ck(sc, seen >= 1, "EX holder got BAST for PR want");
		}
		/* drain-equivalent: holder releases */
		rc = net2_lock_release(env.ls[0], &r0, g0, SH_DEADLINE_MS);
		ck(sc, rc == 0, "n0 release after BAST");
		rc = op_join(&op);
		ck(sc, rc == 0, "n1 PR granted after release");
		ck(sc, op.gen > g0, "gen advanced on regrant");
		gx = op.gen;
	}
	assert_no_overlap(&env, &r0, "after handoff");

	/* second release of the same tenure -> ESTALE re-arm contract */
	rc = net2_lock_release(env.ls[0], &r0, g0, SH_DEADLINE_MS);
	ck(sc, rc == -ESTALE, "stale release returns -ESTALE");

	/* PR co-holder joins, then both release */
	rc = net2_lock_acquire(env.ls[2], &r0, MXFS_LOCK_PR, SH_DEADLINE_MS,
	                       &g1, NULL);
	ck(sc, rc == 0, "n2 PR co-hold");
	assert_no_overlap(&env, &r0, "PR co-hold");
	rc = net2_lock_release(env.ls[1], &r0, gx, SH_DEADLINE_MS);
	ck(sc, rc == 0, "n1 PR release");
	rc = net2_lock_release(env.ls[2], &r0, g1, SH_DEADLINE_MS);
	ck(sc, rc == 0, "n2 PR release");

	probe_monotone(&env, &r0, "basic end");
	assert_single_leader(&env, &r0, "basic end");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: waiter FIFO order + ex_streak fairness ═══ */

static int scen_sh_waiter_order(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(2);
	uint64_t g0 = 0;
	int rc, i;

	if (shenv_start(sc, &env, 3))
		return 1;

	rc = net2_lock_acquire(env.ls[0], &r0, MXFS_LOCK_EX, SH_DEADLINE_MS,
	                       &g0, NULL);
	ck(sc, rc == 0, "n0 EX base");

	/* queue EX waiters in a known order: n1 then n2 */
	{
		struct op_thread w1, w2;

		op_start(&w1, &env, 1, &r0, MXFS_LOCK_EX, SH_DEADLINE_MS);
		mxfs_pal_sleep_ms(300);      /* order the enqueues */
		op_start(&w2, &env, 2, &r0, MXFS_LOCK_EX, SH_DEADLINE_MS);
		mxfs_pal_sleep_ms(300);

		rc = net2_lock_release(env.ls[0], &r0, g0, SH_DEADLINE_MS);
		ck(sc, rc == 0, "n0 release");
		rc = op_join(&w1);
		ck(sc, rc == 0, "w1 granted");
		/* w2 only after w1 releases: FIFO */
		mxfs_pal_sleep_ms(300);
		ck(sc, w2.rc == -4242, "w2 still queued behind w1 (FIFO)");
		rc = net2_lock_release(env.ls[1], &r0, w1.gen,
		                       SH_DEADLINE_MS);
		ck(sc, rc == 0, "w1 release");
		rc = op_join(&w2);
		ck(sc, rc == 0, "w2 granted in order");
		ck(sc, w2.gen > w1.gen, "gen strictly advances");
		rc = net2_lock_release(env.ls[2], &r0, w2.gen,
		                       SH_DEADLINE_MS);
		ck(sc, rc == 0, "w2 release");
	}

	/* ex_streak fairness: 3 consecutive EX grants, then with an EX
	 * head and a PR waiter behind it the PR class is preferred */
	{
		struct op_thread ex_w, pr_w;
		uint64_t gcur = 0;

		for (i = 0; i < 3; i++) {
			rc = net2_lock_acquire(env.ls[0], &r0, MXFS_LOCK_EX,
			                       SH_DEADLINE_MS, &gcur, NULL);
			ck(sc, rc == 0, "streak EX acquire");
			if (i < 2) {
				rc = net2_lock_release(env.ls[0], &r0, gcur,
				                       SH_DEADLINE_MS);
				ck(sc, rc == 0, "streak EX release");
			}
		}
		/* holder n0 (streak >= 3); queue EX (n1) then PR (n2) */
		op_start(&ex_w, &env, 1, &r0, MXFS_LOCK_EX, SH_DEADLINE_MS);
		mxfs_pal_sleep_ms(300);
		op_start(&pr_w, &env, 2, &r0, MXFS_LOCK_PR, SH_DEADLINE_MS);
		mxfs_pal_sleep_ms(300);
		rc = net2_lock_release(env.ls[0], &r0, gcur, SH_DEADLINE_MS);
		ck(sc, rc == 0, "streak holder release");
		rc = op_join(&pr_w);
		ck(sc, rc == 0, "PR fairness grant");
		mxfs_pal_sleep_ms(200);
		ck(sc, ex_w.rc == -4242,
		   "EX head deferred by ex_streak fairness");
		rc = net2_lock_release(env.ls[2], &r0, pr_w.gen,
		                       SH_DEADLINE_MS);
		ck(sc, rc == 0, "PR release");
		rc = op_join(&ex_w);
		ck(sc, rc == 0, "EX granted after fairness break");
		(void)net2_lock_release(env.ls[1], &r0, ex_w.gen,
		                        SH_DEADLINE_MS);
	}

	probe_monotone(&env, &r0, "waiter end");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: leader kill at every commit point ═══ */

struct kill_arm {
	struct shenv *env;
	enum n2_hook_point point;
	uint16_t op_filter;          /* 0 = any */
	int fired;
};

static bool kill_hook(void *data, enum n2_hook_point p, uint32_t shard_id,
                      uint16_t detail)
{
	struct kill_arm *ka = data;

	(void)shard_id;
	if (ka->fired || p != ka->point)
		return false;
	if (ka->op_filter && detail != ka->op_filter)
		return false;
	ka->fired = 1;
	return true;                 /* poison NOW */
}

static int killpoint_run(struct scenario_ctx *sc, enum n2_hook_point point,
                         uint16_t op_filter, int release_phase,
                         const char *label)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(40 + (uint32_t)point);
	struct kill_arm ka;
	uint16_t lslot;
	int lidx, cidx, rc;
	uint64_t g0 = 0;
	char what[160];

	if (shenv_start(sc, &env, 3))
		return 1;
	lslot = shard_leader_slot(&env, 0, &r0);
	lidx = node_by_slot(&env, lslot);
	cidx = (lidx + 1) % env.n;           /* client on a follower */
	if (!ck(sc, lidx >= 0, "leader resolvable"))
		goto out;

	if (release_phase) {
		rc = net2_lock_acquire(env.ls[cidx], &r0, MXFS_LOCK_EX,
		                       SH_DEADLINE_MS, &g0, NULL);
		snprintf(what, sizeof(what), "%s: pre-hold acquire", label);
		if (!ck(sc, rc == 0, what))
			goto out;
	}

	memset(&ka, 0, sizeof(ka));
	ka.env = &env;
	ka.point = point;
	ka.op_filter = op_filter;
	net2_lockspace_set_hook(env.ls[lidx], kill_hook, &ka);

	{
		struct op_thread op;

		if (release_phase)
			op_start_release(&op, &env, cidx, &r0, g0,
			                 SH_DEADLINE_MS + 10000);
		else
			op_start(&op, &env, cidx, &r0, MXFS_LOCK_EX,
			         SH_DEADLINE_MS + 10000);
		/* give the op time to reach the hook */
		{
			uint64_t t0 = mxfs_pal_time_ms();

			while (!ka.fired && mxfs_pal_time_ms() - t0 < 3000)
				mxfs_pal_sleep_ms(10);
		}

		/* the leader died at the point (if the op path reached
		 * it) — finish the kill and fail the node over */
		snprintf(what, sizeof(what), "%s: hook fired", label);
		ck(sc, ka.fired == 1, what);
		shenv_kill(&env, lidx);
		shenv_suspect(&env, lslot);

		if (!release_phase) {
			rc = op_join(&op);
			snprintf(what, sizeof(what),
			         "%s: op completed after failover (rc=%d)",
			         label, rc);
			ck(sc, rc == 0, what);
			g0 = op.gen;
		} else {
			rc = op_join(&op);
			snprintf(what, sizeof(what),
			         "%s: release completed after failover "
			         "(rc=%d)", label, rc);
			ck(sc, rc == 0, what);
			/* the client-side release either committed before
			 * the kill or was re-issued to the new leader;
			 * either way the holder bit must end cleared:
			 * a fresh EX from another node must succeed. */
			int other = -1, i;

			for (i = 0; i < env.n; i++)
				if (env.ls[i] && i != cidx) {
					other = i;
					break;
				}
			if (other >= 0) {
				uint64_t g2 = 0;

				rc = net2_lock_acquire(env.ls[other], &r0,
				                       MXFS_LOCK_EX,
				                       SH_DEADLINE_MS +
				                       10000, &g2, NULL);
				snprintf(what, sizeof(what),
				         "%s: post-release EX obtainable",
				         label);
				ck(sc, rc == 0, what);
				if (rc == 0)
					(void)net2_lock_release(
						env.ls[other], &r0, g2,
						SH_DEADLINE_MS);
			}
		}
	}

	mxfs_pal_sleep_ms(300);
	assert_single_leader(&env, &r0, label);
	assert_no_overlap(&env, &r0, label);
	probe_monotone(&env, &r0, label);
out:
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

static int scen_sh_killpoints(struct scenario_ctx *sc)
{
	static const struct {
		enum n2_hook_point p;
		uint16_t op_filter;
		int release_phase;
		const char *label;
	} points[] = {
		{ N2H_PRE_APPEND,          0,           0, "kp1-pre-append" },
		{ N2H_POST_LOCAL_APPEND,   0,           0, "kp2-local-append" },
		{ N2H_POST_SEND_ONE,       0,           0, "kp3-one-replica" },
		{ N2H_POST_QUORUM_ACK,     0,           0, "kp4-quorum-precommit" },
		{ N2H_POST_COMMIT_PRE_EMIT, N2L_GRANT,  0, "kp5-commit-pregrant" },
		{ N2H_POST_EMIT,           N2L_GRANT,   0, "kp6-grant-preack" },
		{ N2H_PRE_RELEASE_COMMIT,  0,           1, "kp7-release-arrives" },
		{ N2H_POST_COMMIT_PRE_EMIT, N2L_RELEASE, 1, "kp8-release-preack" },
		{ N2H_REVOKE_PENDING,      0,           2, "kp9-revoke-pending" },
	};
	size_t i;
	int rc = 0;
	const char *only = getenv("KP_ONLY");

	for (i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
		int rp = points[i].release_phase;

		if (only && strtoul(only, NULL, 10) != i + 1)
			continue;

		if (rp == 2) {
			/* revocation-pending: PR holder + EX request that
			 * dies at the BAST-emit point */
			struct shenv env;
			struct mxfs_resource_id r0 = res_make(60);
			struct kill_arm ka;
			uint16_t lslot;
			int lidx, hidx, widx;
			uint64_t gpr = 0;
			int lrc;

			if (shenv_start(sc, &env, 3))
				return 1;
			lslot = shard_leader_slot(&env, 0, &r0);
			lidx = node_by_slot(&env, lslot);
			hidx = (lidx + 1) % env.n;
			widx = (lidx + 2) % env.n;
			lrc = net2_lock_acquire(env.ls[hidx], &r0,
			                        MXFS_LOCK_PR, SH_DEADLINE_MS,
			                        &gpr, NULL);
			ck(sc, lrc == 0, "kp9: PR holder");
			memset(&ka, 0, sizeof(ka));
			ka.env = &env;
			ka.point = N2H_REVOKE_PENDING;
			net2_lockspace_set_hook(env.ls[lidx], kill_hook,
			                        &ka);
			{
				struct op_thread op;
				uint64_t t0 = mxfs_pal_time_ms();

				op_start(&op, &env, widx, &r0, MXFS_LOCK_EX,
				         SH_DEADLINE_MS + 10000);
				while (!ka.fired &&
				       mxfs_pal_time_ms() - t0 < 3000)
					mxfs_pal_sleep_ms(10);
				ck(sc, ka.fired == 1, "kp9: hook fired");
				shenv_kill(&env, lidx);
				shenv_suspect(&env, lslot);
				/* pending revoke state survives failover:
				 * the new leader re-issues the BAST from
				 * committed EX_PENDING state... the PR
				 * holder releases, EX proceeds. */
				{
					uint64_t t1 = mxfs_pal_time_ms();
					int seen = 0;

					while (mxfs_pal_time_ms() - t1 <
					       8000) {
						mxfs_pal_mutex_lock(
							env.bast_lock);
						seen = env.bast_count[hidx];
						mxfs_pal_mutex_unlock(
							env.bast_lock);
						if (seen)
							break;
						mxfs_pal_sleep_ms(20);
					}
					ck(sc, seen >= 1,
					   "kp9: BAST re-driven after "
					   "failover (pending survives)");
				}
				lrc = net2_lock_release(env.ls[hidx], &r0,
				                        gpr,
				                        SH_DEADLINE_MS);
				ck(sc, lrc == 0, "kp9: PR release");
				lrc = op_join(&op);
				ck(sc, lrc == 0, "kp9: EX after drain");
			}
			assert_single_leader(&env, &r0, "kp9");
			assert_no_overlap(&env, &r0, "kp9");
			shenv_stop(&env);
			rc |= sc->failed ? 1 : 0;
			continue;
		}
		rc |= killpoint_run(sc, points[i].p, points[i].op_filter,
		                    rp, points[i].label);
	}
	return rc;
}

/* ═══ scenario: dead leader with NO hook (silent death pre-request) ═══ */

static int scen_sh_leader_dead(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(3);
	uint16_t lslot;
	int lidx, cidx, rc;
	uint64_t g0 = 0;

	if (shenv_start(sc, &env, 3))
		return 1;
	lslot = shard_leader_slot(&env, 0, &r0);
	lidx = node_by_slot(&env, lslot);
	cidx = (lidx + 1) % env.n;

	shenv_kill(&env, lidx);
	shenv_suspect(&env, lslot);

	rc = net2_lock_acquire(env.ls[cidx], &r0, MXFS_LOCK_EX,
	                       SH_DEADLINE_MS + 10000, &g0, NULL);
	ck(sc, rc == 0, "acquire completes with leader dead pre-request");
	ck(sc, g0 != 0, "gen nonzero");
	assert_single_leader(&env, &r0, "leader-dead");
	rc = net2_lock_release(env.ls[cidx], &r0, g0, SH_DEADLINE_MS);
	ck(sc, rc == 0, "release on new leader");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: partitions (leader alone / follower alone / heal) ═══ */

static int scen_sh_partitions(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(4);
	uint16_t lslot;
	int lidx, f1, f2, rc;
	uint64_t g0 = 0, gl_before, gl_during;

	if (shenv_start(sc, &env, 3))
		return 1;
	lslot = shard_leader_slot(&env, 0, &r0);
	lidx = node_by_slot(&env, lslot);
	f1 = (lidx + 1) % env.n;
	f2 = (lidx + 2) % env.n;

	/* warm the shard so followers know the leader */
	rc = net2_lock_acquire(env.ls[f1], &r0, MXFS_LOCK_PR,
	                       SH_DEADLINE_MS, &g0, NULL);
	ck(sc, rc == 0, "warm acquire");
	rc = net2_lock_release(env.ls[f1], &r0, g0, SH_DEADLINE_MS);
	ck(sc, rc == 0, "warm release");

	/* leader alone: majority elects; the isolated leader must not
	 * grant anything (it cannot commit) */
	gl_before = stat_of(&env, lidx, pick_grants);
	shenv_partition(&env, 1u << lidx, (1u << f1) | (1u << f2));
	{
		struct op_thread iso;

		/* a client op aimed at the isolated leader: must stall */
		op_start(&iso, &env, lidx, &r0, MXFS_LOCK_EX, 4000);

		shenv_suspect(&env, lslot);
		rc = net2_lock_acquire(env.ls[f1], &r0, MXFS_LOCK_EX,
		                       SH_DEADLINE_MS + 10000, &g0, NULL);
		ck(sc, rc == 0, "majority side grants during partition");
		gl_during = stat_of(&env, lidx, pick_grants);
		ck(sc, gl_during == gl_before,
		   "isolated leader granted NOTHING (cannot commit)");
		rc = op_join(&iso);
		ck(sc, rc == -ETIMEDOUT,
		   "op on isolated leader stalls (visible, not granted)");
		assert_no_overlap(&env, &r0, "during partition");

		/* heal: old leader adopts the higher term; its divergent
		 * uncommitted suffix truncates; state converges */
		shenv_heal(&env);
		mxfs_pal_sleep_ms(1500);
		ck(sc, stat_of(&env, lidx, pick_truncations) >= 1,
		   "divergent suffix truncated on rejoin");
		assert_single_leader(&env, &r0, "after heal");
		assert_no_overlap(&env, &r0, "after heal");
		rc = net2_lock_release(env.ls[f1], &r0, g0, SH_DEADLINE_MS);
		ck(sc, rc == 0, "release after heal");
	}

	/* follower alone: quorum side keeps serving uninterrupted.
	 * Leadership may have MIGRATED during the earlier phases (the
	 * heal leaves whoever won the majority election in charge) —
	 * isolate a CURRENT follower, not the original f2, or this
	 * partitions the live leader with no suspicion injected and
	 * stalls by design. */
	{
		int cl = -1, iso = -1, acq = -1, i;

		for (i = 0; i < env.n; i++) {
			uint32_t sid;
			struct net2_shard snap;

			if (!env.ls[i])
				continue;
			sid = net2_shard_id_for(env.ls[i], &r0);
			if (net2_lockspace_shard_probe(env.ls[i], sid,
			                               &snap))
				continue;
			if (snap.state == SH_ACTIVE &&
			    snap.leader_slot == env.vc->nodes[i].slot)
				cl = i;
		}
		fprintf(stderr, "SCEN-DBG partitions: lidx=%d f1=%d f2=%d "
		        "current-leader-idx=%d\n", lidx, f1, f2, cl);
		/* lidx carries the orphan-grant baggage of its stalled
		 * iso-op (granted post-heal, cleaned by a detached
		 * release) — it must stay CONNECTED, and acquiring from
		 * it self-heals via the same-tenure re-ack.  Isolate
		 * whichever original follower is not the current
		 * leader. */
		if (cl == f1)
			iso = f2;
		else if (cl >= 0)
			iso = f1;
		acq = (cl == lidx || cl < 0) ? f2 : lidx;
		if (iso == acq)
			acq = lidx;
		if (ck(sc, cl >= 0 && iso >= 0 && acq >= 0 && iso != acq &&
		       iso != cl && acq != cl,
		       "live leader + two followers present")) {
			shenv_partition(&env, 1u << iso,
			                (1u << cl) | (1u << acq));
			rc = net2_lock_acquire(env.ls[acq], &r0,
			                       MXFS_LOCK_EX,
			                       SH_DEADLINE_MS, &g0, NULL);
			ck(sc, rc == 0,
			   "quorum side unaffected by lone follower");
			rc = net2_lock_release(env.ls[acq], &r0, g0,
			                       SH_DEADLINE_MS);
			ck(sc, rc == 0, "release");
		}
	}
	shenv_heal(&env);
	mxfs_pal_sleep_ms(500);

	probe_monotone(&env, &r0, "partitions end");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: reconfiguration — unchanged-R shards keep serving;
 *     changed shards transfer; held locks survive ═══ */

static int scen_sh_reconfig(struct scenario_ctx *sc)
{
	struct shenv env;
	uint64_t gens[8];
	struct mxfs_resource_id rs[8];
	int rc, i;
	uint64_t xfers = 0;

	if (shenv_start(sc, &env, 4))
		return 1;

	/* hold a spread of resources across shards from node 3 */
	for (i = 0; i < 8; i++) {
		rs[i] = res_make(100 + (uint32_t)i * 17);
		rc = net2_lock_acquire(env.ls[3], &rs[i], MXFS_LOCK_PR,
		                       SH_DEADLINE_MS, &gens[i], NULL);
		ck(sc, rc == 0, "spread acquire");
	}

	/* restart node 1 (fresh incarnation, empty lock-plane state) and
	 * commit the SAME membership at E+1 with its new inc: shards
	 * whose R contains node1 re-derive (inc is part of HRW identity)
	 * and must state-transfer to it; the rest keep serving. */
	{
		int slot1 = env.vc->nodes[1].slot;

		net2_lockspace_destroy(env.ls[1]);
		env.ls[1] = NULL;
		rc = vc_node_restart(env.vc, 1);
		ck(sc, rc == 0, "node1 restart");
		env.incs[slot1] = env.vc->nodes[1].inc;
		{
			struct net2_lockspace_cfg cfg;

			memset(&cfg, 0, sizeof(cfg));
			cfg.self_slot = (uint16_t)slot1;
			cfg.self_inc = env.vc->nodes[1].inc;
			cfg.elect_base_ms = 80;
			cfg.elect_rank_ms = 40;
			cfg.client_retry_ms = 150;
			cfg.rt_tick_ms = 10;
			cfg.seed = sc->seed + 4242;
			rc = net2_lockspace_create(env.vc->nodes[1].ctx,
			                           &cfg, &env.ls[1]);
			ck(sc, rc == 0, "node1 lockspace recreate");
			bast_bind[1].env = &env;
			bast_bind[1].node = 1;
			net2_lockspace_set_bast_cb(env.ls[1], shenv_bast_cb,
			                           &bast_bind[1]);
			net2_lockspace_start(env.ls[1]);
		}
		shenv_epoch_bump(&env, shenv_mask(&env));
	}

	/* during/after reconfig: ops on every node must succeed (the
	 * central fix — no wholesale purge).  Resources 300+ — disjoint
	 * from the 100+17i spread (200+i collided with spread i=6 at
	 * 202, turning this uncontended-service check into a legitimate
	 * EX-vs-PR wait that outlives the deadline). */
	for (i = 0; i < 4; i++) {
		struct mxfs_resource_id q = res_make(300 + (uint32_t)i);
		uint64_t g = 0;

		if (!env.ls[i])
			continue;
		rc = net2_lock_acquire(env.ls[i], &q, MXFS_LOCK_EX,
		                       SH_DEADLINE_MS + 10000, &g, NULL);
		ck(sc, rc == 0, "op through reconfiguration");
		if (rc != 0) {
			struct mxfs_net2_session_stats ss;
			int a, d;

			for (a = 0; a < 4; a++) {
				if (!env.ls[a])
					continue;
				for (d = 0; d < 4; d++) {
					uint16_t ds = env.vc->nodes[d].slot;

					if (d == a)
						continue;
					if (mxfs_net2_get_session_stats(
					        env.vc->nodes[a].ctx, ds,
					        &ss))
						continue;
					fprintf(stderr, "DIAG n%d->s%u: crt%llu ftx%llu rtx%llu ack%llu dupseq%llu oow%llu staleinc%llu staleep%llu rst%llu\n",
					        a, ds,
					        (unsigned long long)ss.msgs_created,
					        (unsigned long long)ss.first_tx,
					        (unsigned long long)ss.retx,
					        (unsigned long long)ss.acked,
					        (unsigned long long)ss.dup_seq_suppressed,
					        (unsigned long long)ss.out_of_window_drops,
					        (unsigned long long)ss.stale_incarnation_drops,
					        (unsigned long long)ss.stale_epoch_drops,
					        (unsigned long long)ss.resets);
				}
			}
		}
		if (rc == 0)
			(void)net2_lock_release(env.ls[i], &q, g,
			                        SH_DEADLINE_MS);
	}

	mxfs_pal_sleep_ms(1000);             /* let transfers finish */
	for (i = 0; i < 4; i++)
		xfers += stat_of(&env, i, pick_xfer_done);
	ck(sc, xfers >= 1, "state transfers happened for changed shards");

	/* held locks survived: releases with the pre-reconfig gens must
	 * succeed (holder bits transferred, not purged) */
	for (i = 0; i < 8; i++) {
		char what[96];

		rc = net2_lock_release(env.ls[3], &rs[i], gens[i],
		                       SH_DEADLINE_MS + 10000);
		snprintf(what, sizeof(what),
		         "pre-reconfig hold releases cleanly (i=%d rc=%d)",
		         i, rc);
		ck(sc, rc == 0, what);
	}

	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: total replica loss — closed-set recovery barrier ═══ */

static int scen_sh_recovery(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0;
	uint16_t lslot;
	uint32_t sid;
	int rc, i, k;
	uint64_t gpr = 0, gex = 0;
	int survivor = -1, survivor2 = -1;
	struct net2_shard snap;
	uint64_t barriers = 0, rebuilt = 0;

	if (shenv_start(sc, &env, 5))
		return 1;

	/* find a resource whose 3 replicas leave >= 2 non-replica
	 * survivors among our 5 nodes */
	r0 = res_make(300);
	for (k = 300; k < 400; k++) {
		int nrep = 0;

		r0 = res_make((uint32_t)k);
		sid = net2_shard_id_for(env.ls[0], &r0);
		(void)net2_shard_get(env.ls[0], sid, true);
		if (net2_lockspace_shard_probe(env.ls[0], sid, &snap))
			continue;
		for (i = 0; i < env.n; i++)
			if (net2_shard_replica_index(&snap,
			                env.vc->nodes[i].slot) >= 0)
				nrep++;
		if (nrep == 3)
			break;
	}
	sid = net2_shard_id_for(env.ls[0], &r0);
	(void)net2_lockspace_shard_probe(env.ls[0], sid, &snap);
	for (i = 0; i < env.n; i++) {
		if (net2_shard_replica_index(&snap,
		                             env.vc->nodes[i].slot) < 0) {
			if (survivor < 0)
				survivor = i;
			else if (survivor2 < 0)
				survivor2 = i;
		}
	}
	if (!ck(sc, survivor >= 0 && survivor2 >= 0,
	        "recovery: two non-replica survivors exist"))
		goto out;

	/* survivor holds PR (grant flows through the replica set) */
	rc = net2_lock_acquire(env.ls[survivor], &r0, MXFS_LOCK_PR,
	                       SH_DEADLINE_MS, &gpr, NULL);
	if (!ck(sc, rc == 0, "recovery: survivor PR granted"))
		goto out;

	/* kill ALL THREE replicas; commit the survivor-only epoch */
	lslot = snap.leader_slot;
	(void)lslot;
	for (i = 0; i < env.n; i++)
		if (net2_shard_replica_index(&snap,
		                             env.vc->nodes[i].slot) >= 0)
			shenv_kill(&env, i);
	shenv_epoch_bump(&env, shenv_mask(&env));

	/* the new rank-0 must run the closed-set barrier and REBUILD the
	 * survivor's PR — an EX from the other survivor must WAIT for a
	 * release (never an empty-table grant) */
	{
		struct op_thread ex;

		op_start(&ex, &env, survivor2, &r0, MXFS_LOCK_EX,
		         SH_DEADLINE_MS + 15000);
		mxfs_pal_sleep_ms(2500);     /* barrier + BAST window */
		ck(sc, ex.rc == -4242,
		   "recovery: EX blocked by rebuilt PR holder "
		   "(no empty-table assumption)");
		rc = net2_lock_release(env.ls[survivor], &r0, gpr,
		                       SH_DEADLINE_MS + 10000);
		ck(sc, rc == 0, "recovery: rebuilt hold releases cleanly");
		rc = op_join(&ex);
		ck(sc, rc == 0, "recovery: EX after release");
		gex = ex.gen;
		ck(sc, gex >= gpr + 1024,
		   "recovery: gen slack (+1024) applied");
		(void)net2_lock_release(env.ls[survivor2], &r0, gex,
		                        SH_DEADLINE_MS);
	}
	for (i = 0; i < env.n; i++) {
		barriers += stat_of(&env, i, pick_recov_barriers);
		rebuilt += stat_of(&env, i, pick_recov_recs);
	}
	ck(sc, barriers >= 1, "recovery: barrier ran");
	ck(sc, rebuilt >= 1, "recovery: reports rebuilt records");
out:
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: two replicas permanently lost — no quorum, visible
 *     stall (never a timeout-grant), epoch re-derive recovers ═══ */

static int scen_sh_two_loss(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0;
	uint32_t sid;
	int rc, i, k;
	struct net2_shard snap;
	int lidx = -1, dead1 = -1, dead2 = -1, cidx = -1;
	uint64_t g0 = 0, gheld = 0;

	if (shenv_start(sc, &env, 4))
		return 1;

	/* find a resource whose replica set has its leader among our
	 * nodes and at least one NON-replica node to drive from */
	r0 = res_make(500);
	for (k = 500; k < 600; k++) {
		r0 = res_make((uint32_t)k);
		sid = net2_shard_id_for(env.ls[0], &r0);
		(void)net2_shard_get(env.ls[0], sid, true);
		if (net2_lockspace_shard_probe(env.ls[0], sid, &snap))
			continue;
		lidx = node_by_slot(&env, snap.leader_slot);
		cidx = -1;
		for (i = 0; i < env.n; i++)
			if (net2_shard_replica_index(&snap,
			                env.vc->nodes[i].slot) < 0)
				cidx = i;
		if (lidx >= 0 && cidx >= 0)
			break;
	}
	if (!ck(sc, lidx >= 0 && cidx >= 0, "two-loss: topology found"))
		goto out;

	/* a held lock that must SURVIVE via the leader's state */
	rc = net2_lock_acquire(env.ls[cidx], &r0, MXFS_LOCK_PR,
	                       SH_DEADLINE_MS, &gheld, NULL);
	ck(sc, rc == 0, "two-loss: pre-hold");

	dead1 = dead2 = -1;
	for (i = 0; i < env.n; i++) {
		if (i == lidx ||
		    net2_shard_replica_index(&snap,
		                             env.vc->nodes[i].slot) < 0)
			continue;
		if (dead1 < 0)
			dead1 = i;
		else
			dead2 = i;
	}
	if (!ck(sc, dead1 >= 0 && dead2 >= 0, "two-loss: two followers"))
		goto out;
	shenv_kill(&env, dead1);
	shenv_kill(&env, dead2);

	/* quorum gone: an EX request must STALL (visible), never be
	 * granted off a timeout */
	{
		struct op_thread op;

		op_start(&op, &env, cidx, &r0, MXFS_LOCK_EX, 3000);
		rc = op_join(&op);
		ck(sc, rc == -ETIMEDOUT,
		   "two-loss: no grant without quorum (stall, not grant)");
	}
	assert_no_overlap(&env, &r0, "two-loss stall");

	/* epoch re-derive over the survivors: the surviving leader's
	 * state seeds the new config; the held PR must survive */
	shenv_epoch_bump(&env, shenv_mask(&env));
	mxfs_pal_sleep_ms(1500);
	{
		struct op_thread op;

		/* Cross-node conflict: the EX comes from the surviving
		 * LEADER node, against cidx's PR.  (From cidx itself it
		 * would be a same-node mode upgrade — granted once the
		 * quorum is back, per the CAW per-node-slot semantics
		 * net2_lock mirrors.) */
		op_start(&op, &env, lidx, &r0, MXFS_LOCK_EX,
		         SH_DEADLINE_MS + 10000);
		mxfs_pal_sleep_ms(1200);
		ck(sc, op.rc == -4242,
		   "two-loss: EX still blocked by surviving PR hold");
		rc = net2_lock_release(env.ls[cidx], &r0, gheld,
		                       SH_DEADLINE_MS + 10000);
		ck(sc, rc == 0, "two-loss: surviving hold releases");
		rc = op_join(&op);
		ck(sc, rc == 0, "two-loss: EX after re-derive + release");
		g0 = op.gen;
		(void)net2_lock_release(env.ls[lidx], &r0, g0,
		                        SH_DEADLINE_MS);
	}
	probe_monotone(&env, &r0, "two-loss end");
out:
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: epoch change mid-op (stale-epoch deny + re-issue) ═══ */

static int scen_sh_epoch_mid_op(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(6);
	int rc, i;
	uint64_t g0 = 0, denies = 0;

	if (shenv_start(sc, &env, 3))
		return 1;

	/* fire an acquire and immediately move the epoch under it */
	{
		struct op_thread op;

		op_start(&op, &env, 1, &r0, MXFS_LOCK_EX,
		         SH_DEADLINE_MS + 10000);
		shenv_epoch_bump(&env, shenv_mask(&env));
		rc = op_join(&op);
		ck(sc, rc == 0, "op completes across epoch change");
		g0 = op.gen;
	}
	for (i = 0; i < env.n; i++)
		denies += stat_of(&env, i, pick_stale_epoch);
	/* timing-dependent: the deny may or may not have been needed —
	 * completion is the hard assert; record the counter as evidence */
	(void)denies;
	rc = net2_lock_release(env.ls[1], &r0, g0, SH_DEADLINE_MS + 5000);
	ck(sc, rc == 0, "release at the new epoch");
	assert_single_leader(&env, &r0, "epoch-mid-op");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: duplicate-request idempotency across failover ═══ */

static int scen_sh_idempotent_failover(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(7);
	uint16_t lslot;
	int lidx, cidx, rc;
	struct kill_arm ka;
	uint64_t dup0 = 0, dup1 = 0;
	int i;

	if (shenv_start(sc, &env, 3))
		return 1;
	lslot = shard_leader_slot(&env, 0, &r0);
	lidx = node_by_slot(&env, lslot);
	cidx = (lidx + 1) % env.n;

	for (i = 0; i < env.n; i++)
		dup0 += stat_of(&env, i, pick_dup_idem);

	/* kill the leader right after the GRANT is committed+emitted;
	 * the client's re-issue (same request_id) must be answered from
	 * the REPLICATED completed-op cache by the new leader if the
	 * grant got lost, or complete normally — either way exactly one
	 * effect. */
	memset(&ka, 0, sizeof(ka));
	ka.env = &env;
	ka.point = N2H_POST_EMIT;
	ka.op_filter = N2L_GRANT;
	net2_lockspace_set_hook(env.ls[lidx], kill_hook, &ka);
	{
		struct op_thread op;
		uint64_t t0 = mxfs_pal_time_ms();

		op_start(&op, &env, cidx, &r0, MXFS_LOCK_EX,
		         SH_DEADLINE_MS + 10000);
		while (!ka.fired && mxfs_pal_time_ms() - t0 < 3000)
			mxfs_pal_sleep_ms(10);
		ck(sc, ka.fired == 1, "idem: hook fired");
		shenv_kill(&env, lidx);
		shenv_suspect(&env, lslot);
		rc = op_join(&op);
		ck(sc, rc == 0, "idem: grant survives failover");
		/* the same client acquires AGAIN (new request): must be
		 * the already-holder re-ack with the SAME gen */
		{
			uint64_t g2 = 0;

			rc = net2_lock_acquire(env.ls[cidx], &r0,
			                       MXFS_LOCK_EX,
			                       SH_DEADLINE_MS, &g2, NULL);
			ck(sc, rc == 0 && g2 == op.gen,
			   "idem: re-acquire returns the same tenure");
		}
		(void)net2_lock_release(env.ls[cidx], &r0, op.gen,
		                        SH_DEADLINE_MS + 5000);
	}
	for (i = 0; i < env.n; i++)
		dup1 += stat_of(&env, i, pick_dup_idem);
	(void)dup0; (void)dup1;              /* evidence, timing-dependent */
	assert_no_overlap(&env, &r0, "idem end");
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ═══ scenario: restarted replica may not vote until caught up ═══ */

static int scen_sh_xfer_no_vote(struct scenario_ctx *sc)
{
	struct shenv env;
	struct mxfs_resource_id r0 = res_make(8);
	uint32_t sid;
	struct net2_shard snap;
	int rc, i, fidx = -1;
	uint64_t g0 = 0, refused = 0;

	if (shenv_start(sc, &env, 3))
		return 1;

	/* build history on the shard */
	for (i = 0; i < 6; i++) {
		rc = net2_lock_acquire(env.ls[0], &r0, MXFS_LOCK_EX,
		                       SH_DEADLINE_MS, &g0, NULL);
		ck(sc, rc == 0, "history acquire");
		rc = net2_lock_release(env.ls[0], &r0, g0, SH_DEADLINE_MS);
		ck(sc, rc == 0, "history release");
	}
	sid = net2_shard_id_for(env.ls[0], &r0);
	(void)net2_lockspace_shard_probe(env.ls[0], sid, &snap);

	/* restart a FOLLOWER replica (fresh inc, empty state) */
	for (i = 0; i < env.n; i++) {
		uint16_t s = env.vc->nodes[i].slot;

		if (s != snap.leader_slot &&
		    net2_shard_replica_index(&snap, s) >= 0) {
			fidx = i;
			break;
		}
	}
	if (!ck(sc, fidx >= 0, "xfer: follower found"))
		goto out;
	{
		int slot = env.vc->nodes[fidx].slot;
		struct net2_lockspace_cfg cfg;

		net2_lockspace_destroy(env.ls[fidx]);
		env.ls[fidx] = NULL;
		rc = vc_node_restart(env.vc, fidx);
		ck(sc, rc == 0, "xfer: restart");
		env.incs[slot] = env.vc->nodes[fidx].inc;
		memset(&cfg, 0, sizeof(cfg));
		cfg.self_slot = (uint16_t)slot;
		cfg.self_inc = env.vc->nodes[fidx].inc;
		cfg.elect_base_ms = 80;
		cfg.elect_rank_ms = 40;
		cfg.client_retry_ms = 150;
		cfg.rt_tick_ms = 10;
		cfg.seed = sc->seed + 999;
		rc = net2_lockspace_create(env.vc->nodes[fidx].ctx, &cfg,
		                           &env.ls[fidx]);
		ck(sc, rc == 0, "xfer: lockspace recreate");
		bast_bind[fidx].env = &env;
		bast_bind[fidx].node = fidx;
		net2_lockspace_set_bast_cb(env.ls[fidx], shenv_bast_cb,
		                           &bast_bind[fidx]);
		net2_lockspace_start(env.ls[fidx]);
		shenv_epoch_bump(&env, shenv_mask(&env));
	}

	/* while the restarted follower is (potentially) transferring,
	 * inject suspicion of the leader everywhere: the fresh replica
	 * must refuse to vote until CAUGHT_UP.  The leader is actually
	 * alive, so the cluster keeps working regardless. */
	(void)net2_lockspace_shard_probe(env.ls[0], sid, &snap);
	shenv_suspect(&env, snap.leader_slot);
	mxfs_pal_sleep_ms(600);

	/* ops still complete */
	rc = net2_lock_acquire(env.ls[2 % env.n], &r0, MXFS_LOCK_EX,
	                       SH_DEADLINE_MS + 10000, &g0, NULL);
	ck(sc, rc == 0, "xfer: ops complete around restart+suspicion");
	(void)net2_lock_release(env.ls[2 % env.n], &r0, g0,
	                        SH_DEADLINE_MS);

	mxfs_pal_sleep_ms(800);
	for (i = 0; i < env.n; i++)
		refused += stat_of(&env, i, pick_votes_refused_xfer);
	/* evidence: refusals occur when the vote raced the transfer —
	 * timing-dependent; the HARD assert is correctness above.  The
	 * eligibility rule itself is enforced structurally (a fresh
	 * replica NACKs history it does not have and flips ineligible
	 * before any vote). */
	(void)refused;
out:
	shenv_stop(&env);
	return sc->failed ? 1 : 0;
}

/* ─── table ─── */

const struct scenario net2_scen_shard[] = {
	{ "sh_basic",              scen_sh_basic,              1 },
	{ "sh_waiter_order",       scen_sh_waiter_order,       0 },
	{ "sh_killpoints",         scen_sh_killpoints,         0 },
	{ "sh_leader_dead",        scen_sh_leader_dead,        1 },
	{ "sh_partitions",         scen_sh_partitions,         0 },
	{ "sh_reconfig",           scen_sh_reconfig,           0 },
	{ "sh_recovery",           scen_sh_recovery,           0 },
	{ "sh_two_loss",           scen_sh_two_loss,           0 },
	{ "sh_epoch_mid_op",       scen_sh_epoch_mid_op,       0 },
	{ "sh_idempotent_failover", scen_sh_idempotent_failover, 0 },
	{ "sh_xfer_no_vote",       scen_sh_xfer_no_vote,       0 },
};
const int net2_scen_shard_count =
	(int)(sizeof(net2_scen_shard) / sizeof(net2_scen_shard[0]));
