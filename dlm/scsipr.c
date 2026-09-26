/*
 * MXFS — Multinode XFS
 * Portable SCSI-3 Persistent Reservations for I/O fencing
 *
 * Ported from kernel/mxfs_scsipr.c — all pr_ops calls replaced
 * with PAL SCSI PR functions. The PAL layer handles platform-specific
 * details (SG_IO on Linux userspace, pr_ops in kernel, IOKit on macOS).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "scsipr.h"

static int mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx,
				  uint64_t victim_key,
				  bool *victim_present, bool *own_present,
				  int *count, uint32_t *generation);

/* (0.61.0, D1): the departure mutex and the PROUT wrappers — see
 * the contract in scsipr.h. */
static mxfs_mutex_t *scsipr_dep_mutex;
static int           scsipr_dep_owner;     /* pid; 0 = free */
static int           scsipr_dep_depth;
static int scsipr_register_locked(struct mxfs_scsipr_ctx *ctx,
				  bool replace_predecessor);
static int scsipr_register_succeed_locked(struct mxfs_scsipr_ctx *ctx,
					  uint64_t old_key);
static int scsipr_reserve_locked(struct mxfs_scsipr_ctx *ctx);
static int scsipr_preempt_locked(struct mxfs_scsipr_ctx *ctx,
				 uint64_t victim_key, bool abort);
static int scsipr_unregister_locked(struct mxfs_scsipr_ctx *ctx);
static bool scsipr_gate_resv_is_ours(const struct mxfs_scsipr_ctx *ctx,
				     const struct mxfs_pal_pr_reservation *resv);

/* (D8): contexts whose probe thread outlived its bounded join. */
static mxfs_mutex_t *scsipr_quar_lock;
static struct mxfs_scsipr_ctx *scsipr_quar_head;

static void scsipr_free_now(struct mxfs_scsipr_ctx *ctx)
{
	if (ctx->snap_lock)
		mxfs_pal_mutex_destroy(ctx->snap_lock);
	if (ctx->probe_lock)
		mxfs_pal_mutex_destroy(ctx->probe_lock);
	mxfs_pal_free(ctx->snap_keys);
	mxfs_pal_free(ctx->bkt_keys_a);
	mxfs_pal_free(ctx->bkt_keys_b);
	if (ctx->module_pinned)
		mxfs_pal_module_unpin();
	mxfs_pal_free(ctx);
}

/* the probe thread must be joined before any of this is freed.
 * (D8): a join that times out quarantines the context instead —
 * the thread may still dereference it, so nothing is freed. */
static void scsipr_free(struct mxfs_scsipr_ctx *ctx)
{
	if (mxfs_scsipr_probe_stop(ctx) == -ETIMEDOUT)
		return;                     /* quarantined by probe_stop */
	if (ctx->quarantined)
		return;                     /* already on the list */
	scsipr_free_now(ctx);
}

int mxfs_scsipr_departure_init(void)
{
	if (!scsipr_dep_mutex) {
		scsipr_dep_mutex = mxfs_pal_mutex_create();
		if (!scsipr_dep_mutex)
			return -ENOMEM;
	}
	if (!scsipr_quar_lock) {
		scsipr_quar_lock = mxfs_pal_mutex_create();
		if (!scsipr_quar_lock)
			return -ENOMEM;
	}
	return 0;
}

void mxfs_scsipr_departure_exit(void)
{
	if (scsipr_dep_mutex) {
		mxfs_pal_mutex_destroy(scsipr_dep_mutex);
		scsipr_dep_mutex = NULL;
	}
	if (scsipr_quar_lock) {
		mxfs_pal_mutex_destroy(scsipr_quar_lock);
		scsipr_quar_lock = NULL;
	}
}

bool mxfs_scsipr_departure_held(void)
{
	int me = mxfs_pal_current_pid();

	/* owner is written only by the holder, under the mutex; a reader
	 * that is not the holder sees either 0 or another pid. */
	return scsipr_dep_mutex && me && mxfs_pal_flag_get(&scsipr_dep_owner) == me;
}

void mxfs_scsipr_departure_lock(void)
{
	if (!scsipr_dep_mutex)
		return;
	if (mxfs_scsipr_departure_held()) {
		scsipr_dep_depth++;
		return;
	}
	mxfs_pal_mutex_lock(scsipr_dep_mutex);
	mxfs_pal_flag_set(&scsipr_dep_owner, mxfs_pal_current_pid());
	scsipr_dep_depth = 1;
}

int mxfs_scsipr_departure_trylock(void)
{
	if (!scsipr_dep_mutex)
		return 1;
	if (mxfs_scsipr_departure_held()) {
		scsipr_dep_depth++;
		return 1;
	}
	if (!mxfs_pal_mutex_trylock(scsipr_dep_mutex))
		return 0;
	mxfs_pal_flag_set(&scsipr_dep_owner, mxfs_pal_current_pid());
	scsipr_dep_depth = 1;
	return 1;
}

void mxfs_scsipr_departure_unlock(void)
{
	if (!scsipr_dep_mutex)
		return;
	if (!mxfs_scsipr_departure_held()) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-DEPARTURE-UNLOCK-NOT-OWNER pid=%d owner=%d "
			     "— unlock by a thread that does not hold the departure "
			     "mutex; ignored", mxfs_pal_current_pid(),
			     mxfs_pal_flag_get(&scsipr_dep_owner));
		return;
	}
	if (--scsipr_dep_depth > 0)
		return;
	mxfs_pal_flag_set(&scsipr_dep_owner, 0);
	mxfs_pal_mutex_unlock(scsipr_dep_mutex);
}

/* Every local PROUT runs under the departure mutex.  A caller that already
 * holds it nests; one that does not is the assertion failure the D1 ruling
 * names — say so, then take it, so the invariant holds regardless. */
static void scsipr_dep_enter(struct mxfs_scsipr_ctx *ctx, const char *op)
{
	if (!mxfs_scsipr_departure_held())
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-DEPARTURE-UNHELD '%s' op=%s pid=%d — a "
			     "local PROUT issued outside a departure-locked section "
			     "(a fence, a self-succession); taking the host-wide "
			     "departure mutex here so every PROUT runs under it",
			     ctx ? ctx->dev_name : "?", op, mxfs_pal_current_pid());
	mxfs_scsipr_departure_lock();
}

int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx, bool replace_predecessor)
{
	int rc;

	scsipr_dep_enter(ctx, "register");
	rc = scsipr_register_locked(ctx, replace_predecessor);
	mxfs_scsipr_departure_unlock();
	return rc;
}

int mxfs_scsipr_register_succeed(struct mxfs_scsipr_ctx *ctx, uint64_t old_key)
{
	int rc;

	scsipr_dep_enter(ctx, "register-succeed");
	rc = scsipr_register_succeed_locked(ctx, old_key);
	mxfs_scsipr_departure_unlock();
	return rc;
}

int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx)
{
	int rc;

	scsipr_dep_enter(ctx, "reserve");
	rc = scsipr_reserve_locked(ctx);
	mxfs_scsipr_departure_unlock();
	return rc;
}

int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key,
			bool abort)
{
	int rc;

	scsipr_dep_enter(ctx, "preempt");
	rc = scsipr_preempt_locked(ctx, victim_key, abort);
	mxfs_scsipr_departure_unlock();
	return rc;
}

/*
 * 0.85.1: a joiner meets a single-holder Write Exclusive (1) reservation —
 * the sole-survivor gate — whose holder the caller has proved dead (its
 * heartbeat record frozen for a full dead window while no record moved, the
 * key attributed by the PR ledger).  Under WE(1) nobody but the holder can
 * write, so the joiner's ledger publish can never land until the holder is
 * preempted; measured s613c (tests/evidence/20260913T033243Z_intents2tcp_s613c,
 * dmesg_test2_remount.txt): P304-PREOBSERVE held=1 type=0x1 by the dead
 * custodian's key, then P-PRKEY-PUBLISHED rc=-52 UNATTRIBUTED and the mount
 * refused in 2.7 s.  A registrant may preempt the reservation holder: issue
 * PREEMPT AND ABORT rk=own sark=holder with the ALL-REGISTRANTS type this
 * build establishes, so the reservation in force afterwards is WE-AR (the
 * PROUT's type names the replacement reservation; the type-1 form is
 * reserved for the gate's own sark=0 preempt), then verify by READ
 * RESERVATION.  -EBUSY from the PROUT means the holder key was already gone
 * (the target purged it meanwhile): nothing performed, and the readback
 * decides.  Any state that still shows WE(1) refuses.
 */
int mxfs_scsipr_preempt_dead_gate_holder(struct mxfs_scsipr_ctx *ctx,
					 uint64_t holder_key)
{
	struct mxfs_pal_pr_reservation resv;
	int ret, rr;

	if (!ctx || !ctx->dev || !holder_key)
		return -EINVAL;
	if (!ctx->local_key || !ctx->registered)
		return -ENOKEY;
	if (holder_key == ctx->local_key)
		return -EINVAL;
	scsipr_dep_enter(ctx, "dead-gate");
	ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, holder_key, true,
				       MXFS_SCSIPR_RESV_TYPE);
	mxfs_scsipr_snap_invalidate(ctx, "dead-gate");
	if (ret == -EBUSY) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P-PR-DEADGATE-CONFLICT '%s' PREEMPT AND ABORT of "
			     "the dead gate holder's key 0x%llx hit RESERVATION "
			     "CONFLICT — the key is not registered any more (purged "
			     "by the target); nothing performed, the readback decides",
			     ctx->dev_name, (unsigned long long)holder_key);
	} else if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-DEADGATE-FAIL '%s' PREEMPT AND ABORT of the "
			     "dead gate holder's key 0x%llx failed rc=%d",
			     ctx->dev_name, (unsigned long long)holder_key, ret);
		goto out;
	}
	rr = mxfs_scsipr_read_reservation(ctx, &resv);
	if (rr) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-DEADGATE-VERIFY '%s' READ RESERVATION rc=%d "
			     "after preempting key 0x%llx — post-state unknown, "
			     "refusing", ctx->dev_name, rr,
			     (unsigned long long)holder_key);
		ret = rr;
		goto out;
	}
	if (resv.held && resv.type == MXFS_PAL_PR_TYPE_WR_EX) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-DEADGATE-STILLHELD '%s' held=1 type=0x1 "
			     "holder=0x%llx gen=%u after preempting key 0x%llx — a "
			     "single-holder Write Exclusive reservation is still in "
			     "force; refusing", ctx->dev_name,
			     (unsigned long long)resv.key, resv.generation,
			     (unsigned long long)holder_key);
		ret = -EBUSY;
		goto out;
	}
	if (resv.held) {
		ctx->resv_type_seen = resv.type;
		ctx->reserved = (resv.type == MXFS_SCSIPR_RESV_TYPE);
	} else {
		ctx->resv_type_seen = 0;
		ctx->reserved = false;
	}
	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P-PR-DEADGATE-PREEMPTED '%s' dead gate holder key "
		     "0x%llx preempted%s; reservation now held=%d type=0x%x (%s) "
		     "gen=%u — the joiner can write again",
		     ctx->dev_name, (unsigned long long)holder_key,
		     ret == -EBUSY ? " (already gone)" : " and its task set aborted",
		     (int)resv.held, resv.type, mxfs_pr_type_name(resv.type),
		     resv.generation);
	ret = 0;
out:
	mxfs_scsipr_departure_unlock();
	return ret;
}

int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx)
{
	int rc;

	scsipr_dep_enter(ctx, "unregister");
	rc = scsipr_unregister_locked(ctx);
	mxfs_scsipr_departure_unlock();
	return rc;
}

struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
					    const char *dev_name,
					    uint64_t local_key)
{
	struct mxfs_scsipr_ctx *ctx;

	if (!dev)
		return NULL;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->dev = dev;
	ctx->local_key = local_key;     /* ledger-selected per-boot key */
	ctx->reserved = false;
	/* /452: tri-state key-state snapshot + bracket scratch (see
	 * mxfs_scsipr_key_state). */
	ctx->snap_lock = mxfs_pal_mutex_create();
	ctx->probe_lock = mxfs_pal_mutex_create();
	ctx->snap_keys = mxfs_pal_alloc(sizeof(*ctx->snap_keys) * MXFS_PR_MAX_KEYS);
	ctx->bkt_keys_a = mxfs_pal_alloc(sizeof(*ctx->bkt_keys_a) * MXFS_PR_MAX_KEYS);
	ctx->bkt_keys_b = mxfs_pal_alloc(sizeof(*ctx->bkt_keys_b) * MXFS_PR_MAX_KEYS);
	ctx->snap_state = -ENODATA;
	ctx->snap_why = "no-bracket-yet";
	if (!ctx->snap_lock || !ctx->probe_lock || !ctx->snap_keys ||
	    !ctx->bkt_keys_a || !ctx->bkt_keys_b) {
		if (ctx->snap_lock)
			mxfs_pal_mutex_destroy(ctx->snap_lock);
		if (ctx->probe_lock)
			mxfs_pal_mutex_destroy(ctx->probe_lock);
		mxfs_pal_free(ctx->snap_keys);
		mxfs_pal_free(ctx->bkt_keys_a);
		mxfs_pal_free(ctx->bkt_keys_b);
		mxfs_pal_free(ctx);
		return NULL;
	}

	if (dev_name)
		snprintf(ctx->dev_name, sizeof(ctx->dev_name), "%s", dev_name);
	else
		snprintf(ctx->dev_name, sizeof(ctx->dev_name), "(unknown)");

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: initialized for '%s' key=0x%llx",
		     ctx->dev_name, (unsigned long long)ctx->local_key);

	return ctx;
}

void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx)
{
	if (!ctx)
		return;

	/* v0.11.80 (D4): safety-net unregister only if the key is still
	 * believed registered — the normal teardown paths unregister
	 * explicitly first, and re-issuing PROUT for an absent key is a
	 * spec-level RESERVATION CONFLICT (observed as bare conflicts on
	 * the QNAP battery). */
	if (ctx->local_key && ctx->registered) {
		int ret = mxfs_scsipr_unregister(ctx);
		if (ret)
			mxfs_pal_log(MXFS_LOG_WARN,
				     "scsipr: unregister on shutdown failed: %d", ret);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: shutdown for '%s'", ctx->dev_name);

	scsipr_free(ctx);
}

uint64_t mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx)
{
	return ctx ? ctx->local_key : 0;
}

int mxfs_scsipr_set_key(struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	if (!ctx || !key)
		return -EINVAL;
	if (ctx->registered)
		return -EBUSY;      /* the registered key is the key; never rotate */
	ctx->local_key = key;
	return 0;
}

void mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx)
{
	if (!ctx)
		return;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: abandoned for '%s' (deferred unregister)",
		     ctx->dev_name);

	/* 0.59.1 freed only the ctx here and leaked the snapshot lock
	 * and key array on every clean unmount. */
	scsipr_free(ctx);
}

static int scsipr_verify_registered(struct mxfs_scsipr_ctx *ctx);

static int scsipr_register_locked(struct mxfs_scsipr_ctx *ctx,
				  bool replace_predecessor)
{
	int ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	/*
	 * (measured, lone_mount_create remount_refused on 0.45.0):
	 * dm-multipath's dm_pr_register ROLLS BACK a failed plain REGISTER by
	 * issuing REGISTER(rk=new_key, sark=0) on every path (drivers/md/dm.c
	 * dm_pr_register: "unregister all paths if we failed to register any
	 * path").  With a DERIVED per-boot key, new_key is exactly the key a
	 * dirty same-boot departure retained as the fence target (P302), so the
	 * rollback silently UNREGISTERED it — the retention was defeated by the
	 * very attempt that should have found it.  So probe FIRST with the
	 * nexus-local compare REGISTER(rk=K, sark=K): GOOD means this nexus
	 * already holds our key (no change made); -ENOKEY means it holds another
	 * key or none, and only then is a plain REGISTER issued (whose rollback
	 * can then only touch a key that is not registered here: a no-op).
	 */
	{
		int sr = mxfs_pal_scsi_pr_register_swap(ctx->dev, ctx->local_key,
							ctx->local_key);

		mxfs_scsipr_snap_invalidate(ctx, "register-probe");   /* */
		if (sr == 0) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "mxfs: P305-PR-SAME-BOOT-KEY-REUSED '%s' key=0x%llx "
				     "— this nexus already held this boot's derived key "
				     "(earlier REGISTER this boot); reusing it, no "
				     "registration changed",
				     ctx->dev_name, (unsigned long long)ctx->local_key);
			ctx->nexus_reused = true;
			ctx->registered = true;
			return scsipr_verify_registered(ctx);
		}
		if (sr != -ENOKEY && sr != -EOPNOTSUPP) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P305-PR-SAME-KEY-PROBE-FAILED '%s' rc=%d — "
				     "could not decide whether this nexus holds our key; "
				     "refusing to register", ctx->dev_name, sr);
			return sr;
		}
	}
	ret = mxfs_pal_scsi_pr_register(ctx->dev, ctx->local_key);
	mxfs_scsipr_snap_invalidate(ctx, "register");            /* */

	/*
	 * (D-379(B) / D-0355, design-consult ruling): -EEXIST means
	 * this host's I_T nexus already carries a registration.  MXFS keys are
	 * minted per incarnation and a clean departure PROVES its key gone
	 * (READ KEYS post-condition, D-377), so the only way to get here is a
	 * predecessor incarnation of this host that departed dirty or
	 * unfenced and whose key was retained as the fence target.  Replacing
	 * it would re-authorise any surviving predecessor I/O on this nexus
	 * under our identity and destroy the only proof-of-exclusion peers
	 * (or a replayer) can obtain.  A same-nexus successor cannot fence
	 * its predecessor; the ways out are a peer's PREEMPT AND ABORT of that
	 * key, or the operator's single_node_exclusive assertion that no
	 * second initiator exists (exclusion by topology, fence kind 17).
	 */
	if (ret == -EEXIST) {
		if (!replace_predecessor) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P305-PR-PREDECESSOR-KEY-PRESENT '%s': an I_T "
				     "nexus of this host already holds a different PR "
				     "registration — a prior incarnation left without "
				     "retiring its key (dirty departure, P302; or a "
				     "clean departure whose retirement failed, P301) "
				     "or another consumer of this LU.  Refusing to "
				     "register over it: a same-nexus successor cannot "
				     "fence its predecessor.  Remedy: let a peer "
				     "PREEMPT AND ABORT the key, or (lone deployment, "
				     "no other initiator) set single_node_exclusive=1.  "
				     "See D-0355.",
				     ctx->dev_name);
			return -EEXIST;
		}
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P305-PR-PREDECESSOR-KEY-REPLACED '%s': nexus "
			     "already held a registration; REPLACING it with key "
			     "0x%llx under the operator's single_node_exclusive=1 "
			     "assertion (exclusion by topology, not by "
			     "reservation)",
			     ctx->dev_name, (unsigned long long)ctx->local_key);
		ret = mxfs_pal_scsi_pr_register_replace(ctx->dev, ctx->local_key);
		mxfs_scsipr_snap_invalidate(ctx, "register-replace"); /* */
	}

	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: '%s' has no PR support, skipping register",
			     ctx->dev_name);
		return 0;
	}

	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: SCSI persistent reservation register failed "
			     "on '%s': %d (hardware fencing unavailable)",
			     ctx->dev_name, ret);
		return ret;
	}

	ctx->registered = true;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: registered key 0x%llx on '%s'",
		     (unsigned long long)ctx->local_key, ctx->dev_name);
	return scsipr_verify_registered(ctx);
}

/*
 * (ruling item 4): VERIFY the registration against the table.
 * The target said GOOD; the ledger will record REGISTERED only on the
 * strength of READ KEYS showing our key.  A truncated table cannot
 * prove presence and an absent key means the REGISTER did not land on
 * this nexus (a UA-consumed PROUT, silent case): fail the
 * mount here rather than later as an unattributable EBADE.
 */
static int scsipr_verify_registered(struct mxfs_scsipr_ctx *ctx)
{
	bool victim_present = false, own_present = false;
	int count = 0;
	uint32_t gen = 0;
	int vr = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
					&count, &gen);

	if (vr == -EOPNOTSUPP)
		return 0;
	if (vr || !own_present) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-PRKEY-REGISTER-UNVERIFIED '%s' key=0x%llx "
			     "read_keys rc=%d own_present=%d keys=%d gen=%u — "
			     "REGISTER returned GOOD but the table does not show "
			     "the key on this nexus; refusing to treat this node "
			     "as registered",
			     ctx->dev_name, (unsigned long long)ctx->local_key,
			     vr, own_present, count, gen);
		ctx->registered = false;
		return vr ? vr : -EPROTO;
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-PRKEY-REGISTERED '%s' key=0x%llx keys=%d gen=%u "
		     "— registration verified by READ KEYS",
		     ctx->dev_name, (unsigned long long)ctx->local_key,
		     count, gen);
	return 0;
}

static int scsipr_register_succeed_locked(struct mxfs_scsipr_ctx *ctx,
					  uint64_t old_key)
{
	int ret;

	if (!ctx || !ctx->dev || !old_key || !ctx->local_key)
		return -EINVAL;
	if (ctx->registered)
		return -EBUSY;
	ret = mxfs_pal_scsi_pr_register_swap(ctx->dev, old_key, ctx->local_key);
	mxfs_scsipr_snap_invalidate(ctx, "register-succeed");    /* */
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P305-PR-SELF-SUCCESSION-FAILED '%s' old=0x%llx "
			     "new=0x%llx rc=%d — %s",
			     ctx->dev_name, (unsigned long long)old_key,
			     (unsigned long long)ctx->local_key, ret,
			     ret == -ENOKEY ? "this nexus does not hold the "
			     "predecessor key (classification stale); nothing "
			     "changed, refusing" : "swap not executed or unknown; "
			     "refusing");
		return ret;
	}
	ctx->registered = true;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P305-PR-PREDECESSOR-BOOT-REPLACED '%s' old_key=0x%llx "
		     "new_key=0x%llx — REGISTER(rk=old, sark=new) replaced this "
		     "host's previous boot's registration on our own nexus "
		     "(nexus-local; no other registration touched)",
		     ctx->dev_name, (unsigned long long)old_key,
		     (unsigned long long)ctx->local_key);
	return scsipr_verify_registered(ctx);
}

bool mxfs_scsipr_nexus_reused(struct mxfs_scsipr_ctx *ctx)
{
	return ctx && ctx->nexus_reused;
}

void mxfs_scsipr_retain_key(struct mxfs_scsipr_ctx *ctx)
{
	if (!ctx)
		return;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P302-PR-KEY-RETAINED-ON-REFUSAL '%s' key=0x%llx — the "
		     "registration stays on this nexus as the fence target of the "
		     "dirty predecessor; this refused mount will not unregister it",
		     ctx->dev_name, (unsigned long long)ctx->local_key);
	ctx->registered = false;
}

bool mxfs_scsipr_key_present(struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	bool victim_present = false, own_present = false;
	int count = 0, ret;
	uint32_t gen = 0;

	if (!ctx || !ctx->dev || !key)
		return true;
	ret = mxfs_scsipr_probe_keys(ctx, key, &victim_present, &own_present,
				     &count, &gen);
	if (ret == -EOPNOTSUPP)
		return false;        /* no PR: nothing can collide */
	if (ret)
		return true;         /* unknowable ⇒ treat as present */
	return victim_present;
}

/*
 * ── (0.59.2): the bracketed key-state proof ──────────────────────
 *
 * See the contract on enum mxfs_scsipr_key_state in scsipr.h.  One bracket
 * = READ KEYS (A) → READ RESERVATION → READ KEYS (B).  It runs under
 * ctx->probe_lock (never under snap_lock: the heartbeat's table lookups
 * must not wait behind PR I/O) and is committed into the snap_* fields
 * under snap_lock, unless a local PROUT invalidated the snapshot while the
 * bracket was in flight — then it is discarded.
 */
struct scsipr_view {
	int         state;
	uint32_t    gen;
	bool        own_present;
	bool        resv_ok;
	bool        gen_coherent;
	bool        proof;
	int         n;
	const char *why;
};

static int scsipr_read_keys_complete(struct mxfs_scsipr_ctx *ctx,
				     uint64_t *keys, int *n, uint32_t *gen,
				     const char *leg)
{
	int total = 0, ret;

	*n = 0;
	ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_PR_MAX_KEYS, n, gen, &total);
	if (ret == 0 && total > *n) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-VIEW-TRUNC '%s' leg=%s target holds %d "
			     "registration descriptor(s), we could read %d (cap %d) — "
			     "key absence is unknowable from a partial table",
			     ctx->dev_name, leg, total, *n, MXFS_PR_MAX_KEYS);
		ret = -EOVERFLOW;
	}
	return ret;
}

static bool scsipr_keys_contain(const uint64_t *keys, int n, uint64_t key)
{
	int i;

	for (i = 0; i < n; i++)
		if (keys[i] == key)
			return true;
	return false;
}

/* Caller holds ctx->probe_lock.  The B view is left in ctx->bkt_keys_b. */
static int scsipr_bracket_run(struct mxfs_scsipr_ctx *ctx,
			      struct scsipr_view *v)
{
	struct mxfs_pal_pr_reservation resv;
	int n_a = 0, n_b = 0, ret;
	uint32_t gen_a = 0, gen_b = 0;

	memset(v, 0, sizeof(*v));
	v->state = -ENODATA;
	v->why = "not-run";

	if (mxfs_pal_dbg_pr_bracket_fail_take()) {
		v->state = -EIO;
		v->why = "dbg-bracket-fail";
		return -EIO;
	}
	ret = scsipr_read_keys_complete(ctx, ctx->bkt_keys_a, &n_a, &gen_a, "A");
	if (ret) {
		v->state = ret;
		v->why = "read-keys-A";
		return ret;
	}
	memset(&resv, 0, sizeof(resv));
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		v->state = ret;
		v->why = "read-reservation";
		return ret;
	}
	ret = scsipr_read_keys_complete(ctx, ctx->bkt_keys_b, &n_b, &gen_b, "B");
	if (ret) {
		v->state = ret;
		v->why = "read-keys-B";
		return ret;
	}

	v->state = 0;
	v->gen = gen_b;
	v->n = n_b;
	v->own_present = ctx->local_key &&
			 scsipr_keys_contain(ctx->bkt_keys_a, n_a, ctx->local_key) &&
			 scsipr_keys_contain(ctx->bkt_keys_b, n_b, ctx->local_key);
	/* The sole-survivor gate's single-holder Write Exclusive held by OUR key
	 * excludes strictly more than WE-AR does (no other nexus writes at all),
	 * so an absence seen under it is at least as much of a proof. */
	v->resv_ok = resv.held &&
		     (resv.type == MXFS_SCSIPR_RESV_TYPE ||
		      (ctx->gate_held && resv.type == MXFS_PAL_PR_TYPE_WR_EX &&
		       resv.key == ctx->local_key));
	/* sd reports a zeroed descriptor (generation 0) when nothing is held,
	 * so the reservation's generation only takes part when it is held. */
	v->gen_coherent = gen_a == gen_b &&
			  (!resv.held || resv.generation == gen_b);
	v->proof = v->own_present && v->resv_ok && v->gen_coherent;
	v->why = !v->gen_coherent ? "generation-moved" :
		 !v->own_present ? "own-key-absent" :
		 !v->resv_ok ? "no-fencing-reservation" : "ok";
	return 0;
}

/*
 * Run one bracket and commit it.  Serialized by probe_lock; the snapshot
 * is replaced under snap_lock only if no invalidation landed meanwhile.
 * Returns the bracket's command rc (0 even when it yields no proof).
 */
static int scsipr_bracket_and_commit(struct mxfs_scsipr_ctx *ctx)
{
	struct scsipr_view v;
	uint64_t inval_at_start, now;
	int rc;

	mxfs_pal_mutex_lock(ctx->probe_lock);
	mxfs_pal_mutex_lock(ctx->snap_lock);
	inval_at_start = ctx->snap_inval_seq;
	mxfs_pal_mutex_unlock(ctx->snap_lock);

	rc = scsipr_bracket_run(ctx, &v);
	now = mxfs_pal_time_ms();

	mxfs_pal_mutex_lock(ctx->snap_lock);
	ctx->probe_brackets++;
	ctx->probe_last_ms = now;
	if (ctx->snap_inval_seq != inval_at_start) {
		ctx->probe_discarded++;
		ctx->snap_state = -ENODATA;
		ctx->snap_proof = false;
		ctx->snap_why = "invalidated-during-bracket";
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-BRACKET-DISCARDED '%s' — a local PR "
			     "mutation landed while the bracket ran; the view is "
			     "not a proof of anything (rerun)",
			     ctx->dev_name);
	} else {
		if (v.state == 0 && !v.gen_coherent)
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "scsipr: P-PR-BRACKET-INCOHERENT '%s' — the PR "
				     "generation moved between READ KEYS A, READ "
				     "RESERVATION and READ KEYS B (a PROUT landed inside "
				     "the bracket); no absence proof from this view",
				     ctx->dev_name);
		ctx->snap_state = v.state;
		ctx->snap_gen = v.gen;
		ctx->snap_own_present = v.own_present;
		ctx->snap_resv_ok = v.resv_ok;
		ctx->snap_proof = v.state == 0 && v.proof;
		ctx->snap_why = v.why;
		ctx->snap_n = v.state == 0 ? v.n : 0;
		if (v.state == 0 && v.n > 0)
			memcpy(ctx->snap_keys, ctx->bkt_keys_b,
			       sizeof(*ctx->snap_keys) * (size_t)v.n);
		ctx->snap_ms = now;
		ctx->snap_seq++;
	}
	mxfs_pal_mutex_unlock(ctx->snap_lock);
	mxfs_pal_mutex_unlock(ctx->probe_lock);
	return rc;
}

/* Caller holds snap_lock.  True if this (key, bracket) already handed out
 * its one ABSENT; otherwise records it and returns false. */
static bool scsipr_absent_consumed(struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	int i;

	for (i = 0; i < MXFS_SCSIPR_ABSENT_USES; i++)
		if (ctx->absent_used[i].key == key &&
		    ctx->absent_used[i].seq == ctx->snap_seq)
			return true;
	i = ctx->absent_used_next;
	ctx->absent_used[i].key = key;
	ctx->absent_used[i].seq = ctx->snap_seq;
	ctx->absent_used_next = (i + 1) % MXFS_SCSIPR_ABSENT_USES;
	return false;
}

/* Caller holds snap_lock.  Answers from the committed snapshot only. */
static int scsipr_answer(struct mxfs_scsipr_ctx *ctx, uint64_t key,
			 const char **why)
{
	uint64_t now = mxfs_pal_time_ms();

	if (ctx->snap_state != 0) {
		*why = ctx->snap_why;
		return MXFS_SCSIPR_KEY_UNKNOWN;
	}
	if (scsipr_keys_contain(ctx->snap_keys, ctx->snap_n, key)) {
		if (now - ctx->snap_ms <= MXFS_SCSIPR_PRESENT_TTL_MS) {
			*why = "present-in-view";
			return MXFS_SCSIPR_KEY_PRESENT;
		}
		*why = "present-stale";
		return MXFS_SCSIPR_KEY_UNKNOWN;
	}
	if (!ctx->snap_proof) {
		/* The view is complete and the key is not in it, but nothing
		 * makes that absence a proof: log once per 30 s. */
		if (now - ctx->snap_unprovable_log_ms >= 30000) {
			ctx->snap_unprovable_log_ms = now;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-ABSENCE-UNPROVABLE '%s' key=0x%llx "
				     "not in a complete %d-key view (gen=%u), but "
				     "own_key_present=%d resv_in_force=%d why=%s — "
				     "without our own registration AND the fencing "
				     "reservation inside one coherent bracket an absent "
				     "key proves nothing; answering UNKNOWN",
				     ctx->dev_name, (unsigned long long)key,
				     ctx->snap_n, ctx->snap_gen, ctx->snap_own_present,
				     ctx->snap_resv_ok, ctx->snap_why);
		}
		*why = ctx->snap_why;
		return MXFS_SCSIPR_KEY_UNKNOWN;
	}
	if (now - ctx->snap_ms > MXFS_SCSIPR_ABSENT_FRESH_MS) {
		*why = "absent-stale";
		return MXFS_SCSIPR_KEY_UNKNOWN;
	}
	if (scsipr_absent_consumed(ctx, key)) {
		*why = "absent-consumed";
		return MXFS_SCSIPR_KEY_UNKNOWN;
	}
	*why = "absent-proven";
	return MXFS_SCSIPR_KEY_ABSENT;
}

static bool scsipr_answerable(const struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	return ctx && ctx->dev && key && ctx->snap_lock && ctx->probe_lock &&
	       ctx->snap_keys && ctx->bkt_keys_a && ctx->bkt_keys_b;
}

/* ASYNC (heartbeat-safe): table lookup; UNKNOWN kicks the probe thread. */
int mxfs_scsipr_key_state(struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	const char *why = "";
	int st;

	if (!scsipr_answerable(ctx, key))
		return MXFS_SCSIPR_KEY_UNKNOWN;
	mxfs_pal_mutex_lock(ctx->snap_lock);
	st = scsipr_answer(ctx, key, &why);
	if (st == MXFS_SCSIPR_KEY_UNKNOWN)
		mxfs_pal_flag_set(&ctx->probe_kick, 1);
	mxfs_pal_mutex_unlock(ctx->snap_lock);
	return st;
}

/* SYNC (mount thread only): one fresh bracket, then the answer. */
int mxfs_scsipr_key_state_sync(struct mxfs_scsipr_ctx *ctx, uint64_t key)
{
	const char *why = "";
	int st;

	if (!scsipr_answerable(ctx, key))
		return MXFS_SCSIPR_KEY_UNKNOWN;
	scsipr_bracket_and_commit(ctx);
	mxfs_pal_mutex_lock(ctx->snap_lock);
	st = scsipr_answer(ctx, key, &why);
	mxfs_pal_mutex_unlock(ctx->snap_lock);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P-PR-KEY-STATE-SYNC '%s' key=0x%llx state=%s why=%s "
		     "gen=%u keys=%d",
		     ctx->dev_name, (unsigned long long)key,
		     st == MXFS_SCSIPR_KEY_ABSENT ? "ABSENT" :
		     st == MXFS_SCSIPR_KEY_PRESENT ? "PRESENT" : "UNKNOWN",
		     why, ctx->snap_gen, ctx->snap_n);
	return st;
}

/*
 * D-0965: a bracket disturbed by a peer's PROUT (the PR generation moved
 * between READ KEYS A and B, or a local mutation invalidated the view) is
 * neither a proof nor a disproof of our registration — it is a reason to
 * bracket again.  Measured (board s610f, 2/tcp): the chk_clean row remounts
 * both nodes in the same second, the peer's REGISTER landed inside this
 * node's own-proof bracket, the single NOT-PROVEN why=generation-moved
 * answer became 'TCP mount REFUSED (-16)' and the node stayed unmounted for
 * every later row; a retry mounted in 2.9 s.  Bounded: a few fresh
 * brackets with a growing pause between them (a peer registering takes one
 * PROUT, not a stream), stopping at the first coherent one.  A coherent
 * bracket that lacks our key or the fencing reservation still refuses.  The
 * budget is mxfs_pal_dbg_pr_own_proof_brackets() (kernel knob, default 4;
 * 1 restores the single bracket for the A/B).
 */

int mxfs_scsipr_own_registration_proven(struct mxfs_scsipr_ctx *ctx)
{
	const char *why;
	bool proof;
	int state, rc, attempt;
	uint32_t gen;

	if (!ctx || !ctx->dev || !ctx->local_key || !ctx->snap_lock ||
	    !ctx->probe_lock)
		return -EINVAL;
	for (attempt = 1;; attempt++) {
		bool disturbed;

		rc = scsipr_bracket_and_commit(ctx);
		mxfs_pal_mutex_lock(ctx->snap_lock);
		proof = ctx->snap_proof;
		state = ctx->snap_state;
		why = ctx->snap_why;
		gen = ctx->snap_gen;
		mxfs_pal_mutex_unlock(ctx->snap_lock);
		disturbed = !proof && why &&
			    (strcmp(why, "generation-moved") == 0 ||
			     strcmp(why, "invalidated-during-bracket") == 0);
		if (proof || !disturbed ||
		    (uint32_t)attempt >= mxfs_pal_dbg_pr_own_proof_brackets())
			break;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-OWN-PROOF-REBRACKET '%s' key=0x%llx "
			     "attempt=%d why=%s gen=%u — the bracket was disturbed "
			     "by a PROUT and proves nothing either way; bracketing "
			     "again",
			     ctx->dev_name, (unsigned long long)ctx->local_key,
			     attempt, why, gen);
		mxfs_pal_sleep_ms(50u * (uint32_t)attempt);
	}
	mxfs_pal_log(proof ? MXFS_LOG_DEBUG : MXFS_LOG_ERR,
		     "scsipr: P-PR-OWN-PROOF '%s' key=0x%llx %s gen=%u rc=%d "
		     "why=%s — %s",
		     ctx->dev_name, (unsigned long long)ctx->local_key,
		     proof ? "PROVEN" : "NOT-PROVEN", gen, rc, why,
		     proof ? "our registration is live inside the fencing "
		     "reservation in one coherent bracket" :
		     "no coherent bracket shows our key registered under the "
		     "fencing reservation");
	if (proof)
		return 0;
	return state < 0 ? state : -EPROTO;
}

void mxfs_scsipr_snap_invalidate(struct mxfs_scsipr_ctx *ctx, const char *why)
{
	if (!ctx || !ctx->snap_lock)
		return;
	mxfs_pal_mutex_lock(ctx->snap_lock);
	ctx->snap_inval_seq++;
	ctx->snap_state = -ENODATA;
	ctx->snap_proof = false;
	ctx->snap_why = why ? why : "invalidated";
	mxfs_pal_mutex_unlock(ctx->snap_lock);
}

/*
 * The probe thread: brackets on demand (kicked by an UNKNOWN answer), at
 * most one per MXFS_SCSIPR_PROBE_MIN_GAP_MS, otherwise idle in 50 ms
 * interruptible slices.  It is the ONLY thread that issues PR INs on behalf
 * of the heartbeat monitor, so a slow or hung PR command stalls the table,
 * never the heartbeat.
 */
static void scsipr_probe_fn(void *arg)
{
	struct mxfs_scsipr_ctx *ctx = arg;

	mxfs_pal_log(MXFS_LOG_DEBUG, "scsipr: P-PR-PROBE-THREAD '%s' started",
		     ctx->dev_name);
	while (!mxfs_pal_flag_get(&ctx->probe_stop)) {
		bool kick;
		uint64_t last;

		mxfs_pal_mutex_lock(ctx->snap_lock);
		kick = mxfs_pal_flag_get(&ctx->probe_kick) != 0;
		last = ctx->probe_last_ms;
		if (kick && mxfs_pal_time_ms() - last >= MXFS_SCSIPR_PROBE_MIN_GAP_MS)
			mxfs_pal_flag_set(&ctx->probe_kick, 0);
		else
			kick = false;
		mxfs_pal_mutex_unlock(ctx->snap_lock);

		if (kick)
			scsipr_bracket_and_commit(ctx);
		else
			mxfs_pal_sleep_ms_interruptible(50);
		{
			uint32_t hang = mxfs_pal_dbg_probe_hang_take();  /* D9 arm */

			if (hang)
				mxfs_pal_sleep_ms(hang);    /* parked: ignores probe_stop */
		}
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P-PR-PROBE-THREAD '%s' exiting brackets=%llu "
		     "discarded=%llu%s",
		     ctx->dev_name, (unsigned long long)ctx->probe_brackets,
		     (unsigned long long)ctx->probe_discarded,
		     ctx->quarantined ? " (quarantined: reaped later)" : "");
	/* (D8): the last store this thread makes to the context; a
	 * quarantined context is freed only after a reaper sees it. */
	mxfs_pal_flag_set(&ctx->probe_exited, 1);
}

int mxfs_scsipr_probe_start(struct mxfs_scsipr_ctx *ctx)
{
	if (!ctx || !ctx->dev || !ctx->snap_lock || !ctx->probe_lock)
		return -EINVAL;
	if (ctx->probe_thread)
		return 0;
	mxfs_scsipr_quarantine_reap();          /* (D8): free what exited */
	mxfs_pal_flag_set(&ctx->probe_stop, 0);
	mxfs_pal_flag_set(&ctx->probe_exited, 0);
	ctx->probe_thread = mxfs_pal_thread_create(scsipr_probe_fn, ctx);
	if (!ctx->probe_thread) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-PROBE-NOTHREAD '%s' — could not start the "
			     "key-state probe thread; every asynchronous key state "
			     "will be UNKNOWN (no RETIRE_PENDING record settles from "
			     "this node's monitor)", ctx->dev_name);
		return -ENOMEM;
	}
	return 0;
}

/*
 * (0.61.0, D8): bounded stop.  A probe thread that does not return
 * within MXFS_SCSIPR_JOIN_MS is parked in a SCSI command on a wedged path;
 * waiting the SCSI timeout (minutes, times dm-multipath retries) inside an
 * unmount is not acceptable, and freeing the context under it is a
 * use-after-free.  Quarantine: pin the module, put the context on the
 * list, leave every allocation and the thread handle alone.  The caller
 * treats the departure as DIRTY.
 */
int mxfs_scsipr_probe_stop(struct mxfs_scsipr_ctx *ctx)
{
	int rc;

	if (!ctx || !ctx->probe_thread)
		return 0;
	if (ctx->quarantined)
		return -ETIMEDOUT;              /* already quarantined; still parked */
	mxfs_pal_flag_set(&ctx->probe_stop, 1);
	rc = mxfs_pal_thread_join_timeout(ctx->probe_thread, MXFS_SCSIPR_JOIN_MS);
	if (rc == 0) {
		ctx->probe_thread = NULL;
		return 0;
	}
	ctx->quarantined = true;
	ctx->module_pinned = mxfs_pal_module_pin();
	if (scsipr_quar_lock) {
		mxfs_pal_mutex_lock(scsipr_quar_lock);
		ctx->quarantine_next = scsipr_quar_head;
		scsipr_quar_head = ctx;
		mxfs_pal_mutex_unlock(scsipr_quar_lock);
	}
	mxfs_pal_log(MXFS_LOG_ERR,
		     "scsipr: P-PR-PROBE-STUCK '%s' pid=%d — the key-state probe "
		     "thread did not exit within %u ms (a PR IN is parked on a "
		     "wedged path); context QUARANTINED (module pinned=%d, nothing "
		     "freed), the departure is treated as DIRTY (key retained, "
		     "slot not released), and no further clustered mount is "
		     "admitted on this host until the thread exits and is reaped",
		     ctx->dev_name, mxfs_pal_thread_pid(ctx->probe_thread),
		     (unsigned)MXFS_SCSIPR_JOIN_MS, ctx->module_pinned);
	return -ETIMEDOUT;
}

bool mxfs_scsipr_quarantine_active(void)
{
	struct mxfs_scsipr_ctx *c;
	bool active = false;

	if (!scsipr_quar_lock)
		return false;
	mxfs_pal_mutex_lock(scsipr_quar_lock);
	for (c = scsipr_quar_head; c; c = c->quarantine_next)
		if (!mxfs_pal_flag_get(&c->probe_exited))
			active = true;
	mxfs_pal_mutex_unlock(scsipr_quar_lock);
	return active;
}

/* Free every quarantined context whose thread has exited.  Returns how
 * many are still parked. */
int mxfs_scsipr_quarantine_reap(void)
{
	struct mxfs_scsipr_ctx *c, *next, *keep = NULL;
	int parked = 0;

	if (!scsipr_quar_lock)
		return 0;
	mxfs_pal_mutex_lock(scsipr_quar_lock);
	c = scsipr_quar_head;
	scsipr_quar_head = NULL;
	while (c) {
		next = c->quarantine_next;
		if (mxfs_pal_flag_get(&c->probe_exited)) {
			mxfs_pal_thread_join(c->probe_thread);
			c->probe_thread = NULL;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "scsipr: P-PR-PROBE-REAPED '%s' — the quarantined "
				     "probe thread exited; context freed",
				     c->dev_name);
			scsipr_free_now(c);
		} else {
			c->quarantine_next = keep;
			keep = c;
			parked++;
		}
		c = next;
	}
	scsipr_quar_head = keep;
	mxfs_pal_mutex_unlock(scsipr_quar_lock);
	return parked;
}

/*
 * ── (0.61.0, D1 + D6): settle-absent with the single-use token ──
 */
static int scsipr_proof_mint(struct mxfs_scsipr_ctx *ctx, uint64_t key,
			     uint64_t *token)
{
	/* caller holds probe_lock; snap_lock taken here only */
	mxfs_pal_mutex_lock(ctx->snap_lock);
	ctx->token_id = ++ctx->token_ctr;
	if (ctx->token_id == 0)
		ctx->token_id = ++ctx->token_ctr;
	ctx->token_key = key;
	ctx->token_seq = ctx->snap_seq;
	ctx->token_inval = ctx->snap_inval_seq;
	ctx->token_used = false;
	*token = ctx->token_id;
	mxfs_pal_mutex_unlock(ctx->snap_lock);
	return 0;
}

int mxfs_scsipr_proof_consume(struct mxfs_scsipr_ctx *ctx, uint64_t token)
{
	const char *why = NULL;

	if (!ctx || !ctx->snap_lock || !token)
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->snap_lock);
	if (ctx->token_id != token)
		why = "not-the-live-token";
	else if (ctx->token_used)
		why = "already-consumed";
	else if (ctx->token_inval != ctx->snap_inval_seq)
		why = "invalidated-since-mint";
	else if (ctx->token_seq != ctx->snap_seq)
		why = "bracket-superseded";
	/* consumed either way: a proof is spent by the attempt, not the result */
	if (ctx->token_id == token)
		ctx->token_used = true;
	mxfs_pal_mutex_unlock(ctx->snap_lock);
	if (why) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-PROOF-REFUSED '%s' token=%llu why=%s — the "
			     "absence proof is not valid at the CAS; no write",
			     ctx->dev_name, (unsigned long long)token, why);
		return -ESTALE;
	}
	return 0;
}

int mxfs_scsipr_settle_absent(struct mxfs_scsipr_ctx *ctx, uint64_t key,
			      mxfs_scsipr_settle_cas_fn cas_fn, void *cas_data,
			      enum mxfs_scsipr_settle *out)
{
	struct scsipr_view v;
	uint64_t inval_at_start, now, token = 0;
	bool absent, present, proof;
	const char *why;
	int rc, cr;

	if (out)
		*out = MXFS_SCSIPR_SETTLE_UNKNOWN;
	if (!scsipr_answerable(ctx, key) || !cas_fn)
		return -EINVAL;
	if (!mxfs_scsipr_departure_held()) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-SETTLE-UNHELD '%s' key=0x%llx pid=%d — "
			     "settle-absent called without the departure mutex; "
			     "refusing (UNKNOWN)", ctx->dev_name,
			     (unsigned long long)key, mxfs_pal_current_pid());
		return -EDEADLK;
	}

	mxfs_pal_mutex_lock(ctx->probe_lock);
	mxfs_pal_mutex_lock(ctx->snap_lock);
	inval_at_start = ctx->snap_inval_seq;
	mxfs_pal_mutex_unlock(ctx->snap_lock);

	rc = scsipr_bracket_run(ctx, &v);
	now = mxfs_pal_time_ms();

	/* commit exactly as scsipr_bracket_and_commit does, then judge */
	mxfs_pal_mutex_lock(ctx->snap_lock);
	ctx->probe_brackets++;
	ctx->probe_last_ms = now;
	if (ctx->snap_inval_seq != inval_at_start) {
		ctx->probe_discarded++;
		ctx->snap_state = -ENODATA;
		ctx->snap_proof = false;
		ctx->snap_why = "invalidated-during-bracket";
		proof = false; absent = false; present = false;
		why = ctx->snap_why;
	} else {
		ctx->snap_state = v.state;
		ctx->snap_gen = v.gen;
		ctx->snap_own_present = v.own_present;
		ctx->snap_resv_ok = v.resv_ok;
		ctx->snap_proof = v.state == 0 && v.proof;
		ctx->snap_why = v.why;
		ctx->snap_n = v.state == 0 ? v.n : 0;
		if (v.state == 0 && v.n > 0)
			memcpy(ctx->snap_keys, ctx->bkt_keys_b,
			       sizeof(*ctx->snap_keys) * (size_t)v.n);
		ctx->snap_ms = now;
		ctx->snap_seq++;
		present = v.state == 0 &&
			  scsipr_keys_contain(ctx->bkt_keys_b, v.n, key);
		proof = ctx->snap_proof;
		absent = v.state == 0 && !present && proof;
		why = v.why;
	}
	mxfs_pal_mutex_unlock(ctx->snap_lock);

	if (present) {
		if (out)
			*out = MXFS_SCSIPR_SETTLE_PRESENT;
		goto unlock;
	}
	if (!absent) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P-PR-SETTLE-UNPROVEN '%s' key=0x%llx rc=%d why=%s "
			     "gen=%u keys=%d — no fencing-grade absence proof from "
			     "this bracket; UNKNOWN",
			     ctx->dev_name, (unsigned long long)key, rc, why,
			     v.gen, v.n);
		goto unlock;
	}

	scsipr_proof_mint(ctx, key, &token);
	/* D9 injectors: a pause here models a slow settler (the departure
	 * mutex must exclude every local PROUT meanwhile); an invalidation
	 * here models the PR mutation the token guards against. */
	{
		uint32_t pause = mxfs_pal_dbg_settle_pause_ms();

		if (pause)
			mxfs_pal_sleep_ms(pause);
	}
	if (mxfs_pal_dbg_settle_inval_after_mint_take())
		mxfs_scsipr_snap_invalidate(ctx, "dbg-inval-after-mint");
	cr = cas_fn(cas_data, token);
	if (out)
		*out = cr == MXFS_SCSIPR_CAS_DONE  ? MXFS_SCSIPR_SETTLE_DONE :
		       cr == MXFS_SCSIPR_CAS_MOVED ? MXFS_SCSIPR_SETTLE_MOVED :
		       cr == MXFS_SCSIPR_CAS_DEFERRED ? MXFS_SCSIPR_SETTLE_DEFERRED :
						     MXFS_SCSIPR_SETTLE_UNKNOWN;
	mxfs_pal_log(MXFS_LOG_INFO,
		     "scsipr: P-PR-SETTLE-ABSENT '%s' key=0x%llx token=%llu gen=%u "
		     "keys=%d cas=%d — absence proven inside one coherent bracket "
		     "under the departure mutex; CAS %s",
		     ctx->dev_name, (unsigned long long)key,
		     (unsigned long long)token, v.gen, v.n, cr,
		     cr == MXFS_SCSIPR_CAS_DONE ? "landed" :
		     cr == MXFS_SCSIPR_CAS_MOVED ? "lost (record moved)" :
		     cr == MXFS_SCSIPR_CAS_DEFERRED ? "not attempted" : "failed");
	/* the token is spent whatever the CAS did */
	mxfs_pal_mutex_lock(ctx->snap_lock);
	if (ctx->token_id == token)
		ctx->token_used = true;
	mxfs_pal_mutex_unlock(ctx->snap_lock);
unlock:
	mxfs_pal_mutex_unlock(ctx->probe_lock);
	return rc;
}

static int scsipr_reserve_locked(struct mxfs_scsipr_ctx *ctx)
{
	int ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
				       MXFS_SCSIPR_RESV_TYPE);
	mxfs_scsipr_snap_invalidate(ctx, "reserve");             /* */

	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: '%s' has no PR support, skipping reserve",
			     ctx->dev_name);
		return 0;
	}

	if (ret == -EBUSY) {
		/*
		 * RESERVATION CONFLICT.
		 *
		 * this used to return 0 with "another node holds the
		 * reservation; with type 5 we only need to be registered to do I/O".
		 * That is a statement about I/O permission and it silently discarded
		 * the one signal that says the reservation in force is the WRONG TYPE.
		 * Under an all-registrants type a conflict from a registered requester
		 * is abnormal by SPC — every registrant is a holder, and a
		 * matching-scope/type RESERVE from a holder completes GOOD (MEASURED
		 * rc=0 from a second nexus).  So read back and classify instead of
		 * assuming.
		 */
		struct mxfs_pal_pr_reservation resv;
		int rr = mxfs_scsipr_read_reservation(ctx, &resv);

		if (rr == 0 && resv.held && resv.type == MXFS_SCSIPR_RESV_TYPE) {
			/* The right reservation is in force and we are a registrant, so
			 * we are a holder of it.  Benign, but not expected — record it. */
			ctx->resv_type_seen = resv.type;
			ctx->reserved = true;
			mxfs_pal_log(MXFS_LOG_INFO,
				     "scsipr: P304-RESV-CONFLICT-BENIGN '%s' RESERVE "
				     "returned CONFLICT but a %s reservation IS in force "
				     "(gen=%u); we are registered, hence a holder",
				     ctx->dev_name, mxfs_pr_type_name(resv.type),
				     resv.generation);
			return 0;
		}
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P304-RESV-CONFLICT '%s' RESERVE(%s) was REFUSED "
			     "and the reservation actually in force is held=%d "
			     "type=0x%x (%s) [readback rc=%d].  A registered requester "
			     "cannot conflict with a matching all-registrants "
			     "reservation, so this LU carries an incompatible "
			     "reservation (most likely a stale single-holder WE-RO "
			     "left by an older protocol generation, or a foreign "
			     "initiator).  Fencing on this LU is NOT what this build "
			     "expects; refusing to pretend it is",
			     ctx->dev_name, mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE),
			     (rr == 0) ? (int)resv.held : -1,
			     (rr == 0) ? resv.type : 0,
			     (rr == 0) ? mxfs_pr_type_name(resv.type) : "unreadable",
			     rr);
		return -EBUSY;
	}

	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: reserve failed on '%s': %d",
			     ctx->dev_name, ret);
		return ret;
	}

	ctx->reserved = true;
	ctx->resv_type_seen = MXFS_SCSIPR_RESV_TYPE;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: %s reservation acquired on '%s'",
		     mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE), ctx->dev_name);

	return 0;
}

/*
 * OBSERVE BEFORE ACTING.
 *
 * The admission gate used to run immediately after mxfs_scsipr_reserve() and
 * then assert "a reservation is held" — validating a reservation it had just
 * created one line earlier.  It was structurally incapable of reporting the
 * disarmed state, and it proved it: a node mounting onto a LUN with NO
 * reservation at all logged "P303-FENCECAP-OK ... WE-RO held" while two
 * independent observers read "none held" immediately before and after.
 *
 * This call is what a mount makes FIRST, before REGISTER and RESERVE, purely
 * to record what was already there.  It changes nothing.
 */
int mxfs_scsipr_observe_reservation(struct mxfs_scsipr_ctx *ctx,
				    struct mxfs_pal_pr_reservation *out)
{
	struct mxfs_pal_pr_reservation resv;
	int ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P304-PREOBSERVE '%s' READ RESERVATION rc=%d — "
			     "the pre-existing reservation state is UNKNOWN",
			     ctx->dev_name, ret);
		if (out)
			memset(out, 0, sizeof(*out));
		return ret;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P304-PREOBSERVE '%s' held=%d type=0x%x (%s) "
		     "holder_key=0x%llx gen=%u — state observed BEFORE this mount "
		     "registered or reserved anything",
		     ctx->dev_name, (int)resv.held, resv.type,
		     mxfs_pr_type_name(resv.type),
		     (unsigned long long)resv.key, resv.generation);

	if (resv.held)
		ctx->resv_type_seen = resv.type;
	if (out)
		*out = resv;
	return 0;
}

int mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx,
				 struct mxfs_pal_pr_reservation *out)
{
	if (!ctx || !ctx->dev || !out)
		return -EINVAL;
	return mxfs_pal_scsi_pr_read_reservation(ctx->dev, out);
}

static int mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx,
				  uint64_t want_key, bool *out_present,
				  bool *out_self, int *out_count,
				  uint32_t *out_gen);

int mxfs_scsipr_check_reservation_health(struct mxfs_scsipr_ctx *ctx,
					 bool repair,
					 uint32_t *out_gen, int *out_count)
{
	struct mxfs_pal_pr_reservation resv;
	bool self_present = false, dummy = false;
	uint32_t gen = 0;
	int count = 0, ret;

	if (!ctx || !ctx->dev)
		return MXFS_RESV_HEALTH_UNKNOWN;
	if (!ctx->local_key || !ctx->registered)
		return MXFS_RESV_HEALTH_UNKNOWN;

	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		/* Could not answer the question.  That is NOT "healthy" — a caller
		 * that treats an I/O error as OK is exactly the blindness this
		 * function exists to remove. */
		if (out_gen)
			*out_gen = 0;
		if (out_count)
			*out_count = 0;
		return MXFS_RESV_HEALTH_UNKNOWN;
	}
	gen = resv.generation;

	/* The registrant view is part of the invariant: a reservation that is held
	 * while OUR key is gone means we are the excluded one, not that all is
	 * well. */
	if (mxfs_scsipr_probe_keys(ctx, ctx->local_key, &self_present, &dummy,
				   &count, &gen) != 0)
		self_present = true;    /* unknown — do not manufacture a self-fence */

	if (out_gen)
		*out_gen = gen;
	if (out_count)
		*out_count = count;

	if (!self_present)
		return MXFS_RESV_HEALTH_SELF_GONE;

	if (resv.held && resv.type == MXFS_SCSIPR_RESV_TYPE) {
		ctx->resv_type_seen = resv.type;
		return MXFS_RESV_HEALTH_OK;
	}
	if (resv.held && ctx->gate_held &&
	    resv.type == MXFS_PAL_PR_TYPE_WR_EX && resv.key == ctx->local_key) {
		/* The sole-survivor gate is in force by design until the recovery
		 * it authorised publishes; it excludes every other initiator, so
		 * the invariant this check guards holds.  Not WRONG_TYPE. */
		ctx->resv_type_seen = resv.type;
		return MXFS_RESV_HEALTH_OK;
	}
	if (resv.held)
		return MXFS_RESV_HEALTH_WRONG_TYPE;

	if (repair) {
		int rr = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
						  MXFS_SCSIPR_RESV_TYPE);

		mxfs_scsipr_snap_invalidate(ctx, "reserve-repair");  /* */
		if (rr == 0 || rr == -EBUSY) {
			/* Re-read rather than trusting the status: -EBUSY here means
			 * somebody else re-established it in the same window, which is a
			 * fine outcome but only if it is the RIGHT type. */
			if (mxfs_scsipr_read_reservation(ctx, &resv) == 0 && resv.held &&
			    resv.type == MXFS_SCSIPR_RESV_TYPE) {
				ctx->reserved = true;
				ctx->resv_type_seen = resv.type;
				if (out_gen)
					*out_gen = resv.generation;
				/* NOT "OK" — see the enum.  The caller must be able to tell a
				 * cluster that was always armed from one that had a hole. */
				return MXFS_RESV_HEALTH_REPAIRED;
			}
		}
	}
	return MXFS_RESV_HEALTH_ABSENT;
}

const char *mxfs_resv_health_name(int h)
{
	switch (h) {
	case MXFS_RESV_HEALTH_OK:         return "OK";
	case MXFS_RESV_HEALTH_ABSENT:     return "ABSENT";
	case MXFS_RESV_HEALTH_WRONG_TYPE: return "WRONG_TYPE";
	case MXFS_RESV_HEALTH_SELF_GONE:  return "SELF_GONE";
	case MXFS_RESV_HEALTH_REPAIRED:   return "REPAIRED";
	default:                          return "UNKNOWN";
	}
}

void mxfs_scsipr_set_key_live_guard(struct mxfs_scsipr_ctx *ctx,
				    int (*fn)(void *data, uint64_t key,
					      mxfs_node_id_t excl_node,
					      mxfs_node_id_t *live_node,
					      int *live_slot),
									void *data)
{
	if (!ctx)
		return;
	ctx->key_live_fn = fn;
	ctx->key_live_data = data;
}

const char *mxfs_fence_kind_name(enum mxfs_fence_kind k)
{
	switch (k) {
	case MXFS_FENCE_KIND_NONE:                return "NONE";
	case MXFS_FENCE_KIND_ERROR:               return "ERROR";
	case MXFS_FENCE_KIND_UNSUPPORTED:         return "UNSUPPORTED";
	case MXFS_FENCE_KIND_ADVISORY_TOPOLOGY:   return "ADVISORY_TOPOLOGY";
	case MXFS_FENCE_KIND_NOT_REGISTERED:      return "NOT_REGISTERED";
	case MXFS_FENCE_KIND_SELF_PREEMPTED:      return "SELF_PREEMPTED";
	case MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN: return "KEY_ABSENT_UNPROVEN";
	case MXFS_FENCE_KIND_RACE_LOST:           return "RACE_LOST";
	case MXFS_FENCE_KIND_NO_RESERVATION:      return "NO_RESERVATION";
	case MXFS_FENCE_KIND_VIEW_TRUNCATED:      return "VIEW_TRUNCATED";
	case MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1:
		return "PREEMPT_ABORT_PROVEN_V1";
	case MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1:
		return "LU_RESET_WITNESSED_V1";
	case MXFS_FENCE_KIND_PREEMPT_ABORT_DONE:
		return "PREEMPT_ABORT_DONE_RETIRED16";
	case MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE: return "SINGLE_NODE_EXCLUSIVE";
	case MXFS_FENCE_KIND_NO_VICTIM_KEY:       return "NO_VICTIM_KEY";
	case MXFS_FENCE_KIND_SELF_SUCCESSION_DONE: return "SELF_SUCCESSION_DONE";
	case MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE: return "EXCLUSIVE_WRITE_GATE";
	case MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT: return "BOOT_SUCCESSION_ABSENT";
	case MXFS_FENCE_KIND_KEY_HELD_BY_LIVE_MEMBER: return "KEY_HELD_BY_LIVE_MEMBER";
	}
	return "?";
}

static int scsipr_preempt_locked(struct mxfs_scsipr_ctx *ctx,
				 uint64_t victim_key, bool abort)
{
	uint32_t type;
	int ret;

	if (!ctx || !ctx->dev || victim_key == 0)
		return -EINVAL;

	/*
	 * design-consult ruling: NEVER issue a PREEMPT whose SARK is our own key.
	 * SPC protects the issuing nexus's own registration from its own PREEMPT
	 * while removing OTHER registrations carrying the same key — so it is not
	 * a self-fence, and with MXFS's one-key-across-two-nexuses scheme it
	 * silently kills our sibling path instead.  A victim key equal to ours is
	 * an identity collision (D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377), not
	 * a fence.
	 */
	if (victim_key == ctx->local_key) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P304-PREEMPT-SELFKEY '%s' refusing PREEMPT%s "
			     "with SARK == our own key 0x%llx — this cannot fence "
			     "anyone (our own registration is protected from it) and "
			     "would remove our sibling nexus.  Node identity collision",
			     ctx->dev_name, abort ? " AND ABORT" : "",
			     (unsigned long long)victim_key);
		return -EINVAL;
	}

	/*
	 * The PROUT carries the type of the reservation ACTUALLY IN FORCE, not a
	 * hardcoded one — a type mismatch is a scope/type error at the target
	 * .  Fall back to the type this build establishes when nothing
	 * has been observed yet.
	 */
	type = ctx->resv_type_seen ? ctx->resv_type_seen : MXFS_SCSIPR_RESV_TYPE;

	ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, victim_key,
				       abort, type);
	mxfs_scsipr_snap_invalidate(ctx, "preempt");             /* */

	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: '%s' has no PR preempt support",
			     ctx->dev_name);
		return ret;
	}

	if (ret == -EBUSY) {
		/* RESERVATION CONFLICT: the SARK was not registered, so this
		 * command did nothing at all.  Not an error, not a fence. */
		mxfs_pal_log(MXFS_LOG_INFO,
			     "scsipr: preempt%s of key 0x%llx on '%s': RESERVATION "
			     "CONFLICT — key not registered; no registration removed "
			     "and no task set aborted by us",
			     abort ? "-abort" : "",
			     (unsigned long long)victim_key, ctx->dev_name);
		return ret;
	}

	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: preempt%s of key 0x%llx failed on '%s': %d",
			     abort ? "-abort" : "",
			     (unsigned long long)victim_key, ctx->dev_name, ret);
		return ret;
	}

	ctx->reserved = true;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: preempted%s key 0x%llx on '%s'",
		     abort ? "-and-aborted" : "",
		     (unsigned long long)victim_key, ctx->dev_name);

	return 0;
}

/*
 * Snapshot the LUN's registration table and answer the only two questions
 * every classifier in this file asks of it: is the victim registered, and are
 * we?  Both are questions about ABSENCE, which is precisely what a truncated
 * view manufactures — so a partial table is reported as -EOVERFLOW rather
 * than answered.  Callers must translate that into "unknown", never into
 * "absent".  See MXFS_PR_MAX_KEYS in scsipr.h for why the old
 * MXFS_MAX_NODES-sized buffers were too small on a multipath rig.
 *
 * Pass victim_key = 0 when only own-registration matters; MXFS never
 * registers key 0, so it can never match.
 */
static int mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx,
				  uint64_t victim_key,
				  bool *victim_present, bool *own_present,
				  int *count, uint32_t *generation)
{
	uint64_t *keys;
	int total = 0, n = 0, i, ret;

	*victim_present = false;
	*own_present = false;
	*count = 0;

	/* MXFS_PR_MAX_KEYS u64s is 4KB — far past what may sit on a kernel
	 * stack, and this also runs on the heartbeat thread. */
	keys = mxfs_pal_alloc(sizeof(*keys) * MXFS_PR_MAX_KEYS);
	if (!keys)
		return -ENOMEM;

	ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_PR_MAX_KEYS, &n, generation,
				    &total);
	if (ret) {
		mxfs_pal_free(keys);
		return ret;
	}

	if (total > n) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-VIEW-TRUNC '%s' target holds %d "
			     "registration descriptor(s), we could read %d (cap %d) — "
			     "key absence is unknowable from a partial table; "
			     "refusing to classify",
			     ctx->dev_name, total, n, MXFS_PR_MAX_KEYS);
		mxfs_pal_free(keys);
		return -EOVERFLOW;
	}

	for (i = 0; i < n; i++) {
		if (victim_key && keys[i] == victim_key)
			*victim_present = true;
		if (keys[i] == ctx->local_key)
			*own_present = true;
	}
	*count = n;

	mxfs_pal_free(keys);
	return 0;
}

/*
 * LIVE-PROVER FAULTS AT THE COMMAND-SUBMISSION BOUNDARY.
 *
 * The six fence crash cuts destroy the prover.  The design ruling banked in
 * docs/rulings/fence-crash-matrix-cuts.md requires the opposite for the
 * MAY_HAVE_SUBMITTED entries: the prover stays ALIVE and it is the COMMAND's
 * outcome that is made definitely-failed, uncertain, or lost.  A destroyed
 * prover cannot produce any of them, because the thing under test is what
 * THIS prover does next with an answer it cannot trust.
 *
 * Nothing here changes what the target is asked to do, except by not asking.
 * Mode 5 issues the REAL PREEMPT AND ABORT and the victim key really is
 * consumed; only the answer handed back to the prover is replaced.  An
 * injector must be able to make a check fail, never to make it pass.
 *
 *   1 precommand  a DEFINITE pre-command failure at the boundary: nothing
 *                 armed, nothing issued, the attempt stays PRECOMMAND.
 *   2 armfail     the arm CAS is refused: nothing durable, nothing issued.
 *   3 armambig    the arm CAS LANDED and is reported as having FAILED —
 *                 durable arming under an ambiguous answer.
 *   4 uncertain   armed, then NO PROUT is issued and a transport timeout is
 *                 returned: an UNCERTAIN submission the prover cannot
 *                 distinguish from one that reached the target.
 *   5 lostresp    the PROUT IS issued, the target acts, the victim key is
 *                 consumed — and its SUCCESSFUL response is replaced with a
 *                 transport timeout, with the prover still alive.
 *
 * One-shot and filtered by victim node, because the ruling refuses a global
 * one-shot that can catch the wrong attempt.  Modes 3 and 5 can be armed into
 * a no-op — the arm or the command may genuinely fail — and when that happens
 * they DECLINE loudly and let the real outcome stand, rather than reporting a
 * substituted answer for a state that never existed.
 */
static int mxfs_pr_fence_submit_inject;
module_param_named(pr_fence_submit_inject, mxfs_pr_fence_submit_inject, int,
		   0644);
MODULE_PARM_DESC(pr_fence_submit_inject,
		 "TEST ONLY: live-prover fault at the fence command-submission "
		 "boundary (1=definite pre-command failure, 2=arm refused, "
		 "3=arm landed but reported failed, 4=armed and not submitted, "
		 "5=submitted and acted on with the response lost). One-shot; "
		 "0=off. Never enable in production.");

/*
 * A NODE ID IS UNSIGNED AND MORE THAN HALF OF THEM DO NOT FIT IN AN int.
 * mxfs_node_id_t is 32-bit unsigned, so roughly every second node id this rig
 * generates is above INT_MAX.  Declared int, the sysfs write of such an id is
 * refused with -ERANGE and the knob keeps reading back 0 — which is the "any
 * victim" value, so the injector silently becomes a global one-shot the ruling
 * refuses.  Two laps (s132d1 victim 2585738898, s132d2 victim 2431490331)
 * aborted at the arm on exactly that, 9 minutes of rig each, with the mode
 * itself reading back correctly beside it.
 */
static unsigned int mxfs_pr_fence_submit_inject_victim;
module_param_named(pr_fence_submit_inject_victim,
		   mxfs_pr_fence_submit_inject_victim, uint, 0644);
MODULE_PARM_DESC(pr_fence_submit_inject_victim,
		 "TEST ONLY: the victim node id pr_fence_submit_inject applies "
		 "to (0 = any). Naming the victim is what makes the injection "
		 "deterministic rather than whichever attempt arrives first.");

static int scsipr_fence_inject_take(mxfs_node_id_t victim_node)
{
	int mode = mxfs_pr_fence_submit_inject;

	if (mode <= 0)
		return 0;
	if (mxfs_pr_fence_submit_inject_victim != 0 &&
	    (mxfs_node_id_t)mxfs_pr_fence_submit_inject_victim != victim_node)
		return 0;
	mxfs_pr_fence_submit_inject = 0;                        /* one-shot */
	return mode;
}

int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
			   mxfs_node_id_t victim_node, uint64_t victim_key,
			   int live_members,
			   int (*arm_submit)(void *), void *arm_data,
			   struct mxfs_fence_result *out)
{
	struct mxfs_pal_pr_reservation resv;
	uint32_t gen = 0;
	int count = 0, ret, inj;
	bool victim_present = false, own_present = false;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->kind = MXFS_FENCE_KIND_NONE;
	out->victim_key = victim_key;
	/*
	 * PRECOMMAND until the exact line that submits.  Everything from
	 * here to the arm_submit() call below is pure observation — READ KEYS,
	 * READ RESERVATION, classification — so every return in between is
	 * "nothing was submitted, nothing was consumed, this is safe to repeat".
	 * That is the property D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381
	 * exists because nobody recorded.
	 */
	out->phase = MXFS_FENCE_PHASE_PRECOMMAND;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	if (!victim_key) {
		/* no frozen key for the exact dead incarnation.  The old
		 * code derived the key from the node id; a 64-bit per-boot key
		 * cannot be derived from anything, so this is a refusal, not a
		 * fallback.  Nothing was issued. */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-FENCE-NOKEY node=%u on '%s' — the victim's "
			     "PR key was never frozen from a valid identity block of "
			     "the dead incarnation; no PREEMPT AND ABORT can name it. "
			     "NOTHING WAS ISSUED",
			     victim_node, ctx->dev_name);
		out->kind = MXFS_FENCE_KIND_NO_VICTIM_KEY;
		return 0;
	}

	/*
	 * Is the key we are about to PREEMPT AND ABORT also carried by a LIVE
	 * member right now?
	 *
	 * The PR key is derived per BOOT from {host_uuid, boot_uuid, fs_uuid}
	 * (mxfs_prledger_derive_key) and a host reaches the LUN over one I_T
	 * nexus, so a successor incarnation mounting in the SAME kernel
	 * re-registers the IDENTICAL key its dead predecessor left behind as the
	 * fence target.  The target cannot distinguish the two incarnations: a
	 * P&A naming that key strips the LIVE successor's registration and aborts
	 * its outstanding task set, which is a healthy mounted node losing its
	 * write access without ever being at fault.
	 *
	 * A node was already protected from preempting ITS OWN previous
	 * incarnation (P238-FENCE-OWN-KEY compares the victim key against the
	 * fencer's own).  That guard covers only the self direction; when a PEER
	 * fences a dead incarnation whose host has already remounted, the keys
	 * differ from the fencer's and it never fires.  This closes the symmetric
	 * direction, at the primitive every fence path funnels through.
	 *
	 * Fail closed: "cannot tell" refuses too.  Nothing has been submitted at
	 * this point, so the attempt stays PRECOMMAND and is safe to repeat once
	 * the succession has been serialised.
	 */
	if (ctx->key_live_fn) {
		mxfs_node_id_t lnode = 0;
		int lslot = -1, lrc;

		lrc = ctx->key_live_fn(ctx->key_live_data, victim_key, victim_node,
				       &lnode, &lslot);
		if (lrc != 0) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-FENCE-KEY-LIVE-ELSEWHERE key=0x%llx "
				     "victim_node=%u on '%s' — %s.  A PREEMPT AND ABORT "
				     "naming this key would remove that member's "
				     "registration and abort its task set: the key is "
				     "derived per BOOT, so a successor on the victim's "
				     "host carries the SAME key and the target cannot "
				     "tell the incarnations apart.  NOTHING WAS ISSUED; "
				     "this proves no exclusion",
				     (unsigned long long)victim_key, victim_node,
				     ctx->dev_name,
				     lrc > 0 ? "it is carried by a LIVE member's heartbeat "
					       "record"
								 : "the live-member check could not answer "
								   "(failing closed)");
			if (lrc > 0)
				mxfs_pal_log(MXFS_LOG_ERR,
					     "scsipr: P-PR-FENCE-KEY-LIVE-ELSEWHERE holder "
					     "node=%u slot=%d", lnode, lslot);
			out->kind = MXFS_FENCE_KIND_KEY_HELD_BY_LIVE_MEMBER;
			return 0;
		}
	}

	/* SPC hygiene: READ KEYS before PREEMPT.  Preempting a key that is
	 * not registered is a RESERVATION CONFLICT by spec; classify first. */
	ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
				     &own_present, &count, &gen);
	if (ret == -EOPNOTSUPP) {
		/* No PR support: we cannot exclude the victim from the LUN at
		 * all.  Naming it is the whole point — the caller decides, and
		 * it must not decide "fenced". */
		out->kind = MXFS_FENCE_KIND_UNSUPPORTED;
		return 0;
	}
	if (ret == -EOVERFLOW) {
		/* More descriptors than we can read.  We cannot tell whether the
		 * victim is registered, and — worse — cannot tell whether OUR key
		 * is still there, so neither preempting nor self-fencing is
		 * defensible.  Refuse, loudly and durably. */
		out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
		out->rc = ret;
		return 0;
	}
	if (ret) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P-PR-FENCE read_keys failed on '%s': %d "
			     "(cannot classify; skipping preempt)",
			     ctx->dev_name, ret);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	out->pr_generation = gen;

	/* Topology sanity: per-node PR needs one registration per live
	 * member.  Fewer keys than live members means the rig cannot hold
	 * per-node registrations (shared I_T nexus: each node's REGISTER
	 * overwrites the previous one's — measured on the tcm_loop VM rig,
	 * where ALL VMs funnel through one host block device) or the target
	 * purged registrations wholesale.  In that state key-bookkeeping
	 * proves nothing about fencing: no preempt (removing the single
	 * shared registration would fence EVERYONE incl. us), no self-fence
	 * (our key being "missing" is expected, not a preemption).  PR is
	 * ADVISORY here — D1 (EBADE on write = fencing event) plus
	 * lease/disklock exclusion carry the fencing duty. */
	if (count < live_members) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P-PR-ADVISORY '%s' has %d key(s) for %d live "
			     "member(s) — per-node PR not usable on this topology; "
			     "skipping preempt/self-fence (D1+lease fencing apply)",
			     ctx->dev_name, count, live_members);
		out->kind = MXFS_FENCE_KIND_ADVISORY_TOPOLOGY;
		return 0;
	}

	if (!own_present) {
		if (ctx->registered && live_members >= 2) {
			/* UNAMBIGUOUS preemption: every other live member's key is
			 * accounted for and OURS specifically vanished (another node
			 * preempted us, or the target removed exactly us).  We may
			 * be FENCED: every write can bounce off a WE-RO reservation
			 * we are no longer part of.  NEVER auto-re-register (that
			 * would resurrect a deliberately-fenced node) — the caller
			 * must self-fence. */
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
				     "'%s' (%d key(s) present, %d live) — node was "
				     "preempted",
				     (unsigned long long)ctx->local_key, ctx->dev_name,
				     count, live_members);
			out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
			return -ESTALE;
		}
		if (ctx->registered) {
			/* Sole survivor with our key gone: nobody live is left to
			 * have excluded us on purpose, and a lone stale key (the
			 * victim's, or a shared-nexus overwrite) cannot prove a
			 * preemption.  Log and rely on D1: if the target really
			 * fenced us, the next write bounces EBADE and shuts us
			 * down reactively. */
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
				     "'%s' (%d key(s), sole survivor) — ambiguous; "
				     "relying on reactive D1 fencing",
				     (unsigned long long)ctx->local_key, ctx->dev_name,
				     count);
			out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
			return 0;
		}
		/* We never registered (PR not in use for this mount) — a PREEMPT
		 * from an unregistered initiator is itself a conflict; leave
		 * fencing to lease/disklock exclusion. */
		out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
		return 0;
	}

	/*
	 * A reservation must be HELD for deregistration to exclude anyone.
	 * Under WE-RO the target rejects writes from non-registrants at
	 * command-processing time — but only while the reservation exists.
	 * With no reservation, an unregistered initiator writes freely and
	 * the victim's missing key means precisely nothing.  Establish this
	 * BEFORE the preempt so the refusal is attributable.
	 */
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret && ret != -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P-PR-FENCE read_reservation failed on '%s': %d "
			     "— cannot establish that deregistration excludes",
			     ctx->dev_name, ret);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	if (ret == -EOPNOTSUPP || !resv.held ||
	    !mxfs_pr_type_excludes_nonregistrants(resv.type)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-NORESV '%s' held=%d type=0x%x (%s; want a "
			     "Write Exclusive form, 0x%x or 0x%x)%s — removing a "
			     "registration excludes nobody without a reservation; NOT "
			     "a fence, and NOTHING WAS ISSUED: no PREEMPT reached the "
			     "target, no state was consumed, the victim key is intact "
			     "and this attempt is RETRYABLE once a reservation is back",
			     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
			     (ret == -EOPNOTSUPP) ? 0 : resv.type,
			     (ret == -EOPNOTSUPP) ? "unreadable"
						  : mxfs_pr_type_name(resv.type),
					 MXFS_PAL_PR_TYPE_WR_EX_RO, MXFS_PAL_PR_TYPE_WR_EX_AR,
					 (ret == -EOPNOTSUPP) ? " [READ RESERVATION unsupported]"
							      : "");
		out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
		return 0;
	}
	out->resv_type = resv.type;
	ctx->resv_type_seen = resv.type;

	if (!victim_present) {
		/*
		 * this used to return 0 — "fenced elsewhere or never
		 * registered" — and it is the COMMON path at 32 nodes, where up
		 * to 31 survivors race to fence one victim and 30 of them arrive
		 * to find the key already gone.
		 *
		 * Key absence bounds only what the victim may START.  It does not
		 * establish that anybody ever aborted the task set the victim had
		 * ALREADY started, and under the old plain-PREEMPT fence nobody
		 * ever did.  A loser cannot re-derive the winner's guarantee from
		 * the registration table; it has to consume the winner's durably
		 * published evidence.  Name it unproven and let the caller do that.
		 */
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-FENCE-ABSENT victim key 0x%llx already "
			     "absent on '%s' (gen=%u) — exclusion NOT proved here; "
			     "caller must consume published fence evidence",
			     (unsigned long long)victim_key, ctx->dev_name, gen);
		out->kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
		return 0;
	}

	/*
	 * THE COMMAND-SUBMISSION BOUNDARY.  Everything above observed;
	 * everything below may change target state.  Make that durable FIRST, and
	 * do not submit if it cannot be made durable: a preempt whose having
	 * happened cannot later be established consumes the victim key and leaves
	 * the slice provably unrecoverable, which is strictly worse than not
	 * fencing at all.
	 */
	inj = scsipr_fence_inject_take(victim_node);
	if (inj == 1) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-FENCE-INJECT mode=1 precommand '%s' "
			     "victim=%u key=0x%llx — TEST ONLY: a DEFINITE pre-command "
			     "failure at the submission boundary.  Nothing was armed "
			     "and nothing was issued; the attempt stays PRECOMMAND, "
			     "nothing was consumed, and it is safe to repeat",
			     ctx->dev_name, victim_node,
			     (unsigned long long)victim_key);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -EIO;
		return -EIO;
	}

	if (arm_submit) {
		if (inj == 2) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-FENCE-INJECT mode=2 armfail '%s' "
				     "victim=%u key=0x%llx — TEST ONLY: the arm CAS is "
				     "refused without being attempted, so nothing durable "
				     "names this submission and no PREEMPT AND ABORT is "
				     "issued",
				     ctx->dev_name, victim_node,
				     (unsigned long long)victim_key);
			ret = -EIO;
		} else {
			ret = arm_submit(arm_data);
		}
		if (inj == 3) {
			if (ret) {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "scsipr: P-PR-FENCE-INJECT-VACUOUS mode=3 armambig "
					     "'%s' victim=%u rc=%d — the arm CAS GENUINELY "
					     "failed, so there is no landed arm whose answer "
					     "could be made ambiguous.  The injection is "
					     "DECLINED and the real outcome stands",
					     ctx->dev_name, victim_node, ret);
			} else {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "scsipr: P-PR-FENCE-INJECT mode=3 armambig '%s' "
					     "victim=%u key=0x%llx — TEST ONLY: the arm CAS "
					     "LANDED and is being reported to this prover as "
					     "having FAILED.  A durable marker now names a "
					     "submission the prover believes it never made",
					     ctx->dev_name, victim_node,
					     (unsigned long long)victim_key);
				ret = -ETIMEDOUT;
			}
		}
		if (ret) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P304-FENCE-NOARM '%s' victim key 0x%llx rc=%d "
				     "— the command-submission boundary could not be made "
				     "durable, so NO PREEMPT AND ABORT was issued.  Nothing "
				     "was consumed and this attempt is still retryable",
				     ctx->dev_name, (unsigned long long)victim_key, ret);
			out->kind = MXFS_FENCE_KIND_ERROR;
			out->rc = ret;
			return 0;
		}
	}
	out->phase = MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED;

	if (inj == 4) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-FENCE-INJECT mode=4 uncertain '%s' victim=%u "
			     "key=0x%llx — TEST ONLY: the submission is durably armed "
			     "and NO PREEMPT AND ABORT was issued, but the prover is "
			     "given a transport timeout.  From here it cannot tell this "
			     "from a command that reached the target: the attempt is "
			     "MAY_HAVE_SUBMITTED and must not be blindly resubmitted "
			     "under the same arm",
			     ctx->dev_name, victim_node,
			     (unsigned long long)victim_key);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -ETIMEDOUT;
		return -ETIMEDOUT;
	}

	/* PREEMPT AND ABORT — the abort is the point. */
	ret = mxfs_scsipr_preempt(ctx, victim_key, true);
	if (inj == 5) {
		if (ret) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-FENCE-INJECT-VACUOUS mode=5 lostresp "
				     "'%s' victim=%u rc=%d — the real PREEMPT AND ABORT did "
				     "not succeed, so there is no completed target action "
				     "whose response could be lost.  The injection is "
				     "DECLINED and the real outcome stands",
				     ctx->dev_name, victim_node, ret);
		} else {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-FENCE-INJECT mode=5 lostresp '%s' "
				     "victim=%u key=0x%llx — TEST ONLY: the PREEMPT AND "
				     "ABORT COMPLETED at the target and the victim key is "
				     "really consumed; its successful response is being "
				     "replaced with a transport timeout while this prover "
				     "stays ALIVE.  Durable arming alone must not certify, "
				     "and a successor's new attempt needs proved revocation "
				     "and a new term",
				     ctx->dev_name, victim_node,
				     (unsigned long long)victim_key);
			out->kind = MXFS_FENCE_KIND_ERROR;
			out->rc = -ETIMEDOUT;
			return -ETIMEDOUT;
		}
	}
	if (ret == -EBUSY) {
		/* Another initiator preempted the key between our READ KEYS and
		 * our PROUT.  We performed nothing. */
		mxfs_pal_log(MXFS_LOG_INFO,
			     "scsipr: P-PR-FENCE-RACE lost the preempt-abort race "
			     "for node %u (key 0x%llx) on '%s' — exclusion NOT "
			     "proved here",
			     victim_node, (unsigned long long)victim_key,
			     ctx->dev_name);
		out->kind = MXFS_FENCE_KIND_RACE_LOST;
		return 0;
	}
	if (ret) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}

	/*
	 * VERIFY the post-state.  SPC says PREEMPT AND ABORT does not complete
	 * until the victim's task set is aborted, so a successful return is the
	 * abort evidence — but the registration removal still has to be
	 * confirmed against the table, because that is what keeps the victim
	 * excluded from here on.  design review (item 6): "verify after completion
	 * that no descriptor with that key remains."
	 */
	count = 0;
	ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
				     &own_present, &count, &gen);
	if (ret == -EOVERFLOW) {
		/* The preempt-abort completed, but we cannot confirm the victim
		 * holds no surviving descriptor — which is the half of the claim
		 * that keeps it excluded from here on.  Do not upgrade an
		 * unverifiable post-state into proved exclusion. */
		out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
		out->rc = ret;
		return 0;
	}
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-FENCE-VERIFY read_keys failed on '%s': %d "
			     "— the preempt-abort completed but its result is "
			     "unverified; NOT claiming exclusion",
			     ctx->dev_name, ret);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	out->pr_generation = gen;

	if (victim_present || !own_present) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-FENCE-VERIFY '%s' post-state wrong after "
			     "preempt-abort of node %u: victim_present=%d "
			     "own_present=%d keys=%d gen=%u — NOT claiming exclusion",
			     ctx->dev_name, victim_node, victim_present, own_present,
			     count, gen);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -EPROTO;
		return -EPROTO;
	}

	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P-PR-FENCE preempt-and-aborted dead node %u "
		     "(key 0x%llx) on '%s' — task set aborted, registration "
		     "removed, %s reservation held, gen=%u: EXCLUSION PROVED",
		     victim_node, (unsigned long long)victim_key,
		     ctx->dev_name, mxfs_pr_type_name(resv.type), gen);
	out->kind = MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1;
	out->phase = MXFS_FENCE_PHASE_VERIFIED;
	/*
	 * This is the one path in this file that carries its own retirement
	 * evidence rather than a deployment's assertion: the victim's
	 * registration was in the table at the classifying read, our PREEMPT AND
	 * ABORT NAMED it, and that command's defined completion aborts the task
	 * sets of the registrations it removes.  The claim is worded as exactly
	 * that and no more — "the command named the victim's registration" — so a
	 * reader is never told that the target reported which registrations its
	 * scope selection actually covered.  It does not.
	 *
	 * The registration can still disappear between the classifying read and
	 * the target's scope selection, and what happens then is MEASURED rather
	 * than assumed (tests/pr_absent_sark_probe.sh, lap s89a,
	 * tests/evidence/20260920T192919Z_prabs_s89a): on this LUN a PREEMPT AND
	 * ABORT whose SARK names a registration that is not in the table is
	 * terminated with RESERVATION CONFLICT and the PR generation does not
	 * move — measured twice, for a key that was never registered and for one
	 * that was registered and removed, against a control arm in the same lap
	 * that was ACCEPTED with the key present and advanced the generation.  So
	 * the raced execution and the covering one are distinguished by the
	 * target's own status: the conflict arrives here as -EBUSY from
	 * scsipr_preempt_locked and becomes MXFS_FENCE_KIND_RACE_LOST above,
	 * which carries no claim at all.  This block is reached only on the
	 * accepted execution.  That is a qualified observation of this target,
	 * firmware and session topology (data/rigs.json), never a promise about
	 * an arbitrary SPC target.
	 */
	out->retire_obs = MXFS_RETIRE_OBS_REGISTRATION_PRESENT;
	out->retire_basis = MXFS_RETIRE_BASIS_TARGET_OP;
	out->retire_claim = MXFS_RETIRE_CLAIM_PREEMPT_ABORT_NAMED_VICTIM;
	return 0;
}

/*
 * ── IS THE EXCLUSION STILL TRUE? ─────────────────────────────────
 *
 * mxfs_scsipr_fence_node() proves exclusion AT AN INSTANT.  MEASURED on the rig
 * (tests/pr_reregister_probe.sh), that instant is all it proves: a node whose
 * key was PREEMPT-AND-ABORTed re-registered with a fresh key and wrote to the
 * shared LUN seconds later — step 3 of the probe was REFUSED (exclusion real),
 * step 4b was ACCEPTED (exclusion expired).  The certificate authorises roughly
 * eight seconds of in-place foreign log replay over shared XFS metadata, and
 * for that whole window MXFS's only defence is the victim's own cooperative
 * self-fence — which assumes the victim is healthy enough to schedule, the
 * exact assumption a fence exists to drop (D-FENCED-VICTIM-MAY-REREGISTER).
 *
 * This is the RE-CHECK: does the exclusion hold RIGHT NOW?  It is deliberately
 * a DETECTOR, not a preventer — a write can still race between this call and
 * the operation it guards.  What it buys is that a victim which came back stays
 * caught instead of silently sharing the metadata with its own replayer, and
 * that the recovery stops rather than publishing over it.  design review (design-consult ruling
 * requirement C): "reservation-health failure should stop further
 * destructive recovery."
 *
 * Both halves are required and neither is sufficient:
 *   - the WE-RO reservation must STILL be held and STILL be WE-RO, or removing
 *     a registration excludes nobody; and
 *   - the victim's key must STILL be absent from a COMPLETE key view, because
 *     a truncated view cannot establish absence at all.
 *
 * Returns 0 when the exclusion still holds.  On refusal, *out (optional)
 * carries the kind that explains why, using the same vocabulary as the fence.
 */
int mxfs_scsipr_validate_admission(struct mxfs_scsipr_ctx *ctx)
{
	struct mxfs_pal_pr_caps caps;
	struct mxfs_pal_pr_reservation resv;
	bool self_present = false, dummy = false;
	uint32_t gen = 0;
	int count = 0, ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	if (!ctx->local_key) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-UNREGISTERED '%s' — this mount "
			     "holds no PR key, so it can neither be fenced nor fence "
			     "anyone; it must not be admitted read-write",
			     ctx->dev_name);
		return -EPERM;
	}
	/* (0.60.0, review-#3 condition 6): a nonzero key is not enough —
	 * the REGISTER must have been issued and verified by READ KEYS on this
	 * nexus (mxfs_scsipr_register's -EOPNOTSUPP arm returns 0 without it). */
	if (!ctx->registered) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-UNREGISTERED '%s' key=0x%llx — the "
			     "key was never REGISTERED and verified on this nexus "
			     "(no PR support, or the register was skipped); a "
			     "clustered mount cannot be admitted read-write on it",
			     ctx->dev_name, (unsigned long long)ctx->local_key);
		return -EPERM;
	}

	/* 1. What the target says it can do — one command, never issued before
	 * .  Capability, persistence state and the supported reservation
	 *    types all come back together. */
	ret = mxfs_pal_scsi_pr_report_capabilities(ctx->dev, &caps);
	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-NOCAPS '%s' — the target does not "
			     "answer PERSISTENT RESERVE IN / REPORT CAPABILITIES, so "
			     "this mount cannot establish that fencing works before it "
			     "needs it",
			     ctx->dev_name);
		return ret;
	}
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-ERROR '%s' rc=%d — REPORT "
			     "CAPABILITIES failed; fencing capability is UNKNOWN",
			     ctx->dev_name, ret);
		return ret;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P303-FENCECAP '%s' ptpl_c=%d ptpl_a=%d crh=%d "
		     "sip_c=%d atp_c=%d tmv=%d type_mask=0x%04x we_ro=%d we_ar=%d "
		     "abort_capable=%d",
		     ctx->dev_name, (int)caps.ptpl_c, (int)caps.ptpl_a,
		     (int)caps.crh, (int)caps.sip_c, (int)caps.atp_c,
		     (int)caps.tmv, (unsigned)caps.type_mask, (int)caps.we_ro,
		     (int)caps.we_ar, (int)caps.abort_capable);

	if (!caps.abort_capable) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-NOABORT '%s' — no underlying SCSI "
			     "device can be reached, so PREEMPT AND ABORT cannot be "
			     "issued and a fence could never abort a victim's "
			     "in-flight writes.  This is the exact condition that went "
			     "undetected for months (dm drops the abort flag)",
			     ctx->dev_name);
		return -EPERM;
	}
	if (!caps.tmv || !caps.we_ar) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-NOWEAR '%s' tmv=%d mask=0x%04x "
			     "we_ro=%d we_ar=%d — the target does not offer WRITE "
			     "EXCLUSIVE - ALL REGISTRANTS (type 0x07), the reservation "
			     "type every MXFS exclusion proof is written against from "
			     "protocol generation 5 on.  The single-holder type this "
			     "build no longer uses loses the reservation on the "
			     "holder's clean unmount and disarms fencing for the whole "
			     "cluster",
			     ctx->dev_name, (int)caps.tmv, (unsigned)caps.type_mask,
			     (int)caps.we_ro, (int)caps.we_ar);
		return -EPERM;
	}
	if (!caps.ptpl_a) {
		/* APTPL is set by the REGISTER; this is the target CONFIRMING it is
		 * actually active.  Without it the whole cross-boot recovery story
		 * changes silently (see D-PR-REGISTRATION-NOT-PERSISTENT-APTPL). */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-NOPERSIST '%s' ptpl_c=%d ptpl_a=0 "
			     "— PR state is NOT persisting through power loss, so "
			     "registrations do not survive a target restart and "
			     "cross-boot exclusion cannot be relied on",
			     ctx->dev_name, (int)caps.ptpl_c);
		return -EPERM;
	}

	/* 2. The reservation MXFS establishes must actually be HELD.  With no
	 *    reservation, an unregistered initiator writes freely and key absence
	 *    proves nothing.
	 *
	 *    this check is only worth anything because the caller now
	 *    OBSERVES the reservation before it registers or reserves (see
	 *    mxfs_scsipr_observe_reservation()).  Run after our own RESERVE, as
	 *    it must be, this asserts a postcondition — that we are covered — and
	 *    the P304-PREOBSERVE line above it is what says whether the cluster
	 *    was already armed or whether this mount armed it. */
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret && ret != -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-RESVERR '%s' rc=%d", ctx->dev_name,
			     ret);
		return ret;
	}
	if (ret == -EOPNOTSUPP || !resv.held) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-NORESV '%s' held=%d — no "
			     "reservation is in force, so nothing is excluded from "
			     "this LU and a fence would prove nothing",
			     ctx->dev_name,
			     (ret == -EOPNOTSUPP) ? -1 : (int)resv.held);
		return -EPERM;
	}
	if (resv.type != MXFS_SCSIPR_RESV_TYPE) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-WRONGTYPE '%s' type=0x%x (%s), "
			     "want 0x%x (%s) — a reservation IS in force and it does "
			     "exclude non-registrants, but it is not the type this "
			     "protocol generation requires.  A single-holder "
			     "reservation is released by its holder's clean unmount, "
			     "which disarms fencing cluster-wide, so this mount must "
			     "not join under one.  Most likely a stale reservation "
			     "left by a crashed node running an older protocol "
			     "generation: bring every node down, clear it, and remount",
			     ctx->dev_name, resv.type, mxfs_pr_type_name(resv.type),
			     MXFS_SCSIPR_RESV_TYPE,
			     mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE));
		return -EPERM;
	}
	ctx->resv_type_seen = resv.type;

	/* 3. Our own key must be visible in a COMPLETE view.  A truncated view can
	 *    never prove absence, so an exclusion proof read out of one is void. */
	ret = mxfs_scsipr_probe_keys(ctx, ctx->local_key, &self_present, &dummy,
				     &count, &gen);
	if (ret == -EOVERFLOW) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-TRUNCATED '%s' — the target holds "
			     "more registrants than this build can read back, so no "
			     "future exclusion proof on this mount could be sound",
			     ctx->dev_name);
		return -EPERM;
	}
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-KEYSERR '%s' rc=%d", ctx->dev_name,
			     ret);
		return ret;
	}
	if (!self_present) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P303-FENCECAP-SELFABSENT '%s' key=0x%llx "
			     "registrants=%d gen=%u — this mount's own key is not in "
			     "the target's registration table, so it is already "
			     "excluded from the LU it is about to join",
			     ctx->dev_name, (unsigned long long)ctx->local_key,
			     count, gen);
		return -EPERM;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P303-FENCECAP-OK '%s' registrants=%d gen=%u "
		     "resv=%s — fencing capability validated at admission: "
		     "all-registrants reservation held (it survives any single "
		     "node's departure), persistence active, key view complete, "
		     "own key present, PREEMPT AND ABORT issuable",
		     ctx->dev_name, count, gen,
		     mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE));
	return 0;
}

/*
 * 0.89.16 — THE DEPLOYMENT'S RETIREMENT QUALIFICATION IS WITHDRAWN.
 *
 * Until this build a deployment could assert, per LUN, that a registration
 * which disappears with no replacement of ours does so only after the commands
 * the target accepted on that registration's nexus have completed or aborted
 * with their effects ordered.  Matching the assertion authorised replaying a
 * dead incarnation's journal slice.
 *
 * It was never a witness.  Its whole support was four probe laps against one
 * appliance that saw no late write inside a 180 s window sampled at 50 ms.
 * That characterises a target under one workload and one observation interval;
 * it cannot exclude a command the target retained without it ever becoming
 * observable, and nothing in this module can detect a target that breaks the
 * assertion.  A replay authorised against a write the target had not finished
 * lands as an unordered logical write into metadata the replay is rewriting —
 * silent corruption, where a refusal only costs availability.  So the
 * assertion is withdrawn IN CODE rather than in configuration: no contract
 * value, no elapsed interval, no retry and no operator override re-enables it.
 *
 * What remains is the strong basis and nothing else: a completed target
 * operation whose own abort scope covered the victim's tasks — today a PREEMPT
 * AND ABORT that named a registration still present on the target.  Retiring
 * the tasks of a registration that is ALREADY GONE takes a task-management
 * function (LOGICAL UNIT RESET) carrying a matched target response, and this
 * module has no path to issue one: every command it sends goes out as an
 * ordinary CDB, and a task-management function is not a CDB.  Until that path
 * exists the absent-registration case is refused.  The routes and what each
 * would have to establish are recorded in
 * docs/rulings/retirement-witness-routes-lu-reset-early-preempt-or-refuse.md.
 *
 * The deployment parameter is still READ, so a deployment that configured a
 * contract is TOLD its qualification is rejected instead of being left to
 * infer it from a refusal that never mentions it.
 */
bool mxfs_fence_durable_kind_supported(enum mxfs_fence_record_family family,
				       uint16_t kind, const char **why)
{
	const char *reason;

	switch ((enum mxfs_fence_kind)kind) {
	case MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1:
		/* The one supported profile: a PREEMPT AND ABORT that named a
		 * registration present in the target's table, completed, and had its
		 * post-state verified.  Only the completed-operation path can produce
		 * it, in either record family. */
		return true;
	case MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1:
		/* 0.89.33.  The other supported profile, and the only one that
		 * reaches a victim whose registration the target has already purged:
		 * one LOGICAL UNIT RESET, issued by this initiator as the sole
		 * registrant on the unit under an excluding reservation, witnessed by
		 * the target's own task-management response on an unmoved transport
		 * incarnation and on a kernel release the witness was audited on, with
		 * the post-reset barrier held afterwards.  It has exactly ONE producer
		 * — mxfs_scsipr_fence_by_lu_reset() — which is what kind 16 never had,
		 * so a durable 24 can be classified without knowing which path wrote
		 * it, in either record family. */
		return true;
	case MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE:
		reason = "REVOKED kind 17: the operator's single-node assertion is "
			 "about ADMISSION — no second INITIATOR can hold writes — and "
			 "it says nothing about the writes the target had already "
			 "accepted from the previous incarnation, which is the victim "
			 "here.  An operator parameter may select an operating mode; "
			 "it cannot create a retirement witness, and this was the last "
			 "kind allowed to certify replay without one";
		break;
	case MXFS_FENCE_KIND_PREEMPT_ABORT_DONE:
		reason = "RETIRED code point 16: it had two producers and only one of "
			 "them ran an operation — the bootstrap-owner takeover stamped "
			 "the same value on an outcome derived from PR-ledger state — "
			 "so a durable 16 cannot be classified into a proof contract.  "
			 "Re-establish the fact and issue a certificate of the current "
			 "profile; it cannot be relabelled";
		break;
	case MXFS_FENCE_KIND_SELF_SUCCESSION_DONE:
		reason = "REVOKED kind 19: it rested on 'the old task set died with "
			 "the old session', and a REGISTER AND IGNORE that replaces a "
			 "key on the SAME nexus forces no session outcome at all, so "
			 "the old nexus may still be live with its earlier tasks "
			 "active.  Nothing here needs each instance shown unsound — a "
			 "supported, sound interpretation is what is missing";
		break;
	case MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE:
	case MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT:
		reason = "REVOKED absent-registration kind: reachable only from the "
			 "victim's registration already being gone, which leaves "
			 "nothing for a PREEMPT AND ABORT to name, so it can only ever "
			 "have rested on the deployment retirement clause this build "
			 "withdrew";
		break;
	default:
		reason = "the record carries no fence kind this build can classify "
			 "into a supported proof contract";
		break;
	}
	if (why)
		*why = reason;
	return false;
}

enum mxfs_retire_basis
mxfs_scsipr_retire_proof(struct mxfs_scsipr_ctx *ctx,
			 const char *contract,
			 enum mxfs_retire_observation obs,
			 enum mxfs_retire_claim *claim_out,
			 char *why, size_t whysz)
{
	(void)ctx;

	if (claim_out)
		*claim_out = MXFS_RETIRE_CLAIM_NONE;
	if (why && whysz) {
		/*
		 * Lead with the finding.  This buffer is short enough that a reason
		 * assembled the other way round loses the verdict to truncation, and
		 * the configured contract goes LAST for the same reason.
		 */
		if (contract && contract[0])
			snprintf(why, whysz,
				 "WITHDRAWN: a deployment clause is configured and "
				 "REJECTED; only a completed target operation that aborted "
				 "the victim's tasks is a basis.  obs=%s",
				 mxfs_retire_observation_name((uint8_t)obs));
		else
			snprintf(why, whysz,
				 "UNAVAILABLE: no completed target operation aborted the "
				 "victim's tasks, and no clause, interval or retry can "
				 "supply that fact.  obs=%s",
				 mxfs_retire_observation_name((uint8_t)obs));
	}
	/*
	 * The configured contract gets its OWN line.  Carrying it inside `why`
	 * would push it past the caller's buffer and it would be the part that
	 * truncated away — so the deployment would never be told which value was
	 * rejected, which is the one thing this branch exists to say.
	 */
	if (contract && contract[0])
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P303-RETIRE-CONTRACT-REJECTED '%s' — this build "
			     "accepts no deployment clause as a retirement basis, so "
			     "this value qualifies nothing and changes no outcome.  "
			     "Retirement is established by a completed target "
			     "operation that aborted the victim's tasks, and by "
			     "nothing else",
			     contract);
	return MXFS_RETIRE_BASIS_NONE;
}

int mxfs_scsipr_exclusion_holds(struct mxfs_scsipr_ctx *ctx,
				uint64_t victim_key,
				struct mxfs_fence_result *out)
{
	struct mxfs_pal_pr_reservation resv;
	struct mxfs_fence_result local;
	bool victim_present = false, own_present = false;
	uint32_t gen = 0;
	int count = 0, ret;

	if (!out)
		out = &local;
	memset(out, 0, sizeof(*out));
	out->kind = MXFS_FENCE_KIND_NONE;
	out->victim_key = victim_key;
	/*
	 * PRECOMMAND until the exact line that submits.  Everything from
	 * here to the arm_submit() call below is pure observation — READ KEYS,
	 * READ RESERVATION, classification — so every return in between is
	 * "nothing was submitted, nothing was consumed, this is safe to repeat".
	 * That is the property D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381
	 * exists because nobody recorded.
	 */
	out->phase = MXFS_FENCE_PHASE_PRECOMMAND;

	if (!ctx || !ctx->dev || !victim_key)
		return -EINVAL;
	if (!ctx->local_key) {
		out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
		return -EPERM;
	}

	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret && ret != -EOPNOTSUPP) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	/*
	 * 0.85.1: the sole-survivor gate — Write Exclusive (1) held by OUR key —
	 * excludes every other nexus, registrant or not, so a certificate issued
	 * under an all-registrants form still holds under it (a fortiori).
	 * Measured s614a (tests/evidence/20260913T040607Z_intents2tcp_s614a,
	 * dmesg_test1_remount.txt): the successor re-proved the gate for the
	 * taken-over case first, then its own predecessor's BOOT_SUCCESSION_ABSENT
	 * recheck read 'held=1 type=0x1 (WE)' 65 times as NORESV and the mount
	 * barrier expired.  A type-1 reservation held by ANOTHER key is still a
	 * lapse here: we could not write under it either.
	 */
	if (ret == -EOPNOTSUPP || !resv.held ||
	    (!mxfs_pr_type_excludes_nonregistrants(resv.type) &&
	     !scsipr_gate_resv_is_ours(ctx, &resv))) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P239-EXCL-NORESV '%s' held=%d type=0x%x (%s) — "
			     "the reservation the certificate was issued under is no "
			     "longer in force; nothing is excluded from this LU any "
			     "more",
			     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
			     (ret == -EOPNOTSUPP) ? 0 : resv.type,
			     (ret == -EOPNOTSUPP) ? "unreadable"
						  : mxfs_pr_type_name(resv.type));
		out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
		return -EPERM;
	}
	out->resv_type = resv.type;
	ctx->resv_type_seen = resv.type;

	ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
				     &own_present, &count, &gen);
	if (ret == -EOVERFLOW) {
		/* more descriptors than we can read means absence is not
		 * establishable.  Unknown is refused. */
		out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
		out->rc = ret;
		return -EPERM;
	}
	if (ret) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	out->pr_generation = gen;

	if (!own_present) {
		/* Our own key is gone: WE are the fenced node.  Same verdict the
		 * fence path gives, and it is terminal — the caller must self-fence,
		 * not carry on recovering somebody else. */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P239-EXCL-SELFGONE '%s' our key 0x%llx is absent "
			     "while re-checking victim 0x%llx — we are the fenced node",
			     ctx->dev_name, (unsigned long long)ctx->local_key,
			     (unsigned long long)victim_key);
		out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
		return -ESTALE;
	}
	if (victim_present) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P239-EXCL-RETURNED '%s' victim key 0x%llx is "
			     "REGISTERED AGAIN (gen=%u, %d keys) — the exclusion this "
			     "recovery was authorised by has LAPSED.  The victim can "
			     "write to this LU right now; no further destructive "
			     "recovery step may run",
			     ctx->dev_name, (unsigned long long)victim_key, gen, count);
		out->kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
		return -EPERM;
	}

	out->kind = MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1;
	return 0;
}

/*
 * ── THE SOLE-SURVIVOR EXCLUSIVE-WRITE GATE (D-0904) ─────────────────────
 * Contract in scsipr.h.  Every PROUT here runs under the host-wide departure
 * mutex like every other local PROUT.
 */

/* One complete READ KEYS, classified for the gate: how many registrations
 * carry OUR key, how many carry anything else, whether the victim's is among
 * them.  -EOVERFLOW when the table is larger than we can read. */
static int scsipr_gate_view(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key,
			    uint64_t *keys, int *own_n, int *other_n,
			    bool *victim_present, uint32_t *gen)
{
	int n = 0, total = 0, i, ret;

	*own_n = 0;
	*other_n = 0;
	*victim_present = false;
	ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_PR_MAX_KEYS, &n, gen, &total);
	if (ret)
		return ret;
	if (total > n) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-VIEW-TRUNC '%s' target holds %d "
			     "registration descriptor(s), we could read %d (cap %d) — "
			     "the gate cannot classify a partial table",
			     ctx->dev_name, total, n, MXFS_PR_MAX_KEYS);
		return -EOVERFLOW;
	}
	for (i = 0; i < n; i++) {
		if (keys[i] == ctx->local_key)
			(*own_n)++;
		else
			(*other_n)++;
		if (victim_key && keys[i] == victim_key)
			*victim_present = true;
	}
	return 0;
}

/* Is the reservation the gate installs in force for OUR nexus? */
static bool scsipr_gate_resv_is_ours(const struct mxfs_scsipr_ctx *ctx,
				     const struct mxfs_pal_pr_reservation *r)
{
	return r->held && r->type == MXFS_PAL_PR_TYPE_WR_EX &&
	       r->key == ctx->local_key;
}

int mxfs_scsipr_gate_sole_survivor(struct mxfs_scsipr_ctx *ctx,
				   mxfs_node_id_t victim_node,
				   uint64_t victim_key,
				   int (*arm_submit)(void *), void *arm_data,
				   struct mxfs_fence_result *out)
{
	struct mxfs_pal_pr_reservation resv;
	uint64_t *keys;
	uint32_t gen = 0;
	int own_n = 0, other_n = 0, ret;
	bool victim_present = false;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->kind = MXFS_FENCE_KIND_NONE;
	out->victim_key = victim_key;
	out->phase = MXFS_FENCE_PHASE_PRECOMMAND;
	if (!ctx || !ctx->dev)
		return -EINVAL;
	if (!ctx->local_key || !ctx->registered) {
		out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
		return 0;
	}
	keys = mxfs_pal_alloc(sizeof(*keys) * MXFS_PR_MAX_KEYS);
	if (!keys) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -ENOMEM;
		return -ENOMEM;
	}

	scsipr_dep_enter(ctx, "gate");

	/* ── observation: nothing below this line and above arm_submit changes
	 *    target state ── */
	ret = scsipr_gate_view(ctx, victim_key, keys, &own_n, &other_n,
			       &victim_present, &gen);
	if (ret == -EOPNOTSUPP) {
		out->kind = MXFS_FENCE_KIND_UNSUPPORTED;
		ret = 0;
		goto out;
	}
	if (ret == -EOVERFLOW) {
		out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
		out->rc = ret;
		ret = 0;
		goto out;
	}
	if (ret) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		goto out;
	}
	out->pr_generation = gen;
	if (own_n == 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-SELFGONE '%s' our key 0x%llx is not "
			     "registered (gen=%u, %d other key(s)) — we are the "
			     "excluded node; no gate can be installed",
			     ctx->dev_name, (unsigned long long)ctx->local_key, gen,
			     other_n);
		out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
		ret = -ESTALE;
		goto out;
	}
	if (own_n > 1) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-MULTINEXUS '%s' our key 0x%llx is "
			     "registered on %d nexuses — PREEMPT AND ABORT sark=0 "
			     "would remove our own sibling registrations and make ONE "
			     "path the reservation holder; the gate is refused on a "
			     "multipath nexus set.  NOTHING WAS ISSUED",
			     ctx->dev_name, (unsigned long long)ctx->local_key, own_n);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -ENOTUNIQ;
		ret = 0;
		goto out;
	}
	if (victim_present) {
		/* The victim's registration is back (or was never gone by the time
		 * we looked).  The ordinary key preempt is the fence for that; this
		 * gate is for the key the target already removed. */
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-GATE-VICTIM-PRESENT '%s' victim node %u key "
			     "0x%llx IS registered (gen=%u) — not the absent-key case; "
			     "the key preempt applies.  NOTHING WAS ISSUED",
			     ctx->dev_name, victim_node,
			     (unsigned long long)victim_key, gen);
		out->kind = MXFS_FENCE_KIND_NONE;
		ret = 0;
		goto out;
	}

	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret && ret != -EOPNOTSUPP) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		goto out;
	}
	if (ret == -EOPNOTSUPP || !resv.held) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-NORESV '%s' held=%d — no reservation "
			     "is in force; a sark=0 preempt has nothing to preempt "
			     "and nothing excludes a non-registrant.  NOTHING WAS "
			     "ISSUED; retryable once a reservation is back",
			     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held);
		out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
		ret = 0;
		goto out;
	}
	if (scsipr_gate_resv_is_ours(ctx, &resv) && other_n == 0) {
		/* A previous attempt's PROUT completed and its certificate did not
		 * land (or the retry re-drove a verified gate).  The post-state IS
		 * the proof; verify it again and issue nothing.  arm_submit is
		 * idempotent on an already-armed attempt. */
		if (arm_submit) {
			ret = arm_submit(arm_data);
			if (ret) {
				out->kind = MXFS_FENCE_KIND_ERROR;
				out->rc = ret;
				ret = 0;
				goto out;
			}
		}
		ctx->resv_type_seen = MXFS_PAL_PR_TYPE_WR_EX;
		ctx->reserved = true;
		ctx->gate_held = true;
		out->resv_type = MXFS_PAL_PR_TYPE_WR_EX;
		out->kind = MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE;
		out->phase = MXFS_FENCE_PHASE_VERIFIED;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-GATE-ALREADY '%s' victim node %u key "
			     "0x%llx — Write Exclusive (1) is already held by our key "
			     "0x%llx with no other registrant (gen=%u): the gate is "
			     "in force from an earlier attempt; EXCLUSION PROVED, "
			     "nothing issued",
			     ctx->dev_name, victim_node,
			     (unsigned long long)victim_key,
			     (unsigned long long)ctx->local_key, gen);
		ret = 0;
		goto out;
	}
	if (resv.type != MXFS_PAL_PR_TYPE_WR_EX_AR) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-WRONGTYPE '%s' held type=0x%x (%s) "
			     "holder=0x%llx — the gate preempts the ALL-REGISTRANTS "
			     "reservation this build establishes (0x%x); a "
			     "different type or holder is in force.  NOTHING WAS "
			     "ISSUED",
			     ctx->dev_name, resv.type, mxfs_pr_type_name(resv.type),
			     (unsigned long long)resv.key, MXFS_PAL_PR_TYPE_WR_EX_AR);
		out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
		out->resv_type = resv.type;
		ret = 0;
		goto out;
	}
	out->resv_type = resv.type;

	/*
	 * 0.75.83 (D-...-0936, measured s570b on 0.75.80,
	 * tests/evidence/20260909T152143Z_ghost_s570b): THE REGISTRANT SET IS THE
	 * LIVENESS SIGNAL, because it is the set this command is about to evict.
	 *
	 * Every refusal above asks about us or about the victim; none asks whether
	 * anyone ELSE is registered.  The premise this fence kind rests on — "the
	 * prover is the only live member" — was checked one layer up, from lease
	 * membership and the heartbeat table, and a joiner reaches neither of those
	 * until after it has registered its PR key.  Measured: test2 proved sole
	 * survivorship at PR generation 1817 with one registrant; test1 registered
	 * at 1818 ('P-PRKEY-REGISTERED keys=2 gen=1818'), claimed heartbeat slot 1,
	 * was admitted and began log recovery; test2's PROUT landed at 1819 and
	 * removed test1's registration and aborted its task set.  test1's very next
	 * write failed — 'log recovery write I/O error at daddr 0x975 len 4096
	 * error -52' — and its mount died at 1450 ms with 'failed to locate log
	 * tail'.  The same hole would evict a healthy peer on any cluster wider
	 * than two, where the caller's membership count can be stale for entirely
	 * ordinary reasons.
	 *
	 * A refusal here is not a dead end: the attempt stays KEY_ABSENT_UNPROVEN
	 * and retryable, and a victim that is a previous boot of a host that is
	 * live again is provable without touching anyone's registration at all
	 * (fence kind 21, BOOT_SUCCESSION_ABSENT).  The two-node whole-cluster
	 * restart takes that route.  Refusing costs a retry; not refusing costs a
	 * live node its I/O.
	 *
	 * The rest of the function already treats other_n == 0 as the shape: the
	 * already-installed branch above requires it, and the post-state
	 * verification below refuses the certificate without it.
	 */
	if (other_n > 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-NOTSOLE '%s' victim node %u key 0x%llx "
			     "— %d other registrant(s) at gen=%u; a sark=0 PREEMPT AND "
			     "ABORT would remove their registrations and abort their "
			     "task sets, and a nexus that is registered can be a live "
			     "node this cluster has not seen join yet.  NOTHING WAS "
			     "ISSUED; the attempt stays unproven and retryable",
			     ctx->dev_name, victim_node, (unsigned long long)victim_key,
			     other_n, gen);
		out->kind = MXFS_FENCE_KIND_NONE;
		ret = 0;
		goto out;
	}

	/* ── THE COMMAND-SUBMISSION BOUNDARY ── */
	if (arm_submit) {
		ret = arm_submit(arm_data);
		if (ret) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P-PR-GATE-NOARM '%s' victim node %u rc=%d — "
				     "the command-submission boundary could not be made "
				     "durable, so NO PREEMPT AND ABORT was issued.  "
				     "Nothing was consumed; still retryable",
				     ctx->dev_name, victim_node, ret);
			out->kind = MXFS_FENCE_KIND_ERROR;
			out->rc = ret;
			ret = 0;
			goto out;
		}
	}
	out->phase = MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED;

	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P-PR-GATE-ISSUE '%s' victim node %u key 0x%llx "
		     "absent, %d other registrant(s), WE-AR held (gen=%u) — sole "
		     "survivor issuing PREEMPT AND ABORT rk=0x%llx sark=0 "
		     "type=WRITE EXCLUSIVE(1)",
		     ctx->dev_name, victim_node, (unsigned long long)victim_key,
		     other_n, gen, (unsigned long long)ctx->local_key);
	ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, 0, true,
				       MXFS_PAL_PR_TYPE_WR_EX);
	mxfs_scsipr_snap_invalidate(ctx, "gate");
	if (ret == -EBUSY) {
		/* RESERVATION CONFLICT: our key is not a registrant any more, or
		 * the reservation changed under us.  The command performed nothing. */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-CONFLICT '%s' — the sark=0 preempt "
			     "hit RESERVATION CONFLICT; nothing was performed and "
			     "exclusion is NOT proved",
			     ctx->dev_name);
		out->kind = MXFS_FENCE_KIND_RACE_LOST;
		ret = 0;
		goto out;
	}
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-FAIL '%s' rc=%d — the sark=0 PREEMPT "
			     "AND ABORT did not complete; exclusion is NOT proved",
			     ctx->dev_name, ret);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		goto out;
	}

	/* ── VERIFY the post-state: our key alone, type 1 held by it ── */
	ret = scsipr_gate_view(ctx, victim_key, keys, &own_n, &other_n,
			       &victim_present, &gen);
	if (ret == 0)
		ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-VERIFY '%s' rc=%d — the preempt "
			     "completed but its result is unverified; NOT claiming "
			     "exclusion",
			     ctx->dev_name, ret);
		out->kind = ret == -EOVERFLOW ? MXFS_FENCE_KIND_VIEW_TRUNCATED
					      : MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		ret = ret == -EOVERFLOW ? 0 : ret;
		goto out;
	}
	out->pr_generation = gen;
	if (own_n != 1 || other_n != 0 || !scsipr_gate_resv_is_ours(ctx, &resv)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-VERIFY '%s' post-state wrong: own=%d "
			     "other=%d held=%d type=0x%x (%s) holder=0x%llx gen=%u — "
			     "NOT claiming exclusion",
			     ctx->dev_name, own_n, other_n, (int)resv.held, resv.type,
			     mxfs_pr_type_name(resv.type),
			     (unsigned long long)resv.key, gen);
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = -EPROTO;
		ret = -EPROTO;
		goto out;
	}

	ctx->resv_type_seen = MXFS_PAL_PR_TYPE_WR_EX;
	ctx->reserved = true;
	ctx->gate_held = true;
	out->resv_type = MXFS_PAL_PR_TYPE_WR_EX;
	out->kind = MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE;
	out->phase = MXFS_FENCE_PHASE_VERIFIED;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P-PR-GATE '%s' victim node %u (key 0x%llx, already "
		     "purged by the target) — Write Exclusive (1) installed for "
		     "our key 0x%llx, every other registration removed and its "
		     "task set aborted, gen=%u: EXCLUSION PROVED.  No other nexus "
		     "can write until the recovery publishes and WE-AR is "
		     "restored",
		     ctx->dev_name, victim_node, (unsigned long long)victim_key,
		     (unsigned long long)ctx->local_key, gen);
	ret = 0;
out:
	mxfs_scsipr_departure_unlock();
	mxfs_pal_free(keys);
	return ret;
}

bool mxfs_scsipr_gate_is_held(struct mxfs_scsipr_ctx *ctx)
{
	return ctx && ctx->gate_held;
}

int mxfs_scsipr_gate_holds(struct mxfs_scsipr_ctx *ctx,
			   struct mxfs_fence_result *out)
{
	struct mxfs_pal_pr_reservation resv;
	struct mxfs_fence_result local;
	bool own_present = false, dummy = false;
	uint32_t gen = 0;
	int count = 0, ret;

	if (!out)
		out = &local;
	memset(out, 0, sizeof(*out));
	out->kind = MXFS_FENCE_KIND_NONE;
	if (!ctx || !ctx->dev || !ctx->local_key)
		return -EINVAL;

	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	if (!scsipr_gate_resv_is_ours(ctx, &resv)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P239-GATE-LAPSED '%s' held=%d type=0x%x (%s) "
			     "holder=0x%llx own=0x%llx — the Write Exclusive (1) "
			     "reservation this recovery was authorised by is no "
			     "longer held by our key; nothing excludes another "
			     "initiator any more",
			     ctx->dev_name, (int)resv.held, resv.type,
			     mxfs_pr_type_name(resv.type),
			     (unsigned long long)resv.key,
			     (unsigned long long)ctx->local_key);
		out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
		out->resv_type = resv.type;
		return -EPERM;
	}
	out->resv_type = resv.type;
	ret = mxfs_scsipr_probe_keys(ctx, 0, &dummy, &own_present, &count, &gen);
	if (ret == -EOVERFLOW) {
		out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
		out->rc = ret;
		return -EPERM;
	}
	if (ret) {
		out->kind = MXFS_FENCE_KIND_ERROR;
		out->rc = ret;
		return ret;
	}
	out->pr_generation = gen;
	if (!own_present) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P239-GATE-SELFGONE '%s' our key 0x%llx is absent "
			     "while the gate is held — we are the fenced node",
			     ctx->dev_name, (unsigned long long)ctx->local_key);
		out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
		return -ESTALE;
	}
	out->kind = MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE;
	return 0;
}

int mxfs_scsipr_gate_restore(struct mxfs_scsipr_ctx *ctx)
{
	struct mxfs_pal_pr_reservation resv;
	uint64_t *keys;
	uint32_t gen = 0;
	int own_n = 0, other_n = 0, ret;
	bool dummy = false;

	if (!ctx || !ctx->dev || !ctx->local_key)
		return -EINVAL;
	keys = mxfs_pal_alloc(sizeof(*keys) * MXFS_PR_MAX_KEYS);
	if (!keys)
		return -ENOMEM;

	scsipr_dep_enter(ctx, "gate-restore");
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret)
		goto out;
	if (resv.held && resv.type == MXFS_PAL_PR_TYPE_WR_EX_AR) {
		ctx->resv_type_seen = resv.type;
		ctx->gate_held = false;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-GATE-RESTORED '%s' — WE-AR already in force "
			     "(gen=%u); gate cleared, nothing issued",
			     ctx->dev_name, resv.generation);
		ret = 0;
		goto out;
	}
	ret = scsipr_gate_view(ctx, 0, keys, &own_n, &other_n, &dummy, &gen);
	if (ret)
		goto out;
	if (own_n == 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-RESTORE-SELFGONE '%s' our key 0x%llx "
			     "is not registered — cannot convert a reservation we do "
			     "not hold",
			     ctx->dev_name, (unsigned long long)ctx->local_key);
		ret = -ESTALE;
		goto out;
	}
	if (own_n > 1) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-RESTORE-MULTINEXUS '%s' our key is on "
			     "%d nexuses — a self-preempt would remove the siblings; "
			     "gate left in force",
			     ctx->dev_name, own_n);
		ret = -ENOTUNIQ;
		goto out;
	}
	if (!resv.held) {
		/* Nothing held (our registration was removed and re-added, or the
		 * target dropped it): plain RESERVE of the type this build fences
		 * under, exactly what admission does. */
		ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
					       MXFS_PAL_PR_TYPE_WR_EX_AR);
		mxfs_scsipr_snap_invalidate(ctx, "gate-restore-reserve");
		if (ret && ret != -EBUSY)
			goto out;
	} else if (scsipr_gate_resv_is_ours(ctx, &resv)) {
		/* PREEMPT rk=own sark=own type=7: SPC-4 5.9.10.4.3 — the issuing
		 * nexus keeps its registration, the reservation is released and a
		 * WE-AR one established for it in ONE command (measured on the
		 * QNAP: no unreserved gap).  The plain form is enough: there are
		 * no foreign task sets to abort, and the abort form is refused for
		 * a non-zero SARK with our own key by the PAL contract. */
		ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key,
					       ctx->local_key, false,
					       MXFS_PAL_PR_TYPE_WR_EX_AR);
		mxfs_scsipr_snap_invalidate(ctx, "gate-restore-preempt");
		if (ret && ret != -EBUSY)
			goto out;
	} else {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-RESTORE-FOREIGN '%s' held type=0x%x "
			     "(%s) holder=0x%llx — a reservation we did not install "
			     "is in force; not touching it",
			     ctx->dev_name, resv.type, mxfs_pr_type_name(resv.type),
			     (unsigned long long)resv.key);
		ret = -EPERM;
		goto out;
	}
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret)
		goto out;
	if (!resv.held || resv.type != MXFS_PAL_PR_TYPE_WR_EX_AR) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-GATE-RESTORE-VERIFY '%s' held=%d type=0x%x "
			     "(%s) — WE-AR is NOT in force after the conversion; gate "
			     "state kept, retry",
			     ctx->dev_name, (int)resv.held, resv.type,
			     mxfs_pr_type_name(resv.type));
		ret = -EPROTO;
		goto out;
	}
	ctx->resv_type_seen = resv.type;
	ctx->reserved = true;
	ctx->gate_held = false;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P-PR-GATE-RESTORED '%s' — Write Exclusive - All "
		     "Registrants restored for key 0x%llx (gen=%u); joiners and a "
		     "re-registered peer can write again",
		     ctx->dev_name, (unsigned long long)ctx->local_key,
		     resv.generation);
	ret = 0;
out:
	mxfs_scsipr_departure_unlock();
	mxfs_pal_free(keys);
	return ret;
}

/*
 * ── THE SOLE-INITIATOR ADMISSION GATE FOR A LOGICAL UNIT RESET ──────────
 * Contract, and what it deliberately does not prove, in scsipr.h.
 */

const char *mxfs_lu_reset_refusal_name(int r)
{
	switch (r) {
	case MXFS_LURESET_ADMIT_OK:
		return "admitted";
	case MXFS_LURESET_REFUSE_NOT_REGISTERED:
		return "this-mount-holds-no-key";
	case MXFS_LURESET_REFUSE_NO_RESERVATION:
		return "no-reservation-in-force";
	case MXFS_LURESET_REFUSE_RESV_TYPE:
		return "reservation-type-does-not-exclude-nonregistrants";
	case MXFS_LURESET_REFUSE_VIEW_TRUNCATED:
		return "registration-table-truncated";
	case MXFS_LURESET_REFUSE_SELF_GONE:
		return "our-own-key-is-not-registered";
	case MXFS_LURESET_REFUSE_MULTI_NEXUS:
		return "our-key-is-registered-on-more-than-one-nexus";
	case MXFS_LURESET_REFUSE_OTHER_REGISTRANT:
		return "another-initiator-is-registered";
	case MXFS_LURESET_REFUSE_VICTIM_REGISTERED:
		return "victim-is-registered-preempt-and-abort-applies";
	case MXFS_LURESET_REFUSE_NOT_A_REGISTRANT:
		return "reserve-conflicted-this-nexus-does-not-carry-our-key";
	case MXFS_LURESET_REFUSE_RACED:
		return "the-census-moved-under-the-gate";
	case MXFS_LURESET_REFUSE_IO:
		return "the-target-could-not-be-asked";
	default:
		return "?";
	}
}

int mxfs_scsipr_lu_reset_admit(struct mxfs_scsipr_ctx *ctx,
			       mxfs_node_id_t victim_node,
			       uint64_t victim_key,
			       struct mxfs_lu_reset_admission *out)
{
	struct mxfs_pal_pr_reservation resv;
	uint64_t *keys;
	uint32_t gen_b = 0;
	int own_b = 0, other_b = 0;
	bool victim_b = false;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->victim_key = victim_key;
	out->refusal = MXFS_LURESET_REFUSE_IO;
	if (!ctx || !ctx->dev)
		return -EINVAL;

	if (!ctx->local_key || !ctx->registered) {
		out->refusal = MXFS_LURESET_REFUSE_NOT_REGISTERED;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P306-LURESET-ADMIT '%s' admitted=0 "
			     "reason=%s victim_node=%u — an initiator that holds no "
			     "registration cannot show that it is the only one; "
			     "NOTHING WILL BE ISSUED",
			     ctx->dev_name,
			     mxfs_lu_reset_refusal_name(out->refusal), victim_node);
		return 0;
	}

	keys = mxfs_pal_alloc(sizeof(*keys) * MXFS_PR_MAX_KEYS);
	if (!keys) {
		out->rc = -ENOMEM;
		return -ENOMEM;
	}

	scsipr_dep_enter(ctx, "lureset-admit");

	/*
	 * STEP 1 — what excludes non-registrants, read BEFORE anything is issued.
	 * This has to come first for a reason beyond ordering: the RESERVE in step
	 * 3 would CREATE a reservation on a LUN that has none, and a gate that
	 * silently re-armed the cluster's exclusion would hide the interval in
	 * which non-registrants could write.  Having seen a matching reservation
	 * already in force, that RESERVE can only be answered, never acted on.
	 */
	ret = mxfs_scsipr_read_reservation(ctx, &resv);
	if (ret) {
		out->refusal = (ret == -EOPNOTSUPP) ? MXFS_LURESET_REFUSE_NO_RESERVATION
						    : MXFS_LURESET_REFUSE_IO;
		out->rc = ret;
		goto out;
	}
	out->resv_type = resv.type;
	if (!resv.held) {
		out->refusal = MXFS_LURESET_REFUSE_NO_RESERVATION;
		goto out;
	}
	if (!mxfs_pr_type_excludes_nonregistrants(resv.type)) {
		out->refusal = MXFS_LURESET_REFUSE_RESV_TYPE;
		goto out;
	}

	/* STEP 2 — the census, complete or not at all. */
	ret = scsipr_gate_view(ctx, victim_key, keys, &out->own_n, &out->other_n,
			       &out->victim_present, &out->pr_generation);
	if (ret == -EOVERFLOW) {
		out->refusal = MXFS_LURESET_REFUSE_VIEW_TRUNCATED;
		out->rc = ret;
		goto out;
	}
	if (ret) {
		out->refusal = MXFS_LURESET_REFUSE_IO;
		out->rc = ret;
		goto out;
	}
	if (out->own_n == 0) {
		out->refusal = MXFS_LURESET_REFUSE_SELF_GONE;
		goto out;
	}
	if (out->own_n > 1) {
		out->refusal = MXFS_LURESET_REFUSE_MULTI_NEXUS;
		goto out;
	}
	/*
	 * The victim's own registration is checked BEFORE the general
	 * other-registrant count, and the order is the whole value of the check: a
	 * registered victim is necessarily one of the other registrants, so the
	 * generic refusal would fire first and report the less useful of two true
	 * facts.  "The victim is registered, so the key preempt is the fence for
	 * it" tells the caller which operation to run instead; "somebody else is
	 * registered" does not.
	 */
	if (out->victim_present) {
		out->refusal = MXFS_LURESET_REFUSE_VICTIM_REGISTERED;
		goto out;
	}
	if (out->other_n > 0) {
		out->refusal = MXFS_LURESET_REFUSE_OTHER_REGISTRANT;
		goto out;
	}

	/*
	 * STEP 3 — is the one descriptor OURS, or a re-use of our key value on
	 * somebody else's nexus?  Only the target can answer that, and this is how
	 * it answers: a matching-scope/type RESERVE completes GOOD for an I_T nexus
	 * registered with the key in the command and returns RESERVATION CONFLICT
	 * for one that is not.  The PAL primitive is called directly rather than
	 * through mxfs_scsipr_reserve(), which classifies a conflict against a
	 * matching reservation as benign and returns 0 — correct for a mount that
	 * only needs to know exclusion is armed, and the exact opposite of what is
	 * needed here, where the conflict IS the finding.
	 */
	ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
				       MXFS_SCSIPR_RESV_TYPE);
	mxfs_scsipr_snap_invalidate(ctx, "lureset-admit");
	if (ret == -EBUSY) {
		out->refusal = MXFS_LURESET_REFUSE_NOT_A_REGISTRANT;
		out->rc = ret;
		goto out;
	}
	if (ret) {
		out->refusal = MXFS_LURESET_REFUSE_IO;
		out->rc = ret;
		goto out;
	}

	/*
	 * STEP 4 — close the bracket.  Everything above was read before the
	 * RESERVE; a registration that appeared while the gate was deciding would
	 * make the answer describe a table that no longer exists, and any PROUT
	 * that created it bumps the PR generation.
	 */
	ret = scsipr_gate_view(ctx, victim_key, keys, &own_b, &other_b, &victim_b,
			       &gen_b);
	if (ret) {
		out->refusal = (ret == -EOVERFLOW) ?
			       MXFS_LURESET_REFUSE_VIEW_TRUNCATED :
					   MXFS_LURESET_REFUSE_IO;
		out->rc = ret;
		goto out;
	}
	if (gen_b != out->pr_generation || own_b != 1 || other_b != 0 || victim_b) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P306-LURESET-RACE '%s' the registration table "
			     "moved while admission was being decided: gen %u->%u "
			     "own %d->%d other %d->%d victim %d->%d — the answer would "
			     "describe a table that no longer exists",
			     ctx->dev_name, out->pr_generation, gen_b, out->own_n,
			     own_b, out->other_n, other_b, (int)out->victim_present,
			     (int)victim_b);
		out->refusal = MXFS_LURESET_REFUSE_RACED;
		out->own_n = own_b;
		out->other_n = other_b;
		out->victim_present = victim_b;
		out->pr_generation = gen_b;
		goto out;
	}

	out->admitted = true;
	out->refusal = MXFS_LURESET_ADMIT_OK;
	ret = 0;
out:
	mxfs_scsipr_departure_unlock();
	mxfs_pal_free(keys);
	/*
	 * ONE LINE PER DECISION, carrying every number the decision was made
	 * from — a refusal that cannot say which fact was missing is
	 * indistinguishable from a bug in this function.
	 */
	mxfs_pal_log(out->admitted ? MXFS_LOG_DEBUG : MXFS_LOG_ERR,
		     "scsipr: P306-LURESET-ADMIT '%s' admitted=%d reason=%s "
		     "victim_node=%u victim_key=0x%016llx victim_present=%d "
		     "own_n=%d other_n=%d gen=%u resv_type=0x%x (%s) rc=%d — %s",
		     ctx->dev_name, (int)out->admitted,
		     mxfs_lu_reset_refusal_name(out->refusal), victim_node,
		     (unsigned long long)victim_key, (int)out->victim_present,
		     out->own_n, out->other_n, out->pr_generation, out->resv_type,
		     mxfs_pr_type_name(out->resv_type), out->rc,
		     out->admitted ?
		     "an LU-scope reset may be issued: this initiator is the only "
		     "registrant under a reservation that refuses non-registrant "
		     "writes" :
		     "NOTHING WILL BE ISSUED");
	return 0;
}

/*
 * ── THE POST-RESET CONVERGENCE BARRIER, STORAGE HALF ────────────────────
 * Contract, and what it deliberately leaves to the caller, in scsipr.h.
 */

const char *mxfs_lu_reset_convergence_name(int r)
{
	switch (r) {
	case MXFS_LURESET_CONVERGED:
		return "converged";
	case MXFS_LURESET_CONV_PROBE_TIMEOUT:
		return "the-command-path-did-not-answer-inside-the-bound";
	case MXFS_LURESET_CONV_PROBE_FAILED:
		return "the-controlled-probe-returned-an-error";
	case MXFS_LURESET_CONV_ADMISSION_LOST:
		return "the-admission-assertion-set-no-longer-holds";
	case MXFS_LURESET_CONV_GENERATION_MOVED:
		return "the-pr-generation-moved-across-the-reset";
	default:
		return "?";
	}
}

/*
 * THE BOUND ON THE CONTROLLED PROBE, derived and not chosen for roundness.
 * The healthy admission path — four PR commands including a PERSISTENT RESERVE
 * OUT — measured 9 ms end to end on this fleet, and the probe is ONE PR IN.
 * What it may additionally have to absorb is the UNIT ATTENTION the reset
 * leaves pending (one extra command round trip on the same order) and, if the
 * error handler is recovering the session underneath it, the queueing that
 * comes with that.  So the bound is the task-management timeout the reset
 * itself was issued under — libiscsi's 30 s — plus 2000 ms for the probe's own
 * round trips, which is more than two hundred times the measured figure.  A
 * probe that has not answered by then has not shown that the path came back
 * PROMPTLY, and that is a refusal: the caller stops and leaves its durable
 * intent resumable.  It is emphatically NOT sized from the 538 s worst-case
 * error-handler rescue measured for a stranded command — waiting that out here
 * would be this barrier doing the pre-reset drain the design ruling rejected.
 */
static unsigned int mxfs_lu_reset_converge_ms = 32000;
module_param_named(lu_reset_converge_ms, mxfs_lu_reset_converge_ms, uint, 0644);
MODULE_PARM_DESC(lu_reset_converge_ms,
		 "bound on the post-reset controlled probe; exceeding it refuses convergence");

int mxfs_scsipr_lu_reset_converge(struct mxfs_scsipr_ctx *ctx,
				  mxfs_node_id_t victim_node,
				  uint64_t victim_key,
				  uint32_t gen_before,
				  struct mxfs_lu_reset_convergence *out)
{
	struct mxfs_pal_pr_reservation resv;
	uint64_t t0, tprobe;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->refusal = MXFS_LURESET_CONV_PROBE_FAILED;
	out->gen_before = gen_before;
	if (!ctx || !ctx->dev)
		return -EINVAL;

	t0 = mxfs_pal_time_ms();

	/*
	 * STEP 1 — THE CONTROLLED PROBE, and it must be the first command this
	 * node sends after the reset.  A LOGICAL UNIT RESET establishes a UNIT
	 * ATTENTION on every I_T nexus, and the first command to arrive is
	 * answered with it INSTEAD of being executed.  Whatever that command is,
	 * its result describes the reset rather than itself — so a heartbeat
	 * renewal, a replay write or a recovery commit put there would report a
	 * failure that means nothing, and a caller that retried it would be
	 * writing under a condition it had not read.  A PERSISTENT RESERVE IN is
	 * the right thing to spend on that: it mutates nothing, and being consumed
	 * is the whole of its job here.
	 *
	 * The PAL PR path already reissues a bounded number of times on UNIT
	 * ATTENTION, so one call normally absorbs the condition; the loop here is
	 * for the case where the reset was followed by transport recovery and the
	 * path is not yet carrying commands at all.  Its bound is a refusal, never
	 * a wait that grows (see mxfs_lu_reset_converge_ms).
	 */
	for (;;) {
		out->probe_tries++;
		ret = mxfs_scsipr_read_reservation(ctx, &resv);
		tprobe = mxfs_pal_time_ms();
		out->probe_ms = (uint32_t)(tprobe - t0);
		if (ret == 0)
			break;
		if (out->probe_ms >= mxfs_lu_reset_converge_ms) {
			out->refusal = MXFS_LURESET_CONV_PROBE_TIMEOUT;
			out->rc = ret;
			goto done;
		}
		mxfs_pal_sleep_ms(200);
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: P307-LURESET-PROBE '%s' the command path answered "
		     "after the reset: tries=%d ms=%u held=%d type=0x%x (%s) "
		     "gen=%u — a PR IN completing proves the COMMAND PATH and "
		     "nothing about writable media",
		     ctx->dev_name, out->probe_tries, out->probe_ms,
		     (int)resv.held, resv.type, mxfs_pr_type_name(resv.type),
		     resv.generation);

	/*
	 * STEP 2 — the WHOLE admission assertion set, re-established against the
	 * target rather than carried over.  Re-running the admission function
	 * itself is the point: a cheaper post-reset check would be a second,
	 * weaker set of rules for the same question, and the one that ran after
	 * the reset is the one that has to hold.
	 */
	ret = mxfs_scsipr_lu_reset_admit(ctx, victim_node, victim_key,
					 &out->readmit);
	if (ret) {
		out->refusal = MXFS_LURESET_CONV_ADMISSION_LOST;
		out->rc = ret;
		goto done;
	}
	out->gen_after = out->readmit.pr_generation;
	if (!out->readmit.admitted) {
		out->refusal = MXFS_LURESET_CONV_ADMISSION_LOST;
		out->rc = out->readmit.rc;
		goto done;
	}

	/*
	 * STEP 3 — did the registration survive CONTINUOUSLY, or was it destroyed
	 * and recreated under us?  This is the check for the hazard peculiar to a
	 * target that purges registrations together with the iSCSI session: the
	 * reset can be followed by error-handler transport recovery, the session
	 * comes back new, our registration is gone with the old one, and a health
	 * worker's re-REGISTER then restores an admission set that reads
	 * identically while describing a registration that did not exist
	 * throughout.  A LOGICAL UNIT RESET does not bump the PR generation;
	 * every PERSISTENT RESERVE OUT does.  So an unchanged generation across
	 * the reset says no such round trip happened, and a moved one fails
	 * closed even though step 2 passed.
	 */
	if (out->gen_after != gen_before) {
		out->refusal = MXFS_LURESET_CONV_GENERATION_MOVED;
		goto done;
	}

	out->converged = true;
	out->refusal = MXFS_LURESET_CONVERGED;
done:
	out->total_ms = (uint32_t)(mxfs_pal_time_ms() - t0);
	mxfs_pal_log(out->converged ? MXFS_LOG_DEBUG : MXFS_LOG_ERR,
		     "scsipr: P307-LURESET-CONVERGE '%s' converged=%d reason=%s "
		     "victim_node=%u probe_tries=%d probe_ms=%u total_ms=%u "
		     "gen_before=%u gen_after=%u readmit=%s own_n=%d other_n=%d "
		     "victim_present=%d "
		     "resv_type=0x%x rc=%d — %s",
		     ctx->dev_name, (int)out->converged,
		     mxfs_lu_reset_convergence_name(out->refusal), victim_node,
		     out->probe_tries, out->probe_ms, out->total_ms,
		     out->gen_before, out->gen_after,
		     mxfs_lu_reset_refusal_name(out->readmit.refusal),
		     out->readmit.own_n, out->readmit.other_n,
		     (int)out->readmit.victim_present, out->readmit.resv_type,
		     out->rc,
		     out->converged ?
		     "the storage half of the barrier holds; the caller must still "
		     "renew authority through its own synchronous path and STOP if "
		     "the lease lapsed, before any replay or recovery-commit write" :
		     "NO REPLAY AND NO RECOVERY-COMMIT WRITE MAY FOLLOW; leave the "
		     "durable reset intent resumable");
	return 0;
}

/*
 * ── THE AUDITED-KERNEL PIN ───────────────────────────────────────────────
 * Why a pin rather than a version check, in scsipr.h.
 *
 * One row per release the one-TMF-per-session invariant was actually read on,
 * and the row records HOW it was read, because the two strengths are not the
 * same evidence and a later reader must not have to guess which one it is
 * looking at.  Matching is exact: a prefix match would admit 6.8.0-999, which
 * is a different kernel that nobody has read.
 */
struct mxfs_lu_reset_audited_kernel {
	const char *krel;
	const char *how;
};

static const struct mxfs_lu_reset_audited_kernel mxfs_lu_reset_audited[] = {
	{
		"7.1.0-rc7",
		"bodies read: iscsi_tmf_rsp does not check the ITT; every TMF entry "
		"point takes eh_mutex then frwd_lock and refuses unless tmf_state == "
		"TMF_INITIAL; a timed-out TMF fails the connection instead of "
		"returning to TMF_INITIAL; a reconnect across the wait returns "
		"-ENOTCONN",
	},
	{
		"6.8.0-101-generic",
		"STRUCTURAL CROSS-CHECK ONLY, and named as exactly that: the bodies "
		"of this release are not available here, so what was compared is its "
		"shipped include/scsi/libiscsi.h against the read tree's — the TMF_* "
		"enum, eh_mutex, ehwait, tmhdr, tmf_timer, tmf_state, "
		"lu_reset_timeout and frwd_lock, identical at identical line numbers. "
		"A state machine whose declarations are unchanged is strong evidence "
		"and is not a body-level audit",
	},
};

/*
 * THE STRUCTURAL ADMISSION (0.89.80).  Fingerprints of the libiscsi TMF
 * declarations (pal/linux/libiscsi_fingerprint.sh) of trees whose BODIES were
 * read.  A kernel whose own build headers produce one of these — and which is
 * the kernel the module was built for — has the declarations that
 * serialization is built from, unchanged.
 *
 * Measured with the script itself: /src/linux 7.1.0-rc7 (read) gives the value
 * below, and so do the headers of 6.8.0-101-generic, 6.17.2-1-pve and
 * 7.0.14-19-pve (scripts/pve_libiscsi_crosscheck.sh; 7.0.14-19-pve's three
 * iSCSI headers are byte-identical to the read tree, 6.17.2-1-pve's libiscsi.h
 * differs only in the return type of iscsi_queuecommand).
 *
 * 0.90.1: measured the same way on the two other released platforms' build
 * headers, taken from the lab's own nodes — 5.14.0-687.49.1.el9_8.x86_64
 * (RHEL 9.8 family) and 6.12.107+deb13-amd64 (Debian 13, from
 * linux-headers-6.12.107+deb13-common) — both give the value below.  Their
 * libiscsi.h differs from the read tree only in the return types of
 * iscsi_queuecommand and (RHEL) the constness of iscsi_host_alloc's template
 * argument, neither of which is a TMF declaration.
 */
static const char *const mxfs_lu_reset_audited_fp[] = {
	"d5ee9d1ecdea95baf6f96d4321cab4c9fce04c32854e8ed646e58bec9598c3a1",
	NULL,
};

/*
 * Releases refused whatever their fingerprint: a kernel found to break the
 * one-TMF-per-session invariant with its declarations unchanged is named here.
 * None is known.
 */
static const char *const mxfs_lu_reset_denied_krel[] = {
	NULL,
};

static bool mxfs_lu_reset_fp_admitted(const char *krel, const char **why)
{
	const char *build = mxfs_pal_kernel_build_release();
	const char *fp = mxfs_pal_libiscsi_fingerprint();
	bool known = false;
	size_t i;

	for (i = 0; mxfs_lu_reset_denied_krel[i]; i++) {
		if (!strcmp(krel, mxfs_lu_reset_denied_krel[i])) {
			if (why)
				*why = "REFUSED: this kernel release is on the denylist — its "
				       "libiscsi declarations match an audited shape but it is "
				       "known not to keep the one-TMF-per-session invariant";
			return false;
		}
	}
	if (!build[0] || strcmp(krel, build) != 0) {
		if (why)
			*why = "REFUSED: this module was not built for the running kernel, "
			       "so the libiscsi fingerprint it carries describes some other "
			       "kernel's headers and says nothing about this one";
		return false;
	}
	for (i = 0; mxfs_lu_reset_audited_fp[i]; i++)
		if (!strcmp(fp, mxfs_lu_reset_audited_fp[i]))
			known = true;
	mxfs_pal_log(known ? MXFS_LOG_WARN : MXFS_LOG_ERR,
		     "scsipr: P308-LURESET-PIN-FINGERPRINT krel=%s build=%s fp=%s "
		     "%s",
		     krel, build, fp,
		     known ? "— matches a read tree's libiscsi TMF declarations; "
			     "admitted STRUCTURALLY (declarations, not bodies)" :
			     "— not the shape of any read tree; refused");
	if (!known) {
		if (why)
			*why = "REFUSED: this kernel's libiscsi TMF declarations do not "
			       "have the shape of any tree the LU-reset witness was read "
			       "on (or its headers were absent at build)";
		return false;
	}
	if (why)
		*why = "STRUCTURAL FINGERPRINT, and named as exactly that: the TMF_* "
		       "enum and the eh_mutex, ehwait, tmhdr, tmf_timer, tmf_state, "
		       "lu_reset_timeout, frwd_lock and back_lock members of this "
		       "kernel's own build headers hash to a read tree's; the running "
		       "kernel is the one the module was built for.  Declarations "
		       "unchanged is strong evidence and is not a body-level audit";
	return true;
}

bool mxfs_fence_lu_reset_kernel_audited(const char *krel, const char **why)
{
	size_t i;

	if (!krel || !krel[0]) {
		if (why)
			*why = "REFUSED: no kernel release to pin the witness to.  The "
			       "witness's per-operation meaning rests on a kernel-internal "
			       "serialization invariant, so an unnamed kernel is an "
			       "unaudited one";
		return false;
	}
	for (i = 0; i < sizeof(mxfs_lu_reset_audited) /
		    sizeof(mxfs_lu_reset_audited[0]); i++) {
		if (!strcmp(krel, mxfs_lu_reset_audited[i].krel)) {
			if (why)
				*why = mxfs_lu_reset_audited[i].how;
			return true;
		}
	}
	return mxfs_lu_reset_fp_admitted(krel, why);
}

/*
 * A REFUSAL-ONLY INJECTOR for the pin, so the arm that proves the pin sits
 * BEFORE the command boundary can be measured on a rig that runs exactly one
 * kernel.  Set it to a release string and the pin is asked about THAT string
 * instead of the running kernel's.
 *
 * It can only ever cause a refusal: a value that the pin ACCEPTS is rejected
 * here, loudly, and the running kernel is used instead.  A knob that could
 * name an audited release would be a way to mint a durable certificate on a
 * kernel nobody read, which is the exact failure the pin exists to prevent —
 * an injector must be able to make a check fail, never to make it pass.
 */
static char *mxfs_lu_reset_krel_probe;
module_param_named(lu_reset_krel_probe, mxfs_lu_reset_krel_probe, charp, 0644);
MODULE_PARM_DESC(lu_reset_krel_probe,
		 "substitute this release for the running kernel's at the LU-reset audited-kernel pin; only a value the pin REFUSES is honoured");

static const char *mxfs_lu_reset_krel_effective(char *buf, size_t len)
{
	const char *real = mxfs_pal_kernel_release();
	const char *p = mxfs_lu_reset_krel_probe;
	size_t n;

	if (!real)
		real = "";
	if (!p)
		p = "";
	/*
	 * DISARMING HAS TO WORK.  A sysfs store hands a charp parameter the bytes
	 * that were written, terminator included, so `echo '' > .../knob` leaves
	 * this knob holding "\n" rather than nothing — and "\n" is a release no
	 * pin can carry, so one armed refusal arm would go on refusing every later
	 * fence on that node under a reason the operator believes was cleared.
	 * A kernel release contains no whitespace, so trimming it away can only
	 * recover the value that was meant, and an all-whitespace value means the
	 * knob is off.
	 */
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	n = strlen(p);
	while (n && (p[n - 1] == ' ' || p[n - 1] == '\t' ||
		     p[n - 1] == '\n' || p[n - 1] == '\r'))
		n--;
	if (!n) {
		snprintf(buf, len, "%s", real);
		return buf;
	}
	snprintf(buf, len, "%.*s", (int)n, p);
	if (mxfs_fence_lu_reset_kernel_audited(buf, NULL)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P308-LURESET-KRELPROBE IGNORED '%s' — this knob "
			     "exists to exercise the pin's REFUSAL and may name only a "
			     "release the pin rejects; honouring an audited value here "
			     "would be a way to mint on a kernel nobody read.  Using "
			     "the running kernel '%s'",
			     buf, real);
		snprintf(buf, len, "%s", real);
		return buf;
	}
	mxfs_pal_log(MXFS_LOG_WARN,
		     "scsipr: P308-LURESET-KRELPROBE substituting '%s' for the "
		     "running kernel '%s' — the pin must refuse and NO LOGICAL "
		     "UNIT RESET may be issued",
		     buf, real);
	return buf;
}

const char *mxfs_lu_reset_fence_verdict_name(int v)
{
	switch (v) {
	case MXFS_LURESET_FENCE_CERTIFIED:         return "certified";
	case MXFS_LURESET_FENCE_BAD_ARGS:          return "bad-args";
	case MXFS_LURESET_FENCE_NO_LUN_ID:         return "no-lun-designator";
	case MXFS_LURESET_FENCE_KERNEL_UNAUDITED:  return "kernel-unaudited";
	case MXFS_LURESET_FENCE_NOT_ADMITTED:      return "not-admitted";
	case MXFS_LURESET_FENCE_ARM_FAILED:        return "intent-not-durable";
	case MXFS_LURESET_FENCE_NOT_WITNESSED:     return "not-witnessed";
	case MXFS_LURESET_FENCE_INDETERMINATE:     return "reset-indeterminate";
	case MXFS_LURESET_FENCE_KERNEL_MOVED:      return "report-kernel-moved";
	case MXFS_LURESET_FENCE_BARRIER_REFUSED:   return "barrier-refused";
	case MXFS_LURESET_FENCE_BARRIER_UNASKABLE: return "barrier-unaskable";
	default:                                   return "?";
	}
}

/*
 * ── THE WITNESSED-LU-RESET FENCE ─────────────────────────────────────────
 * Contract in scsipr.h.  This is the ONLY producer of
 * MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1, and the only place the three retire
 * fields are set together — v5_mount.c demotes any proving kind back to
 * KEY_ABSENT_UNPROVEN when retire_basis is NONE, so a kind set without its
 * basis and claim is not a weaker certificate, it is no certificate at all.
 */
int mxfs_scsipr_fence_by_lu_reset(struct mxfs_scsipr_ctx *ctx,
				  const struct mxfs_lu_reset_fence_req *req,
				  struct mxfs_lu_reset_fence *out)
{
	struct mxfs_pal_lu_reset_result *wit;   /* heap: it carries the whole
											 * 2 KiB helper report and a
											 * kernel stack has no room for
											 * it */
	struct mxfs_pal_lu_reset_req wreq;
	const char *pin_why = NULL;
	const char *krel;
	char krelbuf[68];
	char victim_tag[24];
	char lun_id[72];
	uint64_t t0 = 0;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->verdict = MXFS_LURESET_FENCE_BAD_ARGS;
	out->result.kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
	out->result.phase = MXFS_FENCE_PHASE_PRECOMMAND;
	out->result.retire_basis = MXFS_RETIRE_BASIS_NONE;
	out->result.retire_claim = MXFS_RETIRE_CLAIM_NONE;
	out->result.retire_obs = MXFS_RETIRE_OBS_UNKNOWN;

	if (!ctx || !ctx->dev || !req)
		return -EINVAL;
	out->result.victim_key = req->victim_key;
	if (!req->authority) {
		/* Not a default-allow.  A certificate whose authority half was never
		 * asked authorises replay by a node that may no longer be entitled to
		 * the slice at all. */
		snprintf(out->why, sizeof(out->why),
			 "REFUSED: no authority barrier was supplied, and there is no "
			 "certificate that can be minted with the authority half "
			 "unasked");
		goto refused;
	}
	/*
	 * WHICH LOGICAL UNIT.  The helper resolves the device to reset by this
	 * designator and refuses unless exactly one device carries it, so an
	 * unidentified LUN must stop here: resetting the wrong unit destroys
	 * in-flight I/O on something nobody was fencing.  A caller may pass the
	 * designator it already read; otherwise it is read from the unit now.
	 */
	if (req->lun_id && req->lun_id[0]) {
		snprintf(lun_id, sizeof(lun_id), "%s", req->lun_id);
	} else {
		struct mxfs_pal_target_id tid;

		ret = mxfs_pal_scsi_target_id(ctx->dev, &tid);
		if (ret || !tid.lun_id[0]) {
			out->verdict = MXFS_LURESET_FENCE_NO_LUN_ID;
			out->result.rc = ret;
			snprintf(out->why, sizeof(out->why),
				 "REFUSED: the unit reports no VPD page 0x83 designator "
				 "(rc=%d), so the reset could land on a logical unit "
				 "nobody is fencing", ret);
			goto refused;
		}
		snprintf(lun_id, sizeof(lun_id), "%s", tid.lun_id);
	}

	t0 = mxfs_pal_time_ms();

	/*
	 * THE KERNEL PIN, BEFORE THE COMMAND BOUNDARY.  An LU-scope reset
	 * terminates the tasks of every nexus on the unit, including a bystander
	 * initiator's in-flight reads.  Spending that on a witness this build
	 * could not use afterwards is pure damage, so the pin is read here as
	 * well as against the report.
	 */
	krel = mxfs_lu_reset_krel_effective(krelbuf, sizeof(krelbuf));
	if (!mxfs_fence_lu_reset_kernel_audited(krel, &pin_why)) {
		out->verdict = MXFS_LURESET_FENCE_KERNEL_UNAUDITED;
		snprintf(out->krel, sizeof(out->krel), "%s", krel ? krel : "");
		snprintf(out->why, sizeof(out->why),
			 "REFUSED BEFORE ISSUING on krel=%s: %s",
			 krel ? krel : "?", pin_why);
		goto refused;
	}

	/*
	 * STEP 1 — ADMISSION.  Nothing is issued on a refusal, so this attempt
	 * stays retryable: the precondition may come back.
	 */
	out->admit_run = true;
	ret = mxfs_scsipr_lu_reset_admit(ctx, req->victim_node, req->victim_key,
					 &out->admit);
	if (ret || !out->admit.admitted) {
		out->verdict = MXFS_LURESET_FENCE_NOT_ADMITTED;
		out->result.rc = ret ? ret : out->admit.rc;
		out->result.pr_generation = out->admit.pr_generation;
		out->result.resv_type = out->admit.resv_type;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED: admission=%s — nothing was issued and this attempt "
			 "is retryable",
			 mxfs_lu_reset_refusal_name(out->admit.refusal));
		goto refused;
	}
	out->result.pr_generation = out->admit.pr_generation;
	out->result.resv_type = out->admit.resv_type;
	/* The observation is a fact, recorded whatever happens next.  It is not a
	 * retirement claim and it never becomes one on its own. */
	out->result.retire_obs = MXFS_RETIRE_OBS_SOLE_REGISTRANT_VICTIM_ABSENT;

	/*
	 * STEP 2 — THE COMMAND-SUBMISSION BOUNDARY.  Make the intent durable
	 * FIRST and do not issue if it cannot be made durable: a reset whose
	 * having happened cannot later be established is the worst of both, since
	 * the work is destroyed and nothing may be replayed on the strength of it.
	 */
	if (req->arm_submit) {
		ret = req->arm_submit(req->arm_data);
		if (ret) {
			out->verdict = MXFS_LURESET_FENCE_ARM_FAILED;
			out->result.rc = ret;
			snprintf(out->why, sizeof(out->why),
				 "REFUSED: the durable reset intent could not be written "
				 "(rc=%d), so NO LOGICAL UNIT RESET was issued and nothing "
				 "was consumed", ret);
			goto refused;
		}
	}

	/* STEP 3 — the operation itself, and the target's answer to it. */
	snprintf(victim_tag, sizeof(victim_tag), "node%u",
		 (unsigned int)req->victim_node);
	memset(&wreq, 0, sizeof(wreq));
	wreq.lun_id = lun_id;
	wreq.victim = victim_tag;
	wreq.epoch = req->epoch;
	wit = mxfs_pal_alloc(sizeof(*wit));
	if (!wit) {
		/* Before the boundary: nothing was issued.  The intent the caller
		 * armed is still on the platter, and it is still resumable. */
		out->verdict = MXFS_LURESET_FENCE_ARM_FAILED;
		out->result.rc = -ENOMEM;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED: no memory for the witness report, so NO LOGICAL "
			 "UNIT RESET was issued");
		goto refused;
	}
	out->reset_issued_ms = mxfs_pal_time_ms();
	ret = mxfs_pal_lu_reset_witness(&wreq, wit);
	out->pal_verdict = wit->verdict;
	out->reset_issued = wit->issued;
	out->reset_ms = wit->reset_wall_ms;
	snprintf(out->krel, sizeof(out->krel), "%s", wit->krel);
	if (wit->issued)
		out->result.phase = MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED;
	if (wit->verdict != MXFS_PAL_LURESET_WITNESSED) {
		/*
		 * INDETERMINATE and REFUSED are different facts and must not be
		 * collapsed.  REFUSED/NOT_RUN means nothing crossed the boundary and
		 * the attempt is retryable; INDETERMINATE means the reset MAY have
		 * been performed, so a retry would be a second LU-scope reset under a
		 * state nobody has established.
		 */
		out->verdict = (wit->verdict == MXFS_PAL_LURESET_INDETERMINATE)
			       ? MXFS_LURESET_FENCE_INDETERMINATE
			       : MXFS_LURESET_FENCE_NOT_WITNESSED;
		out->result.rc = ret;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED: verdict=%s issued=%d reason=%s rc=%d",
			 mxfs_pal_lu_reset_verdict_name(wit->verdict),
			 (int)wit->issued, wit->reason[0] ? wit->reason : "?", ret);
		mxfs_pal_free(wit);
		goto refused;
	}

	/*
	 * STEP 4 — the report must name the release the pin was read against.  A
	 * helper that ran somewhere else, or on a kernel that moved under a
	 * module left loaded across an upgrade, produces a witness whose argument
	 * this build has not made.
	 */
	if (!krel || strcmp(wit->krel, krel) != 0 ||
	    !mxfs_fence_lu_reset_kernel_audited(wit->krel, &pin_why)) {
		out->verdict = MXFS_LURESET_FENCE_KERNEL_MOVED;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED AFTER THE RESET: the report was taken on krel=%s, "
			 "pinned krel=%s — the reset happened and may not be certified",
			 wit->krel[0] ? wit->krel : "?", krel ? krel : "?");
		mxfs_pal_free(wit);
		goto refused;
	}
	mxfs_pal_free(wit);
	wit = NULL;

	/*
	 * STEP 5 — THE POST-RESET BARRIER, both halves.  The reset terminated
	 * this node's own tasks as well, so nothing about the state it left
	 * behind may be assumed: the caller's barrier re-establishes the command
	 * path, re-runs the whole admission set, checks the generation did not
	 * move, and proves this node's own storage authority survived.
	 */
	ret = req->authority(req->authority_data, out->admit.pr_generation,
			     out->reset_issued_ms, &out->conv);
	if (ret == -EPERM) {
		out->verdict = MXFS_LURESET_FENCE_BARRIER_REFUSED;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED AFTER THE RESET: the barrier did not hold "
			 "(storage=%s converged=%d) — the reset happened, the intent "
			 "stays resumable by a later authority holder, and NO replay "
			 "or recovery-commit byte may follow",
			 mxfs_lu_reset_convergence_name(out->conv.refusal),
			 (int)out->conv.converged);
		goto refused;
	}
	if (ret) {
		out->verdict = MXFS_LURESET_FENCE_BARRIER_UNASKABLE;
		out->result.rc = ret;
		snprintf(out->why, sizeof(out->why),
			 "REFUSED AFTER THE RESET: the barrier could not be evaluated "
			 "(rc=%d), which is not permission — the reset happened and "
			 "the intent stays resumable", ret);
		goto refused;
	}

	/*
	 * CERTIFY.  All three retire fields are set here together and nowhere
	 * else: the kind alone is demoted back to KEY_ABSENT_UNPROVEN by the
	 * consumer when the basis is NONE, which is the behaviour that makes a
	 * half-filled certificate impossible rather than merely wrong.
	 */
	out->result.kind = MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1;
	out->result.phase = MXFS_FENCE_PHASE_VERIFIED;
	out->result.pr_generation = out->conv.gen_after ? out->conv.gen_after
							: out->admit.pr_generation;
	out->result.resv_type = out->conv.readmit.resv_type ?
				out->conv.readmit.resv_type : out->admit.resv_type;
	out->result.retire_basis = MXFS_RETIRE_BASIS_TARGET_OP;
	out->result.retire_claim = MXFS_RETIRE_CLAIM_LU_RESET_WITNESSED_ALL_TASKS;
	out->result.retire_obs = MXFS_RETIRE_OBS_SOLE_REGISTRANT_VICTIM_ABSENT;
	out->certified = true;
	out->verdict = MXFS_LURESET_FENCE_CERTIFIED;
	snprintf(out->why, sizeof(out->why),
		 "CERTIFIED: one witnessed LU reset on krel=%s retired the tasks "
		 "of every nexus on the unit, and the barrier held", out->krel);
	out->total_ms = (uint32_t)(mxfs_pal_time_ms() - t0);
	goto log;

refused:
	out->certified = false;
	out->result.kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
	out->result.retire_basis = MXFS_RETIRE_BASIS_NONE;
	out->result.retire_claim = MXFS_RETIRE_CLAIM_NONE;
	if (t0)
		out->total_ms = (uint32_t)(mxfs_pal_time_ms() - t0);
log:
	mxfs_pal_log(out->certified ? MXFS_LOG_DEBUG : MXFS_LOG_ERR,
		     "scsipr: P308-LURESET-FENCE '%s' certified=%d verdict=%s "
		     "victim_node=%u victim_key=0x%016llx epoch=%llu kind=%d "
		     "phase=%s basis=%s claim=%s obs=%s admit_run=%d admitted=%d "
		     "admission=%s "
		     "pal=%s issued=%d reset_ms=%u converged=%d storage=%s "
		     "gen_admit=%u gen_after=%u krel=%s total_ms=%u rc=%d — %s",
		     ctx->dev_name, (int)out->certified,
		     mxfs_lu_reset_fence_verdict_name(out->verdict),
		     req->victim_node, (unsigned long long)req->victim_key,
		     (unsigned long long)req->epoch, (int)out->result.kind,
		     mxfs_fence_phase_name(out->result.phase),
		     mxfs_retire_basis_name(out->result.retire_basis),
		     mxfs_retire_claim_name(out->result.retire_claim),
		     mxfs_retire_observation_name(out->result.retire_obs),
		     (int)out->admit_run, (int)out->admit.admitted,
		     mxfs_lu_reset_refusal_name(out->admit.refusal),
		     mxfs_pal_lu_reset_verdict_name(out->pal_verdict),
		     (int)out->reset_issued, out->reset_ms,
		     (int)out->conv.converged,
		     mxfs_lu_reset_convergence_name(out->conv.refusal),
		     out->admit.pr_generation, out->conv.gen_after,
		     out->krel[0] ? out->krel : "?", out->total_ms,
		     out->result.rc, out->why);
	return 0;
}

int mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members)
{
	int count = 0, ret;
	bool own_present = false, victim_present = false;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	if (!ctx->registered)
		return 0;       /* not participating in PR — nothing to check */

	ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
				     &count, NULL);
	if (ret == -EOPNOTSUPP)
		return 0;
	if (ret == -EOVERFLOW) {
		/*
		 * The table is bigger than we can read, so "our key is missing"
		 * cannot be distinguished from "our key is past the truncation
		 * point".  This branch ends in a node freeze, and a partial view
		 * is exactly how a HEALTHY node would be made to look preempted:
		 * a saturated count also satisfies the count >= live_members
		 * guard below, so the topology escape hatch would not catch it.
		 * Never self-fence on a view that cannot see itself.
		 */
		return 0;
	}
	if (ret) {
		/* Transient READ KEYS failure — retry next tick, but never
		 * silently: a persistently failing self-check looks identical
		 * to a healthy one otherwise. */
		static int d8_rk_fail_logs;

		if (d8_rk_fail_logs < 8) {
			d8_rk_fail_logs++;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "scsipr: P-PR-SELFCHECK read_keys failed on '%s': %d",
				     ctx->dev_name, ret);
		}
		return ret;
	}

	if (own_present) {
		ctx->advisory_logged = false;
		return 0;
	}

	/* Same classification as fence_node: self-fence only on the
	 * UNAMBIGUOUS preemption signature. */
	if (count >= live_members && live_members >= 2) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
			     "'%s' (self-check: %d key(s), %d live) — node was "
			     "preempted",
			     (unsigned long long)ctx->local_key, ctx->dev_name,
			     count, live_members);
		return -ESTALE;
	}
	if (!ctx->advisory_logged) {
		ctx->advisory_logged = true;
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-ADVISORY '%s' self-check: own key gone, "
			     "%d key(s) for %d live member(s) — per-node PR not "
			     "trustworthy on this topology; D1+lease fencing apply",
			     ctx->dev_name, count, live_members);
	}
	return 0;
}

/*
 * /277 — AM I THE FENCED NODE? Target-authoritative, callable
 * from a node whose media READS may be arbitrarily stale (the
 * victim's heartbeat re-reads were 51 generations behind the platter,
 * which is why mxfs_scsipr_self_check's READ-KEYS path never fired for
 * it: this rig's CAW transport never ran self_check at all, and a
 * media-read based check provably cannot work on a wedged initiator).
 *
 * Primary: PR IN / READ FULL STATUS — per-I_T-nexus, generated by the
 * target at command time, permitted to an unregistered initiator.
 * Fallback (-EOPNOTSUPP only): READ KEYS own-key scan, which carries a
 * key-reuse ambiguity but is still target-generated.
 *
 * Returns 1 = our key is provably ABSENT (we are fenced);
 *         0 = our key is present (still registered);
 *        <0 = could not be answered (caller must treat as UNKNOWN,
 *             never as either verdict).
 */
int mxfs_scsipr_fenced_check(struct mxfs_scsipr_ctx *ctx)
{
	uint32_t gen = 0;
	int present = 0;
	int ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	if (!ctx->registered || !ctx->local_key)
		return -ENOENT;     /* never registered — fencing is not the story */

	ret = mxfs_pal_scsi_pr_read_full_status(ctx->dev, ctx->local_key,
						&present, &gen);
	if (ret == 0) {
		if (!present)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P277-PR-FULLSTATUS own key 0x%llx ABSENT "
				     "on '%s' (pr_gen=%u) — target says this node is "
				     "fenced",
				     (unsigned long long)ctx->local_key, ctx->dev_name,
				     gen);
		return present ? 0 : 1;
	}

	if (ret == -EOPNOTSUPP) {
		bool own_present = false, victim_present = false;
		int count = 0;

		ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
					     &count, &gen);
		if (ret)
			return ret;     /* incl. -EOVERFLOW: truncation ⇒ unknown */
		if (!own_present)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "scsipr: P277-PR-READKEYS own key 0x%llx absent "
				     "on '%s' (%d key(s), pr_gen=%u) — fenced "
				     "(full-status unsupported; key-reuse ambiguity "
				     "accepted as fallback)",
				     (unsigned long long)ctx->local_key, ctx->dev_name,
				     count, gen);
		return own_present ? 0 : 1;
	}

	return ret;
}

int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx)
{
	int count = 0, ret;
	bool own_present = false, victim_present = false;

	if (!ctx || !ctx->dev || !ctx->registered)
		return 0;

	ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
				     &count, NULL);
	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-PROBE '%s': READ KEYS unsupported — "
			     "PR state not verifiable (advisory)", ctx->dev_name);
		return 0;
	}
	if (ret == -EOVERFLOW) {
		/* Provisioning-time signal that MXFS_PR_MAX_KEYS is too small for
		 * this target's nexus count — the one place it is cheap to notice
		 * before a fence or a self-check has to refuse. */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: P-PR-PROBE '%s': registration table exceeds the "
			     "%d-descriptor snapshot cap — PR classification will "
			     "refuse until MXFS_PR_MAX_KEYS is raised",
			     ctx->dev_name, MXFS_PR_MAX_KEYS);
		return 0;
	}
	if (ret)
		return ret;

	if (!own_present)
		/* Register reported success but our key is not visible: the
		 * target either shares one I_T nexus across nodes (each
		 * register overwrites the last) or silently drops
		 * registrations.  Fencing must not trust PR here. */
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-PROBE '%s': own key 0x%llx NOT visible "
			     "after successful register (%d key(s)) — per-node PR "
			     "unusable on this target/topology (advisory only)",
			     ctx->dev_name,
			     (unsigned long long)ctx->local_key, count);
	else
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "scsipr: P-PR-PROBE '%s': own key 0x%llx visible, "
			     "%d key(s) registered — per-node PR active",
			     ctx->dev_name,
			     (unsigned long long)ctx->local_key, count);
	return 0;
}

static int scsipr_unregister_locked(struct mxfs_scsipr_ctx *ctx)
{
	int ret;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	/*
	 * (chain 23 s440b, 0.45.1): the refused same-boot dirty remount
	 * printed P302-PR-KEY-RETAINED-ON-REFUSAL and the LU then showed NO
	 * registered keys — err_scsipr calls this unconditionally and this
	 * function never consulted ctx->registered, so mxfs_scsipr_retain_key's
	 * registered=false was a no-op against it.  A key this context does not
	 * hold as its own live registration (retained fence target, or never
	 * registered) is NEVER unregistered here: the caller's "unregistered ->
	 * ledger retired" step must not run either, so this is a non-zero rc.
	 */
	if (!ctx->registered) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: P302-PR-UNREGISTER-SKIPPED '%s' key=0x%llx — "
			     "not this context's live registration (retained fence "
			     "target or never registered); leaving the LU's PR table "
			     "unchanged", ctx->dev_name,
			     (unsigned long long)ctx->local_key);
		return -ENOENT;
	}

	ret = mxfs_pal_scsi_pr_unregister(ctx->dev, ctx->local_key);
	mxfs_scsipr_snap_invalidate(ctx, "unregister");          /* */

	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: '%s' has no PR support, skipping unregister",
			     ctx->dev_name);
		ctx->registered = false;
		return 0;
	}

	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: unregister failed on '%s': %d",
			     ctx->dev_name, ret);
		return ret;
	}

	ctx->reserved = false;
	ctx->registered = false;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: unregistered key 0x%llx from '%s'",
		     (unsigned long long)ctx->local_key, ctx->dev_name);

	return 0;
}

int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
			   int max_keys, int *count, uint32_t *generation,
			   int *total)
{
	int ret;

	if (!ctx || !ctx->dev || !keys || !count || max_keys <= 0)
		return -EINVAL;

	*count = 0;
	if (total)
		*total = 0;

	ret = mxfs_pal_scsi_pr_read_keys(ctx->dev, keys, max_keys, count,
					 generation, total);

	if (ret == -EOPNOTSUPP) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "scsipr: '%s' has no PR read_keys support",
			     ctx->dev_name);
		return ret;
	}

	if (ret) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "scsipr: read_keys failed on '%s': %d",
			     ctx->dev_name, ret);
		return ret;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "scsipr: read_keys on '%s': %d keys",
		     ctx->dev_name, *count);

	return 0;
}
