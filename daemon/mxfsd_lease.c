/*
 * MXFS — Multinode XFS
 * Lease management
 *
 * Runs two threads: one to periodically renew the local node's lease
 * with all peers, and one to monitor remote node leases for expiry.
 * Lease expiry triggers the node-death path: DLM purge + journal recovery.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "mxfsd_lease.h"
#include "mxfsd_log.h"

/* Expire callback state */
static mxfsd_lease_expire_fn expire_callback;
static void *expire_user_data;

/* Get monotonic time in milliseconds */
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Sleep for a given number of milliseconds, interruptible by !running */
static void sleep_ms(struct mxfsd_lease_ctx *ctx, uint64_t ms)
{
	uint64_t end = now_ms() + ms;
	while (ctx->running) {
		uint64_t remaining = end - now_ms();
		if (remaining == 0 || remaining > ms)
			break;
		struct timespec ts;
		uint64_t chunk = remaining > 250 ? 250 : remaining;
		ts.tv_sec = (time_t)(chunk / 1000);
		ts.tv_nsec = (long)((chunk % 1000) * 1000000);
		nanosleep(&ts, NULL);
	}
}

/*
 * Renewal thread: periodically marks the local node's lease as renewed.
 * In a full system this would also send LEASE_RENEW messages to all peers
 * via the peer subsystem, but the lease module itself just tracks state.
 */
static void *renew_thread_fn(void *arg)
{
	struct mxfsd_lease_ctx *ctx = arg;

	mxfsd_info("lease: renewal thread started (interval %lu ms)",
	           (unsigned long)ctx->renew_interval_ms);

	while (ctx->running) {
		sleep_ms(ctx, ctx->renew_interval_ms);
		if (!ctx->running)
			break;

		mxfsd_lease_renew_local(ctx);
	}

	mxfsd_info("lease: renewal thread exiting");
	return NULL;
}

/*
 * Monitor thread: checks all registered remote nodes for lease expiry.
 * If a node has missed enough renewals that its lease has expired,
 * transitions it through SUSPECT -> DEAD and fires the expire callback.
 */
static void *monitor_thread_fn(void *arg)
{
	struct mxfsd_lease_ctx *ctx = arg;

	mxfsd_info("lease: monitor thread started (timeout %lu ms)",
	           (unsigned long)ctx->timeout_ms);

	while (ctx->running) {
		sleep_ms(ctx, ctx->renew_interval_ms);
		if (!ctx->running)
			break;

		uint64_t ts = now_ms();

		pthread_mutex_lock(&ctx->lock);

		for (int i = 0; i < ctx->node_count; i++) {
			struct mxfsd_node_lease *nl = &ctx->nodes[i];

			/* Skip local node and already-dead nodes */
			if (nl->node_id == ctx->local_node)
				continue;
			if (nl->state == MXFS_NODE_DEAD ||
			    nl->state == MXFS_NODE_RECOVERING)
				continue;

			/* Check if lease has expired */
			if (nl->last_renewal_ms == 0)
				continue;

			uint64_t elapsed = ts - nl->last_renewal_ms;

			if (elapsed >= ctx->timeout_ms) {
				/* Lease expired — node is dead */
				mxfsd_err("lease: node %u lease expired "
				          "(last renewal %lu ms ago, "
				          "timeout %lu ms)",
				          nl->node_id,
				          (unsigned long)elapsed,
				          (unsigned long)ctx->timeout_ms);

				nl->state = MXFS_NODE_DEAD;
				nl->missed_renewals = 0;

				mxfs_node_id_t dead_node = nl->node_id;

				pthread_mutex_unlock(&ctx->lock);

				/* Fire expire callback outside the lock */
				if (expire_callback) {
					mxfsd_notice("lease: firing expire "
					             "callback for node %u",
					             dead_node);
					expire_callback(dead_node,
					                expire_user_data);
				}

				pthread_mutex_lock(&ctx->lock);

			} else if (elapsed >= ctx->default_duration_ms) {
				/* Missed a renewal — suspect */
				if (nl->state == MXFS_NODE_ACTIVE) {
					nl->state = MXFS_NODE_SUSPECT;
					nl->missed_renewals++;
					mxfsd_warn("lease: node %u is suspect "
					           "(missed %d renewals, "
					           "elapsed %lu ms)",
					           nl->node_id,
					           nl->missed_renewals,
					           (unsigned long)elapsed);
				} else if (nl->state == MXFS_NODE_SUSPECT) {
					nl->missed_renewals++;
					mxfsd_warn("lease: node %u still "
					           "suspect (missed %d renewals)",
					           nl->node_id,
					           nl->missed_renewals);
				}
			}
		}

		pthread_mutex_unlock(&ctx->lock);
	}

	mxfsd_info("lease: monitor thread exiting");
	return NULL;
}

int mxfsd_lease_init(struct mxfsd_lease_ctx *ctx, mxfs_node_id_t local_node,
                     uint64_t duration_ms, uint64_t renew_ms,
                     uint64_t timeout_ms)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node = local_node;
	ctx->default_duration_ms = duration_ms;
	ctx->renew_interval_ms = renew_ms;
	ctx->timeout_ms = timeout_ms;
	ctx->node_count = 0;
	ctx->running = false;

	expire_callback = NULL;
	expire_user_data = NULL;

	int rc = pthread_mutex_init(&ctx->lock, NULL);
	if (rc != 0) {
		mxfsd_err("lease: pthread_mutex_init failed: %s",
		          strerror(rc));
		return -rc;
	}

	/* Register the local node */
	rc = mxfsd_lease_register_node(ctx, local_node);
	if (rc < 0) {
		pthread_mutex_destroy(&ctx->lock);
		return rc;
	}

	ctx->running = true;

	/* Start renewal thread */
	rc = pthread_create(&ctx->renew_thread, NULL, renew_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("lease: failed to create renewal thread: %s",
		          strerror(rc));
		ctx->running = false;
		pthread_mutex_destroy(&ctx->lock);
		return -rc;
	}

	/* Start monitor thread */
	rc = pthread_create(&ctx->monitor_thread, NULL, monitor_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("lease: failed to create monitor thread: %s",
		          strerror(rc));
		ctx->running = false;
		pthread_join(ctx->renew_thread, NULL);
		pthread_mutex_destroy(&ctx->lock);
		return -rc;
	}

	mxfsd_info("lease: initialized for node %u "
	           "(duration=%lu ms, renew=%lu ms, timeout=%lu ms)",
	           local_node,
	           (unsigned long)duration_ms,
	           (unsigned long)renew_ms,
	           (unsigned long)timeout_ms);

	return 0;
}

void mxfsd_lease_shutdown(struct mxfsd_lease_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->running = false;

	pthread_join(ctx->renew_thread, NULL);
	pthread_join(ctx->monitor_thread, NULL);
	pthread_mutex_destroy(&ctx->lock);

	mxfsd_info("lease: shutdown complete");
}

int mxfsd_lease_set_expire_callback(struct mxfsd_lease_ctx *ctx,
                                    mxfsd_lease_expire_fn fn,
                                    void *user_data)
{
	if (!ctx)
		return -EINVAL;

	expire_callback = fn;
	expire_user_data = user_data;

	mxfsd_dbg("lease: expire callback registered");
	return 0;
}

int mxfsd_lease_register_node(struct mxfsd_lease_ctx *ctx,
                              mxfs_node_id_t node)
{
	if (!ctx)
		return -EINVAL;

	pthread_mutex_lock(&ctx->lock);

	/* Check for duplicate */
	for (int i = 0; i < ctx->node_count; i++) {
		if (ctx->nodes[i].node_id == node) {
			pthread_mutex_unlock(&ctx->lock);
			mxfsd_dbg("lease: node %u already registered", node);
			return 0;
		}
	}

	if (ctx->node_count >= MXFS_MAX_NODES) {
		pthread_mutex_unlock(&ctx->lock);
		mxfsd_err("lease: cannot register node %u, max nodes reached",
		          node);
		return -ENOSPC;
	}

	struct mxfsd_node_lease *nl = &ctx->nodes[ctx->node_count];
	memset(nl, 0, sizeof(*nl));
	nl->node_id = node;
	nl->duration_ms = ctx->default_duration_ms;
	nl->state = (node == ctx->local_node) ?
		MXFS_NODE_ACTIVE : MXFS_NODE_JOINING;
	nl->granted_at_ms = now_ms();
	nl->last_renewal_ms = now_ms();
	nl->epoch = 0;
	nl->missed_renewals = 0;

	ctx->node_count++;

	pthread_mutex_unlock(&ctx->lock);

	mxfsd_info("lease: registered node %u (state=%s)",
	           node, node == ctx->local_node ? "ACTIVE" : "JOINING");
	return 0;
}

int mxfsd_lease_renew_local(struct mxfsd_lease_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->node_count; i++) {
		if (ctx->nodes[i].node_id == ctx->local_node) {
			ctx->nodes[i].last_renewal_ms = now_ms();
			ctx->nodes[i].state = MXFS_NODE_ACTIVE;
			ctx->nodes[i].missed_renewals = 0;
			mxfsd_dbg("lease: local lease renewed");
			pthread_mutex_unlock(&ctx->lock);
			return 0;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	mxfsd_warn("lease: local node %u not found in lease table",
	           ctx->local_node);
	return -ENOENT;
}

int mxfsd_lease_process_renewal(struct mxfsd_lease_ctx *ctx,
                                mxfs_node_id_t node, mxfs_epoch_t epoch)
{
	if (!ctx)
		return -EINVAL;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->node_count; i++) {
		if (ctx->nodes[i].node_id == node) {
			struct mxfsd_node_lease *nl = &ctx->nodes[i];
			uint64_t ts = now_ms();

			mxfsd_dbg("lease: renewal from node %u "
			          "(epoch %lu, was %s)",
			          node, (unsigned long)epoch,
			          nl->state == MXFS_NODE_ACTIVE ? "ACTIVE" :
			          nl->state == MXFS_NODE_SUSPECT ? "SUSPECT" :
			          nl->state == MXFS_NODE_JOINING ? "JOINING" :
			          "OTHER");

			nl->last_renewal_ms = ts;
			nl->epoch = epoch;
			nl->missed_renewals = 0;

			/* Transition to active if was joining or suspect */
			if (nl->state == MXFS_NODE_JOINING ||
			    nl->state == MXFS_NODE_SUSPECT) {
				nl->state = MXFS_NODE_ACTIVE;
				mxfsd_info("lease: node %u is now ACTIVE", node);
			}

			pthread_mutex_unlock(&ctx->lock);
			return 0;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	mxfsd_warn("lease: renewal from unregistered node %u", node);
	return -ENOENT;
}

bool mxfsd_lease_is_valid(struct mxfsd_lease_ctx *ctx, mxfs_node_id_t node,
                          uint64_t ts)
{
	if (!ctx)
		return false;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->node_count; i++) {
		if (ctx->nodes[i].node_id == node) {
			struct mxfsd_node_lease *nl = &ctx->nodes[i];

			if (nl->state == MXFS_NODE_DEAD ||
			    nl->state == MXFS_NODE_RECOVERING) {
				pthread_mutex_unlock(&ctx->lock);
				return false;
			}

			if (nl->last_renewal_ms == 0) {
				pthread_mutex_unlock(&ctx->lock);
				return false;
			}

			bool valid = (ts - nl->last_renewal_ms) < nl->duration_ms;
			pthread_mutex_unlock(&ctx->lock);
			return valid;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	return false;
}

struct mxfsd_node_lease *mxfsd_lease_get(struct mxfsd_lease_ctx *ctx,
                                         mxfs_node_id_t node)
{
	if (!ctx)
		return NULL;

	for (int i = 0; i < ctx->node_count; i++) {
		if (ctx->nodes[i].node_id == node)
			return &ctx->nodes[i];
	}
	return NULL;
}
