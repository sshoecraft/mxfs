/*
 * MXFS — Multinode XFS
 * DLM protocol engine
 *
 * The core of MXFS. Manages the distributed lock table, processes lock
 * requests from the local kernel module and remote peers, enforces the
 * 6-mode compatibility matrix, and handles lock queuing and conversion.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "mxfsd_dlm.h"
#include "mxfsd_log.h"

/*
 * Compatibility matrix: compat[held][requested] = 1 means compatible
 *
 *        NL  CR  CW  PR  PW  EX
 *   NL    1   1   1   1   1   1
 *   CR    1   1   1   1   1   0
 *   CW    1   1   1   0   0   0
 *   PR    1   1   0   1   0   0
 *   PW    1   1   0   0   0   0
 *   EX    1   0   0   0   0   0
 */
static const int lock_compat[MXFS_LOCK_MODE_COUNT][MXFS_LOCK_MODE_COUNT] = {
	/* NL */ { 1, 1, 1, 1, 1, 1 },
	/* CR */ { 1, 1, 1, 1, 1, 0 },
	/* CW */ { 1, 1, 1, 0, 0, 0 },
	/* PR */ { 1, 1, 0, 1, 0, 0 },
	/* PW */ { 1, 1, 0, 0, 0, 0 },
	/* EX */ { 1, 0, 0, 0, 0, 0 },
};

static const char *lock_mode_names[] = {
	"NL", "CR", "CW", "PR", "PW", "EX"
};

static const char *lock_state_names[] = {
	"UNLOCKED", "WAITING", "GRANTED", "CONVERTING", "BLOCKED"
};

/* Get current monotonic time in milliseconds */
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Hash a resource ID into a bucket index */
static uint32_t resource_hash(const struct mxfs_resource_id *res,
                              uint32_t bucket_count)
{
	/* FNV-1a hash over the resource ID fields */
	uint32_t hash = 2166136261u;
	const uint8_t *data = (const uint8_t *)res;
	size_t len = sizeof(*res);

	for (size_t i = 0; i < len; i++) {
		hash ^= data[i];
		hash *= 16777619u;
	}
	return hash % bucket_count;
}

/* Compare two resource IDs for equality */
static int resource_equal(const struct mxfs_resource_id *a,
                          const struct mxfs_resource_id *b)
{
	return a->volume == b->volume &&
	       a->ino == b->ino &&
	       a->offset == b->offset &&
	       a->ag_number == b->ag_number &&
	       a->type == b->type;
}

static const char *mode_name(enum mxfs_lock_mode mode)
{
	if (mode < MXFS_LOCK_MODE_COUNT)
		return lock_mode_names[mode];
	return "??";
}

static const char *state_name(enum mxfs_lock_state state)
{
	if (state <= MXFS_LSTATE_BLOCKED)
		return lock_state_names[state];
	return "??";
}

/*
 * Allocate and initialize a new lock entry.
 */
static struct mxfsd_lock *lock_alloc(const struct mxfs_resource_id *resource,
                                     mxfs_node_id_t owner,
                                     enum mxfs_lock_mode mode,
                                     enum mxfs_lock_state state,
                                     uint32_t flags)
{
	struct mxfsd_lock *lk = calloc(1, sizeof(*lk));
	if (!lk)
		return NULL;

	lk->resource = *resource;
	lk->owner = owner;
	lk->mode = mode;
	lk->state = state;
	lk->flags = flags;
	if (state == MXFS_LSTATE_GRANTED)
		lk->granted_at_ms = now_ms();
	lk->next = NULL;
	return lk;
}

int mxfsd_dlm_modes_compatible(enum mxfs_lock_mode held,
                               enum mxfs_lock_mode requested)
{
	if (held >= MXFS_LOCK_MODE_COUNT || requested >= MXFS_LOCK_MODE_COUNT)
		return 0;
	return lock_compat[held][requested];
}

int mxfsd_dlm_init(struct mxfsd_dlm_ctx *ctx, mxfs_node_id_t local_node,
                   uint32_t table_size)
{
	if (!ctx || table_size == 0)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node = local_node;
	ctx->current_epoch = 1;

	ctx->table.bucket_count = table_size;
	ctx->table.lock_count = 0;

	ctx->table.buckets = calloc(table_size, sizeof(struct mxfsd_lock *));
	if (!ctx->table.buckets) {
		mxfsd_err("dlm: failed to allocate lock table (%u buckets)",
		          table_size);
		return -ENOMEM;
	}

	int rc = pthread_rwlock_init(&ctx->table.rwlock, NULL);
	if (rc != 0) {
		mxfsd_err("dlm: pthread_rwlock_init failed: %s", strerror(rc));
		free(ctx->table.buckets);
		ctx->table.buckets = NULL;
		return -rc;
	}

	rc = pthread_mutex_init(&ctx->epoch_lock, NULL);
	if (rc != 0) {
		mxfsd_err("dlm: pthread_mutex_init (epoch) failed: %s",
		          strerror(rc));
		pthread_rwlock_destroy(&ctx->table.rwlock);
		free(ctx->table.buckets);
		ctx->table.buckets = NULL;
		return -rc;
	}

	mxfsd_info("dlm: initialized lock table with %u buckets for node %u",
	           table_size, local_node);
	return 0;
}

void mxfsd_dlm_shutdown(struct mxfsd_dlm_ctx *ctx)
{
	if (!ctx || !ctx->table.buckets)
		return;

	pthread_rwlock_wrlock(&ctx->table.rwlock);

	/* Free all lock entries */
	for (uint32_t i = 0; i < ctx->table.bucket_count; i++) {
		struct mxfsd_lock *lk = ctx->table.buckets[i];
		while (lk) {
			struct mxfsd_lock *next = lk->next;
			free(lk);
			lk = next;
		}
		ctx->table.buckets[i] = NULL;
	}

	uint32_t count = ctx->table.lock_count;
	ctx->table.lock_count = 0;

	pthread_rwlock_unlock(&ctx->table.rwlock);
	pthread_rwlock_destroy(&ctx->table.rwlock);
	pthread_mutex_destroy(&ctx->epoch_lock);

	free(ctx->table.buckets);
	ctx->table.buckets = NULL;

	mxfsd_info("dlm: shutdown, freed %u lock entries", count);
}

int mxfsd_dlm_lock_request(struct mxfsd_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           mxfs_node_id_t requester,
                           enum mxfs_lock_mode mode, uint32_t flags)
{
	if (!ctx || !resource || mode >= MXFS_LOCK_MODE_COUNT)
		return -EINVAL;

	uint32_t bucket = resource_hash(resource, ctx->table.bucket_count);

	pthread_rwlock_wrlock(&ctx->table.rwlock);

	struct mxfsd_lock *chain = ctx->table.buckets[bucket];

	/* Check if this node already holds or is waiting for this resource */
	for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == requester) {
			if (lk->state == MXFS_LSTATE_GRANTED ||
			    lk->state == MXFS_LSTATE_WAITING ||
			    lk->state == MXFS_LSTATE_BLOCKED) {
				mxfsd_dbg("dlm: node %u already has %s lock "
				          "(%s) on vol=%lu ino=%lu",
				          requester, mode_name(lk->mode),
				          state_name(lk->state),
				          (unsigned long)resource->volume,
				          (unsigned long)resource->ino);
				pthread_rwlock_unlock(&ctx->table.rwlock);
				return -EEXIST;
			}
		}
	}

	/* Check compatibility with all granted locks on this resource */
	int compat = 1;
	for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED)
			continue;
		if (!lock_compat[lk->mode][mode]) {
			compat = 0;
			break;
		}
	}

	if (!compat && (flags & MXFS_LKF_NOQUEUE)) {
		mxfsd_dbg("dlm: denying %s lock on vol=%lu ino=%lu "
		          "to node %u (NOQUEUE, incompatible)",
		          mode_name(mode),
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          requester);
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return -EAGAIN;
	}

	if (!compat && (flags & MXFS_LKF_TRYLOCK)) {
		mxfsd_dbg("dlm: trylock failed for %s on vol=%lu ino=%lu "
		          "to node %u",
		          mode_name(mode),
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          requester);
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return -EWOULDBLOCK;
	}

	/* Create the lock entry */
	enum mxfs_lock_state initial_state = compat ?
		MXFS_LSTATE_GRANTED : MXFS_LSTATE_WAITING;

	struct mxfsd_lock *newlk = lock_alloc(resource, requester, mode,
	                                      initial_state, flags);
	if (!newlk) {
		mxfsd_err("dlm: out of memory allocating lock for node %u",
		          requester);
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return -ENOMEM;
	}

	/* Insert at head of bucket chain */
	newlk->next = ctx->table.buckets[bucket];
	ctx->table.buckets[bucket] = newlk;
	ctx->table.lock_count++;

	if (compat) {
		mxfsd_dbg("dlm: granted %s lock on vol=%lu ino=%lu to node %u",
		          mode_name(mode),
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          requester);
	} else {
		mxfsd_dbg("dlm: queued %s lock on vol=%lu ino=%lu "
		          "for node %u (waiting)",
		          mode_name(mode),
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          requester);
	}

	pthread_rwlock_unlock(&ctx->table.rwlock);

	return compat ? 0 : -EINPROGRESS;
}

int mxfsd_dlm_lock_release(struct mxfsd_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           mxfs_node_id_t owner)
{
	if (!ctx || !resource)
		return -EINVAL;

	uint32_t bucket = resource_hash(resource, ctx->table.bucket_count);

	pthread_rwlock_wrlock(&ctx->table.rwlock);

	struct mxfsd_lock **pp = &ctx->table.buckets[bucket];
	struct mxfsd_lock *found = NULL;

	/* Find and unlink the lock entry */
	while (*pp) {
		struct mxfsd_lock *lk = *pp;
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == owner &&
		    (lk->state == MXFS_LSTATE_GRANTED ||
		     lk->state == MXFS_LSTATE_CONVERTING)) {
			*pp = lk->next;
			found = lk;
			ctx->table.lock_count--;
			break;
		}
		pp = &lk->next;
	}

	if (!found) {
		/* Also try to remove a queued/waiting lock */
		pp = &ctx->table.buckets[bucket];
		while (*pp) {
			struct mxfsd_lock *lk = *pp;
			if (resource_equal(&lk->resource, resource) &&
			    lk->owner == owner) {
				*pp = lk->next;
				found = lk;
				ctx->table.lock_count--;
				break;
			}
			pp = &lk->next;
		}
	}

	if (!found) {
		mxfsd_dbg("dlm: release failed, no lock on vol=%lu ino=%lu "
		          "held by node %u",
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          owner);
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return -ENOENT;
	}

	mxfsd_dbg("dlm: released %s lock (%s) on vol=%lu ino=%lu "
	          "from node %u",
	          mode_name(found->mode), state_name(found->state),
	          (unsigned long)resource->volume,
	          (unsigned long)resource->ino,
	          owner);

	free(found);

	/* Try to promote waiters now that a lock was released */
	struct mxfsd_lock *chain = ctx->table.buckets[bucket];
	/* We need to scan the chain for locks matching this resource */
	int promoted = 0;
	for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_WAITING &&
		    lk->state != MXFS_LSTATE_BLOCKED)
			continue;

		/* Check if this waiter is now compatible with all granted */
		int ok = 1;
		for (struct mxfsd_lock *other = chain; other; other = other->next) {
			if (!resource_equal(&other->resource, resource))
				continue;
			if (other->state != MXFS_LSTATE_GRANTED)
				continue;
			if (other->owner == lk->owner)
				continue;
			if (!lock_compat[other->mode][lk->mode]) {
				ok = 0;
				break;
			}
		}

		if (ok) {
			mxfsd_dbg("dlm: promoting queued %s lock on "
			          "vol=%lu ino=%lu to node %u",
			          mode_name(lk->mode),
			          (unsigned long)lk->resource.volume,
			          (unsigned long)lk->resource.ino,
			          lk->owner);
			lk->state = MXFS_LSTATE_GRANTED;
			lk->granted_at_ms = now_ms();
			promoted++;
		} else {
			lk->state = MXFS_LSTATE_BLOCKED;
		}
	}

	if (promoted > 0)
		mxfsd_dbg("dlm: promoted %d queued locks after release", promoted);

	pthread_rwlock_unlock(&ctx->table.rwlock);
	return 0;
}

int mxfsd_dlm_lock_convert(struct mxfsd_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           mxfs_node_id_t owner,
                           enum mxfs_lock_mode new_mode)
{
	if (!ctx || !resource || new_mode >= MXFS_LOCK_MODE_COUNT)
		return -EINVAL;

	uint32_t bucket = resource_hash(resource, ctx->table.bucket_count);

	pthread_rwlock_wrlock(&ctx->table.rwlock);

	/* Find the lock to convert */
	struct mxfsd_lock *target = NULL;
	struct mxfsd_lock *chain = ctx->table.buckets[bucket];

	for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
		if (resource_equal(&lk->resource, resource) &&
		    lk->owner == owner &&
		    lk->state == MXFS_LSTATE_GRANTED) {
			target = lk;
			break;
		}
	}

	if (!target) {
		mxfsd_dbg("dlm: convert failed, no granted lock on "
		          "vol=%lu ino=%lu for node %u",
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          owner);
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return -ENOENT;
	}

	enum mxfs_lock_mode old_mode = target->mode;

	/* Downgrade is always allowed */
	if (new_mode <= old_mode) {
		mxfsd_dbg("dlm: converting lock on vol=%lu ino=%lu "
		          "node %u: %s -> %s (downgrade)",
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          owner, mode_name(old_mode), mode_name(new_mode));
		target->mode = new_mode;
		target->granted_at_ms = now_ms();

		/* Downgrade may allow queued locks to be granted */
		for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
			if (!resource_equal(&lk->resource, resource))
				continue;
			if (lk->state != MXFS_LSTATE_WAITING &&
			    lk->state != MXFS_LSTATE_BLOCKED)
				continue;

			int ok = 1;
			for (struct mxfsd_lock *h = chain; h; h = h->next) {
				if (!resource_equal(&h->resource, resource))
					continue;
				if (h->state != MXFS_LSTATE_GRANTED)
					continue;
				if (h->owner == lk->owner)
					continue;
				if (!lock_compat[h->mode][lk->mode]) {
					ok = 0;
					break;
				}
			}
			if (ok) {
				lk->state = MXFS_LSTATE_GRANTED;
				lk->granted_at_ms = now_ms();
				mxfsd_dbg("dlm: promoted %s lock for node %u "
				          "after downgrade",
				          mode_name(lk->mode), lk->owner);
			}
		}

		pthread_rwlock_unlock(&ctx->table.rwlock);
		return 0;
	}

	/* Upgrade — check compatibility with other holders */
	int compat = 1;
	for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
		if (!resource_equal(&lk->resource, resource))
			continue;
		if (lk->state != MXFS_LSTATE_GRANTED)
			continue;
		if (lk->owner == owner)
			continue;
		if (!lock_compat[lk->mode][new_mode]) {
			compat = 0;
			break;
		}
	}

	if (compat) {
		mxfsd_dbg("dlm: converting lock on vol=%lu ino=%lu "
		          "node %u: %s -> %s (upgrade granted)",
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          owner, mode_name(old_mode), mode_name(new_mode));
		target->mode = new_mode;
		target->granted_at_ms = now_ms();
		pthread_rwlock_unlock(&ctx->table.rwlock);
		return 0;
	}

	/* Upgrade blocked — mark as converting */
	mxfsd_dbg("dlm: converting lock on vol=%lu ino=%lu "
	          "node %u: %s -> %s (blocked, queueing)",
	          (unsigned long)resource->volume,
	          (unsigned long)resource->ino,
	          owner, mode_name(old_mode), mode_name(new_mode));

	target->state = MXFS_LSTATE_CONVERTING;
	target->mode = new_mode;

	pthread_rwlock_unlock(&ctx->table.rwlock);
	return -EINPROGRESS;
}

int mxfsd_dlm_purge_node(struct mxfsd_dlm_ctx *ctx, mxfs_node_id_t node)
{
	if (!ctx)
		return -EINVAL;

	mxfsd_notice("dlm: purging all locks for dead node %u", node);

	pthread_rwlock_wrlock(&ctx->table.rwlock);

	int purged = 0;

	for (uint32_t i = 0; i < ctx->table.bucket_count; i++) {
		struct mxfsd_lock **pp = &ctx->table.buckets[i];

		while (*pp) {
			struct mxfsd_lock *lk = *pp;
			if (lk->owner == node) {
				*pp = lk->next;
				mxfsd_dbg("dlm: purged %s lock (%s) on "
				          "vol=%lu ino=%lu from dead node %u",
				          mode_name(lk->mode),
				          state_name(lk->state),
				          (unsigned long)lk->resource.volume,
				          (unsigned long)lk->resource.ino,
				          node);
				free(lk);
				ctx->table.lock_count--;
				purged++;
			} else {
				pp = &lk->next;
			}
		}
	}

	/* After purging, try to promote waiters in all buckets that may
	 * have had locks from the dead node */
	int promoted = 0;
	for (uint32_t i = 0; i < ctx->table.bucket_count; i++) {
		struct mxfsd_lock *chain = ctx->table.buckets[i];
		if (!chain)
			continue;

		for (struct mxfsd_lock *lk = chain; lk; lk = lk->next) {
			if (lk->state != MXFS_LSTATE_WAITING &&
			    lk->state != MXFS_LSTATE_BLOCKED)
				continue;

			int ok = 1;
			for (struct mxfsd_lock *h = chain; h; h = h->next) {
				if (!resource_equal(&h->resource, &lk->resource))
					continue;
				if (h->state != MXFS_LSTATE_GRANTED)
					continue;
				if (h->owner == lk->owner)
					continue;
				if (!lock_compat[h->mode][lk->mode]) {
					ok = 0;
					break;
				}
			}
			if (ok) {
				lk->state = MXFS_LSTATE_GRANTED;
				lk->granted_at_ms = now_ms();
				promoted++;
			}
		}
	}

	pthread_rwlock_unlock(&ctx->table.rwlock);

	mxfsd_notice("dlm: purged %d locks from node %u, promoted %d waiters",
	             purged, node, promoted);

	return purged;
}

mxfs_epoch_t mxfsd_dlm_advance_epoch(struct mxfsd_dlm_ctx *ctx)
{
	if (!ctx)
		return 0;

	pthread_mutex_lock(&ctx->epoch_lock);
	ctx->current_epoch++;
	mxfs_epoch_t epoch = ctx->current_epoch;
	pthread_mutex_unlock(&ctx->epoch_lock);

	mxfsd_info("dlm: epoch advanced to %lu", (unsigned long)epoch);
	return epoch;
}

mxfs_epoch_t mxfsd_dlm_get_epoch(struct mxfsd_dlm_ctx *ctx)
{
	if (!ctx)
		return 0;

	pthread_mutex_lock(&ctx->epoch_lock);
	mxfs_epoch_t epoch = ctx->current_epoch;
	pthread_mutex_unlock(&ctx->epoch_lock);

	return epoch;
}
