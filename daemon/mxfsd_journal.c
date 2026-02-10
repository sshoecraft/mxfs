/*
 * MXFS — Multinode XFS
 * Journal recovery coordination
 *
 * Manages journal slot assignment and coordinates recovery when a node
 * dies. The actual XFS journal replay is done by XFS itself — we handle
 * the distributed coordination: which node does the replay, ensuring
 * all locks from the dead node are purged first, and signaling completion.
 *
 * Each node claims a unique journal slot on startup. When a node dies
 * (detected via lease expiry), another node marks the dead node's slot
 * as needing recovery, claims recovery responsibility, and after
 * replaying the journal marks it complete.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <string.h>
#include <errno.h>

#include "mxfsd_journal.h"
#include "mxfsd_log.h"

int mxfsd_journal_init(struct mxfsd_journal_ctx *ctx,
                       mxfs_node_id_t local_node, int slot_count)
{
	if (slot_count <= 0 || slot_count > MXFS_MAX_NODES) {
		mxfsd_err("journal: invalid slot count %d", slot_count);
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node = local_node;
	ctx->slot_count = slot_count;
	ctx->local_slot = (uint32_t)-1;
	pthread_mutex_init(&ctx->lock, NULL);

	for (int i = 0; i < slot_count; i++) {
		ctx->slots[i].slot_id = (uint32_t)i;
		ctx->slots[i].owner = 0;
		ctx->slots[i].state = MXFSD_JSLOT_FREE;
		ctx->slots[i].recovering_node = 0;
	}

	mxfsd_info("journal: initialized with %d slots for node %u",
		   slot_count, local_node);
	return 0;
}

void mxfsd_journal_shutdown(struct mxfsd_journal_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);

	if (ctx->local_slot != (uint32_t)-1) {
		mxfsd_info("journal: releasing slot %u on shutdown",
			   ctx->local_slot);
		ctx->slots[ctx->local_slot].state = MXFSD_JSLOT_FREE;
		ctx->slots[ctx->local_slot].owner = 0;
		ctx->local_slot = (uint32_t)-1;
	}

	pthread_mutex_unlock(&ctx->lock);
	pthread_mutex_destroy(&ctx->lock);
}

int mxfsd_journal_claim_slot(struct mxfsd_journal_ctx *ctx)
{
	int rc = -ENOSPC;

	pthread_mutex_lock(&ctx->lock);

	if (ctx->local_slot != (uint32_t)-1) {
		mxfsd_warn("journal: node %u already has slot %u",
			   ctx->local_node, ctx->local_slot);
		pthread_mutex_unlock(&ctx->lock);
		return 0;
	}

	for (int i = 0; i < ctx->slot_count; i++) {
		if (ctx->slots[i].state == MXFSD_JSLOT_FREE) {
			ctx->slots[i].state = MXFSD_JSLOT_ACTIVE;
			ctx->slots[i].owner = ctx->local_node;
			ctx->local_slot = (uint32_t)i;
			rc = 0;
			mxfsd_info("journal: node %u claimed slot %d",
				   ctx->local_node, i);
			break;
		}
	}

	if (rc)
		mxfsd_err("journal: no free slots for node %u", ctx->local_node);

	pthread_mutex_unlock(&ctx->lock);
	return rc;
}

void mxfsd_journal_release_slot(struct mxfsd_journal_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);

	if (ctx->local_slot == (uint32_t)-1) {
		pthread_mutex_unlock(&ctx->lock);
		return;
	}

	uint32_t slot = ctx->local_slot;
	mxfsd_info("journal: node %u releasing slot %u",
		   ctx->local_node, slot);

	ctx->slots[slot].state = MXFSD_JSLOT_FREE;
	ctx->slots[slot].owner = 0;
	ctx->local_slot = (uint32_t)-1;

	pthread_mutex_unlock(&ctx->lock);
}

int mxfsd_journal_mark_needs_recovery(struct mxfsd_journal_ctx *ctx,
                                      mxfs_node_id_t dead_node)
{
	int rc = -ENOENT;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->slot_count; i++) {
		if (ctx->slots[i].owner == dead_node &&
		    ctx->slots[i].state == MXFSD_JSLOT_ACTIVE) {
			ctx->slots[i].state = MXFSD_JSLOT_NEEDS_RECOVERY;
			mxfsd_notice("journal: slot %d (node %u) marked for recovery",
				     i, dead_node);
			rc = 0;
			break;
		}
	}

	if (rc)
		mxfsd_warn("journal: no active slot found for dead node %u",
			   dead_node);

	pthread_mutex_unlock(&ctx->lock);
	return rc;
}

int mxfsd_journal_begin_recovery(struct mxfsd_journal_ctx *ctx,
                                 mxfs_node_id_t dead_node)
{
	int rc = -ENOENT;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->slot_count; i++) {
		if (ctx->slots[i].owner == dead_node &&
		    ctx->slots[i].state == MXFSD_JSLOT_NEEDS_RECOVERY) {
			ctx->slots[i].state = MXFSD_JSLOT_RECOVERING;
			ctx->slots[i].recovering_node = ctx->local_node;
			mxfsd_notice("journal: node %u beginning recovery "
				     "of slot %d (dead node %u)",
				     ctx->local_node, i, dead_node);
			rc = 0;
			break;
		}
	}

	if (rc == -ENOENT) {
		/* Check if already being recovered */
		for (int i = 0; i < ctx->slot_count; i++) {
			if (ctx->slots[i].owner == dead_node &&
			    ctx->slots[i].state == MXFSD_JSLOT_RECOVERING) {
				mxfsd_warn("journal: slot for node %u already "
					   "being recovered by node %u",
					   dead_node,
					   ctx->slots[i].recovering_node);
				rc = -EBUSY;
				break;
			}
		}
	}

	if (rc == -ENOENT)
		mxfsd_warn("journal: no slot needing recovery for node %u",
			   dead_node);

	pthread_mutex_unlock(&ctx->lock);
	return rc;
}

int mxfsd_journal_finish_recovery(struct mxfsd_journal_ctx *ctx,
                                  mxfs_node_id_t dead_node)
{
	int rc = -ENOENT;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->slot_count; i++) {
		if (ctx->slots[i].owner == dead_node &&
		    ctx->slots[i].state == MXFSD_JSLOT_RECOVERING) {
			mxfsd_notice("journal: recovery of slot %d "
				     "(dead node %u) complete", i, dead_node);
			ctx->slots[i].state = MXFSD_JSLOT_FREE;
			ctx->slots[i].owner = 0;
			ctx->slots[i].recovering_node = 0;
			rc = 0;
			break;
		}
	}

	if (rc)
		mxfsd_warn("journal: no recovering slot for node %u",
			   dead_node);

	pthread_mutex_unlock(&ctx->lock);
	return rc;
}

bool mxfsd_journal_needs_recovery(struct mxfsd_journal_ctx *ctx,
                                  mxfs_node_id_t node)
{
	bool result = false;

	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->slot_count; i++) {
		if (ctx->slots[i].owner == node &&
		    ctx->slots[i].state == MXFSD_JSLOT_NEEDS_RECOVERY) {
			result = true;
			break;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	return result;
}
