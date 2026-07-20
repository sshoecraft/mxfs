/*
 * MXFS — Multinode XFS
 * NET2 transport — routing providers (§7.A)
 *
 * Step-2 scope: the MESH provider only.  route(dst) is the direct link
 * for dst's slot; there are no relays, no TTL, no alternate path.  The
 * OVERLAY provider (deterministic ring+finger neighbor set, greedy
 * closest-not-past routing, node-disjoint alternate, TTL/relay, epoch
 * bridging at relays) is §11 step 8 and slots in behind this vtable
 * without touching any caller.  AUTO resolves to mesh until the overlay
 * gate is green at the largest testable N (§14 decision).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_overlay.h"

static struct net2_link *net2_mesh_route(struct mxfs_net2_ctx *ctx,
                                         uint16_t dst_slot)
{
	if (dst_slot >= MXFS_MAX_NODES || dst_slot == ctx->cfg.self_slot)
		return NULL;
	return &ctx->links[dst_slot];
}

static struct net2_link *net2_mesh_route_alt(struct mxfs_net2_ctx *ctx,
                                             uint16_t dst_slot)
{
	(void)ctx;
	(void)dst_slot;
	return NULL;                       /* mesh has no alternate path */
}

/* ctx->lock held: mark the desired link set from the committed view.
 * New links open eagerly (the RT connect sweep picks desired+DOWN links
 * up on its next tick); dropped ones close lazily after their sessions'
 * retransmit entries drain (RT sweep in net2.c, §7.A). */
static void net2_mesh_view_update(struct mxfs_net2_ctx *ctx)
{
	uint16_t slot;

	for (slot = 0; slot < MXFS_MAX_NODES; slot++) {
		struct net2_link *link = &ctx->links[slot];
		bool want = (ctx->member_mask & (1ULL << slot)) != 0 &&
		            slot != ctx->cfg.self_slot;

		mxfs_pal_mutex_lock(link->lock);
		link->desired = want;
		mxfs_pal_mutex_unlock(link->lock);
	}
}

static const struct net2_provider net2_mesh_provider = {
	.name = "mesh",
	.route = net2_mesh_route,
	.route_alt = net2_mesh_route_alt,
	.view_update = net2_mesh_view_update,
};

const struct net2_provider *net2_provider_get(uint8_t topology)
{
	switch (topology) {
	case MXFS_NET2_TOPO_AUTO:
	case MXFS_NET2_TOPO_MESH:
		return &net2_mesh_provider;
	case MXFS_NET2_TOPO_OVERLAY:
		/* Not built until §11 step 8; fail-safe to mesh with a
		 * loud log so a premature modparam is visible. */
		mxfs_pal_log(MXFS_LOG_WARN,
		             "net2: overlay provider not available yet; "
		             "using mesh");
		return &net2_mesh_provider;
	default:
		return &net2_mesh_provider;
	}
}
