/*
 * MXFS — Multinode XFS
 * NET2 transport — routing providers (engine-internal)
 *
 * §7.A routing abstraction.  Step 2 ships the MESH provider only:
 * route(dst) = the direct link, no relays, no TTL, no alternate.
 * The OVERLAY provider (ring+fingers, greedy routing, node-disjoint
 * alternate, TTL/relay) slots in behind the same vtable at step 8
 * without touching callers.  Membership traffic always rides DIRECT
 * links regardless of provider (§7.C — no circularity).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_OVERLAY_H
#define MXFS_LIBMXFS_NET2_OVERLAY_H

#include "net2_ctx.h"

/* Resolve a topology value (enum mxfs_net2_topology) to a provider.
 * AUTO resolves to mesh until the overlay gate (§11 step 8) is green. */
const struct net2_provider *net2_provider_get(uint8_t topology);

#endif /* MXFS_LIBMXFS_NET2_OVERLAY_H */
