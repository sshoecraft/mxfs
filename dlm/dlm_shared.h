/*
 * MXFS — Multinode XFS
 * DLM shared code — resource hashing, lock-mode compatibility matrix,
 * CAW slot holder-bitmap validity (§11 step 3 lift, DLM_IMPL_PLAN.md)
 *
 * Pure moves out of dlm.c / dlm_caw.c: identical bodies, identical
 * signatures — the only change is static → extern so the legacy TCP
 * DLM, the CAW DLM, and (step 4 on) the NET2 lock plane share ONE
 * copy.  Dual-build (Invariant 4): the popcount helper is the sole
 * platform fork, moved here from dlm_caw.c's two #ifdef branches.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef MXFS_DLM_SHARED_H
#define MXFS_DLM_SHARED_H

#include "dlm.h"        /* mxfs_dlm_bast_cb — dlm_caw.h needs it and
                         * is not self-contained (dlm_caw.c includes
                         * dlm.h first; same order here)             */
#include "dlm_caw.h"    /* pal.h + mxfs_common.h + mxfs_dlm.h +
                         * struct mxfs_caw_lock_slot                 */

#ifdef __KERNEL__
#include <linux/bitops.h>
static inline unsigned int mxfs_pal_popcount64(uint64_t x)
{
	return hweight64(x);
}
#else
static inline unsigned int mxfs_pal_popcount64(uint64_t x)
{
	unsigned int n = 0;
	while (x) { n += (unsigned int)(x & 1); x >>= 1; }
	return n;
}
#endif

/* Lock-mode compatibility matrix (dlm_caw.c/dlm.c had one copy each). */
extern const int lock_compat[MXFS_LOCK_MODE_COUNT][MXFS_LOCK_MODE_COUNT];

/* FNV-1a over raw resource_id bytes (was dlm.c resource_hash_raw ==
 * dlm_caw.c fnv1a_hash, byte-identical bodies). */
uint32_t resource_hash_raw(const struct mxfs_resource_id *res);

bool resource_equal(const struct mxfs_resource_id *a,
                    const struct mxfs_resource_id *b);

/* CAW slot holder-bitmap readers (const side only; the mutable
 * holders_for_mode pointer variant stays private to dlm_caw.c). */
uint64_t holders_for_mode_const(const struct mxfs_caw_lock_slot *slot,
                                uint8_t mode);
bool is_compatible(const struct mxfs_caw_lock_slot *slot, uint8_t mode);
uint8_t recompute_granted_mode(const struct mxfs_caw_lock_slot *slot);

/* EX/PW single-holder popcount validity (v0.3.83 stale-disk-garbage
 * detection, lifted from slot_appears_corrupt).  true = valid. */
bool caw_slot_holders_popcount_ok(const struct mxfs_caw_lock_slot *s);

#endif /* MXFS_DLM_SHARED_H */
