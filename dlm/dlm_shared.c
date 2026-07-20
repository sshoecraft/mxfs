/*
 * MXFS — Multinode XFS
 * DLM shared code — see dlm_shared.h.  Function bodies are verbatim
 * moves (gate 3 proves CAW-neutrality: run.sh 2 caw posix_multi
 * dlm_fairness).  Indentation follows each body's home file.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "dlm_shared.h"

/* ─── Compatibility matrix ───
 *
 *        NL  CR  CW  PR  PW  EX
 *   NL    1   1   1   1   1   1
 *   CR    1   1   1   1   1   0
 *   CW    1   1   1   0   0   0
 *   PR    1   1   0   1   0   0
 *   PW    1   1   0   0   0   0
 *   EX    1   0   0   0   0   0
 */
const int lock_compat[MXFS_LOCK_MODE_COUNT][MXFS_LOCK_MODE_COUNT] = {
	/* NL */ { 1, 1, 1, 1, 1, 1 },
	/* CR */ { 1, 1, 1, 1, 1, 0 },
	/* CW */ { 1, 1, 1, 0, 0, 0 },
	/* PR */ { 1, 1, 0, 1, 0, 0 },
	/* PW */ { 1, 1, 0, 0, 0, 0 },
	/* EX */ { 1, 0, 0, 0, 0, 0 },
};

/* ─── FNV-1a hash over raw resource_id bytes ─── */

uint32_t resource_hash_raw(const struct mxfs_resource_id *res)
{
    uint32_t hash = 2166136261u;
    const uint8_t *data = (const uint8_t *)res;
    size_t i;

    for (i = 0; i < sizeof(*res); i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

bool resource_equal(const struct mxfs_resource_id *a,
                    const struct mxfs_resource_id *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/* ─── Holder bitmap by mode (const reader) ─── */

uint64_t holders_for_mode_const(const struct mxfs_caw_lock_slot *slot,
					uint8_t mode)
{
	switch (mode) {
	case MXFS_LOCK_EX: return slot->holders_ex;
	case MXFS_LOCK_PW: return slot->holders_pw;
	case MXFS_LOCK_PR: return slot->holders_pr;
	case MXFS_LOCK_CW: return slot->holders_cw;
	case MXFS_LOCK_CR: return slot->holders_cr;
	default: return 0;
	}
}

/* ─── Compatibility check ─── */

bool is_compatible(const struct mxfs_caw_lock_slot *slot, uint8_t mode)
{
	int m;

	for (m = MXFS_LOCK_CR; m <= MXFS_LOCK_EX; m++) {
		if (holders_for_mode_const(slot, (uint8_t)m) != 0 &&
		    !lock_compat[m][mode])
			return false;
	}
	return true;
}

/* ─── Recompute granted_mode from holder bitmaps ─── */

uint8_t recompute_granted_mode(const struct mxfs_caw_lock_slot *slot)
{
	if (slot->holders_ex) return MXFS_LOCK_EX;
	if (slot->holders_pw) return MXFS_LOCK_PW;
	if (slot->holders_pr) return MXFS_LOCK_PR;
	if (slot->holders_cw) return MXFS_LOCK_CW;
	if (slot->holders_cr) return MXFS_LOCK_CR;
	return MXFS_LOCK_NL;
}

/*
 * v0.3.83: holder bitmap validity.  h_ex/h_pw are single-holder modes
 * (EX exclusive, PW single-writer); popcount > 1 means stale-disk
 * garbage from a prior FS that mkfs's pwrite-O_SYNC didn't durably
 * overwrite on this LIO target.  Sess23 captured ino=128 slot=51123
 * with hex=e0041d00e1000413 (popcount=16) blocking all peer acquires
 * for 120s until timeout.
 */
bool caw_slot_holders_popcount_ok(const struct mxfs_caw_lock_slot *s)
{
	if (mxfs_pal_popcount64(s->holders_ex) > 1)
		return false;
	if (mxfs_pal_popcount64(s->holders_pw) > 1)
		return false;
	return true;
}
