/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net2_membership — observer aggregation + SUSPECT state machine (§7.C).
 *
 * Liveness is a vote of three independent observers per peer — lease
 * multicast, NET2 unicast probe, disklock HB advance — never a single
 * timer: a slot goes SUSPECT only when ≥2 observers report it missing.
 * A SUSPECT peer that reconnects with the SAME {incarnation, nonce}
 * within the grace window resumes ACTIVE; after grace it goes FENCING;
 * DEAD only ever via an incarnation-qualified fence_done (deliberately
 * NOT the v5 timeout-declare model).  State transitions surface through
 * a callback (fired outside the lock); the owner feeds them into
 * net2_mepoch_suspect() and, at step 6, the fence engine.
 *
 * Also home to the §5 persisted-incarnation bump (runs at mount/slot
 * claim BEFORE joining, through the same storage vtable the epoch
 * module uses) and the boot-nonce helper.  Both builds, PAL only.
 */
#ifndef MXFS_NET2_MEMBERSHIP_H
#define MXFS_NET2_MEMBERSHIP_H

#include "net2_epoch.h"

struct net2_membership;

enum net2_member_state {
	N2MB_UNTRACKED = 0,
	N2MB_ACTIVE,
	N2MB_SUSPECT,
	N2MB_FENCING,
	N2MB_DEAD,
};

/* The three independent liveness observers (§7.C). */
enum net2_observer {
	N2OBS_LEASE = 0,        /* lease multicast beacon seen             */
	N2OBS_PROBE,            /* NET2 unicast probe / link traffic       */
	N2OBS_DISK,             /* disklock HB record advanced on the LUN  */
	N2OBS_COUNT
};

struct net2_membership_cfg {
	uint16_t self_slot;
	uint32_t miss_ms;       /* 0 → 3000: observer silent this long
	                         * counts as one missing vote              */
	uint32_t grace_ms;      /* 0 → 10000: SUSPECT → FENCING            */

	/* Fired outside the lock on every state transition. */
	void (*state_cb)(void *cb_data, uint16_t slot,
	                 enum net2_member_state from,
	                 enum net2_member_state to);
	void *cb_data;
};

int  net2_membership_create(const struct net2_membership_cfg *cfg,
                            struct net2_membership **out);
void net2_membership_destroy(struct net2_membership *mb);

/* Track a peer under identity {inc, nonce} (from the committed epoch's
 * incarnation table + SYN exchange).  Re-tracking with a new identity
 * re-arms the machine at ACTIVE. */
void net2_membership_track(struct net2_membership *mb, uint16_t slot,
                           uint32_t inc, uint64_t nonce);
void net2_membership_untrack(struct net2_membership *mb, uint16_t slot);

/* One observer saw the peer alive under {inc, nonce} at now_ms.  A
 * mismatched identity never resumes a SUSPECT peer — the old
 * incarnation stays on its path to FENCING. */
void net2_membership_observe(struct net2_membership *mb, uint16_t slot,
                             enum net2_observer obs, uint32_t inc,
                             uint64_t nonce, uint64_t now_ms);

/* Evaluate misses/grace; drives ACTIVE→SUSPECT→FENCING. */
void net2_membership_tick(struct net2_membership *mb, uint64_t now_ms);

/* Incarnation-qualified fence completion: the ONLY path to DEAD. */
void net2_membership_fence_done(struct net2_membership *mb, uint16_t slot,
                                uint32_t inc);

enum net2_member_state net2_membership_state(struct net2_membership *mb,
                                             uint16_t slot);

/* §5 persisted incarnation: read own HB mepoch record, +1 (never 0),
 * reseal, write back — content otherwise preserved (a stale PREPARED
 * survives for the next proposer to adopt).  Absent/invalid record →
 * fresh epoch-0 inc-carrier.  Returns 0 and the new incarnation. */
int  net2_membership_inc_bump(const struct net2_mepoch_storage *st,
                              uint16_t self_slot, uint32_t *inc_out);

/* Boot nonce: 64 random bits, never 0. */
uint64_t net2_membership_boot_nonce(void);

#endif /* MXFS_NET2_MEMBERSHIP_H */
