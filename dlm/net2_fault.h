/*
 * MXFS — Multinode XFS
 * NET2 transport — deterministic fault injection (BOTH builds)
 *
 * Compiled into kernel AND user builds unconditionally (DLM_PLAN.md §10):
 * the user-mode protocol harness and the kernel transport must inject
 * faults with IDENTICAL semantics, so the engine is pure logic — no PAL
 * calls, no clocks, no global state; the caller owns the state struct and
 * the evaluation points (net2_link's frame send/recv boundary, step 2).
 *
 * Determinism: xorshift64* PRNG seeded explicitly; given the same seed
 * and the same evaluation sequence, kernel and user builds make the same
 * drop/dup/delay decisions.  The rule string parser lives here too so the
 * kernel modparam and the harness CLI accept the same syntax:
 *
 *   dir:class:type:action:prob_ppm:count:delay_ms
 *
 *   dir    = s|r|a          (send / recv / any)
 *   class  = 0-4|*          (frame_class, * = any)
 *   type   = <n>|*          (inner msg type, * = any)
 *   action = drop|dup|delay|reorder|trunc|corrupt
 *   prob_ppm = 0..1000000   (per-eval probability, parts per million)
 *   count  = <n>|*          (max injections, * = unlimited)
 *   delay_ms = <n>          (delay/reorder hold time; 0 otherwise)
 *
 * e.g. "r:0:4:drop:250000:*:0" = drop 25% of received DATA frames whose
 * inner type is LOCK_RELEASE.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_FAULT_H
#define MXFS_LIBMXFS_NET2_FAULT_H

#include "../pal/pal.h"
#include "net2_wire.h"   /* frame-class bounds for rule validation */

enum mxfs_net2_fault_action {
	MXFS_NET2_FAULT_NONE = 0,
	MXFS_NET2_FAULT_DROP,
	MXFS_NET2_FAULT_DUP,
	MXFS_NET2_FAULT_DELAY,
	MXFS_NET2_FAULT_REORDER,
	MXFS_NET2_FAULT_TRUNC,
	MXFS_NET2_FAULT_CORRUPT,
	MXFS_NET2_FAULT_ACTION_COUNT
};

enum mxfs_net2_fault_dir {
	MXFS_NET2_FAULT_SEND = 0,
	MXFS_NET2_FAULT_RECV = 1,
	MXFS_NET2_FAULT_ANY_DIR = 2,
};

#define MXFS_NET2_FAULT_ANY_CLASS 0xff
#define MXFS_NET2_FAULT_ANY_TYPE  0xffff
#define MXFS_NET2_FAULT_UNLIMITED 0xffffffffu

struct mxfs_net2_fault_rule {
	uint8_t  active;
	uint8_t  action;              /* enum mxfs_net2_fault_action */
	uint8_t  dir;                 /* enum mxfs_net2_fault_dir    */
	uint8_t  frame_class;         /* or ANY_CLASS                */
	uint16_t inner_type;          /* or ANY_TYPE                 */
	uint32_t prob_ppm;            /* 1000000 = always            */
	uint32_t count;               /* remaining; UNLIMITED = no cap */
	uint32_t delay_ms;
};

#define MXFS_NET2_FAULT_MAX_RULES 16

struct mxfs_net2_fault_state {
	struct mxfs_net2_fault_rule rules[MXFS_NET2_FAULT_MAX_RULES];
	uint64_t prng;                /* xorshift64* state, never 0  */
	uint64_t evals;
	uint64_t injected[MXFS_NET2_FAULT_ACTION_COUNT];
};

struct mxfs_net2_fault_hit {
	uint8_t  action;              /* enum mxfs_net2_fault_action */
	uint32_t delay_ms;
};

void mxfs_net2_fault_init(struct mxfs_net2_fault_state *st, uint64_t seed);
int  mxfs_net2_fault_set(struct mxfs_net2_fault_state *st, int idx,
                         const struct mxfs_net2_fault_rule *rule);
void mxfs_net2_fault_clear(struct mxfs_net2_fault_state *st);

/*
 * Evaluate one frame event.  Returns 0 (no fault) or 1 with *hit filled.
 * First matching active rule wins; matching decrements its count.
 * Advances the PRNG exactly once per call REGARDLESS of match, so the
 * decision stream is a pure function of (seed, call sequence).
 */
int  mxfs_net2_fault_eval(struct mxfs_net2_fault_state *st,
                          enum mxfs_net2_fault_dir dir,
                          uint8_t frame_class, uint16_t inner_type,
                          struct mxfs_net2_fault_hit *hit);

/* Parse one rule string (syntax above). Returns 0 or -1 on syntax error. */
int  mxfs_net2_fault_parse_rule(const char *str,
                                struct mxfs_net2_fault_rule *rule);

/* Exposed for the harness's determinism golden test. */
uint64_t mxfs_net2_fault_prng_next(uint64_t *state);

#endif /* MXFS_LIBMXFS_NET2_FAULT_H */
