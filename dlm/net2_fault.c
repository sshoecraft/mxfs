/*
 * MXFS — Multinode XFS
 * NET2 transport — deterministic fault injection engine
 *
 * Pure logic, both builds, no PAL calls (see net2_fault.h header comment).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "net2_fault.h"

/* xorshift64* — deterministic, identical in both builds. */
uint64_t mxfs_net2_fault_prng_next(uint64_t *state)
{
	uint64_t x = *state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

void mxfs_net2_fault_init(struct mxfs_net2_fault_state *st, uint64_t seed)
{
	__builtin_memset(st, 0, sizeof(*st));
	st->prng = seed ? seed : 1;   /* xorshift state must be nonzero */
}

int mxfs_net2_fault_set(struct mxfs_net2_fault_state *st, int idx,
                        const struct mxfs_net2_fault_rule *rule)
{
	if (idx < 0 || idx >= MXFS_NET2_FAULT_MAX_RULES)
		return -1;
	if (rule->action == MXFS_NET2_FAULT_NONE ||
	    rule->action >= MXFS_NET2_FAULT_ACTION_COUNT)
		return -1;
	if (rule->dir > MXFS_NET2_FAULT_ANY_DIR)
		return -1;
	if (rule->prob_ppm > 1000000)
		return -1;
	st->rules[idx] = *rule;
	st->rules[idx].active = 1;
	return 0;
}

void mxfs_net2_fault_clear(struct mxfs_net2_fault_state *st)
{
	uint64_t prng = st->prng;
	uint64_t evals = st->evals;

	__builtin_memset(st, 0, sizeof(*st));
	st->prng = prng;      /* clearing rules must not disturb the
	                       * decision stream of later scenarios  */
	st->evals = evals;
}

int mxfs_net2_fault_eval(struct mxfs_net2_fault_state *st,
                         enum mxfs_net2_fault_dir dir,
                         uint8_t frame_class, uint16_t inner_type,
                         struct mxfs_net2_fault_hit *hit)
{
	/* One PRNG step per eval, unconditionally (determinism contract). */
	uint64_t r = mxfs_net2_fault_prng_next(&st->prng);
	uint32_t roll = (uint32_t)(r % 1000000);
	int i;

	st->evals++;

	for (i = 0; i < MXFS_NET2_FAULT_MAX_RULES; i++) {
		struct mxfs_net2_fault_rule *ru = &st->rules[i];

		if (!ru->active)
			continue;
		if (ru->dir != MXFS_NET2_FAULT_ANY_DIR &&
		    ru->dir != (uint8_t)dir)
			continue;
		if (ru->frame_class != MXFS_NET2_FAULT_ANY_CLASS &&
		    ru->frame_class != frame_class)
			continue;
		if (ru->inner_type != MXFS_NET2_FAULT_ANY_TYPE &&
		    ru->inner_type != inner_type)
			continue;
		if (roll >= ru->prob_ppm)
			continue;
		if (ru->count != MXFS_NET2_FAULT_UNLIMITED) {
			if (ru->count == 0)
				continue;
			ru->count--;
		}
		hit->action = ru->action;
		hit->delay_ms = ru->delay_ms;
		st->injected[ru->action]++;
		return 1;
	}
	return 0;
}

/* ─── Rule string parser (shared by kernel modparam and harness CLI) ─── */

static int parse_u32(const char **s, uint32_t *out, uint32_t wildcard)
{
	const char *p = *s;
	uint64_t v = 0;
	int n = 0;

	if (*p == '*') {
		*out = wildcard;
		*s = p + 1;
		return 0;
	}
	while (*p >= '0' && *p <= '9') {
		v = v * 10 + (uint64_t)(*p - '0');
		if (v > 0xffffffffULL)
			return -1;
		p++;
		n++;
	}
	if (!n)
		return -1;
	*out = (uint32_t)v;
	*s = p;
	return 0;
}

static int match_word(const char **s, const char *w)
{
	const char *p = *s;

	while (*w) {
		if (*p != *w)
			return 0;
		p++;
		w++;
	}
	*s = p;
	return 1;
}

static int expect_colon(const char **s)
{
	if (**s != ':')
		return -1;
	(*s)++;
	return 0;
}

int mxfs_net2_fault_parse_rule(const char *str,
                               struct mxfs_net2_fault_rule *rule)
{
	const char *s = str;
	uint32_t v;

	__builtin_memset(rule, 0, sizeof(*rule));

	switch (*s) {
	case 's': rule->dir = MXFS_NET2_FAULT_SEND;    break;
	case 'r': rule->dir = MXFS_NET2_FAULT_RECV;    break;
	case 'a': rule->dir = MXFS_NET2_FAULT_ANY_DIR; break;
	default:  return -1;
	}
	s++;
	if (expect_colon(&s))
		return -1;

	if (parse_u32(&s, &v, MXFS_NET2_FAULT_ANY_CLASS))
		return -1;
	if (v != MXFS_NET2_FAULT_ANY_CLASS && v >= MXFS_NET2_FC_COUNT)
		return -1;
	rule->frame_class = (uint8_t)v;
	if (expect_colon(&s))
		return -1;

	if (parse_u32(&s, &v, MXFS_NET2_FAULT_ANY_TYPE))
		return -1;
	if (v != MXFS_NET2_FAULT_ANY_TYPE && v > 0xffff)
		return -1;
	rule->inner_type = (uint16_t)v;
	if (expect_colon(&s))
		return -1;

	if (match_word(&s, "drop"))
		rule->action = MXFS_NET2_FAULT_DROP;
	else if (match_word(&s, "dup"))
		rule->action = MXFS_NET2_FAULT_DUP;
	else if (match_word(&s, "delay"))
		rule->action = MXFS_NET2_FAULT_DELAY;
	else if (match_word(&s, "reorder"))
		rule->action = MXFS_NET2_FAULT_REORDER;
	else if (match_word(&s, "trunc"))
		rule->action = MXFS_NET2_FAULT_TRUNC;
	else if (match_word(&s, "corrupt"))
		rule->action = MXFS_NET2_FAULT_CORRUPT;
	else
		return -1;
	if (expect_colon(&s))
		return -1;

	if (parse_u32(&s, &rule->prob_ppm, 1000000) || rule->prob_ppm > 1000000)
		return -1;
	if (expect_colon(&s))
		return -1;

	if (parse_u32(&s, &rule->count, MXFS_NET2_FAULT_UNLIMITED))
		return -1;
	if (expect_colon(&s))
		return -1;

	if (parse_u32(&s, &rule->delay_ms, 0))
		return -1;
	if (*s != '\0')
		return -1;

	rule->active = 1;
	return 0;
}
