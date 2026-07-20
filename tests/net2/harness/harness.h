/*
 * MXFS — NET2 user-mode protocol harness (gate scaffolding).
 *
 * Gate-1 scope: wire-format goldens, fuzz, TLV, fault-engine determinism.
 * Step 2 extends this with the in-process virtual cluster (N node
 * instances over real localhost TCP + a file-backed disklock image).
 *
 * Output protocol: one lib.sh-style line per scenario —
 *   RESULT: PASS|FAIL | test=<scenario> | nodes=1 | measured=... | reason=...
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_NET2_HARNESS_H
#define MXFS_NET2_HARNESS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "dlm/net2.h"
#include "dlm/net2_stats.h"
#include "dlm/net2_fault.h"

struct scenario_ctx {
	const char *vectors_dir;
	uint64_t    seed;
	int         write_vectors;    /* generate instead of compare */
	int         real_time;        /* run at spec-default tunables */
	int         checks;
	int         failed;
};

/* Returns 0 on PASS, 1 on FAIL. */
typedef int (*scenario_fn)(struct scenario_ctx *sc);

struct scenario {
	const char *name;
	scenario_fn fn;
	int         real_time_subset; /* pinned real-defaults subset member */
};

/* Check helper: counts, prints failures, never aborts (full report). */
static inline int ck(struct scenario_ctx *sc, int cond, const char *what)
{
	sc->checks++;
	if (!cond) {
		sc->failed++;
		fprintf(stderr, "  CHECK-FAIL: %s\n", what);
	}
	return cond;
}

/* ─── In-process virtual cluster (step 2) ───
 *
 * N nodes = N independent mxfs_net2_ctx instances in one process, each
 * listening on 127.0.0.1:base+slot and talking REAL TCP through the
 * same mxfs_pal_tcp_* code the kernel path uses.  Time constants come
 * compressed (÷ compress) for scenario breadth; the pinned real-time
 * subset runs at spec defaults (compress=1) because compression can
 * mask races.
 *
 * Tag convention: every harness message carries a u32 tag in its inner
 * payload.  Reliable tags are < VC_TAG_UNREL; vc_send ORs unreliable
 * tags with VC_TAG_UNREL so log filters can tell the two apart.
 * Scenarios use unique tags per operation unless deliberately testing
 * caller-level retry dedup (then they reuse the msg_id).
 */

#define VC_MAX_NODES  8
#define VC_LOG_CAP    16384
#define VC_TAG_UNREL  0x80000000u
#define VC_TAG_MAX    65536         /* reliable tag space per scenario */

struct vc_rec {
	uint16_t src_slot;
	uint16_t type;                /* inner mxfs_dlm_msg_type */
	uint32_t src_inc;
	uint32_t tag;
	uint32_t len;
};

struct vcluster;

struct vc_node {
	int up;
	uint16_t slot;
	uint32_t inc;
	uint64_t nonce;
	struct mxfs_net2_ctx *ctx;
	struct vcluster *vc;
	mxfs_mutex_t *log_lock;
	struct vc_rec *log;           /* VC_LOG_CAP entries */
	int log_n;
	int log_overflow;
	uint64_t ambiguous_hits;      /* COMM_AMBIGUOUS cb count */
	uint32_t unrel_sent[VC_MAX_NODES];
};

struct vcluster {
	int n;
	uint16_t base_port;
	uint64_t seed;
	uint32_t compress;
	uint8_t uuid[16];
	uint32_t uuid_hash;
	uint64_t epoch;
	struct mxfs_net2_tunables tun;   /* effective (already compressed) */
	uint16_t tx_win_override;        /* 0 = default */
	struct vc_node nodes[VC_MAX_NODES];
};

int  vc_create(struct vcluster **vc_out, int n, uint64_t seed,
               uint32_t compress, uint16_t tx_win_override);
int  vc_node_start(struct vcluster *vc, int i);
void vc_node_kill(struct vcluster *vc, int i);
int  vc_node_restart(struct vcluster *vc, int i);   /* bumps inc+nonce */
void vc_view_node(struct vcluster *vc, int i, uint64_t mask, uint64_t epoch);
void vc_view_all(struct vcluster *vc, uint64_t mask, uint64_t epoch);
void vc_destroy(struct vcluster *vc);

/* Send one inner message from node `from` to node `to`; tag rules above.
 * Returns the mxfs_net2_send rc. */
int  vc_send(struct vcluster *vc, int from, int to, uint16_t type,
             uint32_t tag, int reliable, uint32_t msg_id);
/* Same, addressing an explicit (stale) incarnation. */
int  vc_send_inc(struct vcluster *vc, int from, int to, uint32_t inc,
                 uint16_t type, uint32_t tag, int reliable, uint32_t msg_id);

/* Log queries: from_slot < 0 or type == 0 or tag == UINT32_MAX = any. */
int  vc_count(struct vcluster *vc, int node, int from_slot, uint16_t type,
              uint32_t tag);
int  vc_wait_count(struct vcluster *vc, int node, int from_slot,
                   uint16_t type, uint32_t tag, int want, int timeout_ms);
/* Unique reliable tags from `from_slot` seen at `node`; *dups counts
 * tags delivered more than once. */
int  vc_unique_from(struct vcluster *vc, int node, int from_slot, int *dups);

/* All sessions on all up nodes fully retired (created == acked+aborts). */
int  vc_quiesce(struct vcluster *vc, int timeout_ms);

#define VC_INV_ALLOW_DUPTAGS  (1u << 0)
#define VC_INV_ALLOW_QFULL    (1u << 1)
/* §13 standing invariants from the evidence counters. */
int  vc_assert_invariants(struct scenario_ctx *sc, struct vcluster *vc,
                          unsigned flags);
void vc_dump_stats(struct vcluster *vc);

/* scen_midcomms.c scenario table (gate 2). */
extern const struct scenario net2_scen_midcomms[];
extern const int net2_scen_midcomms_count;

/* scen_shard.c scenario table (gate 4, §13.2). */
extern const struct scenario net2_scen_shard[];
extern const int net2_scen_shard_count;

/* scen_mepoch.c scenario table (gate 5, §7.C membership plane). */
extern const struct scenario net2_scen_mepoch[];
extern const int net2_scen_mepoch_count;

#endif /* MXFS_NET2_HARNESS_H */
