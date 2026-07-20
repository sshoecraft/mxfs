/*
 * MXFS — Multinode XFS
 * NET2 transport — evidence counters (DLM_PLAN.md §13)
 *
 * These are the REQUIRED verification evidence, not optional debug info:
 * every fault-matrix run (user harness and kernel) asserts the standing
 * invariants against these counters and dumps them in its RESULT output.
 * Plain u64s, bumped under the owning lock (session lock for session
 * stats, per-link egress lock for class stats) — no atomics needed.
 * Exported live via the mxfs_pal_stats_register surface (step 6) and
 * printed directly by the user harness.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_STATS_H
#define MXFS_LIBMXFS_NET2_STATS_H

#include "net2.h"

/* Per priority class (per link, aggregated per mount). */
struct mxfs_net2_class_stats {
	uint64_t enqueued;
	uint64_t first_tx;
	uint64_t retx;
	uint64_t queue_full;          /* overflow events (GRANT/DISCOVERY:
	                               * -EAGAIN; coherence classes: freeze) */
	uint64_t max_residency_ms;    /* high-water queue residency         */
};

/* Per session (per peer incarnation pair). */
struct mxfs_net2_session_stats {
	uint64_t msgs_created;        /* unique msg_ids allocated           */
	uint64_t first_tx;
	uint64_t retx;
	uint64_t acked;
	uint64_t dup_seq_suppressed;  /* midcomms delivery dedup            */
	uint64_t dup_op_idempotent;   /* lock-handler idempotent replays    */
	uint64_t out_of_window_drops;
	uint64_t stale_incarnation_drops;
	uint64_t stale_epoch_drops;
	uint64_t stale_term_drops;
	uint64_t resets;              /* link teardowns under the session   */
	uint64_t resumes;             /* session survived a reconnect       */
	uint64_t aborts;              /* explicit session-abort dispositions */
};

/* Per mount. */
struct mxfs_net2_stats {
	struct mxfs_net2_class_stats cls[NET2_PRI_COUNT];
	/* Accumulated stats of SUPERSEDED sessions, folded in at the
	 * moment of supersede — the abort dispositions of a dead
	 * incarnation's entries stay observable (§13 invariant evidence)
	 * after the live-session table has moved on. */
	struct mxfs_net2_session_stats retired;
	uint64_t sessions_created;
	uint64_t sessions_gcd;
	uint64_t comm_ambiguous_events;
	uint64_t malformed_frames;    /* by mxfs_net2_hdr_validate reason —
	                               * see malformed[]                    */
	uint64_t malformed[8];        /* indexed by enum mxfs_net2_hdr_err  */
	uint64_t cross_cluster_rejects;   /* SYN uuid/volume/fs_gen mismatch */
	uint64_t freezes[MXFS_NET2_FZR_COUNT];
	uint64_t freeze_active_ms_max;    /* longest observed freeze age    */
	uint64_t fence_requests;
	uint64_t fence_confirmed;
	uint64_t fence_stale_ignored;     /* old-incarnation fence_done     */
	uint64_t recovery_runs;
};

#endif /* MXFS_LIBMXFS_NET2_STATS_H */
