/*
 * MXFS — Multinode XFS
 * NET2 lock plane — sharded replicated lock service (§7.B, §11 step 4)
 *
 * 1024 shards; per committed membership epoch E the replica set of
 * shard s is the HRW top-min(3,|M|) over {E, s, member (slot, inc)},
 * rank-0 the initial leader.  Configs are DERIVED from E — totally
 * ordered, no joint quorums; every message carries (E, term) and a
 * replica accepts only its current committed E (bridge: none at the
 * lock plane — stale-epoch ops are denied, the client re-resolves).
 *
 * The lock table, waiter queue and completed-op cache mutate ONLY via
 * committed log entries (2-of-quorum), so fairness order and
 * idempotent results survive failover.  Until step 5 lands MEPOCH,
 * the committed epoch and its member list are INJECTED by the caller
 * (`net2_lockspace_epoch_commit`) — the harness plays §7.C; the
 * kernel seam gets the real membership plane before any kernel use.
 *
 * Layering: the lockspace sits ABOVE the net2 engine.  Lock order:
 * ls->lock > shard->lock > (client) ls->cl_lock > stats; net2 engine
 * locks are only ever taken AFTER all lock-plane locks (sends), and
 * deliveries arrive with no engine locks held (net2_deliver contract).
 * Never two shard locks at once.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_SHARD_H
#define MXFS_LIBMXFS_NET2_SHARD_H

#include "net2.h"
#include "net2_msg.h"
#include "dlm_shared.h"

#define N2_SHARD_COUNT        1024
#define N2_LOG_WIN            64      /* bounded ring, = NET2_TX_WIN     */
#define N2_REPLICAS_MAX       3
#define N2_OPCACHE_RING       64      /* completed ops kept per client   */
#define N2_REC_HASH           64      /* per-shard record buckets        */
#define N2_LAST_EX_NONE       0xFFFFu

enum n2_shard_state {
	SH_ACTIVE = 0,
	SH_ELECTING,
	SH_XFER,
	SH_FROZEN,
	SH_RECOVERY,
};

struct n2_waiter {
	uint16_t slot;
	uint32_t inc;
	uint64_t request_id;
	uint8_t  mode;
	uint64_t enq_seq;
	struct n2_waiter *next;
};

struct n2_lock_rec {
	struct mxfs_resource_id resource;
	uint64_t holders_ex, holders_pw, holders_pr, holders_cw, holders_cr;
	uint64_t grant_gen;               /* current tenure token, never 0 */
	uint64_t dir_epoch;
	uint16_t last_ex_slot;            /* N2_LAST_EX_NONE = none        */
	uint8_t  handoff;
	uint8_t  ex_streak;               /* fairness mirror of CAW        */
	uint64_t pending_revoke_mask;
	struct n2_waiter *waitq, *waitq_tail;
	struct n2_lock_rec *next;         /* hash chain                    */
};

struct n2_log_ent {
	bool     used;
	bool     committed;
	uint16_t op;                      /* enum mxfs_n2log_op            */
	uint32_t term;                    /* term the entry was created in */
	uint64_t seq;
	struct mxfs_resource_id resource;
	uint8_t  mode;
	uint16_t req_slot;
	uint32_t req_inc;
	uint64_t request_id;
	uint64_t grant_gen;
	uint64_t dir_epoch;
	uint16_t msg_flags;               /* N2F_FROM_WAITQ etc.           */
	uint8_t  ack_mask;                /* replica-index bits (leader)   */
};

struct n2_opcache_ent {
	bool     used;
	uint64_t request_id;
	uint8_t  status;                  /* 0 = granted; else deny reason */
	uint8_t  mode;
	uint64_t gen;
};

struct n2_opcache_client {
	bool     used;
	uint16_t slot;
	uint32_t inc;                     /* new inc supersedes the ring   */
	uint32_t next_idx;
	struct n2_opcache_ent ring[N2_OPCACHE_RING];
};

struct n2_replica { uint16_t slot; uint32_t inc; };

struct net2_shard {
	uint32_t shard_id;
	uint64_t memb_epoch;
	uint32_t term;
	enum n2_shard_state state;
	uint16_t leader_slot;
	struct n2_replica replicas[N2_REPLICAS_MAX];
	uint8_t  nreplicas;

	uint64_t commit_seq;              /* committed high-water          */
	uint64_t last_seq;                /* last appended                 */
	struct n2_log_ent log[N2_LOG_WIN];

	struct n2_lock_rec *recs[N2_REC_HASH];
	struct n2_opcache_client *opcache;   /* array MXFS_MAX_NODES       */

	uint64_t grant_gen_next;          /* nonzero; see §7.B wrap rule   */
	uint64_t dir_epoch_next;
	uint64_t enq_seq_next;            /* waiter FIFO order key         */

	/* election */
	uint32_t voted_term;              /* highest term voted for        */
	uint32_t cand_term;               /* term we are soliciting        */
	uint8_t  votes;
	uint64_t elect_deadline_ms;       /* 0 = no pending election       */

	/* replica eligibility (leader view): slot-bit set = caught up.
	 * A replica that restarted within E (fresh inc, empty state) may
	 * not vote or ack until transfer completes (§7.B).             */
	uint64_t caught_up_mask;
	bool     eligible;                /* this node's own eligibility   */

	/* Leader completeness: a leader may serve client ops only after
	 * an entry of ITS OWN term has committed on the quorum (the TERM
	 * barrier, normally).  A self-appointed rank-0 with an empty log
	 * (restart) can never satisfy this against stateful followers —
	 * their NACKs carry higher commit_seq and force it to abdicate
	 * into a snapshot pull first (§7.B completeness rule). */
	bool     term_proven;

	/* state transfer (this node = transferee) */
	bool     xfer_active;
	uint16_t xfer_src;
	uint32_t xfer_chunks_seen, xfer_chunk_count;
	uint64_t xfer_await_mask;         /* solicited, chunk0 not yet in  */
	uint64_t xfer_deadline_ms;
	bool     xfer_stream_done;        /* claimed stream fully received */
	uint64_t xfer_adv_base;           /* claimed stream's completeness */
	uint64_t xfer_adv_last;           /*   vote (base, src_last)       */

	/* recovery barrier (this node = new leader) */
	bool     recov_active;
	uint64_t recov_reports;           /* member slots heard from       */

	mxfs_mutex_t *lock;
};

/* ─── evidence counters (§13.2) ─── */
struct net2_lockspace_stats {
	uint64_t acquires, releases, grants_sent, denies_sent, basts_sent;
	uint64_t appends_sent, append_acks, append_nacks, truncations;
	uint64_t commits, dup_op_idempotent;
	uint64_t elections_started, votes_granted, votes_refused_xfer,
	         votes_refused_tuple, term_barriers;
	uint64_t xfers_started, xfers_completed, caught_up_logged;
	uint64_t recovery_barriers, recovery_reports_rcvd,
	         recovery_recs_rebuilt;
	uint64_t stale_epoch_denies, stale_term_denies, stale_gen_denies;
	uint64_t redirects_followed, client_reissues;
	uint64_t shards_frozen;
	uint64_t gen_high_water, commit_seq_high_water;   /* monotone max */
};

/* ─── client-side request tracking ─── */
enum n2_creq_state { CR_IDLE = 0, CR_PENDING, CR_WAITING, CR_DONE };

struct n2_creq {
	bool     used;
	uint64_t request_id;
	struct mxfs_resource_id resource;
	uint8_t  mode;
	enum n2_creq_state state;
	uint8_t  status;                  /* deny reason / 0 granted       */
	uint64_t gen, dir_epoch;
	uint16_t target_slot;             /* leader currently addressed    */
	uint64_t last_tx_ms;
	uint32_t retries;                 /* rotates the target on silence */
	bool     is_release;
	bool     detached;                /* no waiter: self-reaps on
	                                   * completion (orphan-grant
	                                   * auto-release, timed-out
	                                   * release re-issue)            */
	uint64_t rel_gen;
};

struct n2_held {
	bool     used;
	struct mxfs_resource_id resource;
	uint8_t  mode;
	uint64_t gen;
	struct n2_held *next;
};

#define N2_CREQ_MAX   128
#define N2_HELD_HASH  256

/* BAST delivery to the client (harness records; kernel drives the XFS
 * notify entries at step 7).  Called without lock-plane locks held. */
typedef void (*net2_bast_cb)(void *data,
                             const struct mxfs_resource_id *resource,
                             uint8_t wanted_mode, uint64_t gen);

/* Deterministic test hook — the §13.2 kill-at-commit-point mechanism.
 * Called (without shard lock held) at named points; a true return
 * POISONS the lockspace: from that instant it neither processes nor
 * sends anything more (models death at exactly that point; the
 * scenario then destroys the node at leisure). */
enum n2_hook_point {
	N2H_PRE_APPEND = 1,          /* leader: entry built, nothing sent  */
	N2H_POST_LOCAL_APPEND,       /* leader: in ring, replicas unsent   */
	N2H_POST_SEND_ONE,           /* leader: APPEND to first replica    */
	N2H_POST_QUORUM_ACK,         /* leader: quorum acked, not applied  */
	N2H_POST_COMMIT_PRE_EMIT,    /* leader: applied, result unsent     */
	N2H_POST_EMIT,               /* leader: GRANT/RELEASE_ACK sent     */
	N2H_PRE_RELEASE_COMMIT,      /* leader: RELEASE entry pre-quorum   */
	N2H_POST_RELEASE_COMMIT,     /* leader: RELEASE applied, ack unsent*/
	N2H_REVOKE_PENDING,          /* leader: EX_PENDING committed       */
	N2H_RECONFIG,                /* epoch change processing            */
	N2H_SNAPSHOT,                /* transfer source: chunk about to go */
	N2H_ELECTED,                 /* winner: barrier committed          */
};
typedef bool (*net2_test_hook)(void *data, enum n2_hook_point point,
                               uint32_t shard_id, uint16_t op_or_detail);

struct net2_lockspace_cfg {
	uint16_t self_slot;
	uint32_t self_inc;
	uint32_t elect_base_ms;      /* 0 -> 150                           */
	uint32_t elect_rank_ms;      /* 0 -> 80 (× HRW rank bias)          */
	uint32_t client_retry_ms;    /* 0 -> 400 (re-issue cadence)        */
	uint32_t rt_tick_ms;         /* 0 -> 20                            */
	uint32_t max_held;           /* 0 -> 32768                         */
	uint64_t seed;               /* election jitter determinism        */
};

struct net2_lockspace {
	struct mxfs_net2_ctx *net;
	uint16_t self_slot;
	uint32_t self_inc;

	uint64_t epoch;                   /* committed E (injected)        */
	uint64_t member_mask;
	uint32_t member_inc[MXFS_MAX_NODES];

	struct net2_shard *shards[N2_SHARD_COUNT];   /* lazy               */
	mxfs_mutex_t *lock;               /* shards[] + epoch/members      */

	/* client side */
	struct n2_creq creqs[N2_CREQ_MAX];
	struct n2_held *held[N2_HELD_HASH];
	uint32_t held_count, max_held;
	uint64_t request_id_next;
	mxfs_mutex_t *cl_lock;
	mxfs_cond_t *cl_cond;
	net2_bast_cb bast_cb;
	void *bast_cb_data;

	/* lifecycle */
	volatile bool running;            /* peer.c stop-latch idiom       */
	volatile bool poisoned;           /* test-hook death model         */
	mxfs_thread_t *rt_thread;

	net2_test_hook hook;
	void *hook_data;

	struct net2_lockspace_stats stats;
	mxfs_mutex_t *stats_lock;

	uint32_t elect_base_ms, elect_rank_ms, client_retry_ms, rt_tick_ms;
	uint64_t seed;
	uint64_t prng;                    /* election jitter state         */
};

/* ─── lifecycle ─── */
int  net2_lockspace_create(struct mxfs_net2_ctx *net,
                           const struct net2_lockspace_cfg *cfg,
                           struct net2_lockspace **out);
int  net2_lockspace_start(struct net2_lockspace *ls);
void net2_lockspace_stop(struct net2_lockspace *ls);
void net2_lockspace_destroy(struct net2_lockspace *ls);

/* Committed-epoch injection (§7.C stand-in until step 5): member_incs
 * indexed by slot; drives HRW re-derivation, reconfiguration, state
 * transfer and the closed-set recovery barrier. */
void net2_lockspace_epoch_commit(struct net2_lockspace *ls, uint64_t epoch,
                                 uint64_t member_mask,
                                 const uint32_t *member_incs);

/* Membership SUSPECT/DEAD signal (never a mere link drop): arms the
 * election timers on shards whose leader is the suspect. */
void net2_lockspace_suspect(struct net2_lockspace *ls, uint16_t slot);

void net2_lockspace_set_bast_cb(struct net2_lockspace *ls, net2_bast_cb cb,
                                void *data);
void net2_lockspace_set_hook(struct net2_lockspace *ls, net2_test_hook hook,
                             void *data);
/* Model death NOW (test surface; also what a true hook return does). */
void net2_lockspace_poison(struct net2_lockspace *ls);

void net2_lockspace_get_stats(struct net2_lockspace *ls,
                              struct net2_lockspace_stats *out);
/* Per-shard probes (harness asserts).  Return -ENOENT if the shard
 * was never instantiated on this node. */
int  net2_lockspace_shard_probe(struct net2_lockspace *ls, uint32_t shard_id,
                                struct net2_shard *snap_out);

/* ─── internals shared between net2_shard.c and net2_lock.c ─── */
uint32_t net2_shard_id_for(const struct net2_lockspace *ls,
                           const struct mxfs_resource_id *res);
struct net2_shard *net2_shard_get(struct net2_lockspace *ls, uint32_t shard_id,
                                  bool create);
void net2_shard_derive_config(struct net2_lockspace *ls,
                              struct net2_shard *sh, uint64_t epoch);
int  net2_shard_append(struct net2_lockspace *ls, struct net2_shard *sh,
                       const struct n2_log_ent *ent_template);
void net2_shard_dispatch(struct net2_lockspace *ls,
                         const struct mxfs_net2_id *src,
                         const struct mxfs_n2msg *m,
                         const uint8_t *payload, uint32_t len,
                         uint32_t recs_off);
bool net2_shard_i_am_leader(const struct net2_lockspace *ls,
                            const struct net2_shard *sh);
void net2_shard_prove_term(struct net2_lockspace *ls, struct net2_shard *sh);
int  net2_shard_replica_index(const struct net2_shard *sh, uint16_t slot);
void net2_shard_send(struct net2_lockspace *ls, uint16_t dst_slot,
                     struct mxfs_n2msg *m, const uint8_t *recs,
                     uint32_t recs_len);
void net2_ls_stat_bump(struct net2_lockspace *ls, uint64_t *field);
void net2_ls_stat_max(struct net2_lockspace *ls, uint64_t *field,
                      uint64_t v);
bool net2_ls_hook(struct net2_lockspace *ls, enum n2_hook_point p,
                  uint32_t shard_id, uint16_t detail);

/* net2_lock.c internals used by the shard machinery */
void net2_lock_apply_entry(struct net2_lockspace *ls, struct net2_shard *sh,
                           const struct n2_log_ent *e);
void net2_lock_leader_validate(struct net2_lockspace *ls,
                               struct net2_shard *sh,
                               const struct mxfs_n2msg *m,
                               const struct mxfs_net2_id *src);
void net2_lock_emit_result(struct net2_lockspace *ls, struct net2_shard *sh,
                           const struct n2_log_ent *e);
void net2_lock_post_release_grants(struct net2_lockspace *ls,
                                   struct net2_shard *sh,
                                   const struct mxfs_resource_id *res);
void net2_lock_client_rx(struct net2_lockspace *ls,
                         const struct mxfs_net2_id *src,
                         const struct mxfs_n2msg *m);
void net2_lock_client_tick(struct net2_lockspace *ls, uint64_t now_ms);
struct n2_lock_rec *net2_rec_get(struct net2_shard *sh,
                                 const struct mxfs_resource_id *res,
                                 bool create);
void net2_shard_free_recs(struct net2_shard *sh);

#endif /* MXFS_LIBMXFS_NET2_SHARD_H */
