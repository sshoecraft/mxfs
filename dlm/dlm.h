/*
 * MXFS — Multinode XFS
 * Portable DLM engine — data structures and API
 *
 * Manages the distributed lock table. Processes lock requests from the
 * local cache and from remote peers, enforces the 6-mode compatibility
 * matrix, and handles lock queuing, granting, conversion, and BAST.
 *
 * Ported from kernel/mxfs_dlm.h — replaces kernel types with PAL types.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_DLM_H
#define MXFS_LIBMXFS_DLM_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"

/* ─── Lock entry — one per (resource, owner) pair ─── */

struct mxfs_lock {
    struct mxfs_resource_id resource;
    mxfs_node_id_t      owner;
    uint8_t              mode;       /* MXFS_LOCK_NL..MXFS_LOCK_EX */
    uint8_t              state;      /* MXFS_LSTATE_* */
    uint32_t             flags;      /* MXFS_LKF_* */
    uint64_t             queued_at;  /* when lock request was first queued */
    uint64_t             granted_at; /* mxfs_pal_time_ms() timestamp */
    uint32_t             grant_gen;  /* sess-tcp: per-grant generation token */
    bool                 handoff;    /* sess63: this grant is a cross-node EX
                                      * handoff (a DIFFERENT node held EX since
                                      * this owner last did) — set by the master
                                      * from dg_shadow.last_owner, delivered to
                                      * the grantee.  The reliable replacement
                                      * for the lossy DIR_MODIFY evict-ring. */
    uint32_t             dir_epoch;  /* sess64 (GPT design): per-resource MONOTONIC
                                      * cross-node handoff epoch.  The master bumps
                                      * dg_shadow.epoch on every cross-node EX
                                      * handoff and stamps it on each grant; the
                                      * grantee stores it here.  LEVEL-triggered
                                      * (compare > valid_epoch) replacement for the
                                      * edge-triggered `handoff` bool — a grantee
                                      * that missed intermediate handoffs still sees
                                      * the epoch advanced and refreshes exactly
                                      * once. */
    mxfs_epoch_t         request_epoch; /* requester's epoch, echoed in grant */
    struct mxfs_lock     *next;      /* hash chain link */
    struct mxfs_lock     *work_next; /* deferred BAST/grant work list */
    void                 *pend_waiter; /* sess4(a16ec5f2): the mxfs_dlm_pending a
                                      * LOCAL thread is blocked on for THIS queued
                                      * entry (NULL when none / not local-queued).
                                      * Never dereferenced — identity only.  Set by
                                      * dlm_lock_impl when queueing WAITING, cleared
                                      * at promotion and at the requester's own
                                      * timeout-unlink.  mxfs_dlm_unlock's WAITING/
                                      * BLOCKED fallback MUST NOT reap an entry with
                                      * a live waiter attached (run19/20 proven: it
                                      * ate a concurrent create's in-flight request,
                                      * whose dangling pointer then freed a recycled
                                      * LIVE remote grant at timeout -> concurrent
                                      * EX -> durable dirent loss). */
};

/* ─── Pending remote request — tracks outstanding lock forwarded to master ─── */

#define MXFS_DLM_PENDING_BITS  8
#define MXFS_DLM_PENDING_SIZE  (1 << MXFS_DLM_PENDING_BITS)

struct mxfs_dlm_pending {
    struct mxfs_dlm_pending *next;          /* hash chain */
    struct mxfs_resource_id resource;
    mxfs_mutex_t            *lock;
    mxfs_cond_t             *cond;
    bool                    done;
    uint8_t                 granted_mode;
    int                     status;         /* 0 or negative errno */
    mxfs_epoch_t            request_epoch;  /* epoch when request was sent */
};

/* ─── Callback function types ─── */

struct mxfs_dlm_ctx;

/* Queued lock was promoted to GRANTED */
typedef void (*mxfs_dlm_grant_cb)(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_resource_id *resource,
                                  mxfs_node_id_t owner,
                                  uint8_t mode);

/* Incompatible request arrived for a lock we hold — downgrade or release */
typedef void (*mxfs_dlm_bast_cb)(struct mxfs_dlm_ctx *ctx,
                                 const struct mxfs_resource_id *resource,
                                 mxfs_node_id_t owner,
                                 uint8_t requested_mode);

/* Send a DLM message to a remote node */
typedef int (*mxfs_dlm_send_cb)(struct mxfs_dlm_ctx *ctx,
                                mxfs_node_id_t target,
                                const void *msg, size_t len);

/* Membership changed — all locks purged, caches must be invalidated */
typedef void (*mxfs_dlm_membership_cb)(struct mxfs_dlm_ctx *ctx);

/* ─── Per-mount DLM context ─── */

struct mxfs_dlm_ctx {
    /* Lock hash table */
    struct mxfs_lock    **buckets;
    uint32_t            bucket_count;
    uint32_t            lock_count;
    mxfs_rwlock_t       *table_rwlock;

    /* Node identity */
    mxfs_node_id_t      local_node;

    /* Shutdown flag: when set, remote lock requests fail fast */
    volatile bool        shutting_down;

    /* sess-tcp double-grant fix: monotonic per-grant generation counter.
     * Protected by table_rwlock (every grant site holds it).  Never 0. */
    uint32_t             grant_gen_next;

    /* Epoch */
    mxfs_epoch_t        current_epoch;
    mxfs_mutex_t        *epoch_lock;

    /* Active node list for distributed mastering */
    struct {
        mxfs_node_id_t  nodes[MXFS_MAX_NODES];
        int             count;
        mxfs_mutex_t    *lock;
    } active_nodes;

    /* sess39: wall-clock (ms) of the most recent membership CHANGE (set in
     * mxfs_dlm_update_active_nodes whenever the active set changed).  The
     * grant path freezes EX grants for mxfs_memb_settle_ms after a change so
     * the workload never runs while membership/mastership is still converging
     * (cluster formation ramp 1->N, or a real death) — the proven split-brain
     * window (P-STALEMASTER-GRANT at active_count<N).  0 = no change yet. */
    uint64_t            last_memb_change_ms;

    /* Pending remote requests (waiting for remote master grant) */
    struct mxfs_dlm_pending *pending_buckets[MXFS_DLM_PENDING_SIZE];
    mxfs_mutex_t        *pending_lock;

    /* Callbacks */
    mxfs_dlm_grant_cb       grant_cb;
    mxfs_dlm_bast_cb        bast_cb;
    mxfs_dlm_send_cb        send_cb;
    mxfs_dlm_membership_cb  membership_cb;
    void                    *cb_data;
};

/* ─── Per-mount lifecycle ─── */

struct mxfs_dlm_ctx *mxfs_dlm_create(mxfs_node_id_t local_node);
void mxfs_dlm_destroy(struct mxfs_dlm_ctx *ctx);

/* ─── Lock operations (called from cache on miss) ─── */

int mxfs_dlm_lock(struct mxfs_dlm_ctx *ctx,
                  const struct mxfs_resource_id *resource,
                  uint8_t mode, uint32_t flags,
                  uint8_t *granted_mode);

/* sess58: retry-budget variant — see dlm.c.  Lets the xfs inode-acquire slow
 * path poll in short windows so it can re-yield cached basted AGs DURING the
 * acquire (breaks the inode<->AG ABBA deadlock). */
int mxfs_dlm_lock_retries(struct mxfs_dlm_ctx *ctx,
                  const struct mxfs_resource_id *resource,
                  uint8_t mode, uint32_t flags,
                  uint8_t *granted_mode, int max_retries);

int mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx,
                    const struct mxfs_resource_id *resource);

/* sess7 FIX-20b: mirror-bypassing unconditional (gen=0) LOCK_RELEASE to the
 * remote master — phantom-grant reconcile only (see dlm.c). */
int mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource);

/* Gen-aware release (sess1 ccloop a9a03929): releases ONLY the tenure whose
 * grant_gen == expected_gen.  Returns -ESTALE (touching nothing) if a
 * same-owner GRANTED entry with a different gen owns the resource — i.e. a
 * re-acquire completed during the caller's async release window.
 * expected_gen=0 = unconditional (legacy behavior). */
int mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx,
                        const struct mxfs_resource_id *resource,
                        uint32_t expected_gen);

int mxfs_dlm_lock_convert(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          mxfs_node_id_t owner, uint8_t new_mode);

void mxfs_dlm_release_all(struct mxfs_dlm_ctx *ctx);
void mxfs_dlm_withdraw_release_all(struct mxfs_dlm_ctx *ctx);

/* ─── Node failure ─── */

int mxfs_dlm_purge_node(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node);

/*
 * Purge stale lock entries for a specific resource.
 *
 * Removes all lock table entries for the given resource that are owned
 * by nodes other than the local node. Called from inode_cache.c when
 * a DLM lock request times out — the timeout indicates a stale remote
 * holder (from a defunct master) that will never release via BAST.
 *
 * After purging, promotes any waiters that become unblocked.
 * Returns the number of stale entries removed.
 */
int mxfs_dlm_purge_stale_for_resource(struct mxfs_dlm_ctx *ctx,
                                       const struct mxfs_resource_id *resource);

/* ─── Distributed mastering ─── */

mxfs_node_id_t mxfs_dlm_resource_master(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource);
bool mxfs_dlm_is_resource_master(struct mxfs_dlm_ctx *ctx,
                                 const struct mxfs_resource_id *resource);
int mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx,
                                 const mxfs_node_id_t *nodes, int count);
bool mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx);
/* sess-tcp: highest mode THIS node holds for `resource` in its local mirror
 * (GRANTED/CONVERTING entry owned by local_node), or MXFS_LOCK_NL if none.
 * Used to detect a phantom-EX on the TCP transport. */
uint8_t mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource);
/* sess61: per-grant generation token THIS node holds for `resource` (highest-mode
 * GRANTED/CONVERTING entry owned by local_node), 0 if none.  Reliable
 * lock-changed-hands signal for the dir-EX fast-path staleness check. */
uint8_t mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx,
                              const struct mxfs_resource_id *resource);
uint32_t mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource);

/* sess63: did THIS node's currently-held EX grant for `resource` arrive as a
 * cross-node handoff (a DIFFERENT node held EX since we last did)?  Returns the
 * handoff bool; *gen_out (if non-NULL) gets the grant_gen of that held grant so
 * the caller can consume the handoff exactly once per grant episode.  Reliable
 * acked-protocol signal computed by the master from dg_shadow.last_owner — the
 * replacement for the lossy DIR_MODIFY evict-ring (i_dlm_dir_gen). */
bool mxfs_dlm_grant_was_handoff(struct mxfs_dlm_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                uint32_t *gen_out);

/* sess64 (GPT design): return the MONOTONIC cross-node handoff epoch the master
 * stamped on our currently-held grant for `resource` (0 if not held / no DLM).
 * Level-triggered replacement for the one-shot handoff bool: the XFS layer keeps
 * a per-inode valid_epoch and refreshes its cached dir base whenever this
 * returned epoch exceeds it. */
uint32_t mxfs_dlm_grant_dir_epoch(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_resource_id *resource);

/* ─── Epoch ─── */

mxfs_epoch_t mxfs_dlm_advance_epoch(struct mxfs_dlm_ctx *ctx);
mxfs_epoch_t mxfs_dlm_get_epoch(struct mxfs_dlm_ctx *ctx);

/* ─── Remote request processing (called by peer recv path) ─── */

int mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t mode, uint32_t flags,
                                    mxfs_epoch_t request_epoch);

int mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_resource_id *resource,
                                  uint8_t mode, int status,
                                  mxfs_epoch_t grant_epoch,
                                  uint32_t grant_gen,
                                  uint8_t handoff,
                                  uint32_t dir_epoch);

int mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_resource_id *resource,
                                    uint32_t grant_gen);

/* ─── Compatibility check ─── */

int mxfs_dlm_modes_compatible(uint8_t held, uint8_t requested);

/* ─── Transport-agnostic DLM dispatch function pointers ───
 *
 * These typedefs allow consumers (inode_cache, alloc, etc.) to call
 * DLM lock/unlock/convert without knowing whether the underlying
 * transport is TCP-based DLM or disk-based CAW.  The mount layer
 * sets the concrete function pointers during mount.
 */
typedef int (*mxfs_dlm_lock_fn)(void *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint8_t mode, uint32_t flags,
                                 uint8_t *granted_mode);
typedef int (*mxfs_dlm_unlock_fn)(void *ctx,
                                   const struct mxfs_resource_id *resource);
typedef int (*mxfs_dlm_convert_fn)(void *ctx,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t new_mode);

#endif /* MXFS_LIBMXFS_DLM_H */
