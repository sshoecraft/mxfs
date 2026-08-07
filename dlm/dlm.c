/*
 * MXFS — Multinode XFS
 * Portable DLM engine
 *
 * The core distributed lock manager, running in portable C.
 * Manages the lock table, processes lock requests from the local
 * cache and from remote peers, enforces the 6-mode compatibility
 * matrix, and handles lock queuing, granting, conversion, and BAST.
 *
 * Ported from kernel/mxfs_dlm.c — kernel APIs replaced with PAL:
 *   rw_semaphore     -> mxfs_rwlock_t
 *   mutex            -> mxfs_mutex_t
 *   spinlock         -> mxfs_mutex_t
 *   completion       -> mxfs_cond_t + mxfs_mutex_t + done flag
 *   kmem_cache/kzalloc -> mxfs_pal_alloc
 *   ktime_get_ns     -> mxfs_pal_time_ms
 *   sort()           -> mxfs_pal_sort
 *   pr_info/etc      -> mxfs_pal_log
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "dlm.h"
#include "dlm_shared.h"

#define MXFS_DLM_DEFAULT_BUCKETS  4096

/* Internal retry sentinel: membership changed, caller should retry.
 * This value is never propagated to external callers — the retry
 * loop in mxfs_dlm_lock() catches it and re-attempts the lock. */
#define MXFS_DLM_RETRY  (-1000)

/* Compatibility matrix + resource hash/equal: lifted to dlm_shared.c
 * (§11 step 3) — one copy shared with dlm_caw.c and the NET2 lock
 * plane. */

static const char * const lock_mode_names[] = {
    "NL", "CR", "CW", "PR", "PW", "EX"
};

static const char * const lock_state_names[] = {
    "UNLOCKED", "WAITING", "GRANTED", "CONVERTING", "BLOCKED"
};

static inline const char *mode_name(uint8_t mode)
{
    if (mode < MXFS_LOCK_MODE_COUNT)
        return lock_mode_names[mode];
    return "??";
}

/*
 * sess-tcp: master lock-table entry-lifecycle trace (P-LKT) for the proven
 * tcp_dlm_scaling DOUBLE-GRANT.  Gated behind the lightweight mxfs.lockwr
 * param (kernel only; user-mode dlm builds compile it out).  Logs INODE
 * resource grant inserts and every entry removal so a spurious removal that
 * lets two nodes hold dir-EX is visible.
 */
#ifdef __KERNEL__
extern int mxfs_lockwr_enabled;
#define lockwr_on() (unlikely(mxfs_lockwr_enabled))
#define dlm_cur_comm() (current->comm)
#else
#define lockwr_on() (0)
#define dlm_cur_comm() "user"
#endif

/*
 * sess39: membership-settle gate.  mxfs_memb_settle_ms is the window (ms) for
 * which EX acquires are frozen after the active-node set changes.  Defined as a
 * module_param in v5_mount.c (kernel); user-mode builds disable the gate.
 *
 * ROOT (PROVEN, RULE 4): during 8-node cluster FORMATION the membership ramps
 * 1->8 and nodes briefly hold DIVERGENT views (P-STALEMASTER-GRANT fired at
 * active_count=5 and =6, t=47s, on a fresh-boot run) -> inconsistent
 * mastership -> two nodes grant EX for the same dir -> mass dir corruption
 * (readdir=0/8 catastrophic).  Freezing EX acquires until the local view has
 * been stable for the settle window means every node defers its EX work until
 * membership has globally converged (all nodes observe the final set within
 * ~discovery-interval of each other, well under the window), so masters are
 * computed consistently and no split-brain EX is granted.  Steady-state has no
 * membership change, so the gate never fires (zero perf impact); combined with
 * the deferred-TCP-death fix (transient flaps no longer mutate membership) the
 * gate fires only on real formation / death events.
 */
#ifdef __KERNEL__
extern int mxfs_memb_settle_ms;
#else
#define mxfs_memb_settle_ms 0
#endif

/* Max time (ms) a single EX acquire will block waiting for membership to
 * settle — a backstop so pathological continuous churn cannot wedge a thread
 * forever (it falls through and the normal grant/retry path runs). */
#define MXFS_DLM_SETTLE_MAX_WAIT_MS 60000

/* v0.11.78 (D7): positive convergence proof.  TRUE iff every node in my
 * current active view has reported (via the lease beacon's piggybacked view
 * signature, ~500ms cadence) the SAME {count,hash} as mine, received AFTER
 * my last membership change.  Equal signatures over the sorted member list
 * mean every confirmer computes the identical nodes[hash%count] mastery
 * mapping — the exact property the wall-clock settle window approximates.
 * Runs only inside the (rare) settle window, so the mutex is off the hot
 * path.  A node whose beacons we cannot see keeps this FALSE and the
 * wall-clock fallback below behaves exactly as before. */
static bool dlm_view_confirmed(struct mxfs_dlm_ctx *ctx)
{
    bool ok = true;
    int i, j;

    mxfs_pal_mutex_lock(ctx->active_nodes.lock);
    if (ctx->my_view_hash == 0 || ctx->active_nodes.count <= 1) {
        mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
        return false;
    }
    for (i = 0; i < ctx->active_nodes.count && ok; i++) {
        mxfs_node_id_t n = ctx->active_nodes.nodes[i];
        bool found = false;

        if (n == ctx->local_node)
            continue;
        for (j = 0; j < MXFS_MAX_NODES; j++) {
            if (ctx->peer_views[j].node_id != n)
                continue;
            found = (ctx->peer_views[j].hash == ctx->my_view_hash &&
                     ctx->peer_views[j].count == ctx->my_view_count &&
                     ctx->peer_views[j].rx_ms >= ctx->last_memb_change_ms);
            break;
        }
        if (!found)
            ok = false;
    }
    mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
    return ok;
}

static inline bool dlm_membership_settling(struct mxfs_dlm_ctx *ctx)
{
    uint64_t since;
    if (mxfs_memb_settle_ms <= 0 || ctx->last_memb_change_ms == 0)
        return false;
    if (ctx->active_nodes.count <= 1)
        return false;   /* single node: mastership is trivially consistent */
    since = mxfs_pal_time_ms() - ctx->last_memb_change_ms;
    if (since >= (uint64_t)mxfs_memb_settle_ms)
        return false;
    /* Inside the wall-clock window: a positive convergence proof ends the
     * freeze early (v0.11.78 D7 — the 20s window was eating every first
     * EX after any membership event, incl. a joiner's mount root-EX). */
    return !dlm_view_confirmed(ctx);
}

uint64_t mxfs_dlm_get_view_sig(struct mxfs_dlm_ctx *ctx, uint32_t *count)
{
    uint64_t h;

    if (!ctx) {
        if (count)
            *count = 0;
        return 0;
    }
    mxfs_pal_mutex_lock(ctx->active_nodes.lock);
    if (count)
        *count = ctx->my_view_count;
    h = ctx->my_view_hash;
    mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
    return h;
}

void mxfs_dlm_report_peer_view(struct mxfs_dlm_ctx *ctx,
                               mxfs_node_id_t node,
                               uint32_t count, uint64_t hash)
{
    int i, free_slot = -1;

    if (!ctx || !node || !hash)
        return;
    mxfs_pal_mutex_lock(ctx->active_nodes.lock);
    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->peer_views[i].node_id == node)
            break;
        if (free_slot < 0 && ctx->peer_views[i].node_id == 0)
            free_slot = i;
    }
    if (i == MXFS_MAX_NODES) {
        if (free_slot < 0) {
            mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
            return;
        }
        i = free_slot;
        ctx->peer_views[i].node_id = node;
    }
    ctx->peer_views[i].count = count;
    ctx->peer_views[i].hash = hash;
    ctx->peer_views[i].rx_ms = mxfs_pal_time_ms();
    mxfs_pal_mutex_unlock(ctx->active_nodes.lock);
}

/*
 * sess-tcp: LOCK-FREE master lock-table entry-lifecycle ring for the proven
 * tcp_dlm_scaling DOUBLE-GRANT.  Records {ts, action, ino, owner, mode} into a
 * fixed in-memory ring with NO printk in the hot path — printk (P-LKT / instr /
 * dirwr) PERTURBS the tight grant/release race and HIDES it (proven 6/6 pass
 * with mxfs.lockwr=1 printk).  All P_LKT() call sites already hold
 * ctx->table_rwlock (grant insert / remove / release), so a plain ring write is
 * safe without new locking; we use an atomic index only to be defensive.
 * Dump the ring post-mortem (after the leftover is observed) via the lktdump
 * param.  Recording is gated on mxfs.lockwr so default builds pay nothing.
 */
struct mxfs_lkt_ev {
    uint64_t        seq;        /* global monotonic event order (primary) */
    uint64_t        ts_ms;      /* mxfs_pal_time_ms (coarse, cross-node-ish) */
    uint64_t        ino;
    const char      *act;
    uint32_t        owner;
    uint8_t         mode;
    uint8_t         rtype;
};
#define MXFS_LKT_RING_SZ 16384          /* power of two */
#define MXFS_LKT_RING_MASK (MXFS_LKT_RING_SZ - 1)
static struct mxfs_lkt_ev mxfs_lkt_ring[MXFS_LKT_RING_SZ];
/* Plain counter: EVERY P_LKT() call site already holds ctx->table_rwlock
 * (grant insert / removal / release), so increments are serialized.  The dump
 * is post-mortem (churn stopped) so it needs no lock. */
static uint64_t mxfs_lkt_seq;

static inline void mxfs_lkt_record(const char *act,
                                   const struct mxfs_resource_id *res,
                                   uint32_t owner, uint8_t mode)
{
    uint64_t gseq;
    struct mxfs_lkt_ev *e;

    if (!lockwr_on() || !res || res->type != MXFS_LTYPE_INODE)
        return;
    /* sess13: optional single-inode filter to keep the shared dir's cross-node
     * events from being evicted by the child-inode GRANT-LOCAL flood. */
    {
        extern unsigned long long mxfs_lkt_ino;
        if (mxfs_lkt_ino && res->ino != mxfs_lkt_ino)
            return;
    }
    gseq = ++mxfs_lkt_seq;
    e = &mxfs_lkt_ring[(gseq - 1) & MXFS_LKT_RING_MASK];
    e->seq   = gseq;
    e->ts_ms = mxfs_pal_time_ms();
    e->ino   = res->ino;
    e->act   = act;
    e->owner = owner;
    e->mode  = mode;
    e->rtype = res->type;
}

/* Post-mortem dump of the recorded events for one inode (or all if ino==0).
 * Runs AFTER the race on explicit trigger (lktdump param), so logging here
 * does not perturb the timing.  Uses mxfs_pal_log per dlm.c convention. */
void mxfs_dlm_lkt_dump(uint64_t want_ino)
{
    uint64_t cur = mxfs_lkt_seq;
    uint64_t n = cur < MXFS_LKT_RING_SZ ? cur : MXFS_LKT_RING_SZ;
    uint64_t i;

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P-LKT-DUMP begin ino=%llu total_events=%llu",
                 (unsigned long long)want_ino, (unsigned long long)cur);
    for (i = 0; i < n; i++) {
        struct mxfs_lkt_ev *e =
            &mxfs_lkt_ring[(cur - n + i) & MXFS_LKT_RING_MASK];

        if (want_ino && e->ino != want_ino)
            continue;
        mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P-LKT seq=%llu ts_ms=%llu %s ino=%llu owner=%u mode=%s",
                 (unsigned long long)e->seq,
                 (unsigned long long)e->ts_ms,
                 e->act ? e->act : "?",
                 (unsigned long long)e->ino, e->owner,
                 e->mode < MXFS_LOCK_MODE_COUNT ?
                     lock_mode_names[e->mode] : "??");
    }
    mxfs_pal_log(MXFS_LOG_WARN, "mxfs: P-LKT-DUMP end ino=%llu",
                 (unsigned long long)want_ino);
}

#define P_LKT(act, res, own, md) mxfs_lkt_record((act), (res), (own), (md))

static inline const char *state_name(uint8_t state)
{
    if (state <= MXFS_LSTATE_BLOCKED)
        return lock_state_names[state];
    return "??";
}

/* resource_hash_raw / resource_equal live in dlm_shared.c (step-3 lift). */

static uint32_t resource_hash(const struct mxfs_resource_id *res,
                              uint32_t bucket_count)
{
    return resource_hash_raw(res) % bucket_count;
}

/* ─── Pending remote request hash helpers ─── */

static uint32_t pending_hash(const struct mxfs_resource_id *res)
{
    return resource_hash_raw(res) & (MXFS_DLM_PENDING_SIZE - 1);
}

/* ─── Lock allocation ─── */

static struct mxfs_lock *lock_alloc(const struct mxfs_resource_id *resource,
                                    mxfs_node_id_t owner,
                                    uint8_t mode, uint8_t state, uint32_t flags)
{
    struct mxfs_lock *lk;

    lk = mxfs_pal_alloc(sizeof(*lk));
    if (!lk)
        return NULL;

    lk->resource = *resource;
    lk->owner = owner;
    lk->mode = mode;
    lk->state = state;
    lk->flags = flags;
    lk->queued_at = mxfs_pal_time_ms();
    if (state == MXFS_LSTATE_GRANTED)
        lk->granted_at = lk->queued_at;
    lk->grant_gen = 0;
    lk->handoff = false;   /* sess63: set true only by dg_grant_ex on handoff */
    lk->next = NULL;
    lk->work_next = NULL;
    lk->pend_waiter = NULL;
    /* sess4(a16ec5f2) POINTER-LIFECYCLE trace: run19 caught the -ETIMEDOUT
     * lock_free(newlk) freeing a REMOTE holder's GRANTED entry (owner and
     * state at free time belonged to test5's live EX gen 8210, yet the
     * pointer matched OUR local WAITING newlk) -> live holder silently
     * dropped from the table -> immediate re-grant -> concurrent EX ->
     * stale-base RMW dirent loss.  Trace every alloc/free with %px for
     * storm-range inodes so the alias/UAF chain is directly visible. */
    if (resource->type == MXFS_LTYPE_INODE && resource->ino <= 256) {
        static atomic_t p4l_n = ATOMIC_INIT(0);
        if (atomic_inc_return(&p4l_n) <= 400000)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P4L-ALLOC ino=%llu ptr=%px owner=%u mode=%u state=%u",
                         (unsigned long long)resource->ino, lk,
                         (unsigned)owner, (unsigned)mode, (unsigned)state);
    }
    return lk;
}

static void lock_free(struct mxfs_lock *lk)
{
    /* sess52(ccloop) PHANTOM-EX probe: catch a GRANTED inode grant being FREED.
     * The proven dir_reuse loss = a dir modify under i_dlm_mode=EX while the
     * local DLM entry is gone (held=0).  bast_process couples its free with
     * i_dlm_mode=NL; any OTHER path that frees our GRANTED entry leaves the XFS
     * cached EX phantom.  Log ino + owner + mode + return address so the caller
     * (which lock_free site) is identified and correlated with a P51-PHANTOM. */
    if (lk && lk->state == MXFS_LSTATE_GRANTED &&
        lk->resource.type == MXFS_LTYPE_INODE &&
        lk->resource.ino <= 256 && lk->mode >= MXFS_LOCK_EX)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P52-GRANT-FREE ino=%llu owner=%u mode=%u ret=%pS",
                     (unsigned long long)lk->resource.ino,
                     (unsigned)lk->owner, (unsigned)lk->mode,
                     __builtin_return_address(0));
    /* sess4(a16ec5f2): pointer-lifecycle trace, ALL states (see lock_alloc). */
    if (lk && lk->resource.type == MXFS_LTYPE_INODE &&
        lk->resource.ino <= 256) {
        static atomic_t p4f_n = ATOMIC_INIT(0);
        if (atomic_inc_return(&p4f_n) <= 400000)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P4L-FREE ino=%llu ptr=%px owner=%u mode=%u state=%u gen=%u ret=%pS",
                         (unsigned long long)lk->resource.ino, lk,
                         (unsigned)lk->owner, (unsigned)lk->mode,
                         (unsigned)lk->state, lk->grant_gen,
                         __builtin_return_address(0));
    }
    mxfs_pal_free(lk);
}

/* ─── Pending entry helpers ─── */

static struct mxfs_dlm_pending *pending_alloc(
    const struct mxfs_resource_id *resource)
{
    struct mxfs_dlm_pending *p;

    p = mxfs_pal_alloc(sizeof(*p));
    if (!p)
        return NULL;

    p->resource = *resource;
    p->lock = mxfs_pal_mutex_create();
    p->cond = mxfs_pal_cond_create();
    p->done = false;
    p->granted_mode = MXFS_LOCK_NL;
    p->status = 0;
    p->request_epoch = 0;
    p->next = NULL;

    if (!p->lock || !p->cond) {
        if (p->lock) mxfs_pal_mutex_destroy(p->lock);
        if (p->cond) mxfs_pal_cond_destroy(p->cond);
        mxfs_pal_free(p);
        return NULL;
    }

    return p;
}

static void pending_free(struct mxfs_dlm_pending *p)
{
    if (!p)
        return;
    if (p->lock) mxfs_pal_mutex_destroy(p->lock);
    if (p->cond) mxfs_pal_cond_destroy(p->cond);
    mxfs_pal_free(p);
}

/* Signal a pending entry that its request is done */
static void pending_complete(struct mxfs_dlm_pending *p,
                             uint8_t mode, int status)
{
    mxfs_pal_mutex_lock(p->lock);
    p->granted_mode = mode;
    p->status = status;
    p->done = true;
    mxfs_pal_cond_signal(p->cond);
    mxfs_pal_mutex_unlock(p->lock);
}

/* Wait for a pending entry to be completed with timeout */
static int pending_wait(struct mxfs_dlm_pending *p, uint64_t timeout_ms)
{
    int ret = 0;

    mxfs_pal_mutex_lock(p->lock);
    while (!p->done) {
        ret = mxfs_pal_cond_timedwait(p->cond, p->lock, timeout_ms);
        if (ret == -ETIMEDOUT)
            break;
    }
    mxfs_pal_mutex_unlock(p->lock);

    return p->done ? 0 : ret;
}

/* Insert a pending entry into the hash table */
static void pending_insert(struct mxfs_dlm_ctx *ctx,
                           struct mxfs_dlm_pending *p)
{
    uint32_t ph = pending_hash(&p->resource);

    mxfs_pal_mutex_lock(ctx->pending_lock);
    p->next = ctx->pending_buckets[ph];
    ctx->pending_buckets[ph] = p;
    mxfs_pal_mutex_unlock(ctx->pending_lock);
}

/* Remove a pending entry from the hash table */
static void pending_remove(struct mxfs_dlm_ctx *ctx,
                           struct mxfs_dlm_pending *p)
{
    uint32_t ph = pending_hash(&p->resource);

    mxfs_pal_mutex_lock(ctx->pending_lock);
    if (ctx->pending_buckets[ph] == p) {
        ctx->pending_buckets[ph] = p->next;
    } else {
        struct mxfs_dlm_pending *cur;

        for (cur = ctx->pending_buckets[ph]; cur; cur = cur->next) {
            if (cur->next == p) {
                cur->next = p->next;
                break;
            }
        }
    }
    mxfs_pal_mutex_unlock(ctx->pending_lock);
}

/* Find and complete a pending entry for a resource.
 *
 * epoch parameter: if non-zero, only match a pending entry whose
 * request_epoch matches. This filters out stale grants from a
 * previous epoch's master that arrive after a membership change
 * caused the requester to retry with a new master (Bug 67).
 * Internal callers (promote_waiters, purge_node, etc.) pass 0
 * to match any pending entry regardless of epoch. */
static bool pending_signal_resource(struct mxfs_dlm_ctx *ctx,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t mode, int status,
                                    mxfs_epoch_t epoch)
{
    uint32_t ph = pending_hash(resource);
    struct mxfs_dlm_pending *p;

    mxfs_pal_mutex_lock(ctx->pending_lock);
    for (p = ctx->pending_buckets[ph]; p; p = p->next) {
        if (resource_equal(&p->resource, resource)) {
            /* If epoch is specified, only discard grants from a HIGHER
             * epoch than the request (genuinely stale: the request was
             * sent to an old master, and a newer master also granted).
             * Accept grants from the SAME or LOWER epoch — a lower
             * epoch means the master hasn't processed the membership
             * change yet but the grant is still valid (Bug 74). */
            if (epoch != 0 && p->request_epoch != 0 &&
                epoch > p->request_epoch) {
                mxfs_pal_mutex_unlock(ctx->pending_lock);
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "dlm: discarding stale grant for ino %llu "
                             "type %u (grant_epoch=%llu request_epoch=%llu)",
                             (unsigned long long)resource->ino,
                             resource->type,
                             (unsigned long long)epoch,
                             (unsigned long long)p->request_epoch);
                return false;
            }
            mxfs_pal_mutex_unlock(ctx->pending_lock);
            pending_complete(p, mode, status);
            return true;
        }
    }
    mxfs_pal_mutex_unlock(ctx->pending_lock);
    return false;
}

/*
 * Fail-complete ALL pending entries with MXFS_DLM_RETRY.
 *
 * Called from mxfs_dlm_update_active_nodes() after a membership change
 * purges the lock table. Threads sleeping in pending_wait() — both
 * remote-master requests waiting for a dead node's grant, and
 * local-master requests waiting for a BAST holder that was just purged
 * — must be woken immediately so they can retry with the new master
 * assignment.
 *
 * Without this, threads block for up to MXFS_LOCK_WAIT_TIMEOUT_MS
 * (120s) on a grant that will never arrive, causing D-state hangs
 * for filesystem operations like ls -la and rm -rf.
 */
static void fail_all_pending(struct mxfs_dlm_ctx *ctx)
{
    struct mxfs_dlm_pending *to_wake[MXFS_MAX_NODES];
    int woken = 0;
    int i;

    /* Collect all incomplete pending entries under pending_lock,
     * then signal them WITHOUT holding the lock. This matches
     * the lock ordering in pending_signal_resource() which also
     * releases pending_lock before calling pending_complete(). */
    mxfs_pal_mutex_lock(ctx->pending_lock);
    for (i = 0; i < MXFS_DLM_PENDING_SIZE; i++) {
        struct mxfs_dlm_pending *p;

        for (p = ctx->pending_buckets[i]; p; p = p->next) {
            if (!p->done && woken < MXFS_MAX_NODES)
                to_wake[woken++] = p;
        }
    }
    mxfs_pal_mutex_unlock(ctx->pending_lock);

    for (i = 0; i < woken; i++)
        pending_complete(to_wake[i], MXFS_LOCK_NL, MXFS_DLM_RETRY);

    if (woken > 0)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "dlm: membership change woke %d pending lock "
                     "requests", woken);
}

/* ─── Deferred BAST records ───
 *
 * BAST callbacks must be deferred until table_rwlock is released: the
 * BAST handler may call mxfs_dlm_unlock() which needs table_rwlock.
 *
 * CRITICAL: We must NOT iterate live lock entries (via work_next) after
 * releasing table_rwlock, because concurrent lock releases can trigger
 * promote_waiters()/collect_post_promotion_basts() which overwrite
 * work_next on those same entries.  With 3+ nodes, a fast holder can
 * release its lock (in response to a BAST) while we're still sending
 * BASTs to subsequent holders, corrupting the work_next chain.
 *
 * Fix: copy BAST targets into a stack-allocated array while under
 * table_rwlock, then iterate the copy after release.
 *
 * Grant dispatching (pending_signal_resource / send_grant) is safe to
 * call while holding table_rwlock, so grants are dispatched inline.
 */

/* Snapshot of a BAST target — copied while under table_rwlock.
 *
 * We only capture (owner, requested_mode) per record.  The resource
 * is the same for all BASTs in a single operation, so it's passed
 * separately to save stack space (avoids copying the full 32-byte
 * resource_id into each record). */
struct mxfs_bast_record {
    mxfs_node_id_t owner;
    uint8_t requested_mode;
};

/* Stack-safe limit: 8 bytes per record * 64 = 512 bytes.
 * Supports up to 64 conflicting holders on a single resource. */
#define MXFS_MAX_BAST_RECORDS  MXFS_MAX_NODES

/* Fire an array of captured BAST records.  Must be called WITHOUT
 * table_rwlock held.  All records share the same resource.
 *
 * The bast_cb callback (dlm_bast_cb in mount.c) handles both local
 * BASTs (queued to bast_worker) and remote BASTs (sent via peer_send
 * with retry).  Since the callback returns void, delivery errors are
 * handled inside the callback itself.  If a remote BAST ultimately
 * fails, the requesting node's pending_wait will timeout and retry. */
static void fire_bast_records(struct mxfs_dlm_ctx *ctx,
                              const struct mxfs_resource_id *resource,
                              struct mxfs_bast_record *recs, int count)
{
    int i;

    if (!ctx->bast_cb) {
        if (count > 0)
            mxfs_pal_log(MXFS_LOG_ERR,
                         "dlm: fire_bast_records: %d BASTs for ino %llu "
                         "but bast_cb is NULL",
                         count,
                         (unsigned long long)resource->ino);
        return;
    }

    for (i = 0; i < count; i++) {
        /* DLM_TRACE: log each BAST fire for inode 128 */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: BAST FIRE ino=128 target_node=%u "
                         "requested_mode=%s local_node=%u "
                         "bast_idx=%d/%d",
                         recs[i].owner,
                         mode_name(recs[i].requested_mode),
                         ctx->local_node, i, count);
        /* sess1(a9a03929) RULE-4 (run45 120s ino-131 wedge): make EVERY
         * master-side BAST fire visible for the hot dirs — pairs with the
         * receiver's P7B-BASTNOTIFY to prove whether a missing release is
         * a master hole (no P7S) or a receiver swallow (P7S, no action). */
        if (resource->type == MXFS_LTYPE_INODE && resource->ino <= 256) {
            static atomic_t p7s_n = ATOMIC_INIT(0);
            if ((unsigned)atomic_inc_return(&p7s_n) <= 60000)
                pr_warn("mxfs: P7S-BAST-FIRE ino=%llu target=%u reqmode=%s\n",
                        (unsigned long long)resource->ino, recs[i].owner,
                        mode_name(recs[i].requested_mode));
        }
        ctx->bast_cb(ctx, resource,
                     recs[i].owner, recs[i].requested_mode);
    }
}

/* sess35 (ccloop) ROOT FIX for the dir_reuse 2/tcp ~6s handoff (RULE 4 PROVEN:
 * the holder honors a BAST in ~14us, yet the requester ALWAYS waits the full
 * MXFS_LOCK_ACQUIRE_WAIT_MS=6000ms — then its retry re-fires the BAST and wins,
 * so dur_ms clusters just above 6000).
 *
 * Root: a DIRECT grant that KEEPS the grantee holding — a PR->EX upgrade
 * (dlm_lock_impl / process_remote_request conv_compat paths) or a remote
 * REAFFIRM — is decided ONLY against conflicting GRANTED holders.  It ignores
 * any WAITING/BLOCKED entry and fires NO BAST.  So when a waiter had queued and
 * fired its BAST against the grantee's PRIOR (lower) grant, then the grantee
 * upgraded / re-acquired racing its own release ahead, the new grant carries no
 * BAST and the waiter is stranded — nothing tells the holder to release — until
 * the waiter's own 6000ms ACQUIRE_WAIT_MS timeout re-fires the BAST.  (The
 * RELEASE path already re-evaluates the queue via promote_waiters +
 * collect_post_promotion_basts; the direct-grant paths bypassed it.)
 *
 * After such a grant, scan for a conflicting WAITING/BLOCKED waiter; if one
 * exists, return a BAST record for the grantee so the caller fires it (after
 * dropping table_rwlock).  The grantee then releases promptly (microseconds,
 * batched by the Minimum-Hold-Time policy) instead of the waiter stalling 6s.
 * Caller holds table_rwlock.  Returns 1 and fills *rec if a BAST should fire. */
static int collect_grantee_bast_if_waiters(
    struct mxfs_lock *chain,
    const struct mxfs_resource_id *resource,
    mxfs_node_id_t grantee, uint8_t grantee_mode,
    struct mxfs_bast_record *rec)
{
    struct mxfs_lock *w;

    for (w = chain; w; w = w->next) {
        if (!resource_equal(&w->resource, resource))
            continue;
        if (w->state != MXFS_LSTATE_WAITING &&
            w->state != MXFS_LSTATE_BLOCKED)
            continue;
        if (w->owner == grantee)
            continue;
        if (!lock_compat[grantee_mode][w->mode]) {
            rec->owner = grantee;
            rec->requested_mode = w->mode;
            return 1;
        }
    }
    return 0;
}

/* sess16(ccloop) MX-DOUBLEGRANT auditor: clock-free master-side detector for the
 * dir_reuse lost-update double-grant hypothesis.  Scans the resource's GRANTED
 * holders in THIS master's table; if any two DIFFERENT-owner holders are
 * mode-incompatible (e.g. two EX, or EX+PR), the master has issued conflicting
 * grants = a serialization break that lets two nodes RMW the shared dir block
 * concurrently (the count=126->77 clobber).  Always-on, capped, loud.  Called
 * with table_rwlock held, AFTER a grant is committed.  Returns # of conflicting
 * pairs (0 = serialized correctly). */
static int mxfs_dlm_audit_double_grant(struct mxfs_lock *chain,
                                       const struct mxfs_resource_id *resource)
{
    struct mxfs_lock *a, *b;
    int conflicts = 0;

    for (a = chain; a; a = a->next) {
        if (a->state != MXFS_LSTATE_GRANTED)
            continue;
        if (!resource_equal(&a->resource, resource))
            continue;
        for (b = a->next; b; b = b->next) {
            if (b->state != MXFS_LSTATE_GRANTED)
                continue;
            if (!resource_equal(&b->resource, resource))
                continue;
            if (b->owner == a->owner)
                continue;
            if (!lock_compat[a->mode][b->mode]) {
                static atomic_t dg_n = ATOMIC_INIT(0);
                conflicts++;
                if (atomic_inc_return(&dg_n) <= 2000)
                    pr_warn("mxfs: MX-DOUBLEGRANT ino=%llu type=%u ownerA=%u modeA=%s ownerB=%u modeB=%s — master granted CONFLICTING holders (serialization break)\n",
                            (unsigned long long)resource->ino,
                            resource->type,
                            a->owner, mode_name(a->mode),
                            b->owner, mode_name(b->mode));
            }
        }
    }
    return conflicts;
}

/* ─── Waiter promotion helpers ─── */

#define MAX_WAITERS      MXFS_MAX_NODES

/* Comparison for sorting waiters by queued_at (oldest first = FIFO) */
static int waiter_cmp(const void *a, const void *b)
{
    const struct mxfs_lock *la = *(const struct mxfs_lock *const *)a;
    const struct mxfs_lock *lb = *(const struct mxfs_lock *const *)b;

    if (la->queued_at < lb->queued_at) return -1;
    if (la->queued_at > lb->queued_at) return 1;
    return 0;
}

/*
 * find_conflicting_waiter — arrival-time FIFO barrier (sess6 a16ec5f2)
 *
 * promote_waiters enforces FIFO at RELEASE time (an EX waiter blocks
 * younger PR waiters behind it), but the immediate-grant paths
 * (check_compat / remote_check_compat) only tested the new request
 * against GRANTED holders — so a steady stream of arriving PR requests
 * was granted straight past a queued EX waiter.  The EX never saw a
 * zero-PR window, timed out every MXFS_LOCK_ACQUIRE_WAIT_MS, was
 * removed and re-queued at the BACK of the FIFO (fresh queued_at), and
 * starved: the P36-RETRY 1s handoff stalls (~10/round on the 8-node
 * create/verify/rm workload, measured run39).
 *
 * Returns the first WAITING/BLOCKED entry from a DIFFERENT owner whose
 * requested mode conflicts with `mode`, or NULL.  A hit means the new
 * request must queue behind it instead of being granted on arrival.
 * Conversions/reaffirms are handled BEFORE the check_compat labels and
 * keep their priority (denying a holder's upgrade cannot help the
 * waiter — the holder's existing grant blocks it anyway — and queuing
 * upgrades behind waiters is the classic conversion deadlock).
 */
static struct mxfs_lock *find_conflicting_waiter(struct mxfs_lock *chain,
                                                 const struct mxfs_resource_id *resource,
                                                 mxfs_node_id_t requester,
                                                 uint8_t mode)
{
    struct mxfs_lock *lk;

    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state != MXFS_LSTATE_WAITING &&
            lk->state != MXFS_LSTATE_BLOCKED)
            continue;
        if (lk->owner == requester)
            continue;
        if (!lock_compat[lk->mode][mode])
            return lk;
    }
    return NULL;
}

/*
 * promote_waiters — FIFO grant ordering
 *
 * Collects all waiters for a resource, sorts by queued_at (oldest first),
 * then grants in order. Stops at the first incompatible waiter to prevent
 * starvation: an EX waiter blocks younger PR waiters behind it, and a PR
 * waiter blocks younger EX waiters behind it.
 */
static uint32_t dlm_next_gen(struct mxfs_dlm_ctx *ctx);  /* sess-tcp fwd decl */

static struct mxfs_lock *promote_waiters(struct mxfs_dlm_ctx *ctx,
                                          struct mxfs_lock *chain,
                                          const struct mxfs_resource_id *resource)
{
    struct mxfs_lock *lk, *other;
    struct mxfs_lock *waiters[MAX_WAITERS];
    int nwaiters = 0;
    struct mxfs_lock *grant_list = NULL;
    int i, ok;

    /* Pass 1: collect all waiters for this resource */
    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state != MXFS_LSTATE_WAITING &&
            lk->state != MXFS_LSTATE_BLOCKED)
            continue;
        if (nwaiters < MAX_WAITERS)
            waiters[nwaiters++] = lk;
    }

    if (nwaiters == 0)
        return NULL;

    /* Sort waiters by queued_at — oldest first (FIFO) */
    mxfs_pal_sort(waiters, (size_t)nwaiters, sizeof(waiters[0]), waiter_cmp);

    /* Pass 2: grant in FIFO order, stop at first incompatible */
    for (i = 0; i < nwaiters; i++) {
        lk = waiters[i];

        ok = 1;
        for (other = chain; other; other = other->next) {
            if (!resource_equal(&other->resource, resource))
                continue;
            if (other->state != MXFS_LSTATE_GRANTED)
                continue;
            if (other->owner == lk->owner)
                continue;
            if (!lock_compat[other->mode][lk->mode]) {
                ok = 0;
                break;
            }
        }

        if (ok) {
            lk->state = MXFS_LSTATE_GRANTED;
            lk->granted_at = mxfs_pal_time_ms();
            lk->grant_gen = dlm_next_gen(ctx);
            /* sess4(a16ec5f2): granted — the waiter is about to be signaled
             * and no longer needs reap-protection; a GRANTED entry is the
             * unlock primary target anyway. */
            lk->pend_waiter = NULL;
            lk->work_next = grant_list;
            grant_list = lk;
            /* sess4(a16ec5f2): pointer-lifecycle trace (see lock_alloc). */
            if (resource->type == MXFS_LTYPE_INODE &&
                resource->ino <= 256) {
                static atomic_t p4p_n = ATOMIC_INIT(0);
                if (atomic_inc_return(&p4p_n) <= 400000)
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: P4L-PROMOTE ino=%llu ptr=%px owner=%u mode=%u gen=%u",
                                 (unsigned long long)resource->ino, lk,
                                 (unsigned)lk->owner, (unsigned)lk->mode,
                                 lk->grant_gen);
            }
            mxfs_dlm_audit_double_grant(chain, resource);
            /* DLM_TRACE: log each waiter promotion for ino 128 */
            if (resource->ino == 128 &&
                resource->type == MXFS_LTYPE_INODE)
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "DLM_TRACE: promote_waiters GRANTED "
                             "ino=128 owner=%u mode=%s",
                             lk->owner, mode_name(lk->mode));
        } else {
            /* FIFO barrier: stop here. Younger waiters stay blocked
             * even if they'd be compatible with current grants.
             * This prevents starvation of this incompatible waiter. */
            /* DLM_TRACE: log FIFO barrier for ino 128 */
            if (resource->ino == 128 &&
                resource->type == MXFS_LTYPE_INODE)
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "DLM_TRACE: promote_waiters BLOCKED "
                             "ino=128 owner=%u mode=%s "
                             "(FIFO barrier, %d remaining)",
                             lk->owner, mode_name(lk->mode),
                             nwaiters - i - 1);
            lk->state = MXFS_LSTATE_BLOCKED;
            /* Mark all remaining waiters as blocked too */
            for (i++; i < nwaiters; i++)
                waiters[i]->state = MXFS_LSTATE_BLOCKED;
            break;
        }
    }

    return grant_list;
}

/*
 * collect_post_promotion_basts — VMS DLM post-promotion BAST collection
 *
 * After promote_waiters grants some waiters, there may be remaining
 * BLOCKED waiters. The newly-granted holders need BASTs so they release
 * when done, allowing the blocked waiters to proceed.
 *
 * Without this, a promoted holder caches the lock indefinitely (per-inode
 * lock caching) and remaining waiters starve/timeout. This is the B→C→D
 * chain in the VMS DLM model: each promoted holder must be told that
 * someone is waiting behind it.
 *
 * Must be called with table_rwlock held.
 */
static struct mxfs_lock *collect_post_promotion_basts(
    struct mxfs_lock *chain,
    const struct mxfs_resource_id *resource,
    uint8_t *blocked_mode_out)
{
    struct mxfs_lock *lk, *blocked;
    struct mxfs_lock *bast_list = NULL;

    *blocked_mode_out = MXFS_LOCK_NL;

    /* Find the first BLOCKED waiter */
    blocked = NULL;
    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state == MXFS_LSTATE_BLOCKED) {
            blocked = lk;
            break;
        }
    }

    if (!blocked)
        return NULL;

    *blocked_mode_out = blocked->mode;

    /* Collect BASTs for GRANTED holders that conflict with the
     * blocked waiter's requested mode */
    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED)
            continue;
        if (lk->owner == blocked->owner)
            continue;
        if (!lock_compat[lk->mode][blocked->mode]) {
            lk->work_next = bast_list;
            bast_list = lk;
        }
    }

    return bast_list;
}

/* sess-tcp double-grant fix: allocate the next monotonic grant generation.
 * Caller MUST hold table_rwlock (all grant sites do).  Never returns 0 so
 * a 0 grant_gen on the wire/mirror reliably means "no recorded grant". */
static uint32_t dlm_next_gen(struct mxfs_dlm_ctx *ctx)
{
    uint32_t g = ++ctx->grant_gen_next;
    if (g == 0)
        g = ctx->grant_gen_next = 1;
    return g;
}

/* Send a grant/deny response to a remote node.
 * Retries once after 10ms on failure.  If the retry also fails,
 * the requesting node's pending_wait will timeout and retry. */
/* sess8 double-grant detector — forward decls (defined below
 * process_remote_request); all callers hold ctx->table_rwlock. */
static bool dg_grant_ex(struct mxfs_dlm_ctx *ctx,
                        const struct mxfs_resource_id *res,
                        mxfs_node_id_t owner, uint32_t gen,
                        uint32_t *epoch_out);
static void dg_release(const struct mxfs_resource_id *res,
                       mxfs_node_id_t owner);

static void send_grant(struct mxfs_dlm_ctx *ctx,
                       mxfs_node_id_t target,
                       const struct mxfs_resource_id *resource,
                       uint8_t mode, uint8_t status_code,
                       uint16_t msg_type, mxfs_epoch_t epoch,
                       uint32_t grant_gen, uint8_t handoff,
                       uint32_t dir_epoch)
{
    struct mxfs_dlm_lock_resp resp;
    int ret;

    if (!ctx->send_cb)
        return;

    memset(&resp, 0, sizeof(resp));
    resp.hdr.magic = MXFS_DLM_MAGIC;
    resp.hdr.version = MXFS_DLM_VERSION;
    resp.hdr.type = msg_type;
    resp.hdr.length = sizeof(resp);
    resp.hdr.sender = ctx->local_node;
    resp.hdr.target = target;
    resp.hdr.epoch = epoch;
    resp.resource = *resource;
    resp.mode = mode;
    resp.status = status_code;
    resp.handoff = handoff;   /* sess63: cross-node EX handoff signal */
    resp.grant_gen = grant_gen;
    resp.dir_epoch = dir_epoch;  /* sess64: monotonic cross-node handoff epoch */

    /* sess50(ccloop) RULE-4: log the dir_epoch this master SENDS on an EX grant
     * for the storm dir (ino 131).  Pairs with P44-GRANTDIREPOCH (the grantee's
     * stored lk->dir_epoch) and P64-MASTER-HANDOFF (the master's dg_shadow.epoch)
     * to localize WHERE the monotonic handoff epoch is lost (sent=0 => caller
     * computed 0; sent>0 but P44 reads 0 => receive/store bug). */
    if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131 &&
        mode == MXFS_LOCK_EX) {
        static atomic_t p51sg = ATOMIC_INIT(0);
        /* sess5(a16ec5f2): CAPPED (not ratelimited) — the deny-window grant
         * (the P2-EPOCHPLACE master_ep=0 loss precursor) was ratelimit-
         * suppressed in run37; every ino-131 EX grant's sent epoch must be
         * visible to split master-computed-0 vs receiver-lost. */
        if ((unsigned)atomic_inc_return(&p51sg) <= 60000)
            pr_warn("mxfs: P51-SENDGRANT ino=131 target=%u grant_gen=%u handoff=%u dir_epoch_sent=%u\n",
                                target, grant_gen, handoff, dir_epoch);
    }

    ret = ctx->send_cb(ctx, target, &resp, sizeof(resp));
    if (ret < 0) {
        mxfs_pal_sleep_ms(10);
        ret = ctx->send_cb(ctx, target, &resp, sizeof(resp));
        if (ret < 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: lock grant to node %u failed (retried), "
                         "file operations on that node may be delayed",
                         target);
    }
}

/* ─── Compatibility check ─── */

int mxfs_dlm_modes_compatible(uint8_t held, uint8_t requested)
{
    if (held >= MXFS_LOCK_MODE_COUNT || requested >= MXFS_LOCK_MODE_COUNT)
        return 0;
    return lock_compat[held][requested];
}

/* ─── Per-mount create / destroy ─── */

struct mxfs_dlm_ctx *mxfs_dlm_create(mxfs_node_id_t local_node)
{
    struct mxfs_dlm_ctx *ctx;
    int i;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->bucket_count = MXFS_DLM_DEFAULT_BUCKETS;
    ctx->buckets = mxfs_pal_alloc(ctx->bucket_count *
                                  sizeof(struct mxfs_lock *));
    if (!ctx->buckets) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "dlm: failed to allocate %u hash buckets",
                     ctx->bucket_count);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->lock_count = 0;
    ctx->table_rwlock = mxfs_pal_rwlock_create();
    if (!ctx->table_rwlock) {
        mxfs_pal_free(ctx->buckets);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->local_node = local_node;
    ctx->shutting_down = false;
    ctx->grant_gen_next = 1;
    ctx->current_epoch = 1;
    ctx->epoch_lock = mxfs_pal_mutex_create();

    ctx->active_nodes.lock = mxfs_pal_mutex_create();
    ctx->active_nodes.nodes[0] = local_node;
    ctx->active_nodes.count = 1;

    /* Init pending remote request hash table */
    ctx->pending_lock = mxfs_pal_mutex_create();
    for (i = 0; i < MXFS_DLM_PENDING_SIZE; i++)
        ctx->pending_buckets[i] = NULL;

    ctx->grant_cb = NULL;
    ctx->bast_cb = NULL;
    ctx->send_cb = NULL;
    ctx->membership_cb = NULL;
    ctx->cb_data = NULL;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: created for node %u with %u buckets",
                 ctx->local_node, ctx->bucket_count);
    return ctx;
}

void mxfs_dlm_destroy(struct mxfs_dlm_ctx *ctx)
{
    uint32_t i;
    uint32_t freed = 0;

    if (!ctx)
        return;

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    for (i = 0; i < ctx->bucket_count; i++) {
        struct mxfs_lock *lk = ctx->buckets[i];

        while (lk) {
            struct mxfs_lock *next = lk->next;

            lock_free(lk);
            freed++;
            lk = next;
        }
        ctx->buckets[i] = NULL;
    }

    ctx->lock_count = 0;
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    mxfs_pal_free(ctx->buckets);
    ctx->buckets = NULL;

    mxfs_pal_rwlock_destroy(ctx->table_rwlock);
    mxfs_pal_mutex_destroy(ctx->epoch_lock);
    mxfs_pal_mutex_destroy(ctx->active_nodes.lock);
    mxfs_pal_mutex_destroy(ctx->pending_lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: destroyed, freed %u lock entries", freed);
    mxfs_pal_free(ctx);
}

/* ─── mxfs_dlm_lock — Local lock acquisition ─── */

/*
 * Implementation body for mxfs_dlm_lock — called from the retry
 * wrapper below. Returns MXFS_DLM_RETRY if the request was
 * interrupted by a membership change and should be retried.
 */
static int dlm_lock_impl(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          uint8_t mode, uint32_t flags,
                          uint8_t *granted_mode)
{
    mxfs_node_id_t master;
    uint32_t bucket;
    struct mxfs_lock *chain, *lk;
    int compat;

    if (ctx->shutting_down)
        return -ESHUTDOWN;

    /*
     * sess39 membership-settle gate: do not acquire EX while the active-node
     * set is still converging (formation ramp or a recent death).  Block this
     * acquire until the view has been stable for mxfs_memb_settle_ms so the
     * master mapping is globally consistent before any exclusive dir/AG/inode
     * modification runs — closes the split-brain EX window that durably
     * corrupts the shared directory.  Bounded by SETTLE_MAX_WAIT so continuous
     * churn cannot wedge the thread.  Only EX (the mutual-exclusion mode that
     * causes the divergent-base RMW); shared reads are not gated.
     */
    if (mode == MXFS_LOCK_EX && dlm_membership_settling(ctx)) {
        int waited = 0;
        /* D7 RULE-4 probe: quantify the settle-gate share of slow EX
         * acquires (joiner root-EX stall 4.7-20s).  Entry logs how long
         * ago the view changed; exit logs the wall actually spent here. */
        uint64_t d7_since = mxfs_pal_time_ms() - ctx->last_memb_change_ms;

        while (dlm_membership_settling(ctx) && !ctx->shutting_down &&
               waited < MXFS_DLM_SETTLE_MAX_WAIT_MS) {
            mxfs_pal_sleep_ms(100);
            waited += 100;
        }
        if (waited > 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P-D7-SETTLEGATE type=%u ino=%llu ag=%u mode=%u "
                         "since_change=%llums settle_ms=%d waited=%dms confirmed=%d",
                         resource->type,
                         (unsigned long long)resource->ino,
                         resource->ag_number, mode,
                         (unsigned long long)d7_since,
                         mxfs_memb_settle_ms, waited,
                         dlm_view_confirmed(ctx) ? 1 : 0);
        if (ctx->shutting_down)
            return -ESHUTDOWN;
    }

    master = mxfs_dlm_resource_master(ctx, resource);

    /* ─── Remote master path ─── */
    if (master != ctx->local_node) {
        struct mxfs_dlm_lock_req req;
        struct mxfs_dlm_pending *pend;
        int ret;

        if (!ctx->send_cb)
            return -ENOTCONN;

        /* Build the wire message */
        memset(&req, 0, sizeof(req));
        req.hdr.magic = MXFS_DLM_MAGIC;
        req.hdr.version = MXFS_DLM_VERSION;
        req.hdr.type = MXFS_MSG_LOCK_REQ;
        req.hdr.length = sizeof(req);
        req.hdr.sender = ctx->local_node;
        req.hdr.target = master;
        req.hdr.epoch = ctx->current_epoch;
        req.resource = *resource;
        req.mode = mode;
        req.flags = flags;

        /* Set up pending entry — stamp with current epoch so that
         * stale grants from a previous master are rejected (Bug 67) */
        pend = pending_alloc(resource);
        if (!pend)
            return -ENOMEM;
        pend->request_epoch = ctx->current_epoch;

        pending_insert(ctx, pend);

        /* Send to remote master (retry up to 3 times on transient failure) */
        {
            int send_retries = 3;
            do {
                ret = ctx->send_cb(ctx, master, &req, sizeof(req));
                if (ret == 0)
                    break;
                if (--send_retries > 0) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: lock request to node %u failed, "
                                 "retrying (%d attempts remaining)",
                                 master, send_retries);
                    mxfs_pal_sleep_ms(100);
                }
            } while (send_retries > 0);
        }
        if (ret) {
            pending_remove(ctx, pend);
            pending_free(pend);
            return ret;
        }

        /* Wait for remote grant/deny (sess-tcp: shorter per-attempt wait;
         * mxfs_dlm_lock retries on -ETIMEDOUT to recover a lost grant msg). */
        ret = pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS);

        pending_remove(ctx, pend);

        if (ret == -ETIMEDOUT) {
            /* sess3 (ccloop a16ec5f2): remote-mastered timeout — the
             * requester cannot see the holder table; at least name the
             * resource + master so the master-side dmesg can be joined
             * (rate-limited: the caller retries this ~60x/acquire). */
            pr_warn_ratelimited(
                "mxfs: P-LKTIMEOUT-REMOTE type=%u ino=%llu ag=%u master=%u req=%s we=%u\n",
                resource->type, (unsigned long long)resource->ino,
                resource->ag_number, master, mode_name(mode),
                ctx->local_node);
            pending_free(pend);
            return -ETIMEDOUT;
        }

        if (pend->status == MXFS_DLM_RETRY) {
            /* Membership changed — retry with new master */
            pending_free(pend);
            return MXFS_DLM_RETRY;
        }

        if (pend->status != 0) {
            ret = pend->status;
            pending_free(pend);
            /*
             * sess-tcp (RULE 4 PROVEN): pend->status carries the master's
             * MXFS_ERR_* protocol code (positive enum), NOT a kernel errno.
             * The master denies a NOQUEUE / TRYLOCK lock it cannot grant by
             * sending MXFS_ERR_DEADLOCK (== 1).  Returned verbatim, that +1
             * propagated up through mxfs_v5_dlm_ag_lock_nb (which only maps
             * -EWOULDBLOCK) into xfs_dialloc as err=1 — and since 1 != -EAGAIN
             * the allocator treated a busy peer-held AG as a FATAL error
             * instead of skipping to the next AG, failing the create and
             * NULL-dereferencing in do_open.  The local NOQUEUE path already
             * returns -EAGAIN (see above); make the remote path agree.  Never
             * leak a positive status to the kernel.
             */
            if (ret == MXFS_ERR_DEADLOCK)
                return -EAGAIN;
            /*
             * sess12 (2/tcp double-grant root fix): the master denied a
             * blocked INODE upgrade WITHOUT removing our grant (it stays
             * visible so no peer double-grants).  Map to -EDEADLK so the
             * XFS ilock layer (P109) drops our lower grant through the BAST
             * drain pipeline and re-acquires the target mode fresh.
             */
            if (ret == MXFS_ERR_UPGRADE_CONFLICT)
                return -EDEADLK;
            if (ret > 0)
                return -EIO;
            return ret;
        }

        *granted_mode = pend->granted_mode;
        pending_free(pend);
        return 0;
    }

    /* ─── Local master path ─── */
    bucket = resource_hash(resource, ctx->bucket_count);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
    chain = ctx->buckets[bucket];

    /* Check for existing lock: same resource, same owner */
    for (lk = chain; lk; lk = lk->next) {
        if (resource_equal(&lk->resource, resource) &&
            lk->owner == ctx->local_node) {
            if (lk->state == MXFS_LSTATE_WAITING ||
                lk->state == MXFS_LSTATE_BLOCKED) {
                mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                return -EEXIST;
            }
            if (lk->state == MXFS_LSTATE_GRANTED) {
                if (lk->mode >= mode) {
                    /* Bug 51 defense-in-depth: verify our existing
                     * grant is still safe before returning the "already
                     * granted" shortcut. Normally this is redundant for
                     * local master requests (unlock + lock are
                     * sequential on the same thread), but it prevents
                     * dual-EX grants if a stale entry survives. Check
                     * for conflicting GRANTED holders AND any
                     * WAITING/BLOCKED entries from other nodes. */
                    {
                        struct mxfs_lock *other;
                        int still_safe = 1;

                        for (other = chain; other; other = other->next) {
                            if (other == lk)
                                continue;
                            if (!resource_equal(&other->resource,
                                               resource))
                                continue;
                            if (other->owner == ctx->local_node)
                                continue;
                            if (other->state == MXFS_LSTATE_GRANTED &&
                                !lock_compat[other->mode][lk->mode]) {
                                still_safe = 0;
                                break;
                            }
                            /* sess7(a9a03929) FIX-17 (RULE-4 PROVEN, run90
                             * r10 cluster wedge): other-node WAITING/BLOCKED
                             * entries are NORMAL contention queued behind our
                             * live grant, NOT staleness evidence.  The old
                             * clause here (still_safe=0 on any waiter) made a
                             * same-mode re-request under contention free the
                             * ONLY GRANTED entry (P52-GRANT-FREE ret=
                             * dlm_lock_impl+0x560, test2 gen=16605) and
                             * re-queue itself fairly BEHIND the waiters —
                             * leaving zero granted holders and a promotion
                             * that only ever runs on release events that can
                             * no longer come: the whole cluster queued on
                             * ino=131 for 184.5s, timed out (rc=-110), and
                             * 6/8 nodes force-shutdown.  Only a CONFLICTING
                             * GRANTED entry (the check above) indicates a
                             * genuine dual-grant worth distrusting. */
                        }
                        if (still_safe) {
                            /* DLM_TRACE: local "already granted" shortcut */
                            if (resource->ino == 128 &&
                                resource->type == MXFS_LTYPE_INODE)
                                mxfs_pal_log(MXFS_LOG_DEBUG,
                                    "DLM_TRACE: dlm_lock LOCAL already-granted "
                                    "shortcut ino=128 mode=%s owner=%u",
                                    mode_name(lk->mode), lk->owner);
                            *granted_mode = lk->mode;
                            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                            return 0;
                        }
                    }
                    /* Existing grant conflicts — stale entry.
                     * Remove and re-check as fresh request. */
                    {
                        struct mxfs_lock **pp;

                        mxfs_pal_log(MXFS_LOG_WARN,
                                     "mxfs: lock contention detected, "
                                     "re-queuing request (normal under "
                                     "concurrent access)");
                        pp = &ctx->buckets[bucket];
                        while (*pp) {
                            if (*pp == lk) {
                                *pp = lk->next;
                                lock_free(lk);
                                ctx->lock_count--;
                                break;
                            }
                            pp = &(*pp)->next;
                        }
                    }
                    chain = ctx->buckets[bucket];
                    goto check_compat;
                }
                /* Upgrade: check compat with OTHER holders */
                {
                    struct mxfs_lock *other;
                    int conv_compat = 1;

                    for (other = chain; other; other = other->next) {
                        if (other == lk)
                            continue;
                        if (!resource_equal(&other->resource, resource))
                            continue;
                        if (other->state != MXFS_LSTATE_GRANTED)
                            continue;
                        if (!lock_compat[other->mode][mode]) {
                            conv_compat = 0;
                            break;
                        }
                    }
                    if (conv_compat) {
                        struct mxfs_bast_record pg_rec;
                        int pg = collect_grantee_bast_if_waiters(
                            chain, resource, ctx->local_node, mode,
                            &pg_rec);
                        lk->mode = mode;
                        /*
                         * sess5 (ccloop a16ec5f2) EPOCH-HOLE FIX (RULE 4 —
                         * PROVEN run38: the MASTER node read master_ep=0 on
                         * 61 placements with valid_ep≈1258 (P2-EPOCHPLACE
                         * unestablished=1) — every one a local PR→EX upgrade
                         * whose mirror kept its PR-era dir_epoch=0 because
                         * THIS path, alone among the four upgrade/grant
                         * sites, never called dg_grant_ex.  With master_ep=0
                         * every epoch-gated dir coherence guard is inert for
                         * the master's own tenures → stale-base RMW → the
                         * residual dir_reuse single-dirent loss (run34 r9,
                         * run37 r18).  Mirror the remote-upgrade twin: fresh
                         * gen + dg_grant_ex stamps handoff/dir_epoch and
                         * advances the master handoff epoch.
                         */
                        lk->grant_gen = dlm_next_gen(ctx);
                        if (mode == MXFS_LOCK_EX)
                            lk->handoff = dg_grant_ex(ctx, resource,
                                                      ctx->local_node,
                                                      lk->grant_gen,
                                                      &lk->dir_epoch);
                        *granted_mode = mode;
                        mxfs_dlm_audit_double_grant(chain, resource);
                        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                        if (pg) {
                            pr_warn_ratelimited(
                                "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u newmode=%s site=local-upgrade\n",
                                (unsigned long long)resource->ino,
                                ctx->local_node, mode_name(mode));
                            fire_bast_records(ctx, resource, &pg_rec, 1);
                        }
                        return 0;
                    }
                }
                /*
                 * sess12 (2/tcp double-grant root fix): blocked INODE
                 * upgrade.  The OLD code removed our GRANTED entry and
                 * re-queued as a fresh WAITING request — but we still hold
                 * the lower grant LOCALLY (i_dlm_mode), so removing the table
                 * entry makes us INVISIBLE while still holding: a peer's
                 * subsequent request scans only GRANTED entries, sees no
                 * conflict, and is granted an incompatible mode -> two nodes
                 * hold conflicting grants = the proven P-CONVBLK-REMOVE
                 * double-grant -> stale-read / dir lost-update.
                 *
                 * Correct: KEEP our GRANTED entry (stay visible as a conflict)
                 * and return -EDEADLK.  The XFS ilock layer (P109) then drops
                 * our lower grant THROUGH the BAST drain pipeline (releasing
                 * it in sync with the table) and re-acquires the target mode
                 * FRESH via the clean FIFO path — no double-grant, no
                 * conversion deadlock.  Scoped to INODE resources (where the
                 * P109 -EDEADLK handling lives); other resource types keep the
                 * legacy remove+requeue behavior.
                 */
                if (resource->type == MXFS_LTYPE_INODE) {
                    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                    return -EDEADLK;
                }
                /* Conversion blocked — release existing, fall through */
                {
                    struct mxfs_lock **pp;

                    pp = &ctx->buckets[bucket];
                    while (*pp) {
                        if (*pp == lk) {
                            *pp = lk->next;
                            lock_free(lk);
                            ctx->lock_count--;
                            break;
                        }
                        pp = &(*pp)->next;
                    }
                }
                chain = ctx->buckets[bucket];
                goto check_compat;
            }
        }
    }

check_compat:
    /* Check compatibility with all granted holders */
    compat = 1;
    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED)
            continue;
        if (!lock_compat[lk->mode][mode]) {
            compat = 0;
            /* P1-AGCONFLICT (local-master mirror of the remote-path log):
             * name the GRANTED holder blocking an AG request. */
            if (resource->type == MXFS_LTYPE_AG)
                pr_warn_ratelimited(
                    "mxfs: P1-AGCONFLICT ag=%u sender=LOCAL req=%s holder=%u hmode=%s hstate=%d nq=%d\n",
                    resource->ag_number, mode_name(mode),
                    lk->owner, mode_name(lk->mode), lk->state,
                    !!(flags & MXFS_LKF_NOQUEUE));
            break;
        }
    }

    /* sess6(a16ec5f2) arrival-time FIFO barrier: do not grant past an
     * older conflicting waiter (see find_conflicting_waiter). */
    if (compat) {
        struct mxfs_lock *cw = find_conflicting_waiter(chain, resource,
                                                       ctx->local_node, mode);
        if (cw) {
            static atomic_t p6f_n = ATOMIC_INIT(0);
            compat = 0;
            if (atomic_inc_return(&p6f_n) <= 60000)
                pr_warn("mxfs: P6-FAIRQ site=local ino=%llu type=%u ag=%u req=%s we=%u behind waiter=%u wmode=%s wage_ms=%llu nq=%d\n",
                        (unsigned long long)resource->ino,
                        resource->type, resource->ag_number,
                        mode_name(mode), ctx->local_node,
                        cw->owner, mode_name(cw->mode),
                        (unsigned long long)(cw->queued_at ?
                            mxfs_pal_time_ms() - cw->queued_at : 0),
                        !!(flags & MXFS_LKF_NOQUEUE));
        }
    }

    if (!compat && (flags & MXFS_LKF_NOQUEUE)) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -EAGAIN;
    }

    if (!compat && (flags & MXFS_LKF_TRYLOCK)) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -EWOULDBLOCK;
    }

    if (compat) {
        /* Grant immediately */
        struct mxfs_lock *newlk;
        struct mxfs_bast_record pg_rec;
        int pg;

        /* DLM_TRACE: local master new grant (no conflict) */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: dlm_lock LOCAL new-grant ino=128 "
                         "mode=%s owner=%u",
                         mode_name(mode), ctx->local_node);

        newlk = lock_alloc(resource, ctx->local_node, mode,
                           MXFS_LSTATE_GRANTED, flags);
        if (!newlk) {
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            return -ENOMEM;
        }

        /* sess1(ccloop a9a03929) RULE-4 PROVEN (run44 wedge): this was the
         * ONE grant path that never stamped grant_gen — every uncontended
         * locally-mastered tenure carried gen=0, so (a) the gen-aware
         * release capture read 0 ("nothing held") and skipped the master's
         * own releases -> cluster wedge, and (b) the owner-scan peer-held-
         * in-between detector (cur_gg != cached_gg) was INERT on the master
         * (0 == 0 forever).  Stamp like every other grant site (793, 1368,
         * 3304, 3356, 3529): every tenure gets a unique non-zero gen. */
        newlk->grant_gen = dlm_next_gen(ctx);

        newlk->next = ctx->buckets[bucket];
        ctx->buckets[bucket] = newlk;
        ctx->lock_count++;
        mxfs_dlm_audit_double_grant(ctx->buckets[bucket], resource);
        P_LKT("GRANT-LOCAL", resource, ctx->local_node, mode);
        if (mode == MXFS_LOCK_EX)
            newlk->handoff = dg_grant_ex(ctx, resource, ctx->local_node,
                                         newlk->grant_gen, &newlk->dir_epoch);

        /* sess35 ROOT FIX: this immediate grant is compatible with all
         * GRANTED holders but may JUMP an older conflicting WAITING entry
         * (a holder released its lower grant then re-requested EX from NL,
         * racing ahead of the waiter's promotion).  Fire a BAST to ourselves
         * so we release for the stranded waiter instead of it stalling the
         * full 6000ms ACQUIRE_WAIT_MS until its retry re-fires the BAST. */
        pg = collect_grantee_bast_if_waiters(ctx->buckets[bucket], resource,
                                             ctx->local_node, mode, &pg_rec);
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        if (pg) {
            pr_warn_ratelimited(
                "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u newmode=%s site=local-immediate\n",
                (unsigned long long)resource->ino,
                ctx->local_node, mode_name(mode));
            fire_bast_records(ctx, resource, &pg_rec, 1);
        }
        *granted_mode = mode;
        return 0;
    }

    /* Incompatible — queue and wait */
    {
        struct mxfs_lock *newlk;
        struct mxfs_dlm_pending *pend;
        struct mxfs_bast_record bast_recs[MXFS_MAX_BAST_RECORDS];
        int bast_count = 0;
        int ret;

        /* DLM_TRACE: local master queuing as waiter */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: dlm_lock LOCAL add-to-waiters ino=128 "
                         "requested_mode=%s owner=%u",
                         mode_name(mode), ctx->local_node);

        /* sess4(a16ec5f2): allocate the pending FIRST so the queued entry
         * can carry its waiter identity (pend_waiter) from the instant it
         * becomes visible in the table — the unlock fallback keys off it. */
        pend = pending_alloc(resource);
        if (!pend) {
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            return -ENOMEM;
        }

        newlk = lock_alloc(resource, ctx->local_node, mode,
                           MXFS_LSTATE_WAITING, flags);
        if (!newlk) {
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            pending_free(pend);
            return -ENOMEM;
        }

        newlk->pend_waiter = pend;
        newlk->next = ctx->buckets[bucket];
        ctx->buckets[bucket] = newlk;
        ctx->lock_count++;

        /* Capture BAST targets into a snapshot array while under
         * table_rwlock.  We must NOT iterate live lock entries via
         * work_next after releasing the lock — concurrent releases
         * can corrupt the work_next chain at 3+ nodes. */
        for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
            if (!resource_equal(&lk->resource, resource))
                continue;
            if (lk->state != MXFS_LSTATE_GRANTED)
                continue;
            if (!lock_compat[lk->mode][mode]) {
                if (bast_count < MXFS_MAX_BAST_RECORDS) {
                    bast_recs[bast_count].owner = lk->owner;
                    bast_recs[bast_count].requested_mode = mode;
                    bast_count++;
                }
            }
        }

        mxfs_pal_rwlock_unlock(ctx->table_rwlock);

        /* Set up pending entry BEFORE firing BASTs.
         *
         * Critical ordering: the pending entry must be in the hash
         * table before any BAST is sent. Otherwise, a fast BAST
         * recipient can release its lock and trigger promote_waiters
         * + pending_signal_resource before we insert the pending
         * entry — the signal is lost and we wait forever (timeout).
         *
         * At 4+ nodes with 3 PR holders, all 3 can process BASTs
         * and release concurrently. If the last release promotes
         * our WAITING entry and signals the pending before it's
         * inserted, the grant is lost. */
        /* sess4(a16ec5f2): pend was allocated (and linked via
         * newlk->pend_waiter) BEFORE the entry became visible in the
         * table; only the hash insert remains here. */
        pending_insert(ctx, pend);

        /* sess35 P37: local request queued WAITING for the contended dir. */
        if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
            pr_warn_ratelimited(
                "mxfs: P37-LREQ-QUEUE ino=131 owner=%u mode=%s bast_targets=%d\n",
                ctx->local_node, mode_name(mode), bast_count);

        /* Fire deferred BASTs from snapshot — pending entry is
         * already in the hash table, so promote_waiters can signal
         * us even if all holders release before we reach pending_wait */
        fire_bast_records(ctx, resource, bast_recs, bast_count);

        /* sess-tcp: shorter per-attempt wait; mxfs_dlm_lock retries on
         * -ETIMEDOUT (re-fires the BAST) to recover a lost grant/release. */
        ret = pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS);

        pending_remove(ctx, pend);

        if (pend->status == MXFS_DLM_RETRY) {
            /* Membership changed — the WAITING lock entry was already
             * freed by update_active_nodes' table purge. Do NOT try
             * to find/free newlk (use-after-free). Just retry. */
            pending_free(pend);
            return MXFS_DLM_RETRY;
        }

        if (ret == -ETIMEDOUT) {
            /* Timeout — remove the queued lock */
            mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
            {
                struct mxfs_lock **pp = &ctx->buckets[bucket];
                struct mxfs_lock *wlk;

                /* sess3 (ccloop a16ec5f2): name the blockers.  A 60s
                 * acquire timeout (the run16 test6 AG2 -110 -> dirty
                 * trans_cancel shutdown) BASTed the granted holder(s)
                 * ~60 times in vain; without their identity the ABBA
                 * (holder stuck waiting for a resource OUR caller
                 * holds) cannot be attributed.  Dump every entry on
                 * this resource with owner/mode/state/age. */
                for (wlk = ctx->buckets[bucket]; wlk; wlk = wlk->next) {
                    if (!resource_equal(&wlk->resource, resource) ||
                        wlk == newlk)
                        continue;
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: P-LKTIMEOUT-HOLDER type=%u ino=%llu ag=%u holder=%u hmode=%s hstate=%u held_ms=%llu queued_ms=%llu (we=%u req=%s)",
                        resource->type,
                        (unsigned long long)resource->ino,
                        resource->ag_number, wlk->owner,
                        mode_name(wlk->mode), wlk->state,
                        (unsigned long long)(wlk->granted_at ?
                            mxfs_pal_time_ms() - wlk->granted_at : 0),
                        (unsigned long long)(wlk->queued_at ?
                            mxfs_pal_time_ms() - wlk->queued_at : 0),
                        ctx->local_node, mode_name(mode));
                }
                while (*pp) {
                    if (*pp == newlk) {
                        /* sess4(a16ec5f2) INVARIANT GUARD (RULE 4, proven in
                         * run19): this free may ONLY drop OUR OWN still-
                         * waiting request.  run19 caught this exact site
                         * (P52-GRANT-FREE ret=dlm_lock_impl+0x10cd) freeing
                         * a REMOTE holder's GRANTED entry (owner=test5 gen
                         * 8210) through the newlk pointer -> live holder
                         * vanished from the table -> immediate re-grant ->
                         * CONCURRENT EX -> stale-base RMW -> durable dirent
                         * loss (round-6 node1_f34.md5).  If the entry at
                         * *pp is not ours-and-waiting, the pointer is
                         * stale/aliased: log and DO NOT free live state. */
                        if (newlk->owner != ctx->local_node ||
                            (newlk->state != MXFS_LSTATE_WAITING &&
                             newlk->state != MXFS_LSTATE_BLOCKED) ||
                            newlk->pend_waiter != pend) {
                            mxfs_pal_log(MXFS_LOG_WARN,
                                "mxfs: P4G-TIMEOUT-FREE-ALIAS ino=%llu type=%u ptr=%px owner=%u mode=%u state=%u gen=%u pw_match=%d (we=%u) — NOT freeing non-local/non-waiting entry",
                                (unsigned long long)resource->ino,
                                resource->type, newlk,
                                (unsigned)newlk->owner,
                                (unsigned)newlk->mode,
                                (unsigned)newlk->state,
                                newlk->grant_gen,
                                newlk->pend_waiter == pend ? 1 : 0,
                                ctx->local_node);
                            break;
                        }
                        newlk->pend_waiter = NULL;
                        *pp = newlk->next;
                        ctx->lock_count--;
                        lock_free(newlk);
                        break;
                    }
                    pp = &(*pp)->next;
                }
            }
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            pending_free(pend);
            return -ETIMEDOUT;
        }

        /* Granted via promote_waiters path */
        pending_free(pend);
        *granted_mode = mode;
        return 0;
    }
}

/* ─── mxfs_dlm_lock — Local lock acquisition ─── */

int mxfs_dlm_lock(struct mxfs_dlm_ctx *ctx,
                  const struct mxfs_resource_id *resource,
                  uint8_t mode, uint32_t flags,
                  uint8_t *granted_mode)
{
    /* sess36 (ccloop): raised 10 -> 60 to keep the TOTAL acquire budget
     * (retries * MXFS_LOCK_ACQUIRE_WAIT_MS) at ~60s after lowering the
     * per-attempt wait to 1000ms — still covers a release-fence drain while
     * recovering a stranded dir-EX waiter in ~1s instead of ~6s. */
    return mxfs_dlm_lock_retries(ctx, resource, mode, flags, granted_mode, 60);
}

/*
 * sess58 (ccloop 8ddb16a2): retry-budget variant.  The xfs-layer inode-DLM
 * acquire slow path (mxfs_dlm_ilock_begin) drives this with a SMALL budget so
 * it returns to the caller every ~retries seconds — long enough for one
 * grant-wait window, short enough that the caller can re-run its cooperative
 * cached-AG yield (mxfs_dlm_yield_basted_cached_ags) DURING the ~60s acquire
 * rather than only once before it.  Without that, a node blocked here on a dir
 * inode EX never releases a cached AG a peer is BAST'ing -> the proven
 * inode<->AG ABBA deadlock -> -ETIMEDOUT -> dirty trans_cancel -> shutdown
 * (the tcp_dlm_scaling within-window/drain failure).
 */
int mxfs_dlm_lock_retries(struct mxfs_dlm_ctx *ctx,
                  const struct mxfs_resource_id *resource,
                  uint8_t mode, uint32_t flags,
                  uint8_t *granted_mode, int max_retries)
{
    int ret;
    int retries = max_retries > 0 ? max_retries : 1;
    int retries0 = retries;

    if (!ctx || !resource || mode >= MXFS_LOCK_MODE_COUNT)
        return -EINVAL;

    /* DLM_TRACE: log entry for inode 128 debugging */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: dlm_lock ENTRY ino=128 "
                     "requested_mode=%s flags=0x%x local_node=%u",
                     mode_name(mode), flags, ctx->local_node);

    /* Retry loop: membership changes during a lock request cause
     * MXFS_DLM_RETRY (the request was sent to a now-dead master, or
     * the WAITING entry was purged from the table). Retry with the
     * updated master assignment — the surviving node is now master
     * for all (or most) resources and the retry typically succeeds
     * immediately on an empty lock table.
     *
     * Bounded to 10 retries to handle multiple rapid membership
     * changes (e.g. several nodes joining/leaving in quick succession).
     * Bug 67: increased from 3 to 10 to prevent lock starvation
     * under repeated epoch changes. */
    do {
        ret = dlm_lock_impl(ctx, resource, mode, flags, granted_mode);
        /*
         * FIX-23 attempt REVERTED (sess8 a9a03929, run107 11/17 vs run106
         * 15/17): sending the gen-0 unconditional release on EVERY
         * -ETIMEDOUT kills a LIVE grant in the re-affirm case — the FS
         * layer holds cached EX (i_dlm_mode=EX) while a re-request times
         * out; the release removed our own GRANTED master entry, the
         * master granted a peer, and mutual exclusion broke (run107:
         * dlm_scaling node3 P26-IGET-FAIL .dlm_scaling err=-2, fence 7/8,
         * fault 5/8).  The no-mirror discard case is already covered by
         * the receiver-side GRANT-REJECT-UNSOLICITED below; do NOT add a
         * blind release here.
         */
        if (ret != MXFS_DLM_RETRY) {
            /* Bug 85: also retry on transport errors.  When a peer
             * disconnects, fail_all_pending() wakes waiters with
             * MXFS_DLM_RETRY.  But the retry may try to send to the
             * same dead master (active node list not yet updated),
             * getting -ENOTCONN.  Retry with a short sleep to give
             * update_active_nodes() time to remap the master. */
            if ((ret == -ENOTCONN || ret == -EPIPE ||
                 ret == -ECONNRESET) && retries > 1) {
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "dlm: lock retry after transport error %d "
                             "(mode=%s, retries_left=%d)",
                             ret, mode_name(mode), retries - 1);
                mxfs_pal_sleep_ms(500);
            } else if (ret == -ETIMEDOUT && retries > 1) {
                /*
                 * sess-tcp (PROVEN root): a contended dir-EX handoff whose
                 * grant/release notification was dropped/delayed leaves this
                 * waiter timed out after MXFS_LOCK_ACQUIRE_WAIT_MS even though
                 * the holder has released.  Retry: dlm_lock_impl re-checks
                 * compatibility (now free -> immediate grant) and re-fires the
                 * BAST if still held.  This recovers the lost-message stall in
                 * seconds instead of the old 60s MXFS_LOCK_WAIT_TIMEOUT_MS.
                 * Bounded by `retries`; a genuinely-unavailable lock still
                 * eventually returns -ETIMEDOUT on the last attempt.
                 */
                pr_warn_ratelimited(
                             "mxfs: P36-RETRY ino=%llu type=%u ag=%u mode=%s retries_left=%d comm=%s (acquire timeout)\n",
                             (unsigned long long)resource->ino,
                             resource->type,
                             resource->ag_number,
                             mode_name(mode), retries - 1,
                             dlm_cur_comm());
                /* sess12(a9a03929) ABBA forensics: on the FIRST timeout of an
                 * episode, dump this waiter's call chain (capped 8/boot).  The
                 * fence 60s AG-0<->dir-EX cycle needs the wait SITE (which
                 * path acquired AG before dir, or vice versa) — comm alone
                 * cannot name the inverted edge. */
                {
                    static atomic_t p36_stack_cap = ATOMIC_INIT(0);
                    if (retries == retries0 &&
                        atomic_inc_return(&p36_stack_cap) <= 8) {
                        pr_warn("mxfs: P36-STACK ino=%llu type=%u ag=%u mode=%s comm=%s (first timeout, dumping wait site)\n",
                                (unsigned long long)resource->ino,
                                resource->type, resource->ag_number,
                                mode_name(mode), dlm_cur_comm());
                        mxfs_pal_dump_stack();
                    }
                }
            } else {
                return ret;
            }
        } else {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "dlm: lock retry after membership change "
                         "(mode=%s, retries_left=%d)",
                         mode_name(mode), retries - 1);
        }
    } while (--retries > 0);

    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: lock request failed after %d retries during "
                 "cluster membership changes — file operation will "
                 "return an error",
                 10);
    return -EAGAIN;
}

/* ─── mxfs_dlm_unlock — Release lock held by local node ─── */

/* sess1(ccloop a9a03929) GEN-AWARE RELEASE: the BAST-driven release pipeline
 * (drain -> NL -> durability barrier -> unlock) is ASYNC and long (ms-to-s for
 * dirs).  A local re-acquire can complete a FULL DLM acquire inside that
 * window (i_dlm_mode already NL), inserting a FRESH GRANTED mirror carrying
 * the new grant_gen + dir_epoch.  The old gen-blind unlock then unlinked the
 * FIRST matching GRANTED entry — the fresh grant at the LIFO chain head — and
 * echoed ITS gen (rel_gen below) in LOCK_RELEASE, which the master ACCEPTS
 * (gen matches current!) -> master hands the resource to a peer while our FS
 * layer believes it holds EX with an emptied local mirror: concurrent EX that
 * P-DOUBLEGRANT cannot see + mxfs_v5_dlm_inode_dir_epoch()==0 (the run42-t4
 * P5H insert dir_epoch=647 -> 4ms -> P2-EPOCHPLACE master_ep=0 signature) ->
 * every epoch coherence guard inert -> stale-base RMW -> durable dirent loss.
 * expected_gen != 0 makes the unlock release ONLY the tenure it was queued
 * for: if the intended entry is gone and a NEWER-gen entry owns the resource,
 * refuse with -ESTALE (caller re-arms the BAST; the new tenure's own release
 * cycle serves the peer). */
int mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx,
                        const struct mxfs_resource_id *resource,
                        uint32_t expected_gen)
{
    uint32_t bucket;
    struct mxfs_lock **pp;
    struct mxfs_lock *found = NULL;
    struct mxfs_lock *grants;
    struct mxfs_bast_record post_bast_recs[MXFS_MAX_BAST_RECORDS];
    int post_bast_count = 0;
    mxfs_node_id_t master;
    uint32_t rel_gen = 0;   /* sess-tcp: gen to echo in LOCK_RELEASE */
    uint32_t other_gen = 0; /* gen of a same-owner GRANTED entry we skipped */
    bool ag_orphan_nak = false; /* ccloop c7ee71c6 sess6: AG unlock-ENOENT heal */

    if (!ctx || !resource)
        return -EINVAL;

    bucket = resource_hash(resource, ctx->bucket_count);

    /* Get master before acquiring table_rwlock to avoid lock ordering
     * deadlock (active_nodes.lock -> table_rwlock in update_active_nodes) */
    master = mxfs_dlm_resource_master(ctx, resource);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    /* Find and unlink (prefer GRANTED/CONVERTING) */
    pp = &ctx->buckets[bucket];
    while (*pp) {
        struct mxfs_lock *lk = *pp;

        if (resource_equal(&lk->resource, resource) &&
            lk->owner == ctx->local_node &&
            (lk->state == MXFS_LSTATE_GRANTED ||
             lk->state == MXFS_LSTATE_CONVERTING)) {
            if (expected_gen && lk->grant_gen != expected_gen) {
                /* Not the tenure this release belongs to — skip it. */
                other_gen = lk->grant_gen;
                pp = &lk->next;
                continue;
            }
            *pp = lk->next;
            found = lk;
            ctx->lock_count--;
            break;
        }
        pp = &lk->next;
    }

    /* Gen-aware refusal: the tenure we meant to release is gone and a
     * DIFFERENT tenure (normally newer — a re-acquire that completed during
     * our release window) owns the resource now.  Do NOT touch it, do NOT
     * dg_release, do NOT send LOCK_RELEASE. */
    if (!found && expected_gen && other_gen) {
        if (resource->type == MXFS_LTYPE_INODE) {
            static atomic_t p6g_n = ATOMIC_INIT(0);
            if ((unsigned)atomic_inc_return(&p6g_n) <= 20000)
                pr_warn("mxfs: P6G-STALE-RELEASE-SKIP ino=%llu rel_gen=%u cur_gen=%u comm=%s — release outlived its tenure; refused\n",
                        (unsigned long long)resource->ino,
                        expected_gen, other_gen, dlm_cur_comm());
        }
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -ESTALE;
    }

    /* Also try waiting/blocked if no granted lock found.
     *
     * sess4(a16ec5f2) ROOT FIX (RULE 4, proven runs 19+20 by P4L pointer
     * lifecycle trace): this fallback used to reap ANY same-owner entry —
     * including a CONCURRENT local thread's live in-flight request queued
     * milliseconds earlier (bucket chains are LIFO, so the newest request
     * matches first).  The requester's newlk pointer then dangled; kmalloc
     * recycled the memory for a peer's entry; the requester's inevitable
     * 1000ms timeout freed the recycled LIVE entry (run19: the peer's
     * GRANTED EX gen 8210) -> holder vanished from the master table ->
     * immediate re-grant -> CONCURRENT EX -> stale-base dir RMW -> durable
     * dirent loss (round-6 node1_f34.md5).  Skip any entry with a live
     * waiter attached (pend_waiter) — only truly abandoned WAITING/BLOCKED
     * leftovers may be reaped here. */
    if (!found) {
        pp = &ctx->buckets[bucket];
        while (*pp) {
            struct mxfs_lock *lk = *pp;

            if (resource_equal(&lk->resource, resource) &&
                lk->owner == ctx->local_node) {
                if (lk->pend_waiter) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: P4U-SKIP-INFLIGHT ino=%llu type=%u ptr=%px mode=%u state=%u — unlock fallback skipping live in-flight request",
                        (unsigned long long)resource->ino,
                        resource->type, lk,
                        (unsigned)lk->mode, (unsigned)lk->state);
                    pp = &lk->next;
                    continue;
                }
                *pp = lk->next;
                found = lk;
                ctx->lock_count--;
                break;
            }
            pp = &lk->next;
        }
    }

    if (!found) {
        /* DLM_TRACE: unlock found no entry for inode 128 */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: dlm_unlock ENOENT ino=128 "
                         "local_node=%u", ctx->local_node);
        /* sess5(a16ec5f2): AG unlock that found nothing to release —
         * the local table thinks we hold nothing while the master may
         * still carry our GRANTED entry (run31 AG-0 wedge shape).
         * ccloop c7ee71c6 sess6: no longer just logged — heal it.  The
         * shape went live (test6 AG-9: membership-change purge ate the
         * local GRANTED record; this ENOENT then sent nothing and the
         * master's zombie starved the cluster for 500+ s).  Set the flag;
         * the guarded orphan NAK is sent after table_rwlock drops. */
        if (resource->type == MXFS_LTYPE_AG) {
            pr_warn_ratelimited(
                "mxfs: P5U-AGUNLOCK-ENOENT ag=%u master=%u local=%u\n",
                resource->ag_number, master, ctx->local_node);
            ag_orphan_nak = true;
        }
        /* sess1(a9a03929): count storm-dir unlocks that found nothing —
         * the residue an eaten mirror leaves behind (the FS layer believed
         * it held; the local table disagrees). */
        if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131) {
            static atomic_t p6e_n = ATOMIC_INIT(0);
            if ((unsigned)atomic_inc_return(&p6e_n) <= 20000)
                pr_warn("mxfs: P6E-UNLOCK-ENOENT ino=131 expected_gen=%u comm=%s\n",
                        expected_gen, dlm_cur_comm());
        }
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        /* ccloop c7ee71c6 sess6: guarded orphan NAK — outside the rwlock
         * (the helper re-scans under rdlock; the send can sleep).  The
         * caller is the release path, so the FS layer no longer believes
         * it holds this grant; if a concurrent local acquire raced in,
         * the helper's any-state scan sees its entry and refuses. */
        if (ag_orphan_nak) {
            int nak_rc = mxfs_dlm_release_orphan_if_unheld(ctx, resource);

            pr_warn_ratelimited(
                "mxfs: P5N-AG-ORPHAN-NAK ag=%u master=%u src=unlock-enoent rc=%d\n",
                resource->ag_number, master, nak_rc);
        }
        return -ENOENT;
    }

    /* DLM_TRACE: log which entry is being removed */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: dlm_unlock REMOVING ino=128 "
                     "owner=%u mode=%s state=%s local_node=%u "
                     "master=%u",
                     found->owner, mode_name(found->mode),
                     state_name(found->state), ctx->local_node,
                     master);

    P_LKT(found->state == MXFS_LSTATE_GRANTED ?
              "UNLOCK-GRANTED" : "UNLOCK-OTHER",
          resource, found->owner, found->mode);

    /* sess6(a16ec5f2) mirror-lifecycle tracer: every local-mirror removal
     * for the storm dir, so a dangerous-unest P2-EPOCHPLACE (master_ep=0
     * with valid_ep>0) can be joined to the removal that emptied the local
     * table (or to its absence — insert-side loss).  Capped, ino 131. */
    if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE) {
        static atomic_t p6u_n = ATOMIC_INIT(0);
        if ((unsigned)atomic_inc_return(&p6u_n) <= 60000)
            pr_warn("mxfs: P6U-UNLOCK ino=131 mode=%s state=%u gen=%u dir_epoch=%u comm=%s\n",
                    mode_name(found->mode), (unsigned)found->state,
                    found->grant_gen, found->dir_epoch, dlm_cur_comm());
    }

    rel_gen = found->grant_gen;     /* echo our held gen in the release */

    dg_release(resource, ctx->local_node);  /* sess8: genuine local release */
    lock_free(found);

    /* Promote waiters */
    grants = promote_waiters(ctx, ctx->buckets[bucket], resource);

    /* sess35 P37: local-release promote outcome for the contended dir. */
    if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE) {
        int p37n = 0; struct mxfs_lock *p37w;
        for (p37w = grants; p37w; p37w = p37w->work_next) p37n++;
        pr_warn_ratelimited("mxfs: P37-LREL ino=131 releaser=%u master=%u promoted=%d\n",
                            ctx->local_node, master, p37n);
    }

    /* DLM_TRACE: log promote_waiters result */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE) {
        if (grants) {
            struct mxfs_lock *wk;
            int gc = 0;
            for (wk = grants; wk; wk = wk->work_next)
                gc++;
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: dlm_unlock promote_waiters "
                         "ino=128 promoted=%d", gc);
        } else {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: dlm_unlock promote_waiters "
                         "ino=128 promoted=0 (no waiters)");
        }
    }

    /* Dispatch grants under lock -- pending_signal_resource and send_grant
     * don't need table_rwlock, so this is safe and avoids work_next
     * collision with the post-promotion BAST list built next. */
    if (grants && master == ctx->local_node) {
        struct mxfs_lock *wk;
        for (wk = grants; wk; wk = wk->work_next) {
            if (wk->mode == MXFS_LOCK_EX)
                wk->handoff = dg_grant_ex(ctx, &wk->resource, wk->owner,
                                          wk->grant_gen, &wk->dir_epoch);
            if (wk->owner == ctx->local_node)
                pending_signal_resource(ctx, &wk->resource,
                                        wk->mode, 0, 0);
            else
                send_grant(ctx, wk->owner, &wk->resource,
                           wk->mode, MXFS_OK, MXFS_MSG_LOCK_GRANT,
                           wk->request_epoch, wk->grant_gen, wk->handoff,
                           wk->dir_epoch);
        }
    }

    /* Post-promotion BASTs: if promotion left remaining BLOCKED waiters,
     * the newly-granted holders need BASTs so they release when done.
     * Capture into snapshot array to avoid work_next corruption.
     *
     * sess36 (ccloop): fire these whenever we are the master, NOT only when
     * promote_waiters granted something.  A waiter left BLOCKED behind a
     * holder that re-acquired ahead of it yields promoted=0, and the old
     * `if (grants)` guard then skipped the BAST so the waiter stranded the
     * full 6000ms ACQUIRE_WAIT (same bug as process_remote_release).
     * collect_post_promotion_basts is a no-op without a BLOCKED waiter. */
    if (master == ctx->local_node) {
        struct mxfs_lock *post_basts;
        uint8_t blocked_mode = MXFS_LOCK_NL;

        post_basts = collect_post_promotion_basts(
            ctx->buckets[bucket], resource, &blocked_mode);

        {
            struct mxfs_lock *wk;
            for (wk = post_basts; wk; wk = wk->work_next) {
                if (post_bast_count < MXFS_MAX_BAST_RECORDS) {
                    post_bast_recs[post_bast_count].owner = wk->owner;
                    post_bast_recs[post_bast_count].requested_mode = blocked_mode;
                    post_bast_count++;
                }
            }
        }
    }

    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    /* Handle remote unlock: send LOCK_RELEASE to remote master
     * (retry up to 3 times on transient failure) */
    if (master != ctx->local_node && ctx->send_cb) {
        struct mxfs_dlm_lock_release rel;
        int send_ret;
        int send_retries = 3;

        memset(&rel, 0, sizeof(rel));
        rel.hdr.magic = MXFS_DLM_MAGIC;
        rel.hdr.version = MXFS_DLM_VERSION;
        rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
        rel.hdr.length = sizeof(rel);
        rel.hdr.sender = ctx->local_node;
        rel.hdr.target = master;
        rel.hdr.epoch = ctx->current_epoch;
        rel.resource = *resource;
        rel.grant_gen = rel_gen;
        do {
            send_ret = ctx->send_cb(ctx, master, &rel, sizeof(rel));
            if (send_ret == 0)
                break;
            if (--send_retries > 0) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: lock release to node %u failed, "
                             "retrying (%d attempts remaining)",
                             master, send_retries);
                mxfs_pal_sleep_ms(100);
            }
        } while (send_retries > 0);
    }

    /* Fire post-promotion BASTs from snapshot */
    fire_bast_records(ctx, resource, post_bast_recs, post_bast_count);

    /* sess5(a16ec5f2): AG unlock visibility — pairs with P5R-AGREL at the
     * master; a P5U with no matching P5R names a lost release message. */
    if (resource->type == MXFS_LTYPE_AG)
        pr_warn_ratelimited(
            "mxfs: P5U-AGUNLOCK ag=%u master=%u local=%u relgen=%u\n",
            resource->ag_number, master, ctx->local_node, rel_gen);

    return 0;
}

/* Legacy unconditional unlock — releases whatever tenure the local node
 * currently holds (expected_gen=0 disables the tenure check). */
int mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx,
                    const struct mxfs_resource_id *resource)
{
    return mxfs_dlm_unlock_gen(ctx, resource, 0);
}

/*
 * sess7(a9a03929) FIX-20b (RULE-4 PROVEN, run91/94): send an UNCONDITIONAL
 * (gen=0) LOCK_RELEASE for `resource` to its remote master, bypassing the
 * local mirror entirely.  For a PHANTOM grant — master's table holds our
 * GRANTED entry while the local mirror has no record (the requester's
 * ACQUIRE_WAIT retry raced the late grant and discarded it, or the mirror
 * was eaten) — the normal unlock is a local -ENOENT no-op and the master
 * keeps the entry forever: every peer queues behind it for 184s and shuts
 * down (run91 held_ms=499427s-shape; run94 ino=16781703).
 * process_remote_release treats gen==0 as unconditional for the sender's
 * entry and promotes the queue; if the master has nothing it logs
 * RREL-ENOENT and no-ops.  Callers MUST have established that no live local
 * tenure exists (mirror empty + no in-flight local acquire) — the caller in
 * mxfs_dlm_bast_process gates on the serialized DEMOTING state plus a fresh
 * grant_gen==0 re-check.  NOT called on the common eviction/ENOENT unlock
 * paths (the first FIX-20 cut did that and the bulk wire flood regressed
 * dlm_fairness — one targeted message per detected phantom only).
 */
int mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource)
{
    struct mxfs_dlm_lock_release rel;
    mxfs_node_id_t master;

    if (!ctx || !resource || !ctx->send_cb)
        return -EINVAL;
    master = mxfs_dlm_resource_master(ctx, resource);
    if (master == ctx->local_node)
        return 0;   /* local master: the local table IS authoritative */

    memset(&rel, 0, sizeof(rel));
    rel.hdr.magic = MXFS_DLM_MAGIC;
    rel.hdr.version = MXFS_DLM_VERSION;
    rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
    rel.hdr.length = sizeof(rel);
    rel.hdr.sender = ctx->local_node;
    rel.hdr.target = master;
    rel.hdr.epoch = ctx->current_epoch;
    rel.resource = *resource;
    rel.grant_gen = 0;
    return ctx->send_cb(ctx, master, &rel, sizeof(rel));
}

/*
 * ccloop c7ee71c6 sess6 — ORPHAN-GRANT NAK (zombie AG grant, captured live).
 *
 * mxfs_dlm_update_active_nodes purges the ENTIRE local lock table on every
 * membership change, and nodes process membership events at different
 * times.  During the 1->N mount ramp a node can acquire a grant whose
 * master's table then SURVIVES (the master's view had already settled)
 * while the holder's own record is purged moments later by its next
 * membership event.  The holder's eventual release then hits local -ENOENT
 * and — before this fix — sent NOTHING: the master carried the zombie
 * GRANTED entry forever, every requester queued behind it retrying 1/s,
 * and the whole cluster starved on that AG (test6 AG-9 17:28:15
 * P5U-AGUNLOCK-ENOENT -> test2 master holder=test6 hstate=2 re-BASTing
 * 1/s for 500+ s -> test1 rm-rf stuck in mxfs_trans_preacquire_inode_ags
 * holding the dir ILOCK -> every dir_reuse run DNF).
 *
 * Heal: when we can PROVE we hold nothing locally — no entry of ANY state
 * (granted / converting / waiting / in-flight pend_waiter) for the
 * resource in the local table — send the FIX-20b unconditional (gen=0)
 * LOCK_RELEASE to the resource's current master.  If the master has a
 * zombie entry for us it is cleared and the queue promotes; if it has
 * nothing it logs RREL-ENOENT and no-ops.  The any-state scan is the
 * safety gate: a live in-flight acquire (WAITING + pend_waiter) blocks
 * the NAK, so a late grant can never be released out from under a local
 * waiter.  Callers must additionally ensure the FS layer does not believe
 * it holds the grant (pag cached=0 / release path already committed).
 */
int mxfs_dlm_release_orphan_if_unheld(struct mxfs_dlm_ctx *ctx,
                                      const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    bool held = false;

    if (!ctx || !resource)
        return -EINVAL;

    bucket = resource_hash(resource, ctx->bucket_count);
    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (resource_equal(&lk->resource, resource) &&
            lk->owner == ctx->local_node) {
            held = true;
            break;
        }
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    if (held)
        return -EBUSY;
    return mxfs_dlm_send_unconditional_release(ctx, resource);
}

/* ─── mxfs_dlm_lock_convert — Mode upgrade/downgrade ─── */

int mxfs_dlm_lock_convert(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          mxfs_node_id_t owner, uint8_t new_mode)
{
    uint32_t bucket;
    struct mxfs_lock *target_lk = NULL;
    struct mxfs_lock *chain, *lk;
    uint8_t old_mode;

    if (!ctx || !resource || new_mode >= MXFS_LOCK_MODE_COUNT)
        return -EINVAL;

    bucket = resource_hash(resource, ctx->bucket_count);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
    chain = ctx->buckets[bucket];

    for (lk = chain; lk; lk = lk->next) {
        if (resource_equal(&lk->resource, resource) &&
            lk->owner == owner &&
            lk->state == MXFS_LSTATE_GRANTED) {
            target_lk = lk;
            break;
        }
    }

    if (!target_lk) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -ENOENT;
    }

    old_mode = target_lk->mode;

    /* Downgrade is always allowed */
    if (new_mode <= old_mode) {
        struct mxfs_lock *cv_grants;

        target_lk->mode = new_mode;
        target_lk->granted_at = mxfs_pal_time_ms();

        /* Downgrade may unblock waiters */
        cv_grants = promote_waiters(ctx, chain, resource);

        if (cv_grants) {
            struct mxfs_lock *wk;
            struct mxfs_lock *cv_basts;
            uint8_t cv_blocked_mode = MXFS_LOCK_NL;
            struct mxfs_bast_record cv_bast_recs[MXFS_MAX_BAST_RECORDS];
            int cv_bast_count = 0;

            /* Dispatch grants under lock.
             * sess44 (ccloop) FIX: this DOWNGRADE→promote path was the ONLY
             * one of the 4 promote_waiters dispatch sites that did NOT call
             * dg_grant_ex (the other 3 — release 1684, 2065, remote 3364 — do),
             * so an EX grant promoted here got dir_epoch=0.  The XFS layer's
             * acquire-side stale-base eviction (newtenure/prior-tenure, gated on
             * mxfs_v5_dlm_inode_dir_epoch != 0) was therefore INERT for any dir
             * whose EX was last granted via a downgrade-promote → it RMW'd a
             * stale cached base = the 8/tcp dir_reuse intra-block offset double-
             * alloc (P68-EVDECIDE cur_mep=0 dominant though the master computed
             * epoch→515).  Stamp dir_epoch (and the handoff bit) like the other
             * sites; also send_grant to a REMOTE grantee (a downgrade can unblock
             * a remote waiter — the old local-only signal stranded it). */
            for (wk = cv_grants; wk; wk = wk->work_next) {
                if (wk->mode == MXFS_LOCK_EX)
                    wk->handoff = dg_grant_ex(ctx, &wk->resource, wk->owner,
                                              wk->grant_gen, &wk->dir_epoch);
                if (wk->owner == ctx->local_node)
                    pending_signal_resource(ctx, &wk->resource,
                                            wk->mode, 0, 0);
                else
                    send_grant(ctx, wk->owner, &wk->resource,
                               wk->mode, MXFS_OK, MXFS_MSG_LOCK_GRANT,
                               wk->request_epoch, wk->grant_gen, wk->handoff,
                               wk->dir_epoch);
            }

            /* Post-promotion BASTs — capture into snapshot */
            cv_basts = collect_post_promotion_basts(
                chain, resource, &cv_blocked_mode);

            for (wk = cv_basts; wk; wk = wk->work_next) {
                if (cv_bast_count < MXFS_MAX_BAST_RECORDS) {
                    cv_bast_recs[cv_bast_count].owner = wk->owner;
                    cv_bast_recs[cv_bast_count].requested_mode = cv_blocked_mode;
                    cv_bast_count++;
                }
            }

            mxfs_pal_rwlock_unlock(ctx->table_rwlock);

            /* Fire BASTs from snapshot */
            fire_bast_records(ctx, resource, cv_bast_recs, cv_bast_count);
        } else {
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        }

        return 0;
    }

    /* Upgrade — check compatibility with other holders */
    {
        int conv_compat = 1;

        for (lk = chain; lk; lk = lk->next) {
            if (!resource_equal(&lk->resource, resource))
                continue;
            if (lk->state != MXFS_LSTATE_GRANTED)
                continue;
            if (lk->owner == owner)
                continue;
            if (!lock_compat[lk->mode][new_mode]) {
                conv_compat = 0;
                break;
            }
        }

        if (conv_compat) {
            target_lk->mode = new_mode;
            target_lk->granted_at = mxfs_pal_time_ms();
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            return 0;
        }

        /* Upgrade blocked — mark as converting */
        target_lk->state = MXFS_LSTATE_CONVERTING;
        target_lk->mode = new_mode;
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -EINPROGRESS;
    }
}

/* ─── mxfs_dlm_purge_node — Release all locks for a dead node ─── */

int mxfs_dlm_purge_node(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node)
{
    uint32_t i;
    int purged = 0;
    struct mxfs_lock *grant_list = NULL;
    int grant_count = 0;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: purging all locks for dead node %u", node);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    for (i = 0; i < ctx->bucket_count; i++) {
        struct mxfs_lock **pp = &ctx->buckets[i];

        while (*pp) {
            struct mxfs_lock *lk = *pp;

            if (lk->owner == node) {
                *pp = lk->next;
                lock_free(lk);
                ctx->lock_count--;
                purged++;
            } else {
                pp = &lk->next;
            }
        }
    }

    /* Promote waiters across all buckets */
    for (i = 0; i < ctx->bucket_count; i++) {
        struct mxfs_lock *chain = ctx->buckets[i];
        struct mxfs_lock *lk_iter;

        if (!chain)
            continue;

        for (lk_iter = chain; lk_iter; lk_iter = lk_iter->next) {
            struct mxfs_lock *other;
            int ok;

            if (lk_iter->state != MXFS_LSTATE_WAITING &&
                lk_iter->state != MXFS_LSTATE_BLOCKED)
                continue;

            ok = 1;
            for (other = chain; other; other = other->next) {
                if (!resource_equal(&other->resource, &lk_iter->resource))
                    continue;
                if (other->state != MXFS_LSTATE_GRANTED)
                    continue;
                if (other->owner == lk_iter->owner)
                    continue;
                if (!lock_compat[other->mode][lk_iter->mode]) {
                    ok = 0;
                    break;
                }
            }

            if (ok) {
                lk_iter->state = MXFS_LSTATE_GRANTED;
                lk_iter->granted_at = mxfs_pal_time_ms();
                lk_iter->work_next = grant_list;
                grant_list = lk_iter;
                grant_count++;
            }
        }
    }

    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: purged %d locks from node %u, promoted %d waiters",
                 purged, node, grant_count);

    /* Complete pending entries for promoted waiters */
    {
        struct mxfs_lock *wk;
        for (wk = grant_list; wk; wk = wk->work_next)
            pending_signal_resource(ctx, &wk->resource, wk->mode, 0, 0);
    }

    /* Bug 85: wake ALL pending lock waiters (not just promoted ones).
     *
     * When a remote-master node dies, threads waiting in pending_wait()
     * for a LOCK_GRANT from that master would stall for up to 120s
     * (MXFS_LOCK_WAIT_TIMEOUT_MS).  The deferred update_active_nodes()
     * path may not call fail_all_pending() if the lease table still
     * includes the dead node (lease expiry takes ~6 min, but TCP
     * disconnect is detected in seconds).
     *
     * By waking all pending waiters here with MXFS_DLM_RETRY, threads
     * immediately retry.  If the master mapping hasn't updated yet,
     * the send will fail fast (-ENOTCONN) and the retry loop in
     * mxfs_dlm_lock() will catch it and retry with a sleep, giving
     * update_active_nodes() time to remap the master. */
    if (purged > 0)
        fail_all_pending(ctx);

    return purged;
}

/* ─── mxfs_dlm_purge_stale_for_resource — Remove stale remote holders ─── */

int mxfs_dlm_purge_stale_for_resource(struct mxfs_dlm_ctx *ctx,
                                       const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock **pp;
    struct mxfs_lock *grants;
    int purged = 0;

    if (!ctx || !resource)
        return 0;

    bucket = resource_hash(resource, ctx->bucket_count);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    /* Remove all entries for this resource owned by remote nodes.
     * These are stale holders from a defunct master that will never
     * release via BAST because the new master doesn't know about them. */
    pp = &ctx->buckets[bucket];
    while (*pp) {
        struct mxfs_lock *lk = *pp;

        if (resource_equal(&lk->resource, resource) &&
            lk->owner != ctx->local_node) {
            *pp = lk->next;
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "dlm: purging stale %s lock for node %u "
                         "on resource (type=%u, ino=%llu)",
                         mode_name(lk->mode), lk->owner,
                         resource->type,
                         (unsigned long long)resource->ino);
            lock_free(lk);
            ctx->lock_count--;
            purged++;
        } else {
            pp = &lk->next;
        }
    }

    if (purged == 0) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return 0;
    }

    /* Promote any waiters that were blocked by the purged holders */
    grants = promote_waiters(ctx, ctx->buckets[bucket], resource);

    if (grants) {
        struct mxfs_lock *wk;
        struct mxfs_lock *post_basts;
        uint8_t blocked_mode = MXFS_LOCK_NL;
        struct mxfs_bast_record post_bast_recs[MXFS_MAX_BAST_RECORDS];
        int post_bast_count = 0;

        /* Dispatch grants under lock */
        for (wk = grants; wk; wk = wk->work_next) {
            if (wk->mode == MXFS_LOCK_EX)
                wk->handoff = dg_grant_ex(ctx, &wk->resource, wk->owner,
                                          wk->grant_gen, &wk->dir_epoch);
            if (wk->owner == ctx->local_node)
                pending_signal_resource(ctx, &wk->resource,
                                        wk->mode, 0, 0);
            else
                send_grant(ctx, wk->owner, &wk->resource,
                           wk->mode, MXFS_OK, MXFS_MSG_LOCK_GRANT,
                           wk->request_epoch, wk->grant_gen, wk->handoff,
                           wk->dir_epoch);
        }

        /* Post-promotion BASTs -- capture into snapshot */
        post_basts = collect_post_promotion_basts(
            ctx->buckets[bucket], resource, &blocked_mode);

        for (wk = post_basts; wk; wk = wk->work_next) {
            if (post_bast_count < MXFS_MAX_BAST_RECORDS) {
                post_bast_recs[post_bast_count].owner = wk->owner;
                post_bast_recs[post_bast_count].requested_mode = blocked_mode;
                post_bast_count++;
            }
        }

        mxfs_pal_rwlock_unlock(ctx->table_rwlock);

        /* Fire post-promotion BASTs from snapshot */
        fire_bast_records(ctx, resource, post_bast_recs, post_bast_count);
    } else {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: purged %d stale entries for resource "
                 "(type=%u, ino=%llu)",
                 purged, resource->type,
                 (unsigned long long)resource->ino);

    return purged;
}

/* ─── mxfs_dlm_withdraw_release_all — wire-release every grant we hold ───
 *
 * sess10 (ccloop 72513a13, RULE-4 PROVEN 32/tcp fio cascade): a node whose
 * FS force-shut down cannot serve BASTs any more (the release drain needs
 * the live FS), but its GRANTED entries remain in every master's table —
 * so any peer's conflicting request starves to terminal -ETIMEDOUT and
 * that peer ALSO force-shuts down (test29 dirty-trans-cancel first, then
 * 5 nodes died rc=-110 on ino=128 whose PR holders included dead nodes;
 * the dead master's service itself kept answering — the un-releasable
 * GRANTS were the block).  A dead FS holds no valid cache: release
 * EVERYTHING on withdrawal so peers promote immediately.
 *
 * Walk ctx->buckets snapshotting every resource with an owner==local entry
 * (GRANTED/CONVERTING mirrors of remote masters AND locally-mastered own
 * grants AND our queued WAITING entries — nobody will ever consume those
 * either), then run the standard mxfs_dlm_unlock per resource (local:
 * remove + promote_waiters + post-promotion grants/BASTs; remote: send
 * LOCK_RELEASE).  Unlocks are done OUTSIDE the table lock. */
void mxfs_dlm_withdraw_release_all(struct mxfs_dlm_ctx *ctx)
{
    struct mxfs_resource_id *list = NULL;
    uint32_t i, n = 0, cap = 0;
    int pass;

    if (!ctx)
        return;

    /* pass 0: count; pass 1: fill (table can shrink between passes — the
     * fill re-checks bounds; a second walk missing new entries is fine,
     * the FS is dead and creates nothing new). */
    for (pass = 0; pass < 2; pass++) {
        uint32_t seen = 0;

        mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
        for (i = 0; i < ctx->bucket_count; i++) {
            struct mxfs_lock *lk;

            for (lk = ctx->buckets[i]; lk; lk = lk->next) {
                if (lk->owner != ctx->local_node)
                    continue;
                if (pass == 1) {
                    if (seen < cap)
                        list[seen] = lk->resource;
                }
                seen++;
            }
        }
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        if (pass == 0) {
            cap = seen;
            if (cap == 0)
                return;
            list = mxfs_pal_alloc(cap * sizeof(*list));
            if (!list) {
                mxfs_pal_log(MXFS_LOG_WARN,
                    "dlm: withdraw_release_all alloc failed (%u entries leak until unmount)",
                    cap);
                return;
            }
        } else {
            n = seen < cap ? seen : cap;
        }
    }

    for (i = 0; i < n; i++)
        mxfs_dlm_unlock(ctx, &list[i]);

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P-WITHDRAW-RELALL released %u held/queued grants (dead-FS holder cannot serve BASTs)",
                 n);
    mxfs_pal_free(list);
}

/* ─── mxfs_dlm_release_all — Release all locks held by local node ─── */

void mxfs_dlm_release_all(struct mxfs_dlm_ctx *ctx)
{
    uint32_t i;
    int released = 0;

    if (!ctx)
        return;

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    for (i = 0; i < ctx->bucket_count; i++) {
        struct mxfs_lock **pp = &ctx->buckets[i];

        while (*pp) {
            struct mxfs_lock *lk = *pp;

            if (lk->owner == ctx->local_node) {
                *pp = lk->next;
                lock_free(lk);
                ctx->lock_count--;
                released++;
            } else {
                pp = &lk->next;
            }
        }
    }

    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: released %d local locks on unmount", released);
}

/* ─── Distributed per-resource mastering ─── */

static int node_id_cmp(const void *a, const void *b)
{
    mxfs_node_id_t na = *(const mxfs_node_id_t *)a;
    mxfs_node_id_t nb = *(const mxfs_node_id_t *)b;

    if (na < nb) return -1;
    if (na > nb) return 1;
    return 0;
}

mxfs_node_id_t mxfs_dlm_resource_master(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource)
{
    uint32_t hash;
    mxfs_node_id_t master;

    if (!ctx || !resource)
        return 0;

    hash = resource_hash_raw(resource);

    mxfs_pal_mutex_lock(ctx->active_nodes.lock);

    master = ctx->local_node;
    if (ctx->active_nodes.count > 0)
        master = ctx->active_nodes.nodes[hash %
                 (uint32_t)ctx->active_nodes.count];

    mxfs_pal_mutex_unlock(ctx->active_nodes.lock);

    return master;
}

bool mxfs_dlm_is_resource_master(struct mxfs_dlm_ctx *ctx,
                                 const struct mxfs_resource_id *resource)
{
    return mxfs_dlm_resource_master(ctx, resource) == ctx->local_node;
}

int mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx,
                                 const mxfs_node_id_t *nodes, int count)
{
    mxfs_node_id_t sorted[MXFS_MAX_NODES];
    int old_count, i;
    bool changed = false;

    if (!ctx || !nodes || count <= 0 || count > MXFS_MAX_NODES)
        return -EINVAL;

    /* Sort into a temp buffer for comparison */
    memcpy(sorted, nodes, (size_t)count * sizeof(mxfs_node_id_t));
    mxfs_pal_sort(sorted, (size_t)count, sizeof(mxfs_node_id_t),
                  node_id_cmp);

    /* Remove duplicates from sorted array */
    if (count > 1) {
        int j = 0;
        for (i = 1; i < count; i++) {
            if (sorted[i] != sorted[j])
                sorted[++j] = sorted[i];
        }
        count = j + 1;
    }

    mxfs_pal_mutex_lock(ctx->active_nodes.lock);

    old_count = ctx->active_nodes.count;

    if (old_count != count) {
        changed = true;
    } else {
        for (i = 0; i < count; i++) {
            if (ctx->active_nodes.nodes[i] != sorted[i]) {
                changed = true;
                break;
            }
        }
    }

    if (changed) {
        uint64_t h = 0xcbf29ce484222325ULL;   /* FNV-1a 64 over sorted ids */

        memcpy(ctx->active_nodes.nodes, sorted,
               (size_t)count * sizeof(mxfs_node_id_t));
        ctx->active_nodes.count = count;
        /* v0.11.78 (D7): my view signature — deterministic across nodes
         * because the list is sorted.  Peers echo theirs on the lease
         * beacon; equality proves identical mastery mapping. */
        for (i = 0; i < count; i++) {
            uint32_t id = sorted[i];
            int b;

            for (b = 0; b < 4; b++) {
                h ^= (id >> (8 * b)) & 0xff;
                h *= 0x100000001b3ULL;
            }
        }
        h ^= (uint32_t)count;
        h *= 0x100000001b3ULL;
        ctx->my_view_count = (uint32_t)count;
        ctx->my_view_hash = h;
    }

    mxfs_pal_mutex_unlock(ctx->active_nodes.lock);

    if (changed) {
        /* Mastering has shifted — purge all lock table entries */
        int purged = 0;
        mxfs_epoch_t new_epoch;

        /* sess39: stamp the change time so the grant path freezes EX grants
         * until membership settles (no split-brain during convergence). */
        ctx->last_memb_change_ms = mxfs_pal_time_ms();

        /* sess45 (ccloop 4cb2d0a2): ALWAYS-ON membership-count beacon.  Fires
         * only on an actual membership change (low frequency), so it is free on
         * the hot path.  The test harness (run.sh prep) greps the LATEST count
         * per node and gates the workload until ALL N nodes report active_count
         * == N — eliminating the FORMATION-RAMP split-brain (8/tcp dir_reuse MASS
         * loss): the master = nodes[hash%count] diverges while nodes hold
         * different counts during the 1->N ramp.  A real deployment forms the
         * cluster before serving I/O; this beacon lets the harness establish
         * that converged precondition. */
        pr_warn("mxfs: MXFS-MEMBERSHIP local=%u active_count=%d\n",
                ctx->local_node, count);

        mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
        for (i = 0; i < (int)ctx->bucket_count; i++) {
            struct mxfs_lock *lk = ctx->buckets[i];
            struct mxfs_lock *next;

            while (lk) {
                next = lk->next;
                mxfs_pal_free(lk);
                purged++;
                lk = next;
            }
            ctx->buckets[i] = NULL;
        }
        ctx->lock_count = 0;
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);

        /* Wake all threads sleeping in pending_wait().
         *
         * The lock table purge above freed all WAITING lock entries,
         * but threads may still be blocked in pending_wait() in two
         * scenarios:
         *
         * 1. Remote-master path: thread sent LOCK_REQ to a now-dead
         *    node and is waiting for a LOCK_GRANT that will never
         *    arrive. Without this wake-up, the thread blocks for
         *    MXFS_LOCK_WAIT_TIMEOUT_MS (120s), causing D-state hangs.
         *
         * 2. Local-master path (incompatible queue): thread created
         *    a WAITING lock entry and sent BASTs to holders that are
         *    now dead. The WAITING entry was freed by the table purge
         *    above, but the pending entry is still in pending_buckets.
         *
         * Completing with MXFS_DLM_RETRY causes mxfs_dlm_lock() to retry
         * the request from scratch with the updated master assignment.
         * The retry will typically succeed immediately because the
         * surviving node is now master for all resources. */
        fail_all_pending(ctx);

        /* Advance epoch so that inode cache entries acquired under
         * the old membership are detected as stale on next access.
         * Without this, a node that processed the membership change
         * later than its peers could hold a cached lock that the new
         * master doesn't know about, causing BASTs to miss that node
         * at 3+ nodes. */
        new_epoch = mxfs_dlm_advance_epoch(ctx);

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "dlm: membership changed (%d->%d nodes), "
                     "purged %d stale locks, epoch=%llu",
                     old_count, count, purged,
                     (unsigned long long)new_epoch);

        /* Notify mount code to invalidate all caches, since cached
         * lock_mode values are now stale after the table purge */
        if (ctx->membership_cb)
            ctx->membership_cb(ctx);
    }

    return changed ? 1 : 0;
}

bool mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx)
{
    if (!ctx)
        return true;

    /*
     * sess16 FIX-K (a9a03929): LOCKLESS read.  This is the gate at the top
     * of every hot XFS-overlay hook (buf lookup/submit/release, ilock
     * begin/end, trans commit) — ftrace measured 2,276,687 calls in ONE
     * single_node_paired rsync leg, all serializing on active_nodes.lock
     * (the single-node residual vs native, ~+5%).  count is an int written
     * only at ctx init and inside mxfs_dlm_update_active_nodes (under the
     * mutex); a bare load is atomic on every supported arch and sees either
     * the old or new value — indistinguishable from having taken the mutex
     * just before/after the membership change (same race window as before).
     * dlm_membership_settling() reads it the same lockless way.
     */
    return ctx->active_nodes.count <= 1;
}

/*
 * sess-tcp phantom-EX detection (TCP transport).  Return the highest mode at
 * which THIS node currently holds `resource` in its LOCAL mirror (a
 * GRANTED/CONVERTING entry owned by local_node), or MXFS_LOCK_NL (0) if we
 * hold nothing.  mxfs_v5_dlm_inode_held() hardcoded 1 for the TCP transport
 * (it only ever consulted the CAW slot table), so the xfs-layer phantom-EX
 * probe — cached i_dlm_mode==EX vs. the real grant — was INERT on TCP, the
 * exact transport the 2/tcp criterion exercises.  A dir-EX fast-path that
 * trusts a stale cached EX while the grant is actually gone is the proven
 * mutual-exclusion violation (concurrent divergent-base RMW -> durable
 * dir lost-update).  Read-only walk under table_rwlock(read); cheap, no I/O.
 */
/*
 * ccloop c7ee71c6 sess21 — ATOMIC-CONTEXT-SAFE variant of
 * mxfs_dlm_held_mode.
 *
 * ROOT (proven byte-exact, 32/tcp rsync_paired, test31 + 7 more nodes):
 * mxfs_dlm_held_mode takes ctx->table_rwlock with mxfs_pal_rwlock_rdlock,
 * and in the kernel PAL that is a struct rw_semaphore.  Under contention
 * down_read() enters rwsem_down_read_slowpath -> schedule().  The sess20
 * "non-blocking" helper mxfs_v5_dlm_inode_held_nb called straight into
 * here on the TCP arm, from inside spin_lock(&pag->pag_ici_lock):
 *
 *   mxfs_pal_rwlock_rdlock <- down_read <- rwsem_down_read_slowpath <- schedule()
 *   mxfs_dlm_held_mode
 *   mxfs_v5_dlm_inode_held_nb
 *   mxfs_submit_partial_inode_write     (preempt_count 0x2)
 *   xfs_buf_submit_bio ... xfsaild
 *
 * -> "BUG: scheduling while atomic", which leaves pag_ici_lock held across
 * the schedule and corrupts preempt_count (the immediately following BUG
 * reports 0x00000000).  A peer CPU then spins on that spinlock forever:
 * test31 logged "soft lockup - CPU#2 stuck for 522s! [rsync]" with zero
 * context switches, stopped answering sshd, and never released its AG
 * grants -- so all 31 peers starved (9210 P-LKTIMEOUT-REMOTE, 8590
 * P36-RETRY) and rsync_paired never terminated.
 *
 * Fix: acquire with the trylock, which never schedules.  Returns 0 and
 * stores the held mode on success, -EWOULDBLOCK if the table was busy.
 * Callers must treat -EWOULDBLOCK as "cannot tell", never as "not held".
 */
int mxfs_dlm_held_mode_nb(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          uint8_t *out_mode)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;

    if (!ctx || !resource || !ctx->buckets || !out_mode)
        return -EWOULDBLOCK;

    if (!mxfs_pal_rwlock_tryrdlock(ctx->table_rwlock))
        return -EWOULDBLOCK;

    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode > best)
            best = lk->mode;
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    *out_mode = best;
    return 0;
}

uint8_t mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;

    if (!ctx || !resource || !ctx->buckets)
        return MXFS_LOCK_NL;

    /*
     * ccloop c7ee71c6 sess21 — P191: SLEEP-IN-ATOMIC TRIPWIRE.
     *
     * table_rwlock is a sleeping lock, so reaching here with a spinlock
     * held corrupts preempt state and soft-locks whichever peer CPU is
     * spinning on that spinlock (proven: 32/tcp rsync_paired, test31
     * rsync stuck 522 s, whole cluster starved).  That defect reached the
     * tree twice — sess19 through a blocking SCSI read, sess20 through
     * this rwsem — because nothing checked.  Name the caller loudly
     * instead of wedging 500 s later somewhere unrelated.  Callers in
     * atomic context must use mxfs_dlm_held_mode_nb.
     */
    if (unlikely(!mxfs_pal_may_sleep())) {
        pr_warn_ratelimited(
            "mxfs: P191-SLEEP-IN-ATOMIC fn=mxfs_dlm_held_mode type=%u ino=%llu ag=%u comm=%s — BLOCKING DLM query from atomic context; use mxfs_dlm_held_mode_nb\n",
            resource->type, (unsigned long long)resource->ino,
            resource->ag_number, dlm_cur_comm());
        return MXFS_LOCK_NL;
    }

    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode > best)
            best = lk->mode;
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    return best;
}

/* sess61 (sess10 plan): the per-grant generation token THIS node currently holds
 * for `resource` in its local mirror — the highest-mode GRANTED/CONVERTING entry
 * owned by local_node, or 0 if none.  grant_gen is the RELIABLE (acked-TCP)
 * "did the lock change hands" signal stamped by the master on every grant
 * episode (dlm_next_gen).  The dir-EX fast path compares it to a per-inode cached
 * value to detect a tenure change without depending on the lossy DIR_MODIFY
 * eviction-ring, forcing a reload-on-reacquire before a stale-base RMW. */
uint32_t mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;
    uint32_t gen = 0;

    if (!ctx || !resource || !ctx->buckets)
        return 0;

    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode >= best) {
            best = lk->mode;
            gen = lk->grant_gen;
        }
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    return gen;
}

/* sess4(a9a03929) FIX-1 support: the highest mode THIS node currently holds
 * for `resource` in the local mirror (MXFS_LOCK_NL if none).  Used by the
 * nested-hold admit arm in mxfs_dlm_ilock_begin to restore i_dlm_mode from
 * the mirror when an abort path left it NL while the grant is retained. */
uint8_t mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx,
                              const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;

    if (!ctx || !resource || !ctx->buckets)
        return MXFS_LOCK_NL;

    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode > best)
            best = lk->mode;
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    return best;
}

/* sess63: did the EX grant THIS node currently holds for `resource` arrive as a
 * cross-node handoff?  Reads the handoff bit the master stamped on this grant
 * (delivered via the grant response / set locally on a local grant).  Returns
 * the bit for the highest-mode GRANTED/CONVERTING entry owned by local_node;
 * *gen_out (if non-NULL) gets that entry's grant_gen so the caller can consume
 * the handoff exactly once per grant episode. */
bool mxfs_dlm_grant_was_handoff(struct mxfs_dlm_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                uint32_t *gen_out)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;
    bool handoff = false;
    uint32_t gen = 0;

    if (gen_out)
        *gen_out = 0;
    if (!ctx || !resource || !ctx->buckets)
        return false;

    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode >= best) {
            best = lk->mode;
            handoff = lk->handoff;
            gen = lk->grant_gen;
        }
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    if (gen_out)
        *gen_out = gen;
    return handoff;
}

/* sess64 (GPT design): the MONOTONIC cross-node handoff epoch the master stamped
 * on our currently-held grant.  Returns the epoch of the highest-mode
 * GRANTED/CONVERTING entry local_node owns for `resource`, or 0 if not held. */
uint32_t mxfs_dlm_grant_dir_epoch(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_resource_id *resource)
{
    uint32_t bucket;
    struct mxfs_lock *lk;
    uint8_t best = MXFS_LOCK_NL;
    uint32_t epoch = 0;

    if (!ctx || !resource || !ctx->buckets)
        return 0;

    mxfs_pal_rwlock_rdlock(ctx->table_rwlock);
    bucket = resource_hash(resource, ctx->bucket_count);
    for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
        if (lk->owner != ctx->local_node)
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED &&
            lk->state != MXFS_LSTATE_CONVERTING)
            continue;
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->mode > best)
            best = lk->mode;
        /* sess5 (ccloop) PROVEN-ROOT FIX: return the MAXIMUM dir_epoch across
         * ALL local granted mirrors of this resource, not the last-iterated
         * highest-mode one.  The dir_epoch is a MONOTONIC cross-node handoff
         * counter (the master sends it correctly — P51-SENDGRANT reaches 190,
         * never 0), but under the dir_reuse storm the local node can hold
         * DUPLICATE granted mirrors for the same dir inode (rapid fast-path
         * re-grants / re-affirms insert a fresh mirror whose advance-only store
         * at dlm.c:3317 updates only the FIRST match), so the old
         * "pick last highest-mode mirror" returned a STALE/zero epoch (P44
         * read 0/8/22 while the master was at 190).  A zero master-epoch
         * DISABLES every epoch-gated dir coherence guard (prior_tenure /
         * tenure_stale / newtenure evict all require master_ep != 0) → the
         * node RMW's a stale cached dir-data base → the dir_reuse readdir
         * undercount (100/400 dirents durably clobbered).  Max is correct:
         * a higher epoch strictly means a more-recent coherent handoff. */
        if (lk->dir_epoch > epoch)
            epoch = lk->dir_epoch;
    }
    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    /* sess44 (ccloop) PROBE: P68-EVDECIDE shows cur_mep=0 dominant at the
     * modifying node though the master computes epoch->515 (P64).  Log what the
     * LOCAL granted lock for the storm dir actually carries — best (mode) and
     * epoch — to see whether the local lock is absent (best=NL) or present with
     * a stale/0 epoch.  Capped; ino 131 only. */
    /* sess6(a16ec5f2): only ZERO reads are anomalies (absent mirror when
     * best==0, or present-with-0).  Capped, NOT ratelimited — run42's
     * failure-moment reads were ratelimit-suppressed exactly when needed. */
    if (resource->type == MXFS_LTYPE_INODE && resource->ino == 131 &&
        epoch == 0) {
        static atomic_t p44ge = ATOMIC_INIT(0);
        /* sess7: cap 60000 -> 2000.  At the observed ~700/s verify-phase
         * rate this print alone was ~6MB of serial-console traffic per run
         * (115200 baud = 11.5KB/s) — a real pace tax.  PR-grant lookups
         * legitimately read epoch=0 (only EX handoffs stamp it), so the
         * bulk was noise; 2000 still covers the anomaly window per boot. */
        if ((unsigned)atomic_inc_return(&p44ge) <= 2000)
            pr_warn("mxfs: P44-GRANTDIREPOCH ino=131 local=%u best_mode=%u epoch=0 comm=%s\n",
                    ctx->local_node, best, dlm_cur_comm());
    }
    return epoch;
}

/* ─── Epoch management ─── */

mxfs_epoch_t mxfs_dlm_advance_epoch(struct mxfs_dlm_ctx *ctx)
{
    mxfs_epoch_t epoch;

    if (!ctx)
        return 0;

    mxfs_pal_mutex_lock(ctx->epoch_lock);
    ctx->current_epoch++;
    epoch = ctx->current_epoch;
    mxfs_pal_mutex_unlock(ctx->epoch_lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "dlm: epoch advanced to %llu",
                 (unsigned long long)epoch);
    return epoch;
}

mxfs_epoch_t mxfs_dlm_get_epoch(struct mxfs_dlm_ctx *ctx)
{
    mxfs_epoch_t epoch;

    if (!ctx)
        return 0;

    mxfs_pal_mutex_lock(ctx->epoch_lock);
    epoch = ctx->current_epoch;
    mxfs_pal_mutex_unlock(ctx->epoch_lock);

    return epoch;
}

/* ─── sess8 DOUBLE-GRANT detector (instrumentation only) ───
 *
 * Tracks current EX holders for INODE resources in a small shadow table,
 * SEPARATE from the lock table (the lock table entry is exactly what gets
 * removed by an administrative removal — convblk/stale/conversion-blocked —
 * leaving a "ghost" holder that the table can no longer show).  The shadow is
 * SET on every EX grant the master dispatches and CLEARED only on a GENUINE
 * release (process_remote_release / mxfs_dlm_unlock) — NOT on administrative
 * removals.  At each EX grant we check for an existing active EX held by a
 * DIFFERENT node on the same resource: that is a true double-grant (two nodes
 * hold EX concurrently), the proven 2/tcp shortform-dir lost-update root.
 *
 * ALL callers hold ctx->table_rwlock (write), so the shadow is consistent with
 * no new lock and no ordering risk.  A bookkeeping miss only mislogs — it can
 * never wedge the DLM.  Master-side only: the master is the single arbiter for
 * a resource, so its shadow captures every grant for the resources it masters
 * (the dir inode is mastered by one node, which is where the check fires). */
/* sess17(ccloop): dg_grant_ex/dg_release LINEAR-SCAN this table per grant, so it
 * must stay small (enlarging to 16384 caused O(N)-per-grant acquire timeouts).
 * The bug it had at 512 was EVICTION POLICY, not size: it recycled the FIRST
 * inactive slot, so the HOT shared dir inode's briefly-inactive slot was evicted
 * by the ~800 file-inode grants between two of its grants — LOSING last_owner
 * (handoff under-fires ~80% on TCP) and resetting epoch to 0.  Fixed by LRU
 * eviction (evict the least-recently-GRANTED inactive slot): the dir inode is
 * granted ~800×/round (every file create takes the parent-dir EX), so its
 * last_grant_seq is always near the top → never the LRU victim → never evicted. */
#define DG_SHADOW_N 8192	/* sess44: 512->8192.  The 8-node x 100-file storm
				 * grants 800+ distinct inodes/round; at 512 the
				 * shadow table can overflow (no empty/inactive slot)
				 * so dg_grant_ex records nothing -> epoch_out=0 ->
				 * cur_mep=0 -> acquire-side coherency evict inert.
				 * A/B for the dir_epoch=0 root. */
struct dg_shadow_ent {
    struct mxfs_resource_id res;
    mxfs_node_id_t          owner;       /* current active EX owner */
    mxfs_node_id_t          last_owner;  /* sess63: most-recent EX owner,
                                          * RETAINED across release so the next
                                          * grant can tell same-node re-grant
                                          * (no handoff) from cross-node handoff */
    uint32_t                gen;
    uint32_t                epoch;       /* sess64 (GPT design): MONOTONIC count of
                                          * cross-node EX handoffs for this resource.
                                          * Bumped in dg_grant_ex whenever handoff is
                                          * computed true.  Stamped on every grant and
                                          * compared level-triggered by the grantee. */
    bool                    active;
    bool                    used;        /* sess63: slot ever populated (res +
                                          * last_owner valid even when !active) */
    uint64_t                last_grant_seq; /* sess17: monotonic seq of this slot's
                                          * most recent grant — for LRU eviction so a
                                          * HOT resource (frequently re-granted) is
                                          * never recycled out from under its peers */
    uint64_t                grant_count; /* sess23(ccloop): total EX grants this slot's
                                          * resource has received.  Eviction prefers the
                                          * COLDEST (lowest grant_count) inactive slot, so
                                          * the hot shared-dir inode (granted ~800x/round)
                                          * is NEVER evicted while cold file inodes
                                          * (granted 1-2x) are — preserving the dir's
                                          * handoff epoch reliably (LRU-by-seq alone let a
                                          * briefly-inactive hot dir be evicted, resetting
                                          * its epoch to 0 -> dir_reuse flaky clobber). */
};
static struct dg_shadow_ent dg_shadow[DG_SHADOW_N];
static uint64_t dg_shadow_grant_seq;     /* sess17: ++ on every dg_grant_ex (under
                                          * table_rwlock write — already held) */

/* Caller holds ctx->table_rwlock.  Record that `owner` was granted EX on
 * `res`; first flag any pre-existing active EX held by a different node.
 *
 * sess63 RETURNS the HANDOFF bit: true iff a DIFFERENT node was the most-recent
 * EX owner of `res` (last_owner != owner).  This is the reliable acked-protocol
 * "the dir base changed under us" signal the XFS reload layer needs — far
 * better than grant_gen (which bumps on benign same-node re-grants) and the
 * lossy DIR_MODIFY evict-ring (which drops messages on TCP).  last_owner is
 * RETAINED across dg_release so a release+reacquire by the same node with no
 * peer in between correctly reports NO handoff (no resurrection). */
static bool dg_grant_ex(struct mxfs_dlm_ctx *ctx,
                        const struct mxfs_resource_id *res,
                        mxfs_node_id_t owner, uint32_t gen,
                        uint32_t *epoch_out)
{
    int i, empty = -1, evict = -1, mine = -1;
    uint64_t evict_seq = 0;	/* sess17: last_grant_seq of the current LRU victim */
    uint64_t evict_gc = 0;	/* sess23: grant_count of the current victim (coldest-first) */
    bool handoff = false;

    if (epoch_out)
        *epoch_out = 0;
    if (res->type != MXFS_LTYPE_INODE)
        return false;

    /* sess8 SPLIT-BRAIN MASTERSHIP probe: recompute the master LOCKLESSLY
     * (plain reads — a torn read only mislogs a diagnostic, never wedges; no
     * new lock so no ordering risk vs the held table_rwlock).  This node only
     * reaches a master-side EX grant for a resource it believed it mastered;
     * if it is NOT the master NOW, mastership flipped under it (membership
     * flap) → two nodes can be master at once → concurrent EX that the
     * per-node P-DOUBLEGRANT cannot see.  Decisive for the flap hypothesis. */
    {
        int cnt = ctx->active_nodes.count;
        if (cnt > 0) {
            uint32_t h = resource_hash_raw(res);
            mxfs_node_id_t m = ctx->active_nodes.nodes[h % (uint32_t)cnt];
            if (m != ctx->local_node)
                pr_warn_ratelimited(
                    "mxfs: P-STALEMASTER-GRANT ino=%llu owner=%u "
                    "local=%u computed_master=%u active_count=%d\n",
                    (unsigned long long)res->ino, owner,
                    ctx->local_node, m, cnt);
        }
    }

    for (i = 0; i < DG_SHADOW_N; i++) {
        if (dg_shadow[i].used && resource_equal(&dg_shadow[i].res, res)) {
            mine = i;
            /* Double-grant: a DIFFERENT node still holds an ACTIVE EX. */
            if (dg_shadow[i].active && dg_shadow[i].owner != owner) {
                pr_warn_ratelimited(
                    "mxfs: P-DOUBLEGRANT ino=%llu type=%u "
                    "owner_existing=%u gen_existing=%u "
                    "owner_new=%u gen_new=%u\n",
                    (unsigned long long)res->ino, res->type,
                    dg_shadow[i].owner, dg_shadow[i].gen,
                    owner, gen);
                /* sess48 (RULE 4): dump the master's live lock chain for this
                 * resource at the double-grant instant.  If the prior EX owner
                 * has a GRANTED chain entry here, the compat check is buggy
                 * (it should have queued+BAST'd); if NO chain entry for it,
                 * the shadow and the chain have desynced (the chain entry was
                 * removed without a matching dg_release) — pinpoints which. */
                {
                    uint32_t b = resource_hash(res, ctx->bucket_count);
                    struct mxfs_lock *cl;
                    int nh = 0;
                    for (cl = ctx->buckets[b]; cl; cl = cl->next) {
                        if (!resource_equal(&cl->resource, res))
                            continue;
                        nh++;
                        pr_warn_ratelimited(
                            "mxfs: P48-DG-CHAIN ino=%llu holder=%u mode=%s state=%s grant_gen=%u\n",
                            (unsigned long long)res->ino, cl->owner,
                            mode_name(cl->mode),
                            (cl->state < 5 ? lock_state_names[cl->state] : "?"),
                            cl->grant_gen);
                    }
                    if (nh == 0)
                        pr_warn_ratelimited(
                            "mxfs: P48-DG-CHAIN ino=%llu EMPTY (no chain entry — shadow/chain desync)\n",
                            (unsigned long long)res->ino);
                }
            }
            break;
        }
        if (!dg_shadow[i].used) {
            if (empty < 0)
                empty = i;
        } else if (!dg_shadow[i].active) {
            /* sess23(ccloop): evict the COLDEST inactive slot — lowest
             * grant_count first, breaking ties by oldest last_grant_seq.  A hot
             * resource (the shared dir, granted ~800x/round) has a huge
             * grant_count so it is NEVER the victim even when briefly inactive
             * between its rapid grants; cold file inodes (granted 1-2x) are
             * evicted instead.  Pure LRU-by-seq let a briefly-inactive hot dir
             * be evicted by the ~800 file-inode grants between two of its grants
             * -> epoch reset to 0 -> dir_reuse durable clobber (flaky). */
            if (evict < 0 ||
                dg_shadow[i].grant_count < evict_gc ||
                (dg_shadow[i].grant_count == evict_gc &&
                 dg_shadow[i].last_grant_seq < evict_seq)) {
                evict = i;
                evict_seq = dg_shadow[i].last_grant_seq;
                evict_gc = dg_shadow[i].grant_count;
            }
        }
    }
    if (mine >= 0) {
        /* HANDOFF iff the prior EX owner was a different node.  last_owner==0
         * means never granted (shouldn't happen for a used slot) -> no handoff. */
        handoff = (dg_shadow[mine].last_owner != 0 &&
                   dg_shadow[mine].last_owner != owner);
        /* sess53(ccloop) RULE-4 under-fire probe: the grantee logs
         * P51-HANDOFF-UNDERFIRE (grant_gen advanced but ho=FALSE).  Capture the
         * master's computation INPUTS so we see WHY handoff is false on a real
         * cross-node handoff: stale last_owner (==owner) vs active_b4=1 (grant
         * while prior owner still ACTIVE = a re-grant w/o intervening release =
         * dg_release missed) vs a NEWSLOT (mine<0, eviction). storm dir only. */
        if (res->ino <= 256 && res->type == MXFS_LTYPE_INODE) {
            static atomic_t pdgex = ATOMIC_INIT(0);
            if (atomic_inc_return(&pdgex) <= 6000)
                pr_warn("mxfs: P-DGEX ino=%llu owner=%u last_owner=%u active_b4=%d gen=%u handoff=%d epoch=%u\n",
                        (unsigned long long)res->ino, owner,
                        dg_shadow[mine].last_owner,
                        dg_shadow[mine].active ? 1 : 0, gen,
                        handoff ? 1 : 0, dg_shadow[mine].epoch);
        }
        /* sess64 (GPT design): a cross-node handoff advances the MONOTONIC
         * per-resource epoch.  The grantee compares this absolute value against
         * its valid_epoch (level-triggered), so even if it missed intermediate
         * handoffs (served fast-path, or a one-shot signal was consumed
         * elsewhere) it still observes epoch > valid_epoch and refreshes its
         * stale dir base exactly once. */
        if (handoff) {
            dg_shadow[mine].epoch++;
            pr_warn_ratelimited(
                "mxfs: P64-MASTER-HANDOFF ino=%llu owner=%u last_owner=%u gen=%u epoch=%u\n",
                (unsigned long long)res->ino, owner,
                dg_shadow[mine].last_owner, gen, dg_shadow[mine].epoch);
        }
        if (epoch_out)
            *epoch_out = dg_shadow[mine].epoch;
        dg_shadow[mine].owner = owner;
        dg_shadow[mine].last_owner = owner;
        dg_shadow[mine].gen = gen;
        dg_shadow[mine].active = true;
        dg_shadow[mine].last_grant_seq = ++dg_shadow_grant_seq;	/* sess17 LRU */
        dg_shadow[mine].grant_count++;	/* sess23: hot-slot eviction immunity */
    } else {
        /* First grant we've recorded for this resource.  Prefer a never-used
         * slot; else recycle an inactive (released) slot — recycling loses that
         * resource's last_owner, but the inode whose last_owner is lost simply
         * reports "no handoff" next time (conservative: no false adopt). */
        int slot = (empty >= 0) ? empty : evict;
        if (slot >= 0) {
            dg_shadow[slot].res = *res;
            dg_shadow[slot].owner = owner;
            dg_shadow[slot].last_owner = owner;
            dg_shadow[slot].gen = gen;
            /* sess35: REVERTED epoch-never-0 (was =1) — it made new_tenure
             * fire SPURIOUSLY in the first tenure (cur_mep=1 != evict_mep=0),
             * so P34-NEWTENURE-RETIRE retired in-AIL UNDESTAGED BLIs that were
             * THIS tenure's own un-landed creates (Inv 1 only holds at RELEASE,
             * not mid-tenure) → readdir=0 catastrophe (proven keeper run iter1
             * round2 readdir=0).  Fresh resource restarts epoch at 0 = the
             * grantee operates in the untracked regime but never spuriously
             * force-retires its own work.  The real fix is release-side
             * ordered publish (GPT-5.5), not making new_tenure over-fire. */
            dg_shadow[slot].epoch = 0;
            dg_shadow[slot].active = true;
            dg_shadow[slot].used = true;
            dg_shadow[slot].last_grant_seq = ++dg_shadow_grant_seq;	/* sess17 LRU */
            dg_shadow[slot].grant_count = 1;	/* sess23: fresh resource */
        }
        if (epoch_out)
            *epoch_out = 0;	/* sess35: REVERTED to 0 (epoch-never-0 caused readdir=0) */
        /* Unknown prior owner -> NOT a handoff (avoid false adopt/resurrection). */
        handoff = false;
        if (res->ino <= 256 && res->type == MXFS_LTYPE_INODE) {
            static atomic_t pdgn = ATOMIC_INIT(0);
            if (atomic_inc_return(&pdgn) <= 6000)
                pr_warn("mxfs: P-DGEX-NEWSLOT ino=%llu owner=%u slot=%d (no prior dg_shadow -> handoff FORCED false; eviction/first-grant under-fire?)\n",
                        (unsigned long long)res->ino, owner, slot);
        }
    }
    return handoff;
}

/* Caller holds ctx->table_rwlock.  Genuine release of `res` by `owner`. */
static void dg_release(const struct mxfs_resource_id *res, mxfs_node_id_t owner)
{
    int i;

    if (res->type != MXFS_LTYPE_INODE)
        return;
    for (i = 0; i < DG_SHADOW_N; i++) {
        if (dg_shadow[i].active && dg_shadow[i].owner == owner &&
            resource_equal(&dg_shadow[i].res, res)) {
            dg_shadow[i].active = false;
            return;
        }
    }
}

/* ─── Remote request processing ─── */

int mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t mode, uint32_t flags,
                                    mxfs_epoch_t request_epoch)
{
    uint32_t bucket;
    struct mxfs_lock *chain, *lk;
    struct mxfs_lock *newlk;
    int compat;

    if (!ctx || !resource || mode >= MXFS_LOCK_MODE_COUNT)
        return -EINVAL;

    /* DLM_TRACE: log remote request entry for inode 128 */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: process_remote_request ENTRY ino=128 "
                     "sender=%u requested_mode=%s flags=0x%x "
                     "local_node=%u",
                     sender, mode_name(mode), flags, ctx->local_node);

    bucket = resource_hash(resource, ctx->bucket_count);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
    chain = ctx->buckets[bucket];

    /* DLM_TRACE: dump all existing holders for inode 128 */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE) {
        int holder_idx = 0;
        for (lk = chain; lk; lk = lk->next) {
            if (resource_equal(&lk->resource, resource))
                mxfs_pal_log(MXFS_LOG_DEBUG,
                    "DLM_TRACE: process_remote_request EXISTING "
                    "ino=128 [%d] owner=%u mode=%s state=%s",
                    holder_idx++, lk->owner,
                    mode_name(lk->mode), state_name(lk->state));
        }
        if (holder_idx == 0)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                "DLM_TRACE: process_remote_request EXISTING "
                "ino=128 (none)");
    }

    /* Check for existing lock from same sender — handle conversion */
    for (lk = chain; lk; lk = lk->next) {
        if (resource_equal(&lk->resource, resource) &&
            lk->owner == sender) {
            if (lk->state == MXFS_LSTATE_WAITING ||
                lk->state == MXFS_LSTATE_BLOCKED) {
                /* Stale entry from a previous timed-out request.
                 * The remote node's pending_wait expired and it
                 * retried, but we still have the old WAITING lock.
                 * Remove it and fall through to re-queue fresh. */
                uint8_t old_state = lk->state;
                struct mxfs_lock **pp = &ctx->buckets[bucket];
                while (*pp) {
                    if (*pp == lk) {
                        *pp = lk->next;
                        lock_free(lk);
                        ctx->lock_count--;
                        break;
                    }
                    pp = &(*pp)->next;
                }
                chain = ctx->buckets[bucket];
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "dlm: removed stale %s entry for "
                             "node %u on retry",
                             state_name(old_state), sender);
                goto remote_check_compat;
            }
            if (lk->state == MXFS_LSTATE_GRANTED) {
                /* Bug 51: always verify the existing grant is safe
                 * before taking the "already granted" shortcut.
                 *
                 * Race condition: the sender's LOCK_REQ can arrive at
                 * the master BEFORE a preceding LOCK_RELEASE when
                 * mxfs_dlm_unlock (BAST handler, recv thread) and
                 * mxfs_dlm_lock (new request, main thread) race for
                 * the peer send_lock. When the LOCK_REQ arrives first,
                 * the master finds the sender's OLD GRANTED entry and
                 * returns "already granted" without checking for
                 * conflicts. The subsequent LOCK_RELEASE removes the
                 * old entry, leaving the master with no record of the
                 * sender's grant while the sender believes it has EX
                 * — both nodes hold EX simultaneously and BASTs stop.
                 *
                 * Fix: check that no other node has a conflicting
                 * GRANTED lock AND no other node has a WAITING/BLOCKED
                 * request. The WAITING check catches the common case:
                 * another node requested the lock, got queued behind
                 * the sender's old grant, and is waiting for the BAST
                 * release cycle. Sending "already granted" would
                 * short-circuit that cycle, leaving both nodes with
                 * effective EX access. */
                if (lk->mode >= mode) {
                    /*
                     * sess-tcp DOUBLE-GRANT FIX (replaces the Bug-51
                     * still_safe re-affirm + the stale-removal+promote
                     * branch).  The sender ALREADY HOLDS a grant of
                     * sufficient mode.  This re-request is its -ETIMEDOUT
                     * retry (the original grant was slow), or a re-acquire
                     * whose LOCK_REQ raced ahead of its LOCK_RELEASE.  The
                     * OLD code removed the holder's entry and promoted a
                     * conflicting waiter whenever a waiter existed — but
                     * the holder did NOT release (it has the grant cached),
                     * so promoting the waiter created a SECOND EX holder:
                     * the PROVEN tcp_dlm_scaling double-grant.
                     *
                     * Correct behaviour: ALWAYS RE-AFFIRM — keep the
                     * holder's entry, stamp a FRESH generation (a new grant
                     * episode), and re-send the grant.  NEVER remove +
                     * promote a waiter here.  Any waiter stays queued with
                     * its BAST and is promoted only when the holder
                     * genuinely releases (process_remote_release).
                     *
                     * Bug-51 (release-in-flight) stays fixed by the gen:
                     * if the sender had released the OLD grant and is
                     * re-acquiring, the stale LOCK_RELEASE that follows
                     * carries the OLD gen; process_remote_release ignores
                     * it on gen-mismatch, so it can neither drop this
                     * re-affirmed entry nor promote a conflicting waiter.
                     */
                    uint32_t gen = lk->grant_gen = dlm_next_gen(ctx);
                    uint8_t reaff_mode = lk->mode;
                    struct mxfs_bast_record pg_rec;
                    int pg = collect_grantee_bast_if_waiters(
                        chain, resource, sender, reaff_mode, &pg_rec);
                    uint8_t ho = 0;
                    uint32_t de = 0;
                    P_LKT("REAFFIRM-REMOTE", resource, sender, lk->mode);
                    if (lk->mode == MXFS_LOCK_EX) {
                        ho = lk->handoff =
                            dg_grant_ex(ctx, resource, sender, gen, &de);
                        lk->dir_epoch = de;
                    }
                    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                    send_grant(ctx, sender, resource, reaff_mode,
                               0, MXFS_MSG_LOCK_GRANT,
                               request_epoch, gen, ho, de);
                    if (pg) {
                        pr_warn_ratelimited(
                            "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u mode=%s site=remote-reaffirm\n",
                            (unsigned long long)resource->ino,
                            sender, mode_name(reaff_mode));
                        fire_bast_records(ctx, resource, &pg_rec, 1);
                    }
                    return 0;
                }

                /* Upgrade: check compat with others */
                {
                    struct mxfs_lock *other;
                    int conv_compat = 1;

                    for (other = chain; other; other = other->next) {
                        if (other == lk)
                            continue;
                        if (!resource_equal(&other->resource, resource))
                            continue;
                        if (other->state != MXFS_LSTATE_GRANTED)
                            continue;
                        if (!lock_compat[other->mode][mode]) {
                            conv_compat = 0;
                            break;
                        }
                    }
                    if (conv_compat) {
                        uint32_t gen;
                        uint8_t ho = 0;
                        uint32_t de = 0;
                        struct mxfs_bast_record pg_rec;
                        int pg = collect_grantee_bast_if_waiters(
                            chain, resource, sender, mode, &pg_rec);
                        lk->mode = mode;
                        gen = lk->grant_gen = dlm_next_gen(ctx);
                        if (mode == MXFS_LOCK_EX) {
                            ho = lk->handoff =
                                dg_grant_ex(ctx, resource, sender, gen, &de);
                            lk->dir_epoch = de;
                        }
                        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                        send_grant(ctx, sender, resource, mode,
                                   0, MXFS_MSG_LOCK_GRANT,
                                   request_epoch, gen, ho, de);
                        if (pg) {
                            pr_warn_ratelimited(
                                "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u newmode=%s site=remote-upgrade\n",
                                (unsigned long long)resource->ino,
                                sender, mode_name(mode));
                            fire_bast_records(ctx, resource, &pg_rec, 1);
                        }
                        return 0;
                    }
                }
                /* Conversion (upgrade) blocked by another holder.
                 *
                 * sess8/sess12 (2/tcp) DOUBLE-GRANT ROOT (RULE 4 PROVEN via
                 * P-CONVBLK-REMOVE firing at a crash_consistency failure):
                 * the OLD code REMOVED the sender's GRANTED entry here and
                 * re-queued it as a fresh WAITING request — but the sender
                 * still LOCALLY holds the old (lower) grant (it requested an
                 * UPGRADE, it did NOT release).  Removing the table entry makes
                 * the sender INVISIBLE as a holder: a different node's
                 * subsequent request scans only GRANTED entries (compat checks
                 * skip non-GRANTED), sees no conflict, and is granted a
                 * conflicting mode -> two nodes hold incompatible grants ->
                 * the stale-read / dir lost-update.
                 *
                 * sess12 FIX: KEEP the sender's GRANTED entry (it stays visible
                 * as a conflict, so no peer can be granted an incompatible mode
                 * behind its back) and DENY the upgrade with
                 * MXFS_ERR_UPGRADE_CONFLICT.  The sender maps that to -EDEADLK,
                 * and the XFS ilock layer (P109) drops its lower grant THROUGH
                 * the BAST drain pipeline (releasing it in sync with the table)
                 * and re-acquires the target mode FRESH via the clean FIFO
                 * path — no invisible-holder window, no conversion deadlock.
                 * Scoped to INODE resources (where the P109 -EDEADLK handling
                 * lives); other types keep the legacy remove+requeue. */
                if (resource->type == MXFS_LTYPE_INODE) {
                    pr_warn_ratelimited(
                        "mxfs: P-CONVBLK-DENY sender=%u ino=%llu held_mode=%s req_mode=%s (keep grant; deny->EDEADLK)\n",
                        sender, (unsigned long long)resource->ino,
                        mode_name(lk->mode), mode_name(mode));
                    mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                    send_grant(ctx, sender, resource, MXFS_LOCK_NL,
                               MXFS_ERR_UPGRADE_CONFLICT, MXFS_MSG_LOCK_DENY,
                               request_epoch, 0, 0, 0);
                    return 0;
                }
                pr_warn_ratelimited(
                    "mxfs: P-CONVBLK-REMOVE sender=%u type=%u ino=%llu held_mode=%s req_mode=%s\n",
                    sender, resource->type,
                    (unsigned long long)resource->ino,
                    mode_name(lk->mode), mode_name(mode));
                {
                    struct mxfs_lock **pp = &ctx->buckets[bucket];
                    while (*pp) {
                        if (*pp == lk) {
                            *pp = lk->next;
                            lock_free(lk);
                            ctx->lock_count--;
                            break;
                        }
                        pp = &(*pp)->next;
                    }
                }
                chain = ctx->buckets[bucket];
                goto remote_check_compat;
            }
        }
    }

remote_check_compat:
    /* Check compatibility */
    compat = 1;
    for (lk = chain; lk; lk = lk->next) {
        if (!resource_equal(&lk->resource, resource))
            continue;
        if (lk->state != MXFS_LSTATE_GRANTED)
            continue;
        if (!lock_compat[lk->mode][mode]) {
            compat = 0;
            /* DLM_TRACE: log which holder caused incompatibility */
            if (resource->ino == 128 &&
                resource->type == MXFS_LTYPE_INODE)
                mxfs_pal_log(MXFS_LOG_DEBUG,
                    "DLM_TRACE: process_remote_request CONFLICT "
                    "ino=128 sender=%u req_mode=%s vs "
                    "holder owner=%u mode=%s",
                    sender, mode_name(mode),
                    lk->owner, mode_name(lk->mode));
            /* P1-AGCONFLICT (RULE 4, master-side attribution for the
             * P36-RETRY type=3 stalls): name the GRANTED holder that
             * blocks an AG request, so the stall's holder node is
             * identifiable in default runs.  Ratelimited; AG requests
             * only conflict under real contention. */
            if (resource->type == MXFS_LTYPE_AG)
                pr_warn_ratelimited(
                    "mxfs: P1-AGCONFLICT ag=%u sender=%u req=%s holder=%u hmode=%s hstate=%d nq=%d\n",
                    resource->ag_number, sender, mode_name(mode),
                    lk->owner, mode_name(lk->mode), lk->state,
                    !!(flags & MXFS_LKF_NOQUEUE));
            break;
        }
    }

    /* sess6(a16ec5f2) arrival-time FIFO barrier: do not grant past an
     * older conflicting waiter (see find_conflicting_waiter). */
    if (compat) {
        struct mxfs_lock *cw = find_conflicting_waiter(chain, resource,
                                                       sender, mode);
        if (cw) {
            static atomic_t p6fr_n = ATOMIC_INIT(0);
            compat = 0;
            if (atomic_inc_return(&p6fr_n) <= 60000)
                pr_warn("mxfs: P6-FAIRQ site=remote ino=%llu type=%u ag=%u req=%s sender=%u behind waiter=%u wmode=%s wage_ms=%llu nq=%d\n",
                        (unsigned long long)resource->ino,
                        resource->type, resource->ag_number,
                        mode_name(mode), sender,
                        cw->owner, mode_name(cw->mode),
                        (unsigned long long)(cw->queued_at ?
                            mxfs_pal_time_ms() - cw->queued_at : 0),
                        !!(flags & MXFS_LKF_NOQUEUE));
        }
    }

    /* DLM_TRACE: log compat result for inode 128 */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: process_remote_request COMPAT_RESULT "
                     "ino=128 compat=%d sender=%u mode=%s",
                     compat, sender, mode_name(mode));

    if (!compat && (flags & MXFS_LKF_NOQUEUE)) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        send_grant(ctx, sender, resource, MXFS_LOCK_NL,
                   MXFS_ERR_DEADLOCK, MXFS_MSG_LOCK_DENY,
                   request_epoch, 0, 0, 0);
        return -EAGAIN;
    }

    if (!compat && (flags & MXFS_LKF_TRYLOCK)) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        send_grant(ctx, sender, resource, MXFS_LOCK_NL,
                   MXFS_ERR_DEADLOCK, MXFS_MSG_LOCK_DENY,
                   request_epoch, 0, 0, 0);
        return -EWOULDBLOCK;
    }

    /* Allocate and insert */
    newlk = lock_alloc(resource, sender, mode,
                       compat ? MXFS_LSTATE_GRANTED : MXFS_LSTATE_WAITING,
                       flags);
    if (!newlk) {
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        return -ENOMEM;
    }

    /* Store requester's epoch so waiter promotions echo it back.
     * Bug 106: nodes observe different membership change counts,
     * so master and requester epochs may differ. */
    newlk->request_epoch = request_epoch;
    newlk->next = ctx->buckets[bucket];
    ctx->buckets[bucket] = newlk;
    ctx->lock_count++;

    if (compat) {
        uint32_t gen = newlk->grant_gen = dlm_next_gen(ctx);
        uint8_t ho = 0;
        uint32_t de = 0;
        struct mxfs_bast_record pg_rec;
        int pg;
        /* DLM_TRACE: remote request granted immediately */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: process_remote_request GRANT_IMMEDIATE "
                         "ino=128 sender=%u mode=%s",
                         sender, mode_name(mode));
        P_LKT("GRANT-REMOTE", resource, sender, mode);
        if (mode == MXFS_LOCK_EX) {
            ho = newlk->handoff = dg_grant_ex(ctx, resource, sender, gen, &de);
            newlk->dir_epoch = de;
        }
        /* sess35 ROOT FIX (see local-immediate): this immediate grant may JUMP
         * an older conflicting WAITING entry (the grantee released its lower
         * grant then re-requested EX from NL, racing ahead of the waiter's
         * promotion).  Fire a BAST to the grantee so it releases for the
         * stranded waiter instead of the waiter stalling the full 6000ms. */
        pg = collect_grantee_bast_if_waiters(ctx->buckets[bucket], resource,
                                             sender, mode, &pg_rec);
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        send_grant(ctx, sender, resource, mode,
                   MXFS_OK, MXFS_MSG_LOCK_GRANT, request_epoch, gen, ho, de);
        if (pg) {
            pr_warn_ratelimited(
                "mxfs: P35-POSTGRANT-BAST ino=%llu grantee=%u newmode=%s site=remote-immediate\n",
                (unsigned long long)resource->ino,
                sender, mode_name(mode));
            fire_bast_records(ctx, resource, &pg_rec, 1);
        }
        return 0;
    }

    /* DLM_TRACE: remote request queued, collecting BAST targets */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: process_remote_request QUEUED_WAITING "
                     "ino=128 sender=%u mode=%s",
                     sender, mode_name(mode));

    /* Capture BAST targets into snapshot array while under
     * table_rwlock.  Must NOT iterate live lock entries via work_next
     * after releasing the lock — concurrent releases from fast holders
     * corrupt the work_next chain at 3+ nodes. */
    {
        struct mxfs_bast_record rr_bast_recs[MXFS_MAX_BAST_RECORDS];
        int rr_bast_count = 0;

        for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
            if (!resource_equal(&lk->resource, resource))
                continue;
            if (lk->state != MXFS_LSTATE_GRANTED)
                continue;
            if (!lock_compat[lk->mode][mode]) {
                if (rr_bast_count < MXFS_MAX_BAST_RECORDS) {
                    rr_bast_recs[rr_bast_count].owner = lk->owner;
                    rr_bast_recs[rr_bast_count].requested_mode = mode;
                    rr_bast_count++;
                }
            }
        }

        /* DLM_TRACE: log BAST target count for ino 128 */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "DLM_TRACE: process_remote_request "
                         "BAST_TARGETS ino=128 count=%d sender=%u",
                         rr_bast_count, sender);

        /* sess35 P37: a remote request queued WAITING for the contended dir;
         * bast_targets=0 here would mean NO holder was told to release (the
         * waiter would stall to timeout). */
        if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
            pr_warn_ratelimited(
                "mxfs: P37-RREQ-QUEUE ino=131 sender=%u mode=%s bast_targets=%d\n",
                sender, mode_name(mode), rr_bast_count);

        mxfs_pal_rwlock_unlock(ctx->table_rwlock);

        /* Fire deferred BASTs from snapshot */
        fire_bast_records(ctx, resource, rr_bast_recs, rr_bast_count);
    }

    return -EINPROGRESS;
}

int mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_resource_id *resource,
                                  uint8_t mode, int status,
                                  mxfs_epoch_t grant_epoch,
                                  uint32_t grant_gen,
                                  uint8_t handoff,
                                  uint32_t dir_epoch)
{
    bool matched;
    bool have_mirror = false;
    bool inserted_provisional = false;

    if (!ctx || !resource)
        return -EINVAL;

    /*
     * sess1 (ccloop a16ec5f2) ROOT FIX — GRANT-EPOCH VISIBILITY ORDER
     * (RULE 4 PROVEN, run5 r23 node4_f1.md5 clobber): the OLD order
     * signaled the pending waiter FIRST and reconciled the local mirror
     * (which stores dir_epoch) AFTER.  The woken acquirer's first dir
     * modify then read mxfs_v5_dlm_inode_dir_epoch()==0 (P2-EPOCHPLACE
     * master_ep=0 unestablished=1 at the exact collide), so EVERY
     * epoch-gated dir coherence guard (addname epoch refresh,
     * prior-tenure evict, tenure-stale bypass) was INERT for the first
     * op(s) after a cross-node EX handoff -> stale-base RMW -> durable
     * peer-dirent clobber (P13-COLLIDE our=[node6_f2]
     * disk=[node4_f1.md5] at the same aoff).  Reconcile the mirror
     * BEFORE signaling so the epoch is visible the moment the waiter
     * wakes.  For a first grant (no existing mirror) insert the mirror
     * provisionally; if the signal then finds NO pending request
     * (unsolicited re-affirm), remove it again and send the
     * gen-stamped reject-release exactly as before — the µs-scale
     * provisional window is harmless because no FS-layer path believes
     * it holds this resource (nothing is waiting on it).
     */
    if (status == 0) {
        uint32_t bucket = resource_hash(resource, ctx->bucket_count);
        struct mxfs_lock *lk, *newlk;

        mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

        /* sess-tcp: a re-affirm GRANT for a lock we still hold — UPDATE the
         * existing mirror's gen/mode in place rather than inserting a
         * duplicate (which would leak and confuse the release gen-match). */
        for (lk = ctx->buckets[bucket]; lk; lk = lk->next) {
            if (resource_equal(&lk->resource, resource) &&
                lk->owner == ctx->local_node &&
                (lk->state == MXFS_LSTATE_GRANTED ||
                 lk->state == MXFS_LSTATE_CONVERTING)) {
                if (mode > lk->mode)
                    lk->mode = mode;
                lk->grant_gen = grant_gen;
                lk->handoff = handoff;   /* sess63: cross-node handoff signal */
                /* sess64: monotonic cross-node handoff epoch.  Only advance it
                 * (never let a stray PR grant carrying 0 clobber a higher value
                 * already delivered by an EX handoff). */
                if (dir_epoch > lk->dir_epoch)
                    lk->dir_epoch = dir_epoch;
                have_mirror = true;
                break;
            }
        }

        if (!have_mirror) {
            /* First grant — insert the mirror BEFORE waking the waiter
             * (provisional: removed below if the grant turns out
             * unsolicited). */
            newlk = lock_alloc(resource, ctx->local_node, mode,
                               MXFS_LSTATE_GRANTED, 0);
            if (newlk) {
                newlk->grant_gen = grant_gen;
                newlk->handoff = handoff;  /* sess63 */
                newlk->dir_epoch = dir_epoch;  /* sess64 */
                newlk->next = ctx->buckets[bucket];
                ctx->buckets[bucket] = newlk;
                ctx->lock_count++;
                have_mirror = true;
                inserted_provisional = true;
            }
        }
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
    }

    /* Signal the pending waiter, passing the grant epoch so that
     * stale grants from a previous epoch's master are discarded
     * rather than completing the wrong pending entry (Bug 67).
     * matched == true iff this grant completed a request WE issued. */
    matched = pending_signal_resource(ctx, resource, mode, status,
                                      grant_epoch);

    /* sess35 P37: trace grant receipt for the contended dir.  matched=0 means
     * the grant arrived but completed NO pending request we issued (epoch
     * mismatch / already-timed-out / wrong resource) -> the requester is NOT
     * woken and will sit until its 6000ms ACQUIRE_WAIT_MS timeout+retry. */
    if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
        pr_warn_ratelimited(
            "mxfs: P37-GRANT-RECV ino=131 mode=%s status=%d gen=%u matched=%d\n",
            mode_name(mode), status, grant_gen, matched ? 1 : 0);
    /* sess4(a9a03929) P74: run68 — the master granted a fresh EX the
     * grantee never visibly processed (no local trace; ino!=131 was
     * blind here).  Trace EVERY inode grant receipt: matched=0 with
     * have_mirror=1 is the silent re-affirm ABSORB (mirror updated,
     * nobody woken, no reject sent) — the local/master divergence
     * producer.  Capped. */
    if (resource->type == MXFS_LTYPE_INODE) {
        static atomic_t p74_n = ATOMIC_INIT(0);
        if (atomic_inc_return(&p74_n) <= 8000)
            mxfs_pal_log(MXFS_LOG_WARN,
                "mxfs: P74-GRANT ino=%llu mode=%s status=%d gen=%u matched=%d have_mirror=%d prov=%d",
                (unsigned long long)resource->ino, mode_name(mode),
                status, grant_gen, matched ? 1 : 0,
                have_mirror ? 1 : 0, inserted_provisional ? 1 : 0);
    }
    /* sess5(a16ec5f2): CAPPED receive-side epoch trace — pairs with the
     * capped P51-SENDGRANT.  dir_epoch_rx=0 on an EX here names the message
     * as the loss point; dir_epoch_rx>0 with a later master_ep=0 read names
     * the mirror store/lifecycle (drop-reacquire window). */
    if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE &&
        mode == MXFS_LOCK_EX && status == 0) {
        static atomic_t p5hrx = ATOMIC_INIT(0);
        if ((unsigned)atomic_inc_return(&p5hrx) <= 60000)
            pr_warn("mxfs: P5H-GRANT-EPOCH-RX ino=131 gen=%u dir_epoch_rx=%u handoff=%u have_mirror=%d inserted=%d matched=%d\n",
                    grant_gen, dir_epoch, handoff,
                    have_mirror ? 1 : 0, inserted_provisional ? 1 : 0,
                    matched ? 1 : 0);
    }

    if (status == 0) {
        uint32_t bucket = resource_hash(resource, ctx->bucket_count);

        /* Unwind the provisional first-grant mirror if nothing we issued
         * was waiting for it (unsolicited re-affirm). */
        if (inserted_provisional && !matched) {
            struct mxfs_lock **pp;

            mxfs_pal_rwlock_wrlock(ctx->table_rwlock);
            pp = &ctx->buckets[bucket];
            while (*pp) {
                struct mxfs_lock *lk = *pp;

                if (resource_equal(&lk->resource, resource) &&
                    lk->owner == ctx->local_node &&
                    lk->state == MXFS_LSTATE_GRANTED &&
                    lk->grant_gen == grant_gen) {
                    *pp = lk->next;
                    lock_free(lk);
                    ctx->lock_count--;
                    break;
                }
                pp = &(*pp)->next;
            }
            mxfs_pal_rwlock_unlock(ctx->table_rwlock);
            have_mirror = false;
        }

        if (!have_mirror && !matched) {
            /*
             * sess-tcp DOUBLE-GRANT FIX (receiver half): an UNSOLICITED
             * grant — no pending request of ours AND no held mirror.  This
             * is a re-affirm of our -ETIMEDOUT retry that reached the master
             * AFTER we already got, used, and RELEASED the original grant.
             * Accepting it would resurrect a PHANTOM EX holder (we and the
             * master would both believe we hold, while our FS layer has
             * released) — the conflicting waiter would starve / a second EX
             * holder appears.  REJECT it: send a gen-stamped LOCK_RELEASE so
             * the master drops the phantom entry and promotes the real
             * waiter.  Harmless if the master already moved on (gen-checked
             * there too). */
            mxfs_node_id_t master = mxfs_dlm_resource_master(ctx, resource);

            P_LKT("GRANT-REJECT-UNSOLICITED", resource, ctx->local_node, mode);
            if (master != ctx->local_node && ctx->send_cb) {
                struct mxfs_dlm_lock_release rel;
                memset(&rel, 0, sizeof(rel));
                rel.hdr.magic = MXFS_DLM_MAGIC;
                rel.hdr.version = MXFS_DLM_VERSION;
                rel.hdr.type = MXFS_MSG_LOCK_RELEASE;
                rel.hdr.length = sizeof(rel);
                rel.hdr.sender = ctx->local_node;
                rel.hdr.target = master;
                rel.hdr.epoch = ctx->current_epoch;
                rel.resource = *resource;
                rel.grant_gen = grant_gen;
                ctx->send_cb(ctx, master, &rel, sizeof(rel));
            }
        }
    }

    return 0;
}

int mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_resource_id *resource,
                                    uint32_t grant_gen)
{
    uint32_t bucket;
    struct mxfs_lock **pp;
    struct mxfs_lock *found = NULL;
    struct mxfs_lock *grants;
    struct mxfs_bast_record post_bast_recs[MXFS_MAX_BAST_RECORDS];
    int post_bast_count = 0;

    if (!ctx || !resource)
        return -EINVAL;

    /* DLM_TRACE: log remote release entry */
    if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "DLM_TRACE: process_remote_release ENTRY ino=128 "
                     "sender=%u local_node=%u",
                     sender, ctx->local_node);

    bucket = resource_hash(resource, ctx->bucket_count);

    mxfs_pal_rwlock_wrlock(ctx->table_rwlock);

    /* Find and remove */
    pp = &ctx->buckets[bucket];
    while (*pp) {
        struct mxfs_lock *lk = *pp;

        if (resource_equal(&lk->resource, resource) &&
            lk->owner == sender &&
            (lk->state == MXFS_LSTATE_GRANTED ||
             lk->state == MXFS_LSTATE_CONVERTING)) {
            /*
             * sess-tcp DOUBLE-GRANT FIX: ignore a STALE release.  If the
             * holder re-acquired (a NEWER grant gen was issued by a
             * re-affirm) since this release was sent, the release carries
             * an OLD gen.  Removing the entry + promoting a waiter now would
             * grant a SECOND EX holder while the sender still believes it
             * holds the re-affirmed grant (Bug-51).  Keep the entry; the
             * sender's CURRENT-gen release will arrive and free it properly.
             * gen==0 on either side falls back to unconditional removal so
             * a pre-gen message can never wedge a lock.
             */
            if (grant_gen != 0 && lk->grant_gen != 0 &&
                lk->grant_gen != grant_gen) {
                P_LKT("REMOTE-RELEASE-STALEGEN", resource, sender, lk->mode);
                if (resource->ino == 131 &&
                    resource->type == MXFS_LTYPE_INODE)
                    pr_warn_ratelimited(
                        "mxfs: P37-RREL-STALEGEN ino=131 sender=%u relgen=%u lkgen=%u (release dropped, NO promote)\n",
                        sender, grant_gen, lk->grant_gen);
                /* sess5(a16ec5f2): AG twin — a dropped AG release wedges
                 * the AG for every peer (run31: AG-0 EX starve 120s →
                 * create -110 → dirty-cancel shutdown).  Name it. */
                if (resource->type == MXFS_LTYPE_AG)
                    pr_warn_ratelimited(
                        "mxfs: P5R-AGREL-STALEGEN ag=%u sender=%u relgen=%u lkgen=%u (release dropped, NO promote)\n",
                        resource->ag_number, sender, grant_gen,
                        lk->grant_gen);
                mxfs_pal_rwlock_unlock(ctx->table_rwlock);
                return 0;
            }
            /* DLM_TRACE: log which entry is being released */
            if (resource->ino == 128 &&
                resource->type == MXFS_LTYPE_INODE)
                mxfs_pal_log(MXFS_LOG_DEBUG,
                    "DLM_TRACE: process_remote_release FOUND ino=128 "
                    "sender=%u mode=%s state=%s",
                    sender, mode_name(lk->mode),
                    state_name(lk->state));
            *pp = lk->next;
            found = lk;
            ctx->lock_count--;
            P_LKT("REMOTE-RELEASE", resource, sender, lk->mode);
            dg_release(resource, sender);
            break;
        }
        pp = &lk->next;
    }

    if (!found) {
        P_LKT("REMOTE-RELEASE-ENOENT", resource, sender, 0);
        if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE)
            pr_warn_ratelimited(
                "mxfs: P37-RREL-ENOENT ino=131 sender=%u (no GRANTED entry; NO promote)\n",
                sender);
        if (resource->type == MXFS_LTYPE_AG)
            pr_warn_ratelimited(
                "mxfs: P5R-AGREL-ENOENT ag=%u sender=%u (no GRANTED entry; NO promote)\n",
                resource->ag_number, sender);
        /* DLM_TRACE: log ENOENT for ino 128 */
        if (resource->ino == 128 && resource->type == MXFS_LTYPE_INODE)
            mxfs_pal_log(MXFS_LOG_DEBUG,
                "DLM_TRACE: process_remote_release ENOENT ino=128 "
                "sender=%u (no GRANTED entry)",
                sender);
        /* Bug 51: do NOT fall back to removing WAITING/BLOCKED entries.
         *
         * When LOCK_REQ arrives before LOCK_RELEASE due to the
         * send_lock ordering race, process_remote_request detects
         * the stale grant, removes it, and creates a fresh WAITING
         * entry. The subsequent LOCK_RELEASE finds no GRANTED entry.
         * If we removed the WAITING entry here, the sender's new
         * lock request would be silently destroyed — it would never
         * get promoted, and the sender's pending_wait would time out.
         *
         * The LOCK_RELEASE with no matching GRANTED entry is harmless:
         * it means the entry was already cleaned up. Return -ENOENT
         * and let promote_waiters handle the WAITING entry when the
         * conflicting holder releases via BAST. */
        mxfs_pal_rwlock_unlock(ctx->table_rwlock);
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "dlm: LOCK_RELEASE from node %u — no GRANTED "
                     "entry found (likely already removed by stale "
                     "re-request handling)",
                     sender);
        return -ENOENT;
    }

    lock_free(found);

    /* Promote waiters */
    grants = promote_waiters(ctx, ctx->buckets[bucket], resource);

    /* sess35 P37: trace the release->promote outcome for the contended dir
     * (ino 131).  If a 6s P34-ACQ-SLOW waiter exists but promoted=0 here, the
     * release isn't promoting it (waiter not visible / FIFO-blocked). */
    if (resource->ino == 131 && resource->type == MXFS_LTYPE_INODE) {
        int p37n = 0; struct mxfs_lock *p37w;
        for (p37w = grants; p37w; p37w = p37w->work_next) p37n++;
        pr_warn_ratelimited("mxfs: P37-RREL ino=131 sender=%u promoted=%d\n",
                            sender, p37n);
    }
    /* sess5(a16ec5f2): AG release visibility at the master. */
    if (resource->type == MXFS_LTYPE_AG) {
        int p5n = 0; struct mxfs_lock *p5w;
        for (p5w = grants; p5w; p5w = p5w->work_next) p5n++;
        pr_warn_ratelimited("mxfs: P5R-AGREL ag=%u sender=%u promoted=%d\n",
                            resource->ag_number, sender, p5n);
    }

    /* Dispatch grants under lock -- we are the master for this resource,
     * so dispatch to local pending and remote nodes directly */
    if (grants) {
        struct mxfs_lock *wk;

        for (wk = grants; wk; wk = wk->work_next) {
            if (wk->mode == MXFS_LOCK_EX)
                wk->handoff = dg_grant_ex(ctx, &wk->resource, wk->owner,
                                          wk->grant_gen, &wk->dir_epoch);
            if (wk->owner == ctx->local_node)
                pending_signal_resource(ctx, &wk->resource,
                                        wk->mode, 0, 0);
            else
                send_grant(ctx, wk->owner, &wk->resource,
                           wk->mode, MXFS_OK, MXFS_MSG_LOCK_GRANT,
                           wk->request_epoch, wk->grant_gen, wk->handoff,
                           wk->dir_epoch);
        }
    }

    /* sess36 (ccloop) ROOT FIX of the dir_reuse 2/tcp residual ~6s stall:
     * collect_post_promotion_basts MUST run even when promote_waiters granted
     * nothing (promoted=0).  A waiter can be left BLOCKED behind a holder that
     * re-acquired ahead of it (a remote re-request jumping an older local
     * waiter): promote_waiters marks it BLOCKED and returns NULL, so the old
     * `if (grants)` guard skipped the BAST collection entirely and NO BAST was
     * fired to the holder — the waiter then stranded the full 6000ms
     * ACQUIRE_WAIT until its own retry re-fired the BAST (PROVEN: P37-RREL
     * promoted=0, a ~6.3s gap, then P34-ACQ-SLOW dur_ms~6300).  We are the
     * master here, so always re-evaluate blocked waiters and BAST their
     * conflicting holders.  collect_post_promotion_basts returns NULL when no
     * BLOCKED waiter exists, so this adds no spurious BASTs in the common
     * (no-waiter) release. */
    {
        struct mxfs_lock *wk;
        struct mxfs_lock *post_basts;
        uint8_t blocked_mode = MXFS_LOCK_NL;

        post_basts = collect_post_promotion_basts(
            ctx->buckets[bucket], resource, &blocked_mode);

        for (wk = post_basts; wk; wk = wk->work_next) {
            if (post_bast_count < MXFS_MAX_BAST_RECORDS) {
                post_bast_recs[post_bast_count].owner = wk->owner;
                post_bast_recs[post_bast_count].requested_mode = blocked_mode;
                post_bast_count++;
            }
        }
    }

    mxfs_pal_rwlock_unlock(ctx->table_rwlock);

    /* Fire post-promotion BASTs from snapshot */
    fire_bast_records(ctx, resource, post_bast_recs, post_bast_count);

    return 0;
}
