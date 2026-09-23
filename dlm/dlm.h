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
    /*
     * sess422 (tcp-authority-ledger step 3): the holder's ledger identity
     * and the DURABLE grant id.  Master side: filled at decision time from
     * the LOCK_REQ (owner_inc/slot/req_id), from the ledger after the
     * commit (auth_epoch/grant_seq/lineage).  Holder side (mirror): copied
     * from the LOCK_GRANT so the LOCK_RELEASE carries them back.
     * `imported` = a ledger-backed blocker installed from a page load
     * (no live table history; gen 0; released only by its owner's
     * {node, inc, grant_id} or by the recovery purge).  `decide_gen` = the
     * page-ownership generation the decision was made under; the commit
     * and the delivery both re-check it.
     */
    uint64_t             owner_inc;
    uint16_t             owner_slot;
    bool                 imported;
    uint32_t             req_id;
    /*
     * The logical acquisition this entry serves, as the requester named it
     * (see acq_seq in struct mxfs_dlm_lock_req).  A re-send carrying the
     * same acq_seq, owner_inc and mode is the SAME wait: the entry keeps
     * its place in the chain and keeps queued_at, so its age is the age of
     * the wait rather than the age of the last re-send.
     *
     * acq_bast_ms is when a blocking notification was last fired on this
     * entry's behalf.  A re-send does not fire another one until that is
     * older than the re-fire interval, so a lost notification is still
     * recovered while a one-second re-send cadence cannot turn into a
     * notification storm at a holder that is already draining.
     */
    uint64_t             acq_seq;
    uint64_t             acq_last_ms;   /* last re-send seen for this wait */
    uint64_t             acq_bast_ms;   /* last blocking notification fired */
    uint32_t             acq_retx;      /* re-sends absorbed by this entry */
    uint64_t             auth_epoch;
    uint64_t             grant_seq;
    uint64_t             lineage;
    uint64_t             decide_gen;
    /* sess425: a PENDING_RELEASE whose retirement commit failed (neither
     * durable nor superseded) carries its release identity here and is
     * re-driven by the master's mxfs_dlm_release_retry_tick; 0 = not
     * stuck (the transition that set PENDING_RELEASE is in flight). */
    uint64_t             rel_failed_ms;
    uint32_t             rel_id;
    bool                 rel_remote;
    /*
     * 0.89.0 (D-0977): open-holder marks.  open_op = the mark change this
     * entry's pending release carries (set when it goes PENDING_RELEASE,
     * copied into the transition item).  open_holders / open_snap = the
     * record's mask the master stamped on THIS grant (holder side: from the
     * LOCK_GRANT; master side: from the commit) and whether the entry is an
     * exclusive grant that carries a valid snapshot.
     */
    int8_t               open_op;
    bool                 open_snap;
    uint64_t             open_holders;
    /* sess425: a LOCAL grant just made GRANTED by finalize and not yet
     * claimed by a waiter or a later local request (cleared by both under
     * the table write lock).  If the waiter is gone (budget exhausted while
     * the grant was PENDING_DURABLE) the master releases the orphan itself
     * — the local analogue of the unsolicited-GRANT LOCK_RELEASE. */
    bool                 unclaimed;
    /*
     * A LOCK_CANCEL for this entry's acquisition arrived while its grant
     * was still committing (PENDING_DURABLE).  When the commit lands the
     * grant is retired instead of delivered: the requester has left, and a
     * delivery it might never receive cannot be relied on to bounce it.
     */
    bool                 cancelled;
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
    uint32_t                req_id;         /* sess422: idempotent retry id */
};

/*
 * sess422 (step 3e): a LOCK_RELEASE sent to a remote master that has not
 * been ACKed yet.  The releaser stops using the lock at once but keeps
 * this state — re-sending on a timer (mxfs_dlm_release_retry_tick) — and
 * may not report release / unmount completion until the ACK
 * (mxfs_dlm_wait_release_acks).
 */
struct mxfs_dlm_pending_release {
    struct mxfs_dlm_pending_release *next;
    struct mxfs_resource_id resource;
    uint32_t                rel_id;
    uint32_t                grant_gen;
    uint64_t                auth_epoch;
    uint64_t                grant_seq;
    uint64_t                lineage;
    uint8_t                 mode;
    int8_t                  open_op;    /* 0.89.0: the mark change every re-send carries */
    int                     sends;
    uint64_t                sent_ms;
};

struct mxfs_tauth_ledger;       /* dlm/tauth_ledger.h */

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

/* A grant a wait solicited that arrived between two of its attempts; see
 * the acq[] entry in the context below. */
struct mxfs_dlm_acq_grant {
    uint8_t             have;
    uint8_t             mode;
    uint8_t             handoff;
    uint32_t            grant_gen;
    uint32_t            dir_epoch;
    uint64_t            auth_epoch;
    uint64_t            grant_seq;
    uint64_t            lineage;
    uint64_t            adopted_ms;
};

struct mxfs_dlm_ctx {
    /* Lock hash table */
    struct mxfs_lock    **buckets;
    uint32_t            bucket_count;
    uint32_t            lock_count;
    mxfs_rwlock_t       *table_rwlock;

    /* Node identity */
    mxfs_node_id_t      local_node;

    /* Shutdown flag: when set, remote lock requests fail fast.
     *
     * Set at UNMOUNT and nowhere else.  It is NOT set by the withdrawal path,
     * so it says nothing about a node that has lost its authority over the
     * shared LUN while still mounted — that is what `authority` below is for,
     * and the two must not be conflated: productive acquisitions closing is
     * not the same event as the DLM engine going away. */
    volatile bool        shutting_down;

    /* "Has this incarnation's authority over the shared LUN closed?", asked
     * of the layer above rather than called directly, because this file also
     * builds user-mode against binaries that do not link the disklock.  NULL
     * means nobody is tracking an authority here and there is nothing to
     * lose.  Takes cb_data, like every other callback on this context. */
    int                 (*authority_lost_cb)(void *data);

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

    /* v0.11.78 (D7): view-signature convergence proof.  The wall-clock
     * settle window above is the FALLBACK; the fast path settles as soon
     * as every node in my active view has confirmed (via the lease
     * beacon's piggybacked view signature) that it computes the SAME
     * sorted-membership signature — i.e. mastery (nodes[hash%count]) is
     * provably identical cluster-wide.  my_view_* are written under
     * active_nodes.lock together with the set; peer_views[] entries are
     * written by the lease RX path and read by the settle gate. */
    uint32_t            my_view_count;
    uint64_t            my_view_hash;
    struct {
        mxfs_node_id_t  node_id;    /* 0 = slot empty */
        uint32_t        count;
        uint64_t        hash;
        uint64_t        rx_ms;      /* mxfs_pal_time_ms() at receipt */
    } peer_views[MXFS_MAX_NODES];

    /* Pending remote requests (waiting for remote master grant) */
    struct mxfs_dlm_pending *pending_buckets[MXFS_DLM_PENDING_SIZE];
    mxfs_mutex_t        *pending_lock;

    /* Callbacks */
    mxfs_dlm_grant_cb       grant_cb;
    mxfs_dlm_bast_cb        bast_cb;
    mxfs_dlm_send_cb        send_cb;
    mxfs_dlm_membership_cb  membership_cb;
    void                    *cb_data;
    /*
     * 0.74.0 (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904): is
     * `node` a DEAD member whose journal-slice recovery is terminally
     * blocked on this node's prover (fence unprovable past the bounded
     * series)?  Its grants stay frozen in the master table until a later
     * re-drive proves exclusion, so a request that conflicts with one of
     * them is DENIED (MXFS_ERR_RECOVERY_BLOCKED / -EHOSTDOWN) instead of
     * queued behind it for the whole acquire budget.  Answered from the
     * mount layer's per-slot blocked table; NULL or 0 = not blocked.
     */
    int                     (*recovery_blocked_cb)(void *data,
                                                   mxfs_node_id_t node);
    /*
     * 0.75.28: is `node` a LIVE member — lease valid, identity not retired,
     * recovery neither blocked nor refused?  Answers the acquire path's
     * question once its budget is exhausted: a request queued behind a live
     * master or live holders is waiting on a slow release, not on a
     * coordination failure, so the requester keeps waiting instead of
     * shutting its own mount down.  NULL = no oracle (nothing is live).
     */
    int                     (*node_live_cb)(void *data, mxfs_node_id_t node);
    /*
     * 0.84.2: is the CALLING task's acquire of `resource` at a fallible
     * boundary — a caller audited to fail its operation cleanly instead of
     * waiting (open, getattr, the read path)?  Answered by the mount layer's
     * per-task registry.  The engine uses it for exactly one thing: a task
     * that has been sent a fatal signal leaves the wait with -EINTR at its
     * next one-second attempt boundary, and the classifier above abandons
     * the acquisition by name.  A caller that is not registered is never
     * interrupted, because it cannot unwind.  NULL = nobody is fallible.
     */
    int                     (*acq_fallible_cb)(void *data,
                                               const struct mxfs_resource_id *resource);
    /*
     * 0.75.115: is THIS node's own session poisoned — its log shut down, its
     * heartbeat slot withdrawn, its PR key retained, a survivor still to fence
     * and replay its slice?  While that holds, an incarnation may not release
     * an on-disk grant: the grant is the evidence the survivor's fence-time
     * manifest is sealed from, and a released one comes back 'notheld' against
     * every image the dead incarnation logged under it.
     *
     * The mount layer enforces that at each of its own release wrappers, which
     * is one gate per caller and therefore one gate to forget — the inode FREE
     * path was missed for exactly that reason (D-0945).  This oracle exists so
     * the question can also be asked HERE, at the two primitives every release
     * funnels through, where forgetting is not possible.  NULL = no oracle.
     */
    int                     (*local_poisoned_cb)(void *data);
    /*
     * 0.75.30 (D-TCP-REFUSED-VICTIM-KEEPS-MASTERSHIP-OUT-OF-MASK-RESOURCES-
     * UNAVAILABLE-0910): is `owner` a dead node whose slice replay was
     * TERMINALLY REFUSED?  Such a node leaves the view (its pages are
     * remastered and taken over like a completed recovery's) but its
     * ledger records are NOT retired wholesale: the grants inside its
     * quarantined domain stay frozen for the life of the mount, only the
     * provably out-of-domain ones are purged.  res == NULL asks about the
     * owner alone: 1 = refused (with *slot_out its heartbeat slot, or -1),
     * 0 = not a refused victim.  res != NULL asks about one record of a
     * refused owner: 1 = keep it frozen (inside the domain, or not provably
     * outside it, or FSWIDE), 0 = provably outside, retire it.  NULL =
     * no refusals exist (every purge is unconditional).
     */
    int                     (*refused_owner_cb)(void *data, mxfs_node_id_t owner,
                                                const struct mxfs_resource_id *res,
                                                int *slot_out);

    /*
     * sess422 (tcp-authority-ledger step 3): the durable authority ledger.
     * `ledger_required` is set by the mount layer for a TCP mount on a
     * volume that carries the region (PROTO_GEN 8 requires it); until
     * mxfs_dlm_attach_ledger runs, every grant is REFUSED (activation
     * barrier: no in-memory grant may coexist with EMPTY records).
     * `ledger_gen` is the page-ownership generation: bumped on every
     * membership change (my_view_hash folded with our incarnation), the
     * ledger's owner_gen mirrors it, and every decision records it.
     * `ledger_failed` latches a proven-unrecoverable ledger state (fail
     * stop: no further grants; releases still ACK).
     */
    struct mxfs_tauth_ledger *ledger;
    /* heartbeat-slot -> {node, incarnation} resolver (the disklock table),
     * used to name the owner of an imported shared-holder bit.  0 = the
     * slot has no live tenant (the bit still blocks, owner UNKNOWN). */
    mxfs_node_id_t          (*slot_node_cb)(void *data, int slot, uint64_t *inc_out);
    uint64_t                *page_import_gen;   /* per page: gen last imported */
    /* sess427 (D-0348 step 2): the ROUTING GEOMETRY — the region's page
     * count and hash seed.  Set from the ledger at attach, or explicitly
     * (mxfs_dlm_set_ledger_geometry) for a node that read the region header
     * but holds no active ledger; 0/0 = the minimum geometry, seed 0 (CAW
     * transport / pre-attach).  Every member must route identically. */
    uint32_t                page_count;
    uint64_t                hash_seed;
    bool                    ledger_required;
    volatile bool           ledger_failed;
    uint64_t                local_inc;
    uint16_t                local_slot;
    uint64_t                ledger_gen;
    uint64_t                view_seq;       /* membership changes seen: makes
                                             * ledger_gen MONOTONIC (a view
                                             * flap A->B->A must not reuse
                                             * a generation: harness-proven
                                             * stale cached pages) */
    uint32_t                req_id_next;
    uint32_t                rel_id_next;
    /* recovery-purged owners: a record whose owner is here is retired on
     * page load instead of imported (dead ids never return, sess11). */
    struct { mxfs_node_id_t node; int slot; } purged_owners[MXFS_MAX_NODES];
    int                     purged_owner_count;
    /*
     * 0.84.5 (D-...-0960): incarnations a bulk takeover was asked to take
     * over by name (mxfs_dlm_handoff_takeover).  Keyed by {node, inc}, not
     * by node id, because one of them is this node's OWN previous
     * incarnation — the settled predecessor whose pages the takeover-only
     * pass moves — and marking that node id purged would retire this
     * incarnation's records too.  dlm_authority_dead answers true for
     * them, so a request on one of their pages is served on demand ahead
     * of the pass instead of parking for the whole pass.
     */
    struct { mxfs_node_id_t node; uint64_t inc; } settled_auth[MXFS_MAX_NODES];
    int                     settled_auth_count;
    /*
     * 0.84.5 (D-...-0960): monotonic count of page takeovers this node has
     * completed (prepared to their owner, activated when the owner is us),
     * counted once per page at the end of the per-page transaction, by
     * every path (bulk, orphan sweep, on demand).  It is the progress a
     * request parked on a page in transition watches: answered to remote
     * requesters in LOCK_DENY grant_gen and in NOT_OWNER prepared_seq.
     * transition_progress_rx is the highest value a bootstrap has relayed
     * to this node.
     */
    uint64_t                takeover_pages_done;
    uint64_t                transition_progress_rx;
    uint64_t                transition_answers;     /* AUTH_TRANSITION denies sent */
    /*
     * 0.75.20 (D-...-0909): members that have announced a clean departure
     * (a FROZEN hand-off flagged MXFS_HANDOFF_F_DEPARTING) but whose
     * goodbye has not yet dropped them from the view.  Hand-off routing
     * (the eager pass, the FROZEN receiver's serve-or-relay decision, the
     * hand-off re-check) maps pages over the view WITHOUT them — the same
     * mapping the departing node used — so a page it handed us is served
     * here instead of relayed straight back to it.  Written and read under
     * active_nodes.lock; an entry is dropped when its node leaves the view.
     * `departing` is the local node's own state, set for the departure
     * hand-off pass so its FROZENs carry the flag.
     */
    struct { mxfs_node_id_t node; uint64_t inc; } departing_nodes[MXFS_MAX_NODES];
    int                     departing_count;
    bool                    departing;
    /* The SEAL CUT of the fence-time manifest (TCP replay authority): an
     * owner listed here has been fenced and its ledger records are being
     * (or have been) collected as the replay gate's authority.  Its late
     * releases are refused, so the sealed authority cannot change between
     * the seal and the replay verdict; the recovery purge is the only
     * retirement and clears the entry (mxfs_dlm_purge_node). */
    struct { mxfs_node_id_t node; uint64_t inc; } sealed_owners[MXFS_MAX_NODES];
    int                     sealed_owner_count;
    uint64_t                sealed_releases_refused;
    /* sess425 (D-0342): owners whose ledger purge did NOT complete (a page
     * commit failed or the view moved mid-walk).  Their imported blockers
     * stay in the table — they mirror the bits still on the platter — and
     * the MASTER re-runs the purge from mxfs_dlm_release_retry_tick over
     * the pages it masters NOW until a whole pass returns 0. */
    struct { mxfs_node_id_t node; int slot; uint64_t since_ms; int rc; }
                            purge_pending[MXFS_MAX_NODES];
    int                     purge_pending_count;
    uint64_t                ledger_purge_partial, ledger_purge_redrives;
    /* sess425 instrumentation: which dlm_lock_impl site answered
     * MXFS_DLM_RETRY (index = site, see dlm_retry()); the exhaustion
     * message prints the tally so 'failed after 10 retries' names its
     * cause. */
    uint32_t                retry_why[11];  /* sess426: [10] = ledger capacity wait */
    /* un-ACKed releases (holder side) */
    struct mxfs_dlm_pending_release *rel_pending;
    mxfs_mutex_t            *rel_lock;
    /*
     * REQUESTER SIDE: cancellations sent and not yet acknowledged, retried
     * on the release retry tick and given up after the same number of sends
     * as a release.  Under rel_lock.  Owned by the engine, never by the task
     * that abandoned the wait: cleanup must not depend on that task still
     * existing.
     */
    struct mxfs_dlm_pending_cancel {
        struct mxfs_dlm_pending_cancel *next;
        struct mxfs_resource_id resource;
        uint64_t                acq_seq;
        uint64_t                sent_ms;
        uint32_t                cancel_id;
        uint8_t                 mode;
        int                     sends;
    } *cancel_pending;
    uint32_t                cancel_id_next;
    uint64_t                cancel_sent;     /* first sends */
    uint64_t                cancel_resends;
    uint64_t                cancel_acked;
    uint64_t                cancel_unacked;  /* given up after max sends */
    /*
     * MASTER SIDE: acquisitions whose sender abandoned them, so that a
     * re-send of one that was still in flight — or replayed by a transport
     * reconnect — cannot recreate the waiter or take a grant nobody will
     * install.  On a single TCP stream a re-send cannot overtake the CANCEL
     * that follows it, so this ring is the belt for the reconnect case, not
     * the ordering.  Count-bounded, oldest overwritten; under table_rwlock.
     */
#define MXFS_DLM_CANCEL_TOMBS 64
    struct {
        mxfs_node_id_t          sender;
        uint64_t                owner_inc;
        uint64_t                acq_seq;
        uint64_t                ms;
    } cancel_tomb[MXFS_DLM_CANCEL_TOMBS];
    uint32_t                cancel_tomb_next;
    /*
     * 0.84.13, MASTER SIDE: acquisitions whose grant this master saw the
     * sender CONSUME and release (LOCK_RELEASE with acq_done), so that a
     * re-send of one that was still in flight when the grant went out is
     * not queued as a fresh request after the release — which minted a
     * second grant for a wait that no longer existed and had the requester
     * bounce it (P958-ACQ-GRANT-BOUNCED, s594c).  Same shape as the cancel
     * ring; larger, because releases are far more frequent than cancels
     * and the window a stale re-send can span is the one-second re-send
     * cadence plus transport latency.
     */
#define MXFS_DLM_CONSUMED_TOMBS 256
    struct {
        mxfs_node_id_t          sender;
        uint64_t                owner_inc;
        uint64_t                acq_seq;
        uint64_t                ms;
    } consumed_tomb[MXFS_DLM_CONSUMED_TOMBS];
    uint32_t                consumed_tomb_next;
    uint64_t                consumed_tomb_added;
    uint64_t                consumed_resend_refused;
    /* TEST ONLY (dl_stale_resend_ino): the last LOCK_REQ sent for the named
     * inode, re-sent once after that inode's next LOCK_RELEASE. */
    struct mxfs_dlm_lock_req dbg_stale_req;
    int                     dbg_stale_req_valid;
    uint64_t                cancel_rx;             /* cancels processed */
    uint64_t                cancel_waiters_removed;
    uint64_t                cancel_grants_retired;
    uint64_t                cancel_grants_retiring;
    uint64_t                cancel_absent;
    uint64_t                cancel_resend_refused; /* tombstoned re-sends */
    /* counters (P-TAUTH lines) */
    uint64_t                ledger_grants, ledger_denies, ledger_imports,
                            ledger_ghosts, ledger_remaster, release_acks,
                            release_resends, release_unacked,
                            ledger_late_deliveries, ledger_imports_resolved,
                            /* 0.75.5: a predecessor's shared bit on our own
                             * slot, released at import */
                            ledger_import_residue,
                            /* D-0966: an imported record of this incarnation
                             * adopted by a local request (fresh grant gen) */
                            ledger_imports_adopted,
                            /* 0.89.0 (D-0977): open-mark changes applied with
                             * no grant to ride (release found no table entry) */
                            open_mark_only,
                            /* sess425: refused bundles whose release was
                             * re-committed alone / retirements the master
                             * had to re-drive from the tick */
                            ledger_release_recommits, ledger_release_stuck,
                            ledger_release_redrives, ledger_local_orphans;

    /*
     * sess423 (tcp-authority-ledger step 4): ordered page handoff.  A page
     * is decided on ONLY while page_state == DLM_PS_MINE and the ledger's
     * cached image says ACTIVE(self); every other state parks the decision
     * (-EAGAIN -> RETRY / REMASTER, fail closed).  Arrays are per page,
     * protected by table_rwlock (write) for state changes.
     *   bootstrap_cb   this node holds the LOWEST LIVE heartbeat slot and
     *                  the membership has settled: it may claim UNOWNED
     *                  pages and takes over a departed authority's pages
     *   node_inc_cb    node id -> mount incarnation (0 = unknown) from the
     *                  disklock table; a PREPARED must name the target's
     *                  incarnation
     */
    uint8_t                 *page_state;        /* DLM_PS_* */
    uint64_t                *page_req_ms;       /* last FREEZE_REQ sent */
    bool                    (*bootstrap_cb)(void *data);
    /* sess426 (D-0345): WHO the bootstrap node is (id, incarnation; 0 =
     * unknown), so a non-bootstrap master of an UNOWNED page can ask it to
     * claim-and-hand-over instead of parking forever */
    mxfs_node_id_t          (*bootstrap_node_cb)(void *data, uint64_t *inc_out);
    uint64_t                (*node_inc_cb)(void *data, mxfs_node_id_t node);
    /* 0.75.69 (D-...-0927): is {node, inc} the CURRENT occupant of some
     * heartbeat slot (the disklock table's "who is there now")?  The durable
     * answer to whether a ledger page's authority or prepared target is
     * still alive: a per-mount purged list cannot name the incarnations of
     * eras this mount never saw, and the slot map can. */
    bool                    (*occupant_cb)(void *data, mxfs_node_id_t node,
                                           uint64_t inc);
    /* 0.89.3 (D-0981): is {node, inc} a recovery VICTIM whose slice replay
     * has not yet reached IMAGES_REPLAYED — its ledger records are the
     * evidence the replay's current-safety check judges against the sealed
     * fence-time manifest, and retiring one of them before that judgement
     * is "authority mutated after the seal", a terminal whole-filesystem
     * quarantine.  Dead is not reclaimable: this overrides every dead
     * classification at the takeover choke point (dlm_takeover_page). */
    bool                    (*recovery_judging_cb)(void *data, mxfs_node_id_t node,
                                                   uint64_t inc);
    volatile bool           handoff_scan;       /* eager pass owed */
    /*
     * sess428 (D-0349): an EAGER per-page activation pass was tried here
     * (tick walks every page the view names ours and runs the acquire
     * chain) and REFUTED: in the 12-node usermode ramp it flooded the
     * bootstrap node's serialized FREEZE_REQ handling (formation_test 9
     * fails, -110 lock timeouts) and at the format-v2 geometry (67651
     * pages) it is O(pages) durable writes per view change.  Pages stay
     * lazily acquired; the bootstrap prepares UNOWNED pages in one
     * transition (mxfs_tauth_ledger_prepare_unowned).  See ccmemory
     * docs/rulings/d0349-eager-page-activation.md.
     */
    uint64_t                handoff_reqs, handoff_frozen, handoff_defers,
                            handoff_not_owner, handoff_activations,
                            handoff_prepares, handoff_parked,
                            handoff_takeovers, handoff_retargets,
                            handoff_ondemand,
                            handoff_takeover_interrupted, /* D-0953: bulk passes
                                                           * stopped between pages
                                                           * because this mount
                                                           * began leaving */
                            handoff_decertified,     /* D-0962: bulk passes stopped
                                                      * between pages because a peer
                                                      * joined on a lower slot and is
                                                      * now the certified writer */
                            handoff_refused_leaving,      /* D-0953: FROZEN hand-offs
                                                           * to a leaving mount, left
                                                           * PREPARED for the successor */
                            handoff_stale_targets,   /* 0.75.18: hand-offs refused
                                                      * because the view moved
                                                      * during the freeze drain */
                            handoff_depart_rx;       /* 0.75.20: departure hand-offs
                                                      * received and served */
    /*
     * Queue receipts from remote masters (MXFS_MSG_LOCK_QUEUED).  A master
     * that cannot grant a remote request now queues it and says so; this
     * records WHEN it last said so, per resource, so a requester whose
     * acquire budget is spent can tell "the master has my request and a
     * holder is draining" from "nothing has ever answered me".  Without it
     * the two are the same observation — silence — and the acquire path
     * cannot choose between waiting and giving up.
     *
     * Deliberately per-RESOURCE and not per-request: the pending entry that
     * carries a request id is freed and reallocated on every one-second
     * retry, so a per-request record would have to outlive the thing that
     * names it.  What per-resource costs is precision in ONE direction only
     * — a receipt for another task's acquire of the same inode can make this
     * one look answered — and that direction is the safe one: it can only
     * make a requester keep waiting, never make it give up on a master that
     * is in fact serving it.
     *
     * Small ring, newest wins, no eviction policy beyond age: an entry that
     * is not refreshed simply goes stale and stops counting as evidence.
     */
#define MXFS_DLM_QACK_SLOTS  32
    struct {
        struct mxfs_resource_id resource;
        uint64_t                ms;      /* mxfs_pal_time_ms of arrival */
        mxfs_node_id_t          master;
        uint32_t                req_id;
    } qack[MXFS_DLM_QACK_SLOTS];
    uint32_t                qack_next;
    uint64_t                qack_rx;     /* receipts recorded */

    /*
     * REQUESTER SIDE: the logical acquisitions this node currently has in
     * flight against remote masters, so that every one-second re-send of
     * the same wait carries the same acq_seq.
     *
     * Keyed by RESOURCE, not by task, because that is the granularity the
     * master keys on: two local tasks acquiring one inode produce a single
     * entry in the master's table (it dedups by owner node), so a per-task
     * identity would hand the master two names for one queue entry.
     *
     * An entry is minted when a resource has no live acquisition, reused by
     * every re-send and by every restart of the acquire classifier, and
     * retired when the acquire ends.  ACQ_IDLE_MS is the backstop for a
     * path that ends without retiring: it must comfortably exceed the
     * one-second re-send cadence plus the classifier's longest backoff
     * between restarts (5 s), and must be short enough that a genuinely
     * new acquire minutes later gets a new name.
     *
     * A re-send that asks for a DIFFERENT mode is a different acquisition
     * and mints a new sequence, so one name can never come to mean two
     * different requests.
     */
#define MXFS_DLM_ACQ_SLOTS   64
#define MXFS_DLM_ACQ_IDLE_MS 15000
/*
 * THE STATUS-DELIVERY CONTRACT a remote wait is judged against.  Every
 * re-send (period P = the one-second pending wait) is a status opportunity
 * the master answers with LOCK_QUEUED echoing that attempt's req_id.  D is the
 * allowance for that answer to arrive — an engineering service budget, not a
 * transport guarantee; N is how many consecutive opportunities may go
 * unanswered.  H = N x P + D is the bound after which a still-pending wait
 * whose master is a live member is DEGRADED_UNCONFIRMED.  Neither the 180 s
 * acquire budget nor the receipt-staleness window takes part.
 */
#define MXFS_DLM_ACQ_STATUS_LATENCY_MS 15000   /* D */
#define MXFS_DLM_ACQ_STATUS_MISSES     30      /* N */
/*
 * Outstanding attempt nonces kept per wait.  A receipt is accepted up to D
 * after its attempt was issued, and attempts are issued once per P, so the
 * ring must hold at least D / P of them or a reply that is inside the
 * allowance is rejected because its nonce has already been evicted.  Four
 * held about four seconds of history against a fifteen-second allowance; a
 * design consult named the contradiction.  Sixteen covers D at P with a
 * margin for a burst of attempts around a classifier restart.
 */
#define MXFS_DLM_ACQ_ATTEMPTS          16
/*
 * How often a re-send of a wait the master already has may fire another
 * blocking notification at the holder.  Not zero, because a notification can
 * be lost and re-sends are the only thing that would recover it; not the
 * one-second re-send cadence, because a holder in a long release drain then
 * receives one per second for the whole drain (measured: 238 across one 244 s
 * wait).  Ten seconds bounds the recovery of a lost notification at ten
 * seconds while cutting a 244 s drain's share to ~24.
 */
#define MXFS_DLM_ACQ_BAST_REFIRE_MS 10000
    struct {
        struct mxfs_resource_id resource;
        uint64_t                acq_seq;
        uint64_t                first_ms;  /* immutable first submission */
        uint64_t                last_ms;   /* last re-send */
        uint64_t                bast_ms;   /* last notification fired locally */
        /*
         * The task that opened this record.  RECORDED, NOT KEYED ON — the
         * name is deliberately per resource and mode, because the master
         * models one wait per (resource, sender NODE) and a per-task name
         * would push a second task's re-sends back onto replace-and-requeue
         * and return that shape to one notification per re-send.  This field
         * exists to MEASURE whether two tasks on one node ever share a record
         * at all, which is what decides whether that sharing is worth a
         * design change.  A design consult predicted it matters; nothing has
         * yet observed it here.
         */
        int                     owner_pid;
        uint8_t                 mode;
        uint8_t                 in_use;
        /*
         * DEGRADED_UNCONFIRMED.  A remote master that is a live member and
         * has never receipted this wait is, from here, indistinguishable
         * from one holding the request behind a long drain — except by the
         * receipts it sends.  master and receipt_ms are the evidence; a
         * wait whose re-sends have gone unanswered for acq_degrade_ms since
         * its first submission or its last receipt is marked degraded
         * (degraded_ms), said once in the log, and exported through the
         * mount's debugfs so the stall is visible without the stalled lock.
         * A receipt or a grant clears it.  Nothing here ends the wait: a
         * caller that cannot be failed keeps waiting, and this is how that
         * wait stops being silent.
         */
        mxfs_node_id_t          master;       /* who the attempts went to */
        uint64_t                receipt_ms;   /* arrival of the last ACCEPTED
                                               * confirmation (diagnostic) */
        uint64_t                confirm_ms;   /* ISSUE time of the attempt that
                                               * confirmation answered: the
                                               * absence clock's anchor, so a
                                               * delayed reply cannot buy an
                                               * arbitrary new interval */
        uint64_t                degraded_ms;  /* 0 = not degraded */
        uint32_t                retx;         /* re-sends of this wait */
        uint32_t                rejected;     /* receipts naming no outstanding
                                               * attempt of this wait, or from
                                               * a node that is not its master,
                                               * or later than the allowance */
        /* The outstanding attempts (req_id is the per-attempt nonce the
         * master echoes) with their issue times, recorded BEFORE the send. */
        struct {
            uint32_t            req_id;
            uint64_t            sent_ms;
        } attempt[MXFS_DLM_ACQ_ATTEMPTS];
        uint8_t                 attempt_next;
        /*
         * A GRANT THIS WAIT SOLICITED THAT ARRIVED BETWEEN TWO OF ITS
         * ATTEMPTS.  The requester registers a pending entry only for the
         * one second each attempt waits; between attempts — the 50 ms
         * between descents, and the classifier's backoff of up to five
         * seconds between restarts — there is none, and a grant landing
         * then used to be read as unsolicited: the mirror was unwound, a
         * release bounced it back, the master retired the grant and
         * promoted the next waiter, and this wait's next re-send queued
         * again at the BACK.  The wait solicited that grant; the pending
         * entry is only the attempt's accounting.  So the grant is kept
         * here, with the mirror it already installed in the local table,
         * and the wait's next attempt claims it without sending.  A wait
         * that never comes back for it — retired idle, ended by anything
         * other than the claim — releases it exactly as the bounce did.
         */
        struct mxfs_dlm_acq_grant grant;
    } acq[MXFS_DLM_ACQ_SLOTS];
    /*
     * Its own lock, and always the innermost one.  table_rwlock is a sleeping
     * lock and the LOCAL-master queue path holds it while it needs an
     * acquisition stamp, so this table cannot be protected by table_rwlock
     * without an ordering hazard.  Nothing under this lock sleeps.
     */
    mxfs_spinlock_t         *acq_lock;
    uint64_t                acq_seq_next;
    uint64_t                acq_minted;    /* logical acquisitions started */
    uint64_t                acq_retired;   /* ... ended */
    uint64_t                acq_retx_kept; /* re-sends the master absorbed */
    uint64_t                acq_requeued;  /* re-sends that replaced an entry */
    uint64_t                acq_bast_refire; /* re-fires under the interval */
    /*
     * The three ways this table can lose a live wait's history, each counted
     * separately so the question "does it, here, under a real workload?" has
     * an answer instead of an argument.  All three degrade to the behaviour
     * that predates the table: a fresh name, no backdated queue time, and a
     * notification fired.  None of them can hang or corrupt; they can only
     * stop the fix from helping.
     */
    uint64_t                acq_key_collide; /* record reused by a 2nd task */
    uint64_t                acq_evict_live;  /* in-use record evicted, full */
    uint64_t                acq_idle_live;   /* in-use record retired as idle */
    /* Grants that arrived between two attempts of a live wait. */
    uint64_t                acq_grant_adopted;  /* kept for the wait */
    uint64_t                acq_grant_claimed;  /* taken by its next attempt */
    uint64_t                acq_grant_vanished; /* mirror gone before the claim */
    uint64_t                acq_grant_released; /* no claimant; handed back */
    uint64_t                acq_grant_bounced;  /* no wait at all; bounced */
};

/* page_state */
#define DLM_PS_UNKNOWN   0   /* not examined under this generation */
#define DLM_PS_MINE      1   /* ACTIVE(self): decisions allowed */
#define DLM_PS_FROZEN    2   /* handed off / not ours: no decisions */
#define DLM_PS_WANTED    3   /* the view names us owner; handoff pending */

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

/* 0.74.0: locally-mastered resource granted to a dead node whose recovery is
 * RECOVERY_BLOCKED (see recovery_blocked_cb), or (0.75.21) a resource
 * mastered by such a node.  1 = yes, fail the operation now; 0 = no. */
int mxfs_dlm_resource_held_by_blocked(struct mxfs_dlm_ctx *ctx,
                                      const struct mxfs_resource_id *resource);

/* 0.75.28: after an acquire timed out — is the party it waits on live?  1 when
 * the resource's remote master is a live member (node_live_cb), or, for a
 * locally mastered resource, when it has at least one GRANTED holder and every
 * remote holder is a live member.  0 when there is nothing live to wait for:
 * no holder at all, a dead/blocked/refused holder or master, or no oracle. */
int mxfs_dlm_resource_wait_is_live(struct mxfs_dlm_ctx *ctx,
                                   const struct mxfs_resource_id *resource);

/* Record a master's MXFS_MSG_LOCK_QUEUED receipt for its resource. */
void mxfs_dlm_process_queued_ack(struct mxfs_dlm_ctx *ctx,
                                 mxfs_node_id_t sender,
                                 const struct mxfs_dlm_lock_resp *resp);

/* Has the party this acquire waits on given first-hand evidence that it HAS
 * the request?  1 for a locally mastered resource, whose holder table is read
 * directly; for a remote master, 1 only while a queue receipt newer than
 * stale_ms stands.  0 means the wait rests on membership alone — the master
 * is a live member and has answered this resource with nothing at all. */
int mxfs_dlm_resource_wait_is_receipted(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource,
                                        uint64_t stale_ms);

/*
 * A snapshot of one degraded acquisition (see the acq[] comment): a wait on
 * a remote master that has gone unanswered past acq_degrade_ms.  The struct
 * lives in include/mxfs/mxfs_dlm.h so the xfs overlay's debugfs reader can
 * see it.  Iterate with prev = -1 first; returns the next in-use degraded
 * slot (> prev) with *out filled, or -1 when exhausted.  Times are
 * mxfs_pal_time_ms() stamps.
 */
int mxfs_dlm_acq_degraded_iter(struct mxfs_dlm_ctx *ctx, int prev,
                               struct mxfs_dlm_acq_state *out);
/* How long a remote wait's re-sends may go unanswered before it is degraded;
 * 0 disables the state.  Module parameter acq_degrade_ms. */
extern unsigned int mxfs_dlm_acq_degrade_ms;

int mxfs_dlm_unlock(struct mxfs_dlm_ctx *ctx,
                    const struct mxfs_resource_id *resource);

/* sess7 FIX-20b: mirror-bypassing unconditional (gen=0) LOCK_RELEASE to the
 * remote master — phantom-grant reconcile only (see dlm.c). */
int mxfs_dlm_send_unconditional_release(struct mxfs_dlm_ctx *ctx,
                                        const struct mxfs_resource_id *resource);

/* ccloop c7ee71c6 sess6: guarded orphan-grant NAK — sends the FIX-20b
 * unconditional release ONLY if the local table holds no entry of ANY state
 * for the resource (in-flight acquires block it).  -EBUSY = held locally,
 * nothing sent.  Heals master-side zombie grants left by the
 * membership-change table purge (see dlm.c). */
int mxfs_dlm_release_orphan_if_unheld(struct mxfs_dlm_ctx *ctx,
                                      const struct mxfs_resource_id *resource);

/* Gen-aware release (sess1 ccloop a9a03929): releases ONLY the tenure whose
 * grant_gen == expected_gen.  Returns -ESTALE (touching nothing) if a
 * same-owner GRANTED entry with a different gen owns the resource — i.e. a
 * re-acquire completed during the caller's async release window.
 * expected_gen=0 = unconditional (legacy behavior). */
int mxfs_dlm_unlock_gen(struct mxfs_dlm_ctx *ctx,
                        const struct mxfs_resource_id *resource,
                        uint32_t expected_gen);
/*
 * 0.89.0 (D-0977): the gen-aware release carrying the releaser's open-holder
 * mark change (MXFS_TAUTH_OPEN_*).  The op rides the LOCK_RELEASE to the
 * master and every re-send of it, and the master applies it inside the
 * ledger transition that retires the grant; mxfs_dlm_unlock_gen is this with
 * MXFS_TAUTH_OPEN_NONE.
 */
int mxfs_dlm_unlock_open(struct mxfs_dlm_ctx *ctx,
                         const struct mxfs_resource_id *resource,
                         uint32_t expected_gen, int open_op);
/*
 * 0.89.0 (D-0977): the open-holder mask snapshot the master stamped on the
 * EXCLUSIVE grant this node holds for `resource`.  0 + *oh_out when such a
 * grant is held and carries a snapshot; -EIO when no exclusive grant is held
 * (the caller must not free: it does not hold the authority the snapshot
 * belongs to).  The snapshot is authoritative for the grant's lifetime and
 * only ever too conservative (see struct mxfs_dlm_lock_resp).
 */
int mxfs_dlm_open_holders(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          uint64_t *oh_out);
/* D-0966: adopt-and-release a GRANTED entry of ours that has no generation
 * (an imported ledger record nobody adopted); -ENOENT if there is none. */
int mxfs_dlm_unlock_genless(struct mxfs_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource);

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
/* v0.11.78 (D7): view-signature convergence proof plumbing.
 * get_view_sig is the lease-TX provider (returns my hash, fills count);
 * report_peer_view is fed by the lease RX path with a peer's signature. */
uint64_t mxfs_dlm_get_view_sig(struct mxfs_dlm_ctx *ctx, uint32_t *count);
void mxfs_dlm_report_peer_view(struct mxfs_dlm_ctx *ctx,
                               mxfs_node_id_t node,
                               uint32_t count, uint64_t hash);

int mxfs_dlm_update_active_nodes(struct mxfs_dlm_ctx *ctx,
                                 const mxfs_node_id_t *nodes, int count);
bool mxfs_dlm_is_single_node(struct mxfs_dlm_ctx *ctx);
/* sess-tcp: highest mode THIS node holds for `resource` in its local mirror
 * (GRANTED/CONVERTING entry owned by local_node), or MXFS_LOCK_NL if none.
 * Used to detect a phantom-EX on the TCP transport. */
uint8_t mxfs_dlm_held_mode(struct mxfs_dlm_ctx *ctx,
                           const struct mxfs_resource_id *resource);
/* sess425 diagnostic: table entries on a ledger page still between
 * decision and finalize (PENDING_DURABLE / PENDING_RELEASE) — what a
 * handoff freeze waits on. */
int mxfs_dlm_page_pending_count(struct mxfs_dlm_ctx *ctx, uint32_t page);
/* ccloop c7ee71c6 sess21: atomic-context-safe form of the above.  The
 * table_rwlock is a SLEEPING lock (struct rw_semaphore) in the kernel PAL,
 * so mxfs_dlm_held_mode MUST NOT be called with a spinlock held.  This
 * variant uses the trylock and reports -EWOULDBLOCK instead of scheduling.
 * Callers must treat -EWOULDBLOCK as "cannot tell", never as "not held". */
int mxfs_dlm_held_mode_nb(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          uint8_t *out_mode);
/* 1 = every entry of ours is GRANTED, 0 = none, -EBUSY = one is in flight,
 * -EWOULDBLOCK = table busy.  Never schedules. */
int mxfs_dlm_settled_grant_nb(struct mxfs_dlm_ctx *ctx,
                              const struct mxfs_resource_id *resource);
/* sess61: per-grant generation token THIS node holds for `resource` (highest-mode
 * GRANTED/CONVERTING entry owned by local_node), 0 if none.  Reliable
 * lock-changed-hands signal for the dir-EX fast-path staleness check. */
uint8_t mxfs_dlm_granted_mode(struct mxfs_dlm_ctx *ctx,
                              const struct mxfs_resource_id *resource);
uint32_t mxfs_dlm_grant_gen(struct mxfs_dlm_ctx *ctx,
                            const struct mxfs_resource_id *resource);
/* sess422: durable grant id + lineage of our held grant (false = none). */
bool mxfs_dlm_grant_id(struct mxfs_dlm_ctx *ctx,
                       const struct mxfs_resource_id *resource,
                       uint64_t *auth_epoch, uint64_t *grant_seq,
                       uint64_t *lineage);

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

/* sess422: the requester's ledger identity + request id ride with the
 * request; the grant id + lineage ride with the grant; the release carries
 * everything the ledger validates.  Passed as the wire structs. */
int mxfs_dlm_process_remote_request(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_dlm_lock_req *req);

int mxfs_dlm_process_remote_grant(struct mxfs_dlm_ctx *ctx,
                                  const struct mxfs_dlm_lock_resp *resp);

/* Abandon this node's live wait on a resource: tell the master (LOCK_CANCEL,
 * retried until acknowledged), retire the acquisition record, and release
 * any grant that had been kept for it.  The caller has already decided to
 * fail its operation and installs nothing. */
void mxfs_dlm_acq_abandon(struct mxfs_dlm_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          uint8_t mode);
int mxfs_dlm_process_cancel(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
                            const struct mxfs_dlm_lock_cancel *msg);
void mxfs_dlm_process_cancel_ack(struct mxfs_dlm_ctx *ctx,
                                 const struct mxfs_dlm_cancel_ack *ack);
int mxfs_dlm_process_remote_release(struct mxfs_dlm_ctx *ctx,
                                    mxfs_node_id_t sender,
                                    const struct mxfs_dlm_lock_release *rel);

int mxfs_dlm_process_release_ack(struct mxfs_dlm_ctx *ctx,
                                 const struct mxfs_dlm_release_ack *ack);

/* ─── sess422: durable authority ledger (tcp-authority-ledger step 3) ─── */

/* Activation barrier: the mount layer attaches the opened ledger with this
 * mount's ledger identity BEFORE the first grant.  On a TCP mount with
 * ledger_required set, grants are refused until this runs. */
/* sess427: routing geometry without (or before) an attached ledger. */
void mxfs_dlm_set_ledger_geometry(struct mxfs_dlm_ctx *ctx, uint32_t npages,
                                  uint64_t hash_seed);
void mxfs_dlm_attach_ledger(struct mxfs_dlm_ctx *ctx,
                            struct mxfs_tauth_ledger *ledger,
                            uint64_t local_inc, uint16_t local_slot);

/* Recovery purge (the ONLY event that retires a ledger-backed blocker):
 * clears every record of `node` (exclusive) / `slot` (shared, -1 = none)
 * on the pages this node masters, and drops the matching imported table
 * entries.  Call after the victim is proven fenced and its slice replayed,
 * or after a clean departure.  Returns records cleared or -errno. */
int mxfs_dlm_ledger_purge_owner(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
                                int slot);

/*
 * 0.75.30: the SELECTIVE recovery purge for a terminally refused victim
 * (refused_owner_cb must name it).  Retires, on the pages this node
 * masters, only the records of `node`/`slot` whose resource the callback
 * classifies as provably outside the victim's quarantined domain, and drops
 * the matching table entries (imported blockers and live grants alike),
 * re-evaluating their waiters through the ledger.  The owner is NOT marked
 * purged and its remaining records import as frozen blockers wherever they
 * are met.  Returns records cleared or -errno (a partial walk is reported,
 * never re-driven: the re-drive path is the unconditional purge).
 */
int mxfs_dlm_ledger_purge_owner_selective(struct mxfs_dlm_ctx *ctx,
                                          mxfs_node_id_t node, int slot);
int mxfs_dlm_purge_node_selective(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node);

/*
 * Seal a fenced owner's authority before its fence-time manifest is
 * collected from the ledger (TCP replay authority; the CAW transport needs
 * no seal because a fenced victim can no longer CAS its own slots).  From
 * this call on, a release naming {node, inc} is refused (the releaser is
 * dead; its records stay as blockers until the recovery purge), and the
 * call returns only once no release of that owner is still committing, so
 * the platter image the collector reads is the image the replay gate will
 * re-check.  Idempotent.  0, or -EBUSY when an in-flight release of the
 * owner did not settle within the bound (the caller retries the snapshot).
 */
int mxfs_dlm_seal_owner(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
                        uint64_t inc);

/* ─── sess423: ordered page handoff (tcp-authority-ledger step 4) ─── */

/* Inbound MXFS_MSG_PAGE_HANDOFF (any kind). */
int  mxfs_dlm_process_page_handoff(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t sender,
                                   const struct mxfs_dlm_page_handoff *msg);

/* Periodic driver (call with mxfs_dlm_release_retry_tick): the eager
 * prepare of pages that moved away at the last view change, FREEZE_REQ
 * retries for pages this node wants, retargeting of PREPAREDs whose target
 * was recovery-purged.  Does ledger I/O; never holds the table lock across
 * it. */
void mxfs_dlm_handoff_tick(struct mxfs_dlm_ctx *ctx);

/* The certified successor's takeover of a departed authority's pages
 * (dead: after the fence certificate, BEFORE the lease unregister; clean:
 * on GOODBYE).  Only the node bootstrap_cb names (lowest live slot) may
 * call it: it PREPAREs every page still ACTIVE({node,inc}) to that page's
 * owner under the current view and retargets PREPAREDs aimed at the
 * departed node.  Returns pages prepared, or -errno. */
int  mxfs_dlm_handoff_takeover(struct mxfs_dlm_ctx *ctx, mxfs_node_id_t node,
                               uint64_t inc);

/* Clean departure: freeze + PREPARE every page this node serves to its
 * owner under the view WITHOUT this node, then tell the targets.  Call
 * after release_all, before GOODBYE.  Returns pages left un-prepared
 * (0 = clean; > 0 means the successor's takeover on GOODBYE finishes it). */
int  mxfs_dlm_handoff_depart(struct mxfs_dlm_ctx *ctx);
/* 0.75.69 (D-...-0927): one pass over every ledger page; every page whose
 * authority is dead (no live member carries that incarnation) is taken over
 * to its owner under the view.  Bootstrap node only (-EPERM elsewhere);
 * waits for the membership to settle first.  Returns pages prepared, or
 * -EAGAIN when some were skipped. */
int  mxfs_dlm_takeover_orphans(struct mxfs_dlm_ctx *ctx);

/* Holder-side release bookkeeping: re-send un-ACKed LOCK_RELEASEs older
 * than the retry interval (call from a periodic thread); wait (bounded)
 * for every outstanding ACK — returns the number still un-ACKed. */
void mxfs_dlm_release_retry_tick(struct mxfs_dlm_ctx *ctx);
int  mxfs_dlm_wait_release_acks(struct mxfs_dlm_ctx *ctx, uint64_t timeout_ms);

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
