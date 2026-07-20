/*
 * MXFS — Multinode XFS
 * Mount orchestration and public API implementation
 *
 * Orchestrates filesystem mount/unmount by initializing all subsystems
 * in the correct order, wiring up callbacks between them, and providing
 * the public API functions that frontends call for filesystem operations.
 *
 * Subsystem init order (same as v1 kernel module):
 *   DLM -> peer -> SCSI PR -> disklock -> discovery -> lease ->
 *   journal -> block_cache -> inode_cache -> dir_cache -> alloc
 *
 * Shutdown order (reverse):
 *   discovery -> lease -> journal -> DLM release_all -> disklock ->
 *   dir_cache -> inode_cache -> block_cache -> alloc -> peer ->
 *   SCSI PR -> DLM destroy
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "mount.h"
#include "../include/mxfs/mxfs_ports.h"

/* BAST work queue item — queued by dlm_bast_cb, processed by bast_worker_fn */
struct bast_work_item {
    struct mxfs_resource_id resource;
    mxfs_node_id_t owner;
    uint8_t requested_mode;
    struct bast_work_item *next;
};

/* Default ports (registry: include/mxfs/mxfs_ports.h) */
#define MXFS_DEFAULT_DLM_PORT       MXFS_PORT_DLM
#define MXFS_DEFAULT_DISCOVERY_PORT MXFS_PORT_DISCOVERY
#define MXFS_DEFAULT_MCAST_ADDR     "239.66.83.1"

/*
 * Membership change cooldown period (milliseconds).
 *
 * After a node removal is triggered (via peer TCP disconnect or lease
 * expiry), suppress further node removals for this duration.  This
 * prevents cascading membership flapping under heavy I/O: the I/O storm
 * from one membership change (DLM purge + cache invalidation) can stall
 * TCP on other peers and starve lease renewals, causing a death spiral
 * where the cluster removes nodes faster than they can recover.
 *
 * Bug 83: peer_disconnect_cb uses per-peer cooldown (last_peer_disconnect
 * array, indexed by node_id % MXFS_MAX_NODES).  Different peers are
 * processed independently — only the SAME peer is suppressed within
 * the cooldown window.  lease_expire_cb uses a separate global
 * timestamp (last_lease_expiry) because cascading lease expiries are
 * always correlated.
 *
 * The cooldown does NOT prevent TCP reconnection attempts.  The peer
 * subsystem handles reconnection independently via discovery
 * announcements (~2s interval).  It only gates the DLM purge +
 * disklock purge + journal recovery that constitute a membership change.
 *
 * 30 seconds is long enough for the I/O storm from a membership change
 * to settle, but short enough that a genuinely dead second node is still
 * removed promptly (deferred by at most 30s, then caught by lease expiry
 * on the next monitor pass).
 */
#define MXFS_MEMBERSHIP_COOLDOWN_MS  30000

/*
 * Membership stabilization window (milliseconds).
 *
 * How long the membership must remain unchanged before we call
 * mxfs_dlm_update_active_nodes().  When a TCP flap causes disconnect
 * followed by reconnect within this window, the stabilization timer
 * resets on each event.  When it finally expires the full node set is
 * present again, so update_active_nodes() sees no net change and does
 * NOT purge the lock table.
 *
 * 3 seconds is long enough to absorb a transient TCP disconnect/
 * reconnect (peer.c reconnects in milliseconds) but short enough that
 * a genuinely dead node's departure is reflected in the DLM quickly
 * (well within the 120s lock wait timeout).
 */
#define MXFS_MEMBERSHIP_STABILIZE_MS  3000

/* ─── Byte-order helpers for symlink headers ─── */

static inline void mount_put_be32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static inline void mount_put_be64(void *p, uint64_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

static inline void mount_put_le32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline uint32_t mount_get_be32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/* ─── Node UUID loading ─── */

/*
 * Generate a random UUID and derive node_id from it.
 * Used when /etc/mxfs/node.uuid doesn't exist.
 */
static void mxfs_generate_random_uuid(uint8_t *uuid, mxfs_node_id_t *node_id)
{
    mxfs_volume_id_t hash;
    int i;

    mxfs_pal_get_random_bytes(uuid, 16);

    /* Derive node_id from the UUID using FNV-1a over 16 bytes */
    hash = MXFS_FNV1A_64_INIT;
    for (i = 0; i < 16; i++) {
        hash ^= uuid[i];
        hash *= MXFS_FNV1A_64_PRIME;
    }
    *node_id = (mxfs_node_id_t)(hash & 0xFFFFFFFF);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: node_id=%u (random UUID generated)",
                 *node_id);
}

/*
 * Read a node UUID from a file (16 raw bytes).
 * Falls back to generating a random UUID if no file exists
 * or the read fails.
 */
static int load_node_uuid(const char *path, uint8_t *uuid, mxfs_node_id_t *node_id)
{
    mxfs_volume_id_t hash;
    int nread;
    int i;

    if (!path || !path[0])
        goto fallback;

    nread = mxfs_pal_read_file(path, uuid, 16);
    if (nread < 16) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: no %s, generating random node identity",
                     path);
        goto fallback;
    }

    /* Derive node_id from the UUID using FNV-1a over 16 bytes */
    hash = MXFS_FNV1A_64_INIT;
    for (i = 0; i < 16; i++) {
        hash ^= uuid[i];
        hash *= MXFS_FNV1A_64_PRIME;
    }
    *node_id = (mxfs_node_id_t)(hash & 0xFFFFFFFF);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: node_id=%u (from %s)",
                 *node_id, path);
    return 0;

fallback:
    mxfs_generate_random_uuid(uuid, node_id);
    return 0;
}

/*
 * Queue a deferred DLM active-node update via the membership stabilization
 * timer.  Records the current time as the last event timestamp and
 * increments the pending counter so the timer thread knows to re-arm.
 * The timer thread will call mxfs_dlm_update_active_nodes() once the
 * membership has been stable for MXFS_MEMBERSHIP_STABILIZE_MS.
 *
 * Falls back to an immediate mxfs_dlm_update_active_nodes() call if
 * the stabilization thread was not created (allocation failure at
 * mount time) — same as pre-stabilization behavior.
 *
 * Must be called with membership_stab_lock NOT held.
 */
static void queue_membership_update(struct mxfs_mount *mnt)
{
    if (!mnt->membership_stab_lock) {
        /* Fallback: no stabilization thread, update immediately */
        if (mnt->dlm && mnt->lease) {
            mxfs_node_id_t active[MXFS_MAX_NODES];
            int count;

            count = mxfs_lease_get_active_nodes(mnt->lease, active,
                                                 MXFS_MAX_NODES);
            if (count > 0)
                mxfs_dlm_update_active_nodes(mnt->dlm, active, count);
        }
        return;
    }

    /*
     * Bug 83: Call update_active_nodes directly (Bug 81 workaround)
     * but throttle to at most once per 3 seconds.  Without throttling,
     * every peer connect/disconnect event triggers a full DLM lock
     * table scan, which at 8+ nodes during startup creates O(N^2)
     * purge storms.  The 3s window lets multiple events batch into
     * a single update.
     *
     * Bug 83: Also removed the dangling mxfs_pal_mutex_unlock that
     * was here without a corresponding lock — left over from Bug 81
     * workaround that bypassed the stabilization timer path.
     */
    {
        uint64_t qnow = mxfs_pal_time_ms();
        uint64_t since_update;

        if (mnt->membership_stab_ts > 0) {
            since_update = qnow - mnt->membership_stab_ts;
            if (since_update < MXFS_MEMBERSHIP_STABILIZE_MS) {
                /* Too recent — signal the timer thread to handle it
                 * when the stabilization window expires */
                mxfs_pal_mutex_lock(mnt->membership_stab_lock);
                mnt->membership_stab_pending++;
                mnt->membership_stab_ts = qnow;
                if (mnt->membership_stab_cond)
                    mxfs_pal_cond_signal(mnt->membership_stab_cond);
                mxfs_pal_mutex_unlock(mnt->membership_stab_lock);
                return;
            }
        }

        if (mnt->dlm && mnt->lease) {
            mxfs_node_id_t active[MXFS_MAX_NODES];
            int count;

            count = mxfs_lease_get_active_nodes(mnt->lease, active,
                                                 MXFS_MAX_NODES);
            if (count > 0) {
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "mount: membership update, calling "
                             "update_active_nodes with %d node(s)",
                             count);
                mxfs_dlm_update_active_nodes(mnt->dlm, active, count);
            }
        }
        mnt->membership_stab_ts = qnow;
    }
}

/*
 * Membership stabilization worker thread.
 *
 * Polls every 200ms.  When membership_stab_pending > 0 and the last
 * event was at least MXFS_MEMBERSHIP_STABILIZE_MS ago, builds the
 * current active node list from the lease subsystem and calls
 * mxfs_dlm_update_active_nodes().
 *
 * Because update_active_nodes() compares the new list against the
 * current one before purging, a TCP flap (disconnect → reconnect
 * within the window) results in the full original node set being
 * passed → no change detected → no lock table purge.
 *
 * On shutdown (membership_stab_stop set), any pending update is
 * processed immediately before the thread exits.
 */
static void membership_stab_worker_fn(void *arg)
{
    struct mxfs_mount *mnt = arg;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: membership stabilization timer thread started");

    while (1) {
        int pending;
        uint64_t ts;
        int stop;

        /*
         * Sleep 200ms between polls.  This is simpler and more reliable
         * than condvar-based waiting: the condvar implementation has a
         * subtle race on some kernels where cond_signal can be lost if
         * the timer thread is between finish_wait and the next
         * prepare_to_wait (Bug 81).  200ms polling adds at most 200ms
         * of latency to membership convergence, which is acceptable
         * since the stabilization window is 3000ms.
         *
         * The stop flag is checked after each sleep, so shutdown
         * latency is at most 200ms.
         */
        mxfs_pal_sleep_ms(200);
        mxfs_pal_mutex_lock(mnt->membership_stab_lock);
        pending = mnt->membership_stab_pending;
        ts      = mnt->membership_stab_ts;
        stop    = mnt->membership_stab_stop;
        mxfs_pal_mutex_unlock(mnt->membership_stab_lock);

        if (pending) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "mount: stab_worker poll pending=%d ts=%llu "
                         "now=%llu",
                         pending,
                         (unsigned long long)ts,
                         (unsigned long long)mxfs_pal_time_ms());
        }

        if (!pending && !stop)
            continue;

        if (!stop) {
            uint64_t elapsed = mxfs_pal_time_ms() - ts;

            /* Not yet stable enough — loop back and sleep for remainder */
            if (elapsed < MXFS_MEMBERSHIP_STABILIZE_MS)
                continue;
        }

        /* Stability window expired (or we are shutting down):
         * build current peer list and call update_active_nodes(). */
        if (mnt->dlm && mnt->lease) {
            mxfs_node_id_t active[MXFS_MAX_NODES];
            int count;

            count = mxfs_lease_get_active_nodes(mnt->lease, active,
                                                 MXFS_MAX_NODES);
            if (count > 0) {
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "mount: membership stabilized, "
                             "calling update_active_nodes with "
                             "%d node(s)", count);
                mxfs_dlm_update_active_nodes(mnt->dlm, active, count);
            }
        }

        /* Clear pending counter under the lock.  New events that
         * arrived during our processing will have incremented it
         * again and updated ts, so we will re-arm on the next pass. */
        mxfs_pal_mutex_lock(mnt->membership_stab_lock);
        mnt->membership_stab_pending = 0;
        mxfs_pal_mutex_unlock(mnt->membership_stab_lock);

        if (stop)
            break;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: membership stabilization timer thread stopped");
}

/*
 * Purge a node from DLM immediately (the per-node locks only), then
 * queue a deferred update_active_nodes() via the stabilization timer.
 *
 * The immediate mxfs_dlm_purge_node() removes this specific node's
 * lock entries so pending requests destined for the dead node unblock
 * quickly.  The full mxfs_dlm_update_active_nodes() (which purges ALL
 * lock table entries and rebuilds mastering) is deferred: if the TCP
 * connection was a transient flap the node will reconnect within the
 * stabilization window and update_active_nodes() will see no net
 * change → no full purge.
 *
 * Does NOT unregister from the lease system — the lease monitor
 * remains the sole authority for declaring a node dead.
 */
static void purge_node_dlm(struct mxfs_mount *mnt, mxfs_node_id_t node_id)
{
    if (mnt->dlm)
        mxfs_dlm_purge_node(mnt->dlm, node_id);
    if (mnt->dlm_caw && mnt->disklock) {
        int dead_slot = mxfs_disklock_find_node_slot(mnt->disklock,
                                                      node_id);
        if (dead_slot >= 0)
            mxfs_dlm_caw_purge_node(mnt->dlm_caw, (uint8_t)dead_slot);
        else
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: node %u left cluster but disk lock cleanup "
                         "could not locate its slot (will be resolved on "
                         "next mount)",
                         node_id);
    }

    /* Deferred: refresh DLM active node list via stabilization timer.
     * The worker will build the current peer list from the lease
     * subsystem once the membership has been stable for
     * MXFS_MEMBERSHIP_STABILIZE_MS.  Filtering of the dead node is
     * handled at that point using the current lease state (if the
     * node is still ACTIVE in the lease table its key will be
     * present, so update_active_nodes will detect the change and
     * purge locks; if it has been unregistered already, it will be
     * absent and only surviving nodes are in the list). */
    queue_membership_update(mnt);
}

/*
 * Remove a node from the cluster: unregister from lease, purge DLM
 * locks, and refresh the DLM active node list.
 *
 * Used for definitive node removal (graceful NODE_LEAVE, lease expiry,
 * TCP disconnect when dlm_transport=TCP).  For CAW DLM, TCP disconnect
 * uses purge_node_dlm() instead — disk-based DLM is independent of TCP,
 * so the lease system remains the authority for node death declaration.
 */
static void remove_node(struct mxfs_mount *mnt, mxfs_node_id_t node_id)
{
    if (mnt->lease)
        mxfs_lease_unregister_node(mnt->lease, node_id);

    purge_node_dlm(mnt, node_id);

    if (mnt->disklock)
        mxfs_disklock_unmonitor_node(mnt->disklock, node_id);
}

/* ─── Callback bridges ─── */

/*
 * DLM send callback: forward DLM messages to peer networking.
 */
static int dlm_send_cb(struct mxfs_dlm_ctx *ctx,
                       mxfs_node_id_t target,
                       const void *msg, size_t len)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)ctx->cb_data;

    if (!mnt->peer)
        return -ENOTCONN;

    return mxfs_peer_send(mnt->peer, target, msg, len);
}

/* Forward declaration -- defined after bast_worker_fn */
static int queue_bast_to_worker(struct mxfs_mount *mnt,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner,
                                uint8_t requested_mode);

/*
 * Peer message callback: dispatch received messages to DLM.
 */
static void peer_msg_cb(void *data, mxfs_node_id_t sender,
                         void *msg, size_t len)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;
    const struct mxfs_dlm_msg_hdr *hdr;

    if (!mnt->dlm || len < sizeof(struct mxfs_dlm_msg_hdr))
        return;

    hdr = (const struct mxfs_dlm_msg_hdr *)msg;

    if (hdr->magic != MXFS_DLM_MAGIC)
        return;

    switch (hdr->type) {
    case MXFS_MSG_LOCK_REQ: {
        const struct mxfs_dlm_lock_req *req =
            (const struct mxfs_dlm_lock_req *)msg;
        if (len >= sizeof(*req))
            mxfs_dlm_process_remote_request(mnt->dlm, sender,
                                            &req->resource,
                                            req->mode, req->flags,
                                            req->hdr.epoch);
        break;
    }
    case MXFS_MSG_LOCK_GRANT:
    case MXFS_MSG_LOCK_DENY: {
        const struct mxfs_dlm_lock_resp *resp =
            (const struct mxfs_dlm_lock_resp *)msg;
        if (len >= sizeof(*resp))
            mxfs_dlm_process_remote_grant(mnt->dlm, &resp->resource,
                                          resp->mode, resp->status,
                                          resp->hdr.epoch,
                                          resp->grant_gen,
                                          resp->handoff,
                                          resp->dir_epoch);
        break;
    }
    case MXFS_MSG_LOCK_RELEASE: {
        const struct mxfs_dlm_lock_release *rel =
            (const struct mxfs_dlm_lock_release *)msg;
        if (len >= sizeof(*rel))
            mxfs_dlm_process_remote_release(mnt->dlm, sender,
                                            &rel->resource,
                                            rel->grant_gen);
        break;
    }
    case MXFS_MSG_LOCK_BAST: {
        const struct mxfs_dlm_bast *bast =
            (const struct mxfs_dlm_bast *)msg;
        if (len >= sizeof(*bast)) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "mount: BAST received from node %u "
                         "for ino=%llu type=%u requested_mode=%u",
                         sender,
                         (unsigned long long)bast->resource.ino,
                         bast->resource.type,
                         bast->requested_mode);

            /* Bug 57: Queue remote BASTs to the worker thread instead
             * of processing inline in the recv thread. Processing
             * inline causes deadlock: complete_bast tries to acquire
             * cache->rwlock, but a create/touch thread may hold that
             * rwlock while waiting for a DLM grant message -- which
             * arrives on this same recv thread. Queueing to the worker
             * thread breaks the deadlock since the recv thread stays
             * free to deliver grant messages. */
            if (queue_bast_to_worker(mnt, &bast->resource,
                                     mnt->node_id,
                                     bast->requested_mode)) {
                /* Alloc failed -- process inline as last resort */
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: low memory during lock notification, "
                             "processing synchronously (may be slower)");
                if (bast->resource.type == MXFS_LTYPE_INODE) {
                    mxfs_dir_cache_bast_cb(mnt->dcache,
                                           bast->resource.ino);
                    mxfs_inode_cache_bast_cb(mnt->icache,
                                             bast->resource.ino);
                } else if (bast->resource.type == MXFS_LTYPE_AG) {
                    mxfs_alloc_bast_cb(mnt->alloc,
                                       bast->resource.ag_number);
                }
            }
        }
        break;
    }
    case MXFS_MSG_NODE_LEAVE:
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: NODE_LEAVE from node %u, "
                     "removing from cluster", sender);

        remove_node(mnt, sender);
        break;
    default:
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: unhandled msg type %u from node %u",
                     hdr->type, sender);
        break;
    }
}

/*
 * Warn once when the TCP DLM cluster exceeds 16 nodes.
 * TCP DLM uses a single lock-master-per-resource design that creates
 * a serial bottleneck at high node counts. Tested to 16 nodes (100%
 * pass); 32 nodes achieves only ~27% metadata completion due to lock
 * wait timeouts. CAW DLM (disk-based) scales beyond 16 nodes.
 */
static void check_tcp_scale_warning(struct mxfs_mount *mnt)
{
    int count;

    if (mnt->tcp_scale_warned)
        return;
    if (mnt->dlm_transport != MXFS_DLM_TRANSPORT_TCP)
        return;
    if (!mnt->lease)
        return;

    mxfs_pal_mutex_lock(mnt->lease->lock);
    count = mnt->lease->node_count;
    mxfs_pal_mutex_unlock(mnt->lease->lock);

    if (count > 16) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mount: TCP DLM cluster has %d nodes; "
                     "performance degrades beyond 16 nodes — "
                     "consider CAW DLM (dlm_transport=caw)",
                     count);
        mnt->tcp_scale_warned = true;
    }
}

/*
 * Peer connect callback: handle inbound TCP connection.
 * Fired by the accept thread when a peer connects to us.
 * Registers the peer with the lease manager and updates DLM active
 * nodes. This is critical for fallback connections where a higher-ID
 * node connects to us without prior multicast discovery.
 */
static void peer_connect_cb(void *data, mxfs_node_id_t node_id)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: peer %u connected (inbound), registering",
                 node_id);

    /* Exit single-node mode */
    if (mnt->alloc)
        mxfs_alloc_set_single_node(mnt->alloc, false);

    /* Register with lease manager */
    if (mnt->lease)
        mxfs_lease_register_node(mnt->lease, node_id);

    check_tcp_scale_warning(mnt);

    /* Monitor heartbeat on shared disk */
    if (mnt->disklock)
        mxfs_disklock_monitor_node(mnt->disklock, node_id);

    /* Queue deferred DLM active node list update via the stabilization
     * timer.  On a TCP flap (disconnect + reconnect), the timer will
     * reset here and, when it fires, see the full original node set →
     * no lock table purge.  On a genuine new peer joining, the timer
     * fires after 3s of stability and the full node set (including
     * the new peer) is passed to update_active_nodes(). */
    queue_membership_update(mnt);
}

/*
 * Replay a dead node's journal and invalidate local caches.
 *
 * Acquires a DLM EX lock on a JOURNAL resource keyed by the dead
 * node's ID to serialize recovery across surviving nodes. After
 * replay, invalidates all local caches because the replayed journal
 * may have written metadata that is now stale in our caches.
 *
 * This function blocks (DLM lock + disk I/O) and must only be called
 * from a context where blocking is safe (kthread, workqueue).
 */
static void recover_dead_node_journal(struct mxfs_mount *mnt,
                                      mxfs_node_id_t dead_node)
{
    int slot;
    struct mxfs_resource_id res;
    uint8_t granted;
    int rc;

    if (!mnt->journal || !mnt->journal->dev || !mnt->dlm_lock_fn)
        return;

    slot = mxfs_journal_find_slot_by_node(mnt->journal, dead_node);
    if (slot < 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mount: no journal slot for dead node %u, "
                     "skipping recovery", dead_node);
        return;
    }

    /* Build DLM resource for journal recovery serialization */
    memset(&res, 0, sizeof(res));
    res.volume = mnt->volume_id;
    res.ino = dead_node;
    res.type = MXFS_LTYPE_JOURNAL;

    rc = mnt->dlm_lock_fn(mnt->dlm_dispatch_ctx, &res, MXFS_LOCK_EX,
                           0, &granted);
    if (rc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mount: DLM lock for journal recovery of node %u "
                     "failed: %d", dead_node, rc);
        return;
    }

    rc = mxfs_journal_begin_recovery(mnt->journal, slot);
    if (rc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mount: journal begin_recovery slot %d failed: %d",
                     slot, rc);
        mnt->dlm_unlock_fn(mnt->dlm_dispatch_ctx, &res);
        return;
    }

    rc = mxfs_journal_replay(mnt->journal, slot);
    if (rc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mount: journal replay slot %d failed: %d",
                     slot, rc);
    }

    rc = mxfs_journal_finish_recovery(mnt->journal, slot);
    if (rc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mount: journal finish_recovery slot %d failed: %d",
                     slot, rc);
    }

    mnt->dlm_unlock_fn(mnt->dlm_dispatch_ctx, &res);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: journal recovery for dead node %u (slot %d) "
                 "complete", dead_node, slot);

    /* Flush dirty inodes and blocks to disk before invalidating caches.
     * The replayed journal may have written metadata blocks that we
     * have cached — those cached copies are now stale. But we must
     * flush our own dirty modifications first to avoid data loss.
     *
     * Bug 50d: Do NOT flush dir_cache — same rationale as the
     * membership callback. Dir data is eagerly flushed during normal
     * operations. Flushing here risks overwriting correct on-disk
     * data with stale cached entries. */
    if (mnt->icache)
        mxfs_inode_cache_flush_all(mnt->icache);
    if (mnt->bcache)
        mxfs_block_cache_flush(mnt->bcache);

    /* Discard dir cache without flushing, drop inode and block caches. */
    if (mnt->dcache)
        mxfs_dir_cache_discard_all(mnt->dcache);
    if (mnt->icache)
        mxfs_inode_cache_drop_all(mnt->icache);
    if (mnt->bcache)
        mxfs_block_cache_invalidate_all(mnt->bcache);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: caches flushed and invalidated after journal "
                 "recovery for node %u", dead_node);
}

/*
 * Deferred journal recovery thread data.
 *
 * peer_disconnect_cb can be called from either the per-peer recv
 * kthread (safe to block) or from mxfs_peer_send() in arbitrary
 * context (NOT safe for long blocking). To handle both safely, we
 * always spawn a short-lived thread for journal recovery.
 */
struct journal_recovery_work {
    struct mxfs_mount   *mnt;
    mxfs_node_id_t      dead_node;
};

static void journal_recovery_thread_fn(void *arg)
{
    struct journal_recovery_work *work = arg;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: journal recovery thread started for "
                 "dead node %u", work->dead_node);

    recover_dead_node_journal(work->mnt, work->dead_node);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: journal recovery thread finished for "
                 "dead node %u", work->dead_node);

    mxfs_pal_free(work);
}

/*
 * Peer disconnect callback: handle node departure.
 *
 * Fires when a TCP peer connection drops (recv error or send failure).
 * This is the FAST path for detecting node death — TCP disconnect is
 * detected in seconds vs the 6-minute lease timeout. Triggers the
 * same cleanup as lease_expire_cb: purge DLM and disklock, mark
 * journal for recovery, and replay the dead node's journal.
 *
 * Membership change cooldown (Bug 69): under heavy I/O, TCP timeouts
 * can cascade — one node's I/O stall causes DLM TCP timeouts on other
 * nodes, and the DLM purge + cache invalidation from handling the
 * first disconnect creates an I/O storm that stalls TCP on even more
 * peers.  If a membership change (peer disconnect or lease expiry)
 * was already processed within MXFS_MEMBERSHIP_COOLDOWN_MS (30s),
 * this callback logs a warning and returns without acting.  The node
 * will still be caught by lease expiry if it is truly dead.  The
 * cooldown does NOT prevent TCP reconnection — the peer subsystem
 * handles that independently after this callback returns.
 *
 * IMPORTANT: does NOT unregister the node from the lease system.
 * The lease monitor is the sole authority for declaring a node dead.
 * TCP disconnect is an early hint, not a definitive death declaration.
 * If the TCP connection was just a transient failure, the lease system
 * will keep the node ACTIVE as long as renewals arrive. If the node
 * is truly dead, the lease will expire and lease_expire_cb will do
 * the definitive cleanup including lease unregistration.
 *
 * Journal recovery is deferred to a short-lived thread because this
 * callback may run from mxfs_peer_send() in arbitrary context where
 * DLM lock acquisition + disk I/O would be unsafe.
 */
static void peer_disconnect_cb(void *data, mxfs_node_id_t node_id)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;
    struct journal_recovery_work *work;
    mxfs_thread_t *t;
    uint64_t now;
    uint64_t since_last;
    int slot;

    /* Bug 100: Skip disconnect processing during unmount.
     * Subsystems may already be torn down. */
    if (!mnt->mounted)
        return;

    /* Bug 83: Per-peer disconnect cooldown.  Only suppress if the
     * SAME peer (same hash slot) disconnected within the cooldown
     * window.  Different peers get processed immediately.  This
     * prevents the old global cooldown from blocking legitimate
     * multi-peer disconnect processing while still preventing
     * rapid-fire re-processing of the same peer.
     *
     * Uses node_id % MXFS_MAX_NODES as the hash slot.  With 64
     * slots and typical node counts (2-32), collisions are rare.
     *
     * NOTE: this does NOT prevent reconnection attempts.  The peer
     * subsystem in peer.c handles reconnection independently via
     * discovery announcements (~2s interval). */
    now = mxfs_pal_time_ms();
    slot = node_id % MXFS_MAX_NODES;
    if (mnt->last_peer_disconnect[slot] > 0) {
        since_last = now - mnt->last_peer_disconnect[slot];
        if (since_last < MXFS_MEMBERSHIP_COOLDOWN_MS) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mount: peer %u disconnected but in per-peer "
                         "cooldown (%llu ms since last, cooldown "
                         "%u ms) -- skipping DLM purge, lease expiry "
                         "will catch if truly dead",
                         node_id,
                         (unsigned long long)since_last,
                         MXFS_MEMBERSHIP_COOLDOWN_MS);
            return;
        }
    }

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: cluster node %u disconnected, cleaning up lock state",
                 node_id);

    /* Record this peer's disconnect for per-peer cooldown tracking */
    mnt->last_peer_disconnect[slot] = mxfs_pal_time_ms();

    /* Bug 107: For TCP DLM, the TCP connection IS the transport.
     * When it drops, the node is definitively unreachable — DLM
     * cannot route messages to it.  Call remove_node() to immediately
     * remove it from active_nodes + lease table so DLM re-masters
     * resources to surviving nodes.  For CAW DLM, disk-based transport
     * is independent of TCP, so defer to lease for death declaration. */
    if (mnt->dlm_transport == MXFS_DLM_TRANSPORT_TCP)
        remove_node(mnt, node_id);
    else
        purge_node_dlm(mnt, node_id);

    /* Purge disklock records for the dead peer */
    if (mnt->disklock)
        mxfs_disklock_purge_node(mnt->disklock, node_id);

    if (mnt->scsipr)
        mxfs_scsipr_preempt(mnt->scsipr, (uint64_t)node_id);

    /* Mark journal for recovery */
    if (mnt->journal)
        mxfs_journal_mark_needs_recovery(mnt->journal, node_id);

    /* Spawn a thread to replay the dead node's journal.
     * The DLM EX lock on the JOURNAL resource serializes this with
     * any concurrent recovery from lease_expire_cb (belt and suspenders),
     * so double-replay is prevented.
     *
     * We store the thread handle in mnt->recovery_thread so it can be
     * joined: before spawning a new recovery thread, and during unmount.
     * If a previous recovery thread is still running, we join it first
     * (recovery is serialized by the DLM EX lock anyway). */
    if (mnt->journal && mnt->journal->dev && mnt->dlm_lock_fn &&
        mnt->recovery_lock) {
        mxfs_thread_t *old;

        work = mxfs_pal_alloc(sizeof(*work));
        if (!work) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: node %u recovery postponed due to low "
                         "memory (will complete automatically)",
                         node_id);
            return;
        }
        work->mnt = mnt;
        work->dead_node = node_id;

        /* Join any previous recovery thread before spawning a new one.
         * This prevents accumulating unkilled kthreads. The join may
         * block but recovery threads are short-lived (disk I/O time). */
        mxfs_pal_mutex_lock(mnt->recovery_lock);
        old = mnt->recovery_thread;
        mnt->recovery_thread = NULL;
        mxfs_pal_mutex_unlock(mnt->recovery_lock);

        if (old)
            mxfs_pal_thread_join(old);

        t = mxfs_pal_thread_create(journal_recovery_thread_fn, work);
        if (!t) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: failed to spawn journal recovery thread "
                         "for node %u — recovery deferred to lease expiry",
                         node_id);
            mxfs_pal_free(work);
            return;
        }

        mxfs_pal_mutex_lock(mnt->recovery_lock);
        mnt->recovery_thread = t;
        mxfs_pal_mutex_unlock(mnt->recovery_lock);
    }
}

/*
 * Discovery callback: handle new peer announcement.
 */
static void discovery_peer_cb(void *data,
                               const struct mxfs_discovery_announce *ann)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;
    char host[64];
    int add_rc = 0;

    /* Only connect to peers with the same volume */
    if (ann->volume_id != mnt->volume_id)
        return;

    /* Don't connect to ourselves */
    if (ann->node_id == mnt->node_id)
        return;

    /* Exit single-node mode: peers exist, alloc must flush
     * metadata to disk before releasing AG locks. */
    if (mnt->alloc)
        mxfs_alloc_set_single_node(mnt->alloc, false);

    /* Exit single-node CAW DLM bypass: flush in-memory locks
     * to disk so the joining peer can see them. */
    if (mnt->dlm_caw)
        mxfs_dlm_caw_set_single_node(mnt->dlm_caw, false);

    if (mnt->peer) {
        /* ─── TCP transport: manage peer connections ─── */

        /* Extract hostname (null-terminated in announcement) */
        memcpy(host, ann->hostname, sizeof(host));
        host[sizeof(host) - 1] = '\0';

        /* Add peer (returns -EEXIST for already-known peers) */
        add_rc = mxfs_peer_add(mnt->peer, ann->node_id, ann->node_uuid,
                                host, ann->tcp_port);

        /*
         * Always try to connect -- mxfs_peer_connect returns immediately
         * if already connected, but will reconnect if the peer is in
         * DISCONNECTED state (e.g. after a connection reset).
         *
         * Normally the lower-ID node initiates. But if we're the higher-ID
         * node and multicast is asymmetric (peer never receives our
         * announcements), the lower-ID node will never discover us and
         * never connect. As a fallback, after discovering the peer, the
         * higher-ID node forces a connection if one isn't already active.
         */
        if (mnt->node_id < ann->node_id) {
            mxfs_peer_connect(mnt->peer, ann->node_id);
        } else if (!mxfs_peer_is_connected(mnt->peer, ann->node_id)) {
            mxfs_peer_connect_force(mnt->peer, ann->node_id);
        }
    }

    /* Bug 78: repeated discovery announcements from an already-active
     * peer must NOT reset the stabilization timer, otherwise the
     * 3-second window never expires and DLM membership never updates.
     *
     * Bug 84: if the peer is in the peer table (EEXIST) but NOT in
     * the lease table, it left and re-joined with the same node_id.
     * We must re-register it with the lease system and update DLM
     * membership. Only skip if the peer is both in the peer table
     * AND already registered in the lease system.
     *
     * Bug 88: For CAW transport (no TCP peer), add_rc stays 0 on
     * first discovery; use lease_has_node to detect duplicates. */
    if (mnt->peer && add_rc == -EEXIST) {
        if (mnt->lease && mxfs_lease_has_node(mnt->lease, ann->node_id))
            return;
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "discovery: returning peer %u re-joined, "
                     "re-registering with lease + DLM",
                     ann->node_id);
    } else if (!mnt->peer) {
        /* CAW transport: no peer table, use lease for dedup */
        if (mnt->lease && mxfs_lease_has_node(mnt->lease, ann->node_id))
            return;
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "discovery: CAW peer %u discovered via multicast",
                     ann->node_id);
    }

    /* Register with lease manager */
    if (mnt->lease)
        mxfs_lease_register_node(mnt->lease, ann->node_id);

    check_tcp_scale_warning(mnt);

    if (mnt->disklock)
        mxfs_disklock_monitor_node(mnt->disklock, ann->node_id);

    /* Queue deferred DLM active node list update via the stabilization
     * timer.  If multiple peers are discovered in quick succession
     * (common at startup), the timer resets on each event and fires
     * once after the cluster is fully assembled, minimizing the number
     * of lock table purges during peer convergence.
     *
     * For CAW transport, TCP DLM is NULL so queue_membership_update
     * is a no-op — CAW DLM doesn't need an active node list. */
    queue_membership_update(mnt);
}

/*
 * Disklock heartbeat monitor detected a dead node (~62s detection).
 * Medium-speed path: faster than lease (10 min) but slower than TCP disconnect (seconds).
 * Uses per-peer cooldown to avoid double-processing with peer_disconnect_cb.
 */
static void disklock_expire_cb(void *data, mxfs_node_id_t dead_node)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;
    uint64_t now;

    if (!mnt->mounted)
        return;

    if (dead_node == mnt->node_id)
        return;

    now = mxfs_pal_time_ms();
    if (now - mnt->last_peer_disconnect[dead_node % MXFS_MAX_NODES]
        < MXFS_MEMBERSHIP_COOLDOWN_MS) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
            "mount: disklock expire for node %u suppressed (cooldown)",
            dead_node);
        return;
    }
    mnt->last_peer_disconnect[dead_node % MXFS_MAX_NODES] = now;

    mxfs_pal_log(MXFS_LOG_WARN,
        "mxfs: node %u is no longer responding (no heartbeat for >%d seconds), "
        "initiating failover",
        dead_node,
        (MXFS_DISKLOCK_DEAD_THRESHOLD * MXFS_DISKLOCK_HB_INTERVAL_MS) / 1000);

    purge_node_dlm(mnt, dead_node);

    if (mnt->disklock)
        mxfs_disklock_purge_node(mnt->disklock, dead_node);

    if (mnt->scsipr)
        mxfs_scsipr_preempt(mnt->scsipr, (uint64_t)dead_node);

    if (mnt->journal)
        mxfs_journal_mark_needs_recovery(mnt->journal, dead_node);

    recover_dead_node_journal(mnt, dead_node);
    queue_membership_update(mnt);
}

/*
 * Lease expire callback: handle dead node.
 *
 * This runs in the lease monitor kthread context, so DLM lock + journal
 * replay can block safely. This is the FALLBACK path for detecting node
 * death — if TCP disconnect was missed for some reason, the lease
 * timeout catches it. The DLM EX lock on the JOURNAL resource
 * prevents double-replay if peer_disconnect_cb already recovered.
 *
 * Membership change cooldown: if another node was declared dead within
 * the last MXFS_MEMBERSHIP_COOLDOWN_MS, skip this expiry.  The
 * I/O storm from a membership change (cache flush + lock purge on all
 * nodes) can starve lease renewals, causing cascading false SUSPECT
 * declarations.  The deferred node will be caught on a subsequent
 * monitor pass once the cooldown expires.
 */
static void lease_expire_cb(void *data, mxfs_node_id_t dead_node)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)data;
    uint64_t now;
    uint64_t since_last;

    if (!mnt->mounted)
        return;

    /* Lease expiry cooldown: suppress rapid-fire node removals.
     * Bug 83: Uses a separate global timestamp (last_lease_expiry)
     * because lease expiry is a heavy operation and cascading lease
     * expiries are always correlated (I/O storm from one expiry
     * starves renewals on other nodes). */
    now = mxfs_pal_time_ms();
    if (mnt->last_lease_expiry > 0) {
        since_last = now - mnt->last_lease_expiry;
        if (since_last < MXFS_MEMBERSHIP_COOLDOWN_MS) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mount: skipping node %u removal during "
                         "lease expiry cooldown (%llu ms since last "
                         "expiry, cooldown %u ms)",
                         dead_node,
                         (unsigned long long)since_last,
                         MXFS_MEMBERSHIP_COOLDOWN_MS);
            return;
        }
    }

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: node %u has left the cluster (lease expired), "
                 "recovering its resources", dead_node);

    /* Record this lease expiry for cooldown tracking */
    mnt->last_lease_expiry = mxfs_pal_time_ms();

    /* Remove from cluster (unregister lease, purge DLM, update active list) */
    remove_node(mnt, dead_node);

    /* Purge disklock records */
    if (mnt->disklock)
        mxfs_disklock_purge_node(mnt->disklock, dead_node);

    if (mnt->scsipr)
        mxfs_scsipr_preempt(mnt->scsipr, (uint64_t)dead_node);

    /* Mark journal for recovery */
    if (mnt->journal)
        mxfs_journal_mark_needs_recovery(mnt->journal, dead_node);

    /* Replay the dead node's journal. This runs directly in the lease
     * monitor kthread which is safe for blocking. If peer_disconnect_cb
     * already replayed this journal, the DLM EX lock + finish_recovery
     * ensures this is a no-op (slot state will be RECOVERED). */
    recover_dead_node_journal(mnt, dead_node);
}

/*
 * queue_bast_to_worker -- enqueue a BAST work item for the bast_worker thread.
 * Used for both local BASTs (from dlm_bast_cb/promote_waiters) and remote
 * BASTs (from peer_msg_cb/MXFS_MSG_LOCK_BAST). Processing BASTs inline in
 * the recv thread causes deadlocks: complete_bast acquires cache->rwlock,
 * but a touch/create thread may hold that rwlock while waiting for a DLM
 * grant that arrives on the same recv thread -- classic AB/BA deadlock.
 *
 * Returns 0 on success, -ENOMEM on allocation failure.
 */
static int queue_bast_to_worker(struct mxfs_mount *mnt,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner,
                                uint8_t requested_mode)
{
    struct bast_work_item *wi;

    wi = mxfs_pal_alloc(sizeof(*wi));
    if (!wi)
        return -ENOMEM;

    wi->resource = *resource;
    wi->owner = owner;
    wi->requested_mode = requested_mode;
    wi->next = NULL;

    mxfs_pal_mutex_lock(mnt->bast_lock);
    if (mnt->bast_tail)
        mnt->bast_tail->next = wi;
    else
        mnt->bast_head = wi;
    mnt->bast_tail = wi;
    mxfs_pal_cond_signal(mnt->bast_cond);
    mxfs_pal_mutex_unlock(mnt->bast_lock);
    return 0;
}

/*
 * BAST worker thread -- drains the deferred BAST queue and processes
 * each item by calling the blocking cache flush/invalidation handlers.
 * Running this in a dedicated thread prevents the DLM recv thread from
 * blocking on disk I/O, which would stall TCP reads and cause peer
 * disconnects under heavy 4-node write load.
 */
static void bast_worker_fn(void *arg)
{
    struct mxfs_mount *mnt = arg;
    struct bast_work_item *item;

    while (mnt->bast_running) {
        mxfs_pal_mutex_lock(mnt->bast_lock);
        while (!mnt->bast_head && mnt->bast_running)
            mxfs_pal_cond_wait(mnt->bast_cond, mnt->bast_lock);

        item = mnt->bast_head;
        if (item) {
            mnt->bast_head = item->next;
            if (!mnt->bast_head)
                mnt->bast_tail = NULL;
        }
        mxfs_pal_mutex_unlock(mnt->bast_lock);

        if (!item)
            continue;

        /* Process the deferred BAST — this is the blocking part
         * that does disk I/O via inode_cache complete_bast() */
        if (item->owner == mnt->node_id) {
            uint64_t bast_start = mxfs_pal_time_ms();
            int qdepth = 0;
            struct bast_work_item *qp;

            /* Count queue depth for diagnostics */
            mxfs_pal_mutex_lock(mnt->bast_lock);
            for (qp = mnt->bast_head; qp; qp = qp->next)
                qdepth++;
            mxfs_pal_mutex_unlock(mnt->bast_lock);

            if (qdepth > 0)
                mxfs_pal_log(MXFS_LOG_DEBUG,
                    "mount: BAST worker processing type=%u "
                    "ino/ag=%llu, queue_backlog=%d",
                    item->resource.type,
                    (unsigned long long)(item->resource.type ==
                        MXFS_LTYPE_INODE ? item->resource.ino :
                        item->resource.ag_number),
                    qdepth);

            if (qdepth >= 5)
                mxfs_pal_log(MXFS_LOG_WARN,
                    "mount: BAST queue backlog=%d — slow BAST "
                    "processing may cause DLM lock timeouts",
                    qdepth);

            if (item->resource.type == MXFS_LTYPE_INODE) {
                mxfs_dir_cache_bast_cb(mnt->dcache, item->resource.ino);
                mxfs_inode_cache_bast_cb(mnt->icache, item->resource.ino);
            } else if (item->resource.type == MXFS_LTYPE_AG) {
                mxfs_alloc_bast_cb(mnt->alloc,
                                   item->resource.ag_number);
            }

            {
                uint64_t elapsed_ms = mxfs_pal_time_ms() - bast_start;
                if (elapsed_ms > 1000)
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mount: BAST callback took %llums "
                        "(type=%u ino/ag=%llu)",
                        (unsigned long long)elapsed_ms,
                        item->resource.type,
                        (unsigned long long)(item->resource.type ==
                            MXFS_LTYPE_INODE ? item->resource.ino :
                            item->resource.ag_number));
                else
                    mxfs_pal_log(MXFS_LOG_DEBUG,
                        "mount: BAST callback completed in %llums",
                        (unsigned long long)elapsed_ms);
            }
        }

        mxfs_pal_free(item);
    }

    /* Drain remaining items on shutdown */
    mxfs_pal_mutex_lock(mnt->bast_lock);
    while (mnt->bast_head) {
        item = mnt->bast_head;
        mnt->bast_head = item->next;
        mxfs_pal_mutex_unlock(mnt->bast_lock);

        if (item->owner == mnt->node_id) {
            if (item->resource.type == MXFS_LTYPE_INODE) {
                mxfs_dir_cache_bast_cb(mnt->dcache, item->resource.ino);
                mxfs_inode_cache_bast_cb(mnt->icache, item->resource.ino);
            } else if (item->resource.type == MXFS_LTYPE_AG) {
                mxfs_alloc_bast_cb(mnt->alloc,
                                   item->resource.ag_number);
            }
        }
        mxfs_pal_free(item);
        mxfs_pal_mutex_lock(mnt->bast_lock);
    }
    mxfs_pal_mutex_unlock(mnt->bast_lock);
}

/*
 * Two cases:
 *   owner == local node: local BAST — queued to bast_worker thread for
 *                        deferred processing (cache flush does disk I/O
 *                        that would block the DLM recv thread).
 *   owner != local node: remote BAST — send MXFS_MSG_LOCK_BAST over TCP
 *                        so the remote holder can release.
 */
static void dlm_bast_cb(struct mxfs_dlm_ctx *ctx,
                         const struct mxfs_resource_id *resource,
                         mxfs_node_id_t owner,
                         uint8_t requested_mode)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)ctx->cb_data;

    if (owner == ctx->local_node) {
        /* Queue local BAST for worker thread -- avoids blocking
         * recv thread on disk I/O in cache flush handlers */
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: queuing local BAST for ino %llu type %u",
                     (unsigned long long)resource->ino, resource->type);

        if (queue_bast_to_worker(mnt, resource, owner, requested_mode)) {
            /* Fallback: process inline if alloc fails */
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: low memory during lock notification, "
                         "processing synchronously");
            if (resource->type == MXFS_LTYPE_INODE) {
                mxfs_dir_cache_bast_cb(mnt->dcache, resource->ino);
                mxfs_inode_cache_bast_cb(mnt->icache, resource->ino);
            } else if (resource->type == MXFS_LTYPE_AG) {
                mxfs_alloc_bast_cb(mnt->alloc, resource->ag_number);
            }
        }
        return;
    } else {
        /* Remote BAST — send MXFS_MSG_LOCK_BAST message to holder.
         *
         * Retry up to 3 times on send failure. Without retry, a
         * transient TCP disconnect causes the BAST to be silently
         * dropped. The holder never releases its lock, never
         * invalidates its dir/inode cache, and serves stale data
         * indefinitely. At 4+ nodes with 3 PR holders, losing 2
         * BASTs means 2 of 3 nodes keep stale dir entries. */
        struct mxfs_dlm_bast bast;
        int send_ret;
        int retries = 3;

        if (!mnt->peer)
            return;

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: BAST remote: sending to node %u "
                     "for ino=%llu type=%u requested_mode=%u",
                     owner,
                     (unsigned long long)resource->ino,
                     resource->type, requested_mode);

        memset(&bast, 0, sizeof(bast));
        bast.hdr.magic = MXFS_DLM_MAGIC;
        bast.hdr.version = MXFS_DLM_VERSION;
        bast.hdr.type = MXFS_MSG_LOCK_BAST;
        bast.hdr.length = sizeof(bast);
        bast.hdr.sender = ctx->local_node;
        bast.hdr.target = owner;
        bast.hdr.epoch = ctx->current_epoch;
        bast.resource = *resource;
        bast.requested_mode = requested_mode;

        do {
            send_ret = mxfs_peer_send(mnt->peer, owner,
                                      &bast, sizeof(bast));
            if (send_ret == 0)
                break;
            if (--retries > 0) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: lock notification to node %u "
                             "failed, retrying (%d attempts remaining)",
                             owner, retries);
                mxfs_pal_sleep_ms(50);
            }
        } while (retries > 0);

        if (send_ret != 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: lock notification to node %u failed "
                         "after retries (inode %llu) — data on that "
                         "node may be temporarily outdated",
                         owner,
                         (unsigned long long)resource->ino);
        }
    }
}

/*
 * CAW DLM BAST callback.
 *
 * The CAW DLM invokes the mxfs_dlm_bast_cb typedef with cb_data cast
 * to struct mxfs_dlm_ctx *.  Since we set cb_data = mnt (the mount
 * struct), the first parameter is actually a struct mxfs_mount *.
 * This wrapper casts it back and queues the BAST to the worker thread,
 * same as the TCP path.  No remote BAST forwarding is needed because
 * the CAW DLM uses UDP multicast for cross-node BAST hints.
 */
static void dlm_bast_cb_caw(struct mxfs_dlm_ctx *fake_ctx,
                              const struct mxfs_resource_id *resource,
                              mxfs_node_id_t owner,
                              uint8_t requested_mode)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)fake_ctx;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: CAW BAST for ino %llu type %u",
                 (unsigned long long)resource->ino, resource->type);

    if (queue_bast_to_worker(mnt, resource, owner, requested_mode)) {
        /* Fallback: process inline if alloc fails */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: low memory during disk lock notification, "
                     "processing synchronously");
        if (resource->type == MXFS_LTYPE_INODE) {
            mxfs_dir_cache_bast_cb(mnt->dcache, resource->ino);
            mxfs_inode_cache_bast_cb(mnt->icache, resource->ino);
        } else if (resource->type == MXFS_LTYPE_AG) {
            mxfs_alloc_bast_cb(mnt->alloc, resource->ag_number);
        }
    }
}

/* ─── DLM dispatch wrappers ───
 *
 * Thin wrappers that cast the void* dispatch context to the concrete
 * DLM context type and call the appropriate implementation.  These
 * allow the inode/dir/alloc caches to call DLM operations through
 * the transport-agnostic function pointers on the mount struct.
 */

static int dlm_lock_tcp_wrapper(void *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint8_t mode, uint32_t flags,
                                 uint8_t *granted_mode)
{
    return mxfs_dlm_lock((struct mxfs_dlm_ctx *)ctx,
                          resource, mode, flags, granted_mode);
}

static int dlm_unlock_tcp_wrapper(void *ctx,
                                   const struct mxfs_resource_id *resource)
{
    return mxfs_dlm_unlock((struct mxfs_dlm_ctx *)ctx, resource);
}

static int dlm_convert_tcp_wrapper(void *ctx,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t new_mode)
{
    struct mxfs_dlm_ctx *dlm = (struct mxfs_dlm_ctx *)ctx;

    return mxfs_dlm_lock_convert(dlm, resource, dlm->local_node, new_mode);
}

static int dlm_lock_caw_wrapper(void *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint8_t mode, uint32_t flags,
                                 uint8_t *granted_mode)
{
    return mxfs_dlm_caw_lock((struct mxfs_dlm_caw_ctx *)ctx,
                              resource, mode, flags, granted_mode);
}

static int dlm_unlock_caw_wrapper(void *ctx,
                                   const struct mxfs_resource_id *resource)
{
    return mxfs_dlm_caw_unlock((struct mxfs_dlm_caw_ctx *)ctx, resource);
}

static int dlm_convert_caw_wrapper(void *ctx,
                                    const struct mxfs_resource_id *resource,
                                    uint8_t new_mode)
{
    return mxfs_dlm_caw_convert((struct mxfs_dlm_caw_ctx *)ctx,
                                 resource, new_mode);
}

/*
 * Cache flush worker thread (Bug 66).
 *
 * Performs the blocking cache flush/discard operations that were
 * previously done synchronously in dlm_membership_cb(). Those
 * operations involve disk I/O and can take 10-100+ seconds under
 * load, starving lease renewals (which share the same thread
 * context via write locks) and causing false node death detection.
 *
 * The worker waits on cache_flush_cond with a 1-second timeout.
 * When cache_flush_pending is set (by dlm_membership_cb), the
 * worker clears it and performs the full flush+discard sequence.
 *
 * The flush logic is identical to the original dlm_membership_cb
 * implementation — see Bug 50d comments below for rationale.
 */
static void cache_flush_worker_fn(void *arg)
{
    struct mxfs_mount *mnt = arg;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: cache flush worker thread started");

    while (1) {
        mxfs_pal_mutex_lock(mnt->cache_flush_lock);

        /* Wait for signal or 1-second timeout */
        while (!mnt->cache_flush_pending && !mnt->cache_flush_stop)
            mxfs_pal_cond_timedwait(mnt->cache_flush_cond,
                                     mnt->cache_flush_lock, 1000);

        if (mnt->cache_flush_stop) {
            mxfs_pal_mutex_unlock(mnt->cache_flush_lock);
            break;
        }

        /* Clear pending flag before releasing lock — any new signal
         * that arrives during our flush will set it again and we'll
         * pick it up on the next iteration */
        mnt->cache_flush_pending = 0;
        mxfs_pal_mutex_unlock(mnt->cache_flush_lock);

        if (!mnt->mounted)
            continue;

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: cache flush worker: flushing dirty data "
                     "before cache invalidation");

        /* Bug 50d: Flush dirty inodes and blocks, then DISCARD all
         * caches.
         *
         * Critical insight: do NOT call dir_cache_flush_all during a
         * membership change. Here's why:
         *
         * dir_cache_flush_all calls mxfs_inode_cache_get() for each
         * dirty dir, which triggers epoch-mismatch detection (the DLM
         * epoch was just advanced). The handler evicts the old inode
         * and reloads it from disk. The reloaded inode has the
         * DEPARTING node's extent map (it was the last to write the
         * inode during its clean unmount). flush_dir_immediate then
         * writes THIS node's cached dir entries (a stale subset) to
         * the physical data blocks pointed to by the departing node's
         * extent map — OVERWRITING the departing node's complete
         * directory with our partial cached version.
         *
         * This caused Bug 50/50b/50c: 500 files per node, but after
         * membership change only 68 survived (one data block's worth).
         *
         * The fix: discard the dir cache without flushing. Dir entries
         * are eagerly flushed to disk via flush_dir_immediate during
         * every add/remove/rename operation. The on-disk directory is
         * always up to date (it was last written by whichever node
         * held the EX lock most recently). Flushing again here is
         * unnecessary at best and destructive at worst.
         *
         * Flush order for other caches:
         * 1. Inodes: writes dirty inode metadata (size, timestamps,
         *    mode) directly to bdev via flush_inode_to_disk. Does NOT
         *    use DLM.
         * 2. Blocks: writes dirty block cache entries to bdev. These
         *    are metadata blocks (AGF, bnobt, etc), NOT dir data
         *    blocks. Dir data blocks are flushed eagerly by
         *    block_cache_flush_range inside flush_leaf_dir /
         *    flush_block_dir.
         *
         * Bug 131: Release the allocator's cached AG lock BEFORE
         * flushing caches. The DLM table was just purged by
         * update_active_nodes, so the cached AG lock is stale —
         * the DLM no longer knows we hold it, and the resource
         * master may have changed. flush_cached_ag writes dirty
         * AG metadata to disk and releases the DLM lock, then
         * resets cached_ag to -1 so the next allocation re-acquires
         * from the new master. */
        if (mnt->alloc)
            mxfs_alloc_release_cached_ag(mnt->alloc);
        if (mnt->icache)
            mxfs_inode_cache_flush_all(mnt->icache);
        if (mnt->bcache)
            mxfs_block_cache_flush(mnt->bcache);

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: cache flush worker: dirty data flushed, "
                     "discarding all caches");

        /* Discard dir cache WITHOUT flushing (prevents stale
         * overwrite). Then drop inode and block caches normally
         * (their drop_all functions flush remaining dirty entries
         * safely — inode flush goes directly to bdev without DLM,
         * block flush is the same). */
        if (mnt->dcache)
            mxfs_dir_cache_discard_all(mnt->dcache);
        if (mnt->icache)
            mxfs_inode_cache_drop_all(mnt->icache);
        if (mnt->bcache)
            mxfs_block_cache_invalidate_all(mnt->bcache);

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: cache flush worker: cache invalidation "
                     "complete");
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: cache flush worker thread stopped");
}

/*
 * DLM membership change callback: DLM purged all lock table entries
 * because the active node set changed and mastering shifted.
 *
 * Bug 66: This callback now signals the async cache flush worker
 * thread instead of performing synchronous cache flush/discard.
 * The synchronous operations took 10-100+ seconds under load,
 * blocking the DLM callback path and starving lease renewals.
 * The async worker performs the identical flush+discard sequence
 * in its own thread context.
 */
static void dlm_membership_cb(struct mxfs_dlm_ctx *ctx)
{
    struct mxfs_mount *mnt = (struct mxfs_mount *)ctx->cb_data;

    if (!mnt->mounted)
        return;

    /* Bug 66: Signal the async cache flush worker if available.
     * Falls back to synchronous flush if the worker thread was
     * not created (allocation failure at mount time). */
    if (mnt->cache_flush_thread) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: DLM membership changed, queuing async "
                     "cache flush");

        mxfs_pal_mutex_lock(mnt->cache_flush_lock);
        mnt->cache_flush_pending = 1;
        mxfs_pal_cond_signal(mnt->cache_flush_cond);
        mxfs_pal_mutex_unlock(mnt->cache_flush_lock);
        return;
    }

    /* Fallback: synchronous flush (same as pre-Bug 66 behavior) */
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: cluster membership changed, flushing caches "
                 "(may cause brief pause)");

    /* Bug 131: Release stale cached AG lock before flushing caches.
     * See async worker path comment for full explanation. */
    if (mnt->alloc)
        mxfs_alloc_release_cached_ag(mnt->alloc);
    if (mnt->icache)
        mxfs_inode_cache_flush_all(mnt->icache);
    if (mnt->bcache)
        mxfs_block_cache_flush(mnt->bcache);
    if (mnt->dcache)
        mxfs_dir_cache_discard_all(mnt->dcache);
    if (mnt->icache)
        mxfs_inode_cache_drop_all(mnt->icache);
    if (mnt->bcache)
        mxfs_block_cache_invalidate_all(mnt->bcache);
}

/* ─── Mount implementation ─── */

int mxfs_mount(const struct mxfs_mount_opts *opts,
               struct mxfs_mount **mnt_out)
{
    struct mxfs_mount *mnt;
    uint16_t dlm_port;
    uint16_t disc_port;
    const char *mcast_addr;
    int ret;

    if (!opts || !opts->device || !mnt_out)
        return -EINVAL;

    mnt = mxfs_pal_alloc(sizeof(*mnt));
    if (!mnt)
        return -ENOMEM;

    memset(mnt, 0, sizeof(*mnt));
    mnt->opts = *opts;
    strncpy(mnt->dev_path, opts->device, MXFS_PATH_MAX - 1);

    /* Recovery thread serialization lock */
    mnt->recovery_lock = mxfs_pal_mutex_create();
    if (!mnt->recovery_lock) {
        mxfs_pal_free(mnt);
        return -ENOMEM;
    }

    dlm_port = opts->dlm_port > 0 ? opts->dlm_port : MXFS_DEFAULT_DLM_PORT;
    disc_port = opts->discovery_port > 0 ? opts->discovery_port :
                                           MXFS_DEFAULT_DISCOVERY_PORT;
    mcast_addr = opts->multicast_addr ? opts->multicast_addr :
                                        MXFS_DEFAULT_MCAST_ADDR;
    /* ─── Load node identity ─── */
    ret = load_node_uuid(opts->node_uuid_path, mnt->node_uuid, &mnt->node_id);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: failed to load or generate node identity: %d "
                     "(check disk permissions)", ret);
        goto err_free;
    }

    /* Auto-derive node_slot from node_id if not explicitly set.
     * This gives each node a different preferred AG for allocation. */
    if (opts->node_slot > 0)
        mnt->node_slot = opts->node_slot;
    else
        mnt->node_slot = mnt->node_id;

    /* ─── Open block device ─── */
    mxfs_pal_log(MXFS_LOG_DEBUG, "mount: opening device %s", opts->device);

    mnt->dev = mxfs_pal_bdev_open(opts->device);
    if (!mnt->dev) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mount: cannot open device %s", opts->device);
        ret = -EBUSY;
        goto err_free;
    }

    /* ─── Auto-detect MXFS on-disk super ─── */
    if (mnt->opts.journal_offset == 0 && mnt->opts.disklock_offset == 0) {
        uint64_t dev_size = 0;
        int det_ret = mxfs_pal_bdev_size(mnt->dev, &dev_size);
        if (det_ret == 0 && dev_size > MXFS_SUPER_SIZE) {
            struct mxfs_ondisk_super *ondisk;
            ondisk = mxfs_pal_alloc(MXFS_SUPER_SIZE);
            if (ondisk) {
                det_ret = mxfs_pal_bdev_read(mnt->dev,
                                              0,
                                              ondisk, MXFS_SUPER_SIZE);
                if (det_ret == 0 &&
                    ondisk->magic == MXFS_FORMAT_MAGIC &&
                    ondisk->version == MXFS_FORMAT_VERSION) {
                    uint32_t stored_crc = ondisk->crc;
                    ondisk->crc = 0;
                    uint32_t computed_crc = mxfs_pal_crc32c(
                        ~0U, ondisk, MXFS_SUPER_SIZE);
                    if (stored_crc == computed_crc) {
                        mnt->opts.journal_offset = ondisk->journal_offset;
                        mnt->opts.disklock_offset = ondisk->disklock_offset;
                        mnt->opts.xfs_data_offset = ondisk->xfs_data_offset;
                        mxfs_pal_log(MXFS_LOG_DEBUG,
                            "mount: auto-detected MXFS super "
                            "(journal=%llu, disklock=%llu, "
                            "xfs_data=%llu)",
                            (unsigned long long)ondisk->journal_offset,
                            (unsigned long long)ondisk->disklock_offset,
                            (unsigned long long)ondisk->xfs_data_offset);
                    } else {
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: filesystem metadata checksum mismatch "
                            "(will attempt standard XFS mount)");
                    }
                }
                mxfs_pal_free(ondisk);
            }
        }
    }

    /* ─── Create XFS data device (with base_offset) ─── */
    if (mnt->opts.xfs_data_offset > 0) {
        mnt->xfs_dev = mxfs_pal_bdev_clone_with_offset(
            mnt->dev, mnt->opts.xfs_data_offset);
        if (!mnt->xfs_dev) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: failed to create XFS data device clone");
            ret = -ENOMEM;
            goto err_close;
        }
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: XFS data at offset %llu",
                     (unsigned long long)mnt->opts.xfs_data_offset);
    } else {
        /* Legacy layout: XFS at offset 0 */
        mnt->xfs_dev = mnt->dev;
    }

    /* ─── Read XFS superblock ─── */
    ret = mxfs_xfs_read_superblock(mnt->xfs_dev, &mnt->sb);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: cannot read filesystem metadata from device: %d "
                     "(check device is accessible)", ret);
        goto err_close;
    }

    /* Compute volume ID from XFS UUID */
    mnt->volume_id = mxfs_uuid_to_volume_id(mnt->sb.uuid, 16);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: volume_id=0x%llx rootino=%llu "
                 "blocksize=%u agcount=%u",
                 (unsigned long long)mnt->volume_id,
                 (unsigned long long)mnt->sb.rootino,
                 mnt->sb.blocksize, mnt->sb.agcount);

    /* ─── Resolve DLM transport ─── */
    if (opts->dlm_transport == MXFS_DLM_TRANSPORT_AUTO) {
        /*
         * Auto-detect transport: listen for peer discovery announcements
         * for up to 3 seconds. If an existing cluster is found, adopt its
         * transport. If no peers, probe the device for SCSI CAW support.
         *
         * Bug 104: Without auto-detection, joining a TCP cluster with
         * the default CAW transport causes 30s DLM timeout on root inode
         * lock, and SCSI PR registration on non-CAW storage (e.g. QNAP)
         * causes reservation conflicts that block all disk I/O.
         */
        struct mxfs_discovery_ctx *probe_disc;
        int detected = -1;
        int probe_ms;

        probe_disc = mxfs_discovery_create(
            mnt->node_id, mnt->node_uuid, mnt->sb.uuid,
            mnt->volume_id, dlm_port, mcast_addr, disc_port,
            opts->use_broadcast);

        if (probe_disc) {
            /* Don't set peer callback — we just want to listen.
             * Start only the receiver thread, not sender (we don't
             * want to announce ourselves before we're ready). */
            mxfs_discovery_start_recv_only(probe_disc);

            /* Poll for 3 seconds in 100ms intervals */
            for (probe_ms = 0; probe_ms < 3000; probe_ms += 100) {
                mxfs_pal_mutex_lock(probe_disc->seen_lock);
                if (probe_disc->seen_count > 0) {
                    mxfs_pal_mutex_unlock(probe_disc->seen_lock);
                    detected = 1;  /* peers found */
                    break;
                }
                mxfs_pal_mutex_unlock(probe_disc->seen_lock);
                mxfs_pal_sleep_ms(100);
            }

            /* If peers found, we need their transport. The seen list
             * tells us peers exist, but we need the announce packet
             * to get the transport field. Receive one more packet. */
            if (detected > 0) {
                /* Listen for actual announce to extract transport.
                 * The recv_fn already received and validated packets.
                 * The transport from the latest packet is in the
                 * announce. We need to peek at incoming packets directly.
                 * Simpler: just read a packet from the socket now. */
                struct mxfs_discovery_announce peek;
                char peek_host[64];
                uint16_t peek_port;
                int peek_ret;
                int peek_tries;

                for (peek_tries = 0; peek_tries < 10; peek_tries++) {
                    memset(&peek, 0, sizeof(peek));
                    peek_ret = mxfs_pal_udp_recvfrom(probe_disc->sock,
                        &peek, sizeof(peek), peek_host, sizeof(peek_host),
                        &peek_port);
                    if (peek_ret >= (int)sizeof(peek) &&
                        mxfs_le32_to_cpu(peek.magic) == MXFS_DISCOVERY_MAGIC &&
                        memcmp(peek.volume_uuid,
                               probe_disc->local_announce.volume_uuid, 16) == 0 &&
                        memcmp(peek.node_uuid,
                               probe_disc->local_announce.node_uuid, 16) != 0) {
                        /* Got a valid peer announce — extract transport */
                        mnt->dlm_transport = (enum mxfs_dlm_transport)peek.dlm_transport;
                        mxfs_pal_log(MXFS_LOG_DEBUG,
                            "mount: auto-detected DLM transport=%s from peer %u (%s)",
                            mnt->dlm_transport == MXFS_DLM_TRANSPORT_TCP ? "tcp" : "caw",
                            peek.node_id, peek_host);
                        detected = 2;  /* transport resolved */
                        break;
                    }
                    mxfs_pal_sleep_ms(100);
                }
            }

            /* Stop and destroy the probe discovery */
            mxfs_discovery_stop(probe_disc);
            mxfs_discovery_destroy(probe_disc);
        }

        /* Sess26 NOTE: this file (dlm/mount.c) is USERSPACE, not part
         * of the kernel module.  The kernel uses dlm/v5_mount.c which
         * only supports CAW transport (see line ~206).  TCP transport
         * needs to be implemented in v5_mount.c first to be usable.
         * Sess27 work item. */
        if (detected < 2) {
            /* No peers found or couldn't read transport — probe device.
             * Try a SCSI Compare-And-Write on the first disklock slot.
             * If the device supports CAW, use it. Otherwise fall back to TCP. */
            if (mnt->opts.disklock_offset > 0) {
                void *caw_buf = mxfs_pal_alloc(1024);  /* 2x 512-byte sectors */
                if (caw_buf) {
                    int caw_ret;
                    void *compare = caw_buf;
                    void *write = (uint8_t *)caw_buf + 512;

                    /* Read current slot content for compare buffer */
                    caw_ret = mxfs_pal_bdev_read(mnt->dev,
                        mnt->opts.disklock_offset, compare, 512);
                    if (caw_ret == 0) {
                        /* Copy to write buffer (write same data back) */
                        memcpy(write, compare, 512);
                        caw_ret = mxfs_pal_bdev_compare_and_write(mnt->dev,
                            mnt->opts.disklock_offset, compare, write);
                        /* 0 = success (CAW supported)
                         * -EAGAIN = MISCOMPARE (CAW supported, data changed)
                         * -EOPNOTSUPP = not supported */
                        if (caw_ret == 0 || caw_ret == -EAGAIN) {
                            mnt->dlm_transport = MXFS_DLM_TRANSPORT_CAW;
                            mxfs_pal_log(MXFS_LOG_DEBUG,
                                "mount: auto-detected DLM transport=caw "
                                "(device supports SCSI CAW)");
                        } else {
                            mnt->dlm_transport = MXFS_DLM_TRANSPORT_TCP;
                            mxfs_pal_log(MXFS_LOG_DEBUG,
                                "mount: auto-detected DLM transport=tcp "
                                "(device does not support SCSI CAW, rc=%d)",
                                caw_ret);
                        }
                    } else {
                        mnt->dlm_transport = MXFS_DLM_TRANSPORT_TCP;
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mount: auto-detect CAW probe read failed: %d, "
                            "defaulting to tcp", caw_ret);
                    }
                    mxfs_pal_free(caw_buf);
                } else {
                    mnt->dlm_transport = MXFS_DLM_TRANSPORT_TCP;
                }
            } else {
                /* No disklock region — CAW not possible */
                mnt->dlm_transport = MXFS_DLM_TRANSPORT_TCP;
                mxfs_pal_log(MXFS_LOG_DEBUG,
                    "mount: auto-detected DLM transport=tcp "
                    "(no disklock region for CAW)");
            }
        }
    } else {
        mnt->dlm_transport = opts->dlm_transport;
    }

    /* Start BAST worker thread (shared by both transports) */
    mnt->bast_lock = mxfs_pal_mutex_create();
    mnt->bast_cond = mxfs_pal_cond_create();
    mnt->bast_head = NULL;
    mnt->bast_tail = NULL;
    mnt->bast_running = true;
    mnt->bast_thread = mxfs_pal_thread_create(bast_worker_fn, mnt);

    if (mnt->dlm_transport == MXFS_DLM_TRANSPORT_CAW) {
        /* ─── CAW DLM: disk-based locking, no TCP peer connections ─── */
        int node_slot;

        if (mnt->opts.disklock_offset == 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: CAW transport requires disklock_offset");
            ret = -EINVAL;
            goto err_close;
        }

        /* Bug 102: Register with SCSI PR BEFORE disklock claim_slot.
         * The reservation type is "Write Exclusive, registrants only"
         * so any disk write (including disklock heartbeat slot claim)
         * will get RESERVATION CONFLICT (-52) if this node isn't
         * registered first. */
        mnt->scsipr = mxfs_scsipr_create(mnt->dev, opts->device,
                                          mnt->node_id);
        if (mnt->scsipr) {
            ret = mxfs_scsipr_register(mnt->scsipr);
            if (ret) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: hardware-level node fencing not available "
                             "on this device (continuing with network-based "
                             "protection)");
                mxfs_scsipr_destroy(mnt->scsipr);
                mnt->scsipr = NULL;
            } else {
                mxfs_scsipr_reserve(mnt->scsipr);
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "mount: SCSI PR registered early for CAW");
            }
        }

        /* Create disklock early to claim a unique heartbeat slot (0-63)
         * which becomes the node's bit position in CAW DLM holder
         * bitmaps.  Bug 101: using node_id directly caused collisions
         * because 1ULL << node_id is UB for node_id >= 64. */
        mnt->disklock = mxfs_disklock_create(mnt->dev,
                                              mnt->opts.disklock_offset,
                                              mnt->node_id);
        if (!mnt->disklock) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: disklock create failed (required for CAW)");
            ret = -ENOMEM;
            goto err_close;
        }

        node_slot = mxfs_disklock_claim_slot(mnt->disklock);
        if (node_slot < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: disklock claim_slot failed: %d", node_slot);
            ret = node_slot;
            goto err_close;
        }

        mnt->dlm_caw = mxfs_dlm_caw_create(mnt->dev,
                                              mnt->opts.disklock_offset,
                                              mnt->node_id,
                                              (uint8_t)node_slot,
                                              mnt->sb.uuid,
                                              mnt->opts.max_dlm_lock_caw);
        if (!mnt->dlm_caw) {
            mxfs_pal_log(MXFS_LOG_ERR, "mount: CAW DLM create failed");
            ret = -ENOMEM;
            goto err_close;
        }

        mxfs_dlm_caw_set_bast_cb(mnt->dlm_caw, dlm_bast_cb_caw, mnt);

        /* Bug 102: Purge stale CAW locks at mount time.
         * After ungraceful shutdown, holder bits persist in on-disk lock
         * slots.  Build a bitmask of dead node slots, then do a single
         * pass through all 65536 lock slots to clear their bits.
         *
         * Our own slot is always purged: we just mounted, so any existing
         * lock bits for our slot are stale from a previous crash.
         * Other slots that are not ACTIVE are also dead. */
        {
            uint64_t dead_mask = 1ULL << node_slot;  /* always purge self */
            struct mxfs_disklock_heartbeat *hb_buf;
            uint32_t hb_slot;

            hb_buf = mxfs_pal_alloc(sizeof(*hb_buf));
            if (hb_buf) {
                for (hb_slot = 0; hb_slot < MXFS_DISKLOCK_HB_SLOTS;
                     hb_slot++) {
                    uint64_t off;
                    int rr;

                    if ((int)hb_slot == node_slot)
                        continue;

                    off = mnt->opts.disklock_offset +
                          (uint64_t)hb_slot *
                          MXFS_DISKLOCK_RECORD_SIZE;
                    rr = mxfs_pal_bdev_read(mnt->dev, off,
                                             hb_buf, sizeof(*hb_buf));
                    if (rr < 0 ||
                        hb_buf->magic != MXFS_DISKLOCK_MAGIC ||
                        hb_buf->flags != MXFS_DISKLOCK_FLAG_ACTIVE)
                        dead_mask |= (1ULL << hb_slot);
                }
                mxfs_pal_free(hb_buf);
            }

            if (dead_mask) {
                int npurged = mxfs_dlm_caw_purge_dead_nodes(
                                  mnt->dlm_caw, dead_mask);
                if (npurged > 0)
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: cleaned up %d stale lock entries "
                        "from previous session", npurged);
            }
        }

        ret = mxfs_dlm_caw_start(mnt->dlm_caw);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: disk-based lock subsystem failed to start: %d "
                         "(check device supports SCSI Compare-And-Write)", ret);
            mxfs_dlm_caw_destroy(mnt->dlm_caw);
            mnt->dlm_caw = NULL;
            goto err_close;
        }

        /* Start in single-node bypass mode — no disk I/O for locks
         * until a peer is discovered via discovery_peer_cb. */
        mxfs_dlm_caw_set_single_node(mnt->dlm_caw, true);

        /* Set transport-agnostic dispatch */
        mnt->dlm_lock_fn = dlm_lock_caw_wrapper;
        mnt->dlm_unlock_fn = dlm_unlock_caw_wrapper;
        mnt->dlm_convert_fn = dlm_convert_caw_wrapper;
        mnt->dlm_dispatch_ctx = mnt->dlm_caw;

        /* No TCP DLM, peer networking, or membership stabilization
         * needed with CAW — all lock coordination is disk-based */
        mnt->dlm = NULL;
        mnt->peer = NULL;

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: using CAW DLM transport (disk-based)");
    } else {
        /* ─── TCP DLM: network-based locking ─── */

        mnt->dlm = mxfs_dlm_create(mnt->node_id);
        if (!mnt->dlm) {
            mxfs_pal_log(MXFS_LOG_ERR, "mount: DLM create failed");
            ret = -ENOMEM;
            goto err_close;
        }

        /* Wire DLM callbacks */
        mnt->dlm->send_cb = dlm_send_cb;
        mnt->dlm->bast_cb = dlm_bast_cb;
        mnt->dlm->membership_cb = dlm_membership_cb;
        mnt->dlm->cb_data = mnt;

        /* Set transport-agnostic dispatch */
        mnt->dlm_lock_fn = dlm_lock_tcp_wrapper;
        mnt->dlm_unlock_fn = dlm_unlock_tcp_wrapper;
        mnt->dlm_convert_fn = dlm_convert_tcp_wrapper;
        mnt->dlm_dispatch_ctx = mnt->dlm;

        mnt->dlm_caw = NULL;

        /* ─── Init peer networking ─── */
        mnt->peer = mxfs_peer_init(mnt->node_id, mnt->node_uuid, dlm_port,
                                   mnt->volume_id);
        if (!mnt->peer) {
            mxfs_pal_log(MXFS_LOG_ERR, "mount: peer init failed");
            ret = -ENOMEM;
            goto err_dlm;
        }

        mxfs_peer_set_msg_cb(mnt->peer, peer_msg_cb, mnt);
        mxfs_peer_set_disconnect_cb(mnt->peer, peer_disconnect_cb, mnt);
        mxfs_peer_set_connect_cb(mnt->peer, peer_connect_cb, mnt);

        /* ─── Create membership stabilization lock/cond BEFORE peer_start ───
         *
         * Bug 81: peer_connect_cb calls queue_membership_update which needs
         * the stabilization lock.  If the lock is NULL (not yet created),
         * the fallback path fires mxfs_dlm_update_active_nodes immediately
         * — but the lease system may not be ready yet, so the active node
         * list is empty and the update is a no-op.  The membership never
         * converges because no further events trigger queue_membership_update.
         *
         * Fix: create the lock and cond here so queue_membership_update can
         * set pending + signal.  The actual worker thread is created later
         * (after lease_start) and will see any pending events on its first
         * iteration. */
        mnt->membership_stab_pending = 0;
        mnt->membership_stab_ts = 0;
        mnt->membership_stab_stop = 0;
        mnt->membership_stab_lock = mxfs_pal_mutex_create();
        mnt->membership_stab_cond = mxfs_pal_cond_create();
        if (!mnt->membership_stab_lock || !mnt->membership_stab_cond) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mount: membership stabilization mutex/cond create "
                         "failed, DLM updates will be immediate");
        }

        ret = mxfs_peer_start(mnt->peer);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: cluster networking failed to start: %d "
                         "(check network configuration and port availability)",
                         ret);
            goto err_peer;
        }

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: using TCP DLM transport (network-based)");
    }

    /* ─── Init SCSI PR ─── */
    /* Bug 102: CAW path registers early (before disklock claim_slot),
     * so skip if already registered.
     *
     * Bug 104: Skip SCSI PR entirely for TCP DLM. TCP DLM uses
     * network-based fencing (TCP connections + lease monitoring)
     * and does not need SCSI PR. On devices with broken PR
     * implementations (e.g., QNAP NAS), PR reservation causes
     * all disk I/O from other nodes to fail with -52 (RESERVATION
     * CONFLICT), crashing the entire cluster. */
    if (!mnt->scsipr && mnt->dlm_transport == MXFS_DLM_TRANSPORT_CAW) {
        mnt->scsipr = mxfs_scsipr_create(mnt->dev, opts->device, mnt->node_id);
        if (mnt->scsipr) {
            ret = mxfs_scsipr_register(mnt->scsipr);
            if (ret) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: hardware-level node fencing not "
                             "available: %d (continuing with network-based "
                             "protection)", ret);
                mxfs_scsipr_destroy(mnt->scsipr);
                mnt->scsipr = NULL;
            } else {
                mxfs_scsipr_reserve(mnt->scsipr);
            }
        }
    }

    /* ─── Init disklock ─── */
    if (mnt->opts.disklock_offset > 0) {
        /* For CAW transport, disklock was already created above for
         * slot claiming.  For TCP transport, create it here. */
        if (!mnt->disklock) {
            mnt->disklock = mxfs_disklock_create(mnt->dev,
                                                  mnt->opts.disklock_offset,
                                                  mnt->node_id);
            if (mnt->disklock)
                mxfs_disklock_claim_slot(mnt->disklock);
        }
        if (mnt->disklock) {
            ret = mxfs_disklock_start_heartbeat(mnt->disklock);
            if (ret) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: disk heartbeat could not be started: %d "
                             "(node failure detection may be delayed)", ret);
            }
            mxfs_disklock_set_expire_cb(mnt->disklock,
                                         disklock_expire_cb, mnt);
        }
    }

    /* ─── Init discovery ─── */
    mnt->discovery = mxfs_discovery_create(
        mnt->node_id, mnt->node_uuid, mnt->sb.uuid,
        mnt->volume_id, dlm_port, mcast_addr, disc_port,
        opts->use_broadcast);

    if (mnt->discovery) {
        mxfs_discovery_set_peer_cb(mnt->discovery, discovery_peer_cb, mnt);
        mxfs_discovery_set_transport(mnt->discovery,
                                      (uint8_t)mnt->dlm_transport);
        ret = mxfs_discovery_start(mnt->discovery);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: cluster auto-discovery failed to start: %d "
                         "(nodes must be added manually or check multicast "
                         "networking)", ret);
        }
    }

    /* ─── Init lease ─── */
    mnt->lease = mxfs_lease_create(mnt->node_id,
                                    mnt->sb.uuid,
                                    mcast_addr,
                                    0,  /* default port */
                                    opts->use_broadcast);
    if (mnt->lease) {
        mxfs_lease_set_expire_cb(mnt->lease, lease_expire_cb, mnt);
        mxfs_lease_start(mnt->lease);
    }

    /* ─── Init journal ─── */
    mnt->journal = mxfs_journal_create(mnt->node_id);
    if (mnt->journal) {
        int jslot;

        jslot = mxfs_journal_claim_slot(mnt->journal);
        if (jslot < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mount: journal claim_slot failed: %d", jslot);
            ret = jslot;
            goto err_subsystems;
        }

        /* Open on-disk journal if journal_offset is configured */
        if (mnt->opts.journal_offset > 0) {
            ret = mxfs_journal_open(mnt->journal, mnt->dev,
                                     mnt->opts.journal_offset);
            if (ret) {
                /* No journal super found — format it */
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "mount: journal open failed (%d), "
                             "formatting new journal", ret);
                ret = mxfs_journal_format(mnt->dev, mnt->opts.journal_offset,
                                           MXFS_MAX_NODES, mnt->sb.uuid);
                if (ret) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mount: journal format failed: %d", ret);
                    goto err_subsystems;
                }
                ret = mxfs_journal_open(mnt->journal, mnt->dev,
                                         mnt->opts.journal_offset);
                if (ret) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mount: journal re-open failed: %d", ret);
                    goto err_subsystems;
                }
            }

            /* Wire xfs_dev into journal for replay writes */
            mnt->journal->xfs_dev = mnt->xfs_dev;

            ret = mxfs_journal_slot_open(mnt->journal, jslot);
            if (ret) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mount: journal slot_open failed: %d", ret);
                goto err_subsystems;
            }

            /* If slot was dirty (previous crash), self-recover */
            if (mnt->journal->slot_dirty) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: recovering uncommitted changes from "
                             "previous session (this is normal after an "
                             "unexpected shutdown)");
                ret = mxfs_journal_replay(mnt->journal, jslot);
                if (ret) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mount: journal replay failed: %d", ret);
                    goto err_subsystems;
                }
            }

            /* Mark our slot dirty (we're active now) */
            ret = mxfs_journal_slot_mark_dirty(mnt->journal);
            if (ret) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mount: journal mark_dirty failed: %d", ret);
                /* Continue — journal works without persistent dirty flag */
            }
        }
    }

    /* ─── Init block cache ─── */
    mnt->bcache = mxfs_block_cache_create(mnt->xfs_dev, mnt->sb.blocksize,
                                           opts->max_block_cache);
    if (!mnt->bcache) {
        mxfs_pal_log(MXFS_LOG_ERR, "mount: block cache create failed");
        ret = -ENOMEM;
        goto err_subsystems;
    }

    /* ─── Init inode cache ─── */
    mnt->icache = mxfs_inode_cache_create(mnt->xfs_dev, &mnt->sb,
                                           mnt->bcache, mnt->dlm,
                                           mnt->volume_id,
                                           opts->max_inode_cache);
    if (!mnt->icache) {
        mxfs_pal_log(MXFS_LOG_ERR, "mount: inode cache create failed");
        ret = -ENOMEM;
        goto err_bcache;
    }

    /* Wire transport-agnostic DLM dispatch into inode cache */
    mnt->icache->dlm_lock_fn = mnt->dlm_lock_fn;
    mnt->icache->dlm_unlock_fn = mnt->dlm_unlock_fn;
    mnt->icache->dlm_convert_fn = mnt->dlm_convert_fn;
    mnt->icache->dlm_dispatch_ctx = mnt->dlm_dispatch_ctx;

    /* Wire journal into inode cache for metadata journaling */
    if (mnt->journal && mnt->opts.journal_offset > 0)
        mnt->icache->journal = mnt->journal;

    /* ─── Init dir cache ─── */
    mnt->dcache = mxfs_dir_cache_create(mnt->xfs_dev, &mnt->sb,
                                          mnt->bcache, mnt->icache,
                                          opts->max_dir_cache);
    if (!mnt->dcache) {
        mxfs_pal_log(MXFS_LOG_ERR, "mount: dir cache create failed");
        ret = -ENOMEM;
        goto err_icache;
    }

    /* Bug 76: wire dir cache into inode cache so complete_bast can
     * flush dirty dir entries before releasing the DLM lock */
    mnt->icache->dcache = mnt->dcache;

    /* ─── Init alloc ─── */
    mnt->alloc = mxfs_alloc_create(mnt->xfs_dev, &mnt->sb, mnt->bcache,
                                    mnt->dlm, mnt->volume_id,
                                    mnt->node_slot);
    if (!mnt->alloc) {
        mxfs_pal_log(MXFS_LOG_ERR, "mount: alloc create failed");
        ret = -ENOMEM;
        goto err_dcache;
    }

    /* Wire transport-agnostic DLM dispatch into alloc */
    mnt->alloc->dlm_lock_fn = mnt->dlm_lock_fn;
    mnt->alloc->dlm_unlock_fn = mnt->dlm_unlock_fn;
    mnt->alloc->dlm_dispatch_ctx = mnt->dlm_dispatch_ctx;

    /* Wire alloc into dir_cache for shortform-to-block upgrades */
    mxfs_dir_cache_set_alloc(mnt->dcache, mnt->alloc);

    /* Bug 109: wire alloc into inode cache for btree extent serialization */
    mnt->icache->alloc = mnt->alloc;

    /* Wire journal into alloc and dir_cache for metadata journaling */
    if (mnt->journal && mnt->opts.journal_offset > 0) {
        mnt->alloc->journal = mnt->journal;
        mnt->dcache->journal = mnt->journal;
    }

    /* Start in single-node mode (no peers yet).  Switched off when
     * the first peer connects via discovery_peer_cb. */
    mxfs_alloc_set_single_node(mnt->alloc, true);

    /* ─── Start membership stabilization timer thread ───
     *
     * Must be created after the lease subsystem is running (the worker
     * calls mxfs_lease_get_active_nodes) and before we set mounted=true
     * (which allows peer connections that trigger queue_membership_update).
     *
     * Bug 81: the lock and cond variables were already created before
     * peer_start (above) so that peer_connect_cb can safely call
     * queue_membership_update on early inbound connections.  We only
     * create the worker thread here, after the lease subsystem is
     * running.  Any events that arrived between lock creation and now
     * are captured in membership_stab_pending and will be processed
     * by the worker on its first iteration. */
    if (mnt->membership_stab_lock && mnt->membership_stab_cond) {
        mnt->membership_stab_thread = mxfs_pal_thread_create(
            membership_stab_worker_fn, mnt);
        if (!mnt->membership_stab_thread) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mount: membership stabilization thread create "
                         "failed, DLM updates will be immediate");
        }
    }

    /* ─── Start cache flush worker thread (Bug 66) ───
     *
     * Must be created after caches are initialized (it accesses
     * icache, bcache, dcache) and before mounted=true (which
     * enables the DLM membership callback to signal it). */
    mnt->cache_flush_pending = 0;
    mnt->cache_flush_stop = 0;
    mnt->cache_flush_lock = mxfs_pal_mutex_create();
    mnt->cache_flush_cond = mxfs_pal_cond_create();
    if (mnt->cache_flush_lock && mnt->cache_flush_cond) {
        mnt->cache_flush_thread = mxfs_pal_thread_create(
            cache_flush_worker_fn, mnt);
        if (!mnt->cache_flush_thread) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mount: cache flush thread create failed, "
                         "membership changes will flush synchronously");
        }
    } else {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mount: cache flush mutex/cond create failed, "
                     "membership changes will flush synchronously");
    }

    mnt->mounted = true;
    *mnt_out = mnt;

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mount: MXFS mounted successfully on %s "
                 "(node_id=%u, volume_id=0x%llx)",
                 opts->device, mnt->node_id,
                 (unsigned long long)mnt->volume_id);

    return 0;

    /* ─── Error cleanup (reverse order) ─── */
err_dcache:
    mxfs_dir_cache_destroy(mnt->dcache);
err_icache:
    mxfs_inode_cache_destroy(mnt->icache);
err_bcache:
    mxfs_block_cache_destroy(mnt->bcache);
err_subsystems:
    if (mnt->journal) {
        mxfs_journal_release_slot(mnt->journal);
        mxfs_journal_destroy(mnt->journal);
    }
    if (mnt->lease) {
        mxfs_lease_stop(mnt->lease);
        mxfs_lease_destroy(mnt->lease);
    }
    if (mnt->discovery) {
        mxfs_discovery_stop(mnt->discovery);
        mxfs_discovery_destroy(mnt->discovery);
    }
    if (mnt->disklock) {
        mxfs_disklock_stop_heartbeat(mnt->disklock);
        mxfs_disklock_destroy(mnt->disklock);
        mnt->disklock = NULL;
    }
    if (mnt->scsipr) {
        mxfs_scsipr_unregister(mnt->scsipr);
        mxfs_scsipr_destroy(mnt->scsipr);
    }
err_peer:
    if (mnt->peer)
        mxfs_peer_shutdown(mnt->peer);
    if (mnt->membership_stab_cond) {
        mxfs_pal_cond_destroy(mnt->membership_stab_cond);
        mnt->membership_stab_cond = NULL;
    }
    if (mnt->membership_stab_lock) {
        mxfs_pal_mutex_destroy(mnt->membership_stab_lock);
        mnt->membership_stab_lock = NULL;
    }
err_dlm:
    if (mnt->bast_thread) {
        mxfs_pal_mutex_lock(mnt->bast_lock);
        mnt->bast_running = false;
        mxfs_pal_cond_signal(mnt->bast_cond);
        mxfs_pal_mutex_unlock(mnt->bast_lock);
        mxfs_pal_thread_join(mnt->bast_thread);
    }
    if (mnt->bast_cond)
        mxfs_pal_cond_destroy(mnt->bast_cond);
    if (mnt->bast_lock)
        mxfs_pal_mutex_destroy(mnt->bast_lock);
    if (mnt->dlm)
        mxfs_dlm_destroy(mnt->dlm);
    if (mnt->dlm_caw) {
        mxfs_dlm_caw_stop(mnt->dlm_caw);
        mxfs_dlm_caw_destroy(mnt->dlm_caw);
    }
err_close:
    /* Disklock may have been created early for CAW slot claiming */
    if (mnt->disklock) {
        mxfs_disklock_stop_heartbeat(mnt->disklock);
        mxfs_disklock_destroy(mnt->disklock);
        mnt->disklock = NULL;
    }
    /* Bug 102: SCSI PR may have been registered early for CAW */
    if (mnt->scsipr) {
        mxfs_scsipr_unregister(mnt->scsipr);
        mxfs_scsipr_destroy(mnt->scsipr);
        mnt->scsipr = NULL;
    }
    if (mnt->xfs_dev && mnt->xfs_dev != mnt->dev) {
        mxfs_pal_bdev_close_clone(mnt->xfs_dev);
        mnt->xfs_dev = NULL;
    }
    mxfs_pal_bdev_close(mnt->dev);
err_free:
    if (mnt->recovery_lock)
        mxfs_pal_mutex_destroy(mnt->recovery_lock);
    mxfs_pal_free(mnt);
    return ret;
}

void mxfs_unmount(struct mxfs_mount *mnt)
{
    if (!mnt)
        return;

    mxfs_pal_log(MXFS_LOG_INFO, "mount: unmounting %s", mnt->dev_path);
    mxfs_pal_log(MXFS_LOG_INFO,
        "hot-path timing: create=%llums/%llu mkdir=%llums/%llu "
        "write=%llums/%llu",
        (unsigned long long)mnt->stat_create_ms,
        (unsigned long long)mnt->stat_create_count,
        (unsigned long long)mnt->stat_mkdir_ms,
        (unsigned long long)mnt->stat_mkdir_count,
        (unsigned long long)mnt->stat_write_ms,
        (unsigned long long)mnt->stat_write_count);
    mxfs_pal_log(MXFS_LOG_INFO,
        "create breakdown: alloc=%llums getex=%llums init=%llums "
        "diradd=%llums",
        (unsigned long long)mnt->stat_create_alloc_ms,
        (unsigned long long)mnt->stat_create_getex_ms,
        (unsigned long long)mnt->stat_create_init_ms,
        (unsigned long long)mnt->stat_create_diradd_ms);

    mnt->mounted = false;

    /* ─── Join any in-flight journal recovery thread ───
     *
     * The recovery thread uses mnt->dlm, mnt->journal, and caches,
     * so it must complete before we tear down any subsystem. */
    if (mnt->recovery_lock) {
        mxfs_pal_mutex_lock(mnt->recovery_lock);
        if (mnt->recovery_thread) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "mount: waiting for journal recovery thread "
                         "to finish before unmount");
            mxfs_pal_mutex_unlock(mnt->recovery_lock);
            mxfs_pal_thread_join(mnt->recovery_thread);
            mxfs_pal_mutex_lock(mnt->recovery_lock);
            mnt->recovery_thread = NULL;
        }
        mxfs_pal_mutex_unlock(mnt->recovery_lock);
    }

    /* ─── Stop membership stabilization timer thread ───
     *
     * Must stop before tearing down the lease subsystem (the worker
     * calls mxfs_lease_get_active_nodes) and before destroying the
     * DLM (the worker calls mxfs_dlm_update_active_nodes).
     * Setting the stop flag causes the worker to process any pending
     * update immediately and then exit. */
    if (mnt->membership_stab_thread) {
        mxfs_pal_mutex_lock(mnt->membership_stab_lock);
        mnt->membership_stab_stop = 1;
        mxfs_pal_cond_signal(mnt->membership_stab_cond);
        mxfs_pal_mutex_unlock(mnt->membership_stab_lock);
        mxfs_pal_thread_join(mnt->membership_stab_thread);
        mnt->membership_stab_thread = NULL;
    }
    if (mnt->membership_stab_cond) {
        mxfs_pal_cond_destroy(mnt->membership_stab_cond);
        mnt->membership_stab_cond = NULL;
    }
    if (mnt->membership_stab_lock) {
        mxfs_pal_mutex_destroy(mnt->membership_stab_lock);
        mnt->membership_stab_lock = NULL;
    }

    /* ─── Stop cache flush worker thread (Bug 66) ───
     *
     * Must stop before flushing caches and tearing down subsystems,
     * because the worker accesses icache, bcache, and dcache.
     * Setting mounted=false above prevents new flush cycles from
     * running, and cache_flush_stop breaks out of the wait loop. */
    if (mnt->cache_flush_thread) {
        mxfs_pal_mutex_lock(mnt->cache_flush_lock);
        mnt->cache_flush_stop = 1;
        mxfs_pal_cond_signal(mnt->cache_flush_cond);
        mxfs_pal_mutex_unlock(mnt->cache_flush_lock);
        mxfs_pal_thread_join(mnt->cache_flush_thread);
        mnt->cache_flush_thread = NULL;
    }
    if (mnt->cache_flush_cond) {
        mxfs_pal_cond_destroy(mnt->cache_flush_cond);
        mnt->cache_flush_cond = NULL;
    }
    if (mnt->cache_flush_lock) {
        mxfs_pal_mutex_destroy(mnt->cache_flush_lock);
        mnt->cache_flush_lock = NULL;
    }

    /* ─── Set shutdown flag BEFORE flushing caches ───
     *
     * This prevents the cross-node deadlock where 2+ nodes unmounting
     * simultaneously each try to acquire a DLM lock mastered by the
     * other. With shutting_down set, mxfs_dlm_lock() returns -ESHUTDOWN
     * immediately for any NEW lock acquisition attempt. Existing held
     * locks remain valid for flushing. */
    if (mnt->dlm)
        mnt->dlm->shutting_down = true;
    /* CAW DLM has no shutting_down flag — it uses a running flag
     * that is cleared by mxfs_dlm_caw_stop() during shutdown. */

    /* ─── Flush dirty data using ALREADY-HELD locks ───
     *
     * With shutting_down set, flush functions will skip entries where
     * we don't already hold a sufficient lock. Data for skipped entries
     * was either already flushed during normal operation or will be
     * recovered by journal replay on next mount. */
    if (mnt->dcache)
        mxfs_dir_cache_flush_all(mnt->dcache);

    if (mnt->icache)
        mxfs_inode_cache_flush_all(mnt->icache);

    if (mnt->bcache)
        mxfs_block_cache_flush(mnt->bcache);

    /* ─── Notify peers we are leaving ─── */
    if (mnt->peer && mnt->dlm) {
        struct mxfs_dlm_node_msg leave;

        memset(&leave, 0, sizeof(leave));
        leave.hdr.magic = MXFS_DLM_MAGIC;
        leave.hdr.version = MXFS_DLM_VERSION;
        leave.hdr.type = MXFS_MSG_NODE_LEAVE;
        leave.hdr.length = sizeof(leave);
        leave.hdr.sender = mnt->node_id;
        leave.hdr.epoch = mxfs_dlm_get_epoch(mnt->dlm);

        mxfs_peer_broadcast(mnt->peer, &leave, sizeof(leave));
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: sent NODE_LEAVE to all peers");
    }

    /* ─── Shutdown in reverse order ─── */

    /* Stop discovery and lease first (stop advertising, stop checking) */
    if (mnt->discovery) {
        mxfs_discovery_stop(mnt->discovery);
        mxfs_discovery_destroy(mnt->discovery);
        mnt->discovery = NULL;
    }

    if (mnt->lease) {
        mxfs_lease_stop(mnt->lease);
        mxfs_lease_destroy(mnt->lease);
        mnt->lease = NULL;
    }

    /* Write clean unmount marker and release journal slot */
    if (mnt->journal) {
        if (mnt->journal->dev) {
            mxfs_journal_write_unmount(mnt->journal);
            mxfs_journal_slot_mark_clean(mnt->journal);
        }
        mxfs_journal_release_slot(mnt->journal);
        mxfs_journal_destroy(mnt->journal);
        mnt->journal = NULL;
    }

    /* Stop BAST worker thread */
    if (mnt->bast_thread) {
        mxfs_pal_mutex_lock(mnt->bast_lock);
        mnt->bast_running = false;
        mxfs_pal_cond_signal(mnt->bast_cond);
        mxfs_pal_mutex_unlock(mnt->bast_lock);
        mxfs_pal_thread_join(mnt->bast_thread);
        mnt->bast_thread = NULL;
    }
    if (mnt->bast_cond) {
        mxfs_pal_cond_destroy(mnt->bast_cond);
        mnt->bast_cond = NULL;
    }
    if (mnt->bast_lock) {
        mxfs_pal_mutex_destroy(mnt->bast_lock);
        mnt->bast_lock = NULL;
    }

    /* Release cached AG lock — flush dirty AG metadata to disk before
     * the bulk DLM release below.  Must happen while DLM is still alive. */
    if (mnt->alloc)
        mxfs_alloc_release_cached_ag(mnt->alloc);

    /* Release DLM locks early (before destroying caches) so that
     * cache destruction doesn't attempt DLM operations */
    if (mnt->dlm)
        mxfs_dlm_release_all(mnt->dlm);
    if (mnt->dlm_caw)
        mxfs_dlm_caw_release_all(mnt->dlm_caw);

    /* Destroy caches (dirty data was already flushed above) */
    if (mnt->dcache) {
        mxfs_dir_cache_destroy(mnt->dcache);
        mnt->dcache = NULL;
    }

    if (mnt->icache) {
        mxfs_inode_cache_destroy(mnt->icache);
        mnt->icache = NULL;
    }

    if (mnt->bcache) {
        mxfs_block_cache_destroy(mnt->bcache);
        mnt->bcache = NULL;
    }

    /* Destroy alloc */
    if (mnt->alloc) {
        mxfs_alloc_destroy(mnt->alloc);
        mnt->alloc = NULL;
    }

    /* Bug 100: Shutdown peer networking BEFORE destroying disklock.
     * Peer recv threads call peer_disconnect_cb → disklock_purge_node
     * during disconnect handling. If disklock is freed while recv
     * threads are still running, purge_node hits freed memory.
     * Joining all recv threads first guarantees no more callbacks. */
    if (mnt->peer) {
        mxfs_peer_shutdown(mnt->peer);
        mnt->peer = NULL;
    }

    /* Stop disklock heartbeat (safe now — no more peer callbacks) */
    if (mnt->disklock) {
        mxfs_disklock_stop_heartbeat(mnt->disklock);
        mxfs_disklock_destroy(mnt->disklock);
        mnt->disklock = NULL;
    }

    /* Unregister and destroy SCSI PR */
    if (mnt->scsipr) {
        mxfs_scsipr_unregister(mnt->scsipr);
        mxfs_scsipr_destroy(mnt->scsipr);
        mnt->scsipr = NULL;
    }

    /* Destroy DLM */
    if (mnt->dlm) {
        mxfs_dlm_destroy(mnt->dlm);
        mnt->dlm = NULL;
    }
    if (mnt->dlm_caw) {
        mxfs_dlm_caw_stop(mnt->dlm_caw);
        mxfs_dlm_caw_destroy(mnt->dlm_caw);
        mnt->dlm_caw = NULL;
    }

    /* Close XFS data device clone (if not the same as dev) */
    if (mnt->xfs_dev && mnt->xfs_dev != mnt->dev) {
        mxfs_pal_bdev_close_clone(mnt->xfs_dev);
        mnt->xfs_dev = NULL;
    }

    /* Close block device */
    if (mnt->dev) {
        mxfs_pal_bdev_close(mnt->dev);
        mnt->dev = NULL;
    }

    /* Destroy recovery serialization lock */
    if (mnt->recovery_lock) {
        mxfs_pal_mutex_destroy(mnt->recovery_lock);
        mnt->recovery_lock = NULL;
    }

    mxfs_pal_log(MXFS_LOG_INFO, "mount: unmount complete");

    mxfs_pal_free(mnt);
}

/* ─── Public API: Path operations ─── */

int mxfs_lookup(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen,
                uint64_t *ino_out)
{
    if (!mnt || !mnt->mounted)
        return -EINVAL;

    return mxfs_dir_lookup(mnt->dcache, dir_ino, name, namelen, ino_out);
}

int mxfs_stat(struct mxfs_mount *mnt, uint64_t ino,
              struct mxfs_stat *st)
{
    struct mxfs_cached_inode *ci;
    int err;

    if (!mnt || !mnt->mounted || !st)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err;

    st->ino = ci->ino;
    st->mode = ci->mode;
    st->nlink = ci->nlink;
    st->uid = ci->uid;
    st->gid = ci->gid;
    st->size = ci->size;
    st->atime_sec = ci->atime_sec;
    st->atime_nsec = ci->atime_nsec;
    st->mtime_sec = ci->mtime_sec;
    st->mtime_nsec = ci->mtime_nsec;
    st->ctime_sec = ci->ctime_sec;
    st->ctime_nsec = ci->ctime_nsec;
    st->rdev = ci->rdev;
    st->blksize = mnt->sb.blocksize;

    /* Compute block count from extent map */
    if (ci->extents) {
        uint64_t total_blocks = 0;
        int ec = mxfs_extent_map_count(ci->extents);
        int i;
        for (i = 0; i < ec; i++) {
            const struct mxfs_extent *ext = mxfs_extent_map_get(ci->extents, i);
            if (ext)
                total_blocks += ext->blockcount;
        }
        st->blocks = total_blocks * (mnt->sb.blocksize / 512);
    } else {
        st->blocks = (ci->size + 511) / 512;
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

/* ─── Fast path: check if we have cluster peers ─── */

static inline bool mxfs_has_peers(struct mxfs_mount *mnt)
{
    return mnt->peer && mnt->peer->peer_count > 0;
}

/* ─── Fast path: direct bdev read bypassing block cache ─── */

static int64_t mxfs_read_direct(struct mxfs_mount *mnt,
                                 struct mxfs_cached_inode *ci,
                                 uint8_t *dst, uint64_t offset, uint32_t len)
{
    uint64_t bytes_read = 0;

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);

        if (phys_block == MXFS_EXTENT_HOLE ||
            (flags & MXFS_EXTENT_F_UNWRITTEN)) {
            /* Hole or unwritten: zero-fill contiguous hole region */
            uint32_t zero_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;

            while (zero_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != MXFS_EXTENT_HOLE &&
                    !(nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                zero_bytes += mnt->sb.blocksize;
                next_logical++;
            }

            if (zero_bytes > len)
                zero_bytes = len;

            memset(dst, 0, zero_bytes);
            dst += zero_bytes;
            offset += zero_bytes;
            len -= zero_bytes;
            bytes_read += zero_bytes;
            continue;
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            uint64_t disk_offset;
            int rret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE ||
                    (nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            /* Direct bdev read — bypass block cache entirely */
            disk_offset = phys_block * mnt->sb.blocksize + block_off;

            /* bdev_read requires sector-aligned offset and length.
             * If block_off != 0 (partial first block), we must read
             * the whole block and copy the needed portion. */
            if (block_off != 0 || (contig_bytes % mnt->sb.blocksize) != 0) {
                /* Align to block boundaries for the bdev read */
                uint64_t aligned_offset = phys_block * mnt->sb.blocksize;
                uint32_t total_blocks = (block_off + contig_bytes +
                                          mnt->sb.blocksize - 1) /
                                         mnt->sb.blocksize;
                uint32_t aligned_len = total_blocks * mnt->sb.blocksize;
                uint8_t *tmpbuf;

                tmpbuf = mxfs_pal_alloc(aligned_len);
                if (!tmpbuf) {
                    if (bytes_read > 0)
                        break;
                    return -ENOMEM;
                }

                rret = mxfs_pal_bdev_read(mnt->xfs_dev, aligned_offset,
                                           tmpbuf, aligned_len);
                if (rret) {
                    mxfs_pal_free(tmpbuf);
                    if (bytes_read > 0)
                        break;
                    return rret;
                }

                memcpy(dst, tmpbuf + block_off, contig_bytes);
                mxfs_pal_free(tmpbuf);
            } else {
                /* Block-aligned: use pipelined async read for O_DIRECT
                 * data. Submits up to 16 bios concurrently. */
                rret = mxfs_pal_bdev_read_async(mnt->xfs_dev, disk_offset,
                                                 dst, contig_bytes);
                if (rret) {
                    if (bytes_read > 0)
                        break;
                    return rret;
                }
            }

            dst += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_read += contig_bytes;
        }
    }

    return (int64_t)bytes_read;
}

/* ─── Fast path: direct bdev write bypassing block cache ─── */

static int64_t mxfs_write_direct(struct mxfs_mount *mnt,
                                   struct mxfs_cached_inode *ci,
                                   const uint8_t *src,
                                   uint64_t offset, uint32_t len)
{
    uint64_t bytes_written = 0;

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;
        bool is_new = false;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);
        if (phys_block == MXFS_EXTENT_HOLE) {
            /* Allocate blocks for this hole region */
            uint64_t alloc_fsblock;
            uint32_t alloc_len;
            uint32_t wanted;
            int alloc_ret;

            wanted = (uint32_t)((offset + len + mnt->sb.blocksize - 1)
                     / mnt->sb.blocksize - logical_block);
            if (wanted < 1)
                wanted = 1;
            if (wanted > 256)
                wanted = 256;

            alloc_ret = mxfs_alloc_blocks(mnt->alloc, wanted, 0,
                                           &alloc_fsblock, &alloc_len);
            if (alloc_ret) {
                if (bytes_written > 0)
                    break;
                return alloc_ret;
            }

            alloc_ret = mxfs_extent_map_insert(ci->extents,
                                                logical_block,
                                                alloc_fsblock,
                                                alloc_len, false);
            if (alloc_ret) {
                if (bytes_written > 0)
                    break;
                return alloc_ret;
            }

            ci->nextents = mxfs_extent_map_count(ci->extents);
            mxfs_inode_cache_dirty(mnt->icache, ci);
            is_new = true;

            phys_block = mxfs_extent_map_lookup(ci->extents,
                                                 logical_block, &flags);
            if (phys_block == MXFS_EXTENT_HOLE) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mount: alloc succeeded but lookup still "
                             "returns hole for ino %llu block %llu",
                             (unsigned long long)ci->ino,
                             (unsigned long long)logical_block);
                break;
            }
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            uint64_t disk_offset;
            int wret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE)
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            /* Direct bdev write — bypass block cache entirely */
            disk_offset = phys_block * mnt->sb.blocksize + block_off;

            if (block_off != 0 || (contig_bytes % mnt->sb.blocksize) != 0) {
                /* Partial block: need read-modify-write */
                uint64_t aligned_offset = phys_block * mnt->sb.blocksize;
                uint32_t total_blocks = (block_off + contig_bytes +
                                          mnt->sb.blocksize - 1) /
                                         mnt->sb.blocksize;
                uint32_t aligned_len = total_blocks * mnt->sb.blocksize;
                uint8_t *tmpbuf;

                tmpbuf = mxfs_pal_alloc(aligned_len);
                if (!tmpbuf) {
                    if (bytes_written > 0)
                        break;
                    return -ENOMEM;
                }

                if (!is_new) {
                    /* Read existing blocks first */
                    wret = mxfs_pal_bdev_read(mnt->xfs_dev, aligned_offset,
                                               tmpbuf, aligned_len);
                    if (wret) {
                        mxfs_pal_free(tmpbuf);
                        if (bytes_written > 0)
                            break;
                        return wret;
                    }
                } else {
                    memset(tmpbuf, 0, aligned_len);
                }

                /* Overlay write data */
                memcpy(tmpbuf + block_off, src, contig_bytes);

                wret = mxfs_pal_bdev_write(mnt->xfs_dev, aligned_offset,
                                            tmpbuf, aligned_len);
                mxfs_pal_free(tmpbuf);

                if (wret) {
                    if (bytes_written > 0)
                        break;
                    return wret;
                }
            } else {
                /* Block-aligned: use pipelined async write for O_DIRECT
                 * data. Submits up to 16 bios concurrently instead of
                 * one-at-a-time submit_bio_wait, achieving real I/O
                 * parallelism that closes the gap with XFS iomap_dio. */
                wret = mxfs_pal_bdev_write_async(mnt->xfs_dev, disk_offset,
                                                  src, contig_bytes);
                if (wret) {
                    if (bytes_written > 0)
                        break;
                    return wret;
                }
            }

            src += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_written += contig_bytes;
        }
    }

    return (int64_t)bytes_written;
}

/* ─── Public API: File I/O ─── */

int64_t mxfs_read(struct mxfs_mount *mnt, uint64_t ino,
                   void *buf, uint64_t offset, uint32_t len)
{
    struct mxfs_cached_inode *ci;
    int err;
    uint64_t bytes_read = 0;
    uint8_t *dst = (uint8_t *)buf;

    if (!mnt || !mnt->mounted || !buf)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err;

    /* Clamp to file size */
    if (offset >= ci->size) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }
    if (offset + len > ci->size)
        len = (uint32_t)(ci->size - offset);

    /* Handle inline data (FMT_LOCAL) */
    if (ci->format == XFS_DINODE_FMT_LOCAL) {
        if (ci->inline_data && (int64_t)offset < ci->inline_len) {
            uint32_t avail = ci->inline_len - (uint32_t)offset;
            uint32_t copy = len < avail ? len : avail;
            memcpy(dst, (const uint8_t *)ci->inline_data + offset, copy);
            bytes_read = copy;
        }
        mxfs_inode_cache_put(mnt->icache, ci);
        return (int64_t)bytes_read;
    }

    /* Extent-based read */
    if (!ci->extents) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -EIO;
    }

    /* Fast path: no cluster peers — bypass block cache entirely.
     * Reads directly from device into the output buffer, avoiding
     * per-block hash lookups, LRU management, and memcpy through
     * the cache layer. Falls through to the normal cached path
     * when peers are connected (coherency needed). */
    if (!mxfs_has_peers(mnt)) {
        int64_t ret = mxfs_read_direct(mnt, ci, dst, offset, len);
        mxfs_inode_cache_put(mnt->icache, ci);
        return ret;
    }

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);

        if (phys_block == MXFS_EXTENT_HOLE ||
            (flags & MXFS_EXTENT_F_UNWRITTEN)) {
            /* Hole or unwritten: zero-fill contiguous hole region */
            uint32_t zero_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;

            while (zero_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != MXFS_EXTENT_HOLE &&
                    !(nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                zero_bytes += mnt->sb.blocksize;
                next_logical++;
            }

            if (zero_bytes > len)
                zero_bytes = len;

            memset(dst, 0, zero_bytes);
            dst += zero_bytes;
            offset += zero_bytes;
            len -= zero_bytes;
            bytes_read += zero_bytes;
            continue;
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            int rret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE ||
                    (nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            /* Bulk read from block cache with read-ahead */
            rret = mxfs_block_cache_read_range(mnt->bcache, phys_block,
                                                block_off, dst,
                                                contig_bytes);
            if (rret) {
                if (bytes_read > 0)
                    break;
                mxfs_inode_cache_put(mnt->icache, ci);
                return rret;
            }

            dst += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_read += contig_bytes;
        }
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return (int64_t)bytes_read;
}

/*
 * Internal: read data from a file using a pre-acquired cached inode.
 * The caller must hold a reference on ci (refcount > 0).
 * Does not acquire or release the inode DLM lock.
 * Returns bytes read, or negative errno.
 */
static int64_t mxfs_read_pinned(struct mxfs_mount *mnt,
                                  struct mxfs_cached_inode *ci,
                                  uint8_t *dst, uint64_t offset,
                                  uint32_t len)
{
    uint64_t bytes_read = 0;

    /* Clamp to file size */
    if (offset >= ci->size)
        return 0;
    if (offset + len > ci->size)
        len = (uint32_t)(ci->size - offset);

    /* Handle inline data (FMT_LOCAL) */
    if (ci->format == XFS_DINODE_FMT_LOCAL) {
        if (ci->inline_data && (int64_t)offset < ci->inline_len) {
            uint32_t avail = ci->inline_len - (uint32_t)offset;
            uint32_t copy = len < avail ? len : avail;
            memcpy(dst, (const uint8_t *)ci->inline_data + offset, copy);
            return (int64_t)copy;
        }
        return 0;
    }

    /* Extent-based read */
    if (!ci->extents)
        return -EIO;

    /* Fast path: no cluster peers — bypass block cache entirely */
    if (!mxfs_has_peers(mnt))
        return mxfs_read_direct(mnt, ci, dst, offset, len);

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);

        if (phys_block == MXFS_EXTENT_HOLE ||
            (flags & MXFS_EXTENT_F_UNWRITTEN)) {
            uint32_t zero_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;

            while (zero_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != MXFS_EXTENT_HOLE &&
                    !(nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                zero_bytes += mnt->sb.blocksize;
                next_logical++;
            }

            if (zero_bytes > len)
                zero_bytes = len;

            memset(dst, 0, zero_bytes);
            dst += zero_bytes;
            offset += zero_bytes;
            len -= zero_bytes;
            bytes_read += zero_bytes;
            continue;
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            int rret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE ||
                    (nflags & MXFS_EXTENT_F_UNWRITTEN))
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            rret = mxfs_block_cache_read_range(mnt->bcache, phys_block,
                                                block_off, dst,
                                                contig_bytes);
            if (rret) {
                if (bytes_read > 0)
                    break;
                return rret;
            }

            dst += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_read += contig_bytes;
        }
    }

    return (int64_t)bytes_read;
}

int64_t mxfs_read_bulk(struct mxfs_mount *mnt, uint64_t ino,
                        uint64_t offset, uint64_t total_len,
                        uint32_t chunk_size,
                        mxfs_read_chunk_fn cb, void *ctx,
                        uint64_t *size_out)
{
    struct mxfs_cached_inode *ci;
    int err;
    uint64_t total_read = 0;
    uint8_t *buf;

    if (!mnt || !mnt->mounted || !cb)
        return -EINVAL;

    if (chunk_size == 0)
        chunk_size = 4 * 1024 * 1024;  /* 4MB default */

    /* Acquire inode with PR lock — held for entire bulk read */
    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err;

    /* Report file size to caller */
    if (size_out)
        *size_out = ci->size;

    /* Clamp to file size */
    if (offset >= ci->size) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }
    if (offset + total_len > ci->size)
        total_len = ci->size - offset;

    /* Allocate the I/O buffer — sized to actual need, not the full
     * chunk_size (which defaults to 4MB). A 4K read should not trigger
     * an order-10 kmalloc for 1024 contiguous pages. */
    {
        size_t alloc_size = (size_t)chunk_size;
        if ((uint64_t)alloc_size > total_len)
            alloc_size = (size_t)total_len;
        buf = mxfs_pal_alloc(alloc_size);
    }
    if (!buf) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENOMEM;
    }

    while (total_read < total_len) {
        uint32_t chunk = chunk_size;
        int64_t nread;
        int cb_ret;

        if ((uint64_t)chunk > total_len - total_read)
            chunk = (uint32_t)(total_len - total_read);

        nread = mxfs_read_pinned(mnt, ci, buf, offset + total_read, chunk);
        if (nread < 0) {
            if (total_read > 0)
                break;
            mxfs_pal_free(buf);
            mxfs_inode_cache_put(mnt->icache, ci);
            return nread;
        }
        if (nread == 0)
            break;

        /* Deliver chunk to caller */
        cb_ret = cb(ctx, buf, (uint32_t)nread);
        if (cb_ret) {
            if (total_read > 0)
                break;
            mxfs_pal_free(buf);
            mxfs_inode_cache_put(mnt->icache, ci);
            return cb_ret;
        }

        total_read += (uint64_t)nread;

        /* Short read means EOF */
        if (nread < (int64_t)chunk)
            break;

        /* Yield periodically to prevent soft lockups.
         * This is critical in kernel context: without yielding,
         * a 50MB read can hold the CPU for seconds doing iSCSI I/O,
         * starving the lease renewal thread and triggering the
         * kernel soft lockup watchdog. */
        mxfs_pal_cond_resched();
    }

    mxfs_pal_free(buf);
    mxfs_inode_cache_put(mnt->icache, ci);
    return (int64_t)total_read;
}

int64_t mxfs_write(struct mxfs_mount *mnt, uint64_t ino,
                    const void *buf, uint64_t offset, uint32_t len)
{
    struct mxfs_cached_inode *ci;
    int err;
    uint64_t bytes_written = 0;
    const uint8_t *src = (const uint8_t *)buf;

    if (!mnt || !mnt->mounted || !buf)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    /* Handle inline data (FMT_LOCAL) */
    if (ci->format == XFS_DINODE_FMT_LOCAL) {
        int new_size = (int)(offset + len);
        int max_inline = ci->raw_len - ci->core_size;

        if (new_size > max_inline) {
            /* Would need to convert to extent format — not supported yet */
            mxfs_inode_cache_put(mnt->icache, ci);
            return -ENOSPC;
        }

        /* Grow inline buffer if needed */
        if (new_size > ci->inline_len) {
            void *new_buf = mxfs_pal_alloc(new_size);
            if (!new_buf) {
                mxfs_inode_cache_put(mnt->icache, ci);
                return -ENOMEM;
            }
            memset(new_buf, 0, new_size);
            if (ci->inline_data && ci->inline_len > 0)
                memcpy(new_buf, ci->inline_data, ci->inline_len);
            if (ci->inline_data)
                mxfs_pal_free(ci->inline_data);
            ci->inline_data = new_buf;
            ci->inline_len = new_size;
        }

        memcpy((uint8_t *)ci->inline_data + offset, src, len);
        if ((uint64_t)new_size > ci->size)
            ci->size = new_size;

        /* Update mtime and ctime on successful write */
        {
            uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
            ci->mtime_sec = now;
            ci->ctime_sec = now;
        }

        mxfs_inode_cache_dirty(mnt->icache, ci);
        mxfs_inode_cache_put(mnt->icache, ci);
        return len;
    }

    /* Extent-based write */
    if (!ci->extents) {
        ci->extents = mxfs_extent_map_create();
        if (!ci->extents) {
            mxfs_inode_cache_put(mnt->icache, ci);
            return -ENOMEM;
        }
    }

    /* Fast path: no cluster peers — bypass block cache entirely.
     * Writes directly to device from the input buffer, avoiding
     * per-block hash lookups, LRU management, dirty tracking, and
     * memcpy through the cache layer. Falls through to the normal
     * cached path when peers are connected (coherency needed). */
    if (!mxfs_has_peers(mnt)) {
        int64_t ret = mxfs_write_direct(mnt, ci, src, offset, len);
        if (ret > 0) {
            bytes_written = (uint64_t)ret;
            /* Update file size if we wrote past the end */
            if (offset + bytes_written > ci->size) {
                ci->size = offset + bytes_written;
                mxfs_inode_cache_dirty(mnt->icache, ci);
            }

            /* Update mtime and ctime */
            {
                uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
                ci->mtime_sec = now;
                ci->ctime_sec = now;
                mxfs_inode_cache_dirty(mnt->icache, ci);
            }
        }
        mxfs_inode_cache_put(mnt->icache, ci);
        return ret;
    }

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;
        bool is_new = false;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);
        if (phys_block == MXFS_EXTENT_HOLE) {
            /* Allocate blocks for this hole region */
            uint64_t alloc_fsblock;
            uint32_t alloc_len;
            uint32_t wanted;
            int alloc_ret;

            /* Try to allocate enough blocks to cover remaining write */
            wanted = (uint32_t)((offset + len + mnt->sb.blocksize - 1)
                     / mnt->sb.blocksize - logical_block);
            if (wanted < 1)
                wanted = 1;
            if (wanted > 256)
                wanted = 256; /* cap preallocation */

            alloc_ret = mxfs_alloc_blocks(mnt->alloc, wanted, 0,
                                           &alloc_fsblock, &alloc_len);
            if (alloc_ret) {
                if (bytes_written > 0)
                    break;
                mxfs_inode_cache_put(mnt->icache, ci);
                return alloc_ret;
            }

            /* Add the allocated extent to the in-memory map */
            alloc_ret = mxfs_extent_map_insert(ci->extents,
                                                logical_block,
                                                alloc_fsblock,
                                                alloc_len, false);
            if (alloc_ret) {
                /* Failed to insert — blocks leaked but avoid crash */
                if (bytes_written > 0)
                    break;
                mxfs_inode_cache_put(mnt->icache, ci);
                return alloc_ret;
            }

            /* Update nextents to match the extent map count.
             * This is critical: without it, flush_inode_to_disk writes
             * nextents=0 to the raw buffer, and remote nodes reading
             * the inode from disk see no extents (EIO on read). */
            ci->nextents = mxfs_extent_map_count(ci->extents);

            mxfs_inode_cache_dirty(mnt->icache, ci);
            is_new = true;

            /* Re-lookup — should now find the allocated block */
            phys_block = mxfs_extent_map_lookup(ci->extents,
                                                 logical_block, &flags);
            if (phys_block == MXFS_EXTENT_HOLE) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mount: alloc succeeded but lookup still "
                             "returns hole for ino %llu block %llu",
                             (unsigned long long)ino,
                             (unsigned long long)logical_block);
                break;
            }
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            int wret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE)
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            /* Bulk write to block cache */
            wret = mxfs_block_cache_write_range(mnt->bcache, phys_block,
                                                 block_off, src,
                                                 contig_bytes, is_new);
            if (wret) {
                if (bytes_written > 0)
                    break;
                mxfs_inode_cache_put(mnt->icache, ci);
                return wret;
            }

            src += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_written += contig_bytes;
        }
    }

    /* Update file size if we wrote past the end */
    if (offset > ci->size) {
        ci->size = offset;
        mxfs_inode_cache_dirty(mnt->icache, ci);
    }

    /* Update mtime and ctime on successful write */
    if (bytes_written > 0) {
        uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
        ci->mtime_sec = now;
        ci->ctime_sec = now;
        mxfs_inode_cache_dirty(mnt->icache, ci);
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return (int64_t)bytes_written;
}

/*
 * Write data to a file with the inode already pinned (DLM lock held).
 * Caller must have obtained ci via mxfs_inode_cache_get_exclusive().
 * Does NOT acquire or release the inode cache reference.
 *
 * Returns bytes written, or negative errno.
 */
static int64_t mxfs_write_pinned(struct mxfs_mount *mnt,
                                   struct mxfs_cached_inode *ci,
                                   const void *buf, uint64_t offset,
                                   uint32_t len)
{
    uint64_t bytes_written = 0;
    const uint8_t *src = (const uint8_t *)buf;

    /* Handle inline data (FMT_LOCAL) */
    if (ci->format == XFS_DINODE_FMT_LOCAL) {
        int new_size = (int)(offset + len);
        int max_inline = ci->raw_len - ci->core_size;

        if (new_size > max_inline)
            return -ENOSPC;

        if (new_size > ci->inline_len) {
            void *new_buf = mxfs_pal_alloc(new_size);
            if (!new_buf)
                return -ENOMEM;
            memset(new_buf, 0, new_size);
            if (ci->inline_data && ci->inline_len > 0)
                memcpy(new_buf, ci->inline_data, ci->inline_len);
            if (ci->inline_data)
                mxfs_pal_free(ci->inline_data);
            ci->inline_data = new_buf;
            ci->inline_len = new_size;
        }

        memcpy((uint8_t *)ci->inline_data + offset, src, len);
        if ((uint64_t)new_size > ci->size)
            ci->size = new_size;

        mxfs_inode_cache_dirty(mnt->icache, ci);
        return len;
    }

    /* Extent-based write */
    if (!ci->extents) {
        ci->extents = mxfs_extent_map_create();
        if (!ci->extents)
            return -ENOMEM;
    }

    /* Fast path: no cluster peers — bypass block cache entirely */
    if (!mxfs_has_peers(mnt)) {
        int64_t ret = mxfs_write_direct(mnt, ci, src, offset, len);
        if (ret > 0) {
            bytes_written = (uint64_t)ret;
            if (offset + bytes_written > ci->size) {
                ci->size = offset + bytes_written;
                mxfs_inode_cache_dirty(mnt->icache, ci);
            }
        }
        return ret;
    }

    while (len > 0) {
        uint64_t logical_block = offset / mnt->sb.blocksize;
        uint32_t block_off = (uint32_t)(offset % mnt->sb.blocksize);
        uint64_t phys_block;
        uint32_t flags;
        bool is_new = false;

        phys_block = mxfs_extent_map_lookup(ci->extents, logical_block,
                                             &flags);
        if (phys_block == MXFS_EXTENT_HOLE) {
            uint64_t alloc_fsblock;
            uint32_t alloc_len;
            uint32_t wanted;
            int alloc_ret;

            wanted = (uint32_t)((offset + len + mnt->sb.blocksize - 1)
                     / mnt->sb.blocksize - logical_block);
            if (wanted < 1)
                wanted = 1;
            if (wanted > 256)
                wanted = 256;

            alloc_ret = mxfs_alloc_blocks(mnt->alloc, wanted, 0,
                                           &alloc_fsblock, &alloc_len);
            if (alloc_ret) {
                if (bytes_written > 0)
                    break;
                return alloc_ret;
            }

            alloc_ret = mxfs_extent_map_insert(ci->extents,
                                                logical_block,
                                                alloc_fsblock,
                                                alloc_len, false);
            if (alloc_ret) {
                if (bytes_written > 0)
                    break;
                return alloc_ret;
            }

            ci->nextents = mxfs_extent_map_count(ci->extents);
            mxfs_inode_cache_dirty(mnt->icache, ci);
            is_new = true;

            phys_block = mxfs_extent_map_lookup(ci->extents,
                                                 logical_block, &flags);
            if (phys_block == MXFS_EXTENT_HOLE) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mount: alloc succeeded but lookup still "
                             "returns hole for ino %llu block %llu",
                             (unsigned long long)ci->ino,
                             (unsigned long long)logical_block);
                break;
            }
        }

        /* Find contiguous physical block run */
        {
            uint32_t contig_bytes = mnt->sb.blocksize - block_off;
            uint64_t next_logical = logical_block + 1;
            uint64_t next_phys = phys_block + 1;
            int wret;

            while (contig_bytes < len) {
                uint32_t nflags;
                uint64_t np = mxfs_extent_map_lookup(ci->extents,
                                                      next_logical,
                                                      &nflags);
                if (np != next_phys || np == MXFS_EXTENT_HOLE)
                    break;
                contig_bytes += mnt->sb.blocksize;
                next_logical++;
                next_phys++;
            }

            if (contig_bytes > len)
                contig_bytes = len;

            wret = mxfs_block_cache_write_range(mnt->bcache, phys_block,
                                                 block_off, src,
                                                 contig_bytes, is_new);
            if (wret) {
                if (bytes_written > 0)
                    break;
                return wret;
            }

            src += contig_bytes;
            offset += contig_bytes;
            len -= contig_bytes;
            bytes_written += contig_bytes;
        }
    }

    /* Update file size if we wrote past the end */
    if (offset > ci->size) {
        ci->size = offset;
        mxfs_inode_cache_dirty(mnt->icache, ci);
    }

    return (int64_t)bytes_written;
}

/*
 * Bulk write — acquires DLM EX lock once for the entire write.
 *
 * This is the write analog of mxfs_read_bulk(). The caller provides
 * a callback that delivers chunks of data to write. The DLM EX lock
 * is held across all chunks, eliminating per-chunk DLM round-trips
 * that cause BAST storms and D-state hangs on multi-node.
 *
 * For a 256MB write with 4MB chunks:
 *   Old: 64 * (DLM EX get + write + DLM EX put) = 64 BAST round-trips
 *   New: 1 DLM EX get + 64 writes + 1 DLM EX put = 1 BAST round-trip
 *
 * Single-node optimization: when no cluster peers are connected, the
 * EX lock scope is narrowed. The lock protects only the metadata phase
 * (extent map lookup + block allocation). The actual data write to disk
 * (mxfs_write_direct with pipelined bios) runs without the EX lock,
 * allowing concurrent I/O to other files. This is safe because no
 * remote node can read stale data when there are no peers. In multi-node
 * mode, the lock is held across the entire write for coherency.
 */
int64_t mxfs_write_bulk(struct mxfs_mount *mnt, uint64_t ino,
                          uint64_t offset, uint64_t total_len,
                          uint32_t chunk_size,
                          mxfs_write_chunk_fn write_fn, void *ctx,
                          uint64_t *size_out)
{
    struct mxfs_cached_inode *ci;
    int err;
    uint64_t total_written = 0;
    uint8_t *buf;
    bool single_node;
    uint64_t t0 = mxfs_pal_time_ms();

    if (!mnt || !mnt->mounted || !write_fn)
        return -EINVAL;

    if (chunk_size == 0)
        chunk_size = 4 * 1024 * 1024;  /* 4MB default */

    /* Snapshot peer state once per call. If peers connect mid-write,
     * the next write_bulk call sees the change. Within a single call
     * the optimization mode stays consistent. */
    single_node = !mxfs_has_peers(mnt);

    /* Acquire inode with EX lock */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    /* Allocate the I/O buffer — sized to actual need, not the full
     * chunk_size (which defaults to 4MB). A 4K write should not trigger
     * an order-10 kmalloc for 1024 contiguous pages. */
    {
        size_t alloc_size = (size_t)chunk_size;
        if ((uint64_t)alloc_size > total_len)
            alloc_size = (size_t)total_len;
        buf = mxfs_pal_alloc(alloc_size);
    }
    if (!buf) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENOMEM;
    }

    while (total_written < total_len) {
        uint32_t chunk = chunk_size;
        int got;
        int64_t nwritten;

        if ((uint64_t)chunk > total_len - total_written)
            chunk = (uint32_t)(total_len - total_written);

        /* Get next chunk of data from caller */
        got = write_fn(ctx, buf, chunk);
        if (got < 0) {
            if (total_written > 0)
                break;
            mxfs_pal_free(buf);
            mxfs_inode_cache_put(mnt->icache, ci);
            return got;
        }
        if (got == 0)
            break;

        if (single_node && total_len > 65536) {
            /*
             * Single-node lock narrowing: split metadata and data
             * phases. The EX lock protects extent map + allocation
             * only. Data write uses pipelined async bios without
             * the lock, allowing concurrent I/O to other inodes.
             *
             * Safe because: no peers = no BAST = no remote reader
             * can see stale data. The write_direct path only touches
             * data blocks after allocation is committed.
             *
             * Only applied when total_len > 64KB. For small random
             * writes (e.g. 4K), the EX->PR->EX dance triples the
             * lock cycles per I/O (3x cache_get_locked, each taking
             * a global wrlock). Below the threshold, write directly
             * under the initial EX lock via the multi-node path.
             */

            /* Phase 1 (EX lock held): pre-allocate any needed blocks */
            if (!ci->extents) {
                ci->extents = mxfs_extent_map_create();
                if (!ci->extents) {
                    mxfs_pal_free(buf);
                    mxfs_inode_cache_put(mnt->icache, ci);
                    return -ENOMEM;
                }
            }

            {
                uint64_t woff = offset + total_written;
                uint32_t wlen = (uint32_t)got;
                uint64_t end = woff + wlen;

                while (woff < end) {
                    uint64_t logical_block = woff / mnt->sb.blocksize;
                    uint64_t phys_block;
                    uint32_t flags;

                    phys_block = mxfs_extent_map_lookup(ci->extents,
                                                         logical_block,
                                                         &flags);
                    if (phys_block == MXFS_EXTENT_HOLE) {
                        uint64_t alloc_fsblock;
                        uint32_t alloc_len;
                        uint32_t wanted;
                        int alloc_ret;

                        wanted = (uint32_t)((end + mnt->sb.blocksize - 1)
                                 / mnt->sb.blocksize - logical_block);
                        if (wanted < 1) wanted = 1;
                        if (wanted > 256) wanted = 256;

                        alloc_ret = mxfs_alloc_blocks(mnt->alloc, wanted, 0,
                                                       &alloc_fsblock,
                                                       &alloc_len);
                        if (alloc_ret) {
                            if (total_written > 0)
                                goto finish;
                            mxfs_pal_free(buf);
                            mxfs_inode_cache_put(mnt->icache, ci);
                            return alloc_ret;
                        }

                        alloc_ret = mxfs_extent_map_insert(ci->extents,
                                                            logical_block,
                                                            alloc_fsblock,
                                                            alloc_len,
                                                            false);
                        if (alloc_ret) {
                            if (total_written > 0)
                                goto finish;
                            mxfs_pal_free(buf);
                            mxfs_inode_cache_put(mnt->icache, ci);
                            return alloc_ret;
                        }

                        ci->nextents = mxfs_extent_map_count(ci->extents);
                        mxfs_inode_cache_dirty(mnt->icache, ci);
                        /* Skip past the allocated extent */
                        woff = (logical_block + alloc_len) *
                               mnt->sb.blocksize;
                    } else {
                        woff = (logical_block + 1) * mnt->sb.blocksize;
                    }
                }
            }

            /* Update file size under the EX lock */
            {
                uint64_t write_end = offset + total_written + (uint64_t)got;
                if (write_end > ci->size) {
                    ci->size = write_end;
                    mxfs_inode_cache_dirty(mnt->icache, ci);
                }
            }

            /* Release EX lock before data write. ci stays valid in memory
             * because mxfs_write_direct only reads the extent map (no
             * mutation). We will re-acquire EX for the next chunk. */
            mxfs_inode_cache_put(mnt->icache, ci);
            ci = NULL;

            /* Phase 2 (no lock): write data using pipelined async bios.
             * Re-acquire a PR (shared) reference for extent map access. */
            {
                struct mxfs_cached_inode *ci_data;
                ci_data = mxfs_inode_cache_get(mnt->icache, ino, &err);
                if (!ci_data) {
                    if (total_written > 0)
                        goto finish_no_ci;
                    mxfs_pal_free(buf);
                    return err;
                }

                nwritten = mxfs_write_direct(mnt, ci_data,
                                              (const uint8_t *)buf,
                                              offset + total_written,
                                              (uint32_t)got);
                mxfs_inode_cache_put(mnt->icache, ci_data);
            }

            /* Re-acquire EX lock for next iteration */
            ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
            if (!ci) {
                if (nwritten > 0)
                    total_written += (uint64_t)nwritten;
                goto finish_no_ci;
            }
        } else {
            /* Multi-node: hold EX lock across entire data write.
             * Prevents another node from reading stale data between
             * allocation and write completion. */
            nwritten = mxfs_write_pinned(mnt, ci, buf,
                                          offset + total_written,
                                          (uint32_t)got);
        }

        if (nwritten < 0) {
            if (total_written > 0)
                break;
            mxfs_pal_free(buf);
            mxfs_inode_cache_put(mnt->icache, ci);
            return nwritten;
        }
        if (nwritten == 0)
            break;

        total_written += (uint64_t)nwritten;

        /* Short write means we couldn't write everything */
        if (nwritten < (int64_t)got)
            break;

        /* Yield periodically to prevent soft lockups.
         * Same rationale as mxfs_read_bulk: large writes on iSCSI
         * can hold the CPU for seconds without yielding. */
        mxfs_pal_cond_resched();
    }

finish:
    /* Update mtime and ctime once for the entire bulk write */
    if (total_written > 0) {
        uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
        ci->mtime_sec = now;
        ci->ctime_sec = now;
        mxfs_inode_cache_dirty(mnt->icache, ci);
    }

    /* Report final file size to caller */
    if (size_out)
        *size_out = ci->size;

    mxfs_pal_free(buf);
    mxfs_inode_cache_put(mnt->icache, ci);
    mnt->stat_write_ms += mxfs_pal_time_ms() - t0;
    mnt->stat_write_count++;
    return (int64_t)total_written;

finish_no_ci:
    /* Re-acquire failed after data write. Fetch size for caller. */
    if (size_out) {
        struct mxfs_cached_inode *ci_tmp;
        ci_tmp = mxfs_inode_cache_get(mnt->icache, ino, &err);
        if (ci_tmp) {
            *size_out = ci_tmp->size;
            mxfs_inode_cache_put(mnt->icache, ci_tmp);
        } else {
            *size_out = 0;
        }
    }
    mxfs_pal_free(buf);
    return (int64_t)total_written;
}

int mxfs_truncate(struct mxfs_mount *mnt, uint64_t ino, uint64_t size)
{
    struct mxfs_cached_inode *ci;
    int err;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    ci->size = size;
    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

int mxfs_trim_eof_blocks(struct mxfs_mount *mnt, uint64_t ino)
{
    struct mxfs_cached_inode *ci;
    const struct mxfs_extent *ext;
    uint64_t eof_block;
    uint64_t ext_end;
    int next;
    int err;
    int i;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    /* Nothing to trim for inline data or empty files */
    if (ci->format == XFS_DINODE_FMT_LOCAL || ci->size == 0) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }

    next = mxfs_extent_map_count(ci->extents);
    if (next == 0) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }

    /* Logical block just past end of file data */
    eof_block = (ci->size + mnt->sb.blocksize - 1) / mnt->sb.blocksize;

    /* Check the last extent for blocks beyond EOF */
    ext = mxfs_extent_map_get(ci->extents, next - 1);
    if (!ext) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }

    ext_end = ext->startoff + ext->blockcount;
    if (ext_end <= eof_block) {
        /* No speculative prealloc beyond EOF */
        mxfs_inode_cache_put(mnt->icache, ci);
        return 0;
    }

    /* Punch out blocks from eof_block to ext_end */
    {
        uint64_t punch_start = eof_block;
        uint64_t punch_count = ext_end - eof_block;
        int max_freed = next + 1;
        struct mxfs_freed_extent *freed;
        int num_freed = 0;

        freed = mxfs_pal_alloc(max_freed * sizeof(*freed));
        if (!freed) {
            mxfs_inode_cache_put(mnt->icache, ci);
            return -ENOMEM;
        }

        err = mxfs_extent_map_punch(ci->extents, punch_start,
                                     punch_count, freed,
                                     max_freed, &num_freed);
        if (err) {
            mxfs_pal_free(freed);
            mxfs_inode_cache_put(mnt->icache, ci);
            return err;
        }

        for (i = 0; i < num_freed; i++) {
            int fret = mxfs_free_blocks(mnt->alloc,
                                         freed[i].startblock,
                                         freed[i].blockcount);
            if (fret) {
                mxfs_pal_log(MXFS_LOG_WARN,
                    "trim_eof: free blocks at %llu len %u "
                    "failed: %d",
                    (unsigned long long)freed[i].startblock,
                    freed[i].blockcount, fret);
            }
        }

        if (num_freed > 0) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                "trim_eof: ino %llu trimmed %llu blocks "
                "beyond EOF",
                (unsigned long long)ino,
                (unsigned long long)punch_count);
        }

        mxfs_pal_free(freed);
    }

    ci->nextents = mxfs_extent_map_count(ci->extents);
    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

int mxfs_fsync(struct mxfs_mount *mnt, uint64_t ino)
{
    struct mxfs_cached_inode *ci;
    int err;
    int ret;
    int flush_ret;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err;

    ret = mxfs_inode_cache_flush_inode(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Flush dirty metadata blocks (AGF, bnobt, cntbt from alloc).
     * In single-node mode these are deferred at allocation time. */
    mxfs_block_cache_flush(mnt->bcache);

    /* Flush any batched journal commits to stable storage. This must
     * happen before the device flush so that journal entries are durable
     * before we report fsync success. */
    if (mnt->journal) {
        flush_ret = mxfs_journal_flush(mnt->journal);
        if (flush_ret && !ret)
            ret = flush_ret;
    }

    /* Unconditional device flush: mxfs_write_direct() writes data via
     * submit_bio_wait(REQ_OP_WRITE) which may complete with data still
     * in the device's volatile write cache. flush_inode_to_disk and
     * block_cache_flush each call bdev_flush only when they had dirty
     * data to write. If the inode was already clean (flushed by a
     * prior fsync or BAST) and no block cache entries were dirty,
     * neither call issues a device flush, leaving direct-write data
     * unflushed. This explicit flush covers that gap. */
    flush_ret = mxfs_pal_bdev_flush(mnt->xfs_dev);
    if (flush_ret && !ret)
        ret = flush_ret;

    return ret;
}

/* ─── Public API: Fallocate ─── */

/*
 * Preallocate blocks for a file range (mode 0 or KEEP_SIZE).
 *
 * Allocates blocks covering [offset, offset+len), skipping any blocks
 * that are already allocated. Tries to allocate large contiguous
 * extents to minimize fragmentation (the primary use case for QEMU
 * disk images).
 */
static int fallocate_prealloc(struct mxfs_mount *mnt,
                               struct mxfs_cached_inode *ci,
                               uint64_t offset, uint64_t len,
                               bool keep_size)
{
    uint64_t start_block;
    uint64_t end_block;
    uint64_t block;
    uint32_t blocksize = mnt->sb.blocksize;
    int err = 0;

    start_block = offset / blocksize;
    end_block = (offset + len + blocksize - 1) / blocksize;

    if (!ci->extents) {
        ci->extents = mxfs_extent_map_create();
        if (!ci->extents)
            return -ENOMEM;
    }

    /* Walk the logical block range, allocating any holes */
    block = start_block;
    while (block < end_block) {
        uint64_t phys;
        uint32_t flags;
        uint64_t run_start;
        uint32_t run_len;

        phys = mxfs_extent_map_lookup(ci->extents, block, &flags);
        if (phys != MXFS_EXTENT_HOLE) {
            /* Already allocated — find end of this extent to skip */
            int i;
            bool found = false;

            for (i = 0; i < ci->extents->count; i++) {
                const struct mxfs_extent *e = &ci->extents->extents[i];
                if (block >= e->startoff &&
                    block < e->startoff + e->blockcount) {
                    block = e->startoff + e->blockcount;
                    found = true;
                    break;
                }
            }
            if (!found)
                block++;
            continue;
        }

        /* Find the length of this hole (contiguous unallocated blocks) */
        run_start = block;
        run_len = 0;
        while (block < end_block) {
            phys = mxfs_extent_map_lookup(ci->extents, block, &flags);
            if (phys != MXFS_EXTENT_HOLE)
                break;
            block++;
            run_len++;
        }

        /* Allocate blocks for this hole run */
        while (run_len > 0) {
            uint64_t alloc_fsblock;
            uint32_t alloc_len;
            uint32_t wanted = run_len;

            err = mxfs_alloc_blocks(mnt->alloc, wanted, 0,
                                     &alloc_fsblock, &alloc_len);
            if (err) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "fallocate: alloc %u blocks at logical %llu "
                             "failed: %d",
                             wanted,
                             (unsigned long long)run_start, err);
                return err;
            }

            err = mxfs_extent_map_insert(ci->extents, run_start,
                                          alloc_fsblock, alloc_len, true);
            if (err) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "fallocate: extent insert failed: %d", err);
                return err;
            }

            run_start += alloc_len;
            run_len -= alloc_len;
        }
    }

    /* Transition from inline format if needed */
    if (ci->format == XFS_DINODE_FMT_LOCAL)
        ci->format = XFS_DINODE_FMT_EXTENTS;

    ci->nextents = mxfs_extent_map_count(ci->extents);

    /* Update file size if needed */
    if (!keep_size && (offset + len) > ci->size)
        ci->size = offset + len;

    /* Update timestamps */
    {
        uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
        ci->mtime_sec = now;
        ci->ctime_sec = now;
    }

    mxfs_inode_cache_dirty(mnt->icache, ci);
    return 0;
}

/*
 * Punch a hole in the file by deallocating blocks in [offset, offset+len).
 * Does not change file size.
 */
static int fallocate_punch_hole(struct mxfs_mount *mnt,
                                 struct mxfs_cached_inode *ci,
                                 uint64_t offset, uint64_t len)
{
    uint64_t start_block;
    uint64_t end_block;
    uint64_t block_count;
    uint32_t blocksize = mnt->sb.blocksize;
    struct mxfs_freed_extent *freed;
    int num_freed = 0;
    int max_freed;
    int err;
    int i;

    if (!ci->extents || ci->extents->count == 0)
        return 0;  /* nothing to punch */

    /* Align to block boundaries — only punch whole blocks.
     * Partial blocks at the edges are zeroed via bdev_write. */
    start_block = (offset + blocksize - 1) / blocksize;
    end_block = (offset + len) / blocksize;

    if (start_block >= end_block) {
        /* Range is entirely within a single block — just zero the range.
         * For simplicity, we zero via block cache write of zeroes. */
        if (len > 0) {
            uint64_t logical = offset / blocksize;
            uint64_t phys;
            uint32_t flags;

            phys = mxfs_extent_map_lookup(ci->extents, logical, &flags);
            if (phys != MXFS_EXTENT_HOLE) {
                uint32_t blk_off = (uint32_t)(offset % blocksize);
                uint32_t zero_len = (uint32_t)len;
                void *zbuf;

                zbuf = mxfs_pal_alloc(zero_len);
                if (!zbuf)
                    return -ENOMEM;
                memset(zbuf, 0, zero_len);

                err = mxfs_block_cache_write_range(mnt->bcache, phys,
                                                    blk_off, zbuf,
                                                    zero_len, false);
                mxfs_pal_free(zbuf);
                if (err)
                    return err;
            }
        }
        goto update_meta;
    }

    block_count = end_block - start_block;

    /* Zero partial block at start boundary */
    if (offset % blocksize != 0) {
        uint64_t logical = offset / blocksize;
        uint64_t phys;
        uint32_t flags;

        phys = mxfs_extent_map_lookup(ci->extents, logical, &flags);
        if (phys != MXFS_EXTENT_HOLE) {
            uint32_t blk_off = (uint32_t)(offset % blocksize);
            uint32_t zero_len = blocksize - blk_off;
            void *zbuf;

            zbuf = mxfs_pal_alloc(zero_len);
            if (!zbuf)
                return -ENOMEM;
            memset(zbuf, 0, zero_len);

            err = mxfs_block_cache_write_range(mnt->bcache, phys,
                                                blk_off, zbuf,
                                                zero_len, false);
            mxfs_pal_free(zbuf);
            if (err)
                return err;
        }
    }

    /* Zero partial block at end boundary */
    if ((offset + len) % blocksize != 0) {
        uint64_t logical = (offset + len) / blocksize;
        uint64_t phys;
        uint32_t flags;

        phys = mxfs_extent_map_lookup(ci->extents, logical, &flags);
        if (phys != MXFS_EXTENT_HOLE) {
            uint32_t zero_len = (uint32_t)((offset + len) % blocksize);
            void *zbuf;

            zbuf = mxfs_pal_alloc(zero_len);
            if (!zbuf)
                return -ENOMEM;
            memset(zbuf, 0, zero_len);

            err = mxfs_block_cache_write_range(mnt->bcache, phys,
                                                0, zbuf,
                                                zero_len, false);
            mxfs_pal_free(zbuf);
            if (err)
                return err;
        }
    }

    /* Remove whole blocks from the extent map */
    max_freed = ci->extents->count + 1;  /* splitting can add at most 1 */
    freed = mxfs_pal_alloc(max_freed * sizeof(*freed));
    if (!freed)
        return -ENOMEM;

    err = mxfs_extent_map_punch(ci->extents, start_block, block_count,
                                 freed, max_freed, &num_freed);
    if (err) {
        mxfs_pal_free(freed);
        return err;
    }

    /* Free the physical blocks */
    for (i = 0; i < num_freed; i++) {
        int fret = mxfs_free_blocks(mnt->alloc, freed[i].startblock,
                                     freed[i].blockcount);
        if (fret) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "fallocate: free blocks at %llu len %u failed: %d",
                         (unsigned long long)freed[i].startblock,
                         freed[i].blockcount, fret);
        }
    }

    mxfs_pal_free(freed);

update_meta:
    ci->nextents = mxfs_extent_map_count(ci->extents);

    /* Update timestamps */
    {
        uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
        ci->mtime_sec = now;
        ci->ctime_sec = now;
    }

    mxfs_inode_cache_dirty(mnt->icache, ci);
    return 0;
}

/*
 * Zero data in allocated blocks within [offset, offset+len) without
 * freeing extents. Unlike PUNCH_HOLE, extents remain allocated.
 */
static int fallocate_zero_range(struct mxfs_mount *mnt,
                                 struct mxfs_cached_inode *ci,
                                 uint64_t offset, uint64_t len,
                                 bool keep_size)
{
    uint32_t blocksize = mnt->sb.blocksize;
    uint64_t pos = offset;
    uint64_t end = offset + len;
    void *zbuf;
    int err;

    zbuf = mxfs_pal_alloc(blocksize);
    if (!zbuf)
        return -ENOMEM;
    memset(zbuf, 0, blocksize);

    while (pos < end) {
        uint64_t logical = pos / blocksize;
        uint64_t phys;
        uint32_t flags;
        uint32_t blk_off;
        uint32_t zero_len;

        phys = mxfs_extent_map_lookup(ci->extents, logical, &flags);
        if (phys == MXFS_EXTENT_HOLE) {
            /* Skip holes — no data to zero */
            pos = (logical + 1) * blocksize;
            continue;
        }

        blk_off = (uint32_t)(pos % blocksize);
        zero_len = blocksize - blk_off;
        if (pos + zero_len > end)
            zero_len = (uint32_t)(end - pos);

        err = mxfs_block_cache_write_range(mnt->bcache, phys,
                                            blk_off, zbuf,
                                            zero_len, false);
        if (err) {
            mxfs_pal_free(zbuf);
            return err;
        }

        pos += zero_len;
    }

    mxfs_pal_free(zbuf);

    /* Update file size if needed and KEEP_SIZE not set */
    if (!keep_size && end > ci->size)
        ci->size = end;

    /* Update timestamps */
    {
        uint32_t now = (uint32_t)mxfs_pal_time_real_sec();
        ci->mtime_sec = now;
        ci->ctime_sec = now;
    }

    mxfs_inode_cache_dirty(mnt->icache, ci);
    return 0;
}

int mxfs_fallocate(struct mxfs_mount *mnt, uint64_t ino,
                    int mode, uint64_t offset, uint64_t len)
{
    struct mxfs_cached_inode *ci;
    int err;
    int ret;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    if (len == 0)
        return 0;

    /* Validate mode combinations */
    if (mode & ~(MXFS_FALLOC_FL_KEEP_SIZE | MXFS_FALLOC_FL_PUNCH_HOLE |
                 MXFS_FALLOC_FL_ZERO_RANGE))
        return -EOPNOTSUPP;

    /* Punch hole requires KEEP_SIZE */
    if ((mode & MXFS_FALLOC_FL_PUNCH_HOLE) &&
        !(mode & MXFS_FALLOC_FL_KEEP_SIZE))
        return -EINVAL;

    /* Zero range and punch hole are mutually exclusive */
    if ((mode & MXFS_FALLOC_FL_ZERO_RANGE) &&
        (mode & MXFS_FALLOC_FL_PUNCH_HOLE))
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    if (mode & MXFS_FALLOC_FL_PUNCH_HOLE) {
        ret = fallocate_punch_hole(mnt, ci, offset, len);
    } else if (mode & MXFS_FALLOC_FL_ZERO_RANGE) {
        bool keep_size = (mode & MXFS_FALLOC_FL_KEEP_SIZE) != 0;
        ret = fallocate_zero_range(mnt, ci, offset, len, keep_size);
    } else {
        bool keep_size = (mode & MXFS_FALLOC_FL_KEEP_SIZE) != 0;
        ret = fallocate_prealloc(mnt, ci, offset, len, keep_size);
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return ret;
}

/* XFS superblock field offsets (big-endian on disk) */
#define XFS_SB_OFF_ICOUNT     128  /* __be64 */
#define XFS_SB_OFF_IFREE      136  /* __be64 */
#define XFS_SB_OFF_FDBLOCKS   144  /* __be64 */
#define XFS_SB_CRC_OFF        224  /* __le32 CRC32C */

/*
 * Write updated fdblocks/icount/ifree into the on-disk XFS superblock.
 * Bug 129: the superblock counters were never persisted — after remount,
 * the stale fdblocks caused the allocator free_blocks counter to diverge
 * from the AGF ground truth, leading to negative df output.
 */
static int flush_superblock_counters(struct mxfs_mount *mnt)
{
    void *sb_buf;
    uint8_t *sb_sec;
    uint64_t free_blk, total_ino, free_ino;
    uint32_t crc;
    int ret;

    if (!mnt->alloc || !mnt->bcache)
        return 0;

    /* The XFS superblock is in block 0 (first block of XFS data area).
     * Within that block, the SB sector is at offset 0. */
    sb_buf = mxfs_pal_alloc(mnt->sb.blocksize);
    if (!sb_buf)
        return -ENOMEM;

    ret = mxfs_block_cache_read(mnt->bcache, 0, sb_buf);
    if (ret) {
        mxfs_pal_free(sb_buf);
        return ret;
    }

    sb_sec = (uint8_t *)sb_buf;

    /* Recount from on-disk AGF/AGI for cluster-accurate values (Bug 134),
     * then read the updated counters.  Without recount, we'd write this
     * node's stale local counter to the superblock, overwriting correct
     * values from other nodes' sync calls. */
    mxfs_alloc_recount_counters(mnt->alloc);
    mxfs_alloc_get_counters(mnt->alloc, &free_blk, &total_ino, &free_ino);

    /* Update the three counter fields (big-endian) */
    mount_put_be64(sb_sec + XFS_SB_OFF_ICOUNT,   total_ino);
    mount_put_be64(sb_sec + XFS_SB_OFF_IFREE,     free_ino);
    mount_put_be64(sb_sec + XFS_SB_OFF_FDBLOCKS, free_blk);

    /* Recompute V5 CRC if applicable */
    if (mnt->sb.is_v5) {
        /* Zero the CRC field, compute over the 512-byte sector,
         * store as native uint32_t (little-endian on x86) */
        memset(sb_sec + XFS_SB_CRC_OFF, 0, 4);
        crc = ~mxfs_pal_crc32c(~0U, sb_sec, 512);
        mount_put_le32(sb_sec + XFS_SB_CRC_OFF, crc);
    }

    ret = mxfs_block_cache_write_range(mnt->bcache, 0, 0,
                                        sb_sec, mnt->sb.sectsize, false);
    mxfs_pal_free(sb_buf);

    if (ret == 0) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: flushed sb counters "
                     "fdblocks=%llu icount=%llu ifree=%llu",
                     (unsigned long long)free_blk,
                     (unsigned long long)total_ino,
                     (unsigned long long)free_ino);
    }

    return ret;
}

int mxfs_sync_fs(struct mxfs_mount *mnt)
{
    int ret = 0;
    int r;
    uint64_t t0, t1, t2, t3, t4, t5, t6;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    t0 = mxfs_pal_time_ms();

    /* Flush all dirty dir cache entries to disk */
    if (mnt->dcache)
        mxfs_dir_cache_flush_all(mnt->dcache);

    t1 = mxfs_pal_time_ms();

    /* Write updated superblock counters (Bug 129) before block cache
     * flush so the SB block is dirty and gets written to disk. */
    r = flush_superblock_counters(mnt);
    if (r && !ret)
        ret = r;

    /* Flush dirty metadata blocks BEFORE inode flush.
     * The alloc subsystem writes inode cluster initialization blocks
     * (full 4K blocks with just magic+version) to the block_cache.
     * If block_cache_flush runs AFTER inode_cache_flush_all, these
     * stale 4K blocks overwrite the fresh 512-byte inode data that
     * was written directly to disk via scatter write/FUA.
     * By flushing block_cache first, the stale cluster blocks hit
     * disk first, then inode_cache_flush_all overwrites them with
     * the correct per-inode data. */
    if (mnt->bcache) {
        r = mxfs_block_cache_flush(mnt->bcache);
        if (r && !ret)
            ret = r;
    }

    t2 = mxfs_pal_time_ms();

    /* Flush all dirty inodes to disk (updates size, extents, timestamps).
     * This MUST happen AFTER block_cache_flush — see comment above. */
    if (mnt->icache) {
        r = mxfs_inode_cache_flush_all(mnt->icache);
        if (r && !ret)
            ret = r;
    }

    t3 = mxfs_pal_time_ms();

    t4 = mxfs_pal_time_ms();

    /* Flush any batched journal commits to stable storage */
    if (mnt->journal) {
        r = mxfs_journal_flush(mnt->journal);
        if (r && !ret)
            ret = r;
    }

    t5 = mxfs_pal_time_ms();

    /* Unconditional device flush to push everything through the device's
     * volatile write cache to stable storage */
    r = mxfs_pal_bdev_flush(mnt->xfs_dev);
    if (r && !ret)
        ret = r;

    t6 = mxfs_pal_time_ms();

    mxfs_pal_log(MXFS_LOG_INFO,
        "sync_fs: dir=%llums inode=%llums sb=%llums bcache=%llums "
        "jflush=%llums devflush=%llums total=%llums",
        (unsigned long long)(t1 - t0),
        (unsigned long long)(t2 - t1),
        (unsigned long long)(t3 - t2),
        (unsigned long long)(t4 - t3),
        (unsigned long long)(t5 - t4),
        (unsigned long long)(t6 - t5),
        (unsigned long long)(t6 - t0));

    return ret;
}

/* ─── Public API: Directory operations ─── */

int mxfs_readdir(struct mxfs_mount *mnt, uint64_t dir_ino,
                 mxfs_readdir_fn cb, void *ctx)
{
    if (!mnt || !mnt->mounted)
        return -EINVAL;

    return mxfs_dir_readdir(mnt->dcache, dir_ino, cb, ctx);
}

int mxfs_create(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen,
                uint16_t mode, uint32_t uid, uint32_t gid,
                uint64_t *ino_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t new_ino;
    uint64_t t0, t1, t2, t3, t4;
    uint64_t now;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name || !ino_out)
        return -EINVAL;

    t0 = mxfs_pal_time_ms();

    /* Allocate a new inode */
    ret = mxfs_alloc_inode(mnt->alloc, &new_ino);
    if (ret)
        return ret;

    t1 = mxfs_pal_time_ms();

    /* Initialize the new inode — skip disk read since inode is fresh */
    ci = mxfs_inode_cache_get_new_exclusive(mnt->icache, new_ino, &err);
    if (!ci) {
        mxfs_free_inode(mnt->alloc, new_ino);
        return err;
    }

    t2 = mxfs_pal_time_ms();

    ci->mode = MXFS_S_IFREG | (mode & 07777);
    ci->uid = uid;
    ci->gid = gid;
    ci->nlink = 1;
    ci->size = 0;
    ci->format = XFS_DINODE_FMT_EXTENTS;

    /* Initialize empty extent map for the new file */
    if (!ci->extents) {
        ci->extents = mxfs_extent_map_create();
        if (!ci->extents) {
            mxfs_inode_cache_put(mnt->icache, ci);
            mxfs_free_inode(mnt->alloc, new_ino);
            return -ENOMEM;
        }
    }

    now = mxfs_pal_time_real_sec();
    ci->atime_sec = (uint32_t)now;
    ci->mtime_sec = (uint32_t)now;
    ci->ctime_sec = (uint32_t)now;

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    t3 = mxfs_pal_time_ms();

    /* Add directory entry.
     * If this fails, free the orphan inode back to the allocator. */
    ret = mxfs_dir_add_entry(mnt->dcache, dir_ino, name, namelen,
                              new_ino, MXFS_FT_REG_FILE);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "create: dir_add_entry for '%.*s' in dir %llu "
                     "failed: %d, freeing orphan inode %llu",
                     (int)namelen, name,
                     (unsigned long long)dir_ino, ret,
                     (unsigned long long)new_ino);
        mxfs_free_inode(mnt->alloc, new_ino);
        return ret;
    }

    t4 = mxfs_pal_time_ms();

    mnt->stat_create_alloc_ms += (t1 - t0);
    mnt->stat_create_getex_ms += (t2 - t1);
    mnt->stat_create_init_ms += (t3 - t2);
    mnt->stat_create_diradd_ms += (t4 - t3);
    mnt->stat_create_ms += (t4 - t0);
    mnt->stat_create_count++;

    *ino_out = new_ino;
    return 0;
}

int mxfs_mknod(struct mxfs_mount *mnt,
               uint64_t dir_ino,
               const char *name, uint8_t namelen,
               uint16_t mode, uint32_t uid, uint32_t gid,
               uint32_t rdev,
               uint64_t *ino_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t new_ino;
    uint64_t now;
    uint8_t ftype;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name || !ino_out)
        return -EINVAL;

    /* Determine directory entry file type from mode */
    switch (mode & MXFS_S_IFMT) {
    case MXFS_S_IFBLK:  ftype = MXFS_FT_BLKDEV;  break;
    case MXFS_S_IFCHR:  ftype = MXFS_FT_CHRDEV;  break;
    case MXFS_S_IFIFO:  ftype = MXFS_FT_FIFO;    break;
    case MXFS_S_IFSOCK: ftype = MXFS_FT_SOCK;    break;
    default:
        return -EINVAL;
    }

    /* Allocate a new inode */
    ret = mxfs_alloc_inode(mnt->alloc, &new_ino);
    if (ret)
        return ret;

    /* Initialize the new inode — skip disk read since inode is fresh */
    ci = mxfs_inode_cache_get_new_exclusive(mnt->icache, new_ino, &err);
    if (!ci) {
        mxfs_free_inode(mnt->alloc, new_ino);
        return err;
    }

    ci->mode = mode;
    ci->uid = uid;
    ci->gid = gid;
    ci->nlink = 1;
    ci->size = 0;

    /* Block and char devices use FMT_DEV with rdev in the data fork.
     * FIFOs and sockets use FMT_EXTENTS with 0 extents (same as XFS). */
    if ((mode & MXFS_S_IFMT) == MXFS_S_IFBLK ||
        (mode & MXFS_S_IFMT) == MXFS_S_IFCHR) {
        ci->format = XFS_DINODE_FMT_DEV;
        ci->rdev = rdev;
        ci->nextents = 0;
        /* Set forkoff to roundup(sizeof(uint32_t), 8) >> 3 = 1
         * to match XFS behavior for device inodes */
        ci->forkoff = 1;
    } else {
        ci->format = XFS_DINODE_FMT_EXTENTS;
        ci->rdev = 0;
        ci->nextents = 0;
        /* Initialize empty extent map */
        if (!ci->extents) {
            ci->extents = mxfs_extent_map_create();
            if (!ci->extents) {
                mxfs_inode_cache_put(mnt->icache, ci);
                mxfs_free_inode(mnt->alloc, new_ino);
                return -ENOMEM;
            }
        }
    }

    now = mxfs_pal_time_real_sec();
    ci->atime_sec = (uint32_t)now;
    ci->mtime_sec = (uint32_t)now;
    ci->ctime_sec = (uint32_t)now;

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Add directory entry */
    ret = mxfs_dir_add_entry(mnt->dcache, dir_ino, name, namelen,
                              new_ino, ftype);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mknod: dir_add_entry for '%.*s' in dir %llu "
                     "failed: %d, freeing orphan inode %llu",
                     (int)namelen, name,
                     (unsigned long long)dir_ino, ret,
                     (unsigned long long)new_ino);
        mxfs_free_inode(mnt->alloc, new_ino);
        return ret;
    }

    *ino_out = new_ino;
    return 0;
}

int mxfs_mkdir(struct mxfs_mount *mnt,
               uint64_t parent_ino,
               const char *name, uint8_t namelen,
               uint16_t mode, uint32_t uid, uint32_t gid,
               uint64_t *ino_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t new_ino;
    uint64_t now;
    int err;
    uint64_t t0 = mxfs_pal_time_ms();
    int ret;

    if (!mnt || !mnt->mounted || !name || !ino_out)
        return -EINVAL;

    ret = mxfs_alloc_inode(mnt->alloc, &new_ino);
    if (ret)
        return ret;

    /* Initialize the new directory inode — skip disk read */
    ci = mxfs_inode_cache_get_new_exclusive(mnt->icache, new_ino, &err);
    if (!ci) {
        mxfs_free_inode(mnt->alloc, new_ino);
        return err;
    }

    ci->mode = MXFS_S_IFDIR | (mode & 07777);
    ci->uid = uid;
    ci->gid = gid;
    ci->nlink = 2; /* "." and parent's entry */
    ci->size = 0;
    ci->format = XFS_DINODE_FMT_LOCAL;

    now = mxfs_pal_time_real_sec();
    ci->atime_sec = (uint32_t)now;
    ci->mtime_sec = (uint32_t)now;
    ci->ctime_sec = (uint32_t)now;

    /* Create minimal shortform directory inline data (. and ..) */
    {
        int hdr_size = 6; /* count(1) + i8count(0)(1) + parent(4) */
        int sf_size = hdr_size; /* empty dir, just . and .. */
        uint8_t *sf = mxfs_pal_alloc(sf_size);
        if (!sf) {
            mxfs_inode_cache_put(mnt->icache, ci);
            mxfs_free_inode(mnt->alloc, new_ino);
            return -ENOMEM;
        }
        memset(sf, 0, sf_size);
        sf[0] = 0;  /* count = 0 (entries beyond . and ..) */
        sf[1] = 0;  /* i8count = 0 (4-byte inodes) */
        {   /* Write parent ino as big-endian 32-bit */
            uint32_t be_ino = mxfs_cpu_to_be32((uint32_t)parent_ino);
            memcpy(sf + 2, &be_ino, 4);
        }

        ci->inline_data = sf;
        ci->inline_len = sf_size;
        ci->size = sf_size;
    }

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Add entry in parent directory.
     * If this fails, free the orphan inode back to the allocator. */
    ret = mxfs_dir_add_entry(mnt->dcache, parent_ino, name, namelen,
                              new_ino, MXFS_FT_DIR);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mkdir: dir_add_entry for '%.*s' in dir %llu "
                     "failed: %d, freeing orphan inode %llu",
                     (int)namelen, name,
                     (unsigned long long)parent_ino, ret,
                     (unsigned long long)new_ino);
        mxfs_free_inode(mnt->alloc, new_ino);
        return ret;
    }

    /* Increment parent nlink (for ".." in new dir) */
    {
        struct mxfs_cached_inode *parent;
        parent = mxfs_inode_cache_get_exclusive(mnt->icache, parent_ino, &err);
        if (parent) {
            parent->nlink++;
            mxfs_inode_cache_dirty(mnt->icache, parent);
            mxfs_inode_cache_put(mnt->icache, parent);
        }
    }

    *ino_out = new_ino;
    mnt->stat_mkdir_ms += mxfs_pal_time_ms() - t0;
    mnt->stat_mkdir_count++;
    return 0;
}

/* Callback for rmdir empty-check: counts entries that are not "." or ".." */
static int rmdir_count_cb(void *ctx, const char *name,
                          uint8_t namelen, uint64_t ino, uint8_t ftype)
{
    int *count = (int *)ctx;

    /* Skip "." and ".." */
    if (namelen == 1 && name[0] == '.')
        return 0;
    if (namelen == 2 && name[0] == '.' && name[1] == '.')
        return 0;

    /* Found a real entry — directory is non-empty, stop iteration */
    (*count)++;
    return 1;
}

int mxfs_rmdir(struct mxfs_mount *mnt,
               uint64_t parent_ino,
               const char *name, uint8_t namelen)
{
    uint64_t dir_ino;
    struct mxfs_cached_inode *ci;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name)
        return -EINVAL;

    /* Look up the directory to remove */
    ret = mxfs_dir_lookup(mnt->dcache, parent_ino, name, namelen, &dir_ino);
    if (ret)
        return ret;

    /* Verify it's a directory and it's empty (only . and ..) */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, dir_ino, &err);
    if (!ci)
        return err;

    if (!MXFS_S_ISDIR(ci->mode)) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENOTDIR;
    }

    /* Release inode lock before readdir (readdir acquires its own locks) */
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Check if directory is truly empty by scanning entries */
    {
        int entry_count = 0;
        ret = mxfs_dir_readdir(mnt->dcache, dir_ino, rmdir_count_cb,
                               &entry_count);
        if (ret && ret != 1)
            return ret;
        if (entry_count > 0)
            return -ENOTEMPTY;
    }

    /* Re-acquire exclusive access for modification */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, dir_ino, &err);
    if (!ci)
        return err;

    /* Set nlink to 0 */
    ci->nlink = 0;
    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Remove from parent directory */
    ret = mxfs_dir_remove_entry(mnt->dcache, parent_ino, name, namelen);
    if (ret)
        return ret;

    /* Decrement parent nlink */
    {
        struct mxfs_cached_inode *parent;
        parent = mxfs_inode_cache_get_exclusive(mnt->icache, parent_ino, &err);
        if (parent) {
            if (parent->nlink > 0)
                parent->nlink--;
            mxfs_inode_cache_dirty(mnt->icache, parent);
            mxfs_inode_cache_put(mnt->icache, parent);
        }
    }

    /* Evict from inode cache before freeing (prevents stale reuse) */
    mxfs_inode_cache_invalidate(mnt->icache, dir_ino);

    /* Free the inode */
    mxfs_free_inode(mnt->alloc, dir_ino);

    /* Invalidate cached dir entries */
    mxfs_dir_cache_invalidate(mnt->dcache, dir_ino);

    return 0;
}

int mxfs_unlink(struct mxfs_mount *mnt,
                uint64_t dir_ino,
                const char *name, uint8_t namelen)
{
    uint64_t target_ino;
    struct mxfs_cached_inode *ci;
    bool should_free;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name)
        return -EINVAL;

    ret = mxfs_dir_lookup(mnt->dcache, dir_ino, name, namelen, &target_ino);
    if (ret)
        return ret;

    /* Decrement nlink */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, target_ino, &err);
    if (!ci)
        return err;

    if (MXFS_S_ISDIR(ci->mode)) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -EISDIR;
    }

    if (ci->nlink > 0)
        ci->nlink--;

    mxfs_inode_cache_dirty(mnt->icache, ci);

    should_free = (ci->nlink == 0);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Remove directory entry */
    ret = mxfs_dir_remove_entry(mnt->dcache, dir_ino, name, namelen);
    if (ret)
        return ret;

    /* Free inode if nlink reached 0 */
    if (should_free) {
        /* Free data blocks from the extent map before releasing the inode */
        ci = mxfs_inode_cache_get(mnt->icache, target_ino, &err);
        if (ci) {
            if (ci->extents) {
                int ec = mxfs_extent_map_count(ci->extents);
                int i;
                for (i = 0; i < ec; i++) {
                    const struct mxfs_extent *ext =
                        mxfs_extent_map_get(ci->extents, i);
                    if (ext && ext->blockcount > 0) {
                        mxfs_free_blocks(mnt->alloc, ext->startblock,
                                         ext->blockcount);
                    }
                }
            }
            mxfs_inode_cache_put(mnt->icache, ci);
        }

        mxfs_inode_cache_invalidate(mnt->icache, target_ino);
        mxfs_free_inode(mnt->alloc, target_ino);
    }

    return 0;
}

/*
 * Helper: derive XFS directory ftype from inode mode.
 */
static uint8_t mxfs_mode_to_ftype(uint16_t mode)
{
    if (MXFS_S_ISDIR(mode))
        return MXFS_FT_DIR;
    if (MXFS_S_ISLNK(mode))
        return MXFS_FT_SYMLINK;
    return MXFS_FT_REG_FILE;
}

int mxfs_rename(struct mxfs_mount *mnt,
                uint64_t old_dir_ino, const char *old_name, uint8_t old_namelen,
                uint64_t new_dir_ino, const char *new_name, uint8_t new_namelen,
                unsigned int flags)
{
    struct mxfs_cached_inode *ci;
    uint64_t src_ino;
    uint64_t dst_ino;
    uint8_t ftype;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !old_name || !new_name)
        return -EINVAL;

    /* Look up the source entry */
    ret = mxfs_dir_lookup(mnt->dcache, old_dir_ino, old_name, old_namelen,
                           &src_ino);
    if (ret)
        return ret;

    /* RENAME_EXCHANGE: atomically swap two directory entries.
     * Both source and dest must exist. No nlink changes — both
     * entries continue to exist, just pointing at each other's inodes. */
    if (flags & MXFS_RENAME_EXCHANGE) {
        uint8_t src_ftype;
        uint8_t dst_ftype;

        /* Destination must exist */
        ret = mxfs_dir_lookup(mnt->dcache, new_dir_ino, new_name,
                               new_namelen, &dst_ino);
        if (ret)
            return ret;

        /* Get ftypes for both inodes */
        src_ftype = MXFS_FT_REG_FILE;
        ci = mxfs_inode_cache_get(mnt->icache, src_ino, &err);
        if (ci) {
            src_ftype = mxfs_mode_to_ftype(ci->mode);
            mxfs_inode_cache_put(mnt->icache, ci);
        }

        dst_ftype = MXFS_FT_REG_FILE;
        ci = mxfs_inode_cache_get(mnt->icache, dst_ino, &err);
        if (ci) {
            dst_ftype = mxfs_mode_to_ftype(ci->mode);
            mxfs_inode_cache_put(mnt->icache, ci);
        }

        /* Remove both entries, then re-add with swapped inodes.
         * Order: remove old, remove new, add old name->dst_ino,
         * add new name->src_ino. */
        ret = mxfs_dir_remove_entry(mnt->dcache, old_dir_ino,
                                     old_name, old_namelen);
        if (ret)
            return ret;

        ret = mxfs_dir_remove_entry(mnt->dcache, new_dir_ino,
                                     new_name, new_namelen);
        if (ret) {
            /* Restore old entry on failure */
            mxfs_dir_add_entry(mnt->dcache, old_dir_ino,
                                old_name, old_namelen,
                                src_ino, src_ftype);
            return ret;
        }

        ret = mxfs_dir_add_entry(mnt->dcache, old_dir_ino,
                                  old_name, old_namelen,
                                  dst_ino, dst_ftype);
        if (ret) {
            /* Best-effort restore */
            mxfs_dir_add_entry(mnt->dcache, old_dir_ino,
                                old_name, old_namelen,
                                src_ino, src_ftype);
            mxfs_dir_add_entry(mnt->dcache, new_dir_ino,
                                new_name, new_namelen,
                                dst_ino, dst_ftype);
            return ret;
        }

        ret = mxfs_dir_add_entry(mnt->dcache, new_dir_ino,
                                  new_name, new_namelen,
                                  src_ino, src_ftype);
        if (ret) {
            /* Best-effort restore */
            mxfs_dir_add_entry(mnt->dcache, old_dir_ino,
                                old_name, old_namelen,
                                src_ino, src_ftype);
            mxfs_dir_add_entry(mnt->dcache, new_dir_ino,
                                new_name, new_namelen,
                                dst_ino, dst_ftype);
            return ret;
        }

        return 0;
    }

    /* Check if destination already exists */
    ret = mxfs_dir_lookup(mnt->dcache, new_dir_ino, new_name, new_namelen,
                           &dst_ino);
    if (ret == 0) {
        /* Destination exists */
        if (flags & MXFS_RENAME_NOREPLACE)
            return -EEXIST;

        /* Classic rename: remove existing destination first */
        {
            bool should_free = false;

            ci = mxfs_inode_cache_get_exclusive(mnt->icache, dst_ino, &err);
            if (ci) {
                if (ci->nlink > 0)
                    ci->nlink--;
                mxfs_inode_cache_dirty(mnt->icache, ci);
                should_free = (ci->nlink == 0);
                mxfs_inode_cache_put(mnt->icache, ci);

                mxfs_dir_remove_entry(mnt->dcache, new_dir_ino, new_name,
                                       new_namelen);

                if (should_free) {
                    mxfs_inode_cache_invalidate(mnt->icache, dst_ino);
                    mxfs_free_inode(mnt->alloc, dst_ino);
                }
            }
        }
    }

    if (old_dir_ino == new_dir_ino) {
        /* Same directory — just rename the entry */
        return mxfs_dir_rename_entry(mnt->dcache, old_dir_ino,
                                      old_name, old_namelen,
                                      new_name, new_namelen);
    }

    /* Cross-directory rename: remove from old, add to new */
    ftype = MXFS_FT_REG_FILE;

    ci = mxfs_inode_cache_get(mnt->icache, src_ino, &err);
    if (ci) {
        ftype = mxfs_mode_to_ftype(ci->mode);
        mxfs_inode_cache_put(mnt->icache, ci);
    }

    ret = mxfs_dir_add_entry(mnt->dcache, new_dir_ino, new_name, new_namelen,
                              src_ino, ftype);
    if (ret)
        return ret;

    ret = mxfs_dir_remove_entry(mnt->dcache, old_dir_ino, old_name,
                                 old_namelen);
    return ret;
}

int mxfs_link(struct mxfs_mount *mnt,
              uint64_t dir_ino,
              const char *name, uint8_t namelen,
              uint64_t target_ino)
{
    struct mxfs_cached_inode *ci;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name)
        return -EINVAL;

    /* Increment target nlink */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, target_ino, &err);
    if (!ci)
        return err;

    if (MXFS_S_ISDIR(ci->mode)) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -EPERM; /* No hard links to directories */
    }

    ci->nlink++;
    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Add directory entry */
    ret = mxfs_dir_add_entry(mnt->dcache, dir_ino, name, namelen,
                              target_ino, MXFS_FT_REG_FILE);
    if (ret) {
        /* Rollback nlink increment */
        ci = mxfs_inode_cache_get_exclusive(mnt->icache, target_ino, &err);
        if (ci) {
            ci->nlink--;
            mxfs_inode_cache_dirty(mnt->icache, ci);
            mxfs_inode_cache_put(mnt->icache, ci);
        }
        return ret;
    }

    return 0;
}

/*
 * Build a V5 CRC symlink data block header (56 bytes).
 *
 * XFS stores long symlink targets in data blocks with a per-block header
 * (V5 only; V4 has no header). Each block's header tracks which byte
 * range of the symlink target it contains.
 *
 * On-disk layout (xfs_dsymlink_hdr):
 *   offset  0: sl_magic   (be32)  XFS_SYMLINK_MAGIC
 *   offset  4: sl_offset  (be32)  byte offset of this chunk in target
 *   offset  8: sl_bytes   (be32)  bytes of target in this block
 *   offset 12: sl_crc     (le32)  CRC32C of entire block
 *   offset 16: sl_uuid    (16 bytes) filesystem UUID
 *   offset 32: sl_owner   (be64)  inode number
 *   offset 40: sl_blkno   (be64)  disk block number in 512-byte sectors
 *   offset 48: sl_lsn     (be64)  log sequence number (0 for new blocks)
 */
static void build_symlink_hdr_v5(uint8_t *blkbuf, uint32_t blocksize,
                                  uint32_t offset, uint32_t nbytes,
                                  const uint8_t *uuid, uint64_t owner,
                                  uint64_t disk_blkno_sectors)
{
    uint32_t crc;

    memset(blkbuf, 0, XFS_DSYMLINK_HDR_SIZE);

    mount_put_be32(blkbuf + 0, XFS_SYMLINK_MAGIC);
    mount_put_be32(blkbuf + 4, offset);
    mount_put_be32(blkbuf + 8, nbytes);
    /* sl_crc at offset 12 — zeroed for now, computed below */
    memcpy(blkbuf + 16, uuid, 16);
    mount_put_be64(blkbuf + 32, owner);
    mount_put_be64(blkbuf + 40, disk_blkno_sectors);
    mount_put_be64(blkbuf + 48, 0);  /* sl_lsn = 0 for new blocks */

    /* CRC32C over the entire block (with sl_crc field zeroed) */
    crc = mxfs_pal_crc32c(~(uint32_t)0, blkbuf, blocksize);
    mount_put_le32(blkbuf + XFS_SYMLINK_CRC_OFF, ~crc);
}

/*
 * Write long symlink target data into allocated data blocks.
 *
 * For V5 (CRC) filesystems, each block gets an xfs_dsymlink_hdr
 * (56 bytes) followed by the target data. For V4, the target data
 * is written directly with no header.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int symlink_write_remote_blocks(struct mxfs_mount *mnt,
                                        uint64_t ino,
                                        const char *target,
                                        int target_len,
                                        struct mxfs_extent_map *emap)
{
    int bufspace = mxfs_xfs_symlink_buf_space(mnt->sb.is_v5,
                                               mnt->sb.blocksize);
    int nblocks = mxfs_xfs_symlink_blocks(mnt->sb.is_v5,
                                            mnt->sb.blocksize, target_len);
    int offset = 0;
    int n;
    uint8_t *blkbuf;
    int ret;

    blkbuf = mxfs_pal_alloc(mnt->sb.blocksize);
    if (!blkbuf)
        return -ENOMEM;

    for (n = 0; n < nblocks; n++) {
        const struct mxfs_extent *ext;
        uint64_t disk_offset;
        int chunk = target_len - offset;
        uint8_t *data_start;

        if (chunk > bufspace)
            chunk = bufspace;

        ext = mxfs_extent_map_get(emap, n);
        if (!ext) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "symlink: ino %llu extent %d missing",
                         (unsigned long long)ino, n);
            mxfs_pal_free(blkbuf);
            return -EIO;
        }

        memset(blkbuf, 0, mnt->sb.blocksize);

        if (mnt->sb.is_v5) {
            uint64_t sectors = ext->startblock *
                                (mnt->sb.blocksize / 512);
            build_symlink_hdr_v5(blkbuf, mnt->sb.blocksize,
                                  (uint32_t)offset, (uint32_t)chunk,
                                  mnt->sb.uuid, ino, sectors);
            data_start = blkbuf + XFS_DSYMLINK_HDR_SIZE;
        } else {
            data_start = blkbuf;
        }

        memcpy(data_start, target + offset, chunk);

        /* Recompute CRC after data is written (V5 only) */
        if (mnt->sb.is_v5) {
            uint32_t crc;
            memset(blkbuf + XFS_SYMLINK_CRC_OFF, 0, 4);
            crc = mxfs_pal_crc32c(~(uint32_t)0, blkbuf,
                                    mnt->sb.blocksize);
            mount_put_le32(blkbuf + XFS_SYMLINK_CRC_OFF, ~crc);
        }

        disk_offset = mxfs_xfs_fsblock_to_offset(&mnt->sb,
                                                    ext->startblock);
        ret = mxfs_pal_bdev_write_fua(mnt->xfs_dev, disk_offset,
                                       blkbuf, mnt->sb.blocksize);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "symlink: ino %llu write block %d at "
                         "fsblock %llu failed: %d",
                         (unsigned long long)ino, n,
                         (unsigned long long)ext->startblock, ret);
            mxfs_pal_free(blkbuf);
            return ret;
        }

        offset += chunk;
    }

    mxfs_pal_free(blkbuf);
    return 0;
}

int mxfs_symlink(struct mxfs_mount *mnt,
                 uint64_t dir_ino,
                 const char *name, uint8_t namelen,
                 const char *target, uint16_t target_len,
                 uint32_t uid, uint32_t gid,
                 uint64_t *ino_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t new_ino;
    uint64_t now;
    int err;
    int ret;

    if (!mnt || !mnt->mounted || !name || !target || !ino_out)
        return -EINVAL;

    if (target_len == 0 || target_len > XFS_SYMLINK_MAXLEN)
        return -ENAMETOOLONG;

    ret = mxfs_alloc_inode(mnt->alloc, &new_ino);
    if (ret)
        return ret;

    ci = mxfs_inode_cache_get_new_exclusive(mnt->icache, new_ino, &err);
    if (!ci) {
        mxfs_free_inode(mnt->alloc, new_ino);
        return err;
    }

    ci->mode = MXFS_S_IFLNK | 0777;
    ci->uid = uid;
    ci->gid = gid;
    ci->nlink = 1;
    ci->size = target_len;

    now = mxfs_pal_time_real_sec();
    ci->atime_sec = (uint32_t)now;
    ci->mtime_sec = (uint32_t)now;
    ci->ctime_sec = (uint32_t)now;

    if (target_len <= ci->dfork_size) {
        /*
         * Short symlink: fits inline in the inode data fork (FMT_LOCAL).
         * This is the common case for symlinks under ~336 bytes.
         */
        ci->format = XFS_DINODE_FMT_LOCAL;

        ci->inline_data = mxfs_pal_alloc(target_len);
        if (!ci->inline_data) {
            mxfs_inode_cache_put(mnt->icache, ci);
            mxfs_free_inode(mnt->alloc, new_ino);
            return -ENOMEM;
        }
        memcpy(ci->inline_data, target, target_len);
        ci->inline_len = target_len;
    } else {
        /*
         * Long symlink: target exceeds inline capacity.
         * Allocate data blocks, write symlink data (with per-block
         * headers for V5 CRC filesystems), and set FMT_EXTENTS.
         */
        int nblocks;
        int i;

        ci->format = XFS_DINODE_FMT_EXTENTS;
        ci->nextents = 0;

        nblocks = mxfs_xfs_symlink_blocks(mnt->sb.is_v5,
                                            mnt->sb.blocksize,
                                            (int)target_len);

        /* Create extent map for this inode */
        ci->extents = mxfs_extent_map_create();
        if (!ci->extents) {
            mxfs_inode_cache_put(mnt->icache, ci);
            mxfs_free_inode(mnt->alloc, new_ino);
            return -ENOMEM;
        }

        /* Allocate data blocks and build extent map */
        for (i = 0; i < nblocks; i++) {
            uint64_t fsblock;
            uint32_t len_got;

            ret = mxfs_alloc_blocks(mnt->alloc, 1, 0, &fsblock, &len_got);
            if (ret || len_got == 0) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "symlink: ino %llu alloc block %d/%d "
                             "failed: %d",
                             (unsigned long long)new_ino,
                             i, nblocks, ret);
                /* Free already-allocated blocks */
                {
                    int j;
                    for (j = 0; j < i; j++) {
                        const struct mxfs_extent *ext =
                            mxfs_extent_map_get(ci->extents, j);
                        if (ext)
                            mxfs_free_blocks(mnt->alloc,
                                              ext->startblock,
                                              ext->blockcount);
                    }
                }
                mxfs_extent_map_destroy(ci->extents);
                ci->extents = NULL;
                mxfs_inode_cache_put(mnt->icache, ci);
                mxfs_free_inode(mnt->alloc, new_ino);
                return ret ? ret : -ENOSPC;
            }

            ret = mxfs_extent_map_insert(ci->extents,
                                           (uint64_t)i, fsblock,
                                           1, false);
            if (ret) {
                mxfs_free_blocks(mnt->alloc, fsblock, 1);
                {
                    int j;
                    for (j = 0; j < i; j++) {
                        const struct mxfs_extent *ext =
                            mxfs_extent_map_get(ci->extents, j);
                        if (ext)
                            mxfs_free_blocks(mnt->alloc,
                                              ext->startblock,
                                              ext->blockcount);
                    }
                }
                mxfs_extent_map_destroy(ci->extents);
                ci->extents = NULL;
                mxfs_inode_cache_put(mnt->icache, ci);
                mxfs_free_inode(mnt->alloc, new_ino);
                return ret;
            }
        }

        ci->nextents = nblocks;

        /* Write symlink target data into the allocated blocks */
        ret = symlink_write_remote_blocks(mnt, new_ino, target,
                                           (int)target_len, ci->extents);
        if (ret) {
            int j;
            for (j = 0; j < nblocks; j++) {
                const struct mxfs_extent *ext =
                    mxfs_extent_map_get(ci->extents, j);
                if (ext)
                    mxfs_free_blocks(mnt->alloc, ext->startblock,
                                      ext->blockcount);
            }
            mxfs_extent_map_destroy(ci->extents);
            ci->extents = NULL;
            mxfs_inode_cache_put(mnt->icache, ci);
            mxfs_free_inode(mnt->alloc, new_ino);
            return ret;
        }

        /* No inline data for FMT_EXTENTS symlinks */
        ci->inline_data = NULL;
        ci->inline_len = 0;

        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "symlink: ino %llu long symlink (%u bytes, "
                     "%d blocks, dfork_size=%d)",
                     (unsigned long long)new_ino, target_len,
                     nblocks, ci->dfork_size);
    }

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);

    /* Add entry in parent directory.
     * If this fails, free the orphan inode back to the allocator. */
    ret = mxfs_dir_add_entry(mnt->dcache, dir_ino, name, namelen,
                              new_ino, MXFS_FT_SYMLINK);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "symlink: dir_add_entry for '%.*s' in dir %llu "
                     "failed: %d, freeing orphan inode %llu",
                     (int)namelen, name,
                     (unsigned long long)dir_ino, ret,
                     (unsigned long long)new_ino);
        mxfs_free_inode(mnt->alloc, new_ino);
        return ret;
    }

    *ino_out = new_ino;
    return 0;
}

/*
 * Read symlink target from remote (extent-based) data blocks.
 *
 * For V5 CRC filesystems, each block has an xfs_dsymlink_hdr (56 bytes)
 * before the actual target data. For V4, data starts at offset 0.
 *
 * Returns bytes copied into buf, or negative errno on error.
 */
static int readlink_remote(struct mxfs_mount *mnt,
                            struct mxfs_cached_inode *ci,
                            char *buf, uint32_t buflen)
{
    int pathlen = (int)ci->size;
    int bufspace = mxfs_xfs_symlink_buf_space(mnt->sb.is_v5,
                                               mnt->sb.blocksize);
    int nblocks = mxfs_xfs_symlink_blocks(mnt->sb.is_v5,
                                            mnt->sb.blocksize, pathlen);
    int offset = 0;
    int n;
    uint8_t *blkbuf;
    int ret;
    int total_copied = 0;

    if (pathlen <= 0 || pathlen > XFS_SYMLINK_MAXLEN)
        return -EIO;

    if (!ci->extents) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "readlink: ino %llu FMT_EXTENTS but no extent map",
                     (unsigned long long)ci->ino);
        return -EIO;
    }

    blkbuf = mxfs_pal_alloc(mnt->sb.blocksize);
    if (!blkbuf)
        return -ENOMEM;

    for (n = 0; n < nblocks && offset < pathlen; n++) {
        uint64_t phys_block;
        uint32_t flags;
        uint64_t disk_offset;
        const uint8_t *data_start;
        int chunk;
        int copy_len;

        /* Look up the physical block for logical block n */
        phys_block = mxfs_extent_map_lookup(ci->extents,
                                              (uint64_t)n, &flags);
        if (phys_block == MXFS_EXTENT_HOLE) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "readlink: ino %llu block %d is a hole",
                         (unsigned long long)ci->ino, n);
            mxfs_pal_free(blkbuf);
            return -EIO;
        }

        disk_offset = mxfs_xfs_fsblock_to_offset(&mnt->sb, phys_block);

        ret = mxfs_pal_bdev_read(mnt->xfs_dev, disk_offset,
                                  blkbuf, mnt->sb.blocksize);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "readlink: ino %llu read block %d at "
                         "fsblock %llu failed: %d",
                         (unsigned long long)ci->ino, n,
                         (unsigned long long)phys_block, ret);
            mxfs_pal_free(blkbuf);
            return ret;
        }

        /* Validate and skip V5 header */
        if (mnt->sb.is_v5) {
            uint32_t magic = mount_get_be32(blkbuf);
            if (magic != XFS_SYMLINK_MAGIC) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "readlink: ino %llu block %d bad magic "
                             "0x%08x (expected 0x%08x)",
                             (unsigned long long)ci->ino, n,
                             magic, XFS_SYMLINK_MAGIC);
                mxfs_pal_free(blkbuf);
                return -EIO;
            }
            data_start = blkbuf + XFS_DSYMLINK_HDR_SIZE;
        } else {
            data_start = blkbuf;
        }

        /* How many bytes of target data in this block */
        chunk = pathlen - offset;
        if (chunk > bufspace)
            chunk = bufspace;

        /* Copy to output buffer, respecting buflen */
        copy_len = chunk;
        if ((uint32_t)(total_copied + copy_len) > buflen)
            copy_len = (int)(buflen - total_copied);
        if (copy_len > 0) {
            memcpy(buf + total_copied, data_start, copy_len);
            total_copied += copy_len;
        }

        offset += chunk;
    }

    mxfs_pal_free(blkbuf);
    return total_copied;
}

int mxfs_readlink(struct mxfs_mount *mnt, uint64_t ino,
                  char *buf, uint32_t buflen)
{
    struct mxfs_cached_inode *ci;
    int err;
    int copy_len;

    if (!mnt || !mnt->mounted || !buf)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err;

    if (!MXFS_S_ISLNK(ci->mode)) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -EINVAL;
    }

    if (ci->format == XFS_DINODE_FMT_LOCAL) {
        /* Short (inline) symlink */
        if (!ci->inline_data) {
            mxfs_inode_cache_put(mnt->icache, ci);
            return -EIO;
        }

        copy_len = ci->inline_len;
        if ((uint32_t)copy_len > buflen)
            copy_len = buflen;

        memcpy(buf, ci->inline_data, copy_len);
        mxfs_inode_cache_put(mnt->icache, ci);
        return copy_len;
    }

    if (ci->format == XFS_DINODE_FMT_EXTENTS ||
        ci->format == XFS_DINODE_FMT_BTREE) {
        /* Long (remote) symlink stored in data blocks */
        int result = readlink_remote(mnt, ci, buf, buflen);
        mxfs_inode_cache_put(mnt->icache, ci);
        return result;
    }

    /* Unknown format */
    mxfs_pal_log(MXFS_LOG_ERR,
                 "readlink: ino %llu unexpected format %u",
                 (unsigned long long)ino, ci->format);
    mxfs_inode_cache_put(mnt->icache, ci);
    return -EIO;
}

/* ─── Public API: Attribute operations ─── */

int mxfs_chmod(struct mxfs_mount *mnt, uint64_t ino, uint16_t mode)
{
    struct mxfs_cached_inode *ci;
    int err;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    ci->mode = (ci->mode & MXFS_S_IFMT) | (mode & 07777);
    ci->ctime_sec = (uint32_t)mxfs_pal_time_real_sec();

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

int mxfs_chown(struct mxfs_mount *mnt, uint64_t ino,
               uint32_t uid, uint32_t gid)
{
    struct mxfs_cached_inode *ci;
    int err;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    ci->uid = uid;
    ci->gid = gid;
    ci->ctime_sec = (uint32_t)mxfs_pal_time_real_sec();

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

int mxfs_utimes(struct mxfs_mount *mnt, uint64_t ino,
                uint32_t atime_sec, uint32_t atime_nsec,
                uint32_t mtime_sec, uint32_t mtime_nsec)
{
    struct mxfs_cached_inode *ci;
    int err;

    if (!mnt || !mnt->mounted)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err;

    ci->atime_sec = atime_sec;
    ci->atime_nsec = atime_nsec;
    ci->mtime_sec = mtime_sec;
    ci->mtime_nsec = mtime_nsec;
    ci->ctime_sec = (uint32_t)mxfs_pal_time_real_sec();

    mxfs_inode_cache_dirty(mnt->icache, ci);
    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

/* ─── Public API: Query ─── */

uint64_t mxfs_root_ino(struct mxfs_mount *mnt)
{
    if (!mnt)
        return 0;
    return mnt->sb.rootino;
}

int mxfs_statfs(struct mxfs_mount *mnt,
                uint32_t *blocksize,
                uint64_t *total_blocks,
                uint64_t *free_blocks,
                uint64_t *total_inodes,
                uint64_t *free_inodes)
{
    if (!mnt || !mnt->mounted)
        return -EINVAL;

    if (blocksize)
        *blocksize = mnt->sb.blocksize;
    if (total_blocks)
        *total_blocks = mnt->sb.dblocks;

    /* Recount from on-disk AGF/AGI to get cluster-accurate values.
     * Each node's in-memory counter only reflects local alloc/free;
     * recount reads the ground truth from disk (Bug 134). */
    if (mnt->alloc) {
        mxfs_alloc_recount_counters(mnt->alloc);
        mxfs_alloc_get_counters(mnt->alloc, free_blocks,
                                total_inodes, free_inodes);
    } else {
        /* Fallback to superblock snapshot if allocator not yet initialized */
        if (free_blocks)
            *free_blocks = mnt->sb.fdblocks;
        if (total_inodes)
            *total_inodes = mnt->sb.icount;
        if (free_inodes)
            *free_inodes = mnt->sb.ifree;
    }

    return 0;
}

enum mxfs_dlm_transport mxfs_get_dlm_transport(struct mxfs_mount *mnt)
{
    if (!mnt)
        return MXFS_DLM_TRANSPORT_TCP;
    return mnt->dlm_transport;
}

/* ─── Public API: Page cache support ─── */

void mxfs_set_page_invalidate_cb(struct mxfs_mount *mnt,
                                 void (*fn)(void *, uint64_t), void *ctx)
{
    if (!mnt || !mnt->icache)
        return;
    mnt->icache->page_invalidate_fn = fn;
    mnt->icache->page_invalidate_ctx = ctx;
}

int mxfs_inode_lock_shared(struct mxfs_mount *mnt, uint64_t ino,
                           uint64_t *size_out)
{
    struct mxfs_cached_inode *ci;
    int err = 0;

    if (!mnt || !mnt->icache)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (size_out)
        *size_out = ci->size;

    return 0;
}

int mxfs_inode_lock_exclusive(struct mxfs_mount *mnt, uint64_t ino,
                              uint64_t *size_out)
{
    struct mxfs_cached_inode *ci;
    int err = 0;

    if (!mnt || !mnt->icache)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (size_out)
        *size_out = ci->size;

    return 0;
}

void mxfs_inode_unlock(struct mxfs_mount *mnt, uint64_t ino)
{
    if (!mnt || !mnt->icache)
        return;
    mxfs_inode_cache_put_by_ino(mnt->icache, ino);
}

int mxfs_inode_lock_downgrade(struct mxfs_mount *mnt, uint64_t ino)
{
    if (!mnt || !mnt->icache)
        return -EINVAL;
    return mxfs_inode_cache_downgrade(mnt->icache, ino);
}

int mxfs_get_block_map(struct mxfs_mount *mnt, uint64_t ino,
                       uint64_t logical_block,
                       uint64_t *phys_block_out, uint32_t *flags_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t phys;
    uint32_t flags = 0;
    int err = 0;

    if (!mnt || !mnt->icache || !phys_block_out)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (!ci->extents || ci->format == XFS_DINODE_FMT_LOCAL) {
        /* Inline data or no extents — no block mapping */
        mxfs_inode_cache_put(mnt->icache, ci);
        *phys_block_out = UINT64_MAX;
        if (flags_out)
            *flags_out = MXFS_PGCACHE_F_HOLE;
        return 0;
    }

    phys = mxfs_extent_map_lookup(ci->extents, logical_block, &flags);
    mxfs_inode_cache_put(mnt->icache, ci);

    *phys_block_out = phys;
    if (flags_out) {
        uint32_t out = 0;
        if (phys == MXFS_EXTENT_HOLE || (flags & MXFS_EXTENT_F_HOLE))
            out |= MXFS_PGCACHE_F_HOLE;
        if (flags & MXFS_EXTENT_F_UNWRITTEN)
            out |= MXFS_PGCACHE_F_UNWRITTEN;
        *flags_out = out;
    }

    return 0;
}

int mxfs_get_block_map_range(struct mxfs_mount *mnt, uint64_t ino,
                              uint64_t logical_block,
                              struct mxfs_extent_range *range)
{
    struct mxfs_cached_inode *ci;
    int err = 0;

    if (!mnt || !mnt->icache || !range)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (!ci->extents || ci->format == XFS_DINODE_FMT_LOCAL) {
        /* Inline data or no extents — report as hole */
        mxfs_inode_cache_put(mnt->icache, ci);
        range->phys_start = 0;
        range->blockcount = UINT32_MAX;
        range->flags = MXFS_EXTENT_F_HOLE;
        return 0;
    }

    err = mxfs_extent_map_lookup_range(ci->extents, logical_block, range);
    mxfs_inode_cache_put(mnt->icache, ci);

    return err;
}

int mxfs_convert_unwritten(struct mxfs_mount *mnt, uint64_t ino,
                            uint64_t logical_block)
{
    struct mxfs_cached_inode *ci;
    int err = 0;
    int i;

    if (!mnt || !mnt->icache)
        return -EINVAL;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (!ci->extents) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -EINVAL;
    }

    for (i = 0; i < ci->extents->count; i++) {
        struct mxfs_extent *e = &ci->extents->extents[i];

        if (logical_block < e->startoff ||
            logical_block >= e->startoff + e->blockcount)
            continue;
        if (!e->unwritten)
            break; /* already written — nothing to do */

        if (e->blockcount == 1) {
            /* Single block — just clear unwritten */
            e->unwritten = false;
        } else if (logical_block == e->startoff) {
            /* First block — shrink extent, insert written block */
            uint64_t phys = e->startblock;

            e->startoff++;
            e->startblock++;
            e->blockcount--;
            err = mxfs_extent_map_insert(ci->extents,
                                          logical_block, phys, 1, false);
        } else if (logical_block == e->startoff + e->blockcount - 1) {
            /* Last block — shrink extent, insert written block */
            uint64_t phys = e->startblock +
                            (logical_block - e->startoff);

            e->blockcount--;
            err = mxfs_extent_map_insert(ci->extents,
                                          logical_block, phys, 1, false);
        } else {
            /* Middle — split into three:
             * [startoff..block-1] unwritten
             * [block] written
             * [block+1..end] unwritten */
            uint64_t mid_phys = e->startblock +
                                (logical_block - e->startoff);
            uint64_t right_off = logical_block + 1;
            uint64_t right_phys = mid_phys + 1;
            uint32_t right_count = (uint32_t)(
                e->startoff + e->blockcount - right_off);

            /* Shrink original to left unwritten portion */
            e->blockcount = (uint32_t)(logical_block - e->startoff);

            /* Insert the written single block */
            err = mxfs_extent_map_insert(ci->extents,
                                          logical_block, mid_phys,
                                          1, false);
            if (!err) {
                /* Insert right unwritten portion */
                err = mxfs_extent_map_insert(ci->extents,
                                              right_off, right_phys,
                                              right_count, true);
            }
        }

        if (!err) {
            ci->nextents = mxfs_extent_map_count(ci->extents);
            mxfs_inode_cache_dirty(mnt->icache, ci);
        }
        break;
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return err;
}

int mxfs_update_inode_size(struct mxfs_mount *mnt, uint64_t ino,
                           uint64_t new_size)
{
    struct mxfs_cached_inode *ci;
    int err = 0;

    if (!mnt || !mnt->icache)
        return -EINVAL;

    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    if (new_size > ci->size) {
        uint64_t old_size = ci->size;
        ci->size = new_size;
        mxfs_inode_cache_dirty(mnt->icache, ci);
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "mount: update_inode_size ino %llu old=%llu new=%llu",
                     (unsigned long long)ino,
                     (unsigned long long)old_size,
                     (unsigned long long)new_size);
    }

    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

int mxfs_alloc_file_block(struct mxfs_mount *mnt, uint64_t ino,
                          uint64_t logical_block,
                          uint64_t *phys_block_out)
{
    struct mxfs_cached_inode *ci;
    uint64_t alloc_fsblock;
    uint32_t alloc_len;
    int err = 0;

    if (!mnt || !mnt->icache || !phys_block_out)
        return -EINVAL;

    /* The caller must already hold EX lock — just look up the inode.
     * Use get_exclusive which increments refcount (lock already cached). */
    ci = mxfs_inode_cache_get_exclusive(mnt->icache, ino, &err);
    if (!ci)
        return err ? err : -EIO;

    /* Adaptive speculative preallocation: scale prealloc size with file
     * offset to balance space efficiency (small files) with throughput
     * (large sequential writes).  Tier thresholds match common patterns:
     *   - First 64KB:  16 blocks (64KB) — small files waste little
     *   - Up to 1MB:  256 blocks (1MB) — moderate files
     *   - Beyond 1MB: 2048 blocks (8MB) — large sequential writes
     *
     * At 8MB prealloc, a 128MB file needs only 16 allocation calls
     * (vs 128 at 1MB), reducing DLM lock round-trips 8x.  The allocator
     * returns the actual contiguous length (may be less than requested).
     *
     * Near-allocation: pass the physical end of the file's last extent
     * as a target so the allocator tries to place the new extent
     * contiguously, reducing fragmentation for sequential writes. */
    {
        uint32_t prealloc;
        uint64_t target = 0;

        /* Compute near-allocation target from the last extent */
        if (ci->extents) {
            int nex = mxfs_extent_map_count(ci->extents);
            if (nex > 0) {
                const struct mxfs_extent *last;
                last = mxfs_extent_map_get(ci->extents, nex - 1);
                if (last && last->blockcount > 0)
                    target = last->startblock + last->blockcount;
            }
        }

        if (logical_block < 16)
            prealloc = 16;
        else if (logical_block < 256)
            prealloc = 256;
        else
            prealloc = 2048;
        err = mxfs_alloc_blocks(mnt->alloc, prealloc, target,
                                &alloc_fsblock, &alloc_len);
    }
    if (err) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return err;
    }

    *phys_block_out = alloc_fsblock;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "mount: alloc_file_block ino %llu lblock=%llu "
                 "phys=%llu len=%u",
                 (unsigned long long)ino,
                 (unsigned long long)logical_block,
                 (unsigned long long)alloc_fsblock,
                 alloc_len);

    /* Insert into extent map */
    err = mxfs_extent_map_insert(ci->extents, logical_block,
                                  alloc_fsblock, alloc_len, false);
    if (err) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return err;
    }

    /* Transition from inline (FMT_LOCAL) to extent-based format.
     * When the page cache write path allocates a block for a file
     * that was previously inline, the format must be updated so
     * that subsequent reads via mxfs_get_block_map find the extent
     * instead of treating the file as inline/hole. */
    if (ci->format == XFS_DINODE_FMT_LOCAL)
        ci->format = XFS_DINODE_FMT_EXTENTS;

    /* Update extent count and mark dirty */
    ci->nextents = mxfs_extent_map_count(ci->extents);
    mxfs_inode_cache_dirty(mnt->icache, ci);

    mxfs_inode_cache_put(mnt->icache, ci);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * SEEK_DATA / SEEK_HOLE — sparse file seek support
 *
 * Walk the cached inode's sorted extent map to find data regions
 * and holes. The extent map is sorted by startoff (logical block)
 * and holes are implicit gaps between extents.
 *
 * Acquires a PR (shared) DLM lock on the inode via the inode cache.
 * ═══════════════════════════════════════════════════════════════════ */

int64_t mxfs_seek_data(struct mxfs_mount *mnt, uint64_t ino, int64_t offset)
{
    struct mxfs_cached_inode *ci;
    int err = 0;
    int64_t file_size;
    uint64_t block_off;
    uint32_t blocksize;
    int i;
    int ext_count;

    if (!mnt || !mnt->icache)
        return -EINVAL;
    if (offset < 0)
        return -ENXIO;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? (int64_t)err : -EIO;

    file_size = (int64_t)ci->size;

    /* Past or at EOF: no data */
    if (offset >= file_size) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENXIO;
    }

    /* FMT_LOCAL (inline data): entire file is data, no holes */
    if (!ci->extents || ci->format == XFS_DINODE_FMT_LOCAL) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return offset;
    }

    blocksize = mnt->sb.blocksize;
    ext_count = mxfs_extent_map_count(ci->extents);

    /* No extents: entire file is a hole */
    if (ext_count == 0) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENXIO;
    }

    /* Convert byte offset to logical block offset */
    block_off = (uint64_t)offset / blocksize;

    /* Walk extents (sorted by startoff) to find data at or after offset */
    for (i = 0; i < ext_count; i++) {
        const struct mxfs_extent *ext = mxfs_extent_map_get(ci->extents, i);
        uint64_t ext_end;

        if (!ext)
            continue;

        ext_end = ext->startoff + ext->blockcount;

        /* Skip extents entirely before our position */
        if (ext_end <= block_off)
            continue;

        /* Offset falls within this extent: already in data */
        if (block_off >= ext->startoff && block_off < ext_end) {
            mxfs_inode_cache_put(mnt->icache, ci);
            return offset;
        }

        /* Offset is in a hole before this extent: return extent start */
        if (block_off < ext->startoff) {
            int64_t data_start = (int64_t)(ext->startoff * blocksize);
            mxfs_inode_cache_put(mnt->icache, ci);
            if (data_start >= file_size)
                return -ENXIO;
            return data_start;
        }
    }

    /* No data found at or after offset */
    mxfs_inode_cache_put(mnt->icache, ci);
    return -ENXIO;
}

int64_t mxfs_seek_hole(struct mxfs_mount *mnt, uint64_t ino, int64_t offset)
{
    struct mxfs_cached_inode *ci;
    int err = 0;
    int64_t file_size;
    uint64_t block_off;
    uint32_t blocksize;
    int i;
    int ext_count;

    if (!mnt || !mnt->icache)
        return -EINVAL;
    if (offset < 0)
        return -ENXIO;

    ci = mxfs_inode_cache_get(mnt->icache, ino, &err);
    if (!ci)
        return err ? (int64_t)err : -EIO;

    file_size = (int64_t)ci->size;

    /* At or past EOF: no hole to report */
    if (offset >= file_size) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return -ENXIO;
    }

    /* FMT_LOCAL (inline data): only hole is the virtual one at EOF */
    if (!ci->extents || ci->format == XFS_DINODE_FMT_LOCAL) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return file_size;
    }

    blocksize = mnt->sb.blocksize;
    ext_count = mxfs_extent_map_count(ci->extents);

    /* No extents: entire file is a hole */
    if (ext_count == 0) {
        mxfs_inode_cache_put(mnt->icache, ci);
        return offset;
    }

    /* Convert byte offset to logical block offset */
    block_off = (uint64_t)offset / blocksize;

    /* Walk extents to find the first hole at or after offset */
    for (i = 0; i < ext_count; i++) {
        const struct mxfs_extent *ext = mxfs_extent_map_get(ci->extents, i);
        uint64_t ext_end;

        if (!ext)
            continue;

        ext_end = ext->startoff + ext->blockcount;

        /* Skip extents entirely before our position */
        if (ext_end <= block_off)
            continue;

        /* Offset is in a hole before this extent: already in hole */
        if (block_off < ext->startoff) {
            mxfs_inode_cache_put(mnt->icache, ci);
            return offset;
        }

        /* Offset falls within this extent: hole starts at extent end */
        if (block_off >= ext->startoff && block_off < ext_end) {
            int64_t hole_start = (int64_t)(ext_end * blocksize);
            mxfs_inode_cache_put(mnt->icache, ci);
            /* Clamp to file_size (virtual hole at EOF) */
            if (hole_start >= file_size)
                return file_size;
            return hole_start;
        }
    }

    /* Past all extents but before EOF: we're in a trailing hole */
    mxfs_inode_cache_put(mnt->icache, ci);
    return offset;
}
