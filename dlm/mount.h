/*
 * MXFS — Multinode XFS
 * Mount orchestration — internal header
 *
 * Defines the mxfs_mount structure with all subsystem contexts.
 * This is an internal header used by mount.c and other libmxfs
 * modules that need access to the mount state. The public API
 * in mxfs.h exposes only the opaque struct mxfs_mount pointer.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_MOUNT_H
#define MXFS_LIBMXFS_MOUNT_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_super.h"
#include "../include/mxfs/mxfs_dlm.h"
#include "xfs_format.h"
#include "block_cache.h"
#include "inode_cache.h"
#include "dir_cache.h"
#include "alloc.h"
#include "dlm.h"
#include "dlm_caw.h"
#include "peer.h"
#include "discovery.h"
#include "lease.h"
#include "journal.h"
#include "disklock.h"
#include "scsipr.h"
#include "extent.h"
#include "mxfs.h"

/* Mount state */
struct mxfs_mount {
    /* Block device */
    mxfs_bdev_t             *dev;       /* raw device (for MXFS meta, journal, disklock) */
    mxfs_bdev_t             *xfs_dev;   /* offset clone (for XFS data I/O) */
    char                    dev_path[MXFS_PATH_MAX];

    /* XFS superblock (parsed, host byte order) */
    struct mxfs_xfs_sb      sb;

    /* Node identity */
    mxfs_node_id_t          node_id;
    uint8_t                 node_uuid[16];
    mxfs_volume_id_t        volume_id;
    uint32_t                node_slot;

    /* DLM transport selection and dispatch */
    enum mxfs_dlm_transport     dlm_transport;
    struct mxfs_dlm_caw_ctx     *dlm_caw;   /* non-NULL when transport=caw */
    mxfs_dlm_lock_fn            dlm_lock_fn;
    mxfs_dlm_unlock_fn          dlm_unlock_fn;
    mxfs_dlm_convert_fn         dlm_convert_fn;
    void                        *dlm_dispatch_ctx;

    /* Subsystem contexts (init order: DLM, peer, SCSI PR,
     * disklock, discovery, lease, journal, block_cache,
     * inode_cache, dir_cache, alloc) */
    struct mxfs_dlm_ctx         *dlm;
    struct mxfs_peer_ctx        *peer;
    struct mxfs_scsipr_ctx      *scsipr;
    struct mxfs_disklock_ctx    *disklock;
    struct mxfs_discovery_ctx   *discovery;
    struct mxfs_lease_ctx       *lease;
    struct mxfs_journal_ctx     *journal;
    struct mxfs_block_cache     *bcache;
    struct mxfs_inode_cache     *icache;
    struct mxfs_dir_cache       *dcache;
    struct mxfs_alloc_ctx       *alloc;

    /* Mount options */
    struct mxfs_mount_opts  opts;

    /* State flags */
    bool                    mounted;
    bool                    tcp_scale_warned; /* one-shot: warned about >16 TCP DLM nodes */

    /* Journal recovery thread spawned by peer_disconnect_cb.
     * Stored so it can be joined before spawning a new one
     * or during unmount. Protected by recovery_lock. */
    mxfs_thread_t           *recovery_thread;
    mxfs_mutex_t            *recovery_lock;

    /* BAST worker thread — defers blocking cache flush/invalidation
     * off the DLM recv thread to prevent TCP buffer overflow */
    mxfs_thread_t           *bast_thread;
    mxfs_mutex_t            *bast_lock;
    mxfs_cond_t             *bast_cond;
    struct bast_work_item   *bast_head;
    struct bast_work_item   *bast_tail;
    bool                    bast_running;

    /* Cache flush worker thread — Bug 66: defers blocking cache flush
     * operations off the DLM membership callback path. Without this,
     * synchronous cache flushes (10-100+ seconds under load) in
     * dlm_membership_cb() starve lease renewals, causing false node
     * death detection. The DLM callback just sets cache_flush_pending
     * and signals the worker, returning immediately. */
    mxfs_thread_t           *cache_flush_thread;
    mxfs_mutex_t            *cache_flush_lock;
    mxfs_cond_t             *cache_flush_cond;
    int                     cache_flush_pending;
    int                     cache_flush_stop;

    /* Per-peer disconnect cooldown — prevents cascading flapping.
     * Under heavy I/O, a TCP disconnect triggers DLM purge + cache
     * invalidation, creating an I/O storm that stalls TCP on other
     * peers, causing more disconnects in rapid succession.
     *
     * Bug 83: Changed from a single global timestamp to per-peer
     * tracking.  The global cooldown was too aggressive — if peer A
     * disconnects, it suppressed processing of peer B's disconnect
     * for 30s even though they are independent events.  Now we only
     * suppress if the SAME peer (same hash slot, node_id % 64)
     * disconnected within the cooldown window.  Different peers get
     * processed immediately.
     *
     * lease_expire_cb still uses a global timestamp (last_lease_expiry)
     * because lease expiry is a heavier operation and cascading lease
     * expiries are always correlated (I/O storm from one expiry
     * starves renewals on other nodes).
     *
     * Does NOT prevent TCP reconnection attempts. */
    uint64_t                last_peer_disconnect[MXFS_MAX_NODES];
    uint64_t                last_lease_expiry;

    /* Membership stabilization timer — prevents full DLM lock table
     * purges on transient TCP flaps.  When peer connect/disconnect
     * events arrive, we defer the mxfs_dlm_update_active_nodes() call
     * (which purges the lock table if the node set changed) until the
     * membership has been stable for MXFS_MEMBERSHIP_STABILIZE_MS.
     * If a TCP flap (disconnect + reconnect) completes within the
     * window, the timer fires with the original node set and
     * update_active_nodes sees no change → no purge.
     *
     * The immediate mxfs_dlm_purge_node() call on disconnect is NOT
     * deferred — only the update_active_nodes() (full table purge) is.
     *
     * Protected by membership_stab_lock. */
    mxfs_mutex_t            *membership_stab_lock;
    mxfs_cond_t             *membership_stab_cond;
    mxfs_thread_t           *membership_stab_thread;
    int                     membership_stab_pending;  /* events queued */
    uint64_t                membership_stab_ts;       /* last event time */
    int                     membership_stab_stop;     /* shutdown flag */

    /* Hot-path cumulative timers (ms + call count) */
    uint64_t                stat_create_ms, stat_create_count;
    uint64_t                stat_mkdir_ms, stat_mkdir_count;
    uint64_t                stat_write_ms, stat_write_count;

    /* mxfs_create sub-operation breakdown */
    uint64_t                stat_create_alloc_ms;
    uint64_t                stat_create_getex_ms;
    uint64_t                stat_create_init_ms;
    uint64_t                stat_create_diradd_ms;
};

#endif /* MXFS_LIBMXFS_MOUNT_H */
