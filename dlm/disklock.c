/*
 * MXFS — Multinode XFS
 * Portable on-disk lock state persistence
 *
 * Persists DLM lock state and node heartbeats to a reserved region
 * on the shared block device. Uses PAL bdev_read/bdev_write for
 * sector-aligned atomic I/O visible to all nodes immediately.
 *
 * Ported from kernel/mxfs_disklock.c — kernel file I/O replaced
 * with PAL block device I/O, delayed_work replaced with PAL thread.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "disklock.h"
#include "../include/mxfs/mxfs_super.h"

/*
 * Instr gate for diagnostic probes — mirrors caw_instr_on() in dlm_caw.c.
 * mxfs_instr_enabled lives in the xfs overlay (xfs_mxfs_dlm.c) and is
 * linked into mxfs.ko alongside this file; user-mode dlm builds (no
 * overlay) compile the gate out.  Pure logging, no side effects.
 */
#ifdef __KERNEL__
extern int mxfs_instr_enabled;
#define dl_instr_on() (unlikely(mxfs_instr_enabled))
#else
#define dl_instr_on() (0)
#endif

/*
 * sess1 (ccloop 46efd8b6) ROOT FIX of the 32/caw budget-timeout family
 * (cache_coherency / crash_consistency / dir_reuse verify convoys) — RULE-4
 * PROVEN chain: the heartbeat monitor scan reads peer HB sectors with a
 * PLAIN, CACHEABLE read (see the sess69 note at the dead-detect confirm —
 * only DEAD detection got the FUA re-check).  Under storm load the block
 * layer / SCST per-initiator cache returns STALE heartbeat sectors, so a
 * peer's evict-ring head_seq is observed JUMPING BACKWARD (stale) and then
 * forward again (fresh).  The old consume condition (`h != last_evict_seq`)
 * fired on BOTH directions: a backward jump wrap-clamped (h - pos > c) into
 * replaying up to the full 28-entry ring of ALREADY-CONSUMED DIR_MODIFY /
 * INODE_FREE entries, and the following fresh read replayed the overlap
 * again.  Each replayed DIR_MODIFY bumps i_dlm_dir_gen and arms
 * MXFS_IF_DIR_RELOAD on every node caching the dir ("gen-bump is
 * idempotent" is FALSE for the counter) — measured live at 32/caw: during
 * the PURE-READ rename_visibility verify, test20's hot-dir dir_gen advanced
 * 197->859 (~6/s) with ZERO writers anywhere, 689 reload_inode calls ALL
 * with identical dinode fields, P138-WAIT mode=5 (EX) = 0 cluster-wide —
 * i.e. the entire per-op release+reacquire+reload+block-re-read convoy
 * (~0.25s/op, 1920 ops -> 470s wall vs 300s budget) was manufactured by
 * stale-HB ring replay, not by any real coherency traffic.
 *
 * Fix: consume the ring MONOTONICALLY — only when head_seq is genuinely
 * AHEAD of our cursor in wrap-safe int32 distance; never move the cursor
 * backward; a backward/behind observation is a stale read and is skipped
 * (counted + logged).  Peer reboot (head_seq restart) re-baselines via
 * evict_seen=false at fire_dead.  A/B: evict_ring_monotonic=0 restores the
 * old any-difference behavior.
 */
int mxfs_evict_ring_monotonic = 1;

/* Compile-time size verification */
_Static_assert(sizeof(struct mxfs_disklock_record) == 512,
               "disklock record must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == 512,
               "disklock heartbeat must be exactly 512 bytes");

/* FNV-1a 32-bit hash over a resource ID */
static uint32_t resource_hash(const struct mxfs_resource_id *res)
{
    uint32_t hash = 2166136261u;
    const uint8_t *data = (const uint8_t *)res;
    size_t len = sizeof(*res);
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

/* Compare two resource IDs for equality */
static bool resource_equal(const struct mxfs_resource_id *a,
                            const struct mxfs_resource_id *b)
{
    return a->volume == b->volume &&
           a->ino == b->ino &&
           a->offset == b->offset &&
           a->ag_number == b->ag_number &&
           a->type == b->type;
}

/* Compute absolute offset for a lock record slot */
static uint64_t lock_slot_offset(struct mxfs_disklock_ctx *ctx, uint32_t slot)
{
    return ctx->base_offset + MXFS_DISKLOCK_HB_SIZE +
           (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
}

/* Compute absolute offset for a heartbeat slot */
static uint64_t hb_slot_offset(struct mxfs_disklock_ctx *ctx,
                                mxfs_node_id_t node)
{
    return ctx->base_offset +
           (uint64_t)(node % MXFS_DISKLOCK_HB_SLOTS) *
           MXFS_DISKLOCK_RECORD_SIZE;
}

/* Read a single 512-byte sector */
static int read_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset,
                        void *buf)
{
    return mxfs_pal_bdev_read(ctx->dev, offset, buf,
                               MXFS_DISKLOCK_RECORD_SIZE);
}

/* Write a single 512-byte sector */
static int write_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset,
                          const void *buf)
{
    return mxfs_pal_bdev_write(ctx->dev, offset, buf,
                                MXFS_DISKLOCK_RECORD_SIZE);
}

static int write_sector_fua(struct mxfs_disklock_ctx *ctx, uint64_t offset,
                              const void *buf)
{
    return mxfs_pal_bdev_write_fua(ctx->dev, offset, buf,
                                    MXFS_DISKLOCK_RECORD_SIZE);
}

/*
 * sess131: a heartbeat record from a different mkfs generation.  Only
 * meaningful once the mount layer has installed our identity; tools and
 * legacy paths (have_fs_identity == false) treat every record as native.
 */
static bool hb_gen_foreign(const struct mxfs_disklock_ctx *ctx,
                           const struct mxfs_disklock_heartbeat *hb)
{
    return ctx->have_fs_identity && hb->fs_gen != ctx->fs_gen;
}

/*
 * sess131 self-fence probe: re-read the on-disk MXFS superblock and compare
 * its fs_uuid against the volume this mount belongs to.  Returns 1 if the
 * device was re-formatted under us (fence!), 0 if identity still matches,
 * negative on I/O error (do NOT fence on transient read failure).  `buf`
 * is a caller-provided 512-byte sector buffer (the super's magic and
 * fs_uuid both live in the first sector of the device).
 */
static int fs_identity_changed(struct mxfs_disklock_ctx *ctx, void *buf)
{
    const struct mxfs_ondisk_super *sup = buf;
    int rc;

    rc = mxfs_pal_bdev_read(ctx->dev, 0, buf, MXFS_DISKLOCK_RECORD_SIZE);
    if (rc < 0)
        return rc;

    if (sup->magic != MXFS_FORMAT_MAGIC)
        return 1;       /* super destroyed/replaced — not our volume */
    if (memcmp(sup->fs_uuid, ctx->fs_uuid, 16) != 0)
        return 1;       /* re-mkfs'd: new uuid */
    return 0;
}

/*
 * Find a lock record slot for a resource+owner.
 * Uses linear probing from the hash base.
 *
 * Returns the slot index if found, or -1 if not found.
 * If not found and empty_out is non-NULL, *empty_out is set to the
 * first empty slot encountered (for insertion).
 */
static int find_lock_slot(struct mxfs_disklock_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           mxfs_node_id_t owner, int *empty_out)
{
    uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
    uint8_t buf[512];
    int first_empty = -1;
    int result = -1;
    uint32_t i;

    for (i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
        uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
        uint64_t offset = lock_slot_offset(ctx, slot);
        struct mxfs_disklock_record *rec;
        int rc;

        rc = read_sector(ctx, offset, buf);
        if (rc < 0)
            break;

        rec = (struct mxfs_disklock_record *)buf;

        if (rec->magic != MXFS_DISKLOCK_MAGIC ||
            rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
            if (first_empty < 0)
                first_empty = (int)slot;
            /* Linear probing: no record past first gap */
            break;
        }

        if (resource_equal(&rec->resource, resource) &&
            rec->owner == owner) {
            result = (int)slot;
            break;
        }
    }

    if (empty_out)
        *empty_out = first_empty;
    return result;
}

/*
 * Validate existing lockstate region by checking magic on first records.
 */
static int validate_lockstate(struct mxfs_disklock_ctx *ctx)
{
    uint8_t buf[512];
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_record *rec;
    int rc;

    /* Check first heartbeat slot */
    rc = read_sector(ctx, hb_slot_offset(ctx, 0), buf);
    if (rc < 0)
        return rc;

    hb = (struct mxfs_disklock_heartbeat *)buf;
    if (hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
        hb->magic != MXFS_DISKLOCK_MAGIC) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: corrupt heartbeat at slot 0 "
                     "(magic=%08x, expected=%08x)",
                     hb->magic, MXFS_DISKLOCK_MAGIC);
        return -EIO;
    }

    /* Check first lock record slot */
    rc = read_sector(ctx, lock_slot_offset(ctx, 0), buf);
    if (rc < 0)
        return rc;

    rec = (struct mxfs_disklock_record *)buf;
    if (rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
        rec->magic != MXFS_DISKLOCK_MAGIC) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: corrupt lock record at slot 0 "
                     "(magic=%08x, expected=%08x)",
                     rec->magic, MXFS_DISKLOCK_MAGIC);
        return -EIO;
    }

    return 0;
}

/* Heartbeat thread: writes heartbeat, sleeps, repeats */
static void disklock_hb_fn(void *arg)
{
    struct mxfs_disklock_ctx *ctx = arg;
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_heartbeat *rhb;
    uint64_t offset;
    int rc;

    mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat thread started");

    /* Heap-allocate both 512-byte heartbeat buffers to avoid
     * exceeding the 1024-byte kernel stack frame limit */
    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: failed to alloc heartbeat buffer");
        return;
    }

    rhb = mxfs_pal_alloc(sizeof(*rhb));
    if (!rhb) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: failed to alloc monitor buffer");
        mxfs_pal_free(hb);
        return;
    }

    while (ctx->running) {
        /*
         * sess131 self-fence: before writing anything, verify the device
         * still carries OUR volume's superblock.  If it was re-mkfs'd under
         * this live mount, every further write from us is ghost pollution
         * of the new cluster generation — stop heartbeating immediately and
         * tell the mount layer to force-shutdown.  rhb doubles as the 512B
         * super read buffer (overwritten by the monitor pass below anyway).
         */
        if (ctx->have_fs_identity && !ctx->fenced) {
            rc = fs_identity_changed(ctx, rhb);
            if (rc == 1) {
                ctx->fenced = true;
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mxfs: P131-SELF-FENCE node %u slot %d: device "
                             "reformatted under live mount (super fs_uuid "
                             "mismatch) — stopping heartbeat, forcing "
                             "shutdown",
                             ctx->local_node, ctx->local_slot);
                if (ctx->fence_cb)
                    ctx->fence_cb(ctx->fence_cb_data);
                break;
            }
        }

        memset(hb, 0, sizeof(*hb));
        hb->magic = MXFS_DISKLOCK_MAGIC;
        hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
        hb->node_id = ctx->local_node;
        hb->fs_gen = ctx->fs_gen;
        hb->timestamp_ms = mxfs_pal_time_ms();
        hb->epoch = ctx->epoch;
        hb->lock_count = ctx->lock_count;

        /*
         * sess55: publish the inode-eviction ring.  Copy the staging ring in
         * its physical circular layout; peers reconstruct the logically-recent
         * entries from head_seq/count.  magic flags the ring as populated
         * (a node running an older build leaves this zeroed → peers skip).
         */
        mxfs_pal_mutex_lock(ctx->evict_lock);
        hb->evict.magic = MXFS_EVICT_RING_MAGIC;
        hb->evict.head_seq = ctx->evict_head_seq;
        hb->evict.count = ctx->evict_count;
        hb->evict.pad = 0;
        memcpy(hb->evict.entry, ctx->evict_stage, sizeof(ctx->evict_stage));
        mxfs_pal_mutex_unlock(ctx->evict_lock);

        offset = ctx->base_offset +
                 (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;

        mxfs_pal_mutex_lock(ctx->lock);
        rc = write_sector_fua(ctx, offset, hb);
        mxfs_pal_mutex_unlock(ctx->lock);

        if (rc < 0)
            mxfs_pal_log(MXFS_LOG_ERR,
                         "disklock: heartbeat write failed: %d", rc);

        /* Bug 99: check running after each I/O call so
         * stop_heartbeat is not blocked behind N disk reads */
        if (!ctx->running)
            break;

        /* --- Monitor: read remote heartbeat slots --- */
        {
            uint32_t slot;

            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
                struct mxfs_disklock_node_track *nt;
                uint64_t off;
                int rr;
                int crr;	/* sess69: confirm-before-evict re-read rc */

                if (!ctx->running)
                    break;

                if ((int)slot == ctx->local_slot)
                    continue;

                nt = &ctx->node_track[slot];
                off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

                mxfs_pal_mutex_lock(ctx->lock);
                rr = mxfs_pal_bdev_read(ctx->dev, off,
                                         rhb, sizeof(*rhb));
                mxfs_pal_mutex_unlock(ctx->lock);

                if (rr < 0 ||
                    rhb->magic != MXFS_DISKLOCK_MAGIC ||
                    rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
                    hb_gen_foreign(ctx, rhb)) {
                    /*
                     * Inactive / garbage / foreign-generation slot (sess131:
                     * pre-mkfs ghost writers must never become tracked
                     * members).  Only run the dead-detection state machine
                     * for slots we were already monitoring; an unclaimed
                     * slot is simply skipped.
                     */
                    if (!ctx->monitored[slot])
                        continue;
                    nt->equal_samples++;
                    nt->changed_samples = 0;
                    goto check_dead;
                }

                /*
                 * sess82: ACTIVE peer heartbeat observed.  In CAW mode the
                 * explicit mxfs_disklock_monitor_node() wiring exists ONLY in
                 * the TCP dlm/mount.c peer-connect path — v5_mount.c (CAW)
                 * never calls it, so monitored[] stayed all-false and the
                 * inode-eviction ring (INODE_FREE + DIR_MODIFY) was NEVER
                 * consumed cross-node (producer staged fine, consumer dispatch
                 * = 0 — proven via P-EVICT-STAGE vs P-EVICT-DISPATCH).  Self-
                 * heal: auto-monitor any active peer slot we see.  Idempotent —
                 * only initialises the slot→node mapping on first sight; the
                 * dead-detection state in node_track was zeroed at create and
                 * is driven below.
                 */
                if (!ctx->monitored[slot]) {
                    ctx->monitored[slot] = true;
                    ctx->slot_node_id[slot] = rhb->node_id;
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: P-EVICT-AUTOMON slot=%u node=%u (CAW auto-monitor)",
                        slot, rhb->node_id);
                }

                /*
                 * sess55: consume the peer's inode-eviction ring.  For each
                 * {ino, gen} the peer published since we last scanned, invoke
                 * the XFS-layer callback to invalidate a stale NL-cached copy.
                 * All arithmetic on the publish counter is unsigned so it is
                 * wrap-safe; if we fell behind by more than the ring depth we
                 * clamp to the oldest available entry (rare — the ring depth
                 * dwarfs frees-per-HB-interval; a true gap just means a few
                 * extra entries get re-checked harmlessly, or are missed and
                 * caught by the VFS-lookup staleness trap).
                 */
                if (ctx->evict_cb &&
                    rhb->evict.magic == MXFS_EVICT_RING_MAGIC) {
                    uint32_t h = rhb->evict.head_seq;
                    uint16_t c = rhb->evict.count;
                    uint32_t pos;

                    if (c > MXFS_EVICT_RING_ENTRIES)
                        c = MXFS_EVICT_RING_ENTRIES;

                    if (!nt->evict_seen) {
                        /* First sighting: adopt head as baseline; do not
                         * replay pre-existing history. */
                        nt->last_evict_seq = h;
                        nt->evict_seen = true;
                    } else if ((int32_t)(h - nt->last_evict_seq) > 0 ||
                               (!mxfs_evict_ring_monotonic &&
                                h != nt->last_evict_seq)) {
                        pos = nt->last_evict_seq;
                        if ((uint32_t)(h - pos) > c)
                            pos = h - c;        /* fell behind > ring depth */
                        while (pos != h) {
                            uint32_t idx = pos % MXFS_EVICT_RING_ENTRIES;
                            uint64_t ino = rhb->evict.entry[idx].ino;
                            uint32_t gen = rhb->evict.entry[idx].gen;
                            uint32_t type = rhb->evict.entry[idx].type;

                            if (ino) {
                                if (dl_instr_on())
                                    mxfs_pal_log(MXFS_LOG_WARN,
                                        "mxfs: P-EVICT-DISPATCH slot=%u ino=%llu type=%u seq=%u head=%u",
                                        slot, (unsigned long long)ino, type,
                                        pos, h);
                                ctx->evict_cb(ctx->evict_cb_data, ino, gen,
                                              type);
                            }
                            pos++;
                        }
                        nt->last_evict_seq = h;
                    } else if (h != nt->last_evict_seq) {
                        /*
                         * head_seq observed BEHIND our cursor: a stale
                         * cached heartbeat read (see the sess1 monotonic
                         * fix note above).  Do NOT replay, do NOT move
                         * the cursor back — the next fresh read resumes
                         * exactly where we left off.  Counted for the
                         * RULE-4 proof that stale HB reads occur.
                         */
                        static uint32_t dl_stale_hb_skips;

                        dl_stale_hb_skips++;
                        if (dl_stale_hb_skips <= 50 ||
                            (dl_stale_hb_skips & 1023) == 0)
                            mxfs_pal_log(MXFS_LOG_WARN,
                                "mxfs: P-EVICT-STALEHB slot=%u h=%u cursor=%u skips=%u — stale cached HB read, ring replay suppressed",
                                slot, h, nt->last_evict_seq,
                                dl_stale_hb_skips);
                    }
                }

                /* Epoch change = node rebooted */
                if (nt->last_epoch != 0 &&
                    rhb->epoch != nt->last_epoch) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: node in slot %u has restarted "
                        "(detected epoch change), reclaiming its "
                        "resources",
                        slot);
                    nt->last_epoch = rhb->epoch;
                    nt->last_timestamp = rhb->timestamp_ms;
                    goto fire_dead;
                }

                if (rhb->timestamp_ms != nt->last_timestamp) {
                    /* Heartbeat is fresh */
                    nt->changed_samples++;
                    nt->equal_samples = 0;
                    nt->last_timestamp = rhb->timestamp_ms;
                    nt->last_epoch = rhb->epoch;

                    if (nt->changed_samples >= MXFS_DISKLOCK_LIVE_THRESHOLD &&
                        !nt->live) {
                        nt->live = true;
                        mxfs_pal_log(MXFS_LOG_DEBUG,
                            "disklock: node %u (slot %u) is LIVE",
                            rhb->node_id, slot);
                    }
                } else {
                    /* Heartbeat is stale */
                    nt->equal_samples++;
                    nt->changed_samples = 0;
                }

check_dead:
                if (nt->equal_samples >= ctx->dead_threshold &&
                    nt->live) {
                    /*
                     * sess69: the monitor read above (mxfs_pal_bdev_read) is
                     * a plain, cacheable read.  Under heavy storm load the
                     * guest block layer / SCST per-initiator cache can return
                     * a STALE heartbeat sector, so a LIVE-but-busy peer looks
                     * frozen and we falsely evict it — triggering an expensive
                     * purge_node (65536-slot FUA scan) + journal replay that
                     * starves the whole cluster (zsl / posix_multi16 verify
                     * hang).  Before evicting, CONFIRM with a FUA, cache-
                     * bypassing priority re-read.  If the heartbeat actually
                     * advanced, it was a stale-read false alarm — do not evict.
                     * Epoch-change reboots reach fire_dead via goto and skip
                     * this confirm (definite restart, no false positive).
                     */
                    mxfs_pal_mutex_lock(ctx->lock);
                    crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
                                                  sizeof(*rhb));
                    mxfs_pal_mutex_unlock(ctx->lock);
                    if (crr == 0 &&
                        rhb->magic == MXFS_DISKLOCK_MAGIC &&
                        rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                        !hb_gen_foreign(ctx, rhb) &&
                        rhb->timestamp_ms != nt->last_timestamp) {
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: P-HBFALSE slot=%u last_ts=%llu fua_ts=%llu "
                            "eq=%d — stale cached heartbeat read, NOT evicting",
                            slot,
                            (unsigned long long)nt->last_timestamp,
                            (unsigned long long)rhb->timestamp_ms,
                            nt->equal_samples);
                        nt->equal_samples = 0;
                        nt->changed_samples++;
                        nt->last_timestamp = rhb->timestamp_ms;
                        nt->last_epoch = rhb->epoch;
                        continue;
                    }
fire_dead:
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: node in slot %u is no longer responding "
                        "(heartbeat expired after %d checks), initiating "
                        "recovery",
                        slot, nt->equal_samples);
                    nt->live = false;
                    nt->changed_samples = 0;
                    nt->equal_samples = 0;
                    ctx->monitored[slot] = false;
                    /* sess1 (ccloop 46efd8b6): the peer died/rebooted — its
                     * evict-ring head_seq restarts.  Drop our cursor baseline
                     * so the monotonic consume guard re-baselines on next
                     * sight instead of ignoring the reborn ring forever. */
                    nt->evict_seen = false;

                    /* Bug 108: Use slot_node_id[] instead of rhb->node_id.
                     * When the heartbeat sector has been zeroed (by
                     * disklock_purge_node) or the read failed, rhb->node_id
                     * is 0.  slot_node_id was set by monitor_node() and
                     * is the authoritative mapping. */
                    if (ctx->expire_cb)
                        ctx->expire_cb(ctx->expire_cb_data,
                                       ctx->slot_node_id[slot]);
                }
                continue;  /* after check_dead/fire_dead labels */
            }
        }

        /* Use condvar timed wait so mxfs_disklock_stop_heartbeat()
         * can wake us immediately instead of waiting up to 2s */
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running)
            mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                    ctx->shutdown_lock,
                                    MXFS_DISKLOCK_HB_INTERVAL_MS);
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }

    mxfs_pal_free(rhb);
    mxfs_pal_free(hb);

    mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat thread exiting");
}

struct mxfs_disklock_ctx *mxfs_disklock_create(mxfs_bdev_t *dev,
                                                uint64_t disklock_offset,
                                                mxfs_node_id_t local_node)
{
    struct mxfs_disklock_ctx *ctx;
    int rc;

    if (!dev)
        return NULL;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->dev = dev;
    ctx->base_offset = disklock_offset;
    ctx->local_node = local_node;
    ctx->local_slot = -1;
    ctx->running = false;
    ctx->epoch = 0;
    ctx->lock_count = 0;
    ctx->hb_thread = NULL;
    memset(ctx->node_track, 0, sizeof(ctx->node_track));
    memset(ctx->monitored, 0, sizeof(ctx->monitored));
    memset(ctx->slot_node_id, 0, sizeof(ctx->slot_node_id));
    ctx->expire_cb = NULL;
    ctx->expire_cb_data = NULL;
    ctx->dead_threshold = MXFS_DISKLOCK_DEAD_THRESHOLD;
    ctx->evict_cb = NULL;
    ctx->evict_cb_data = NULL;
    ctx->evict_head_seq = 0;
    ctx->evict_count = 0;
    memset(ctx->evict_stage, 0, sizeof(ctx->evict_stage));

    ctx->lock = mxfs_pal_mutex_create();
    if (!ctx->lock) {
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_lock = mxfs_pal_mutex_create();
    if (!ctx->shutdown_lock) {
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->shutdown_cond = mxfs_pal_cond_create();
    if (!ctx->shutdown_cond) {
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    ctx->evict_lock = mxfs_pal_mutex_create();
    if (!ctx->evict_lock) {
        mxfs_pal_cond_destroy(ctx->shutdown_cond);
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
        mxfs_pal_mutex_destroy(ctx->lock);
        mxfs_pal_free(ctx);
        return NULL;
    }

    rc = validate_lockstate(ctx);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: lockstate validation returned %d "
                     "(may be freshly initialized)", rc);
        /* Not fatal — region may be empty/new */
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: initialized for node %u "
                 "(offset=%llu, region size=%llu bytes, %u lock slots)",
                 local_node,
                 (unsigned long long)disklock_offset,
                 (unsigned long long)MXFS_DISKLOCK_REGION_SIZE,
                 MXFS_DISKLOCK_MAX_SLOTS);

    return ctx;
}

void mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_disklock_stop_heartbeat(ctx);

    if (ctx->shutdown_cond)
        mxfs_pal_cond_destroy(ctx->shutdown_cond);
    if (ctx->shutdown_lock)
        mxfs_pal_mutex_destroy(ctx->shutdown_lock);
    if (ctx->evict_lock)
        mxfs_pal_mutex_destroy(ctx->evict_lock);
    mxfs_pal_mutex_destroy(ctx->lock);
    mxfs_pal_free(ctx);

    mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: shutdown complete");
}

int mxfs_disklock_start_heartbeat(struct mxfs_disklock_ctx *ctx)
{
    if (!ctx || !ctx->dev)
        return -EINVAL;

    if (ctx->running) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: heartbeat already running");
        return 0;
    }

    ctx->running = true;

    ctx->hb_thread = mxfs_pal_thread_create(disklock_hb_fn, ctx);
    if (!ctx->hb_thread) {
        ctx->running = false;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: failed to start heartbeat thread");
        return -ENOMEM;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: heartbeat started (interval=%u ms)",
                 MXFS_DISKLOCK_HB_INTERVAL_MS);

    return 0;
}

void mxfs_disklock_stop_heartbeat(struct mxfs_disklock_ctx *ctx)
{
    if (!ctx || !ctx->running)
        return;

    ctx->running = false;

    /* Wake heartbeat thread from its condvar timed wait */
    mxfs_pal_mutex_lock(ctx->shutdown_lock);
    mxfs_pal_cond_broadcast(ctx->shutdown_cond);
    mxfs_pal_mutex_unlock(ctx->shutdown_lock);

    if (ctx->hb_thread) {
        /* Bug 99: timed join first — the running flag + condvar signal
         * above normally end the thread within one heartbeat cycle
         * (~2s); 5s covers scheduling jitter without stalling teardown.
         *
         * ccloop 72513a13 (2026-07-18): but NEVER abandon the thread on
         * timeout.  An abandoned kthread still executes module code and
         * still owns an in-flight 512-byte heartbeat bio; rmmod then
         * unmaps the module text, and when the slow command finally
         * completes, bio_endio jumps into freed memory (the recurring
         * "Unable to access opcode bytes at 0xffffffffc1..." panics —
         * 4-20 per node in serial-log history, end_clone_bio frames on
         * the dm-multipath rig).  The stuck write is bounded by the
         * guest SCSI command timeout + error handling (~180s + EH), so
         * a blocking join is slow-but-terminating in the worst case —
         * a slow unmount beats a delayed crash. */
        if (mxfs_pal_thread_join_timeout(ctx->hb_thread, 5000)) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "disklock: heartbeat thread still in disk I/O "
                         "after 5s — waiting it out (bounded by the SCSI "
                         "command timeout; do NOT abandon)");
            mxfs_pal_thread_join(ctx->hb_thread);
        }
        ctx->hb_thread = NULL;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat stopped");
}

int mxfs_disklock_write_grant(struct mxfs_disklock_ctx *ctx,
                               const struct mxfs_resource_id *resource,
                               mxfs_node_id_t owner,
                               uint8_t mode, mxfs_epoch_t epoch)
{
    uint8_t buf[512];
    struct mxfs_disklock_record *rec;
    int empty_slot = -1;
    int existing;
    int target_slot;
    uint64_t offset;
    int rc;

    if (!ctx || !resource || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    existing = find_lock_slot(ctx, resource, owner, &empty_slot);

    if (existing >= 0) {
        target_slot = existing;
    } else if (empty_slot >= 0) {
        target_slot = empty_slot;
    } else {
        /*
         * find_lock_slot stopped at the first gap — search further
         * for any free slot from the hash base.
         */
        uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
        int found = 0;
        uint32_t i;

        for (i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
            uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
            uint64_t soffset = lock_slot_offset(ctx, slot);

            rc = read_sector(ctx, soffset, buf);
            if (rc < 0)
                continue;

            rec = (struct mxfs_disklock_record *)buf;
            if (rec->magic != MXFS_DISKLOCK_MAGIC ||
                rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
                target_slot = (int)slot;
                found = 1;
                break;
            }
        }
        if (!found) {
            mxfs_pal_log(MXFS_LOG_ERR, "disklock: no free lock slots");
            mxfs_pal_mutex_unlock(ctx->lock);
            return -ENOSPC;
        }
    }

    /* Build the record */
    memset(buf, 0, sizeof(buf));
    rec = (struct mxfs_disklock_record *)buf;
    rec->magic = MXFS_DISKLOCK_MAGIC;
    rec->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
    rec->resource = *resource;
    rec->owner = owner;
    rec->mode = mode;
    rec->state = (uint8_t)MXFS_LSTATE_GRANTED;
    rec->granted_at_ms = mxfs_pal_time_ms();
    rec->epoch = epoch;

    offset = lock_slot_offset(ctx, (uint32_t)target_slot);
    rc = write_sector(ctx, offset, buf);

    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: write_grant failed at slot %d: %d",
                     target_slot, rc);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: wrote grant vol=%llu ino=%llu "
                 "owner=%u mode=%u slot=%d",
                 (unsigned long long)resource->volume,
                 (unsigned long long)resource->ino,
                 owner, mode, target_slot);

    return 0;
}

int mxfs_disklock_clear_grant(struct mxfs_disklock_ctx *ctx,
                               const struct mxfs_resource_id *resource,
                               mxfs_node_id_t owner)
{
    uint8_t buf[512];
    int slot;
    uint64_t offset;
    int rc;

    if (!ctx || !resource || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    slot = find_lock_slot(ctx, resource, owner, NULL);
    if (slot < 0) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "disklock: clear_grant: no record for "
                     "vol=%llu ino=%llu owner=%u",
                     (unsigned long long)resource->volume,
                     (unsigned long long)resource->ino,
                     owner);
        mxfs_pal_mutex_unlock(ctx->lock);
        return -ENOENT;
    }

    memset(buf, 0, sizeof(buf));

    offset = lock_slot_offset(ctx, (uint32_t)slot);
    rc = write_sector(ctx, offset, buf);

    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: clear_grant failed at slot %d: %d",
                     slot, rc);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: cleared grant vol=%llu ino=%llu "
                 "owner=%u slot=%d",
                 (unsigned long long)resource->volume,
                 (unsigned long long)resource->ino,
                 owner, slot);

    return 0;
}

int mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx,
                              mxfs_node_id_t node_id)
{
    uint8_t *buf;
    uint8_t *zerobuf;
    int purged = 0;
    uint32_t slot;
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    buf = mxfs_pal_alloc(512);
    zerobuf = mxfs_pal_alloc(512);
    if (!buf || !zerobuf) {
        mxfs_pal_free(buf);
        mxfs_pal_free(zerobuf);
        return -ENOMEM;
    }

    mxfs_pal_mutex_lock(ctx->lock);

    for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS; slot++) {
        uint64_t offset = lock_slot_offset(ctx, slot);
        struct mxfs_disklock_record *rec;

        rc = read_sector(ctx, offset, buf);
        if (rc < 0)
            continue;

        rec = (struct mxfs_disklock_record *)buf;

        if (rec->magic == MXFS_DISKLOCK_MAGIC &&
            rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            rec->owner == node_id) {
            rc = write_sector(ctx, offset, zerobuf);
            if (rc < 0) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "disklock: purge write failed at slot %u: %d",
                             slot, rc);
                continue;
            }
            purged++;
        }
    }

    /* Clear the node's heartbeat record — scan for actual slot */
    {
        uint32_t hb_slot;
        struct mxfs_disklock_heartbeat *phb;

        for (hb_slot = 0; hb_slot < MXFS_DISKLOCK_HB_SLOTS; hb_slot++) {
            uint64_t hb_off = ctx->base_offset +
                              (uint64_t)hb_slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = read_sector(ctx, hb_off, buf);
            if (rc < 0)
                continue;
            phb = (struct mxfs_disklock_heartbeat *)buf;
            if (phb->magic == MXFS_DISKLOCK_MAGIC &&
                phb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                phb->node_id == node_id) {
                rc = write_sector(ctx, hb_off, zerobuf);
                if (rc < 0)
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "disklock: purge heartbeat failed "
                                 "for node %u slot %u: %d",
                                 node_id, hb_slot, rc);
                break;
            }
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);

    mxfs_pal_free(buf);
    mxfs_pal_free(zerobuf);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: purged %d lock records for dead node %u",
                 purged, node_id);

    return purged;
}

int mxfs_disklock_read_all(struct mxfs_disklock_ctx *ctx,
                            struct mxfs_disklock_record *records,
                            int max, int *count)
{
    uint8_t buf[512];
    int found = 0;
    uint32_t slot;

    if (!ctx || !records || !count || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS && found < max; slot++) {
        uint64_t offset = lock_slot_offset(ctx, slot);
        struct mxfs_disklock_record *rec;
        int rc;

        rc = read_sector(ctx, offset, buf);
        if (rc < 0)
            continue;

        rec = (struct mxfs_disklock_record *)buf;

        if (rec->magic == MXFS_DISKLOCK_MAGIC &&
            rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE) {
            memcpy(&records[found], rec, sizeof(*rec));
            found++;
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);

    *count = found;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: read_all found %d active lock records", found);
    return 0;
}

void mxfs_disklock_set_expire_cb(struct mxfs_disklock_ctx *ctx,
                                  mxfs_disklock_expire_cb cb, void *data)
{
    ctx->expire_cb = cb;
    ctx->expire_cb_data = data;
}

void mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx,
                                   const uint8_t *fs_uuid)
{
    mxfs_volume_id_t vid;

    if (!ctx || !fs_uuid)
        return;

    memcpy(ctx->fs_uuid, fs_uuid, 16);
    vid = mxfs_uuid_to_volume_id(fs_uuid, 16);
    ctx->fs_gen = (uint32_t)(vid ^ (vid >> 32));
    if (ctx->fs_gen == 0)
        ctx->fs_gen = 1;        /* 0 means legacy/unset on disk */
    ctx->have_fs_identity = true;
}

void mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx,
                                mxfs_disklock_fence_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->fence_cb = cb;
    ctx->fence_cb_data = data;
}

void mxfs_disklock_set_evict_cb(struct mxfs_disklock_ctx *ctx,
                                mxfs_disklock_evict_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->evict_cb = cb;
    ctx->evict_cb_data = data;
}

/*
 * sess55: producer side of the inode-eviction ring.  Record that this node has
 * freed inode `ino` (now at di_gen `gen`).  Non-blocking: append to the in-mem
 * staging ring (overwriting the oldest entry once full — peers detect the gap
 * via the head_seq jump and fall back to a sweep) and bump the publish counter.
 * disklock_hb_fn serialises this into the outgoing heartbeat on its next write.
 */
void mxfs_disklock_note_freed(struct mxfs_disklock_ctx *ctx,
                              uint64_t ino, uint32_t gen, uint32_t type)
{
    uint32_t idx;

    if (!ctx || !ctx->evict_lock)
        return;

    mxfs_pal_mutex_lock(ctx->evict_lock);
    /*
     * sess80: dedup — if the most-recent staged entry is the same (ino,type)
     * we just published, skip.  A node renaming 20 files in one shared dir
     * would otherwise stage 20 identical DIR_MODIFY entries and overflow the
     * 28-deep ring (evicting other peers' useful entries).  One entry per dir
     * per burst is enough; the consumer's gen-bump is idempotent.
     */
    if (ctx->evict_head_seq > 0) {
        uint32_t prev = (ctx->evict_head_seq - 1) % MXFS_EVICT_RING_ENTRIES;
        if (ctx->evict_stage[prev].ino == ino &&
            ctx->evict_stage[prev].type == type) {
            mxfs_pal_mutex_unlock(ctx->evict_lock);
            return;
        }
    }
    idx = ctx->evict_head_seq % MXFS_EVICT_RING_ENTRIES;
    ctx->evict_stage[idx].ino = ino;
    ctx->evict_stage[idx].gen = gen;
    ctx->evict_stage[idx].type = type;
    ctx->evict_head_seq++;
    if (dl_instr_on())
        mxfs_pal_log(MXFS_LOG_WARN,
            "mxfs: P-EVICT-STAGE ino=%llu type=%u head_seq=%u",
            (unsigned long long)ino, type, ctx->evict_head_seq);
    if (ctx->evict_count < MXFS_EVICT_RING_ENTRIES)
        ctx->evict_count++;
    mxfs_pal_mutex_unlock(ctx->evict_lock);
}

void mxfs_disklock_monitor_node(struct mxfs_disklock_ctx *ctx,
                                 mxfs_node_id_t node_id)
{
    int slot = mxfs_disklock_find_node_slot(ctx, node_id);

    if (slot < 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
            "mxfs: node %u has not started heartbeat yet, "
            "will retry monitoring", node_id);
        return;
    }

    memset(&ctx->node_track[slot], 0, sizeof(ctx->node_track[slot]));
    ctx->slot_node_id[slot] = node_id;
    ctx->monitored[slot] = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
        "disklock: monitoring node %u (slot %d)", node_id, slot);
}

/*
 * v0.5.0: override the dead-declaration window.  The monitor declares a
 * peer dead after dead_threshold consecutive stale heartbeat samples at
 * MXFS_DISKLOCK_HB_INTERVAL_MS each; the compile-time default (62 s) is
 * production-conservative.  Test rigs need fast fail-detect — crash
 * recovery (lock purge + foreign-slice replay) is gated on this.
 * Floor of 2 samples: one stale sample is sampling-phase noise, not death.
 */
void mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx,
                                       uint32_t timeout_ms)
{
    uint32_t samples;

    if (!ctx)
        return;
    if (timeout_ms == 0) {
        ctx->dead_threshold = MXFS_DISKLOCK_DEAD_THRESHOLD;
        return;
    }
    samples = timeout_ms / MXFS_DISKLOCK_HB_INTERVAL_MS;
    if (samples < 2)
        samples = 2;
    ctx->dead_threshold = samples;
    mxfs_pal_log(MXFS_LOG_INFO,
        "disklock: dead-declaration window set to %u ms (%u samples)",
        samples * MXFS_DISKLOCK_HB_INTERVAL_MS, samples);
}

/*
 * v0.5.0 foreign-slice replay election: return the lowest live heartbeat
 * slot among the survivors (this node's own slot plus every monitored
 * slot whose tracker says live), excluding skip_slot (the dead node).
 * Survivors each compute this from their own monitor view; the node
 * whose local_slot equals the result is the elected replayer.  Double
 * election is correctness-safe (replay is LSN-gated/idempotent), so a
 * transiently divergent view only costs duplicate work.
 *
 * Called from the heartbeat thread (lease-expire path) — the same thread
 * that mutates monitored[]/node_track[], so no locking is needed.
 */
/* ccloop 72513a13 sess2: advisory per-slot liveness — see disklock.h. */
bool mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return false;
    if (slot == ctx->local_slot)
        return true;
    return ctx->monitored[slot] && ctx->node_track[slot].live;
}

int mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx,
                                   int skip_slot)
{
    int slot;

    if (!ctx)
        return -1;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (slot == skip_slot)
            continue;
        if (slot == ctx->local_slot)
            return slot;
        if (ctx->monitored[slot] && ctx->node_track[slot].live)
            return slot;
    }
    return -1;
}

void mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx,
                                   mxfs_node_id_t node_id)
{
    uint32_t slot;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (ctx->monitored[slot] && ctx->slot_node_id[slot] == node_id) {
            ctx->monitored[slot] = false;
            ctx->slot_node_id[slot] = 0;
            memset(&ctx->node_track[slot], 0, sizeof(ctx->node_track[slot]));
            mxfs_pal_log(MXFS_LOG_DEBUG,
                "disklock: unmonitoring node %u (slot %u)", node_id, slot);
            return;
        }
    }

    mxfs_pal_log(MXFS_LOG_WARN,
        "mxfs: node %u was not being monitored "
        "(may have already been removed)", node_id);
}

/*
 * Scan the 64 heartbeat slots on disk to find which slot a given
 * node_id occupies.  Returns the slot index (0-63) or -1 if not found.
 */
int mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx,
                                   mxfs_node_id_t node_id)
{
    struct mxfs_disklock_heartbeat *hb;
    uint32_t slot;
    int found = -1;

    if (!ctx || !ctx->dev)
        return -1;

    /* Check in-memory mapping first (populated by monitor_node) */
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (ctx->monitored[slot] && ctx->slot_node_id[slot] == node_id)
            return (int)slot;
    }

    /* Fall back to disk scan */
    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return -1;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        int rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        if (rc < 0)
            continue;
        if (hb->magic == MXFS_DISKLOCK_MAGIC &&
            hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            hb->node_id == node_id) {
            found = (int)slot;
            break;
        }
    }

    mxfs_pal_free(hb);
    return found;
}

/*
 * sess67 ASYMMETRIC MDS: resolve which node_id currently occupies a given
 * heartbeat slot (0-63).  Checks the in-memory map first, then reads the slot
 * on disk.  Returns the node_id or 0 if the slot is empty/unreadable.  Used by
 * clients to address the metadata-server node (static v1: MDS = slot 0).
 */
mxfs_node_id_t mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx,
                                              int slot)
{
    struct mxfs_disklock_heartbeat *hb;
    mxfs_node_id_t node_id = 0;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return 0;

    if (ctx->slot_node_id[slot])
        return ctx->slot_node_id[slot];

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return 0;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
    rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
    if (rc >= 0 && hb->magic == MXFS_DISKLOCK_MAGIC &&
        hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
        !hb_gen_foreign(ctx, hb))
        node_id = hb->node_id;
    mxfs_pal_free(hb);
    return node_id;
}

/*
 * Claim a unique heartbeat slot (0-63).  Scans all slots; prefers
 * re-claiming our own node_id from a previous mount, otherwise takes
 * the first empty slot.  Returns the slot index or negative errno.
 */
/*
 * sess130 (ccloop, RULE 4 PROVEN): the slot claim was a non-atomic
 * read-scan + plain FUA write.  Two nodes mounting concurrently (the
 * 4-node criterion harness mounts in parallel) both scanned, both saw
 * the same slot free, both wrote their heartbeat ~0.5s apart — test3
 * and test4 each booted with node_slot=1 / node_bit=2 (MDS-IDENTITY
 * logs), so each saw the OTHER's CAW lock-slot holder bits as its own
 * ("already-held", P15-INSTR slot=50299 h_ex=2).  Result: ZERO mutual
 * exclusion between the two nodes — concurrent EX on the same AG,
 * double inode allocation ("Allocated a known in-use inode"), missing
 * BASTs, stale dinode reloads, FS shutdown (strong_consistency FAIL).
 *
 * Fix: claim the slot with SCSI COMPARE-AND-WRITE from the observed
 * sector image, exactly like the CAW lock slots.  A concurrent claimer
 * miscompares (-EAGAIN), rescans, and takes the next free slot.  Slot
 * uniqueness (invariant: disklock slot 0..63 unique per live node) is
 * then guaranteed by the device's atomic CAW, not by timing luck.
 */
#define MXFS_DISKLOCK_CLAIM_RETRIES 16

/*
 * Verified non-CAW slot claim — fallback for targets that REJECT the SCSI
 * COMPARE AND WRITE used by the primary claim (this SCST LUN answers opcode
 * 0x89 with ILLEGAL REQUEST / INVALID FIELD IN CDB, sense 0x5/0x24, so the
 * CAW claim returns -EIO and every node would otherwise default to slot 0 ->
 * one shared preferred AG -> concurrent same-AG inode alloc/free corrupts the
 * inobt -> FS shutdown).
 *
 * Unlike the racy sess130-era plain-write claim (read-scan + blind FUA write,
 * no confirmation — two parallel mounts both took the same slot), this path
 * FUA-WRITES then FUA-READS-BACK and only accepts the slot if our own
 * node_id AND our unique timestamp survived.  A racing claimer that wrote the
 * same slot later wins the read-back; the earlier writer's read-back
 * mismatches and it advances to the next free slot.  The harness also mounts
 * nodes sequentially, so the common path is uncontended.
 */
static int mxfs_disklock_claim_slot_noncaw(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_heartbeat *rec;
    uint32_t slot;
    int attempt;
    int rc = -ENOSPC;

    hb = mxfs_pal_alloc(sizeof(*hb));
    rec = mxfs_pal_alloc(sizeof(*rec));
    if (!hb || !rec) {
        mxfs_pal_free(hb);
        mxfs_pal_free(rec);
        return -ENOMEM;
    }

    mxfs_pal_mutex_lock(ctx->lock);

    for (attempt = 0; attempt < MXFS_DISKLOCK_CLAIM_RETRIES; attempt++) {
        int found_slot = -1;

        /* Pass 1: re-claim our own prior-mount slot (FUA reads). */
        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
            uint64_t off = ctx->base_offset +
                           (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
            if (rc < 0)
                continue;
            if (rec->magic == MXFS_DISKLOCK_MAGIC &&
                rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                rec->node_id == ctx->local_node &&
                !hb_gen_foreign(ctx, rec)) {
                found_slot = (int)slot;
                break;
            }
        }

        /* Pass 2: first free / foreign-generation slot (FUA reads). */
        if (found_slot < 0) {
            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
                uint64_t off = ctx->base_offset +
                               (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
                if (rc < 0)
                    continue;
                if (rec->magic != MXFS_DISKLOCK_MAGIC ||
                    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
                    hb_gen_foreign(ctx, rec)) {
                    found_slot = (int)slot;
                    break;
                }
            }
        }

        if (found_slot < 0) {
            rc = -ENOSPC;
            break;
        }

        /* Write our record with a unique timestamp, then verify. */
        memset(hb, 0, sizeof(*hb));
        hb->magic = MXFS_DISKLOCK_MAGIC;
        hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
        hb->node_id = ctx->local_node;
        hb->fs_gen = ctx->fs_gen;
        hb->timestamp_ms = mxfs_pal_time_ms();
        hb->epoch = ctx->epoch;

        {
            uint64_t off = ctx->base_offset +
                           (uint64_t)found_slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = write_sector_fua(ctx, off, hb);
            if (rc < 0)
                continue;            /* write error — rescan & retry */

            /* Settle, then FUA read-back confirm.  node_id + timestamp must
             * both match (a racing peer that overwrote us later changes both). */
            mxfs_pal_sleep_ms(30);
            rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
            if (rc == 0 &&
                rec->magic == MXFS_DISKLOCK_MAGIC &&
                rec->node_id == ctx->local_node &&
                rec->timestamp_ms == hb->timestamp_ms) {
                ctx->local_slot = found_slot;
                mxfs_pal_mutex_unlock(ctx->lock);
                mxfs_pal_free(hb);
                mxfs_pal_free(rec);
                mxfs_pal_log(MXFS_LOG_WARN,
                             "disklock: claimed heartbeat slot %d for node %u "
                             "(non-CAW verified, attempt %d)",
                             found_slot, ctx->local_node, attempt);
                return found_slot;
            }
            /* Lost the race for this slot — rescan (it now reads as a peer's). */
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    mxfs_pal_free(hb);
    mxfs_pal_free(rec);
    mxfs_pal_log(MXFS_LOG_ERR,
                 "disklock: non-CAW claim failed: %d", rc);
    return rc < 0 ? rc : -ENOSPC;
}

int mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_heartbeat *expected;
    uint32_t slot;
    int attempt;
    int rc = -ENOSPC;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    hb = mxfs_pal_alloc(sizeof(*hb));
    expected = mxfs_pal_alloc(sizeof(*expected));
    if (!hb || !expected) {
        mxfs_pal_free(hb);
        mxfs_pal_free(expected);
        return -ENOMEM;
    }

    mxfs_pal_mutex_lock(ctx->lock);

    for (attempt = 0; attempt < MXFS_DISKLOCK_CLAIM_RETRIES; attempt++) {
        int found_slot = -1;

        /* First pass: look for our own node_id (re-claim from previous
         * mount).  Keep the read image — it is the CAW compare buffer. */
        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
            uint64_t off = ctx->base_offset +
                           (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = mxfs_pal_bdev_read(ctx->dev, off, expected,
                                    sizeof(*expected));
            if (rc < 0)
                continue;
            if (expected->magic == MXFS_DISKLOCK_MAGIC &&
                expected->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                expected->node_id == ctx->local_node &&
                !hb_gen_foreign(ctx, expected)) {
                found_slot = (int)slot;
                break;
            }
        }

        /* Second pass: find first empty slot */
        if (found_slot < 0) {
            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
                uint64_t off = ctx->base_offset +
                               (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                rc = mxfs_pal_bdev_read(ctx->dev, off, expected,
                                        sizeof(*expected));
                if (rc < 0)
                    continue;
                if (expected->magic != MXFS_DISKLOCK_MAGIC ||
                    expected->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
                    hb_gen_foreign(ctx, expected)) {
                    /* sess131: foreign-generation (pre-mkfs ghost) records
                     * are claimable — the CAW below overwrites them. */
                    found_slot = (int)slot;
                    break;
                }
            }
        }

        if (found_slot < 0) {
            mxfs_pal_mutex_unlock(ctx->lock);
            mxfs_pal_free(hb);
            mxfs_pal_free(expected);
            mxfs_pal_log(MXFS_LOG_ERR,
                         "disklock: no free heartbeat slot (all 64 occupied)");
            return -ENOSPC;
        }

        /* Atomically claim: CAW from the observed image to our record. */
        memset(hb, 0, sizeof(*hb));
        hb->magic = MXFS_DISKLOCK_MAGIC;
        hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
        hb->node_id = ctx->local_node;
        hb->fs_gen = ctx->fs_gen;
        hb->timestamp_ms = mxfs_pal_time_ms();
        hb->epoch = ctx->epoch;

        {
            uint64_t off = ctx->base_offset +
                           (uint64_t)found_slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expected, hb);
        }

        if (rc == 0) {
            mxfs_pal_mutex_unlock(ctx->lock);
            mxfs_pal_free(hb);
            mxfs_pal_free(expected);
            ctx->local_slot = found_slot;
            mxfs_pal_log(MXFS_LOG_WARN,
                         "disklock: claimed heartbeat slot %d for node %u "
                         "(attempt %d)",
                         found_slot, ctx->local_node, attempt);
            return found_slot;
        }

        if (rc == -EAGAIN) {
            /* A peer claimed this slot between our read and our CAW —
             * the exact race that used to hand two nodes the same
             * node_slot.  Rescan; the peer's record is now visible. */
            mxfs_pal_log(MXFS_LOG_WARN,
                         "disklock: P130-CLAIM-RACE slot %d (node %u, "
                         "attempt %d) — rescanning",
                         found_slot, ctx->local_node, attempt);
            continue;
        }

        break;  /* hard I/O error or -EOPNOTSUPP */
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    mxfs_pal_free(hb);
    mxfs_pal_free(expected);

    /* CAW claim unavailable on this target — fall back to the verified
     * non-CAW claim so we still get a UNIQUE slot (never default to 0). */
    {
        int ncrc = mxfs_disklock_claim_slot_noncaw(ctx);
        if (ncrc >= 0)
            return ncrc;
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: claim_slot failed (CAW rc=%d, non-CAW rc=%d)",
                     rc, ncrc);
        return ncrc < 0 ? ncrc : (rc < 0 ? rc : -ENOSPC);
    }
}

int mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx)
{
    if (!ctx)
        return -1;
    return ctx->local_slot;
}

int mxfs_disklock_get_stale_slot_mask(struct mxfs_disklock_ctx *ctx,
                                        uint64_t threshold_ms,
                                        int skip_slot,
                                        uint64_t *out_mask)
{
    struct mxfs_disklock_heartbeat *hb;
    uint64_t snap_ts[64];
    uint32_t snap_node[64];
    bool snap_active[64];
    uint64_t mask = 0;
    uint32_t slot;
    /*
     * Snapshot+wait+rescan strategy: timestamp_ms is from
     * ktime_get_boottime_ns which resets on reboot, so absolute-age
     * comparison is unsound across crashes.  Instead, snapshot all
     * ACTIVE slots' timestamps now, wait long enough for an alive
     * heartbeat round (default 2s × 5 = 10s), and rescan: any slot
     * whose timestamp didn't advance is dead and its CAW bits are
     * stuck-orphan.  threshold_ms is interpreted as the wait window.
     */

    if (!ctx || !out_mask || !ctx->dev)
        return -EINVAL;

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return -ENOMEM;

    /* Snapshot pass */
    mxfs_pal_mutex_lock(ctx->lock);
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        int rc;

        snap_active[slot] = false;
        if ((int)slot == skip_slot)
            continue;

        rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        if (rc < 0)
            continue;
        if (hb->magic != MXFS_DISKLOCK_MAGIC ||
            hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
            hb_gen_foreign(ctx, hb))
            continue;

        snap_active[slot] = true;
        snap_ts[slot] = hb->timestamp_ms;
        snap_node[slot] = hb->node_id;
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (!threshold_ms) {
        /* No-wait path — used when caller knows all peers are dead */
        for (slot = 0; slot < 64; slot++)
            if (snap_active[slot])
                mask |= (1ULL << slot);
        mxfs_pal_free(hb);
        *out_mask = mask;
        return 0;
    }

    /*
     * Poll for heartbeat advance with early exit, instead of one fixed
     * sleep(threshold_ms).  A live node rewrites its heartbeat every
     * MXFS_DISKLOCK_HB_INTERVAL_MS; we only need to observe each active
     * slot advance ONCE to prove it alive.  A slot that never advances
     * within the full threshold_ms window is a previous crashed instance
     * and gets purged.  Correctness is identical to the old fixed-wait
     * (stale is still declared only after the whole window elapses with
     * no advance) but the common case — all snapshot-active slots are
     * live peers — returns in ~one heartbeat interval rather than the
     * full 10 s, which keeps joining-node mount latency low.
     */
    {
        bool advanced[64];
        int n_active = 0;
        int n_pending;
        uint64_t waited = 0;
        const uint64_t poll_ms = 500;

        for (slot = 0; slot < 64; slot++) {
            advanced[slot] = false;
            if (snap_active[slot])
                n_active++;
        }

        /* No active slots snapshotted — nothing can be stale, no wait. */
        if (n_active == 0) {
            mxfs_pal_free(hb);
            *out_mask = 0;
            return 0;
        }
        n_pending = n_active;

        while (n_pending > 0 && waited < threshold_ms) {
            mxfs_pal_sleep_ms(poll_ms);
            waited += poll_ms;

            mxfs_pal_mutex_lock(ctx->lock);
            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
                uint64_t off;
                int rc;

                if (!snap_active[slot] || advanced[slot])
                    continue;

                off = ctx->base_offset +
                      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
                if (rc < 0)
                    continue;

                /* Alive iff still our snapshotted node AND timestamp moved. */
                if (hb->magic == MXFS_DISKLOCK_MAGIC &&
                    hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                    hb->node_id == snap_node[slot] &&
                    hb->timestamp_ms != snap_ts[slot]) {
                    advanced[slot] = true;
                    n_pending--;
                }
            }
            mxfs_pal_mutex_unlock(ctx->lock);
        }

        /* Anything that never advanced across the full window is stale. */
        for (slot = 0; slot < 64; slot++) {
            if (snap_active[slot] && !advanced[slot]) {
                mask |= (1ULL << slot);
                mxfs_pal_log(MXFS_LOG_INFO,
                    "disklock: slot %u stale (node=%u ts unchanged across %llu ms) — will purge",
                    slot, snap_node[slot],
                    (unsigned long long)threshold_ms);
            }
        }
    }

    mxfs_pal_free(hb);
    *out_mask = mask;
    return 0;
}
