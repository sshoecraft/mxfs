/*
 * MXFS — Multinode XFS
 * Portable journal — slot management, write engine, replay, transactions
 *
 * Manages journal slot assignment, coordinates recovery, and provides
 * a write-ahead log for metadata operations. Each node gets a dedicated
 * circular buffer (slot) on the shared block device. Metadata changes
 * are journaled before being applied, enabling crash recovery via
 * two-pass replay.
 *
 * On-disk layout:
 *   [journal_super 512B]
 *   [slot0_hdr 512B] [slot0_entries...]
 *   [slot1_hdr 512B] [slot1_entries...]
 *   ...
 *
 * Ported from kernel/mxfs_journal.c — kernel mutex/ktime replaced
 * with PAL equivalents. Write engine, replay, and transaction API
 * are new additions.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "journal.h"

/* Compile-time size verification */
_Static_assert(sizeof(struct mxfs_journal_super) == 512,
               "journal super must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_journal_slot_hdr) == 512,
               "journal slot header must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_journal_entry_hdr) == 40,
               "journal entry header must be exactly 40 bytes");

/* ─── Internal helpers ─── */

/* Round up to next multiple of 512 */
static uint32_t round_up_sector(uint32_t bytes)
{
    return (bytes + MXFS_JOURNAL_SECTOR_SIZE - 1) &
           ~(MXFS_JOURNAL_SECTOR_SIZE - 1);
}

/*
 * Compute the byte offset on device for a given slot's header sector.
 * Layout: [super 512B] [slot0_hdr 512B] [slot0_data...] [slot1_hdr 512B] ...
 */
static uint64_t slot_offset(struct mxfs_journal_ctx *ctx, int slot)
{
    return ctx->journal_offset + MXFS_JOURNAL_SECTOR_SIZE +
           (uint64_t)slot * (uint64_t)ctx->super_disk.slot_size_sectors *
           MXFS_JOURNAL_SECTOR_SIZE;
}

/*
 * Compute CRC32C of a 512-byte sector, with the CRC field zeroed.
 * crc_offset is the byte offset of the CRC field within the sector.
 */
static uint32_t sector_crc(const void *buf, size_t crc_offset)
{
    uint8_t tmp[512];
    memcpy(tmp, buf, 512);
    memset(tmp + crc_offset, 0, sizeof(uint32_t));
    return mxfs_pal_crc32c(~0U, tmp, 512);
}

/*
 * Read a single 512-byte sector from device.
 */
static int read_sector(mxfs_bdev_t *dev, uint64_t offset, void *buf)
{
    return mxfs_pal_bdev_read(dev, offset, buf, MXFS_JOURNAL_SECTOR_SIZE);
}

/*
 * Write a single 512-byte sector to device.
 */
static int write_sector(mxfs_bdev_t *dev, uint64_t offset, const void *buf)
{
    return mxfs_pal_bdev_write(dev, offset, buf, MXFS_JOURNAL_SECTOR_SIZE);
}

/*
 * Compute the on-device byte offset for a relative sector within
 * the current slot. Sector 0 of the slot is the slot header.
 * Data sectors start at 1.
 */
static uint64_t entry_sector_offset(struct mxfs_journal_ctx *ctx,
                                     uint32_t rel_sector)
{
    return ctx->slot_base + (uint64_t)rel_sector * MXFS_JOURNAL_SECTOR_SIZE;
}

/*
 * Advance a sector position within the circular data area of a slot.
 * Data sectors: 1 .. (slot_size_sectors - 1). Sector 0 is the header.
 */
static uint32_t advance_sector(struct mxfs_journal_ctx *ctx, uint32_t pos,
                                uint32_t count)
{
    uint32_t data_sectors = ctx->slot_size_sectors - 1;
    /* pos is 1-based in the data area */
    uint32_t idx = pos - 1;
    idx = (idx + count) % data_sectors;
    return idx + 1;
}

/*
 * Number of free data sectors in the circular buffer.
 * Head and tail are both 1-based sector indices.
 * When head == tail, buffer is empty.
 */
static uint32_t free_sectors(struct mxfs_journal_ctx *ctx)
{
    uint32_t data_sectors = ctx->slot_size_sectors - 1;
    if (ctx->head == ctx->tail)
        return data_sectors - 1; /* leave 1 free to distinguish full/empty */
    if (ctx->head > ctx->tail)
        return data_sectors - (ctx->head - ctx->tail) - 1;
    return ctx->tail - ctx->head - 1;
}

/* Forward declaration — used by checkpoint_locked below */
static int flush_slot_header(struct mxfs_journal_ctx *ctx);

/*
 * Checkpoint (internal, caller holds ctx->lock).
 * Advances tail to head, reclaiming all journal space.
 * Does NOT write a CHECKPOINT entry — used when the journal
 * is full and there's no room for additional entries.
 * Flushes device and updates the slot header.
 * Returns 0 on success, negative errno on failure.
 */
static int checkpoint_locked(struct mxfs_journal_ctx *ctx)
{
    int rc;

    if (ctx->head == ctx->tail)
        return 0; /* nothing to checkpoint */

    /* Advance tail to head — all previous entries are now consumed */
    ctx->tail = ctx->head;

    /* Flush device to ensure all prior writes are durable */
    rc = mxfs_pal_bdev_flush(ctx->dev);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: checkpoint_locked flush failed: %d", rc);
        return rc;
    }

    /* Update slot header on disk */
    rc = flush_slot_header(ctx);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: checkpoint_locked slot header failed: %d", rc);
        return rc;
    }

    /* Full flush done, clear unflushed counter */
    ctx->unflushed_commits = 0;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: auto-checkpoint complete (head=tail=%u)",
                 ctx->head);
    return 0;
}

/*
 * Total data sectors in the circular buffer (excludes header sector).
 */
static uint32_t total_data_sectors(struct mxfs_journal_ctx *ctx)
{
    return ctx->slot_size_sectors - 1;
}

/*
 * Write a journal entry at the current head position.
 * Handles multi-sector entries. Advances head.
 * The entry header's seq is filled in here.
 * Returns 0 on success, negative errno on failure.
 *
 * entry_buf must be total_len bytes, already filled except for seq/crc.
 *
 * If the journal is full, auto-checkpoints to reclaim space and retries.
 * Also triggers proactive checkpoint at 75% capacity to avoid hitting
 * the wall on large transactions.
 */
static int write_entry(struct mxfs_journal_ctx *ctx, void *entry_buf,
                        uint32_t total_len)
{
    struct mxfs_journal_entry_hdr *hdr = entry_buf;
    uint32_t sectors_needed = total_len / MXFS_JOURNAL_SECTOR_SIZE;
    uint32_t free;
    uint32_t capacity;
    uint32_t i;
    int rc;

    free = free_sectors(ctx);

    /* Proactive checkpoint: if journal is >= 75% full, checkpoint now */
    capacity = total_data_sectors(ctx);
    if (capacity > 0 && free < capacity / 4) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "journal: proactive checkpoint (%u free of %u, 75%% threshold)",
                     free, capacity);
        rc = checkpoint_locked(ctx);
        if (rc == 0)
            free = free_sectors(ctx);
        /* If checkpoint failed, continue — we may still have enough space */
    }

    if (sectors_needed > free) {
        /* Journal full — force checkpoint to reclaim space */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: journal space low, writing pending data to disk "
                     "(brief pause may occur)");

        rc = checkpoint_locked(ctx);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: journal space reclaim failed: %d "
                         "(filesystem operations may fail until space "
                         "is freed)", rc);
            return -ENOSPC;
        }

        free = free_sectors(ctx);
        if (sectors_needed > free) {
            /* Single transaction larger than entire journal capacity */
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: entry too large even after checkpoint "
                         "(%u sectors needed, %u available)",
                         sectors_needed, free);
            return -ENOSPC;
        }
    }

    /* Fill in sequence and compute CRC */
    hdr->seq = ctx->next_seq++;
    hdr->crc = 0;
    hdr->crc = mxfs_pal_crc32c(~0U, entry_buf, total_len);

    /* Write each sector */
    for (i = 0; i < sectors_needed; i++) {
        uint64_t offset = entry_sector_offset(ctx, ctx->head);
        const uint8_t *src = (const uint8_t *)entry_buf +
                             i * MXFS_JOURNAL_SECTOR_SIZE;

        rc = write_sector(ctx->dev, offset, src);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: write_entry failed at sector %u: %d",
                         ctx->head, rc);
            return rc;
        }
        ctx->head = advance_sector(ctx, ctx->head, 1);
    }

    return 0;
}

/*
 * Write the slot header to disk, updating CRC.
 */
static int flush_slot_header(struct mxfs_journal_ctx *ctx)
{
    struct mxfs_journal_slot_hdr hdr;
    int rc;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = MXFS_JOURNAL_MAGIC;
    hdr.flags = MXFS_JSLOT_FLAG_DIRTY;
    hdr.owner = ctx->local_node;
    hdr.head_sector = ctx->head;
    hdr.tail_sector = ctx->tail;
    hdr.seq_head = ctx->next_seq;
    hdr.seq_tail = 0; /* updated by checkpoint */

    /* CRC: zero the crc field, compute over full 512 bytes */
    hdr.crc = 0;
    hdr.crc = sector_crc(&hdr,
                          offsetof(struct mxfs_journal_slot_hdr, crc));

    rc = write_sector(ctx->dev, ctx->slot_base, &hdr);
    if (rc < 0)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: flush_slot_header failed: %d", rc);
    return rc;
}

/*
 * Build a simple (no-payload) entry: COMMIT, CHECKPOINT, UNMOUNT.
 */
static int write_simple_entry(struct mxfs_journal_ctx *ctx, uint32_t type,
                               uint64_t txn_id)
{
    uint8_t buf[MXFS_JOURNAL_SECTOR_SIZE];
    struct mxfs_journal_entry_hdr *hdr;

    memset(buf, 0, sizeof(buf));
    hdr = (struct mxfs_journal_entry_hdr *)buf;
    hdr->magic = MXFS_JE_MAGIC;
    hdr->type = type;
    hdr->txn_id = txn_id;
    hdr->total_len = MXFS_JOURNAL_SECTOR_SIZE;
    hdr->payload_len = 0;

    return write_entry(ctx, buf, MXFS_JOURNAL_SECTOR_SIZE);
}

/*
 * Free all entries in a transaction.
 */
static void free_txn_entries(struct mxfs_txn *txn)
{
    struct mxfs_txn_entry *e = txn->entries;
    while (e) {
        struct mxfs_txn_entry *next = e->next;
        if (e->data)
            mxfs_pal_free(e->data);
        mxfs_pal_free(e);
        e = next;
    }
    txn->entries = NULL;
    txn->tail = NULL;
    txn->count = 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Slot management (original code, unchanged)
 * ════════════════════════════════════════════════════════════════════ */

struct mxfs_journal_ctx *mxfs_journal_create(mxfs_node_id_t local_node)
{
    struct mxfs_journal_ctx *ctx;
    int i;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->local_node = local_node;
    ctx->local_slot = -1;

    ctx->lock = mxfs_pal_mutex_create();
    if (!ctx->lock) {
        mxfs_pal_free(ctx);
        return NULL;
    }

    for (i = 0; i < MXFS_MAX_NODES; i++) {
        ctx->slots[i].node_id = 0;
        ctx->slots[i].state = MXFS_JSLOT_FREE;
        ctx->slots[i].claimed_at = 0;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: initialized for node %u (%d slots)",
                 local_node, MXFS_MAX_NODES);

    return ctx;
}

void mxfs_journal_destroy(struct mxfs_journal_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->local_slot >= 0 && ctx->local_slot < MXFS_MAX_NODES) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "journal: releasing slot %d on shutdown",
                     ctx->local_slot);
        ctx->slots[ctx->local_slot].state = MXFS_JSLOT_FREE;
        ctx->slots[ctx->local_slot].node_id = 0;
        ctx->slots[ctx->local_slot].claimed_at = 0;
        ctx->local_slot = -1;
    }

    mxfs_pal_mutex_unlock(ctx->lock);

    mxfs_pal_log(MXFS_LOG_INFO,
                 "journal: destroyed (commits=%llu, flushes=%llu)",
                 (unsigned long long)ctx->stat_commits,
                 (unsigned long long)ctx->stat_flush_count);

    if (ctx->write_buf)
        mxfs_pal_free(ctx->write_buf);

    mxfs_pal_mutex_destroy(ctx->lock);
    mxfs_pal_free(ctx);
}

int mxfs_journal_claim_slot(struct mxfs_journal_ctx *ctx)
{
    int i;
    int rc = -ENOSPC;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->local_slot >= 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "journal: node %u already has slot %d",
                     ctx->local_node, ctx->local_slot);
        mxfs_pal_mutex_unlock(ctx->lock);
        return ctx->local_slot;
    }

    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->slots[i].state == MXFS_JSLOT_FREE) {
            ctx->slots[i].state = MXFS_JSLOT_ACTIVE;
            ctx->slots[i].node_id = ctx->local_node;
            ctx->slots[i].claimed_at = mxfs_pal_time_ms();
            ctx->local_slot = i;
            rc = i;

            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "journal: node %u claimed slot %d",
                         ctx->local_node, i);
            break;
        }
    }

    if (rc == -ENOSPC)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: no free slots for node %u",
                     ctx->local_node);

    mxfs_pal_mutex_unlock(ctx->lock);
    return rc;
}

void mxfs_journal_release_slot(struct mxfs_journal_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->local_slot < 0) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: node %u releasing slot %d",
                 ctx->local_node, ctx->local_slot);

    ctx->slots[ctx->local_slot].state = MXFS_JSLOT_FREE;
    ctx->slots[ctx->local_slot].node_id = 0;
    ctx->slots[ctx->local_slot].claimed_at = 0;
    ctx->local_slot = -1;

    mxfs_pal_mutex_unlock(ctx->lock);
}

/*
 * Scan on-disk journal slot headers to find a DIRTY slot owned by a
 * given node. The in-memory slots[] table is per-node and doesn't
 * know about remote nodes' slot assignments. When a remote node crashes,
 * we must read the on-disk headers to discover which slot it used.
 *
 * Returns slot index (>= 0) on success, -ENOENT if not found.
 * Caller must hold ctx->lock if needed. Does NOT modify in-memory state.
 */
static int scan_disk_for_node_slot(struct mxfs_journal_ctx *ctx,
                                    mxfs_node_id_t node_id)
{
    struct mxfs_journal_slot_hdr *hdr;
    uint32_t nslots;
    uint32_t i;
    int found = -ENOENT;

    if (!ctx->dev || ctx->journal_offset == 0)
        return -ENOENT;

    nslots = ctx->super_disk.slot_count;
    if (nslots == 0 || nslots > MXFS_MAX_NODES)
        return -ENOENT;

    hdr = mxfs_pal_alloc(sizeof(*hdr));
    if (!hdr)
        return -ENOMEM;

    for (i = 0; i < nslots; i++) {
        uint64_t off = slot_offset(ctx, i);
        int rc = read_sector(ctx->dev, off, hdr);
        if (rc < 0)
            continue;

        if (hdr->magic != MXFS_JOURNAL_MAGIC)
            continue;

        if (hdr->owner == node_id &&
            (hdr->flags & MXFS_JSLOT_FLAG_DIRTY)) {
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "journal: on-disk scan found DIRTY slot %u "
                         "owned by node %u", i, node_id);
            found = (int)i;
            break;
        }
    }

    mxfs_pal_free(hdr);
    return found;
}

int mxfs_journal_mark_needs_recovery(struct mxfs_journal_ctx *ctx,
                                      mxfs_node_id_t node_id)
{
    int i;
    int rc = -ENOENT;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    /* First check the in-memory slot table (covers local node's slot) */
    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->slots[i].node_id == node_id &&
            ctx->slots[i].state == MXFS_JSLOT_ACTIVE) {
            ctx->slots[i].state = MXFS_JSLOT_NEEDS_RECOVERY;
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "journal: slot %d (node %u) marked for recovery",
                         i, node_id);
            rc = 0;
            break;
        }
    }

    /*
     * If not found in-memory, scan on-disk slot headers. The in-memory
     * table is per-node — remote nodes' slot assignments are only recorded
     * on disk (in the slot header's owner field + DIRTY flag).
     */
    if (rc == -ENOENT) {
        int disk_slot = scan_disk_for_node_slot(ctx, node_id);
        if (disk_slot >= 0 && disk_slot < MXFS_MAX_NODES) {
            ctx->slots[disk_slot].node_id = node_id;
            ctx->slots[disk_slot].state = MXFS_JSLOT_NEEDS_RECOVERY;
            ctx->slots[disk_slot].claimed_at = 0;
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "journal: slot %d (node %u) found on disk, "
                         "marked for recovery", disk_slot, node_id);
            rc = 0;
        }
    }

    if (rc)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "journal: no active slot for dead node %u "
                     "(checked in-memory and on-disk)", node_id);

    mxfs_pal_mutex_unlock(ctx->lock);
    return rc;
}

int mxfs_journal_begin_recovery(struct mxfs_journal_ctx *ctx, int slot)
{
    if (!ctx)
        return -EINVAL;

    if (slot < 0 || slot >= MXFS_MAX_NODES)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->slots[slot].state == MXFS_JSLOT_RECOVERING) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "journal: slot %d already being recovered", slot);
        mxfs_pal_mutex_unlock(ctx->lock);
        return -EBUSY;
    }

    if (ctx->slots[slot].state != MXFS_JSLOT_NEEDS_RECOVERY) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "journal: slot %d not in NEEDS_RECOVERY state (state=%d)",
                     slot, ctx->slots[slot].state);
        mxfs_pal_mutex_unlock(ctx->lock);
        return -EINVAL;
    }

    ctx->slots[slot].state = MXFS_JSLOT_RECOVERING;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: beginning recovery of slot %d (node %u)",
                 slot, ctx->slots[slot].node_id);

    mxfs_pal_mutex_unlock(ctx->lock);
    return 0;
}

int mxfs_journal_finish_recovery(struct mxfs_journal_ctx *ctx, int slot)
{
    if (!ctx)
        return -EINVAL;

    if (slot < 0 || slot >= MXFS_MAX_NODES)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->slots[slot].state != MXFS_JSLOT_RECOVERING) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "journal: slot %d not in RECOVERING state (state=%d)",
                     slot, ctx->slots[slot].state);
        mxfs_pal_mutex_unlock(ctx->lock);
        return -EINVAL;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: recovery of slot %d (node %u) complete",
                 slot, ctx->slots[slot].node_id);

    /* Transition RECOVERING -> FREE */
    ctx->slots[slot].state = MXFS_JSLOT_FREE;
    ctx->slots[slot].node_id = 0;
    ctx->slots[slot].claimed_at = 0;

    mxfs_pal_mutex_unlock(ctx->lock);
    return 0;
}

enum mxfs_journal_state mxfs_journal_get_state(struct mxfs_journal_ctx *ctx,
                                                mxfs_node_id_t node_id)
{
    enum mxfs_journal_state state = MXFS_JSLOT_FREE;
    int i;

    if (!ctx)
        return MXFS_JSLOT_FREE;

    mxfs_pal_mutex_lock(ctx->lock);

    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->slots[i].node_id == node_id &&
            ctx->slots[i].state != MXFS_JSLOT_FREE) {
            state = ctx->slots[i].state;
            break;
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    return state;
}

int mxfs_journal_slot_count(struct mxfs_journal_ctx *ctx)
{
    int count = 0;
    int i;

    if (!ctx)
        return 0;

    mxfs_pal_mutex_lock(ctx->lock);

    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->slots[i].state == MXFS_JSLOT_ACTIVE)
            count++;
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    return count;
}

int mxfs_journal_find_slot_by_node(struct mxfs_journal_ctx *ctx,
                                    mxfs_node_id_t node_id)
{
    int i;
    int rc = -ENOENT;

    if (!ctx)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    /* Check in-memory slot table first */
    for (i = 0; i < MXFS_MAX_NODES; i++) {
        if (ctx->slots[i].node_id == node_id &&
            ctx->slots[i].state != MXFS_JSLOT_FREE) {
            rc = i;
            break;
        }
    }

    /*
     * Fall back to on-disk scan. The in-memory table only knows about
     * slots claimed by this node. Remote nodes' slots are recorded
     * on-disk in the slot header (owner field + DIRTY flag).
     * If found, populate the in-memory entry so subsequent lookups
     * (begin_recovery, finish_recovery) work without re-scanning.
     */
    if (rc == -ENOENT) {
        int disk_slot = scan_disk_for_node_slot(ctx, node_id);
        if (disk_slot >= 0 && disk_slot < MXFS_MAX_NODES) {
            /* Only populate if the slot isn't already in use in-memory
             * (e.g. our own node could be using this slot index) */
            if (ctx->slots[disk_slot].state == MXFS_JSLOT_FREE) {
                ctx->slots[disk_slot].node_id = node_id;
                ctx->slots[disk_slot].state = MXFS_JSLOT_NEEDS_RECOVERY;
                ctx->slots[disk_slot].claimed_at = 0;
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "journal: find_slot_by_node populated slot %d "
                             "for node %u from on-disk scan",
                             disk_slot, node_id);
            }
            rc = disk_slot;
        }
    }

    mxfs_pal_mutex_unlock(ctx->lock);
    return rc;
}

/* ════════════════════════════════════════════════════════════════════
 * On-disk journal operations
 * ════════════════════════════════════════════════════════════════════ */

/*
 * Format a fresh journal region on device.
 * Writes the journal superblock and empty slot headers.
 */
int mxfs_journal_format(mxfs_bdev_t *dev, uint64_t offset,
                         uint32_t slot_count, const uint8_t *uuid)
{
    /* Heap-allocate 512-byte structs to avoid kernel stack overflow */
    struct mxfs_journal_super *super;
    struct mxfs_journal_slot_hdr *slot_hdr;
    uint32_t i;
    int rc;

    if (!dev || !uuid || slot_count == 0)
        return -EINVAL;

    super = mxfs_pal_alloc(sizeof(*super));
    slot_hdr = mxfs_pal_alloc(sizeof(*slot_hdr));
    if (!super || !slot_hdr) {
        mxfs_pal_free(super);
        mxfs_pal_free(slot_hdr);
        return -ENOMEM;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: formatting %u slots at offset %llu",
                 slot_count, (unsigned long long)offset);

    /* Write journal superblock */
    memset(super, 0, sizeof(*super));
    super->magic = MXFS_JOURNAL_MAGIC;
    super->version = MXFS_JOURNAL_VERSION;
    super->slot_count = slot_count;
    super->slot_size_sectors = MXFS_JOURNAL_SLOT_SIZE_SECTORS;
    super->sector_size = MXFS_JOURNAL_SECTOR_SIZE;
    memcpy(super->fs_uuid, uuid, 16);
    super->crc = 0;
    super->crc = sector_crc(super,
                             offsetof(struct mxfs_journal_super, crc));

    rc = write_sector(dev, offset, super);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: format failed writing super: %d", rc);
        goto out;
    }

    /* Write empty slot headers */
    for (i = 0; i < slot_count; i++) {
        uint64_t hdr_offset = offset + MXFS_JOURNAL_SECTOR_SIZE +
                              (uint64_t)i * MXFS_JOURNAL_SLOT_SIZE_SECTORS *
                              MXFS_JOURNAL_SECTOR_SIZE;

        memset(slot_hdr, 0, sizeof(*slot_hdr));
        slot_hdr->magic = MXFS_JOURNAL_MAGIC;
        slot_hdr->flags = MXFS_JSLOT_FLAG_CLEAN;
        slot_hdr->owner = 0;
        slot_hdr->head_sector = 1;  /* data starts at sector 1 */
        slot_hdr->tail_sector = 1;  /* empty: head == tail */
        slot_hdr->seq_head = 0;
        slot_hdr->seq_tail = 0;
        slot_hdr->crc = 0;
        slot_hdr->crc = sector_crc(slot_hdr,
                                    offsetof(struct mxfs_journal_slot_hdr, crc));

        rc = write_sector(dev, hdr_offset, slot_hdr);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: format failed writing slot %u hdr: %d",
                         i, rc);
            goto out;
        }
    }

    rc = mxfs_pal_bdev_flush(dev);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: format flush failed: %d", rc);
        goto out;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: format complete (%u slots, %u sectors/slot)",
                 slot_count, MXFS_JOURNAL_SLOT_SIZE_SECTORS);

    rc = 0;

out:
    mxfs_pal_free(super);
    mxfs_pal_free(slot_hdr);
    return rc;
}

/*
 * Open and validate an existing journal.
 * Reads the journal superblock and validates magic/version.
 */
int mxfs_journal_open(struct mxfs_journal_ctx *ctx, mxfs_bdev_t *dev,
                       uint64_t offset)
{
    struct mxfs_journal_super super;
    uint32_t stored_crc;
    uint32_t computed_crc;
    int rc;

    if (!ctx || !dev)
        return -EINVAL;

    rc = read_sector(dev, offset, &super);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: open failed reading super: %d", rc);
        return rc;
    }

    if (super.magic != MXFS_JOURNAL_MAGIC) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: bad magic %08x (expected %08x)",
                     super.magic, MXFS_JOURNAL_MAGIC);
        return -EINVAL;
    }

    if (super.version != MXFS_JOURNAL_VERSION) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: unsupported version %u (expected %u)",
                     super.version, MXFS_JOURNAL_VERSION);
        return -EINVAL;
    }

    /* Validate CRC */
    stored_crc = super.crc;
    computed_crc = sector_crc(&super,
                               offsetof(struct mxfs_journal_super, crc));
    if (stored_crc != computed_crc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: journal metadata is corrupt (checksum mismatch) "
                     "— run chk_mxfs to repair");
        return -EIO;
    }

    ctx->dev = dev;
    ctx->journal_offset = offset;
    ctx->super_disk = super;
    ctx->slot_size_sectors = super.slot_size_sectors;

    /* Allocate write buffer (one sector) */
    if (!ctx->write_buf) {
        ctx->write_buf = mxfs_pal_alloc(MXFS_JOURNAL_SECTOR_SIZE);
        if (!ctx->write_buf)
            return -ENOMEM;
        ctx->write_buf_size = MXFS_JOURNAL_SECTOR_SIZE;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: opened (%u slots, %u sectors/slot, version %u)",
                 super.slot_count, super.slot_size_sectors, super.version);

    return 0;
}

/*
 * Open a specific slot for this node's use.
 * Reads the slot header and initializes the circular buffer state.
 */
int mxfs_journal_slot_open(struct mxfs_journal_ctx *ctx, int slot)
{
    struct mxfs_journal_slot_hdr hdr;
    uint64_t hdr_offset;
    uint32_t stored_crc;
    uint32_t computed_crc;
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    if (slot < 0 || (uint32_t)slot >= ctx->super_disk.slot_count)
        return -EINVAL;

    hdr_offset = slot_offset(ctx, slot);

    rc = read_sector(ctx->dev, hdr_offset, &hdr);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: slot_open failed reading hdr for slot %d: %d",
                     slot, rc);
        return rc;
    }

    if (hdr.magic != MXFS_JOURNAL_MAGIC) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: slot %d bad magic %08x", slot, hdr.magic);
        return -EINVAL;
    }

    /* Validate CRC */
    stored_crc = hdr.crc;
    computed_crc = sector_crc(&hdr,
                               offsetof(struct mxfs_journal_slot_hdr, crc));
    if (stored_crc != computed_crc) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: journal slot %d header checksum invalid, "
                     "reinitializing (no data loss — slot was from "
                     "previous session)", slot);
        /* Treat as empty slot */
        hdr.head_sector = 1;
        hdr.tail_sector = 1;
        hdr.seq_head = 0;
        hdr.seq_tail = 0;
    }

    ctx->slot_base = hdr_offset;
    ctx->head = hdr.head_sector;
    ctx->tail = hdr.tail_sector;
    ctx->next_seq = hdr.seq_head;
    ctx->next_txn_id = hdr.seq_head; /* start txn IDs from seq */

    /* Validate head/tail are in range */
    if (ctx->head == 0 || ctx->head >= ctx->slot_size_sectors)
        ctx->head = 1;
    if (ctx->tail == 0 || ctx->tail >= ctx->slot_size_sectors)
        ctx->tail = 1;

    /* Record whether the slot was dirty (previous crash) */
    ctx->slot_dirty = (hdr.flags & MXFS_JSLOT_FLAG_DIRTY) ? true : false;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: slot %d opened (head=%u tail=%u seq=%llu "
                 "flags=%s owner=%u)",
                 slot, ctx->head, ctx->tail,
                 (unsigned long long)ctx->next_seq,
                 ctx->slot_dirty ? "DIRTY" : "CLEAN",
                 hdr.owner);

    return 0;
}

/*
 * Mark the current slot as DIRTY on disk.
 */
int mxfs_journal_slot_mark_dirty(struct mxfs_journal_ctx *ctx)
{
    struct mxfs_journal_slot_hdr hdr;
    int rc;

    if (!ctx || !ctx->dev || ctx->local_slot < 0)
        return -EINVAL;

    rc = read_sector(ctx->dev, ctx->slot_base, &hdr);
    if (rc < 0)
        return rc;

    hdr.flags = MXFS_JSLOT_FLAG_DIRTY;
    hdr.owner = ctx->local_node;
    hdr.crc = 0;
    hdr.crc = sector_crc(&hdr,
                          offsetof(struct mxfs_journal_slot_hdr, crc));

    rc = write_sector(ctx->dev, ctx->slot_base, &hdr);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: mark_dirty failed: %d", rc);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "journal: slot %d marked DIRTY",
                 ctx->local_slot);
    return 0;
}

/*
 * Mark the current slot as CLEAN on disk.
 */
int mxfs_journal_slot_mark_clean(struct mxfs_journal_ctx *ctx)
{
    struct mxfs_journal_slot_hdr hdr;
    int rc;

    if (!ctx || !ctx->dev || ctx->local_slot < 0)
        return -EINVAL;

    rc = read_sector(ctx->dev, ctx->slot_base, &hdr);
    if (rc < 0)
        return rc;

    hdr.flags = MXFS_JSLOT_FLAG_CLEAN;
    hdr.head_sector = ctx->head;
    hdr.tail_sector = ctx->tail;
    hdr.seq_head = ctx->next_seq;
    hdr.seq_tail = 0;
    hdr.crc = 0;
    hdr.crc = sector_crc(&hdr,
                          offsetof(struct mxfs_journal_slot_hdr, crc));

    rc = write_sector(ctx->dev, ctx->slot_base, &hdr);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: mark_clean failed: %d", rc);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "journal: slot %d marked CLEAN",
                 ctx->local_slot);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Transaction API
 * ════════════════════════════════════════════════════════════════════ */

/*
 * Begin a new transaction.
 * Returns an allocated txn struct, or NULL on OOM.
 */
struct mxfs_txn *mxfs_journal_txn_begin(struct mxfs_journal_ctx *ctx)
{
    struct mxfs_txn *txn;

    if (!ctx)
        return NULL;

    txn = mxfs_pal_alloc(sizeof(*txn));
    if (!txn)
        return NULL;

    memset(txn, 0, sizeof(*txn));

    mxfs_pal_mutex_lock(ctx->lock);
    txn->txn_id = ctx->next_txn_id++;
    mxfs_pal_mutex_unlock(ctx->lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: txn %llu begin",
                 (unsigned long long)txn->txn_id);

    return txn;
}

/*
 * Log a metadata write to the transaction.
 * Buffers the data for later commit.
 */
int mxfs_journal_txn_log_write(struct mxfs_journal_ctx *ctx,
                                struct mxfs_txn *txn,
                                uint64_t disk_offset,
                                const void *data, uint32_t len)
{
    struct mxfs_txn_entry *e;

    if (!ctx || !txn || !data || len == 0)
        return -EINVAL;

    e = mxfs_pal_alloc(sizeof(*e));
    if (!e)
        return -ENOMEM;

    memset(e, 0, sizeof(*e));
    e->type = MXFS_JE_METADATA;
    e->disk_offset = disk_offset;
    e->data_len = len;
    e->data = mxfs_pal_alloc(len);
    if (!e->data) {
        mxfs_pal_free(e);
        return -ENOMEM;
    }
    memcpy(e->data, data, len);
    e->next = NULL;

    /* Append to tail of list */
    if (txn->tail) {
        txn->tail->next = e;
        txn->tail = e;
    } else {
        txn->entries = e;
        txn->tail = e;
    }
    txn->count++;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: txn %llu log_write offset=%llu len=%u",
                 (unsigned long long)txn->txn_id,
                 (unsigned long long)disk_offset, len);

    return 0;
}

/*
 * Log a revoke to the transaction.
 * On replay, metadata writes to this offset will be skipped.
 */
int mxfs_journal_txn_log_revoke(struct mxfs_journal_ctx *ctx,
                                 struct mxfs_txn *txn,
                                 uint64_t disk_offset, uint32_t len)
{
    struct mxfs_txn_entry *e;

    if (!ctx || !txn)
        return -EINVAL;

    e = mxfs_pal_alloc(sizeof(*e));
    if (!e)
        return -ENOMEM;

    memset(e, 0, sizeof(*e));
    e->type = MXFS_JE_REVOKE;
    e->disk_offset = disk_offset;
    e->data_len = len;
    e->data = NULL;
    e->next = NULL;

    if (txn->tail) {
        txn->tail->next = e;
        txn->tail = e;
    } else {
        txn->entries = e;
        txn->tail = e;
    }
    txn->count++;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: txn %llu log_revoke offset=%llu len=%u",
                 (unsigned long long)txn->txn_id,
                 (unsigned long long)disk_offset, len);

    return 0;
}

/*
 * Compute the serialized on-disk size of one transaction entry.
 */
static uint32_t compute_entry_size(struct mxfs_txn_entry *e)
{
    if (e->type == MXFS_JE_METADATA) {
        uint32_t payload = (uint32_t)sizeof(struct mxfs_journal_metadata_payload)
                         + e->data_len;
        return round_up_sector(
            (uint32_t)sizeof(struct mxfs_journal_entry_hdr) + payload);
    }
    /* REVOKE entries are always 1 sector */
    return MXFS_JOURNAL_SECTOR_SIZE;
}

/*
 * Serialize one transaction entry into a buffer at the given offset.
 * Fills in header, payload, seq number, and CRC.
 * Returns the entry size (same as compute_entry_size).
 */
static uint32_t serialize_entry(struct mxfs_journal_ctx *ctx,
                                 struct mxfs_txn_entry *e,
                                 uint64_t txn_id,
                                 uint8_t *buf, uint32_t entry_size)
{
    struct mxfs_journal_entry_hdr *hdr = (struct mxfs_journal_entry_hdr *)buf;

    memset(buf, 0, entry_size);
    hdr->magic = MXFS_JE_MAGIC;
    hdr->txn_id = txn_id;
    hdr->total_len = entry_size;

    if (e->type == MXFS_JE_METADATA) {
        struct mxfs_journal_metadata_payload meta;
        uint32_t payload_size = (uint32_t)sizeof(meta) + e->data_len;

        hdr->type = MXFS_JE_METADATA;
        hdr->payload_len = payload_size;

        meta.disk_offset = e->disk_offset;
        meta.data_len = e->data_len;
        meta.pad = 0;
        memcpy(buf + sizeof(*hdr), &meta, sizeof(meta));
        memcpy(buf + sizeof(*hdr) + sizeof(meta), e->data, e->data_len);
    } else {
        struct mxfs_journal_revoke_payload rev;

        hdr->type = MXFS_JE_REVOKE;
        hdr->payload_len = (uint32_t)sizeof(rev);

        rev.disk_offset = e->disk_offset;
        rev.len = e->data_len;
        rev.pad = 0;
        memcpy(buf + sizeof(*hdr), &rev, sizeof(rev));
    }

    hdr->seq = ctx->next_seq++;
    hdr->crc = 0;
    hdr->crc = mxfs_pal_crc32c(~0U, buf, entry_size);

    return entry_size;
}

/*
 * Commit a transaction: serialize all entries + COMMIT marker into a
 * single contiguous buffer and write to the journal in one or two I/Os
 * (two if the write wraps the circular buffer). This reduces hundreds
 * of individual 512-byte iSCSI WRITE commands to 1-2 large writes.
 *
 * On-disk format is identical to per-sector writes — replay reads
 * sector-by-sector and doesn't care how sectors were written.
 *
 * The device flush and slot header update are deferred to
 * mxfs_journal_flush() (from sync_fs, fsync, checkpoint, or unmount).
 */
int mxfs_journal_txn_commit(struct mxfs_journal_ctx *ctx,
                             struct mxfs_txn *txn)
{
    struct mxfs_txn_entry *e;
    uint32_t total_bytes = 0;
    uint32_t sectors_needed;
    uint32_t free;
    uint32_t capacity;
    uint8_t *batch_buf;
    uint32_t offset;
    int rc;

    if (!ctx || !txn || !ctx->dev)
        return -EINVAL;

    /* Pass 1: compute total size of all entries + COMMIT */
    for (e = txn->entries; e; e = e->next)
        total_bytes += compute_entry_size(e);
    total_bytes += MXFS_JOURNAL_SECTOR_SIZE;  /* COMMIT entry */
    sectors_needed = total_bytes / MXFS_JOURNAL_SECTOR_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);

    /* Space check — same logic as write_entry() */
    free = free_sectors(ctx);
    capacity = total_data_sectors(ctx);

    if (capacity > 0 && free < capacity / 4) {
        rc = checkpoint_locked(ctx);
        if (rc == 0)
            free = free_sectors(ctx);
    }

    if (sectors_needed > free) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: journal space low, writing pending data to disk "
                     "(brief pause may occur)");
        rc = checkpoint_locked(ctx);
        if (rc < 0) {
            mxfs_pal_mutex_unlock(ctx->lock);
            return -ENOSPC;
        }
        free = free_sectors(ctx);
        if (sectors_needed > free) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: txn too large even after checkpoint "
                         "(%u sectors needed, %u available)",
                         sectors_needed, free);
            mxfs_pal_mutex_unlock(ctx->lock);
            return -ENOSPC;
        }
    }

    /* Allocate contiguous batch buffer */
    batch_buf = mxfs_pal_alloc(total_bytes);
    if (!batch_buf) {
        /* Fallback: write entries individually (old path) */
        for (e = txn->entries; e; e = e->next) {
            uint32_t esz = compute_entry_size(e);
            uint8_t *ebuf = mxfs_pal_alloc(esz);
            if (!ebuf) {
                mxfs_pal_mutex_unlock(ctx->lock);
                return -ENOMEM;
            }
            serialize_entry(ctx, e, txn->txn_id, ebuf, esz);
            rc = write_entry(ctx, ebuf, esz);
            mxfs_pal_free(ebuf);
            if (rc < 0) {
                mxfs_pal_mutex_unlock(ctx->lock);
                return rc;
            }
        }
        rc = write_simple_entry(ctx, MXFS_JE_COMMIT, txn->txn_id);
        if (rc < 0) {
            mxfs_pal_mutex_unlock(ctx->lock);
            return rc;
        }
        goto committed;
    }

    /* Pass 2: serialize all entries into the batch buffer */
    offset = 0;
    for (e = txn->entries; e; e = e->next) {
        uint32_t esz = compute_entry_size(e);
        serialize_entry(ctx, e, txn->txn_id, batch_buf + offset, esz);
        offset += esz;
    }

    /* Serialize COMMIT entry at the end */
    {
        struct mxfs_journal_entry_hdr *chdr =
            (struct mxfs_journal_entry_hdr *)(batch_buf + offset);
        memset(batch_buf + offset, 0, MXFS_JOURNAL_SECTOR_SIZE);
        chdr->magic = MXFS_JE_MAGIC;
        chdr->type = MXFS_JE_COMMIT;
        chdr->txn_id = txn->txn_id;
        chdr->total_len = MXFS_JOURNAL_SECTOR_SIZE;
        chdr->payload_len = 0;
        chdr->seq = ctx->next_seq++;
        chdr->crc = 0;
        chdr->crc = mxfs_pal_crc32c(~0U, batch_buf + offset,
                                      MXFS_JOURNAL_SECTOR_SIZE);
    }

    /* Write batch buffer — handle circular buffer wrap */
    {
        uint32_t data_sectors = ctx->slot_size_sectors - 1;
        uint32_t head_idx = ctx->head - 1;  /* 0-based */
        uint32_t sectors_to_end = data_sectors - head_idx;

        if (sectors_needed <= sectors_to_end) {
            /* No wrap: single contiguous write */
            uint64_t disk_off = entry_sector_offset(ctx, ctx->head);
            rc = mxfs_pal_bdev_write(ctx->dev, disk_off,
                                      batch_buf, total_bytes);
        } else {
            /* Wrap: two writes */
            uint32_t first_bytes = sectors_to_end * MXFS_JOURNAL_SECTOR_SIZE;
            uint32_t second_bytes = total_bytes - first_bytes;
            uint64_t off1 = entry_sector_offset(ctx, ctx->head);
            uint64_t off2 = entry_sector_offset(ctx, 1);  /* start of data area */

            rc = mxfs_pal_bdev_write(ctx->dev, off1,
                                      batch_buf, first_bytes);
            if (rc == 0)
                rc = mxfs_pal_bdev_write(ctx->dev, off2,
                                          batch_buf + first_bytes,
                                          second_bytes);
        }

        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: txn %llu batch write failed: %d",
                         (unsigned long long)txn->txn_id, rc);
            mxfs_pal_free(batch_buf);
            mxfs_pal_mutex_unlock(ctx->lock);
            return rc;
        }

        ctx->head = advance_sector(ctx, ctx->head, sectors_needed);
    }

    mxfs_pal_free(batch_buf);

committed:
    ctx->unflushed_commits++;
    ctx->stat_commits++;
    mxfs_pal_mutex_unlock(ctx->lock);

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: txn %llu committed (%d entries, %u sectors, "
                 "%u unflushed)",
                 (unsigned long long)txn->txn_id, txn->count,
                 sectors_needed, ctx->unflushed_commits);

    /* Free transaction resources */
    free_txn_entries(txn);
    mxfs_pal_free(txn);

    return 0;
}

/*
 * Abort a transaction: discard all buffered entries without writing.
 */
void mxfs_journal_txn_abort(struct mxfs_journal_ctx *ctx,
                             struct mxfs_txn *txn)
{
    if (!txn)
        return;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: txn %llu aborted (%d entries discarded)",
                 (unsigned long long)txn->txn_id, txn->count);

    free_txn_entries(txn);
    mxfs_pal_free(txn);
}

/* ════════════════════════════════════════════════════════════════════
 * Recovery — two-pass journal replay
 * ════════════════════════════════════════════════════════════════════ */

/* Revoke table entry for replay filtering */
struct revoke_entry {
    uint64_t        disk_offset;
    uint32_t        len;
    struct revoke_entry *next;
};

/* Check if a disk_offset is in the revoke table */
static bool is_revoked(struct revoke_entry *revoke_list,
                        uint64_t disk_offset)
{
    struct revoke_entry *r;
    for (r = revoke_list; r; r = r->next) {
        if (disk_offset >= r->disk_offset &&
            disk_offset < r->disk_offset + r->len)
            return true;
    }
    return false;
}

/* Free the revoke list */
static void free_revoke_list(struct revoke_entry *list)
{
    while (list) {
        struct revoke_entry *next = list->next;
        mxfs_pal_free(list);
        list = next;
    }
}

/* Committed txn tracker */
struct committed_txn {
    uint64_t        txn_id;
    struct committed_txn *next;
};

static bool is_committed(struct committed_txn *list, uint64_t txn_id)
{
    struct committed_txn *c;
    for (c = list; c; c = c->next) {
        if (c->txn_id == txn_id)
            return true;
    }
    return false;
}

static void free_committed_list(struct committed_txn *list)
{
    while (list) {
        struct committed_txn *next = list->next;
        mxfs_pal_free(list);
        list = next;
    }
}

/*
 * Read an entry at a given sector position within a slot.
 * Returns the entry header and optionally the full entry buffer.
 * Caller must free *out_buf if non-NULL.
 */
static int read_entry_at(struct mxfs_journal_ctx *ctx, uint32_t sector_pos,
                          struct mxfs_journal_entry_hdr *out_hdr,
                          void **out_buf)
{
    uint64_t offset;
    uint8_t first_sector[MXFS_JOURNAL_SECTOR_SIZE];
    struct mxfs_journal_entry_hdr *hdr;
    uint32_t total_len;
    uint32_t sectors;
    uint8_t *full_buf;
    uint32_t stored_crc;
    uint32_t computed_crc;
    uint32_t i;
    int rc;

    offset = entry_sector_offset(ctx, sector_pos);
    rc = read_sector(ctx->dev, offset, first_sector);
    if (rc < 0)
        return rc;

    hdr = (struct mxfs_journal_entry_hdr *)first_sector;
    if (hdr->magic != MXFS_JE_MAGIC) {
        return -EINVAL; /* not a valid entry */
    }

    total_len = hdr->total_len;
    if (total_len == 0 || total_len % MXFS_JOURNAL_SECTOR_SIZE != 0)
        return -EIO;

    sectors = total_len / MXFS_JOURNAL_SECTOR_SIZE;

    /* Read full entry */
    full_buf = mxfs_pal_alloc(total_len);
    if (!full_buf)
        return -ENOMEM;

    memcpy(full_buf, first_sector, MXFS_JOURNAL_SECTOR_SIZE);

    for (i = 1; i < sectors; i++) {
        uint32_t next_pos = advance_sector(ctx, sector_pos, i);
        offset = entry_sector_offset(ctx, next_pos);
        rc = read_sector(ctx->dev, offset,
                          full_buf + i * MXFS_JOURNAL_SECTOR_SIZE);
        if (rc < 0) {
            mxfs_pal_free(full_buf);
            return rc;
        }
    }

    /* Verify CRC */
    hdr = (struct mxfs_journal_entry_hdr *)full_buf;
    stored_crc = hdr->crc;
    hdr->crc = 0;
    computed_crc = mxfs_pal_crc32c(~0U, full_buf, total_len);
    hdr->crc = stored_crc;

    if (stored_crc != computed_crc) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: journal entry at position %u has invalid "
                     "checksum (end of recoverable data reached)",
                     sector_pos);
        mxfs_pal_free(full_buf);
        return -EIO;
    }

    *out_hdr = *hdr;
    if (out_buf)
        *out_buf = full_buf;
    else
        mxfs_pal_free(full_buf);

    return 0;
}

/*
 * Two-pass journal replay for a slot.
 *
 * Pass 1: Scan from tail to head, collect:
 *   - Set of committed transaction IDs (from COMMIT entries)
 *   - Revoke table (from REVOKE entries in committed txns)
 *
 * Pass 2: Scan again from tail to head, replay:
 *   - METADATA entries from committed txns, unless their
 *     target offset is in the revoke table
 */
int mxfs_journal_replay(struct mxfs_journal_ctx *ctx, int slot)
{
    /* Heap-allocate slot header to avoid kernel stack overflow */
    struct mxfs_journal_slot_hdr *hdr;
    uint64_t hdr_offset;
    uint32_t scan_pos;
    uint32_t saved_head;
    uint32_t saved_tail;
    uint64_t saved_slot_base;
    uint32_t saved_slot_size;
    struct revoke_entry *revoke_list = NULL;
    struct committed_txn *committed_list = NULL;
    int replayed = 0;
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    if (slot < 0 || (uint32_t)slot >= ctx->super_disk.slot_count)
        return -EINVAL;

    hdr = mxfs_pal_alloc(sizeof(*hdr));
    if (!hdr)
        return -ENOMEM;

    hdr_offset = slot_offset(ctx, slot);

    rc = read_sector(ctx->dev, hdr_offset, hdr);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: replay failed reading slot %d hdr: %d",
                     slot, rc);
        mxfs_pal_free(hdr);
        return rc;
    }

    if (hdr->magic != MXFS_JOURNAL_MAGIC) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: replay slot %d bad magic", slot);
        mxfs_pal_free(hdr);
        return -EINVAL;
    }

    /* If slot is clean, nothing to replay */
    if (hdr->flags == MXFS_JSLOT_FLAG_CLEAN) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "journal: slot %d is clean, nothing to replay", slot);
        mxfs_pal_free(hdr);
        return 0;
    }

    /* Save current context state and temporarily set up for this slot */
    saved_head = ctx->head;
    saved_tail = ctx->tail;
    saved_slot_base = ctx->slot_base;
    saved_slot_size = ctx->slot_size_sectors;

    ctx->slot_base = hdr_offset;
    ctx->slot_size_sectors = ctx->super_disk.slot_size_sectors;
    ctx->head = hdr->head_sector;
    ctx->tail = hdr->tail_sector;

    if (ctx->head == 0 || ctx->head >= ctx->slot_size_sectors)
        ctx->head = 1;
    if (ctx->tail == 0 || ctx->tail >= ctx->slot_size_sectors)
        ctx->tail = 1;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: replaying slot %d (head=%u tail=%u owner=%u)",
                 slot, ctx->head, ctx->tail, hdr->owner);

    mxfs_pal_free(hdr);
    hdr = NULL;

    /* If head == tail, journal is empty */
    if (ctx->head == ctx->tail) {
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "journal: slot %d is empty, nothing to replay", slot);
        goto out_restore;
    }

    /* ─── Pass 1: collect committed txn IDs and revoke entries ─── */
    scan_pos = ctx->tail;
    while (scan_pos != ctx->head) {
        struct mxfs_journal_entry_hdr ehdr;
        void *buf = NULL;

        rc = read_entry_at(ctx, scan_pos, &ehdr, &buf);
        if (rc < 0) {
            /* CRC error or bad entry — stop scanning */
            mxfs_pal_log(MXFS_LOG_WARN,
                         "journal: pass1 bad entry at sector %u, stopping",
                         scan_pos);
            if (buf)
                mxfs_pal_free(buf);
            break;
        }

        if (ehdr.type == MXFS_JE_COMMIT) {
            struct committed_txn *ct = mxfs_pal_alloc(sizeof(*ct));
            if (ct) {
                ct->txn_id = ehdr.txn_id;
                ct->next = committed_list;
                committed_list = ct;
            }
        } else if (ehdr.type == MXFS_JE_UNMOUNT) {
            /* Clean unmount — no replay needed past this point */
            mxfs_pal_log(MXFS_LOG_DEBUG,
                         "journal: slot %d has UNMOUNT marker, no replay",
                         slot);
            mxfs_pal_free(buf);
            goto out_clean;
        }

        /* Advance scan_pos past this entry */
        scan_pos = advance_sector(ctx, scan_pos,
                                   ehdr.total_len / MXFS_JOURNAL_SECTOR_SIZE);
        mxfs_pal_free(buf);
    }

    /* Now collect revokes from committed transactions */
    scan_pos = ctx->tail;
    while (scan_pos != ctx->head) {
        struct mxfs_journal_entry_hdr ehdr;
        void *buf = NULL;

        rc = read_entry_at(ctx, scan_pos, &ehdr, &buf);
        if (rc < 0) {
            if (buf)
                mxfs_pal_free(buf);
            break;
        }

        if (ehdr.type == MXFS_JE_REVOKE &&
            is_committed(committed_list, ehdr.txn_id)) {
            struct mxfs_journal_revoke_payload *rev;
            rev = (struct mxfs_journal_revoke_payload *)
                  ((uint8_t *)buf + sizeof(struct mxfs_journal_entry_hdr));

            struct revoke_entry *re = mxfs_pal_alloc(sizeof(*re));
            if (re) {
                re->disk_offset = rev->disk_offset;
                re->len = rev->len;
                re->next = revoke_list;
                revoke_list = re;
            }
        }

        scan_pos = advance_sector(ctx, scan_pos,
                                   ehdr.total_len / MXFS_JOURNAL_SECTOR_SIZE);
        mxfs_pal_free(buf);
    }

    /* ─── Pass 2: replay committed METADATA, skip revoked ─── */
    scan_pos = ctx->tail;
    while (scan_pos != ctx->head) {
        struct mxfs_journal_entry_hdr ehdr;
        void *buf = NULL;

        rc = read_entry_at(ctx, scan_pos, &ehdr, &buf);
        if (rc < 0) {
            if (buf)
                mxfs_pal_free(buf);
            break;
        }

        if (ehdr.type == MXFS_JE_METADATA &&
            is_committed(committed_list, ehdr.txn_id)) {
            struct mxfs_journal_metadata_payload *meta;
            uint8_t *write_data;

            meta = (struct mxfs_journal_metadata_payload *)
                   ((uint8_t *)buf + sizeof(struct mxfs_journal_entry_hdr));
            write_data = (uint8_t *)buf +
                         sizeof(struct mxfs_journal_entry_hdr) +
                         sizeof(struct mxfs_journal_metadata_payload);

            if (!is_revoked(revoke_list, meta->disk_offset)) {
                mxfs_bdev_t *replay_dev = ctx->xfs_dev ? ctx->xfs_dev : ctx->dev;
                rc = mxfs_pal_bdev_write(replay_dev, meta->disk_offset,
                                          write_data, meta->data_len);
                if (rc < 0) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "journal: replay write failed at "
                                 "offset %llu: %d",
                                 (unsigned long long)meta->disk_offset, rc);
                    mxfs_pal_free(buf);
                    goto out_cleanup;
                }
                replayed++;

                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "journal: replayed metadata txn=%llu "
                             "offset=%llu len=%u",
                             (unsigned long long)ehdr.txn_id,
                             (unsigned long long)meta->disk_offset,
                             meta->data_len);
            } else {
                mxfs_pal_log(MXFS_LOG_DEBUG,
                             "journal: skipped revoked offset=%llu",
                             (unsigned long long)meta->disk_offset);
            }
        }

        scan_pos = advance_sector(ctx, scan_pos,
                                   ehdr.total_len / MXFS_JOURNAL_SECTOR_SIZE);
        mxfs_pal_free(buf);
    }

    /* Flush replayed writes */
    if (replayed > 0) {
        mxfs_bdev_t *flush_dev = ctx->xfs_dev ? ctx->xfs_dev : ctx->dev;
        rc = mxfs_pal_bdev_flush(flush_dev);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "journal: replay flush failed: %d", rc);
            goto out_cleanup;
        }
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: replay complete for slot %d (%d entries replayed)",
                 slot, replayed);

out_clean:
    /* Mark slot clean after successful replay */
    {
        struct mxfs_journal_slot_hdr *clean_hdr;
        clean_hdr = mxfs_pal_alloc(sizeof(*clean_hdr));
        if (clean_hdr) {
            memset(clean_hdr, 0, sizeof(*clean_hdr));
            clean_hdr->magic = MXFS_JOURNAL_MAGIC;
            clean_hdr->flags = MXFS_JSLOT_FLAG_CLEAN;
            clean_hdr->owner = 0;
            clean_hdr->head_sector = 1;
            clean_hdr->tail_sector = 1;
            clean_hdr->seq_head = 0;
            clean_hdr->seq_tail = 0;
            clean_hdr->crc = 0;
            clean_hdr->crc = sector_crc(clean_hdr,
                                         offsetof(struct mxfs_journal_slot_hdr,
                                                  crc));
            write_sector(ctx->dev, hdr_offset, clean_hdr);
            mxfs_pal_bdev_flush(ctx->dev);
            mxfs_pal_free(clean_hdr);
        }
    }
    rc = 0;

out_cleanup:
    free_revoke_list(revoke_list);
    free_committed_list(committed_list);

out_restore:
    /* Restore original context state */
    ctx->head = saved_head;
    ctx->tail = saved_tail;
    ctx->slot_base = saved_slot_base;
    ctx->slot_size_sectors = saved_slot_size;

    return rc;
}

/* ════════════════════════════════════════════════════════════════════
 * Maintenance
 * ════════════════════════════════════════════════════════════════════ */

/*
 * Flush unflushed journal commits to stable storage.
 * Issues a device flush and updates the slot header on disk.
 * Called from sync_fs, fsync, checkpoint, and unmount to ensure
 * durability of previously committed transactions.
 *
 * No-op if there are no unflushed commits.
 */
int mxfs_journal_flush(struct mxfs_journal_ctx *ctx)
{
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->unflushed_commits == 0) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return 0;
    }

    /* Flush device to push all journal writes to stable storage */
    rc = mxfs_pal_bdev_flush(ctx->dev);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: flush failed (%u unflushed commits): %d",
                     ctx->unflushed_commits, rc);
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    /* Update slot header on disk */
    rc = flush_slot_header(ctx);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: flush slot header failed: %d", rc);
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: flushed %u commits to stable storage",
                 ctx->unflushed_commits);

    ctx->unflushed_commits = 0;
    ctx->stat_flush_count++;

    mxfs_pal_mutex_unlock(ctx->lock);
    return 0;
}

/*
 * Checkpoint: advance tail to head (all entries consumed).
 * Writes a CHECKPOINT entry and updates the slot header.
 */
int mxfs_journal_checkpoint(struct mxfs_journal_ctx *ctx)
{
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    if (ctx->head == ctx->tail) {
        /* Nothing to checkpoint */
        mxfs_pal_mutex_unlock(ctx->lock);
        return 0;
    }

    /* Write CHECKPOINT entry */
    rc = write_simple_entry(ctx, MXFS_JE_CHECKPOINT, 0);
    if (rc < 0) {
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    /* Advance tail to head — all previous entries are now consumed */
    ctx->tail = ctx->head;

    /* Flush and update slot header */
    rc = mxfs_pal_bdev_flush(ctx->dev);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: checkpoint flush failed: %d", rc);
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    rc = flush_slot_header(ctx);

    /* Checkpoint includes a full flush, so clear the unflushed counter */
    if (rc == 0)
        ctx->unflushed_commits = 0;

    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == 0)
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "journal: checkpoint complete (head=tail=%u)",
                     ctx->head);

    return rc;
}

/*
 * Write a clean unmount marker and mark the slot CLEAN.
 */
int mxfs_journal_write_unmount(struct mxfs_journal_ctx *ctx)
{
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);

    /* Write UNMOUNT entry */
    rc = write_simple_entry(ctx, MXFS_JE_UNMOUNT, 0);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: write_unmount entry failed: %d", rc);
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    /* Flush — also covers any unflushed commits */
    rc = mxfs_pal_bdev_flush(ctx->dev);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: write_unmount flush failed: %d", rc);
        mxfs_pal_mutex_unlock(ctx->lock);
        return rc;
    }

    ctx->unflushed_commits = 0;

    mxfs_pal_mutex_unlock(ctx->lock);

    /* Mark slot clean */
    rc = mxfs_journal_slot_mark_clean(ctx);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "journal: write_unmount mark_clean failed: %d", rc);
        return rc;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "journal: clean unmount written (slot %d)",
                 ctx->local_slot);

    return 0;
}
