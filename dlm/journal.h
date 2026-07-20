/*
 * MXFS — Multinode XFS
 * Portable journal — slot management, write engine, replay, transactions
 *
 * Each node gets a dedicated journal slot (circular buffer on disk).
 * Metadata changes are journaled before being applied, enabling
 * crash recovery. When a node dies (lease expires), another node
 * replays the dead node's journal to restore consistency.
 *
 * On-disk layout (per slot, 1MB default):
 *   [slot_hdr 512B] [entry0 512B] [entry1 512B] ... [entryN 512B]
 *   Circular buffer: head advances on write, tail on checkpoint.
 *   Entries wrap around from end to start.
 *
 * Transaction model:
 *   txn_begin -> txn_log_write/txn_log_revoke (buffered) -> txn_commit (write)
 *   On commit: all entries written, COMMIT entry appended. Device flush
 *   is deferred to mxfs_journal_flush() for batching (called from
 *   sync_fs, fsync, checkpoint, unmount).
 *   On abort: buffered entries discarded, nothing written.
 *
 * Recovery (two-pass):
 *   Pass 1: scan from tail to head, collect revoke set + committed txn IDs
 *   Pass 2: replay committed METADATA entries, skip revoked offsets
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_JOURNAL_H
#define MXFS_LIBMXFS_JOURNAL_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"

/* ─── Constants ─── */

#define MXFS_JOURNAL_MAGIC              0x4D584A4C  /* "MXJL" */
#define MXFS_JOURNAL_VERSION            1
#define MXFS_JE_MAGIC                   0x4D584A45  /* "MXJE" */

/* Journal entry types */
#define MXFS_JE_METADATA                1
#define MXFS_JE_REVOKE                  2
#define MXFS_JE_COMMIT                  3
#define MXFS_JE_CHECKPOINT              4
#define MXFS_JE_UNMOUNT                 5

/* Slot flags */
#define MXFS_JSLOT_FLAG_CLEAN           0x00
#define MXFS_JSLOT_FLAG_DIRTY           0x01

/* Default slot size: 2048 sectors = 1MB per slot */
#define MXFS_JOURNAL_SLOT_SIZE_SECTORS  2048

/* Sector size for journal I/O */
#define MXFS_JOURNAL_SECTOR_SIZE        512

/* ─── On-disk structures (all 512 bytes, native byte order) ─── */

/*
 * Journal superblock — first sector of the journal region.
 * Written once by format, read on open.
 */
struct mxfs_journal_super {
    uint32_t        magic;              /* MXFS_JOURNAL_MAGIC */
    uint32_t        version;            /* MXFS_JOURNAL_VERSION */
    uint32_t        slot_count;         /* number of journal slots */
    uint32_t        slot_size_sectors;  /* sectors per slot */
    uint32_t        sector_size;        /* bytes per sector (512) */
    uint32_t        crc;                /* CRC32C of this sector */
    uint8_t         fs_uuid[16];        /* filesystem UUID */
    uint8_t         reserved[472];
};

/*
 * Per-slot header — first sector of each slot.
 * Updated on commit, checkpoint, clean/dirty transitions.
 */
struct mxfs_journal_slot_hdr {
    uint32_t        magic;              /* MXFS_JOURNAL_MAGIC */
    uint32_t        flags;              /* CLEAN/DIRTY */
    uint32_t        owner;              /* node_id that owns this slot */
    uint32_t        head_sector;        /* next write position (relative) */
    uint32_t        tail_sector;        /* oldest valid entry (relative) */
    uint32_t        crc;                /* CRC32C of this sector */
    uint64_t        seq_head;           /* sequence of next write */
    uint64_t        seq_tail;           /* sequence of oldest entry */
    uint8_t         reserved[472];
};

/*
 * Journal entry header — 40 bytes at the start of each 512-byte entry.
 * Followed by payload_len bytes of data (for METADATA entries),
 * padded to fill the 512-byte sector.
 *
 * For entries larger than 512 - 40 = 472 bytes payload, the entry
 * spans multiple consecutive sectors. total_len gives the full
 * on-disk size including header and padding.
 */
struct mxfs_journal_entry_hdr {
    uint32_t        magic;              /* MXFS_JE_MAGIC */
    uint32_t        type;               /* METADATA, REVOKE, COMMIT, etc */
    uint64_t        seq;                /* monotonic sequence number */
    uint64_t        txn_id;             /* transaction ID */
    uint32_t        total_len;          /* total on-disk bytes (header + payload + pad) */
    uint32_t        payload_len;        /* actual payload bytes */
    uint32_t        crc;                /* CRC32C of entire entry */
    uint32_t        pad;
};

/* Payload for METADATA entries: disk_offset + data */
struct mxfs_journal_metadata_payload {
    uint64_t        disk_offset;        /* where to write on replay */
    uint32_t        data_len;           /* bytes of data following */
    uint32_t        pad;
    /* data follows immediately */
};

/* Payload for REVOKE entries: disk_offset + len */
struct mxfs_journal_revoke_payload {
    uint64_t        disk_offset;        /* revoked range start */
    uint32_t        len;                /* revoked range length */
    uint32_t        pad;
};

/* ─── In-memory slot state (from original code) ─── */

enum mxfs_journal_state {
    MXFS_JSLOT_FREE = 0,
    MXFS_JSLOT_CLAIMED,
    MXFS_JSLOT_ACTIVE,
    MXFS_JSLOT_NEEDS_RECOVERY,
    MXFS_JSLOT_RECOVERING,
    MXFS_JSLOT_RECOVERED,
};

struct mxfs_journal_slot {
    mxfs_node_id_t          node_id;
    enum mxfs_journal_state state;
    uint64_t                claimed_at;
};

/* ─── Transaction structures ─── */

struct mxfs_txn_entry {
    uint32_t                type;       /* MXFS_JE_METADATA or MXFS_JE_REVOKE */
    uint32_t                data_len;
    uint64_t                disk_offset;
    void                    *data;      /* alloc'd copy for METADATA */
    struct mxfs_txn_entry   *next;
};

struct mxfs_txn {
    uint64_t                txn_id;
    struct mxfs_txn_entry   *entries;
    struct mxfs_txn_entry   *tail;
    int                     count;
};

/* ─── Journal context ─── */

struct mxfs_journal_ctx {
    /* Slot coordination (original) */
    struct mxfs_journal_slot slots[MXFS_MAX_NODES];
    int                     local_slot;
    mxfs_node_id_t          local_node;
    mxfs_mutex_t            *lock;

    /* On-disk journal state */
    mxfs_bdev_t             *dev;       /* raw device for journal sector I/O */
    mxfs_bdev_t             *xfs_dev;   /* offset device for XFS data replay */
    uint64_t                journal_offset;     /* byte offset of journal super on device */
    struct mxfs_journal_super super_disk;       /* cached journal superblock */
    uint64_t                slot_base;          /* byte offset of our slot's first sector */
    uint32_t                slot_size_sectors;  /* sectors in our slot */

    /* Circular buffer write state */
    uint32_t                head;               /* next write sector (relative to slot) */
    uint32_t                tail;               /* oldest valid sector (relative to slot) */
    uint64_t                next_seq;           /* next sequence number */
    uint64_t                next_txn_id;        /* next transaction ID */

    /* Scratch buffer for I/O */
    void                    *write_buf;
    uint32_t                write_buf_size;

    /* Set by slot_open if the slot was dirty (unclean shutdown) */
    bool                    slot_dirty;

    /* Batched commit support: counts committed-but-unflushed txns.
     * txn_commit writes entries + COMMIT to the journal buffer but
     * skips the device flush. The flush happens periodically (via
     * mxfs_journal_flush), on sync/fsync, on unmount, or on
     * checkpoint. This eliminates per-txn flush overhead (~50ms
     * on iSCSI) for metadata-heavy workloads. */
    uint32_t                unflushed_commits;

    /* I/O stats */
    uint64_t                stat_commits;
    uint64_t                stat_flush_count;
};

/* ─── Lifecycle ─── */

struct mxfs_journal_ctx *mxfs_journal_create(mxfs_node_id_t local_node);
void mxfs_journal_destroy(struct mxfs_journal_ctx *ctx);

/* ─── Slot management ─── */

int  mxfs_journal_claim_slot(struct mxfs_journal_ctx *ctx);
void mxfs_journal_release_slot(struct mxfs_journal_ctx *ctx);

/* ─── Recovery coordination ─── */

int  mxfs_journal_mark_needs_recovery(struct mxfs_journal_ctx *ctx,
                                       mxfs_node_id_t node_id);
int  mxfs_journal_begin_recovery(struct mxfs_journal_ctx *ctx, int slot);
int  mxfs_journal_finish_recovery(struct mxfs_journal_ctx *ctx, int slot);

/* ─── Query ─── */

enum mxfs_journal_state mxfs_journal_get_state(struct mxfs_journal_ctx *ctx,
                                                mxfs_node_id_t node_id);
int  mxfs_journal_slot_count(struct mxfs_journal_ctx *ctx);

/*
 * Find the journal slot owned by a given node.
 * Returns the slot index (>= 0) on success, -ENOENT if not found.
 */
int  mxfs_journal_find_slot_by_node(struct mxfs_journal_ctx *ctx,
                                     mxfs_node_id_t node_id);

/* ─── On-disk journal operations ─── */

/* Format a fresh journal region on device */
int  mxfs_journal_format(mxfs_bdev_t *dev, uint64_t offset,
                          uint32_t slot_count, const uint8_t *uuid);

/* Open and validate an existing journal */
int  mxfs_journal_open(struct mxfs_journal_ctx *ctx, mxfs_bdev_t *dev,
                        uint64_t offset);

/* Open a specific slot for this node's use */
int  mxfs_journal_slot_open(struct mxfs_journal_ctx *ctx, int slot);

/* Mark slot dirty/clean on disk */
int  mxfs_journal_slot_mark_dirty(struct mxfs_journal_ctx *ctx);
int  mxfs_journal_slot_mark_clean(struct mxfs_journal_ctx *ctx);

/* ─── Transaction API ─── */

struct mxfs_txn *mxfs_journal_txn_begin(struct mxfs_journal_ctx *ctx);

int  mxfs_journal_txn_log_write(struct mxfs_journal_ctx *ctx,
                                 struct mxfs_txn *txn,
                                 uint64_t disk_offset,
                                 const void *data, uint32_t len);

int  mxfs_journal_txn_log_revoke(struct mxfs_journal_ctx *ctx,
                                  struct mxfs_txn *txn,
                                  uint64_t disk_offset, uint32_t len);

int  mxfs_journal_txn_commit(struct mxfs_journal_ctx *ctx,
                              struct mxfs_txn *txn);

void mxfs_journal_txn_abort(struct mxfs_journal_ctx *ctx,
                             struct mxfs_txn *txn);

/* ─── Recovery ─── */

/* Two-pass replay of a slot's journal */
int  mxfs_journal_replay(struct mxfs_journal_ctx *ctx, int slot);

/* ─── Maintenance ─── */

/*
 * Flush unflushed journal commits to stable storage.
 * Issues a device flush and updates the slot header on disk.
 * Called from sync_fs, fsync, checkpoint, and unmount.
 * No-op if there are no unflushed commits.
 */
int  mxfs_journal_flush(struct mxfs_journal_ctx *ctx);

/* Advance tail past committed entries */
int  mxfs_journal_checkpoint(struct mxfs_journal_ctx *ctx);

/* Write clean unmount marker */
int  mxfs_journal_write_unmount(struct mxfs_journal_ctx *ctx);

#endif /* MXFS_LIBMXFS_JOURNAL_H */
