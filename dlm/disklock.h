/*
 * MXFS — Multinode XFS
 * Portable on-disk lock state persistence
 *
 * Persists lock state and node heartbeats to a reserved region on the
 * shared block device. Uses PAL bdev_read/bdev_write for sector-aligned
 * atomic I/O visible to all nodes.
 *
 * Region layout (relative to disklock_offset):
 *   Offset 0 .. 32767:      heartbeat records (64 slots x 512 bytes)
 *   Offset 32768 .. end:     lock records (65536 slots x 512 bytes)
 *
 * Ported from kernel/mxfs_disklock.{c,h} — kernel file I/O replaced
 * with PAL block device I/O, delayed_work replaced with PAL thread.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_DISKLOCK_H
#define MXFS_LIBMXFS_DISKLOCK_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"

#define MXFS_DISKLOCK_RECORD_SIZE       512
#define MXFS_DISKLOCK_MAX_SLOTS         65536
#define MXFS_DISKLOCK_HB_SLOTS          64
#define MXFS_DISKLOCK_MAGIC             0x4D584C4B  /* "MXLK" */

#define MXFS_DISKLOCK_FLAG_ACTIVE       1
#define MXFS_DISKLOCK_FLAG_EMPTY        0
/*
 * sess9 (ccloop c7ee71c6) D2: voluntary death stamp.  A force-shutdown FS
 * writes this into its own heartbeat record (magic/node_id/epoch kept) so
 * peers detect the death on their next monitor scan (~2-4 s) instead of
 * after the 31-sample stale window (62 s).  Peers then run the same
 * fence → elected-slice-replay → purge pipeline as for a crashed node —
 * the withdrawn node's grants stay frozen until its journal slice has
 * been replayed (see mxfs_disklock_recovered_cb).
 */
#define MXFS_DISKLOCK_FLAG_WITHDRAWN    2

/* Offset where lock records begin (after heartbeat region) */
#define MXFS_DISKLOCK_HB_SIZE           (MXFS_DISKLOCK_HB_SLOTS * \
                                         MXFS_DISKLOCK_RECORD_SIZE)

/* Total region size: heartbeat region + lock region */
#define MXFS_DISKLOCK_REGION_SIZE       (MXFS_DISKLOCK_HB_SIZE + \
                                         (uint64_t)MXFS_DISKLOCK_MAX_SLOTS * \
                                         MXFS_DISKLOCK_RECORD_SIZE)

#define MXFS_DISKLOCK_HB_INTERVAL_MS    2000
#define MXFS_DISKLOCK_LIVE_THRESHOLD    2
#define MXFS_DISKLOCK_DEAD_THRESHOLD    31

/*
 * On-disk lock record — exactly 512 bytes, one sector.
 */
struct mxfs_disklock_record {
    uint32_t                magic;
    uint32_t                flags;
    struct mxfs_resource_id resource;
    mxfs_node_id_t          owner;
    uint8_t                 mode;
    uint8_t                 state;
    uint8_t                 pad[2];
    uint64_t                granted_at_ms;
    mxfs_epoch_t            epoch;
    uint8_t                 reserved[448];
};

/*
 * sess55: heartbeat-embedded inode-eviction ring.
 *
 * Roots the cache-coherency fix (notes/sess55_gemini_design.md): MXFS caches
 * in-core inodes at NL (no DLM grant), and the CAW poll only scans slots THIS
 * node holds, so a peer's free+reuse of an inode number never BASTs a passively
 * caching node → it serves a stale prior incarnation (wrong type/content).
 *
 * Each node publishes its most-recently-freed {ino, gen} in its OWN heartbeat
 * record (single-writer per HB slot → no CAW needed; the HB sector write is
 * already periodic).  Peers, which already scan the HB area for liveness, diff
 * head_seq vs their per-peer tail and invalidate any matching NL-cached inode.
 * Lives in the previously-reserved tail of the HB record, so it adds no on-disk
 * region and needs no mkfs format change (old nodes wrote zeros here → magic==0
 * → consumers skip; fully backward compatible).
 */
#define MXFS_EVICT_RING_MAGIC       0x4D584552  /* "MXER" */
/* net2 step 5: 28 → 25, freeing 48 B of the HB record for the MEPOCH
 * authority record (DLM_PLAN §7.C; decision record in DLM_IMPL_PLAN).
 * The ring is a non-authoritative hint ring; old 28-entry records read
 * by new code are capped by the count guard in disklock.c, and the
 * bytes where entries 25..27 lived are now mepoch+reserved — protected
 * by their own magic+crc so stale ring garbage is never misread. */
#define MXFS_EVICT_RING_ENTRIES     25

/*
 * sess80: entry TYPE, carried in the former `pad` field (wire size unchanged,
 * fully backward compatible — a pre-sess80 peer always wrote pad=0 which now
 * reads as INODE_FREE).
 *   INODE_FREE  — a peer freed inode `ino` (now at di_gen `gen`); consumer
 *                 flags any NL-cached in-core copy XFS_ISTALE_CAW so the next
 *                 lookup re-reads the (possibly reused) dinode.
 *   DIR_MODIFY  — a peer modified the directory `ino` (added/removed a dirent);
 *                 consumer bumps the in-core dir inode's i_dlm_dir_gen so the
 *                 next readdir FUA-re-reads stale-but-CLEAN cached dir DATA/LEAF
 *                 blocks (closes the NL-cache reader-staleness + the write-side
 *                 lost-update where a peer RMWs off a stale shared-dir block).
 *                 `gen` is unused for this type.
 */
#define MXFS_EVICT_TYPE_INODE_FREE  0
#define MXFS_EVICT_TYPE_DIR_MODIFY  1

struct mxfs_evict_entry {
    uint64_t                ino;        /* freed inode number / modified dir ino */
    uint32_t                gen;        /* di_gen after free (ABA / reuse detect) */
    uint32_t                type;       /* MXFS_EVICT_TYPE_* (was pad; 0=INODE_FREE) */
};                                      /* 16 bytes */

struct mxfs_evict_ring {
    uint32_t                magic;      /* MXFS_EVICT_RING_MAGIC when populated, else 0 */
    uint32_t                head_seq;   /* total entries ever published (wrap/gap detect) */
    uint16_t                count;      /* live entries in entry[] (<= MXFS_EVICT_RING_ENTRIES) */
    uint16_t                pad;
    struct mxfs_evict_entry entry[MXFS_EVICT_RING_ENTRIES];
};                                      /* hdr 16 (4B align pad before entry[])
                                         * + 28*16 = 464 bytes */

/*
 * net2 step 5 (§7.C): the committed MEPOCH authority record, embedded in
 * each node's OWN heartbeat record (single-writer sector, atomic at
 * 512 B).  Every node republishes the latest COMMITTED record each
 * heartbeat; a voter stages a PREPARED candidate here (flags) before
 * ACKing so a proposer crash cannot fork the epoch.  Fields are LE on
 * disk; magic+crc make old-format bytes (ex-evict entries) unreadable
 * as a record.  All u64s naturally aligned; packed only to pin
 * sizeof==44.
 */
#define MXFS_MEPOCH_MAGIC       0x4F50454D  /* "MEPO" LE */
#define MXFS_MEPOCH_F_PREPARED  0x0001      /* staged candidate, not committed */
#define MXFS_MEPOCH_F_VOTERS5   0x0002      /* 5-voter regime (|members| >= 16) */

struct mxfs_mepoch_rec {
    uint64_t epoch;
    uint64_t member_mask;
    uint64_t fenced_mask;
    uint32_t magic;
    uint32_t self_incarnation;      /* §5 persisted incarnation lives here */
    uint16_t voter_slots[3];        /* voters that committed this epoch */
    uint16_t flags;                 /* MXFS_MEPOCH_F_* */
    uint32_t crc32c;                /* pal crc32c over bytes 0..39 */
} __attribute__((packed));

/*
 * On-disk heartbeat record — exactly 512 bytes, one sector.
 */
struct mxfs_disklock_heartbeat {
    uint32_t                magic;
    uint32_t                flags;
    mxfs_node_id_t          node_id;
    uint32_t                fs_gen;         /* sess131: folded volume_id of the
                                             * mkfs generation this record
                                             * belongs to; 0 = legacy/unset.
                                             * Records whose fs_gen differs
                                             * from ours are pre-mkfs ghosts —
                                             * ignored and reclaimable. */
    uint64_t                timestamp_ms;
    mxfs_epoch_t            epoch;
    uint64_t                lock_count;
    struct mxfs_evict_ring  evict;          /* sess55; net2 step 5: 416B (25 entries) */
    struct mxfs_mepoch_rec  mepoch;         /* net2 step 5: 44B, §7.C authority */
    uint8_t                 reserved[12];   /* 40(hdr) + 416 + 44 + 12 = 512 */
};

#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_HB() \
    BUILD_BUG_ON(sizeof(struct mxfs_disklock_heartbeat) != \
                 MXFS_DISKLOCK_RECORD_SIZE)
#else
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == MXFS_DISKLOCK_RECORD_SIZE,
               "mxfs_disklock_heartbeat must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_evict_ring) == 416,
               "mxfs_evict_ring must be 25 entries (net2 step 5 carve)");
_Static_assert(sizeof(struct mxfs_mepoch_rec) == 44,
               "mxfs_mepoch_rec is 44 bytes on disk (§7.C)");
#endif

struct mxfs_disklock_node_track {
    uint64_t        last_timestamp;
    mxfs_epoch_t    last_epoch;
    int             changed_samples;
    int             equal_samples;
    bool            live;
    uint32_t        last_evict_seq;   /* sess55: highest evict head_seq consumed from this peer */
    bool            evict_seen;       /* sess55: last_evict_seq has been initialised */
};

typedef void (*mxfs_disklock_expire_cb)(void *data, mxfs_node_id_t dead_node);

/*
 * sess9 (ccloop c7ee71c6) D2: recovery-complete callback.  Fired by the
 * monitor when a slot previously marked recovery-pending (fire_dead ran;
 * purge was DEFERRED) reads as reclaimed on disk — i.e. the elected
 * replayer zeroed it AFTER replaying the dead node's log slice (see
 * mxfs_v5_dlm_recovery_complete), or the dead node itself remounted (its
 * own mount-time recovery replayed the slice; epoch differs).  The body
 * performs the LOCAL half of the old expire-time purge (DLM grant
 * tables, membership refresh).  Deferring that purge is what keeps peers
 * off the dead node's resources until its journal is replayed — the
 * PROVEN drc@16 r13 tear (ifree destaged, dirent-remove abandoned) was
 * consumed by peers precisely because grants flowed before replay.
 */
typedef void (*mxfs_disklock_recovered_cb)(void *data, int slot,
                                           mxfs_node_id_t dead_node);

/*
 * sess131: self-fence callback.  Fired (once) by the heartbeat thread when it
 * detects that the device's MXFS superblock no longer matches the volume this
 * mount belongs to — i.e. the device was re-mkfs'd under a live mount.  The
 * body (v5_mount → XFS glue) must force-shutdown the filesystem; the heartbeat
 * thread stops writing immediately so the new cluster generation is not
 * polluted by ghost heartbeats.
 */
typedef void (*mxfs_disklock_fence_cb)(void *data);

/*
 * sess55: per-freed-inode eviction callback.  The disklock HB consumer reads a
 * peer's evict ring and invokes this for each {ino, gen} the peer freed since we
 * last scanned.  The body (in the XFS layer) does the radix lookup +
 * XFS_ISTALE_CAW + background eviction — disklock.c never touches XFS directly.
 */
typedef void (*mxfs_disklock_evict_cb)(void *data, uint64_t ino, uint32_t gen,
                                       uint32_t type);

/* Disk lock subsystem context */
struct mxfs_disklock_ctx {
    mxfs_bdev_t             *dev;
    uint64_t                base_offset;    /* byte offset on device */
    mxfs_node_id_t          local_node;
    int                     local_slot;     /* unique HB slot 0-63, -1 if unclaimed */
    mxfs_thread_t           *hb_thread;
    mxfs_mutex_t            *lock;
    volatile bool           running;

    /* Shutdown signaling: condvar wakes sleeping heartbeat thread */
    mxfs_mutex_t            *shutdown_lock;
    mxfs_cond_t             *shutdown_cond;
    mxfs_epoch_t            epoch;
    uint64_t                lock_count;

    struct mxfs_disklock_node_track  node_track[MXFS_DISKLOCK_HB_SLOTS];
    bool                             monitored[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_node_id_t                   slot_node_id[MXFS_DISKLOCK_HB_SLOTS];

    /* v0.5.0: dead-declaration threshold in stale HB samples.  Defaults
     * to MXFS_DISKLOCK_DEAD_THRESHOLD (62 s at 2 s/sample); overridden
     * via mxfs_disklock_set_dead_timeout_ms (lease_timeout_ms param). */
    uint32_t                         dead_threshold;
    mxfs_disklock_expire_cb          expire_cb;
    void                             *expire_cb_data;

    /*
     * sess9 (ccloop c7ee71c6) D2: per-slot recovery-pending state.  Set
     * (under ctx->lock) by mxfs_disklock_mark_recovery_pending when the
     * v5 expire path defers the purge behind the dead node's slice
     * replay; cleared by the monitor when the slot reads reclaimed
     * (recovered_cb fires) or by the elected replayer via
     * mxfs_disklock_clear_recovery_pending just before it zeroes the
     * slot itself.  pending_node/pending_epoch pin the exact incarnation
     * we are waiting out, so a rejoin (same node, new epoch) also reads
     * as resolved.
     */
    bool                             recovery_pending[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_node_id_t                   pending_node[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_epoch_t                     pending_epoch[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_disklock_recovered_cb       recovered_cb;
    void                             *recovered_cb_data;

    /*
     * sess131 generation identity.  fs_gen is a nonzero 32-bit fold of the
     * volume_id (FNV-1a of the XFS sb_uuid); written into every heartbeat
     * record this node emits.  Heartbeat records with a different fs_gen are
     * pre-mkfs ghosts: skipped by the monitor and reclaimable by claim_slot.
     * fs_uuid is the raw 16-byte uuid, compared each heartbeat cycle against
     * the on-disk MXFS super to detect re-mkfs under a live mount
     * (→ fence_cb + stop heartbeating).  have_fs_identity gates all of this
     * so user-mode tools that never set it keep legacy behavior.
     */
    uint32_t                         fs_gen;
    uint8_t                          fs_uuid[16];
    bool                             have_fs_identity;
    bool                             fenced;
    mxfs_disklock_fence_cb           fence_cb;
    void                             *fence_cb_data;

    /*
     * sess55: inode-eviction ring.  Producer side stages locally-freed
     * {ino, gen} here; disklock_hb_fn serialises evict_stage into the
     * outgoing heartbeat's evict ring on each write.  evict_head_seq is
     * the monotonically increasing total ever published (peers diff it
     * against their per-peer last_evict_seq to detect new/wrapped entries).
     * Guarded by evict_lock.  evict_cb is invoked by the consumer for each
     * peer-freed inode (set by the XFS layer; see mxfs_disklock_evict_cb).
     */
    struct mxfs_evict_entry          evict_stage[MXFS_EVICT_RING_ENTRIES];
    uint32_t                         evict_head_seq;
    uint16_t                         evict_count;
    mxfs_mutex_t                     *evict_lock;
    mxfs_disklock_evict_cb           evict_cb;
    void                             *evict_cb_data;
};

/* Lifecycle */
struct mxfs_disklock_ctx *mxfs_disklock_create(mxfs_bdev_t *dev,
                                                uint64_t disklock_offset,
                                                mxfs_node_id_t local_node);
void mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx);

/* Heartbeat */
int  mxfs_disklock_start_heartbeat(struct mxfs_disklock_ctx *ctx);
void mxfs_disklock_stop_heartbeat(struct mxfs_disklock_ctx *ctx);

/* v0.11.76 (D3): clear our heartbeat record's ACTIVE flag on CLEAN
 * teardown (FUA).  Without this every past tenure stays ACTIVE on the
 * platter forever: later mounts count the ghost as an active foreign
 * slot (15s settle-gate tax) and the auto-monitor keeps re-evicting it.
 * Call AFTER stop_heartbeat; not on withdraw (peers must still detect
 * the death and recover the slice). */
int  mxfs_disklock_release_slot(struct mxfs_disklock_ctx *ctx);

/* Lock record operations */
int  mxfs_disklock_write_grant(struct mxfs_disklock_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner,
                                uint8_t mode, mxfs_epoch_t epoch);

int  mxfs_disklock_clear_grant(struct mxfs_disklock_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                mxfs_node_id_t owner);

/* Purge all records owned by a dead node */
int  mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx,
                               mxfs_node_id_t node_id);

/* Read all active lock records (for recovery) */
int  mxfs_disklock_read_all(struct mxfs_disklock_ctx *ctx,
                             struct mxfs_disklock_record *records,
                             int max, int *count);

void mxfs_disklock_set_expire_cb(struct mxfs_disklock_ctx *ctx,
                                  mxfs_disklock_expire_cb cb, void *data);

/* sess9 (ccloop c7ee71c6) D2 — withdraw + deferred-purge recovery API */
void mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx);
void mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx,
                                    mxfs_disklock_recovered_cb cb, void *data);
void mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx,
                                         int slot, mxfs_node_id_t node);
bool mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot);
void mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx,
                                          int slot);
mxfs_node_id_t mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx,
                                          int slot);
/* Iterate pending slots: first call prev=-1; returns next pending slot
 * (> prev) with *node filled, or -1 when exhausted. */
int mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx,
                                        int prev, mxfs_node_id_t *node);

/*
 * sess131 generation identity.  set_fs_identity must be called after create
 * and BEFORE claim_slot/start_heartbeat so the claim record carries fs_gen
 * and foreign-generation records are filtered from the very first scan.
 * fs_uuid is the 16-byte XFS sb_uuid of the mounted volume.
 */
void mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx,
                                   const uint8_t *fs_uuid);
void mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx,
                                mxfs_disklock_fence_cb cb, void *data);

/*
 * sess55: inode-eviction ring API.
 *   note_freed  — producer: record that this node freed `ino` (now at di_gen
 *                 `gen`).  Non-blocking; staged for the next heartbeat write.
 *   set_evict_cb — register the XFS-layer consumer callback (invoked once per
 *                  peer-freed inode the HB consumer observes).
 */
void mxfs_disklock_note_freed(struct mxfs_disklock_ctx *ctx,
                              uint64_t ino, uint32_t gen, uint32_t type);
void mxfs_disklock_set_evict_cb(struct mxfs_disklock_ctx *ctx,
                                mxfs_disklock_evict_cb cb, void *data);
void mxfs_disklock_monitor_node(struct mxfs_disklock_ctx *ctx,
                                 mxfs_node_id_t node_id);
void mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx,
                                   mxfs_node_id_t node_id);

/* Unique heartbeat slot claiming (Bug 101 fix) */
int  mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx);
int  mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx);
int  mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx,
                                    mxfs_node_id_t node_id);
/* sess67 ASYMMETRIC MDS: resolve slot (0-63) -> occupying node_id (0 if empty) */
mxfs_node_id_t mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx,
                                              int slot);
/* ccloop 72513a13 sess2: is the node occupying heartbeat slot `slot`
 * provably alive (our own slot, or monitored with a current heartbeat)?
 * Advisory cross-thread read of the hb thread's tracker — a stale-by-one-
 * sample answer is fine for its only caller (the CAW wait-timeout
 * liveness extension, which re-asks every poll round). */
bool mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot);
/* v0.5.0 foreign-slice replay election: lowest live slot among survivors
 * (includes local_slot), excluding skip_slot.  -1 if none. */
int  mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx,
                                    int skip_slot);
/* v0.5.0: override the dead-declaration window (ms → HB samples, min 2).
 * 0 restores the compile-time default. */
void mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx,
                                       uint32_t timeout_ms);

/*
 * Scan all heartbeat slots; return a 64-bit mask of slots whose ACTIVE
 * heartbeat is older than threshold_ms (i.e. previous-instance crashed
 * without releasing).  Caller passes their own slot in skip_slot to
 * exclude themselves.  Used at mount time to seed CAW dead-node purge.
 */
int  mxfs_disklock_get_stale_slot_mask(struct mxfs_disklock_ctx *ctx,
                                        uint64_t threshold_ms,
                                        int skip_slot,
                                        uint64_t *out_mask);

#endif /* MXFS_LIBMXFS_DISKLOCK_H */
