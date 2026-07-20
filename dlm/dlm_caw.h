/*
 * MXFS — Multinode XFS
 * Compare-and-Write (CAW) based DLM — data structures and API
 *
 * Replaces the TCP-based distributed lock manager with a disk-based
 * implementation using SCSI Compare-and-Write (CAW) for atomic lock
 * state transitions on the shared block device. Eliminates all TCP
 * peer-to-peer connections for lock coordination.
 *
 * On-disk layout: lock slots live in the disklock region, starting
 * at base_offset + 32KB (after the heartbeat area). Each slot is
 * exactly 512 bytes (one sector) for atomic CAW operations.
 *
 * BAST notifications use UDP multicast to hint that a lock holder
 * should check disk for conflicting waiters. The BAST poll thread
 * periodically scans held lock slots as a fallback.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_DLM_CAW_H
#define MXFS_LIBMXFS_DLM_CAW_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"
#include "../include/mxfs/mxfs_ports.h"

/* ─── Constants ─── */

#define MXFS_CAW_MAGIC              0x4D584357  /* "MXCW" — live slot */
#define MXFS_CAW_TOMBSTONE_MAGIC    0x4D58444C  /* "MXDL" — deleted; skip-but-continue probing */
#define MXFS_CAW_VERSION            1
#define MXFS_CAW_SLOT_SIZE          512
#define MXFS_CAW_MAX_SLOTS          65536
/*
 * Default cap on locally-tracked held locks.  Used when the caller
 * passes max_held=0 to mxfs_dlm_caw_create (legacy/test paths that
 * don't have access to the dynamic per-mount cap derived from
 * mxfs_cache_caps.dlm_lock).
 *
 * Sess33 (sibling project mxfs.1 sess74): per-inode lock caching is
 * an architectural invariant — each cached inode = one held DLM lock.
 * Real workloads exceed 4096 trivially (element-web rsync alone uses
 * ~5400 inodes).  When the cap is hit, "disk lock table full" floods
 * dmesg and perf collapses.  v5 default bumped to 32768; well below
 * on-disk MAX_SLOTS=65536.  Memory cost per ctx ≈ max_held × 44 bytes
 * (slots[] + mem_locks[]).
 */
#define MXFS_CAW_MAX_HELD           32768   /* default; max_held param overrides */
#define MXFS_CAW_MAX_RETRIES        100     /* max CAW retry attempts.  v0.3.79 attempted 500; made things worse (avg 3.7 vs 7.8) — likely longer retries widen window for OTHER races. */
#define MXFS_CAW_UNLOCK_DEADLINE_MS 5000    /* sess3(ccloop 26c41354): when caw_unlock_backoff=1, an INODE unlock CAS miscompare is always transient (concurrent slot mutation), so retry until this wall-clock deadline instead of -EIO at 100 tight retries.  Giving up leaves the lock STUCK -> BAST re-fires -> mxfs-ino-bast kworker storm (dir_reuse@16: load 870).  Unlike acquire, retrying longer is SAFE (we still hold the lock, just release later; no double-grant window). */
#define MXFS_CAW_IO_MAX_RETRIES     5       /* max retries for transient I/O errors */
#define MXFS_CAW_IO_BACKOFF_MS      10      /* initial backoff for I/O retry (ms) */
#define MXFS_CAW_IO_BACKOFF_MAX_MS  200     /* max backoff for I/O retry (ms) */
#define MXFS_CAW_POLL_INITIAL_MS    1       /* initial poll interval */
#define MXFS_CAW_POLL_MAX_MS        25      /* max poll interval */
/*
 * v0.10.36 inode-acquire fresh-handoff window: poll at 2 ms (no exponential
 * backoff) for the first 64 ms of an inode wait.  A BAST-driven cross-node
 * handoff completes in ~10-25 ms (UDP BAST + holder dwork + slot CAS); the
 * 1,2,4,8,16,25 backoff parked the waiter up to 25 ms AFTER the slot was
 * already free — measured 42-46 ms/unlink in the 32-node dir_reuse rm storm
 * where holder-side work was only ~10-17 ms.  One waiter at 2 ms is ≤32
 * extra slot reads over the window — negligible; long convoy waits back off
 * exactly as before once past the window.
 */
#define MXFS_CAW_INODE_FASTPOLL_MS  64
#define MXFS_CAW_INODE_FASTPOLL_INTERVAL_MS 2
#define MXFS_CAW_BAST_POLL_MS       200     /* BAST poll thread interval (no contention) */
/*
 * BAST poll interval under contention.  v5 sess33 (mxfs.1 sess74
 * finding ported): was 5 ms.  At 256 slots polled per cycle, 5 ms =
 * 51K reads/sec which storms the disk queue at scale (16+ nodes
 * contending on a shared LUN).  100 ms still gives sub-second BAST
 * detection while leaving disk bandwidth for actual work.  UDP
 * multicast BAST is the primary fast path; disk polling is just a
 * backup for dropped packets.
 */
#define MXFS_CAW_BAST_POLL_FAST_MS  100     /* BAST poll interval under contention */
/*
 * v0.5.3 (ccloop 14d31183 scaling_curve): idle BAST poll interval when
 * the UDP BAST path is operational.  The 200 ms idle poll at 256 slots
 * per cycle is 1280 single-sector FUA reads/sec PER NODE against the
 * shared LUN — measured as the dominant slice of the ~9.7K READ_16s a
 * 2-node rsync issues (vs ~0 truly-single-node).  Since waiters now
 * RE-SEND the UDP BAST hint every MXFS_CAW_BAST_RESEND_MS while
 * blocked (caw_wait_for_grant), a lost packet no longer needs the
 * disk poll for recovery — the next resend (100 ms) covers it.  The
 * disk poll remains the only path when the UDP socket failed to set
 * up, so the relaxed interval applies ONLY when bast_mcast_sock is
 * live; any observed contention immediately drops the interval back
 * to MXFS_CAW_BAST_POLL_FAST_MS.
 */
#define MXFS_CAW_BAST_POLL_RELAX_MS 4000    /* idle poll when UDP BAST path is up.
       ccloop 72513a13 sess3: 1000 -> 4000.  Waiters re-send UDP hints every
       100ms while blocked, so the disk poll is packet-loss insurance only;
       at 1000ms it was the #1 idle+rm-phase read source (256-slot sweep/s
       per node = ~50-240 FUA reads/s each, ~13k reads per dir_reuse round
       at 8 nodes, kprobe-counted). */
#define MXFS_CAW_BAST_RESEND_MS     100     /* waiter UDP BAST re-send while blocked */
#define MXFS_CAW_BAST_RESEND_FAST_MS 25     /* sess8 (ccloop 72513a13): first
       resends go FAST.  cc@32 hop anatomy: PR-holder demotes staggered across
       100-378ms inter-tenure gaps — lost-hint recovery is quantized by the
       resend cadence (holder disk poll is 4000ms with UDP up).  A flat 25ms
       cadence regressed cc@32 60->91s: every hint fires bast_cb on all
       receivers (no dedup), and ~31 waiters x 40/s melted the cluster in
       callback processing.  Burst only the first FAST_COUNT resends of a wait
       (the initial-loss window that gates the handoff), then steady 100ms. */
#define MXFS_CAW_BAST_RESEND_FAST_COUNT 4
#define MXFS_CAW_WAIT_TIMEOUT_MS    120000  /* 120s lock wait timeout */
/* ccloop 72513a13 sess2: hard ceiling for the liveness-extended wait.  The
 * base timeout's job is DEAD-holder detection, but dead holders are already
 * detected+purged by disklock lease expiry (their slot bits get cleared and
 * the waiter promotes).  A LIVE holder that is merely slow (32-node fio
 * saturation: dio-completion convoys hold AG/inode locks for minutes) must
 * not turn into -ETIMEDOUT -> userspace error -> ilock_begin force-shutdown
 * cascade (18:1x fio_perf: test28 create err=-110 while 10+ nodes logged
 * 30s+ hung tasks; 0.11.8 board: one wedged holder -> 31 peer shutdowns).
 * While EVERY blocking holder is provably heartbeating the waiter keeps
 * waiting — but only up to this cap, so a live-but-wedged holder (P113
 * family) still surfaces as a timeout instead of hanging forever. */
#define MXFS_CAW_WAIT_HARDCAP_MS    480000  /* 8 min liveness-extended ceiling */
#define MXFS_CAW_YIELD_TIMEOUT_MS   5000    /* 5s stale yield_to timeout */
#define MXFS_CAW_EX_STREAK_YIELD    3       /* v0.10.39: after this many
					     * consecutive EX-class grants,
					     * the fair-handoff releaser
					     * yields one turn to the whole
					     * shared (PR) waiter class */
#define MXFS_CAW_YIELD_BACKOFF_MS   3       /* base yield backoff (+ node jitter) */
#define MXFS_CAW_BAST_PORT          MXFS_PORT_CAW_BAST  /* UDP multicast BAST port */

/* ─── On-disk lock slot — exactly 512 bytes, one sector ─── */

struct mxfs_caw_lock_slot {
    uint32_t                magic;          /* MXFS_CAW_MAGIC */
    uint32_t                generation;     /* ABA prevention counter */
    struct mxfs_resource_id resource;       /* 32 bytes */
    uint64_t                holders_ex;     /* bitmap: nodes holding EX */
    uint64_t                holders_pw;     /* bitmap: nodes holding PW */
    uint64_t                holders_pr;     /* bitmap: nodes holding PR */
    uint64_t                holders_cw;     /* bitmap: nodes holding CW */
    uint64_t                holders_cr;     /* bitmap: nodes holding CR */
    uint64_t                waiters;        /* bitmap: nodes waiting (any mode) */
    uint8_t                 granted_mode;   /* highest mode currently held */
    uint8_t                 waiter_mode;    /* highest mode waiters need */
    uint16_t                pad;
    uint32_t                ex_grant_streak; /* v0.10.39 (was pad2): count of
                                             * consecutive EX/PW grants since
                                             * the last shared-class grant.
                                             * Maintained inside the grant
                                             * CAS; the fair-handoff release
                                             * chooser yields to the WHOLE
                                             * shared class once it reaches
                                             * MXFS_CAW_EX_STREAK_YIELD, so a
                                             * PR reader can never starve
                                             * behind an endless EX rotation
                                             * (proven: verify readdir PR
                                             * starved 240s -> rc=-110
                                             * shutdown while 31 creators
                                             * round-robined the dir EX). */
    uint64_t                last_modified_ms;
    uint64_t                yield_to;       /* bitmap: priority nodes for next acquire */
    uint64_t                yield_set_ms;   /* timestamp when yield_to was set */
    /*
     * sess50 (run14d): bitmap of nodes waiting for an EXCLUSIVE-class mode
     * (EX or PW).  Subset of `waiters`.  Needed because waiter_mode cannot be
     * downgraded from EX->PR otherwise: when the exclusive waiter leaves but
     * shared (PR) waiters remain, recompute_waiter_mode must know NO exclusive
     * waiter remains, else it leaves waiter_mode stuck at EX and
     * defer_for_waiter starves all fresh PR readers forever (16-node
     * posix_semantics wedge).
     */
    uint64_t                waiters_ex;
    /*
     * v0.6.0 (caw-multipath matrix): cross-node EX-handoff epoch — the CAW
     * analog of the TCP master's per-resource dir_epoch (sess64 design).
     * Bumped by the ACQUIRER, inside the same grant CAS, whenever it takes
     * an EX-class mode (EX/PW) and last_ex_slot names a DIFFERENT node.
     * Every grant (any mode) reports the observed value to the XFS layer,
     * which adopts the on-disk dir image when the epoch it stamped at its
     * last coherent load no longer matches (slot reclamation can RESTART
     * the counter, so the consumer must compare != rather than >).
     * last_ex_slot: node_slot of the most recent EX-class holder;
     * MXFS_CAW_EX_SLOT_NONE until the first EX grant on this slot.
     */
    uint32_t                dir_epoch;
    uint8_t                 last_ex_slot;
    uint8_t                 pad3[3];
    /*
     * ccloop(3e02e7dd) sess3: canonical dir logical-block0 record, WRITE-ONCE
     * per directory incarnation (di_gen).  Companion to dir_epoch but solves
     * a DIFFERENT problem: epoch says "something changed since my baseline"
     * (a relative, timing-sensitive comparison that a simultaneous first
     * acquirer can race past before any commit is visible); this says
     * "does a canonical block0 exist for this incarnation, full stop" (an
     * absolute existence check with no staleness window).  The first node to
     * materialize logical block0 for a shortform->block conversion publishes
     * {fsb,gen} here (mxfs_dlm_caw_set_dir_block0, CAS write-once: only sets
     * when unset or gen has advanced — first publisher wins, never
     * overwritten within the same gen).  Every later node about to convert
     * the SAME incarnation's shortform dir checks this (via the grant_meta
     * cache, populated on every grant CAS same as dir_epoch) immediately
     * before calling xfs_dir2_sf_to_block; if set, it must adopt the
     * canonical block instead of allocating a second one.  Durability of the
     * referenced block by the time a peer can observe it is guaranteed by
     * Invariant 1 (no DLM unlock without a successful drain, which flushes
     * dir data blocks before release) -- so the canonical fsb is always safe
     * to trust without an extra disk read.  See docs/canonical_block0_fix_plan.md.
     */
    uint64_t                dir_block0_fsb;
    uint32_t                dir_block0_gen;
    uint8_t                 reserved[364];  /* pad to 512 */
};

#define MXFS_CAW_EX_SLOT_NONE   0xFF

/* Compile-time size check */
#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_CAW_SLOT() \
    BUILD_BUG_ON(sizeof(struct mxfs_caw_lock_slot) != MXFS_CAW_SLOT_SIZE)
#else
_Static_assert(sizeof(struct mxfs_caw_lock_slot) == MXFS_CAW_SLOT_SIZE,
               "mxfs_caw_lock_slot must be exactly 512 bytes");
#endif

/* ─── BAST notification packet (UDP multicast) ─── */

#define MXFS_BAST_MAGIC             0x4D584242  /* "MXBB" */
/* ccloop 72513a13 sess3: grant/release nudge — same wire struct as the
 * BAST hint, distinguished by magic.  requested_mode carries 0. */
#define MXFS_GRANT_MAGIC            0x4D584247  /* "MXBG" */

struct mxfs_caw_bast_notify {
    uint32_t                magic;
    uint16_t                version;
    uint16_t                pad;
    struct mxfs_resource_id resource;       /* 32 bytes */
    mxfs_node_id_t          requester;
    uint8_t                 requested_mode;
    uint8_t                 pad2[3];
    uint8_t                 volume_uuid[16];
};

/* ─── Per-mount CAW DLM context ─── */

struct mxfs_dlm_caw_ctx {
    mxfs_bdev_t             *dev;
    uint64_t                base_offset;        /* disklock region base */
    uint64_t                lock_region_offset; /* base_offset + heartbeat area size */
    mxfs_node_id_t          local_node;
    uint8_t                 node_slot;          /* unique 0-63 from disklock */
    uint64_t                node_bit;           /* 1ULL << node_slot */

    /*
     * Local tracking of held lock slot indices (for BAST poll).
     *
     * v5 sess33: dynamic-allocated array sized by max_held (set at
     * create from mxfs_cache_caps.dlm_lock).  Replaces the legacy
     * compile-time-sized inline array which capped at 4096 — well
     * below real-workload demand.
     */
    struct {
        uint32_t            *slots;     /* size = ctx->max_held */
        int                 count;
        mxfs_mutex_t        *lock;
    } held;
    int                     max_held;   /* size of held.slots[] and mem_locks[] */

    /* BAST poll thread */
    mxfs_thread_t           *bast_poll_thread;
    mxfs_cond_t             *stop_cond;
    mxfs_mutex_t            *stop_lock;

    /* UDP multicast BAST */
    mxfs_sock_t             *bast_mcast_sock;
    mxfs_thread_t           *bast_recv_thread;

    /* ccloop 72513a13 sess3: GRANT NUDGE — the reverse of the BAST hint.
     * A releasing/handing-off node multicasts MXFS_GRANT_MAGIC when the
     * slot it just CAW'd had other waiter bits; blocked acquirers wake
     * from their poll sleep immediately instead of eating the up-to-25ms
     * poll backoff (kprobe-proven: 4.6s of a 6.0s 8-node create phase was
     * dd sleeping in acquire polls).  Best-effort: a lost packet just
     * means the old poll cadence.  nudge_seq is bumped under nudge_lock
     * on every received nudge; waiters snapshot it before their slot
     * read and cond_timedwait for a change (no lost-wakeup window). */
    mxfs_mutex_t            *nudge_lock;
    mxfs_cond_t             *nudge_cond;
    uint64_t                nudge_seq;

    /* Callbacks (same signatures as TCP DLM) */
    mxfs_dlm_bast_cb        bast_cb;
    void                    *cb_data;

    /* ccloop 72513a13 sess2: liveness oracle for the wait-timeout
     * extension (see MXFS_CAW_WAIT_HARDCAP_MS).  Returns true iff EVERY
     * slot set in slot_mask (bit i = heartbeat slot i) is provably
     * alive.  Wired by v5_mount over disklock; NULL = no extension
     * (base timeout behavior). */
    bool                    (*holders_alive_fn)(void *data,
                                                uint64_t slot_mask);
    void                    *holders_alive_data;

    volatile bool           running;
    uint8_t                 volume_uuid[16];

    /* Single-node bypass: when true, lock/unlock operate purely
     * in-memory (no disk I/O).  Cleared when a peer joins; the
     * transition handler flushes all held locks to disk. */
    bool                    single_node;

    /*
     * In-memory lock state for single-node fast path.  Tracks
     * (resource, mode) for each held lock so we can flush them to
     * disk on the single→multi transition.
     *
     * v5 sess33: dynamic-allocated, sized by ctx->max_held.
     */
    struct mxfs_caw_mem_lock {
        struct mxfs_resource_id resource;
        uint8_t                 mode;
    } *mem_locks;                       /* size = ctx->max_held */
    int                     mem_lock_count;
    mxfs_mutex_t            *mem_lock_mutex;

    /*
     * v0.5.3 slot-index hint cache (in-memory, direct-mapped).
     *
     * Every resource-keyed CAW operation (lock/unlock/held/convert/
     * read_generation) re-derives the resource's slot via an on-disk
     * hash-chain walk — one serialized single-sector FUA read per probe.
     * Measured (ccloop 14d31183, 2-node rsync): ~2.9K of 6.1K slot reads
     * were re-lookups of slots this node had ALREADY located.  The hint
     * maps resource -> last-known slot index; find_slot_skip validates a
     * hit BY CONTENT (read the hinted slot, require live magic + exact
     * resource match) before trusting it, so a stale hint costs one
     * wasted read and falls back to the full walk — correctness never
     * rests on hint freshness.
     */
    struct mxfs_caw_slot_hint {
        struct mxfs_resource_id resource;
        uint32_t                slot_idx;
        bool                    valid;
    } *slot_hints;                      /* MXFS_CAW_SLOTHINT_SIZE entries */
    mxfs_mutex_t            *slot_hint_lock;

    /*
     * v0.6.0: per-resource grant metadata observed at the moment of the
     * last grant CAS — the CAW analog of the TCP mirror's lk->dir_epoch /
     * handoff bit.  Direct-mapped by resource hash (same pattern as
     * slot_hints); a collision evicts the older entry, and a query miss
     * returns epoch=0/handoff=false, which only means "no adopt trigger
     * from this mechanism" (the eviction-ring path still covers).
     */
    struct mxfs_caw_grant_meta {
        struct mxfs_resource_id resource;
        uint32_t                dir_epoch;
        bool                    handoff;
        bool                    valid;
        /* ccloop(3e02e7dd) sess3: canonical dir block0, cached from the
         * same grant CAS read as dir_epoch above (see the slot field's
         * comment in struct mxfs_caw_lock_slot). */
        uint64_t                dir_block0_fsb;
        uint32_t                dir_block0_gen;
        /* v0.6.2 unlock-vs-regrant race closure (P106 phantom EX) */
        bool                    releasing;  /* our unlock CAS loop is live */
        uint64_t                grant_seq;  /* bumped on every meta store */
    } *grant_meta;                      /* MXFS_CAW_GRANTMETA_SIZE entries */
    mxfs_mutex_t            *grant_meta_lock;
    uint64_t                 grant_seq_counter; /* under grant_meta_lock */

    /*
     * interactive session 2026-07-13 (fence_during_write@8/caw
     * PR-starvation): wall-clock orphan-strand escape trackers, keyed by
     * RESOURCE (fnv1a hash) like grant_meta above, but held in a SEPARATE
     * table with its OWN spinlock (mxfs_pal_spinlock_*, not the mutex above)
     * because the reader/writer (mxfs_dlm_bast_process, xfs_mxfs_dlm.c) runs
     * with ip->i_dlm_lock (a real kernel spinlock) held and must not sleep —
     * sharing grant_meta's mutex would be scheduling-while-atomic.  RULE-4
     * PROVEN (P15-REL-ABORT init_seq instrumentation, ino=131/8caw): the
     * per-inode versions of these fields (xfs_inode.h
     * i_dlm_orphan_since_ns / i_dlm_bast_starve_since_ns) get silently reset
     * to 0 whenever the in-core VFS inode is evicted and reinstantiated —
     * the hot-dir create/unlink storm churns icache faster than the 3s
     * force-release threshold, so neither wall-clock escape nor the
     * same-gen strike counter (also per-inode) ever accumulates enough
     * CONTINUOUS observation to fire; P15H-PEER-STARVE-TIMEOUT measured 0
     * fires across thousands of aborts.  A resource-keyed table survives
     * both local re-acquire churn (a colliding SAME-resource claim in
     * caw_grant_seq_prebump preserves the grant_meta bucket's other fields
     * — this table follows the identical claim/preserve discipline) and
     * VFS inode eviction (not stored on the xfs_inode at all).
     */
    struct mxfs_caw_orphan_clock {
        struct mxfs_resource_id resource;
        bool                     valid;
        uint64_t                 orphan_since_ns;
        uint64_t                 bast_starve_since_ns;
    } *orphan_clock;                    /* MXFS_CAW_ORPHANCLOCK_SIZE entries */
    mxfs_spinlock_t          *orphan_clock_lock;
};

#define MXFS_CAW_SLOTHINT_SIZE  4096    /* direct-mapped hint entries */
/* sess4 (ccloop 46efd8b6): 4096 direct-mapped buckets gave birthday-certain
 * collisions for a 32-node run's ~200-resource working set, and a colliding
 * claim used to WIPE the victim's releasing mark + grant_seq (the v0.6.2
 * unlock protections) — 339 anchor-less releases in one run (065143Z).
 * 32768 x ~48B = ~1.5MB per mount; collisions become rare, and the no-wipe
 * waits in store/prebump/release_mark make the residual ones harmless. */
#define MXFS_CAW_GRANTMETA_SIZE 32768   /* direct-mapped grant-meta entries */
#define MXFS_CAW_ORPHANCLOCK_SIZE 4096  /* direct-mapped orphan-clock entries;
                                          * working set is just the currently
                                          * hot-contended resources, far
                                          * smaller than grant_meta's */

/* ─── Lifecycle ─── */

/*
 * max_held: cap on locally-tracked held locks (0 = use compile-time
 * default MXFS_CAW_MAX_HELD).  Memory cost per ctx ≈ max_held × 44
 * bytes (slots[] + mem_locks[]).  Clamped to MXFS_CAW_MAX_SLOTS.
 */
struct mxfs_dlm_caw_ctx *mxfs_dlm_caw_create(mxfs_bdev_t *dev,
                                               uint64_t disklock_offset,
                                               mxfs_node_id_t local_node,
                                               uint8_t node_slot,
                                               const uint8_t *volume_uuid,
                                               int max_held);
void mxfs_dlm_caw_destroy(struct mxfs_dlm_caw_ctx *ctx);

int  mxfs_dlm_caw_start(struct mxfs_dlm_caw_ctx *ctx);
void mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx);

/* ─── Lock operations ─── */

int mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx,
                       const struct mxfs_resource_id *resource,
                       uint8_t mode, uint32_t flags,
                       uint8_t *granted_mode);

int mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx,
                            const struct mxfs_resource_id *resource,
                            uint32_t expected_gen32, bool is_free);
int mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx,
                          const struct mxfs_resource_id *resource);

/* sess39: read-only — does this node hold the resource on disk? 1/0/<0 */
void mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource);
int mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx,
                      const struct mxfs_resource_id *resource);
/* ccloop cc87fed3 sess3: real (non-boolean) per-node granted mode — see
 * definition for why mxfs_dlm_caw_held's collapsed 0/1 is unsafe for
 * mxfs_v5_dlm_inode_granted_mode's CAW branch. */
uint8_t mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource);

/* sess19: read the shared on-disk slot generation (cross-node AG epoch). */
int mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint64_t *out_gen);

/* sess52: read-only concurrent-EX detector — popcount(OR of holders_ex over
 * the whole probe chain for `resource`); *nslots_out = live-slot count.
 * popcount>1 == two nodes hold EX on the same resource simultaneously. */
int mxfs_dlm_caw_ex_count(struct mxfs_dlm_caw_ctx *ctx,
                          const struct mxfs_resource_id *resource,
                          int *nslots_out);

/* ccloop a864 sess3: duplicate-immune self-EX check (full-chain scan).  1 if
 * our node_bit is set in holders_ex over any live slot for `resource`, else 0.
 * *nslots_out = live-slot count; *hex_or_out = OR of holders_ex.  Read-only. */
int mxfs_dlm_caw_self_held_scan(struct mxfs_dlm_caw_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                int *nslots_out, uint64_t *hex_or_out);

/* ccloop a864 sess3: unconditional scan-based self-release — CAS-clear our bit
 * from every live slot matching `resource` (recovery for an orphaned holder bit
 * the normal hinted/seq-gated unlock left set).  Caller must hold the DEMOTING
 * claim (in-core mode==NL).  Returns #slots cleared, <0 on error. */
int mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx,
                                    const struct mxfs_resource_id *resource);

int mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           uint8_t new_mode);

/*
 * v0.6.0: cross-node EX-handoff epoch observed at our last grant of
 * `resource` (0 = unknown/never granted), and whether that grant detected a
 * handoff (previous EX-class holder was a different node).  CAW analogs of
 * mxfs_dlm_grant_dir_epoch() / the TCP grant handoff bit — see slot field
 * dir_epoch above.  gen_out (may be NULL) receives the epoch to use as the
 * consume-once generation for the handoff path.
 */
uint32_t mxfs_dlm_caw_grant_dir_epoch(struct mxfs_dlm_caw_ctx *ctx,
                                      const struct mxfs_resource_id *resource);
bool mxfs_dlm_caw_grant_handoff(struct mxfs_dlm_caw_ctx *ctx,
                                const struct mxfs_resource_id *resource,
                                uint32_t *gen_out);

/* ccloop(3e02e7dd) sess3: canonical dir block0 query/publish — see the
 * dir_block0_fsb comment in struct mxfs_caw_lock_slot above.
 * mxfs_dlm_caw_grant_dir_block0: *fsb_out set to the canonical block0 iff a
 * value is published for incarnation `want_gen` (returns true) — read from
 * the local grant-meta cache (same freshness as dir_epoch, no extra I/O).
 * mxfs_dlm_caw_set_dir_block0: WRITE-ONCE publish for incarnation `gen` —
 * CAS-updates the on-disk slot; a no-op if already set for this gen (first
 * publisher wins) or a lower gen is reported (stale caller). */
bool mxfs_dlm_caw_grant_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
                                   const struct mxfs_resource_id *resource,
                                   uint32_t want_gen, uint64_t *fsb_out);
void mxfs_dlm_caw_set_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint64_t fsb, uint32_t gen);


/* v0.6.2: LOCAL grant-episode token for `resource` (CAW analog of the TCP
 * mirror's grant_gen).  Bumped by every grant-meta store (each grant episode);
 * 0 = no known local tenure.  The v5 gen-aware release compares this against
 * its capture at release-decision time and refuses (-ESTALE) to release a
 * NEWER tenure — closing the unlock-vs-regrant race behind P106-STALE-EX. */
uint32_t mxfs_dlm_caw_grant_seq32(struct mxfs_dlm_caw_ctx *ctx,
                                  const struct mxfs_resource_id *resource);

/* interactive session 2026-07-13: resource-scoped (survives inode eviction)
 * orphan-strand wall-clock trackers — see the grant_meta struct comment
 * above.  get() returns 0 on a bucket miss/collision (degrade to "not yet
 * tracked", same as a fresh start).  set() is a no-op on a bucket
 * miss/collision (the caller's next get() will then also read 0 and
 * re-seed — safe, just loses this one sample on the rare collision path). */
uint64_t mxfs_dlm_caw_orphan_clock_get(struct mxfs_dlm_caw_ctx *ctx,
                                       const struct mxfs_resource_id *resource,
                                       bool starve);
void mxfs_dlm_caw_orphan_clock_set(struct mxfs_dlm_caw_ctx *ctx,
                                   const struct mxfs_resource_id *resource,
                                   bool starve, uint64_t val);

void mxfs_dlm_caw_release_all(struct mxfs_dlm_caw_ctx *ctx);

/* ─── Node failure ─── */

int mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx,
                              uint8_t dead_slot);

/* Purge stale locks from multiple dead nodes in a single pass.
 * dead_mask is a 64-bit bitmap: bit N set means node slot N is dead.
 * Called at mount time to clear orphan holder bits from crashed nodes. */
int mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx,
                                    uint64_t dead_mask);

/* ─── Single-node bypass ─── */

/*
 * Enable or disable single-node bypass mode.  When transitioning
 * from single-node to multi-node, all locks held in-memory are
 * flushed to disk so incoming peers can see them.
 */
void mxfs_dlm_caw_set_single_node(struct mxfs_dlm_caw_ctx *ctx, bool single);

/*
 * Flush all in-memory held locks to disk.  Called internally on the
 * single→multi-node transition, but exposed for testing.
 */
int mxfs_dlm_caw_flush_held_to_disk(struct mxfs_dlm_caw_ctx *ctx);

/* ─── Callbacks ─── */

void mxfs_dlm_caw_set_bast_cb(struct mxfs_dlm_caw_ctx *ctx,
                                mxfs_dlm_bast_cb cb, void *data);

/* ccloop 72513a13 sess2: wire the liveness oracle for the wait-timeout
 * extension (holders_alive_fn in the ctx). */
void mxfs_dlm_caw_set_holders_alive_fn(struct mxfs_dlm_caw_ctx *ctx,
                                        bool (*fn)(void *data,
                                                   uint64_t slot_mask),
                                        void *data);

#endif /* MXFS_LIBMXFS_DLM_CAW_H */
