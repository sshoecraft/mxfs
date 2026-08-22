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
 * sess35 NUDGE v2 companion — HOPELESS-DEFER interval.  A waiter whose last
 * slot read proves it cannot be granted until someone else's release (a
 * foreign EX holder, or a fair-handoff ticket naming another node) used to
 * keep the 2/1..25ms cadence anyway; at a 32-node single-resource convoy
 * that is ~28 waiters x 40 reads/s = >1100 FUA reads/s serialized at the
 * one SCSI target — the reads themselves were the measured 21.6ms handoff
 * latency.  Such a waiter now sleeps this long between verification reads
 * and relies on the targeted v2 nudge to wake it the moment it can act.
 * Bounds preserved: stale-ticket clear (5s) and PR patience clocks tick at
 * this granularity; a lost nudge costs at most this much extra latency on
 * one handoff.
 */
#define MXFS_CAW_DEFER_POLL_MS      250
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
    /*
     * D-AGLOCK-...-LIVELOCK-488 (sess243 RULE-5 ruling, Option B'): sticky
     * ANONYMOUS revoke request.  A NOQUEUE contender exits caw_lock BEFORE
     * waiter registration and BEFORE the UDP BAST multicast, so against a
     * LAZILY-CACHED holder (which by design only demotes on a BAST) it
     * generates no signal at all and can spin -EAGAIN forever.  A contender
     * carrying MXFS_LKF_DEMAND CASes this to 1 on conflict and NEVER clears
     * it; the holder's poll thread treats a set revoke exactly like a
     * received BAST and demotes unconditionally.  It is consumed ONLY by
     * (a) the holder's release CAS once the slot has no holders left, or
     * (b) a fresh grant CAS on an otherwise unowned slot (normalizes a
     * stale bit).  A holder must never clear it and keep caching.  Unlike
     * the `waiters` bitmap this carries no node identity, so it cannot
     * recreate the same-node waiter-cancel collision family (ledger #15).
     */
    uint8_t                 revoke;         /* sticky anonymous revoke request */
    uint8_t                 pad0;
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
    /*
     * sess40 (D-CROSSNODE-OPEN-UNLINK / AGI orphan-coordinator): bitmap of
     * node slots that MAY have protected activity (open fds, mappings,
     * in-flight I/O, or just a cached in-core inode) for the INODE this
     * slot's resource names.  SET inside the grant/claim CAS (zero added
     * I/O); cleared LAZILY: by the owner's evict (one small CAS when the
     * wire-truth read shows the bit set), by unlock_free (the freer), by
     * fencing (dead nodes' bits stripped with their holder bits), or on
     * demand when a reaper's EX pressure drives a cache-only holder to
     * evict.  A stale set bit only DELAYS destructive inactivation of an
     * unlinked inode (the reaper defers while any peer bit is set); it can
     * never cause premature free.  Tombstones PRESERVE this field with the
     * resource identity — an open-unlinked file's protection must survive
     * grant-idle gaps; recycling the slot for a DIFFERENT resource builds a
     * fresh image (field zeroed).  Meaningful for MXFS_LTYPE_INODE only.
     */
    /*
     * EXPLICIT PADDING — DO NOT REMOVE.  open_holders is 8-byte aligned and
     * the field before it (dir_block0_gen) is a uint32_t, so without this
     * the compiler inserts the padding itself and the struct GROWS past the
     * 512-byte on-disk slot size.  That is not a cosmetic error: find_slot's
     * probe indexes its multi-slot read buffer as an ARRAY OF THIS STRUCT
     * (span[idx - span_base]), so an oversized struct makes every slot past
     * the first in a window decode from the wrong byte offset.  Shipped
     * briefly in 0.11.333-339 and measured as P94-SPAN-DISAGREE: the span
     * image was byte-for-byte the true slot SHIFTED BY 8, which the probe
     * then classified as "truly empty" (terminating the chain) and fed to
     * the claim CAS as its compare image (never matching) — the
     * cluster-cascading -110 shutdown of
     * D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN.
     */
    uint32_t                pad4;
    uint64_t                open_holders;
    /*
     * sess48 (D-FOREIGN-REPLAY full fix, step 1 — GPT-ruled token design):
     * the generation value of the CAS that granted the CURRENT exclusive
     * class (EX/PW) holder.  Written INSIDE the granting CAS, so it is
     * durable before the grantee can touch any covered metadata; unique
     * per slot forever (generation is the monotonic ABA counter); changes
     * on every release/reacquire.  Together with the resource id this is
     * the authority token a dead node's buffer-log images must carry for
     * foreign replay to apply them: at fencing, the frozen slot (dead
     * node's EX bit + this epoch) IS the held-at-death manifest.  Left
     * stale on release — validity requires the exclusive holder bit.
     * Slot repair must PRESERVE it.
     */
    uint64_t                ex_grant_epoch;
    /*
     * sess176 (D-FOREIGN-REPLAY lineage discriminator, sess175 RULE-5
     * ruling): random nonzero 64-bit id minted when a slot is bound to a
     * resource by a FRESH image (empty slot or different-resource
     * tombstone); INHERITED unchanged on a same-resource tombstone
     * recycle.  A slot number alone cannot distinguish "the binding my
     * token was issued under" from "a later binding of the same slot to
     * the same resource" once generation restarts after reclamation;
     * lineage is that discriminator.  EQUALITY comparison only — no
     * ordering, age, or distance semantics anywhere, audit tooling
     * included.  Zero means "no lineage" (pre-v3 image).  Tombstones and
     * the frozen victim manifest PRESERVE it with the resource identity.
     */
    uint64_t                resource_lineage;
    uint8_t                 reserved[336];  /* pad to 512 */
};

#define MXFS_CAW_EX_SLOT_NONE   0xFF

/*
 * Compile-time size check.
 *
 * sess40: the kernel arm used to be a MACRO that NOTHING EVER INVOKED
 * (grep proved zero call sites), so kernel builds had NO size assertion at
 * all — which is how a field added in 0.11.333 silently grew the struct past
 * 512 and corrupted the probe's multi-slot decode for a week of builds.  Use
 * _Static_assert unconditionally: it needs no call site and fires at the
 * point of definition in every build, kernel and user-space alike.  The
 * macro is kept as a no-op alias so any future caller still compiles.
 */
_Static_assert(sizeof(struct mxfs_caw_lock_slot) == MXFS_CAW_SLOT_SIZE,
               "mxfs_caw_lock_slot must be exactly 512 bytes (on-disk slot)");
#define MXFS_BUILD_CHECK_CAW_SLOT() do { } while (0)

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
    /*
     * sess35 (c7ee71c6) NUDGE v2 — targeted wakeups (Gemini-reviewed).
     * v1 grant nudges woke EVERY blocked acquirer on every node; each did
     * a READ(16)+FUA re-check, and at a 32-node single-dir create convoy
     * those ~28 serialized reads at the one SCSI target WERE the measured
     * ~21.6ms per-handoff latency (3200 creates / 69s, cc md5 phase).
     * v2 carries the set of nodes that can actually act on the slot
     * change (the fair-handoff ticket, the PR class, or all waiters);
     * receivers with their bit clear skip the disk read and keep
     * sleeping.  The disk poll interval remains the lossless backstop
     * (lost/overwritten nudges and stale-ticket clearance both ride it).
     * version >= 2 iff wake_mask is valid; v1 receivers parse the
     * leading bytes unchanged and keep wake-all semantics.
     */
    uint64_t                wake_mask;
};

/* sess35 NUDGE v2: receive-side record of the last nudges, scanned by
 * blocked acquirers under nudge_lock to decide wake vs keep-sleeping
 * without touching the disk.  Ring depth absorbs scheduling jitter
 * during release bursts; a waiter whose last-seen seq has fallen off
 * the ring falls back to a slot read (never silently misses). */
#define MXFS_CAW_NUDGE_RING 32
struct mxfs_caw_nudge_rec {
    uint64_t                seq;
    uint64_t                wake_mask;
    struct mxfs_resource_id resource;
    uint16_t                version;
};

/*
 * ─── sess128 BAST DISPATCH QUEUE (RULE-4 rooted, GPT RULE-5 reviewed) ───
 *
 * THE DEFECT.  bast_recv_fn is ONE thread per node and it called ctx->bast_cb
 * SYNCHRONOUSLY inside its recvfrom loop.  That callback reaches
 * mxfs_dlm_caw_held() -> find_slot() -> a shared-LUN SCSI read, and on the
 * no-inode path a whole release pipeline.  Measured at 32 nodes
 * (0.11.452, virgin fs, crash_consistency): 35.22% of ALL DLM release-side
 * blocked wall was
 *   blk_execute_rq < scsi_execute_cmd < mxfs_pal_scsi_read_fua_bdev
 *     < read_slot < find_slot_skip < mxfs_dlm_caw_held
 *     < mxfs_v5_dlm_inode_held < mxfs_dlm_bast_notify < v5_bast_cb
 *     < bast_recv_fn
 * and the node's UDP counters read `InErrors 8085 RcvbufErrors 8085` — EVERY
 * UDP error was a receive-buffer overflow, on a socket that already has a
 * 4 MB locked sk_rcvbuf.  Overflowing 4 MB means that thread was stalled for
 * seconds at a time, so BAST hints AND the grant nudges that share the socket
 * were being silently dropped.  Consequence, measured on the mount root
 * (ino 128) with 19 nodes queued on it: ~1.6 handoffs/s, mean grant wait
 * 3533 ms.  Holders were not refusing to release — THEY HAD NOT BEEN TOLD.
 *
 * sess8 saw the shape and tuned around it: "every hint fires bast_cb on all
 * receivers (NO DEDUP), and ~31 waiters x 40/s melted the cluster in callback
 * processing" (see MXFS_CAW_BAST_RESEND_FAST_MS).  It lowered the send
 * cadence instead of adding the dedup.  This is the dedup.
 *
 * THE QUEUE.  Every BAST producer — the UDP receive thread AND the disk poll
 * thread — now submits through caw_bast_submit() instead of calling
 * ctx->bast_cb itself.  Submission is O(1), allocation-free (the whole pool is
 * preallocated at create) and never touches the device, so the socket drains
 * at line rate.  A small pool of dispatcher threads runs the callbacks.
 *
 * WHY IT IS SAFE TO COALESCE.  A BAST is a LEVEL-triggered advisory ("there is
 * an incompatible waiter for R; reconsider R"), not a counted edge: the waiter
 * bit is published in the slot BEFORE the hint is sent and stays published
 * until the wait ends, and the callback re-reads live state.  So N hints for
 * the same resource and one hint for that resource ask for exactly the same
 * work.  Merging keeps the CONSERVATIVE JOIN of the requested modes
 * (caw_bast_mode_join): the merged mode conflicts with everything either
 * original conflicted with, so no release that would have happened is lost.
 * EX is a fixed point of the join, which is what preserves the XFS layer's
 * i_dlm_dir_want_ex latch (only an EX requester invalidates a cached dir).
 *
 * PER-RESOURCE SERIALIZATION IS NEW, not a relaxation.  Before this, the recv
 * thread and the poll thread could run bast_cb for the SAME resource
 * concurrently; nothing serialized them.  Now a resource is in at most one of
 * QUEUED/RUNNING, and a hint that arrives while its callback is running sets
 * the re-arm flag and is re-queued at the TAIL on completion (tail, not head,
 * so one hot resource cannot starve the rest).  Cross-resource ordering is NOT
 * preserved and must not be relied on — UDP multicast never provided it.
 *
 * WORKER COUNT.  Two.  That is exactly the callback concurrency that already
 * existed (recv thread + poll thread), so this change cannot widen the
 * liveness class; it only removes the head-of-line block.  Raising it needs a
 * callback lock-order audit first.
 */
#define MXFS_CAW_BASTQ_ENTRIES  2048   /* distinct resources in flight, not packets */
#define MXFS_CAW_BASTQ_BUCKETS  2048   /* power of two */
#define MXFS_CAW_BAST_WORKERS   2      /* == today's recv+poll callback concurrency */
#define MXFS_CAW_BASTQ_WAIT_MS  200    /* dispatcher idle wakeup (shutdown responsiveness) */
/* An overflowed queue means a hint was dropped.  Hold the disk poll at its
 * FAST cadence for this long afterwards so the backstop actually covers the
 * loss, instead of relaxing straight back to POLL_RELAX_MS. */
#define MXFS_CAW_BASTQ_FASTPOLL_MS 2000
/* Cadence of the harvestable P265-BASTQ-STATS line (emitted by the poll
 * thread, which already wakes on a cadence).  The coalescing ratio is the
 * claim this whole mechanism makes; it has to be measurable. */
#define MXFS_CAW_BASTQ_REPORT_MS 10000

enum mxfs_caw_bq_state {
    MXFS_CAW_BQ_FREE = 0,
    MXFS_CAW_BQ_QUEUED,
    MXFS_CAW_BQ_RUNNING,
};

struct mxfs_caw_bq_ent {
    struct mxfs_resource_id  resource;
    struct mxfs_caw_bq_ent  *hnext;     /* hash chain */
    struct mxfs_caw_bq_ent  *qnext;     /* FIFO ready queue, or free list */
    uint64_t                 enq_ms;
    uint32_t                 merges;    /* hints absorbed while QUEUED */
    uint8_t                  state;
    uint8_t                  queued_mode;
    uint8_t                  rearm;
    uint8_t                  rearm_mode;
};

/* ─── Per-mount CAW DLM context ─── */

/* sess112: local request registry entry — definition is private to
 * dlm_caw.c; nothing outside the CAW transport may reach into it. */
struct mxfs_caw_lreq;

/*
 * ─── sess133 (GPT sess132 ruling, defects D2 + D4): THE LIFECYCLE STATE ───
 *
 * WHY A STATE AND NOT A BOOL.  `running` could not encode this lifecycle, and
 * the attempt to make it do so was a live blocker.  stop() clears it near the
 * START of teardown (phase 1, so the thread loops end and admission shuts), so
 * a SECOND caller arriving any time during the following phases read
 * `running == false`, took the "already stopped" shortcut, and returned AS
 * THOUGH TEARDOWN HAD COMPLETED — free to destroy the context, free it, or
 * read an intermediate verdict, while the first stop was still inside phase 2
 * waiting on live operations.  One bit cannot distinguish "never started" from
 * "stopping right now" from "stopped, verdict final"; those are three answers
 * and each one demands different behaviour from the caller.
 *
 * All transitions happen under lreq_lock — the SAME lock that guards
 * ops_closed / ops_active / the verdict fields — so a state transition and the
 * admission decision that depends on it are one atomic event.  Every ctx has
 * that lock: mxfs_dlm_caw_create fails the mount when the registry cannot be
 * allocated (sess114), so there is no lock-less ctx to degrade for.
 *
 *      NEW ──▶ STARTING ──▶ RUNNING ──▶ STOPPING ──▶ STOPPED
 *                      └──▶ START_FAILED ──▶ STOPPING ──▶ STOPPED
 *      NEW ─────────────────────────────▶ STOPPING ──▶ STOPPED
 *
 * Exactly ONE caller owns the RUNNING/START_FAILED/NEW → STOPPING transition
 * and therefore owns teardown; every other caller either waits for STOPPED or
 * reads the stored verdict.  `running` survives ONLY as a loop-exit hint for
 * the worker threads (it is read in ~20 hot loops and a state enum read under a
 * mutex there would be gratuitous); it is written solely as part of a
 * transition and is never again the basis of a lifecycle decision.
 */
enum mxfs_caw_lifecycle {
    MXFS_CAW_LC_NEW = 0,     /* created; no threads, no admitted ops        */
    MXFS_CAW_LC_STARTING,    /* inside mxfs_dlm_caw_start                   */
    MXFS_CAW_LC_RUNNING,     /* threads up; the ONLY state that admits ops  */
    MXFS_CAW_LC_START_FAILED,/* start unwound; may hold published residue   */
    MXFS_CAW_LC_STOPPING,    /* one owner is inside teardown                */
    MXFS_CAW_LC_STOPPED,     /* teardown finished; the verdict is final     */
};

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

    /*
     * sess309 step-6 F1 (sess307 ruling item 5): WEDGED-release pins.  A
     * resource whose ICLUS release proof could not complete within bounds
     * is pinned here so the unconditional teardown release_all REFUSES to
     * strip this node's bits from its slot (counted `lost` → clean
     * departure refused → peers fence and run recovery, the safe
     * direction).  Writes under held.lock; bounded small — a wedge is a
     * one-shot per cluster and force-shuts the mount.
     */
#define MXFS_CAW_MAX_PINNED 4
    struct mxfs_resource_id pinned_res[MXFS_CAW_MAX_PINNED];
    int                     pinned_n;

    /* BAST poll thread */
    mxfs_thread_t           *bast_poll_thread;
    mxfs_cond_t             *stop_cond;
    mxfs_mutex_t            *stop_lock;

    /* UDP multicast BAST */
    mxfs_sock_t             *bast_mcast_sock;
    mxfs_thread_t           *bast_recv_thread;

    /*
     * sess128 BAST dispatch queue — see the block comment above
     * struct mxfs_caw_bq_ent.  Producers (bast_recv_fn, bast_poll_fn) call
     * caw_bast_submit(); the dispatchers below run ctx->bast_cb.  Everything
     * here is guarded by bq.lock, which is NEVER held across a callback.
     */
    struct {
        struct mxfs_caw_bq_ent  *pool;      /* preallocated entries */
        struct mxfs_caw_bq_ent **hash;      /* MXFS_CAW_BASTQ_BUCKETS chains */
        struct mxfs_caw_bq_ent  *freelist;
        struct mxfs_caw_bq_ent  *head;      /* FIFO ready queue */
        struct mxfs_caw_bq_ent  *tail;
        mxfs_mutex_t            *lock;
        mxfs_cond_t             *cond;
        uint32_t                 depth;     /* entries QUEUED right now */
        uint32_t                 hiwater;
        uint32_t                 running_n; /* entries RUNNING right now */
        uint64_t                 submitted; /* hints handed to submit() */
        uint64_t                 merged;    /* absorbed into a QUEUED entry */
        uint64_t                 rearmed;   /* absorbed into a RUNNING entry */
        uint64_t                 dispatched;/* callbacks actually run */
        uint64_t                 overflow;  /* dropped: pool exhausted */
        uint64_t                 inline_cb; /* fallback: ran on the producer */
        uint64_t                 fastpoll_until_ms; /* overflow -> hold FAST poll */
    } bq;
    mxfs_thread_t           *bast_disp_thread[MXFS_CAW_BAST_WORKERS];

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
    /* sess35 NUDGE v2: ring of the last MXFS_CAW_NUDGE_RING received
     * nudges (entry seq == its nudge_seq value, stored at seq % ring
     * size), written by the receive thread and scanned by waiters, all
     * under nudge_lock. */
    struct mxfs_caw_nudge_rec nudge_ring[MXFS_CAW_NUDGE_RING];

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

    /* sess374 (sess363 ruling item B) — OUT-OF-CLOSURE SCRUB ORACLE.
     * Answers, for ONE blocking node slot and ONE resource: may that node's
     * state on this slot be force-revoked?  1 = yes (the slot's occupant
     * carries a durable TERMINAL_REFUSED verdict and the resource is
     * PROVABLY outside its quarantined domain), 0 = no / cannot prove,
     * <0 = hard error (abort, never "keep").  It re-reads the victim's
     * heartbeat sector on every call — it IS the leaseless gate, so no
     * answer is ever amortized across a CAS.  Wired by v5_mount; NULL =
     * no scrub (pre-fix behavior: keep waiting). */
    int                     (*closure_scrub_fn)(void *data,
                                                uint8_t blocking_slot,
                                                const struct mxfs_resource_id *res);
    void                    *closure_scrub_data;
    /* sess374 (sess357 ruling part 1, second half) — WAIT CANCELLATION.
     * "The DLM rejects NEW waits immediately with a distinct terminal-
     * quarantine error AND CANCELS EXISTING waits the same way."  The new
     * half was already enforced at the XFS acquire gate; a wait ALREADY in
     * flight when the verdict imported had no way to hear about it and sat
     * out the full DLM timeout (measured sess374: quarantine at t=171s, the
     * same waiter reached the refusal gate at t=467s — the sess356 five-
     * minute wedge).  Returns >0 iff this resource is inside a quarantined
     * victim domain and the wait must abort NOW.  Lockless and I/O-free by
     * contract (it reads a monotonic in-memory map), because it is consulted
     * on every poll lap.  NULL = no cancellation (pre-fix behavior). */
    int                     (*wait_refuse_fn)(void *data,
                                              const struct mxfs_resource_id *res);
    void                    *wait_refuse_data;
    /* sess374 (RULE-5 review items 2+3): SKIP-ONLY candidate hint — bit i set
     * iff this mount has imported a terminal AG_MASK refusal for heartbeat
     * slot i.  Published by v5 on every outcome import; read with no I/O.
     * Without it, one scrub attempt costs a heartbeat platter read per
     * foreign bit on the slot, on every blocked waiter — the read storm the
     * ruling rejected.  It can only cause a repair to be SKIPPED (a stale bit
     * costs one gate read and authorizes nothing; a missing bit just defers
     * the repair to the import lap), so it is never consulted for authority:
     * every strip is still gated on a fresh platter read. */
    volatile uint64_t       closure_cand_mask;
    /* Throttle for the NOQUEUE-conflict scrub hook, armed ONLY when a
     * candidate bit is actually present on the slot in conflict, so an
     * unrelated healthy resource can never spend the frozen one's
     * opportunity (review item 8).  The wait-loop hook carries its own
     * per-wait stamp. */
    uint64_t                noq_scrub_last_ms;
    /* Atomic winner election for that throttle (review round 2, item 3).  A
     * bare timestamp compare lets every CPU in the NOQUEUE spin loop decide
     * the interval expired at once and all issue gate reads — the storm the
     * throttle exists to prevent.  Exactly one holder of this counter runs a
     * scrub at a time; PAL has no 64-bit CAS, and inc-returns-new is a
     * sufficient try-lock. */
    mxfs_atomic32_t         noq_scrub_busy;

    volatile bool           running;
    uint8_t                 volume_uuid[16];

    /* Single-node bypass: when true, lock/unlock operate purely
     * in-memory (no disk I/O).  Cleared when a peer joins; the
     * transition handler flushes all held locks to disk. */
    bool                    single_node;

    /*
     * sess52 (D-FOREIGN-REPLAY step 4a) — MOUNT ADOPT WINDOW.
     *
     * Set by v5_mount between the step-4 own-slot purge (which now
     * RETAINS our previous incarnation's EX/PW bits — they are the
     * authority manifest xlog_recover replays under) and the
     * post-recovery settle.  While it is true, an acquire that finds
     * our bit already set on disk but NOT in ctx->held is adopting a
     * retained bit rather than observing its own steady-state hold, so
     * it converts the no-CAS fast path into a real CAS + track_held.
     *
     * That CAS is what serialises adoption against the settle purge:
     * both sides now compete on the same slot, so the settle can never
     * strip a bit out from under an acquire that is about to return
     * success on it (the loser re-reads and re-decides).  ex_grant_epoch
     * is deliberately NOT restamped — adoption inherits the previous
     * incarnation's authority, it does not mint new authority.
     */
    bool                    mount_adopt_window;
    int                     mount_retained;     /* EX/PW slots kept at step 4 */

    /*
     * sess53 — STICKY held-table overflow.
     *
     * ctx->held is the ONLY discriminator the settle purge has for
     * "live hold" vs "dead incarnation's leftover bit".  If a grant
     * ever failed to record itself (table full), that discriminator is
     * incomplete for the rest of the mount: an untracked bit may be a
     * live hold, and purging it would strip authority from under a
     * holder — manufacturing the very publish-without-authority failure
     * class this work exists to close.
     *
     * So the overflow is recorded here and it is permanent for the
     * mount.  Any SKIP_TRACKED purge refuses to run while it is set and
     * returns -EOVERFLOW, leaving the on-disk manifest intact (GPT
     * sess52 ruling item 6: on any failure, never "clean up" retained
     * bits).  Declining to reclaim leaks slots; purging a live hold
     * corrupts.  The fail-safe direction is not symmetric.
     */
    bool                    held_overflow;

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

    /*
     * sess112 — LOCAL REQUEST REGISTRY (one entry per live (node, resource)).
     *
     * THE DEFECT IT CLOSES.  A CAW slot represents this node with a SINGLE
     * bit per bitmap: one `waiters` bit, one `waiters_ex` bit, one holder
     * bit per mode.  That is a node-granular encoding, but the requests
     * behind it are THREAD-granular and more than one can be live at once:
     * inode acquires are serialised by the MXFS_DLM_ISTATE_ACQUIRING park in
     * mxfs_dlm_ilock_begin, and the demoter is deliberately EXEMPT from that
     * park (its drain's trailing xfs_irele must self-reenter).  So two local
     * attempts on one resource legitimately share one on-disk bit.
     *
     * caw_drop_own_waiter() — the give-up reconcile — clears those bits keyed
     * on ctx->node_bit alone.  It therefore destroys state that belongs to a
     * DIFFERENT local attempt:
     *
     *   - clearing holders[giveup_mode] strips authority from under a local
     *     tenure that adopted a direct handoff (the adopt arm is pure
     *     recognition: it writes NOTHING to the slot, so the on-disk image is
     *     byte-identical for "grant landed, nobody adopted" and "grant landed
     *     and another local thread is live on it").  That is an unfenced
     *     writer — a corruption-class outcome, not a liveness one.
     *   - clearing `waiters` / `waiters_ex` destroys another local attempt's
     *     registration, so no releaser ever hands off to it and it burns its
     *     whole timeout.  A leaked-in-the-other-direction EX waiter bit has
     *     already been MEASURED wedging 16 nodes for >600s.
     *
     * No slot field can disambiguate this: node identity is one bit and
     * adoption leaves no trace, so the discriminator must be in-core.  This
     * registry IS that discriminator — the single authoritative statement of
     * what this node currently wants and holds on a resource.
     *
     * WHY A CHAINED TABLE AND NOT THE DIRECT-MAPPED PATTERN grant_meta USES.
     * grant_meta/slot_hints/orphan_clock are CACHES: a collision evicts and
     * the reader falls back to a safe answer.  This is not a cache.  A missing
     * entry would read as "no other local attempt is live", which is exactly
     * the false statement that authorises the wrongful clear.  Eviction is
     * therefore not available, so entries are chained and allocated per live
     * resource, and an allocation failure REFUSES the acquisition rather than
     * proceeding with an unsound view (see lreq_join / P247-LREQ-NOMEM).
     *
     * LOCKING.  A plain mutex: every caller (mxfs_dlm_caw_lock,
     * mxfs_dlm_caw_convert, caw_wait_for_grant, mxfs_dlm_caw_unlock_gen) is
     * already a sleeping context doing shared-LUN I/O.  Unlike orphan_clock
     * this table is never touched from mxfs_dlm_bast_process, so it does not
     * need that table's spinlock discipline.  The mutex is NEVER held across
     * disk I/O: the reconcile takes a decision snapshot under the lock and
     * then runs its CAS loop unlocked, which is sound because the decision is
     * fail-closed in the corruption direction (refusing to clear leaks a bit;
     * clearing wrongly loses data) and any bit left behind is re-collected by
     * the LAST local attempt to leave the resource (lreq_finish).
     */
    struct mxfs_caw_lreq    **lreq;     /* MXFS_CAW_LREQ_BUCKETS chain heads */
    mxfs_mutex_t             *lreq_lock;
    /*
     * Paired with lreq_lock.  sess122: this is the OWED-CLEANUP WAKE CHANNEL.
     * Anything that can make a deferred obligation runnable — a new obligation
     * published, a clear window closing, the last local attempt leaving,
     * teardown — broadcasts it, and the owed worker (caw_owed_worker_fn) parks
     * on it.  It carries no other traffic: the sess117 "last leaver waits out an
     * open clear window" park was deleted when the worker made it unnecessary
     * (the obligation is now published BEFORE the I/O that would discharge it,
     * so there is no window in which a departing attempt can orphan work a
     * clearer has not written down yet).
     */
    mxfs_cond_t              *lreq_cond;
    mxfs_thread_t            *owed_worker;
    /*
     * ─── sess129 (GPT sess126 ruling, blocker 4): the OWED-READY QUEUE ───
     *
     * FIFO of registry entries that owe cleanup and are not currently claimed
     * by the collector.  It REPLACES the sess125 rotating bucket cursor, which
     * could not deliver the fairness it claimed: that cursor stored a BUCKET
     * index, so a sweep which stopped part-way along a chain resumed at that
     * chain's HEAD and re-claimed the same entry forever.  With the teardown
     * drain's one-entry claim cap that is not a corner case but the normal
     * case — a bucket holding pending X,Y,Z claims X on every single sweep and
     * Y,Z are never reached.  Intra-bucket position is not representable in a
     * bucket cursor, so no cap or start-offset tweak can fix it.
     *
     * THE INVARIANT, and it is load-bearing for MEMORY SAFETY, not just for
     * fairness:
     *
     *     e is on this queue  IFF  lreq_owed_pending(e) && !e->owed_busy
     *
     * maintained at exactly four transition points, every one of which already
     * runs under lreq_lock: publication (lreq_owed_merge) enqueues at the
     * tail, retraction (lreq_owed_retract) dequeues once nothing is left owed,
     * the sweep's claim dequeues and raises owed_busy, and caw_owed_release
     * drops owed_busy and re-enqueues at the tail if anything is still owed.
     * All four go through lreq_oq_sync so there is ONE place the queue can get
     * out of step with the record it schedules.
     *
     * WHY THAT MAKES IT A SAFETY INVARIANT.  lreq_gc frees entries, and it
     * already refuses on BOTH halves of the right-hand side (owed_busy and
     * lreq_owed_pending).  So under this invariant a queued entry can never be
     * freed — which is the only thing standing between this queue and a
     * use-after-free.  lreq_gc refuses on oq_queued directly as well: belt and
     * braces, so that weakening the invariant later leaks an entry instead of
     * corrupting the queue.
     *
     * The hash table stays, for LOOKUP only.  All three fields, and every
     * oq_* field on the entry, are guarded by lreq_lock.
     */
    struct mxfs_caw_lreq     *owed_q_head;
    struct mxfs_caw_lreq     *owed_q_tail;
    uint32_t                  owed_q_n;
    /*
     * ─── sess130 (GPT sess126 ruling, blocker 2): THE ADMISSION GATE ───
     *
     * THE PROOF THIS EXISTS TO SUPPORT.  Once teardown has observed ops_active
     * == 0 while holding lreq_lock, admission is closed and every operation
     * that can publish an obligation publishes it BEFORE decrementing
     * ops_active under that same lock.  Therefore no obligation can appear
     * after that point, and the collector's final residue check is a real
     * census rather than a sample.  `running = false` proved none of that: it
     * is a flag the producers never read.
     *
     * WHY A COUNT AND A GATE AND NOT A THREAD ARGUMENT.  Obligations are
     * published from exactly two public entry points (mxfs_dlm_caw_lock and
     * mxfs_dlm_caw_convert — the only two callers of lreq_join, verified
     * sess129), but the threads that run them are XFS's, not ours: there is
     * nothing to stop and join.  So the quiescence has to be expressed as an
     * admission gate plus an in-flight count on the CALLS.
     *
     * THE GATE IS WIDER THAN THE PROOF, DELIBERATELY.  It covers every public
     * entry point that WRITES a slot or touches the registry, not just the two
     * publishers, because mxfs_dlm_caw_release_all runs during teardown and
     * must run EXCLUSIVELY.  GPT sess130 found the race that makes that
     * mandatory: with release_all before quiescence, an acquire already inside
     * the door completes after release_all has cleared everything, re-takes a
     * holder bit, publishes nothing (it SUCCEEDED — success needs no cleanup),
     * and the node then announces a clean departure while still holding the
     * bit on disk.  Ordering release_all after the gate closes and the count
     * reaches zero is what removes that window.
     *
     * Pure readers (dump_slot, read_generation, ex_count, held, footprint_scan,
     * self_held_scan) are NOT gated: they cannot write a slot, cannot publish,
     * and cannot race release_all.  Their lifetime against ctx teardown is the
     * caller's problem and is unchanged by this mechanism.
     *
     * Both fields are guarded by lreq_lock.  A ctx with no lreq_lock (the
     * registry allocation is all-or-nothing, and mount fails when it fails)
     * has no gate — every entry point is admitted, which matches the pre-gate
     * behaviour exactly.
     */
    bool                      ops_closed;   /* admission shut, teardown owns us */
    uint32_t                  ops_active;   /* entry points past the door */
    uint64_t                  ops_refused;  /* calls turned away by the gate */
    /*
     * sess131 teardown sequencing, all guarded by lreq_lock.
     *
     * `drain_armed` splits a signal that used to be one.  The owed worker left
     * its main loop on `running == false` and began its teardown drain
     * immediately — which is BEFORE release_all runs, so anything release_all
     * published could never be collected.  Now `running = false` only ends the
     * main loop; the worker then parks until teardown has finished the
     * exclusive release_all and armed the drain.  Two signals because they are
     * two events.
     *
     * `release_on_stop` lets the layer above suppress the release entirely.
     * mxfs_v5_dlm_shutdown deliberately does NOT release when the mount is
     * WITHDRAWN — the D2 freeze — and destroy's unconditional release_all used
     * to defeat that.  A flag rather than a stop() argument because stop() has
     * five callers and only one of them knows about withdrawal.
     *
     * `unsafe_to_free` is set when the quiesce did NOT reach zero.  Teardown
     * then must not continue: freeing the ctx under an operation still inside
     * it is a use-after-free, and proceeding would also let that operation
     * publish after the final census and destroy the claim the census makes.
     * destroy() honours it by leaking the ctx, loudly.  A leaked mount context
     * on a wedged unmount is strictly better than either alternative.
     */
    bool                      drain_armed;
    bool                      release_on_stop;
    bool                      unsafe_to_free;
    uint64_t                  quiesce_ms;   /* wall time the quiesce took */
    /*
     * Teardown outcome, written once by mxfs_dlm_caw_stop and read by the
     * layer above it.  FALSE means this node must NOT claim a clean departure:
     * peers have to treat it as a death, fence it and replay its slice, because
     * we cannot prove our bits are off the disk.  It starts false and only a
     * completed quiesce + release + drain with a zero residue sets it true, so
     * every path that never reached that point — an early return, a wedged
     * producer, a dead LUN — fails closed.
     *
     * It is the OWNER'S STORED VERDICT: a second stop() caller waits for
     * MXFS_CAW_LC_STOPPED and then reads this, under lreq_lock, rather than
     * computing anything of its own.  (sess134, ruling A1.  The `stop_ran`
     * bool this replaces could not tell "never started" from "stopping right
     * now" from "stopped, verdict final" — see enum mxfs_caw_lifecycle.)
     */
    bool                      departed_clean;
    /*
     * ─── sess134 (GPT sess133 ruling A2/A3 + B): TEARDOWN STATE ───
     *
     * All guarded by lreq_lock, which is also what serialises the
     * NEW/RUNNING/START_FAILED → STOPPING transition electing the single
     * teardown owner.
     *
     * `lc` is the lifecycle (see the enum).  It supersedes `running` for every
     * lifecycle decision; `running` survives only as a loop-exit hint.
     *
     * `release_all_done` means caw_release_all_body's traversal FINISHED —
     * ruling A3 was explicit that "release_all ran" must not mean "was
     * entered".  Its early exits (a NULL ctx; an allocation failure that
     * clears nothing) leave it false, and a false refuses the clean departure
     * exactly as a nonzero residue does.
     *
     * `held_at_stop` is the held-list depth snapshotted under held.lock BEFORE
     * lreq_lock is taken for the verdict (ruling A3: the no-release term must
     * not read a count teardown can still change, and these two locks must
     * never be taken in the other order).
     *
     * `teardown_expired` is the STICKY record that a blocking teardown phase
     * blew MXFS_CAW_QUIESCE_MS.  Ruling B2: that threshold is fault DETECTION
     * and escalation, never permission to abandon — once latched, a clean
     * departure is impossible for this attempt even if the phase later
     * completes, and the mandatory fail-stop deadline is armed.
     * `teardown_defer_sent` makes the escalation one-shot.
     */
    enum mxfs_caw_lifecycle   lc;
    bool                      release_all_done;
    bool                      teardown_expired;
    bool                      teardown_defer_sent;
    uint64_t                  teardown_expired_ms;
    int                       held_at_stop;
    /*
     * ─── sess130 (GPT sess126 ruling, blocker 3): TERMINAL ESCALATION ───
     *
     * Latched once. `owed_failed` is the DLM's OWN record that this mount can
     * no longer discharge its obligations; it is set synchronously, under
     * lreq_lock, in the same critical section that closes admission and forbids
     * a clean departure — BEFORE the callback is invoked. That ordering is the
     * whole point: the callback is an escalation channel, not the safety latch.
     * If it is unregistered, racing teardown, or its work is cancelled because
     * unmount already owns the transition, the state recorded here still
     * prevents the GOODBYE and the clean heartbeat-slot release.
     */
    bool                      owed_failed;
    uint64_t                  owed_failed_ms;
    void                    (*owed_stuck_fn)(void *data);
    void                     *owed_stuck_data;
    /*
     * ─── sess132 (GPT sess130 ruling item 7): MEMBERSHIP CONTEXT ───
     *
     * The escalation diagnostic has to say WHICH membership this node was in
     * when its cleanup got stuck, or the line cannot be correlated with the
     * peers' view of the same interval.
     *
     * HONEST NAMING.  `mship_view` is a LOCAL generation counter — the Nth
     * membership view this mount has observed — NOT a cluster-committed epoch.
     * MXFS does have a real committed membership epoch on disk
     * (struct mxfs_mepoch_rec: epoch, member_mask, fenced_mask, agreed by a
     * voter protocol), but it belongs to the net2 transport, whose objects are
     * not in the module's Kbuild; on the CAW transport nothing commits an
     * epoch.  Printing a local counter under the name "epoch" would invite
     * exactly the cross-node comparison it cannot support, so it is named for
     * what it is and the gap is recorded here.
     *
     * Guarded by lreq_lock: the setter is the membership callback, the readers
     * are escalation paths that already hold it.
     */
    uint64_t                  mship_view;
    uint32_t                  mship_members;
    uint64_t                  lreq_guard_hits;  /* refused: live local tenure */
    uint64_t                  lreq_defer_hits;  /* refused: peer attempt live */
    uint64_t                  lreq_frozen_defer; /* P269: frozen world had live attempt */
    uint64_t                  lreq_owed_runs;   /* deferred cleanups performed */
    uint64_t                  lreq_exhausted;   /* cleanup CAS loop gave up */
    uint64_t                  lreq_nomem;       /* acquisitions refused (OOM) */
    /* sess117 clear-window linearization (see the block comment above
     * lreq_clr_begin in dlm_caw.c). */
    uint64_t                  lreq_clr_refuse;  /* publications sent back to retry */
    uint64_t                  lreq_rel_kept;    /* tenure kept across a release */
    /*
     * sess153 (D-RELEASEALL-LREQ-RETIRE-MISSING, GPT sess153 ruling).
     *
     * lreq_finish_gen counts tenure PUBLICATIONS context-wide — it moves with
     * every pub_seq bump, under lreq_lock.  stop() phase 4 snapshots it into
     * stop_finish_gen immediately before release_all; the teardown tenure
     * retire in caw_owed_release compares the two and fails CLOSED on any
     * mismatch, because a moved generation means a publication landed inside
     * a window the phase-2/3 joins are supposed to have frozen.  A global
     * generation (not the entry's own pub_seq) is deliberate: an illicit
     * publication on ANY entry disproves the freeze argument, and an
     * entry-local sample taken at claim time could not see one that landed
     * between release_all and the claim.
     */
    uint64_t                  lreq_finish_gen;   /* publications, context-wide */
    uint64_t                  stop_finish_gen;   /* phase-4 freeze snapshot */
    uint64_t                  lreq_teardown_retired; /* completions that retired tenure */
    uint64_t                  lreq_rel_ioretry;  /* release_all in-line CAS retries (B) */
    /*
     * sess122 (GPT sess121 ruling on blocker 2 — guaranteed-progress owed
     * cleanup).  An obligation to clear one of this node's bits is published
     * before the I/O that would discharge it and retracted only on proof, so
     * these count a state machine, not a best-effort retry.
     */
    uint64_t                  lreq_owed_pub;     /* obligations published/merged */
    uint64_t                  lreq_owed_done;    /* obligations fully discharged */
    uint64_t                  lreq_owed_moot;    /* holder bit owned by a live tenure */
    uint64_t                  lreq_owed_moot_refused; /* P270: moot on tenured mode in frozen world */
    uint64_t                  lreq_owed_genrace; /* retraction refused: newer intent */
    uint64_t                  lreq_owed_disp;    /* worker dispatches */
    uint64_t                  lreq_owed_stuck;   /* obligations past the escalation bar */
    uint64_t                  lreq_owed_left;    /* obligations still owed at teardown */
    /*
     * sess127 (GPT sess126 ruling, blocker 6 — the condvar lost-wakeup window).
     *
     * Guarded by lreq_lock and bumped inside the SAME critical section as every
     * event that can make an obligation runnable: a publication (lreq_owed_merge),
     * a clear window closing (lreq_clr_end, which can un-skip an entry the sweep
     * passed over), the departure of the last local attempt (lreq_finish, which
     * can turn a refused plan permissive), and the stop request itself.
     *
     * WHY A SEQUENCE AND NOT JUST THE BROADCAST.  Every broadcast is issued
     * OUTSIDE lreq_lock — deliberately, so the wakee does not immediately block
     * on a mutex the waker still holds.  That makes the broadcast lossy against
     * a worker that is between "decided to park" and "actually parked": the
     * signal lands with nobody waiting and the publication then sits out a full
     * idle interval.  The worker samples this counter inside the same locked
     * walk that chooses its claim set and refuses to park if it has moved, which
     * converts a lost edge into a re-check.  The broadcast remains as the fast
     * path; correctness rests on the counter.
     */
    uint64_t                  lreq_owed_work_seq;
    /*
     * sess120 (GPT sess118 ruling item 5 — "an ENOMEM fallback that proceeds
     * without registry coverage is a correctness defect").
     *
     * A destructive clear may not call the allocator.  Two independent reasons,
     * either sufficient:
     *
     *  1. It must fail CLOSED on allocation failure, and the fail-closed
     *     disposition of an unlock (leave the lock held, make every waiting
     *     peer re-BAST) is itself a cluster-wide stall.  Depending on the
     *     allocator for a path whose failure mode is that bad is a design
     *     defect even when the fallback is correct.
     *  2. mxfs_pal_alloc is GFP_KERNEL.  Reclaim entered from inside a DLM
     *     release can re-enter XFS writeback, which acquires the very DLM
     *     resource being released.  The DLM must not allocate under a lock
     *     whose reclaim path re-enters MXFS.
     *
     * So destructive paths draw registry entries from THIS pre-allocated
     * reserve instead.  It is restocked only from allocation-safe contexts
     * (mount, and the acquire path's existing outside-the-lock allocation),
     * and lreq_gc returns quiescent entries to it rather than freeing them,
     * which makes the steady state self-sustaining: an entry a destructive
     * clear creates goes straight back when that clear's window closes.
     *
     * Chained through mxfs_caw_lreq::next.  Guarded by lreq_lock.
     */
    struct mxfs_caw_lreq     *lreq_reserve;
    uint32_t                  lreq_reserve_n;
    uint64_t                  lreq_reserve_dry; /* destructive clear found it empty */
};

#define MXFS_CAW_SLOTHINT_SIZE  4096    /* direct-mapped hint entries */
/* sess4 (ccloop 46efd8b6): 4096 direct-mapped buckets gave birthday-certain
 * collisions for a 32-node run's ~200-resource working set, and a colliding
 * claim used to WIPE the victim's releasing mark + grant_seq (the v0.6.2
 * unlock protections) — 339 anchor-less releases in one run (065143Z).
 * 32768 x ~48B = ~1.5MB per mount; collisions become rare, and the no-wipe
 * waits in store/prebump/release_mark make the residual ones harmless. */
#define MXFS_CAW_GRANTMETA_SIZE 32768   /* direct-mapped grant-meta entries */
/* sess112: chain heads for the local request registry.  Sized for the
 * currently-contended working set (a 32-node board holds a few hundred live
 * resources at once), not for the whole slot table — entries are allocated on
 * demand and freed the moment a resource has no local attempt and no local
 * tenure, so this is a pointer array, not a preallocated entry pool. */
#define MXFS_CAW_LREQ_BUCKETS   1024
/* sess120: pre-allocated registry entries reserved for destructive clear
 * windows, which may not call the allocator (see ctx->lreq_reserve).  The high
 * water mark is the number of clear windows that can be open SIMULTANEOUSLY on
 * resources with no other local activity — one per thread in unlock /
 * give-up-cleanup / force-release, which on a 32-node board is a handful.  64
 * entries is ~7KB and leaves two orders of magnitude of headroom; running dry
 * is counted (P251-LREQ-DRY) and fails the clear closed rather than silently
 * dropping registry coverage. */
#define MXFS_CAW_LREQ_RESERVE   64
/* How long a destructive clear will wait for the reserve to be restocked by a
 * concurrent window closing before it gives up and fails closed.  Restocking is
 * a memory operation by another CPU, not disk I/O, so this is deliberately far
 * below any lock budget: if it does not come back in this long the reserve is
 * not merely contended, it is exhausted. */
#define MXFS_CAW_LREQ_RESERVE_WAIT_MS  20
#define MXFS_CAW_LREQ_RESERVE_STEP_MS   2
/*
 * ─── sess122: the owed-cleanup worker (GPT sess121 ruling, blocker 2) ───
 *
 * WHY A DEDICATED THREAD AND NOT THE BAST POLL THREAD.  The obligation's retry
 * is a destructive CAW loop against a contended slot; running it in the BAST
 * poll/callback path delays lock revocation for every OTHER resource, puts
 * cleanup behind path failover head-of-line, and admits a dependency cycle
 * (clear progress waiting on FS activity that a BAST is needed to trigger).
 *
 * WHY IT MAY NEVER GIVE UP.  A leaked EX-waiter bit is not cosmetic: every peer
 * defers fresh readers behind a request nobody is making, which is precisely
 * the measured 16-node >600s wedge.  So the worker retries with backoff
 * indefinitely; escalation means SHOUTING (P253) and, at teardown, refusing to
 * exit quietly (P254) — never dropping the record.
 */
/* CAS attempts per dispatch.  Deliberately small: persistence is provided by
 * re-dispatch with backoff, not by a long spin holding a worker slot against
 * every other entry's obligation (ruling item F, fairness). */
#define MXFS_CAW_OWED_TRIES        16
/* Entries the worker will dispatch in one sweep before going back to sleep, so
 * one hot resource cannot monopolise a pass. */
#define MXFS_CAW_OWED_DISPATCH_MAX 16
/* Idle park; the worker is normally woken explicitly, so this is only the
 * missed-wakeup safety net the ruling requires. */
#define MXFS_CAW_OWED_IDLE_MS      1000
/* Park after a sweep that dispatched something — come straight back for the
 * rest rather than waiting out the idle interval. */
#define MXFS_CAW_OWED_BUSY_MS      20
/* Per-entry backoff after a dispatch that did not discharge the obligation:
 * doubles from BACKOFF_MS up to BACKOFF_MAX_MS. */
#define MXFS_CAW_OWED_BACKOFF_MS     4
#define MXFS_CAW_OWED_BACKOFF_MAX_MS 500
/* Failed dispatches after which an obligation is reported as stuck. */
#define MXFS_CAW_OWED_ESCALATE     32
/* Teardown drain budget.  Unmount is not a RULE-0 workload path, but this
 * cannot be unbounded either: a genuinely dead LUN would hang the unmount.  On
 * expiry the residue is reported (P254) and membership withdrawal is what makes
 * the bits reclaimable by peers. */
#define MXFS_CAW_OWED_DRAIN_MS     2000
#define MXFS_CAW_OWED_DRAIN_STEP_MS 20
/*
 * ─── sess128 (GPT sess126 ruling, blocker 1): TIME BUDGETS, NOT RETRY COUNTS ───
 *
 * "A retry count is not a time bound."  The give-up cleanup CAS loop ran a fixed
 * 1000 attempts; at up to 8ms of backoff plus two slot I/Os apiece that is well
 * over ten seconds, so ONE teardown drain sweep (16 entries x 4 modes x that)
 * came to roughly 512s — against a DRAIN_MS that was only ever checked BETWEEN
 * sweeps.  Every collection path now carries an ABSOLUTE wall-clock deadline,
 * checked before each claim, each mode, each slot read, each CAW and each retry
 * sleep, and every retry-count policy on those paths is gone.
 *
 * WHAT A DEADLINE DOES AND DOES NOT BOUND.  It bounds the work a path will
 * START.  A slot I/O already in flight is NOT cancellable — mxfs_pal_bdev hands
 * it to the block layer, whose own timeout on a dead LUN is tens of seconds — so
 * the true worst case is (deadline + one block-layer I/O timeout), not the
 * deadline.  read_slot's retry loop does exit early once ctx->running is false,
 * which is the cheap half the drain gets for free.  These are BUDGETS.  Do not
 * describe any of them, in code or in a log line, as a hard bound.
 */
/* Give-up cleanup budget when the obligation IS recorded: the registry is
 * present, so the owed worker retries this indefinitely with backoff and the
 * calling thread — an XFS thread, mid-operation — has no reason to keep
 * spinning on a contended slot.  Short on purpose; persistence lives in the
 * worker now, which is the entire point of the sess122-127 machinery. */
#define MXFS_CAW_DROP_OWED_MS       200
/* ... and when it is NOT.  With no registry (its allocation failed at start)
 * there is no worker and no record, so the calling thread is the only collector
 * this bit will ever get, and leaving early is the permanent EX-waiter leak the
 * mechanism exists to prevent.  16s is an honest restatement of the wall time
 * the 1000-attempt loop it replaces actually consumed, not a new tolerance. */
#define MXFS_CAW_DROP_UNOWED_MS   16000
/* Per-entry budget for one dispatch in the RUNNING worker (the teardown drain
 * uses its own shared absolute deadline instead).  Bounds one hot resource's
 * hold on a worker pass in time as well as in mode count. */
#define MXFS_CAW_OWED_PASS_MS      1000
/* Entries the DRAIN claims per sweep.  ONE, so the deadline is re-checked
 * between every bounded operation: claiming 16 with 2s left is exactly the
 * shape that made DRAIN_MS meaningless. */
#define MXFS_CAW_OWED_DRAIN_CLAIM  1
/*
 * ─── sess131: the teardown QUIESCE budget ───
 *
 * How long mxfs_dlm_caw_stop waits for the operations already inside the
 * admission gate to leave.  DERIVED, not chosen: the longest an admitted
 * operation can legitimately take is one full grant wait
 * (MXFS_CAW_WAIT_TIMEOUT_MS) followed by the release CAS budget its unwind may
 * spend (MXFS_CAW_UNLOCK_DEADLINE_MS), plus one block-layer I/O timeout of
 * slack for the I/O that is already in flight when the deadline lands (see the
 * budgets note above: a deadline bounds work STARTED).
 *
 * The point of deriving it is that expiry must mean something.  A budget under
 * WAIT_TIMEOUT_MS would make escalation routine — every unmount that races one
 * slow acquire would report a failed quiesce — and an escalation that fires in
 * normal operation is not an escalation.  Expiry here means an operation has
 * exceeded every deadline the DLM itself imposes, which is a genuine fault.
 *
 * In the ordinary case this costs nothing: ops_active reaches zero in
 * microseconds and the wait returns on the first predicate test.  This is a
 * safety deadline, not a RULE-0 performance budget.
 */
#define MXFS_CAW_QUIESCE_MS  (MXFS_CAW_WAIT_TIMEOUT_MS + \
			      MXFS_CAW_UNLOCK_DEADLINE_MS + 30000)
/* Poll granularity for the quiesce wait — it is a condvar wait woken by the
 * last operation out, so this only bounds how long a LOST wakeup could cost. */
#define MXFS_CAW_QUIESCE_POLL_MS   50
/*
 * Re-report interval once the quiesce budget has expired.
 *
 * Expiry does not end the wait — teardown must not continue past a live
 * producer (see mxfs_dlm_caw_stop) — so the wait can in principle last as long
 * as the stuck operation does.  A single log line at expiry would leave an
 * operator watching an unmount that appears hung with no indication that the
 * DLM knows why.  30s is chosen against the kernel's own 120s hung-task
 * detector: several of these land before the generic warning does, so the
 * specific diagnosis arrives first.
 */
#define MXFS_CAW_QUIESCE_GRIPE_MS  30000
/*
 * ─── sess134 (GPT sess133 ruling B): THE MANDATORY FAIL-STOP DEADLINE ───
 *
 * MXFS_CAW_QUIESCE_MS expiring does NOT end a blocking teardown phase, and it
 * never grants permission to abandon one.  What it ends is the assumption that the
 * mount is merely slow.  At that point teardown latches the expiry, refuses the
 * clean departure for good, asynchronously asks the layer above to shut the
 * filesystem down — and starts ONE final grace.  If the grace also expires, the
 * node performs a non-returning local fail-stop.
 *
 * WHY FAIL-STOP AND NOT "GIVE UP AND RETURN".  Returning from a teardown phase
 * that could not finish means phases 3-6 must be skipped, so the BAST poll and
 * BAST multicast threads are still live.  They call ctx->bast_cb, which is
 * v5_bast_cb, which calls straight into closures holding the XFS mount — and
 * the VFS frees that mount regardless of anything the DLM decides.  Leaking the
 * CAW context does not save it; clearing bast_cb closes only the future window,
 * not the thread already past the NULL test.  A withdraw is not equivalent
 * either: it neither proves the wedged threads are gone nor makes freeing the
 * mount safe.  The alternatives are a permanent kernel hang or a known
 * use-after-free on shared-write clustered storage; a local fail-stop is the
 * only bounded answer that keeps this node off the LUN.
 *
 * WHY THE GRACE IS NOT "UNTIL SCSI EH FINISHES".  There is no portable upper
 * bound across SCSI EH, multipath failover, retries and driver bugs — keying
 * the deadline to it just moves the unbounded wait down a layer.  It is an
 * explicit policy interval instead, and mxfs_caw_failstop_grace_ms is clamped
 * on read so that it can never be configured to infinity on a shared-write
 * clustered mount.
 */
#define MXFS_CAW_FAILSTOP_GRACE_MS      45000
#define MXFS_CAW_FAILSTOP_GRACE_MIN_MS   5000
#define MXFS_CAW_FAILSTOP_GRACE_MAX_MS 300000
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
/*
 * sess134 (GPT sess133 ruling A1): stop() is IDEMPOTENT AND SERIALISING, not
 * merely idempotent.  Exactly one caller wins the transition to
 * MXFS_CAW_LC_STOPPING and runs teardown; every other caller BLOCKS until that
 * owner publishes MXFS_CAW_LC_STOPPED, and then reads the owner's stored
 * verdict.  A caller therefore never observes an intermediate teardown, and in
 * particular never returns free to destroy a context the owner is still inside.
 *
 * The wait is bounded because every blocking phase of teardown is bounded:
 * MXFS_CAW_QUIESCE_MS then MXFS_CAW_FAILSTOP_GRACE_MS, after which the node
 * fail-stops rather than waiting on.  A caller that cannot afford even that
 * bound must not call stop() from a context that holds up an unrelated
 * deadline; see the note on the escalation path in mxfs_dlm_caw.c.
 */
void mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx);

/*
 * sess131 teardown contract for the layer above (mxfs_v5_dlm_shutdown).
 *
 * set_release_on_stop() BEFORE stop(): false suppresses the wire release for a
 * WITHDRAWN mount, whose journal slice may be unreplayed.  Default is false, so
 * a caller that says nothing gets the conservative behaviour.
 *
 * departed_clean() AFTER stop(): the ONLY basis on which this node may announce
 * a clean departure — the GOODBYE broadcast and the heartbeat-slot release.  It
 * is true only when the quiesce completed, the release ran, the drain emptied
 * the obligation registry, and nothing was lost along the way.  A NULL ctx
 * answers true: a mount with no CAW context has no CAW bits to account for.
 *
 * unsafe_to_free() AFTER stop(): an operation admitted before teardown never
 * left.  Freeing the context would be a use-after-free; destroy() leaks it
 * instead, loudly.
 *
 * Both answers are the OWNER'S STORED VERDICT, read under lreq_lock (sess134,
 * ruling A1/A2): a caller that had to wait out another thread's teardown gets
 * that thread's conclusion, not a racing re-read of intermediate state.
 */
void mxfs_dlm_caw_set_release_on_stop(struct mxfs_dlm_caw_ctx *ctx, bool on);
bool mxfs_dlm_caw_departed_clean(struct mxfs_dlm_caw_ctx *ctx);
bool mxfs_dlm_caw_unsafe_to_free(struct mxfs_dlm_caw_ctx *ctx);

/*
 * ─── sess132 (GPT sess130 ruling, step 5): THE ESCALATION CHANNEL ───
 *
 * `fn` is invoked, with NO DLM lock held, when this mount has proved it can no
 * longer discharge an obligation to clear its own bits from the on-disk slot
 * table.  Peers block behind those bits, so this is a cluster-wide liveness
 * fault, not a local one.
 *
 * IT IS A NOTIFICATION OF A DECISION ALREADY MADE, never the decision itself
 * (ruling item 5).  Before `fn` runs, the DLM has already recorded the failure
 * under lreq_lock, closed admission, and revoked any claim to a clean
 * departure.  An unregistered, racing, or cancelled callback therefore cannot
 * turn an unclean departure into a clean one — it can only cost the mount the
 * chance to react.
 *
 * The registration is cleared under lreq_lock once the owed worker is joined,
 * so no escalation is ever issued after teardown owns the context.
 */
void mxfs_dlm_caw_set_owed_stuck_fn(struct mxfs_dlm_caw_ctx *ctx,
                                    void (*fn)(void *data), void *data);

/*
 * Membership context for the escalation diagnostic.  Call on every membership
 * change: `view` is a local generation counter, `members` the active count in
 * that view.  See mship_view in the ctx for why this is not called an epoch.
 */
void mxfs_dlm_caw_set_membership(struct mxfs_dlm_caw_ctx *ctx,
                                 uint64_t view, uint32_t members);

/* ─── Lock operations ─── */

/*
 * sess97 step 5.3(b): `gres` (optional, may be NULL) returns the immutable
 * provenance of the grant this call obtained — the resource, the durable
 * ex_grant_epoch, and the granted mode, all captured from the exact slot
 * image that carries them.  See struct mxfs_grant_result for why the epoch
 * may not be read back out of a cache afterwards.  On every failure path it
 * is left non-proving (valid == 0).
 */
int mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx,
                       const struct mxfs_resource_id *resource,
                       uint8_t mode, uint32_t flags,
                       uint8_t *granted_mode,
                       struct mxfs_grant_result *gres);
/* sess386 (474 leg A): mxfs_dlm_caw_lock with an ABSOLUTE mxfs_pal_time_ms
 * deadline (0 = unbounded).  Expiry cancels the waiter via the robust
 * drop-own-waiter path (grant-wins on the final read; handoff-vs-cancel
 * races reconcile through ABORT-RECONCILE) and returns -ETIMEDOUT.  For
 * acquires that must not block under a held AGI buffer / ILOCK. */
int mxfs_dlm_caw_lock_deadline(struct mxfs_dlm_caw_ctx *ctx,
                       const struct mxfs_resource_id *resource,
                       uint8_t mode, uint32_t flags,
                       uint8_t *granted_mode,
                       struct mxfs_grant_result *gres,
                       uint64_t deadline_ms);
/* sess290 (D-488 leg 7): acquire carrying the caller's ATTESTED in-core
 * published write-authority epoch for this resource (0 = none/surrendered).
 * Gates the already-held reaffirm: published==slot → reaffirm; published==0
 * with own bit set (outside the mount adopt window) → forced READOPT mint of
 * a fresh epoch via a real CAS — the surrendered epoch is never returned.
 * Attest ONLY from paths whose release-commit zeroes the published epoch
 * strictly after the Invariant-1 drain (the AG lock paths). */
int mxfs_dlm_caw_lock_attested(struct mxfs_dlm_caw_ctx *ctx,
                       const struct mxfs_resource_id *resource,
                       uint8_t mode, uint32_t flags,
                       uint64_t local_epoch,
                       uint8_t *granted_mode,
                       struct mxfs_grant_result *gres);

/* sess41 (GPT audit C1): open_op piggybacks this node's open-holder bit on
 * the release CAS itself — publication inseparable from release.  +1 sets
 * the bit (releasing while local fds/mappings live), -1 clears it (releasing
 * with no protected activity and a previously-published bit), 0 leaves it.
 * A failed unlock retains the grant AND skips the bit change — both sides
 * of the protection invariant stay consistent under every rc. */
int mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx,
                            const struct mxfs_resource_id *resource,
                            uint32_t expected_gen32, bool is_free,
                            int open_op);
int mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx,
                          const struct mxfs_resource_id *resource);
/* D-488 (sess273 ruling): unlock reporting the tri-state outcome
 * (enum mxfs_unlock_state, mxfs_dlm.h) proven by the body's own reads
 * and CAS results.  Callers that surrendered in-core tenure before the
 * release MUST use this and act on the outcome — a discarded rc is how
 * the stranded-EX-bit birth happened. */
int mxfs_dlm_caw_unlock_state(struct mxfs_dlm_caw_ctx *ctx,
                              const struct mxfs_resource_id *resource,
                              enum mxfs_unlock_state *state_out);

/* sess39: read-only — does this node hold the resource on disk? 1/0/<0 */
void mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource);
int mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx,
                      const struct mxfs_resource_id *resource);
/* ccloop cc87fed3 sess3: real (non-boolean) per-node granted mode — see
 * definition for why mxfs_dlm_caw_held's collapsed 0/1 is unsafe for
 * mxfs_v5_dlm_inode_granted_mode's CAW branch. */
/* sess41 (GPT audit C5): FAIL-CLOSED contract.  Returns 0 with *oh_out set
 * on a successful read; -errno when the bitmap could not be read (OOM,
 * probe failure, no live slot while the caller holds a grant).  The B6
 * defer guard must treat any error as "peers may hold this open" (defer),
 * never as an empty bitmap. */
int mxfs_dlm_caw_open_holders(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      uint64_t *oh_out);
void mxfs_dlm_caw_open_clear(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource);
/* sess46 (iclus open tracking): durable standalone SET of this node's open
 * bit — allocates a live bit-only slot when the resource has no record
 * (routed files never per-inode lock).  0 = durably set; any error must
 * GATE the caller's cluster-resource release (publication-before-release). */
int mxfs_dlm_caw_open_set(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource);
/* sess46: B6 read for a caller holding no per-inode claim (routed freer
 * holds the CLUSTER EX).  0 + bits = union across every same-resource
 * record (live or tombstone); 0 + *oh_out==0 + *authoritative = provable
 * absence (clean chain to terminator); negative = defer (fail closed). */
int mxfs_dlm_caw_open_probe(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint64_t *oh_out, bool *authoritative);
uint8_t mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource);

/* sess19: read the shared on-disk slot generation (cross-node AG epoch). */
int mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx,
                                 const struct mxfs_resource_id *resource,
                                 uint64_t *out_gen);

/* sess48's mxfs_dlm_caw_read_ex_grant_epoch() was DELETED in sess110 — an
 * out-of-band epoch read cannot be bound to the grant the caller holds.
 * Authority epochs come out of the granting CAS via struct mxfs_grant_result
 * (the gres out-param on mxfs_dlm_caw_lock / _convert).  See dlm_caw.c. */

/*
 * sess165 (D-FOREIGN-REPLAY-UNGATED-IMAGES step 5, shadow evaluator) —
 * CONSUMER-ONLY read of one slot of a FENCED VICTIM's held-at-death manifest.
 *
 * This is NOT the sess110-deleted producer primitive coming back.  That one
 * read ex_grant_epoch out of band to STAMP it into new log records as write
 * authority, and no second read can prove the epoch it saw belongs to the
 * grant the caller holds.  This one runs on the CONSUMER side of the same
 * token: foreign/adopted log replay comparing a dead node's recorded epoch
 * against the slot state its fencing froze.  The value is stable not because
 * the caller holds the grant but because the victim is fenced (it cannot CAS)
 * and recovery purges its bits only after MXFS_RECOV_STAGE_IMAGES_REPLAYED —
 * i.e. after every caller of this function is done.  The result must NEVER
 * be stamped into new log records or fed to any producer-side path.
 *
 * *out_holds_ex = victim_slot's bit in (holders_ex | holders_pw) — the
 * exclusive-class manifest bit; ex_grant_epoch is only meaningful when it is
 * set (the field is left stale on release by design).  Returns 0 with outputs
 * filled, -ENOENT if no live slot exists for `resource` (the victim cannot
 * hold what was never locked), or a negative I/O error.  Read-only.
 *
 * sess177: *out_lineage = the slot's resource_lineage, taken from the SAME
 * slot image as the other outputs (sess175 ruling Q-C: no second read — a
 * lineage from a different read instant could disagree with the hold bitmap
 * and epoch it is compared against).  0 = binding minted pre-lineage.
 * EQUALITY COMPARISONS ONLY.
 */
int mxfs_dlm_caw_victim_manifest_read(struct mxfs_dlm_caw_ctx *ctx,
                                      const struct mxfs_resource_id *resource,
                                      uint32_t victim_slot,
                                      bool *out_holds_ex,
                                      uint64_t *out_ex_grant_epoch,
                                      uint64_t *out_lineage);

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
 * the normal hinted/seq-gated unlock left set).  `att` is REQUIRED; see above.
 * Returns #slots cleared, or <0 (-EINVAL on an incomplete attestation). */
int mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx,
                                    const struct mxfs_resource_id *resource,
                                    const struct mxfs_forcerel_attest *att);

int mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx,
                           const struct mxfs_resource_id *resource,
                           uint8_t new_mode,
                           struct mxfs_grant_result *gres);

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

/* sess309: record a WEDGED-release pin — release_all will refuse to clear
 * this node's bits on the resource's slot (counted `lost`, departure not
 * clean).  Idempotent per resource; -ENOSPC past MXFS_CAW_MAX_PINNED. */
int mxfs_dlm_caw_pin_resource(struct mxfs_dlm_caw_ctx *ctx,
                              const struct mxfs_resource_id *res);

/* ─── Node failure ─── */

int mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx,
                              uint8_t dead_slot);

/* Purge stale locks from multiple dead nodes in a single pass.
 * dead_mask is a 64-bit bitmap: bit N set means node slot N is dead.
 * Called at mount time to clear orphan holder bits from crashed nodes. */
int mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx,
                                    uint64_t dead_mask);

/*
 * sess52 (D-FOREIGN-REPLAY step 4a) — flagged form of the above.
 *
 * MXFS_CAW_PURGE_KEEP_EX
 *   Strip the dead slot's PR/CW/CR, waiter and open-holder bits but
 *   LEAVE holders_ex/holders_pw intact, and never tombstone the slot
 *   (a tombstone loses the holder bits, destroying the very authority
 *   token the foreign-replay gate reads).  Used for our OWN slot at
 *   mount: the retained EX/PW bits are the manifest proving our
 *   previous incarnation had cross-slice write authority, and
 *   xlog_recover must run under them, not after they are erased.
 *
 * MXFS_CAW_PURGE_SKIP_TRACKED
 *   Skip any slot currently present in ctx->held, i.e. one this mount
 *   has actively acquired (or adopted — see mount_adopt_window).  Used
 *   for the post-recovery settle sweep of our own slot, so it clears
 *   only the retained bits nothing re-adopted and never strips a live
 *   hold out from under the running filesystem.
 *
 * flags == 0 is byte-for-byte the legacy behaviour.
 */
#define MXFS_CAW_PURGE_KEEP_EX          0x1u
#define MXFS_CAW_PURGE_SKIP_TRACKED     0x2u

int mxfs_dlm_caw_purge_dead_nodes_ex(struct mxfs_dlm_caw_ctx *ctx,
                                     uint64_t dead_mask, uint32_t flags);

/*
 * sess58 — read-only census of what node_mask still owns in the table.
 * Returns the slot count carrying any footprint (holder/waiter/open-holder)
 * of the mask, *out_ex the subset holding EX or PW, or -EIO/-ENOMEM if the
 * table could not be read in full (which callers MUST treat as "still
 * owns things", never as zero).  See the definition for why the mount
 * recovery barrier needs it.
 */
int mxfs_dlm_caw_footprint_scan(struct mxfs_dlm_caw_ctx *ctx,
                                uint64_t node_mask, int *out_ex);

/* sess52: open/close the mount adopt window (see ctx->mount_adopt_window).
 * Returns the number of EX/PW slots retained by the last KEEP_EX purge. */
void mxfs_dlm_caw_set_adopt_window(struct mxfs_dlm_caw_ctx *ctx, bool on);
int  mxfs_dlm_caw_retained_count(struct mxfs_dlm_caw_ctx *ctx);

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

/*
 * sess374 (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356, sess363 RULE-5 ruling).
 *
 * mxfs_dlm_caw_set_closure_scrub_fn registers the survivor-side scrub oracle
 * (see closure_scrub_fn in the ctx).  Registered by v5_mount alongside the
 * liveness oracle; must be unregistered (NULL) before the ctx it closes over
 * goes away.
 *
 * mxfs_dlm_caw_purge_victim_selective force-revokes ONE victim's CAW state on
 * every slot where `classify` proves the resource lies outside the victim's
 * quarantined domain.  Run by the refusal publisher while it still holds the
 * recovery lease.
 *
 *   classify(carg, res)  >0 provably out of closure (strip)
 *                         0 in closure / ambiguous (freeze — the safe way)
 *                        <0 error: abort, retry required
 *   gate(garg)            0 the caller's authority + the victim's terminal
 *                           verdict still hold; anything else aborts.  Called
 *                           at phase 0 and again immediately before EVERY
 *                           destructive CAS — never amortized.  May be NULL
 *                           only when the classifier itself gates.
 *
 * Returns 0 only when the scan ran to completion with every candidate either
 * stripped or deliberately kept.  Negative otherwise — the gate's rc when it
 * refused, or -EIO when any candidate could not be read or rewritten.
 * *out_purged counts successful CASes only and is valid on every return; a
 * partial result NEVER reports success (ruling item C).
 */
/* Registers the wait-cancellation oracle (see wait_refuse_fn in the ctx).
 * The callback MUST be lockless and must not do I/O: it runs on every poll
 * lap of every blocking acquire. */
void mxfs_dlm_caw_set_wait_refuse_fn(struct mxfs_dlm_caw_ctx *ctx,
                                     int (*fn)(void *data,
                                               const struct mxfs_resource_id *res),
                                     void *data);
void mxfs_dlm_caw_set_closure_scrub_fn(struct mxfs_dlm_caw_ctx *ctx,
                                       int (*fn)(void *data,
                                                 uint8_t blocking_slot,
                                                 const struct mxfs_resource_id *res),
                                       void *data);
/* Publishes the skip-only candidate hint (see closure_cand_mask).  Called by
 * v5 whenever the set of imported terminal AG_MASK verdicts changes. */
void mxfs_dlm_caw_set_closure_cand_mask(struct mxfs_dlm_caw_ctx *ctx,
                                        uint64_t mask);
int mxfs_dlm_caw_purge_victim_selective(struct mxfs_dlm_caw_ctx *ctx,
                                        uint8_t victim_slot,
                                        int (*classify)(void *arg,
                                                const struct mxfs_resource_id *res),
                                        void *carg,
                                        int (*gate)(void *arg),
                                        void *garg,
                                        uint32_t *out_purged,
                                        uint32_t *out_kept);

#endif /* MXFS_LIBMXFS_DLM_CAW_H */
