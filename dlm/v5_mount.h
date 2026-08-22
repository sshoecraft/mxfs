/*
 * MXFS — Multinode XFS
 * v5 DLM→XFS Integration Shim
 *
 * Wires the portable DLM engine (dlm.c, dlm_caw.c, peer.c, discovery.c,
 * lease.c, disklock.c, scsipr.c, journal.c) into kernel XFS v5.
 *
 * Replaces dlm/mount.c from mxfs.1 which depended on the custom cache
 * layer (block_cache, inode_cache, dir_cache, alloc).  v5 uses kernel
 * XFS natively — the DLM hooks into xfs_ilock/iunlock and xfs_alloc.
 *
 * This header is used by BOTH the DLM code (PAL world) and the XFS
 * kernel code.  It avoids including XFS headers — all XFS interaction
 * goes through opaque pointers.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_DLM_V5_MOUNT_H
#define MXFS_DLM_V5_MOUNT_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"

/* ─── DLM transport selection ─── */

#define MXFS_V5_TRANSPORT_CAW   0
#define MXFS_V5_TRANSPORT_TCP   1
#define MXFS_V5_TRANSPORT_AUTO  2

/* ─── Opaque v5 DLM context ─── */

struct mxfs_v5_dlm;
/* sess121: defined in dlm_caw.h; callers of the force-release pass-through
 * below include that header for the definition. */
struct mxfs_forcerel_attest;

/* ─── Init options ─── */

struct mxfs_v5_dlm_opts {
    int             transport;          /* MXFS_V5_TRANSPORT_* */
    uint16_t        dlm_port;           /* TCP port (default 7600) */
    uint16_t        discovery_port;     /* UDP port (default 7601) */
    uint64_t        journal_offset;     /* from MXFS on-disk super */
    uint64_t        disklock_offset;    /* from MXFS on-disk super */
    uint32_t        max_nodes;          /* from MXFS on-disk super */
    void            *bdev;              /* struct block_device * (kernel) */
    uint8_t         volume_uuid[16];    /* XFS superblock UUID */
    /*
     * v5 sess33: cap on locally-tracked held CAW DLM locks.  0 = use
     * MXFS_CAW_MAX_HELD compile-time default.  Filled by xfs_super.c
     * fill_super from mxfs_cache_caps.dlm_lock (auto-sized at module
     * load from cache_mem_pct module param + host RAM).
     */
    int             max_dlm_lock_caw;
    /*
     * v0.5.0: dead-node detection window in ms.  0 = compile-time default
     * (MXFS_DISKLOCK_DEAD_THRESHOLD × HB interval = 62 s, the production-
     * conservative value).  Test rigs set this low (e.g. 15000) so crash
     * recovery — lock purge + foreign-slice replay — fires promptly.
     * Filled from the lease_timeout_ms module param.
     */
    uint32_t        lease_timeout_ms;
    /*
     * sess65: number of per-node XFS log slices this volume was formatted
     * with (MXFS on-disk super xfs_log_node_count; 0 = no per-node slices).
     * A dead node's slice is the IDENTICALLY numbered slice; a slot beyond
     * this count owns no slice at all (D-LOG-SLICE-SHARED-MULTIWRITER —
     * the old modulo mapping aliased many slots onto one slice).  The
     * durable recovery descriptor records both index and count so it stays
     * self-describing if the volume is ever re-formatted differently.
     */
    uint32_t        log_node_count;
    /*
     * Fix 3c (sess180 ruling, D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE):
     * operator assertion that NO other initiator can write this bdev
     * (single-host deployment, non-shared disk, exclusive LUN masking).
     * Filled from the single_node_exclusive module param, default 0.
     * When set AND cluster membership is single-node at fence time, a
     * dead slot whose exclusion the PR machinery cannot prove (no PR
     * context, or PREEMPT AND ABORT unsupported by the target) may be
     * certified MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE so its dirty
     * journal slice can be replayed instead of blocking forever.
     */
    bool            single_node_exclusive;
    /*
     * sess378: when the admission-time fencing-capability check
     * (mxfs_scsipr_validate_admission) fails, the default is to REFUSE the
     * mount.  The sess93 RULE-5 ruling requires that a rig which cannot
     * produce fencing evidence be EXPLICITLY single-node, read-only or given
     * another fencing provider — never silently given weaker production
     * semantics.  This knob is that explicit operator statement; it makes the
     * downgrade loud and attributable instead of invisible.  Default 0.
     */
    bool            fence_capability_override;
};

/* ─── Lifecycle ─── */

/*
 * Initialize all DLM subsystems.
 * Returns opaque context on success, NULL on failure.
 * The caller (XFS mount code) stores this in mp->m_mxfs_dlm.
 */
struct mxfs_v5_dlm *mxfs_v5_dlm_init(const struct mxfs_v5_dlm_opts *opts);

/*
 * Shut down all DLM subsystems and free the context.
 */
void mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx);

/*
 * sess192 (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE Arm C): a clean
 * teardown used to zero its heartbeat slot INSIDE shutdown, before XFS
 * wrote the unmount record — a crash in that window left a dirty journal
 * slice behind an EMPTY (consumable) slot, the same silent loss as the
 * closed Arm A/B, just crash-timed.  Per the sess180 ruling the slot may
 * become consumable only once the clean unmount is DURABLE, so the
 * release is split out of shutdown the same way the PR key is:
 *
 *   struct mxfs_v5_dlm_slot_release late = {0};
 *   mxfs_v5_dlm_shutdown_defer_release(ctx, &late);
 *   ...xfs_unmountfs() — unmount record forced with PREFLUSH|FUA...
 *   mxfs_v5_dlm_slot_release_commit(&late, unmount_clean);
 *
 * shutdown_defer_release fills `late` ONLY on a depart_clean teardown
 * (heartbeat already stopped, slot still ACTIVE on disk); every other
 * disposition behaves exactly like mxfs_v5_dlm_shutdown.  commit zeroes
 * the slot iff unmount_clean, otherwise leaves it ACTIVE so peers fence
 * and recover the slice, then destroys the disklock and closes the dev
 * clone whose ownership travelled with it.  commit is a no-op on an
 * unfilled struct, so it is safe to call unconditionally.
 */
struct mxfs_disklock_ctx;
struct mxfs_v5_dlm_slot_release {
    struct mxfs_disklock_ctx *disklock; /* heartbeat stopped; slot ACTIVE */
    mxfs_bdev_t              *dev;      /* dev clone the disklock borrows */
};
void mxfs_v5_dlm_shutdown_defer_release(struct mxfs_v5_dlm *ctx,
                                        struct mxfs_v5_dlm_slot_release *late);
void mxfs_v5_dlm_slot_release_commit(struct mxfs_v5_dlm_slot_release *late,
                                     bool unmount_clean);

/*
 * v0.11.74: detach the SCSI PR registration from the ctx before
 * shutdown and return its key (0 if none/no PR).  The caller owns the
 * deferred unregister, issued via mxfs_pal_scsi_pr_unregister_bdev
 * AFTER the unmount log record is on disk — unregistering inside
 * shutdown fenced the node's own final log write on WE-RO targets.
 */
uint64_t mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx);

/*
 * sess9 (ccloop a864): owning FS force-shut-down (still mounted) — leave the
 * cluster: fence all new acquires (inode + AG return -ESHUTDOWN) and stop the
 * disklock heartbeat so peers' dead-node purge reclaims our slots.  Sleeps
 * (<=5s thread join); process context only.  Idempotent.
 */
void mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx);
/* sess9 (ccloop c7ee71c6) D2: called by the elected replayer after the
 * dead node's slice is durably replayed — shared purges + zeroing the
 * dead HB slot (the cluster-wide "replay done" signal). */
/* sess43 recovery-guard passthroughs (unclaimed-bucket sweep exclusion):
 * semantics documented on the mxfs_disklock_* originals in disklock.h. */
int  mxfs_v5_dlm_local_slot(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_slot_unclaimed(struct mxfs_v5_dlm *ctx, int slot);
int  mxfs_v5_dlm_guard_slot(struct mxfs_v5_dlm *ctx, int slot);
int  mxfs_v5_dlm_guard_refresh(struct mxfs_v5_dlm *ctx);
void mxfs_v5_dlm_unguard_slot(struct mxfs_v5_dlm *ctx);

/* sess59 (GPT item 6D): returns 0 when the recovery was PUBLISHED (CAW
 * authority purged, flushed durable, dead heartbeat provably zeroed), or a
 * negative errno when nothing was published — in which case the pending
 * marker and heartbeat record are still set and the completion is owed. */
int  mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx,
                                   uint32_t dead_slot);

/*
 * sess93 — THE REPLAY GATE.  Acquire (or revalidate) the recovery EXECUTION
 * LEASE for a dead peer's journal slice.  Returns 0 only when a FENCE
 * CERTIFICATE on the victim's own heartbeat sector proves that victim was
 * excluded from the LUN, AND this node holds the lease to act on it.
 *
 * Every destructive step of a foreign-slice recovery must be behind this:
 * the log replay, the CAW authority purge, each milestone advance, and the
 * sector zero that broadcasts "recovered".  Until sess93 nothing asked, which
 * is D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION: exclusion was proved by one
 * node and consumed by another, and the proof had nowhere to go.
 *
 * The lease is held across the whole recovery (claim once, not per step) so a
 * takeover that happens while we work surfaces as -EBUSY instead of two nodes
 * publishing the same slice.
 *
 *   0         authorised
 *   -EPERM    no certificate yet — WAIT and ask again.  There is no timeout
 *             after which replay becomes allowed.
 *   -EBUSY    another survivor owns the recovery and we have not proved it dead
 *   -ENOENT   no descriptor: never fenced, or already published
 *   -ESTALE   the descriptor names a different victim/incarnation
 *   -ENODATA  no pending victim identity recorded for this slot
 *
 * MUST NOT be called from the heartbeat-monitor thread: the takeover arm
 * sleeps MXFS_RECOV_ABANDON_MS.
 */
int  mxfs_v5_dlm_recovery_acquire(struct mxfs_v5_dlm *ctx, uint32_t dead_slot);
/* Drop our cached lease tuple for a slot (the platter stays authoritative). */
void mxfs_v5_dlm_recovery_release(struct mxfs_v5_dlm *ctx, uint32_t dead_slot);

/*
 * ── sess93: RECOVERY_BLOCKED_FENCE — the observable state ─────────────────
 *
 * Everything above fails CLOSED: when exclusion cannot be proved, or has
 * lapsed, MXFS refuses to replay the dead peer's journal slice, refuses to
 * release its grants, and refuses to zero its sector.  That is correct, and it
 * is also indistinguishable — from outside — from a filesystem that is simply
 * hung, because peers block on the frozen victim's locks either way.
 *
 * MEASURED (tests/excl_lapse_probe.sh, 0.11.424): a slice whose exclusion had
 * lapsed retried every ~30 s indefinitely with the whole story visible only in
 * dmesg.  GPT (RULE-5 ruling sess93, Q2): "Add an explicit durable and
 * observable state, not merely repeated log lines... Mount status should
 * clearly say that the filesystem is blocked on unproven exclusion, rather
 * than appearing hung."
 *
 * This is that state.  It is per victim SLOT, set at every refusal point, and
 * cleared only when the recovery actually publishes.  The durable half already
 * exists on the platter (a descriptor stuck below FENCED, or one whose
 * certificate no longer holds); this record is what makes it answerable
 * without a raw sector read.
 */
#define MXFS_RBLK_NONE              0
#define MXFS_RBLK_NO_PR             1  /* no SCSI PR context: no evidence possible */
#define MXFS_RBLK_FENCE_UNPROVEN    2  /* the attempt ran and proved nothing */
#define MXFS_RBLK_CERT_UNRECORDED   3  /* PROVED but the certificate is not durable —
                                        * the victim key is consumed, so no successor
                                        * can prove it again.  Operator action. */
#define MXFS_RBLK_NO_INTENT         4  /* the intent could not be made durable */
#define MXFS_RBLK_NO_CERTIFICATE    5  /* waiting for some prover's certificate */
#define MXFS_RBLK_OWNED_ELSEWHERE   6  /* another survivor owns it, not proved dead */
#define MXFS_RBLK_EXCL_LAPSED       7  /* the fenced victim came BACK */
#define MXFS_RBLK_SELF_FENCED       8  /* our own PR key is gone */
#define MXFS_RBLK_NO_INCARNATION    9  /* no detector observed the victim's incarnation */
#define MXFS_RBLK_SN_LAPSED         10 /* kind-17: a peer appeared, or the operator
                                        * single_node_exclusive assertion was withdrawn,
                                        * while the recovery ran (sess188) */
#define MXFS_RBLK_NO_LOG_SLICE      11 /* victim slot >= log slice count: it has no
                                        * slice of its own, so any slice this path
                                        * could name belongs to a DIFFERENT slot */

struct mxfs_recov_blocked {
    uint32_t        reason;         /* MXFS_RBLK_* */
    int32_t         last_rc;
    mxfs_node_id_t  victim_node;
    uint64_t        victim_epoch;
    uint64_t        victim_key;
    uint16_t        victim_slot;
    uint16_t        fence_kind;     /* last observed enum mxfs_fence_kind */
    uint16_t        resv_type;      /* reservation type observed at the refusal */
    uint16_t        fence_term;
    mxfs_node_id_t  prover_node;    /* whoever holds/held the fencing attempt */
    mxfs_node_id_t  owner_node;     /* whoever holds the execution lease */
    uint32_t        pr_generation;
    uint32_t        attempts;
    uint64_t        first_ms;       /* when this slot first went blocked */
    uint64_t        last_ms;        /* most recent attempt */
};

const char *mxfs_recov_blocked_reason(uint32_t reason);
/* Iterate blocked slots: first call prev = -1.  Returns the next blocked slot
 * (> prev) with *out filled, or -1 when exhausted. */
int  mxfs_v5_dlm_blocked_iter(struct mxfs_v5_dlm *ctx, int prev,
                              struct mxfs_recov_blocked *out);

/*
 * sess53 (D-FOREIGN-REPLAY step 4a): post-recovery mount settle.  Closes
 * the two-phase mount reclaim — releases our previous incarnation's
 * un-adopted authority bits, closes the adopt window, and routes the
 * stale peer slots deferred at mount step 6.5 into fence + slice
 * recovery.  MUST be called after log recovery is durable and after the
 * dead-node notify hook is registered.  Returns 0, or a negative errno
 * if the own-slot reclaim was refused (mount continues; slots leak).
 */
int  mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx);
/* sess58: can the mount barrier's unresolved (unfenceable) residue block
 * xfs_log_mount_finish?  0 = no, 1 = yes, <0 = could not tell (treat as 1). */
int  mxfs_v5_dlm_mount_residue_blocking(struct mxfs_v5_dlm *ctx,
                                        uint64_t *out_residue,
                                        int *out_nslots, int *out_nex);

/*
 * sess56 (D-FOREIGN-REPLAY step 4a — MOUNT ORDERING FIX).  The pieces of
 * the settle that MUST run before xfs_mountfs can take a cluster lock,
 * split out for the pre-mountfs recovery barrier:
 *
 *   _settle_own_slot            phases 1-2: release our previous
 *                               incarnation's un-adopted authority bits
 *                               (their only consumer, our own image
 *                               replay inside xfs_log_mount, is done) and
 *                               close the adopt window.
 *   _mount_recovery_cohort      confirm + fence + mark-pending every
 *                               cross-instance slot recorded at step 6.5;
 *                               returns the resolved mask.  Purges
 *                               nothing — the caller replays each slice.
 *   _mount_cohort_complete      the deferred purges, once the WHOLE
 *                               cohort is durably replayed.  sess59: fills
 *                               *out_published with the subset actually
 *                               PUBLISHED and returns 0 only when that is
 *                               the whole input mask.
 */
int  mxfs_v5_dlm_settle_own_slot(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_mount_recovery_cohort(struct mxfs_v5_dlm *ctx,
                                       uint64_t *out_slots);
int  mxfs_v5_dlm_mount_cohort_complete(struct mxfs_v5_dlm *ctx,
                                       uint64_t slots,
                                       uint64_t *out_published);

/*
 * sess62 (GPT sess57 review item 6B) — peers that die WHILE we are mounting.
 *
 * The cohort above is a SNAPSHOT: it covers peers already frozen when we
 * arrived.  A peer that was healthy then and freezes during the barrier's
 * ~62 s confirmation window is detected by the heartbeat monitor, which
 * fences it and marks its slice recovery-pending — but cannot dispatch the
 * replay, because the slice-replay hook is registered only after
 * xfs_mountfs returns.  It records the slot instead.
 *
 *   _take_late_deaths     drain and clear the record.  Every returned slot
 *                         is fenced, durably recovery-pending, and has its
 *                         CAW grants frozen — replayable inline exactly
 *                         like a cohort slot.
 *   _defer_late_deaths    give back what was not durably replayed AND
 *                         published, so the post-mount settle dispatches it.
 *
 * Anything left in the record when the DLM tears down is reported by
 * P233-MPHASE-UNDISPATCHED; it stays fenced and pending on disk, so the
 * next mount or a survivor's re-election sweep still recovers it.
 */
uint64_t mxfs_v5_dlm_mount_take_late_deaths(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_mount_pending_recovery(struct mxfs_v5_dlm *ctx,
                                        uint64_t *out_mask);
void mxfs_v5_dlm_mount_defer_late_deaths(struct mxfs_v5_dlm *ctx,
                                         uint64_t slots);

bool mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx);

/* ─── Inode lock interface ─── */

/*
 * sess97 step 5.3(b): `gres` (optional, may be NULL) returns the immutable
 * provenance of the grant obtained — see struct mxfs_grant_result.  It is
 * initialised to non-proving on entry, so a NULL-transport, TCP, or failure
 * path leaves it unable to authorise anything.
 */
int  mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino,
                             uint8_t mode, struct mxfs_grant_result *gres);
/* sess58: short per-call retry budget; caller loops + re-yields cached AGs. */
int  mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino,
                             uint8_t mode, int retries,
                             struct mxfs_grant_result *gres);
void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess171 (D-EX-GRANT-EPOCH verification vehicle, RULE-5 approved sess170):
 * drive the real CAW lock/convert/unlock paths on a geometry-reserved
 * unallocatable inode key and assert the tenure-token contract (mint /
 * convert-preserve / re-mint / acquire-upgrade-preserve).  Synchronous,
 * seconds-scale; caller must serialize runs and must NOT hold XFS locks.
 * 0 = PASS; -EREMOTEIO = assertion failed; other -errno = infra refusal.
 * Verdict + per-step evidence on the P274-PWTEST log lines. */
int  mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* ccloop cc87fed3 sess8: use in place of mxfs_v5_dlm_inode_unlock when the
 * caller has already verified nlink==0 and is doing destructive inactivation
 * (a genuine free, not an idle-gap release).  CAW transport piggybacks a
 * dir_epoch/last_ex_slot clear onto the unlock's own tombstone CAS so a
 * reused ino doesn't inherit a stale cross-node-handoff signal; zero extra
 * I/O.  TCP transport: identical to the plain unlock (no epoch concept). */
void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess7 FIX-20b: phantom-grant reconcile (mirror-bypassing gen=0 release). */
int  mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx,
                                             uint64_t ino);
/* sess1(a9a03929): gen-aware release — -ESTALE = a newer tenure owns the
 * resource; caller must re-arm its BAST instead of assuming released. */
/* sess41 (GPT audit C1): release with atomic open-bit change (open_op:
 * +1 set self bit, -1 clear self bit, 0 leave).  See dlm_caw.h. */
int  mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                   uint32_t expected_gen, int open_op);
int  mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t expected_gen);
void mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino);
int  mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                int *nslots_out);
/* ccloop a864 sess3: duplicate-immune self-EX check (full-chain scan).  1 if
 * this node holds `ino` EX on disk (any live slot), else 0.  CAW only.
 * *nslots_out = live-slot count; *hex_or_out = OR of holders_ex.  Read-only. */
int  mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                      int *nslots_out, uint64_t *hex_or_out);
/* ccloop a864 sess3: unconditional scan-based self-release (orphan-bit reclaim).
 * CAW only.  Caller holds the DEMOTING claim.  Returns #slots cleared. */
/* sess121: `att` is REQUIRED — see struct mxfs_forcerel_attest in dlm_caw.h.
 * An absent or incomplete attestation REFUSES the release with -EINVAL. */
int  mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                          const struct mxfs_forcerel_attest *att);

/* sess55: producer bridge for the inode-eviction ring (called from xfs_ifree). */
void mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen);

/* sess80: producer bridge for a dir-modify eviction-ring entry (called from the
 * dir-modify chokepoints xfs_dir_createname/removename/replace). */
void mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino);

/* sess56: register the eviction-ring consumer (the XFS-layer callback that
 * flags a stale NL-cached inode / bumps a peer-modified dir's gen).  Forwards
 * to the disklock layer. */
void mxfs_v5_dlm_set_evict_cb(struct mxfs_v5_dlm *ctx,
                              void (*cb)(void *data, uint64_t ino,
                                         uint32_t gen, uint32_t type),
                              void *data);

/*
 * sess323 (sess320 ruling, D-513): terminal recovery-refusal channel.
 * Both types are defined in dlm/disklock.h; XFS-side callers include it.
 *
 * set_quarantine_cb registers the XFS-layer consumer fired (heartbeat
 * thread) once per imported (victim_epoch, publish_seq) terminal outcome.
 * recovery_publish_refusal is called by the elected replayer that holds the
 * recovery execution lease for dead_slot when replay of the victim's slice
 * is REFUSED (policy or torn): it durably quarantines the descriptor and
 * publishes the outcome record so every survivor converges on the same
 * quarantine domain instead of timing out into shutdown.  On failure the
 * refusal is NOT durable — the caller keeps its retry path armed.
 */
struct mxfs_recov_outcome;
struct mxfs_recov_refusal_info;
/* sess383 (RULE-5 ruling Q1): the consumer VALIDATES and returns an
 * enum mxfs_quar_disposition (dlm/disklock.h).  Callers may act on the record
 * beyond importing it — closure candidacy in particular — ONLY on a VALID_*
 * disposition, and never by inferring validity from the fact that something
 * was imported: a rejected record imports FSWIDE by design. */
void mxfs_v5_dlm_set_quarantine_cb(struct mxfs_v5_dlm *ctx,
                                   int (*cb)(void *data, int victim_slot,
                                        const struct mxfs_recov_outcome *oc),
                                   void *data);
int mxfs_v5_dlm_recovery_publish_refusal(struct mxfs_v5_dlm *ctx,
                                    int dead_slot,
                                    const struct mxfs_recov_refusal_info *info,
                                    struct mxfs_recov_outcome *oc_out);
/* sess327 (sess325 ruling items 2+4): canonical-outcome read (return contract
 * in disklock.h) and the synchronous registration-time scan that replays
 * already-terminal verdicts into quar_cb before ops are exposed. */
int mxfs_v5_dlm_recovery_read_outcome(struct mxfs_v5_dlm *ctx, int dead_slot,
                                      struct mxfs_recov_outcome *oc_out);
/*
 * sess374 (sess363 RULE-5 ruling, D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356):
 * after publish_refusal lands and BEFORE the caller releases the recovery
 * lease, force-revoke the victim's provably out-of-closure CAW grants so
 * survivors blocked on out-of-domain resources stop running to -110.
 *
 * expect_victim / expect_ag_mask are the victim and domain of the CANONICAL
 * outcome the caller has already imported and is enforcing.  The platter gate
 * is re-read and must reproduce them exactly, at phase 0 and again before
 * every destructive CAS; any drift is -ESTALE and nothing further is
 * stripped.  There is deliberately no zero sentinel — node 0 is a valid
 * victim, so the expectation is always passed in explicitly.
 *
 * classify returns >0 = the resource is PROVABLY outside the quarantined
 * domain (purgeable), 0 = in-domain / ambiguous (stays frozen), <0 = error
 * (aborts; an errno must never be read as "keep").  The v5 layer additionally
 * freezes any resource whose volume is not this mount's.
 *
 * Returns 0 only on a complete scan; -EPERM without the lease, -ESTALE on
 * verdict drift, the gate's rc when it refuses, -EIO when any candidate could
 * not be read or rewritten.  *out_purged counts landed CASes only and is
 * valid on every return: a partial result NEVER reports success, and the
 * caller must not log the purge as complete on one.
 *
 * mxfs_v5_dlm_set_closure_classify_fn registers the same AG-domain judgement
 * for the SURVIVOR-side demand scrub (dlm_caw's wait and NOQUEUE chokepoints),
 * which has no lease and no caller to pass a domain in — it derives the domain
 * from the blocking node's own terminal verdict and asks this callback.
 */
int mxfs_v5_dlm_recovery_purge_out_of_closure(struct mxfs_v5_dlm *ctx,
                                    int dead_slot,
                                    mxfs_node_id_t expect_victim,
                                    uint64_t expect_ag_mask,
                                    int (*classify)(void *arg,
                                        const struct mxfs_resource_id *res),
                                    void *arg,
                                    uint32_t *out_purged,
                                    uint32_t *out_kept);
/*
 * sess374 (sess357 ruling part 1, second half): registers "is this resource
 * inside a quarantined victim domain?".  The XFS layer owns the imported
 * quarantine map; the DLM consults this on every poll lap of every blocking
 * acquire so that a wait the verdict OVERTOOK is cancelled with the same
 * terminal-quarantine error a fresh acquire would get, instead of sitting out
 * the DLM timeout against a grant that can never be released.  The callback
 * MUST be lockless and MUST NOT do I/O.  Returns >0 = covered (cancel).
 */
void mxfs_v5_dlm_set_quar_covers_fn(struct mxfs_v5_dlm *ctx,
                                    int (*fn)(void *data,
                                        const struct mxfs_resource_id *res),
                                    void *data);
void mxfs_v5_dlm_set_closure_classify_fn(struct mxfs_v5_dlm *ctx,
                                    int (*fn)(void *data,
                                        const struct mxfs_resource_id *res,
                                        uint64_t ag_mask),
                                    void *data);
/* sess330 (RULE-5 ruling): leaseless terminalization of a LEGACY intent-path
 * quarantine (QUARANTINED descriptor, all-zero outcome region).  Predicate
 * and return contract in disklock.h. */
int mxfs_v5_dlm_recovery_backfill_legacy(struct mxfs_v5_dlm *ctx,
                                         int dead_slot,
                                         struct mxfs_recov_outcome *oc_out);
void mxfs_v5_dlm_recovery_scan_outcomes(struct mxfs_v5_dlm *ctx);

/* ─── AG lock interface ─── */

/*
 * sess110 step 5.3 (ruling blocker 5): `gres` (optional, may be NULL) returns
 * the immutable provenance of the grant obtained — same contract as the inode
 * path above.  It replaces the post-acquire re-read that used to source the AG
 * authority epoch: a separate read cannot prove the epoch it returns belongs to
 * the grant THIS acquire obtained (the slot can be released and re-granted
 * between the CAS and the read).  Initialised non-proving on entry, so a NULL
 * transport, TCP, or any failure path authorises nothing.
 */
/* sess290 (D-488 leg 7): local_epoch = the caller's published in-core
 * write-authority epoch for this AG (READ_ONCE(pag_mxfs_grant_epoch); 0 =
 * none/surrendered).  Attested down to the CAW already-held path: published
 * epoch matching the slot reaffirms; published 0 with our bit stranded
 * forces a fresh READOPT mint — the surrendered epoch is never returned. */
int  mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno,
                         uint64_t local_epoch,
                         struct mxfs_grant_result *gres);
/* demand=true: leave a sticky on-disk revoke behind on conflict instead of
 * failing silently (D-AGLOCK-...-LIVELOCK-488).  See the definition. */
int  mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno,
                            uint64_t local_epoch,
                            struct mxfs_grant_result *gres, bool demand);
/* D-488 (sess273 ruling): tri-state release outcome (mxfs_dlm.h).  CAW
 * resolves an UNKNOWN body outcome via an authoritative own-bit read-back
 * before returning; only a read error leaves UNKNOWN.  Callers that have
 * surrendered in-core tenure must re-arm on STILL_HELD and quarantine on
 * UNKNOWN — never clear demoting as if released. */
enum mxfs_unlock_state mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx,
                                             uint32_t agno);
int  mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno);
/* ccloop c7ee71c6 sess6: orphan-grant NAK — when a bast arrives for an AG the
 * FS layer does not hold (holders=0, !cached, nothing scheduled), tell the
 * master to drop its zombie GRANTED entry for us.  Guarded: no-op if the
 * local dlm table holds any entry (incl. an in-flight acquire).  TCP only. */
int  mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno);
int  mxfs_v5_dlm_is_caw(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_inode_held_nb(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess19: read shared on-disk AG slot generation (cross-node coherency epoch) */
int  mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno,
                                    uint64_t *out_gen);
/*
 * sess48's mxfs_v5_dlm_ag_grant_epoch() was DELETED in sess110 (step 5.3
 * ruling blocker 5).  It read ex_grant_epoch in a second I/O after the
 * acquire returned, which cannot bind the epoch to the grant the caller
 * actually obtained — an intervening release+regrant (ours or a peer's)
 * yields a nonzero, current, and WRONG epoch.  The epoch now comes out of
 * the granting CAS itself via the mxfs_grant_result on ag_lock/ag_lock_nb.
 * Do not reintroduce a standalone post-acquire epoch read.
 */
/*
 * sess165 (foreign-replay step 5, shadow evaluator) — CONSUMER-side reads of a
 * FENCED victim's frozen state, for untrusted log replay only.  NOT the
 * sess110-deleted producer read returning: these answer "does the VICTIM hold
 * exclusive here, under which epoch" against a manifest its fencing froze
 * (purge is ordered after IMAGES_REPLAYED), never "what epoch may I stamp".
 * See mxfs_dlm_caw_victim_manifest_read in dlm_caw.h for the full contract.
 * CAW transport only (-ENODEV on TCP/single-node).
 */
int  mxfs_v5_dlm_victim_ag_manifest_read(struct mxfs_v5_dlm *ctx, uint32_t agno,
                                         uint32_t victim_slot,
                                         bool *out_holds_ex,
                                         uint64_t *out_ex_grant_epoch,
                                         uint64_t *out_lineage);
int  mxfs_v5_dlm_victim_inode_manifest_read(struct mxfs_v5_dlm *ctx,
                                            uint64_t ino, uint32_t victim_slot,
                                            bool *out_holds_ex,
                                            uint64_t *out_ex_grant_epoch,
                                            uint64_t *out_lineage);
/* Read the live recovery descriptor (if any) on `slot`'s heartbeat sector:
 * the shadow evaluator's capability check that a fence-certified freeze
 * actually covers the victim it is evaluating.  Returns 0 with the stage and
 * victim identity filled, -ENOENT if no descriptor, -EPROTO if one is present
 * but uninterpretable, or a negative I/O error. */
int  mxfs_v5_dlm_victim_recovery_read(struct mxfs_v5_dlm *ctx, uint32_t slot,
                                      uint16_t *out_stage,
                                      uint64_t *out_victim_epoch,
                                      uint32_t *out_victim_node);
/* sess187: untagged-replay authority for a victim slot — cert_sn_excl (the
 * descriptor certificate is FENCED with fence_kind SINGLE_NODE_EXCLUSIVE)
 * and victim_snlocal (the victim durably self-classified via the write-time
 * MXFS_HB_FEAT_SNLOCAL marker, frozen into the descriptor at creation).
 * Untagged foreign replay may proceed only on the CONJUNCTION; a kind-17
 * cert WITHOUT the victim marker is a refusal diagnosis, not authority.
 * Fail closed: any error returns with both flags false. */
int  mxfs_v5_dlm_victim_untagged_authority(struct mxfs_v5_dlm *ctx,
                                           uint32_t slot,
                                           bool *out_cert_sn_excl,
                                           bool *out_victim_snlocal);
int  mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess42: raw held mode (MXFS_LOCK_NL/PR/EX) — phantom-lock callers compare
 * against the mode they believe they hold (NOT hardcoded EX, which
 * false-negatives a valid PR). */
uint8_t mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess37: 1=this node masters the inode resource, 0=no, -1=no TCP dlm. */
int mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess61 (sess10 plan): reliable per-grant generation token this node holds for
 * `ino` on TCP (0 if not held / CAW).  Dir-EX fast-path tenure-change signal. */
uint32_t mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* interactive session 2026-07-13: resource-scoped (CAW-only; 0/no-op on TCP)
 * orphan-strand wall-clock trackers for `ino` — survives VFS inode eviction,
 * unlike an xfs_inode field.  See dlm_caw.h's grant_meta struct comment. */
uint64_t mxfs_v5_dlm_inode_orphan_clock_get(struct mxfs_v5_dlm *ctx,
                                            uint64_t ino, bool starve);
void mxfs_v5_dlm_inode_orphan_clock_set(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                        bool starve, uint64_t val);
uint8_t mxfs_v5_dlm_inode_granted_mode(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess41 C5 fail-closed rc contract — see v5_mount.c comment. */
int mxfs_v5_dlm_inode_open_holders(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                   uint64_t *oh_out);
void mxfs_v5_dlm_inode_open_clear(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess46 iclus open tracking: gated standalone SET + claim-less B6 probe. */
int mxfs_v5_dlm_inode_open_set(struct mxfs_v5_dlm *ctx, uint64_t ino);
int mxfs_v5_dlm_inode_open_probe(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                 uint64_t *oh_out, bool *authoritative);
uint64_t mxfs_v5_dlm_node_bit(struct mxfs_v5_dlm *ctx);
/* sess63: did this node's held EX grant for `ino` arrive as a cross-node handoff
 * (a DIFFERENT node held EX since we last did)?  *gen_out gets the grant_gen for
 * once-per-episode consumption.  Reliable replacement for the lossy evict-ring.
 * v0.6.0: served on BOTH transports (TCP master mirror / CAW slot dir_epoch). */
bool mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                     uint32_t *gen_out);
/* sess64 (GPT design): cross-node handoff epoch for `ino`'s held grant
 * (0 if not held).  Level-triggered staleness signal for the XFS layer.
 * TCP: monotonic (compare >).  CAW (v0.6.0): slot-carried, can restart on
 * slot reclamation (compare !=; see mxfs_v5_dlm_transport_caw). */
uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* ccloop(3e02e7dd) sess3: canonical dir logical-block0 record, write-once per
 * incarnation `gen` (dp->i_generation) — see docs/canonical_block0_fix_plan.md
 * and the dir_block0_fsb comment in struct mxfs_caw_lock_slot.  CAW-only
 * (TCP has no equivalent yet; returns false / no-op — TCP already passes its
 * criteria without this mechanism).  Query: true + *fsb_out iff a canonical
 * block0 is published for incarnation `gen`.  Publish: WRITE-ONCE, a no-op
 * if already published for `gen`. */
bool mxfs_v5_dlm_inode_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen, uint64_t *fsb_out);
void mxfs_v5_dlm_inode_set_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                      uint64_t fsb, uint32_t gen);
/* v0.6.0: true iff this mount coordinates via the CAW (disk-slot) transport. */
bool mxfs_v5_dlm_transport_caw(struct mxfs_v5_dlm *ctx);
/* sess-tcp: true iff this mount runs the TCP DLM transport (grants live in the
 * dlm.c local mirror, so mxfs_v5_dlm_inode_held is a cheap in-mem lookup — the
 * dir-EX held verify can run un-throttled, unlike the CAW 512B slot read). */
bool mxfs_v5_dlm_is_tcp(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_ag_ex_count(struct mxfs_v5_dlm *ctx, uint32_t agno,
                             int *nslots_out);

/* ─── Non-blocking lock ─── */

int  mxfs_v5_dlm_inode_lock_try(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                 uint8_t mode,
                                 struct mxfs_grant_result *gres);

/* ─── BAST notification callback ─── */

/*
 * Called by v5_bast_cb when another node needs a lock we're caching.
 * data = opaque pointer (struct xfs_mount * in practice).
 * ino = inode number of the contested resource.
 * mode = lock mode the remote node requested.
 */
typedef void (*mxfs_v5_bast_notify_fn)(void *data, uint64_t ino,
                                        uint8_t mode);

void mxfs_v5_dlm_set_bast_notify(struct mxfs_v5_dlm *ctx,
                                   mxfs_v5_bast_notify_fn fn, void *data);

/*
 * ICLUSTER ops (ccloop 72513a13 sess3, ICLUSTER PLAN in DLM_PLAN.md).
 * One on-disk resource per XFS inode cluster; base_ino must already be
 * the cluster base (ino & ~(inodes_per_cluster-1)).  Refcounting across
 * the covered inodes lives in the xfs-side mediating layer — these move
 * only the on-disk slot.  The BAST callback receives the cluster BASE.
 */
int mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                           uint8_t mode, struct mxfs_grant_result *gres);
int mxfs_v5_dlm_iclus_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                                 uint32_t expected_gen, bool is_free);
int mxfs_v5_dlm_iclus_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t base_ino);
/* sess309: pin a WEDGED ICLUS release against teardown release_all
 * (CAW only; TCP no-op) */
int mxfs_v5_dlm_iclus_pin(struct mxfs_v5_dlm *ctx, uint64_t base_ino);
int mxfs_v5_dlm_inode_pin(struct mxfs_v5_dlm *ctx, uint64_t ino);
void mxfs_v5_dlm_set_iclus_bast_notify(struct mxfs_v5_dlm *ctx,
                                       mxfs_v5_bast_notify_fn fn, void *data);

/*
 * Per-AG BAST notify.  Called by v5_bast_cb when a peer requests an AG
 * lock this node holds in cached state (no active local holders).
 */
typedef void (*mxfs_v5_ag_bast_notify_fn)(void *data, uint32_t agno,
                                           uint8_t mode);

void mxfs_v5_dlm_set_ag_bast_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_ag_bast_notify_fn fn,
                                      void *data);

/*
 * Called once when the DLM transitions from single-node to multi-node
 * (first peer discovered).  The XFS layer must flush all dirty data
 * to disk before the peer can read our allocated clusters — otherwise
 * the peer, or even this node after a subsequent DLM reload, will
 * read pre-allocation zeros and trip xfs_inode_buf_verify.
 */
typedef void (*mxfs_v5_peer_joined_notify_fn)(void *data);

void mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx,
                                          mxfs_v5_peer_joined_notify_fn fn,
                                          void *data);

/*
 * sess131 self-fence notification.  Fired once when this node must stop
 * writing to the shared device immediately; the XFS layer must force-shutdown
 * the filesystem.
 *
 * `reason` is an enum mxfs_self_fence_reason (mxfs_common.h).  Four detectors
 * fire this — a re-mkfs'd device, a survivor taking over our heartbeat slot,
 * and two SCSI-PR key-loss paths.  sess79: before the reason was plumbed, the
 * XFS layer printed "device reformatted under live mount" for all four, so
 * three quarters of MXFS's most severe operator message named a cause that
 * had not happened.
 */
typedef void (*mxfs_v5_fence_notify_fn)(void *data, int reason);

void mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx,
                                  mxfs_v5_fence_notify_fn fn,
                                  void *data);

/*
 * sess279 (sess276 ruling, part A): record one data-path SCSI RESERVATION
 * CONFLICT (-EBADE).  Callers: the disklock HB CAS relay and the CAW unlock
 * wrappers.  Threshold crossings launch a one-shot PR IN inspection thread
 * that withdraws the mount when the target confirms this node's key is gone
 * (reason MXFS_SELF_FENCE_PR_CONFLICT_FENCED).  Cheap, non-blocking, safe
 * from any sleepable context.
 */
void mxfs_v5_dlm_note_resv_conflict(struct mxfs_v5_dlm *ctx);

/*
 * v0.5.0 dead-node notification (foreign-slice replay trigger).  Fired from
 * the disklock heartbeat thread after a dead peer's CAW/disklock/DLM state
 * has been purged, ONLY on the elected survivor (lowest live heartbeat slot,
 * see mxfs_disklock_lowest_live_slot).  dead_slot is the dead node's
 * heartbeat slot == its per-node XFS log slice index.  Runs in heartbeat
 * context — the body must not block; queue work and return.
 */
typedef void (*mxfs_v5_dead_node_notify_fn)(void *data, uint32_t dead_slot);

void mxfs_v5_dlm_set_dead_node_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_dead_node_notify_fn fn,
                                      void *data);

/*
 * sess348 (#92 clean departure): fired from the disklock heartbeat thread
 * when a monitored peer's slot is FUA-confirmed cleanly released
 * (FLAG_EMPTY, own stamp) — the peer unmounted; nothing died and nothing
 * needs replay.  The XFS body must clear any dead/torn latch it holds for
 * the slot so a stale latched refusal cannot poison the slot's next
 * tenant, and must not start recovery.  Runs in heartbeat context — the
 * body must not block.
 */
typedef void (*mxfs_v5_clean_depart_notify_fn)(void *data, uint32_t slot);

void mxfs_v5_dlm_set_clean_depart_notify(struct mxfs_v5_dlm *ctx,
                                         mxfs_v5_clean_depart_notify_fn fn,
                                         void *data);

/*
 * sess132 (GPT sess130 ruling, step 5): DLM-STUCK notification.
 *
 * Fired when the CAW layer has proved it can no longer clear this node's own
 * bits out of the on-disk slot table.  Peers block behind those bits, so this
 * is a cluster-wide liveness fault: the mount above must stop mutating the
 * filesystem BEFORE this node stops advertising liveness, or peers will fence
 * and replay a node that is still writing.
 *
 * CONTRACT FOR THE HANDLER (GPT sess132 ruling, part 3C/3D):
 *   - It may be called from the owed worker thread.  It must therefore NOT do
 *     anything that can re-enter mxfs_dlm_caw_stop synchronously — that would
 *     join the very thread it was called from.  Queue the work and return.
 *   - It must be idempotent and once-only.
 *   - It must hold whatever reference keeps the mount alive across the queued
 *     work, and be cancellable by an ordinary unmount without self-deadlock.
 *   - It is a NOTIFICATION, never the safety latch.  The CAW layer has already
 *     recorded the failure and revoked any claim to a clean departure before
 *     this fires; a handler that never runs cannot make the departure clean.
 */
typedef void (*mxfs_v5_dlm_stuck_notify_fn)(void *data);

void mxfs_v5_dlm_set_dlm_stuck_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_dlm_stuck_notify_fn fn,
                                      void *data);

/*
 * sess67 ASYMMETRIC MDS metadata-RPC (Phase 1, see ASYMMETRIC_MDS_PLAN.md).
 * Max concurrent in-flight metadata RPCs from this node (one per blocked
 * client VFS thread).  The unlink_visibility workload is sequential per node,
 * so a modest table suffices.
 */
#define MXFS_MD_MAX_PENDING 64

struct mxfs_md_req;
struct mxfs_md_reply;

/*
 * Server-side handler up-call into the XFS layer.  Invoked on the MDS when an
 * MXFS_MSG_MD_* request arrives.  name1/name2 point at the inline names parsed
 * from the request.  The handler runs the real XFS transaction and fills
 * *reply (rc + child ino/gen/attrs + post-op parent gen).  Must not block
 * indefinitely; runs in the peer recv-thread context.
 */
typedef void (*mxfs_v5_md_request_fn)(void *data,
                                      const struct mxfs_md_req *req,
                                      const char *name1, const char *name2,
                                      struct mxfs_md_reply *reply);

void mxfs_v5_dlm_set_md_request_fn(struct mxfs_v5_dlm *ctx,
                                   mxfs_v5_md_request_fn fn, void *data);

/*
 * Client-side: forward a metadata op to the MDS and block for the reply.
 * type = MXFS_MSG_MD_*; req carries the fixed fields; name1/name2 inline.
 * Returns 0 on a completed RPC (check reply->rc for the op result), or
 * negative errno on transport/timeout failure.
 */
int mxfs_v5_dlm_md_request(struct mxfs_v5_dlm *ctx, uint16_t type,
                           const struct mxfs_md_req *req,
                           const char *name1, const char *name2,
                           struct mxfs_md_reply *reply);

/* Resolve the MDS node_id (static v1: occupant of disklock slot 0). 0 if unknown. */
mxfs_node_id_t mxfs_v5_dlm_mds_node_id(struct mxfs_v5_dlm *ctx);

/* ─── Query ─── */

bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx);
/* sess94: {slot, node_id, mount incarnation} — all or nothing, lock-free.
 * false (with the outputs zeroed) is a CAPTURE FAILURE, not "no identity". */
bool mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *ctx, uint32_t *slot,
                                uint32_t *node, uint64_t *epoch);
bool mxfs_v5_dlm_slice_adopted(struct mxfs_v5_dlm *ctx);
/* sess67 ASYMMETRIC MDS (Phase 1) — see ASYMMETRIC_MDS_PLAN.md */
bool mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx);

#endif /* MXFS_DLM_V5_MOUNT_H */
