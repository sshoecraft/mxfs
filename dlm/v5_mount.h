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
#include "static_peers.h"

/* ─── DLM transport selection ─── */

#define MXFS_V5_TRANSPORT_CAW   0
#define MXFS_V5_TRANSPORT_TCP   1
#define MXFS_V5_TRANSPORT_AUTO  2

/* ─── Opaque v5 DLM context ─── */

struct mxfs_v5_dlm;
/* defined in dlm_caw.h; callers of the force-release pass-through
 * below include that header for the definition. */
struct mxfs_forcerel_attest;

/* ─── Init options ─── */

struct mxfs_authority;

struct mxfs_v5_dlm_opts {
	/*
	 * This incarnation's authority object, allocated by the mount BEFORE the
	 * DLM exists so the gate has an answer from the first instant a clustered
	 * mutation is possible, and outliving the DLM because the work it governs
	 * does.  NULL means the caller has no mount to own one and the DLM makes
	 * its own.
	 */
	struct mxfs_authority *authority;
	int             transport;          /* MXFS_V5_TRANSPORT_* */
	uint16_t        dlm_port;           /* TCP port (default 7600) */
	uint16_t        discovery_port;     /* UDP port (default 7601) */
	/*
	 * Mount option peers=: the cluster's addresses.  NULL or empty = find
	 * peers by multicast.  Owned by the mount and read only during init
	 * (each consumer copies it).
	 */
	const struct mxfs_static_peers *peers;
	uint64_t        journal_offset;     /* from MXFS on-disk super */
	uint64_t        rman_offset;        /* recovery manifest region (0 = none) */
	uint64_t        rman_size;
	uint64_t        tauth_offset;       /* TCP authority ledger region (0 = none) */
	uint64_t        tauth_size;
	uint64_t        prkey_offset;       /* PR registrant ledger region (0 = none) */
	uint64_t        prkey_size;
	uint64_t        bootstrap_offset;   /* bootstrap record region (0 = none) */
	uint64_t        bootstrap_size;
	uint64_t        slife_offset;       /* 0.88.0: slice lifecycle region (0 = none) */
	uint64_t        slife_size;
	uint64_t        disklock_offset;    /* from MXFS on-disk super */
	uint32_t        max_nodes;          /* from MXFS on-disk super */
	void            *bdev;              /* struct block_device * (kernel) */
	uint8_t         volume_uuid[16];    /* XFS superblock UUID */
	/*
	 * v5 cap on locally-tracked held CAW DLM locks.  0 = use
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
	 * number of per-node XFS log slices this volume was formatted
	 * with (MXFS on-disk super xfs_log_node_count; 0 = no per-node slices).
	 * A dead node's slice is the IDENTICALLY numbered slice; a slot beyond
	 * this count owns no slice at all (D-LOG-SLICE-SHARED-MULTIWRITER —
	 * the old modulo mapping aliased many slots onto one slice).  The
	 * durable recovery descriptor records both index and count so it stays
	 * self-describing if the volume is ever re-formatted differently.
	 */
	uint32_t        log_node_count;
	/*
	 * Fix 3c (ruling, D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE):
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
	 * 0.74.0: the LIVE value of the same assertion — a pointer into the
	 * platform layer's parameter so the fence gate can honour an operator
	 * who sets single_node_exclusive=1 on a survivor whose peer's recovery is
	 * RECOVERY_BLOCKED, at the next re-drive, without a remount.  Only the
	 * fence gate reads it; every mount-time decision keeps the snapshot.
	 * NULL = no live source.
	 */
	const unsigned int *single_node_exclusive_live;
	/*
	 * when the admission-time fencing-capability check
	 * (mxfs_scsipr_validate_admission) fails, the default is to REFUSE the
	 * mount.  The design-consult ruling requires that a rig which cannot
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
 * (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE Arm C): a clean
 * teardown used to zero its heartbeat slot INSIDE shutdown, before XFS
 * wrote the unmount record — a crash in that window left a dirty journal
 * slice behind an EMPTY (consumable) slot, the same silent loss as the
 * closed Arm A/B, just crash-timed.  Per the ruling the slot may
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
 *
 * (D-379(B)): commit returns true iff the slot was DURABLY
 * released (unmount_clean and the release write completed).  The caller
 * may retire its SCSI PR key only in that case; on a dirty or failed
 * departure the key stays registered as the fence target peers PREEMPT
 * AND ABORT (a same-nexus successor cannot self-fence — ruling).
 */
struct mxfs_disklock_ctx;
struct mxfs_v5_dlm_slot_release {
	struct mxfs_disklock_ctx *disklock; /* heartbeat stopped; slot ACTIVE */
	mxfs_bdev_t              *dev;      /* dev clone the disklock borrows */
	bool                      self_retire_ok; /* admitted under
										 * single_node_exclusive or
										 * fence_capability_override — may
										 * complete its own retirement */
};
void mxfs_v5_dlm_shutdown_defer_release(struct mxfs_v5_dlm *ctx,
					struct mxfs_v5_dlm_slot_release *late);
bool mxfs_v5_dlm_slot_release_commit(struct mxfs_v5_dlm_slot_release *late,
				     bool unmount_clean);
/*
 * (D-0356 / D-377 two-phase departure): commit no longer destroys
 * the disklock.  After the late PR unregister, call
 *   mxfs_v5_dlm_slot_restamp_unretired(&late)  iff the key could not be
 *     proven retired — CASes our RELEASED record back to WITHDRAWN (with the
 *     key) so peers fence it; 0 ok, -ESTALE slot no longer ours, -ENOENT
 *     nothing deferred;
 *   mxfs_v5_dlm_slot_release_finish(&late)     ALWAYS, last — destroys the
 *     disklock and closes the dev clone (no-op on an unfilled struct).
 */
int  mxfs_v5_dlm_slot_restamp_unretired(struct mxfs_v5_dlm_slot_release *late);
/* the release stamp is RETIRE_PENDING (see disklock.h).  A
 * departure that had NO PR key to retire completes it itself — CAS to
 * EMPTY.  A departure whose key WAS unregistered leaves it to the peers'
 * READ KEYS (a de-registered initiator cannot write the LUN). */
int  mxfs_v5_dlm_slot_retire_complete(struct mxfs_v5_dlm_slot_release *late);
void mxfs_v5_dlm_slot_release_finish(struct mxfs_v5_dlm_slot_release *late);
/*
 * (design-consult merge criterion 4, "serialize against any old
 * shutdown/re-registration worker"): one host-wide lock that a departing
 * unmount holds across its late phase (slot release → PR unregister →
 * re-stamp/complete → finish) and a CAW mount holds from its PR REGISTER
 * through the P305 same-boot settlement.  Same boot ⇒ same derived key, so
 * an old unmount's late unregister racing a new mount's register on the
 * same nexus could remove the NEW mount's registration, and the new mount's
 * settlement could publish EMPTY while the old incarnation's late phase
 * still owns the record.  Created at module init; the lock helpers are
 * no-ops when it does not exist (user-mode tools).
 */
int  mxfs_v5_dlm_global_init(void);
void mxfs_v5_dlm_global_exit(void);
void mxfs_v5_dlm_departure_lock(void);
void mxfs_v5_dlm_departure_unlock(void);

/*
 * v0.11.74: detach the SCSI PR registration from the ctx before
 * shutdown and return its key (0 if none/no PR).  The caller owns the
 * deferred unregister, issued via mxfs_pal_scsi_pr_unregister_bdev
 * AFTER the unmount log record is on disk — unregistering inside
 * shutdown fenced the node's own final log write on WE-RO targets.
 */
/*
 * (0.61.0, D8): *quarantined is set when the retire settle worker
 * or the PR probe thread could not be joined within its bound (parked in a
 * SCSI command).  The context is then leaked deliberately (module pinned)
 * and the caller MUST treat the departure as DIRTY: no slot release, key
 * retained as the fence target.
 */
uint64_t mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx, bool *quarantined);

/*
 * ( a864): owning FS force-shut-down (still mounted) — leave the
 * cluster: fence all new acquires (inode + AG return -ESHUTDOWN) and stop the
 * disklock heartbeat so peers' dead-node purge reclaims our slots.  Sleeps
 * (<=5s thread join); process context only.  Idempotent.
 */
void mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx);
/*
 * (D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286): the NON-SLEEPING
 * half of withdrawal — poison the session's departure state (terminal)
 * and publish withdrawn, with full barriers, before any cleanup can run.
 * Safe from xfs_do_force_shutdown context.  Idempotent; returns true on
 * the call that did the poisoning.  `why` is a short label for the log.
 */
bool mxfs_v5_dlm_poison(struct mxfs_v5_dlm *ctx, const char *why);
bool mxfs_v5_dlm_is_poisoned(struct mxfs_v5_dlm *ctx);
/* D2: called by the elected replayer after the
 * dead node's slice is durably replayed — shared purges + zeroing the
 * dead HB slot (the cluster-wide "replay done" signal). */
/* recovery-guard passthroughs (unclaimed-bucket sweep exclusion):
 * semantics documented on the mxfs_disklock_* originals in disklock.h. */
int  mxfs_v5_dlm_local_slot(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_slot_unclaimed(struct mxfs_v5_dlm *ctx, int slot);
int  mxfs_v5_dlm_guard_slot(struct mxfs_v5_dlm *ctx, int slot);
int  mxfs_v5_dlm_guard_refresh(struct mxfs_v5_dlm *ctx);
void mxfs_v5_dlm_unguard_slot(struct mxfs_v5_dlm *ctx);

/* (design review item 6D): returns 0 when the recovery was PUBLISHED (CAW
 * authority purged, flushed durable, dead heartbeat provably zeroed), or a
 * negative errno when nothing was published — in which case the pending
 * marker and heartbeat record are still set and the completion is owed. */
int  mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx,
				   uint32_t dead_slot);

/*
 * — THE REPLAY GATE.  Acquire (or revalidate) the recovery EXECUTION
 * LEASE for a dead peer's journal slice.  Returns 0 only when a FENCE
 * CERTIFICATE on the victim's own heartbeat sector proves that victim was
 * excluded from the LUN, AND this node holds the lease to act on it.
 *
 * Every destructive step of a foreign-slice recovery must be behind this:
 * the log replay, the CAW authority purge, each milestone advance, and the
 * sector zero that broadcasts "recovered".  Until nothing asked, which
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
/*
 * The same acquire under a caller's remaining budget (ms; 0 = unbounded, the
 * worker-context form above).  An arm that must pay the MXFS_RECOV_ABANDON_MS
 * observation before it can take a descriptor over is NOT STARTED when that
 * interval plus its bounded continuation would not fit: a takeover that
 * cannot complete inside the budget is refused up front instead of running
 * the mount past its own bound (D-0980).
 */
int  mxfs_v5_dlm_recovery_acquire_bounded(struct mxfs_v5_dlm *ctx,
					  uint32_t dead_slot,
					  uint32_t budget_ms);
/* the typed completion — see struct mxfs_recov_complete_res.
 * mxfs_v5_dlm_recovery_complete() is now a wrapper returning res.rc. */
struct mxfs_recov_complete_res;
int  mxfs_v5_dlm_recovery_complete2(struct mxfs_v5_dlm *ctx, uint32_t dead_slot,
				    struct mxfs_recov_complete_res *res);
/* (ruling 5): the durable stage of the descriptor THIS node holds the
 * execution lease on.  0 with *stage filled when the descriptor is ours (same
 * recovery identity as our auth); -ENOENT when we hold no lease or the
 * descriptor is not ours; -errno on a read failure.  Lets the replayer skip a
 * redundant slice replay once IMAGES_REPLAYED is on the platter. */
int  mxfs_v5_dlm_recovery_stage(struct mxfs_v5_dlm *ctx, uint32_t dead_slot,
				unsigned int *stage);
/* Drop our cached lease tuple for a slot (the platter stays authoritative). */
void mxfs_v5_dlm_recovery_release(struct mxfs_v5_dlm *ctx, uint32_t dead_slot);
/*
 * Give a held execution lease back DURABLY (owner -> none on the platter,
 * stage and certificate preserved) and drop it locally — the state a prover
 * leaves when it sealed a fence, claimed the lease and then failed its mount
 * before replaying.  Returns the disklock relinquish rc (0 given back).
 */
int  mxfs_v5_dlm_recovery_relinquish(struct mxfs_v5_dlm *ctx, uint32_t dead_slot);

/*
 * ── RECOVERY_BLOCKED_FENCE — the observable state ─────────────────
 *
 * Everything above fails CLOSED: when exclusion cannot be proved, or has
 * lapsed, MXFS refuses to replay the dead peer's journal slice, refuses to
 * release its grants, and refuses to zero its sector.  That is correct, and it
 * is also indistinguishable — from outside — from a filesystem that is simply
 * hung, because peers block on the frozen victim's locks either way.
 *
 * MEASURED (tests/excl_lapse_probe.sh, 0.11.424): a slice whose exclusion had
 * lapsed retried every ~30 s indefinitely with the whole story visible only in
 * dmesg.  design review (design-consult ruling, Q2): "Add an explicit durable and
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
										* while the recovery ran */
#define MXFS_RBLK_SNAPSHOT_PENDING  12 /* exclusion PROVED (SNAPSHOTTING)
										* but the fence-time manifest is not
										* sealed yet; re-driven automatically */
#define MXFS_RBLK_NO_LOG_SLICE      11 /* victim slot >= log slice count: it has no
										* slice of its own, so any slice this path
										* could name belongs to a DIFFERENT slot */
/* (D-RECOV-ADVANCE-UNBOUNDED-RETRY): the completion ladder's
 * classified, TERMINATING outcomes.  Each names a recovery identity
 * (recovery_gen + owner_term) in the record; a new identity clears it. */
#define MXFS_RBLK_COMPLETE_INVARIANT 13 /* descriptor unchanged and still ours,
										 * yet our auth failed: invariant
										 * violation — FS withdrawn, descriptor
										 * left untouched for inspection */
#define MXFS_RBLK_COMPLETE_DEADLINE  14 /* transient completion failures past
										 * the bounded deadline: lease given
										 * back, FS withdrawn so the next
										 * survivor is elected */
#define MXFS_RBLK_COMPLETE_SUPERSEDED 15 /* the descriptor changed hands (or
										  * was published) under us: our
										  * recovery identity is cancelled */
#define MXFS_RBLK_FENCE_BLOCKED     16 /* 0.74.0: the bounded series of
										* non-proving pre-command attempts
										* expired.  Durable on the descriptor
										* (MXFS_RECOV_F_FENCE_BLOCKED), slow
										* re-drive, path ops on the victim's
										* grants fail fast.  Operator action:
										* docs/dlm-protocol.md */

/*
 * typed outcome of one completion attempt
 * (mxfs_v5_dlm_recovery_complete2).  Replaces "0 or -errno, the caller
 * re-arms on any errno for ever" (the D-RECOV-ADVANCE-UNBOUNDED-RETRY loop).
 * Only PUBLISHED retires the dead slot as recovered.  RETRY carries the
 * caller's next delay (exponential 5/10/20/40 s with jitter, capped by the
 * deadline).  SUPERSEDED cancels this node's stale work — the descriptor now
 * belongs to another recovery identity or is already consumable — and the
 * caller must NOT re-arm.  The two FATAL outcomes mean the DLM has done its
 * part (INVARIANT: nothing touched; WITHDRAW: lease durably given back) and
 * the filesystem MUST now be withdrawn (fail-stop) so that this node stops
 * being the positional elected owner and a survivor takes the recovery over.
 */
#define MXFS_RECOV_COMPLETE_PUBLISHED        0
#define MXFS_RECOV_COMPLETE_RETRY            1
#define MXFS_RECOV_COMPLETE_SUPERSEDED       2
#define MXFS_RECOV_COMPLETE_FATAL_INVARIANT  3
#define MXFS_RECOV_COMPLETE_FATAL_WITHDRAW   4
/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED): the descriptor is durably at
 * IMAGES_REPLAYED with an OPEN obligation record and this node holds the
 * execution lease.  On the TCP transport the dead node's grants have already
 * been retired (remaster, ledger purge, table purge) so the custodian can
 * acquire the obligation AGs; the AGs in the record's mask are FROZEN against
 * every other local caller by the filesystem layer.  The caller must now run
 * the completion engine (mxfs_recov_obl_complete), which writes the proof and
 * advances OBLIGATIONS_DONE, and then call complete2 again.  The ladder
 * itself never completes an obligation: it has no transaction context.
 * complete2 returns -EINPROGRESS with this outcome.
 */
#define MXFS_RECOV_COMPLETE_OBLIGATIONS_OPEN 5

struct mxfs_recov_complete_res {
	int             outcome;        /* MXFS_RECOV_COMPLETE_* */
	int             rc;             /* the underlying -errno (0 on PUBLISHED) */
	unsigned int    retry_ms;       /* RETRY: delay before the next attempt */
	unsigned int    attempts;       /* failures charged to this identity so far */
	const char      *site;          /* the ladder step that failed */
};

/* the budget rule derivations for the bounded completion ladder (ruling 5):
 * a healthy descriptor CAS or purge completes in milliseconds; the reap
 * cadence that used to drive the unbounded loop was 30 s.  Deadline from the
 * FIRST failure of this recovery identity: 120 s (= four of the old cadence,
 * >= the 62 s dead window so a peer-death storm during completion cannot
 * itself expire it).  Absolute cap from the durable acquisition of the
 * execution lease: 600 s (a 4-slice node_death_replay lap measured 312 s
 * end to end; one slice's replay + completion is well inside). */
#define MXFS_V5_COMPLETE_DEADLINE_MS    120000u
#define MXFS_V5_COMPLETE_ABS_CAP_MS     600000u
#define MXFS_V5_COMPLETE_BACKOFF0_MS    5000u
#define MXFS_V5_COMPLETE_BACKOFF_MAX_MS 40000u

/* (D-0523 ruling STOP-SHIP 4, second half): when every peer falls
 * silent DURING the claim wait (disklock -ERESTART, P300-CLAIM-WAIT-PEERS-
 * LOST) the joiner is the peerless cluster and must re-run the whole-cluster
 * bootstrap IN THIS MOUNT rather than fail and hope the next attempt does.
 * Bounded: one restart.  A second peer loss means the membership is churning
 * faster than a bootstrap scan (one dead window) can settle, and the truthful
 * answer is the failed mount, not a third scan. */
#define MXFS_V5_CLAIM_BOOTSTRAP_RESTARTS 1

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
/* 0.74.0: RECOVERY_BLOCKED queries for the acquire paths.  any_: O(1), read
 * before anything else (0.75.33: true while any recovery is blocked OR any
 * victim is terminally refused, matching node_'s answer); node_: is this dead
 * member's slot blocked on our prover (its frozen grants will not be released
 * by repetition). */
int  mxfs_v5_dlm_any_recovery_blocked(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_node_recovery_blocked(struct mxfs_v5_dlm *ctx,
				       mxfs_node_id_t node);
/* 0.75.25: a victim whose slice replay was terminally refused (quarantine
 * imported for its slot) answers the node_ query the same way a blocked one
 * does, for the life of the mount.  victim 0 = resolve from the slot.
 * 0.75.30: on the first call for a slot the victim also LEAVES the view
 * (identity retired, lease unregistered, pages remastered and taken over)
 * with selective purges: fswide != 0 keeps every record of the victim
 * frozen; otherwise the records whose resource lies provably outside
 * ag_mask are retired and the rest stay frozen.  victim_inc = the
 * victim's incarnation from the verdict (0 = the slot's last epoch). */
void mxfs_v5_dlm_recovery_refused(struct mxfs_v5_dlm *ctx, int slot,
				  mxfs_node_id_t victim, uint64_t victim_inc,
				  int fswide, uint64_t ag_mask);
int  mxfs_v5_dlm_inode_held_by_blocked(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* 0.75.28: after an exhausted acquire budget — is the grant this inode waits
 * on held or mastered by a LIVE node?  1 = keep waiting, 0 = nothing live. */
/* Degraded remote acquisitions (dlm.h struct mxfs_dlm_acq_state): first call
 * prev = -1; returns the next degraded slot (> prev) with *out filled, or -1.
 * Always -1 on the CAW transport, whose waits need no receipt. */
int  mxfs_v5_dlm_acq_degraded_iter(struct mxfs_v5_dlm *ctx, int prev,
				   struct mxfs_dlm_acq_state *out);
int  mxfs_v5_dlm_inode_wait_is_live(struct mxfs_v5_dlm *ctx, uint64_t ino);
void mxfs_v5_dlm_inode_acq_abandon(struct mxfs_v5_dlm *ctx, uint64_t ino,
				   uint8_t mode);
int  mxfs_v5_dlm_inode_wait_is_receipted(struct mxfs_v5_dlm *ctx, uint64_t ino,
					 uint64_t stale_ms);

/*
 * (D-FOREIGN-REPLAY step 4a): post-recovery mount settle.  Closes
 * the two-phase mount reclaim — releases our previous incarnation's
 * un-adopted authority bits, closes the adopt window, and routes the
 * stale peer slots deferred at mount step 6.5 into fence + slice
 * recovery.  MUST be called after log recovery is durable and after the
 * dead-node notify hook is registered.  Returns 0, or a negative errno
 * if the own-slot reclaim was refused (mount continues; slots leak).
 */
int  mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx);
/* 0.75.72: frozen heartbeat records the monitor has not yet declared dead,
 * and the dead window they must stay silent for (the barrier's extension). */
int  mxfs_v5_dlm_deaths_undeclared(struct mxfs_v5_dlm *ctx,
				   unsigned int *window_ms);
/* can the mount barrier's unresolved (unfenceable) residue block
 * xfs_log_mount_finish?  0 = no, 1 = yes, <0 = could not tell (treat as 1). */
int  mxfs_v5_dlm_mount_residue_blocking(struct mxfs_v5_dlm *ctx,
					uint64_t *out_residue,
					int *out_nslots, int *out_nex);

/*
 * (D-FOREIGN-REPLAY step 4a — MOUNT ORDERING FIX).  The pieces of
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
 *                               cohort is durably replayed.  fills
 *                               *out_published with the subset actually
 *                               PUBLISHED and returns 0 only when that is
 *                               the whole input mask.
 */
int  mxfs_v5_dlm_settle_own_slot(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_mount_recovery_cohort(struct mxfs_v5_dlm *ctx,
				       uint64_t *out_slots);
/* 0.85.0: *out_open = slots whose ladder returned OBLIGATIONS_OPEN (grants
 * retired, AGs frozen, completion owed to the post-mount engine; not an
 * error and not published). */
int  mxfs_v5_dlm_mount_cohort_complete(struct mxfs_v5_dlm *ctx,
				       uint64_t slots,
				       uint64_t *out_published,
				       uint64_t *out_open);
/*
 * (docs/whole-cluster-restart.md §6.5-6.6, shape B): whole-cluster
 * bootstrap OWNER hooks for xfs_mountfs.  _adopted: this mount's slot K is
 * a certified victim's slice adopted under a RECOVERING bootstrap term —
 * xfs_log_mount replays it FULLY but authority-evaluated
 * (XLOG_MXFS_BOOTSTRAP_ADOPTED).  _terminal: a sealed slice ended terminal
 * in the barrier → the term is REFUSED.  _finish: after the barrier —
 * K_REPLAY_OK, completeness, READ KEYS reconciliation, RECOVERY_COMPLETE,
 * normalise K; nonzero refuses the mount.
 */
bool mxfs_v5_dlm_bootstrap_adopted(struct mxfs_v5_dlm *ctx);
void mxfs_v5_dlm_bootstrap_terminal(struct mxfs_v5_dlm *ctx, uint32_t slot);
/* the TYPED refusal of the adopted slice K's own-log replay
 * (authority refusal / torn K) — escrow K_REPLAY_REFUSED(rc) + record
 * REFUSED naming K.  The only path that ends a term on K; every other unwind
 * leaves K_CLAIMED for a same-boot resume. */
void mxfs_v5_dlm_bootstrap_k_refused(struct mxfs_v5_dlm *ctx, int rc);
int  mxfs_v5_dlm_bootstrap_finish(struct mxfs_v5_dlm *ctx);

/*
 * (design review item 6B) — peers that die WHILE we are mounting.
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
uint64_t mxfs_v5_dlm_mount_peek_late_deaths(struct mxfs_v5_dlm *ctx);	/* */
int  mxfs_v5_dlm_mount_pending_recovery(struct mxfs_v5_dlm *ctx,
					uint64_t *out_mask);
void mxfs_v5_dlm_mount_defer_late_deaths(struct mxfs_v5_dlm *ctx,
					 uint64_t slots);
/* subset of `mask` a survivor recovered while this mount waited
 * (marker cleared + fresh sector no longer holds the victim); the barrier
 * retires those bits from its cut without publishing them. */
uint64_t mxfs_v5_dlm_mount_resolved_elsewhere(struct mxfs_v5_dlm *ctx,
					      uint64_t mask);

bool mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx);

/* ─── Inode lock interface ─── */

/*
 * step 5.3(b): `gres` (optional, may be NULL) returns the immutable
 * provenance of the grant obtained — see struct mxfs_grant_result.  It is
 * initialised to non-proving on entry, so a NULL-transport, TCP, or failure
 * path leaves it unable to authorise anything.
 */
int  mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino,
			     uint8_t mode, struct mxfs_grant_result *gres);
/* short per-call retry budget; caller loops + re-yields cached AGs. */
int  mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino,
			     uint8_t mode, int retries,
			     struct mxfs_grant_result *gres);
void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* (D-EX-GRANT-EPOCH verification vehicle, design-consult approved):
 * drive the real CAW lock/convert/unlock paths on a geometry-reserved
 * unallocatable inode key and assert the tenure-token contract (mint /
 * convert-preserve / re-mint / acquire-upgrade-preserve).  Synchronous,
 * seconds-scale; caller must serialize runs and must NOT hold XFS locks.
 * 0 = PASS; -EREMOTEIO = assertion failed; other -errno = infra refusal.
 * Verdict + per-step evidence on the P274-PWTEST log lines. */
int  mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* same-node reconcile exerciser (D-SAMENODE-WAITER-CANCEL-COLLISION
 * closure vehicle).  mode 1 = hold EX 14 s (peer), 2 = collide (two local
 * attempts, one forced give-up), 3 = negative control (one attempt).  Same
 * contract as the pw selftest: 0 PASS, -EREMOTEIO assertion, -ENOLCK when no
 * foreign EX holder is on the key, -ETIMEDOUT attempt thread never returned.
 * Verdict on the P275-SAMENODE log line. */
int  mxfs_v5_dlm_caw_samenode_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino,
				       unsigned int mode);
/*  use in place of mxfs_v5_dlm_inode_unlock when the
 * caller has already verified nlink==0 and is doing destructive inactivation
 * (a genuine free, not an idle-gap release).  CAW transport piggybacks a
 * dir_epoch/last_ex_slot clear onto the unlock's own tombstone CAS so a
 * reused ino doesn't inherit a stale cross-node-handoff signal; zero extra
 * I/O.  TCP transport: identical to the plain unlock (no epoch concept). */
void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* FIX-20b: phantom-grant reconcile (mirror-bypassing gen=0 release). */
int  mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx,
					     uint64_t ino);
/* D-0966: release the generation-less grant of ours on `ino` (an imported
 * ledger record of this incarnation nobody adopted); TCP only, -ENOENT if
 * the mirror holds no such entry. */
int  mxfs_v5_dlm_inode_unlock_genless(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* gen-aware release — -ESTALE = a newer tenure owns the
 * resource; caller must re-arm its BAST instead of assuming released. */
/* (design review audit C1): release with atomic open-bit change (open_op:
 * +1 set self bit, -1 clear self bit, 0 leave).  See dlm_caw.h. */
int  mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *ctx, uint64_t ino,
				   uint32_t expected_gen, int open_op);
int  mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino,
				  uint32_t expected_gen);
void mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino);
int  mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino,
				int *nslots_out);
/*  a864 duplicate-immune self-EX check (full-chain scan).  1 if
 * this node holds `ino` EX on disk (any live slot), else 0.  CAW only.
 * *nslots_out = live-slot count; *hex_or_out = OR of holders_ex.  Read-only. */
int  mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino,
				      int *nslots_out, uint64_t *hex_or_out);
/*  a864 unconditional scan-based self-release (orphan-bit reclaim).
 * CAW only.  Caller holds the DEMOTING claim.  Returns #slots cleared. */
/* `att` is REQUIRED — see struct mxfs_forcerel_attest in dlm_caw.h.
 * An absent or incomplete attestation REFUSES the release with -EINVAL. */
int  mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino,
					  const struct mxfs_forcerel_attest *att);

/* producer bridge for the inode-eviction ring (called from xfs_ifree). */
void mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino,
				  uint32_t gen);

/* producer bridge for a dir-modify eviction-ring entry (called from the
 * dir-modify chokepoints xfs_dir_createname/removename/replace). */
void mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino);

/* register the eviction-ring consumer (the XFS-layer callback that
 * flags a stale NL-cached inode / bumps a peer-modified dir's gen).  Forwards
 * to the disklock layer. */
void mxfs_v5_dlm_set_evict_cb(struct mxfs_v5_dlm *ctx,
			      void (*cb)(void *data, uint64_t ino,
					 uint32_t gen, uint32_t type),
							  void *data);

/*
 * (ruling, D-513): terminal recovery-refusal channel.
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
/* (design-consult ruling Q1): the consumer VALIDATES and returns an
 * enum mxfs_quar_disposition (dlm/disklock.h).  Callers may act on the record
 * beyond importing it — closure candidacy in particular — ONLY on a VALID_*
 * disposition, and never by inferring validity from the fact that something
 * was imported: a rejected record imports FSWIDE by design. */
void mxfs_v5_dlm_set_quarantine_cb(struct mxfs_v5_dlm *ctx,
				   int (*cb)(void *data, int victim_slot,
					const struct mxfs_recov_outcome *oc),
								   void *data);
/* test injector: non-elected survivor runs the normal purge path. */
int mxfs_v5_dlm_dbg_purge_node(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id);
int mxfs_v5_dlm_recovery_publish_refusal(struct mxfs_v5_dlm *ctx,
				    int dead_slot,
				    const struct mxfs_recov_refusal_info *info,
				    struct mxfs_recov_outcome *oc_out);
struct mxfs_recov_obl;
struct mxfs_recov_obl_ext;
struct mxfs_recov_obl_geom;
/*
 * (item 5 increment 2): the obligation list + record (disklock.h,
 * recov_obl.h).  Both need the recovery execution lease like publish_refusal.
 * obl_write makes the RECOVER extent list durable in the victim's rman zone
 * and returns the sealed record; publish_refusal_obl carries that record in
 * the SAME CAS as the terminal outcome (F_TERMINAL only: evidence, never an
 * open obligation).  read_obl is the leaseless consumer.
 */
int mxfs_v5_dlm_recovery_obl_write(struct mxfs_v5_dlm *ctx, int dead_slot,
				   struct mxfs_recov_obl_ext *ext,
				   uint32_t count,
				   const struct mxfs_recov_obl_geom *geom,
				   uint64_t census_digest, uint16_t flags,
				   struct mxfs_recov_obl *out_rec);
int mxfs_v5_dlm_recovery_publish_refusal_obl(struct mxfs_v5_dlm *ctx,
				    int dead_slot,
				    const struct mxfs_recov_refusal_info *info,
				    const struct mxfs_recov_obl *obl,
				    struct mxfs_recov_outcome *oc_out);
int mxfs_v5_dlm_recovery_read_obl(struct mxfs_v5_dlm *ctx, int dead_slot,
				  struct mxfs_recov_obl *rec_out,
				  struct mxfs_recov_obl_ext *ext_out,
				  uint32_t *count_out);
/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED, completion on the TCP transport;
 * docs/dlm-protocol.md "Item 5"):
 *
 * set_obligations / set_census_zero — the replayer hands the ladder its
 * census verdict for dead_slot BEFORE calling complete2: the RECOVER extent
 * list (copied; canonicalized and made durable by the ladder's list write)
 * or "nothing owed".  The IMAGES_REPLAYED milestone carries that verdict in
 * its compare-and-write; a ladder entered without one over a descriptor
 * below IMAGES_REPLAYED is a HELD failure (nothing published).
 *
 * set_obl_cb — the OPEN-obligation observer (typedef in disklock.h): fired
 * by the disklock monitor for every readable sector every pass, once
 * synchronously at registration, and by the ladder itself the moment it
 * publishes an OPEN case or reaches OBLIGATIONS_DONE (the publisher must not
 * wait a monitor pass for its own freeze).
 *
 * obl_done_write / advance_obl_done — the custodian's completion proof and
 * the OBLIGATIONS_DONE milestone (contracts in disklock.h); both need the
 * execution lease.
 */
struct mxfs_rman_obl_done;
int mxfs_v5_dlm_recovery_set_obligations(struct mxfs_v5_dlm *ctx, int dead_slot,
					 const struct mxfs_recov_obl_ext *ext,
					 uint32_t count,
					 const struct mxfs_recov_obl_geom *geom,
					 uint64_t census_digest);
void mxfs_v5_dlm_recovery_set_census_zero(struct mxfs_v5_dlm *ctx,
					  int dead_slot);
void mxfs_v5_dlm_set_obl_cb(struct mxfs_v5_dlm *ctx,
			    void (*cb)(void *data, int slot, int state,
				       uint32_t victim_node,
				       uint64_t victim_epoch, uint32_t pub_seq,
				       uint64_t ag_mask, bool fswide),
							void *data);
int mxfs_v5_dlm_recovery_obl_done_write(struct mxfs_v5_dlm *ctx, int dead_slot,
					struct mxfs_rman_obl_done *proof);
int mxfs_v5_dlm_recovery_platter_stage(struct mxfs_v5_dlm *ctx,
				       uint32_t dead_slot, unsigned int *stage,
				       bool *quarantined);
int mxfs_v5_dlm_recovery_advance_obl_done(struct mxfs_v5_dlm *ctx,
					  int dead_slot);
/* (ruling items 2+4): canonical-outcome read (return contract
 * in disklock.h) and the synchronous registration-time scan that replays
 * already-terminal verdicts into quar_cb before ops are exposed. */
int mxfs_v5_dlm_recovery_read_outcome(struct mxfs_v5_dlm *ctx, int dead_slot,
				      struct mxfs_recov_outcome *oc_out);
/*
 * (design-consult ruling, D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356):
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
 * (ruling part 1, second half): registers "is this resource
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
/* (design-consult ruling): leaseless terminalization of a LEGACY intent-path
 * quarantine (QUARANTINED descriptor, all-zero outcome region).  Predicate
 * and return contract in disklock.h. */
int mxfs_v5_dlm_recovery_backfill_legacy(struct mxfs_v5_dlm *ctx,
					 int dead_slot,
					 struct mxfs_recov_outcome *oc_out);
void mxfs_v5_dlm_recovery_scan_outcomes(struct mxfs_v5_dlm *ctx);

/* ─── AG lock interface ─── */

/*
 * step 5.3 (ruling blocker 5): `gres` (optional, may be NULL) returns
 * the immutable provenance of the grant obtained — same contract as the inode
 * path above.  It replaces the post-acquire re-read that used to source the AG
 * authority epoch: a separate read cannot prove the epoch it returns belongs to
 * the grant THIS acquire obtained (the slot can be released and re-granted
 * between the CAS and the read).  Initialised non-proving on entry, so a NULL
 * transport, TCP, or any failure path authorises nothing.
 */
/* (D-488 leg 7): local_epoch = the caller's published in-core
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
/* D-488 (ruling): tri-state release outcome (mxfs_dlm.h).  CAW
 * resolves an UNKNOWN body outcome via an authoritative own-bit read-back
 * before returning; only a read error leaves UNKNOWN.  Callers that have
 * surrendered in-core tenure must re-arm on STILL_HELD and quarantine on
 * UNKNOWN — never clear demoting as if released. */
enum mxfs_unlock_state mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx,
					     uint32_t agno);
int  mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno);
/* Is AG @agno still ours by the transport's own authority, for the
 * stranded-AG repair: 1 yes, 0 no, <0 cannot tell / in flight. */
int  mxfs_v5_dlm_ag_strand_held(struct mxfs_v5_dlm *ctx, uint32_t agno);
/*  orphan-grant NAK — when a bast arrives for an AG the
 * FS layer does not hold (holders=0, !cached, nothing scheduled), tell the
 * master to drop its zombie GRANTED entry for us.  Guarded: no-op if the
 * local dlm table holds any entry (incl. an in-flight acquire).  TCP only. */
int  mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno);
int  mxfs_v5_dlm_inode_orphan_nak(struct mxfs_v5_dlm *ctx, uint64_t ino);
int  mxfs_v5_dlm_is_caw(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_inode_held_nb(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* read shared on-disk AG slot generation (cross-node coherency epoch) */
int  mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno,
				    uint64_t *out_gen);
/*
 * mxfs_v5_dlm_ag_grant_epoch was DELETED in (step 5.3
 * ruling blocker 5).  It read ex_grant_epoch in a second I/O after the
 * acquire returned, which cannot bind the epoch to the grant the caller
 * actually obtained — an intervening release+regrant (ours or a peer's)
 * yields a nonzero, current, and WRONG epoch.  The epoch now comes out of
 * the granting CAS itself via the mxfs_grant_result on ag_lock/ag_lock_nb.
 * Do not reintroduce a standalone post-acquire epoch read.
 */
/*
 * (foreign-replay step 5, shadow evaluator) — CONSUMER-side reads of a
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
/* (docs/recovery-manifest.md): load the victim's SEALED fence-time
 * manifest, validated against the FENCED descriptor's pointer record.  The
 * entry array is mxfs_pal_alloc'd (caller frees with mxfs_pal_free).  Any
 * error means NO verdict may be taken from the manifest and the replay
 * attempt must abort.  *out_no_caw: the manifest says the transport had no
 * CAW table (structurally empty; per-resource lookups answer -ENODEV). */
/* live slot read with exact mode + slot index (current-safety check).
 * kind = MXFS_AUTH_CLASS_AG / _INODE; resource = agno / ino. */
int  mxfs_v5_dlm_victim_live_read(struct mxfs_v5_dlm *ctx, uint8_t ltype,
				  uint64_t resource, uint32_t victim_slot,
				  bool *out_holds, uint64_t *out_epoch,
				  uint64_t *out_lineage, uint8_t *out_mode,
				  uint32_t *out_slot_idx);
/* (design review item 17): revalidate every sealed-manifest entry against
 * the live table right before the irreversible purge.  0 = consistent;
 * -EPROTO = a mutation was found (caller publishes AUTHORITY_MUTATED, purges
 * NOTHING); other negative = could not decide (retry, purge nothing). */
int  mxfs_v5_dlm_rman_verify_live(struct mxfs_v5_dlm *ctx, uint32_t slot,
				  uint32_t victim_node, uint64_t victim_epoch,
				  uint32_t *out_checked);
struct mxfs_rman_entry;
struct mxfs_recov_manifest_ptr;
/* (docs/whole-cluster-restart.md §6.8.5): the adopted K's earlier
 * incarnations — one (descriptor, fence-time manifest) pair per lineage hop
 * that ended with K adopted; idx 0 = the most recent predecessor.  The
 * evaluator judges a transaction by the pair whose victim incarnation the
 * token names; only the CURRENT pair is live-checked against K's CAW bits. */
unsigned int mxfs_v5_dlm_victim_lineage_count(struct mxfs_v5_dlm *ctx,
					      uint32_t slot);
int  mxfs_v5_dlm_victim_lineage_load(struct mxfs_v5_dlm *ctx, uint32_t slot,
				     unsigned int idx, uint32_t *out_node,
				     uint64_t *out_epoch, uint16_t *out_stage,
				     uint64_t *out_term,
				     struct mxfs_recov_manifest_ptr *out_ptr,
				     struct mxfs_rman_entry **out_ents,
				     uint32_t *out_count, bool *out_no_caw);
int  mxfs_v5_dlm_victim_manifest_load(struct mxfs_v5_dlm *ctx, uint32_t slot,
				      uint32_t victim_node,
				      uint64_t victim_epoch,
				      struct mxfs_recov_manifest_ptr *out_ptr,
				      struct mxfs_rman_entry **out_ents,
				      uint32_t *out_count, bool *out_no_caw);
/* Read the live recovery descriptor (if any) on `slot`'s heartbeat sector:
 * the shadow evaluator's capability check that a fence-certified freeze
 * actually covers the victim it is evaluating.  Returns 0 with the stage and
 * victim identity filled, -ENOENT if no descriptor, -EPROTO if one is present
 * but uninterpretable, or a negative I/O error. */
int  mxfs_v5_dlm_victim_recovery_read(struct mxfs_v5_dlm *ctx, uint32_t slot,
				      uint16_t *out_stage,
				      uint64_t *out_victim_epoch,
				      uint32_t *out_victim_node);
/* untagged-replay authority for a victim slot — cert_sn_excl (the
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
/* the victim's record carried MXFS_HB_FEAT_ADOPTED (pass-2 fresh
 * claim: previous incarnations' records in its slice are published by
 * construction).  Fail closed (false on any read/validation error). */
bool mxfs_v5_dlm_victim_adopted(struct mxfs_v5_dlm *ctx, uint32_t slot);
int  mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* raw held mode (MXFS_LOCK_NL/PR/EX) — phantom-lock callers compare
 * against the mode they believe they hold (NOT hardcoded EX, which
 * false-negatives a valid PR). */
uint8_t mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* 1=this node masters the inode resource, 0=no, -1=no TCP dlm. */
int mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* (plan): reliable per-grant generation token this node holds for
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
/* C5 fail-closed rc contract — see v5_mount.c comment. */
int mxfs_v5_dlm_inode_open_holders(struct mxfs_v5_dlm *ctx, uint64_t ino,
				   uint64_t *oh_out);
void mxfs_v5_dlm_inode_open_clear(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* 0.89.0 (D-0977): true on the TCP transport, where a mark is cleared only
 * by a release carrying MXFS_TAUTH_OPEN_CLEAR (mxfs_v5_dlm_inode_open_clear
 * is a no-op there); false on CAW, whose standalone clear CAS is durable. */
bool mxfs_v5_dlm_open_clear_rides_release(struct mxfs_v5_dlm *ctx);
/* iclus open tracking: gated standalone SET + claim-less B6 probe. */
int mxfs_v5_dlm_inode_open_set(struct mxfs_v5_dlm *ctx, uint64_t ino);
int mxfs_v5_dlm_inode_open_probe(struct mxfs_v5_dlm *ctx, uint64_t ino,
				 uint64_t *oh_out, bool *authoritative);
uint64_t mxfs_v5_dlm_node_bit(struct mxfs_v5_dlm *ctx);
/* did this node's held EX grant for `ino` arrive as a cross-node handoff
 * (a DIFFERENT node held EX since we last did)?  *gen_out gets the grant_gen for
 * once-per-episode consumption.  Reliable replacement for the lossy evict-ring.
 * v0.6.0: served on BOTH transports (TCP master mirror / CAW slot dir_epoch). */
bool mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino,
				     uint32_t *gen_out);
/* (design review): cross-node handoff epoch for `ino`'s held grant
 * (0 if not held).  Level-triggered staleness signal for the XFS layer.
 * TCP: monotonic (compare >).  CAW (v0.6.0): slot-carried, can restart on
 * slot reclamation (compare !=; see mxfs_v5_dlm_transport_caw). */
uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* (3e02e7dd) canonical dir logical-block0 record, write-once per
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

/* 0.89.31: the LU-reset admission gate's verdict, issuing nothing.  Contract
 * at the definition in v5_mount.c; the gate itself is documented in scsipr.h.
 * 0 = admitted, -EPERM = refused, other negative = could not be asked. */
int mxfs_v5_dlm_lu_reset_admit_probe(struct mxfs_v5_dlm *ctx,
				     mxfs_node_id_t victim_node,
				     uint64_t victim_key);

struct mxfs_lu_reset_convergence;   /* dlm/scsipr.h */

/* 0.89.32: the whole post-reset convergence barrier — scsipr.h's storage half
 * plus the authority half, which waits for a heartbeat ISSUED AFTER the reset
 * to land and is bounded by the lease itself rather than by a chosen number.
 * Contract at the definition in v5_mount.c.  0 = replay may proceed; -EPERM =
 * STOP and leave the durable intent resumable; other negative = could not be
 * asked.  `reset_issued_ms` is mxfs_pal_time_ms() captured before the reset. */
int mxfs_v5_dlm_lu_reset_barrier(struct mxfs_v5_dlm *ctx,
				 mxfs_node_id_t victim_node,
				 uint64_t victim_key,
				 uint32_t gen_before,
				 uint64_t reset_issued_ms,
				 struct mxfs_lu_reset_convergence *conv);
struct mxfs_lu_reset_fence;         /* dlm/scsipr.h */

/* 0.89.33: the whole witnessed-LU-reset fence — admission, the witnessed
 * reset, the audited-kernel pin, and both halves of the post-reset barrier —
 * with the authority half supplied from this layer.  It is the only producer
 * of a certificate of that kind.  Contract at the definition in v5_mount.c
 * and at MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1 in scsipr.h.  Read
 * out->certified, never the return value; a refusal after the reset was
 * issued is a refusal and never a retry. */
int mxfs_v5_dlm_fence_by_lu_reset(struct mxfs_v5_dlm *ctx,
				  mxfs_node_id_t victim_node,
				  uint64_t victim_key,
				  int (*arm_submit)(void *), void *arm_data,
				  struct mxfs_lu_reset_fence *out);
int mxfs_v5_dlm_fence_by_lu_reset_probe(struct mxfs_v5_dlm *ctx,
					mxfs_node_id_t victim_node,
					uint64_t victim_key);

int mxfs_v5_dlm_lu_reset_barrier_probe(struct mxfs_v5_dlm *ctx,
				       mxfs_node_id_t victim_node,
				       uint64_t victim_key);
bool mxfs_v5_dlm_transport_tcp(struct mxfs_v5_dlm *ctx);
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
/* 0.23.0 (design-consult ruling): the dialloc candidate reserve — ONE
 * nonqueued CAS attempt for EX on an inode slot.  0 = reserved (the grant is
 * node-cached, iget adopts it); -EAGAIN = held by a peer (no waiter, no
 * request outlives the call); with demand=1 a sticky revoke + BAST hint is
 * left on a held slot so the holder eventually lets go. */
int  mxfs_v5_dlm_inode_reserve_try(struct mxfs_v5_dlm *ctx, uint64_t ino,
				    int demand,
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
 * ICLUSTER ops (ICLUSTER PLAN in DLM_PLAN.md).
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
/* pin a WEDGED ICLUS release against teardown release_all
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
/*
 * 0.83.4 (D-0959): the transition is a PREPARE / COMMIT pair run on the
 * DLM's join worker, never on a protocol thread.  PREPARE returns 0 once the
 * filesystem is quiescent and its cached views are dropped (on a mounted
 * filesystem it holds a kernel freeze until COMMIT); a non-zero return means
 * "not yet" -- the worker retries, and the view is NOT installed until a
 * prepare succeeds, so a peer is never admitted against undrained state.
 * COMMIT releases whatever PREPARE holds; it is called only after the view
 * is installed.
 */
typedef int (*mxfs_v5_peer_joined_notify_fn)(void *data);
typedef void (*mxfs_v5_join_commit_fn)(void *data);

void mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx,
					  mxfs_v5_peer_joined_notify_fn prepare,
					  mxfs_v5_join_commit_fn commit,
					  void *data);

/*
 * self-fence notification.  Fired once when this node must stop
 * writing to the shared device immediately; the XFS layer must force-shutdown
 * the filesystem.
 *
 * `reason` is an enum mxfs_self_fence_reason (mxfs_common.h).  Four detectors
 * fire this — a re-mkfs'd device, a survivor taking over our heartbeat slot,
 * and two SCSI-PR key-loss paths.  before the reason was plumbed, the
 * XFS layer printed "device reformatted under live mount" for all four, so
 * three quarters of MXFS's most severe operator message named a cause that
 * had not happened.
 */
typedef void (*mxfs_v5_fence_notify_fn)(void *data, int reason);

void mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx,
				  mxfs_v5_fence_notify_fn fn,
				  void *data);

/*
 * (ruling, part A): record one data-path SCSI RESERVATION
 * CONFLICT (-EBADE).  Callers: the disklock HB CAS relay and the CAW unlock
 * wrappers.  Threshold crossings launch a one-shot PR IN inspection thread
 * that withdraws the mount when the target confirms this node's key is gone
 * (reason MXFS_SELF_FENCE_PR_CONFLICT_FENCED).  Cheap, non-blocking, safe
 * from any sleepable context.
 */
void mxfs_v5_dlm_note_resv_conflict(struct mxfs_v5_dlm *ctx);

/*
 * 0.89.20 — THE WRITE GATE.  True while this mount still holds authority over
 * the shared LUN; false the instant its local authority lease has expired or
 * been closed, at which point the caller MUST refuse the mutation.
 *
 * Every other detector this build has needs the LUN to answer — a write that
 * bounces with RESERVATION CONFLICT, or a periodic PR IN.  Measured: a node
 * that is issuing nothing, whose audit tick has not come round, is fenced and
 * knows nothing, and once the last registrant is purged the reservation goes
 * with it and the LUN refuses nobody.  Its bytes were read back off the
 * platter.  This is the answer to that: authority expires on a deadline this
 * node set for itself, so losing access does not require reaching the LUN in
 * order to contain the mount.
 *
 * Contract for callers: two atomic loads and a compare on the fast path.  It
 * takes no lock the withdrawal path needs, allocates nothing, touches no
 * device and never sleeps, so it is safe from submission and completion
 * context alike.  It does not shut the filesystem down — it records that a
 * withdrawal is owed and the PR worker drives it — so a caller that gets
 * false must complete its own I/O with an error itself.
 */
bool mxfs_v5_dlm_write_admitted(struct mxfs_v5_dlm *ctx);

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
 * (#92 clean departure): fired from the disklock heartbeat thread
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
 * (design-consult ruling, step 5): DLM-STUCK notification.
 *
 * Fired when the CAW layer has proved it can no longer clear this node's own
 * bits out of the on-disk slot table.  Peers block behind those bits, so this
 * is a cluster-wide liveness fault: the mount above must stop mutating the
 * filesystem BEFORE this node stops advertising liveness, or peers will fence
 * and replay a node that is still writing.
 *
 * CONTRACT FOR THE HANDLER (design-consult ruling, part 3C/3D):
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
 * ASYMMETRIC MDS metadata-RPC (Phase 1, see ASYMMETRIC_MDS_PLAN.md).
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
/* single-node NOW after having been multi-node in this mount: the caches
 * still carry the departed peers' pending invalidations (0.72.2). */
bool mxfs_v5_dlm_sole_survivor(struct mxfs_v5_dlm *ctx);
/* There is no "single-node and never multi-node" predicate: 0.83.3 made it
 * the only state in which an inode could be modified and published without
 * a grant, and 0.87.16 removed that state -- a mount that is alone takes
 * real grants from the master (itself) whatever its history, because the
 * replayer of its slice after a death needs the grant behind every image. */
int  mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx);
/* {slot, node_id, mount incarnation} — all or nothing, lock-free.
 * false (with the outputs zeroed) is a CAPTURE FAILURE, not "no identity". */
bool mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *ctx, uint32_t *slot,
				uint32_t *node, uint64_t *epoch);
bool mxfs_v5_dlm_slice_adopted(struct mxfs_v5_dlm *ctx);
/*
 * 0.88.0 (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531): the slice lifecycle
 * record of `slice` (dlm/bootstrap.h).  _claim: run the claimant's state
 * machine for the slice this mount's heartbeat slot owns, zeroing the
 * payload [payload_off, +payload_len) through the FUA path when the record
 * says INIT_REQUIRED or ZEROING; -ENODEV when the volume carries no
 * lifecycle region (legacy format).  _state: the validated state of any
 * slice's record, for the foreign-slice recovery.
 */
int mxfs_v5_dlm_slice_lifecycle_claim(struct mxfs_v5_dlm *ctx, uint32_t slice,
				      uint64_t payload_off,
				      uint64_t payload_len,
				      uint32_t *before, uint32_t *after,
				      uint32_t *zero_ms);
int mxfs_v5_dlm_slice_lifecycle_state(struct mxfs_v5_dlm *ctx, uint32_t slice,
				      uint32_t *state);
const char *mxfs_v5_dlm_slice_lifecycle_name(uint32_t state);
/* ASYMMETRIC MDS (Phase 1) — see ASYMMETRIC_MDS_PLAN.md */
bool mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx);

#endif /* MXFS_DLM_V5_MOUNT_H */
