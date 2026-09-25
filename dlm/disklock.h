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
#include "recov_obl.h"          /* obligation record + list formats */

#define MXFS_DISKLOCK_RECORD_SIZE       512
#define MXFS_DISKLOCK_MAX_SLOTS         65536
#define MXFS_DISKLOCK_HB_SLOTS          64
#define MXFS_DISKLOCK_MAGIC             0x4D584C4B  /* "MXLK" */

#define MXFS_DISKLOCK_FLAG_ACTIVE       1
#define MXFS_DISKLOCK_FLAG_EMPTY        0
/*
 * D2: voluntary death stamp.  A force-shutdown FS
 * writes this into its own heartbeat record (magic/node_id/epoch kept) so
 * peers detect the death on their next monitor scan (~2-4 s) instead of
 * after the 31-sample stale window (62 s).  Peers then run the same
 * fence → elected-slice-replay → purge pipeline as for a crashed node —
 * the withdrawn node's grants stay frozen until its journal slice has
 * been replayed (see mxfs_disklock_recovered_cb).
 */
#define MXFS_DISKLOCK_FLAG_WITHDRAWN    2
/*
 * recovery GUARD stamp.  An UNCLAIMED slot's AGI unlinked bucket can
 * hold durable zombies with no owner to reap them (offline chk repairs; a
 * survivor that crashed after its sweep retired the slot; cold cluster
 * shrink).  The node sweeping such a bucket must hold a cluster-visible
 * exclusion against a joiner claiming the slot mid-sweep (inode-EX alone is
 * not an ownership proof).  A GUARD record is that hold:
 *   - claim_slot (both variants) refuses slots holding a FRESH same-gen
 *     GUARD; a STALE guard (holder died mid-sweep) is claimable again, and
 *     the new claimant's mount-time own-bucket rescan re-drives the bucket —
 *     takeover needs no monitor or fencing involvement.
 *   - the monitor, join gate, vergate, and membership all key on
 *     flags==ACTIVE, so GUARD records are invisible to them: no member
 *     count change, no fence risk for the (live) holder.
 *   - guard/refresh/unguard are CAS transitions from the exact stored
 *     image; a lost guard is detected at the next refresh boundary and the
 *     sweep aborts.
 */
#define MXFS_DISKLOCK_FLAG_RECOVERY_GUARD 3
/*
 * (D-0356 / D-377 two-phase departure, design-consult ruling):
 * STORAGE-AUTHORITY RETIREMENT PENDING.  A clean unmount used to CAS its
 * own ACTIVE record straight to EMPTY and only THEN retire its PR key.  A
 * crash (or a failed unregister that could not re-stamp) between the two
 * left the worst state there is: a reusable EMPTY slot next to a key that
 * still grants this initiator write privilege and that nothing names.
 * mxfs_disklock_release_slot now writes THIS flag instead — identity,
 * epoch, provenance and the PR key kept, the identity crc re-bound to the
 * new flags — and the record stays NON-CONSUMABLE until the key is proven
 * absent:
 *   - peers' monitor, on first sight (no prior tracking needed): the
 *     asynchronous key lookup ctx->key_state_fn (tri-state,; a
 *     table read fed by a probe thread's coherent READ KEYS / READ
 *     RESERVATION / READ KEYS bracket, — no PR I/O on the
 *     heartbeat).  Key ABSENT (a proof: complete view under the peer's
 *     own registration + the fencing reservation, one PR generation,
 *     fresh, single-use) → CAS the record to EMPTY
 *     (P304-RETIRE-COMPLETED-BY-PEER); the ordinary clean-departure arm
 *     then retires the tracking.  Key PRESENT past
 *     MXFS_DISKLOCK_RETIRE_GRACE_MS → CAS the record to WITHDRAWN
 *     (P304-RETIRE-EXPIRED-WITHDRAWN); the withdraw pipeline fences
 *     the key, replays the (clean) slice and purges the slot.  Key
 *     UNKNOWN → nothing, ever: the record stays RETIRE_PENDING and the
 *     monitor escalates once per grace (P304-RETIRE-UNKNOWN-STALLED).
 *   - a CAS lost to a concurrent settler/claimant refreshes the image
 *     before anyone classifies it (blocker 1: no fire_dead on a stale
 *     RETIRE_PENDING image over a slot a new incarnation already owns).
 *   - the MOUNT thread settles it too (mxfs_disklock_retire_settle_slot,
 *     immediate = no grace, via the SYNC lookup that runs a fresh bracket
 *     inline): the admission barrier's requires-recovery sweep, which
 *     counts RETIRE_PENDING as pending (blocker 2) — a mount never goes
 *     writable beside an unretired registration.  A record naming the
 *     mount's OWN key (this boot's predecessor) is settled ONLY by P305
 *     through mxfs_disklock_retire_settle_own, after a fresh bracket
 *     proves our registration live (blocker 3; there is no OWN
 *     answer in the generic lookup).
 *   - the departing node whose unregister FAILED re-stamps it WITHDRAWN
 *     itself (P303, 0.58.0); a departure admitted WITHOUT a fence
 *     capability (single_node_exclusive / fence_capability_override)
 *     completes its own retirement (mxfs_disklock_retire_complete_self);
 *     a clustered one never does (blocker 2), and a record
 *     naming key 0 is UNKNOWN to every settlement, never ABSENT.
 *   - claim_slot (both variants) never takes it; the monitor settles it.
 *   - join gate, vergate and membership key on flags==ACTIVE: invisible.
 *   - identity crc covers `flags` (every transition re-binds it, only
 *     `flags` moves); the provenance crc does NOT cover the transition.
 */
#define MXFS_DISKLOCK_FLAG_RETIRE_PENDING 4
/* PR verify deadline (MXFS_PR_VERIFY_DEADLINE_MS 20 s) + one monitor lap +
 * margin: a key still present this long after the release is a departure
 * that never finished. */
#define MXFS_DISKLOCK_RETIRE_GRACE_MS   30000
/* D-0965 (0.87.11): the MOUNT thread's grace on a PRESENT key.  The key
 * may be a same-boot successor's fresh registration (identical per-boot
 * key) that has not settled its predecessor's record yet, so the mount
 * thread no longer withdraws at once — but its wait lives inside the
 * admission barrier's 30 s bound, which must also fit the fence and the
 * replay once a genuinely stalled record is withdrawn.  Measured 2/tcp:
 * a successor settles 40 ms after REGISTER unloaded and 8 s with a 1.5 s
 * delay injected into every READ KEYS; a full 30 s mount-thread grace
 * expired at 29.3 s of the barrier bound and the fence + replay took
 * 12 s more.  10 s covers the successor with a wide margin and leaves
 * two thirds of the bound for the withdraw's recovery. */
#define MXFS_DISKLOCK_RETIRE_MOUNT_GRACE_MS 10000
/* How often a sweeping holder re-stamps its guard.  Abandonment is detected
 * by ABSENCE OF CHANGE across ~3 of these intervals, never by comparing a
 * record's timestamp against the reader's clock: mxfs_pal_time_ms() is
 * ktime_get_boottime (per-node UPTIME), so cross-node clock arithmetic on
 * these records is meaningless. */
#define MXFS_DISKLOCK_GUARD_REFRESH_MS  1000

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
 * THE LOCAL AUTHORITY LEASE (0.89.20).  How long a landed heartbeat buys this
 * node the right to mutate the shared LUN.  The state machine and why the
 * anchor is taken at ISSUE are documented on the ctx fields below.
 *
 * WHERE 30 s COMES FROM, because a ratio of the remote timeout is not a
 * derivation.  Two constraints, from opposite directions:
 *
 *   AVAILABILITY — the lease must comfortably outlast a heartbeat cycle plus
 *   scheduling and completion delays, or a merely busy node withdraws a
 *   healthy mount.  A cycle is 2 s; a cycle that takes more than 4 s already
 *   logs P-HB-SLOW as an anomaly.  30 s is fifteen cycles.
 *
 *   SAFETY — the lease must expire before a peer can complete a conflicting
 *   ownership handoff.  A peer declares death after this node's slot record
 *   has been unchanged for DEAD_THRESHOLD * HB_INTERVAL = 62 s AS THE PEER
 *   OBSERVES IT, and its observation cannot begin earlier than the moment our
 *   beat landed on the platter — which is after we anchored.  So the budget
 *   below 62 s is 32 s, and it has to cover: the pump's own lateness (one
 *   250 ms tick, and zero for an I/O admission, which evaluates the deadline
 *   itself); guest clock error against the peer's (±500 ppm each way is 62 ms
 *   across the whole window); and the time already-submitted old-epoch
 *   commands take to become incapable of executing.
 *
 * THE LAST TERM IS NOT BOUNDED BY ANYTHING THIS CODE CAN SEE, and 31.7 s of
 * unallocated budget is not a proof that it fits.  Completing a Linux request
 * with an error does not establish that the corresponding SCSI command can
 * never execute later, and no choice of lease length changes that.  Closing it
 * needs exclusion that survives the fencer's disappearance, a proven target
 * quiescence mechanism, or a handoff that keeps protection until quiescence is
 * established — which is tracked as its own obligation, not settled here.
 */
#define MXFS_DISKLOCK_AUTH_LEASE_MS     30000

/*
 * Authority is HELD UNTIL A DEADLINE, not discovered to be lost.  CLOSED is
 * terminal for this incarnation: nothing short of a fresh coordinated
 * admission under a new incarnation leaves it.
 */
enum mxfs_auth_state {
	MXFS_AUTH_NOT_ADMITTED = 0,     /* mounting; no beat has landed yet */
	MXFS_AUTH_ADMITTED,             /* a beat landed; deadline is in force */
	MXFS_AUTH_CLOSED,               /* expired or revoked; sticky */
};

/*
 * THE AUTHORITY OBJECT, AND WHY IT IS NOT PART OF ANYTHING ELSE.
 *
 * One incarnation's right to put bytes on the shared LUN, held to a deadline.
 * It is a separate, reference-counted allocation for one reason: every other
 * object that could have held it is destroyed while work governed by it can
 * still be submitted.  The mount takes a reference before the DLM exists and
 * drops it only when the mount itself is freed, after every producer,
 * workqueue, timer and I/O completion of that incarnation is gone; the
 * disklock context borrows one for as long as it lives.  So the answer to
 * "may this incarnation still write?" is available for the whole life of the
 * work, and its absence is never the answer.
 *
 * There is exactly ONE of these per incarnation and nothing mirrors it.  A
 * second copy of {state, deadline} would have to be published across a
 * renewal racing a close, and a reader could then see a state from one update
 * and a deadline from another.
 *
 * It is never reset and never reopened.  A fresh incarnation is a fresh
 * mount, which allocates a fresh one.
 */
struct mxfs_authority {
	mxfs_atomic32_t         state;          /* enum mxfs_auth_state */
	mxfs_atomic32_t         refcnt;
	volatile uint64_t       deadline_ms;    /* anchored at ISSUE, never at completion */
	volatile uint64_t       anchor_ms;      /* the anchor it came from */
	volatile uint64_t       closed_at_ms;
	volatile uint64_t       last_ok_ms;     /* last landed beat, for the log line */
	volatile int            close_reason;   /* enum mxfs_self_fence_reason */
	mxfs_atomic32_t         withdraw_pending; /* a withdrawal is owed; taken by exchange, so exactly one consumer notifies (0.89.67) */
	/*
	 * Identity, for the trace.  A mount address is recycled; an incarnation
	 * is drawn once and never reused, so it is what a lap can key on to say
	 * WHICH incarnation an admission belonged to.
	 */
	volatile uint64_t       incarnation;
	volatile uint32_t       node;
	volatile int            slot;
};

/*
 * Allocate one in NOT_ADMITTED with a single reference.  The caller is the
 * first owner; every further holder takes its own.
 */
struct mxfs_authority *mxfs_authority_alloc(void);
struct mxfs_authority *mxfs_authority_get(struct mxfs_authority *auth);
void mxfs_authority_put(struct mxfs_authority *auth);

/* THE GATE.  Nothing here can reach the LUN, block, allocate, or reopen. */
bool mxfs_authority_ok(struct mxfs_authority *auth);
void mxfs_authority_renew(struct mxfs_authority *auth, uint64_t anchor_ms,
			  uint64_t last_ok_ms);
void mxfs_authority_close(struct mxfs_authority *auth, int reason,
			  const char *why);
bool mxfs_authority_take_withdraw(struct mxfs_authority *auth, int *reason_out);

/*
 * (D-REJOIN-CLAIM-ENOSPC-DURING-TRANSIENT-SWEEP-GUARD-AT-CAPACITY-0523,
 * Design-consult ruling ccmemory ccloop-c7ee71c6-sess464-GPT-ruling-d0523-claim-wait-
 * transient-guard-at-capacity): when every slice is occupied but some
 * occupants are TRANSIENT records a live peer resolves (a bucket-sweep guard,
 * a recovery lease, a WITHDRAWN slice awaiting fence+replay, a RETIRE_PENDING
 * record awaiting PR-key retirement proof), the claim WAITS for them instead
 * of failing -ENOSPC.  One absolute deadline, never reset by churn, derived
 * from MEASURED 32-node walls (tests/evidence, extraction of every
 * 'WAIT recovery: ... at +Ns after last kill' line, n~100 over 16 chain
 * logs): kill -> terminal foreign-replay line p50 70 s, max 181 s (includes
 * the 31 x 2 s death window and the PR fence), plus the retirement grace,
 * one heartbeat interval and one guard refresh.  Scans every heartbeat
 * interval: a peer proves itself live by re-stamping within the dead window,
 * a sweep guard by re-stamping within its refresh period.
 */
#define MXFS_DISKLOCK_CLAIM_WAIT_MS     (181000 + MXFS_DISKLOCK_RETIRE_GRACE_MS + \
										 MXFS_DISKLOCK_HB_INTERVAL_MS + \
										 MXFS_DISKLOCK_GUARD_REFRESH_MS)
#define MXFS_DISKLOCK_CLAIM_SCAN_MS     MXFS_DISKLOCK_HB_INTERVAL_MS

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
 * heartbeat-embedded inode-eviction ring.
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
 * by their own magic+crc so stale ring garbage is never misread.
 *
 * (#92 clean-departure): 25 → 23, freeing 32 B for the claim
 * provenance block (mxfs_hb_provenance, between the body union and
 * mepoch).  Same compatibility argument as the 28→25 carve — the ring
 * is a hint, the count guard caps old records, and the provenance
 * block carries its own magic+crc.  Layout change ⇒ MXFS_PROTO_GEN
 * bump (vergate fences old nodes).
 *
 * (docs/whole-cluster-restart.md item 2): 23 → 19, freeing 64 B
 * for the host/boot IDENTITY block (mxfs_hb_identity, between the body
 * union and prov).  Same argument again; the identity block carries its
 * own magic+crc and the layout shift is fenced by MXFS_PROTO_GEN 12. */
#define MXFS_EVICT_RING_ENTRIES     19

/*
 * entry TYPE, carried in the former `pad` field (wire size unchanged,
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
										 * + 19*16 = 320 bytes */

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
 * — the DURABLE RECOVERY DESCRIPTOR (design-consult ruling).
 *
 * The problem it solves.  Everything that tracked "this dead node's slice is
 * being recovered" lived in ONE PLACE: the in-memory recovery_pending[] array
 * of each survivor.  Nothing on disk said so.  Consequences, all proven by
 * line-reading in 
 *   - A survivor that crashes mid-recovery leaves NO record of how far it got;
 *     its successor re-runs from scratch, or (worse) never learns there was a
 *     recovery at all and treats the victim's slot as ordinary garbage.
 *   - The slot state was BINARY — ACTIVE (member) or zeroed (consumable) — so
 *     the only way to say "fenced" was to zero it, and zeroing is also the
 *     cluster-wide "grants released, go ahead" broadcast.  One bit could not
 *     carry two independent facts.
 *   - mount_cohort_complete's `replayed` bitmap has the same defect: it is
 *     in-memory, so a crash between "slice replayed" and "recovery published"
 *     loses the replay evidence entirely.
 *
 * The fix is a MILESTONE STATE MACHINE stamped on the victim's own heartbeat
 * sector, in the previously-unusable evict-ring bytes of a GUARD record:
 *
 *   ACTIVE/WITHDRAWN            the victim, alive or self-declared dead
 *        │  CAS (recovery_begin) — durable BEFORE any purge
 *        ▼
 *   GUARD + desc{FENCED}        victim can no longer write; NOTHING purged
 *        ▼  advance()
 *   GUARD + desc{IMAGES_REPLAYED}
 *        ▼  advance()
 *   GUARD + desc{OBLIGATIONS_DONE}
 *        ▼  advance()
 *   GUARD + desc{GRANTS_RELEASED}   authority purged and durable
 *        ▼  purge_node zeroes the sector
 *   CONSUMABLE (all zeroes)      slot reclaimable, slice reusable
 *
 * Rules the ruling fixed and this layout encodes:
 *
 *   1. ORDERING.  The ACTIVE→GUARD(FENCED) CAS must be DURABLE BEFORE the
 *      first CAW purge.  Purging first is a crash hole: the heartbeat still
 *      reads ACTIVE (so peers believe the victim is a live member) while half
 *      the authority evidence its own replay gate needs is already destroyed.
 *
 *   2. VICTIM IDENTITY IS NEVER OVERWRITTEN.  The GUARD record keeps the
 *      victim's node_id / epoch / fs_gen in the record header; the recovery
 *      owner's identity lives ONLY inside the descriptor.  This is what makes
 *      the broadcast predicate splittable (rule 3) and what lets any survivor
 *      answer "whose slice is this?" from the sector alone.
 *
 *   3. THE BROADCAST PREDICATE SPLITS.  Before this, a peer's monitor treated
 *      "the slot no longer carries the dead stamp" as proof of BOTH "victim
 *      fenced" AND "victim's grants are released", and ran its deferred local
 *      purge.  A GUARD transition would have tripped that — telling every peer
 *      to drop grants that recovery is deliberately holding frozen.  So:
 *        victim fenced          := GUARD + descriptor naming this victim
 *        grants released        := stage >= GRANTS_RELEASED
 *        recovery complete      := sector zeroed (CONSUMABLE)
 *      Only the last one releases a peer's deferred purge.
 *
 *   4. VICTIM-MANIFEST FREEZE.  The on-disk CAW table is simultaneously the
 *      lock table AND the authority manifest that the foreign-replay token
 *      gate reads.  While a descriptor exists at stage < GRANTS_RELEASED the
 *      victim's entries must not be purged, reused, repaired or epoch-reset by
 *      anyone but the recovery owner.  Enforced by: claim_slot never taking a
 *      GUARD slot (pre-existing), guard_slot refusing a slot that carries a
 *      descriptor, and purge_node refusing to zero a guarded sector until the
 *      descriptor says GRANTS_RELEASED.
 *
 *   5. A STALE DESCRIPTOR IS A RECOVERY LEASE, NEVER A MEMBER SLOT.  If the
 *      recovery owner dies mid-recovery its descriptor stops being re-stamped.
 *      A survivor may TAKE OVER (CAS only the owner fields to itself, bump
 *      owner_term) and RESUME FROM THE RECORDED STAGE — it must never re-run
 *      an earlier stage, because peers may already have acted on the later
 *      one.  It may never turn the slot ACTIVE, mount on it, or lay a fresh
 *      journal over the victim's slice until CONSUMABLE.
 *
 *   6. recovery_gen IS THE TRANSACTION, owner_term IS THE AUTHORITY (
 *      design-consult ruling item 7).  recovery_gen names WHICH recovery this is and is
 *      CONSTANT from begin() to the final zero — every takeover inherits it,
 *      so peers can correlate a resumed recovery with the one they saw start.
 *      owner_term is the monotonic "who may execute it right now" counter,
 *      bumped by every takeover.  They must be two fields, not one:
 *      A → B → A within a SINGLE session of A leaves {owner_node, owner_epoch}
 *      byte-identical to what A's still-running worker last saw, so without a
 *      term that worker reads as current and resumes writing under an
 *      authority it no longer holds.  Every stage-changing or non-idempotent
 *      operation therefore revalidates the whole authorization tuple
 *      {victim_node, victim_epoch, recovery_gen, owner_node, owner_epoch,
 *      owner_term} — that tuple is struct mxfs_recov_auth, handed out by
 *      begin()/takeover() and demanded back by advance()/refresh().
 *
 * Abandonment is detected the same way the sweep guard detects it: by
 * ABSENCE OF CHANGE across MXFS_RECOV_ABANDON_MS.  Never by comparing
 * owner_stamp_ms to the reader's clock — mxfs_pal_time_ms() is per-node boot
 * time and cross-node arithmetic on it is meaningless.  ANY of {owner_stamp_ms,
 * stage, stage_seq, owner_term, recovery_gen, owner identity} changing counts
 * as liveness, not just the stamp.
 *
 * A STALLED STAMP IS NOT PERMISSION TO TAKE OVER.  It proves only "I observed
 * no refresh" — never "the old owner cannot resume".  A delayed workqueue, a
 * device timeout or a scheduler stall all produce a stalled stamp on a node
 * that is about to wake up and keep writing.  The caller MUST have confirmed
 * the owner's session dead and FENCED from the LUN before calling takeover;
 * the stall probe is the second gate, not the first.
 *
 * Wire placement: the descriptor OVERLAYS the evict ring (union below).  That
 * is sound because the evict ring is produced only into a node's own ACTIVE
 * record and consumed only from a peer's ACTIVE record (the monitor's ring
 * consumer sits behind a flags == ACTIVE test), so a GUARD record's ring bytes
 * are dead space in every existing build.  No region growth, no mkfs change,
 * and the descriptor carries its own magic + crc so a pre-sess64 node's zeroed
 * or ring-shaped bytes can never be misread as a descriptor.
 */
#define MXFS_RECOV_DESC_MAGIC       0x5643524Du  /* "MRCV" LE */
/*
 * v2 adds the FENCE CERTIFICATE and the FENCING intent stage, and
 * renumbers the stage ladder to make room for the intent below FENCED.
 * Renumbering is safe ONLY because v1 and v2 can never coexist in a cluster:
 * MXFS_PROTO_GEN moved 1 -> 2 in the same change, so the C7 gate
 * refuses the mount (superblock) and fences a live mismatched incarnation
 * (heartbeat feature block).  Do NOT change the descriptor version without
 * bumping MXFS_PROTO_GEN — the ruling refuted the idea that
 * per-slot version-mismatch is fail-closed on its own: today's replayer
 * REPLAYS FIRST and only consults the descriptor afterwards, so a v1 node
 * would replay a v2-fenced slice on the old ungated path.
 */
/*
 * v3 inserts the SNAPSHOTTING stage between FENCING and FENCED and
 * adds the recovery-MANIFEST POINTER record after the outcome record (see
 * docs/recovery-manifest.md).  Same coexistence argument as v2: MXFS_PROTO_GEN
 * moved 6 -> 7 with the rman envelope region, so a v2 node can never share a
 * cluster with a v3 node and the renumbered ladder is never read by v2 code.
 */
#define MXFS_RECOV_DESC_VERSION     3

/*
 * Milestones.  Monotonic: a stage may only ever advance.
 *
 * FENCING is an INTENT, not a fence (ruling, rule-1 amendment).  It is
 * written BEFORE the PREEMPT AND ABORT is issued so that the attempt is
 * serialised cluster-wide, the exact victim key and pre-command observations
 * are preserved, and a crash between "P&A completed at the target" and "the
 * certificate is durable" is distinguishable from "fencing never started".
 * It authorises NOTHING: no replay, no purge, no manifest repair or reuse, no
 * grants release, no broadcast, no zeroing.  Only a CERTIFIED FENCED
 * descriptor does that.
 */
/*
 * (docs/recovery-manifest.md): SNAPSHOTTING sits between FENCING and
 * FENCED.  Exclusion has been PROVED and the certificate bytes are durable,
 * but the victim's fence-time authority manifest is not yet sealed.  Every
 * gate that demands stage >= FENCED therefore still refuses (no claim, no
 * replay, no purge), while the writer guard's protection of the victim's CAW
 * bits starts here.  The prover keeps the fencing-ATTEMPT lease through this
 * stage and releases it (UNOWNED) only in the SNAPSHOTTING -> FENCED CAS that
 * also publishes the manifest pointer.  A prover death here is recovered by
 * the fencing-attempt takeover, which redoes the scan (idempotent; seq bumps)
 * and NEVER redoes the P&A (the key is already consumed).
 */
#define MXFS_RECOV_STAGE_NONE               0
#define MXFS_RECOV_STAGE_FENCING            1
#define MXFS_RECOV_STAGE_SNAPSHOTTING       2
#define MXFS_RECOV_STAGE_FENCED             3
#define MXFS_RECOV_STAGE_IMAGES_REPLAYED    4
#define MXFS_RECOV_STAGE_OBLIGATIONS_DONE   5
#define MXFS_RECOV_STAGE_GRANTS_RELEASED    6
#define MXFS_RECOV_STAGE_MAX                MXFS_RECOV_STAGE_GRANTS_RELEASED

/* mxfs_disklock_recovery_fence_intent(): positive return meaning "this is our
 * own attempt, exclusion is already proved and durable at SNAPSHOTTING; do
 * NOT issue a P&A — resume at the manifest snapshot". */
#define MXFS_FENCE_INTENT_SNAPSHOT_PENDING  2

/*
 * UNOWNED — a distinct state, never "an abandoned owner" (ruling).
 *
 * The node that PROVES exclusion and the node that REPLAYS are structurally
 * different: exactly one node's PREEMPT AND ABORT wins the race, every other
 * survivor gets RESERVATION CONFLICT, and the replayer is chosen by
 * lowest_live_slot — measured on the rig at 1 winner / 30 losers.
 * So the certificate is published by the PROVER into the VICTIM's own sector
 * with NO recovery owner, and the elected replayer CLAIMS it.
 *
 * Claiming an unowned recovery lease is NOT takeover: there is no prior owner
 * to displace, nothing to prove dead, and no stage to resume.  It is a
 * whole-descriptor CAS that validates the immutable certificate bytes and
 * establishes owner_term 1 atomically.  owner_node == 0 must be impossible
 * for a real node (every API here rejects node id 0), which is what keeps the
 * two states from ever aliasing.
 */
#define MXFS_RECOV_OWNER_NONE       0u

/*
 * Terminal quarantine.  Set when the victim's slice carries an obligation this
 * build cannot discharge soundly — an unsupported intent type, or an
 * intent/done pair whose admission verdicts are contradictory (design review: "admitted
 * intent + REJECTED done is genuinely ambiguous; honouring it suppresses
 * unreplayed work, ignoring it double-frees metadata that did reach home —
 * quarantine, never guess").  A quarantined slot NEVER becomes consumable on
 * its own: its grants stay frozen, its slice is never reused, and it takes
 * operator action.  Losing capacity is the correct failure; silently
 * publishing a slice with undischarged obligations is not.
 */
#define MXFS_RECOV_F_QUARANTINED    0x00000001u
/* The victim declared its own death (WITHDRAWN) rather than being detected. */
#define MXFS_RECOV_F_VICTIM_WITHDREW 0x00000002u
/*
 * the victim's own record carried a VALID feature block with
 * MXFS_HB_FEAT_SNLOCAL set — its incarnation durably classified itself a
 * single-node local log BEFORE writing (ruling item 1).  Captured at
 * descriptor creation from the victim record being overlaid and immutable
 * from then on, like MXFS_RECOV_F_VICTIM_WITHDREW.  A recovery certificate
 * NEVER retroactively classifies untagged records (precedent boundary) —
 * this flag is the only way a replay may learn the victim was snlocal.
 */
#define MXFS_RECOV_F_VICTIM_SNLOCAL  0x00000004u
/*
 * (D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381) — THE
 * COMMAND-SUBMISSION BOUNDARY, MADE DURABLE.
 *
 * Set immediately BEFORE a state-changing PR command (PREEMPT / PREEMPT AND
 * ABORT) is handed to the transport, and never cleared while the attempt
 * stands.  It is MONOTONIC, like the other flags here, and it is deliberately
 * the "may have run" polarity rather than "nothing ran": a fresh intent has it
 * clear by construction, every pre-command early return leaves it clear, and
 * nothing has to succeed at clearing it on a path that must not fail.  The name
 * is also the contract — it may NEVER be read as proof that submission DID
 * happen, only that it might have.
 *
 * The three durable states this creates, with `stage`:
 *   FENCING, bit CLEAR  — GUARANTEED no state-changing command was submitted
 *                         for this standing attempt.  Nothing was consumed, the
 *                         victim key is intact, and the attempt is safe to
 *                         repeat.  This is the state the fence-retry worker
 *                         drives.
 *   FENCING, bit SET    — a command may have reached the target, including the
 *                         case "it executed and the response was never seen".
 *                         MUST be reconciled against a coherent PR view before
 *                         anything is assumed; it is NOT retryable-as-harmless.
 *   stage >= FENCED     — a certificate.
 *
 * Crash between setting the bit and submitting leaves the conservative
 * ambiguous state, which is the correct failure mode.
 *
 * 0.89.9 (D-FENCE-CRASH-MATRIX-UNTESTED, sweep s71a cuts 3 and 4; design-
 * consult ruling): the bit is scoped to the CURRENT fence_term.  A fencing-
 * attempt takeover starts a new term under which nothing has been submitted,
 * so it clears this bit and folds the dead term's value into
 * MXFS_RECOV_F_FENCE_PRIOR_TERM_MAY_HAVE_RUN below.  Measured before that:
 * the successor inherited the dead prover's armed bit, its first prove
 * returned NO_RESERVATION before any command (another victim's single-holder
 * gate was in force), and the retry worker then refused the descriptor as
 * ambiguous for good — the slice was never certified and the successor's own
 * mount barrier failed.
 */
#define MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN 0x00000008u
/* the victim's own record carried MXFS_HB_FEAT_ADOPTED (pass-2 fresh
 * claim — previous incarnations' records in its slice are published by
 * construction), captured at descriptor creation like VICTIM_SNLOCAL. */
#define MXFS_RECOV_F_VICTIM_ADOPTED  0x00000010u
/*
 * (docs/whole-cluster-restart.md §6.2, design-consult ruling Q2): the
 * recovery OWNER is a whole-cluster bootstrap owner — a provisional identity
 * that holds NO heartbeat slot and heartbeats only in the bootstrap record.
 * An explicit owner kind, not a magic slot value: every consumer of
 * owner_slot dispatches on this bit.  Set ⇒ owner_slot MUST be
 * MXFS_RECOV_NO_SLOT and liveness of {owner_node, owner_epoch} is answered
 * by mxfs_bootstrap_owner_is(); clear ⇒ owner_slot < MXFS_DISKLOCK_HB_SLOTS
 * and liveness is the heartbeat table.  Written by every owner-field write
 * (begin, intent, claim, takeover, fence_takeover) from ctx->owner_bootstrap,
 * so an ordinary member taking over a bootstrap owner's descriptor clears it.
 */
#define MXFS_RECOV_F_OWNER_BOOTSTRAP 0x00000020u
#define MXFS_RECOV_NO_SLOT           0xFFFFu
/*
 * 0.74.0 (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904): the
 * prover's bounded series of NON-PROVING pre-command fence attempts has
 * expired — every attempt returned before any PREEMPT-family command was
 * submitted (the victim key is absent and no gate applies, or the target
 * holds no reservation, or the view was truncated), so nothing was consumed
 * and nothing was proved.  The descriptor stays at FENCING under the same
 * attempt lease and the prover keeps re-driving it slowly; this bit is the
 * DURABLE, cluster-visible statement that recovery of this slice is BLOCKED
 * pending a change in PR state or operator action, so a peer reading the
 * sector can tell "blocked" from "in progress".  Cleared by the certify CAS
 * (the series ended in a proof) and by a fencing-attempt takeover (a new
 * prover starts a new series).
 */
#define MXFS_RECOV_F_FENCE_BLOCKED   0x00000040u
/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED, completion): the explicit ZERO
 * CENSUS discriminator.  Set in the IMAGES_REPLAYED compare-and-write when the
 * replayed slice carried NO open intent obligation, so a descriptor at or past
 * IMAGES_REPLAYED is in exactly one of three states: CENSUS_ZERO with an
 * all-zero record region (nothing owed), a valid record (OPEN, TERMINAL
 * evidence, or DONE), or INVALID (anything else — an unreadable record, or
 * neither the flag nor a record).  "No record" is never read as "no
 * obligations": the purge milestone refuses the INVALID state and the freeze
 * consumer treats it as a whole-filesystem freeze.
 */
#define MXFS_RECOV_F_CENSUS_ZERO     0x00000080u
/*
 * 0.89.9: a PREVIOUS fence_term of this standing attempt was armed when its
 * prover died — a PREEMPT-family command MAY have reached the target under
 * that dead term and its result is lost.  Set by the fencing-attempt takeover
 * from the dead term's MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN (or from this bit,
 * across successive takeovers) and never cleared while the attempt stands;
 * the certify CAS ends the attempt.  History, not scheduling: the retry
 * predicate looks only at the current term's bit, because a new term that
 * submitted nothing is safe to re-drive.  What this bit forbids is reading
 * the victim key's absence as that dead command's success — an absent key
 * stays KEY_ABSENT_UNPROVEN until a mechanism of the current term names
 * itself (self succession, boot succession, the sole-survivor gate).
 */
#define MXFS_RECOV_F_FENCE_PRIOR_TERM_MAY_HAVE_RUN 0x00000100u

/*
 * THE FENCE CERTIFICATE (v2).
 *
 * Fields 76..115 are the certificate.  It is COMPLETE at FENCED and IMMUTABLE
 * from then on: claim, advance, refresh and takeover all carry it through byte
 * for byte and revalidate it.  A replay gate does not ask "is there a
 * descriptor and is its fence_kind in a set"; it revalidates the whole
 * certificate against the sector's own identity (ruling, Q4).
 *
 * At FENCING the same bytes hold the ATTEMPT state — who is trying, on which
 * attempt term, against which key, since when.  That is deliberate and cannot
 * be mistaken for a certificate: fence_kind stays MXFS_FENCE_KIND_NONE and
 * fence_resv_type stays 0 until certify writes them, and every gate demands
 * BOTH stage >= FENCED AND a fence_kind that
 * mxfs_fence_durable_kind_supported() classifies into a proof contract this
 * build still supports.  An intent therefore reads as "not certified" on
 * every path, and so does a certificate written under a contract that has
 * since been revoked.
 *
 * fence_victim_key is the one field whose MEANING moves with the stage: at
 * FENCING it is the key this attempt INTENDS to remove (recorded before the
 * P&A is issued, so a successor can see what was in flight); at FENCED it is
 * the key the P&A actually removed, and certify REFUSES a result whose key
 * differs from the intent.
 *
 * fence_pr_gen is DIAGNOSTIC ONLY.  It is a wrapping counter that unrelated
 * PR operations also move; it is not a transaction id and nothing may be
 * gated on it.  It exists so a reader can say "the registration table has
 * changed since this observation" — never "this observation is still true".
 */
struct mxfs_recov_desc {
	uint32_t    magic;              /*  0: MXFS_RECOV_DESC_MAGIC */
	uint16_t    version;            /*  4: MXFS_RECOV_DESC_VERSION */
	uint16_t    stage;              /*  6: MXFS_RECOV_STAGE_* */
	uint64_t    victim_epoch;       /*  8: the victim INCARNATION being recovered */
	uint64_t    owner_epoch;        /* 16: recovery owner's mount incarnation */
	uint64_t    recovery_gen;       /* 24: identity of the recovery TRANSACTION
									 *     — CONSTANT across takeover (rule 6) */
	uint64_t    owner_stamp_ms;     /* 32: owner liveness re-stamp (owner clock) */
	uint32_t    victim_node;        /* 40 */
	uint32_t    owner_node;         /* 44: MXFS_RECOV_OWNER_NONE while unowned */
	uint32_t    victim_fs_gen;      /* 48: mkfs generation this recovery belongs to */
	uint32_t    flags;              /* 52: MXFS_RECOV_F_* */
	uint16_t    victim_slot;        /* 56: the HB slot this descriptor sits in */
	uint16_t    owner_slot;         /* 58 */
	uint16_t    slice_idx;          /* 60: journal slice the victim owned */
	uint16_t    slice_count;        /* 62: slice divisor in force at begin() */
	uint64_t    stage_seq;          /* 64: monotonic milestone counter */
	uint32_t    owner_term;         /* 72: RECOVERY-EXECUTION term.  0 while
									 *     unowned; 1 on claim; bumped by every
									 *     execution takeover (rule 6) */
	/* ── the certificate: written once at FENCING->FENCED, then immutable ── */
	uint16_t    fence_kind;         /* 76: enum mxfs_fence_kind that was proved */
	uint16_t    fence_resv_type;    /* 78: MXFS_PAL_PR_TYPE_* held at the verify */
	uint64_t    fence_victim_key;   /* 80: FENCING: the key this attempt intends
									 *     to remove.  FENCED: the key the P&A
									 *     actually removed (certify refuses a
									 *     result that disagrees with the intent) */
	uint64_t    fence_prover_epoch; /* 88: prover's mount incarnation */
	uint64_t    fence_stamp_ms;     /* 96: prover clock at certification */
	uint32_t    fence_prover_node;  /*104: who proved it (never 0 once certified) */
	uint32_t    fence_pr_gen;       /*108: PR generation at the verifying read —
									 *     DIAGNOSTIC ONLY, never a gate */
	uint32_t    fence_term;         /*112: FENCING-ATTEMPT term, bumped by every
									 *     fencing-attempt takeover.  Kept apart
									 *     from owner_term deliberately: the
									 *     attempt lease and the execution lease
									 *     are different authorities held by
									 *     different nodes at different stages */
	uint32_t    crc32c;             /*116: over bytes 0..115 + victim identity */
};                                  /* 120 */

/* How often the recovery owner re-stamps owner_stamp_ms. */
#define MXFS_RECOV_REFRESH_MS       1000

/*
 * How long a descriptor must show NO CHANGE AT ALL before a caller that has
 * already confirmed the owner dead+fenced may take it over.
 *
 * This is a CORRECTNESS lease, not a liveness heuristic, so it is deliberately
 * far longer than the refresh cadence (design-consult ruling item 4).  The old
 * value — 3 * MXFS_RECOV_REFRESH_MS — is inside the noise of this stack: a
 * delayed workqueue behind a long replay, a SCSI command that takes the LIO
 * target's retry path, or a scheduler stall on a 32-node host under load all
 * exceed 3 s routinely.  Six seconds of provable silence costs a few seconds
 * of recovery latency in the rare owner-death case; getting it wrong hands two
 * nodes the same recovery.
 */
#define MXFS_RECOV_ABANDON_MS       6000

/*
 * The authorization tuple for a recovery this node owns (rule 6).
 *
 * Handed out by recovery_begin()/recovery_takeover() and demanded back by
 * every stage-changing or non-idempotent op, which revalidates it against the
 * sector before writing.  Holding one is NOT durable authority — it is only a
 * claim to be rechecked; the platter is always the authority.
 */
struct mxfs_recov_auth {
	mxfs_node_id_t  victim_node;
	uint64_t        victim_epoch;
	uint64_t        recovery_gen;
	uint32_t        owner_term;
	uint16_t        victim_slot;
	uint16_t        stage;          /* stage observed when the auth was issued */
};

/*
 * The FENCING-ATTEMPT authorization tuple (ruling: keep the fencing
 * lease and the recovery-execution lease semantically separate even though
 * one descriptor encodes both).  Held by the PROVER between fence_intent()
 * and fence_certify(); never by the replayer, which holds mxfs_recov_auth.
 * Presenting one where the other is required cannot type-check.
 */
struct mxfs_recov_fence_auth {
	mxfs_node_id_t  victim_node;
	uint64_t        victim_epoch;
	uint64_t        recovery_gen;
	uint64_t        victim_key;     /* observed BEFORE the P&A was issued */
	uint32_t        fence_term;
	uint16_t        victim_slot;
};

/*
 * ── THE TERMINAL RECOVERY OUTCOME RECORD (ruling) ─────────
 *
 * Written by the recovery-lease OWNER when it refuses to publish a victim's
 * slice as recovered — either the replay policy refused every obligation
 * (foreign gate: 0 applied / N refused) or the slice is physically torn.
 * Publishing "recovered" in that state suppresses unreplayed work; publishing
 * nothing leaves 31 survivors to time out one by one into their own
 * shutdowns (the proven all-32 suicide of D-513).  The outcome record is the
 * third verdict: TERMINAL REFUSED, durable in the victim's own sector next
 * to the descriptor, imported by every survivor's monitor so the whole
 * cluster converges on the same quarantine domain instead of dying.
 *
 * It lives at byte 120 of mxfs_recov_body — after the descriptor, inside
 * bytes the pad already owned — so the sector layout does not move.  It has
 * its own magic/version/crc: a descriptor from a build that never wrote an
 * outcome presents zeroes here, which fail the magic test and read as "no
 * outcome", never as garbage.  The crc binds the record to the sector's
 * victim identity exactly as recov_desc_crc does, so an outcome spliced next
 * to a different victim's header never validates.
 *
 * The record is written ONLY together with MXFS_RECOV_F_QUARANTINED in the
 * descriptor flags, and every stage gate already refuses a quarantined
 * descriptor, so the state machine cannot advance past it: it is terminal
 * until operator action.
 */
#define MXFS_RECOV_OUTCOME_MAGIC    0x4F435652u  /* "RVCO" LE */
#define MXFS_RECOV_OUTCOME_VERSION  1

/* outcome */
#define MXFS_RECOV_OUTCOME_TERMINAL_REFUSED     1u
/* reason */
#define MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE  1u  /* gate refused all */
#define MXFS_RECOV_REFUSAL_PHYSICALLY_TORN          2u  /* slice unreadable/corrupt */
/*
 * /(ruling Q1 + ruling): BACKFILL
 * provenance, never a fresh verdict.  A descriptor QUARANTINED with an
 * ALL-ZERO outcome region is the legacy intent-path quarantine: builds
 * before the outcome record set MXFS_RECOV_F_QUARANTINED alone
 * (undischargeable intent obligations), leaving terminal-but-
 * uncommunicated state — peers park forever and a remount cannot
 * reconstruct the verdict (the D-513 shape again).  No recovery auth can
 * EVER exist over a quarantined descriptor (the claim path's certificate
 * evaluator refuses it, verified), so the backfill is leaseless:
 * recovery_backfill_legacy() synthesizes a terminal record with THIS
 * reason so the record's provenance is honest — the quarantine is
 * inherited, not the result of a replay this build ran.  Domain is FSWIDE
 * because the intent path recorded no domain evidence (verified 
 * no in-tree setter writes the flag without an outcome).
 * publish_refusal() REJECTS this reason (-EINVAL); only the backfill API
 * writes it, only against an already-QUARANTINED descriptor whose outcome
 * region is exactly all-zero — it can backfill, never overwrite.
 */
#define MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE 3u  /* backfilled verdict */
/*
 * (docs/recovery-manifest.md): the victim's FENCE-TIME AUTHORITY
 * CHANGED after the manifest was sealed — the current-safety check at
 * replay, or the pre-purge revalidation, found a manifest entry whose live
 * CAW slot no longer shows the victim's bit with the same mode, lineage and
 * grant epoch.  That is a broken protocol invariant (the writer guard
 * should make it impossible), never a transient: retrying would either loop
 * or succeed only because a further mutation hid the first.  Terminal,
 * FSWIDE, no purge, no slice clean, no slot reuse; operator action.
 */
#define MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED        4u
/*
 * the victim's sealed fence-time manifest is STRUCTURALLY invalid
 * (unsealed, bad crc, pointer mismatch, malformed entries) — -EPROTO from
 * mxfs_disklock_recovery_manifest_read.  Deterministic: re-reading yields the
 * same bytes and nothing can re-snapshot a FENCED victim, so retrying would
 * park the survivors into the D-513 shape.  Terminal, FSWIDE, no purge.
 * (An I/O error reading the manifest is NOT this — that stays retryable.)
 */
#define MXFS_RECOV_REFUSAL_MANIFEST_INVALID         5u
/* transaction assembly crossed an ophdr discontinuity in a
 * PROVEN-STABLE slice snapshot (stale prior-life records inside the
 * [tail,head] span dropped expected regions).  Terminal for this
 * snapshot/lifecycle generation — rereading identical bytes cannot
 * converge — but explicitly NOT a media tear. */
#define MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY   6u
/* a TEST INJECTION published by the recovery owner through the
 * normal refusal path (mxfs.dbg_purge_refreeze) so the purge's mid-scan
 * and final-heartbeat authority re-derivations can be exercised against a
 * real on-disk descriptor transition.  Terminal like every other reason;
 * chk_mxfs names it so an operator never mistakes it for a real verdict. */
#define MXFS_RECOV_REFUSAL_DBG_INJECTED             7u
/* (D-FOREIGN-SLICE-INTENTS-ABANDONED interim, barrier
 * ruling): the victim's slice carries intent items (EFI/RUI/CUI/BUI/ATTRI/
 * XMI) whose done items never landed inside the slice.  Nothing on the
 * replay path may complete a dead peer's intents, so the slice is refused
 * BEFORE any purge — terminal, domain = the open intents' AGs (FSWIDE when
 * unmappable), no slot reuse; operator repair.  The only fix that could
 * ever clear it is real obligation completion (ledger record item 5). */
#define MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED     8u
/* 0.85.0: the completion engine found an obligation extent PARTIALLY free
 * (the bnobt covers some but not all of it), or the allocation metadata of an
 * obligation AG failed verification while completing it.  Neither "still
 * allocated" nor "already free", so nothing may be freed and nothing may be
 * skipped: terminal, domain = the record's AG mask, no purge; operator
 * repair.  Published by the custodian while it still holds the execution
 * lease, over a descriptor at IMAGES_REPLAYED carrying an OPEN record. */
#define MXFS_RECOV_REFUSAL_OBLIGATION_UNRECONCILABLE 9u
/* domain_kind */
#define MXFS_RECOV_DOMAIN_FSWIDE    1u  /* quarantine the whole filesystem */
#define MXFS_RECOV_DOMAIN_AG_MASK   2u  /* quarantine only the AGs in ag_mask */
/* flags (ruling item 5): digest must not gate containment.
 * DIGEST_VALID set = slice_digest is a real reread crc of the refused image;
 * clear = the forensic reread failed and slice_digest is zero.  The verdict
 * publishes either way — a missing digest weakens forensics, never safety. */
#define MXFS_RECOV_OUTCOME_F_DIGEST_VALID   (1u << 0)

struct mxfs_recov_outcome {
	uint32_t    magic;          /*  0: MXFS_RECOV_OUTCOME_MAGIC */
	uint16_t    version;        /*  4: MXFS_RECOV_OUTCOME_VERSION */
	uint16_t    outcome;        /*  6: MXFS_RECOV_OUTCOME_* */
	uint16_t    reason;         /*  8: MXFS_RECOV_REFUSAL_* */
	uint16_t    domain_kind;    /* 10: MXFS_RECOV_DOMAIN_* */
	uint16_t    victim_slot;    /* 12 */
	uint16_t    owner_slot;     /* 14 */
	uint64_t    victim_epoch;   /* 16 */
	uint64_t    owner_epoch;    /* 24 */
	uint64_t    recovery_gen;   /* 32: ties the refusal to the recovery txn */
	uint64_t    ag_mask;        /* 40: valid iff domain_kind == AG_MASK; bit n
								 *     = AG n is quarantined (AGs >= 64 force
								 *     FSWIDE at collection time) */
	uint64_t    slice_digest;   /* 48: crc32c of the refused slice image,
								 *     reread at refusal time — forensic
								 *     identity of WHAT was refused */
	uint64_t    publish_seq;    /* 56: monotonic per-victim publish counter;
								 *     importers dedup on (victim_epoch, seq) */
	uint32_t    victim_node;    /* 64 */
	uint32_t    victim_fs_gen;  /* 68 */
	uint32_t    owner_node;     /* 72: who refused */
	uint32_t    owner_term;     /* 76: owner_term at publication */
	uint32_t    refused_items;  /* 80: log items the gate refused */
	uint32_t    malformed_items;/* 84: log items that failed to parse */
	uint32_t    flags;          /* 88: MXFS_RECOV_OUTCOME_F_* (was pad0;
								 *     old records read as flags==0 =
								 *     digest not validated) */
	uint32_t    crc32c;         /* 92: over bytes 0..91 + victim identity */
};                              /* 96 */

/*
 * The refusal verdict as it crosses the layer boundary — filled by the XFS
 * replay layer at the refusal site (publish direction) and handed back to
 * the XFS layer by the monitor import (consume direction).  Deliberately the
 * SAME struct both ways so the two paths cannot diverge in what they carry.
 */
struct mxfs_recov_refusal_info {
	uint16_t    reason;         /* MXFS_RECOV_REFUSAL_* */
	uint16_t    domain_kind;    /* MXFS_RECOV_DOMAIN_* */
	uint64_t    ag_mask;
	uint64_t    slice_digest;   /* meaningful iff digest_valid */
	uint32_t    refused;
	uint32_t    malformed;
	bool        digest_valid;   /* forensic reread succeeded; when
								 * false the outcome still publishes with
								 * slice_digest zeroed and the DIGEST_VALID
								 * flag clear (ruling item 5) */
};

/*
 * ── THE RECOVERY-MANIFEST POINTER (docs/recovery-manifest.md) ─────
 *
 * Written by the PROVER in the SNAPSHOTTING -> FENCED CAS, after the victim's
 * fence-time authority manifest has been written, flushed and SEALED in the
 * envelope's rman region (slot = victim_slot).  It names exactly which sealed
 * manifest the certificate vouches for: snapshot seq, entry count, exact byte
 * length, the crc32c of the entry area and the crc32c of the sealed header.
 * The replayer loads the manifest and validates the header against this
 * record before any verdict is taken from it; a mismatch is a broken
 * recovery invariant (attempt abort), never a per-transaction skip.
 *
 * It lives at body byte 216, immediately after the outcome record, inside
 * bytes the pad owned.  Own magic/version/crc bound to the victim identity
 * exactly like the descriptor and the outcome.  A certified (stage >= FENCED)
 * descriptor WITHOUT a valid pointer is not a certificate this build accepts
 * (mxfs_recov_cert_proves_exclusion demands it).
 */
#define MXFS_RECOV_MPTR_MAGIC       0x50564D52u  /* "RMVP" LE */
#define MXFS_RECOV_MPTR_VERSION     1
/* flags */
#define MXFS_RECOV_MPTR_F_NO_CAW_TABLE  (1u << 0)  /* transport has no CAW
													* table; manifest is
													* structurally empty and
													* lookups answer -ENODEV
													* (the pre-manifest
													* behaviour) */
#define MXFS_RECOV_MPTR_F_INJECT_TORN   (1u << 1)  /* test knob: header was
													* deliberately written
													* with a bad entries crc */
#define MXFS_RECOV_MPTR_F_TAUTH_LEDGER  (1u << 2)  /* TCP transport: the
													* entries were collected
													* from the durable
													* authority ledger, not
													* the CAW slot table;
													* scan_slots = ledger
													* pages scanned (the
													* consumer checks it
													* against its region) */

struct mxfs_recov_manifest_ptr {
	uint32_t    magic;          /*  0: MXFS_RECOV_MPTR_MAGIC */
	uint16_t    version;        /*  4: MXFS_RECOV_MPTR_VERSION */
	uint16_t    flags;          /*  6: MXFS_RECOV_MPTR_F_* */
	uint64_t    seq;            /*  8: snapshot sequence (bumps per scan) */
	uint64_t    scan_stamp_ms;  /* 16: writer clock at scan start */
	uint32_t    entry_count;    /* 24 */
	uint32_t    byte_len;       /* 28: exact bytes of the entry area */
	uint32_t    entries_crc32c; /* 32: crc32c over the entry area */
	uint32_t    hdr_crc32c;     /* 36: the sealed header's hdr_crc32c */
	uint32_t    writer_node;    /* 40: MANIFEST WRITER (the attempt-lease
								 *     holder that scanned + sealed) — NOT
								 *     necessarily the fence prover, which the
								 *     descriptor's certificate names */
	uint32_t    fence_term;     /* 44: the certificate's fencing-attempt term
								 *     (immutable; a SNAPSHOTTING takeover
								 *     does NOT bump it) */
	uint32_t    scan_slots;     /* 48: CAW slots scanned (65536, or 0 NO_CAW) */
	uint32_t    crc32c;         /* 52: over bytes 0..51 and 56..63 + victim
								 *     identity (the crc field itself is
								 *     skipped — see recov_mptr_crc) */
	uint64_t    writer_epoch;   /* 56: the writer's mount incarnation */
};                              /* 64 */

/* The descriptor plus the rest of the evict-ring footprint it overlays. */
struct mxfs_recov_body {
	struct mxfs_recov_desc      desc;
	struct mxfs_recov_outcome   outcome;    /* terminal refusal */
	struct mxfs_recov_manifest_ptr mptr;    /* manifest pointer */
	struct mxfs_recov_obl       obl;        /* sess462: obligation record —
											 * the last 40 pad bytes (sess346:
											 * 200→168; sess405: →104; sess438
											 * identity carve: →40; sess462: 0).
											 * All-zero = no record (pre-0.62.1
											 * builds); recov_obl.h */
};

/*
 * ── THE RECOVERY MANIFEST ON DISK (envelope rman region) ──────────
 *
 * One slot per disklock heartbeat slot, MXFS_RMAN_SLOT_BYTES each (see
 * include/mxfs/mxfs_super.h): a 4 KiB header at slot offset 0, the entry area
 * at MXFS_RMAN_ENTRIES_OFF (64 KiB, leaving the header zone room to grow),
 * 32-byte entries in CAW-slot order.  Entries record every CAW slot whose
 * EX or PW bitmap carried the victim bit at scan time — the authority the
 * victim HELD AT DEATH.  PR-only / waiter / open-holder footprints are NOT
 * authority (they never satisfy APPLY) and are not recorded.
 *
 * Write protocol (prover, attempt lease held, descriptor at SNAPSHOTTING):
 *   1. header zeroed + flush     (invalidates any stale sealed manifest)
 *   2. entries written + flush
 *   3. header written with seal + crc, + flush   (SEALED)
 *   4. descriptor CAS SNAPSHOTTING -> FENCED with the pointer.
 * Sealed = magic/version OK AND hdr_crc32c valid AND seal == MXFS_RMAN_SEAL.
 * A torn header write fails the crc and reads as unsealed; a header from an
 * earlier snapshot/incarnation fails the pointer match (seq/epoch/term).
 */
#define MXFS_RMAN_MAGIC         0x4D52584Du  /* "MXRM" LE */
#define MXFS_RMAN_VERSION       1
#define MXFS_RMAN_SEAL          0x4C41455344454C53ULL /* "SLEDSEAL" */
#define MXFS_RMAN_ENTRIES_OFF   65536u
#define MXFS_RMAN_MAX_ENTRIES   65536u
/* Entry-area I/O is done in whole 4 KiB blocks: a writer's entry buffer MUST
 * be zero-padded (readable) up to round_up(count*32, MXFS_RMAN_IO_ALIGN) —
 * the 2 MiB collection buffer is; the crc covers the exact byte_len only. */
#define MXFS_RMAN_IO_ALIGN      4096u

/* entry.mode bits */
#define MXFS_RMAN_MODE_EX       0x01u
#define MXFS_RMAN_MODE_PW       0x02u

struct mxfs_rman_entry {
	uint8_t     type;           /*  0: enum mxfs_lock_type of the CAW slot */
	uint8_t     mode;           /*  1: MXFS_RMAN_MODE_* held by the victim */
	uint16_t    flags;          /*  2: 0 */
	uint32_t    slot_idx;       /*  4: CAW slot index (diagnostic) */
	uint64_t    id;             /*  8: ag number (AG) or inode number
								 *     (INODE / ICLUSTER cluster base) */
	uint64_t    lineage;        /* 16: resource_lineage at scan */
	uint64_t    grant_epoch;    /* 24: ex_grant_epoch at scan */
};                              /* 32 */

struct mxfs_rman_hdr {
	uint32_t    magic;          /*  0: MXFS_RMAN_MAGIC */
	uint16_t    version;        /*  4: MXFS_RMAN_VERSION */
	uint16_t    victim_slot;    /*  6 */
	uint32_t    victim_node;    /*  8 */
	uint32_t    victim_fs_gen;  /* 12 */
	uint64_t    victim_epoch;   /* 16 */
	uint64_t    recovery_gen;   /* 24 */
	uint32_t    fence_term;     /* 32: the certificate's term (immutable) */
	uint32_t    writer_node;    /* 36: manifest writer (attempt-lease holder) */
	uint64_t    writer_epoch;   /* 40: its mount incarnation */
	uint64_t    seq;            /* 48 */
	uint64_t    scan_stamp_ms;  /* 56 */
	uint32_t    entry_count;    /* 64 */
	uint32_t    byte_len;       /* 68 */
	uint32_t    entries_crc32c; /* 72 */
	uint32_t    scan_slots;     /* 76 */
	uint32_t    flags;          /* 80: MXFS_RECOV_MPTR_F_* (same namespace) */
	uint32_t    hdr_crc32c;     /* 84: over bytes 0..83 */
	uint64_t    seal;           /* 88: MXFS_RMAN_SEAL, written in the same
								 *     sector as the crc (step 3) */
	uint8_t     pad[4000];      /* to 4096 */
};

/*
 * C7 version gate — heartbeat-embedded feature declaration.
 *
 * Every gate-aware member publishes its protocol generation in the SAME
 * single-sector HB/claim write, so the declaration exists from the node's
 * very first write.  Pre-gate nodes wrote zeros here (magic==0 → LEGACY).
 * The crc binds the declaration to the claimant INCARNATION (fs_gen,
 * node_id, epoch folded in — see mxfs_hb_feature_crc in disklock.c), so a
 * feature block cannot be validated against a different incarnation's
 * identity fields after a torn/spliced event.  Enforcement:
 *   - joiners quarantine until every live current-fs_gen peer validates
 *     (mxfs_disklock_join_gate);
 *   - the monitor re-validates every live record each pass and fences a
 *     live LEGACY/mismatched incarnation (vergate_cb → SCSI-PR fence);
 *   - a joiner facing an ESTABLISHED incompatible cluster withdraws
 *     instead of fencing incumbents (asymmetric policy, design-consult ruling).
 */
#define MXFS_HB_FEAT_MAGIC      0x47465846u  /* "FXFG" LE → reads MXFG-ish */

/*
 * sess186 (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE blocker 1, sess184
 * Design-consult ruling): WRITE-TIME provenance for a SINGLE_NODE_LOCAL_LOG
 * incarnation.  Set in every own-record write of a mount that claimed its
 * slot under the operator's single_node_exclusive assertion, from the CLAIM
 * onwards — i.e. durably BEFORE the first untagged log record this
 * incarnation can produce.  The feature crc binds it to the incarnation
 * identity, and the fence-intent path copies the victim record wholesale, so
 * the marker survives WITHDRAWN stamping and GUARD overlay.
 *
 * The marker used to be one of TWO independent predicates for untagged-image
 * replay (ruling item 5): it proves log_was_single_node_authorized_when_written,
 * and a KIND_SINGLE_NODE_EXCLUSIVE certificate was taken to prove
 * takeover_is_exclusive_now.  Replay required BOTH, since neither implies the
 * other.
 *
 * 0.89.18: the second predicate is gone, because kind 17 is revoked — an
 * operator's exclusive-access assertion bounds which INITIATORS may write and
 * says nothing about writes the target already accepted from the incarnation
 * being recovered, so it never established the half replay depends on.  The
 * conjunction therefore can no longer be satisfied and untagged images are not
 * replayed at all.  This marker is kept as durable provenance about how a
 * tenure was configured — it is still written, and its disagreement with a
 * record's other evidence is still a useful diagnosis — but nothing reads it
 * as permission.  It is never set, cleared, or reinterpreted mid-incarnation
 * (ruling item 3: no dirty mode transition).
 */
#define MXFS_HB_FEAT_SNLOCAL    0x0001

/*
 * 0.41.1 (D-0354 lap 2 — design-consult ruling): WRITE-TIME provenance that
 * this incarnation's slot claim was a PASS-2 FRESH claim (slice ADOPTED): the
 * sector it consumed was released or recovered-and-zeroed, which by
 * construction means every record of any PREVIOUS incarnation still lying in
 * the slice was already published (a recovered slot is zeroed only at
 * P163-RECOVERY-COMPLETE; a released slot's log ends in an unmount record).
 * Set from the claim's own fresh_claim BEFORE the first record write, uniform
 * across the tenure like SNLOCAL, crc-bound to the incarnation, captured
 * into the descriptor as MXFS_RECOV_F_VICTIM_ADOPTED at fence time.  A
 * replayer of THIS incarnation's slice may therefore skip, whole-transaction
 * and silently, any record whose token names a different incarnation of the
 * same slot (P310) instead of refusing the slice — the certificate the ruling
 * required before age alone may be trusted.  A PASS-1 own-stamp reclaim
 * (nobody replayed the previous incarnation) carries no such bit.
 */
#define MXFS_HB_FEAT_ADOPTED    0x0002
/*
 * (docs/whole-cluster-restart.md §6.5 shape B, design-consult ruling): this
 * ACTIVE record is the WHOLE-CLUSTER BOOTSTRAP OWNER's adoption of a
 * certified victim slot K while the bootstrap term is still RECOVERING.  It
 * is NOT an admitted member: the bootstrap record refuses every other
 * mount, the slice under it is being FULLY replayed as the owner's own log
 * (never ADOPTED), and a successor term that finds this record frozen
 * treats it as a fresh class-2 victim and PREFERS it as its own K (its
 * partially-replayed intents must not be stranded in a foreign replay).
 * Cleared by the owner (next own-record write) only after RECOVERY_COMPLETE.
 */
#define MXFS_HB_FEAT_BOOTSTRAP_PENDING 0x0004
/*
 * 0.75.0 (D-JOINER-TRANSPORT-NOT-CONFORMED-...-0904): this incarnation runs
 * the TCP DLM transport; clear means CAW.  The transport is a property of
 * the cluster on the platter, not of a module argument: two lock managers
 * over one filesystem exclude nothing from each other.  Stamped before the
 * claim like SNLOCAL and never flipped mid-tenure, so every record of the
 * tenure says which transport must recover it.  Read by
 * mxfs_disklock_scan_transport BEFORE a mount selects its transport (a
 * default-argument joiner adopts the platter's transport; a forced mismatch
 * is refused), by the join gate (a live incumbent on the other transport
 * makes the joiner withdraw) and by the monitor (a live intruder on the
 * other transport is fenced like a protocol-incompatible one).  Absent on
 * every record of a build older than PROTO_GEN 19, which is why that
 * generation was bumped: an old record's clear bit would otherwise vote CAW
 * for a TCP node.
 */
#define MXFS_HB_FEAT_TCP        0x0008

struct mxfs_hb_feature {
	uint32_t                magic;      /* MXFS_HB_FEAT_MAGIC */
	uint16_t                proto_gen;  /* must equal MXFS_PROTO_GEN */
	uint16_t                feat_flags; /* compatible advertisements; 0 */
	uint32_t                crc32c;     /* over {magic,proto_gen,feat_flags,
										 * fs_gen,node_id,epoch} — see
										 * mxfs_hb_feature_crc() */
};

/*
 * (#92 D-CLEAN-RELEASE-TREATED-AS-DEATH, ruling items
 * 7-9): CLAIM PROVENANCE — on-disk proof of what this incarnation's
 * claim CONSUMED, carried in every heartbeat record it writes.
 *
 * The clean-departure protocol lets a monitor retire a released
 * (FLAG_EMPTY) slot without fencing — but only while the EMPTY record
 * is still on the platter.  If a new claimant consumes the EMPTY
 * between two monitor passes (ACTIVE→EMPTY→ACTIVE' missed-EMPTY race),
 * the monitor sees only an epoch change and would conservatively fire
 * death on the CLEAN predecessor.  The provenance block closes that:
 * the successor's record proves "I consumed a clean EMPTY left by
 * {prev_node, prev_epoch}", and slot_seq/chain_len extend the proof
 * across MULTIPLE missed clean cycles (monitor's last-tracked seq S
 * within [S'-chain_len, S'-1] of the observed record ⇒ every tenancy
 * between S and S' ended cleanly).
 *
 * seq rules (claim time):
 *   - pass-1 own-stamp reclaim:       seq = old.seq+1 if old prov valid
 *                                     else fresh random; chain_len = 0
 *                                     (dirty predecessor: ourselves).
 *   - pass-2 from valid EMPTY+prov:   prev = EMPTY's {node, epoch},
 *                                     seq = prev.seq+1,
 *                                     chain_len = min(prev.chain_len+1, cap).
 *   - pass-2 from zero/garbage:       RANDOM 64-bit seq (entropy à la
 *                                     hb_draw_incarnation), chain_len = 0,
 *                                     prev = 0.  The random restart makes
 *                                     cross-generation seq collision
 *                                     negligible.
 *
 * crc32c binds the block to the record identity {magic, prev_node,
 * prev_epoch, slot_seq, chain_len, fs_gen, node_id, epoch} (packed LE,
 * mirroring mxfs_hb_feature_crc) so a stale or foreign provenance block
 * can never validate against the wrong incarnation.  Old-proto records
 * carry zeros here (magic 0 ⇒ invalid ⇒ conservative fire), and the
 * layout shift is fenced by the PROTO_GEN bump anyway.
 */
#define MXFS_HB_PROV_MAGIC      0x5650584D  /* "MXPV" LE */
#define MXFS_HB_PROV_CHAIN_CAP  255

struct mxfs_hb_provenance {
	uint32_t                magic;      /* MXFS_HB_PROV_MAGIC */
	uint32_t                prev_node;  /* clean-EMPTY predecessor, 0 = none */
	uint64_t                prev_epoch; /* predecessor's incarnation, 0 = none */
	uint64_t                slot_seq;   /* per-slot tenancy sequence */
	uint32_t                chain_len;  /* proven-clean lineage length */
	uint32_t                crc32c;     /* see block comment */
};                                      /* 32 bytes */

/*
 * (docs/whole-cluster-restart.md item 2, design-consult ruling ccmemory
 * docs/rulings/prkey64-item2-ledger-not-deferrable.md):
 * HOST / BOOT IDENTITY + the 64-bit per-boot SCSI PR key, carried in every
 * record this incarnation writes.
 *
 * The PR key used to be the 32-bit node_id, so a fencer derived the victim
 * key from a node id and nothing tied a registration to a HOST or a BOOT.
 * After a whole-cluster power loss every host's own predecessor key survives
 * (PTPL) and no mount can proceed (P305-PR-PREDECESSOR-KEY-PRESENT).  This
 * block is what lets a successor prove "a previous BOOT of this machine"
 * and what lets a fencer name the victim's REAL key:
 *
 *   - fencers take the victim key from the victim's ACTIVE/WITHDRAWN record
 *     (frozen in the monitor's per-slot incarnation snapshot the moment a
 *     valid block for the tracked (node_id, epoch) is read) — NEVER from a
 *     GUARD record (its block names the guard WRITER) and never from node_id.
 *     No frozen key for the exact incarnation ⇒ the fence is refused
 *     (MXFS_FENCE_KIND_NO_VICTIM_KEY); a DIFFERENT key for an already-frozen
 *     (node_id, epoch) is a protocol violation.
 *   - key_gen is the generation of the key selected for {this boot, this
 *     LUN} (registrant ledger, mxfs_prledger.h); it changes only when the
 *     key changes, which for one boot on one LUN it never does after
 *     selection.
 *   - crc32c binds {magic, ver, key_gen, host_uuid, boot_uuid, pr_key,
 *     host_src, slot, flags, fs_gen, node_id, epoch} so a block cannot be
 *     transplanted across slots, record roles, generations or incarnations.
 *     It is corruption/transplant detection, not authenticity.
 */
#define MXFS_HB_IDENT_MAGIC     0x4449584Du  /* "MXID" LE */
#define MXFS_HB_IDENT_VERSION   1

struct mxfs_hb_identity {
	uint32_t                magic;          /* MXFS_HB_IDENT_MAGIC */
	uint16_t                ver;            /* MXFS_HB_IDENT_VERSION */
	uint16_t                key_gen;        /* ledger key generation */
	uint8_t                 host_uuid[16];  /* stable host identity */
	uint8_t                 boot_uuid[16];  /* immutable per kernel boot */
	uint64_t                pr_key;         /* 64-bit per-boot PR key */
	uint32_t                host_src;       /* MXFS_HOSTID_SRC_* */
	uint32_t                crc32c;         /* see block comment */
	uint8_t                 reserved[8];
};                                          /* 64 bytes */

/*
 * On-disk heartbeat record — exactly 512 bytes, one sector.
 */
struct mxfs_disklock_heartbeat {
	uint32_t                magic;
	uint32_t                flags;
	mxfs_node_id_t          node_id;
	uint32_t                fs_gen;         /* folded volume_id of the
											 * mkfs generation this record
											 * belongs to; 0 = legacy/unset.
											 * Records whose fs_gen differs
											 * from ours are pre-mkfs ghosts —
											 * ignored and reclaimable. */
	uint64_t                timestamp_ms;
	mxfs_epoch_t            epoch;
	uint64_t                lock_count;
	/*
	 * the 416-byte body is interpreted BY flags.
	 *   flags == ACTIVE → evict (inode-eviction hint ring)
	 *   flags == RECOVERY_GUARD → recov (durable recovery descriptor)
	 * The ring producer writes only into its OWN active record and the ring
	 * consumer sits behind a flags == ACTIVE test, so the two never alias in
	 * a live path.  Both members carry their own magic so a record written by
	 * the other interpretation (or by a pre-sess64 node, which zeroed these
	 * bytes in a guard) is rejected rather than misread.
	 */
	union {
		struct mxfs_evict_ring  evict;      /* 320B (19 entries) */
		struct mxfs_recov_body  recov;      /* 120B descriptor + outcome + pad */
	};
	struct mxfs_hb_identity ident;          /* 64B host/boot/PR-key identity */
	struct mxfs_hb_provenance prov;         /* 32B claim provenance */
	struct mxfs_mepoch_rec  mepoch;         /* net2 step 5: 44B, §7.C authority */
	struct mxfs_hb_feature  feat;           /* C7: 12B version gate */
};

#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_HB() \
	do { \
		BUILD_BUG_ON(sizeof(struct mxfs_disklock_heartbeat) != \
			     MXFS_DISKLOCK_RECORD_SIZE); \
		BUILD_BUG_ON(sizeof(struct mxfs_recov_desc) != 120); \
		BUILD_BUG_ON(sizeof(struct mxfs_recov_body) != \
			     sizeof(struct mxfs_evict_ring)); \
		BUILD_BUG_ON(sizeof(struct mxfs_hb_identity) != 64); \
		BUILD_BUG_ON(offsetof(struct mxfs_disklock_heartbeat, ident) != 360); \
		BUILD_BUG_ON(offsetof(struct mxfs_disklock_heartbeat, prov) != 424); \
		BUILD_BUG_ON(offsetof(struct mxfs_disklock_heartbeat, mepoch) != 456); \
	} while (0)
#else
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == MXFS_DISKLOCK_RECORD_SIZE,
	       "mxfs_disklock_heartbeat must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_evict_ring) == 320,
	       "mxfs_evict_ring must be 19 entries (sess438 identity carve)");
_Static_assert(sizeof(struct mxfs_hb_identity) == 64,
	       "mxfs_hb_identity is the 64-byte sess438 carve");
_Static_assert(offsetof(struct mxfs_disklock_heartbeat, ident) == 360,
	       "the identity block sits between the body union and prov");
_Static_assert(sizeof(struct mxfs_mepoch_rec) == 44,
	       "mxfs_mepoch_rec is 44 bytes on disk (§7.C)");
_Static_assert(sizeof(struct mxfs_hb_feature) == 12,
	       "mxfs_hb_feature is the 12-byte HB tail (sess42 C7)");
#endif

/*
 * these run in BOTH builds, deliberately.  MXFS_BUILD_CHECK_HB above
 * is referenced by nothing in the tree, so the kernel side of the #ifdef has
 * never actually validated anything — the only live checks were the user-mode
 * _Static_asserts and the pair at the top of disklock.c.  The recovery
 * descriptor OVERLAYS the evict ring, so a layout slip would silently corrupt
 * peers' heartbeat parsing; assert it where the kernel compiler will see it.
 */
_Static_assert(sizeof(struct mxfs_recov_desc) == 120,
	       "mxfs_recov_desc is 120 bytes on disk (sess75 v2 certificate)");
_Static_assert(offsetof(struct mxfs_recov_desc, fence_kind) == 76,
	       "the v2 certificate starts at byte 76");
_Static_assert(offsetof(struct mxfs_recov_desc, crc32c) == 116,
	       "the crc must remain the LAST descriptor field");
_Static_assert(sizeof(struct mxfs_recov_body) == sizeof(struct mxfs_evict_ring),
	       "recovery descriptor body must exactly overlay the evict ring");
_Static_assert(sizeof(struct mxfs_recov_outcome) == 96,
	       "mxfs_recov_outcome is 96 bytes on disk (sess323)");
_Static_assert(offsetof(struct mxfs_recov_outcome, crc32c) == 92,
	       "the outcome crc must remain the LAST field");
_Static_assert(offsetof(struct mxfs_recov_body, outcome) == 120,
	       "the outcome record sits immediately after the 120B descriptor");
_Static_assert(sizeof(struct mxfs_recov_manifest_ptr) == 64,
	       "mxfs_recov_manifest_ptr is 64 bytes on disk (sess405)");
_Static_assert(offsetof(struct mxfs_recov_manifest_ptr, crc32c) == 52 &&
	       offsetof(struct mxfs_recov_manifest_ptr, writer_epoch) == 56,
	       "the manifest pointer crc/writer_epoch layout");
_Static_assert(offsetof(struct mxfs_recov_body, mptr) == 216,
	       "the manifest pointer sits immediately after the outcome record");
_Static_assert(offsetof(struct mxfs_recov_body, obl) == 280,
	       "desc+outcome+mptr must stay contiguous ahead of the obligation record");
_Static_assert(sizeof(struct mxfs_recov_obl) == 40 &&
	       offsetof(struct mxfs_recov_obl, crc32c) == 36,
	       "mxfs_recov_obl is the 40-byte tail of the recovery body (sess462)");
_Static_assert(sizeof(struct mxfs_recov_body) == 320,
	       "the recovery body must keep its 320-byte footprint (sess462)");
_Static_assert(sizeof(struct mxfs_rman_obl_hdr) == MXFS_RMAN_OBL_HDR_BYTES &&
	       offsetof(struct mxfs_rman_obl_hdr, hdr_crc32c) == 108 &&
	       MXFS_RMAN_OBL_ENTRIES_OFF +
	       (uint64_t)MXFS_RECOV_OBL_MAX_EXTENTS * sizeof(struct mxfs_recov_obl_ext) <=
	       MXFS_RMAN_ENTRIES_OFF,
	       "the obligation list zone must stay inside [4 KiB, 64 KiB) of the rman slot (sess462)");
_Static_assert(sizeof(struct mxfs_rman_entry) == 32,
	       "mxfs_rman_entry is 32 bytes on disk (sess405)");
_Static_assert(sizeof(struct mxfs_rman_hdr) == 4096,
	       "mxfs_rman_hdr is the 4 KiB manifest header (sess405)");
_Static_assert(offsetof(struct mxfs_rman_hdr, hdr_crc32c) == 84 &&
	       offsetof(struct mxfs_rman_hdr, seal) == 88,
	       "manifest header crc/seal layout");
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == MXFS_DISKLOCK_RECORD_SIZE,
	       "sess64 union must not change the 512-byte heartbeat record");
_Static_assert(sizeof(struct mxfs_hb_provenance) == 32,
	       "mxfs_hb_provenance is the 32-byte sess346 carve");
_Static_assert(offsetof(struct mxfs_disklock_heartbeat, prov) == 424,
	       "the provenance block sits between the body union and mepoch");
_Static_assert(offsetof(struct mxfs_disklock_heartbeat, mepoch) == 456,
	       "sess64 union must not move the mepoch/feat tail");

struct mxfs_disklock_node_track {
	uint64_t        last_timestamp;
	mxfs_epoch_t    last_epoch;
	int             changed_samples;
	int             equal_samples;
	bool            live;
	uint32_t        last_evict_seq;   /* highest evict head_seq consumed from this peer */
	bool            evict_seen;       /* last_evict_seq has been initialised */
	/* (#92): slot_seq from the last VALID provenance block seen on
	 * this slot's ACTIVE record.  The epoch-change arm tests the successor's
	 * lineage window against it; seq_seen gates the test so a peer without a
	 * tracked seq (pre-carve record, or we joined mid-tenure before the first
	 * valid prov) conservatively fires instead of falsely retiring. */
	uint64_t        last_seq;
	bool            seq_seen;
	/* P-HB-INC-ZERO printed once per zero episode (the sector may
	 * read zero for many monitor passes); cleared by the next valid read. */
	bool            inc_zero_logged;
	/* 0.89.66: this node's own clock (mxfs_pal_time_ms) at the monitor pass
	 * that last saw the record's timestamp CHANGE.  The dead window is
	 * counted in samples from that pass, so the pass itself is the start of
	 * the window, and the death line prints it beside the victim's own
	 * stamp so a lap can measure the window's actual start and length
	 * instead of inferring both from the constants. */
	uint64_t        last_change_ms;
};

/*
 * the death callback carries the VICTIM INCARNATION, it does not let
 * the consumer read it back.
 *
 * The monitor's epoch-change arm adopts the NEW incarnation into
 * node_track[].last_epoch before it declares the old one dead, so any consumer
 * that resolved the victim epoch by reading node_track back named the LIVE
 * successor as the victim.  Under the pre-sess85 constant-zero epoch that was
 * invisible (every comparison was 0 == 0); with real incarnations and required
 * matching it would lay a recovery guard on a live node.  dead_epoch is the
 * incarnation that actually stopped — 0 only where the caller genuinely never
 * observed one (the lease layer's node-scoped expiry), which degrades to the
 * node-scoped predicates and never to a wildcard match.
 *
 * dead_slot is the heartbeat slot the death was observed on, or -1 when the
 * caller has no slot context (again the lease layer) and the consumer must
 * resolve it by node id.
 */
typedef void (*mxfs_disklock_expire_cb)(void *data, mxfs_node_id_t dead_node,
					int dead_slot,
					mxfs_epoch_t dead_epoch);

/*
 * D2: recovery-complete callback.  Fired by the
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
 * (#92 D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526):
 * CLEAN-DEPARTURE callback.  Fired by the monitor when a tracked slot's
 * record reads FLAG_EMPTY with an FUA-confirmed EXACT stamp match on the
 * incarnation we were tracking — i.e. the node RELEASED its slot via
 * mxfs_disklock_release_slot (clean unmount), it did not die.  Also fired
 * by the pending-block EMPTY arm when a recovery-pending victim's slot
 * reads as its own clean release (the death was declared from a stale
 * read that raced the release).
 *
 * The body unwinds membership WITHOUT the death machinery: lease
 * unregister, in-memory DLM grant purge, membership refresh, and the XFS
 * notify that clears the dead-slot/torn latches and re-arms the reap
 * worker.  It must NOT retire the identity (no v5_note_dead_node — a
 * cleanly-departed node must be able to remount and rejoin) and must NOT
 * zero the slot on disk (it is already EMPTY, and peers still need the
 * stamp for their own clean-departure matching).
 */
typedef void (*mxfs_disklock_clean_depart_cb)(void *data, int slot,
					      mxfs_node_id_t node,
					      mxfs_epoch_t epoch);

/*
 * /"is this PR key registered on the LUN right now?" — the
 * READ KEYS the monitor issues to settle a RETIRE_PENDING record (see the
 * flag's comment).  TRI-STATE plus one special case (design-consult
 * STOP-SHIP blocker 3: a bool folded errors into PRESENT and -EOPNOTSUPP
 * into ABSENT):
 *   ABSENT  — a fencing-grade proof (complete READ KEYS taken under the
 *             answerer's own live registration and the reservation this
 *             build fences under): the record may be published EMPTY.
 *   PRESENT — registered: after the grace (or at once from the mount
 *             thread) the record is stamped WITHDRAWN and the fence path
 *             retires the key.
 *   UNKNOWN — no PR context on this transport, a transport/UA/timeout
 *             error, a truncated view, our own key missing, no or
 *             wrong-type reservation, a stale or already-consumed proof.
 *             NEVER settles either way: the record stays RETIRE_PENDING
 *             (non-consumable; the admission barrier holds on it) and the
 *             monitor escalates once per grace.
 *
 * (0.59.2, design-consult STOP-SHIP #2 blockers 3 and 4): there is no OWN
 * answer any more.  0.59.1 let the generic lookup report our own key as
 * OWN and every settlement path clear any record naming it — a stale,
 * duplicate or colliding record included.  Our own key is PRESENT like any
 * other; the ONE path that may clear a record naming our key is the P305
 * same-boot settlement (mxfs_disklock_retire_settle_own) under the
 * host-wide departure lock with a FRESH bracket proving our registration.
 * Two callbacks now: key_state_fn is the ASYNC, heartbeat-safe lookup
 * (table read, no PR I/O — the monitor's arms, immediate=false);
 * key_state_sync_fn runs a fresh bracket inline and is used only by the
 * mount thread (immediate=true: admission barrier, P305).  A sync callback
 * left unset makes the immediate settlements UNKNOWN.
 */
enum mxfs_disklock_key_state {
	MXFS_DISKLOCK_KEY_ABSENT  = 0,
	MXFS_DISKLOCK_KEY_PRESENT = 1,
	MXFS_DISKLOCK_KEY_UNKNOWN = 2,
};
typedef int (*mxfs_disklock_key_state_fn)(void *data, uint64_t key);
/* (0.61.0, D1): the ABSENT settlement callback — contract at the
 * mxfs_disklock_set_settle_absent_fn declaration below. */
typedef int (*mxfs_disklock_settle_absent_fn)(void *data, uint32_t slot,
					      uint64_t key,
					      struct mxfs_disklock_heartbeat *pending,
					      bool immediate);

/*
 * self-fence callback.  Fired (once) by the heartbeat thread when
 * this mount must stop writing immediately.  The body (v5_mount → XFS glue)
 * must force-shutdown the filesystem; the heartbeat thread stops writing
 * before calling so neither a new cluster generation nor an in-flight
 * recovery is polluted by ghost heartbeats.
 *
 * `reason` is an enum mxfs_self_fence_reason.  it exists because the
 * two disklock detectors — a re-mkfs'd device (FS_IDENTITY) and a survivor
 * taking over our heartbeat slot (SLOT_TAKEOVER) — are opposite diagnoses
 * (your LUN was destroyed vs your LUN is fine and you were fenced), and the
 * callback used to report both as the former.
 */
typedef void (*mxfs_disklock_fence_cb)(void *data, int reason);

/*
 * (fenced-victim ruling): heartbeat-write RESERVATION
 * CONFLICT callback.  Fired (from the HB thread) each time the own-slot
 * CAS bounces with SCSI RESERVATION CONFLICT (-EBADE) — the one signal a
 * fenced-but-alive victim gets from the TARGET rather than from stale
 * media.  The v5 layer counts these and runs the PR IN inspection that
 * decides withdraw; disklock itself keeps heartbeating (the writes bounce
 * harmlessly) so a transient target hiccup never kills a healthy node.
 */
typedef void (*mxfs_disklock_conflict_cb)(void *data);
/*
 * (D-PURGE-NONATOMIC-PUBLICATION verification, design-consult ruling):
 * test-only hook called from inside mxfs_disklock_purge_node at three
 * points — 1 = phase-0 freeze gate passed, before the first record zero;
 * 2 = start of the record scan (a nonzero return forces the mid-scan
 * authority re-read immediately instead of at the 2 s cadence); 3 = record
 * scan finished, before the final heartbeat gate/CAS.  victim_slot is the
 * heartbeat slot carrying the victim's recovery descriptor, or -1 when no
 * descriptor covers the victim.  NULL in production.
 */
typedef int (*mxfs_disklock_dbg_purge_hook)(void *data, int point,
					    int victim_slot);

/*
 * per-freed-inode eviction callback.  The disklock HB consumer reads a
 * peer's evict ring and invokes this for each {ino, gen} the peer freed since we
 * last scanned.  The body (in the XFS layer) does the radix lookup +
 * XFS_ISTALE_CAW + background eviction — disklock.c never touches XFS directly.
 */
typedef void (*mxfs_disklock_evict_cb)(void *data, uint64_t ino, uint32_t gen,
				       uint32_t type);

/*
 * C7: protocol-incompatible LIVE member detected by the monitor
 * (feature block missing/mismatched/corrupt on a progressing current-fs_gen
 * record, confirmed by a second priority re-read of the same incarnation).
 * The v5 layer must SCSI-PR fence the incarnation so its next write fails.
 * Fired at most once per (slot, node, epoch) incarnation.
 * state: 1=LEGACY (zero block) 2=MISMATCH (different proto_gen) 3=CORRUPT.
 */
typedef void (*mxfs_disklock_vergate_cb)(void *data, int slot,
					 mxfs_node_id_t node_id,
					 mxfs_epoch_t epoch, int state);

/*
 * terminal recovery-outcome callback.  Fired by the monitor when a
 * recovery-pending slot's GUARD record carries a VALID outcome record (magic/
 * version/crc against the sector's victim identity) plus F_QUARANTINED, and
 * the (victim_epoch, publish_seq) pair is newer than what this ctx has
 * already delivered for the slot.  The body (v5 → XFS) imports the quarantine
 * domain; the deferred local purge stays armed — a quarantined slot never
 * becomes CONSUMABLE on its own.  Fired at most once per (epoch, seq).
 *
 * (ruling item 8): oc == NULL is the fail-closed contract — the slot
 * is QUARANTINED but its outcome record is unreadable (present yet fails
 * magic/version/crc), so no domain evidence exists.  The consumer MUST treat
 * NULL as an FSWIDE quarantine.  Unlike valid outcomes this fires every
 * monitor pass (there is no (epoch, seq) to dedup on); importers make it
 * idempotent on their side.
 *
 * (design-consult ruling): the callback now RETURNS a disposition instead of
 * being a void notification with side effects.  Two consumers of this record
 * were found importing it with no validation at all, and one of them then fed
 * the SELECTIVE GRANT PURGE from the same unvalidated bytes.  The semantic
 * predicate (which outcome kinds and reasons exist, what a domain means,
 * whether an AG mask is valid for THIS filesystem) is XFS-layer policy and
 * must have exactly ONE implementation, so it lives behind this callback —
 * and the callback must report what it decided so no caller can act on a
 * record the validator rejected.  In particular a rejected record still
 * imports an FSWIDE quarantine (fail closed), so "it imported FSWIDE" is NOT
 * evidence the record was valid, and MUST NOT authorize closure processing.
 *
 * The monitor therefore hands over EVERY structurally readable quarantined
 * outcome; it may not pre-filter on outcome kind (that filter was itself a
 * bypass: an unknown kind was silently skipped pass after pass, so a
 * quarantined slot never quarantined any live peer).
 */
enum mxfs_quar_disposition {
	MXFS_QUAR_NOT_TERMINAL = 0, /* nothing terminal here */
	MXFS_QUAR_VALID_AG,         /* validated TERMINAL_REFUSED, AG-scoped */
	MXFS_QUAR_VALID_FSWIDE,     /* validated TERMINAL_REFUSED, whole fs */
	MXFS_QUAR_INVALID_FSWIDE,   /* failed validation -> fail-closed FSWIDE */
	MXFS_QUAR_FOREIGN,          /* pre-mkfs ghost; ignored operationally */
};

typedef int (*mxfs_disklock_recov_outcome_cb)(void *data, int slot,
				    const struct mxfs_recov_outcome *oc);

/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED): the OPEN-obligation observer.
 * The monitor fires it for EVERY slot on EVERY complete pass (O(1), no I/O:
 * the sector was already read), with `state` naming what the slot's recovery
 * object owes right now:
 *   MXFS_OBL_NONE    — no descriptor, a descriptor below IMAGES_REPLAYED or
 *                      at/past OBLIGATIONS_DONE, a quarantined descriptor,
 *                      CENSUS_ZERO, or a TERMINAL/DONE record: nothing frozen.
 *   MXFS_OBL_OPEN    — a valid OPEN record: ag_mask (or fswide) is frozen
 *                      until the case reaches OBLIGATIONS_DONE or a terminal.
 *   MXFS_OBL_INVALID — a descriptor in [IMAGES_REPLAYED, OBLIGATIONS_DONE)
 *                      whose record region does not validate, or that has
 *                      neither CENSUS_ZERO nor a record: fail closed, the
 *                      consumer freezes the whole filesystem for the slot.
 * A slot whose sector could not be read is NOT reported (the consumer keeps
 * its previous answer).  The consumer is idempotent and keyed by
 * (victim_epoch, pub_seq) so repeated reports cost nothing.
 */
#define MXFS_OBL_NONE       0
#define MXFS_OBL_OPEN       1
#define MXFS_OBL_INVALID    2
typedef void (*mxfs_disklock_recov_obl_cb)(void *data, int slot, int state,
				    uint32_t victim_node, uint64_t victim_epoch,
				    uint32_t pub_seq, uint64_t ag_mask,
				    bool fswide);

/*
 * (ruling, part D): heartbeat-cycle stage, published by the
 * heartbeat thread at each phase boundary so the watchdog can name WHERE a
 * stalled cycle is stuck (identity read vs ctx->lock wait vs the CAS write
 * vs the 63-slot monitor pass) instead of only that the lease is aging.
 * SLEEP is the only stage with no I/O in flight, so only non-SLEEP ages
 * count as stalls.
 */
enum mxfs_hb_stage {
	MXFS_HB_STAGE_SLEEP = 0,
	MXFS_HB_STAGE_IDCHECK,
	MXFS_HB_STAGE_LOCKWAIT,
	MXFS_HB_STAGE_CASWRITE,
	MXFS_HB_STAGE_MONITOR,
};

/* Disk lock subsystem context */
struct mxfs_disklock_ctx {
	mxfs_bdev_t             *dev;
	uint64_t                base_offset;    /* byte offset on device */
	/* the envelope's recovery-manifest region (0 = none; then no
	 * victim can be certified by this node — gen 7 requires the region and
	 * mount refuses a super without it, so 0 only happens in user-mode
	 * tools / tests that never fence). */
	uint64_t                rman_offset;
	uint64_t                rman_size;
	mxfs_node_id_t          local_node;
	int                     local_slot;     /* unique HB slot 0-63, -1 if unclaimed */
	/* (§6.2): this node is a whole-cluster bootstrap owner — no slot;
	 * descriptors it owns carry MXFS_RECOV_F_OWNER_BOOTSTRAP. */
	bool                    owner_bootstrap;
	/* incarnation drawn at the bootstrap claim, consumed ONCE by the
	 * ACTIVE claim so the provisional and member epochs are the same. */
	mxfs_epoch_t            epoch_predrawn;
	/*
	 * D-LOG-SLICE-SHARED-MULTIWRITER (ruling, claim-time layer):
	 * exclusive upper bound on the slot number this node may CLAIM.  Set
	 * from the volume's xfs_log_node_count before claiming, because a
	 * slot's journal slice is the identically numbered slice — a node on
	 * a slot >= the slice count has no slice and must not join at all.
	 * 0 = no bound (unsliced legacy volume / user-mode tools).
	 */
	uint32_t                slot_limit;
	/* (D-FOREIGN-REPLAY-UNGATED-IMAGES): true when the slot was won by
	 * the pass-2 fresh scan — our previous incarnation's ACTIVE stamp was
	 * absent/zeroed, so any dirt in the log slice (the identically numbered
	 * slice) belongs
	 * to an already-recovered or foreign incarnation and its images must NOT
	 * be re-applied by our mount recovery (cross-slice LSNs incomparable).
	 * false = pass-1 reclaim of our own surviving stamp: nobody replayed us,
	 * full own-slice recovery is safe and REQUIRED. */
	bool                    slice_adopted;
	/* (D-SHUTDOWN-UMOUNT, ruling item 1): true when this
	 * mount durably classifies itself a SINGLE-NODE LOCAL LOG writer —
	 * set from the operator's single_node_exclusive assertion BEFORE the
	 * slot is claimed, so every heartbeat/claim record this incarnation
	 * ever writes carries MXFS_HB_FEAT_SNLOCAL in its feature block.
	 * Write-time provenance only: it must never be flipped after
	 * claim_slot has stamped the first record (mxfs_disklock_set_snlocal
	 * refuses once local_slot >= 0), because a marker that can appear
	 * mid-tenure is a retroactive classification, which the ruling
	 * forbids. */
	bool                    snlocal;
	/* this incarnation's claim was a pass-2 fresh claim — set by
	 * the claim loop from fresh_claim BEFORE its first record write so
	 * every record of the tenure carries MXFS_HB_FEAT_ADOPTED (see the
	 * feature-block comment); never flipped afterwards. */
	bool                    claim_fresh;
	/* (§6.5): own record carries MXFS_HB_FEAT_BOOTSTRAP_PENDING */
	bool                    bootstrap_pending;
	/* 0.75.0: own record carries MXFS_HB_FEAT_TCP; set before the claim
	 * (mxfs_disklock_set_transport_tcp refuses once local_slot >= 0) and
	 * compared against every live record by the join gate and monitor. */
	bool                    transport_tcp;
	mxfs_thread_t           *hb_thread;
	/*
	 * part D: heartbeat-stall watchdog.  hb_stage/hb_stage_ms are
	 * written only by the heartbeat thread and read racily by the watchdog
	 * (diagnostic tolerance — a torn read costs one poll, never a false
	 * fence).  hb_pid names the heartbeat task for the stack dump; 0 in
	 * user mode where mxfs_pal_dump_task_stack is a no-op.
	 */
	volatile int            hb_stage;       /* enum mxfs_hb_stage */
	volatile uint64_t       hb_stage_ms;    /* entry time of hb_stage */
	/* (D-0347): when OUR heartbeat record last landed (CAS ok).
	 * A node whose own beat is older than the death timeout may already
	 * have been declared dead by its peers — it must not act as the
	 * bootstrap node (claim UNOWNED ledger pages) on the strength of
	 * ranking its own slot first. */
	volatile uint64_t       hb_last_ok_ms;
	/*
	 * 0.89.20 — THE LOCAL AUTHORITY LEASE.
	 *
	 * Measured: a node that has been PREEMPT AND ABORTed, but has not yet
	 * NOTICED, writes into a LUN that has since lost its last registrant and
	 * its reservation with it.  Both of the detectors this build had need the
	 * LUN to answer — a data write that bounces, or a periodic PR IN — so a
	 * node that is issuing nothing, whose audit tick has not come round, has
	 * no local state at all that says it has lost ownership.  Its bytes were
	 * read back off the platter with O_DIRECT and no filesystem in the path.
	 *
	 * The lease is the state that was missing.  Authority is something this
	 * node HOLDS UNTIL A DEADLINE, not something it discovers it has lost:
	 *
	 *     NOT_ADMITTED --(first landed beat)--> ADMITTED(deadline)
	 *                                              |
	 *                     expiry / revocation      v
	 *                                           CLOSED  (sticky, forever)
	 *
	 * Three properties make it sound, and each one is a way an epoch could
	 * otherwise be resurrected:
	 *
	 *  - THE DEADLINE IS ANCHORED BEFORE THE BEAT IS ISSUED, never at its
	 *    completion.  A beat can become visible at the target, have its
	 *    completion delayed, be aged out by peers in the meantime, and only
	 *    then be stamped "now" here — which would make our authority look
	 *    YOUNGER than the one our peers can see.  Anchoring at issue makes
	 *    the local deadline expire no later than the remote one.
	 *  - A RENEWAL IS ONLY ACCEPTED WHILE THE PREVIOUS AUTHORITY IS STILL
	 *    VALID.  A completion that arrives after the deadline has passed
	 *    cannot revive the epoch, whether or not any timer ran.
	 *  - CLOSED IS STICKY.  A heartbeat that starts working again does not
	 *    restore ownership; only a fresh coordinated admission does, under a
	 *    new incarnation.
	 *
	 * And the check is made WHERE AUTHORITY IS USED, not only in a timer:
	 * a timer and a heartbeat thread can be stalled along with the rest of
	 * the VM, so the first I/O a resumed node attempts must evaluate the
	 * deadline itself and close the epoch if it has passed.  The periodic
	 * pump exists for prompt withdrawal when there is no I/O at all.
	 *
	 * THE STATE DOES NOT LIVE HERE.  It lives in a struct mxfs_authority the
	 * MOUNT owns and holds a reference to, because the work the lease governs
	 * outlives this context: teardown frees the disklock and the DLM long
	 * before the last buffer, iclog and completion of that incarnation has
	 * been submitted.  A gate written against a pointer the teardown clears
	 * reads the absence of the reference as permission, which is exactly the
	 * hole this indirection closes.  This context only borrows a reference.
	 */
	struct mxfs_authority   *auth;
	uint64_t                hb_inc_zero_retained;   /* P-HB-INC-ZERO count */
	int                     hb_pid;
	mxfs_thread_t           *hb_watchdog;
	mxfs_mutex_t            *lock;
	/*
	 * D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION: serializes local dead-node
	 * purges (freeze gate -> 65536-record scan -> heartbeat publication)
	 * against each other.  purge_node used to get this serialization by
	 * holding ctx->lock for the whole scan, which starved the heartbeat
	 * writer for the entire purge (~35s measured, >half the 62s lease).
	 * The heartbeat writer NEVER takes purge_lock; ordering is purge_lock
	 * first, ctx->lock per-I/O inside it, never the reverse.
	 */
	mxfs_mutex_t            *purge_lock;
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
	 * D2: per-slot recovery-pending state.  Set
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
	/* (#92): clean-departure delivery (see typedef above). */
	mxfs_disklock_clean_depart_cb    clean_depart_cb;
	void                             *clean_depart_cb_data;
	/* /451/452: RETIRE_PENDING settlement (see the flag's comment):
	 * async (monitor) and sync (mount thread) lookups. */
	mxfs_disklock_key_state_fn       key_state_fn;
	mxfs_disklock_key_state_fn       key_state_sync_fn;
	void                             *key_state_data;
	/* (0.61.0, D1): the ABSENT settlement path (see typedef) */
	mxfs_disklock_settle_absent_fn   settle_absent_fn;
	void                             *settle_absent_data;
	/* per-slot rate limit for the UNKNOWN-key escalation */
	uint64_t                         retire_unknown_log_ms[MXFS_DISKLOCK_HB_SLOTS];
	/* D-0965: per-slot rate limit for the mount thread's held-admission log
	 * on a PRESENT key inside the grace (a same-boot successor settling) */
	uint64_t                         retire_present_log_ms[MXFS_DISKLOCK_HB_SLOTS];
	/* first sight of a RETIRE_PENDING record per slot, keyed to the exact
	 * incarnation it names; the grace runs on this node's uptime clock
	 * (durations only — never compared with the record's timestamp) */
	uint64_t                         retire_seen_ms[MXFS_DISKLOCK_HB_SLOTS];
	mxfs_node_id_t                   retire_seen_node[MXFS_DISKLOCK_HB_SLOTS];
	mxfs_epoch_t                     retire_seen_epoch[MXFS_DISKLOCK_HB_SLOTS];
	/* (D-0519): the victim incarnation whose CERTIFIED fence
	 * descriptor this monitor already declared dead on first sight, per
	 * slot — the arm fires once per (node, incarnation); the 31-sample
	 * stale window stays as the backstop. */
	mxfs_node_id_t                   fenced_seen_node[MXFS_DISKLOCK_HB_SLOTS];
	mxfs_epoch_t                     fenced_seen_epoch[MXFS_DISKLOCK_HB_SLOTS];
	/* (0.60.0, review-#3 condition 8): a settlement write whose
	 * COMPARE AND WRITE came back unsupported is REFUSED, never emulated
	 * with a plain FUA write; logged once per slot. */
	bool                             retire_nocaw_logged[MXFS_DISKLOCK_HB_SLOTS];

	/* recovery GUARD (see MXFS_DISKLOCK_FLAG_RECOVERY_GUARD).  One
	 * guard at a time per node; guard_img is the exact on-disk image we
	 * wrote — the CAS compare source for refresh and unguard. */
	int                              guard_slot;     /* -1 = none held */
	struct mxfs_disklock_heartbeat   guard_img;

	/*
	 * (D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD) — the exact image we
	 * last wrote into our OWN heartbeat slot, and the compare source for
	 * every subsequent write to it.
	 *
	 * Before every own-slot write was BLIND (memset → fill → write).
	 * A survivor that laid a recovery guard/descriptor into a live-but-
	 * declared-dead node's slot had it destroyed by that node's next
	 * heartbeat, 2 s later — measured on the 32-node rig at t+0.8 s
	 * (tests/hb_guard_clobber_probe.sh).  Two consequences, both fatal:
	 *   - the SCSI-PR fence certificate is a ONE-SHOT token.  Once the
	 *     PREEMPT AND ABORT consumes the victim's key, certify() CASes the
	 *     proof into the descriptor.  If the descriptor was clobbered first,
	 *     the key is gone and NO successor can ever prove exclusion — that
	 *     journal slice becomes permanently unreplayable.
	 *   - a node whose slot is guarded kept heartbeating and kept writing to
	 *     the filesystem while a survivor replayed its journal.  Nothing
	 *     stopped it: P131-SELF-FENCE fires only on an fs_uuid change.
	 *
	 * The only writers of our own slot are us and a recovery/purge, so a
	 * compare-and-write MISCOMPARE has exactly one meaning: somebody is
	 * recovering us.  That is a self-fence, not a retry.  hb_img_valid is
	 * false while the on-disk image is unknown (before the first claim, and
	 * after any write whose outcome was indeterminate) — the next own-slot
	 * write re-establishes it with a read that must still find OUR record.
	 */
	struct mxfs_disklock_heartbeat   hb_img;
	bool                             hb_img_valid;
	/* (D-0359 step 1): the slot claim landed through a real
	 * COMPARE AND WRITE (false = the verified non-CAW fallback took it,
	 * i.e. this device cannot execute the lock-slot CAS). */
	bool                             claim_via_caw;

	/*
	 * (#92): this incarnation's claim provenance, computed ONCE at
	 * claim time (see mxfs_hb_provenance) and copied verbatim into every
	 * record the heartbeat thread writes — disklock_hb_fn rebuilds the
	 * outgoing record fresh each cycle, so the block must persist here or
	 * the first heartbeat would erase the lineage proof the claim wrote.
	 * The crc binds it to {fs_gen, node_id, epoch}, all fixed for the
	 * incarnation, so the copy stays valid without recomputation.
	 */
	struct mxfs_hb_provenance        own_prov;
	/*
	 * this incarnation's host/boot/PR-key identity block, stamped
	 * (with a per-record crc) on every record it writes once
	 * mxfs_disklock_set_identity() has run; and the monitor's per-slot
	 * OBSERVED identity — frozen from a valid block whose (node_id, epoch)
	 * is the incarnation being tracked (ACTIVE or WITHDRAWN, never GUARD).
	 * At fire_dead the observation for the exact victim tuple is copied
	 * into the death snapshot (pending_key*), which is what
	 * mxfs_disklock_victim_key() serves to the fencer.  A DIFFERENT key
	 * observed for an already-frozen tuple is a protocol violation: the
	 * observation is poisoned (conflict) and the victim can never be
	 * fenced by key from this node.
	 */
	struct mxfs_hb_identity          own_ident;
	bool                             own_ident_set;
	struct mxfs_disklock_ident_obs {
		mxfs_node_id_t  node;
		mxfs_epoch_t    epoch;
		uint64_t        key;
		uint32_t        key_gen;
		uint8_t         host_uuid[16];  /* frozen with the key */
		uint8_t         boot_uuid[16];
		bool            valid;
		bool            conflict;
	}                                ident_obs[MXFS_DISKLOCK_HB_SLOTS];
	mxfs_node_id_t                   pending_key_node[MXFS_DISKLOCK_HB_SLOTS];
	mxfs_epoch_t                     pending_key_epoch[MXFS_DISKLOCK_HB_SLOTS];
	uint64_t                         pending_key[MXFS_DISKLOCK_HB_SLOTS];
	uint32_t                         pending_key_gen[MXFS_DISKLOCK_HB_SLOTS];
	uint8_t                          pending_host[MXFS_DISKLOCK_HB_SLOTS][16];
	uint8_t                          pending_boot[MXFS_DISKLOCK_HB_SLOTS][16];

	/*
	 * generation identity.  fs_gen is a nonzero 32-bit fold of the
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
	mxfs_disklock_conflict_cb        conflict_cb;
	void                             *conflict_cb_data;
	mxfs_disklock_dbg_purge_hook     dbg_purge_hook;     /* test only */
	void                             *dbg_purge_hook_data;

	/*
	 * inode-eviction ring.  Producer side stages locally-freed
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

	/*
	 * C7 version gate state.  vergate_cb fences a live incompatible
	 * incarnation (see typedef).  vergate_fenced_epoch[slot] pins the last
	 * incarnation already fenced so the monitor never re-fences the same one
	 * (and never fences a NEWER compatible incarnation on the same slot).
	 * vergate_admitted flips true once mxfs_disklock_join_gate passed —
	 * before that the monitor observes but does not fence (a joiner facing
	 * an established incompatible cluster WITHDRAWS; it does not shoot the
	 * incumbents).
	 */
	mxfs_disklock_vergate_cb         vergate_cb;
	void                             *vergate_cb_data;
	bool                             vergate_admitted;
	mxfs_epoch_t                     vergate_fenced_epoch[MXFS_DISKLOCK_HB_SLOTS];
	bool                             vergate_fenced[MXFS_DISKLOCK_HB_SLOTS];

	/*
	 * terminal recovery-outcome import state.  The monitor fires
	 * recov_outcome_cb at most once per (victim_epoch, publish_seq) per
	 * slot; the seen cache is what makes the delivery idempotent across
	 * monitor passes (the record stays on the platter until operator
	 * action, so every pass re-reads it).
	 */
	mxfs_disklock_recov_outcome_cb   recov_outcome_cb;
	void                             *recov_outcome_cb_data;
	/* 0.85.0: the OPEN-obligation observer (see the typedef). */
	mxfs_disklock_recov_obl_cb       recov_obl_cb;
	void                             *recov_obl_cb_data;
	/*
	 * (docs/recovery-manifest.md, writer guard S4): the PROTECTED
	 * victim mask — bit n set while slot n carries ANY validated recovery
	 * descriptor (stage >= FENCING: from the fencing INTENT, i.e. before the
	 * P&A is issued, through certify, snapshot, replay and purge; cleared
	 * when the sector is zeroed CONSUMABLE or otherwise stops carrying a
	 * descriptor).  Starting at the intent closes the window between the
	 * fence and the scan (design review item 1).  Recomputed
	 * from a COMPLETE monitor pass only (a pass cut short by shutdown never
	 * shrinks it); a slot whose record could not be read keeps its previous
	 * bit (conservative).  Published through protect_cb on every change so
	 * the CAW layer can refuse any CAS that would mutate a protected node's
	 * EX/PW authority outside the recovery owner's purge.
	 */
	uint64_t                         protected_mask;
	/* bumped by every out-of-pass publication (synchronous refresh,
	 * local-proof add).  A monitor pass that started before the bump reads
	 * some sectors from before the change it proves and must not publish
	 * over it — it skips, the next pass recomputes from the platter. */
	uint64_t                         protected_gen;
	/* (design-consult ruling Q1): gen validation, mask installation and the
	 * callback are ONE critical section under prot_lock for every publisher
	 * (monitor pass commit, synchronous refresh, local-proof add) — a bare
	 * generation counter still allowed check-then-publish and OR-before-gen
	 * races between the monitor's stale candidate and an add. */
	mxfs_mutex_t                    *prot_lock;
	void                           (*protect_cb)(void *data, uint64_t mask);
	void                             *protect_cb_data;
	mxfs_epoch_t                     outcome_seen_epoch[MXFS_DISKLOCK_HB_SLOTS];
	uint64_t                         outcome_seen_seq[MXFS_DISKLOCK_HB_SLOTS];
	/* (ruling item 8): a QUARANTINED descriptor whose outcome record
	 * is present but fails magic/version/crc is a persistent high-severity
	 * condition — the monitor alerts once per slot (this latch) and fires
	 * recov_outcome_cb with oc == NULL every pass so the consumer fails
	 * closed fswide.  Cleared when the slot's descriptor goes away. */
	bool                             outcome_badcrc_alerted[MXFS_DISKLOCK_HB_SLOTS];
};

/* Lifecycle */
/*
 * `auth` is the incarnation's authority object, allocated by whoever owns the
 * incarnation (the mount) BEFORE this context exists, so that the gate has an
 * answer from the first instant a clustered mutation is possible.  The
 * context takes its own reference.  NULL means "make your own" and is for the
 * user-mode build, which has no mount to own one.
 */
struct mxfs_disklock_ctx *mxfs_disklock_create(mxfs_bdev_t *dev,
						uint64_t disklock_offset,
						mxfs_node_id_t local_node,
						struct mxfs_authority *auth);
void mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx);
struct mxfs_authority *mxfs_disklock_authority(struct mxfs_disklock_ctx *ctx);

/* durably classify this incarnation a single-node local log
 * writer (MXFS_HB_FEAT_SNLOCAL in every record it emits).  PRE-CLAIM
 * ONLY — refused (with a conspicuous log line) once a slot is held,
 * because the marker is write-time provenance, not mutable state. */
void mxfs_disklock_set_snlocal(struct mxfs_disklock_ctx *ctx, bool snlocal);
/* 0.75.0: write-time transport marker (MXFS_HB_FEAT_TCP); before the claim only. */
void mxfs_disklock_set_transport_tcp(struct mxfs_disklock_ctx *ctx, bool tcp);

/*
 * 0.75.0: the platter's transport census, taken BEFORE a mount selects its
 * transport and before any disklock context exists.  Every ACTIVE or
 * WITHDRAWN record of this mkfs generation with a VALID feature block votes
 * by its MXFS_HB_FEAT_TCP bit; LEGACY, CORRUPT and other-generation feature
 * blocks never vote (unknown is not a transport).  first_tcp / first_caw
 * name one voting slot of each kind (-1 = none) for the refusal line.
 */
struct mxfs_disklock_transport_census {
	int                     n_tcp;
	int                     n_caw;
	int                     n_unknown;      /* current-gen ACTIVE/WITHDRAWN, no valid vote */
	int                     first_tcp;
	int                     first_caw;
};
int mxfs_disklock_scan_transport(mxfs_bdev_t *dev, uint64_t base_offset,
				 uint32_t fs_gen,
				 struct mxfs_disklock_transport_census *c);

/*
 * install this incarnation's identity block BEFORE the slot claim
 * (the claim record is the first record that must carry it).  pr_key is the
 * ledger-selected 64-bit per-boot key (dlm/prledger.h), key_gen its
 * generation.  Refused (-EBUSY) once a slot is held: the block, like snlocal,
 * must be uniform across the tenure.
 */
int mxfs_disklock_set_identity(struct mxfs_disklock_ctx *ctx,
			       const uint8_t host_uuid[16],
			       const uint8_t boot_uuid[16],
			       uint32_t host_src, uint64_t pr_key,
			       uint32_t key_gen);

/*
 * the PR key of the incarnation whose death was declared on `slot`
 * — served from the DEATH SNAPSHOT taken at fire_dead, never from current
 * slot state, and only for the exact (node, epoch) the caller names.  0 when
 * no valid identity block of that incarnation was ever observed by this
 * node, or when conflicting keys were observed for it; the fencer must then
 * refuse (MXFS_FENCE_KIND_NO_VICTIM_KEY), never derive a key from node_id.
 */
/* the victim's host/boot uuids frozen with its key in the death
 * snapshot (same exact-incarnation rule).  false when no key was frozen. */
bool mxfs_disklock_victim_identity(struct mxfs_disklock_ctx *ctx, int slot,
				   mxfs_node_id_t node, mxfs_epoch_t epoch,
				   uint8_t host_uuid[16], uint8_t boot_uuid[16]);
uint64_t mxfs_disklock_victim_key(struct mxfs_disklock_ctx *ctx, int slot,
				  mxfs_node_id_t node, mxfs_epoch_t epoch,
				  uint32_t *key_gen);

/*
 * 0.75.71 (MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT): is the host that ran the
 * victim incarnation live again under a LATER boot?  True when this node's
 * own identity, or the observed identity of a monitored slot whose heartbeat
 * is advancing (node_track live), carries `host_uuid` with a boot_uuid other
 * than `boot_uuid`.  live_node/live_slot name the member found.
 */
bool mxfs_disklock_host_live_other_boot(struct mxfs_disklock_ctx *ctx,
					const uint8_t host_uuid[16],
					const uint8_t boot_uuid[16],
					mxfs_node_id_t *live_node,
					int *live_slot);

/*
 * Is `key` carried RIGHT NOW by a LIVE member other than `excl_node`, the
 * incarnation that is about to be fenced?
 *
 * The PR key is derived per BOOT from {host, boot, LUN} and a host reaches the
 * LUN over one I_T nexus, so a successor incarnation mounting in the same
 * kernel re-registers the identical key its dead predecessor left behind as
 * the fence target.  A PREEMPT AND ABORT naming that key would strip the LIVE
 * successor's registration, because the target cannot tell the incarnations
 * apart.  The fence primitive consults this before issuing anything.
 *
 * Own identity counts: this node's own key is "live elsewhere" for any victim
 * that is not this node's own tracked incarnation.  Returns 1 = yes (live_node
 * / live_slot name the holder), 0 = no live record carries it, <0 = could not
 * tell, which the caller must treat as a refusal.
 */
int mxfs_disklock_key_live_elsewhere(struct mxfs_disklock_ctx *ctx,
				     uint64_t key, mxfs_node_id_t excl_node,
				     mxfs_node_id_t *live_node,
				     int *live_slot);
/*
 * 0.75.71: does ANY record on the table carrying `boot_uuid` in a valid
 * identity block advance its stamp across a heartbeat interval (two reads
 * >= 2.5 s apart)?  A clone or snapshot-resumed copy of the victim's boot
 * that is heartbeating somewhere answers yes and the boot boundary cannot be
 * claimed.  0 = scanned, *advancing set; <0 = an I/O error (refuse).
 */
int mxfs_disklock_boot_advancing(struct mxfs_disklock_ctx *ctx,
				 const uint8_t boot_uuid[16], bool *advancing,
				 int *records);
/*
 * 0.75.72: how many monitored records are frozen but NOT yet declared dead
 * (never live, baseline seeded, no recovery pending) — deaths the monitor
 * will declare once they have been silent for the dead window.  window_ms
 * receives that window (dead_threshold x heartbeat interval).  The mount
 * admission barrier extends its wait by it: the blockers it is waiting on
 * (a dead prover's standing fence attempt, an unfenced dead slice) resolve
 * only after those declarations.
 */
int mxfs_disklock_deaths_undeclared(struct mxfs_disklock_ctx *ctx,
				    unsigned int *window_ms);

/* Is a heartbeat record's identity block valid for `slot`?  Exported for the
 * user-mode tools (chk_mxfs, caw_slotdump) which share this file. */
/* 0.75.77: a RECOVERY_GUARD's identity block, validated under the flags its
 * victim writer bound it to (ACTIVE / WITHDRAWN / RETIRE_PENDING); other
 * records exactly as mxfs_hb_identity_valid. */
bool mxfs_hb_guard_identity_valid(const struct mxfs_disklock_heartbeat *hb,
				  uint32_t slot);
bool mxfs_hb_identity_valid(const struct mxfs_disklock_heartbeat *hb,
			    uint32_t slot);
void mxfs_disklock_set_slot_limit(struct mxfs_disklock_ctx *ctx, uint32_t limit);

/*
 * (D-0359 step 1, design-consult ruling): OPERATIONAL CAW capability of the
 * device this mount runs on, established on the sector this node owns (its
 * own heartbeat slot) through the same PAL path the lock-slot CAS uses.
 * Positive half = the claim itself landed via CAW (claim_via_caw); negative
 * half = a deliberately mismatching CAW must MISCOMPARE and must not install
 * its write image.  Call after claim_slot, before the CAW DLM is created.
 *   MXFS_CAW_CAP_OK          both halves held
 *   MXFS_CAW_CAP_UNSUPPORTED definitive: no SCSI device / opcode rejected
 *   MXFS_CAW_CAP_TRANSIENT   ambiguous I/O outcome — fail THIS admission,
 *                            never classify the device
 *   MXFS_CAW_CAP_VIOLATION   semantic: mismatch reported success, or the
 *                            record changed under a miscompare — hard refusal
 */
enum mxfs_caw_cap {
	MXFS_CAW_CAP_OK = 0,
	MXFS_CAW_CAP_UNSUPPORTED,
	MXFS_CAW_CAP_TRANSIENT,
	MXFS_CAW_CAP_VIOLATION,
};
enum mxfs_caw_cap mxfs_disklock_caw_capability(struct mxfs_disklock_ctx *ctx,
					       int *rc_out);
const char *mxfs_caw_cap_name(enum mxfs_caw_cap cap);

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

/* D2 — withdraw + deferred-purge recovery API */
void mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx);
/* (D-0356/D-377): after a clean release whose late PR unregister
 * failed, CAS our RELEASED record back to WITHDRAWN (identity + key kept) so
 * peers fence the key.  0 ok; -ESTALE slot no longer ours; -EBUSY heartbeat
 * still running. */
int  mxfs_disklock_restamp_withdrawn_after_release(struct mxfs_disklock_ctx *ctx);
/* a departure with NO PR key to retire (no PR on the target, or
 * the transport never registered one) completes its own retirement: CAS our
 * RETIRE_PENDING record to EMPTY.  Never called after a real unregister — a
 * de-registered initiator cannot write a WE-RO LUN; peers complete it. */
int  mxfs_disklock_retire_complete_self(struct mxfs_disklock_ctx *ctx);
/*
 * (0.59.2): the P305 same-boot settlement — the ONLY path that may
 * publish EMPTY for a RETIRE_PENDING record naming the caller's OWN key.
 * The caller (mount thread, under mxfs_v5_dlm_departure_lock) has already
 * obtained the proof it names in `proof` (a fresh bracket showing its
 * registration live inside the fencing reservation, or the operator's
 * single_node_exclusive topology assertion for a key-0 record).  This
 * function re-reads the sector FUA and requires it to be exactly the
 * RETIRE_PENDING record {slot, node, epoch} with a valid identity whose
 * pr_key == `key`; anything else is CHANGED (nothing written).  Returns
 * MXFS_DISKLOCK_RETIRE_EMPTY, MXFS_DISKLOCK_RETIRE_CHANGED, or <0.
 */
int  mxfs_disklock_retire_settle_own(struct mxfs_disklock_ctx *ctx,
				     uint32_t slot, mxfs_node_id_t node,
				     mxfs_epoch_t epoch, uint64_t key,
				     const char *proof);
void mxfs_disklock_set_key_state_sync_fn(struct mxfs_disklock_ctx *ctx,
					 mxfs_disklock_key_state_fn fn);
void mxfs_disklock_set_key_state_fn(struct mxfs_disklock_ctx *ctx,
				    mxfs_disklock_key_state_fn fn,
				    void *data);
/* the result vocabulary of one RETIRE_PENDING settlement attempt. */
enum mxfs_disklock_retire_result {
	MXFS_DISKLOCK_RETIRE_EMPTY     = 0, /* key ABSENT/OWN: record now EMPTY */
	MXFS_DISKLOCK_RETIRE_WAITING   = 1, /* PRESENT inside the grace, or UNKNOWN */
	MXFS_DISKLOCK_RETIRE_WITHDRAWN = 2, /* PRESENT past grace/immediate: WITHDRAWN */
	MXFS_DISKLOCK_RETIRE_CHANGED   = 3, /* sector moved under us; re-classify */
	MXFS_DISKLOCK_RETIRE_PRESENT   = 4, /* settle-absent found the key registered
										 * (internal: the settle callback's answer) */
};

/*
 * (0.61.0, design-consult design ruling D1): the ABSENT settlement no longer
 * happens on the heartbeat thread from a table lookup.  When a RETIRE_PENDING
 * record names a nonzero key that the async table does not show PRESENT, the
 * monitor hands the record to this callback with immediate=false: the owner
 * (v5_mount) enqueues {slot, image} to its retire settle worker and the
 * callback returns WAITING.  The worker — and the mount thread at P305,
 * which calls it with immediate=true — takes the host-wide departure mutex,
 * runs ONE fresh bracket and, if it proves the key absent, CASes the exact
 * pending image to EMPTY through mxfs_disklock_retire_cas_empty() while the
 * proof's single-use token is validated adjacent to the write (D6).
 * Returns MXFS_DISKLOCK_RETIRE_EMPTY (settled; *pending is the EMPTY image),
 * CHANGED (*pending is the current image), PRESENT (key registered — the
 * caller applies the grace/WITHDRAWN rule), WAITING (no proof / enqueued),
 * or <0.
 */
void mxfs_disklock_set_settle_absent_fn(struct mxfs_disklock_ctx *ctx,
					mxfs_disklock_settle_absent_fn fn,
					void *data);
/*
 * The CAS primitive the settlement uses.  FUA re-reads the sector, requires
 * it to be byte-identical to `expect` (the RETIRE_PENDING image the proof
 * was obtained for), calls validate_fn (the proof-token consume) and, only
 * if that returns 0, compare-and-writes EMPTY.  On return *expect holds the
 * sector's current image.  Returns MXFS_DISKLOCK_RETIRE_EMPTY, CHANGED,
 * WAITING (validate refused / CAW unsupported), or <0.
 */
typedef int (*mxfs_disklock_validate_fn)(void *data);
int  mxfs_disklock_retire_cas_empty(struct mxfs_disklock_ctx *ctx, uint32_t slot,
				    struct mxfs_disklock_heartbeat *expect,
				    mxfs_disklock_validate_fn validate_fn,
				    void *validate_data);
/*
 * settle one slot's RETIRE_PENDING record from the MOUNT thread —
 * the P305 same-boot predecessor and the admission barrier's sweep.
 * immediate=true skips the grace: a PRESENT key is stamped WITHDRAWN at
 * once (fencing a present key is the safe operation; admitting-and-waiting
 * beside a write-capable registration is not).  UNKNOWN never settles.
 * Returns a mxfs_disklock_retire_result, <0 on I/O failure, -ENOENT when
 * the slot does not hold a RETIRE_PENDING record of this filesystem.
 */
int  mxfs_disklock_retire_settle_slot(struct mxfs_disklock_ctx *ctx,
				      uint32_t slot, bool immediate);
void mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx,
				    mxfs_disklock_recovered_cb cb, void *data);
/* (#92): clean-departure delivery (see the typedef's comment). */
void mxfs_disklock_set_clean_depart_cb(struct mxfs_disklock_ctx *ctx,
				       mxfs_disklock_clean_depart_cb cb,
				       void *data);
/*
 * the victim incarnation is an ARGUMENT, never a read-back.  See the
 * mxfs_disklock_expire_cb comment — mark_recovery_pending used to copy
 * node_track[slot].last_epoch, which the epoch-change arm had already rebased
 * onto the successor.  Pass 0 only when the caller truly never observed the
 * victim's incarnation.
 */
void mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx,
					 int slot, mxfs_node_id_t node,
					 mxfs_epoch_t victim_epoch);
bool mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot);
/* (§6.4): mark pending AND freeze the victim's PR identity from the
 * bootstrap owner's sealed manifest (there is no monitor death snapshot after
 * a total outage).  pr_key == 0 freezes nothing: the fence is refused. */
void mxfs_disklock_mark_recovery_pending_ident(struct mxfs_disklock_ctx *ctx,
					       int slot, mxfs_node_id_t node,
					       mxfs_epoch_t victim_epoch,
					       uint64_t pr_key,
					       uint32_t key_gen,
					       const uint8_t host_uuid[16],
					       const uint8_t boot_uuid[16]);
/*
 * COMPARE-and-clear.  A pending marker is a promise about ONE
 * incarnation; completing A's recovery must not silently drop a marker that
 * has since been re-armed for B.  Clears only when the marker still names
 * {node, victim_epoch}; returns 0 when cleared, -ESTALE when the marker names
 * a different victim (left intact), -ENOENT when nothing was pending.
 *
 * victim_epoch == 0 degrades to the node-scoped match, for callers that never
 * observed an incarnation.  There is no unconditional clear: an unconditional
 * clear is exactly the bug this replaces.
 *
 * The tuple is (proto_gen, slot, node, incarnation); proto_gen is elided
 * because this marker is per-mount volatile state that cannot outlive the
 * module, so MXFS_PROTO_GEN is invariant across its whole lifetime.  If the
 * marker is ever made durable, proto_gen must become explicit.
 */
int  mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx,
					  int slot, mxfs_node_id_t node,
					  mxfs_epoch_t victim_epoch);
/*
 * There is deliberately NO "what incarnation is in slot N" accessor.
 * node_track[].last_epoch answers "who is there NOW", and every attempt to use
 * it as a victim identity is the same category error: the monitor rebases it
 * onto a successor, so the answer names a LIVE node — and names it with
 * inc_valid() set, so every downstream match succeeds and the wrong claim
 * looks verified.  A caller that must name a victim either had it handed down
 * (mxfs_disklock_expire_cb / confirm_dead_mask's out_epoch) or genuinely never
 * observed one and must pass 0.
 */
mxfs_node_id_t mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx,
					  int slot);
mxfs_epoch_t mxfs_disklock_pending_epoch(struct mxfs_disklock_ctx *ctx,
					 int slot);
/* Iterate pending slots: first call prev=-1; returns next pending slot
 * (> prev) with *node filled, or -1 when exhausted. */
int mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx,
					int prev, mxfs_node_id_t *node);

/*
 * — DURABLE RECOVERY DESCRIPTOR ops (see the big comment above
 * MXFS_RECOV_DESC_MAGIC for the state machine and the five rules).
 *
 * All five re-read the victim's heartbeat sector cache-piercingly, act by
 * compare-and-write from the exact observed image, and make the result
 * durable before returning.  A failed CAS is always reported, never retried
 * blindly: the caller must re-read and re-decide (design review: "refresh vs stage-CAS
 * vs takeover vs final-zero must be serialized with mandatory reread after
 * CAS failure").
 *
 * recovery_begin   ACTIVE/WITHDRAWN → GUARD{FENCED}, victim identity kept in
 *                  the record header, recovery owner recorded in the
 *                  descriptor.  MUST run — and be durable — BEFORE the first
 *                  CAW purge.  Idempotent when we already own the descriptor.
 *                  `victim_epoch` NAMES THE INCARNATION BEING RECOVERED and is
 *                  enforced, not merely logged: a sector that has
 *                  moved on to a later incarnation of the same node is a
 *                  SUPERSESSION, not drift to be adopted.
 *                    0        descriptor exists and is ours
 *                    -ENOENT  sector already CONSUMABLE (someone published)
 *                    -EBUSY   another node owns this recovery
 *                    -ESTALE  the sector no longer names this victim
 *                    -EPROTO  a descriptor we cannot interpret (refuse)
 *                    -EAGAIN  lost the CAS; re-read and re-decide
 *                    MXFS_RECOVERY_SUPERSEDED  see below
 *                  On 0 it fills *out_auth with the authorization tuple the
 *                  caller must present to advance/refresh.
 * recovery_advance  monotonic stage CAS.  Refuses to go backwards (returns 0
 *                  when the stage is already reached), refuses a quarantined
 *                  descriptor (-EPERM) and refuses if the presented auth no
 *                  longer matches the sector (-EBUSY) — which is exactly the
 *                  "we were taken over while we worked" case.
 * recovery_refresh  re-stamp owner_stamp_ms so survivors can tell a live
 *                  recovery from an abandoned one.  Same auth check; -ESTALE
 *                  when it no longer holds (stop touching the descriptor).
 * recovery_read     copy out the validated descriptor (-ENOENT if the slot
 *                  carries none, -EPROTO if it carries one we cannot read).
 * recovery_takeover claim an abandoned recovery: CASes ONLY the owner fields
 *                  and bumps owner_term — victim identity, recovery_gen and
 *                  stage are preserved, and the caller must RESUME from the
 *                  returned stage rather than re-run an earlier one.  Returns
 *                  the stage (>= 0) on success and fills *out_auth.
 *                  PRECONDITION (rule 5): the caller has already confirmed the
 *                  current owner's session dead AND fenced from the LUN.  This
 *                  call re-proves only that nothing changed on the sector for
 *                  MXFS_RECOV_ABANDON_MS, which alone is NOT sufficient.
 *
 * NOTE the blocking cost: recovery_takeover sleeps MXFS_RECOV_ABANDON_MS
 * inside the call.  It must never run on the heartbeat monitor thread.
 */

/*
 * MXFS_RECOVERY_SUPERSEDED — the recovery we were asked to publish is
 * NO LONGER OURS TO PUBLISH, because the victim itself already did it.
 *
 * The slot now carries a LIVE, current-generation, ACTIVE record for the SAME
 * node at a LATER incarnation.  That is only reachable through the claim
 * pass-1 own-stamp reclaim, which matches on node_id alone and therefore hands
 * the rebooted node back its own slot with slice_adopted = false — its mount
 * recovery replayed the whole slice, including everything we were about to
 * replay.  Laying a guard on that sector would freeze a LIVE member.
 *
 * It is a NAMED outcome, not an overloaded errno: the caller must retire the
 * pending marker and report success, which is the opposite of what every other
 * negative return here means.  The wire value is -EREMCHG purely so it
 * propagates through int-returning API boundaries; never test for -EREMCHG.
 *
 * Emitted ONLY when every one of these holds — anything malformed, zeroed,
 * wrong-generation, guarded, or naming another node is NOT supersession and
 * fails closed:
 *   valid magic + feature block at the CURRENT proto_gen; same slot; flags ==
 *   ACTIVE; same node_id; our own fs_gen; expected incarnation nonzero; sector
 *   incarnation nonzero; and the two incarnations differ.
 */
#define MXFS_RECOVERY_SUPERSEDED        (-EREMCHG)

int mxfs_disklock_recovery_begin(struct mxfs_disklock_ctx *ctx, int slot,
				 mxfs_node_id_t victim,
				 mxfs_epoch_t victim_epoch,
				 uint16_t slice_idx, uint16_t slice_count,
				 uint32_t flags,
				 struct mxfs_recov_auth *out_auth);
int mxfs_disklock_recovery_advance(struct mxfs_disklock_ctx *ctx, int slot,
				   unsigned int stage,
				   const struct mxfs_recov_auth *auth);
int mxfs_disklock_recovery_refresh(struct mxfs_disklock_ctx *ctx, int slot,
				   const struct mxfs_recov_auth *auth);
int mxfs_disklock_recovery_read(struct mxfs_disklock_ctx *ctx, int slot,
				struct mxfs_recov_desc *out);
/*
 * sess420 (D-RECOV-ADVANCE-UNBOUNDED-RETRY, sess91 ruling item 3 + sess420
 * ruling): durably give back ONE recovery lease this incarnation owns, so a
 * successor can take the descriptor over — the per-slot twin of
 * mxfs_disklock_recovery_relinquish_owned.  The expected image is read fresh
 * and the descriptor must still be ours AND still carry `auth`'s recovery
 * identity (recovery_gen + owner_term): a blind owner->UNOWNED CAS is never
 * issued.  Stage and certificate are preserved.
 * Returns 0 given back; -ENOENT not ours / not this identity (nothing done);
 * -EAGAIN the CAS raced (caller may re-read and decide); other -errno I/O.
 */
int mxfs_disklock_recovery_relinquish_slot(struct mxfs_disklock_ctx *ctx,
					   int slot,
					   const struct mxfs_recov_auth *auth);
int mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot,
				    struct mxfs_recov_auth *out_auth);

/*
 * ── THE FENCE-EVIDENCE CHANNEL ──────────────────────────────────
 *
 * Measured on the rig: a peer death produces exactly ONE node whose
 * PREEMPT AND ABORT completes and 30 whose 0x05 hits RESERVATION CONFLICT,
 * while the replayer is chosen by lowest_live_slot and was — in the captured
 * run — one of the losers, dispatching foreign replay 22 ms after its own
 * `proves_excl=0`.  Exclusion is therefore proved by one node and consumed by
 * another, and until now the prover's evidence had nowhere to go.
 *
 * The channel is the victim's own heartbeat sector.  The certificate belongs
 * to the victim RECOVERY TRANSACTION, not to the prover: putting it in the
 * prover's sector loses it exactly when the prover also dies, which is the
 * case the channel exists for.
 *
 *   fence_intent   ACTIVE/WITHDRAWN -> GUARD{FENCING}, owned by the prover as
 *                  a FENCING-ATTEMPT lease.  Durable BEFORE the P&A is issued
 *                  (blocker 1).  Serialises fence attempts, records the
 *                  exact victim key the attempt is about, and makes "the
 *                  result is uncertain" distinguishable from "fencing never
 *                  started".  Authorises NOTHING on its own.
 *                    0        the intent is ours (fresh or resumed)
 *                    -ENOENT  sector already CONSUMABLE
 *                    -EEXIST  already CERTIFIED by someone; nothing to do
 *                    -EBUSY   another prover holds a live fencing-attempt lease
 *                    -ESTALE  the sector no longer names this victim
 *                    -EPROTO  a descriptor we cannot interpret (refuse)
 *                  `victim_key` is the key the caller is about to preempt.  It
 *                  is recorded so a successor can see what was in flight — it
 *                  is NOT evidence: ruled the inference "intent exists +
 *                  prover died + key absent => the P&A completed" UNSOUND.  A
 *                  successor must run a NEW accepted exclusion operation and
 *                  certify THAT.
 *   fence_certify  FENCING -> FENCED: writes the certificate and RELEASES
 *                  ownership in the SAME CAS, leaving the descriptor UNOWNED
 *                  and claimable.  Refuses any result that does not prove
 *                  exclusion — the certificate can only ever say the truth.
 *                    0        certified (or already certified BY US)
 *                    -EEXIST  certified by a different prover/attempt
 *                    -EPERM   the result does not prove exclusion, or its key
 *                             disagrees with the intent — nothing written
 *                    -EBUSY   the attempt lease is no longer ours
 *                    -ESTALE  the sector no longer carries our attempt
 *   recovery_claim claim an UNOWNED certified descriptor as the recovery
 *                  EXECUTION owner.  This is NOT takeover: no prior owner is
 *                  displaced, nothing must be proved dead.  Whole-descriptor
 *                  CAS; the certificate bytes are revalidated and carried
 *                  through unchanged; owner_term becomes 1 atomically.
 *                    >= 0     the stage now owned (fills *out_auth)
 *                    -ENOENT  no descriptor (sector zeroed or ACTIVE)
 *                    -EBUSY   already owned by somebody
 *                    -EPERM   present but NOT certified (intent only, or the
 *                             certificate does not prove exclusion)
 *   replay_authorized THE CENTRAL GATE (blocker 4).  Full revalidation
 *                  of the certificate against the sector's own identity and
 *                  the caller's expectation.  Every destructive step asks
 *                  this — not just the replay dispatch: the IMAGES_REPLAYED
 *                  transition, destructive victim-manifest work, and sector
 *                  zeroing all route through it.  `site` names the caller in
 *                  the refusal log.  Returns 0 when authorised.
 *                    0        authorised
 *                    -EPERM   no valid certificate (the reason is logged)
 *                    -EBUSY   certified, but the execution lease is not ours
 *                             any more — we were taken over mid-flight
 *                    -ENOENT  no descriptor at all / sector CONSUMABLE
 *                    -EPROTO  a descriptor we cannot interpret
 *                  `auth` may be NULL for a pre-claim, defence-in-depth probe
 *                  ("is this slice certified fenced?").  Every caller that is
 *                  about to DO something destructive must pass the execution
 *                  lease it holds, or the taken-over case cannot be detected.
 */
int mxfs_disklock_recovery_fence_intent(struct mxfs_disklock_ctx *ctx, int slot,
					mxfs_node_id_t victim,
					mxfs_epoch_t victim_epoch,
					uint64_t victim_key,
					uint16_t slice_idx,
					uint16_t slice_count,
					uint32_t flags,
					struct mxfs_recov_fence_auth *out_auth);
/*
 * Make "this prover is about to submit a state-changing PR command" DURABLE.
 *
 * .  Called on the last line before the PROUT leaves for the transport,
 * with the fencing-attempt lease held.  Sets MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN
 * on the standing FENCING descriptor and does not return until that write is
 * durable — the ordering is the whole point, so a caller may NOT submit if this
 * returns nonzero.
 *
 *   0        the boundary is durable; the command may now be issued
 *   -EBUSY   the fencing-attempt lease is no longer ours
 *   -EEXIST  already certified by somebody; there is nothing to submit
 *   <0 other the boundary is NOT durable — DO NOT ISSUE THE COMMAND
 *
 * Idempotent: re-arming an attempt that already carries the bit returns 0
 * without a write.
 */
/*
 * 0.74.0: make the prover's RECOVERY_BLOCKED verdict durable on its own
 * standing FENCING attempt (MXFS_RECOV_F_FENCE_BLOCKED).  Idempotent; refuses
 * (-EBUSY) when the attempt lease is no longer ours, -EEXIST once certified.
 */
int mxfs_disklock_recovery_fence_mark_blocked(struct mxfs_disklock_ctx *ctx,
					      int slot,
					      const struct mxfs_recov_fence_auth *auth);
int mxfs_disklock_recovery_fence_arm_submit(struct mxfs_disklock_ctx *ctx,
					    int slot,
					    const struct mxfs_recov_fence_auth *auth);

/*
 * Does this slot carry a standing fencing attempt owned by THIS node?
 *
 *   1  ours, stage FENCING with MAY_HAVE_RUN clear (known never to have
 *      submitted a command), or our own SNAPSHOTTING — the set the fence-retry
 *      worker re-drives unconditionally.
 *   2  ours, stage FENCING with MAY_HAVE_RUN set (0.89.63).  The platter can
 *      say only that a command MAY have been issued under the arm; whether one
 *      WAS is the calling incarnation's own knowledge, and the caller decides.
 *   0  not ours: certified, taken over, or gone.
 *  <0  the question could not be answered — which is NOT "no".
 *
 * Fills *out_victim / *out_epoch / *out_term (each may be NULL) when it
 * returns 1 or 2.
 */
int mxfs_disklock_recovery_fence_retryable(struct mxfs_disklock_ctx *ctx,
					   int slot,
					   mxfs_node_id_t *out_victim,
					   mxfs_epoch_t *out_epoch,
					   uint32_t *out_term);

/*
 * certify writes the certificate bytes and moves FENCING ->
 * SNAPSHOTTING (NOT FENCED).  The prover KEEPS the fencing-attempt lease; the
 * descriptor becomes UNOWNED/FENCED only in mxfs_disklock_recovery_fence_seal()
 * once the victim's manifest is written and sealed.  Idempotent for our own
 * attempt already at SNAPSHOTTING (returns 0 without a write); -EEXIST once
 * anybody's certificate reached FENCED.
 *
 * 0.89.15: the certificate carries a RETIREMENT PROOF as well as the proof of
 * exclusion, and this constructor is where that obligation is enforced — a
 * replay-authorising kind arriving with retire_basis NONE is refused before
 * the platter is touched, whichever classification path reached it.  The
 * basis/claim/observation triple is the proof's provenance: what it stood on,
 * the exact proposition asserted, and what was observed about the victim's
 * registration.  They are logged with the certificate; making them durable is
 * the separate on-disk work recorded in the defect queue.
 */
int mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot,
					 const struct mxfs_recov_fence_auth *auth,
					 uint16_t fence_kind,
					 uint16_t fence_resv_type,
					 uint64_t fence_victim_key,
					 uint32_t fence_pr_gen,
					 uint8_t retire_basis,
					 uint8_t retire_claim,
					 uint8_t retire_obs);

/*
 * — the recovery manifest (docs/recovery-manifest.md).
 *
 * mxfs_disklock_set_rman(): install the envelope region.  Without it no
 * manifest can be written, so certify/seal refuse (-ENODEV) and the slice
 * stays at FENCING/SNAPSHOTTING — fail closed.
 *
 * mxfs_disklock_recovery_manifest_write(): write `count` entries (caller
 * collected them from the CAW table; canonical slot_idx order) into the
 * victim's rman slot under OUR attempt lease with the descriptor at
 * SNAPSHOTTING, then seal.  Fills *out_ptr with the pointer record the seal
 * CAS must carry (unsealed fields; seal() binds it to the victim identity).
 * Returns 0 only when the manifest is durably SEALED on the platter.
 *
 * mxfs_disklock_recovery_fence_seal(): the SNAPSHOTTING -> FENCED CAS with the
 * manifest pointer, releasing the attempt lease (UNOWNED) atomically.
 *   0        certified+sealed; the elected replayer may claim
 *   -EBUSY   the attempt lease is no longer ours
 *   -EEXIST  already FENCED (idempotent only for our own term)
 *   -EPROTO  descriptor not at SNAPSHOTTING
 *
 * mxfs_disklock_recovery_manifest_read(): the CONSUMER.  Reads the victim's
 * rman slot, validates the sealed header against the descriptor's pointer
 * record (read fresh from the sector), and returns the entry array
 * (mxfs_pal_alloc'd; caller frees).  A NO_CAW_TABLE manifest returns 0 with
 * count 0 and *out_no_caw = true.  Any mismatch / unsealed / unreadable
 * manifest is an error — the caller MUST abort the replay attempt, never
 * skip per transaction.
 */
void mxfs_disklock_set_rman(struct mxfs_disklock_ctx *ctx, uint64_t rman_offset,
			    uint64_t rman_size);
int mxfs_disklock_recovery_manifest_write(struct mxfs_disklock_ctx *ctx, int slot,
					  const struct mxfs_recov_fence_auth *auth,
					  const struct mxfs_rman_entry *ents,
					  uint32_t count, uint32_t scan_slots,
					  uint32_t flags,
					  struct mxfs_recov_manifest_ptr *out_ptr);
int mxfs_disklock_recovery_fence_seal(struct mxfs_disklock_ctx *ctx, int slot,
				      const struct mxfs_recov_fence_auth *auth,
				      const struct mxfs_recov_manifest_ptr *mp);
/* the same load for the bootstrap owner's adopted slot K, whose
 * sector no longer carries the descriptor: `d`/`mptr` are the ESCROWED copies
 * (the pointer's crc is re-verified for the victim identity). */
int mxfs_disklock_recovery_manifest_read_escrow(struct mxfs_disklock_ctx *ctx,
						int slot, mxfs_node_id_t victim,
						mxfs_epoch_t victim_epoch,
						const struct mxfs_recov_desc *d,
						const struct mxfs_recov_manifest_ptr *mptr,
						struct mxfs_recov_manifest_ptr *out_ptr,
						struct mxfs_rman_entry **out_ents,
						uint32_t *out_count,
						bool *out_no_caw);
/* the certified descriptor's validated manifest pointer, for the
 * escrow (-ENOENT when the sector carries none). */
int mxfs_disklock_recovery_mptr_read(struct mxfs_disklock_ctx *ctx, int slot,
				     struct mxfs_recov_manifest_ptr *out);
int mxfs_disklock_recovery_manifest_read(struct mxfs_disklock_ctx *ctx, int slot,
					 mxfs_node_id_t victim,
					 mxfs_epoch_t victim_epoch,
					 struct mxfs_recov_manifest_ptr *out_ptr,
					 struct mxfs_rman_entry **out_ents,
					 uint32_t *out_count,
					 bool *out_no_caw);
/*
 * Take over an ABANDONED fencing-attempt lease.  The ONLY case this exists
 * for: the prover died with the intent durable.  At FENCING it authorises
 * issuing a NEW PREEMPT AND ABORT and certifying THAT result — never the dead
 * prover's (ruled that inference unsound).  If the victim key is
 * already gone, no exclusion can be proved and the slice stays unreplayable;
 * that is the correct outcome, not a bug to optimise away.
 *
 * at SNAPSHOTTING the certificate is already proved and durable, so
 * the takeover authorises ONLY redoing the manifest scan+seal (the P&A is
 * never repeated).  The certificate's fence_prover_* bytes are carried through
 * untouched — they name who PROVED; owner_* and fence_term name the current
 * attempt-lease holder.  The caller learns which case it got from
 * fence_intent() on the resumed attempt (0 = P&A, SNAPSHOT_PENDING = scan).
 *
 * Same precondition as recovery_takeover (rule 5): the caller must ALREADY
 * have confirmed the prover's session dead.  Blocks MXFS_RECOV_ABANDON_MS
 * inside the call — never run it on the heartbeat monitor thread.
 *   0        the attempt lease is ours; resume via fence_intent()
 *   -EEXIST  already certified — call recovery_claim instead
 *   -EBUSY   the prover is alive, or a third node took the attempt
 */
int mxfs_disklock_recovery_fence_takeover(struct mxfs_disklock_ctx *ctx,
					  int slot,
					  uint64_t victim_key,
					  struct mxfs_recov_fence_auth *out_auth);
int mxfs_disklock_recovery_claim(struct mxfs_disklock_ctx *ctx, int slot,
				 mxfs_node_id_t victim,
				 mxfs_epoch_t victim_epoch,
				 struct mxfs_recov_auth *out_auth);
/*
 * out_fence_kind (optional): set to the certificate's fence_kind, but ONLY
 * when the gate answers 0 — i.e. only from a descriptor that validated
 * strictly AND still matches the presented execution lease.  On any refusal
 * it reads MXFS_FENCE_KIND_NONE.  ruling: an exclusion recheck may
 * branch on the certificate kind only through this path; a bare descriptor
 * reread could hand it a successor's kind.
 */
int mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx,
					     int slot,
					     mxfs_node_id_t victim,
					     mxfs_epoch_t victim_epoch,
					     const struct mxfs_recov_auth *auth,
					     const char *site,
					     uint16_t *out_fence_kind);

/*
 * — READ-ONLY classification of a victim slot.
 *
 * recovery_claim() collapses several very different on-disk states into
 * -ENOENT ("no descriptor"), and the caller's correct response differs
 * completely between them: retire the pending marker and report success, or
 * refuse and keep it for a retry.  Getting that wrong either loses a recovery
 * or livelocks against a rejoined member.  This tells them apart without
 * writing anything, so a gate can classify before it decides.
 *
 * Non-negative values are states; negative is an errno (I/O, bad args).
 */
#define MXFS_RECOV_SLOT_DESCRIPTOR  0   /* carries a descriptor — ask the gate */
#define MXFS_RECOV_SLOT_CONSUMABLE  1   /* zeroed / foreign gen: PUBLISHED */
#define MXFS_RECOV_SLOT_SUPERSEDED  2   /* ACTIVE, same node, LATER incarnation */
#define MXFS_RECOV_SLOT_UNFENCED    3   /* ACTIVE, still this victim: never fenced */
#define MXFS_RECOV_SLOT_FOREIGN     4   /* names another node / unprovable state */
#define MXFS_RECOV_SLOT_UNREADABLE  5   /* a descriptor this build cannot validate */
int mxfs_disklock_recovery_slot_status(struct mxfs_disklock_ctx *ctx, int slot,
				       mxfs_node_id_t victim,
				       mxfs_epoch_t victim_epoch);

/*
 * (D-532): durably give back every recovery lease this incarnation
 * owns (descriptor -> UNOWNED, stage + certificate preserved).  Called by
 * release_slot BEFORE the clean member release; 0 iff provably none remain
 * owned.  On error the caller must NOT cleanly release the member slot —
 * the identity must stay fenceable.
 */
int mxfs_disklock_recovery_relinquish_owned(struct mxfs_disklock_ctx *ctx);

/*
 * Certificate validation against an ALREADY-READ descriptor.  Split out so a
 * caller holding a snapshot (recovery_read) can gate without a second I/O.
 * `fs_gen` is the reader's mkfs generation; `victim_epoch` 0 means "do not
 * cross-check the incarnation" and is only legitimate where the sector itself
 * is the incarnation authority.
 */
bool mxfs_recov_cert_proves_exclusion(const struct mxfs_recov_desc *d,
				      uint32_t fs_gen, int slot,
				      mxfs_node_id_t victim,
				      mxfs_epoch_t victim_epoch,
				      const char **why);

/*
 * generation identity.  set_fs_identity must be called after create
 * and BEFORE claim_slot/start_heartbeat so the claim record carries fs_gen
 * and foreign-generation records are filtered from the very first scan.
 * fs_uuid is the 16-byte XFS sb_uuid of the mounted volume.
 */
void mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx,
				   const uint8_t *fs_uuid);
void mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx,
				mxfs_disklock_fence_cb cb, void *data);
void mxfs_disklock_set_dbg_purge_hook(struct mxfs_disklock_ctx *ctx,
				      mxfs_disklock_dbg_purge_hook hook,
				      void *data);
void mxfs_disklock_set_conflict_cb(struct mxfs_disklock_ctx *ctx,
				   mxfs_disklock_conflict_cb cb, void *data);

/*
 * inode-eviction ring API.
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
/* 0.75.26: retire a recovered incarnation's slot tracking on the node that
 * completed its recovery (the elected replayer never takes the monitor's
 * P163-RECOVERED path); a successor already in the slot is adopted. */
void mxfs_disklock_slot_tenancy_retire(struct mxfs_disklock_ctx *ctx, int slot,
				       mxfs_node_id_t node,
				       mxfs_epoch_t victim_epoch);
void mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx,
				   mxfs_node_id_t node_id);

/* Unique heartbeat slot claiming (Bug 101 fix) */
int  mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx);
int  mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx);

/*
 * this mount's complete on-disk identity — {slot, node_id,
 * incarnation} — as one call.  Returns false, with all three outputs
 * zeroed, unless ALL of them are established: the slot is claimed
 * (local_slot >= 0), the node_id is nonzero, and the incarnation is valid.
 *
 * The triple is what binds a durable record to a specific mount instance:
 * a slot alone is reused across mounts (measured nodes migrating
 * slots), and a node_id alone spans incarnations.  Callers that can only
 * store part of it are storing something weaker than an identity and must
 * say so.  Any output pointer may be NULL.
 *
 * O(1) and lock-free by design: all three are fixed for the life of a mount
 * once claimed, so hot paths (the log-format path in particular) take no
 * lock to stamp them.
 */
bool mxfs_disklock_mount_identity(struct mxfs_disklock_ctx *ctx,
				  uint32_t *slot, mxfs_node_id_t *node,
				  mxfs_epoch_t *epoch);

/* recovery GUARD ops (unclaimed-bucket sweep exclusion).
 * guard_slot:   0 = guard won (image stored); -EBUSY = slot occupied or a
 *               guard is already held; -EAGAIN = lost the CAS race; <0 = IO.
 * guard_refresh: re-stamps the held guard's timestamp via CAS from the
 *               stored image.  0 = still ours; -ESTALE = lost (state
 *               cleared — caller must abort its sweep); <0 = IO (guard
 *               retained; transient).
 * unguard:      CAS the stored image back to zeros; always clears local
 *               state (a lost CAS means a stale-guard takeover won — the
 *               successor owns the slot now).
 * slot_unclaimed: 1 = unclaimed (empty/ghost/stale-guard — guardable);
 *               0 = claimed, recovery-pending, withdrawn, or freshly
 *               guarded; <0 = IO error. */
int  mxfs_disklock_guard_slot(struct mxfs_disklock_ctx *ctx, int slot);
int  mxfs_disklock_guard_refresh(struct mxfs_disklock_ctx *ctx);
void mxfs_disklock_unguard(struct mxfs_disklock_ctx *ctx);
int  mxfs_disklock_slot_unclaimed(struct mxfs_disklock_ctx *ctx, int slot);

/*
 * C7 version gate.
 * set_vergate_cb: register the fence hook (v5 layer, SCSI-PR preempt).
 * join_gate: call AFTER claim_slot + start_heartbeat.  Scans all HB slots;
 * every current-fs_gen ACTIVE record that shows liveness progression must
 * carry a valid feature block with proto_gen == MXFS_PROTO_GEN.  Records
 * needing a liveness verdict are sampled twice across >1 HB interval
 * (bounded by timeout_ms).  Returns 0 (admitted; monitor enforcement arms),
 * -EPROTO (live incompatible incumbent found — caller must WITHDRAW the
 * mount; incumbents are never fenced by a joiner), -ETIMEDOUT (ambiguity
 * unresolved within bound — fail closed).
 */
void mxfs_disklock_set_vergate_cb(struct mxfs_disklock_ctx *ctx,
				  mxfs_disklock_vergate_cb cb, void *data);

/*
 * (ruling, D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513):
 * the recovery-lease owner durably publishes a TERMINAL REFUSED outcome for
 * the victim's slice instead of either lying ("recovered") or going silent
 * (all-32 timeout suicide).  Requires the caller's live recov_auth — the same
 * authority contract as recovery_advance; -EBUSY with P234-RECOV-NOTOURS
 * evidence otherwise.  Sets MXFS_RECOV_F_QUARANTINED and fills the outcome
 * record in ONE durable CAS; does NOT advance the stage (quarantine is
 * terminal, and every stage gate already refuses a quarantined descriptor).
 * Idempotent: a descriptor already quarantined with an equivalent outcome
 * returns 0.  A publish failure means the refusal is NOT durable — the
 * caller must keep the retry path armed and must not act as if it landed.
 *
 * set_recov_outcome_cb registers the survivor-side import hook (see the
 * typedef); the publisher itself must ALSO import its own record locally so
 * enforcement does not wait a monitor lap.  On success (including the
 * idempotent already-quarantined case) *oc_out receives the canonical
 * on-platter outcome record so the caller imports EXACTLY what the cluster
 * will read, not its local draft (oc_out may be NULL if unwanted).
 */
int mxfs_disklock_recovery_publish_refusal(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    const struct mxfs_recov_refusal_info *info,
				    struct mxfs_recov_outcome *oc_out);
/*
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED item 5, increment 2; ruling
 * ccmemory ccloop-c7ee71c6-sess462-GPT-ruling-item5-inc2-obligation-record-
 * plumbing-only): the OBLIGATION LIST + RECORD (recov_obl.h).
 *
 * mxfs_disklock_recovery_obl_write() — the recovery-lease OWNER makes the
 * victim's RECOVER extent list durable in the victim's rman slot zone
 * (entries -> flush -> crc'd header LAST -> flush) and hands back the
 * 40-byte record, sealed against the victim sector's identity, that a later
 * descriptor CAS must carry (publish_refusal_obl below, or the
 * IMAGES_REPLAYED advance of increments 3-4).  Nothing in the heartbeat
 * sector changes here: until a CAS carries the record the list is
 * UNPUBLISHED and a successor may overwrite it.  `ext` is canonicalized IN
 * PLACE and validated against `geom`; a malformed/overlapping/oversized list
 * is refused (-EINVAL/-EEXIST/-EOVERFLOW) — the caller then quarantines.
 * count == 0 writes nothing and returns an empty (count 0) record.  The same
 * authority contract as recovery_advance (-EBUSY, P234-RECOV-NOTOURS).
 *
 * mxfs_disklock_recovery_publish_refusal_obl() — publish_refusal with the
 * record embedded in the SAME CAS as the terminal outcome.  Increment 2 only
 * ever publishes it with MXFS_RECOV_OBL_F_TERMINAL set: evidence of what a
 * completion would have owed, gating nothing (the descriptor is QUARANTINED
 * and stays terminal).  `obl` NULL == the plain publish_refusal.
 *
 * mxfs_disklock_recovery_read_obl() — the consumer: reads the sector, then
 * (count > 0) the list zone, and validates record, header and entries
 * against each other and the descriptor's recovery-case identity.  Returns
 * 0 with the record (and up to MXFS_RECOV_OBL_MAX_EXTENTS entries in
 * ext_out, *count_out), -ENOENT when the sector carries no record, -EPROTO
 * when anything fails to validate (the caller treats that as QUARANTINE,
 * never as "no obligations" — ruling STOP-SHIP 4), -ESTALE for a sector that
 * is not a recovery descriptor.  No authority needed: a published record is
 * public state like the outcome.
 */
int mxfs_disklock_recovery_obl_write(struct mxfs_disklock_ctx *ctx, int slot,
				     const struct mxfs_recov_auth *auth,
				     struct mxfs_recov_obl_ext *ext,
				     uint32_t count,
				     const struct mxfs_recov_obl_geom *geom,
				     uint64_t census_digest, uint16_t flags,
				     struct mxfs_recov_obl *out_rec);
int mxfs_disklock_recovery_publish_refusal_obl(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    const struct mxfs_recov_refusal_info *info,
				    const struct mxfs_recov_obl *obl,
				    struct mxfs_recov_outcome *oc_out);
int mxfs_disklock_recovery_read_obl(struct mxfs_disklock_ctx *ctx, int slot,
				    struct mxfs_recov_obl *rec_out,
				    struct mxfs_recov_obl_ext *ext_out,
				    uint32_t *count_out);
/*
 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED, real EFI completion on the TCP
 * transport — docs/dlm-protocol.md "Item 5", the 2-node custody model).
 *
 * mxfs_disklock_recovery_advance_obl() — the IMAGES_REPLAYED milestone with
 * its census verdict in the SAME compare-and-write: `rec` NULL sets
 * MXFS_RECOV_F_CENSUS_ZERO ("nothing owed"); a record sealed by obl_write
 * without F_TERMINAL is the OPEN case ("these extents are owed; the AGs in
 * ag_mask are frozen until OBLIGATIONS_DONE").  Refuses a TERMINAL or DONE
 * record here (those belong to publish_refusal_obl / advance_obl_done), and
 * refuses when the descriptor already carries a record (-EEXIST).  Same
 * authority contract as recovery_advance.  Monotonic like it: a descriptor
 * already at or past IMAGES_REPLAYED returns 0 and changes nothing.
 *
 * mxfs_disklock_recovery_obl_done_write() — the custodian's COMPLETION PROOF
 * (recov_obl_done.h): the caller fills n_empty/n_full/n_sparse, the outcome
 * bitmap and fs_uuid; this binds the identity (descriptor, record, list
 * header, lease term, stage_seq), writes it two-phase (uncommitted body +
 * flush, COMMITTED + crc + flush) and reads it back.  Requires the execution
 * lease, stage == IMAGES_REPLAYED and a valid OPEN record whose list header
 * validates; n_sparse must be 0.
 *
 * mxfs_disklock_recovery_advance_obl_done() — re-reads the sector and the
 * proof, requires: lease still ours, stage exactly IMAGES_REPLAYED, a valid
 * OPEN record, a COMMITTED proof that validates against the record and the
 * list header with the current owner_term and stage_seq; ONE compare-and-
 * write sets stage = OBLIGATIONS_DONE and the record's F_DONE.  Returns 0
 * when already DONE with the flag set; -ENOENT when no proof is committed;
 * -EPROTO when the proof or record does not validate; -EBUSY/-EPERM as
 * recovery_advance.
 *
 * mxfs_disklock_set_recov_obl_cb() — registers the OPEN-obligation observer
 * (typedef above) and runs one synchronous scan of all 64 sectors so a
 * mount installs its freezes BEFORE its first allocation (the monitor's
 * first pass may be up to one heartbeat interval away).
 */
struct mxfs_rman_obl_done;
int mxfs_disklock_recovery_advance_obl(struct mxfs_disklock_ctx *ctx, int slot,
				       const struct mxfs_recov_auth *auth,
				       const struct mxfs_recov_obl *rec);
int mxfs_disklock_recovery_obl_done_write(struct mxfs_disklock_ctx *ctx,
					  int slot,
					  const struct mxfs_recov_auth *auth,
					  struct mxfs_rman_obl_done *proof);
int mxfs_disklock_recovery_advance_obl_done(struct mxfs_disklock_ctx *ctx,
					    int slot,
					    const struct mxfs_recov_auth *auth);
int mxfs_disklock_set_recov_obl_cb(struct mxfs_disklock_ctx *ctx,
				   mxfs_disklock_recov_obl_cb cb, void *data);
/*
 * (design-consult ruling, D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356):
 * the CLOSURE GATE — the authority+verdict test that authorizes force-revoking
 * a quarantined victim's provably-out-of-closure grants.
 *
 * built the revoke itself here, over the disklock RECORD table.  That
 * was the wrong table: write_grant has zero callers, so the frozen
 * grants that strand survivors are CAW slot bits, not disklock records.  The
 * mutation now lives in dlm_caw.c where those bits are; disklock keeps only
 * the gate, because the descriptor + outcome that authorize it live in the
 * victim's heartbeat sector and nothing above this layer may parse them.
 *
 * All three read the sector FRESH on every call.  A gate image is never
 * cached, never amortized across a scan, and never reused across a CAS —
 * every destructive CAS is authorized by its own read (ruling item A).
 *
 * Common gate predicate (all required): the slot's descriptor must parse,
 * name THIS slot as its victim_slot, be QUARANTINED, and carry a valid
 * TERMINAL_REFUSED outcome with an AG_MASK domain and a non-zero mask.
 * FSWIDE refusals define no out-of-closure set at all — -EOPNOTSUPP.
 *
 * Returns (all three):
 *   0          gate holds; *victim / *ag_mask filled from the image read
 *   -ESTALE    no descriptor (snapshot/terminal), or the descriptor/verdict
 *              moved out from under the caller (revalidate)
 *   -EPROTO    descriptor bytes present but unparseable, or its victim_slot
 *              does not name this slot
 *   -EBUSY     the caller's recovery lease no longer holds (leased forms), or
 *              the slot is still LIVE (leaseless form — fail closed)
 *   -EINVAL    descriptor is not QUARANTINED (the full purge's job), or bad
 *              arguments
 *   -EBADMSG   QUARANTINED with no readable verdict
 *   -EOPNOTSUPP FSWIDE / malformed domain — no out-of-closure set exists
 *   other      I/O errors from the platter read pass through
 *
 * _snapshot     leased phase-0 read: establishes {victim, ag_mask} for the
 *               whole operation from an image the caller's auth covers.
 * _revalidate   leased per-CAS recheck: re-reads, re-evaluates, and compares
 *               against the caller's expected {victim, ag_mask} — any drift
 *               is -ESTALE.  There is deliberately NO zero sentinel: node 0
 *               is a valid victim, so the expectation is always passed in.
 * _terminal_gate_check
 *               LEASELESS form for the survivor-side scrub, which can hold no
 *               lease (none is obtainable over a quarantined descriptor).  It
 *               is sound only because a TERMINAL verdict is irreversible for
 *               a given {fs, node, epoch, recovery_gen} and the slot cannot be
 *               re-adopted while that descriptor stands.  It therefore drops
 *               the auth test and adds a liveness test FIRST: a slot our
 *               monitor still calls live (our own included) fails -EBUSY.
 */
int mxfs_disklock_closure_gate_snapshot(struct mxfs_disklock_ctx *ctx, int slot,
				    const struct mxfs_recov_auth *auth,
				    mxfs_node_id_t *victim,
				    uint64_t *ag_mask);
int mxfs_disklock_closure_gate_revalidate(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    mxfs_node_id_t victim,
				    uint64_t ag_mask);
int mxfs_disklock_terminal_gate_check(struct mxfs_disklock_ctx *ctx, int slot,
				    mxfs_node_id_t *victim,
				    uint64_t *ag_mask);
/*
 * (D-0493): CONTEXT-FREE terminal-guard classification of one
 * heartbeat record image, for readers that run before a disklock context
 * exists (the whole-cluster-restart survivor scan) and for offline tools.
 * Same identity binding as the closure gate: RECOVERY_GUARD of generation
 * `fs_gen`, descriptor crc bound to the sector's {fs_gen, node, epoch},
 * victim tuple == the record's own tuple and `slot`, QUARANTINED.
 *   0        canonical TERMINAL_REFUSED outcome (crc-valid, FSWIDE with mask 0
 *            or AG_MASK with a non-zero mask); *oc_out set
 *   -ENODATA QUARANTINED with the exact all-zero legacy outcome region:
 *            terminal, no domain evidence (admission terminalizes it FSWIDE)
 *   -EBADMSG QUARANTINED with outcome bytes that do not validate, or a
 *            non-canonical verdict: torn — fail closed
 *   -EAGAIN  a live descriptor (not quarantined): a victim, not a verdict
 *   -EPROTO  descriptor present but unparseable / bound to another tuple
 *   -ESTALE  another mkfs generation;  -ENOENT  no descriptor at all
 * A terminal guard is durable state, never evidence of an outage: nothing
 * fences, replays, adopts or zeroes it, and claim_slot never takes it.
 */
int mxfs_hb_terminal_guard_classify(const struct mxfs_disklock_heartbeat *hb,
				    uint32_t slot, uint32_t fs_gen,
				    const struct mxfs_recov_outcome **oc_out);
/*
 * (design-consult ruling): leaseless terminalization of the LEGACY
 * intent-path quarantine — a descriptor QUARANTINED with an outcome region
 * of exactly all-zero bytes (pre-outcome-build state).  No authority
 * argument by design: no recovery lease is obtainable over a quarantined
 * descriptor, and the write preserves every descriptor byte (owner, epoch,
 * gen, term, stage, flags, stamp) while filling ONLY the outcome region
 * with a deterministic synthesized FSWIDE LEGACY_INTENT verdict via
 * full-record CAS at normal publish durability.  Returns:
 *   0        - a terminal outcome is now durable; *oc_out (if non-NULL)
 *              holds the CANONICAL record (ours, or a pre-existing/racing
 *              verdict that won — first durable verdict wins either way)
 *   -ENOENT  - no recovery descriptor on the slot
 *   -EPROTO  - descriptor bytes present but unparseable
 *   -EAGAIN  - descriptor live (not QUARANTINED — not backfillable), or
 *              the CAS raced past the retry bound; caller re-arms
 *   -EBADMSG - nonzero outcome bytes that fail validation: corruption;
 *              caller must fail closed, backfill never overwrites
 *   other    - I/O errors pass through (verdict NOT durable)
 */
int mxfs_disklock_recovery_backfill_legacy(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    struct mxfs_recov_outcome *oc_out);
/*
 * (ruling item 2): synchronous read of a slot's canonical durable
 * outcome — the -EPERM-conflict import path and the registration-time scan.
 * No authority required; this is a read of terminal public state.  Returns:
 *   0        - valid outcome copied to *oc_out
 *   -ENOENT  - no recovery descriptor on the slot
 *   -ESTALE  - a recovery object IS present, but the sector belongs to a
 *              DIFFERENT mkfs generation: a pre-mkfs ghost.  It is
 *              outside this filesystem's recovery namespace, so malformed
 *              bytes inside it must not quarantine the new filesystem either
 *              — the generation gate runs BEFORE any crc or semantic test.
 *              -ESTALE may never cause backfill, closure-note insertion,
 *              grant purge, slot retirement/zeroing or quarantine import;
 *              it is observational only.  It is deliberately DISTINCT from
 *              -ENOENT so a caller cannot mistake "wrong generation" for
 *              "nothing there", and so a test can prove the ghost was
 *              recognized rather than accidentally absent.
 *   -EPROTO  - current-generation descriptor present but unparseable (bad
 *              magic/version/crc), or its victim_slot does not name the slot
 *              the sector was read from (the descriptor's identity
 *              binding, checked here so EVERY consumer gets it — the crc
 *              binds the sector header, which travels with a byte-copied
 *              record, so victim_slot is the only slot binding)
 *   -ENODATA - QUARANTINED but outcome region all-zero (intent-path
 *              quarantine: terminal, but carries no domain evidence)
 *   -EBADMSG - QUARANTINED with an outcome present but invalid (bad
 *              magic/version/crc) — consumer must fail closed fswide
 *   -EAGAIN  - descriptor valid but not QUARANTINED (no outcome yet)
 *   other    - I/O errors from the platter read pass through.  An unknown
 *              negative must NEVER be treated as absence.
 */
int mxfs_disklock_recovery_read_outcome(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    struct mxfs_recov_outcome *oc_out);
/* install the protected-mask consumer (see ctx->protected_mask).
 * Fires from the heartbeat monitor thread on every change; the callee must
 * not block. */
void mxfs_disklock_set_protect_cb(struct mxfs_disklock_ctx *ctx,
				  void (*cb)(void *data, uint64_t mask),
				  void *data);
uint64_t mxfs_disklock_protected_mask(const struct mxfs_disklock_ctx *ctx);
/* Synchronous recompute of the protected mask from all 64 sectors (a mount
 * must install protection BEFORE its first CAW write; the monitor's first
 * pass may be up to one heartbeat interval away).  Publishes via the cb. */
int mxfs_disklock_protected_mask_refresh(struct mxfs_disklock_ctx *ctx);
/* LOCAL PROOF — the caller has just made a descriptor at stage >=
 * FENCING durable for `slot` (prover intent) or claimed the execution lease
 * against a certified one (replayer).  Protect the slot NOW rather than one
 * monitor pass (<= 2 s) later: mutate1 on 0.26.2 showed the elected
 * replayer's own CAS clearing a victim EX bit 1.7 s before its monitor
 * published the bit.  O(1), no I/O; safe on the heartbeat thread. */
void mxfs_disklock_protected_mask_add(struct mxfs_disklock_ctx *ctx, int slot);
void mxfs_disklock_set_recov_outcome_cb(struct mxfs_disklock_ctx *ctx,
				    mxfs_disklock_recov_outcome_cb cb,
				    void *data);
int  mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx,
			     uint32_t timeout_ms);
bool mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx);
int  mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx,
				    mxfs_node_id_t node_id);
/* ASYMMETRIC MDS: resolve slot (0-63) -> occupying node_id (0 if empty) */
mxfs_node_id_t mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx,
					      int slot);
/*  is the node occupying heartbeat slot `slot`
 * provably alive (our own slot, or monitored with a current heartbeat)?
 * Advisory cross-thread read of the hb thread's tracker — a stale-by-one-
 * sample answer is fine for its only caller (the CAW wait-timeout
 * liveness extension, which re-asks every poll round). */
bool mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot);
/*
 * — DISK TRUTH about which mount incarnation OCCUPIES a slot.
 *
 * Cache-piercing single-sector read.  Returns true only when the slot's
 * on-disk record is a well-formed ACTIVE record of OUR mkfs generation
 * naming exactly {node, epoch}.
 *
 * READ THE LIMIT BEFORE USING THIS.  A false answer is NOT proof that the
 * incarnation was fenced, and must never be used as a takeover precondition
 * on its own (design-consult ruling, decision 1 — an earlier draft of this
 * comment claimed exactly that and was REFUTED):
 *
 *   - node_id is an IDENTITY, not an I/O capability.  A mount whose slot
 *     was released, overwritten or zeroed can still have an in-flight or
 *     already-accepted SCSI command land afterwards, and a still-running
 *     replay worker writes buffer images that no descriptor CAS guards.
 *   - bad magic, a failed crc or an unread sector are INDETERMINATE state,
 *     never evidence of departure.  Those answer true here (fail closed).
 *   - flags == 0 is only retirement evidence if clean release is ordered
 *     after worker quiescence and LUN I/O drain.  That ordering is NOT
 *     established in this tree yet.
 *
 * What it is good for: refuting a claim of residency, and answering "could
 * that identity still be the legitimate occupant of this slot" — which
 * mxfs_disklock_find_node_slot CANNOT answer, because its in-memory
 * slot_node_id[] fast path keeps resolving a dead node forever.
 *
 * NOTE also that mxfs_disklock_slot_live() indexes LIVENESS BY SLOT, not by
 * incarnation: once a slot is reclaimed by a later incarnation it reads
 * live again, and for our own slot it is unconditionally true.  It is
 * therefore unusable as "is the descriptor's owner incarnation alive".
 *
 * *out_read_ok is set false when the sector could not be read.
 */
bool mxfs_disklock_slot_holds_incarnation(struct mxfs_disklock_ctx *ctx,
					  int slot, mxfs_node_id_t node,
					  mxfs_epoch_t epoch,
					  bool *out_read_ok);
/* enumerated terminal state of a victim's slot (ZERO record, or an
 * ACTIVE successor of another incarnation) from a FRESH read; anything else
 * — including an unread sector — is false.  *why names the observed shape. */
bool mxfs_disklock_slot_terminal_for(struct mxfs_disklock_ctx *ctx, int slot,
				     mxfs_node_id_t node, mxfs_epoch_t epoch,
				     const char **why);
/* v0.5.0 foreign-slice replay election: lowest live slot among survivors
 * (includes local_slot), excluding skip_slot.  -1 if none. */
int  mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx,
				    int skip_slot);
/* Position of this node in that same election: the number of live slots below
 * ours, so 0 is the elected node and N is the N-th stand-in behind it.  -1 if
 * this node holds no slot.  For work that must still happen when the elected
 * node is absent — the others queue by rank instead of each concluding "not
 * me".  Uses the same liveness test as the election, on purpose. */
int  mxfs_disklock_live_slot_rank(struct mxfs_disklock_ctx *ctx);
/* v0.5.0: override the dead-declaration window (ms → HB samples, min 2).
 * 0 restores the compile-time default. */
void mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx,
				       uint32_t timeout_ms);

/* ─── the local authority lease ───────────────────────────────────────────
 *
 * mxfs_disklock_authority_ok() is THE GATE, and it is the one function on
 * this path that any mutating I/O may call: two loads and a compare on the
 * fast path, no lock that withdrawal needs, no allocation, no peer, and above
 * all NO ACCESS TO THE LUN — a node that cannot reach its storage must still
 * be able to contain itself.  It returns false once the deadline has passed,
 * and CLOSES the epoch as it does so, because the caller that discovers the
 * expiry may be the only thread running.
 *
 * It does NOT withdraw the filesystem.  Forcing a shutdown from inside a
 * submission path would need locks that shutdown itself waits on; the close
 * raises auth_withdraw_pending and the periodic pump does the notify.  The
 * gate stays effective whether or not that pump ever runs.
 */
bool mxfs_disklock_authority_ok(struct mxfs_disklock_ctx *ctx);
/* Renew from an anchor captured BEFORE the beat that landed was issued.
 * Refuses (and closes) if the epoch is already closed, or if the anchor is
 * itself past the deadline the previous renewal set — a completion that
 * arrives after authority has lapsed cannot revive it. */
/*
 * 0.89.34: issue ONE heartbeat right now, on the calling thread, and renew the
 * authority lease if it lands.  For a caller that must prove its own
 * coordination I/O converged and its lease is live before it writes anything
 * else — the post-reset authority barrier — and that may itself BE the
 * heartbeat thread, in which case waiting for a beat waits forever.
 * 0 = the beat landed and the lease was renewed.
 */
int mxfs_disklock_beat_now(struct mxfs_disklock_ctx *ctx);

void mxfs_disklock_authority_renew(struct mxfs_disklock_ctx *ctx,
				   uint64_t anchor_ms);
/* Close it for a named reason (a detector that fired, a revocation seen). */
void mxfs_disklock_authority_close(struct mxfs_disklock_ctx *ctx, int reason,
				   const char *why);
/* True while a close has happened and nobody has driven the withdrawal yet;
 * clears the flag, so the caller owes the notify. */
bool mxfs_disklock_authority_take_withdraw(struct mxfs_disklock_ctx *ctx,
					   int *reason_out);

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

/*
 * (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE): scan all
 * heartbeat slots ONCE and report own-generation WITHDRAWN records —
 * voluntary death declarations left by a force-shutdown FS whose
 * journal slice is dirty and unreplayed.  No wait window: unlike an
 * ACTIVE record, a WITHDRAWN stamp is definitive (its writer declared
 * its own death), so there is no liveness to disprove.  out_node[] /
 * out_epoch[] (each indexed by slot, sized MXFS_DISKLOCK_HB_SLOTS)
 * receive the victim identity the stamp itself names — the record is
 * the victim's own final write, so no baseline tracking is needed.
 */
int  mxfs_disklock_get_withdrawn_slots(struct mxfs_disklock_ctx *ctx,
					int skip_slot,
					uint64_t *out_mask,
					mxfs_node_id_t *out_node,
					mxfs_epoch_t *out_epoch);

/*
 * (admission-barrier ruling, shape B): scan the heartbeat
 * slots ONCE and report every slice the platter says REQUIRES RECOVERY —
 * a WITHDRAWN stamp (voluntary death, fence pipeline not yet started) or
 * a recovery descriptor below GRANTS_RELEASED (fence/replay underway or
 * abandoned).  There is no gap between the two shapes: fence_intent
 * replaces the WITHDRAWN flags and lays the FENCING descriptor in one
 * durable CAS, so at every instant a dirty slice is visible under exactly
 * one of them.  The in-memory recovery_pending[] marker is deliberately
 * NOT consulted — it records only deaths THIS node's monitor processed.
 * Fail-closed: an unreadable sector or an unvalidatable descriptor sets
 * the slot's bit.  out_node[]/out_epoch[] (optional, indexed by slot,
 * sized MXFS_DISKLOCK_HB_SLOTS) receive the victim identity where the
 * evidence names one; a fail-closed bit leaves them 0.
 * (design-consult STOP-SHIP blocker 2): a RETIRE_PENDING stamp — a clean
 * release whose PR key retirement was never proven — is a THIRD shape
 * that requires-recovery: the departed initiator may still hold a
 * write-capable registration, so the mount must not go writable beside
 * it.  Its bit is set (identity filled) and ALSO reported in
 * out_retire_mask (optional) so the caller can settle it: EMPTY once the
 * key is proven absent, or WITHDRAWN + fence + replay + purge.
 */
int  mxfs_disklock_get_recovery_pending_slots(struct mxfs_disklock_ctx *ctx,
					      int skip_slot,
					      uint64_t *out_mask,
					      mxfs_node_id_t *out_node,
					      mxfs_epoch_t *out_epoch,
					      uint64_t *out_retire_mask);

/*
 * WHAT THE EXCLUSIVE-WRITE GATE STILL OWES, READ FROM THE PLATTER.
 *
 * The sole-survivor gate (a single-holder Write Exclusive reservation) is the
 * exclusion every recovery certified with fence_kind EXCLUSIVE_WRITE_GATE rests
 * on, and only the node whose key holds it can convert it back to WE-AR.  An
 * in-memory set of the recoveries this node has VALIDATED cannot answer
 * whether the gate may be lifted, because an obligation that exists durably
 * but has not been claimed yet — this node's own certificate written seconds
 * ago, or one a dead peer wrote before it died — registers nothing there.
 * The platter is the authority on what is owed, so the restore asks it.
 *
 * Every heartbeat slot is read.  A slot contributes to *out_owed when it
 * carries a validated descriptor whose certificate kind is
 * EXCLUSIVE_WRITE_GATE, whose stage is below GRANTS_RELEASED (completion) and
 * which is not QUARANTINED (terminal refusal).  Unowned, claimed, taken over,
 * certified by another incarnation, or aged: none of those exempt it.  A
 * certificate is written at SNAPSHOTTING, so a gate-kind descriptor at NONE or
 * FENCING contradicts the format; it is reported in *out_malformed AND counted
 * as owed.  A sector that cannot be read, or a guard record whose descriptor
 * does not validate, is reported in *out_unreadable: the caller must treat it
 * as owed, because "cannot tell" is never "nothing owed".  Records of a
 * foreign mkfs generation are skipped exactly as the admission sweep skips them.
 *
 * A QUARANTINED gate-kind descriptor owes nothing (its refused images are
 * never applied and the slot is frozen until operator action), but the gate
 * was installed for it because its victim's key was already absent from the
 * target and "absent" proves nothing about a revived incarnation that
 * re-registers.  So every such descriptor is reported in *out_terminal with
 * its certificate's victim key in out_terminal_key[slot] (an array of
 * MXFS_DISKLOCK_HB_SLOTS, may be NULL): the restore re-checks that the key is
 * still absent before it converts the reservation back to WE-AR
 * (D-SOLE-SURVIVOR-GATE-NEVER-RESTORED-AFTER-A-TERMINAL-REFUSAL, 0.87.12).
 *
 * Returns 0, or -errno only when no sector could be examined at all.
 */
int  mxfs_disklock_gate_owed_sweep(struct mxfs_disklock_ctx *ctx,
				   uint64_t *out_owed,
				   uint64_t *out_unreadable,
				   uint64_t *out_malformed,
				   uint64_t *out_terminal,
				   uint64_t *out_terminal_key);

/*
 * continuous, cancellable death confirmation for a set of slots.
 * Unlike get_stale_slot_mask (single window, re-baselined per call, no
 * identity tracking) this holds ONE baseline across `samples` heartbeat
 * intervals and re-checks node id + epoch on every sample, so it is safe
 * to fence on.  expect_node[] (optional, indexed by slot) rejects a slot
 * that already changed hands; *cancel (optional) is polled between samples
 * so an unmount can abandon the wait.  Every ambiguity — read error, slot
 * gone inactive, foreign fs_gen — drops the candidate rather than
 * confirming it.  Sleeps samples * MXFS_DISKLOCK_HB_INTERVAL_MS worst case;
 * returns as soon as every candidate is disproved.
 *
 * out_epoch[] (optional, indexed by slot, sized MXFS_DISKLOCK_HB_SLOTS)
 * receives the BASELINE incarnation of every confirmed slot — the exact
 * incarnation held frozen across the whole window, and therefore the only
 * correct victim to name when marking the recovery pending.
 */
int  mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx,
					uint64_t candidate_mask,
					const mxfs_node_id_t *expect_node,
					uint32_t samples,
					const volatile int *cancel,
					uint64_t *out_confirmed,
					mxfs_epoch_t *out_epoch);

/*
 * (docs/whole-cluster-restart.md §6.2): whole-cluster bootstrap owner
 * support.  set_owner_bootstrap marks every descriptor this ctx writes with
 * MXFS_RECOV_F_OWNER_BOOTSTRAP / MXFS_RECOV_NO_SLOT (call before the first
 * fence intent; clear it before the ACTIVE claim).  predraw_epoch pins the
 * ctx's CURRENT incarnation as the one the later mxfs_disklock_claim_slot()
 * must publish, so the provisional identity and the member are one epoch.
 */
void mxfs_disklock_set_owner_bootstrap(struct mxfs_disklock_ctx *ctx, bool on);
/* fs_gen fold of a volume uuid (identical to set_fs_identity's). */
uint32_t mxfs_disklock_fs_gen_of(const uint8_t *fs_uuid);
/*
 * (§6.5 shape B): the bootstrap owner ADOPTS certified victim slot
 * `slot`: CAW from the exact guarded image (a RECOVERY_GUARD whose
 * descriptor names THIS ctx as owner at stage >= FENCED, with `expect_desc`
 * byte-equal to the escrowed descriptor) to our ACTIVE record carrying
 * MXFS_HB_FEAT_BOOTSTRAP_PENDING, under the pre-drawn epoch, with
 * slice_adopted = false (FULL replay of the slice as our own log).  Returns
 * the slot, -ESTALE if the sector no longer holds that exact image (nothing
 * written), -EAGAIN on a lost CAW.  *old_crc receives crc32c of the consumed
 * sector (for the escrow's audit trail).
 */
int mxfs_disklock_claim_victim_slot(struct mxfs_disklock_ctx *ctx, int slot,
				    const struct mxfs_recov_desc *expect_desc,
				    uint32_t *old_crc);
/* Drop the PENDING advertisement; the next own-record write carries it. */
void mxfs_disklock_clear_bootstrap_pending(struct mxfs_disklock_ctx *ctx);
/* Does the record in `slot` advertise BOOTSTRAP_PENDING? (survivor scan:
 * successor preference for a predecessor term's adopted K) */
bool mxfs_hb_feature_bootstrap_pending(const struct mxfs_disklock_heartbeat *hb);
void mxfs_disklock_predraw_epoch(struct mxfs_disklock_ctx *ctx);
/*
 * (§6.7 same-boot RESUME): adopt the incarnation the bootstrap
 * record names as this ctx's CURRENT epoch and pre-draw it, before any
 * record is written — the descriptors and certificates of the resumed term
 * name {node, epoch}, and a fresh draw would make this mount a stranger to
 * its own evidence.  Refused (-EBUSY) once a slot is held.
 */
int mxfs_disklock_adopt_epoch(struct mxfs_disklock_ctx *ctx, mxfs_epoch_t epoch);
/*
 * (§6.7): re-take OUR OWN adopted K record after a same-boot unwind:
 * the sector must hold an ACTIVE record of {local_node, ctx->epoch} under our
 * fs generation that advertises MXFS_HB_FEAT_BOOTSTRAP_PENDING.  Nothing is
 * written; the read image becomes the CAW source, slice_adopted = false
 * (FULL replay of our own log again), bootstrap_pending stays advertised.
 * Returns the slot; -ESTALE if the sector is anything else.
 */
int mxfs_disklock_reclaim_own_slot(struct mxfs_disklock_ctx *ctx, int slot);
/* Read one heartbeat sector (validated size; FUA/prio read). */
int mxfs_disklock_read_record(struct mxfs_disklock_ctx *ctx, int slot,
			      struct mxfs_disklock_heartbeat *out);

#endif /* MXFS_LIBMXFS_DISKLOCK_H */
