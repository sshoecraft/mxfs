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
/*
 * sess43: recovery GUARD stamp.  An UNCLAIMED slot's AGI unlinked bucket can
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
/* How often a sweeping holder re-stamps its guard.  Abandonment is detected
 * by ABSENCE OF CHANGE across ~3 of these intervals, never by comparing a
 * record's timestamp against the reader's clock: mxfs_pal_time_ms() is
 * ktime_get_boottime (per-node UPTIME), so cross-node clock arithmetic on
 * these records is meaningless (sess43). */
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
 * sess64 — the DURABLE RECOVERY DESCRIPTOR (GPT RULE-5 ruling, sess63).
 *
 * The problem it solves.  Everything that tracked "this dead node's slice is
 * being recovered" lived in ONE PLACE: the in-memory recovery_pending[] array
 * of each survivor.  Nothing on disk said so.  Consequences, all proven by
 * line-reading in sess63:
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
 *   6. recovery_gen IS THE TRANSACTION, owner_term IS THE AUTHORITY (sess67,
 *      GPT ruling item 7).  recovery_gen names WHICH recovery this is and is
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
 * Abandonment is detected the same way the sess43 sweep guard detects it: by
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
 * sess75: v2 adds the FENCE CERTIFICATE and the FENCING intent stage, and
 * renumbers the stage ladder to make room for the intent below FENCED.
 * Renumbering is safe ONLY because v1 and v2 can never coexist in a cluster:
 * MXFS_PROTO_GEN moved 1 -> 2 in the same change, so the sess42 C7 gate
 * refuses the mount (superblock) and fences a live mismatched incarnation
 * (heartbeat feature block).  Do NOT change the descriptor version without
 * bumping MXFS_PROTO_GEN — the sess74 ruling refuted the idea that
 * per-slot version-mismatch is fail-closed on its own: today's replayer
 * REPLAYS FIRST and only consults the descriptor afterwards, so a v1 node
 * would replay a v2-fenced slice on the old ungated path.
 */
#define MXFS_RECOV_DESC_VERSION     2

/*
 * Milestones.  Monotonic: a stage may only ever advance.
 *
 * FENCING is an INTENT, not a fence (sess74 ruling, rule-1 amendment).  It is
 * written BEFORE the PREEMPT AND ABORT is issued so that the attempt is
 * serialised cluster-wide, the exact victim key and pre-command observations
 * are preserved, and a crash between "P&A completed at the target" and "the
 * certificate is durable" is distinguishable from "fencing never started".
 * It authorises NOTHING: no replay, no purge, no manifest repair or reuse, no
 * grants release, no broadcast, no zeroing.  Only a CERTIFIED FENCED
 * descriptor does that.
 */
#define MXFS_RECOV_STAGE_NONE               0
#define MXFS_RECOV_STAGE_FENCING            1
#define MXFS_RECOV_STAGE_FENCED             2
#define MXFS_RECOV_STAGE_IMAGES_REPLAYED    3
#define MXFS_RECOV_STAGE_OBLIGATIONS_DONE   4
#define MXFS_RECOV_STAGE_GRANTS_RELEASED    5
#define MXFS_RECOV_STAGE_MAX                MXFS_RECOV_STAGE_GRANTS_RELEASED

/*
 * UNOWNED — a distinct state, never "an abandoned owner" (sess74 ruling).
 *
 * The node that PROVES exclusion and the node that REPLAYS are structurally
 * different: exactly one node's PREEMPT AND ABORT wins the race, every other
 * survivor gets RESERVATION CONFLICT, and the replayer is chosen by
 * lowest_live_slot — measured on the rig at 1 winner / 30 losers (sess73).
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
 * intent/done pair whose admission verdicts are contradictory (GPT: "admitted
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
 * THE FENCE CERTIFICATE (sess75, v2).
 *
 * Fields 76..115 are the certificate.  It is COMPLETE at FENCED and IMMUTABLE
 * from then on: claim, advance, refresh and takeover all carry it through byte
 * for byte and revalidate it.  A replay gate does not ask "is there a
 * descriptor and is its fence_kind in a set"; it revalidates the whole
 * certificate against the sector's own identity (sess74 ruling, Q4).
 *
 * At FENCING the same bytes hold the ATTEMPT state — who is trying, on which
 * attempt term, against which key, since when.  That is deliberate and cannot
 * be mistaken for a certificate: fence_kind stays MXFS_FENCE_KIND_NONE and
 * fence_resv_type stays 0 until certify writes them, and every gate demands
 * BOTH stage >= FENCED AND mxfs_fence_kind_proves_exclusion(fence_kind).  An
 * intent therefore reads as "not certified" on every path.
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
 * far longer than the refresh cadence (sess67, GPT ruling item 4).  The old
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
 * The FENCING-ATTEMPT authorization tuple (sess74 ruling: keep the fencing
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

/* The descriptor plus the rest of the evict-ring footprint it overlays. */
struct mxfs_recov_body {
    struct mxfs_recov_desc  desc;
    uint8_t                 pad[296];
};

/*
 * sess42 C7 version gate — heartbeat-embedded feature declaration.
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
 *     instead of fencing incumbents (asymmetric policy, GPT ruling).
 */
#define MXFS_HB_FEAT_MAGIC      0x47465846u  /* "FXFG" LE → reads MXFG-ish */

struct mxfs_hb_feature {
    uint32_t                magic;      /* MXFS_HB_FEAT_MAGIC */
    uint16_t                proto_gen;  /* must equal MXFS_PROTO_GEN */
    uint16_t                feat_flags; /* compatible advertisements; 0 */
    uint32_t                crc32c;     /* over {magic,proto_gen,feat_flags,
                                         * fs_gen,node_id,epoch} — see
                                         * mxfs_hb_feature_crc() */
};

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
    /*
     * sess64: the 416-byte body is interpreted BY flags.
     *   flags == ACTIVE           → evict (sess55 inode-eviction hint ring)
     *   flags == RECOVERY_GUARD   → recov (sess64 durable recovery descriptor)
     * The ring producer writes only into its OWN active record and the ring
     * consumer sits behind a flags == ACTIVE test, so the two never alias in
     * a live path.  Both members carry their own magic so a record written by
     * the other interpretation (or by a pre-sess64 node, which zeroed these
     * bytes in a guard) is rejected rather than misread.
     */
    union {
        struct mxfs_evict_ring  evict;      /* sess55; net2 step 5: 416B (25 entries) */
        struct mxfs_recov_body  recov;      /* sess64: 80B descriptor + pad */
    };
    struct mxfs_mepoch_rec  mepoch;         /* net2 step 5: 44B, §7.C authority */
    struct mxfs_hb_feature  feat;           /* sess42 C7: 12B version gate */
};

#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_HB() \
    do { \
        BUILD_BUG_ON(sizeof(struct mxfs_disklock_heartbeat) != \
                     MXFS_DISKLOCK_RECORD_SIZE); \
        BUILD_BUG_ON(sizeof(struct mxfs_recov_desc) != 120); \
        BUILD_BUG_ON(sizeof(struct mxfs_recov_body) != \
                     sizeof(struct mxfs_evict_ring)); \
        BUILD_BUG_ON(offsetof(struct mxfs_disklock_heartbeat, mepoch) != 456); \
    } while (0)
#else
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == MXFS_DISKLOCK_RECORD_SIZE,
               "mxfs_disklock_heartbeat must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_evict_ring) == 416,
               "mxfs_evict_ring must be 25 entries (net2 step 5 carve)");
_Static_assert(sizeof(struct mxfs_mepoch_rec) == 44,
               "mxfs_mepoch_rec is 44 bytes on disk (§7.C)");
_Static_assert(sizeof(struct mxfs_hb_feature) == 12,
               "mxfs_hb_feature is the 12-byte HB tail (sess42 C7)");
#endif

/*
 * sess64: these run in BOTH builds, deliberately.  MXFS_BUILD_CHECK_HB() above
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
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == MXFS_DISKLOCK_RECORD_SIZE,
               "sess64 union must not change the 512-byte heartbeat record");
_Static_assert(offsetof(struct mxfs_disklock_heartbeat, mepoch) == 456,
               "sess64 union must not move the mepoch/feat tail");

struct mxfs_disklock_node_track {
    uint64_t        last_timestamp;
    mxfs_epoch_t    last_epoch;
    int             changed_samples;
    int             equal_samples;
    bool            live;
    uint32_t        last_evict_seq;   /* sess55: highest evict head_seq consumed from this peer */
    bool            evict_seen;       /* sess55: last_evict_seq has been initialised */
};

/*
 * sess86: the death callback carries the VICTIM INCARNATION, it does not let
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
 * sess131: self-fence callback.  Fired (once) by the heartbeat thread when
 * this mount must stop writing immediately.  The body (v5_mount → XFS glue)
 * must force-shutdown the filesystem; the heartbeat thread stops writing
 * before calling so neither a new cluster generation nor an in-flight
 * recovery is polluted by ghost heartbeats.
 *
 * `reason` is an enum mxfs_self_fence_reason.  sess79: it exists because the
 * two disklock detectors — a re-mkfs'd device (FS_IDENTITY) and a survivor
 * taking over our heartbeat slot (SLOT_TAKEOVER) — are opposite diagnoses
 * (your LUN was destroyed vs your LUN is fine and you were fenced), and the
 * callback used to report both as the former.
 */
typedef void (*mxfs_disklock_fence_cb)(void *data, int reason);

/*
 * sess55: per-freed-inode eviction callback.  The disklock HB consumer reads a
 * peer's evict ring and invokes this for each {ino, gen} the peer freed since we
 * last scanned.  The body (in the XFS layer) does the radix lookup +
 * XFS_ISTALE_CAW + background eviction — disklock.c never touches XFS directly.
 */
typedef void (*mxfs_disklock_evict_cb)(void *data, uint64_t ino, uint32_t gen,
                                       uint32_t type);

/*
 * sess42 C7: protocol-incompatible LIVE member detected by the monitor
 * (feature block missing/mismatched/corrupt on a progressing current-fs_gen
 * record, confirmed by a second priority re-read of the same incarnation).
 * The v5 layer must SCSI-PR fence the incarnation so its next write fails.
 * Fired at most once per (slot, node, epoch) incarnation.
 * state: 1=LEGACY (zero block) 2=MISMATCH (different proto_gen) 3=CORRUPT.
 */
typedef void (*mxfs_disklock_vergate_cb)(void *data, int slot,
                                         mxfs_node_id_t node_id,
                                         mxfs_epoch_t epoch, int state);

/* Disk lock subsystem context */
struct mxfs_disklock_ctx {
    mxfs_bdev_t             *dev;
    uint64_t                base_offset;    /* byte offset on device */
    mxfs_node_id_t          local_node;
    int                     local_slot;     /* unique HB slot 0-63, -1 if unclaimed */
    /* sess32 (D-FOREIGN-REPLAY-UNGATED-IMAGES): true when the slot was won by
     * the pass-2 fresh scan — our previous incarnation's ACTIVE stamp was
     * absent/zeroed, so any dirt in the log slice (slot %% node_count) belongs
     * to an already-recovered or foreign incarnation and its images must NOT
     * be re-applied by our mount recovery (cross-slice LSNs incomparable).
     * false = pass-1 reclaim of our own surviving stamp: nobody replayed us,
     * full own-slice recovery is safe and REQUIRED. */
    bool                    slice_adopted;
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

    /* sess43 recovery GUARD (see MXFS_DISKLOCK_FLAG_RECOVERY_GUARD).  One
     * guard at a time per node; guard_img is the exact on-disk image we
     * wrote — the CAS compare source for refresh and unguard. */
    int                              guard_slot;     /* -1 = none held */
    struct mxfs_disklock_heartbeat   guard_img;

    /*
     * sess78 (D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD) — the exact image we
     * last wrote into our OWN heartbeat slot, and the compare source for
     * every subsequent write to it.
     *
     * Before sess78 every own-slot write was BLIND (memset → fill → write).
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

    /*
     * sess42 C7 version gate state.  vergate_cb fences a live incompatible
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
/*
 * sess86: the victim incarnation is an ARGUMENT, never a read-back.  See the
 * mxfs_disklock_expire_cb comment — mark_recovery_pending used to copy
 * node_track[slot].last_epoch, which the epoch-change arm had already rebased
 * onto the successor.  Pass 0 only when the caller truly never observed the
 * victim's incarnation.
 */
void mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx,
                                         int slot, mxfs_node_id_t node,
                                         mxfs_epoch_t victim_epoch);
bool mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot);
/*
 * COMPARE-and-clear (sess86).  A pending marker is a promise about ONE
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
 * There is deliberately NO "what incarnation is in slot N" accessor (sess86).
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
 * sess65 — DURABLE RECOVERY DESCRIPTOR ops (see the big comment above
 * MXFS_RECOV_DESC_MAGIC for the state machine and the five rules).
 *
 * All five re-read the victim's heartbeat sector cache-piercingly, act by
 * compare-and-write from the exact observed image, and make the result
 * durable before returning.  A failed CAS is always reported, never retried
 * blindly: the caller must re-read and re-decide (GPT: "refresh vs stage-CAS
 * vs takeover vs final-zero must be serialized with mandatory reread after
 * CAS failure").
 *
 * recovery_begin   ACTIVE/WITHDRAWN → GUARD{FENCED}, victim identity kept in
 *                  the record header, recovery owner recorded in the
 *                  descriptor.  MUST run — and be durable — BEFORE the first
 *                  CAW purge.  Idempotent when we already own the descriptor.
 *                  `victim_epoch` NAMES THE INCARNATION BEING RECOVERED and is
 *                  enforced (sess86), not merely logged: a sector that has
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
 * MXFS_RECOVERY_SUPERSEDED (sess86) — the recovery we were asked to publish is
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
int mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot,
                                    struct mxfs_recov_auth *out_auth);

/*
 * ── sess75: THE FENCE-EVIDENCE CHANNEL ──────────────────────────────────
 *
 * Measured on the rig (sess73): a peer death produces exactly ONE node whose
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
 *                  (sess74 blocker 1).  Serialises fence attempts, records the
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
 *                  is NOT evidence: sess74 ruled the inference "intent exists +
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
 *   replay_authorized  THE CENTRAL GATE (sess74 blocker 4).  Full revalidation
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
int mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot,
                                         const struct mxfs_recov_fence_auth *auth,
                                         uint16_t fence_kind,
                                         uint16_t fence_resv_type,
                                         uint64_t fence_victim_key,
                                         uint32_t fence_pr_gen);
/*
 * Take over an ABANDONED fencing-attempt lease.  The ONLY case this exists
 * for: the prover died with the intent durable.  It authorises issuing a NEW
 * PREEMPT AND ABORT and certifying THAT result — never the dead prover's
 * (sess74 ruled that inference unsound).  If the victim key is already gone,
 * no exclusion can be proved and the slice stays unreplayable; that is the
 * correct outcome, not a bug to optimise away.
 *
 * Same precondition as recovery_takeover (rule 5): the caller must ALREADY
 * have confirmed the prover's session dead.  Blocks MXFS_RECOV_ABANDON_MS
 * inside the call — never run it on the heartbeat monitor thread.
 *   0        the attempt lease is ours; retry the P&A
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
int mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx,
                                             int slot,
                                             mxfs_node_id_t victim,
                                             mxfs_epoch_t victim_epoch,
                                             const struct mxfs_recov_auth *auth,
                                             const char *site);

/*
 * sess93 — READ-ONLY classification of a victim slot.
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

/*
 * sess94: this mount's complete on-disk identity — {slot, node_id,
 * incarnation} — as one call.  Returns false, with all three outputs
 * zeroed, unless ALL of them are established: the slot is claimed
 * (local_slot >= 0), the node_id is nonzero, and the incarnation is valid.
 *
 * The triple is what binds a durable record to a specific mount instance:
 * a slot alone is reused across mounts (sess89 measured nodes migrating
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

/* sess43 recovery GUARD ops (unclaimed-bucket sweep exclusion).
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
 * sess42 C7 version gate.
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
int  mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx,
                             uint32_t timeout_ms);
bool mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx);
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
/*
 * sess68 — DISK TRUTH about which mount incarnation OCCUPIES a slot.
 *
 * Cache-piercing single-sector read.  Returns true only when the slot's
 * on-disk record is a well-formed ACTIVE record of OUR mkfs generation
 * naming exactly {node, epoch}.
 *
 * READ THE LIMIT BEFORE USING THIS.  A false answer is NOT proof that the
 * incarnation was fenced, and must never be used as a takeover precondition
 * on its own (sess68 GPT ruling, decision 1 — an earlier draft of this
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

/*
 * sess54: continuous, cancellable death confirmation for a set of slots.
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
 * correct victim to name when marking the recovery pending (sess86).
 */
int  mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx,
                                        uint64_t candidate_mask,
                                        const mxfs_node_id_t *expect_node,
                                        uint32_t samples,
                                        const volatile int *cancel,
                                        uint64_t *out_confirmed,
                                        mxfs_epoch_t *out_epoch);

#endif /* MXFS_LIBMXFS_DISKLOCK_H */
