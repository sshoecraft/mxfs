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
#include "scsipr.h"     /* sess75: the fence certificate stores enum
                         * mxfs_fence_kind and is validated with
                         * mxfs_fence_kind_proves_exclusion() — the ONE
                         * predicate every replay gate must use */
#include "../include/mxfs/mxfs_super.h"

/*
 * Instr gate for diagnostic probes — mirrors caw_instr_on() in dlm_caw.c.
 * mxfs_instr_enabled lives in the xfs overlay (xfs_mxfs_dlm.c) and is
 * linked into mxfs.ko alongside this file; user-mode dlm builds (no
 * overlay) compile the gate out.  Pure logging, no side effects.
 */
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/moduleparam.h>
extern int mxfs_instr_enabled;
#define dl_instr_on() (unlikely(mxfs_instr_enabled))

/*
 * sess374 (sess363 ruling, Hazards section 7): deterministic fault injection
 * for the CLOSURE GATE.  The ruling requires POSITIVE observation of each
 * refusal path, and none of them occur naturally on a healthy rig — a gate
 * that never fails proves only that it was never asked.  Each knob is a
 * CONSUMABLE count: writing N arms the next N hits of its site, each hit
 * decrements, 0 disarms.  TEST ONLY — all default 0 and stay 0 in production.
 */
static int mxfs_dl_inject_closure_read;
module_param_named(dl_inject_closure_read, mxfs_dl_inject_closure_read,
                   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_read,
                 "TEST ONLY: fail the next N closure-gate heartbeat sector "
                 "reads with -EIO (consumable; 0=off)");

static int mxfs_dl_inject_closure_crc;
module_param_named(dl_inject_closure_crc, mxfs_dl_inject_closure_crc,
                   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_crc,
                 "TEST ONLY: make the next N closure-gate predicate "
                 "evaluations read the descriptor as unparseable (-EPROTO), "
                 "as a torn/miscrc'd record would (consumable; 0=off)");

static int mxfs_dl_inject_closure_mask;
module_param_named(dl_inject_closure_mask, mxfs_dl_inject_closure_mask,
                   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_mask,
                 "TEST ONLY: perturb the ag_mask the next N closure-gate "
                 "REVALIDATIONS read, so the expected-vs-platter compare "
                 "fails and the purge must stop -ESTALE (consumable; 0=off)");

/* Consume one armed injection: true and decrement while the knob is >0. */
static inline bool dl_inject_take(int *knob)
{
    if (*knob > 0) {
        (*knob)--;
        return true;
    }
    return false;
}
#else
#define dl_instr_on() (0)
#define dl_inject_take(k) (false)
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

static bool hb_guard_abandoned(struct mxfs_disklock_ctx *ctx, int slot,
                               const struct mxfs_disklock_heartbeat *first);

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
 * ── MOUNT INCARNATION (D-MOUNT-INCARNATION-CONSTANT-ZERO) ───────────────────
 *
 * `epoch` names ONE published slot tenancy.  It is an OPAQUE, nonzero,
 * cryptographically random 64-bit identity compared for EQUALITY ONLY — never
 * ordered.  A larger value does not mean "newer": a resurrected older record
 * must fail closed, not be reasoned about numerically.
 *
 * Lifecycle (GPT sess83 RULE-5 ruling):
 *   - drawn BEFORE the first claim publication, so the first durable ACTIVE
 *     record, its feature CRC and every descriptor carry the same value;
 *   - immutable for the life of that published tenancy — transient rewrites
 *     of a still-owned record reuse it;
 *   - losing the slot TERMINATES the incarnation; that value may never
 *     establish a new tenancy, so every claim draws a fresh one.
 *
 * ZERO IS NEVER A WILDCARD.  Under the MXFS_PROTO_GEN 3 gate it has exactly
 * one meaning — "no valid published incarnation" (vacant / purged /
 * uninitialised / legacy).  Every authoritative recovery transition fails
 * closed on zero or on mismatch; only non-authoritative paths (identifying a
 * sector as empty, diagnostic decode, quarantining or purging a legacy record
 * after independent proof) may accept it.
 */
#define MXFS_INCARNATION_DRAWS  16

static mxfs_epoch_t hb_draw_incarnation(void)
{
    mxfs_epoch_t e = 0;
    int i;

    /*
     * mxfs_pal_get_random_bytes() returns void and cannot report failure.
     * Its ONLY failure mode is the user-space backend zero-filling the buffer
     * when /dev/urandom will not open, so a bounded draw-until-nonzero loop
     * IS the fail-closed detector for it: 16 consecutive all-zero draws from
     * a working RNG has probability 2^-1024.  Never fall back to a clock —
     * a timestamp has too little collision resistance exactly in the cases an
     * incarnation exists to survive (VM snapshot restore, stuck RTC, rapid
     * reboot, pre-NTP boot).
     */
    for (i = 0; i < MXFS_INCARNATION_DRAWS; i++) {
        mxfs_pal_get_random_bytes(&e, sizeof(e));
        if (e != 0)
            return e;
    }
    return 0;                   /* caller MUST fail the mount/claim closed */
}

/* A published incarnation is valid iff nonzero. */
static inline bool inc_valid(mxfs_epoch_t e)
{
    return e != 0;
}

/*
 * The REQUIRED-match test.  Both sides must name a real published incarnation
 * AND name the same one.  Zero on either side is a REFUSAL, never a
 * match-anything.  Use this everywhere the old `epoch == 0 || a == b` and
 * `epoch && a == b` idioms appeared.
 */
static inline bool inc_eq(mxfs_epoch_t a, mxfs_epoch_t b)
{
    return a != 0 && b != 0 && a == b;
}

/*
 * sess91 — the OTHER equality, deliberately named apart from inc_eq().
 *
 * inc_eq() is the CROSS-SOURCE incarnation proof: "these two independently
 * obtained values name the same KNOWN incarnation".  Zero must fail there:
 * zero is never a wildcard, and two unknowns do not identify each other.
 *
 * recov_tok_eq() is the DESCRIPTOR-TOKEN identity: "this token carries exactly
 * the value that was copied out of THIS descriptor".  Zero equals zero there,
 * because it proves only that both encoded the same UNKNOWN — the binding
 * comes from the rest of the descriptor identity (slot, victim node, recovery
 * generation, term, and the owner check that precedes it), never from this
 * field alone.
 *
 * Using inc_eq() for the second meaning made any descriptor whose victim_epoch
 * is legitimately 0 un-advanceable BY ITS OWN OWNER — and recovery_begin()
 * creates exactly that on the P237-RECOV-INC-UNOBSERVED arm, for a caller that
 * never observed the victim's incarnation.  inc_eq(0,0) is false, so the owner
 * failed its own authentication, mxfs_disklock_recovery_advance() returned
 * -EBUSY for ever, the milestone ladder stopped at FENCED, the freeze gate
 * refused to zero the sector, and the dead node's grants stayed frozen with a
 * silent unbounded retry behind them.  MEASURED on the 32-node rig, sess91:
 * slot 4 held RECOVERY_GUARD/stage=2 for 12 minutes and 11 retries while
 * P234-RECOV-NOTOURS printed two IDENTICAL owner tuples as the "evidence" of a
 * takeover that never happened.
 */
static inline bool recov_tok_eq(uint64_t a, uint64_t b)
{
    return a == b;
}

/*
 * sess42 C7 version gate — HB feature block (see disklock.h).
 *
 * The crc binds the declaration to the claimant INCARNATION: it covers the
 * feature fields AND the record's identity (fs_gen, node_id, epoch), all
 * serialized little-endian into a packed scratch, so a feature payload
 * spliced next to a different incarnation's header never validates.
 */
static uint32_t hb_feature_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
                               mxfs_epoch_t epoch,
                               const struct mxfs_hb_feature *ft)
{
    struct {
        uint32_t magic;
        uint16_t proto_gen;
        uint16_t feat_flags;
        uint32_t fs_gen;
        uint32_t node_id;
        uint64_t epoch;
    } __attribute__((packed)) b;

    b.magic      = ft->magic;
    b.proto_gen  = ft->proto_gen;
    b.feat_flags = ft->feat_flags;
    b.fs_gen     = fs_gen;
    b.node_id    = (uint32_t)node_id;
    b.epoch      = (uint64_t)epoch;
    return mxfs_pal_crc32c(~0U, &b, sizeof(b));
}

/* Stamp the outgoing record's feature block (identity fields must be set).
 * sess187: takes the ctx so ctx->snlocal is carried in feat_flags on EVERY
 * record this incarnation writes — the marker is write-time provenance and
 * must be uniform across the tenure (sess184 ruling item 1). */
static void hb_feature_fill(const struct mxfs_disklock_ctx *ctx,
                            struct mxfs_disklock_heartbeat *hb)
{
    hb->feat.magic      = MXFS_HB_FEAT_MAGIC;
    hb->feat.proto_gen  = (uint16_t)MXFS_PROTO_GEN;
    hb->feat.feat_flags = ctx->snlocal ? MXFS_HB_FEAT_SNLOCAL : 0;
    hb->feat.crc32c     = hb_feature_crc(hb->fs_gen, hb->node_id,
                                         hb->epoch, &hb->feat);
}

#define MXFS_HBFEAT_OK        0
#define MXFS_HBFEAT_LEGACY    1   /* pre-gate writer: all-zero tail */
#define MXFS_HBFEAT_MISMATCH  2   /* gate-aware, different proto_gen */
#define MXFS_HBFEAT_CORRUPT   3   /* bad magic or crc */

static int hb_feature_state(const struct mxfs_disklock_heartbeat *hb)
{
    if (hb->feat.magic == 0 && hb->feat.proto_gen == 0 &&
        hb->feat.feat_flags == 0 && hb->feat.crc32c == 0)
        return MXFS_HBFEAT_LEGACY;
    if (hb->feat.magic != MXFS_HB_FEAT_MAGIC)
        return MXFS_HBFEAT_CORRUPT;
    if (hb->feat.crc32c != hb_feature_crc(hb->fs_gen, hb->node_id,
                                          hb->epoch, &hb->feat))
        return MXFS_HBFEAT_CORRUPT;
    if (hb->feat.proto_gen != (uint16_t)MXFS_PROTO_GEN)
        return MXFS_HBFEAT_MISMATCH;
    return MXFS_HBFEAT_OK;
}

/*
 * sess187: did this victim record durably classify itself single-node-local?
 * Fail-closed: only a VALID feature block (crc binds it to the record's own
 * identity triple) may assert the marker — LEGACY, MISMATCH and CORRUPT
 * tails all read as "not snlocal", so a torn or foreign-generation record
 * can never unlock the untagged-replay path.
 */
static bool hb_victim_snlocal(const struct mxfs_disklock_heartbeat *hb)
{
    return hb_feature_state(hb) == MXFS_HBFEAT_OK &&
           (hb->feat.feat_flags & MXFS_HB_FEAT_SNLOCAL);
}

/*
 * ── sess346 (#92): CLAIM PROVENANCE — parsing/derivation side ────────────
 *
 * See the block comment above struct mxfs_hb_provenance in disklock.h for
 * the protocol.  The crc mirrors hb_feature_crc: it covers the provenance
 * fields AND the record's identity triple, serialized little-endian into a
 * packed scratch, so a provenance block spliced next to a different
 * incarnation's header never validates.
 */
static uint32_t hb_prov_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
                            mxfs_epoch_t epoch,
                            const struct mxfs_hb_provenance *pv)
{
    struct {
        uint32_t magic;
        uint32_t prev_node;
        uint64_t prev_epoch;
        uint64_t slot_seq;
        uint32_t chain_len;
        uint32_t fs_gen;
        uint32_t node_id;
        uint64_t epoch;
    } __attribute__((packed)) b;

    b.magic      = pv->magic;
    b.prev_node  = pv->prev_node;
    b.prev_epoch = (uint64_t)pv->prev_epoch;
    b.slot_seq   = pv->slot_seq;
    b.chain_len  = pv->chain_len;
    b.fs_gen     = fs_gen;
    b.node_id    = (uint32_t)node_id;
    b.epoch      = (uint64_t)epoch;
    return mxfs_pal_crc32c(~0U, &b, sizeof(b));
}

/* Fail-closed validity: only a block whose magic AND identity-bound crc
 * both check may feed the lineage test.  Pre-carve records carry zeros
 * here (magic 0 ⇒ invalid ⇒ conservative fire). */
static bool hb_prov_valid(const struct mxfs_disklock_heartbeat *hb)
{
    return hb->prov.magic == MXFS_HB_PROV_MAGIC &&
           hb->prov.crc32c == hb_prov_crc(hb->fs_gen, hb->node_id,
                                          hb->epoch, &hb->prov);
}

/*
 * sess346 (#92): does this record read as the CLEAN RELEASE STAMP of the
 * expected occupant?  mxfs_disklock_release_slot() CAS-writes the node's
 * own final ACTIVE image with flags flipped to EMPTY, so a clean departure
 * leaves {magic, node_id, epoch, fs_gen} intact under FLAG_EMPTY.  An
 * expected epoch we never observed (0) degrades to the node-scoped test —
 * safe here because the ONLY consequence of a match is a clean retire
 * (no fence, no recovery, no slot write).  node == 0 never matches: a
 * snapshot that names nobody identifies nothing.
 */
static bool hb_clean_empty_match(const struct mxfs_disklock_ctx *ctx,
                                 const struct mxfs_disklock_heartbeat *hb,
                                 mxfs_node_id_t node, mxfs_epoch_t epoch)
{
    if (hb->magic != MXFS_DISKLOCK_MAGIC)
        return false;
    if (hb->flags != MXFS_DISKLOCK_FLAG_EMPTY)
        return false;
    if (hb_gen_foreign(ctx, hb))
        return false;
    if (node == 0 || hb->node_id != node)
        return false;
    if (!inc_valid(epoch))
        return true;            /* degrade to node scope */
    return inc_eq(hb->epoch, epoch);
}

/*
 * sess346 (#92): derive THIS tenancy's provenance from the record the
 * claim is about to consume, and remember it in ctx->own_prov for every
 * subsequent own-record write of this incarnation.  Called with the claim
 * identity (local_node, fs_gen, epoch) already final.
 *
 *   own-stamp reclaim (pass 1)      → predecessor is our own DIRTY record:
 *                                     continue the seq (peers' lineage
 *                                     windows must exclude it), chain = 0,
 *                                     no prev stamp.
 *   fresh claim of a clean EMPTY    → prev = the released stamp,
 *   with valid provenance             seq = prev.seq + 1,
 *                                     chain = min(prev.chain + 1, cap).
 *   anything else (garbage, foreign
 *   generation, zeroed, pre-carve)  → RANDOM 64-bit seq restart, chain 0.
 */
static void hb_prov_derive(struct mxfs_disklock_ctx *ctx,
                           const struct mxfs_disklock_heartbeat *consumed,
                           bool fresh_claim)
{
    struct mxfs_hb_provenance *pv = &ctx->own_prov;

    memset(pv, 0, sizeof(*pv));
    pv->magic = MXFS_HB_PROV_MAGIC;
    if (!fresh_claim && hb_prov_valid(consumed)) {
        pv->slot_seq  = consumed->prov.slot_seq + 1;
        pv->chain_len = 0;
    } else if (fresh_claim &&
               consumed->magic == MXFS_DISKLOCK_MAGIC &&
               consumed->flags == MXFS_DISKLOCK_FLAG_EMPTY &&
               !hb_gen_foreign(ctx, consumed) &&
               hb_prov_valid(consumed)) {
        pv->prev_node  = (uint32_t)consumed->node_id;
        pv->prev_epoch = (uint64_t)consumed->epoch;
        pv->slot_seq   = consumed->prov.slot_seq + 1;
        pv->chain_len  = consumed->prov.chain_len < MXFS_HB_PROV_CHAIN_CAP ?
                         consumed->prov.chain_len + 1 :
                         MXFS_HB_PROV_CHAIN_CAP;
    } else {
        mxfs_pal_get_random_bytes(&pv->slot_seq, sizeof(pv->slot_seq));
        pv->chain_len = 0;
    }
    pv->crc32c = hb_prov_crc(ctx->fs_gen, ctx->local_node, ctx->epoch, pv);
}

/*
 * ── sess65: DURABLE RECOVERY DESCRIPTOR — parsing side ──────────────────
 *
 * See the state-machine comment above MXFS_RECOV_DESC_MAGIC in disklock.h.
 * Three predicates, deliberately different in strictness:
 *
 *   recov_desc_of()      the STRICT reader.  Returns the descriptor only when
 *                        it is a RECOVERY_GUARD record carrying a descriptor
 *                        of a version we understand whose crc validates
 *                        against the record's (victim) identity.  Everything
 *                        that INTERPRETS the recovery — stage tests, owner
 *                        tests, takeover — must use this.
 *   recov_lease_covers_{node,inc}()
 *                        the CONSERVATIVE freeze test.  True for any sector
 *                        that even claims to carry a descriptor, including a
 *                        torn one or one written by a future protocol
 *                        generation.  Everything that would DESTROY or REUSE
 *                        the slot must use this: refusing to act on a
 *                        descriptor we cannot read is correct (the slice
 *                        underneath is mid-recovery), guessing is not.
 *   recov_desc_names_{node,inc}()
 *                        strict identity test, for resolving "whose slot is
 *                        this?" — a torn descriptor names nobody.  The _inc
 *                        form is the AUTHORITATIVE one (required incarnation
 *                        match); _node is for callers whose authority comes
 *                        from elsewhere.  There is deliberately no
 *                        optional-epoch form: zero is never a wildcard.
 *
 * The crc binds the descriptor to the record's identity triple exactly as
 * hb_feature_crc binds the feature block, so a descriptor payload spliced
 * next to a different victim's header never validates.
 */
static uint32_t recov_desc_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
                               mxfs_epoch_t epoch,
                               const struct mxfs_recov_desc *d)
{
    struct {
        uint32_t fs_gen;
        uint32_t node_id;
        uint64_t epoch;
    } __attribute__((packed)) id;
    uint32_t crc;

    id.fs_gen  = fs_gen;
    id.node_id = (uint32_t)node_id;
    id.epoch   = (uint64_t)epoch;
    /* Bytes 0..75: every descriptor field except the crc itself.  The
     * structure is naturally aligned end to end (asserted in disklock.h), so
     * this covers no padding. */
    crc = mxfs_pal_crc32c(~0U, d, offsetof(struct mxfs_recov_desc, crc32c));
    return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

static bool recov_desc_present(const struct mxfs_disklock_heartbeat *hb)
{
    return hb->magic == MXFS_DISKLOCK_MAGIC &&
           hb->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
           hb->recov.desc.magic == MXFS_RECOV_DESC_MAGIC;
}

static const struct mxfs_recov_desc *
recov_desc_of(const struct mxfs_disklock_heartbeat *hb)
{
    const struct mxfs_recov_desc *d = &hb->recov.desc;

    if (!recov_desc_present(hb))
        return NULL;
    if (d->version != MXFS_RECOV_DESC_VERSION)
        return NULL;            /* a generation we do not speak */
    if (d->crc32c != recov_desc_crc(hb->fs_gen, hb->node_id, hb->epoch, d))
        return NULL;
    return d;
}

/*
 * sess323: the terminal outcome record (disklock.h) gets the SAME identity
 * binding as the descriptor — crc32c over its own bytes folded with the
 * sector's {fs_gen, node_id, epoch} — so an outcome spliced next to a
 * different victim's header never validates.
 */
static uint32_t recov_outcome_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
                                  mxfs_epoch_t epoch,
                                  const struct mxfs_recov_outcome *oc)
{
    struct {
        uint32_t fs_gen;
        uint32_t node_id;
        uint64_t epoch;
    } __attribute__((packed)) id;
    uint32_t crc;

    id.fs_gen  = fs_gen;
    id.node_id = (uint32_t)node_id;
    id.epoch   = (uint64_t)epoch;
    crc = mxfs_pal_crc32c(~0U, oc, offsetof(struct mxfs_recov_outcome, crc32c));
    return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

/*
 * The STRICT outcome reader.  Returns the outcome record only when the
 * sector is a RECOVERY_GUARD record and the outcome bytes carry our magic,
 * a version we speak, and a crc that validates against the record's victim
 * identity.  A descriptor written by a build that never had outcome records
 * presents zeroed bytes here and reads as "no outcome", never as garbage.
 */
static const struct mxfs_recov_outcome *
recov_outcome_of(const struct mxfs_disklock_heartbeat *hb)
{
    const struct mxfs_recov_outcome *oc = &hb->recov.outcome;

    if (!recov_desc_present(hb))
        return NULL;
    if (oc->magic != MXFS_RECOV_OUTCOME_MAGIC)
        return NULL;
    if (oc->version != MXFS_RECOV_OUTCOME_VERSION)
        return NULL;
    if (oc->crc32c != recov_outcome_crc(hb->fs_gen, hb->node_id,
                                        hb->epoch, oc))
        return NULL;
    return oc;
}

/*
 * sess327 (ruling item 8): distinguish "no outcome was ever written" (all
 * zero — the intent-quarantine path and pre-outcome builds) from "an outcome
 * was written but does not validate" (torn/corrupt — must fail closed).
 * recov_outcome_of() answers "valid?"; this answers "any bytes at all?".
 */
static bool recov_outcome_present(const struct mxfs_disklock_heartbeat *hb)
{
    const unsigned char *p = (const unsigned char *)&hb->recov.outcome;
    size_t i;

    for (i = 0; i < sizeof(hb->recov.outcome); i++)
        if (p[i])
            return true;
    return false;
}

/*
 * sess383 (RULE-5 ruling Q2/Q5.1): the STRUCTURAL verdict of one already-read
 * heartbeat sector — the single place that decides what a sector's recovery
 * object structurally IS, so the monitor and the synchronous readers cannot
 * disagree about it.  Semantic validation (outcome kinds, reasons, AG-mask
 * validity for the mounted filesystem) is XFS-layer policy and lives behind
 * the outcome callback; nothing of that sort belongs here.
 *
 * Two gates were missing from every consumer except the pending sweep and are
 * added here so ALL of them inherit them:
 *
 *   - the GENERATION gate, FIRST.  A sector whose fs_gen is not ours is a
 *     pre-mkfs ghost: it is outside this filesystem's recovery namespace, so
 *     it is neither a verdict nor corruption of one.  Measured sess383: a
 *     ghost record quarantined a freshly-formatted filesystem because this
 *     reader looked at its bytes at all.
 *   - the DESCRIPTOR IDENTITY gate.  The descriptor crc binds the SECTOR's
 *     {fs_gen, node_id, epoch}, which travel with a byte-copied record, so
 *     victim_slot is the only binding to the slot the sector was read from.
 *     A misplaced record must not be read as this slot's verdict.
 */
static int recov_outcome_structural(const struct mxfs_disklock_ctx *ctx,
                                    const struct mxfs_disklock_heartbeat *hb,
                                    int slot,
                                    const struct mxfs_recov_outcome **oc_out)
{
    const struct mxfs_recov_desc *d;
    const struct mxfs_recov_outcome *oc;

    if (oc_out)
        *oc_out = NULL;

    if (!recov_desc_present(hb)) {
        /* No descriptor of ours.  A foreign-generation sector that carries
         * one still reports -ESTALE rather than -ENOENT: "wrong generation"
         * is evidence, "nothing there" is not. */
        return hb_gen_foreign(ctx, hb) && hb->recov.desc.magic ==
                        MXFS_RECOV_DESC_MAGIC ? -ESTALE : -ENOENT;
    }
    if (hb_gen_foreign(ctx, hb))
        return -ESTALE;
    d = recov_desc_of(hb);
    if (!d)
        return -EPROTO;         /* descriptor bytes present but unparseable */
    if (d->victim_slot != (uint16_t)slot)
        return -EPROTO;         /* misplaced/copied record: names another slot */
    if (!(d->flags & MXFS_RECOV_F_QUARANTINED))
        return -EAGAIN;         /* live descriptor, no verdict yet */
    oc = recov_outcome_of(hb);
    if (oc) {
        if (oc_out)
            *oc_out = oc;
        return 0;
    }
    /* QUARANTINED with no valid outcome: intent-path quarantine wrote no
     * outcome bytes at all (-ENODATA — terminal, but no domain evidence);
     * anything nonzero that fails validation is corruption the consumer
     * must fail closed on (-EBADMSG, ruling item 8). */
    return recov_outcome_present(hb) ? -EBADMSG : -ENODATA;
}

/*
 * ── Descriptor victim identification: TWO APIs, never one optional epoch ────
 *
 * An optional-epoch argument recreates exactly the wildcard bug this work
 * exists to kill (ruling Q3: "prefer separate APIs for 'inspect a legacy or
 * empty record' vs 'prove a live incarnation'"), so the node-scoped and the
 * incarnation-scoped questions are separate functions and every caller must
 * state which one it means.
 *
 * _node() is NON-AUTHORITATIVE: "is this slot's descriptor about that node at
 * all?".  Legitimate only where the caller's authority comes from elsewhere —
 * e.g. a purge already justified by independent fencing/protocol proof.  It
 * may NEVER gate replay, descriptor adoption, fence certification or recovery
 * advancement.
 *
 * _inc() is the AUTHORITATIVE test: this descriptor names exactly that
 * (node, incarnation).  Zero on either side is a refusal.
 */
static bool recov_desc_names_node(const struct mxfs_disklock_heartbeat *hb,
                                  mxfs_node_id_t node)
{
    const struct mxfs_recov_desc *d = recov_desc_of(hb);

    return d && d->victim_node == node;
}

static bool recov_desc_names_inc(const struct mxfs_disklock_heartbeat *hb,
                                 mxfs_node_id_t node, mxfs_epoch_t epoch)
{
    const struct mxfs_recov_desc *d = recov_desc_of(hb);

    return d && d->victim_node == node && inc_eq(d->victim_epoch, epoch);
}

static bool recov_lease_covers_node(const struct mxfs_disklock_heartbeat *hb,
                                    mxfs_node_id_t node)
{
    if (!recov_desc_present(hb))
        return false;
    /* Present but unreadable: the sector IS a recovery lease and this is the
     * victim's own slot, so it can only be about this victim.  Treat it as
     * covering — frozen until someone who can read it finishes the job. */
    if (!recov_desc_of(hb))
        return true;
    return recov_desc_names_node(hb, node);
}

static bool recov_lease_covers_inc(const struct mxfs_disklock_heartbeat *hb,
                                   mxfs_node_id_t node, mxfs_epoch_t epoch)
{
    if (!recov_desc_present(hb))
        return false;
    if (!recov_desc_of(hb))
        return true;            /* unreadable lease on the victim's own slot */
    return recov_desc_names_inc(hb, node, epoch);
}

/*
 * The split broadcast predicate (GPT sess63 ruling, rule 3).
 *
 * "The slot no longer carries the dead stamp" used to mean BOTH "the victim
 * is fenced" AND "the victim's grants have been released" — one bit carrying
 * two independent facts.  With the descriptor, a fenced victim's slot reads
 * RECOVERY_GUARD while its authority is deliberately held frozen, so the
 * ONLY transition that may release a peer's deferred local purge is the
 * final zeroing (CONSUMABLE).
 */
static bool hb_still_dead_stamp(const struct mxfs_disklock_heartbeat *hb,
                                mxfs_node_id_t pn, mxfs_epoch_t pe)
{
    if (hb->magic != MXFS_DISKLOCK_MAGIC)
        return false;                       /* zeroed => CONSUMABLE */
    /*
     * A pending incarnation we never observed (pe == 0: we marked the slot
     * pending without ever having seen a fresh heartbeat from it) degrades to
     * the node-scoped test.  That direction is the safe one HERE: a true only
     * keeps the deferred local purge armed, and the CONSUMABLE zeroing at the
     * end of recovery releases the barrier regardless of this predicate.
     */
    if (!inc_valid(pe))
        return hb->node_id == pn || recov_lease_covers_node(hb, pn);
    /*
     * The victim's own stamp intact — now a REQUIRED match.  A same-node
     * record at a DIFFERENT incarnation is a SUCCESSOR tenancy, not our
     * victim: the node rejoined and its own mount replayed the slice, so the
     * barrier must lift.  That is the designed rejoin release, and it only
     * became real once incarnations stopped being a constant zero.
     */
    if (hb->node_id == pn && inc_eq(hb->epoch, pe))
        return true;
    return recov_lease_covers_inc(hb, pn, pe); /* fenced, recovery in flight */
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

/*
 * ── sess78: OWN-SLOT WRITES ARE COMPARE-AND-WRITE ───────────────────────────
 *
 * D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD.  See the hb_img comment in
 * disklock.h for the defect; measured on the 32-node rig by
 * tests/hb_guard_clobber_probe.sh (guard destroyed 0.8 s after it was laid
 * into a live node's slot, victim logged nothing).
 *
 * Is `cur` still OUR live record?  Only we ever write this content: our
 * node_id, our mkfs generation, our mount incarnation, flags ACTIVE.  A
 * recovery guard keeps our node_id but moves `flags`; a purge zeroes the
 * sector; a successor claimant writes its own node_id.  So this predicate is
 * exactly "no foreign writer has touched our slot".
 */
static bool hb_own_record(const struct mxfs_disklock_ctx *ctx,
                          const struct mxfs_disklock_heartbeat *cur)
{
    return cur->magic == MXFS_DISKLOCK_MAGIC &&
           cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
           cur->node_id == ctx->local_node &&
           cur->epoch == ctx->epoch &&
           !hb_gen_foreign(ctx, cur);
}

/* Name what a foreign own-slot image is, for the self-fence log. */
static const char *hb_foreign_kind(const struct mxfs_disklock_ctx *ctx,
                                   const struct mxfs_disklock_heartbeat *cur)
{
    if (cur->magic != MXFS_DISKLOCK_MAGIC)
        return "sector PURGED/zeroed (our slice was recovered and retired)";
    if (hb_gen_foreign(ctx, cur))
        return "foreign mkfs generation (device re-formatted under us)";
    if (cur->node_id != ctx->local_node)
        return "another node CLAIMED our slot";
    if (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
        return "a survivor laid a RECOVERY GUARD on us — our journal slice "
               "is being replayed RIGHT NOW";
    if (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN)
        return "our record was stamped WITHDRAWN by someone else";
    if (cur->epoch != ctx->epoch)
        return "a different incarnation of this node owns the slot";
    return "unrecognised foreign image";
}

/*
 * Compare-and-write `want` into our own heartbeat slot from ctx->hb_img.
 *
 * Returns:
 *    0        written; hb_img now equals `want`.
 *   -EPERM    MISCOMPARE and the sector is NOT ours — a recovery/purge/
 *             successor owns it.  The caller MUST self-fence: everything we
 *             write from here on is pollution of a slice somebody else is
 *             replaying, and our exclusion has already been asserted.
 *   -EAGAIN   MISCOMPARE but the sector still holds OUR live record, i.e. our
 *             cached image had drifted (an earlier write whose completion we
 *             never saw did land).  Re-synced; the caller retries next cycle.
 *   <0        I/O error.  The write outcome is INDETERMINATE, so hb_img is
 *             invalidated and the next call re-establishes it by reading.
 *
 * A lost race is never retried in here: on -EAGAIN the content we would write
 * is already one cycle stale, and on -EPERM retrying is the bug.
 */
static int hb_cas_own_slot(struct mxfs_disklock_ctx *ctx, uint64_t off,
                           const struct mxfs_disklock_heartbeat *want,
                           struct mxfs_disklock_heartbeat *scratch)
{
    int rc;

    /* Bootstrap / post-indeterminate: re-establish the compare source. */
    if (!ctx->hb_img_valid) {
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, scratch, sizeof(*scratch));
        if (rc < 0)
            return rc;
        if (!hb_own_record(ctx, scratch))
            return -EPERM;
        ctx->hb_img = *scratch;
        ctx->hb_img_valid = true;
    }

    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, &ctx->hb_img, want);

    if (rc == -EOPNOTSUPP) {
        /*
         * No CAW on this transport.  Read-verify-write: strictly weaker than
         * a CAW (a foreign write landing inside the window is still lost) but
         * it closes the 2-second hole, which is where every real occurrence
         * lives.  Targets without CAW cannot host a clustered RW mount that
         * needs proven fencing anyway (sess77 ruling Q5).
         */
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, scratch, sizeof(*scratch));
        if (rc < 0)
            goto indeterminate;
        if (memcmp(scratch, &ctx->hb_img, sizeof(*scratch)) != 0)
            rc = -EAGAIN;
        else
            rc = write_sector_fua(ctx, off, want);
    }

    if (rc == 0) {
        ctx->hb_img = *want;
        return 0;
    }

    if (rc == -EAGAIN) {
        /* Somebody else wrote our sector.  Who? */
        int rrc = mxfs_pal_bdev_read_prio(ctx->dev, off, scratch,
                                          sizeof(*scratch));
        if (rrc < 0) {
            ctx->hb_img_valid = false;
            return rrc;
        }
        if (hb_own_record(ctx, scratch)) {
            /* Still ours: our cached image drifted, not a takeover. */
            ctx->hb_img = *scratch;
            ctx->hb_img_valid = true;
            mxfs_pal_log(MXFS_LOG_WARN,
                "mxfs: P236-HB-CAS-RESYNC slot=%d node=%u — own-slot CAS "
                "MISCOMPARE but the sector still holds OUR live record "
                "(ts=%llu); re-synced the compare image and retrying. This "
                "means a previous own-slot write completed without us seeing "
                "it — investigate if it repeats.",
                ctx->local_slot, ctx->local_node,
                (unsigned long long)scratch->timestamp_ms);
            return -EAGAIN;
        }
        ctx->hb_img_valid = false;
        mxfs_pal_log(MXFS_LOG_ERR,
            "mxfs: P236-HB-FOREIGN-WRITE slot=%d node=%u — own-slot CAS "
            "MISCOMPARE: %s (magic=%08x flags=%u node=%u fs_gen=%u epoch=%llu)",
            ctx->local_slot, ctx->local_node, hb_foreign_kind(ctx, scratch),
            scratch->magic, scratch->flags, scratch->node_id, scratch->fs_gen,
            (unsigned long long)scratch->epoch);
        return -EPERM;
    }

indeterminate:
    /* The write may or may not have landed — the compare source is unknown. */
    ctx->hb_img_valid = false;
    return rc;
}

/*
 * sess280 (sess276 ruling, part D): heartbeat-stall watchdog.
 *
 * The sess276 false-death incident fenced a node whose heartbeat had not
 * landed for the full 62s lease while the node looked alive — and nothing
 * named WHERE the heartbeat cycle was stuck (thread wedge vs ctx->lock
 * starvation vs a write parked in the saturated device queue vs the
 * monitor's 63 peer reads).  P-HB-SLOW only reports after a cycle
 * COMPLETES; a cycle that never completes is exactly the one that kills.
 *
 * The heartbeat thread publishes its stage at each phase boundary
 * (hb_stage_set); this watchdog polls every 2s and, when a non-SLEEP
 * stage is older than 8s (4x the 2s heartbeat interval — a healthy full
 * cycle is milliseconds), logs P278-HB-STALL with the stage and dumps the
 * heartbeat task's kernel stack so the blocked wait site is captured
 * WHILE it is blocked.  Re-logs every 30s while the same stall persists.
 * Diagnostic only: it never fences, never writes, and reads the stage
 * pair racily (a torn read costs one poll).
 */
#define MXFS_HB_STALL_POLL_MS   2000
#define MXFS_HB_STALL_MS        8000
#define MXFS_HB_STALL_RELOG_MS  30000

static void hb_stage_set(struct mxfs_disklock_ctx *ctx, int stage)
{
    ctx->hb_stage = stage;
    ctx->hb_stage_ms = mxfs_pal_time_ms();
}

static const char *hb_stage_name(int stage)
{
    switch (stage) {
    case MXFS_HB_STAGE_SLEEP:    return "SLEEP";
    case MXFS_HB_STAGE_IDCHECK:  return "IDCHECK";
    case MXFS_HB_STAGE_LOCKWAIT: return "LOCKWAIT";
    case MXFS_HB_STAGE_CASWRITE: return "CASWRITE";
    case MXFS_HB_STAGE_MONITOR:  return "MONITOR";
    default:                     return "UNKNOWN";
    }
}

static void disklock_hb_watchdog_fn(void *arg)
{
    struct mxfs_disklock_ctx *ctx = arg;
    uint64_t stall_entered = 0;   /* hb_stage_ms of the stall being tracked */
    uint64_t last_log_ms = 0;

    while (ctx->running) {
        int stage = ctx->hb_stage;
        uint64_t entered = ctx->hb_stage_ms;
        uint64_t now = mxfs_pal_time_ms();

        if (stage != MXFS_HB_STAGE_SLEEP && entered != 0 &&
            now - entered > MXFS_HB_STALL_MS) {
            if (entered != stall_entered ||
                now - last_log_ms >= MXFS_HB_STALL_RELOG_MS) {
                stall_entered = entered;
                last_log_ms = now;
                mxfs_pal_log(MXFS_LOG_ERR,
                    "mxfs: P278-HB-STALL node %u slot %d stage=%s "
                    "age_ms=%llu hb_pid=%d — heartbeat cycle stuck; "
                    "dumping heartbeat task stack",
                    ctx->local_node, ctx->local_slot,
                    hb_stage_name(stage),
                    (unsigned long long)(now - entered), ctx->hb_pid);
                mxfs_pal_dump_task_stack(ctx->hb_pid);
            }
        } else {
            stall_entered = 0;
        }

        /* Condvar timed wait, not msleep: msleep parks this worker in
         * uninterruptible (D) sleep, which precond_readiness's D-state
         * scan flags as a stuck task.  The shutdown broadcast also wakes
         * us immediately on stop. */
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running)
            mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                    ctx->shutdown_lock,
                                    MXFS_HB_STALL_POLL_MS);
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }
}

/*
 * sess355 (#92 races 6/7 closure): test-only monitor blackout.  While
 * mxfs_monitor_blind=1 the heartbeat thread suppresses ONLY the peer
 * observation pass — its own heartbeat CAS, self-fence, reservation-
 * conflict relay and shutdown handling all stay live — so a test can
 * make one observer miss a peer's ACTIVE->EMPTY->ACTIVE tenancy change
 * without the observer's own record ever going stale (no P225 barrier
 * on other mounts, no fencing risk, no suspend-window arithmetic).
 * The knob is a stretched monitor interval, nothing more.
 *
 * The gate is taken at the scan BOUNDARY only: a pass already in flight
 * finishes untouched, and the first suppressed pass logs an ACK the
 * test must wait for before it starts choreography.  Auto-clears after
 * MXFS_HB_BLIND_MAX_MS or on heartbeat-thread exit; an auto-clear means
 * the run is INVALID (reason is logged, the test asserts reason=user).
 * Param lives in v5_mount.c (this file also builds user-mode).
 */
int mxfs_monitor_blind;
#define MXFS_HB_BLIND_MAX_MS 120000

static struct {
    bool     active;    /* hb thread acked the request */
    uint32_t gen;       /* activation generation */
    uint32_t skips;     /* peer scans suppressed this activation */
    uint32_t hb_ok;     /* successful own-hb writes while blind */
    uint64_t t0;        /* activation time, ms */
} hb_blind;

static void hb_blind_clear(const char *reason)
{
    mxfs_monitor_blind = 0;
    hb_blind.active = false;
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P163T-BLIND-CLEAR reason=%s gen=%u skips=%u hb_ok=%u",
                 reason, hb_blind.gen, hb_blind.skips, hb_blind.hb_ok);
}

/* Returns true when this cycle's peer scan must be suppressed. */
static bool hb_blind_gate(struct mxfs_disklock_ctx *ctx, int hb_rc)
{
    if (!mxfs_monitor_blind) {
        if (hb_blind.active)
            hb_blind_clear("user");
        return false;
    }
    if (!hb_blind.active) {
        hb_blind.active = true;
        hb_blind.gen++;
        hb_blind.skips = 0;
        hb_blind.hb_ok = 0;
        hb_blind.t0 = mxfs_pal_time_ms();
        mxfs_pal_log(MXFS_LOG_WARN, "mxfs: P163T-BLIND-ACK gen=%u slot=%d",
                     hb_blind.gen, ctx->local_slot);
    }
    if (mxfs_pal_time_ms() - hb_blind.t0 > MXFS_HB_BLIND_MAX_MS) {
        hb_blind_clear("timeout");
        return false;
    }
    hb_blind.skips++;
    if (hb_rc == 0)
        hb_blind.hb_ok++;
    mxfs_pal_log(MXFS_LOG_INFO, "mxfs: P163T-BLIND-SKIP gen=%u skips=%u hb_rc=%d",
                 hb_blind.gen, hb_blind.skips, hb_rc);
    return true;
}

/* Heartbeat thread: writes heartbeat, sleeps, repeats */
static void disklock_hb_fn(void *arg)
{
    struct mxfs_disklock_ctx *ctx = arg;
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_heartbeat *rhb;
    uint64_t offset;
    int rc;
    /* sess38 P-HB-SLOW cycle clocks (persist across loop iterations) */
    uint64_t hb_t0 = 0, hb_tlock = 0, hb_t1 = 0;
    uint64_t hb_last_ok_ms = 0, hb_mon_ms = 0;

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
        hb_stage_set(ctx, MXFS_HB_STAGE_IDCHECK);
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
                    ctx->fence_cb(ctx->fence_cb_data,
                                  MXFS_SELF_FENCE_FS_IDENTITY);
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
        hb_feature_fill(ctx, hb);       /* sess42 C7 */
        hb->prov = ctx->own_prov;       /* sess346 #92: constant per tenure */

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

        /* sess38 (D-RELABORT-...-SELFFENCE RULE-4): time every hb write and
         * track the age since the last SUCCESSFUL one.  test21 was fenced
         * after its hb failed to land for the FULL 62s lease while the node
         * looked alive — this names the outage as it grows (write stuck in
         * the saturated device queue vs mutex held vs hard failure), at zero
         * cost on the healthy path (one log only when late/slow/failed). */
        hb_t0 = mxfs_pal_time_ms();
        hb_stage_set(ctx, MXFS_HB_STAGE_LOCKWAIT);
        mxfs_pal_mutex_lock(ctx->lock);
        hb_stage_set(ctx, MXFS_HB_STAGE_CASWRITE);
        hb_tlock = mxfs_pal_time_ms();
        /* sess78: CAS, never a blind write — see hb_cas_own_slot().  rhb is
         * free again here (the identity check above finished with it). */
        rc = hb_cas_own_slot(ctx, offset, hb, rhb);
        mxfs_pal_mutex_unlock(ctx->lock);
        hb_t1 = mxfs_pal_time_ms();

        /*
         * sess78 self-fence.  Our slot no longer holds our record: a survivor
         * has fenced us and owns our journal slice.  Every further write from
         * this mount — heartbeat, metadata, log — corrupts a recovery already
         * in flight, and our exclusion has already been asserted to the
         * cluster.  Stop heartbeating and force the filesystem down.
         */
        if (rc == -EPERM) {
            ctx->fenced = true;
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P236-SELF-FENCE node %u slot %d: our heartbeat "
                         "slot was taken over by a recovery — stopping "
                         "heartbeat, forcing shutdown",
                         ctx->local_node, ctx->local_slot);
            if (ctx->fence_cb)
                ctx->fence_cb(ctx->fence_cb_data,
                              MXFS_SELF_FENCE_SLOT_TAKEOVER);
            break;
        }

        /* sess279 (sess276 ruling, part A): RESERVATION CONFLICT on the
         * own-slot write is the target telling a fenced-but-alive victim
         * its registration is gone — the ONE fencing signal that cannot
         * be served from stale media.  Relay to the v5 layer, which
         * counts conflicts and runs the PR IN inspection that decides
         * withdraw.  Keep heartbeating meanwhile: the writes bounce
         * harmlessly, and a transient target hiccup must not kill a
         * healthy node from here. */
        if (rc == -EBADE && ctx->conflict_cb)
            ctx->conflict_cb(ctx->conflict_cb_data);

        if (rc < 0)
            mxfs_pal_log(MXFS_LOG_ERR,
                         "disklock: heartbeat write failed: %d "
                         "(age_since_last_ok_ms=%llu)", rc,
                         (unsigned long long)(hb_last_ok_ms ?
                             hb_t1 - hb_last_ok_ms : 0));
        else
            hb_last_ok_ms = hb_t1;
        if (hb_t1 - hb_t0 > 2000 ||
            (hb_last_ok_ms && hb_t1 - hb_last_ok_ms >
             2 * MXFS_DISKLOCK_HB_INTERVAL_MS))
            mxfs_pal_log(MXFS_LOG_WARN,
                "mxfs: P-HB-SLOW slot=%d write_ms=%llu lockwait_ms=%llu rc=%d age_since_last_ok_ms=%llu prev_cycle_monitor_ms=%llu",
                ctx->local_slot,
                (unsigned long long)(hb_t1 - hb_tlock),
                (unsigned long long)(hb_tlock - hb_t0), rc,
                (unsigned long long)(hb_last_ok_ms ?
                    hb_t1 - hb_last_ok_ms : 0),
                (unsigned long long)hb_mon_ms);

        /* Bug 99: check running after each I/O call so
         * stop_heartbeat is not blocked behind N disk reads */
        if (!ctx->running)
            break;

        /* --- Monitor: read remote heartbeat slots --- */
        if (hb_blind_gate(ctx, rc)) {
            hb_mon_ms = 0;
            goto hb_blind_sleep;
        }
        hb_stage_set(ctx, MXFS_HB_STAGE_MONITOR);
        {
            uint32_t slot;

            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
                struct mxfs_disklock_node_track *nt;
                uint64_t off;
                int rr;
                int crr;	/* sess69: confirm-before-evict re-read rc */
                /*
                 * sess86: the death that fire_dead declares is named
                 * EXPLICITLY — {victim_node, victim_epoch} — instead of being
                 * read back out of slot_node_id[]/node_track[] by the
                 * consumer.  Both of those are rebased onto the SUCCESSOR
                 * before the predecessor's death is dispatched (the
                 * auto-monitor re-arm clobbers slot_node_id, and the
                 * epoch-change arm used to adopt the new incarnation), so a
                 * read-back names the LIVE node as the victim.
                 */
                mxfs_node_id_t victim_node;
                mxfs_epoch_t victim_epoch = 0;
                /* Rebase state: the successor incarnation to resume tracking
                 * once the predecessor's death has been dispatched. */
                bool rebase_inc = false;
                mxfs_epoch_t rebase_epoch = 0;
                uint64_t rebase_ts = 0;
                mxfs_node_id_t rebase_node = 0;

                if (!ctx->running)
                    break;

                if ((int)slot == ctx->local_slot)
                    continue;

                nt = &ctx->node_track[slot];
                victim_node = ctx->slot_node_id[slot];
                off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

                mxfs_pal_mutex_lock(ctx->lock);
                rr = mxfs_pal_bdev_read(ctx->dev, off,
                                         rhb, sizeof(*rhb));
                mxfs_pal_mutex_unlock(ctx->lock);

                /*
                 * sess9 (ccloop c7ee71c6) D2: a slot in recovery-pending
                 * is owned by the recovery protocol — the elected
                 * replayer zeroes it only AFTER the dead node's log
                 * slice is durably replayed.  Watch for that transition
                 * (or a rejoin: same node, new epoch — its own mount
                 * recovery replayed the slice) and only then run the
                 * DEFERRED local purge via recovered_cb.  FUA-confirm
                 * before releasing the barrier: a stale cached read must
                 * not unfreeze the dead node's grants early.
                 */
                {
                    bool pend;
                    mxfs_node_id_t pn;
                    mxfs_epoch_t pe;

                    mxfs_pal_mutex_lock(ctx->lock);
                    pend = ctx->recovery_pending[slot];
                    pn = ctx->pending_node[slot];
                    pe = ctx->pending_epoch[slot];
                    mxfs_pal_mutex_unlock(ctx->lock);

                    if (pend) {
                        /*
                         * sess65: the predicate SPLITS (GPT sess63 rule 3).
                         * A RECOVERY_GUARD carrying a descriptor that names
                         * this victim means FENCED, not RECOVERED — its
                         * grants are deliberately frozen and the deferred
                         * local purge must stay armed.  Only the final
                         * zeroing (CONSUMABLE) releases it.
                         */
                        bool still_dead_stamp = (rr == 0) &&
                            hb_still_dead_stamp(rhb, pn, pe);

                        /*
                         * sess346 (#92, ruling item 4): the pending victim's
                         * slot reads as its OWN CLEAN RELEASE STAMP — the
                         * death was declared from a stale read that raced
                         * mxfs_disklock_release_slot, and the node in fact
                         * unmounted cleanly.  The stamp keeps
                         * hb_still_dead_stamp() TRUE forever (node+epoch
                         * intact under EMPTY), so without this arm the
                         * barrier never lifts: no replayer can fence an
                         * EMPTY slot (fence_intent → -ESTALE, the observed
                         * P238-FENCE-NOINTENT rc=-116 livelock).  FUA-confirm,
                         * then run the DEDICATED unlatch: clear the pending
                         * marker and fire the clean-departure callback —
                         * NOT recovered_cb (there was no recovery; the P163
                         * purge path retires the identity, which a cleanly
                         * departed node must keep).
                         */
                        if (rr == 0 && still_dead_stamp &&
                            hb_clean_empty_match(ctx, rhb, pn, pe)) {
                            mxfs_pal_mutex_lock(ctx->lock);
                            crr = mxfs_pal_bdev_read_prio(ctx->dev, off,
                                                          rhb, sizeof(*rhb));
                            mxfs_pal_mutex_unlock(ctx->lock);
                            if (crr == 0 &&
                                hb_clean_empty_match(ctx, rhb, pn, pe)) {
                                mxfs_disklock_clear_recovery_pending(
                                    ctx, (int)slot, pn, pe);
                                mxfs_pal_log(MXFS_LOG_WARN,
                                    "mxfs: P163-CLEAN-DEPART-PEND slot=%u "
                                    "node=%u inc=%llu — pending victim's slot "
                                    "is its own clean release stamp (FUA "
                                    "confirmed); unlatching WITHOUT recovery",
                                    slot, pn, (unsigned long long)pe);
                                if (ctx->clean_depart_cb)
                                    ctx->clean_depart_cb(
                                        ctx->clean_depart_cb_data,
                                        (int)slot, pn, pe);
                                mxfs_pal_mutex_lock(ctx->lock);
                                nt->last_epoch      = 0;
                                nt->last_timestamp  = 0;
                                nt->live            = false;
                                nt->changed_samples = 0;
                                nt->equal_samples   = 0;
                                nt->evict_seen      = false;
                                nt->seq_seen        = false;
                                ctx->monitored[slot] = false;
                                mxfs_pal_mutex_unlock(ctx->lock);
                            }
                            continue;
                        }

                        /*
                         * sess323: a GUARD record carrying a VALID terminal
                         * outcome + F_QUARANTINED is the recovery owner's
                         * durable "this slice will NEVER be recovered"
                         * verdict (sess320 ruling).  Import it — once per
                         * (victim_epoch, publish_seq) — so this node
                         * quarantines the victim's domain instead of timing
                         * out into its own shutdown.  The deferred local
                         * purge stays armed: quarantine is terminal, the
                         * slot never becomes CONSUMABLE on its own.
                         */
                        if (rr == 0 && still_dead_stamp) {
                            const struct mxfs_recov_outcome *oc = NULL;
                            const struct mxfs_recov_desc *qd =
                                recov_desc_of(rhb);
                            int src = recov_outcome_structural(ctx, rhb,
                                                               (int)slot, &oc);

                            /*
                             * sess383 (RULE-5 ruling Q1): the old arm fired
                             * the import cb only when
                             * oc->outcome == TERMINAL_REFUSED.  That filter
                             * was itself a BYPASS of the one validator: a
                             * crc-valid record carrying an unknown outcome
                             * kind was skipped silently, pass after pass, so
                             * a QUARANTINED slot never quarantined any live
                             * peer and the D-513 park/timeout shape returned.
                             * Every structurally readable outcome now reaches
                             * the callback, which owns the semantic verdict
                             * and fails closed on anything it rejects.
                             */
                            if (src == 0) {
                                bool fresh;

                                mxfs_pal_mutex_lock(ctx->lock);
                                fresh = !inc_eq(
                                        ctx->outcome_seen_epoch[slot],
                                        oc->victim_epoch) ||
                                    oc->publish_seq >
                                        ctx->outcome_seen_seq[slot];
                                if (fresh) {
                                    ctx->outcome_seen_epoch[slot] =
                                        oc->victim_epoch;
                                    ctx->outcome_seen_seq[slot] =
                                        oc->publish_seq;
                                }
                                mxfs_pal_mutex_unlock(ctx->lock);

                                if (fresh) {
                                    mxfs_pal_log(MXFS_LOG_ERR,
                                        "mxfs: P241-RECOV-TERMINAL-IMPORT "
                                        "slot=%u victim=%u/%llu reason=%u "
                                        "domain=%u ag_mask=0x%llx seq=%llu "
                                        "— peer %u published a terminal "
                                        "verdict; handing it to the validator",
                                        slot, oc->victim_node,
                                        (unsigned long long)oc->victim_epoch,
                                        oc->reason, oc->domain_kind,
                                        (unsigned long long)oc->ag_mask,
                                        (unsigned long long)oc->publish_seq,
                                        oc->owner_node);
                                    if (ctx->recov_outcome_cb)
                                        ctx->recov_outcome_cb(
                                            ctx->recov_outcome_cb_data,
                                            (int)slot, oc);
                                }
                            }

                            /*
                             * sess327 (sess325 ruling item 8): QUARANTINED
                             * with outcome bytes that DO NOT validate is a
                             * persistent corruption of a terminal verdict —
                             * it must never be silently skipped pass after
                             * pass.  Alert once per slot, and fire the
                             * import cb with oc == NULL EVERY pass (the
                             * fail-closed fswide contract; there is no
                             * (epoch, seq) to dedup on, importers are
                             * idempotent).  The all-zero outcome region
                             * (intent-path quarantine) is NOT this case —
                             * it is a legitimate terminal state with no
                             * domain evidence, handled by the read_outcome
                             * -ENODATA arm at import time.
                             *
                             * sess383: -EPROTO joins -EBADMSG here.  A
                             * descriptor whose bytes do not parse, or whose
                             * victim_slot names a different slot, is exactly
                             * as unreadable as a torn verdict, and the
                             * synchronous readers already fail closed on it.
                             * -ESTALE (pre-mkfs ghost) does NOT: it is not
                             * this filesystem's recovery object at all.
                             */
                            if (src == -EBADMSG || src == -EPROTO) {
                                bool first;

                                mxfs_pal_mutex_lock(ctx->lock);
                                first = !ctx->outcome_badcrc_alerted[slot];
                                ctx->outcome_badcrc_alerted[slot] = true;
                                mxfs_pal_mutex_unlock(ctx->lock);

                                if (first)
                                    mxfs_pal_log(MXFS_LOG_ERR,
                                        "mxfs: P241-RECOV-OUTCOME-BADCRC "
                                        "slot=%u victim=%u rc=%d — PERSISTENT: "
                                        "quarantined/guarded slot carries "
                                        "unreadable verdict state; no domain "
                                        "evidence exists, failing closed "
                                        "FSWIDE until operator action",
                                        slot, qd ? qd->victim_node : 0, src);
                                if (ctx->recov_outcome_cb)
                                    ctx->recov_outcome_cb(
                                        ctx->recov_outcome_cb_data,
                                        (int)slot, NULL);
                            }
                        }

                        if (rr == 0 && !still_dead_stamp) {
                            mxfs_pal_mutex_lock(ctx->lock);
                            crr = mxfs_pal_bdev_read_prio(ctx->dev, off,
                                                          rhb, sizeof(*rhb));
                            mxfs_pal_mutex_unlock(ctx->lock);
                            if (crr == 0 &&
                                !hb_still_dead_stamp(rhb, pn, pe)) {
                                bool successor =
                                    rhb->magic == MXFS_DISKLOCK_MAGIC &&
                                    rhb->flags ==
                                        MXFS_DISKLOCK_FLAG_ACTIVE &&
                                    !hb_gen_foreign(ctx, rhb);

                                mxfs_disklock_clear_recovery_pending(
                                    ctx, (int)slot, pn, pe);
                                mxfs_pal_log(MXFS_LOG_WARN,
                                    "mxfs: P163-RECOVERED slot=%u node=%u — "
                                    "dead slice replay complete (slot "
                                    "reclaimed); running deferred local purge",
                                    slot, pn);
                                if (ctx->recovered_cb)
                                    ctx->recovered_cb(ctx->recovered_cb_data,
                                                      (int)slot, pn);
                                /*
                                 * sess86: retire the victim's tracking state
                                 * with the victim.  Leaving last_epoch
                                 * pinned to the departed incarnation makes
                                 * the NEXT occupant of this slot read as an
                                 * epoch change against a node that is already
                                 * fully recovered — a spurious second death,
                                 * whose first act is a per-node fence.
                                 *
                                 * If a successor already holds the slot,
                                 * inherit the slot's membership standing so
                                 * it enters dead-detection immediately (an
                                 * ACTIVE record proves ownership, not
                                 * liveness).  Otherwise forget the slot
                                 * entirely and let the auto-monitor
                                 * re-baseline on whoever claims it next.
                                 */
                                mxfs_pal_mutex_lock(ctx->lock);
                                nt->changed_samples = 0;
                                nt->equal_samples   = 0;
                                nt->evict_seen      = false;
                                nt->seq_seen        = false; /* sess346 #92 */
                                if (successor) {
                                    nt->last_epoch     = rhb->epoch;
                                    nt->last_timestamp = rhb->timestamp_ms;
                                    nt->live           = true;
                                    ctx->monitored[slot]    = true;
                                    ctx->slot_node_id[slot] = rhb->node_id;
                                } else {
                                    nt->last_epoch     = 0;
                                    nt->last_timestamp = 0;
                                    nt->live           = false;
                                    ctx->monitored[slot]    = false;
                                }
                                mxfs_pal_mutex_unlock(ctx->lock);
                            }
                        }
                        continue;
                    }
                }

                /*
                 * sess9 (ccloop c7ee71c6) D2: explicit WITHDRAWN stamp =
                 * voluntary death declaration by a force-shutdown FS.
                 * Confirmed via a cache-piercing re-read (same
                 * discipline as the stale-HB dead-confirm below), it
                 * skips the 31-sample window entirely — peers must start
                 * fence+replay within seconds, with the withdrawn node's
                 * grants frozen meanwhile.  This replaces the old
                 * withdraw_release_all instant-promotion (which handed
                 * peers the withdrawn node's TORN, unreplayed state —
                 * PROVEN drc@16 r13 dirent→freed-inode dangle).
                 */
                /* sess182: fire on FIRST SIGHT — no prior-liveness
                 * requirement.  A WITHDRAWN record left by a node that died
                 * (or unmounted) before this monitor ever tracked it is
                 * still a dirty slice needing fence+replay; requiring
                 * `monitored && live` made a no-survivor withdrawn slice
                 * permanently unreachable (the !monitored arm below just
                 * skips it).  The recovery_pending latch above prevents
                 * re-fire once recovery starts, and the WITHDRAWN record
                 * itself names the victim — no tracking state is needed. */
                if (rr == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
                    rhb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN &&
                    !hb_gen_foreign(ctx, rhb)) {
                    mxfs_pal_mutex_lock(ctx->lock);
                    crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
                                                  sizeof(*rhb));
                    mxfs_pal_mutex_unlock(ctx->lock);
                    if (crr == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
                        rhb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: P163-WITHDRAW-SEEN slot=%u node=%u — "
                            "peer declared voluntary death (FS shutdown); "
                            "initiating recovery now",
                            slot, rhb->node_id);
                        /* The WITHDRAWN record is the victim's OWN final
                         * record, so its stamp names the victim directly —
                         * no successor is involved and nothing is rebased. */
                        nt->last_epoch = rhb->epoch;
                        victim_node = rhb->node_id;
                        victim_epoch = rhb->epoch;
                        goto fire_dead;
                    }
                }

                /*
                 * sess346 (#92, ruling item 2): CLEAN DEPARTURE.  A tracked
                 * slot reading FLAG_EMPTY with the stamp of the occupant we
                 * were monitoring is mxfs_disklock_release_slot's clean
                 * unmount, not a death.  Before this arm the EMPTY record
                 * fell into the inactive branch below, accumulated
                 * equal_samples, and fired the FULL death machinery —
                 * expire_cb → per-node fence → recovery election — against
                 * a node that said goodbye properly (the sess342 31-way
                 * mass-unmount false-death storm).  FUA-confirm the stamp
                 * (a successor's claim CAS may have landed between the
                 * plain read and now), then retire the tracking state
                 * quietly: no fence, no expire_cb, no pending latch, and
                 * the sector is left untouched (peers still need the stamp
                 * for their own matching; the next claimant consumes it).
                 */
                if (rr == 0 && ctx->monitored[slot] &&
                    hb_clean_empty_match(ctx, rhb, victim_node,
                                         nt->last_epoch)) {
                    mxfs_pal_mutex_lock(ctx->lock);
                    crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
                                                  sizeof(*rhb));
                    mxfs_pal_mutex_unlock(ctx->lock);
                    if (crr == 0 &&
                        hb_clean_empty_match(ctx, rhb, victim_node,
                                             nt->last_epoch)) {
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: P163-CLEAN-DEPART slot=%u node=%u "
                            "inc=%llu — clean slot release observed (FUA "
                            "confirmed); retiring tracking WITHOUT recovery",
                            slot, victim_node,
                            (unsigned long long)nt->last_epoch);
                        if (ctx->clean_depart_cb)
                            ctx->clean_depart_cb(ctx->clean_depart_cb_data,
                                                 (int)slot, victim_node,
                                                 nt->last_epoch);
                        nt->last_epoch      = 0;
                        nt->last_timestamp  = 0;
                        nt->live            = false;
                        nt->changed_samples = 0;
                        nt->equal_samples   = 0;
                        nt->evict_seen      = false;
                        nt->seq_seen        = false;
                        ctx->monitored[slot] = false;
                        continue;
                    }
                    /* Confirm refuted the EMPTY (successor claimed it, or
                     * the read failed): fall through and classify whatever
                     * the confirm read actually returned. */
                }

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

                /*
                 * Epoch change = the slot changed hands (the occupant
                 * rebooted, or a different node claimed a released slot).
                 *
                 * sess86.  This arm used to adopt the SUCCESSOR incarnation
                 * into nt->last_epoch and then jump to fire_dead, leaving
                 * every consumer that read node_track back to name the LIVE
                 * successor as the victim.  Under required incarnation
                 * matching that is not a cosmetic mislabel — it lays a
                 * recovery guard on a live member and freezes it.  The victim
                 * is captured HERE, before anything is rebased, and the
                 * successor is picked up again only after the death has been
                 * dispatched (see the rebase block at fire_dead).
                 */
                if (nt->last_epoch != 0 &&
                    !inc_eq(rhb->epoch, nt->last_epoch)) {
                    bool already;

                    victim_epoch = nt->last_epoch;
                    /* victim_node is the PRE-scan snapshot: the auto-monitor
                     * re-arm above may already have retargeted
                     * slot_node_id[] at the successor. */
                    rebase_inc   = true;
                    rebase_epoch = rhb->epoch;
                    rebase_ts    = rhb->timestamp_ms;
                    rebase_node  = rhb->node_id;

                    mxfs_pal_mutex_lock(ctx->lock);
                    already = ctx->recovery_pending[slot] &&
                              ctx->pending_node[slot] == victim_node &&
                              inc_eq(ctx->pending_epoch[slot], victim_epoch);
                    mxfs_pal_mutex_unlock(ctx->lock);

                    if (already) {
                        /*
                         * We already declared this exact incarnation dead and
                         * its recovery is in flight.  Re-declaring it would
                         * re-enter the expire path, whose FIRST act is a
                         * per-NODE fence — and the node is live again as the
                         * successor.  Just resume tracking the successor.
                         */
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: P237-SLOT-REOCCUPIED slot=%u node=%u "
                            "victim_inc=%llu new_inc=%llu new_node=%u — "
                            "successor tenancy observed while the "
                            "predecessor's recovery is still pending; "
                            "tracking the successor, NOT re-declaring the "
                            "death",
                            slot, victim_node,
                            (unsigned long long)victim_epoch,
                            (unsigned long long)rebase_epoch, rebase_node);
                        /* sess346 #92: the tracked seq names the PREDECESSOR;
                         * drop it so the fresh-HB block re-seeds from the
                         * successor's own provenance. */
                        nt->seq_seen = false;
                        goto rebase_only;
                    }

                    /*
                     * sess346 (#92, ruling items 8+9): the successor's
                     * provenance can PROVE the predecessor departed cleanly
                     * even though we never saw the intermediate EMPTY (the
                     * release and the re-claim both landed inside one
                     * monitor interval).  The successor's chain covers every
                     * tenancy back to the last dirty consume: tracked seq S
                     * within [S' - chain, S' - 1] of the new record means
                     * the tenancy we were tracking ended in a clean release
                     * that a later claim consumed.  Unsigned arithmetic is
                     * wrap-safe; seq_seen gates against an untracked
                     * predecessor (pre-carve record or mid-tenure join),
                     * which conservatively fires instead.
                     */
                    if (nt->seq_seen && hb_prov_valid(rhb) &&
                        rhb->prov.chain_len > 0) {
                        uint64_t d = rhb->prov.slot_seq - nt->last_seq;

                        if (d >= 1 && d <= rhb->prov.chain_len) {
                            mxfs_pal_log(MXFS_LOG_WARN,
                                "mxfs: P163-CLEAN-DEPART-LINEAGE slot=%u "
                                "node=%u inc=%llu — successor (node=%u "
                                "inc=%llu seq=%llu chain=%u) proves the "
                                "predecessor's clean release; retiring it "
                                "WITHOUT recovery",
                                slot, victim_node,
                                (unsigned long long)victim_epoch,
                                rebase_node,
                                (unsigned long long)rebase_epoch,
                                (unsigned long long)rhb->prov.slot_seq,
                                rhb->prov.chain_len);
                            if (ctx->clean_depart_cb)
                                ctx->clean_depart_cb(
                                    ctx->clean_depart_cb_data,
                                    (int)slot, victim_node, victim_epoch);
                            /* Seed the tracked seq from the successor —
                             * rebase_only resets everything else but
                             * deliberately not these two. */
                            nt->last_seq = rhb->prov.slot_seq;
                            nt->seq_seen = true;
                            goto rebase_only;
                        }
                    }

                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: node in slot %u has restarted "
                        "(detected epoch change from %llu to %llu), "
                        "reclaiming its resources",
                        slot, (unsigned long long)victim_epoch,
                        (unsigned long long)rebase_epoch);
                    goto fire_dead;
                }

                if (rhb->timestamp_ms != nt->last_timestamp) {
                    /* Heartbeat is fresh */
                    nt->changed_samples++;
                    nt->equal_samples = 0;
                    nt->last_timestamp = rhb->timestamp_ms;
                    nt->last_epoch = rhb->epoch;
                    /* sess346 #92: record the occupant's slot_seq once per
                     * tenancy (provenance is constant per incarnation, so
                     * the first valid sighting is the whole story).  Every
                     * nt reset clears seq_seen so a new tenancy re-seeds. */
                    if (!nt->seq_seen && hb_prov_valid(rhb)) {
                        nt->last_seq = rhb->prov.slot_seq;
                        nt->seq_seen = true;
                    }

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

                /*
                 * sess42 C7 version gate — per-pass validation of every LIVE
                 * current-generation record (not just live-transitions: an
                 * epoch change, a slot reuse, or a peer that was live before
                 * our boot must all be caught; the read is already in hand so
                 * this costs one crc32c per live slot per pass).  A live
                 * incarnation without a valid equal-generation feature block
                 * is protocol-incompatible: confirm on a priority re-read of
                 * the SAME incarnation (transient corruption / stale cache
                 * must not shoot a healthy node), then fence it exactly once
                 * per (slot, epoch).  Fencing only arms after our own join
                 * gate admitted us — a joiner facing an established
                 * incompatible cluster withdraws instead (join_gate).
                 */
                if (nt->live && ctx->vergate_cb && ctx->vergate_admitted &&
                    rhb->magic == MXFS_DISKLOCK_MAGIC &&
                    rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                    !hb_gen_foreign(ctx, rhb) &&
                    hb_feature_state(rhb) != MXFS_HBFEAT_OK &&
                    !(ctx->vergate_fenced[slot] &&
                      ctx->vergate_fenced_epoch[slot] == rhb->epoch)) {
                    int vfst;

                    mxfs_pal_mutex_lock(ctx->lock);
                    crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
                                                  sizeof(*rhb));
                    mxfs_pal_mutex_unlock(ctx->lock);
                    vfst = (crr == 0) ? hb_feature_state(rhb) : MXFS_HBFEAT_OK;
                    if (crr == 0 && vfst != MXFS_HBFEAT_OK &&
                        rhb->magic == MXFS_DISKLOCK_MAGIC &&
                        rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
                        !hb_gen_foreign(ctx, rhb) &&
                        rhb->epoch == nt->last_epoch) {
                        ctx->vergate_fenced[slot] = true;
                        ctx->vergate_fenced_epoch[slot] = rhb->epoch;
                        mxfs_pal_log(MXFS_LOG_ERR,
                            "mxfs: P-VERGATE slot=%u node=%u epoch=%llu "
                            "state=%d (1=legacy 2=mismatch 3=corrupt) "
                            "proto_gen=%u ours=%u — live protocol-"
                            "incompatible member, fencing",
                            slot, rhb->node_id,
                            (unsigned long long)rhb->epoch, vfst,
                            rhb->feat.proto_gen, (unsigned)MXFS_PROTO_GEN);
                        ctx->vergate_cb(ctx->vergate_cb_data, (int)slot,
                                        rhb->node_id, rhb->epoch, vfst);
                    }
                }

check_dead:
                /* Reached by fall-through or by the inactive/garbage goto:
                 * the occupant we were tracking simply stopped.  No successor
                 * is in play, so the victim IS what node_track still holds. */
                victim_epoch = nt->last_epoch;
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
                    /*
                     * sess346 (#92, ruling item 3): the confirm read shows
                     * the victim's own CLEAN RELEASE STAMP — the release
                     * landed between the plain read (which still said
                     * ACTIVE/stale) and this confirm.  The old arm only
                     * cancelled on ACTIVE + advanced timestamp, so this
                     * window still fired death on a clean unmount.  Same
                     * clean retire as the monitor arm: no fence, no
                     * expire_cb, no pending latch.
                     */
                    if (crr == 0 &&
                        hb_clean_empty_match(ctx, rhb, victim_node,
                                             victim_epoch)) {
                        mxfs_pal_log(MXFS_LOG_WARN,
                            "mxfs: P163-CLEAN-DEPART-CONFIRM slot=%u node=%u "
                            "inc=%llu — dead-confirm read found the clean "
                            "release stamp; retiring tracking WITHOUT "
                            "recovery",
                            slot, victim_node,
                            (unsigned long long)victim_epoch);
                        if (ctx->clean_depart_cb)
                            ctx->clean_depart_cb(ctx->clean_depart_cb_data,
                                                 (int)slot, victim_node,
                                                 victim_epoch);
                        nt->last_epoch      = 0;
                        nt->last_timestamp  = 0;
                        nt->live            = false;
                        nt->changed_samples = 0;
                        nt->equal_samples   = 0;
                        nt->evict_seen      = false;
                        nt->seq_seen        = false;
                        ctx->monitored[slot] = false;
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
                    nt->seq_seen = false;       /* sess346 #92: tenancy over */

                    /* Bug 108: never use rhb->node_id here.  When the
                     * heartbeat sector has been zeroed (by
                     * disklock_purge_node) or the read failed, rhb->node_id
                     * is 0.  victim_node is the pre-scan snapshot of
                     * slot_node_id[], which monitor_node()/the auto-monitor
                     * set — and, unlike slot_node_id[] itself, it cannot have
                     * been retargeted at a successor earlier in this pass
                     * (sess86). */
                    if (ctx->expire_cb)
                        ctx->expire_cb(ctx->expire_cb_data, victim_node,
                                       (int)slot, victim_epoch);
                }
rebase_only:
                /*
                 * sess86 — REBASE ONTO THE SUCCESSOR.
                 *
                 * fire_dead has just torn down this slot's tracking state
                 * (live = false, monitored = false).  When the death was
                 * detected *because* a successor incarnation appeared, that
                 * teardown must not leave the successor untracked: an ACTIVE
                 * record proves OWNERSHIP, not LIVENESS.  A node that claimed
                 * the slot and then died before its first heartbeat tick
                 * would otherwise never accumulate the changed_samples needed
                 * to become live, and check_dead — which requires nt->live —
                 * would never fire for it.  Its slice would be abandoned
                 * silently, with the predecessor's marker already cleared.
                 *
                 * So the successor inherits the slot's membership standing
                 * (live = true) rather than re-earning it, and enters the
                 * dead-detection state machine immediately: if it never
                 * advances its timestamp, equal_samples climbs to
                 * dead_threshold and it is declared dead on the normal path,
                 * FUA-confirmed like any other eviction.
                 */
                if (rebase_inc) {
                    nt->last_epoch     = rebase_epoch;
                    nt->last_timestamp = rebase_ts;
                    nt->equal_samples  = 0;
                    nt->changed_samples = 0;
                    nt->live           = true;
                    nt->evict_seen     = false;   /* successor ring restarts */
                    ctx->monitored[slot]    = true;
                    ctx->slot_node_id[slot] = rebase_node;
                }
                continue;  /* after check_dead/fire_dead/rebase_only labels */
            }
        }

        /* sess38: monitor-pass duration for the same P-HB-SLOW attribution
         * (32 peer reads share ctx->lock with the hb write). */
        hb_mon_ms = mxfs_pal_time_ms() - hb_t1;
        if (hb_mon_ms > 2 * MXFS_DISKLOCK_HB_INTERVAL_MS)
            mxfs_pal_log(MXFS_LOG_WARN,
                "mxfs: P-HB-MONSLOW slot=%d monitor_ms=%llu",
                ctx->local_slot, (unsigned long long)hb_mon_ms);

        /* Use condvar timed wait so mxfs_disklock_stop_heartbeat()
         * can wake us immediately instead of waiting up to 2s */
hb_blind_sleep:
        hb_stage_set(ctx, MXFS_HB_STAGE_SLEEP);
        mxfs_pal_mutex_lock(ctx->shutdown_lock);
        if (ctx->running)
            mxfs_pal_cond_timedwait(ctx->shutdown_cond,
                                    ctx->shutdown_lock,
                                    MXFS_DISKLOCK_HB_INTERVAL_MS);
        mxfs_pal_mutex_unlock(ctx->shutdown_lock);
    }

    /* Fence-path breaks leave ctx->running true with this thread gone —
     * park the stage at SLEEP so the watchdog does not report a stall
     * against a deliberately exited heartbeat. */
    hb_stage_set(ctx, MXFS_HB_STAGE_SLEEP);

    if (hb_blind.active)
        hb_blind_clear("shutdown");

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
    ctx->guard_slot = -1;
    ctx->running = false;
    /*
     * Draw the mount incarnation before ANY field of ours can be published.
     * There must be no window in which this ctx could write an ACTIVE record
     * carrying a zero incarnation — under proto_gen 3 that record would be
     * indistinguishable from a legacy writer and would be fenced.  A claim
     * later redraws for its own tenancy (see mxfs_disklock_claim_slot).
     */
    ctx->epoch = hb_draw_incarnation();
    if (!inc_valid(ctx->epoch)) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: no entropy for a mount incarnation — "
                     "refusing to create a disklock context (failing closed; "
                     "a zero incarnation is not a valid identity)");
        mxfs_pal_free(ctx);
        return NULL;
    }
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

    ctx->purge_lock = mxfs_pal_mutex_create();
    if (!ctx->purge_lock) {
        mxfs_pal_mutex_destroy(ctx->evict_lock);
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

void mxfs_disklock_set_snlocal(struct mxfs_disklock_ctx *ctx, bool snlocal)
{
    if (!ctx)
        return;
    /*
     * Write-time provenance only (sess184 ruling item 1): the marker must be
     * uniform across every record an incarnation ever writes, so it can only
     * be set before the first claim stamps a record.  Flipping it mid-tenure
     * would retroactively re-classify records already on the platter.
     */
    if (ctx->local_slot >= 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: set_snlocal(%d) REFUSED — slot %d already "
                     "claimed; the snlocal marker is write-time provenance "
                     "and cannot change mid-tenure",
                     snlocal ? 1 : 0, ctx->local_slot);
        return;
    }
    ctx->snlocal = snlocal;
}

void mxfs_disklock_set_slot_limit(struct mxfs_disklock_ctx *ctx, uint32_t limit)
{
    if (!ctx)
        return;
    /*
     * Claim-time bound only (D-LOG-SLICE-SHARED-MULTIWRITER): it decides
     * which slots a claim may take, so changing it after the claim cannot
     * retroactively legitimize the slot already held.  Set it before
     * mxfs_disklock_claim_slot, like snlocal.
     */
    if (ctx->local_slot >= 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: set_slot_limit(%u) REFUSED — slot %d already "
                     "claimed; the claim bound cannot change mid-tenure",
                     limit, ctx->local_slot);
        return;
    }
    ctx->slot_limit = limit;
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
    if (ctx->purge_lock)
        mxfs_pal_mutex_destroy(ctx->purge_lock);
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

    /* sess280 part D: stall watchdog.  Diagnostic only — a node without
     * one is fully functional, so creation failure is not fatal. */
    ctx->hb_pid = mxfs_pal_thread_pid(ctx->hb_thread);
    ctx->hb_watchdog = mxfs_pal_thread_create(disklock_hb_watchdog_fn, ctx);
    if (!ctx->hb_watchdog)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: heartbeat watchdog failed to start "
                     "(stall diagnostics unavailable this mount)");

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

    /* sess280 part D: the watchdog wakes from its 2s poll sleep and sees
     * running==false; its whole loop body is log-only, so a blocking join
     * is bounded at one poll interval. */
    if (ctx->hb_watchdog) {
        mxfs_pal_thread_join(ctx->hb_watchdog);
        ctx->hb_watchdog = NULL;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat stopped");
}

int mxfs_disklock_release_slot(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || ctx->local_slot < 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P278-RELEASE-EINVAL ctx=%d dev=%d slot=%d — "
                     "release_slot has nothing to operate on",
                     ctx != NULL, ctx && ctx->dev != NULL,
                     ctx ? ctx->local_slot : -1);
        return -EINVAL;
    }
    if (ctx->running) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P278-RELEASE-EBUSY slot=%d — heartbeat still "
                     "running; stop_heartbeat first",
                     ctx->local_slot);
        return -EBUSY;      /* stop_heartbeat first — no racing rewrites */
    }

    cur  = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }

    off = ctx->base_offset +
          (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P278-RELEASE-READFAIL slot=%d rc=%d — cannot "
                     "read our record back; leaving it untouched",
                     ctx->local_slot, rc);
        goto out;
    }

    /*
     * Only clear a record that is still OURS — an evicted/re-claimed slot
     * belongs to someone else's story now.
     *
     * sess78: magic+node_id alone was NOT that test.  A recovery guard keeps
     * the victim's magic and node_id byte for byte and only moves `flags`
     * (mxfs_disklock_recovery_begin rule 2), so this path used to sail past
     * the check and blind-write flags=0 straight over a live recovery
     * descriptor — the same clobber the heartbeat did, just once at unmount.
     * hb_own_record() tests flags/epoch/fs_gen too, and the clear is a CAS
     * from the exact image we just read, so a recovery that lands inside the
     * read→write window loses nothing either.
     */
    if (!hb_own_record(ctx, cur)) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P236-RELEASE-REFUSED slot=%d node=%u — %s; "
                     "leaving the sector untouched",
                     ctx->local_slot, ctx->local_node,
                     hb_foreign_kind(ctx, cur));
        rc = -ESTALE;
        goto out;
    }

    *want = *cur;
    want->flags = MXFS_DISKLOCK_FLAG_EMPTY;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, cur, want);
    if (rc == -EOPNOTSUPP)
        rc = write_sector_fua(ctx, off, want);
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == 0) {
        ctx->hb_img_valid = false;      /* the slot is no longer ours */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "disklock: released heartbeat slot %d (clean teardown)",
                     ctx->local_slot);
    } else if (rc == -EAGAIN) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P236-RELEASE-RACE slot=%d node=%u — the "
                     "sector changed between our read and our CAS (a recovery "
                     "took the slot); not clearing it",
                     ctx->local_slot, ctx->local_node);
    } else {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: slot %d release write failed: %d",
                     ctx->local_slot, rc);
    }
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
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

/*
 * ── sess69: the purge publication is an EXACT-IMAGE CAS, never a plain
 *    write (GPT sess68 refusal 4) ──
 *
 * Zeroing a sector in mxfs_disklock_purge_node() is a PUBLICATION.  On a lock
 * record it releases the dead node's grant; on the heartbeat sector it
 * declares the node consumable and hands the slot back to the claim scan.
 * The code did read_sector() then write_sector() — a read-modify-write with
 * no interlock against the other survivors running the identical purge for
 * the same dead node (six call sites; mount.c's peer-death handlers run one
 * on EVERY survivor).  The losing interleaving needs no exotic timing:
 *
 *     P1 reads slot S      -> the dead node's ACTIVE grant
 *     P2 reads slot S      -> the same image
 *     P2 writes zero       -> S is free
 *     live node E claims S -> writes its own ACTIVE grant
 *     P1 writes zero       -> E's LIVE grant is destroyed
 *
 * E then believes it holds a lock that no longer exists on disk, so the same
 * resource can be granted twice.  The heartbeat variant is worse: the late
 * zero erases a LIVE node's heartbeat record, every peer declares that node
 * dead, and the cluster fences it and replays its journal slice while it is
 * still writing to the LUN.
 *
 * CAS closes it — we only zero the exact image whose predicate we evaluated.
 * -EAGAIN (MISCOMPARE) means the sector moved under us, so the decision was
 * derived from a stale image and must be re-derived from the new one.
 *
 * -EOPNOTSUPP means mxfs_bdev_to_sdev() found no SCSI device behind the bdev
 * at all, so this is not a shared LUN and no second purger can exist.  Fall
 * back to the plain write and COUNT it, rather than failing every purge on a
 * single-node/user-mode device.
 */
#define MXFS_PURGE_CAS_RETRIES  4

static int purge_cas_zero(struct mxfs_disklock_ctx *ctx, uint64_t off,
                          const void *expect, const void *zerobuf,
                          int *nonatomic)
{
    int rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expect, zerobuf);

    if (rc == -EOPNOTSUPP) {
        (*nonatomic)++;
        rc = write_sector(ctx, off, zerobuf);
    }
    return rc;
}

/*
 * Does `hb` carry a recovery lease covering `node_id`, and does its
 * descriptor permit THIS node to consume the victim's state right now?
 * -ENOENT = no covering lease (not a refusal), 0 = permitted, anything
 * else = covered but frozen.  Shared by the phase-0 freeze gate, the
 * mid-scan authority revalidation, and purge_hb_zeroable so the three
 * decisions can never drift apart.
 */
static int purge_recov_gate(struct mxfs_disklock_ctx *ctx,
                            const struct mxfs_disklock_heartbeat *hb,
                            mxfs_node_id_t node_id)
{
    const struct mxfs_recov_desc *d;

    if (hb->magic != MXFS_DISKLOCK_MAGIC ||
        !recov_lease_covers_node(hb, node_id))
        return -ENOENT;
    d = recov_desc_of(hb);
    if (!d)
        return -EPROTO;                 /* torn/newer protocol — never guess */
    if (d->flags & MXFS_RECOV_F_QUARANTINED)
        return -EPERM;                  /* terminal */
    if (d->stage < MXFS_RECOV_STAGE_GRANTS_RELEASED)
        return -EBUSY;                  /* authority not released yet */
    if (d->owner_node != ctx->local_node ||
        !inc_eq(d->owner_epoch, ctx->epoch))
        return -EBUSY;                  /* the owner's act, not ours */
    return 0;
}

/*
 * May `hb` — a freshly read heartbeat sector image — be zeroed as part of
 * purging `node_id`?  0 = yes, -ENOENT = not this victim's sector (keep
 * scanning), anything else = it IS this victim's sector but is frozen.
 *
 * sess69: this repeats the phase-0 freeze gate on the image the CAS then
 * publishes against.  Phase 0 decides from a read taken BEFORE the 65536-
 * record scan, and the old zero pass re-checked only "does the descriptor
 * name this victim" — not its stage or owner.  A descriptor that advanced,
 * changed owner or became unreadable in between was therefore published
 * anyway, defeating the gate.  Deciding here and CASing this exact image
 * makes "the gate says consumable" and "the sector is zeroed" one step.
 */
static int purge_hb_zeroable(struct mxfs_disklock_ctx *ctx,
                             const struct mxfs_disklock_heartbeat *hb,
                             mxfs_node_id_t node_id)
{
    if (hb->magic != MXFS_DISKLOCK_MAGIC)
        return -ENOENT;

    /* Plain member record: ACTIVE, or the sess9 voluntary WITHDRAWN stamp. */
    if ((hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
         hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) &&
        hb->node_id == node_id)
        return 0;

    /* A recovery lease over this victim: zeroing it IS the CONSUMABLE
     * publication, so it is ours to make only at GRANTS_RELEASED and only
     * while we still own the recovery. */
    return purge_recov_gate(ctx, hb, node_id);
}

/*
 * sess59 (GPT sess57 review item 6D): this used to swallow EVERY I/O
 * failure and always return a success-shaped count.
 *
 * Two of the failures it swallowed are load-bearing.  Zeroing the dead
 * node's heartbeat sector IS the cluster-wide "slice replay done"
 * broadcast — the thing that releases every peer's deferred purge — and a
 * failed write there left the record ACTIVE while the caller went on to
 * log RECOVERY-COMPLETE.  And a read failure on a lock-record sector
 * meant we could not prove the sector was not an ACTIVE grant owned by
 * the dead node, yet the sector was skipped and counted as clean.
 *
 * An incomplete purge is not a purge.  Report:
 *   >= 0  every sector was readable, every ACTIVE record owned by
 *         node_id was zeroed, and the heartbeat sector is provably not
 *         ACTIVE/WITHDRAWN for this node (either zeroed here or already
 *         gone).  Value is the lock-record count, as before.
 *   < 0   the purge could not be proven complete.  The caller must NOT
 *         treat this node's recovery as published.
 */
int mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx,
                              mxfs_node_id_t node_id)
{
    uint8_t *buf;
    uint8_t *zerobuf;
    int purged = 0;
    int rd_fail = 0;
    int wr_fail = 0;
    int hb_rd_fail = 0;
    int hb_wr_fail = 0;
    int hb_found = 0;
    int nonatomic = 0;
    uint32_t first_rd_fail = 0;
    int first_rc = 0;
    uint32_t slot;
    int rc;
    int gate_found = 0;
    uint64_t gate_off = 0;
    uint64_t gate_check_ms = 0;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    buf = mxfs_pal_alloc(512);
    zerobuf = mxfs_pal_alloc(512);
    if (!buf || !zerobuf) {
        mxfs_pal_free(buf);
        mxfs_pal_free(zerobuf);
        return -ENOMEM;
    }

    /*
     * sess224 (D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION): the whole purge used
     * to run under ONE ctx->lock hold — a 65536-sector FUA scan that starved
     * the heartbeat writer for ~35s (P-HB-SLOW lockwait_ms=34978), more than
     * half the 62s lease.  Now purge_lock serializes concurrent purges
     * (the heartbeat writer NEVER takes it) and ctx->lock is taken per-I/O,
     * so the hb writer interleaves freely.  Order: purge_lock -> ctx->lock,
     * never the reverse.
     */
    mxfs_pal_mutex_lock(ctx->purge_lock);

    /*
     * ── sess65 phase 0: the VICTIM-MANIFEST FREEZE gate (GPT rule 4) ──
     *
     * Locate the victim's heartbeat sector and decide whether its state may
     * be consumed AT ALL — before a single record is zeroed.  The old order
     * (purge the 65536 lock records, then look at the heartbeat) destroys
     * the authority manifest the foreign-replay token gate reads and only
     * afterwards discovers it was not allowed to.
     *
     * The gate refuses when the sector carries a recovery descriptor that is
     *   - unreadable (torn, or a newer protocol generation) — never guess;
     *   - QUARANTINED — terminal; losing the slot's capacity is the correct
     *     failure, silently publishing undischarged obligations is not;
     *   - below GRANTS_RELEASED — the recovery has not released the victim's
     *     authority yet, so nothing about it is consumable;
     *   - owned by another survivor — the final zero is the recovery owner's
     *     act, serialized with its stage CASes.
     */
    {
        uint32_t s;

        for (s = 0; s < MXFS_DISKLOCK_HB_SLOTS; s++) {
            uint64_t hb_off = ctx->base_offset +
                              (uint64_t)s * MXFS_DISKLOCK_RECORD_SIZE;
            struct mxfs_disklock_heartbeat *chb;

            mxfs_pal_mutex_lock(ctx->lock);
            rc = read_sector(ctx, hb_off, buf);
            mxfs_pal_mutex_unlock(ctx->lock);
            if (rc < 0)
                continue;       /* counted for real in the zeroing pass */
            chb = (struct mxfs_disklock_heartbeat *)buf;
            rc = purge_recov_gate(ctx, chb, node_id);
            if (rc == -ENOENT)
                continue;       /* no covering lease on this sector */
            if (rc) {
                const struct mxfs_recov_desc *d = recov_desc_of(chb);

                mxfs_pal_log(MXFS_LOG_WARN,
                    "disklock: P234-PURGE-FROZEN node=%u slot=%u stage=%d "
                    "owner=%d rc=%d — the victim's authority manifest is "
                    "frozen by a live recovery descriptor; NOTHING purged "
                    "and nothing may be published",
                    node_id, s, d ? (int)d->stage : -1,
                    d ? (int)d->owner_node : -1, rc);
                mxfs_pal_mutex_unlock(ctx->purge_lock);
                mxfs_pal_free(buf);
                mxfs_pal_free(zerobuf);
                return rc;
            }
            gate_found = 1;
            gate_off = hb_off;
            gate_check_ms = mxfs_pal_time_ms();
            break;
        }
    }

    for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS; slot++) {
        uint64_t offset = lock_slot_offset(ctx, slot);
        struct mxfs_disklock_record *rec;

        /*
         * Amortized authority revalidation (~every 2s of scan): with
         * ctx->lock no longer held across the scan, the recovery
         * descriptor can move while we work.  Re-derive the phase-0 gate
         * from its sector so a purge whose authority was lost mid-scan
         * stops publishing instead of finishing on stale authority.
         */
        if (gate_found &&
            mxfs_pal_time_ms() - gate_check_ms > 2000) {
            gate_check_ms = mxfs_pal_time_ms();
            mxfs_pal_mutex_lock(ctx->lock);
            rc = read_sector(ctx, gate_off, buf);
            mxfs_pal_mutex_unlock(ctx->lock);
            if (rc == 0) {
                rc = purge_recov_gate(ctx,
                        (const struct mxfs_disklock_heartbeat *)buf, node_id);
                if (rc == -ENOENT) {
                    /* Lease gone: consumed/published elsewhere.  The plain
                     * member-record purge needs no descriptor authority. */
                    gate_found = 0;
                } else if (rc) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                        "disklock: P234-PURGE-REFROZE-MIDSCAN node=%u "
                        "slot=%u purged=%d rc=%d — recovery descriptor "
                        "changed under the scan; purge STOPPED and recovery "
                        "is NOT published",
                        node_id, slot, purged, rc);
                    mxfs_pal_mutex_unlock(ctx->purge_lock);
                    mxfs_pal_free(buf);
                    mxfs_pal_free(zerobuf);
                    return rc;
                }
            }
            /* Unreadable gate sector: keep scanning; the zeroing pass
             * counts I/O failures for real and refuses publication. */
        }

        mxfs_pal_mutex_lock(ctx->lock);
        rc = read_sector(ctx, offset, buf);
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0) {
            /* Unreadable: may be an ACTIVE grant owned by the dead
             * node.  Keep scanning (one bad sector must not abandon
             * the other 65535) but remember that this pass is not a
             * proof of completeness. */
            if (!rd_fail) {
                first_rd_fail = slot;
                first_rc = rc;
            }
            rd_fail++;
            continue;
        }

        rec = (struct mxfs_disklock_record *)buf;

        if (rec->magic == MXFS_DISKLOCK_MAGIC &&
            rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            rec->owner == node_id) {
            int tries;

            /* sess69: CAS the exact image we just validated.  On MISCOMPARE
             * the sector changed under us — re-read and re-decide, because
             * the new occupant may be a LIVE node (see purge_cas_zero). */
            for (tries = 0; ; tries++) {
                mxfs_pal_mutex_lock(ctx->lock);
                rc = purge_cas_zero(ctx, offset, buf, zerobuf, &nonatomic);
                mxfs_pal_mutex_unlock(ctx->lock);
                if (rc == 0) {
                    purged++;
                    break;
                }
                if (rc != -EAGAIN) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "disklock: purge write failed at slot %u: %d",
                                 slot, rc);
                    wr_fail++;
                    break;
                }
                if (tries >= MXFS_PURGE_CAS_RETRIES) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "disklock: P235-PURGE-CONTENDED slot=%u "
                                 "node=%u — the record still names the dead "
                                 "node after %d CAS retries; this purge is "
                                 "NOT complete",
                                 slot, node_id, tries);
                    wr_fail++;
                    break;
                }
                mxfs_pal_mutex_lock(ctx->lock);
                rc = read_sector(ctx, offset, buf);
                mxfs_pal_mutex_unlock(ctx->lock);
                if (rc < 0) {
                    /* Cannot prove the sector is not still the dead node's. */
                    if (!rd_fail) {
                        first_rd_fail = slot;
                        first_rc = rc;
                    }
                    rd_fail++;
                    break;
                }
                if (rec->magic != MXFS_DISKLOCK_MAGIC ||
                    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
                    rec->owner != node_id)
                    break;      /* no longer the dead node's — nothing to do */
            }
        }
    }

    /* Clear the node's heartbeat record — scan for actual slot */
    {
        uint32_t hb_slot;
        struct mxfs_disklock_heartbeat *phb;

        for (hb_slot = 0; hb_slot < MXFS_DISKLOCK_HB_SLOTS; hb_slot++) {
            uint64_t hb_off = ctx->base_offset +
                              (uint64_t)hb_slot * MXFS_DISKLOCK_RECORD_SIZE;
            mxfs_pal_mutex_lock(ctx->lock);
            rc = read_sector(ctx, hb_off, buf);
            mxfs_pal_mutex_unlock(ctx->lock);
            if (rc < 0) {
                /* An unread HB sector could be this node's — we cannot
                 * claim the broadcast was made. */
                hb_rd_fail++;
                continue;
            }
            phb = (struct mxfs_disklock_heartbeat *)buf;
            /* sess9 D2: also clear a WITHDRAWN stamp — zeroing the dead
             * node's HB sector is the cluster-wide "slice replay done"
             * signal that releases every peer's deferred local purge.
             *
             * sess65: and a RECOVERY_GUARD whose descriptor names the victim.
             * That sector IS the recovery record, so zeroing it is exactly
             * the CONSUMABLE transition.
             *
             * sess69: the gate is re-derived HERE, from the image the CAS
             * publishes against — phase 0 alone is not enough, because it
             * decides before the 65536-record scan and the descriptor can
             * move in between. */
            rc = purge_hb_zeroable(ctx, phb, node_id);
            if (rc == -ENOENT)
                continue;                       /* not this victim's sector */
            if (rc < 0) {
                /* It IS the victim's sector, but the gate re-evaluated on
                 * this image refuses.  Phase 0 let us through, so the state
                 * moved under us: report incompleteness — never publish. */
                mxfs_pal_log(MXFS_LOG_ERR,
                             "disklock: P235-PURGE-REFROZE node=%u slot=%u "
                             "rc=%d — the victim's recovery descriptor changed "
                             "between the freeze gate and the publication; the "
                             "slot is NOT zeroed and recovery is NOT published",
                             node_id, hb_slot, rc);
                hb_found = 1;
                hb_wr_fail = rc;
                break;
            }
            {
                int tries;

                hb_found = 1;
                for (tries = 0; ; tries++) {
                    mxfs_pal_mutex_lock(ctx->lock);
                    rc = purge_cas_zero(ctx, hb_off, buf, zerobuf, &nonatomic);
                    mxfs_pal_mutex_unlock(ctx->lock);
                    if (rc == 0)
                        break;
                    if (rc != -EAGAIN) {
                        mxfs_pal_log(MXFS_LOG_ERR,
                                     "disklock: purge heartbeat failed "
                                     "for node %u slot %u: %d",
                                     node_id, hb_slot, rc);
                        hb_wr_fail = rc;
                        break;
                    }
                    if (tries >= MXFS_PURGE_CAS_RETRIES) {
                        mxfs_pal_log(MXFS_LOG_ERR,
                                     "disklock: P235-PURGE-CONTENDED-HB "
                                     "node=%u slot=%u — the sector still needs "
                                     "publishing after %d CAS retries; "
                                     "recovery is NOT published",
                                     node_id, hb_slot, tries);
                        hb_wr_fail = -EAGAIN;
                        break;
                    }
                    mxfs_pal_mutex_lock(ctx->lock);
                    rc = read_sector(ctx, hb_off, buf);
                    mxfs_pal_mutex_unlock(ctx->lock);
                    if (rc < 0) {
                        hb_rd_fail++;
                        hb_wr_fail = rc;
                        break;
                    }
                    /* Re-derive the whole decision from the new image. */
                    rc = purge_hb_zeroable(ctx, phb, node_id);
                    if (rc == -ENOENT)
                        break;      /* already published by another survivor */
                    if (rc < 0) {
                        mxfs_pal_log(MXFS_LOG_ERR,
                                     "disklock: P235-PURGE-REFROZE node=%u "
                                     "slot=%u rc=%d — descriptor changed under "
                                     "the publication CAS; NOT published",
                                     node_id, hb_slot, rc);
                        hb_wr_fail = rc;
                        break;
                    }
                }
                break;
            }
        }
    }

    mxfs_pal_mutex_unlock(ctx->purge_lock);

    mxfs_pal_free(buf);
    mxfs_pal_free(zerobuf);

    if (rd_fail || wr_fail || hb_wr_fail || (!hb_found && hb_rd_fail)) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: P229-PURGE-INCOMPLETE node=%u purged=%d "
                     "rec_unread=%d (first slot=%u rc=%d) rec_wrfail=%d "
                     "hb_found=%d hb_unread=%d hb_wrfail=%d nonatomic=%d — "
                     "this node's recovery MUST NOT be published as complete",
                     node_id, purged, rd_fail, first_rd_fail, first_rc,
                     wr_fail, hb_found, hb_rd_fail, hb_wr_fail, nonatomic);
        return hb_wr_fail ? hb_wr_fail : -EIO;
    }

    if (nonatomic)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: P235-PURGE-NONATOMIC node=%u sectors=%d — the "
                     "device has no SCSI COMPARE AND WRITE, so %d of this "
                     "purge's publications were plain writes; safe only "
                     "because a non-SCSI bdev cannot be a shared LUN",
                     node_id, nonatomic, nonatomic);

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

    /* sess38 (P-HB-SLOW lockwait_ms=26726 root, D-RELABORT-...-SELFFENCE):
     * do NOT hold ctx->lock across the whole multi-slot read loop — under
     * device saturation 64 reads x ~400ms = a ~25s continuous hold that
     * starves the heartbeat writer toward the 62s lease (the test21
     * self-fence).  Per-slot lock/unlock (the monitor pass precedent)
     * bounds the writer's wait to ONE read; slot reads are 512B
     * device-atomic and need no cross-slot mutual exclusion. */
    for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS && found < max; slot++) {
        uint64_t offset = lock_slot_offset(ctx, slot);
        struct mxfs_disklock_record *rec;
        int rc;

        mxfs_pal_mutex_lock(ctx->lock);
        rc = read_sector(ctx, offset, buf);
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0)
            continue;

        rec = (struct mxfs_disklock_record *)buf;

        if (rec->magic == MXFS_DISKLOCK_MAGIC &&
            rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE) {
            memcpy(&records[found], rec, sizeof(*rec));
            found++;
        }
    }

    *count = found;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "disklock: read_all found %d active lock records", found);
    return 0;
}

/*
 * sess9 (ccloop c7ee71c6) D2 — voluntary death declaration ("withdraw").
 * The owning FS has force-shut down; its journal slice may hold committed
 * transactions whose buffers were only partially destaged (PROVEN drc@16
 * r13: ifree destaged, dirent-remove abandoned → durable dangling
 * dirent).  Peers MUST replay that slice before they touch anything we
 * held, and they must find out NOW, not after the 62 s stale-sample
 * window.  Stop our heartbeat, then stamp our own HB slot WITHDRAWN
 * (magic/node/fs_gen/epoch kept so the monitor can attribute and
 * generation-check it).  Peers' monitors treat a confirmed WITHDRAWN
 * stamp as instant death → fence → elected slice replay → purge; our
 * grants stay frozen until the replay lands.
 *
 * Sleeps (heartbeat thread join) — process context only.  If the stamp
 * write fails the peers still converge via the normal 62 s stale window;
 * the stamp is a latency optimization for correctness that is enforced
 * by the deferred-purge protocol regardless.
 */
void mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *hb, *cur;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || ctx->local_slot < 0)
        return;

    mxfs_disklock_stop_heartbeat(ctx);

    hb = mxfs_pal_alloc(sizeof(*hb));
    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!hb || !cur) {
        mxfs_pal_free(hb);
        mxfs_pal_free(cur);
        mxfs_pal_log(MXFS_LOG_WARN,
                     "disklock: withdraw stamp alloc failed — peers will "
                     "detect death via the stale-heartbeat window");
        return;
    }

    off = ctx->base_offset +
          (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;

    /*
     * sess78: the stamp used to be a BLIND write.  If a survivor had already
     * declared us dead and laid a recovery guard/descriptor on our slot (the
     * TCP-dead-but-disk-alive case this whole pipeline exists for), the
     * "voluntary death" stamp destroyed the recovery it was trying to trigger
     * — including a fence certificate whose SCSI-PR key is already consumed
     * and unrecoverable.  Read first, refuse if the slot is no longer ours,
     * and CAS from the exact image so a guard landing inside the window wins.
     */
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    if (rc == 0 && !hb_own_record(ctx, cur)) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P236-WITHDRAW-REFUSED slot=%d node=%u — %s; the "
                     "recovery that owns our slot already knows we are dead, "
                     "so the stamp is unnecessary and would destroy it",
                     ctx->local_slot, ctx->local_node,
                     hb_foreign_kind(ctx, cur));
        mxfs_pal_free(hb);
        mxfs_pal_free(cur);
        return;
    }

    memset(hb, 0, sizeof(*hb));
    hb->magic = MXFS_DISKLOCK_MAGIC;
    hb->flags = MXFS_DISKLOCK_FLAG_WITHDRAWN;
    hb->node_id = ctx->local_node;
    hb->fs_gen = ctx->fs_gen;
    hb->timestamp_ms = mxfs_pal_time_ms();
    hb->epoch = ctx->epoch;
    hb_feature_fill(ctx, hb);       /* sess42 C7 */

    mxfs_pal_mutex_lock(ctx->lock);
    if (rc == 0) {
        rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, cur, hb);
        if (rc == -EOPNOTSUPP)
            rc = write_sector_fua(ctx, off, hb);
    } else {
        /* The read failed — we cannot see the slot, but a peer that never
         * gets a death signal waits the full 62 s stale window over a node
         * that is already gone.  Stamp it; the risk is the pre-sess78 one
         * and strictly smaller than never declaring death at all. */
        rc = write_sector_fua(ctx, off, hb);
    }
    ctx->hb_img_valid = false;
    mxfs_pal_mutex_unlock(ctx->lock);
    mxfs_pal_free(cur);
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P163-WITHDRAW-STAMP slot=%d node=%u rc=%d — "
                 "voluntary death declared; peers will fence, replay our "
                 "slice, then purge",
                 ctx->local_slot, ctx->local_node, rc);
    mxfs_pal_free(hb);
}

void mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx,
                                    mxfs_disklock_recovered_cb cb, void *data)
{
    ctx->recovered_cb = cb;
    ctx->recovered_cb_data = data;
}

void mxfs_disklock_set_clean_depart_cb(struct mxfs_disklock_ctx *ctx,
                                       mxfs_disklock_clean_depart_cb cb,
                                       void *data)
{
    ctx->clean_depart_cb = cb;
    ctx->clean_depart_cb_data = data;
}

void mxfs_disklock_set_vergate_cb(struct mxfs_disklock_ctx *ctx,
                                  mxfs_disklock_vergate_cb cb, void *data)
{
    ctx->vergate_cb = cb;
    ctx->vergate_cb_data = data;
}

void mxfs_disklock_set_recov_outcome_cb(struct mxfs_disklock_ctx *ctx,
                                        mxfs_disklock_recov_outcome_cb cb,
                                        void *data)
{
    ctx->recov_outcome_cb = cb;
    ctx->recov_outcome_cb_data = data;
}

/*
 * sess42 C7 — join-time admission gate (contract in disklock.h).
 *
 * Classify every non-self HB slot once; slots that are ACTIVE, current
 * fs_gen, and carry a bad feature block are SUSPECTS.  A suspect only
 * blocks admission if it is provably LIVE (timestamp/epoch progression
 * across re-reads spanning >1 HB interval); an unchanged suspect after two
 * rechecks is a pre-gate corpse — the normal death/recovery pipeline owns
 * it, admission proceeds.  A live incompatible incumbent ⇒ -EPROTO: the
 * caller must WITHDRAW this mount (asymmetric policy: joiners never fence
 * established members; the established side's monitor fences intruders).
 */
int mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx,
                            uint32_t timeout_ms)
{
    struct mxfs_disklock_heartbeat *rhb;
    uint64_t sus_ts[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_epoch_t sus_epoch[MXFS_DISKLOCK_HB_SLOTS];
    uint8_t sus[MXFS_DISKLOCK_HB_SLOTS];   /* 0=no, 1=suspect */
    uint32_t slot, nsus = 0, recheck, waited = 0;
    int rc, fst;

    if (timeout_ms == 0)
        timeout_ms = 12000;

    rhb = mxfs_pal_alloc(sizeof(*rhb));
    if (!rhb)
        return -ENOMEM;
    memset(sus, 0, sizeof(sus));

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint64_t off;

        if ((int)slot == ctx->local_slot)
            continue;
        off = ctx->base_offset +
              (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0) {
            /* Fail closed on unreadable slots: cannot admit against an
             * unknown.  One retry below via the suspect path. */
            sus[slot] = 1;
            sus_ts[slot] = 0;
            sus_epoch[slot] = 0;
            nsus++;
            continue;
        }
        if (rhb->magic != MXFS_DISKLOCK_MAGIC ||
            rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
            hb_gen_foreign(ctx, rhb))
            continue;           /* empty / withdrawn corpse / ghost */
        fst = hb_feature_state(rhb);
        if (fst == MXFS_HBFEAT_OK)
            continue;
        sus[slot] = 1;
        sus_ts[slot] = rhb->timestamp_ms;
        sus_epoch[slot] = rhb->epoch;
        nsus++;
        mxfs_pal_log(MXFS_LOG_WARN,
            "mxfs: P-VERGATE-JOIN-SUSPECT slot=%u node=%u epoch=%llu "
            "state=%d — awaiting liveness verdict",
            slot, rhb->node_id, (unsigned long long)rhb->epoch, fst);
    }

    for (recheck = 0; nsus > 0 && recheck < 2; recheck++) {
        uint32_t nap = MXFS_DISKLOCK_HB_INTERVAL_MS + 1000;

        if (waited + nap > timeout_ms)
            break;
        mxfs_pal_sleep_ms(nap);
        waited += nap;

        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
            uint64_t off;

            if (!sus[slot])
                continue;
            off = ctx->base_offset +
                  (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
            mxfs_pal_mutex_lock(ctx->lock);
            rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
            mxfs_pal_mutex_unlock(ctx->lock);
            if (rc < 0)
                continue;       /* still unreadable — stays suspect */
            if (rhb->magic != MXFS_DISKLOCK_MAGIC ||
                rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
                hb_gen_foreign(ctx, rhb)) {
                sus[slot] = 0;  /* resolved: corpse cleared/withdrawn */
                nsus--;
                continue;
            }
            fst = hb_feature_state(rhb);
            if (fst == MXFS_HBFEAT_OK) {
                sus[slot] = 0;  /* compatible incarnation took the slot */
                nsus--;
                continue;
            }
            if (sus_ts[slot] == 0 && sus_epoch[slot] == 0) {
                /* First read of this slot failed earlier: this read is the
                 * BASELINE, not progression.  Stay suspect one more round. */
                sus_ts[slot] = rhb->timestamp_ms;
                sus_epoch[slot] = rhb->epoch;
                continue;
            }
            if (rhb->timestamp_ms != sus_ts[slot] ||
                rhb->epoch != sus_epoch[slot]) {
                mxfs_pal_log(MXFS_LOG_ERR,
                    "mxfs: P-VERGATE-JOIN slot=%u node=%u epoch=%llu "
                    "state=%d proto_gen=%u ours=%u — LIVE protocol-"
                    "incompatible incumbent; withdrawing (join refused)",
                    slot, rhb->node_id,
                    (unsigned long long)rhb->epoch, fst,
                    rhb->feat.proto_gen, (unsigned)MXFS_PROTO_GEN);
                mxfs_pal_free(rhb);
                return -EPROTO;
            }
        }
    }

    mxfs_pal_free(rhb);
    if (nsus > 0) {
        /* Unchanged across both rechecks (>1 HB interval each): pre-gate
         * corpses.  The death pipeline owns them; the monitor's per-pass
         * validation catches any that later turn out to be slow-writers. */
        mxfs_pal_log(MXFS_LOG_WARN,
            "mxfs: P-VERGATE-JOIN %u suspect slot(s) classified dead "
            "corpses — admitted; monitor enforcement armed", nsus);
    }
    ctx->vergate_admitted = true;
    return 0;
}

void mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx,
                                         int slot, mxfs_node_id_t node,
                                         mxfs_epoch_t victim_epoch)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return;
    /*
     * sess86: victim_epoch is an ARGUMENT.  This used to read
     * node_track[slot].last_epoch back, and the monitor's epoch-change arm
     * rebases that onto the SUCCESSOR before dispatching the predecessor's
     * death — so the marker named the live node as the victim, and under
     * required incarnation matching that match succeeds.
     */
    mxfs_pal_mutex_lock(ctx->lock);
    ctx->recovery_pending[slot] = true;
    ctx->pending_node[slot] = node;
    ctx->pending_epoch[slot] = victim_epoch;
    mxfs_pal_mutex_unlock(ctx->lock);
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P163-RECOVERY-PENDING slot=%d node=%u epoch=%llu — "
                 "purge deferred until slice replay completes%s",
                 slot, node, (unsigned long long)victim_epoch,
                 inc_valid(victim_epoch) ? "" :
                     " (incarnation UNOBSERVED — node-scoped)");
}

bool mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return false;
    return ctx->recovery_pending[slot];
}

/*
 * sess86 COMPARE-and-clear.  The pending marker is a promise about ONE
 * incarnation.  An unconditional clear lets the completion of victim A retire
 * a marker that has since been re-armed for victim B on the same slot — B's
 * slice is then never replayed and nothing records that it was owed.  The
 * window is real: A's recovery runs for seconds (fence + replay + purge +
 * flush), and the slot becomes claimable the moment A's sector is zeroed.
 */
int mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx,
                                         int slot, mxfs_node_id_t node,
                                         mxfs_epoch_t victim_epoch)
{
    mxfs_node_id_t hadn;
    mxfs_epoch_t hade;
    int rc;

    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    mxfs_pal_mutex_lock(ctx->lock);
    hadn = ctx->pending_node[slot];
    hade = ctx->pending_epoch[slot];
    if (!ctx->recovery_pending[slot]) {
        rc = -ENOENT;
    } else if (hadn != node) {
        rc = -ESTALE;
    } else if (inc_valid(victim_epoch) && inc_valid(hade) &&
               !inc_eq(hade, victim_epoch)) {
        /*
         * Same node, different incarnation: the marker was re-armed for a
         * SUCCESSOR while our recovery ran.  Leave it — the successor's slice
         * still owes a replay.
         */
        rc = -ESTALE;
    } else {
        ctx->recovery_pending[slot] = false;
        /* sess327: the descriptor is gone with the pending marker — re-arm
         * the item-8 corrupt-outcome alert for the slot's next occupant. */
        ctx->outcome_badcrc_alerted[slot] = false;
        rc = 0;
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == -ESTALE)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P237-PENDING-REARMED slot=%d — completion for "
                     "node=%u inc=%llu did NOT clear the marker, which now "
                     "names node=%u inc=%llu; that recovery is still owed",
                     slot, node, (unsigned long long)victim_epoch,
                     hadn, (unsigned long long)hade);
    return rc;
}

mxfs_node_id_t mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx,
                                          int slot)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return 0;
    return ctx->pending_node[slot];
}

int mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx,
                                        int prev, mxfs_node_id_t *node)
{
    int slot;

    if (!ctx)
        return -1;
    for (slot = prev + 1; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (ctx->recovery_pending[slot]) {
            if (node)
                *node = ctx->pending_node[slot];
            return slot;
        }
    }
    return -1;
}

mxfs_epoch_t mxfs_disklock_pending_epoch(struct mxfs_disklock_ctx *ctx,
                                         int slot)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return 0;
    return ctx->pending_epoch[slot];
}

/* ── sess65: DURABLE RECOVERY DESCRIPTOR — the milestone state machine ── */

/*
 * Replace a heartbeat sector by compare-and-write from the EXACT image the
 * caller observed, and make the result durable before returning.
 *
 * Durability is not optional here: the whole point of the FENCED milestone is
 * that it is on the platter before the first CAW purge destroys the evidence
 * a successor would need (GPT rule 1).  On a transport without CAW the write
 * is FUA'd and confirmed by a cache-piercing read-back of the descriptor we
 * just wrote — the same discipline claim_slot_noncaw and guard_slot use.
 *
 * A lost race is reported as -EAGAIN and NEVER retried here: the caller must
 * re-read and re-decide, because the sector may now be owned by a successor
 * that has already advanced past our stage.
 */
static int recov_cas_durable(struct mxfs_disklock_ctx *ctx, int slot,
                             const struct mxfs_disklock_heartbeat *expect,
                             const struct mxfs_disklock_heartbeat *want)
{
    struct mxfs_disklock_heartbeat *back;
    uint64_t off;
    int rc;

    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expect, want);
    if (rc == -EOPNOTSUPP) {
        rc = write_sector_fua(ctx, off, want);
        if (rc == 0) {
            back = mxfs_pal_alloc(sizeof(*back));
            if (!back) {
                rc = -ENOMEM;
            } else {
                mxfs_pal_sleep_ms(30);
                rc = mxfs_pal_bdev_read_prio(ctx->dev, off, back,
                                             sizeof(*back));
                /* sess323: verify the descriptor AND the outcome record —
                 * they are contiguous (asserted in disklock.h) and both
                 * carry state a torn write must not be reported as having
                 * landed. */
                if (rc == 0 &&
                    memcmp(&back->recov, &want->recov,
                           offsetof(struct mxfs_recov_body, pad)) != 0)
                    rc = -EAGAIN;
                mxfs_pal_free(back);
            }
        }
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == 0)
        rc = mxfs_pal_bdev_flush(ctx->dev);
    return rc;
}

/* Stamp `d` into `want` and seal it against the record's (victim) identity. */
static void recov_desc_seal(struct mxfs_disklock_heartbeat *want)
{
    want->recov.desc.crc32c = recov_desc_crc(want->fs_gen, want->node_id,
                                             want->epoch, &want->recov.desc);
}

/* Monotonic owner liveness stamp: never equal to, never behind, the previous
 * one — survivors detect abandonment by ABSENCE OF CHANGE, so a clock that
 * stalls or steps backwards must not be mistaken for a live owner. */
static uint64_t recov_stamp_after(uint64_t prev)
{
    uint64_t now = mxfs_pal_time_ms();

    return now > prev ? now : prev + 1;
}

/*
 * sess67 (GPT ruling item 7) — the authorization tuple.
 *
 * recov_auth_issue() hands the caller the identity of the recovery it now owns;
 * recov_auth_holds() is the check every stage-changing op runs against the
 * sector it just read.  The owner_term member is what closes the ABA hole:
 * {owner_node, owner_epoch} alone repeat exactly when A is taken over by B and
 * then takes it back within the same session, so a slow A worker holding a
 * pre-B auth would otherwise pass and resume writing under B's (or its own
 * newer) authority.
 *
 * A NULL auth is accepted only where the caller has no prior claim to check —
 * it degrades to the pre-sess67 owner-identity test and is never used by the
 * coordinator.
 */
static void recov_auth_issue(struct mxfs_recov_auth *auth,
                             const struct mxfs_recov_desc *d)
{
    if (!auth)
        return;
    auth->victim_node  = d->victim_node;
    auth->victim_epoch = d->victim_epoch;
    auth->recovery_gen = d->recovery_gen;
    auth->owner_term   = d->owner_term;
    auth->victim_slot  = d->victim_slot;
    auth->stage        = d->stage;
}

static bool recov_auth_holds(const struct mxfs_disklock_ctx *ctx,
                             const struct mxfs_recov_desc *d,
                             const struct mxfs_recov_auth *auth)
{
    if (d->owner_node != ctx->local_node ||
        !inc_eq(d->owner_epoch, ctx->epoch))
        return false;
    if (!auth)
        return true;
    /*
     * sess91: every field below is a TOKEN field — recov_auth_issue() copied it
     * verbatim out of this descriptor — so the test is exact encoded equality,
     * not an incarnation proof (see recov_tok_eq()).  victim_slot is compared
     * because the issuer has always copied it and nothing ever checked it: a
     * stale auth could otherwise pass against a DIFFERENT slot's descriptor
     * that happened to share victim node, generation and term.  That hazard is
     * not zero-specific — it applied to nonzero incarnations too.
     */
    return d->victim_slot  == auth->victim_slot &&
           d->victim_node  == auth->victim_node &&
           recov_tok_eq(d->victim_epoch, auth->victim_epoch) &&
           d->recovery_gen == auth->recovery_gen &&
           d->owner_term   == auth->owner_term;
}

int mxfs_disklock_recovery_begin(struct mxfs_disklock_ctx *ctx, int slot,
                                 mxfs_node_id_t victim,
                                 mxfs_epoch_t victim_epoch,
                                 uint16_t slice_idx, uint16_t slice_count,
                                 uint32_t flags,
                                 struct mxfs_recov_auth *out_auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim)
        return -EINVAL;

    /*
     * ── sess93: THIS FUNCTION IS OUT OF THE LIVE RECOVERY PATH ───────────
     *
     * It creates a descriptor that reaches MXFS_RECOV_STAGE_FENCED directly,
     * with fence_kind = MXFS_FENCE_KIND_NONE and no certificate.  That is
     * exactly the state every gate in this file refuses, and until sess93 it
     * was the ONLY descriptor the cluster ever published — which is why
     * D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION survived the sess74/75/76
     * campaign: the certificate was designed, given a wire format and a
     * proto_gen bump, and then never invoked (sess91: 0 callers).
     *
     * FENCED is now reached only through fence_intent() -> the PREEMPT AND
     * ABORT -> fence_certify(), and the execution lease only through
     * recovery_claim() / recovery_takeover().  GPT ruling (RULE 5, sess93,
     * correction 3): "recovery_begin() must leave the live recovery path — do
     * not retain it as a fallback.  Once certified descriptors exist its
     * -EBUSY behaviour is incompatible, and its direct production of
     * FENCED/NONE violates the protocol."
     *
     * The refusal is here, at the entry, rather than left to code review: a
     * function that can mint an uncertified fence record is one edit away from
     * reintroducing the defect, and a loud -EPROTO at the call is far cheaper
     * to diagnose than a slice replayed against a live writer.
     */
    mxfs_pal_log(MXFS_LOG_ERR,
        "disklock: P238-RECOV-BEGIN-RETIRED slot=%d victim=%u — "
        "recovery_begin() is retired: it mints a FENCED descriptor with NO "
        "fence certificate, which every replay gate must refuse.  Use "
        "fence_intent + PREEMPT AND ABORT + fence_certify to reach FENCED, "
        "then recovery_claim/recovery_takeover for the execution lease",
        slot, victim);
    return -EPROTO;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    if (recov_desc_present(cur)) {
        d = recov_desc_of(cur);
        if (!d) {
            mxfs_pal_log(MXFS_LOG_ERR,
                "disklock: P234-RECOV-UNREADABLE slot=%d victim=%u — the slot "
                "carries a recovery descriptor this build cannot validate "
                "(torn, or a newer protocol generation); refusing to touch it",
                slot, victim);
            rc = -EPROTO;
            goto out;
        }
        if (d->victim_node != victim) {
            rc = -ESTALE;
            goto out;
        }
        if (d->owner_node == ctx->local_node &&
            inc_eq(d->owner_epoch, ctx->epoch)) {
            recov_auth_issue(out_auth, d);
            rc = 0;             /* already ours — resume from d->stage */
            goto out;
        }
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P234-RECOV-OWNED slot=%d victim=%u owner=%u gen=%llu "
            "stage=%u — another survivor owns this recovery; not publishing",
            slot, victim, d->owner_node,
            (unsigned long long)d->recovery_gen, d->stage);
        rc = -EBUSY;
        goto out;
    }

    if (cur->magic != MXFS_DISKLOCK_MAGIC) {
        /* Zeroed sector: the recovery was already published by someone. */
        rc = -ENOENT;
        goto out;
    }
    if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
         cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
        cur->node_id != victim || hb_gen_foreign(ctx, cur)) {
        rc = -ESTALE;
        goto out;
    }
    /*
     * ── sess86: SUPERSESSION, not "drift" ────────────────────────────────
     *
     * This used to warn and then adopt the sector's incarnation, publishing a
     * recovery for whoever happened to occupy the slot.  With a constant-zero
     * epoch the branch was unreachable; with real incarnations it is the
     * common reboot case, and adopting means laying a RECOVERY_GUARD on a LIVE
     * member — freezing its authority and, via the self-fence check in
     * hb_cas_own_slot, forcing its filesystem down.
     *
     * A same-node, later, ACTIVE incarnation on this slot can only have got
     * there through the claim pass-1 own-stamp reclaim, which matches on
     * node_id alone.  That path sets slice_adopted = false, so the successor's
     * own mount recovery replayed the ENTIRE slice — including every record we
     * were about to replay.  The recovery is discharged; it is simply not ours
     * to publish.
     *
     * Everything else fails closed.  Supersession requires ALL of: a valid
     * feature block at the CURRENT proto_gen (a record we cannot fully
     * interpret proves nothing), flags == ACTIVE (a WITHDRAWN successor is
     * itself dead and owes its own replay — do not let its presence retire the
     * predecessor's marker), both incarnations nonzero (zero is never a
     * wildcard), and the two differing.  node_id, fs_gen and magic were
     * already proven above.
     */
    if (inc_valid(victim_epoch) && !inc_eq(cur->epoch, victim_epoch)) {
        int fst = hb_feature_state(cur);

        if (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            fst == MXFS_HBFEAT_OK &&
            inc_valid(cur->epoch)) {
            mxfs_pal_log(MXFS_LOG_WARN,
                "disklock: P237-RECOV-SUPERSEDED slot=%d victim=%u "
                "victim_inc=%llu slot_inc=%llu — the victim itself reclaimed "
                "this slot and its own mount recovery replayed the slice; "
                "retiring our pending recovery instead of guarding a LIVE "
                "member",
                slot, victim, (unsigned long long)victim_epoch,
                (unsigned long long)cur->epoch);
            rc = MXFS_RECOVERY_SUPERSEDED;
            goto out;
        }
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P237-RECOV-INC-MISMATCH slot=%d victim=%u "
            "victim_inc=%llu slot_inc=%llu flags=0x%x featstate=%d — the "
            "slot no longer carries the incarnation we were asked to recover "
            "and this is NOT a provable supersession; refusing to publish",
            slot, victim, (unsigned long long)victim_epoch,
            (unsigned long long)cur->epoch, cur->flags, fst);
        rc = -ESTALE;
        goto out;
    }
    if (!inc_valid(victim_epoch))
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P237-RECOV-INC-UNOBSERVED slot=%d victim=%u "
            "on-disk=%llu — the caller never observed the victim's "
            "incarnation; recording the SECTOR's (it is the authority for "
            "which incarnation last owned this slice)",
            slot, victim, (unsigned long long)cur->epoch);

    /*
     * Rule 2: the victim's identity is NEVER overwritten.  Everything the
     * victim wrote — node_id, fs_gen, epoch, its last timestamp, lock_count,
     * the §7.C mepoch authority record and the version-gate feature block —
     * is carried through byte for byte.  Only `flags` changes, and the
     * previously-dead evict-ring bytes become the descriptor.
     */
    *want = *cur;
    want->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
    memset(&want->recov, 0, sizeof(want->recov));
    want->recov.desc.magic          = MXFS_RECOV_DESC_MAGIC;
    want->recov.desc.version        = MXFS_RECOV_DESC_VERSION;
    want->recov.desc.stage          = MXFS_RECOV_STAGE_FENCED;
    want->recov.desc.victim_epoch   = cur->epoch;
    want->recov.desc.owner_epoch    = ctx->epoch;
    /*
     * The recovery TRANSACTION identity (rule 6).  1, not a counter, and
     * deliberately so: a descriptor is created at most once per victim
     * incarnation (begin() refuses when one already exists, and the sector is
     * only ever zeroed after GRANTS_RELEASED — after which the slot belongs to
     * a future incarnation with a different victim_epoch).  So the transaction
     * is named by {victim_node, victim_epoch, victim_slot, recovery_gen}, and
     * this field exists to stay CONSTANT while owner_term moves.  Do NOT turn
     * it back into a takeover counter — that is the ABA hole GPT rejected.
     */
    want->recov.desc.recovery_gen   = 1;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(0);
    want->recov.desc.victim_node    = victim;
    want->recov.desc.owner_node     = ctx->local_node;
    want->recov.desc.victim_fs_gen  = cur->fs_gen;
    want->recov.desc.flags          = flags |
        (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ?
             MXFS_RECOV_F_VICTIM_WITHDREW : 0) |
        (hb_victim_snlocal(cur) ? MXFS_RECOV_F_VICTIM_SNLOCAL : 0);
    want->recov.desc.victim_slot    = (uint16_t)slot;
    want->recov.desc.owner_slot     = (uint16_t)ctx->local_slot;
    want->recov.desc.slice_idx      = slice_idx;
    want->recov.desc.slice_count    = slice_count;
    want->recov.desc.stage_seq      = 1;
    want->recov.desc.owner_term     = 1;
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0) {
        recov_auth_issue(out_auth, &want->recov.desc);
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P234-RECOV-FENCED slot=%d victim=%u epoch=%llu "
            "slice=%u/%u owner=%u gen=%llu term=1 — durable recovery "
            "descriptor laid down; the victim's authority is now FROZEN "
            "until GRANTS_RELEASED",
            slot, victim, (unsigned long long)cur->epoch,
            slice_idx, slice_count, ctx->local_node,
            (unsigned long long)want->recov.desc.recovery_gen);
    } else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P234-RECOV-BEGIN-FAIL slot=%d victim=%u rc=%d — no "
            "fence record; nothing may be purged or published",
            slot, victim, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_advance(struct mxfs_disklock_ctx *ctx, int slot,
                                   unsigned int stage,
                                   const struct mxfs_recov_auth *auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        stage == MXFS_RECOV_STAGE_NONE || stage > MXFS_RECOV_STAGE_MAX)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
        goto out;
    }
    /*
     * sess76: the milestone ladder starts at FENCED, and the ONLY way to
     * reach FENCED is fence_certify().  Without this, a caller holding no
     * auth (NULL degrades to the owner-identity test) could advance its own
     * FENCING intent straight to FENCED — manufacturing a "fence" with
     * fence_kind still NONE.  The gate would catch it, but the state machine
     * must not be able to produce the lie in the first place.
     */
    if (d->stage < MXFS_RECOV_STAGE_FENCED ||
        stage <= MXFS_RECOV_STAGE_FENCED) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-RECOV-ADVANCE-PREFENCE slot=%d victim=%u %u->%u — "
            "the milestone ladder begins at a CERTIFIED FENCED descriptor; "
            "only mxfs_disklock_recovery_fence_certify() may reach it",
            slot, d->victim_node, d->stage, stage);
        rc = -EPERM;
        goto out;
    }
    if (!recov_auth_holds(ctx, d, auth)) {
        /*
         * sess91 — say WHICH test failed, and never assert a takeover we did
         * not observe.  The old wording claimed "we were taken over" for every
         * failure and printed only the owner tuple as its evidence; when the
         * token comparison was what failed, that produced two IDENTICAL tuples
         * offered as proof of a takeover, and cost a full rig investigation to
         * see through.  An owner mismatch IS a takeover; a token mismatch is a
         * stale/foreign auth; both mean the same thing for publication, and
         * neither may be guessed at in the log.
         */
        bool owner_ok = (d->owner_node == ctx->local_node) &&
                        inc_eq(d->owner_epoch, ctx->epoch);

        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P234-RECOV-NOTOURS slot=%d victim=%u stage->%u kind=%s "
            "— descriptor owner=%u/%llu gen=%llu term=%u vslot=%u vnode=%u "
            "vepoch=%llu; we are %u/%llu holding auth gen=%llu term=%u "
            "vslot=%u vnode=%u vepoch=%llu.  NOTHING we did may be published",
            slot, d->victim_node, stage,
            owner_ok ? "TOKEN-MISMATCH (stale or foreign auth)"
                     : "TAKEOVER (descriptor owner is not us)",
            d->owner_node, (unsigned long long)d->owner_epoch,
            (unsigned long long)d->recovery_gen, d->owner_term,
            d->victim_slot, d->victim_node,
            (unsigned long long)d->victim_epoch,
            ctx->local_node, (unsigned long long)ctx->epoch,
            auth ? (unsigned long long)auth->recovery_gen : 0ULL,
            auth ? auth->owner_term : 0u,
            auth ? auth->victim_slot : 0u,
            auth ? auth->victim_node : 0u,
            auth ? (unsigned long long)auth->victim_epoch : 0ULL);
        rc = -EBUSY;
        goto out;
    }
    if (d->flags & MXFS_RECOV_F_QUARANTINED) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P234-RECOV-QUARANTINED slot=%d victim=%u — this slice "
            "carries an obligation this build cannot discharge; the milestone "
            "state machine is terminal here and the slot never becomes "
            "consumable without operator action",
            slot, d->victim_node);
        rc = -EPERM;
        goto out;
    }
    if (stage <= d->stage) {
        rc = 0;                 /* monotonic: already at or past this stage */
        goto out;
    }

    *want = *cur;
    want->recov.desc.stage          = (uint16_t)stage;
    want->recov.desc.stage_seq      = d->stage_seq + 1;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0)
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P234-RECOV-STAGE slot=%d victim=%u %u->%u seq=%llu",
            slot, d->victim_node, d->stage, stage,
            (unsigned long long)want->recov.desc.stage_seq);
    else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P234-RECOV-STAGE-FAIL slot=%d victim=%u %u->%u rc=%d — "
            "the milestone is NOT durable; the caller must not act as if it is",
            slot, d->victim_node, d->stage, stage, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

/*
 * sess330: fill `want`'s outcome region as a TERMINAL REFUSED record bound
 * to descriptor `d` and the record's victim identity.  Shared by the lease
 * holder's publish path and the leaseless legacy backfill so the two can
 * never diverge in what a terminal record carries.  Touches ONLY the
 * outcome region; the caller owns any descriptor-side change (flag, stamp,
 * seal).  Deterministic for fixed inputs — the backfill path depends on
 * that (racing backfillers write identical bytes).
 */
static void recov_outcome_fill(struct mxfs_disklock_heartbeat *want,
                               const struct mxfs_recov_desc *d,
                               uint16_t reason, uint16_t domain_kind,
                               uint64_t ag_mask, bool digest_valid,
                               uint64_t slice_digest, uint64_t publish_seq,
                               uint32_t refused, uint32_t malformed)
{
    struct mxfs_recov_outcome *oc = &want->recov.outcome;

    memset(oc, 0, sizeof(*oc));
    oc->magic           = MXFS_RECOV_OUTCOME_MAGIC;
    oc->version         = MXFS_RECOV_OUTCOME_VERSION;
    oc->outcome         = MXFS_RECOV_OUTCOME_TERMINAL_REFUSED;
    oc->reason          = reason;
    oc->domain_kind     = domain_kind;
    oc->victim_slot     = d->victim_slot;
    oc->owner_slot      = d->owner_slot;
    oc->victim_epoch    = d->victim_epoch;
    oc->owner_epoch     = d->owner_epoch;
    oc->recovery_gen    = d->recovery_gen;
    oc->ag_mask         = domain_kind == MXFS_RECOV_DOMAIN_AG_MASK ?
                          ag_mask : 0;
    /* Ruling item 5: a failed forensic reread must not gate the verdict.
     * Publish with the DIGEST_VALID flag clear and the digest zeroed. */
    oc->flags           = digest_valid ?
                          MXFS_RECOV_OUTCOME_F_DIGEST_VALID : 0;
    oc->slice_digest    = digest_valid ? slice_digest : 0;
    oc->publish_seq     = publish_seq;
    oc->victim_node     = d->victim_node;
    oc->victim_fs_gen   = d->victim_fs_gen;
    oc->owner_node      = d->owner_node;
    oc->owner_term      = d->owner_term;
    oc->refused_items   = refused;
    oc->malformed_items = malformed;
    oc->crc32c = recov_outcome_crc(want->fs_gen, want->node_id,
                                   want->epoch, oc);
}

/*
 * sess323 (sess320 ruling): durably publish TERMINAL REFUSED for the victim
 * this auth covers.  Contract in disklock.h.  Authority discipline is
 * recovery_advance's; the write is quarantine-flag + outcome record in one
 * CAS, with the stage deliberately untouched.
 */
int mxfs_disklock_recovery_publish_refusal(struct mxfs_disklock_ctx *ctx,
                                    int slot,
                                    const struct mxfs_recov_auth *auth,
                                    const struct mxfs_recov_refusal_info *info,
                                    struct mxfs_recov_outcome *oc_out)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    const struct mxfs_recov_outcome *old_oc;
    struct mxfs_recov_outcome *oc;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !info)
        return -EINVAL;
    /* sess330 ruling: LEGACY_INTENT is NOT a publishable reason here.  No
     * recovery auth can ever exist over a QUARANTINED descriptor (the
     * claim path's certificate evaluator refuses it before the owner-
     * reacquire check), so the legacy backfill is leaseless by
     * construction and goes through
     * mxfs_disklock_recovery_backfill_legacy(), never this path. */
    if (info->reason != MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE &&
        info->reason != MXFS_RECOV_REFUSAL_PHYSICALLY_TORN)
        return -EINVAL;
    if (info->domain_kind != MXFS_RECOV_DOMAIN_FSWIDE &&
        info->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK)
        return -EINVAL;
    /* An empty AG mask quarantines nothing — that is not a refusal domain,
     * it is a bug in the caller's collection pass.  Refuse it rather than
     * publish a terminal record that enforces nothing. */
    if (info->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK && info->ag_mask == 0)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
        goto out;
    }
    if (!recov_auth_holds(ctx, d, auth)) {
        bool owner_ok = (d->owner_node == ctx->local_node) &&
                        inc_eq(d->owner_epoch, ctx->epoch);

        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P234-RECOV-NOTOURS slot=%d victim=%u op=refusal "
            "kind=%s — descriptor owner=%u/%llu gen=%llu term=%u; we are "
            "%u/%llu holding auth gen=%llu term=%u.  NOTHING we did may be "
            "published",
            slot, d->victim_node,
            owner_ok ? "TOKEN-MISMATCH (stale or foreign auth)"
                     : "TAKEOVER (descriptor owner is not us)",
            d->owner_node, (unsigned long long)d->owner_epoch,
            (unsigned long long)d->recovery_gen, d->owner_term,
            ctx->local_node, (unsigned long long)ctx->epoch,
            auth ? (unsigned long long)auth->recovery_gen : 0ULL,
            auth ? auth->owner_term : 0u);
        rc = -EBUSY;
        goto out;
    }
    if (d->flags & MXFS_RECOV_F_QUARANTINED) {
        old_oc = recov_outcome_of(cur);
        if (old_oc &&
            old_oc->outcome == MXFS_RECOV_OUTCOME_TERMINAL_REFUSED &&
            old_oc->reason == info->reason &&
            old_oc->domain_kind == info->domain_kind &&
            old_oc->ag_mask == info->ag_mask) {
            /* Idempotent: this refusal already landed.  Hand back the
             * CANONICAL record — the caller imports what the cluster reads,
             * not its local draft (whose digest/seq may differ). */
            if (oc_out)
                *oc_out = *old_oc;
            rc = 0;
            goto out;
        }
        /* Quarantined by a DIFFERENT verdict (or corrupt/absent outcome
         * bytes).  Terminal state never gets rewritten — the first
         * durable verdict wins.  (The QUARANTINED-with-all-zero-outcome
         * legacy shape is NOT publishable here either: no auth can exist
         * over a quarantined descriptor, so that state is only reachable
         * through the leaseless backfill API.) */
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P241-RECOV-TERMINAL-CONFLICT slot=%d victim=%u — "
            "descriptor already quarantined with %s; refusing to "
            "overwrite a terminal verdict (ours: reason=%u domain=%u)",
            slot, d->victim_node,
            old_oc ? "a different outcome record" :
            (recov_outcome_present(cur) ? "corrupt outcome bytes" :
                                          "no outcome record"),
            info->reason, info->domain_kind);
        rc = -EPERM;
        goto out;
    }

    *want = *cur;
    want->recov.desc.flags         |= MXFS_RECOV_F_QUARANTINED;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
    recov_desc_seal(want);

    old_oc = recov_outcome_of(cur);
    recov_outcome_fill(want, d, info->reason, info->domain_kind,
                       info->ag_mask, info->digest_valid, info->slice_digest,
                       old_oc ? old_oc->publish_seq + 1 : 1,
                       info->refused, info->malformed);
    oc = &want->recov.outcome;

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0 && oc_out)
        *oc_out = *oc;
    if (rc == 0)
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P241-RECOV-TERMINAL slot=%d victim=%u/%llu — slice "
            "replay REFUSED (reason=%u domain=%u ag_mask=0x%llx refused=%u "
            "malformed=%u digest=%llx dvalid=%d seq=%llu); victim domain "
            "quarantined cluster-wide, slot frozen until operator action",
            slot, d->victim_node, (unsigned long long)d->victim_epoch,
            info->reason, info->domain_kind,
            (unsigned long long)oc->ag_mask, info->refused, info->malformed,
            (unsigned long long)oc->slice_digest, (int)info->digest_valid,
            (unsigned long long)oc->publish_seq);
    else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P241-RECOV-TERMINAL-FAIL slot=%d victim=%u rc=%d — "
            "the refusal is NOT durable; the caller must keep its retry "
            "path armed and must not act as if it landed",
            slot, d->victim_node, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

/*
 * sess374 (sess363 RULE-5 ruling): the shared state+verdict predicate behind
 * every closure gate.  Evaluated on a freshly read image of the victim's
 * heartbeat sector — never on a cached or amortized copy.
 *
 * `check_auth` selects the two callers' authority contracts.  The PUBLISHER
 * (leased) path passes true together with its live recov_auth: the purge is
 * that owner's act, and a NULL auth would silently degrade recov_auth_holds
 * to a bare owner-identity test.  The SCRUB (leaseless) path passes false —
 * no recovery lease over a quarantined descriptor is obtainable by anyone,
 * so the only thing that path may rely on is that a TERMINAL verdict is
 * irreversible public state; mxfs_disklock_terminal_gate_check carries the
 * extra fail-closed conditions it needs instead.
 *
 * victim_slot is checked against `slot` on every call: the descriptor is a
 * byte-copied record, so that field is the only binding between the sector
 * it was found in and the victim it names.
 *
 * 0 = the victim's out-of-closure domain is well defined; *victim / *ag_mask
 * are filled from THIS image.
 */
static int closure_gate_predicate(struct mxfs_disklock_ctx *ctx,
                              const struct mxfs_disklock_heartbeat *hb,
                              int slot,
                              const struct mxfs_recov_auth *auth,
                              bool check_auth,
                              mxfs_node_id_t *victim, uint64_t *ag_mask)
{
    const struct mxfs_recov_desc *d;
    const struct mxfs_recov_outcome *oc;

    /*
     * sess374 (RULE-5 review items 4+5): the IDENTITY BINDING, and the reason
     * the leaseless form is sound at all.
     *
     * recov_desc_of() is the strict reader: it requires the sector to be a
     * RECOVERY_GUARD record (never an ACTIVE heartbeat) and validates the
     * descriptor's crc against the sector's own {fs_gen, node_id, epoch}
     * triple.  So a slot whose occupant is LIVE cannot present a descriptor
     * here at all — the platter read itself, not a cached monitor opinion, is
     * what proves the slot has no live tenant.  A descriptor spliced beside a
     * different victim's header does not validate.
     *
     * On top of that the checks below bind the verdict to THIS filesystem and
     * THIS incarnation: a pre-mkfs ghost sector, or a descriptor naming a
     * different node/incarnation/slot than the record it sits in, authorizes
     * nothing.  Without them a stale terminal record for an earlier occupant
     * of a slot could authorize stripping a LATER occupant's grants — the DLM
     * bit is indexed by slot, so it would name the wrong node.
     */
    if (hb_gen_foreign(ctx, hb))
        return -ESTALE;
    if (dl_inject_take(&mxfs_dl_inject_closure_crc)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P299-INJECT-GATE-CRC slot=%d — closure-gate descriptor "
            "forced unparseable", slot);
        return -EPROTO;
    }
    d = recov_desc_of(hb);
    if (!d)
        return recov_desc_present(hb) ? -EPROTO : -ESTALE;
    if (d->victim_slot != (uint16_t)slot ||
        d->victim_node != hb->node_id ||
        !inc_eq(d->victim_epoch, hb->epoch) ||
        d->victim_fs_gen != hb->fs_gen)
        return -EPROTO;
    if (check_auth && !recov_auth_holds(ctx, d, auth))
        return -EBUSY;
    if (!(d->flags & MXFS_RECOV_F_QUARANTINED))
        return -EINVAL;         /* not terminal — this is the full purge's job */
    oc = recov_outcome_of(hb);
    if (!oc)
        return -EBADMSG;        /* quarantined without a readable verdict */
    if (oc->outcome != MXFS_RECOV_OUTCOME_TERMINAL_REFUSED ||
        oc->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK ||
        oc->ag_mask == 0)
        return -EOPNOTSUPP;     /* FSWIDE (or malformed domain): no
                                 * out-of-closure set exists */
    if (victim)
        *victim = d->victim_node;
    if (ag_mask)
        *ag_mask = oc->ag_mask;
    return 0;
}

/*
 * One authoritative read of slot's heartbeat sector into a caller-owned 512 B
 * buffer.  Every gate evaluation below starts here — the ruling forbids
 * amortizing or caching the image a destructive CAS is authorized from.
 */
static int closure_read_gate_sector(struct mxfs_disklock_ctx *ctx, int slot,
                                    uint8_t *buf)
{
    uint64_t off = ctx->base_offset +
                   (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
    int rc;

    if (dl_inject_take(&mxfs_dl_inject_closure_read)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P299-INJECT-GATE-READ slot=%d — closure-gate sector "
            "read forced to -EIO", slot);
        return -EIO;
    }
    mxfs_pal_mutex_lock(ctx->lock);
    rc = read_sector(ctx, off, buf);
    mxfs_pal_mutex_unlock(ctx->lock);
    return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_closure_gate_snapshot(struct mxfs_disklock_ctx *ctx, int slot,
                                        const struct mxfs_recov_auth *auth,
                                        mxfs_node_id_t *victim,
                                        uint64_t *ag_mask)
{
    uint8_t *buf;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !auth || !victim || !ag_mask)
        return -EINVAL;
    buf = mxfs_pal_alloc(512);
    if (!buf)
        return -ENOMEM;
    rc = closure_read_gate_sector(ctx, slot, buf);
    if (rc == 0)
        rc = closure_gate_predicate(ctx,
                (const struct mxfs_disklock_heartbeat *)buf, slot,
                auth, true, victim, ag_mask);
    mxfs_pal_free(buf);
    return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_closure_gate_revalidate(struct mxfs_disklock_ctx *ctx,
                                          int slot,
                                          const struct mxfs_recov_auth *auth,
                                          mxfs_node_id_t victim,
                                          uint64_t ag_mask)
{
    mxfs_node_id_t v2 = 0;
    uint64_t m2 = 0;
    uint8_t *buf;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !auth)
        return -EINVAL;
    buf = mxfs_pal_alloc(512);
    if (!buf)
        return -ENOMEM;
    rc = closure_read_gate_sector(ctx, slot, buf);
    if (rc == 0)
        rc = closure_gate_predicate(ctx,
                (const struct mxfs_disklock_heartbeat *)buf, slot,
                auth, true, &v2, &m2);
    /*
     * An unreadable gate sector is NOT a pass.  sess361 let the scan carry on
     * through one; under the sess363 ruling every destructive CAS must be
     * authorized by a gate image we actually read, so I/O failure propagates
     * and the caller stops with retry-required.
     */
    if (rc == 0 && dl_inject_take(&mxfs_dl_inject_closure_mask)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P299-INJECT-GATE-MASK slot=%d — closure-gate revalidate "
            "ag_mask perturbed 0x%llx->0x%llx", slot,
            (unsigned long long)m2, (unsigned long long)(m2 ^ 1ULL));
        m2 ^= 1ULL;
    }
    if (rc == 0 && (v2 != victim || m2 != ag_mask))
        rc = -ESTALE;
    mxfs_pal_free(buf);
    return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_terminal_gate_check(struct mxfs_disklock_ctx *ctx, int slot,
                                      mxfs_node_id_t *victim,
                                      uint64_t *ag_mask)
{
    uint8_t *buf;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim || !ag_mask)
        return -EINVAL;
    /*
     * FAIL CLOSED on liveness, in TWO independent ways (RULE-5 review item 4:
     * an advisory tracker alone is not enough, because an UNMONITORED slot
     * reads as "not live" and that must never mean "known dead").
     *
     *  1. Here: our own monitor's opinion.  It is advisory and incomplete, so
     *     it is used only to REFUSE, never to authorize — a slot it calls
     *     live (our own included) stops us dead.
     *  2. Authoritatively, in closure_gate_predicate below: the platter
     *     sector must be a RECOVERY_GUARD record whose descriptor crc binds
     *     to its own {fs_gen, node_id, epoch}.  A live tenant writes ACTIVE
     *     heartbeats there, which cannot present a descriptor at all.  THAT
     *     is the proof; the monitor check is the belt around it.
     *
     * An unmonitored slot therefore does not get stripped on a tracker
     * technicality — it gets stripped only if the platter itself still shows
     * a guarded, quarantined, terminally-refused victim of this filesystem.
     */
    if (mxfs_disklock_slot_live(ctx, slot))
        return -EBUSY;
    buf = mxfs_pal_alloc(512);
    if (!buf)
        return -ENOMEM;
    rc = closure_read_gate_sector(ctx, slot, buf);
    if (rc == 0)
        rc = closure_gate_predicate(ctx,
                (const struct mxfs_disklock_heartbeat *)buf, slot,
                NULL, false, victim, ag_mask);
    mxfs_pal_free(buf);
    return rc;
}

/*
 * sess330 (RULE-5 ruling): leaseless backfill of the LEGACY intent-path
 * quarantine.  Contract in disklock.h.  A descriptor QUARANTINED with an
 * ALL-ZERO outcome region is terminal state from a pre-outcome build; no
 * recovery auth can ever exist over it (the claim path's certificate
 * evaluator refuses quarantined descriptors before the owner-reacquire
 * check), so the synthesized verdict is written WITHOUT authority — but
 * under the tightest possible predicate, with the descriptor bytes
 * preserved exactly (owner/epoch/gen/term/stage/flags/stamp untouched)
 * and deterministic outcome bytes, so racing backfillers write identical
 * records and the full-record CAS makes the race benign.
 */
int mxfs_disklock_recovery_backfill_legacy(struct mxfs_disklock_ctx *ctx,
                                    int slot,
                                    struct mxfs_recov_outcome *oc_out)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    const struct mxfs_recov_outcome *oc;
    uint64_t off;
    int tries, rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    for (tries = 0; tries < 5; tries++) {
        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0)
            goto out;

        if (!recov_desc_present(cur)) {
            rc = -ENOENT;       /* no recovery descriptor on this slot */
            goto out;
        }
        if (hb_gen_foreign(ctx, cur)) {
            /* sess383 (RULE-5 ruling Q2): a pre-mkfs ghost is not this
             * filesystem's recovery object, so it is not "inherited
             * emptiness" to terminalize either.  Backfill is a WRITE; a
             * foreign generation may never authorize one.  The classifier
             * cannot reach this arm any more (read_outcome gates first), but
             * this is the function that mutates, so it carries its own gate. */
            rc = -ESTALE;
            goto out;
        }
        d = recov_desc_of(cur);
        if (!d) {
            rc = -EPROTO;       /* descriptor bytes present, unparseable */
            goto out;
        }
        if (d->victim_slot != (uint16_t)slot) {
            /* sess334 (sess333 review): the descriptor CRC binds the
             * SECTOR's fs_gen/node_id/epoch — bytes that travel with a
             * byte-copied record — so victim_slot is the only binding
             * to the slot this sector was read from.  A mismatch is a
             * misplaced or copied record: never backfill it and never
             * treat it as legacy emptiness.  (No reason/scope predicate
             * exists to check beyond this: a legacy descriptor is
             * exactly QUARANTINED flag + all-zero outcome region.) */
            mxfs_pal_log(MXFS_LOG_ERR,
                "disklock: P241-RECOV-BACKFILL-IDENT slot=%d victim=%u "
                "victim_slot=%u — descriptor's victim identity does not "
                "match the sector it was read from; refusing backfill "
                "(fail closed)",
                slot, d->victim_node, d->victim_slot);
            rc = -EPROTO;
            goto out;
        }
        if (!(d->flags & MXFS_RECOV_F_QUARANTINED)) {
            /* Live descriptor: not legacy-terminal state.  A live recovery
             * publishes a real verdict with real evidence under its lease;
             * backfill fills inherited emptiness only. */
            rc = -EAGAIN;
            goto out;
        }
        oc = recov_outcome_of(cur);
        if (oc) {
            /* A verdict already landed (possibly a racing backfiller's).
             * First durable verdict wins — hand back the canonical record
             * for import. */
            if (oc_out)
                *oc_out = *oc;
            rc = 0;
            goto out;
        }
        if (recov_outcome_present(cur)) {
            /* Nonzero bytes that fail validation: corruption.  Backfill
             * fills exact emptiness, it never overwrites — fail closed. */
            mxfs_pal_log(MXFS_LOG_ERR,
                "disklock: P241-RECOV-BACKFILL-BADOC slot=%d victim=%u — "
                "quarantined descriptor carries nonzero outcome bytes that "
                "fail validation; refusing to overwrite (fail closed)",
                slot, d->victim_node);
            rc = -EBADMSG;
            goto out;
        }

        /* Eligible: QUARANTINED + outcome region exactly all-zero.  The
         * intent path recorded no domain evidence, so the synthesized
         * record is FSWIDE with LEGACY_INTENT provenance (sess328 Q1). */
        *want = *cur;
        recov_outcome_fill(want, d,
                           MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE,
                           MXFS_RECOV_DOMAIN_FSWIDE,
                           0, false, 0, 1, 0, 0);

        rc = recov_cas_durable(ctx, slot, cur, want);
        if (rc == 0) {
            mxfs_pal_log(MXFS_LOG_WARN,
                "disklock: P241-RECOV-BACKFILL slot=%d victim=%u — "
                "descriptor quarantined by the legacy intent path with no "
                "outcome record; backfilled a synthesized FSWIDE terminal "
                "verdict so peers converge instead of parking",
                slot, d->victim_node);
            if (oc_out)
                *oc_out = want->recov.outcome;
            goto out;
        }
        if (rc != -EAGAIN)
            goto out;           /* I/O failure: not durable, caller re-arms */
        /* CAS lost: something changed under us.  Reread and reclassify —
         * a racing backfiller's identical record imports via the oc branch
         * above; anything else reclassifies or fails closed. */
    }
    rc = -EAGAIN;
out:
    if (rc < 0 && rc != -EAGAIN)
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P241-RECOV-BACKFILL-FAIL slot=%d rc=%d — legacy "
            "terminalization did NOT land; the caller must fail closed or "
            "keep its retry path armed",
            slot, rc);
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

/*
 * sess327 (sess325 ruling item 2): synchronous canonical-outcome read.
 * Return-code contract in disklock.h.  No authority needed — a terminal
 * outcome is public state; -EPERM conflict losers and late mounts both
 * import through here instead of trusting a local draft or waiting a
 * monitor lap.
 */
int mxfs_disklock_recovery_read_outcome(struct mxfs_disklock_ctx *ctx,
                                    int slot,
                                    struct mxfs_recov_outcome *oc_out)
{
    struct mxfs_disklock_heartbeat *cur;
    const struct mxfs_recov_outcome *oc;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !oc_out)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!cur)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    rc = recov_outcome_structural(ctx, cur, slot, &oc);
    if (rc == 0)
        *oc_out = *oc;
out:
    mxfs_pal_free(cur);
    return rc;
}

int mxfs_disklock_recovery_refresh(struct mxfs_disklock_ctx *ctx, int slot,
                                   const struct mxfs_recov_auth *auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
        goto out;
    }
    if (!recov_auth_holds(ctx, d, auth)) {
        rc = -ESTALE;           /* taken over: stop touching it */
        goto out;
    }

    *want = *cur;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_read(struct mxfs_disklock_ctx *ctx, int slot,
                                struct mxfs_recov_desc *out)
{
    struct mxfs_disklock_heartbeat *cur;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!cur)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc == 0) {
        d = recov_desc_of(cur);
        if (d) {
            if (out)
                *out = *d;
            rc = 0;
        } else {
            rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
        }
    }
    mxfs_pal_free(cur);
    return rc;
}

int mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot,
                                    struct mxfs_recov_auth *out_auth)
{
    struct mxfs_disklock_heartbeat *first, *again, *want;
    const struct mxfs_recov_desc *d0, *d1;
    struct mxfs_recov_desc snap;
    uint64_t off;
    unsigned int stage;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    first = mxfs_pal_alloc(sizeof(*first));
    again = mxfs_pal_alloc(sizeof(*again));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!first || !again || !want) {
        rc = -ENOMEM;
        goto out;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, first, sizeof(*first));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d0 = recov_desc_of(first);
    if (!d0) {
        rc = recov_desc_present(first) ? -EPROTO : -ENOENT;
        goto out;
    }
    if (d0->owner_node == ctx->local_node &&
        inc_eq(d0->owner_epoch, ctx->epoch)) {
        recov_auth_issue(out_auth, d0);
        rc = (int)d0->stage;    /* already ours */
        goto out;
    }
    if (d0->flags & MXFS_RECOV_F_QUARANTINED) {
        rc = -EPERM;
        goto out;
    }
    snap = *d0;

    /*
     * Rule 5 / the sess43 discipline: abandonment is ABSENCE OF CHANGE across
     * MXFS_RECOV_ABANDON_MS, never clock arithmetic — owner_stamp_ms is the
     * OWNER's boot-relative time and means nothing on our clock.  Any change
     * at all (a re-stamp, a stage advance, a takeover by a third node) proves
     * someone else is driving this recovery.
     *
     * This is the SECOND gate, not the first.  A stalled stamp proves only "I
     * observed no refresh"; the caller must already have confirmed the current
     * owner's session dead AND fenced from the LUN (header rule 5).  We sleep
     * MXFS_RECOV_ABANDON_MS here, which is why this call may never run on the
     * heartbeat monitor thread.
     */
    mxfs_pal_sleep_ms(MXFS_RECOV_ABANDON_MS);

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d1 = recov_desc_of(again);
    if (!d1) {
        rc = recov_desc_present(again) ? -EPROTO : -ENOENT;
        goto out;
    }
    if (d1->victim_node != snap.victim_node ||
        d1->victim_epoch != snap.victim_epoch ||
        d1->owner_node != snap.owner_node ||
        d1->owner_epoch != snap.owner_epoch ||
        d1->recovery_gen != snap.recovery_gen ||
        d1->owner_term != snap.owner_term ||
        d1->stage != snap.stage ||
        d1->stage_seq != snap.stage_seq ||
        d1->owner_stamp_ms != snap.owner_stamp_ms) {
        rc = -EBUSY;            /* owner is alive / a third node took over */
        goto out;
    }

    /*
     * Take ONLY the owner fields.  Victim identity, recovery_gen and stage are
     * preserved: recovery_gen names the TRANSACTION and must survive the change
     * of authority (rule 6), and the successor RESUMES from the recorded
     * milestone rather than re-running an earlier one, because peers may
     * already have acted on the later one.  owner_term is what moves — it is
     * the only field that makes a pre-takeover worker's authorization tuple
     * fail its recheck.
     */
    stage = d1->stage;
    *want = *again;
    want->recov.desc.owner_node     = ctx->local_node;
    want->recov.desc.owner_epoch    = ctx->epoch;
    want->recov.desc.owner_slot     = (uint16_t)ctx->local_slot;
    want->recov.desc.owner_term     = d1->owner_term + 1;
    want->recov.desc.stage_seq      = d1->stage_seq + 1;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(d1->owner_stamp_ms);
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, again, want);
    if (rc == 0) {
        recov_auth_issue(out_auth, &want->recov.desc);
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P234-RECOV-TAKEOVER slot=%d victim=%u from owner=%u "
            "gen=%llu term=%u->%u resuming at stage=%u — this is a RECOVERY "
            "LEASE, not a member slot: no ACTIVE, no fresh journal over the "
            "victim's slice, no mount on it until the slot is CONSUMABLE",
            slot, snap.victim_node, snap.owner_node,
            (unsigned long long)snap.recovery_gen,
            snap.owner_term, want->recov.desc.owner_term, stage);
        rc = (int)stage;
    }
out:
    mxfs_pal_free(first);
    mxfs_pal_free(again);
    mxfs_pal_free(want);
    return rc;
}

/*
 * ── sess76: THE FENCE-EVIDENCE CHANNEL, C side ─────────────────────────────
 *
 * Measured on the rig (sess73): a peer death produces exactly ONE node whose
 * PREEMPT AND ABORT completes and 30 whose 0x05 hits RESERVATION CONFLICT,
 * while the replayer is chosen by lowest_live_slot and — in the captured run —
 * was one of the LOSERS, dispatching foreign replay 22 ms after its own
 * proves_excl=0.  Exclusion is proved by one node and consumed by another, so
 * the proof needs a durable channel between them: the victim's own sector.
 *
 * Four calls implement it.  fence_intent lays down the attempt BEFORE the P&A
 * so the attempt is serialised and a crash mid-fence is distinguishable from
 * "never started"; fence_certify turns a proved exclusion into the immutable
 * certificate and releases the descriptor UNOWNED; recovery_claim takes the
 * unowned certified descriptor as the execution lease; replay_authorized is
 * the gate every destructive step must pass.
 *
 * fence_takeover exists for one specific case and no other: the prover died
 * with the intent durable.  A successor may retry the P&A and certify ITS OWN
 * result.  It may NEVER certify the dead prover's — sess74 ruled the inference
 * "intent exists + prover died + victim key absent => the intended P&A
 * completed" UNSOUND, because it depends on target-specific registration-
 * removal semantics.  Where the key is already gone and no new accepted
 * exclusion operation can be performed, the slice stays unreplayable.  That is
 * a deliberate loss of capacity, not a bug to be optimised away.
 */

/* Hand the caller the fencing-ATTEMPT lease it now holds. */
static void recov_fence_auth_issue(struct mxfs_recov_fence_auth *auth,
                                   const struct mxfs_recov_desc *d)
{
    if (!auth)
        return;
    auth->victim_node  = d->victim_node;
    auth->victim_epoch = d->victim_epoch;
    auth->recovery_gen = d->recovery_gen;
    auth->victim_key   = d->fence_victim_key;
    auth->fence_term   = d->fence_term;
    auth->victim_slot  = d->victim_slot;
}

/*
 * Is this descriptor's FENCING-ATTEMPT lease ours?  Deliberately NOT
 * recov_auth_holds(): that one tests the recovery-EXECUTION lease, and the two
 * authorities are held by different nodes at different stages (sess74).  The
 * prover identity is the certificate's own fence_prover_* pair, not the owner
 * fields, so a successor that takes the attempt over cannot pass as the
 * original prover.
 */
static bool recov_fence_auth_holds(const struct mxfs_disklock_ctx *ctx,
                                   const struct mxfs_recov_desc *d,
                                   const struct mxfs_recov_fence_auth *auth)
{
    if (d->owner_node != ctx->local_node ||
        !inc_eq(d->owner_epoch, ctx->epoch))
        return false;
    if (d->fence_prover_node != ctx->local_node ||
        !inc_eq(d->fence_prover_epoch, ctx->epoch))
        return false;
    if (!auth)
        return false;           /* the attempt lease is never implicit */
    /*
     * sess91: token identity, exactly as in recov_auth_holds() —
     * recov_fence_auth_issue() copies each of these out of this descriptor, so
     * an UNKNOWN victim incarnation must compare equal to the UNKNOWN it was
     * issued from.  The substantive "which incarnation did we actually fence?"
     * question is NOT asked here; it belongs to the certificate's fence_kind /
     * fence_victim_key, which mxfs_recov_cert_proves_exclusion() checks with
     * the cross-source comparator.
     */
    return d->victim_slot  == auth->victim_slot &&
           d->victim_node  == auth->victim_node &&
           recov_tok_eq(d->victim_epoch, auth->victim_epoch) &&
           d->recovery_gen == auth->recovery_gen &&
           d->fence_term   == auth->fence_term;
}

bool mxfs_recov_cert_proves_exclusion(const struct mxfs_recov_desc *d,
                                      uint32_t fs_gen, int slot,
                                      mxfs_node_id_t victim,
                                      mxfs_epoch_t victim_epoch,
                                      const char **why)
{
    const char *reason = NULL;

    if (!d) {
        reason = "no descriptor";
        goto no;
    }
    /*
     * Structural validation FIRST, and against the descriptor's OWN identity
     * fields.  recov_desc_crc() binds the payload to {fs_gen, node_id, epoch}
     * taken from the record HEADER; recomputing it here from victim_fs_gen /
     * victim_node / victim_epoch therefore proves two things at once — that
     * the payload is intact, and that the descriptor's internal identity
     * agrees with the header it was sealed against.  A payload spliced next to
     * a different victim's header fails, and so does one whose victim_* fields
     * were altered.
     */
    if (d->magic != MXFS_RECOV_DESC_MAGIC) {
        reason = "descriptor magic";
        goto no;
    }
    if (d->version != MXFS_RECOV_DESC_VERSION) {
        reason = "descriptor version not exactly supported";
        goto no;
    }
    if (d->crc32c != recov_desc_crc(d->victim_fs_gen, d->victim_node,
                                    d->victim_epoch, d)) {
        reason = "crc / descriptor-vs-header identity mismatch";
        goto no;
    }

    /* Identity: this must be the recovery we think it is. */
    if (!victim) {
        reason = "caller named no victim";
        goto no;
    }
    if (d->victim_node != victim) {
        reason = "descriptor names a different victim node";
        goto no;
    }
    if (!d->victim_epoch) {
        reason = "descriptor carries no victim incarnation";
        goto no;
    }
    if (!inc_eq(d->victim_epoch, victim_epoch)) {
        reason = "descriptor names a different victim incarnation";
        goto no;
    }
    if (fs_gen && d->victim_fs_gen != fs_gen) {
        reason = "descriptor belongs to a different mkfs generation";
        goto no;
    }
    if (slot >= 0 && d->victim_slot != (uint16_t)slot) {
        reason = "descriptor names a different slot";
        goto no;
    }
    if (!d->recovery_gen) {
        reason = "recovery_gen is zero";
        goto no;
    }
    if (!d->slice_count || d->slice_idx >= d->slice_count) {
        reason = "slice_idx/slice_count do not name a journal slice";
        goto no;
    }

    /* State: an INTENT is not a fence (sess74, rule-1 amendment). */
    if (d->stage < MXFS_RECOV_STAGE_FENCED) {
        reason = d->stage == MXFS_RECOV_STAGE_FENCING ?
            "fencing ATTEMPT only — no exclusion has been proved yet" :
            "descriptor carries no fence stage";
        goto no;
    }
    if (d->flags & MXFS_RECOV_F_QUARANTINED) {
        reason = "slice is QUARANTINED";
        goto no;
    }

    /* The certificate itself. */
    if (!mxfs_fence_kind_proves_exclusion(
                (enum mxfs_fence_kind)d->fence_kind)) {
        reason = "fence_kind does not prove exclusion";
        goto no;
    }
    if ((enum mxfs_fence_kind)d->fence_kind ==
            MXFS_FENCE_KIND_PREEMPT_ABORT_DONE &&
        !mxfs_pr_type_excludes_nonregistrants(d->fence_resv_type)) {
        /*
         * Without a Write Exclusive reservation held at the verifying read,
         * removing the victim's registration excludes nobody: an unreserved LU
         * accepts writes from unregistered initiators.
         * A SINGLE_NODE_EXCLUSIVE certificate's exclusion comes from topology
         * (operator-asserted exclusive bdev + single-node membership), not
         * from a reservation, so it carries no resv_type supporting fact.
         *
         * sess381: this tested `== WR_EX_RO`, which rejected the
         * all-registrants form (0x07) MXFS reserves from proto-gen 5 on.  The
         * question the certificate rests on is whether the type excludes
         * NON-REGISTRANTS, and both Write Exclusive forms do.
         */
        reason = "reservation type at the verify does not exclude non-registrants";
        goto no;
    }
    if (!d->fence_victim_key) {
        reason = "certificate names no victim key";
        goto no;
    }
    if (!d->fence_prover_node || !d->fence_prover_epoch) {
        reason = "certificate names no prover incarnation";
        goto no;
    }
    if (!d->fence_term) {
        reason = "certificate carries no fencing-attempt term";
        goto no;
    }

    if (why)
        *why = "certified";
    return true;
no:
    if (why)
        *why = reason;
    return false;
}

int mxfs_disklock_recovery_fence_intent(struct mxfs_disklock_ctx *ctx, int slot,
                                        mxfs_node_id_t victim,
                                        mxfs_epoch_t victim_epoch,
                                        uint64_t victim_key,
                                        uint16_t slice_idx,
                                        uint16_t slice_count,
                                        uint32_t flags,
                                        struct mxfs_recov_fence_auth *out_auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim || !victim_key || !slice_count || slice_idx >= slice_count)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    if (recov_desc_present(cur)) {
        d = recov_desc_of(cur);
        if (!d) {
            mxfs_pal_log(MXFS_LOG_ERR,
                "disklock: P236-FENCE-UNREADABLE slot=%d victim=%u — the slot "
                "carries a recovery descriptor this build cannot validate; "
                "refusing to overwrite it with a fencing intent",
                slot, victim);
            rc = -EPROTO;
            goto out;
        }
        if (d->victim_node != victim ||
            !inc_eq(d->victim_epoch, victim_epoch)) {
            rc = -ESTALE;
            goto out;
        }
        if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
            /* Someone already proved it.  Nothing for this prover to do. */
            rc = -EEXIST;
            goto out;
        }
        /* stage == FENCING: an attempt is already recorded. */
        if (d->owner_node == ctx->local_node &&
            inc_eq(d->owner_epoch, ctx->epoch) &&
            d->fence_prover_node == ctx->local_node) {
            recov_fence_auth_issue(out_auth, d);
            rc = 0;             /* our own attempt — resume it */
            goto out;
        }
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-FENCE-ATTEMPT-BUSY slot=%d victim=%u prover=%u "
            "term=%u key=%llu — another survivor holds the fencing-attempt "
            "lease; not issuing a second PREEMPT AND ABORT",
            slot, victim, d->fence_prover_node, d->fence_term,
            (unsigned long long)d->fence_victim_key);
        rc = -EBUSY;
        goto out;
    }

    if (cur->magic != MXFS_DISKLOCK_MAGIC) {
        rc = -ENOENT;           /* zeroed: CONSUMABLE, nothing to recover */
        goto out;
    }
    if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
         cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
        cur->node_id != victim || hb_gen_foreign(ctx, cur)) {
        rc = -ESTALE;
        goto out;
    }

    /*
     * Rule 2: the victim's identity is never overwritten — only `flags`
     * changes and the dead evict-ring bytes become the descriptor.  Note the
     * live-victim race is FAIL-CLOSED by construction: if this node is wrong
     * about the death, the victim's next ACTIVE heartbeat write clobbers this
     * intent, and the certify CAS then fails because the sector no longer
     * matches.  A live node cannot be certified as fenced by accident.
     */
    /*
     * sess93 — NO ZERO-INCARNATION DESCRIPTOR MAY EVER BE CREATED.
     *
     * D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN: a descriptor that
     * cannot name its victim's incarnation cannot derive authority from
     * incarnation identity, and the slot/slice-level quarantine that would be
     * the alternative is not established.  The sess91 RULE-5 ruling's item 3
     * offered a choice — prove the seven quarantine invariants, or forbid
     * zero-epoch descriptors at CREATION.  This is the second.
     *
     * The only other creator, recovery_begin(), is retired (see its entry
     * guard), so with this refusal the class becomes unconstructible rather
     * than merely unlikely.  A sector whose ACTIVE record carries epoch 0 is
     * a pre-incarnation-landing (pre-0.11.420) writer; treating it as a
     * fenceable victim would publish a guard naming an incarnation nobody
     * observed.
     */
    if (!inc_valid(cur->epoch)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P238-FENCE-ZEROINC slot=%d victim=%u — the victim's own "
            "record carries incarnation 0, so no certificate could ever name "
            "what it fenced; refusing to lay a fencing intent.  This slot needs "
            "a build that publishes a real mount incarnation (0.11.420+)",
            slot, victim);
        rc = -EPROTO;
        goto out;
    }

    *want = *cur;
    want->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
    memset(&want->recov, 0, sizeof(want->recov));
    want->recov.desc.magic           = MXFS_RECOV_DESC_MAGIC;
    want->recov.desc.version         = MXFS_RECOV_DESC_VERSION;
    want->recov.desc.stage           = MXFS_RECOV_STAGE_FENCING;
    want->recov.desc.victim_epoch    = cur->epoch;
    want->recov.desc.owner_epoch     = ctx->epoch;
    want->recov.desc.recovery_gen    = 1;   /* constant across takeover; see
                                             * recovery_begin() for why it is
                                             * not a counter */
    want->recov.desc.owner_stamp_ms  = recov_stamp_after(0);
    want->recov.desc.victim_node     = victim;
    want->recov.desc.owner_node      = ctx->local_node;
    want->recov.desc.victim_fs_gen   = cur->fs_gen;
    want->recov.desc.flags           = flags |
        (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ?
             MXFS_RECOV_F_VICTIM_WITHDREW : 0) |
        (hb_victim_snlocal(cur) ? MXFS_RECOV_F_VICTIM_SNLOCAL : 0);
    want->recov.desc.victim_slot     = (uint16_t)slot;
    want->recov.desc.owner_slot      = (uint16_t)ctx->local_slot;
    want->recov.desc.slice_idx       = slice_idx;
    want->recov.desc.slice_count     = slice_count;
    want->recov.desc.stage_seq       = 1;
    /*
     * owner_term stays 0: this is the fencing-ATTEMPT lease, not the
     * recovery-EXECUTION lease.  Nothing may be executed under it, and
     * recovery_advance()/refresh() refuse a pre-FENCED descriptor outright so
     * an intent cannot be walked up the milestone ladder.
     */
    want->recov.desc.owner_term      = 0;
    /* Attempt state in the certificate bytes.  fence_kind stays NONE and
     * fence_resv_type stays 0, which is what makes this read as "not
     * certified" on every gate. */
    want->recov.desc.fence_kind      = MXFS_FENCE_KIND_NONE;
    want->recov.desc.fence_resv_type = 0;
    want->recov.desc.fence_victim_key  = victim_key;
    want->recov.desc.fence_prover_epoch = ctx->epoch;
    want->recov.desc.fence_stamp_ms  = mxfs_pal_time_ms();
    want->recov.desc.fence_prover_node = ctx->local_node;
    want->recov.desc.fence_pr_gen    = 0;
    want->recov.desc.fence_term      = 1;
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0) {
        recov_fence_auth_issue(out_auth, &want->recov.desc);
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-FENCE-INTENT slot=%d victim=%u epoch=%llu key=%llu "
            "slice=%u/%u prover=%u term=1 — fencing intent is DURABLE; the "
            "PREEMPT AND ABORT may now be issued.  This authorises NOTHING: "
            "no replay, no purge, no manifest work, no zeroing",
            slot, victim, (unsigned long long)cur->epoch,
            (unsigned long long)victim_key, slice_idx, slice_count,
            ctx->local_node);
    } else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-FENCE-INTENT-FAIL slot=%d victim=%u rc=%d — the "
            "intent is NOT durable; the fence must not be issued (a P&A whose "
            "result cannot be recorded destroys this slice's only route to "
            "recovery: the victim key is consumed and no successor can prove "
            "exclusion)",
            slot, victim, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_fence_arm_submit(struct mxfs_disklock_ctx *ctx,
                                            int slot,
                                            const struct mxfs_recov_fence_auth *auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !auth)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
        goto out;
    }
    if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
        rc = -EEXIST;
        goto out;
    }
    if (d->stage != MXFS_RECOV_STAGE_FENCING) {
        rc = -EPROTO;
        goto out;
    }
    if (!recov_fence_auth_holds(ctx, d, auth)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P304-FENCE-ARM-LEASE-LOST slot=%d victim=%u prover=%u "
            "term=%u — the fencing-attempt lease is no longer ours; no command "
            "may be submitted under it",
            slot, d->victim_node, d->fence_prover_node, d->fence_term);
        rc = -EBUSY;
        goto out;
    }
    if (d->flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN) {
        rc = 0;                 /* already armed — idempotent, no write */
        goto out;
    }

    *want = *cur;
    want->recov.desc.flags          = d->flags |
                                      MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN;
    want->recov.desc.fence_stamp_ms = mxfs_pal_time_ms();
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0)
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P304-FENCE-ARM slot=%d victim=%u prover=%u term=%u — "
            "the command-submission boundary is DURABLE.  From this point a "
            "PREEMPT-family command MAY have reached the target, so no reader "
            "may treat this attempt as 'nothing was submitted' again",
            slot, d->victim_node, ctx->local_node, d->fence_term);
    else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P304-FENCE-ARM-FAIL slot=%d victim=%u rc=%d — the "
            "command-submission boundary is NOT durable, so the command must "
            "NOT be issued: a preempt nobody can later tell happened is "
            "indistinguishable from one that did not",
            slot, d->victim_node, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_fence_retryable(struct mxfs_disklock_ctx *ctx,
                                           int slot,
                                           mxfs_node_id_t *out_victim,
                                           mxfs_epoch_t *out_epoch)
{
    struct mxfs_disklock_heartbeat *cur;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc, ans = 0;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!cur)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        /* No descriptor, or one we cannot validate.  Neither is a retryable
         * attempt of ours, and "cannot validate" must not read as "no". */
        rc = recov_desc_present(cur) ? -EPROTO : 0;
        goto out;
    }
    rc = 0;
    if (d->stage != MXFS_RECOV_STAGE_FENCING)
        goto out;
    if (d->flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN)
        goto out;               /* ambiguous — needs reconciliation, not retry */
    if (d->fence_prover_node != ctx->local_node ||
        !inc_eq(d->fence_prover_epoch, ctx->epoch))
        goto out;               /* somebody else's attempt; takeover, not retry */
    if (out_victim)
        *out_victim = d->victim_node;
    if (out_epoch)
        *out_epoch = d->victim_epoch;
    ans = 1;
out:
    mxfs_pal_free(cur);
    return rc < 0 ? rc : ans;
}

int mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot,
                                         const struct mxfs_recov_fence_auth *auth,
                                         uint16_t fence_kind,
                                         uint16_t fence_resv_type,
                                         uint64_t fence_victim_key,
                                         uint32_t fence_pr_gen)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !auth)
        return -EINVAL;

    /*
     * THE CERTIFICATE CAN ONLY EVER SAY THE TRUTH.  Refuse before touching the
     * platter — a descriptor that claims an exclusion nobody proved is worse
     * than no descriptor at all, because every downstream gate trusts it.
     */
    if (!mxfs_fence_kind_proves_exclusion((enum mxfs_fence_kind)fence_kind)) {
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-FENCE-NOT-PROVED slot=%d victim=%u kind=%s — the "
            "fence attempt did not prove exclusion; leaving the intent in "
            "place uncertified.  The slice stays unreplayable, which is the "
            "correct outcome",
            slot, auth->victim_node,
            mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind));
        return -EPERM;
    }
    if ((enum mxfs_fence_kind)fence_kind ==
            MXFS_FENCE_KIND_PREEMPT_ABORT_DONE &&
        !mxfs_pr_type_excludes_nonregistrants(fence_resv_type)) {
        /* The resv-type supporting fact belongs to the preempt proof only;
         * SINGLE_NODE_EXCLUSIVE proves exclusion by topology, without a
         * reservation (see mxfs_recov_cert_proves_exclusion).
         *
         * sess381: this tested `== WR_EX_RO` and so refused to certify a
         * PROVED exclusion taken under the all-registrants type — the worst
         * possible outcome, because the victim key is already consumed by then
         * and no successor can prove it again.  MEASURED on the rig as
         * "P238-FENCE-UNRECORDED ... exclusion was PROVED but the certificate
         * is not durable ... this slice is BLOCKED". */
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-FENCE-NO-RESV slot=%d victim=%u resv_type=0x%02x — "
            "removing a registration only excludes while a Write Exclusive "
            "reservation (0x%02x or 0x%02x) is held; refusing to certify",
            slot, auth->victim_node, fence_resv_type,
            MXFS_PAL_PR_TYPE_WR_EX_RO, MXFS_PAL_PR_TYPE_WR_EX_AR);
        return -EPERM;
    }
    if (!fence_victim_key)
        return -EINVAL;
    if (auth->victim_key && fence_victim_key != auth->victim_key) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-FENCE-KEY-DRIFT slot=%d victim=%u intended=%llu "
            "removed=%llu — the key actually preempted is not the key this "
            "attempt was registered against; refusing to certify",
            slot, auth->victim_node,
            (unsigned long long)auth->victim_key,
            (unsigned long long)fence_victim_key);
        return -EPERM;
    }

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
        goto out;
    }
    if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
        /* Already certified.  Idempotent only if it is OUR certificate. */
        if (d->fence_prover_node == ctx->local_node &&
            inc_eq(d->fence_prover_epoch, ctx->epoch) &&
            d->fence_term == auth->fence_term)
            rc = 0;
        else
            rc = -EEXIST;
        goto out;
    }
    if (!recov_fence_auth_holds(ctx, d, auth)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-FENCE-LEASE-LOST slot=%d victim=%u prover=%u "
            "term=%u — the fencing-attempt lease is no longer ours (we hold "
            "node=%u epoch=%llu term=%u).  The exclusion we proved is real, "
            "but it is not ours to certify: another prover owns this attempt "
            "and will certify its own result",
            slot, d->victim_node, d->fence_prover_node, d->fence_term,
            ctx->local_node, (unsigned long long)ctx->epoch, auth->fence_term);
        rc = -EBUSY;
        goto out;
    }

    /*
     * FENCING -> FENCED and prover -> UNOWNED in ONE compare-and-write.  Two
     * writes would leave a window in which the descriptor is certified but
     * still owned by a prover that is not going to execute the recovery, and
     * a prover death inside that window would need a takeover of an execution
     * lease nobody ever used.
     */
    *want = *cur;
    want->recov.desc.stage           = MXFS_RECOV_STAGE_FENCED;
    want->recov.desc.stage_seq       = d->stage_seq + 1;
    want->recov.desc.owner_stamp_ms  = recov_stamp_after(d->owner_stamp_ms);
    want->recov.desc.owner_node      = MXFS_RECOV_OWNER_NONE;
    want->recov.desc.owner_epoch     = 0;
    want->recov.desc.owner_slot      = 0;
    want->recov.desc.owner_term      = 0;
    want->recov.desc.fence_kind      = fence_kind;
    want->recov.desc.fence_resv_type = fence_resv_type;
    want->recov.desc.fence_victim_key = fence_victim_key;
    want->recov.desc.fence_stamp_ms  = mxfs_pal_time_ms();
    want->recov.desc.fence_pr_gen    = fence_pr_gen;
    /* fence_prover_node/epoch and fence_term are carried through from the
     * intent: the certificate names the incarnation that did the work. */
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0)
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-FENCE-CERTIFIED slot=%d victim=%u epoch=%llu "
            "kind=%s resv=0x%02x key=%llu pr_gen=%u prover=%u term=%u — "
            "exclusion is PROVED and durable.  The descriptor is now UNOWNED; "
            "the elected replayer may claim it",
            slot, d->victim_node, (unsigned long long)d->victim_epoch,
            mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
            fence_resv_type, (unsigned long long)fence_victim_key,
            fence_pr_gen, ctx->local_node, d->fence_term);
    else
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-FENCE-CERTIFY-FAIL slot=%d victim=%u rc=%d — the "
            "exclusion was proved but the certificate is NOT durable.  This "
            "slice cannot be replayed by anyone: the victim key is consumed, "
            "so no successor can prove exclusion again",
            slot, d->victim_node, rc);
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_fence_takeover(struct mxfs_disklock_ctx *ctx,
                                          int slot,
                                          uint64_t victim_key,
                                          struct mxfs_recov_fence_auth *out_auth)
{
    struct mxfs_disklock_heartbeat *first, *again, *want;
    const struct mxfs_recov_desc *d0, *d1;
    struct mxfs_recov_desc snap;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim_key)
        return -EINVAL;

    first = mxfs_pal_alloc(sizeof(*first));
    again = mxfs_pal_alloc(sizeof(*again));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!first || !again || !want) {
        rc = -ENOMEM;
        goto out;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, first, sizeof(*first));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d0 = recov_desc_of(first);
    if (!d0) {
        rc = recov_desc_present(first) ? -EPROTO : -ENOENT;
        goto out;
    }
    if (d0->stage >= MXFS_RECOV_STAGE_FENCED) {
        rc = -EEXIST;           /* already certified; claim it instead */
        goto out;
    }
    if (d0->stage != MXFS_RECOV_STAGE_FENCING) {
        rc = -EPROTO;
        goto out;
    }
    if (d0->owner_node == ctx->local_node &&
        inc_eq(d0->owner_epoch, ctx->epoch)) {
        recov_fence_auth_issue(out_auth, d0);
        rc = 0;                 /* already ours */
        goto out;
    }
    if (d0->flags & MXFS_RECOV_F_QUARANTINED) {
        rc = -EPERM;
        goto out;
    }
    snap = *d0;

    /*
     * Same discipline as recovery_takeover: abandonment is ABSENCE OF CHANGE
     * across MXFS_RECOV_ABANDON_MS, never clock arithmetic.  And the same
     * precondition — the caller must ALREADY have confirmed the prover's
     * session dead.  A stalled stamp proves only "I observed no refresh".
     *
     * The stakes differ from an execution takeover, though, and in our favour:
     * taking an attempt lease authorises nothing.  It authorises issuing a NEW
     * PREEMPT AND ABORT and certifying THAT result.  If two survivors both get
     * here, exactly one P&A wins and only that one can certify — the loser's
     * fence_kind is RACE_LOST and certify refuses it.
     *
     * Blocks for MXFS_RECOV_ABANDON_MS; never call this on the HB thread.
     */
    mxfs_pal_sleep_ms(MXFS_RECOV_ABANDON_MS);

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d1 = recov_desc_of(again);
    if (!d1) {
        rc = recov_desc_present(again) ? -EPROTO : -ENOENT;
        goto out;
    }
    if (d1->victim_node != snap.victim_node ||
        d1->victim_epoch != snap.victim_epoch ||
        d1->owner_node != snap.owner_node ||
        d1->owner_epoch != snap.owner_epoch ||
        d1->recovery_gen != snap.recovery_gen ||
        d1->fence_term != snap.fence_term ||
        d1->stage != snap.stage ||
        d1->stage_seq != snap.stage_seq ||
        d1->owner_stamp_ms != snap.owner_stamp_ms) {
        rc = -EBUSY;            /* the prover is alive, or a third node took it */
        goto out;
    }

    *want = *again;
    want->recov.desc.owner_node        = ctx->local_node;
    want->recov.desc.owner_epoch       = ctx->epoch;
    want->recov.desc.owner_slot        = (uint16_t)ctx->local_slot;
    want->recov.desc.stage_seq         = d1->stage_seq + 1;
    want->recov.desc.owner_stamp_ms    = recov_stamp_after(d1->owner_stamp_ms);
    want->recov.desc.fence_term        = d1->fence_term + 1;
    want->recov.desc.fence_prover_node = ctx->local_node;
    want->recov.desc.fence_prover_epoch = ctx->epoch;
    want->recov.desc.fence_victim_key  = victim_key;
    want->recov.desc.fence_stamp_ms    = mxfs_pal_time_ms();
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, again, want);
    if (rc == 0) {
        recov_fence_auth_issue(out_auth, &want->recov.desc);
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-FENCE-ATTEMPT-TAKEOVER slot=%d victim=%u from "
            "prover=%u term=%u->%u — the previous prover died with the intent "
            "durable.  We may retry the PREEMPT AND ABORT and certify OUR "
            "result; we may NEVER certify theirs.  If the victim key is "
            "already gone, no exclusion can be proved and this slice stays "
            "unreplayable",
            slot, snap.victim_node, snap.fence_prover_node,
            snap.fence_term, want->recov.desc.fence_term);
    }
out:
    mxfs_pal_free(first);
    mxfs_pal_free(again);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_claim(struct mxfs_disklock_ctx *ctx, int slot,
                                 mxfs_node_id_t victim,
                                 mxfs_epoch_t victim_epoch,
                                 struct mxfs_recov_auth *out_auth)
{
    struct mxfs_disklock_heartbeat *cur, *want;
    const struct mxfs_recov_desc *d;
    const char *why = NULL;
    uint64_t off;
    unsigned int stage;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    want = mxfs_pal_alloc(sizeof(*want));
    if (!cur || !want) {
        mxfs_pal_free(cur);
        mxfs_pal_free(want);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
        goto out;
    }
    if (d->victim_node != victim ||
        !inc_eq(d->victim_epoch, victim_epoch)) {
        rc = -ESTALE;
        goto out;
    }
    /*
     * The certificate is checked BEFORE ownership, and that ordering matters:
     * "-EPERM, not certified" tells the caller to wait for a prover, while
     * "-EBUSY, owned" tells it another replayer already has the job.  Getting
     * -EBUSY for an uncertified descriptor would send an elected replayer off
     * to wait for a recovery that nobody is authorised to run.
     */
    if (!mxfs_recov_cert_proves_exclusion(d,
                ctx->have_fs_identity ? ctx->fs_gen : 0,
                slot, victim, victim_epoch, &why)) {
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-CLAIM-UNCERTIFIED slot=%d victim=%u stage=%u "
            "kind=%u — %s; refusing the claim.  Nothing on this slice may be "
            "replayed, purged, repaired or published",
            slot, victim, d->stage, d->fence_kind, why ? why : "?");
        rc = -EPERM;
        goto out;
    }
    if (d->owner_node == ctx->local_node &&
        inc_eq(d->owner_epoch, ctx->epoch)) {
        recov_auth_issue(out_auth, d);
        rc = (int)d->stage;     /* idempotent: re-acquire our own auth */
        goto out;
    }
    if (d->owner_node != MXFS_RECOV_OWNER_NONE) {
        rc = -EBUSY;
        goto out;
    }

    /*
     * Claiming an UNOWNED lease is NOT takeover (sess74): there is no prior
     * owner to displace and nothing to prove dead, so there is no abandonment
     * wait.  The CAS covers the WHOLE record, so the immutable certificate
     * bytes are carried through byte for byte and any concurrent change to
     * them loses the race.
     */
    stage = d->stage;
    *want = *cur;
    want->recov.desc.owner_node     = ctx->local_node;
    want->recov.desc.owner_epoch    = ctx->epoch;
    want->recov.desc.owner_slot     = (uint16_t)ctx->local_slot;
    want->recov.desc.owner_term     = 1;
    want->recov.desc.stage_seq      = d->stage_seq + 1;
    want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
    recov_desc_seal(want);

    rc = recov_cas_durable(ctx, slot, cur, want);
    if (rc == 0) {
        recov_auth_issue(out_auth, &want->recov.desc);
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P236-RECOV-CLAIMED slot=%d victim=%u epoch=%llu "
            "gen=%llu owner=%u term=1 stage=%u — claimed a CERTIFIED unowned "
            "recovery (proved by node=%u term=%u); this is a recovery lease, "
            "not a member slot",
            slot, victim, (unsigned long long)d->victim_epoch,
            (unsigned long long)d->recovery_gen, ctx->local_node, stage,
            d->fence_prover_node, d->fence_term);
        rc = (int)stage;
    }
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(want);
    return rc;
}

int mxfs_disklock_recovery_slot_status(struct mxfs_disklock_ctx *ctx, int slot,
                                       mxfs_node_id_t victim,
                                       mxfs_epoch_t victim_epoch)
{
    struct mxfs_disklock_heartbeat *cur;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim)
        return -EINVAL;

    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!cur)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0)
        goto out;

    if (recov_desc_present(cur)) {
        rc = recov_desc_of(cur) ? MXFS_RECOV_SLOT_DESCRIPTOR
                                : MXFS_RECOV_SLOT_UNREADABLE;
        goto out;
    }
    if (cur->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, cur)) {
        rc = MXFS_RECOV_SLOT_CONSUMABLE;
        goto out;
    }
    if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
         cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
        cur->node_id != victim) {
        rc = MXFS_RECOV_SLOT_FOREIGN;
        goto out;
    }
    /*
     * Same predicate as recovery_begin's supersession arm, and deliberately no
     * weaker: a valid feature block at the CURRENT proto_gen, flags == ACTIVE
     * (a WITHDRAWN successor is itself dead and owes its own replay), both
     * incarnations nonzero, and the two differing.
     */
    if (inc_valid(victim_epoch) && !inc_eq(cur->epoch, victim_epoch)) {
        if (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            hb_feature_state(cur) == MXFS_HBFEAT_OK &&
            inc_valid(cur->epoch))
            rc = MXFS_RECOV_SLOT_SUPERSEDED;
        else
            rc = MXFS_RECOV_SLOT_FOREIGN;
        goto out;
    }
    rc = MXFS_RECOV_SLOT_UNFENCED;
out:
    mxfs_pal_free(cur);
    return rc;
}

int mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx,
                                             int slot,
                                             mxfs_node_id_t victim,
                                             mxfs_epoch_t victim_epoch,
                                             const struct mxfs_recov_auth *auth,
                                             const char *site,
                                             uint16_t *out_fence_kind)
{
    struct mxfs_disklock_heartbeat *cur;
    const struct mxfs_recov_desc *d;
    const char *why = NULL;
    uint64_t off;
    int rc;

    if (out_fence_kind)
        *out_fence_kind = MXFS_FENCE_KIND_NONE;
    if (!site)
        site = "?";
    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !victim) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u — bad "
            "arguments; a gate that cannot identify what it is authorising "
            "authorises nothing",
            site, slot, victim);
        return -EINVAL;
    }

    /*
     * Deliberately a FRESH READ every time, never a cached snapshot.  The
     * platter is the authority (rule 6) and this gate sits in front of
     * irreversible work: in-place XFS log replay onto the shared LUN,
     * destructive manifest repair, sector zeroing.  One extra 512-byte
     * prio read is not a cost worth trading for that.
     */
    cur = mxfs_pal_alloc(sizeof(*cur));
    if (!cur)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u rc=%d — "
            "could not read the victim's sector; authorisation is UNKNOWN and "
            "unknown is refused",
            site, slot, victim, rc);
        goto out;
    }

    d = recov_desc_of(cur);
    if (!d) {
        rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u rc=%d — "
            "%s.  No certificate means no proof that the victim is excluded "
            "from the LUN, and replaying its journal slice while it can still "
            "write is how two nodes write the same blocks",
            site, slot, victim, rc,
            rc == -EPROTO ? "the descriptor cannot be validated by this build" :
                            "the slot carries no recovery descriptor");
        goto out;
    }

    if (!mxfs_recov_cert_proves_exclusion(d,
                ctx->have_fs_identity ? ctx->fs_gen : 0,
                slot, victim, victim_epoch, &why)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u "
            "epoch=%llu stage=%u kind=%u resv=0x%02x — %s",
            site, slot, victim, (unsigned long long)victim_epoch,
            d->stage, d->fence_kind, d->fence_resv_type, why ? why : "?");
        rc = -EPERM;
        goto out;
    }

    /*
     * Certified.  If the caller holds an execution lease it must still be the
     * current one — otherwise we were taken over while we worked and nothing
     * we are about to do may be published.  A NULL auth is a pre-claim probe
     * and gets the certificate answer only.
     */
    if (auth && !recov_auth_holds(ctx, d, auth)) {
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u — the "
            "slice is certified fenced, but the execution lease is now "
            "owner=%u epoch=%llu term=%u and we hold node=%u epoch=%llu "
            "gen=%llu term=%u.  We were taken over mid-flight",
            site, slot, victim, d->owner_node,
            (unsigned long long)d->owner_epoch, d->owner_term,
            ctx->local_node, (unsigned long long)ctx->epoch,
            (unsigned long long)auth->recovery_gen, auth->owner_term);
        rc = -EBUSY;
        goto out;
    }

    if (out_fence_kind)
        *out_fence_kind = d->fence_kind;
    rc = 0;
out:
    mxfs_pal_free(cur);
    return rc;
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

void mxfs_disklock_set_conflict_cb(struct mxfs_disklock_ctx *ctx,
                                   mxfs_disklock_conflict_cb cb, void *data)
{
    if (!ctx)
        return;
    ctx->conflict_cb = cb;
    ctx->conflict_cb_data = data;
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

/*
 * sess68 — see disklock.h.  Disk truth about slot occupancy, for the
 * recovery coordinator's takeover gate.  Priority read so it pierces every
 * cache layer the way the recovery ops themselves do; a read failure is
 * reported through *out_read_ok and answered "still resident" so a caller
 * that cannot see the sector never concludes departure from silence.
 */
bool mxfs_disklock_slot_holds_incarnation(struct mxfs_disklock_ctx *ctx,
                                          int slot, mxfs_node_id_t node,
                                          mxfs_epoch_t epoch,
                                          bool *out_read_ok)
{
    struct mxfs_disklock_heartbeat *hb;
    uint64_t off;
    bool held;
    int rc;

    if (out_read_ok)
        *out_read_ok = false;
    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        !node)
        return true;            /* cannot prove departure — fail closed */
    /*
     * No incarnation named.  This function's entire contract is fail-closed
     * ("cannot prove departure -> say it is still resident"), but the match
     * below is an equality test, so a zero `epoch` against a real record
     * would return FALSE — i.e. actively assert departure — from an argument
     * that proves nothing.  That is the wrong direction, and it is exactly
     * the wildcard hazard the incarnation work exists to remove.
     */
    if (!inc_valid(epoch))
        return true;

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return true;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, hb, sizeof(*hb));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc < 0) {
        mxfs_pal_free(hb);
        return true;            /* unread sector: assume still resident */
    }
    if (out_read_ok)
        *out_read_ok = true;

    held = (hb->magic == MXFS_DISKLOCK_MAGIC &&
            hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            hb->node_id == node &&
            hb->epoch == epoch &&
            !hb_gen_foreign(ctx, hb));
    mxfs_pal_free(hb);
    return held;
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

    /*
     * Check in-memory mapping first (populated by monitor_node / the
     * auto-monitor).  sess9 (ccloop c7ee71c6) D2: do NOT gate on
     * monitored[] — fire_dead clears it right before invoking expire_cb,
     * and the expire path needs this lookup to mark recovery pending.
     * slot_node_id[] persists (cleared only by unmonitor_node on a clean
     * leave), and a node→slot binding never changes within a generation.
     */
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (ctx->slot_node_id[slot] == node_id)
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
        /* sess9 D2: a WITHDRAWN stamp still names its slot — the expire
         * path must resolve it to mark recovery pending.
         *
         * sess65: so does a RECOVERY_GUARD whose descriptor names this
         * victim.  Without that arm a peer that never witnessed the death
         * resolves slot = -1 and falls into v5_lease_expire_cb's "owns no
         * heartbeat slot, so owns no journal slice — purge immediately" arm,
         * which would purge the in-memory grants of a node whose slice is
         * mid-recovery.  The in-memory slot_node_id[] fast path above masks
         * this for peers that DID see the death, which is why the disk-scan
         * arm is the one that has to be right. */
        if (hb->magic == MXFS_DISKLOCK_MAGIC &&
            (((hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
               hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) &&
              hb->node_id == node_id) ||
             recov_desc_names_node(hb, node_id))) {
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
 * D-LOG-SLICE-SHARED-MULTIWRITER (sess219 ruling, claim-time layer): the
 * exclusive bound on slot numbers a CLAIM may scan.  A slot's journal slice
 * is the identically numbered slice, so a volume formatted with N slices
 * supports at most N members — claiming slot >= N would admit a node with
 * no journal.  Monitor/purge/fence scans deliberately do NOT use this
 * bound: legacy out-of-range occupants must still be seen, declared dead,
 * and fenced.
 */
static uint32_t hb_claim_slot_bound(const struct mxfs_disklock_ctx *ctx)
{
    if (ctx->slot_limit && ctx->slot_limit < MXFS_DISKLOCK_HB_SLOTS)
        return ctx->slot_limit;
    return MXFS_DISKLOCK_HB_SLOTS;
}

/*
 * D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376, sess377 RULE-5 ruling
 * item 1 ("correct the ENOSPC diagnostic; count and report guards").
 *
 * The old message said the cluster was FULL and told the operator to
 * "reformat with more slices (mkfs_mxfs -n)".  Both halves can be wrong and
 * the advice can be actively destructive:
 *
 *   - a slot occupied by a RECOVERY_GUARD is NOT a member.  It is a durable
 *     terminal-refusal verdict awaiting operator repair, and it is the only
 *     copy of that verdict.  Reformatting destroys the very evidence the
 *     quarantine exists to preserve.
 *   - a WITHDRAWN slot is a dirty journal slice awaiting fence+replay, i.e. a
 *     transient state the monitor is already working on — retrying the mount
 *     is the correct response, not reformatting.
 *   - at the maximum supported cluster size the advice is UNFOLLOWABLE:
 *     mkfs_mxfs refuses -n > 32, so a 32-slice volume has no larger format.
 *
 * So classify the table and say what is actually there.  Diagnostic only —
 * this changes no claim decision.  Out-of-range occupants (slot >= slot_max
 * on a volume with fewer slices than MXFS_DISKLOCK_HB_SLOTS) are counted and
 * reported separately: they are a format/protocol violation in their own
 * right and must never be mistaken for admissible members.
 */
static void hb_report_claim_exhausted(struct mxfs_disklock_ctx *ctx,
                                      uint32_t slot_max)
{
    struct mxfs_disklock_heartbeat *rec;
    uint32_t slot;
    uint32_t n_active = 0, n_guard = 0, n_withdrawn = 0;
    uint32_t n_other = 0, n_unread = 0, n_outofrange = 0;
    uint32_t n_recovering = 0, n_sweepguard = 0, n_bucketguard_hi = 0;
    int first_guard = -1;
    mxfs_node_id_t first_guard_node = 0;

    rec = mxfs_pal_alloc(sizeof(*rec));
    if (!rec) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: no free heartbeat slot in 0..%u (no memory to "
                     "classify the table)", slot_max - 1);
        return;
    }

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        bool occupied;

        if (mxfs_pal_bdev_read(ctx->dev, off, rec, sizeof(*rec)) < 0) {
            if (slot < slot_max)
                n_unread++;
            continue;
        }
        occupied = (rec->magic == MXFS_DISKLOCK_MAGIC) &&
                   !hb_gen_foreign(ctx, rec);

        if (slot >= slot_max) {
            /* sess377: beyond the volume's slice count, exactly ONE kind of
             * record is legitimate — the unclaimed-bucket sweep's transient
             * RECOVERY_GUARD.  mxfs_unclaimed_bucket_scan() iterates
             * b < XFS_AGI_UNLINKED_BUCKETS (64) and uses the bucket index AS
             * the disklock slot index, so on an N-slice volume buckets
             * N..63 are always unclaimed and their sweeps guard slots N..63
             * by design.  A MEMBER-shaped record up here (ACTIVE or
             * WITHDRAWN) is a different matter: this volume has no journal
             * slice for it, so it is a format/protocol violation. */
            if (occupied &&
                rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
                !recov_desc_present(rec))
                n_bucketguard_hi++;
            else if (occupied && rec->flags != 0)
                n_outofrange++;
            continue;
        }
        if (!occupied)
            continue;
        switch (rec->flags) {
        case MXFS_DISKLOCK_FLAG_ACTIVE:
            n_active++;
            break;
        case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD: {
            /* sess377: a RECOVERY_GUARD is TWO different things and the
             * difference decides what the operator must do.
             *   - with a valid QUARANTINED descriptor: a terminal verdict.
             *     Permanent until an operator accepts the loss.
             *   - with no descriptor at all: the unclaimed-bucket sweep's
             *     transient working guard (mxfs_unclaimed_bucket_scan takes
             *     one on any unclaimed slot < 64 to sweep that AGI bucket).
             *     It clears itself; reporting it as a quarantine would send
             *     the operator hunting a verdict that does not exist.
             * recov_desc_present() requires MXFS_RECOV_DESC_MAGIC in the
             * body, which a sweep guard never writes. */
            const struct mxfs_recov_desc *d = recov_desc_of(rec);

            if (d && (d->flags & MXFS_RECOV_F_QUARANTINED)) {
                n_guard++;
                if (first_guard < 0) {
                    first_guard = (int)slot;
                    first_guard_node = rec->node_id;
                }
            } else if (d) {
                n_recovering++;
            } else {
                n_sweepguard++;
            }
            break;
        }
        case MXFS_DISKLOCK_FLAG_WITHDRAWN:
            n_withdrawn++;
            break;
        default:
            n_other++;
            break;
        }
    }
    mxfs_pal_free(rec);

    mxfs_pal_log(MXFS_LOG_ERR,
                 "P300-CLAIM-EXHAUSTED no free heartbeat slot in 0..%u — "
                 "this volume has %u log slices, and a slot beyond them would "
                 "have no journal.  Table: %u live member(s), %u quarantined "
                 "recovery verdict(s), %u withdrawn slice(s) awaiting replay, "
                 "%u recovery lease(s) in progress, %u bucket-sweep guard(s), "
                 "%u other, %u unreadable (plus %u bucket-sweep guard(s) above "
                 "the slice count, which are normal).",
                 slot_max - 1, slot_max, n_active, n_guard, n_withdrawn,
                 n_recovering, n_sweepguard, n_other, n_unread,
                 n_bucketguard_hi);
    if (n_outofrange)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "P300-CLAIM-OUTOFRANGE %u occupied slot(s) at or "
                     "above %u — a FORMAT/PROTOCOL VIOLATION: this volume has "
                     "no journal slice for them.  They are not members and were "
                     "not counted as admissible.",
                     n_outofrange, slot_max);

    if (n_guard)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "P300-CLAIM-QUARANTINE %u slot(s) hold a TERMINAL "
                     "REFUSAL VERDICT awaiting operator repair (first: slot %d, "
                     "victim node %u).  Those slices are unreplayable, so this "
                     "volume's usable member count is %u, not %u.  Do NOT "
                     "reformat: mkfs_mxfs -f destroys the verdict, and at 32 "
                     "slices there is no larger format (mkfs_mxfs refuses "
                     "-n > 32).  Read the verdict at "
                     "/sys/kernel/debug/mxfs/<dev>/recovery_blocked on a mounted "
                     "node, or offline with: chk_mxfs --show-quarantine <dev>",
                     n_guard, first_guard, (unsigned)first_guard_node,
                     slot_max - n_guard, slot_max);
    else if (n_withdrawn || n_recovering || n_sweepguard)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "P300-CLAIM-WITHDRAWN %u slot(s) hold a dirty WITHDRAWN "
                     "slice awaiting fence+replay, %u hold a recovery lease in "
                     "progress, %u hold a transient bucket-sweep guard.  All "
                     "three are TRANSIENT — a live peer resolves them.  Retry "
                     "the mount rather than reformatting.",
                     n_withdrawn, n_recovering, n_sweepguard);
    else
        mxfs_pal_log(MXFS_LOG_ERR,
                     "P300-CLAIM-FULL every slice is held by a live "
                     "member.  The cluster is genuinely at capacity; admitting "
                     "more nodes needs a volume formatted with more slices "
                     "(mkfs_mxfs -n, max 32).");
}

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
    uint32_t slot_max = hb_claim_slot_bound(ctx);
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
        bool fresh_claim = false;   /* sess32: pass-2 = adopted slice */

        /* Pass 1: re-claim our own prior-mount slot (FUA reads). */
        for (slot = 0; slot < slot_max; slot++) {
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
            fresh_claim = true;
            for (slot = 0; slot < slot_max; slot++) {
                uint64_t off = ctx->base_offset +
                               (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
                if (rc < 0)
                    continue;
                /* sess43: never claim a guarded slot (see CAW pass 2). */
                if (rec->magic == MXFS_DISKLOCK_MAGIC &&
                    !hb_gen_foreign(ctx, rec) &&
                    rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
                    continue;
                /* sess182: never claim an own-generation WITHDRAWN slot
                 * either.  A WITHDRAWN record is a dirty journal slice whose
                 * owner declared voluntary death — the slice awaits
                 * fence+replay, and claiming it as fresh/ADOPTED silently
                 * discards the committed-but-undestaged transactions it
                 * protects.  The monitor's WITHDRAWN arm recovers it. */
                if (rec->magic == MXFS_DISKLOCK_MAGIC &&
                    !hb_gen_foreign(ctx, rec) &&
                    rec->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: P274-CLAIM-WITHDRAWN-SKIP slot=%u node=%u — "
                        "dirty withdrawn slice awaits recovery; claiming a "
                        "different slot",
                        slot, rec->node_id);
                    continue;
                }
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
        hb_prov_derive(ctx, rec, fresh_claim);          /* sess346 #92 */
        memset(hb, 0, sizeof(*hb));
        hb->magic = MXFS_DISKLOCK_MAGIC;
        hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
        hb->node_id = ctx->local_node;
        hb->fs_gen = ctx->fs_gen;
        hb->timestamp_ms = mxfs_pal_time_ms();
        hb->epoch = ctx->epoch;
        hb_feature_fill(ctx, hb);       /* sess42 C7 */
        hb->prov = ctx->own_prov;       /* sess346 #92 */

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
                ctx->slice_adopted = fresh_claim;
                /* sess78: read-back-verified image is the CAS compare source.
                 * Use `rec` (what the platter actually holds), not `hb`. */
                ctx->hb_img = *rec;
                ctx->hb_img_valid = true;
                mxfs_pal_mutex_unlock(ctx->lock);
                mxfs_pal_free(hb);
                mxfs_pal_free(rec);
                mxfs_pal_log(MXFS_LOG_WARN,
                             "disklock: claimed heartbeat slot %d for node %u "
                             "(non-CAW verified, attempt %d, %s)",
                             found_slot, ctx->local_node, attempt,
                             fresh_claim ? "fresh claim — slice ADOPTED" :
                                           "own-stamp reclaim");
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
    /* sess377 item 1: the same honest table classification on this path. */
    if (rc == -ENOSPC)
        hb_report_claim_exhausted(ctx, slot_max);
    return rc < 0 ? rc : -ENOSPC;
}

int mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *hb;
    struct mxfs_disklock_heartbeat *expected;
    uint32_t slot;
    uint32_t slot_max;
    int attempt;
    int rc = -ENOSPC;

    if (!ctx || !ctx->dev)
        return -EINVAL;
    slot_max = hb_claim_slot_bound(ctx);

    /*
     * A claim establishes a NEW published tenancy, so it draws a NEW
     * incarnation: losing a slot TERMINATES an incarnation, and that value
     * may never establish a later tenancy.  Drawing here also covers the
     * non-CAW fallback — claim_slot_noncaw() is only reachable from this
     * function.
     *
     * This deliberately does NOT enter the pass-1 own-stamp match below.
     * That match is by node_id ONLY, and must stay that way: it is what lets
     * a rebooted node re-claim its own slot with slice_adopted=false, i.e.
     * FULL replay of its PREVIOUS incarnation's log records.  Adding an epoch
     * equality test there would push every rebooted node onto a pass-2 fresh
     * claim, whose adopted-slice gate suppresses image replay — silently
     * abandoning that node's own unreplayed journal slice.
     */
    ctx->epoch = hb_draw_incarnation();
    if (!inc_valid(ctx->epoch)) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "disklock: no entropy for a mount incarnation — "
                     "refusing to claim a heartbeat slot (failing closed)");
        return -EIO;
    }

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
        bool fresh_claim = false;   /* sess32: pass-2 = adopted slice */

        /* First pass: look for our own node_id (re-claim from previous
         * mount).  Keep the read image — it is the CAW compare buffer. */
        for (slot = 0; slot < slot_max; slot++) {
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
            fresh_claim = true;
            for (slot = 0; slot < slot_max; slot++) {
                uint64_t off = ctx->base_offset +
                               (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                rc = mxfs_pal_bdev_read(ctx->dev, off, expected,
                                        sizeof(*expected));
                if (rc < 0)
                    continue;
                /* sess43: NEVER claim a slot carrying a recovery GUARD.
                 * The claim path must not judge guard freshness — the only
                 * sound test needs a timed re-read (see hb_guard_abandoned)
                 * and this path is latency-critical at mount.  Skipping is
                 * always safe: 64 slots, and an ABANDONED guard is reclaimed
                 * by the next live sweeper's guard_slot, so a dead holder
                 * cannot strand the slot permanently. */
                if (expected->magic == MXFS_DISKLOCK_MAGIC &&
                    !hb_gen_foreign(ctx, expected) &&
                    expected->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
                    continue;
                /* sess182: same rule for WITHDRAWN — the record marks a
                 * dirty journal slice awaiting fence+replay.  Consuming it
                 * here as a fresh claim (slice_adopted) discards the
                 * committed transactions in that slice; skip and let the
                 * monitor's WITHDRAWN arm drive recovery. */
                if (expected->magic == MXFS_DISKLOCK_MAGIC &&
                    !hb_gen_foreign(ctx, expected) &&
                    expected->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                        "mxfs: P274-CLAIM-WITHDRAWN-SKIP slot=%u node=%u — "
                        "dirty withdrawn slice awaits recovery; claiming a "
                        "different slot",
                        slot, expected->node_id);
                    continue;
                }
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
            hb_report_claim_exhausted(ctx, slot_max);
            return -ENOSPC;
        }

        /* Atomically claim: CAW from the observed image to our record. */
        hb_prov_derive(ctx, expected, fresh_claim);     /* sess346 #92 */
        memset(hb, 0, sizeof(*hb));
        hb->magic = MXFS_DISKLOCK_MAGIC;
        hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
        hb->node_id = ctx->local_node;
        hb->fs_gen = ctx->fs_gen;
        hb->timestamp_ms = mxfs_pal_time_ms();
        hb->epoch = ctx->epoch;
        hb_feature_fill(ctx, hb);       /* sess42 C7 */
        hb->prov = ctx->own_prov;       /* sess346 #92 */

        {
            uint64_t off = ctx->base_offset +
                           (uint64_t)found_slot * MXFS_DISKLOCK_RECORD_SIZE;
            rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expected, hb);
        }

        if (rc == 0) {
            ctx->local_slot = found_slot;
            ctx->slice_adopted = fresh_claim;
            /* sess78: the CAW just made `hb` the exact on-disk image — it is
             * the compare source for every later own-slot write. */
            ctx->hb_img = *hb;
            ctx->hb_img_valid = true;
            mxfs_pal_mutex_unlock(ctx->lock);
            mxfs_pal_free(hb);
            mxfs_pal_free(expected);
            mxfs_pal_log(MXFS_LOG_WARN,
                         "disklock: claimed heartbeat slot %d for node %u "
                         "(attempt %d, %s)",
                         found_slot, ctx->local_node, attempt,
                         fresh_claim ? "fresh claim — slice ADOPTED" :
                                       "own-stamp reclaim");
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

/*
 * sess94: the {slot, node_id, incarnation} triple.  See disklock.h.
 *
 * Fails closed and ALL-OR-NOTHING: a partial identity is worse than none,
 * because a consumer that gets a slot but a zero incarnation cannot tell
 * "this mount" from "some earlier tenancy of the same slot", which is
 * exactly the confusion the incarnation exists to prevent.
 */
bool mxfs_disklock_mount_identity(struct mxfs_disklock_ctx *ctx,
                                  uint32_t *slot, mxfs_node_id_t *node,
                                  mxfs_epoch_t *epoch)
{
    int          s;
    mxfs_epoch_t e;

    if (slot)
        *slot = 0;
    if (node)
        *node = 0;
    if (epoch)
        *epoch = 0;

    if (!ctx)
        return false;

    s = ctx->local_slot;
    e = ctx->epoch;
    if (s < 0 || s >= MXFS_DISKLOCK_HB_SLOTS)
        return false;
    if (!ctx->local_node)
        return false;
    if (!inc_valid(e))
        return false;

    if (slot)
        *slot = (uint32_t)s;
    if (node)
        *node = ctx->local_node;
    if (epoch)
        *epoch = e;
    return true;
}

/* ── sess43: recovery GUARD ops (see MXFS_DISKLOCK_FLAG_RECOVERY_GUARD) ── */

/* Staleness by wall delta against the writer's stamp.  Nodes are NTP-synced;
 * an absurdly ahead-of-us stamp (> one stale window) is garbage, not fresh —
 * otherwise a skewed writer could block a slot forever. */
/*
 * Is a recovery GUARD abandoned (its holder died mid-sweep)?
 *
 * sess43 CORRECTNESS FIX — the first version of this compared
 * mxfs_pal_time_ms() against hb->timestamp_ms.  That is WRONG across nodes:
 * mxfs_pal_time_ms() is ktime_get_boottime_ns()/1e6, i.e. each node's own
 * UPTIME, so the subtraction mixes the reader's boot clock with the writer's.
 * Two nodes with different uptimes — the normal case — would compute a delta
 * of hours and judge a perfectly FRESH guard stale, which defeats the entire
 * exclusion the guard exists to provide.  (Same trap the heartbeat monitor
 * already avoids, and that tests/hb_live_count.sh documents: HB timestamps
 * are only ever comparable to THEMSELVES.)
 *
 * The only sound test with these clocks is CHANGE: a live holder re-stamps
 * its guard (mxfs_disklock_guard_refresh) as it sweeps, so re-read the record
 * after a refresh interval and see whether the timestamp moved.  Callers are
 * background paths (the unclaimed-bucket scan), so the sleep is affordable —
 * and this is never on the claim fast path, which now skips guards outright
 * rather than judging them.
 */
static bool hb_guard_abandoned(struct mxfs_disklock_ctx *ctx, int slot,
                               const struct mxfs_disklock_heartbeat *first)
{
    struct mxfs_disklock_heartbeat *again;
    uint64_t off;
    bool abandoned = false;
    int rc;

    if (first->node_id == ctx->local_node)
        return false;               /* ours */
    again = mxfs_pal_alloc(sizeof(*again));
    if (!again)
        return false;               /* cannot prove abandoned => leave it */
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_sleep_ms(MXFS_DISKLOCK_GUARD_REFRESH_MS * 3);

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (rc == 0) {
        if (again->magic != MXFS_DISKLOCK_MAGIC ||
            again->flags != MXFS_DISKLOCK_FLAG_RECOVERY_GUARD ||
            hb_gen_foreign(ctx, again)) {
            abandoned = true;       /* guard released/overwritten meanwhile */
        } else if (again->node_id == first->node_id &&
                   again->timestamp_ms == first->timestamp_ms) {
            abandoned = true;       /* holder stopped re-stamping => dead */
        }
    }
    mxfs_pal_free(again);
    return abandoned;
}

int mxfs_disklock_guard_slot(struct mxfs_disklock_ctx *ctx, int slot)
{
    struct mxfs_disklock_heartbeat *cur, *g;
    uint64_t off;
    bool pend;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
        slot == ctx->local_slot)
        return -EINVAL;
    if (ctx->guard_slot >= 0)
        return -EBUSY;

    cur = mxfs_pal_alloc(sizeof(*cur));
    g = mxfs_pal_alloc(sizeof(*g));
    if (!cur || !g) {
        mxfs_pal_free(cur);
        mxfs_pal_free(g);
        return -ENOMEM;
    }
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    pend = ctx->recovery_pending[slot];
    rc = pend ? 0 : mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
    mxfs_pal_mutex_unlock(ctx->lock);
    if (pend) {
        rc = -EBUSY;            /* recovery protocol owns the slot */
        goto out;
    }
    if (rc < 0)
        goto out;

    /*
     * sess65 rule 4 (victim-manifest freeze): a guard carrying a RECOVERY
     * DESCRIPTOR is a recovery lease, strictly stronger than this sweep
     * guard.  It is never takeable — not even when abandoned, which is why
     * this test precedes hb_guard_abandoned() rather than joining it.  An
     * abandoned recovery is resumed via mxfs_disklock_recovery_takeover(),
     * which preserves the victim identity and the milestone; overwriting it
     * with a sweep guard would destroy both.
     */
    if (recov_desc_present(cur)) {
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P234-GUARD-REFUSED slot=%d — slot holds a recovery "
            "lease (victim mid-recovery); the unclaimed-bucket sweep may not "
            "take it", slot);
        rc = -EBUSY;
        goto out;
    }

    /* Guardable: empty, foreign-gen ghost, bad magic, or a STALE guard.
     * NOT guardable: a member (ACTIVE — live or dead-pending-detection),
     * a WITHDRAWN corpse (death pipeline owns it), or a fresh guard. */
    if (cur->magic == MXFS_DISKLOCK_MAGIC && !hb_gen_foreign(ctx, cur) &&
        (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
         cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ||
         (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
          !hb_guard_abandoned(ctx, slot, cur)))) {
        rc = -EBUSY;
        goto out;
    }

    memset(g, 0, sizeof(*g));
    g->magic = MXFS_DISKLOCK_MAGIC;
    g->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
    g->node_id = ctx->local_node;
    g->fs_gen = ctx->fs_gen;
    g->timestamp_ms = mxfs_pal_time_ms();
    g->epoch = ctx->epoch;
    hb_feature_fill(ctx, g);

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, cur, g);
    if (rc == -EOPNOTSUPP) {
        /* Non-CAW transport: write + settle + FUA read-back confirm, the
         * claim_slot_noncaw discipline (node_id + timestamp tiebreak). */
        rc = write_sector_fua(ctx, off, g);
        if (rc == 0) {
            mxfs_pal_sleep_ms(30);
            rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
            if (rc == 0 &&
                !(cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
                  cur->node_id == ctx->local_node &&
                  cur->timestamp_ms == g->timestamp_ms))
                rc = -EAGAIN;
        }
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == 0) {
        ctx->guard_slot = slot;
        ctx->guard_img = *g;
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P99-GUARD slot=%d node=%u — recovery guard held for unclaimed-bucket sweep",
            slot, ctx->local_node);
    }
out:
    mxfs_pal_free(cur);
    mxfs_pal_free(g);
    return rc;
}

int mxfs_disklock_guard_refresh(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *cur, *g2;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev)
        return -EINVAL;
    if (ctx->guard_slot < 0)
        return -ESTALE;

    cur = mxfs_pal_alloc(sizeof(*cur));
    g2 = mxfs_pal_alloc(sizeof(*g2));
    if (!cur || !g2) {
        mxfs_pal_free(cur);
        mxfs_pal_free(g2);
        return -ENOMEM;         /* guard retained; transient */
    }
    off = ctx->base_offset +
          (uint64_t)ctx->guard_slot * MXFS_DISKLOCK_RECORD_SIZE;
    *g2 = ctx->guard_img;
    g2->timestamp_ms = mxfs_pal_time_ms();
    if (g2->timestamp_ms <= ctx->guard_img.timestamp_ms)
        g2->timestamp_ms = ctx->guard_img.timestamp_ms + 1;

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, &ctx->guard_img, g2);
    if (rc == -EOPNOTSUPP) {
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
        if (rc == 0) {
            if (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
                cur->node_id == ctx->local_node &&
                cur->timestamp_ms == ctx->guard_img.timestamp_ms)
                rc = write_sector_fua(ctx, off, g2);
            else
                rc = -EAGAIN;
        }
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == 0) {
        ctx->guard_img = *g2;
    } else if (rc == -EAGAIN) {
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P99-GUARD-LOST slot=%d — record changed under us; sweep must abort",
            ctx->guard_slot);
        ctx->guard_slot = -1;
        rc = -ESTALE;
    }
    /* other rc: transient IO — guard retained, caller may retry or abort */
    mxfs_pal_free(cur);
    mxfs_pal_free(g2);
    return rc;
}

void mxfs_disklock_unguard(struct mxfs_disklock_ctx *ctx)
{
    struct mxfs_disklock_heartbeat *cur, *z;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || ctx->guard_slot < 0)
        return;
    cur = mxfs_pal_alloc(sizeof(*cur));
    z = mxfs_pal_alloc(sizeof(*z));
    if (!cur || !z) {
        /* Cannot zero now: leave the guard to go stale (62s) — claimable
         * again after; loud so it is visible. */
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P99-UNGUARD-ENOMEM slot=%d — guard left to expire",
            ctx->guard_slot);
        ctx->guard_slot = -1;
        mxfs_pal_free(cur);
        mxfs_pal_free(z);
        return;
    }
    off = ctx->base_offset +
          (uint64_t)ctx->guard_slot * MXFS_DISKLOCK_RECORD_SIZE;
    memset(z, 0, sizeof(*z));

    mxfs_pal_mutex_lock(ctx->lock);
    rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, &ctx->guard_img, z);
    if (rc == -EOPNOTSUPP) {
        rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
        if (rc == 0) {
            if (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
                cur->node_id == ctx->local_node &&
                cur->timestamp_ms == ctx->guard_img.timestamp_ms)
                rc = write_sector_fua(ctx, off, z);
            else
                rc = -EAGAIN;
        }
    }
    mxfs_pal_mutex_unlock(ctx->lock);

    if (rc == -EAGAIN)
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P99-UNGUARD-RACED slot=%d — successor overwrote a stale guard; theirs now",
            ctx->guard_slot);
    else if (rc)
        mxfs_pal_log(MXFS_LOG_ERR,
            "disklock: P99-UNGUARD-IOERR slot=%d rc=%d — guard left to expire",
            ctx->guard_slot, rc);
    else
        mxfs_pal_log(MXFS_LOG_WARN,
            "disklock: P99-UNGUARD slot=%d — recovery guard released",
            ctx->guard_slot);
    ctx->guard_slot = -1;
    mxfs_pal_free(cur);
    mxfs_pal_free(z);
}

int mxfs_disklock_slot_unclaimed(struct mxfs_disklock_ctx *ctx, int slot)
{
    struct mxfs_disklock_heartbeat *rec;
    bool pend;
    uint64_t off;
    int rc;

    if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;
    if (slot == ctx->local_slot)
        return 0;
    rec = mxfs_pal_alloc(sizeof(*rec));
    if (!rec)
        return -ENOMEM;
    off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

    mxfs_pal_mutex_lock(ctx->lock);
    pend = ctx->recovery_pending[slot];
    rc = pend ? 0 : mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
    mxfs_pal_mutex_unlock(ctx->lock);

    if (pend)
        rc = 0;                 /* recovery protocol owns it: not unclaimed */
    else if (rc < 0)
        ;                       /* propagate the IO error */
    else if (rec->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, rec))
        rc = 1;                 /* empty / pre-mkfs ghost */
    else if (rec->flags == MXFS_DISKLOCK_FLAG_EMPTY)
        rc = 1;
    else if (recov_lease_covers_node(rec, rec->node_id))
        rc = 0;                 /* sess65: a RECOVERY LEASE, never unclaimed —
                                 * the slice underneath is mid-recovery even
                                 * if its owner stopped re-stamping */
    else if (rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
             hb_guard_abandoned(ctx, slot, rec))
        rc = 1;                 /* dead guard-holder: takeover allowed */
    else
        rc = 0;                 /* ACTIVE / WITHDRAWN / fresh guard */
    mxfs_pal_free(rec);
    return rc;
}

/* sess32: true when the HB slot was won by the pass-2 fresh scan — the log
 * slice this node inherits may carry an already-recovered (or foreign)
 * incarnation's dirty records, whose images must not be re-applied at mount
 * (D-FOREIGN-REPLAY-UNGATED-IMAGES: cross-slice LSNs are incomparable). */
bool mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx)
{
    if (!ctx)
        return false;
    return ctx->slice_adopted;
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

    /* Snapshot pass.  sess38: per-slot lock (see read_all comment) — the
     * old whole-loop hold starved the heartbeat writer for tens of seconds
     * under device saturation; this path runs from RUNTIME acquire/join
     * paths (v5_mount), not just mount. */
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        int rc;

        snap_active[slot] = false;
        if ((int)slot == skip_slot)
            continue;

        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        mxfs_pal_mutex_unlock(ctx->lock);
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

            /* sess38: per-slot lock (see snapshot-pass comment) — this poll
             * repeats up to threshold_ms/poll_ms times; the old whole-loop
             * hold multiplied the heartbeat-writer starvation. */
            for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
                uint64_t off;
                int rc;

                if (!snap_active[slot] || advanced[slot])
                    continue;

                off = ctx->base_offset +
                      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
                mxfs_pal_mutex_lock(ctx->lock);
                rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
                mxfs_pal_mutex_unlock(ctx->lock);
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

/* sess185: see disklock.h — single-pass WITHDRAWN scan for the mount
 * barrier's step-6.5 cohort.  A WITHDRAWN record is a voluntary death
 * declaration over a DIRTY slice; the old barrier snapshotted ACTIVE
 * slots only, so these slices were recovered ASYNC by the monitor while
 * the mount completed and took locks over unreplayed resources. */
int mxfs_disklock_get_withdrawn_slots(struct mxfs_disklock_ctx *ctx,
                                       int skip_slot,
                                       uint64_t *out_mask,
                                       mxfs_node_id_t *out_node,
                                       mxfs_epoch_t *out_epoch)
{
    struct mxfs_disklock_heartbeat *hb;
    uint64_t mask = 0;
    uint32_t slot;

    if (!ctx || !out_mask || !ctx->dev)
        return -EINVAL;
    *out_mask = 0;

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return -ENOMEM;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        int rc;

        if ((int)slot == skip_slot)
            continue;

        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0)
            continue;
        if (hb->magic != MXFS_DISKLOCK_MAGIC ||
            hb->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN ||
            hb_gen_foreign(ctx, hb))
            continue;

        mask |= (1ULL << slot);
        if (out_node)
            out_node[slot] = hb->node_id;
        if (out_epoch)
            out_epoch[slot] = hb->epoch;
    }

    mxfs_pal_free(hb);
    *out_mask = mask;
    return 0;
}

/* sess190: see disklock.h.  The admission barrier's requires-recovery
 * sweep.  Unlike get_withdrawn_slots this also reports slots the fence
 * pipeline has already converted to a recovery descriptor — the sess189
 * measured root was exactly that conversion racing the mount's
 * WITHDRAWN-only scan (monitor consumed the stamp during DLM init, the
 * step-6.5 scan found nothing, and the barrier went live over an
 * unreplayed slice). */
int mxfs_disklock_get_recovery_pending_slots(struct mxfs_disklock_ctx *ctx,
                                             int skip_slot,
                                             uint64_t *out_mask,
                                             mxfs_node_id_t *out_node,
                                             mxfs_epoch_t *out_epoch)
{
    struct mxfs_disklock_heartbeat *hb;
    uint64_t mask = 0;
    uint32_t slot;

    if (!ctx || !out_mask || !ctx->dev)
        return -EINVAL;
    *out_mask = 0;

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return -ENOMEM;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
        uint64_t off = ctx->base_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        const struct mxfs_recov_desc *d;
        int rc;

        if ((int)slot == skip_slot)
            continue;

        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0) {
            /* Unread slot: may hold anything — same fail-closed rule as
             * the (b2) residue gate. */
            mask |= (1ULL << slot);
            continue;
        }
        if (hb->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, hb))
            continue;               /* consumable / pre-mkfs ghost */

        if (hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
            mask |= (1ULL << slot);
            if (out_node)
                out_node[slot] = hb->node_id;
            if (out_epoch)
                out_epoch[slot] = hb->epoch;
            continue;
        }
        if (!recov_desc_present(hb))
            continue;               /* ACTIVE / EMPTY shapes */
        d = recov_desc_of(hb);
        if (!d) {
            /* The sector IS a recovery lease but this build cannot
             * validate it: the slice underneath is mid-recovery under
             * evidence we cannot interpret.  Frozen — pending. */
            mask |= (1ULL << slot);
            continue;
        }
        if (d->stage >= MXFS_RECOV_STAGE_GRANTS_RELEASED)
            continue;               /* complete, awaiting slot zeroing */
        mask |= (1ULL << slot);
        if (out_node)
            out_node[slot] = d->victim_node;
        if (out_epoch)
            out_epoch[slot] = d->victim_epoch;
    }

    mxfs_pal_free(hb);
    *out_mask = mask;
    return 0;
}

/*
 * sess54 (D-FOREIGN-REPLAY step 4a) — CONTINUOUS, CANCELLABLE DEAD CONFIRM.
 *
 * mxfs_disklock_get_stale_slot_mask() above answers "did this slot advance
 * during ONE window", and it re-baselines on every call.  That is fine for
 * the 10 s mount probe, whose only consumer is a decision to defer.  It is
 * NOT sufficient to justify a hardware fence, and chaining several short
 * calls and AND-ing the results does not fix it: an advance that lands
 * between call N's last poll and call N+1's baseline read is invisible to
 * both — N never sees it, N+1 adopts it as its own baseline — so a node
 * whose heartbeat is merely slow can be declared dead by the chain even
 * though it advanced inside the nominal window.  (GPT RULE-5 review, sess54
 * item 3.)
 *
 * This entry point keeps ONE baseline for the whole window and samples
 * against it, so "never advanced" means never, continuously.  It also
 * re-checks identity on every sample rather than once at the end: a final
 * node-id comparison cannot see an A -> inactive -> A' reclaim in between,
 * and node ids are UUID-derived, so a rebooted host returns with the SAME
 * id.  The heartbeat's own epoch (mount incarnation) is what distinguishes
 * them, and it is pinned at baseline and enforced every sample.
 *
 * A candidate is dropped — i.e. NOT confirmed dead — on any of:
 *   timestamp advanced, node id changed, epoch changed, record no longer
 *   ACTIVE, fs_gen foreign, or the read failed.  Every ambiguity resolves
 *   toward "leave it alone": a missed fence costs availability, a wrong
 *   fence shoots a healthy member.
 *
 * expect_node[] (optional) pins which incarnation the CALLER saw, so a slot
 * that changed hands before this even started is rejected at baseline.
 *
 * cancel (optional) is polled between samples so an unmount can abandon the
 * wait.  It is deliberately NOT honoured after this returns: the caller's
 * fence -> mark-pending sequence must not be interruptible half way.
 *
 * Returns 0 with *out_confirmed set (0 if cancelled), or a negative errno.
 */
int mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx,
                                    uint64_t candidate_mask,
                                    const mxfs_node_id_t *expect_node,
                                    uint32_t samples,
                                    const volatile int *cancel,
                                    uint64_t *out_confirmed,
                                    mxfs_epoch_t *out_epoch)
{
    struct mxfs_disklock_heartbeat *hb;
    uint64_t base_ts[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_epoch_t base_epoch[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_node_id_t base_node[MXFS_DISKLOCK_HB_SLOTS];
    uint64_t live = 0;
    uint32_t slot;
    uint32_t i;

    if (!ctx || !out_confirmed || !ctx->dev)
        return -EINVAL;

    *out_confirmed = 0;
    if (out_epoch) {
        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++)
            out_epoch[slot] = 0;
    }
    if (!candidate_mask || !samples)
        return 0;

    hb = mxfs_pal_alloc(sizeof(*hb));
    if (!hb)
        return -ENOMEM;

    /* ── Baseline pass ───────────────────────────────────────────── */
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint64_t off;
        int rc;

        if (!(candidate_mask & (1ULL << slot)))
            continue;

        off = ctx->base_offset +
              (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        mxfs_pal_mutex_lock(ctx->lock);
        rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
        mxfs_pal_mutex_unlock(ctx->lock);
        if (rc < 0)
            continue;
        if (hb->magic != MXFS_DISKLOCK_MAGIC ||
            hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
            hb_gen_foreign(ctx, hb))
            continue;
        if (expect_node && expect_node[slot] &&
            hb->node_id != expect_node[slot]) {
            mxfs_pal_log(MXFS_LOG_INFO,
                "disklock: confirm slot %u baseline node=%u != expected %u "
                "— slot changed hands, dropping candidate",
                slot, hb->node_id, expect_node[slot]);
            continue;
        }

        base_ts[slot] = hb->timestamp_ms;
        base_epoch[slot] = hb->epoch;
        base_node[slot] = hb->node_id;
        live |= (1ULL << slot);
    }

    /* ── Sample against that ONE baseline ────────────────────────── */
    for (i = 0; i < samples && live; i++) {
        mxfs_pal_sleep_ms(MXFS_DISKLOCK_HB_INTERVAL_MS);

        if (cancel && *cancel) {
            mxfs_pal_free(hb);
            return 0;
        }

        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
            uint64_t off;
            const char *why = NULL;
            int rc;

            if (!(live & (1ULL << slot)))
                continue;

            off = ctx->base_offset +
                  (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
            mxfs_pal_mutex_lock(ctx->lock);
            rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
            mxfs_pal_mutex_unlock(ctx->lock);

            if (rc < 0)
                why = "read failed (cannot prove continuity)";
            else if (hb->magic != MXFS_DISKLOCK_MAGIC ||
                     hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE)
                why = "record no longer ACTIVE";
            else if (hb_gen_foreign(ctx, hb))
                why = "fs_gen went foreign";
            else if (hb->node_id != base_node[slot])
                why = "node id changed";
            else if (hb->epoch != base_epoch[slot])
                why = "epoch changed (rejoined)";
            else if (hb->timestamp_ms != base_ts[slot])
                why = "heartbeat advanced";

            if (why) {
                mxfs_pal_log(MXFS_LOG_INFO,
                    "disklock: confirm slot %u node=%u dropped at sample "
                    "%u/%u — %s", slot, base_node[slot], i + 1, samples,
                    why);
                live &= ~(1ULL << slot);
            }
        }
    }

    mxfs_pal_free(hb);

    /*
     * sess86: export the BASELINE incarnation of each confirmed slot.  This
     * is the incarnation held frozen across the whole window — every sample
     * proved hb->epoch still equalled it, and any slot whose epoch moved was
     * dropped above.  It is therefore the only incarnation the caller may
     * name as the victim; re-reading the sector later would race a rejoin.
     */
    if (out_epoch) {
        for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
            if (live & (1ULL << slot))
                out_epoch[slot] = base_epoch[slot];
        }
    }

    *out_confirmed = live;
    return 0;
}
