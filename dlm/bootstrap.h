/*
 * MXFS — WHOLE-CLUSTER BOOTSTRAP RECORD (sess439, docs/whole-cluster-restart.md
 * §5; design-consult ruling ccmemory
 * docs/rulings/bootstrap-record-self-succession-intent.md).
 *
 * After a total outage nobody survives to fence anybody, every host's own
 * previous boot still holds a PTPL registration on its own I_T nexus, and the
 * per-slot recovery descriptors — which decide who fences and replays ONE
 * slice — cannot say which old slots and which old registrants make up the
 * recovery set for this outage, cannot lend a slotless node a durable identity
 * that may own fence intents, and cannot forbid ACTIVE publication (and
 * xfs_mountfs) before every slice of that set is durably complete.  This one
 * CAW-written sector does exactly those three things.
 *
 * States (one 512-byte record in its own envelope region,
 * MXFS_FORMAT_F_BOOTSTRAP; mkfs writes IDLE):
 *
 *   IDLE               no bootstrap in progress (mkfs, or the last one
 *                      completed and was retired by ordinary membership)
 *   CLAIMED            an owner holds term T under a PROVISIONAL identity
 *                      {host, boot, node_id, epoch, pr_key, key_gen, nonce};
 *                      it heartbeats here and may own fence intents and
 *                      recovery descriptors, but it is NOT a member: no
 *                      filesystem write, no grant, no xfs_mountfs
 *   MANIFEST_SEALED    the owner recorded the recovery set: the bitmap of dead
 *                      heartbeat slots + the registrant-ledger generation and
 *                      a hash of both.  Admission of any new ACTIVE member is
 *                      refused from here until RECOVERY_COMPLETE
 *   RECOVERING         fence certificates + per-slot recovery in progress;
 *                      complete_bitmap accumulates per-slot RECOVERY_COMPLETE
 *   RECOVERY_COMPLETE  every sealed slot and registrant is durably complete;
 *                      ACTIVE claims and xfs_mountfs may proceed
 *
 * Every state change is a COMPARE AND WRITE from the exact image last read
 * (the plain-write fallback exists only for devices without CAW, which cannot
 * run a CAW cluster anyway).  The owner heartbeat is a CAW that changes only
 * stamp_ms/seq under the SAME term and owner; a heartbeat that finds another
 * term or owner has lost the record and must stop (-ESTALE).
 *
 * A silent owner is NEVER replaced on silence alone (a paused host resumes).
 * Takeover requires the caller to present the fence kind that removed the
 * prior owner's pr_key (PREEMPT_ABORT_DONE, or a consumed SELF_SUCCESSION
 * certificate) — the API refuses anything else — and then CASes to term+1.
 * A zeroed sector (no magic) is UNFORMATTED, not IDLE: mkfs must have written
 * the record, so a torn/unformatted sector fails closed.
 */
#ifndef MXFS_BOOTSTRAP_H
#define MXFS_BOOTSTRAP_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_super.h"

#define MXFS_BOOTSTRAP_MAGIC        0x5342584Du  /* "MXBS" LE */
/* sess440: v2 = refused_slot/refused_reason fields + the manifest sectors
 * (MXFS_BOOTSTRAP_BYTES 8192, MXFS_PROTO_GEN 14).
 * sess441: v3 = the adopted-slice ESCROW (§6.5 shape B, MXFS_PROTO_GEN 15). */
/* sess442: v4 = the escrow carries the manifest POINTER (264 bytes), PROTO_GEN 16. */
/* sess443: v5 = 32 KiB region: manifest banks, completion tombstones,
 * lineage, takeover journal; record gains episode_term / lineage_count
 * (docs/whole-cluster-restart.md §6.8, PROTO_GEN 17). */
#define MXFS_BOOTSTRAP_VERSION      5

/* Sector map of the region (docs/whole-cluster-restart.md §6.8). */
#define MXFS_BOOT_SEC_RECORD        0
#define MXFS_BOOT_SEC_MF_A          1       /* 15 sectors */
#define MXFS_BOOT_SEC_MF_B          16      /* 15 sectors */
#define MXFS_BOOT_SEC_TAKEOVER      31
#define MXFS_BOOT_SEC_TOMB          32      /* 8 sectors */
#define MXFS_BOOT_SEC_LINEAGE       40      /* 8 sectors */
#define MXFS_BOOT_SECTORS           64
#define MXFS_BOOT_REGION_BYTES      (MXFS_BOOT_SECTORS * MXFS_BOOTSTRAP_REC_BYTES)
#define MXFS_BOOT_MF_BANK(term)     (((term) & 1) ? MXFS_BOOT_SEC_MF_B : \
                                                    MXFS_BOOT_SEC_MF_A)

/*
 * THE ADOPTED-SLICE ESCROW (sess441, docs/whole-cluster-restart.md §6.5,
 * Design-consult ruling ccmemory ccloop-c7ee71c6-sess441-GPT-ruling-item5d-adopt-one-
 * slice).  After phase 3 the owner needs a heartbeat slot and a journal
 * slice of its own to run xfs_log_mount — under full occupancy the only
 * slots are the victims'.  It adopts ONE certified class-2 victim slot K:
 * K's guarded sector (the recovery descriptor with its fence certificate)
 * is REPLACED by the owner's ACTIVE record, so the evidence that authorised
 * that overwrite is escrowed HERE, durably, before the CAW that destroys
 * it.  The complete descriptor is carried verbatim — a digest of evidence
 * about to be destroyed is not evidence.
 *
 *   NONE       no adoption in this term
 *   PREPARED   escrow durable; K's sector still holds the guard (a
 *              successor may redo the claim CAW or abandon the term)
 *   K_CLAIMED  K's sector is the owner's ACTIVE|BOOTSTRAP_PENDING record;
 *              xfs_log_mount on K performs FULL replay (never ADOPTED)
 *   K_REPLAY_OK
 *   K_REPLAY_REFUSED   terminal for this term (replay_rc); never a fallback
 *              to another slot in the same term
 */
#define MXFS_BOOT_ESCROW_NONE               0
#define MXFS_BOOT_ESCROW_PREPARED           1
#define MXFS_BOOT_ESCROW_K_CLAIMED          2
#define MXFS_BOOT_ESCROW_K_REPLAY_OK        3
#define MXFS_BOOT_ESCROW_K_REPLAY_REFUSED   4

#define MXFS_BOOT_ESCROW_DESC_BYTES 120     /* sizeof(struct mxfs_recov_desc) */
#define MXFS_BOOT_ESCROW_MPTR_BYTES 64      /* sizeof(struct mxfs_recov_manifest_ptr) */

struct mxfs_bootstrap_escrow {
    uint8_t     state;              /*   0: MXFS_BOOT_ESCROW_* */
    uint8_t     cls;                /*   1: the victim's manifest class */
    uint16_t    slot;               /*   2: K */
    uint32_t    victim_node;        /*   4 */
    uint64_t    victim_epoch;       /*   8 */
    uint64_t    victim_key;         /*  16 */
    uint32_t    victim_key_gen;     /*  24 */
    uint32_t    old_sector_crc;     /*  28: crc32c of the guarded sector consumed */
    uint8_t     victim_host[16];    /*  32 */
    uint8_t     victim_boot[16];    /*  48 */
    uint8_t     desc[MXFS_BOOT_ESCROW_DESC_BYTES]; /* 64: the destroyed
                                     * descriptor, byte for byte (owner kind,
                                     * node, epoch, term, stage, certificate,
                                     * crc) */
    uint64_t    claim_epoch;        /* 184: the pre-drawn epoch K is claimed under */
    uint32_t    claim_node;         /* 192 */
    int32_t     replay_rc;          /* 196: K_REPLAY_REFUSED errno */
    uint8_t     mptr[MXFS_BOOT_ESCROW_MPTR_BYTES]; /* 200: the certificate's
                                     * fence-time MANIFEST POINTER (sess442):
                                     * the sealed manifest K's own-log replay
                                     * is gated by is validated against it,
                                     * exactly as a foreign replay would read
                                     * it from the sector the claim consumed */
};                                  /* 264 */

#define MXFS_BOOTSTRAP_IDLE                 0
#define MXFS_BOOTSTRAP_CLAIMED              1
#define MXFS_BOOTSTRAP_MANIFEST_SEALED      2
#define MXFS_BOOTSTRAP_RECOVERING           3
#define MXFS_BOOTSTRAP_RECOVERY_COMPLETE    4
/*
 * sess440 (§6.6, design-consult ruling Q5): a sealed slice ended TERMINAL (quarantined
 * / intents undischarged / policy refused) or a registrant could not be
 * classified.  A quarantined slice is not a recovered slice, so the bootstrap
 * does NOT reach RECOVERY_COMPLETE: the verdict stays in the victim's sector,
 * refused_slot/refused_reason name it, ACTIVE admission stays refused, and the
 * operator repairs.  Claimable again only after `chk_mxfs --clear-bootstrap`
 * (which requires the named slot's verdict to be gone).
 */
#define MXFS_BOOTSTRAP_REFUSED              5

/* refused_reason */
#define MXFS_BOOT_REFUSE_TERMINAL_SLICE     1   /* slot's replay verdict is terminal */
#define MXFS_BOOT_REFUSE_UNCLASSIFIED_KEY   2   /* READ KEYS holds a key nobody explains */
#define MXFS_BOOT_REFUSE_FENCE_UNPROVEN     3   /* a victim key's absence has no certificate */
#define MXFS_BOOT_REFUSE_RECONCILE          4   /* final READ FULL STATUS disagreed with the manifest */
#define MXFS_BOOT_REFUSE_INHERITANCE_UNPROVEN 5 /* sess443 §6.8.4: a completion bit with
                                                 * neither a validating guard nor a
                                                 * tombstone behind it */

/*
 * THE SEALED MANIFEST (§6.3).  Sector 0 of the region is the record; sectors
 * 1..15 hold the manifest, 7 entries per sector (105 entries: 64 slots plus
 * slotless registrants).  It is the immutable list a takeover resumes from —
 * never the victims' sectors, which completion may already have erased.
 * Written with FUA under the CLAIMED term before the seal CAS; the record's
 * manifest_hash is crc32c over all entries in order, so a torn manifest can
 * never validate against a sealed record.
 */
#define MXFS_BOOT_MF_MAGIC          0x4D42584Du  /* "MXBM" LE */
#define MXFS_BOOT_MF_SECTORS        15
#define MXFS_BOOT_MF_PER_SECTOR     7
#define MXFS_BOOT_MF_MAX            (MXFS_BOOT_MF_SECTORS * MXFS_BOOT_MF_PER_SECTOR)
#define MXFS_BOOT_MF_NO_SLOT        0xFFFFu
#define MXFS_BOOT_MF_NO_INDEX       0xFFFFFFFFu

/* entry classes — the ruling's classification of every non-owner key */
#define MXFS_BOOT_MF_VICTIM_SLICE       2   /* dead record with a slice: fence + replay */
#define MXFS_BOOT_MF_VICTIM_NOSLICE     3   /* dead record beyond the slice count, or a
                                             * slotless ledger registrant: fence only */
#define MXFS_BOOT_MF_SELF_SUCCESSOR     4   /* ledger entry N succeeds a class-2/3 key:
                                             * never a P&A target; its predecessor's
                                             * absence is certified through it */

/* rec_flags bit: the victim record advertised MXFS_HB_FEAT_BOOTSTRAP_PENDING
 * (a predecessor term's adopted slice K; §6.5 successor preference). */
#define MXFS_BOOT_MF_RECF_PENDING       0x40
/* rec_flags bit (sess443 §6.8.4): this entry is the FENCED OLD OWNER of the
 * term a takeover ended — on K (class 2) or slotless (class 3). */
#define MXFS_BOOT_MF_RECF_OWNER         0x80

struct mxfs_bootstrap_mf_entry {
    uint16_t    slot;           /*  0: heartbeat slot, or MXFS_BOOT_MF_NO_SLOT */
    uint8_t     cls;            /*  2: MXFS_BOOT_MF_* */
    uint8_t     rec_flags;      /*  3: the record's flags at the seal (victims)
                                 *     | MXFS_BOOT_MF_RECF_PENDING */
    uint32_t    node_id;        /*  4 */
    uint64_t    epoch;          /*  8 */
    uint64_t    pr_key;         /* 16 */
    uint32_t    key_gen;        /* 24 */
    uint32_t    succ_of;        /* 28: class 4 — index of the entry it succeeds */
    uint8_t     host_uuid[16];  /* 32 */
    uint8_t     boot_uuid[16];  /* 48 */
};                              /* 64 */

struct mxfs_bootstrap_mf_sector {
    uint32_t    magic;          /*  0: MXFS_BOOT_MF_MAGIC */
    uint16_t    ver;            /*  4: MXFS_BOOTSTRAP_VERSION */
    uint16_t    count;          /*  6: entries used in this sector */
    uint64_t    term;           /*  8: the term that wrote it */
    uint32_t    idx;            /* 16: sector index 0..14 */
    uint32_t    crc32c;         /* 20: over the sector with crc32c = 0 */
    struct mxfs_bootstrap_mf_entry e[MXFS_BOOT_MF_PER_SECTOR];   /* 24..472 */
    uint8_t     pad[MXFS_BOOTSTRAP_REC_BYTES - 24 -
                    MXFS_BOOT_MF_PER_SECTOR * 64];
};

/* Owner heartbeat cadence and the silence after which a caller that has
 * ALREADY fenced the owner's key may take the record over.  Silence alone
 * authorises nothing (see the header comment); this only bounds how long a
 * fenced owner's stale claim delays its successor. */
#define MXFS_BOOTSTRAP_REFRESH_MS   1000
#define MXFS_BOOTSTRAP_ABANDON_MS   6000

struct mxfs_bootstrap_rec {
    uint32_t    magic;              /*   0: MXFS_BOOTSTRAP_MAGIC */
    uint16_t    ver;                /*   4: MXFS_BOOTSTRAP_VERSION */
    uint16_t    state;              /*   6: MXFS_BOOTSTRAP_* */
    uint64_t    term;               /*   8: bootstrap term; +1 per claim/takeover */
    uint64_t    seq;                /*  16: +1 on every CAS/CAW */
    uint64_t    stamp_ms;           /*  24: owner clock at last write */
    uint32_t    owner_node;         /*  32: provisional node_id (0 = none) */
    uint32_t    owner_key_gen;      /*  36 */
    uint64_t    owner_epoch;        /*  40: provisional incarnation */
    uint64_t    owner_pr_key;       /*  48: the owner's registered 64-bit key */
    uint64_t    owner_nonce;        /*  56: drawn at claim; names THIS claim */
    uint8_t     owner_host_uuid[16];/*  64 */
    uint8_t     owner_boot_uuid[16];/*  80 */
    uint8_t     fs_uuid[16];        /*  96: the volume (mkfs) */
    uint32_t    fs_gen;             /* 112: folded volume id, as HB records */
    uint32_t    host_src;           /* 116: MXFS_HOSTID_SRC_* of the owner */
    uint64_t    victim_bitmap;      /* 120: sealed dead heartbeat slots */
    uint64_t    complete_bitmap;    /* 128: per-slot RECOVERY_COMPLETE */
    uint64_t    ledger_gen;         /* 136: registrant-ledger generation at seal */
    uint64_t    manifest_hash;      /* 144: crc of {victim_bitmap, ledger_gen,
                                     *      sealed registrant keys} */
    uint32_t    registrants;        /* 152: sealed slotless registrant count */
    uint32_t    registrants_done;   /* 156: of those, certified fenced */
    uint64_t    claim_stamp_ms;     /* 160: when this term was claimed */
    uint64_t    seal_stamp_ms;      /* 168 */
    uint64_t    complete_stamp_ms;  /* 176 */
    uint32_t    prev_owner_node;    /* 184: at takeover: whom we replaced */
    uint32_t    prev_fence_kind;    /* 188: the fence kind that removed them */
    uint64_t    prev_owner_epoch;   /* 192 */
    uint64_t    prev_owner_pr_key;  /* 200 */
    uint32_t    crc32c;             /* 208: over the record with crc32c = 0 */
    uint32_t    refused_slot;       /* 212: REFUSED — the slot that ended terminal
                                     *      (MXFS_BOOT_MF_NO_SLOT for a key reason) */
    uint32_t    refused_reason;     /* 216: MXFS_BOOT_REFUSE_* */
    uint32_t    escrow_pad;         /* 220: 8-byte alignment for the escrow */
    struct mxfs_bootstrap_escrow escrow;    /* 224..488: sess441 v3, sess442 mptr */
    uint64_t    episode_term;       /* 488: sess443 v5 — the term of the CLAIM
                                     *      that opened this recovery episode;
                                     *      every takeover carries it; a
                                     *      tombstone or lineage entry proving a
                                     *      term below it belongs to an older,
                                     *      completed episode and is ignored */
    uint16_t    lineage_count;      /* 496: sess443 v5 — terms ended by a
                                     *      takeover in this episode (0..8) */
    uint16_t    takeover_gen;       /* 498: sess443 v5 — +1 per takeover CAS */
    uint8_t     reserved[12];       /* to 512 */
};

_Static_assert(sizeof(struct mxfs_bootstrap_rec) == MXFS_BOOTSTRAP_REC_BYTES,
               "bootstrap record is one sector (PAL I/O must be sector-sized)");
_Static_assert(sizeof(struct mxfs_bootstrap_escrow) == 264, "escrow layout");
_Static_assert(offsetof(struct mxfs_bootstrap_rec, escrow) == 224,
               "escrow offset");
_Static_assert(offsetof(struct mxfs_bootstrap_rec, episode_term) == 488,
               "episode_term offset");
_Static_assert(sizeof(struct mxfs_bootstrap_mf_entry) == 64, "manifest entry");
_Static_assert(sizeof(struct mxfs_bootstrap_mf_sector) == MXFS_BOOTSTRAP_REC_BYTES,
               "manifest sector is one sector");

/*
 * COMPLETION TOMBSTONES (sess443, §6.8.4; review SS-6/SS-7).  A slot's
 * complete_bitmap bit is CAS'd AFTER the ladder's GRANTS_RELEASED and BEFORE
 * the victim sector is zeroed — so a takeover of a mid-finish term finds
 * zeroed sectors behind bare bits.  The bit is trusted only with durable
 * evidence bound to the obligation: this 64-byte tombstone, written by an
 * exact-image CAW of its sector BEFORE the bit CAS.  It is term-INDEPENDENT
 * (keyed by the victim incarnation + the manifest entry it discharges) so a
 * second takeover can still prove it; kind INHERITED is written by a takeover
 * for every bit it carries forward and names the proof it validated — it
 * never claims the new term replayed anything.
 */
#define MXFS_BOOT_TOMB_MAGIC        0x4254584Du  /* "MXTB" LE */
#define MXFS_BOOT_TOMB_DIRECT       1   /* this term replayed + purged the slice */
#define MXFS_BOOT_TOMB_INHERITED    2   /* carried forward under a validated proof */
#define MXFS_BOOT_TOMB_PER_SECTOR   8
#define MXFS_BOOT_TOMB_SECTORS      8

struct mxfs_bootstrap_tomb {
    uint32_t    magic;              /*  0 */
    uint8_t     kind;               /*  4: MXFS_BOOT_TOMB_* */
    uint8_t     stage;              /*  5: descriptor stage proven (GRANTS_RELEASED) */
    uint16_t    slot;               /*  6 */
    uint32_t    victim_node;        /*  8 */
    uint32_t    victim_key_gen;     /* 12 */
    uint64_t    victim_epoch;       /* 16 */
    uint64_t    victim_key;         /* 24 */
    uint64_t    term;               /* 32: the term that wrote it */
    uint32_t    obligation;         /* 40: crc32c of the manifest entry discharged */
    uint32_t    proof_crc;          /* 44: DIRECT — crc32c of the descriptor at
                                     *     GRANTS_RELEASED; INHERITED — crc32c of
                                     *     the tombstone or descriptor validated */
    uint64_t    source_term;        /* 48: INHERITED — the term whose proof was validated */
    uint32_t    pad;                /* 56 */
    uint32_t    crc32c;             /* 60: over the tombstone with crc32c = 0 */
};                                  /* 64 */

struct mxfs_bootstrap_tomb_sector {
    struct mxfs_bootstrap_tomb t[MXFS_BOOT_TOMB_PER_SECTOR];
};

_Static_assert(sizeof(struct mxfs_bootstrap_tomb) == 64, "tombstone");
_Static_assert(sizeof(struct mxfs_bootstrap_tomb_sector) == MXFS_BOOTSTRAP_REC_BYTES,
               "tombstone sector");

/*
 * LINEAGE (sess443, §6.8.5).  One entry per term a takeover ended in this
 * episode: the old owner, the hash of its sealed manifest (still readable in
 * its bank until overwritten two terms later — the entry carries what the
 * composite K replay needs, not the manifest), its final escrow VERBATIM
 * (the original victim's certificate and manifest pointer for K's first
 * incarnation) and the fence that ended it.  FUA-written before the record
 * CAS that starts T+1; validated by term + crc.
 */
#define MXFS_BOOT_LIN_MAGIC         0x4C42584Du  /* "MXBL" LE */
#define MXFS_BOOT_LIN_MAX           8

struct mxfs_bootstrap_lineage {
    uint32_t    magic;              /*   0 */
    uint16_t    ver;                /*   4 */
    uint16_t    idx;                /*   6: 0..7 */
    uint64_t    term;               /*   8: the term this entry ends */
    uint64_t    episode_term;       /*  16 */
    uint32_t    owner_node;         /*  24 */
    uint32_t    owner_key_gen;      /*  28 */
    uint64_t    owner_epoch;        /*  32 */
    uint64_t    owner_pr_key;       /*  40 */
    uint8_t     owner_host_uuid[16];/*  48 */
    uint8_t     owner_boot_uuid[16];/*  64 */
    uint64_t    manifest_hash;      /*  80 */
    uint64_t    victim_bitmap;      /*  88 */
    uint64_t    complete_bitmap;    /*  96: as the record stood when taken over */
    uint32_t    fence_kind;         /* 104: how the owner's key was removed */
    uint32_t    fence_pr_gen;       /* 108 */
    uint16_t    state;              /* 112: the record state taken over */
    uint16_t    pad16;              /* 114 */
    uint32_t    crc32c;             /* 116: over the entry with crc32c = 0 */
    struct mxfs_bootstrap_escrow escrow;    /* 120..384: verbatim */
    uint8_t     reserved[128];      /* to 512 */
};

_Static_assert(sizeof(struct mxfs_bootstrap_lineage) == MXFS_BOOTSTRAP_REC_BYTES,
               "lineage entry is one sector");

/*
 * THE TAKEOVER JOURNAL (sess443, §6.8.2; review SS-3/SS-4).  One CAW-written
 * sector that serialises contenders (the election is the exact-image CAW
 * from EMPTY or from a STALE contender) and records every irreversible step
 * of a takeover durably BEFORE it happens, so a successor contender can tell
 * "fenced and crashed" from "the key vanished", fence the stale contender by
 * its exact key, and take over any descriptor it left.  Stages:
 *   EMPTY → CONTENDER → OLD_FENCE_INTENT → OLD_FENCE_DONE →
 *   [K_DESC_DONE] → CAPSULE_WRITTEN → RECORD_COMMITTED (→ EMPTY, cleared)
 * Every write is an exact-image CAW; the contender heartbeats seq under its
 * nonce; anything that does not name us is -ESTALE.
 */
#define MXFS_BOOT_TK_MAGIC          0x4B42584Du  /* "MXBK" LE */
#define MXFS_BOOT_TK_EMPTY              0
#define MXFS_BOOT_TK_CONTENDER          1
#define MXFS_BOOT_TK_OLD_FENCE_INTENT   2
#define MXFS_BOOT_TK_OLD_FENCE_DONE     3
#define MXFS_BOOT_TK_K_DESC_DONE        4
#define MXFS_BOOT_TK_CAPSULE_WRITTEN    5
#define MXFS_BOOT_TK_RECORD_COMMITTED   6

struct mxfs_bootstrap_takeover_id {
    uint32_t    node_id;            /*  0 */
    uint32_t    key_gen;            /*  4 */
    uint64_t    epoch;              /*  8 */
    uint64_t    pr_key;             /* 16 */
    uint8_t     host_uuid[16];      /* 24 */
    uint8_t     boot_uuid[16];      /* 40 */
};                                  /* 56 */

struct mxfs_bootstrap_takeover {
    uint32_t    magic;              /*   0 */
    uint16_t    ver;                /*   4 */
    uint16_t    stage;              /*   6: MXFS_BOOT_TK_* */
    uint64_t    seq;                /*   8: +1 per CAW (the contender's heartbeat) */
    uint64_t    stamp_ms;           /*  16: contender clock */
    uint64_t    nonce;              /*  24: names THIS contender's claim */
    /* the record being taken over, exactly */
    uint64_t    target_term;        /*  32 */
    uint64_t    target_nonce;       /*  40: the owner's claim nonce */
    uint64_t    target_seq;         /*  48: R0.seq at the election */
    uint16_t    target_state;       /*  56 */
    uint16_t    pad16;              /*  58 */
    uint32_t    old_fence_kind;     /*  60: how the old owner's key was removed */
    uint32_t    old_fence_pr_gen;   /*  64 */
    uint32_t    pred_fence_kind;    /*  68: how the predecessor contender's key was removed */
    uint32_t    pred_fence_pr_gen;  /*  72 */
    uint32_t    k_desc_crc;         /*  76: K's takeover descriptor, when written */
    uint16_t    k_slot;             /*  80: MXFS_BOOT_MF_NO_SLOT when the owner was slotless */
    uint16_t    pad16b;             /*  82 */
    uint32_t    crc32c;             /*  84: over the sector with crc32c = 0 */
    struct mxfs_bootstrap_takeover_id owner;    /*  88: the old owner */
    struct mxfs_bootstrap_takeover_id us;       /* 144: the contender */
    struct mxfs_bootstrap_takeover_id pred;     /* 200: a STALE contender we replaced (zero = none) */
    uint8_t     reserved[256];      /* to 512 */
};

_Static_assert(sizeof(struct mxfs_bootstrap_takeover_id) == 56, "takeover id");
_Static_assert(sizeof(struct mxfs_bootstrap_takeover) == MXFS_BOOTSTRAP_REC_BYTES,
               "takeover journal is one sector");

/* The provisional identity a claimant presents. */
struct mxfs_bootstrap_identity {
    uint8_t     host_uuid[16];
    uint8_t     boot_uuid[16];
    uint32_t    node_id;
    uint32_t    key_gen;
    uint64_t    epoch;
    uint64_t    pr_key;
    uint32_t    host_src;
};

struct mxfs_bootstrap {
    mxfs_bdev_t                 *dev;
    uint64_t                    offset;
    mxfs_mutex_t                *lock;
    uint8_t                     fs_uuid[16];
    uint32_t                    fs_gen;
    /* our claim, once made: the exact on-disk image is the CAW source */
    bool                        owned;
    struct mxfs_bootstrap_rec   img;
    uint64_t                    nonce;
    /*
     * 0.89.41: WHEN A RECORD WRITE OF OURS LAST LANDED, stamped with the
     * instant that went into that write's stamp_ms — the ISSUE time, not the
     * completion time.  That choice is what lets a reader ask "was a write
     * ISSUED after instant X, and did it land?" with one comparison and no
     * ambiguity about a write that was already in flight when X happened.
     *
     * It is the bootstrap term's answer to the disklock heartbeat's
     * last_ok_ms.  A slotless bootstrap owner claims no heartbeat slot and so
     * has no disklock beat and no authority lease; this record write is the
     * only liveness its term has, and MXFS_BOOTSTRAP_ABANDON_MS since this
     * instant is the window after which a peer may take the term away.
     */
    volatile uint64_t           last_ok_ms;
};

struct mxfs_bootstrap *mxfs_bootstrap_open(mxfs_bdev_t *dev, uint64_t offset,
                                           uint64_t size,
                                           const uint8_t fs_uuid[16],
                                           uint32_t fs_gen);
void mxfs_bootstrap_close(struct mxfs_bootstrap *b);

/* Read + validate the record.  -ENODATA: unformatted (no magic) — fail
 * closed; -EUCLEAN: bad crc/version; -EXDEV: names another volume. */
int mxfs_bootstrap_read(struct mxfs_bootstrap *b,
                        struct mxfs_bootstrap_rec *out);

/*
 * CLAIM term+1 from IDLE or RECOVERY_COMPLETE (an ordinary bootstrap start),
 * recording `id` as the provisional owner.  -EBUSY if a term is CLAIMED /
 * SEALED / RECOVERING by someone else (the caller must decide liveness and,
 * if the owner is fenced, use mxfs_bootstrap_takeover); -EAGAIN on a lost
 * CAS (re-read and retry); -ENODATA/-EUCLEAN/-EXDEV as read.
 */
int mxfs_bootstrap_claim(struct mxfs_bootstrap *b,
                         const struct mxfs_bootstrap_identity *id);

/*
 * sess443 (§6.8.3 step 14): RESEAL an abandoned term as T+1 under a NEW
 * owner, from VALIDATED inheritance (docs/whole-cluster-restart.md §6.8).
 * The caller has already: fenced the old owner's key with a certificate,
 * imported / built T+1's manifest into bank (T+1), written every inherited
 * tombstone and the lineage entry for T.  `prev` is the caller's post-fence
 * exact image (the fenced owner cannot write any more, so it is final); the
 * CAS is from it — any change loses (-EAGAIN: re-read, re-validate).
 * Everything the new term asserts is passed explicitly; nothing is carried
 * forward blind.  episode_term is carried; lineage_count/takeover_gen +1;
 * the escrow is reset (K's adoption under T+1 is a fresh escrow; T's is in
 * the lineage).  State REFUSED with refused_* lets a takeover that proved
 * the fence but not the inheritance end the term for the operator.
 */
struct mxfs_bootstrap_reseal_args {
    uint16_t    state;              /* CLAIMED (T was CLAIMED: fresh scan follows),
                                     * RECOVERING, or REFUSED */
    uint32_t    prev_fence_kind;
    uint64_t    victim_bitmap;
    uint64_t    complete_bitmap;    /* PROVEN bits only */
    uint64_t    ledger_gen;
    uint64_t    manifest_hash;
    uint32_t    registrants;
    uint32_t    registrants_done;
    uint32_t    refused_slot;
    uint32_t    refused_reason;
};
int mxfs_bootstrap_reseal(struct mxfs_bootstrap *b,
                          const struct mxfs_bootstrap_rec *prev,
                          const struct mxfs_bootstrap_identity *id,
                          const struct mxfs_bootstrap_reseal_args *a);

/* Owner heartbeat: CAW stamp/seq under our term+owner.  -ESTALE when the
 * record no longer names us (we lost it; stop acting as owner). */
int mxfs_bootstrap_heartbeat(struct mxfs_bootstrap *b);

/* Owner transitions (all CAS from our image; -ESTALE when not ours). */
int mxfs_bootstrap_seal(struct mxfs_bootstrap *b, uint64_t victim_bitmap,
                        uint64_t ledger_gen, uint32_t registrants,
                        uint64_t manifest_hash);
/*
 * sess441: CLAIMED -> IDLE under our exact image.  Legal ONLY before the
 * seal: up to then nothing durable or destructive has happened (no manifest,
 * no intent, no P&A), so a claimant that finds a survivor in its fresh
 * post-claim scan, or cannot classify a key, hands the record back instead of
 * leaving a CLAIMED term that refuses every ACTIVE admission until a fence.
 * Never called after MANIFEST_SEALED (bs_own_transition refuses it).
 */
int mxfs_bootstrap_release_claim(struct mxfs_bootstrap *b);
int mxfs_bootstrap_set_recovering(struct mxfs_bootstrap *b);
int mxfs_bootstrap_slot_complete(struct mxfs_bootstrap *b, int slot);
int mxfs_bootstrap_registrant_done(struct mxfs_bootstrap *b);
int mxfs_bootstrap_complete(struct mxfs_bootstrap *b);

/*
 * Liveness view for descriptor-owner checks (v5_incarnation_state): does the
 * record name (node, epoch) as the CURRENT owner?  Returns 1 and sets *seq
 * (the record's write counter, bumped by every heartbeat and transition)
 * when it does; 0 when it does not; <0 on I/O or validation failure (which
 * callers must treat as UNKNOWN, never as live).
 *
 * sess440 (D-BOOTSTRAP-OWNER-LIVENESS-CROSS-NODE-CLOCK-0450): the owner's
 * stamp_ms is the OWNER's boot-relative clock and is never subtracted from
 * the reader's.  Liveness is CHANGE: the caller remembers {seq, its own
 * clock} and calls the owner LIVE only when seq advanced within
 * MXFS_BOOTSTRAP_ABANDON_MS of its own clock — the disklock.h rule.
 */
int mxfs_bootstrap_owner_is(struct mxfs_bootstrap *b, uint32_t node,
                            uint64_t epoch, uint64_t *seq);

/*
 * sess440 (§6.7): exact-owner SAME-BOOT RESUME.  A mount that claimed the
 * record and then unwound (the recovery hook failed) retries in the same
 * kernel boot: its key cannot be preempted by itself and self-succession
 * proves nothing, so the record is neither taken over nor re-claimed — it is
 * RESUMED under the same term.  The record must be CLAIMED/SEALED/RECOVERING
 * and name OUR host_uuid, boot_uuid, pr_key and key_gen; the recorded
 * provisional node_id/epoch are returned so the caller ADOPTS them (they are
 * the identity the descriptors name).  The caller holds the module-wide
 * bootstrap exclusion so no second process on this host can also resume.
 * 0 = resumed (b is owner); -ENOENT = no such claim; -EBUSY = claimed by a
 * different boot/host (fence/takeover rules apply instead).
 */
int mxfs_bootstrap_resume(struct mxfs_bootstrap *b,
                          const uint8_t host_uuid[16],
                          const uint8_t boot_uuid[16], uint64_t pr_key,
                          uint32_t key_gen, uint32_t *node_out,
                          uint64_t *epoch_out);

/* Owner: RECOVERING -> REFUSED (terminal, operator).  reason = MXFS_BOOT_REFUSE_*. */
int mxfs_bootstrap_refuse(struct mxfs_bootstrap *b, uint32_t slot,
                          uint32_t reason);

/*
 * sess441 (§6.5 shape B): the adopted-slice escrow.  prepare: RECOVERING,
 * escrow NONE -> PREPARED with `e` (state forced to PREPARED), CAS'd then
 * READ BACK so the caller's claim CAW never runs ahead of the evidence.
 * advance: PREPARED -> K_CLAIMED -> K_REPLAY_OK | K_REPLAY_REFUSED (the
 * latter records replay_rc).  Both -ESTALE when the record is not ours.
 */
int mxfs_bootstrap_escrow_prepare(struct mxfs_bootstrap *b,
                                  const struct mxfs_bootstrap_escrow *e);
int mxfs_bootstrap_escrow_advance(struct mxfs_bootstrap *b, uint8_t state,
                                  int32_t replay_rc);
const char *mxfs_bootstrap_escrow_name(uint8_t state);

/*
 * The sealed manifest (§6.3).  write: FUA the entries into sectors 1..15
 * under our CLAIMED term and return the hash the seal must carry (the
 * caller then calls mxfs_bootstrap_seal with it).  read: load the manifest
 * sealed under `term` — every sector's term/crc must match and the whole
 * must hash to `hash`; -EUCLEAN otherwise.  n <= MXFS_BOOT_MF_MAX.
 */
int mxfs_bootstrap_manifest_write(struct mxfs_bootstrap *b,
                                  const struct mxfs_bootstrap_mf_entry *e,
                                  unsigned int n, uint64_t *hash_out);
/* sess443: the same, into bank(term) before the record names us (a takeover
 * writes T+1's manifest BEFORE the reseal CAS). */
int mxfs_bootstrap_manifest_write_term(struct mxfs_bootstrap *b, uint64_t term,
                                       const struct mxfs_bootstrap_mf_entry *e,
                                       unsigned int n, uint64_t *hash_out);
int mxfs_bootstrap_manifest_read(struct mxfs_bootstrap *b, uint64_t term,
                                 uint64_t hash,
                                 struct mxfs_bootstrap_mf_entry *e,
                                 unsigned int max, unsigned int *n_out);
uint64_t mxfs_bootstrap_manifest_hash(const struct mxfs_bootstrap_mf_entry *e,
                                      unsigned int n);
const char *mxfs_bootstrap_refuse_name(uint32_t reason);

/*
 * The survivor scan (§6.1): two reads of the heartbeat table on the reader's
 * clock; any record that changes is a survivor (returns with *moved > 0 and
 * no entries); a table frozen for `window_ms` is a total outage and every
 * member-shaped record becomes a class-2/3 entry (slot < slice_count ⇒
 * class 2).  Polls every `early_ms` so a live cluster is recognised within
 * two heartbeat intervals.  *unread counts sectors that could not be read
 * (the caller fails closed); *noident counts victims whose record carries no
 * identity block (unclassifiable: the caller refuses).
 */
#define MXFS_BOOTSTRAP_SCAN_EARLY_MS    2500
int mxfs_bootstrap_survivor_scan(mxfs_bdev_t *dev, uint64_t disklock_offset,
                                 uint32_t fs_gen, uint32_t slice_count,
                                 uint32_t window_ms, uint32_t early_ms,
                                 struct mxfs_bootstrap_mf_entry *e,
                                 unsigned int max, unsigned int *n_out,
                                 uint64_t *victims_out, unsigned int *moved_out,
                                 unsigned int *unread_out,
                                 unsigned int *noident_out);

/*
 * sess443 (§6.8.4): completion tombstones.  write: exact-image CAW of the
 * tombstone's sector (8 per sector; a lost CAS re-reads and retries so a
 * concurrent completion worker's neighbour is never clobbered); the crc is
 * sealed here.  read: 0 and *out filled when slot's tombstone validates
 * (magic, crc, slot) and its term is within this episode (>= episode_term
 * of the caller's record image); -ENOENT otherwise.  entry_crc: the
 * obligation key — crc32c of the manifest entry a tombstone discharges.
 */
int mxfs_bootstrap_tomb_write(struct mxfs_bootstrap *b,
                              struct mxfs_bootstrap_tomb *t);
/* sess443: the same under an explicit term, before the record names us (a
 * takeover writes INHERITED tombstones for T+1 before its reseal CAS). */
int mxfs_bootstrap_tomb_write_term(struct mxfs_bootstrap *b, uint64_t term,
                                   struct mxfs_bootstrap_tomb *t);
int mxfs_bootstrap_tomb_read(struct mxfs_bootstrap *b, unsigned int slot,
                             uint64_t episode_term,
                             struct mxfs_bootstrap_tomb *out);
uint32_t mxfs_bootstrap_tomb_crc(const struct mxfs_bootstrap_tomb *t);
uint32_t mxfs_bootstrap_mf_entry_crc(const struct mxfs_bootstrap_mf_entry *e);
const char *mxfs_bootstrap_tomb_kind_name(uint8_t kind);

/*
 * sess443 (§6.8.5): lineage.  write: FUA entry `idx` (crc sealed; magic,
 * ver, idx forced).  read: 0 when entry `idx` validates and names `term`
 * (0 = any) within `episode_term`; -ENOENT otherwise.
 */
int mxfs_bootstrap_lineage_write(struct mxfs_bootstrap *b, unsigned int idx,
                                 struct mxfs_bootstrap_lineage *l);
int mxfs_bootstrap_lineage_read(struct mxfs_bootstrap *b, unsigned int idx,
                                uint64_t term, uint64_t episode_term,
                                struct mxfs_bootstrap_lineage *out);
uint32_t mxfs_bootstrap_lineage_crc(const struct mxfs_bootstrap_lineage *l);

/*
 * sess443 (§6.8.2): the takeover journal.  read: the raw sector (0; an
 * all-zero or invalid sector reads back as stage EMPTY with *valid = false).
 * cas: exact-image CAW cur -> want, sealing seq/stamp/crc (magic/ver
 * forced); -EAGAIN when the platter moved.  clear: CAS to all-zero from the
 * exact image.  Used by the takeover arm (§6.8.3) and by chk_mxfs.
 */
int mxfs_bootstrap_takeover_read(struct mxfs_bootstrap *b,
                                 struct mxfs_bootstrap_takeover *out,
                                 bool *valid);
int mxfs_bootstrap_takeover_cas(struct mxfs_bootstrap *b,
                                const struct mxfs_bootstrap_takeover *cur,
                                struct mxfs_bootstrap_takeover *want);
int mxfs_bootstrap_takeover_clear(struct mxfs_bootstrap *b,
                                  const struct mxfs_bootstrap_takeover *cur);
uint32_t mxfs_bootstrap_takeover_crc(const struct mxfs_bootstrap_takeover *t);
const char *mxfs_bootstrap_takeover_stage_name(uint16_t stage);

/* Shared with chk_mxfs. */
uint32_t mxfs_bootstrap_rec_crc(const struct mxfs_bootstrap_rec *r);
bool mxfs_bootstrap_rec_valid(const struct mxfs_bootstrap_rec *r);
const char *mxfs_bootstrap_state_name(uint16_t state);
/* mkfs: fill an IDLE record for a fresh volume (crc sealed). */
void mxfs_bootstrap_rec_init_idle(struct mxfs_bootstrap_rec *r,
                                  const uint8_t fs_uuid[16], uint32_t fs_gen);

/*
 * 0.88.0 — SLICE LIFECYCLE (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531,
 * docs/rulings/twin-hole-fix-zeroing-strictness.md item (a)).  One record per
 * XFS log slice in the MXFS_FORMAT_F_SLIFE region (struct mxfs_slife_record,
 * include/mxfs/mxfs_super.h).  Lives here because it is the same kind of
 * thing as the bootstrap record: a 512-byte envelope sector written FUA by the
 * one node the protocol makes its exclusive owner — for a slice, the node
 * holding the identically numbered heartbeat slot.
 *
 * mxfs_slife_read: the record for `slice`, validated (magic, version, crc,
 *   fs_uuid == this volume's).  -ENODATA: no magic (mkfs never wrote it);
 *   -EUCLEAN: invalid; -EXDEV: another volume's; -ERANGE: no such slice.
 * mxfs_slife_claim_init: the claimant's state machine.  READY -> nothing;
 *   INIT_REQUIRED or ZEROING -> persist ZEROING (FUA), zero the payload
 *   [payload_off, +payload_len) with FUA writes, flush, read the whole
 *   payload back and require zeros, persist READY (FUA) and read it back.
 *   Any failure leaves the record ZEROING (the next claimant restarts the
 *   full zero) and returns the error; the caller must not mount the log.
 *   Returns 0 with *before/*after the states seen/left and *zero_ms the
 *   wall of the zero+verify (0 when nothing was zeroed).
 */
int mxfs_slife_read(mxfs_bdev_t *dev, uint64_t region_off,
                    uint64_t region_size, uint32_t slice,
                    const uint8_t fs_uuid[16], struct mxfs_slife_record *out);
int mxfs_slife_claim_init(mxfs_bdev_t *dev, uint64_t region_off,
                          uint64_t region_size, uint32_t slice,
                          const uint8_t fs_uuid[16], uint64_t node,
                          uint64_t epoch, uint64_t payload_off,
                          uint64_t payload_len, uint32_t *before,
                          uint32_t *after, uint32_t *zero_ms);
const char *mxfs_slife_state_name(uint32_t state);

#endif /* MXFS_BOOTSTRAP_H */
