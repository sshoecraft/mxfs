/*
 * MXFS — Multinode XFS
 * Recovery obligation record + list: the RECOVER extents of a dead node's
 * journal slice, made durable so the recovery owner (or a takeover
 * successor) can complete them without ever re-reading the slice.
 *
 * sess462 — D-FOREIGN-SLICE-INTENTS-ABANDONED item 5, increment 2.
 * Design-consult rulings: ccmemory ccloop-c7ee71c6-sess461-GPT-ruling-intents-item5-
 * efi-completion-design (the design) and ccloop-c7ee71c6-sess462-GPT-ruling-
 * item5-inc2-obligation-record-plumbing-only (this increment's shape).
 *
 * Two on-disk pieces, both bound to the victim identity {fs_gen, node_id,
 * epoch} of the sector they describe, exactly like the descriptor, the
 * terminal outcome and the manifest pointer:
 *
 *  1. THE OBLIGATION RECORD (40 bytes) inside the victim's heartbeat sector
 *     at mxfs_recov_body byte 280 — after the manifest pointer, exactly the
 *     bytes the pad owned.  A sector written by a build that never wrote one
 *     presents zeroes there, which fail the magic test and read as "no
 *     record", never as garbage.  It is written ONLY inside the same
 *     compare-and-write as the milestone it belongs to: IMAGES_REPLAYED
 *     (increments 3-4), or — in this increment — the TERMINAL outcome, with
 *     MXFS_RECOV_OBL_F_TERMINAL set (evidence only, gates nothing).
 *
 *  2. THE OBLIGATION LIST in the victim's recovery-manifest slot, zone
 *     [MXFS_RMAN_OBL_OFF, MXFS_RMAN_ENTRIES_OFF) = [4 KiB, 64 KiB): a 4 KiB
 *     header block at 4 KiB and up to MXFS_RECOV_OBL_MAX_EXTENTS 16-byte
 *     entries from 8 KiB (3072 x 16 = 48 KiB, ending at 56 KiB).  The fence
 *     prover's manifest owns [0, 4 KiB) and [64 KiB, ...): its header crc
 *     and entries crc never cover this zone, its invalidate step zeroes only
 *     its own header block, and manifest revalidation never reads here —
 *     the slot is formally partitioned (ruling Q1).  Nothing may grow the
 *     manifest header into this zone without an on-disk format change.
 *
 * Write protocol (recovery owner, execution lease held, stage >= FENCED,
 * ruling Q4): entries -> flush -> header (crc'd, LAST) -> flush -> then the
 * descriptor CAS that carries the record.  A list whose header does not
 * match a record in the sector is UNPUBLISHED GARBAGE: a successor ignores
 * it, replays as usual and rewrites it.  Once a record references it the
 * list is IMMUTABLE — a takeover successor validates and consumes it and
 * never rewrites it.  A torn header or payload fails its crc and reads as
 * unpublished.
 *
 * Identity (ruling Q1/Q4): the STABLE recovery-case identity is
 * {victim_node, victim_epoch, victim_fs_gen, victim_slot, recovery_gen,
 * seq}; it survives an ownership takeover.  The publisher's own identity is
 * carried for diagnostics ONLY and is never a validation key (a successor
 * must be able to consume a list its dead predecessor published).
 *
 * Canonical form (ruling Q5.8): entries sorted by (agno, agbno); every entry
 * has len > 0, lies inside its AG (agbno + len <= agblocks), agno < agcount,
 * agno == fsbno >> agblklog; no duplicates, no overlaps.  ag_mask is
 * recomputed from the list and must equal the record's; an AG >= 64 cannot
 * be represented and forces MXFS_RECOV_OBL_F_FSWIDE on BOTH the record and
 * the header (never truncated, never dropped).  Anything else is a
 * validation failure the consumer treats as QUARANTINE — never as "no
 * obligations", never best-effort (ruling STOP-SHIP 4, 8, 10).
 *
 * Everything in this header is PAL-only and builds user-mode: chk_mxfs
 * mirrors the same validation.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_RECOV_OBL_H
#define MXFS_LIBMXFS_RECOV_OBL_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"

/* ── the record in the heartbeat sector (mxfs_recov_body.obl) ─────────── */
#define MXFS_RECOV_OBL_MAGIC        0x424F5652u  /* "RVOB" LE */
#define MXFS_RECOV_OBL_VERSION      1

/* flags — shared by the record and the list header */
/* Evidence only: published next to a TERMINAL outcome (increment 2).  A
 * consumer must never read it as an open obligation: the descriptor is
 * QUARANTINED and stays terminal; the record exists so the rig exercises
 * the list path and chk_mxfs can show what a completion WOULD have owed. */
#define MXFS_RECOV_OBL_F_TERMINAL   (1u << 0)
/* An obligation names an AG >= 64: obl_ag_mask cannot represent the
 * domain; the freeze is filesystem-wide (ruling Q5.3). */
#define MXFS_RECOV_OBL_F_FSWIDE     (1u << 1)
/* The rman obligation list for this record is published (count > 0).  A
 * record with count == 0 carries no list. */
#define MXFS_RECOV_OBL_F_LIST       (1u << 2)
/* The completion proof (recov_obl_done.h) for this record is COMMITTED and
 * the descriptor reached OBLIGATIONS_DONE in the same compare-and-write:
 * every RECOVER extent was freed by the custodian or found already free,
 * the allocation metadata is home and flushed.  A consumer treats a DONE
 * record as NO open obligation; the flag is set only by
 * mxfs_disklock_recovery_advance_obl_done, never by the list writer. */
#define MXFS_RECOV_OBL_F_DONE       (1u << 3)
#define MXFS_RECOV_OBL_F_ALL        (MXFS_RECOV_OBL_F_TERMINAL | \
                                     MXFS_RECOV_OBL_F_FSWIDE | \
                                     MXFS_RECOV_OBL_F_LIST | \
                                     MXFS_RECOV_OBL_F_DONE)

struct mxfs_recov_obl {
    uint32_t    magic;          /*  0: MXFS_RECOV_OBL_MAGIC */
    uint16_t    version;        /*  4: MXFS_RECOV_OBL_VERSION */
    uint16_t    flags;          /*  6: MXFS_RECOV_OBL_F_* */
    uint64_t    obl_ag_mask;    /*  8: bit n = AG n carries an obligation
                                 *     (0 iff count == 0 or FSWIDE) */
    uint32_t    count;          /* 16: RECOVER extents in the list */
    uint32_t    list_crc32c;    /* 20: crc32c over the canonical entry bytes
                                 *     (count * 16), ~0 seed; 0 when count==0 */
    uint64_t    census_digest;  /* 24: crc32c of the slice image at census
                                 *     time (the replay's forensic digest) */
    uint32_t    pub_seq;        /* 32: the list header's seq this record
                                 *     publishes (0 when count == 0) */
    uint32_t    crc32c;         /* 36: over bytes 0..35 + victim identity */
};                              /* 40 */

/* An OPEN case: a record naming obligations that are neither terminal
 * evidence nor completed.  The freeze and the completion engine key on
 * exactly this predicate; everything else is "nothing owed here". */
static inline bool mxfs_recov_obl_is_open(const struct mxfs_recov_obl *rec)
{
    return rec && rec->count > 0 &&
           !(rec->flags & (MXFS_RECOV_OBL_F_TERMINAL | MXFS_RECOV_OBL_F_DONE));
}

/* ── the list in the recovery-manifest slot ───────────────────────────── */
#define MXFS_RMAN_OBL_OFF           4096u   /* header block, slot-relative */
#define MXFS_RMAN_OBL_HDR_BYTES     4096u
#define MXFS_RMAN_OBL_ENTRIES_OFF   8192u   /* entries, slot-relative */
#define MXFS_RECOV_OBL_MAX_EXTENTS  3072u   /* 3072 x 16 B = 48 KiB -> ends at
                                             * 56 KiB, under the 64 KiB manifest
                                             * entry area; more => QUARANTINE */
#define MXFS_RMAN_OBL_MAGIC         0x424F584Du  /* "MXOB" LE */
#define MXFS_RMAN_OBL_VERSION       1

struct mxfs_recov_obl_ext {
    uint64_t    fsbno;          /*  0: (agno << agblklog) | agbno */
    uint32_t    agno;           /*  8 */
    uint32_t    len;            /* 12: blocks, > 0 */
};                              /* 16 */

struct mxfs_rman_obl_hdr {
    uint32_t    magic;          /*  0: MXFS_RMAN_OBL_MAGIC */
    uint16_t    version;        /*  4: MXFS_RMAN_OBL_VERSION */
    uint16_t    flags;          /*  6: MXFS_RECOV_OBL_F_* */
    uint64_t    seq;            /*  8: publication sequence — strictly greater
                                 *     than any sealed header this slot/victim
                                 *     carried before; the record's pub_seq */
    uint64_t    recovery_gen;   /* 16: identity of the recovery transaction
                                 *     (constant across takeover) */
    uint64_t    victim_epoch;   /* 24 */
    uint32_t    victim_node;    /* 32 */
    uint32_t    victim_fs_gen;  /* 36 */
    uint16_t    victim_slot;    /* 40 */
    uint16_t    slice_idx;      /* 42: the victim's journal slice */
    uint16_t    slice_count;    /* 44 */
    uint16_t    entry_bytes;    /* 46: sizeof(struct mxfs_recov_obl_ext) */
    uint32_t    count;          /* 48 */
    uint32_t    byte_len;       /* 52: count * entry_bytes, exact */
    uint32_t    entries_crc32c; /* 56: crc32c over byte_len entry bytes */
    uint32_t    publisher_node; /* 60: DIAGNOSTIC ONLY */
    uint64_t    publisher_epoch;/* 64: DIAGNOSTIC ONLY */
    uint32_t    publisher_term; /* 72: DIAGNOSTIC ONLY (owner_term) */
    uint32_t    agcount;        /* 76: geometry the list was validated against */
    uint64_t    census_digest;  /* 80 */
    uint64_t    obl_ag_mask;    /* 88 */
    uint64_t    stamp_ms;       /* 96: publisher clock */
    uint32_t    agblocks;       /*104 */
    uint32_t    hdr_crc32c;     /*108: over bytes 0..107 and 112..4095 */
    uint8_t     pad[MXFS_RMAN_OBL_HDR_BYTES - 112];   /* must be zero */
};

/* The geometry a list is validated against (from the XFS superblock). */
struct mxfs_recov_obl_geom {
    uint32_t    agcount;
    uint32_t    agblocks;
    uint8_t     agblklog;
};

/*
 * Canonicalize + validate a list IN PLACE: sorts by (agno, agbno) and checks
 * every entry against the geometry and against its neighbours.  On success
 * fills *ag_mask (the union of the entries' AGs, 0 when *fswide) and *fswide
 * (an AG >= 64 is present).  Returns 0, or -EINVAL for a malformed entry
 * (zero length, outside its AG, agno/fsbno disagreement, agno >= agcount),
 * -EEXIST for a duplicate or overlapping pair, -EOVERFLOW for n above
 * MXFS_RECOV_OBL_MAX_EXTENTS.  A non-zero return means QUARANTINE.
 */
int mxfs_recov_obl_canonicalize(struct mxfs_recov_obl_ext *ext, uint32_t n,
                                const struct mxfs_recov_obl_geom *geom,
                                uint64_t *ag_mask, bool *fswide);

/* crc32c (~0 seed, no inversion) over the canonical entry bytes; 0 for n==0 */
uint32_t mxfs_recov_obl_list_crc(const struct mxfs_recov_obl_ext *ext,
                                 uint32_t n);

/*
 * The identity binding shared by every sub-record of a heartbeat sector:
 * crc32c(~0) over the record's own bytes up to its crc field, folded with
 * the sector's {fs_gen, node_id, epoch}.  Same recipe as recov_desc_crc /
 * recov_outcome_crc / recov_mptr_crc in disklock.c and chk_recov_body_crc
 * in chk_mxfs.c — reproduced exactly, never approximated.
 */
uint32_t mxfs_recov_obl_rec_crc(uint32_t fs_gen, uint32_t node_id,
                                uint64_t epoch,
                                const struct mxfs_recov_obl *rec);

/* header crc over bytes 0..107 and 112..4095 */
uint32_t mxfs_rman_obl_hdr_crc(const struct mxfs_rman_obl_hdr *h);

/*
 * Structural validation of a record image (magic/version/flags/crc against
 * the sector identity, count vs flags, mask vs FSWIDE).  Returns 0 for a
 * valid record, -ENOENT when the region is all-zero (no record), -EPROTO
 * otherwise.  Does NOT read the list.
 */
int mxfs_recov_obl_rec_check(const struct mxfs_recov_obl *rec,
                             uint32_t fs_gen, uint32_t node_id,
                             uint64_t epoch, const char **why);

/*
 * Validation of a list header against the record that publishes it and the
 * recovery-case identity (victim node/epoch/fs_gen/slot, recovery_gen).
 * Returns 0, -ENOENT when the header block is all-zero, -EPROTO otherwise;
 * *why names the failing check.  The entries' crc and canonical form are
 * checked separately by the reader once the entries are in memory
 * (mxfs_recov_obl_list_check).
 */
int mxfs_rman_obl_hdr_check(const struct mxfs_rman_obl_hdr *h,
                            const struct mxfs_recov_obl *rec,
                            uint32_t victim_node, uint64_t victim_epoch,
                            uint32_t victim_fs_gen, uint16_t victim_slot,
                            uint64_t recovery_gen, const char **why);

/*
 * Validation of the entries read back for a checked header: crc, canonical
 * form under the header's geometry, and the recomputed mask/fswide against
 * the header AND the record.  `ext` is re-canonicalized in place (a sorted
 * list sorts to itself; any reorder is itself a failure).  Returns 0 or
 * -EPROTO with *why.
 */
int mxfs_recov_obl_list_check(struct mxfs_recov_obl_ext *ext, uint32_t n,
                              const struct mxfs_rman_obl_hdr *h,
                              const struct mxfs_recov_obl *rec,
                              const char **why);

#endif /* MXFS_LIBMXFS_RECOV_OBL_H */
