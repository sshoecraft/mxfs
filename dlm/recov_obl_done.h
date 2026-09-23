/*
 * MXFS — Multinode XFS
 * Recovery obligation COMPLETION evidence: the completion proof block that
 * authorizes OBLIGATIONS_DONE (docs/dlm-protocol.md, "Item 5").
 *
 * The proof lives in the victim's recovery-manifest slot, inside the
 * obligation zone the fence prover never touches ([4 KiB, 64 KiB), see
 * recov_obl.h), and is bound to the victim identity {fs_gen, node_id,
 * epoch} of the sector it describes exactly like the record and the list.
 *
 * THE COMPLETION PROOF at [MXFS_RMAN_OBL_DONE_OFF, +4 KiB) = [56 KiB,
 * 60 KiB): one 4 KiB block naming the case (victim identity, recovery_gen,
 * pub_seq), the list it completed (count, entries crc, header crc, AG
 * mask), the lease term and stage_seq at which the completer was
 * authorized, the per-extent outcome bitmap (bit set = EMPTY -> freed by
 * the completer; clear = FULL -> already free) and the counters
 * n_empty/n_full/n_sparse (n_sparse MUST be 0 — a SPARSE extent terminates
 * the case).  Two-phase durability: the block is written with F_COMMITTED
 * clear and flushed, then rewritten with F_COMMITTED set + crc and flushed,
 * then read back.  Only a COMMITTED, crc-valid block whose identity matches
 * the record and the list is evidence; anything else is "no proof" and
 * OBLIGATIONS_DONE stays unreachable.  The crc covers the whole block
 * including the bitmap.
 *
 * Custody is RETAINED on the TCP transport: the custodian is the recovery
 * owner, the dead node's grants are retired by the ladder before the
 * engine runs, and the freeze at the AG-grant choke point keeps every
 * other acquirer out — no AG holder bit is ever transferred, so there are
 * no per-AG transfer receipts and rcpt_digest is always 0.
 *
 * Zone budget: the list entry area is capped at MXFS_RECOV_OBL_MAX_EXTENTS
 * (3072 x 16 B = 48 KiB, [8 KiB, 56 KiB)); the proof follows at 56 KiB;
 * [60 KiB, 64 KiB) stays reserved and zero.  recov_obl_done.c
 * static-asserts the geometry.
 *
 * Everything here is PAL-only and builds user-mode: chk_mxfs mirrors it.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_RECOV_OBL_DONE_H
#define MXFS_LIBMXFS_RECOV_OBL_DONE_H

#include "recov_obl.h"

/* ── zone layout, slot-relative ─────────────────────────────────────────── */
#define MXFS_RMAN_OBL_DONE_OFF      57344u  /* 56 KiB */
#define MXFS_RMAN_OBL_DONE_BYTES    4096u
#define MXFS_RMAN_OBL_ZONE_END      65536u  /* the manifest entries begin */

/* ── completion proof block ─────────────────────────────────────────────── */
#define MXFS_RMAN_OBL_DONE_MAGIC    0x444F584Du  /* "MXOD" LE */
#define MXFS_RMAN_OBL_DONE_VERSION  1
#define MXFS_RMAN_OBL_DONE_F_COMMITTED  (1u << 0)
#define MXFS_RMAN_OBL_DONE_F_ALL        (MXFS_RMAN_OBL_DONE_F_COMMITTED)
#define MXFS_RMAN_OBL_DONE_BITMAP_BYTES 384u    /* 3072 bits, one per list entry */

struct mxfs_rman_obl_done {
    uint32_t    magic;              /*  0: MXFS_RMAN_OBL_DONE_MAGIC */
    uint16_t    version;            /*  4 */
    uint16_t    flags;              /*  6: MXFS_RMAN_OBL_DONE_F_* */
    uint32_t    length;             /*  8: MXFS_RMAN_OBL_DONE_BYTES */
    uint32_t    rman_slot;          /* 12: the heartbeat slot this zone belongs to */
    uint64_t    recovery_gen;       /* 16 */
    uint64_t    victim_epoch;       /* 24 */
    uint32_t    victim_node;        /* 32 */
    uint32_t    victim_fs_gen;      /* 36 */
    uint8_t     fs_uuid[16];        /* 40: sb_uuid of the filesystem */
    uint32_t    pub_seq;            /* 56: the record/list publication seq */
    uint32_t    count;              /* 60: list entries (== record count) */
    uint32_t    list_crc32c;        /* 64: entries crc (== record/header) */
    uint32_t    hdr_crc32c;         /* 68: the list header's hdr_crc32c */
    uint64_t    obl_ag_mask;        /* 72 */
    uint32_t    n_empty;            /* 80: extents freed by the completer */
    uint32_t    n_full;             /* 84: extents found already free */
    uint32_t    n_sparse;           /* 88: MUST be 0 */
    uint32_t    owner_term;         /* 92: lease term at authorization */
    uint64_t    stage_seq;          /* 96: descriptor stage_seq at authorization */
    uint64_t    rcpt_digest;        /*104: always 0 — custody is retained,
                                     *     no holder transfer, no receipts */
    uint32_t    completer_node;     /*112: DIAGNOSTIC */
    uint32_t    completer_slot;     /*116: DIAGNOSTIC */
    uint64_t    completer_epoch;    /*120: DIAGNOSTIC */
    uint64_t    stamp_ms;           /*128 */
    uint64_t    seq;                /*136: proof sequence, > any earlier proof
                                     *     of this slot (a reused slot's old
                                     *     proof never matches a new case) */
    uint8_t     outcome[MXFS_RMAN_OBL_DONE_BITMAP_BYTES]; /*144: bit i = entry i EMPTY->freed */
    uint8_t     pad[MXFS_RMAN_OBL_DONE_BYTES - 144 - MXFS_RMAN_OBL_DONE_BITMAP_BYTES - 4];
    uint32_t    crc32c;             /*4092: over bytes 0..4091 + victim identity */
};

/* ── the proof ──────────────────────────────────────────────────────────── */

/* crc32c(~0) over bytes 0..4091 folded with the sector identity */
uint32_t mxfs_rman_obl_done_crc(uint32_t fs_gen, uint32_t node_id,
                                uint64_t epoch,
                                const struct mxfs_rman_obl_done *p);

/*
 * Validation of a proof block against the sector identity, the record and
 * the list header it claims to complete.  Returns 0 for a COMMITTED, valid
 * proof; -ENOENT when the block is all zero; -EINPROGRESS for a structurally
 * valid block that is not COMMITTED (phase 1 landed, phase 2 did not — no
 * proof); -EPROTO otherwise.  Checks: magic/version/length/flags, crc,
 * reserved bytes zero, identity {victim node/epoch/fs_gen, slot,
 * recovery_gen, pub_seq}, count/list crc/header crc/mask against the record
 * and header, n_sparse == 0, n_empty + n_full == count, popcount(outcome)
 * == n_empty, no outcome bit at or beyond count, rcpt_digest == 0.  Does
 * NOT check the lease/stage (the caller's authorization context).
 */
int mxfs_rman_obl_done_check(const struct mxfs_rman_obl_done *p,
                             const struct mxfs_recov_obl *rec,
                             const struct mxfs_rman_obl_hdr *hdr,
                             uint32_t fs_gen, uint32_t node_id,
                             uint64_t epoch, uint32_t rman_slot,
                             uint64_t recovery_gen, const char **why);

static inline bool mxfs_rman_obl_done_bit(const struct mxfs_rman_obl_done *p,
                                          uint32_t idx)
{
    if (idx >= MXFS_RMAN_OBL_DONE_BITMAP_BYTES * 8u)
        return false;
    return (p->outcome[idx >> 3] >> (idx & 7)) & 1u;
}

static inline void mxfs_rman_obl_done_set(struct mxfs_rman_obl_done *p,
                                          uint32_t idx)
{
    if (idx < MXFS_RMAN_OBL_DONE_BITMAP_BYTES * 8u)
        p->outcome[idx >> 3] |= (uint8_t)(1u << (idx & 7));
}

#endif /* MXFS_LIBMXFS_RECOV_OBL_DONE_H */
