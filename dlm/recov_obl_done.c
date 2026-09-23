/*
 * MXFS — Multinode XFS
 * Recovery obligation completion evidence (the completion proof): pure
 * validation helpers.  No I/O, no kernel API (dlm/ builds user-mode;
 * chk_mxfs mirrors these).  Contract and layout: recov_obl_done.h.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "recov_obl_done.h"

/* Layout guards.  The zone must fit between the list entries and the
 * manifest entry area, in this order: list header (4 KiB) | entries
 * (MXFS_RECOV_OBL_MAX_EXTENTS x 16) | proof (4 KiB) | reserved. */
typedef char mxfs_rman_obl_done_size_check[
    (sizeof(struct mxfs_rman_obl_done) == MXFS_RMAN_OBL_DONE_BYTES) ? 1 : -1];
typedef char mxfs_rman_obl_done_crc_last_check[
    (offsetof(struct mxfs_rman_obl_done, crc32c) ==
     MXFS_RMAN_OBL_DONE_BYTES - 4) ? 1 : -1];
typedef char mxfs_rman_obl_entries_fit_check[
    (MXFS_RMAN_OBL_ENTRIES_OFF +
     (uint64_t)MXFS_RECOV_OBL_MAX_EXTENTS * sizeof(struct mxfs_recov_obl_ext)
     <= MXFS_RMAN_OBL_DONE_OFF) ? 1 : -1];
typedef char mxfs_rman_obl_done_fit_check[
    (MXFS_RMAN_OBL_DONE_OFF + MXFS_RMAN_OBL_DONE_BYTES <= MXFS_RMAN_OBL_ZONE_END)
    ? 1 : -1];
typedef char mxfs_rman_obl_bitmap_check[
    (MXFS_RMAN_OBL_DONE_BITMAP_BYTES * 8u >= MXFS_RECOV_OBL_MAX_EXTENTS) ? 1 : -1];
typedef char mxfs_rman_obl_zone_align_check[
    ((MXFS_RMAN_OBL_DONE_OFF % 4096u) == 0) ? 1 : -1];

static bool done_all_zero(const void *p, size_t len)
{
    const uint8_t *b = p;
    size_t i;

    for (i = 0; i < len; i++)
        if (b[i])
            return false;
    return true;
}

struct obl_done_ident {
    uint32_t fs_gen;
    uint32_t node_id;
    uint64_t epoch;
} __attribute__((packed));

uint32_t mxfs_rman_obl_done_crc(uint32_t fs_gen, uint32_t node_id,
                                uint64_t epoch,
                                const struct mxfs_rman_obl_done *p)
{
    struct obl_done_ident id;
    uint32_t crc;

    id.fs_gen  = fs_gen;
    id.node_id = node_id;
    id.epoch   = epoch;
    crc = mxfs_pal_crc32c(~0U, p, offsetof(struct mxfs_rman_obl_done, crc32c));
    return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

static uint32_t done_popcount(const uint8_t *b, size_t len)
{
    uint32_t n = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t v = b[i];

        while (v) {
            n += v & 1u;
            v >>= 1;
        }
    }
    return n;
}

int mxfs_rman_obl_done_check(const struct mxfs_rman_obl_done *p,
                             const struct mxfs_recov_obl *rec,
                             const struct mxfs_rman_obl_hdr *hdr,
                             uint32_t fs_gen, uint32_t node_id,
                             uint64_t epoch, uint32_t rman_slot,
                             uint64_t recovery_gen, const char **why)
{
    const char *w = "ok";
    int rc = -EPROTO;
    uint32_t i;

    if (!p || !rec || !hdr) {
        w = "no proof/record/header image";
        goto out;
    }
    if (done_all_zero(p, sizeof(*p))) {
        w = "no proof (all zero)";
        rc = -ENOENT;
        goto out;
    }
    if (p->magic != MXFS_RMAN_OBL_DONE_MAGIC) {
        w = "proof magic";
        goto out;
    }
    if (p->version != MXFS_RMAN_OBL_DONE_VERSION) {
        w = "proof version";
        goto out;
    }
    if (p->length != MXFS_RMAN_OBL_DONE_BYTES) {
        w = "proof length";
        goto out;
    }
    if (p->flags & ~MXFS_RMAN_OBL_DONE_F_ALL) {
        w = "proof flags";
        goto out;
    }
    if (p->crc32c != mxfs_rman_obl_done_crc(fs_gen, node_id, epoch, p)) {
        w = "proof crc / victim identity";
        goto out;
    }
    if (!done_all_zero(p->pad, sizeof(p->pad))) {
        w = "proof reserved bytes";
        goto out;
    }
    if (p->rman_slot != rman_slot || p->victim_node != node_id ||
        p->victim_epoch != epoch || p->victim_fs_gen != fs_gen ||
        p->recovery_gen != recovery_gen) {
        w = "proof names another recovery case";
        goto out;
    }
    if (p->pub_seq == 0 || p->pub_seq != rec->pub_seq ||
        p->pub_seq != (uint32_t)hdr->seq) {
        w = "proof names another list publication";
        goto out;
    }
    if (p->count == 0 || p->count != rec->count || p->count != hdr->count ||
        p->count > MXFS_RECOV_OBL_MAX_EXTENTS) {
        w = "proof count differs from the record/header";
        goto out;
    }
    if (p->list_crc32c != rec->list_crc32c ||
        p->list_crc32c != hdr->entries_crc32c) {
        w = "proof list crc differs from the record/header";
        goto out;
    }
    if (p->hdr_crc32c != hdr->hdr_crc32c) {
        w = "proof list-header crc differs from the header";
        goto out;
    }
    if (p->obl_ag_mask != rec->obl_ag_mask || p->obl_ag_mask == 0) {
        w = "proof AG mask differs from the record";
        goto out;
    }
    if (p->n_sparse != 0) {
        w = "proof records a SPARSE extent (the case is terminal, not done)";
        goto out;
    }
    if (p->rcpt_digest != 0) {
        w = "proof carries a receipts digest (custody is retained, never transferred)";
        goto out;
    }
    if ((uint64_t)p->n_empty + (uint64_t)p->n_full != (uint64_t)p->count) {
        w = "proof outcome counters do not sum to the count";
        goto out;
    }
    if (done_popcount(p->outcome, sizeof(p->outcome)) != p->n_empty) {
        w = "proof outcome bitmap population differs from n_empty";
        goto out;
    }
    for (i = p->count; i < MXFS_RMAN_OBL_DONE_BITMAP_BYTES * 8u; i++) {
        if (mxfs_rman_obl_done_bit(p, i)) {
            w = "proof outcome bit beyond the list count";
            goto out;
        }
    }
    if (p->owner_term == 0 || p->stage_seq == 0 || p->seq == 0) {
        w = "proof authorization identity (term/stage_seq/seq)";
        goto out;
    }
    if (!(p->flags & MXFS_RMAN_OBL_DONE_F_COMMITTED)) {
        w = "proof not committed (phase 1 only)";
        rc = -EINPROGRESS;
        goto out;
    }
    rc = 0;
out:
    if (why)
        *why = w;
    return rc;
}
