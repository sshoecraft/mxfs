/*
 * MXFS — Multinode XFS
 * Recovery obligation record + list: pure validation helpers.  No I/O, no
 * kernel API (RULE: dlm/ builds user-mode; chk_mxfs links this file).
 * Contract and on-disk layout: recov_obl.h.
 *
 * — D-FOREIGN-SLICE-INTENTS-ABANDONED item 5, increment 2.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include "recov_obl.h"

/* Compile-time layout guards: the record must be exactly the 40 bytes the
 * mxfs_recov_body pad owned, the header exactly one 4 KiB block, and an
 * entry 16 bytes — chk_mxfs mirrors these with its own _Static_asserts. */
typedef char mxfs_recov_obl_size_check[
    (sizeof(struct mxfs_recov_obl) == 40) ? 1 : -1];
typedef char mxfs_rman_obl_hdr_size_check[
    (sizeof(struct mxfs_rman_obl_hdr) == MXFS_RMAN_OBL_HDR_BYTES) ? 1 : -1];
typedef char mxfs_recov_obl_ext_size_check[
    (sizeof(struct mxfs_recov_obl_ext) == 16) ? 1 : -1];
typedef char mxfs_rman_obl_zone_check[
    (MXFS_RMAN_OBL_ENTRIES_OFF +
     (uint64_t)MXFS_RECOV_OBL_MAX_EXTENTS * 16 <= 65536u) ? 1 : -1];

static int obl_ext_cmp(const void *pa, const void *pb)
{
	const struct mxfs_recov_obl_ext *a = pa, *b = pb;

	if (a->agno != b->agno)
		return a->agno < b->agno ? -1 : 1;
	if (a->fsbno != b->fsbno)
		return a->fsbno < b->fsbno ? -1 : 1;
	if (a->len != b->len)
		return a->len < b->len ? -1 : 1;
	return 0;
}

int mxfs_recov_obl_canonicalize(struct mxfs_recov_obl_ext *ext, uint32_t n,
				const struct mxfs_recov_obl_geom *geom,
				uint64_t *ag_mask, bool *fswide)
{
	uint64_t mask = 0;
	bool fsw = false;
	uint32_t i;

	if (ag_mask)
		*ag_mask = 0;
	if (fswide)
		*fswide = false;
	if ((n && !ext) || !geom || geom->agcount == 0 || geom->agblocks == 0 ||
	    geom->agblklog == 0 || geom->agblklog >= 64)
		return -EINVAL;
	if (n > MXFS_RECOV_OBL_MAX_EXTENTS)
		return -EOVERFLOW;
	if (n == 0)
		return 0;

	mxfs_pal_sort(ext, n, sizeof(*ext), obl_ext_cmp);

	for (i = 0; i < n; i++) {
		const struct mxfs_recov_obl_ext *e = &ext[i];
		uint64_t agbno_mask = ((uint64_t)1 << geom->agblklog) - 1;
		uint64_t agbno = e->fsbno & agbno_mask;

		/* one extent: nonzero, inside its AG, agno consistent with fsbno */
		if (e->len == 0)
			return -EINVAL;
		if (e->agno >= geom->agcount)
			return -EINVAL;
		if ((e->fsbno >> geom->agblklog) != e->agno)
			return -EINVAL;
		if (agbno >= geom->agblocks ||
		    (uint64_t)e->len > (uint64_t)geom->agblocks - agbno)
			return -EINVAL;
		/* against the previous entry (sorted): no duplicate, no overlap */
		if (i > 0) {
			const struct mxfs_recov_obl_ext *p = &ext[i - 1];

			if (p->agno == e->agno) {
				uint64_t pbno = p->fsbno & agbno_mask;

				if (pbno + p->len > agbno)
					return -EEXIST;     /* overlap or duplicate */
			}
		}
		if (e->agno >= 64)
			fsw = true;
		else
			mask |= (uint64_t)1 << e->agno;
	}
	if (ag_mask)
		*ag_mask = fsw ? 0 : mask;
	if (fswide)
		*fswide = fsw;
	return 0;
}

uint32_t mxfs_recov_obl_list_crc(const struct mxfs_recov_obl_ext *ext,
				 uint32_t n)
{
	if (n == 0 || !ext)
		return 0;
	return mxfs_pal_crc32c(~0U, ext, (size_t)n * sizeof(*ext));
}

uint32_t mxfs_recov_obl_rec_crc(uint32_t fs_gen, uint32_t node_id,
				uint64_t epoch,
				const struct mxfs_recov_obl *rec)
{
	struct {
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) id;
	uint32_t crc;

	id.fs_gen  = fs_gen;
	id.node_id = node_id;
	id.epoch   = epoch;
	crc = mxfs_pal_crc32c(~0U, rec, offsetof(struct mxfs_recov_obl, crc32c));
	return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

uint32_t mxfs_rman_obl_hdr_crc(const struct mxfs_rman_obl_hdr *h)
{
	uint32_t crc;

	crc = mxfs_pal_crc32c(~0U, h, offsetof(struct mxfs_rman_obl_hdr, hdr_crc32c));
	return mxfs_pal_crc32c(crc, h->pad, sizeof(h->pad));
}

static bool obl_all_zero(const void *p, size_t len)
{
	const uint8_t *b = p;
	size_t i;

	for (i = 0; i < len; i++)
		if (b[i])
			return false;
	return true;
}

int mxfs_recov_obl_rec_check(const struct mxfs_recov_obl *rec,
			     uint32_t fs_gen, uint32_t node_id,
			     uint64_t epoch, const char **why)
{
	const char *w = "ok";
	int rc = -EPROTO;

	if (!rec) {
		w = "no record image";
		goto out;
	}
	if (obl_all_zero(rec, sizeof(*rec))) {
		w = "no record (all zero)";
		rc = -ENOENT;
		goto out;
	}
	if (rec->magic != MXFS_RECOV_OBL_MAGIC) {
		w = "record magic";
		goto out;
	}
	if (rec->version != MXFS_RECOV_OBL_VERSION) {
		w = "record version";
		goto out;
	}
	if (rec->crc32c != mxfs_recov_obl_rec_crc(fs_gen, node_id, epoch, rec)) {
		w = "record crc / victim identity";
		goto out;
	}
	if (rec->flags & ~MXFS_RECOV_OBL_F_ALL) {
		w = "record flags";
		goto out;
	}
	if (rec->count > MXFS_RECOV_OBL_MAX_EXTENTS) {
		w = "record count";
		goto out;
	}
	if (rec->count == 0) {
		if ((rec->flags & (MXFS_RECOV_OBL_F_LIST | MXFS_RECOV_OBL_F_FSWIDE)) ||
		    rec->obl_ag_mask || rec->list_crc32c || rec->pub_seq) {
			w = "empty record carries list evidence";
			goto out;
		}
	} else {
		if (!(rec->flags & MXFS_RECOV_OBL_F_LIST) || rec->pub_seq == 0) {
			w = "record with obligations but no published list";
			goto out;
		}
		if (rec->flags & MXFS_RECOV_OBL_F_FSWIDE) {
			if (rec->obl_ag_mask) {
				w = "FSWIDE record with an AG mask";
				goto out;
			}
		} else if (rec->obl_ag_mask == 0) {
			w = "AG-scoped record with an empty mask";
			goto out;
		}
	}
	rc = 0;
out:
	if (why)
		*why = w;
	return rc;
}

int mxfs_rman_obl_hdr_check(const struct mxfs_rman_obl_hdr *h,
			    const struct mxfs_recov_obl *rec,
			    uint32_t victim_node, uint64_t victim_epoch,
			    uint32_t victim_fs_gen, uint16_t victim_slot,
			    uint64_t recovery_gen, const char **why)
{
	const char *w = "ok";
	int rc = -EPROTO;

	if (!h || !rec) {
		w = "no header/record image";
		goto out;
	}
	if (obl_all_zero(h, sizeof(*h))) {
		w = "no list header (all zero)";
		rc = -ENOENT;
		goto out;
	}
	if (h->magic != MXFS_RMAN_OBL_MAGIC) {
		w = "list header magic";
		goto out;
	}
	if (h->version != MXFS_RMAN_OBL_VERSION) {
		w = "list header version";
		goto out;
	}
	if (h->hdr_crc32c != mxfs_rman_obl_hdr_crc(h)) {
		w = "list header crc";
		goto out;
	}
	if (!obl_all_zero(h->pad, sizeof(h->pad))) {
		w = "list header reserved bytes";
		goto out;
	}
	if (h->flags & ~MXFS_RECOV_OBL_F_ALL) {
		w = "list header flags";
		goto out;
	}
	/* the stable recovery-case identity */
	if (h->victim_node != victim_node || h->victim_epoch != victim_epoch ||
	    h->victim_fs_gen != victim_fs_gen || h->victim_slot != victim_slot ||
	    h->recovery_gen != recovery_gen) {
		w = "list header names another recovery case";
		goto out;
	}
	/* the record that publishes it */
	if (h->seq != rec->pub_seq || h->count != rec->count ||
	    h->entries_crc32c != rec->list_crc32c ||
	    h->census_digest != rec->census_digest ||
	    h->obl_ag_mask != rec->obl_ag_mask ||
	    (h->flags & MXFS_RECOV_OBL_F_FSWIDE) !=
		(rec->flags & MXFS_RECOV_OBL_F_FSWIDE) ||
		(h->flags & MXFS_RECOV_OBL_F_TERMINAL) !=
		    (rec->flags & MXFS_RECOV_OBL_F_TERMINAL)) {
		w = "list header does not match the record";
		goto out;
	}
	if (h->seq == 0 || h->count == 0 || h->count > MXFS_RECOV_OBL_MAX_EXTENTS) {
		w = "list header seq/count";
		goto out;
	}
	if (h->entry_bytes != sizeof(struct mxfs_recov_obl_ext) ||
	    (uint64_t)h->byte_len != (uint64_t)h->count * h->entry_bytes ||
	    (uint64_t)MXFS_RMAN_OBL_ENTRIES_OFF + h->byte_len >
		(uint64_t)MXFS_RMAN_OBL_ENTRIES_OFF +
		(uint64_t)MXFS_RECOV_OBL_MAX_EXTENTS * sizeof(struct mxfs_recov_obl_ext)) {
		w = "list entry geometry";
		goto out;
	}
	if (h->agcount == 0 || h->agblocks == 0) {
		w = "list header fs geometry";
		goto out;
	}
	rc = 0;
out:
	if (why)
		*why = w;
	return rc;
}

int mxfs_recov_obl_list_check(struct mxfs_recov_obl_ext *ext, uint32_t n,
			      const struct mxfs_rman_obl_hdr *h,
			      const struct mxfs_recov_obl *rec,
			      const char **why)
{
	struct mxfs_recov_obl_geom geom;
	struct mxfs_recov_obl_ext *copy = NULL;
	const char *w = "ok";
	uint64_t mask = 0;
	bool fsw = false;
	uint32_t i;
	int rc = -EPROTO;

	if (!h || !rec || (n && !ext)) {
		w = "no list image";
		goto out;
	}
	if (n != h->count) {
		w = "entry count differs from the header";
		goto out;
	}
	if (mxfs_recov_obl_list_crc(ext, n) != h->entries_crc32c) {
		w = "list entries crc";
		goto out;
	}
	geom.agcount  = h->agcount;
	geom.agblocks = h->agblocks;
	/* agblklog = ceil(log2(agblocks)) exactly as mkfs derives sb_agblklog */
	geom.agblklog = 0;
	while (geom.agblklog < 63 &&
	       ((uint64_t)1 << geom.agblklog) < (uint64_t)h->agblocks)
		geom.agblklog++;
	/* canonical form is checked on a COPY: the platter bytes are the
	 * evidence and a list that had to be reordered is itself a failure */
	copy = mxfs_pal_alloc((size_t)(n ? n : 1) * sizeof(*copy));
	if (!copy) {
		w = "no memory for the canonical check";
		rc = -ENOMEM;
		goto out;
	}
	if (n)
		memcpy(copy, ext, (size_t)n * sizeof(*copy));
	if (mxfs_recov_obl_canonicalize(copy, n, &geom, &mask, &fsw)) {
		w = "list entries are not canonical (bounds/duplicate/overlap)";
		goto out;
	}
	for (i = 0; i < n; i++) {
		if (copy[i].fsbno != ext[i].fsbno || copy[i].agno != ext[i].agno ||
		    copy[i].len != ext[i].len) {
			w = "list entries are not in canonical order";
			goto out;
		}
	}
	if (fsw != !!(h->flags & MXFS_RECOV_OBL_F_FSWIDE) ||
	    mask != h->obl_ag_mask || mask != rec->obl_ag_mask) {
		w = "recomputed AG mask/fswide differs from the header/record";
		goto out;
	}
	rc = 0;
out:
	mxfs_pal_free(copy);
	if (why)
		*why = w;
	return rc;
}
