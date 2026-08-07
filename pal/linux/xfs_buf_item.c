// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_mount.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_buf_item.h"
#include "xfs_inode.h"
#include "xfs_inode_item.h"
#include "xfs_quota.h"
#include "xfs_dquot_item.h"
#include "xfs_dquot.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_error.h"
#include "xfs_ag.h"
/*
 * sess96 step 5.3(a): the v5 owner-bearing metadata headers.  Every
 * xfs_*_buf_ops symbol the owner ladder compares against is declared either by
 * xfs_shared.h (already included) or by xfs_dir2.h for the dir3 families.
 * Deliberately NOT pulling xfs_attr_remote.h / xfs_symlink.h / xfs_da_btree.h:
 * those declare functions over types this file has no forward declaration for
 * and emit incomplete-type warnings, while the buf_ops they would supply are
 * already visible via xfs_shared.h.
 */
#include "xfs_da_format.h"
#include "xfs_dir2.h"
#include "xfs_mxfs_dlm.h"
#include <mxfs/mxfs_dlm.h>	/* sess103 step 5.3: MXFS_LOCK_* modes */


struct kmem_cache	*xfs_buf_item_cache;

static inline struct xfs_buf_log_item *BUF_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_buf_log_item, bli_item);
}

static void
xfs_buf_item_get_format(
	struct xfs_buf_log_item	*bip,
	int			count)
{
	ASSERT(bip->bli_formats == NULL);
	bip->bli_format_count = count;

	if (count == 1) {
		bip->bli_formats = &bip->__bli_format;
		return;
	}

	bip->bli_formats = kzalloc(count * sizeof(struct xfs_buf_log_format),
				GFP_KERNEL | __GFP_NOFAIL);
}

static void
xfs_buf_item_free_format(
	struct xfs_buf_log_item	*bip)
{
	if (bip->bli_formats != &bip->__bli_format) {
		kfree(bip->bli_formats);
		bip->bli_formats = NULL;
	}
}

static void
xfs_buf_item_free(
	struct xfs_buf_log_item	*bip)
{
	xfs_buf_item_free_format(bip);
	kvfree(bip->bli_item.li_lv_shadow);
	kmem_cache_free(xfs_buf_item_cache, bip);
}

/*
 * xfs_buf_item_relse() is called when the buf log item is no longer needed.
 */
static void
xfs_buf_item_relse(
	struct xfs_buf_log_item	*bip)
{
	struct xfs_buf		*bp = bip->bli_buf;

	trace_xfs_buf_item_relse(bp, _RET_IP_);

	ASSERT(!test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags));
	ASSERT(atomic_read(&bip->bli_refcount) == 0);

	bp->b_log_item = NULL;
	xfs_buf_rele(bp);
	xfs_buf_item_free(bip);
}

/* Is this log iovec plausibly large enough to contain the buffer log format? */
bool
xfs_buf_log_check_iovec(
	struct kvec			*iovec)
{
	struct xfs_buf_log_format	*blfp = iovec->iov_base;
	char				*bmp_end;
	char				*item_end;

	if (offsetof(struct xfs_buf_log_format, blf_data_map) > iovec->iov_len)
		return false;

	item_end = (char *)iovec->iov_base + iovec->iov_len;
	bmp_end = (char *)&blfp->blf_data_map[blfp->blf_map_size];
	return bmp_end <= item_end;
}

static inline int
xfs_buf_log_format_size(
	struct xfs_buf_log_format *blfp)
{
	return offsetof(struct xfs_buf_log_format, blf_data_map) +
			(blfp->blf_map_size * sizeof(blfp->blf_data_map[0]));
}

/*
 * sess48 authority token (step 3a): does this (non-stale) buf item emit
 * the mxfs_blf_authority trailer?  A pure function of the mount so the
 * size estimate and the format emission can never disagree (the trailer
 * is emitted with class NONE when no authority is known — presence must
 * be size-stable, content is resolved at format time).
 */
struct mxfs_v5_dlm;
extern bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *);
extern int mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *);
/*
 * sess94 step 5.2: the emitting mount's identity, as ONE atomic-enough read
 * of three mount-lifetime constants (slot, node_id, incarnation).  Returns
 * false — with all three outputs zeroed — if any of them is unavailable, and
 * that is a token CAPTURE FAILURE, not a "no authority" answer: an image we
 * cannot bind to an emitting incarnation is not evidence about anything.
 * O(1), lock-free; the slot and the incarnation are fixed for the life of a
 * mount so the format path takes no lock.
 */
extern bool mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *, uint32_t *slot,
				       uint32_t *node, uint64_t *epoch);

static inline bool
mxfs_buf_item_wants_authority(
	struct xfs_buf_log_item	*bip)
{
	struct xfs_mount	*mp = bip->bli_buf->b_mount;

	return mp && mp->m_mxfs_dlm &&
	       !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);
}

/*
 * sess82 step 5.1(c): does the containing AG's EX grant actually AUTHORIZE
 * this buffer?
 *
 * The sess48 rule classified by xfs_daddr_to_agno(blf_blkno) ALONE, which is
 * wrong: a dir data block, da-node, attr block, symlink block or bmbt block
 * physically lives inside an AG but its authority is the *inode's* EX grant,
 * not the AG's.  Labelling those class=AG{containing agno} would let a future
 * exact-match gate "prove" the wrong resource and apply an image the victim
 * had already handed off — a false APPLY, strictly worse than today's taint.
 *
 * The discriminator is a CONJUNCTION, and b_ops must be primary:
 * XFS_BLFT_BTREE_BUF conflates the AG btrees with the per-inode bmbt, so BLFT
 * alone cannot tell them apart.  BLFT is required to agree as a second,
 * independent witness (it is set by xfs_trans_buf_set_type before format
 * time, so both halves are available here with no new plumbing).
 *
 * Anything not on this list => MXFS_AUTH_CLASS_NONE => recovery taints and
 * skips.  Fail closed.
 */
static bool
mxfs_buf_ag_authorized(
	const struct xfs_buf		*bp,
	struct xfs_buf_log_format	*blfp)
{
	const struct xfs_buf_ops	*ops = bp->b_ops;
	uint16_t			blft = xfs_blft_from_flags(blfp);

	if (!ops)
		return false;

	if (ops == &xfs_agf_buf_ops)
		return blft == XFS_BLFT_AGF_BUF;
	if (ops == &xfs_agi_buf_ops)
		return blft == XFS_BLFT_AGI_BUF;
	if (ops == &xfs_agfl_buf_ops)
		return blft == XFS_BLFT_AGFL_BUF;
	if (ops == &xfs_bnobt_buf_ops || ops == &xfs_cntbt_buf_ops ||
	    ops == &xfs_inobt_buf_ops || ops == &xfs_finobt_buf_ops ||
	    ops == &xfs_rmapbt_buf_ops || ops == &xfs_refcountbt_buf_ops)
		return blft == XFS_BLFT_BTREE_BUF;

	return false;
}

/*
 * sess96 step 5.3(a) — OWNER DERIVATION.
 *
 * The population step 5.1 measured as "mislabel" (4770 of 16384 tokens on the
 * 0.11.427 rig, 100% directory blocks) is authorized by the owning INODE's EX
 * grant, not by the containing AG's.  To name that authority on the wire we
 * must first know WHICH inode owns the image, and the only in-band source is
 * the v5 metadata header the block already carries.
 *
 * The sess95 RULE-5 ruling is explicit about how this may be done:
 *
 *  - derive ONCE per logical buffer log item, from offset 0 (map 0), and reuse
 *    the cached answer for every segment.  Never derive per segment: all
 *    segments of a discontiguous buffer must carry identical token fields, and
 *    only map 0 holds the header.
 *  - the header is NOT trustable unconditionally.  Validate b_ops family,
 *    exact magic, header fits, UUID, and that the owner is a plausible inode.
 *  - for bmbt specifically, prove it is a LONG-format inode-owned bmap btree
 *    block and not an AG btree admitted through the generic XFS_BLFT_BTREE_BUF.
 *  - any failure is a NON-PROVING status, never a fallback to the containing
 *    AG's epoch.  That fallback is exactly how the 29% got mislabelled.
 *
 * One honest limit, recorded because 5.4 has to handle it: reading the owner
 * out of buffer MEMORY does not prove the owner field is inside the LOGGED
 * regions of this image.  If only a dirent range is logged, the header may name
 * an owner that no longer holds the block after reuse.  Inode authority alone
 * therefore cannot prove an old partial image still targets a block owned by
 * that inode — recovery must re-validate the owner against the replay target.
 */
struct mxfs_buf_owner {
	uint64_t	ino;		/* validated owning inode number */
	bool		valid;		/* false => OWNER_UNKNOWN, fail closed */
};

static bool
mxfs_owner_hdr_ok(
	struct xfs_mount	*mp,
	const void		*addr,
	size_t			blen,
	size_t			need,
	const uuid_t		*uuid,
	uint64_t		owner)
{
	if (need > blen)
		return false;			/* header does not fit */
	if (!uuid_equal(uuid, &mp->m_sb.sb_meta_uuid))
		return false;			/* another filesystem */
	if (!xfs_verify_ino(mp, (xfs_ino_t)owner))
		return false;			/* not a plausible inode */
	return true;
}

static void
mxfs_buf_derive_owner(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp,
	struct mxfs_buf_owner		*out)
{
	struct xfs_mount		*mp = bp->b_mount;
	const struct xfs_buf_ops	*ops = bp->b_ops;
	uint16_t			blft = xfs_blft_from_flags(blfp);
	const void			*addr;
	size_t				blen;
	uint64_t			owner;

	out->ino = 0;
	out->valid = false;

	/* Owners exist only in the v5/CRC metadata headers. */
	if (!ops || !mp || !xfs_has_crc(mp))
		return;

	/*
	 * Offset 0 of the LOGICAL buffer.  xfs_buf_offset() resolves this
	 * correctly for discontiguous (vmapped) buffers too, so map 0's header
	 * is reachable without knowing the mapping shape.
	 */
	addr = xfs_buf_offset(bp, 0);
	if (!addr)
		return;
	blen = BBTOB(bp->b_length);

	if (ops == &xfs_dir3_data_buf_ops || ops == &xfs_dir3_block_buf_ops ||
	    ops == &xfs_dir3_free_buf_ops) {
		const struct xfs_dir3_blk_hdr *h = addr;
		uint32_t magic;

		if (sizeof(*h) > blen)
			return;
		magic = be32_to_cpu(h->magic);
		/* magic must agree with BOTH b_ops and the BLFT */
		if (ops == &xfs_dir3_data_buf_ops) {
			if (magic != XFS_DIR3_DATA_MAGIC ||
			    blft != XFS_BLFT_DIR_DATA_BUF)
				return;
		} else if (ops == &xfs_dir3_block_buf_ops) {
			if (magic != XFS_DIR3_BLOCK_MAGIC ||
			    blft != XFS_BLFT_DIR_BLOCK_BUF)
				return;
		} else {
			if (magic != XFS_DIR3_FREE_MAGIC ||
			    blft != XFS_BLFT_DIR_FREE_BUF)
				return;
		}
		owner = be64_to_cpu(h->owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->uuid,
				       owner))
			return;
	} else if (ops == &xfs_dir3_leaf1_buf_ops ||
		   ops == &xfs_dir3_leafn_buf_ops ||
		   ops == &xfs_da3_node_buf_ops ||
		   ops == &xfs_attr3_leaf_buf_ops) {
		const struct xfs_da3_blkinfo *h = addr;
		uint16_t magic;

		if (sizeof(*h) > blen)
			return;
		magic = be16_to_cpu(h->hdr.magic);
		if (ops == &xfs_dir3_leaf1_buf_ops) {
			if (magic != XFS_DIR3_LEAF1_MAGIC ||
			    blft != XFS_BLFT_DIR_LEAF1_BUF)
				return;
		} else if (ops == &xfs_dir3_leafn_buf_ops) {
			if (magic != XFS_DIR3_LEAFN_MAGIC ||
			    blft != XFS_BLFT_DIR_LEAFN_BUF)
				return;
		} else if (ops == &xfs_da3_node_buf_ops) {
			/*
			 * xfs_da3_node_buf_ops verifies BOTH the da-node magic
			 * and (for a dir) the leafn magic, and both BLFTs are
			 * legitimate for it — accept the exact pairs only.
			 */
			if (!((magic == XFS_DA3_NODE_MAGIC &&
			       blft == XFS_BLFT_DA_NODE_BUF) ||
			      (magic == XFS_DIR3_LEAFN_MAGIC &&
			       blft == XFS_BLFT_DIR_LEAFN_BUF)))
				return;
		} else {
			if (magic != XFS_ATTR3_LEAF_MAGIC ||
			    blft != XFS_BLFT_ATTR_LEAF_BUF)
				return;
		}
		owner = be64_to_cpu(h->owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->uuid,
				       owner))
			return;
	} else if (ops == &xfs_attr3_rmt_buf_ops) {
		const struct xfs_attr3_rmt_hdr *h = addr;

		if (sizeof(*h) > blen ||
		    be32_to_cpu(h->rm_magic) != XFS_ATTR3_RMT_MAGIC ||
		    blft != XFS_BLFT_ATTR_RMT_BUF)
			return;
		owner = be64_to_cpu(h->rm_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->rm_uuid,
				       owner))
			return;
	} else if (ops == &xfs_symlink_buf_ops) {
		const struct xfs_dsymlink_hdr *h = addr;

		if (sizeof(*h) > blen ||
		    be32_to_cpu(h->sl_magic) != XFS_SYMLINK_MAGIC ||
		    blft != XFS_BLFT_SYMLINK_BUF)
			return;
		owner = be64_to_cpu(h->sl_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->sl_uuid,
				       owner))
			return;
	} else if (ops == &xfs_bmbt_buf_ops) {
		const struct xfs_btree_block *h = addr;

		/*
		 * The ruling's specific trap: XFS_BLFT_BTREE_BUF is the generic
		 * btree type shared with every AG btree, so BLFT alone cannot
		 * prove this block is inode-owned.  b_ops == xfs_bmbt_buf_ops
		 * AND magic == BMA3 is the exact discriminator — BMA3 is only
		 * ever written to a LONG-format (inode-owned) bmap btree block,
		 * and only the long form has bb_u.l.bb_owner at all.  Demand
		 * the long-form CRC header length as well, so a short-form
		 * block can never be read through the long-form union arm.
		 */
		if (XFS_BTREE_LBLOCK_CRC_LEN > blen ||
		    be32_to_cpu(h->bb_magic) != XFS_BMAP_CRC_MAGIC ||
		    blft != XFS_BLFT_BTREE_BUF)
			return;
		owner = be64_to_cpu(h->bb_u.l.bb_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, XFS_BTREE_LBLOCK_CRC_LEN,
				       &h->bb_u.l.bb_uuid, owner))
			return;
	} else {
		return;			/* not an inode-owned buffer family */
	}

	out->ino = owner;
	out->valid = true;
}

/*
 * ─── sess101 step 5.3 — THE DECIDING MEASUREMENT ─────────────────────────
 *
 * sess100 measured 13153 inodes entering UNPUBLISHED_EX against 321 durable
 * tenures installed on one rsync_paired lap, and concluded a DURABLE_EX gate
 * would refuse ~97.6% of the images a create-heavy workload produces.  The
 * sess101 RULE-5 ruling rejected that inference: `unpublished_noted` counts
 * STATE ENTRIES, not IMAGES.  It cannot say how many logged images were
 * actually formatted while their owner was unpublished, nor which image types,
 * nor whether the allocating AG tenure was still live.  The 13153-vs-321
 * comparison therefore does not establish the refusal rate at all.
 *
 * This is the measurement that does: for every inode-owned buffer image (the
 * population step 5.1 counts as `mislabel` + `unknown`), resolve the OWNING
 * inode from the block's own v5 header and record the owner's authority state
 * AT FORMAT TIME.  That single joint distribution decides the design fork the
 * ruling laid out:
 *
 *   durable dominates  -> the per-inode certificate is the right gate and the
 *                         producer just needs wiring;
 *   unpub dominates    -> the ruling's "durable unpublished-child delegation
 *                         minted under the AG grant" is required, because
 *                         these are LATER modifications of an unpublished
 *                         object, not initial creation, and an AG-derived
 *                         birth certificate cannot reach them;
 *   uncached/stale     -> the owner is not resolvable at format time and the
 *                         capture has to move to the dirty/join seam (the
 *                         sess48 ruling item (b) that is still owed).
 *
 * The BLFT histogram is kept only for the NON-durable outcomes: that is the
 * population that would be refused, and its type mix is the ruling's "image
 * relationship" axis (DINO_BUF = initial cluster init, bmbt/dir/attr = later
 * modification of an existing object).
 *
 * HONEST LIMITS, recorded because the design must not over-read this:
 *   - the authority fields are read WITHOUT i_dlm_lock.  Taking it at CIL
 *     format time would invert the established lock order, so this is a
 *     sampled read: a state that changes concurrently may be attributed to
 *     either side.  It measures a distribution, and must never become the
 *     gate's own test.
 *   - it counts per SEGMENT, so a discontiguous buffer contributes once per
 *     segment.  Every segment of one buffer derives the same owner (map 0),
 *     so the distribution is unaffected; only the absolute total is inflated.
 *   - reading the owner out of buffer MEMORY does not prove the owner field
 *     lies inside the LOGGED regions of this image (the sess96 limit).
 */
enum {
	MXFS_OWNAUTH_NOOWNER = 0,	/* header gave no trustworthy owner */
	MXFS_OWNAUTH_BADAG,		/* owner ino outside the AG range */
	MXFS_OWNAUTH_NOPAG,		/* perag unavailable */
	MXFS_OWNAUTH_UNCACHED,		/* owner not in the inode cache */
	MXFS_OWNAUTH_STALE,		/* found, but reclaiming or reused */
	MXFS_OWNAUTH_NONE,		/* MXFS_AUTH_NONE */
	MXFS_OWNAUTH_UNPUB,		/* MXFS_AUTH_UNPUBLISHED_EX */
	MXFS_OWNAUTH_RELEASING,		/* MXFS_AUTH_RELEASING */
	MXFS_OWNAUTH_DURABLE,		/* DURABLE_EX with a real epoch */
	MXFS_OWNAUTH_DURABLE_NOEP,	/* DURABLE_EX, epoch 0 — plumbing hole */
	MXFS_OWNAUTH_MAX
};

static atomic64_t	mxfs_ownauth_n[MXFS_OWNAUTH_MAX];
static atomic64_t	mxfs_ownauth_blft[XFS_BLFT_MAX_BUF];

/*
 * P240-AUTHCAP — the capture-point instrument the sess102 ruling demanded.
 *
 * Everything here is counted at the FIRST PROTECTED DIRTY, not at format
 * time, so it describes the tenure that authorized the mutation.
 *
 *   mxfs_authcap_mode[oc]  of the images with outcome `oc`, how many were
 *                          dirtied while this node held mode >= PW on the
 *                          derived owner.  This is the cross-tab that
 *                          separates "the recorder is broken" from "the
 *                          modification was genuinely unauthorized" (P3).
 *   win                    capture windows opened (one per bli per trans).
 *   relog                  re-logs of an already-captured buffer inside the
 *                          same window that were re-resolved and verified.
 *   mismatch               ... of which resolved to a DIFFERENT authority
 *                          object or epoch.  The ruling's "one buffer, two
 *                          authorities" case: never silently overwritten,
 *                          the image is downgraded to MIXED.
 *   noblft                 captures taken before xfs_trans_buf_set_type ran,
 *                          so owner derivation had no BLFT witness.
 *   blftchg                the BLFT changed between capture and format —
 *                          the capture described a different image kind and
 *                          cannot be serialized as proof.
 *   nocap                  formatted with NO capture at all (a dirty path
 *                          that bypasses xfs_trans_dirty_buf).  Must be 0;
 *                          any nonzero value is a plumbing hole.
 */
static atomic64_t	mxfs_authcap_mode[MXFS_OWNAUTH_MAX];
static atomic64_t	mxfs_authcap_win;
static atomic64_t	mxfs_authcap_relog;
static atomic64_t	mxfs_authcap_mismatch;
static atomic64_t	mxfs_authcap_noblft;
static atomic64_t	mxfs_authcap_blftchg;
static atomic64_t	mxfs_authcap_nocap;

/*
 * P241-AUTHTRY — the decisive instrument the sess104 RULE-5 ruling asked for.
 *
 * The sess104 cross-tab established that every NONE image was dirtied while
 * this node held a WRITING mode, i.e. the authority RECORD is incomplete
 * rather than the modification unauthorized.  It could not say WHY, because
 * `i_mxfs_auth_line` names the last SUCCESSFUL transition (the revoke that
 * established NONE) and a failed install does not transition at all.
 *
 * So the owner's last install ATTEMPT is carried out of the same i_flags_lock
 * section as the state, and histogrammed at exactly the images that matter:
 * the NONE-at-writing-mode population.  Reading the ruling's table:
 *
 *   try == never                  no install was ever attempted — a MISSING
 *                                 CALL: this acquire path does not install
 *   try_gen < gen                 an attempt happened, then a revoke, and
 *                                 nothing retried — MISSING POST-REVOKE EVENT
 *   try == st:write_zero_epoch    the slot had a writing mode and no epoch —
 *                                 EPOCH PUBLICATION/RESTART GAP
 *   try == st:nonwrite_mode       installed against a READ grant and never
 *                                 retried at the conversion that made it a
 *                                 write grant — the ruling's leading
 *                                 hypothesis for this population
 *   try == install/advance        authority WAS installed and something
 *                                 revoked it since — a release-side defect
 */
struct mxfs_ownauth_snap {
	uint64_t	epoch;
	uint64_t	res;
	uint64_t	gen;
	uint64_t	try_gen;
	uint64_t	try_epoch;
	uint32_t	auth_line;
	uint32_t	try_line;
	uint8_t		dlm_mode;
	uint8_t		try;
	uint8_t		try_mode;
	uint8_t		unpublished;
};

static atomic64_t	mxfs_authtry_none[MXFS_AUTH_TRY_MAX];
static atomic64_t	mxfs_authtry_stale;	/* of those, try_gen < gen */
static atomic64_t	mxfs_authtry_samegen;	/* of those, try_gen == gen */

static int
mxfs_buf_owner_authority(
	struct xfs_mount	*mp,
	uint64_t		ino,
	struct mxfs_ownauth_snap *sn)
{
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	int			out;

	memset(sn, 0, sizeof(*sn));

	agno = XFS_INO_TO_AGNO(mp, ino);
	if (agno >= mp->m_sb.sb_agcount)
		return MXFS_OWNAUTH_BADAG;
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return MXFS_OWNAUTH_NOPAG;

	/*
	 * RCU lookup only — never an iget.  The sess95 ruling forbids taking a
	 * reference from the formatter (it can recurse into reclaim and into
	 * the very transaction being formatted); the sess96 ruling names this
	 * exact shape instead: rcu_read_lock across lookup, validate identity
	 * and reclaim state under i_flags_lock, copy out, drop.
	 */
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, XFS_INO_TO_AGINO(mp, ino));
	if (!ip) {
		out = MXFS_OWNAUTH_UNCACHED;
	} else {
		spin_lock(&ip->i_flags_lock);
		if (ip->i_ino != ino ||
		    (ip->i_flags & (XFS_IRECLAIM | XFS_IRECLAIMABLE))) {
			out = MXFS_OWNAUTH_STALE;
		} else {
			uint8_t  st = READ_ONCE(ip->i_mxfs_auth_state);
			uint64_t ep = READ_ONCE(ip->i_mxfs_auth_epoch);

			/*
			 * sess103: the ruling's decisive cross-tab is
			 * outcome x (dlm_mode >= PW), and it must be taken
			 * under the SAME i_flags_lock section as the state —
			 * a mode read outside it can describe a different
			 * instant and would make "NONE at mode>=PW" (broken
			 * recorder) indistinguishable from "NONE at mode<PW"
			 * (genuinely unauthorized modification).
			 *
			 * sess105: the last install ATTEMPT rides out of the
			 * same section, for the same reason — the whole point
			 * is to pair it with the state it failed to reach.
			 */
			sn->gen = READ_ONCE(ip->i_mxfs_auth_gen);
			sn->dlm_mode = READ_ONCE(ip->i_dlm_mode);
			sn->auth_line = READ_ONCE(ip->i_mxfs_auth_line);
			sn->try = READ_ONCE(ip->i_mxfs_auth_try);
			sn->try_mode = READ_ONCE(ip->i_mxfs_auth_try_mode);
			sn->try_line = READ_ONCE(ip->i_mxfs_auth_try_line);
			sn->try_epoch = READ_ONCE(ip->i_mxfs_auth_try_epoch);
			sn->try_gen = READ_ONCE(ip->i_mxfs_auth_try_gen);
			sn->unpublished = READ_ONCE(ip->i_dlm_unpublished);

			switch (st) {
			case MXFS_AUTH_UNPUBLISHED_EX:
				out = MXFS_OWNAUTH_UNPUB;
				break;
			case MXFS_AUTH_RELEASING:
				out = MXFS_OWNAUTH_RELEASING;
				break;
			case MXFS_AUTH_DURABLE_EX:
				if (ep) {
					out = MXFS_OWNAUTH_DURABLE;
					sn->epoch = ep;
					sn->res = READ_ONCE(
						ip->i_mxfs_auth_resource);
				} else {
					out = MXFS_OWNAUTH_DURABLE_NOEP;
				}
				break;
			default:
				out = MXFS_OWNAUTH_NONE;
				break;
			}
		}
		spin_unlock(&ip->i_flags_lock);
	}
	rcu_read_unlock();
	xfs_perag_put(pag);
	return out;
}

/*
 * Resolve the INODE arm of the ladder for one image and record it in the
 * P239-OWNAUTH histogram.  Called only from the capture point (sess103): the
 * histogram used to be taken at CIL format time, where — per the sess102
 * ruling — neither `durable` nor `none` means what it appears to mean,
 * because authority may have been acquired or released between the mutation
 * and the format.  Taken at first dirty, the same buckets DO describe the
 * grant that authorized the mutation.
 */
static int
mxfs_ownauth_measure(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp,
	struct xfs_mount		*mp,
	struct mxfs_bli_auth		*out)
{
	struct mxfs_buf_owner		own;
	struct mxfs_ownauth_snap	sn;
	uint8_t				mode;
	int				oc;

	mxfs_buf_derive_owner(bp, blfp, &own);
	if (!own.valid) {
		memset(&sn, 0, sizeof(sn));
		oc = MXFS_OWNAUTH_NOOWNER;
	} else {
		oc = mxfs_buf_owner_authority(mp, own.ino, &sn);
	}
	mode = sn.dlm_mode;
	atomic64_inc(&mxfs_ownauth_n[oc]);
	/*
	 * The ruling's decisive cross-tab: of each outcome, how many were
	 * taken while this node held a WRITING mode on the owner.
	 *   DURABLE + writing  -> expected
	 *   NONE    + writing  -> the RECORDER is broken (state-machine gap)
	 *   NONE    + !writing -> a genuinely UNAUTHORIZED modification, a
	 *                         live coherency defect worse than replay
	 */
	if (mxfs_mode_can_write(mode)) {
		atomic64_inc(&mxfs_authcap_mode[oc]);
		/*
		 * P241: the NONE-at-writing-mode population is the one
		 * sess104 proved is a recorder gap.  Classify it by the
		 * owner's last install ATTEMPT — that is what names the
		 * missing event.
		 */
		if (oc == MXFS_OWNAUTH_NONE) {
			uint8_t t = sn.try < MXFS_AUTH_TRY_MAX ?
				    sn.try : MXFS_AUTH_TRY_NONE;

			atomic64_inc(&mxfs_authtry_none[t]);
			if (sn.try_gen < sn.gen)
				atomic64_inc(&mxfs_authtry_stale);
			else
				atomic64_inc(&mxfs_authtry_samegen);
			if (printk_ratelimit())
				pr_warn("mxfs: P241-AUTHTRY ino=%llu mode=%u try=%u try_mode=%u try_ep=%llu try_line=%u try_gen=%llu gen=%llu line=%u unpub=%u\n",
					(unsigned long long)own.ino,
					(unsigned)mode, (unsigned)sn.try,
					(unsigned)sn.try_mode,
					(unsigned long long)sn.try_epoch,
					(unsigned)sn.try_line,
					(unsigned long long)sn.try_gen,
					(unsigned long long)sn.gen,
					(unsigned)sn.auth_line,
					(unsigned)sn.unpublished);
		}
	}
	if (oc != MXFS_OWNAUTH_DURABLE) {
		uint16_t bt = xfs_blft_from_flags(blfp);

		if (bt < XFS_BLFT_MAX_BUF)
			atomic64_inc(&mxfs_ownauth_blft[bt]);
	}

	out->mba_owner_ino = own.valid ? own.ino : 0;
	out->mba_dlm_mode = mode;
	out->mba_outcome = (uint8_t)oc;

	/*
	 * Only a DURABLE tenure with a real epoch proves anything.  Every
	 * other outcome maps to the specific non-proving status the sess95
	 * ruling reserved for it — they must not collapse into one bucket,
	 * because recovery has to fail closed DIFFERENTLY per reason.
	 */
	switch (oc) {
	case MXFS_OWNAUTH_DURABLE:
		out->mba_class = MXFS_AUTH_CLASS_INODE;
		out->mba_resource = sn.res;
		out->mba_epoch = sn.epoch;
		out->mba_auth_gen = sn.gen;
		out->mba_status = MXFS_AUTH_ST_VALID;
		break;
	case MXFS_OWNAUTH_NOOWNER:
	case MXFS_OWNAUTH_BADAG:
		out->mba_status = MXFS_AUTH_ST_OWNER_UNKNOWN;
		break;
	case MXFS_OWNAUTH_NOPAG:
		out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
		break;
	case MXFS_OWNAUTH_UNCACHED:
	case MXFS_OWNAUTH_STALE:
		out->mba_status = MXFS_AUTH_ST_AUTH_NOT_CACHED;
		break;
	case MXFS_OWNAUTH_NONE:
	case MXFS_OWNAUTH_UNPUB:
	case MXFS_OWNAUTH_RELEASING:
		out->mba_status = MXFS_AUTH_ST_AUTH_NOT_HELD;
		break;
	case MXFS_OWNAUTH_DURABLE_NOEP:
		out->mba_status = MXFS_AUTH_ST_EPOCH_UNAVAIL;
		break;
	default:
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		break;
	}
	return oc;
}

/*
 * sess82 step 5.1(d): direct measurement of the false-APPLY exposure the
 * RULE-5 ruling predicted from code reading alone.  MISLABEL counts buffers
 * the OLD rule would have stamped class=AG but which are not AG-authorized at
 * all; NOEPOCH counts genuinely AG-authorized buffers that now stamp NONE
 * because the grant-state lifecycle says we do not positively hold the grant.
 * The BLFT histogram is only touched on the mislabel path — that is the
 * population under study.
 */
static atomic64_t	mxfs_tokcls_n;
static atomic64_t	mxfs_tokcls_ag;
static atomic64_t	mxfs_tokcls_sb;
static atomic64_t	mxfs_tokcls_mislabel;
static atomic64_t	mxfs_tokcls_noepoch;
/*
 * sess94 step 5.2: two populations v1 could not name.  UNKNOWN is the image
 * whose authority is neither the containing AG nor the superblock — a dir
 * data block, da-node, attr block, symlink or bmbt block, whose real
 * authority is the INODE's EX grant.  That is the population step 5.3 has to
 * capture, and it is the population whose false-SKIP makes this defect
 * critical, so measuring its size is the point of the counter.  INCOMPLETE
 * is a capture failure (no mount identity, or no perag) and must never be
 * normalized into "no authority".
 */
static atomic64_t	mxfs_tokcls_unknown;
static atomic64_t	mxfs_tokcls_incomplete;
static atomic64_t	mxfs_tokcls_blft[XFS_BLFT_MAX_BUF];

static const char * const mxfs_ownauth_name[MXFS_OWNAUTH_MAX] = {
	"noowner", "badag", "nopag", "uncached", "stale",
	"none", "unpub", "releasing", "durable", "durnoep",
};

/* Names for the P241 last-install-attempt histogram.  Sparse by design: the
 * MXFS_AUTH_TRY_STATUS_BASE range mirrors enum mxfs_grant_auth_status. */
static const char * const mxfs_authtry_name[MXFS_AUTH_TRY_MAX] = {
	[MXFS_AUTH_TRY_NONE]		= "never",
	[MXFS_AUTH_TRY_INSTALL]		= "install",
	[MXFS_AUTH_TRY_ADVANCE]		= "advance",
	[MXFS_AUTH_TRY_SAMETENURE]	= "sametenure",
	[MXFS_AUTH_TRY_NOGRES]		= "nogres",
	[MXFS_AUTH_TRY_STALEGEN]	= "stalegen",
	[MXFS_AUTH_TRY_RELEASING]	= "releasing",
	[MXFS_AUTH_TRY_UNPUB]		= "unpub",
	[MXFS_AUTH_TRY_ROUTING]		= "routing",
	[MXFS_AUTH_TRY_RECLAIM]		= "reclaim",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_UNSET]		= "st_unset",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_EPOCH]	= "st_wrep",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NONWRITE_MODE]	= "st_nonwr",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_ZERO_EPOCH] = "st_wrzero",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NO_RESOURCE]	= "st_nores",
};

/*
 * Two lines, so neither can be truncated by the other: the outcome
 * distribution, then the BLFT mix of everything that was NOT durable.
 */
static void
mxfs_ownauth_report(void)
{
	char	buf[240];
	int	len = 0;
	int	i;
	long long tot = 0;

	for (i = 0; i < MXFS_OWNAUTH_MAX; i++) {
		long long v = atomic64_read(&mxfs_ownauth_n[i]);

		tot += v;
		if (len < (int)sizeof(buf) - 24)
			len += scnprintf(buf + len, sizeof(buf) - len,
					 " %s=%lld", mxfs_ownauth_name[i], v);
	}
	buf[len] = '\0';
	pr_warn("mxfs: P239-OWNAUTH n=%lld%s\n", tot, buf);

	len = 0;
	for (i = 0; i < XFS_BLFT_MAX_BUF; i++) {
		long long v = atomic64_read(&mxfs_ownauth_blft[i]);

		if (!v || len >= (int)sizeof(buf) - 24)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " t%d=%lld",
				 i, v);
	}
	buf[len] = '\0';
	pr_warn("mxfs: P239-OWNAUTH-NONDURABLE-blft:%s\n", len ? buf : " none");
}

static void mxfs_authcap_report(void);

static void
mxfs_tokcls_report(void)
{
	char	buf[160];
	int	len = 0;
	int	i;

	for (i = 0; i < XFS_BLFT_MAX_BUF; i++) {
		long long v = atomic64_read(&mxfs_tokcls_blft[i]);

		if (!v || len >= (int)sizeof(buf) - 24)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " t%d=%lld",
				 i, v);
	}
	buf[len] = '\0';
	pr_warn("mxfs: P228-TOKCLASS n=%lld ag=%lld sb=%lld mislabel=%lld noepoch=%lld unknown=%lld incomplete=%lld mis_blft:%s\n",
		(long long)atomic64_read(&mxfs_tokcls_n),
		(long long)atomic64_read(&mxfs_tokcls_ag),
		(long long)atomic64_read(&mxfs_tokcls_sb),
		(long long)atomic64_read(&mxfs_tokcls_mislabel),
		(long long)atomic64_read(&mxfs_tokcls_noepoch),
		(long long)atomic64_read(&mxfs_tokcls_unknown),
		(long long)atomic64_read(&mxfs_tokcls_incomplete),
		len ? buf : " none");
	mxfs_ownauth_report();
	mxfs_authcap_report();
}

/*
 * ─── sess103 step 5.3, ruling P0/P1: CAPTURE AT FIRST PROTECTED DIRTY ───
 *
 * Runs the whole classification ladder ONCE, at the seam where the mutation
 * becomes attributable to a tenure, and writes the answer into the buf log
 * item.  xfs_buf_item_format_segment then only SERIALIZES it.
 *
 * Ladder (unchanged in substance from the format-time version it replaces —
 * only the instant it is evaluated at has changed, which is the entire fix):
 *   superblock            -> CLASS_SB, UNPROVEN (no grant epoch to name)
 *   AG-authorized + epoch -> CLASS_AG, VALID
 *   AG-authorized, no epoch -> UNPROVEN (we do not positively hold the grant)
 *   holds an AG grant that is not this buffer's authority -> MISLABELLED,
 *                            then resolved on the INODE arm
 *   neither               -> the inode-authority population, INODE arm
 *
 * The mount identity is captured here too: a record that cannot be bound to
 * an emitting incarnation is not evidence about any victim, so an identity
 * failure DOMINATES every classification above it.
 */
static void
mxfs_auth_classify(
	struct xfs_buf_log_item		*bip,
	struct xfs_mount		*mp,
	struct mxfs_bli_auth		*out)
{
	struct xfs_buf			*bp = bip->bli_buf;
	/*
	 * The BLFT lives in __bli_format for EVERY buffer — xfs_trans_buf_
	 * set_type writes only there, and format_segment copies it into each
	 * segment.  blf_blkno does NOT: for a discontiguous buffer the
	 * per-map array holds the real block numbers and __bli_format is left
	 * zeroed, so the AG must come from map 0 (which is also the only map
	 * whose header the owner derivation reads).
	 */
	struct xfs_buf_log_format	*blfp = &bip->__bli_format;
	xfs_daddr_t			blkno = bip->bli_formats[0].blf_blkno;
	xfs_agnumber_t			agno;
	uint16_t			blft = xfs_blft_from_flags(blfp);

	memset(out, 0, sizeof(*out));
	out->mba_class = MXFS_AUTH_CLASS_NONE;
	out->mba_status = MXFS_AUTH_ST_UNPROVEN;
	out->mba_blft = blft;
	out->mba_outcome = MXFS_OWNAUTH_MAX;	/* "inode arm not taken" */

	/*
	 * The BLFT is the second, independent witness both mxfs_buf_ag_
	 * authorized() and the owner derivation require.  If the type has not
	 * been set yet, no derivation this build trusts can succeed, and a
	 * capture that silently proceeds would manufacture OWNER_UNKNOWN for a
	 * perfectly ordinary buffer.  Count it and fail closed.
	 */
	if (blft <= XFS_BLFT_UNKNOWN_BUF || blft >= XFS_BLFT_MAX_BUF) {
		atomic64_inc(&mxfs_authcap_noblft);
		out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
		return;
	}

	atomic64_inc(&mxfs_tokcls_n);

	if (bp->b_ops == &xfs_sb_buf_ops) {
		out->mba_class = MXFS_AUTH_CLASS_SB;
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		atomic64_inc(&mxfs_tokcls_sb);
		goto identity;
	}

	agno = xfs_daddr_to_agno(mp, blkno);
	if (agno >= mp->m_sb.sb_agcount) {
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		atomic64_inc(&mxfs_tokcls_unknown);
		goto identity;
	}

	{
		struct xfs_perag	*apag = xfs_perag_get(mp, agno);
		uint64_t		ge;
		bool			auth;

		if (!apag) {
			out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
			atomic64_inc(&mxfs_tokcls_incomplete);
			goto identity;
		}
		ge = READ_ONCE(apag->pag_mxfs_grant_epoch);
		auth = mxfs_buf_ag_authorized(bp, blfp);

		if (auth && ge) {
			out->mba_class = MXFS_AUTH_CLASS_AG;
			out->mba_resource = agno;
			out->mba_epoch = ge;
			out->mba_status = MXFS_AUTH_ST_VALID;
			atomic64_inc(&mxfs_tokcls_ag);
		} else if (!auth && ge) {
			atomic64_inc(&mxfs_tokcls_mislabel);
			if (blft < XFS_BLFT_MAX_BUF)
				atomic64_inc(&mxfs_tokcls_blft[blft]);
			mxfs_ownauth_measure(bp, blfp, mp, out);
			if (out->mba_status != MXFS_AUTH_ST_VALID)
				out->mba_status = MXFS_AUTH_ST_MISLABELLED;
		} else if (auth) {
			out->mba_status = MXFS_AUTH_ST_UNPROVEN;
			atomic64_inc(&mxfs_tokcls_noepoch);
		} else {
			atomic64_inc(&mxfs_tokcls_unknown);
			mxfs_ownauth_measure(bp, blfp, mp, out);
		}
		xfs_perag_put(apag);
	}

identity:
	{
		uint32_t oslot = 0, onode = 0;
		uint64_t oepoch = 0;

		if (!mxfs_v5_dlm_mount_identity(mp->m_mxfs_dlm, &oslot, &onode,
						&oepoch)) {
			out->mba_class = MXFS_AUTH_CLASS_NONE;
			out->mba_resource = 0;
			out->mba_epoch = 0;
			out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
			atomic64_inc(&mxfs_tokcls_incomplete);
		}
	}
}

/*
 * Do two classifications describe the SAME authority?  Compared on the
 * proving fields only — the diagnostic ones (outcome, dlm_mode) are allowed
 * to differ between two instants without the proof being contradicted.
 */
static bool
mxfs_auth_same(
	const struct mxfs_bli_auth	*a,
	const struct mxfs_bli_auth	*b)
{
	return a->mba_class == b->mba_class &&
	       a->mba_status == b->mba_status &&
	       a->mba_resource == b->mba_resource &&
	       a->mba_epoch == b->mba_epoch &&
	       a->mba_owner_ino == b->mba_owner_ino &&
	       a->mba_auth_gen == b->mba_auth_gen;
}

/*
 * Capture the authority proof for `bp` in `tp`'s window.  Called from
 * xfs_trans_dirty_buf — the single seam every buffer passes through to become
 * dirty in a transaction, and the earliest point at which the mutation is
 * attributable to a tenure.
 *
 * Idempotent within a window: the FIRST capture is immutable.  A re-log in
 * the same window is re-resolved and compared, because the ruling requires
 * that "one buffer, two authorities" be DETECTED rather than silently
 * resolved to whichever tenure happened to be current last.
 */
void
mxfs_bli_auth_capture(
	struct xfs_trans	*tp,
	struct xfs_buf		*bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct mxfs_bli_auth	*cap;
	struct xfs_mount	*mp;
	uint64_t		seq;

	if (!bip || !tp)
		return;
	mp = bp->b_mount;
	if (!mp || !mxfs_buf_item_wants_authority(bip))
		return;

	/*
	 * A stale buffer logs nothing but the cancel record, and the formatter
	 * emits it untokenized.  Capturing for it would count a window that
	 * can never be serialized.
	 */
	if (bip->bli_flags & XFS_BLI_STALE)
		return;

	/*
	 * Window key.  Lazily assigned so no edit to the transaction alloc
	 * paths is needed; a transaction is owned by exactly one thread, so
	 * the read-modify-write needs no lock.  See t_mxfs_capseq.
	 */
	seq = tp->t_mxfs_capseq;
	if (!seq) {
		static atomic64_t next = ATOMIC64_INIT(0);

		seq = (uint64_t)atomic64_inc_return(&next);
		tp->t_mxfs_capseq = seq;
	}

	cap = &bip->bli_mxfs_auth;
	if (cap->mba_capseq == seq) {
		struct mxfs_bli_auth	now;

		atomic64_inc(&mxfs_authcap_relog);
		mxfs_auth_classify(bip, mp, &now);
		if (!mxfs_auth_same(cap, &now)) {
			/*
			 * Two provenances in one whole-buffer image.  A single
			 * token cannot represent it, and picking either one
			 * would be a fabricated proof — MIXED says so, and
			 * MIXED does not prove (mxfs_auth_st_proves).
			 */
			atomic64_inc(&mxfs_authcap_mismatch);
			cap->mba_status = MXFS_AUTH_ST_MIXED;
		}
		return;
	}

	{
		long long w = atomic64_inc_return(&mxfs_authcap_win);

		mxfs_auth_classify(bip, mp, cap);
		cap->mba_capseq = seq;
		/*
		 * Report from the CAPTURE path, not the format path: the
		 * sess102 trap note measured that the old (tn & 8191) trigger
		 * advanced only ONE node of 32 past a boundary across a whole
		 * 8-criterion dir-heavy chunk, so the sample was one node's,
		 * not the fleet's.  1023 gives 8x the resolution at the same
		 * cost per report.
		 */
		if ((w & 1023) == 0)
			mxfs_tokcls_report();
	}
}

static void
mxfs_authcap_report(void)
{
	char	buf[280];
	int	len = 0;
	int	i;

	for (i = 0; i < MXFS_OWNAUTH_MAX; i++) {
		long long v = atomic64_read(&mxfs_authcap_mode[i]);

		if (!v || len >= (int)sizeof(buf) - 28)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " %s=%lld",
				 mxfs_ownauth_name[i], v);
	}
	buf[len] = '\0';
	pr_warn("mxfs: P240-AUTHCAP win=%lld relog=%lld mismatch=%lld noblft=%lld blftchg=%lld nocap=%lld pw_by_outcome:%s\n",
		(long long)atomic64_read(&mxfs_authcap_win),
		(long long)atomic64_read(&mxfs_authcap_relog),
		(long long)atomic64_read(&mxfs_authcap_mismatch),
		(long long)atomic64_read(&mxfs_authcap_noblft),
		(long long)atomic64_read(&mxfs_authcap_blftchg),
		(long long)atomic64_read(&mxfs_authcap_nocap),
		len ? buf : " none");

	/*
	 * P241 — the same population, classified by the owner's last install
	 * ATTEMPT.  This is the line that names the missing event.
	 */
	len = 0;
	for (i = 0; i < MXFS_AUTH_TRY_MAX; i++) {
		long long v = atomic64_read(&mxfs_authtry_none[i]);

		if (!v || len >= (int)sizeof(buf) - 28)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " %s=%lld",
				 mxfs_authtry_name[i] ? mxfs_authtry_name[i] :
				 "?", v);
	}
	buf[len] = '\0';
	pr_warn("mxfs: P241-AUTHTRY nonewr_samegen=%lld nonewr_stalegen=%lld by_try:%s\n",
		(long long)atomic64_read(&mxfs_authtry_samegen),
		(long long)atomic64_read(&mxfs_authtry_stale),
		len ? buf : " none");
}

/*
 * Return the number of log iovecs and space needed to log the given buf log
 * item segment.
 *
 * It calculates this as 1 iovec for the buf log format structure and 1 for each
 * stretch of non-contiguous chunks to be logged.  Contiguous chunks are logged
 * in a single iovec.
 */
STATIC void
xfs_buf_item_size_segment(
	struct xfs_buf_log_item		*bip,
	struct xfs_buf_log_format	*blfp,
	uint				offset,
	int				*nvecs,
	int				*nbytes)
{
	int				first_bit;
	int				nbits;

	first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size, 0);
	if (first_bit == -1)
		return;

	(*nvecs)++;
	*nbytes += xfs_buf_log_format_size(blfp);
	/*
	 * sess48 authority token (step 3a): multi-node buf format regions
	 * carry a fixed-size trailer, MXFS_BLF_AUTHORITY_SIZE bytes — 40 as
	 * of the sess94 v2 wire (see mxfs_blf_authority_v2).  MUST mirror
	 * the emission condition in xfs_buf_item_format_segment exactly —
	 * an underestimate here overruns the CIL shadow buffer.  Stale
	 * items never reach this function (handled in xfs_buf_item_size)
	 * and are emitted untokenized.
	 */
	if (mxfs_buf_item_wants_authority(bip))
		*nbytes += MXFS_BLF_AUTHORITY_SIZE;

	do {
		nbits = xfs_contig_bits(blfp->blf_data_map,
					blfp->blf_map_size, first_bit);
		ASSERT(nbits > 0);
		(*nvecs)++;
		*nbytes += nbits * XFS_BLF_CHUNK;

		/*
		 * This takes the bit number to start looking from and
		 * returns the next set bit from there.  It returns -1
		 * if there are no more bits set or the start bit is
		 * beyond the end of the bitmap.
		 */
		first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size,
					(uint)first_bit + nbits + 1);
	} while (first_bit != -1);

	return;
}

/*
 * Compute the worst case log item overhead for an invalidated buffer with the
 * given map count and block size.
 */
unsigned int
xfs_buf_inval_log_space(
	unsigned int	map_count,
	unsigned int	blocksize)
{
	unsigned int	chunks = DIV_ROUND_UP(blocksize, XFS_BLF_CHUNK);
	unsigned int	bitmap_size = DIV_ROUND_UP(chunks, NBWORD);
	unsigned int	ret =
		offsetof(struct xfs_buf_log_format, blf_data_map) +
			(bitmap_size * sizeof_field(struct xfs_buf_log_format,
						    blf_data_map[0]));

	return ret * map_count;
}

/*
 * Return the number of log iovecs and space needed to log the given buf log
 * item.
 *
 * Discontiguous buffers need a format structure per region that is being
 * logged. This makes the changes in the buffer appear to log recovery as though
 * they came from separate buffers, just like would occur if multiple buffers
 * were used instead of a single discontiguous buffer. This enables
 * discontiguous buffers to be in-memory constructs, completely transparent to
 * what ends up on disk.
 *
 * If the XFS_BLI_STALE flag has been set, then log nothing but the buf log
 * format structures. If the item has previously been logged and has dirty
 * regions, we do not relog them in stale buffers. This has the effect of
 * reducing the size of the relogged item by the amount of dirty data tracked
 * by the log item. This can result in the committing transaction reducing the
 * amount of space being consumed by the CIL.
 */
STATIC void
xfs_buf_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	int			i;
	int			bytes;
	uint			offset = 0;

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	if (bip->bli_flags & XFS_BLI_STALE) {
		/*
		 * The buffer is stale, so all we need to log is the buf log
		 * format structure with the cancel flag in it as we are never
		 * going to replay the changes tracked in the log item.
		 */
		trace_xfs_buf_item_size_stale(bip);
		ASSERT(bip->__bli_format.blf_flags & XFS_BLF_CANCEL);
		*nvecs += bip->bli_format_count;
		for (i = 0; i < bip->bli_format_count; i++) {
			*nbytes += xfs_buf_log_format_size(&bip->bli_formats[i]);
		}
		return;
	}

	ASSERT(bip->bli_flags & XFS_BLI_LOGGED);

	if (bip->bli_flags & XFS_BLI_ORDERED) {
		/*
		 * The buffer has been logged just to order it. It is not being
		 * included in the transaction commit, so no vectors are used at
		 * all.
		 */
		trace_xfs_buf_item_size_ordered(bip);
		*nvecs = XFS_LOG_VEC_ORDERED;
		return;
	}

	/*
	 * The vector count is based on the number of buffer vectors we have
	 * dirty bits in. This will only be greater than one when we have a
	 * compound buffer with more than one segment dirty. Hence for compound
	 * buffers we need to track which segment the dirty bits correspond to,
	 * and when we move from one segment to the next increment the vector
	 * count for the extra buf log format structure that will need to be
	 * written.
	 */
	bytes = 0;
	for (i = 0; i < bip->bli_format_count; i++) {
		xfs_buf_item_size_segment(bip, &bip->bli_formats[i], offset,
					  nvecs, &bytes);
		offset += BBTOB(bp->b_maps[i].bm_len);
	}

	/*
	 * Round up the buffer size required to minimise the number of memory
	 * allocations that need to be done as this item grows when relogged by
	 * repeated modifications.
	 */
	*nbytes = round_up(bytes, 512);
	trace_xfs_buf_item_size(bip);
}

static inline void
xfs_buf_item_copy_iovec(
	struct xlog_format_buf	*lfb,
	struct xfs_buf		*bp,
	uint			offset,
	int			first_bit,
	uint			nbits)
{
	offset += first_bit * XFS_BLF_CHUNK;
	xlog_format_copy(lfb, XLOG_REG_TYPE_BCHUNK, xfs_buf_offset(bp, offset),
			nbits * XFS_BLF_CHUNK);
}

static void
xfs_buf_item_format_segment(
	struct xfs_buf_log_item	*bip,
	struct xlog_format_buf	*lfb,
	uint			offset,
	struct xfs_buf_log_format *blfp)
{
	struct xfs_buf		*bp = bip->bli_buf;
	uint			base_size;
	int			first_bit;
	uint			nbits;

	/* copy the flags across from the base format item */
	blfp->blf_flags = bip->__bli_format.blf_flags;

	/*
	 * Base size is the actual size of the ondisk structure - it reflects
	 * the actual size of the dirty bitmap rather than the size of the in
	 * memory structure.
	 */
	base_size = xfs_buf_log_format_size(blfp);

	first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size, 0);
	if (!(bip->bli_flags & XFS_BLI_STALE) && first_bit == -1) {
		/*
		 * If the map is not be dirty in the transaction, mark
		 * the size as zero and do not advance the vector pointer.
		 */
		return;
	}

	if (!(bip->bli_flags & XFS_BLI_STALE) &&
	    mxfs_buf_item_wants_authority(bip)) {
		/*
		 * sess48 authority token (step 3a): emit the format struct
		 * with the mxfs_blf_authority trailer appended in the SAME
		 * region (a separate iovec would shift the chunk indexing
		 * recovery walks by blf_size).  Build the pair in a local
		 * buffer; the returned pointer into the emitted copy keeps
		 * the blf_size++ mutations below working.  Size side already
		 * reserved the extra bytes (xfs_buf_item_size_segment) — the
		 * conditions MUST match.
		 *
		 * sess103, ruling item (b) / sess102 P0+P1 — DONE.  Token
		 * content is NO LONGER resolved here.  It is captured at the
		 * first protected dirtying (mxfs_bli_auth_capture, called
		 * from xfs_trans_dirty_buf) and this site only SERIALIZES it,
		 * because a format-time lookup can only ever report the grant
		 * installed when the CIL ran, not the grant that authorized
		 * the mutation.  See struct mxfs_bli_auth for the full
		 * argument and the invariants.
		 *
		 * sess94 step 5.2: the wire is v2.
		 */
		struct {
			char blf[sizeof(struct xfs_buf_log_format)];
			struct mxfs_blf_authority_v2 tok;
		} lbuf;
		struct mxfs_blf_authority_v2 *tok;
		struct xfs_mount *mp = bp->b_mount;
		const struct mxfs_bli_auth *cap = &bip->bli_mxfs_auth;
		uint32_t oslot = 0, onode = 0;
		uint64_t oepoch = 0, res, gepoch;
		uint16_t cls;
		uint8_t  st;
		bool ident;

		BUILD_BUG_ON(sizeof(lbuf.blf) < sizeof(*blfp));
		memcpy(lbuf.blf, blfp, base_size);
		((struct xfs_buf_log_format *)lbuf.blf)->blf_flags |=
						XFS_BLF_MXFS_AUTHORITY;
		tok = (struct mxfs_blf_authority_v2 *)(lbuf.blf + base_size);
		memset(tok, 0, sizeof(*tok));
		{
			/*
			 * SERIALIZE ONLY.  Three things can still invalidate a
			 * capture between the dirty and here, and each of them
			 * must void the proof rather than be papered over:
			 *
			 *  1. no capture at all — a dirty path that bypasses
			 *     xfs_trans_dirty_buf.  Must not happen; counted so
			 *     the claim is measured rather than assumed.
			 *  2. the BLFT changed after capture, so the capture
			 *     described a different image kind than the one
			 *     being emitted.
			 *  3. the emitting mount identity is unavailable — an
			 *     image that cannot be bound to an incarnation is
			 *     not evidence about any victim, so this DOMINATES
			 *     whatever the capture concluded.
			 */
			cls = cap->mba_class;
			st = cap->mba_status;
			res = cap->mba_resource;
			gepoch = cap->mba_epoch;

			if (!cap->mba_capseq) {
				atomic64_inc(&mxfs_authcap_nocap);
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
			} else if (cap->mba_blft !=
				   xfs_blft_from_flags(&bip->__bli_format)) {
				atomic64_inc(&mxfs_authcap_blftchg);
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
			}

			ident = mxfs_v5_dlm_mount_identity(mp->m_mxfs_dlm,
						&oslot, &onode, &oepoch);
			if (!ident) {
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				oslot = 0;
				onode = 0;
				oepoch = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
				atomic64_inc(&mxfs_tokcls_incomplete);
			}
		}
		tok->mba_version = cpu_to_be16(MXFS_BLF_AUTHORITY_V2);
		tok->mba_class = cpu_to_be16(cls);
		/* reserved bits (8-31) stay zero — a parser rejects them */
		tok->mba_flags =
			cpu_to_be32((uint32_t)st & MXFS_AUTH_FLAG_STATUS_MASK);
		tok->mba_resource = cpu_to_be64(res);
		tok->mba_grant_epoch = cpu_to_be64(gepoch);
		tok->mba_owner_epoch = cpu_to_be64(oepoch);
		tok->mba_owner_slot = cpu_to_be32(oslot);
		tok->mba_owner_node = cpu_to_be32(onode);

		blfp = xlog_format_copy(lfb, XLOG_REG_TYPE_BFORMAT, &lbuf,
					base_size +
					(uint)MXFS_BLF_AUTHORITY_SIZE);
		blfp->blf_size = 1;
	} else {
		blfp = xlog_format_copy(lfb, XLOG_REG_TYPE_BFORMAT, blfp,
					base_size);
		blfp->blf_size = 1;
	}

	if (bip->bli_flags & XFS_BLI_STALE) {
		/*
		 * The buffer is stale, so all we need to log
		 * is the buf log format structure with the
		 * cancel flag in it.
		 */
		trace_xfs_buf_item_format_stale(bip);
		ASSERT(blfp->blf_flags & XFS_BLF_CANCEL);
		return;
	}


	/*
	 * Fill in an iovec for each set of contiguous chunks.
	 */
	do {
		ASSERT(first_bit >= 0);
		nbits = xfs_contig_bits(blfp->blf_data_map,
					blfp->blf_map_size, first_bit);
		ASSERT(nbits > 0);
		xfs_buf_item_copy_iovec(lfb, bp, offset, first_bit, nbits);
		blfp->blf_size++;

		/*
		 * This takes the bit number to start looking from and
		 * returns the next set bit from there.  It returns -1
		 * if there are no more bits set or the start bit is
		 * beyond the end of the bitmap.
		 */
		first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size,
					(uint)first_bit + nbits + 1);
	} while (first_bit != -1);

	return;
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given log buf item.  It fills the first entry with a buf log
 * format structure, and the rest point to contiguous chunks
 * within the buffer.
 */
STATIC void
xfs_buf_item_format(
	struct xfs_log_item	*lip,
	struct xlog_format_buf	*lfb)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	uint			offset = 0;
	int			i;

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	ASSERT((bip->bli_flags & XFS_BLI_LOGGED) ||
	       (bip->bli_flags & XFS_BLI_STALE));
	ASSERT((bip->bli_flags & XFS_BLI_STALE) ||
	       (xfs_blft_from_flags(&bip->__bli_format) > XFS_BLFT_UNKNOWN_BUF
	        && xfs_blft_from_flags(&bip->__bli_format) < XFS_BLFT_MAX_BUF));
	ASSERT(!(bip->bli_flags & XFS_BLI_ORDERED) ||
	       (bip->bli_flags & XFS_BLI_STALE));


	/*
	 * If it is an inode buffer, transfer the in-memory state to the
	 * format flags and clear the in-memory state.
	 *
	 * For buffer based inode allocation, we do not transfer
	 * this state if the inode buffer allocation has not yet been committed
	 * to the log as setting the XFS_BLI_INODE_BUF flag will prevent
	 * correct replay of the inode allocation.
	 *
	 * For icreate item based inode allocation, the buffers aren't written
	 * to the journal during allocation, and hence we should always tag the
	 * buffer as an inode buffer so that the correct unlinked list replay
	 * occurs during recovery.
	 */
	if (bip->bli_flags & XFS_BLI_INODE_BUF) {
		if (xfs_has_v3inodes(lip->li_log->l_mp) ||
		    !((bip->bli_flags & XFS_BLI_INODE_ALLOC_BUF) &&
		      xfs_log_item_in_current_chkpt(lip)))
			bip->__bli_format.blf_flags |= XFS_BLF_INODE_BUF;
		bip->bli_flags &= ~XFS_BLI_INODE_BUF;
	}

	for (i = 0; i < bip->bli_format_count; i++) {
		xfs_buf_item_format_segment(bip, lfb, offset,
					    &bip->bli_formats[i]);
		offset += BBTOB(bp->b_maps[i].bm_len);
	}

	/*
	 * Check to make sure everything is consistent.
	 */
	trace_xfs_buf_item_format(bip);
}

/*
 * This is called to pin the buffer associated with the buf log item in memory
 * so it cannot be written out.
 *
 * We take a reference to the buffer log item here so that the BLI life cycle
 * extends at least until the buffer is unpinned via xfs_buf_item_unpin() and
 * inserted into the AIL.
 *
 * We also need to take a reference to the buffer itself as the BLI unpin
 * processing requires accessing the buffer after the BLI has dropped the final
 * BLI reference. See xfs_buf_item_unpin() for an explanation.
 * If unpins race to drop the final BLI reference and only the
 * BLI owns a reference to the buffer, then the loser of the race can have the
 * buffer fgreed from under it (e.g. on shutdown). Taking a buffer reference per
 * pin count ensures the life cycle of the buffer extends for as
 * long as we hold the buffer pin reference in xfs_buf_item_unpin().
 */
STATIC void
xfs_buf_item_pin(
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	ASSERT((bip->bli_flags & XFS_BLI_LOGGED) ||
	       (bip->bli_flags & XFS_BLI_ORDERED) ||
	       (bip->bli_flags & XFS_BLI_STALE));

	trace_xfs_buf_item_pin(bip);

	xfs_buf_hold(bip->bli_buf);
	atomic_inc(&bip->bli_refcount);
	atomic_inc(&bip->bli_buf->b_pin_count);
}

/*
 * For a stale BLI, process all the necessary completions that must be
 * performed when the final BLI reference goes away. The buffer will be
 * referenced and locked here - we return to the caller with the buffer still
 * referenced and locked for them to finalise processing of the buffer.
 */
static void
xfs_buf_item_finish_stale(
	struct xfs_buf_log_item	*bip)
{
	struct xfs_buf		*bp = bip->bli_buf;
	struct xfs_log_item	*lip = &bip->bli_item;

	ASSERT(bip->bli_flags & XFS_BLI_STALE);
	ASSERT(xfs_buf_islocked(bp));
	ASSERT(bp->b_flags & XBF_STALE);
	ASSERT(bip->__bli_format.blf_flags & XFS_BLF_CANCEL);
	ASSERT(list_empty(&lip->li_trans));
	ASSERT(!bp->b_transp);

	if (bip->bli_flags & XFS_BLI_STALE_INODE) {
		xfs_buf_item_done(bp);
		xfs_buf_inode_iodone(bp);
		ASSERT(list_empty(&bp->b_li_list));
		return;
	}

	/*
	 * We may or may not be on the AIL here, xfs_trans_ail_delete() will do
	 * the right thing regardless of the situation in which we are called.
	 */
	xfs_trans_ail_delete(lip, SHUTDOWN_LOG_IO_ERROR);
	xfs_buf_item_relse(bip);
	ASSERT(bp->b_log_item == NULL);
}

/*
 * This is called to unpin the buffer associated with the buf log item which was
 * previously pinned with a call to xfs_buf_item_pin().  We enter this function
 * with a buffer pin count, a buffer reference and a BLI reference.
 *
 * We must drop the BLI reference before we unpin the buffer because the AIL
 * doesn't acquire a BLI reference whenever it accesses it. Therefore if the
 * refcount drops to zero, the bli could still be AIL resident and the buffer
 * submitted for I/O at any point before we return. This can result in IO
 * completion freeing the buffer while we are still trying to access it here.
 * This race condition can also occur in shutdown situations where we abort and
 * unpin buffers from contexts other that journal IO completion.
 *
 * Hence we have to hold a buffer reference per pin count to ensure that the
 * buffer cannot be freed until we have finished processing the unpin operation.
 * The reference is taken in xfs_buf_item_pin(), and we must hold it until we
 * are done processing the buffer state. In the case of an abort (remove =
 * true) then we re-use the current pin reference as the IO reference we hand
 * off to IO failure handling.
 */
STATIC void
xfs_buf_item_unpin(
	struct xfs_log_item	*lip,
	int			remove)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	int			stale = bip->bli_flags & XFS_BLI_STALE;
	int			freed;

	ASSERT(bp->b_log_item == bip);
	ASSERT(atomic_read(&bip->bli_refcount) > 0);

	trace_xfs_buf_item_unpin(bip);

	freed = atomic_dec_and_test(&bip->bli_refcount);
	if (atomic_dec_and_test(&bp->b_pin_count))
		wake_up_all(&bp->b_waiters);

	/*
	 * Nothing to do but drop the buffer pin reference if the BLI is
	 * still active.
	 */
	if (!freed) {
		xfs_buf_rele(bp);
		return;
	}

	if (stale) {
		trace_xfs_buf_item_unpin_stale(bip);

		/*
		 * The buffer has been locked and referenced since it was marked
		 * stale so we own both lock and reference exclusively here. We
		 * do not need the pin reference any more, so drop it now so
		 * that we only have one reference to drop once item completion
		 * processing is complete.
		 */
		xfs_buf_rele(bp);
		xfs_buf_item_finish_stale(bip);
		xfs_buf_relse(bp);
		return;
	}

	if (remove) {
		/*
		 * We need to simulate an async IO failures here to ensure that
		 * the correct error completion is run on this buffer. This
		 * requires a reference to the buffer and for the buffer to be
		 * locked. We can safely pass ownership of the pin reference to
		 * the IO to ensure that nothing can free the buffer while we
		 * wait for the lock and then run the IO failure completion.
		 */
		xfs_buf_lock(bp);
		bp->b_flags |= XBF_ASYNC;
		xfs_buf_ioend_fail(bp);
		return;
	}

	/*
	 * BLI has no more active references - it will be moved to the AIL to
	 * manage the remaining BLI/buffer life cycle. There is nothing left for
	 * us to do here so drop the pin reference to the buffer.
	 */
	xfs_buf_rele(bp);
}

STATIC uint
xfs_buf_item_push(
	struct xfs_log_item	*lip,
	struct list_head	*buffer_list)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	uint			rval = XFS_ITEM_SUCCESS;

	if (xfs_buf_ispinned(bp))
		return XFS_ITEM_PINNED;
	if (!xfs_buf_trylock(bp)) {
		/*
		 * If we have just raced with a buffer being pinned and it has
		 * been marked stale, we could end up stalling until someone else
		 * issues a log force to unpin the stale buffer. Check for the
		 * race condition here so xfsaild recognizes the buffer is pinned
		 * and queues a log force to move it along.
		 */
		if (xfs_buf_ispinned(bp))
			return XFS_ITEM_PINNED;
		return XFS_ITEM_LOCKED;
	}

	ASSERT(!(bip->bli_flags & XFS_BLI_STALE));

	/*
	 * sess23 (ccloop 4eef1f39): xfsaild AG-meta writeback interlock.  If
	 * this is an AG-allocation-metadata buffer for an AG we do NOT currently
	 * hold (a peer owns it), our cached image is a stale prior-tenure log-
	 * tail artifact; writing it would revert the peer's durable free-space
	 * btree change (the held=1 P93/P124 clobber, whose push is decided HERE
	 * while held=0 even though xfs_buf_submit later samples held=1) and
	 * poison our own allocator into an `ltbno+ltlen>bno` in-core double-free.
	 * Invariant #1 made every legitimate this-node AG-meta change durable
	 * before release, so the BLI carries nothing we still need.  Stale it
	 * (removes the BLI from the AIL with no I/O) and report SUCCESS so
	 * xfsaild advances the log tail and the peer's allocation stands.  When
	 * we DO hold the AG the predicate is false and the normal write below
	 * runs (so single-node / uncontended mounts are unaffected).
	 */
	if (mxfs_buf_xfsaild_skip_agmeta_write(bp)) {
		pr_warn_ratelimited("mxfs: P126-XFSAILD-SKIP-AGMETA agno=%u daddr=%lld ops=%s in_ail=%d dirty=%d pin=%d — not held in-core; staling stale prior-tenure AG-meta instead of reverting peer\n",
			bp->b_pag ? pag_agno(bp->b_pag) : (unsigned)-1,
			(long long)bp->b_maps[0].bm_bn,
			(bp->b_ops == &xfs_bnobt_buf_ops) ? "bnobt" :
			(bp->b_ops == &xfs_cntbt_buf_ops) ? "cntbt" :
			(bp->b_ops == &xfs_agf_buf_ops)   ? "agf"   :
			(bp->b_ops == &xfs_agfl_buf_ops)  ? "agfl"  :
			(bp->b_ops == &xfs_agi_buf_ops)   ? "agi"   :
			(bp->b_ops == &xfs_inobt_buf_ops) ? "inobt" :
			(bp->b_ops == &xfs_finobt_buf_ops)? "finobt": "?",
			test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags) ? 1 : 0,
			(bip->bli_flags & XFS_BLI_DIRTY) ? 1 : 0,
			xfs_buf_ispinned(bp) ? 1 : 0);
		xfs_buf_stale(bp);
		xfs_buf_unlock(bp);
		return XFS_ITEM_SUCCESS;
	}

	/*
	 * sess60 (RULE 4, zero_silent_loss residual): the bmbt analogue of the
	 * AG-meta interlock above.  A bmbt extent-map block whose owner dir we
	 * have released (i_dlm_mode==NL) must NOT be written from our lingering
	 * prior-tenure BLI — that reverts a peer's newer leaf records and is the
	 * proven `ir.loaded != if_nextents` (loaded < if_nextents) leaf-lag.
	 * Invariant #1 made our legitimate bmbt changes durable before NL, so
	 * the BLI here carries only a superseded image; stale it (drop from AIL,
	 * no I/O) so the peer's leaf stands.  Scoped to in-core released dirs
	 * only — files and held dirs fall through to the normal write.
	 */
	if (mxfs_buf_xfsaild_skip_bmbt_write(bp)) {
		pr_warn_ratelimited("mxfs: P60-XFSAILD-SKIP-BMBT owner=%llu daddr=%lld in_ail=%d dirty=%d pin=%d — released dir, staling stale prior-tenure bmbt leaf instead of reverting peer\n",
			(unsigned long long)be64_to_cpu(((struct xfs_btree_block *)bp->b_addr)->bb_u.l.bb_owner),
			(long long)bp->b_maps[0].bm_bn,
			test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags) ? 1 : 0,
			(bip->bli_flags & XFS_BLI_DIRTY) ? 1 : 0,
			xfs_buf_ispinned(bp) ? 1 : 0);
		xfs_buf_stale(bp);
		xfs_buf_unlock(bp);
		return XFS_ITEM_SUCCESS;
	}

	/*
	 * sess25 (ccloop 4cb2d0a2): DEFER a background xfsaild destage of a
	 * multi-node dir DATA/LEAF block while we hold the owner dir's EX and a
	 * peer BAST is pending (contended).  Keep the BLI in the AIL with NO I/O
	 * (return XFS_ITEM_LOCKED) so the block's on-disk image changes ONLY via
	 * the synchronous release-drain (Invariant #1) — never via a background
	 * write that could clobber a peer's dirent (the dir_reuse_coherency
	 * readdir=799 root, PROVEN sess25 dataclobber=1 detect run).  Self-clears
	 * the instant we release EX (mode->NL), so no permanent AIL stall; an
	 * uncontended hold (no BAST) falls through and destages normally.
	 */
	if (mxfs_dir_ail_push_defer(bp)) {
		xfs_buf_unlock(bp);
		return XFS_ITEM_LOCKED;
	}

	/*
	 * sess33 (ccloop 4cb2d0a2, GPT-5.5 consult #2, PROVEN root): LAST-LINE
	 * guard for the dir_reuse readdir=799 durable dirent loss.  A
	 * coherency-invalidated (XBF_DONE clear), clean, DESTAGED, in-AIL dir
	 * DATA buffer is a "zombie": its content is on disk (destaged) but stale
	 * (a peer superseded it during our NL window), and re-flushing it reverts
	 * the peer's durable add.  Stale it (drops the BLI from the AIL with NO
	 * I/O — same proven pattern as P126/P60 above) and report SUCCESS so
	 * xfsaild advances the log tail (no starvation).  Loss-safe: a legit
	 * write is DONE=1 or undestaged and never matches (see predicate).
	 */
	if (mxfs_dir_zombie_push_retire(bp)) {
		pr_warn_ratelimited("mxfs: P33-PUSH-RETIRE daddr=%lld in_ail=%d dirty=%d pin=%d — staling DONE=0 destaged zombie dir buffer instead of reflushing stale over peer add\n",
			(long long)bp->b_maps[0].bm_bn,
			test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags) ? 1 : 0,
			(bip->bli_flags & XFS_BLI_DIRTY) ? 1 : 0,
			xfs_buf_ispinned(bp) ? 1 : 0);
		xfs_buf_stale(bp);
		xfs_buf_unlock(bp);
		return XFS_ITEM_SUCCESS;
	}

	trace_xfs_buf_item_push(bip);

	/* has a previous flush failed due to IO errors? */
	if (bp->b_flags & XBF_WRITE_FAIL) {
		xfs_buf_alert_ratelimited(bp, "XFS: Failing async write",
	    "Failing async write on buffer block 0x%llx. Retrying async write.",
					  (long long)xfs_buf_daddr(bp));
	}

	if (!xfs_buf_delwri_queue(bp, buffer_list))
		rval = XFS_ITEM_FLUSHING;
	xfs_buf_unlock(bp);
	return rval;
}

/*
 * Drop the buffer log item refcount and take appropriate action. This helper
 * determines whether the bli must be freed or not, since a decrement to zero
 * does not necessarily mean the bli is unused.
 */
void
xfs_buf_item_put(
	struct xfs_buf_log_item	*bip)
{

	ASSERT(xfs_buf_islocked(bip->bli_buf));

	/* drop the bli ref and return if it wasn't the last one */
	if (!atomic_dec_and_test(&bip->bli_refcount))
		return;

	/* If the BLI is in the AIL, then it is still dirty and in use */
	if (test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) {
		ASSERT(bip->bli_flags & XFS_BLI_DIRTY);
		return;
	}

	/*
	 * In shutdown conditions, we can be asked to free a dirty BLI that
	 * isn't in the AIL. This can occur due to a checkpoint aborting a BLI
	 * instead of inserting it into the AIL at checkpoint IO completion. If
	 * there's another bli reference (e.g. a btree cursor holds a clean
	 * reference) and it is released via xfs_trans_brelse(), we can get here
	 * with that aborted, dirty BLI. In this case, it is safe to free the
	 * dirty BLI immediately, as it is not in the AIL and there are no
	 * other references to it.
	 *
	 * We should never get here with a stale BLI via that path as
	 * xfs_trans_brelse() specifically holds onto stale buffers rather than
	 * releasing them.
	 */
	ASSERT(!(bip->bli_flags & XFS_BLI_DIRTY) ||
			test_bit(XFS_LI_ABORTED, &bip->bli_item.li_flags));
	ASSERT(!(bip->bli_flags & XFS_BLI_STALE));
	xfs_buf_item_relse(bip);
}

/*
 * Release the buffer associated with the buf log item.  If there is no dirty
 * logged data associated with the buffer recorded in the buf log item, then
 * free the buf log item and remove the reference to it in the buffer.
 *
 * This call ignores the recursion count.  It is only called when the buffer
 * should REALLY be unlocked, regardless of the recursion count.
 *
 * We unconditionally drop the transaction's reference to the log item. If the
 * item was logged, then another reference was taken when it was pinned, so we
 * can safely drop the transaction reference now.  This also allows us to avoid
 * potential races with the unpin code freeing the bli by not referencing the
 * bli after we've dropped the reference count.
 *
 * If the XFS_BLI_HOLD flag is set in the buf log item, then free the log item
 * if necessary but do not unlock the buffer.  This is for support of
 * xfs_trans_bhold(). Make sure the XFS_BLI_HOLD field is cleared if we don't
 * free the item.
 *
 * If the XFS_BLI_STALE flag is set, the last reference to the BLI *must*
 * perform a completion abort of any objects attached to the buffer for IO
 * tracking purposes. This generally only happens in shutdown situations,
 * normally xfs_buf_item_unpin() will drop the last BLI reference and perform
 * completion processing. However, because transaction completion can race with
 * checkpoint completion during a shutdown, this release context may end up
 * being the last active reference to the BLI and so needs to perform this
 * cleanup.
 */
STATIC void
xfs_buf_item_release(
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	bool			hold = bip->bli_flags & XFS_BLI_HOLD;
	bool			stale = bip->bli_flags & XFS_BLI_STALE;
	bool			aborted = test_bit(XFS_LI_ABORTED,
						   &lip->li_flags);
	bool			dirty = bip->bli_flags & XFS_BLI_DIRTY;
#if defined(DEBUG) || defined(XFS_WARN)
	bool			ordered = bip->bli_flags & XFS_BLI_ORDERED;
#endif

	trace_xfs_buf_item_release(bip);

	ASSERT(xfs_buf_islocked(bp));

	/*
	 * The bli dirty state should match whether the blf has logged segments
	 * except for ordered buffers, where only the bli should be dirty.
	 */
	ASSERT((!ordered && dirty == xfs_buf_item_dirty_format(bip)) ||
	       (ordered && dirty && !xfs_buf_item_dirty_format(bip)));
	ASSERT(!stale || (bip->__bli_format.blf_flags & XFS_BLF_CANCEL));

	/*
	 * Clear the buffer's association with this transaction and
	 * per-transaction state from the bli, which has been copied above.
	 */
	bp->b_transp = NULL;
	bip->bli_flags &= ~(XFS_BLI_LOGGED | XFS_BLI_HOLD | XFS_BLI_ORDERED);

	/* If there are other references, then we have nothing to do. */
	if (!atomic_dec_and_test(&bip->bli_refcount))
		goto out_release;

	/*
	 * Stale buffer completion frees the BLI, unlocks and releases the
	 * buffer. Neither the BLI or buffer are safe to reference after this
	 * call, so there's nothing more we need to do here.
	 *
	 * If we get here with a stale buffer and references to the BLI remain,
	 * we must not unlock the buffer as the last BLI reference owns lock
	 * context, not us.
	 */
	if (stale) {
		xfs_buf_item_finish_stale(bip);
		xfs_buf_relse(bp);
		ASSERT(!hold);
		return;
	}

	/*
	 * Dirty or clean, aborted items are done and need to be removed from
	 * the AIL and released. This frees the BLI, but leaves the buffer
	 * locked and referenced.
	 */
	if (aborted || xlog_is_shutdown(lip->li_log)) {
		ASSERT(list_empty(&bip->bli_buf->b_li_list));
		/*
		 * sess-pve: this bli detaches WITHOUT writeback (xfs_buf_item_done
		 * runs no ioend, so bp->b_iodone never fires) — reclaim any
		 * outstanding mxfs_ag_meta_track hold here or it leaks and wedges
		 * xfs_buftarg_drain at unmount (agi/inobt/finobt stuck at b_hold=2).
		 */
		mxfs_ag_meta_reclaim_abort(bp);
		xfs_buf_item_done(bp);
		goto out_release;
	}

	/*
	 * Clean, unreferenced BLIs can be immediately freed, leaving the buffer
	 * locked and referenced.
	 *
	 * Dirty, unreferenced BLIs *must* be in the AIL awaiting writeback.
	 */
	if (!dirty)
		xfs_buf_item_relse(bip);
	else
		ASSERT(test_bit(XFS_LI_IN_AIL, &lip->li_flags));

	/* Not safe to reference the BLI from here */
out_release:
	/*
	 * If we get here with a stale buffer, we must not unlock the
	 * buffer as the last BLI reference owns lock context, not us.
	 */
	if (stale || hold)
		return;
	xfs_buf_relse(bp);
}

STATIC void
xfs_buf_item_committing(
	struct xfs_log_item	*lip,
	xfs_csn_t		seq)
{
	return xfs_buf_item_release(lip);
}

/*
 * This is called to find out where the oldest active copy of the
 * buf log item in the on disk log resides now that the last log
 * write of it completed at the given lsn.
 * We always re-log all the dirty data in a buffer, so usually the
 * latest copy in the on disk log is the only one that matters.  For
 * those cases we simply return the given lsn.
 *
 * The one exception to this is for buffers full of newly allocated
 * inodes.  These buffers are only relogged with the XFS_BLI_INODE_BUF
 * flag set, indicating that only the di_next_unlinked fields from the
 * inodes in the buffers will be replayed during recovery.  If the
 * original newly allocated inode images have not yet been flushed
 * when the buffer is so relogged, then we need to make sure that we
 * keep the old images in the 'active' portion of the log.  We do this
 * by returning the original lsn of that transaction here rather than
 * the current one.
 */
STATIC xfs_lsn_t
xfs_buf_item_committed(
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);

	trace_xfs_buf_item_committed(bip);

	if ((bip->bli_flags & XFS_BLI_INODE_ALLOC_BUF) && lip->li_lsn != 0)
		return lip->li_lsn;
	return lsn;
}

#ifdef DEBUG_EXPENSIVE
static int
xfs_buf_item_precommit(
	struct xfs_trans	*tp,
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	struct xfs_mount	*mp = bp->b_mount;
	xfs_failaddr_t		fa;

	if (!bp->b_ops || !bp->b_ops->verify_struct)
		return 0;
	if (bip->bli_flags & XFS_BLI_STALE)
		return 0;

	fa = bp->b_ops->verify_struct(bp);
	if (fa) {
		xfs_buf_verifier_error(bp, -EFSCORRUPTED, bp->b_ops->name,
				bp->b_addr, BBTOB(bp->b_length), fa);
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		ASSERT(fa == NULL);
	}

	return 0;
}
#else
# define xfs_buf_item_precommit	NULL
#endif

static const struct xfs_item_ops xfs_buf_item_ops = {
	.iop_size	= xfs_buf_item_size,
	.iop_precommit	= xfs_buf_item_precommit,
	.iop_format	= xfs_buf_item_format,
	.iop_pin	= xfs_buf_item_pin,
	.iop_unpin	= xfs_buf_item_unpin,
	.iop_release	= xfs_buf_item_release,
	.iop_committing	= xfs_buf_item_committing,
	.iop_committed	= xfs_buf_item_committed,
	.iop_push	= xfs_buf_item_push,
};

/*
 * Allocate a new buf log item to go with the given buffer.
 * Set the buffer's b_log_item field to point to the new
 * buf log item.
 */
int
xfs_buf_item_init(
	struct xfs_buf	*bp,
	struct xfs_mount *mp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	int			chunks;
	int			map_size;
	int			i;

	/*
	 * Check to see if there is already a buf log item for
	 * this buffer. If we do already have one, there is
	 * nothing to do here so return.
	 */
	ASSERT(bp->b_mount == mp);
	if (bip) {
		ASSERT(bip->bli_item.li_type == XFS_LI_BUF);
		ASSERT(!bp->b_transp);
		ASSERT(bip->bli_buf == bp);
		return 0;
	}

	bip = kmem_cache_zalloc(xfs_buf_item_cache, GFP_KERNEL | __GFP_NOFAIL);
	xfs_log_item_init(mp, &bip->bli_item, XFS_LI_BUF, &xfs_buf_item_ops);
	bip->bli_buf = bp;

	/*
	 * chunks is the number of XFS_BLF_CHUNK size pieces the buffer
	 * can be divided into. Make sure not to truncate any pieces.
	 * map_size is the size of the bitmap needed to describe the
	 * chunks of the buffer.
	 *
	 * Discontiguous buffer support follows the layout of the underlying
	 * buffer. This makes the implementation as simple as possible.
	 */
	xfs_buf_item_get_format(bip, bp->b_map_count);

	for (i = 0; i < bip->bli_format_count; i++) {
		chunks = DIV_ROUND_UP(BBTOB(bp->b_maps[i].bm_len),
				      XFS_BLF_CHUNK);
		map_size = DIV_ROUND_UP(chunks, NBWORD);

		if (map_size > XFS_BLF_DATAMAP_SIZE) {
			xfs_buf_item_free_format(bip);
			kmem_cache_free(xfs_buf_item_cache, bip);
			xfs_err(mp,
	"buffer item dirty bitmap (%u uints) too small to reflect %u bytes!",
					map_size,
					BBTOB(bp->b_maps[i].bm_len));
			return -EFSCORRUPTED;
		}

		bip->bli_formats[i].blf_type = XFS_LI_BUF;
		bip->bli_formats[i].blf_blkno = bp->b_maps[i].bm_bn;
		bip->bli_formats[i].blf_len = bp->b_maps[i].bm_len;
		bip->bli_formats[i].blf_map_size = map_size;
	}

	bp->b_log_item = bip;
	xfs_buf_hold(bp);
	return 0;
}


/*
 * Mark bytes first through last inclusive as dirty in the buf
 * item's bitmap.
 */
static void
xfs_buf_item_log_segment(
	uint			first,
	uint			last,
	uint			*map)
{
	uint		first_bit;
	uint		last_bit;
	uint		bits_to_set;
	uint		bits_set;
	uint		word_num;
	uint		*wordp;
	uint		bit;
	uint		end_bit;
	uint		mask;

	ASSERT(first < XFS_BLF_DATAMAP_SIZE * XFS_BLF_CHUNK * NBWORD);
	ASSERT(last < XFS_BLF_DATAMAP_SIZE * XFS_BLF_CHUNK * NBWORD);

	/*
	 * Convert byte offsets to bit numbers.
	 */
	first_bit = first >> XFS_BLF_SHIFT;
	last_bit = last >> XFS_BLF_SHIFT;

	/*
	 * Calculate the total number of bits to be set.
	 */
	bits_to_set = last_bit - first_bit + 1;

	/*
	 * Get a pointer to the first word in the bitmap
	 * to set a bit in.
	 */
	word_num = first_bit >> BIT_TO_WORD_SHIFT;
	wordp = &map[word_num];

	/*
	 * Calculate the starting bit in the first word.
	 */
	bit = first_bit & (uint)(NBWORD - 1);

	/*
	 * First set any bits in the first word of our range.
	 * If it starts at bit 0 of the word, it will be
	 * set below rather than here.  That is what the variable
	 * bit tells us. The variable bits_set tracks the number
	 * of bits that have been set so far.  End_bit is the number
	 * of the last bit to be set in this word plus one.
	 */
	if (bit) {
		end_bit = min(bit + bits_to_set, (uint)NBWORD);
		mask = ((1U << (end_bit - bit)) - 1) << bit;
		*wordp |= mask;
		wordp++;
		bits_set = end_bit - bit;
	} else {
		bits_set = 0;
	}

	/*
	 * Now set bits a whole word at a time that are between
	 * first_bit and last_bit.
	 */
	while ((bits_to_set - bits_set) >= NBWORD) {
		*wordp = 0xffffffff;
		bits_set += NBWORD;
		wordp++;
	}

	/*
	 * Finally, set any bits left to be set in one last partial word.
	 */
	end_bit = bits_to_set - bits_set;
	if (end_bit) {
		mask = (1U << end_bit) - 1;
		*wordp |= mask;
	}
}

/*
 * Mark bytes first through last inclusive as dirty in the buf
 * item's bitmap.
 */
void
xfs_buf_item_log(
	struct xfs_buf_log_item	*bip,
	uint			first,
	uint			last)
{
	int			i;
	uint			start;
	uint			end;
	struct xfs_buf		*bp = bip->bli_buf;

	/*
	 * walk each buffer segment and mark them dirty appropriately.
	 */
	start = 0;
	for (i = 0; i < bip->bli_format_count; i++) {
		if (start > last)
			break;
		end = start + BBTOB(bp->b_maps[i].bm_len) - 1;

		/* skip to the map that includes the first byte to log */
		if (first > end) {
			start += BBTOB(bp->b_maps[i].bm_len);
			continue;
		}

		/*
		 * Trim the range to this segment and mark it in the bitmap.
		 * Note that we must convert buffer offsets to segment relative
		 * offsets (e.g., the first byte of each segment is byte 0 of
		 * that segment).
		 */
		if (first < start)
			first = start;
		if (end > last)
			end = last;
		xfs_buf_item_log_segment(first - start, end - start,
					 &bip->bli_formats[i].blf_data_map[0]);

		start += BBTOB(bp->b_maps[i].bm_len);
	}
}


/*
 * Return true if the buffer has any ranges logged/dirtied by a transaction,
 * false otherwise.
 */
bool
xfs_buf_item_dirty_format(
	struct xfs_buf_log_item	*bip)
{
	int			i;

	for (i = 0; i < bip->bli_format_count; i++) {
		if (!xfs_bitmap_empty(bip->bli_formats[i].blf_data_map,
			     bip->bli_formats[i].blf_map_size))
			return true;
	}

	return false;
}

void
xfs_buf_item_done(
	struct xfs_buf		*bp)
{
	/*
	 * sess1(e8e920f7) — atomically CLAIM the BLI.  The stock code read
	 * bp->b_log_item twice (once for ail_delete, once for relse); two
	 * concurrent callers — reachable when a b_sema-poisoned buffer lets a
	 * completion and a retire (or two completions of a double submit) run
	 * simultaneously — both passed the caller's non-NULL check, the loser
	 * re-read NULL after the winner's relse and oopsed in
	 * xfs_buf_item_relse (PROVEN: test1 r17 validate2 015913Z, xfsaild
	 * NULL deref at xfs_buf_item_relse+0xf; the loser's ail_delete of the
	 * already-removed item also fired the spurious not-in-AIL
	 * SHUTDOWN_CORRUPT_INCORE that killed the FS moments earlier).  xchg
	 * guarantees exactly one caller retires the BLI; the loser logs loudly
	 * — this is containment + detection, NOT a mask: the poisoning source
	 * is tracked by P-SEMA-OVERUP/P-SEMA-DUALLOCK and stays a bug.
	 */
	struct xfs_buf_log_item	*bip = xchg(&bp->b_log_item, NULL);

	if (unlikely(!bip)) {
		static atomic_t pbdd_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&pbdd_n);

		if (n <= 200) {
			pr_warn("mxfs: P-BLI-DOUBLEDONE daddr=%lld ops=%s flags=0x%x comm=%s — concurrent xfs_buf_item_done lost the claim race (double completion/retire on one buffer)\n",
			    (long long)bp->b_maps[0].bm_bn,
			    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
			    (unsigned int)bp->b_flags, current->comm);
			if (n <= 8)
				dump_stack();
		}
		return;
	}

	/*
	 * If we are forcibly shutting down, this may well be off the AIL
	 * already. That's because we simulate the log-committed callbacks to
	 * unpin these buffers. Or we may never have put this item on AIL
	 * because of the transaction was aborted forcibly.
	 * xfs_trans_ail_delete() takes care of these.
	 *
	 * Either way, AIL is useless if we're forcing a shutdown.
	 *
	 * Note that log recovery writes might have buffer items that are not on
	 * the AIL even when the file system is not shut down.
	 */
	xfs_trans_ail_delete(&bip->bli_item,
			     (bp->b_flags & _XBF_LOGRECOVERY) ? 0 :
			     SHUTDOWN_CORRUPT_INCORE);
	xfs_buf_item_relse(bip);
}
