// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_bmap.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_health.h"
#ifdef __KERNEL__
#include "../../dlm/v5_mount.h"	/* sess21: mxfs_v5_dlm_is_single_node */
#include <linux/sort.h>		/* sess21: sort() for leaf rebuild */
#include "../xfs_mxfs_dlm.h"	/* sess10(a9a03929): mxfs_ino_watched */
#endif

/*
 * Local function declarations.
 */
static int xfs_dir2_leaf_lookup_int(xfs_da_args_t *args, struct xfs_buf **lbpp,
				    int *indexp, struct xfs_buf **dbpp,
				    struct xfs_dir3_icleaf_hdr *leafhdr);
static void xfs_dir3_leaf_log_bests(struct xfs_da_args *args,
				    struct xfs_buf *bp, int first, int last);
static void xfs_dir3_leaf_log_tail(struct xfs_da_args *args,
				   struct xfs_buf *bp);

void
xfs_dir2_leaf_hdr_from_disk(
	struct xfs_mount		*mp,
	struct xfs_dir3_icleaf_hdr	*to,
	struct xfs_dir2_leaf		*from)
{
	if (xfs_has_crc(mp)) {
		struct xfs_dir3_leaf *from3 = (struct xfs_dir3_leaf *)from;

		to->forw = be32_to_cpu(from3->hdr.info.hdr.forw);
		to->back = be32_to_cpu(from3->hdr.info.hdr.back);
		to->magic = be16_to_cpu(from3->hdr.info.hdr.magic);
		to->count = be16_to_cpu(from3->hdr.count);
		to->stale = be16_to_cpu(from3->hdr.stale);
		to->ents = from3->__ents;

		ASSERT(to->magic == XFS_DIR3_LEAF1_MAGIC ||
		       to->magic == XFS_DIR3_LEAFN_MAGIC);
	} else {
		to->forw = be32_to_cpu(from->hdr.info.forw);
		to->back = be32_to_cpu(from->hdr.info.back);
		to->magic = be16_to_cpu(from->hdr.info.magic);
		to->count = be16_to_cpu(from->hdr.count);
		to->stale = be16_to_cpu(from->hdr.stale);
		to->ents = from->__ents;

		ASSERT(to->magic == XFS_DIR2_LEAF1_MAGIC ||
		       to->magic == XFS_DIR2_LEAFN_MAGIC);
	}
}

void
xfs_dir2_leaf_hdr_to_disk(
	struct xfs_mount		*mp,
	struct xfs_dir2_leaf		*to,
	struct xfs_dir3_icleaf_hdr	*from)
{
	if (xfs_has_crc(mp)) {
		struct xfs_dir3_leaf *to3 = (struct xfs_dir3_leaf *)to;

		ASSERT(from->magic == XFS_DIR3_LEAF1_MAGIC ||
		       from->magic == XFS_DIR3_LEAFN_MAGIC);

		to3->hdr.info.hdr.forw = cpu_to_be32(from->forw);
		to3->hdr.info.hdr.back = cpu_to_be32(from->back);
		to3->hdr.info.hdr.magic = cpu_to_be16(from->magic);
		to3->hdr.count = cpu_to_be16(from->count);
		to3->hdr.stale = cpu_to_be16(from->stale);
	} else {
		ASSERT(from->magic == XFS_DIR2_LEAF1_MAGIC ||
		       from->magic == XFS_DIR2_LEAFN_MAGIC);

		to->hdr.info.forw = cpu_to_be32(from->forw);
		to->hdr.info.back = cpu_to_be32(from->back);
		to->hdr.info.magic = cpu_to_be16(from->magic);
		to->hdr.count = cpu_to_be16(from->count);
		to->hdr.stale = cpu_to_be16(from->stale);
	}
}

/*
 * Check the internal consistency of a leaf1 block.
 * Pop an assert if something is wrong.
 */
#ifdef DEBUG
static xfs_failaddr_t
xfs_dir3_leaf1_check(
	struct xfs_inode	*dp,
	struct xfs_buf		*bp)
{
	struct xfs_dir2_leaf	*leaf = bp->b_addr;
	struct xfs_dir3_icleaf_hdr leafhdr;

	xfs_dir2_leaf_hdr_from_disk(dp->i_mount, &leafhdr, leaf);

	if (leafhdr.magic == XFS_DIR3_LEAF1_MAGIC) {
		struct xfs_dir3_leaf_hdr *leaf3 = bp->b_addr;
		if (be64_to_cpu(leaf3->info.blkno) != xfs_buf_daddr(bp))
			return __this_address;
	} else if (leafhdr.magic != XFS_DIR2_LEAF1_MAGIC)
		return __this_address;

	return xfs_dir3_leaf_check_int(dp->i_mount, &leafhdr, leaf, false);
}

static inline void
xfs_dir3_leaf_check(
	struct xfs_inode	*dp,
	struct xfs_buf		*bp)
{
	xfs_failaddr_t		fa;

	fa = xfs_dir3_leaf1_check(dp, bp);
	if (!fa)
		return;
	xfs_corruption_error(__func__, XFS_ERRLEVEL_LOW, dp->i_mount,
			bp->b_addr, BBTOB(bp->b_length), __FILE__, __LINE__,
			fa);
	ASSERT(0);
}
#else
#define	xfs_dir3_leaf_check(dp, bp)
#endif

xfs_failaddr_t
xfs_dir3_leaf_check_int(
	struct xfs_mount		*mp,
	struct xfs_dir3_icleaf_hdr	*hdr,
	struct xfs_dir2_leaf		*leaf,
	bool				expensive_checking)
{
	struct xfs_da_geometry		*geo = mp->m_dir_geo;
	xfs_dir2_leaf_tail_t		*ltp;
	int				stale;
	int				i;
	bool				isleaf1 = (hdr->magic == XFS_DIR2_LEAF1_MAGIC ||
						   hdr->magic == XFS_DIR3_LEAF1_MAGIC);

	ltp = xfs_dir2_leaf_tail_p(geo, leaf);

	/*
	 * XXX (dgc): This value is not restrictive enough.
	 * Should factor in the size of the bests table as well.
	 * We can deduce a value for that from i_disk_size.
	 */
	if (hdr->count > geo->leaf_max_ents)
		return __this_address;

	/* Leaves and bests don't overlap in leaf format. */
	if (isleaf1 &&
	    (char *)&hdr->ents[hdr->count] > (char *)xfs_dir2_leaf_bests_p(ltp))
		return __this_address;

	if (!expensive_checking)
		return NULL;

	/* Check hash value order, count stale entries.  */
	for (i = stale = 0; i < hdr->count; i++) {
		if (i + 1 < hdr->count) {
			if (be32_to_cpu(hdr->ents[i].hashval) >
					be32_to_cpu(hdr->ents[i + 1].hashval))
				return __this_address;
		}
		if (hdr->ents[i].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			stale++;
		if (isleaf1 && xfs_dir2_dataptr_to_db(geo,
				be32_to_cpu(hdr->ents[i].address)) >=
				be32_to_cpu(ltp->bestcount))
			return __this_address;
	}
	if (hdr->stale != stale)
		return __this_address;
	return NULL;
}

/*
 * We verify the magic numbers before decoding the leaf header so that on debug
 * kernels we don't get assertion failures in xfs_dir3_leaf_hdr_from_disk() due
 * to incorrect magic numbers.
 */
static xfs_failaddr_t
xfs_dir3_leaf_verify(
	struct xfs_buf			*bp)
{
	struct xfs_mount		*mp = bp->b_mount;
	struct xfs_dir3_icleaf_hdr	leafhdr;
	xfs_failaddr_t			fa;

	fa = xfs_da3_blkinfo_verify(bp, bp->b_addr);
	if (fa)
		return fa;

	xfs_dir2_leaf_hdr_from_disk(mp, &leafhdr, bp->b_addr);
	return xfs_dir3_leaf_check_int(mp, &leafhdr, bp->b_addr, true);
}

xfs_failaddr_t
xfs_dir3_leaf_header_check(
	struct xfs_buf		*bp,
	xfs_ino_t		owner)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (xfs_has_crc(mp)) {
		struct xfs_dir3_leaf *hdr3 = bp->b_addr;

		if (hdr3->hdr.info.hdr.magic !=
					cpu_to_be16(XFS_DIR3_LEAF1_MAGIC) &&
		    hdr3->hdr.info.hdr.magic !=
					cpu_to_be16(XFS_DIR3_LEAFN_MAGIC))
			return __this_address;

		if (be64_to_cpu(hdr3->hdr.info.owner) != owner)
			return __this_address;
	}

	return NULL;
}

static void
xfs_dir3_leaf_read_verify(
	struct xfs_buf  *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	xfs_failaddr_t		fa;

	if (xfs_has_crc(mp) &&
	     !xfs_buf_verify_cksum(bp, XFS_DIR3_LEAF_CRC_OFF)) {
		/* sess38(ccloop) RULE-4 decisive probe: a leaf read that fails
		 * CRC.  Dump the ACTUAL on-disk header so we can tell a torn
		 * write of a real leaf (leaf magic, bad crc) from an extent-map
		 * divergence / block double-alloc (a DATA/other block sitting at
		 * the daddr the reader's map resolves the leaf to).  Always-on,
		 * ratelimited; only the failure path pays it. */
		{
			struct xfs_da3_blkinfo *bi = bp->b_addr;
			pr_warn_ratelimited(
				"mxfs: P38-LEAFCRC-FAIL daddr=%lld found_magic=0x%04x self_blkno=%llu owner=%llu comm=%s\n",
				(long long)bp->b_maps[0].bm_bn,
				be16_to_cpu(bi->hdr.magic),
				(unsigned long long)be64_to_cpu(bi->blkno),
				(unsigned long long)be64_to_cpu(bi->owner),
				current->comm);
		}
		xfs_verifier_error(bp, -EFSBADCRC, __this_address);
	} else {
		fa = xfs_dir3_leaf_verify(bp);
		if (fa)
			xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		else {
			/* sess2 (a9a03929) P2R-LEAFR: provenance of every leaf
			 * block that comes off the platter.  run49 t7 died on a
			 * PRIOR-incarnation leaf (bestcount=2) under a same-
			 * incarnation dinode with disize=4096 (1 data block) —
			 * MAP_HOLE at create.  This logs what every disk read
			 * actually returned so the stale image's origin (never-
			 * destaged fresh leaf vs ghost-writeback revert) is
			 * decidable from one run's cross-node log.
			 * instr-gated: with per-op barriers on, leaf IO is per
			 * dirop and this would print tens of thousands of
			 * lines + perturb pace runs. */
			extern int mxfs_leafprobe;
			struct xfs_dir3_icleaf_hdr p2lh;
			struct xfs_da3_blkinfo *p2bi = bp->b_addr;
			unsigned int p2bc = 0;

			if (!unlikely(mxfs_leafprobe))
				return;
			xfs_dir2_leaf_hdr_from_disk(mp, &p2lh, bp->b_addr);
			if (p2bi->hdr.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC)) {
				struct xfs_dir2_leaf_tail *p2ltp =
					xfs_dir2_leaf_tail_p(mp->m_dir_geo,
							     bp->b_addr);
				p2bc = be32_to_cpu(p2ltp->bestcount);
			}
			pr_warn("mxfs: P2R-LEAFR daddr=%lld owner=%llu blkno=%llu magic=0x%04x bestcount=%u count=%u stale=%u lsn=%llu comm=%s realns=%llu\n",
				(long long)bp->b_maps[0].bm_bn,
				(unsigned long long)be64_to_cpu(p2bi->owner),
				(unsigned long long)be64_to_cpu(p2bi->blkno),
				be16_to_cpu(p2bi->hdr.magic), p2bc,
				p2lh.count, p2lh.stale,
				(unsigned long long)be64_to_cpu(p2bi->lsn),
				current->comm,
				(unsigned long long)ktime_get_real_ns());
		}
	}
}

static void
xfs_dir3_leaf_write_verify(
	struct xfs_buf  *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_dir3_leaf_hdr *hdr3 = bp->b_addr;
	xfs_failaddr_t		fa;

	fa = xfs_dir3_leaf_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (!xfs_has_crc(mp))
		return;

	if (bip)
		hdr3->info.lsn = cpu_to_be64(bip->bli_item.li_lsn);

	/* sess2 (a9a03929) P2W-LEAFW: pair of P2R-LEAFR — provenance of every
	 * leaf block written toward the platter (drain, xfsaild, durable
	 * signal), so a stale-image writeback (ghost revert) or a missing
	 * fresh-leaf destage is directly visible.  comm= identifies the
	 * writer path.  instr-gated (see P2R-LEAFR). */
	{
		extern int mxfs_leafprobe;
		struct xfs_dir3_icleaf_hdr p2lh;
		struct xfs_da3_blkinfo *p2bi = bp->b_addr;
		unsigned int p2bc = 0;

		if (unlikely(mxfs_leafprobe)) {
		xfs_dir2_leaf_hdr_from_disk(mp, &p2lh, bp->b_addr);
		if (p2bi->hdr.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC)) {
			struct xfs_dir2_leaf_tail *p2ltp =
				xfs_dir2_leaf_tail_p(mp->m_dir_geo,
						     bp->b_addr);
			p2bc = be32_to_cpu(p2ltp->bestcount);
		}
		pr_warn("mxfs: P2W-LEAFW daddr=%lld owner=%llu blkno=%llu magic=0x%04x bestcount=%u count=%u stale=%u lsn=%llu comm=%s realns=%llu\n",
			(long long)bp->b_maps[0].bm_bn,
			(unsigned long long)be64_to_cpu(p2bi->owner),
			(unsigned long long)be64_to_cpu(p2bi->blkno),
			be16_to_cpu(p2bi->hdr.magic), p2bc,
			p2lh.count, p2lh.stale,
			(unsigned long long)be64_to_cpu(p2bi->lsn),
			current->comm,
			(unsigned long long)ktime_get_real_ns());
		}
	}

	xfs_buf_update_cksum(bp, XFS_DIR3_LEAF_CRC_OFF);
}

const struct xfs_buf_ops xfs_dir3_leaf1_buf_ops = {
	.name = "xfs_dir3_leaf1",
	.magic16 = { cpu_to_be16(XFS_DIR2_LEAF1_MAGIC),
		     cpu_to_be16(XFS_DIR3_LEAF1_MAGIC) },
	.verify_read = xfs_dir3_leaf_read_verify,
	.verify_write = xfs_dir3_leaf_write_verify,
	.verify_struct = xfs_dir3_leaf_verify,
};

const struct xfs_buf_ops xfs_dir3_leafn_buf_ops = {
	.name = "xfs_dir3_leafn",
	.magic16 = { cpu_to_be16(XFS_DIR2_LEAFN_MAGIC),
		     cpu_to_be16(XFS_DIR3_LEAFN_MAGIC) },
	.verify_read = xfs_dir3_leaf_read_verify,
	.verify_write = xfs_dir3_leaf_write_verify,
	.verify_struct = xfs_dir3_leaf_verify,
};

int
xfs_dir3_leaf_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_ino_t		owner,
	xfs_dablk_t		fbno,
	struct xfs_buf		**bpp)
{
	xfs_failaddr_t		fa;
	int			err;

	err = xfs_da_read_buf(tp, dp, fbno, 0, bpp, XFS_DATA_FORK,
			&xfs_dir3_leaf1_buf_ops);
	if (err || !(*bpp))
		return err;

	fa = xfs_dir3_leaf_header_check(*bpp, owner);
	if (fa) {
		__xfs_buf_mark_corrupt(*bpp, fa);
		xfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
		return -EFSCORRUPTED;
	}

	if (tp)
		xfs_trans_buf_set_type(tp, *bpp, XFS_BLFT_DIR_LEAF1_BUF);
	return 0;
}

int
xfs_dir3_leafn_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_ino_t		owner,
	xfs_dablk_t		fbno,
	struct xfs_buf		**bpp)
{
	xfs_failaddr_t		fa;
	int			err;

	err = xfs_da_read_buf(tp, dp, fbno, 0, bpp, XFS_DATA_FORK,
			&xfs_dir3_leafn_buf_ops);
	if (err || !(*bpp))
		return err;

	fa = xfs_dir3_leaf_header_check(*bpp, owner);
	if (fa) {
		__xfs_buf_mark_corrupt(*bpp, fa);
		xfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
		return -EFSCORRUPTED;
	}

	if (tp)
		xfs_trans_buf_set_type(tp, *bpp, XFS_BLFT_DIR_LEAFN_BUF);
	return 0;
}

/*
 * Initialize a new leaf block, leaf1 or leafn magic accepted.
 */
static void
xfs_dir3_leaf_init(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,
	uint16_t		type)
{
	struct xfs_mount	*mp = args->dp->i_mount;
	struct xfs_trans	*tp = args->trans;
	struct xfs_dir2_leaf	*leaf = bp->b_addr;

	ASSERT(type == XFS_DIR2_LEAF1_MAGIC || type == XFS_DIR2_LEAFN_MAGIC);

	if (xfs_has_crc(mp)) {
		struct xfs_dir3_leaf_hdr *leaf3 = bp->b_addr;

		memset(leaf3, 0, sizeof(*leaf3));

		leaf3->info.hdr.magic = (type == XFS_DIR2_LEAF1_MAGIC)
					 ? cpu_to_be16(XFS_DIR3_LEAF1_MAGIC)
					 : cpu_to_be16(XFS_DIR3_LEAFN_MAGIC);
		leaf3->info.blkno = cpu_to_be64(xfs_buf_daddr(bp));
		leaf3->info.owner = cpu_to_be64(args->owner);
		uuid_copy(&leaf3->info.uuid, &mp->m_sb.sb_meta_uuid);
	} else {
		memset(leaf, 0, sizeof(*leaf));
		leaf->hdr.info.magic = cpu_to_be16(type);
	}

	/*
	 * If it's a leaf-format directory initialize the tail.
	 * Caller is responsible for initialising the bests table.
	 */
	if (type == XFS_DIR2_LEAF1_MAGIC) {
		struct xfs_dir2_leaf_tail *ltp;

		ltp = xfs_dir2_leaf_tail_p(mp->m_dir_geo, leaf);
		ltp->bestcount = 0;
		bp->b_ops = &xfs_dir3_leaf1_buf_ops;
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DIR_LEAF1_BUF);
	} else {
		bp->b_ops = &xfs_dir3_leafn_buf_ops;
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DIR_LEAFN_BUF);
	}

	/* sess16(ccloop): stamp the coherent-tenure epoch on a freshly created
	 * LEAF block (see xfs_dir3_data_init) so the prior-tenure evict override
	 * can distinguish a stale prior-tenure leaf cache-hit from our own
	 * current-tenure leaf without resurrecting a just-created leaf.  Inert
	 * unless dir_evict_prior_tenure is enabled. */
	bp->b_mxfs_dir_epoch = args->dp->i_dlm_dir_valid_epoch;
}

int
xfs_dir3_leaf_get_buf(
	xfs_da_args_t		*args,
	xfs_dir2_db_t		bno,
	struct xfs_buf		**bpp,
	uint16_t		magic)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_trans	*tp = args->trans;
	struct xfs_buf		*bp;
	int			error;

	ASSERT(magic == XFS_DIR2_LEAF1_MAGIC || magic == XFS_DIR2_LEAFN_MAGIC);
	ASSERT(bno >= xfs_dir2_byte_to_db(args->geo, XFS_DIR2_LEAF_OFFSET) &&
	       bno < xfs_dir2_byte_to_db(args->geo, XFS_DIR2_FREE_OFFSET));

	error = xfs_da_get_buf(tp, dp, xfs_dir2_db_to_da(args->geo, bno),
			       &bp, XFS_DATA_FORK);
	if (error)
		return error;

	xfs_dir3_leaf_init(args, bp, magic);
	xfs_dir3_leaf_log_header(args, bp);
	if (magic == XFS_DIR2_LEAF1_MAGIC)
		xfs_dir3_leaf_log_tail(args, bp);
	*bpp = bp;
	return 0;
}

/*
 * Convert a block form directory to a leaf form directory.
 */
int						/* error */
xfs_dir2_block_to_leaf(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		*dbp)		/* input block's buffer */
{
	__be16			*bestsp;	/* leaf's bestsp entries */
	xfs_dablk_t		blkno;		/* leaf block's bno */
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block's leaf entries */
	xfs_dir2_block_tail_t	*btp;		/* block's tail */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	struct xfs_buf		*lbp;		/* leaf block's buffer */
	xfs_dir2_db_t		ldb;		/* leaf block's bno */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf's tail */
	int			needlog;	/* need to log block header */
	int			needscan;	/* need to rescan bestfree */
	xfs_trans_t		*tp;		/* transaction pointer */
	struct xfs_dir2_data_free *bf;
	struct xfs_dir3_icleaf_hdr leafhdr;

	trace_xfs_dir2_block_to_leaf(args);

	dp = args->dp;
	tp = args->trans;
	/*
	 * Add the leaf block to the inode.
	 * This interface will only put blocks in the leaf/node range.
	 * Since that's empty now, we'll get the root (block 0 in range).
	 */
	if ((error = xfs_da_grow_inode(args, &blkno))) {
		return error;
	}
	ldb = xfs_dir2_da_to_db(args->geo, blkno);
	ASSERT(ldb == xfs_dir2_byte_to_db(args->geo, XFS_DIR2_LEAF_OFFSET));
	/*
	 * Initialize the leaf block, get a buffer for it.
	 */
	error = xfs_dir3_leaf_get_buf(args, ldb, &lbp, XFS_DIR2_LEAF1_MAGIC);
	if (error)
		return error;

	leaf = lbp->b_addr;
	hdr = dbp->b_addr;
	xfs_dir3_data_check(dp, dbp);
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);

	/*
	 * Set the counts in the leaf header.
	 */
	xfs_dir2_leaf_hdr_from_disk(dp->i_mount, &leafhdr, leaf);
	leafhdr.count = be32_to_cpu(btp->count);
	leafhdr.stale = be32_to_cpu(btp->stale);
	xfs_dir2_leaf_hdr_to_disk(dp->i_mount, leaf, &leafhdr);
	xfs_dir3_leaf_log_header(args, lbp);

	/*
	 * Could compact these but I think we always do the conversion
	 * after squeezing out stale entries.
	 */
	memcpy(leafhdr.ents, blp,
		be32_to_cpu(btp->count) * sizeof(struct xfs_dir2_leaf_entry));
	xfs_dir3_leaf_log_ents(args, &leafhdr, lbp, 0, leafhdr.count - 1);
	needscan = 0;
	needlog = 1;
	/*
	 * Make the space formerly occupied by the leaf entries and block
	 * tail be free.
	 */
	xfs_dir2_data_make_free(args, dbp,
		(xfs_dir2_data_aoff_t)((char *)blp - (char *)hdr),
		(xfs_dir2_data_aoff_t)((char *)hdr + args->geo->blksize -
				       (char *)blp),
		&needlog, &needscan);
	/*
	 * Fix up the block header, make it a data block.
	 */
	dbp->b_ops = &xfs_dir3_data_buf_ops;
	xfs_trans_buf_set_type(tp, dbp, XFS_BLFT_DIR_DATA_BUF);
	if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC))
		hdr->magic = cpu_to_be32(XFS_DIR2_DATA_MAGIC);
	else
		hdr->magic = cpu_to_be32(XFS_DIR3_DATA_MAGIC);

	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	/*
	 * Set up leaf tail and bests table.
	 */
	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);
	ltp->bestcount = cpu_to_be32(1);
	bestsp = xfs_dir2_leaf_bests_p(ltp);
	bestsp[0] =  bf[0].length;
	/*
	 * Log the data header and leaf bests table.
	 */
	if (needlog)
		xfs_dir2_data_log_header(args, dbp);
	xfs_dir3_leaf_check(dp, lbp);
	xfs_dir3_data_check(dp, dbp);
	xfs_dir3_leaf_log_bests(args, lbp, 0, 0);
#ifdef __KERNEL__
	/*
	 * sess36 ROOT FIX (dir_reuse_coherency round-1 format-transition loss):
	 * block 0's daddr is reused in place (block-fmt -> data-fmt) with no
	 * dir-gen advance, so a pre-conversion cached image aliases as current
	 * and a later writeback clobbers this post-conversion data block.  Bump
	 * the dir gen and stamp the live converted buffers so pre-conversion
	 * buffers are detected stale by the read/write gen guards.
	 */
	{
		extern void mxfs_dir_gen_bump_on_convert(struct xfs_inode *,
				struct xfs_buf *, struct xfs_buf *);
		mxfs_dir_gen_bump_on_convert(dp, dbp, lbp);
	}
#endif
	return 0;
}

#ifdef __KERNEL__
static int
mxfs_leaf_kv_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

/*
 * sess21: collect {hashval<<32 | dataptr} for every LIVE dirent in one DATA
 * block image `img` (either an in-core buffer or a coherent plain-bio snapshot)
 * for data block number `db`.  Appends to kv[] starting at n; returns the new
 * count, or -1 on overflow (img holds more entries than kvcap -> caller bails).
 */
static int
mxfs_collect_dir_hashes(struct xfs_mount *mp, struct xfs_da_geometry *geo,
			void *img, int db, uint64_t *kv, int kvcap, int n)
{
	unsigned int offset = geo->data_entry_offset;
	unsigned int end = xfs_dir3_data_end_offset(geo, img);

	while (offset < end) {
		struct xfs_dir2_data_unused	*dup = img + offset;
		struct xfs_dir2_data_entry	*dep = img + offset;
		struct xfs_name			nm;

		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			offset += be16_to_cpu(dup->length);
			continue;
		}
		if (n >= kvcap)
			return -1;
		nm.name = dep->name;
		nm.len = dep->namelen;
		nm.type = xfs_dir2_data_get_ftype(mp, dep);
		kv[n++] = ((uint64_t)xfs_dir2_hashname(mp, &nm) << 32) |
			  xfs_dir2_db_off_to_dataptr(geo, db, offset);
		offset += xfs_dir2_data_entsize(mp, dep->namelen);
	}
	return n;
}

/*
 * sess21 (ccloop 8ddb16a2) MXFS clustered-dir LEAF coherency repair.
 *
 * The shared directory's single LEAF1 (hash index) block is perpetually pinned
 * on whichever node is actively creating (every create touches it, so the CIL
 * never quiesces it).  The DLM acquire-side evict therefore cannot refresh it
 * (clearing XBF_DONE on a pinned buffer loses the un-checkpointed delta = sess64
 * corruption), so a node ends up holding a STALE in-core leaf missing a peer's
 * committed hashvals; its next dir RMW + release-destage durably drops them --
 * readdir still lists the name from the (coherent) DATA block, but lookup
 * ENOENTs because its hash entry is gone from the leaf.
 *
 * The leaf is DERIVED metadata: it is fully reconstructible from the DATA
 * blocks, which ARE coherent here (every node sees all dirents via readdir).
 * Rebuild the leaf hash index (+ the leaf bests table) from the DATA blocks and
 * RELOG it in the caller's already-open transaction.  Relogging a pinned buffer
 * is normal XFS (the CIL relogs pinned metadata into a newer checkpoint); it
 * supersedes the stale image with NO XBF_DONE clear and NO extra DLM acquire.
 *
 * Caller holds dp ILOCK_EXCL + an active tp + the dir-inode DLM EX grant, and
 * has consumed MXFS_IF_DIR_LEAF_STALE.  Scoped to LEAF1 format only; any odd
 * condition (block/node format, holes, would-overflow-leaf, OOM, read error)
 * BAILS cleanly BEFORE mutating anything (returns 0 = no repair this op).  A
 * negative errno is only returned for a transaction read error after we may
 * have joined buffers, which the caller treats as a normal op error.
 */
int
mxfs_dir_rebuild_leaf_from_data(
	struct xfs_da_args	*args)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo = args->geo;
	struct xfs_trans	*tp = args->trans;
	struct xfs_buf		*lbp = NULL;
	struct xfs_dir2_leaf	*leaf;
	struct xfs_dir3_icleaf_hdr leafhdr;
	struct xfs_dir2_leaf_tail *ltp;
	__be16			*bestsp;
	uint64_t		*kv = NULL;
	__be16			*bests = NULL;
	int			max_ents, nent = 0, ndb, i, db, error;

	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS) {
		static atomic_t p26b = ATOMIC_INIT(0);
		if (atomic_inc_return(&p26b) <= 60)
			pr_warn("mxfs: P26-REBUILD-BAIL ino=%llu reason=fmt=%d (not-extents)\n",
				(unsigned long long)dp->i_ino, dp->i_df.if_format);
		return 0;	/* shortform / btree: not a single-leaf dir */
	}

	/*
	 * ccloop c7ee71c6 sess7: gate on the ACTUAL dir format before probing
	 * geo->leafblk.  The old unconditional leaf_read assumed "no leaf
	 * block -> clean failure", but xfs_dir3_leaf_read maps the offset via
	 * xfs_dabuf_map WITHOUT XFS_DABUF_MAP_HOLE_OK, so on a BLOCK-form dir
	 * (extents, nextents=1, disize=blksize) it fires the full corruption
	 * machinery — xfs_dirattr_mark_sick + "Corruption detected" console
	 * storm + the P14-DABUF-HOLE forensics (FUA disk probe, ms each) — on
	 * EVERY leaf-stale-armed create while the shared dir is still small
	 * (run 192304Z: every P14 in the run was this probe read, comm=dd,
	 * fmt=2 nextents=1 disize=4096).  Only a LEAF-format dir is in this
	 * rebuild's scope; everything else bails clean, matching the
	 * "no repair this op" contract.
	 */
	{
		int	frc = 0;

		if (xfs_dir2_format(args, &frc) != XFS_DIR2_FMT_LEAF || frc)
			return 0;
	}

	error = xfs_dir3_leaf_read(tp, dp, args->owner, geo->leafblk, &lbp);
	if (error || !lbp)
		return 0;	/* no leaf block (block format) -> nothing to do */

	leaf = lbp->b_addr;
	xfs_dir2_leaf_hdr_from_disk(mp, &leafhdr, leaf);
	if (leafhdr.magic != XFS_DIR2_LEAF1_MAGIC &&
	    leafhdr.magic != XFS_DIR3_LEAF1_MAGIC) {
		static atomic_t p26n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p26n) <= 60)
			pr_warn("mxfs: P26-REBUILD-BAIL ino=%llu reason=leafn magic=0x%x\n",
				(unsigned long long)dp->i_ino, leafhdr.magic);
		xfs_trans_brelse(tp, lbp);
		return 0;	/* LEAFN/node format: out of scope */
	}

	ltp = xfs_dir2_leaf_tail_p(geo, leaf);
	ndb = be32_to_cpu(ltp->bestcount);
	bestsp = xfs_dir2_leaf_bests_p(ltp);
	max_ents = ((char *)bestsp - (char *)leafhdr.ents) /
		   (int)sizeof(struct xfs_dir2_leaf_entry);
	if (ndb <= 0 || max_ents <= 0) {
		xfs_trans_brelse(tp, lbp);
		return 0;
	}

	/*
	 * sess21 union read: collect dirent hashes from BOTH the in-core data
	 * block (this node's uncommitted adds; hook-refreshed when clean) AND a
	 * COHERENT plain-bio snapshot of the same physical block (the peer's
	 * durable adds — needed when the in-core block was undestaged-skipped at
	 * acquire and so missing a peer entry).  Disjoint names => the (hash,addr)
	 * union, deduped, is exactly the complete index.  kv holds up to 2x.
	 */
	{
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
				uint64_t, void *, uint32_t);
		extern int mxfs_dir_leaf_rebuild;
		int kvcap = max_ents * 2;
		void *snap = NULL;
		uint32_t snaplen = 0;

		kv = kmalloc_array(kvcap, sizeof(*kv), GFP_NOFS);
		bests = kmalloc_array(ndb, sizeof(__be16), GFP_NOFS);
		if (!kv || !bests) {
			kfree(kv);
			kfree(bests);
			xfs_trans_brelse(tp, lbp);
			return 0;	/* OOM: skip repair (no harm) */
		}

		for (db = 0; db < ndb; db++) {
			struct xfs_buf			*dbp = NULL;
			struct xfs_dir2_data_hdr	*hdr;
			struct xfs_dir2_data_free	*bf;
			xfs_dablk_t			dablk =
				xfs_dir2_db_to_da(geo, db);

			/*
			 * mxfs (8/tcp dir_reuse shutdown fix): a freed/empty
			 * data block is a HOLE in the data fork and is marked
			 * NULLDATAOFF in the leaf bests array.  Calling
			 * xfs_dir3_data_read on a hole maps to no block and
			 * returns EFSCORRUPTED — and because this rebuild runs
			 * inside xfs_create's ALREADY-DIRTY transaction (the
			 * child inode is allocated before xfs_dir_createname),
			 * that error forces xfs_trans_cancel on a dirty trans =
			 * "Corruption of in-memory data" = filesystem SHUTDOWN.
			 * A dir with freed middle blocks is perfectly normal, so
			 * skip the hole (it has no live dirents to index) and
			 * carry its NULLDATAOFF through to the rebuilt bests.
			 */
			if (bestsp[db] == cpu_to_be16(NULLDATAOFF)) {
				bests[db] = cpu_to_be16(NULLDATAOFF);
				continue;
			}

			error = xfs_dir3_data_read(tp, dp, args->owner, dablk, 0,
						   &dbp);
			if (error || !dbp) {
				/*
				 * mxfs: a data block we cannot read (CRC error,
				 * unexpected hole, transient corruption) must NOT
				 * propagate out of this leaf rebuild — the rebuild
				 * runs inside xfs_create's ALREADY-DIRTY transaction
				 * (child inode allocated), so returning an error here
				 * forces a dirty xfs_trans_cancel = filesystem
				 * SHUTDOWN.  Bail the rebuild cleanly (return 0, no
				 * leaf mutation): this create degrades to the
				 * leaf_rebuild-off path (stale leaf kept) but the node
				 * stays up.  A genuinely corrupt block will still be
				 * caught by the normal read verifiers if/when a real
				 * access touches it.
				 */
				static atomic_t p26r = ATOMIC_INIT(0);
				if (atomic_inc_return(&p26r) <= 60)
					pr_warn("mxfs: P26-REBUILD-BAIL ino=%llu reason=dataread db=%d rc=%d (leaf not rebuilt, node stays up)\n",
						(unsigned long long)dp->i_ino, db, error);
				kfree(snap);
				kfree(kv);
				kfree(bests);
				xfs_trans_brelse(tp, lbp);
				return 0;
			}
			hdr = dbp->b_addr;
			bf = xfs_dir2_data_bestfree_p(mp, hdr);
			bests[db] = bf[0].length;

			/* in-core source */
			nent = mxfs_collect_dir_hashes(mp, geo, hdr, db, kv,
						       kvcap, nent);
			if (nent < 0)
				goto overflow_bail;

			/*
			 * ccloop c7ee71c6 sess2 (RULE 4, cache_coherency rv
			 * "old gone" fail ×8 nodes, P26-REBUILD-OK comm=mv on
			 * the rv dir): the on-disk union is DELETE-UNSAFE.  A
			 * dirent our committed-but-undestaged removename just
			 * freed is still LIVE in the disk snapshot, and
			 * "in-core free + disk live" is indistinguishable from
			 * a peer add — the union resurrects the removed name's
			 * (hash,dataptr) into the relogged leaf, and any node
			 * that cold-reads the not-yet-destaged data block then
			 * fully resolves the old name (rename-visibility loss,
			 * durably).  The union existed to compensate for an
			 * acquire-refresh SKIPPED on own-dirt — but in that
			 * state the peer already RMW'd the block from a base
			 * missing our dirt (data-level break the leaf cannot
			 * repair), while in the healthy release-destage world
			 * the post-refresh IN-CORE data already carries every
			 * peer entry.  Rebuild from in-core only: fixes leaf
			 * HOLES (peer hashvals dropped by a stale pinned leaf
			 * relog) without resurrecting deletes.  Disk union
			 * kept behind mxfs_dir_leaf_rebuild=2 for A/B.
			 */
			if (mxfs_dir_leaf_rebuild >= 2 &&
			    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
				uint32_t blen = BBTOB(dbp->b_length);
				uint64_t lba = (uint64_t)xfs_buf_daddr(dbp) +
					mp->m_ddev_targp->bt_sector_offset;

				if (snap && snaplen < blen) {
					kfree(snap);
					snap = NULL;
				}
				if (!snap) {
					snap = ((blen & 511) == 0 && blen) ?
						kmalloc(blen, GFP_NOFS) : NULL;
					snaplen = snap ? blen : 0;
				}
				if (snap &&
				    mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev, lba, snap,
					blen) == 0) {
					struct xfs_dir2_data_hdr *sh = snap;
					__be32 m = sh->magic;

					if (m == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
					    m == cpu_to_be32(XFS_DIR3_DATA_MAGIC)) {
						nent = mxfs_collect_dir_hashes(mp,
							geo, snap, db, kv, kvcap,
							nent);
						if (nent < 0) {
							xfs_trans_brelse(tp, dbp);
							goto overflow_bail;
						}
					}
				}
			}
			xfs_trans_brelse(tp, dbp);
			continue;
overflow_bail:
			/* more entries than the leaf can hold -> node format;
			 * bail without mutating anything. */
			{
				static atomic_t p26o = ATOMIC_INIT(0);
				if (atomic_inc_return(&p26o) <= 60)
					pr_warn("mxfs: P26-REBUILD-BAIL ino=%llu reason=overflow nent=%d max=%d ndb=%d db=%d\n",
						(unsigned long long)dp->i_ino, nent,
						max_ents, ndb, db);
			}
			kfree(snap);
			kfree(kv);
			kfree(bests);
			xfs_trans_brelse(tp, lbp);
			return 0;
		}
		kfree(snap);
	}

	/* Sort by (hashval, address), then write UNIQUE entries (dedup the
	 * in-core/disk overlap) into the leaf -- the XFS leaf entry ordering. */
	sort(kv, nent, sizeof(*kv), mxfs_leaf_kv_cmp, NULL);
	{
		int u = 0;

		for (i = 0; i < nent; i++) {
			if (i > 0 && kv[i] == kv[i - 1])
				continue;	/* same entry from both sources */
			if (u >= max_ents) {
				kfree(kv);
				kfree(bests);
				xfs_trans_brelse(tp, lbp);
				return 0;	/* overflow: bail w/o mutating */
			}
			leafhdr.ents[u].hashval =
				cpu_to_be32((uint32_t)(kv[i] >> 32));
			leafhdr.ents[u].address =
				cpu_to_be32((uint32_t)(kv[i] & 0xffffffffULL));
			u++;
		}
		nent = u;
	}

	/* Overwrite the (possibly pinned) leaf header + bests, then RELOG. */
	leafhdr.count = nent;
	leafhdr.stale = 0;
	xfs_dir2_leaf_hdr_to_disk(mp, leaf, &leafhdr);
	xfs_dir3_leaf_log_header(args, lbp);
	if (nent > 0)
		xfs_dir3_leaf_log_ents(args, &leafhdr, lbp, 0, nent - 1);

	for (db = 0; db < ndb; db++)
		bestsp[db] = bests[db];
	xfs_dir3_leaf_log_bests(args, lbp, 0, ndb - 1);

	{
		static atomic_t p26ok = ATOMIC_INIT(0);
		if (atomic_inc_return(&p26ok) <= 400)
			pr_warn("mxfs: P26-REBUILD-OK ino=%llu nent=%d ndb=%d comm=%s\n",
				(unsigned long long)dp->i_ino, nent, ndb,
				current->comm);
	}
	kfree(kv);
	kfree(bests);
	/* leaf buffer stays joined to tp (logged) -- do NOT brelse it. */
	return 0;
}
#endif /* __KERNEL__ */

STATIC void
xfs_dir3_leaf_find_stale(
	struct xfs_dir3_icleaf_hdr *leafhdr,
	struct xfs_dir2_leaf_entry *ents,
	int			index,
	int			*lowstale,
	int			*highstale)
{
	/*
	 * Find the first stale entry before our index, if any.
	 */
	for (*lowstale = index - 1; *lowstale >= 0; --*lowstale) {
		if (ents[*lowstale].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			break;
	}

	/*
	 * Find the first stale entry at or after our index, if any.
	 * Stop if the result would require moving more entries than using
	 * lowstale.
	 */
	for (*highstale = index; *highstale < leafhdr->count; ++*highstale) {
		if (ents[*highstale].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			break;
		if (*lowstale >= 0 && index - *lowstale <= *highstale - index)
			break;
	}
}

struct xfs_dir2_leaf_entry *
xfs_dir3_leaf_find_entry(
	struct xfs_dir3_icleaf_hdr *leafhdr,
	struct xfs_dir2_leaf_entry *ents,
	int			index,		/* leaf table position */
	int			compact,	/* need to compact leaves */
	int			lowstale,	/* index of prev stale leaf */
	int			highstale,	/* index of next stale leaf */
	int			*lfloglow,	/* low leaf logging index */
	int			*lfloghigh)	/* high leaf logging index */
{
	if (!leafhdr->stale) {
		xfs_dir2_leaf_entry_t	*lep;	/* leaf entry table pointer */

		/*
		 * Now we need to make room to insert the leaf entry.
		 *
		 * If there are no stale entries, just insert a hole at index.
		 */
		lep = &ents[index];
		if (index < leafhdr->count)
			memmove(lep + 1, lep,
				(leafhdr->count - index) * sizeof(*lep));

		/*
		 * Record low and high logging indices for the leaf.
		 */
		*lfloglow = index;
		*lfloghigh = leafhdr->count++;
		return lep;
	}

	/*
	 * There are stale entries.
	 *
	 * We will use one of them for the new entry.  It's probably not at
	 * the right location, so we'll have to shift some up or down first.
	 *
	 * If we didn't compact before, we need to find the nearest stale
	 * entries before and after our insertion point.
	 */
	if (compact == 0)
		xfs_dir3_leaf_find_stale(leafhdr, ents, index,
					 &lowstale, &highstale);

	/*
	 * If the low one is better, use it.
	 */
	if (lowstale >= 0 &&
	    (highstale == leafhdr->count ||
	     index - lowstale - 1 < highstale - index)) {
		ASSERT(index - lowstale - 1 >= 0);
		ASSERT(ents[lowstale].address ==
		       cpu_to_be32(XFS_DIR2_NULL_DATAPTR));

		/*
		 * Copy entries up to cover the stale entry and make room
		 * for the new entry.
		 */
		if (index - lowstale - 1 > 0) {
			memmove(&ents[lowstale], &ents[lowstale + 1],
				(index - lowstale - 1) *
					sizeof(xfs_dir2_leaf_entry_t));
		}
		*lfloglow = min(lowstale, *lfloglow);
		*lfloghigh = max(index - 1, *lfloghigh);
		leafhdr->stale--;
		return &ents[index - 1];
	}

	/*
	 * The high one is better, so use that one.
	 */
	ASSERT(highstale - index >= 0);
	ASSERT(ents[highstale].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR));

	/*
	 * Copy entries down to cover the stale entry and make room for the
	 * new entry.
	 */
	if (highstale - index > 0) {
		memmove(&ents[index + 1], &ents[index],
			(highstale - index) * sizeof(xfs_dir2_leaf_entry_t));
	}
	*lfloglow = min(index, *lfloglow);
	*lfloghigh = max(highstale, *lfloghigh);
	leafhdr->stale--;
	return &ents[index];
}

/*
 * Add an entry to a leaf form directory.
 */
int						/* error */
xfs_dir2_leaf_addname(
	struct xfs_da_args	*args)		/* operation arguments */
{
	struct xfs_dir3_icleaf_hdr leafhdr;
	struct xfs_trans	*tp = args->trans;
	__be16			*bestsp;	/* freespace table in leaf */
	__be16			*tagp;		/* end of data entry */
	struct xfs_buf		*dbp;		/* data block buffer */
	struct xfs_buf		*lbp;		/* leaf's buffer */
	struct xfs_dir2_leaf	*leaf;		/* leaf structure */
	struct xfs_inode	*dp = args->dp;	/* incore directory inode */
	struct xfs_dir2_data_hdr *hdr;		/* data block header */
	struct xfs_dir2_data_entry *dep;	/* data block entry */
	struct xfs_dir2_leaf_entry *lep;	/* leaf entry table pointer */
	struct xfs_dir2_leaf_entry *ents;
	struct xfs_dir2_data_unused *dup;	/* data unused entry */
	struct xfs_dir2_leaf_tail *ltp;		/* leaf tail pointer */
	struct xfs_dir2_data_free *bf;		/* bestfree table */
	int			compact;	/* need to compact leaves */
	int			error;		/* error return value */
	int			grown;		/* allocated new data block */
	int			highstale = 0;	/* index of next stale leaf */
	int			i;		/* temporary, index */
	int			index;		/* leaf table position */
	int			length;		/* length of new entry */
	int			lfloglow;	/* low leaf logging index */
	int			lfloghigh;	/* high leaf logging index */
	int			lowstale = 0;	/* index of prev stale leaf */
	int			needbytes;	/* leaf block bytes needed */
	int			needlog;	/* need to log data header */
	int			needscan;	/* need to rescan data free */
	xfs_dir2_db_t		use_block;	/* data block number */

	trace_xfs_dir2_leaf_addname(args);

	error = xfs_dir3_leaf_read(tp, dp, args->owner, args->geo->leafblk,
			&lbp);
	if (error)
		return error;

	/* sess2(ccloop) ROOT FIX (leaf-HASH side): the data-block epoch refresh
	 * (xfs_dir2_data.c) closed the intra-block free-slot double-alloc, but the
	 * LEAF block (hash index) was still unprotected — a peer's leaf-hash insert
	 * since this leaf's base loaded is invisible, so this node's insert RMWs a
	 * stale leaf and a hash entry is durably dropped (readdir=800 but lookup
	 * ENOENT = leaf-hash hole, then DABUF_MAP_HOLE on the rm node).  Mirror the
	 * data-block fix on the LEAF buffer: if its coherent-read epoch lags the
	 * master handoff epoch (a peer held EX + modified the dir since), cold
	 * re-read it before the hash insert.  CLEAN-only (own dirty/in-AIL-undestaged/
	 * pinned leaf work never dropped).  A leaf is a pure derived index, so a
	 * coherent re-read is loss-safe.  Gated mxfs_dir_addname_epoch_refresh. */
	{
		extern int mxfs_dir_addname_epoch_refresh;
		struct xfs_mount *lmp = dp->i_mount;
		if (mxfs_dir_addname_epoch_refresh && lbp && lmp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(lmp->m_mxfs_dlm) &&
		    !dp->i_dlm_unpublished && (lbp->b_flags & XBF_DONE)) {
			extern uint32_t mxfs_v5_dlm_inode_dir_epoch(
				struct mxfs_v5_dlm *, uint64_t);
			extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *);
			struct xfs_buf_log_item *lbip = lbp->b_log_item;
			bool l_dirty = lbip && test_bit(XFS_LI_DIRTY,
					&lbip->bli_item.li_flags);
			bool l_inail = lbip && test_bit(XFS_LI_IN_AIL,
					&lbip->bli_item.li_flags);
			uint32_t master_ep = mxfs_v5_dlm_inode_dir_epoch(
					lmp->m_mxfs_dlm, dp->i_ino);
			/* sess45: braces — unconditional incarn stamp (see the
			 * xfs_da_btree.c sibling fix). */
			if (master_ep > dp->i_dlm_dir_valid_epoch) {
				dp->i_dlm_dir_valid_epoch = master_ep;
				dp->i_dlm_dir_valid_incarn = VFS_I(dp)->i_generation;	/* sess28: the baseline belongs to THIS incarnation */
			}
			if (master_ep != 0 && lbp->b_mxfs_dir_epoch != 0 &&
			    lbp->b_mxfs_dir_epoch < dp->i_dlm_dir_valid_epoch &&
			    !l_dirty && !xfs_buf_ispinned(lbp) &&
			    !(lbp->b_flags & _XBF_DELWRI_Q) &&
			    !(l_inail && mxfs_dir_buf_is_undestaged(lbp))) {
				pr_warn_ratelimited("mxfs: P2-LEAFHASH-EPOCHSTALE ino=%llu b_ep=%u master_ep=%u — leaf-index epoch-stale; invalidate+reread before hash insert\n",
					(unsigned long long)dp->i_ino,
					lbp->b_mxfs_dir_epoch, master_ep);
				lbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				lbp->b_mxfs_dir_gen = 0;
				xfs_trans_brelse(tp, lbp);
				error = xfs_dir3_leaf_read(tp, dp, args->owner,
						args->geo->leafblk, &lbp);
				if (error)
					return error;
			}
		}
	}

	/*
	 * Look up the entry by hash value and name.
	 * We know it's not there, our caller has already done a lookup.
	 * So the index is of the entry to insert in front of.
	 * But if there are dup hash values the index is of the first of those.
	 */
	index = xfs_dir2_leaf_search_hash(args, lbp);
	leaf = lbp->b_addr;
	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);
	xfs_dir2_leaf_hdr_from_disk(dp->i_mount, &leafhdr, leaf);
	ents = leafhdr.ents;
	bestsp = xfs_dir2_leaf_bests_p(ltp);
	length = xfs_dir2_data_entsize(dp->i_mount, args->namelen);

	/*
	 * See if there are any entries with the same hash value
	 * and space in their block for the new entry.
	 * This is good because it puts multiple same-hash value entries
	 * in a data block, improving the lookup of those entries.
	 */
	for (use_block = -1, lep = &ents[index];
	     index < leafhdr.count && be32_to_cpu(lep->hashval) == args->hashval;
	     index++, lep++) {
		if (be32_to_cpu(lep->address) == XFS_DIR2_NULL_DATAPTR)
			continue;
		i = xfs_dir2_dataptr_to_db(args->geo, be32_to_cpu(lep->address));
		ASSERT(i < be32_to_cpu(ltp->bestcount));
		ASSERT(bestsp[i] != cpu_to_be16(NULLDATAOFF));
		if (be16_to_cpu(bestsp[i]) >= length) {
			use_block = i;
			break;
		}
	}
	/*
	 * Didn't find a block yet, linear search all the data blocks.
	 */
	if (use_block == -1) {
		for (i = 0; i < be32_to_cpu(ltp->bestcount); i++) {
			/*
			 * Remember a block we see that's missing.
			 */
			if (bestsp[i] == cpu_to_be16(NULLDATAOFF) &&
			    use_block == -1)
				use_block = i;
			else if (be16_to_cpu(bestsp[i]) >= length) {
				use_block = i;
				break;
			}
		}
	}
	/*
	 * How many bytes do we need in the leaf block?
	 */
	needbytes = 0;
	if (!leafhdr.stale)
		needbytes += sizeof(xfs_dir2_leaf_entry_t);
	if (use_block == -1)
		needbytes += sizeof(xfs_dir2_data_off_t);

	/*
	 * Now kill use_block if it refers to a missing block, so we
	 * can use it as an indication of allocation needed.
	 */
	if (use_block != -1 && bestsp[use_block] == cpu_to_be16(NULLDATAOFF))
		use_block = -1;
	/* sess2 (a9a03929) P2U-LEAF-USEBLK: fires ONLY when the bests array
	 * steers this insert at a data block the dir's own size says cannot
	 * exist (run49 MAP_HOLE root: a prior-incarnation leaf image consulted
	 * under a same-incarnation dinode with disize=1 block).  Captures the
	 * leaf buffer's provenance at the moment of use, before the create
	 * walks into the hole. */
	if (use_block != -1 &&
	    use_block >= (xfs_dir2_db_t)xfs_dir2_byte_to_db(args->geo,
							    dp->i_disk_size)) {
		struct xfs_buf_log_item *p2bip = lbp->b_log_item;

		pr_warn("mxfs: P2U-LEAF-USEBLK ino=%llu use_block=%d bestcount=%u disize=%lld bflags=0x%x ep=%u valid_ep=%u dirty=%d inail=%d pin=%d lsn=%llu comm=%s\n",
			(unsigned long long)dp->i_ino, (int)use_block,
			be32_to_cpu(ltp->bestcount),
			(long long)dp->i_disk_size,
			lbp->b_flags, lbp->b_mxfs_dir_epoch,
			dp->i_dlm_dir_valid_epoch,
			p2bip && test_bit(XFS_LI_DIRTY,
					  &p2bip->bli_item.li_flags) ? 1 : 0,
			p2bip && test_bit(XFS_LI_IN_AIL,
					  &p2bip->bli_item.li_flags) ? 1 : 0,
			xfs_buf_ispinned(lbp) ? 1 : 0,
			(unsigned long long)be64_to_cpu(
				((struct xfs_da3_blkinfo *)lbp->b_addr)->lsn),
			current->comm);
	}
	/*
	 * If we don't have enough free bytes but we can make enough
	 * by compacting out stale entries, we'll do that.
	 */
	if ((char *)bestsp - (char *)&ents[leafhdr.count] < needbytes &&
	    leafhdr.stale > 1)
		compact = 1;

	/*
	 * Otherwise if we don't have enough free bytes we need to
	 * convert to node form.
	 */
	else if ((char *)bestsp - (char *)&ents[leafhdr.count] < needbytes) {
		/*
		 * Just checking or no space reservation, give up.
		 */
		if ((args->op_flags & XFS_DA_OP_JUSTCHECK) ||
							args->total == 0) {
			xfs_trans_brelse(tp, lbp);
			return -ENOSPC;
		}
		/*
		 * Convert to node form.
		 */
		error = xfs_dir2_leaf_to_node(args, lbp);
		if (error)
			return error;
		/*
		 * Then add the new entry.
		 */
		return xfs_dir2_node_addname(args);
	}
	/*
	 * Otherwise it will fit without compaction.
	 */
	else
		compact = 0;
	/*
	 * If just checking, then it will fit unless we needed to allocate
	 * a new data block.
	 */
	if (args->op_flags & XFS_DA_OP_JUSTCHECK) {
		xfs_trans_brelse(tp, lbp);
		return use_block == -1 ? -ENOSPC : 0;
	}
	/*
	 * If no allocations are allowed, return now before we've
	 * changed anything.
	 */
	if (args->total == 0 && use_block == -1) {
		xfs_trans_brelse(tp, lbp);
		return -ENOSPC;
	}
	/*
	 * Need to compact the leaf entries, removing stale ones.
	 * Leave one stale entry behind - the one closest to our
	 * insertion index - and we'll shift that one to our insertion
	 * point later.
	 */
	if (compact) {
		xfs_dir3_leaf_compact_x1(&leafhdr, ents, &index, &lowstale,
			&highstale, &lfloglow, &lfloghigh);
	}
	/*
	 * There are stale entries, so we'll need log-low and log-high
	 * impossibly bad values later.
	 */
	else if (leafhdr.stale) {
		lfloglow = leafhdr.count;
		lfloghigh = -1;
	}
	/*
	 * If there was no data block space found, we need to allocate
	 * a new one.
	 */
	if (use_block == -1) {
		/*
		 * Add the new data block.
		 */
		if ((error = xfs_dir2_grow_inode(args, XFS_DIR2_DATA_SPACE,
				&use_block))) {
			xfs_trans_brelse(tp, lbp);
			return error;
		}
		/*
		 * Initialize the block.
		 */
		if ((error = xfs_dir3_data_init(args, use_block, &dbp))) {
			xfs_trans_brelse(tp, lbp);
			return error;
		}
		/*
		 * If we're adding a new data block on the end we need to
		 * extend the bests table.  Copy it up one entry.
		 */
		if (use_block >= be32_to_cpu(ltp->bestcount)) {
			bestsp--;
			memmove(&bestsp[0], &bestsp[1],
				be32_to_cpu(ltp->bestcount) * sizeof(bestsp[0]));
			be32_add_cpu(&ltp->bestcount, 1);
			xfs_dir3_leaf_log_tail(args, lbp);
			xfs_dir3_leaf_log_bests(args, lbp, 0,
						be32_to_cpu(ltp->bestcount) - 1);
		}
		/*
		 * If we're filling in a previously empty block just log it.
		 */
		else
			xfs_dir3_leaf_log_bests(args, lbp, use_block, use_block);
		hdr = dbp->b_addr;
		bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);
		bestsp[use_block] = bf[0].length;
		grown = 1;
	} else {
		/*
		 * Already had space in some data block.
		 * Just read that one in.
		 */
		error = xfs_dir3_data_read(tp, dp, args->owner,
				xfs_dir2_db_to_da(args->geo, use_block), 0,
				&dbp);
		if (error) {
			xfs_trans_brelse(tp, lbp);
			return error;
		}
		hdr = dbp->b_addr;
		bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);
		grown = 0;
	}
	/* sess28: read-side staleness fix — if the CLEAN existing data block is
	 * stale vs the durable platter (grown=0 only; a freshly-grown block is
	 * legitimately empty), invalidate + cold re-read it through the verifier so
	 * bestfree reflects a peer's durable add and use_free does not overwrite
	 * it.  Re-read in place (no leaf-state restart needed). */
	if (!grown) {
		extern int mxfs_dir_addname_coherent_refresh(
			struct xfs_da_args *, struct xfs_buf *);
		if (mxfs_dir_addname_coherent_refresh(args, dbp)) {
			xfs_trans_brelse(tp, dbp);
			error = xfs_dir3_data_read(tp, dp, args->owner,
					xfs_dir2_db_to_da(args->geo, use_block),
					0, &dbp);
			if (error) {
				xfs_trans_brelse(tp, lbp);
				return error;
			}
			hdr = dbp->b_addr;
			bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);
		}
	}
	/*
	 * Point to the biggest freespace in our data block.
	 */
	dup = (xfs_dir2_data_unused_t *)
	      ((char *)hdr + be16_to_cpu(bf[0].offset));
	needscan = needlog = 0;
	/*
	 * Mark the initial part of our freespace in use for the new entry.
	 */
	error = xfs_dir2_data_use_free(args, dbp, dup,
			(xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr),
			length, &needlog, &needscan);
	if (error) {
		xfs_trans_brelse(tp, lbp);
		return error;
	}
	/*
	 * Initialize our new entry (at last).
	 */
	dep = (xfs_dir2_data_entry_t *)dup;
	dep->inumber = cpu_to_be64(args->inumber);
	dep->namelen = args->namelen;
	memcpy(dep->name, args->name, dep->namelen);
	xfs_dir2_data_put_ftype(dp->i_mount, dep, args->filetype);
	tagp = xfs_dir2_data_entry_tag_p(dp->i_mount, dep);
	*tagp = cpu_to_be16((char *)dep - (char *)hdr);
	/*
	 * sess13run (RULE 4): leaf-addname placement trace for the storm dir.
	 * P13-COLLIDE proved entries land at off=64 (first slot) — i.e. the data
	 * block's bestfree says it is near-EMPTY.  Distinguish a freshly-GROWN
	 * block (grown=1, legitimately empty) from a REUSED existing block
	 * (grown=0) that xfs_dir3_data_read at L1168 returned as near-empty = a
	 * STALE/reverted read of a block that should be full (the dir_reuse loss
	 * smoking gun).  bf0len = biggest freespace; a reused block with a huge
	 * bf0len is the stale-empty read.  Always-on, storm-dir scoped. */
	if (mxfs_ino_watched(dp->i_ino) && args->namelen >= 4 &&
	    args->name[0] == 'n' && args->name[1] == 'o') {
		uint32_t aoff = (uint32_t)((char *)dep - (char *)hdr);
		uint32_t bf0 = be16_to_cpu(bf[0].length);
		/* sess42(ccloop) RULE-4: ALWAYS-ON leaf-format placement trace,
		 * the leaf-path twin of P13-NADD (node format).  PROVEN this run:
		 * the insert-loss victim (node8_f14.md5) is added in LEAF format
		 * (no P13-NADD), then dropped before its DATA block is durable.
		 * Capture the exact (data daddr, aoff) so the loss is traced to
		 * its placement block and the release-drain coverage checked
		 * against it.  Storm-dir scoped + node* names, ratelimited. */
		{
		/* sess43: capped (not ratelimited) — capture the full failing
		 * round's create wave so the victim's placement block is logged. */
		static atomic_t p13l = ATOMIC_INIT(0);
		if (atomic_inc_return(&p13l) <= 60000)
		pr_warn("mxfs: P13-LADD ino=%llu use_block=%d daddr=%lld aoff=%u grown=%d name=[%.*s] comm=%s realns=%llu\n",
			(unsigned long long)dp->i_ino, use_block,
			(long long)dbp->b_maps[0].bm_bn, aoff, grown,
			(int)args->namelen, args->name, current->comm,
			(unsigned long long)ktime_get_real_ns());
		}
		if (grown == 0 && bf0 >= (BBTOB(dbp->b_length) / 2))
			pr_warn_ratelimited("mxfs: P13-STALEREAD ino=%llu use_block=%d daddr=%lld aoff=%u bf0len=%u name=[%.*s] comm=%s — REUSED data block read near-EMPTY (stale/reverted read of a should-be-full block)\n",
				(unsigned long long)dp->i_ino, use_block,
				(long long)dbp->b_maps[0].bm_bn, aoff, bf0,
				(int)args->namelen, args->name, current->comm);
	}
	/*
	 * Need to scan fix up the bestfree table.
	 */
	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	/*
	 * Need to log the data block's header.
	 */
	if (needlog)
		xfs_dir2_data_log_header(args, dbp);
	xfs_dir2_data_log_entry(args, dbp, dep);
	/*
	 * If the bests table needs to be changed, do it.
	 * Log the change unless we've already done that.
	 */
	if (be16_to_cpu(bestsp[use_block]) != be16_to_cpu(bf[0].length)) {
		bestsp[use_block] = bf[0].length;
		if (!grown)
			xfs_dir3_leaf_log_bests(args, lbp, use_block, use_block);
	}

	lep = xfs_dir3_leaf_find_entry(&leafhdr, ents, index, compact, lowstale,
				       highstale, &lfloglow, &lfloghigh);

	/*
	 * Fill in the new leaf entry.
	 */
	lep->hashval = cpu_to_be32(args->hashval);
	lep->address = cpu_to_be32(
				xfs_dir2_db_off_to_dataptr(args->geo, use_block,
				be16_to_cpu(*tagp)));
	/*
	 * Log the leaf fields and give up the buffers.
	 */
	xfs_dir2_leaf_hdr_to_disk(dp->i_mount, leaf, &leafhdr);
	xfs_dir3_leaf_log_header(args, lbp);
	xfs_dir3_leaf_log_ents(args, &leafhdr, lbp, lfloglow, lfloghigh);
	xfs_dir3_leaf_check(dp, lbp);
	xfs_dir3_data_check(dp, dbp);
	return 0;
}

/*
 * Compact out any stale entries in the leaf.
 * Log the header and changed leaf entries, if any.
 */
void
xfs_dir3_leaf_compact(
	xfs_da_args_t	*args,		/* operation arguments */
	struct xfs_dir3_icleaf_hdr *leafhdr,
	struct xfs_buf	*bp)		/* leaf buffer */
{
	int		from;		/* source leaf index */
	xfs_dir2_leaf_t	*leaf;		/* leaf structure */
	int		loglow;		/* first leaf entry to log */
	int		to;		/* target leaf index */
	struct xfs_inode *dp = args->dp;

	leaf = bp->b_addr;
	if (!leafhdr->stale)
		return;

	/*
	 * Compress out the stale entries in place.
	 */
	for (from = to = 0, loglow = -1; from < leafhdr->count; from++) {
		if (leafhdr->ents[from].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			continue;
		/*
		 * Only actually copy the entries that are different.
		 */
		if (from > to) {
			if (loglow == -1)
				loglow = to;
			leafhdr->ents[to] = leafhdr->ents[from];
		}
		to++;
	}
	/*
	 * Update and log the header, log the leaf entries.
	 */
	ASSERT(leafhdr->stale == from - to);
	leafhdr->count -= leafhdr->stale;
	leafhdr->stale = 0;

	xfs_dir2_leaf_hdr_to_disk(dp->i_mount, leaf, leafhdr);
	xfs_dir3_leaf_log_header(args, bp);
	if (loglow != -1)
		xfs_dir3_leaf_log_ents(args, leafhdr, bp, loglow, to - 1);
}

/*
 * Compact the leaf entries, removing stale ones.
 * Leave one stale entry behind - the one closest to our
 * insertion index - and the caller will shift that one to our insertion
 * point later.
 * Return new insertion index, where the remaining stale entry is,
 * and leaf logging indices.
 */
void
xfs_dir3_leaf_compact_x1(
	struct xfs_dir3_icleaf_hdr *leafhdr,
	struct xfs_dir2_leaf_entry *ents,
	int		*indexp,	/* insertion index */
	int		*lowstalep,	/* out: stale entry before us */
	int		*highstalep,	/* out: stale entry after us */
	int		*lowlogp,	/* out: low log index */
	int		*highlogp)	/* out: high log index */
{
	int		from;		/* source copy index */
	int		highstale;	/* stale entry at/after index */
	int		index;		/* insertion index */
	int		keepstale;	/* source index of kept stale */
	int		lowstale;	/* stale entry before index */
	int		newindex=0;	/* new insertion index */
	int		to;		/* destination copy index */

	ASSERT(leafhdr->stale > 1);
	index = *indexp;

	xfs_dir3_leaf_find_stale(leafhdr, ents, index, &lowstale, &highstale);

	/*
	 * Pick the better of lowstale and highstale.
	 */
	if (lowstale >= 0 &&
	    (highstale == leafhdr->count ||
	     index - lowstale <= highstale - index))
		keepstale = lowstale;
	else
		keepstale = highstale;
	/*
	 * Copy the entries in place, removing all the stale entries
	 * except keepstale.
	 */
	for (from = to = 0; from < leafhdr->count; from++) {
		/*
		 * Notice the new value of index.
		 */
		if (index == from)
			newindex = to;
		if (from != keepstale &&
		    ents[from].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR)) {
			if (from == to)
				*lowlogp = to;
			continue;
		}
		/*
		 * Record the new keepstale value for the insertion.
		 */
		if (from == keepstale)
			lowstale = highstale = to;
		/*
		 * Copy only the entries that have moved.
		 */
		if (from > to)
			ents[to] = ents[from];
		to++;
	}
	ASSERT(from > to);
	/*
	 * If the insertion point was past the last entry,
	 * set the new insertion point accordingly.
	 */
	if (index == from)
		newindex = to;
	*indexp = newindex;
	/*
	 * Adjust the leaf header values.
	 */
	leafhdr->count -= from - to;
	leafhdr->stale = 1;
	/*
	 * Remember the low/high stale value only in the "right"
	 * direction.
	 */
	if (lowstale >= newindex)
		lowstale = -1;
	else
		highstale = leafhdr->count;
	*highlogp = leafhdr->count - 1;
	*lowstalep = lowstale;
	*highstalep = highstale;
}

/*
 * Log the bests entries indicated from a leaf1 block.
 */
static void
xfs_dir3_leaf_log_bests(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,		/* leaf buffer */
	int			first,		/* first entry to log */
	int			last)		/* last entry to log */
{
	__be16			*firstb;	/* pointer to first entry */
	__be16			*lastb;		/* pointer to last entry */
	struct xfs_dir2_leaf	*leaf = bp->b_addr;
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */

	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC));

	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);
	firstb = xfs_dir2_leaf_bests_p(ltp) + first;
	lastb = xfs_dir2_leaf_bests_p(ltp) + last;
	xfs_trans_log_buf(args->trans, bp,
		(uint)((char *)firstb - (char *)leaf),
		(uint)((char *)lastb - (char *)leaf + sizeof(*lastb) - 1));
}

/*
 * Log the leaf entries indicated from a leaf1 or leafn block.
 */
void
xfs_dir3_leaf_log_ents(
	struct xfs_da_args	*args,
	struct xfs_dir3_icleaf_hdr *hdr,
	struct xfs_buf		*bp,
	int			first,
	int			last)
{
	xfs_dir2_leaf_entry_t	*firstlep;	/* pointer to first entry */
	xfs_dir2_leaf_entry_t	*lastlep;	/* pointer to last entry */
	struct xfs_dir2_leaf	*leaf = bp->b_addr;

	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC));

	firstlep = &hdr->ents[first];
	lastlep = &hdr->ents[last];
	xfs_trans_log_buf(args->trans, bp,
		(uint)((char *)firstlep - (char *)leaf),
		(uint)((char *)lastlep - (char *)leaf + sizeof(*lastlep) - 1));
}

/*
 * Log the header of the leaf1 or leafn block.
 */
void
xfs_dir3_leaf_log_header(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp)
{
	struct xfs_dir2_leaf	*leaf = bp->b_addr;

	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC));

	xfs_trans_log_buf(args->trans, bp,
			  (uint)((char *)&leaf->hdr - (char *)leaf),
			  args->geo->leaf_hdr_size - 1);

	/* sess16(ccloop): MODIFY-time coherent-tenure stamp on the LEAF block (see
	 * xfs_dir2_data_log_entry) — current-tenure leaf work carries the current
	 * handoff epoch so the prior-tenure evict override never reverts it. */
	if (args->dp)
		bp->b_mxfs_dir_epoch = args->dp->i_dlm_dir_valid_epoch;
}

/*
 * Log the tail of the leaf1 block.
 */
STATIC void
xfs_dir3_leaf_log_tail(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp)
{
	struct xfs_dir2_leaf	*leaf = bp->b_addr;
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */

	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAF1_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
	       leaf->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC));

	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);
	xfs_trans_log_buf(args->trans, bp, (uint)((char *)ltp - (char *)leaf),
		(uint)(args->geo->blksize - 1));
}

#ifdef __KERNEL__
/*
 * sess22 (ccloop 8ddb16a2) AUTHORITATIVE DATA-SCAN LOOKUP FALLBACK.
 *
 * The shared LEAF1 hash index is a DERIVED structure; the DATA blocks are the
 * authoritative dirent store and ARE coherent across nodes (readdir lists every
 * name on every node).  Under dir-inode REUSE churn the perpetually-pinned leaf
 * can durably lose a peer's MOST-RECENT hash entry: the rebuild that last
 * destaged the leaf reconstructed it from data that did not yet include the
 * peer's final add (the add was in the peer's CIL, not yet on the LUN at rebuild
 * time), and that stale-derived leaf clobbered the good one at release-destage.
 * readdir still lists the name (its dirent IS in a coherent data block) but the
 * hash-index lookup ENOENTs (the dir_reuse_coherency "node2_f50.md5" hole, the
 * LAST entry the peer wrote each round).
 *
 * When the hash-index lookup misses on a multi-node dir, fall back to a linear
 * scan of the AUTHORITATIVE data blocks so lookup is correct regardless of leaf
 * staleness.  This runs ONLY on an ENOENT — every successful hash lookup returns
 * before reaching here, so the hot path is untouched; a genuine negative lookup
 * pays one O(dir) data walk (data blocks are usually already cached).  Returns
 * the same convention as xfs_dir2_leaf_lookup's tail: xfs_dir_cilookup_result()
 * => -EEXIST when found (xfs_dir_lookup_args maps -EEXIST -> 0), -ENOENT if the
 * name is genuinely absent from the data blocks too.
 *
 * sess22(ccloop): non-static so xfs_dir2_node_lookup (node/BTREE-format dirs)
 * can also route its -ENOENT through this leaf-hash-hole heal.
 */
int
mxfs_dir2_datascan_lookup(
	struct xfs_da_args	*args)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo = args->geo;
	struct xfs_trans	*tp = args->trans;
	struct xfs_buf		*dbp = NULL;
	int			ndb, db, error;
	int			ci_found = 0, ci_namelen = 0;
	int			scanned = 0;	/* sess27: live dirents the scan saw */
	unsigned char		ci_name[256];

	/*
	 * sess29 (ccloop 8ddb16a2): reset args->cmpresult before scanning.  The
	 * FAILED leaf lookup (xfs_dir2_leaf_lookup_int) that routed us here can
	 * leave args->cmpresult == XFS_CMP_EXACT (it sets it on a candidate
	 * before returning -ENOENT).  The scan's match gate below is
	 * `cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult` — so a stale
	 * EXACT makes an EXACT match for the present dirent SKIP (cmp ==
	 * args->cmpresult) and the datascan MISSES a dirent it physically sees
	 * (the leaf-hash-hole "match/encoding bug" face, scanned~=EXP).  Reset to
	 * XFS_CMP_DIFFERENT so the first real match is always taken.
	 */
	args->cmpresult = XFS_CMP_DIFFERENT;

	/*
	 * sess22(ccloop): heal the leaf-hash hole for NODE/BTREE-format dirs too,
	 * not just single-leaf EXTENTS.  A large multi-node churn dir (dir_reuse's
	 * 800-entry shared dir) grows to BTREE format; its leaf-hash hole was left
	 * UNHEALED because this scan bailed on any non-EXTENTS fork.  The scan body
	 * below reads DATA blocks through the bmap (xfs_dir2_db_to_da ->
	 * xfs_da_read_buf) and walks the in-core extent list — both work for a
	 * BTREE fork once its extents are loaded (always true here: the failed
	 * xfs_da3_node_lookup_int that routed us in just traversed the dir through
	 * those same extents).  Only bail when the extents are NOT in core (cannot
	 * scan) or the dir is shortform/local (no separate data blocks).
	 */
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE) {
		if (xfs_need_iread_extents(&dp->i_df))
			return -ENOENT;	/* extents not loaded: cannot scan */
	} else if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS) {
		return -ENOENT;		/* shortform / local: no data blocks */
	}

	/*
	 * sess27 (ccloop 8ddb16a2): derive the data-block count from the in-core
	 * data-fork EXTENT MAP (the same blocks readdir enumerates), NOT
	 * di_size/blksize.  A STALE/small di_size at lookup time under-scans and
	 * misses a higher DATA block that readdir lists — leaving the leaf-hash
	 * hole UNHEALED (P26-DSCAN ran but P22-DATASCAN-HIT=0 = under-scan).  The
	 * DATA blocks live at logical fsb offsets [0, geo->leafblk); the LEAF/free
	 * index sit at/above XFS_DIR2_LEAF_OFFSET.  Walk the extents and take the
	 * highest data-region block so the scan below covers every data block.
	 */
	{
		struct xfs_iext_cursor	icur;
		struct xfs_bmbt_irec	got;
		xfs_fileoff_t		maxoff = 0;

		for_each_xfs_iext(&dp->i_df, &icur, &got) {
			xfs_fileoff_t	end;

			if (got.br_startblock == HOLESTARTBLOCK)
				continue;
			if (got.br_startoff >= geo->leafblk)
				continue;	/* leaf / free-index region */
			end = got.br_startoff + got.br_blockcount;
			if (end > geo->leafblk)
				end = geo->leafblk;
			if (end > maxoff)
				maxoff = end;
		}
		ndb = (int)(maxoff / geo->fsbcount);
	}
	if (ndb <= 0)
		return -ENOENT;
	pr_warn_ratelimited("mxfs: P26-DSCAN ino=%llu ndb=%d size=%llu fmt=%u name=\"%.*s\"\n",
			(unsigned long long)dp->i_ino, ndb,
			(unsigned long long)dp->i_disk_size, dp->i_df.if_format,
			args->namelen, args->name);

	for (db = 0; db < ndb; db++) {
		struct xfs_dir2_data_hdr *hdr;
		unsigned int		offset, end;

		/* sess5 (46efd8b6): HOLE_OK is load-bearing — a churned shared
		 * dir is legally SPARSE (shrink frees middle data blocks), and
		 * without the flag every hole this scan touches raises
		 * xfs_corruption_error + marks the dir sick (PROVEN test4
		 * 094029Z: dscan over the rv dir's holes → EFSCORRUPTED storm
		 * → mv wave dies → node4's renames invisible cluster-wide). */
		error = xfs_dir3_data_read(tp, dp, args->owner,
					   xfs_dir2_db_to_da(geo, db),
					   XFS_DABUF_MAP_HOLE_OK, &dbp);
		if (error || !dbp)
			continue;	/* hole / transient: keep scanning */
		hdr = dbp->b_addr;
		offset = geo->data_entry_offset;
		end = xfs_dir3_data_end_offset(geo, hdr);
		while (offset < end) {
			struct xfs_dir2_data_unused	*dup =
				(void *)((char *)hdr + offset);
			struct xfs_dir2_data_entry	*dep =
				(void *)((char *)hdr + offset);
			enum xfs_dacmp			cmp;

			if (be16_to_cpu(dup->freetag) ==
			    XFS_DIR2_DATA_FREE_TAG) {
				offset += be16_to_cpu(dup->length);
				continue;
			}
			scanned++;	/* sess27: a live dirent the scan visited */
			cmp = xfs_dir2_compname(args, dep->name, dep->namelen);
			if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
				args->cmpresult = cmp;
				args->inumber = be64_to_cpu(dep->inumber);
				args->filetype =
					xfs_dir2_data_get_ftype(mp, dep);
				if (cmp == XFS_CMP_EXACT) {
					int rv = xfs_dir_cilookup_result(args,
						dep->name, dep->namelen);

					pr_warn_ratelimited("mxfs: P22-DATASCAN-HIT ino=%llu name=\"%.*s\" inum=%llu db=%d/%d (leaf-hash hole healed)\n",
							(unsigned long long)dp->i_ino,
							args->namelen, args->name,
							(unsigned long long)args->inumber,
							db, ndb);
					xfs_trans_brelse(tp, dbp);
					return rv;
				}
				/* first case-insensitive match: remember it */
				if (dep->namelen <= sizeof(ci_name)) {
					memcpy(ci_name, dep->name, dep->namelen);
					ci_namelen = dep->namelen;
					ci_found = 1;
				}
			}
			offset += xfs_dir2_data_entsize(mp, dep->namelen);
		}
		xfs_trans_brelse(tp, dbp);
		dbp = NULL;
	}

	if (ci_found && args->cmpresult == XFS_CMP_CASE)
		return xfs_dir_cilookup_result(args, ci_name, ci_namelen);
	/*
	 * sess33 (ccloop 8ddb16a2) P33-DSCAN-ONDISK DECISIVE DISCRIMINATOR
	 * (RULE 4): a leaf-referenced name is in NO data block this node's
	 * in-core extent map covers (ndb too small).  Is the ON-DISK dinode
	 * itself missing the higher data block (durability/checkpoint gap —
	 * the inode extent-map growth never reached the platter), or does the
	 * platter dinode map it and the in-core rebuild/FUA-read diverged?
	 * Plain coherent disk read of THIS dir inode's cluster, report the
	 * platter dinode's format/nextents/size vs in-core.  Capped.
	 */
	{
		static DEFINE_RATELIMIT_STATE(mxfs_p33_rs, 5 * HZ, 30);

		ratelimit_set_flags(&mxfs_p33_rs, RATELIMIT_MSG_ON_RELEASE);
		if (mp->m_mxfs_dlm &&
		    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev &&
		    __ratelimit(&mxfs_p33_rs)) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *, uint32_t);
			uint32_t clen = (uint32_t)dp->i_imap.im_len << 9;
			void *cb = (clen && clen <= 65536) ?
				kmalloc(clen, GFP_NOFS) : NULL;
			int rrc = (cb) ? mxfs_pal_bdev_read_plain_bdev(
			    mp->m_ddev_targp->bt_bdev,
			    (uint64_t)dp->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset,
			    cb, clen) : -9999;

			if (rrc == 0) {
				struct xfs_dinode *ddi =
					(struct xfs_dinode *)((char *)cb +
						dp->i_imap.im_boffset);
				uint64_t big_nx = be64_to_cpu(ddi->di_big_nextents);
				uint32_t nx32 = be32_to_cpu(ddi->di_nextents);
				uint64_t fl2 = be64_to_cpu(ddi->di_flags2);
				uint64_t disk_nx = (fl2 & XFS_DIFLAG2_NREXT64) ?
					big_nx : nx32;

				pr_warn("mxfs: P33-DSCAN-ONDISK ino=%llu name=\"%.*s\" incore_fmt=%u incore_nx=%llu incore_size=%lld incore_gen=%u ndb=%d || disk_magic=0x%04x disk_fmt=%u disk_nx=%llu disk_size=%lld disk_gen=%u sameincarn=%d — disk smaller=durability/torn-disk; incore bigger=read rebuilt larger than disk\n",
					(unsigned long long)dp->i_ino,
					args->namelen, args->name,
					dp->i_df.if_format,
					(unsigned long long)dp->i_df.if_nextents,
					(long long)dp->i_disk_size,
					(unsigned)VFS_I(dp)->i_generation, ndb,
					be16_to_cpu(ddi->di_magic),
					ddi->di_format,
					(unsigned long long)disk_nx,
					(long long)be64_to_cpu(ddi->di_size),
					be32_to_cpu(ddi->di_gen),
					be32_to_cpu(ddi->di_gen) == VFS_I(dp)->i_generation);
			} else {
				pr_warn("mxfs: P33-DSCAN-ONDISK-FAIL ino=%llu rrc=%d clen=%u im_len=%u im_blkno=%llu im_boffset=%u incore_fmt=%u incore_nx=%llu ndb=%d\n",
					(unsigned long long)dp->i_ino, rrc, clen,
					(unsigned)dp->i_imap.im_len,
					(unsigned long long)dp->i_imap.im_blkno,
					(unsigned)dp->i_imap.im_boffset,
					dp->i_df.if_format,
					(unsigned long long)dp->i_df.if_nextents,
					ndb);
			}
			if (cb)
				kfree(cb);
		}
	}
	pr_warn_ratelimited("mxfs: P26-DSCAN-MISS ino=%llu ndb=%d scanned=%d name=\"%.*s\" (not in any data block; scanned=#live dirents seen — ~200=>match/encoding bug, <200=>under-read)\n",
			(unsigned long long)dp->i_ino, ndb, scanned,
			args->namelen, args->name);
	/*
	 * sess1 (ccloop 46efd8b6) datascan gen-gate: this scan walked EVERY
	 * data block and found nothing the leaf missed — the hash index is
	 * ENOENT-consistent at the current coherency state.  Record the state
	 * key so further misses at this state skip the O(dir) scan (the gate
	 * at the callers).  Any peer modify moves the epoch/gen; any real
	 * fork adopt resets the key to the ~0 sentinel.
	 */
	dp->i_mxfs_dscan_clean_key = mxfs_dscan_state_key(dp);
	return -ENOENT;
}

/*
 * sess5 (ccloop 46efd8b6) LEAFLESS REMOVE — the write-side twin of the
 * datascan lookup heal above.  PROVEN uv-ghost chain (32/caw cache_coherency
 * run 084821Z + raw platter decode): the concurrent create wave loses leaf
 * hash entries (P21H-LEAFHOLE fires at create time for whole per-node file
 * ranges while their data dirents + inodes are live).  The unlink of such a
 * hole-name then ENOENTs at the leaf lookup, the remove transaction aborts,
 * `rm -f` swallows the error, and the file survives as a LEAFLESS GHOST:
 * dirent bytes live in a data block no leaf entry references (platter
 * decode: leaf count=0 while db2 still carried node15_file15..30 = the
 * "uv none remain got=16" failure), kept visible by the datascan heal.
 *
 * Heal the REMOVE the same way the lookup is healed: scan the data blocks
 * for the exact-match dirent and expunge it data-side (make_free + freescan
 * + log).  No leaf entry exists, so no leaf/freeindex update is needed; the
 * stored bests/free entries for this block can only UNDERSTATE its free
 * space afterward (benign: addname may skip a usable block — never the
 * corrupting overstatement).  Block-empty shrink is deliberately skipped
 * (an empty unreferenced data block is legal, space-only).  Returning 0
 * lets the caller's transaction complete so the inode unlink proceeds —
 * the ghost is fully reaped.  Multinode only, and only after the leaf
 * lookup said ENOENT.
 */
int
mxfs_dir2_leafless_removename(
	xfs_da_args_t		*args)
{
	struct xfs_mount	*mp = args->dp->i_mount;
	struct xfs_da_geometry	*geo = args->geo;
	struct xfs_inode	*dp = args->dp;
	struct xfs_trans	*tp = args->trans;
	struct xfs_buf		*dbp = NULL;
	int			ndb, db, error;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return -ENOENT;
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE) {
		if (xfs_need_iread_extents(&dp->i_df))
			return -ENOENT;
	} else if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS)
		return -ENOENT;

	/* highest data-region block, from the in-core extent map (same
	 * derivation as the datascan above) */
	{
		struct xfs_iext_cursor	icur;
		struct xfs_bmbt_irec	got;
		xfs_fileoff_t		maxoff = 0;

		for_each_xfs_iext(&dp->i_df, &icur, &got) {
			xfs_fileoff_t	end;

			if (got.br_startblock == HOLESTARTBLOCK)
				continue;
			if (got.br_startoff >= geo->leafblk)
				continue;
			end = got.br_startoff + got.br_blockcount;
			if (end > geo->leafblk)
				end = geo->leafblk;
			if (end > maxoff)
				maxoff = end;
		}
		ndb = (int)(maxoff / geo->fsbcount);
	}

	for (db = 0; db < ndb; db++) {
		struct xfs_dir2_data_hdr *hdr;
		unsigned int	offset, end;

		/* sess5: HOLE_OK — the dir is legally sparse mid-churn; a bare
		 * hole read raises xfs_corruption_error (see datascan above). */
		error = xfs_dir3_data_read(tp, dp, args->owner,
					   xfs_dir2_db_to_da(geo, db),
					   XFS_DABUF_MAP_HOLE_OK, &dbp);
		if (error || !dbp)
			continue;	/* hole / transient: keep scanning */
		hdr = dbp->b_addr;
		offset = geo->data_entry_offset;
		end = xfs_dir3_data_end_offset(geo, hdr);
		while (offset < end) {
			struct xfs_dir2_data_unused *dup =
				(void *)((char *)hdr + offset);
			struct xfs_dir2_data_entry *dep =
				(void *)((char *)hdr + offset);

			if (be16_to_cpu(dup->freetag) ==
			    XFS_DIR2_DATA_FREE_TAG) {
				uint16_t l = be16_to_cpu(dup->length);

				if (l < sizeof(*dup))
					break;
				offset += l;
				continue;
			}
			if (dep->namelen == 0 || dep->namelen > MAXNAMELEN)
				break;
			if (dep->namelen == args->namelen &&
			    memcmp(dep->name, args->name,
				   args->namelen) == 0) {
				int needlog = 0, needscan = 0;

				/* name matches but the bound inode differs =
				 * a foreign-incarnation ghost; the txn's
				 * inode accounting wouldn't match — leave it
				 * for a later matching unlink. */
				if (args->inumber != 0 &&
				    be64_to_cpu(dep->inumber) !=
				    args->inumber) {
					pr_warn_ratelimited(
					    "mxfs: P73-LEAFLESS-RM-SKIP ino=%llu name=\"%.*s\" dep_ino=%llu arg_ino=%llu db=%d — name match, inode mismatch\n",
					    (unsigned long long)dp->i_ino,
					    args->namelen, args->name,
					    (unsigned long long)be64_to_cpu(
						dep->inumber),
					    (unsigned long long)args->inumber,
					    db);
					offset += xfs_dir2_data_entsize(mp,
						dep->namelen);
					continue;
				}
				xfs_dir2_data_make_free(args, dbp,
					(xfs_dir2_data_aoff_t)offset,
					xfs_dir2_data_entsize(mp,
						dep->namelen),
					&needlog, &needscan);
				if (needscan)
					xfs_dir2_data_freescan(mp, hdr,
							       &needlog);
				if (needlog)
					xfs_dir2_data_log_header(args, dbp);
				xfs_dir3_data_check(dp, dbp);
				pr_warn_ratelimited(
				    "mxfs: P73-LEAFLESS-RM ino=%llu name=\"%.*s\" inum=%llu db=%d/%d — expunged leafless ghost dirent (leaf-hash hole unlink heal)\n",
				    (unsigned long long)dp->i_ino,
				    args->namelen, args->name,
				    (unsigned long long)args->inumber,
				    db, ndb);
				/* buffer stays joined to the txn (logged) */
				return 0;
			}
			offset += xfs_dir2_data_entsize(mp, dep->namelen);
		}
		xfs_trans_brelse(tp, dbp);
		dbp = NULL;
	}
	return -ENOENT;
}
#endif /* __KERNEL__ */

/*
 * Look up the entry referred to by args in the leaf format directory.
 * Most of the work is done by the xfs_dir2_leaf_lookup_int routine which
 * is also used by the node-format code.
 */
int
xfs_dir2_leaf_lookup(
	xfs_da_args_t		*args)		/* operation arguments */
{
	struct xfs_buf		*dbp;		/* data block buffer */
	xfs_dir2_data_entry_t	*dep;		/* data block entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	int			index;		/* found entry index */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_trans_t		*tp;		/* transaction pointer */
	struct xfs_dir3_icleaf_hdr leafhdr;

	trace_xfs_dir2_leaf_lookup(args);

	/*
	 * Look up name in the leaf block, returning both buffers and index.
	 */
	error = xfs_dir2_leaf_lookup_int(args, &lbp, &index, &dbp, &leafhdr);
	if (error) {
#ifdef __KERNEL__
		/*
		 * sess22: the hash index missed.  On a multi-node dir the
		 * perpetually-pinned leaf can durably lose a peer's last hash
		 * entry while the authoritative DATA block still holds the
		 * dirent — heal the lookup from the coherent data blocks.
		 * (lookup_int already released its buffers on the ENOENT path.)
		 */
		if (args->dp->i_mount->m_mxfs_dlm) {
			pr_warn_ratelimited("mxfs: P26-LKERR ino=%llu err=%d single=%d name=\"%.*s\"\n",
					(unsigned long long)args->dp->i_ino, error,
					mxfs_v5_dlm_is_single_node(args->dp->i_mount->m_mxfs_dlm) ? 1 : 0,
					args->namelen, args->name);
		}
		if (error == -ENOENT && args->dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(args->dp->i_mount->m_mxfs_dlm)) {
			/*
			 * sess1 (ccloop 46efd8b6) datascan gen-gate: the scan
			 * exists to heal a leaf-hash HOLE left by a peer's
			 * write.  If a prior scan already verified the leaf
			 * ENOENT-consistent at the CURRENT coherency state (no
			 * peer modify/handoff/reload since — key unchanged),
			 * the leaf is authoritative and this is a genuine
			 * miss.  Unconditional scanning cost 459 read-IOs /
			 * ~112ms per negative lookup on the 640-entry rv/uv
			 * shared dirs (measured, 87E860C4).
			 */
			if (!mxfs_dscan_gen_gate ||
			    args->dp->i_mxfs_dscan_clean_key !=
					mxfs_dscan_state_key(args->dp))
				return mxfs_dir2_datascan_lookup(args);
		}
#endif
		return error;
	}

	tp = args->trans;
	dp = args->dp;
	xfs_dir3_leaf_check(dp, lbp);

	/*
	 * Get to the leaf entry and contained data entry address.
	 */
	lep = &leafhdr.ents[index];

	/*
	 * Point to the data entry.
	 */
	dep = (xfs_dir2_data_entry_t *)
	      ((char *)dbp->b_addr +
	       xfs_dir2_dataptr_to_off(args->geo, be32_to_cpu(lep->address)));
	/*
	 * Return the found inode number & CI name if appropriate
	 */
	args->inumber = be64_to_cpu(dep->inumber);
	args->filetype = xfs_dir2_data_get_ftype(dp->i_mount, dep);
	error = xfs_dir_cilookup_result(args, dep->name, dep->namelen);
	xfs_trans_brelse(tp, dbp);
	xfs_trans_brelse(tp, lbp);
	return error;
}

/*
 * Look up name/hash in the leaf block.
 * Fill in indexp with the found index, and dbpp with the data buffer.
 * If not found dbpp will be NULL, and ENOENT comes back.
 * lbpp will always be filled in with the leaf buffer unless there's an error.
 */
static int					/* error */
xfs_dir2_leaf_lookup_int(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		**lbpp,		/* out: leaf buffer */
	int			*indexp,	/* out: index in leaf block */
	struct xfs_buf		**dbpp,		/* out: data buffer */
	struct xfs_dir3_icleaf_hdr *leafhdr)
{
	xfs_dir2_db_t		curdb = -1;	/* current data block number */
	struct xfs_buf		*dbp = NULL;	/* data buffer */
	xfs_dir2_data_entry_t	*dep;		/* data entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	int			index;		/* index in leaf block */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_db_t		newdb;		/* new data block number */
	xfs_trans_t		*tp;		/* transaction pointer */
	xfs_dir2_db_t		cidb = -1;	/* case match data block no. */
	enum xfs_dacmp		cmp;		/* name compare result */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;

	error = xfs_dir3_leaf_read(tp, dp, args->owner, args->geo->leafblk,
			&lbp);
	if (error)
		return error;

	*lbpp = lbp;
	leaf = lbp->b_addr;
	xfs_dir3_leaf_check(dp, lbp);
	xfs_dir2_leaf_hdr_from_disk(mp, leafhdr, leaf);

	/*
	 * Look for the first leaf entry with our hash value.
	 */
	index = xfs_dir2_leaf_search_hash(args, lbp);
	/*
	 * Loop over all the entries with the right hash value
	 * looking to match the name.
	 */
	for (lep = &leafhdr->ents[index];
	     index < leafhdr->count &&
			be32_to_cpu(lep->hashval) == args->hashval;
	     lep++, index++) {
		/*
		 * Skip over stale leaf entries.
		 */
		if (be32_to_cpu(lep->address) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Get the new data block number.
		 */
		newdb = xfs_dir2_dataptr_to_db(args->geo,
					       be32_to_cpu(lep->address));
		/*
		 * If it's not the same as the old data block number,
		 * need to pitch the old one and read the new one.
		 */
		if (newdb != curdb) {
			if (dbp)
				xfs_trans_brelse(tp, dbp);
			error = xfs_dir3_data_read(tp, dp, args->owner,
					xfs_dir2_db_to_da(args->geo, newdb), 0,
					&dbp);
			if (error) {
				xfs_trans_brelse(tp, lbp);
				return error;
			}
			curdb = newdb;
		}
		/*
		 * Point to the data entry.
		 */
		dep = (xfs_dir2_data_entry_t *)((char *)dbp->b_addr +
			xfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(lep->address)));
		/*
		 * Compare name and if it's an exact match, return the index
		 * and buffer. If it's the first case-insensitive match, store
		 * the index and buffer and continue looking for an exact match.
		 */
		cmp = xfs_dir2_compname(args, dep->name, dep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			*indexp = index;
			/* case exact match: return the current buffer. */
			if (cmp == XFS_CMP_EXACT) {
				*dbpp = dbp;
				return 0;
			}
			cidb = curdb;
		}
	}
	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or remove).
	 * If a case-insensitive match was found earlier, re-read the
	 * appropriate data block if required and return it.
	 */
	if (args->cmpresult == XFS_CMP_CASE) {
		ASSERT(cidb != -1);
		if (cidb != curdb) {
			xfs_trans_brelse(tp, dbp);
			error = xfs_dir3_data_read(tp, dp, args->owner,
					xfs_dir2_db_to_da(args->geo, cidb), 0,
					&dbp);
			if (error) {
				xfs_trans_brelse(tp, lbp);
				return error;
			}
		}
		*dbpp = dbp;
		return 0;
	}
	/*
	 * No match found, return -ENOENT.
	 */
	ASSERT(cidb == -1);
#ifdef __KERNEL__
	/*
	 * sess21 (ccloop 8ddb16a2) RULE-4 DETECTOR for the dir_reuse_coherency
	 * durable LEAF-HASH HOLE: readdir lists a name (its dirent is in a data
	 * block) but lookup ENOENTs because the leaf hash index lacks a usable
	 * entry for it.  Two opposite roots need opposite fixes, distinguished
	 * here by scanning the leaf for the searched hashval:
	 *   hv_in_leaf==0 -> the hashval is GENUINELY ABSENT from the on-disk
	 *                    leaf (case 1: a write durably dropped/never added
	 *                    the peer's hash entry).
	 *   hv_in_leaf>0  -> the hashval IS present but its address resolved to
	 *                    a data block where the name is not (case 2: stale
	 *                    leaf ADDRESS / data-block layout skew).
	 * Lightweight + always-on: fires ONLY on an ENOENT lookup (the test
	 * probes ~9-22 missing names per failing round), so it does not perturb
	 * timing the way the dirwr=1 P-LEAFWRITE firehose does.  Multi-node only.
	 */
	if (dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		static atomic_t p21h_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p21h_n) <= 400) {
			int hv_in_leaf = 0, k;

			for (k = 0; k < leafhdr->count; k++)
				if (be32_to_cpu(leafhdr->ents[k].hashval) ==
				    args->hashval)
					hv_in_leaf++;
			pr_warn("mxfs: P21H-LEAFHOLE dir_ino=%llu name=\"%.*s\" hashval=0x%x leaf_count=%u hv_in_leaf=%d nextents=%llu fmt=%d realns=%llu\n",
				(unsigned long long)dp->i_ino,
				args->namelen, args->name, args->hashval,
				leafhdr->count, hv_in_leaf,
				(unsigned long long)dp->i_df.if_nextents,
				dp->i_df.if_format,
				(unsigned long long)ktime_get_real_ns());
		}
	}
#endif
	if (dbp)
		xfs_trans_brelse(tp, dbp);
	xfs_trans_brelse(tp, lbp);
	return -ENOENT;
}

/*
 * Remove an entry from a leaf format directory.
 */
int						/* error */
xfs_dir2_leaf_removename(
	xfs_da_args_t		*args)		/* operation arguments */
{
	struct xfs_da_geometry	*geo = args->geo;
	__be16			*bestsp;	/* leaf block best freespace */
	xfs_dir2_data_hdr_t	*hdr;		/* data block header */
	xfs_dir2_db_t		db;		/* data block number */
	struct xfs_buf		*dbp;		/* data block buffer */
	xfs_dir2_data_entry_t	*dep;		/* data entry structure */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	xfs_dir2_db_t		i;		/* temporary data block # */
	int			index;		/* index into leaf entries */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */
	int			needlog;	/* need to log data header */
	int			needscan;	/* need to rescan data frees */
	xfs_dir2_data_off_t	oldbest;	/* old value of best free */
	struct xfs_dir2_data_free *bf;		/* bestfree table */
	struct xfs_dir3_icleaf_hdr leafhdr;

	trace_xfs_dir2_leaf_removename(args);

	/*
	 * Lookup the leaf entry, get the leaf and data blocks read in.
	 */
	error = xfs_dir2_leaf_lookup_int(args, &lbp, &index, &dbp, &leafhdr);
	if (error) {
#ifdef __KERNEL__
		/* sess5 (ccloop 46efd8b6): leaf-hash hole — the name has no
		 * leaf entry but its dirent may still live in a data block
		 * (the uv leafless-ghost chain).  Expunge it data-side so the
		 * unlink transaction completes and the inode is reaped. */
		if (error == -ENOENT)
			error = mxfs_dir2_leafless_removename(args);
#endif
		return error;
	}

	dp = args->dp;
	leaf = lbp->b_addr;
	hdr = dbp->b_addr;
	xfs_dir3_data_check(dp, dbp);
	bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);

	/*
	 * Point to the leaf entry, use that to point to the data entry.
	 */
	lep = &leafhdr.ents[index];
	db = xfs_dir2_dataptr_to_db(geo, be32_to_cpu(lep->address));
	dep = (xfs_dir2_data_entry_t *)((char *)hdr +
		xfs_dir2_dataptr_to_off(geo, be32_to_cpu(lep->address)));
	needscan = needlog = 0;
	oldbest = be16_to_cpu(bf[0].length);
	ltp = xfs_dir2_leaf_tail_p(geo, leaf);
	bestsp = xfs_dir2_leaf_bests_p(ltp);
	if (be16_to_cpu(bestsp[db]) != oldbest) {
		xfs_buf_mark_corrupt(lbp);
		xfs_da_mark_sick(args);
		return -EFSCORRUPTED;
	}

	/*
	 * Mark the former data entry unused.
	 */
	xfs_dir2_data_make_free(args, dbp,
		(xfs_dir2_data_aoff_t)((char *)dep - (char *)hdr),
		xfs_dir2_data_entsize(dp->i_mount, dep->namelen), &needlog,
		&needscan);
	/*
	 * We just mark the leaf entry stale by putting a null in it.
	 */
	leafhdr.stale++;
	xfs_dir2_leaf_hdr_to_disk(dp->i_mount, leaf, &leafhdr);
	xfs_dir3_leaf_log_header(args, lbp);

	lep->address = cpu_to_be32(XFS_DIR2_NULL_DATAPTR);
	xfs_dir3_leaf_log_ents(args, &leafhdr, lbp, index, index);

	/*
	 * Scan the freespace in the data block again if necessary,
	 * log the data block header if necessary.
	 */
	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	if (needlog)
		xfs_dir2_data_log_header(args, dbp);
	/*
	 * If the longest freespace in the data block has changed,
	 * put the new value in the bests table and log that.
	 */
	if (be16_to_cpu(bf[0].length) != oldbest) {
		bestsp[db] = bf[0].length;
		xfs_dir3_leaf_log_bests(args, lbp, db, db);
	}
	xfs_dir3_data_check(dp, dbp);
	/*
	 * If the data block is now empty then get rid of the data block.
	 */
	if (be16_to_cpu(bf[0].length) ==
	    geo->blksize - geo->data_entry_offset) {
		extern int mxfs_dir_keep_middle_block;
		ASSERT(db != geo->datablk);
		/*
		 * <ccloop sess3> UNIFIED torn-map FIX: do NOT free a NON-LAST
		 * (middle) dir data block under multi-node.  Freeing it removes
		 * its extent but leaves di_size unchanged -> a GAP in the
		 * data-region extent map; across a cross-node EX handoff a peer's
		 * stale leaf still references the freed block -> durable
		 * DABUF_MAP_HOLE -> FS shutdown (the dir_reuse 4/8 +
		 * fence_during_write 2/tcp hot-dir root).  Leave it as a valid
		 * EMPTY data block, mapped, with bests[db] kept all-free (already
		 * set above) so a later add reuses it.  No extent removed -> no
		 * gap.  Tail-block frees still shrink di_size normally.
		 */
		if (mxfs_dir_keep_middle_block && dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
		    dp->i_disk_size >
			xfs_dir2_db_off_to_byte(geo, db + 1, 0)) {
			/* bestsp[db] already = bf[0].length (all-free); keep it.
			 * Drop the buffer ref (middle block, like the !first rule)
			 * but do NOT shrink/unmap and do NOT NULLDATAOFF the best. */
			dbp = NULL;
			xfs_dir3_leaf_check(dp, lbp);
			return xfs_dir2_leaf_to_block(args, lbp, dbp);
		}
		if ((error = xfs_dir2_shrink_inode(args, db, dbp))) {
			/*
			 * Nope, can't get rid of it because it caused
			 * allocation of a bmap btree block to do so.
			 * Just go on, returning success, leaving the
			 * empty block in place.
			 */
			if (error == -ENOSPC && args->total == 0)
				error = 0;
			xfs_dir3_leaf_check(dp, lbp);
			return error;
		}
		dbp = NULL;
		/*
		 * If this is the last data block then compact the
		 * bests table by getting rid of entries.
		 */
		if (db == be32_to_cpu(ltp->bestcount) - 1) {
			/*
			 * Look for the last active entry (i).
			 */
			for (i = db - 1; i > 0; i--) {
				if (bestsp[i] != cpu_to_be16(NULLDATAOFF))
					break;
			}
			/*
			 * Copy the table down so inactive entries at the
			 * end are removed.
			 */
			memmove(&bestsp[db - i], bestsp,
				(be32_to_cpu(ltp->bestcount) - (db - i)) * sizeof(*bestsp));
			be32_add_cpu(&ltp->bestcount, -(db - i));
			xfs_dir3_leaf_log_tail(args, lbp);
			xfs_dir3_leaf_log_bests(args, lbp, 0,
						be32_to_cpu(ltp->bestcount) - 1);
		} else
			bestsp[db] = cpu_to_be16(NULLDATAOFF);
	}
	/*
	 * If the data block was not the first one, drop it.
	 */
	else if (db != geo->datablk)
		dbp = NULL;

	xfs_dir3_leaf_check(dp, lbp);
	/*
	 * See if we can convert to block form.
	 */
	return xfs_dir2_leaf_to_block(args, lbp, dbp);
}

/*
 * Replace the inode number in a leaf format directory entry.
 */
int						/* error */
xfs_dir2_leaf_replace(
	xfs_da_args_t		*args)		/* operation arguments */
{
	struct xfs_buf		*dbp;		/* data block buffer */
	xfs_dir2_data_entry_t	*dep;		/* data block entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	int			index;		/* index of leaf entry */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_trans_t		*tp;		/* transaction pointer */
	struct xfs_dir3_icleaf_hdr leafhdr;

	trace_xfs_dir2_leaf_replace(args);

	/*
	 * Look up the entry.
	 */
	error = xfs_dir2_leaf_lookup_int(args, &lbp, &index, &dbp, &leafhdr);
	if (error)
		return error;

	dp = args->dp;
	/*
	 * Point to the leaf entry, get data address from it.
	 */
	lep = &leafhdr.ents[index];
	/*
	 * Point to the data entry.
	 */
	dep = (xfs_dir2_data_entry_t *)
	      ((char *)dbp->b_addr +
	       xfs_dir2_dataptr_to_off(args->geo, be32_to_cpu(lep->address)));
	ASSERT(args->inumber != be64_to_cpu(dep->inumber));
	/*
	 * Put the new inode number in, log it.
	 */
	dep->inumber = cpu_to_be64(args->inumber);
	xfs_dir2_data_put_ftype(dp->i_mount, dep, args->filetype);
	tp = args->trans;
	xfs_dir2_data_log_entry(args, dbp, dep);
	xfs_dir3_leaf_check(dp, lbp);
	xfs_trans_brelse(tp, lbp);
	return 0;
}

/*
 * Return index in the leaf block (lbp) which is either the first
 * one with this hash value, or if there are none, the insert point
 * for that hash value.
 */
int						/* index value */
xfs_dir2_leaf_search_hash(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		*lbp)		/* leaf buffer */
{
	xfs_dahash_t		hash=0;		/* hash from this entry */
	xfs_dahash_t		hashwant;	/* hash value looking for */
	int			high;		/* high leaf index */
	int			low;		/* low leaf index */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	int			mid=0;		/* current leaf index */
	struct xfs_dir3_icleaf_hdr leafhdr;

	xfs_dir2_leaf_hdr_from_disk(args->dp->i_mount, &leafhdr, lbp->b_addr);

	/*
	 * Note, the table cannot be empty, so we have to go through the loop.
	 * Binary search the leaf entries looking for our hash value.
	 */
	for (lep = leafhdr.ents, low = 0, high = leafhdr.count - 1,
		hashwant = args->hashval;
	     low <= high; ) {
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(lep[mid].hashval)) == hashwant)
			break;
		if (hash < hashwant)
			low = mid + 1;
		else
			high = mid - 1;
	}
	/*
	 * Found one, back up through all the equal hash values.
	 */
	if (hash == hashwant) {
		while (mid > 0 && be32_to_cpu(lep[mid - 1].hashval) == hashwant) {
			mid--;
		}
	}
	/*
	 * Need to point to an entry higher than ours.
	 */
	else if (hash < hashwant)
		mid++;
	return mid;
}

/*
 * Trim off a trailing data block.  We know it's empty since the leaf
 * freespace table says so.
 */
int						/* error */
xfs_dir2_leaf_trim_data(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		*lbp,		/* leaf buffer */
	xfs_dir2_db_t		db)		/* data block number */
{
	struct xfs_da_geometry	*geo = args->geo;
	__be16			*bestsp;	/* leaf bests table */
	struct xfs_buf		*dbp;		/* data block buffer */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return value */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */
	xfs_trans_t		*tp;		/* transaction pointer */

	dp = args->dp;
	tp = args->trans;
	/*
	 * Read the offending data block.  We need its buffer.
	 */
	error = xfs_dir3_data_read(tp, dp, args->owner,
			xfs_dir2_db_to_da(geo, db), 0, &dbp);
	if (error)
		return error;

	leaf = lbp->b_addr;
	ltp = xfs_dir2_leaf_tail_p(geo, leaf);

#ifdef DEBUG
{
	struct xfs_dir2_data_hdr *hdr = dbp->b_addr;
	struct xfs_dir2_data_free *bf =
		xfs_dir2_data_bestfree_p(dp->i_mount, hdr);

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC));
	ASSERT(be16_to_cpu(bf[0].length) ==
	       geo->blksize - geo->data_entry_offset);
	ASSERT(db == be32_to_cpu(ltp->bestcount) - 1);
}
#endif

	/*
	 * Get rid of the data block.
	 */
	if ((error = xfs_dir2_shrink_inode(args, db, dbp))) {
		ASSERT(error != -ENOSPC);
		xfs_trans_brelse(tp, dbp);
		return error;
	}
	/*
	 * Eliminate the last bests entry from the table.
	 */
	bestsp = xfs_dir2_leaf_bests_p(ltp);
	be32_add_cpu(&ltp->bestcount, -1);
	memmove(&bestsp[1], &bestsp[0], be32_to_cpu(ltp->bestcount) * sizeof(*bestsp));
	xfs_dir3_leaf_log_tail(args, lbp);
	xfs_dir3_leaf_log_bests(args, lbp, 0, be32_to_cpu(ltp->bestcount) - 1);
	return 0;
}

static inline size_t
xfs_dir3_leaf_size(
	struct xfs_dir3_icleaf_hdr	*hdr,
	int				counts)
{
	int	entries;
	int	hdrsize;

	entries = hdr->count - hdr->stale;
	if (hdr->magic == XFS_DIR2_LEAF1_MAGIC ||
	    hdr->magic == XFS_DIR2_LEAFN_MAGIC)
		hdrsize = sizeof(struct xfs_dir2_leaf_hdr);
	else
		hdrsize = sizeof(struct xfs_dir3_leaf_hdr);

	return hdrsize + entries * sizeof(xfs_dir2_leaf_entry_t)
	               + counts * sizeof(xfs_dir2_data_off_t)
		       + sizeof(xfs_dir2_leaf_tail_t);
}

/*
 * Convert node form directory to leaf form directory.
 * The root of the node form dir needs to already be a LEAFN block.
 * Just return if we can't do anything.
 */
int						/* error */
xfs_dir2_node_to_leaf(
	xfs_da_state_t		*state)		/* directory operation state */
{
	xfs_da_args_t		*args;		/* operation arguments */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	struct xfs_buf		*fbp;		/* buffer for freespace block */
	xfs_fileoff_t		fo;		/* freespace file offset */
	struct xfs_buf		*lbp;		/* buffer for leaf block */
	xfs_dir2_leaf_tail_t	*ltp;		/* tail of leaf structure */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_mount_t		*mp;		/* filesystem mount point */
	int			rval;		/* successful free trim? */
	xfs_trans_t		*tp;		/* transaction pointer */
	struct xfs_dir3_icleaf_hdr leafhdr;
	struct xfs_dir3_icfree_hdr freehdr;

	/*
	 * There's more than a leaf level in the btree, so there must
	 * be multiple leafn blocks.  Give up.
	 */
	if (state->path.active > 1)
		return 0;
	args = state->args;

	trace_xfs_dir2_node_to_leaf(args);

	mp = state->mp;
	dp = args->dp;
	tp = args->trans;
	/*
	 * Get the last offset in the file.
	 */
	if ((error = xfs_bmap_last_offset(dp, &fo, XFS_DATA_FORK))) {
		return error;
	}
	fo -= args->geo->fsbcount;
	/*
	 * If there are freespace blocks other than the first one,
	 * take this opportunity to remove trailing empty freespace blocks
	 * that may have been left behind during no-space-reservation
	 * operations.
	 */
	while (fo > args->geo->freeblk) {
		if ((error = xfs_dir2_node_trim_free(args, fo, &rval))) {
			return error;
		}
		if (rval)
			fo -= args->geo->fsbcount;
		else
			return 0;
	}
	/*
	 * Now find the block just before the freespace block.
	 */
	if ((error = xfs_bmap_last_before(tp, dp, &fo, XFS_DATA_FORK))) {
		return error;
	}
	/*
	 * If it's not the single leaf block, give up.
	 */
	if (XFS_FSB_TO_B(mp, fo) > XFS_DIR2_LEAF_OFFSET + args->geo->blksize)
		return 0;
	lbp = state->path.blk[0].bp;
	leaf = lbp->b_addr;
	xfs_dir2_leaf_hdr_from_disk(mp, &leafhdr, leaf);

	ASSERT(leafhdr.magic == XFS_DIR2_LEAFN_MAGIC ||
	       leafhdr.magic == XFS_DIR3_LEAFN_MAGIC);

	/*
	 * Read the freespace block.
	 */
	error = xfs_dir2_free_read(tp, dp, args->owner, args->geo->freeblk,
			&fbp);
	if (error)
		return error;
	xfs_dir2_free_hdr_from_disk(mp, &freehdr, fbp->b_addr);

	ASSERT(!freehdr.firstdb);

	/*
	 * Now see if the leafn and free data will fit in a leaf1.
	 * If not, release the buffer and give up.
	 */
	if (xfs_dir3_leaf_size(&leafhdr, freehdr.nvalid) > args->geo->blksize) {
		xfs_trans_brelse(tp, fbp);
		return 0;
	}

	/*
	 * If the leaf has any stale entries in it, compress them out.
	 */
	if (leafhdr.stale)
		xfs_dir3_leaf_compact(args, &leafhdr, lbp);

	lbp->b_ops = &xfs_dir3_leaf1_buf_ops;
	xfs_trans_buf_set_type(tp, lbp, XFS_BLFT_DIR_LEAF1_BUF);
	leafhdr.magic = (leafhdr.magic == XFS_DIR2_LEAFN_MAGIC)
					? XFS_DIR2_LEAF1_MAGIC
					: XFS_DIR3_LEAF1_MAGIC;

	/*
	 * Set up the leaf tail from the freespace block.
	 */
	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);
	ltp->bestcount = cpu_to_be32(freehdr.nvalid);

	/*
	 * Set up the leaf bests table.
	 */
	memcpy(xfs_dir2_leaf_bests_p(ltp), freehdr.bests,
		freehdr.nvalid * sizeof(xfs_dir2_data_off_t));

	xfs_dir2_leaf_hdr_to_disk(mp, leaf, &leafhdr);
	xfs_dir3_leaf_log_header(args, lbp);
	xfs_dir3_leaf_log_bests(args, lbp, 0, be32_to_cpu(ltp->bestcount) - 1);
	xfs_dir3_leaf_log_tail(args, lbp);
	xfs_dir3_leaf_check(dp, lbp);

	/*
	 * Get rid of the freespace block.
	 */
	error = xfs_dir2_shrink_inode(args,
			xfs_dir2_byte_to_db(args->geo, XFS_DIR2_FREE_OFFSET),
			fbp);
	if (error) {
		/*
		 * This can't fail here because it can only happen when
		 * punching out the middle of an extent, and this is an
		 * isolated block.
		 */
		ASSERT(error != -ENOSPC);
		return error;
	}
	fbp = NULL;
	/*
	 * Now see if we can convert the single-leaf directory
	 * down to a block form directory.
	 * This routine always kills the dabuf for the leaf, so
	 * eliminate it from the path.
	 */
	error = xfs_dir2_leaf_to_block(args, lbp, NULL);
	state->path.blk[0].bp = NULL;
	return error;
}
