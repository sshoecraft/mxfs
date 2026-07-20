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
#include "xfs_trans.h"
#include "xfs_bmap.h"
#include "xfs_buf_item.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_health.h"
#include "../../dlm/v5_mount.h"	/* sess56: mxfs_v5_dlm_is_single_node + pal log */
#include "xfs_mxfs_dlm.h"	/* sess56: MXFS_IF_DIR_RELOAD */

/*
 * Local function prototypes.
 */
static void xfs_dir2_block_log_leaf(xfs_trans_t *tp, struct xfs_buf *bp,
				    int first, int last);
static void xfs_dir2_block_log_tail(xfs_trans_t *tp, struct xfs_buf *bp);
static int xfs_dir2_block_lookup_int(xfs_da_args_t *args, struct xfs_buf **bpp,
				     int *entno);
static int xfs_dir2_block_sort(const void *a, const void *b);

static xfs_dahash_t xfs_dir_hash_dot, xfs_dir_hash_dotdot;

/*
 * One-time startup routine called from xfs_init().
 */
void
xfs_dir_startup(void)
{
	xfs_dir_hash_dot = xfs_da_hashname((unsigned char *)".", 1);
	xfs_dir_hash_dotdot = xfs_da_hashname((unsigned char *)"..", 2);
}

static xfs_failaddr_t
xfs_dir3_block_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_dir3_blk_hdr	*hdr3 = bp->b_addr;

	if (!xfs_verify_magic(bp, hdr3->magic))
		return __this_address;

	if (xfs_has_crc(mp)) {
		if (!uuid_equal(&hdr3->uuid, &mp->m_sb.sb_meta_uuid))
			return __this_address;
		if (be64_to_cpu(hdr3->blkno) != xfs_buf_daddr(bp))
			return __this_address;
		if (!xfs_log_check_lsn(mp, be64_to_cpu(hdr3->lsn)))
			return __this_address;
	}
	return __xfs_dir3_data_check(NULL, bp);
}

static void
xfs_dir3_block_read_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	xfs_failaddr_t		fa;

	if (xfs_has_crc(mp) &&
	     !xfs_buf_verify_cksum(bp, XFS_DIR3_DATA_CRC_OFF)) {
		/* P-BLKRV (RULE-4): CRC fail on read of a dir3 block under
		 * multinode — log owner + daddr + caller so we can see if this
		 * is a re-read of a freshly-realloc'd block whose stale prior
		 * owner image is still on disk (the sf->block double-alloc). */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			struct xfs_dir3_blk_hdr *h3 = bp->b_addr;
			pr_warn("mxfs: P-BLKRV-CRC daddr=%lld blkno=%llu owner=%llu — dir3 block CRC fail on read (multinode)\n",
				(long long)xfs_buf_daddr(bp),
				(unsigned long long)be64_to_cpu(h3->blkno),
				(unsigned long long)be64_to_cpu(h3->owner));
			dump_stack();
		}
		xfs_verifier_error(bp, -EFSBADCRC, __this_address);
	} else {
		fa = xfs_dir3_block_verify(bp);
		if (fa) {
			/* P-BLKRV (RULE-4): structural fail — same instrumentation.
			 * If owner != the reading dir inode, a foreign block was
			 * read (stale extent map / block double-alloc). */
			if (mp->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
				struct xfs_dir3_blk_hdr *h3 = bp->b_addr;
				pr_warn("mxfs: P-BLKRV-STRUCT daddr=%lld blkno=%llu owner=%llu fa=%pS — dir3 block struct-verify fail on read (multinode)\n",
					(long long)xfs_buf_daddr(bp),
					(unsigned long long)be64_to_cpu(h3->blkno),
					(unsigned long long)be64_to_cpu(h3->owner), fa);
				dump_stack();
			}
			xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		}
	}
}

static void
xfs_dir3_block_write_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_dir3_blk_hdr	*hdr3 = bp->b_addr;
	xfs_failaddr_t		fa;

	fa = xfs_dir3_block_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	/* P-BLKWR (RULE-4): log every WRITE-out of a block-format dir block under
	 * multinode so we can confirm whether the failing daddr (block0) is ever
	 * written to disk at all (lost-write) vs written-but-read-elsewhere. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		pr_warn_ratelimited("mxfs: P-BLKWR daddr=%lld owner=%llu — writing block-fmt dir block to disk\n",
			(long long)xfs_buf_daddr(bp),
			(unsigned long long)be64_to_cpu(hdr3->owner));

	if (!xfs_has_crc(mp))
		return;

	if (bip)
		hdr3->lsn = cpu_to_be64(bip->bli_item.li_lsn);

	xfs_buf_update_cksum(bp, XFS_DIR3_DATA_CRC_OFF);
}

const struct xfs_buf_ops xfs_dir3_block_buf_ops = {
	.name = "xfs_dir3_block",
	.magic = { cpu_to_be32(XFS_DIR2_BLOCK_MAGIC),
		   cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) },
	.verify_read = xfs_dir3_block_read_verify,
	.verify_write = xfs_dir3_block_write_verify,
	.verify_struct = xfs_dir3_block_verify,
};

xfs_failaddr_t
xfs_dir3_block_header_check(
	struct xfs_buf		*bp,
	xfs_ino_t		owner)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (xfs_has_crc(mp)) {
		struct xfs_dir3_blk_hdr *hdr3 = bp->b_addr;

		if (hdr3->magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
			return __this_address;

		if (be64_to_cpu(hdr3->owner) != owner)
			return __this_address;
	}

	return NULL;
}

int
xfs_dir3_block_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_ino_t		owner,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = dp->i_mount;
	xfs_failaddr_t		fa;
	int			err;

	err = xfs_da_read_buf(tp, dp, mp->m_dir_geo->datablk, 0, bpp,
				XFS_DATA_FORK, &xfs_dir3_block_buf_ops);
	if (err || !*bpp)
		return err;

	/*
	 * sess56 (ccloop 14d31183) P56-BLKREAD — capture the stale-inode read.
	 * We are reading dir block 0 with BLOCK-format ops because the caller
	 * decided FMT_BLOCK (in-core nextents==1).  If the buffer's on-disk
	 * magic is XDD3 (0x58444433 = dir3 DATA) rather than XDB3 (block), the
	 * peer converted this dir block->leaf and our in-core inode (nextents/
	 * format) is STALE while the DATA block was FUA-re-read fresh — the
	 * inode-vs-datablock coherency asymmetry.  Log the in-core inode state
	 * + which path/comm so the timeline names the stale reader.  Rare on a
	 * healthy fs; capped.
	 */
	{
		extern int mxfs_dirwr_enabled;
		extern int mxfs_instr_enabled;

		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    (*bpp)->b_addr) {
			const unsigned char *m = (*bpp)->b_addr;

			if (!(m[0] == 0x58 && m[1] == 0x44 && m[2] == 0x42 &&
			      m[3] == 0x33)) {		/* not XDB3 */
				static atomic_t p56b_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p56b_n) <= 400)
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: P56-BLKREAD ino=%llu magic=%02x%02x%02x%02x nextents=%llu fmt=%d size=%lld dir_gen=%llu loaded_gen=%u reload_flag=%d dlm_mode=%d comm=%s realns=%llu",
						(unsigned long long)dp->i_ino,
						m[0], m[1], m[2], m[3],
						(unsigned long long)dp->i_df.if_nextents,
						dp->i_df.if_format,
						(long long)dp->i_disk_size,
						(unsigned long long)dp->i_dlm_dir_gen,
						dp->i_dlm_dir_loaded_gen,
						!!xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD),
						dp->i_dlm_mode,
						current->comm,
						(unsigned long long)ktime_get_real_ns());
			}
		}
	}

	/* Check things that we can't do in the verifier. */
	fa = xfs_dir3_block_header_check(*bpp, owner);
	if (fa) {
		__xfs_buf_mark_corrupt(*bpp, fa);
		xfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
		return -EFSCORRUPTED;
	}

	xfs_trans_buf_set_type(tp, *bpp, XFS_BLFT_DIR_BLOCK_BUF);
	return err;
}

static void
xfs_dir3_block_init(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp)
{
	struct xfs_trans	*tp = args->trans;
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_dir3_blk_hdr	*hdr3 = bp->b_addr;

	bp->b_ops = &xfs_dir3_block_buf_ops;
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DIR_BLOCK_BUF);

	if (xfs_has_crc(mp)) {
		memset(hdr3, 0, sizeof(*hdr3));
		hdr3->magic = cpu_to_be32(XFS_DIR3_BLOCK_MAGIC);
		hdr3->blkno = cpu_to_be64(xfs_buf_daddr(bp));
		hdr3->owner = cpu_to_be64(args->owner);
		uuid_copy(&hdr3->uuid, &mp->m_sb.sb_meta_uuid);
		return;

	}
	hdr3->magic = cpu_to_be32(XFS_DIR2_BLOCK_MAGIC);
}

static void
xfs_dir2_block_need_space(
	struct xfs_inode		*dp,
	struct xfs_dir2_data_hdr	*hdr,
	struct xfs_dir2_block_tail	*btp,
	struct xfs_dir2_leaf_entry	*blp,
	__be16				**tagpp,
	struct xfs_dir2_data_unused	**dupp,
	struct xfs_dir2_data_unused	**enddupp,
	int				*compact,
	int				len)
{
	struct xfs_dir2_data_free	*bf;
	__be16				*tagp = NULL;
	struct xfs_dir2_data_unused	*dup = NULL;
	struct xfs_dir2_data_unused	*enddup = NULL;

	*compact = 0;
	bf = xfs_dir2_data_bestfree_p(dp->i_mount, hdr);

	/*
	 * If there are stale entries we'll use one for the leaf.
	 */
	if (btp->stale) {
		if (be16_to_cpu(bf[0].length) >= len) {
			/*
			 * The biggest entry enough to avoid compaction.
			 */
			dup = (xfs_dir2_data_unused_t *)
			      ((char *)hdr + be16_to_cpu(bf[0].offset));
			goto out;
		}

		/*
		 * Will need to compact to make this work.
		 * Tag just before the first leaf entry.
		 */
		*compact = 1;
		tagp = (__be16 *)blp - 1;

		/* Data object just before the first leaf entry.  */
		dup = (xfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));

		/*
		 * If it's not free then the data will go where the
		 * leaf data starts now, if it works at all.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			if (be16_to_cpu(dup->length) + (be32_to_cpu(btp->stale) - 1) *
			    (uint)sizeof(*blp) < len)
				dup = NULL;
		} else if ((be32_to_cpu(btp->stale) - 1) * (uint)sizeof(*blp) < len)
			dup = NULL;
		else
			dup = (xfs_dir2_data_unused_t *)blp;
		goto out;
	}

	/*
	 * no stale entries, so just use free space.
	 * Tag just before the first leaf entry.
	 */
	tagp = (__be16 *)blp - 1;

	/* Data object just before the first leaf entry.  */
	enddup = (xfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));

	/*
	 * If it's not free then can't do this add without cleaning up:
	 * the space before the first leaf entry needs to be free so it
	 * can be expanded to hold the pointer to the new entry.
	 */
	if (be16_to_cpu(enddup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
		/*
		 * Check out the biggest freespace and see if it's the same one.
		 */
		dup = (xfs_dir2_data_unused_t *)
		      ((char *)hdr + be16_to_cpu(bf[0].offset));
		if (dup != enddup) {
			/*
			 * Not the same free entry, just check its length.
			 */
			if (be16_to_cpu(dup->length) < len)
				dup = NULL;
			goto out;
		}

		/*
		 * It is the biggest freespace, can it hold the leaf too?
		 */
		if (be16_to_cpu(dup->length) < len + (uint)sizeof(*blp)) {
			/*
			 * Yes, use the second-largest entry instead if it works.
			 */
			if (be16_to_cpu(bf[1].length) >= len)
				dup = (xfs_dir2_data_unused_t *)
				      ((char *)hdr + be16_to_cpu(bf[1].offset));
			else
				dup = NULL;
		}
	}
out:
	*tagpp = tagp;
	*dupp = dup;
	*enddupp = enddup;
}

/*
 * compact the leaf entries.
 * Leave the highest-numbered stale entry stale.
 * XXX should be the one closest to mid but mid is not yet computed.
 */
static void
xfs_dir2_block_compact(
	struct xfs_da_args		*args,
	struct xfs_buf			*bp,
	struct xfs_dir2_data_hdr	*hdr,
	struct xfs_dir2_block_tail	*btp,
	struct xfs_dir2_leaf_entry	*blp,
	int				*needlog,
	int				*lfloghigh,
	int				*lfloglow)
{
	int			fromidx;	/* source leaf index */
	int			toidx;		/* target leaf index */
	int			needscan = 0;
	int			highstale;	/* high stale index */

	fromidx = toidx = be32_to_cpu(btp->count) - 1;
	highstale = *lfloghigh = -1;
	for (; fromidx >= 0; fromidx--) {
		if (blp[fromidx].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR)) {
			if (highstale == -1)
				highstale = toidx;
			else {
				if (*lfloghigh == -1)
					*lfloghigh = toidx;
				continue;
			}
		}
		if (fromidx < toidx)
			blp[toidx] = blp[fromidx];
		toidx--;
	}
	*lfloglow = toidx + 1 - (be32_to_cpu(btp->stale) - 1);
	*lfloghigh -= be32_to_cpu(btp->stale) - 1;
	be32_add_cpu(&btp->count, -(be32_to_cpu(btp->stale) - 1));
	xfs_dir2_data_make_free(args, bp,
		(xfs_dir2_data_aoff_t)((char *)blp - (char *)hdr),
		(xfs_dir2_data_aoff_t)((be32_to_cpu(btp->stale) - 1) * sizeof(*blp)),
		needlog, &needscan);
	btp->stale = cpu_to_be32(1);
	/*
	 * If we now need to rebuild the bestfree map, do so.
	 * This needs to happen before the next call to use_free.
	 */
	if (needscan)
		xfs_dir2_data_freescan(args->dp->i_mount, hdr, needlog);
}

/*
 * Add an entry to a block directory.
 */
int						/* error */
xfs_dir2_block_addname(
	xfs_da_args_t		*args)		/* directory op arguments */
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* buffer for block */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	int			compact;	/* need to compact leaf ents */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* directory inode */
	xfs_dir2_data_unused_t	*dup;		/* block unused entry */
	int			error;		/* error return value */
	xfs_dir2_data_unused_t	*enddup=NULL;	/* unused at end of data */
	xfs_dahash_t		hash;		/* hash value of found entry */
	int			high;		/* high index for binary srch */
	int			highstale;	/* high stale index */
	int			lfloghigh=0;	/* last final leaf to log */
	int			lfloglow=0;	/* first final leaf to log */
	int			len;		/* length of the new entry */
	int			low;		/* low index for binary srch */
	int			lowstale;	/* low stale index */
	int			mid=0;		/* midpoint for binary srch */
	int			needlog;	/* need to log header */
	int			needscan;	/* need to rescan freespace */
	__be16			*tagp;		/* pointer to tag value */
	xfs_trans_t		*tp;		/* transaction structure */

	trace_xfs_dir2_block_addname(args);

	dp = args->dp;
	tp = args->trans;

	/* Read the (one and only) directory block into bp. */
	error = xfs_dir3_block_read(tp, dp, args->owner, &bp);
	if (error)
		return error;

	len = xfs_dir2_data_entsize(dp->i_mount, args->namelen);

	/* sess28: read-side staleness fix — if the CLEAN block-format dir block is
	 * stale vs the durable platter, invalidate + cold re-read it through the
	 * verifier so bestfree reflects a peer's durable add and use_free does not
	 * overwrite it. */
	{
		extern int mxfs_dir_addname_coherent_refresh(
			struct xfs_da_args *, struct xfs_buf *);
		if (mxfs_dir_addname_coherent_refresh(args, bp)) {
			xfs_trans_brelse(tp, bp);
			error = xfs_dir3_block_read(tp, dp, args->owner, &bp);
			if (error)
				return error;
		}
	}

	/*
	 * Set up pointers to parts of the block.
	 */
	hdr = bp->b_addr;
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);

	/*
	 * Find out if we can reuse stale entries or whether we need extra
	 * space for entry and new leaf.
	 */
	xfs_dir2_block_need_space(dp, hdr, btp, blp, &tagp, &dup,
				  &enddup, &compact, len);

	/*
	 * Done everything we need for a space check now.
	 */
	if (args->op_flags & XFS_DA_OP_JUSTCHECK) {
		xfs_trans_brelse(tp, bp);
		if (!dup)
			return -ENOSPC;
		return 0;
	}

	/*
	 * If we don't have space for the new entry & leaf ...
	 */
	if (!dup) {
		/* Don't have a space reservation: return no-space.  */
		if (args->total == 0)
			return -ENOSPC;
		/*
		 * Convert to the next larger format.
		 * Then add the new entry in that format.
		 */
		error = xfs_dir2_block_to_leaf(args, bp);
		if (error)
			return error;
		return xfs_dir2_leaf_addname(args);
	}

	needlog = needscan = 0;

	/*
	 * If need to compact the leaf entries, do it now.
	 */
	if (compact) {
		xfs_dir2_block_compact(args, bp, hdr, btp, blp, &needlog,
				      &lfloghigh, &lfloglow);
		/* recalculate blp post-compaction */
		blp = xfs_dir2_block_leaf_p(btp);
	} else if (btp->stale) {
		/*
		 * Set leaf logging boundaries to impossible state.
		 * For the no-stale case they're set explicitly.
		 */
		lfloglow = be32_to_cpu(btp->count);
		lfloghigh = -1;
	}

	/*
	 * Find the slot that's first lower than our hash value, -1 if none.
	 */
	for (low = 0, high = be32_to_cpu(btp->count) - 1; low <= high; ) {
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(blp[mid].hashval)) == args->hashval)
			break;
		if (hash < args->hashval)
			low = mid + 1;
		else
			high = mid - 1;
	}
	while (mid >= 0 && be32_to_cpu(blp[mid].hashval) >= args->hashval) {
		mid--;
	}
	/*
	 * No stale entries, will use enddup space to hold new leaf.
	 */
	if (!btp->stale) {
		xfs_dir2_data_aoff_t	aoff;

		/*
		 * Mark the space needed for the new leaf entry, now in use.
		 */
		aoff = (xfs_dir2_data_aoff_t)((char *)enddup - (char *)hdr +
				be16_to_cpu(enddup->length) - sizeof(*blp));
		error = xfs_dir2_data_use_free(args, bp, enddup, aoff,
				(xfs_dir2_data_aoff_t)sizeof(*blp), &needlog,
				&needscan);
		if (error)
			return error;

		/*
		 * Update the tail (entry count).
		 */
		be32_add_cpu(&btp->count, 1);
		/*
		 * If we now need to rebuild the bestfree map, do so.
		 * This needs to happen before the next call to use_free.
		 */
		if (needscan) {
			xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
			needscan = 0;
		}
		/*
		 * Adjust pointer to the first leaf entry, we're about to move
		 * the table up one to open up space for the new leaf entry.
		 * Then adjust our index to match.
		 */
		blp--;
		mid++;
		if (mid)
			memmove(blp, &blp[1], mid * sizeof(*blp));
		lfloglow = 0;
		lfloghigh = mid;
	}
	/*
	 * Use a stale leaf for our new entry.
	 */
	else {
		for (lowstale = mid;
		     lowstale >= 0 &&
			blp[lowstale].address !=
			cpu_to_be32(XFS_DIR2_NULL_DATAPTR);
		     lowstale--)
			continue;
		for (highstale = mid + 1;
		     highstale < be32_to_cpu(btp->count) &&
			blp[highstale].address !=
			cpu_to_be32(XFS_DIR2_NULL_DATAPTR) &&
			(lowstale < 0 || mid - lowstale > highstale - mid);
		     highstale++)
			continue;
		/*
		 * Move entries toward the low-numbered stale entry.
		 */
		if (lowstale >= 0 &&
		    (highstale == be32_to_cpu(btp->count) ||
		     mid - lowstale <= highstale - mid)) {
			if (mid - lowstale)
				memmove(&blp[lowstale], &blp[lowstale + 1],
					(mid - lowstale) * sizeof(*blp));
			lfloglow = min(lowstale, lfloglow);
			lfloghigh = max(mid, lfloghigh);
		}
		/*
		 * Move entries toward the high-numbered stale entry.
		 */
		else {
			ASSERT(highstale < be32_to_cpu(btp->count));
			mid++;
			if (highstale - mid)
				memmove(&blp[mid + 1], &blp[mid],
					(highstale - mid) * sizeof(*blp));
			lfloglow = min(mid, lfloglow);
			lfloghigh = max(highstale, lfloghigh);
		}
		be32_add_cpu(&btp->stale, -1);
	}
	/*
	 * Point to the new data entry.
	 */
	dep = (xfs_dir2_data_entry_t *)dup;
	/*
	 * Fill in the leaf entry.
	 */
	blp[mid].hashval = cpu_to_be32(args->hashval);
	blp[mid].address = cpu_to_be32(xfs_dir2_byte_to_dataptr(
				(char *)dep - (char *)hdr));
	xfs_dir2_block_log_leaf(tp, bp, lfloglow, lfloghigh);
	/*
	 * Mark space for the data entry used.
	 */
	error = xfs_dir2_data_use_free(args, bp, dup,
			(xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr),
			(xfs_dir2_data_aoff_t)len, &needlog, &needscan);
	if (error)
		return error;
	/*
	 * Create the new data entry.
	 */
	dep->inumber = cpu_to_be64(args->inumber);
	dep->namelen = args->namelen;
	memcpy(dep->name, args->name, args->namelen);
	xfs_dir2_data_put_ftype(dp->i_mount, dep, args->filetype);
	tagp = xfs_dir2_data_entry_tag_p(dp->i_mount, dep);
	*tagp = cpu_to_be16((char *)dep - (char *)hdr);
	/*
	 * Clean up the bestfree array and log the header, tail, and entry.
	 */
	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	if (needlog)
		xfs_dir2_data_log_header(args, bp);
	xfs_dir2_block_log_tail(tp, bp);
	xfs_dir2_data_log_entry(args, bp, dep);
	xfs_dir3_data_check(dp, bp);
	return 0;
}

/*
 * Log leaf entries from the block.
 */
static void
xfs_dir2_block_log_leaf(
	xfs_trans_t		*tp,		/* transaction structure */
	struct xfs_buf		*bp,		/* block buffer */
	int			first,		/* index of first logged leaf */
	int			last)		/* index of last logged leaf */
{
	xfs_dir2_data_hdr_t	*hdr = bp->b_addr;
	xfs_dir2_leaf_entry_t	*blp;
	xfs_dir2_block_tail_t	*btp;

	btp = xfs_dir2_block_tail_p(tp->t_mountp->m_dir_geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	xfs_trans_log_buf(tp, bp, (uint)((char *)&blp[first] - (char *)hdr),
		(uint)((char *)&blp[last + 1] - (char *)hdr - 1));
}

/*
 * Log the block tail.
 */
static void
xfs_dir2_block_log_tail(
	xfs_trans_t		*tp,		/* transaction structure */
	struct xfs_buf		*bp)		/* block buffer */
{
	xfs_dir2_data_hdr_t	*hdr = bp->b_addr;
	xfs_dir2_block_tail_t	*btp;

	btp = xfs_dir2_block_tail_p(tp->t_mountp->m_dir_geo, hdr);
	xfs_trans_log_buf(tp, bp, (uint)((char *)btp - (char *)hdr),
		(uint)((char *)(btp + 1) - (char *)hdr - 1));
}

/*
 * Look up an entry in the block.  This is the external routine,
 * xfs_dir2_block_lookup_int does the real work.
 */
int						/* error */
xfs_dir2_block_lookup(
	xfs_da_args_t		*args)		/* dir lookup arguments */
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* entry index */
	int			error;		/* error return value */

	trace_xfs_dir2_block_lookup(args);

	/*
	 * Get the buffer, look up the entry.
	 * If not found (ENOENT) then return, have no buffer.
	 */
	if ((error = xfs_dir2_block_lookup_int(args, &bp, &ent)))
		return error;
	dp = args->dp;
	hdr = bp->b_addr;
	xfs_dir3_data_check(dp, bp);
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Get the offset from the leaf entry, to point to the data.
	 */
	dep = (xfs_dir2_data_entry_t *)((char *)hdr +
			xfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	/*
	 * Fill in inode number, CI name if appropriate, release the block.
	 */
	args->inumber = be64_to_cpu(dep->inumber);
	args->filetype = xfs_dir2_data_get_ftype(dp->i_mount, dep);
	error = xfs_dir_cilookup_result(args, dep->name, dep->namelen);
	xfs_trans_brelse(args->trans, bp);
	return error;
}

/*
 * Internal block lookup routine.
 */
static int					/* error */
xfs_dir2_block_lookup_int(
	xfs_da_args_t		*args,		/* dir lookup arguments */
	struct xfs_buf		**bpp,		/* returned block buffer */
	int			*entno)		/* returned entry number */
{
	xfs_dir2_dataptr_t	addr;		/* data entry address */
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			error;		/* error return value */
	xfs_dahash_t		hash;		/* found hash value */
	int			high;		/* binary search high index */
	int			low;		/* binary search low index */
	int			mid;		/* binary search current idx */
	xfs_trans_t		*tp;		/* transaction pointer */
	enum xfs_dacmp		cmp;		/* comparison result */

	dp = args->dp;
	tp = args->trans;

	/* P-BLKLK (RULE-4): log the reading dir inode's coherence state right
	 * BEFORE the block read (survives the read-verify shutdown) so we can
	 * tell whether an owner-mismatch is a STALE REUSED in-core inode
	 * (incore state diverged from disk) vs a genuine block double-alloc. */
	if (dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(dp)->i_mode)) {
		pr_warn_ratelimited(
			"mxfs: P-BLKLK ino=%llu owner=%llu incore_gen=%u fmt=%u nx=%llu dlm_mode=%u dir_gen=%u loaded_gen=%u self=%d reused=%d stale=%d comm=%s — about to block-read for lookup\n",
			(unsigned long long)dp->i_ino,
			(unsigned long long)args->owner,
			VFS_I(dp)->i_generation, dp->i_df.if_format,
			(unsigned long long)dp->i_df.if_nextents,
			dp->i_dlm_mode, dp->i_dlm_dir_gen,
			dp->i_dlm_dir_loaded_gen,
			dp->i_mxfs_self_created ? 1 : 0,
			dp->i_mxfs_reused_create ? 1 : 0,
			dp->i_dlm_stale ? 1 : 0, current->comm);
	}

	error = xfs_dir3_block_read(tp, dp, args->owner, &bp);
	if (error)
		return error;

	hdr = bp->b_addr;
	xfs_dir3_data_check(dp, bp);
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Loop doing a binary search for our hash value.
	 * Find our entry, ENOENT if it's not there.
	 */
	for (low = 0, high = be32_to_cpu(btp->count) - 1; ; ) {
		ASSERT(low <= high);
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(blp[mid].hashval)) == args->hashval)
			break;
		if (hash < args->hashval)
			low = mid + 1;
		else
			high = mid - 1;
		if (low > high) {
			ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
			xfs_trans_brelse(tp, bp);
			return -ENOENT;
		}
	}
	/*
	 * Back up to the first one with the right hash value.
	 */
	while (mid > 0 && be32_to_cpu(blp[mid - 1].hashval) == args->hashval) {
		mid--;
	}
	/*
	 * Now loop forward through all the entries with the
	 * right hash value looking for our name.
	 */
	do {
		if ((addr = be32_to_cpu(blp[mid].address)) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Get pointer to the entry from the leaf.
		 */
		dep = (xfs_dir2_data_entry_t *)
			((char *)hdr + xfs_dir2_dataptr_to_off(args->geo, addr));
		/*
		 * Compare name and if it's an exact match, return the index
		 * and buffer. If it's the first case-insensitive match, store
		 * the index and buffer and continue looking for an exact match.
		 */
		cmp = xfs_dir2_compname(args, dep->name, dep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			*bpp = bp;
			*entno = mid;
			if (cmp == XFS_CMP_EXACT)
				return 0;
		}
	} while (++mid < be32_to_cpu(btp->count) &&
			be32_to_cpu(blp[mid].hashval) == hash);

	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or replace).
	 * If a case-insensitive match was found earlier, return success.
	 */
	if (args->cmpresult == XFS_CMP_CASE)
		return 0;
	/*
	 * No match, release the buffer and return ENOENT.
	 */
	xfs_trans_brelse(tp, bp);
	return -ENOENT;
}

/*
 * Remove an entry from a block format directory.
 * If that makes the block small enough to fit in shortform, transform it.
 */
int						/* error */
xfs_dir2_block_removename(
	xfs_da_args_t		*args)		/* directory operation args */
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf pointer */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* block leaf entry index */
	int			error;		/* error return value */
	int			needlog;	/* need to log block header */
	int			needscan;	/* need to fixup bestfree */
	xfs_dir2_sf_hdr_t	sfh;		/* shortform header */
	int			size;		/* shortform size */
	xfs_trans_t		*tp;		/* transaction pointer */

	trace_xfs_dir2_block_removename(args);

	/*
	 * Look up the entry in the block.  Gets the buffer and entry index.
	 * It will always be there, the vnodeops level does a lookup first.
	 */
	if ((error = xfs_dir2_block_lookup_int(args, &bp, &ent))) {
		return error;
	}
	dp = args->dp;
	tp = args->trans;
	hdr = bp->b_addr;
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Point to the data entry using the leaf entry.
	 */
	dep = (xfs_dir2_data_entry_t *)((char *)hdr +
			xfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	/*
	 * Mark the data entry's space free.
	 */
	needlog = needscan = 0;
	xfs_dir2_data_make_free(args, bp,
		(xfs_dir2_data_aoff_t)((char *)dep - (char *)hdr),
		xfs_dir2_data_entsize(dp->i_mount, dep->namelen), &needlog,
		&needscan);
	/*
	 * Fix up the block tail.
	 */
	be32_add_cpu(&btp->stale, 1);
	xfs_dir2_block_log_tail(tp, bp);
	/*
	 * Remove the leaf entry by marking it stale.
	 */
	blp[ent].address = cpu_to_be32(XFS_DIR2_NULL_DATAPTR);
	xfs_dir2_block_log_leaf(tp, bp, ent, ent);
	/*
	 * Fix up bestfree, log the header if necessary.
	 */
	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	if (needlog)
		xfs_dir2_data_log_header(args, bp);
	xfs_dir3_data_check(dp, bp);
	/*
	 * See if the size as a shortform is good enough.
	 */
	size = xfs_dir2_block_sfsize(dp, hdr, &sfh);
	if (size > xfs_inode_data_fork_size(dp))
		return 0;

	/*
	 * If it works, do the conversion.
	 */
	return xfs_dir2_block_to_sf(args, bp, size, &sfh);
}

/*
 * Replace an entry in a V2 block directory.
 * Change the inode number to the new value.
 */
int						/* error */
xfs_dir2_block_replace(
	xfs_da_args_t		*args)		/* directory operation args */
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* leaf entry index */
	int			error;		/* error return value */

	trace_xfs_dir2_block_replace(args);

	/*
	 * Lookup the entry in the directory.  Get buffer and entry index.
	 * This will always succeed since the caller has already done a lookup.
	 */
	if ((error = xfs_dir2_block_lookup_int(args, &bp, &ent))) {
		return error;
	}
	dp = args->dp;
	hdr = bp->b_addr;
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Point to the data entry we need to change.
	 */
	dep = (xfs_dir2_data_entry_t *)((char *)hdr +
			xfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	ASSERT(be64_to_cpu(dep->inumber) != args->inumber);
	/*
	 * Change the inode number to the new value.
	 */
	dep->inumber = cpu_to_be64(args->inumber);
	xfs_dir2_data_put_ftype(dp->i_mount, dep, args->filetype);
	xfs_dir2_data_log_entry(args, bp, dep);
	xfs_dir3_data_check(dp, bp);
	return 0;
}

/*
 * Qsort comparison routine for the block leaf entries.
 */
static int					/* sort order */
xfs_dir2_block_sort(
	const void			*a,	/* first leaf entry */
	const void			*b)	/* second leaf entry */
{
	const xfs_dir2_leaf_entry_t	*la;	/* first leaf entry */
	const xfs_dir2_leaf_entry_t	*lb;	/* second leaf entry */

	la = a;
	lb = b;
	return be32_to_cpu(la->hashval) < be32_to_cpu(lb->hashval) ? -1 :
		(be32_to_cpu(la->hashval) > be32_to_cpu(lb->hashval) ? 1 : 0);
}

/*
 * Convert a V2 leaf directory to a V2 block directory if possible.
 */
int						/* error */
xfs_dir2_leaf_to_block(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		*lbp,		/* leaf buffer */
	struct xfs_buf		*dbp)		/* data buffer */
{
	__be16			*bestsp;	/* leaf bests table */
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_inode_t		*dp;		/* incore directory inode */
	xfs_dir2_data_unused_t	*dup;		/* unused data entry */
	int			error;		/* error return value */
	int			from;		/* leaf from index */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */
	xfs_mount_t		*mp;		/* file system mount point */
	int			needlog;	/* need to log data header */
	int			needscan;	/* need to scan for bestfree */
	xfs_dir2_sf_hdr_t	sfh;		/* shortform header */
	int			size;		/* bytes used */
	__be16			*tagp;		/* end of entry (tag) */
	int			to;		/* block/leaf to index */
	xfs_trans_t		*tp;		/* transaction pointer */
	struct xfs_dir3_icleaf_hdr leafhdr;

	trace_xfs_dir2_leaf_to_block(args);

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;
	leaf = lbp->b_addr;
	xfs_dir2_leaf_hdr_from_disk(mp, &leafhdr, leaf);
	ltp = xfs_dir2_leaf_tail_p(args->geo, leaf);

	{
		extern unsigned long long mxfs_watch_ino;

		if (unlikely(mxfs_watch_ino) && dp->i_ino == mxfs_watch_ino)
			pr_warn("mxfs: PW-LEAF2BLOCK ino=%llu nx=%llu size=%lld pin=%d comm=%s realns=%llu\n",
				(unsigned long long)dp->i_ino,
				(unsigned long long)dp->i_df.if_nextents,
				(long long)dp->i_disk_size,
				atomic_read(&dp->i_pincount),
				current->comm,
				(unsigned long long)ktime_get_real_ns());
	}

	ASSERT(leafhdr.magic == XFS_DIR2_LEAF1_MAGIC ||
	       leafhdr.magic == XFS_DIR3_LEAF1_MAGIC);
	/*
	 * If there are data blocks other than the first one, take this
	 * opportunity to remove trailing empty data blocks that may have
	 * been left behind during no-space-reservation operations.
	 * These will show up in the leaf bests table.
	 */
	while (dp->i_disk_size > args->geo->blksize) {
		int hdrsz;

		hdrsz = args->geo->data_entry_offset;
		bestsp = xfs_dir2_leaf_bests_p(ltp);
		if (be16_to_cpu(bestsp[be32_to_cpu(ltp->bestcount) - 1]) ==
					    args->geo->blksize - hdrsz) {
			if ((error =
			    xfs_dir2_leaf_trim_data(args, lbp,
				    (xfs_dir2_db_t)(be32_to_cpu(ltp->bestcount) - 1))))
				return error;
		} else
			return 0;
	}
	/*
	 * Read the data block if we don't already have it, give up if it fails.
	 */
	if (!dbp) {
		error = xfs_dir3_data_read(tp, dp, args->owner,
				args->geo->datablk, 0, &dbp);
		if (error)
			return error;
	}
	hdr = dbp->b_addr;
	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC));

	/*
	 * sess69 RULE-4 PROBE (always-on, ratelimited): the leaf->block reshape
	 * consolidates the dir into ONE block; the resulting active-entry set is
	 * leafhdr.count-leafhdr.stale, copied verbatim from the LEAF buffer (lbp).
	 * If lbp is a STALE cached image (gen lags i_dlm_dir_gen, or it was
	 * stranded in-AIL so the lazy read hook skipped it), the reshape
	 * resurrects peers' already-deleted dirents into the new block and the
	 * release fence durably lands it = the proven unlink_visibility lost
	 * update.  Dump both source buffers' coherency state to confirm.
	 */
	{
		struct xfs_buf_log_item	*l_bip = lbp ? lbp->b_log_item : NULL;
		struct xfs_buf_log_item	*d_bip = dbp ? dbp->b_log_item : NULL;
		pr_warn_ratelimited(
		    "mxfs: P69-L2B ino=%llu dlm_gen=%llu active=%d "
		    "LEAF daddr=%llu gen=%u in_ail=%d pin=%d "
		    "DATA daddr=%llu gen=%u in_ail=%d pin=%d\n",
		    (unsigned long long)dp->i_ino,
		    (unsigned long long)dp->i_dlm_dir_gen,
		    (int)(leafhdr.count - leafhdr.stale),
		    lbp ? (unsigned long long)lbp->b_maps[0].bm_bn : 0,
		    lbp ? lbp->b_mxfs_dir_gen : 0,
		    !!(l_bip && test_bit(XFS_LI_IN_AIL, &l_bip->bli_item.li_flags)),
		    lbp ? xfs_buf_ispinned(lbp) : 0,
		    dbp ? (unsigned long long)dbp->b_maps[0].bm_bn : 0,
		    dbp ? dbp->b_mxfs_dir_gen : 0,
		    !!(d_bip && test_bit(XFS_LI_IN_AIL, &d_bip->bli_item.li_flags)),
		    dbp ? xfs_buf_ispinned(dbp) : 0);
	}

	/*
	 * Size of the "leaf" area in the block.
	 */
	size = (uint)sizeof(xfs_dir2_block_tail_t) +
	       (uint)sizeof(*lep) * (leafhdr.count - leafhdr.stale);
	/*
	 * Look at the last data entry.
	 */
	tagp = (__be16 *)((char *)hdr + args->geo->blksize) - 1;
	dup = (xfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));
	/*
	 * If it's not free or is too short we can't do it.
	 */
	if (be16_to_cpu(dup->freetag) != XFS_DIR2_DATA_FREE_TAG ||
	    be16_to_cpu(dup->length) < size)
		return 0;

	/*
	 * Start converting it to block form.
	 */
	xfs_dir3_block_init(args, dbp);

	needlog = 1;
	needscan = 0;
	/*
	 * Use up the space at the end of the block (blp/btp).
	 */
	error = xfs_dir2_data_use_free(args, dbp, dup,
			args->geo->blksize - size, size, &needlog, &needscan);
	if (error)
		return error;
	/*
	 * Initialize the block tail.
	 */
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	btp->count = cpu_to_be32(leafhdr.count - leafhdr.stale);
	btp->stale = 0;
	xfs_dir2_block_log_tail(tp, dbp);
	/*
	 * Initialize the block leaf area.  We compact out stale entries.
	 */
	lep = xfs_dir2_block_leaf_p(btp);
	for (from = to = 0; from < leafhdr.count; from++) {
		if (leafhdr.ents[from].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			continue;
		lep[to++] = leafhdr.ents[from];
	}
	ASSERT(to == be32_to_cpu(btp->count));
	xfs_dir2_block_log_leaf(tp, dbp, 0, be32_to_cpu(btp->count) - 1);
	/*
	 * Scan the bestfree if we need it and log the data block header.
	 */
	if (needscan)
		xfs_dir2_data_freescan(dp->i_mount, hdr, &needlog);
	if (needlog)
		xfs_dir2_data_log_header(args, dbp);
	/*
	 * Pitch the old leaf block.
	 */
	error = xfs_da_shrink_inode(args, args->geo->leafblk, lbp);
	if (error)
		return error;

	/*
	 * Now see if the resulting block can be shrunken to shortform.
	 */
	size = xfs_dir2_block_sfsize(dp, hdr, &sfh);
	if (size > xfs_inode_data_fork_size(dp))
		return 0;

	return xfs_dir2_block_to_sf(args, dbp, size, &sfh);
}

/*
 * Convert the shortform directory to block form.
 */
int						/* error */
xfs_dir2_sf_to_block(
	struct xfs_da_args	*args)
{
	struct xfs_trans	*tp = args->trans;
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_ifork	*ifp = xfs_ifork_ptr(dp, XFS_DATA_FORK);
	struct xfs_da_geometry	*geo = args->geo;
	xfs_dir2_db_t		blkno;		/* dir-relative block # (0) */
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail pointer */
	xfs_dir2_data_entry_t	*dep;		/* data entry pointer */
	int			dummy;		/* trash */
	xfs_dir2_data_unused_t	*dup;		/* unused entry pointer */
	int			endoffset;	/* end of data objects */
	int			error;		/* error return value */
	int			i;		/* index */
	int			needlog;	/* need to log block header */
	int			needscan;	/* need to scan block freespc */
	int			newoffset;	/* offset from current entry */
	unsigned int		offset = geo->data_entry_offset;
	xfs_dir2_sf_entry_t	*sfep;		/* sf entry pointer */
	struct xfs_dir2_sf_hdr	*oldsfp = ifp->if_data;
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform header  */
	__be16			*tagp;		/* end of data entry */
	struct xfs_name		name;

	trace_xfs_dir2_sf_to_block(args);

	/* sess62 (RULE 4): UNGATED — is sf->block conversion even being called?
	 * P42-SFCONV logged 0x in a full failing run while the dir was block
	 * format (3 data blocks) and node1_f1 (first dirent) was durably lost
	 * every round.  This fires with NO multinode gate to settle whether the
	 * conversion runs at all (and whether is_single_node mis-reports). */
	{
		static atomic_t p62sc = ATOMIC_INIT(0);
		if (atomic_inc_return(&p62sc) <= 300000) {
			/* sess63: dump the in-core shortform NAMES being frozen into
			 * block0 — decisive on whether node1_f1 (the inaugural dirent)
			 * is in the converting base.  Present => loss is a post-convert
			 * block0 overwrite; absent => the converter froze a stale base
			 * (handoff reload didn't reach it before this conversion). */
			char p62nm[160];
			int p62p = 0, p62k;
			struct xfs_dir2_sf_entry *p62e =
				oldsfp ? xfs_dir2_sf_firstentry(oldsfp) : NULL;

			p62nm[0] = '\0';
			for (p62k = 0; oldsfp && p62k < oldsfp->count &&
			     p62p < (int)sizeof(p62nm) - 14; p62k++) {
				int p62l = min_t(int, p62e->namelen, 11);
				p62p += scnprintf(p62nm + p62p, sizeof(p62nm) - p62p,
						  "%.*s ", p62l, p62e->name);
				p62e = (void *)p62e +
				       xfs_dir2_sf_entsize(mp, oldsfp, p62e->namelen);
			}
			pr_warn("mxfs: P62-SF2BLK-CALLED ino=%llu single=%d sf_count=%u i_gen=%u dlm_mode=%u add=\"%.*s\" comm=%s names=[%s]\n",
				(unsigned long long)dp->i_ino,
				(mp->m_mxfs_dlm ?
				 mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) : -1),
				oldsfp ? oldsfp->count : 0,
				VFS_I(dp)->i_generation, dp->i_dlm_mode,
				args->namelen, args->name, current->comm, p62nm);
		}
	}

	/*
	 * sess42 (ccloop 8ddb16a2) P42-SFCONV (ALWAYS-ON, capped, NO I/O):
	 * the PROVEN dir_reuse_coherency root is a cross-node split of the dir's
	 * LOGICAL block 0 (node1 -> fsb=15, node2 -> fsb=14) because BOTH nodes
	 * convert shortform->block for the SAME incarnation from their own
	 * shortform base instead of the second adopting the first's already-
	 * materialized block0.  This non-perturbing line names EVERY sf->block
	 * conversion (ino, incore shortform size = dirents being frozen,
	 * dir_gen/loaded_gen, dlm_mode, the name triggering it, comm).  Two
	 * P42-SFCONV for the same ino within one incarnation (no rm-rf between)
	 * == the double-conversion that splits block0.  No disk read (unlike
	 * P31E, which perturbs the race); pure in-core fields. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		static atomic_t p42sc = ATOMIC_INIT(0);
		char p42_nm[28];
		int p42_l = min_t(int, args->namelen, 27);

		memcpy(p42_nm, args->name, p42_l);
		p42_nm[p42_l] = '\0';
		if (atomic_inc_return(&p42sc) <= 300000)
			pr_warn("mxfs: P42-SFCONV ino=%llu sf_size=%lld sf_count=%u dir_gen=%u loaded_gen=%u dlm_mode=%u i_gen=%u addname=\"%s\" comm=%s\n",
				(unsigned long long)dp->i_ino,
				(long long)dp->i_disk_size,
				oldsfp ? oldsfp->count : 0,
				dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
				dp->i_dlm_mode,
				VFS_I(dp)->i_generation,
				p42_nm, current->comm);
	}

	/*
	 * sess60 DECISIVE non-perturbing probe (in-core scan, NO disk I/O): is
	 * node1_f1 (the durably-lost first dirent) PRESENT in the shortform base
	 * being frozen into block0?  ABSENT => the converter (test2) adopted a
	 * STALE shortform base missing rank1's committed first entry, and the
	 * conversion permanently drops it (the root).  PRESENT => the loss is
	 * downstream of the conversion (a later block0 RMW).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    oldsfp) {
		static atomic_t p60sc = ATOMIC_INIT(0);
		if (atomic_inc_return(&p60sc) <= 300000) {
			struct xfs_dir2_sf_entry *se =
				xfs_dir2_sf_firstentry(oldsfp);
			int k, n1cnt = 0, has_n1f1 = 0;

			for (k = 0; k < oldsfp->count && se; k++) {
				if (se->namelen >= 7 &&
				    memcmp(se->name, "node1_f", 7) == 0) {
					n1cnt++;
					if (se->namelen == 8 &&
					    se->name[7] == '1')
						has_n1f1 = 1;
				}
				se = xfs_dir2_sf_nextentry(mp, oldsfp, se);
			}
			pr_warn("mxfs: P60-SFCONV-BASE ino=%llu i_gen=%u sf_count=%u node1f_cnt=%d has_node1_f1=%d add=\"%.*s\" comm=%s\n",
				(unsigned long long)dp->i_ino,
				VFS_I(dp)->i_generation,
				oldsfp->count, n1cnt, has_n1f1,
				args->namelen, args->name, current->comm);
		}
	}

	/* sess34 P-H14-INSTR: log every LOCAL→BLOCK format transition.  This
	 * is the suspected leak point for test_concurrent_mkdir's lost first
	 * entry from peer's view.
	 *
	 * sess15 (RULE 4, GPT-confirmed #1 hypothesis): dump the FULL in-core
	 * shortform NAME LIST being frozen into block0.  Cross-reference with
	 * P-SFREL (release-side raw on-disk SF names): if a peer's durably-
	 * committed dirent (on-disk via P-SFREL) is ABSENT from this in-core SF
	 * at conversion, the cross-node reload/3-way-merge failed to adopt it and
	 * xfs_dir2_sf_to_block permanently drops it into the new block format. */
	{
		extern int mxfs_instr_enabled;  /* sess36: gate diagnostic */
		extern int mxfs_dirwr_enabled;
		if (unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled)) {
			struct xfs_dir2_sf_hdr *p14_sfp = (struct xfs_dir2_sf_hdr *)ifp->if_data;
			char p14_name[32] = "";
			int p14_namelen = min_t(int, args->namelen, 31);
			char p14_list[240];
			int p14_pos = 0, p14_k;
			memcpy(p14_name, args->name, p14_namelen);
			p14_name[p14_namelen] = '\0';
			p14_list[0] = '\0';
			if (p14_sfp) {
				struct xfs_dir2_sf_entry *p14_e =
					xfs_dir2_sf_firstentry(p14_sfp);
				for (p14_k = 0; p14_k < p14_sfp->count &&
				     p14_pos < (int)sizeof(p14_list) - 14; p14_k++) {
					int nl = min_t(int, p14_e->namelen, 12);
					p14_pos += scnprintf(p14_list + p14_pos,
						sizeof(p14_list) - p14_pos, "%.*s ",
						nl, p14_e->name);
					p14_e = (void *)p14_e +
						xfs_dir2_sf_entsize(mp, p14_sfp, p14_e->namelen);
				}
			}
			pr_warn("mxfs: P-H14-INSTR sf_to_block START ino=%llu sf_count=%u sf_size=%u adding=\"%s\" incore_names=[%s]",
				(unsigned long long)dp->i_ino,
				p14_sfp ? p14_sfp->count : 0,
				(unsigned int)ifp->if_bytes,
				p14_name, p14_list);
		}
	}

	ASSERT(ifp->if_format == XFS_DINODE_FMT_LOCAL);
	ASSERT(dp->i_disk_size >= offsetof(struct xfs_dir2_sf_hdr, parent));

	ASSERT(ifp->if_bytes == dp->i_disk_size);
	ASSERT(oldsfp != NULL);
	ASSERT(dp->i_disk_size >= xfs_dir2_sf_hdr_size(oldsfp->i8count));
	ASSERT(dp->i_df.if_nextents == 0);

	/*
	 * Copy the directory into a temporary buffer.
	 * Then pitch the incore inode data so we can make extents.
	 */
	sfp = kmalloc(ifp->if_bytes, GFP_KERNEL | __GFP_NOFAIL);
	memcpy(sfp, oldsfp, ifp->if_bytes);

	xfs_idata_realloc(dp, -ifp->if_bytes, XFS_DATA_FORK);
	xfs_bmap_local_to_extents_empty(tp, dp, XFS_DATA_FORK);
	dp->i_disk_size = 0;

	/*
	 * Add block 0 to the inode.
	 */
	error = xfs_dir2_grow_inode(args, XFS_DIR2_DATA_SPACE, &blkno);
	if (error)
		goto out_free;

	/*
	 * ccloop(3e02e7dd) sess3: publish the canonical block0 for this
	 * incarnation NOW that xfs_dir2_grow_inode has committed the extent
	 * mapping logical block0 to a physical fsb — see
	 * docs/canonical_block0_fix_plan.md and the dir_block0_fsb comment in
	 * struct mxfs_caw_lock_slot.  Cheap (we already hold EX; no extra
	 * acquire), CAW-only, write-once (a no-op if a peer already published
	 * for this same incarnation — mxfs_dlm_caw_set_dir_block0), and race-
	 * free against the very double-conversion this closes: only one node
	 * can hold EX on this inode at a time, so whichever of two racing
	 * converters gets here first wins the publish; the other's later
	 * mxfs_dlm_dir_modify_reload_prelock check adopts instead of
	 * re-converting.
	 */
	if (mp->m_mxfs_dlm && mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
		struct xfs_iext_cursor p3cur;
		struct xfs_bmbt_irec p3got;

		if (xfs_iext_lookup_extent(dp, ifp, 0, &p3cur, &p3got) &&
		    p3got.br_startblock != HOLESTARTBLOCK)
			mxfs_v5_dlm_inode_set_dir_block0(mp->m_mxfs_dlm,
				dp->i_ino, (uint64_t)p3got.br_startblock,
				VFS_I(dp)->i_generation);
	}

	/*
	 * Initialize the data block, then convert it to block format.
	 */
	error = xfs_dir3_data_init(args, blkno, &bp);
	if (error)
		goto out_free;
	xfs_dir3_block_init(args, bp);
	hdr = bp->b_addr;

	/*
	 * Compute size of block "tail" area.
	 */
	i = (uint)sizeof(*btp) +
	    (sfp->count + 2) * (uint)sizeof(xfs_dir2_leaf_entry_t);
	/*
	 * The whole thing is initialized to free by the init routine.
	 * Say we're using the leaf and tail area.
	 */
	dup = bp->b_addr + offset;
	needlog = needscan = 0;
	error = xfs_dir2_data_use_free(args, bp, dup, args->geo->blksize - i,
			i, &needlog, &needscan);
	if (error)
		goto out_free;
	ASSERT(needscan == 0);
	/*
	 * Fill in the tail.
	 */
	btp = xfs_dir2_block_tail_p(args->geo, hdr);
	btp->count = cpu_to_be32(sfp->count + 2);	/* ., .. */
	btp->stale = 0;
	blp = xfs_dir2_block_leaf_p(btp);
	endoffset = (uint)((char *)blp - (char *)hdr);
	/*
	 * Remove the freespace, we'll manage it.
	 */
	error = xfs_dir2_data_use_free(args, bp, dup,
			(xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr),
			be16_to_cpu(dup->length), &needlog, &needscan);
	if (error)
		goto out_free;

	/*
	 * Create entry for .
	 */
	dep = bp->b_addr + offset;
	dep->inumber = cpu_to_be64(args->owner);
	dep->namelen = 1;
	dep->name[0] = '.';
	xfs_dir2_data_put_ftype(mp, dep, XFS_DIR3_FT_DIR);
	tagp = xfs_dir2_data_entry_tag_p(mp, dep);
	*tagp = cpu_to_be16(offset);
	xfs_dir2_data_log_entry(args, bp, dep);
	blp[0].hashval = cpu_to_be32(xfs_dir_hash_dot);
	blp[0].address = cpu_to_be32(xfs_dir2_byte_to_dataptr(offset));
	offset += xfs_dir2_data_entsize(mp, dep->namelen);

	/*
	 * Create entry for ..
	 */
	dep = bp->b_addr + offset;
	dep->inumber = cpu_to_be64(xfs_dir2_sf_get_parent_ino(sfp));
	dep->namelen = 2;
	dep->name[0] = dep->name[1] = '.';
	xfs_dir2_data_put_ftype(mp, dep, XFS_DIR3_FT_DIR);
	tagp = xfs_dir2_data_entry_tag_p(mp, dep);
	*tagp = cpu_to_be16(offset);
	xfs_dir2_data_log_entry(args, bp, dep);
	blp[1].hashval = cpu_to_be32(xfs_dir_hash_dotdot);
	blp[1].address = cpu_to_be32(xfs_dir2_byte_to_dataptr(offset));
	offset += xfs_dir2_data_entsize(mp, dep->namelen);

	/*
	 * Loop over existing entries, stuff them in.
	 */
	i = 0;
	if (!sfp->count)
		sfep = NULL;
	else
		sfep = xfs_dir2_sf_firstentry(sfp);

	/*
	 * Need to preserve the existing offset values in the sf directory.
	 * Insert holes (unused entries) where necessary.
	 */
	while (offset < endoffset) {
		/*
		 * sfep is null when we reach the end of the list.
		 */
		if (sfep == NULL)
			newoffset = endoffset;
		else
			newoffset = xfs_dir2_sf_get_offset(sfep);
		/*
		 * There should be a hole here, make one.
		 */
		if (offset < newoffset) {
			dup = bp->b_addr + offset;
			dup->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
			dup->length = cpu_to_be16(newoffset - offset);
			*xfs_dir2_data_unused_tag_p(dup) = cpu_to_be16(offset);
			xfs_dir2_data_log_unused(args, bp, dup);
			xfs_dir2_data_freeinsert(hdr,
					xfs_dir2_data_bestfree_p(mp, hdr),
					dup, &dummy);
			offset += be16_to_cpu(dup->length);
			continue;
		}
		/*
		 * Copy a real entry.
		 */
		dep = bp->b_addr + newoffset;
		dep->inumber = cpu_to_be64(xfs_dir2_sf_get_ino(mp, sfp, sfep));
		dep->namelen = sfep->namelen;
		xfs_dir2_data_put_ftype(mp, dep,
				xfs_dir2_sf_get_ftype(mp, sfep));
		memcpy(dep->name, sfep->name, dep->namelen);
		/* sess34 P-H14b: log each entry copied from inline to block.
		 * sess36: gated — this fires PER-DIRENT in the hot path. */
		{
			extern int mxfs_instr_enabled;
			if (unlikely(mxfs_instr_enabled)) {
				char p14b_name[32] = "";
				int p14b_len = min_t(int, sfep->namelen, 31);
				memcpy(p14b_name, sfep->name, p14b_len);
				p14b_name[p14b_len] = '\0';
				pr_warn("mxfs: P-H14b-INSTR sf_to_block COPY ino=%llu i=%d/%u name=\"%s\" namelen=%u offset=%d",
					(unsigned long long)dp->i_ino,
					i, sfp->count, p14b_name,
					(unsigned int)sfep->namelen, newoffset);
			}
		}
		tagp = xfs_dir2_data_entry_tag_p(mp, dep);
		*tagp = cpu_to_be16(newoffset);
		xfs_dir2_data_log_entry(args, bp, dep);
		name.name = sfep->name;
		name.len = sfep->namelen;
		blp[2 + i].hashval = cpu_to_be32(xfs_dir2_hashname(mp, &name));
		blp[2 + i].address =
			cpu_to_be32(xfs_dir2_byte_to_dataptr(newoffset));
		offset = (int)((char *)(tagp + 1) - (char *)hdr);
		if (++i == sfp->count)
			sfep = NULL;
		else
			sfep = xfs_dir2_sf_nextentry(mp, sfp, sfep);
	}
	/* Done with the temporary buffer */
	kfree(sfp);
	/*
	 * Sort the leaf entries by hash value.
	 */
	xfs_sort(blp, be32_to_cpu(btp->count), sizeof(*blp), xfs_dir2_block_sort);
	/*
	 * Log the leaf entry area and tail.
	 * Already logged the header in data_init, ignore needlog.
	 */
	ASSERT(needscan == 0);
	xfs_dir2_block_log_leaf(tp, bp, 0, be32_to_cpu(btp->count) - 1);
	xfs_dir2_block_log_tail(tp, bp);
	xfs_dir3_data_check(dp, bp);
	return 0;
out_free:
	kfree(sfp);
	return error;
}
