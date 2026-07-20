// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_bit.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_trace.h"
#include "xfs_bmap.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_error.h"
#include "xfs_health.h"
#include "xfs_mxfs_dlm.h"
#include "../dlm/v5_mount.h"

/*
 * Directory file type support functions
 */
static unsigned char xfs_dir3_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK,
	DT_FIFO, DT_SOCK, DT_LNK, DT_WHT,
};

unsigned char
xfs_dir3_get_dtype(
	struct xfs_mount	*mp,
	uint8_t			filetype)
{
	if (!xfs_has_ftype(mp))
		return DT_UNKNOWN;

	if (filetype >= XFS_DIR3_FT_MAX)
		return DT_UNKNOWN;

	return xfs_dir3_filetype_table[filetype];
}

/*
 * sess10(a9a03929) RULE-4 readdir-tear instrumentation.
 *
 * r8 round-13 dir_reuse: every node's readdir returned the IDENTICAL short
 * view (341/400, and 390/400 in round 6) across two consecutive getdents
 * passes, while every missing name stayed lookup-able and the round's
 * cleanup removed all 400 — a transient, globally-consistent stale
 * DATA-block view confined to the readdir path.  P49-STALEBASE and
 * P13-COLLIDE fired 0x, so no placement-time clobber.  Two probes split
 * stale-cache from stale-platter:
 *
 *   mxfs_dirblk_count_active() — active-dirent counter over one dir data
 *   block image (works on an in-core b_addr or a raw platter copy).
 *
 *   P10-RDBLK (xfs_dir2_leaf_getdents) — per data block a storm-dir readdir
 *   consumes, log the active count + buffer epoch/gen/state: a short round
 *   shows exactly which block lagged and what image getdents walked.
 *
 *   mxfs_dirdump() — on-demand dump of EVERY data block of one dir:
 *   in-core cached image count vs coherent platter-read count + buffer and
 *   DLM state.  Triggered from xfs_lookup by the magic name prefix
 *   ".mxfs_dirdump" (the dir_reuse test probes it the moment readdir
 *   returns short) and returns ENOENT without touching the dir's
 *   coherency state.
 */
int
mxfs_dirblk_count_active(
	struct xfs_mount	*mp,
	void			*blk,
	uint32_t		blen)
{
	uint32_t		off = mp->m_dir_geo->data_entry_offset;
	int			n = 0;

	while (off + 8 <= blen) {
		struct xfs_dir2_data_unused *du =
			(void *)((char *)blk + off);
		struct xfs_dir2_data_entry  *de =
			(void *)((char *)blk + off);

		if (be16_to_cpu(du->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint32_t l = be16_to_cpu(du->length);

			if (l < 8)
				break;
			off += l;
			continue;
		}
		if (de->namelen == 0 || off + 9 + de->namelen > blen)
			break;
		n++;
		off += xfs_dir2_data_entsize(mp, de->namelen);
	}
	return n;
}

/*
 * Coherent platter-side active-dirent count for one dir data block.  -1 =
 * infrastructure unavailable / read failed; -2 = the platter image is not a
 * dir3 data/block image (foreign owner or garbage — reused-daddr lineage).
 */
int
mxfs_dirblk_platter_active(
	struct xfs_mount	*mp,
	xfs_daddr_t		daddr)
{
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	uint32_t		blen = mp->m_dir_geo->blksize;
	void			*tmp;
	int			n = -1;

	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return -1;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return -1;
	if (mxfs_pal_bdev_read_plain_bdev(mp->m_ddev_targp->bt_bdev,
			daddr + mp->m_ddev_targp->bt_sector_offset,
			tmp, blen) == 0) {
		struct xfs_dir3_blk_hdr *ph = tmp;
		uint32_t magic = be32_to_cpu(ph->magic);

		if (magic == XFS_DIR3_DATA_MAGIC ||
		    magic == XFS_DIR3_BLOCK_MAGIC)
			n = mxfs_dirblk_count_active(mp, tmp, blen);
		else
			n = -2;
	}
	kfree(tmp);
	return n;
}

void
mxfs_dirdump(
	struct xfs_inode	*dp,
	const char		*why)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo = mp->m_dir_geo;
	uint64_t		nblks;
	uint64_t		i;

	if (!mp->m_mxfs_dlm || xfs_is_shutdown(mp) ||
	    !S_ISDIR(VFS_I(dp)->i_mode))
		return;

	pr_warn("mxfs: P10-DIRDUMP why=%s ino=%llu fmt=%u size=%lld nextents=%llu dlm_mode=%u dir_gen=%llu loaded_gen=%llu valid_ep=%llu stale=%d realns=%llu\n",
		why, (unsigned long long)dp->i_ino, dp->i_df.if_format,
		(long long)dp->i_disk_size,
		(unsigned long long)dp->i_df.if_nextents,
		dp->i_dlm_mode,
		(unsigned long long)dp->i_dlm_dir_gen,
		(unsigned long long)dp->i_dlm_dir_loaded_gen,
		(unsigned long long)dp->i_dlm_dir_valid_epoch,
		dp->i_dlm_stale ? 1 : 0,
		(unsigned long long)ktime_get_real_ns());

	if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL)
		return;

	nblks = dp->i_disk_size >> geo->blklog;
	if (nblks > 32)
		nblks = 32;

	for (i = 0; i < nblks; i++) {
		struct xfs_bmbt_irec	map;
		int			nmap = 1;
		int			err = -EDEADLK;
		xfs_daddr_t		daddr;
		uint32_t		blen = geo->blksize;
		struct xfs_buf		*cbp = NULL;
		void			*tmp;
		int			incore_n = -1, plat_n = -1;
		unsigned long long	b_ep = 0, b_gen = 0;
		unsigned int		bflags = 0;
		int			dirty = -1, inail = -1, pin = -1;
		uint32_t		pmagic = 0;
		uint64_t		powner = 0;

		if (xfs_ilock_nowait(dp, XFS_ILOCK_SHARED)) {
			err = xfs_bmapi_read(dp, i * geo->fsbcount,
					     geo->fsbcount, &map, &nmap, 0);
			xfs_iunlock(dp, XFS_ILOCK_SHARED);
		}
		if (err || nmap != 1 ||
		    isnullstartblock(map.br_startblock) ||
		    map.br_startblock == HOLESTARTBLOCK) {
			pr_warn("mxfs: P10-DIRDUMP-BLK ino=%llu db=%llu MAPFAIL err=%d nmap=%d\n",
				(unsigned long long)dp->i_ino,
				(unsigned long long)i, err, nmap);
			continue;
		}
		daddr = XFS_FSB_TO_DADDR(mp, map.br_startblock);

		if (xfs_buf_incore(mp->m_ddev_targp, daddr,
				   XFS_FSB_TO_BB(mp, geo->fsbcount),
				   XBF_TRYLOCK, &cbp) == 0 && cbp) {
			struct xfs_buf_log_item *bip = cbp->b_log_item;

			if (BBTOB(cbp->b_length) >= blen && cbp->b_addr)
				incore_n = mxfs_dirblk_count_active(mp,
							cbp->b_addr, blen);
			b_ep = cbp->b_mxfs_dir_epoch;
			b_gen = cbp->b_mxfs_dir_gen;
			bflags = cbp->b_flags;
			dirty = bip && test_bit(XFS_LI_DIRTY,
						&bip->bli_item.li_flags);
			inail = bip && test_bit(XFS_LI_IN_AIL,
						&bip->bli_item.li_flags);
			pin = xfs_buf_ispinned(cbp);
			xfs_buf_relse(cbp);
		}

		tmp = kmalloc(blen, GFP_NOFS);
		if (tmp) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint64_t lba = daddr +
				mp->m_ddev_targp->bt_sector_offset;

			if (mp->m_ddev_targp->bt_bdev &&
			    mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev,
					lba, tmp, blen) == 0) {
				struct xfs_dir3_blk_hdr *ph = tmp;

				plat_n = mxfs_dirblk_count_active(mp, tmp,
								  blen);
				pmagic = be32_to_cpu(ph->magic);
				powner = be64_to_cpu(ph->owner);
			}
			kfree(tmp);
		}

		pr_warn("mxfs: P10-DIRDUMP-BLK ino=%llu db=%llu daddr=%lld lba=%llu incore=%d platter=%d pmagic=0x%x powner=%llu b_ep=%llu b_gen=%llu flags=0x%x dirty=%d inail=%d pin=%d\n",
			(unsigned long long)dp->i_ino, (unsigned long long)i,
			(long long)daddr,
			(unsigned long long)(daddr +
				mp->m_ddev_targp->bt_sector_offset),
			incore_n, plat_n, pmagic,
			(unsigned long long)powner, b_ep, b_gen, bflags,
			dirty, inail, pin);
	}

	/* sess12(a9a03929): dump the watched-inode DLM transition ring with
	 * the same trigger — the double-grant forensics need the full local
	 * mode/state history, which the sampled probes cannot give. */
	{
		extern void mxfs_dlmtr_dump(void);
		mxfs_dlmtr_dump();
	}
}

STATIC int
xfs_dir2_sf_getdents(
	struct xfs_da_args	*args,
	struct dir_context	*ctx)
{
	int			i;		/* shortform entry number */
	struct xfs_inode	*dp = args->dp;	/* incore directory inode */
	struct xfs_mount	*mp = dp->i_mount;
	xfs_dir2_dataptr_t	off;		/* current entry's offset */
	xfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	struct xfs_dir2_sf_hdr	*sfp = dp->i_df.if_data;
	xfs_dir2_dataptr_t	dot_offset;
	xfs_dir2_dataptr_t	dotdot_offset;
	xfs_ino_t		ino;
	struct xfs_da_geometry	*geo = args->geo;

	ASSERT(dp->i_df.if_format == XFS_DINODE_FMT_LOCAL);
	ASSERT(dp->i_df.if_bytes == dp->i_disk_size);
	ASSERT(sfp != NULL);

	/*
	 * If the block number in the offset is out of range, we're done.
	 */
	if (xfs_dir2_dataptr_to_db(geo, ctx->pos) > geo->datablk)
		return 0;

	/*
	 * Precalculate offsets for "." and ".." as we will always need them.
	 * This relies on the fact that directories always start with the
	 * entries for "." and "..".
	 */
	dot_offset = xfs_dir2_db_off_to_dataptr(geo, geo->datablk,
			geo->data_entry_offset);
	dotdot_offset = xfs_dir2_db_off_to_dataptr(geo, geo->datablk,
			geo->data_entry_offset +
			xfs_dir2_data_entsize(mp, sizeof(".") - 1));

	/*
	 * Put . entry unless we're starting past it.
	 */
	if (ctx->pos <= dot_offset) {
		ctx->pos = dot_offset & 0x7fffffff;
		if (!dir_emit(ctx, ".", 1, dp->i_ino, DT_DIR))
			return 0;
	}

	/*
	 * Put .. entry unless we're starting past it.
	 */
	if (ctx->pos <= dotdot_offset) {
		ino = xfs_dir2_sf_get_parent_ino(sfp);
		ctx->pos = dotdot_offset & 0x7fffffff;
		if (!dir_emit(ctx, "..", 2, ino, DT_DIR))
			return 0;
	}

	/*
	 * Loop while there are more entries and put'ing works.
	 */
	sfep = xfs_dir2_sf_firstentry(sfp);
	for (i = 0; i < sfp->count; i++) {
		uint8_t filetype;

		off = xfs_dir2_db_off_to_dataptr(geo, geo->datablk,
				xfs_dir2_sf_get_offset(sfep));

		if (ctx->pos > off) {
			sfep = xfs_dir2_sf_nextentry(mp, sfp, sfep);
			continue;
		}

		ino = xfs_dir2_sf_get_ino(mp, sfp, sfep);
		filetype = xfs_dir2_sf_get_ftype(mp, sfep);
		ctx->pos = off & 0x7fffffff;
		if (XFS_IS_CORRUPT(dp->i_mount,
				   !xfs_dir2_namecheck(sfep->name,
						       sfep->namelen))) {
			xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
			return -EFSCORRUPTED;
		}
		if (!dir_emit(ctx, (char *)sfep->name, sfep->namelen, ino,
			    xfs_dir3_get_dtype(mp, filetype)))
			return 0;
		sfep = xfs_dir2_sf_nextentry(mp, sfp, sfep);
	}

	ctx->pos = xfs_dir2_db_off_to_dataptr(geo, geo->datablk + 1, 0) &
								0x7fffffff;
	return 0;
}

/*
 * Readdir for block directories.
 */
STATIC int
xfs_dir2_block_getdents(
	struct xfs_da_args	*args,
	struct dir_context	*ctx,
	unsigned int		*lock_mode)
{
	struct xfs_inode	*dp = args->dp;	/* incore directory inode */
	struct xfs_buf		*bp;		/* buffer for block */
	int			error;		/* error return value */
	int			wantoff;	/* starting block offset */
	xfs_off_t		cook;
	struct xfs_da_geometry	*geo = args->geo;
	unsigned int		offset, next_offset;
	unsigned int		end;

	/*
	 * If the block number in the offset is out of range, we're done.
	 */
	if (xfs_dir2_dataptr_to_db(geo, ctx->pos) > geo->datablk)
		return 0;

	error = xfs_dir3_block_read(args->trans, dp, args->owner, &bp);
	if (error) {
		/*
		 * ccloop sess31 P31-FACEA disambiguation (RULE 4, failure-only so
		 * zero perf cost): the block-format readdir read failed (FACE A:
		 * daddr 0x78 holds XDD3 leaf-data magic while xfs_dir3_block_verify
		 * expects XDB3).  We are HERE only because the IN-CORE inode says
		 * BLOCK format (xfs_dir2_isblock: di_size == geo->blksize).  The
		 * decisive unknown is whether the ON-DISK inode agrees:
		 *   - disk di_size == blksize (BLOCK) => the on-disk dir is block
		 *     format but daddr 0x78 holds stale XDD3 => BLOCK-STALE: a stale
		 *     leaf-data buffer survived the reuse and was flushed over the
		 *     fresh XDB3 block.
		 *   - disk di_size  > blksize (LEAF)  => the on-disk dir grew to
		 *     leaf format and daddr 0x78 = XDD3 is CORRECT => INODE-STALE:
		 *     this reader's cached inode is behind the leaf-growth.
		 * FUA/plain-read the dir inode's on-disk di_core and log both views.
		 */
		struct xfs_mount *mp = dp->i_mount;
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    mp->m_ddev_targp) {
			static atomic_t p31n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p31n) <= 2000) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t, void *,
					uint32_t);
				uint32_t ilen = (uint32_t)dp->i_imap.im_len * 512;
				void *itmp = (ilen >= 512) ?
					kmalloc(ilen, GFP_NOFS) : NULL;

				if (itmp &&
				    mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev,
					(uint64_t)dp->i_imap.im_blkno +
					    mp->m_ddev_targp->bt_sector_offset,
					itmp, ilen) == 0) {
					struct xfs_dinode *dip =
						(struct xfs_dinode *)((char *)itmp +
						dp->i_imap.im_boffset);
					uint16_t dmagic = be16_to_cpu(dip->di_magic);
					uint8_t  dfmt = dip->di_format;
					uint64_t dsize = be64_to_cpu(dip->di_size);
					uint64_t dnext =
						be64_to_cpu(dip->di_big_nextents);

					pr_warn("mxfs: P31-FACEA ino=%llu err=%d blksize=%u INCORE[size=%llu fmt=%u nextents=%llu] DISK-INODE[magic=%04x fmt=%u size=%llu nextents=%llu] verdict=%s node=%d comm=%s\n",
						(unsigned long long)dp->i_ino,
						error, mp->m_sb.sb_blocksize,
						(unsigned long long)dp->i_disk_size,
						dp->i_df.if_format,
						(unsigned long long)dp->i_df.if_nextents,
						dmagic, dfmt,
						(unsigned long long)dsize,
						(unsigned long long)dnext,
						(dsize > mp->m_sb.sb_blocksize) ?
							"INODE-STALE" : "BLOCK-STALE",
						mxfs_v5_dlm_get_node_slot(mp->m_mxfs_dlm),
						current->comm);
				}
				kfree(itmp);
			}
		}
		return error;
	}

	xfs_iunlock(dp, *lock_mode);
	*lock_mode = 0;

	/*
	 * Extract the byte offset we start at from the seek pointer.
	 * We'll skip entries before this.
	 */
	wantoff = xfs_dir2_dataptr_to_off(geo, ctx->pos);
	xfs_dir3_data_check(dp, bp);

	/*
	 * Loop over the data portion of the block.
	 * Each object is a real entry (dep) or an unused one (dup).
	 */
	end = xfs_dir3_data_end_offset(geo, bp->b_addr);
	for (offset = geo->data_entry_offset;
	     offset < end;
	     offset = next_offset) {
		struct xfs_dir2_data_unused	*dup = bp->b_addr + offset;
		struct xfs_dir2_data_entry	*dep = bp->b_addr + offset;
		uint8_t filetype;

		/*
		 * Unused, skip it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			next_offset = offset + be16_to_cpu(dup->length);
			continue;
		}

		/*
		 * Bump pointer for the next iteration.
		 */
		next_offset = offset +
			xfs_dir2_data_entsize(dp->i_mount, dep->namelen);

		/*
		 * The entry is before the desired starting point, skip it.
		 */
		if (offset < wantoff)
			continue;

		cook = xfs_dir2_db_off_to_dataptr(geo, geo->datablk, offset);

		ctx->pos = cook & 0x7fffffff;
		filetype = xfs_dir2_data_get_ftype(dp->i_mount, dep);
		/*
		 * If it didn't fit, set the final offset to here & return.
		 */
		if (XFS_IS_CORRUPT(dp->i_mount,
				   !xfs_dir2_namecheck(dep->name,
						       dep->namelen))) {
			xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
			error = -EFSCORRUPTED;
			goto out_rele;
		}
		if (!dir_emit(ctx, (char *)dep->name, dep->namelen,
			    be64_to_cpu(dep->inumber),
			    xfs_dir3_get_dtype(dp->i_mount, filetype)))
			goto out_rele;
	}

	/*
	 * Reached the end of the block.
	 * Set the offset to a non-existent block 1 and return.
	 */
	ctx->pos = xfs_dir2_db_off_to_dataptr(geo, geo->datablk + 1, 0) &
								0x7fffffff;
out_rele:
	xfs_trans_brelse(args->trans, bp);
	return error;
}

/*
 * Read a directory block and initiate readahead for blocks beyond that.
 * We maintain a sliding readahead window of the remaining space in the
 * buffer rounded up to the nearest block.
 */
STATIC int
xfs_dir2_leaf_readbuf(
	struct xfs_da_args	*args,
	size_t			bufsize,
	xfs_dir2_off_t		*cur_off,
	xfs_dablk_t		*ra_blk,
	struct xfs_buf		**bpp)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_buf		*bp = NULL;
	struct xfs_da_geometry	*geo = args->geo;
	struct xfs_ifork	*ifp = xfs_ifork_ptr(dp, XFS_DATA_FORK);
	struct xfs_bmbt_irec	map;
	struct blk_plug		plug;
	xfs_dir2_off_t		new_off;
	xfs_dablk_t		next_ra;
	xfs_dablk_t		map_off;
	xfs_dablk_t		last_da;
	struct xfs_iext_cursor	icur;
	int			ra_want;
	int			error = 0;

	error = xfs_iread_extents(args->trans, dp, XFS_DATA_FORK);
	if (error)
		goto out;

	/*
	 * Look for mapped directory blocks at or above the current offset.
	 * Truncate down to the nearest directory block to start the scanning
	 * operation.
	 */
	last_da = xfs_dir2_byte_to_da(geo, XFS_DIR2_LEAF_OFFSET);
	map_off = xfs_dir2_db_to_da(geo, xfs_dir2_byte_to_db(geo, *cur_off));
	if (!xfs_iext_lookup_extent(dp, ifp, map_off, &icur, &map))
		goto out;
	if (map.br_startoff >= last_da)
		goto out;
	xfs_trim_extent(&map, map_off, last_da - map_off);

	/* Read the directory block of that first mapping. */
	new_off = xfs_dir2_da_to_byte(geo, map.br_startoff);
	if (new_off > *cur_off)
		*cur_off = new_off;
	error = xfs_dir3_data_read(args->trans, dp, args->owner,
			map.br_startoff, 0, &bp);
	if (error)
		goto out;

	/*
	 * Start readahead for the next bufsize's worth of dir data blocks.
	 * We may have already issued readahead for some of that range;
	 * ra_blk tracks the last block we tried to read(ahead).
	 */
	ra_want = howmany(bufsize + geo->blksize, (1 << geo->fsblog));
	if (*ra_blk >= last_da)
		goto out;
	else if (*ra_blk == 0)
		*ra_blk = map.br_startoff;
	next_ra = map.br_startoff + geo->fsbcount;
	if (next_ra >= last_da)
		goto out_no_ra;
	if (map.br_blockcount < geo->fsbcount &&
	    !xfs_iext_next_extent(ifp, &icur, &map))
		goto out_no_ra;
	if (map.br_startoff >= last_da)
		goto out_no_ra;
	xfs_trim_extent(&map, next_ra, last_da - next_ra);

	/* Start ra for each dir (not fs) block that has a mapping. */
	blk_start_plug(&plug);
	while (ra_want > 0) {
		next_ra = roundup((xfs_dablk_t)map.br_startoff, geo->fsbcount);
		while (ra_want > 0 &&
		       next_ra < map.br_startoff + map.br_blockcount) {
			if (next_ra >= last_da) {
				*ra_blk = last_da;
				break;
			}
			if (next_ra > *ra_blk) {
				xfs_dir3_data_readahead(dp, next_ra,
							XFS_DABUF_MAP_HOLE_OK);
				*ra_blk = next_ra;
			}
			ra_want -= geo->fsbcount;
			next_ra += geo->fsbcount;
		}
		if (!xfs_iext_next_extent(ifp, &icur, &map)) {
			*ra_blk = last_da;
			break;
		}
	}
	blk_finish_plug(&plug);

out:
	*bpp = bp;
	return error;
out_no_ra:
	*ra_blk = last_da;
	goto out;
}

/*
 * Getdents (readdir) for leaf and node directories.
 * This reads the data blocks only, so is the same for both forms.
 */
STATIC int
xfs_dir2_leaf_getdents(
	struct xfs_da_args	*args,
	struct dir_context	*ctx,
	size_t			bufsize,
	unsigned int		*lock_mode)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*bp = NULL;	/* data block buffer */
	xfs_dir2_data_entry_t	*dep;		/* data entry */
	xfs_dir2_data_unused_t	*dup;		/* unused entry */
	struct xfs_da_geometry	*geo = args->geo;
	xfs_dablk_t		rablk = 0;	/* current readahead block */
	xfs_dir2_off_t		curoff;		/* current overall offset */
	int			length;		/* temporary length value */
	int			byteoff;	/* offset in current block */
	unsigned int		offset = 0;
	int			error = 0;	/* error return value */

	/*
	 * If the offset is at or past the largest allowed value,
	 * give up right away.
	 */
	if (ctx->pos >= XFS_DIR2_MAX_DATAPTR)
		return 0;

	/*
	 * Inside the loop we keep the main offset value as a byte offset
	 * in the directory file.
	 */
	curoff = xfs_dir2_dataptr_to_byte(ctx->pos);

	/*
	 * Loop over directory entries until we reach the end offset.
	 * Get more blocks and readahead as necessary.
	 */
	while (curoff < XFS_DIR2_LEAF_OFFSET) {
		uint8_t filetype;

		/*
		 * If we have no buffer, or we're off the end of the
		 * current buffer, need to get another one.
		 */
		if (!bp || offset >= geo->blksize) {
			if (bp) {
				xfs_trans_brelse(args->trans, bp);
				bp = NULL;
			}

			if (*lock_mode == 0)
				*lock_mode = xfs_ilock_data_map_shared(dp);
			error = xfs_dir2_leaf_readbuf(args, bufsize, &curoff,
					&rablk, &bp);
			if (error || !bp)
				break;

			xfs_iunlock(dp, *lock_mode);
			*lock_mode = 0;

			xfs_dir3_data_check(dp, bp);

			/* sess10(a9a03929) P10-RDBLK: record what THIS
			 * getdents pass actually consumes per storm-dir data
			 * block (see mxfs_dirdump comment above).  Uncapped —
			 * the failing round is late in a run and the volume
			 * is a few lines per readdir. */
			if (dp->i_mount->m_mxfs_dlm &&
			    mxfs_ino_watched(dp->i_ino) &&
			    !mxfs_v5_dlm_is_single_node(
						dp->i_mount->m_mxfs_dlm)) {
				struct xfs_buf_log_item *rbip = bp->b_log_item;

				pr_warn("mxfs: P10-RDBLK ino=%llu daddr=%lld act=%d b_ep=%llu valid_ep=%llu b_gen=%llu dir_gen=%llu flags=0x%x dirty=%d pin=%d comm=%s realns=%llu\n",
					(unsigned long long)dp->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					mxfs_dirblk_count_active(mp,
						bp->b_addr, geo->blksize),
					(unsigned long long)bp->b_mxfs_dir_epoch,
					(unsigned long long)dp->i_dlm_dir_valid_epoch,
					(unsigned long long)bp->b_mxfs_dir_gen,
					(unsigned long long)dp->i_dlm_dir_gen,
					bp->b_flags,
					rbip && test_bit(XFS_LI_DIRTY,
						&rbip->bli_item.li_flags) ? 1 : 0,
					xfs_buf_ispinned(bp),
					current->comm,
					(unsigned long long)ktime_get_real_ns());
			}
			/*
			 * Find our position in the block.
			 */
			offset = geo->data_entry_offset;
			byteoff = xfs_dir2_byte_to_off(geo, curoff);
			/*
			 * Skip past the header.
			 */
			if (byteoff == 0)
				curoff += geo->data_entry_offset;
			/*
			 * Skip past entries until we reach our offset.
			 */
			else {
				while (offset < byteoff) {
					dup = bp->b_addr + offset;

					if (be16_to_cpu(dup->freetag)
						  == XFS_DIR2_DATA_FREE_TAG) {

						length = be16_to_cpu(dup->length);
						offset += length;
						continue;
					}
					dep = bp->b_addr + offset;
					length = xfs_dir2_data_entsize(mp,
							dep->namelen);
					offset += length;
				}
				/*
				 * Now set our real offset.
				 */
				curoff =
					xfs_dir2_db_off_to_byte(geo,
					    xfs_dir2_byte_to_db(geo, curoff),
					    offset);
				if (offset >= geo->blksize)
					continue;
			}
		}

		/*
		 * We have a pointer to an entry.  Is it a live one?
		 */
		dup = bp->b_addr + offset;

		/*
		 * No, it's unused, skip over it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			length = be16_to_cpu(dup->length);
			offset += length;
			curoff += length;
			continue;
		}

		dep = bp->b_addr + offset;
		length = xfs_dir2_data_entsize(mp, dep->namelen);
		filetype = xfs_dir2_data_get_ftype(mp, dep);

		ctx->pos = xfs_dir2_byte_to_dataptr(curoff) & 0x7fffffff;
		if (XFS_IS_CORRUPT(dp->i_mount,
				   !xfs_dir2_namecheck(dep->name,
						       dep->namelen))) {
			xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
			error = -EFSCORRUPTED;
			break;
		}
		if (!dir_emit(ctx, (char *)dep->name, dep->namelen,
			    be64_to_cpu(dep->inumber),
			    xfs_dir3_get_dtype(dp->i_mount, filetype)))
			break;

		/*
		 * Advance to next entry in the block.
		 */
		offset += length;
		curoff += length;
		/* bufsize may have just been a guess; don't go negative */
		bufsize = bufsize > length ? bufsize - length : 0;
	}

	/*
	 * All done.  Set output offset value to current offset.
	 */
	if (curoff > xfs_dir2_dataptr_to_byte(XFS_DIR2_MAX_DATAPTR))
		ctx->pos = XFS_DIR2_MAX_DATAPTR & 0x7fffffff;
	else
		ctx->pos = xfs_dir2_byte_to_dataptr(curoff) & 0x7fffffff;
	if (bp)
		xfs_trans_brelse(args->trans, bp);
	return error;
}

/*
 * Read a directory.
 *
 * If supplied, the transaction collects locked dir buffers to avoid
 * nested buffer deadlocks.  This function does not dirty the
 * transaction.  The caller must hold the IOLOCK (shared or exclusive)
 * before calling this function.
 */
int
xfs_readdir(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	struct dir_context	*ctx,
	size_t			bufsize)
{
	struct xfs_da_args	args = { NULL };
	unsigned int		lock_mode;
	int			error;

	trace_xfs_readdir(dp);

	if (xfs_is_shutdown(dp->i_mount))
		return -EIO;
	if (xfs_ifork_zapped(dp, XFS_DATA_FORK))
		return -EIO;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	xfs_assert_ilocked(dp, XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL);
	XFS_STATS_INC(dp->i_mount, xs_dir_getdents);

	args.dp = dp;
	args.geo = dp->i_mount->m_dir_geo;
	args.trans = tp;
	args.owner = dp->i_ino;

	/*
	 * mxfs sess42 (ccloop 14d31183): event-driven SHORTFORM-dir coherency.
	 * A peer's DIR_MODIFY evict-ring event armed MXFS_IF_DIR_RELOAD on this
	 * cached dir (the i_dlm_dir_gen bump only refreshes block/leaf dirs via
	 * xfs_da_read_buf; the inline fork read below never gets there).
	 * Reload the inode from disk BEFORE the format check so getdents sees
	 * the peer's added/removed entries — including a peer-driven
	 * LOCAL->block conversion.  mxfs_dlm_reload_inode takes i_lock itself
	 * (raw down_write_trylock) and must NOT be entered with ILOCK held;
	 * here we hold only the IOLOCK, matching the lookup-path call sites.
	 * On a contended BAIL the reload leaves i_dlm_stale set — re-arm the
	 * flag so the next readdir retries instead of reading stale inline
	 * data.  Strictly event-driven: no peer event, no disk traffic (the
	 * sess38/91 per-readdir poll regression must not come back).
	 */
	if (dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		extern int mxfs_instr_enabled;
		bool p_rl = xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD);
		/* P-RDDIAG (RULE 4): observe the dir grant state at readdir time
		 * for the tcp_dlm_scaling stale-readdir leftover.  mode==NL =>
		 * slow-path PR reacquire should have reloaded; mode==PR/EX while a
		 * peer modified => a LOST BAST left us a stale cached grant. */
		if (unlikely(mxfs_instr_enabled) &&
		    dp->i_ino != dp->i_mount->m_sb.sb_rootino)
			pr_warn_ratelimited(
			    "mxfs: P-RDDIAG ino=%llu dlm_mode=%u dir_gen=%llu fmt=%u reload_armed=%d\n",
			    (unsigned long long)dp->i_ino,
			    dp->i_dlm_mode,
			    (unsigned long long)dp->i_dlm_dir_gen,
			    dp->i_df.if_format, p_rl ? 1 : 0);
		/* sess48: ALSO reload on the reliable gen-staleness signal
		 * (dir_gen > loaded_gen), not just the laggy evict-ring flag —
		 * see the matching note in mxfs_dlm_dir_consumer_refresh.  The
		 * reader otherwise keeps a stale BLOCK-format inode after a peer's
		 * block->shortform delete-shrink and getdents the freed block.
		 * Gated (gen==loaded => no disk traffic); reload advances
		 * loaded_gen so it fires once per peer change. */
		bool need_reload =
			xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_RELOAD) ||
			dp->i_dlm_dir_gen > dp->i_dlm_dir_loaded_gen;
		/*
		 * sess60 ROOT FIX (RULE 4, PROVEN root
		 * [[sess59-drc-root-grantless-readdir-async-evict-latency]]):
		 * both triggers above (the MXFS_IF_DIR_RELOAD flag and the
		 * i_dlm_dir_gen bump) are delivered SOLELY by the ASYNC disklock
		 * heartbeat eviction ring.  At a concurrent barrier-release (4-node
		 * dir_reuse_coherency) the peer's DIR_MODIFY for its final
		 * block-growth has not been delivered yet, so neither trigger is
		 * true, this grant-less reader keeps its STALE in-core data fork,
		 * and a cold readdir enumerates the old block set — missing the
		 * peer's just-committed trailing-block dirent (readdir=399/400,
		 * lookup_fail=0).  The entry IS durable on disk (the writer sync'd
		 * before the barrier); only this reader's in-core fork lags.
		 *
		 * Add a SYNCHRONOUS coherence check that does NOT depend on the
		 * async ring: for a dir this node has already seen peer activity on
		 * (dir_gen>0) and does NOT hold EX for (an EX holder is the
		 * authoritative writer — its in-core is current and may legitimately
		 * be ahead of disk), do ONE cheap coherent FUA dinode read.  If the
		 * durable on-disk di_size differs from our in-core size, a peer grew
		 * (or shrank) the dir and our cached fork is stale -> reload, which
		 * adopts the disk (a non-EX holder has no uncommitted local mods, so
		 * disk is authoritative).  Gated on dir_gen>0 so solo dirs (rsync,
		 * gen==0) issue NO disk traffic — preserving the sess38/91 perf
		 * constraint against a per-readdir poll on every dir.
		 */
		/*
		 * sess60 ROOT FIX v2 (RULE 4 — the FUA-di_size check above was
		 * REFUTED: P26-RDDIR showed the miss is a SAME-SIZE stale dir DATA
		 * block, disk_size==incore_size==12288, so a size compare never
		 * fires — P60-RDSYNC=0 while readdir still missed an entry).  The
		 * reader holds a CACHED PR grant (dlm_mode=3) whose i_dlm_dir_gen is
		 * stuck at 1: peers took EX and added dirents into an EXISTING data
		 * block (no di_size growth), but nothing bumped this reader's
		 * i_dlm_dir_gen — the only producers are the ASYNC heartbeat
		 * evict-ring and the slow-path reacquire, and a fast-pathed cached PR
		 * hits neither.  So the xfs_da_read_buf read-time invalidation (which
		 * re-reads a cached dir block only when b_mxfs_dir_gen <
		 * i_dlm_dir_gen) never triggers, and the cold readdir enumerates the
		 * STALE cached data/leaf block.
		 *
		 * Synchronous, ring-independent coherence: on readdir of a dir this
		 * node has seen peer activity on (dir_gen>0) and does NOT own EX for
		 * (an EX owner is the authoritative writer — its cache is current and
		 * may hold uncommitted growth that must NOT be invalidated), BUMP
		 * i_dlm_dir_gen so every cached dir block is re-fetched from the
		 * platter by xfs_da_read_buf below.  Safe + durable: if we can read
		 * (hold PR/NL, not EX) then no peer holds EX, so per Invariant 1 each
		 * peer drained its dirents durable before releasing — the platter is
		 * the authoritative superset.  Gated on dir_gen>0 so solo dirs
		 * (rsync, gen==0) re-read NOTHING (the sess38/91 perf guard).  Also
		 * reload the inode fork so a size-grow / format change is adopted in
		 * the same pass.
		 */
		/* sess14(ccloop): force coherent leaf/data-block re-reads on a
		 * non-EX reader that has seen peer activity — but ONLY after the
		 * extent map has actually been refreshed (see below).  Bumping
		 * i_dlm_dir_gen BEFORE a reload that then BAILS is the round-23
		 * DABUF_MAP_HOLE bug: the bump makes xfs_da_read_buf re-fetch a
		 * FRESH leaf that references a peer-grown data block, while the
		 * data-fork EXTENT MAP stays STALE (no mapping for that block) ->
		 * xfs_dabuf_map returns a hole -> !XFS_DABUF_MAP_HOLE_OK ->
		 * EFSCORRUPTED whole-FS shutdown. */
		bool want_block_refresh =
			(dp->i_dlm_dir_gen > 0 &&
			 dp->i_dlm_mode != MXFS_LOCK_EX &&
			 dp->i_ino != dp->i_mount->m_sb.sb_rootino);
		if (need_reload || want_block_refresh) {
			extern int mxfs_dir_relverify;
			unsigned long long p48_nx0 = dp->i_df.if_nextents;
			dp->i_dlm_stale = true; dp->i_dlm_stale_src = 1;
			mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
			/* sess48 (RULE 4): decisive readdir-reload probe (light, gated
			 * dir_relverify).  Did the reload BAIL (stale kept) or change the
			 * extent count?  A bail under i_lock contention leaves a stale
			 * extent map -> readdir misses a peer's grown blocks (the proven
			 * reader-side root). */
			if (mxfs_dir_relverify && dp->i_ino <= 256)
				pr_warn_ratelimited(
				    "mxfs: P48-RDRELOAD ino=%llu mode=%u nx_before=%llu nx_after=%llu bailed=%d need=%d wbr=%d\n",
				    (unsigned long long)dp->i_ino, dp->i_dlm_mode,
				    p48_nx0, (unsigned long long)dp->i_df.if_nextents,
				    dp->i_dlm_stale ? 1 : 0, need_reload ? 1 : 0,
				    want_block_refresh ? 1 : 0);
			if (dp->i_dlm_stale) {
				/* Reload BAILED (trylock contention): extent map NOT
				 * refreshed.  Do NOT bump i_dlm_dir_gen — keep the
				 * in-core leaf/extent view CONSISTENT-stale (no hole,
				 * no shutdown) and retry on the next readdir. */
				xfs_iflags_set(dp, MXFS_IF_DIR_RELOAD);
			} else if (want_block_refresh) {
				/* Reload succeeded: extent map is now fresh from the
				 * platter.  NOW force the cached leaf/data blocks to be
				 * re-fetched too, consistently with the fresh map. */
				dp->i_dlm_dir_gen++;
				pr_warn_ratelimited(
				    "mxfs: P60-RDGEN ino=%llu mode=%u dir_gen->%llu (force coherent dir-block re-read, post-reload)\n",
					(unsigned long long)dp->i_ino, dp->i_dlm_mode,
					(unsigned long long)dp->i_dlm_dir_gen);
			}
		}
	}

	if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL)
		return xfs_dir2_sf_getdents(&args, ctx);

	lock_mode = xfs_ilock_data_map_shared(dp);
	switch (xfs_dir2_format(&args, &error)) {
	case XFS_DIR2_FMT_BLOCK:
		error = xfs_dir2_block_getdents(&args, ctx, &lock_mode);
		break;
	case XFS_DIR2_FMT_LEAF:
	case XFS_DIR2_FMT_NODE:
		error = xfs_dir2_leaf_getdents(&args, ctx, bufsize, &lock_mode);
		break;
	default:
		break;
	}

	/*
	 * sess26 (ccloop 8ddb16a2) RULE-4 DETECTOR (P26-RDDIR, capped): the
	 * dir_reuse_coherency residual is test2 reading SHORT (readdir=100-117
	 * vs 200) while test1 reads the full 200 from the same LUN.  Log the
	 * dir inode's extent/size/grant state at cold-read time so a cross-node
	 * timeline shows whether the short reader has a STALE (short) data-fork
	 * bmap (peer-grown data block not adopted) or a full bmap with stale
	 * data-block content.  Scoped to non-root multi-node dirs.
	 */
	if (dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    dp->i_ino != dp->i_mount->m_sb.sb_rootino &&
	    S_ISDIR(VFS_I(dp)->i_mode)) {
		static atomic_t p26rd = ATOMIC_INIT(0);
		if (atomic_inc_return(&p26rd) <= 800)
			pr_warn("mxfs: P26-RDDIR ino=%llu nextents=%llu disk_size=%llu fmt=%u dlm_mode=%u dir_gen=%llu reload_armed=%d comm=%s\n",
				(unsigned long long)dp->i_ino,
				(unsigned long long)dp->i_df.if_nextents,
				(unsigned long long)dp->i_disk_size,
				dp->i_df.if_format, dp->i_dlm_mode,
				(unsigned long long)dp->i_dlm_dir_gen,
				xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD) ? 1 : 0,
				current->comm);
	}

	if (lock_mode)
		xfs_iunlock(dp, lock_mode);
	return error;
}
