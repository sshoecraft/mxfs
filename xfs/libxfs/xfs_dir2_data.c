// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
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
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_mxfs_dlm.h"
#include "../dlm/v5_mount.h"
#include "xfs_error.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_log.h"
#include "xfs_health.h"
#include "xfs_ag.h"

static xfs_failaddr_t xfs_dir2_data_freefind_verify(
		struct xfs_dir2_data_hdr *hdr, struct xfs_dir2_data_free *bf,
		struct xfs_dir2_data_unused *dup,
		struct xfs_dir2_data_free **bf_ent);

struct xfs_dir2_data_free *
xfs_dir2_data_bestfree_p(
	struct xfs_mount		*mp,
	struct xfs_dir2_data_hdr	*hdr)
{
	if (xfs_has_crc(mp))
		return ((struct xfs_dir3_data_hdr *)hdr)->best_free;
	return hdr->bestfree;
}

/*
 * Pointer to an entry's tag word.
 */
__be16 *
xfs_dir2_data_entry_tag_p(
	struct xfs_mount		*mp,
	struct xfs_dir2_data_entry	*dep)
{
	return (__be16 *)((char *)dep +
		xfs_dir2_data_entsize(mp, dep->namelen) - sizeof(__be16));
}

uint8_t
xfs_dir2_data_get_ftype(
	struct xfs_mount		*mp,
	struct xfs_dir2_data_entry	*dep)
{
	if (xfs_has_ftype(mp)) {
		uint8_t			ftype = dep->name[dep->namelen];

		if (likely(ftype < XFS_DIR3_FT_MAX))
			return ftype;
	}

	return XFS_DIR3_FT_UNKNOWN;
}

void
xfs_dir2_data_put_ftype(
	struct xfs_mount		*mp,
	struct xfs_dir2_data_entry	*dep,
	uint8_t				ftype)
{
	ASSERT(ftype < XFS_DIR3_FT_MAX);
	ASSERT(dep->namelen != 0);

	if (xfs_has_ftype(mp))
		dep->name[dep->namelen] = ftype;
}

/*
 * The number of leaf entries is limited by the size of the block and the amount
 * of space used by the data entries.  We don't know how much space is used by
 * the data entries yet, so just ensure that the count falls somewhere inside
 * the block right now.
 */
static inline unsigned int
xfs_dir2_data_max_leaf_entries(
	struct xfs_da_geometry		*geo)
{
	return (geo->blksize - sizeof(struct xfs_dir2_block_tail) -
		geo->data_entry_offset) /
			sizeof(struct xfs_dir2_leaf_entry);
}

/*
 * Check the consistency of the data block.
 * The input can also be a block-format directory.
 * Return NULL if the buffer is good, otherwise the address of the error.
 */
xfs_failaddr_t
__xfs_dir3_data_check(
	struct xfs_inode	*dp,		/* incore inode pointer */
	struct xfs_buf		*bp)		/* data block's buffer */
{
	xfs_dir2_dataptr_t	addr;		/* addr for leaf lookup */
	xfs_dir2_data_free_t	*bf;		/* bestfree table */
	xfs_dir2_block_tail_t	*btp=NULL;	/* block tail */
	int			count;		/* count of entries found */
	xfs_dir2_data_hdr_t	*hdr;		/* data block header */
	xfs_dir2_data_free_t	*dfp;		/* bestfree entry */
	int			freeseen;	/* mask of bestfrees seen */
	xfs_dahash_t		hash;		/* hash of current name */
	int			i;		/* leaf index */
	int			lastfree;	/* last entry was unused */
	xfs_dir2_leaf_entry_t	*lep=NULL;	/* block leaf entries */
	struct xfs_mount	*mp = bp->b_mount;
	int			stale;		/* count of stale leaves */
	struct xfs_name		name;
	unsigned int		offset;
	unsigned int		end;
	struct xfs_da_geometry	*geo = mp->m_dir_geo;

	/*
	 * If this isn't a directory, something is seriously wrong.  Bail out.
	 */
	if (dp && !S_ISDIR(VFS_I(dp)->i_mode))
		return __this_address;

	hdr = bp->b_addr;
	offset = geo->data_entry_offset;

	switch (hdr->magic) {
	case cpu_to_be32(XFS_DIR3_BLOCK_MAGIC):
	case cpu_to_be32(XFS_DIR2_BLOCK_MAGIC):
		btp = xfs_dir2_block_tail_p(geo, hdr);
		lep = xfs_dir2_block_leaf_p(btp);

		if (be32_to_cpu(btp->count) >=
		    xfs_dir2_data_max_leaf_entries(geo))
			return __this_address;
		break;
	case cpu_to_be32(XFS_DIR3_DATA_MAGIC):
	case cpu_to_be32(XFS_DIR2_DATA_MAGIC):
		break;
	default:
		return __this_address;
	}
	end = xfs_dir3_data_end_offset(geo, hdr);
	if (!end)
		return __this_address;

	/*
	 * Account for zero bestfree entries.
	 */
	bf = xfs_dir2_data_bestfree_p(mp, hdr);
	count = lastfree = freeseen = 0;
	if (!bf[0].length) {
		if (bf[0].offset)
			return __this_address;
		freeseen |= 1 << 0;
	}
	if (!bf[1].length) {
		if (bf[1].offset)
			return __this_address;
		freeseen |= 1 << 1;
	}
	if (!bf[2].length) {
		if (bf[2].offset)
			return __this_address;
		freeseen |= 1 << 2;
	}

	if (be16_to_cpu(bf[0].length) < be16_to_cpu(bf[1].length))
		return __this_address;
	if (be16_to_cpu(bf[1].length) < be16_to_cpu(bf[2].length))
		return __this_address;
	/*
	 * Loop over the data/unused entries.
	 */
	while (offset < end) {
		struct xfs_dir2_data_unused	*dup = bp->b_addr + offset;
		struct xfs_dir2_data_entry	*dep = bp->b_addr + offset;
		unsigned int	reclen;

		/*
		 * Are the remaining bytes large enough to hold an
		 * unused entry?
		 */
		if (offset > end - xfs_dir2_data_unusedsize(1))
			return __this_address;

		/*
		 * If it's unused, look for the space in the bestfree table.
		 * If we find it, account for that, else make sure it
		 * doesn't need to be there.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			xfs_failaddr_t	fa;

			reclen = xfs_dir2_data_unusedsize(
					be16_to_cpu(dup->length));
			if (lastfree != 0)
				return __this_address;
			if (be16_to_cpu(dup->length) != reclen)
				return __this_address;
			if (offset + reclen > end)
				return __this_address;
			if (be16_to_cpu(*xfs_dir2_data_unused_tag_p(dup)) !=
			    offset)
				return __this_address;
			fa = xfs_dir2_data_freefind_verify(hdr, bf, dup, &dfp);
			if (fa)
				return fa;
			if (dfp) {
				i = (int)(dfp - bf);
				if ((freeseen & (1 << i)) != 0)
					return __this_address;
				freeseen |= 1 << i;
			} else {
				if (be16_to_cpu(dup->length) >
				    be16_to_cpu(bf[2].length))
					return __this_address;
			}
			offset += reclen;
			lastfree = 1;
			continue;
		}

		/*
		 * This is not an unused entry. Are the remaining bytes
		 * large enough for a dirent with a single-byte name?
		 */
		if (offset > end - xfs_dir2_data_entsize(mp, 1))
			return __this_address;

		/*
		 * It's a real entry.  Validate the fields.
		 * If this is a block directory then make sure it's
		 * in the leaf section of the block.
		 * The linear search is crude but this is DEBUG code.
		 */
		if (dep->namelen == 0)
			return __this_address;
		reclen = xfs_dir2_data_entsize(mp, dep->namelen);
		if (offset + reclen > end)
			return __this_address;
		if (!xfs_verify_dir_ino(mp, be64_to_cpu(dep->inumber)))
			return __this_address;
		if (be16_to_cpu(*xfs_dir2_data_entry_tag_p(mp, dep)) != offset)
			return __this_address;
		if (xfs_dir2_data_get_ftype(mp, dep) >= XFS_DIR3_FT_MAX)
			return __this_address;
		count++;
		lastfree = 0;
		if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
		    hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC)) {
			addr = xfs_dir2_db_off_to_dataptr(geo, geo->datablk,
						(xfs_dir2_data_aoff_t)
						((char *)dep - (char *)hdr));
			name.name = dep->name;
			name.len = dep->namelen;
			hash = xfs_dir2_hashname(mp, &name);
			for (i = 0; i < be32_to_cpu(btp->count); i++) {
				if (be32_to_cpu(lep[i].address) == addr &&
				    be32_to_cpu(lep[i].hashval) == hash)
					break;
			}
			if (i >= be32_to_cpu(btp->count))
				return __this_address;
		}
		offset += reclen;
	}
	/*
	 * Need to have seen all the entries and all the bestfree slots.
	 */
	if (freeseen != 7)
		return __this_address;
	if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	    hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC)) {
		for (i = stale = 0; i < be32_to_cpu(btp->count); i++) {
			if (lep[i].address ==
			    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
				stale++;
			if (i > 0 && be32_to_cpu(lep[i].hashval) <
				     be32_to_cpu(lep[i - 1].hashval))
				return __this_address;
		}
		if (count != be32_to_cpu(btp->count) - be32_to_cpu(btp->stale))
			return __this_address;
		if (stale != be32_to_cpu(btp->stale))
			return __this_address;
	}
	return NULL;
}

#ifdef DEBUG
void
xfs_dir3_data_check(
	struct xfs_inode	*dp,
	struct xfs_buf		*bp)
{
	xfs_failaddr_t		fa;

	fa = __xfs_dir3_data_check(dp, bp);
	if (!fa)
		return;
	xfs_corruption_error(__func__, XFS_ERRLEVEL_LOW, dp->i_mount,
			bp->b_addr, BBTOB(bp->b_length), __FILE__, __LINE__,
			fa);
	ASSERT(0);
}
#endif

static xfs_failaddr_t
xfs_dir3_data_verify(
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

/*
 * Readahead of the first block of the directory when it is opened is completely
 * oblivious to the format of the directory. Hence we can either get a block
 * format buffer or a data format buffer on readahead.
 */
static void
xfs_dir3_data_reada_verify(
	struct xfs_buf		*bp)
{
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;

	switch (hdr->magic) {
	case cpu_to_be32(XFS_DIR2_BLOCK_MAGIC):
	case cpu_to_be32(XFS_DIR3_BLOCK_MAGIC):
		bp->b_ops = &xfs_dir3_block_buf_ops;
		bp->b_ops->verify_read(bp);
		return;
	case cpu_to_be32(XFS_DIR2_DATA_MAGIC):
	case cpu_to_be32(XFS_DIR3_DATA_MAGIC):
		bp->b_ops = &xfs_dir3_data_buf_ops;
		bp->b_ops->verify_read(bp);
		return;
	default:
		xfs_verifier_error(bp, -EFSCORRUPTED, __this_address);
		break;
	}
}

/* sess-tcp: dir-block content forensic gate (P-DWR/P-DRD); off unless mxfs.dirwr=1. */
extern int mxfs_dirwr_enabled;

static void
xfs_dir3_data_read_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	xfs_failaddr_t		fa;

	if (xfs_has_crc(mp) &&
	    !xfs_buf_verify_cksum(bp, XFS_DIR3_DATA_CRC_OFF)) {
		/*
		 * sess5(a9a03929) P56X-CRCFAIL: run75 live repro — userspace
		 * reads of this daddr are clean while this read verifier fails
		 * deterministically.  Dump buffer geometry (length, map count,
		 * per-map daddr/len) + per-512B-sector crc32c of b_addr so the
		 * divergent sectors/fragments can be identified offline against
		 * the known-clean image.  Capped hard.
		 */
		{
			static atomic_t p56x_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p56x_n) <= 40) {
				unsigned int nb = BBTOB(bp->b_length);
				unsigned int ns = nb / 512, s;
				uint32_t scrc[16];
				const char *ba = bp->b_addr;

				if (ns > 16)
					ns = 16;
				for (s = 0; s < ns; s++)
					scrc[s] = crc32c(0, ba + s * 512, 512);
				pr_warn("mxfs: P56X-CRCFAIL daddr=%lld blen_bb=%u nmaps=%d map0=%lld/%d map1=%lld/%d stored_crc=0x%08x secrc=%*ph\n",
					(long long)xfs_buf_daddr(bp),
					(unsigned)bp->b_length,
					bp->b_map_count,
					(long long)bp->b_maps[0].bm_bn,
					(int)bp->b_maps[0].bm_len,
					bp->b_map_count > 1 ?
					    (long long)bp->b_maps[1].bm_bn : -1,
					bp->b_map_count > 1 ?
					    (int)bp->b_maps[1].bm_len : -1,
					be32_to_cpu(((struct xfs_dir3_blk_hdr *)
						     bp->b_addr)->crc),
					(int)(ns * 4), (const u8 *)scrc);
			}
		}
		xfs_verifier_error(bp, -EFSBADCRC, __this_address);
	} else {
		fa = xfs_dir3_data_verify(bp);
		if (fa)
			xfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}

	/* sess-tcp READ-SIDE forensic (always-on, capped): node1 dirent count in
	 * a dir DATA block as it comes OFF DISK (this verifier runs only on a real
	 * disk read = cache miss).  If node2's read of the block-0 daddr returns a
	 * LOW count here, node1's update was NOT durable on disk when node2 read =
	 * WRITE-SIDE durability gap.  If disk reads are full (100) yet node2 WRITES
	 * a low count (P-DWR), node2 RMW'd a stale CACHED block = READ-SIDE. */
	if (unlikely(mxfs_dirwr_enabled)) {
		const char	*pb = bp->b_addr;
		int		blen = BBTOB(bp->b_length);
		int		k, ncnt = 0;

		for (k = 0; k + 7 <= blen; k++)
			if (pb[k] == 'n' && !memcmp(pb + k, "node1_f", 7))
				ncnt++;
		if (ncnt) {
			static atomic_t pdrd = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdrd) <= 1500)
				pr_warn("mxfs: P-DRD daddr=%lld node1_cnt=%d comm=%s\n",
					(long long)xfs_buf_daddr(bp), ncnt,
					current->comm);
		}
	}
}

static void
xfs_dir3_data_write_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_dir3_blk_hdr	*hdr3 = bp->b_addr;
	xfs_failaddr_t		fa;

	fa = xfs_dir3_data_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	/* sess-tcp WRITE-SIDE forensic (always-on, capped): count node1's dirents
	 * in EVERY dir DATA block as it is written to disk, with the writing
	 * thread.  A write of a given daddr carrying FEWER node1_f names than an
	 * earlier write of the SAME daddr is the durable clobber; comm=kworker/
	 * xfsaild => stale writeback of an undrained prior-incarnation block,
	 * comm=dd/sync/md5sum => a live stale-base RMW.  Decides write- vs
	 * read-side for the dir_reuse 2/tcp lost-update. */
	if (unlikely(mxfs_dirwr_enabled)) {
		const char	*pb = bp->b_addr;
		int		blen = BBTOB(bp->b_length);
		int		k, ncnt = 0;

		for (k = 0; k + 7 <= blen; k++)
			if (pb[k] == 'n' && !memcmp(pb + k, "node1_f", 7))
				ncnt++;
		if (ncnt) {
			static atomic_t pdwr = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdwr) <= 1500)
				pr_warn("mxfs: P-DWR daddr=%lld node1_cnt=%d comm=%s\n",
					(long long)xfs_buf_daddr(bp), ncnt,
					current->comm);
		}
	}

	/* sess68 WRITE-SIDE forensic (ALWAYS-ON, cheap, no-IO, ratelimited):
	 * count ALL "node" dirents (node1_/node2_/...) in EVERY multinode dir DATA
	 * block as it is written to disk, with the writing thread.  A write of a
	 * given daddr carrying FEWER entries than an EARLIER write of the SAME
	 * daddr is the durable lost-update IN THE ACT (the residual is a pure
	 * data-block content RMW: extent maps agree [P68-MAPDIVERGE=0], inode is
	 * durable [P68-GROWREL-VERIFY], blocks dropped by drop_caches).  comm=
	 * kworker/xfsaild => stale writeback; comm=dd/bash/sync/md5sum => live
	 * stale-base RMW.  Generic (all node ranks) so it catches whichever
	 * rank's entry is lost this run. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		const char	*pb = bp->b_addr;
		int		blen = BBTOB(bp->b_length);
		int		k, tot = 0;
		uint32_t	nameset = 0;	/* XOR of per-entry hashes */

		for (k = 0; k + 7 <= blen; k++) {
			/* match "node{R}_f{N}" optionally followed by ".md5" */
			if (pb[k] == 'n' && pb[k+1] == 'o' && pb[k+2] == 'd' &&
			    pb[k+3] == 'e' && pb[k+4] >= '1' && pb[k+4] <= '8' &&
			    pb[k+5] == '_' && pb[k+6] == 'f' &&
			    pb[k+7] >= '0' && pb[k+7] <= '9') {
				int r = pb[k+4] - '0';
				int j = k + 7, num = 0;
				uint32_t h;
				bool md5 = false;

				while (j < blen && pb[j] >= '0' && pb[j] <= '9') {
					num = num * 10 + (pb[j] - '0');
					j++;
				}
				if (j + 4 <= blen && pb[j] == '.' &&
				    pb[j+1] == 'm' && pb[j+2] == 'd' &&
				    pb[j+3] == '5')
					md5 = true;
				h = ((uint32_t)r << 24) ^ ((uint32_t)num << 4) ^
				    (md5 ? 1u : 0u);
				nameset ^= h;
				tot++;
			}
		}
		{
			static atomic_t pdwr2 = ATOMIC_INIT(0);
			if (unlikely(mxfs_dirwr_enabled) &&
			    atomic_inc_return(&pdwr2) <= 4000)
				pr_warn("mxfs: P68-DWR daddr=%lld nodecnt=%d nameset=0x%08x incarn=%u owner=%llu comm=%s\n",
					(long long)xfs_buf_daddr(bp), tot, nameset,
					bp->b_mxfs_dir_incarn,
					(unsigned long long)be64_to_cpu(hdr3->owner),
					current->comm);
		}
	}

	/* sess62 (RULE 4) ALWAYS-ON, capped, low-flood (writes only): the durable
	 * dir_reuse loss is ALWAYS node1_f1 (the first dirent of the reused dir).
	 * Track node1_f1's EXACT presence in every dir DATA block written to disk,
	 * with daddr + comm.  A write of a daddr that earlier carried node1_f1 and
	 * now does NOT is the clobbering write; comm tells us xfsaild (stale
	 * writeback) vs dd/md5sum/sync (live stale-base RMW).  Matches "node1_f1"
	 * (8 bytes) NOT followed by a digit or '.', so node1_f10..19 and
	 * node1_f1.md5 do not false-match. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		const char	*pb = bp->b_addr;
		int		blen = BBTOB(bp->b_length);
		int		k, n1f1 = 0, n1tot = 0;

		for (k = 0; k + 8 <= blen; k++) {
			if (pb[k] != 'n' || memcmp(pb + k, "node1_f", 7))
				continue;
			n1tot++;
			if (pb[k + 7] == '1') {
				char nx = (k + 8 < blen) ? pb[k + 8] : 0;
				if (!(nx >= '0' && nx <= '9') && nx != '.')
					n1f1++;
			}
		}
		{
			static atomic_t pn1 = ATOMIC_INIT(0);
			if (atomic_inc_return(&pn1) <= 3000)
				pr_warn("mxfs: P62-DWR-N1F1 daddr=%lld node1_f1=%d node1_tot=%d owner=%llu comm=%s\n",
					(long long)xfs_buf_daddr(bp), n1f1, n1tot,
					(unsigned long long)be64_to_cpu(hdr3->owner),
					current->comm);
		}
	}

	if (!xfs_has_crc(mp))
		return;

	if (bip)
		hdr3->lsn = cpu_to_be64(bip->bli_item.li_lsn);

	xfs_buf_update_cksum(bp, XFS_DIR3_DATA_CRC_OFF);
}

const struct xfs_buf_ops xfs_dir3_data_buf_ops = {
	.name = "xfs_dir3_data",
	.magic = { cpu_to_be32(XFS_DIR2_DATA_MAGIC),
		   cpu_to_be32(XFS_DIR3_DATA_MAGIC) },
	.verify_read = xfs_dir3_data_read_verify,
	.verify_write = xfs_dir3_data_write_verify,
	.verify_struct = xfs_dir3_data_verify,
};

static const struct xfs_buf_ops xfs_dir3_data_reada_buf_ops = {
	.name = "xfs_dir3_data_reada",
	.magic = { cpu_to_be32(XFS_DIR2_DATA_MAGIC),
		   cpu_to_be32(XFS_DIR3_DATA_MAGIC) },
	.verify_read = xfs_dir3_data_reada_verify,
	.verify_write = xfs_dir3_data_write_verify,
};

xfs_failaddr_t
xfs_dir3_data_header_check(
	struct xfs_buf		*bp,
	xfs_ino_t		owner)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (xfs_has_crc(mp)) {
		struct xfs_dir3_data_hdr *hdr3 = bp->b_addr;

		if (hdr3->hdr.magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC))
			return __this_address;

		if (be64_to_cpu(hdr3->hdr.owner) != owner)
			return __this_address;
	}

	return NULL;
}

int
xfs_dir3_data_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_ino_t		owner,
	xfs_dablk_t		bno,
	unsigned int		flags,
	struct xfs_buf		**bpp)
{
	xfs_failaddr_t		fa;
	int			err;

	err = xfs_da_read_buf(tp, dp, bno, flags, bpp, XFS_DATA_FORK,
			&xfs_dir3_data_buf_ops);
	if (err || !*bpp)
		return err;

	/* Check things that we can't do in the verifier. */
	fa = xfs_dir3_data_header_check(*bpp, owner);
	if (fa) {
		__xfs_buf_mark_corrupt(*bpp, fa);
		xfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		xfs_dirattr_mark_sick(dp, XFS_DATA_FORK);
		return -EFSCORRUPTED;
	}

	xfs_trans_buf_set_type(tp, *bpp, XFS_BLFT_DIR_DATA_BUF);
	return err;
}

int
xfs_dir3_data_readahead(
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	unsigned int		flags)
{
	return xfs_da_reada_buf(dp, bno, flags, XFS_DATA_FORK,
				&xfs_dir3_data_reada_buf_ops);
}

/*
 * Find the bestfree entry that exactly coincides with unused directory space
 * or a verifier error because the bestfree data are bad.
 */
static xfs_failaddr_t
xfs_dir2_data_freefind_verify(
	struct xfs_dir2_data_hdr	*hdr,
	struct xfs_dir2_data_free	*bf,
	struct xfs_dir2_data_unused	*dup,
	struct xfs_dir2_data_free	**bf_ent)
{
	struct xfs_dir2_data_free	*dfp;
	xfs_dir2_data_aoff_t		off;
	bool				matched = false;
	bool				seenzero = false;

	*bf_ent = NULL;
	off = (xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr);

	/*
	 * Validate some consistency in the bestfree table.
	 * Check order, non-overlapping entries, and if we find the
	 * one we're looking for it has to be exact.
	 */
	for (dfp = &bf[0]; dfp < &bf[XFS_DIR2_DATA_FD_COUNT]; dfp++) {
		if (!dfp->offset) {
			if (dfp->length)
				return __this_address;
			seenzero = true;
			continue;
		}
		if (seenzero)
			return __this_address;
		if (be16_to_cpu(dfp->offset) == off) {
			matched = true;
			if (dfp->length != dup->length)
				return __this_address;
		} else if (be16_to_cpu(dfp->offset) > off) {
			if (off + be16_to_cpu(dup->length) >
					be16_to_cpu(dfp->offset))
				return __this_address;
		} else {
			if (be16_to_cpu(dfp->offset) +
					be16_to_cpu(dfp->length) > off)
				return __this_address;
		}
		if (!matched &&
		    be16_to_cpu(dfp->length) < be16_to_cpu(dup->length))
			return __this_address;
		if (dfp > &bf[0] &&
		    be16_to_cpu(dfp[-1].length) < be16_to_cpu(dfp[0].length))
			return __this_address;
	}

	/* Looks ok so far; now try to match up with a bestfree entry. */
	*bf_ent = xfs_dir2_data_freefind(hdr, bf, dup);
	return NULL;
}

/*
 * Given a data block and an unused entry from that block,
 * return the bestfree entry if any that corresponds to it.
 */
xfs_dir2_data_free_t *
xfs_dir2_data_freefind(
	struct xfs_dir2_data_hdr *hdr,		/* data block header */
	struct xfs_dir2_data_free *bf,		/* bestfree table pointer */
	struct xfs_dir2_data_unused *dup)	/* unused space */
{
	xfs_dir2_data_free_t	*dfp;		/* bestfree entry */
	xfs_dir2_data_aoff_t	off;		/* offset value needed */

	off = (xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr);

	/*
	 * If this is smaller than the smallest bestfree entry,
	 * it can't be there since they're sorted.
	 */
	if (be16_to_cpu(dup->length) <
	    be16_to_cpu(bf[XFS_DIR2_DATA_FD_COUNT - 1].length))
		return NULL;
	/*
	 * Look at the three bestfree entries for our guy.
	 */
	for (dfp = &bf[0]; dfp < &bf[XFS_DIR2_DATA_FD_COUNT]; dfp++) {
		if (!dfp->offset)
			return NULL;
		if (be16_to_cpu(dfp->offset) == off)
			return dfp;
	}
	/*
	 * Didn't find it.  This only happens if there are duplicate lengths.
	 */
	return NULL;
}

/*
 * Insert an unused-space entry into the bestfree table.
 */
xfs_dir2_data_free_t *				/* entry inserted */
xfs_dir2_data_freeinsert(
	struct xfs_dir2_data_hdr *hdr,		/* data block pointer */
	struct xfs_dir2_data_free *dfp,		/* bestfree table pointer */
	struct xfs_dir2_data_unused *dup,	/* unused space */
	int			*loghead)	/* log the data header (out) */
{
	xfs_dir2_data_free_t	new;		/* new bestfree entry */

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));

	new.length = dup->length;
	new.offset = cpu_to_be16((char *)dup - (char *)hdr);

	/*
	 * Insert at position 0, 1, or 2; or not at all.
	 */
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[0].length)) {
		dfp[2] = dfp[1];
		dfp[1] = dfp[0];
		dfp[0] = new;
		*loghead = 1;
		return &dfp[0];
	}
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[1].length)) {
		dfp[2] = dfp[1];
		dfp[1] = new;
		*loghead = 1;
		return &dfp[1];
	}
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[2].length)) {
		dfp[2] = new;
		*loghead = 1;
		return &dfp[2];
	}
	return NULL;
}

/*
 * Remove a bestfree entry from the table.
 */
STATIC void
xfs_dir2_data_freeremove(
	struct xfs_dir2_data_hdr *hdr,		/* data block header */
	struct xfs_dir2_data_free *bf,		/* bestfree table pointer */
	struct xfs_dir2_data_free *dfp,		/* bestfree entry pointer */
	int			*loghead)	/* out: log data header */
{

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));

	/*
	 * It's the first entry, slide the next 2 up.
	 */
	if (dfp == &bf[0]) {
		bf[0] = bf[1];
		bf[1] = bf[2];
	}
	/*
	 * It's the second entry, slide the 3rd entry up.
	 */
	else if (dfp == &bf[1])
		bf[1] = bf[2];
	/*
	 * Must be the last entry.
	 */
	else
		ASSERT(dfp == &bf[2]);
	/*
	 * Clear the 3rd entry, must be zero now.
	 */
	bf[2].length = 0;
	bf[2].offset = 0;
	*loghead = 1;
}

/*
 * Given a data block, reconstruct its bestfree map.
 */
void
xfs_dir2_data_freescan(
	struct xfs_mount		*mp,
	struct xfs_dir2_data_hdr	*hdr,
	int				*loghead)
{
	struct xfs_da_geometry		*geo = mp->m_dir_geo;
	struct xfs_dir2_data_free	*bf = xfs_dir2_data_bestfree_p(mp, hdr);
	void				*addr = hdr;
	unsigned int			offset = geo->data_entry_offset;
	unsigned int			end;

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));

	/*
	 * Start by clearing the table.
	 */
	memset(bf, 0, sizeof(*bf) * XFS_DIR2_DATA_FD_COUNT);
	*loghead = 1;

	end = xfs_dir3_data_end_offset(geo, addr);
	while (offset < end) {
		struct xfs_dir2_data_unused	*dup = addr + offset;
		struct xfs_dir2_data_entry	*dep = addr + offset;

		/*
		 * If it's a free entry, insert it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			ASSERT(offset ==
			       be16_to_cpu(*xfs_dir2_data_unused_tag_p(dup)));
			xfs_dir2_data_freeinsert(hdr, bf, dup, loghead);
			offset += be16_to_cpu(dup->length);
			continue;
		}

		/*
		 * For active entries, check their tags and skip them.
		 */
		ASSERT(offset ==
		       be16_to_cpu(*xfs_dir2_data_entry_tag_p(mp, dep)));
		offset += xfs_dir2_data_entsize(mp, dep->namelen);
	}
}

/*
 * Initialize a data block at the given block number in the directory.
 * Give back the buffer for the created block.
 */
int						/* error */
xfs_dir3_data_init(
	struct xfs_da_args		*args,	/* directory operation args */
	xfs_dir2_db_t			blkno,	/* logical dir block number */
	struct xfs_buf			**bpp)	/* output block buffer */
{
	struct xfs_trans		*tp = args->trans;
	struct xfs_inode		*dp = args->dp;
	struct xfs_mount		*mp = dp->i_mount;
	struct xfs_da_geometry		*geo = args->geo;
	struct xfs_buf			*bp;
	struct xfs_dir2_data_hdr	*hdr;
	struct xfs_dir2_data_unused	*dup;
	struct xfs_dir2_data_free 	*bf;
	int				error;
	int				i;

	/*
	 * Get the buffer set up for the block.
	 */
	error = xfs_da_get_buf(tp, dp, xfs_dir2_db_to_da(args->geo, blkno),
			       &bp, XFS_DATA_FORK);
	if (error)
		return error;

	/* sess16(ccloop): stamp the dir-block COHERENT-TENURE epoch on a freshly
	 * created/initialized DATA block so it carries the CURRENT handoff epoch
	 * (not 0).  This is what makes the prior-tenure evict override
	 * (mxfs_dir_evict_data_blocks, dir_evict_prior_tenure) able to drop its
	 * epoch!=0 guard and reliably distinguish a stale prior-tenure cache-hit
	 * (epoch < valid_epoch) from our own current-tenure work (epoch ==
	 * valid_epoch) WITHOUT resurrecting a just-created block.  Inert unless
	 * dir_evict_prior_tenure is enabled. */
	bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch;

	/*
	 * sess54(ccloop) RULE-4: ALWAYS-ON, I/O-FREE dir-block DOUBLE-ALLOCATION
	 * detector.  The durable round-N whole-block losses (LOOKUP_ENOENT, spread
	 * across many nodes' entries, addname coherent-compare CLEAN = the clobber
	 * is NOT a read-side RMW) point at xfs_dir3_data_init ZEROING a daddr that
	 * is ALREADY mapped by THIS dir's in-core fork at a DIFFERENT logical
	 * offset — i.e. the AG free-space handed out an in-use block as free, so
	 * two logical dir blocks alias one daddr and the init wipes the live one.
	 * Pure in-core iext scan (no disk I/O), so it cannot mask the race like the
	 * gated P31E plain-read does.  Fires per init that double-maps; capped.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(dp)->i_mode)) {
		xfs_fsblock_t	d2_fsb = XFS_DADDR_TO_FSB(mp, xfs_buf_daddr(bp));
		xfs_fileoff_t	d2_off = xfs_dir2_db_to_da(args->geo, blkno);
		struct xfs_iext_cursor	d2_icur;
		struct xfs_bmbt_irec	d2_got;
		static atomic_t		p54dm = ATOMIC_INIT(0);

		for_each_xfs_iext(&dp->i_df, &d2_icur, &d2_got) {
			if (isnullstartblock(d2_got.br_startblock))
				continue;
			if (d2_fsb >= d2_got.br_startblock &&
			    d2_fsb < d2_got.br_startblock + d2_got.br_blockcount) {
				xfs_fileoff_t mapped = d2_got.br_startoff +
					(d2_fsb - d2_got.br_startblock);
				if (mapped != d2_off &&
				    atomic_inc_return(&p54dm) <= 4000)
					pr_warn("mxfs: P54-DOUBLEMAP ino=%llu new_lblk=%d daddr=%lld pfsb=%llu already_mapped_off=%llu init_off=%llu — daddr already mapped by THIS dir at a different logical block = dir-block DOUBLE-ALLOC about to zero live data\n",
						(unsigned long long)dp->i_ino,
						(int)blkno,
						(long long)xfs_buf_daddr(bp),
						(unsigned long long)d2_fsb,
						(unsigned long long)mapped,
						(unsigned long long)d2_off);
			}
		}
	}

	/*
	 * ccloop sess31 P31E-DATAINIT-ABA (GPT-5.5 RULE-5 decisive detector):
	 * xfs_da_get_buf returns a get_buf (NOT read) buffer about to be ZEROED
	 * and re-initialized as an empty dir DATA block.  Under the
	 * dir_reuse_coherency churn (rm-rf+recreate reuses the dir inode# and its
	 * data-block daddrs) a STALE in-core data fork can make this node treat a
	 * logical dir block as NEW/hole when the PEER has already materialized it
	 * at this physical daddr — so this init zeroes a block that already holds
	 * the peer's durable committed dirents (the first-wave node1_f1..f12
	 * durable loss = readdir short).  Coherently plain-read the physical daddr
	 * we are about to clobber; if it ALREADY carries a valid dir3 data/block
	 * header (XDD3/XDB3) with the SAME owner and live dirents, fire — the
	 * get_buf/init ABA clobber is caught in the act.  Capped, multi-node dir.
	 */
	{
		extern int mxfs_instr_enabled;
		struct xfs_inode *p31e_dp = dp;
		struct xfs_mount *p31e_mp = mp;

		/* sess37: these detectors do SYNCHRONOUS plain-read disk I/O per
		 * fire (capped 800) which materially perturbs the create-heavy
		 * dir_reuse path timing and MASKS the stale-RMW race (a heisenbug:
		 * the test flips pass/fail with the extra latency).  Gate behind
		 * mxfs.instr so production/measurement runs are true-speed; the
		 * P31E/P31F clobbers were PROVEN benign (prior-incarnation freed-
		 * block reuse — on-disk inode is shortform/small at the clobber). */
		if (unlikely(mxfs_instr_enabled) &&
		    p31e_mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(p31e_mp->m_mxfs_dlm) &&
		    p31e_mp->m_ddev_targp && p31e_mp->m_ddev_targp->bt_bdev) {
			static atomic_t p31e_n = ATOMIC_INIT(0);

			/*
			 * sess32 (b)-discriminator (GPT-5.5): is the daddr the
			 * allocator just handed out for this "new" dir block
			 * ALREADY mapped by THIS dir's in-core data-fork extent
			 * map at a DIFFERENT logical offset?  If so the AG
			 * free-space considered an in-use block free → a dir-block
			 * DOUBLE-ALLOCATION, and data_init is about to zero live
			 * CURRENT dir data (decisive vs the ambiguous reuse case
			 * where the block belongs to a freed prior incarnation and
			 * is NOT in the current map).  Pure in-core scan, no I/O.
			 */
			{
				xfs_fsblock_t	dm_fsb = XFS_DADDR_TO_FSB(p31e_mp,
							xfs_buf_daddr(bp));
				xfs_fileoff_t	dm_off = xfs_dir2_db_to_da(args->geo,
							blkno);
				struct xfs_iext_cursor	dm_icur;
				struct xfs_bmbt_irec	dm_got;
				static atomic_t		p32b_n = ATOMIC_INIT(0);

				for_each_xfs_iext(&dp->i_df, &dm_icur, &dm_got) {
					if (isnullstartblock(dm_got.br_startblock))
						continue;
					if (dm_fsb >= dm_got.br_startblock &&
					    dm_fsb < dm_got.br_startblock +
						     dm_got.br_blockcount) {
						xfs_fileoff_t mapped = dm_got.br_startoff +
							(dm_fsb - dm_got.br_startblock);
						if (mapped != dm_off &&
						    atomic_inc_return(&p32b_n) <= 800)
							pr_warn("mxfs: P32B-DOUBLEMAP ino=%llu new_lblk=%d daddr=%lld pfsb=%llu already_mapped_off=%llu init_off=%llu — daddr already mapped by THIS dir at a different logical block = dir-block DOUBLE-ALLOC\n",
								(unsigned long long)dp->i_ino,
								(int)blkno,
								(long long)xfs_buf_daddr(bp),
								(unsigned long long)dm_fsb,
								(unsigned long long)mapped,
								(unsigned long long)dm_off);
					}
				}
			}

			if (atomic_inc_return(&p31e_n) <= 800) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t blen = p31e_mp->m_sb.sb_blocksize;
				void *tmp = (blen >= 512 && (blen & 511) == 0) ?
					kmalloc(blen, GFP_NOFS) : NULL;

				if (tmp && mxfs_pal_bdev_read_plain_bdev(
				    p31e_mp->m_ddev_targp->bt_bdev,
				    (uint64_t)xfs_buf_daddr(bp) +
					p31e_mp->m_ddev_targp->bt_sector_offset,
				    tmp, blen) == 0) {
					struct xfs_dir3_blk_hdr *h3 = tmp;
					uint32_t m = be32_to_cpu(h3->magic);
					bool isdir = (m == XFS_DIR3_DATA_MAGIC ||
						      m == XFS_DIR3_BLOCK_MAGIC);
					uint64_t down = be64_to_cpu(h3->owner);
					int live = 0;
					unsigned int off = p31e_mp->m_dir_geo->data_entry_offset;
					unsigned int end = p31e_mp->m_dir_geo->blksize;
					/* sess32: capture the first real dirent name on the
					 * block about to be zeroed.  DECISIVE dual-EX proof:
					 * if THIS node (e.g. test1, writes node1_*) is about
					 * to zero a block holding the PEER's node2_* names,
					 * it is clobbering the peer's CURRENT dirents (real
					 * cross-node loss).  node1_* alone is ambiguous
					 * (could be a prior reused incarnation). */
					char p31e_nm[20] = "";

					while (isdir && off + 8 <= end) {
						struct xfs_dir2_data_unused *du =
							(struct xfs_dir2_data_unused *)((char *)tmp + off);
						if (be16_to_cpu(du->freetag) ==
						    XFS_DIR2_DATA_FREE_TAG) {
							unsigned int l = be16_to_cpu(du->length);
							if (l < 8) break;
							off += l;
						} else {
							struct xfs_dir2_data_entry *de =
								(struct xfs_dir2_data_entry *)((char *)tmp + off);
							if (de->namelen == 0) break;
							if (!p31e_nm[0] && de->namelen) {
								int nl = de->namelen < 19 ?
									de->namelen : 19;
								memcpy(p31e_nm, de->name, nl);
								p31e_nm[nl] = '\0';
							}
							live++;
							off += xfs_dir2_data_entsize(p31e_mp, de->namelen);
						}
					}
					if (isdir && live > 0) {
						/* sess37 RULE-4 DECISIVE: is the on-disk INODE's
						 * extent map missing the block we are about to
						 * clobber (durability/drain gap) or does in-core
						 * lag disk (reload gap)?  Dump the in-core data-
						 * fork extents and whether the clobbered daddr is
						 * mapped in-core, plus a coherent plain-read of the
						 * on-disk dir inode's di_nextents/fmt/size/gen. */
						{
							struct xfs_iext_cursor f_icur;
							struct xfs_bmbt_irec f_got;
							xfs_fileoff_t cl_off = xfs_dir2_db_to_da(args->geo, blkno);
							int f_n = 0, f_mapped = 0;
							char f_ex[160]; int f_p = 0;
							uint32_t icl = BBTOB(p31e_dp->i_imap.im_len);
							void *ict = ((icl & 511) == 0 && icl) ?
								kmalloc(icl, GFP_NOFS) : NULL;
							long long disk_nx = -1, disk_sz = -1;
							int disk_fmt = -1; uint32_t disk_gen = 0;

							for_each_xfs_iext(&p31e_dp->i_df, &f_icur, &f_got) {
								if (f_n < 6 && f_p < 150)
									f_p += scnprintf(f_ex + f_p,
										sizeof(f_ex) - f_p,
										"[o%llu s%llu c%llu]",
										(unsigned long long)f_got.br_startoff,
										(unsigned long long)f_got.br_startblock,
										(unsigned long long)f_got.br_blockcount);
								f_n++;
								if (!isnullstartblock(f_got.br_startblock) &&
								    cl_off >= f_got.br_startoff &&
								    cl_off < f_got.br_startoff + f_got.br_blockcount)
									f_mapped = 1;
							}
							if (ict && mxfs_pal_bdev_read_plain_bdev(
							    p31e_mp->m_ddev_targp->bt_bdev,
							    (uint64_t)p31e_dp->i_imap.im_blkno +
								p31e_mp->m_ddev_targp->bt_sector_offset,
							    ict, icl) == 0) {
								struct xfs_dinode *idd =
									ict + p31e_dp->i_imap.im_boffset;
								disk_nx = be32_to_cpu(idd->di_nextents);
								disk_sz = be64_to_cpu(idd->di_size);
								disk_fmt = idd->di_format;
								disk_gen = be32_to_cpu(idd->di_gen);
							}
							pr_warn("mxfs: P31F-BMAP ino=%llu clobber_off=%llu incore_nx=%d incore_mapped=%d disk_nx=%lld disk_fmt=%d disk_size=%lld disk_gen=%u incore_gen=%u extents=%s\n",
								(unsigned long long)p31e_dp->i_ino,
								(unsigned long long)cl_off, f_n, f_mapped,
								disk_nx, disk_fmt, disk_sz, disk_gen,
								VFS_I(p31e_dp)->i_generation, f_ex);
							kfree(ict);
						}
						/* sess32 RULE-4 (a)-vs-(b) discriminator:
						 * bast_pending=1 at the clobber => this node
						 * is fast-path-serving an EX MODIFY while a
						 * peer's BAST is deferred under MHT (sess10
						 * case a).  ex_grant_seq vs dirty_seq tells if
						 * the dirty fork belongs to an earlier EX
						 * tenure (we yielded EX in between => the
						 * reacquire did not reload = sess10 case b). */
						pr_warn("mxfs: P31E-DATAINIT-ABA ino=%llu lblk=%d daddr=%lld caller=%pS disk_magic=0x%08x disk_owner=%llu live_dirents=%d first_name=\"%s\" incore_fmt=%d incore_nx=%llu incore_size=%lld dir_gen=%llu loaded_gen=%u dlm_mode=%u dlm_state=%u stale=%d selfc=%d unpub=%d reused=%d bast_pend=%d ex_gseq=%llu dirty_seq=%llu comm=%s — get_buf/init about to ZERO a block holding live peer dirents\n",
							(unsigned long long)p31e_dp->i_ino,
							(int)blkno,
							(long long)xfs_buf_daddr(bp),
							__builtin_return_address(0),
							m, (unsigned long long)down, live,
							p31e_nm,
							(int)p31e_dp->i_df.if_format,
							(unsigned long long)p31e_dp->i_df.if_nextents,
							(long long)p31e_dp->i_disk_size,
							(unsigned long long)p31e_dp->i_dlm_dir_gen,
							p31e_dp->i_dlm_dir_loaded_gen,
							p31e_dp->i_dlm_mode,
							p31e_dp->i_dlm_state,
							p31e_dp->i_dlm_stale ? 1 : 0,
							p31e_dp->i_mxfs_self_created ? 1 : 0,
							p31e_dp->i_dlm_unpublished ? 1 : 0,
							p31e_dp->i_mxfs_reused_create ? 1 : 0,
							p31e_dp->i_dlm_bast_pending ? 1 : 0,
							(unsigned long long)p31e_dp->i_mxfs_ex_grant_seq,
							(unsigned long long)p31e_dp->i_mxfs_dirty_seq,
							current->comm);
					}
				}
				kfree(tmp);
			}
		}
	}

	/* sess62 (RULE 4) ALWAYS-ON, no-FUA, decisive: log every data_init of a
	 * multinode non-root dir's LOGICAL BLOCK 0.  The durable loss is ALWAYS
	 * node1_f1 (first dirent of the reused dir); if data_init(blk0) is called
	 * during the create wave (after node1_f1 exists) it ZEROES block0 ->
	 * mechanism (a) [data_init-zeroes-live-block].  If block0 is never
	 * re-init'd here, the loss is a stale-cached-block0 RMW [mechanism (b)].
	 * Also scan the get_buf'd buffer (cheap, in-memory) for node1_f1: if the
	 * cached buffer being zeroed already holds it, that IS the clobber. */
	if (blkno == 0 && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(dp)->i_mode) && dp->i_ino != mp->m_sb.sb_rootino) {
		const char *cb = bp->b_addr;
		int blen = BBTOB(bp->b_length);
		int k, has_n1f1 = 0, done = !!(bp->b_flags & XBF_DONE);

		for (k = 0; cb && done && k + 8 <= blen; k++) {
			if (cb[k] == 'n' && !memcmp(cb + k, "node1_f1", 8)) {
				char nx = (k + 8 < blen) ? cb[k + 8] : 0;
				if (!(nx >= '0' && nx <= '9') && nx != '.') {
					has_n1f1 = 1;
					break;
				}
			}
		}
		{
			static atomic_t pdi0 = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdi0) <= 3000)
				pr_warn("mxfs: P62-DATAINIT-BLK0 ino=%llu daddr=%lld buf_done=%d cached_has_n1f1=%d i_gen=%u dlm_mode=%u comm=%s — about to ZERO+init dir logical block0\n",
					(unsigned long long)dp->i_ino,
					(long long)xfs_buf_daddr(bp), done, has_n1f1,
					VFS_I(dp)->i_generation, dp->i_dlm_mode,
					current->comm);
		}
		/* P-DBLALLOC-BIRTH (RULE-4): FUA-read the CURRENT on-disk content of
		 * the block we are about to allocate+init as this dir's block0.  If
		 * disk already holds a VALID dir3 block/data magic owned by a
		 * DIFFERENT inode, the allocator just handed us a block that is LIVE
		 * in another dir = cross-node bnobt DOUBLE-ALLOC caught at birth
		 * (proves disk-level double-alloc, not a phantom in-core map). */
		{
			static atomic_t pdib = ATOMIC_INIT(0);
			uint32_t blen2 = BBTOB(bp->b_length);
			void *dbuf = (atomic_inc_return(&pdib) <= 400)
				? kmalloc(blen2, GFP_NOFS) : NULL;
			if (dbuf) {
				uint64_t lba = (uint64_t)xfs_buf_daddr(bp) +
					mp->m_ddev_targp->bt_sector_offset;
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *, uint64_t, void *,
					uint32_t);
				int rrc = mxfs_pal_scsi_read_fua_bdev(
					mp->m_ddev_targp->bt_bdev, lba, dbuf, blen2);
				if (rrc == 0) {
					__be32 dmagic = *(__be32 *)dbuf;
					uint64_t downer = be64_to_cpu(
						*(__be64 *)((char *)dbuf + 0x28));
					uint32_t m = be32_to_cpu(dmagic);
					if (m == XFS_DIR3_BLOCK_MAGIC ||
					    m == XFS_DIR3_DATA_MAGIC) {
						pr_warn("mxfs: P-DBLALLOC-BIRTH ino=%llu daddr=%lld disk_magic=0x%x disk_owner=%llu foreign=%d — allocating dir block0 over a %s on-disk dir block\n",
							(unsigned long long)dp->i_ino,
							(long long)xfs_buf_daddr(bp),
							m, (unsigned long long)downer,
							(downer != dp->i_ino) ? 1 : 0,
							(downer != dp->i_ino) ?
							"FOREIGN LIVE" : "own-stale");
						/* P-DBLALLOC-AGF (RULE 4, sess5): read-vs-write
						 * discriminator for the bnobt double-alloc.  On a
						 * FOREIGN-LIVE birth, compare this node's in-core AGF
						 * summary (pag->pagf_freeblks/longest) against the
						 * on-disk AGF (FUA).  DIFFER => in-core AG-meta STALE
						 * (peer's alloc unseen; coldread miss = READ coherence).
						 * SAME  => on-disk bnobt itself considers the block free
						 * (peer's alloc never durably updated free-space =
						 * WRITE/durability).  Pinpoints which side to fix. */
						if (downer != dp->i_ino) {
							xfs_fsblock_t fb = XFS_DADDR_TO_FSB(mp,
								xfs_buf_daddr(bp));
							xfs_agnumber_t agno = XFS_FSB_TO_AGNO(mp, fb);
							struct xfs_perag *pag = xfs_perag_get(mp, agno);
							void *ab = kmalloc(512, GFP_NOFS);
							if (pag && ab) {
								uint64_t alba = (uint64_t)XFS_AG_DADDR(mp,
									agno, XFS_AGF_DADDR(mp)) +
									mp->m_ddev_targp->bt_sector_offset;
								if (mxfs_pal_scsi_read_fua_bdev(
								    mp->m_ddev_targp->bt_bdev, alba,
								    ab, 512) == 0) {
									struct xfs_agf *dagf = ab;
									uint32_t dfree = be32_to_cpu(dagf->agf_freeblks);
									uint32_t dlong = be32_to_cpu(dagf->agf_longest);
									pr_warn("mxfs: P-DBLALLOC-AGF ino=%llu agno=%u incore_freeblks=%u disk_freeblks=%u incore_longest=%u disk_longest=%u agf_differ=%d — %s\n",
										(unsigned long long)dp->i_ino,
										agno,
										(unsigned)pag->pagf_freeblks,
										dfree,
										(unsigned)pag->pagf_longest,
										dlong,
										(pag->pagf_freeblks != dfree) ? 1 : 0,
										(pag->pagf_freeblks != dfree) ?
										"in-core AGF STALE = READ coherence" :
										"in-core==disk AGF = WRITE/durability");
								}
							}
							if (ab) kfree(ab);
							if (pag) xfs_perag_put(pag);
						}
					}
				}
				kfree(dbuf);
			}
		}
	}

	/* sess68 (RULE 4) ALWAYS-ON, NO-IO: log every data_init of a multinode
	 * non-root dir at ANY logical block.  force_block converged block0 (all
	 * nodes @ same daddr); the residual 4-node loss is now at HIGHER blocks
	 * (BLOCK->LEAF grow).  Decisive question: does this node data_init a
	 * logical block the PEER already materialized (divergent extent map)?
	 * Cheap in-core only: log blkno, daddr, in-core if_nextents, disk
	 * di_nextents, dlm_mode, i_gen.  If in-core nextents lags disk at a higher
	 * block, the node grew on a stale map -> re-allocates a block the peer owns. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(dp)->i_mode) && dp->i_ino != mp->m_sb.sb_rootino) {
		static atomic_t pdi_any = ATOMIC_INIT(0);
		if (unlikely(mxfs_dirwr_enabled) &&
		    atomic_inc_return(&pdi_any) <= 3000)
			pr_warn("mxfs: P68-DATAINIT blkno=%d ino=%llu daddr=%lld buf_done=%d incore_nx=%llu fmt=%u dlm_mode=%u dir_gen=%u loaded_gen=%u i_gen=%u comm=%s\n",
				(int)blkno, (unsigned long long)dp->i_ino,
				(long long)xfs_buf_daddr(bp),
				!!(bp->b_flags & XBF_DONE),
				(unsigned long long)dp->i_df.if_nextents,
				dp->i_df.if_format, dp->i_dlm_mode,
				dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
				VFS_I(dp)->i_generation, current->comm);
	}

	bp->b_ops = &xfs_dir3_data_buf_ops;
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DIR_DATA_BUF);

	/*
	 * Initialize the header.
	 */
	hdr = bp->b_addr;
	if (xfs_has_crc(mp)) {
		struct xfs_dir3_blk_hdr *hdr3 = bp->b_addr;

		memset(hdr3, 0, sizeof(*hdr3));
		hdr3->magic = cpu_to_be32(XFS_DIR3_DATA_MAGIC);
		hdr3->blkno = cpu_to_be64(xfs_buf_daddr(bp));
		hdr3->owner = cpu_to_be64(args->owner);
		uuid_copy(&hdr3->uuid, &mp->m_sb.sb_meta_uuid);

	} else
		hdr->magic = cpu_to_be32(XFS_DIR2_DATA_MAGIC);

	bf = xfs_dir2_data_bestfree_p(mp, hdr);
	bf[0].offset = cpu_to_be16(geo->data_entry_offset);
	bf[0].length = cpu_to_be16(geo->blksize - geo->data_entry_offset);
	for (i = 1; i < XFS_DIR2_DATA_FD_COUNT; i++) {
		bf[i].length = 0;
		bf[i].offset = 0;
	}

	/*
	 * Set up an unused entry for the block's body.
	 */
	dup = bp->b_addr + geo->data_entry_offset;
	dup->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
	dup->length = bf[0].length;
	*xfs_dir2_data_unused_tag_p(dup) = cpu_to_be16((char *)dup - (char *)hdr);

	/*
	 * Log it and return it.
	 */
	xfs_dir2_data_log_header(args, bp);
	xfs_dir2_data_log_unused(args, bp, dup);
	/*
	 * sess40 (ccloop 8ddb16a2): stamp the CURRENT incarnation on this freshly
	 * get_buf'd + re-initialized dir DATA block — mirror of the read-path
	 * stamp (xfs_da_btree.c:3484).  xfs_da_get_buf above can return a LINGERING
	 * cached buffer at a reused daddr that still carries the PRIOR incarnation's
	 * b_mxfs_dir_incarn; this block now holds the CURRENT incarnation's content,
	 * so without re-stamping it the writeback ABA guard
	 * (mxfs_buf_xfsaild_skip_dir_write, sess40) would mistake the first block of
	 * a recreated dir for a dead-incarnation leftover and suppress its flush =
	 * durable loss.  dp is the owning dir inode.
	 */
	bp->b_mxfs_dir_incarn = VFS_I(dp)->i_generation;
	*bpp = bp;
	return 0;
}

/*
 * sess49 (ccloop, RULE 4 DECISIVE): does a block image contain an active dirent
 * with the given name?  Walks active dirents from data_entry_offset, skipping
 * free entries by length, stopping defensively on a zero/garbage namelen so it
 * never wanders into a block-format leaf tail.  Pure in-memory, no I/O.
 */
static bool
mxfs_dirblk_has_name(
	struct xfs_mount	*mp,
	const void		*blk,
	uint32_t		blen,
	const __u8		*name,
	uint8_t			namelen)
{
	uint32_t off = mp->m_dir_geo->data_entry_offset;
	uint32_t end = mp->m_dir_geo->blksize;

	if (end > blen)
		end = blen;
	while (off + 8 <= end) {
		const struct xfs_dir2_data_unused *du =
			(const struct xfs_dir2_data_unused *)((const char *)blk + off);

		if (be16_to_cpu(du->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			uint32_t l = be16_to_cpu(du->length);
			if (l < 8)
				break;
			off += l;
			continue;
		} else {
			const struct xfs_dir2_data_entry *de =
				(const struct xfs_dir2_data_entry *)((const char *)blk + off);
			uint8_t nl = de->namelen;

			if (nl == 0 || off + 9 + nl > end)
				break;
			if (nl == namelen && memcmp(de->name, name, nl) == 0)
				return true;
			off += xfs_dir2_data_entsize(mp, nl);
		}
	}
	return false;
}

/*
 * Log an active data entry from the block.
 */
void
xfs_dir2_data_log_entry(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,
	xfs_dir2_data_entry_t	*dep)		/* data entry pointer */
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));

	xfs_trans_log_buf(args->trans, bp, (uint)((char *)dep - (char *)hdr),
		(uint)((char *)(xfs_dir2_data_entry_tag_p(mp, dep) + 1) -
		       (char *)hdr - 1));

	/* sess52(ccloop) DECISIVE concurrent-modify / phantom-EX probe (sess50 plan).
	 * P28-PLATTER proved the DATA base is COHERENT at modify (in-core==platter),
	 * so the count-preserving single-dirent loss is a DLM SERIALIZATION HOLE, not
	 * a cache bug: TWO nodes RMW the SAME dir block in overlapping windows.  Log
	 * every storm-dir DATA modify with this node's serialization state +
	 * wall-clock so a cross-node correlation can catch the same daddr modified by
	 * different nodes concurrently.  master/held/gg settle master double-grant
	 * (audit found 0) vs non-master phantom-EX (stale local EX not demoted on a
	 * master revoke -> i_dlm_mode=EX while the master granted a peer). */
	if (unlikely(mxfs_dirwr_enabled) && args->dp &&
	    args->dp->i_ino <= 256 && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern int mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *,
							 uint64_t);
		extern uint32_t mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *,
							    uint64_t);
		extern int mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *, uint64_t);
		static atomic_t mxfs_p51n = ATOMIC_INIT(0);
		int mxfs_held51 = mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm,
							 args->dp->i_ino);
		int mxfs_master51 = mxfs_v5_dlm_inode_master_self(mp->m_mxfs_dlm,
								  args->dp->i_ino);
		/* PHANTOM-EX: a non-master dir modify with NO held DLM grant =
		 * the PROVEN dir_reuse loss (1:1 with the lost dirent).  Dump the
		 * stack + state ONCE to pinpoint the path that served a phantom EX. */
		if (mxfs_held51 == 0 && mxfs_master51 == 0 &&
		    current->comm[0] != 'm' /* skip benign mkdir master self-grant */) {
			static atomic_t mxfs_phantom_dumped = ATOMIC_INIT(0);
			pr_warn("mxfs: P51-PHANTOM ino=%llu daddr=%lld name=[%.*s] state=%d bastacq=%d demoter_self=%d comm=%s\n",
				(unsigned long long)args->dp->i_ino,
				(long long)xfs_buf_daddr(bp),
				args->namelen, args->name,
				args->dp->i_dlm_state,
				args->dp->i_dlm_bast_during_acq ? 1 : 0,
				(args->dp->i_dlm_demoter == current) ? 1 : 0,
				current->comm);
			if (atomic_inc_return(&mxfs_phantom_dumped) <= 2)
				dump_stack();
		}
		if (atomic_inc_return(&mxfs_p51n) <= 40000)
			pr_warn("mxfs: P51-MOD ino=%llu daddr=%lld name=[%.*s] dlm_mode=%d master=%d held=%d gg=%u bastpend=%d bastacq=%d demoting=%d realns=%llu comm=%s\n",
				(unsigned long long)args->dp->i_ino,
				(long long)xfs_buf_daddr(bp),
				args->namelen, args->name,
				args->dp->i_dlm_mode,
				mxfs_master51,
				mxfs_held51,
				mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm,
							    args->dp->i_ino),
				args->dp->i_dlm_bast_pending ? 1 : 0,
				args->dp->i_dlm_bast_during_acq ? 1 : 0,
				args->dp->i_dlm_demoter ? 1 : 0,
				(unsigned long long)ktime_get_real_ns(),
				current->comm);
	}

	/* sess2(ccloop) ALWAYS-ON cheap epoch-at-placement probe (RULE 4): the
	 * mht=1500 residual is a CLEAN round-1 single-dirent loss = stale-base
	 * free-slot double-alloc.  HYPOTHESIS: in round 1 the per-dir master/valid
	 * epoch is still 0/low so the addname epoch-staleness gates never fire on
	 * the first cross-node handoffs -> unprotected stale-base RMW.  Capture (in
	 * mem only, NO FUA / NO dump_stack -> non-perturbing) the epoch triple at
	 * EVERY storm-dir placement, BEFORE the sess16 stamp launders b_epoch.  Log
	 * the EPOCH-UNESTABLISHED (master_ep==0) and STALE-BASE (b_ep<master_ep)
	 * placements so a captured round-1 loss can be correlated. Capped. */
	if (args->dp && mxfs_ino_watched(args->dp->i_ino) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *,
							    uint64_t);
		uint32_t master_ep = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
							args->dp->i_ino);
		uint32_t valid_ep = args->dp->i_dlm_dir_valid_epoch;
		uint32_t b_ep = bp->b_mxfs_dir_epoch;
		bool unestablished = (master_ep == 0 || valid_ep == 0);
		bool stale_base = (master_ep != 0 && b_ep != 0 &&
				   b_ep < master_ep);
		if (unestablished || stale_base) {
			static atomic_t p2ep = ATOMIC_INIT(0);
			if (atomic_inc_return(&p2ep) <= 400)
				pr_warn("mxfs: P2-EPOCHPLACE ino=%llu daddr=%lld name=[%.*s] master_ep=%u valid_ep=%u b_ep=%u unestablished=%d stale_base=%d comm=%s\n",
					(unsigned long long)args->dp->i_ino,
					(long long)xfs_buf_daddr(bp),
					args->namelen, args->name,
					master_ep, valid_ep, b_ep,
					unestablished ? 1 : 0,
					stale_base ? 1 : 0, current->comm);
		}
		/* sess13 PLACEMENT LEDGER (watch-gated, RULE 4): the drc f1 loss
		 * commits in-core and never reaches the platter (P13-COLLIDE
		 * never fired for blk0; the final bins lack the names).  Log
		 * EVERY placement on the watched dir with the dir's DLM
		 * serialization state + wall clock so the cross-node timeline
		 * (with P64-N1F1 write tracer + P51-REL/P70-BP release marks)
		 * shows whether the victim's commit landed inside the release
		 * drain->unlock window or was tossed by a later adopt. */
		{
			/* sess13: dirwr-gated — at 8 nodes this always-on
			 * ledger's printk volume (journald ratelimit off) blew
			 * the drc/tds time budgets (~40s rounds; workers
			 * killed with empty results).  mxfs.dirwr=1 re-arms
			 * the 4-node swallow hunt. */
			extern int mxfs_dirwr_enabled;
			static atomic_t p13pl = ATOMIC_INIT(0);
			if (unlikely(mxfs_dirwr_enabled) &&
			    atomic_inc_return(&p13pl) <= 40000)
				pr_warn("mxfs: P13-PLACE ino=%llu daddr=%lld name=[%.*s] mode=%u state=%u exh=%u bpend=%d bacq=%d realns=%llu comm=%s\n",
					(unsigned long long)args->dp->i_ino,
					(long long)xfs_buf_daddr(bp),
					args->namelen, args->name,
					args->dp->i_dlm_mode,
					args->dp->i_dlm_state,
					args->dp->i_dlm_ex_holders,
					args->dp->i_dlm_bast_pending ? 1 : 0,
					args->dp->i_dlm_bast_during_acq ? 1 : 0,
					(unsigned long long)ktime_get_real_ns(),
					current->comm);
		}
	}

	/* sess16(ccloop): MODIFY-time coherent-tenure stamp.  We are modifying this
	 * DATA block under the dir's current grant tenure, so its content is OUR
	 * current-tenure work — stamp the current handoff epoch so the prior-tenure
	 * evict override never mistakes it for a stale prior-tenure base (the piece
	 * that lets that override drop its epoch!=0 guard and catch a tenure-0
	 * block0 served as a stale cache-hit, without resurrecting our own work). */
	if (args->dp)
		bp->b_mxfs_dir_epoch = args->dp->i_dlm_dir_valid_epoch;

	/* sess13run (ccloop, RULE 4 DECISIVE): collision detector AT placement.
	 * The dir_reuse residual is a free-slot DOUBLE-ALLOCATION — two nodes place
	 * different dirents at the same (daddr, byte offset).  Here, right as we
	 * write our dirent, do a COHERENT plain-bdev read of THIS data block from
	 * the shared LUN and check whether the SAME byte offset already holds a
	 * DIFFERENT, non-free dirent on disk.  If so, our addname's free-slot
	 * search used a STALE base (it believed this offset free) and we are about
	 * to durably clobber a peer's committed entry — log it with both names.
	 * Fires ONLY on the actual collision (rare) so perturbation is minimal.
	 * SAFE in-transaction: plain-bdev read into a kmalloc temp does NOT touch
	 * the buffer cache (no fresh xfs_buf_incore, which sess11run proved
	 * corrupts).  Scoped to the storm dir (ino<=256), multinode only. */
	if (args->dp && mxfs_ino_watched(args->dp->i_ino) &&
	    !READ_ONCE(mxfs_watch_light) && bp->b_target &&
	    bp->b_target->bt_bdev && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
				uint64_t, void *, uint32_t);
		uint32_t blen = BBTOB(bp->b_length);
		uint32_t off = (uint32_t)((char *)dep - (char *)hdr);
		void *tmp = (blen && (blen & 511) == 0) ?
				kmalloc(blen, GFP_NOFS) : NULL;
		uint64_t lba = bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;

		if (tmp && off + 10 <= blen &&
		    mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
						  lba, tmp, blen) == 0) {
			__be16 *ftag = (void *)((char *)tmp + off);
			struct xfs_dir3_blk_hdr *dhdr = (void *)tmp;
			uint32_t dmagic = be32_to_cpu(dhdr->magic);
			uint64_t downer = be64_to_cpu(dhdr->owner);
			int disk_is_ourdir = (dmagic == XFS_DIR3_DATA_MAGIC ||
					      dmagic == XFS_DIR3_BLOCK_MAGIC) &&
					     downer == args->dp->i_ino;

			/* 0xffff freetag => free on disk (no collision). */
			if (be16_to_cpu(*ftag) != XFS_DIR2_DATA_FREE_TAG) {
				struct xfs_dir2_data_entry *de = (void *)ftag;
				uint8_t dnl = de->namelen;

				if (dnl >= 1 && off + 9 + dnl <= blen &&
				    (dnl != dep->namelen ||
				     memcmp(de->name, dep->name, dnl) != 0)) {
					/* sess46 (ccloop, RULE 4 DECISIVE): capture the
					 * colliding buffer's clean/dirty/AIL state AT the
					 * collision.  If dirty/in-AIL/pinned/delwri/!DONE,
					 * mxfs_dir_addname_coherent_refresh SKIPPED this
					 * block (the "never touch own dirty work" guard) ->
					 * the residual SINGLE is a DIRTY-stale-base RMW and
					 * the fix must be release-side (clean+retire-BLI so
					 * it isn't dirty at the next acquire) or a dirty-
					 * block refresh.  If CLEAN, addname_coherent reread
					 * a STILL-LAGGING platter -> writer-FUA gap. */
					struct xfs_buf_log_item *cbip = bp->b_log_item;
					int cdirty = cbip && test_bit(XFS_LI_DIRTY,
						&cbip->bli_item.li_flags);
					int cinail = cbip && test_bit(XFS_LI_IN_AIL,
						&cbip->bli_item.li_flags);
					int cpin = xfs_buf_ispinned(bp);
					int cdelwri = !!(bp->b_flags & _XBF_DELWRI_Q);
					int cdone = !!(bp->b_flags & XBF_DONE);
					pr_warn_ratelimited(
					    "mxfs: P13-COLLIDE ino=%llu daddr=%lld off=%u our=[%.*s] disk=[%.*s] comm=%s dirty=%d inail=%d pin=%d delwri=%d done=%d bufgen=%llu dirgen=%llu cohgen=%u dmagic=0x%x downer=%llu ourdir=%d — placing onto a DIFFERENT durable dirent (stale-base free-slot double-alloc)\n",
					    (unsigned long long)args->dp->i_ino,
					    (long long)bp->b_maps[0].bm_bn, off,
					    (int)dep->namelen, dep->name,
					    (int)dnl, de->name, current->comm,
					    cdirty, cinail, cpin, cdelwri, cdone,
					    (unsigned long long)bp->b_mxfs_dir_gen,
					    (unsigned long long)args->dp->i_dlm_dir_gen,
					    bp->b_mxfs_coherent_gen,
					    dmagic, (unsigned long long)downer,
					    disk_is_ourdir);
				}
			}

			/* sess49 (ccloop, RULE 4 DECISIVE): whole-block stale-base
			 * detector.  P13-COLLIDE above only fires when the SAME byte
			 * offset already holds a different durable dirent — i.e. a
			 * free-slot DOUBLE-ALLOCATION.  The residual single-dirent loss
			 * is a NON-collision: this node adds its entry into a slot that
			 * is free on BOTH images, but its in-core base block is MISSING
			 * one of a peer's durable entries elsewhere in the block.  When
			 * this dirty in-core image is written back whole, that peer
			 * entry is durably clobbered.  Walk every active dirent on the
			 * durable platter image (tmp); if one is absent from our in-core
			 * block (bp->b_addr), we are about to lose it.  Report dirty/AIL
			 * state and the dir-tenure epoch: a PRIOR-tenure dirty block
			 * (b_mxfs_dir_epoch < i_dlm_dir_valid_epoch) means
			 * addname_coherent's CLEAN-only guard SKIPPED the FUA refresh
			 * for a stale leftover — the proven dirty-stale-base RMW. */
			if (disk_is_ourdir) {
				uint32_t woff = mp->m_dir_geo->data_entry_offset;
				uint32_t wend = mp->m_dir_geo->blksize;
				int misses = 0;
				char firstmiss[20] = "";

				if (wend > blen)
					wend = blen;
				while (woff + 8 <= wend && misses < 64) {
					struct xfs_dir2_data_unused *wu =
						(void *)((char *)tmp + woff);
					struct xfs_dir2_data_entry *we =
						(void *)((char *)tmp + woff);
					uint8_t wnl;

					if (be16_to_cpu(wu->freetag) ==
					    XFS_DIR2_DATA_FREE_TAG) {
						uint32_t l = be16_to_cpu(wu->length);
						if (l < 8)
							break;
						woff += l;
						continue;
					}
					wnl = we->namelen;
					if (wnl == 0 || woff + 9 + wnl > wend)
						break;
					if (!(wnl == 1 && we->name[0] == '.') &&
					    !(wnl == 2 && we->name[0] == '.' &&
					      we->name[1] == '.') &&
					    !mxfs_dirblk_has_name(mp, hdr, blen,
							we->name, wnl)) {
						if (!firstmiss[0]) {
							int c = wnl < 19 ? wnl : 19;
							memcpy(firstmiss, we->name, c);
							firstmiss[c] = '\0';
						}
						misses++;
					}
					woff += xfs_dir2_data_entsize(mp, wnl);
				}
				if (misses > 0) {
					struct xfs_buf_log_item *sbip = bp->b_log_item;
					int sdirty = sbip && test_bit(XFS_LI_DIRTY,
						&sbip->bli_item.li_flags);
					int sinail = sbip && test_bit(XFS_LI_IN_AIL,
						&sbip->bli_item.li_flags);
					int spin = xfs_buf_ispinned(bp);
					int sdelwri = !!(bp->b_flags & _XBF_DELWRI_Q);
					int sdone = !!(bp->b_flags & XBF_DONE);
					pr_warn_ratelimited(
					    /* sess79: the trailing prose used to repeat the count
					     * with a %d that had NO argument — 16 specifiers, 15
					     * args.  vsnprintf then read an uninitialised va_arg,
					     * so this probe's own summary line printed garbage.
					     * missing= above already carries the count. */
					    "mxfs: P49-STALEBASE ino=%llu daddr=%lld adding=[%.*s] missing=%d firstmiss=[%s] dirty=%d inail=%d pin=%d delwri=%d done=%d buf_epoch=%llu valid_epoch=%llu prior_tenure=%d dirgen=%llu — in-core base missing the durable peer dirent(s) listed above; whole-block writeback will clobber them\n",
					    (unsigned long long)args->dp->i_ino,
					    (long long)bp->b_maps[0].bm_bn,
					    (int)dep->namelen, dep->name,
					    misses, firstmiss,
					    sdirty, sinail, spin, sdelwri, sdone,
					    (unsigned long long)bp->b_mxfs_dir_epoch,
					    (unsigned long long)args->dp->i_dlm_dir_valid_epoch,
					    (bp->b_mxfs_dir_epoch <
					     args->dp->i_dlm_dir_valid_epoch) ? 1 : 0,
					    (unsigned long long)args->dp->i_dlm_dir_gen);
				}
			}
		}
		if (tmp)
			kfree(tmp);
	}

	/* sess11(ccloop) P11-DATALOG: the entry BYTES of a dirent are logged to
	 * THIS data block here.  Capture (dir ino, daddr, name) for the storm
	 * dir so a lost dirent (PRELOGF shows its block lacks it post-commit)
	 * can be traced to the exact block it was written to — isolating whether
	 * the addname placed it in a block i_df later doesn't reflect, or commit
	 * reverts the block.  Read-only beyond the already-done log_buf; no
	 * extra buffer lock (uses the passed, transaction-held bp). */
	if (unlikely((mxfs_dirwr_enabled || mxfs_instr_enabled ||
		      READ_ONCE(mxfs_watch_ino) > 1) && args->dp &&
		     mxfs_ino_watched(args->dp->i_ino) && dep->namelen >= 8 &&
		     dep->name[0] == 'n' && dep->name[1] == 'o' &&
		     dep->name[2] == 'd' && dep->name[3] == 'e'))
		pr_warn("mxfs: P11-DATALOG ino=%llu daddr=%lld off=%u name=[%.*s] comm=%s\n",
			(unsigned long long)args->dp->i_ino,
			(long long)bp->b_maps[0].bm_bn,
			(unsigned int)((char *)dep - (char *)hdr),
			(int)dep->namelen, dep->name, current->comm);
}

/*
 * Log a data block header.
 */
void
xfs_dir2_data_log_header(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp)
{
#ifdef DEBUG
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));
#endif

	xfs_trans_log_buf(args->trans, bp, 0, args->geo->data_entry_offset - 1);

	/* sess16(ccloop): MODIFY-time coherent-tenure stamp (see
	 * xfs_dir2_data_log_entry). */
	if (args->dp)
		bp->b_mxfs_dir_epoch = args->dp->i_dlm_dir_valid_epoch;
}

/*
 * Log a data unused entry.
 */
void
xfs_dir2_data_log_unused(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,
	xfs_dir2_data_unused_t	*dup)		/* data unused pointer */
{
	xfs_dir2_data_hdr_t	*hdr = bp->b_addr;

	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));

	/*
	 * Log the first part of the unused entry.
	 */
	xfs_trans_log_buf(args->trans, bp, (uint)((char *)dup - (char *)hdr),
		(uint)((char *)&dup->length + sizeof(dup->length) -
		       1 - (char *)hdr));
	/*
	 * Log the end (tag) of the unused entry.
	 */
	xfs_trans_log_buf(args->trans, bp,
		(uint)((char *)xfs_dir2_data_unused_tag_p(dup) - (char *)hdr),
		(uint)((char *)xfs_dir2_data_unused_tag_p(dup) - (char *)hdr +
		       sizeof(xfs_dir2_data_off_t) - 1));
}

/*
 * Make a byte range in the data block unused.
 * Its current contents are unimportant.
 */
void
xfs_dir2_data_make_free(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,
	xfs_dir2_data_aoff_t	offset,		/* starting byte offset */
	xfs_dir2_data_aoff_t	len,		/* length in bytes */
	int			*needlogp,	/* out: log header */
	int			*needscanp)	/* out: regen bestfree */
{
	xfs_dir2_data_hdr_t	*hdr;		/* data block pointer */
	xfs_dir2_data_free_t	*dfp;		/* bestfree pointer */
	int			needscan;	/* need to regen bestfree */
	xfs_dir2_data_unused_t	*newdup;	/* new unused entry */
	xfs_dir2_data_unused_t	*postdup;	/* unused entry after us */
	xfs_dir2_data_unused_t	*prevdup;	/* unused entry before us */
	unsigned int		end;
	struct xfs_dir2_data_free *bf;

	hdr = bp->b_addr;

	/*
	 * sess9(a9a03929) RULE-4 free-side ledger — mirror of P13-LADD.  Every
	 * byte-range free in a storm-dir data block, with the live dirent name
	 * currently at the freed offset.  Discriminator for the readdir-tear:
	 * a make_free that lands on a PEER's dirent leaves the entry's bytes as
	 * residue under the new unused descriptor (lookup-by-leaf still reads
	 * them, readdir walks past) — if the lost name appears here, a LOCAL
	 * path freed it (remove/heal/union); if not, the unused descriptor
	 * arrived via a whole-block image (write-side divergence).  Always-on,
	 * storm-dir scoped, capped.
	 */
	if (args->dp && mxfs_ino_watched(args->dp->i_ino)) {
		static atomic_t p9lf = ATOMIC_INIT(0);

		if (atomic_inc_return(&p9lf) <= 60000) {
			xfs_dir2_data_entry_t *fdep =
				(xfs_dir2_data_entry_t *)((char *)bp->b_addr + offset);
			int live = be16_to_cpu(((xfs_dir2_data_unused_t *)fdep)->freetag)
					!= XFS_DIR2_DATA_FREE_TAG;
			int nl = live ? fdep->namelen : 0;

			if (nl > 32)
				nl = 32;
			pr_warn("mxfs: P9-LFREE ino=%llu daddr=%lld aoff=%u len=%u live=%d name=[%.*s] comm=%s realns=%llu\n",
				(unsigned long long)args->dp->i_ino,
				(long long)bp->b_maps[0].bm_bn,
				(unsigned)offset, (unsigned)len, live,
				nl, live ? (char *)fdep->name : "",
				current->comm,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * Figure out where the end of the data area is.
	 */
	end = xfs_dir3_data_end_offset(args->geo, hdr);
	ASSERT(end != 0);

	/*
	 * If this isn't the start of the block, then back up to
	 * the previous entry and see if it's free.
	 */
	if (offset > args->geo->data_entry_offset) {
		__be16			*tagp;	/* tag just before us */

		tagp = (__be16 *)((char *)hdr + offset) - 1;
		prevdup = (xfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));
		if (be16_to_cpu(prevdup->freetag) != XFS_DIR2_DATA_FREE_TAG)
			prevdup = NULL;
	} else
		prevdup = NULL;
	/*
	 * If this isn't the end of the block, see if the entry after
	 * us is free.
	 */
	if (offset + len < end) {
		postdup =
			(xfs_dir2_data_unused_t *)((char *)hdr + offset + len);
		if (be16_to_cpu(postdup->freetag) != XFS_DIR2_DATA_FREE_TAG)
			postdup = NULL;
	} else
		postdup = NULL;
	ASSERT(*needscanp == 0);
	needscan = 0;
	/*
	 * Previous and following entries are both free,
	 * merge everything into a single free entry.
	 */
	bf = xfs_dir2_data_bestfree_p(args->dp->i_mount, hdr);
	if (prevdup && postdup) {
		xfs_dir2_data_free_t	*dfp2;	/* another bestfree pointer */

		/*
		 * See if prevdup and/or postdup are in bestfree table.
		 */
		dfp = xfs_dir2_data_freefind(hdr, bf, prevdup);
		dfp2 = xfs_dir2_data_freefind(hdr, bf, postdup);
		/*
		 * We need a rescan unless there are exactly 2 free entries
		 * namely our two.  Then we know what's happening, otherwise
		 * since the third bestfree is there, there might be more
		 * entries.
		 */
		needscan = (bf[2].length != 0);
		/*
		 * Fix up the new big freespace.
		 */
		be16_add_cpu(&prevdup->length, len + be16_to_cpu(postdup->length));
		*xfs_dir2_data_unused_tag_p(prevdup) =
			cpu_to_be16((char *)prevdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, prevdup);
		if (!needscan) {
			/*
			 * Has to be the case that entries 0 and 1 are
			 * dfp and dfp2 (don't know which is which), and
			 * entry 2 is empty.
			 * Remove entry 1 first then entry 0.
			 */
			ASSERT(dfp && dfp2);
			if (dfp == &bf[1]) {
				dfp = &bf[0];
				ASSERT(dfp2 == dfp);
				dfp2 = &bf[1];
			}
			xfs_dir2_data_freeremove(hdr, bf, dfp2, needlogp);
			xfs_dir2_data_freeremove(hdr, bf, dfp, needlogp);
			/*
			 * Now insert the new entry.
			 */
			dfp = xfs_dir2_data_freeinsert(hdr, bf, prevdup,
						       needlogp);
			ASSERT(dfp == &bf[0]);
			ASSERT(dfp->length == prevdup->length);
			ASSERT(!dfp[1].length);
			ASSERT(!dfp[2].length);
		}
	}
	/*
	 * The entry before us is free, merge with it.
	 */
	else if (prevdup) {
		dfp = xfs_dir2_data_freefind(hdr, bf, prevdup);
		be16_add_cpu(&prevdup->length, len);
		*xfs_dir2_data_unused_tag_p(prevdup) =
			cpu_to_be16((char *)prevdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, prevdup);
		/*
		 * If the previous entry was in the table, the new entry
		 * is longer, so it will be in the table too.  Remove
		 * the old one and add the new one.
		 */
		if (dfp) {
			xfs_dir2_data_freeremove(hdr, bf, dfp, needlogp);
			xfs_dir2_data_freeinsert(hdr, bf, prevdup, needlogp);
		}
		/*
		 * Otherwise we need a scan if the new entry is big enough.
		 */
		else {
			needscan = be16_to_cpu(prevdup->length) >
				   be16_to_cpu(bf[2].length);
		}
	}
	/*
	 * The following entry is free, merge with it.
	 */
	else if (postdup) {
		dfp = xfs_dir2_data_freefind(hdr, bf, postdup);
		newdup = (xfs_dir2_data_unused_t *)((char *)hdr + offset);
		newdup->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
		newdup->length = cpu_to_be16(len + be16_to_cpu(postdup->length));
		*xfs_dir2_data_unused_tag_p(newdup) =
			cpu_to_be16((char *)newdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup);
		/*
		 * If the following entry was in the table, the new entry
		 * is longer, so it will be in the table too.  Remove
		 * the old one and add the new one.
		 */
		if (dfp) {
			xfs_dir2_data_freeremove(hdr, bf, dfp, needlogp);
			xfs_dir2_data_freeinsert(hdr, bf, newdup, needlogp);
		}
		/*
		 * Otherwise we need a scan if the new entry is big enough.
		 */
		else {
			needscan = be16_to_cpu(newdup->length) >
				   be16_to_cpu(bf[2].length);
		}
	}
	/*
	 * Neither neighbor is free.  Make a new entry.
	 */
	else {
		newdup = (xfs_dir2_data_unused_t *)((char *)hdr + offset);
		newdup->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
		newdup->length = cpu_to_be16(len);
		*xfs_dir2_data_unused_tag_p(newdup) =
			cpu_to_be16((char *)newdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup);
		xfs_dir2_data_freeinsert(hdr, bf, newdup, needlogp);
	}
	*needscanp = needscan;
}

/* Check our free data for obvious signs of corruption. */
static inline xfs_failaddr_t
xfs_dir2_data_check_free(
	struct xfs_dir2_data_hdr	*hdr,
	struct xfs_dir2_data_unused	*dup,
	xfs_dir2_data_aoff_t		offset,
	xfs_dir2_data_aoff_t		len)
{
	if (hdr->magic != cpu_to_be32(XFS_DIR2_DATA_MAGIC) &&
	    hdr->magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    hdr->magic != cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) &&
	    hdr->magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return __this_address;
	if (be16_to_cpu(dup->freetag) != XFS_DIR2_DATA_FREE_TAG)
		return __this_address;
	if (offset < (char *)dup - (char *)hdr)
		return __this_address;
	if (offset + len > (char *)dup + be16_to_cpu(dup->length) - (char *)hdr)
		return __this_address;
	if ((char *)dup - (char *)hdr !=
			be16_to_cpu(*xfs_dir2_data_unused_tag_p(dup)))
		return __this_address;
	return NULL;
}

/* Sanity-check a new bestfree entry. */
static inline xfs_failaddr_t
xfs_dir2_data_check_new_free(
	struct xfs_dir2_data_hdr	*hdr,
	struct xfs_dir2_data_free	*dfp,
	struct xfs_dir2_data_unused	*newdup)
{
	if (dfp == NULL)
		return __this_address;
	if (dfp->length != newdup->length)
		return __this_address;
	if (be16_to_cpu(dfp->offset) != (char *)newdup - (char *)hdr)
		return __this_address;
	return NULL;
}

/*
 * sess28(ccloop) THE FIX — format-agnostic read-side staleness guard.  Called
 * from block/leaf/node addname right after the data block's bestfree (bf) is
 * located and BEFORE dup/use_free.  If the CLEAN in-core dir DATA block diverges
 * from the durable platter image (a peer added a dirent we never saw — the lossy
 * TCP gen/epoch left our cached block current-stamped but stale), refresh the
 * buffer IN PLACE from the platter so bf reflects the peer's entry and the
 * caller's dup = hdr + bf[0].offset lands on a genuinely free slot instead of
 * overwriting the peer (PROVEN byte-exact: node7_f47 over node5_f46 @ off=1280).
 * Returns 1 if it refreshed (caller's bf/hdr pointers are unchanged — same buf
 * address — so no recompute is needed; the next dup deref reads the fresh
 * bestfree).  Ground-truth platter check, independent of handoff reliability.
 */
int
mxfs_dir_addname_coherent_refresh(
	struct xfs_da_args	*args,
	struct xfs_buf		*dbp)
{
	extern int mxfs_dir_addname_coherent;
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf_log_item	*bip;
	struct xfs_dir3_blk_hdr	*ph;
	uint32_t		blen;
	uint64_t		lba;
	void			*tmp;
	bool			pcur;
	int			ret = 0;

	if (!mxfs_dir_addname_coherent || !dbp || !dbp->b_addr || !dbp->b_maps)
		return 0;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	if (!S_ISDIR(VFS_I(dp)->i_mode) || dp->i_dlm_unpublished)
		return 0;
	/* ccloop 0d6e174d dlm_scaling ROOT FIX: a published dir held EX with zero
	 * peer BASTs is provably private (i_dlm_mode==EX && !i_dlm_dir_contended;
	 * see mxfs_dir_priv_ex_skip) — no peer can have committed a dirent our
	 * in-core base is missing, so the per-addname FUA-platter compare below is
	 * pure waste.  dlm_scaling's private per-node subdir returns to CLEAN between
	 * each create/unlink (immediate commit+destage), defeating the "throttled
	 * after the first add makes the block dirty" guard and firing this FUA every
	 * op — the measured ~2.9 dir-FUA/op that sank the 50/s floor at 16 nodes. */
	{
		extern int mxfs_dir_priv_ex_skip;
		if (mxfs_dir_priv_ex_skip &&
		    dp->i_dlm_mode == MXFS_LOCK_EX && !dp->i_dlm_dir_contended &&
		    dp->i_dlm_dir_valid_epoch == 0)
			return 0;
	}
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return 0;

	/* CLEAN only: never touch our own dirty/in-AIL in-tenure work.  This is
	 * ALSO the natural RULE-0 throttle: once this node adds an entry the block
	 * becomes dirty, so the per-addname FUA platter check fires only on the
	 * FIRST add into each still-CLEAN (potentially peer-stale) block per tenure
	 * — not on every addname.  A gen/seq dedup is UNSOUND here: the proven root
	 * is that a peer modifies our cached block with NO local signal (dir_gen
	 * unchanged at the clobber, P28W), so only the platter is ground truth. */
	bip = dbp->b_log_item;
	{
		extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *);
		bool b_dirty = bip && test_bit(XFS_LI_DIRTY,
				&bip->bli_item.li_flags);
		bool b_inail = bip && test_bit(XFS_LI_IN_AIL,
				&bip->bli_item.li_flags);

		/*
		 * sess54(ccloop) RULE-4 — relax the in-AIL half of the keep-guard.
		 * The residual durable single .md5 loss survives ALL read-side
		 * checks (P28E coherent, DOUBLEMAP=0, KEEPGUARD=0, MEPZERO=0) AND
		 * is NOT a modify-without-EX hole (P54-NOTEX-MODIFY=0) NOR a
		 * stale reflush (tenure_reflush_skip ineffective).  The only
		 * remaining skip is THIS guard returning 0 on an in-AIL block:
		 * a block that is XBF_DONE + CLEAN + already-DESTAGED (content on
		 * the platter, lseq==wseq) but whose BLI still LINGERS in the AIL
		 * (a "zombie") is a stale snapshot a peer may have superseded
		 * (it added a dirent at the daddr after our release-drain landed
		 * our image).  The old guard blocked the FUA-compare for it, so
		 * the addname RMW'd the stale cached block and durably reverted
		 * the peer's dirent.  A DESTAGED in-AIL block carries NO un-landed
		 * local work (Inv 1: drained durable at release), so FUA-comparing
		 * + invalidating-for-reread loses nothing — it just re-fetches the
		 * peer's current durable image.  Still KEEP a dirty/pinned/delwri/
		 * !DONE or UNDESTAGED-in-AIL block (real un-landed work).
		 */
		/*
		 * sess5(a9a03929) run80 ROOT FIX (RULE 4, test2 r1 @69.966):
		 * the undestaged keep-guard was conditioned on b_inail — but a
		 * block whose fresh adds are still CIL-RESIDENT (committed,
		 * not yet AIL-inserted: in_cil=1 in_ail=0, transient pin
		 * already dropped, BLI not DIRTY) fell through to the
		 * platter-compare, which of course differed (in-core is
		 * SUPPOSED to be ahead pre-destage) — P28C then invalidated
		 * the block and re-read the platter, discarding the last four
		 * md5 adds of the wave (node2_f47-50.md5 durably lost
		 * cluster-wide).  With completion-time wseq (FIX-5) the
		 * undestaged predicate (pinned || lseq>wseq) is exact through
		 * the whole commit->destage pipeline — honor it
		 * UNCONDITIONALLY.  The sess54 zombie relaxation is
		 * preserved: a genuinely destaged (lseq==wseq) in-AIL zombie
		 * still gets FUA-compared.
		 */
		if (!(dbp->b_flags & XBF_DONE) || b_dirty ||
		    xfs_buf_ispinned(dbp) ||
		    (dbp->b_flags & _XBF_DELWRI_Q) ||
		    mxfs_dir_buf_is_undestaged(dbp))
			return 0;

		if (b_inail && dp->i_ino <= 256) {
			static atomic_t p54id = ATOMIC_INIT(0);
			if (atomic_inc_return(&p54id) <= 4000)
				pr_warn("mxfs: P54-INAIL-DESTAGED ino=%llu daddr=%lld — in-AIL destaged-zombie dir block now FUA-compared (was keep-guard-skipped); candidate residual clobber site\n",
					(unsigned long long)dp->i_ino,
					(long long)dbp->b_maps[0].bm_bn);
		}
	}

	blen = BBTOB(dbp->b_length);
	if (!blen || (blen & 511))
		return 0;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return 0;
	lba = (uint64_t)dbp->b_maps[0].bm_bn + mp->m_ddev_targp->bt_sector_offset;
	if (mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba,
					tmp, blen) == 0) {
		ph = tmp;
		pcur = (be32_to_cpu(ph->magic) == XFS_DIR3_DATA_MAGIC ||
			be32_to_cpu(ph->magic) == XFS_DIR3_BLOCK_MAGIC) &&
		       be64_to_cpu(ph->owner) == dp->i_ino;
		/* sess28 capped (NOT ratelimited -> real counts) instrument: does the
		 * helper reach the FUA read for the storm dir, and does the in-core
		 * block diverge from the platter?  diff=1 means a stale base caught. */
		if (mxfs_ino_watched(dp->i_ino)) {
			static atomic_t p28e = ATOMIC_INIT(0);
			if (atomic_inc_return(&p28e) <= 60000)
				pr_warn("mxfs: P28E ino=%llu daddr=%lld pcur=%d pmagic=0x%x powner=%llu diff=%d\n",
					(unsigned long long)dp->i_ino,
					(long long)dbp->b_maps[0].bm_bn, pcur,
					be32_to_cpu(ph->magic),
					(unsigned long long)be64_to_cpu(ph->owner),
					pcur ? (memcmp(tmp, dbp->b_addr, blen) != 0) : -1);
		}
		if (pcur) {
			if (memcmp(tmp, dbp->b_addr, blen) != 0) {
				/* CLEAN in-core base is STALE vs the durable
				 * platter.  Do NOT memcpy in place (injects an
				 * unverified image past the read verifier ->
				 * later CRC/dir3 check fails -> shutdown).  Mark
				 * the buffer for a VERIFIED cold re-read and let
				 * the caller restart so xfs_dir3_data_read re-
				 * fetches it through the read verifier. */
				dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				dbp->b_mxfs_dir_gen = 0;
				ret = 1;
				pr_warn_ratelimited("mxfs: P28C-STALE ino=%llu daddr=%lld dir_gen=%llu — CLEAN in-core dir block stale vs platter; invalidate+reread\n",
					(unsigned long long)dp->i_ino,
					(long long)dbp->b_maps[0].bm_bn,
					(unsigned long long)dp->i_dlm_dir_gen);
			}
		}
	}
	kfree(tmp);
	/* sess2(ccloop) ROOT FIX (P2-EPOCHPLACE PROVEN): leaf/block-format addname
	 * RMW'd an EPOCH-STALE base UNPROTECTED.  node-format addname (xfs_dir2_node.c)
	 * has a coarse master-handoff-epoch gate (b_mxfs_dir_epoch < valid_epoch =>
	 * a peer held EX + modified the dir since this block's base loaded => cold
	 * re-read), but leaf.c/block.c had ONLY the FUA-platter-compare above, which
	 * MISSES the case where the peer's add is committed-but-not-yet-destaged (the
	 * platter ALSO lags, so in-core==platter and the compare matches) — exactly
	 * the dir_reuse storm dir (LEAF format).  Port the epoch gate here so ALL
	 * callers (leaf:1262, block:448, node:2008) get it.  Clean-only (gated above),
	 * so own dirty/in-AIL/pinned/undestaged work is never dropped.  Forces the
	 * caller's existing brelse + xfs_dir3_data_read cold-refetch so the free-slot
	 * search reflects the peer's tenure (no intra-block double-alloc). */
	{
	extern int mxfs_dir_addname_epoch_refresh;
	if (!ret && mxfs_dir_addname_epoch_refresh) {
		extern uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *,
							    uint64_t);
		uint32_t master_ep = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
								 dp->i_ino);
		/* sess45: braces — unconditional incarn stamp (see the
		 * xfs_da_btree.c sibling fix). */
		if (master_ep > dp->i_dlm_dir_valid_epoch) {
			dp->i_dlm_dir_valid_epoch = master_ep;
			dp->i_dlm_dir_valid_incarn = VFS_I(dp)->i_generation;	/* sess28: the baseline belongs to THIS incarnation */
		}
		if (master_ep != 0 && dbp->b_mxfs_dir_epoch != 0 &&
		    dbp->b_mxfs_dir_epoch < dp->i_dlm_dir_valid_epoch) {
			dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			dbp->b_mxfs_dir_gen = 0;
			ret = 1;
			pr_warn_ratelimited("mxfs: P2-LEAF-EPOCHSTALE ino=%llu daddr=%lld b_ep=%u master_ep=%u — leaf/block addname epoch-stale base; invalidate+reread\n",
				(unsigned long long)dp->i_ino,
				(long long)dbp->b_maps[0].bm_bn,
				dbp->b_mxfs_dir_epoch, master_ep);
		}
	}
	}
	return ret;
}

/*
 * Take a byte range out of an existing unused space and make it un-free.
 */
int
xfs_dir2_data_use_free(
	struct xfs_da_args	*args,
	struct xfs_buf		*bp,
	xfs_dir2_data_unused_t	*dup,		/* unused entry */
	xfs_dir2_data_aoff_t	offset,		/* starting offset to use */
	xfs_dir2_data_aoff_t	len,		/* length to use */
	int			*needlogp,	/* out: need to log header */
	int			*needscanp)	/* out: need regen bestfree */
{
	xfs_dir2_data_hdr_t	*hdr;		/* data block header */
	xfs_dir2_data_free_t	*dfp;		/* bestfree pointer */
	xfs_dir2_data_unused_t	*newdup;	/* new unused entry */
	xfs_dir2_data_unused_t	*newdup2;	/* another new unused entry */
	struct xfs_dir2_data_free *bf;
	xfs_failaddr_t		fa;
	int			matchback;	/* matches end of freespace */
	int			matchfront;	/* matches start of freespace */
	int			needscan;	/* need to regen bestfree */
	int			oldlen;		/* old unused entry's length */

	hdr = bp->b_addr;

	/*
	 * sess54(ccloop) RULE-4 SERIALIZATION-HOLE probe.  The durable dirent loss
	 * is NOT a stale-base RMW (read-side coherent) and NOT a stale reflush
	 * (tenure_reflush_skip=1 did not help) => sess50/54 converge on a DLM
	 * serialization hole.  DECISIVE test: a dirent is being PLACED here; if this
	 * node does NOT hold the owning dir inode's DLM EX at the placement, two
	 * nodes can place into the same block concurrently and one durably erases
	 * the other (the count-preserving single/contiguous loss).  Fires ONLY on
	 * the anomaly (mode != EX) so it is low-volume and cannot mask the race.
	 */
	{
		struct xfs_inode *ufdp = args->dp;
		struct xfs_mount *ufmp = ufdp->i_mount;

		if (ufmp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ufmp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(ufdp)->i_mode) && ufdp->i_ino <= 256 &&
		    ufdp->i_dlm_mode != MXFS_LOCK_EX) {
			static atomic_t p54nx = ATOMIC_INIT(0);
			if (atomic_inc_return(&p54nx) <= 4000)
				pr_warn("mxfs: P54-NOTEX-MODIFY ino=%llu dlm_mode=%d daddr=%lld off=%u len=%u comm=%s — placing a dirent while NOT holding dir DLM EX (serialization hole)\n",
					(unsigned long long)ufdp->i_ino,
					ufdp->i_dlm_mode,
					(long long)bp->b_maps[0].bm_bn,
					(unsigned)offset, (unsigned)len,
					current->comm);
		}
	}

	fa = xfs_dir2_data_check_free(hdr, dup, offset, len);
	if (fa)
		goto corrupt;
	/*
	 * Look up the entry in the bestfree table.
	 */
	oldlen = be16_to_cpu(dup->length);
	bf = xfs_dir2_data_bestfree_p(args->dp->i_mount, hdr);
	dfp = xfs_dir2_data_freefind(hdr, bf, dup);
	ASSERT(dfp || oldlen <= be16_to_cpu(bf[2].length));
	/*
	 * Check for alignment with front and back of the entry.
	 */
	matchfront = (char *)dup - (char *)hdr == offset;
	matchback = (char *)dup + oldlen - (char *)hdr == offset + len;
	ASSERT(*needscanp == 0);
	needscan = 0;
	/*
	 * If we matched it exactly we just need to get rid of it from
	 * the bestfree table.
	 */
	if (matchfront && matchback) {
		if (dfp) {
			needscan = (bf[2].offset != 0);
			if (!needscan)
				xfs_dir2_data_freeremove(hdr, bf, dfp,
							 needlogp);
		}
	}
	/*
	 * We match the first part of the entry.
	 * Make a new entry with the remaining freespace.
	 */
	else if (matchfront) {
		newdup = (xfs_dir2_data_unused_t *)((char *)hdr + offset + len);
		newdup->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
		newdup->length = cpu_to_be16(oldlen - len);
		*xfs_dir2_data_unused_tag_p(newdup) =
			cpu_to_be16((char *)newdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup);
		/*
		 * If it was in the table, remove it and add the new one.
		 */
		if (dfp) {
			xfs_dir2_data_freeremove(hdr, bf, dfp, needlogp);
			dfp = xfs_dir2_data_freeinsert(hdr, bf, newdup,
						       needlogp);
			fa = xfs_dir2_data_check_new_free(hdr, dfp, newdup);
			if (fa)
				goto corrupt;
			/*
			 * If we got inserted at the last slot,
			 * that means we don't know if there was a better
			 * choice for the last slot, or not.  Rescan.
			 */
			needscan = dfp == &bf[2];
		}
	}
	/*
	 * We match the last part of the entry.
	 * Trim the allocated space off the tail of the entry.
	 */
	else if (matchback) {
		newdup = dup;
		newdup->length = cpu_to_be16(((char *)hdr + offset) - (char *)newdup);
		*xfs_dir2_data_unused_tag_p(newdup) =
			cpu_to_be16((char *)newdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup);
		/*
		 * If it was in the table, remove it and add the new one.
		 */
		if (dfp) {
			xfs_dir2_data_freeremove(hdr, bf, dfp, needlogp);
			dfp = xfs_dir2_data_freeinsert(hdr, bf, newdup,
						       needlogp);
			fa = xfs_dir2_data_check_new_free(hdr, dfp, newdup);
			if (fa)
				goto corrupt;
			/*
			 * If we got inserted at the last slot,
			 * that means we don't know if there was a better
			 * choice for the last slot, or not.  Rescan.
			 */
			needscan = dfp == &bf[2];
		}
	}
	/*
	 * Poking out the middle of an entry.
	 * Make two new entries.
	 */
	else {
		newdup = dup;
		newdup->length = cpu_to_be16(((char *)hdr + offset) - (char *)newdup);
		*xfs_dir2_data_unused_tag_p(newdup) =
			cpu_to_be16((char *)newdup - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup);
		newdup2 = (xfs_dir2_data_unused_t *)((char *)hdr + offset + len);
		newdup2->freetag = cpu_to_be16(XFS_DIR2_DATA_FREE_TAG);
		newdup2->length = cpu_to_be16(oldlen - len - be16_to_cpu(newdup->length));
		*xfs_dir2_data_unused_tag_p(newdup2) =
			cpu_to_be16((char *)newdup2 - (char *)hdr);
		xfs_dir2_data_log_unused(args, bp, newdup2);
		/*
		 * If the old entry was in the table, we need to scan
		 * if the 3rd entry was valid, since these entries
		 * are smaller than the old one.
		 * If we don't need to scan that means there were 1 or 2
		 * entries in the table, and removing the old and adding
		 * the 2 new will work.
		 */
		if (dfp) {
			needscan = (bf[2].length != 0);
			if (!needscan) {
				xfs_dir2_data_freeremove(hdr, bf, dfp,
							 needlogp);
				xfs_dir2_data_freeinsert(hdr, bf, newdup,
							 needlogp);
				xfs_dir2_data_freeinsert(hdr, bf, newdup2,
							 needlogp);
			}
		}
	}
	*needscanp = needscan;
	return 0;
corrupt:
	xfs_corruption_error(__func__, XFS_ERRLEVEL_LOW, args->dp->i_mount,
			hdr, sizeof(*hdr), __FILE__, __LINE__, fa);
	xfs_da_mark_sick(args);
	return -EFSCORRUPTED;
}

/* Find the end of the entry data in a data/block format dir block. */
unsigned int
xfs_dir3_data_end_offset(
	struct xfs_da_geometry		*geo,
	struct xfs_dir2_data_hdr	*hdr)
{
	void				*p;

	switch (hdr->magic) {
	case cpu_to_be32(XFS_DIR3_BLOCK_MAGIC):
	case cpu_to_be32(XFS_DIR2_BLOCK_MAGIC):
		p = xfs_dir2_block_leaf_p(xfs_dir2_block_tail_p(geo, hdr));
		return p - (void *)hdr;
	case cpu_to_be32(XFS_DIR3_DATA_MAGIC):
	case cpu_to_be32(XFS_DIR2_DATA_MAGIC):
		return geo->blksize;
	default:
		return 0;
	}
}
