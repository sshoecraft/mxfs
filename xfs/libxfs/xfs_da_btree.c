// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
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
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_trans.h"
#include "xfs_bmap.h"
#include "xfs_attr_leaf.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_buf_item.h"
#include "xfs_log.h"
#include "xfs_errortag.h"
#include "xfs_health.h"
#include "xfs_mxfs_dlm.h"	/* sess10(a9a03929): mxfs_ino_watched */
#include "../dlm/v5_mount.h"	/* ccloop 0d6e174d: enum mxfs_lock_mode (MXFS_LOCK_EX) */

/* sess43: true-multi-node check for the gen-0 dir-coherency fix (decl only;
 * struct is opaque here — we just pass the mount's m_mxfs_dlm pointer). */
struct mxfs_v5_dlm;
extern bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx);
extern int mxfs_dir_delalloc_tripwire(struct xfs_inode *ip, const char *site);
extern void mxfs_dir_hole_disk_probe(struct xfs_inode *ip,
				     xfs_fileoff_t want_bno);
/* sess61: concurrent dir-inode EX popcount for the double-grant A/B check. */
extern int mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino,
				      int *nslots);
/* sess133: payload-LSN destaged-vs-undestaged discriminator for dir/bmbt
 * buffers (defined in xfs_mxfs_dlm.c) — see the in-AIL refresh below. */
extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *bp);

/* sess44 RULE-4 isolation lever: gate the unpublished-dir FUA-skip fast path.
 * Default 1 (on).  Set mxfs.dir_unpub_skip=0 to disable at runtime and test
 * deferred-publish in isolation. */
extern int mxfs_dir_unpub_skip;
extern int mxfs_force_coherent;	/* NEWARCH Phase 0 measurement instrument */

/*
 * xfs_da_btree.c
 *
 * Routines to implement directories as Btrees of hashed names.
 */

/*========================================================================
 * Function prototypes for the kernel.
 *========================================================================*/

/*
 * Routines used for growing the Btree.
 */
STATIC int xfs_da3_root_split(xfs_da_state_t *state,
					    xfs_da_state_blk_t *existing_root,
					    xfs_da_state_blk_t *new_child);
STATIC int xfs_da3_node_split(xfs_da_state_t *state,
					    xfs_da_state_blk_t *existing_blk,
					    xfs_da_state_blk_t *split_blk,
					    xfs_da_state_blk_t *blk_to_add,
					    int treelevel,
					    int *result);
STATIC void xfs_da3_node_rebalance(xfs_da_state_t *state,
					 xfs_da_state_blk_t *node_blk_1,
					 xfs_da_state_blk_t *node_blk_2);
STATIC void xfs_da3_node_add(xfs_da_state_t *state,
				   xfs_da_state_blk_t *old_node_blk,
				   xfs_da_state_blk_t *new_node_blk);

/*
 * Routines used for shrinking the Btree.
 */
STATIC int xfs_da3_root_join(xfs_da_state_t *state,
					   xfs_da_state_blk_t *root_blk);
STATIC int xfs_da3_node_toosmall(xfs_da_state_t *state, int *retval);
STATIC void xfs_da3_node_remove(xfs_da_state_t *state,
					      xfs_da_state_blk_t *drop_blk);
STATIC void xfs_da3_node_unbalance(xfs_da_state_t *state,
					 xfs_da_state_blk_t *src_node_blk,
					 xfs_da_state_blk_t *dst_node_blk);

/*
 * Utility routines.
 */
STATIC int	xfs_da3_blk_unlink(xfs_da_state_t *state,
				  xfs_da_state_blk_t *drop_blk,
				  xfs_da_state_blk_t *save_blk);


struct kmem_cache	*xfs_da_state_cache;	/* anchor for dir/attr state */

/*
 * Allocate a dir-state structure.
 * We don't put them on the stack since they're large.
 */
struct xfs_da_state *
xfs_da_state_alloc(
	struct xfs_da_args	*args)
{
	struct xfs_da_state	*state;

	state = kmem_cache_zalloc(xfs_da_state_cache,
			GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
	state->args = args;
	state->mp = args->dp->i_mount;
	return state;
}

/*
 * Kill the altpath contents of a da-state structure.
 */
STATIC void
xfs_da_state_kill_altpath(xfs_da_state_t *state)
{
	int	i;

	for (i = 0; i < state->altpath.active; i++)
		state->altpath.blk[i].bp = NULL;
	state->altpath.active = 0;
}

/*
 * Free a da-state structure.
 */
void
xfs_da_state_free(xfs_da_state_t *state)
{
	xfs_da_state_kill_altpath(state);
#ifdef DEBUG
	memset((char *)state, 0, sizeof(*state));
#endif /* DEBUG */
	kmem_cache_free(xfs_da_state_cache, state);
}

void
xfs_da_state_reset(
	struct xfs_da_state	*state,
	struct xfs_da_args	*args)
{
	xfs_da_state_kill_altpath(state);
	memset(state, 0, sizeof(struct xfs_da_state));
	state->args = args;
	state->mp = state->args->dp->i_mount;
}

static inline int xfs_dabuf_nfsb(struct xfs_mount *mp, int whichfork)
{
	if (whichfork == XFS_DATA_FORK)
		return mp->m_dir_geo->fsbcount;
	return mp->m_attr_geo->fsbcount;
}

void
xfs_da3_node_hdr_from_disk(
	struct xfs_mount		*mp,
	struct xfs_da3_icnode_hdr	*to,
	struct xfs_da_intnode		*from)
{
	if (xfs_has_crc(mp)) {
		struct xfs_da3_intnode	*from3 = (struct xfs_da3_intnode *)from;

		to->forw = be32_to_cpu(from3->hdr.info.hdr.forw);
		to->back = be32_to_cpu(from3->hdr.info.hdr.back);
		to->magic = be16_to_cpu(from3->hdr.info.hdr.magic);
		to->count = be16_to_cpu(from3->hdr.__count);
		to->level = be16_to_cpu(from3->hdr.__level);
		to->btree = from3->__btree;
		ASSERT(to->magic == XFS_DA3_NODE_MAGIC);
	} else {
		to->forw = be32_to_cpu(from->hdr.info.forw);
		to->back = be32_to_cpu(from->hdr.info.back);
		to->magic = be16_to_cpu(from->hdr.info.magic);
		to->count = be16_to_cpu(from->hdr.__count);
		to->level = be16_to_cpu(from->hdr.__level);
		to->btree = from->__btree;
		ASSERT(to->magic == XFS_DA_NODE_MAGIC);
	}
}

void
xfs_da3_node_hdr_to_disk(
	struct xfs_mount		*mp,
	struct xfs_da_intnode		*to,
	struct xfs_da3_icnode_hdr	*from)
{
	if (xfs_has_crc(mp)) {
		struct xfs_da3_intnode	*to3 = (struct xfs_da3_intnode *)to;

		ASSERT(from->magic == XFS_DA3_NODE_MAGIC);
		to3->hdr.info.hdr.forw = cpu_to_be32(from->forw);
		to3->hdr.info.hdr.back = cpu_to_be32(from->back);
		to3->hdr.info.hdr.magic = cpu_to_be16(from->magic);
		to3->hdr.__count = cpu_to_be16(from->count);
		to3->hdr.__level = cpu_to_be16(from->level);
	} else {
		ASSERT(from->magic == XFS_DA_NODE_MAGIC);
		to->hdr.info.forw = cpu_to_be32(from->forw);
		to->hdr.info.back = cpu_to_be32(from->back);
		to->hdr.info.magic = cpu_to_be16(from->magic);
		to->hdr.__count = cpu_to_be16(from->count);
		to->hdr.__level = cpu_to_be16(from->level);
	}
}

/*
 * Verify an xfs_da3_blkinfo structure. Note that the da3 fields are only
 * accessible on v5 filesystems. This header format is common across da node,
 * attr leaf and dir leaf blocks.
 */
xfs_failaddr_t
xfs_da3_blkinfo_verify(
	struct xfs_buf		*bp,
	struct xfs_da3_blkinfo	*hdr3)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_da_blkinfo	*hdr = &hdr3->hdr;

	if (!xfs_verify_magic16(bp, hdr->magic))
		return __this_address;

	if (xfs_has_crc(mp)) {
		if (!uuid_equal(&hdr3->uuid, &mp->m_sb.sb_meta_uuid))
			return __this_address;
		if (be64_to_cpu(hdr3->blkno) != xfs_buf_daddr(bp))
			return __this_address;
		if (!xfs_log_check_lsn(mp, be64_to_cpu(hdr3->lsn)))
			return __this_address;
	}

	return NULL;
}

static xfs_failaddr_t
xfs_da3_node_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_da_intnode	*hdr = bp->b_addr;
	struct xfs_da3_icnode_hdr ichdr;
	xfs_failaddr_t		fa;

	xfs_da3_node_hdr_from_disk(mp, &ichdr, hdr);

	fa = xfs_da3_blkinfo_verify(bp, bp->b_addr);
	if (fa)
		return fa;

	if (ichdr.level == 0)
		return __this_address;
	if (ichdr.level > XFS_DA_NODE_MAXDEPTH)
		return __this_address;
	if (ichdr.count == 0)
		return __this_address;

	/*
	 * we don't know if the node is for and attribute or directory tree,
	 * so only fail if the count is outside both bounds
	 */
	if (ichdr.count > mp->m_dir_geo->node_ents &&
	    ichdr.count > mp->m_attr_geo->node_ents)
		return __this_address;

	/* XXX: hash order check? */

	return NULL;
}

xfs_failaddr_t
xfs_da3_node_header_check(
	struct xfs_buf		*bp,
	xfs_ino_t		owner)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (xfs_has_crc(mp)) {
		struct xfs_da3_blkinfo *hdr3 = bp->b_addr;

		if (hdr3->hdr.magic != cpu_to_be16(XFS_DA3_NODE_MAGIC))
			return __this_address;

		if (be64_to_cpu(hdr3->owner) != owner)
			return __this_address;
	}

	return NULL;
}

xfs_failaddr_t
xfs_da3_header_check(
	struct xfs_buf		*bp,
	xfs_ino_t		owner)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_da_blkinfo	*hdr = bp->b_addr;

	if (!xfs_has_crc(mp))
		return NULL;

	switch (hdr->magic) {
	case cpu_to_be16(XFS_ATTR3_LEAF_MAGIC):
		return xfs_attr3_leaf_header_check(bp, owner);
	case cpu_to_be16(XFS_DA3_NODE_MAGIC):
		return xfs_da3_node_header_check(bp, owner);
	case cpu_to_be16(XFS_DIR3_LEAF1_MAGIC):
	case cpu_to_be16(XFS_DIR3_LEAFN_MAGIC):
		return xfs_dir3_leaf_header_check(bp, owner);
	}

	ASSERT(0);
	return NULL;
}

static void
xfs_da3_node_write_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_da3_node_hdr *hdr3 = bp->b_addr;
	xfs_failaddr_t		fa;

	fa = xfs_da3_node_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (!xfs_has_crc(mp))
		return;

	if (bip)
		hdr3->info.lsn = cpu_to_be64(bip->bli_item.li_lsn);

	xfs_buf_update_cksum(bp, XFS_DA3_NODE_CRC_OFF);
}

/*
 * leaf/node format detection on trees is sketchy, so a node read can be done on
 * leaf level blocks when detection identifies the tree as a node format tree
 * incorrectly. In this case, we need to swap the verifier to match the correct
 * format of the block being read.
 */
static void
xfs_da3_node_read_verify(
	struct xfs_buf		*bp)
{
	struct xfs_da_blkinfo	*info = bp->b_addr;
	xfs_failaddr_t		fa;

	switch (be16_to_cpu(info->magic)) {
		case XFS_DA3_NODE_MAGIC:
			if (!xfs_buf_verify_cksum(bp, XFS_DA3_NODE_CRC_OFF)) {
				xfs_verifier_error(bp, -EFSBADCRC,
						__this_address);
				break;
			}
			fallthrough;
		case XFS_DA_NODE_MAGIC:
			fa = xfs_da3_node_verify(bp);
			if (fa)
				xfs_verifier_error(bp, -EFSCORRUPTED, fa);
			return;
		case XFS_ATTR_LEAF_MAGIC:
		case XFS_ATTR3_LEAF_MAGIC:
			bp->b_ops = &xfs_attr3_leaf_buf_ops;
			bp->b_ops->verify_read(bp);
			return;
		case XFS_DIR2_LEAFN_MAGIC:
		case XFS_DIR3_LEAFN_MAGIC:
			bp->b_ops = &xfs_dir3_leafn_buf_ops;
			bp->b_ops->verify_read(bp);
			return;
		default:
			xfs_verifier_error(bp, -EFSCORRUPTED, __this_address);
			break;
	}
}

/* Verify the structure of a da3 block. */
static xfs_failaddr_t
xfs_da3_node_verify_struct(
	struct xfs_buf		*bp)
{
	struct xfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
	case XFS_DA3_NODE_MAGIC:
	case XFS_DA_NODE_MAGIC:
		return xfs_da3_node_verify(bp);
	case XFS_ATTR_LEAF_MAGIC:
	case XFS_ATTR3_LEAF_MAGIC:
		bp->b_ops = &xfs_attr3_leaf_buf_ops;
		return bp->b_ops->verify_struct(bp);
	case XFS_DIR2_LEAFN_MAGIC:
	case XFS_DIR3_LEAFN_MAGIC:
		bp->b_ops = &xfs_dir3_leafn_buf_ops;
		return bp->b_ops->verify_struct(bp);
	default:
		return __this_address;
	}
}

const struct xfs_buf_ops xfs_da3_node_buf_ops = {
	.name = "xfs_da3_node",
	.magic16 = { cpu_to_be16(XFS_DA_NODE_MAGIC),
		     cpu_to_be16(XFS_DA3_NODE_MAGIC) },
	.verify_read = xfs_da3_node_read_verify,
	.verify_write = xfs_da3_node_write_verify,
	.verify_struct = xfs_da3_node_verify_struct,
};

static int
xfs_da3_node_set_type(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	int			whichfork,
	struct xfs_buf		*bp)
{
	struct xfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
	case XFS_DA_NODE_MAGIC:
	case XFS_DA3_NODE_MAGIC:
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DA_NODE_BUF);
		return 0;
	case XFS_ATTR_LEAF_MAGIC:
	case XFS_ATTR3_LEAF_MAGIC:
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_ATTR_LEAF_BUF);
		return 0;
	case XFS_DIR2_LEAFN_MAGIC:
	case XFS_DIR3_LEAFN_MAGIC:
		xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DIR_LEAFN_BUF);
		return 0;
	default:
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, tp->t_mountp,
				info, sizeof(*info));
		xfs_trans_brelse(tp, bp);
		xfs_dirattr_mark_sick(dp, whichfork);
		return -EFSCORRUPTED;
	}
}

int
xfs_da3_node_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	struct xfs_buf		**bpp,
	int			whichfork)
{
	int			error;

	error = xfs_da_read_buf(tp, dp, bno, 0, bpp, whichfork,
			&xfs_da3_node_buf_ops);
	if (error || !*bpp || !tp)
		return error;
	return xfs_da3_node_set_type(tp, dp, whichfork, *bpp);
}

int
xfs_da3_node_read_mapped(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp,
	int			whichfork)
{
	struct xfs_mount	*mp = dp->i_mount;
	int			error;

	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp, mappedbno,
			XFS_FSB_TO_BB(mp, xfs_dabuf_nfsb(mp, whichfork)), 0,
			bpp, &xfs_da3_node_buf_ops);
	if (xfs_metadata_is_sick(error))
		xfs_dirattr_mark_sick(dp, whichfork);
	if (error || !*bpp)
		return error;

	if (whichfork == XFS_ATTR_FORK)
		xfs_buf_set_ref(*bpp, XFS_ATTR_BTREE_REF);
	else
		xfs_buf_set_ref(*bpp, XFS_DIR_BTREE_REF);

	if (!tp)
		return 0;
	return xfs_da3_node_set_type(tp, dp, whichfork, *bpp);
}

/*
 * Copy src directory/attr leaf/node buffer to the dst.
 * For v5 file systems make sure the right blkno is stamped in.
 */
void
xfs_da_buf_copy(
	struct xfs_buf *dst,
	struct xfs_buf *src,
	size_t size)
{
	struct xfs_da3_blkinfo *da3 = dst->b_addr;

	memcpy(dst->b_addr, src->b_addr, size);
	dst->b_ops = src->b_ops;
	xfs_trans_buf_copy_type(dst, src);
	if (xfs_has_crc(dst->b_mount))
		da3->blkno = cpu_to_be64(xfs_buf_daddr(dst));
}

/*========================================================================
 * Routines used for growing the Btree.
 *========================================================================*/

/*
 * Create the initial contents of an intermediate node.
 */
int
xfs_da3_node_create(
	struct xfs_da_args	*args,
	xfs_dablk_t		blkno,
	int			level,
	struct xfs_buf		**bpp,
	int			whichfork)
{
	struct xfs_da_intnode	*node;
	struct xfs_trans	*tp = args->trans;
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_da3_icnode_hdr ichdr = {0};
	struct xfs_buf		*bp;
	int			error;
	struct xfs_inode	*dp = args->dp;

	trace_xfs_da_node_create(args);
	ASSERT(level <= XFS_DA_NODE_MAXDEPTH);

	error = xfs_da_get_buf(tp, dp, blkno, &bp, whichfork);
	if (error)
		return error;
	bp->b_ops = &xfs_da3_node_buf_ops;
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_DA_NODE_BUF);
	node = bp->b_addr;

	if (xfs_has_crc(mp)) {
		struct xfs_da3_node_hdr *hdr3 = bp->b_addr;

		memset(hdr3, 0, sizeof(struct xfs_da3_node_hdr));
		ichdr.magic = XFS_DA3_NODE_MAGIC;
		hdr3->info.blkno = cpu_to_be64(xfs_buf_daddr(bp));
		hdr3->info.owner = cpu_to_be64(args->owner);
		uuid_copy(&hdr3->info.uuid, &mp->m_sb.sb_meta_uuid);
	} else {
		ichdr.magic = XFS_DA_NODE_MAGIC;
	}
	ichdr.level = level;

	xfs_da3_node_hdr_to_disk(dp->i_mount, node, &ichdr);
	xfs_trans_log_buf(tp, bp,
		XFS_DA_LOGRANGE(node, &node->hdr, args->geo->node_hdr_size));

	*bpp = bp;
	return 0;
}

/*
 * Split a leaf node, rebalance, then possibly split
 * intermediate nodes, rebalance, etc.
 */
int							/* error */
xfs_da3_split(
	struct xfs_da_state	*state)
{
	struct xfs_da_state_blk	*oldblk;
	struct xfs_da_state_blk	*newblk;
	struct xfs_da_state_blk	*addblk;
	struct xfs_da_intnode	*node;
	int			max;
	int			action = 0;
	int			error;
	int			i;

	trace_xfs_da_split(state->args);

	if (XFS_TEST_ERROR(state->mp, XFS_ERRTAG_DA_LEAF_SPLIT))
		return -EIO;

	/*
	 * Walk back up the tree splitting/inserting/adjusting as necessary.
	 * If we need to insert and there isn't room, split the node, then
	 * decide which fragment to insert the new block from below into.
	 * Note that we may split the root this way, but we need more fixup.
	 */
	max = state->path.active - 1;
	ASSERT((max >= 0) && (max < XFS_DA_NODE_MAXDEPTH));
	ASSERT(state->path.blk[max].magic == XFS_ATTR_LEAF_MAGIC ||
	       state->path.blk[max].magic == XFS_DIR2_LEAFN_MAGIC);

	addblk = &state->path.blk[max];		/* initial dummy value */
	for (i = max; (i >= 0) && addblk; state->path.active--, i--) {
		oldblk = &state->path.blk[i];
		newblk = &state->altpath.blk[i];

		/*
		 * If a leaf node then
		 *     Allocate a new leaf node, then rebalance across them.
		 * else if an intermediate node then
		 *     We split on the last layer, must we split the node?
		 */
		switch (oldblk->magic) {
		case XFS_ATTR_LEAF_MAGIC:
			error = xfs_attr3_leaf_split(state, oldblk, newblk);
			if (error < 0)
				return error;	/* GROT: attr is inconsistent */
			if (!error) {
				addblk = newblk;
				break;
			}
			/*
			 * Entry wouldn't fit, split the leaf again. The new
			 * extrablk will be consumed by xfs_da3_node_split if
			 * the node is split.
			 */
			state->extravalid = 1;
			if (state->inleaf) {
				state->extraafter = 0;	/* before newblk */
				trace_xfs_attr_leaf_split_before(state->args);
				error = xfs_attr3_leaf_split(state, oldblk,
							    &state->extrablk);
			} else {
				state->extraafter = 1;	/* after newblk */
				trace_xfs_attr_leaf_split_after(state->args);
				error = xfs_attr3_leaf_split(state, newblk,
							    &state->extrablk);
			}
			if (error == 1)
				return -ENOSPC;
			if (error)
				return error;	/* GROT: attr inconsistent */
			addblk = newblk;
			break;
		case XFS_DIR2_LEAFN_MAGIC:
			error = xfs_dir2_leafn_split(state, oldblk, newblk);
			if (error)
				return error;
			addblk = newblk;
			break;
		case XFS_DA_NODE_MAGIC:
			error = xfs_da3_node_split(state, oldblk, newblk, addblk,
							 max - i, &action);
			addblk->bp = NULL;
			if (error)
				return error;	/* GROT: dir is inconsistent */
			/*
			 * Record the newly split block for the next time thru?
			 */
			if (action)
				addblk = newblk;
			else
				addblk = NULL;
			break;
		}

		/*
		 * Update the btree to show the new hashval for this child.
		 */
		xfs_da3_fixhashpath(state, &state->path);
	}
	if (!addblk)
		return 0;

	/*
	 * xfs_da3_node_split() should have consumed any extra blocks we added
	 * during a double leaf split in the attr fork. This is guaranteed as
	 * we can't be here if the attr fork only has a single leaf block.
	 */
	ASSERT(state->extravalid == 0 ||
	       state->path.blk[max].magic == XFS_DIR2_LEAFN_MAGIC);

	/*
	 * Split the root node.
	 */
	ASSERT(state->path.active == 0);
	oldblk = &state->path.blk[0];
	error = xfs_da3_root_split(state, oldblk, addblk);
	if (error)
		goto out;

	/*
	 * Update pointers to the node which used to be block 0 and just got
	 * bumped because of the addition of a new root node.  Note that the
	 * original block 0 could be at any position in the list of blocks in
	 * the tree.
	 *
	 * Note: the magic numbers and sibling pointers are in the same physical
	 * place for both v2 and v3 headers (by design). Hence it doesn't matter
	 * which version of the xfs_da_intnode structure we use here as the
	 * result will be the same using either structure.
	 */
	node = oldblk->bp->b_addr;
	if (node->hdr.info.forw) {
		if (be32_to_cpu(node->hdr.info.forw) != addblk->blkno) {
			xfs_buf_mark_corrupt(oldblk->bp);
			xfs_da_mark_sick(state->args);
			error = -EFSCORRUPTED;
			goto out;
		}
		node = addblk->bp->b_addr;
		node->hdr.info.back = cpu_to_be32(oldblk->blkno);
		xfs_trans_log_buf(state->args->trans, addblk->bp,
				  XFS_DA_LOGRANGE(node, &node->hdr.info,
				  sizeof(node->hdr.info)));
	}
	node = oldblk->bp->b_addr;
	if (node->hdr.info.back) {
		if (be32_to_cpu(node->hdr.info.back) != addblk->blkno) {
			xfs_buf_mark_corrupt(oldblk->bp);
			xfs_da_mark_sick(state->args);
			error = -EFSCORRUPTED;
			goto out;
		}
		node = addblk->bp->b_addr;
		node->hdr.info.forw = cpu_to_be32(oldblk->blkno);
		xfs_trans_log_buf(state->args->trans, addblk->bp,
				  XFS_DA_LOGRANGE(node, &node->hdr.info,
				  sizeof(node->hdr.info)));
	}
out:
	addblk->bp = NULL;
	return error;
}

/*
 * Split the root.  We have to create a new root and point to the two
 * parts (the split old root) that we just created.  Copy block zero to
 * the EOF, extending the inode in process.
 */
STATIC int						/* error */
xfs_da3_root_split(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*blk1,
	struct xfs_da_state_blk	*blk2)
{
	struct xfs_da_intnode	*node;
	struct xfs_da_intnode	*oldroot;
	struct xfs_da_node_entry *btree;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_da_args	*args;
	struct xfs_buf		*bp;
	struct xfs_inode	*dp;
	struct xfs_trans	*tp;
	struct xfs_dir2_leaf	*leaf;
	xfs_dablk_t		blkno;
	int			level;
	int			error;
	int			size;

	trace_xfs_da_root_split(state->args);

	/*
	 * Copy the existing (incorrect) block from the root node position
	 * to a free space somewhere.
	 */
	args = state->args;
	error = xfs_da_grow_inode(args, &blkno);
	if (error)
		return error;

	dp = args->dp;
	tp = args->trans;
	error = xfs_da_get_buf(tp, dp, blkno, &bp, args->whichfork);
	if (error)
		return error;
	node = bp->b_addr;
	oldroot = blk1->bp->b_addr;
	if (oldroot->hdr.info.magic == cpu_to_be16(XFS_DA_NODE_MAGIC) ||
	    oldroot->hdr.info.magic == cpu_to_be16(XFS_DA3_NODE_MAGIC)) {
		struct xfs_da3_icnode_hdr icnodehdr;

		xfs_da3_node_hdr_from_disk(dp->i_mount, &icnodehdr, oldroot);
		btree = icnodehdr.btree;
		size = (int)((char *)&btree[icnodehdr.count] - (char *)oldroot);
		level = icnodehdr.level;
	} else {
		struct xfs_dir3_icleaf_hdr leafhdr;

		leaf = (xfs_dir2_leaf_t *)oldroot;
		xfs_dir2_leaf_hdr_from_disk(dp->i_mount, &leafhdr, leaf);

		ASSERT(leafhdr.magic == XFS_DIR2_LEAFN_MAGIC ||
		       leafhdr.magic == XFS_DIR3_LEAFN_MAGIC);
		size = (int)((char *)&leafhdr.ents[leafhdr.count] -
			(char *)leaf);
		level = 0;
	}

	/*
	 * Copy old root to new buffer and log it.
	 */
	xfs_da_buf_copy(bp, blk1->bp, size);
	xfs_trans_log_buf(tp, bp, 0, size - 1);

	/*
	 * Update blk1 to point to new buffer.
	 */
	blk1->bp = bp;
	blk1->blkno = blkno;

	/*
	 * Set up the new root node.
	 */
	error = xfs_da3_node_create(args,
		(args->whichfork == XFS_DATA_FORK) ? args->geo->leafblk : 0,
		level + 1, &bp, args->whichfork);
	if (error)
		return error;

	node = bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
	btree = nodehdr.btree;
	btree[0].hashval = cpu_to_be32(blk1->hashval);
	btree[0].before = cpu_to_be32(blk1->blkno);
	btree[1].hashval = cpu_to_be32(blk2->hashval);
	btree[1].before = cpu_to_be32(blk2->blkno);
	nodehdr.count = 2;
	xfs_da3_node_hdr_to_disk(dp->i_mount, node, &nodehdr);

#ifdef DEBUG
	if (oldroot->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
	    oldroot->hdr.info.magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC)) {
		ASSERT(blk1->blkno >= args->geo->leafblk &&
		       blk1->blkno < args->geo->freeblk);
		ASSERT(blk2->blkno >= args->geo->leafblk &&
		       blk2->blkno < args->geo->freeblk);
	}
#endif

	/* Header is already logged by xfs_da_node_create */
	xfs_trans_log_buf(tp, bp,
		XFS_DA_LOGRANGE(node, btree, sizeof(xfs_da_node_entry_t) * 2));

	return 0;
}

/*
 * Split the node, rebalance, then add the new entry.
 */
STATIC int						/* error */
xfs_da3_node_split(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*oldblk,
	struct xfs_da_state_blk	*newblk,
	struct xfs_da_state_blk	*addblk,
	int			treelevel,
	int			*result)
{
	struct xfs_da_intnode	*node;
	struct xfs_da3_icnode_hdr nodehdr;
	xfs_dablk_t		blkno;
	int			newcount;
	int			error;
	int			useextra;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_split(state->args);

	node = oldblk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);

	/*
	 * With V2 dirs the extra block is data or freespace.
	 */
	useextra = state->extravalid && state->args->whichfork == XFS_ATTR_FORK;
	newcount = 1 + useextra;
	/*
	 * Do we have to split the node?
	 */
	if (nodehdr.count + newcount > state->args->geo->node_ents) {
		/*
		 * Allocate a new node, add to the doubly linked chain of
		 * nodes, then move some of our excess entries into it.
		 */
		error = xfs_da_grow_inode(state->args, &blkno);
		if (error)
			return error;	/* GROT: dir is inconsistent */

		error = xfs_da3_node_create(state->args, blkno, treelevel,
					   &newblk->bp, state->args->whichfork);
		if (error)
			return error;	/* GROT: dir is inconsistent */
		newblk->blkno = blkno;
		newblk->magic = XFS_DA_NODE_MAGIC;
		xfs_da3_node_rebalance(state, oldblk, newblk);
		error = xfs_da3_blk_link(state, oldblk, newblk);
		if (error)
			return error;
		*result = 1;
	} else {
		*result = 0;
	}

	/*
	 * Insert the new entry(s) into the correct block
	 * (updating last hashval in the process).
	 *
	 * xfs_da3_node_add() inserts BEFORE the given index,
	 * and as a result of using node_lookup_int() we always
	 * point to a valid entry (not after one), but a split
	 * operation always results in a new block whose hashvals
	 * FOLLOW the current block.
	 *
	 * If we had double-split op below us, then add the extra block too.
	 */
	node = oldblk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
	if (oldblk->index <= nodehdr.count) {
		oldblk->index++;
		xfs_da3_node_add(state, oldblk, addblk);
		if (useextra) {
			if (state->extraafter)
				oldblk->index++;
			xfs_da3_node_add(state, oldblk, &state->extrablk);
			state->extravalid = 0;
		}
	} else {
		newblk->index++;
		xfs_da3_node_add(state, newblk, addblk);
		if (useextra) {
			if (state->extraafter)
				newblk->index++;
			xfs_da3_node_add(state, newblk, &state->extrablk);
			state->extravalid = 0;
		}
	}

	return 0;
}

/*
 * Balance the btree elements between two intermediate nodes,
 * usually one full and one empty.
 *
 * NOTE: if blk2 is empty, then it will get the upper half of blk1.
 */
STATIC void
xfs_da3_node_rebalance(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*blk1,
	struct xfs_da_state_blk	*blk2)
{
	struct xfs_da_intnode	*node1;
	struct xfs_da_intnode	*node2;
	struct xfs_da_node_entry *btree1;
	struct xfs_da_node_entry *btree2;
	struct xfs_da_node_entry *btree_s;
	struct xfs_da_node_entry *btree_d;
	struct xfs_da3_icnode_hdr nodehdr1;
	struct xfs_da3_icnode_hdr nodehdr2;
	struct xfs_trans	*tp;
	int			count;
	int			tmp;
	int			swap = 0;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_rebalance(state->args);

	node1 = blk1->bp->b_addr;
	node2 = blk2->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr1, node1);
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr2, node2);
	btree1 = nodehdr1.btree;
	btree2 = nodehdr2.btree;

	/*
	 * Figure out how many entries need to move, and in which direction.
	 * Swap the nodes around if that makes it simpler.
	 */
	if (nodehdr1.count > 0 && nodehdr2.count > 0 &&
	    ((be32_to_cpu(btree2[0].hashval) < be32_to_cpu(btree1[0].hashval)) ||
	     (be32_to_cpu(btree2[nodehdr2.count - 1].hashval) <
			be32_to_cpu(btree1[nodehdr1.count - 1].hashval)))) {
		swap(node1, node2);
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr1, node1);
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr2, node2);
		btree1 = nodehdr1.btree;
		btree2 = nodehdr2.btree;
		swap = 1;
	}

	count = (nodehdr1.count - nodehdr2.count) / 2;
	if (count == 0)
		return;
	tp = state->args->trans;
	/*
	 * Two cases: high-to-low and low-to-high.
	 */
	if (count > 0) {
		/*
		 * Move elements in node2 up to make a hole.
		 */
		tmp = nodehdr2.count;
		if (tmp > 0) {
			tmp *= (uint)sizeof(xfs_da_node_entry_t);
			btree_s = &btree2[0];
			btree_d = &btree2[count];
			memmove(btree_d, btree_s, tmp);
		}

		/*
		 * Move the req'd B-tree elements from high in node1 to
		 * low in node2.
		 */
		nodehdr2.count += count;
		tmp = count * (uint)sizeof(xfs_da_node_entry_t);
		btree_s = &btree1[nodehdr1.count - count];
		btree_d = &btree2[0];
		memcpy(btree_d, btree_s, tmp);
		nodehdr1.count -= count;
	} else {
		/*
		 * Move the req'd B-tree elements from low in node2 to
		 * high in node1.
		 */
		count = -count;
		tmp = count * (uint)sizeof(xfs_da_node_entry_t);
		btree_s = &btree2[0];
		btree_d = &btree1[nodehdr1.count];
		memcpy(btree_d, btree_s, tmp);
		nodehdr1.count += count;

		xfs_trans_log_buf(tp, blk1->bp,
			XFS_DA_LOGRANGE(node1, btree_d, tmp));

		/*
		 * Move elements in node2 down to fill the hole.
		 */
		tmp  = nodehdr2.count - count;
		tmp *= (uint)sizeof(xfs_da_node_entry_t);
		btree_s = &btree2[count];
		btree_d = &btree2[0];
		memmove(btree_d, btree_s, tmp);
		nodehdr2.count -= count;
	}

	/*
	 * Log header of node 1 and all current bits of node 2.
	 */
	xfs_da3_node_hdr_to_disk(dp->i_mount, node1, &nodehdr1);
	xfs_trans_log_buf(tp, blk1->bp,
		XFS_DA_LOGRANGE(node1, &node1->hdr,
				state->args->geo->node_hdr_size));

	xfs_da3_node_hdr_to_disk(dp->i_mount, node2, &nodehdr2);
	xfs_trans_log_buf(tp, blk2->bp,
		XFS_DA_LOGRANGE(node2, &node2->hdr,
				state->args->geo->node_hdr_size +
				(sizeof(btree2[0]) * nodehdr2.count)));

	/*
	 * Record the last hashval from each block for upward propagation.
	 * (note: don't use the swapped node pointers)
	 */
	if (swap) {
		node1 = blk1->bp->b_addr;
		node2 = blk2->bp->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr1, node1);
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr2, node2);
		btree1 = nodehdr1.btree;
		btree2 = nodehdr2.btree;
	}
	blk1->hashval = be32_to_cpu(btree1[nodehdr1.count - 1].hashval);
	blk2->hashval = be32_to_cpu(btree2[nodehdr2.count - 1].hashval);

	/*
	 * Adjust the expected index for insertion.
	 */
	if (blk1->index >= nodehdr1.count) {
		blk2->index = blk1->index - nodehdr1.count;
		blk1->index = nodehdr1.count + 1;	/* make it invalid */
	}
}

/*
 * Add a new entry to an intermediate node.
 */
STATIC void
xfs_da3_node_add(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*oldblk,
	struct xfs_da_state_blk	*newblk)
{
	struct xfs_da_intnode	*node;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_da_node_entry *btree;
	int			tmp;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_add(state->args);

	node = oldblk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
	btree = nodehdr.btree;

	ASSERT(oldblk->index >= 0 && oldblk->index <= nodehdr.count);
	ASSERT(newblk->blkno != 0);
	if (state->args->whichfork == XFS_DATA_FORK)
		ASSERT(newblk->blkno >= state->args->geo->leafblk &&
		       newblk->blkno < state->args->geo->freeblk);

	/*
	 * We may need to make some room before we insert the new node.
	 */
	tmp = 0;
	if (oldblk->index < nodehdr.count) {
		tmp = (nodehdr.count - oldblk->index) * (uint)sizeof(*btree);
		memmove(&btree[oldblk->index + 1], &btree[oldblk->index], tmp);
	}
	btree[oldblk->index].hashval = cpu_to_be32(newblk->hashval);
	btree[oldblk->index].before = cpu_to_be32(newblk->blkno);
	xfs_trans_log_buf(state->args->trans, oldblk->bp,
		XFS_DA_LOGRANGE(node, &btree[oldblk->index],
				tmp + sizeof(*btree)));

	nodehdr.count += 1;
	xfs_da3_node_hdr_to_disk(dp->i_mount, node, &nodehdr);
	xfs_trans_log_buf(state->args->trans, oldblk->bp,
		XFS_DA_LOGRANGE(node, &node->hdr,
				state->args->geo->node_hdr_size));

	/*
	 * Copy the last hash value from the oldblk to propagate upwards.
	 */
	oldblk->hashval = be32_to_cpu(btree[nodehdr.count - 1].hashval);
}

/*========================================================================
 * Routines used for shrinking the Btree.
 *========================================================================*/

/*
 * Deallocate an empty leaf node, remove it from its parent,
 * possibly deallocating that block, etc...
 */
int
xfs_da3_join(
	struct xfs_da_state	*state)
{
	struct xfs_da_state_blk	*drop_blk;
	struct xfs_da_state_blk	*save_blk;
	int			action = 0;
	int			error;

	trace_xfs_da_join(state->args);

	drop_blk = &state->path.blk[ state->path.active-1 ];
	save_blk = &state->altpath.blk[ state->path.active-1 ];
	ASSERT(state->path.blk[0].magic == XFS_DA_NODE_MAGIC);
	ASSERT(drop_blk->magic == XFS_ATTR_LEAF_MAGIC ||
	       drop_blk->magic == XFS_DIR2_LEAFN_MAGIC);

	/*
	 * Walk back up the tree joining/deallocating as necessary.
	 * When we stop dropping blocks, break out.
	 */
	for (  ; state->path.active >= 2; drop_blk--, save_blk--,
		 state->path.active--) {
		/*
		 * See if we can combine the block with a neighbor.
		 *   (action == 0) => no options, just leave
		 *   (action == 1) => coalesce, then unlink
		 *   (action == 2) => block empty, unlink it
		 */
		switch (drop_blk->magic) {
		case XFS_ATTR_LEAF_MAGIC:
			error = xfs_attr3_leaf_toosmall(state, &action);
			if (error)
				return error;
			if (action == 0)
				return 0;
			xfs_attr3_leaf_unbalance(state, drop_blk, save_blk);
			break;
		case XFS_DIR2_LEAFN_MAGIC:
			error = xfs_dir2_leafn_toosmall(state, &action);
			if (error)
				return error;
			if (action == 0)
				return 0;
			xfs_dir2_leafn_unbalance(state, drop_blk, save_blk);
			break;
		case XFS_DA_NODE_MAGIC:
			/*
			 * Remove the offending node, fixup hashvals,
			 * check for a toosmall neighbor.
			 */
			xfs_da3_node_remove(state, drop_blk);
			xfs_da3_fixhashpath(state, &state->path);
			error = xfs_da3_node_toosmall(state, &action);
			if (error)
				return error;
			if (action == 0)
				return 0;
			xfs_da3_node_unbalance(state, drop_blk, save_blk);
			break;
		}
		xfs_da3_fixhashpath(state, &state->altpath);
		error = xfs_da3_blk_unlink(state, drop_blk, save_blk);
		xfs_da_state_kill_altpath(state);
		if (error)
			return error;
		error = xfs_da_shrink_inode(state->args, drop_blk->blkno,
							 drop_blk->bp);
		drop_blk->bp = NULL;
		if (error)
			return error;
	}
	/*
	 * We joined all the way to the top.  If it turns out that
	 * we only have one entry in the root, make the child block
	 * the new root.
	 */
	xfs_da3_node_remove(state, drop_blk);
	xfs_da3_fixhashpath(state, &state->path);
	error = xfs_da3_root_join(state, &state->path.blk[0]);
	return error;
}

#ifdef	DEBUG
static void
xfs_da_blkinfo_onlychild_validate(struct xfs_da_blkinfo *blkinfo, __u16 level)
{
	__be16	magic = blkinfo->magic;

	if (level == 1) {
		ASSERT(magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
		       magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC) ||
		       magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC) ||
		       magic == cpu_to_be16(XFS_ATTR3_LEAF_MAGIC));
	} else {
		ASSERT(magic == cpu_to_be16(XFS_DA_NODE_MAGIC) ||
		       magic == cpu_to_be16(XFS_DA3_NODE_MAGIC));
	}
	ASSERT(!blkinfo->forw);
	ASSERT(!blkinfo->back);
}
#else	/* !DEBUG */
#define	xfs_da_blkinfo_onlychild_validate(blkinfo, level)
#endif	/* !DEBUG */

/*
 * We have only one entry in the root.  Copy the only remaining child of
 * the old root to block 0 as the new root node.
 */
STATIC int
xfs_da3_root_join(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*root_blk)
{
	struct xfs_da_intnode	*oldroot;
	struct xfs_da_args	*args;
	xfs_dablk_t		child;
	struct xfs_buf		*bp;
	struct xfs_da3_icnode_hdr oldroothdr;
	int			error;
	struct xfs_inode	*dp = state->args->dp;
	xfs_failaddr_t		fa;

	trace_xfs_da_root_join(state->args);

	ASSERT(root_blk->magic == XFS_DA_NODE_MAGIC);

	args = state->args;
	oldroot = root_blk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &oldroothdr, oldroot);
	ASSERT(oldroothdr.forw == 0);
	ASSERT(oldroothdr.back == 0);

	/*
	 * If the root has more than one child, then don't do anything.
	 */
	if (oldroothdr.count > 1)
		return 0;

	/*
	 * Read in the (only) child block, then copy those bytes into
	 * the root block's buffer and free the original child block.
	 */
	child = be32_to_cpu(oldroothdr.btree[0].before);
	ASSERT(child != 0);
	error = xfs_da3_node_read(args->trans, dp, child, &bp, args->whichfork);
	if (error)
		return error;
	fa = xfs_da3_header_check(bp, args->owner);
	if (fa) {
		__xfs_buf_mark_corrupt(bp, fa);
		xfs_trans_brelse(args->trans, bp);
		xfs_da_mark_sick(args);
		return -EFSCORRUPTED;
	}
	xfs_da_blkinfo_onlychild_validate(bp->b_addr, oldroothdr.level);

	/*
	 * Copy child to root buffer and log it.
	 */
	xfs_da_buf_copy(root_blk->bp, bp, args->geo->blksize);
	xfs_trans_log_buf(args->trans, root_blk->bp, 0,
			  args->geo->blksize - 1);
	/*
	 * Now we can drop the child buffer.
	 */
	error = xfs_da_shrink_inode(args, child, bp);
	return error;
}

/*
 * Check a node block and its neighbors to see if the block should be
 * collapsed into one or the other neighbor.  Always keep the block
 * with the smaller block number.
 * If the current block is over 50% full, don't try to join it, return 0.
 * If the block is empty, fill in the state structure and return 2.
 * If it can be collapsed, fill in the state structure and return 1.
 * If nothing can be done, return 0.
 */
STATIC int
xfs_da3_node_toosmall(
	struct xfs_da_state	*state,
	int			*action)
{
	struct xfs_da_intnode	*node;
	struct xfs_da_state_blk	*blk;
	struct xfs_da_blkinfo	*info;
	xfs_dablk_t		blkno;
	struct xfs_buf		*bp;
	xfs_failaddr_t		fa;
	struct xfs_da3_icnode_hdr nodehdr;
	int			count;
	int			forward;
	int			error;
	int			retval;
	int			i;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_toosmall(state->args);

	/*
	 * Check for the degenerate case of the block being over 50% full.
	 * If so, it's not worth even looking to see if we might be able
	 * to coalesce with a sibling.
	 */
	blk = &state->path.blk[ state->path.active-1 ];
	info = blk->bp->b_addr;
	node = (xfs_da_intnode_t *)info;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
	if (nodehdr.count > (state->args->geo->node_ents >> 1)) {
		*action = 0;	/* blk over 50%, don't try to join */
		return 0;	/* blk over 50%, don't try to join */
	}

	/*
	 * Check for the degenerate case of the block being empty.
	 * If the block is empty, we'll simply delete it, no need to
	 * coalesce it with a sibling block.  We choose (arbitrarily)
	 * to merge with the forward block unless it is NULL.
	 */
	if (nodehdr.count == 0) {
		/*
		 * Make altpath point to the block we want to keep and
		 * path point to the block we want to drop (this one).
		 */
		forward = (info->forw != 0);
		memcpy(&state->altpath, &state->path, sizeof(state->path));
		error = xfs_da3_path_shift(state, &state->altpath, forward,
						 0, &retval);
		if (error)
			return error;
		if (retval) {
			*action = 0;
		} else {
			*action = 2;
		}
		return 0;
	}

	/*
	 * Examine each sibling block to see if we can coalesce with
	 * at least 25% free space to spare.  We need to figure out
	 * whether to merge with the forward or the backward block.
	 * We prefer coalescing with the lower numbered sibling so as
	 * to shrink a directory over time.
	 */
	count  = state->args->geo->node_ents;
	count -= state->args->geo->node_ents >> 2;
	count -= nodehdr.count;

	/* start with smaller blk num */
	forward = nodehdr.forw < nodehdr.back;
	for (i = 0; i < 2; forward = !forward, i++) {
		struct xfs_da3_icnode_hdr thdr;
		if (forward)
			blkno = nodehdr.forw;
		else
			blkno = nodehdr.back;
		if (blkno == 0)
			continue;
		error = xfs_da3_node_read(state->args->trans, dp, blkno, &bp,
				state->args->whichfork);
		if (error)
			return error;
		fa = xfs_da3_node_header_check(bp, state->args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(bp, fa);
			xfs_trans_brelse(state->args->trans, bp);
			xfs_da_mark_sick(state->args);
			return -EFSCORRUPTED;
		}

		node = bp->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &thdr, node);
		xfs_trans_brelse(state->args->trans, bp);

		if (count - thdr.count >= 0)
			break;	/* fits with at least 25% to spare */
	}
	if (i >= 2) {
		*action = 0;
		return 0;
	}

	/*
	 * Make altpath point to the block we want to keep (the lower
	 * numbered block) and path point to the block we want to drop.
	 */
	memcpy(&state->altpath, &state->path, sizeof(state->path));
	if (blkno < blk->blkno) {
		error = xfs_da3_path_shift(state, &state->altpath, forward,
						 0, &retval);
	} else {
		error = xfs_da3_path_shift(state, &state->path, forward,
						 0, &retval);
	}
	if (error)
		return error;
	if (retval) {
		*action = 0;
		return 0;
	}
	*action = 1;
	return 0;
}

/*
 * Pick up the last hashvalue from an intermediate node.
 */
STATIC uint
xfs_da3_node_lasthash(
	struct xfs_inode	*dp,
	struct xfs_buf		*bp,
	int			*count)
{
	struct xfs_da3_icnode_hdr nodehdr;

	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, bp->b_addr);
	if (count)
		*count = nodehdr.count;
	if (!nodehdr.count)
		return 0;
	return be32_to_cpu(nodehdr.btree[nodehdr.count - 1].hashval);
}

/*
 * Walk back up the tree adjusting hash values as necessary,
 * when we stop making changes, return.
 */
void
xfs_da3_fixhashpath(
	struct xfs_da_state	*state,
	struct xfs_da_state_path *path)
{
	struct xfs_da_state_blk	*blk;
	struct xfs_da_intnode	*node;
	struct xfs_da_node_entry *btree;
	xfs_dahash_t		lasthash=0;
	int			level;
	int			count;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_fixhashpath(state->args);

	level = path->active-1;
	blk = &path->blk[ level ];
	switch (blk->magic) {
	case XFS_ATTR_LEAF_MAGIC:
		lasthash = xfs_attr_leaf_lasthash(blk->bp, &count);
		if (count == 0)
			return;
		break;
	case XFS_DIR2_LEAFN_MAGIC:
		lasthash = xfs_dir2_leaf_lasthash(dp, blk->bp, &count);
		if (count == 0)
			return;
		break;
	case XFS_DA_NODE_MAGIC:
		lasthash = xfs_da3_node_lasthash(dp, blk->bp, &count);
		if (count == 0)
			return;
		break;
	}
	for (blk--, level--; level >= 0; blk--, level--) {
		struct xfs_da3_icnode_hdr nodehdr;

		node = blk->bp->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
		btree = nodehdr.btree;
		if (be32_to_cpu(btree[blk->index].hashval) == lasthash)
			break;
		blk->hashval = lasthash;
		btree[blk->index].hashval = cpu_to_be32(lasthash);
		xfs_trans_log_buf(state->args->trans, blk->bp,
				  XFS_DA_LOGRANGE(node, &btree[blk->index],
						  sizeof(*btree)));

		lasthash = be32_to_cpu(btree[nodehdr.count - 1].hashval);
	}
}

/*
 * Remove an entry from an intermediate node.
 */
STATIC void
xfs_da3_node_remove(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*drop_blk)
{
	struct xfs_da_intnode	*node;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_da_node_entry *btree;
	int			index;
	int			tmp;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_remove(state->args);

	node = drop_blk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
	ASSERT(drop_blk->index < nodehdr.count);
	ASSERT(drop_blk->index >= 0);

	/*
	 * Copy over the offending entry, or just zero it out.
	 */
	index = drop_blk->index;
	btree = nodehdr.btree;
	if (index < nodehdr.count - 1) {
		tmp  = nodehdr.count - index - 1;
		tmp *= (uint)sizeof(xfs_da_node_entry_t);
		memmove(&btree[index], &btree[index + 1], tmp);
		xfs_trans_log_buf(state->args->trans, drop_blk->bp,
		    XFS_DA_LOGRANGE(node, &btree[index], tmp));
		index = nodehdr.count - 1;
	}
	memset(&btree[index], 0, sizeof(xfs_da_node_entry_t));
	xfs_trans_log_buf(state->args->trans, drop_blk->bp,
	    XFS_DA_LOGRANGE(node, &btree[index], sizeof(btree[index])));
	nodehdr.count -= 1;
	xfs_da3_node_hdr_to_disk(dp->i_mount, node, &nodehdr);
	xfs_trans_log_buf(state->args->trans, drop_blk->bp,
	    XFS_DA_LOGRANGE(node, &node->hdr, state->args->geo->node_hdr_size));

	/*
	 * Copy the last hash value from the block to propagate upwards.
	 */
	drop_blk->hashval = be32_to_cpu(btree[index - 1].hashval);
}

/*
 * Unbalance the elements between two intermediate nodes,
 * move all Btree elements from one node into another.
 */
STATIC void
xfs_da3_node_unbalance(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*drop_blk,
	struct xfs_da_state_blk	*save_blk)
{
	struct xfs_da_intnode	*drop_node;
	struct xfs_da_intnode	*save_node;
	struct xfs_da_node_entry *drop_btree;
	struct xfs_da_node_entry *save_btree;
	struct xfs_da3_icnode_hdr drop_hdr;
	struct xfs_da3_icnode_hdr save_hdr;
	struct xfs_trans	*tp;
	int			sindex;
	int			tmp;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_node_unbalance(state->args);

	drop_node = drop_blk->bp->b_addr;
	save_node = save_blk->bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &drop_hdr, drop_node);
	xfs_da3_node_hdr_from_disk(dp->i_mount, &save_hdr, save_node);
	drop_btree = drop_hdr.btree;
	save_btree = save_hdr.btree;
	tp = state->args->trans;

	/*
	 * If the dying block has lower hashvals, then move all the
	 * elements in the remaining block up to make a hole.
	 */
	if ((be32_to_cpu(drop_btree[0].hashval) <
			be32_to_cpu(save_btree[0].hashval)) ||
	    (be32_to_cpu(drop_btree[drop_hdr.count - 1].hashval) <
			be32_to_cpu(save_btree[save_hdr.count - 1].hashval))) {
		/* XXX: check this - is memmove dst correct? */
		tmp = save_hdr.count * sizeof(xfs_da_node_entry_t);
		memmove(&save_btree[drop_hdr.count], &save_btree[0], tmp);

		sindex = 0;
		xfs_trans_log_buf(tp, save_blk->bp,
			XFS_DA_LOGRANGE(save_node, &save_btree[0],
				(save_hdr.count + drop_hdr.count) *
						sizeof(xfs_da_node_entry_t)));
	} else {
		sindex = save_hdr.count;
		xfs_trans_log_buf(tp, save_blk->bp,
			XFS_DA_LOGRANGE(save_node, &save_btree[sindex],
				drop_hdr.count * sizeof(xfs_da_node_entry_t)));
	}

	/*
	 * Move all the B-tree elements from drop_blk to save_blk.
	 */
	tmp = drop_hdr.count * (uint)sizeof(xfs_da_node_entry_t);
	memcpy(&save_btree[sindex], &drop_btree[0], tmp);
	save_hdr.count += drop_hdr.count;

	xfs_da3_node_hdr_to_disk(dp->i_mount, save_node, &save_hdr);
	xfs_trans_log_buf(tp, save_blk->bp,
		XFS_DA_LOGRANGE(save_node, &save_node->hdr,
				state->args->geo->node_hdr_size));

	/*
	 * Save the last hashval in the remaining block for upward propagation.
	 */
	save_blk->hashval = be32_to_cpu(save_btree[save_hdr.count - 1].hashval);
}

/*========================================================================
 * Routines used for finding things in the Btree.
 *========================================================================*/

/*
 * Walk down the Btree looking for a particular filename, filling
 * in the state structure as we go.
 *
 * We will set the state structure to point to each of the elements
 * in each of the nodes where either the hashval is or should be.
 *
 * We support duplicate hashval's so for each entry in the current
 * node that could contain the desired hashval, descend.  This is a
 * pruned depth-first tree search.
 */
int							/* error */
xfs_da3_node_lookup_int(
	struct xfs_da_state	*state,
	int			*result)
{
	struct xfs_da_state_blk	*blk;
	struct xfs_da_blkinfo	*curr;
	struct xfs_da_intnode	*node;
	struct xfs_da_node_entry *btree;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_da_args	*args;
	xfs_failaddr_t		fa;
	xfs_dablk_t		blkno;
	xfs_dahash_t		hashval;
	xfs_dahash_t		btreehashval;
	int			probe;
	int			span;
	int			max;
	int			error;
	int			retval;
	unsigned int		expected_level = 0;
	uint16_t		magic;
	struct xfs_inode	*dp = state->args->dp;

	args = state->args;

	/*
	 * Descend thru the B-tree searching each level for the right
	 * node to use, until the right hashval is found.
	 */
	blkno = args->geo->leafblk;
	for (blk = &state->path.blk[0], state->path.active = 1;
			 state->path.active <= XFS_DA_NODE_MAXDEPTH;
			 blk++, state->path.active++) {
		/*
		 * Read the next node down in the tree.
		 */
		blk->blkno = blkno;
		error = xfs_da3_node_read(args->trans, args->dp, blkno,
					&blk->bp, args->whichfork);
		if (error) {
			blk->blkno = 0;
			state->path.active--;
			return error;
		}
		curr = blk->bp->b_addr;
		magic = be16_to_cpu(curr->magic);

		if (magic == XFS_ATTR_LEAF_MAGIC ||
		    magic == XFS_ATTR3_LEAF_MAGIC) {
			fa = xfs_attr3_leaf_header_check(blk->bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(blk->bp, fa);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			blk->magic = XFS_ATTR_LEAF_MAGIC;
			blk->hashval = xfs_attr_leaf_lasthash(blk->bp, NULL);
			break;
		}

		if (magic == XFS_DIR2_LEAFN_MAGIC ||
		    magic == XFS_DIR3_LEAFN_MAGIC) {
			fa = xfs_dir3_leaf_header_check(blk->bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(blk->bp, fa);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			blk->magic = XFS_DIR2_LEAFN_MAGIC;
			blk->hashval = xfs_dir2_leaf_lasthash(args->dp,
							      blk->bp, NULL);
			break;
		}

		if (magic != XFS_DA_NODE_MAGIC && magic != XFS_DA3_NODE_MAGIC) {
			xfs_buf_mark_corrupt(blk->bp);
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		}

		fa = xfs_da3_node_header_check(blk->bp, args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(blk->bp, fa);
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		}

		blk->magic = XFS_DA_NODE_MAGIC;

		/*
		 * Search an intermediate node for a match.
		 */
		node = blk->bp->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr, node);
		btree = nodehdr.btree;

		/* Tree taller than we can handle; bail out! */
		if (nodehdr.level >= XFS_DA_NODE_MAXDEPTH) {
			xfs_buf_mark_corrupt(blk->bp);
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		}

		/* Check the level from the root. */
		if (blkno == args->geo->leafblk)
			expected_level = nodehdr.level - 1;
		else if (expected_level != nodehdr.level) {
			xfs_buf_mark_corrupt(blk->bp);
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		} else
			expected_level--;

		max = nodehdr.count;
		blk->hashval = be32_to_cpu(btree[max - 1].hashval);

		/*
		 * Binary search.  (note: small blocks will skip loop)
		 */
		probe = span = max / 2;
		hashval = args->hashval;
		while (span > 4) {
			span /= 2;
			btreehashval = be32_to_cpu(btree[probe].hashval);
			if (btreehashval < hashval)
				probe += span;
			else if (btreehashval > hashval)
				probe -= span;
			else
				break;
		}
		ASSERT((probe >= 0) && (probe < max));
		ASSERT((span <= 4) ||
			(be32_to_cpu(btree[probe].hashval) == hashval));

		/*
		 * Since we may have duplicate hashval's, find the first
		 * matching hashval in the node.
		 */
		while (probe > 0 &&
		       be32_to_cpu(btree[probe].hashval) >= hashval) {
			probe--;
		}
		while (probe < max &&
		       be32_to_cpu(btree[probe].hashval) < hashval) {
			probe++;
		}

		/*
		 * Pick the right block to descend on.
		 */
		if (probe == max) {
			blk->index = max - 1;
			blkno = be32_to_cpu(btree[max - 1].before);
		} else {
			blk->index = probe;
			blkno = be32_to_cpu(btree[probe].before);
		}

		/* We can't point back to the root. */
		if (XFS_IS_CORRUPT(dp->i_mount, blkno == args->geo->leafblk)) {
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		}
	}

	if (XFS_IS_CORRUPT(dp->i_mount, expected_level != 0)) {
		xfs_da_mark_sick(args);
		return -EFSCORRUPTED;
	}

	/*
	 * A leaf block that ends in the hashval that we are interested in
	 * (final hashval == search hashval) means that the next block may
	 * contain more entries with the same hashval, shift upward to the
	 * next leaf and keep searching.
	 */
	for (;;) {
		if (blk->magic == XFS_DIR2_LEAFN_MAGIC) {
			retval = xfs_dir2_leafn_lookup_int(blk->bp, args,
							&blk->index, state);
		} else if (blk->magic == XFS_ATTR_LEAF_MAGIC) {
			retval = xfs_attr3_leaf_lookup_int(blk->bp, args);
			blk->index = args->index;
			args->blkno = blk->blkno;
		} else {
			ASSERT(0);
			xfs_da_mark_sick(args);
			return -EFSCORRUPTED;
		}
		if (((retval == -ENOENT) || (retval == -ENOATTR)) &&
		    (blk->hashval == args->hashval)) {
			error = xfs_da3_path_shift(state, &state->path, 1, 1,
							 &retval);
			if (error)
				return error;
			if (retval == 0) {
				continue;
			} else if (blk->magic == XFS_ATTR_LEAF_MAGIC) {
				/* path_shift() gives ENOENT */
				retval = -ENOATTR;
			}
		}
		break;
	}
	*result = retval;
	return 0;
}

/*========================================================================
 * Utility routines.
 *========================================================================*/

/*
 * Compare two intermediate nodes for "order".
 */
STATIC int
xfs_da3_node_order(
	struct xfs_inode *dp,
	struct xfs_buf	*node1_bp,
	struct xfs_buf	*node2_bp)
{
	struct xfs_da_intnode	*node1;
	struct xfs_da_intnode	*node2;
	struct xfs_da_node_entry *btree1;
	struct xfs_da_node_entry *btree2;
	struct xfs_da3_icnode_hdr node1hdr;
	struct xfs_da3_icnode_hdr node2hdr;

	node1 = node1_bp->b_addr;
	node2 = node2_bp->b_addr;
	xfs_da3_node_hdr_from_disk(dp->i_mount, &node1hdr, node1);
	xfs_da3_node_hdr_from_disk(dp->i_mount, &node2hdr, node2);
	btree1 = node1hdr.btree;
	btree2 = node2hdr.btree;

	if (node1hdr.count > 0 && node2hdr.count > 0 &&
	    ((be32_to_cpu(btree2[0].hashval) < be32_to_cpu(btree1[0].hashval)) ||
	     (be32_to_cpu(btree2[node2hdr.count - 1].hashval) <
	      be32_to_cpu(btree1[node1hdr.count - 1].hashval)))) {
		return 1;
	}
	return 0;
}

/*
 * Link a new block into a doubly linked list of blocks (of whatever type).
 */
int							/* error */
xfs_da3_blk_link(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*old_blk,
	struct xfs_da_state_blk	*new_blk)
{
	struct xfs_da_blkinfo	*old_info;
	struct xfs_da_blkinfo	*new_info;
	struct xfs_da_blkinfo	*tmp_info;
	struct xfs_da_args	*args;
	struct xfs_buf		*bp;
	xfs_failaddr_t		fa;
	int			before = 0;
	int			error;
	struct xfs_inode	*dp = state->args->dp;

	/*
	 * Set up environment.
	 */
	args = state->args;
	ASSERT(args != NULL);
	old_info = old_blk->bp->b_addr;
	new_info = new_blk->bp->b_addr;
	ASSERT(old_blk->magic == XFS_DA_NODE_MAGIC ||
	       old_blk->magic == XFS_DIR2_LEAFN_MAGIC ||
	       old_blk->magic == XFS_ATTR_LEAF_MAGIC);

	switch (old_blk->magic) {
	case XFS_ATTR_LEAF_MAGIC:
		before = xfs_attr_leaf_order(old_blk->bp, new_blk->bp);
		break;
	case XFS_DIR2_LEAFN_MAGIC:
		before = xfs_dir2_leafn_order(dp, old_blk->bp, new_blk->bp);
		break;
	case XFS_DA_NODE_MAGIC:
		before = xfs_da3_node_order(dp, old_blk->bp, new_blk->bp);
		break;
	}

	/*
	 * Link blocks in appropriate order.
	 */
	if (before) {
		/*
		 * Link new block in before existing block.
		 */
		trace_xfs_da_link_before(args);
		new_info->forw = cpu_to_be32(old_blk->blkno);
		new_info->back = old_info->back;
		if (old_info->back) {
			error = xfs_da3_node_read(args->trans, dp,
						be32_to_cpu(old_info->back),
						&bp, args->whichfork);
			if (error)
				return error;
			fa = xfs_da3_header_check(bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(bp, fa);
				xfs_trans_brelse(args->trans, bp);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			ASSERT(bp != NULL);
			tmp_info = bp->b_addr;
			ASSERT(tmp_info->magic == old_info->magic);
			ASSERT(be32_to_cpu(tmp_info->forw) == old_blk->blkno);
			tmp_info->forw = cpu_to_be32(new_blk->blkno);
			xfs_trans_log_buf(args->trans, bp, 0, sizeof(*tmp_info)-1);
		}
		old_info->back = cpu_to_be32(new_blk->blkno);
	} else {
		/*
		 * Link new block in after existing block.
		 */
		trace_xfs_da_link_after(args);
		new_info->forw = old_info->forw;
		new_info->back = cpu_to_be32(old_blk->blkno);
		if (old_info->forw) {
			error = xfs_da3_node_read(args->trans, dp,
						be32_to_cpu(old_info->forw),
						&bp, args->whichfork);
			if (error)
				return error;
			fa = xfs_da3_header_check(bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(bp, fa);
				xfs_trans_brelse(args->trans, bp);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			ASSERT(bp != NULL);
			tmp_info = bp->b_addr;
			ASSERT(tmp_info->magic == old_info->magic);
			ASSERT(be32_to_cpu(tmp_info->back) == old_blk->blkno);
			tmp_info->back = cpu_to_be32(new_blk->blkno);
			xfs_trans_log_buf(args->trans, bp, 0, sizeof(*tmp_info)-1);
		}
		old_info->forw = cpu_to_be32(new_blk->blkno);
	}

	xfs_trans_log_buf(args->trans, old_blk->bp, 0, sizeof(*tmp_info) - 1);
	xfs_trans_log_buf(args->trans, new_blk->bp, 0, sizeof(*tmp_info) - 1);
	return 0;
}

/*
 * Unlink a block from a doubly linked list of blocks.
 */
STATIC int						/* error */
xfs_da3_blk_unlink(
	struct xfs_da_state	*state,
	struct xfs_da_state_blk	*drop_blk,
	struct xfs_da_state_blk	*save_blk)
{
	struct xfs_da_blkinfo	*drop_info;
	struct xfs_da_blkinfo	*save_info;
	struct xfs_da_blkinfo	*tmp_info;
	struct xfs_da_args	*args;
	struct xfs_buf		*bp;
	xfs_failaddr_t		fa;
	int			error;

	/*
	 * Set up environment.
	 */
	args = state->args;
	ASSERT(args != NULL);
	save_info = save_blk->bp->b_addr;
	drop_info = drop_blk->bp->b_addr;
	ASSERT(save_blk->magic == XFS_DA_NODE_MAGIC ||
	       save_blk->magic == XFS_DIR2_LEAFN_MAGIC ||
	       save_blk->magic == XFS_ATTR_LEAF_MAGIC);
	ASSERT(save_blk->magic == drop_blk->magic);
	ASSERT((be32_to_cpu(save_info->forw) == drop_blk->blkno) ||
	       (be32_to_cpu(save_info->back) == drop_blk->blkno));
	ASSERT((be32_to_cpu(drop_info->forw) == save_blk->blkno) ||
	       (be32_to_cpu(drop_info->back) == save_blk->blkno));

	/*
	 * Unlink the leaf block from the doubly linked chain of leaves.
	 */
	if (be32_to_cpu(save_info->back) == drop_blk->blkno) {
		trace_xfs_da_unlink_back(args);
		save_info->back = drop_info->back;
		if (drop_info->back) {
			error = xfs_da3_node_read(args->trans, args->dp,
						be32_to_cpu(drop_info->back),
						&bp, args->whichfork);
			if (error)
				return error;
			fa = xfs_da3_header_check(bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(bp, fa);
				xfs_trans_brelse(args->trans, bp);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			ASSERT(bp != NULL);
			tmp_info = bp->b_addr;
			ASSERT(tmp_info->magic == save_info->magic);
			ASSERT(be32_to_cpu(tmp_info->forw) == drop_blk->blkno);
			tmp_info->forw = cpu_to_be32(save_blk->blkno);
			xfs_trans_log_buf(args->trans, bp, 0,
						    sizeof(*tmp_info) - 1);
		}
	} else {
		trace_xfs_da_unlink_forward(args);
		save_info->forw = drop_info->forw;
		if (drop_info->forw) {
			error = xfs_da3_node_read(args->trans, args->dp,
						be32_to_cpu(drop_info->forw),
						&bp, args->whichfork);
			if (error)
				return error;
			fa = xfs_da3_header_check(bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(bp, fa);
				xfs_trans_brelse(args->trans, bp);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			ASSERT(bp != NULL);
			tmp_info = bp->b_addr;
			ASSERT(tmp_info->magic == save_info->magic);
			ASSERT(be32_to_cpu(tmp_info->back) == drop_blk->blkno);
			tmp_info->back = cpu_to_be32(save_blk->blkno);
			xfs_trans_log_buf(args->trans, bp, 0,
						    sizeof(*tmp_info) - 1);
		}
	}

	xfs_trans_log_buf(args->trans, save_blk->bp, 0, sizeof(*save_info) - 1);
	return 0;
}

/*
 * Move a path "forward" or "!forward" one block at the current level.
 *
 * This routine will adjust a "path" to point to the next block
 * "forward" (higher hashvalues) or "!forward" (lower hashvals) in the
 * Btree, including updating pointers to the intermediate nodes between
 * the new bottom and the root.
 */
int							/* error */
xfs_da3_path_shift(
	struct xfs_da_state	*state,
	struct xfs_da_state_path *path,
	int			forward,
	int			release,
	int			*result)
{
	struct xfs_da_state_blk	*blk;
	struct xfs_da_blkinfo	*info;
	struct xfs_da_args	*args;
	struct xfs_da_node_entry *btree;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_buf		*bp;
	xfs_failaddr_t		fa;
	xfs_dablk_t		blkno = 0;
	int			level;
	int			error;
	struct xfs_inode	*dp = state->args->dp;

	trace_xfs_da_path_shift(state->args);

	/*
	 * Roll up the Btree looking for the first block where our
	 * current index is not at the edge of the block.  Note that
	 * we skip the bottom layer because we want the sibling block.
	 */
	args = state->args;
	ASSERT(args != NULL);
	ASSERT(path != NULL);
	ASSERT((path->active > 0) && (path->active < XFS_DA_NODE_MAXDEPTH));
	level = (path->active-1) - 1;	/* skip bottom layer in path */
	for (; level >= 0; level--) {
		blk = &path->blk[level];
		xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr,
					   blk->bp->b_addr);

		if (forward && (blk->index < nodehdr.count - 1)) {
			blk->index++;
			blkno = be32_to_cpu(nodehdr.btree[blk->index].before);
			break;
		} else if (!forward && (blk->index > 0)) {
			blk->index--;
			blkno = be32_to_cpu(nodehdr.btree[blk->index].before);
			break;
		}
	}
	if (level < 0) {
		*result = -ENOENT;	/* we're out of our tree */
		ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
		return 0;
	}

	/*
	 * Roll down the edge of the subtree until we reach the
	 * same depth we were at originally.
	 */
	for (blk++, level++; level < path->active; blk++, level++) {
		/*
		 * Read the next child block into a local buffer.
		 */
		error = xfs_da3_node_read(args->trans, dp, blkno, &bp,
					  args->whichfork);
		if (error)
			return error;

		/*
		 * Release the old block (if it's dirty, the trans doesn't
		 * actually let go) and swap the local buffer into the path
		 * structure. This ensures failure of the above read doesn't set
		 * a NULL buffer in an active slot in the path.
		 */
		if (release)
			xfs_trans_brelse(args->trans, blk->bp);
		blk->blkno = blkno;
		blk->bp = bp;

		info = blk->bp->b_addr;
		ASSERT(info->magic == cpu_to_be16(XFS_DA_NODE_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_DA3_NODE_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_ATTR3_LEAF_MAGIC));


		/*
		 * Note: we flatten the magic number to a single type so we
		 * don't have to compare against crc/non-crc types elsewhere.
		 */
		switch (be16_to_cpu(info->magic)) {
		case XFS_DA_NODE_MAGIC:
		case XFS_DA3_NODE_MAGIC:
			fa = xfs_da3_node_header_check(blk->bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(blk->bp, fa);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			blk->magic = XFS_DA_NODE_MAGIC;
			xfs_da3_node_hdr_from_disk(dp->i_mount, &nodehdr,
						   bp->b_addr);
			btree = nodehdr.btree;
			blk->hashval = be32_to_cpu(btree[nodehdr.count - 1].hashval);
			if (forward)
				blk->index = 0;
			else
				blk->index = nodehdr.count - 1;
			blkno = be32_to_cpu(btree[blk->index].before);
			break;
		case XFS_ATTR_LEAF_MAGIC:
		case XFS_ATTR3_LEAF_MAGIC:
			fa = xfs_attr3_leaf_header_check(blk->bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(blk->bp, fa);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			blk->magic = XFS_ATTR_LEAF_MAGIC;
			ASSERT(level == path->active-1);
			blk->index = 0;
			blk->hashval = xfs_attr_leaf_lasthash(blk->bp, NULL);
			break;
		case XFS_DIR2_LEAFN_MAGIC:
		case XFS_DIR3_LEAFN_MAGIC:
			fa = xfs_dir3_leaf_header_check(blk->bp, args->owner);
			if (fa) {
				__xfs_buf_mark_corrupt(blk->bp, fa);
				xfs_da_mark_sick(args);
				return -EFSCORRUPTED;
			}
			blk->magic = XFS_DIR2_LEAFN_MAGIC;
			ASSERT(level == path->active-1);
			blk->index = 0;
			blk->hashval = xfs_dir2_leaf_lasthash(args->dp,
							      blk->bp, NULL);
			break;
		default:
			ASSERT(0);
			break;
		}
	}
	*result = 0;
	return 0;
}


/*========================================================================
 * Utility routines.
 *========================================================================*/

/*
 * Implement a simple hash on a character string.
 * Rotate the hash value by 7 bits, then XOR each character in.
 * This is implemented with some source-level loop unrolling.
 */
xfs_dahash_t
xfs_da_hashname(const uint8_t *name, int namelen)
{
	xfs_dahash_t hash;

	/*
	 * Do four characters at a time as long as we can.
	 */
	for (hash = 0; namelen >= 4; namelen -= 4, name += 4)
		hash = (name[0] << 21) ^ (name[1] << 14) ^ (name[2] << 7) ^
		       (name[3] << 0) ^ rol32(hash, 7 * 4);

	/*
	 * Now do the rest of the characters.
	 */
	switch (namelen) {
	case 3:
		return (name[0] << 14) ^ (name[1] << 7) ^ (name[2] << 0) ^
		       rol32(hash, 7 * 3);
	case 2:
		return (name[0] << 7) ^ (name[1] << 0) ^ rol32(hash, 7 * 2);
	case 1:
		return (name[0] << 0) ^ rol32(hash, 7 * 1);
	default: /* case 0: */
		return hash;
	}
}

enum xfs_dacmp
xfs_da_compname(
	struct xfs_da_args *args,
	const unsigned char *name,
	int		len)
{
	return (args->namelen == len && memcmp(args->name, name, len) == 0) ?
					XFS_CMP_EXACT : XFS_CMP_DIFFERENT;
}

int
xfs_da_grow_inode_int(
	struct xfs_da_args	*args,
	xfs_fileoff_t		*bno,
	int			count)
{
	struct xfs_trans	*tp = args->trans;
	struct xfs_inode	*dp = args->dp;
	int			w = args->whichfork;
	xfs_rfsblock_t		nblks = dp->i_nblocks;
	struct xfs_bmbt_irec	map, *mapp = &map;
	int			nmap, error, got, i, mapi = 1;

	/*
	 * Find a spot in the file space to put the new block.
	 */
	error = xfs_bmap_first_unused(tp, dp, count, bno, w);
	if (error)
		return error;

	/*
	 * Try mapping it in one filesystem block.
	 */
	nmap = 1;
	error = xfs_bmapi_write(tp, dp, *bno, count,
			xfs_bmapi_aflag(w)|XFS_BMAPI_METADATA|XFS_BMAPI_CONTIG,
			args->total, &map, &nmap);
	if (error == -ENOSPC && count > 1) {
		xfs_fileoff_t		b;
		int			c;

		/*
		 * If we didn't get it and the block might work if fragmented,
		 * try without the CONTIG flag.  Loop until we get it all.
		 */
		mapp = kmalloc(sizeof(*mapp) * count,
				GFP_KERNEL | __GFP_NOFAIL);
		for (b = *bno, mapi = 0; b < *bno + count; ) {
			c = (int)(*bno + count - b);
			nmap = min(XFS_BMAP_MAX_NMAP, c);
			error = xfs_bmapi_write(tp, dp, b, c,
					xfs_bmapi_aflag(w)|XFS_BMAPI_METADATA,
					args->total, &mapp[mapi], &nmap);
			if (error)
				goto out_free_map;
			mapi += nmap;
			b = mapp[mapi - 1].br_startoff +
			    mapp[mapi - 1].br_blockcount;
		}
	}
	if (error)
		goto out_free_map;

	/*
	 * Count the blocks we got, make sure it matches the total.
	 */
	for (i = 0, got = 0; i < mapi; i++)
		got += mapp[i].br_blockcount;
	if (got != count || mapp[0].br_startoff != *bno ||
	    mapp[mapi - 1].br_startoff + mapp[mapi - 1].br_blockcount !=
	    *bno + count) {
		error = -ENOSPC;
		goto out_free_map;
	}

	/* account for newly allocated blocks in reserved blocks total */
	args->total -= dp->i_nblocks - nblks;

	/*
	 * sess34 (ccloop 14d31183) P34C DOUBLE-MAP PROBE (RULE 4 step 2):
	 * every dir-space grow logs (startoff -> fsblock).  The orphaned-
	 * block quiet loss (sess33 forensics: committed XDD3 block absent
	 * from the on-disk bmbt) requires TWO nodes mapping the SAME dir
	 * offset to DIFFERENT fsblocks — the loser's block is unlinked from
	 * the map.  xfs_bmap_first_unused above picks *bno from the IN-CORE
	 * extent map; if that map predates a peer's grow, *bno collides.
	 * Cross-node merge of these lines by (ino, startoff) is the proof.
	 */
	{
		extern int mxfs_dirwr_enabled;
		extern int mxfs_instr_enabled;

		if ((mxfs_dirwr_enabled || mxfs_instr_enabled ||
		     dp->i_ino <= 256 /* sess3: shared-dir lineage, always-on */) &&
		    w == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
		    dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			for (i = 0; i < mapi; i++)
				pr_warn("mxfs: P34C-DIRGROW ino=%llu startoff=%llu fsb=0x%llx len=%llu next=%llu size=%lld fmt=%d realns=%llu\n",
					(unsigned long long)dp->i_ino,
					(unsigned long long)mapp[i].br_startoff,
					(unsigned long long)mapp[i].br_startblock,
					(unsigned long long)mapp[i].br_blockcount,
					(unsigned long long)dp->i_df.if_nextents,
					(long long)dp->i_disk_size,
					dp->i_df.if_format,
					(unsigned long long)ktime_get_real_ns());
		}
	}

out_free_map:
	if (mapp != &map)
		kfree(mapp);
	return error;
}

/*
 * Add a block to the btree ahead of the file.
 * Return the new block number to the caller.
 */
int
xfs_da_grow_inode(
	struct xfs_da_args	*args,
	xfs_dablk_t		*new_blkno)
{
	xfs_fileoff_t		bno;
	int			error;

	trace_xfs_da_grow_inode(args);

	bno = args->geo->leafblk;
	error = xfs_da_grow_inode_int(args, &bno, args->geo->fsbcount);
	if (!error)
		*new_blkno = (xfs_dablk_t)bno;
	return error;
}

/*
 * Ick.  We need to always be able to remove a btree block, even
 * if there's no space reservation because the filesystem is full.
 * This is called if xfs_bunmapi on a btree block fails due to ENOSPC.
 * It swaps the target block with the last block in the file.  The
 * last block in the file can always be removed since it can't cause
 * a bmap btree split to do that.
 */
STATIC int
xfs_da3_swap_lastblock(
	struct xfs_da_args	*args,
	xfs_dablk_t		*dead_blknop,
	struct xfs_buf		**dead_bufp)
{
	struct xfs_da_blkinfo	*dead_info;
	struct xfs_da_blkinfo	*sib_info;
	struct xfs_da_intnode	*par_node;
	struct xfs_da_intnode	*dead_node;
	struct xfs_dir2_leaf	*dead_leaf2;
	struct xfs_da_node_entry *btree;
	struct xfs_da3_icnode_hdr par_hdr;
	struct xfs_inode	*dp;
	struct xfs_trans	*tp;
	struct xfs_mount	*mp;
	struct xfs_buf		*dead_buf;
	struct xfs_buf		*last_buf;
	struct xfs_buf		*sib_buf;
	struct xfs_buf		*par_buf;
	xfs_failaddr_t		fa;
	xfs_dahash_t		dead_hash;
	xfs_fileoff_t		lastoff;
	xfs_dablk_t		dead_blkno;
	xfs_dablk_t		last_blkno;
	xfs_dablk_t		sib_blkno;
	xfs_dablk_t		par_blkno;
	int			error;
	int			w;
	int			entno;
	int			level;
	int			dead_level;

	trace_xfs_da_swap_lastblock(args);

	dead_buf = *dead_bufp;
	dead_blkno = *dead_blknop;
	tp = args->trans;
	dp = args->dp;
	w = args->whichfork;
	ASSERT(w == XFS_DATA_FORK);
	mp = dp->i_mount;
	lastoff = args->geo->freeblk;
	error = xfs_bmap_last_before(tp, dp, &lastoff, w);
	if (error)
		return error;
	if (XFS_IS_CORRUPT(mp, lastoff == 0)) {
		xfs_da_mark_sick(args);
		return -EFSCORRUPTED;
	}
	/*
	 * Read the last block in the btree space.
	 */
	last_blkno = (xfs_dablk_t)lastoff - args->geo->fsbcount;
	error = xfs_da3_node_read(tp, dp, last_blkno, &last_buf, w);
	if (error)
		return error;
	fa = xfs_da3_header_check(last_buf, args->owner);
	if (fa) {
		__xfs_buf_mark_corrupt(last_buf, fa);
		xfs_trans_brelse(tp, last_buf);
		xfs_da_mark_sick(args);
		return -EFSCORRUPTED;
	}

	/*
	 * Copy the last block into the dead buffer and log it.
	 */
	xfs_da_buf_copy(dead_buf, last_buf, args->geo->blksize);
	xfs_trans_log_buf(tp, dead_buf, 0, args->geo->blksize - 1);
	dead_info = dead_buf->b_addr;

	/*
	 * Get values from the moved block.
	 */
	if (dead_info->magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
	    dead_info->magic == cpu_to_be16(XFS_DIR3_LEAFN_MAGIC)) {
		struct xfs_dir3_icleaf_hdr leafhdr;
		struct xfs_dir2_leaf_entry *ents;

		dead_leaf2 = (xfs_dir2_leaf_t *)dead_info;
		xfs_dir2_leaf_hdr_from_disk(dp->i_mount, &leafhdr,
					    dead_leaf2);
		ents = leafhdr.ents;
		dead_level = 0;
		dead_hash = be32_to_cpu(ents[leafhdr.count - 1].hashval);
	} else {
		struct xfs_da3_icnode_hdr deadhdr;

		dead_node = (xfs_da_intnode_t *)dead_info;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &deadhdr, dead_node);
		btree = deadhdr.btree;
		dead_level = deadhdr.level;
		dead_hash = be32_to_cpu(btree[deadhdr.count - 1].hashval);
	}
	sib_buf = par_buf = NULL;
	/*
	 * If the moved block has a left sibling, fix up the pointers.
	 */
	if ((sib_blkno = be32_to_cpu(dead_info->back))) {
		error = xfs_da3_node_read(tp, dp, sib_blkno, &sib_buf, w);
		if (error)
			goto done;
		fa = xfs_da3_header_check(sib_buf, args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(sib_buf, fa);
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		sib_info = sib_buf->b_addr;
		if (XFS_IS_CORRUPT(mp,
				   be32_to_cpu(sib_info->forw) != last_blkno ||
				   sib_info->magic != dead_info->magic)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		sib_info->forw = cpu_to_be32(dead_blkno);
		xfs_trans_log_buf(tp, sib_buf,
			XFS_DA_LOGRANGE(sib_info, &sib_info->forw,
					sizeof(sib_info->forw)));
		sib_buf = NULL;
	}
	/*
	 * If the moved block has a right sibling, fix up the pointers.
	 */
	if ((sib_blkno = be32_to_cpu(dead_info->forw))) {
		error = xfs_da3_node_read(tp, dp, sib_blkno, &sib_buf, w);
		if (error)
			goto done;
		fa = xfs_da3_header_check(sib_buf, args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(sib_buf, fa);
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		sib_info = sib_buf->b_addr;
		if (XFS_IS_CORRUPT(mp,
				   be32_to_cpu(sib_info->back) != last_blkno ||
				   sib_info->magic != dead_info->magic)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		sib_info->back = cpu_to_be32(dead_blkno);
		xfs_trans_log_buf(tp, sib_buf,
			XFS_DA_LOGRANGE(sib_info, &sib_info->back,
					sizeof(sib_info->back)));
		sib_buf = NULL;
	}
	par_blkno = args->geo->leafblk;
	level = -1;
	/*
	 * Walk down the tree looking for the parent of the moved block.
	 */
	for (;;) {
		error = xfs_da3_node_read(tp, dp, par_blkno, &par_buf, w);
		if (error)
			goto done;
		fa = xfs_da3_node_header_check(par_buf, args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(par_buf, fa);
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		par_node = par_buf->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &par_hdr, par_node);
		if (XFS_IS_CORRUPT(mp,
				   level >= 0 && level != par_hdr.level + 1)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		level = par_hdr.level;
		btree = par_hdr.btree;
		for (entno = 0;
		     entno < par_hdr.count &&
		     be32_to_cpu(btree[entno].hashval) < dead_hash;
		     entno++)
			continue;
		if (XFS_IS_CORRUPT(mp, entno == par_hdr.count)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		par_blkno = be32_to_cpu(btree[entno].before);
		if (level == dead_level + 1)
			break;
		xfs_trans_brelse(tp, par_buf);
		par_buf = NULL;
	}
	/*
	 * We're in the right parent block.
	 * Look for the right entry.
	 */
	for (;;) {
		for (;
		     entno < par_hdr.count &&
		     be32_to_cpu(btree[entno].before) != last_blkno;
		     entno++)
			continue;
		if (entno < par_hdr.count)
			break;
		par_blkno = par_hdr.forw;
		xfs_trans_brelse(tp, par_buf);
		par_buf = NULL;
		if (XFS_IS_CORRUPT(mp, par_blkno == 0)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		error = xfs_da3_node_read(tp, dp, par_blkno, &par_buf, w);
		if (error)
			goto done;
		fa = xfs_da3_node_header_check(par_buf, args->owner);
		if (fa) {
			__xfs_buf_mark_corrupt(par_buf, fa);
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		par_node = par_buf->b_addr;
		xfs_da3_node_hdr_from_disk(dp->i_mount, &par_hdr, par_node);
		if (XFS_IS_CORRUPT(mp, par_hdr.level != level)) {
			xfs_da_mark_sick(args);
			error = -EFSCORRUPTED;
			goto done;
		}
		btree = par_hdr.btree;
		entno = 0;
	}
	/*
	 * Update the parent entry pointing to the moved block.
	 */
	btree[entno].before = cpu_to_be32(dead_blkno);
	xfs_trans_log_buf(tp, par_buf,
		XFS_DA_LOGRANGE(par_node, &btree[entno].before,
				sizeof(btree[entno].before)));
	*dead_blknop = last_blkno;
	*dead_bufp = last_buf;
	return 0;
done:
	if (par_buf)
		xfs_trans_brelse(tp, par_buf);
	if (sib_buf)
		xfs_trans_brelse(tp, sib_buf);
	xfs_trans_brelse(tp, last_buf);
	return error;
}

/*
 * Remove a btree block from a directory or attribute.
 */
int
xfs_da_shrink_inode(
	struct xfs_da_args	*args,
	xfs_dablk_t		dead_blkno,
	struct xfs_buf		*dead_buf)
{
	struct xfs_inode	*dp;
	int			done, error, w, count;
	struct xfs_trans	*tp;

	trace_xfs_da_shrink_inode(args);

	dp = args->dp;
	w = args->whichfork;
	tp = args->trans;
	count = args->geo->fsbcount;
	for (;;) {
		/*
		 * Remove extents.  If we get ENOSPC for a dir we have to move
		 * the last block to the place we want to kill.
		 */
		error = xfs_bunmapi(tp, dp, dead_blkno, count,
				    xfs_bmapi_aflag(w), 0, &done);
		if (error == -ENOSPC) {
			if (w != XFS_DATA_FORK)
				break;
			error = xfs_da3_swap_lastblock(args, &dead_blkno,
						      &dead_buf);
			if (error)
				break;
		} else {
			break;
		}
	}
	xfs_trans_binval(tp, dead_buf);

	/* sess34 P34C companion: log dir-space UNMAPs so the cross-node
	 * (ino,startoff) merge can tell a legit remap-after-free from the
	 * double-map bug.  Same gating as P34C-DIRGROW. */
	{
		extern int mxfs_dirwr_enabled;
		extern int mxfs_instr_enabled;

		if ((mxfs_dirwr_enabled || mxfs_instr_enabled ||
		     dp->i_ino <= 256 /* sess3: shared-dir lineage, always-on */) &&
		    w == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
		    dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			pr_warn("mxfs: P34C-DIRSHRINK ino=%llu startoff=%u len=%d rc=%d realns=%llu\n",
				(unsigned long long)dp->i_ino,
				(unsigned)dead_blkno, count, error,
				(unsigned long long)ktime_get_real_ns());
		}
	}
	return error;
}

static int
xfs_dabuf_map(
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	unsigned int		flags,
	int			whichfork,
	struct xfs_buf_map	**mapp,
	int			*nmaps)
{
	struct xfs_mount	*mp = dp->i_mount;
	int			nfsb = xfs_dabuf_nfsb(mp, whichfork);
	struct xfs_bmbt_irec	irec, *irecs = &irec;
	struct xfs_buf_map	*map = *mapp;
	xfs_fileoff_t		off = bno;
	int			error = 0, nirecs, i;

	if (nfsb > 1)
		irecs = kzalloc(sizeof(irec) * nfsb,
				GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);

	nirecs = nfsb;
	error = xfs_bmapi_read(dp, bno, nfsb, irecs, &nirecs,
			xfs_bmapi_aflag(whichfork));
	if (error)
		goto out_free_irecs;

	/*
	 * Use the caller provided map for the single map case, else allocate a
	 * larger one that needs to be free by the caller.
	 */
	if (nirecs > 1) {
		map = kzalloc(nirecs * sizeof(struct xfs_buf_map),
				GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
		if (!map) {
			error = -ENOMEM;
			goto out_free_irecs;
		}
		*mapp = map;
	}

	for (i = 0; i < nirecs; i++) {
		if (irecs[i].br_startblock == HOLESTARTBLOCK ||
		    irecs[i].br_startblock == DELAYSTARTBLOCK)
			goto invalid_mapping;
		if (off != irecs[i].br_startoff)
			goto invalid_mapping;

		map[i].bm_bn = XFS_FSB_TO_DADDR(mp, irecs[i].br_startblock);
		map[i].bm_len = XFS_FSB_TO_BB(mp, irecs[i].br_blockcount);
		off += irecs[i].br_blockcount;
	}

	if (off != bno + nfsb)
		goto invalid_mapping;

	*nmaps = nirecs;
out_free_irecs:
	if (irecs != &irec)
		kfree(irecs);
	return error;

invalid_mapping:
#ifdef __KERNEL__
	/*
	 * sess14(ccloop) SMOKING-GUN probe (RULE 4): on a multi-node DIR DATA-fork
	 * hole, dump the inode coherency state.  Hypothesis: the async evict-ring
	 * bumped i_dlm_dir_gen (so xfs_da_read_buf re-fetched a FRESH leaf that
	 * references block `bno`) but the EXTENT MAP was NOT reloaded for that gen
	 * (i_dlm_dir_loaded_gen < i_dlm_dir_gen) -> fresh-leaf/stale-map -> this
	 * hole.  If loaded_gen < dir_gen here, that decoupling is PROVEN; the fix
	 * is to couple a dir_gen bump with an extent-map reload (or arm
	 * MXFS_IF_DIR_RELOAD whenever dir_gen advances).
	 */
	if (whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
	    /* sess5 (46efd8b6): a HOLE_OK caller (readdir, datascan,
	     * leafless-remove) EXPECTS sparse holes in a churned dir —
	     * don't spam P14 or run the FUA hole-forensics for those;
	     * only a dataptr-following lookup (no HOLE_OK) is a real
	     * mixed-era symptom. */
	    !(flags & XFS_DABUF_MAP_HOLE_OK) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern u64 mxfs_vfs_inode_iversion(struct inode *);
		static atomic_t p14h = ATOMIC_INIT(0);
		/* <ccloop sess49> at the hole, dump the full extent map + stack
		 * (catches the in-core delalloc that strands the leaf). */
		mxfs_dir_delalloc_tripwire(dp, "dabuf_map_hole");
		/* <ccloop sess49b> FUA-read the durable dinode: is the gap on the
		 * platter (DISK-TORN, write-side) or only in-core (read-side)? */
		mxfs_dir_hole_disk_probe(dp, (xfs_fileoff_t)bno);
		if (atomic_inc_return(&p14h) <= 60)
			pr_warn("mxfs: P14-DABUF-HOLE ino=%llu bno=%u fmt=%u nextents=%llu disize=%lld i_gen=%u dir_gen=%llu loaded_gen=%llu evicted_incarn=%u dlm_mode=%d reload_armed=%d iget_age_ms=%lld iversion=%llu comm=%s\n",
				(unsigned long long)dp->i_ino, bno,
				dp->i_df.if_format,
				(unsigned long long)dp->i_df.if_nextents,
				(long long)dp->i_disk_size,
				VFS_I(dp)->i_generation,
				(unsigned long long)dp->i_dlm_dir_gen,
				(unsigned long long)dp->i_dlm_dir_loaded_gen,
				dp->i_dlm_dir_evicted_incarn,
				dp->i_dlm_mode,
				xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD) ? 1 : 0,
				/* sess3 (46efd8b6): tiny age here = cold-iget
				 * adopted a lagging home image (dir inode was
				 * evicted mid-run, structure buffers survived
				 * newer) — the cornered mixed-era mechanism. */
				dp->i_mxfs_iget_ns ?
					(long long)((ktime_get_ns() -
						     dp->i_mxfs_iget_ns) /
						    NSEC_PER_MSEC) : -1,
				(unsigned long long)mxfs_vfs_inode_iversion(VFS_I(dp)),
				current->comm);
		/*
		 * sess15(ccloop) EXTENT-SHAPE probe (RULE 4): the gen-coupling
		 * hypothesis was REFUTED (loaded_gen==dir_gen at every hole).
		 * Dump the in-core data-fork extent records so we can see the
		 * map's actual shape (expected [0][3][leaf] = blocks 1,2 lost
		 * from a 4-data-block leaf dir) and prove whether the map is
		 * internally inconsistent with di_size.  Safe: in-core only,
		 * no I/O, no locking.  First few holes only.
		 */
		{
			static atomic_t p15s = ATOMIC_INIT(0);
			if (atomic_inc_return(&p15s) <= 12 &&
			    dp->i_df.if_format == XFS_DINODE_FMT_EXTENTS &&
			    !xfs_need_iread_extents(&dp->i_df)) {
				struct xfs_bmbt_irec	r;
				struct xfs_iext_cursor	c;
				int			k = 0;
				for (xfs_iext_first(&dp->i_df, &c);
				     xfs_iext_get_extent(&dp->i_df, &c, &r);
				     xfs_iext_next(&dp->i_df, &c)) {
					pr_warn("mxfs: P15-EXTSHAPE ino=%llu req_bno=%u rec[%d] off=%llu blk=%lld len=%llu state=%d\n",
						(unsigned long long)dp->i_ino, bno, k,
						(unsigned long long)r.br_startoff,
						(long long)r.br_startblock,
						(unsigned long long)r.br_blockcount,
						r.br_state);
					k++;
				}
			}
		}
	}
#endif
	/* Caller ok with no mapping. */
	if (XFS_IS_CORRUPT(mp, !(flags & XFS_DABUF_MAP_HOLE_OK))) {
		xfs_dirattr_mark_sick(dp, whichfork);
		error = -EFSCORRUPTED;
		if (xfs_error_level >= XFS_ERRLEVEL_LOW) {
			xfs_alert(mp, "%s: bno %u inode %llu",
					__func__, bno, dp->i_ino);

			for (i = 0; i < nirecs; i++) {
				xfs_alert(mp,
"[%02d] br_startoff %lld br_startblock %lld br_blockcount %lld br_state %d",
					i, irecs[i].br_startoff,
					irecs[i].br_startblock,
					irecs[i].br_blockcount,
					irecs[i].br_state);
			}
		}
	} else {
		*nmaps = 0;
	}
	goto out_free_irecs;
}

/*
 * Get a buffer for the dir/attr block.
 */
int
xfs_da_get_buf(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	struct xfs_buf		**bpp,
	int			whichfork)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*bp;
	struct xfs_buf_map	map, *mapp = &map;
	int			nmap = 1;
	int			error;

	*bpp = NULL;
	error = xfs_dabuf_map(dp, bno, 0, whichfork, &mapp, &nmap);
	if (error || nmap == 0)
		goto out_free;

	error = xfs_trans_get_buf_map(tp, mp->m_ddev_targp, mapp, nmap, 0, &bp);
	if (error)
		goto out_free;

	/*
	 * sess55 (ccloop) RULE-4 M2 SOURCE DETECTOR.  Face B of
	 * posix_semantics_multi16 was PROVEN (sess55) to be a stale dir
	 * extent-map mis-WRITE: this dir's in-core extent fork maps logical
	 * dir block `bno` to a physical daddr that actually backs a LIVE
	 * inode cluster, so the dirent write here clobbers it (imap_to_bp
	 * rc=-5 shutdown).  The allocator was ruled out 3 ways (P55-ALLOC-*
	 * all 0×).  Here we are about to hand the caller a WRITE buffer for
	 * that daddr.  If the buffer the cache returned already holds inode
	 * content (di_magic 'IN'), the daddr xfs_dabuf_map produced from this
	 * dir's extent fork aliases a live inode cluster cached on this node.
	 * No I/O — just inspect the cached buffer content.  dp->i_ino names
	 * the directory whose extent map is stale.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    bp && bp->b_addr) {
		__be16 *m = bp->b_addr;
		bool inode_here = false;
		__u16 dimode = 0;

		if ((bp->b_flags & XBF_DONE) &&
		    be16_to_cpu(*m) == XFS_DINODE_MAGIC) {
			/* locally-cached inode cluster aliased as a dir block */
			inode_here = true;
			dimode = be16_to_cpu(*(__be16 *)((char *)bp->b_addr + 2));
		} else if (!(bp->b_flags & XBF_DONE)) {
			/*
			 * Cache-miss dir-block get: the inode cluster that may
			 * alias this daddr lives on a PEER and is not in our
			 * cache, so the fresh buffer is empty.  A plain-bio read
			 * hits the COHERENT SCST write-back cache (fua_disable=1)
			 * and reveals a peer's live inode cluster.  Scoped to
			 * cache-miss only to bound the extra I/O.
			 */
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *, uint32_t);
			void *probe = kmalloc(512, GFP_NOFS);
			if (probe) {
				uint64_t lba = (uint64_t)mapp[0].bm_bn +
					mp->m_ddev_targp->bt_sector_offset;
				if (mxfs_pal_bdev_read_plain_bdev(
				    mp->m_ddev_targp->bt_bdev, lba, probe, 512) == 0 &&
				    be16_to_cpu(*(__be16 *)probe) == XFS_DINODE_MAGIC) {
					inode_here = true;
					dimode = be16_to_cpu(*(__be16 *)((char *)probe + 2));
				}
				kfree(probe);
			}
		}
		if (inode_here)
			pr_warn_ratelimited("mxfs: P55-DIRWRITE-OVER-INODE dir_ino=%llu dablk=%u daddr=0x%llx nmap=%d disk_di_mode=0%o bflags=0x%x cached=%d — stale dir extent-map maps a dir block onto a live inode cluster\n",
				(unsigned long long)dp->i_ino,
				(unsigned)bno,
				(unsigned long long)mapp[0].bm_bn,
				nmap, dimode, bp->b_flags,
				(bp->b_flags & XBF_DONE) ? 1 : 0);
	}

	*bpp = bp;

out_free:
	if (mapp != &map)
		kfree(mapp);

	return error;
}

/*
 * sess15 (RULE 4 — block-dir concurrent-create durable loss REQUIRES inode/daddr
 * REUSE): a dir DATA/BLOCK buffer cached at a physical daddr that has since been
 * FREED from its old owner inode and REALLOCATED to a different dir inode is an
 * ABA alias — XBF_DONE is set (the verifier passed when it was read for the OLD
 * owner), the per-dir generation can collide (both low), so neither the v5
 * verifier (cache-hit skips it) nor the b_mxfs_dir_gen hook re-reads it.  A
 * subsequent RMW of "this inode's" block then operates on the OLD inode's dirents
 * and writes them back, durably dropping the new dir's entries (proven: the
 * crash_consistency loss reproduces ONLY when earlier work frees+reallocs the
 * daddrs; a never-reusing workload is 40/40 clean).  Detect it cheaply at read:
 * a dir3 DATA/BLOCK header carries the owning inode number; if it does not match
 * the inode we are reading for, the cached image is a stale ABA alias.
 * Returns true only for v5 dir DATA/BLOCK blocks with a mismatched owner.
 */
static inline bool
mxfs_dir_data_buf_owner_mismatch(struct xfs_buf *bp, xfs_ino_t ino)
{
	struct xfs_dir3_blk_hdr	*h3;
	__be32			magic;

	if (!bp || !bp->b_addr)
		return false;
	magic = *(__be32 *)bp->b_addr;
	if (magic != cpu_to_be32(XFS_DIR3_DATA_MAGIC) &&
	    magic != cpu_to_be32(XFS_DIR3_BLOCK_MAGIC))
		return false;	/* v4 (no owner) or non-dirent block type */
	h3 = bp->b_addr;
	return be64_to_cpu(h3->owner) != ino;
}

/*
 * Get a buffer for the dir/attr block, fill in the contents.
 */
int
xfs_da_read_buf(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	unsigned int		flags,
	struct xfs_buf		**bpp,
	int			whichfork,
	const struct xfs_buf_ops *ops)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*bp;
	struct xfs_buf_map	map, *mapp = &map;
	int			nmap = 1;
	int			error;
	/*
	 * v0.5.6 dir-gen fresh-read stamp: the coherency hook below stamps
	 * b_mxfs_dir_gen ONLY in its invalidate branch.  A dir block fetched
	 * from disk on a true cache miss — or one the BAST/evict fence
	 * invalidated (!XBF_DONE) — comes back with gen 0 even though its
	 * content is coherent for the CURRENT tenure.  Every later read of it
	 * then sees a gen mismatch: if unpinned it pays a pointless
	 * invalidate + FUA re-read (doubling cold dir-block reads in a
	 * multi-node storm); if our own transaction has it pinned it fires
	 * DIR-STALE-SKIP as a FALSE positive.  Record at hook time whether
	 * the read below will genuinely fetch from disk, and stamp the
	 * buffer with the gen SNAPSHOTTED at hook time (never re-read at
	 * stamp time: a lock_flags=0 reader is not a DLM holder, so a BAST +
	 * peer modify + local re-acquire can bump the gen mid-read — the
	 * older snapshot then correctly leaves the buffer marked stale).
	 */
	bool			dir_stamp_fresh = false;
	uint32_t		dir_gen_snap = 0;
	/*
	 * sess5 (ccloop 46efd8b6, RULE 4 PROVEN): the pre-read incore
	 * (XBF_TRYLOCK) invalidation below is SKIPPABLE — under concurrent
	 * same-dir walkers the da-tree node/leaf buffers are locked at check
	 * time on EVERY read (P34-TRYLOCK-STALE rc=-11 storms, 100-170/node/run,
	 * repeating across tenure gens 39→40 on the same daddrs), so a stale
	 * prior-tenure leaf survives every boundary and every read.  Walkers
	 * then follow its entries into data blocks the current era freed
	 * (P14-DABUF-HOLE want_bno=38/39/40 with DISK_MAPS_WANT=0 = platter
	 * bmbt agrees with the fresh map, and P70 release audits all clean =
	 * platter leaf never refs holes ⇒ the served LEAF VIEW is the stale
	 * odd-one-out) = the cache_coherency@32 rv-content/ENOENT family.
	 * Record a trylock-skip here; after xfs_trans_read_buf_map returns the
	 * buffer LOCKED, redo the invalidation decision race-free (post-read
	 * revalidation below).
	 */
	bool			dir_inval_skipped = false;
	/*
	 * sess44 deferred-publish perf: when THIS directory is UNPUBLISHED, it
	 * has never had an on-disk DLM slot, so no peer has ever been able to
	 * reach it, let alone modify its dir blocks — our cached copy is
	 * unconditionally authoritative.  Skip the cross-node dir-block
	 * coherency machinery below (the dir-gen engage + invalidation that
	 * clears _XBF_FUA_FRESH and forces a synchronous SCSI FUA re-read of
	 * every dir block).  This was the dominant residual rsync_paired cost:
	 * a node-private rsync reads its own dir blocks thousands of times, each
	 * paying a FUA round-trip for a peer modification that can never happen.
	 *
	 * NOTE: we deliberately do NOT use "i_dlm_mode == EX" here.  A SHARED
	 * dir that we hold EX may still have STALE cached data blocks if we
	 * released it on a peer BAST and re-acquired it after the peer modified
	 * it (the gen mechanism refreshes those) — gating on EX skipped that
	 * refresh and regressed rename/unlink_visibility.  "unpublished" is the
	 * strictly-safe signal: such a dir has provably never been shared.  Once
	 * a peer BAST publishes it (i_dlm_unpublished cleared), the coherency
	 * path re-engages.
	 */
	/* ccloop 0d6e174d dlm_scaling ROOT FIX: extend the provably-private skip
	 * from "unpublished" (never had a disk slot) to "published but held EX with
	 * zero peer BASTs since load" (i_dlm_mode==EX && !i_dlm_dir_contended).  MXFS
	 * releases a cached dir EX to NL ONLY on a peer BAST (sets i_dlm_dir_contended)
	 * or eviction (resets it + fresh re-read on reacquire); no idle release.  So
	 * EX && !contended == held continuously, never contended == no peer could have
	 * modified the blocks == cached image authoritative.  This is strictly stronger
	 * than the bare EX the NOTE above rejects: that reject case ("released on a peer
	 * BAST, re-acquired after a peer modify") SETS i_dlm_dir_contended and is thus
	 * excluded.  The NL-window peer-modify case is handled BEFORE this skip engages
	 * by the acquire-reload staling + the owned_ex-INDEPENDENT honor hook below. */
	extern int mxfs_dir_priv_ex_skip;
	extern int mxfs_dir_shared_pr_skip;
	bool			owned_ex = mp->m_mxfs_dlm &&
				S_ISDIR(VFS_I(dp)->i_mode) &&
				!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
				((mxfs_dir_unpub_skip && dp->i_dlm_unpublished) ||
				 (mxfs_dir_priv_ex_skip &&
				  dp->i_dlm_mode == MXFS_LOCK_EX &&
				  !dp->i_dlm_dir_contended &&
				  dp->i_dlm_dir_valid_epoch == 0) ||
				 /* ccloop 12e0d157 sess4: SHARED dir held >=PR with no
				  * peer-wants-EX — cache authoritative (PR excludes all
				  * peer write modes); kills the 32-node dlm_scaling
				  * shared-parent reread storm.  See mxfs_dir_shared_pr_skip. */
				 (mxfs_dir_shared_pr_skip &&
				  dp->i_dlm_mode >= MXFS_LOCK_PR &&
				  !dp->i_dlm_dir_want_ex));

	/* ccloop 12e0d157 sess4 P-DSCAN (RULE-4, dlm_scaling@32): the proven storm
	 * is cold re-reads of the SHARED parent path (.dlm_scaling in AG0) — every
	 * node re-reads it ~100x/op at 32-node load because the owned_ex skip above
	 * requires EX, but the shared parent is held only at ≥PR (readers).  Log the
	 * exact cached DLM state of every non-root multinode DATA-fork dir read that
	 * MISSES the skip so the fix gate (extend skip to ≥PR-held, no peer-wants-EX)
	 * can be verified against real state: is the parent held PR (fix works) or NL
	 * (needs a different fix)?  is valid_epoch 0 or bumped by setup handoffs?
	 * Ratelimited; gated on dirwr (the dlm_scaling criterion sets dirwr=1). */
	{
		extern int mxfs_dirwr_enabled;
		if (unlikely(mxfs_dirwr_enabled) && !owned_ex &&
		    whichfork == XFS_DATA_FORK &&
		    S_ISDIR(VFS_I(dp)->i_mode) && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_ino != mp->m_sb.sb_rootino)
			pr_warn_ratelimited(
				"mxfs: P-DSCAN ino=%llu bno=%u mode=%u contended=%d want_ex=%d valid_epoch=%u dir_gen=%llu unpub=%d comm=%s\n",
				(unsigned long long)dp->i_ino, (unsigned)bno,
				dp->i_dlm_mode, dp->i_dlm_dir_contended,
				dp->i_dlm_dir_want_ex,
				dp->i_dlm_dir_valid_epoch,
				(unsigned long long)dp->i_dlm_dir_gen,
				dp->i_dlm_unpublished, current->comm);
	}

	*bpp = NULL;
	error = xfs_dabuf_map(dp, bno, flags, whichfork, &mapp, &nmap);
	if (error || !nmap)
		goto out_free;

	/*
	 * sess60 LOGICAL-BLOCK-MAP probe (in-core extent resolution, NO I/O):
	 * dump logical-block -> physical daddr for DATA-fork dir blocks of a
	 * non-root multinode dir.  STRONGEST untried lead for the durable
	 * node1_f1 loss (LOOKUP_ENOENT + REREAD_MISS, all read/write staleness
	 * probes silent): a logical-block0 SPLIT (sess42) — node1_f1's dirent is
	 * in a physical block the home dinode's logical-0 does NOT resolve to, so
	 * it is orphaned.  Compare this daddr ACROSS nodes for the same i_gen at a
	 * failing round: divergent daddr for the same logical bno == the split.
	 */
	if (whichfork == XFS_DATA_FORK && bno == 0 &&
	    S_ISDIR(VFS_I(dp)->i_mode) &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    dp->i_ino != dp->i_mount->m_sb.sb_rootino) {
		extern int mxfs_instr_enabled;
		static atomic_t p60lm = ATOMIC_INIT(0);
		if (unlikely(mxfs_instr_enabled) &&
		    atomic_inc_return(&p60lm) <= 100000)
			pr_warn("mxfs: P60-LBMAP ino=%llu i_gen=%u lbno0 daddr=%lld nmap=%d nextents=%llu disize=%lld dir_gen=%llu dlm_mode=%d comm=%s\n",
				(unsigned long long)dp->i_ino,
				VFS_I(dp)->i_generation,
				(long long)mapp[0].bm_bn, nmap,
				(unsigned long long)dp->i_df.if_nextents,
				(long long)dp->i_disk_size,
				(unsigned long long)dp->i_dlm_dir_gen,
				dp->i_dlm_mode,
				current->comm);
	}

	/* sess38(ccloop) RULE-4: log the logical->physical resolution of every
	 * NON-zero dir DATA-fork block (leaf / node / free / extra data) in
	 * multinode mode.  Compared across nodes for the same (ino,i_gen,bno) at
	 * the failing round this reveals an extent-map divergence: if node A
	 * resolves the leaf logical bno to daddr D1 while node B resolves the
	 * same bno to a different daddr (or to a daddr that physically holds a
	 * DATA block), the dir's data fork is incoherent across nodes (block
	 * double-alloc / stale bmbt).  Always-on but ratelimited + bno!=0 so the
	 * hot data-block-0 path is untouched. */
	if (whichfork == XFS_DATA_FORK && bno != 0 &&
	    S_ISDIR(VFS_I(dp)->i_mode) &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    dp->i_ino != dp->i_mount->m_sb.sb_rootino)
		pr_warn_ratelimited(
			"mxfs: P38-DIRMAP ino=%llu i_gen=%u bno=%u daddr=%lld nmap=%d nextents=%llu fmt=%d dir_gen=%llu dlm_mode=%d comm=%s\n",
			(unsigned long long)dp->i_ino,
			VFS_I(dp)->i_generation,
			(unsigned)bno,
			(long long)mapp[0].bm_bn, nmap,
			(unsigned long long)dp->i_df.if_nextents,
			dp->i_df.if_format,
			(unsigned long long)dp->i_dlm_dir_gen,
			dp->i_dlm_mode,
			current->comm);

	/*
	 * MXFS read-time block-format-dir coherency (sess38).
	 *
	 * A cached dir DATA-fork block whose freshness stamp predates the
	 * inode's most recent DLM re-acquire-after-BAST is stale: while we
	 * did not hold the lock a peer node committed dirents into this
	 * block, and we never re-read them.  Returning the cached copy lets
	 * a subsequent create/remove read-modify-write off the stale image
	 * and clobber the peer's entries (the long-standing "Mode A"
	 * block-format lost-update).
	 *
	 * We cannot re-read the buffer in place after xfs_trans_read_buf_map
	 * returns it — that buffer is joined to the transaction, and
	 * re-submitting / releasing it corrupts the DLM holder accounting
	 * (observed: leaked ino-DLM holder -> peer BAST starves -> peer
	 * acquire times out -> shutdown).  Instead, BEFORE the read, look
	 * the buffer up in-core and, if its stamp lags the inode gen, clear
	 * XBF_DONE (and _XBF_FUA_FRESH so the FUA gate re-pierces the
	 * per-initiator storage cache).  The sanctioned read path below then
	 * re-reads the peer's committed block, verifies it, and joins it to
	 * the transaction normally.  i_dlm_dir_gen is monotonic and starts
	 * at 0, so the single-node / never-BAST'd case skips this entirely.
	 */
	/* sess43 FIX (gen-0 dir-coherency window): the coherency hook below is
	 * gated on i_dlm_dir_gen != 0 (a single-node optimization).  CONFIRMED
	 * (P83) that DATA-fork dir reads happen in multi-node mode while
	 * i_dlm_dir_gen==0 (lock_flags=0 lookup/readdir reads bypass
	 * mxfs_dlm_ilock_begin, so the gen never bumps) → cross-node invalidation
	 * is SKIPPED → a stale cached first-dir-block is read (peer miss) or
	 * RMW-clobbered → "writer's first entries missed by peers".  ENGAGE the
	 * gen mechanism: in TRUE multi-node mode, bump i_dlm_dir_gen 0→1 so the
	 * hook below runs THIS read — cached blocks stamped at the default gen 0
	 * then mismatch (0 < 1) and get invalidated + FUA-re-read fresh.  Gated on
	 * mxfs_v5_dlm_is_single_node()==false so single-node dir reads keep the
	 * no-FUA fast path (no single_node_paired perf regression). */
	if (!owned_ex &&
	    whichfork == XFS_DATA_FORK && nmap == 1 &&
	    dp->i_dlm_dir_gen == 0 && S_ISDIR(VFS_I(dp)->i_mode) &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		/* sess46 RE-ENABLED (was sess43 A/B disabled): ENGAGE the dir-gen
		 * coherency mechanism on the first multi-node DATA-fork dir read.
		 * readdir/lookup use lock_flags=0 and bypass mxfs_dlm_ilock_begin,
		 * so i_dlm_dir_gen never bumps off 0 → the invalidation hook below
		 * (gated gen!=0) is SKIPPED → a stale cached dir block is served
		 * cross-node → a peer's just-added/renamed dirents are invisible
		 * (the rename_visibility / barrier-marker-visibility failure +
		 * 120s barrier timeouts).  Bumping 0→1 here makes the hook below
		 * run in THIS same call: cached blocks stamped at the default
		 * gen 0 mismatch (0 < 1) → invalidated + FUA-re-read fresh.  The
		 * dirty/in-AIL/pin/delwri guards in that hook protect this node's
		 * own uncommitted work.  The cross_write_read EACCES regression
		 * that motivated the sess43 A/B disable was addressed by sess45
		 * (node-affine alloc + atime-skip + getattr ILOCK reload). */
		dp->i_dlm_dir_gen = 1;
	}

	/*
	 * sess5 (ccloop) DEFERRED-STALE honor hook — closes the acquire-reload
	 * locked-skip gap (the dir_reuse readdir-undercount lost-update).  The
	 * fresh-EX-grant reload (mxfs_dlm_reload_inode) UNCONDITIONALLY stales
	 * cached dir blocks so the RMW cold-reads the peer's image, but it
	 * TRYLOCK-skips a LOCKED block (in-flight writeback) and flags it
	 * b_mxfs_stale_pending instead (blocking-lock there DEADLOCKS).  Honor
	 * that flag here, at the next read of the block: force-invalidate it
	 * (clear XBF_DONE) so the addname RMW base is coherent.  Runs for EVERY
	 * multinode dir DATA read regardless of owned_ex — but is NARROWLY
	 * scoped to buffers the reload explicitly flagged (unlike a blanket
	 * salvage/evict), so it cannot over-invalidate a shared reader's fresh
	 * cache.  Loss-safe: the flag is only set at a fresh acquire where
	 * Invariant-1 drained our own work durable (block is destaged). */
	if (whichfork == XFS_DATA_FORK && nmap == 1 &&
	    S_ISDIR(VFS_I(dp)->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		/*
		 * sess6(ccloop) FIX-15: BOUNDED honor-wait.  run88 r2/r4 proved
		 * the stale-serve: the reload flags the block, but the FIRST
		 * readdir maps it while it is transiently busy (locked /
		 * dirty / pinned / delwri — the just-finished create wave still
		 * settling), the honor arm can't run, and the count-`ls` serves
		 * the stale view (all 37 victims LOOKUP_OK REREAD_SHOWS — the
		 * classifier's later maps did the invalidate).  Retry the honor
		 * for up to ~50ms so the transient clears and the read gets the
		 * fresh image.  Bounded trylock+msleep (never a blocking
		 * xfs_buf_lock — sess37 deadlock); on exhaustion serve stale as
		 * before but say so (P5D).
		 */
		int p5_try;

		for (p5_try = 0; p5_try < 25; p5_try++) {
			struct xfs_buf	*pbp = NULL;
			struct xfs_buf_log_item	*pbip;
			bool pend, pdirty, busy;
			int p5_rc;

			/* incore(TRYLOCK): 0 = found+LOCKED, -EAGAIN = found
			 * but locked elsewhere, -ENOENT = absent. */
			p5_rc = xfs_buf_incore(mp->m_ddev_targp,
					       mapp[0].bm_bn,
					       mapp[0].bm_len, XBF_TRYLOCK,
					       &pbp);
			if (p5_rc == -EAGAIN) {
				/*
				 * v0.6.5 (sess5 186320ae) — SELF-JOINED refresh.
				 * RULE 4 PROVEN (dlm_fairness 4/caw run 020719Z,
				 * ino 6291584 daddr 6279744 @:52.727): the
				 * "locked elsewhere" holder can be OUR OWN
				 * transaction — the rename's earlier da_read
				 * joined this block, then the dir EX was yielded
				 * mid-trans (clean-trans ABBA breaker), a peer
				 * modified the block, and the re-acquire reload
				 * flagged it stale_pending.  The trylock+msleep
				 * loop below can NEVER win against our own trans
				 * lock: 25 futile laps then P5D served the
				 * pre-yield image, the RMW resurrected the
				 * peers' removed round-1 dirents, and the
				 * block->sf conversion crystallized the ghosts
				 * durably ("df shared dir drained exp=0 got=1").
				 * We HOLD the buffer lock via tp, so refresh the
				 * content IN PLACE from the platter (FUA) —
				 * legal because nothing is logged against it
				 * (trans clean, bli clean, not in AIL, unpinned)
				 * so the in-core image is a pure cache of a
				 * superseded disk state.  On any doubt (dirty
				 * trans, dirty/in-AIL bli, pinned, short read,
				 * bad magic/CRC) leave it alone and fall back to
				 * today's bounded-wait + stale-serve.
				 */
				if (tp) {
					struct xfs_log_item *p5r_lip;
					struct xfs_buf *p5r_bp = NULL;

					list_for_each_entry(p5r_lip, &tp->t_items,
							    li_trans) {
						struct xfs_buf_log_item *p5r_blip =
							(struct xfs_buf_log_item *)p5r_lip;

						if (p5r_lip->li_type == XFS_LI_BUF &&
						    p5r_blip->bli_buf->b_target ==
							mp->m_ddev_targp &&
						    xfs_buf_daddr(p5r_blip->bli_buf) ==
							mapp[0].bm_bn &&
						    p5r_blip->bli_buf->b_length ==
							mapp[0].bm_len) {
							p5r_bp = p5r_blip->bli_buf;
							break;
						}
					}
					if (p5r_bp) {
						bool p5r_pend;

						spin_lock(&p5r_bp->b_lock);
						p5r_pend = p5r_bp->b_mxfs_stale_pending;
						spin_unlock(&p5r_bp->b_lock);
						if (p5r_pend &&
						    !(tp->t_flags & XFS_TRANS_DIRTY) &&
						    !xfs_buf_ispinned(p5r_bp) &&
						    (!p5r_bp->b_log_item ||
						     (!test_bit(XFS_LI_DIRTY,
							&p5r_bp->b_log_item->bli_item.li_flags) &&
						      !test_bit(XFS_LI_IN_AIL,
							&p5r_bp->b_log_item->bli_item.li_flags)))) {
							extern int mxfs_pal_scsi_read_fua_bdev(
								struct block_device *,
								uint64_t, void *, uint32_t);
							struct xfs_buftarg *p5r_dtp =
								mp->m_ddev_targp;
							uint32_t p5r_len =
								BBTOB(p5r_bp->b_length);
							void *p5r_tmp =
								((p5r_len & 511) == 0 &&
								 p5r_len) ?
								kmalloc(p5r_len, GFP_NOFS) :
								NULL;
							bool p5r_done = false;

							if (p5r_tmp && p5r_dtp &&
							    p5r_dtp->bt_bdev &&
							    mxfs_pal_scsi_read_fua_bdev(
								p5r_dtp->bt_bdev,
								(uint64_t)mapp[0].bm_bn +
								p5r_dtp->bt_sector_offset,
								p5r_tmp, p5r_len) == 0) {
								struct xfs_dir3_blk_hdr *p5r_h =
									p5r_tmp;
								if ((p5r_h->magic ==
								     cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) ||
								     p5r_h->magic ==
								     cpu_to_be32(XFS_DIR3_DATA_MAGIC)) &&
								    xfs_verify_cksum(p5r_tmp,
									p5r_len,
									offsetof(struct xfs_dir3_blk_hdr,
										 crc))) {
									memcpy(p5r_bp->b_addr,
									       p5r_tmp, p5r_len);
									spin_lock(&p5r_bp->b_lock);
									p5r_bp->b_mxfs_stale_pending =
										false;
									spin_unlock(&p5r_bp->b_lock);
									p5r_bp->b_mxfs_dir_gen =
										dp->i_dlm_dir_gen;
									p5r_done = true;
								}
							}
							pr_warn_ratelimited(
								"mxfs: P5R-TRANSREFRESH ino=%llu daddr=%lld len=%u ok=%d — self-trans-joined stale dir block %s (comm=%s realns=%llu)\n",
								(unsigned long long)dp->i_ino,
								(long long)mapp[0].bm_bn,
								p5r_len, p5r_done ? 1 : 0,
								p5r_done ?
								"FUA-refreshed in place" :
								"refresh failed; serving stale",
								current->comm,
								(unsigned long long)ktime_get_real_ns());
							kfree(p5r_tmp);
						}
						/* Self-locked: waiting cannot
						 * help either way. */
						break;
					}
				}
				/* possibly a flagged block mid-I/O: wait it
				 * out, bounded */
				if (p5_try == 24) {
					pr_warn_ratelimited(
						"mxfs: P5D-STALE-SERVED ino=%llu daddr=%lld LOCKED plat_act=%d — deferred-stale block still locked after wait; serving stale view (trans=%d comm=%s realns=%llu)\n",
						(unsigned long long)dp->i_ino,
						(long long)mapp[0].bm_bn,
						mxfs_dirblk_platter_active(mp,
							mapp[0].bm_bn),
						tp ? 1 : 0, current->comm,
						(unsigned long long)ktime_get_real_ns());
					break;
				}
				msleep(2);
				continue;
			}
			if (p5_rc != 0 || !pbp)
				break;		/* not cached: cold read is fresh */
			spin_lock(&pbp->b_lock);
			pend = pbp->b_mxfs_stale_pending;
			spin_unlock(&pbp->b_lock);
			if (!pend) {
				xfs_buf_relse(pbp);
				break;
			}
			pbip = pbp->b_log_item;
			pdirty = pbip && test_bit(XFS_LI_DIRTY,
						  &pbip->bli_item.li_flags);
			/* sess6 FIX-11 (PROVEN run81 r5): an UNDESTAGED buffer
			 * can never be invalidated — under Invariant-1 every
			 * release drains, so a peer can only be ahead of a
			 * DESTAGED copy.  The flag's premise is false here —
			 * drop it, keep the buffer. */
			if (mxfs_dir_buf_is_undestaged(pbp)) {
				spin_lock(&pbp->b_lock);
				pbp->b_mxfs_stale_pending = false;
				spin_unlock(&pbp->b_lock);
				pr_warn_ratelimited(
					"mxfs: P5B-DEFERRED-STALE-KEPT ino=%llu daddr=%lld lseq=%u wseq=%u pin=%d — undestaged local adds, flag dropped (would have discarded committed dirents)\n",
					(unsigned long long)dp->i_ino,
					(long long)mapp[0].bm_bn,
					pbp->b_mxfs_logged_seq,
					pbp->b_mxfs_written_seq,
					xfs_buf_ispinned(pbp));
				xfs_buf_relse(pbp);
				break;
			}
			busy = pdirty || xfs_buf_ispinned(pbp) ||
			       (pbp->b_flags & (_XBF_DELWRI_Q | XBF_WRITE));
			if (!busy) {
				pbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				pbp->b_mxfs_dir_gen = 0;
				spin_lock(&pbp->b_lock);
				pbp->b_mxfs_stale_pending = false;
				spin_unlock(&pbp->b_lock);
				pr_warn_ratelimited(
					"mxfs: P5-DEFERRED-STALE ino=%llu daddr=%lld — force-invalidated acquire-reload-skipped stale dir block (coherent RMW base)\n",
					(unsigned long long)dp->i_ino,
					(long long)mapp[0].bm_bn);
				xfs_buf_relse(pbp);
				break;
			}
			/* flagged but transiently busy: wait it out (bounded) */
			xfs_buf_relse(pbp);
			if (p5_try == 24) {
				pr_warn_ratelimited(
					"mxfs: P5D-STALE-SERVED ino=%llu daddr=%lld dirty=%d plat_act=%d — deferred-stale block still busy after wait; serving stale view (trans=%d comm=%s realns=%llu)\n",
					(unsigned long long)dp->i_ino,
					(long long)mapp[0].bm_bn, pdirty,
					mxfs_dirblk_platter_active(mp,
						mapp[0].bm_bn),
					tp ? 1 : 0, current->comm,
					(unsigned long long)ktime_get_real_ns());
				break;
			}
			msleep(2);
		}
	}

	/* sess32 (GPT RULE-5): EX-side prior-tenure revalidation.  owned_ex
	 * disables the freshness check entirely (it protects OUR unpublished
	 * work), but the PROVEN dir_reuse loss is an EX holder RMW'ing a CLEAN
	 * prior-tenure base block it did NOT modify this tenure (P-WMERGE
	 * MERGE-NEEDED, held_mode=EX, in_ail=1 = our add on a stale base missing
	 * a peer's durable add).  The tenure_stale (epoch) check below is
	 * owned_ex-INDEPENDENT, and the invalidate clean-guard (!in_ail ||
	 * !undestaged, !dirty, !pinned, !delwri) still keeps our genuine
	 * unpublished work.  Run the read-time revalidation under EX too when
	 * dir_tenure_evict is on (default off -> keeper unaffected). */
	{
	extern int mxfs_dir_tenure_evict;
	bool mxfs_ex_reval = mxfs_dir_tenure_evict && mp->m_mxfs_dlm &&
		!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);
	if (whichfork == XFS_DATA_FORK && nmap == 1 &&
	    S_ISDIR(VFS_I(dp)->i_mode) &&
	    ((!owned_ex && dp->i_dlm_dir_gen != 0) || mxfs_ex_reval)) {
		struct xfs_buf	*cbp = NULL;
		int		inc_rc;

		dir_gen_snap = dp->i_dlm_dir_gen;
		/*
		 * XBF_TRYLOCK: never block here.  A blocking lock on this
		 * dir buffer deadlocks — the buffer can be held by I/O
		 * completion or by a peer's drain while this thread already
		 * holds inode DLM locks (observed: rename wedged in
		 * xfs_buf_lock under xfs_da_read_buf, starving a peer's
		 * inode-DLM grant).  If we can't grab it cleanly we skip the
		 * invalidation; the gen stays mismatched so a later
		 * uncontended read retries it.
		 */
		inc_rc = xfs_buf_incore(mp->m_ddev_targp, mapp[0].bm_bn,
					mapp[0].bm_len, XBF_TRYLOCK, &cbp);
		/* P-RDPATH (RULE-4): decisive — for a dir block0 read, log whether
		 * the buffer is in-core (and its state) or a true cache miss, so we
		 * know if block0 is EVICTED (miss) vs INVALIDATED (in-core !DONE) vs
		 * FUA-forced-reread.  Explains the 0xFF cold-read shutdown. */
		if (bno == 0 && whichfork == XFS_DATA_FORK &&
		    S_ISDIR(VFS_I(dp)->i_mode) && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_ino != mp->m_sb.sb_rootino)
			pr_warn_ratelimited(
				"mxfs: P-RDPATH ino=%llu daddr=%lld inc_rc=%d in_cache=%d DONE=%d fua_fresh=%d gen=%u dirgen=%llu in_ail=%d undest=%d owned_ex=%d dlm_mode=%u comm=%s\n",
				(unsigned long long)dp->i_ino,
				(long long)mapp[0].bm_bn, inc_rc,
				(inc_rc == 0 && cbp) ? 1 : 0,
				(inc_rc == 0 && cbp && (cbp->b_flags & XBF_DONE)) ? 1 : 0,
				(inc_rc == 0 && cbp && (cbp->b_flags & _XBF_FUA_FRESH)) ? 1 : 0,
				(inc_rc == 0 && cbp) ? cbp->b_mxfs_dir_gen : 0,
				(unsigned long long)dp->i_dlm_dir_gen,
				(inc_rc == 0 && cbp && cbp->b_log_item &&
				 test_bit(XFS_LI_IN_AIL, &cbp->b_log_item->bli_item.li_flags)) ? 1 : 0,
				(inc_rc == 0 && cbp && (cbp->b_flags & XBF_DONE)) ?
					(mxfs_dir_buf_is_undestaged(cbp) ? 1 : 0) : -1,
				owned_ex ? 1 : 0, dp->i_dlm_mode, current->comm);
		/*
		 * v0.5.6: a TRUE cache miss (-ENOENT, distinct from a trylock
		 * failure) means the read below fetches the block from disk —
		 * coherent for this tenure, so stamp it post-read.  A trylock
		 * failure stamps nothing (can't inspect; gen stays mismatched
		 * for a later retry — the conservative direction).
		 */
		if (inc_rc == -ENOENT)
			dir_stamp_fresh = true;
		else if (inc_rc != 0) {
			/* sess34 P34-TRYLOCK-STALE: TRYLOCK failed on an EXISTING
			 * cached dir block (-EAGAIN, buffer locked by I/O or a
			 * peer drain) — the read-time invalidation is SKIPPED and
			 * the read below serves the cached (possibly STALE)
			 * XBF_DONE buffer → acquire-side stale-RMW candidate under
			 * contention.  Always-on, capped. */
			static atomic_t p34ts = ATOMIC_INIT(0);
			/* sess5 (46efd8b6): arm the post-read revalidation — the
			 * read below returns this buffer LOCKED, where the gen
			 * check can run race-free. */
			dir_inval_skipped = true;
			if (atomic_inc_return(&p34ts) <= 800)
				pr_warn("mxfs: P34-TRYLOCK-STALE ino=%llu blk=%u daddr=%lld gen=%llu rc=%d\n",
					(unsigned long long)dp->i_ino,
					(unsigned int)bno,
					(long long)mapp[0].bm_bn,
					(unsigned long long)dp->i_dlm_dir_gen,
					inc_rc);
		}
		if (inc_rc == 0 && cbp && !(cbp->b_flags & XBF_DONE)) {
			/*
			 * v0.5.6: an in-core but INVALIDATED buffer (the
			 * BAST/evict fence cleared XBF_DONE and zeroed the
			 * gen) — the read below re-fetches it from disk.
			 * Stamp pre-read, same idiom as the invalidate
			 * branch: the gen only has meaning once XBF_DONE is
			 * set again, at which point the content matches the
			 * snapshot tenure.
			 */
			cbp->b_mxfs_dir_gen = dir_gen_snap;
			/*
			 * sess5 (ccloop, RULE 4 PROVEN) — UNDESTAGED COLD-READ
			 * SALVAGE.  One of the ~10 DONE-clearing sites (evict /
			 * reload / modify-refresh) cleared XBF_DONE on a dir DATA
			 * buffer that is UNDESTAGED — i.e. this node's freshly
			 * created/reused block0 whose content was NEVER written to
			 * disk (multinode dir data blocks destage only at DLM
			 * release, P16=0).  For a REUSED daddr the on-disk image is
			 * a FREED prior owner's un-zeroed dir3 block (or garbage on
			 * a never-written block); re-reading it here returns that
			 * foreign/garbage content and xfs_dir3_block_verify shuts
			 * the FS down (PROVEN fb1 2/tcp cache_coherency: ino=132
			 * daddr=112 read back garbage owner=0x91..; ino=2097281
			 * daddr=2093344 read back owner=2097280).  Our in-core
			 * content is the ONLY authoritative copy and (raw
			 * XBF_DONE-clear sites do not stale the buffer, so) b_addr
			 * is intact — RESTORE XBF_DONE and serve it instead of
			 * cold-reading the stale disk.  Guards: only a genuinely
			 * undestaged (payload-LSN this-node-ahead) buffer whose
			 * in-core header owner matches THIS inode (never an ABA /
			 * foreign block, which must still re-read), not marked
			 * STALE, with a live payload.  Multinode dir only. */
			if (cbp->b_addr &&
			    !(cbp->b_flags & XBF_STALE) &&
			    mp->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
			    mxfs_dir_buf_is_undestaged(cbp) &&
			    !mxfs_dir_data_buf_owner_mismatch(cbp, dp->i_ino)) {
				cbp->b_flags |= XBF_DONE;
				pr_warn_ratelimited(
					"mxfs: P5-UNDEST-SALVAGE ino=%llu daddr=%lld — restored XBF_DONE on undestaged self-owned dir block (skip stale cold-read)\n",
					(unsigned long long)dp->i_ino,
					(long long)mapp[0].bm_bn);
			}
		}
		if (inc_rc == 0 && cbp) {
			struct xfs_buf_log_item	*bip = cbp->b_log_item;
			bool	dirty = bip && test_bit(XFS_LI_DIRTY,
							&bip->bli_item.li_flags);
			bool	in_ail = bip && test_bit(XFS_LI_IN_AIL,
							&bip->bli_item.li_flags);

			/*
			 * Only invalidate a CLEAN cached buffer.  If the buffer
			 * carries unwritten modifications — a dirty buffer log
			 * item, a nonzero pin count (changes still in the CIL),
			 * a committed item still in the AIL awaiting metadata
			 * writeback (sess43: XFS_LI_DIRTY is CLEAR post-commit
			 * and pin==0 post-CIL-push, yet the in-core dirents are
			 * NOT yet on disk — proven for AG-meta via P70:
			 * dirty=0 pin=0 yet disk_differs=1), or a pending delwri
			 * write — its in-memory content is newer than disk, and
			 * re-reading would clobber our own updates (and a later
			 * write of garbage would trip xfs_buf_verify_write ->
			 * SHUTDOWN_CORRUPT_INCORE).  In that case our copy is
			 * authoritative anyway, so leave it.  This mirrors the
			 * dirty-BLI skip in xfs_buf_submit.
			 *
			 * sess43: the OLD guard omitted the in-AIL check, so a
			 * just-committed-but-not-written dir block (this node's
			 * own renamed dirents, in the AIL) was DISCARDED and
			 * re-read from the stale on-disk image → this node's own
			 * dirents vanished from in-core → never written back →
			 * every node missed them (repro_rename_concurrent:
			 * writer N's renames invisible to ALL readers).  An
			 * in-AIL dir block is always THIS node's committed work
			 * (the inode DLM serialises peers; release drains the
			 * AIL), so preserving it is correct.
			 */
			/*
			 * sess64 REVERTED: relaxing this guard to allow a PINNED
			 * buffer through (clear XBF_DONE + re-read) caused
			 * xfs_inode_buf_verify metadata corruption + FS shutdown
			 * on all nodes (build C7BF9BFD).  Even though the CIL copies
			 * buffer content into the log vector at COMMIT time (so the
			 * journal is not corrupted by a later re-read), re-reading a
			 * still-pinned buffer races the writeback/unpin machinery
			 * and clobbers in-core metadata.  The pin guard MUST stay.
			 */
			/*
			 * sess133 (RULE 4, PROVEN true-silent-dirent-loss):
			 * the blanket !in_ail guard above (sess43) also
			 * blocked refreshing a buffer whose content was
			 * DRAINED-DURABLE at the previous release but whose
			 * BLI lingers in the AIL (dirty=0 li_empty=1
			 * disk_differs=1 — 126 DIR-STALE-SKIP events in the
			 * dpn=100 run that lost node3_dir63/64 cluster-wide).
			 * RMW on that stale base clobbers the peer's entries.
			 * Use the payload-LSN discriminator: an in-AIL buffer
			 * whose last mods were already written
			 * (!mxfs_dir_buf_is_undestaged) is safe to refresh —
			 * disk is a superset of our destaged content; only
			 * genuinely committed-unwritten work keeps the sess43
			 * protection.
			 */
			/* sess15: ABA alias = cached dir DATA/BLOCK block whose v5
			 * header owner != the inode we are reading for (daddr freed
			 * from old owner, realloc'd to this dir).  Independent of the
			 * dir-gen (which can collide on reuse), and ALWAYS stale for
			 * this inode, so it must trigger the same invalidate+re-read. */
			bool owner_aba =
				mxfs_dir_data_buf_owner_mismatch(cbp, dp->i_ino);
			/* sess15: SAME-inode-number ABA — a previous incarnation's
			 * buffer stamped with a DIFFERENT (non-zero) i_generation.
			 * 0 = never stamped (e.g. a freshly get_buf-init'd CURRENT
			 * block) → NOT treated as ABA, so a missed stamp site can
			 * never cause us to discard live current work. */
			bool incarn_aba =
				(cbp->b_mxfs_dir_incarn != 0 &&
				 cbp->b_mxfs_dir_incarn != VFS_I(dp)->i_generation);
			/* sess16(ccloop) ALWAYS-ON PRE-READ epoch-stale check: this is
			 * the RELIABLE per-tenure staleness signal, evaluated on EVERY
			 * dir read (fast-path or slow), unlike the slow-path-only evict.
			 * b_mxfs_dir_epoch is stamped to the inode's handoff epoch at
			 * block CREATE (xfs_dir3_data_init/leaf_init) and MODIFY
			 * (xfs_dir2_data_log_entry/header, xfs_dir3_leaf_log_header), so a
			 * cached block whose epoch LAGS i_dlm_dir_valid_epoch was neither
			 * created nor touched since the last cross-node handoff = a stale
			 * prior-tenure base a peer superseded (the count=126->77 clobber's
			 * stale READ).  Like owner/incarn ABA, epoch-lag bypasses the
			 * in_ail-undestaged keep-guard: valid_epoch advances only on a real
			 * handoff where our own work was drained durable (Inv 1), so
			 * discarding it loses nothing current.  Gated dir_evict_prior_tenure. */
			extern int mxfs_dir_evict_prior_tenure;
			extern int mxfs_dir_tenure_evict;
			extern int mxfs_dir_tenure_stale_bypass;
			extern int mxfs_instr_enabled;
			extern int mxfs_dirwr_enabled;
			extern uint32_t mxfs_v5_dlm_inode_dir_epoch(
				struct mxfs_v5_dlm *, uint64_t);
			/* sess16: compare against the MASTER's AUTHORITATIVE handoff
			 * epoch, NOT the local i_dlm_dir_valid_epoch (which LAGS — it is
			 * set only at the end of the reload, after keep-guards that often
			 * short-circuit, so it under-counts real handoffs and the stale
			 * base is never flagged). */
			uint32_t cur_ep = ((mxfs_dir_evict_prior_tenure ||
					    mxfs_dir_tenure_evict) && mp->m_mxfs_dlm)
				? mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm, dp->i_ino)
				: 0;
			/* sess23(ccloop): SYNC the lagging local valid_epoch up to the
			 * reliable master epoch so the post-read b_mxfs_dir_epoch stamp
			 * (which uses valid_epoch) marks this re-read block CURRENT —
			 * else tenure_stale would re-fire every read (b_epoch stuck
			 * below master) and thrash.  Monotonic; master can't advance
			 * mid continuous-hold so a same-tenure block is not flagged. */
			if (mxfs_dir_tenure_evict && cur_ep > dp->i_dlm_dir_valid_epoch)
				dp->i_dlm_dir_valid_epoch = cur_ep;
			bool epoch_stale =
				(mxfs_dir_evict_prior_tenure &&
				 cur_ep != 0 &&
				 cbp->b_mxfs_dir_epoch < cur_ep);
			/* sess23(ccloop): the SAFE read-path prior-tenure signal.  Same
			 * master-epoch compare as epoch_stale, but added ONLY to the
			 * invalidation TRIGGER below — NOT to the keep-guard bypass — so
			 * a genuinely in-AIL-UNDESTAGED current block is still KEPT
			 * (unlike epoch_stale, whose bypass cleared XBF_DONE on in-AIL
			 * buffers during reads -> shutdown).  Relies on the sess23 §9.1
			 * release undestaged-clear so a drained prior-tenure block is
			 * !undestaged -> passes the keep-guard -> gets invalidated.
			 * This covers the !owned_ex addname RMW base read (owned_ex is
			 * false for the shared published dir) that the gen check
			 * under-fired on (bgen==dir_gen). */
			bool tenure_stale =
				(mxfs_dir_tenure_evict &&
				 cur_ep != 0 &&
				 cbp->b_mxfs_dir_epoch < cur_ep);

			if ((cbp->b_flags & XBF_DONE) &&
			    (cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen ||
			     unlikely(mxfs_force_coherent) ||
			     owner_aba || incarn_aba || epoch_stale || tenure_stale) &&
			    !dirty &&
			    /* ABA aliases (owner/incarn mismatch) bypass the
			     * undestaged-in-AIL keep-guard: their committed-unwritten
			     * content belongs to a FREED prior incarnation/owner, not
			     * to us, so discarding it loses nothing current.  Normal
			     * gen-mismatch + tenure_stale still HONOR the guard.
			     * sess38 (ccloop, GPT Policy-A gap-close): when
			     * dir_tenure_stale_bypass is set, a tenure_stale buffer
			     * (b_mxfs_dir_epoch < MASTER epoch) ALSO bypasses the
			     * keep-guard.  Justification: a tenure_stale block was last
			     * touched in a PRIOR tenure (this tenure's blocks carry
			     * b_epoch == valid_epoch == master_epoch, synced above), so
			     * its in-AIL-undestaged "keep" is a FALSE POSITIVE — Inv 1
			     * drained our work at our prior release before the peer's
			     * intervening tenure, so discarding loses nothing current.
			     * This closes the residual where dir_tenure_evict caught
			     * the read but the keep-guard preserved an in_ail-undestaged
			     * stale base = the ~1/3 readdir=799 that slips through. */
			    /* sess5 (ccloop, RULE 4 PROVEN): the `!in_ail` term was
			     * a hole.  AIL presence outlives writeback — a freshly
			     * get_buf-init'd dir block0 over a REUSED/freed daddr
			     * (its disk image still holds the prior owner's un-zeroed
			     * content or garbage) is UNDESTAGED (never written) yet its
			     * BLI can leave the AIL (removed on log-tail advance, not on
			     * write).  Once in_ail=0, `!in_ail` let the gen-mismatch
			     * (b_mxfs_dir_gen=0 vs bumped i_dlm_dir_gen) invalidation
			     * clear XBF_DONE → the read below cold-fetched the stale
			     * disk (foreign owner / garbage) → xfs_dir3_block_verify
			     * owner-mismatch/CRC → shutdown (PROVEN fb1 2/tcp
			     * cache_coherency: ino=2097281 daddr=2093344 read back
			     * owner=2097280; ino=132 daddr=112 read back garbage).  An
			     * UNDESTAGED dir buffer is this-node's authoritative unwritten
			     * content REGARDLESS of AIL membership, so re-reading disk
			     * loses it.  Drop `!in_ail`: keep any undestaged buffer;
			     * genuinely-destaged prior-tenure buffers (undestaged=false)
			     * are still invalidated, and ABA/owner/incarn/epoch cases
			     * (content belongs to a freed prior owner) still bypass. */
			    (owner_aba || incarn_aba || epoch_stale ||
			     (mxfs_dir_tenure_stale_bypass && tenure_stale) ||
			     !mxfs_dir_buf_is_undestaged(cbp)) &&
			    !xfs_buf_ispinned(cbp) &&
			    !(cbp->b_flags & _XBF_DELWRI_Q)) {
				if (unlikely(epoch_stale &&
				    (mxfs_instr_enabled || mxfs_dirwr_enabled)))
					pr_warn_ratelimited("mxfs: P16-PREREAD-EPOCHSTALE ino=%llu blk=%u daddr=%lld buf_epoch=%u master_epoch=%u in_ail=%d — invalidate stale prior-tenure read base\n",
						(unsigned long long)dp->i_ino,
						(unsigned int)bno,
						(long long)mapp[0].bm_bn,
						cbp->b_mxfs_dir_epoch,
						cur_ep, in_ail);
				extern int mxfs_instr_enabled;
				extern int mxfs_dirwr_enabled;

				if (unlikely((owner_aba || incarn_aba) &&
				    (mxfs_instr_enabled || mxfs_dirwr_enabled)))
					pr_warn("mxfs: P15-ABA-DIRINVAL ino=%llu blk=%u daddr=%lld owner_aba=%d incarn_aba=%d buf_incarn=%u cur_gen=%u -> invalidate+re-read\n",
						(unsigned long long)dp->i_ino,
						(unsigned int)bno,
						(long long)mapp[0].bm_bn,
						owner_aba, incarn_aba,
						cbp->b_mxfs_dir_incarn,
						VFS_I(dp)->i_generation);
				if (unlikely(mxfs_instr_enabled))
					pr_warn("mxfs: %s ino=%llu blk=%u buf_gen=%u inode_gen=%u flags=0x%x -> invalidate+re-read\n",
						unlikely(mxfs_force_coherent) ?
						    "P0-FCOH-DIRINVAL" :
						    "P-H18-INVAL",
						(unsigned long long)dp->i_ino,
						(unsigned int)bno,
						cbp->b_mxfs_dir_gen,
						dp->i_dlm_dir_gen,
						cbp->b_flags);
				if (in_ail)
					pr_warn_ratelimited(
						"mxfs: P133-INAIL-REFRESH ino=%llu blk=%u buf_gen=%u inode_gen=%u (destaged in-AIL dir block refreshed)\n",
						(unsigned long long)dp->i_ino,
						(unsigned int)bno,
						cbp->b_mxfs_dir_gen,
						dp->i_dlm_dir_gen);
				{ extern int mxfs_dir_perf_probe;
				  static atomic_t p19i = ATOMIC_INIT(0);
				  if (mxfs_dir_perf_probe &&
				      atomic_inc_return(&p19i) <= 8000)
					pr_warn("mxfs: P19-DIRINVAL daddr=%lld buf_gen=%u dir_gen=%llu owner_aba=%d incarn_aba=%d epoch_stale=%d fcoh=%d comm=%s\n",
						(long long)mapp[0].bm_bn,
						cbp->b_mxfs_dir_gen,
						(unsigned long long)dp->i_dlm_dir_gen,
						owner_aba, incarn_aba, epoch_stale,
						!!mxfs_force_coherent, current->comm);
				}
				/*
				 * sess33 (ccloop 4cb2d0a2, GPT-5.5 consult #2 —
				 * PROVEN root): this is the destructive XBF_DONE-clear
				 * site for the dir_reuse readdir=799 loss.  Clearing
				 * XBF_DONE here (so the read re-fetches the peer's
				 * image) leaves the buffer's BLI in the AIL if one
				 * lingers — a clean, already-DESTAGED BLI that XFS
				 * failed to retire after its last write.  A later AIL
				 * push (xfsaild or a sync push in user ctx) then writes
				 * the now-!DONE STALE b_addr over a peer's durable add =
				 * the durable dirent loss (P-WMERGE DONE=0 in_ail=1
				 * dirty=0 destaged held_mode=EX).  Before invalidating,
				 * RETIRE that zombie BLI (xfs_buf_item_done = the exact
				 * clean-checkpointed AIL retirement xfs_buf iodone runs)
				 * so NO write path can resubmit the stale image.  Safe:
				 * the BLI is in-AIL, clean (!dirty), unpinned, !delwri
				 * and DESTAGED (lseq==wseq) => its content is already on
				 * disk, nothing of ours is lost; we re-read fresh right
				 * after.  cbp is locked (TRYLOCK incore above).  Strict
				 * destaged gate excludes aba/epoch-undestaged (un-landed
				 * prior-incarnation content) — those just clear DONE. */
				extern int mxfs_dir_zombie_retire;
				if (mxfs_dir_zombie_retire && cbp->b_log_item &&
				    test_bit(XFS_LI_IN_AIL,
					     &cbp->b_log_item->bli_item.li_flags) &&
				    !test_bit(XFS_LI_DIRTY,
					      &cbp->b_log_item->bli_item.li_flags) &&
				    !xfs_buf_ispinned(cbp) &&
				    !(cbp->b_flags & _XBF_DELWRI_Q) &&
				    !mxfs_dir_buf_is_undestaged(cbp)) {
					xfs_buf_item_done(cbp);	/* ail_delete+relse */
					if (unlikely(mxfs_instr_enabled ||
						     mxfs_dirwr_enabled))
						pr_warn_ratelimited("mxfs: P33-READ-RETIRE ino=%llu daddr=%lld — retired lingering destaged BLI before read-path invalidate (prevents stale reflush)\n",
							(unsigned long long)dp->i_ino,
							(long long)mapp[0].bm_bn);
				}
				cbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				cbp->b_mxfs_dir_gen = dp->i_dlm_dir_gen;
			} else if ((cbp->b_flags & XBF_DONE) &&
				   cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen) {
				/*
				 * sess39 ALWAYS-ON: the cached dir block is STALE
				 * (gen lags the inode's post-BAST gen) but we did
				 * NOT invalidate it because it is dirty / pinned /
				 * delwri-queued.  Returning this stale image to a
				 * read-modify-write is the block-format-dir LOST
				 * UPDATE that clobbers a peer's just-committed
				 * dirents (the persistent "one node's renames are
				 * invisible to peers" residual).  If this fires
				 * during a failing run, the skip IS the lost-update
				 * window.  Ratelimited so it surfaces in production
				 * without flooding.
				 */
				extern int mxfs_ag_buf_disk_differs(struct xfs_buf *);
				extern int mxfs_instr_enabled;
				/*
				 * v0.5.2: the disk_differs FUA compare-read is
				 * instr-gated.  With the in-AIL evict guard
				 * (publish-only dirsig), every committed-
				 * unwritten dir block of our OWN fresh dirs
				 * takes this branch on every lookup until the
				 * AIL destages it; a synchronous FUA read per
				 * lookup just to enrich a ratelimited log line
				 * dominated the solo-rsync profile.  diff=-2 =
				 * not computed.
				 */
				int diff = unlikely(mxfs_instr_enabled) ?
					mxfs_ag_buf_disk_differs(cbp) : -2;

				pr_warn_ratelimited(
				    "mxfs: DIR-STALE-SKIP ino=%llu blk=%u buf_gen=%u inode_gen=%u flags=0x%x dirty=%d in_ail=%d pin=%d delwri=%d disk_differs=%d pincnt=%d hold=%u has_bli=%d li_empty=%d bli_flags=0x%x lseq=%u wseq=%u undest=%d\n",
				    (unsigned long long)dp->i_ino,
				    (unsigned int)bno,
				    cbp->b_mxfs_dir_gen, dp->i_dlm_dir_gen,
				    cbp->b_flags, dirty, in_ail,
				    xfs_buf_ispinned(cbp),
				    !!(cbp->b_flags & _XBF_DELWRI_Q), diff,
				    atomic_read(&cbp->b_pin_count),
				    cbp->b_hold,
				    bip ? 1 : 0,
				    list_empty(&cbp->b_li_list),
				    bip ? (unsigned int)bip->bli_flags : 0u,
				    cbp->b_mxfs_logged_seq, cbp->b_mxfs_written_seq,
				    mxfs_dir_buf_is_undestaged(cbp));
				/* sess32: THIS is the real stale-RMW-base point — a
				 * cached in-AIL/dirty/pinned dir DATA block whose gen
				 * lags the inode's is being KEPT (sess43 guard) and
				 * served to a read-modify-write, yet the on-disk image
				 * may carry a peer add we lack (P-WMERGE MERGE-NEEDED at
				 * the later async destage).  We cannot re-read it here
				 * (loses our own committed dirents) nor merge here (no
				 * txn).  Arm the modify-path transactional reconcile
				 * (mxfs_dir_reconcile_stale_data_blocks) which PLAIN-reads
				 * disk and re-adds the peer's missing dirents via a proper
				 * dir transaction (data+leaf+freeindex coherent) before
				 * the next destage.  Gated dir_stale_reconcile (keeper
				 * unaffected). */
				{
					extern int mxfs_dir_stale_reconcile;
					if (mxfs_dir_stale_reconcile)
						xfs_iflags_set(dp,
						    MXFS_IF_DIR_DATA_STALE);
				}
			} else if ((cbp->b_flags & XBF_DONE) &&
				   cbp->b_mxfs_dir_gen == dp->i_dlm_dir_gen &&
				   dp->i_ino != mp->m_sb.sb_rootino &&
				   !dirty && !in_ail && !xfs_buf_ispinned(cbp)) {
				/*
				 * sess60 DECISIVE PROBE (RULE 4): the gen MATCHES
				 * (b_mxfs_dir_gen == i_dlm_dir_gen) so the two branches
				 * above both skip — the block is treated as FRESH and
				 * served as-is.  But if a peer modified this block while
				 * our i_dlm_dir_gen failed to advance, the cached content
				 * is STALE despite the gen match, and serving it to a
				 * create/remove RMW durably clobbers the peer's dirent
				 * (the node1_f1 first-block loss, sess28/36).  No probe
				 * covered this case.  Bounded coherent FUA compare vs the
				 * platter: if it DIFFERS, this is the silent stale-serve.
				 * Clean buffers only (a dirty/in-AIL/pinned buffer is our
				 * own ahead-of-disk work and legitimately differs).
				 */
				static atomic_t p60gm = ATOMIC_INIT(0);
				extern int mxfs_dirwr_enabled;
				extern int mxfs_instr_enabled;

				/* sess7: gate the per-hit synchronous FUA
				 * compare-read behind instr — it is a pure
				 * diagnostic costing a device round-trip in
				 * the hot dir-read path (≤3000/boot). */
				if ((mxfs_dirwr_enabled || mxfs_instr_enabled) &&
				    atomic_inc_return(&p60gm) <= 3000) {
					extern int mxfs_ag_buf_disk_differs(
						struct xfs_buf *);
					int d = mxfs_ag_buf_disk_differs(cbp);
					if (d > 0)
						pr_warn("mxfs: P60-GENMATCH-STALE ino=%llu blk=%u daddr=%lld buf_gen=%u inode_gen=%u dlm_mode=%u disk_differs=%d comm=%s (gen-match but content STALE vs disk -> RMW clobber candidate)\n",
							(unsigned long long)dp->i_ino,
							(unsigned int)bno,
							(long long)mapp[0].bm_bn,
							cbp->b_mxfs_dir_gen,
							dp->i_dlm_dir_gen,
							dp->i_dlm_mode, d,
							current->comm);
				}
			}
			xfs_buf_relse(cbp);
		}
	}
	} /* sess32: close EX-side revalidation scope (mxfs_ex_reval) */

	error = xfs_trans_read_buf_map(mp, tp, mp->m_ddev_targp, mapp, nmap, 0,
			&bp, ops);

	/*
	 * sess5 (ccloop 46efd8b6) POST-READ REVALIDATION — the race-free home
	 * of the read-time dir-buffer invalidation.  Runs ONLY when the
	 * pre-read incore(XBF_TRYLOCK) check above was skipped because the
	 * buffer was locked (dir_inval_skipped): we now HOLD the buffer lock
	 * (xfs_trans_read_buf_map returns it locked), so the staleness checks
	 * that were blind at pre-read run deterministically here.  Same keep
	 * guards as the pre-read branch: only a CLEAN (bli-clean, unpinned,
	 * !delwri) destaged buffer is invalidated; an UNDESTAGED buffer is our
	 * own unpublished work and is kept unless it is an ABA alias
	 * (owner/incarn mismatch = content of a freed prior owner).  A
	 * tp-RECURSED buffer (bli_recur>0: this transaction read it earlier
	 * and the gen bumped mid-txn) cannot be re-read —
	 * xfs_trans_read_buf_map's recursion path asserts XBF_DONE and returns
	 * the cached image without I/O — so it is kept and logged (P72-SELFHOLD).
	 * On invalidate: clear XBF_DONE, release (xfs_trans_brelse when joined
	 * to tp, xfs_buf_relse otherwise) and re-read — the fresh read then
	 * takes the dir_stamp_fresh stamps below, so the next read's gen check
	 * passes and this cannot loop.
	 */
	if (dir_inval_skipped && !error && bp && (bp->b_flags & XBF_DONE)) {
		struct xfs_buf_log_item	*rbli = bp->b_log_item;
		bool rdirty = rbli && test_bit(XFS_LI_DIRTY,
					       &rbli->bli_item.li_flags);
		bool r_in_ail = rbli && test_bit(XFS_LI_IN_AIL,
						 &rbli->bli_item.li_flags);
		bool r_owner_aba = mxfs_dir_data_buf_owner_mismatch(bp,
								    dp->i_ino);
		bool r_incarn_aba = (bp->b_mxfs_dir_incarn != 0 &&
				     bp->b_mxfs_dir_incarn !=
				     VFS_I(dp)->i_generation);
		bool r_stale = (bp->b_mxfs_dir_gen != dp->i_dlm_dir_gen) ||
			       r_owner_aba || r_incarn_aba;
		extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *);

		if (r_stale && tp && rbli && rbli->bli_recur > 0) {
			pr_warn_ratelimited(
			    "mxfs: P72-SELFHOLD-STALE ino=%llu blk=%u daddr=%lld buf_gen=%u inode_gen=%llu recur=%d — txn re-read of own gen-stale dir buf; serving txn image\n",
			    (unsigned long long)dp->i_ino, (unsigned int)bno,
			    (long long)mapp[0].bm_bn, bp->b_mxfs_dir_gen,
			    (unsigned long long)dp->i_dlm_dir_gen,
			    rbli->bli_recur);
		} else if (r_stale && !rdirty && !xfs_buf_ispinned(bp) &&
			   !(bp->b_flags & _XBF_DELWRI_Q) &&
			   (r_owner_aba || r_incarn_aba ||
			    !mxfs_dir_buf_is_undestaged(bp))) {
			extern int mxfs_dir_zombie_retire;

			pr_warn_ratelimited(
			    "mxfs: P72-POSTREAD-INVAL ino=%llu blk=%u daddr=%lld buf_gen=%u inode_gen=%llu owner_aba=%d incarn_aba=%d in_ail=%d tp=%d dlm_mode=%u comm=%s — trylock-skipped stale dir buf invalidated under read lock\n",
			    (unsigned long long)dp->i_ino, (unsigned int)bno,
			    (long long)mapp[0].bm_bn, bp->b_mxfs_dir_gen,
			    (unsigned long long)dp->i_dlm_dir_gen,
			    r_owner_aba, r_incarn_aba, r_in_ail, tp ? 1 : 0,
			    dp->i_dlm_mode, current->comm);
			/* sess33 zombie-BLI retire (P33 parity): a lingering
			 * clean destaged in-AIL BLI would reflush the stale
			 * image after we clear DONE.  Retire it first — but
			 * only when NOT joined to a transaction (with tp the
			 * buffer was just bjoined; ripping its bli out from
			 * under the txn is unsafe — xfs_trans_brelse below
			 * releases the join properly instead). */
			if (mxfs_dir_zombie_retire && !tp && rbli &&
			    r_in_ail && !rdirty && !xfs_buf_ispinned(bp) &&
			    !(bp->b_flags & _XBF_DELWRI_Q) &&
			    !mxfs_dir_buf_is_undestaged(bp))
				xfs_buf_item_done(bp);
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			bp->b_mxfs_dir_gen = dp->i_dlm_dir_gen;
			if (tp)
				xfs_trans_brelse(tp, bp);
			else
				xfs_buf_relse(bp);
			bp = NULL;
			error = xfs_trans_read_buf_map(mp, tp, mp->m_ddev_targp,
					mapp, nmap, 0, &bp, ops);
			if (!error && bp)
				dir_stamp_fresh = true;
		}
	}

	/*
	 * sess61 DECISIVE PROBE (RULE 4): after reading block0 of a multinode
	 * non-root dir, scan the freshly-read IN-CORE buffer AND an independent
	 * FUA read of the SAME daddr from the platter for node1's dirent name
	 * bytes ("node1_f").  This separates the two surviving hypotheses for the
	 * durable node1_f* peer-miss (extent maps PROVEN to agree -> NOT a split):
	 *   disk_n1>0 && core_n1==0  => re-read served STALE (read-side / FUA gate)
	 *   disk_n1==0               => node1's block0 writes never landed on disk
	 *                               at this daddr (WRITE-side durability)
	 */
	{ extern int mxfs_instr_enabled; /* sess61: gate the per-read FUA probe
	  * (synchronous SCSI FUA per block0 read) behind mxfs.instr — it badly
	  * perturbs the create-heavy timing (amplifies the race ~1-2/20 -> 15/24).
	  * Default OFF so runs are representative; set mxfs.instr=1 to diagnose. */
	if (unlikely(mxfs_instr_enabled) &&
	    !error && bp && bp->b_addr && bno == 0 &&
	    whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dp->i_ino != mp->m_sb.sb_rootino) {
		static atomic_t p61 = ATOMIC_INIT(0);
		if (atomic_inc_return(&p61) <= 20000) {
			extern int mxfs_pal_scsi_read_fua_bdev(
				struct block_device *, uint64_t, void *, uint32_t);
			uint32_t  len = BBTOB(bp->b_length);
			uint64_t  lba = (uint64_t)mapp[0].bm_bn +
				bp->b_target->bt_sector_offset;
			void     *disk = kmalloc(len, GFP_NOFS);
			int       core_n1 = 0, disk_n1 = 0, frc = -1;
			uint32_t  off;
			const char needle[7] = {'n','o','d','e','1'};
			const u8 *cb = bp->b_addr;

			/* scan in-core buffer for "node1" name bytes */
			for (off = 0; off + 5 <= len; off++)
				if (cb[off] == 'n' && cb[off+1]=='o' &&
				    cb[off+2]=='d' && cb[off+3]=='e' &&
				    cb[off+4]=='1')
					core_n1++;
			if (disk) {
				frc = mxfs_pal_scsi_read_fua_bdev(
					bp->b_target->bt_bdev, lba, disk, len);
				if (frc == 0) {
					const u8 *db = disk;
					for (off = 0; off + 5 <= len; off++)
						if (db[off]=='n' && db[off+1]=='o' &&
						    db[off+2]=='d' && db[off+3]=='e' &&
						    db[off+4]=='1')
							disk_n1++;
				}
				kfree(disk);
			}
			(void)needle;
			{
				struct xfs_buf_log_item *bbi = bp->b_log_item;
				int b_dirty = (bbi && test_bit(XFS_LI_DIRTY,
					&bbi->bli_item.li_flags)) ? 1 : 0;
				int b_inail = (bbi && test_bit(XFS_LI_IN_AIL,
					&bbi->bli_item.li_flags)) ? 1 : 0;
				int b_pin = xfs_buf_ispinned(bp) ? 1 : 0;
				int exn = 0, exp = -1;
				/* sess61 A/B DISCRIMINATOR: when the in-core block0 is
				 * BEHIND disk under a writer (stale base), read the
				 * concurrent dir-inode EX popcount.  exp>1 == a peer ALSO
				 * holds EX right now == DLM double-grant (case B, no
				 * dir-layer fix helps).  exp<=1 == single holder == case A
				 * (stale cached/own buffer not refreshed). */
				if (core_n1 < disk_n1 && frc == 0 && mp->m_mxfs_dlm)
					exp = mxfs_v5_dlm_inode_ex_count(
						mp->m_mxfs_dlm, dp->i_ino, &exn);
				pr_warn("mxfs: P61-BLK0 ino=%llu i_gen=%u daddr=%lld len=%u core_node1=%d disk_node1=%d fua_rc=%d dir_gen=%llu bufgen=%u incarn=%u dirty=%d inail=%d pin=%d ex_pop=%d ex_nslots=%d dlm_mode=%d comm=%s\n",
					(unsigned long long)dp->i_ino,
					VFS_I(dp)->i_generation,
					(long long)mapp[0].bm_bn, len,
					core_n1, disk_n1, frc,
					(unsigned long long)dp->i_dlm_dir_gen,
					bp->b_mxfs_dir_gen, bp->b_mxfs_dir_incarn,
					b_dirty, b_inail, b_pin, exp, exn,
					dp->i_dlm_mode, current->comm);
			}
		}
	} }

	/*
	 * MXFS torn-read recovery (sess39).  A peer node that released the
	 * dir inode DLM lock before its dir-block write bio reached the
	 * platter leaves a window where our FUA read of the same block can
	 * observe a partially-written image: half the old bytes, half the
	 * new, so the on-disk CRC matches neither -> -EFSBADCRC (errno 74,
	 * the "Metadata I/O error ... error 74" + xfs_da_read_buf shutdown
	 * we see under concurrent same-dir rename).  This is transient: once
	 * the peer's bio lands, a re-read returns a coherent, verifying
	 * block.  Distinguish a transient torn read (retry succeeds) from
	 * genuine on-disk corruption (retry keeps failing) and, for the
	 * transient case, recover instead of shutting the filesystem down.
	 *
	 * Scope tightly: DATA-fork directory blocks only, and only the
	 * verifier-failure errnos a torn image produces.  A torn buffer is
	 * left in-core flagged !XBF_DONE with b_error set; stale it so the
	 * retry re-reads from disk rather than returning the cached error.
	 */
	if ((error == -EFSBADCRC || error == -EFSCORRUPTED) &&
	    whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode)) {
		extern int mxfs_instr_enabled;
		int		tr;

		/*
		 * sess39 diagnostic: dump the in-memory data-fork extent map
		 * that produced this daddr.  The corrupt block read back as an
		 * INODE cluster (magic "IN"), meaning the dir's logical block
		 * mapped to a daddr owned by an inode cluster — either a stale
		 * in-memory extent map (coherency) or a double-allocated block
		 * (AG free-space lost-update).  Comparing this map to the
		 * on-disk dinode (read post-mortem from the device) tells which.
		 */
		if (unlikely(mxfs_instr_enabled)) {
			struct xfs_ifork	*ifp = &dp->i_df;
			struct xfs_iext_cursor	dcur;
			struct xfs_bmbt_irec	drec;
			int			ne = 0;

			pr_warn("mxfs: P-EMAP ino=%llu bno=%u daddr=%llu fmt=%d nextents=%llu disk_size=%lld dlm_stale=%d dlm_mode=%d\n",
				(unsigned long long)dp->i_ino,
				(unsigned int)bno,
				(unsigned long long)mapp[0].bm_bn,
				ifp->if_format,
				(unsigned long long)ifp->if_nextents,
				(long long)dp->i_disk_size,
				dp->i_dlm_stale, dp->i_dlm_mode);
			for_each_xfs_iext(ifp, &dcur, &drec) {
				pr_warn("mxfs: P-EMAP   ext[%d] off=%llu sblk=%llu cnt=%llu\n",
					ne, (unsigned long long)drec.br_startoff,
					(unsigned long long)drec.br_startblock,
					(unsigned long long)drec.br_blockcount);
				if (++ne >= 6)
					break;
			}
		}

		for (tr = 0; tr < 8; tr++) {
			struct xfs_buf	*sbp = NULL;

			/* Drop the torn cached buffer so the retry re-reads. */
			if (xfs_buf_incore(mp->m_ddev_targp, mapp[0].bm_bn,
					   mapp[0].bm_len, XBF_TRYLOCK,
					   &sbp) == 0 && sbp) {
				xfs_buf_stale(sbp);
				sbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				xfs_buf_relse(sbp);
			}

			msleep(5);

			error = xfs_trans_read_buf_map(mp, tp,
					mp->m_ddev_targp, mapp, nmap, 0,
					&bp, ops);
			if (unlikely(mxfs_instr_enabled))
				pr_warn("mxfs: P-TORN ino=%llu blk=%u daddr=%llu try=%d rc=%d%s\n",
					(unsigned long long)dp->i_ino,
					(unsigned int)bno,
					(unsigned long long)mapp[0].bm_bn,
					tr, error,
					error ? "" : " RECOVERED");
			if (error != -EFSBADCRC && error != -EFSCORRUPTED)
				break;
		}
	}

	/*
	 * sess54 (ccloop 14d31183) DECISIVE PROBE — torn-read retry exhausted
	 * on a DATA-fork dir block.  Plain-read the daddr straight from the
	 * device (bypassing the cache that just failed verify) and report
	 * whether the DISK copy is self-consistent: magic, owner (== reading
	 * dir's ino?), and CRC.  This disambiguates:
	 *   disk_ok=1 owner_ok=1 => the CACHE held a torn/overlapped image
	 *      (peer write still in flight at EX (re)acquire / incomplete
	 *      drain-before-release) — disk is fine, fix = read disk / finish
	 *      the peer's write before releasing the dir lock.
	 *   disk_ok=0           => DURABLE on-disk corruption (a torn write
	 *      was destaged, or the block is double-allocated).
	 *   owner_ok=0          => the reader's EXTENT MAP is stale and maps
	 *      this dir offset onto another inode's block (aliasing).
	 * Ungated + ratelimited so it surfaces in a clean instr=0 run.
	 */
	if ((error == -EFSBADCRC || error == -EFSCORRUPTED) &&
	    whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
				uint64_t, void *, uint32_t);
		struct xfs_buftarg *dtp = mp->m_ddev_targp;
		uint32_t blen = BBTOB(mapp[0].bm_len);
		void	*tmp = ((blen & 511) == 0 && blen) ?
				kmalloc(blen, GFP_NOFS) : NULL;

		if (tmp && dtp && dtp->bt_bdev &&
		    mxfs_pal_bdev_read_plain_bdev(dtp->bt_bdev,
			(uint64_t)mapp[0].bm_bn + dtp->bt_sector_offset,
			tmp, blen) == 0) {
			struct xfs_dir3_blk_hdr *h = tmp;
			__be32	magic = h->magic;
			uint64_t owner = be64_to_cpu(h->owner);
			int	magic_ok = (magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC) ||
					    magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC));
			int	crc_ok = xfs_verify_cksum(tmp, blen,
					offsetof(struct xfs_dir3_blk_hdr, crc));

			pr_warn_ratelimited(
			    "mxfs: P54-DIRBLK-PROBE rdr_ino=%llu bno=%u daddr=%llu disk_magic=0x%x magic_ok=%d disk_owner=%llu owner_ok=%d disk_crc_ok=%d rc=%d\n",
			    (unsigned long long)dp->i_ino, (unsigned)bno,
			    (unsigned long long)mapp[0].bm_bn,
			    be32_to_cpu(magic), magic_ok,
			    (unsigned long long)owner,
			    owner == dp->i_ino, crc_ok, error);

			/*
			 * sess5(a9a03929) P55-TORN-DIFF: run75 live repro — every
			 * userspace read of this daddr (plain, O_DIRECT, SG_IO FUA)
			 * returns a clean self-consistent image, yet this kernel read
			 * path fails CRC deterministically across a full remount.
			 * Diff the failing in-core buffer against the clean plain-read
			 * image per 512B sector to name exactly WHICH bytes the kernel
			 * path assembled differently (torn tail? unfilled page? wrong
			 * LBA fragment?).
			 */
			{
				struct xfs_buf	*dbp = NULL;

				if (xfs_buf_incore(mp->m_ddev_targp,
						   mapp[0].bm_bn, mapp[0].bm_len,
						   XBF_TRYLOCK, &dbp) == 0 && dbp) {
					const u8	*ka = dbp->b_addr;
					const u8	*pa = tmp;
					unsigned int	ds, dmask = 0, first;

					for (ds = 0; ds < blen / 512; ds++)
						if (memcmp(ka + ds * 512,
							   pa + ds * 512, 512))
							dmask |= 1u << ds;
					for (first = 0; first < blen &&
						     ka[first] == pa[first]; first++)
						;
					pr_warn("mxfs: P55-TORN-DIFF daddr=%llu flags=0x%x err=%d fua_fresh=%d done=%d stale=%d secmask=0x%x firstdiff=%u incore=%16ph plain=%16ph\n",
						(unsigned long long)mapp[0].bm_bn,
						(unsigned)dbp->b_flags,
						dbp->b_error,
						!!(dbp->b_flags & _XBF_FUA_FRESH),
						!!(dbp->b_flags & XBF_DONE),
						!!(dbp->b_flags & XBF_STALE),
						dmask, first,
						ka + (first < blen ? (first & ~15u) : 0),
						pa + (first < blen ? (first & ~15u) : 0));
					xfs_buf_relse(dbp);
				} else {
					pr_warn("mxfs: P55-TORN-DIFF daddr=%llu NO-INCORE-BUF\n",
						(unsigned long long)mapp[0].bm_bn);
				}
			}
		}
		kfree(tmp);
	}

	if (xfs_metadata_is_sick(error))
		xfs_dirattr_mark_sick(dp, whichfork);
	/*
	 * ENODATA from disk implies a disk medium failure; ENODATA for
	 * xattrs means attribute not found, so disambiguate that here.
	 */
	if (error == -ENODATA && whichfork == XFS_ATTR_FORK)
		error = -EIO;
	if (error)
		goto out_free;

	if (whichfork == XFS_ATTR_FORK)
		xfs_buf_set_ref(bp, XFS_ATTR_BTREE_REF);
	else
		xfs_buf_set_ref(bp, XFS_DIR_BTREE_REF);
	/*
	 * v0.5.6: stamp a freshly disk-read dir block with the tenure gen
	 * snapshotted at hook time (see dir_stamp_fresh above).  If another
	 * thread raced us and inserted the buffer first, its content still
	 * came from a disk read after our -ENOENT lookup, so the snapshot
	 * gen remains a valid lower bound.
	 */
	if (dir_stamp_fresh && bp->b_mxfs_dir_gen != dir_gen_snap)
		bp->b_mxfs_dir_gen = dir_gen_snap;
	/* sess10(ccloop): a genuinely disk-read dir block is coherent under the
	 * owning inode's CURRENT grant.  Stamp grant gen ONLY on a real fresh read
	 * (dir_stamp_fresh) — never on a bare cache hit (that would mark a stale
	 * cached block current, the bug this guards).  DATA-fork dir only. */
	if (dir_stamp_fresh && whichfork == XFS_DATA_FORK &&
	    S_ISDIR(VFS_I(dp)->i_mode)) {
		bp->b_mxfs_grant_gen = dp->i_dlm_cached_grant_gen;
		/* sess16: this block is coherent for the inode's current handoff
		 * epoch (freshly disk-read) -> stamp it so a later tenure that
		 * advances valid_epoch marks it stale. */
		bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch;
		/* sess50: a freshly disk-read block is coherent under the inode's
		 * CURRENT local release-epoch -> stamp it so the writeback gate
		 * (skip-if relepoch < i_dlm_epoch) never wrongly skips a current
		 * coherent image, only a pre-release stale one. */
		bp->b_mxfs_relepoch = (uint32_t)dp->i_dlm_epoch;
	}
	/*
	 * sess15: stamp the owning dir inode's CURRENT incarnation (i_generation)
	 * on every dir DATA-fork buffer we hand back — the buffer now reflects
	 * THIS inode incarnation's content (freshly disk-read, or a cache hit we
	 * just validated).  A later cache hit whose stamp differs from the
	 * reading inode's i_generation is a previous-incarnation ABA alias of a
	 * reused inode#/daddr and is invalidated (above + the evict path).
	 * Unconditional (not gated on dir_stamp_fresh) so an invalidate+re-read
	 * re-stamps the fresh incarnation and cannot loop.
	 */
	if (whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode))
		bp->b_mxfs_dir_incarn = VFS_I(dp)->i_generation;

	/*
	 * sess50(ccloop) GPT-5.5 MODIFY-TIME stale-cache fix (the real loss vector):
	 * a CLEAN cached dir DATA/leaf buffer whose image predates a grant RELEASE by
	 * this node (b_mxfs_relepoch < dp->i_dlm_epoch) is served to an addname RMW as
	 * the base.  The victim region a peer durably filled still reads as a valid
	 * xfs_dir2_data_unused record in this stale image, so addname consumes it and
	 * OVERWRITES the peer's dirent (count-preserving, self-consistent, durable =
	 * the dir_reuse readdir=799 single-dirent loss).  The writeback relepoch gate
	 * could NOT catch this (the buffer gets re-stamped CURRENT when modified), so
	 * the epoch rule MUST also apply at buffer USE.  i_dlm_epoch is the RELIABLE
	 * LOCAL release counter (immune to the grant_gen/handoff underfire).  On a
	 * stale-by-epoch CLEAN cache hit, FUA-re-read the peer's durable image before
	 * the RMW.  Always-on for multinode shared non-root dirs; a fresh disk read
	 * (dir_stamp_fresh) is stamped current so it never loops.  CLEAN-only: dirty/
	 * pinned/undestaged is our own current-tenure work (epoch cannot advance while
	 * we hold the grant) -> never tossed.
	 */
	if (bp && bp->b_addr && whichfork == XFS_DATA_FORK &&
	    S_ISDIR(VFS_I(dp)->i_mode) && !dir_stamp_fresh &&
	    (bp->b_flags & XBF_DONE) &&
	    (bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_block_buf_ops ||
	     bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	     bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	     bp->b_ops == &xfs_da3_node_buf_ops) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dp->i_ino != mp->m_sb.sb_rootino &&
	    bp->b_mxfs_relepoch != 0 &&
	    bp->b_mxfs_relepoch < (uint32_t)dp->i_dlm_epoch) {
		extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *);
		extern int mxfs_dir_relepoch_reread;
		struct xfs_buf_log_item *ebli = bp->b_log_item;
		bool edirty = ebli && test_bit(XFS_LI_DIRTY,
				&ebli->bli_item.li_flags);
		if (mxfs_dir_relepoch_reread && !edirty &&
		    !xfs_buf_ispinned(bp) &&
		    !(bp->b_flags & _XBF_DELWRI_Q) &&
		    !mxfs_dir_buf_is_undestaged(bp)) {
			pr_warn_ratelimited(
			    "mxfs: P50-RELEPOCH-REREAD ino=%llu blk=%u daddr=%lld relepoch=%u i_dlm_epoch=%lu — CLEAN stale-by-release cache hit; FUA re-read peer's durable base before RMW\n",
			    (unsigned long long)dp->i_ino, (unsigned int)bno,
			    (long long)mapp[0].bm_bn, bp->b_mxfs_relepoch,
			    dp->i_dlm_epoch);
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			xfs_buf_relse(bp);
			bp = NULL;
			error = xfs_trans_read_buf_map(mp, tp, mp->m_ddev_targp,
					mapp, nmap, 0, &bp, ops);
			if (error)
				goto out_free;
			if (bp) {
				bp->b_mxfs_relepoch = (uint32_t)dp->i_dlm_epoch;
				bp->b_mxfs_dir_incarn = VFS_I(dp)->i_generation;
				bp->b_mxfs_grant_gen = dp->i_dlm_cached_grant_gen;
				bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch;
				xfs_buf_set_ref(bp, XFS_DIR_BTREE_REF);
			}
		}
	}

	/*
	 * sess50(ccloop) RULE-4 content-history trace: log the dirent count of the
	 * dir DATA/BLOCK image populated into b_addr at READ-completion, with the
	 * fresh/cache-hit + FUA-fresh state and wall-clock.  Merge by realns with the
	 * write-submit P50-WR trace to reconstruct the daddr-120 count timeline and
	 * find the BACKWARD step (the sess69 reversion: a READ repopulating stale
	 * content older than a prior durable write -> the xfsaild clobber).  dirwr-gated.
	 */
	if (whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) && bp &&
	    bp->b_addr &&
	    (bp->b_ops == &xfs_dir3_data_buf_ops ||
	     bp->b_ops == &xfs_dir3_block_buf_ops)) {
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		/* sess10(a9a03929): also fire for the armed watch ino — the
		 * consumer-side content record (count+sum of the image the
		 * caller is about to walk/RMW).  NO platter read here: the
		 * per-da_read sync read amplified I/O ~6000x/min and collapsed
		 * the timing-sensitive tests (s10 iter5 tds window miss).  The
		 * placement-time P49-STALEBASE walk + on-miss P10-DIRDUMP
		 * carry the platter side.  plat=-3 always (field kept for
		 * parser compat). */
		bool p50w = READ_ONCE(mxfs_watch_ino) > 1 &&
			    mxfs_ino_watched(dp->i_ino);
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled || p50w)) {
			extern uint32_t mxfs_dir3_data_fingerprint(struct xfs_mount *,
				const void *, uint32_t, bool, uint32_t *, uint32_t *);
			bool isblk = (bp->b_ops == &xfs_dir3_block_buf_ops);
			uint32_t s = 0, x = 0;
			uint32_t cnt = mxfs_dir3_data_fingerprint(mp, bp->b_addr,
					BBTOB(bp->b_length), isblk, &s, &x);
			pr_warn("mxfs: P50-RD owner=%llu daddr=%lld cnt=%u sum=%u plat=%d incarn=%u relepoch=%u i_dlm_epoch=%lu mode=%d fresh=%d fua_fresh=%d realns=%llu comm=%s\n",
				(unsigned long long)dp->i_ino,
				(long long)mapp[0].bm_bn, cnt, s, -3,
				VFS_I(dp)->i_generation,
				bp->b_mxfs_relepoch, dp->i_dlm_epoch,
				dp->i_dlm_mode,
				dir_stamp_fresh ? 1 : 0,
				(bp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
				(unsigned long long)ktime_get_real_ns(),
				current->comm);
		}
	}

	/*
	 * sess67 (GPT-5.5 RULE-5 design): UNDER-BUFFER-LOCK dir-block coherency
	 * backstop.  The pre-read gen-invalidation above uses XBF_TRYLOCK and
	 * SKIPS a transiently-locked cached buffer (P34-TRYLOCK-STALE) — serving a
	 * STALE XBF_DONE dir DATA/leaf block to the RMW, which durably clobbers a
	 * peer's dirent (dir_reuse_coherency 4/tcp: one node's entry lost on ALL
	 * nodes).  bp is now held+locked by us (xfs_trans_read_buf_map returns it
	 * locked), so re-reading here is deadlock-free — no trylock, no extra
	 * lock-ordering vs a peer drain.  If this is a multinode non-root dir
	 * DATA/leaf CACHE HIT whose b_mxfs_dir_gen lags i_dlm_dir_gen (reliably
	 * bumped on every slow-path post-handoff re-acquire) AND it is CLEAN (no
	 * dirty/pinned/in-AIL/delwri/undestaged local work — that is our own
	 * committed-unwritten dirents, which MUST be kept, never clobbered), the
	 * pre-read invalidation was skipped: FUA-re-read the peer's durable image
	 * before any RMW.  A genuinely fresh read is stamped == i_dlm_dir_gen
	 * (dir_stamp_fresh) so it never re-reads here (no loop / no cold double-read).
	 */
	{
		extern int mxfs_dir_postread_reread;
		extern int mxfs_dir_postread_leaf_only;
		extern bool mxfs_dir_buf_is_undestaged(struct xfs_buf *);
		/*
		 * sess20(ccloop) PROVEN (RULE 4): the dir_reuse low-mht
		 * DABUF_MAP_HOLE shutdown is a STALE cached LEAF block that still
		 * references DATA blocks a peer legitimately freed (P14/P15 probe:
		 * extent map fresh+consistent {0,5,leaf}, but the leaf walk asks
		 * for freed blocks 1-4 -> hole).  postread_reread FUA-re-reads the
		 * stale leaf -> DABUF_HOLE eliminated (count 6-60 -> 0).  BUT the
		 * SAME postread, applied to a hot DATA block, FUA-reads the PLATTER
		 * which LAGS the target's writeback cache (sess13 torn-read) ->
		 * Metadata CRC error on dir3_data block 0x70 -> new shutdown.  DATA
		 * blocks read coherently via the NORMAL path (the release-invalidate
		 * run had NO CRC errors); only the LEAF/NODE mapping blocks need the
		 * forced refresh to fix the hole.  leaf_only=1 (default) restricts
		 * the re-read to leaf/node ops so we fix the hole without tearing a
		 * data block.
		 */
		bool postread_is_mapblk =
			(ops == &xfs_dir3_leaf1_buf_ops ||
			 ops == &xfs_dir3_leafn_buf_ops ||
			 ops == &xfs_da3_node_buf_ops);

		if (mxfs_dir_postread_reread && bp &&
		    (!mxfs_dir_postread_leaf_only || postread_is_mapblk) &&
		    whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_ino != mp->m_sb.sb_rootino &&
		    (bp->b_flags & XBF_DONE) &&
		    (bp->b_mxfs_dir_gen < dp->i_dlm_dir_gen ||
		     /* sess10(ccloop) GPT-5.5 freshness-by-provenance: the lossy
		      * i_dlm_dir_gen gets stamped FRESH over STALE content (PROVEN:
		      * the 4/tcp dir_reuse clobber is stale_base=0 — invisible to the
		      * dir_gen gate above), so an EX RMW serves a stale base.  The
		      * acked-TCP grant gen is reliable: if this cached block was last
		      * coherently read under an OLDER grant than the inode currently
		      * holds (i_dlm_cached_grant_gen), we lost+reacquired EX since (a
		      * peer modified) -> the block is stale -> re-read it.  EX-only:
		      * the modify path is where the clobber happens, and cached_grant_gen
		      * is maintained on EX acquires; the clean+destaged guard below
		      * preserves our own committed-unwritten work (no resurrection). */
		     (dp->i_dlm_mode == 5 /* MXFS_LOCK_EX (enum not in scope here) */ &&
		      bp->b_mxfs_grant_gen != dp->i_dlm_cached_grant_gen) ||
		     /* sess16(ccloop) GPT-5.5 TENURE trigger: this block was read under
		      * an OLDER coherent epoch than the inode now knows (a peer was
		      * granted+modified the LUN since) -> stale RMW base regardless of
		      * grant mode (covers the PR/NL reader AND the cross-tenure cached-EX
		      * RMW the grant_gen trigger missed -> the count=126 -> count=77
		      * durable revert).  Reliable level-triggered epoch, not the lossy
		      * dir_gen / overfiring grant_gen. */
		     (dp->i_dlm_dir_valid_epoch != 0 &&
		      bp->b_mxfs_dir_epoch < dp->i_dlm_dir_valid_epoch))) {
			struct xfs_buf_log_item *bli = bp->b_log_item;
			bool dirty = bli && test_bit(XFS_LI_DIRTY,
						&bli->bli_item.li_flags);
			bool in_ail = bli && test_bit(XFS_LI_IN_AIL,
						&bli->bli_item.li_flags);
			/* sess16: a block stale-by-EPOCH was last read in a PRIOR tenure,
			 * which ended only because WE released EX (Invariant-1 drained our
			 * work durable) -> any in-AIL/undestaged content is already on the
			 * LUN, so it is safe to discard+re-read (OVERRIDE the payload-LSN
			 * undestaged keep-guard that wrongly preserved test2's stale 77
			 * base).  dirty/pinned/delwri are genuine in-flight LOCAL work in the
			 * CURRENT tenure (epoch cannot advance while we hold EX) -> still
			 * hard-guarded, never clobbered. */
			bool epoch_stale = (dp->i_dlm_dir_valid_epoch != 0 &&
					    bp->b_mxfs_dir_epoch <
						dp->i_dlm_dir_valid_epoch);
			bool clean = !dirty &&
				!xfs_buf_ispinned(bp) &&
				!(bp->b_flags & _XBF_DELWRI_Q) &&
				(epoch_stale ||
				 (!in_ail && !mxfs_dir_buf_is_undestaged(bp)));

			if (clean) {
				uint32_t want = dp->i_dlm_dir_gen;

				pr_warn_ratelimited(
				    "mxfs: P67-POSTREAD-REREAD ino=%llu blk=%u daddr=%lld bufgen=%u inodegen=%u — stale clean cache-hit escaped pre-read inval; FUA re-read under held lock\n",
				    (unsigned long long)dp->i_ino,
				    (unsigned int)bno,
				    (long long)mapp[0].bm_bn,
				    bp->b_mxfs_dir_gen, want);

				bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				xfs_buf_relse(bp);
				bp = NULL;
				error = xfs_trans_read_buf_map(mp, tp,
						mp->m_ddev_targp, mapp, nmap, 0,
						&bp, ops);
				if (error)
					goto out_free;
				if (bp) {
					bp->b_mxfs_dir_gen = want;
					bp->b_mxfs_dir_incarn =
						VFS_I(dp)->i_generation;
					/* sess10(ccloop): mark this block coherent under
					 * the CURRENT grant so a same-tenure re-read does
					 * not loop. */
					bp->b_mxfs_grant_gen =
						dp->i_dlm_cached_grant_gen;
					/* sess16: coherent for the current handoff
					 * epoch (just FUA-re-read the peer's image). */
					bp->b_mxfs_dir_epoch =
						dp->i_dlm_dir_valid_epoch;
					xfs_buf_set_ref(bp, XFS_DIR_BTREE_REF);
				}
			}
		}
	}

	/*
	 * sess19 LEAF-HASH stale-read detector (RULE 4).  PROVEN this session:
	 * the 2/tcp cc_blockdir_probe "loss" is a dir LEAF hash-index vs DATA
	 * block inconsistency — the leaf block, read on the modify path from a
	 * STALE base (the read keep-guard refused to refresh a pinned/undestaged
	 * leaf, DIR-STALE-SKIP pin=1 undest=1), gets RMW'd MISSING the peer's
	 * committed hash entries, so readdir lists the name (durable in the data
	 * block) but lookup ENOENTs (its hash is gone from the leaf).  After a
	 * successful leaf-block read, plain-read the COHERENT on-disk leaf
	 * (coherent SCST cache under fua_disable=1) and compare entry counts: a
	 * buffer count BELOW disk means we are about to RMW a leaf that is
	 * missing the peer's hash entries.  Gated (dirwr/instr); fires only on a
	 * genuine buf<disk shortfall.
	 */
	{
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;

		if (!error && bp &&
		    (ops == &xfs_dir3_leaf1_buf_ops ||
		     ops == &xfs_dir3_leafn_buf_ops) &&
		    whichfork == XFS_DATA_FORK && S_ISDIR(VFS_I(dp)->i_mode) &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
			struct xfs_buftarg *dtp = mp->m_ddev_targp;
			uint32_t blen = BBTOB(mapp[0].bm_len);
			void *tmp = ((blen & 511) == 0 && blen) ?
					kmalloc(blen, GFP_NOFS) : NULL;

			if (tmp && dtp && dtp->bt_bdev &&
			    mxfs_pal_bdev_read_plain_bdev(dtp->bt_bdev,
				(uint64_t)mapp[0].bm_bn + dtp->bt_sector_offset,
				tmp, blen) == 0) {
				struct xfs_dir3_leaf_hdr *bh = bp->b_addr;
				struct xfs_dir3_leaf_hdr *dh = tmp;
				uint16_t bcnt = be16_to_cpu(bh->count);
				uint16_t dcnt = be16_to_cpu(dh->count);
				uint16_t dmag =
					be16_to_cpu(dh->info.hdr.magic);

				if ((dmag == XFS_DIR3_LEAF1_MAGIC ||
				     dmag == XFS_DIR3_LEAFN_MAGIC) &&
				    bcnt < dcnt)
					pr_warn("mxfs: P-LEAFREADSTALE ino=%llu blk=%u daddr=%llu buf_cnt=%u disk_cnt=%u dlm_mode=%d gen=%u bufgen=%u realns=%llu\n",
						(unsigned long long)dp->i_ino,
						(unsigned int)bno,
						(unsigned long long)mapp[0].bm_bn,
						bcnt, dcnt, dp->i_dlm_mode,
						dp->i_dlm_dir_gen,
						bp->b_mxfs_dir_gen,
						(unsigned long long)ktime_get_real_ns());
			}
			kfree(tmp);
		}
	}

	*bpp = bp;
out_free:
	if (mapp != &map)
		kfree(mapp);

	return error;
}

/*
 * Readahead the dir/attr block.
 */
int
xfs_da_reada_buf(
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	unsigned int		flags,
	int			whichfork,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf_map	map;
	struct xfs_buf_map	*mapp;
	int			nmap;
	int			error;

	mapp = &map;
	nmap = 1;
	error = xfs_dabuf_map(dp, bno, flags, whichfork, &mapp, &nmap);
	if (error || !nmap)
		goto out_free;

	/*
	 * sess19 (RULE 4, GPT Hole B): on a multinode shared dir, a dir-block
	 * READAHEAD issued in one DLM tenure can complete LATER (after a peer
	 * modified the block + this node re-acquired) and re-populate the buffer
	 * cache with a STALE image marked XBF_DONE — which the acquire-side evict
	 * already ran past, so the next modify RMWs a stale dir base and the
	 * leaf hash-index entries are computed against a divergent data layout
	 * (readdir-yes / lookup-ENOENT, proven this session).  Readahead is a
	 * pure perf optimization; for a concurrently-modified shared dir it is a
	 * coherency hazard.  Skip it (gated by mxfs.dir_no_reada, default 1) so
	 * every dir block is read on-demand, coherently, within the using tenure.
	 */
	{
		extern int mxfs_dir_no_reada;
		struct xfs_mount *rmp = dp->i_mount;

		if (mxfs_dir_no_reada && rmp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(rmp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(dp)->i_mode))
			goto out_free;
	}

	xfs_buf_readahead_map(dp->i_mount->m_ddev_targp, mapp, nmap, ops);

out_free:
	if (mapp != &map)
		kfree(mapp);

	return error;
}
