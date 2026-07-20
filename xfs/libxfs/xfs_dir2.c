// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
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
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_health.h"
#include "xfs_bmap_btree.h"
#include "xfs_trans_space.h"
#include "xfs_parent.h"
#include "xfs_ag.h"
#include "xfs_ialloc.h"
#include "../../dlm/v5_mount.h"	/* sess59: mxfs_v5_dlm_is_single_node + pal log */
#include "xfs_mxfs_dlm.h"	/* sess80: mxfs_dlm_note_dir_modified */

const struct xfs_name xfs_name_dotdot = {
	.name	= (const unsigned char *)"..",
	.len	= 2,
	.type	= XFS_DIR3_FT_DIR,
};

const struct xfs_name xfs_name_dot = {
	.name	= (const unsigned char *)".",
	.len	= 1,
	.type	= XFS_DIR3_FT_DIR,
};

/*
 * Convert inode mode to directory entry filetype
 */
unsigned char
xfs_mode_to_ftype(
	int		mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
		return XFS_DIR3_FT_REG_FILE;
	case S_IFDIR:
		return XFS_DIR3_FT_DIR;
	case S_IFCHR:
		return XFS_DIR3_FT_CHRDEV;
	case S_IFBLK:
		return XFS_DIR3_FT_BLKDEV;
	case S_IFIFO:
		return XFS_DIR3_FT_FIFO;
	case S_IFSOCK:
		return XFS_DIR3_FT_SOCK;
	case S_IFLNK:
		return XFS_DIR3_FT_SYMLINK;
	default:
		return XFS_DIR3_FT_UNKNOWN;
	}
}

/*
 * ASCII case-insensitive (ie. A-Z) support for directories that was
 * used in IRIX.
 */
xfs_dahash_t
xfs_ascii_ci_hashname(
	const struct xfs_name	*name)
{
	xfs_dahash_t		hash;
	int			i;

	for (i = 0, hash = 0; i < name->len; i++)
		hash = xfs_ascii_ci_xfrm(name->name[i]) ^ rol32(hash, 7);

	return hash;
}

enum xfs_dacmp
xfs_ascii_ci_compname(
	struct xfs_da_args	*args,
	const unsigned char	*name,
	int			len)
{
	enum xfs_dacmp		result;
	int			i;

	if (args->namelen != len)
		return XFS_CMP_DIFFERENT;

	result = XFS_CMP_EXACT;
	for (i = 0; i < len; i++) {
		if (args->name[i] == name[i])
			continue;
		if (xfs_ascii_ci_xfrm(args->name[i]) !=
		    xfs_ascii_ci_xfrm(name[i]))
			return XFS_CMP_DIFFERENT;
		result = XFS_CMP_CASE;
	}

	return result;
}

int
xfs_da_mount(
	struct xfs_mount	*mp)
{
	struct xfs_da_geometry	*dageo;


	ASSERT(mp->m_sb.sb_versionnum & XFS_SB_VERSION_DIRV2BIT);
	ASSERT(xfs_dir2_dirblock_bytes(&mp->m_sb) <= XFS_MAX_BLOCKSIZE);

	mp->m_dir_geo = kzalloc(sizeof(struct xfs_da_geometry),
				GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	mp->m_attr_geo = kzalloc(sizeof(struct xfs_da_geometry),
				GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!mp->m_dir_geo || !mp->m_attr_geo) {
		kfree(mp->m_dir_geo);
		kfree(mp->m_attr_geo);
		return -ENOMEM;
	}

	/* set up directory geometry */
	dageo = mp->m_dir_geo;
	dageo->blklog = mp->m_sb.sb_blocklog + mp->m_sb.sb_dirblklog;
	dageo->fsblog = mp->m_sb.sb_blocklog;
	dageo->blksize = xfs_dir2_dirblock_bytes(&mp->m_sb);
	dageo->fsbcount = 1 << mp->m_sb.sb_dirblklog;
	if (xfs_has_crc(mp)) {
		dageo->node_hdr_size = sizeof(struct xfs_da3_node_hdr);
		dageo->leaf_hdr_size = sizeof(struct xfs_dir3_leaf_hdr);
		dageo->free_hdr_size = sizeof(struct xfs_dir3_free_hdr);
		dageo->data_entry_offset =
				sizeof(struct xfs_dir3_data_hdr);
	} else {
		dageo->node_hdr_size = sizeof(struct xfs_da_node_hdr);
		dageo->leaf_hdr_size = sizeof(struct xfs_dir2_leaf_hdr);
		dageo->free_hdr_size = sizeof(struct xfs_dir2_free_hdr);
		dageo->data_entry_offset =
				sizeof(struct xfs_dir2_data_hdr);
	}
	dageo->leaf_max_ents = (dageo->blksize - dageo->leaf_hdr_size) /
			sizeof(struct xfs_dir2_leaf_entry);
	dageo->free_max_bests = (dageo->blksize - dageo->free_hdr_size) /
			sizeof(xfs_dir2_data_off_t);

	dageo->data_first_offset = dageo->data_entry_offset +
			xfs_dir2_data_entsize(mp, 1) +
			xfs_dir2_data_entsize(mp, 2);

	/*
	 * Now we've set up the block conversion variables, we can calculate the
	 * segment block constants using the geometry structure.
	 */
	dageo->datablk = xfs_dir2_byte_to_da(dageo, XFS_DIR2_DATA_OFFSET);
	dageo->leafblk = xfs_dir2_byte_to_da(dageo, XFS_DIR2_LEAF_OFFSET);
	dageo->freeblk = xfs_dir2_byte_to_da(dageo, XFS_DIR2_FREE_OFFSET);
	dageo->node_ents = (dageo->blksize - dageo->node_hdr_size) /
				(uint)sizeof(xfs_da_node_entry_t);
	dageo->max_extents = (XFS_DIR2_MAX_SPACES * XFS_DIR2_SPACE_SIZE) >>
					mp->m_sb.sb_blocklog;
	dageo->magicpct = (dageo->blksize * 37) / 100;

	/* set up attribute geometry - single fsb only */
	dageo = mp->m_attr_geo;
	dageo->blklog = mp->m_sb.sb_blocklog;
	dageo->fsblog = mp->m_sb.sb_blocklog;
	dageo->blksize = 1 << dageo->blklog;
	dageo->fsbcount = 1;
	dageo->node_hdr_size = mp->m_dir_geo->node_hdr_size;
	dageo->node_ents = (dageo->blksize - dageo->node_hdr_size) /
				(uint)sizeof(xfs_da_node_entry_t);

	if (xfs_has_large_extent_counts(mp))
		dageo->max_extents = XFS_MAX_EXTCNT_ATTR_FORK_LARGE;
	else
		dageo->max_extents = XFS_MAX_EXTCNT_ATTR_FORK_SMALL;

	dageo->magicpct = (dageo->blksize * 37) / 100;
	return 0;
}

void
xfs_da_unmount(
	struct xfs_mount	*mp)
{
	kfree(mp->m_dir_geo);
	kfree(mp->m_attr_geo);
}

/*
 * Return 1 if directory contains only "." and "..".
 */
static bool
xfs_dir_isempty(
	xfs_inode_t	*dp)
{
	xfs_dir2_sf_hdr_t	*sfp;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	if (dp->i_disk_size == 0)	/* might happen during shutdown. */
		return true;
	if (dp->i_disk_size > xfs_inode_data_fork_size(dp))
		return false;
	sfp = dp->i_df.if_data;
	return !sfp->count;
}

/*
 * v0.6.5 (sess5 186320ae): BLOCK-format emptiness check for multinode dirs.
 *
 * With mxfs.dir_force_block a multinode dir is born block-format and (as of
 * v0.6.5) the rm/unlink shrink path never converts it back to shortform —
 * shared dirs must never carry live dirents in the inode literal area (the
 * shortform coherency machinery's residual races mint ghost dirents under
 * cross-node churn; dlm_fairness "drained exp=0 got=N").  Upstream can never
 * see an EMPTY block dir (the last removename always converts), so
 * xfs_dir_isempty treats any block-sized dir as non-empty and rmdir would
 * fail ENOTEMPTY forever (PROVEN: precond_readiness "unlink/cleanup" FAIL on
 * all 4 nodes).  Read block 0 through the transaction (normal verify +
 * coherency machinery applies) and count live entries besides "." / "..".
 */
static bool
xfs_dir_block_isempty(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_dir2_sf_hdr	sfh;
	struct xfs_buf		*bp;

	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS)
		return false;
	if (!mp->m_dir_geo || dp->i_disk_size != mp->m_dir_geo->blksize)
		return false;
	if (!(({ extern int mxfs_dir_force_block; mxfs_dir_force_block; }) &&
	      mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)))
		return false;
	if (xfs_dir3_block_read(tp, dp, dp->i_ino, &bp))
		return false;
	xfs_dir2_block_sfsize(dp, bp->b_addr, &sfh);
	xfs_trans_brelse(tp, bp);
	return sfh.count == 0;
}

/*
 * Validate a given inode number.
 */
int
xfs_dir_ino_validate(
	xfs_mount_t	*mp,
	xfs_ino_t	ino)
{
	bool		ino_ok = xfs_verify_dir_ino(mp, ino);

	if (XFS_IS_CORRUPT(mp, !ino_ok) ||
	    XFS_TEST_ERROR(mp, XFS_ERRTAG_DIR_INO_VALIDATE)) {
		xfs_warn(mp, "Invalid inode number 0x%Lx",
				(unsigned long long) ino);
		return -EFSCORRUPTED;
	}
	return 0;
}

/*
 * Initialize a directory with its "." and ".." entries.
 */
int
xfs_dir_init(
	xfs_trans_t	*tp,
	xfs_inode_t	*dp,
	xfs_inode_t	*pdp)
{
	struct xfs_da_args *args;
	int		error;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	error = xfs_dir_ino_validate(tp->t_mountp, pdp->i_ino);
	if (error)
		return error;

	args = kzalloc(sizeof(*args), GFP_KERNEL | __GFP_NOFAIL);
	if (!args)
		return -ENOMEM;

	args->geo = dp->i_mount->m_dir_geo;
	args->dp = dp;
	args->trans = tp;
	args->owner = dp->i_ino;
	error = xfs_dir2_sf_create(args, pdp->i_ino);
	kfree(args);
	return error;
}

enum xfs_dir2_fmt
xfs_dir2_format(
	struct xfs_da_args	*args,
	int			*error)
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo = mp->m_dir_geo;
	xfs_fileoff_t		eof;

	xfs_assert_ilocked(dp, XFS_ILOCK_SHARED | XFS_ILOCK_EXCL);

	*error = 0;
	if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL)
		return XFS_DIR2_FMT_SF;

	*error = xfs_bmap_last_offset(dp, &eof, XFS_DATA_FORK);
	if (*error)
		return XFS_DIR2_FMT_ERROR;

	if (eof == XFS_B_TO_FSB(mp, geo->blksize)) {
		if (XFS_IS_CORRUPT(mp, dp->i_disk_size != geo->blksize)) {
			/*
			 * sess58 (ccloop 14d31183) P58-FMT-DISIZE-CORRUPT — RULE-4
			 * proof probe at the EXACT shutdown site.  This is the
			 * dominant clean-gate root (sess57): a MODIFY path
			 * (xfs_create/remove/rename) reached here with an extent
			 * map that maps eof==1 block (so xfs_bmap says BLOCK
			 * format) but a di_size that is NOT one block — the two
			 * came from DIFFERENT incarnations because
			 * mxfs_dlm_dir_modify_refresh only evicts cached dir DATA
			 * blocks and does NOT refresh di_size or the extent map
			 * (a full mxfs_dlm_reload_inode self-deadlocks on
			 * down_write under the held ILOCK_EXCL).  Dump every
			 * staleness signal so the cross-node timeline proves
			 * di_size stale vs extent-map fresh + reload pending.
			 * Ungated: fires only on the corrupt branch (just before
			 * the FS shuts down), so it is inherently rare.
			 */
			if (mp->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P58-FMT-DISIZE-CORRUPT ino=%llu di_size=%lld blksize=%u eof=%llu fmt=%d nextents=%llu dir_gen=%llu loaded_gen=%u evicted_gen=%u reload_flag=%d self_created=%d dlm_mode=%d comm=%s realns=%llu",
					(unsigned long long)dp->i_ino,
					(long long)dp->i_disk_size,
					geo->blksize,
					(unsigned long long)eof,
					dp->i_df.if_format,
					(unsigned long long)dp->i_df.if_nextents,
					(unsigned long long)dp->i_dlm_dir_gen,
					dp->i_dlm_dir_loaded_gen,
					dp->i_dlm_dir_evicted_gen,
					!!xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD),
					dp->i_mxfs_self_created ? 1 : 0,
					dp->i_dlm_mode,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
			xfs_da_mark_sick(args);
			*error = -EFSCORRUPTED;
			return XFS_DIR2_FMT_ERROR;
		}
		/*
		 * sess56 (ccloop 14d31183) P56-FMT-BLOCK-RELOAD-PENDING — proof
		 * probe for the format-transition coherency gap.  A peer that
		 * grows this dir block->leaf arms MXFS_IF_DIR_RELOAD via the
		 * DIR_MODIFY evict-ring; the LOOKUP/READDIR paths consume it and
		 * rebuild the extent map, but the MODIFY paths (create/remove/
		 * rename via mxfs_dlm_dir_modify_refresh) do NOT — they hold
		 * ILOCK_EXCL and mxfs_dlm_reload_inode would self-deadlock on
		 * down_write(i_lock).  So a modify can reach here with a stale
		 * 1-extent map, decide FMT_BLOCK, and read block 0 (now an XDD3
		 * data block) with block ops -> xfs_dir3_block_verify magic
		 * mismatch -> dirty trans cancel -> shutdown.  Fire when we
		 * return BLOCK while a reload is pending: that is the bug in the
		 * act.  No I/O; gated behind mxfs.dirwr/instr.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_df.if_nextents != 1) {
			/*
			 * sess56 (ccloop 14d31183): FMT_BLOCK requires EXACTLY
			 * one extent (the single dir data block).  if_nextents
			 * != 1 here means the in-core data-fork extent map is
			 * STALE or TORN (e.g. nextents=2 from a peer's block->
			 * leaf grow, but xfs_bmap_last_offset still yields eof=1)
			 * -> we are about to read block 0 with block-format ops
			 * on a leaf dir -> XDD3-vs-XDB3 verify shutdown.  Always
			 * log (rare, not gated) with the staleness signals so a
			 * cross-node timeline shows the reload that should have
			 * rebuilt this fork.
			 */
			static atomic_t p56f_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p56f_n) <= 400)
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P56-FMT-BLOCK-TORN ino=%llu eof=%llu size=%lld nextents=%llu fmt=%d dir_gen=%llu loaded_gen=%u reload_flag=%d self_created=%d dlm_mode=%d comm=%s realns=%llu",
					(unsigned long long)dp->i_ino,
					(unsigned long long)eof,
					(long long)dp->i_disk_size,
					(unsigned long long)dp->i_df.if_nextents,
					dp->i_df.if_format,
					(unsigned long long)dp->i_dlm_dir_gen,
					dp->i_dlm_dir_loaded_gen,
					!!xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD),
					dp->i_mxfs_self_created ? 1 : 0,
					dp->i_dlm_mode,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
		return XFS_DIR2_FMT_BLOCK;
	}
	if (eof == geo->leafblk + geo->fsbcount)
		return XFS_DIR2_FMT_LEAF;
	return XFS_DIR2_FMT_NODE;
}

int
xfs_dir_createname_args(
	struct xfs_da_args	*args)
{
	int			error;
	int			fmt;
	int			rval;
	struct xfs_inode	*dp = args->dp;
	extern int		mxfs_dirwr_enabled;
	extern int		mxfs_instr_enabled;

	if (!args->inumber)
		args->op_flags |= XFS_DA_OP_JUSTCHECK;

	fmt = xfs_dir2_format(args, &error);

	/*
	 * sess59 RULE-4 ALWAYS-ON: format-agnostic create-time detector for the
	 * cross_visibility lost-update.  P-SFADD (xfs_dir2_sf.c) only fires for
	 * the FMT_SF path; the sess58 timeline showed the victim node's add was
	 * ABSENT from P-SFADD entirely (the dirent for node1.txt never appeared),
	 * so the add either took a non-SF format or a different parent.  Log the
	 * format + parent + child for every node*.txt add so we can see, per
	 * node, which dir inode and which format the create actually used.
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    dp && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    args->inumber && args->namelen >= 8 &&
	    args->name[0] == 'n' && args->name[1] == 'o' &&
	    args->name[2] == 'd' && args->name[3] == 'e')
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P-CRNAME pino=%llu add=[%.*s] cino=%llu fmt=%d realns=%llu",
			(unsigned long long)dp->i_ino,
			args->namelen, args->name,
			(unsigned long long)args->inumber, fmt,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * sess58 (ccloop 14d31183) P58-STALE-BASE-ADD — RULE-4 ALWAYS-ON
	 * detector for the durable dirent lost-update (the silent=11 residual
	 * in zero_silent_loss: e.g. node14_dir1 created by test14 but durably
	 * absent from the shared parent).  A block/leaf-format parent dir whose
	 * in-core data blocks were loaded at a gen OLDER than the latest known
	 * peer modification (i_dlm_dir_gen > i_dlm_dir_loaded_gen) is a STALE
	 * RMW base: adding our dirent on top of it and writing the block back
	 * durably ERASES any peer dirent that exists on disk but not in our
	 * stale cached block.  The EX-acquire stale-refresh (P101-FASTEX-EVICT)
	 * is supposed to close this, so a fire here with gen>loaded_gen at
	 * add-time means the refresh was SKIPPED (self_created gate) or left a
	 * stale block uncovered (evict left>0).  self_created is logged so the
	 * benign 0->1 self-arming artifact (gen>loaded on a never-BASTed dir we
	 * created) is distinguishable from a real peer-modified stale base.
	 * Cheap: two integer compares, multi-node + non-SF only, rate-limited.
	 */
	/* sess58: NON-PERTURBING narrow trigger — only log when the gen metric
	 * says our RMW base is stale (rare).  An every-add log hides the race
	 * (instr-slowdown).  If loss occurs with this SILENT, the gen tracking
	 * itself misses the staleness (the real bug is a stale reload, stale=0). */
	if (dp && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    dp->i_dlm_dir_gen > dp->i_dlm_dir_loaded_gen) {
		static atomic_t p58sb_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p58sb_n) <= 600)
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P58-STALE-BASE-ADD pino=%llu add=[%.*s] fmt=%d disize=%lld dir_gen=%llu loaded_gen=%u self_created=%d reload_flag=%d realns=%llu",
				(unsigned long long)dp->i_ino,
				args->namelen, args->name, fmt,
				(long long)dp->i_disk_size,
				(unsigned long long)dp->i_dlm_dir_gen,
				dp->i_dlm_dir_loaded_gen,
				dp->i_mxfs_self_created ? 1 : 0,
				!!xfs_iflags_test(dp, MXFS_IF_DIR_RELOAD),
				(unsigned long long)ktime_get_real_ns());
	}

	switch (fmt) {
	case XFS_DIR2_FMT_SF:
		rval = xfs_dir2_sf_addname(args);
		break;
	case XFS_DIR2_FMT_BLOCK:
		rval = xfs_dir2_block_addname(args);
		break;
	case XFS_DIR2_FMT_LEAF:
		rval = xfs_dir2_leaf_addname(args);
		break;
	case XFS_DIR2_FMT_NODE:
		rval = xfs_dir2_node_addname(args);
		break;
	default:
		return error;
	}

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    dp && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    args->inumber && args->namelen >= 8 &&
	    args->name[0] == 'n' && args->name[1] == 'o' &&
	    args->name[2] == 'd' && args->name[3] == 'e')
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P-CRNAME-DONE pino=%llu add=[%.*s] cino=%llu fmt=%d rval=%d realns=%llu",
			(unsigned long long)dp->i_ino,
			args->namelen, args->name,
			(unsigned long long)args->inumber, fmt, rval,
			(unsigned long long)ktime_get_real_ns());

	return rval;
}

/*
 * Enter a name in a directory, or check for available space.
 * If inum is 0, only the available space test is performed.
 */
int
xfs_dir_createname(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	xfs_ino_t		inum,		/* new entry inode number */
	xfs_extlen_t		total)		/* bmap's total block count */
{
	struct xfs_da_args	*args;
	int			rval;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));

	if (inum) {
		rval = xfs_dir_ino_validate(tp->t_mountp, inum);
		if (rval)
			return rval;
		XFS_STATS_INC(dp->i_mount, xs_dir_create);
	}

	args = kzalloc(sizeof(*args), GFP_KERNEL | __GFP_NOFAIL);
	if (!args)
		return -ENOMEM;

	args->geo = dp->i_mount->m_dir_geo;
	args->name = name->name;
	args->namelen = name->len;
	args->filetype = name->type;
	args->hashval = xfs_dir2_hashname(dp->i_mount, name);
	args->inumber = inum;
	args->dp = dp;
	args->total = total;
	args->whichfork = XFS_DATA_FORK;
	args->trans = tp;
	args->op_flags = XFS_DA_OP_ADDNAME | XFS_DA_OP_OKNOENT;
	args->owner = dp->i_ino;

#ifdef __KERNEL__
	/*
	 * sess21 (ccloop 8ddb16a2): if a peer modified this dir's shared LEAF
	 * (hash index) block while it was pinned on this node (the acquire-side
	 * evict could not refresh a pinned/undestaged leaf), our in-core leaf is
	 * missing the peer's committed hashvals.  Rebuild the leaf hash index
	 * from the coherent DATA blocks (which DO have the peer's dirents) inside
	 * THIS create transaction BEFORE adding our entry, so we do not durably
	 * destage a leaf that drops the peer's hash entries (the dir_reuse_
	 * coherency leaf-hash hole).  RELOG, no XBF_DONE clear, no extra DLM
	 * acquire.  Cheap: gated on the flag, fires only after a real stale-skip.
	 */
	/*
	 * sess26 (ccloop 8ddb16a2): the flag-only trigger (set solely on an
	 * evict-SKIP of an undurable leaf) MISSED the dominant dir_reuse_
	 * coherency leaf-hash hole — the failing run fired ZERO
	 * P21S-EVICTSKIP-LEAF, so the rebuild never ran and a node durably
	 * destaged a SHORT leaf (its own + the peer's first few entries only).
	 * readdir always == EXP (data blocks coherent), so the leaf is
	 * reconstructible.  The flag is now ALSO armed once per cross-node
	 * tenure in mxfs_dlm_dir_modify_refresh (the first modify after a peer
	 * handoff / new incarnation), so the rebuild fires reliably at the top
	 * of the tenure — when this node's cached leaf is most likely stale —
	 * without the every-create overhead that perturbed the reuse race and
	 * tripped the bnobt stale-extent shutdown (P26-REBUILD-OK 113x/run).
	 * The rebuild only ADDs the peer's missing hashvals (union of in-core +
	 * plain-bio data), never drops ours; bails fast for non-LEAF1.
	 */
	{
	extern int mxfs_dir_leaf_rebuild;
	if (mxfs_dir_leaf_rebuild &&
	    xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_LEAF_STALE)) {
		rval = mxfs_dir_rebuild_leaf_from_data(args);
		if (rval) {
			kfree(args);
			return rval;
		}
	}
	}
#endif

	rval = xfs_dir_createname_args(args);
	kfree(args);
	/* sess80: tell passively-caching peers this shared dir changed. */
	if (!rval)
		mxfs_dlm_note_dir_modified(dp->i_mount, dp->i_ino);
	return rval;
}

/*
 * If doing a CI lookup and case-insensitive match, dup actual name into
 * args.value. Return EEXIST for success (ie. name found) or an error.
 */
int
xfs_dir_cilookup_result(
	struct xfs_da_args *args,
	const unsigned char *name,
	int		len)
{
	if (args->cmpresult == XFS_CMP_DIFFERENT)
		return -ENOENT;
	if (args->cmpresult != XFS_CMP_CASE ||
					!(args->op_flags & XFS_DA_OP_CILOOKUP))
		return -EEXIST;

	args->value = kmemdup(name, len,
			GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_RETRY_MAYFAIL);
	if (!args->value)
		return -ENOMEM;

	args->valuelen = len;
	return -EEXIST;
}

int
xfs_dir_lookup_args(
	struct xfs_da_args	*args)
{
	int			error;

	int fmt = xfs_dir2_format(args, &error);

	switch (fmt) {
	case XFS_DIR2_FMT_SF:
		error = xfs_dir2_sf_lookup(args);
		break;
	case XFS_DIR2_FMT_BLOCK:
		error = xfs_dir2_block_lookup(args);
		break;
	case XFS_DIR2_FMT_LEAF:
		error = xfs_dir2_leaf_lookup(args);
		break;
	case XFS_DIR2_FMT_NODE:
		error = xfs_dir2_node_lookup(args);
		break;
	default:
		break;
	}

#ifdef __KERNEL__
	/* sess26 (ccloop): which FORMAT path did a FAILING multi-node lookup
	 * take?  datascan-heal is only wired into the LEAF path; if the failing
	 * lookups dispatch to NODE/BLOCK the leaf-hash hole goes unhealed. */
	if (error && error != -EEXIST && args->dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(args->dp->i_mount->m_mxfs_dlm)) {
		static atomic_t p26fl = ATOMIC_INIT(0);
		if (atomic_inc_return(&p26fl) <= 200)
			pr_warn("mxfs: P26-LKFMT ino=%llu fmt=%d err=%d name=\"%.*s\"\n",
				(unsigned long long)args->dp->i_ino, fmt, error,
				args->namelen, args->name);
	}
#endif

	if (error != -EEXIST)
		return error;
	return 0;
}

/*
 * Lookup a name in a directory, give back the inode number.
 * If ci_name is not NULL, returns the actual name in ci_name if it differs
 * to name, or ci_name->name is set to NULL for an exact match.
 */

int
xfs_dir_lookup(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	xfs_ino_t		*inum,	  /* out: inode number */
	struct xfs_name		*ci_name, /* out: actual name if CI match */
	uint8_t			*ftypep)  /* out: dirent on-disk ftype (or NULL) */
{
	struct xfs_da_args	*args;
	int			rval;
	int			lock_mode;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	XFS_STATS_INC(dp->i_mount, xs_dir_lookup);

	args = kzalloc(sizeof(*args),
			GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
	args->geo = dp->i_mount->m_dir_geo;
	args->name = name->name;
	args->namelen = name->len;
	args->filetype = name->type;
	args->hashval = xfs_dir2_hashname(dp->i_mount, name);
	args->dp = dp;
	args->whichfork = XFS_DATA_FORK;
	args->trans = tp;
	args->op_flags = XFS_DA_OP_OKNOENT;
	args->owner = dp->i_ino;
	if (ci_name)
		args->op_flags |= XFS_DA_OP_CILOOKUP;

	lock_mode = xfs_ilock_data_map_shared(dp);
	/*
	 * sess115 PROVEN ROOT FIX (RULE 4, dmesg EFSCORRUPTED trace):
	 * xfs_ilock_data_map_shared above recurses into the MXFS DLM acquire
	 * hook, which can RELOAD dp from a peer-committed on-disk image
	 * (mxfs_dlm_reload_inode).  If a peer FREED dp (rm/teardown) or REUSED
	 * its inode number for a different type across the lock, the reloaded
	 * dinode is mode=0 (freed) or non-dir — the S_ISDIR assert at entry ran
	 * BEFORE that reload, so it does not protect us here.  A freed inode's
	 * data fork is reset to empty-EXTENTS (sess114) while i_disk_size stays
	 * stale-large; xfs_dir_lookup_args' format dispatch then defaults to
	 * xfs_dir2_node_lookup, which walks the now-EMPTY extent map and reads
	 * the node-root daddr (bno 0x800000) → xfs_dabuf_map finds a HOLE with
	 * !XFS_DABUF_MAP_HOLE_OK → xfs_corruption_error → EFSCORRUPTED FS
	 * SHUTDOWN (PROVEN: "xfs_dabuf_map: bno 8388608 inode 131",
	 * br_startblock -2; ino=131 = the churned .mxfs_test dir reloaded to
	 * disk_mode=00 mid-lookup).  Correct POSIX behavior: the parent
	 * directory we were about to search has been removed/reused underneath
	 * us → -ENOENT, NOT an FS shutdown.  Zero risk to the single-node /
	 * stable-parent path (mode is unchanged there).
	 */
	if (unlikely(!S_ISDIR(VFS_I(dp)->i_mode))) {
		xfs_iunlock(dp, lock_mode);
		pr_warn_ratelimited(
			"mxfs: P115-PARENT-FREED ino=%llu mode=0%o name=%.*s -> ENOENT (peer freed/reused parent dir mid-lookup)\n",
			(unsigned long long)dp->i_ino, VFS_I(dp)->i_mode,
			name->len, (const char *)name->name);
		kfree(args);
		return -ENOENT;
	}
	rval = xfs_dir_lookup_args(args);
	if (!rval) {
		*inum = args->inumber;
		if (ci_name) {
			ci_name->name = args->value;
			ci_name->len = args->valuelen;
		}
		/*
		 * mxfs: hand back the dirent's on-disk filetype so the caller
		 * (xfs_lookup) can detect a cross-node inode-number REUSE where
		 * our cached in-core inode is a stale prior incarnation of a
		 * DIFFERENT type (e.g. a peer freed a regular file and reused
		 * the number for a directory).  Zero extra I/O — the dir block
		 * has already been read for the lookup.
		 */
		if (ftypep)
			*ftypep = args->filetype;
	}
	xfs_iunlock(dp, lock_mode);
	kfree(args);
	return rval;
}

/*
 * mxfs: lock-free variant of xfs_dir_lookup for callers that ALREADY hold
 * dp's ILOCK (e.g. xfs_create after xfs_ilock(dp, XFS_ILOCK_EXCL)).
 *
 * The stock xfs_dir_lookup takes xfs_ilock_data_map_shared(dp) internally,
 * which under MXFS recurses into the distributed-lock hook (mxfs_dlm_ilock_*)
 * and deadlocks when the caller already holds ILOCK_EXCL (sess36).  This
 * helper skips the relock — the caller's ILOCK covers the read.
 *
 * Used to re-validate non-existence of @name under the held cross-node EX
 * DLM.  After a peer demotes our parent-dir DLM and adds an entry, our
 * earlier VFS lookup's negative dentry is stale; without this re-check
 * both nodes create a duplicate (Mode A lost-update).  Returns 0 if the
 * name exists (inum filled), -ENOENT if absent, or another negative errno.
 */
int
xfs_dir_lookup_locked(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	xfs_ino_t		*inum)
{
	struct xfs_da_args	*args;
	int			rval;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	XFS_STATS_INC(dp->i_mount, xs_dir_lookup);

	args = kzalloc(sizeof(*args),
			GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
	args->geo = dp->i_mount->m_dir_geo;
	args->name = name->name;
	args->namelen = name->len;
	args->filetype = name->type;
	args->hashval = xfs_dir2_hashname(dp->i_mount, name);
	args->dp = dp;
	args->whichfork = XFS_DATA_FORK;
	args->trans = tp;
	args->op_flags = XFS_DA_OP_OKNOENT;
	args->owner = dp->i_ino;

	rval = xfs_dir_lookup_args(args);
	if (!rval)
		*inum = args->inumber;
	kfree(args);
	return rval;
}

int
xfs_dir_removename_args(
	struct xfs_da_args	*args)
{
	int			error;

	switch (xfs_dir2_format(args, &error)) {
	case XFS_DIR2_FMT_SF:
		return xfs_dir2_sf_removename(args);
	case XFS_DIR2_FMT_BLOCK:
		return xfs_dir2_block_removename(args);
	case XFS_DIR2_FMT_LEAF:
		return xfs_dir2_leaf_removename(args);
	case XFS_DIR2_FMT_NODE:
		return xfs_dir2_node_removename(args);
	default:
		return error;
	}
}

/*
 * Remove an entry from a directory.
 */
int
xfs_dir_removename(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	xfs_ino_t		ino,
	xfs_extlen_t		total)		/* bmap's total block count */
{
	struct xfs_da_args	*args;
	int			rval;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));
	XFS_STATS_INC(dp->i_mount, xs_dir_remove);

	args = kzalloc(sizeof(*args), GFP_KERNEL | __GFP_NOFAIL);
	if (!args)
		return -ENOMEM;

	args->geo = dp->i_mount->m_dir_geo;
	args->name = name->name;
	args->namelen = name->len;
	args->filetype = name->type;
	args->hashval = xfs_dir2_hashname(dp->i_mount, name);
	args->inumber = ino;
	args->dp = dp;
	args->total = total;
	args->whichfork = XFS_DATA_FORK;
	args->trans = tp;
	args->owner = dp->i_ino;
	rval = xfs_dir_removename_args(args);
	kfree(args);
	/* sess80: tell passively-caching peers this shared dir changed. */
	if (!rval) {
		mxfs_dlm_note_dir_modified(dp->i_mount, dp->i_ino);
		/* sess34: record the removed inumber in this tenure's removed-set
		 * so the release-drain merge never resurrects our own remove. */
		mxfs_dir_record_removed(dp, ino);
	}
	return rval;
}

int
xfs_dir_replace_args(
	struct xfs_da_args	*args)
{
	int			error;

	switch (xfs_dir2_format(args, &error)) {
	case XFS_DIR2_FMT_SF:
		return xfs_dir2_sf_replace(args);
	case XFS_DIR2_FMT_BLOCK:
		return xfs_dir2_block_replace(args);
	case XFS_DIR2_FMT_LEAF:
		return xfs_dir2_leaf_replace(args);
	case XFS_DIR2_FMT_NODE:
		return xfs_dir2_node_replace(args);
	default:
		return error;
	}
}

/*
 * Replace the inode number of a directory entry.
 */
int
xfs_dir_replace(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,		/* name of entry to replace */
	xfs_ino_t		inum,		/* new inode number */
	xfs_extlen_t		total)		/* bmap's total block count */
{
	struct xfs_da_args	*args;
	int			rval;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));

	rval = xfs_dir_ino_validate(tp->t_mountp, inum);
	if (rval)
		return rval;

	args = kzalloc(sizeof(*args), GFP_KERNEL | __GFP_NOFAIL);
	if (!args)
		return -ENOMEM;

	args->geo = dp->i_mount->m_dir_geo;
	args->name = name->name;
	args->namelen = name->len;
	args->filetype = name->type;
	args->hashval = xfs_dir2_hashname(dp->i_mount, name);
	args->inumber = inum;
	args->dp = dp;
	args->total = total;
	args->whichfork = XFS_DATA_FORK;
	args->trans = tp;
	args->owner = dp->i_ino;
	rval = xfs_dir_replace_args(args);
	kfree(args);
	/* sess80: tell passively-caching peers this shared dir changed. */
	if (!rval)
		mxfs_dlm_note_dir_modified(dp->i_mount, dp->i_ino);
	return rval;
}

/*
 * See if this entry can be added to the directory without allocating space.
 */
int
xfs_dir_canenter(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	const struct xfs_name	*name)		/* name of entry to add */
{
	return xfs_dir_createname(tp, dp, name, 0, 0);
}

/*
 * Utility routines.
 */

/*
 * Add a block to the directory.
 *
 * This routine is for data and free blocks, not leaf/node blocks which are
 * handled by xfs_da_grow_inode.
 */
int
xfs_dir2_grow_inode(
	struct xfs_da_args	*args,
	int			space,	/* v2 dir's space XFS_DIR2_xxx_SPACE */
	xfs_dir2_db_t		*dbp)	/* out: block number added */
{
	struct xfs_inode	*dp = args->dp;
	struct xfs_mount	*mp = dp->i_mount;
	xfs_fileoff_t		bno;	/* directory offset of new block */
	int			count;	/* count of filesystem blocks */
	int			error;

	trace_xfs_dir2_grow_inode(args, space);

	/*
	 * Set lowest possible block in the space requested.
	 */
	bno = XFS_B_TO_FSBT(mp, space * XFS_DIR2_SPACE_SIZE);
	count = args->geo->fsbcount;

	error = xfs_da_grow_inode_int(args, &bno, count);
	if (error)
		return error;

	*dbp = xfs_dir2_da_to_db(args->geo, (xfs_dablk_t)bno);

	/* <ccloop sess49> tripwire: a successful dir grow must leave the new
	 * block REAL-allocated, never delalloc.  Catch the path that leaves a
	 * DELAYSTARTBLOCK in the dir data fork (the 8/tcp DABUF_MAP_HOLE root). */
	if (S_ISDIR(VFS_I(dp)->i_mode))
		mxfs_dir_delalloc_tripwire(dp, "dir2_grow_inode");

	/*
	 * ccloop sess39 P-GROW0 (RULE 4 DECISIVE, low-perturbation, NO disk I/O):
	 * log every allocation of dir DATA logical block 0.  The dir_reuse_coherency
	 * durable loss is a DIVERGENT extent map — node1 writes blk0 to one daddr,
	 * node2 to another, for the SAME dir incarnation (i_generation).  If BOTH
	 * nodes log P-GROW0 with the SAME gen, blk0 was DOUBLE-ALLOCATED across the
	 * EX handoff (a node re-allocated blk0 the peer already materialized) -> the
	 * canonical map orphans one node's first-block dirents.  Correlate across
	 * nodes by ino+gen.  Capped; gated dirwr/instr.  Pure in-core scan.
	 */
	if (space == XFS_DIR2_DATA_SPACE && *dbp == 0 &&
	    S_ISDIR(VFS_I(dp)->i_mode)) {
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			static atomic_t pg0 = ATOMIC_INIT(0);
			xfs_fsblock_t	g0_fsb = 0;
			struct xfs_iext_cursor	g0_cur;
			struct xfs_bmbt_irec	g0_got;

			for_each_xfs_iext(&dp->i_df, &g0_cur, &g0_got) {
				if (g0_got.br_startoff == 0 &&
				    !isnullstartblock(g0_got.br_startblock)) {
					g0_fsb = g0_got.br_startblock;
					break;
				}
			}
			if (atomic_inc_return(&pg0) <= 1200)
				pr_warn("mxfs: P-GROW0 ino=%llu gen=%u fmt=%d nx=%llu fsb=%llu comm=%s\n",
					(unsigned long long)dp->i_ino,
					VFS_I(dp)->i_generation,
					dp->i_df.if_format,
					(unsigned long long)dp->i_df.if_nextents,
					(unsigned long long)g0_fsb,
					current->comm);
		}
	}

	/*
	 * Update file's size if this is the data space and it grew.
	 */
	if (space == XFS_DIR2_DATA_SPACE) {
		xfs_fsize_t	size;		/* directory file (data) size */

		size = XFS_FSB_TO_B(mp, bno + count);
		if (size > dp->i_disk_size) {
			dp->i_disk_size = size;
			xfs_trans_log_inode(args->trans, dp, XFS_ILOG_CORE);
		}
	}
	return 0;
}

/*
 * Remove the given block from the directory.
 * This routine is used for data and free blocks, leaf/node are done
 * by xfs_da_shrink_inode.
 */
int
xfs_dir2_shrink_inode(
	struct xfs_da_args	*args,
	xfs_dir2_db_t		db,
	struct xfs_buf		*bp)
{
	xfs_fileoff_t		bno;		/* directory file offset */
	xfs_dablk_t		da;		/* directory file offset */
	int			done;		/* bunmap is finished */
	struct xfs_inode	*dp;
	int			error;
	struct xfs_mount	*mp;
	struct xfs_trans	*tp;

	trace_xfs_dir2_shrink_inode(args, db);

	dp = args->dp;
	mp = dp->i_mount;
	tp = args->trans;
	da = xfs_dir2_db_to_da(args->geo, db);

	/* Unmap the fsblock(s). */
	error = xfs_bunmapi(tp, dp, da, args->geo->fsbcount, 0, 0, &done);
	if (error) {
		/*
		 * ENOSPC actually can happen if we're in a removename with no
		 * space reservation, and the resulting block removal would
		 * cause a bmap btree split or conversion from extents to btree.
		 * This can only happen for un-fragmented directory blocks,
		 * since you need to be punching out the middle of an extent.
		 * In this case we need to leave the block in the file, and not
		 * binval it.  So the block has to be in a consistent empty
		 * state and appropriately logged.  We don't free up the buffer,
		 * the caller can tell it hasn't happened since it got an error
		 * back.
		 */
		return error;
	}
	ASSERT(done);
	/*
	 * Invalidate the buffer from the transaction.
	 */
	xfs_trans_binval(tp, bp);
	/*
	 * If it's not a data block, we're done.
	 */
	if (db >= xfs_dir2_byte_to_db(args->geo, XFS_DIR2_LEAF_OFFSET))
		return 0;
	/*
	 * If the block isn't the last one in the directory, we're done.
	 */
	if (dp->i_disk_size > xfs_dir2_db_off_to_byte(args->geo, db + 1, 0)) {
		/* <ccloop sess49b> ORIGIN PROBE: freeing a NON-last (middle) dir
		 * data block removes its extent but leaves di_size unchanged ->
		 * a GAP in the data-region extent map.  Legitimate single-node
		 * (the leaf/free index no longer references it), but the PROVEN
		 * 8/tcp DISK-TORN root when this block-free and the leaf update do
		 * NOT reach the platter atomically/consistently across a cross-node
		 * handoff (a peer's stale leaf then references the freed block ->
		 * DABUF_MAP_HOLE).  Confirm this is where the in-core gap is born. */
		if (S_ISDIR(VFS_I(dp)->i_mode))
			mxfs_dir_delalloc_tripwire(dp, "shrink_inode_midblock");
		return 0;
	}
	bno = da;
	if ((error = xfs_bmap_last_before(tp, dp, &bno, XFS_DATA_FORK))) {
		/*
		 * This can't really happen unless there's kernel corruption.
		 */
		return error;
	}
	if (db == args->geo->datablk)
		ASSERT(bno == 0);
	else
		ASSERT(bno > 0);
	/*
	 * Set the size to the new last block.
	 */
	dp->i_disk_size = XFS_FSB_TO_B(mp, bno);
	xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);
	return 0;
}

/* Returns true if the directory entry name is valid. */
bool
xfs_dir2_namecheck(
	const void	*name,
	size_t		length)
{
	/*
	 * MAXNAMELEN includes the trailing null, but (name/length) leave it
	 * out, so use >= for the length check.
	 */
	if (length >= MAXNAMELEN)
		return false;

	/* There shouldn't be any slashes or nulls here */
	return !memchr(name, '/', length) && !memchr(name, 0, length);
}

xfs_dahash_t
xfs_dir2_hashname(
	struct xfs_mount	*mp,
	const struct xfs_name	*name)
{
	if (unlikely(xfs_has_asciici(mp)))
		return xfs_ascii_ci_hashname(name);
	return xfs_da_hashname(name->name, name->len);
}

enum xfs_dacmp
xfs_dir2_compname(
	struct xfs_da_args	*args,
	const unsigned char	*name,
	int			len)
{
	if (unlikely(xfs_has_asciici(args->dp->i_mount)))
		return xfs_ascii_ci_compname(args, name, len);
	return xfs_da_compname(args, name, len);
}

#ifdef CONFIG_XFS_LIVE_HOOKS
/*
 * Use a static key here to reduce the overhead of directory live update hooks.
 * If the compiler supports jump labels, the static branch will be replaced by
 * a nop sled when there are no hook users.  Online fsck is currently the only
 * caller, so this is a reasonable tradeoff.
 *
 * Note: Patching the kernel code requires taking the cpu hotplug lock.  Other
 * parts of the kernel allocate memory with that lock held, which means that
 * XFS callers cannot hold any locks that might be used by memory reclaim or
 * writeback when calling the static_branch_{inc,dec} functions.
 */
DEFINE_STATIC_XFS_HOOK_SWITCH(xfs_dir_hooks_switch);

void
xfs_dir_hook_disable(void)
{
	xfs_hooks_switch_off(&xfs_dir_hooks_switch);
}

void
xfs_dir_hook_enable(void)
{
	xfs_hooks_switch_on(&xfs_dir_hooks_switch);
}

/* Call hooks for a directory update relating to a child dirent update. */
inline void
xfs_dir_update_hook(
	struct xfs_inode		*dp,
	struct xfs_inode		*ip,
	int				delta,
	const struct xfs_name		*name)
{
	if (xfs_hooks_switched_on(&xfs_dir_hooks_switch)) {
		struct xfs_dir_update_params	p = {
			.dp		= dp,
			.ip		= ip,
			.delta		= delta,
			.name		= name,
		};
		struct xfs_mount	*mp = ip->i_mount;

		xfs_hooks_call(&mp->m_dir_update_hooks, 0, &p);
	}
}

/* Call the specified function during a directory update. */
int
xfs_dir_hook_add(
	struct xfs_mount	*mp,
	struct xfs_dir_hook	*hook)
{
	return xfs_hooks_add(&mp->m_dir_update_hooks, &hook->dirent_hook);
}

/* Stop calling the specified function during a directory update. */
void
xfs_dir_hook_del(
	struct xfs_mount	*mp,
	struct xfs_dir_hook	*hook)
{
	xfs_hooks_del(&mp->m_dir_update_hooks, &hook->dirent_hook);
}

/* Configure directory update hook functions. */
void
xfs_dir_hook_setup(
	struct xfs_dir_hook	*hook,
	notifier_fn_t		mod_fn)
{
	xfs_hook_setup(&hook->dirent_hook, mod_fn);
}
#endif /* CONFIG_XFS_LIVE_HOOKS */

/*
 * Given a directory @dp, a newly allocated inode @ip, and a @name, link @ip
 * into @dp under the given @name.  If @ip is a directory, it will be
 * initialized.  Both inodes must have the ILOCK held and the transaction must
 * have sufficient blocks reserved.
 */
int
xfs_dir_create_child(
	struct xfs_trans	*tp,
	unsigned int		resblks,
	struct xfs_dir_update	*du)
{
	struct xfs_inode	*dp = du->dp;
	const struct xfs_name	*name = du->name;
	struct xfs_inode	*ip = du->ip;
	int			error;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	xfs_assert_ilocked(dp, XFS_ILOCK_EXCL);

	error = xfs_dir_createname(tp, dp, name, ip->i_ino, resblks);
	if (error) {
		ASSERT(error != -ENOSPC);
		return error;
	}

	xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);

	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		error = xfs_dir_init(tp, ip, dp);
		if (error)
			return error;

		xfs_bumplink(tp, dp);
	}

	/*
	 * If we have parent pointers, we need to add the attribute containing
	 * the parent information now.
	 */
	if (du->ppargs) {
		error = xfs_parent_addname(tp, du->ppargs, dp, name, ip);
		if (error)
			return error;
	}

	xfs_dir_update_hook(dp, ip, 1, name);
	return 0;
}

/*
 * Given a directory @dp, an existing non-directory inode @ip, and a @name,
 * link @ip into @dp under the given @name.  Both inodes must have the ILOCK
 * held.
 */
int
xfs_dir_add_child(
	struct xfs_trans	*tp,
	unsigned int		resblks,
	struct xfs_dir_update	*du)
{
	struct xfs_inode	*dp = du->dp;
	const struct xfs_name	*name = du->name;
	struct xfs_inode	*ip = du->ip;
	struct xfs_mount	*mp = tp->t_mountp;
	int			error;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	xfs_assert_ilocked(dp, XFS_ILOCK_EXCL);
	ASSERT(!S_ISDIR(VFS_I(ip)->i_mode));

	if (!resblks) {
		error = xfs_dir_canenter(tp, dp, name);
		if (error)
			return error;
	}

	/*
	 * Handle initial link state of O_TMPFILE inode
	 */
	if (VFS_I(ip)->i_nlink == 0) {
		struct xfs_perag	*pag;

		pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
		error = xfs_iunlink_remove(tp, pag, ip);
		xfs_perag_put(pag);
		if (error)
			return error;
	}

	error = xfs_dir_createname(tp, dp, name, ip->i_ino, resblks);
	if (error)
		return error;

	xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);

	xfs_bumplink(tp, ip);

	/*
	 * If we have parent pointers, we now need to add the parent record to
	 * the attribute fork of the inode. If this is the initial parent
	 * attribute, we need to create it correctly, otherwise we can just add
	 * the parent to the inode.
	 */
	if (du->ppargs) {
		error = xfs_parent_addname(tp, du->ppargs, dp, name, ip);
		if (error)
			return error;
	}

	xfs_dir_update_hook(dp, ip, 1, name);
	return 0;
}

/*
 * Given a directory @dp, a child @ip, and a @name, remove the (@name, @ip)
 * entry from the directory.  Both inodes must have the ILOCK held.
 */
int
xfs_dir_remove_child(
	struct xfs_trans	*tp,
	unsigned int		resblks,
	struct xfs_dir_update	*du)
{
	struct xfs_inode	*dp = du->dp;
	const struct xfs_name	*name = du->name;
	struct xfs_inode	*ip = du->ip;
	int			error;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	xfs_assert_ilocked(dp, XFS_ILOCK_EXCL);

	/*
	 * If we're removing a directory perform some additional validation.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		ASSERT(VFS_I(ip)->i_nlink >= 2);
		if (VFS_I(ip)->i_nlink != 2)
			return -ENOTEMPTY;
		if (!xfs_dir_isempty(ip) && !xfs_dir_block_isempty(tp, ip))
			return -ENOTEMPTY;

		/* Drop the link from ip's "..".  */
		error = xfs_droplink(tp, dp);
		if (error)
			return error;

		/* Drop the "." link from ip to self.  */
		error = xfs_droplink(tp, ip);
		if (error)
			return error;

		/*
		 * Point the unlinked child directory's ".." entry to the root
		 * directory to eliminate back-references to inodes that may
		 * get freed before the child directory is closed.  If the fs
		 * gets shrunk, this can lead to dirent inode validation errors.
		 */
		if (dp->i_ino != tp->t_mountp->m_sb.sb_rootino) {
			error = xfs_dir_replace(tp, ip, &xfs_name_dotdot,
					tp->t_mountp->m_sb.sb_rootino, 0);
			if (error)
				return error;
		}
	} else {
		/*
		 * mxfs (8/tcp dir_reuse shutdown fix): under multi-node churn a
		 * peer can leave THIS node's in-core directory inconsistent — a
		 * leaf-hash entry whose data-block dirent is absent — so
		 * xfs_dir_removename returns -ENOENT even though the pre-flight
		 * lookup in xfs_remove (xfs_dir_lookup_locked) found the name.
		 * Upstream logs the parent inode and drops the link BEFORE
		 * removename, so that -ENOENT then forces xfs_trans_cancel on a
		 * DIRTY transaction = "Corruption of in-memory data" = whole-fs
		 * SHUTDOWN (which cascades, failing every test on the node:
		 * dir_reuse 0/8).
		 *
		 * For a non-directory the removename is independent of the link
		 * drop, so run it FIRST while the transaction is still CLEAN: an
		 * -ENOENT then cancels a clean transaction (benign skip — the
		 * dirent is already gone from the durable dir) and the node stays
		 * up.  Only after removename succeeds do we log the parent and
		 * drop the link.
		 */
		error = xfs_dir_removename(tp, dp, name, ip->i_ino, resblks);
		if (error) {
			pr_warn("mxfs: MX-INSTR remove dp=%llu ip=%llu name=\"%.*s\" xfs_dir_removename rc=%d (clean-cancel, node stays up)",
				(unsigned long long)dp->i_ino,
				(unsigned long long)ip->i_ino,
				name->len, (const char *)name->name, error);
			return error;
		}
		/*
		 * When removing a non-directory we need to log the parent
		 * inode here.  For a directory this is done implicitly
		 * by the xfs_droplink call for the ".." entry.
		 */
		xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);
		xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);

		/* Drop the link from dp to ip. */
		error = xfs_droplink(tp, ip);
		if (error) {
			pr_warn("mxfs: MX-INSTR remove dp=%llu ip=%llu nlink=%u xfs_droplink rc=%d",
				(unsigned long long)dp->i_ino,
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_nlink, error);
			return error;
		}
	}

	/*
	 * Directory removal keeps the upstream ordering: emptiness has already
	 * been validated above (so removename cannot legitimately -ENOENT after
	 * the child-link drops), and the ".."/"." droplinks must precede the
	 * parent dirent removal.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);

		/* Drop the link from dp to ip. */
		error = xfs_droplink(tp, ip);
		if (error) {
			pr_warn("mxfs: MX-INSTR remove dp=%llu ip=%llu nlink=%u xfs_droplink rc=%d",
				(unsigned long long)dp->i_ino,
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_nlink, error);
			return error;
		}

		error = xfs_dir_removename(tp, dp, name, ip->i_ino, resblks);
		if (error) {
			pr_warn("mxfs: MX-INSTR remove dp=%llu ip=%llu name=\"%.*s\" xfs_dir_removename rc=%d",
				(unsigned long long)dp->i_ino,
				(unsigned long long)ip->i_ino,
				name->len, (const char *)name->name, error);
			return error;
		}
	}

	/* Remove parent pointer. */
	if (du->ppargs) {
		error = xfs_parent_removename(tp, du->ppargs, dp, name, ip);
		if (error) {
			pr_warn("mxfs: MX-INSTR remove dp=%llu ip=%llu xfs_parent_removename rc=%d",
				(unsigned long long)dp->i_ino,
				(unsigned long long)ip->i_ino, error);
			return error;
		}
	}

	xfs_dir_update_hook(dp, ip, -1, name);
	return 0;
}

/*
 * Exchange the entry (@name1, @ip1) in directory @dp1 with the entry (@name2,
 * @ip2) in directory @dp2, and update '..' @ip1 and @ip2's entries as needed.
 * @ip1 and @ip2 need not be of the same type.
 *
 * All inodes must have the ILOCK held, and both entries must already exist.
 */
int
xfs_dir_exchange_children(
	struct xfs_trans	*tp,
	struct xfs_dir_update	*du1,
	struct xfs_dir_update	*du2,
	unsigned int		spaceres)
{
	struct xfs_inode	*dp1 = du1->dp;
	const struct xfs_name	*name1 = du1->name;
	struct xfs_inode	*ip1 = du1->ip;
	struct xfs_inode	*dp2 = du2->dp;
	const struct xfs_name	*name2 = du2->name;
	struct xfs_inode	*ip2 = du2->ip;
	int			ip1_flags = 0;
	int			ip2_flags = 0;
	int			dp2_flags = 0;
	int			error;

	/* Swap inode number for dirent in first parent */
	error = xfs_dir_replace(tp, dp1, name1, ip2->i_ino, spaceres);
	if (error)
		return error;

	/* Swap inode number for dirent in second parent */
	error = xfs_dir_replace(tp, dp2, name2, ip1->i_ino, spaceres);
	if (error)
		return error;

	/*
	 * If we're renaming one or more directories across different parents,
	 * update the respective ".." entries (and link counts) to match the new
	 * parents.
	 */
	if (dp1 != dp2) {
		dp2_flags = XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG;

		if (S_ISDIR(VFS_I(ip2)->i_mode)) {
			error = xfs_dir_replace(tp, ip2, &xfs_name_dotdot,
						dp1->i_ino, spaceres);
			if (error)
				return error;

			/* transfer ip2 ".." reference to dp1 */
			if (!S_ISDIR(VFS_I(ip1)->i_mode)) {
				error = xfs_droplink(tp, dp2);
				if (error)
					return error;
				xfs_bumplink(tp, dp1);
			}

			/*
			 * Although ip1 isn't changed here, userspace needs
			 * to be warned about the change, so that applications
			 * relying on it (like backup ones), will properly
			 * notify the change
			 */
			ip1_flags |= XFS_ICHGTIME_CHG;
			ip2_flags |= XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG;
		}

		if (S_ISDIR(VFS_I(ip1)->i_mode)) {
			error = xfs_dir_replace(tp, ip1, &xfs_name_dotdot,
						dp2->i_ino, spaceres);
			if (error)
				return error;

			/* transfer ip1 ".." reference to dp2 */
			if (!S_ISDIR(VFS_I(ip2)->i_mode)) {
				error = xfs_droplink(tp, dp1);
				if (error)
					return error;
				xfs_bumplink(tp, dp2);
			}

			/*
			 * Although ip2 isn't changed here, userspace needs
			 * to be warned about the change, so that applications
			 * relying on it (like backup ones), will properly
			 * notify the change
			 */
			ip1_flags |= XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG;
			ip2_flags |= XFS_ICHGTIME_CHG;
		}
	}

	if (ip1_flags) {
		xfs_trans_ichgtime(tp, ip1, ip1_flags);
		xfs_trans_log_inode(tp, ip1, XFS_ILOG_CORE);
	}
	if (ip2_flags) {
		xfs_trans_ichgtime(tp, ip2, ip2_flags);
		xfs_trans_log_inode(tp, ip2, XFS_ILOG_CORE);
	}
	if (dp2_flags) {
		xfs_trans_ichgtime(tp, dp2, dp2_flags);
		xfs_trans_log_inode(tp, dp2, XFS_ILOG_CORE);
	}
	xfs_trans_ichgtime(tp, dp1, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, dp1, XFS_ILOG_CORE);

	/* Schedule parent pointer replacements */
	if (du1->ppargs) {
		error = xfs_parent_replacename(tp, du1->ppargs, dp1, name1,
				dp2, name2, ip1);
		if (error)
			return error;
	}

	if (du2->ppargs) {
		error = xfs_parent_replacename(tp, du2->ppargs, dp2, name2,
				dp1, name1, ip2);
		if (error)
			return error;
	}

	/*
	 * Inform our hook clients that we've finished an exchange operation as
	 * follows: removed the source and target files from their directories;
	 * added the target to the source directory; and added the source to
	 * the target directory.  All inodes are locked, so it's ok to model a
	 * rename this way so long as we say we deleted entries before we add
	 * new ones.
	 */
	xfs_dir_update_hook(dp1, ip1, -1, name1);
	xfs_dir_update_hook(dp2, ip2, -1, name2);
	xfs_dir_update_hook(dp1, ip2, 1, name1);
	xfs_dir_update_hook(dp2, ip1, 1, name2);
	return 0;
}

/*
 * Given an entry (@src_name, @src_ip) in directory @src_dp, make the entry
 * @target_name in directory @target_dp point to @src_ip and remove the
 * original entry, cleaning up everything left behind.
 *
 * Cleanup involves dropping a link count on @target_ip, and either removing
 * the (@src_name, @src_ip) entry from @src_dp or simply replacing the entry
 * with (@src_name, @wip) if a whiteout inode @wip is supplied.
 *
 * All inodes must have the ILOCK held.  We assume that if @src_ip is a
 * directory then its '..' doesn't already point to @target_dp, and that @wip
 * is a freshly allocated whiteout.
 */
int
xfs_dir_rename_children(
	struct xfs_trans	*tp,
	struct xfs_dir_update	*du_src,
	struct xfs_dir_update	*du_tgt,
	unsigned int		spaceres,
	struct xfs_dir_update	*du_wip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_inode	*src_dp = du_src->dp;
	const struct xfs_name	*src_name = du_src->name;
	struct xfs_inode	*src_ip = du_src->ip;
	struct xfs_inode	*target_dp = du_tgt->dp;
	const struct xfs_name	*target_name = du_tgt->name;
	struct xfs_inode	*target_ip = du_tgt->ip;
	bool			new_parent = (src_dp != target_dp);
	bool			src_is_directory;
	int			error;

	src_is_directory = S_ISDIR(VFS_I(src_ip)->i_mode);

	/*
	 * Check for expected errors before we dirty the transaction
	 * so we can return an error without a transaction abort.
	 */
	if (target_ip == NULL) {
		/*
		 * If there's no space reservation, check the entry will
		 * fit before actually inserting it.
		 */
		if (!spaceres) {
			error = xfs_dir_canenter(tp, target_dp, target_name);
			if (error)
				return error;
		}
	} else {
		/*
		 * If target exists and it's a directory, check that whether
		 * it can be destroyed.
		 */
		if (S_ISDIR(VFS_I(target_ip)->i_mode) &&
		    ((!xfs_dir_isempty(target_ip) &&
		      !xfs_dir_block_isempty(tp, target_ip)) ||
		     (VFS_I(target_ip)->i_nlink > 2)))
			return -EEXIST;
	}

	/*
	 * Directory entry creation below may acquire the AGF. Remove
	 * the whiteout from the unlinked list first to preserve correct
	 * AGI/AGF locking order. This dirties the transaction so failures
	 * after this point will abort and log recovery will clean up the
	 * mess.
	 *
	 * For whiteouts, we need to bump the link count on the whiteout
	 * inode. After this point, we have a real link, clear the tmpfile
	 * state flag from the inode so it doesn't accidentally get misused
	 * in future.
	 */
	if (du_wip->ip) {
		struct xfs_perag	*pag;

		ASSERT(VFS_I(du_wip->ip)->i_nlink == 0);

		pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, du_wip->ip->i_ino));
		error = xfs_iunlink_remove(tp, pag, du_wip->ip);
		xfs_perag_put(pag);
		if (error)
			return error;

		xfs_bumplink(tp, du_wip->ip);
	}

	/*
	 * Set up the target.
	 */
	if (target_ip == NULL) {
		/*
		 * If target does not exist and the rename crosses
		 * directories, adjust the target directory link count
		 * to account for the ".." reference from the new entry.
		 */
		error = xfs_dir_createname(tp, target_dp, target_name,
					   src_ip->i_ino, spaceres);
		if (error)
			return error;

		xfs_trans_ichgtime(tp, target_dp,
					XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);

		if (new_parent && src_is_directory) {
			xfs_bumplink(tp, target_dp);
		}
	} else { /* target_ip != NULL */
		/*
		 * Link the source inode under the target name.
		 * If the source inode is a directory and we are moving
		 * it across directories, its ".." entry will be
		 * inconsistent until we replace that down below.
		 *
		 * In case there is already an entry with the same
		 * name at the destination directory, remove it first.
		 */
		error = xfs_dir_replace(tp, target_dp, target_name,
					src_ip->i_ino, spaceres);
		if (error)
			return error;

		xfs_trans_ichgtime(tp, target_dp,
					XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);

		/*
		 * Decrement the link count on the target since the target
		 * dir no longer points to it.
		 */
		error = xfs_droplink(tp, target_ip);
		if (error)
			return error;

		if (src_is_directory) {
			/*
			 * Drop the link from the old "." entry.
			 */
			error = xfs_droplink(tp, target_ip);
			if (error)
				return error;
		}
	} /* target_ip != NULL */

	/*
	 * Remove the source.
	 */
	if (new_parent && src_is_directory) {
		/*
		 * Rewrite the ".." entry to point to the new
		 * directory.
		 */
		error = xfs_dir_replace(tp, src_ip, &xfs_name_dotdot,
					target_dp->i_ino, spaceres);
		ASSERT(error != -EEXIST);
		if (error)
			return error;
	}

	/*
	 * We always want to hit the ctime on the source inode.
	 *
	 * This isn't strictly required by the standards since the source
	 * inode isn't really being changed, but old unix file systems did
	 * it and some incremental backup programs won't work without it.
	 */
	xfs_trans_ichgtime(tp, src_ip, XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, src_ip, XFS_ILOG_CORE);

	/*
	 * Adjust the link count on src_dp.  This is necessary when
	 * renaming a directory, either within one parent when
	 * the target existed, or across two parent directories.
	 */
	if (src_is_directory && (new_parent || target_ip != NULL)) {

		/*
		 * Decrement link count on src_directory since the
		 * entry that's moved no longer points to it.
		 */
		error = xfs_droplink(tp, src_dp);
		if (error)
			return error;
	}

	/*
	 * For whiteouts, we only need to update the source dirent with the
	 * inode number of the whiteout inode rather than removing it
	 * altogether.
	 */
	if (du_wip->ip)
		error = xfs_dir_replace(tp, src_dp, src_name, du_wip->ip->i_ino,
					spaceres);
	else
		error = xfs_dir_removename(tp, src_dp, src_name, src_ip->i_ino,
					   spaceres);
	{
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    src_dp->i_mount->m_mxfs_dlm)
			pr_warn_ratelimited("mxfs: P-RENAME-SRCDEL src_dp=%llu src=%.*s tgt=%.*s src_ino=%llu rc=%d dp_fmt=%u dp_size=%lld dlm_mode=%u realns=%llu\n",
				(unsigned long long)src_dp->i_ino,
				src_name->len, (const char *)src_name->name,
				target_name->len, (const char *)target_name->name,
				(unsigned long long)src_ip->i_ino, error,
				src_dp->i_df.if_format,
				(long long)src_dp->i_disk_size,
				src_dp->i_dlm_mode,
				(unsigned long long)ktime_get_real_ns());
	}
	if (error)
		return error;

	xfs_trans_ichgtime(tp, src_dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, src_dp, XFS_ILOG_CORE);
	if (new_parent)
		xfs_trans_log_inode(tp, target_dp, XFS_ILOG_CORE);

	/* Schedule parent pointer updates. */
	if (du_wip->ppargs) {
		error = xfs_parent_addname(tp, du_wip->ppargs, src_dp,
				src_name, du_wip->ip);
		if (error)
			return error;
	}

	if (du_src->ppargs) {
		error = xfs_parent_replacename(tp, du_src->ppargs, src_dp,
				src_name, target_dp, target_name, src_ip);
		if (error)
			return error;
	}

	if (du_tgt->ppargs) {
		error = xfs_parent_removename(tp, du_tgt->ppargs, target_dp,
				target_name, target_ip);
		if (error)
			return error;
	}

	/*
	 * Inform our hook clients that we've finished a rename operation as
	 * follows: removed the source and target files from their directories;
	 * that we've added the source to the target directory; and finally
	 * that we've added the whiteout, if there was one.  All inodes are
	 * locked, so it's ok to model a rename this way so long as we say we
	 * deleted entries before we add new ones.
	 */
	if (target_ip)
		xfs_dir_update_hook(target_dp, target_ip, -1, target_name);
	xfs_dir_update_hook(src_dp, src_ip, -1, src_name);
	xfs_dir_update_hook(target_dp, src_ip, 1, target_name);
	if (du_wip->ip)
		xfs_dir_update_hook(src_dp, du_wip->ip, 1, src_name);
	return 0;
}
