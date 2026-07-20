// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
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
#include "xfs_trans_priv.h"
#include "xfs_inode_item.h"

#include <linux/iversion.h>

/*
 * Add a locked inode to the transaction.
 *
 * The inode must be locked, and it cannot be associated with any transaction.
 * If lock_flags is non-zero the inode will be unlocked on transaction commit.
 */
void
xfs_trans_ijoin(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	struct xfs_inode_log_item *iip;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	if (ip->i_itemp == NULL)
		xfs_inode_item_init(ip, ip->i_mount);
	iip = ip->i_itemp;

	ASSERT(iip->ili_lock_flags == 0);
	iip->ili_lock_flags = lock_flags;
	ASSERT(!xfs_iflags_test(ip, XFS_ISTALE));

	/* Reset the per-tx dirty context and add the item to the tx. */
	iip->ili_dirty_flags = 0;
	xfs_trans_add_item(tp, &iip->ili_item);
}

/*
 * Transactional inode timestamp update. Requires the inode to be locked and
 * joined to the transaction supplied. Relies on the transaction subsystem to
 * track dirty state and update/writeback the inode accordingly.
 */
void
xfs_trans_ichgtime(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	int			flags)
{
	struct inode		*inode = VFS_I(ip);
	struct timespec64	tv;

	ASSERT(tp);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);

	/* If the mtime changes, then ctime must also change */
	ASSERT(flags & XFS_ICHGTIME_CHG);

	tv = inode_set_ctime_current(inode);
	if (flags & XFS_ICHGTIME_MOD)
		inode_set_mtime_to_ts(inode, tv);
	if (flags & XFS_ICHGTIME_ACCESS)
		inode_set_atime_to_ts(inode, tv);
	if (flags & XFS_ICHGTIME_CREATE)
		ip->i_crtime = tv;
}

/*
 * This is called to mark the fields indicated in fieldmask as needing to be
 * logged when the transaction is committed.  The inode must already be
 * associated with the given transaction. All we do here is record where the
 * inode was dirtied and mark the transaction and inode log item dirty;
 * everything else is done in the ->precommit log item operation after the
 * changes in the transaction have been completed.
 */
void
xfs_trans_log_inode(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	uint			flags)
{
	struct xfs_inode_log_item *iip = ip->i_itemp;
	struct inode		*inode = VFS_I(ip);

	ASSERT(iip);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	ASSERT(!xfs_iflags_test(ip, XFS_ISTALE));

	/* sess2 (a9a03929) P2G-LOGWHO: name whoever logs a REGULAR file's
	 * core during the rm-phase window (P2D-DRAINWHY shows every rm-target
	 * inode dirty-in-AIL with fields=0x1 at its own release, re-appearing
	 * per inode after the shared cluster buffer was already flushed —
	 * some path keeps re-logging them).  Fires for REG inodes only, with
	 * the caller so the logging site is named in one run. */
	if (unlikely(S_ISREG(VFS_I(ip)->i_mode)) && ip->i_mount &&
	    ip->i_mount->m_mxfs_dlm)
		pr_warn_ratelimited("mxfs: P2G-LOGWHO ino=%llu flags=0x%x dlm_state=%u comm=%s caller=%pS\n",
			(unsigned long long)ip->i_ino, flags,
			ip->i_dlm_state, current->comm,
			__builtin_return_address(0));

	tp->t_flags |= XFS_TRANS_DIRTY;

	/*
	 * sess17b (ccloop 4eef1f39, Gemini DLM-epoch lineage guard): bind this
	 * dirtying to the current EX tenure.  Modifications only happen while we
	 * hold the inode EX (multinode write authority), so i_mxfs_ex_grant_seq is
	 * the epoch of the tenure under which this change was made.  If we later
	 * yield EX and re-acquire it (bumping ex_grant_seq), this dirty_seq will no
	 * longer match and the flush path (xfs_iflush_int) treats the in-core image
	 * as a stale ghost rather than clobbering a peer's live on-disk inode.
	 * Memory-only, under ILOCK_EXCL.
	 */
	ip->i_mxfs_dirty_seq = ip->i_mxfs_ex_grant_seq;

	/*
	 * First time we log the inode in a transaction, bump the inode change
	 * counter if it is configured for this to occur. While we have the
	 * inode locked exclusively for metadata modification, we can usually
	 * avoid setting XFS_ILOG_CORE if no one has queried the value since
	 * the last time it was incremented. If we have XFS_ILOG_CORE already
	 * set however, then go ahead and bump the i_version counter
	 * unconditionally.
	 */
	if (!test_and_set_bit(XFS_LI_DIRTY, &iip->ili_item.li_flags)) {
		if (IS_I_VERSION(inode) &&
		    inode_maybe_inc_iversion(inode, flags & XFS_ILOG_CORE))
			flags |= XFS_ILOG_IVERSION;
	}

	/*
	 * sess6 (ccloop 46efd8b6) RULE-4 PROVEN (run 112803Z, test12 i!=1):
	 * on a multi-node MXFS mount di_changecount is the cross-node reload
	 * freshness stamp (P-RELOAD-IDENTICAL / P3-REFUSE-OLDER / epoch
	 * gates compare it to decide whether a peer modified the inode since
	 * our in-core state loaded).  The upstream bump above fires only on
	 * the log item's clean->dirty TRANSITION — under a storm the item
	 * never leaves the AIL between EX tenures, so a whole tenure of dir
	 * ops (measured: 20 bmbt-leaf rewrites, nx 13->28) left cc frozen at
	 * 1124 cluster-wide, the identical-skip kept a peer's stale loaded
	 * iext across a count-invariant bmbt left-edge resize, and the next
	 * shrink died at xfs_bmap_del_extent_real i!=1.  Force one bump per
	 * CORE-logging transaction (ili_dirty_flags is the per-tx
	 * accumulator, consumed at precommit) so cc is a true modification
	 * counter under MXFS; single-node/non-MXFS keeps upstream laziness.
	 */
	if ((flags & XFS_ILOG_CORE) &&
	    !(iip->ili_dirty_flags & (XFS_ILOG_CORE | XFS_ILOG_IVERSION)) &&
	    !(flags & XFS_ILOG_IVERSION) &&
	    ip->i_mount && ip->i_mount->m_mxfs_dlm &&
	    IS_I_VERSION(inode)) {
		inode_inc_iversion(inode);
		flags |= XFS_ILOG_IVERSION;
	}

	iip->ili_dirty_flags |= flags;
}

int
xfs_trans_roll_inode(
	struct xfs_trans	**tpp,
	struct xfs_inode	*ip)
{
	int			error;

	xfs_trans_log_inode(*tpp, ip, XFS_ILOG_CORE);
	error = xfs_trans_roll(tpp);
	if (!error)
		xfs_trans_ijoin(*tpp, ip, 0);
	return error;
}
