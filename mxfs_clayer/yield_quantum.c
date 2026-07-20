// SPDX-License-Identifier: GPL-2.0
/*
 * mxfs_clayer/yield_quantum.c — D10 yield-counter helpers.
 *
 * The yield counter lives on the xfs_inode (i_dlm_yield_remaining) and is
 * manipulated under i_dlm_lock.  This file holds only the trivial arm/
 * decrement helpers; the release-trigger check (quantum 1→0 invokes
 * §7.2 release sequence) lives in pinned_resource.c::mxfs_inode_unpin
 * and in xfs_mxfs_dlm.c::mxfs_dlm_ilock_end.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "yield_quantum.h"

void
mxfs_yield_arm(
	struct xfs_inode	*ip)
{
	ip->i_dlm_yield_remaining = MXFS_BAST_YIELD_QUANTUM;
}

void
mxfs_yield_decrement(
	struct xfs_inode	*ip)
{
	if (ip->i_dlm_yield_remaining > 0)
		ip->i_dlm_yield_remaining--;
}
