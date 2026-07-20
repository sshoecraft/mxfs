// SPDX-License-Identifier: GPL-2.0
/*
 * mxfs_clayer/invalidate.c — v6a invalidation primitives (sess35 SKETCH)
 *
 * STATUS: SKELETON ONLY. Not built into the module. Sess36+ implementation
 * task. The functions below are stubs documenting the intended structure;
 * the actual logic should be lifted/refactored from existing v5 code at:
 *
 *   - xfs/xfs_mxfs_dlm.c:2480-2716 (mxfs_dlm_invalidate_ag_meta — AG path)
 *   - xfs/xfs_mxfs_dlm.c:300-470  (BAST-DIR-STALE walk — inode dir bufs)
 *   - xfs/xfs_mxfs_dlm.c:480-490  (filemap_write_and_wait + invalidate_inode_pages2)
 *
 * Per `docs/v6-cache-architecture-proposal.md` §3.2.
 *
 * Sess35 prescription: do this AFTER more careful design work in sess36.
 * Don't merge as-is. The skeleton exists to let sess36 fill it in
 * without re-deriving the design.
 */

#ifndef MXFS_CLAYER_INVALIDATE_BUILD_NOT_READY
/* Stub-out the whole file at compile time until sess36 lands the impl.
 * Define MXFS_CLAYER_INVALIDATE_BUILD_NOT_READY in the Makefile to
 * enable. */

#include <linux/types.h>
#include "invalidate.h"

/* xfs headers needed for real implementation:
 * #include "xfs.h"
 * #include "xfs_buf.h"
 * #include "xfs_mount.h"
 * #include "xfs_inode.h"
 * #include "xfs_dir2.h"
 */

int mxfs_invalidate_ag(struct xfs_mount *mp, xfs_agnumber_t ag_no)
{
	/*
	 * Sess36 implementation:
	 * 1. xfs_perag_get(mp, ag_no)
	 * 2. mutex_lock(&pag->pag_dlm_lock)
	 * 3. Walk pag->pag_bcache.bc_hash via rhashtable_walk_*
	 * 4. For each AG-meta buf (AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/etc):
	 *    - xfs_buf_lock (blocking, NOT trylock — chokepoint owns the
	 *      release path so deadlock with xfsaild is structurally
	 *      impossible)
	 *    - xfs_buf_stale + clear XBF_DONE
	 *    - xfs_buf_unlock + xfs_buf_relse
	 * 5. blkdev_issue_flush(mp->m_ddev_targp->bt_bdev)
	 * 6. xfs_perag_clear_initialised(pag)
	 * 7. mutex_unlock + xfs_perag_put
	 *
	 * Reference: lift logic from xfs_mxfs_dlm.c:2480-2716 (sess25
	 * v0.3.99) into this function, then remove the original.
	 */
	(void)mp; (void)ag_no;
	return -ENOSYS;
}

int mxfs_invalidate_inode(struct xfs_inode *ip)
{
	/*
	 * Sess36 implementation (CRITICAL — this is the Mode A fix):
	 *
	 * 1. spin_lock(&ip->i_dlm_lock); ip->i_dlm_stale = true; spin_unlock
	 * 2. **Pre-step: drain in-flight transactions on this inode.**
	 *    The skip_locked problem in v5's BAST-DIR-STALE walk (sess34
	 *    P-H12) is that the dir3 buf is held by an in-flight
	 *    transaction commit. We need to ensure no transaction is
	 *    actively modifying our dir at this moment. Approach (e) from
	 *    V6A_ROADMAP.md:
	 *    a. xfs_log_force(mp, XFS_LOG_SYNC) — push CIL to log
	 *    b. mxfs_ail_push_ag_sync(XFS_INO_TO_AGNO(mp, ip->i_ino)) —
	 *       push AIL items in inode's AG (already implemented in v5)
	 *    These force xfsaild to iflush our dir3 buf to disk
	 *    *without us needing to lock it ourselves*. xfsaild owns
	 *    the lock; once iflush completes the bio, b_sema is released
	 *    and the buf is on disk.
	 * 3. NOW walk dir extents via xfs_iext, lookup dir3 bufs:
	 *    - xfs_buf_incore(...) lookup
	 *    - if found, xfs_buf_lock (blocking — we should never deadlock
	 *      now because step 2 ensured no transaction holds it)
	 *    - xfs_buf_stale + clear XBF_DONE
	 *    - xfs_buf_unlock + xfs_buf_relse
	 * 4. For inode itself: filemap_write_and_wait(VFS_I(ip)->i_mapping)
	 * 5. invalidate_inode_pages2(VFS_I(ip)->i_mapping)
	 * 6. xfs_imap_to_bp barrier — ensures inode-cluster-buf bio
	 *    completion (sess29 fix at xfs_mxfs_dlm.c:527-545)
	 *
	 * The CRUCIAL difference from v5: NO skip_locked escape.
	 * Step 2's log_force + AIL drain ensures the buf is unlocked
	 * before step 3 runs. v5's BAST-DIR-STALE walk does step 3
	 * BEFORE step 2, so it hits the lock and skips. v6a inverts
	 * the order.
	 *
	 * Reference: existing v5 code at xfs_mxfs_dlm.c:300-545. The
	 * v6a version reorders log_force/ail_push to BEFORE the buf walk.
	 */
	(void)ip;
	return -ENOSYS;
}

int mxfs_pagecache_inval_inode(struct xfs_inode *ip)
{
	/*
	 * Sess36 implementation:
	 * truncate_inode_pages_final(VFS_I(ip)->i_mapping, 0);
	 *
	 * Or just call mxfs_invalidate_inode if we don't separately
	 * handle PCACHE class for v6a phase 1 (single-class-per-inode).
	 */
	(void)ip;
	return -ENOSYS;
}

#endif /* MXFS_CLAYER_INVALIDATE_BUILD_NOT_READY */
