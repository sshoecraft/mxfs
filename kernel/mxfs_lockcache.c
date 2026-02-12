/*
 * MXFS — Multinode XFS
 * Per-inode DLM lock cache
 *
 * Caches the granted DLM lock mode per inode so that repeated VFS
 * operations on the same inode avoid the netlink round-trip to the
 * daemon. Locks are held until:
 *   - A BAST (blocking AST) from the daemon requests release
 *   - The inode is evicted from the VFS cache
 *   - The filesystem is unmounted
 *
 * Mode hierarchy for modes actually used by MXFS VFS hooks:
 *   NL(0) < CR(1) < PR(3) < EX(5)
 * A cached mode can serve any request at or below its level.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Resource ID builder (shared with inode/file/dir ops) ─── */

static void build_resource(struct mxfs_resource_id *res,
			   mxfs_volume_id_t volume_id, uint64_t ino)
{
	memset(res, 0, sizeof(*res));
	res->volume = volume_id;
	res->ino = ino;
	res->type = MXFS_LTYPE_INODE;
}

/*
 * mxfs_lockcache_init_inode — Initialize lock cache fields.
 * Called from mxfs_alloc_inode() when the slab object is first used.
 */
void mxfs_lockcache_init_inode(struct mxfs_inode_info *info)
{
	spin_lock_init(&info->lock_spin);
	info->cached_mode = MXFS_LOCK_NL;
	info->bast_pending = false;
	atomic_set(&info->lock_holders, 0);
}

/*
 * mxfs_lock_inode — Acquire a DLM lock for a VFS operation.
 *
 * Fast path: if the inode already holds a cached lock at a mode
 * sufficient for the request, just increment the holder count and
 * return immediately — no netlink round-trip.
 *
 * Slow path: send a lock request to the daemon, wait for grant,
 * cache the result.
 *
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_lock_inode(struct inode *inode, uint8_t mode)
{
	struct mxfs_inode_info *info = MXFS_INODE(inode);
	struct mxfs_sb_info *sbi = MXFS_SB(inode->i_sb);
	struct mxfs_resource_id res;
	uint8_t granted;
	int ret;

	/* Fast path: check cache */
	spin_lock(&info->lock_spin);
	if (!info->bast_pending && info->cached_mode >= mode) {
		atomic_inc(&info->lock_holders);
		spin_unlock(&info->lock_spin);
		return 0;
	}
	spin_unlock(&info->lock_spin);

	/* Slow path: need to acquire or upgrade via daemon */
	ret = mxfs_wait_for_recovery(sbi);
	if (ret)
		return ret;

	build_resource(&res, sbi->volume_id, inode->i_ino);
	ret = mxfs_nl_send_lock_req(&res, mode, 0, &granted);
	if (ret)
		return ret;

	spin_lock(&info->lock_spin);
	if (granted > info->cached_mode)
		info->cached_mode = granted;
	info->bast_pending = false;
	atomic_inc(&info->lock_holders);
	spin_unlock(&info->lock_spin);

	return 0;
}

/*
 * mxfs_unlock_inode — Release a VFS operation's hold on the cached lock.
 *
 * Does NOT send a lock release to the daemon. The lock stays cached
 * for the next operation on this inode.
 */
void mxfs_unlock_inode(struct inode *inode)
{
	struct mxfs_inode_info *info = MXFS_INODE(inode);

	atomic_dec(&info->lock_holders);
}

/*
 * mxfs_bast_work_fn — Deferred BAST processing.
 *
 * Waits for all active VFS operations to finish using the cached lock,
 * then releases it to the daemon so a conflicting request can proceed.
 */
void mxfs_bast_work_fn(struct work_struct *work)
{
	struct mxfs_inode_info *info;
	struct inode *inode;
	struct mxfs_sb_info *sbi;
	struct mxfs_resource_id res;
	uint8_t old_mode;
	int waited = 0;

	info = container_of(work, struct mxfs_inode_info, bast_work);
	inode = &info->vfs_inode;
	sbi = MXFS_SB(inode->i_sb);

	/* Wait for active holders to drain (bounded by BAST timeout) */
	while (atomic_read(&info->lock_holders) > 0 &&
	       waited < MXFS_BAST_TIMEOUT_MS) {
		msleep(1);
		waited++;
	}

	spin_lock(&info->lock_spin);
	old_mode = info->cached_mode;
	info->cached_mode = MXFS_LOCK_NL;
	info->bast_pending = false;
	spin_unlock(&info->lock_spin);

	if (old_mode != MXFS_LOCK_NL) {
		build_resource(&res, sbi->volume_id, inode->i_ino);
		mxfs_nl_send_lock_release(&res);
	}
}

/*
 * mxfs_lockcache_evict — Release cached lock before inode destruction.
 * Called from mxfs_evict_inode() before clear_inode().
 */
void mxfs_lockcache_evict(struct inode *inode)
{
	struct mxfs_inode_info *info = MXFS_INODE(inode);
	struct mxfs_sb_info *sbi = MXFS_SB(inode->i_sb);
	struct mxfs_resource_id res;
	uint8_t old_mode;

	spin_lock(&info->lock_spin);
	old_mode = info->cached_mode;
	info->cached_mode = MXFS_LOCK_NL;
	info->bast_pending = false;
	spin_unlock(&info->lock_spin);

	cancel_work_sync(&info->bast_work);

	if (old_mode != MXFS_LOCK_NL && sbi->daemon_ready) {
		build_resource(&res, sbi->volume_id, inode->i_ino);
		mxfs_nl_send_lock_release(&res);
	}
}
