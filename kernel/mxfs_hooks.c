/*
 * MXFS — Multinode XFS
 * XFS lock intercept hooks
 *
 * Intercepts XFS inode lock, extent lock, and AG lock operations.
 * When a local XFS thread needs a lock that may be held by another node,
 * the hook forwards the request through netlink to mxfsd for distributed
 * coordination, then blocks until the DLM grants or denies.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/rwlock.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include <mxfs/mxfs_netlink.h>

/* From mxfs_netlink.c */
extern int mxfs_nl_send_lock_req(const struct mxfs_resource_id *resource,
				 uint8_t mode, uint32_t flags,
				 uint8_t *granted_mode);
extern int mxfs_nl_send_lock_release(const struct mxfs_resource_id *resource);

/* From mxfs_cache.c */
extern int mxfs_cache_invalidate(uint64_t volume, uint64_t ino,
				 uint64_t offset, uint64_t length);

/* ─── Per-volume recovery state ───
 *
 * When the daemon signals RECOVERY_START for a volume, all new lock
 * requests for that volume block until RECOVERY_DONE arrives.
 */

struct mxfs_volume_state {
	uint64_t		volume_id;
	atomic_t		recovering;	/* 1 = recovery in progress */
	wait_queue_head_t	recovery_wait;
};

#define MXFS_MAX_TRACKED_VOLUMES 64

static struct mxfs_volume_state volumes[MXFS_MAX_TRACKED_VOLUMES];
static int volume_count;
static DEFINE_RWLOCK(volume_lock);

static struct mxfs_volume_state *find_volume(uint64_t volume_id)
{
	int i;

	for (i = 0; i < volume_count; i++) {
		if (volumes[i].volume_id == volume_id)
			return &volumes[i];
	}
	return NULL;
}

static struct mxfs_volume_state *find_or_create_volume(uint64_t volume_id)
{
	struct mxfs_volume_state *vol;

	vol = find_volume(volume_id);
	if (vol)
		return vol;

	if (volume_count >= MXFS_MAX_TRACKED_VOLUMES) {
		pr_err("mxfs: too many tracked volumes\n");
		return NULL;
	}

	vol = &volumes[volume_count];
	vol->volume_id = volume_id;
	atomic_set(&vol->recovering, 0);
	init_waitqueue_head(&vol->recovery_wait);
	volume_count++;
	return vol;
}

/*
 * Called by mxfs_netlink when daemon signals RECOVERY_START.
 * Freeze all new lock requests for this volume.
 */
void mxfs_hooks_recovery_start(uint64_t volume_id)
{
	struct mxfs_volume_state *vol;

	write_lock(&volume_lock);
	vol = find_or_create_volume(volume_id);
	if (vol)
		atomic_set(&vol->recovering, 1);
	write_unlock(&volume_lock);

	pr_info("mxfs: hooks frozen for volume 0x%llx\n", volume_id);
}

/*
 * Called by mxfs_netlink when daemon signals RECOVERY_DONE.
 * Unfreeze and wake all waiters.
 */
void mxfs_hooks_recovery_done(uint64_t volume_id)
{
	struct mxfs_volume_state *vol;

	read_lock(&volume_lock);
	vol = find_volume(volume_id);
	read_unlock(&volume_lock);

	if (vol) {
		atomic_set(&vol->recovering, 0);
		wake_up_all(&vol->recovery_wait);
	}

	pr_info("mxfs: hooks unfrozen for volume 0x%llx\n", volume_id);
}

/*
 * Wait if the volume is currently in recovery. Returns 0 when clear,
 * -EINTR if interrupted.
 */
static int wait_for_recovery(uint64_t volume_id)
{
	struct mxfs_volume_state *vol;

	read_lock(&volume_lock);
	vol = find_volume(volume_id);
	read_unlock(&volume_lock);

	if (!vol)
		return 0;

	if (!atomic_read(&vol->recovering))
		return 0;

	return wait_event_interruptible(vol->recovery_wait,
					!atomic_read(&vol->recovering));
}

/* ─── Lock request helpers ─── */

static void build_inode_resource(struct mxfs_resource_id *res,
				 uint64_t volume, uint64_t ino)
{
	memset(res, 0, sizeof(*res));
	res->volume = volume;
	res->ino = ino;
	res->type = MXFS_LTYPE_INODE;
}

static void build_extent_resource(struct mxfs_resource_id *res,
				  uint64_t volume, uint64_t ino,
				  uint64_t offset)
{
	memset(res, 0, sizeof(*res));
	res->volume = volume;
	res->ino = ino;
	res->offset = offset;
	res->type = MXFS_LTYPE_EXTENT;
}

static void build_ag_resource(struct mxfs_resource_id *res,
			      uint64_t volume, uint32_t ag_number)
{
	memset(res, 0, sizeof(*res));
	res->volume = volume;
	res->ag_number = ag_number;
	res->type = MXFS_LTYPE_AG;
}

/*
 * mxfs_hook_inode_lock — Acquire distributed lock for an inode.
 *
 * Called when XFS needs to lock an inode that may be contended across nodes.
 * Blocks the calling thread until the DLM grants (or denies) the lock.
 *
 * Returns 0 on success with *granted_mode set, negative errno on failure.
 */
int mxfs_hook_inode_lock(uint64_t volume, uint64_t ino,
			 uint8_t mode, uint32_t flags,
			 uint8_t *granted_mode)
{
	struct mxfs_resource_id res;
	int ret;

	ret = wait_for_recovery(volume);
	if (ret)
		return ret;

	build_inode_resource(&res, volume, ino);
	return mxfs_nl_send_lock_req(&res, mode, flags, granted_mode);
}

/*
 * mxfs_hook_inode_unlock — Release distributed inode lock.
 */
int mxfs_hook_inode_unlock(uint64_t volume, uint64_t ino)
{
	struct mxfs_resource_id res;

	build_inode_resource(&res, volume, ino);
	return mxfs_nl_send_lock_release(&res);
}

/*
 * mxfs_hook_extent_lock — Acquire distributed lock for an extent range.
 *
 * Used when XFS performs I/O on a specific extent that may be cached or
 * modified on another node.
 */
int mxfs_hook_extent_lock(uint64_t volume, uint64_t ino,
			  uint64_t offset, uint8_t mode, uint32_t flags,
			  uint8_t *granted_mode)
{
	struct mxfs_resource_id res;
	int ret;

	ret = wait_for_recovery(volume);
	if (ret)
		return ret;

	build_extent_resource(&res, volume, ino, offset);
	return mxfs_nl_send_lock_req(&res, mode, flags, granted_mode);
}

/*
 * mxfs_hook_extent_unlock — Release distributed extent lock.
 */
int mxfs_hook_extent_unlock(uint64_t volume, uint64_t ino,
			    uint64_t offset)
{
	struct mxfs_resource_id res;

	build_extent_resource(&res, volume, ino, offset);
	return mxfs_nl_send_lock_release(&res);
}

/*
 * mxfs_hook_ag_lock — Acquire distributed lock for an allocation group.
 *
 * Used when XFS needs to allocate or free space within an AG. Only one
 * node may modify a given AG at a time (EX mode), but concurrent reads
 * are allowed (PR mode).
 */
int mxfs_hook_ag_lock(uint64_t volume, uint32_t ag_number,
		      uint8_t mode, uint32_t flags,
		      uint8_t *granted_mode)
{
	struct mxfs_resource_id res;
	int ret;

	ret = wait_for_recovery(volume);
	if (ret)
		return ret;

	build_ag_resource(&res, volume, ag_number);
	return mxfs_nl_send_lock_req(&res, mode, flags, granted_mode);
}

/*
 * mxfs_hook_ag_unlock — Release distributed AG lock.
 */
int mxfs_hook_ag_unlock(uint64_t volume, uint32_t ag_number)
{
	struct mxfs_resource_id res;

	build_ag_resource(&res, volume, ag_number);
	return mxfs_nl_send_lock_release(&res);
}

/* ─── Init / Exit ─── */

int mxfs_hooks_init(void)
{
	volume_count = 0;
	memset(volumes, 0, sizeof(volumes));

	pr_info("mxfs: XFS lock hooks initialized\n");
	return 0;
}

void mxfs_hooks_exit(void)
{
	pr_info("mxfs: XFS lock hooks removed\n");
}
