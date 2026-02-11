/*
 * MXFS — Multinode XFS
 * Volume management
 *
 * Tracks shared XFS volumes, their mount state on the local node, and
 * which peer nodes have each volume mounted. Coordinates with the kernel
 * module via netlink for mount/unmount events.
 *
 * Volume IDs are derived from the XFS superblock UUID using FNV-1a
 * hash over all 16 bytes. This matches the kernel's computation and
 * gives a deterministic mapping from device to volume identity.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <mxfs/mxfs_common.h>
#include "mxfsd_volume.h"
#include "mxfsd_log.h"

/*
 * XFS superblock magic and UUID offset.
 * The XFS superblock starts at byte 0 of the device. The magic is "XFSB"
 * at offset 0, and the UUID is at offset 32 (16 bytes).
 */
#define XFS_SB_MAGIC        0x58465342  /* "XFSB" */
#define XFS_SB_MAGIC_OFFSET 0
#define XFS_SB_UUID_OFFSET  32
#define XFS_SB_UUID_LEN     16

/*
 * Read the XFS superblock UUID from a device and derive a volume ID.
 * Uses FNV-1a hash over all 16 UUID bytes, matching the kernel.
 */
static int read_volume_id(const char *device, mxfs_volume_id_t *id)
{
	unsigned char uuid[XFS_SB_UUID_LEN];
	uint32_t magic;
	int fd;
	ssize_t n;

	fd = open(device, O_RDONLY);
	if (fd < 0) {
		mxfsd_err("volume: cannot open device '%s': %s",
			  device, strerror(errno));
		return -errno;
	}

	/* Read magic number */
	n = pread(fd, &magic, sizeof(magic), XFS_SB_MAGIC_OFFSET);
	if (n != sizeof(magic)) {
		mxfsd_err("volume: cannot read superblock from '%s'", device);
		close(fd);
		return -EIO;
	}

	/* XFS magic is stored big-endian on disk */
	uint32_t be_magic = __builtin_bswap32(XFS_SB_MAGIC);
	if (magic != be_magic) {
		mxfsd_err("volume: '%s' is not an XFS filesystem (magic=%08x)",
			  device, magic);
		close(fd);
		return -EINVAL;
	}

	/* Read UUID */
	n = pread(fd, uuid, XFS_SB_UUID_LEN, XFS_SB_UUID_OFFSET);
	if (n != XFS_SB_UUID_LEN) {
		mxfsd_err("volume: cannot read UUID from '%s'", device);
		close(fd);
		return -EIO;
	}

	close(fd);

	/* FNV-1a hash all 16 UUID bytes — must match kernel computation */
	*id = mxfs_uuid_to_volume_id(uuid, XFS_SB_UUID_LEN);

	return 0;
}

int mxfsd_volume_init(struct mxfsd_volume_ctx *ctx, mxfs_node_id_t local_node)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node = local_node;
	pthread_mutex_init(&ctx->lock, NULL);
	return 0;
}

void mxfsd_volume_shutdown(struct mxfsd_volume_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);

	for (int i = 0; i < ctx->volume_count; i++) {
		struct mxfsd_volume *vol = &ctx->volumes[i];
		if (vol->state == MXFSD_VOL_ACTIVE) {
			mxfsd_info("volume: marking '%s' as unmounted on shutdown",
				   vol->name);
			vol->state = MXFSD_VOL_CONFIGURED;
			vol->mount_point[0] = '\0';
			vol->mount_nodes &= ~(1u << ctx->local_node);
		}
	}

	ctx->volume_count = 0;
	pthread_mutex_unlock(&ctx->lock);
	pthread_mutex_destroy(&ctx->lock);
}

int mxfsd_volume_add(struct mxfsd_volume_ctx *ctx, const char *name,
                     const char *device)
{
	int rc;

	pthread_mutex_lock(&ctx->lock);

	if (ctx->volume_count >= MXFS_MAX_VOLUMES) {
		mxfsd_err("volume: cannot add '%s': max volumes reached", name);
		pthread_mutex_unlock(&ctx->lock);
		return -ENOSPC;
	}

	/* Check for duplicate name */
	for (int i = 0; i < ctx->volume_count; i++) {
		if (strcmp(ctx->volumes[i].name, name) == 0) {
			mxfsd_err("volume: duplicate name '%s'", name);
			pthread_mutex_unlock(&ctx->lock);
			return -EEXIST;
		}
	}

	struct mxfsd_volume *vol = &ctx->volumes[ctx->volume_count];
	memset(vol, 0, sizeof(*vol));

	snprintf(vol->name, sizeof(vol->name), "%s", name);
	snprintf(vol->device, sizeof(vol->device), "%s", device);
	vol->state = MXFSD_VOL_CONFIGURED;

	/* Try to read the volume ID from the XFS superblock. If the device
	 * is not accessible (not yet attached, etc.), we still add the
	 * volume but with id=0; it will be populated later on mount. */
	rc = read_volume_id(device, &vol->id);
	if (rc < 0) {
		mxfsd_warn("volume: cannot read UUID from '%s', "
			   "will retry on mount", device);
		vol->id = 0;
	}

	ctx->volume_count++;

	mxfsd_info("volume: added '%s' device=%s id=%lu",
		   vol->name, vol->device, (unsigned long)vol->id);

	pthread_mutex_unlock(&ctx->lock);
	return 0;
}

int mxfsd_volume_set_mounted(struct mxfsd_volume_ctx *ctx,
                              mxfs_volume_id_t id, const char *mount_point)
{
	pthread_mutex_lock(&ctx->lock);

	struct mxfsd_volume *vol = NULL;
	for (int i = 0; i < ctx->volume_count; i++) {
		if (ctx->volumes[i].id == id) {
			vol = &ctx->volumes[i];
			break;
		}
	}

	if (!vol) {
		mxfsd_err("volume: set_mounted: unknown volume id %lu",
			  (unsigned long)id);
		pthread_mutex_unlock(&ctx->lock);
		return -ENOENT;
	}

	if (vol->state == MXFSD_VOL_ACTIVE) {
		mxfsd_warn("volume: '%s' already mounted at '%s'",
			   vol->name, vol->mount_point);
		pthread_mutex_unlock(&ctx->lock);
		return 0;
	}

	vol->state = MXFSD_VOL_ACTIVE;
	snprintf(vol->mount_point, sizeof(vol->mount_point), "%s", mount_point);
	vol->mount_nodes |= (1u << ctx->local_node);

	mxfsd_info("volume: '%s' mounted at '%s'", vol->name, mount_point);

	pthread_mutex_unlock(&ctx->lock);
	return 0;
}

int mxfsd_volume_set_unmounted(struct mxfsd_volume_ctx *ctx,
                                mxfs_volume_id_t id)
{
	pthread_mutex_lock(&ctx->lock);

	struct mxfsd_volume *vol = NULL;
	for (int i = 0; i < ctx->volume_count; i++) {
		if (ctx->volumes[i].id == id) {
			vol = &ctx->volumes[i];
			break;
		}
	}

	if (!vol) {
		mxfsd_err("volume: set_unmounted: unknown volume id %lu",
			  (unsigned long)id);
		pthread_mutex_unlock(&ctx->lock);
		return -ENOENT;
	}

	mxfsd_info("volume: '%s' unmounted from '%s'",
		   vol->name, vol->mount_point);

	vol->state = MXFSD_VOL_CONFIGURED;
	vol->mount_point[0] = '\0';
	vol->mount_nodes &= ~(1u << ctx->local_node);

	pthread_mutex_unlock(&ctx->lock);
	return 0;
}

struct mxfsd_volume *mxfsd_volume_find_by_id(struct mxfsd_volume_ctx *ctx,
                                             mxfs_volume_id_t id)
{
	/* Caller must hold ctx->lock or ensure single-threaded access */
	for (int i = 0; i < ctx->volume_count; i++) {
		if (ctx->volumes[i].id == id)
			return &ctx->volumes[i];
	}
	return NULL;
}

struct mxfsd_volume *mxfsd_volume_find_by_device(struct mxfsd_volume_ctx *ctx,
                                                 const char *device)
{
	/* Caller must hold ctx->lock or ensure single-threaded access */
	for (int i = 0; i < ctx->volume_count; i++) {
		if (strcmp(ctx->volumes[i].device, device) == 0)
			return &ctx->volumes[i];
	}
	return NULL;
}
