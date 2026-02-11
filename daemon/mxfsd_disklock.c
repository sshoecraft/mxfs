/*
 * MXFS — Multinode XFS
 * On-disk lock state persistence
 *
 * Persists DLM lock state and node heartbeats to a reserved file on the
 * shared XFS volume. Uses O_DIRECT + O_SYNC for sector-aligned atomic I/O
 * so that lock records are durable and visible to all nodes immediately.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/falloc.h>

#include "mxfsd_disklock.h"
#include "mxfsd_log.h"

_Static_assert(sizeof(struct mxfsd_disklock_record) == 512,
               "disklock record must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfsd_disklock_heartbeat) == 512,
               "disklock heartbeat must be exactly 512 bytes");

/* FNV-1a hash over a resource ID — same algorithm as the DLM lock table */
static uint32_t resource_hash(const struct mxfs_resource_id *res)
{
	uint32_t hash = 2166136261u;
	const uint8_t *data = (const uint8_t *)res;
	size_t len = sizeof(*res);

	for (size_t i = 0; i < len; i++) {
		hash ^= data[i];
		hash *= 16777619u;
	}
	return hash;
}

/* Compare two resource IDs for equality */
static int resource_equal(const struct mxfs_resource_id *a,
                          const struct mxfs_resource_id *b)
{
	return a->volume == b->volume &&
	       a->ino == b->ino &&
	       a->offset == b->offset &&
	       a->ag_number == b->ag_number &&
	       a->type == b->type;
}

/* Current monotonic time in milliseconds */
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Allocate a 512-byte aligned buffer for O_DIRECT I/O */
static void *alloc_sector_buf(void)
{
	void *buf = NULL;
	if (posix_memalign(&buf, 512, MXFS_DISKLOCK_RECORD_SIZE) != 0)
		return NULL;
	return buf;
}

/* Compute the file offset for a lock record slot */
static off_t lock_slot_offset(uint32_t slot)
{
	return (off_t)MXFS_DISKLOCK_LOCK_OFFSET +
	       (off_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
}

/* Compute the file offset for a heartbeat slot */
static off_t hb_slot_offset(mxfs_node_id_t node)
{
	return (off_t)node * MXFS_DISKLOCK_RECORD_SIZE;
}

/*
 * Read a single 512-byte sector from the lockstate file.
 * buf must be 512-byte aligned.
 */
static int read_sector(int fd, off_t offset, void *buf)
{
	ssize_t n = pread(fd, buf, MXFS_DISKLOCK_RECORD_SIZE, offset);
	if (n < 0)
		return -errno;
	if (n != MXFS_DISKLOCK_RECORD_SIZE)
		return -EIO;
	return 0;
}

/*
 * Write a single 512-byte sector to the lockstate file.
 * buf must be 512-byte aligned.
 */
static int write_sector(int fd, off_t offset, const void *buf)
{
	ssize_t n = pwrite(fd, buf, MXFS_DISKLOCK_RECORD_SIZE, offset);
	if (n < 0)
		return -errno;
	if (n != MXFS_DISKLOCK_RECORD_SIZE)
		return -EIO;
	return 0;
}

/*
 * Find the lock record slot for a given resource.
 * Uses linear probing to handle hash collisions.
 *
 * Returns the slot index where the resource is found, or -1 if not found.
 * If not found and empty_out is non-NULL, sets *empty_out to the first
 * empty slot encountered (for insertion).
 */
static int find_lock_slot(int fd, const struct mxfs_resource_id *resource,
                          mxfs_node_id_t owner, int *empty_out)
{
	uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
	void *buf = alloc_sector_buf();
	int first_empty = -1;
	int result = -1;

	if (!buf)
		return -1;

	for (uint32_t i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
		uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
		off_t offset = lock_slot_offset(slot);

		int rc = read_sector(fd, offset, buf);
		if (rc < 0)
			break;

		struct mxfsd_disklock_record *rec = buf;

		if (rec->magic != MXFS_DISKLOCK_MAGIC ||
		    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
			/* Empty or invalid slot */
			if (first_empty < 0)
				first_empty = (int)slot;
			/* If we hit an empty slot and haven't found the record,
			 * the resource is not in the table (linear probing
			 * guarantee: no record exists past the first gap). */
			break;
		}

		if (resource_equal(&rec->resource, resource) &&
		    rec->owner == owner) {
			result = (int)slot;
			break;
		}
	}

	free(buf);

	if (empty_out)
		*empty_out = first_empty;
	return result;
}

/*
 * Find any active lock record slot for a resource regardless of owner.
 * Used when clearing a grant where we need to find the slot.
 */
static int find_lock_slot_any_owner(int fd,
                                    const struct mxfs_resource_id *resource,
                                    mxfs_node_id_t owner)
{
	uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
	void *buf = alloc_sector_buf();
	int result = -1;

	if (!buf)
		return -1;

	for (uint32_t i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
		uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
		off_t offset = lock_slot_offset(slot);

		int rc = read_sector(fd, offset, buf);
		if (rc < 0)
			break;

		struct mxfsd_disklock_record *rec = buf;

		if (rec->magic != MXFS_DISKLOCK_MAGIC ||
		    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE)
			break;

		if (resource_equal(&rec->resource, resource) &&
		    rec->owner == owner) {
			result = (int)slot;
			break;
		}
	}

	free(buf);
	return result;
}

/*
 * Create the .mxfs directory and lockstate file, pre-allocate to full size.
 */
static int create_lockstate_file(const char *path, const char *dir)
{
	int rc;

	rc = mkdir(dir, 0700);
	if (rc < 0 && errno != EEXIST) {
		mxfsd_err("disklock: cannot create directory '%s': %s",
		          dir, strerror(errno));
		return -errno;
	}

	int fd = open(path, O_RDWR | O_DIRECT | O_SYNC | O_CREAT, 0600);
	if (fd < 0) {
		mxfsd_err("disklock: cannot open '%s': %s",
		          path, strerror(errno));
		return -errno;
	}

	/* Pre-allocate the full file size for contiguous allocation */
	rc = fallocate(fd, 0, 0, (off_t)MXFS_DISKLOCK_FILE_SIZE);
	if (rc < 0) {
		mxfsd_warn("disklock: fallocate failed on '%s': %s "
		           "(will use ftruncate fallback)",
		           path, strerror(errno));
		/* Fallback to ftruncate */
		rc = ftruncate(fd, (off_t)MXFS_DISKLOCK_FILE_SIZE);
		if (rc < 0) {
			mxfsd_err("disklock: ftruncate failed on '%s': %s",
			          path, strerror(errno));
			close(fd);
			return -errno;
		}
	}

	return fd;
}

/*
 * Validate existing lockstate file by checking a few magic numbers.
 * Returns 0 if valid or the file is empty/new, -1 on corruption.
 */
static int validate_lockstate(int fd)
{
	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	/* Check first heartbeat slot */
	int rc = read_sector(fd, hb_slot_offset(0), buf);
	if (rc < 0) {
		free(buf);
		return rc;
	}

	struct mxfsd_disklock_heartbeat *hb = buf;

	/* If the slot has data, verify magic */
	if (hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    hb->magic != MXFS_DISKLOCK_MAGIC) {
		mxfsd_err("disklock: corrupt heartbeat record at slot 0 "
		          "(magic=%08x, expected=%08x)",
		          hb->magic, MXFS_DISKLOCK_MAGIC);
		free(buf);
		return -1;
	}

	/* Check first lock record slot */
	rc = read_sector(fd, lock_slot_offset(0), buf);
	if (rc < 0) {
		free(buf);
		return rc;
	}

	struct mxfsd_disklock_record *rec = buf;

	if (rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    rec->magic != MXFS_DISKLOCK_MAGIC) {
		mxfsd_err("disklock: corrupt lock record at slot 0 "
		          "(magic=%08x, expected=%08x)",
		          rec->magic, MXFS_DISKLOCK_MAGIC);
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}

/* Heartbeat writer thread */
static void *heartbeat_thread_fn(void *arg)
{
	struct mxfsd_disklock_ctx *ctx = arg;

	mxfsd_info("disklock: heartbeat thread started for node %u",
	           ctx->local_node);

	while (ctx->running) {
		int rc = mxfsd_disklock_write_heartbeat(ctx);
		if (rc < 0) {
			mxfsd_err("disklock: heartbeat write failed: %s",
			          strerror(-rc));
		}

		/* Sleep for MXFS_LEASE_RENEW_MS (2 seconds) in small
		 * increments so we can detect shutdown promptly */
		for (int i = 0; i < 20 && ctx->running; i++)
			usleep(100000); /* 100ms */
	}

	mxfsd_info("disklock: heartbeat thread stopped for node %u",
	           ctx->local_node);
	return NULL;
}

int mxfsd_disklock_init(struct mxfsd_disklock_ctx *ctx,
                        const char *mount_point,
                        mxfs_node_id_t local_node)
{
	if (!ctx || !mount_point)
		return -EINVAL;

	if (local_node >= MXFS_DISKLOCK_HB_SLOTS) {
		mxfsd_err("disklock: node id %u exceeds max heartbeat slots (%d)",
		          local_node, MXFS_DISKLOCK_HB_SLOTS);
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;
	ctx->local_node = local_node;
	ctx->running = false;

	int rc = pthread_mutex_init(&ctx->lock, NULL);
	if (rc != 0) {
		mxfsd_err("disklock: pthread_mutex_init failed: %s",
		          strerror(rc));
		return -rc;
	}

	/* Build paths */
	char dir[MXFS_PATH_MAX];
	snprintf(dir, sizeof(dir), "%s/.mxfs", mount_point);
	snprintf(ctx->path, sizeof(ctx->path), "%s/.mxfs/lockstate", mount_point);

	/* Create/open the lockstate file */
	int fd = create_lockstate_file(ctx->path, dir);
	if (fd < 0) {
		pthread_mutex_destroy(&ctx->lock);
		return fd;
	}

	ctx->fd = fd;

	/* Validate if file already has data */
	rc = validate_lockstate(fd);
	if (rc < 0) {
		mxfsd_err("disklock: lockstate file validation failed");
		close(fd);
		ctx->fd = -1;
		pthread_mutex_destroy(&ctx->lock);
		return -EIO;
	}

	mxfsd_info("disklock: initialized at '%s' for node %u "
	           "(file size: %lu bytes, %u lock slots)",
	           ctx->path, local_node,
	           (unsigned long)MXFS_DISKLOCK_FILE_SIZE,
	           MXFS_DISKLOCK_MAX_SLOTS);

	return 0;
}

void mxfsd_disklock_shutdown(struct mxfsd_disklock_ctx *ctx)
{
	if (!ctx)
		return;

	mxfsd_disklock_stop_heartbeat(ctx);

	pthread_mutex_lock(&ctx->lock);

	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}

	pthread_mutex_unlock(&ctx->lock);
	pthread_mutex_destroy(&ctx->lock);

	mxfsd_info("disklock: shutdown complete");
}

int mxfsd_disklock_write_grant(struct mxfsd_disklock_ctx *ctx,
                               const struct mxfs_resource_id *resource,
                               mxfs_node_id_t owner,
                               enum mxfs_lock_mode mode,
                               mxfs_epoch_t epoch)
{
	if (!ctx || !resource || ctx->fd < 0)
		return -EINVAL;

	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	pthread_mutex_lock(&ctx->lock);

	/* Find existing slot or first empty slot */
	int empty_slot = -1;
	int existing = find_lock_slot(ctx->fd, resource, owner, &empty_slot);

	int target_slot;
	if (existing >= 0) {
		target_slot = existing;
	} else if (empty_slot >= 0) {
		target_slot = empty_slot;
	} else {
		/* No empty slot found — need to probe further for one */
		uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
		int found = 0;
		for (uint32_t i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
			uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
			off_t offset = lock_slot_offset(slot);

			int rc = read_sector(ctx->fd, offset, buf);
			if (rc < 0)
				continue;

			struct mxfsd_disklock_record *rec = buf;
			if (rec->magic != MXFS_DISKLOCK_MAGIC ||
			    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
				target_slot = (int)slot;
				found = 1;
				break;
			}
		}
		if (!found) {
			mxfsd_err("disklock: no free lock slots available");
			pthread_mutex_unlock(&ctx->lock);
			free(buf);
			return -ENOSPC;
		}
	}

	/* Build the record */
	memset(buf, 0, MXFS_DISKLOCK_RECORD_SIZE);
	struct mxfsd_disklock_record *rec = buf;
	rec->magic = MXFS_DISKLOCK_MAGIC;
	rec->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
	rec->resource = *resource;
	rec->owner = owner;
	rec->mode = (uint8_t)mode;
	rec->state = (uint8_t)MXFS_LSTATE_GRANTED;
	rec->granted_at_ms = now_ms();
	rec->epoch = epoch;

	off_t offset = lock_slot_offset((uint32_t)target_slot);
	int rc = write_sector(ctx->fd, offset, buf);

	pthread_mutex_unlock(&ctx->lock);
	free(buf);

	if (rc < 0) {
		mxfsd_err("disklock: write_grant failed at slot %d: %s",
		          target_slot, strerror(-rc));
		return rc;
	}

	mxfsd_dbg("disklock: wrote grant for vol=%lu ino=%lu owner=%u "
	          "mode=%u at slot %d",
	          (unsigned long)resource->volume,
	          (unsigned long)resource->ino,
	          owner, mode, target_slot);

	return 0;
}

int mxfsd_disklock_clear_grant(struct mxfsd_disklock_ctx *ctx,
                               const struct mxfs_resource_id *resource,
                               mxfs_node_id_t owner)
{
	if (!ctx || !resource || ctx->fd < 0)
		return -EINVAL;

	pthread_mutex_lock(&ctx->lock);

	int slot = find_lock_slot_any_owner(ctx->fd, resource, owner);
	if (slot < 0) {
		mxfsd_dbg("disklock: clear_grant: no record found for "
		          "vol=%lu ino=%lu owner=%u",
		          (unsigned long)resource->volume,
		          (unsigned long)resource->ino,
		          owner);
		pthread_mutex_unlock(&ctx->lock);
		return -ENOENT;
	}

	/* Zero the slot to mark it empty */
	void *buf = alloc_sector_buf();
	if (!buf) {
		pthread_mutex_unlock(&ctx->lock);
		return -ENOMEM;
	}

	memset(buf, 0, MXFS_DISKLOCK_RECORD_SIZE);

	off_t offset = lock_slot_offset((uint32_t)slot);
	int rc = write_sector(ctx->fd, offset, buf);

	pthread_mutex_unlock(&ctx->lock);
	free(buf);

	if (rc < 0) {
		mxfsd_err("disklock: clear_grant failed at slot %d: %s",
		          slot, strerror(-rc));
		return rc;
	}

	mxfsd_dbg("disklock: cleared grant for vol=%lu ino=%lu owner=%u "
	          "at slot %d",
	          (unsigned long)resource->volume,
	          (unsigned long)resource->ino,
	          owner, slot);

	return 0;
}

int mxfsd_disklock_read_all(struct mxfsd_disklock_ctx *ctx,
                            struct mxfsd_disklock_record *records,
                            int *count, int max)
{
	if (!ctx || !records || !count || ctx->fd < 0)
		return -EINVAL;

	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	pthread_mutex_lock(&ctx->lock);

	int found = 0;

	for (uint32_t slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS && found < max; slot++) {
		off_t offset = lock_slot_offset(slot);

		int rc = read_sector(ctx->fd, offset, buf);
		if (rc < 0)
			continue;

		struct mxfsd_disklock_record *rec = buf;

		if (rec->magic == MXFS_DISKLOCK_MAGIC &&
		    rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE) {
			memcpy(&records[found], rec, sizeof(*rec));
			found++;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	free(buf);

	*count = found;

	mxfsd_info("disklock: read_all found %d active lock records", found);
	return 0;
}

int mxfsd_disklock_purge_node(struct mxfsd_disklock_ctx *ctx,
                              mxfs_node_id_t node)
{
	if (!ctx || ctx->fd < 0)
		return -EINVAL;

	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	void *zerobuf = alloc_sector_buf();
	if (!zerobuf) {
		free(buf);
		return -ENOMEM;
	}
	memset(zerobuf, 0, MXFS_DISKLOCK_RECORD_SIZE);

	pthread_mutex_lock(&ctx->lock);

	int purged = 0;

	for (uint32_t slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS; slot++) {
		off_t offset = lock_slot_offset(slot);

		int rc = read_sector(ctx->fd, offset, buf);
		if (rc < 0)
			continue;

		struct mxfsd_disklock_record *rec = buf;

		if (rec->magic == MXFS_DISKLOCK_MAGIC &&
		    rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		    rec->owner == node) {
			rc = write_sector(ctx->fd, offset, zerobuf);
			if (rc < 0) {
				mxfsd_err("disklock: purge write failed at "
				          "slot %u: %s", slot, strerror(-rc));
				continue;
			}
			purged++;
		}
	}

	/* Also clear the node's heartbeat record */
	if (node < MXFS_DISKLOCK_HB_SLOTS) {
		off_t hb_offset = hb_slot_offset(node);
		int rc = write_sector(ctx->fd, hb_offset, zerobuf);
		if (rc < 0) {
			mxfsd_err("disklock: purge heartbeat write failed "
			          "for node %u: %s", node, strerror(-rc));
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	free(buf);
	free(zerobuf);

	mxfsd_notice("disklock: purged %d lock records for dead node %u",
	             purged, node);

	return purged;
}

int mxfsd_disklock_write_heartbeat(struct mxfsd_disklock_ctx *ctx)
{
	if (!ctx || ctx->fd < 0)
		return -EINVAL;

	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, MXFS_DISKLOCK_RECORD_SIZE);
	struct mxfsd_disklock_heartbeat *hb = buf;

	hb->magic = MXFS_DISKLOCK_MAGIC;
	hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
	hb->node_id = ctx->local_node;
	hb->timestamp_ms = now_ms();
	hb->epoch = 0;  /* filled in by caller or integration layer */
	hb->lock_count = 0;

	off_t offset = hb_slot_offset(ctx->local_node);

	pthread_mutex_lock(&ctx->lock);
	int rc = write_sector(ctx->fd, offset, buf);
	pthread_mutex_unlock(&ctx->lock);

	free(buf);

	if (rc < 0) {
		mxfsd_err("disklock: write_heartbeat failed for node %u: %s",
		          ctx->local_node, strerror(-rc));
		return rc;
	}

	return 0;
}

int mxfsd_disklock_read_heartbeat(struct mxfsd_disklock_ctx *ctx,
                                  mxfs_node_id_t node,
                                  struct mxfsd_disklock_heartbeat *hb)
{
	if (!ctx || !hb || ctx->fd < 0)
		return -EINVAL;

	if (node >= MXFS_DISKLOCK_HB_SLOTS) {
		mxfsd_err("disklock: read_heartbeat: node %u exceeds "
		          "max slots (%d)", node, MXFS_DISKLOCK_HB_SLOTS);
		return -EINVAL;
	}

	void *buf = alloc_sector_buf();
	if (!buf)
		return -ENOMEM;

	off_t offset = hb_slot_offset(node);

	pthread_mutex_lock(&ctx->lock);
	int rc = read_sector(ctx->fd, offset, buf);
	pthread_mutex_unlock(&ctx->lock);

	if (rc < 0) {
		free(buf);
		return rc;
	}

	memcpy(hb, buf, sizeof(*hb));
	free(buf);

	/* Validate the record */
	if (hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    hb->magic != MXFS_DISKLOCK_MAGIC) {
		mxfsd_err("disklock: corrupt heartbeat for node %u "
		          "(magic=%08x)", node, hb->magic);
		return -EIO;
	}

	return 0;
}

int mxfsd_disklock_start_heartbeat(struct mxfsd_disklock_ctx *ctx)
{
	if (!ctx || ctx->fd < 0)
		return -EINVAL;

	if (ctx->running) {
		mxfsd_warn("disklock: heartbeat thread already running");
		return 0;
	}

	ctx->running = true;

	int rc = pthread_create(&ctx->heartbeat_thread, NULL,
	                        heartbeat_thread_fn, ctx);
	if (rc != 0) {
		ctx->running = false;
		mxfsd_err("disklock: failed to create heartbeat thread: %s",
		          strerror(rc));
		return -rc;
	}

	mxfsd_info("disklock: heartbeat thread started (interval=%u ms)",
	           MXFS_LEASE_RENEW_MS);

	return 0;
}

void mxfsd_disklock_stop_heartbeat(struct mxfsd_disklock_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return;

	ctx->running = false;

	pthread_join(ctx->heartbeat_thread, NULL);

	mxfsd_info("disklock: heartbeat thread stopped");
}
