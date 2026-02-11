/*
 * MXFS — Multinode XFS
 * Page cache invalidation
 *
 * When the DLM signals that another node has modified data covered by
 * a lock we previously held or are acquiring, we must invalidate the
 * local page cache for the affected range before allowing local reads.
 *
 * The daemon sends CACHE_INVAL commands via netlink. The netlink handler
 * calls mxfs_cache_invalidate() which looks up the inode and invalidates
 * the appropriate page range.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <mxfs/mxfs_common.h>
#include "mxfs_internal.h"

/* ─── Volume->superblock mapping ───
 *
 * To invalidate page cache for an inode, we need its struct inode,
 * which requires the superblock. We maintain a mapping from MXFS
 * volume IDs to their registered superblocks.
 */

#define MXFS_SB_HASH_BITS 4

struct mxfs_sb_entry {
	struct hlist_node	hnode;
	uint64_t		volume_id;
	struct super_block	*sb;
};

static DEFINE_HASHTABLE(sb_table, MXFS_SB_HASH_BITS);
static DEFINE_RWLOCK(sb_table_lock);

/*
 * mxfs_cache_register_sb — Register a superblock for a volume.
 * Called from mount hook when XFS mounts with MXFS enabled.
 */
int mxfs_cache_register_sb(uint64_t volume_id, struct super_block *sb)
{
	struct mxfs_sb_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->volume_id = volume_id;
	entry->sb = sb;

	write_lock(&sb_table_lock);
	hash_add(sb_table, &entry->hnode, (u32)volume_id);
	write_unlock(&sb_table_lock);

	pr_info("mxfs: registered superblock for volume 0x%llx\n", volume_id);
	return 0;
}

/*
 * mxfs_cache_unregister_sb — Unregister a superblock for a volume.
 * Called from unmount path.
 */
void mxfs_cache_unregister_sb(uint64_t volume_id)
{
	struct mxfs_sb_entry *entry;
	struct hlist_node *tmp;

	write_lock(&sb_table_lock);
	hash_for_each_possible_safe(sb_table, entry, tmp, hnode,
				    (u32)volume_id) {
		if (entry->volume_id == volume_id) {
			hash_del(&entry->hnode);
			write_unlock(&sb_table_lock);
			kfree(entry);
			pr_info("mxfs: unregistered superblock for volume 0x%llx\n",
				volume_id);
			return;
		}
	}
	write_unlock(&sb_table_lock);
}

static struct super_block *find_sb_for_volume(uint64_t volume_id)
{
	struct mxfs_sb_entry *entry;

	hash_for_each_possible(sb_table, entry, hnode, (u32)volume_id) {
		if (entry->volume_id == volume_id)
			return entry->sb;
	}

	return NULL;
}

/*
 * mxfs_cache_find_sbi_by_volume — Look up an mxfs_sb_info by volume ID.
 *
 * Used by the netlink DAEMON_READY and RECOVERY handlers to find the
 * per-mount state for a given volume. Returns NULL if not found.
 * Caller must hold no locks (we take sb_table_lock internally).
 */
struct mxfs_sb_info *mxfs_cache_find_sbi_by_volume(mxfs_volume_id_t volume_id)
{
	struct super_block *sb;
	struct mxfs_sb_info *sbi = NULL;

	read_lock(&sb_table_lock);
	sb = find_sb_for_volume(volume_id);
	if (sb)
		sbi = MXFS_SB(sb);
	read_unlock(&sb_table_lock);

	return sbi;
}

/*
 * mxfs_cache_invalidate — Invalidate page cache for a given resource.
 *
 * Called by the netlink handler when the daemon sends CACHE_INVAL.
 *
 * @volume:  Volume ID to identify the superblock
 * @ino:     Inode number whose pages to invalidate
 * @offset:  Starting byte offset (0 for full invalidation)
 * @length:  Number of bytes to invalidate (0 = entire inode)
 *
 * Returns 0 on success, negative errno on failure.
 */
int mxfs_cache_invalidate(uint64_t volume, uint64_t ino,
			  uint64_t offset, uint64_t length)
{
	struct super_block *sb;
	struct inode *inode;
	pgoff_t start, end;

	read_lock(&sb_table_lock);
	sb = find_sb_for_volume(volume);
	read_unlock(&sb_table_lock);

	if (!sb) {
		pr_warn("mxfs: cache_inval: no superblock for volume 0x%llx\n",
			volume);
		return -ENODEV;
	}

	inode = ilookup(sb, (unsigned long)ino);
	if (!inode) {
		/*
		 * Inode not in cache — nothing to invalidate.
		 * This is normal: the remote node modified data that we
		 * never cached locally.
		 */
		return 0;
	}

	if (length == 0) {
		/* Invalidate the entire address space */
		invalidate_inode_pages2(inode->i_mapping);
	} else {
		/* Invalidate a specific byte range */
		start = offset >> PAGE_SHIFT;
		end = (offset + length - 1) >> PAGE_SHIFT;
		invalidate_inode_pages2_range(inode->i_mapping, start, end);
	}

	iput(inode);
	return 0;
}

/* ─── Init / Exit ─── */

int mxfs_cache_init(void)
{
	hash_init(sb_table);

	pr_info("mxfs: page cache invalidation subsystem initialized\n");
	return 0;
}

void mxfs_cache_exit(void)
{
	struct mxfs_sb_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	/* Clean up any remaining entries (shouldn't happen on clean unmount) */
	write_lock(&sb_table_lock);
	hash_for_each_safe(sb_table, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	write_unlock(&sb_table_lock);

	pr_info("mxfs: page cache invalidation subsystem removed\n");
}
