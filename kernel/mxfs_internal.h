/*
 * MXFS — Multinode XFS
 * Internal kernel module declarations shared between mxfs_*.c files
 *
 * Stacking filesystem model: MXFS wraps XFS at the VFS layer,
 * intercepting operations to provide distributed locking and
 * cache coherency across cluster nodes.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_INTERNAL_H
#define MXFS_INTERNAL_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/path.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/if.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <mxfs/mxfs_common.h>

/* MXFS filesystem magic number — "MXFS" in ASCII */
#define MXFS_SUPER_MAGIC	0x4D584653

/* ─── Per-mount superblock info ─── */

struct mxfs_sb_info {
	/* Lower (XFS) filesystem */
	struct super_block	*lower_sb;
	struct vfsmount		*lower_mnt;

	/* Volume identity */
	u8			volume_uuid[16];
	mxfs_volume_id_t	volume_id;

	/* Daemon state */
	pid_t			daemon_pid;
	u32			daemon_portid;
	bool			daemon_ready;
	struct completion	daemon_startup;

	/* Mount options */
	char			iface[IFNAMSIZ];
	uint16_t		port;
	char			mcast_addr[64];
	char			bcast_addr[64];

	/* Device and mount point paths (for daemon spawn) */
	char			*dev_name;
	char			*mount_path;

	/* Recovery state */
	atomic_t		recovering;
	wait_queue_head_t	recovery_wait;
};

/* ─── Per-inode info ─── */

struct mxfs_inode_info {
	struct inode		*lower_inode;

	/* Lock cache — holds DLM lock across VFS operations */
	spinlock_t		lock_spin;
	uint8_t			cached_mode;	/* MXFS_LOCK_NL if none */
	bool			bast_pending;	/* daemon requested release */
	atomic_t		lock_holders;	/* active VFS ops using lock */
	struct work_struct	bast_work;

	struct inode		vfs_inode;	/* must be last for container_of */
};

/* ─── Per-dentry info ─── */

struct mxfs_dentry_info {
	struct path		lower_path;
};

/* ─── Per-file info ─── */

struct mxfs_file_info {
	struct file		*lower_file;
};

/* ─── Accessor macros ─── */

static inline struct mxfs_sb_info *MXFS_SB(const struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct mxfs_inode_info *MXFS_INODE(const struct inode *inode)
{
	return container_of(inode, struct mxfs_inode_info, vfs_inode);
}

static inline struct mxfs_dentry_info *MXFS_DENTRY(const struct dentry *dent)
{
	return dent->d_fsdata;
}

static inline struct mxfs_file_info *MXFS_FILE(const struct file *file)
{
	return file->private_data;
}

/* Lower object accessors */

static inline struct inode *mxfs_lower_inode(const struct inode *inode)
{
	return MXFS_INODE(inode)->lower_inode;
}

static inline struct super_block *mxfs_lower_sb(const struct super_block *sb)
{
	return MXFS_SB(sb)->lower_sb;
}

static inline void mxfs_get_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	struct mxfs_dentry_info *info = MXFS_DENTRY(dent);

	lower_path->dentry = info->lower_path.dentry;
	lower_path->mnt = info->lower_path.mnt;
	path_get(lower_path);
}

static inline void mxfs_put_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	path_put(lower_path);
}

static inline void mxfs_set_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	struct mxfs_dentry_info *info = MXFS_DENTRY(dent);

	info->lower_path.dentry = lower_path->dentry;
	info->lower_path.mnt = lower_path->mnt;
}

static inline struct dentry *mxfs_lower_dentry(const struct dentry *dent)
{
	return MXFS_DENTRY(dent)->lower_path.dentry;
}

static inline struct vfsmount *mxfs_lower_mnt(const struct dentry *dent)
{
	return MXFS_DENTRY(dent)->lower_path.mnt;
}

/* ─── Filesystem type (mxfs_main.c) ─── */

extern struct file_system_type mxfs_fs_type;

/* ─── mxfs_super.c ─── */

int mxfs_init_inode_cache(void);
void mxfs_destroy_inode_cache(void);
struct inode *mxfs_iget(struct super_block *sb, struct inode *lower_inode);
int mxfs_interpose(struct dentry *dentry, struct super_block *sb,
		   struct path *lower_path);
/* mxfs_uuid_to_volume_id() is static inline in mxfs_common.h */

int mxfs_wait_for_recovery(struct mxfs_sb_info *sbi);

extern const struct super_operations mxfs_sops;
extern const struct dentry_operations mxfs_dops;

/* ─── mxfs_inode.c ─── */

extern const struct inode_operations mxfs_dir_iops;
extern const struct inode_operations mxfs_main_iops;
extern const struct inode_operations mxfs_symlink_iops;

/* ─── mxfs_file.c ─── */

extern const struct file_operations mxfs_main_fops;

/* ─── mxfs_dir.c ─── */

extern const struct file_operations mxfs_dir_fops;

/* ─── mxfs_netlink.c ─── */

int mxfs_netlink_init(void);
void mxfs_netlink_exit(void);
int mxfs_nl_send_lock_req(const struct mxfs_resource_id *resource,
			   uint8_t mode, uint32_t flags,
			   uint8_t *granted_mode);
int mxfs_nl_send_lock_release(const struct mxfs_resource_id *resource);
int mxfs_nl_send_volume_mount(uint64_t volume_id,
			      const char *dev_path,
			      const char *mount_path);
int mxfs_nl_send_volume_umount(uint64_t volume_id);
uint8_t mxfs_nl_get_node_state(uint32_t node_id);

/* ─── mxfs_lockcache.c ─── */

int mxfs_lock_inode(struct inode *inode, uint8_t mode);
void mxfs_unlock_inode(struct inode *inode);
void mxfs_lockcache_evict(struct inode *inode);
void mxfs_lockcache_init_inode(struct mxfs_inode_info *info);
void mxfs_bast_work_fn(struct work_struct *work);

/* ─── mxfs_cache.c ─── */

int mxfs_cache_init(void);
void mxfs_cache_exit(void);
int mxfs_cache_invalidate(uint64_t volume, uint64_t ino,
			  uint64_t offset, uint64_t length);
int mxfs_cache_register_sb(uint64_t volume_id, struct super_block *sb);
void mxfs_cache_unregister_sb(uint64_t volume_id);
struct mxfs_sb_info *mxfs_cache_find_sbi_by_volume(mxfs_volume_id_t volume_id);
struct super_block *mxfs_cache_find_sb_by_volume(mxfs_volume_id_t volume_id);

#endif /* MXFS_INTERNAL_H */
