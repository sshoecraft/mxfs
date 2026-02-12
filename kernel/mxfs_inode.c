/*
 * MXFS — Multinode XFS
 * Inode operations (passthrough to lower XFS) with DLM lock integration
 *
 * Three inode_operations tables:
 *   mxfs_dir_iops    — directories (create, lookup, link, unlink, etc.)
 *   mxfs_main_iops   — regular files and special files
 *   mxfs_symlink_iops — symbolic links
 *
 * All operations acquire the appropriate distributed lock via the
 * per-inode lock cache (mxfs_lockcache.c), call the VFS helper on the
 * lower XFS filesystem, release the lock hold, and copy attributes
 * back up.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
#include <linux/mnt_idmapping.h>
#endif
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Helper: copy attributes from lower inode after modification ─── */

static void mxfs_copy_attr(struct inode *inode)
{
	struct inode *lower = mxfs_lower_inode(inode);

	fsstack_copy_attr_all(inode, lower);
	fsstack_copy_inode_size(inode, lower);
}

/* ─── Directory inode operations ─── */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_create(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, umode_t mode, bool excl)
#else
static int mxfs_create(struct inode *dir, struct dentry *dentry,
		       umode_t mode, bool excl)
#endif
{
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct path lower_path;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry->d_parent, &lower_path);
	lower_dir_dentry = lower_path.dentry;
	lower_dir = d_inode(lower_dir_dentry);

	lower_dentry = lookup_one_len(dentry->d_name.name, lower_dir_dentry,
				      dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		ret = PTR_ERR(lower_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_create(&nop_mnt_idmap, lower_dir, lower_dentry, mode, excl);
#else
	ret = vfs_create(lower_dir, lower_dentry, mode, excl);
#endif
	if (ret)
		goto out_dput;

	ret = mxfs_interpose(dentry, dir->i_sb, &(struct path) {
		.dentry = lower_dentry,
		.mnt = lower_path.mnt,
	});
	if (ret)
		goto out_dput;

	mxfs_copy_attr(dir);

out_dput:
	dput(lower_dentry);
out:
	mxfs_put_lower_path(dentry->d_parent, &lower_path);
	mxfs_unlock_inode(dir);
	return ret;
}

static struct dentry *mxfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct path lower_dir_path;
	struct mxfs_dentry_info *info;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_PR);
	if (ret)
		return ERR_PTR(ret);

	mxfs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir_dentry = lower_dir_path.dentry;

	lower_dentry = lookup_one_len(dentry->d_name.name, lower_dir_dentry,
				      dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		ret = PTR_ERR(lower_dentry);
		mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
		mxfs_unlock_inode(dir);
		return ERR_PTR(ret);
	}

	/* Allocate dentry private data */
	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		dput(lower_dentry);
		mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
		mxfs_unlock_inode(dir);
		return ERR_PTR(-ENOMEM);
	}

	info->lower_path.dentry = lower_dentry;
	info->lower_path.mnt = mntget(lower_dir_path.mnt);
	dentry->d_fsdata = info;

	if (d_inode(lower_dentry)) {
		/* Positive dentry — create wrapping inode */
		struct inode *inode;

		inode = mxfs_iget(dir->i_sb, d_inode(lower_dentry));
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			path_put(&info->lower_path);
			kfree(info);
			dentry->d_fsdata = NULL;
			mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
			mxfs_unlock_inode(dir);
			return ERR_PTR(ret);
		}

		d_add(dentry, inode);
	} else {
		/* Negative dentry — file does not exist */
		d_add(dentry, NULL);
	}

	mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
	mxfs_unlock_inode(dir);
	return NULL;
}

static int mxfs_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *new_dentry)
{
	struct path lower_old_path, lower_dir_path;
	struct dentry *lower_new_dentry;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(old_dentry, &lower_old_path);
	mxfs_get_lower_path(new_dentry->d_parent, &lower_dir_path);
	lower_dir = d_inode(lower_dir_path.dentry);

	lower_new_dentry = lookup_one_len(new_dentry->d_name.name,
					  lower_dir_path.dentry,
					  new_dentry->d_name.len);
	if (IS_ERR(lower_new_dentry)) {
		ret = PTR_ERR(lower_new_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_link(lower_old_path.dentry, &nop_mnt_idmap, lower_dir,
		       lower_new_dentry, NULL);
#else
	ret = vfs_link(lower_old_path.dentry, lower_dir,
		       lower_new_dentry, NULL);
#endif
	if (ret)
		goto out_dput;

	ret = mxfs_interpose(new_dentry, dir->i_sb, &(struct path) {
		.dentry = lower_new_dentry,
		.mnt = lower_dir_path.mnt,
	});
	if (!ret) {
		mxfs_copy_attr(dir);
		mxfs_copy_attr(d_inode(old_dentry));
	}

out_dput:
	dput(lower_new_dentry);
out:
	mxfs_put_lower_path(new_dentry->d_parent, &lower_dir_path);
	mxfs_put_lower_path(old_dentry, &lower_old_path);
	mxfs_unlock_inode(dir);
	return ret;
}

static int mxfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct path lower_path, lower_dir_path;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry, &lower_path);
	mxfs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir = d_inode(lower_dir_path.dentry);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_unlink(&nop_mnt_idmap, lower_dir, lower_path.dentry, NULL);
#else
	ret = vfs_unlink(lower_dir, lower_path.dentry, NULL);
#endif
	if (!ret) {
		d_drop(dentry);
		mxfs_copy_attr(dir);
	}

	mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
	mxfs_put_lower_path(dentry, &lower_path);
	mxfs_unlock_inode(dir);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, const char *symname)
#else
static int mxfs_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
#endif
{
	struct path lower_dir_path;
	struct dentry *lower_dentry;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir = d_inode(lower_dir_path.dentry);

	lower_dentry = lookup_one_len(dentry->d_name.name,
				      lower_dir_path.dentry,
				      dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		ret = PTR_ERR(lower_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_symlink(&nop_mnt_idmap, lower_dir, lower_dentry, symname);
#else
	ret = vfs_symlink(lower_dir, lower_dentry, symname);
#endif
	if (ret)
		goto out_dput;

	ret = mxfs_interpose(dentry, dir->i_sb, &(struct path) {
		.dentry = lower_dentry,
		.mnt = lower_dir_path.mnt,
	});
	if (!ret)
		mxfs_copy_attr(dir);

out_dput:
	dput(lower_dentry);
out:
	mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
	mxfs_unlock_inode(dir);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *dentry, umode_t mode)
#else
static int mxfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
	struct path lower_dir_path;
	struct dentry *lower_dentry;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir = d_inode(lower_dir_path.dentry);

	lower_dentry = lookup_one_len(dentry->d_name.name,
				      lower_dir_path.dentry,
				      dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		ret = PTR_ERR(lower_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_mkdir(&nop_mnt_idmap, lower_dir, lower_dentry, mode);
#else
	ret = vfs_mkdir(lower_dir, lower_dentry, mode);
#endif
	if (ret)
		goto out_dput;

	ret = mxfs_interpose(dentry, dir->i_sb, &(struct path) {
		.dentry = lower_dentry,
		.mnt = lower_dir_path.mnt,
	});
	if (!ret)
		mxfs_copy_attr(dir);

out_dput:
	dput(lower_dentry);
out:
	mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
	mxfs_unlock_inode(dir);
	return ret;
}

static int mxfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct path lower_path, lower_dir_path;
	struct inode *lower_dir;
	int ret;

	ret = mxfs_lock_inode(dir, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry, &lower_path);
	mxfs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir = d_inode(lower_dir_path.dentry);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = vfs_rmdir(&nop_mnt_idmap, lower_dir, lower_path.dentry);
#else
	ret = vfs_rmdir(lower_dir, lower_path.dentry);
#endif
	if (!ret) {
		d_drop(dentry);
		mxfs_copy_attr(dir);
	}

	mxfs_put_lower_path(dentry->d_parent, &lower_dir_path);
	mxfs_put_lower_path(dentry, &lower_path);
	mxfs_unlock_inode(dir);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_rename(struct mnt_idmap *idmap,
		       struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
#else
static int mxfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
#endif
{
	struct path lower_old_path;
	struct path lower_old_dir_path, lower_new_dir_path;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *lower_new_dentry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
	struct renamedata rd;
#endif
	int ret;

	if (flags)
		return -EINVAL;  /* no RENAME_NOREPLACE etc. for now */

	/* Lock both parent dirs in inode number order to prevent deadlock */
	if (old_dir->i_ino <= new_dir->i_ino) {
		ret = mxfs_lock_inode(old_dir, MXFS_LOCK_EX);
		if (ret)
			return ret;

		if (old_dir != new_dir) {
			ret = mxfs_lock_inode(new_dir, MXFS_LOCK_EX);
			if (ret) {
				mxfs_unlock_inode(old_dir);
				return ret;
			}
		}
	} else {
		ret = mxfs_lock_inode(new_dir, MXFS_LOCK_EX);
		if (ret)
			return ret;

		ret = mxfs_lock_inode(old_dir, MXFS_LOCK_EX);
		if (ret) {
			mxfs_unlock_inode(new_dir);
			return ret;
		}
	}

	mxfs_get_lower_path(old_dentry, &lower_old_path);
	mxfs_get_lower_path(old_dentry->d_parent, &lower_old_dir_path);
	mxfs_get_lower_path(new_dentry->d_parent, &lower_new_dir_path);

	lower_old_dir_dentry = lower_old_dir_path.dentry;
	lower_new_dir_dentry = lower_new_dir_path.dentry;

	lower_new_dentry = lookup_one_len(new_dentry->d_name.name,
					  lower_new_dir_dentry,
					  new_dentry->d_name.len);
	if (IS_ERR(lower_new_dentry)) {
		ret = PTR_ERR(lower_new_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
	memset(&rd, 0, sizeof(rd));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	rd.old_mnt_idmap = &nop_mnt_idmap;
	rd.new_mnt_idmap = &nop_mnt_idmap;
#endif
	rd.old_dir = d_inode(lower_old_dir_dentry);
	rd.old_dentry = lower_old_path.dentry;
	rd.new_dir = d_inode(lower_new_dir_dentry);
	rd.new_dentry = lower_new_dentry;
	ret = vfs_rename(&rd);
#else
	ret = vfs_rename(d_inode(lower_old_dir_dentry),
			 lower_old_path.dentry,
			 d_inode(lower_new_dir_dentry),
			 lower_new_dentry, NULL, 0);
#endif
	if (!ret) {
		mxfs_copy_attr(old_dir);
		if (old_dir != new_dir)
			mxfs_copy_attr(new_dir);
	}

	dput(lower_new_dentry);
out:
	mxfs_put_lower_path(new_dentry->d_parent, &lower_new_dir_path);
	mxfs_put_lower_path(old_dentry->d_parent, &lower_old_dir_path);
	mxfs_put_lower_path(old_dentry, &lower_old_path);

	mxfs_unlock_inode(old_dir);
	if (old_dir != new_dir)
		mxfs_unlock_inode(new_dir);

	return ret;
}

/* ─── Shared inode operations (used by all three tables) ─── */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_permission(struct mnt_idmap *idmap, struct inode *inode,
			   int mask)
#else
static int mxfs_permission(struct inode *inode, int mask)
#endif
{
	struct inode *lower = mxfs_lower_inode(inode);
	int ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_CR);
	if (ret)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = inode_permission(&nop_mnt_idmap, lower, mask);
#else
	ret = inode_permission(lower, mask);
#endif

	mxfs_unlock_inode(inode);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_getattr(struct mnt_idmap *idmap, const struct path *path,
			struct kstat *stat, u32 request_mask,
			unsigned int query_flags)
#else
static int mxfs_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags)
#endif
{
	struct dentry *dentry = path->dentry;
	struct path lower_path;
	int ret;

	ret = mxfs_lock_inode(d_inode(dentry), MXFS_LOCK_PR);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry, &lower_path);
	ret = vfs_getattr(&lower_path, stat, request_mask, query_flags);
	mxfs_put_lower_path(dentry, &lower_path);

	if (!ret) {
		/* Override device to avoid exposing lower filesystem */
		stat->dev = dentry->d_sb->s_dev;
		mxfs_copy_attr(d_inode(dentry));
	}

	mxfs_unlock_inode(d_inode(dentry));
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int mxfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			struct iattr *ia)
#else
static int mxfs_setattr(struct dentry *dentry, struct iattr *ia)
#endif
{
	struct path lower_path;
	struct dentry *lower_dentry;
	struct inode *inode = d_inode(dentry);
	struct inode *lower_inode;
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = setattr_prepare(&nop_mnt_idmap, dentry, ia);
#else
	ret = setattr_prepare(dentry, ia);
#endif
	if (ret)
		return ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_EX);
	if (ret)
		return ret;

	mxfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = d_inode(lower_dentry);

	/* Size change needs special handling */
	if (ia->ia_valid & ATTR_SIZE) {
		ret = inode_newsize_ok(inode, ia->ia_size);
		if (ret)
			goto out;
	}

	inode_lock(lower_inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	ret = notify_change(&nop_mnt_idmap, lower_dentry, ia, NULL);
#else
	ret = notify_change(lower_dentry, ia, NULL);
#endif
	inode_unlock(lower_inode);

	if (!ret)
		mxfs_copy_attr(inode);

out:
	mxfs_put_lower_path(dentry, &lower_path);
	mxfs_unlock_inode(inode);
	return ret;
}

static ssize_t mxfs_listxattr(struct dentry *dentry, char *buffer,
			       size_t buffer_size)
{
	struct path lower_path;
	ssize_t ret;

	mxfs_get_lower_path(dentry, &lower_path);
	ret = vfs_listxattr(lower_path.dentry, buffer, buffer_size);
	mxfs_put_lower_path(dentry, &lower_path);

	return ret;
}

/* ─── Symlink operations ─── */

static const char *mxfs_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *done)
{
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	const char *link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	lower_dentry = mxfs_lower_dentry(dentry);
	lower_inode = d_inode(lower_dentry);

	if (!lower_inode->i_op->get_link)
		return ERR_PTR(-EINVAL);

	link = lower_inode->i_op->get_link(lower_dentry, lower_inode, done);
	return link;
}

/* ─── Inode operations tables ─── */

const struct inode_operations mxfs_dir_iops = {
	.create		= mxfs_create,
	.lookup		= mxfs_lookup,
	.link		= mxfs_link,
	.unlink		= mxfs_unlink,
	.symlink	= mxfs_symlink,
	.mkdir		= mxfs_mkdir,
	.rmdir		= mxfs_rmdir,
	.rename		= mxfs_rename,
	.permission	= mxfs_permission,
	.getattr	= mxfs_getattr,
	.setattr	= mxfs_setattr,
	.listxattr	= mxfs_listxattr,
};

const struct inode_operations mxfs_main_iops = {
	.permission	= mxfs_permission,
	.getattr	= mxfs_getattr,
	.setattr	= mxfs_setattr,
	.listxattr	= mxfs_listxattr,
};

const struct inode_operations mxfs_symlink_iops = {
	.get_link	= mxfs_get_link,
	.permission	= mxfs_permission,
	.getattr	= mxfs_getattr,
	.setattr	= mxfs_setattr,
	.listxattr	= mxfs_listxattr,
};
