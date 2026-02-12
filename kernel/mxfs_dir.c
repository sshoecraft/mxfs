/*
 * MXFS — Multinode XFS
 * Directory file operations (passthrough to lower XFS)
 * with DLM lock integration via per-inode lock cache
 *
 * Implements iterate_shared (readdir) by wrapping iterate_dir on the
 * lower XFS directory file. A filldir callback translates entries
 * from the lower filesystem using dir_emit.
 *
 * DLM lock policy (cached per-inode):
 *   readdir — PR on dir inode (read-only directory scan)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Open / Release ─── */

static int mxfs_dir_open(struct inode *inode, struct file *file)
{
	struct mxfs_file_info *finfo;
	struct file *lower_file;
	struct path lower_path;
	int ret;

	finfo = kmalloc(sizeof(*finfo), GFP_KERNEL);
	if (!finfo)
		return -ENOMEM;

	mxfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	mxfs_put_lower_path(file->f_path.dentry, &lower_path);

	if (IS_ERR(lower_file)) {
		ret = PTR_ERR(lower_file);
		kfree(finfo);
		return ret;
	}

	finfo->lower_file = lower_file;
	file->private_data = finfo;

	return 0;
}

static int mxfs_dir_release(struct inode *inode, struct file *file)
{
	struct mxfs_file_info *finfo = MXFS_FILE(file);

	if (finfo) {
		if (finfo->lower_file)
			fput(finfo->lower_file);
		kfree(finfo);
		file->private_data = NULL;
	}

	return 0;
}

/* ─── Readdir (iterate_shared) ─── */

struct mxfs_readdir_ctx {
	struct dir_context	ctx;
	struct dir_context	*caller_ctx;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
static bool mxfs_filldir(struct dir_context *ctx, const char *name,
			int namelen, loff_t offset, u64 ino,
			unsigned int d_type)
{
	struct mxfs_readdir_ctx *rctx;

	rctx = container_of(ctx, struct mxfs_readdir_ctx, ctx);

	rctx->caller_ctx->pos = ctx->pos;
	return dir_emit(rctx->caller_ctx, name, namelen, ino, d_type);
}
#else
static int mxfs_filldir(struct dir_context *ctx, const char *name,
			int namelen, loff_t offset, u64 ino,
			unsigned int d_type)
{
	struct mxfs_readdir_ctx *rctx;

	rctx = container_of(ctx, struct mxfs_readdir_ctx, ctx);

	rctx->caller_ctx->pos = ctx->pos;
	return !dir_emit(rctx->caller_ctx, name, namelen, ino, d_type);
}
#endif

static int mxfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = d_inode(file->f_path.dentry);
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	struct mxfs_readdir_ctx rctx = {
		.ctx.actor = mxfs_filldir,
		.caller_ctx = ctx,
	};
	int ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_PR);
	if (ret)
		return ret;

	rctx.ctx.pos = ctx->pos;
	ret = iterate_dir(lower_file, &rctx.ctx);
	ctx->pos = rctx.ctx.pos;
	file->f_pos = lower_file->f_pos;

	mxfs_unlock_inode(inode);
	return ret;
}

/* ─── Seek ─── */

static loff_t mxfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	loff_t ret;

	ret = vfs_llseek(lower_file, offset, whence);
	if (ret >= 0)
		file->f_pos = lower_file->f_pos;

	return ret;
}

/* ─── Fsync ─── */

static int mxfs_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct file *lower_file = MXFS_FILE(file)->lower_file;

	return vfs_fsync_range(lower_file, start, end, datasync);
}

/* ─── Directory file operations table ─── */

const struct file_operations mxfs_dir_fops = {
	.llseek		= mxfs_dir_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= mxfs_readdir,
	.open		= mxfs_dir_open,
	.release	= mxfs_dir_release,
	.fsync		= mxfs_dir_fsync,
};
