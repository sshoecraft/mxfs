/*
 * MXFS — Multinode XFS
 * File operations for regular files (passthrough to lower XFS)
 * with DLM lock integration via per-inode lock cache
 *
 * Each open file holds an mxfs_file_info with a reference to the
 * corresponding lower (XFS) file. Read/write operations swap ki_filp
 * to the lower file, invoke the lower op, then swap back and copy attrs.
 *
 * DLM lock policy (cached per-inode):
 *   open       — CR on file inode (coherent inode state)
 *   release    — no lock (cleanup only)
 *   read_iter  — PR on file inode (shared read)
 *   write_iter — EX on file inode (exclusive write)
 *   fsync      — EX on file inode (flush + barrier)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/fs_stack.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/splice.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Open / Release ─── */

static int mxfs_open(struct inode *inode, struct file *file)
{
	struct mxfs_file_info *finfo;
	struct file *lower_file;
	struct path lower_path;
	int ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_CR);
	if (ret)
		return ret;

	finfo = kmalloc(sizeof(*finfo), GFP_KERNEL);
	if (!finfo) {
		mxfs_unlock_inode(inode);
		return -ENOMEM;
	}

	mxfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	mxfs_put_lower_path(file->f_path.dentry, &lower_path);

	if (IS_ERR(lower_file)) {
		ret = PTR_ERR(lower_file);
		kfree(finfo);
		mxfs_unlock_inode(inode);
		return ret;
	}

	finfo->lower_file = lower_file;
	file->private_data = finfo;

	mxfs_unlock_inode(inode);
	return 0;
}

static int mxfs_release(struct inode *inode, struct file *file)
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

/* ─── Read / Write ─── */

static ssize_t mxfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = d_inode(file->f_path.dentry);
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	ssize_t ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_PR);
	if (ret)
		return ret;

	if (!lower_file->f_op->read_iter) {
		mxfs_unlock_inode(inode);
		return -EINVAL;
	}

	iocb->ki_filp = lower_file;
	ret = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;

	if (ret >= 0) {
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					d_inode(lower_file->f_path.dentry));
	}

	mxfs_unlock_inode(inode);
	return ret;
}

static ssize_t mxfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = d_inode(file->f_path.dentry);
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	ssize_t ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_EX);
	if (ret)
		return ret;

	if (!lower_file->f_op->write_iter) {
		mxfs_unlock_inode(inode);
		return -EINVAL;
	}

	iocb->ki_filp = lower_file;
	ret = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;

	if (ret >= 0) {
		fsstack_copy_attr_all(inode,
				      d_inode(lower_file->f_path.dentry));
		fsstack_copy_inode_size(inode,
					d_inode(lower_file->f_path.dentry));
	}

	mxfs_unlock_inode(inode);
	return ret;
}

/* ─── Seek ─── */

static loff_t mxfs_llseek(struct file *file, loff_t offset, int whence)
{
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	loff_t ret;

	ret = vfs_llseek(lower_file, offset, whence);
	if (ret >= 0)
		file->f_pos = lower_file->f_pos;

	return ret;
}

/* ─── Mmap ─── */

static int mxfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	int ret;

	if (!lower_file->f_op->mmap)
		return -ENODEV;

	/*
	 * Swap vm_file to the lower file so the VMA tracks the XFS file.
	 * This is the standard stacking FS approach — pages are owned by
	 * the lower filesystem's address space.
	 */
	get_file(lower_file);
	vma->vm_file = lower_file;
	ret = lower_file->f_op->mmap(lower_file, vma);
	if (ret)
		fput(lower_file);
	else
		fput(file);

	return ret;
}

/* ─── Fsync ─── */

static int mxfs_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	struct inode *inode = d_inode(file->f_path.dentry);
	struct file *lower_file = MXFS_FILE(file)->lower_file;
	int ret;

	ret = mxfs_lock_inode(inode, MXFS_LOCK_EX);
	if (ret)
		return ret;

	ret = vfs_fsync_range(lower_file, start, end, datasync);

	mxfs_unlock_inode(inode);
	return ret;
}

/* ─── Ioctl ─── */

static long mxfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct file *lower_file = MXFS_FILE(file)->lower_file;

	if (!lower_file->f_op->unlocked_ioctl)
		return -ENOTTY;

	return lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
}

/* ─── Splice ─── */

static ssize_t mxfs_splice_read(struct file *in, loff_t *ppos,
				struct pipe_inode_info *pipe,
				size_t len, unsigned int flags)
{
	struct file *lower_file = MXFS_FILE(in)->lower_file;
	ssize_t ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
	ret = filemap_splice_read(lower_file, ppos, pipe, len, flags);
#else
	ret = generic_file_splice_read(lower_file, ppos, pipe, len, flags);
#endif
	if (ret >= 0) {
		fsstack_copy_attr_atime(d_inode(in->f_path.dentry),
					d_inode(lower_file->f_path.dentry));
	}

	return ret;
}

/* ─── File operations table ─── */

const struct file_operations mxfs_main_fops = {
	.llseek		= mxfs_llseek,
	.read_iter	= mxfs_read_iter,
	.write_iter	= mxfs_write_iter,
	.mmap		= mxfs_mmap,
	.open		= mxfs_open,
	.release	= mxfs_release,
	.fsync		= mxfs_fsync,
	.unlocked_ioctl	= mxfs_unlocked_ioctl,
	.splice_read	= mxfs_splice_read,
};
