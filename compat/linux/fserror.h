/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compat stub for linux/fserror.h (added in ~6.19)
 * Provides no-op implementations for older kernels.
 */
#ifndef _LINUX_FSERROR_H__
#define _LINUX_FSERROR_H__

#include <linux/fs.h>
#include <linux/workqueue.h>

enum fserror_type {
	FSERR_BUFFERED_READ,
	FSERR_BUFFERED_WRITE,
	FSERR_DIRECTIO_READ,
	FSERR_DIRECTIO_WRITE,
	FSERR_DATA_LOST,
	FSERR_METADATA,
};

struct fserror_event {
	struct work_struct work;
	struct super_block *sb;
	struct inode *inode;
	loff_t pos;
	u64 len;
	enum fserror_type type;
	int error;
};

static inline void fserror_mount(struct super_block *sb) { }
static inline void fserror_unmount(struct super_block *sb) { }

static inline void fserror_report(struct super_block *sb, struct inode *inode,
		enum fserror_type type, loff_t pos, u64 len, int error,
		gfp_t gfp) { }

static inline void fserror_report_io(struct inode *inode,
		enum fserror_type type, loff_t pos, u64 len, int error,
		gfp_t gfp) { }

static inline void fserror_report_data_lost(struct inode *inode, loff_t pos,
		u64 len, gfp_t gfp) { }

static inline void fserror_report_file_metadata(struct inode *inode, int error,
		gfp_t gfp) { }

static inline void fserror_report_metadata(struct super_block *sb, int error,
		gfp_t gfp) { }

static inline void fserror_report_shutdown(struct super_block *sb,
		gfp_t gfp) { }

#endif /* _LINUX_FSERROR_H__ */
