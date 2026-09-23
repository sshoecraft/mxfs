// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2008-2010, Dave Chinner
 * All Rights Reserved.
 */
#ifndef XFS_ICREATE_ITEM_H
#define XFS_ICREATE_ITEM_H	1

/* in memory log item structure */
struct xfs_icreate_item {
	struct xfs_log_item	ic_item;
	struct xfs_icreate_log	ic_format;
	/* MXFS: formatted contiguously after ic_format when magic is set */
	struct mxfs_icreate_trailer ic_mxfs;
};

extern struct kmem_cache *xfs_icreate_cache;	/* inode create item */

struct xfs_icreate_item *xfs_icreate_log(struct xfs_trans *tp,
			xfs_agnumber_t agno,
			xfs_agblock_t agbno, unsigned int count,
			unsigned int inode_size, xfs_agblock_t length,
			unsigned int generation);
void xfs_icreate_mark_syncinit(struct xfs_icreate_item *icp);
/* MXFS: parse the writer-time trailer of an ICREATE log record; returns the
 * flags, 0 when the record carries no trailer. */
uint32_t mxfs_icreate_record_flags(const void *iov_base, size_t iov_len);

#endif	/* XFS_ICREATE_ITEM_H */
