// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2022, Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef XFS_IUNLINK_ITEM_H
#define XFS_IUNLINK_ITEM_H	1

struct xfs_trans;
struct xfs_inode;
struct xfs_perag;

/* in memory log item structure */
struct xfs_iunlink_item {
	struct xfs_log_item	item;
	struct xfs_inode	*ip;
	struct xfs_perag	*pag;
	xfs_agino_t		next_agino;
	xfs_agino_t		old_agino;
	/*
	 * mxfs sess396 (D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN, design-consult
	 * ruling ccmemory ccloop-c7ee71c6-sess396-GPT-ruling-insert-mode-
	 * iunlink-item): INSERT mode.  Created by xfs_iunlink_insert_inode,
	 * the one path that PROVES the inode is on no unlinked list, so any
	 * non-NULL di_next_unlinked the cluster buffer carries at precommit is
	 * a prior-life fossil and is overwritten instead of being treated as
	 * a chain mismatch.  Also forces an item for the NULL->NULL empty-
	 * bucket case so a buffer-only fossil is cleared at SORTED precommit
	 * (never by an early, unordered dirty buffer lock).  Every non-INSERT
	 * item keeps upstream's strict buffer==old_agino check.
	 */
	uint8_t			insert;	/* 0 = strict (upstream), 1 = xfs_iunlink_insert_inode, 2 = create (xfs_inode_init) */
};

extern struct kmem_cache *xfs_iunlink_cache;

int xfs_iunlink_log_inode(struct xfs_trans *tp, struct xfs_inode *ip,
			struct xfs_perag *pag, xfs_agino_t next_agino);
int xfs_iunlink_log_inode_insert(struct xfs_trans *tp, struct xfs_inode *ip,
			struct xfs_perag *pag, xfs_agino_t next_agino,
			unsigned int site);

#endif	/* XFS_IUNLINK_ITEM_H */
