// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2005-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_AOPS_H__
#define __XFS_AOPS_H__

extern const struct address_space_operations xfs_address_space_operations;
extern const struct address_space_operations xfs_dax_aops;

int xfs_setfilesize(struct xfs_inode *ip, xfs_off_t offset, size_t size);
void xfs_end_bio(struct bio *bio);
void xfs_end_io(struct work_struct *work);
/* FIX-25 (sess8): true when current is the xfs-conv ioend worker — admitted
 * to a nested EX during a BAST/DEMOTING drain (see mxfs_dlm_ilock_begin). */
bool xfs_task_in_ioend(void);
/* FIX-26 (ccloop c7ee71c6 sess6): true while current is inside
 * xfs_vm_writepages (writeback SUBMISSION — flusher, sync, fsync).  These
 * tasks hold folio locks across ->map_blocks' xfs_ilock(EX) (delalloc
 * conversion); the same nested-EX admit as FIX-25 applies, else the bast
 * drain's filemap_write_and_wait deadlocks on the submitter's folio lock
 * (test8 live capture: flusher D in mxfs_dlm_ilock_begin holding the folio,
 * mxfs-ino-bast worker D in __folio_lock — permanent AB-BA). */
bool xfs_task_in_writepages(void);

#endif /* __XFS_AOPS_H__ */
