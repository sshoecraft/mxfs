/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS TCP authority ledger — VIEW RECORD / ROOT device primitives
 * (docs/tauth-view-table.md build step 1).  The format itself
 * (structs, digest, crc, validation, HRW) is header-only in
 * include/mxfs/mxfs_tauth.h; this file is the PAL-backed I/O: root read and
 * full-block COMPARE AND WRITE, view slot read and FUA write + readback.
 * Kernel and usermode.  No policy: proposals, ballots and the barrier are
 * later build steps.
 */
#ifndef MXFS_TAUTH_VIEW_H
#define MXFS_TAUTH_VIEW_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_tauth.h"

/* base = the region's byte offset on the LUN (tauth_offset). */
/* Read the root CAW image (MXFS_TAUTH_ROOT_BYTES) into *img.  0 / -EIO. */
int  mxfs_tauth_root_read(mxfs_bdev_t *dev, uint64_t base, struct mxfs_tauth_root *img);
/* Full-block COMPARE AND WRITE of the root: `expect` = the last image read,
 * `next` = the new image (already sealed).  0 success; -EAGAIN miscompare
 * (re-read, re-derive); -EIO / -EOPNOTSUPP from the PAL.  The caller applies
 * the ambiguous-outcome rule (§12) on -EIO. */
int  mxfs_tauth_root_caw(mxfs_bdev_t *dev, uint64_t base,
                         const struct mxfs_tauth_root *expect,
                         const struct mxfs_tauth_root *next);
/* Read one view slot page (0 / -EIO); validation is the caller's. */
int  mxfs_tauth_view_read(mxfs_bdev_t *dev, uint64_t base, unsigned slot,
                          struct mxfs_tauth_view *v);
/* Write one view slot page (FUA) + flush + readback compare.  0 / -EIO. */
int  mxfs_tauth_view_write(mxfs_bdev_t *dev, uint64_t base, unsigned slot,
                           const struct mxfs_tauth_view *v);

#endif /* MXFS_TAUTH_VIEW_H */
