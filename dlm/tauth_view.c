// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS TCP authority ledger — VIEW RECORD / ROOT device primitives.
 * See tauth_view.h and docs/tauth-view-table.md (build step 1, sess428).
 */
#include "tauth_view.h"
#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#else
#include <string.h>
#include <errno.h>
#endif

/* ── device primitives ── */

int mxfs_tauth_root_read(mxfs_bdev_t *dev, uint64_t base, struct mxfs_tauth_root *img)
{
    return mxfs_pal_bdev_read_prio(dev, base + mxfs_tauth_ctrl_off(MXFS_TAUTH_CTRL_ROOT),
                                   img, MXFS_TAUTH_ROOT_BYTES);
}

int mxfs_tauth_root_caw(mxfs_bdev_t *dev, uint64_t base,
                        const struct mxfs_tauth_root *expect,
                        const struct mxfs_tauth_root *next)
{
    return mxfs_pal_bdev_compare_and_write(dev,
                base + mxfs_tauth_ctrl_off(MXFS_TAUTH_CTRL_ROOT), expect, next);
}

int mxfs_tauth_view_read(mxfs_bdev_t *dev, uint64_t base, unsigned slot,
                         struct mxfs_tauth_view *v)
{
    if (slot > MXFS_TAUTH_CTRL_VIEW_B)
        return -EINVAL;
    return mxfs_pal_bdev_read_prio(dev, base + mxfs_tauth_ctrl_off(slot), v,
                                   MXFS_TAUTH_PAGE_BYTES);
}

int mxfs_tauth_view_write(mxfs_bdev_t *dev, uint64_t base, unsigned slot,
                          const struct mxfs_tauth_view *v)
{
    struct mxfs_tauth_view *rb;
    int rc;

    if (slot > MXFS_TAUTH_CTRL_VIEW_B)
        return -EINVAL;
    rc = mxfs_pal_bdev_write_fua(dev, base + mxfs_tauth_ctrl_off(slot), v,
                                 MXFS_TAUTH_PAGE_BYTES);
    if (rc)
        return rc;
    rc = mxfs_pal_bdev_flush(dev);
    if (rc)
        return rc;
    rb = mxfs_pal_alloc(sizeof(*rb));
    if (!rb)
        return -ENOMEM;
    rc = mxfs_pal_bdev_read_prio(dev, base + mxfs_tauth_ctrl_off(slot), rb,
                                 MXFS_TAUTH_PAGE_BYTES);
    if (rc == 0 && memcmp(rb, v, sizeof(*v)) != 0)
        rc = -EIO;
    mxfs_pal_free(rb);
    return rc;
}
