// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS — Stubs for excluded XFS features
 * 
 * Provides link-time symbols referenced by core XFS code but whose
 * implementations are in files we don't build (RT, quota, zones, ACL,
 * ioctl, sysctl, exchmaps, pNFS, dahash).
 */
#include "xfs_platform.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_buf.h"
#include "xfs_btree.h"
#include "xfs_log_recover.h"
#include "xfs_fsops.h"

/* ── RT btree stubs ── */
const struct xfs_buf_ops xfs_rtrefcountbt_buf_ops = { };
const struct xfs_buf_ops xfs_rtrmapbt_buf_ops = { };
const struct xfs_btree_ops xfs_rtrefcountbt_ops = { };
const struct xfs_btree_ops xfs_rtrmapbt_ops = { };
struct kmem_cache *xfs_xmd_cache;
struct kmem_cache *xfs_xmi_cache;

int xfs_rtrefcountbt_init_cur_cache(void) { return 0; }
void xfs_rtrefcountbt_destroy_cur_cache(void) { }
int xfs_rtrmapbt_init_cur_cache(void) { return 0; }
void xfs_rtrmapbt_destroy_cur_cache(void) { }
void xfs_rtrefcountbt_compute_maxlevels(struct xfs_mount *mp) { }
void xfs_rtrmapbt_compute_maxlevels(struct xfs_mount *mp) { }
unsigned int xfs_rtrefcountbt_maxrecs(struct xfs_mount *mp, unsigned int bl, bool l) { return 0; }
unsigned int xfs_rtrmapbt_maxrecs(struct xfs_mount *mp, unsigned int bl, bool l) { return 0; }
int xfs_rtrefcountbt_calc_reserves(struct xfs_mount *mp, struct xfs_trans *tp,
	struct xfs_group *g, xfs_filblks_t *a, xfs_filblks_t *b) { return 0; }
int xfs_rtrmapbt_calc_reserves(struct xfs_mount *mp, struct xfs_trans *tp,
	struct xfs_group *g, xfs_filblks_t *a, xfs_filblks_t *b) { return 0; }
void xfs_rtrefcountbt_to_disk(struct xfs_mount *mp, struct xfs_btree_block *rblock,
	int lev, struct xfs_btree_block *dblock) { }
void xfs_rtrmapbt_to_disk(struct xfs_mount *mp, struct xfs_btree_block *rblock,
	int lev, struct xfs_btree_block *dblock) { }
struct xfs_btree_cur *xfs_rtrefcountbt_init_cursor(struct xfs_trans *tp,
	struct xfs_group *g) { return NULL; }
struct xfs_btree_cur *xfs_rtrmapbt_init_cursor(struct xfs_trans *tp,
	struct xfs_group *g) { return NULL; }
int xfs_iformat_rtrefcount(struct xfs_inode *ip, struct xfs_dinode *dip) { return -EOPNOTSUPP; }
int xfs_iformat_rtrmap(struct xfs_inode *ip, struct xfs_dinode *dip) { return -EOPNOTSUPP; }
void xfs_iflush_rtrefcount(struct xfs_inode *ip, struct xfs_dinode *dip) { }
void xfs_iflush_rtrmap(struct xfs_inode *ip, struct xfs_dinode *dip) { }

/* ── Log item stubs ── */
const struct xlog_recover_item_ops xlog_dquot_item_ops = { .item_type = XFS_LI_DQUOT };
const struct xlog_recover_item_ops xlog_quotaoff_item_ops = { .item_type = XFS_LI_QUOTAOFF };
const struct xlog_recover_item_ops xlog_xmd_item_ops = { .item_type = XFS_LI_XMD };
const struct xlog_recover_item_ops xlog_xmi_item_ops = { .item_type = XFS_LI_XMI };

/* ── Sysctl stubs ── */
int xfs_sysctl_register(void) { return 0; }
void xfs_sysctl_unregister(void) { }

/* ── Ioctl stubs ── */
/* The xfs ioctl surface stays excluded (MXFS ships its own tools; the
 * on-disk envelope makes xfs_db/xfs_io admin senseless against an mxfs
 * device) — EXCEPT XFS_IOC_GOINGDOWN, which is load-bearing for fault
 * testing: it is the only way to force-shutdown a live mount without
 * yanking the device.  xfs_io cannot deliver it (its FSGEOMETRY probe
 * fails first); tests/mxfs_shutdown.sh issues the raw ioctl. */
long xfs_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	if (cmd == XFS_IOC_GOINGDOWN) {
		uint32_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(in, (uint32_t __user *)arg))
			return -EFAULT;
		return xfs_fs_goingdown(XFS_I(file_inode(f))->i_mount, in);
	}
	return -ENOTTY;
}
long xfs_file_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg) { return -ENOTTY; }
int xfs_fileattr_get(struct dentry *d, struct file_kattr *fa) { return -EOPNOTSUPP; }
int xfs_fileattr_set(struct mnt_idmap *idmap, struct dentry *d, struct file_kattr *fa) { return -EOPNOTSUPP; }

/* ── ACL stubs ── */
void xfs_forget_acl(struct inode *inode, const char *name) { }

/* ── pNFS stubs ── */
int xfs_fs_get_uuid(struct super_block *sb, u8 *buf, u32 *len, u64 *offset) { return -EOPNOTSUPP; }
int xfs_fs_map_blocks(struct inode *inode, loff_t offset, u64 length,
	void *block, int flags) { return -EOPNOTSUPP; }
int xfs_fs_commit_blocks(struct inode *inode, void *lcl, u32 bc, void *ds) { return -EOPNOTSUPP; }

/* ── Exchmaps stubs ── */
void xfs_exchmaps_defer_add(void *tp, void *req) { }

/* ── Zone stubs ── */
void xfs_zone_alloc_and_submit(void *ctx, struct bio *bio) { bio_endio(bio); }

/* ── Break layouts stub ── */
int xfs_break_leased_layouts(struct inode *inode, uint *iolock, bool *retry)
{ return 0; }

/* ── Dahash test stub ── */
int xfs_dahash_test(void) { return 0; }

/* ── bio_add_folio_nofail — may be missing on 6.8 ── */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
void bio_add_folio_nofail(struct bio *bio, struct folio *folio,
	size_t len, size_t off)
{
	bio_add_folio(bio, folio, len, off);
}
#endif
