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
#include "xfs_mxfs_dirshard.h"	/* MXFS_IOC_TYPE, mxfs_dirshard_ioctl */
/* the real prototypes, so each stub is checked against what its callers call */
#include "xfs_rtrefcount_btree.h"
#include "xfs_rtrmap_btree.h"
#include "xfs_ioctl.h"
#include "xfs_acl.h"
#include "xfs_pnfs.h"
#include "xfs_exchmaps_item.h"
#include "xfs_zone_alloc.h"
#include "xfs_dahash_test.h"

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
xfs_filblks_t xfs_rtrefcountbt_calc_reserves(struct xfs_mount *mp) { return 0; }
xfs_filblks_t xfs_rtrmapbt_calc_reserves(struct xfs_mount *mp) { return 0; }
void xfs_rtrefcountbt_to_disk(struct xfs_mount *mp,
	struct xfs_btree_block *rblock, int rblocklen,
	struct xfs_rtrefcount_root *dblock, int dblocklen) { }
void xfs_rtrmapbt_to_disk(struct xfs_mount *mp, struct xfs_btree_block *rblock,
	unsigned int rblocklen, struct xfs_rtrmap_root *dblock,
	unsigned int dblocklen) { }
struct xfs_btree_cur *xfs_rtrefcountbt_init_cursor(struct xfs_trans *tp,
	struct xfs_rtgroup *rtg) { return NULL; }
struct xfs_btree_cur *xfs_rtrmapbt_init_cursor(struct xfs_trans *tp,
	struct xfs_rtgroup *rtg) { return NULL; }
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
	/*
	 * sess467: MXFS private ioctls (type MXFS_IOC_TYPE 0xB7) — directory
	 * sharding (docs/dir-sharding.md).  THIS stub is the ioctl entry the
	 * module compiles (pal/linux/xfs_ioctl.c is not in Kbuild; sess466
	 * wired the dispatch there and chain 97's stage-1 selftest failed every
	 * ioctl with ENOTTY on the frozen 0.64.0 — objdump showed no reference
	 * to mxfs_dirshard_ioctl anywhere in the module).  The dispatcher
	 * refuses unknown numbers of the type itself.
	 */
	if (_IOC_TYPE(cmd) == MXFS_IOC_TYPE)
		return mxfs_dirshard_ioctl(f, cmd, arg);
	return -ENOTTY;
}
long xfs_file_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg) { return -ENOTTY; }
int xfs_fileattr_get(struct dentry *d, struct file_kattr *fa) { return -EOPNOTSUPP; }
int xfs_fileattr_set(struct mnt_idmap *idmap, struct dentry *d, struct file_kattr *fa) { return -EOPNOTSUPP; }

/* ── ACL stubs ── */
#ifdef CONFIG_XFS_POSIX_ACL
void xfs_forget_acl(struct inode *inode, const char *name) { }
#endif

/* ── pNFS stubs ── */
int xfs_fs_get_uuid(struct super_block *sb, u8 *buf, u32 *len, u64 *offset) { return -EOPNOTSUPP; }
int xfs_fs_map_blocks(struct inode *inode, loff_t offset, u64 length,
	struct iomap *iomap, bool write, u32 *device_generation) { return -EOPNOTSUPP; }
int xfs_fs_commit_blocks(struct inode *inode, struct iomap *maps, int nr_maps,
	struct iattr *iattr) { return -EOPNOTSUPP; }

/* ── Exchmaps stubs ── */
void xfs_exchmaps_defer_add(struct xfs_trans *tp,
	struct xfs_exchmaps_intent *xmi) { }

/* ── Zone stubs ── */
/* Unreachable: xfs_fs_fill_super refuses every zoned filesystem. */
void xfs_zone_alloc_and_submit(struct iomap_ioend *ioend,
	struct xfs_open_zone **oz)
{
	WARN_ON_ONCE(1);
}

/* ── Break layouts stub ── */
int xfs_break_leased_layouts(struct inode *inode, uint *iolock, bool *did_unlock)
{ return 0; }

/* ── Dahash test stub ── */
int xfs_dahash_test(void) { return 0; }

/* ── bio_add_folio_nofail — may be missing on 6.8 ──
 * Upstream's body (block/bio.c), through bio_add_page: RHEL 9 declares
 * bio_add_folio and bio_add_folio_nofail but exports neither to modules, and
 * bio_add_page is exported on every kernel this builds for. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
void bio_add_folio_nofail(struct bio *bio, struct folio *folio,
	size_t len, size_t off)
{
	unsigned long nr = off / PAGE_SIZE;

	WARN_ON_ONCE(bio_add_page(bio, folio_page(folio, nr), len,
				  off % PAGE_SIZE) != len);
}
#endif
